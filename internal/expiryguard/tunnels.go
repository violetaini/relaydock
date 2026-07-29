package expiryguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/tunnelidentity"
)

const (
	TunnelStateProvisioning   = "provisioning"
	TunnelStateActive         = "active"
	TunnelStateSuspendPending = "suspend_pending"
	TunnelStateSuspended      = "suspended"
	TunnelStateDeletePending  = "delete_pending"
	TunnelStateDeleted        = "deleted"
	TunnelStateExpiryPending  = "expiry_pending"
	TunnelStateExpired        = "expired"

	maxTunnelLease = 10 * time.Minute

	tunnelNetworkTCP    = "tcp"
	tunnelNetworkUDP    = "udp"
	tunnelNetworkTCPUDP = "tcp_udp"
	xrayNetworkTCPUDP   = "tcp,udp"
)

// CommandRunner is injectable so nftables transactions can be verified without
// mutating the test host.
type CommandRunner interface {
	CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error)
}

type OSCommandRunner struct{}

func (OSCommandRunner) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// TunnelResource is the durable, Agent-local ownership record for one managed
// dokodemo-door inbound. The guard derives Tag from ResourceID; callers cannot
// use this API to overwrite arbitrary Xray inbounds.
type TunnelResource struct {
	ResourceID      string     `json:"resource_id"`
	Tag             string     `json:"tag"`
	Generation      uint64     `json:"generation"`
	ListenIP        string     `json:"listen_ip"`
	ListenPort      int        `json:"listen_port"`
	TargetIP        string     `json:"target_ip"`
	TargetPort      int        `json:"target_port"`
	Network         string     `json:"network"`
	SourceCIDRs     []string   `json:"source_cidrs,omitempty"`
	HardNotAfter    time.Time  `json:"hard_not_after"`
	LeaseUntil      time.Time  `json:"lease_until"`
	State           string     `json:"state"`
	CleanupTerminal string     `json:"cleanup_terminal,omitempty"`
	Attempts        int        `json:"attempts,omitempty"`
	NextAttemptAt   *time.Time `json:"next_attempt_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type TunnelApplyRequest struct {
	ResourceID               string    `json:"resource_id"`
	Generation               uint64    `json:"generation"`
	ListenIP                 string    `json:"listen_ip,omitempty"`
	ListenPort               int       `json:"listen_port"`
	TargetIP                 string    `json:"target_ip"`
	TargetPort               int       `json:"target_port"`
	Network                  string    `json:"network"`
	SourceCIDRs              []string  `json:"source_cidrs,omitempty"`
	HardNotAfter             time.Time `json:"hard_not_after"`
	LeaseUntil               time.Time `json:"lease_until"`
	SpeedLimitBytesPerSecond uint64    `json:"speed_limit_bytes_per_second,omitempty"`
	ConnectionLimit          int       `json:"connection_limit,omitempty"`
}

type TunnelIdentityRequest struct {
	ResourceID string `json:"resource_id"`
	Generation uint64 `json:"generation,omitempty"`
}

type TunnelTraffic struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

type TunnelStatus struct {
	TunnelResource
	EffectiveNotAfter time.Time      `json:"effective_not_after"`
	Configured        bool           `json:"configured"`
	Running           bool           `json:"running"`
	ObservedState     string         `json:"observed_state"`
	ObservationError  string         `json:"observation_error,omitempty"`
	Traffic           *TunnelTraffic `json:"traffic,omitempty"`
}

type tunnelAPIError struct {
	status  int
	code    string
	message string
}

func (e *tunnelAPIError) Error() string { return e.message }

func tunnelErr(status int, code, message string) error {
	return &tunnelAPIError{status: status, code: code, message: message}
}

func tunnelTag(resourceID string) string {
	return tunnelidentity.Tag(resourceID)
}

func validResourceID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func normalizeIP(value, field string, defaultIP net.IP) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" && defaultIP != nil {
		value = defaultIP.String()
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", fmt.Errorf("%s must be an IP literal", field)
	}
	if ip.IsMulticast() {
		return "", fmt.Errorf("%s cannot be multicast", field)
	}
	return ip.String(), nil
}

func normalizeSourceCIDRs(values []string) ([]string, error) {
	if len(values) > 64 {
		return nil, errors.New("source_cidrs cannot contain more than 64 entries")
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid source CIDR %q", raw)
		}
		prefix, _ := network.Mask.Size()
		if prefix == 0 || network.IP.IsUnspecified() || network.IP.IsMulticast() {
			return nil, fmt.Errorf("source CIDR %q is not a bounded unicast range", raw)
		}
		canonical := network.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result, nil
}

func validPersistedTunnelNetwork(network string) bool {
	switch network {
	case tunnelNetworkTCP, tunnelNetworkUDP, tunnelNetworkTCPUDP:
		return true
	default:
		return false
	}
}

// All managed tunnel inbounds are installed as combined TCP+UDP listeners.
// "tcp" remains an apply-time alias for controllers deployed before tcp_udp
// became the canonical control-plane value.
func normalizeTunnelApplyNetwork(network string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "", tunnelNetworkTCP, tunnelNetworkTCPUDP:
		return tunnelNetworkTCPUDP, true
	default:
		return "", false
	}
}

func tunnelNetworksConflict(left, right string) bool {
	return validPersistedTunnelNetwork(left) && validPersistedTunnelNetwork(right)
}

func canUpgradeTunnelNetwork(current, requested string) bool {
	if current == requested {
		return true
	}
	return (current == tunnelNetworkTCP || current == tunnelNetworkUDP) && requested == tunnelNetworkTCPUDP
}

func normalizeTunnelApply(request TunnelApplyRequest, now time.Time) (TunnelResource, error) {
	request.ResourceID = strings.TrimSpace(request.ResourceID)
	if !validResourceID(request.ResourceID) {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "invalid_resource_id", "resource_id must be 8-128 URL-safe characters")
	}
	if request.Generation == 0 {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "invalid_generation", "generation must be greater than zero")
	}
	if request.ListenPort < 1024 || request.ListenPort > 65535 || request.TargetPort < 1 || request.TargetPort > 65535 {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "invalid_port", "listen_port must be 1024-65535 and target_port must be 1-65535")
	}
	listenIP, err := normalizeIP(request.ListenIP, "listen_ip", net.IPv4zero)
	if err != nil {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "invalid_listen_ip", err.Error())
	}
	targetIP, err := normalizeIP(request.TargetIP, "target_ip", nil)
	if err != nil || net.ParseIP(targetIP).IsUnspecified() {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "invalid_target_ip", "target_ip must be a non-unspecified IP literal")
	}
	network, supported := normalizeTunnelApplyNetwork(request.Network)
	if !supported {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "unsupported_network", "managed_tunnel_v1 requires tcp_udp (legacy tcp requests are accepted)")
	}
	sourceCIDRs, err := normalizeSourceCIDRs(request.SourceCIDRs)
	if err != nil {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "invalid_source_cidrs", err.Error())
	}
	if request.SpeedLimitBytesPerSecond != 0 || request.ConnectionLimit != 0 {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "capability_unavailable", "inbound_limiter_v1 is unavailable; non-zero tunnel limits are rejected")
	}
	if request.HardNotAfter.IsZero() || request.LeaseUntil.IsZero() {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "missing_expiry", "hard_not_after and lease_until are required")
	}
	hardNotAfter := request.HardNotAfter.UTC()
	leaseUntil := request.LeaseUntil.UTC()
	if !hardNotAfter.After(now) || !leaseUntil.After(now) {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "expired_deadline", "hard_not_after and lease_until must be in the future")
	}
	if leaseUntil.Sub(now) > maxTunnelLease {
		return TunnelResource{}, tunnelErr(http.StatusUnprocessableEntity, "lease_too_long", "lease_until cannot be more than 10 minutes in the future")
	}
	return TunnelResource{
		ResourceID:   request.ResourceID,
		Tag:          tunnelTag(request.ResourceID),
		Generation:   request.Generation,
		ListenIP:     listenIP,
		ListenPort:   request.ListenPort,
		TargetIP:     targetIP,
		TargetPort:   request.TargetPort,
		Network:      network,
		SourceCIDRs:  sourceCIDRs,
		HardNotAfter: hardNotAfter,
		LeaseUntil:   leaseUntil,
		State:        TunnelStateProvisioning,
		UpdatedAt:    now.UTC(),
	}, nil
}

func validTunnelState(state string) bool {
	switch state {
	case TunnelStateProvisioning, TunnelStateActive, TunnelStateSuspendPending, TunnelStateSuspended,
		TunnelStateDeletePending, TunnelStateDeleted, TunnelStateExpiryPending, TunnelStateExpired:
		return true
	default:
		return false
	}
}

func validatePersistedTunnelResource(resource TunnelResource) error {
	if !validResourceID(resource.ResourceID) || resource.Tag != tunnelTag(resource.ResourceID) || resource.Generation == 0 {
		return errors.New("invalid identity or generation")
	}
	if resource.ListenPort < 1024 || resource.ListenPort > 65535 || resource.TargetPort < 1 || resource.TargetPort > 65535 {
		return errors.New("invalid port")
	}
	if net.ParseIP(resource.ListenIP) == nil || net.ParseIP(resource.TargetIP) == nil || !validPersistedTunnelNetwork(resource.Network) {
		return errors.New("invalid TCP/UDP endpoint")
	}
	if resource.HardNotAfter.IsZero() || resource.LeaseUntil.IsZero() || resource.UpdatedAt.IsZero() || !validTunnelState(resource.State) {
		return errors.New("invalid lifecycle state")
	}
	if normalized, err := normalizeSourceCIDRs(resource.SourceCIDRs); err != nil || strings.Join(normalized, "\x00") != strings.Join(resource.SourceCIDRs, "\x00") {
		return errors.New("invalid source CIDRs")
	}
	return nil
}

func (resource TunnelResource) effectiveNotAfter() time.Time {
	if resource.LeaseUntil.Before(resource.HardNotAfter) {
		return resource.LeaseUntil
	}
	return resource.HardNotAfter
}

func boundedTunnelError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}

func (resource TunnelResource) reservesPort() bool {
	return resource.State != TunnelStateDeleted && resource.State != TunnelStateExpired
}

func (resource TunnelResource) needsACL() bool {
	return len(resource.SourceCIDRs) > 0 && resource.reservesPort()
}

func sameTunnelSpec(left, right TunnelResource) bool {
	return left.ResourceID == right.ResourceID && left.Tag == right.Tag && left.Generation == right.Generation &&
		left.ListenIP == right.ListenIP && left.ListenPort == right.ListenPort && left.TargetIP == right.TargetIP &&
		left.TargetPort == right.TargetPort && left.Network == right.Network &&
		strings.Join(left.SourceCIDRs, "\x00") == strings.Join(right.SourceCIDRs, "\x00") &&
		left.HardNotAfter.Equal(right.HardNotAfter)
}

func sameTunnelDefinition(left, right TunnelResource) bool {
	return left.ResourceID == right.ResourceID && left.Tag == right.Tag && left.ListenIP == right.ListenIP &&
		left.ListenPort == right.ListenPort && left.TargetIP == right.TargetIP && left.TargetPort == right.TargetPort &&
		canUpgradeTunnelNetwork(left.Network, right.Network) && strings.Join(left.SourceCIDRs, "\x00") == strings.Join(right.SourceCIDRs, "\x00")
}

func (g *Guard) SetCommandRunner(runner CommandRunner) {
	if runner != nil {
		g.commands = runner
	}
}

func (g *Guard) PendingTunnels() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	count := 0
	for _, resource := range g.tunnels {
		if resource.State == TunnelStateProvisioning || strings.HasSuffix(resource.State, "_pending") {
			count++
		}
	}
	return count
}

func (g *Guard) tunnelSnapshot(resourceID string) (TunnelResource, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	resource, exists := g.tunnels[resourceID]
	return resource, exists
}

func (g *Guard) storeTunnel(resource TunnelResource) error {
	g.mu.Lock()
	previous, existed := g.tunnels[resource.ResourceID]
	g.tunnels[resource.ResourceID] = resource
	committed, err := g.persistLocked()
	if err != nil && !committed {
		if existed {
			g.tunnels[resource.ResourceID] = previous
		} else {
			delete(g.tunnels, resource.ResourceID)
		}
	}
	g.mu.Unlock()
	return err
}

func (g *Guard) checkDurablePort(resource TunnelResource) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, other := range g.tunnels {
		if other.ResourceID != resource.ResourceID && other.reservesPort() &&
			tunnelNetworksConflict(other.Network, resource.Network) && other.ListenPort == resource.ListenPort {
			return tunnelErr(http.StatusConflict, "port_reserved", fmt.Sprintf("TCP/UDP port %d is reserved by another managed resource", resource.ListenPort))
		}
	}
	return nil
}

type agentInboundObservation struct {
	Tag        string
	ListenIP   string
	Port       int
	Configured bool
	Running    bool
	Inbound    map[string]interface{}
}

func intFromJSON(value interface{}) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := strconv.Atoi(typed.String())
		return parsed
	case int:
		return typed
	default:
		parsed, _ := strconv.Atoi(strings.TrimSpace(fmt.Sprint(value)))
		return parsed
	}
}

func (g *Guard) listAgentInbounds(ctx context.Context) ([]agentInboundObservation, error) {
	raw, err := g.agentRequest(ctx, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode Agent inbound list: %w", err)
	}
	if !response.Success {
		return nil, errors.New("Agent did not acknowledge inbound list")
	}
	result := make([]agentInboundObservation, 0, len(response.Inbounds))
	for _, inbound := range response.Inbounds {
		tag, _ := inbound["tag"].(string)
		listenIP, _ := inbound["listen"].(string)
		runtimeStatus, _ := inbound["_runtime_status"].(string)
		source, _ := inbound["_source"].(string)
		result = append(result, agentInboundObservation{
			Tag:        tag,
			ListenIP:   listenIP,
			Port:       intFromJSON(inbound["port"]),
			Configured: source != "runtime_only",
			Running:    runtimeStatus == "running",
			Inbound:    inbound,
		})
	}
	return result, nil
}

func observeInbound(inbounds []agentInboundObservation, tag string) (agentInboundObservation, bool) {
	for _, inbound := range inbounds {
		if inbound.Tag == tag {
			return inbound, true
		}
	}
	return agentInboundObservation{}, false
}

func portConflicts(inbounds []agentInboundObservation, resource TunnelResource) bool {
	for _, inbound := range inbounds {
		if inbound.Tag != resource.Tag && inbound.Port == resource.ListenPort {
			return true
		}
	}
	return false
}

func tunnelInbound(resource TunnelResource) map[string]interface{} {
	return map[string]interface{}{
		"tag":      resource.Tag,
		"listen":   resource.ListenIP,
		"port":     resource.ListenPort,
		"protocol": "dokodemo-door",
		"settings": map[string]interface{}{
			"address":        resource.TargetIP,
			"port":           resource.TargetPort,
			"network":        xrayNetworkTCPUDP,
			"followRedirect": false,
		},
		"sniffing": map[string]interface{}{"enabled": false},
	}
}

func decodeAgentMutationACK(raw []byte) (bool, error) {
	var ack struct {
		Success        bool   `json:"success"`
		Warning        string `json:"warning"`
		RuntimeWarning string `json:"runtime_warning"`
	}
	if err := json.Unmarshal(raw, &ack); err != nil {
		return false, fmt.Errorf("decode Agent mutation ACK: %w", err)
	}
	if !ack.Success {
		return false, errors.New("Agent did not acknowledge inbound mutation")
	}
	return strings.TrimSpace(ack.Warning) != "" || strings.TrimSpace(ack.RuntimeWarning) != "", nil
}

func (g *Guard) applyTunnelInbound(ctx context.Context, resource TunnelResource) error {
	raw, err := g.agentRequest(ctx, http.MethodPost, "/api/child/inbounds", map[string]interface{}{
		"action":  "add",
		"inbound": tunnelInbound(resource),
	})
	if err != nil {
		return err
	}
	deferred, err := decodeAgentMutationACK(raw)
	if err != nil {
		return err
	}
	if deferred {
		if err := g.restartXray(ctx); err != nil {
			return err
		}
	}
	inbounds, err := g.listAgentInbounds(ctx)
	if err != nil {
		return fmt.Errorf("verify applied tunnel inbound: %w", err)
	}
	observed, exists := observeInbound(inbounds, resource.Tag)
	if !exists || !observed.Configured || !observed.Running || observed.Port != resource.ListenPort {
		return errors.New("Agent did not expose the applied tunnel inbound as configured and running")
	}
	return nil
}

func (g *Guard) removeTunnelInbound(ctx context.Context, resource TunnelResource) error {
	raw, err := g.agentRequest(ctx, http.MethodPost, "/api/child/inbounds", map[string]interface{}{
		"action": "remove",
		"tag":    resource.Tag,
	})
	if err != nil {
		return err
	}
	if _, err := decodeAgentMutationACK(raw); err != nil {
		return err
	}
	inbounds, err := g.listAgentInbounds(ctx)
	if err != nil {
		return fmt.Errorf("verify removed tunnel inbound: %w", err)
	}
	if _, exists := observeInbound(inbounds, resource.Tag); !exists {
		return nil
	}
	if err := g.restartXray(ctx); err != nil {
		return err
	}
	inbounds, err = g.listAgentInbounds(ctx)
	if err != nil {
		return err
	}
	if _, exists := observeInbound(inbounds, resource.Tag); exists {
		return errors.New("tunnel inbound remains after Agent removal and Xray restart")
	}
	return nil
}

func (g *Guard) nftAvailable(ctx context.Context) bool {
	if g.commands == nil {
		return false
	}
	if _, err := g.commands.CombinedOutput(ctx, "nft", "--version"); err != nil {
		return false
	}
	_, err := g.commands.CombinedOutput(ctx, "nft", "list", "ruleset")
	return err == nil
}

func (g *Guard) aclResources(excludeResourceID string) []TunnelResource {
	g.mu.Lock()
	defer g.mu.Unlock()
	resources := make([]TunnelResource, 0)
	for _, resource := range g.tunnels {
		if resource.ResourceID != excludeResourceID && resource.needsACL() {
			resources = append(resources, resource)
		}
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].ListenPort != resources[j].ListenPort {
			return resources[i].ListenPort < resources[j].ListenPort
		}
		return resources[i].ResourceID < resources[j].ResourceID
	})
	return resources
}

func buildNFTablesRules(resources []TunnelResource, tableExists bool) string {
	var builder strings.Builder
	if tableExists {
		builder.WriteString("delete table inet arcway_forwarding\n")
	}
	builder.WriteString("table inet arcway_forwarding {\n")
	builder.WriteString("  chain input {\n")
	builder.WriteString("    type filter hook input priority -20; policy accept;\n")
	for _, resource := range resources {
		var v4, v6 []string
		for _, source := range resource.SourceCIDRs {
			ip, _, _ := net.ParseCIDR(source)
			if ip.To4() != nil {
				v4 = append(v4, source)
			} else {
				v6 = append(v6, source)
			}
		}
		if len(v4) > 0 {
			fmt.Fprintf(&builder, "    ip saddr { %s } tcp dport %d accept\n", strings.Join(v4, ", "), resource.ListenPort)
			fmt.Fprintf(&builder, "    ip saddr { %s } udp dport %d accept\n", strings.Join(v4, ", "), resource.ListenPort)
		}
		if len(v6) > 0 {
			fmt.Fprintf(&builder, "    ip6 saddr { %s } tcp dport %d accept\n", strings.Join(v6, ", "), resource.ListenPort)
			fmt.Fprintf(&builder, "    ip6 saddr { %s } udp dport %d accept\n", strings.Join(v6, ", "), resource.ListenPort)
		}
		fmt.Fprintf(&builder, "    tcp dport %d drop\n", resource.ListenPort)
		fmt.Fprintf(&builder, "    udp dport %d drop\n", resource.ListenPort)
	}
	builder.WriteString("  }\n")
	builder.WriteString("}\n")
	return builder.String()
}

func (g *Guard) applyNFTablesRules(ctx context.Context, resources []TunnelResource) error {
	g.aclMu.Lock()
	defer g.aclMu.Unlock()
	if !g.nftAvailable(ctx) {
		return errors.New("nftables is unavailable")
	}
	_, listErr := g.commands.CombinedOutput(ctx, "nft", "list", "table", "inet", "arcway_forwarding")
	script := buildNFTablesRules(resources, listErr == nil)
	temporary, err := os.CreateTemp("", ".arcway-forwarding-nft-*.conf")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(script); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if output, err := g.commands.CombinedOutput(ctx, "nft", "-c", "-f", path); err != nil {
		return fmt.Errorf("validate nftables tunnel ACL: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := g.commands.CombinedOutput(ctx, "nft", "-f", path); err != nil {
		return fmt.Errorf("apply nftables tunnel ACL: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (g *Guard) rebuildTunnelACL(ctx context.Context, excludeResourceID string) error {
	return g.applyNFTablesRules(ctx, g.aclResources(excludeResourceID))
}

// PrepareTunnelACL reconstructs the guard-owned nftables table after restart.
// It is a no-op when no persisted resource uses source CIDRs.
func (g *Guard) PrepareTunnelACL(ctx context.Context) error {
	resources := g.aclResources("")
	if len(resources) == 0 && !g.nftAvailable(ctx) {
		return nil
	}
	return g.applyNFTablesRules(ctx, resources)
}

// failClosedTunnelACL schedules every live ACL-protected inbound for immediate
// withdrawal. A host reboot must not leave a persisted Xray inbound exposed
// while the nftables table is missing or cannot be restored.
func (g *Guard) failClosedTunnelACL(cause error) {
	now := time.Now().UTC()
	g.mu.Lock()
	changed := false
	for id, resource := range g.tunnels {
		if len(resource.SourceCIDRs) == 0 {
			continue
		}
		switch resource.State {
		case TunnelStateActive, TunnelStateProvisioning:
			resource.State = TunnelStateExpiryPending
			resource.CleanupTerminal = TunnelStateSuspended
			resource.LastError = boundedTunnelError(fmt.Errorf("source ACL restore failed: %w", cause))
			resource.UpdatedAt = now
			resource.NextAttemptAt = nil
			resource.Attempts = 0
			g.tunnels[id] = resource
			changed = true
		}
	}
	if changed {
		_, _ = g.persistLocked()
	}
	g.mu.Unlock()
	if changed {
		g.notify()
	}
}

// InitializeTunnelSafety restores ACLs before the guard starts serving. If the
// ACL transaction fails, every affected inbound is synchronously withdrawn (or
// left in durable cleanup_pending state for Run to retry) before returning.
func (g *Guard) InitializeTunnelSafety(ctx context.Context) error {
	aclErr := g.PrepareTunnelACL(ctx)
	if aclErr != nil {
		g.failClosedTunnelACL(aclErr)
	}
	due, _ := g.dueTunnels(time.Now().UTC())
	for _, resource := range due {
		g.expireOrCleanupTunnel(ctx, resource)
	}
	if aclErr != nil {
		return fmt.Errorf("restore tunnel source ACLs: %w; affected inbounds were withdrawn", aclErr)
	}
	return nil
}

func (g *Guard) ApplyTunnel(ctx context.Context, request TunnelApplyRequest) (TunnelResource, bool, error) {
	g.tunnelOpsMu.Lock()
	defer g.tunnelOpsMu.Unlock()

	now := time.Now().UTC()
	resource, err := normalizeTunnelApply(request, now)
	if err != nil {
		return TunnelResource{}, false, err
	}
	if len(resource.SourceCIDRs) > 0 && !g.nftAvailable(ctx) {
		return TunnelResource{}, false, tunnelErr(http.StatusUnprocessableEntity, "capability_unavailable", "inbound_acl_v1 requires nftables on this server")
	}

	current, exists := g.tunnelSnapshot(resource.ResourceID)
	if exists {
		if current.State == TunnelStateDeleted || current.State == TunnelStateDeletePending {
			return current, false, tunnelErr(http.StatusConflict, "resource_deleted", "deleted resource IDs cannot be reused")
		}
		if resource.Generation < current.Generation {
			return current, false, tunnelErr(http.StatusConflict, "stale_generation", "generation is older than the durable resource")
		}
		if resource.Generation == current.Generation {
			if current.State != TunnelStateActive {
				return current, false, tunnelErr(http.StatusConflict, "generation_conflict", "the current generation is not active; use a newer generation")
			}
			if !sameTunnelSpec(current, resource) {
				return current, false, tunnelErr(http.StatusConflict, "generation_conflict", "the same generation cannot change tunnel configuration")
			}
			if !current.effectiveNotAfter().After(now) {
				return current, false, tunnelErr(http.StatusConflict, "lease_expired", "an expired generation cannot be renewed; use a newer generation")
			}
			if !resource.LeaseUntil.After(current.LeaseUntil) {
				return current, false, nil
			}
			current.LeaseUntil = resource.LeaseUntil
			current.UpdatedAt = now
			current.LastError = ""
			if err := g.storeTunnel(current); err != nil {
				return current, false, tunnelErr(http.StatusInternalServerError, "state_persist_failed", "renewed lease was not durably persisted")
			}
			g.notify()
			return current, true, nil
		}
		if !sameTunnelDefinition(current, resource) {
			return current, false, tunnelErr(http.StatusConflict, "resource_definition_conflict", "listen, target, network, and source CIDRs are immutable; create a new resource")
		}
	}
	if err := g.checkDurablePort(resource); err != nil {
		return TunnelResource{}, false, err
	}
	inbounds, err := g.listAgentInbounds(ctx)
	if err != nil {
		return TunnelResource{}, false, tunnelErr(http.StatusBadGateway, "agent_preflight_failed", "Agent inbound state is unavailable; port allocation failed closed")
	}
	if portConflicts(inbounds, resource) {
		return TunnelResource{}, false, tunnelErr(http.StatusConflict, "port_in_use", fmt.Sprintf("TCP/UDP port %d is already used by an Agent inbound", resource.ListenPort))
	}
	resource.CleanupTerminal = TunnelStateSuspended
	if err := g.storeTunnel(resource); err != nil {
		g.notify()
		return resource, false, tunnelErr(http.StatusInternalServerError, "state_persist_failed", "provisioning state was not durably persisted")
	}
	if len(resource.SourceCIDRs) > 0 {
		if err := g.rebuildTunnelACL(ctx, ""); err != nil {
			resource.LastError = boundedTunnelError(err)
			_ = g.storeTunnel(resource)
			g.notify()
			return resource, false, tunnelErr(http.StatusBadGateway, "acl_apply_failed", "source ACL could not be applied")
		}
	}
	if err := g.applyTunnelInbound(ctx, resource); err != nil {
		resource.LastError = boundedTunnelError(err)
		next := now
		resource.NextAttemptAt = &next
		_ = g.storeTunnel(resource)
		g.notify()
		return resource, false, tunnelErr(http.StatusBadGateway, "agent_apply_failed", "Agent did not atomically apply the tunnel inbound")
	}
	resource.State = TunnelStateActive
	resource.CleanupTerminal = ""
	resource.LastError = ""
	resource.NextAttemptAt = nil
	resource.UpdatedAt = time.Now().UTC()
	if err := g.storeTunnel(resource); err != nil {
		// The durable state must never lag behind a live inbound. Fail closed and
		// leave a cleanup record for the scheduler.
		resource.State = TunnelStateProvisioning
		resource.CleanupTerminal = TunnelStateSuspended
		resource.LastError = "final active state was not durably persisted"
		next := time.Now().UTC()
		resource.NextAttemptAt = &next
		_ = g.storeTunnel(resource)
		_ = g.removeTunnelInbound(ctx, resource)
		g.notify()
		return resource, false, tunnelErr(http.StatusInternalServerError, "state_persist_failed", "active state was not durably persisted; inbound was withdrawn")
	}
	return resource, true, nil
}

func (g *Guard) transitionTunnelForCleanup(ctx context.Context, request TunnelIdentityRequest, terminal string) (TunnelResource, bool, error) {
	g.tunnelOpsMu.Lock()
	defer g.tunnelOpsMu.Unlock()
	request.ResourceID = strings.TrimSpace(request.ResourceID)
	if !validResourceID(request.ResourceID) || request.Generation == 0 {
		return TunnelResource{}, false, tunnelErr(http.StatusUnprocessableEntity, "invalid_identity", "resource_id and a positive generation are required")
	}
	resource, exists := g.tunnelSnapshot(request.ResourceID)
	if !exists {
		return TunnelResource{}, false, tunnelErr(http.StatusNotFound, "not_found", "managed tunnel resource not found")
	}
	if request.Generation < resource.Generation {
		return resource, false, tunnelErr(http.StatusConflict, "stale_generation", "generation is older than the durable resource")
	}
	if terminal == TunnelStateSuspended && (resource.State == TunnelStateDeleted || resource.State == TunnelStateDeletePending) {
		return resource, false, tunnelErr(http.StatusConflict, "resource_deleted", "deleted resources cannot be suspended")
	}
	if request.Generation == resource.Generation && resource.State == terminal {
		return resource, false, nil
	}
	if request.Generation == resource.Generation && strings.HasSuffix(resource.State, "_pending") && resource.CleanupTerminal == terminal {
		return resource, false, nil
	}
	resource.Generation = request.Generation
	resource.State = map[string]string{TunnelStateSuspended: TunnelStateSuspendPending, TunnelStateDeleted: TunnelStateDeletePending}[terminal]
	resource.CleanupTerminal = terminal
	resource.Attempts = 0
	resource.NextAttemptAt = nil
	resource.LastError = ""
	resource.UpdatedAt = time.Now().UTC()
	if err := g.storeTunnel(resource); err != nil {
		return resource, false, tunnelErr(http.StatusInternalServerError, "state_persist_failed", "cleanup intent was not durably persisted")
	}
	if err := g.removeTunnelInbound(ctx, resource); err != nil {
		resource.LastError = boundedTunnelError(err)
		next := time.Now().UTC().Add(retryDelay(1))
		resource.NextAttemptAt = &next
		resource.Attempts = 1
		_ = g.storeTunnel(resource)
		g.notify()
		return resource, false, tunnelErr(http.StatusBadGateway, "agent_remove_failed", "Agent did not confirm tunnel inbound removal")
	}
	if len(resource.SourceCIDRs) > 0 {
		if err := g.rebuildTunnelACL(ctx, resource.ResourceID); err != nil {
			resource.LastError = boundedTunnelError(err)
			next := time.Now().UTC().Add(retryDelay(1))
			resource.NextAttemptAt = &next
			resource.Attempts = 1
			_ = g.storeTunnel(resource)
			g.notify()
			return resource, false, tunnelErr(http.StatusBadGateway, "acl_cleanup_failed", "tunnel inbound was removed but source ACL cleanup is pending")
		}
	}
	resource.State = terminal
	resource.CleanupTerminal = ""
	resource.Attempts = 0
	resource.NextAttemptAt = nil
	resource.LastError = ""
	resource.UpdatedAt = time.Now().UTC()
	if err := g.storeTunnel(resource); err != nil {
		g.notify()
		return resource, false, tunnelErr(http.StatusInternalServerError, "state_persist_failed", "terminal state was not durably persisted")
	}
	return resource, true, nil
}

func (g *Guard) SuspendTunnel(ctx context.Context, request TunnelIdentityRequest) (TunnelResource, bool, error) {
	return g.transitionTunnelForCleanup(ctx, request, TunnelStateSuspended)
}

func (g *Guard) DeleteTunnel(ctx context.Context, request TunnelIdentityRequest) (TunnelResource, bool, error) {
	return g.transitionTunnelForCleanup(ctx, request, TunnelStateDeleted)
}

func (g *Guard) tunnelTraffic(ctx context.Context, tag string) (*TunnelTraffic, error) {
	raw, err := g.agentRequest(ctx, http.MethodGet, "/api/child/traffic", nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Success bool `json:"success"`
		Stats   struct {
			Inbound map[string]TunnelTraffic `json:"inbound"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || !response.Success {
		return nil, errors.New("Agent traffic response is unavailable")
	}
	traffic, exists := response.Stats.Inbound[tag]
	if !exists {
		return nil, nil
	}
	return &traffic, nil
}

func (g *Guard) TunnelStatus(ctx context.Context, request TunnelIdentityRequest) (TunnelStatus, error) {
	request.ResourceID = strings.TrimSpace(request.ResourceID)
	if !validResourceID(request.ResourceID) {
		return TunnelStatus{}, tunnelErr(http.StatusUnprocessableEntity, "invalid_resource_id", "invalid resource_id")
	}
	resource, exists := g.tunnelSnapshot(request.ResourceID)
	if !exists {
		return TunnelStatus{}, tunnelErr(http.StatusNotFound, "not_found", "managed tunnel resource not found")
	}
	status := TunnelStatus{TunnelResource: resource, EffectiveNotAfter: resource.effectiveNotAfter(), ObservedState: "unknown"}
	inbounds, err := g.listAgentInbounds(ctx)
	if err != nil {
		status.ObservationError = "Agent inbound state unavailable"
		return status, nil
	}
	if observed, found := observeInbound(inbounds, resource.Tag); found {
		status.Configured = observed.Configured
		status.Running = observed.Running
	}
	switch {
	case status.Configured && status.Running:
		status.ObservedState = "active"
	case status.Configured:
		status.ObservedState = "configured"
	case status.Running:
		status.ObservedState = "runtime_only"
	default:
		status.ObservedState = "absent"
	}
	if traffic, trafficErr := g.tunnelTraffic(ctx, resource.Tag); trafficErr == nil {
		status.Traffic = traffic
	}
	return status, nil
}

func (g *Guard) dueTunnels(now time.Time) ([]TunnelResource, time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	due := make([]TunnelResource, 0)
	var next time.Time
	for _, resource := range g.tunnels {
		var attemptAt time.Time
		switch resource.State {
		case TunnelStateActive:
			attemptAt = resource.effectiveNotAfter()
		case TunnelStateProvisioning, TunnelStateSuspendPending, TunnelStateDeletePending, TunnelStateExpiryPending:
			attemptAt = resource.UpdatedAt
		default:
			continue
		}
		if resource.NextAttemptAt != nil && resource.NextAttemptAt.After(attemptAt) {
			attemptAt = *resource.NextAttemptAt
		}
		if !now.Before(attemptAt) {
			due = append(due, resource)
		} else if next.IsZero() || attemptAt.Before(next) {
			next = attemptAt
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].ResourceID < due[j].ResourceID })
	return due, next
}

func (g *Guard) expireOrCleanupTunnel(ctx context.Context, expected TunnelResource) {
	g.tunnelOpsMu.Lock()
	defer g.tunnelOpsMu.Unlock()
	resource, exists := g.tunnelSnapshot(expected.ResourceID)
	if !exists || resource.Generation != expected.Generation || resource.State != expected.State {
		return
	}
	if resource.State == TunnelStateActive {
		if time.Now().UTC().Before(resource.effectiveNotAfter()) {
			return
		}
		resource.State = TunnelStateExpiryPending
		resource.CleanupTerminal = TunnelStateExpired
		resource.UpdatedAt = time.Now().UTC()
		resource.Attempts = 0
		resource.NextAttemptAt = nil
		if err := g.storeTunnel(resource); err != nil {
			return
		}
	}
	if err := g.removeTunnelInbound(ctx, resource); err != nil {
		resource.Attempts++
		next := time.Now().UTC().Add(retryDelay(resource.Attempts))
		resource.NextAttemptAt = &next
		resource.LastError = boundedTunnelError(err)
		resource.UpdatedAt = time.Now().UTC()
		_ = g.storeTunnel(resource)
		return
	}
	if len(resource.SourceCIDRs) > 0 {
		if err := g.rebuildTunnelACL(ctx, resource.ResourceID); err != nil {
			resource.Attempts++
			next := time.Now().UTC().Add(retryDelay(resource.Attempts))
			resource.NextAttemptAt = &next
			resource.LastError = boundedTunnelError(err)
			resource.UpdatedAt = time.Now().UTC()
			_ = g.storeTunnel(resource)
			return
		}
	}
	terminal := resource.CleanupTerminal
	if terminal == "" {
		terminal = TunnelStateSuspended
	}
	resource.State = terminal
	resource.CleanupTerminal = ""
	resource.Attempts = 0
	resource.NextAttemptAt = nil
	resource.LastError = ""
	resource.UpdatedAt = time.Now().UTC()
	_ = g.storeTunnel(resource)
}

func (g *Guard) tunnelCapabilities(ctx context.Context) map[string]interface{} {
	acl := g.nftAvailable(ctx)
	return map[string]interface{}{
		"managed_tunnel_v1":  true,
		"inbound_expiry_v1":  true,
		"inbound_acl_v1":     acl,
		"inbound_limiter_v1": false,
		"inbound_stats_v1":   false,
		"tunnel_networks":    []string{tunnelNetworkTCPUDP},
		"max_lease_seconds":  int(maxTunnelLease.Seconds()),
		"stats_semantics":    "best_effort; counters can reset with Xray",
		"tunnel_operations":  []string{"apply", "status", "suspend", "remove"},
	}
}

func writeTunnelAPIError(w http.ResponseWriter, err error) {
	var apiErr *tunnelAPIError
	if errors.As(err, &apiErr) {
		writeJSON(w, apiErr.status, map[string]interface{}{"success": false, "code": apiErr.code, "error": apiErr.message})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "code": "internal_error", "error": "internal tunnel operation failure"})
}

func (g *Guard) openTunnelRequest(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	raw, err := g.openRequest(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"success": false, "error": "unauthorized"})
		return false
	}
	if err := decodeRequest(raw, target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "invalid tunnel request"})
		return false
	}
	return true
}

func (g *Guard) registerTunnelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("PUT /v1/tunnels/apply", func(w http.ResponseWriter, r *http.Request) {
		var request TunnelApplyRequest
		if !g.openTunnelRequest(w, r, &request) {
			return
		}
		resource, changed, err := g.ApplyTunnel(r.Context(), request)
		if err != nil {
			writeTunnelAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "changed": changed, "resource": resource})
	})
	mux.HandleFunc("POST /v1/tunnels/status", func(w http.ResponseWriter, r *http.Request) {
		var request TunnelIdentityRequest
		if !g.openTunnelRequest(w, r, &request) {
			return
		}
		status, err := g.TunnelStatus(r.Context(), request)
		if err != nil {
			writeTunnelAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "resource": status})
	})
	mux.HandleFunc("POST /v1/tunnels/suspend", func(w http.ResponseWriter, r *http.Request) {
		var request TunnelIdentityRequest
		if !g.openTunnelRequest(w, r, &request) {
			return
		}
		resource, changed, err := g.SuspendTunnel(r.Context(), request)
		if err != nil {
			writeTunnelAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "changed": changed, "resource": resource})
	})
	remove := func(w http.ResponseWriter, r *http.Request) {
		var request TunnelIdentityRequest
		if !g.openTunnelRequest(w, r, &request) {
			return
		}
		resource, changed, err := g.DeleteTunnel(r.Context(), request)
		if err != nil {
			writeTunnelAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "changed": changed, "resource": resource})
	}
	mux.HandleFunc("DELETE /v1/tunnels/remove", remove)
	mux.HandleFunc("DELETE /v1/tunnels/delete", remove)
}
