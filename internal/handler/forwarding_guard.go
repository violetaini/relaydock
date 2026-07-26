package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/tunnelidentity"
)

const (
	forwardingGuardReadyTTL      = 2 * time.Minute
	forwardingGuardTunnelNetwork = "tcp_udp"
)

type forwardingGuardReadiness struct {
	checkedAt time.Time
	tokenHash [sha256.Size]byte
	full      bool
}

// ForwardingGuardDeployer sends tunnel mutations only through the signed,
// durable expiry-guard API installed beside each mmw-agent.
type ForwardingGuardDeployer struct {
	managed *ManagedNodesHandler

	mu    sync.Mutex
	ready map[int64]forwardingGuardReadiness
	now   func() time.Time
}

func NewForwardingGuardDeployer(managed *ManagedNodesHandler) *ForwardingGuardDeployer {
	return &ForwardingGuardDeployer{
		managed: managed,
		ready:   make(map[int64]forwardingGuardReadiness),
		now:     time.Now,
	}
}

type forwardingGuardCapabilities struct {
	ManagedTunnelV1 bool     `json:"managed_tunnel_v1"`
	InboundExpiryV1 bool     `json:"inbound_expiry_v1"`
	InboundACLV1    bool     `json:"inbound_acl_v1"`
	TunnelNetworks  []string `json:"tunnel_networks"`
	MaxLeaseSeconds int      `json:"max_lease_seconds"`
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func forwardingGuardHasRequiredCapabilities(capabilities forwardingGuardCapabilities) bool {
	return forwardingGuardHasBasicCapabilities(capabilities) && capabilities.InboundACLV1 &&
		containsString(capabilities.TunnelNetworks, forwardingGuardTunnelNetwork) && capabilities.MaxLeaseSeconds >= 300
}

func forwardingGuardHasBasicCapabilities(capabilities forwardingGuardCapabilities) bool {
	return capabilities.ManagedTunnelV1 && capabilities.InboundExpiryV1
}

func (d *ForwardingGuardDeployer) ensureReady(ctx context.Context, serverID int64, requireFullCapabilities bool) error {
	if d == nil || d.managed == nil || d.managed.repo == nil {
		return errors.New("managed tunnel guard is unavailable")
	}
	server, err := d.managed.repo.GetRemoteServer(ctx, serverID)
	if err != nil || server == nil {
		return errors.New("managed tunnel server is unavailable")
	}
	now := d.now().UTC()
	tokenHash := sha256.Sum256([]byte(server.Token))
	d.mu.Lock()
	cached, ok := d.ready[serverID]
	d.mu.Unlock()
	if ok && cached.tokenHash == tokenHash && now.Sub(cached.checkedAt) < forwardingGuardReadyTTL &&
		(!requireFullCapabilities || cached.full) {
		return nil
	}

	body, err := d.managed.callManagedExpiryGuard(ctx, serverID, http.MethodGet, "/v1/capabilities", nil)
	if err != nil {
		return fmt.Errorf("managed tunnel capability handshake: %w", err)
	}
	var capabilities forwardingGuardCapabilities
	if err := json.Unmarshal(body, &capabilities); err != nil {
		return errors.New("managed tunnel guard returned invalid capabilities")
	}
	if !forwardingGuardHasBasicCapabilities(capabilities) {
		return errors.New("managed tunnel guard lacks required tunnel or expiry capability")
	}
	if err := d.managed.syncManagedExpiryGuardAgentToken(ctx, serverID, server.Token); err != nil {
		return errors.New("managed tunnel guard Agent token synchronization failed")
	}
	full := forwardingGuardHasRequiredCapabilities(capabilities)
	d.mu.Lock()
	d.ready[serverID] = forwardingGuardReadiness{checkedAt: now, tokenHash: tokenHash, full: full}
	d.mu.Unlock()
	if requireFullCapabilities && !full {
		return errors.New("managed tunnel guard lacks required TCP+UDP, expiry, or ACL capability")
	}
	return nil
}

func (d *ForwardingGuardDeployer) Probe(ctx context.Context, serverID int64) error {
	return d.ensureReady(ctx, serverID, true)
}

func forwardingGuardErrorCode(body []byte) string {
	var envelope struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	return envelope.Code
}

func classifyForwardingGuardError(err error) error {
	if err == nil {
		return nil
	}
	var responseErr *managedExpiryGuardHTTPError
	if errors.As(err, &responseErr) {
		code := forwardingGuardErrorCode(responseErr.Body)
		if code == "port_in_use" || code == "port_reserved" {
			return fmt.Errorf("%w: %v", ErrForwardTunnelPortInUse, err)
		}
	}
	message := err.Error()
	if strings.Contains(message, `"code":"port_in_use"`) || strings.Contains(message, `"code": "port_in_use"`) ||
		strings.Contains(message, `"code":"port_reserved"`) || strings.Contains(message, `"code": "port_reserved"`) {
		return fmt.Errorf("%w: %v", ErrForwardTunnelPortInUse, err)
	}
	return err
}

func validateForwardingGuardACK(body []byte, resourceID, tag string, generation int64, state string) error {
	var ack struct {
		Success  bool `json:"success"`
		Resource struct {
			ResourceID string `json:"resource_id"`
			Tag        string `json:"tag"`
			Generation int64  `json:"generation"`
			State      string `json:"state"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &ack); err != nil || !ack.Success || ack.Resource.ResourceID != resourceID ||
		ack.Resource.Tag != tag || ack.Resource.Generation != generation || ack.Resource.State != state {
		return errors.New("managed tunnel guard did not acknowledge the operation")
	}
	return nil
}

func forwardingGuardApplyPayload(spec ForwardTunnelSpec) map[string]any {
	return map[string]any{
		"resource_id":    spec.ResourceID,
		"generation":     spec.Generation,
		"listen_ip":      "0.0.0.0",
		"listen_port":    spec.ListenPort,
		"target_ip":      spec.TargetHost,
		"target_port":    spec.TargetPort,
		"network":        forwardingGuardTunnelNetwork,
		"source_cidrs":   spec.SourceCIDRs,
		"hard_not_after": spec.HardNotAfter.UTC(),
		"lease_until":    spec.LeaseUntil.UTC(),
	}
}

func (d *ForwardingGuardDeployer) Apply(ctx context.Context, spec ForwardTunnelSpec) error {
	if err := d.ensureReady(ctx, spec.ServerID, true); err != nil {
		return err
	}
	if spec.HardNotAfter == nil {
		return errors.New("managed tunnel hard expiry is required")
	}
	payload := forwardingGuardApplyPayload(spec)
	body, err := d.managed.callManagedExpiryGuard(ctx, spec.ServerID, http.MethodPut, "/v1/tunnels/apply", payload)
	if err != nil {
		return classifyForwardingGuardError(err)
	}
	return validateForwardingGuardACK(body, spec.ResourceID, spec.Tag, spec.Generation, "active")
}

func (d *ForwardingGuardDeployer) mutate(ctx context.Context, serverID int64, resourceID string, generation int64, method, path string) error {
	if err := d.ensureReady(ctx, serverID, false); err != nil {
		return err
	}
	body, err := d.managed.callManagedExpiryGuard(ctx, serverID, method, path, map[string]any{
		"resource_id": resourceID,
		"generation":  generation,
	})
	if err != nil {
		// Only the current Guard's structured not_found response is an idempotent
		// removal. A proxy or old endpoint returning a generic 404 fails closed.
		var responseErr *managedExpiryGuardHTTPError
		if method == http.MethodDelete && errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusNotFound &&
			forwardingGuardErrorCode(responseErr.Body) == "not_found" {
			return nil
		}
		return err
	}
	expectedState := "suspended"
	if method == http.MethodDelete {
		expectedState = "deleted"
	}
	return validateForwardingGuardACK(body, resourceID, tunnelidentity.Tag(resourceID), generation, expectedState)
}

func (d *ForwardingGuardDeployer) Suspend(ctx context.Context, serverID int64, resourceID string, generation int64) error {
	return d.mutate(ctx, serverID, resourceID, generation, http.MethodPost, "/v1/tunnels/suspend")
}

func (d *ForwardingGuardDeployer) Remove(ctx context.Context, serverID int64, resourceID string, generation int64) error {
	return d.mutate(ctx, serverID, resourceID, generation, http.MethodDelete, "/v1/tunnels/remove")
}
