package expiryguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/guardwire"
)

type fakeTunnelAgent struct {
	mu            sync.Mutex
	inbounds      map[string]map[string]interface{}
	addCalls      int
	removeCalls   int
	failList      bool
	failAdd       bool
	failRemove    bool
	traffic       map[string]TunnelTraffic
	lastAdd       map[string]interface{}
	authorization string
}

func newFakeTunnelAgent() *fakeTunnelAgent {
	return &fakeTunnelAgent{
		inbounds: make(map[string]map[string]interface{}),
		traffic:  make(map[string]TunnelTraffic),
	}
}

func cloneMap(value map[string]interface{}) map[string]interface{} {
	raw, _ := json.Marshal(value)
	var cloned map[string]interface{}
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func (agent *fakeTunnelAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	agent.authorization = r.Header.Get("Authorization")
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/child/inbounds":
		if r.Method == http.MethodGet {
			if agent.failList {
				http.Error(w, "list failed", http.StatusServiceUnavailable)
				return
			}
			items := make([]map[string]interface{}, 0, len(agent.inbounds))
			for _, inbound := range agent.inbounds {
				item := cloneMap(inbound)
				item["_source"] = "config"
				item["_runtime_status"] = "running"
				items = append(items, item)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "inbounds": items})
			return
		}
		var request struct {
			Action  string                 `json:"action"`
			Inbound map[string]interface{} `json:"inbound"`
			Tag     string                 `json:"tag"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch request.Action {
		case "add":
			agent.addCalls++
			if agent.failAdd {
				http.Error(w, "add failed", http.StatusInternalServerError)
				return
			}
			tag, _ := request.Inbound["tag"].(string)
			agent.inbounds[tag] = cloneMap(request.Inbound)
			agent.lastAdd = cloneMap(request.Inbound)
		case "remove":
			agent.removeCalls++
			if agent.failRemove {
				http.Error(w, "remove failed", http.StatusInternalServerError)
				return
			}
			delete(agent.inbounds, request.Tag)
		default:
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	case "/api/child/traffic":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"stats":   map[string]interface{}{"inbound": agent.traffic},
		})
	case "/api/child/services/control":
		_, _ = w.Write([]byte(`{"success":true}`))
	case "/api/child/services/status":
		_, _ = w.Write([]byte(`{"xray":{"running":true}}`))
	default:
		http.NotFound(w, r)
	}
}

type fakeNFTRunner struct {
	mu        sync.Mutex
	available bool
	table     bool
	scripts   []string
	failApply bool
}

func (runner *fakeNFTRunner) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if name != "nft" || !runner.available {
		return nil, errors.New("nft unavailable")
	}
	joined := strings.Join(args, " ")
	if joined == "--version" || joined == "list ruleset" {
		return []byte("nftables test"), nil
	}
	if joined == "list table inet arcway_forwarding" {
		if runner.table {
			return []byte("table inet arcway_forwarding"), nil
		}
		return nil, errors.New("table not found")
	}
	if (len(args) == 3 && args[0] == "-c" && args[1] == "-f") || (len(args) == 2 && args[0] == "-f") {
		path := args[len(args)-1]
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		runner.scripts = append(runner.scripts, string(raw))
		if runner.failApply {
			return []byte("synthetic nft failure"), errors.New("nft failed")
		}
		if len(args) == 2 {
			runner.table = true
		}
		return nil, nil
	}
	return nil, errors.New("unexpected nft invocation: " + joined)
}

func newTunnelGuard(t *testing.T, agent *fakeTunnelAgent, runner CommandRunner) (*Guard, string, *httptest.Server) {
	t.Helper()
	agentServer := httptest.NewServer(agent)
	t.Cleanup(agentServer.Close)
	statePath := t.TempDir() + "/guard/state.json"
	guard, err := New(statePath, "guard-secret", "agent-token", agentServer.URL, agentServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	guard.SetCommandRunner(runner)
	return guard, statePath, agentServer
}

func validTunnelRequest(id string, port int) TunnelApplyRequest {
	now := time.Now().UTC()
	return TunnelApplyRequest{
		ResourceID:   id,
		Generation:   1,
		ListenPort:   port,
		TargetIP:     "198.51.100.20",
		TargetPort:   443,
		Network:      tunnelNetworkTCPUDP,
		HardNotAfter: now.Add(time.Hour),
		LeaseUntil:   now.Add(5 * time.Minute),
	}
}

func apiErrorCode(err error) string {
	var typed *tunnelAPIError
	if errors.As(err, &typed) {
		return typed.code
	}
	return ""
}

func TestTunnelNetworkNormalizationAndPersistedCompatibility(t *testing.T) {
	now := time.Now().UTC()
	for _, network := range []string{"", tunnelNetworkTCP, tunnelNetworkTCPUDP, "TCP_UDP"} {
		request := validTunnelRequest("forward_hop_network_1", 24010)
		request.Network = network
		resource, err := normalizeTunnelApply(request, now)
		if err != nil {
			t.Fatalf("normalize network %q: %v", network, err)
		}
		if resource.Network != tunnelNetworkTCPUDP {
			t.Fatalf("normalize network %q = %q, want %q", network, resource.Network, tunnelNetworkTCPUDP)
		}
	}

	request := validTunnelRequest("forward_hop_network_2", 24011)
	request.Network = tunnelNetworkUDP
	if _, err := normalizeTunnelApply(request, now); apiErrorCode(err) != "unsupported_network" {
		t.Fatalf("new udp-only request error = %v", err)
	}

	resource, err := normalizeTunnelApply(validTunnelRequest("forward_hop_network_3", 24012), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{tunnelNetworkTCP, tunnelNetworkUDP, tunnelNetworkTCPUDP} {
		persisted := resource
		persisted.Network = network
		if err := validatePersistedTunnelResource(persisted); err != nil {
			t.Fatalf("persisted network %q rejected: %v", network, err)
		}
		candidate := resource
		candidate.ResourceID = "forward_hop_network_candidate"
		candidate.Tag = tunnelTag(candidate.ResourceID)
		guard := &Guard{tunnels: map[string]TunnelResource{persisted.ResourceID: persisted}}
		if err := guard.checkDurablePort(candidate); apiErrorCode(err) != "port_reserved" {
			t.Fatalf("persisted network %q did not reserve combined port: %v", network, err)
		}
		if network == tunnelNetworkTCPUDP {
			if !sameTunnelSpec(persisted, resource) {
				t.Fatal("canonical same-generation network was not idempotent")
			}
			continue
		}
		if sameTunnelSpec(persisted, resource) {
			t.Fatalf("legacy network %q was accepted as a same-generation tcp_udp spec", network)
		}
		upgrade := resource
		upgrade.Generation++
		if !sameTunnelDefinition(persisted, upgrade) {
			t.Fatalf("persisted network %q is not upgrade-compatible with tcp_udp", network)
		}
	}
}

func TestTunnelLegacyNetworkRequiresNewGenerationAndReappliesCombinedInbound(t *testing.T) {
	agent := newFakeTunnelAgent()
	guard, _, _ := newTunnelGuard(t, agent, &fakeNFTRunner{available: true})
	request := validTunnelRequest("forward_hop_legacy_network", 24013)
	now := time.Now().UTC()
	persisted, err := normalizeTunnelApply(request, now)
	if err != nil {
		t.Fatal(err)
	}
	persisted.Network = tunnelNetworkTCP
	persisted.State = TunnelStateActive
	if err := guard.storeTunnel(persisted); err != nil {
		t.Fatal(err)
	}
	legacyInbound := tunnelInbound(persisted)
	legacyInbound["settings"].(map[string]interface{})["network"] = tunnelNetworkTCP
	agent.inbounds[persisted.Tag] = legacyInbound

	request.LeaseUntil = request.LeaseUntil.Add(time.Minute)
	if _, _, err := guard.ApplyTunnel(context.Background(), request); apiErrorCode(err) != "generation_conflict" {
		t.Fatalf("same-generation legacy network error = %v", err)
	}
	agent.mu.Lock()
	if agent.addCalls != 0 {
		t.Fatalf("same-generation legacy resource was reapplied %d time(s)", agent.addCalls)
	}
	agent.mu.Unlock()

	request.Generation++
	upgraded, changed, err := guard.ApplyTunnel(context.Background(), request)
	if err != nil || !changed || upgraded.State != TunnelStateActive || upgraded.Network != tunnelNetworkTCPUDP {
		t.Fatalf("legacy network upgrade = %#v changed=%v err=%v", upgraded, changed, err)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	settings, _ := agent.lastAdd["settings"].(map[string]interface{})
	if agent.addCalls != 1 || settings["network"] != xrayNetworkTCPUDP {
		t.Fatalf("legacy upgrade apply calls=%d settings=%#v", agent.addCalls, settings)
	}
}

func TestTunnelApplyIsDurableIdempotentAndInstallsSourceACL(t *testing.T) {
	agent := newFakeTunnelAgent()
	runner := &fakeNFTRunner{available: true}
	guard, statePath, agentServer := newTunnelGuard(t, agent, runner)
	request := validTunnelRequest("forward_hop_0001", 24001)
	request.SourceCIDRs = []string{"203.0.113.7/32", "2001:db8::1/64", "203.0.113.7/32"}

	resource, changed, err := guard.ApplyTunnel(context.Background(), request)
	if err != nil {
		t.Fatalf("ApplyTunnel() error = %v", err)
	}
	if !changed || resource.State != TunnelStateActive || resource.Tag != tunnelTag(request.ResourceID) {
		t.Fatalf("resource = %#v, changed = %v", resource, changed)
	}
	agent.mu.Lock()
	if agent.addCalls != 1 || agent.authorization != "Bearer agent-token" {
		t.Fatalf("Agent apply calls = %d, auth = %q", agent.addCalls, agent.authorization)
	}
	if agent.lastAdd["protocol"] != "dokodemo-door" || intFromJSON(agent.lastAdd["port"]) != request.ListenPort {
		t.Fatalf("unexpected inbound = %#v", agent.lastAdd)
	}
	settings, _ := agent.lastAdd["settings"].(map[string]interface{})
	if settings["network"] != xrayNetworkTCPUDP {
		t.Fatalf("dokodemo network = %#v, want %q", settings["network"], xrayNetworkTCPUDP)
	}
	agent.mu.Unlock()

	runner.mu.Lock()
	combinedRules := strings.Join(runner.scripts, "\n")
	runner.mu.Unlock()
	for _, fragment := range []string{
		"table inet arcway_forwarding",
		"type filter hook input priority -20; policy accept;",
		"ip saddr { 203.0.113.7/32 } tcp dport 24001 accept",
		"ip saddr { 203.0.113.7/32 } udp dport 24001 accept",
		"ip6 saddr { 2001:db8::/64 } tcp dport 24001 accept",
		"ip6 saddr { 2001:db8::/64 } udp dport 24001 accept",
		"tcp dport 24001 drop",
		"udp dport 24001 drop",
	} {
		if !strings.Contains(combinedRules, fragment) {
			t.Fatalf("nft rules do not contain %q:\n%s", fragment, combinedRules)
		}
	}

	request.LeaseUntil = request.LeaseUntil.Add(time.Minute)
	renewed, changed, err := guard.ApplyTunnel(context.Background(), request)
	if err != nil || !changed || !renewed.LeaseUntil.Equal(request.LeaseUntil) {
		t.Fatalf("lease renewal = %#v, changed=%v, err=%v", renewed, changed, err)
	}
	agent.mu.Lock()
	if agent.addCalls != 1 {
		t.Fatalf("idempotent renewal reapplied inbound %d times", agent.addCalls)
	}
	agent.mu.Unlock()

	conflict := request
	conflict.TargetPort = 8443
	if _, _, err := guard.ApplyTunnel(context.Background(), conflict); apiErrorCode(err) != "generation_conflict" {
		t.Fatalf("same-generation mutation error = %v", err)
	}

	reloaded, err := New(statePath, "guard-secret", "agent-token", agentServer.URL, agentServer.Client())
	if err != nil {
		t.Fatalf("reload error = %v", err)
	}
	got, exists := reloaded.tunnelSnapshot(request.ResourceID)
	if !exists || got.State != TunnelStateActive || got.Generation != 1 || !got.LeaseUntil.Equal(request.LeaseUntil) {
		t.Fatalf("reloaded resource = %#v, exists=%v", got, exists)
	}
}

func TestTunnelPortPreflightFailsClosed(t *testing.T) {
	agent := newFakeTunnelAgent()
	agent.inbounds["legacy-inbound"] = map[string]interface{}{
		"tag": "legacy-inbound", "listen": "0.0.0.0", "port": 24002, "protocol": "vless",
	}
	guard, _, _ := newTunnelGuard(t, agent, &fakeNFTRunner{available: true})
	if _, _, err := guard.ApplyTunnel(context.Background(), validTunnelRequest("forward_hop_0002", 24002)); apiErrorCode(err) != "port_in_use" {
		t.Fatalf("port conflict error = %v", err)
	}
	if _, exists := guard.tunnelSnapshot("forward_hop_0002"); exists {
		t.Fatal("port-conflicting resource was persisted")
	}

	agent.failList = true
	if _, _, err := guard.ApplyTunnel(context.Background(), validTunnelRequest("forward_hop_0003", 24003)); apiErrorCode(err) != "agent_preflight_failed" {
		t.Fatalf("unavailable preflight error = %v", err)
	}
}

func TestTunnelSuspendResumeAndDeleteAreGenerationSafe(t *testing.T) {
	agent := newFakeTunnelAgent()
	runner := &fakeNFTRunner{available: true}
	guard, _, _ := newTunnelGuard(t, agent, runner)
	request := validTunnelRequest("forward_hop_0004", 24004)
	request.SourceCIDRs = []string{"203.0.113.8/32"}
	if _, _, err := guard.ApplyTunnel(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	suspended, changed, err := guard.SuspendTunnel(context.Background(), TunnelIdentityRequest{ResourceID: request.ResourceID, Generation: 2})
	if err != nil || !changed || suspended.State != TunnelStateSuspended {
		t.Fatalf("suspend = %#v changed=%v err=%v", suspended, changed, err)
	}
	if _, changed, err := guard.SuspendTunnel(context.Background(), TunnelIdentityRequest{ResourceID: request.ResourceID, Generation: 2}); err != nil || changed {
		t.Fatalf("repeated suspend changed=%v err=%v", changed, err)
	}
	if _, _, err := guard.ApplyTunnel(context.Background(), request); apiErrorCode(err) != "stale_generation" {
		t.Fatalf("stale apply error = %v", err)
	}

	request.Generation = 3
	request.LeaseUntil = time.Now().UTC().Add(5 * time.Minute)
	resumed, changed, err := guard.ApplyTunnel(context.Background(), request)
	if err != nil || !changed || resumed.State != TunnelStateActive {
		t.Fatalf("resume = %#v changed=%v err=%v", resumed, changed, err)
	}
	deleted, changed, err := guard.DeleteTunnel(context.Background(), TunnelIdentityRequest{ResourceID: request.ResourceID, Generation: 4})
	if err != nil || !changed || deleted.State != TunnelStateDeleted {
		t.Fatalf("delete = %#v changed=%v err=%v", deleted, changed, err)
	}
	request.Generation = 5
	if _, _, err := guard.ApplyTunnel(context.Background(), request); apiErrorCode(err) != "resource_deleted" {
		t.Fatalf("deleted resource resurrection error = %v", err)
	}
}

func TestExpiredTunnelIsRemovedAfterGuardRestart(t *testing.T) {
	agent := newFakeTunnelAgent()
	runner := &fakeNFTRunner{available: true}
	guard, statePath, agentServer := newTunnelGuard(t, agent, runner)
	request := validTunnelRequest("forward_hop_0005", 24005)
	request.HardNotAfter = time.Now().UTC().Add(time.Hour)
	request.LeaseUntil = time.Now().UTC().Add(80 * time.Millisecond)
	if _, _, err := guard.ApplyTunnel(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)

	reloaded, err := New(statePath, "guard-secret", "agent-token", agentServer.URL, agentServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	reloaded.SetCommandRunner(runner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reloaded.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resource, _ := reloaded.tunnelSnapshot(request.ResourceID)
		if resource.State == TunnelStateExpired {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	resource, _ := reloaded.tunnelSnapshot(request.ResourceID)
	if resource.State != TunnelStateExpired {
		t.Fatalf("resource state after restart = %q, last error = %q", resource.State, resource.LastError)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if agent.removeCalls == 0 {
		t.Fatal("expired persisted inbound was not removed")
	}
	if _, exists := agent.inbounds[resource.Tag]; exists {
		t.Fatal("expired inbound remains on Agent")
	}
}

func TestTunnelCapabilityGatesACLAndLimiter(t *testing.T) {
	agent := newFakeTunnelAgent()
	unavailableNFT := &fakeNFTRunner{}
	guard, _, _ := newTunnelGuard(t, agent, unavailableNFT)
	request := validTunnelRequest("forward_hop_0006", 24006)
	request.SourceCIDRs = []string{"203.0.113.9/32"}
	if _, _, err := guard.ApplyTunnel(context.Background(), request); apiErrorCode(err) != "capability_unavailable" {
		t.Fatalf("ACL capability error = %v", err)
	}
	request.SourceCIDRs = nil
	request.SpeedLimitBytesPerSecond = 1024
	if _, _, err := guard.ApplyTunnel(context.Background(), request); apiErrorCode(err) != "capability_unavailable" {
		t.Fatalf("limiter capability error = %v", err)
	}
}

func TestTunnelACLRestoreFailureWithdrawsInboundFailClosed(t *testing.T) {
	agent := newFakeTunnelAgent()
	runner := &fakeNFTRunner{available: true}
	guard, _, _ := newTunnelGuard(t, agent, runner)
	request := validTunnelRequest("forward_hop_0008", 24008)
	request.SourceCIDRs = []string{"203.0.113.10/32"}
	if _, _, err := guard.ApplyTunnel(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	runner.mu.Lock()
	runner.failApply = true
	runner.mu.Unlock()
	if err := guard.InitializeTunnelSafety(context.Background()); err == nil {
		t.Fatal("ACL restore failure was not reported")
	}
	resource, _ := guard.tunnelSnapshot(request.ResourceID)
	agent.mu.Lock()
	_, remains := agent.inbounds[resource.Tag]
	removeCalls := agent.removeCalls
	agent.mu.Unlock()
	if remains || removeCalls == 0 {
		t.Fatalf("fail-closed cleanup remains=%v remove_calls=%d state=%s", remains, removeCalls, resource.State)
	}
	if resource.State != TunnelStateExpiryPending && resource.State != TunnelStateSuspended {
		t.Fatalf("state after ACL failure = %q", resource.State)
	}
}

func signedGuardRequest(t *testing.T, client *http.Client, method, url, path string, payload interface{}) *http.Response {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sealed, metadata, err := guardwire.Seal("guard-secret", method, path, raw, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, url+path, bytes.NewReader(sealed))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(guardwire.HeaderTimestamp, metadata.Timestamp)
	request.Header.Set(guardwire.HeaderNonce, metadata.Nonce)
	request.Header.Set(guardwire.HeaderSignature, metadata.Signature)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestTunnelHTTPContractAndCapabilities(t *testing.T) {
	agent := newFakeTunnelAgent()
	runner := &fakeNFTRunner{available: true}
	guard, _, _ := newTunnelGuard(t, agent, runner)
	server := httptest.NewServer(guard.Handler())
	defer server.Close()

	capabilities := signedGuardRequest(t, server.Client(), http.MethodGet, server.URL, "/v1/capabilities", map[string]interface{}{})
	capabilityBody, _ := io.ReadAll(capabilities.Body)
	capabilities.Body.Close()
	if capabilities.StatusCode != http.StatusOK {
		t.Fatalf("capabilities status=%d body=%s", capabilities.StatusCode, capabilityBody)
	}
	var advertised map[string]interface{}
	if err := json.Unmarshal(capabilityBody, &advertised); err != nil {
		t.Fatal(err)
	}
	if advertised["managed_tunnel_v1"] != true || advertised["inbound_expiry_v1"] != true || advertised["inbound_acl_v1"] != true || advertised["inbound_limiter_v1"] != false {
		t.Fatalf("capabilities = %#v", advertised)
	}
	networks, _ := advertised["tunnel_networks"].([]interface{})
	if len(networks) != 1 || networks[0] != tunnelNetworkTCPUDP {
		t.Fatalf("tunnel networks = %#v", advertised["tunnel_networks"])
	}

	apply := signedGuardRequest(t, server.Client(), http.MethodPut, server.URL, "/v1/tunnels/apply", validTunnelRequest("forward_hop_0007", 24007))
	applyBody, _ := io.ReadAll(apply.Body)
	apply.Body.Close()
	if apply.StatusCode != http.StatusOK || !strings.Contains(string(applyBody), `"state":"active"`) {
		t.Fatalf("apply status=%d body=%s", apply.StatusCode, applyBody)
	}
	status := signedGuardRequest(t, server.Client(), http.MethodPost, server.URL, "/v1/tunnels/status", TunnelIdentityRequest{ResourceID: "forward_hop_0007"})
	statusBody, _ := io.ReadAll(status.Body)
	status.Body.Close()
	if status.StatusCode != http.StatusOK || !strings.Contains(string(statusBody), `"observed_state":"active"`) {
		t.Fatalf("status=%d body=%s", status.StatusCode, statusBody)
	}
}

func TestGeneratedNFTablesSyntaxWhenAvailable(t *testing.T) {
	runner := OSCommandRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := runner.CombinedOutput(ctx, "nft", "list", "ruleset"); err != nil {
		t.Skip("nftables validation is unavailable")
	}
	_, tableErr := runner.CombinedOutput(ctx, "nft", "list", "table", "inet", "arcway_forwarding")
	resource := TunnelResource{
		ResourceID:  "syntax_resource_1",
		ListenPort:  24009,
		SourceCIDRs: []string{"203.0.113.0/24", "2001:db8::/64"},
	}
	path := t.TempDir() + "/rules.nft"
	if err := os.WriteFile(path, []byte(buildNFTablesRules([]TunnelResource{resource}, tableErr == nil)), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := runner.CombinedOutput(ctx, "nft", "-c", "-f", path); err != nil {
		t.Fatalf("generated nftables syntax is invalid: %v: %s", err, output)
	}
}

func TestLegacyStateVersionStillLoads(t *testing.T) {
	statePath := t.TempDir() + "/state.json"
	if err := os.WriteFile(statePath, []byte(`{"version":1,"entries":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	guard, err := New(statePath, "guard-secret", "agent-token", "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("legacy state load error = %v", err)
	}
	if guard.Pending() != 0 || guard.PendingTunnels() != 0 {
		t.Fatal("legacy empty state did not load empty")
	}
	if err := guard.UpdateAgentToken("rotated-token"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var migrated stateFile
	if err := json.Unmarshal(raw, &migrated); err != nil {
		t.Fatal(err)
	}
	if migrated.Version != stateVersion {
		t.Fatalf("migrated state version = %d, want %d", migrated.Version, stateVersion)
	}
}
