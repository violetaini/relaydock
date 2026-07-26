package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/tunnelidentity"
)

func TestForwardingGuardCapabilitiesRequireTCPUDP(t *testing.T) {
	capabilities := forwardingGuardCapabilities{
		ManagedTunnelV1: true,
		InboundExpiryV1: true,
		InboundACLV1:    true,
		TunnelNetworks:  []string{forwardingGuardTunnelNetwork},
		MaxLeaseSeconds: 600,
	}
	if !forwardingGuardHasRequiredCapabilities(capabilities) {
		t.Fatal("tcp_udp guard capabilities were rejected")
	}

	legacy := capabilities
	legacy.TunnelNetworks = []string{"tcp"}
	if forwardingGuardHasRequiredCapabilities(legacy) {
		t.Fatal("legacy tcp-only guard capabilities were accepted")
	}
	if !forwardingGuardHasBasicCapabilities(legacy) {
		t.Fatal("legacy guard was rejected for cleanup-only operations")
	}

	withoutACL := capabilities
	withoutACL.InboundACLV1 = false
	if forwardingGuardHasRequiredCapabilities(withoutACL) {
		t.Fatal("guard without inbound ACL capability was accepted")
	}
	withoutExpiry := capabilities
	withoutExpiry.InboundExpiryV1 = false
	if forwardingGuardHasBasicCapabilities(withoutExpiry) {
		t.Fatal("guard without durable tunnel expiry was accepted for cleanup")
	}
}

func TestForwardingGuardBasicReadinessAllowsCleanupButCannotBypassApplyGate(t *testing.T) {
	const resourceID = "forward_hop_readiness_1"
	var fullCapabilities atomic.Bool
	var capabilityCalls, removeCalls, applyCalls atomic.Int64
	_, agentPort := startManagedGuardServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/capabilities":
			capabilityCalls.Add(1)
			networks := []string{"tcp"}
			acl := false
			if fullCapabilities.Load() {
				networks = []string{forwardingGuardTunnelNetwork}
				acl = true
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"managed_tunnel_v1": true,
				"inbound_expiry_v1": true,
				"inbound_acl_v1":    acl,
				"tunnel_networks":   networks,
				"max_lease_seconds": 600,
			})
		case "/v1/agent-token":
			_, _ = w.Write([]byte(`{"success":true}`))
		case "/v1/tunnels/remove":
			removeCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":  true,
				"resource": map[string]any{"resource_id": resourceID, "tag": tunnelidentity.Tag(resourceID), "generation": 2, "state": "deleted"},
			})
		case "/v1/tunnels/apply":
			applyCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":  true,
				"resource": map[string]any{"resource_id": resourceID, "tag": tunnelidentity.Tag(resourceID), "generation": 3, "state": "active"},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	repo := newManagedSecurityTestRepo(t)
	server := &storage.RemoteServer{
		Name: "legacy-forwarding-guard", Token: "agent-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "127.0.0.1", ListenPort: agentPort, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	deployer := NewForwardingGuardDeployer(NewManagedNodesHandler(repo, nil, nil))
	if err := deployer.Remove(context.Background(), server.ID, resourceID, 2); err != nil {
		t.Fatalf("legacy guard cleanup failed: %v", err)
	}
	if capabilityCalls.Load() != 1 || removeCalls.Load() != 1 {
		t.Fatalf("cleanup calls capabilities=%d remove=%d", capabilityCalls.Load(), removeCalls.Load())
	}

	hardNotAfter := time.Now().UTC().Add(time.Hour)
	spec := ForwardTunnelSpec{
		ResourceID: resourceID, Generation: 3, ServerID: server.ID, Tag: tunnelidentity.Tag(resourceID),
		ListenPort: 2033, TargetHost: "198.51.100.23", TargetPort: 2033,
		HardNotAfter: &hardNotAfter, LeaseUntil: time.Now().UTC().Add(5 * time.Minute),
	}
	if err := deployer.Apply(context.Background(), spec); err == nil {
		t.Fatal("basic readiness cache allowed tcp-only guard to apply a tunnel")
	}
	if capabilityCalls.Load() != 2 || applyCalls.Load() != 0 {
		t.Fatalf("apply gate calls capabilities=%d apply=%d", capabilityCalls.Load(), applyCalls.Load())
	}

	fullCapabilities.Store(true)
	if err := deployer.Apply(context.Background(), spec); err != nil {
		t.Fatalf("upgraded guard apply failed: %v", err)
	}
	if capabilityCalls.Load() != 3 || applyCalls.Load() != 1 {
		t.Fatalf("upgraded apply calls capabilities=%d apply=%d", capabilityCalls.Load(), applyCalls.Load())
	}
}

func TestForwardingGuardApplyPayloadUsesTCPUDP(t *testing.T) {
	hardNotAfter := time.Date(2026, time.July, 23, 1, 2, 3, 0, time.FixedZone("test", 8*60*60))
	leaseUntil := hardNotAfter.Add(-time.Hour)
	spec := ForwardTunnelSpec{
		ResourceID:   "forward_hop_payload_1",
		Generation:   4,
		ListenPort:   2033,
		TargetHost:   "198.51.100.23",
		TargetPort:   2033,
		SourceCIDRs:  []string{"203.0.113.7/32"},
		HardNotAfter: &hardNotAfter,
		LeaseUntil:   leaseUntil,
	}
	payload := forwardingGuardApplyPayload(spec)
	if payload["network"] != forwardingGuardTunnelNetwork {
		t.Fatalf("network = %#v, want %q", payload["network"], forwardingGuardTunnelNetwork)
	}
	if payload["listen_port"] != 2033 || payload["target_port"] != 2033 {
		t.Fatalf("same-port payload = %#v", payload)
	}
	if got, ok := payload["hard_not_after"].(time.Time); !ok || !got.Equal(hardNotAfter.UTC()) || got.Location() != time.UTC {
		t.Fatalf("hard_not_after = %#v", payload["hard_not_after"])
	}
	if got, ok := payload["lease_until"].(time.Time); !ok || !got.Equal(leaseUntil.UTC()) || got.Location() != time.UTC {
		t.Fatalf("lease_until = %#v", payload["lease_until"])
	}
}

func TestClassifyForwardingGuardPortConflicts(t *testing.T) {
	for _, body := range []string{
		`expiry guard returned HTTP 409: {"code":"port_in_use"}`,
		`expiry guard returned HTTP 409: {"code": "port_reserved"}`,
	} {
		if err := classifyForwardingGuardError(errors.New(body)); !errors.Is(err, ErrForwardTunnelPortInUse) {
			t.Fatalf("expected port conflict sentinel for %q, got %v", body, err)
		}
	}
	if err := classifyForwardingGuardError(errors.New("network unavailable")); errors.Is(err, ErrForwardTunnelPortInUse) {
		t.Fatalf("unexpected port conflict classification: %v", err)
	}
}

func TestValidateForwardingGuardACK(t *testing.T) {
	valid := `{"success":true,"resource":{"resource_id":"rd_12345678","tag":"rd-tun-test","generation":3,"state":"active"}}`
	if err := validateForwardingGuardACK([]byte(valid), "rd_12345678", "rd-tun-test", 3, "active"); err != nil {
		t.Fatalf("expected successful acknowledgement: %v", err)
	}
	for _, body := range []string{
		`{"success":true}`,
		`{"success":false}`,
		`{"success":true,"resource":{"resource_id":"rd_12345678","tag":"rd-tun-test","generation":3,"state":"delete_pending"}}`,
		`{"success":true,"resource":{"resource_id":"other","tag":"rd-tun-test","generation":3,"state":"active"}}`,
		`{}`,
		`not-json`,
	} {
		if err := validateForwardingGuardACK([]byte(body), "rd_12345678", "rd-tun-test", 3, "active"); err == nil {
			t.Fatalf("expected acknowledgement rejection for %q", body)
		}
	}
}

func TestForwardingGuardErrorCode(t *testing.T) {
	if got := forwardingGuardErrorCode([]byte(`{"success":false,"code":"not_found"}`)); got != "not_found" {
		t.Fatalf("unexpected code %q", got)
	}
	if got := forwardingGuardErrorCode([]byte(`not-json`)); got != "" {
		t.Fatalf("unexpected malformed response code %q", got)
	}
}
