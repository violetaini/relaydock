package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type forwardingLimiterTestAgent struct {
	capable   bool
	ack       bool
	mu        sync.Mutex
	payloads  []WSLimiterConfigPayload
	started   chan WSLimiterConfigPayload
	release   chan struct{}
	releaseMu sync.Once
}

func (a *forwardingLimiterTestAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "inbounds": []any{}})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":      true,
			"capabilities": map[string]bool{"forwarding_speed_limit_v1": a.capable},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
		var payload WSLimiterConfigPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		a.payloads = append(a.payloads, payload)
		a.mu.Unlock()
		if a.started != nil {
			a.started <- payload
			<-a.release
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": a.ack})
	default:
		http.NotFound(w, r)
	}
}

func (a *forwardingLimiterTestAgent) snapshot() []WSLimiterConfigPayload {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]WSLimiterConfigPayload(nil), a.payloads...)
}

func (a *forwardingLimiterTestAgent) releaseACK() {
	if a.release != nil {
		a.releaseMu.Do(func() { close(a.release) })
	}
}

func setForwardingFixtureSpeed(t *testing.T, fixture *forwardingHandlerFixture, speedMbps float64) {
	t.Helper()
	current, err := fixture.repo.GetUserTunnelGrantByID(context.Background(), fixture.forward.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	input := *current
	input.PerForwardSpeedMbps = speedMbps
	updated, err := fixture.repo.UpdateUserTunnelGrant(context.Background(), current.PublicID, current.Username, input, current.Version, "admin")
	if err != nil {
		t.Fatal(err)
	}
	fixture.grant = updated
}

func attachForwardingLimiterTestAgent(t *testing.T, fixture *forwardingHandlerFixture, agent *httptest.Server) {
	t.Helper()
	entry := fixture.forward.Hops[0]
	server, err := fixture.repo.GetRemoteServer(context.Background(), entry.ServerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.repo.UpdateRemoteServerHeartbeat(context.Background(), server.Token, "127.0.0.1", ""); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.UpdateRemoteServerListenPort(context.Background(), server.ID, remoteAgentTestPort(t, agent.URL)); err != nil {
		t.Fatal(err)
	}
	pusher := NewLimiterConfigPusher(fixture.repo, nil)
	pusher.httpClient = agent.Client()
	fixture.handler.SetLimiterPusher(pusher)
}

func forwardEntryApplyCount(deployer *fakeForwardTunnelDeployer, resourceID string) int {
	deployer.mu.Lock()
	defer deployer.mu.Unlock()
	count := 0
	for _, operation := range deployer.operations {
		if operation == "apply:"+resourceID {
			count++
		}
	}
	return count
}

func findForwardingLimiterPayload(payloads []WSLimiterConfigPayload, inboundTag string) (WSLimiterConfigPayload, bool) {
	for _, payload := range payloads {
		if payload.InboundTag == inboundTag {
			return payload, true
		}
	}
	return WSLimiterConfigPayload{}, false
}

func updateManualForwardingGrantSpeed(t *testing.T, fixture *forwardingHandlerFixture, speedMbps float64) *httptest.ResponseRecorder {
	t.Helper()
	current, err := fixture.repo.GetUserTunnelGrantByID(context.Background(), fixture.forward.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	startsAt := current.StartsAt
	body, err := json.Marshal(tunnelGrantRequest{
		Enabled: &enabled, StartsAt: &startsAt, ExpiresAt: current.ExpiresAt,
		MaxActiveForwards: current.MaxActiveForwards, PerForwardSpeedMbps: speedMbps,
		TrafficLimitBytes: current.TrafficLimitBytes, BillingModeOverride: current.BillingModeOverride,
		Version: current.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/admin/users/alice/tunnel-grants/"+current.PublicID, strings.NewReader(string(body)))
	request.SetPathValue("username", "alice")
	request.SetPathValue("id", current.PublicID)
	response := httptest.NewRecorder()
	fixture.handler.HandleAdminUserTunnelGrant(response, request)
	return response
}

func serviceAuthorizationForwardingSpeedRequest(t *testing.T, fixture *forwardingHandlerFixture, speedMbps float64) serviceAuthorizationCustomRequest {
	t.Helper()
	serverGrants, err := fixture.repo.ListUserServerGrants(context.Background(), "alice")
	if err != nil || len(serverGrants) != 1 {
		t.Fatalf("server grants=%+v err=%v", serverGrants, err)
	}
	tunnelGrant, err := fixture.repo.GetUserTunnelGrantByID(context.Background(), fixture.forward.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	fixed := []serviceAuthorizationFixedNodeGrant{}
	servers := []serviceAuthorizationServerGrant{{
		ServerID: serverGrants[0].ServerID, Enabled: true, StartsAt: serverGrants[0].StartsAt,
		ExpiresAt: serverGrants[0].ExpiresAt, MaxActiveNodes: serverGrants[0].MaxActiveNodes,
		SpeedLimitMbps: serverGrants[0].SpeedLimitMbps, ConnectionLimit: serverGrants[0].ConnectionLimit,
		TrafficLimitBytes: serverGrants[0].TrafficLimitBytes, BillingMode: serverGrants[0].BillingMode,
		ResetPolicy: serverGrants[0].ResetPolicy, ResetDay: serverGrants[0].ResetDay,
		AllowedProtocols: serverGrants[0].AllowedProtocols, AllowedProtocolProfiles: serverGrants[0].AllowedProtocolProfiles,
	}}
	forwarding := []serviceAuthorizationForwardingGrant{{
		TunnelID: tunnelGrant.TunnelID, Enabled: true, StartsAt: tunnelGrant.StartsAt,
		ExpiresAt: tunnelGrant.ExpiresAt, MaxActiveForwards: tunnelGrant.MaxActiveForwards,
		PerForwardSpeedMbps: speedMbps, TrafficLimitBytes: tunnelGrant.TrafficLimitBytes,
		BillingModeOverride: *tunnelGrant.BillingModeOverride,
	}}
	return serviceAuthorizationCustomRequest{FixedNodeGrants: &fixed, ServerGrants: &servers, ForwardingGrants: &forwarding}
}

func TestForwardingSpeedLimiterRequiresCapabilityAndACKBeforeEntryApply(t *testing.T) {
	for _, testCase := range []struct {
		name              string
		capable           bool
		ack               bool
		wantError         string
		wantEntryApplyInc int
		wantPush          bool
	}{
		{name: "supported", capable: true, ack: true, wantEntryApplyInc: 1, wantPush: true},
		{name: "legacy Agent", ack: true, wantError: "forwarding_speed_limit_v1"},
		{name: "unacknowledged policy", capable: true, wantError: "not acknowledged", wantPush: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newForwardingHandlerFixture(t)
			setForwardingFixtureSpeed(t, &fixture, 80)
			agentState := &forwardingLimiterTestAgent{capable: testCase.capable, ack: testCase.ack}
			agent := httptest.NewServer(agentState)
			t.Cleanup(agent.Close)
			attachForwardingLimiterTestAgent(t, &fixture, agent)

			entry := fixture.forward.Hops[0]
			before := forwardEntryApplyCount(fixture.deployer, entry.ResourceID)
			err := fixture.handler.deployForward(context.Background(), fixture.forward)
			if testCase.wantError == "" {
				if err != nil {
					t.Fatalf("deploy with forwarding limiter: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("deploy error=%v, want substring %q", err, testCase.wantError)
			}
			if got := forwardEntryApplyCount(fixture.deployer, entry.ResourceID) - before; got != testCase.wantEntryApplyInc {
				t.Fatalf("entry Apply increment=%d want=%d", got, testCase.wantEntryApplyInc)
			}

			payload, pushed := findForwardingLimiterPayload(agentState.snapshot(), entry.ResourceTag)
			if pushed != testCase.wantPush {
				t.Fatalf("forwarding limiter pushed=%t want=%t payloads=%+v", pushed, testCase.wantPush, agentState.snapshot())
			}
			if pushed {
				if !payload.InboundSharedLimit || payload.NodeLimit != 10_000_000 {
					t.Fatalf("shared limiter=%+v, want 80 Mbps = 10000000 bytes/s", payload)
				}
				if payload.Users == nil || len(payload.Users) != 0 || payload.WireGuardPeers == nil || len(payload.WireGuardPeers) != 0 {
					t.Fatalf("forwarding limiter must contain explicit empty identities: %+v", payload)
				}
			}
		})
	}
}

func TestManualForwardingGrantSpeedUpdateCapabilityGatesAndReconciles(t *testing.T) {
	t.Run("legacy Agent rejected before write", func(t *testing.T) {
		fixture := newForwardingHandlerFixture(t)
		agentState := &forwardingLimiterTestAgent{ack: true}
		agent := httptest.NewServer(agentState)
		t.Cleanup(agent.Close)
		attachForwardingLimiterTestAgent(t, &fixture, agent)

		response := updateManualForwardingGrantSpeed(t, &fixture, 80)
		if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "forwarding_speed_limit_v1") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		stored, err := fixture.repo.GetUserTunnelGrantByID(context.Background(), fixture.forward.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.PerForwardSpeedMbps != 0 {
			t.Fatalf("legacy Agent rejection persisted speed=%v", stored.PerForwardSpeedMbps)
		}
	})

	t.Run("supported Agent reconciles existing forward", func(t *testing.T) {
		fixture := newForwardingHandlerFixture(t)
		agentState := &forwardingLimiterTestAgent{capable: true, ack: true}
		agent := httptest.NewServer(agentState)
		t.Cleanup(agent.Close)
		attachForwardingLimiterTestAgent(t, &fixture, agent)
		entry := fixture.forward.Hops[0]
		beforeApply := forwardEntryApplyCount(fixture.deployer, entry.ResourceID)

		response := updateManualForwardingGrantSpeed(t, &fixture, 80)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		stored, err := fixture.repo.GetUserTunnelGrantByID(context.Background(), fixture.forward.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.PerForwardSpeedMbps != 80 {
			t.Fatalf("stored speed=%v want=80", stored.PerForwardSpeedMbps)
		}
		if got := forwardEntryApplyCount(fixture.deployer, entry.ResourceID) - beforeApply; got != 1 {
			t.Fatalf("entry Apply increment=%d want=1", got)
		}
		payload, ok := findForwardingLimiterPayload(agentState.snapshot(), entry.ResourceTag)
		if !ok || !payload.InboundSharedLimit || payload.NodeLimit != 10_000_000 {
			t.Fatalf("reconciled forwarding limiter=%+v found=%t", payload, ok)
		}
	})
}

func TestServiceAuthorizationForwardingSpeedUpdateCapabilityGatesAndReconciles(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		capable   bool
		wantError bool
	}{
		{name: "legacy Agent rejected before write", wantError: true},
		{name: "supported Agent schedules existing forward reconciliation", capable: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newForwardingHandlerFixture(t)
			agentState := &forwardingLimiterTestAgent{capable: testCase.capable, ack: true}
			agent := httptest.NewServer(agentState)
			t.Cleanup(agent.Close)
			attachForwardingLimiterTestAgent(t, &fixture, agent)
			packages := NewPackageAssignHandler(fixture.repo, nil, nil)
			managed := NewManagedNodesHandler(fixture.repo, nil, nil)
			service := NewServiceAuthorizationHandler(fixture.repo, packages, managed, fixture.handler)
			request := serviceAuthorizationForwardingSpeedRequest(t, &fixture, 40)

			err := service.validateCustomRequest(context.Background(), &request)
			if testCase.wantError {
				if err == nil || !strings.Contains(err.Error(), "forwarding_speed_limit_v1") {
					t.Fatalf("validate error=%v", err)
				}
				stored, readErr := fixture.repo.GetUserTunnelGrantByID(context.Background(), fixture.forward.GrantID)
				if readErr != nil || stored.PerForwardSpeedMbps != 0 {
					t.Fatalf("legacy validation mutated grant=%+v err=%v", stored, readErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate custom speed: %v", err)
			}
			beforeGeneration := fixture.forward.Generation
			_, _, err = service.applyCustomDesired(context.Background(), "alice", request, "admin")
			if err != nil {
				t.Fatalf("apply custom speed: %v", err)
			}
			stored, err := fixture.repo.GetUserTunnelGrantByID(context.Background(), fixture.forward.GrantID)
			if err != nil || stored.PerForwardSpeedMbps != 40 {
				t.Fatalf("stored grant=%+v err=%v", stored, err)
			}
			forward, err := fixture.repo.GetUserForward(context.Background(), fixture.forward.PublicID, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if forward.Generation <= beforeGeneration {
				t.Fatalf("forward generation=%d want >%d after grant update", forward.Generation, beforeGeneration)
			}
		})
	}
}

func TestLegacyWebSocketRejectsForwardingSpeedSnapshotBeforeWrite(t *testing.T) {
	ws := NewRemoteWSHandler(nil, nil)
	ws.conns.Store(int64(505), &RemoteWSConnection{ServerID: 505})
	err := ws.SendLimiterConfig(505, []WSLimiterConfigPayload{{
		InboundTag: "forward-entry", NodeLimit: 1, InboundSharedLimit: true,
		Users: []WSUserLimitInfo{}, WireGuardPeers: []WSWireGuardPeerIdentity{},
	}})
	if err == nil || !strings.Contains(err.Error(), "forwarding_speed_limit_v1") {
		t.Fatalf("SendLimiterConfig error=%v, want forwarding_speed_limit_v1 rejection", err)
	}
}

func TestForwardingSpeedLimiterClearsBeforeSuspendOrDeleteFinalizes(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		wantDesired string
		action      func(context.Context, *forwardingHandlerFixture) error
	}{
		{name: "suspend", wantDesired: storage.ForwardDesiredInactive, action: func(ctx context.Context, fixture *forwardingHandlerFixture) error {
			return fixture.handler.suspendForward(ctx, fixture.forward, "alice")
		}},
		{name: "delete", wantDesired: storage.ForwardDesiredDeleted, action: func(ctx context.Context, fixture *forwardingHandlerFixture) error {
			return fixture.handler.deleteForward(ctx, fixture.forward, "alice")
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newForwardingHandlerFixture(t)
			setForwardingFixtureSpeed(t, &fixture, 80)
			agentState := &forwardingLimiterTestAgent{
				capable: true, ack: true, started: make(chan WSLimiterConfigPayload, 1), release: make(chan struct{}),
			}
			agent := httptest.NewServer(agentState)
			t.Cleanup(agent.Close)
			t.Cleanup(agentState.releaseACK)
			attachForwardingLimiterTestAgent(t, &fixture, agent)

			done := make(chan error, 1)
			go func() { done <- testCase.action(context.Background(), &fixture) }()

			var payload WSLimiterConfigPayload
			select {
			case payload = <-agentState.started:
			case <-time.After(2 * time.Second):
				t.Fatal("zero forwarding limiter snapshot did not arrive")
			}
			if payload.InboundTag != fixture.forward.Hops[0].ResourceTag || !payload.InboundSharedLimit || payload.NodeLimit != 0 ||
				payload.Users == nil || len(payload.Users) != 0 || payload.WireGuardPeers == nil || len(payload.WireGuardPeers) != 0 {
				t.Fatalf("invalid forwarding limiter clear: %+v", payload)
			}
			current, err := fixture.repo.GetUserForward(context.Background(), fixture.forward.PublicID, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if current.DesiredState != testCase.wantDesired || len(current.Hops) == 0 {
				t.Fatalf("clear was not issued while rule/hops remained: desired=%s hops=%d", current.DesiredState, len(current.Hops))
			}
			select {
			case err := <-done:
				t.Fatalf("operation completed before limiter ACK: %v", err)
			default:
			}

			agentState.releaseACK()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("operation did not complete after limiter ACK")
			}
			if testCase.wantDesired == storage.ForwardDesiredDeleted {
				deleted, err := fixture.repo.GetUserForward(context.Background(), fixture.forward.PublicID, "alice")
				if err != nil {
					t.Fatal(err)
				}
				if len(deleted.Hops) != 0 {
					t.Fatalf("delete did not finalize after limiter ACK: hops=%d", len(deleted.Hops))
				}
			}
		})
	}
}
