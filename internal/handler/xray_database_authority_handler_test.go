package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type databaseAuthorityAgent struct {
	mu              sync.Mutex
	inbounds        map[string]map[string]interface{}
	configOmitTags  map[string]bool
	mutations       []map[string]interface{}
	serviceControls int
	rawConfigWrites int
}

func newDatabaseAuthorityAgent(inbounds ...map[string]interface{}) *databaseAuthorityAgent {
	agent := &databaseAuthorityAgent{
		inbounds:       make(map[string]map[string]interface{}, len(inbounds)),
		configOmitTags: make(map[string]bool),
	}
	for _, inbound := range inbounds {
		if inbound == nil {
			continue
		}
		agent.inbounds[wireGuardStringValue(inbound["tag"])] = cloneInboundMap(inbound)
	}
	return agent
}

func (a *databaseAuthorityAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	a.mu.Lock()
	defer a.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		inbounds := make([]map[string]interface{}, 0, len(a.inbounds))
		for _, inbound := range a.inbounds {
			inbounds = append(inbounds, cloneInboundMap(inbound))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "inbounds": inbounds})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
		inbounds := make([]map[string]interface{}, 0, len(a.inbounds))
		for tag, inbound := range a.inbounds {
			if a.configOmitTags[tag] {
				continue
			}
			inbounds = append(inbounds, observedInboundConfig(inbound))
		}
		config, _ := json.Marshal(map[string]interface{}{
			"inbounds": inbounds, "outbounds": []interface{}{},
		})
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "config": string(config)})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.mutations = append(a.mutations, cloneInboundMap(request))
		action := wireGuardStringValue(request["action"])
		mutationID := wireGuardStringValue(request["mutation_id"])
		if action == "remove" {
			delete(a.inbounds, wireGuardStringValue(request["tag"]))
		} else {
			inbound, _ := request["inbound"].(map[string]interface{})
			stored := cloneInboundMap(inbound)
			stored["_mutation_id"] = mutationID
			a.inbounds[wireGuardStringValue(stored["tag"])] = stored
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "mutation_id": mutationID,
		})
	case r.URL.Path == "/api/child/services/control":
		a.serviceControls++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	case (r.Method == http.MethodPost || r.Method == http.MethodPut) && r.URL.Path == "/api/child/xray/config":
		a.rawConfigWrites++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	default:
		http.NotFound(w, r)
	}
}

func (a *databaseAuthorityAgent) mutationSnapshot() []map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]map[string]interface{}, len(a.mutations))
	for i, mutation := range a.mutations {
		result[i] = cloneInboundMap(mutation)
	}
	return result
}

func newDatabaseAuthorityHandlerRepo(t *testing.T, agentURL string) (*storage.TrafficRepository, *storage.RemoteServer) {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "database-authority-handler.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name:           "database-authority-edge",
		Token:          "database-authority-token",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModePush,
		IPAddress:      "127.0.0.1",
		ListenPort:     tunnelChainAgentPort(t, agentURL),
		XrayMode:       "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	return repo, server
}

func databaseAuthorityInbound(tag string, port int, mutationID string) map[string]interface{} {
	inbound := map[string]interface{}{
		"tag": tag, "listen": "0.0.0.0", "port": port, "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{}},
	}
	if mutationID != "" {
		inbound["_mutation_id"] = mutationID
	}
	return inbound
}

func seedDatabaseAuthorityDesired(t *testing.T, repo *storage.TrafficRepository, serverID int64, inbound map[string]interface{}, mutationID string) {
	t.Helper()
	raw, err := json.Marshal(observedInboundConfig(inbound))
	if err != nil {
		t.Fatal(err)
	}
	tag := wireGuardStringValue(inbound["tag"])
	if _, err := repo.UpsertActiveDesiredInbound(context.Background(), serverID, tag, mutationID, raw); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetRemoteInboundOwnership(context.Background(), serverID, tag, mutationID); err != nil {
		t.Fatal(err)
	}
}

func seedDatabaseAuthoritySnapshot(t *testing.T, repo *storage.TrafficRepository, serverID int64, inbounds ...map[string]interface{}) {
	t.Helper()
	items := make([]interface{}, 0, len(inbounds))
	for _, inbound := range inbounds {
		items = append(items, observedInboundConfig(inbound))
	}
	raw, err := json.Marshal(map[string]interface{}{
		"inbounds": items, "outbounds": []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertCurrentXraySnapshot(context.Background(), serverID, string(raw), storage.XraySnapshotSourceMasterWrite); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseInboundReconcileRemovesAgentOnlyWithoutClaimingNode(t *testing.T) {
	agentState := newDatabaseAuthorityAgent(databaseAuthorityInbound("agent-ghost", 2443, "agent-generation"))
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	seedDatabaseAuthoritySnapshot(t, repo, server.ID)

	result, err := NewRemoteManageHandler(repo, nil).reconcileDatabaseOwnedInboundsLeased(context.Background(), server.ID, "")
	if err != nil {
		t.Fatalf("reconcile database inbounds: %v", err)
	}
	if result.Removed != 1 || result.Restored != 0 || result.Updated != 0 {
		t.Fatalf("reconcile result = %+v", result)
	}
	mutations := agentState.mutationSnapshot()
	if len(mutations) != 1 || wireGuardStringValue(mutations[0]["action"]) != "remove" || wireGuardStringValue(mutations[0]["tag"]) != "agent-ghost" {
		t.Fatalf("Agent mutations = %#v", mutations)
	}
	if count, err := repo.CountNodes(context.Background()); err != nil || count != 0 {
		t.Fatalf("node count = %d, err=%v", count, err)
	}
	if owner, err := repo.GetRemoteInboundOwnership(context.Background(), server.ID, "agent-ghost"); err != nil || owner != "" {
		t.Fatalf("Agent-only inbound owner = %q, err=%v", owner, err)
	}
	desired, err := repo.GetDesiredInbound(context.Background(), server.ID, "agent-ghost")
	if err != nil {
		t.Fatal(err)
	}
	if desired != nil {
		t.Fatalf("Agent-only inbound leaked into desired state: %+v", desired)
	}
}

func TestDatabaseInboundReconcileBackfillsAuthorizedLiveInboundBeforeRemovingGhost(t *testing.T) {
	bound := databaseAuthorityInbound("legacy-bound", 8443, "old-agent-generation")
	ghost := databaseAuthorityInbound("agent-ghost", 9443, "agent-generation")
	agentState := newDatabaseAuthorityAgent(bound, ghost)
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	if _, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "admin", RawURL: "vless://fixture@example.test:443", NodeName: "Legacy bound",
		Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "legacy-bound",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := NewRemoteManageHandler(repo, nil).reconcileDatabaseOwnedInboundsLeased(context.Background(), server.ID, "")
	if err != nil {
		t.Fatalf("reconcile database inbounds: %v", err)
	}
	if result.Removed != 1 || result.Restored != 0 || result.Updated != 0 {
		t.Fatalf("reconcile result = %+v", result)
	}
	mutations := agentState.mutationSnapshot()
	if len(mutations) != 1 || wireGuardStringValue(mutations[0]["tag"]) != "agent-ghost" {
		t.Fatalf("Agent mutations = %#v", mutations)
	}
	desired, err := repo.GetDesiredInbound(context.Background(), server.ID, "legacy-bound")
	if err != nil || desired == nil || !strings.HasPrefix(desired.MutationID, "database-migration:") {
		t.Fatalf("backfilled desired = %+v, err=%v", desired, err)
	}
}

func TestDatabaseInboundReconcileUsesAuthorizedInventoryWhenBaseConfigOmitsConfdirInbound(t *testing.T) {
	bound := databaseAuthorityInbound("legacy-confdir", 8443, "old-agent-generation")
	bound["_source"] = "confdir"
	ghost := databaseAuthorityInbound("agent-ghost", 9443, "agent-generation")
	agentState := newDatabaseAuthorityAgent(bound, ghost)
	agentState.configOmitTags["legacy-confdir"] = true
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	if _, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "admin", RawURL: "vless://fixture@example.test:443", NodeName: "Legacy confdir",
		Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "legacy-confdir",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := NewRemoteManageHandler(repo, nil).reconcileDatabaseOwnedInboundsLeased(context.Background(), server.ID, "")
	if err != nil {
		t.Fatalf("reconcile database inbounds: %v", err)
	}
	if result.Removed != 1 || result.Restored != 0 || result.Updated != 0 {
		t.Fatalf("reconcile result = %+v", result)
	}
	desired, err := repo.GetDesiredInbound(context.Background(), server.ID, "legacy-confdir")
	if err != nil || desired == nil {
		t.Fatalf("backfilled desired = %+v, err=%v", desired, err)
	}
	if strings.Contains(string(desired.InboundJSON), "_source") || strings.Contains(string(desired.InboundJSON), "_mutation_id") {
		t.Fatalf("Agent observation metadata leaked into desired inbound: %s", desired.InboundJSON)
	}
	mutations := agentState.mutationSnapshot()
	if len(mutations) != 1 || wireGuardStringValue(mutations[0]["tag"]) != "agent-ghost" {
		t.Fatalf("Agent mutations = %#v", mutations)
	}
}

func TestDatabaseInboundReconcileFailsClosedWhenAuthorizedDefinitionIsMissing(t *testing.T) {
	ghost := databaseAuthorityInbound("agent-ghost", 9443, "agent-generation")
	agentState := newDatabaseAuthorityAgent(ghost)
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	if _, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "admin", RawURL: "vless://fixture@example.test:443", NodeName: "Missing legacy",
		Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "missing-legacy",
	}); err != nil {
		t.Fatal(err)
	}

	_, err := NewRemoteManageHandler(repo, nil).reconcileDatabaseOwnedInboundsLeased(context.Background(), server.ID, "")
	if err == nil || !strings.Contains(err.Error(), "missing-legacy has no complete desired definition") {
		t.Fatalf("reconcile error = %v", err)
	}
	if mutations := agentState.mutationSnapshot(); len(mutations) != 0 {
		t.Fatalf("fail-closed reconciliation mutated Agent: %#v", mutations)
	}
}

func TestDatabaseInboundReconcileRestoresDesiredAndEnforcesMutationFence(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		observed     map[string]interface{}
		wantRestored int
		wantUpdated  int
	}{
		{name: "missing desired", wantRestored: 1},
		{name: "structural drift", observed: databaseAuthorityInbound("database-owned", 9443, "database-generation"), wantUpdated: 1},
		{name: "mutation fence", observed: databaseAuthorityInbound("database-owned", 8443, "agent-generation"), wantUpdated: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			agentState := newDatabaseAuthorityAgent(testCase.observed)
			agent := httptest.NewServer(agentState)
			defer agent.Close()
			repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
			desired := databaseAuthorityInbound("database-owned", 8443, "")
			seedDatabaseAuthorityDesired(t, repo, server.ID, desired, "database-generation")
			seedDatabaseAuthoritySnapshot(t, repo, server.ID, desired)

			result, err := NewRemoteManageHandler(repo, nil).reconcileDatabaseOwnedInboundsLeased(context.Background(), server.ID, "")
			if err != nil {
				t.Fatalf("reconcile database inbounds: %v", err)
			}
			if result.Restored != testCase.wantRestored || result.Updated != testCase.wantUpdated || result.Removed != 0 {
				t.Fatalf("reconcile result = %+v", result)
			}
			mutations := agentState.mutationSnapshot()
			if len(mutations) != 1 {
				t.Fatalf("Agent mutations = %#v", mutations)
			}
			mutation := mutations[0]
			if wireGuardStringValue(mutation["action"]) != "add" || wireGuardStringValue(mutation["mutation_id"]) != "database-generation" {
				t.Fatalf("mutation did not use database generation: %#v", mutation)
			}
			gotInbound, _ := mutation["inbound"].(map[string]interface{})
			if !sameInboundConfig(gotInbound, desired) {
				t.Fatalf("restored inbound = %#v, want %#v", gotInbound, desired)
			}
		})
	}
}

func TestDatabaseInboundMigrationFenceAcceptsIdenticalLegacyListenerWithoutRewrite(t *testing.T) {
	desired := databaseAuthorityInbound("database-owned", 8443, "")
	observed := databaseAuthorityInbound("database-owned", 8443, "old-agent-generation")
	agentState := newDatabaseAuthorityAgent(observed)
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	seedDatabaseAuthorityDesired(t, repo, server.ID, desired, "database-migration:1:database-owned")

	result, err := NewRemoteManageHandler(repo, nil).reconcileDatabaseOwnedInboundsLeased(context.Background(), server.ID, "")
	if err != nil {
		t.Fatalf("reconcile database inbounds: %v", err)
	}
	if result != (databaseInboundReconcileResult{}) {
		t.Fatalf("reconcile result = %+v", result)
	}
	if mutations := agentState.mutationSnapshot(); len(mutations) != 0 {
		t.Fatalf("migration fence rewrote identical listener: %#v", mutations)
	}
	owner, err := repo.GetRemoteInboundOwnership(context.Background(), server.ID, "database-owned")
	if err != nil || owner != "database-migration:1:database-owned" {
		t.Fatalf("database owner = %q, err=%v", owner, err)
	}
}

func TestDatabaseTunnelTakeoverAcceptsLegacyEmptyMode(t *testing.T) {
	if !databaseTunnelTakeoverEnabled(&storage.RemoteServer{StealSelf: true}) {
		t.Fatal("legacy empty steal mode should authorize tunnel takeover")
	}
	if !databaseTunnelTakeoverEnabled(&storage.RemoteServer{StealSelf: true, StealMode: " TUNNEL "}) {
		t.Fatal("tunnel mode should authorize tunnel takeover")
	}
	if databaseTunnelTakeoverEnabled(&storage.RemoteServer{StealSelf: true, StealMode: "fallback"}) ||
		databaseTunnelTakeoverEnabled(&storage.RemoteServer{StealMode: "tunnel"}) {
		t.Fatal("unapproved takeover mode was accepted")
	}
}

func TestActiveForwardInboundDefinitionRequiresFreshLeaseAndExactDatabaseShape(t *testing.T) {
	now := time.Now().UTC()
	forward := storage.UserForwardRule{DesiredState: storage.ForwardDesiredActive, EffectiveExpiresAt: timePointer(now.Add(time.Hour))}
	hop := storage.UserForwardHop{
		ServerID: 7, ResourceTag: "rd-tun-test", ListenPort: 39001, NextHost: "198.51.100.9", NextPort: 443,
		DesiredState: storage.ForwardDesiredActive, ObservedState: storage.ForwardObservedActive,
		Generation: 1, AppliedGeneration: 1, UpdatedAt: now,
	}
	expected, ok := databaseForwardInbound(forward, hop, 7, now)
	if !ok {
		t.Fatal("fresh active forward was rejected")
	}
	want := map[string]interface{}{
		"tag": "rd-tun-test", "listen": "0.0.0.0", "port": 39001, "protocol": "dokodemo-door",
		"settings": map[string]interface{}{"address": "198.51.100.9", "port": 443, "network": "tcp,udp", "followRedirect": false},
		"sniffing": map[string]interface{}{"enabled": false},
	}
	if !sameInboundConfig(expected, want) {
		t.Fatalf("forward inbound = %#v, want %#v", expected, want)
	}
	hop.UpdatedAt = now.Add(-forwardTunnelLeaseDuration)
	if _, ok := databaseForwardInbound(forward, hop, 7, now); ok {
		t.Fatal("expired forwarding lease was trusted")
	}
	hop.UpdatedAt = now
	forward.EffectiveExpiresAt = timePointer(now)
	if _, ok := databaseForwardInbound(forward, hop, 7, now); ok {
		t.Fatal("expired forwarding hard deadline was trusted")
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func TestDatabaseInboundReconcileRemovesForwardWithDatabaseShapeMismatch(t *testing.T) {
	agentState := newDatabaseAuthorityAgent()
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, entry := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	ctx := context.Background()
	for _, user := range []struct {
		name string
		role string
	}{{"admin", storage.RoleAdmin}, {"alice", storage.RoleUser}} {
		if err := repo.CreateUser(ctx, user.name, user.name+"@example.test", user.name, "hash", user.role, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repo.UpdateRemoteServerXrayStatus(ctx, entry.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	target := storage.RemoteServer{
		Name: "database-authority-target", Token: "target-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "198.51.100.20", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, &target); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateRemoteServerXrayStatus(ctx, target.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", RawURL: "vless://fixture@example.test:443", NodeName: "Forward target",
		Protocol: "vless", Enabled: true, OriginalServer: target.Name, InboundTag: "target-in",
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := repo.CreateTunnelTemplate(ctx, storage.TunnelTemplate{
		Name: "authority-forward", State: storage.TunnelStateActive, BillingMode: storage.ManagedBillingDownload,
		TrafficMultiplierMilli: 1000, AllowManagedTarget: true, PortRangeStart: 39000, PortRangeEnd: 39100,
		CreatedBy: "admin", Hops: []storage.TunnelTemplateHop{{ServerID: entry.ID}, {ServerID: target.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	grant, err := repo.CreateUserTunnelGrant(ctx, storage.UserTunnelGrant{
		Username: "alice", TunnelID: tunnel.ID, Enabled: true, StartsAt: now.Add(-time.Hour), ExpiresAt: &expires,
		MaxActiveForwards: 1, AllowManagedTarget: true, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	forward, err := repo.CreateUserForward(ctx, storage.CreateUserForwardInput{
		Username: "alice", Name: "shape-check", GrantPublicID: grant.PublicID, TargetNodeID: node.ID,
		TargetHost: target.IPAddress, TargetPort: 443, EffectiveExpiresAt: &expires, Actor: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, hop := range forward.Hops {
		if err := repo.MarkUserForwardHop(ctx, hop.ID, storage.ForwardObservedActive, true, ""); err != nil {
			t.Fatal(err)
		}
	}
	forward, err = repo.GetUserForward(ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	var entryHop storage.UserForwardHop
	for _, hop := range forward.Hops {
		if hop.ServerID == entry.ID {
			entryHop = hop
		}
	}
	expected, ok := databaseForwardInbound(*forward, entryHop, entry.ID, time.Now().UTC())
	if !ok {
		t.Fatalf("fresh database forward was not active: %+v", entryHop)
	}
	mismatched := cloneInboundMap(expected)
	mismatched["settings"].(map[string]interface{})["address"] = "203.0.113.250"
	mismatched["_mutation_id"] = "guard-generation"
	agentState.mu.Lock()
	agentState.inbounds[entryHop.ResourceTag] = mismatched
	agentState.mu.Unlock()

	result, err := NewRemoteManageHandler(repo, nil).reconcileDatabaseOwnedInboundsLeased(ctx, entry.ID, "")
	if err != nil {
		t.Fatalf("reconcile database inbounds: %v", err)
	}
	if result.Removed != 1 || result.Restored != 0 || result.Updated != 0 {
		t.Fatalf("reconcile result = %+v", result)
	}
	mutations := agentState.mutationSnapshot()
	if len(mutations) != 1 || wireGuardStringValue(mutations[0]["action"]) != "remove" ||
		wireGuardStringValue(mutations[0]["tag"]) != entryHop.ResourceTag {
		t.Fatalf("mismatched forward mutations = %#v", mutations)
	}
}

func TestDatabaseInboundReconnectDoesNotRestartOrAcceptAgentOnlyInbound(t *testing.T) {
	agentState := newDatabaseAuthorityAgent(databaseAuthorityInbound("reconnect-ghost", 3443, "agent-generation"))
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	seedDatabaseAuthoritySnapshot(t, repo, server.ID)

	NewRemoteManageHandler(repo, nil).SyncXrayConfigOnReconnect(context.Background(), server.ID, storage.RemoteServerStatusOffline)

	agentState.mu.Lock()
	serviceControls := agentState.serviceControls
	rawConfigWrites := agentState.rawConfigWrites
	agentState.mu.Unlock()
	if serviceControls != 0 || rawConfigWrites != 0 {
		t.Fatalf("reconnect performed restart/config write: controls=%d raw_writes=%d", serviceControls, rawConfigWrites)
	}
	if count, err := repo.CountNodes(context.Background()); err != nil || count != 0 {
		t.Fatalf("node count = %d, err=%v", count, err)
	}
	if owner, err := repo.GetRemoteInboundOwnership(context.Background(), server.ID, "reconnect-ghost"); err != nil || owner != "" {
		t.Fatalf("reconnect accepted Agent ownership %q, err=%v", owner, err)
	}
	snapshot, err := repo.GetCurrentXraySnapshot(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	inbounds, err := xrayConfigInbounds(snapshot.ConfigJSON)
	if err != nil {
		t.Fatal(err)
	}
	if inbounds["reconnect-ghost"] != nil {
		t.Fatalf("Agent-only inbound entered canonical snapshot: %s", snapshot.ConfigJSON)
	}
}

func TestHandleRawXrayConfigCannotChangeDatabaseInbounds(t *testing.T) {
	agentState := newDatabaseAuthorityAgent()
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	desired := databaseAuthorityInbound("database-owned", 8443, "")
	seedDatabaseAuthorityDesired(t, repo, server.ID, desired, "database-generation")
	seedDatabaseAuthoritySnapshot(t, repo, server.ID, desired)
	handler := NewRemoteManageHandler(repo, nil)

	for _, testCase := range []struct {
		name     string
		inbounds []interface{}
	}{
		{name: "add Agent-only inbound", inbounds: []interface{}{desired, databaseAuthorityInbound("raw-added", 9443, "")}},
		{name: "remove desired inbound", inbounds: []interface{}{}},
		{name: "modify desired inbound", inbounds: []interface{}{databaseAuthorityInbound("database-owned", 10443, "")}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config, err := json.Marshal(map[string]interface{}{
				"inbounds": testCase.inbounds, "outbounds": []interface{}{},
			})
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]interface{}{"config": string(config)})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPut, "/api/admin/remote/xray/config?server_id="+strconv.FormatInt(server.ID, 10), bytes.NewReader(body))
			response := httptest.NewRecorder()
			handler.HandleXrayConfig(response, request)
			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
			}
		})
	}

	agentState.mu.Lock()
	rawConfigWrites := agentState.rawConfigWrites
	agentState.mu.Unlock()
	if rawConfigWrites != 0 {
		t.Fatalf("rejected raw config reached Agent %d time(s)", rawConfigWrites)
	}
}

func TestHandleXrayConfigFilesRejectsWrites(t *testing.T) {
	handler := NewRemoteManageHandler(nil, nil)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			request := httptest.NewRequest(method, "/api/admin/remote/xray/config/files?server_id=1&file=config.json", bytes.NewBufferString(`{"file":"config.json","content":"{}"}`))
			response := httptest.NewRecorder()

			handler.HandleXrayConfigFiles(response, request)

			if response.Code != http.StatusGone {
				t.Fatalf("status=%d body=%s, want 410", response.Code, response.Body.String())
			}
		})
	}
}

func TestFederationRejectsActualXrayConfigFilesWritePath(t *testing.T) {
	handler := NewFederationHandler(nil, nil, nil)
	payload := []byte(`{"method":"PUT","path":"/api/child/xray/config/files?file=config.json","body":"e30="}`)
	request := httptest.NewRequest(http.MethodPost, "/api/federation/manage", bytes.NewReader(payload))
	response := httptest.NewRecorder()

	handler.handleManage(response, request, 1)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", response.Code, response.Body.String())
	}
}

func TestXrayConfigFilesWriteTriggersSnapshotRefreshClassification(t *testing.T) {
	if !shouldRefreshXraySnapshotAfter(http.MethodPut, "/api/child/xray/config/files?file=config.json") {
		t.Fatal("actual Xray config files write path was not classified as mutating")
	}
}

func TestAgentMutationAcknowledgedRequiresMatchingInboundFence(t *testing.T) {
	request := []byte(`{"action":"add","mutation_id":"generation-two","inbound":{"tag":"edge"}}`)
	for _, testCase := range []struct {
		name     string
		response string
		want     bool
	}{
		{name: "matching", response: `{"success":true,"mutation_id":"generation-two"}`, want: true},
		{name: "rejected", response: `{"success":false,"mutation_id":"generation-two"}`},
		{name: "superseded", response: `{"success":true,"mutation_id":"generation-two","superseded":true}`},
		{name: "wrong generation", response: `{"success":true,"mutation_id":"generation-one"}`},
		{name: "invalid response", response: `not-json`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := agentMutationAcknowledged("/api/child/inbounds", request, []byte(testCase.response)); got != testCase.want {
				t.Fatalf("acknowledged=%v, want %v", got, testCase.want)
			}
		})
	}
}

func TestCanonicalizeDatabaseXrayConfigRequestReplacesInternalCandidateInbounds(t *testing.T) {
	agentState := newDatabaseAuthorityAgent()
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	desired := databaseAuthorityInbound("database-owned", 8443, "")
	seedDatabaseAuthorityDesired(t, repo, server.ID, desired, "database-generation")
	seedDatabaseAuthoritySnapshot(t, repo, server.ID, desired)
	handler := NewRemoteManageHandler(repo, nil)

	candidate, err := json.Marshal(map[string]interface{}{
		"inbounds":  []interface{}{databaseAuthorityInbound("internal-bypass", 9443, "")},
		"outbounds": []interface{}{map[string]interface{}{"tag": "new-out", "protocol": "freedom"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]interface{}{"config": string(candidate), "force": true})
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := handler.canonicalizeDatabaseXrayConfigRequest(context.Background(), server.ID, body)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Config string `json:"config"`
		Force  bool   `json:"force"`
	}
	if err := json.Unmarshal(normalized, &request); err != nil {
		t.Fatal(err)
	}
	inbounds, err := xrayConfigInbounds(request.Config)
	if err != nil {
		t.Fatal(err)
	}
	if !request.Force || inbounds["database-owned"] == nil || inbounds["internal-bypass"] != nil {
		t.Fatalf("canonical request force=%v inbounds=%#v", request.Force, inbounds)
	}
	if !strings.Contains(request.Config, `"tag":"new-out"`) {
		t.Fatalf("non-inbound config was not preserved: %s", request.Config)
	}
}
