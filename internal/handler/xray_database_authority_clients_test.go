package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func databaseAuthorityInboundWithClients(tag string, port int, clients ...map[string]interface{}) map[string]interface{} {
	items := make([]interface{}, 0, len(clients))
	for _, client := range clients {
		items = append(items, client)
	}
	return map[string]interface{}{
		"tag": tag, "listen": "0.0.0.0", "port": port, "protocol": "vless",
		"settings": map[string]interface{}{"clients": items},
	}
}

func seedLegacyDatabaseInboundCredential(
	t *testing.T,
	repo *storage.TrafficRepository,
	server *storage.RemoteServer,
	username string,
	credentialJSON string,
	packageEnd time.Time,
) {
	t.Helper()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "owner", "owner@example.test", "Owner", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, username, username+"@example.test", username, "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", RawURL: "vless://owner-id@example.test:8443", NodeName: "Database authority node",
		Protocol: "vless", Enabled: true, OriginalServer: server.Name,
		InboundTag: "database-owned", InboundMutationID: "database-generation",
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "Database authority package", CycleDays: 30, Nodes: []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AssignPackageToUser(ctx, username, packageID, packageEnd.Add(-30*24*time.Hour), packageEnd, false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: username, ServerID: server.ID, InboundTag: "database-owned",
		Protocol: "vless", CredentialJSON: credentialJSON,
	}); err != nil {
		t.Fatal(err)
	}
}

func reconciledDatabaseAuthorityClients(t *testing.T, agentState *databaseAuthorityAgent, repo *storage.TrafficRepository, serverID int64) []interface{} {
	t.Helper()
	result, err := NewRemoteManageHandler(repo, nil).reconcileDatabaseOwnedInboundsLeased(context.Background(), serverID, "")
	if err != nil {
		t.Fatalf("reconcile database inbounds: %v", err)
	}
	if result.Restored+result.Updated != 1 {
		t.Fatalf("reconcile result = %+v", result)
	}
	mutations := agentState.mutationSnapshot()
	if len(mutations) != 1 {
		t.Fatalf("Agent mutations = %#v", mutations)
	}
	inbound, _ := mutations[0]["inbound"].(map[string]interface{})
	settings, _ := inbound["settings"].(map[string]interface{})
	clients, _ := settings["clients"].([]interface{})
	return clients
}

func TestDatabaseInboundReconcileDoesNotPromoteAgentClient(t *testing.T) {
	owner := map[string]interface{}{"id": "owner-id", "email": "owner__database-owned"}
	injected := map[string]interface{}{"id": "injected-id", "email": "attacker__database-owned"}
	desired := databaseAuthorityInboundWithClients("database-owned", 8443, owner)
	observed := databaseAuthorityInboundWithClients("database-owned", 8443, owner, injected)
	observed["_mutation_id"] = "database-generation"
	agentState := newDatabaseAuthorityAgent(observed)
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	seedDatabaseAuthorityDesired(t, repo, server.ID, desired, "database-generation")
	seedDatabaseAuthoritySnapshot(t, repo, server.ID, desired)

	clients := reconciledDatabaseAuthorityClients(t, agentState, repo, server.ID)
	if len(clients) != 1 || wireGuardStringValue(clients[0].(map[string]interface{})["id"]) != "owner-id" {
		t.Fatalf("reconciled clients = %#v, want only database owner", clients)
	}
	snapshot, err := repo.GetCurrentXraySnapshot(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	inbounds, err := xrayConfigInbounds(snapshot.ConfigJSON)
	if err != nil {
		t.Fatal(err)
	}
	snapshotSettings, _ := inbounds["database-owned"]["settings"].(map[string]interface{})
	if got, _ := snapshotSettings["clients"].([]interface{}); len(got) != 1 {
		t.Fatalf("Agent-injected client entered snapshot: %s", snapshot.ConfigJSON)
	}
}

func TestDatabaseInboundReconcileDoesNotReviveInactiveCredential(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		configure func(*testing.T, *storage.TrafficRepository, string)
		end       time.Time
	}{
		{name: "expired package", end: time.Now().UTC().Add(-time.Hour)},
		{
			name: "disabled user", end: time.Now().UTC().Add(time.Hour),
			configure: func(t *testing.T, repo *storage.TrafficRepository, username string) {
				t.Helper()
				if err := repo.UpdateUserStatus(context.Background(), username, false); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "over limit", end: time.Now().UTC().Add(time.Hour),
			configure: func(t *testing.T, repo *storage.TrafficRepository, username string) {
				t.Helper()
				if err := repo.UpdateUserOverLimit(context.Background(), username, true); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			agentState := newDatabaseAuthorityAgent()
			agent := httptest.NewServer(agentState)
			defer agent.Close()
			repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
			// Simulate a desired row backfilled from an old snapshot while this
			// credential was still active. Current authorization must win.
			stale := map[string]interface{}{"id": "alice-id", "email": "alice__database-owned"}
			desired := databaseAuthorityInboundWithClients("database-owned", 8443, stale)
			seedDatabaseAuthorityDesired(t, repo, server.ID, desired, "database-generation")
			seedDatabaseAuthoritySnapshot(t, repo, server.ID, desired)
			seedLegacyDatabaseInboundCredential(
				t, repo, server, "alice", `{"id":"alice-id","email":"alice__database-owned"}`, testCase.end,
			)
			if testCase.configure != nil {
				testCase.configure(t, repo, "alice")
			}

			if clients := reconciledDatabaseAuthorityClients(t, agentState, repo, server.ID); len(clients) != 0 {
				t.Fatalf("inactive credential was restored: %#v", clients)
			}
		})
	}
}

func TestDatabaseInboundReconcileRestoresEffectiveDatabaseCredential(t *testing.T) {
	agentState := newDatabaseAuthorityAgent()
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	repo, server := newDatabaseAuthorityHandlerRepo(t, agent.URL)
	desired := databaseAuthorityInboundWithClients("database-owned", 8443)
	seedDatabaseAuthorityDesired(t, repo, server.ID, desired, "database-generation")
	seedDatabaseAuthoritySnapshot(t, repo, server.ID, desired)
	seedLegacyDatabaseInboundCredential(
		t, repo, server, "alice", `{"id":"alice-id","email":"alice__database-owned"}`, time.Now().UTC().Add(time.Hour),
	)

	clients := reconciledDatabaseAuthorityClients(t, agentState, repo, server.ID)
	if len(clients) != 1 {
		t.Fatalf("restored clients = %#v", clients)
	}
	credential, _ := clients[0].(map[string]interface{})
	if wireGuardStringValue(credential["id"]) != "alice-id" || wireGuardStringValue(credential["email"]) != "alice__database-owned" {
		t.Fatalf("restored credential = %#v", credential)
	}
}

func classicDatabaseAuthorityFixture(t *testing.T, liveClient map[string]interface{}) (*storage.TrafficRepository, *storage.RemoteServer, map[string]map[string]interface{}, map[string]map[string]interface{}) {
	t.Helper()
	ctx := context.Background()
	repo, server := newDatabaseAuthorityHandlerRepo(t, "http://127.0.0.1:1")
	if err := repo.CreateUser(ctx, "owner", "owner@example.test", "Owner", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	marker := storage.ManagedShadowsocksMultiUserMarker
	clashJSON, err := json.Marshal(map[string]interface{}{
		"type": "ss", "cipher": "aes-128-gcm", "password": "owner-password", marker: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", RawURL: "ss://owner@example.test:8388", NodeName: "Classic database authority node",
		Protocol: "shadowsocks", ClashConfig: string(clashJSON), ParsedConfig: string(clashJSON), Enabled: true,
		OriginalServer: server.Name, InboundTag: "database-owned", InboundMutationID: "database-generation",
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{Name: "Classic database authority package", CycleDays: 30, Nodes: []int64{node.ID}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "database-owned", Protocol: "shadowsocks",
		CredentialJSON: `{"password":"alice-password","email":"alice__database-owned","level":0}`,
	}); err != nil {
		t.Fatal(err)
	}
	owner := map[string]interface{}{"method": "aes-128-gcm", "password": "owner-password", "email": "owner__database-owned"}
	desiredInbound := map[string]interface{}{
		"tag": "database-owned", "listen": "0.0.0.0", "port": float64(8388), "protocol": "shadowsocks",
		"settings": map[string]interface{}{"clients": []interface{}{owner}},
	}
	liveInbound := cloneInboundMap(desiredInbound)
	liveSettings := liveInbound["settings"].(map[string]interface{})
	liveSettings["clients"] = append(liveSettings["clients"].([]interface{}), liveClient)
	return repo, server,
		map[string]map[string]interface{}{"database-owned": desiredInbound},
		map[string]map[string]interface{}{"database-owned": liveInbound}
}

func TestDatabaseInboundRebuildBackfillsClassicMethodFromMatchingLiveClient(t *testing.T) {
	liveClient := map[string]interface{}{
		"method": "aes-128-gcm", "password": "alice-password", "email": "alice__database-owned", "level": float64(0),
	}
	repo, server, desired, observed := classicDatabaseAuthorityFixture(t, liveClient)
	if err := NewRemoteManageHandler(repo, nil).rebuildDatabaseAuthorizedInboundClients(context.Background(), server.ID, desired, observed); err != nil {
		t.Fatalf("rebuild database clients: %v", err)
	}
	settings := desired["database-owned"]["settings"].(map[string]interface{})
	clients := settings["clients"].([]interface{})
	if len(clients) != 2 || wireGuardStringValue(clients[1].(map[string]interface{})["method"]) != "aes-128-gcm" {
		t.Fatalf("rebuilt classic clients = %#v", clients)
	}
	stored, err := repo.GetUserInboundConfig(context.Background(), "alice", server.ID, "database-owned")
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]interface{}
	if err := json.Unmarshal([]byte(stored.CredentialJSON), &persisted); err != nil || persisted["method"] != "aes-128-gcm" {
		t.Fatalf("persisted credential = %#v, err=%v", persisted, err)
	}
}

func TestDatabaseInboundRebuildRejectsUnverifiedClassicMethodBackfill(t *testing.T) {
	liveClient := map[string]interface{}{
		"method": "aes-256-gcm", "password": "alice-password", "email": "alice__database-owned", "level": float64(0),
	}
	repo, server, desired, observed := classicDatabaseAuthorityFixture(t, liveClient)
	err := NewRemoteManageHandler(repo, nil).rebuildDatabaseAuthorizedInboundClients(context.Background(), server.ID, desired, observed)
	if err == nil {
		t.Fatal("mismatched live classic cipher was accepted")
	}
	settings := desired["database-owned"]["settings"].(map[string]interface{})
	if clients := settings["clients"].([]interface{}); len(clients) != 1 {
		t.Fatalf("unverified classic credential was appended: %#v", clients)
	}
	stored, getErr := repo.GetUserInboundConfig(context.Background(), "alice", server.ID, "database-owned")
	if getErr != nil {
		t.Fatal(getErr)
	}
	var persisted map[string]interface{}
	if decodeErr := json.Unmarshal([]byte(stored.CredentialJSON), &persisted); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if _, exists := persisted["method"]; exists {
		t.Fatalf("unverified method was persisted: %#v", persisted)
	}
}
