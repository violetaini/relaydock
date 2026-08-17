package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func TestDatabaseInboundAuthorityKeepsManagedCredentialWhenLegacyPackageOverLimit(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "mixed-authority.db")
	repo, err := storage.NewTrafficRepository(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "mixed-authority-edge", Token: "token", IPAddress: "203.0.113.30",
		XrayMode: "embedded", Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "mixed-authority", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "mixed-in",
		ClashConfig: `{"name":"mixed-authority","type":"vless","server":"203.0.113.30","port":443,"uuid":"owner-uuid"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveNodes: 1,
		SpeedLimitMbps: 50, ConnectionLimit: 4,
		BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "owner",
	}); err != nil {
		t.Fatal(err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "mixed-in", Protocol: "vless",
		CredentialJSON: `{"id":"alice-uuid","email":"alice__mixed-in"}`,
	}); err != nil {
		t.Fatal(err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "mixed-in")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetUserNodeSelectionCredential(ctx, activation.Selection.ID, credential.ID); err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "over-limit legacy package", CycleDays: 30, Nodes: []int64{node.ID},
		SpeedLimitMbps: 5, DeviceLimit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Current APIs correctly reject package/custom overlap. Preserve a legacy
	// pre-mode-migration overlap explicitly so authority remains fail-safe while
	// old rows are being reconciled instead of deleting an independent peer.
	legacyDB, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyDB.ExecContext(ctx, `UPDATE users SET
package_id = ?, authorization_mode = ?, package_start_date = ?, package_end_date = ?
WHERE username = ?`, packageID, storage.AuthorizationModePackage, now.Add(-time.Hour), expires, "alice"); err != nil {
		_ = legacyDB.Close()
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateUserOverLimit(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}

	desired := map[string]map[string]interface{}{
		"mixed-in": databaseAuthorityInboundWithClients("mixed-in", 443),
	}
	if err := NewRemoteManageHandler(repo, nil).rebuildDatabaseAuthorizedInboundClients(ctx, server.ID, desired, nil); err != nil {
		t.Fatalf("rebuild mixed managed credential: %v", err)
	}
	settings := desired["mixed-in"]["settings"].(map[string]interface{})
	clients := settings["clients"].([]interface{})
	if len(clients) != 1 || wireGuardStringValue(clients[0].(map[string]interface{})["id"]) != "alice-uuid" {
		t.Fatalf("package over-limit removed independent managed credential: %#v", clients)
	}

	limiter, err := NewLimiterConfigPusher(repo, nil).BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build mixed managed limiter: %v", err)
	}
	managedLimit := findLimiterUser(t, limiter, "mixed-in", "alice__mixed-in")
	if managedLimit.SpeedLimit != 6_250_000 || managedLimit.DeviceLimit != 4 {
		t.Fatalf("over-limit package policy contaminated independent managed limit: %#v", managedLimit)
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

func TestDatabaseInboundRebuildRestoresSanitizedWireGuardPeer(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)
	if err := repo.CreateUser(ctx, "owner", "owner@example.test", "Owner", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	server := &storage.RemoteServer{Name: "wg-database-edge", Token: "token", IPAddress: "127.0.0.1", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	settings, _ := wireGuardCredentialTestSettings(t)
	bootstrapPeer := wireGuardInterfaceSlice(settings["peers"])[0].(map[string]interface{})
	bootstrapPublicKey := wireGuardStringValue(bootstrapPeer["publicKey"])
	probePrivateKey, probePublicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	settings["peers"] = append(wireGuardInterfaceSlice(settings["peers"]), map[string]interface{}{
		"publicKey": probePublicKey, "allowedIPs": []interface{}{"10.66.66.3/32"}, "keepAlive": float64(0),
	})
	desiredInbound := map[string]interface{}{
		"tag": "wg-database", "listen": "0.0.0.0", "port": float64(51820), "protocol": "wireguard",
		"settings": cloneInboundMap(map[string]interface{}{"settings": settings})["settings"],
	}
	resource, err := repo.CreateManagedInboundResource(ctx, storage.ManagedInboundResource{
		ServerID: server.ID, DisplayName: "wg-database", Protocol: "wireguard", InboundTag: "wg-database",
		MutationID: "managed-wireguard:wg-generation", EndpointHost: "203.0.113.10", EndpointPort: 51820,
		PublicMetadataJSON: json.RawMessage(`{}`), CreatedBy: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateWireGuardProbePeer(ctx, storage.WireGuardProbePeer{
		ResourceID: resource.ID, PublicKey: probePublicKey, PrivateKey: probePrivateKey,
		Addresses: []string{"10.66.66.3/32"}, State: storage.WireGuardProbePeerStatePending,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MarkWireGuardProbePeerActive(ctx, resource.ID); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "wg-database", Protocol: "wireguard", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-database", InboundMutationID: "managed-wireguard:wg-generation",
		ClashConfig: fmt.Sprintf(
			`{"name":"wg-database","type":"wireguard","server":"203.0.113.10","port":51820,"private-key":%q,"public-key":%q}`,
			wireGuardYAMLTestKey(0x51), wireGuardYAMLTestKey(0x52),
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{Name: "wg-database", CycleDays: 30, Nodes: []int64{node.ID}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	alice, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := getOrCreateInboundCredential(ctx, repo, alice, server.ID, "wg-database", "wireguard", settings); err != nil {
		t.Fatal(err)
	}
	seedDatabaseAuthorityDesired(t, repo, server.ID, desiredInbound, "managed-wireguard:wg-generation")
	desired := map[string]map[string]interface{}{"wg-database": desiredInbound}
	if err := NewRemoteManageHandler(repo, nil).rebuildDatabaseAuthorizedInboundClients(ctx, server.ID, desired, nil); err != nil {
		t.Fatalf("rebuild database WireGuard peers: %v", err)
	}

	peerSettings := desired["wg-database"]["settings"].(map[string]interface{})
	peers := peerSettings["peers"].([]interface{})
	if len(peers) != 2 {
		t.Fatalf("rebuilt WireGuard peers=%#v, want probe plus user", peers)
	}
	basePeer := peers[0].(map[string]interface{})
	if !equalManagedWireGuardKeys(wireGuardStringValue(basePeer["publicKey"]), probePublicKey) ||
		equalManagedWireGuardKeys(wireGuardStringValue(basePeer["publicKey"]), bootstrapPublicKey) {
		t.Fatalf("rebuilt base peer=%#v, want only database probe %q", basePeer, probePublicKey)
	}
	peer := peers[1].(map[string]interface{})
	if len(peer) != 3 || peer["publicKey"] == nil || peer["allowedIPs"] == nil || peer["keepAlive"] == nil {
		t.Fatalf("rebuilt WireGuard peer is not server-only: %#v", peer)
	}
	for _, forbidden := range []string{"privateKey", "encryptedPrivateKey", "serverPublicKey", "address", "email"} {
		if _, leaked := peer[forbidden]; leaked {
			t.Fatalf("rebuilt WireGuard peer leaked %s: %#v", forbidden, peer)
		}
	}
	stored, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-database")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored.CredentialJSON, "encryptedPrivateKey") || strings.Contains(stored.CredentialJSON, `"privateKey"`) {
		t.Fatalf("stored WireGuard credential is not encrypted: %s", stored.CredentialJSON)
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
