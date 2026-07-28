package handler

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
	"miaomiaowux/internal/storage"
)

func newManagedSecurityTestRepo(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("create test repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func createManagedSecurityTestUser(t *testing.T, repo *storage.TrafficRepository, username, role string) {
	t.Helper()
	if err := repo.CreateUser(context.Background(), username, username+"@example.test", username, "test-hash", role, ""); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
}

func TestPrepareImportedNodeOrdinaryUserCannotClaimManagedInbound(t *testing.T) {
	h := &nodesHandler{}
	node := storage.Node{OriginalServer: "managed-server", InboundTag: "vless-in"}

	h.prepareImportedNode(context.Background(), &node, false)

	if node.OriginalServer != "" || node.InboundTag != "" {
		t.Fatalf("ordinary import retained managed association: server=%q tag=%q", node.OriginalServer, node.InboundTag)
	}
}

func TestApplyUserCredentialsFailsClosed(t *testing.T) {
	managed := storage.Node{Protocol: "vless", OriginalServer: "edge-1", InboundTag: "vless-in"}
	adminProxy := map[string]any{"uuid": "admin-uuid", "flow": "xtls-rprx-vision"}

	if applyUserCredentials(adminProxy, managed, nil) {
		t.Fatal("managed node without a credential unexpectedly passed")
	}
	if got := adminProxy["uuid"]; got != "admin-uuid" {
		t.Fatalf("failed replacement mutated proxy: %v", got)
	}

	badJSON := map[credKey]string{{"edge-1", "vless-in"}: "{not-json"}
	if applyUserCredentials(adminProxy, managed, badJSON) {
		t.Fatal("managed node with corrupt credential JSON unexpectedly passed")
	}

	valid := map[credKey]string{{"edge-1", "vless-in"}: `{"id":"user-uuid"}`}
	if !applyUserCredentials(adminProxy, managed, valid) {
		t.Fatal("valid per-user credential was rejected")
	}
	if got := adminProxy["uuid"]; got != "user-uuid" {
		t.Fatalf("uuid was not replaced, got %v", got)
	}
	if _, exists := adminProxy["flow"]; exists {
		t.Fatalf("flow from the owner template was not removed: %#v", adminProxy)
	}

	visionProxy := map[string]any{"uuid": "admin-uuid"}
	vision := map[credKey]string{{"edge-1", "vless-in"}: `{"id":"vision-user","flow":"xtls-rprx-vision"}`}
	if !applyUserCredentials(visionProxy, managed, vision) {
		t.Fatal("VLESS Vision credential was rejected")
	}
	if got := visionProxy["flow"]; got != "xtls-rprx-vision" {
		t.Fatalf("VLESS Vision flow was not applied, got %v", got)
	}

	personal := storage.Node{Protocol: "vless"}
	if !applyUserCredentials(map[string]any{"uuid": "personal"}, personal, nil) {
		t.Fatal("unmanaged personal node should not require credential replacement")
	}

	socksProxy := map[string]any{"username": "admin", "password": "admin-pass"}
	socksNode := storage.Node{Protocol: "socks", OriginalServer: "edge-1", InboundTag: "socks-in"}
	socksCred := map[credKey]string{{"edge-1", "socks-in"}: `{"user":"alice","pass":"user-pass"}`}
	if !applyUserCredentials(socksProxy, socksNode, socksCred) || socksProxy["username"] != "alice" || socksProxy["password"] != "user-pass" {
		t.Fatalf("socks credential was not safely replaced: %#v", socksProxy)
	}

	wireGuardProxy := map[string]any{
		"name": "WG", "type": "wireguard", "server": "203.0.113.10", "port": 51820,
		"private-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"public-key":  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
	}
	wireGuardNode := storage.Node{ID: 9, NodeName: "WG", Protocol: "wireguard", OriginalServer: "edge-1", InboundTag: "wg-in"}
	if !applyUserCredentials(wireGuardProxy, wireGuardNode, nil) {
		t.Fatal("managed WireGuard static client config was hidden from an assigned user")
	}
	wireGuardJSON, _ := json.Marshal(wireGuardProxy)
	wireGuardNode.ClashConfig = string(wireGuardJSON)
	item, err := makeNodeURIItem("alice", wireGuardNode, substore.NewURIProducer())
	if err != nil || !strings.HasPrefix(item.URI, "wireguard://") {
		t.Fatalf("managed WireGuard URI item=%+v err=%v", item, err)
	}
	delete(wireGuardProxy, "private-key")
	if applyUserCredentials(wireGuardProxy, wireGuardNode, nil) {
		t.Fatal("managed WireGuard config without a hydrated private key passed")
	}
}

func TestWireGuardDoesNotPersistHydratedConfigToLegacyYAML(t *testing.T) {
	if shouldSyncNodeToLegacyYAML(storage.Node{
		Protocol:    "wireguard",
		ClashConfig: `{"private-key":"sensitive"}`,
	}) {
		t.Fatal("hydrated WireGuard config would be written to a legacy YAML file")
	}
	if !shouldSyncNodeToLegacyYAML(storage.Node{
		Protocol:    "vless",
		ClashConfig: `{"uuid":"ordinary"}`,
	}) {
		t.Fatal("ordinary proxy updates should continue syncing to legacy YAML files")
	}
	if shouldPersistNodeInLegacyPackageSnapshot(storage.Node{Protocol: "wireguard"}) {
		t.Fatal("WireGuard identity would be copied into a legacy package snapshot")
	}
	if !shouldPersistNodeInLegacyPackageSnapshot(storage.Node{Protocol: "vless"}) {
		t.Fatal("ordinary nodes should remain available to legacy package snapshots")
	}
}

func TestCloneClashWithCredentialSynchronizesVLESSFlow(t *testing.T) {
	tests := []struct {
		name       string
		parent     string
		credential map[string]interface{}
		wantFlow   string
	}{
		{
			name:       "adds Vision selected by the routed credential",
			parent:     `{"name":"parent","type":"vless","uuid":"owner"}`,
			credential: map[string]interface{}{"id": "vision-user", "flow": "xtls-rprx-vision"},
			wantFlow:   "xtls-rprx-vision",
		},
		{
			name:       "removes owner Vision for a no-flow credential",
			parent:     `{"name":"parent","type":"vless","uuid":"owner","flow":"xtls-rprx-vision"}`,
			credential: map[string]interface{}{"id": "standard-user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cloned := cloneClashWithCredential(tt.parent, "vless", tt.credential, "routed")
			var proxy map[string]interface{}
			if err := json.Unmarshal([]byte(cloned), &proxy); err != nil {
				t.Fatalf("parse cloned Clash config: %v", err)
			}
			if proxy["uuid"] != tt.credential["id"] || proxy["name"] != "routed" {
				t.Fatalf("credential or name was not replaced: %#v", proxy)
			}
			if tt.wantFlow == "" {
				if _, exists := proxy["flow"]; exists {
					t.Fatalf("owner flow leaked into no-flow credential: %#v", proxy)
				}
			} else if proxy["flow"] != tt.wantFlow {
				t.Fatalf("flow = %#v, want %q", proxy["flow"], tt.wantFlow)
			}
		})
	}
}

func TestSubstituteNodesForUserDropsManagedNodeWithCorruptCredential(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{Name: "edge-1", Token: "token", IPAddress: "203.0.113.10", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username:       "alice",
		ServerID:       server.ID,
		InboundTag:     "vless-in",
		Protocol:       "vless",
		CredentialJSON: "{broken",
	}); err != nil {
		t.Fatalf("save inbound credential: %v", err)
	}

	nodes := []storage.Node{
		{ID: 1, NodeName: "managed", Protocol: "vless", OriginalServer: "edge-1", InboundTag: "vless-in", ClashConfig: `{"name":"managed","uuid":"admin-uuid"}`},
		{ID: 2, NodeName: "personal", Protocol: "vless", ClashConfig: `{"name":"personal","uuid":"personal-uuid"}`},
	}
	got := substituteNodesForUser(ctx, repo, "alice", nodes)
	if len(got) != 1 || got[0].NodeName != "personal" {
		t.Fatalf("expected only personal node, got %#v", got)
	}
}

func TestSubscriptionCreatorIsolationFailsClosed(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	if subscriptionCreatorRequiresIsolation(ctx, repo, "owner") {
		t.Fatal("administrator subscription should retain the legacy fallback")
	}
	if !subscriptionCreatorRequiresIsolation(ctx, repo, "alice") {
		t.Fatal("ordinary user subscription must be isolated")
	}
	if !subscriptionCreatorRequiresIsolation(ctx, repo, "deleted-user") {
		t.Fatal("missing creator record must fail closed")
	}
	if subscriptionCreatorRequiresIsolation(ctx, repo, "") {
		t.Fatal("legacy empty creator should retain administrator behavior")
	}
}

func TestBuildRoutedProxyForUserRejectsCorruptCredential(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	base, err := repo.CreateNode(ctx, storage.Node{
		Username:    "alice",
		NodeName:    "routed-template",
		Protocol:    "vless",
		ClashConfig: `{"name":"routed-template","uuid":"admin-uuid"}`,
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("create routed template node: %v", err)
	}
	if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username:       "alice",
		RoutedNodeID:   base.ID,
		Email:          "alice__route",
		CredentialJSON: "{broken",
		IsActive:       true,
	}); err != nil {
		t.Fatalf("save routed credential: %v", err)
	}

	routed := base
	routed.NodeType = "routed"
	if proxy, ok := buildRoutedProxyForUser(ctx, repo, routed, "alice"); ok || proxy != nil {
		t.Fatalf("corrupt routed credential was published: %#v", proxy)
	}
}

func TestRemoteSyncDoesNotClaimOrdinaryUserNodes(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{Name: "edge-1", Token: "token", IPAddress: "203.0.113.10"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	config := `{"name":"external","type":"vless","server":"203.0.113.10","port":443,"uuid":"admin-uuid"}`
	adminNode, err := repo.CreateNode(ctx, storage.Node{Username: "owner", NodeName: "admin-node", Protocol: "vless", ClashConfig: config, Enabled: true})
	if err != nil {
		t.Fatalf("create admin node: %v", err)
	}
	userNode, err := repo.CreateNode(ctx, storage.Node{Username: "alice", NodeName: "user-node", Protocol: "vless", ClashConfig: config, Enabled: true})
	if err != nil {
		t.Fatalf("create user node: %v", err)
	}
	unknownNode, err := repo.CreateNode(ctx, storage.Node{Username: "deleted-user", NodeName: "unknown-owner-node", Protocol: "vless", ClashConfig: config, Enabled: true})
	if err != nil {
		t.Fatalf("create unknown owner node: %v", err)
	}

	h := &RemoteManageHandler{repo: repo}
	if !h.tryClaimExternalNodeForSync(ctx, server, "vless", 443, config, "vless-in") {
		t.Fatal("expected the administrator node to be claimed")
	}
	gotAdmin, err := repo.GetNodeByID(ctx, adminNode.ID)
	if err != nil {
		t.Fatalf("read admin node: %v", err)
	}
	gotUser, err := repo.GetNodeByID(ctx, userNode.ID)
	if err != nil {
		t.Fatalf("read user node: %v", err)
	}
	if gotAdmin.OriginalServer != server.Name || gotAdmin.InboundTag != "vless-in" {
		t.Fatalf("admin node was not claimed: %#v", gotAdmin)
	}
	if gotUser.OriginalServer != "" || gotUser.InboundTag != "" {
		t.Fatalf("ordinary user node was claimed: %#v", gotUser)
	}
	gotUnknown, err := repo.GetNodeByID(ctx, unknownNode.ID)
	if err != nil {
		t.Fatalf("read unknown owner node: %v", err)
	}
	if gotUnknown.OriginalServer != "" || gotUnknown.InboundTag != "" {
		t.Fatalf("unknown owner node was claimed: %#v", gotUnknown)
	}
}

func TestBuildLimiterConfigIncludesEmptyInboundSnapshot(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	server := &storage.RemoteServer{Name: "edge-1", Token: "token", IPAddress: "203.0.113.10", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	if _, err := repo.CreateNode(ctx, storage.Node{
		Username:       "owner",
		NodeName:       "managed",
		Protocol:       "vless",
		ClashConfig:    `{"name":"managed","type":"vless","server":"203.0.113.10","port":443,"uuid":"admin-uuid"}`,
		Enabled:        true,
		OriginalServer: server.Name,
		InboundTag:     "vless-in",
	}); err != nil {
		t.Fatalf("create managed node: %v", err)
	}

	pusher := NewLimiterConfigPusher(repo, nil)
	configs, err := pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build limiter config: %v", err)
	}
	if len(configs) != 1 || configs[0].InboundTag != "vless-in" || configs[0].Users == nil || len(configs[0].Users) != 0 {
		t.Fatalf("expected explicit empty snapshot, got %#v", configs)
	}
}

func TestEnsureEmptyLimiterSnapshotsCoversAgentTags(t *testing.T) {
	configs := []WSLimiterConfigPayload{{
		InboundTag: "active",
		Users:      []WSUserLimitInfo{{Email: "alice", SpeedLimit: 100}},
	}}
	got := ensureEmptyLimiterSnapshots(configs, []string{"stale", "active", "stale"})
	if len(got) != 2 || got[0].InboundTag != "active" || got[1].InboundTag != "stale" {
		t.Fatalf("unexpected merged snapshots: %#v", got)
	}
	if len(got[0].Users) != 1 || got[1].Users == nil || len(got[1].Users) != 0 {
		t.Fatalf("active or empty users were lost: %#v", got)
	}
}
