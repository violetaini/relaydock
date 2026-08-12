package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestRefreshExternalNodeNameReplacesGeneratedSuffix(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		suffix   string
		want     string
	}{
		{name: "replace", existing: "Tokyo 10.00GB📊 8Days⏳", suffix: " 8.50GB📊 7Days⏳", want: "Tokyo 8.50GB📊 7Days⏳"},
		{name: "remove", existing: "Tokyo 10.00GB📊 8Days⏳", want: "Tokyo"},
		{name: "clean accumulated legacy suffixes", existing: "Tokyo 10.00GB📊 8Days⏳ 8.50GB📊 7Days⏳", suffix: " 7.00GB📊 6Days⏳", want: "Tokyo 7.00GB📊 6Days⏳"},
		{name: "preserve ordinary name", existing: "Tokyo Premium", suffix: " 900MB📊", want: "Tokyo Premium 900MB📊"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refreshExternalNodeName(tt.existing, tt.suffix); got != tt.want {
				t.Fatalf("refreshExternalNodeName(%q, %q) = %q, want %q", tt.existing, tt.suffix, got, tt.want)
			}
		})
	}
}

func TestPreserveExternalNodeNameDoesNotStripIdenticalUpstreamName(t *testing.T) {
	const upstreamName = "Quota 10GB📊"
	if got := preserveExternalNodeName(upstreamName, upstreamName, ""); got != upstreamName {
		t.Fatalf("identical upstream name changed to %q", got)
	}
	if got := preserveExternalNodeName("Tokyo 10GB📊", "Tokyo", ""); got != "Tokyo" {
		t.Fatalf("stale generated suffix was not removed: %q", got)
	}
}

func TestMatchExternalNodeByNameUsesSourceAndIgnoresStaleSuffix(t *testing.T) {
	nodes := []storage.Node{
		{ID: 3, RawURL: "https://first.example/sub", NodeName: "Tokyo 8.50GB📊 7Days⏳", OriginalServer: "managed-server", InboundTag: "managed-inbound"},
		{ID: 4, RawURL: "https://first.example/sub", NodeName: "Tokyo 8.50GB📊 7Days⏳", NodeType: "routed"},
		{ID: 1, RawURL: "https://first.example/sub", NodeName: "Tokyo 10.00GB📊 8Days⏳"},
		{ID: 2, RawURL: "https://second.example/sub", NodeName: "Tokyo 8.50GB📊 7Days⏳"},
	}
	matched := matchExternalNodeByName(nodes, "https://first.example/sub", "Tokyo 8.50GB📊 7Days⏳")
	if matched == nil || matched.ID != 1 {
		t.Fatalf("matched = %#v, want first subscription node", matched)
	}
	if matched := matchExternalNodeByName(nodes, "https://missing.example/sub", "Tokyo 8.50GB📊 7Days⏳"); matched != nil {
		t.Fatalf("cross-subscription node matched: %#v", matched)
	}
}

func TestExternalSubscriptionSyncDoesNotUpdateServerBoundOrRoutedNodes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("proxies:\n  - name: upstream replacement\n    type: ss\n    server: edge.example\n    port: 443\n    cipher: aes-128-gcm\n    password: new-secret\n"))
	}))
	t.Cleanup(upstream.Close)

	repo, managed, routed := createExternalSyncProtectedNodes(t, upstream.URL, "managed original", "routed original")
	synced, _, err := syncSingleExternalSubscription(
		context.Background(), upstream.Client(), repo, "", "alice",
		storage.ExternalSubscription{ID: 1, Name: "source", URL: upstream.URL},
		storage.UserSettings{MatchRule: "server_port", SyncScope: "saved_only"},
	)
	if err != nil {
		t.Fatalf("sync subscription: %v", err)
	}
	if synced != 0 {
		t.Fatalf("synced count = %d, want 0", synced)
	}
	assertExternalSyncNodeUnchanged(t, repo, managed)
	assertExternalSyncNodeUnchanged(t, repo, routed)
}

func TestExternalSubscriptionFilterDoesNotDeleteServerBoundOrRoutedNodes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("proxies:\n  - name: safe upstream\n    type: ss\n    server: other.example\n    port: 8443\n    cipher: aes-128-gcm\n    password: safe-secret\n"))
	}))
	t.Cleanup(upstream.Close)

	repo, managed, routed := createExternalSyncProtectedNodes(t, upstream.URL, "DROP managed", "DROP routed")
	if _, _, err := syncSingleExternalSubscription(
		context.Background(), upstream.Client(), repo, "", "alice",
		storage.ExternalSubscription{ID: 1, Name: "source", URL: upstream.URL},
		storage.UserSettings{MatchRule: "node_name", SyncScope: "saved_only", NodeNameFilter: "^DROP"},
	); err != nil {
		t.Fatalf("sync subscription: %v", err)
	}
	assertExternalSyncNodeUnchanged(t, repo, managed)
	assertExternalSyncNodeUnchanged(t, repo, routed)
}

func createExternalSyncProtectedNodes(t *testing.T, sourceURL, managedName, routedName string) (*storage.TrafficRepository, storage.Node, storage.Node) {
	t.Helper()
	ctx := context.Background()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "external-sync-guard.db"))
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("create user: %v", err)
	}

	parent, err := repo.CreateNode(ctx, storage.Node{
		Username: "alice", NodeName: "parent", Protocol: "ss", Enabled: true,
		ParsedConfig: `{"name":"parent","type":"ss","server":"parent.example","port":9443,"cipher":"aes-128-gcm","password":"parent-secret"}`,
		ClashConfig:  `{"name":"parent","type":"ss","server":"parent.example","port":9443,"cipher":"aes-128-gcm","password":"parent-secret"}`,
	})
	if err != nil {
		t.Fatalf("create parent node: %v", err)
	}

	managedConfig := `{"name":"managed original","type":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"managed-secret"}`
	managed, err := repo.CreateNode(ctx, storage.Node{
		Username: "alice", RawURL: sourceURL, NodeName: managedName, Protocol: "ss", Enabled: true,
		ParsedConfig: managedConfig, ClashConfig: managedConfig,
		OriginalServer: "edge.example", InboundTag: "managed-ss",
	})
	if err != nil {
		t.Fatalf("create managed node: %v", err)
	}

	routedConfig := `{"name":"routed original","type":"ss","server":"edge.example","port":443,"cipher":"aes-128-gcm","password":"routed-secret"}`
	parentID := parent.ID
	routedDetail, err := repo.CreateRoutedNode(ctx, storage.RoutedNodeDetail{
		Node: storage.Node{
			Username: "alice", RawURL: sourceURL, NodeName: routedName, Protocol: "ss", Enabled: true,
			ParsedConfig: routedConfig, ClashConfig: routedConfig, ParentNodeID: &parentID,
		},
		RoutedOutboundTag: "external-sync-guard-outbound",
		RoutedRuleMarktag: "external-sync-guard-rule",
	})
	if err != nil {
		t.Fatalf("create routed node: %v", err)
	}
	return repo, managed, routedDetail.Node
}

func assertExternalSyncNodeUnchanged(t *testing.T, repo *storage.TrafficRepository, want storage.Node) {
	t.Helper()
	got, err := repo.GetNode(context.Background(), want.ID, want.Username)
	if err != nil {
		t.Fatalf("get protected node %d: %v", want.ID, err)
	}
	if got.NodeName != want.NodeName || got.ClashConfig != want.ClashConfig || got.ParsedConfig != want.ParsedConfig || got.RawURL != want.RawURL {
		t.Fatalf("protected node %d changed: got %#v, want %#v", want.ID, got, want)
	}
}
