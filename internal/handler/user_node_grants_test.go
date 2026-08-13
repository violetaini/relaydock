package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestAdminDirectNodeGrantResponseNeverContainsNodeCredential(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "direct-node-handler.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	server := storage.RemoteServer{
		Name: "edge-direct", Token: "edge-direct-token", Status: storage.RemoteServerStatusConnected,
		XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush,
	}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", RawURL: "vless://owner-secret@edge.example:443",
		NodeName: "Direct", Protocol: "vless", ParsedConfig: `{}`,
		ClashConfig: `{"type":"vless","uuid":"owner-secret","server":"edge.example","port":443}`,
		Enabled:     true, OriginalServer: server.Name, InboundTag: "vless-in",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	item, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	handler := NewManagedNodesHandler(repo, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/api/admin/users/alice/node-grants", nil)
	request.SetPathValue("username", "alice")
	recorder := httptest.NewRecorder()
	handler.HandleAdminUserNodeGrants(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "owner-secret") || strings.Contains(body, "clash_config") ||
		strings.Contains(body, "credential_json") || strings.Contains(body, "raw_url") {
		t.Fatalf("grant response leaked node credential material: %s", body)
	}
	var response struct {
		Success bool `json:"success"`
		Items   []struct {
			ID         int64  `json:"id"`
			SourceType string `json:"source_type"`
		} `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Success || len(response.Items) != 1 || response.Items[0].ID != item.Grant.ID ||
		response.Items[0].SourceType != storage.GrantSourceManual {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestManagedReconcilerQueuesExpiredAppliedDirectGrant(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "expired-direct-node.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	server := storage.RemoteServer{
		Name: "expired-direct-edge", Token: "expired-direct-token", Status: storage.RemoteServerStatusConnected,
		XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush,
	}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "Expired Direct", Protocol: "vless", ParsedConfig: `{}`,
		ClashConfig: `{"type":"vless","uuid":"owner-secret","server":"edge.example","port":443}`,
		Enabled:     true, OriginalServer: server.Name, InboundTag: "expired-vless-in",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	item, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	expiredAt := time.Now().UTC().Add(-time.Minute)
	active, err := repo.SetUserInboundAccessSourceState(ctx, item.Source.ID, item.Source.Generation,
		storage.ManagedDesiredActive, storage.ManagedSuspendNone, "test", &expiredAt)
	if err != nil {
		t.Fatalf("set expired source deadline: %v", err)
	}
	active, err = repo.MarkUserInboundAccessSourceApplied(ctx, active.ID, active.Generation,
		storage.ManagedObservedActive, time.Now().UTC())
	if err != nil {
		t.Fatalf("mark expired source applied: %v", err)
	}

	NewManagedNodesHandler(repo, nil, nil).reconcileAll(ctx)

	got, err := repo.GetUserInboundAccessSource(ctx, active.ID)
	if err != nil {
		t.Fatalf("GetUserInboundAccessSource: %v", err)
	}
	if got.DesiredState != storage.ManagedDesiredInactive || got.SuspendReason != storage.ManagedSuspendExpired ||
		got.Generation != active.Generation+1 || got.AppliedGeneration != active.Generation {
		t.Fatalf("reconciler did not queue expired direct revoke: %+v", got)
	}
	pending, err := repo.ListPendingUserInboundAccessSources(ctx, time.Now().UTC(), 10, server.ID)
	if err != nil || len(pending) != 1 || pending[0].ID != got.ID {
		t.Fatalf("remote revoke retry queue=%+v err=%v", pending, err)
	}
}
