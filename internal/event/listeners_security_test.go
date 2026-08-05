package event

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestInboundEventNeverClaimsImportedNodes(t *testing.T) {
	ctx := context.Background()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("create test repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	for _, user := range []struct {
		name string
		role string
	}{{"owner", storage.RoleAdmin}, {"alice", storage.RoleUser}} {
		if err := repo.CreateUser(ctx, user.name, user.name+"@example.test", user.name, "test-hash", user.role, ""); err != nil {
			t.Fatalf("create user %s: %v", user.name, err)
		}
	}
	server := &storage.RemoteServer{Name: "edge-1", Token: "token", IPAddress: "203.0.113.10"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	config := `{"name":"external","type":"vless","server":"203.0.113.10","port":443,"uuid":"template-uuid"}`
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

	listener := NewNodeSyncListener(repo, func(_ int64, _ map[string]any) (string, error) { return config, nil })
	if err := listener.Handle(InboundEvent{
		Type: EventInboundAdded, ServerID: server.ID, Tag: "vless-in", MutationID: "managed-generation",
		Protocol: "vless", Port: 443, Inbound: map[string]any{"tag": "vless-in", "protocol": "vless", "port": 443},
	}); err != nil {
		t.Fatalf("handle inbound event: %v", err)
	}
	gotAdmin, err := repo.GetNodeByID(ctx, adminNode.ID)
	if err != nil {
		t.Fatalf("read admin node: %v", err)
	}
	gotUser, err := repo.GetNodeByID(ctx, userNode.ID)
	if err != nil {
		t.Fatalf("read user node: %v", err)
	}
	if gotAdmin.OriginalServer != "" || gotAdmin.InboundTag != "" {
		t.Fatalf("administrator import was claimed: %#v", gotAdmin)
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
