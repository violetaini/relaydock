package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRemoteInboundOwnershipCoversTunnelWithoutNode(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "inbound-ownership.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	server := RemoteServer{Name: "tunnel-edge", Token: "token", Status: RemoteServerStatusConnected, IPAddress: "203.0.113.9", ListenPort: 21888}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetRemoteInboundOwnership(ctx, server.ID, "tunnel-only", "generation-one"); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.FindInboundMutationID(ctx, server.ID, "tunnel-only"); err != nil || got != "generation-one" {
		t.Fatalf("resolved ownership=%q err=%v", got, err)
	}
	if err := repo.SetRemoteInboundOwnership(ctx, server.ID, "tunnel-only", "generation-two"); err != nil {
		t.Fatal(err)
	}
	if deleted, err := repo.DeleteRemoteInboundOwnershipIfMutation(ctx, server.ID, "tunnel-only", "generation-one"); err != nil || deleted != 0 {
		t.Fatalf("stale ownership delete=%d err=%v", deleted, err)
	}
	if got, err := repo.FindInboundMutationID(ctx, server.ID, "tunnel-only"); err != nil || got != "generation-two" {
		t.Fatalf("replacement ownership=%q err=%v", got, err)
	}
	if deleted, err := repo.DeleteRemoteInboundOwnershipIfMutation(ctx, server.ID, "tunnel-only", "generation-two"); err != nil || deleted != 1 {
		t.Fatalf("matching ownership delete=%d err=%v", deleted, err)
	}
}
