package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestNodeMutationFencePreventsStaleSameTagDelete(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "node-mutation-fence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	node, err := repo.CreateNode(ctx, Node{
		Username:          "admin",
		RawURL:            "vless://managed",
		NodeName:          "same-tag node",
		Protocol:          "vless",
		ParsedConfig:      `{}`,
		ClashConfig:       `{}`,
		Enabled:           true,
		OriginalServer:    "edge-a",
		InboundTag:        "same-tag",
		InboundMutationID: "generation-new",
	})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := repo.DeleteNodesByInboundTagMutation(ctx, node.OriginalServer, node.InboundTag, "generation-old")
	if err != nil || deleted != 0 {
		t.Fatalf("stale delete affected=%d err=%v", deleted, err)
	}
	current, err := repo.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.InboundMutationID != "generation-new" {
		t.Fatalf("new generation mutation=%q", current.InboundMutationID)
	}
}

func TestDeleteNodeByIDIfMutationPreservesConcurrentReplacement(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "node-delete-mutation-fence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	node, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "replaceable", Protocol: "vless",
		ParsedConfig: `{}`, ClashConfig: `{}`, Enabled: true,
		InboundMutationID: "generation-new",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteNodeByIDIfMutation(ctx, node.ID, "generation-old"); !errors.Is(err, ErrNodeMutationChanged) {
		t.Fatalf("stale delete error=%v", err)
	}
	if _, err := repo.GetNodeByID(ctx, node.ID); err != nil {
		t.Fatalf("stale delete removed replacement: %v", err)
	}
	if err := repo.DeleteNodeByIDIfMutation(ctx, node.ID, "generation-new"); err != nil {
		t.Fatalf("matching generation delete: %v", err)
	}
}
