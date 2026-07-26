package event

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"miaomiaowux/internal/storage"
)

func TestInboundRemovedEventDeletesManagedWireGuardResource(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "managed-wireguard-listener.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	server := &storage.RemoteServer{
		Name: "wireguard-edge", Token: "agent-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "203.0.113.25", ListenPort: 21888,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	resource, err := repo.CreateManagedInboundResource(context.Background(), storage.ManagedInboundResource{
		ServerID:           server.ID,
		DisplayName:        "Managed WireGuard",
		Protocol:           "wireguard",
		InboundTag:         "wireguard-in",
		EndpointHost:       server.IPAddress,
		EndpointPort:       51820,
		PublicMetadataJSON: json.RawMessage(`{"server_public_key":"public-only"}`),
		CreatedBy:          "admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	listener := NewNodeSyncListener(repo, nil)
	listener.Handle(InboundEvent{Type: EventInboundRemoved, ServerID: server.ID, Tag: resource.InboundTag})

	if _, err := repo.GetManagedInboundResource(context.Background(), resource.ID); !errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		t.Fatalf("removed inbound left managed resource: %v", err)
	}
}

func TestInboundAddedWireGuardDoesNotCreateSubscriptionNode(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "managed-wireguard-added-listener.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	server := &storage.RemoteServer{
		Name: "wireguard-edge", Token: "agent-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "203.0.113.25", ListenPort: 21888,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	converterCalls := 0
	listener := NewNodeSyncListener(repo, func(int64, map[string]any) (string, error) {
		converterCalls++
		return "", nil
	})
	listener.Handle(InboundEvent{Type: EventInboundAdded, ServerID: server.ID, Tag: "wireguard-in", Protocol: "wireguard", Port: 51820})
	if converterCalls != 0 {
		t.Fatalf("WireGuard invoked subscription converter %d time(s)", converterCalls)
	}
	nodes, err := repo.ListAllNodes(context.Background())
	if err != nil || len(nodes) != 0 {
		t.Fatalf("WireGuard event created subscription nodes: nodes=%+v err=%v", nodes, err)
	}
}
