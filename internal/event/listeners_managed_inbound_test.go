package event

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
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

func TestStaleInboundRemovedEventDoesNotDeleteNewManagedGeneration(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "managed-wireguard-stale-listener.db"))
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
		ServerID: server.ID, DisplayName: "Managed WireGuard", Protocol: "wireguard",
		InboundTag: "wireguard-in", MutationID: "generation-new",
		EndpointHost: server.IPAddress, EndpointPort: 51820,
		PublicMetadataJSON: json.RawMessage(`{"server_public_key":"public-only"}`), CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	listener := NewNodeSyncListener(repo, nil)
	listener.Handle(InboundEvent{
		Type: EventInboundRemoved, ServerID: server.ID, Tag: resource.InboundTag, MutationID: "generation-old",
	})
	current, err := repo.GetManagedInboundResource(context.Background(), resource.ID)
	if err != nil {
		t.Fatalf("new generation was deleted: %v", err)
	}
	if current.MutationID != "generation-new" {
		t.Fatalf("mutation=%q", current.MutationID)
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

func TestInboundReplacementUpdatesConfigAndMutationWithoutChangingNodeID(t *testing.T) {
	for _, test := range []struct {
		name    string
		oldPort int
		newPort int
	}{
		{name: "same port", oldPort: 39081, newPort: 39081},
		{name: "changed port", oldPort: 39081, newPort: 39082},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "managed-replacement.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Close()
			ctx := context.Background()
			if err := repo.CreateUser(ctx, "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
				t.Fatal(err)
			}
			server := &storage.RemoteServer{Name: "edge-replace", Token: "token", Status: storage.RemoteServerStatusConnected, IPAddress: "203.0.113.41", ListenPort: 21888}
			if err := repo.CreateRemoteServer(ctx, server); err != nil {
				t.Fatal(err)
			}
			oldConfig, _ := json.Marshal(map[string]interface{}{
				"name": "Kept name", "type": "vless", "server": server.IPAddress,
				"port": test.oldPort, "uuid": "old-uuid", "reality-opts": map[string]interface{}{"public-key": "old-key"},
			})
			created, err := repo.CreateNode(ctx, storage.Node{
				Username: "admin", NodeName: "Kept name", Protocol: "vless",
				ParsedConfig: string(oldConfig), ClashConfig: string(oldConfig), Enabled: true,
				OriginalServer: server.Name, InboundTag: "reality-in", InboundMutationID: "generation-a",
			})
			if err != nil {
				t.Fatal(err)
			}
			listener := NewNodeSyncListener(repo, func(int64, map[string]any) (string, error) {
				value, _ := json.Marshal(map[string]interface{}{
					"name": "generated", "type": "vless", "server": server.IPAddress,
					"port": test.newPort, "uuid": "new-uuid", "reality-opts": map[string]interface{}{"public-key": "new-key"},
				})
				return string(value), nil
			})
			listener.Handle(InboundEvent{
				Type: EventInboundAdded, ServerID: server.ID, Tag: "reality-in",
				MutationID: "generation-b", Protocol: "vless", Port: test.newPort,
				Inbound: map[string]any{"tag": "reality-in"},
			})
			nodes, err := repo.ListAllNodes(ctx)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("nodes=%+v err=%v", nodes, err)
			}
			updated := nodes[0]
			if updated.ID != created.ID || updated.NodeName != created.NodeName || updated.InboundMutationID != "generation-b" {
				t.Fatalf("replacement lost stable identity: %+v", updated)
			}
			var config map[string]interface{}
			if err := json.Unmarshal([]byte(updated.ClashConfig), &config); err != nil {
				t.Fatal(err)
			}
			if config["uuid"] != "new-uuid" || int(config["port"].(float64)) != test.newPort ||
				config["reality-opts"].(map[string]interface{})["public-key"] != "new-key" {
				t.Fatalf("replacement kept stale connection config: %#v", config)
			}
		})
	}
}
