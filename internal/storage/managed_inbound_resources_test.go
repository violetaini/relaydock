package storage

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func newManagedInboundResourceTestRepository(t *testing.T) (*TrafficRepository, RemoteServer) {
	t.Helper()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "managed-inbound-resources.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := RemoteServer{
		Name: "wireguard-edge", Token: "agent-token", Status: RemoteServerStatusConnected,
		IPAddress: "203.0.113.8", ListenPort: 21888, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), &server); err != nil {
		t.Fatal(err)
	}
	return repo, server
}

func managedInboundResourceFixture(serverID int64) ManagedInboundResource {
	return ManagedInboundResource{
		ServerID:     serverID,
		DisplayName:  "Hong Kong WireGuard",
		Protocol:     "wireguard",
		InboundTag:   "wireguard-hk",
		EndpointHost: "edge.example.test",
		EndpointPort: 51820,
		PublicMetadataJSON: json.RawMessage(`{
            "server_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "server_addresses":["10.66.66.1/32"],
            "mtu":1420,
            "peers":[{"public_key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","allowed_ips":["10.66.66.2/32"],"keep_alive":25}]
        }`),
		CreatedBy: "admin",
	}
}

func TestManagedInboundResourceCRUDAndUpsertPreservesDisplayName(t *testing.T) {
	repo, server := newManagedInboundResourceTestRepository(t)
	ctx := context.Background()
	created, err := repo.CreateManagedInboundResource(ctx, managedInboundResourceFixture(server.ID))
	if err != nil {
		t.Fatalf("CreateManagedInboundResource: %v", err)
	}
	if created.ID <= 0 || created.ServerName != server.Name || created.Protocol != "wireguard" {
		t.Fatalf("unexpected created resource: %+v", created)
	}

	renamed, err := repo.RenameManagedInboundResource(ctx, created.ID, "Renamed WireGuard")
	if err != nil {
		t.Fatalf("RenameManagedInboundResource: %v", err)
	}
	if renamed.DisplayName != "Renamed WireGuard" {
		t.Fatalf("display_name=%q", renamed.DisplayName)
	}

	updated := managedInboundResourceFixture(server.ID)
	updated.DisplayName = "sync default must not replace rename"
	updated.EndpointHost = "203.0.113.9"
	updated.EndpointPort = 51821
	updated.CreatedBy = "system-sync"
	updated.MutationID = ""
	upserted, err := repo.UpsertManagedInboundResource(ctx, updated)
	if err != nil {
		t.Fatalf("UpsertManagedInboundResource: %v", err)
	}
	if upserted.ID != created.ID || upserted.DisplayName != "Renamed WireGuard" {
		t.Fatalf("upsert replaced identity/name: %+v", upserted)
	}
	if upserted.EndpointHost != updated.EndpointHost || upserted.EndpointPort != updated.EndpointPort {
		t.Fatalf("upsert did not refresh endpoint: %+v", upserted)
	}

	resources, err := repo.ListManagedInboundResources(ctx)
	if err != nil || len(resources) != 1 {
		t.Fatalf("ListManagedInboundResources=%+v, %v", resources, err)
	}
	deleted, err := repo.DeleteManagedInboundResourceByServerTag(ctx, server.ID, updated.InboundTag)
	if err != nil || deleted != 1 {
		t.Fatalf("DeleteManagedInboundResourceByServerTag=%d, %v", deleted, err)
	}
	if _, err := repo.GetManagedInboundResource(ctx, created.ID); !errors.Is(err, ErrManagedInboundResourceNotFound) {
		t.Fatalf("GetManagedInboundResource after delete error=%v", err)
	}
}

func TestManagedInboundResourceMutationFencesStaleDelete(t *testing.T) {
	repo, server := newManagedInboundResourceTestRepository(t)
	ctx := context.Background()
	old := managedInboundResourceFixture(server.ID)
	old.MutationID = "generation-old"
	created, err := repo.CreateManagedInboundResource(ctx, old)
	if err != nil {
		t.Fatal(err)
	}

	newGeneration := managedInboundResourceFixture(server.ID)
	newGeneration.MutationID = "generation-new"
	if _, err := repo.UpsertManagedInboundResource(ctx, newGeneration); err != nil {
		t.Fatal(err)
	}
	deleted, err := repo.DeleteManagedInboundResourceByServerTagMutation(ctx, server.ID, old.InboundTag, old.MutationID)
	if err != nil || deleted != 0 {
		t.Fatalf("stale delete affected=%d err=%v", deleted, err)
	}
	current, err := repo.GetManagedInboundResource(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.MutationID != newGeneration.MutationID {
		t.Fatalf("new generation mutation=%q", current.MutationID)
	}
}

func TestManagedInboundResourceStorageRejectsSecrets(t *testing.T) {
	repo, server := newManagedInboundResourceTestRepository(t)
	for _, metadata := range []string{
		`{"client_private_key":"do-not-store"}`,
		`{"peers":[{"private-key":"do-not-store"}]}`,
		`{"server_secret":"do-not-store"}`,
	} {
		resource := managedInboundResourceFixture(server.ID)
		resource.PublicMetadataJSON = json.RawMessage(metadata)
		if _, err := repo.CreateManagedInboundResource(context.Background(), resource); err == nil {
			t.Fatalf("secret metadata was accepted: %s", metadata)
		}
	}
	resources, err := repo.ListManagedInboundResources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 0 {
		t.Fatalf("secret attempts left records: %+v", resources)
	}
}

func TestManagedInboundResourceMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-inbound-migration.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.migrateManagedInboundResources(); err != nil {
		t.Fatalf("second migration: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	defer reopened.Close()
}
