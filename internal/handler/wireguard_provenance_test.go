package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func seedHandlerManagedWireGuardProvenance(
	t *testing.T,
	repo *storage.TrafficRepository,
	server *storage.RemoteServer,
	node *storage.Node,
	inbound map[string]interface{},
	mutationID string,
	activateProbe bool,
) *storage.ManagedInboundResource {
	t.Helper()
	ctx := context.Background()
	if server == nil || node == nil || inbound == nil {
		t.Fatal("managed WireGuard provenance fixture is incomplete")
	}
	if mutationID == "" {
		mutationID = "managed-wireguard:test-generation"
	}
	if canonicalManagedProtocol(node.Protocol) != "wireguard" {
		t.Fatalf("provenance node protocol=%q, want wireguard", node.Protocol)
	}
	tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
	if tag == "" || tag != strings.TrimSpace(node.InboundTag) {
		t.Fatalf("provenance inbound tag=%q node tag=%q", tag, node.InboundTag)
	}
	node.InboundMutationID = mutationID
	updated, err := repo.UpdateNode(ctx, *node)
	if err != nil {
		t.Fatalf("set managed WireGuard node mutation: %v", err)
	}
	*node = updated

	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		t.Fatal("managed WireGuard fixture has no settings")
	}
	probePrivateKey, probePublicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generate managed WireGuard probe: %v", err)
	}
	probeAddress := "10.66.66.250/32"
	settings["peers"] = append(wireGuardInterfaceSlice(settings["peers"]), map[string]interface{}{
		"publicKey": probePublicKey, "allowedIPs": []interface{}{probeAddress}, "keepAlive": float64(0),
	})
	metadata, err := managedWireGuardPublicMetadataFromInbound(inbound)
	if err != nil {
		t.Fatalf("derive managed WireGuard metadata: %v", err)
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("encode managed WireGuard metadata: %v", err)
	}
	resource, err := repo.CreateManagedInboundResource(ctx, storage.ManagedInboundResource{
		ServerID: server.ID, DisplayName: node.NodeName, Protocol: "wireguard",
		InboundTag: tag, MutationID: mutationID, EndpointHost: "203.0.113.10", EndpointPort: 51820,
		PublicMetadataJSON: metadataJSON, CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("create managed WireGuard resource: %v", err)
	}
	rawInbound, err := json.Marshal(observedInboundConfig(inbound))
	if err != nil {
		t.Fatalf("encode managed WireGuard desired inbound: %v", err)
	}
	if _, err := repo.UpsertActiveDesiredInbound(ctx, server.ID, tag, mutationID, rawInbound); err != nil {
		t.Fatalf("create managed WireGuard desired inbound: %v", err)
	}
	if err := repo.SetRemoteInboundOwnership(ctx, server.ID, tag, mutationID); err != nil {
		t.Fatalf("create managed WireGuard ownership: %v", err)
	}
	if _, err := repo.CreateWireGuardProbePeer(ctx, storage.WireGuardProbePeer{
		ResourceID: resource.ID, PublicKey: probePublicKey, PrivateKey: probePrivateKey,
		Addresses: []string{probeAddress},
	}); err != nil {
		t.Fatalf("create managed WireGuard probe: %v", err)
	}
	if activateProbe {
		if _, err := repo.MarkWireGuardProbePeerActive(ctx, resource.ID); err != nil {
			t.Fatalf("activate managed WireGuard probe: %v", err)
		}
	}
	return resource
}
