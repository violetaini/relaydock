package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func seedManagedWireGuardProvenanceForTest(
	t *testing.T,
	repo *TrafficRepository,
	ctx context.Context,
	server RemoteServer,
	node *Node,
	fill byte,
) *ManagedInboundResource {
	t.Helper()
	if node == nil {
		t.Fatal("managed WireGuard node is required")
	}
	mutationID := fmt.Sprintf("managed-wireguard:test-%d-%02x", node.ID, fill)
	node.InboundMutationID = mutationID
	updated, err := repo.UpdateNode(ctx, *node)
	if err != nil {
		t.Fatalf("set managed WireGuard node mutation: %v", err)
	}
	*node = updated

	serverPublicKey, serverPrivateKey := wireGuardProbeTestKeyPair(t, fill)
	probePublicKey, probePrivateKey := wireGuardProbeTestKeyPair(t, fill+1)
	subnet := fmt.Sprintf("10.%d.%d", int(fill), int(node.ID%200)+1)
	probeAddress := subnet + ".2/32"
	desired, err := json.Marshal(map[string]interface{}{
		"tag":      node.InboundTag,
		"listen":   "0.0.0.0",
		"port":     51820,
		"protocol": "wireguard",
		"settings": map[string]interface{}{
			"secretKey": serverPrivateKey,
			"address":   []interface{}{subnet + ".1/24"},
			"peers": []interface{}{map[string]interface{}{
				"publicKey":  probePublicKey,
				"allowedIPs": []interface{}{probeAddress},
			}},
		},
	})
	if err != nil {
		t.Fatalf("encode managed WireGuard desired inbound: %v", err)
	}
	metadata, err := json.Marshal(map[string]interface{}{
		"server_public_key": serverPublicKey,
		"server_addresses":  []string{subnet + ".1/24"},
		"mtu":               1420,
	})
	if err != nil {
		t.Fatalf("encode managed WireGuard metadata: %v", err)
	}
	resource, err := repo.CreateManagedInboundResource(ctx, ManagedInboundResource{
		ServerID: server.ID, DisplayName: node.NodeName, Protocol: "wireguard",
		InboundTag: node.InboundTag, MutationID: mutationID,
		EndpointHost: "edge.example.test", EndpointPort: 51820,
		PublicMetadataJSON: metadata, CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("create managed WireGuard resource: %v", err)
	}
	if _, err := repo.UpsertActiveDesiredInbound(ctx, server.ID, node.InboundTag, mutationID, desired); err != nil {
		t.Fatalf("create managed WireGuard desired inbound: %v", err)
	}
	if err := repo.SetRemoteInboundOwnership(ctx, server.ID, node.InboundTag, mutationID); err != nil {
		t.Fatalf("create managed WireGuard ownership: %v", err)
	}
	if _, err := repo.CreateWireGuardProbePeer(ctx, WireGuardProbePeer{
		ResourceID: resource.ID, PublicKey: probePublicKey, PrivateKey: probePrivateKey,
		Addresses: []string{probeAddress},
	}); err != nil {
		t.Fatalf("create managed WireGuard probe: %v", err)
	}
	if _, err := repo.MarkWireGuardProbePeerActive(ctx, resource.ID); err != nil {
		t.Fatalf("activate managed WireGuard probe: %v", err)
	}
	return resource
}

func TestManagedWireGuardProvenanceRejectsCoordinatesAndAcceptsCurrentGeneration(t *testing.T) {
	repo, ctx, server, node := seedDirectNodeGrantTest(t)
	configureTestNodeSecretEncryption(t, repo, 0x70)
	node.Protocol = "wireguard"
	node.ClashConfig = testWireGuardNodeConfig("provenance-wg")
	node.ParsedConfig = node.ClashConfig
	if _, err := repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("update coordinate-only WireGuard node: %v", err)
	}
	if provisionable, err := repo.ManagedWireGuardNodeProvisionable(ctx, node.ID); err != nil || provisionable {
		t.Fatalf("coordinate-only WireGuard provisionable=%v err=%v", provisionable, err)
	}

	seedManagedWireGuardProvenanceForTest(t, repo, ctx, server, &node, 0x71)
	if provisionable, err := repo.ManagedWireGuardNodeProvisionable(ctx, node.ID); err != nil || !provisionable {
		t.Fatalf("current managed WireGuard node provisionable=%v err=%v", provisionable, err)
	}
	if provisionable, err := repo.ManagedWireGuardInboundProvisionable(ctx, server.ID, node.InboundTag); err != nil || !provisionable {
		t.Fatalf("current managed WireGuard inbound provisionable=%v err=%v", provisionable, err)
	}

	if _, err := repo.db.ExecContext(ctx, `UPDATE remote_inbound_ownership SET mutation_id = 'stale-generation'
WHERE server_id = ? AND inbound_tag = ?`, server.ID, node.InboundTag); err != nil {
		t.Fatalf("corrupt WireGuard ownership generation: %v", err)
	}
	if provisionable, err := repo.ManagedWireGuardNodeProvisionable(ctx, node.ID); err != nil || provisionable {
		t.Fatalf("mismatched WireGuard generation provisionable=%v err=%v", provisionable, err)
	}
}
