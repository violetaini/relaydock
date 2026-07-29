package event

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func newTunnelListenerTestRepo(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "tunnel-listener.db"))
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func createTunnelListenerServer(t *testing.T, repo *storage.TrafficRepository) *storage.RemoteServer {
	t.Helper()
	server := &storage.RemoteServer{
		Name:      "relay-edge",
		Token:     "relay-token",
		Domain:    "relay.example.test",
		IPAddress: "203.0.113.40",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	return server
}

func TestBareTunnelAliasesDoNotCreateSubscriptionNodes(t *testing.T) {
	for _, protocol := range []string{"tunnel", "dokodemo-door"} {
		t.Run(protocol, func(t *testing.T) {
			repo := newTunnelListenerTestRepo(t)
			server := createTunnelListenerServer(t, repo)
			converterCalls := 0
			listener := NewNodeSyncListener(repo, func(int64, map[string]any) (string, error) {
				converterCalls++
				return `{"name":"unexpected"}`, nil
			})

			listener.Handle(InboundEvent{Type: EventInboundAdded, ServerID: server.ID, Tag: "bare-forward", Protocol: protocol, Port: 2033})

			if converterCalls != 0 {
				t.Fatalf("converter called %d time(s)", converterCalls)
			}
			nodes, err := repo.ListAllNodes(context.Background())
			if err != nil {
				t.Fatalf("list nodes: %v", err)
			}
			if len(nodes) != 0 {
				t.Fatalf("bare forwarding inbound created nodes: %#v", nodes)
			}
		})
	}
}

func TestForwardNodeTunnelAliasesCloneSourceWithResolvedServerHost(t *testing.T) {
	for _, protocol := range []string{"tunnel", "dokodemo-door"} {
		t.Run(protocol, func(t *testing.T) {
			ctx := context.Background()
			repo := newTunnelListenerTestRepo(t)
			if err := repo.CreateUser(ctx, "owner", "owner@example.test", "Owner", "test-hash", storage.RoleAdmin, ""); err != nil {
				t.Fatalf("create owner: %v", err)
			}
			server := createTunnelListenerServer(t, repo)
			sourceConfig := `{"name":"source","type":"vless","server":"origin.example.test","port":443,"uuid":"source-uuid"}`
			source, err := repo.CreateNode(ctx, storage.Node{
				Username: "owner", NodeName: "source", Protocol: "vless",
				ClashConfig: sourceConfig, ParsedConfig: sourceConfig, Enabled: true,
			})
			if err != nil {
				t.Fatalf("create source node: %v", err)
			}
			listener := NewNodeSyncListener(repo, func(int64, map[string]any) (string, error) {
				t.Fatal("tunnel forwarding unexpectedly invoked inbound-to-Clash conversion")
				return "", nil
			})

			listener.Handle(InboundEvent{
				Type: EventInboundAdded, ServerID: server.ID, Tag: "forward-source",
				Protocol: protocol, Port: 2033, ForwardNodeID: source.ID,
				NodeName: "  custom tunnel  ",
			})

			nodes, err := repo.ListAllNodes(ctx)
			if err != nil {
				t.Fatalf("list nodes: %v", err)
			}
			var clone *storage.Node
			for i := range nodes {
				if nodes[i].ID != source.ID {
					clone = &nodes[i]
					break
				}
			}
			if clone == nil {
				t.Fatalf("forwarded clone missing: %#v", nodes)
			}
			if clone.OriginalServer != server.Name || clone.InboundTag != "forward-source" || clone.Protocol != source.Protocol {
				t.Fatalf("unexpected clone metadata: %#v", clone)
			}
			if clone.NodeName != "custom tunnel" {
				t.Fatalf("clone name = %q, want trimmed event name", clone.NodeName)
			}
			var config map[string]any
			if err := json.Unmarshal([]byte(clone.ClashConfig), &config); err != nil {
				t.Fatalf("decode cloned config: %v", err)
			}
			if config["name"] != "custom tunnel" || config["server"] != server.Domain ||
				int(config["port"].(float64)) != 2033 || config["uuid"] != "source-uuid" {
				t.Fatalf("unexpected cloned config: %#v", config)
			}
			chainTargetID := source.ID
			clone.NodeName = "administrator-renamed-tunnel"
			clone.Enabled = false
			clone.Tag = "custom-primary"
			clone.Tags = []string{"custom-primary", "custom-secondary"}
			clone.RawURL = "vless://preserve-me"
			clone.OriginalDomain = "original-domain.example.test"
			clone.ChainProxyNodeID = &chainTargetID
			clone.RelayOrigServer = "origin-before-relay.example.test"
			clone.RelayOrigPort = 443
			if _, err := repo.UpdateNode(ctx, *clone); err != nil {
				t.Fatalf("customize forwarded clone: %v", err)
			}

			listener.Handle(InboundEvent{
				Type: EventInboundAdded, ServerID: server.ID, Tag: "forward-source",
				Protocol: protocol, Port: 3044, ForwardNodeID: source.ID,
				NodeName: "replacement-name-must-be-ignored",
			})
			nodes, err = repo.ListAllNodes(ctx)
			if err != nil {
				t.Fatalf("list nodes after repeated add: %v", err)
			}
			if len(nodes) != 2 {
				t.Fatalf("repeated forwarding event created a duplicate clone: %#v", nodes)
			}
			updated, err := repo.GetNodeByID(ctx, clone.ID)
			if err != nil {
				t.Fatalf("get updated clone: %v", err)
			}
			if updated.Enabled || updated.Tag != "custom-primary" || len(updated.Tags) != 2 ||
				updated.NodeName != "administrator-renamed-tunnel" ||
				updated.RawURL != clone.RawURL || updated.OriginalDomain != clone.OriginalDomain ||
				updated.ChainProxyNodeID == nil || *updated.ChainProxyNodeID != chainTargetID ||
				updated.RelayOrigServer != clone.RelayOrigServer || updated.RelayOrigPort != clone.RelayOrigPort {
				t.Fatalf("repeated event discarded administrator-managed state: %#v", updated)
			}
			if err := json.Unmarshal([]byte(updated.ClashConfig), &config); err != nil {
				t.Fatalf("decode updated cloned config: %v", err)
			}
			if config["name"] != "administrator-renamed-tunnel" || int(config["port"].(float64)) != 3044 {
				t.Fatalf("repeated event did not refresh forwarding port: %#v", config)
			}

			listener.Handle(InboundEvent{Type: EventInboundRemoved, ServerID: server.ID, Tag: "forward-source"})
			nodes, err = repo.ListAllNodes(ctx)
			if err != nil {
				t.Fatalf("list nodes after removal: %v", err)
			}
			if len(nodes) != 1 || nodes[0].ID != source.ID {
				t.Fatalf("removing forwarded inbound did not preserve only the source: %#v", nodes)
			}

			listener.Handle(InboundEvent{
				Type: EventInboundAdded, ServerID: server.ID, Tag: "forward-default-name",
				Protocol: protocol, Port: 2033, ForwardNodeID: source.ID,
			})
			nodes, err = repo.ListAllNodes(ctx)
			if err != nil {
				t.Fatalf("list nodes after default-name forwarding: %v", err)
			}
			clone = nil
			for i := range nodes {
				if nodes[i].ID != source.ID {
					clone = &nodes[i]
					break
				}
			}
			if clone == nil || clone.NodeName != "source | Tunnel" {
				t.Fatalf("empty event name did not fall back to the source name: %#v", nodes)
			}
			if err := json.Unmarshal([]byte(clone.ClashConfig), &config); err != nil {
				t.Fatalf("decode default-name cloned config: %v", err)
			}
			if config["name"] != "source | Tunnel" {
				t.Fatalf("default clone name was not written to Clash config: %#v", config)
			}
		})
	}
}
