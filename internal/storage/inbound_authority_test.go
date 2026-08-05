package storage

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func newDesiredInboundTestRepository(t *testing.T) (*TrafficRepository, RemoteServer) {
	t.Helper()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "desired-inbounds.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := RemoteServer{
		Name: "edge-a", Token: "edge-a-token", Status: RemoteServerStatusConnected,
		IPAddress: "203.0.113.10", ListenPort: 21888, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), &server); err != nil {
		t.Fatal(err)
	}
	return repo, server
}

func desiredInboundJSON(tag string, port int) json.RawMessage {
	value, _ := json.Marshal(map[string]interface{}{
		"tag": tag, "listen": "0.0.0.0", "port": port, "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{}},
	})
	return value
}

func TestDesiredInboundLifecycleKeepsDeletionTombstone(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()

	created, err := repo.UpsertActiveDesiredInbound(ctx, server.ID, "vless-main", "generation-one", desiredInboundJSON("vless-main", 443))
	if err != nil {
		t.Fatalf("UpsertActiveDesiredInbound: %v", err)
	}
	if created.DesiredState != DesiredInboundStateActive || created.MutationID != "generation-one" {
		t.Fatalf("unexpected active desired inbound: %+v", created)
	}

	deleted, err := repo.MarkDesiredInboundDeleted(ctx, server.ID, "vless-main", "generation-one")
	if err != nil {
		t.Fatalf("MarkDesiredInboundDeleted: %v", err)
	}
	if deleted.DesiredState != DesiredInboundStateDeleted || string(deleted.InboundJSON) == "{}" {
		t.Fatalf("deletion did not retain definition: %+v", deleted)
	}
	active, err := repo.ListActiveDesiredInbounds(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || len(active) != 0 {
		t.Fatalf("active desired inbounds after delete = %+v", active)
	}

	if _, err := repo.UpsertActiveDesiredInbound(ctx, server.ID, "vless-main", "generation-one", desiredInboundJSON("vless-main", 443)); !errors.Is(err, ErrDesiredInboundMutationChanged) {
		t.Fatalf("deleted generation replay error = %v", err)
	}
	recreated, err := repo.UpsertActiveDesiredInbound(ctx, server.ID, "vless-main", "generation-two", desiredInboundJSON("vless-main", 8443))
	if err != nil {
		t.Fatalf("recreate desired inbound: %v", err)
	}
	if recreated.DesiredState != DesiredInboundStateActive || recreated.MutationID != "generation-two" {
		t.Fatalf("unexpected recreated desired inbound: %+v", recreated)
	}
	if _, err := repo.MarkDesiredInboundDeleted(ctx, server.ID, "vless-main", "generation-one"); !errors.Is(err, ErrDesiredInboundMutationChanged) {
		t.Fatalf("stale delete error = %v", err)
	}
	if _, err := repo.MarkDesiredInboundDeleted(ctx, server.ID, "vless-main", ""); !errors.Is(err, ErrDesiredInboundMutationChanged) {
		t.Fatalf("unfenced delete error = %v", err)
	}
}

func TestDesiredInboundMigrationBackfillsOnlyExplicitDatabaseIntent(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()

	if err := repo.SetRemoteInboundOwnership(ctx, server.ID, "ownership-ghost", "ghost-generation"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetRemoteInboundOwnership(ctx, server.ID, "tunnel-only", "tunnel-generation"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://fixture@example.test:443", NodeName: "Bound node",
		Protocol: "vless", Enabled: true, OriginalServer: server.Name,
		InboundTag: "node-inbound", InboundMutationID: "node-generation",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateManagedInboundResource(ctx, ManagedInboundResource{
		ServerID: server.ID, DisplayName: "Inventory ghost", Protocol: "vless",
		InboundTag: "inventory-ghost", EndpointHost: "edge.example.test", EndpointPort: 2443,
		PublicMetadataJSON: json.RawMessage(`{}`), CreatedBy: "system-sync",
	}); err != nil {
		t.Fatal(err)
	}

	config, err := json.Marshal(map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"inbounds": []interface{}{
			json.RawMessage(desiredInboundJSON("ownership-ghost", 1443)),
			json.RawMessage(desiredInboundJSON("node-inbound", 1444)),
			json.RawMessage(desiredInboundJSON("inventory-ghost", 1445)),
			json.RawMessage(desiredInboundJSON("runtime-only", 1446)),
			json.RawMessage(desiredInboundJSON("tunnel-only", 1447)),
			json.RawMessage(desiredInboundJSON("api", 10085)),
		},
		"outbounds": []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertCurrentXraySnapshot(ctx, server.ID, string(config), XraySnapshotSourceMasterWrite); err != nil {
		t.Fatal(err)
	}
	if err := repo.migrateRemoteInboundDesired(); err != nil {
		t.Fatalf("migrateRemoteInboundDesired: %v", err)
	}

	got, err := repo.ListActiveDesiredInbounds(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	gotTags := make([]string, 0, len(got))
	for _, inbound := range got {
		gotTags = append(gotTags, inbound.InboundTag)
	}
	wantTags := []string{"node-inbound", "tunnel-only"}
	if !reflect.DeepEqual(gotTags, wantTags) {
		t.Fatalf("migrated active tags = %#v, want %#v", gotTags, wantTags)
	}
	if got[0].MutationID != "node-generation" || got[1].MutationID != "tunnel-generation" {
		t.Fatalf("migrated mutation IDs = %q, %q", got[0].MutationID, got[1].MutationID)
	}
	for _, excludedTag := range []string{"ownership-ghost", "inventory-ghost", "runtime-only", "api"} {
		if inbound, err := repo.GetDesiredInbound(ctx, server.ID, excludedTag); err != nil || inbound != nil {
			t.Fatalf("excluded tag %q migrated as %+v, err=%v", excludedTag, inbound, err)
		}
	}

	if _, err := repo.MarkDesiredInboundDeleted(ctx, server.ID, "tunnel-only", "tunnel-generation"); err != nil {
		t.Fatal(err)
	}
	if err := repo.migrateRemoteInboundDesired(); err != nil {
		t.Fatalf("second migrateRemoteInboundDesired: %v", err)
	}
	tombstone, err := repo.GetDesiredInbound(ctx, server.ID, "tunnel-only")
	if err != nil {
		t.Fatal(err)
	}
	if tombstone == nil || tombstone.DesiredState != DesiredInboundStateDeleted {
		t.Fatalf("startup backfill resurrected tombstone: %+v", tombstone)
	}
}

func TestDesiredInboundBackfillKeepsOnlyPhysicalNodeOwnerCredential(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()
	if _, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://owner-id@example.test:443", NodeName: "Owner node",
		Protocol: "vless", ClashConfig: `{"type":"vless","uuid":"owner-id","server":"example.test","port":443}`,
		ParsedConfig: `{"type":"vless","uuid":"owner-id","server":"example.test","port":443}`,
		Enabled:      true, OriginalServer: server.Name, InboundTag: "client-filter",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://disabled-id@example.test:443", NodeName: "Disabled node",
		Protocol: "vless", ClashConfig: `{"type":"vless","uuid":"disabled-id","server":"example.test","port":443}`,
		ParsedConfig: `{"type":"vless","uuid":"disabled-id","server":"example.test","port":443}`,
		Enabled:      false, OriginalServer: server.Name, InboundTag: "client-filter",
	}); err != nil {
		t.Fatal(err)
	}
	routed, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://routed-id@example.test:443", NodeName: "Routed node",
		Protocol: "vless", ClashConfig: `{"type":"vless","uuid":"routed-id","server":"example.test","port":443}`,
		ParsedConfig: `{"type":"vless","uuid":"routed-id","server":"example.test","port":443}`,
		Enabled:      true, OriginalServer: server.Name, InboundTag: "client-filter",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE nodes SET node_type = 'routed' WHERE id = ?`, routed.ID); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag": "client-filter", "protocol": "vless", "port": 443,
			"settings": map[string]interface{}{"clients": []interface{}{
				map[string]interface{}{"id": "owner-id", "email": "admin"},
				map[string]interface{}{"id": "disabled-id", "email": "disabled"},
				map[string]interface{}{"id": "routed-id", "email": "routed"},
				map[string]interface{}{"id": "expired-id", "email": "expired__client-filter"},
				map[string]interface{}{"id": "injected-id", "email": "attacker__client-filter"},
			}},
		}},
		"outbounds": []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := repo.BackfillAuthorizedDesiredInbounds(ctx, server.ID, string(config))
	if err != nil || inserted != 1 {
		t.Fatalf("backfill inserted=%d err=%v", inserted, err)
	}
	desired, err := repo.GetDesiredInbound(ctx, server.ID, "client-filter")
	if err != nil || desired == nil {
		t.Fatalf("desired inbound=%+v err=%v", desired, err)
	}
	var inbound map[string]interface{}
	if err := json.Unmarshal(desired.InboundJSON, &inbound); err != nil {
		t.Fatal(err)
	}
	settings, _ := inbound["settings"].(map[string]interface{})
	clients, _ := settings["clients"].([]interface{})
	if len(clients) != 1 {
		t.Fatalf("sanitized clients=%#v, want only the physical node owner", clients)
	}
	owner, _ := clients[0].(map[string]interface{})
	if owner["id"] != "owner-id" {
		t.Fatalf("sanitized owner=%#v", owner)
	}
}

func TestDesiredInboundBackfillPreservesOnlyProtocolSpecificNodeCredential(t *testing.T) {
	tests := []struct {
		name         string
		protocol     string
		nodeProtocol string
		nodeClash    map[string]interface{}
		listKey      string
		settings     map[string]interface{}
		wantSettings map[string]interface{}
		owner        map[string]interface{}
		untrusted    []interface{}
	}{
		{
			name: "vless id", protocol: "vless", nodeProtocol: "vless",
			nodeClash: map[string]interface{}{"type": "vless", "uuid": "owner-id"},
			listKey:   "clients", owner: map[string]interface{}{"id": "owner-id", "email": "admin"},
			untrusted: []interface{}{map[string]interface{}{"id": "injected-id", "email": "attacker"}},
		},
		{
			name: "trojan password", protocol: "trojan", nodeProtocol: "trojan",
			nodeClash: map[string]interface{}{"type": "trojan", "password": "owner-secret"},
			listKey:   "clients", owner: map[string]interface{}{"password": "owner-secret", "email": "admin"},
			untrusted: []interface{}{map[string]interface{}{"password": "injected-secret", "email": "attacker"}},
		},
		{
			name: "socks user and password", protocol: "socks", nodeProtocol: "socks",
			nodeClash: map[string]interface{}{"type": "socks5", "username": "owner-user", "password": "owner-pass"},
			listKey:   "accounts", owner: map[string]interface{}{"user": "owner-user", "pass": "owner-pass"},
			untrusted: []interface{}{
				map[string]interface{}{"user": "owner-user"},
				map[string]interface{}{"user": "owner-user", "pass": "attacker-pass"},
				map[string]interface{}{"user": "attacker", "pass": "owner-pass"},
			},
		},
		{
			name: "http user and password", protocol: "http", nodeProtocol: "http",
			nodeClash: map[string]interface{}{"type": "http", "username": "owner-user", "password": "owner-pass"},
			listKey:   "accounts", owner: map[string]interface{}{"user": "owner-user", "pass": "owner-pass"},
			untrusted: []interface{}{
				map[string]interface{}{"user": "owner-user"},
				map[string]interface{}{"user": "owner-user", "pass": "attacker-pass"},
				map[string]interface{}{"user": "attacker", "pass": "owner-pass"},
			},
		},
		{
			name: "hysteria auth", protocol: "hysteria", nodeProtocol: "hysteria",
			nodeClash: map[string]interface{}{"type": "hysteria2", "password": "owner-auth"},
			listKey:   "clients", owner: map[string]interface{}{"auth": "owner-auth", "email": "admin"},
			untrusted: []interface{}{map[string]interface{}{"auth": "injected-auth", "email": "attacker"}},
		},
		{
			name: "snell psk", protocol: "snell", nodeProtocol: "snell",
			nodeClash: map[string]interface{}{"type": "snell", "psk": "owner-psk"},
			listKey:   "users", owner: map[string]interface{}{"psk": "owner-psk", "email": "admin"},
			untrusted: []interface{}{map[string]interface{}{"psk": "injected-psk", "email": "attacker"}},
		},
		{
			name: "shadowsocks 2022 user password", protocol: "shadowsocks", nodeProtocol: "shadowsocks",
			nodeClash: map[string]interface{}{
				"type": "ss", "cipher": "2022-blake3-aes-128-gcm",
				"password": "master-secret:owner-user-secret",
			},
			listKey: "clients",
			settings: map[string]interface{}{
				"method": "2022-blake3-aes-128-gcm", "password": "agent-injected-master",
			},
			wantSettings: map[string]interface{}{"password": "master-secret"},
			owner:        map[string]interface{}{"password": "owner-user-secret", "email": "admin"},
			untrusted:    []interface{}{map[string]interface{}{"password": "injected-user-secret", "email": "attacker"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo, server := newDesiredInboundTestRepository(t)
			ctx := context.Background()
			tag := "credential-filter"
			test.nodeClash["server"] = "example.test"
			test.nodeClash["port"] = 443
			clashJSON, err := json.Marshal(test.nodeClash)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.CreateNode(ctx, Node{
				Username: "admin", RawURL: "test://owner@example.test:443", NodeName: "Owner node",
				Protocol: test.nodeProtocol, ClashConfig: string(clashJSON), ParsedConfig: string(clashJSON),
				Enabled: true, OriginalServer: server.Name, InboundTag: tag,
			}); err != nil {
				t.Fatal(err)
			}

			settings := make(map[string]interface{}, len(test.settings)+1)
			for key, value := range test.settings {
				settings[key] = value
			}
			settings[test.listKey] = append([]interface{}{test.owner}, test.untrusted...)
			config, err := json.Marshal(map[string]interface{}{
				"inbounds": []interface{}{map[string]interface{}{
					"tag": tag, "protocol": test.protocol, "port": 443, "settings": settings,
				}},
				"outbounds": []interface{}{},
			})
			if err != nil {
				t.Fatal(err)
			}
			inserted, err := repo.BackfillAuthorizedDesiredInbounds(ctx, server.ID, string(config))
			if err != nil || inserted != 1 {
				t.Fatalf("backfill inserted=%d err=%v", inserted, err)
			}
			desired, err := repo.GetDesiredInbound(ctx, server.ID, tag)
			if err != nil || desired == nil {
				t.Fatalf("desired inbound=%+v err=%v", desired, err)
			}
			var inbound map[string]interface{}
			if err := json.Unmarshal(desired.InboundJSON, &inbound); err != nil {
				t.Fatal(err)
			}
			storedSettings, _ := inbound["settings"].(map[string]interface{})
			credentials, _ := storedSettings[test.listKey].([]interface{})
			if len(credentials) != 1 || !reflect.DeepEqual(credentials[0], test.owner) {
				t.Fatalf("sanitized %s=%#v, want only %#v", test.listKey, credentials, test.owner)
			}
			for key, want := range test.wantSettings {
				if got := storedSettings[key]; !reflect.DeepEqual(got, want) {
					t.Fatalf("sanitized setting %s=%#v, want %#v", key, got, want)
				}
			}
		})
	}
}

func wireGuardBackfillTestKeyPair(t *testing.T, fill byte) (string, string) {
	t.Helper()
	privateBytes := bytes.Repeat([]byte{fill}, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(privateBytes),
		base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
}

func TestDesiredInboundBackfillRebuildsWireGuardPeersFromDatabaseMetadata(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x61}, 32)); err != nil {
		t.Fatalf("ConfigureNodeSecretEncryption: %v", err)
	}
	serverPrivateKey, serverPublicKey := wireGuardBackfillTestKeyPair(t, 0x21)
	clientPrivateKey, clientPublicKey := wireGuardBackfillTestKeyPair(t, 0x22)
	injectedPrivateKey, injectedPublicKey := wireGuardBackfillTestKeyPair(t, 0x23)
	probePrivateKey, probePublicKey := wireGuardBackfillTestKeyPair(t, 0x24)
	tag := "wireguard-db"
	nodeConfig, err := json.Marshal(map[string]interface{}{
		"name": "Owner WireGuard", "type": "wireguard", "server": "edge.example.test", "port": 51820,
		"private-key": clientPrivateKey, "public-key": serverPublicKey, "ip": "10.66.66.2", "mtu": 1420,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "Owner WireGuard", Protocol: "wireguard",
		ClashConfig: string(nodeConfig), ParsedConfig: string(nodeConfig), Enabled: true,
		OriginalServer: server.Name, InboundTag: tag, InboundMutationID: "wireguard-generation",
	}); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(backfillWireGuardMetadata{
		ServerPublicKey: serverPublicKey,
		ServerAddresses: []string{"10.66.66.1/32"},
		MTU:             1420,
		Peers: []backfillWireGuardPeer{
			{PublicKey: clientPublicKey, AllowedIPs: []string{"10.66.66.2/32"}, KeepAlive: 25},
			{PublicKey: probePublicKey, AllowedIPs: []string{"10.66.66.3/32"}},
			{PublicKey: injectedPublicKey, AllowedIPs: []string{"10.66.66.2/32"}, KeepAlive: 25},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := repo.CreateManagedInboundResource(ctx, ManagedInboundResource{
		ServerID: server.ID, DisplayName: "Owner WireGuard", Protocol: "wireguard", InboundTag: tag,
		MutationID: "wireguard-generation", EndpointHost: "edge.example.test", EndpointPort: 51820,
		PublicMetadataJSON: metadata, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateWireGuardProbePeer(ctx, WireGuardProbePeer{
		ResourceID: resource.ID, PublicKey: probePublicKey, PrivateKey: probePrivateKey,
		Addresses: []string{"10.66.66.3/32"},
	}); err != nil {
		t.Fatal(err)
	}

	config, err := json.Marshal(map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag": tag, "protocol": "wireguard", "port": 51820,
			"settings": map[string]interface{}{
				"secretKey": serverPrivateKey, "address": []interface{}{"10.99.0.1/32"}, "mtu": 600,
				"peers": []interface{}{map[string]interface{}{
					"publicKey": injectedPublicKey, "allowedIPs": []interface{}{"10.66.66.2/32"}, "keepAlive": 1,
				}},
			},
		}},
		"outbounds": []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	startupUntrustedConfig, err := json.Marshal(map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag": tag, "protocol": "wireguard", "port": 51999,
			"settings": map[string]interface{}{
				"secretKey": injectedPrivateKey,
				"peers": []interface{}{map[string]interface{}{
					"publicKey": injectedPublicKey, "allowedIPs": []interface{}{"10.66.66.2/32"},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	deferred, err := backfillAuthorizedDesiredInbounds(ctx, repo.db, server.ID, string(startupUntrustedConfig), nil)
	if err != nil || deferred != 0 {
		t.Fatalf("startup backfill with encrypted node identity inserted=%d err=%v", deferred, err)
	}
	if pending, err := repo.GetDesiredInbound(ctx, server.ID, tag); err != nil || pending != nil {
		t.Fatalf("startup backfill persisted unverified WireGuard desired inbound=%+v err=%v", pending, err)
	}
	if _, err := repo.UpsertCurrentXraySnapshot(ctx, server.ID, string(config), XraySnapshotSourceMasterWrite); err != nil {
		t.Fatal(err)
	}
	inserted, err := repo.CompleteDeferredDesiredInboundBackfill(ctx)
	if err != nil || inserted != 1 {
		t.Fatalf("deferred backfill inserted=%d err=%v", inserted, err)
	}
	if inserted, err := repo.CompleteDeferredDesiredInboundBackfill(ctx); err != nil || inserted != 0 {
		t.Fatalf("idempotent deferred backfill inserted=%d err=%v", inserted, err)
	}
	desired, err := repo.GetDesiredInbound(ctx, server.ID, tag)
	if err != nil || desired == nil {
		t.Fatalf("desired inbound=%+v err=%v", desired, err)
	}
	var inbound map[string]interface{}
	if err := json.Unmarshal(desired.InboundJSON, &inbound); err != nil {
		t.Fatal(err)
	}
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings["secretKey"] != serverPrivateKey {
		t.Fatalf("server private key changed during reconstruction")
	}
	if mtu, ok := backfillNumericInt(settings["mtu"]); !ok || mtu != 1420 {
		t.Fatalf("rebuilt MTU=%#v, want 1420", settings["mtu"])
	}
	addresses, _ := settings["address"].([]interface{})
	if !reflect.DeepEqual(addresses, []interface{}{"10.66.66.1/32"}) {
		t.Fatalf("rebuilt server addresses=%#v", addresses)
	}
	peers, _ := settings["peers"].([]interface{})
	if len(peers) != 2 {
		t.Fatalf("rebuilt peers=%#v, want the database node and probe peers", peers)
	}
	rebuiltByKey := make(map[string]map[string]interface{}, len(peers))
	for _, rawPeer := range peers {
		peer, _ := rawPeer.(map[string]interface{})
		publicKey, _ := peer["publicKey"].(string)
		rebuiltByKey[publicKey] = peer
	}
	if _, exists := rebuiltByKey[injectedPublicKey]; exists {
		t.Fatalf("Agent-injected peer survived reconstruction: %#v", rebuiltByKey[injectedPublicKey])
	}
	if peer := rebuiltByKey[clientPublicKey]; peer == nil ||
		!reflect.DeepEqual(peer["allowedIPs"], []interface{}{"10.66.66.2/32"}) {
		t.Fatalf("rebuilt database node peer=%#v", peer)
	}
	if peer := rebuiltByKey[probePublicKey]; peer == nil ||
		!reflect.DeepEqual(peer["allowedIPs"], []interface{}{"10.66.66.3/32"}) {
		t.Fatalf("rebuilt database probe peer=%#v", peer)
	}

	maliciousConfig, err := json.Marshal(map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag": tag, "protocol": "wireguard", "port": 51820,
			"settings": map[string]interface{}{
				"secretKey": injectedPrivateKey, "address": []interface{}{"10.66.66.99/32"}, "mtu": 600,
				"peers": []interface{}{map[string]interface{}{
					"publicKey": injectedPublicKey, "allowedIPs": []interface{}{"10.66.66.99/32"},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if inserted, err := repo.BackfillAuthorizedDesiredInbounds(ctx, server.ID, string(maliciousConfig)); err != nil || inserted != 0 {
		t.Fatalf("existing desired inbound consulted malicious Agent state: inserted=%d err=%v", inserted, err)
	}
	unchanged, err := repo.GetDesiredInbound(ctx, server.ID, tag)
	if err != nil || unchanged == nil || string(unchanged.InboundJSON) != string(desired.InboundJSON) {
		t.Fatalf("malicious Agent state changed existing desired inbound=%+v err=%v", unchanged, err)
	}
}

func TestDesiredInboundBackfillRejectsWireGuardServerKeyMismatch(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x62}, 32)); err != nil {
		t.Fatalf("ConfigureNodeSecretEncryption: %v", err)
	}
	serverPrivateKey, serverPublicKey := wireGuardBackfillTestKeyPair(t, 0x31)
	clientPrivateKey, clientPublicKey := wireGuardBackfillTestKeyPair(t, 0x32)
	attackerPrivateKey, _ := wireGuardBackfillTestKeyPair(t, 0x33)
	tag := "wireguard-key-mismatch"
	nodeConfig, err := json.Marshal(map[string]interface{}{
		"type": "wireguard", "server": "edge.example.test", "port": 51820,
		"private-key": clientPrivateKey, "public-key": serverPublicKey, "ip": "10.77.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "Owner WireGuard", Protocol: "wireguard",
		ClashConfig: string(nodeConfig), ParsedConfig: string(nodeConfig), Enabled: true,
		OriginalServer: server.Name, InboundTag: tag,
	}); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(backfillWireGuardMetadata{
		ServerPublicKey: serverPublicKey, ServerAddresses: []string{"10.77.0.1/32"}, MTU: 1420,
		Peers: []backfillWireGuardPeer{{PublicKey: clientPublicKey, AllowedIPs: []string{"10.77.0.2/32"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateManagedInboundResource(ctx, ManagedInboundResource{
		ServerID: server.ID, DisplayName: "Owner WireGuard", Protocol: "wireguard", InboundTag: tag,
		EndpointHost: "edge.example.test", EndpointPort: 51820, PublicMetadataJSON: metadata, CreatedBy: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]interface{}{
		"inbounds": []interface{}{map[string]interface{}{
			"tag": tag, "protocol": "wireguard", "port": 51820,
			"settings": map[string]interface{}{
				"secretKey": attackerPrivateKey, "address": []interface{}{"10.77.0.1/32"}, "mtu": 1420,
				"peers": []interface{}{map[string]interface{}{
					"publicKey": clientPublicKey, "allowedIPs": []interface{}{"10.77.0.2/32"},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if inserted, err := repo.BackfillAuthorizedDesiredInbounds(ctx, server.ID, string(config)); err == nil || inserted != 0 {
		t.Fatalf("mismatched server key backfill inserted=%d err=%v", inserted, err)
	}
	if desired, err := repo.GetDesiredInbound(ctx, server.ID, tag); err != nil || desired != nil {
		t.Fatalf("mismatched server key created desired inbound=%+v err=%v", desired, err)
	}
	if serverPrivateKey == attackerPrivateKey {
		t.Fatal("test key fixture unexpectedly reused the server key")
	}
}

func TestDesiredInboundValidationAndEmptyList(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()

	for _, test := range []struct {
		name string
		tag  string
		body json.RawMessage
	}{
		{"invalid JSON", "tag-a", json.RawMessage(`{`)},
		{"non-object JSON", "tag-a", json.RawMessage(`[]`)},
		{"mismatched tag", "tag-a", desiredInboundJSON("tag-b", 443)},
		{"missing settings and port", "tag-a", json.RawMessage(`{"tag":"tag-a","protocol":"vless"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := repo.UpsertActiveDesiredInbound(ctx, server.ID, test.tag, "generation", test.body); err == nil {
				t.Fatal("invalid desired inbound was accepted")
			}
		})
	}
	got, err := repo.ListActiveDesiredInbounds(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("invalid server list = %#v, want non-nil empty list", got)
	}
}

func TestDesiredInboundMigrationRequiresExplicitTunnelInIntent(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()
	if err := repo.SetRemoteInboundOwnership(ctx, server.ID, "tunnel-in", "tunnel-in-generation"); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]interface{}{
		"inbounds":  []interface{}{json.RawMessage(desiredInboundJSON("tunnel-in", 443))},
		"outbounds": []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertCurrentXraySnapshot(ctx, server.ID, string(config), XraySnapshotSourceMasterWrite); err != nil {
		t.Fatal(err)
	}
	if err := repo.migrateRemoteInboundDesired(); err != nil {
		t.Fatal(err)
	}
	if inbound, err := repo.GetDesiredInbound(ctx, server.ID, "tunnel-in"); err != nil || inbound != nil {
		t.Fatalf("default server retained tunnel-in: %+v, err=%v", inbound, err)
	}

	if _, err := repo.db.ExecContext(ctx, `UPDATE remote_servers SET steal_self = 1, steal_mode = '' WHERE id = ?`, server.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.migrateRemoteInboundDesired(); err != nil {
		t.Fatal(err)
	}
	inbound, err := repo.GetDesiredInbound(ctx, server.ID, "tunnel-in")
	if err != nil {
		t.Fatal(err)
	}
	if inbound == nil || inbound.DesiredState != DesiredInboundStateActive || inbound.MutationID != "tunnel-in-generation" {
		t.Fatalf("explicit tunnel intent was not migrated: %+v", inbound)
	}
}

func TestListAuthorizedInboundTagsUsesDatabaseEvidenceAndTombstones(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()
	otherServer := RemoteServer{
		Name: "edge-b", Token: "edge-b-token", Status: RemoteServerStatusConnected,
		IPAddress: "203.0.113.11", ListenPort: 21888, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, &otherServer); err != nil {
		t.Fatal(err)
	}

	for _, node := range []Node{
		{Username: "admin", RawURL: "vless://live@example.test:443", NodeName: "Live", Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "node-live", InboundMutationID: "node-live-generation"},
		{Username: "admin", RawURL: "vless://deleted@example.test:443", NodeName: "Deleted", Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "node-deleted", InboundMutationID: "node-deleted-generation"},
		{Username: "admin", RawURL: "vless://other@example.test:443", NodeName: "Other", Protocol: "vless", Enabled: true, OriginalServer: otherServer.Name, InboundTag: "other-node", InboundMutationID: "other-generation"},
	} {
		if _, err := repo.CreateNode(ctx, node); err != nil {
			t.Fatalf("CreateNode(%s): %v", node.NodeName, err)
		}
	}
	for tag, mutationID := range map[string]string{
		"ordinary-ownership-ghost": "ordinary-generation",
		"tunnel-legacy":            "tunnel-generation",
		"tunnel-in":                "tunnel-in-generation",
	} {
		if err := repo.SetRemoteInboundOwnership(ctx, server.ID, tag, mutationID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repo.CreateManagedInboundResource(ctx, ManagedInboundResource{
		ServerID: server.ID, DisplayName: "Managed ghost", Protocol: "vless",
		InboundTag: "managed-ghost", EndpointHost: "edge.example.test", EndpointPort: 2443,
		PublicMetadataJSON: json.RawMessage(`{}`), CreatedBy: "system-sync",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MarkDesiredInboundDeleted(ctx, server.ID, "node-deleted", "node-deleted-generation"); err != nil {
		t.Fatal(err)
	}

	tags, err := repo.ListAuthorizedInboundTags(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"node-live", "tunnel-legacy"}; !reflect.DeepEqual(tags, want) {
		t.Fatalf("authorized tags = %#v, want %#v", tags, want)
	}

	if _, err := repo.db.ExecContext(ctx, `UPDATE remote_servers SET steal_self = 1, steal_mode = 'tunnel' WHERE id = ?`, server.ID); err != nil {
		t.Fatal(err)
	}
	tags, err = repo.ListAuthorizedInboundTags(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"node-live", "tunnel-in", "tunnel-legacy"}; !reflect.DeepEqual(tags, want) {
		t.Fatalf("authorized tags with tunnel takeover = %#v, want %#v", tags, want)
	}
	if _, err := repo.MarkDesiredInboundDeleted(ctx, server.ID, "tunnel-in", "tunnel-in-generation"); err != nil {
		t.Fatal(err)
	}
	tags, err = repo.ListAuthorizedInboundTags(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"node-live", "tunnel-legacy"}; !reflect.DeepEqual(tags, want) {
		t.Fatalf("authorized tags after tunnel tombstone = %#v, want %#v", tags, want)
	}
}

func TestBackfillAuthorizedDesiredInboundsWithoutSnapshot(t *testing.T) {
	repo, server := newDesiredInboundTestRepository(t)
	ctx := context.Background()
	for _, node := range []Node{
		{Username: "admin", RawURL: "vless://live@example.test:443", NodeName: "Live", Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "node-live", InboundMutationID: "node-live-generation"},
		{Username: "admin", RawURL: "vless://deleted@example.test:443", NodeName: "Deleted", Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "node-deleted", InboundMutationID: "node-deleted-generation"},
	} {
		if _, err := repo.CreateNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.SetRemoteInboundOwnership(ctx, server.ID, "tunnel-legacy", "tunnel-generation"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateManagedInboundResource(ctx, ManagedInboundResource{
		ServerID: server.ID, DisplayName: "Managed ghost", Protocol: "vless",
		InboundTag: "managed-ghost", EndpointHost: "edge.example.test", EndpointPort: 2443,
		PublicMetadataJSON: json.RawMessage(`{}`), CreatedBy: "system-sync",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MarkDesiredInboundDeleted(ctx, server.ID, "node-deleted", "node-deleted-generation"); err != nil {
		t.Fatal(err)
	}
	if current, err := repo.GetCurrentXraySnapshot(ctx, server.ID); err != nil || current != nil {
		t.Fatalf("test requires no current snapshot, got %+v err=%v", current, err)
	}

	liveConfig, err := json.Marshal(map[string]interface{}{
		"inbounds": []interface{}{
			json.RawMessage(desiredInboundJSON("node-live", 1443)),
			json.RawMessage(desiredInboundJSON("node-deleted", 1444)),
			json.RawMessage(desiredInboundJSON("tunnel-legacy", 1445)),
			json.RawMessage(desiredInboundJSON("managed-ghost", 1446)),
			json.RawMessage(desiredInboundJSON("runtime-only", 1447)),
			json.RawMessage(desiredInboundJSON("api", 10085)),
		},
		"outbounds": []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := repo.BackfillAuthorizedDesiredInbounds(ctx, server.ID, string(liveConfig))
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 2 {
		t.Fatalf("inserted desired inbounds = %d, want 2", inserted)
	}
	active, err := repo.ListActiveDesiredInbounds(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	tags := make([]string, 0, len(active))
	for _, inbound := range active {
		tags = append(tags, inbound.InboundTag)
	}
	if want := []string{"node-live", "tunnel-legacy"}; !reflect.DeepEqual(tags, want) {
		t.Fatalf("backfilled active tags = %#v, want %#v", tags, want)
	}
	deleted, err := repo.GetDesiredInbound(ctx, server.ID, "node-deleted")
	if err != nil {
		t.Fatal(err)
	}
	if deleted == nil || deleted.DesiredState != DesiredInboundStateDeleted {
		t.Fatalf("backfill replaced deletion tombstone: %+v", deleted)
	}
	for _, excludedTag := range []string{"managed-ghost", "runtime-only", "api"} {
		if inbound, err := repo.GetDesiredInbound(ctx, server.ID, excludedTag); err != nil || inbound != nil {
			t.Fatalf("excluded tag %q was adopted as %+v, err=%v", excludedTag, inbound, err)
		}
	}
	inserted, err = repo.BackfillAuthorizedDesiredInbounds(ctx, server.ID, string(liveConfig))
	if err != nil || inserted != 0 {
		t.Fatalf("idempotent backfill inserted=%d err=%v", inserted, err)
	}
}
