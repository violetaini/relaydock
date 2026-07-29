package storage

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func wireGuardProbeTestKeyPair(t *testing.T, fill byte) (string, string) {
	t.Helper()
	privateBytes := bytes.Repeat([]byte{fill}, 32)
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), base64.StdEncoding.EncodeToString(privateBytes)
}

func createWireGuardProbeTestResource(t *testing.T, repo *TrafficRepository, tag string) *ManagedInboundResource {
	t.Helper()
	server := RemoteServer{
		Name:       "probe-edge-" + tag,
		Token:      "probe-agent-token-" + tag,
		Status:     RemoteServerStatusConnected,
		IPAddress:  "203.0.113.20",
		ListenPort: 21888,
		XrayMode:   "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), &server); err != nil {
		t.Fatal(err)
	}
	resource, err := repo.CreateManagedInboundResource(context.Background(), ManagedInboundResource{
		ServerID:           server.ID,
		DisplayName:        "Probe WireGuard",
		Protocol:           "wireguard",
		InboundTag:         tag,
		EndpointHost:       "edge.example.test",
		EndpointPort:       51820,
		PublicMetadataJSON: json.RawMessage(`{"server_public_key":"test"}`),
		CreatedBy:          "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func TestWireGuardProbePeerEncryptsAtRestAndMarksActive(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-probe-peer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	masterKey := bytes.Repeat([]byte{0x41}, 32)
	if err := repo.ConfigureNodeSecretEncryption(masterKey); err != nil {
		t.Fatal(err)
	}
	resource := createWireGuardProbeTestResource(t, repo, "wireguard-probe-encrypted")
	publicKey, privateKey := wireGuardProbeTestKeyPair(t, 0x21)

	created, err := repo.CreateWireGuardProbePeer(context.Background(), WireGuardProbePeer{
		ResourceID: resource.ID,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Addresses:  []string{"10.77.0.2/32", "fd77::2/128"},
	})
	if err != nil {
		t.Fatalf("CreateWireGuardProbePeer: %v", err)
	}
	if created.PrivateKey != privateKey || created.PublicKey != publicKey || created.State != WireGuardProbePeerStatePending {
		t.Fatalf("unexpected created probe peer: %+v", created)
	}
	serialized, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte(privateKey)) {
		t.Fatalf("serialized probe peer exposed private key: %s", serialized)
	}

	var storedPublicKey, ciphertext, addressesJSON string
	if err := repo.db.QueryRow(`
SELECT public_key, private_key_ciphertext, addresses_json
FROM wireguard_probe_peers WHERE resource_id = ?`, resource.ID).
		Scan(&storedPublicKey, &ciphertext, &addressesJSON); err != nil {
		t.Fatal(err)
	}
	if storedPublicKey != publicKey || strings.Contains(ciphertext, privateKey) || ciphertext == privateKey {
		t.Fatalf("unsafe stored probe peer public=%q ciphertext=%q", storedPublicKey, ciphertext)
	}
	if _, err := repo.openWireGuardProbePrivateKey(resource.ID+1, ciphertext); err == nil {
		t.Fatal("probe private-key ciphertext opened under a different resource AAD")
	}

	active, err := repo.MarkWireGuardProbePeerActive(context.Background(), resource.ID)
	if err != nil {
		t.Fatalf("MarkWireGuardProbePeerActive: %v", err)
	}
	if active.State != WireGuardProbePeerStateActive || active.PrivateKey != privateKey {
		t.Fatalf("unexpected active probe peer: %+v", active)
	}
}

func TestWireGuardProbePeerRejectsInvalidResourceKeysAndAddresses(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-probe-validation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal(err)
	}
	resource := createWireGuardProbeTestResource(t, repo, "wireguard-probe-validation")
	publicKey, privateKey := wireGuardProbeTestKeyPair(t, 0x22)
	otherPublicKey, _ := wireGuardProbeTestKeyPair(t, 0x23)

	for name, peer := range map[string]WireGuardProbePeer{
		"short private key": {
			ResourceID: resource.ID, PublicKey: publicKey, PrivateKey: "short", Addresses: []string{"10.77.0.2/32"},
		},
		"mismatched key pair": {
			ResourceID: resource.ID, PublicKey: otherPublicKey, PrivateKey: privateKey, Addresses: []string{"10.77.0.2/32"},
		},
		"invalid address": {
			ResourceID: resource.ID, PublicKey: publicKey, PrivateKey: privateKey, Addresses: []string{"not-a-prefix"},
		},
		"active on create": {
			ResourceID: resource.ID, PublicKey: publicKey, PrivateKey: privateKey, Addresses: []string{"10.77.0.2/32"}, State: WireGuardProbePeerStateActive,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := repo.CreateWireGuardProbePeer(context.Background(), peer); err == nil {
				t.Fatal("invalid WireGuard probe peer was accepted")
			}
		})
	}

	server := RemoteServer{
		Name: "non-wg-edge", Token: "non-wg-token", Status: RemoteServerStatusConnected,
		IPAddress: "203.0.113.21", ListenPort: 21888, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), &server); err != nil {
		t.Fatal(err)
	}
	nonWireGuard, err := repo.CreateManagedInboundResource(context.Background(), ManagedInboundResource{
		ServerID: server.ID, DisplayName: "VLESS", Protocol: "vless", InboundTag: "vless-probe",
		EndpointHost: "edge.example.test", EndpointPort: 443, PublicMetadataJSON: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateWireGuardProbePeer(context.Background(), WireGuardProbePeer{
		ResourceID: nonWireGuard.ID, PublicKey: publicKey, PrivateKey: privateKey, Addresses: []string{"10.77.0.2/32"},
	}); err == nil || !strings.Contains(err.Error(), "resource not found") {
		t.Fatalf("non-WireGuard resource error=%v", err)
	}
}

func TestWireGuardProbePeerStartupRejectsWrongMasterAndInvalidPlaintext(t *testing.T) {
	t.Run("wrong master", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wireguard-probe-wrong-master.db")
		correctMaster := bytes.Repeat([]byte{0x43}, 32)
		repo, err := NewTrafficRepository(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.ConfigureNodeSecretEncryption(correctMaster); err != nil {
			t.Fatal(err)
		}
		resource := createWireGuardProbeTestResource(t, repo, "wireguard-probe-wrong-master")
		publicKey, privateKey := wireGuardProbeTestKeyPair(t, 0x24)
		if _, err := repo.CreateWireGuardProbePeer(context.Background(), WireGuardProbePeer{
			ResourceID: resource.ID, PublicKey: publicKey, PrivateKey: privateKey, Addresses: []string{"10.77.0.2/32"},
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}

		reopened, err := NewTrafficRepository(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if err := reopened.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x44}, 32)); err == nil || !strings.Contains(err.Error(), "decrypt") {
			t.Fatalf("wrong master error=%v", err)
		}
		if _, err := reopened.GetWireGuardProbePeer(context.Background(), resource.ID); err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Fatalf("failed configuration left encryption enabled: %v", err)
		}
		if err := reopened.ConfigureNodeSecretEncryption(correctMaster); err != nil {
			t.Fatalf("correct master after failure: %v", err)
		}
	})

	t.Run("decrypted key is not 32 bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wireguard-probe-invalid-key.db")
		masterKey := bytes.Repeat([]byte{0x45}, 32)
		repo, err := NewTrafficRepository(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.ConfigureNodeSecretEncryption(masterKey); err != nil {
			t.Fatal(err)
		}
		resource := createWireGuardProbeTestResource(t, repo, "wireguard-probe-invalid-key")
		publicKey, _ := wireGuardProbeTestKeyPair(t, 0x25)
		repo.nodeSecretMu.RLock()
		box := repo.nodeSecretBox
		repo.nodeSecretMu.RUnlock()
		ciphertext, err := box.Seal([]byte("short"), wireGuardProbePeerAssociatedData(resource.ID))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.db.Exec(`
INSERT INTO wireguard_probe_peers
    (resource_id, public_key, private_key_ciphertext, addresses_json, state)
VALUES (?, ?, ?, '["10.77.0.2/32"]', 'pending')`, resource.ID, publicKey, ciphertext); err != nil {
			t.Fatal(err)
		}
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}

		reopened, err := NewTrafficRepository(path)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if err := reopened.ConfigureNodeSecretEncryption(masterKey); err == nil || !strings.Contains(err.Error(), "32 bytes") {
			t.Fatalf("invalid decrypted key error=%v", err)
		}
	})
}

func TestWireGuardProbePeerCascadesWithManagedInboundResource(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-probe-cascade.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x46}, 32)); err != nil {
		t.Fatal(err)
	}
	resource := createWireGuardProbeTestResource(t, repo, "wireguard-probe-cascade")
	publicKey, privateKey := wireGuardProbeTestKeyPair(t, 0x26)
	if _, err := repo.CreateWireGuardProbePeer(context.Background(), WireGuardProbePeer{
		ResourceID: resource.ID, PublicKey: publicKey, PrivateKey: privateKey, Addresses: []string{"10.77.0.2/32"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteManagedInboundResource(context.Background(), resource.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetWireGuardProbePeer(context.Background(), resource.ID); !errors.Is(err, ErrWireGuardProbePeerNotFound) {
		t.Fatalf("probe peer survived managed resource deletion: %v", err)
	}
}
