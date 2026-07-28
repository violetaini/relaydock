package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const testWireGuardPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func testWireGuardNodeConfig(name string) string {
	encoded, _ := json.Marshal(map[string]interface{}{
		"name": name, "type": "wireguard", "server": "203.0.113.10", "port": 51820,
		"ip": "10.66.66.2", "private-key": testWireGuardPrivateKey,
		"public-key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", "udp": true,
		"allowed-ips": []string{"0.0.0.0/0"},
	})
	return string(encoded)
}

func testWireGuardPublicNodeConfig(name string) string {
	var config map[string]interface{}
	_ = json.Unmarshal([]byte(testWireGuardNodeConfig(name)), &config)
	delete(config, "private-key")
	encoded, _ := json.Marshal(config)
	return string(encoded)
}

func configureTestNodeSecretEncryption(t *testing.T, repo *TrafficRepository, fill byte) {
	t.Helper()
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{fill}, 32)); err != nil {
		t.Fatalf("ConfigureNodeSecretEncryption: %v", err)
	}
}

func TestWireGuardSubscriptionPrivateKeyIsBoundToScopeAndAuthenticated(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-subscription-secret.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x2a)

	ciphertext, err := repo.SealWireGuardSubscriptionPrivateKey("first.yaml", testWireGuardPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, testWireGuardPrivateKey) {
		t.Fatal("subscription ciphertext contains the plaintext private key")
	}
	opened, err := repo.OpenWireGuardSubscriptionPrivateKey("first.yaml", ciphertext)
	if err != nil || opened != testWireGuardPrivateKey {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	if _, err := repo.OpenWireGuardSubscriptionPrivateKey("second.yaml", ciphertext); err == nil {
		t.Fatal("subscription ciphertext opened under a different scope")
	}

	tampered := []byte(ciphertext)
	if tampered[len(tampered)-1] == 'A' {
		tampered[len(tampered)-1] = 'B'
	} else {
		tampered[len(tampered)-1] = 'A'
	}
	if _, err := repo.OpenWireGuardSubscriptionPrivateKey("first.yaml", string(tampered)); err == nil {
		t.Fatal("tampered subscription ciphertext was accepted")
	}
}

func TestWireGuardNodePrivateKeyEncryptedAtRestAndHydrated(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-secret.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x31)
	config := testWireGuardNodeConfig("WG")
	created, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "WG", Protocol: "wireguard",
		RawURL:       "wireguard://" + testWireGuardPrivateKey + "@203.0.113.10:51820#wg",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(created.ClashConfig, testWireGuardPrivateKey) || created.RawURL != "" {
		t.Fatalf("created node was not safely hydrated: %+v", created)
	}
	var rawURL, parsedConfig, clashConfig, ciphertext string
	if err := repo.db.QueryRow(`SELECT raw_url, parsed_config, clash_config FROM nodes WHERE id = ?`, created.ID).
		Scan(&rawURL, &parsedConfig, &clashConfig); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT ciphertext FROM node_secrets WHERE node_id = ?`, created.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	for label, value := range map[string]string{"raw_url": rawURL, "parsed_config": parsedConfig, "clash_config": clashConfig, "ciphertext": ciphertext} {
		if strings.Contains(value, testWireGuardPrivateKey) {
			t.Fatalf("%s contains plaintext private key: %q", label, value)
		}
	}
	created.NodeName = "WG renamed"
	updated, err := repo.UpdateNode(context.Background(), created)
	if err != nil || updated.NodeName != "WG renamed" || !strings.Contains(updated.ClashConfig, testWireGuardPrivateKey) {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	listed, err := repo.ListAllNodes(context.Background())
	if err != nil || len(listed) != 1 || !strings.Contains(listed[0].ParsedConfig, testWireGuardPrivateKey) {
		t.Fatalf("listed=%+v err=%v", listed, err)
	}
}

func TestWireGuardNodeWriteFailsClosedWithoutEncryption(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-no-key.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	config := testWireGuardNodeConfig("WG")
	if _, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "WG", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
	}); err == nil || !strings.Contains(err.Error(), "加密尚未初始化") {
		t.Fatalf("CreateNode err=%v, want fail closed", err)
	}
	var count int
	if err := repo.db.QueryRow(`SELECT COUNT(1) FROM nodes`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed write left count=%d err=%v", count, err)
	}
}

func TestWireGuardNodeRejectsDeclaredProtocolMismatchAndAcceptsWGAlias(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-protocol-evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x35)
	config := testWireGuardNodeConfig("WG")

	for _, candidate := range []Node{
		{Username: "admin", NodeName: "Disguised type", Protocol: "vless", ParsedConfig: config, ClashConfig: config, Enabled: true},
		{Username: "admin", NodeName: "Disguised URL", Protocol: "vless", RawURL: "wg://" + testWireGuardPrivateKey + "@203.0.113.10:51820", ClashConfig: `{"name":"ordinary","type":"vless"}`, Enabled: true},
		{Username: "admin", NodeName: "Conflicting config", Protocol: "wireguard", ParsedConfig: config, ClashConfig: `{"name":"wrong","type":"vless"}`, Enabled: true},
	} {
		if _, err := repo.CreateNode(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "conflict") {
			t.Fatalf("CreateNode(%s) err=%v, want protocol conflict", candidate.NodeName, err)
		}
	}
	var count int
	if err := repo.db.QueryRow(`SELECT COUNT(1) FROM nodes`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected protocol mismatches left %d rows: %v", count, err)
	}

	created, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "Alias WG", Protocol: "wg",
		ParsedConfig: strings.ReplaceAll(config, `"type":"wireguard"`, `"type":"wg"`),
		ClashConfig:  strings.ReplaceAll(config, `"type":"wireguard"`, `"type":"wg"`),
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Protocol != "wireguard" || !strings.Contains(created.ClashConfig, testWireGuardPrivateKey) {
		t.Fatalf("wg alias was not canonicalized and hydrated: %+v", created)
	}
}

func TestWireGuardStartupRejectsDisguisedLegacyPlaintextAndMigratesWGAlias(t *testing.T) {
	t.Run("disguised protocol fails closed", func(t *testing.T) {
		repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-disguised-startup.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer repo.Close()
		config := testWireGuardNodeConfig("Disguised")
		if _, err := repo.db.Exec(`INSERT INTO nodes(username, raw_url, node_name, protocol, parsed_config, clash_config, enabled) VALUES('admin', '', 'Disguised', 'vless', ?, ?, 1)`, config, config); err != nil {
			t.Fatal(err)
		}
		if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x36}, 32)); err == nil || !strings.Contains(err.Error(), "conflict") {
			t.Fatalf("ConfigureNodeSecretEncryption err=%v, want fail-closed protocol conflict", err)
		}
		var stored string
		if err := repo.db.QueryRow(`SELECT clash_config FROM nodes WHERE node_name = 'Disguised'`).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stored, testWireGuardPrivateKey) {
			t.Fatal("rejected startup partially modified the disguised row")
		}
	})

	t.Run("wg alias is canonicalized", func(t *testing.T) {
		repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-alias-startup.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer repo.Close()
		config := strings.ReplaceAll(testWireGuardNodeConfig("Alias"), `"type":"wireguard"`, `"type":"wg"`)
		result, err := repo.db.Exec(`INSERT INTO nodes(username, raw_url, node_name, protocol, parsed_config, clash_config, enabled) VALUES('admin', '', 'Alias', 'wg', ?, ?, 1)`, config, config)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		configureTestNodeSecretEncryption(t, repo, 0x37)
		var protocol, stored string
		if err := repo.db.QueryRow(`SELECT protocol, clash_config FROM nodes WHERE id = ?`, id).Scan(&protocol, &stored); err != nil {
			t.Fatal(err)
		}
		if protocol != "wireguard" || strings.Contains(stored, testWireGuardPrivateKey) {
			t.Fatalf("alias migration protocol=%q config=%s", protocol, stored)
		}
	})
}

func TestWireGuardNodeRequiresPrivateKeyAndRejectsProtocolChange(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-required-key.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x39)
	publicOnly := testWireGuardPublicNodeConfig("Public only")
	if _, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "Public only", Protocol: "wireguard",
		ParsedConfig: publicOnly, ClashConfig: publicOnly, Enabled: true,
	}); err == nil || !strings.Contains(err.Error(), "requires a private key") {
		t.Fatalf("public-only WireGuard create err=%v", err)
	}

	config := testWireGuardNodeConfig("WG")
	created, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "WG", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	created.Protocol = "vless"
	if _, err := repo.UpdateNode(context.Background(), created); err == nil || !strings.Contains(err.Error(), "protocol cannot be changed") {
		t.Fatalf("WireGuard protocol change err=%v", err)
	}
	stored, err := repo.GetNodeByID(context.Background(), created.ID)
	if err != nil || stored.Protocol != "wireguard" || !strings.Contains(stored.ClashConfig, testWireGuardPrivateKey) {
		t.Fatalf("stored node changed after rejected transition: %+v err=%v", stored, err)
	}

	created = stored
	created.ClashConfig = strings.ReplaceAll(created.ClashConfig, testWireGuardPrivateKey, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=")
	created.ParsedConfig = created.ClashConfig
	if _, err := repo.UpdateNode(context.Background(), created); err == nil || !strings.Contains(err.Error(), "rotation") {
		t.Fatalf("WireGuard private key rotation err=%v", err)
	}
	if err := repo.MarkNodeAsRouted(context.Background(), created.ID, "blocked-outbound", 0); err == nil || !strings.Contains(err.Error(), "cannot be converted") {
		t.Fatalf("WireGuard routed conversion err=%v", err)
	}
}

func TestStagedWireGuardNodeMutationCAS(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-staged-cas.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x5a)
	ctx := context.Background()
	config := testWireGuardNodeConfig("staged")
	staged, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "staged", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: false,
		InboundMutationID: "managed-wireguard:generation-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	found, err := repo.GetStagedWireGuardNodeByMutation(ctx, staged.InboundMutationID)
	if err != nil || found.ID != staged.ID || !strings.Contains(found.ClashConfig, testWireGuardPrivateKey) {
		t.Fatalf("found=%+v err=%v", found, err)
	}
	attached, err := repo.AttachStagedWireGuardNodeIfMutation(ctx, staged.ID, staged.InboundMutationID, "edge-a", "wireguard-a")
	if err != nil {
		t.Fatal(err)
	}
	if !attached.Enabled || attached.OriginalServer != "edge-a" || attached.InboundTag != "wireguard-a" {
		t.Fatalf("attached=%+v", attached)
	}
	if deleted, err := repo.DeleteStagedWireGuardNodeIfMutation(ctx, staged.ID, staged.InboundMutationID); err != nil || deleted {
		t.Fatalf("attached node deleted=%v err=%v", deleted, err)
	}
	if _, err := repo.GetNodeByID(ctx, staged.ID); err != nil {
		t.Fatalf("attached node disappeared: %v", err)
	}
}

func TestDeleteStagedWireGuardNodeRejectsOtherRowsAndDuplicateMutation(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-staged-guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x5b)
	ctx := context.Background()
	config := testWireGuardNodeConfig("staged")
	first, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "first", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: false, InboundMutationID: "duplicate",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondConfig := strings.ReplaceAll(config, `"name":"staged"`, `"name":"second"`)
	second, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "second", Protocol: "wireguard",
		ParsedConfig: secondConfig, ClashConfig: secondConfig, Enabled: false, InboundMutationID: "duplicate",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetStagedWireGuardNodeByMutation(ctx, "duplicate"); err == nil || !strings.Contains(err.Error(), "multiple staged") {
		t.Fatalf("duplicate lookup err=%v", err)
	}
	if deleted, err := repo.DeleteStagedWireGuardNodeIfMutation(ctx, first.ID, "wrong"); err != nil || deleted {
		t.Fatalf("wrong mutation deleted=%v err=%v", deleted, err)
	}
	if deleted, err := repo.DeleteStagedWireGuardNodeIfMutation(ctx, second.ID, "duplicate"); err != nil || !deleted {
		t.Fatalf("exact staged delete=%v err=%v", deleted, err)
	}
	if _, err := repo.GetNodeByID(ctx, first.ID); err != nil {
		t.Fatalf("other staged row was removed: %v", err)
	}
}

func TestWireGuardNodeRejectsNonObjectConfigAndAlwaysClearsRawURL(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-shape.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x3a)
	for _, config := range []string{"not-json", "null", `[{"PrivateKey":"` + testWireGuardPrivateKey + `"}]`} {
		if _, err := repo.CreateNode(context.Background(), Node{
			Username: "admin", NodeName: "Bad WG", Protocol: "wireguard",
			ParsedConfig: config, ClashConfig: config, Enabled: true,
		}); err == nil || !strings.Contains(err.Error(), "JSON object") {
			t.Fatalf("config %q err=%v, want strict object rejection", config, err)
		}
	}
	config := testWireGuardNodeConfig("WG")
	created, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "WG", Protocol: "wireguard",
		RawURL:       "https://example.test/subscription?opaque=1",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.RawURL != "" {
		t.Fatalf("WireGuard raw URL was retained: %q", created.RawURL)
	}
}

func TestProtectWireGuardNodeSecretsMigratesLegacyPlaintextIdempotently(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	config := testWireGuardNodeConfig("Legacy WG")
	result, err := repo.db.Exec(`INSERT INTO nodes(username, raw_url, node_name, protocol, parsed_config, clash_config, enabled) VALUES(?, ?, ?, ?, ?, ?, 1)`,
		"admin", "", "Legacy WG", "wireguard", config, config)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	if _, err := repo.GetNodeByID(context.Background(), id); err == nil || !strings.Contains(err.Error(), "unprotected") {
		t.Fatalf("legacy plaintext read err=%v, want fail closed", err)
	}
	configureTestNodeSecretEncryption(t, repo, 0x42)
	if err := repo.ProtectWireGuardNodeSecrets(context.Background()); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
	node, err := repo.GetNodeByID(context.Background(), id)
	if err != nil || !strings.Contains(node.ClashConfig, testWireGuardPrivateKey) {
		t.Fatalf("migrated node=%+v err=%v", node, err)
	}
	var stored string
	if err := repo.db.QueryRow(`SELECT clash_config FROM nodes WHERE id = ?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, testWireGuardPrivateKey) {
		t.Fatalf("legacy plaintext remained: %s", stored)
	}
}

func TestProtectWireGuardNodeSecretsStripsMatchingPlaintextWithoutReplacingCiphertext(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-duplicate-plaintext.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x43)
	config := testWireGuardNodeConfig("WG")
	created, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "WG", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var originalCiphertext string
	if err := repo.db.QueryRow(`SELECT ciphertext FROM node_secrets WHERE node_id = ?`, created.ID).Scan(&originalCiphertext); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`UPDATE nodes SET parsed_config = ?, clash_config = ? WHERE id = ?`, config, config, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.ProtectWireGuardNodeSecrets(context.Background()); err != nil {
		t.Fatalf("strip matching duplicate plaintext: %v", err)
	}
	var storedConfig, storedCiphertext string
	if err := repo.db.QueryRow(`SELECT clash_config FROM nodes WHERE id = ?`, created.ID).Scan(&storedConfig); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT ciphertext FROM node_secrets WHERE node_id = ?`, created.ID).Scan(&storedCiphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedConfig, testWireGuardPrivateKey) || storedCiphertext != originalCiphertext {
		t.Fatalf("matching cleanup changed identity: config=%q ciphertext_changed=%t", storedConfig, storedCiphertext != originalCiphertext)
	}
}

func TestProtectWireGuardNodeSecretsRejectsConflictingPlaintextIdentity(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-conflicting-plaintext.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x44)
	config := testWireGuardNodeConfig("WG")
	created, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "WG", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var originalCiphertext string
	if err := repo.db.QueryRow(`SELECT ciphertext FROM node_secrets WHERE node_id = ?`, created.ID).Scan(&originalCiphertext); err != nil {
		t.Fatal(err)
	}
	conflicting := strings.ReplaceAll(config, testWireGuardPrivateKey, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=")
	if _, err := repo.db.Exec(`UPDATE nodes SET parsed_config = ?, clash_config = ? WHERE id = ?`, conflicting, conflicting, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.ProtectWireGuardNodeSecrets(context.Background()); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflicting plaintext migration err=%v", err)
	}
	var storedConfig, storedCiphertext string
	if err := repo.db.QueryRow(`SELECT clash_config FROM nodes WHERE id = ?`, created.ID).Scan(&storedConfig); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT ciphertext FROM node_secrets WHERE node_id = ?`, created.ID).Scan(&storedCiphertext); err != nil {
		t.Fatal(err)
	}
	if storedConfig != conflicting || storedCiphertext != originalCiphertext {
		t.Fatal("rejected conflicting plaintext migration partially mutated the node identity")
	}
}

func TestWireGuardBatchCreateStoresSecretsTransactionally(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "wireguard-batch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x53)
	config := testWireGuardNodeConfig("Batch WG")
	created, err := repo.BatchCreateNodes(context.Background(), []Node{{
		Username: "admin", NodeName: "Batch WG", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
	}})
	if err != nil || len(created) != 1 || !strings.Contains(created[0].ClashConfig, testWireGuardPrivateKey) {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	var count int
	if err := repo.db.QueryRow(`SELECT COUNT(1) FROM node_secrets WHERE node_id = ?`, created[0].ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("secret count=%d err=%v", count, err)
	}
}

func TestWireGuardReadFailsClosedWithWrongEncryptionKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard-wrong-key.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	configureTestNodeSecretEncryption(t, repo, 0x64)
	config := testWireGuardNodeConfig("WG")
	_, err = repo.CreateNode(context.Background(), Node{Username: "admin", NodeName: "WG", Protocol: "wireguard", ParsedConfig: config, ClashConfig: config, Enabled: true})
	if err != nil {
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
	if err := reopened.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x65}, 32)); err == nil || !strings.Contains(err.Error(), "解密") {
		t.Fatalf("wrong-key startup err=%v", err)
	}
}

func TestWireGuardWrongKeyDoesNotPartiallyMigrateMixedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard-mixed-wrong-key.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	configureTestNodeSecretEncryption(t, repo, 0x68)
	config := testWireGuardNodeConfig("Encrypted WG")
	created, err := repo.CreateNode(context.Background(), Node{
		Username: "admin", NodeName: "Encrypted WG", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var originalCiphertext string
	if err := repo.db.QueryRow(`SELECT ciphertext FROM node_secrets WHERE node_id = ?`, created.ID).Scan(&originalCiphertext); err != nil {
		t.Fatal(err)
	}
	legacyConfig := testWireGuardNodeConfig("Legacy WG")
	result, err := repo.db.Exec(`INSERT INTO nodes(username, raw_url, node_name, protocol, parsed_config, clash_config, enabled) VALUES(?, '', ?, 'wireguard', ?, ?, 1)`,
		"admin", "Legacy WG", legacyConfig, legacyConfig)
	if err != nil {
		t.Fatal(err)
	}
	legacyID, _ := result.LastInsertId()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x69}, 32)); err == nil || !strings.Contains(err.Error(), "解密") {
		t.Fatalf("mixed wrong-key startup err=%v", err)
	}
	var storedLegacy, storedCiphertext string
	if err := reopened.db.QueryRow(`SELECT clash_config FROM nodes WHERE id = ?`, legacyID).Scan(&storedLegacy); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(storedLegacy, testWireGuardPrivateKey) {
		t.Fatal("legacy plaintext was mutated before existing ciphertext validation")
	}
	if err := reopened.db.QueryRow(`SELECT ciphertext FROM node_secrets WHERE node_id = ?`, created.ID).Scan(&storedCiphertext); err != nil {
		t.Fatal(err)
	}
	if storedCiphertext != originalCiphertext {
		t.Fatal("existing ciphertext changed during rejected initialization")
	}
	var legacySecretCount int
	if err := reopened.db.QueryRow(`SELECT COUNT(1) FROM node_secrets WHERE node_id = ?`, legacyID).Scan(&legacySecretCount); err != nil || legacySecretCount != 0 {
		t.Fatalf("legacy secret count=%d err=%v, want no partial migration", legacySecretCount, err)
	}
}

func TestWireGuardEncryptionInitializationRejectsCorruptCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard-corrupt.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x76}, 32)
	if err := repo.ConfigureNodeSecretEncryption(key); err != nil {
		t.Fatal(err)
	}
	config := testWireGuardNodeConfig("WG")
	created, err := repo.CreateNode(context.Background(), Node{Username: "admin", NodeName: "WG", Protocol: "wireguard", ParsedConfig: config, ClashConfig: config, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`UPDATE node_secrets SET ciphertext = 'v1:corrupt' WHERE node_id = ?`, created.ID); err != nil {
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
	if err := reopened.ConfigureNodeSecretEncryption(key); err == nil {
		t.Fatal("corrupt ciphertext was accepted during initialization")
	}
}

func TestWireGuardEncryptionInitializationRejectsMissingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard-missing-secret.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	config := testWireGuardPublicNodeConfig("WG")
	result, err := repo.db.Exec(`INSERT INTO nodes(username, raw_url, node_name, protocol, parsed_config, clash_config, enabled) VALUES(?, '', ?, 'wireguard', ?, ?, 1)`,
		"admin", "WG", config, config)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := result.LastInsertId(); id <= 0 {
		t.Fatal("missing-secret fixture was not inserted")
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x77}, 32)); err == nil || !strings.Contains(err.Error(), "缺少有效") {
		t.Fatalf("missing secret startup err=%v", err)
	}
}
