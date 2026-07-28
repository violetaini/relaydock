package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

type mmwSecurityTestNode struct {
	id       int64
	name     string
	protocol string
	rawURL   string
	config   string
}

func createMmwSecurityTestSource(t *testing.T, path string, nodes []mmwSecurityTestNode) {
	t.Helper()
	source, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	statements := []string{
		`CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TIMESTAMP NOT NULL)`,
		`INSERT INTO users(username,password_hash,role,created_at) VALUES ('imported-user','hash','user','2026-01-01 00:00:00')`,
		`CREATE TABLE nodes (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			raw_url TEXT NOT NULL,
			node_name TEXT NOT NULL,
			protocol TEXT NOT NULL,
			parsed_config TEXT NOT NULL,
			clash_config TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			tag TEXT NOT NULL DEFAULT 'imported',
			original_server TEXT,
			chain_proxy_node_id INTEGER,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := source.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range nodes {
		if _, err := source.Exec(`INSERT INTO nodes(
			id, username, raw_url, node_name, protocol, parsed_config, clash_config,
			enabled, tag, original_server, chain_proxy_node_id, created_at, updated_at
		) VALUES (?, 'imported-user', ?, ?, ?, ?, ?, 1, 'imported', '', NULL, '2026-01-01 00:00:00', '2026-01-01 00:00:00')`,
			node.id, node.rawURL, node.name, node.protocol, node.config, node.config,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func TestImportFromMmwEncryptsWireGuardNodeInImportTransaction(t *testing.T) {
	root := t.TempDir()
	repo, err := NewTrafficRepository(filepath.Join(root, "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x37)
	config := testWireGuardNodeConfig("Imported WG")
	sourcePath := filepath.Join(root, "source.db")
	createMmwSecurityTestSource(t, sourcePath, []mmwSecurityTestNode{{
		id: 51, name: "Imported WG", protocol: "wireguard",
		rawURL: "wireguard://" + testWireGuardPrivateKey + "@203.0.113.10:51820#wg",
		config: config,
	}})

	report, err := repo.ImportFromMmw(context.Background(), sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if report.Nodes != 1 {
		t.Fatalf("imported nodes=%d, want 1; report=%+v", report.Nodes, report)
	}
	var rawURL, parsedConfig, clashConfig, kind, ciphertext string
	if err := repo.db.QueryRow(`SELECT n.raw_url, n.parsed_config, n.clash_config, ns.kind, ns.ciphertext
		FROM nodes n JOIN node_secrets ns ON ns.node_id = n.id WHERE n.id = 51`).
		Scan(&rawURL, &parsedConfig, &clashConfig, &kind, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if kind != wireGuardPrivateKeySecretKind {
		t.Fatalf("secret kind=%q", kind)
	}
	for field, value := range map[string]string{
		"raw_url": rawURL, "parsed_config": parsedConfig, "clash_config": clashConfig, "ciphertext": ciphertext,
	} {
		if strings.Contains(value, testWireGuardPrivateKey) {
			t.Fatalf("%s retained the imported plaintext private key: %q", field, value)
		}
	}
	hydrated, err := repo.GetNodeByID(context.Background(), 51)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hydrated.ParsedConfig, testWireGuardPrivateKey) || !strings.Contains(hydrated.ClashConfig, testWireGuardPrivateKey) {
		t.Fatalf("imported node was not hydrated for normal use: %+v", hydrated)
	}
}

func TestImportFromMmwRollsBackEveryTableWhenWireGuardProtectionFails(t *testing.T) {
	root := t.TempDir()
	repo, err := NewTrafficRepository(filepath.Join(root, "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	configureTestNodeSecretEncryption(t, repo, 0x48)
	invalidConfig := strings.ReplaceAll(testWireGuardNodeConfig("Invalid WG"), testWireGuardPrivateKey, "not-a-private-key")
	sourcePath := filepath.Join(root, "source.db")
	createMmwSecurityTestSource(t, sourcePath, []mmwSecurityTestNode{
		{id: 61, name: "Imported SS", protocol: "ss", rawURL: "ss://example", config: `{"name":"Imported SS","type":"ss"}`},
		{id: 62, name: "Invalid WG", protocol: "wireguard", config: invalidConfig},
	})

	if _, err := repo.ImportFromMmw(context.Background(), sourcePath); err == nil {
		t.Fatal("MMW import with an invalid WireGuard private key unexpectedly succeeded")
	}
	for _, table := range []string{"users", "nodes", "node_secrets"} {
		var count int
		if err := repo.db.QueryRow(`SELECT COUNT(1) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("failed import left %d row(s) in %s", count, table)
		}
	}
}

func TestImportFromMmwWireGuardFailsClosedWithoutSecretEncryption(t *testing.T) {
	root := t.TempDir()
	repo, err := NewTrafficRepository(filepath.Join(root, "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	sourcePath := filepath.Join(root, "source.db")
	createMmwSecurityTestSource(t, sourcePath, []mmwSecurityTestNode{{
		id: 71, name: "Imported WG", protocol: "wireguard", config: testWireGuardNodeConfig("Imported WG"),
	}})

	if _, err := repo.ImportFromMmw(context.Background(), sourcePath); err == nil || !strings.Contains(err.Error(), "加密尚未初始化") {
		t.Fatalf("MMW import without node-secret encryption err=%v", err)
	}
	var nodes, users int
	if err := repo.db.QueryRow(`SELECT COUNT(1) FROM nodes`).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if nodes != 0 || users != 0 {
		t.Fatalf("failed import was not atomic: nodes=%d users=%d", nodes, users)
	}
}

func TestMmwImportBlockingCountsAllowsOnlyCurrentAdminScaffolding(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "owner", "", "Owner", "hash", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO user_settings(username) VALUES (?)`, "owner"); err != nil {
		t.Fatal(err)
	}
	counts, err := repo.MmwImportBlockingCounts(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 0 {
		t.Fatalf("admin scaffolding was treated as business data: %#v", counts)
	}
	if err := repo.CreateUser(ctx, "existing", "", "Existing", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	counts, err = repo.MmwImportBlockingCounts(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if counts["users"] != 1 {
		t.Fatalf("users blocking count=%d, want 1; all=%#v", counts["users"], counts)
	}
}

func TestImportFromMmwKeepsAuthenticatedAdminAndAssignsOwnership(t *testing.T) {
	root := t.TempDir()
	repo, err := NewTrafficRepository(filepath.Join(root, "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "current-admin", "", "Current", "hash", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE users SET created_at = '2025-01-01 00:00:00' WHERE username = 'current-admin'`); err != nil {
		t.Fatal(err)
	}

	sourcePath := filepath.Join(root, "source.db")
	source, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TIMESTAMP NOT NULL)`,
		`INSERT INTO users(username,password_hash,role,created_at) VALUES ('source-admin','hash','admin','2000-01-01 00:00:00')`,
		`CREATE TABLE templates (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`,
		`INSERT INTO templates(id,name) VALUES (17,'Imported Template')`,
	}
	for _, statement := range statements {
		if _, err := source.Exec(statement); err != nil {
			_ = source.Close()
			t.Fatal(err)
		}
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.ImportFromMmw(ctx, sourcePath, "current-admin"); err != nil {
		t.Fatal(err)
	}
	current, err := repo.GetUser(ctx, "current-admin")
	if err != nil {
		t.Fatal(err)
	}
	if current.Role != RoleAdmin {
		t.Fatalf("current admin role=%q, want admin", current.Role)
	}
	imported, err := repo.GetUser(ctx, "source-admin")
	if err != nil {
		t.Fatal(err)
	}
	if imported.Role != RoleUser {
		t.Fatalf("source admin role=%q, want user", imported.Role)
	}
	var owner string
	if err := repo.db.QueryRowContext(ctx, `SELECT created_by FROM templates WHERE id = 17`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != "current-admin" {
		t.Fatalf("template owner=%q, want current-admin", owner)
	}
}
