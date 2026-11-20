package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestForwardDomainMigrationPreservesExistingBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE node_forward_targets(node_id INTEGER PRIMARY KEY,target_node_id INTEGER NOT NULL,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP); INSERT INTO node_forward_targets(node_id,target_node_id) VALUES(42,41)`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	var target int64
	var host string
	err = repo.db.QueryRowContext(context.Background(), `SELECT target_node_id,target_host FROM node_forward_targets WHERE node_id=42`).Scan(&target, &host)
	if err != nil || target != 41 || host != "" {
		t.Fatalf("legacy binding lost: %d %q %v", target, host, err)
	}
	if _, err = repo.db.Exec(`UPDATE node_forward_targets SET target_host='ddns.example.test' WHERE node_id=42`); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	err = repo.db.QueryRow(`SELECT target_node_id,target_host FROM node_forward_targets WHERE node_id=42`).Scan(&target, &host)
	if err != nil || target != 41 || host != "ddns.example.test" {
		t.Fatal("restart lost explicit domain")
	}
}
