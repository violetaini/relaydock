package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacySessionsAreRevokedAcrossUpgradeAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-epoch.db")
	ctx := context.Background()
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "alice", "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `DROP TABLE sessions;
		CREATE TABLE sessions (
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO sessions
		(token, username, expires_at) VALUES ('legacy-before-upgrade', 'alice', ?)`, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("sessions after upgrade = %#v", sessions)
	}
	if err := repo.CreateSession(ctx, "current", "alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err = repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Token != "current" {
		t.Fatalf("current sessions after restart = %#v", sessions)
	}

	// An older binary does not name auth_epoch, so the defensive default must
	// keep its newly issued session outside the current trust epoch.
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO sessions
		(token, username, expires_at) VALUES ('legacy-after-rollback', 'alice', ?)`, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	sessions, err = repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Token != "current" {
		t.Fatalf("sessions after rollback and re-upgrade = %#v", sessions)
	}
	var legacyCount int
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE auth_epoch < ?`, currentAuthSessionEpoch).Scan(&legacyCount); err != nil {
		t.Fatal(err)
	}
	if legacyCount != 0 {
		t.Fatalf("legacy sessions remaining = %d", legacyCount)
	}
}
