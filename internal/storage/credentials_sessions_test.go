package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestReservedGlobalAPITokenUsernameCannotBeCreatedOrRenamed(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "reserved.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, ReservedGlobalAPITokenUsername, "", "", "hash", RoleUser, ""); !errors.Is(err, ErrReservedUsername) {
		t.Fatalf("create reserved username error=%v", err)
	}
	if err := repo.RenameUser(ctx, "alice", "API-TOKEN-ADMIN"); !errors.Is(err, ErrReservedUsername) {
		t.Fatalf("rename to reserved username error=%v", err)
	}
	if _, err := repo.GetUser(ctx, "alice"); err != nil {
		t.Fatalf("failed reserved rename changed source user: %v", err)
	}
}

func TestSaveUserInboundConfigRejectsConflictingCredentialOrProtocol(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "inbound-conflict.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	base := UserInboundConfig{
		Username: "alice", ServerID: 7, InboundTag: "shared-in", Protocol: "vless",
		CredentialJSON: `{"email":"alice__shared-in","id":"stable-id"}`,
	}
	if err := repo.SaveUserInboundConfig(ctx, base); err != nil {
		t.Fatalf("save base credential: %v", err)
	}

	equivalent := base
	equivalent.Protocol = " VLESS "
	equivalent.CredentialJSON = `{"id":"stable-id", "email":"alice__shared-in"}`
	if err := repo.SaveUserInboundConfig(ctx, equivalent); err != nil {
		t.Fatalf("equivalent retry was not idempotent: %v", err)
	}

	differentCredential := base
	differentCredential.CredentialJSON = `{"email":"alice__shared-in","id":"untracked-id"}`
	if err := repo.SaveUserInboundConfig(ctx, differentCredential); !errors.Is(err, ErrUserInboundConfigConflict) {
		t.Fatalf("different credential error=%v, want %v", err, ErrUserInboundConfigConflict)
	}

	differentProtocol := base
	differentProtocol.Protocol = "trojan"
	if err := repo.SaveUserInboundConfig(ctx, differentProtocol); !errors.Is(err, ErrUserInboundConfigConflict) {
		t.Fatalf("different protocol error=%v, want %v", err, ErrUserInboundConfigConflict)
	}

	stored, err := repo.GetUserInboundConfig(ctx, base.Username, base.ServerID, base.InboundTag)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Protocol != base.Protocol || stored.CredentialJSON != base.CredentialJSON {
		t.Fatalf("conflicting writes changed authoritative credential: %+v", stored)
	}
}

func TestRenameUserRejectsRemoteBoundAccounts(t *testing.T) {
	tests := []struct {
		name  string
		setup func(context.Context, *TrafficRepository) error
	}{
		{
			name: "inbound credential",
			setup: func(ctx context.Context, repo *TrafficRepository) error {
				return repo.SaveUserInboundConfig(ctx, UserInboundConfig{
					Username: "alice", ServerID: 1, InboundTag: "vless-in", Protocol: "vless",
					CredentialJSON: `{"id":"uuid","email":"alice__vless-in"}`,
				})
			},
		},
		{
			name: "user outbound",
			setup: func(ctx context.Context, repo *TrafficRepository) error {
				return repo.SaveUserOutbound(ctx, UserOutbound{
					Username: "alice", ServerID: 1, InboundTag: "vless-in",
					OutboundTag: "user_alice_direct", OutboundJSON: `{"tag":"user_alice_direct"}`,
				})
			},
		},
		{
			name: "routed subaccount",
			setup: func(ctx context.Context, repo *TrafficRepository) error {
				_, err := repo.db.ExecContext(ctx, `INSERT INTO user_subaccounts
					(username, routed_node_id, email, credential_json) VALUES (?, 1, ?, ?)`,
					"alice", "alice__routed", `{"id":"uuid","email":"alice__routed"}`)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "remote-bound.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Close()
			ctx := context.Background()
			if err := repo.CreateUser(ctx, "alice", "", "", "hash", RoleUser, ""); err != nil {
				t.Fatal(err)
			}
			if err := test.setup(ctx, repo); err != nil {
				t.Fatal(err)
			}

			if err := repo.RenameUser(ctx, "alice", "renamed"); !errors.Is(err, ErrUsernameRenameRequiresCredentialMigration) {
				t.Fatalf("rename remote-bound account error=%v", err)
			}
			if _, err := repo.GetUser(ctx, "alice"); err != nil {
				t.Fatalf("source account changed after rejected rename: %v", err)
			}
			if _, err := repo.GetUser(ctx, "renamed"); !errors.Is(err, ErrUserNotFound) {
				t.Fatalf("target account exists after rejected rename: %v", err)
			}
		})
	}
}

func TestPasswordOnlyCredentialUpdateWorksWithRemoteBindings(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "remote-bound-password.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "old-hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: "alice", ServerID: 1, InboundTag: "vless-in", Protocol: "vless",
		CredentialJSON: `{"id":"uuid","email":"alice__vless-in"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, "old-token", "alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	updated, err := repo.UpdateCredentialsAndDeleteSessions(ctx, "alice", "", "new-hash")
	if err != nil {
		t.Fatal(err)
	}
	if updated != "alice" {
		t.Fatalf("updated username=%q", updated)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != "new-hash" {
		t.Fatalf("password hash=%q", user.PasswordHash)
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("sessions survived password update: %#v", sessions)
	}
}

func TestRemoteBoundCredentialRenameDoesNotPartiallyUpdatePasswordOrSessions(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "remote-bound-atomic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "old-hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: "alice", ServerID: 1, InboundTag: "vless-in", Protocol: "vless",
		CredentialJSON: `{"id":"uuid","email":"alice__vless-in"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, "old-token", "alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.UpdateCredentialsAndDeleteSessions(ctx, "alice", "renamed", "new-hash"); !errors.Is(err, ErrUsernameRenameRequiresCredentialMigration) {
		t.Fatalf("remote-bound credential rename error=%v", err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != "old-hash" {
		t.Fatalf("rejected rename changed password hash=%q", user.PasswordHash)
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Token != "old-token" {
		t.Fatalf("rejected rename changed sessions: %#v", sessions)
	}
}

func TestUpdateCredentialsAndDeleteSessionsIsAtomic(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "credentials.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "old-hash", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "bob", "", "", "bob-hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, "old-token", "alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.ensureRuleTemplateOwnersTable(ctx); err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name  string
		query string
		args  []any
	}{
		{"settings", `INSERT INTO user_settings (username) VALUES (?)`, []any{"alice"}},
		{"api token", `INSERT INTO user_api_tokens (username, name, token_hash) VALUES (?, 'cli', 'hash')`, []any{"alice"}},
		{"subscription owner", `INSERT INTO subscribe_files (name, url, type, filename, created_by) VALUES ('owned', 'https://example.test', 'create', 'owned.yaml', ?)`, []any{"alice"}},
		{"invite owner and binding", `INSERT INTO invite_codes (code, kind, bind_username, created_by) VALUES ('invite', 'bind', ?, ?)`, []any{"alice", "alice"}},
		{"template owner", `INSERT INTO rule_template_owners (filename, created_by) VALUES ('owned.tpl', ?)`, []any{"alice"}},
		{"billable traffic", `INSERT INTO user_email_traffic (server_id, email, billable_username) VALUES (1, 'client@example.test', ?)`, []any{"alice"}},
	}
	for _, fixture := range fixtures {
		if _, err := repo.db.ExecContext(ctx, fixture.query, fixture.args...); err != nil {
			t.Fatalf("insert %s: %v", fixture.name, err)
		}
	}

	if _, err := repo.UpdateCredentialsAndDeleteSessions(ctx, "alice", "bob", "new-hash"); err == nil {
		t.Fatal("duplicate rename unexpectedly succeeded")
	}
	alice, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if alice.PasswordHash != "old-hash" {
		t.Fatalf("failed transaction changed password: %q", alice.PasswordHash)
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Token != "old-token" {
		t.Fatalf("failed transaction changed sessions: %#v", sessions)
	}

	updated, err := repo.UpdateCredentialsAndDeleteSessions(ctx, "alice", "charlie", "new-hash")
	if err != nil {
		t.Fatal(err)
	}
	if updated != "charlie" {
		t.Fatalf("updated username = %q", updated)
	}
	charlie, err := repo.GetUser(ctx, "charlie")
	if err != nil {
		t.Fatal(err)
	}
	if charlie.PasswordHash != "new-hash" {
		t.Fatalf("password hash = %q", charlie.PasswordHash)
	}
	sessions, err = repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("old sessions remained: %#v", sessions)
	}
	checks := []struct {
		name  string
		query string
		want  int
	}{
		{"settings", `SELECT COUNT(*) FROM user_settings WHERE username = 'charlie'`, 1},
		{"api token", `SELECT COUNT(*) FROM user_api_tokens WHERE username = 'charlie'`, 1},
		{"subscription owner", `SELECT COUNT(*) FROM subscribe_files WHERE created_by = 'charlie'`, 1},
		{"invite owner and binding", `SELECT COUNT(*) FROM invite_codes WHERE created_by = 'charlie' AND bind_username = 'charlie'`, 1},
		{"template owner", `SELECT COUNT(*) FROM rule_template_owners WHERE created_by = 'charlie'`, 1},
		{"billable traffic", `SELECT COUNT(*) FROM user_email_traffic WHERE billable_username = 'charlie'`, 1},
	}
	for _, check := range checks {
		var got int
		if err := repo.db.QueryRowContext(ctx, check.query).Scan(&got); err != nil {
			t.Fatalf("check %s: %v", check.name, err)
		}
		if got != check.want {
			t.Fatalf("%s rows = %d, want %d", check.name, got, check.want)
		}
	}
}

func TestRenameUserPreservesSessionsAndOwnership(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "rename.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, "session", "alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO user_settings (username) VALUES ('alice')`); err != nil {
		t.Fatal(err)
	}

	if err := repo.RenameUser(ctx, "alice", "renamed"); err != nil {
		t.Fatal(err)
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Username != "renamed" {
		t.Fatalf("renamed sessions = %#v", sessions)
	}
	if _, err := repo.GetUser(ctx, "renamed"); err != nil {
		t.Fatal(err)
	}
	var settings int
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_settings WHERE username = 'renamed'`).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	if settings != 1 {
		t.Fatalf("renamed settings rows = %d", settings)
	}
}

func TestUpdateUserPasswordAndDeleteSessions(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "password.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "old-hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, "old-token", "alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateUserPasswordAndDeleteSessions(ctx, "alice", "new-hash"); err != nil {
		t.Fatal(err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != "new-hash" {
		t.Fatalf("password hash = %q", user.PasswordHash)
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("old sessions remained: %#v", sessions)
	}
}
