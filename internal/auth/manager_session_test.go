package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordResetCannotLeaveConcurrentOldPasswordSession(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	oldHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(context.Background(), "alice", "", "", string(oldHash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}

	authenticated := make(chan struct{})
	allowIssue := make(chan struct{})
	loginDone := make(chan error, 1)
	go func() {
		_, loginErr := manager.AuthenticateAndRun(context.Background(), "alice", "old-password", func(storage.User) error {
			close(authenticated)
			<-allowIssue
			return repo.CreateSession(context.Background(), "old-password-session", "alice", time.Now().Add(time.Hour))
		})
		loginDone <- loginErr
	}()
	<-authenticated

	newHash, err := bcrypt.GenerateFromPassword([]byte("new-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	resetDone := make(chan error, 1)
	go func() {
		resetDone <- manager.ResetPasswordAndRun(context.Background(), "alice", string(newHash), nil)
	}()

	close(allowIssue)
	if err := <-loginDone; err != nil {
		t.Fatalf("concurrent login: %v", err)
	}
	if err := <-resetDone; err != nil {
		t.Fatalf("password reset: %v", err)
	}

	sessions, err := repo.LoadSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("old-password session survived reset: %#v", sessions)
	}
}

func TestDisableSerializesWithAuthenticatedSessionIssuance(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "disable-race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(context.Background(), "alice", "", "", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}

	authenticated := make(chan struct{})
	allowIssue := make(chan struct{})
	loginDone := make(chan error, 1)
	go func() {
		_, loginErr := manager.AuthenticateAndRun(context.Background(), "alice", "password", func(storage.User) error {
			close(authenticated)
			<-allowIssue
			return repo.CreateSession(context.Background(), "racing-session", "alice", time.Now().Add(time.Hour))
		})
		loginDone <- loginErr
	}()
	<-authenticated
	disableDone := make(chan error, 1)
	go func() { disableDone <- repo.DisableUserAndDeleteSessions(context.Background(), "alice") }()
	select {
	case err := <-disableDone:
		t.Fatalf("disable bypassed authenticated issuance critical section: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(allowIssue)
	if err := <-loginDone; err != nil {
		t.Fatal(err)
	}
	if err := <-disableDone; err != nil {
		t.Fatal(err)
	}
	sessions, err := repo.LoadSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("session survived serialized disable: %#v", sessions)
	}
}

func TestDeletionSerializesSessionIssuanceAndSameNameRecreation(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "delete-race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(context.Background(), "alice", "", "", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	tokens := NewTokenStore(time.Hour)
	repo.SetSessionRevoker(tokens.RevokeAllForUser)

	authenticated := make(chan struct{})
	allowIssue := make(chan struct{})
	issuedToken := make(chan string, 1)
	loginDone := make(chan error, 1)
	go func() {
		_, loginErr := manager.AuthenticateAndRun(context.Background(), "alice", "password", func(storage.User) error {
			close(authenticated)
			<-allowIssue
			token, expiry, issueErr := tokens.Issue("alice")
			if issueErr != nil {
				return issueErr
			}
			issuedToken <- token
			return repo.CreateSession(context.Background(), token, "alice", expiry)
		})
		loginDone <- loginErr
	}()
	<-authenticated

	deleteDone := make(chan error, 1)
	go func() {
		_, deleteErr := repo.PrepareUserDeletion(context.Background(), "alice", "admin")
		deleteDone <- deleteErr
	}()
	select {
	case err := <-deleteDone:
		t.Fatalf("deletion bypassed authenticated issuance critical section: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(allowIssue)
	if err := <-loginDone; err != nil {
		t.Fatal(err)
	}
	token := <-issuedToken
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if _, ok := tokens.Lookup(token); ok {
		t.Fatal("session issued before deletion commit remained in memory")
	}
	if err := repo.FinalizeUserDeletion(context.Background(), "alice", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(context.Background(), "alice", "", "", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := tokens.Lookup(token); ok {
		t.Fatal("same-name account recreation revived deleted account session")
	}
	sessions, err := repo.LoadSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("deleted account sessions survived recreation: %#v", sessions)
	}
}

func TestRenameSessionMigrationSerializesWithDisable(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "rename-disable-race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	tokens := NewTokenStore(time.Hour)
	repo.SetSessionRevoker(tokens.RevokeAllForUser)
	token, expiry, err := tokens.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, token, "alice", expiry); err != nil {
		t.Fatal(err)
	}

	callbackEntered := make(chan struct{})
	allowCallback := make(chan struct{})
	renameDone := make(chan error, 1)
	go func() {
		renameDone <- repo.RenameUserAndRun(ctx, "alice", "renamed", func() {
			tokens.UpdateUsername("alice", "renamed")
			close(callbackEntered)
			<-allowCallback
		})
	}()
	select {
	case <-callbackEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("rename callback was not reached")
	}
	if username, ok := tokens.Lookup(token); !ok || username != "renamed" {
		t.Fatalf("token was not migrated inside rename callback: username=%q ok=%v", username, ok)
	}

	disableDone := make(chan error, 1)
	go func() {
		disableDone <- repo.DisableUserAndDeleteSessions(ctx, "renamed")
	}()
	select {
	case err := <-disableDone:
		t.Fatalf("disable bypassed rename callback critical section: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(allowCallback)
	if err := <-renameDone; err != nil {
		t.Fatal(err)
	}
	if err := <-disableDone; err != nil {
		t.Fatal(err)
	}
	if _, ok := tokens.Lookup(token); ok {
		t.Fatal("migrated token survived account disable")
	}
	if err := repo.UpdateUserStatus(ctx, "renamed", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := tokens.Lookup(token); ok {
		t.Fatal("reenabling renamed account revived revoked token")
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("persisted session survived disable: %#v", sessions)
	}
}

func TestRenameSessionMigrationSerializesWithDeletion(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "rename-delete-race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	tokens := NewTokenStore(time.Hour)
	repo.SetSessionRevoker(tokens.RevokeAllForUser)
	token, expiry, err := tokens.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, token, "alice", expiry); err != nil {
		t.Fatal(err)
	}

	callbackEntered := make(chan struct{})
	allowCallback := make(chan struct{})
	renameDone := make(chan error, 1)
	go func() {
		renameDone <- repo.RenameUserAndRun(ctx, "alice", "renamed", func() {
			tokens.UpdateUsername("alice", "renamed")
			close(callbackEntered)
			<-allowCallback
		})
	}()
	select {
	case <-callbackEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("rename callback was not reached")
	}
	if username, ok := tokens.Lookup(token); !ok || username != "renamed" {
		t.Fatalf("token was not migrated inside rename callback: username=%q ok=%v", username, ok)
	}

	deleteDone := make(chan error, 1)
	go func() {
		_, deleteErr := repo.PrepareUserDeletion(ctx, "renamed", "admin")
		if deleteErr == nil {
			deleteErr = repo.FinalizeUserDeletion(ctx, "renamed", "admin")
		}
		deleteDone <- deleteErr
	}()
	select {
	case err := <-deleteDone:
		t.Fatalf("deletion bypassed rename callback critical section: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(allowCallback)
	if err := <-renameDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if _, ok := tokens.Lookup(token); ok {
		t.Fatal("migrated token survived account deletion")
	}
	if err := repo.CreateUser(ctx, "renamed", "", "", "new-hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := tokens.Lookup(token); ok {
		t.Fatal("same-name account recreation revived deleted account token")
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("deleted account sessions survived recreation: %#v", sessions)
	}
}

func TestPasswordChangeRevokesPendingTwoFactorChallenge(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(context.Background(), "alice", "", "", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	pending := NewTwoFactorPendingStore(time.Minute)
	challenge, err := pending.Issue("alice", false)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.ChangePasswordAndRun(context.Background(), "alice", "old-password", "new-password", func() {
		pending.RevokeUser("alice")
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := pending.Acquire(challenge); ok {
		t.Fatal("password change did not revoke pending 2FA challenge")
	}
}
