package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestDisablingUserRevokesMemoryAndPersistentSessions(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}

	store := auth.NewTokenStore(time.Hour)
	token, expiry, err := store.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, token, "alice", expiry); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/admin/users/status",
		strings.NewReader(`{"username":"alice","is_active":false}`))
	response := httptest.NewRecorder()
	NewUserStatusHandler(repo, nil, nil, store).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, ok := store.Lookup(token); ok {
		t.Fatal("disabled user's in-memory session remained valid")
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("persistent sessions remain after disable: %#v", sessions)
	}

	// Simulate the process startup restoration loop. A deleted database row
	// must not be able to restore the old token in a new TokenStore.
	restarted := auth.NewTokenStore(time.Hour)
	for _, session := range sessions {
		restarted.LoadSession(session.Token, session.Username, session.ExpiresAt)
	}
	if _, ok := restarted.Lookup(token); ok {
		t.Fatal("disabled user's session was restored after restart")
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.IsActive {
		t.Fatalf("user active=%v err=%v", user.IsActive, err)
	}
}

func TestPreparingUserDeletionImmediatelyRevokesAllSessions(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "delete-sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	store := auth.NewTokenStore(time.Hour)
	login, expiry, err := store.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	service, _, err := store.IssueServiceWithTTL("alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSession(ctx, login, "alice", expiry); err != nil {
		t.Fatal(err)
	}
	// The status handler constructor is part of normal server wiring and
	// connects repository lifecycle commits to the process-local token store.
	_ = NewUserStatusHandler(repo, nil, nil, store)
	if _, err := repo.PrepareUserDeletion(ctx, "alice", "admin"); err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{"login": login, "service": service} {
		if _, ok := store.Lookup(token); ok {
			t.Fatalf("%s session survived deletion preparation", name)
		}
	}
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("persistent sessions survived deletion preparation: %#v", sessions)
	}
}
