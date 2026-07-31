package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type middlewareTestRepository struct {
	users       map[string]User
	apiTokens   map[string]string
	globalToken string
}

func (r *middlewareTestRepository) GetUser(_ context.Context, username string) (User, error) {
	user, ok := r.users[username]
	if !ok {
		return User{}, context.Canceled
	}
	return user, nil
}

func (r *middlewareTestRepository) GetAPIToken(context.Context) (string, error) {
	return r.globalToken, nil
}

func (r *middlewareTestRepository) ResolveAPIToken(_ context.Context, token string) (string, bool) {
	username, ok := r.apiTokens[token]
	return username, ok
}

func TestRequireTokenRejectsInactiveSessionAndAPIToken(t *testing.T) {
	store := NewTokenStore(time.Hour)
	repo := &middlewareTestRepository{
		users: map[string]User{
			"active":   {Username: "active", Role: RoleUser, IsActive: true},
			"disabled": {Username: "disabled", Role: RoleUser, IsActive: false},
		},
		apiTokens: map[string]string{"disabled-api": "disabled"},
	}
	disabledSession, _, err := store.Issue("disabled")
	if err != nil {
		t.Fatal(err)
	}
	activeSession, _, err := store.Issue("active")
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UsernameFromContext(r.Context()) == "" {
			t.Fatal("authenticated username missing from context")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RequireToken(store, repo, next)

	for name, token := range map[string]string{"session": disabledSession, "api": "disabled-api"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set(AuthHeader, token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d want=%d", response.Code, http.StatusForbidden)
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(AuthHeader, activeSession)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("active status=%d want=%d", response.Code, http.StatusNoContent)
	}
}

func TestRequireAdminRejectsInactiveAdministrator(t *testing.T) {
	store := NewTokenStore(time.Hour)
	token, _, err := store.Issue("disabled-admin")
	if err != nil {
		t.Fatal(err)
	}
	repo := &middlewareTestRepository{users: map[string]User{
		"disabled-admin": {Username: "disabled-admin", Role: RoleAdmin, IsActive: false},
	}}
	handler := RequireAdmin(store, repo, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("inactive administrator reached protected handler")
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(AuthHeader, token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", response.Code, http.StatusForbidden)
	}
}

func TestTokenStoreRevokeUserOnlyRemovesTargetSessions(t *testing.T) {
	store := NewTokenStore(time.Hour)
	aliceOne, _, err := store.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	aliceTwo, _, err := store.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := store.Issue("bob")
	if err != nil {
		t.Fatal(err)
	}

	store.RevokeUser(" alice ")
	for _, token := range []string{aliceOne, aliceTwo} {
		if _, ok := store.Lookup(token); ok {
			t.Fatal("target user's session remained valid")
		}
	}
	if username, ok := store.Lookup(bob); !ok || username != "bob" {
		t.Fatalf("unrelated session was revoked: username=%q valid=%v", username, ok)
	}
}
