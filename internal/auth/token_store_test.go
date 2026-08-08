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

func TestRequireAdminDoesNotTrustReservedUsername(t *testing.T) {
	store := NewTokenStore(time.Hour)
	token, _, err := store.Issue(GlobalAPITokenSubject)
	if err != nil {
		t.Fatal(err)
	}
	repo := &middlewareTestRepository{users: map[string]User{
		GlobalAPITokenSubject: {Username: GlobalAPITokenSubject, Role: RoleUser, IsActive: true},
	}}
	handler := RequireAdmin(store, repo, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("reserved username forged global API authorization")
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(AuthHeader, token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", response.Code, http.StatusForbidden)
	}
}

func TestRequireAdminAcceptsGlobalAPITokenMarker(t *testing.T) {
	store := NewTokenStore(time.Hour)
	repo := &middlewareTestRepository{users: map[string]User{}, globalToken: "global-secret"}
	handler := RequireAdmin(store, repo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsGlobalAPIToken(r.Context()) {
			t.Fatal("global API token source marker missing")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(AuthHeader, "global-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d want=%d", response.Code, http.StatusNoContent)
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

func TestServiceSessionHasIndependentRevocationLifecycle(t *testing.T) {
	store := NewTokenStore(time.Hour)
	login, _, err := store.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	service, _, err := store.IssueServiceWithTTL("admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	store.RevokeUser("admin")
	if _, ok := store.Lookup(login); ok {
		t.Fatal("interactive session survived password-session revocation")
	}
	if username, ok := store.Lookup(service); !ok || username != "admin" {
		t.Fatalf("service session was revoked: username=%q valid=%v", username, ok)
	}

	store.RevokeAllForUser("admin")
	if _, ok := store.Lookup(service); ok {
		t.Fatal("service session survived account lifecycle revocation")
	}
}

func TestRequireTokenIgnoresQuerySessionToken(t *testing.T) {
	store := NewTokenStore(time.Hour)
	token, _, err := store.Issue("active")
	if err != nil {
		t.Fatal(err)
	}
	repo := &middlewareTestRepository{users: map[string]User{
		"active": {Username: "active", Role: RoleUser, IsActive: true},
	}}
	handler := RequireToken(store, repo, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("query token reached protected handler")
	}))
	request := httptest.NewRequest(http.MethodGet, "/?token="+token, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=%d", response.Code, http.StatusUnauthorized)
	}
}

func TestWebSocketTicketIsOneTimeCredential(t *testing.T) {
	store := NewTokenStore(time.Hour)
	sessionToken, _, err := store.Issue("active")
	if err != nil {
		t.Fatal(err)
	}
	repo := &middlewareTestRepository{users: map[string]User{
		"active": {Username: "active", Role: RoleUser, IsActive: true},
	}}
	ticket, _, err := store.IssueWebSocketTicket("active", sessionToken, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	handler := RequireWebSocketTicket(store, repo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if got := UsernameFromContext(r.Context()); got != "active" {
			t.Fatalf("username = %q", got)
		}
		if got := SessionTokenFromContext(r.Context()); got != sessionToken {
			t.Fatalf("session token = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	for attempt, want := range []int{http.StatusNoContent, http.StatusUnauthorized} {
		request := httptest.NewRequest(http.MethodGet, "/?ticket="+ticket, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("attempt %d status=%d want=%d", attempt+1, response.Code, want)
		}
	}
	if called != 1 {
		t.Fatalf("protected handler called %d times", called)
	}
}

func TestWebSocketTicketRequiresAndTracksActiveSession(t *testing.T) {
	store := NewTokenStore(time.Hour)
	sessionToken, _, err := store.Issue("active")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.IssueWebSocketTicket("active", "not-a-session", time.Minute); err == nil {
		t.Fatal("ticket was issued for an invalid session")
	}
	ticket, _, err := store.IssueWebSocketTicket("active", sessionToken, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store.Revoke(sessionToken)
	if _, _, ok := store.ConsumeWebSocketTicket(ticket); ok {
		t.Fatal("ticket survived parent session revocation")
	}
}

func TestWebSocketTicketsAreBoundedPerUser(t *testing.T) {
	store := NewTokenStore(time.Hour)
	sessionToken, _, err := store.Issue("active")
	if err != nil {
		t.Fatal(err)
	}
	tickets := make([]string, 0, maxWebSocketTicketsPerUser+1)
	for i := 0; i < maxWebSocketTicketsPerUser+1; i++ {
		ticket, _, issueErr := store.IssueWebSocketTicket("active", sessionToken, time.Minute)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		tickets = append(tickets, ticket)
	}
	if _, _, ok := store.ConsumeWebSocketTicket(tickets[0]); ok {
		t.Fatal("oldest ticket was not evicted")
	}
	if _, _, ok := store.ConsumeWebSocketTicket(tickets[len(tickets)-1]); !ok {
		t.Fatal("newest ticket was unexpectedly evicted")
	}
}
