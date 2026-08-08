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

func TestCredentialsRenameMigratesServiceSessionAndRevokesLogin(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "credentials-rename.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.CreateUser(context.Background(), "admin", "", "", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	tokens := auth.NewTokenStore(time.Hour)
	login, _, err := tokens.Issue("admin")
	if err != nil {
		t.Fatal(err)
	}
	service, _, err := tokens.IssueServiceWithTTL("admin", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPut, "/api/admin/credentials",
		strings.NewReader(`{"username":"renamed-admin"}`))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	response := httptest.NewRecorder()
	NewCredentialsHandler(manager, tokens, repo, nil).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if _, ok := tokens.Lookup(login); ok {
		t.Fatal("interactive session survived administrator rename")
	}
	if username, ok := tokens.Lookup(service); !ok || username != "renamed-admin" {
		t.Fatalf("service session username=%q valid=%v", username, ok)
	}
	protected := auth.RequireToken(tokens, auth.NewRepositoryAdapter(repo), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.UsernameFromContext(r.Context()) != "renamed-admin" {
			t.Fatalf("service request username=%q", auth.UsernameFromContext(r.Context()))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	serviceRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	serviceRequest.Header.Set(auth.AuthHeader, service)
	serviceResponse := httptest.NewRecorder()
	protected.ServeHTTP(serviceResponse, serviceRequest)
	if serviceResponse.Code != http.StatusNoContent {
		t.Fatalf("renamed service session status=%d body=%q", serviceResponse.Code, serviceResponse.Body.String())
	}
}

func TestUserIsAdminRequiresRoleOrGlobalTokenSourceMarker(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "admin-source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.CreateUser(context.Background(), "alice", "", "", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	forged := auth.ContextWithUsername(context.Background(), auth.GlobalAPITokenSubject)
	if userIsAdmin(forged, repo, auth.GlobalAPITokenSubject) {
		t.Fatal("reserved username string forged global API token authorization")
	}
	global := auth.ContextWithGlobalAPIToken(context.Background())
	if !userIsAdmin(global, repo, auth.GlobalAPITokenSubject) {
		t.Fatal("authenticated global API token was not recognized as administrator")
	}
}
