package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestGlobalHandlersRejectOrdinaryUsersWithoutRelyingOnRouteMiddleware(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "authorization.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.CreateUser(context.Background(), "alice", "", "", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		handler http.Handler
		method  string
		path    string
		body    []byte
	}{
		{name: "process-wide debug", handler: NewDebugHandler(repo), method: http.MethodGet, path: "/api/user/debug/status"},
		{name: "global short-link reset", handler: NewShortLinkResetHandler(repo), method: http.MethodPost, path: "/api/user/short-link"},
		{name: "template v3", handler: NewTemplateV3Handler(repo), method: http.MethodGet, path: "/api/admin/template-v3"},
		{name: "local xray outbound mutation", handler: http.HandlerFunc(NewXrayHandler(repo).AddOutbound), method: http.MethodPost, path: "/api/xray/outbounds", body: []byte(`{"tag":"blocked","type":"freedom"}`)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, bytes.NewReader(test.body))
			request = request.WithContext(auth.ContextWithUsername(request.Context(), "alice"))
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%q, want 403", response.Code, response.Body.String())
			}
		})
	}
}

func TestSubscribeFileGlobalViewsRejectOrdinaryUsers(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "subscribe-authorization.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.CreateUser(context.Background(), "alice", "", "", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	handler := &subscribeFilesHandler{repo: repo}

	for _, test := range []struct {
		name   string
		invoke func(http.ResponseWriter, *http.Request)
	}{
		{name: "global reorder", invoke: handler.handleReorder},
		{name: "subscription users", invoke: func(w http.ResponseWriter, r *http.Request) { handler.handleGetSubscriptionUsers(w, r, "1") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"ids":[]}`)))
			request = request.WithContext(auth.ContextWithUsername(request.Context(), "alice"))
			response := httptest.NewRecorder()
			test.invoke(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%q, want 403", response.Code, response.Body.String())
			}
		})
	}
}

func TestGlobalHandlersAllowAdministratorPastAuthorization(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "admin-authorization.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.CreateUser(context.Background(), "admin", "", "", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		handler http.Handler
		method  string
		path    string
	}{
		{name: "process-wide debug", handler: NewDebugHandler(repo), method: http.MethodGet, path: "/api/user/debug/status"},
		{name: "global short-link reset", handler: NewShortLinkResetHandler(repo), method: http.MethodPost, path: "/api/user/short-link"},
		{name: "template v3", handler: NewTemplateV3Handler(repo), method: http.MethodGet, path: "/api/admin/template-v3"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)
			if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden {
				t.Fatalf("administrator was rejected: status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}
