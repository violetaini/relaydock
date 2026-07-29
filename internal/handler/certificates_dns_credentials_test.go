package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type dnsCredentialsTestFixture struct {
	repo     *storage.TrafficRepository
	handler  *CertificateHandler
	provider *storage.DNSProvider
}

func newDNSCredentialsTestFixture(t *testing.T) dnsCredentialsTestFixture {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "dns-credentials.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	provider := &storage.DNSProvider{
		Name:         "Cloudflare",
		ProviderType: "cloudflare",
		Credentials:  `{"CF_DNS_API_TOKEN":"top-secret-token"}`,
	}
	if err := repo.CreateDNSProvider(context.Background(), provider); err != nil {
		t.Fatalf("CreateDNSProvider: %v", err)
	}
	return dnsCredentialsTestFixture{
		repo:     repo,
		handler:  NewCertificateHandler(repo, nil),
		provider: provider,
	}
}

func adminDNSCredentialsRequest(method, path string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	return request.WithContext(auth.ContextWithUsername(request.Context(), "api-token-admin"))
}

func assertDNSCredentialsNoStore(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
	if got := response.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma=%q, want no-cache", got)
	}
}

func TestRevealDNSProviderCredentialsReturnsSecretOnlyToAdmin(t *testing.T) {
	fixture := newDNSCredentialsTestFixture(t)
	path := "/api/admin/dns-providers/" + strconv.FormatInt(fixture.provider.ID, 10) + "/credentials"
	response := httptest.NewRecorder()
	fixture.handler.RevealDNSProviderCredentials(response, adminDNSCredentialsRequest(http.MethodGet, path))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	assertDNSCredentialsNoStore(t, response)
	var result struct {
		Success     bool              `json:"success"`
		Credentials map[string]string `json:"credentials"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !result.Success || result.Credentials["CF_DNS_API_TOKEN"] != "top-secret-token" {
		t.Fatalf("unexpected reveal response: %#v", result)
	}
}

func TestRevealDNSProviderCredentialsRejectsUnauthenticatedAndNonAdmin(t *testing.T) {
	fixture := newDNSCredentialsTestFixture(t)
	if err := fixture.repo.CreateUser(context.Background(), "viewer", "", "Viewer", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	path := "/api/admin/dns-providers/" + strconv.FormatInt(fixture.provider.ID, 10) + "/credentials"
	tests := []struct {
		name    string
		request *http.Request
	}{
		{name: "unauthenticated", request: httptest.NewRequest(http.MethodGet, path, nil)},
		{name: "non-admin", request: httptest.NewRequest(http.MethodGet, path, nil)},
	}
	tests[1].request = tests[1].request.WithContext(auth.ContextWithUsername(tests[1].request.Context(), "viewer"))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			fixture.handler.RevealDNSProviderCredentials(response, test.request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			assertDNSCredentialsNoStore(t, response)
			if strings.Contains(response.Body.String(), "top-secret-token") {
				t.Fatalf("forbidden response leaked credentials: %s", response.Body.String())
			}
		})
	}
}

func TestRevealDNSProviderCredentialsNotFoundIsNotCacheable(t *testing.T) {
	fixture := newDNSCredentialsTestFixture(t)
	response := httptest.NewRecorder()
	fixture.handler.RevealDNSProviderCredentials(response, adminDNSCredentialsRequest(
		http.MethodGet,
		"/api/admin/dns-providers/999999/credentials",
	))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	assertDNSCredentialsNoStore(t, response)
}

func TestListDNSProvidersDoesNotLeakRevealCredentials(t *testing.T) {
	fixture := newDNSCredentialsTestFixture(t)
	response := httptest.NewRecorder()
	request := adminDNSCredentialsRequest(http.MethodGet, "/api/admin/dns-providers")
	fixture.handler.ListDNSProviders(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "top-secret-token") {
		t.Fatalf("list response leaked secret: %s", response.Body.String())
	}
	var result struct {
		Providers []map[string]any `json:"providers"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(result.Providers) != 1 {
		t.Fatalf("providers=%d, want 1", len(result.Providers))
	}
	if _, exposed := result.Providers[0]["credentials"]; exposed {
		t.Fatalf("list response exposed credentials field: %#v", result.Providers[0])
	}
}
