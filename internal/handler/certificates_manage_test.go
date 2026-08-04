package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestCertificateHandlerUsesInjectedLocalDeployer(t *testing.T) {
	handler := &CertificateHandler{}
	called := false
	handler.SetLocalDeployer(func(certPEM, keyPEM, certPath, keyPath, reloadTarget string) error {
		called = true
		if certPEM != "certificate" || keyPEM != "private-key" || certPath != "/cert" || keyPath != "/key" || reloadTarget != "xray" {
			return fmt.Errorf("unexpected deployment arguments")
		}
		return nil
	})
	if err := handler.deployLocal("certificate", "private-key", "/cert", "/key", "xray"); err != nil {
		t.Fatalf("deployLocal: %v", err)
	}
	if !called {
		t.Fatal("injected local deployer was not called")
	}
}

func TestAutomaticCertificateReloadTargetNeverRestartsXray(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
		ok    bool
	}{
		{input: "nginx", want: "nginx", ok: true},
		{input: "xray", want: "none", ok: true},
		{input: "both", want: "nginx", ok: true},
		{input: "none", want: "", ok: false},
	} {
		got, ok := automaticCertificateReloadTarget(test.input)
		if got != test.want || ok != test.ok {
			t.Fatalf("automaticCertificateReloadTarget(%q) = (%q, %v), want (%q, %v)", test.input, got, ok, test.want, test.ok)
		}
	}
}

func TestPublicDNSProviderNeverSerializesCredentials(t *testing.T) {
	provider := storage.DNSProvider{
		ID:           7,
		Name:         "Cloudflare",
		ProviderType: "cloudflare",
		Credentials:  `{"CF_DNS_API_TOKEN":"top-secret-token"}`,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	payload, err := json.Marshal(publicDNSProvider(provider))
	if err != nil {
		t.Fatalf("marshal public provider: %v", err)
	}
	text := string(payload)
	if strings.Contains(text, "top-secret-token") || strings.Contains(text, "credentials\"") {
		t.Fatalf("response leaked credentials: %s", text)
	}
	if !strings.Contains(text, `"credentials_configured":true`) {
		t.Fatalf("response should retain non-secret configured state: %s", text)
	}
}

func TestNormalizeDNSProviderCredentialsChoosesCloudflareGlobalMode(t *testing.T) {
	payload, err := normalizeDNSProviderCredentials("cloudflare", `{
		"CF_DNS_API_TOKEN":"stale-token",
		"CF_API_EMAIL":"admin@example.com",
		"CF_API_KEY":"global-key"
	}`)
	if err != nil {
		t.Fatalf("normalizeDNSProviderCredentials: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("unmarshal normalized credentials: %v", err)
	}
	if got["CF_API_EMAIL"] != "admin@example.com" || got["CF_API_KEY"] != "global-key" {
		t.Fatalf("unexpected normalized credentials: %#v", got)
	}
	if _, exists := got["CF_DNS_API_TOKEN"]; exists {
		t.Fatalf("token must be removed from global mode: %#v", got)
	}
}

func TestDNSProviderCredentialsForUpdatePreservesSecretForEmptyObject(t *testing.T) {
	existing := storage.DNSProvider{
		ProviderType: "cloudflare",
		Credentials:  `{"CF_DNS_API_TOKEN":"stored-secret"}`,
	}
	for _, raw := range []string{"", `{}`, `{"CF_DNS_API_TOKEN":" "}`} {
		got, err := dnsProviderCredentialsForUpdate(existing, "cloudflare", raw)
		if err != nil {
			t.Fatalf("raw %q: %v", raw, err)
		}
		if got != existing.Credentials {
			t.Fatalf("raw %q replaced the stored secret: %q", raw, got)
		}
	}
}

func TestDNSProviderCredentialsForUpdateRequiresSecretWhenTypeChanges(t *testing.T) {
	existing := storage.DNSProvider{ProviderType: "cloudflare", Credentials: `{"CF_DNS_API_TOKEN":"stored-secret"}`}
	_, err := dnsProviderCredentialsForUpdate(existing, "alidns", `{}`)
	if err == nil || !strings.Contains(err.Error(), "切换 DNS 提供商") {
		t.Fatalf("expected provider-switch credential error, got %v", err)
	}
}

func TestUpdateDNSProviderPreservesStoredCredentialsForEmptyObject(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "certificates.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	provider := &storage.DNSProvider{
		Name:         "Cloudflare old name",
		ProviderType: "cloudflare",
		Credentials:  `{"CF_DNS_API_TOKEN":"stored-secret"}`,
	}
	if err := repo.CreateDNSProvider(context.Background(), provider); err != nil {
		t.Fatalf("CreateDNSProvider: %v", err)
	}

	handler := NewCertificateHandler(repo, nil)
	body := []byte(`{"name":"Cloudflare new name","provider_type":"cloudflare","credentials":"{}"}`)
	request := httptest.NewRequest(http.MethodPut, "/api/admin/dns-providers/"+strconv.FormatInt(provider.ID, 10), bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "api-token-admin"))
	response := httptest.NewRecorder()
	handler.UpdateDNSProvider(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	updated, err := repo.GetDNSProvider(context.Background(), provider.ID)
	if err != nil {
		t.Fatalf("GetDNSProvider: %v", err)
	}
	if updated.Name != "Cloudflare new name" || updated.Credentials != provider.Credentials {
		t.Fatalf("unexpected updated provider: %#v", updated)
	}
}

func TestUpdateCertificateRejectsIssuedDomainMetadataChange(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "issued-certificate.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	cert := &storage.Certificate{
		Domain:        "issued.example.com",
		Email:         "admin@example.com",
		Provider:      "letsencrypt",
		CertPEM:       "issued-certificate",
		KeyPEM:        "issued-key",
		Status:        storage.CertStatusValid,
		ChallengeMode: storage.CertChallengeStandalone,
		DeployTarget:  "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	body := []byte(`{"domain":"other.example.com","email":"admin@example.com","provider":"letsencrypt","challenge_mode":"standalone","deploy_target":"none"}`)
	request := httptest.NewRequest(http.MethodPut, "/api/admin/certificates/"+strconv.FormatInt(cert.ID, 10), bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "api-token-admin"))
	response := httptest.NewRecorder()
	NewCertificateHandler(repo, nil).GetCertificate(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "不能修改域名") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if stored.Domain != cert.Domain {
		t.Fatalf("issued certificate domain changed to %q", stored.Domain)
	}
}

func TestUpdateFailedCertificateChangesDNSProviderForRetry(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "failed-certificate.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	first := &storage.DNSProvider{Name: "first", ProviderType: "cloudflare", Credentials: `{"CF_DNS_API_TOKEN":"first"}`}
	second := &storage.DNSProvider{Name: "second", ProviderType: "cloudflare", Credentials: `{"CF_DNS_API_TOKEN":"second"}`}
	if err := repo.CreateDNSProvider(context.Background(), first); err != nil {
		t.Fatalf("CreateDNSProvider first: %v", err)
	}
	if err := repo.CreateDNSProvider(context.Background(), second); err != nil {
		t.Fatalf("CreateDNSProvider second: %v", err)
	}
	cert := &storage.Certificate{
		Domain:         "retry.example.com",
		Email:          "admin@example.com",
		Provider:       "letsencrypt",
		Status:         storage.CertStatusFailed,
		ChallengeMode:  storage.CertChallengeDNS,
		DNSProviderID:  first.ID,
		DeployTarget:   "none",
		RemoteServerID: 0,
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	body := []byte(`{"domain":"retry.example.com","email":"admin@example.com","provider":"letsencrypt","challenge_mode":"dns","dns_provider_id":` + strconv.FormatInt(second.ID, 10) + `,"deploy_target":"none","auto_renew":true}`)
	request := httptest.NewRequest(http.MethodPut, "/api/admin/certificates/"+strconv.FormatInt(cert.ID, 10), bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "api-token-admin"))
	response := httptest.NewRecorder()
	NewCertificateHandler(repo, nil).GetCertificate(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if stored.DNSProviderID != second.ID || stored.ChallengeMode != storage.CertChallengeDNS {
		t.Fatalf("retry settings were not saved: %#v", stored)
	}
}

func TestUpdateManualWildcardCertificateDeploymentWithoutEmail(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "manual-certificate.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	cert := &storage.Certificate{
		Domain:        "*.manual.example.com",
		Email:         "api-token-admin@upload",
		Provider:      "manual",
		CertPEM:       "issued-certificate",
		KeyPEM:        "issued-key",
		Status:        storage.CertStatusValid,
		ChallengeMode: "manual",
		DeployTarget:  "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	body := []byte(`{"domain":"*.manual.example.com","email":"","provider":"manual","challenge_mode":"manual","deploy_target":"nginx","deploy_cert_path":"/etc/nginx/manual.pem","deploy_key_path":"/etc/nginx/manual.key","auto_deploy":true}`)
	request := httptest.NewRequest(http.MethodPut, "/api/admin/certificates/"+strconv.FormatInt(cert.ID, 10), bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "api-token-admin"))
	response := httptest.NewRecorder()
	NewCertificateHandler(repo, nil).GetCertificate(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if stored.DeployTarget != "nginx" || stored.DeployCertPath != "/etc/nginx/manual.pem" || !stored.AutoDeploy {
		t.Fatalf("manual deployment settings were not saved: %#v", stored)
	}
}
