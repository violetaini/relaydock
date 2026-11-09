package handler

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestCertificatesMultiTenantIsolation(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "multi_tenant_test.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx := context.Background()
	// Enable certificates page for all normal users in global settings
	if err := repo.SetSystemSetting(ctx, settingUserPeracmPages, `["certificates"]`); err != nil {
		t.Fatalf("SetSystemSetting: %v", err)
	}

	// Create test users: userA, userB
	if err := repo.CreateUser(ctx, "userA", "a@example.com", "User A", "hashA", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser userA: %v", err)
	}
	if err := repo.CreateUser(ctx, "userB", "b@example.com", "User B", "hashB", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser userB: %v", err)
	}

	h := NewCertificateHandler(repo, nil)

	userReq := func(method, path, username string, body any) *http.Request {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		if username == "admin" {
			return req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
		}
		return req.WithContext(auth.ContextWithUsername(req.Context(), username))
	}

	// 1. Create DNS Provider for Admin, User A, and User B
	adminDNS := &storage.DNSProvider{
		Username:     "admin",
		Name:         "admin-cf",
		ProviderType: "cloudflare",
		Credentials:  `{"CF_DNS_API_TOKEN":"admin-secret"}`,
	}
	if err := repo.CreateDNSProvider(ctx, adminDNS); err != nil {
		t.Fatalf("CreateDNSProvider admin: %v", err)
	}

	userADNS := &storage.DNSProvider{
		Username:     "userA",
		Name:         "userA-hw",
		ProviderType: "huaweicloud",
		Credentials:  `{"HUAWEICLOUD_ACCESS_KEY_ID":"ak-a","HUAWEICLOUD_SECRET_ACCESS_KEY":"sk-a"}`,
	}
	if err := repo.CreateDNSProvider(ctx, userADNS); err != nil {
		t.Fatalf("CreateDNSProvider userA: %v", err)
	}

	userBDNS := &storage.DNSProvider{
		Username:     "userB",
		Name:         "userB-cf",
		ProviderType: "cloudflare",
		Credentials:  `{"CF_DNS_API_TOKEN":"b-secret"}`,
	}
	if err := repo.CreateDNSProvider(ctx, userBDNS); err != nil {
		t.Fatalf("CreateDNSProvider userB: %v", err)
	}

	// 2. Create Certificates for Admin, User A, and User B
	now := time.Now().UTC()
	expiry := now.Add(90 * 24 * time.Hour)

	adminCert := &storage.Certificate{
		Username:      "admin",
		Domain:        "admin.example.com",
		Email:         "admin@example.com",
		Provider:      "letsencrypt",
		DNSProviderID: adminDNS.ID,
		Status:        storage.CertStatusValid,
		IssueDate:     &now,
		ExpiryDate:    &expiry,
	}
	if err := repo.CreateCertificate(ctx, adminCert); err != nil {
		t.Fatalf("CreateCertificate admin: %v", err)
	}

	userACert := &storage.Certificate{
		Username:      "userA",
		Domain:        "a.example.com",
		Email:         "usera@example.com",
		Provider:      "letsencrypt",
		DNSProviderID: userADNS.ID,
		Status:        storage.CertStatusValid,
		IssueDate:     &now,
		ExpiryDate:    &expiry,
	}
	if err := repo.CreateCertificate(ctx, userACert); err != nil {
		t.Fatalf("CreateCertificate userA: %v", err)
	}

	userBCert := &storage.Certificate{
		Username:      "userB",
		Domain:        "b.example.com",
		Email:         "userb@example.com",
		Provider:      "letsencrypt",
		DNSProviderID: userBDNS.ID,
		Status:        storage.CertStatusValid,
		IssueDate:     &now,
		ExpiryDate:    &expiry,
	}
	if err := repo.CreateCertificate(ctx, userBCert); err != nil {
		t.Fatalf("CreateCertificate userB: %v", err)
	}

	// 3. Test ListCertificates Multi-Tenant Isolation
	t.Run("ListCertificates Isolation", func(t *testing.T) {
		// Admin
		rec := httptest.NewRecorder()
		h.ListCertificates(rec, userReq(http.MethodGet, "/api/admin/certificates", "admin", nil))
		var adminResp struct {
			Success      bool                  `json:"success"`
			Certificates []storage.Certificate `json:"certificates"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &adminResp)
		if len(adminResp.Certificates) != 1 || adminResp.Certificates[0].Domain != "admin.example.com" {
			t.Fatalf("expected admin only 1 cert, got: %+v", adminResp.Certificates)
		}

		// User A
		rec = httptest.NewRecorder()
		h.ListCertificates(rec, userReq(http.MethodGet, "/api/admin/certificates", "userA", nil))
		var userAResp struct {
			Success      bool                  `json:"success"`
			Certificates []storage.Certificate `json:"certificates"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &userAResp)
		if len(userAResp.Certificates) != 1 || userAResp.Certificates[0].Domain != "a.example.com" {
			t.Fatalf("expected userA only 1 cert, got: %+v", userAResp.Certificates)
		}

		// User B
		rec = httptest.NewRecorder()
		h.ListCertificates(rec, userReq(http.MethodGet, "/api/admin/certificates", "userB", nil))
		var userBResp struct {
			Success      bool                  `json:"success"`
			Certificates []storage.Certificate `json:"certificates"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &userBResp)
		if len(userBResp.Certificates) != 1 || userBResp.Certificates[0].Domain != "b.example.com" {
			t.Fatalf("expected userB only 1 cert, got: %+v", userBResp.Certificates)
		}
	})

	// 4. Test ListDNSProviders Multi-Tenant Isolation
	t.Run("ListDNSProviders Isolation", func(t *testing.T) {
		// Admin
		rec := httptest.NewRecorder()
		h.ListDNSProviders(rec, userReq(http.MethodGet, "/api/admin/dns-providers", "admin", nil))
		var adminResp struct {
			Success   bool                  `json:"success"`
			Providers []storage.DNSProvider `json:"providers"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &adminResp)
		if len(adminResp.Providers) != 1 || adminResp.Providers[0].Name != "admin-cf" {
			t.Fatalf("expected admin only 1 provider, got: %+v", adminResp.Providers)
		}

		// User A
		rec = httptest.NewRecorder()
		h.ListDNSProviders(rec, userReq(http.MethodGet, "/api/admin/dns-providers", "userA", nil))
		var userAResp struct {
			Success   bool                  `json:"success"`
			Providers []storage.DNSProvider `json:"providers"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &userAResp)
		if len(userAResp.Providers) != 1 || userAResp.Providers[0].Name != "userA-hw" {
			t.Fatalf("expected userA only 1 provider, got: %+v", userAResp.Providers)
		}

		// User B
		rec = httptest.NewRecorder()
		h.ListDNSProviders(rec, userReq(http.MethodGet, "/api/admin/dns-providers", "userB", nil))
		var userBResp struct {
			Success   bool                  `json:"success"`
			Providers []storage.DNSProvider `json:"providers"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &userBResp)
		if len(userBResp.Providers) != 1 || userBResp.Providers[0].Name != "userB-cf" {
			t.Fatalf("expected userB only 1 provider, got: %+v", userBResp.Providers)
		}
	})

	// 5. Reveal Credentials: User B cannot reveal User A or Admin credentials
	t.Run("Reveal DNS Credentials Security", func(t *testing.T) {
		// User A reveals User A credentials -> should succeed
		pathA := "/api/admin/dns-providers/" + strconv.FormatInt(userADNS.ID, 10) + "/credentials"
		rec := httptest.NewRecorder()
		h.RevealDNSProviderCredentials(rec, userReq(http.MethodGet, pathA, "userA", nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ak-a") {
			t.Fatalf("userA could not reveal own credentials: %d %s", rec.Code, rec.Body.String())
		}

		// User B reveals User A credentials -> must fail (404 Not Found)
		rec = httptest.NewRecorder()
		h.RevealDNSProviderCredentials(rec, userReq(http.MethodGet, pathA, "userB", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("userB revealed userA credentials! Code: %d, body: %s", rec.Code, rec.Body.String())
		}

		// User B reveals Admin credentials -> must fail (404 Not Found)
		pathAdmin := "/api/admin/dns-providers/" + strconv.FormatInt(adminDNS.ID, 10) + "/credentials"
		rec = httptest.NewRecorder()
		h.RevealDNSProviderCredentials(rec, userReq(http.MethodGet, pathAdmin, "userB", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("userB revealed admin credentials! Code: %d, body: %s", rec.Code, rec.Body.String())
		}
	})

	// 6. Delete & Update DNS Provider Isolation
	t.Run("Mutate DNS Provider Isolation", func(t *testing.T) {
		pathA := "/api/admin/dns-providers/" + strconv.FormatInt(userADNS.ID, 10)

		// User B tries to update User A's DNS provider -> must fail
		rec := httptest.NewRecorder()
		h.UpdateDNSProvider(rec, userReq(http.MethodPut, pathA, "userB", map[string]string{
			"name":          "hacked",
			"provider_type": "huaweicloud",
		}))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("userB updated userA provider! Code: %d", rec.Code)
		}

		// User B tries to delete User A's DNS provider -> must fail
		rec = httptest.NewRecorder()
		h.DeleteDNSProvider(rec, userReq(http.MethodDelete, pathA, "userB", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("userB deleted userA provider! Code: %d", rec.Code)
		}
	})

	// 7. Create Certificate Isolation: User B cannot use User A's DNS Provider ID
	t.Run("Create Certificate Using Another User's DNS Provider Rejects", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.CreateCertificate(rec, userReq(http.MethodPost, "/api/admin/certificates/create", "userB", map[string]any{
			"domain":          "b-attack.example.com",
			"email":           "attacker@example.com",
			"provider":        "letsencrypt",
			"challenge_mode":  "dns",
			"dns_provider_id": userADNS.ID, // User A's provider!
		}))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Fatalf("expected rejection using another user's provider, got code: %d, body: %s", rec.Code, rec.Body.String())
		}
	})

	// 8. Certificate Mutation Isolation: User B cannot delete or renew User A's certificate
	t.Run("Certificate Mutation Isolation", func(t *testing.T) {
		// User B tries to delete User A's certificate -> must fail
		rec := httptest.NewRecorder()
		h.DeleteCertificate(rec, userReq(http.MethodPost, "/api/admin/certificates/delete", "userB", map[string]any{
			"id": userACert.ID,
		}))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("userB deleted userA cert! Code: %d", rec.Code)
		}

		// User B tries to renew User A's certificate -> must fail
		rec = httptest.NewRecorder()
		h.RenewCertificate(rec, userReq(http.MethodPost, "/api/admin/certificates/renew", "userB", map[string]any{
			"id": userACert.ID,
		}))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("userB renewed userA cert! Code: %d", rec.Code)
		}
	})

	// 9. Node Creation TLS Inbound Certificate Isolation
	t.Run("Managed Node TLS Certificate Binding Isolation", func(t *testing.T) {
		nodeHandler := NewManagedNodesHandler(repo, nil, nil)

		// User A creates TLS inbound with User A cert -> should succeed
		userACtx := auth.ContextWithUsername(ctx, "userA")
		err := nodeHandler.validateUserManagedCertificate(userACtx, 0, map[string]interface{}{
			"streamSettings": map[string]interface{}{"security": "tls"},
			"cert_id":        userACert.ID,
		})
		if err != nil {
			t.Fatalf("userA could not bind own cert: %v", err)
		}

		// User A creates TLS inbound with User B cert -> must fail
		err = nodeHandler.validateUserManagedCertificate(userACtx, 0, map[string]interface{}{
			"streamSettings": map[string]interface{}{"security": "tls"},
			"cert_id":        userBCert.ID,
		})
		if err == nil {
			t.Fatalf("userA successfully bound userB cert!")
		}

		// User A creates TLS inbound with Admin cert -> must fail
		err = nodeHandler.validateUserManagedCertificate(userACtx, 0, map[string]interface{}{
			"streamSettings": map[string]interface{}{"security": "tls"},
			"cert_id":        adminCert.ID,
		})
		if err == nil {
			t.Fatalf("userA successfully bound admin cert!")
		}

		// User B creates TLS inbound with User B cert -> should succeed
		userBCtx := auth.ContextWithUsername(ctx, "userB")
		err = nodeHandler.validateUserManagedCertificate(userBCtx, 0, map[string]interface{}{
			"streamSettings": map[string]interface{}{"security": "tls"},
			"cert_id":        userBCert.ID,
		})
		if err != nil {
			t.Fatalf("userB could not bind own cert: %v", err)
		}

		// User B creates TLS inbound with User A cert -> must fail
		err = nodeHandler.validateUserManagedCertificate(userBCtx, 0, map[string]interface{}{
			"streamSettings": map[string]interface{}{"security": "tls"},
			"cert_id":        userACert.ID,
		})
		if err == nil {
			t.Fatalf("userB successfully bound userA cert!")
		}

		// Admin creates TLS inbound with Admin cert -> should succeed
		adminCtx := auth.ContextWithUsername(ctx, "admin")
		err = nodeHandler.validateUserManagedCertificate(adminCtx, 0, map[string]interface{}{
			"streamSettings": map[string]interface{}{"security": "tls"},
			"cert_id":        adminCert.ID,
		})
		if err != nil {
			t.Fatalf("admin could not bind admin cert: %v", err)
		}
	})
}
