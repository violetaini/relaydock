package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestCollectManagedXrayCertPaths(t *testing.T) {
	config := `{
		"inbounds": [{
			"streamSettings": {
				"tlsSettings": {
					"certificates": [
						{
							"certificateFile": "/usr/local/etc/xray/certs/example.com.pem",
							"keyFile": "/usr/local/etc/xray/certs/example.com.key"
						},
						{
							"certificateFile": "/etc/custom/manual.pem",
							"keyFile": "/etc/custom/manual.key"
						},
						{
							"certificateFile": "/usr/local/etc/xray/certs/../../outside.pem",
							"keyFile": "/usr/local/etc/xray/certs/../../outside.key"
						}
					]
				}
			}
		}]
	}`

	refs := collectManagedXrayCertPaths(config)
	if len(refs) != 1 {
		t.Fatalf("expected one managed certificate reference, got %d: %#v", len(refs), refs)
	}
	if got := refs["/usr/local/etc/xray/certs/example.com.pem"]; got != "/usr/local/etc/xray/certs/example.com.key" {
		t.Fatalf("unexpected key path: %q", got)
	}
}

func TestCollectManagedXrayCertPathsInvalidJSON(t *testing.T) {
	if refs := collectManagedXrayCertPaths("{"); len(refs) != 0 {
		t.Fatalf("invalid JSON must not produce references: %#v", refs)
	}
}

func TestManagedXrayCertPathsWildcard(t *testing.T) {
	certPath, keyPath := managedXrayCertPaths("*.example.com")
	if certPath != "/usr/local/etc/xray/certs/_.example.com.pem" {
		t.Fatalf("unexpected wildcard certificate path: %s", certPath)
	}
	if keyPath != "/usr/local/etc/xray/certs/_.example.com.key" {
		t.Fatalf("unexpected wildcard key path: %s", keyPath)
	}
}

func TestXrayCertSyncFingerprint(t *testing.T) {
	h := &CertificateHandler{}
	cert := &storage.Certificate{ID: 12, CertPEM: "cert-v1", KeyPEM: "key-v1"}

	if !h.needsXrayCertSync(7, cert) {
		t.Fatal("certificate without a successful deployment must need sync")
	}
	h.rememberXrayCertSync(7, cert)
	if h.needsXrayCertSync(7, cert) {
		t.Fatal("unchanged successfully deployed certificate must not need sync")
	}

	cert.CertPEM = "cert-v2"
	if !h.needsXrayCertSync(7, cert) {
		t.Fatal("changed certificate material must need sync")
	}

	h.forgetXrayCertSync(7, cert.ID)
	if !h.needsXrayCertSync(7, cert) {
		t.Fatal("forgotten deployment must need sync")
	}
}

func TestCertReferencedByManagedXrayPaths(t *testing.T) {
	cert := &storage.Certificate{Domain: "example.com"}
	refs := map[string]string{
		"/usr/local/etc/xray/certs/example.com.pem": "/usr/local/etc/xray/certs/example.com.key",
	}
	if !certReferencedByManagedXrayPaths(cert, refs) {
		t.Fatal("expected exact managed path pair to match")
	}
	refs["/usr/local/etc/xray/certs/example.com.pem"] = "/usr/local/etc/xray/certs/other.key"
	if certReferencedByManagedXrayPaths(cert, refs) {
		t.Fatal("mismatched key path must not match")
	}
}

func TestManagedXrayCertificateMaterialUpdateDeploysAndRestartsReferencedAgent(t *testing.T) {
	var deploys atomic.Int64
	var restarts atomic.Int64
	var deployed WSCertDeployPayload
	restarted := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/cert/deploy":
			if err := json.NewDecoder(r.Body).Decode(&deployed); err != nil {
				t.Errorf("decode certificate deployment: %v", err)
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			deploys.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control":
			restarts.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/services/status":
			_, _ = w.Write([]byte(`{"xray":{"running":true}}`))
			select {
			case restarted <- struct{}{}:
			default:
			}
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	cert := &storage.Certificate{
		Domain:         "hy.example.test",
		Email:          "admin@example.test",
		Provider:       "letsencrypt-staging",
		Status:         storage.CertStatusValid,
		RemoteServerID: 0,
		CertPEM:        "old-certificate",
		KeyPEM:         "old-key",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	config := `{"inbounds":[{"protocol":"hysteria2","streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/usr/local/etc/xray/certs/hy.example.test.pem","keyFile":"/usr/local/etc/xray/certs/hy.example.test.key"}]}}}]}`
	if _, err := repo.UpsertCurrentXraySnapshot(context.Background(), server.ID, config, storage.XraySnapshotSourceMasterWrite); err != nil {
		t.Fatalf("UpsertCurrentXraySnapshot: %v", err)
	}

	remote := NewRemoteManageHandler(repo, nil)
	h := NewCertificateHandler(repo, nil)
	h.SetRemoteManage(remote)
	h.syncManagedXrayAfterMaterialUpdate(cert, "renewed-certificate", "renewed-key")

	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the referenced agent certificate deployment and Xray restart")
	}
	if got := deploys.Load(); got != 1 {
		t.Fatalf("certificate deployments = %d, want 1", got)
	}
	if got := restarts.Load(); got != 1 {
		t.Fatalf("Xray restarts = %d, want 1", got)
	}
	if deployed.CertPEM != "renewed-certificate" || deployed.KeyPEM != "renewed-key" {
		t.Fatalf("unexpected renewed certificate material: %#v", deployed)
	}
	if deployed.CertPath != "/usr/local/etc/xray/certs/hy.example.test.pem" || deployed.KeyPath != "/usr/local/etc/xray/certs/hy.example.test.key" || deployed.Reload != "none" {
		t.Fatalf("unexpected managed certificate deployment: %#v", deployed)
	}
	if h.needsXrayCertSync(server.ID, &storage.Certificate{ID: cert.ID, CertPEM: "renewed-certificate", KeyPEM: "renewed-key"}) {
		t.Fatal("successful renewed deployment must be remembered by its certificate fingerprint")
	}
}
