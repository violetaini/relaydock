package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestManagedXrayCertificateMaterialUpdateDeploysWithoutRestartingReferencedAgent(t *testing.T) {
	var deploys atomic.Int64
	var restarts atomic.Int64
	var deployed WSCertDeployPayload
	deployedSignal := make(chan struct{}, 1)
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
			select {
			case deployedSignal <- struct{}{}:
			default:
			}
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control":
			restarts.Add(1)
			http.Error(w, "certificate material updates must not restart Xray", http.StatusInternalServerError)
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
	case <-deployedSignal:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the referenced agent certificate deployment")
	}
	// The material update runs in a background task. It holds this mutex for
	// the whole deployment, so reacquiring it confirms no later service-control
	// request can be issued by this synchronization pass.
	h.xrayCertSyncMu.Lock()
	h.xrayCertSyncMu.Unlock()
	if got := deploys.Load(); got != 1 {
		t.Fatalf("certificate deployments = %d, want 1", got)
	}
	if got := restarts.Load(); got != 0 {
		t.Fatalf("Xray restarts = %d, want 0 for a content-only certificate update", got)
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

func TestManagedXrayCertificateDeploymentFailureRestoresPreviousMaterialWithoutRestart(t *testing.T) {
	var deployments []WSCertDeployPayload
	var restarts atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control" {
			restarts.Add(1)
			http.Error(w, "certificate rollback must not restart Xray", http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/child/cert/deploy" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		var payload WSCertDeployPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		deployments = append(deployments, payload)
		if len(deployments) == 1 {
			http.Error(w, "simulated certificate write failure", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	previous := &storage.Certificate{
		ID: 31, Domain: "hy.example.test", CertPEM: "old-certificate", KeyPEM: "old-key",
		Status: storage.CertStatusValid, RemoteServerID: 0,
	}
	renewed := *previous
	renewed.CertPEM = "renewed-certificate"
	renewed.KeyPEM = "renewed-key"

	h := NewCertificateHandler(repo, nil)
	h.SetRemoteManage(NewRemoteManageHandler(repo, nil))
	err := h.deployManagedXrayCert(context.Background(), server, &renewed, previous)
	if err == nil || !strings.Contains(err.Error(), "simulated certificate write failure") {
		t.Fatalf("expected renewed certificate deployment failure, got %v", err)
	}
	if len(deployments) != 2 {
		t.Fatalf("deployments=%d want renewed and rollback payloads: %#v", len(deployments), deployments)
	}
	if deployments[0].CertPEM != renewed.CertPEM || deployments[1].CertPEM != previous.CertPEM {
		t.Fatalf("unexpected deployment order: %#v", deployments)
	}
	if got := restarts.Load(); got != 0 {
		t.Fatalf("Xray restarts = %d, want 0 during certificate rollback", got)
	}
	if !h.needsXrayCertSync(server.ID, &renewed) {
		t.Fatal("renewed material must remain pending after rollback")
	}
	if h.needsXrayCertSync(server.ID, previous) {
		t.Fatal("successfully restored old material must be remembered")
	}
}
