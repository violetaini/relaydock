package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/acme"
	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type fakeCertificateACMEClient struct {
	obtainResult  *acme.CertResult
	obtainErr     error
	obtainStarted chan struct{}
	obtainRelease chan struct{}
	renewResult   *acme.CertResult
	renewErr      error
}

func (f *fakeCertificateACMEClient) ObtainCertificateV2(context.Context, acme.CertRequest) (*acme.CertResult, error) {
	if f.obtainStarted != nil {
		f.obtainStarted <- struct{}{}
	}
	if f.obtainRelease != nil {
		<-f.obtainRelease
	}
	return f.obtainResult, f.obtainErr
}

func (f *fakeCertificateACMEClient) RenewCertificateV2(context.Context, acme.CertRequest, string, string) (*acme.CertResult, error) {
	return f.renewResult, f.renewErr
}

func (f *fakeCertificateACMEClient) ProcessCertResult(string, []byte, []byte) (*acme.CertResult, error) {
	return nil, errors.New("not implemented by lifecycle test fake")
}

func TestLocalCertificateApplicationPersistsIssuedMaterial(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	now := time.Now().UTC()
	cert := &storage.Certificate{
		Domain:         "issue.example.test",
		Email:          "admin@example.test",
		Provider:       acme.CALetsEncryptStaging,
		Status:         storage.CertStatusPending,
		ChallengeMode:  storage.CertChallengeStandalone,
		RemoteServerID: 0,
		DeployTarget:   "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	h := NewCertificateHandler(repo, nil)
	h.acmeClient = &fakeCertificateACMEClient{obtainResult: &acme.CertResult{
		Domain: "issue.example.test", CertPath: "/stored/fullchain.pem", KeyPath: "/stored/privkey.pem",
		CertPEM: "issued-cert", KeyPEM: "issued-key", IssueDate: now, ExpiryDate: now.Add(90 * 24 * time.Hour),
	}}

	h.requestLocalCertificate(cert)
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if stored.Status != storage.CertStatusValid || stored.CertPEM != "issued-cert" || stored.KeyPEM != "issued-key" {
		t.Fatalf("certificate application did not persist issued material: %#v", stored)
	}
}

func TestRenewalFailureKeepsStillValidCertificate(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	expiry := time.Now().Add(30 * 24 * time.Hour)
	cert := &storage.Certificate{
		Domain: "renew.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt,
		Status: storage.CertStatusValid, ChallengeMode: storage.CertChallengeStandalone,
		CertPEM: "old-cert", KeyPEM: "old-key", ExpiryDate: &expiry, DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	h := NewCertificateHandler(repo, nil)
	h.acmeClient = &fakeCertificateACMEClient{renewErr: errors.New("simulated ACME outage")}

	h.renewLocalCertificate(cert)
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if stored.Status != storage.CertStatusValid || stored.CertPEM != "old-cert" || stored.KeyPEM != "old-key" {
		t.Fatalf("failed renewal replaced or invalidated old certificate: %#v", stored)
	}
	if !strings.Contains(stored.Message, "已保留当前有效证书") || !strings.Contains(stored.Message, "simulated ACME outage") {
		t.Fatalf("renewal failure is not diagnosable: %q", stored.Message)
	}
}

func TestAutomaticRenewalPersistsReplacementCertificate(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	now := time.Now().UTC()
	expiry := now.Add(5 * 24 * time.Hour)
	cert := &storage.Certificate{
		Domain: "automatic-renew.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt,
		Status: storage.CertStatusValid, ChallengeMode: storage.CertChallengeStandalone, AutoRenew: true,
		CertPEM: "old-cert", KeyPEM: "old-key", ExpiryDate: &expiry, DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)
	h.acmeClient = &fakeCertificateACMEClient{renewResult: &acme.CertResult{
		Domain: cert.Domain, CertPath: "/stored/fullchain.pem", KeyPath: "/stored/privkey.pem",
		CertPEM: "renewed-cert", KeyPEM: "renewed-key", IssueDate: now, ExpiryDate: now.Add(90 * 24 * time.Hour),
	}}

	h.checkAndRenewCertificates()
	deadline := time.Now().Add(2 * time.Second)
	for {
		stored, err := repo.GetCertificate(context.Background(), cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Status == storage.CertStatusValid && stored.CertPEM == "renewed-cert" {
			if stored.KeyPEM != "renewed-key" {
				t.Fatalf("automatic renewal stored a mismatched pair: %#v", stored)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("automatic renewal did not finish: %#v", stored)
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitForCertificateOperation(t, h, cert.ID)
}

func TestRenewCertificateRejectsDuplicateOperation(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	expiry := time.Now().Add(30 * 24 * time.Hour)
	cert := &storage.Certificate{
		Domain: "duplicate.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt,
		Status: storage.CertStatusValid, ChallengeMode: storage.CertChallengeStandalone,
		CertPEM: "old-cert", KeyPEM: "old-key", ExpiryDate: &expiry, DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)
	if !h.beginRenewal(cert.ID) {
		t.Fatal("failed to reserve renewal operation")
	}
	defer h.finishRenewal(cert.ID)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/certificates/renew", bytes.NewBufferString(`{"id":`+itoa64(cert.ID)+`}`))
	req = req.WithContext(auth.ContextWithUsername(req.Context(), "api-token-admin"))
	resp := httptest.NewRecorder()
	h.RenewCertificate(resp, req)
	if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "重复提交") {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestManualCertificateDeployReportsReloadFailureAndKeepsSettings(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	cert := &storage.Certificate{
		Domain: "deploy.example.test", Email: "admin@example.test", Provider: "manual",
		Status: storage.CertStatusValid, ChallengeMode: "manual", CertPEM: "cert", KeyPEM: "key", DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)
	h.SetLocalDeployer(func(string, string, string, string, string) error {
		return errors.New("simulated reload failure")
	})
	body := `{"id":` + itoa64(cert.ID) + `,"deploy_target":"xray","deploy_cert_path":"/tmp/new.pem","deploy_key_path":"/tmp/new.key"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/certificates/deploy", bytes.NewBufferString(body))
	req = req.WithContext(auth.ContextWithUsername(req.Context(), "api-token-admin"))
	resp := httptest.NewRecorder()
	h.DeployCertificate(resp, req)
	if resp.Code != http.StatusBadGateway || !strings.Contains(resp.Body.String(), "已恢复旧证书") {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DeployTarget != "none" || stored.DeployCertPath != "" || stored.DeployKeyPath != "" {
		t.Fatalf("failed deployment persisted new settings: %#v", stored)
	}
}

func TestCreateCertificateRejectsInvalidRequestBeforeBackgroundOperation(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	h := NewCertificateHandler(repo, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/certificates/create", bytes.NewBufferString(`{
		"domain":"*.example.test","email":"admin@example.test","provider":"letsencrypt",
		"challenge_mode":"standalone","auto_renew":true
	}`))
	req = req.WithContext(auth.ContextWithUsername(req.Context(), "api-token-admin"))
	resp := httptest.NewRecorder()
	h.CreateCertificate(resp, req)
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "DNS-01") {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	certs, err := repo.ListCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatalf("invalid application created certificate rows: %#v", certs)
	}
}

func TestCreateCertificateReservesIssuanceOperation(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	now := time.Now().UTC()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	h := NewCertificateHandler(repo, nil)
	h.acmeClient = &fakeCertificateACMEClient{
		obtainStarted: started,
		obtainRelease: release,
		obtainResult: &acme.CertResult{
			Domain: "guarded-issue.example.test", CertPath: "/stored/fullchain.pem", KeyPath: "/stored/privkey.pem",
			CertPEM: "issued-cert", KeyPEM: "issued-key", IssueDate: now, ExpiryDate: now.Add(90 * 24 * time.Hour),
		},
	}
	createReq := httptest.NewRequest(http.MethodPost, "/api/admin/certificates", bytes.NewBufferString(`{
		"domain":"guarded-issue.example.test","email":"admin@example.test",
		"provider":"letsencrypt-staging","challenge_mode":"standalone"
	}`))
	createReq = createReq.WithContext(auth.ContextWithUsername(createReq.Context(), "api-token-admin"))
	createResp := httptest.NewRecorder()
	h.CreateCertificate(createResp, createReq)
	if createResp.Code != http.StatusAccepted {
		close(release)
		t.Fatalf("create status=%d body=%s", createResp.Code, createResp.Body.String())
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("certificate issuance did not start")
	}
	certs, err := repo.ListCertificates(context.Background())
	if err != nil || len(certs) != 1 {
		close(release)
		t.Fatalf("ListCertificates: certs=%#v err=%v", certs, err)
	}
	renewReq := httptest.NewRequest(http.MethodPost, "/api/admin/certificates/renew", bytes.NewBufferString(`{"id":`+itoa64(certs[0].ID)+`}`))
	renewReq = renewReq.WithContext(auth.ContextWithUsername(renewReq.Context(), "api-token-admin"))
	renewResp := httptest.NewRecorder()
	h.RenewCertificate(renewResp, renewReq)
	if renewResp.Code != http.StatusConflict {
		close(release)
		t.Fatalf("renew status=%d body=%s", renewResp.Code, renewResp.Body.String())
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		stored, getErr := repo.GetCertificate(context.Background(), certs[0].ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if stored.Status == storage.CertStatusValid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("issuance did not finish: %#v", stored)
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitForCertificateOperation(t, h, certs[0].ID)
}

func newCertificateLifecycleRepo(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "cert-lifecycle.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func waitForCertificateOperation(t *testing.T, h *CertificateHandler, certID int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, active := h.renewals.Load(certID); !active {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("certificate operation %d did not release its in-flight marker", certID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func itoa64(value int64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	index := len(buf)
	for value > 0 {
		index--
		buf[index] = digits[value%10]
		value /= 10
	}
	return string(buf[index:])
}
