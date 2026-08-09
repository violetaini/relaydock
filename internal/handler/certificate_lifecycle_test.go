package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	processResult *acme.CertResult
	processErr    error
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
	return f.processResult, f.processErr
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
	req = req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
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
	req = req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
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

func TestDeployAfterIssueRequiresAutoDeployAndPreservesTarget(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	h := NewCertificateHandler(repo, nil)
	var calls atomic.Int64
	var reloadTarget string
	h.SetLocalDeployer(func(_, _, _, _, reload string) error {
		calls.Add(1)
		reloadTarget = reload
		return nil
	})
	cert := &storage.Certificate{
		Domain: "scope.example.test", Provider: acme.CALetsEncrypt, ChallengeMode: storage.CertChallengeStandalone,
		DeployTarget: "xray", DeployCertPath: "/etc/arcway/scope.pem", DeployKeyPath: "/etc/arcway/scope.key",
	}
	result := &acme.CertResult{CertPEM: "certificate", KeyPEM: "private-key"}

	h.deployAfterIssue(cert, result)
	if got := calls.Load(); got != 0 {
		t.Fatalf("deploy calls with auto_deploy=false = %d, want 0", got)
	}

	cert.AutoDeploy = true
	h.deployAfterIssue(cert, result)
	if got := calls.Load(); got != 1 {
		t.Fatalf("deploy calls with auto_deploy=true = %d, want 1", got)
	}
	if reloadTarget != "none" {
		t.Fatalf("automatic Xray reload target = %q, want file-only none", reloadTarget)
	}
	if cert.DeployTarget != "xray" {
		t.Fatalf("automatic deployment rewrote deploy target to %q", cert.DeployTarget)
	}
}

func TestDeployAfterIssueRefreshesAutomationSettings(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	cert := &storage.Certificate{
		Domain: "refresh-gate.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt,
		Status: storage.CertStatusValid, ChallengeMode: storage.CertChallengeStandalone,
		AutoDeploy: true, DeployTarget: "xray", DeployCertPath: "/tmp/cert.pem", DeployKeyPath: "/tmp/key.pem",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	stale := *cert
	if err := repo.SetCertificateAutoDeploy(context.Background(), cert.ID, false); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)
	var calls atomic.Int64
	h.SetLocalDeployer(func(string, string, string, string, string) error { calls.Add(1); return nil })

	h.deployAfterIssue(&stale, &acme.CertResult{CertPEM: "new-cert", KeyPEM: "new-key"})
	if calls.Load() != 0 {
		t.Fatal("automatic deployment ignored the latest disabled setting")
	}
}

func TestManualDeploySettingsDoNotOverwriteConcurrentIssuedMaterial(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	now := time.Now().UTC()
	cert := &storage.Certificate{
		Domain: "deploy-race.example.test", Email: "admin@example.test", Provider: "manual",
		Status: storage.CertStatusValid, ChallengeMode: "manual", CertPEM: "old-cert", KeyPEM: "old-key",
		DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)
	h.SetLocalDeployer(func(string, string, string, string, string) error {
		return repo.UpdateCertificateIssued(context.Background(), cert.ID, "/new/cert", "/new/key", "new-cert", "new-key", now, now.Add(90*24*time.Hour))
	})
	body := `{"id":` + itoa64(cert.ID) + `,"deploy_target":"xray","deploy_cert_path":"/deploy/cert.pem","deploy_key_path":"/deploy/key.pem","deploy_local":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/certificates/deploy", bytes.NewBufferString(body))
	req = req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
	resp := httptest.NewRecorder()
	h.DeployCertificate(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CertPEM != "new-cert" || stored.KeyPEM != "new-key" || stored.DeployTarget != "xray" || stored.DeployCertPath != "/deploy/cert.pem" {
		t.Fatalf("deployment settings overwrote concurrent certificate material: %#v", stored)
	}
}

func TestUploadExistingCertificateKeepsReplacementMaterialWhenInitializingPaths(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	now := time.Now().UTC()
	cert := &storage.Certificate{
		Domain: "upload-existing.example.test", Email: "admin@example.test", Provider: "manual",
		Status: storage.CertStatusValid, ChallengeMode: "manual", CertPEM: "old-cert", KeyPEM: "old-key",
		DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)
	h.acmeClient = &fakeCertificateACMEClient{processResult: &acme.CertResult{
		Domain: cert.Domain, CertPath: "/stored/new-cert", KeyPath: "/stored/new-key",
		CertPEM: "replacement-cert", KeyPEM: "replacement-key", IssueDate: now, ExpiryDate: now.Add(90 * 24 * time.Hour),
	}}
	body := `{"domain":"upload-existing.example.test","cert_pem":"-----BEGIN CERTIFICATE-----\nreplacement","key_pem":"-----BEGIN PRIVATE KEY-----\nreplacement"}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/certificates/upload", bytes.NewBufferString(body))
	req = req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
	resp := httptest.NewRecorder()
	h.UploadCertificate(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CertPEM != "replacement-cert" || stored.KeyPEM != "replacement-key" {
		t.Fatalf("upload restored stale certificate material: %#v", stored)
	}
	if stored.DeployCertPath == "" || stored.DeployKeyPath == "" {
		t.Fatalf("upload did not initialize deployment paths: %#v", stored)
	}
}

func TestHandleCertUpdateChecksBoundServerBeforeMutation(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	owner := &storage.RemoteServer{Name: "certificate owner", Token: "owner-token"}
	intruder := &storage.RemoteServer{Name: "other agent", Token: "intruder-token"}
	for _, server := range []*storage.RemoteServer{owner, intruder} {
		if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
			t.Fatalf("CreateRemoteServer(%s): %v", server.Name, err)
		}
	}
	expiry := time.Now().UTC().Add(30 * 24 * time.Hour)
	cert := &storage.Certificate{
		Domain: "owned.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt,
		Status: storage.CertStatusValid, ChallengeMode: storage.CertChallengeStandalone,
		CertPEM: "original-cert", KeyPEM: "original-key", ExpiryDate: &expiry,
		RemoteServerID: owner.ID, DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)

	h.HandleCertUpdate(intruder.ID, WSCertUpdatePayload{
		CertID: cert.ID, Success: true, CertPEM: "forged-cert", KeyPEM: "forged-key",
		IssueDate: time.Now().UTC(), ExpiryDate: time.Now().UTC().Add(90 * 24 * time.Hour),
	})
	h.HandleCertUpdate(intruder.ID, WSCertUpdatePayload{CertID: cert.ID, Success: false, Error: "forged failure"})
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != storage.CertStatusValid || stored.CertPEM != "original-cert" || stored.KeyPEM != "original-key" || strings.Contains(stored.Message, "forged") {
		t.Fatalf("unbound agent mutated certificate: %#v", stored)
	}

	h.HandleCertUpdate(owner.ID, WSCertUpdatePayload{
		CertID: cert.ID, Success: true, CertPEM: "renewed-cert", KeyPEM: "renewed-key",
		IssueDate: time.Now().UTC(), ExpiryDate: time.Now().UTC().Add(90 * 24 * time.Hour),
	})
	stored, err = repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != storage.CertStatusValid || stored.CertPEM != "renewed-cert" || stored.KeyPEM != "renewed-key" {
		t.Fatalf("bound agent update was not persisted: %#v", stored)
	}
}

func TestCertificateAutomationPatchesRejectInvalidEnables(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	manual := &storage.Certificate{
		Domain: "manual.example.test", Email: "admin@example.test", Provider: "manual", ChallengeMode: "manual", Status: storage.CertStatusValid,
		DeployTarget: "xray", DeployCertPath: "/etc/arcway/manual.pem", DeployKeyPath: "/etc/arcway/manual.key",
	}
	missingTarget := &storage.Certificate{
		Domain: "missing-target.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt,
		ChallengeMode: storage.CertChallengeStandalone, Status: storage.CertStatusValid, DeployTarget: "none",
	}
	missingPaths := &storage.Certificate{
		Domain: "missing-paths.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt,
		ChallengeMode: storage.CertChallengeStandalone, Status: storage.CertStatusValid, DeployTarget: "nginx",
	}
	for _, cert := range []*storage.Certificate{manual, missingTarget, missingPaths} {
		if err := repo.CreateCertificate(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
	}
	h := NewCertificateHandler(repo, nil)
	tests := []struct {
		name string
		path string
		body string
		call func(http.ResponseWriter, *http.Request)
		want string
	}{
		{name: "manual auto renew", path: "/api/admin/certificates/auto-renew", body: `{"id":` + itoa64(manual.ID) + `,"auto_renew":true}`, call: h.SetAutoRenew, want: "手动上传证书"},
		{name: "auto deploy without target", path: "/api/admin/certificates/auto-deploy", body: `{"id":` + itoa64(missingTarget.ID) + `,"auto_deploy":true}`, call: h.SetAutoDeploy, want: "部署目标"},
		{name: "auto deploy without paths", path: "/api/admin/certificates/auto-deploy", body: `{"id":` + itoa64(missingPaths.ID) + `,"auto_deploy":true}`, call: h.SetAutoDeploy, want: "证书和私钥路径"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch, tc.path, bytes.NewBufferString(tc.body))
			req = req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
			resp := httptest.NewRecorder()
			tc.call(resp, req)
			if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), tc.want) {
				t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestUpdateCertificateNormalizesManualAutoRenew(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	cert := &storage.Certificate{
		Domain: "manual-update.example.test", Email: "admin@example.test", Provider: "manual", ChallengeMode: "manual", Status: storage.CertStatusValid,
		CertPEM: "certificate", KeyPEM: "private-key", DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)
	body := `{
		"domain":"manual-update.example.test","provider":"manual","challenge_mode":"manual",
		"auto_renew":true,"auto_deploy":true,"deploy_target":"xray",
		"deploy_cert_path":"/etc/arcway/manual.pem","deploy_key_path":"/etc/arcway/manual.key"
	}`
	req := httptest.NewRequest(http.MethodPut, "/api/admin/certificates/"+itoa64(cert.ID), bytes.NewBufferString(body))
	req = req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
	resp := httptest.NewRecorder()
	h.UpdateCertificate(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	stored, err := repo.GetCertificate(context.Background(), cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AutoRenew || !stored.AutoDeploy {
		t.Fatalf("manual certificate automation was not normalized as expected: %#v", stored)
	}
}

func TestManualCertificateDeployUsesExplicitRemoteSelectionAndReportsPartialFailure(t *testing.T) {
	var selectedCalls atomic.Int64
	var unselectedCalls atomic.Int64
	var selectedPayload WSCertDeployPayload
	selectedAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selectedCalls.Add(1)
		if err := json.NewDecoder(r.Body).Decode(&selectedPayload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer selectedAgent.Close()
	unselectedAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		unselectedCalls.Add(1)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer unselectedAgent.Close()

	repo := newCertificateLifecycleRepo(t)
	selected := createRemoteHandlerTestServer(t, repo, "selected-edge", selectedAgent.URL)
	_ = createRemoteHandlerTestServer(t, repo, "unselected-edge", unselectedAgent.URL)
	cert := &storage.Certificate{
		Domain: "selected.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt,
		ChallengeMode: storage.CertChallengeStandalone, Status: storage.CertStatusValid,
		CertPEM: "certificate", KeyPEM: "private-key", DeployTarget: "none",
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	h := NewCertificateHandler(repo, nil)
	var localCalls atomic.Int64
	h.SetLocalDeployer(func(_, _, _, _, _ string) error {
		localCalls.Add(1)
		return nil
	})
	body := `{"id":` + itoa64(cert.ID) + `,"deploy_target":"xray","deploy_cert_path":"/etc/arcway/selected.pem","deploy_key_path":"/etc/arcway/selected.key","deploy_local":false,"remote_server_ids":[` + itoa64(selected.ID) + `,999999]}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/certificates/deploy", bytes.NewBufferString(body))
	req = req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
	resp := httptest.NewRecorder()
	h.DeployCertificate(resp, req)
	if resp.Code != http.StatusMultiStatus {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload CertificateDeployResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Success || !payload.PartialFailure || len(payload.Deployments) != 2 {
		t.Fatalf("unexpected partial deployment response: %#v", payload)
	}
	if selectedCalls.Load() != 1 || unselectedCalls.Load() != 0 || localCalls.Load() != 0 {
		t.Fatalf("deploy calls selected=%d unselected=%d local=%d", selectedCalls.Load(), unselectedCalls.Load(), localCalls.Load())
	}
	if selectedPayload.Reload != "xray" || selectedPayload.Automatic {
		t.Fatalf("unexpected selected remote payload: %#v", selectedPayload)
	}
}

func TestDeployAutoDeployCertificatesOnlyUsesBoundServerCertificates(t *testing.T) {
	var deployments atomic.Int64
	var deployed WSCertDeployPayload
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deployments.Add(1)
		if err := json.NewDecoder(r.Body).Decode(&deployed); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer agent.Close()
	repo := newCertificateLifecycleRepo(t)
	server := createRemoteHandlerTestServer(t, repo, "bound-edge", agent.URL)
	otherServer := createRemoteHandlerTestServer(t, repo, "other-edge", agent.URL)
	certificates := []*storage.Certificate{
		{Domain: "controller.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt, ChallengeMode: storage.CertChallengeStandalone, Status: storage.CertStatusValid, CertPEM: "controller-cert", KeyPEM: "controller-key", AutoDeploy: true, DeployTarget: "nginx", DeployCertPath: "/etc/arcway/controller.pem", DeployKeyPath: "/etc/arcway/controller.key"},
		{Domain: "bound.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt, ChallengeMode: storage.CertChallengeStandalone, Status: storage.CertStatusValid, CertPEM: "bound-cert", KeyPEM: "bound-key", AutoDeploy: true, RemoteServerID: server.ID, DeployTarget: "xray", DeployCertPath: "/etc/arcway/bound.pem", DeployKeyPath: "/etc/arcway/bound.key"},
		{Domain: "other.example.test", Email: "admin@example.test", Provider: acme.CALetsEncrypt, ChallengeMode: storage.CertChallengeStandalone, Status: storage.CertStatusValid, CertPEM: "other-cert", KeyPEM: "other-key", AutoDeploy: true, RemoteServerID: otherServer.ID, DeployTarget: "both", DeployCertPath: "/etc/arcway/other.pem", DeployKeyPath: "/etc/arcway/other.key"},
	}
	for _, cert := range certificates {
		if err := repo.CreateCertificate(context.Background(), cert); err != nil {
			t.Fatal(err)
		}
	}
	h := NewCertificateHandler(repo, nil)
	h.DeployAutoDeployCertificates(server.ID)
	if got := deployments.Load(); got != 1 {
		t.Fatalf("deployments to newly ready server = %d, want only the bound certificate", got)
	}
	if deployed.Domain != "bound.example.test" || deployed.Reload != "none" || !deployed.Automatic {
		t.Fatalf("unexpected bound deployment payload: %#v", deployed)
	}
}

func TestCreateCertificateRejectsInvalidRequestBeforeBackgroundOperation(t *testing.T) {
	repo := newCertificateLifecycleRepo(t)
	h := NewCertificateHandler(repo, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/certificates/create", bytes.NewBufferString(`{
		"domain":"*.example.test","email":"admin@example.test","provider":"letsencrypt",
		"challenge_mode":"standalone","auto_renew":true
	}`))
	req = req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
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
	createReq = createReq.WithContext(auth.ContextWithGlobalAPIToken(createReq.Context()))
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
	renewReq = renewReq.WithContext(auth.ContextWithGlobalAPIToken(renewReq.Context()))
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
