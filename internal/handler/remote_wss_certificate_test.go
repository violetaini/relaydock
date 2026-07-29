package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func createWSSCertificateForTest(t *testing.T, repo *storage.TrafficRepository, certificate *storage.Certificate) {
	t.Helper()
	if certificate.Email == "" {
		certificate.Email = "admin@example.test"
	}
	if err := repo.CreateCertificate(context.Background(), certificate); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
}

func TestFindCertificateForRemoteDomainRequiresDeployableCertificate(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-time.Minute)
	tests := []struct {
		name       string
		status     string
		certPEM    string
		keyPEM     string
		expiryDate *time.Time
		want       bool
	}{
		{name: "valid with no expiry is accepted", status: storage.CertStatusValid, certPEM: "cert", keyPEM: "key", want: true},
		{name: "valid future certificate is accepted", status: storage.CertStatusValid, certPEM: "cert", keyPEM: "key", expiryDate: &future, want: true},
		{name: "pending status is rejected", status: storage.CertStatusPending, certPEM: "cert", keyPEM: "key"},
		{name: "expired status is rejected", status: storage.CertStatusExpired, certPEM: "cert", keyPEM: "key", expiryDate: &future},
		{name: "past expiry is rejected", status: storage.CertStatusValid, certPEM: "cert", keyPEM: "key", expiryDate: &past},
		{name: "missing certificate PEM is rejected", status: storage.CertStatusValid, keyPEM: "key"},
		{name: "missing private key PEM is rejected", status: storage.CertStatusValid, certPEM: "cert"},
		{name: "whitespace PEM is rejected", status: storage.CertStatusValid, certPEM: " \n", keyPEM: "\t"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, server := newRemoteInstallationHandlerRepo(t, 23889)
			certPEM, keyPEM := tt.certPEM, tt.keyPEM
			if tt.want {
				certPEM, keyPEM, _ = createTestCertificatePEM(t, "example.test")
			}
			certificate := &storage.Certificate{
				Domain:         "example.test",
				Status:         tt.status,
				CertPEM:        certPEM,
				KeyPEM:         keyPEM,
				ExpiryDate:     tt.expiryDate,
				RemoteServerID: server.ID,
			}
			createWSSCertificateForTest(t, repo, certificate)

			got, err := NewRemoteManageHandler(repo, nil).findCertificateForRemoteDomain(context.Background(), "example.test", server.ID)
			if tt.want {
				if err != nil {
					t.Fatalf("findCertificateForRemoteDomain: %v", err)
				}
				if got == nil || got.ID != certificate.ID {
					t.Fatalf("certificate = %#v, want ID %d", got, certificate.ID)
				}
				return
			}
			if !errors.Is(err, storage.ErrCertificateNotFound) || got != nil {
				t.Fatalf("certificate = %#v, error = %v; want ErrCertificateNotFound", got, err)
			}
		})
	}
}

func TestFindCertificateForRemoteDomainVerifiesLeafDNSNames(t *testing.T) {
	tests := []struct {
		name         string
		recordDomain string
		dnsNames     []string
		hostname     string
		want         bool
	}{
		{
			name:         "exact child certificate covers child hostname",
			recordDomain: "edge.example.test",
			dnsNames:     []string{"edge.example.test"},
			hostname:     "edge.example.test",
			want:         true,
		},
		{
			name:         "apex certificate does not cover child hostname",
			recordDomain: "example.test",
			dnsNames:     []string{"example.test"},
			hostname:     "edge.example.test",
		},
		{
			name:         "wildcard covers one child label",
			recordDomain: "*.example.test",
			dnsNames:     []string{"*.example.test"},
			hostname:     "edge.example.test",
			want:         true,
		},
		{
			name:         "wildcard does not cover multiple child labels",
			recordDomain: "*.example.test",
			dnsNames:     []string{"*.example.test"},
			hostname:     "deep.edge.example.test",
		},
		{
			name:         "secondary SAN covers hostname",
			recordDomain: "primary.other.test",
			dnsNames:     []string{"primary.other.test", "edge.example.test"},
			hostname:     "edge.example.test",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, server := newRemoteInstallationHandlerRepo(t, 23889)
			certPEM, keyPEM, expiry := createTestCertificatePEM(t, tt.dnsNames...)
			certificate := &storage.Certificate{
				Domain:         tt.recordDomain,
				Status:         storage.CertStatusValid,
				CertPEM:        certPEM,
				KeyPEM:         keyPEM,
				ExpiryDate:     &expiry,
				RemoteServerID: server.ID,
			}
			createWSSCertificateForTest(t, repo, certificate)

			got, err := NewRemoteManageHandler(repo, nil).findCertificateForRemoteDomain(context.Background(), tt.hostname, server.ID)
			if tt.want {
				if err != nil {
					t.Fatalf("findCertificateForRemoteDomain: %v", err)
				}
				if got == nil || got.ID != certificate.ID {
					t.Fatalf("certificate = %#v, want ID %d", got, certificate.ID)
				}
				return
			}
			if !errors.Is(err, storage.ErrCertificateNotFound) || got != nil {
				t.Fatalf("certificate = %#v, error = %v; want ErrCertificateNotFound", got, err)
			}
		})
	}
}

func TestCertificateNameCoversHostnameLimitsWildcardToOneLabel(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		hostname string
		want     bool
	}{
		{name: "exact", pattern: "edge.example.test", hostname: "edge.example.test", want: true},
		{name: "one label", pattern: "*.example.test", hostname: "edge.example.test", want: true},
		{name: "apex", pattern: "*.example.test", hostname: "example.test"},
		{name: "multiple labels", pattern: "*.example.test", hostname: "deep.edge.example.test"},
		{name: "different suffix", pattern: "*.example.test", hostname: "edge.other.test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certificateNameCoversHostname(tt.pattern, tt.hostname); got != tt.want {
				t.Fatalf("certificateNameCoversHostname(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.want)
			}
		})
	}
}

func TestCertificateCoversHostnameRejectsKeyMismatchAndInvalidLeafDates(t *testing.T) {
	certPEM, keyPEM, expiry := createTestCertificatePEM(t, "edge.example.test")
	_, otherKeyPEM, _ := createTestCertificatePEM(t, "edge.example.test")
	now := time.Now()

	tests := []struct {
		name   string
		keyPEM string
		now    time.Time
		want   bool
	}{
		{name: "valid pair and date", keyPEM: keyPEM, now: now, want: true},
		{name: "mismatched private key", keyPEM: otherKeyPEM, now: now},
		{name: "before leaf validity", keyPEM: keyPEM, now: now.Add(-2 * time.Hour)},
		{name: "at leaf expiry", keyPEM: keyPEM, now: expiry},
		{name: "after leaf expiry", keyPEM: keyPEM, now: expiry.Add(time.Second)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certificateCoversHostname(certPEM, tt.keyPEM, "edge.example.test", tt.now); got != tt.want {
				t.Fatalf("certificateCoversHostname() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindCertificateForRemoteDomainKeepsCandidatePriority(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	past := time.Now().Add(-time.Minute)
	exactCertPEM, exactKeyPEM, _ := createTestCertificatePEM(t, "edge.example.test")
	createWSSCertificateForTest(t, repo, &storage.Certificate{
		Domain:         "edge.example.test",
		Status:         storage.CertStatusValid,
		CertPEM:        exactCertPEM,
		KeyPEM:         exactKeyPEM,
		ExpiryDate:     &past,
		RemoteServerID: server.ID,
	})
	wildcardCertPEM, wildcardKeyPEM, _ := createTestCertificatePEM(t, "*.example.test")
	perServerWildcard := &storage.Certificate{
		Domain:         "*.example.test",
		Status:         storage.CertStatusValid,
		CertPEM:        wildcardCertPEM,
		KeyPEM:         wildcardKeyPEM,
		RemoteServerID: server.ID,
	}
	createWSSCertificateForTest(t, repo, perServerWildcard)
	globalWildcardCertPEM, globalWildcardKeyPEM, _ := createTestCertificatePEM(t, "*.example.test")
	createWSSCertificateForTest(t, repo, &storage.Certificate{
		Domain:         "*.example.test",
		Status:         storage.CertStatusValid,
		CertPEM:        globalWildcardCertPEM,
		KeyPEM:         globalWildcardKeyPEM,
		RemoteServerID: 0,
	})
	globalExactCertPEM, globalExactKeyPEM, _ := createTestCertificatePEM(t, "edge.example.test")
	createWSSCertificateForTest(t, repo, &storage.Certificate{
		Domain:         "edge.example.test",
		Status:         storage.CertStatusValid,
		CertPEM:        globalExactCertPEM,
		KeyPEM:         globalExactKeyPEM,
		RemoteServerID: 0,
	})

	got, err := NewRemoteManageHandler(repo, nil).findCertificateForRemoteDomain(context.Background(), "edge.example.test", server.ID)
	if err != nil {
		t.Fatalf("findCertificateForRemoteDomain: %v", err)
	}
	if got.ID != perServerWildcard.ID {
		t.Fatalf("certificate ID = %d, want per-server wildcard ID %d", got.ID, perServerWildcard.ID)
	}
}

func TestSyncWSSNginxRejectsUnusableCertificatesBeforeAgentWrites(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	tests := []struct {
		name       string
		status     string
		expiryDate *time.Time
	}{
		{name: "pending", status: storage.CertStatusPending},
		{name: "expired by date", status: storage.CertStatusValid, expiryDate: &past},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var agentRequests atomic.Int64
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				agentRequests.Add(1)
				http.Error(w, "unexpected Agent request", http.StatusInternalServerError)
			}))
			defer agent.Close()

			repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
			createWSSCertificateForTest(t, repo, &storage.Certificate{
				Domain:         "example.test",
				Status:         tt.status,
				CertPEM:        "cert",
				KeyPEM:         "key",
				ExpiryDate:     tt.expiryDate,
				RemoteServerID: server.ID,
			})
			handler := NewRemoteManageHandler(repo, nil)
			attachRemoteCertificateHandler(t, repo, handler)

			if err := handler.SyncWSSNginx(context.Background(), server.ID); err == nil {
				t.Fatal("SyncWSSNginx succeeded with unusable certificate")
			}
			if got := agentRequests.Load(); got != 0 {
				t.Fatalf("unusable certificate reached Agent %d time(s)", got)
			}
		})
	}
}

func TestSyncWSSNginxRequiresCertificateHandler(t *testing.T) {
	var agentRequests atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		agentRequests.Add(1)
		http.Error(w, "unexpected Agent request", http.StatusInternalServerError)
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	createRemoteDomainCertificate(t, repo, server.ID, "edge.example.test")
	err := NewRemoteManageHandler(repo, nil).SyncWSSNginx(context.Background(), server.ID)
	if err == nil || !strings.Contains(err.Error(), "证书功能未初始化") {
		t.Fatalf("SyncWSSNginx error = %v, want certificate handler error", err)
	}
	if got := agentRequests.Load(); got != 0 {
		t.Fatalf("missing certificate handler reached Agent %d time(s)", got)
	}
}

func TestHandleInboundsWSSPreflightStopsBeforeAgentMutation(t *testing.T) {
	var agentRequests atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		agentRequests.Add(1)
		http.Error(w, "unexpected Agent request", http.StatusInternalServerError)
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewRemoteManageHandler(repo, nil)
	attachRemoteCertificateHandler(t, repo, handler)
	body := strings.NewReader(`{"action":"add","inbound":{"tag":"wss-no-cert","protocol":"vless","listen":"127.0.0.1","settings":{"clients":[]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/wss"}}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/remote/inbounds?server_id="+leaseTestID(server.ID), body)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "wss-preflight-user"))
	response := httptest.NewRecorder()

	handler.HandleInbounds(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if got := agentRequests.Load(); got != 0 {
		t.Fatalf("WSS preflight reached Agent %d time(s) without a certificate", got)
	}
}

func TestSyncWSSNginxDeploysCertificateBeforeNginx(t *testing.T) {
	var mu sync.Mutex
	sequence := make([]string, 0, 3)
	var certPayload WSCertDeployPayload
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			mu.Lock()
			sequence = append(sequence, "inbounds")
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true,"inbounds":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/cert/deploy":
			if err := json.NewDecoder(r.Body).Decode(&certPayload); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			sequence = append(sequence, "certificate")
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/nginx/setup-ssl":
			mu.Lock()
			sequence = append(sequence, "nginx")
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	createRemoteDomainCertificate(t, repo, server.ID, "edge.example.test")
	handler := NewRemoteManageHandler(repo, nil)
	attachRemoteCertificateHandler(t, repo, handler)

	if err := handler.SyncWSSNginx(context.Background(), server.ID); err != nil {
		t.Fatalf("SyncWSSNginx: %v", err)
	}
	mu.Lock()
	gotSequence := append([]string(nil), sequence...)
	mu.Unlock()
	if want := []string{"inbounds", "certificate", "nginx"}; !reflect.DeepEqual(gotSequence, want) {
		t.Fatalf("Agent sequence = %v, want %v", gotSequence, want)
	}
	if certPayload.Domain != "example.test" || !strings.Contains(certPayload.CertPEM, "BEGIN CERTIFICATE") || !strings.Contains(certPayload.KeyPEM, "BEGIN EC PRIVATE KEY") {
		t.Fatalf("certificate payload = %#v", certPayload)
	}
	if certPayload.CertPath != "/usr/local/nginx/cert/edge.example.test.pem" || certPayload.KeyPath != "/usr/local/nginx/cert/edge.example.test.key" || certPayload.Reload != "none" {
		t.Fatalf("certificate deployment paths = %#v", certPayload)
	}
}

func TestSyncWSSNginxCertificateDeployFailureDoesNotWriteNginx(t *testing.T) {
	var certificateWrites atomic.Int64
	var nginxWrites atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			_, _ = w.Write([]byte(`{"success":true,"inbounds":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/cert/deploy":
			certificateWrites.Add(1)
			_, _ = w.Write([]byte(`{"success":false,"error":"certificate disk full"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/nginx/setup-ssl":
			nginxWrites.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	createRemoteDomainCertificate(t, repo, server.ID, "edge.example.test")
	handler := NewRemoteManageHandler(repo, nil)
	attachRemoteCertificateHandler(t, repo, handler)

	err := handler.SyncWSSNginx(context.Background(), server.ID)
	if err == nil || !strings.Contains(err.Error(), "Agent ACK") {
		t.Fatalf("SyncWSSNginx error = %v, want certificate ACK error", err)
	}
	if got := certificateWrites.Load(); got != 1 {
		t.Fatalf("certificate writes = %d, want 1", got)
	}
	if got := nginxWrites.Load(); got != 0 {
		t.Fatalf("nginx writes = %d after certificate deployment failure, want 0", got)
	}
}
