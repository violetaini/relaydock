package handler

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func attachRemoteCertificateHandler(t *testing.T, repo *storage.TrafficRepository, remote *RemoteManageHandler) {
	t.Helper()
	certHandler := NewCertificateHandler(repo, nil)
	certHandler.SetRemoteManage(remote)
	remote.SetCertificateHandler(certHandler)
}

func createRemoteDomainCertificate(t *testing.T, repo *storage.TrafficRepository, serverID int64, domain string) {
	t.Helper()
	certPEM, keyPEM, expiry := createTestCertificatePEM(t, domain)
	cert := &storage.Certificate{
		Domain:         domain,
		Email:          "admin@example.test",
		Status:         storage.CertStatusValid,
		RemoteServerID: serverID,
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
		ExpiryDate:     &expiry,
	}
	if err := repo.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
}

func createTestCertificatePEM(t *testing.T, dnsNames ...string) (string, string, time.Time) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test certificate key: %v", err)
	}
	now := time.Now()
	expiry := now.Add(24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     expiry,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal test certificate key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM), expiry
}

func decodeResponseMap(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
	return payload
}

func TestRemoteMultiStepHandlersRejectActiveInstallationBeforeAgentRequest(t *testing.T) {
	tests := []struct {
		name string
		call func(*RemoteManageHandler, *storage.RemoteServer) *httptest.ResponseRecorder
	}{
		{
			name: "inbounds",
			call: func(handler *RemoteManageHandler, server *storage.RemoteServer) *httptest.ResponseRecorder {
				body := bytes.NewBufferString(`{"action":"remove","tag":"old-inbound"}`)
				request := httptest.NewRequest(http.MethodPost, "/api/remote/inbounds?server_id="+leaseTestID(server.ID), body)
				response := httptest.NewRecorder()
				handler.HandleInbounds(response, request)
				return response
			},
		},
		{
			name: "add website",
			call: func(handler *RemoteManageHandler, server *storage.RemoteServer) *httptest.ResponseRecorder {
				body, _ := json.Marshal(map[string]any{
					"server_id":  server.ID,
					"domain":     "www.example.test",
					"site_type":  "static",
					"site_value": "/usr/local/nginx/html",
				})
				request := httptest.NewRequest(http.MethodPost, "/api/remote/websites", bytes.NewReader(body))
				response := httptest.NewRecorder()
				handler.HandleAddWebsite(response, request)
				return response
			},
		},
		{
			name: "setup ssl",
			call: func(handler *RemoteManageHandler, server *storage.RemoteServer) *httptest.ResponseRecorder {
				request := httptest.NewRequest(http.MethodPost, "/api/remote/setup-ssl?server_id="+leaseTestID(server.ID), nil)
				response := httptest.NewRecorder()
				handler.HandleSetupSSL(response, request)
				return response
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var agentRequests atomic.Int64
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				agentRequests.Add(1)
				http.Error(w, "unexpected Agent request", http.StatusInternalServerError)
			}))
			defer agent.Close()

			repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
			if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "active-"+test.name, time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			handler := NewRemoteManageHandler(repo, nil)
			attachRemoteCertificateHandler(t, repo, handler)

			response := test.call(handler, server)
			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
			}
			if got := agentRequests.Load(); got != 0 {
				t.Fatalf("active installation reached Agent %d time(s)", got)
			}
		})
	}
}

func TestHandleInboundsHoldsLeaseThroughWSSPostSync(t *testing.T) {
	var inboundMu sync.RWMutex
	var storedInbound map[string]any
	nginxStarted := make(chan struct{})
	allowNginx := make(chan struct{})
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			inboundMu.RLock()
			inbounds := []map[string]any{}
			if storedInbound != nil {
				inbounds = append(inbounds, storedInbound)
			}
			inboundMu.RUnlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "inbounds": inbounds})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			var request struct {
				Inbound    map[string]any `json:"inbound"`
				MutationID string         `json:"mutation_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			inboundMu.Lock()
			storedInbound = request.Inbound
			inboundMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "mutation_id": request.MutationID})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/cert/deploy":
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/nginx/setup-ssl":
			close(nginxStarted)
			<-allowNginx
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			_, _ = w.Write([]byte(`{"success":true,"config":"{}"}`))
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	createRemoteDomainCertificate(t, repo, server.ID, "edge.example.test")
	handler := NewRemoteManageHandler(repo, nil)
	attachRemoteCertificateHandler(t, repo, handler)

	body := bytes.NewBufferString(`{"action":"add","inbound":{"tag":"wss-test","protocol":"vless","listen":"127.0.0.1","settings":{"clients":[]},"streamSettings":{"network":"ws","security":"none","wsSettings":{}}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/remote/inbounds?server_id="+leaseTestID(server.ID), body)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "lease-test-user"))
	response := httptest.NewRecorder()
	handlerDone := make(chan struct{})
	go func() {
		handler.HandleInbounds(response, request)
		close(handlerDone)
	}()

	select {
	case <-nginxStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("WSS post-sync did not reach nginx")
	}

	beginDone := make(chan error, 1)
	go func() {
		beginDone <- repo.BeginRemoteServerInstallation(context.Background(), server.ID, "wait-for-wss-sync", time.Now().Add(time.Minute))
	}()
	select {
	case err := <-beginDone:
		t.Fatalf("installation Begin escaped in-flight WSS sync lease: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(allowNginx)
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleInbounds did not finish")
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("BeginRemoteServerInstallation after WSS sync: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("installation Begin remained blocked after handler release")
	}
}

func TestHandleInboundsRollsBackWSSWhenPostSyncFails(t *testing.T) {
	var added atomic.Bool
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			inbounds := []map[string]any{}
			if added.Load() {
				inbounds = append(inbounds, map[string]any{
					"tag": "wss-partial", "protocol": "vless", "port": float64(11000), "listen": "127.0.0.1",
					"streamSettings": map[string]any{"network": "ws", "security": "none", "wsSettings": map[string]any{"path": "/ws/test"}},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "inbounds": inbounds})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			var request struct {
				Action     string `json:"action"`
				MutationID string `json:"mutation_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			added.Store(request.Action != "remove")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "mutation_id": request.MutationID})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/cert/deploy":
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/nginx/setup-ssl":
			http.Error(w, "nginx reload rejected", http.StatusInternalServerError)
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			_, _ = w.Write([]byte(`{"success":true,"config":"{}"}`))
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	createRemoteDomainCertificate(t, repo, server.ID, "edge.example.test")
	handler := NewRemoteManageHandler(repo, nil)
	attachRemoteCertificateHandler(t, repo, handler)
	body := bytes.NewBufferString(`{"action":"add","inbound":{"tag":"wss-partial","protocol":"vless","listen":"127.0.0.1","settings":{"clients":[]},"streamSettings":{"network":"ws","security":"none","wsSettings":{}}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/remote/inbounds?server_id="+leaseTestID(server.ID), body)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "lease-test-user"))
	response := httptest.NewRecorder()

	handler.HandleInbounds(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want CDN-safe 400", response.Code, response.Body.String())
	}
	payload := decodeResponseMap(t, response)
	if payload["success"] != false || payload["partial"] == true {
		t.Fatalf("unexpected rollback response: %#v", payload)
	}
	if added.Load() {
		t.Fatal("WSS inbound remained after nginx post-sync failed")
	}
}

func TestHandleAddWebsiteRequiresCertificateAndRestartACKs(t *testing.T) {
	t.Run("certificate rejection stops the flow", func(t *testing.T) {
		var certRequests atomic.Int64
		var laterRequests atomic.Int64
		agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/child/cert/deploy" {
				certRequests.Add(1)
				_, _ = w.Write([]byte(`{"success":false,"error":"disk full"}`))
				return
			}
			laterRequests.Add(1)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}))
		defer agent.Close()

		repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
		createRemoteDomainCertificate(t, repo, server.ID, "*.example.test")
		handler := NewRemoteManageHandler(repo, nil)
		attachRemoteCertificateHandler(t, repo, handler)
		body, _ := json.Marshal(map[string]any{
			"server_id": server.ID, "domain": "www.example.test", "site_type": "static", "site_value": "/srv/www",
		})
		response := httptest.NewRecorder()
		handler.HandleAddWebsite(response, httptest.NewRequest(http.MethodPost, "/api/remote/websites", bytes.NewReader(body)))

		if response.Code != http.StatusConflict {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		payload := decodeResponseMap(t, response)
		if payload["success"] != false || payload["partial"] != true {
			t.Fatalf("unexpected response: %#v", payload)
		}
		if certRequests.Load() != 1 || laterRequests.Load() != 0 {
			t.Fatalf("cert requests=%d later requests=%d", certRequests.Load(), laterRequests.Load())
		}
	})

	t.Run("restart rejection is partial failure", func(t *testing.T) {
		var restartRequests atomic.Int64
		agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/api/child/cert/deploy":
				_, _ = w.Write([]byte(`{"success":true}`))
			case r.URL.Path == "/api/child/nginx/setup-ssl":
				_, _ = w.Write([]byte(`{"success":true}`))
			case r.URL.Path == "/api/child/xray/config" && r.Method == http.MethodGet:
				config := `{"routing":{"rules":[{"outboundTag":"nginx","inboundTag":["tunnel-in"],"domain":[]}]}}`
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "config": config})
			case r.URL.Path == "/api/child/xray/config" && r.Method == http.MethodPost:
				_, _ = w.Write([]byte(`{"success":true}`))
			case r.URL.Path == "/api/child/services/control":
				restartRequests.Add(1)
				_, _ = w.Write([]byte(`{"success":false,"message":"failed to load config"}`))
			default:
				http.Error(w, "unexpected path", http.StatusNotFound)
			}
		}))
		defer agent.Close()

		repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
		createRemoteDomainCertificate(t, repo, server.ID, "*.example.test")
		handler := NewRemoteManageHandler(repo, nil)
		attachRemoteCertificateHandler(t, repo, handler)
		body, _ := json.Marshal(map[string]any{
			"server_id": server.ID, "domain": "www.example.test", "site_type": "static", "site_value": "/srv/www",
		})
		response := httptest.NewRecorder()
		handler.HandleAddWebsite(response, httptest.NewRequest(http.MethodPost, "/api/remote/websites", bytes.NewReader(body)))

		if response.Code != http.StatusConflict {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		payload := decodeResponseMap(t, response)
		if payload["success"] != false || payload["partial"] != true {
			t.Fatalf("unexpected response: %#v", payload)
		}
		if restartRequests.Load() != 1 {
			t.Fatalf("restart requests=%d, want 1", restartRequests.Load())
		}
	})
}

func TestHandleSetupSSLDoesNotReportCertificateFailureAsDeployed(t *testing.T) {
	var setupRequests atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/child/inbounds":
			_, _ = w.Write([]byte(`{"success":true,"inbounds":[]}`))
		case "/api/child/cert/deploy":
			_, _ = w.Write([]byte(`{"success":false,"error":"certificate write failed"}`))
		case "/api/child/nginx/setup-ssl":
			setupRequests.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	createRemoteDomainCertificate(t, repo, server.ID, "edge.example.test")
	handler := NewRemoteManageHandler(repo, nil)
	attachRemoteCertificateHandler(t, repo, handler)
	request := httptest.NewRequest(http.MethodPost, "/api/remote/setup-ssl?server_id="+leaseTestID(server.ID), nil)
	response := httptest.NewRecorder()

	handler.HandleSetupSSL(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	payload := decodeResponseMap(t, response)
	if payload["success"] != false || payload["cert_deployed"] != false {
		t.Fatalf("unexpected response: %#v", payload)
	}
	if setupRequests.Load() != 0 {
		t.Fatalf("nginx setup ran %d time(s) after certificate rejection", setupRequests.Load())
	}
}

func leaseTestID(value int64) string {
	return strconv.FormatInt(value, 10)
}
