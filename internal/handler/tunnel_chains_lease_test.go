package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"miaomiaowux/internal/storage"
)

func newTunnelChainTestRepo(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "tunnel-chain.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func tunnelChainAgentPort(t *testing.T, rawURL string) int {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func createTunnelChainRemoteServer(t *testing.T, repo *storage.TrafficRepository, name, agentURL string) *storage.RemoteServer {
	t.Helper()
	server := &storage.RemoteServer{
		Name:           name,
		Token:          name + "-token",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModePush,
		IPAddress:      "127.0.0.1",
		IPv6Enabled:    true,
		ListenPort:     tunnelChainAgentPort(t, agentURL),
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatalf("CreateRemoteServer(%s): %v", name, err)
	}
	return server
}

func tunnelChainRequest(t *testing.T, serverIDs []int64) *http.Request {
	t.Helper()
	body, err := json.Marshal(createChainReq{
		Label:         "lease-test",
		ServerIDs:     serverIDs,
		EntryPort:     25000,
		TargetAddress: "target.example.test",
		TargetPort:    443,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPost, "/api/admin/tunnel-chains", bytes.NewReader(body))
}

func writeEmptyXrayConfig(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"config":  `{"inbounds":[]}`,
	})
}

func TestTunnelChainRejectsAnyActiveInstallationBeforeAgentRequest(t *testing.T) {
	var agentRequests atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		agentRequests.Add(1)
		http.Error(w, "unexpected Agent request", http.StatusInternalServerError)
	}))
	defer agent.Close()

	repo := newTunnelChainTestRepo(t)
	first := createTunnelChainRemoteServer(t, repo, "tunnel-chain-first", agent.URL)
	second := createTunnelChainRemoteServer(t, repo, "tunnel-chain-second", agent.URL)
	if err := repo.BeginRemoteServerInstallation(context.Background(), second.ID, "active-chain-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("BeginRemoteServerInstallation: %v", err)
	}

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	// Reverse request order to verify acquisition does not depend on hop order.
	handler.ServeHTTP(response, tunnelChainRequest(t, []int64{second.ID, first.ID}))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if got := agentRequests.Load(); got != 0 {
		t.Fatalf("active installation reached Agent %d time(s)", got)
	}

	// The earlier lease must be released when a later server rejects acquisition.
	if err := repo.BeginRemoteServerInstallation(context.Background(), first.ID, "after-partial-acquire", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("lease acquired before conflict was not released: %v", err)
	}
}

func TestTunnelChainFailureRollsBackSynchronouslyWhileHoldingAllLeases(t *testing.T) {
	rollbackStarted := make(chan struct{})
	allowRollback := make(chan struct{})
	var firstActionsMu sync.Mutex
	var firstActions []string
	firstAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			writeEmptyXrayConfig(w)
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			var request struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			firstActionsMu.Lock()
			firstActions = append(firstActions, request.Action)
			firstActionsMu.Unlock()
			if request.Action == "remove" {
				close(rollbackStarted)
				<-allowRollback
			}
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer firstAgent.Close()

	var secondActionsMu sync.Mutex
	var secondActions []string
	secondAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config" {
			writeEmptyXrayConfig(w)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds" {
			var request struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			secondActionsMu.Lock()
			secondActions = append(secondActions, request.Action)
			secondActionsMu.Unlock()
			if request.Action == "remove" {
				_, _ = w.Write([]byte(`{"success":true}`))
				return
			}
			http.Error(w, "forced second-hop failure", http.StatusBadGateway)
			return
		}
		http.NotFound(w, r)
	}))
	defer secondAgent.Close()

	repo := newTunnelChainTestRepo(t)
	first := createTunnelChainRemoteServer(t, repo, "rollback-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "rollback-second", secondAgent.URL)
	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handlerDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, tunnelChainRequest(t, []int64{first.ID, second.ID}))
		close(handlerDone)
	}()

	select {
	case <-rollbackStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("rollback did not start")
	}
	select {
	case <-handlerDone:
		t.Fatal("handler returned before rollback Agent acknowledgement")
	default:
	}

	beginResults := make(chan error, 2)
	for _, serverID := range []int64{first.ID, second.ID} {
		serverID := serverID
		go func() {
			beginResults <- repo.BeginRemoteServerInstallation(context.Background(), serverID, "wait-for-chain-rollback-"+strconv.FormatInt(serverID, 10), time.Now().Add(time.Minute))
		}()
	}
	select {
	case err := <-beginResults:
		t.Fatalf("installation acquired a server before chain rollback completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(allowRollback)
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return after rollback acknowledgement")
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-beginResults:
			if err != nil {
				t.Fatalf("installation did not acquire released lease: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("installation remained blocked after chain rollback")
		}
	}
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "已确认回滚") {
		t.Fatalf("response does not report confirmed rollback: %s", response.Body.String())
	}
	firstActionsMu.Lock()
	actions := append([]string(nil), firstActions...)
	firstActionsMu.Unlock()
	if got := strings.Join(actions, ","); got != "add,remove" {
		t.Fatalf("first Agent actions=%q, want add,remove", got)
	}
	secondActionsMu.Lock()
	secondActionLog := append([]string(nil), secondActions...)
	secondActionsMu.Unlock()
	if got := strings.Join(secondActionLog, ","); got != "add,remove" {
		t.Fatalf("second Agent actions=%q, want add,remove", got)
	}
}

func TestTunnelChainDoesNotClaimRollbackSuccessWithoutAgentAck(t *testing.T) {
	firstAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config" {
			writeEmptyXrayConfig(w)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds" {
			var request struct {
				Action string `json:"action"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.Action == "remove" {
				http.Error(w, "rollback rejected", http.StatusBadGateway)
				return
			}
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer firstAgent.Close()
	secondAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config" {
			writeEmptyXrayConfig(w)
			return
		}
		http.Error(w, "add rejected", http.StatusBadGateway)
	}))
	defer secondAgent.Close()

	repo := newTunnelChainTestRepo(t)
	first := createTunnelChainRemoteServer(t, repo, "rollback-failure-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "rollback-failure-second", secondAgent.URL)
	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequest(t, []int64{first.ID, second.ID}))

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "回滚未完整确认") {
		t.Fatalf("response hides rollback failure: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "已确认回滚") {
		t.Fatalf("response falsely claims rollback success: %s", response.Body.String())
	}
}
