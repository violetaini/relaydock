package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type packageLeaseAgent struct {
	requests        atomic.Int64
	addClientCalls  atomic.Int64
	serviceControls atomic.Int64
	restartStarted  chan struct{}
	releaseRestart  <-chan struct{}
	restartOnce     sync.Once
	batchResult     string
	runtimeWarnings []string
	xrayRunning     *bool
}

func (a *packageLeaseAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests.Add(1)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/batch-apply":
		result := a.batchResult
		if result == "" {
			result = "ok"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":          true,
			"inbound_results":  []string{result},
			"runtime_warnings": a.runtimeWarnings,
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		a.addClientCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control":
		a.serviceControls.Add(1)
		if a.restartStarted != nil {
			a.restartOnce.Do(func() { close(a.restartStarted) })
			if a.releaseRestart != nil {
				<-a.releaseRestart
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/services/status":
		running := true
		if a.xrayRunning != nil {
			running = *a.xrayRunning
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "xray": map[string]any{"installed": true, "running": running}})
	default:
		http.NotFound(w, r)
	}
}

func newPackageLeaseFixture(t *testing.T, agent http.Handler) (*storage.TrafficRepository, *storage.RemoteServer, *RemoteManageHandler) {
	t.Helper()
	agentServer := httptest.NewServer(agent)
	t.Cleanup(agentServer.Close)
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	if err := repo.CreateUser(context.Background(), "alice", "alice@example.test", "alice", "test-hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	return repo, server, NewRemoteManageHandler(repo, nil)
}

func packageBatchItem(serverID int64) InboundClientAddItem {
	return InboundClientAddItem{
		Username:   "alice",
		ServerID:   serverID,
		InboundTag: "vless-in",
		Protocol:   "vless",
		Settings: map[string]any{
			"clients": []any{map[string]any{"id": "owner-id", "flow": "xtls-rprx-vision"}},
		},
	}
}

func TestInboundBatchActiveInstallationDoesNotReachAgentOrReserveCredential(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "package-batch-active", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	err := applyInboundClientsBatchToAgent(ctx, remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)})
	if !errors.Is(err, storage.ErrRemoteInstallationActive) {
		t.Fatalf("applyInboundClientsBatchToAgent error=%v, want ErrRemoteInstallationActive", err)
	}
	if got := agent.requests.Load(); got != 0 {
		t.Fatalf("active installation reached Agent %d time(s)", got)
	}
	if config, _ := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); config != nil {
		t.Fatalf("active installation reserved credential: %+v", config)
	}
}

func TestInboundBatchNoOpDoesNotRestartXray(t *testing.T) {
	restartStarted := make(chan struct{})
	agent := &packageLeaseAgent{
		restartStarted: restartStarted,
		batchResult:    "ok (no-op)",
	}
	repo, server, remote := newPackageLeaseFixture(t, agent)

	if err := applyInboundClientsBatchToAgent(context.Background(), remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)}); err != nil {
		t.Fatalf("applyInboundClientsBatchToAgent: %v", err)
	}
	select {
	case <-restartStarted:
		t.Fatal("idempotent inbound batch unexpectedly restarted Xray")
	case <-time.After(100 * time.Millisecond):
	}

	config, err := repo.GetUserInboundConfig(context.Background(), "alice", server.ID, "vless-in")
	if err != nil || config == nil {
		t.Fatalf("credential was not reserved before Agent publish: config=%+v err=%v", config, err)
	}
}

func TestInboundBatchRuntimeWarningDoesNotRestartXray(t *testing.T) {
	agent := &packageLeaseAgent{runtimeWarnings: []string{"vless-in: runtime apply deferred"}}
	repo, server, remote := newPackageLeaseFixture(t, agent)

	if err := applyInboundClientsBatchToAgent(context.Background(), remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)}); err != nil {
		t.Fatalf("applyInboundClientsBatchToAgent: %v", err)
	}
	if got := agent.serviceControls.Load(); got != 0 {
		t.Fatalf("runtime warning made %d Xray control request(s)", got)
	}
}

func TestPackageInboundUnbindActiveInstallationKeepsRemoteAndDatabaseState(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	config := storage.UserInboundConfig{
		Username:       "alice",
		ServerID:       server.ID,
		InboundTag:     "vless-in",
		Protocol:       "vless",
		CredentialJSON: `{"id":"alice-id","email":"alice__vless-in"}`,
	}
	if err := repo.SaveUserInboundConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "package-unbind-active", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	_, err := removePackageUserInboundConfig(ctx, remote, repo, config)
	if !errors.Is(err, storage.ErrRemoteInstallationActive) {
		t.Fatalf("removePackageUserInboundConfig error=%v, want ErrRemoteInstallationActive", err)
	}
	if got := agent.requests.Load(); got != 0 {
		t.Fatalf("active installation reached Agent %d time(s)", got)
	}
	if stored, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); err != nil || stored == nil {
		t.Fatalf("active installation removed credential state: stored=%+v err=%v", stored, err)
	}
}

func TestInboundBatchRejectionIsReportedWithoutPerItemFallback(t *testing.T) {
	var addClientCalls atomic.Int64
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/batch-apply":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "rejected for test"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			addClientCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true})
		default:
			http.NotFound(w, r)
		}
	})
	repo, server, remote := newPackageLeaseFixture(t, agent)

	warnings := applyInboundBatchOrFallback(
		context.Background(), remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)}, "PackageLeaseTest",
	)
	if len(warnings) == 0 {
		t.Fatal("rejected batch was reported as success")
	}
	if got := addClientCalls.Load(); got != 0 {
		t.Fatalf("rejected batch unexpectedly fell back to add-client %d time(s)", got)
	}
}
