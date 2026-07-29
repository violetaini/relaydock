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
	requests       atomic.Int64
	addClientCalls atomic.Int64
	restartStarted chan struct{}
	releaseRestart <-chan struct{}
	restartOnce    sync.Once
	batchResult    string
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
			"success":         true,
			"inbound_results": []string{result},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		a.addClientCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control":
		if a.restartStarted != nil {
			a.restartOnce.Do(func() { close(a.restartStarted) })
			if a.releaseRestart != nil {
				<-a.releaseRestart
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/services/status":
		_ = json.NewEncoder(w).Encode(map[string]any{"xray": map[string]any{"running": true}})
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

func TestInstallationBeginWaitsForInboundBatchRestartAndReservation(t *testing.T) {
	restartStarted := make(chan struct{})
	releaseRestart := make(chan struct{})
	agent := &packageLeaseAgent{
		restartStarted: restartStarted,
		releaseRestart: releaseRestart,
		batchResult:    "ok (no-op)",
	}
	repo, server, remote := newPackageLeaseFixture(t, agent)

	applyDone := make(chan error, 1)
	go func() {
		applyDone <- applyInboundClientsBatchToAgent(context.Background(), remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)})
	}()
	select {
	case <-restartStarted:
	case err := <-applyDone:
		t.Fatalf("batch apply returned before required restart: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("batch apply did not reach required restart")
	}

	config, err := repo.GetUserInboundConfig(context.Background(), "alice", server.ID, "vless-in")
	if err != nil || config == nil {
		t.Fatalf("credential was not reserved before Agent publish: config=%+v err=%v", config, err)
	}

	beginDone := make(chan error, 1)
	go func() {
		beginDone <- repo.BeginRemoteServerInstallation(context.Background(), server.ID, "package-batch-wait", time.Now().Add(time.Minute))
	}()
	select {
	case err := <-beginDone:
		t.Fatalf("installation Begin returned during required restart: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseRestart)
	if err := <-applyDone; err != nil {
		t.Fatalf("applyInboundClientsBatchToAgent: %v", err)
	}
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("Begin after batch transaction: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Begin remained blocked after batch transaction")
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
