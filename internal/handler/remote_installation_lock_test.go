package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func newRemoteInstallationHandlerRepo(t *testing.T, listenPort int) (*storage.TrafficRepository, *storage.RemoteServer) {
	return newRemoteInstallationHandlerRepoWithSteal(t, listenPort, true)
}

func newRemoteInstallationHandlerRepoWithSteal(t *testing.T, listenPort int, stealSelf bool) (*storage.TrafficRepository, *storage.RemoteServer) {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "installation-handler.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name:           "installation-handler-edge",
		Token:          "installation-handler-token",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket,
		IPAddress:      "127.0.0.1",
		ListenPort:     listenPort,
		Domain:         "edge.example.test",
		Use443:         true,
		StealSelf:      stealSelf,
		StealMode:      "tunnel",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	return repo, server
}

func testServerPort(t *testing.T, rawURL string) int {
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

func finalizeRemoteInstallationForTest(t *testing.T, repo *storage.TrafficRepository, serverID int64, nonce string) {
	t.Helper()
	ctx := context.Background()
	if err := repo.MarkRemoteServerInstallationReady(ctx, serverID, nonce); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerInstallationPrepared(ctx, serverID, nonce); err != nil {
		t.Fatal(err)
	}
	if err := repo.FinalizeRemoteServerInstallation(ctx, serverID, nonce); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteServerAdminHandlersConflictDuringInstallation(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "admin-handler-lock", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	handler := NewXrayServerHandler(repo, nil, nil)

	deleteBody, err := json.Marshal(RemoteServerDeleteRequest{ID: server.ID, UninstallAgent: true})
	if err != nil {
		t.Fatal(err)
	}
	deleteRequest := httptest.NewRequest(http.MethodPost, "/api/remote-servers/delete", bytes.NewReader(deleteBody))
	deleteResponse := httptest.NewRecorder()
	handler.DeleteRemoteServer(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusConflict {
		t.Fatalf("DeleteRemoteServer status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}

	updateBody, err := json.Marshal(RemoteServerUpdateRequest{ID: server.ID, Name: "new-handler-name"})
	if err != nil {
		t.Fatal(err)
	}
	updateRequest := httptest.NewRequest(http.MethodPut, "/api/remote-servers/update", bytes.NewReader(updateBody))
	updateResponse := httptest.NewRecorder()
	handler.UpdateRemoteServer(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusConflict {
		t.Fatalf("UpdateRemoteServer status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
}

func TestRemoteStreamReturnsHTTPConflictBeforeStartingSSE(t *testing.T) {
	var agentRequests int
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentRequests++
		http.Error(w, "unexpected Agent request", http.StatusInternalServerError)
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "stream-conflict", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	handler := NewRemoteManageHandler(repo, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/remote/xray/install-stream", nil)
	response := httptest.NewRecorder()

	handler.forwardStreamToRemote(response, req, server.ID, "/api/child/xray/install-stream")

	if response.Code != http.StatusConflict {
		t.Fatalf("stream conflict status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("stream conflict content-type=%q, want application/json", got)
	}
	if agentRequests != 0 {
		t.Fatalf("stream conflict reached the Agent %d time(s)", agentRequests)
	}
}

func TestRemoteStreamContextDeadlineCoversHTTPFallback(t *testing.T) {
	agentStarted := make(chan struct{})
	agentCanceled := make(chan struct{})
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(agentStarted)
		<-r.Context().Done()
		close(agentCanceled)
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewRemoteManageHandler(repo, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/remote/xray/install-stream", nil)
	response := httptest.NewRecorder()
	startedAt := time.Now()

	handler.forwardStreamToRemoteWithin(response, req, server.ID, "/api/child/xray/install-stream", 50*time.Millisecond)

	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("stream did not honor its context deadline: elapsed=%v", elapsed)
	}
	select {
	case <-agentStarted:
	default:
		t.Fatal("HTTP fallback did not reach the Agent")
	}
	select {
	case <-agentCanceled:
	case <-time.After(time.Second):
		t.Fatal("stream deadline was not propagated to the Agent request")
	}
	if got := response.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("stream timeout content-type=%q, want text/event-stream", got)
	}
}

func TestRemoteSSECompletionTrackerRequiresExplicitSuccessfulTerminal(t *testing.T) {
	for _, tt := range []struct {
		name    string
		chunks  []string
		success bool
	}{
		{name: "complete", chunks: []string{`data: {"type":"complete","success":true}` + "\n\n"}, success: true},
		{name: "fragmented complete", chunks: []string{`data: {"type":"comp`, `lete","success":true}` + "\n\n"}, success: true},
		{name: "output only", chunks: []string{`data: {"type":"output","data":"done"}` + "\n\n"}},
		{name: "error", chunks: []string{`data: {"type":"error","message":"failed"}` + "\n\n"}},
		{name: "error before complete", chunks: []string{`data: {"type":"error"}` + "\n", `data: {"type":"complete","success":true}` + "\n"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			tracker := &remoteSSECompletionTracker{writer: &output}
			for _, chunk := range tt.chunks {
				if _, err := tracker.Write([]byte(chunk)); err != nil {
					t.Fatal(err)
				}
			}
			if got := tracker.succeeded(); got != tt.success {
				t.Fatalf("succeeded=%v want=%v, stream=%q", got, tt.success, output.String())
			}
		})
	}
}

func TestXrayInstallStreamOnlyDeploysDeferredConfigAfterFirstInstallSuccess(t *testing.T) {
	for _, tt := range []struct {
		name             string
		initialInstalled bool
		stealSelf        bool
		streamError      bool
		wantDeploy       bool
	}{
		{name: "first install", stealSelf: true, wantDeploy: true},
		{name: "stream error", stealSelf: true, streamError: true},
		{name: "core update", initialInstalled: true, stealSelf: true},
		{name: "non takeover first install", stealSelf: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var installed atomic.Bool
			installed.Store(tt.initialInstalled)
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/child/services/status":
					ready := installed.Load()
					_ = json.NewEncoder(w).Encode(map[string]any{
						"success": true,
						"xray":    map[string]any{"installed": ready, "running": ready},
					})
				case r.Method == http.MethodPost && r.URL.Path == "/api/child/xray/install-stream":
					w.Header().Set("Content-Type", "text/event-stream")
					if tt.streamError {
						_, _ = io.WriteString(w, "data: {\"type\":\"error\",\"message\":\"install failed\"}\n\n")
						return
					}
					installed.Store(true)
					_, _ = io.WriteString(w, "data: {\"type\":\"complete\",\"success\":true}\n\n")
				default:
					http.NotFound(w, r)
				}
			}))
			defer agent.Close()

			repo, server := newRemoteInstallationHandlerRepoWithSteal(t, testServerPort(t, agent.URL), tt.stealSelf)
			if err := repo.UpdateRemoteServerXrayMode(context.Background(), server.ID, "external"); err != nil {
				t.Fatal(err)
			}
			var deployCalls atomic.Int32
			handler := NewRemoteManageHandler(repo, nil)
			handler.SetStealSelfDeployer(func(context.Context, int64) error {
				deployCalls.Add(1)
				return nil
			})
			request := httptest.NewRequest(http.MethodPost, "/api/admin/remote/xray/install-stream?server_id="+strconv.FormatInt(server.ID, 10), nil)
			response := httptest.NewRecorder()
			handler.HandleXrayInstallStream(response, request)

			if got := deployCalls.Load(); got != map[bool]int32{true: 1, false: 0}[tt.wantDeploy] {
				t.Fatalf("deploy calls=%d wantDeploy=%v, body=%s", got, tt.wantDeploy, response.Body.String())
			}
			if tt.streamError && !strings.Contains(response.Body.String(), `"type":"error"`) {
				t.Fatalf("stream error was not preserved: %s", response.Body.String())
			}
			if !tt.streamError && strings.Contains(response.Body.String(), "post-install verification failed") {
				t.Fatalf("successful stream reported post-install failure: %s", response.Body.String())
			}
		})
	}
}

func TestXrayInstallStreamRetriesPersistedDeferredConfigWithoutChangingOrdinaryUpdates(t *testing.T) {
	var installed atomic.Bool
	installed.Store(true)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/services/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"xray":    map[string]any{"installed": installed.Load(), "running": installed.Load()},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/xray/install-stream":
			_, _ = io.WriteString(w, "data: {\"type\":\"complete\",\"success\":true}\n\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.UpdateRemoteServerXrayMode(context.Background(), server.ID, "external"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetRemoteServerXrayBootstrapPending(context.Background(), server.ID, true); err != nil {
		t.Fatal(err)
	}

	var deployCalls atomic.Int32
	failDeploy := atomic.Bool{}
	failDeploy.Store(true)
	handler := NewRemoteManageHandler(repo, nil)
	handler.SetStealSelfDeployer(func(context.Context, int64) error {
		deployCalls.Add(1)
		if failDeploy.Load() {
			return errors.New("temporary deployment failure")
		}
		return nil
	})

	run := func() string {
		request := httptest.NewRequest(http.MethodPost, "/api/admin/remote/xray/install-stream?server_id="+strconv.FormatInt(server.ID, 10), nil)
		response := httptest.NewRecorder()
		handler.HandleXrayInstallStream(response, request)
		return response.Body.String()
	}
	if body := run(); !strings.Contains(body, "post-install verification failed") {
		t.Fatalf("failed deferred deployment was not reported: %s", body)
	}
	pending, err := repo.RemoteServerXrayBootstrapPending(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("failed deferred deployment cleared its retry marker")
	}

	failDeploy.Store(false)
	if body := run(); strings.Contains(body, `"type":"error"`) {
		t.Fatalf("deferred deployment retry failed: %s", body)
	}
	pending, err = repo.RemoteServerXrayBootstrapPending(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("successful deferred deployment retained its retry marker")
	}
	if got := deployCalls.Load(); got != 2 {
		t.Fatalf("deploy calls=%d want=2", got)
	}

	if body := run(); strings.Contains(body, `"type":"error"`) {
		t.Fatalf("ordinary Xray update failed: %s", body)
	}
	if got := deployCalls.Load(); got != 2 {
		t.Fatalf("ordinary update redeployed existing config: deploy calls=%d", got)
	}
}

func TestHandleScanResultDoesNotAutoDeployStoppedXray(t *testing.T) {
	var agentRequests atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentRequests.Add(1)
		http.Error(w, "scan result must not call the Agent", http.StatusInternalServerError)
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	deployed := make(chan struct{}, 1)
	handler := NewRemoteManageHandler(repo, nil)
	handler.SetStealSelfDeployer(func(context.Context, int64) error {
		deployed <- struct{}{}
		return nil
	})

	// A stopped core may have been stopped explicitly by the administrator.
	// Scanning may persist that status but must not inspect/write its config,
	// invoke the 443 deployer, or start the core.
	handler.HandleScanResult(server.ID, WSScanResultPayload{XrayRunning: false})
	select {
	case <-deployed:
		t.Fatal("scan result invoked automatic deployment for a stopped Xray core")
	case <-time.After(150 * time.Millisecond):
	}
	if got := agentRequests.Load(); got != 0 {
		t.Fatalf("scan result made %d unexpected Agent request(s)", got)
	}

	updated, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.XrayRunning {
		t.Fatal("scan result did not persist the stopped Xray status")
	}
}

func TestWSFirstConnectAutoDeployRechecksInstallationLock(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	deployed := make(chan struct{}, 4)
	handler := NewRemoteWSHandler(repo, nil)
	handler.SetStealSelfDeployer(func(context.Context, int64) error {
		deployed <- struct{}{}
		return nil
	})

	ctx := context.Background()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "active-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	handler.scheduleFirstConnectAutoDeploy(server, 0)
	select {
	case <-deployed:
		t.Fatal("active installation passed WS pre-queue gate")
	case <-time.After(50 * time.Millisecond):
	}
	finalizeRemoteInstallationForTest(t, repo, server.ID, "active-install")

	handler.scheduleFirstConnectAutoDeploy(server, 80*time.Millisecond)
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "late-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-deployed:
		t.Fatal("late installation passed WS in-goroutine gate")
	case <-time.After(150 * time.Millisecond):
	}
	finalizeRemoteInstallationForTest(t, repo, server.ID, "late-install")

	handler.scheduleFirstConnectAutoDeploy(server, 0)
	select {
	case <-deployed:
	case <-time.After(time.Second):
		t.Fatal("finalized installation remained blocked on WS auto-deploy")
	}
}

func TestWSAutoDeployLeaseDrainsBeforeInstallationBegin(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	deployStarted := make(chan struct{})
	releaseDeploy := make(chan struct{})
	handler := NewRemoteWSHandler(repo, nil)
	handler.SetStealSelfDeployer(func(context.Context, int64) error {
		close(deployStarted)
		<-releaseDeploy
		return nil
	})
	handler.scheduleFirstConnectAutoDeploy(server, 0)
	select {
	case <-deployStarted:
	case <-time.After(time.Second):
		t.Fatal("WS auto-deploy did not start")
	}

	beginAttempted := make(chan struct{})
	beginDone := make(chan error, 1)
	go func() {
		close(beginAttempted)
		beginDone <- repo.BeginRemoteServerInstallation(context.Background(), server.ID, "drain-nonce", time.Now().Add(time.Minute))
	}()
	<-beginAttempted
	select {
	case err := <-beginDone:
		t.Fatalf("Begin returned before WS mutation completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseDeploy)
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("Begin after WS mutation drain: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Begin remained blocked after WS mutation completed")
	}
}

func TestRemoteInstallationAutoDeployGateFailsClosedOnRepositoryError(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	if remoteInstallationAllowsAutoDeploy(context.Background(), repo, server.ID, "test") {
		t.Fatal("repository query failure allowed automatic deployment")
	}
}

func TestHandleScanResultSkipsInboundSyncDuringInstallation(t *testing.T) {
	requested := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested <- struct{}{}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "inbounds": []any{}})
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "sync-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	NewRemoteManageHandler(repo, nil).HandleScanResult(server.ID, WSScanResultPayload{XrayRunning: true})
	select {
	case <-requested:
		t.Fatal("active installation allowed scan_result inbound sync")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandleScanResultUsesExclusiveLeaseWithoutUpgradeFailure(t *testing.T) {
	requested := make(chan string, 4)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested <- r.URL.Path
		switch r.URL.Path {
		case "/api/child/inbounds":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "inbounds": []any{},
				"mutation_fence_known": true, "mutation_owners": map[string]string{},
			})
		case "/api/child/xray/config":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "config": `{"inbounds":[],"routing":{"rules":[]}}`})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))

	NewRemoteManageHandler(repo, nil).HandleScanResult(server.ID, WSScanResultPayload{XrayRunning: true})
	select {
	case path := <-requested:
		if path != "/api/child/inbounds" {
			t.Fatalf("first sync request=%q", path)
		}
	case <-time.After(time.Second):
		t.Fatal("scan_result did not reach Agent inbound inventory; lease upgrade likely failed")
	}
}

func TestFinalizeRemoteInstallationRefreshesXrayStatusAfterLeaseRelease(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/child/services/status" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"xray": map[string]any{
				"running": true,
				"version": "Xray 25.7.26",
			},
		})
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	const nonce = "finalize-status-refresh"
	ctx := context.Background()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, nonce, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerInstallationReady(ctx, server.ID, nonce); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerInstallationPrepared(ctx, server.ID, nonce); err != nil {
		t.Fatal(err)
	}

	handler := NewXrayServerHandler(repo, nil, nil)
	handler.SetRemoteManager(NewRemoteManageHandler(repo, nil))
	request := httptest.NewRequest(http.MethodPost, "/api/remote/install-finalize", nil)
	request.Header.Set("Authorization", "Bearer "+server.Token)
	request.Header.Set(remoteInstallationNonceHeader, nonce)
	response := httptest.NewRecorder()
	handler.FinalizeRemoteInstallation(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("finalize status=%d body=%s", response.Code, response.Body.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		stored, err := repo.GetRemoteServer(ctx, server.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.XrayRunning && stored.XrayVersion == "Xray 25.7.26" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("finalized server status was not refreshed: running=%v version=%q", stored.XrayRunning, stored.XrayVersion)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPrepareRemoteInstallationDefersStealSelfUntilExternalXrayExists(t *testing.T) {
	for _, tt := range []struct {
		name           string
		installed      bool
		wantDeployCall bool
	}{
		{name: "missing", installed: false, wantDeployCall: false},
		{name: "installed", installed: true, wantDeployCall: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/child/services/status" || r.Method != http.MethodGet {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"xray":    map[string]any{"installed": tt.installed, "running": tt.installed},
				})
			}))
			defer agent.Close()

			repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
			if err := repo.UpdateRemoteServerXrayMode(context.Background(), server.ID, "external"); err != nil {
				t.Fatal(err)
			}
			const nonce = "prepare-external-xray-state"
			if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, nonce, time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if err := repo.MarkRemoteServerInstallationReady(context.Background(), server.ID, nonce); err != nil {
				t.Fatal(err)
			}

			deployed := false
			remote := NewRemoteManageHandler(repo, nil)
			remote.SetStealSelfDeployer(func(context.Context, int64) error {
				deployed = true
				return nil
			})
			handler := NewXrayServerHandler(repo, nil, nil)
			handler.SetRemoteManager(remote)
			request := httptest.NewRequest(http.MethodPost, "/api/remote/install-prepare", nil)
			request.Header.Set("Authorization", "Bearer "+server.Token)
			request.Header.Set(remoteInstallationNonceHeader, nonce)
			response := httptest.NewRecorder()
			handler.PrepareRemoteInstallation(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("prepare status=%d body=%s", response.Code, response.Body.String())
			}
			if deployed != tt.wantDeployCall {
				t.Fatalf("deployed=%v want=%v", deployed, tt.wantDeployCall)
			}
			pending, err := repo.RemoteServerXrayBootstrapPending(context.Background(), server.ID)
			if err != nil {
				t.Fatal(err)
			}
			if pending != !tt.installed {
				t.Fatalf("bootstrap pending=%v want=%v", pending, !tt.installed)
			}
		})
	}
}

func TestSnapshotSyncRechecksLockAfterRemoteRead(t *testing.T) {
	configRequested := make(chan struct{}, 1)
	releaseConfig := make(chan struct{})
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/child/xray/config" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		configRequested <- struct{}{}
		<-releaseConfig
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"config":  `{"inbounds":[{"tag":"temporary","protocol":"vless"}]}`,
		})
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewRemoteManageHandler(repo, nil)
	done := make(chan struct{})
	go func() {
		handler.SyncXrayConfigOnReconnect(context.Background(), server.ID, storage.RemoteServerStatusConnected)
		close(done)
	}()
	select {
	case <-configRequested:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot sync did not fetch remote config")
	}
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "snapshot-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	close(releaseConfig)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot sync did not return")
	}
	snapshot, err := repo.GetCurrentXraySnapshot(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot != nil {
		t.Fatalf("installation-time config was snapshotted: %+v", snapshot)
	}
}

func TestSnapshotRestoreRechecksLockImmediatelyBeforePut(t *testing.T) {
	testRequested := make(chan struct{}, 1)
	releaseTest := make(chan struct{})
	configPut := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"config":  `{"inbounds":[],"outbounds":[]}`,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/xray/test-config":
			testRequested <- struct{}{}
			<-releaseTest
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/xray/config":
			configPut <- struct{}{}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if _, err := repo.UpsertCurrentXraySnapshot(context.Background(), server.ID,
		`{"inbounds":[{"tag":"stable","protocol":"vless"}],"outbounds":[]}`,
		storage.XraySnapshotSourceMasterWrite); err != nil {
		t.Fatal(err)
	}
	handler := NewRemoteManageHandler(repo, nil)
	handler.SetExpectRecovery(server.ID)
	done := make(chan struct{})
	go func() {
		handler.SyncXrayConfigOnReconnect(context.Background(), server.ID, storage.RemoteServerStatusOffline)
		close(done)
	}()
	select {
	case <-testRequested:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot restore did not validate config")
	}
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "restore-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	close(releaseTest)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot restore did not return")
	}
	select {
	case <-configPut:
		t.Fatal("installation acquired during config test did not block restore PUT")
	default:
	}
	if !handler.consumeExpectRecovery(server.ID) {
		t.Fatal("blocked restore lost the pending recovery intent")
	}
}

func TestXrayModeCorrectionSkipsDuringInstallation(t *testing.T) {
	requested := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested <- struct{}{}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.UpdateRemoteServerXrayMode(context.Background(), server.ID, "embedded"); err != nil {
		t.Fatal(err)
	}
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "mode-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	NewRemoteManageHandler(repo, nil).CorrectXrayModeDrift(context.Background(), server.ID, "external")
	select {
	case <-requested:
		t.Fatal("active installation allowed xray mode correction")
	case <-time.After(100 * time.Millisecond):
	}
}
