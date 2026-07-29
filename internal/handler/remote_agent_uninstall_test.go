package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

const testCleanupID = "0123456789abcdef0123456789abcdef"

func newAgentUninstallHandler(
	t *testing.T,
	agent http.Handler,
	wsCapabilities *AgentCapabilities,
) (*XrayServerHandler, *storage.TrafficRepository, *storage.RemoteServer) {
	t.Helper()
	agentServer := httptest.NewServer(agent)
	t.Cleanup(agentServer.Close)
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	wsHandler := NewRemoteWSHandler(repo, nil)
	if wsCapabilities != nil {
		wsHandler.conns.Store(server.Token, &RemoteWSConnection{
			ServerID: server.ID, ServerName: server.Name, Token: server.Token,
			Capabilities: *wsCapabilities,
		})
	}
	remoteManager := NewRemoteManageHandler(repo, wsHandler)
	handler := NewXrayServerHandler(repo, nil, nil)
	handler.SetWSHandler(wsHandler)
	handler.SetRemoteManager(remoteManager)
	callbackServer := httptest.NewServer(http.HandlerFunc(handler.HandleAgentUninstallComplete))
	t.Cleanup(callbackServer.Close)
	if err := repo.SetSystemSetting(context.Background(), "master_url", callbackServer.URL); err != nil {
		t.Fatal(err)
	}
	return handler, repo, server
}

func requestRemoteServerDelete(t *testing.T, handler *XrayServerHandler, serverID int64, uninstallAgent bool) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(RemoteServerDeleteRequest{ID: serverID, UninstallAgent: uninstallAgent})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/remote-servers/delete", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.DeleteRemoteServer(response, request)
	return response
}

func decodeUninstallDispatch(r *http.Request) (agentUninstallDispatchRequest, error) {
	var request agentUninstallDispatchRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return request, errors.New("dispatch contains trailing JSON")
	}
	if request.CallbackURL == "" || request.CallbackToken == "" {
		return request, errors.New("dispatch is missing callback fields")
	}
	return request, nil
}

func postUninstallCallback(dispatch agentUninstallDispatchRequest, callback agentUninstallCallback) (int, error) {
	body, err := json.Marshal(callback)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequest(http.MethodPost, dispatch.CallbackURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+dispatch.CallbackToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, nil
}

func writeDispatchAck(w http.ResponseWriter, cleanupID string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true, "dispatch_verified": true, "cleanup_id": cleanupID,
	})
}

func TestDeleteRemoteServerWaitsForWarpAndAgentCompletionBeforeDeletingRecord(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/child/warp/status":
			_, _ = w.Write([]byte(`{"success":true,"installed":true}`))
		case "/api/child/warp/remove":
			_, _ = w.Write([]byte(`{"success":true,"uninstalled":true}`))
		case "/api/child/agent/uninstall-v2":
			dispatch, err := decodeUninstallDispatch(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Exercise the race where cleanup finishes before the dispatch HTTP
			// response reaches the panel.
			if status, err := postUninstallCallback(dispatch, agentUninstallCallback{Success: true, CleanupID: testCleanupID}); err != nil || status != http.StatusOK {
				http.Error(w, "callback failed", http.StatusInternalServerError)
				return
			}
			writeDispatchAck(w, testCleanupID)
		default:
			http.NotFound(w, r)
		}
	})
	capabilities := AgentCapabilities{AgentUninstallV2: true}
	handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)
	if err := repo.UpdateRemoteServerWarpInstalled(context.Background(), server.Token, false); err != nil {
		t.Fatal(err)
	}

	response := requestRemoteServerDelete(t, handler, server.ID, true)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := repo.GetRemoteServer(context.Background(), server.ID); !errors.Is(err, storage.ErrRemoteServerNotFound) {
		t.Fatalf("server still exists after completed uninstall: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"/api/child/warp/status", "/api/child/warp/remove", "/api/child/agent/uninstall-v2"}
	if len(calls) != len(want) {
		t.Fatalf("agent calls=%v want=%v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("agent calls=%v want=%v", calls, want)
		}
	}
}

func TestDeleteRemoteServerKeepsRecordUntilCompletionCallback(t *testing.T) {
	dispatches := make(chan agentUninstallDispatchRequest, 1)
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/warp/status":
			_, _ = w.Write([]byte(`{"success":true,"installed":false}`))
		case "/api/child/agent/uninstall-v2":
			dispatch, err := decodeUninstallDispatch(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			dispatches <- dispatch
			writeDispatchAck(w, testCleanupID)
		default:
			http.NotFound(w, r)
		}
	})
	capabilities := AgentCapabilities{AgentUninstallV2: true}
	handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)

	deleteDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { deleteDone <- requestRemoteServerDelete(t, handler, server.ID, true) }()
	dispatch := <-dispatches
	if persisted, err := repo.GetRemoteServer(context.Background(), server.ID); err != nil || persisted == nil {
		t.Fatalf("record removed before completion callback: server=%v err=%v", persisted, err)
	}
	if status, err := postUninstallCallback(dispatch, agentUninstallCallback{Success: true, CleanupID: testCleanupID}); err != nil || status != http.StatusOK {
		t.Fatalf("callback status=%d err=%v", status, err)
	}
	select {
	case response := <-deleteDone:
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delete did not finish after completion callback")
	}
}

func TestDeleteRemoteServerCompletionFailureAndTimeoutKeepRecord(t *testing.T) {
	tests := []struct {
		name       string
		callback   *agentUninstallCallback
		wantStatus int
	}{
		{name: "cleanup failure", callback: &agentUninstallCallback{Success: false, CleanupID: testCleanupID, Error: "cleanup verification failed"}, wantStatus: http.StatusBadGateway},
		{name: "callback timeout", callback: nil, wantStatus: http.StatusGatewayTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/child/warp/status":
					_, _ = w.Write([]byte(`{"success":true,"installed":false}`))
				case "/api/child/agent/uninstall-v2":
					dispatch, err := decodeUninstallDispatch(r)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					if test.callback != nil {
						if status, err := postUninstallCallback(dispatch, *test.callback); err != nil || status != http.StatusOK {
							http.Error(w, "callback failed", http.StatusInternalServerError)
							return
						}
					}
					writeDispatchAck(w, testCleanupID)
				default:
					http.NotFound(w, r)
				}
			})
			capabilities := AgentCapabilities{AgentUninstallV2: true}
			handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)
			handler.agentUninstallTimeout = 60 * time.Millisecond

			response := requestRemoteServerDelete(t, handler, server.ID, true)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if persisted, err := repo.GetRemoteServer(context.Background(), server.ID); err != nil || persisted == nil {
				t.Fatalf("record not retained: server=%v err=%v", persisted, err)
			}
		})
	}
}

func TestDeleteRemoteServerRejectsInvalidDispatchAck(t *testing.T) {
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/warp/status":
			_, _ = w.Write([]byte(`{"success":true,"installed":false}`))
		case "/api/child/agent/uninstall-v2":
			_, _ = w.Write([]byte(`{"success":true,"dispatch_verified":false,"cleanup_id":"0123456789abcdef0123456789abcdef"}`))
		default:
			http.NotFound(w, r)
		}
	})
	capabilities := AgentCapabilities{AgentUninstallV2: true}
	handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)
	response := requestRemoteServerDelete(t, handler, server.ID, true)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if persisted, err := repo.GetRemoteServer(context.Background(), server.ID); err != nil || persisted == nil {
		t.Fatalf("record not retained: server=%v err=%v", persisted, err)
	}
}

func TestDeleteRemoteServerWarpStatusFailsClosed(t *testing.T) {
	for _, responseBody := range []string{
		`{"success":false,"installed":false,"error":"status unavailable"}`,
		`{"success":true}`,
		`not-json`,
	} {
		t.Run(responseBody, func(t *testing.T) {
			var uninstallCalls int
			agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/child/warp/status":
					_, _ = w.Write([]byte(responseBody))
				case "/api/child/agent/uninstall-v2":
					uninstallCalls++
				default:
					http.NotFound(w, r)
				}
			})
			capabilities := AgentCapabilities{AgentUninstallV2: true}
			handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)
			result := requestRemoteServerDelete(t, handler, server.ID, true)
			if result.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
			}
			if uninstallCalls != 0 {
				t.Fatalf("uninstall ran %d times after untrusted WARP status", uninstallCalls)
			}
			if _, err := repo.GetRemoteServer(context.Background(), server.ID); err != nil {
				t.Fatalf("record not retained: %v", err)
			}
		})
	}
}

func TestDeleteRemoteServerProbesHTTPAgentCapabilityWithoutWS(t *testing.T) {
	var systemInfoCalls int
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/system/info":
			systemInfoCalls++
			_, _ = w.Write([]byte(`{"success":true,"capabilities":{"agent_uninstall_v2":true}}`))
		case "/api/child/warp/status":
			_, _ = w.Write([]byte(`{"success":true,"installed":false}`))
		case "/api/child/agent/uninstall-v2":
			dispatch, err := decodeUninstallDispatch(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if status, err := postUninstallCallback(dispatch, agentUninstallCallback{Success: true, CleanupID: testCleanupID}); err != nil || status != http.StatusOK {
				http.Error(w, "callback failed", http.StatusInternalServerError)
				return
			}
			writeDispatchAck(w, testCleanupID)
		default:
			http.NotFound(w, r)
		}
	})
	handler, repo, server := newAgentUninstallHandler(t, agent, nil)
	response := requestRemoteServerDelete(t, handler, server.ID, true)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if systemInfoCalls != 1 {
		t.Fatalf("system info calls=%d want=1", systemInfoCalls)
	}
	if _, err := repo.GetRemoteServer(context.Background(), server.ID); !errors.Is(err, storage.ErrRemoteServerNotFound) {
		t.Fatalf("server still exists: %v", err)
	}
}

func TestDeleteRemoteServerRejectsKnownUnsupportedWSAgent(t *testing.T) {
	var calls int
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ })
	capabilities := AgentCapabilities{RPC: true, Stream: true}
	handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)
	response := requestRemoteServerDelete(t, handler, server.ID, true)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if calls != 0 {
		t.Fatalf("unsupported Agent received %d calls", calls)
	}
	if _, err := repo.GetRemoteServer(context.Background(), server.ID); err != nil {
		t.Fatalf("record not retained: %v", err)
	}
}

func TestAgentUninstallCallbackRejectsInvalidCredentialMismatchAndReplay(t *testing.T) {
	repo, _ := newRemoteInstallationHandlerRepo(t, 23889)
	handler := NewXrayServerHandler(repo, nil, nil)
	if handler.agentUninstallTimeout < 420*time.Second {
		t.Fatalf("callback timeout=%s does not cover the Agent's 360s hard cleanup bound", handler.agentUninstallTimeout)
	}
	token, pending, err := handler.registerAgentUninstall(17)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.unregisterAgentUninstall(token, pending)
	if len(token) != 43 || strings.Contains(token, "=") {
		t.Fatalf("callback token does not satisfy Agent's raw base64url contract: %q", token)
	}
	if err := pending.setExpectedCleanupID(testCleanupID); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerDeletionDispatched(context.Background(), 17, agentUninstallTokenHash(token), testCleanupID); err != nil {
		t.Fatal(err)
	}

	requestCallback := func(bearer, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/remote/agent/uninstall-complete", bytes.NewBufferString(body))
		request.Header.Set("Authorization", "Bearer "+bearer)
		response := httptest.NewRecorder()
		handler.HandleAgentUninstallComplete(response, request)
		return response
	}
	if response := requestCallback("not-a-token", `{"success":true,"cleanup_id":"0123456789abcdef0123456789abcdef"}`); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid credential status=%d", response.Code)
	}
	if response := requestCallback(token, `{"success":true,"cleanup_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`); response.Code != http.StatusConflict {
		t.Fatalf("mismatched cleanup status=%d body=%s", response.Code, response.Body.String())
	}
	validBody := `{"success":true,"cleanup_id":"0123456789abcdef0123456789abcdef"}`
	if response := requestCallback(token, validBody); response.Code != http.StatusOK {
		t.Fatalf("valid callback status=%d body=%s", response.Code, response.Body.String())
	}
	if response := requestCallback(token, validBody); response.Code != http.StatusConflict {
		t.Fatalf("replay status=%d body=%s", response.Code, response.Body.String())
	}
	handler.unregisterAgentUninstall(token, pending)
	if response := requestCallback(token, validBody); response.Code != http.StatusConflict {
		t.Fatalf("durable replay status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDeleteRemoteServerIgnoresBrowserCancellationAfterDispatch(t *testing.T) {
	dispatches := make(chan agentUninstallDispatchRequest, 1)
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/warp/status":
			_, _ = w.Write([]byte(`{"success":true,"installed":false}`))
		case "/api/child/agent/uninstall-v2":
			dispatch, err := decodeUninstallDispatch(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			dispatches <- dispatch
			writeDispatchAck(w, testCleanupID)
		default:
			http.NotFound(w, r)
		}
	})
	capabilities := AgentCapabilities{AgentUninstallV2: true}
	handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)
	body, _ := json.Marshal(RemoteServerDeleteRequest{ID: server.ID, UninstallAgent: true})
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/api/admin/remote-servers/delete", bytes.NewReader(body)).WithContext(requestCtx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.DeleteRemoteServer(response, request)
		close(done)
	}()
	dispatch := <-dispatches
	cancelRequest()
	if status, err := postUninstallCallback(dispatch, agentUninstallCallback{Success: true, CleanupID: testCleanupID}); err != nil || status != http.StatusOK {
		t.Fatalf("callback status=%d err=%v", status, err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("delete was canceled with the browser request")
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := repo.GetRemoteServer(context.Background(), server.ID); !errors.Is(err, storage.ErrRemoteServerNotFound) {
		t.Fatalf("server still exists: %v", err)
	}
}

func TestDeleteRemoteServerUninstallHoldsExclusiveMutationLeaseUntilCallback(t *testing.T) {
	dispatches := make(chan agentUninstallDispatchRequest, 1)
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/warp/status":
			_, _ = w.Write([]byte(`{"success":true,"installed":false}`))
		case "/api/child/agent/uninstall-v2":
			dispatch, err := decodeUninstallDispatch(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			dispatches <- dispatch
			writeDispatchAck(w, testCleanupID)
		default:
			http.NotFound(w, r)
		}
	})
	capabilities := AgentCapabilities{AgentUninstallV2: true}
	handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)
	deleteDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { deleteDone <- requestRemoteServerDelete(t, handler, server.ID, true) }()
	dispatch := <-dispatches

	mutationStarted := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- repo.WithRemoteServerMutationLease(context.Background(), server.ID, func(context.Context) error {
			close(mutationStarted)
			return nil
		})
	}()
	select {
	case <-mutationStarted:
		t.Fatal("ordinary mutation entered while uninstall awaited completion")
	case <-time.After(100 * time.Millisecond):
	}
	if status, err := postUninstallCallback(dispatch, agentUninstallCallback{Success: true, CleanupID: testCleanupID}); err != nil || status != http.StatusOK {
		t.Fatalf("callback status=%d err=%v", status, err)
	}
	select {
	case result := <-deleteDone:
		if result.Code != http.StatusOK {
			t.Fatalf("delete status=%d body=%s", result.Code, result.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delete did not finish")
	}
	select {
	case err := <-mutationDone:
		if err != nil {
			t.Fatalf("queued mutation failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued mutation remained blocked")
	}
}

func TestDeleteRemoteServerRejectsFederatedAndForwardingConflictsBeforeAgentCall(t *testing.T) {
	t.Run("federated", func(t *testing.T) {
		var calls int
		capabilities := AgentCapabilities{AgentUninstallV2: true}
		handler, repo, server := newAgentUninstallHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }), &capabilities)
		if err := repo.SetFederatedServer(context.Background(), server.ID, "https://owner.example.test", "share-token", "shared-"); err != nil {
			t.Fatal(err)
		}
		response := requestRemoteServerDelete(t, handler, server.ID, true)
		if response.Code != http.StatusOK || calls != 0 {
			t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
		}
		if _, err := repo.GetRemoteServer(context.Background(), server.ID); !errors.Is(err, storage.ErrRemoteServerNotFound) {
			t.Fatalf("shared local record still exists: %v", err)
		}
	})
	t.Run("forwarding", func(t *testing.T) {
		var calls int
		capabilities := AgentCapabilities{AgentUninstallV2: true}
		handler, repo, server := newAgentUninstallHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }), &capabilities)
		second := storage.RemoteServer{Name: "peer", Token: "peer-token", Status: storage.RemoteServerStatusConnected, IPAddress: "127.0.0.2", XrayMode: "embedded"}
		if err := repo.CreateRemoteServer(context.Background(), &second); err != nil {
			t.Fatal(err)
		}
		for _, serverID := range []int64{server.ID, second.ID} {
			if _, err := repo.UpdateRemoteServerXrayStatus(context.Background(), serverID, true, "test"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := repo.CreateTunnelTemplate(context.Background(), storage.TunnelTemplate{
			Name: "conflict", State: storage.TunnelStateActive, Network: storage.ForwardNetworkTCPUDP,
			BillingMode: storage.ManagedBillingBoth, TrafficMultiplierMilli: 1000,
			PortRangeStart: 39000, PortRangeEnd: 40000, CreatedBy: "admin",
			Hops: []storage.TunnelTemplateHop{{ServerID: server.ID}, {ServerID: second.ID}},
		}); err != nil {
			t.Fatal(err)
		}
		response := requestRemoteServerDelete(t, handler, server.ID, true)
		if response.Code != http.StatusConflict || calls != 0 {
			t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
		}
	})
}

func TestDeleteOwnedRemoteServerWithoutUninstallIsRejected(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	handler := NewXrayServerHandler(repo, nil, nil)
	response := requestRemoteServerDelete(t, handler, server.ID, false)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := repo.GetRemoteServer(context.Background(), server.ID); err != nil {
		t.Fatalf("owned server changed after fail-closed request: %v", err)
	}
}

func TestDeleteSharedRemoteServerWaitsForOrdinaryServerMutation(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	if err := repo.SetFederatedServer(context.Background(), server.ID, "https://owner.example.test", "share-token", "shared-"); err != nil {
		t.Fatal(err)
	}
	handler := NewXrayServerHandler(repo, nil, nil)
	_, releaseMutation, err := repo.AcquireRemoteServerMutationLease(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	deleteDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { deleteDone <- requestRemoteServerDelete(t, handler, server.ID, false) }()
	select {
	case <-deleteDone:
		t.Fatal("record-only delete entered while an ordinary server mutation was active")
	case <-time.After(100 * time.Millisecond):
	}
	releaseMutation()
	select {
	case response := <-deleteDone:
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("record-only delete remained blocked after mutation release")
	}
}

func TestDeleteRemoteServerLeaseAcquisitionTimesOutWithoutDeleting(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	if err := repo.SetFederatedServer(context.Background(), server.ID, "https://owner.example.test", "share-token", "shared-"); err != nil {
		t.Fatal(err)
	}
	handler := NewXrayServerHandler(repo, nil, nil)
	handler.serverDeleteLeaseTimeout = 40 * time.Millisecond
	_, releaseMutation, err := repo.AcquireRemoteServerMutationLease(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	response := requestRemoteServerDelete(t, handler, server.ID, false)
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := repo.GetRemoteServer(context.Background(), server.ID); err != nil {
		t.Fatalf("record changed after lease timeout: %v", err)
	}
	// Let the abandoned acquisition goroutine observe its canceled context and
	// leave without ever retaining the exclusive lease.
	releaseMutation()
	deadline := time.Now().Add(time.Second)
	for {
		_, release, err := repo.AcquireRemoteServerMutationLease(context.Background(), server.ID)
		if err == nil {
			release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("abandoned exclusive acquisition did not unwind: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRemoteServerListReportsKnownAndUnknownAgentUninstallCapability(t *testing.T) {
	trueCapabilities := AgentCapabilities{AgentUninstallV2: true}
	handler, repo, server := newAgentUninstallHandler(t, http.NotFoundHandler(), &trueCapabilities)
	response := handler.BuildRemoteServersList(context.Background())
	if !response.Success || len(response.Servers) != 1 || response.Servers[0].AgentUninstallV2 == nil || !*response.Servers[0].AgentUninstallV2 {
		t.Fatalf("unexpected known-capable response: %+v", response)
	}
	connection, connected := handler.wsHandler.GetConnectionByServerID(server.ID)
	if !connected {
		t.Fatal("test WebSocket connection disappeared")
	}
	connection.Capabilities.AgentUninstallV2 = false
	response = handler.BuildRemoteServersList(context.Background())
	if response.Servers[0].AgentUninstallV2 == nil || *response.Servers[0].AgentUninstallV2 {
		t.Fatalf("known unsupported capability must be explicit false: %+v", response.Servers[0].AgentUninstallV2)
	}
	handler.wsHandler.conns.Delete(server.Token)
	response = handler.BuildRemoteServersList(context.Background())
	if response.Servers[0].AgentUninstallV2 != nil {
		t.Fatalf("HTTP-only capability must be unknown until confirmation: %+v", response.Servers[0].AgentUninstallV2)
	}
	if err := repo.SetFederatedServer(context.Background(), server.ID, "https://owner.example.test", "share-token", "shared-"); err != nil {
		t.Fatal(err)
	}
	response = handler.BuildRemoteServersList(context.Background())
	if response.Servers[0].AgentUninstallV2 != nil {
		t.Fatal("federated server advertised local Agent uninstall capability")
	}
}

func TestLegacyAgentUninstallStreamIsGone(t *testing.T) {
	handler := NewRemoteManageHandler(nil, nil)
	request := httptest.NewRequest(http.MethodPost, "/api/admin/remote/agent/uninstall-stream?server_id=7", nil)
	response := httptest.NewRecorder()
	handler.HandleAgentUninstallStream(response, request)
	if response.Code != http.StatusGone {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusGone, response.Body.String())
	}
}

func TestAgentUninstallCallbackSurvivesPanelRestartAndFinalizesDeletion(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	first := NewXrayServerHandler(repo, nil, nil)
	token, pending, err := first.registerAgentUninstall(server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerDeletionDispatched(context.Background(), server.ID, agentUninstallTokenHash(token), testCleanupID); err != nil {
		t.Fatal(err)
	}
	first.unregisterAgentUninstall(token, pending)

	restarted := NewXrayServerHandler(repo, nil, nil)
	body := `{"success":true,"cleanup_id":"` + testCleanupID + `"}`
	request := httptest.NewRequest(http.MethodPost, AgentUninstallCompletePath, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	restarted.HandleAgentUninstallComplete(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", response.Code, response.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := repo.GetRemoteServer(context.Background(), server.ID)
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("restart callback was persisted but server deletion did not resume")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDeleteRemoteServerRetrySkipsAgentAfterPersistedSuccess(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	handler := NewXrayServerHandler(repo, nil, nil)
	token, pending, err := handler.registerAgentUninstall(server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerDeletionDispatched(context.Background(), server.ID, agentUninstallTokenHash(token), testCleanupID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConsumeRemoteServerDeletionCallback(context.Background(), agentUninstallTokenHash(token), testCleanupID, true, ""); err != nil {
		t.Fatal(err)
	}
	handler.unregisterAgentUninstall(token, pending)

	response := requestRemoteServerDelete(t, handler, server.ID, true)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := repo.GetRemoteServer(context.Background(), server.ID); !errors.Is(err, storage.ErrRemoteServerNotFound) {
		t.Fatalf("server still exists after confirmed retry: %v", err)
	}
}

func TestDeleteRemoteServerReplacesPreDispatchPendingTask(t *testing.T) {
	var uninstallCalls int
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/warp/status":
			_, _ = w.Write([]byte(`{"success":true,"installed":false}`))
		case "/api/child/agent/uninstall-v2":
			uninstallCalls++
			dispatch, err := decodeUninstallDispatch(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if status, err := postUninstallCallback(dispatch, agentUninstallCallback{Success: true, CleanupID: testCleanupID}); err != nil || status != http.StatusOK {
				http.Error(w, "callback failed", http.StatusInternalServerError)
				return
			}
			writeDispatchAck(w, testCleanupID)
		default:
			http.NotFound(w, r)
		}
	})
	capabilities := AgentCapabilities{AgentUninstallV2: true}
	handler, repo, server := newAgentUninstallHandler(t, agent, &capabilities)
	if _, err := repo.CreateRemoteServerDeletionTask(context.Background(), server.ID, strings.Repeat("e", 64), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	response := requestRemoteServerDelete(t, handler, server.ID, true)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if uninstallCalls != 1 {
		t.Fatalf("uninstall calls=%d want=1", uninstallCalls)
	}
}

func TestGetRemoteServerDeleteImpactReportsOwnershipAndTask(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	wsHandler := NewRemoteWSHandler(repo, nil)
	wsHandler.conns.Store(server.Token, &RemoteWSConnection{
		ServerID: server.ID, ServerName: server.Name, Token: server.Token,
		Capabilities: AgentCapabilities{AgentUninstallV2: true},
	})
	handler := NewXrayServerHandler(repo, nil, nil)
	handler.SetWSHandler(wsHandler)
	if _, err := repo.CreateRemoteServerDeletionTask(context.Background(), server.ID, strings.Repeat("f", 64), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/admin/remote-servers/delete-impact?server_id="+strconv.FormatInt(server.ID, 10), nil)
	response := httptest.NewRecorder()
	handler.GetRemoteServerDeleteImpact(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var impact RemoteServerDeleteImpactResponse
	if err := json.NewDecoder(response.Body).Decode(&impact); err != nil {
		t.Fatal(err)
	}
	if !impact.Success || impact.Server.Ownership != "owned" || impact.Server.AgentUninstallV2 == nil || !*impact.Server.AgentUninstallV2 {
		t.Fatalf("unexpected impact response: %+v", impact)
	}
	if impact.DeletionTask == nil || impact.DeletionTask.Status != storage.RemoteServerDeletionPending {
		t.Fatalf("missing persisted deletion task: %+v", impact.DeletionTask)
	}
}
