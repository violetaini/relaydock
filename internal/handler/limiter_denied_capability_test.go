package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func deniedLimiterTestSnapshots(denied bool) []WSLimiterConfigPayload {
	return []WSLimiterConfigPayload{{
		InboundTag: "deny-test",
		Users: []WSUserLimitInfo{{
			Email: "alice__deny-test", Denied: denied,
		}},
	}}
}

func forwardingLimiterTestSnapshots(speed uint64) []WSLimiterConfigPayload {
	return []WSLimiterConfigPayload{{
		InboundTag: "forward-test", NodeLimit: speed, InboundSharedLimit: true,
		Users: []WSUserLimitInfo{},
	}}
}

func TestForwardingSpeedCapabilityHTTPFallback(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		capable    bool
		wantErr    bool
		wantPushes int64
	}{
		{name: "capable", capable: true, wantPushes: 1},
		{name: "legacy", wantErr: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var probes atomic.Int64
			var pushes atomic.Int64
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info":
					probes.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"success": true,
						"capabilities": map[string]bool{
							"forwarding_speed_limit_v1": testCase.capable,
						},
					})
				case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
					pushes.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
				default:
					http.NotFound(w, r)
				}
			}))
			defer agent.Close()

			server := &storage.RemoteServer{
				ID: 505, Name: "forwarding-http", Token: "token", IPAddress: "127.0.0.1",
				ListenPort: remoteAgentTestPort(t, agent.URL),
			}
			pusher := NewLimiterConfigPusher(nil, nil)
			pusher.httpClient = agent.Client()
			err := pusher.pushViaHTTPChecked(context.Background(), server, forwardingLimiterTestSnapshots(1250000))
			if testCase.wantErr {
				if err == nil || !strings.Contains(err.Error(), "forwarding_speed_limit_v1") {
					t.Fatalf("push error=%v, want forwarding_speed_limit_v1 rejection", err)
				}
			} else if err != nil {
				t.Fatalf("push with capable Agent: %v", err)
			}
			if got := probes.Load(); got != 1 {
				t.Fatalf("system/info probes=%d want 1", got)
			}
			if got := pushes.Load(); got != testCase.wantPushes {
				t.Fatalf("limiter pushes=%d want %d", got, testCase.wantPushes)
			}
		})
	}
}

func TestForwardingUnlimitedSnapshotDoesNotRequireCapability(t *testing.T) {
	var probes atomic.Int64
	var pushes atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info" {
			probes.Add(1)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter" {
			pushes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
		http.NotFound(w, r)
	}))
	defer agent.Close()
	server := &storage.RemoteServer{
		ID: 606, Name: "forwarding-unlimited", Token: "token", IPAddress: "127.0.0.1",
		ListenPort: remoteAgentTestPort(t, agent.URL),
	}
	pusher := NewLimiterConfigPusher(nil, nil)
	pusher.httpClient = agent.Client()
	if err := pusher.pushViaHTTPChecked(context.Background(), server, forwardingLimiterTestSnapshots(0)); err != nil {
		t.Fatalf("clear forwarding limiter: %v", err)
	}
	if probes.Load() != 0 || pushes.Load() != 1 {
		t.Fatalf("system/info probes=%d limiter pushes=%d", probes.Load(), pushes.Load())
	}
}

func TestLimiterDeniedCapabilityHTTPFallback(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		capable    bool
		wantErr    bool
		wantProbes int64
		wantPushes int64
	}{
		{name: "capable", capable: true, wantProbes: 1, wantPushes: 1},
		{name: "legacy", wantErr: true, wantProbes: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var probes atomic.Int64
			var pushes atomic.Int64
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info":
					probes.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"success": true,
						"capabilities": map[string]bool{
							"limiter_denied_v1": testCase.capable,
						},
					})
				case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
					pushes.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
				default:
					http.NotFound(w, r)
				}
			}))
			defer agent.Close()

			server := &storage.RemoteServer{
				ID: 101, Name: "denied-http", Token: "token", IPAddress: "127.0.0.1",
				ListenPort: remoteAgentTestPort(t, agent.URL),
			}
			pusher := NewLimiterConfigPusher(nil, nil)
			pusher.httpClient = agent.Client()
			err := pusher.pushViaHTTPChecked(context.Background(), server, deniedLimiterTestSnapshots(true))
			if testCase.wantErr {
				if err == nil || !strings.Contains(err.Error(), "limiter_denied_v1") {
					t.Fatalf("push error=%v, want limiter_denied_v1 rejection", err)
				}
			} else if err != nil {
				t.Fatalf("push with capable Agent: %v", err)
			}
			if got := probes.Load(); got != testCase.wantProbes {
				t.Fatalf("system/info probes=%d want %d", got, testCase.wantProbes)
			}
			if got := pushes.Load(); got != testCase.wantPushes {
				t.Fatalf("limiter pushes=%d want %d", got, testCase.wantPushes)
			}
		})
	}
}

func TestLimiterDeniedCapabilityUsesActiveWebSocketAsAuthority(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		capable    bool
		wantErr    bool
		wantPushes int64
	}{
		{name: "capable", capable: true, wantPushes: 1},
		{name: "legacy", wantErr: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var probes atomic.Int64
			var pushes atomic.Int64
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info" {
					probes.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"success":      true,
						"capabilities": map[string]bool{"limiter_denied_v1": !testCase.capable},
					})
					return
				}
				if r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter" {
					pushes.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
					return
				}
				http.NotFound(w, r)
			}))
			defer agent.Close()

			server := &storage.RemoteServer{
				ID: 202, Name: "denied-ws", Token: "token", IPAddress: "127.0.0.1",
				ListenPort: remoteAgentTestPort(t, agent.URL),
			}
			ws := NewRemoteWSHandler(nil, nil)
			ws.conns.Store(server.ID, &RemoteWSConnection{
				ServerID: server.ID,
				Capabilities: AgentCapabilities{
					LimiterDeniedV1: testCase.capable,
				},
			})
			pusher := NewLimiterConfigPusher(nil, ws)
			pusher.httpClient = agent.Client()
			err := pusher.pushViaHTTPChecked(context.Background(), server, deniedLimiterTestSnapshots(true))
			if testCase.wantErr {
				if err == nil || !strings.Contains(err.Error(), "limiter_denied_v1") {
					t.Fatalf("push error=%v, want limiter_denied_v1 rejection", err)
				}
			} else if err != nil {
				t.Fatalf("push with capable WS Agent: %v", err)
			}
			if got := probes.Load(); got != 0 {
				t.Fatalf("system/info probes=%d, active WS handshake must be authoritative", got)
			}
			if got := pushes.Load(); got != testCase.wantPushes {
				t.Fatalf("limiter pushes=%d want %d", got, testCase.wantPushes)
			}
		})
	}
}

func TestLegacyWebSocketRejectsDeniedLimiterSnapshotBeforeWrite(t *testing.T) {
	ws := NewRemoteWSHandler(nil, nil)
	ws.conns.Store(int64(303), &RemoteWSConnection{ServerID: 303})
	err := ws.SendLimiterConfig(303, deniedLimiterTestSnapshots(true))
	if err == nil || !strings.Contains(err.Error(), "limiter_denied_v1") {
		t.Fatalf("SendLimiterConfig error=%v, want limiter_denied_v1 rejection", err)
	}
}

func TestNormalLimiterSnapshotDoesNotRequireDeniedCapability(t *testing.T) {
	var probes atomic.Int64
	var pushes atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info" {
			probes.Add(1)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter" {
			pushes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
		http.NotFound(w, r)
	}))
	defer agent.Close()
	server := &storage.RemoteServer{
		ID: 404, Name: "normal-http", Token: "token", IPAddress: "127.0.0.1",
		ListenPort: remoteAgentTestPort(t, agent.URL),
	}
	pusher := NewLimiterConfigPusher(nil, nil)
	pusher.httpClient = agent.Client()
	if err := pusher.pushViaHTTPChecked(context.Background(), server, deniedLimiterTestSnapshots(false)); err != nil {
		t.Fatalf("normal limiter push: %v", err)
	}
	if probes.Load() != 0 || pushes.Load() != 1 {
		t.Fatalf("system/info probes=%d limiter pushes=%d", probes.Load(), pushes.Load())
	}
}

func TestLimiterReplaceACKRejectsWarnings(t *testing.T) {
	for _, body := range []string{
		`{"success":true,"warning":"snapshot not persisted"}`,
		`{"success":true,"runtime_warning":"snapshot not applied"}`,
	} {
		if err := validateLimiterReplaceACK([]byte(body)); err == nil {
			t.Fatalf("validateLimiterReplaceACK(%s) accepted a warning", body)
		}
	}
	if err := validateLimiterReplaceACK([]byte(`{"success":true}`)); err != nil {
		t.Fatalf("validateLimiterReplaceACK accepted ACK: %v", err)
	}
}
