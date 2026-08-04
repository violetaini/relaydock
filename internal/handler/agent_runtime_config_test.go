package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/version"

	"github.com/gorilla/websocket"
)

func TestAgentRuntimeConfigUpdatesGateXrayAuthorization(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	ctx := context.Background()

	legacy := agentRuntimeConfigUpdates(ctx, repo, server.ID, AgentCapabilities{})
	if _, ok := legacy[xrayAuthorizedConfigKey]; ok {
		t.Fatalf("legacy Agent received %q: %#v", xrayAuthorizedConfigKey, legacy)
	}

	safe := agentRuntimeConfigUpdates(ctx, repo, server.ID, AgentCapabilities{XrayAuthorizationV2: true})
	if got := safe[xrayAuthorizedConfigKey]; got != "true" {
		t.Fatalf("safe Agent %q=%q, want true (updates=%#v)", xrayAuthorizedConfigKey, got, safe)
	}
}

func TestRemoteTrafficConfigUpdatesGateXrayAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name         string
		capabilities AgentCapabilities
		wantPresent  bool
	}{
		{name: "legacy agent", wantPresent: false},
		{
			name:         "xray authorization v2 agent",
			capabilities: AgentCapabilities{XrayAuthorizationV2: true},
			wantPresent:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, server := newRemoteInstallationHandlerRepo(t, 23889)
			body, err := json.Marshal(RemoteTrafficRequest{Capabilities: tc.capabilities})
			if err != nil {
				t.Fatalf("marshal traffic request: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/remote/traffic", bytes.NewReader(body))
			req.Header.Set("User-Agent", version.AgentUserAgent)
			req.Header.Set("Authorization", "Bearer "+server.Token)
			response := httptest.NewRecorder()
			NewRemoteTrafficHandler(repo, nil, &CryptoConfig{}).ServeHTTP(response, req)

			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload struct {
				Success       bool              `json:"success"`
				ConfigUpdates map[string]string `json:"config_updates"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode traffic response: %v (body=%s)", err, response.Body.String())
			}
			if !payload.Success {
				t.Fatalf("traffic response was unsuccessful: %s", response.Body.String())
			}
			got, present := payload.ConfigUpdates[xrayAuthorizedConfigKey]
			if present != tc.wantPresent {
				t.Fatalf("%q present=%v want=%v (updates=%#v)", xrayAuthorizedConfigKey, present, tc.wantPresent, payload.ConfigUpdates)
			}
			if tc.wantPresent && got != "true" {
				t.Fatalf("%q=%q, want true", xrayAuthorizedConfigKey, got)
			}
		})
	}
}

func TestPushAgentRuntimeConfigGatesXrayAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name         string
		capabilities AgentCapabilities
		wantPresent  bool
	}{
		{name: "legacy agent", wantPresent: false},
		{
			name:         "xray authorization v2 agent",
			capabilities: AgentCapabilities{XrayAuthorizationV2: true},
			wantPresent:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agentConnection := make(chan *websocket.Conn, 1)
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				agentConnection <- conn
			}))
			defer agent.Close()

			masterConn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(agent.URL, "http"), nil)
			if err != nil {
				t.Fatalf("dial fake Agent websocket: %v", err)
			}
			defer masterConn.Close()
			fakeAgentConn := <-agentConnection
			defer fakeAgentConn.Close()

			repo, server := newRemoteInstallationHandlerRepo(t, 23889)
			handler := NewRemoteWSHandler(repo, nil)
			handler.conns.Store(server.Token, &RemoteWSConnection{
				ServerID:     server.ID,
				Token:        server.Token,
				Conn:         masterConn,
				Capabilities: tc.capabilities,
			})

			handler.PushAgentRuntimeConfigToAgent(context.Background(), server.ID)

			if err := fakeAgentConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatalf("set websocket read deadline: %v", err)
			}
			_, wire, err := fakeAgentConn.ReadMessage()
			if err != nil {
				t.Fatalf("read runtime config push: %v", err)
			}
			var message WSMessage
			if err := json.Unmarshal(wire, &message); err != nil {
				t.Fatalf("decode websocket message: %v", err)
			}
			if message.Type != WSMsgTypeConfigUpdate {
				t.Fatalf("message type=%q want=%q", message.Type, WSMsgTypeConfigUpdate)
			}
			var updates map[string]string
			if err := json.Unmarshal(message.Payload, &updates); err != nil {
				t.Fatalf("decode runtime config updates: %v", err)
			}
			got, present := updates[xrayAuthorizedConfigKey]
			if present != tc.wantPresent {
				t.Fatalf("%q present=%v want=%v (updates=%#v)", xrayAuthorizedConfigKey, present, tc.wantPresent, updates)
			}
			if tc.wantPresent && got != "true" {
				t.Fatalf("%q=%q, want true", xrayAuthorizedConfigKey, got)
			}
		})
	}
}
