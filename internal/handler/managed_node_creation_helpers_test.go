package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestCanonicalManagedProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     string
	}{
		{name: "shadowsocks alias", protocol: "ss", want: "shadowsocks"},
		{name: "shadowsocks alias normalized", protocol: " SS ", want: "shadowsocks"},
		{name: "hysteria2 alias", protocol: "hysteria2", want: "hysteria"},
		{name: "hy2 alias normalized", protocol: " Hy2 ", want: "hysteria"},
		{name: "canonical protocol normalized", protocol: " VLESS ", want: "vless"},
		{name: "unknown protocol normalized", protocol: " TUIC ", want: "tuic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalManagedProtocol(tt.protocol); got != tt.want {
				t.Fatalf("canonicalManagedProtocol(%q) = %q, want %q", tt.protocol, got, tt.want)
			}
		})
	}
}

func TestCreateManagedNodeRejectsWireGuardSubscriptionTransaction(t *testing.T) {
	handler := NewRemoteManageHandler(nil, nil)
	body, err := json.Marshal(map[string]any{
		"node_name": "WireGuard one-time client",
		"inbound": map[string]any{
			"tag":      "wireguard-one-time",
			"protocol": "wireguard",
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/admin/managed-nodes/create?server_id=1", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.HandleCreateManagedNode(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), http.StatusUnprocessableEntity)
	}
	var payload struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
		Status  int    `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Success || payload.Status != http.StatusUnprocessableEntity || !strings.Contains(payload.Error, "客户端私钥") {
		t.Fatalf("unexpected response: %+v", payload)
	}
}

func TestManagedNodeResponseRecorderAndCopyHTTPResponse(t *testing.T) {
	source := &managedNodeResponseRecorder{header: make(http.Header)}
	source.Header().Add("Content-Type", "application/json")
	source.Header().Add("X-Arcway-Test", "first")
	source.Header().Add("X-Arcway-Test", "second")
	source.WriteHeader(http.StatusBadGateway)
	if _, err := source.Write([]byte(`{"error":"remote rejected request"}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if source.status != http.StatusBadGateway {
		t.Fatalf("recorded status = %d, want %d", source.status, http.StatusBadGateway)
	}

	destination := httptest.NewRecorder()
	copyHTTPResponse(destination, source)
	response := destination.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("copied status = %d, want %d", response.StatusCode, http.StatusBadGateway)
	}
	if got := destination.Body.String(); got != `{"error":"remote rejected request"}` {
		t.Fatalf("copied body = %q", got)
	}
	if got := response.Header.Values("X-Arcway-Test"); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("copied multi-value header = %v", got)
	}
}

func TestManagedNodeResponseRecorderWriteDefaultsStatusToOK(t *testing.T) {
	source := &managedNodeResponseRecorder{header: make(http.Header)}
	if _, err := source.Write([]byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if source.status != http.StatusOK {
		t.Fatalf("implicit status = %d, want %d", source.status, http.StatusOK)
	}
}

func TestManagedNodePartialResponseParsing(t *testing.T) {
	partial := &managedNodeResponseRecorder{header: make(http.Header), status: http.StatusConflict}
	_, _ = partial.Write([]byte(`{"success":false,"partial":true,"message":"WSS nginx 同步失败"}`))
	if !managedNodeResponseIsPartial(partial) {
		t.Fatal("expected partial response to be detected")
	}
	if got := managedNodeResponseMessage(partial, "fallback"); got != "WSS nginx 同步失败" {
		t.Fatalf("message = %q", got)
	}

	ordinary := &managedNodeResponseRecorder{header: make(http.Header), status: http.StatusBadGateway}
	_, _ = ordinary.Write([]byte(`{"success":false,"error":"agent unavailable"}`))
	if managedNodeResponseIsPartial(ordinary) {
		t.Fatal("ordinary remote failure must not be treated as partial success")
	}
	if got := managedNodeResponseMessage(ordinary, "fallback"); got != "agent unavailable" {
		t.Fatalf("error message = %q", got)
	}

	invalid := &managedNodeResponseRecorder{header: make(http.Header)}
	_, _ = invalid.Write([]byte("not-json"))
	if got := managedNodeResponseMessage(invalid, "fallback"); got != "fallback" {
		t.Fatalf("invalid JSON message = %q", got)
	}
}

func TestManagedNodeResponseRequiresExplicitSuccess(t *testing.T) {
	accepted := &managedNodeResponseRecorder{header: make(http.Header)}
	_, _ = accepted.Write([]byte(`{"success":true,"message":"created"}`))
	if success, message := managedNodeResponseSuccess(accepted); !success || message != "" {
		t.Fatalf("accepted response = %v, %q", success, message)
	}

	for name, body := range map[string]string{
		"explicit rejection":  `{"success":false,"message":"duplicate tag"}`,
		"missing success":     `{"message":"created maybe"}`,
		"persistence warning": `{"success":true,"message":"runtime only","warning":"persist_failed"}`,
		"runtime warning":     `{"success":true,"runtime_warning":"runtime deferred"}`,
		"invalid JSON":        `not-json`,
	} {
		t.Run(name, func(t *testing.T) {
			recorder := &managedNodeResponseRecorder{header: make(http.Header)}
			_, _ = recorder.Write([]byte(body))
			if success, message := managedNodeResponseSuccess(recorder); success || message == "" {
				t.Fatalf("response = %v, %q", success, message)
			}
		})
	}
}

func TestCreateManagedNodeRollsBackWarningResponse(t *testing.T) {
	var actions []string
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "inbounds": []any{},
				"mutation_fence_known": true, "mutation_owners": map[string]string{},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			var request struct {
				Action     string `json:"action"`
				MutationID string `json:"mutation_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			actions = append(actions, request.Action)
			if request.Action == "remove" {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "mutation_id": request.MutationID})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "mutation_id": request.MutationID,
				"message": "runtime only", "warning": "persist_failed",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	repo := newRemoteHandlerTestRepo(t)
	if err := repo.CreateUser(context.Background(), "admin", "admin@example.test", "Admin", "test-hash", storage.RoleAdmin, ""); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	server := createRemoteHandlerTestServer(t, repo, "managed-warning-edge", agent.URL)
	if _, err := repo.UpdateRemoteServerXrayStatus(context.Background(), server.ID, true, "test"); err != nil {
		t.Fatalf("mark Xray running: %v", err)
	}
	handler := NewRemoteManageHandler(repo, nil)
	body, _ := json.Marshal(map[string]any{
		"action": "add", "node_name": "Forwarded node",
		"inbound": map[string]any{
			"tag": "anydoor-node-7", "protocol": "tunnel", "port": 2033,
			"settings": map[string]any{"address": "target.example.test", "port": 443, "network": "tcp,udp"},
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/admin/managed-nodes/create?server_id="+leaseTestID(server.ID), bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	response := httptest.NewRecorder()
	handler.HandleCreateManagedNode(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want CDN-safe 400", response.Code, response.Body.String())
	}
	var responseBody struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &responseBody); err != nil || responseBody.Status != http.StatusBadGateway {
		t.Fatalf("body=%s, want original status 502", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "persist_failed") || !strings.Contains(response.Body.String(), "已回滚") {
		t.Fatalf("warning and rollback were not surfaced: %s", response.Body.String())
	}
	if len(actions) != 2 || actions[0] != "add" || actions[1] != "remove" {
		t.Fatalf("warning response was not rolled back: actions=%v", actions)
	}
}

func TestCopyHTTPResponseDefaultsUnsetStatusToOK(t *testing.T) {
	source := &managedNodeResponseRecorder{header: make(http.Header)}
	destination := httptest.NewRecorder()

	copyHTTPResponse(destination, source)

	if destination.Code != http.StatusOK {
		t.Fatalf("copied default status = %d, want %d", destination.Code, http.StatusOK)
	}
}

func TestCloneURLWithQueryPreservesRequestAndOverwritesServerID(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://panel.example/api/admin/managed-nodes/create?server_id=1&trace=yes", nil)
	originalRawQuery := request.URL.RawQuery

	cloned := cloneURLWithQuery(request, 42)

	if cloned == request.URL {
		t.Fatal("cloneURLWithQuery returned the request URL pointer")
	}
	if request.URL.RawQuery != originalRawQuery {
		t.Fatalf("source query mutated from %q to %q", originalRawQuery, request.URL.RawQuery)
	}
	if got := cloned.Query().Get("server_id"); got != "42" {
		t.Fatalf("server_id = %q, want 42", got)
	}
	if got := cloned.Query().Get("trace"); got != "yes" {
		t.Fatalf("trace = %q, want yes", got)
	}
	if cloned.Path != request.URL.Path {
		t.Fatalf("path = %q, want %q", cloned.Path, request.URL.Path)
	}
}
