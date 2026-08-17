package expiryguard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/guardwire"
	"github.com/violetaini/relaydock/internal/version"
)

func newTestGuard(t *testing.T, agent http.Handler) (*Guard, string, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(agent)
	t.Cleanup(server.Close)
	statePath := filepath.Join(t.TempDir(), "guard", "state.json")
	guard, err := New(statePath, "guard-secret", "secret-token", server.URL, server.Client())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return guard, statePath, server
}

func TestGuardHTTPAuthAndPersistence(t *testing.T) {
	guard, statePath, _ := newTestGuard(t, http.NotFoundHandler())
	server := httptest.NewServer(guard.Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}

	schedule := Schedule{
		Tag:      "inbound-1",
		Protocol: "vless",
		Client:   map[string]interface{}{"email": "user@example.com", "id": "uuid"},
		NotAfter: time.Now().Add(time.Hour).UTC(),
	}
	if err := guard.Upsert(schedule); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("state mode = %o, want 600", got)
	}

	reloaded, err := New(statePath, "guard-secret", "secret-token", "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("reload error = %v", err)
	}
	if got := reloaded.Pending(); got != 1 {
		t.Fatalf("reloaded pending = %d, want 1", got)
	}
	if err := reloaded.Delete(schedule.Tag, schedule.Client); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if got := reloaded.Pending(); got != 0 {
		t.Fatalf("pending after delete = %d, want 0", got)
	}
}

func TestGuardPersistsWireGuardPeerByPublicKey(t *testing.T) {
	guard, statePath, _ := newTestGuard(t, http.NotFoundHandler())
	schedule := Schedule{
		Tag:      "wireguard-in",
		Protocol: "wireguard",
		Client: map[string]interface{}{
			"publicKey":  "bW9jay13aXJlZ3VhcmQtcHVibGljLWtleS0zMi1ieXRlcw==",
			"allowedIPs": []interface{}{"10.0.0.2/32"},
		},
		NotAfter: time.Now().Add(time.Hour).UTC(),
	}
	if err := guard.Upsert(schedule); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	reloaded, err := New(statePath, "guard-secret", "secret-token", "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("reload error = %v", err)
	}
	if err := reloaded.Delete(schedule.Tag, schedule.Client); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if got := reloaded.Pending(); got != 0 {
		t.Fatalf("pending after WireGuard delete = %d, want 0", got)
	}
}

func TestGuardExpiresClientAndPersistsCompletion(t *testing.T) {
	var mu sync.Mutex
	var calls []map[string]interface{}
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != version.AgentUserAgent {
			t.Errorf("User-Agent = %q", got)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		mu.Lock()
		calls = append(calls, body)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	guard, statePath, _ := newTestGuard(t, agent)
	if err := guard.Upsert(Schedule{
		Tag:      "inbound-expiring",
		Protocol: "vless",
		Client:   map[string]interface{}{"email": "expiring@example.com", "id": "uuid"},
		NotAfter: time.Now().Add(40 * time.Millisecond).UTC(),
	}); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go guard.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for guard.Pending() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := guard.Pending(); got != 0 {
		t.Fatalf("pending = %d, want 0", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("remove calls = %d, want 1", len(calls))
	}
	if calls[0]["action"] != "remove-client" || calls[0]["tag"] != "inbound-expiring" {
		t.Fatalf("unexpected remove payload: %#v", calls[0])
	}

	reloaded, err := New(statePath, "guard-secret", "secret-token", "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("reload completed state: %v", err)
	}
	if got := reloaded.Pending(); got != 0 {
		t.Fatalf("reloaded pending = %d, want 0", got)
	}
}

func TestGuardEncryptedAPIAndAgentTokenPersistence(t *testing.T) {
	guard, statePath, _ := newTestGuard(t, http.NotFoundHandler())
	server := httptest.NewServer(guard.Handler())
	defer server.Close()

	payload := []byte(`{"token":"rotated-agent-token"}`)
	sealed, metadata, err := guardwire.Seal("guard-secret", http.MethodPut, "/v1/agent-token", payload, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, server.URL+"/v1/agent-token", bytes.NewReader(sealed))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(guardwire.HeaderTimestamp, metadata.Timestamp)
	request.Header.Set(guardwire.HeaderNonce, metadata.Nonce)
	request.Header.Set(guardwire.HeaderSignature, metadata.Signature)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}

	reloaded, err := New(statePath, "guard-secret", "stale-env-token", "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.currentAgentToken(); got != "rotated-agent-token" {
		t.Fatalf("persisted Agent token = %q", got)
	}

	replayRequest, err := http.NewRequestWithContext(context.Background(), http.MethodPut, server.URL+"/v1/agent-token", bytes.NewReader(sealed))
	if err != nil {
		t.Fatal(err)
	}
	replayRequest.Header.Set(guardwire.HeaderTimestamp, metadata.Timestamp)
	replayRequest.Header.Set(guardwire.HeaderNonce, metadata.Nonce)
	replayRequest.Header.Set(guardwire.HeaderSignature, metadata.Signature)
	replayed, err := server.Client().Do(replayRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayed.Body.Close()
	if replayed.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed status = %d", replayed.StatusCode)
	}
}

func TestGuardDefersDeferredRemovalWithoutRestartingXray(t *testing.T) {
	var mu sync.Mutex
	paths := make([]string, 0, 3)
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/api/child/inbounds":
			_, _ = w.Write([]byte(`{"success":true,"runtime_warning":"runtime apply deferred"}`))
		case "/api/child/services/control":
			_, _ = w.Write([]byte(`{"success":true}`))
		case "/api/child/services/status":
			_, _ = w.Write([]byte(`{"xray":{"running":true}}`))
		default:
			http.NotFound(w, r)
		}
	})
	guard, _, _ := newTestGuard(t, agent)
	entry := Schedule{
		Tag: "deferred-in", Client: map[string]interface{}{"email": "deferred@example.com"},
		NotAfter: time.Now().Add(-time.Second).UTC(),
	}
	key, err := scheduleKey(entry.Tag, entry.Client)
	if err != nil {
		t.Fatal(err)
	}
	entry.Key = key
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = guard.removeClient(ctx, entry)
	if err == nil || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("removeClient() error = %v, want deferred retry", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"/api/child/inbounds"}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths = %v, want %v", paths, want)
		}
	}
}
