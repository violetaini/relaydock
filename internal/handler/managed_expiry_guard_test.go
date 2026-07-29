package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/guardwire"
	"github.com/violetaini/relaydock/internal/storage"
)

func startManagedGuardServer(t *testing.T, handler http.Handler) (*httptest.Server, int) {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if port <= 1024 {
			listener.Close()
			continue
		}
		// The repository stores the Agent port; the guard is adjacent to it.
		agentPort := port - managedExpiryGuardPortOffset
		server := httptest.NewUnstartedServer(handler)
		server.Listener = listener
		server.Start()
		t.Cleanup(server.Close)
		return server, agentPort
	}
	t.Fatal("could not allocate expiry guard test port")
	return nil, 0
}

func TestManagedExpiryGuardFallbackPersistsAndDeletesSchedule(t *testing.T) {
	var mu sync.Mutex
	methods := make([]string, 0, 2)
	var putBody map[string]interface{}
	var syncedToken string
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	var remoteServerID int64
	guard, agentPort := startManagedGuardServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Errorf("plaintext Authorization header = %q", authorization)
		}
		secret, err := repo.GetOrCreateRemoteServerGuardSecret(r.Context(), remoteServerID)
		if err != nil {
			t.Errorf("guard secret: %v", err)
			http.Error(w, "secret", http.StatusInternalServerError)
			return
		}
		sealed, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read sealed request: %v", err)
			return
		}
		plaintext, err := guardwire.Open(secret, r.Method, r.URL.EscapedPath(), sealed, guardwire.Metadata{
			Timestamp: r.Header.Get(guardwire.HeaderTimestamp),
			Nonce:     r.Header.Get(guardwire.HeaderNonce),
			Signature: r.Header.Get(guardwire.HeaderSignature),
		}, time.Now().UTC())
		if err != nil {
			t.Errorf("open sealed request: %v", err)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/capabilities":
			_, _ = w.Write([]byte(`{"client_expiry":true,"durable":true}`))
		case "/v1/agent-token":
			var tokenRequest struct {
				Token string `json:"token"`
			}
			_ = json.NewDecoder(bytes.NewReader(plaintext)).Decode(&tokenRequest)
			mu.Lock()
			syncedToken = tokenRequest.Token
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true}`))
		case "/v1/schedules":
			mu.Lock()
			methods = append(methods, r.Method)
			if r.Method == http.MethodPut {
				_ = json.NewDecoder(bytes.NewReader(plaintext)).Decode(&putBody)
			}
			mu.Unlock()
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	guardPort := guard.Listener.Addr().(*net.TCPAddr).Port
	if guardPort != agentPort+managedExpiryGuardPortOffset {
		t.Fatalf("guard port = %d, agent port = %d", guardPort, agentPort)
	}

	server := &storage.RemoteServer{
		Name: "guard-edge", Token: "edge-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "127.0.0.1", ListenPort: agentPort, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	remoteServerID = server.ID
	remote := managedRemoteWithCapabilities(repo, server.ID, AgentCapabilities{RPC: true, Stream: true})
	handler := NewManagedNodesHandler(repo, remote, nil)
	if err := handler.requireManagedAgentCapabilities(ctx, server.ID); err != nil {
		t.Fatalf("fallback capabilities: %v", err)
	}
	credential := map[string]interface{}{"email": "alice__in", "id": "uuid"}
	expires := time.Now().Add(time.Hour).UTC()
	if err := handler.ensureManagedClientExpiry(ctx, server.ID, "in", credential, &expires); err != nil {
		t.Fatalf("persist schedule: %v", err)
	}
	if err := handler.ensureManagedClientExpiry(ctx, server.ID, "in", credential, nil); err != nil {
		t.Fatalf("delete schedule: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(methods) != 2 || methods[0] != http.MethodPut || methods[1] != http.MethodDelete {
		t.Fatalf("schedule methods = %v", methods)
	}
	if putBody["tag"] != "in" || putBody["not_after"] == nil {
		t.Fatalf("unexpected schedule body: %#v", putBody)
	}
	if syncedToken != "edge-token" {
		t.Fatalf("synced Agent token = %q", syncedToken)
	}
}

func TestManagedNativeExpiryDoesNotRequireGuard(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	server := &storage.RemoteServer{
		Name: "native-expiry", Token: "token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "192.0.2.1", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	remote := managedRemoteWithCapabilities(repo, server.ID, managedReadyAgentCapabilities())
	handler := NewManagedNodesHandler(repo, remote, nil)
	if err := handler.requireManagedAgentCapabilities(ctx, server.ID); err != nil {
		t.Fatalf("native capability check: %v", err)
	}
	if err := handler.ensureManagedClientExpiry(ctx, server.ID, "in", map[string]interface{}{"id": "uuid"}, nil); err != nil {
		t.Fatalf("native expiry unexpectedly called guard: %v", err)
	}
}
