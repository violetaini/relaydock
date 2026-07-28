package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

func createNodeURITestNode(t *testing.T, repo *storage.TrafficRepository, username, name, protocol, config string) storage.Node {
	t.Helper()
	created, err := repo.CreateNode(context.Background(), storage.Node{
		Username:     username,
		NodeName:     name,
		Protocol:     protocol,
		ParsedConfig: config,
		ClashConfig:  config,
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("create node %s: %v", name, err)
	}
	return created
}

func requestNodeURI(t *testing.T, handler http.Handler, username string, nodeID int64) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/admin/nodes/"+strconv.FormatInt(nodeID, 10)+"/uri", nil)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), username))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestNodeURIEndpointReturnsOnlyCurrentUsersVisibleNode(t *testing.T) {
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	createManagedSecurityTestUser(t, repo, "bob", storage.RoleUser)
	aliceUUID := "10000000-0000-4000-8000-000000000001"
	alice := createNodeURITestNode(t, repo, "alice", "Alice VLESS", "vless",
		`{"name":"Alice VLESS","type":"vless","server":"edge.example.com","port":443,"uuid":"`+aliceUUID+`","tls":true,"network":"tcp"}`)
	bob := createNodeURITestNode(t, repo, "bob", "Bob VLESS", "vless",
		`{"name":"Bob VLESS","type":"vless","server":"edge.example.com","port":443,"uuid":"20000000-0000-4000-8000-000000000002","tls":true,"network":"tcp"}`)
	handler := NewNodesHandler(repo, t.TempDir(), nil)

	response := requestNodeURI(t, handler, "alice", alice.ID)
	if response.Code != http.StatusOK {
		t.Fatalf("own node status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		Item nodeURIItem `json:"item"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode URI response: %v", err)
	}
	if !strings.HasPrefix(payload.Item.URI, "vless://") || !strings.Contains(payload.Item.URI, aliceUUID) {
		t.Fatalf("unexpected URI: %q", payload.Item.URI)
	}

	forbidden := requestNodeURI(t, handler, "alice", bob.ID)
	if forbidden.Code != http.StatusNotFound {
		t.Fatalf("foreign node status = %d, want 404; body = %s", forbidden.Code, forbidden.Body.String())
	}
}

func TestMakeNodeURIItemNormalizesSocksAndRejectsUnsupportedProtocol(t *testing.T) {
	producer := substore.NewURIProducer()
	socksConfig := `{"name":"SOCKS","type":"socks","server":"127.0.0.1","port":1080,"username":"alice","password":"secret"}`
	socks, err := makeNodeURIItem("alice", storage.Node{
		ID: 1, NodeName: "SOCKS", Protocol: "socks", ClashConfig: socksConfig,
	}, producer)
	if err != nil {
		t.Fatalf("generate SOCKS URI: %v", err)
	}
	if !strings.HasPrefix(socks.URI, "socks://") {
		t.Fatalf("SOCKS URI = %q, want socks://", socks.URI)
	}

	_, err = makeNodeURIItem("alice", storage.Node{
		ID: 2, NodeName: "Snell", Protocol: "snell",
		ClashConfig: `{"name":"Snell","type":"snell","server":"edge.example.com","port":443,"psk":"secret","version":3}`,
	}, producer)
	if err == nil || !strings.Contains(err.Error(), "暂不支持") {
		t.Fatalf("unsupported protocol error = %v", err)
	}
}
