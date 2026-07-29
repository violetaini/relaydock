package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"

	"github.com/MMWOrg/mmwX-plugins/proxyparser"
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

func TestMakeNodeURIItemCanonicalWireGuardRoundTripDualStack(t *testing.T) {
	privateKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+="
	publicKey := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB+="
	allowedIPs := []string{"0.0.0.0/0", "::/0"}
	tests := []struct {
		name          string
		server        string
		wantAuthority string
	}{
		{name: "IPv4 endpoint", server: "203.0.113.10", wantAuthority: "@203.0.113.10:51820/"},
		{name: "IPv6 endpoint", server: "2001:db8::10", wantAuthority: "@[2001:db8::10]:51820/"},
	}

	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := map[string]any{
				"name":                 "双栈 WireGuard + #1",
				"type":                 "wireguard",
				"server":               tt.server,
				"port":                 51820,
				"private-key":          privateKey,
				"public-key":           publicKey,
				"ip":                   "10.66.66.2",
				"ipv6":                 "fd00::2",
				"allowed-ips":          allowedIPs,
				"persistent-keepalive": 25,
				"udp":                  true,
			}
			config, err := json.Marshal(proxy)
			if err != nil {
				t.Fatal(err)
			}
			item, err := makeNodeURIItem("alice", storage.Node{
				ID: int64(index + 1), NodeName: "双栈 WireGuard", Protocol: "wireguard", ClashConfig: string(config),
			}, substore.NewURIProducer())
			if err != nil {
				t.Fatalf("generate WireGuard URI: %v", err)
			}
			if !strings.Contains(item.URI, tt.wantAuthority) {
				t.Fatalf("URI authority = %q, want fragment %q", item.URI, tt.wantAuthority)
			}
			if !strings.Contains(item.URI, "allowed-ips=%5B0.0.0.0%2F0%2C%3A%3A%2F0%5D") {
				t.Fatalf("allowed-ips array was not comma encoded: %q", item.URI)
			}
			if !strings.Contains(item.URI, "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%2B%3D@") {
				t.Fatalf("private key reserved characters were not encoded: %q", item.URI)
			}

			parsed, err := proxyparser.Parse(item.URI)
			if err != nil {
				t.Fatalf("parse generated WireGuard URI: %v", err)
			}
			if got := strings.Trim(strings.TrimSpace(parsed["server"].(string)), "[]"); got != tt.server {
				t.Fatalf("parsed server = %q, want %q", got, tt.server)
			}
			if parsed["private-key"] != privateKey || parsed["public-key"] != publicKey {
				t.Fatalf("parsed keys changed: private=%q public=%q", parsed["private-key"], parsed["public-key"])
			}
			if parsed["ip"] != "10.66.66.2" || parsed["ipv6"] != "fd00::2" {
				t.Fatalf("parsed dual-stack addresses = ip:%v ipv6:%v", parsed["ip"], parsed["ipv6"])
			}
			if got, ok := parsed["allowed-ips"].([]string); !ok || !reflect.DeepEqual(got, allowedIPs) {
				t.Fatalf("parsed allowed-ips = %#v, want %#v", parsed["allowed-ips"], allowedIPs)
			}

			reencoded, err := encodeCanonicalWireGuardURI(parsed)
			if err != nil {
				t.Fatalf("re-encode parsed WireGuard URI: %v", err)
			}
			if reencoded != item.URI {
				t.Fatalf("WireGuard URI round trip changed:\nfirst:  %s\nsecond: %s", item.URI, reencoded)
			}
		})
	}
}
