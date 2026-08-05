package handler

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func wssInboundRequest(protocol, network string) map[string]interface{} {
	return map[string]interface{}{
		"action": "add",
		"inbound": map[string]interface{}{
			"protocol": protocol,
			"listen":   "127.0.0.1",
			"streamSettings": map[string]interface{}{
				"network":  network,
				"security": "none",
			},
		},
	}
}

func TestWSSInboundRequestRecognizesSupportedProtocols(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		network  string
		want     bool
	}{
		{name: "VLESS", protocol: "vless", network: "ws", want: true},
		{name: "VMess normalized", protocol: " VMESS ", network: " WS ", want: true},
		{name: "Trojan", protocol: "trojan", network: "ws", want: true},
		{name: "unsupported protocol", protocol: "shadowsocks", network: "ws", want: false},
		{name: "non websocket transport", protocol: "vmess", network: "tcp", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := wssInboundRequest(tt.protocol, tt.network)
			if got := isWSSInboundReq(request); got != tt.want {
				t.Fatalf("isWSSInboundReq(%q, %q) = %v, want %v", tt.protocol, tt.network, got, tt.want)
			}
			wantLegacy := tt.want && isWSSProtocol(tt.protocol) && canonicalManagedProtocol(tt.protocol) == "vless"
			if got := isVlessWSInboundReq(request); got != wantLegacy {
				t.Fatalf("isVlessWSInboundReq(%q, %q) = %v, want %v", tt.protocol, tt.network, got, wantLegacy)
			}
		})
	}
}

func TestWSSInboundRequestRejectsDirectWebSocketInbounds(t *testing.T) {
	tests := []struct {
		name     string
		listen   interface{}
		security interface{}
	}{
		{name: "public IPv4", listen: "0.0.0.0", security: "none"},
		{name: "public IPv6", listen: "::", security: "none"},
		{name: "specific public address", listen: "203.0.113.9", security: "none"},
		{name: "missing listen", security: "none"},
		{name: "direct TLS", listen: "127.0.0.1", security: "tls"},
		{name: "missing security", listen: "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := wssInboundRequest("vmess", "ws")
			inbound := request["inbound"].(map[string]interface{})
			stream := inbound["streamSettings"].(map[string]interface{})
			if tt.listen == nil {
				delete(inbound, "listen")
			} else {
				inbound["listen"] = tt.listen
			}
			if tt.security == nil {
				delete(stream, "security")
			} else {
				stream["security"] = tt.security
			}
			if isWSSInboundReq(request) {
				t.Fatal("direct WS inbound was classified as nginx-managed WSS")
			}
		})
	}
}

func TestExtractWSSInboundsIncludesVLESSVMessAndTrojan(t *testing.T) {
	inbounds := []map[string]interface{}{
		{"protocol": "vless", "listen": "127.0.0.1", "port": float64(11001), "streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/vless"}}},
		{"protocol": "VMESS", "listen": "localhost", "port": "11002", "streamSettings": map[string]interface{}{"network": "WS", "security": "NONE", "wsSettings": map[string]interface{}{"path": "/vmess"}}},
		{"protocol": "trojan", "listen": "127.0.0.1", "port": float64(11003), "streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/trojan"}}},
		{"protocol": "shadowsocks", "listen": "127.0.0.1", "port": float64(11004), "streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/ss"}}},
		{"protocol": "vmess", "listen": "127.0.0.1", "port": float64(11005), "streamSettings": map[string]interface{}{"network": "tcp", "security": "none", "wsSettings": map[string]interface{}{"path": "/tcp"}}},
		{"protocol": "trojan", "listen": "127.0.0.1", "port": float64(11006), "streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": map[string]interface{}{}}},
		{"protocol": "vless", "listen": "0.0.0.0", "port": float64(11007), "streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/plain-v4"}}},
		{"protocol": "vmess", "listen": "::", "port": float64(11008), "streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/plain-v6"}}},
	}

	want := []wssInboundInfo{
		{WSPath: "/vless", Port: "11001"},
		{WSPath: "/vmess", Port: "11002"},
		{WSPath: "/trojan", Port: "11003"},
	}
	if got := extractWSSInbounds(inbounds); !reflect.DeepEqual(got, want) {
		t.Fatalf("extractWSSInbounds() = %#v, want %#v", got, want)
	}
}

func TestApplyWSSClientRewriteSupportsVLESSVMessAndTrojan(t *testing.T) {
	server := &storage.RemoteServer{Domain: "edge.example.test"}
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			inbound := map[string]interface{}{
				"protocol": protocol,
				"listen":   "127.0.0.1",
				"streamSettings": map[string]interface{}{
					"network":  "ws",
					"security": "none",
					"wsSettings": map[string]interface{}{
						"path": "/" + protocol,
					},
				},
			}

			port, host := applyWSSClientRewrite(inbound, server)
			if port != 443 || host != server.Domain {
				t.Fatalf("applyWSSClientRewrite() = (%d, %q), want (443, %q)", port, host, server.Domain)
			}
			stream := inbound["streamSettings"].(map[string]interface{})
			if stream["security"] != "tls" {
				t.Fatalf("security = %v, want tls", stream["security"])
			}
			tlsSettings := stream["tlsSettings"].(map[string]interface{})
			if tlsSettings["serverName"] != server.Domain {
				t.Fatalf("TLS serverName = %v, want %q", tlsSettings["serverName"], server.Domain)
			}
			wsSettings := stream["wsSettings"].(map[string]interface{})
			if wsSettings["host"] != server.Domain {
				t.Fatalf("WebSocket host = %v, want %q", wsSettings["host"], server.Domain)
			}
		})
	}
}

func TestApplyWSSClientRewriteRejectsUnsupportedProtocol(t *testing.T) {
	inbound := map[string]interface{}{
		"protocol": "shadowsocks",
		"listen":   "127.0.0.1",
		"streamSettings": map[string]interface{}{
			"network":  "ws",
			"security": "none",
		},
	}
	if port, host := applyWSSClientRewrite(inbound, &storage.RemoteServer{Domain: "edge.example.test"}); port != 0 || host != "" {
		t.Fatalf("unsupported rewrite = (%d, %q), want (0, empty)", port, host)
	}
}

func TestApplyWSSClientRewriteLeavesDirectWebSocketUntouched(t *testing.T) {
	for _, listen := range []string{"0.0.0.0", "::", "203.0.113.9"} {
		t.Run(listen, func(t *testing.T) {
			inbound := map[string]interface{}{
				"protocol": "vmess",
				"listen":   listen,
				"streamSettings": map[string]interface{}{
					"network":  "ws",
					"security": "none",
					"wsSettings": map[string]interface{}{
						"path": "/plain",
					},
				},
			}
			before := map[string]interface{}{
				"protocol": "vmess",
				"listen":   listen,
				"streamSettings": map[string]interface{}{
					"network":  "ws",
					"security": "none",
					"wsSettings": map[string]interface{}{
						"path": "/plain",
					},
				},
			}
			if port, host := applyWSSClientRewrite(inbound, &storage.RemoteServer{Domain: "edge.example.test"}); port != 0 || host != "" {
				t.Fatalf("direct WS rewrite = (%d, %q), want (0, empty)", port, host)
			}
			if !reflect.DeepEqual(inbound, before) {
				t.Fatalf("direct WS inbound mutated: got %#v, want %#v", inbound, before)
			}
		})
	}
}

func TestInboundToClashProxyKeepsDirectWebSocketOnOriginalAddressAndPort(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unexpected remote request", http.StatusInternalServerError)
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewRemoteManageHandler(repo, nil)
	inbound := map[string]interface{}{
		"tag":      "plain-vless-ws",
		"protocol": "vless",
		"listen":   "0.0.0.0",
		"port":     float64(18080),
		"settings": map[string]interface{}{
			"clients":    []interface{}{map[string]interface{}{"id": "63d4765a-4e7e-4a60-a47f-9780b98e7e9b", "email": "admin"}},
			"decryption": "none",
		},
		"streamSettings": map[string]interface{}{
			"network":  "ws",
			"security": "none",
			"wsSettings": map[string]interface{}{
				"path": "/socket",
			},
		},
	}

	raw, err := handler.InboundToClashProxyByServerID(server.ID, inbound)
	if err != nil {
		t.Fatalf("InboundToClashProxyByServerID: %v", err)
	}
	var proxy map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &proxy); err != nil {
		t.Fatalf("decode Clash proxy: %v", err)
	}
	if got := proxy["server"]; got != chooseClashServerHost(server) {
		t.Fatalf("server = %v, want %q", got, chooseClashServerHost(server))
	}
	if got := proxy["port"]; got != float64(18080) {
		t.Fatalf("port = %v, want 18080", got)
	}
	if _, exists := proxy["tls"]; exists {
		t.Fatalf("plain WS unexpectedly enabled TLS: %#v", proxy)
	}
	wsOptions, ok := proxy["ws-opts"].(map[string]interface{})
	if !ok || wsOptions["path"] != "/socket" {
		t.Fatalf("ws-opts = %#v, want path /socket", proxy["ws-opts"])
	}
	if _, exists := wsOptions["headers"]; exists {
		t.Fatalf("plain WS unexpectedly gained Host headers: %#v", wsOptions)
	}
}

func TestInboundToClashProxyMapsCurrentAndLegacyWebSocketHost(t *testing.T) {
	for _, test := range []struct {
		name       string
		wsSettings map[string]interface{}
		wantHost   string
	}{
		{name: "current host", wsSettings: map[string]interface{}{"path": "/current", "host": "current.example.test"}, wantHost: "current.example.test"},
		{name: "legacy Host header", wsSettings: map[string]interface{}{"path": "/legacy", "headers": map[string]interface{}{"Host": "legacy.example.test"}}, wantHost: "legacy.example.test"},
		{name: "current host wins", wsSettings: map[string]interface{}{"host": "current.example.test", "headers": map[string]interface{}{"Host": "legacy.example.test", "X-Test": "kept"}}, wantHost: "current.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inbound := map[string]interface{}{
				"tag": "vmess-ws", "protocol": "vmess", "port": float64(18080),
				"settings":       map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": "63d4765a-4e7e-4a60-a47f-9780b98e7e9b"}}},
				"streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": test.wsSettings},
			}
			proxy, err := (&RemoteManageHandler{}).inboundToClashProxy(inbound, "203.0.113.10", "edge", 0)
			if err != nil {
				t.Fatalf("inboundToClashProxy: %v", err)
			}
			wsOpts := proxy["ws-opts"].(map[string]interface{})
			headers := wsOpts["headers"].(map[string]interface{})
			if headers["Host"] != test.wantHost {
				t.Fatalf("Host = %v, want %q", headers["Host"], test.wantHost)
			}
			if _, exists := test.wsSettings["host"]; exists && test.name == "current host wins" && headers["X-Test"] != "kept" {
				t.Fatalf("custom headers were not preserved: %#v", headers)
			}
		})
	}
}

func TestNodeDeletionDoesNotSyncNginxForDirectWebSocket(t *testing.T) {
	var removed atomic.Bool
	var nginxWrites atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			inbounds := []map[string]interface{}{}
			if !removed.Load() {
				inbounds = append(inbounds, map[string]interface{}{
					"tag": "plain-vmess-ws", "protocol": "vmess", "listen": "0.0.0.0", "port": 18080,
					"streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/plain"}},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "inbounds": inbounds})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			removed.Store(true)
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/nginx/setup-ssl":
			nginxWrites.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	createRemoteDomainCertificate(t, repo, server.ID, "edge.example.test")
	handler := &nodesHandler{repo: repo, remoteManage: NewRemoteManageHandler(repo, nil)}
	handler.deleteRemoteInbound(context.Background(), server.Name, "plain-vmess-ws", "")

	if !removed.Load() {
		t.Fatal("plain WS inbound was not removed")
	}
	if got := nginxWrites.Load(); got != 0 {
		t.Fatalf("plain WS node deletion triggered %d nginx writes", got)
	}
}

func TestNodeDeletionSyncsNginxForManagedWSS(t *testing.T) {
	var removed atomic.Bool
	var nginxWrites atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			inbounds := []map[string]interface{}{}
			if !removed.Load() {
				inbounds = append(inbounds, map[string]interface{}{
					"tag": "managed-vmess-wss", "protocol": "vmess", "listen": "127.0.0.1", "port": 11001,
					"streamSettings": map[string]interface{}{"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/managed"}},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "inbounds": inbounds})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			removed.Store(true)
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/cert/deploy":
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/nginx/setup-ssl":
			nginxWrites.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	createRemoteDomainCertificate(t, repo, server.ID, "edge.example.test")
	remote := NewRemoteManageHandler(repo, nil)
	attachRemoteCertificateHandler(t, repo, remote)
	handler := &nodesHandler{repo: repo, remoteManage: remote}
	handler.deleteRemoteInbound(context.Background(), server.Name, "managed-vmess-wss", "")

	if !removed.Load() {
		t.Fatal("managed WSS inbound was not removed")
	}
	if got := nginxWrites.Load(); got != 1 {
		t.Fatalf("managed WSS node deletion triggered %d nginx writes, want 1", got)
	}
}

func TestGetInboundRemovalSyncStateIgnoresDirectWebSocket(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/child/inbounds" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"inbounds": []map[string]interface{}{
				{
					"tag":      "plain-ws",
					"protocol": "vmess",
					"listen":   "0.0.0.0",
					"port":     18080,
					"streamSettings": map[string]interface{}{
						"network":  "ws",
						"security": "none",
						"wsSettings": map[string]interface{}{
							"path": "/plain",
						},
					},
				},
			},
		})
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewRemoteManageHandler(repo, nil)
	domains, wasWSS, err := handler.getInboundRemovalSyncState(context.Background(), server.ID, "plain-ws")
	if err != nil {
		t.Fatalf("getInboundRemovalSyncState: %v", err)
	}
	if wasWSS || len(domains) != 0 {
		t.Fatalf("direct WS removal state = (%v, %v), want (empty, false)", domains, wasWSS)
	}
}

func TestHandleInboundsLeavesDirectWebSocketConfigurationIntact(t *testing.T) {
	var inboundGets atomic.Int64
	var nginxWrites atomic.Int64
	forwarded := make(chan map[string]interface{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			var request struct {
				Inbound    map[string]interface{} `json:"inbound"`
				MutationID string                 `json:"mutation_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			forwarded <- request.Inbound
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "mutation_id": request.MutationID})
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			inboundGets.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"inbounds":[],"mutation_fence_known":true,"mutation_owners":{}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/nginx/setup-ssl":
			nginxWrites.Add(1)
			_, _ = w.Write([]byte(`{"success":true}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			_, _ = w.Write([]byte(`{"success":true,"config":"{}"}`))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewRemoteManageHandler(repo, nil)
	body := bytes.NewBufferString(`{"action":"add","inbound":{"tag":"plain-vmess-ws","protocol":"vmess","listen":"0.0.0.0","port":18080,"settings":{"clients":[]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/plain"}}}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/remote/inbounds?server_id="+leaseTestID(server.ID), body)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "plain-ws-test-user"))
	response := httptest.NewRecorder()

	handler.HandleInbounds(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var inbound map[string]interface{}
	select {
	case inbound = <-forwarded:
	default:
		t.Fatal("plain WS inbound was not forwarded")
	}
	if got := inbound["listen"]; got != "0.0.0.0" {
		t.Fatalf("listen = %v, want 0.0.0.0", got)
	}
	if got := inbound["port"]; got != float64(18080) {
		t.Fatalf("port = %v, want 18080", got)
	}
	stream := inbound["streamSettings"].(map[string]interface{})
	ws := stream["wsSettings"].(map[string]interface{})
	if got := ws["path"]; got != "/plain" {
		t.Fatalf("path = %v, want /plain", got)
	}
	if got := inboundGets.Load(); got != 1 {
		t.Fatalf("plain WS made %d inbound reads, want one database-authority reconciliation read", got)
	}
	if got := nginxWrites.Load(); got != 0 {
		t.Fatalf("plain WS triggered %d nginx writes", got)
	}
}

func TestInboundToClashProxyPreservesVMessCipher(t *testing.T) {
	tests := []struct {
		name     string
		security interface{}
		want     string
	}{
		{name: "missing defaults to auto", want: "auto"},
		{name: "empty defaults to auto", security: " ", want: "auto"},
		{name: "AES 128", security: " AES-128-GCM ", want: "aes-128-gcm"},
		{name: "ChaCha20", security: "chacha20-poly1305", want: "chacha20-poly1305"},
		{name: "none", security: "none", want: "none"},
		{name: "zero", security: "zero", want: "zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := map[string]interface{}{"id": "63d4765a-4e7e-4a60-a47f-9780b98e7e9b"}
			if tt.security != nil {
				client["security"] = tt.security
			}
			inbound := map[string]interface{}{
				"tag":      "vmess-test",
				"protocol": "vmess",
				"port":     float64(443),
				"settings": map[string]interface{}{"clients": []interface{}{client}},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "none",
				},
			}
			proxy, err := (&RemoteManageHandler{}).inboundToClashProxy(inbound, "203.0.113.10", "edge", 0)
			if err != nil {
				t.Fatalf("inboundToClashProxy: %v", err)
			}
			if got := proxy["cipher"]; got != tt.want {
				t.Fatalf("cipher = %v, want %q", got, tt.want)
			}
		})
	}
}

func TestInboundToClashProxyUsesCompatibleTypeAndUDPDefaults(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		settings map[string]interface{}
		wantType string
	}{
		{
			name: "SOCKS5", protocol: "socks", wantType: "socks5",
			settings: map[string]interface{}{"accounts": []interface{}{map[string]interface{}{"user": "alice", "pass": "secret"}}},
		},
		{
			name: "HTTP", protocol: "http", wantType: "http",
			settings: map[string]interface{}{"accounts": []interface{}{map[string]interface{}{"user": "alice", "pass": "secret"}}},
		},
		{
			name: "Shadowsocks", protocol: "shadowsocks", wantType: "ss",
			settings: map[string]interface{}{"method": "aes-128-gcm", "password": "secret"},
		},
		{
			name: "Hysteria2", protocol: "hysteria", wantType: "hysteria2",
			settings: map[string]interface{}{"clients": []interface{}{map[string]interface{}{"auth": "secret"}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inbound := map[string]interface{}{
				"tag": tt.protocol + "-in", "protocol": tt.protocol, "port": float64(443),
				"settings": tt.settings,
			}
			proxy, err := (&RemoteManageHandler{}).inboundToClashProxy(inbound, "203.0.113.10", "edge", 0)
			if err != nil {
				t.Fatal(err)
			}
			if proxy["type"] != tt.wantType {
				t.Fatalf("type = %#v, want %q", proxy["type"], tt.wantType)
			}
			if proxy["udp"] != true {
				t.Fatalf("udp = %#v, want true", proxy["udp"])
			}
		})
	}
}

func TestInboundToClashProxyDerivesRealityPublicKey(t *testing.T) {
	privateBytes := make([]byte, 32)
	for i := range privateBytes {
		privateBytes[i] = byte(i + 1)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	privateKeyText := base64.RawURLEncoding.EncodeToString(privateBytes)
	wantPublicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	inbound := map[string]interface{}{
		"tag":      "reality-import",
		"protocol": "vless",
		"port":     float64(443),
		"settings": map[string]interface{}{
			"clients": []interface{}{map[string]interface{}{"id": "63d4765a-4e7e-4a60-a47f-9780b98e7e9b"}},
		},
		"streamSettings": map[string]interface{}{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"target":      "www.example.com:443",
				"serverNames": []interface{}{"www.example.com"},
				"privateKey":  privateKeyText,
				"shortIds":    []interface{}{"0123456789abcdef"},
			},
		},
	}

	proxy, err := (&RemoteManageHandler{}).inboundToClashProxy(inbound, "203.0.113.10", "edge", 0)
	if err != nil {
		t.Fatalf("inboundToClashProxy: %v", err)
	}
	realityOpts, ok := proxy["reality-opts"].(map[string]interface{})
	if !ok {
		t.Fatalf("reality-opts = %#v", proxy["reality-opts"])
	}
	if got := realityOpts["public-key"]; got != wantPublicKey {
		t.Fatalf("public-key = %v, want %q", got, wantPublicKey)
	}
	if got := proxy["servername"]; got != "www.example.com" {
		t.Fatalf("servername = %v", got)
	}
	if got := proxy["client-fingerprint"]; got != "chrome" {
		t.Fatalf("client-fingerprint = %v", got)
	}
	if got := proxy["skip-cert-verify"]; got != false {
		t.Fatalf("skip-cert-verify = %v, want false", got)
	}
}

func TestInboundToClashProxyRejectsIncompleteReality(t *testing.T) {
	validPrivate := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	tests := []struct {
		name    string
		reality map[string]interface{}
	}{
		{name: "missing keys", reality: map[string]interface{}{"serverNames": []interface{}{"www.example.com"}}},
		{name: "invalid private key", reality: map[string]interface{}{"privateKey": "bad", "serverNames": []interface{}{"www.example.com"}}},
		{name: "missing SNI", reality: map[string]interface{}{"privateKey": validPrivate}},
		{name: "IP SNI", reality: map[string]interface{}{"privateKey": validPrivate, "serverNames": []interface{}{"1.1.1.1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inbound := map[string]interface{}{
				"tag":      "bad-reality",
				"protocol": "vless",
				"port":     float64(443),
				"settings": map[string]interface{}{
					"clients": []interface{}{map[string]interface{}{"id": "63d4765a-4e7e-4a60-a47f-9780b98e7e9b"}},
				},
				"streamSettings": map[string]interface{}{
					"network":         "tcp",
					"security":        "reality",
					"realitySettings": tt.reality,
				},
			}
			if _, err := (&RemoteManageHandler{}).inboundToClashProxy(inbound, "203.0.113.10", "edge", 0); err == nil {
				t.Fatal("expected incomplete Reality config to fail")
			}
		})
	}
}
