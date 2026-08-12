package handler

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func assertInboundBuilds(t *testing.T, inbound map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(inbound)
	if err != nil {
		t.Fatalf("marshal inbound: %v", err)
	}
	var config conf.InboundDetourConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("unmarshal inbound: %v", err)
	}
	if _, err := config.Build(); err != nil {
		t.Fatalf("build inbound: %v", err)
	}
}

func TestManagedProtocolPresetsBuildWithPinnedXrayCore(t *testing.T) {
	uuid := "63d4765a-4e7e-4a60-a47f-9780b98e7e9b"
	privateKey, _, err := genX25519Pair()
	if err != nil {
		t.Fatalf("generate Reality key pair: %v", err)
	}
	privateKeyText := base64.RawURLEncoding.EncodeToString(privateKey)
	tests := []struct {
		name    string
		inbound map[string]interface{}
	}{
		{
			name: "VLESS Reality with current target field",
			inbound: map[string]interface{}{
				"tag": "vless-reality", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
				"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{
					"id": uuid, "email": "admin", "flow": "xtls-rprx-vision",
				}}, "decryption": "none"},
				"streamSettings": map[string]interface{}{
					"network": "tcp", "security": "reality",
					"realitySettings": map[string]interface{}{
						"show": false, "target": "www.example.com:443", "xver": 0,
						"serverNames": []interface{}{"www.example.com"}, "privateKey": privateKeyText,
						"shortIds": []interface{}{"0123456789abcdef"},
					},
				},
			},
		},
		{
			name: "VLESS plain WebSocket without host or domain",
			inbound: map[string]interface{}{
				"tag": "vless-ws", "listen": "0.0.0.0", "port": 18080, "protocol": "vless",
				"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": uuid, "email": "admin"}}, "decryption": "none"},
				"streamSettings": map[string]interface{}{
					"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/ws/vless"},
				},
			},
		},
		{
			name: "VMess TCP",
			inbound: map[string]interface{}{
				"tag": "vmess-tcp", "listen": "0.0.0.0", "port": 18443, "protocol": "vmess",
				"settings":       map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": uuid, "email": "admin", "security": "auto"}}},
				"streamSettings": map[string]interface{}{"network": "tcp", "security": "none"},
			},
		},
		{
			name: "VMess plain WebSocket without host or domain",
			inbound: map[string]interface{}{
				"tag": "vmess-ws", "listen": "0.0.0.0", "port": 18081, "protocol": "vmess",
				"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": uuid, "email": "admin", "security": "auto"}}},
				"streamSettings": map[string]interface{}{
					"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/ws/vmess"},
				},
			},
		},
		{
			name: "VMess WSS backend",
			inbound: map[string]interface{}{
				"tag": "vmess-wss", "listen": "127.0.0.1", "port": 11001, "protocol": "vmess",
				"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{
					"id": uuid, "email": "admin", "security": "chacha20-poly1305",
				}}},
				"streamSettings": map[string]interface{}{
					"network": "ws", "security": "none",
					"wsSettings": map[string]interface{}{"path": "/ws/vmess", "host": "edge.example.com"},
				},
			},
		},
		{
			name: "Trojan WSS backend",
			inbound: map[string]interface{}{
				"tag": "trojan-wss", "listen": "127.0.0.1", "port": 11002, "protocol": "trojan",
				"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{
					"password": "admin-password", "email": "admin",
				}}},
				"streamSettings": map[string]interface{}{
					"network": "ws", "security": "none",
					"wsSettings": map[string]interface{}{"path": "/ws/trojan", "host": "edge.example.com"},
				},
			},
		},
		{
			name: "Shadowsocks AES 128",
			inbound: map[string]interface{}{
				"tag": "ss-aes-128", "listen": "0.0.0.0", "port": 18444, "protocol": "shadowsocks",
				"settings": map[string]interface{}{
					"clients": []interface{}{map[string]interface{}{"method": "aes-128-gcm", "password": "classic-password", "email": "admin", "level": 0}}, "network": "tcp,udp",
				},
			},
		},
		{
			name: "Shadowsocks AES 256",
			inbound: map[string]interface{}{
				"tag": "ss-aes-256", "listen": "0.0.0.0", "port": 18445, "protocol": "shadowsocks",
				"settings": map[string]interface{}{
					"clients": []interface{}{map[string]interface{}{"method": "aes-256-gcm", "password": "classic-password", "email": "admin", "level": 0}}, "network": "tcp,udp",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInboundBuilds(t, tt.inbound)
		})
	}
}

func TestExtractDomainsFromInboundReadsRealityTargetAndLegacyDest(t *testing.T) {
	seen := make(map[string]struct{})
	var domains []string
	extractDomainsFromInbound(map[string]interface{}{
		"streamSettings": map[string]interface{}{
			"realitySettings": map[string]interface{}{
				"target":      "new.example.com:443",
				"dest":        "legacy.example.com:8443",
				"serverNames": []interface{}{"sni.example.com"},
			},
		},
	}, seen, &domains)

	want := []string{"new.example.com", "legacy.example.com", "sni.example.com"}
	if len(domains) != len(want) {
		t.Fatalf("domains = %v, want %v", domains, want)
	}
	for index := range want {
		if domains[index] != want[index] {
			t.Fatalf("domains = %v, want %v", domains, want)
		}
	}
}

func TestValidateInboundRealityTargetRequiresCamouflageDomainAndAlignedSNI(t *testing.T) {
	request := func(target string, serverNames ...interface{}) map[string]interface{} {
		return map[string]interface{}{
			"inbound": map[string]interface{}{
				"streamSettings": map[string]interface{}{
					"security": "reality",
					"realitySettings": map[string]interface{}{
						"target": target, "serverNames": serverNames,
					},
				},
			},
		}
	}

	tests := []struct {
		name         string
		request      map[string]interface{}
		serverDomain string
		wantError    bool
	}{
		{name: "valid target", request: request("www.example.com:443", "www.example.com")},
		{name: "missing target port", request: request("www.example.com", "www.example.com"), wantError: true},
		{name: "IP target", request: request("203.0.113.9:443", "203.0.113.9"), wantError: true},
		{name: "invalid domain label", request: request("bad_label.example.com:443", "bad_label.example.com"), wantError: true},
		{name: "invalid port", request: request("www.example.com:70000", "www.example.com"), wantError: true},
		{name: "unexpected target suffix", request: request("www.example.com:443:8443", "www.example.com"), wantError: true},
		{name: "missing SNI", request: request("www.example.com:443"), wantError: true},
		{name: "unaligned SNI", request: request("www.example.com:443", "other.example.com"), wantError: true},
		{name: "self target", request: request("edge.example.com:443", "edge.example.com"), serverDomain: "edge.example.com", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := validateInboundRealityTarget(test.request, test.serverDomain)
			if (message != "") != test.wantError {
				t.Fatalf("message = %q, wantError=%v", message, test.wantError)
			}
		})
	}
}
