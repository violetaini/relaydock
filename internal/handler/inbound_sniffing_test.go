package handler

import "testing"

func TestApplyManagedInboundSniffingEnablesEveryProxyProtocol(t *testing.T) {
	protocols := []string{
		"vless", "vmess", "trojan", "shadowsocks", "socks", "http",
		"hysteria2", "tuic", "anytls",
	}
	for _, protocol := range protocols {
		t.Run(protocol, func(t *testing.T) {
			request := map[string]interface{}{
				"inbound": map[string]interface{}{
					"protocol": protocol,
					"sniffing": map[string]interface{}{
						"enabled":        false,
						"excludeDomains": []interface{}{"example.test"},
					},
				},
			}
			applyManagedInboundSniffing(request)
			inbound := request["inbound"].(map[string]interface{})
			sniffing := inbound["sniffing"].(map[string]interface{})
			if enabled, _ := sniffing["enabled"].(bool); !enabled {
				t.Fatalf("sniffing.enabled=%v, want true", sniffing["enabled"])
			}
			if _, ok := sniffing["destOverride"]; !ok {
				t.Fatal("destOverride was not defaulted")
			}
			if _, ok := sniffing["excludeDomains"]; !ok {
				t.Fatal("existing sniffing options were discarded")
			}
		})
	}
}

func TestApplyManagedInboundSniffingKeepsProtocolExceptions(t *testing.T) {
	wireGuard := map[string]interface{}{
		"inbound": map[string]interface{}{
			"protocol": "wireguard",
			"sniffing": map[string]interface{}{"enabled": true},
		},
	}
	applyManagedInboundSniffing(wireGuard)
	wgSniffing := wireGuard["inbound"].(map[string]interface{})["sniffing"].(map[string]interface{})
	if enabled, _ := wgSniffing["enabled"].(bool); enabled {
		t.Fatal("WireGuard sniffing must remain disabled")
	}

	tunnelInbound := map[string]interface{}{
		"protocol": "dokodemo-door",
		"settings": map[string]interface{}{"address": "127.0.0.1"},
	}
	tunnel := map[string]interface{}{"inbound": tunnelInbound}
	applyManagedInboundSniffing(tunnel)
	if _, exists := tunnelInbound["sniffing"]; exists {
		t.Fatal("forwarding tunnel unexpectedly received sniffing configuration")
	}
}
