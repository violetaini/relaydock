package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func wireGuardInboundRequest(t *testing.T) map[string]interface{} {
	t.Helper()
	var request map[string]interface{}
	if err := json.Unmarshal([]byte(`{
		"action":"add",
		"inbound":{
			"tag":"wireguard-in",
			"listen":"0.0.0.0",
			"port":51820,
			"protocol":"wireguard",
			"settings":{
				"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"address":["10.66.66.1/32"],
				"mtu":1420,
				"noKernelTun":false,
				"peers":[{"publicKey":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","allowedIPs":["10.66.66.2/32"],"keepAlive":25}]
			},
			"sniffing":{"enabled":false}
		}
	}`), &request); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestValidateInboundWireGuardAcceptsPanelPresetAndXrayBuildsIt(t *testing.T) {
	request := wireGuardInboundRequest(t)
	if message := validateInboundWireGuard(request); message != "" {
		t.Fatalf("validation failed: %s", message)
	}
	inboundJSON, err := json.Marshal(request["inbound"])
	if err != nil {
		t.Fatal(err)
	}
	var inbound conf.InboundDetourConfig
	if err := json.Unmarshal(inboundJSON, &inbound); err != nil {
		t.Fatal(err)
	}
	if _, err := inbound.Build(); err != nil {
		t.Fatalf("xray rejected panel WireGuard preset: %v", err)
	}
}

func TestValidateInboundWireGuardRejectsClientPrivateKeyAndStreamSettings(t *testing.T) {
	request := wireGuardInboundRequest(t)
	settings := request["inbound"].(map[string]interface{})["settings"].(map[string]interface{})
	settings["peers"].([]interface{})[0].(map[string]interface{})["privateKey"] = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	if message := validateInboundWireGuard(request); !strings.Contains(message, "客户端私钥") {
		t.Fatalf("message = %q, want client private key rejection", message)
	}

	request = wireGuardInboundRequest(t)
	request["inbound"].(map[string]interface{})["streamSettings"] = map[string]interface{}{"security": "tls"}
	if message := validateInboundWireGuard(request); !strings.Contains(message, "不能搭配") {
		t.Fatalf("message = %q, want streamSettings rejection", message)
	}
}

func TestValidateInboundWireGuardRejectsInvalidAndDuplicatePeers(t *testing.T) {
	request := wireGuardInboundRequest(t)
	settings := request["inbound"].(map[string]interface{})["settings"].(map[string]interface{})
	peer := settings["peers"].([]interface{})[0].(map[string]interface{})
	settings["peers"] = []interface{}{peer, map[string]interface{}{
		"publicKey":  peer["publicKey"],
		"allowedIPs": []interface{}{"10.66.66.3/32"},
	}}
	if message := validateInboundWireGuard(request); !strings.Contains(message, "相同公钥") {
		t.Fatalf("message = %q, want duplicate public key rejection", message)
	}

	request = wireGuardInboundRequest(t)
	request["inbound"].(map[string]interface{})["settings"].(map[string]interface{})["mtu"] = float64(128)
	if message := validateInboundWireGuard(request); !strings.Contains(message, "MTU") {
		t.Fatalf("message = %q, want MTU rejection", message)
	}

	request = wireGuardInboundRequest(t)
	request["inbound"].(map[string]interface{})["settings"].(map[string]interface{})["address"] = []interface{}{"10.66.66.1/24"}
	if message := validateInboundWireGuard(request); !strings.Contains(message, "/32") {
		t.Fatalf("message = %q, want WireGuard host-prefix rejection", message)
	}
}
