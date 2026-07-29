package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
)

func managedTLSClientOptionRequest() map[string]interface{} {
	return map[string]interface{}{
		"action": "add",
		"client_options": map[string]interface{}{
			"skip_cert_verify": true,
		},
		"inbound": map[string]interface{}{
			"tag":      "vless-tls-test",
			"port":     float64(443),
			"protocol": "vless",
			"settings": map[string]interface{}{
				"clients": []interface{}{map[string]interface{}{"id": "test-uuid"}},
			},
			"streamSettings": map[string]interface{}{
				"network":  "tcp",
				"security": "tls",
				"tlsSettings": map[string]interface{}{
					"serverName": "edge.example.test",
				},
			},
		},
	}
}

func TestValidateInboundClientsSelfOnlyChecksHysteriaUsers(t *testing.T) {
	ctx := auth.ContextWithUsername(context.Background(), "alice")
	request := map[string]interface{}{
		"inbound": map[string]interface{}{
			"settings": map[string]interface{}{
				"users": []interface{}{map[string]interface{}{"auth": "secret", "email": "alice"}},
			},
		},
	}
	if message := validateInboundClientsSelfOnly(ctx, request); message != "" {
		t.Fatalf("own Hysteria user rejected: %s", message)
	}
	request["inbound"].(map[string]interface{})["settings"].(map[string]interface{})["users"] =
		[]interface{}{map[string]interface{}{"auth": "secret", "email": "bob"}}
	if message := validateInboundClientsSelfOnly(ctx, request); !strings.Contains(message, "bob") {
		t.Fatalf("foreign Hysteria user was not rejected: %q", message)
	}
}

func TestExtractManagedClientOptionsStripsAgentPayload(t *testing.T) {
	request := managedTLSClientOptionRequest()
	skip, err := extractManagedClientOptions(request)
	if err != nil || !skip {
		t.Fatalf("extractManagedClientOptions = %v, %v", skip, err)
	}
	if _, exists := request["client_options"]; exists {
		t.Fatal("client_options remained in Agent request")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "client_options") || strings.Contains(string(encoded), managedClientSkipCertVerifyMarker) {
		t.Fatalf("panel-only option leaked to Agent payload: %s", encoded)
	}
}

func TestExtractManagedClientOptionsRejectsInvalidUse(t *testing.T) {
	for name, mutate := range map[string]func(map[string]interface{}){
		"non TLS inbound": func(request map[string]interface{}) {
			stream := request["inbound"].(map[string]interface{})["streamSettings"].(map[string]interface{})
			stream["security"] = "none"
		},
		"unknown option": func(request map[string]interface{}) {
			request["client_options"].(map[string]interface{})["other"] = true
		},
		"non boolean": func(request map[string]interface{}) {
			request["client_options"].(map[string]interface{})["skip_cert_verify"] = "yes"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := managedTLSClientOptionRequest()
			mutate(request)
			if _, err := extractManagedClientOptions(request); err == nil {
				t.Fatal("invalid client option was accepted")
			}
		})
	}
}

func TestInboundToClashAppliesPanelClientTLSOption(t *testing.T) {
	request := managedTLSClientOptionRequest()
	inbound := request["inbound"].(map[string]interface{})
	inbound[managedClientSkipCertVerifyMarker] = true

	proxy, err := (&RemoteManageHandler{}).inboundToClashProxy(inbound, "203.0.113.10", "edge", 0)
	if err != nil {
		t.Fatalf("inboundToClashProxy: %v", err)
	}
	if skip, ok := proxy["skip-cert-verify"].(bool); !ok || !skip {
		t.Fatalf("skip-cert-verify = %#v, want true", proxy["skip-cert-verify"])
	}
}
