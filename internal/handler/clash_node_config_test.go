package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
	"gopkg.in/yaml.v3"
)

func TestParseClashNodeConfigPayload_YAMLAndJSON(t *testing.T) {
	yamlProxiesPayload := `
proxies:
  - name: 1111
    type: vmess
    server: 170.9.59.149
    port: 5245
    uuid: fd3123de-8ad2-480e-b106-8445cc4006e3
    alterId: 0
    cipher: auto
    network: tcp
    udp: true
    reality-opts:
      public-key: pub123
      short-id: 01234567
`
	m, normalizedJSON, err := parseClashNodeConfigPayload(yamlProxiesPayload)
	if err != nil {
		t.Fatalf("parseClashNodeConfigPayload failed on proxies YAML: %v", err)
	}
	if m["name"] != "1111" {
		t.Fatalf("expected name '1111' as string, got %#v", m["name"])
	}
	if _, hasNet := m["network"]; hasNet {
		t.Fatalf("expected network: tcp to be omitted, got %#v", m["network"])
	}
	if strings.Contains(normalizedJSON, `"network":"tcp"`) {
		t.Fatalf("normalizedJSON should not contain network:tcp: %s", normalizedJSON)
	}

	jsonPayload := `{"alterId":0,"cipher":"auto","name":"1111","network":"tcp","port":5245,"server":"170.9.59.149","type":"vmess","udp":true,"uuid":"fd3123de-8ad2-480e-b106-8445cc4006e3"}`
	m2, normalizedJSON2, err := parseClashNodeConfigPayload(jsonPayload)
	if err != nil {
		t.Fatalf("parseClashNodeConfigPayload failed on JSON: %v", err)
	}
	if _, hasNet := m2["network"]; hasNet {
		t.Fatalf("expected network: tcp to be omitted from JSON input, got %#v", m2["network"])
	}
	if strings.Contains(normalizedJSON2, `"network":"tcp"`) {
		t.Fatalf("normalizedJSON2 should not contain network:tcp: %s", normalizedJSON2)
	}

	node := mapToYAMLNode(m2)
	yamlBytes, err := yaml.Marshal(node)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}
	if strings.Contains(string(yamlBytes), "network: tcp") {
		t.Fatalf("mapToYAMLNode should omit network: tcp, got:\n%s", string(yamlBytes))
	}
}

func TestPackageSubscriptionExcludesForwardingProtocols(t *testing.T) {
	if !isNonClashForwardingProtocol("dokodemo-door") {
		t.Fatal("expected dokodemo-door to be recognized as non-Clash forwarding protocol")
	}
	if !isNonClashForwardingProtocol("tunnel") {
		t.Fatal("expected tunnel to be recognized as non-Clash forwarding protocol")
	}
	if isNonClashForwardingProtocol("vmess") {
		t.Fatal("did not expect vmess to be excluded")
	}
	if packageSubscriptionNodeEligible(context.Background(), nil, storage.Node{Enabled: true, Protocol: "dokodemo-door"}) {
		t.Fatal("dokodemo-door node should not be eligible for Clash subscription")
	}
	if !packageSubscriptionNodeEligible(context.Background(), nil, storage.Node{Enabled: true, Protocol: "vmess"}) {
		t.Fatal("vmess node should be eligible for Clash subscription")
	}
}
