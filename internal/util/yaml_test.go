package util

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSanitizeAndReorderClashProxyToNode(t *testing.T) {
	proxy := map[string]any{
		"alterId":                 0,
		"cipher":                  "auto",
		"name":                    "1111",
		"network":                 "tcp",
		"port":                    5245,
		"server":                  "170.9.59.149",
		"type":                    "vmess",
		"udp":                     true,
		"uuid":                    "fd3123de-8ad2-480e-b106-8445cc4006e3",
		"x-arcway-managed-users": []any{"u1"},
	}

	node := ReorderProxyFieldsToNode(proxy)
	out, err := yaml.Marshal(node)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}
	text := string(out)
	if strings.Contains(text, "network: tcp") {
		t.Fatalf("expected network: tcp to be omitted, got:\n%s", text)
	}
	if strings.Contains(text, "x-arcway-managed-users") {
		t.Fatalf("expected internal marker to be omitted, got:\n%s", text)
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) < 4 {
		t.Fatalf("unexpected yaml lines: %v", lines)
	}
	if !strings.HasPrefix(lines[0], "name:") ||
		!strings.HasPrefix(lines[1], "type: vmess") ||
		!strings.HasPrefix(lines[2], "server: 170.9.59.149") ||
		!strings.HasPrefix(lines[3], "port: 5245") {
		t.Fatalf("expected canonical priority field order (name, type, server, port), got:\n%s", text)
	}
}
