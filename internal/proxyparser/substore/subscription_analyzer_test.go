package substore

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAnalyzeSubscription(t *testing.T) {
	// Sample subscription YAML content
	content := `
proxies:
  - name: 🇭🇰 香港 01
    type: vmess
    server: hk1.example.com
    port: 443
  - name: 🇭🇰 香港 02
    type: vmess
    server: hk2.example.com
    port: 443
  - name: 🇺🇸 美国 01
    type: vmess
    server: us1.example.com
    port: 443
  - name: 🇯🇵 日本 01
    type: vmess
    server: jp1.example.com
    port: 443
  - name: 🇸🇬 新加坡 01
    type: vmess
    server: sg1.example.com
    port: 443

proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - 🎯 全球直连
      - ♻️ 自动选择
      - 🇭🇰 香港节点
      - 🇺🇸 美国节点
  - name: ♻️ 自动选择
    type: url-test
    proxies:
      - 🇭🇰 香港 01
      - 🇭🇰 香港 02
      - 🇺🇸 美国 01
      - 🇯🇵 日本 01
      - 🇸🇬 新加坡 01
    url: http://www.gstatic.com/generate_204
    interval: 300
  - name: 🇭🇰 香港节点
    type: url-test
    proxies:
      - 🇭🇰 香港 01
      - 🇭🇰 香港 02
    url: http://www.gstatic.com/generate_204
    interval: 300
  - name: 🇺🇸 美国节点
    type: url-test
    proxies:
      - 🇺🇸 美国 01
    url: http://www.gstatic.com/generate_204
    interval: 300
  - name: 🎯 全球直连
    type: select
    proxies:
      - DIRECT

rules:
  - GEOIP,CN,🎯 全球直连
  - MATCH,🚀 节点选择
`

	allNodeNames := []string{
		"🇭🇰 香港 01", "🇭🇰 香港 02",
		"🇺🇸 美国 01",
		"🇯🇵 日本 01",
		"🇸🇬 新加坡 01",
	}

	result, err := AnalyzeSubscription(content, allNodeNames)
	if err != nil {
		t.Fatalf("AnalyzeSubscription failed: %v", err)
	}

	t.Logf("Analyzed %d proxy groups", len(result.ProxyGroups))
	t.Logf("All proxy names: %v", result.AllProxyNames)
	t.Logf("Matched region counts: %v", result.MatchedRegionCounts)
	t.Logf("Add region groups: %v", result.AddRegionGroups)

	for i, pg := range result.ProxyGroups {
		t.Logf("Proxy Group[%d]: Name='%s', Type='%s'", i, pg.Name, pg.Type)
		t.Logf("  IncludeAllProxies=%v, InferredFilter='%s', MatchedRegion='%s'",
			pg.IncludeAllProxies, pg.InferredFilter, pg.MatchedRegion)
		t.Logf("  ReferencedGroups=%v", pg.ReferencedGroups)
	}

	// Verify proxy names were extracted
	if len(result.AllProxyNames) != 5 {
		t.Errorf("Expected 5 proxy names, got %d", len(result.AllProxyNames))
	}

	// Verify region counts
	if result.MatchedRegionCounts["🇭🇰 香港节点"] != 2 {
		t.Errorf("Expected 2 Hong Kong nodes, got %d", result.MatchedRegionCounts["🇭🇰 香港节点"])
	}

	// Generate template
	templateContent := GenerateV3TemplateFromAnalysis(result)
	t.Logf("Generated template:\n%s", templateContent)

	if templateContent == "" {
		t.Error("Generated template is empty")
	}
}

func TestMatchesFilter(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		expected bool
	}{
		{"🇭🇰 香港 01", "港|HK|Hong Kong", true},
		{"🇺🇸 美国 01", "美|US|USA", true},
		{"🇯🇵 日本 01", "日|JP|Japan", true},
		{"🇸🇬 新加坡 01", "新加坡|SG|Singapore", true},
		{"xxx JP xxx", "🇯🇵|日本|(?<!尼|-)日|\\bJP(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Japan", true},
		{"印尼节点", "🇯🇵|日本|(?<!尼|-)日|\\bJP(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Japan", false},
		{"🇭🇰 香港 01", "美|US|USA", false},
		{"Random Node", "港|HK|Hong Kong", false},
	}

	for _, tt := range tests {
		result := matchesFilter(tt.name, tt.filter)
		if result != tt.expected {
			t.Errorf("matchesFilter(%q, %q) = %v, expected %v", tt.name, tt.filter, result, tt.expected)
		}
	}
}

func TestGenerateV3TemplatePreservesRuleProviders(t *testing.T) {
	analysis, err := AnalyzeSubscription(`
proxies:
  - {name: edge, type: vless, server: edge.example.com, port: 443}
proxy-groups:
  - {name: proxy, type: select, proxies: [edge]}
rules:
  - RULE-SET,private,DIRECT
  - MATCH,proxy
rule-providers:
  private:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://rules.example.com/private.mrs
    path: ./rules/private.mrs
`, nil)
	if err != nil {
		t.Fatal(err)
	}

	generated := GenerateV3TemplateFromAnalysis(analysis)
	var config map[string]any
	if err := yaml.Unmarshal([]byte(generated), &config); err != nil {
		t.Fatalf("generated template is invalid YAML: %v\n%s", err, generated)
	}
	providers, ok := config["rule-providers"].(map[string]any)
	if !ok {
		t.Fatalf("rule-providers missing from generated template: %s", generated)
	}
	private, ok := providers["private"].(map[string]any)
	if !ok {
		t.Fatalf("private provider missing: %#v", providers)
	}
	for key, want := range map[string]any{
		"type": "http", "behavior": "domain", "format": "mrs",
		"url": "https://rules.example.com/private.mrs", "path": "./rules/private.mrs",
	} {
		if private[key] != want {
			t.Fatalf("provider %s = %#v, want %#v", key, private[key], want)
		}
	}
	if private["interval"] != 86400 {
		t.Fatalf("provider interval = %#v, want 86400", private["interval"])
	}
}
