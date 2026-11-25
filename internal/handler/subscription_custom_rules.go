package handler

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
	"gopkg.in/yaml.v3"
)

//go:embed subscription_rule_categories.json
var subscriptionRuleCategoryJSON []byte

type subscriptionRuleCategory struct {
	Key   string   `json:"key"`
	Rules []string `json:"rules"`
}

var subscriptionRuleCategories = func() []subscriptionRuleCategory {
	var categories []subscriptionRuleCategory
	if err := json.Unmarshal(subscriptionRuleCategoryJSON, &categories); err != nil {
		panic(err)
	}
	return categories
}()

func validateSubscriptionRuleCategories(out storage.SubscriptionOutput) error {
	if out.RuleMode != "" && out.RuleMode != "template" && out.RuleMode != "custom" {
		return errors.New("无效的规则模式")
	}
	if out.RuleMode != "custom" {
		return nil
	}
	known := map[string]bool{}
	for _, category := range subscriptionRuleCategories {
		known[category.Key] = true
	}
	if len(out.RuleCategories) > len(known) {
		return errors.New("规则分类数量无效")
	}
	seen := map[string]bool{}
	for _, key := range out.RuleCategories {
		if !known[key] || seen[key] {
			return errors.New("规则分类无效或重复，请重新选择")
		}
		seen[key] = true
	}
	return nil
}

const subscriptionRuleSetPrefix = "/api/public/subscription-rule-sets/"

func renderCustomSubscriptionRules(ctx context.Context, repo *storage.TrafficRepository, nodes []map[string]any, out storage.SubscriptionOutput) ([]byte, error) {
	selected := map[string]bool{}
	for _, key := range out.RuleCategories {
		selected[key] = true
	}
	rules := []string{}
	providers := map[string]any{}
	nativeLists := out.Client == "clash-to-shadowrocket" || out.Client == "clash-to-surge" || out.Client == "clash-to-loon"
	base := ""
	if nativeLists && len(selected) > 0 {
		var err error
		base, err = canonicalProviderMasterURL(ctx, repo)
		if err != nil {
			return nil, errors.New("请先在系统设置填写面板 HTTPS 地址，以提供跨客户端分类规则")
		}
	}
	for _, category := range subscriptionRuleCategories {
		if !selected[category.Key] {
			continue
		}
		for _, text := range category.Rules {
			if nativeLists {
				parts := strings.Split(text, ",")
				kind, name := strings.ToLower(parts[0]), strings.ToLower(parts[1])
				key := kind + "-" + name
				providers[key] = map[string]any{"type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": base + subscriptionRuleSetPrefix + kind + "/" + name + ".list"}
				text = "RULE-SET," + key + "," + parts[2]
			}
			rules = append(rules, text)
		}
	}
	rules = append(rules, "MATCH,PROXY")
	names := []string{}
	for _, node := range nodes {
		names = append(names, node["name"].(string))
	}
	doc := map[string]any{
		"mode": "rule", "mixed-port": 7890, "allow-lan": false, "log-level": "info",
		"geodata-mode": true, "geo-auto-update": true, "geo-update-interval": 24,
		"geox-url":     map[string]any{"geoip": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat", "geosite": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat"},
		"proxies":      nodes,
		"proxy-groups": []any{map[string]any{"name": "PROXY", "type": "select", "proxies": names}, map[string]any{"name": "AUTO", "type": "url-test", "url": "https://cp.cloudflare.com/generate_204", "interval": 300, "proxies": names}},
		"rules":        rules,
	}
	if len(providers) > 0 {
		doc["rule-providers"] = providers
	}
	return yaml.Marshal(doc)
}
