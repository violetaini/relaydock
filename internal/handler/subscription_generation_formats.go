package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/proxyparser/substore"
	"github.com/violetaini/relaydock/internal/storage"
	"gopkg.in/yaml.v3"
)

func builtInSubscriptionConfig(nodes []map[string]any) ([]byte, error) {
	names := []string{}
	for _, p := range nodes {
		names = append(names, fmt.Sprint(p["name"]))
	}
	return yaml.Marshal(map[string]any{
		"mode": "rule", "proxies": nodes,
		"proxy-groups": []any{map[string]any{"name": "节点选择", "type": "select", "proxies": names}},
		"dns":          map[string]any{"enable": true, "nameserver": []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}},
		"rules":        []string{"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR6,fc00::/7,DIRECT,no-resolve", "DOMAIN-SUFFIX,lan,DIRECT", "GEOIP,CN,DIRECT", "MATCH,节点选择"},
	})
}

// Conversion support is checked before rendering groups. Unsupported nodes are
// counted explicitly; a target with zero supported nodes is never published.
func compatibleGenerationNodes(nodes []map[string]any, out storage.SubscriptionOutput) ([]map[string]any, []string) {
	kept := []map[string]any{}
	warnings := []string{}
	counts := map[string]int{}
	for _, p := range nodes {
		var err error
		typ := fmt.Sprint(p["type"])
		proxy := substore.Proxy(p)
		switch out.Client {
		case "clashmeta":
		case "v2ray", "uri", "shadowrocket":
			if p["dialer-proxy"] != nil {
				err = errors.New("链式节点不支持 URI 输出")
			} else {
				_, err = substore.NewURIProducer().ProduceOne(proxy)
			}
		case "clash-to-shadowrocket":
			if out.Mode == "nodes" {
				_, err = substore.NewURIProducer().ProduceOne(proxy)
			} else {
				result, e := substore.NewShadowrocketTemplateProducer().Produce([]substore.Proxy{proxy}, "", &substore.ProduceOptions{FullConfig: map[string]any{}})
				err = e
				if err == nil && !strings.Contains(fmt.Sprint(result), fmt.Sprint(p["name"])+"=") {
					err = errors.New("小火箭不支持该节点")
				}
			}
		case "clash-to-surge":
			_, err = substore.NewSurgeProducer().ProduceOne(proxy, "", &substore.ProduceOptions{})
		case "clash-to-loon":
			_, err = substore.NewLoonProducer().ProduceOne(proxy, "", &substore.ProduceOptions{})
		case "sing-box":
			result, e := substore.NewSingboxProducer().Produce([]substore.Proxy{proxy}, "internal", &substore.ProduceOptions{})
			err = e
			if err == nil {
				list, ok := result.([]map[string]interface{})
				if !ok || len(list) == 0 {
					err = errors.New("sing-box 不支持该节点")
				}
			}
		default:
			err = errors.New("未知客户端")
		}
		if err != nil {
			counts[typ]++
			continue
		}
		kept = append(kept, p)
	}
	for typ, count := range counts {
		warnings = append(warnings, fmt.Sprintf("%s 输出排除了 %d 个不兼容的 %s 节点", out.Client, count, typ))
	}
	return kept, warnings
}

func (h *SubscriptionHandler) convertGenerationOutput(ctx context.Context, data []byte, out storage.SubscriptionOutput) ([]byte, error) {
	if out.Client == "clashmeta" {
		return data, nil
	}
	if out.Client == "sing-box" && out.Mode == "full" {
		return h.convertGenerationSingbox(ctx, data)
	}
	return h.convertSubscription(ctx, data, generationClient(out))
}

// Standard Xray routing configuration is a separate download, since URI
// subscriptions have no field capable of carrying it. Application policy groups
// map to the client's proxy outbound; DIRECT/REJECT map to direct/block.
func generationXrayRouting(source map[string]any) (map[string]any, error) {
	rules := []any{}
	list, _ := source["rules"].([]any)
	for _, entry := range list {
		parts := strings.Split(fmt.Sprint(entry), ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 2 {
			return nil, errors.New("无效的路由规则")
		}
		kind := strings.ToUpper(parts[0])
		value := parts[1]
		policy := ""
		if len(parts) > 2 {
			policy = parts[2]
		}
		if kind == "MATCH" || kind == "FINAL" {
			policy = value
		}
		tag := "proxy"
		if policy == "DIRECT" {
			tag = "direct"
		}
		if policy == "REJECT" || policy == "REJECT-DROP" {
			tag = "block"
		}
		rule := map[string]any{"type": "field", "outboundTag": tag}
		switch kind {
		case "DOMAIN":
			rule["domain"] = []string{"full:" + value}
		case "DOMAIN-SUFFIX":
			rule["domain"] = []string{"domain:" + value}
		case "DOMAIN-KEYWORD":
			rule["domain"] = []string{value}
		case "DOMAIN-REGEX":
			rule["domain"] = []string{"regexp:" + value}
		case "GEOSITE":
			rule["domain"] = []string{"geosite:" + strings.ToLower(value)}
		case "GEOIP":
			rule["ip"] = []string{"geoip:" + strings.ToLower(value)}
		case "IP-CIDR", "IP-CIDR6":
			rule["ip"] = []string{value}
		case "SRC-IP-CIDR":
			rule["source"] = []string{value}
		case "DST-PORT":
			rule["port"] = value
		case "SRC-PORT":
			rule["sourcePort"] = value
		case "NETWORK":
			rule["network"] = strings.ToLower(value)
		case "PROTOCOL":
			rule["protocol"] = []string{strings.ToLower(value)}
		case "MATCH", "FINAL":
			rule["network"] = "tcp,udp"
		default:
			return nil, fmt.Errorf("Xray 路由导出不支持模板中的 %s 规则，请选择通用分流模板", kind)
		}
		rules = append(rules, rule)
		if kind == "MATCH" || kind == "FINAL" {
			break
		}
	}
	return map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules}, nil
}

// Modern sing-box uses native route actions and SRS rule sets, not deprecated
// geosite/geoip fields. Complex unmatched constructs fail explicitly instead of
// disappearing while the UI still claims the template is active.
func (h *SubscriptionHandler) convertGenerationSingbox(ctx context.Context, data []byte) ([]byte, error) {
	raw, err := h.convertSubscription(ctx, data, "sing-box")
	if err != nil {
		return nil, err
	}
	var target, source map[string]any
	if err = json.Unmarshal(raw, &target); err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(data, &source); err != nil {
		return nil, err
	}
	outbounds, _ := target["outbounds"].([]any)
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "DIRECT"})
	groups, _ := source["proxy-groups"].([]any)
	valid := map[string]bool{"DIRECT": true}
	for _, item := range outbounds {
		if ob, ok := item.(map[string]any); ok {
			valid[fmt.Sprint(ob["tag"])] = true
		}
	}
	for _, item := range groups {
		if g, ok := item.(map[string]any); ok {
			valid[fmt.Sprint(g["name"])] = true
		}
	}
	for _, item := range groups {
		g, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := g["name"].(string)
		typ, _ := g["type"].(string)
		if typ != "select" && typ != "url-test" {
			return nil, fmt.Errorf("sing-box 不支持模板策略组 %s 的 %s 类型，请使用通用分流模板", name, typ)
		}
		refs, _ := g["proxies"].([]any)
		names := []string{}
		for _, ref := range refs {
			tag := fmt.Sprint(ref)
			if !valid[tag] {
				return nil, fmt.Errorf("sing-box 策略组 %s 引用了不支持的节点或策略 %s", name, tag)
			}
			names = append(names, tag)
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("sing-box 策略组 %s 没有节点", name)
		}
		native := map[string]any{"type": "selector", "tag": name, "outbounds": names}
		if typ == "url-test" {
			native["type"] = "urltest"
			if u, ok := g["url"].(string); ok {
				native["url"] = u
			}
			if n, ok := g["interval"].(int); ok {
				native["interval"] = fmt.Sprintf("%ds", n)
			}
		}
		outbounds = append(outbounds, native)
	}
	rules := []any{}
	sets := []any{}
	setNames := map[string]bool{}
	final := "DIRECT"
	list, _ := source["rules"].([]any)
	for _, entry := range list {
		text, ok := entry.(string)
		if !ok {
			return nil, errors.New("sing-box 模板规则不是字符串")
		}
		parts := strings.Split(text, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 2 {
			return nil, fmt.Errorf("无效模板规则: %s", text)
		}
		kind := strings.ToUpper(parts[0])
		if kind == "MATCH" || kind == "FINAL" {
			final = parts[1]
			if final == "REJECT" || !valid[final] {
				return nil, fmt.Errorf("sing-box 不支持兜底策略 %s", final)
			}
			break
		}
		if len(parts) < 3 {
			return nil, fmt.Errorf("无效模板规则: %s", text)
		}
		value, policy := parts[1], parts[2]
		rule := map[string]any{"action": "route", "outbound": policy}
		if policy == "REJECT" || policy == "REJECT-DROP" {
			rule = map[string]any{"action": "reject"}
		} else if !valid[policy] {
			return nil, fmt.Errorf("sing-box 规则引用了未知策略 %s", policy)
		}
		switch kind {
		case "DOMAIN":
			rule["domain"] = []string{value}
		case "DOMAIN-SUFFIX":
			rule["domain_suffix"] = []string{value}
		case "DOMAIN-KEYWORD":
			rule["domain_keyword"] = []string{value}
		case "DOMAIN-REGEX":
			rule["domain_regex"] = []string{value}
		case "IP-CIDR", "IP-CIDR6":
			rule["ip_cidr"] = []string{value}
		case "SRC-IP-CIDR":
			rule["source_ip_cidr"] = []string{value}
		case "NETWORK":
			rule["network"] = strings.ToLower(value)
		case "DST-PORT", "SRC-PORT":
			n, e := strconv.Atoi(value)
			if e != nil {
				return nil, fmt.Errorf("sing-box 端口规则无法转换: %s", text)
			}
			key := "port"
			if kind == "SRC-PORT" {
				key = "source_port"
			}
			rule[key] = []int{n}
		case "PROCESS-NAME":
			rule["process_name"] = []string{value}
		case "PROCESS-PATH":
			rule["process_path"] = []string{value}
		case "GEOIP", "GEOSITE":
			category := strings.ToLower(value)
			if !regexp.MustCompile(`^[a-z0-9_@!.-]+$`).MatchString(category) {
				return nil, fmt.Errorf("不支持的 GEO 分类 %s", category)
			}
			tag := strings.ToLower(kind) + "-" + category
			rule["rule_set"] = []string{tag}
			if !setNames[tag] {
				sets = append(sets, map[string]any{"type": "remote", "tag": tag, "format": "binary", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/" + strings.ToLower(kind) + "/" + category + ".srs", "download_detour": final})
				setNames[tag] = true
			}
		default:
			return nil, fmt.Errorf("sing-box 暂不支持模板中的 %s 规则，请选择通用分流模板或仅节点输出", kind)
		}
		rules = append(rules, rule)
	}
	target["outbounds"] = outbounds
	// Rule-set downloads must not rely on a final rule that itself needs them.
	for _, item := range sets {
		item.(map[string]any)["download_detour"] = "DIRECT"
	}
	target["route"] = map[string]any{"rules": rules, "rule_set": sets, "final": final, "default_domain_resolver": "local"}
	servers := []any{map[string]any{"type": "local", "tag": "local"}}
	if dns, ok := source["dns"].(map[string]any); ok {
		for _, field := range []string{"nameserver-policy", "fallback", "fake-ip-filter"} {
			if dns[field] != nil {
				return nil, fmt.Errorf("sing-box 暂不支持模板 DNS 的 %s 设置，请使用通用分流模板", field)
			}
		}
		list, _ := dns["nameserver"].([]any)
		for i, item := range list {
			value, ok := item.(string)
			if !ok {
				continue
			}
			u, e := url.Parse(value)
			if e != nil || u.Scheme != "https" {
				return nil, errors.New("sing-box 完整配置目前要求模板使用 HTTPS DNS")
			}
			ns := map[string]any{"type": "https", "tag": fmt.Sprintf("dns-%d", i), "server": u.Hostname(), "path": u.EscapedPath(), "domain_resolver": "local"}
			if u.Port() != "" {
				port, e := strconv.Atoi(u.Port())
				if e != nil {
					return nil, e
				}
				ns["server_port"] = port
			}
			if u.Fragment != "" {
				if !valid[u.Fragment] {
					return nil, errors.New("DNS 引用了未知策略组")
				}
				ns["detour"] = u.Fragment
			}
			servers = append(servers, ns)
		}
	}
	target["dns"] = map[string]any{"servers": servers, "final": "local"}
	if len(servers) > 1 {
		target["dns"].(map[string]any)["final"] = "dns-0"
	}
	target["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}}
	return json.MarshalIndent(target, "", "  ")
}
