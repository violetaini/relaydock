// Package patches 包含启动时对 rule_templates/ 下用户本地模板做的"语义升级"补丁。
//
// 背景:
//
//	rule_templates/embed.go 的 Ensure() 设计为 "用户本地文件已存在就不覆盖",
//	这保护了用户对模板的自定义修改,但也让我们想"批量推送已知错误 DNS 配置的修复"
//	做不到。本包就是补这条路径 — 用 yaml 语义比对(顺序无关) + 内部块替换,
//	只在 dns 块"逐字段等于历史已知错误版本"时才替换,其它情况一律不动。
//
// 迁移性:
//
//	本文件设计为独立包,迁移到同类项目只需:
//	  1. 复制本 .go 文件到对应位置
//	  2. 在 main.go 启动序列里 ruletemplates.Ensure(...) 之后调一行 patches.ApplyDNSPatches(dir)
//	不依赖项目内任何其它符号,纯 yaml.v3 + 标准库。
package patches

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// dnsPatch 一对 (旧 dns 内部 yaml,新 dns 内部 yaml)。
// 旧/新 yaml 内容均为 dns 字段**内部值** — 不带顶层 "dns:" key。
// 比对时:用户文件里的 dns 块 decode 成 map[string]any,跟 oldYaml 同样 decode 成的 map 做 DeepEqual,
// 这样字段顺序差异、引号风格差异都不影响比对。
type dnsPatch struct {
	name    string
	oldYaml string
	newYaml string
}

var dnsPatches = []dnsPatch{
	{
		name: "redir-host with dns.google → 8.8.8.8 (v0.2)",
		oldYaml: `
enable: true
enhanced-mode: redir-host
nameserver:
  - https://dns.google/dns-query/dns-query#🚀 节点选择
direct-nameserver:
  - https://doh.pub/dns-query
nameserver-policy:
  geosite:cn,apple,private,steam,onedrive,category-games@cn:
    - https://doh.pub/dns-query
proxy-server-nameserver:
  - https://doh.pub/dns-query
ipv6: false
listen: 0.0.0.0:7874
default-nameserver:
  - https://cloudflare-dns.com/dns-query/dns-query#🚀 节点选择
`,
		newYaml: `
default-nameserver:
  - https://8.8.8.8/dns-query#🚀 节点选择
direct-nameserver:
  - https://1.12.12.12/dns-query
enable: true
ipv6: false
listen: 0.0.0.0:7874
nameserver:
  - https://8.8.8.8/dns-query#🚀 节点选择
nameserver-policy:
  geosite:cn,apple,private,steam,onedrive,category-games@cn:
    - https://1.12.12.12/dns-query
proxy-server-nameserver:
  - https://1.12.12.12/dns-query
`,
	},
	{
		name: "fake-ip with doh.pub → 120.53.53.53 (v0.2)",
		oldYaml: `
enable: true
enhanced-mode: fake-ip
fake-ip-range: 198.18.0.1/16
nameserver:
  - tls://8.8.8.8
  - tls://1.1.1.1
direct-nameserver:
  - https://doh.pub/dns-query
nameserver-policy:
  geosite:cn:
    - 223.5.5.5
    - 119.29.29.29
proxy-server-nameserver:
  - https://doh.pub/dns-query
ipv6: false
listen: 0.0.0.0:7874
default-nameserver:
  - tls://1.12.12.12
fake-ip-filter:
  - +.lan
  - +.local
  - +.example.com
`,
		newYaml: `
enable: true
enhanced-mode: fake-ip
fake-ip-range: 198.18.0.1/16
nameserver:
  - tls://8.8.8.8
  - tls://1.1.1.1
direct-nameserver:
  - https://120.53.53.53/dns-query
nameserver-policy:
  geosite:cn:
    - 223.5.5.5
    - 119.29.29.29
proxy-server-nameserver:
  - https://120.53.53.53/dns-query
ipv6: false
listen: 0.0.0.0:7874
default-nameserver:
  - tls://1.12.12.12
fake-ip-filter:
  - +.lan
  - +.local
  - +.example.com
`,
	},
}

// compiledPatch 预解析后的 patch:oldMap 用于比对,newNode 用于替换。
type compiledPatch struct {
	name    string
	oldMap  any
	newNode *yaml.Node
}

// ApplyDNSPatches 扫描 dir 下所有 .yaml/.yml 文件,匹配预置的旧 dns 块就替换为新版本。
//   - dir 为空时默认 "rule_templates"
//   - 不匹配任何 patch 的文件、没有 dns 字段的文件、不是 mapping 根的文件都跳过
//   - 写回原子(tmp + rename)
//   - 返回 (patched 文件数, error)
//
// 文件 dns 块以外的部分(proxies / proxy-groups / rules / 顶层 / 注释)由 yaml.Node 在
// re-marshal 时尽量保留位置。本包**不**追求保留原文件字节级排版 — yaml-encoded 的输出
// 字段顺序、引号风格可能跟手写版本略有差异,但**语义**完全等价。
func ApplyDNSPatches(dir string) (int, error) {
	if dir == "" {
		dir = "rule_templates"
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// 目录不存在不算错(还没调过 Ensure)
			return 0, nil
		}
		return 0, fmt.Errorf("read templates dir: %w", err)
	}

	compiled, err := compilePatches()
	if err != nil {
		return 0, err
	}

	patched := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		if applied, err := tryApplyToFile(path, compiled); err != nil {
			log.Printf("[DNSPatch] %s failed: %v", name, err)
		} else if applied != "" {
			log.Printf("[DNSPatch] %s ← [%s]", name, applied)
			patched++
		}
	}
	return patched, nil
}

func compilePatches() ([]compiledPatch, error) {
	out := make([]compiledPatch, 0, len(dnsPatches))
	for _, p := range dnsPatches {
		var oldMap any
		if err := yaml.Unmarshal([]byte(p.oldYaml), &oldMap); err != nil {
			return nil, fmt.Errorf("compile patch %q old: %w", p.name, err)
		}
		var newDoc yaml.Node
		if err := yaml.Unmarshal([]byte(p.newYaml), &newDoc); err != nil {
			return nil, fmt.Errorf("compile patch %q new: %w", p.name, err)
		}
		if newDoc.Kind != yaml.DocumentNode || len(newDoc.Content) == 0 {
			return nil, fmt.Errorf("compile patch %q new: empty document", p.name)
		}
		out = append(out, compiledPatch{
			name:    p.name,
			oldMap:  oldMap,
			newNode: newDoc.Content[0],
		})
	}
	return out, nil
}

// tryApplyToFile 读、解析、比对、替换、写回。
// 返回 (命中的 patch 名字, error)。两者都为空表示文件解析成功但没命中 patch。
func tryApplyToFile(path string, compiled []compiledPatch) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		// 模板文件本身不合法 yaml(用户手贱写错了),不去碰,等用户自己改
		return "", fmt.Errorf("parse: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return "", nil
	}
	rootMap := root.Content[0]
	if rootMap.Kind != yaml.MappingNode {
		return "", nil
	}

	dnsIdx := -1
	for i := 0; i+1 < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value == "dns" {
			dnsIdx = i + 1
			break
		}
	}
	if dnsIdx < 0 {
		return "", nil
	}
	dnsValue := rootMap.Content[dnsIdx]

	var dnsMap any
	if err := dnsValue.Decode(&dnsMap); err != nil {
		return "", fmt.Errorf("decode dns: %w", err)
	}

	for _, p := range compiled {
		if !reflect.DeepEqual(dnsMap, p.oldMap) {
			continue
		}
		rootMap.Content[dnsIdx] = p.newNode

		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(&root); err != nil {
			return "", fmt.Errorf("marshal: %w", err)
		}
		_ = enc.Close()

		// yaml.v3 把含 emoji 的字符串 marshal 成 "\U0001F680 ..." 这种形式,
		// 转回真实字符让模板文件可读(yaml 解析对带不带 \U escape 等价,Clash 端无差异)。
		output := unescapeUnicodeEmoji(buf.Bytes())

		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, output, 0o644); err != nil {
			return "", fmt.Errorf("write tmp: %w", err)
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("rename: %w", err)
		}
		return p.name, nil
	}
	return "", nil
}

// unicodeEscapeRe 匹配 yaml.v3 marshal 出来的 \U + 8 hex 或 \u + 4 hex 转义序列。
var unicodeEscapeRe = regexp.MustCompile(`\\U[0-9A-Fa-f]{8}|\\u[0-9A-Fa-f]{4}`)

// unescapeUnicodeEmoji 把 \Uxxxxxxxx / \uxxxx 替换回实际 unicode 字符。
// 简化版,仅处理 yaml.v3 输出含 emoji 时的可读性问题;**不**剥引号(yaml 端两种格式等价)。
// 为保持本包可独立移植到 sibling 项目,**不**依赖 internal/handler 里的同款 helper。
func unescapeUnicodeEmoji(in []byte) []byte {
	return unicodeEscapeRe.ReplaceAllFunc(in, func(m []byte) []byte {
		// m 形如 \Uxxxxxxxx 或 \uxxxx;hex 从 m[2:] 开始
		var r rune
		for _, c := range m[2:] {
			r = r*16 + hexNibble(c)
		}
		return []byte(string(r))
	})
}

func hexNibble(c byte) rune {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0')
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10
	}
	return 0
}
