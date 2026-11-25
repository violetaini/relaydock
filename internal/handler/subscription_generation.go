package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/proxyparser"
	"github.com/violetaini/relaydock/internal/speedtest"
	"github.com/violetaini/relaydock/internal/storage"
	"gopkg.in/yaml.v3"
)

type generationRequest struct {
	ID                        int64                           `json:"id,omitempty"`
	Name                      string                          `json:"name"`
	Description               string                          `json:"description"`
	Filename                  string                          `json:"filename"`
	SelectedNodeIDs           []int64                         `json:"selected_node_ids"`
	SelectedCustomRuleIDs     []int64                         `json:"selected_custom_rule_ids"`
	SelectedOverrideScriptIDs []int64                         `json:"selected_override_script_ids"`
	Generation                *storage.SubscriptionGeneration `json:"generation"`
	TrafficLimit              json.RawMessage                 `json:"traffic_limit,omitempty"`
}
type previewNodeSummary struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	CountryCode string `json:"country_code,omitempty"`
	SourceIndex int    `json:"source_index,omitempty"`
}

type generationPreview struct {
	Input     int                  `json:"input"`
	Duplicate int                  `json:"duplicate"`
	Filtered  int                  `json:"filtered"`
	Dead      int                  `json:"dead"`
	Unknown   int                  `json:"unknown"`
	Output    int                  `json:"output"`
	Warnings  []string             `json:"warnings"`
	Content   string               `json:"content"`
	Client    string               `json:"client"`
	Nodes     []previewNodeSummary `json:"nodes,omitempty"`
	Outputs   []generationPreview  `json:"outputs,omitempty"`
}

const builtInSubscriptionTemplate = "__relaydock_balanced__"

func generationClient(out storage.SubscriptionOutput) string {
	if out.Mode == "nodes" {
		switch out.Client {
		case "clash-to-shadowrocket", "shadowrocket":
			return "v2ray"
		case "clash-to-surge":
			return "surge"
		case "clash-to-loon":
			return "loon"
		}
	}
	return out.Client
}

func subscriptionKind(f storage.SubscribeFile) string {
	if f.Generation != nil {
		return f.Generation.Kind
	}
	if strings.HasPrefix(f.Description, "[策略订阅]") || strings.HasPrefix(f.Description, "[策略訂閱]") {
		return "strategy"
	}
	if f.Type == storage.SubscribeTypeImport || f.Type == storage.SubscribeTypeUpload || f.URL != "" {
		return "external"
	}
	return "custom"
}

func generationFingerprint(p map[string]any) string {
	copy := make(map[string]any, len(p))
	for k, v := range p {
		if k != "name" {
			copy[k] = v
		}
	}
	b, _ := json.Marshal(copy)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (h *SubscriptionHandler) validateGeneration(ctx context.Context, f storage.SubscribeFile) error {
	g := f.Generation
	if g == nil {
		return errors.New("缺少订阅生成设置")
	}
	if g.Kind != "strategy" && g.Kind != "custom" && g.Kind != "external" {
		return errors.New("无效的订阅分类")
	}
	if len(g.SourceIDs) > 100 || len(g.Outputs) == 0 || len(g.Outputs) > 8 {
		return errors.New("请选择 1–8 个客户端输出，来源最多 100 个")
	}
	if g.Kind == "strategy" && len(g.SourceIDs) == 0 {
		return errors.New("请至少选择一个来源订阅")
	}
	if g.Kind != "strategy" && len(g.SourceIDs) > 0 {
		return errors.New("只有策略订阅可以绑定其他订阅")
	}
	if g.Kind == "custom" && len(f.SelectedNodeIDs) == 0 {
		return errors.New("请至少选择一个面板节点")
	}
	for _, pattern := range []string{g.Processing.Include, g.Processing.Exclude} {
		if len(pattern) > 512 {
			return errors.New("过滤表达式过长")
		}
		if pattern != "" {
			if _, err := regexp.Compile(pattern); err != nil {
				return errors.New("节点过滤正则表达式无效")
			}
		}
	}
	if g.Processing.Sort != "" && g.Processing.Sort != "source" && g.Processing.Sort != "name" && g.Processing.Sort != "type" && g.Processing.Sort != "region" && g.Processing.Sort != "custom" {
		return errors.New("无效的排序方式")
	}
	if g.Processing.SortDirection != "" && g.Processing.SortDirection != "asc" && g.Processing.SortDirection != "desc" {
		return errors.New("无效的排序方向")
	}
	if len(g.Processing.TypeOrder) > 100 || len(g.Processing.RegionOrder) > 100 {
		return errors.New("节点类型或地区排序列表过长")
	}
	if len(g.Processing.CustomOrder) > 5000 {
		return errors.New("自定义节点排序列表过长")
	}
	seen := map[string]bool{}
	for _, out := range g.Outputs {
		if err := validateSubscriptionRuleCategories(out); err != nil {
			return err
		}
		switch out.Client {
		case "clashmeta", "shadowrocket", "clash-to-shadowrocket", "v2ray", "uri", "sing-box", "clash-to-surge", "clash-to-loon":
		default:
			return errors.New("不支持的客户端输出")
		}
		if seen[out.Client] {
			return errors.New("同一客户端只能保存一组输出设置")
		}
		seen[out.Client] = true
		if out.Mode != "nodes" && out.Mode != "full" && out.Mode != "source" {
			return errors.New("无效的规则模板模式")
		}
		if (out.Client == "v2ray" || out.Client == "uri" || out.Client == "shadowrocket") && out.Mode != "nodes" {
			return errors.New("该客户端节点订阅不携带分流规则，请选择仅节点输出")
		}
		if out.Mode == "source" {
			if out.Client != "clashmeta" {
				return errors.New("保留上游原配置目前仅支持 Clash Meta")
			}
			if g.Kind == "custom" || (g.Kind == "strategy" && len(g.SourceIDs) != 1) {
				return errors.New("仅单一外部订阅可以保留上游规则")
			}
		}
		if out.Mode == "full" {
			if out.RuleMode == "custom" {
				continue
			}
			if out.TemplateFilename == builtInSubscriptionTemplate {
				continue
			}
			if out.TemplateFilename == "" || filepath.Base(out.TemplateFilename) != out.TemplateFilename || strings.ContainsAny(out.TemplateFilename, `/\`) {
				return errors.New("请选择有效的规则模板")
			}
			owner, err := h.repo.GetRuleTemplateOwner(ctx, out.TemplateFilename)
			if err != nil {
				return fmt.Errorf("读取模板权限失败: %w", err)
			}
			if owner != "" && owner != f.CreatedBy && !userIsAdmin(ctx, h.repo, f.CreatedBy) {
				return errors.New("无权使用该规则模板")
			}
			if _, err := os.Stat(filepath.Join("rule_templates", out.TemplateFilename)); err != nil {
				return errors.New("所选规则模板不存在")
			}
		}
	}
	return nil
}

func (h *SubscriptionHandler) readGenerationSource(ctx context.Context, f storage.SubscribeFile) ([]map[string]any, map[string]any, error) {
	viewer, _ := ctx.Value(subscriptionViewerKey{}).(string)
	if subscriptionKind(f) == "custom" && (len(f.SelectedNodeIDs) > 0 || len(f.SelectedTags) > 0 || f.TemplateFilename != "") {
		if viewer != "" && !userIsAdmin(ctx, h.repo, viewer) {
			f.CreatedBy = viewer
		}
		nodes, err := h.subscriptionNodeProxies(ctx, f)
		return nodes, nil, err
	}
	if viewer != "" && viewer != f.CreatedBy && !userIsAdmin(ctx, h.repo, viewer) {
		return nil, nil, errors.New("外部来源不能按用户独立统计，不能向该用户下发共享节点凭据")
	}
	if err := storage.ValidateSubscribeFilename(f.Filename); err != nil {
		return nil, nil, err
	}
	unlock, err := lockSubscriptionFilenames(f.Filename)
	if err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(filepath.Join(h.baseDir, f.Filename))
	unlock()
	if err != nil {
		return nil, nil, fmt.Errorf("来源 %s 暂不可用", f.Name)
	}
	hydrated, err := hydrateWireGuardSubscriptionContent(ctx, h.repo, f.Filename, string(raw))
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(hydrated), &doc); err != nil {
		return nil, nil, err
	}
	var proxies []map[string]any
	if list, ok := doc["proxies"].([]any); ok {
		for _, item := range list {
			if p, ok := item.(map[string]any); ok {
				proxies = append(proxies, p)
			}
		}
	}
	if len(proxies) == 0 {
		return nil, nil, fmt.Errorf("来源 %s 没有可用节点（仅含 Provider 的配置需先展开节点）", f.Name)
	}
	if f.Generation != nil && len(f.Generation.Processing.NodeRegions) > 0 {
		for _, p := range proxies {
			fp := generationFingerprint(p)
			if cc, ok := f.Generation.Processing.NodeRegions[fp]; ok && cc != "" {
				p["_rd_country_code"] = cc
			} else if cc, ok := f.Generation.Processing.NodeRegions[fmt.Sprint(p["name"])]; ok && cc != "" {
				p["_rd_country_code"] = cc
			}
		}
	}
	return proxies, doc, nil
}

// Every read rechecks source ownership. A revoked or removed source cannot be
// served out of a cached combined file. Strategy nesting is deliberately barred.
func (h *SubscriptionHandler) generationSources(ctx context.Context, f storage.SubscribeFile) ([]map[string]any, map[string]any, error) {
	if f.Generation.Kind != "strategy" {
		return h.readGenerationSource(ctx, f)
	}
	var proxies []map[string]any
	var inherited map[string]any
	var batches [][]map[string]any
	var batchNames []string
	nameCounts := map[string]int{}
	seen := map[int64]bool{}
	for _, id := range f.Generation.SourceIDs {
		if id <= 0 || id == f.ID || seen[id] {
			return nil, nil, errors.New("来源订阅重复或引用了自身")
		}
		seen[id] = true
		source, err := h.repo.GetSubscribeFileByID(ctx, id)
		if err != nil {
			return nil, nil, errors.New("来源订阅已删除或不可访问")
		}
		if source.CreatedBy != f.CreatedBy {
			if !userIsAdmin(ctx, h.repo, f.CreatedBy) || (source.CreatedBy != "" && !userIsAdmin(ctx, h.repo, source.CreatedBy)) {
				return nil, nil, errors.New("来源订阅已删除或不可访问")
			}
		}
		if subscriptionKind(source) == "strategy" {
			return nil, nil, errors.New("策略订阅不能再次作为组合来源")
		}
		nodes, doc, err := h.readGenerationSource(ctx, source)
		if err != nil {
			return nil, nil, err
		}
		if len(f.Generation.SourceIDs) == 1 && subscriptionKind(source) == "external" {
			inherited = doc
		}
		batches = append(batches, nodes)
		batchNames = append(batchNames, fmt.Sprintf("%s #%d", source.Name, source.ID))
		for _, p := range nodes {
			nameCounts[fmt.Sprint(p["name"])]++
		}
	}
	for i, batch := range batches {
		renames := map[string]string{}
		for _, p := range batch {
			name := fmt.Sprint(p["name"])
			if nameCounts[name] > 1 {
				renames[name] = batchNames[i] + " · " + name
				p["name"] = renames[name]
			}
		}
		for _, p := range batch {
			if replacement := renames[fmt.Sprint(p["dialer-proxy"])]; replacement != "" {
				p["dialer-proxy"] = replacement
			}
			p["_rd_source_index"] = i
		}
		proxies = append(proxies, batch...)
	}
	return proxies, inherited, nil
}

func (h *SubscriptionHandler) processGenerationNodes(ctx context.Context, f storage.SubscribeFile, nodes []map[string]any) ([]map[string]any, generationPreview, error) {
	stats := generationPreview{Input: len(nodes), Warnings: []string{}}
	cfg := f.Generation.Processing
	var include, exclude *regexp.Regexp
	if cfg.Include != "" {
		include = regexp.MustCompile(cfg.Include)
	}
	if cfg.Exclude != "" {
		exclude = regexp.MustCompile(cfg.Exclude)
	}
	excluded := map[string]bool{}
	for _, t := range cfg.ExcludeTypes {
		excluded[strings.ToLower(t)] = true
	}
	health, err := h.repo.ListSubscriptionNodeHealth(ctx, f.CreatedBy)
	if err != nil {
		return nil, stats, err
	}
	fingerprints := map[string]string{}
	aliases := map[string]string{}
	names := map[string]int{}
	var filtered, live []map[string]any
	for _, p := range nodes {
		name, _ := p["name"].(string)
		typ, _ := p["type"].(string)
		if include != nil && !include.MatchString(name) || exclude != nil && exclude.MatchString(name) || excluded[strings.ToLower(typ)] {
			stats.Filtered++
			continue
		}
		fp := generationFingerprint(p)
		if cfg.Deduplicate && fingerprints[fp] != "" {
			aliases[name] = fingerprints[fp]
			stats.Duplicate++
			continue
		}
		fingerprints[fp] = name
		filtered = append(filtered, p)
		probe, known := health[fp]
		recent := known && time.Since(probe.CheckedAt) < 15*time.Minute
		if !recent {
			stats.Unknown++
		}
		if cfg.RemoveDead && recent && probe.Failures >= 3 {
			stats.Dead++
			continue
		}
		live = append(live, p)
	}
	if len(live) == 0 && len(filtered) > 0 && stats.Dead > 0 {
		live = filtered
		stats.Dead = 0
		stats.Warnings = append(stats.Warnings, "所有节点检测失败，本次保留当前来源节点，避免发布空订阅")
	}
	if len(live) == 0 {
		return nil, stats, errors.New("处理后没有可用节点，请调整来源或过滤条件")
	}
	// Keep stable, unique names and fix dialer references within each output.
	for _, p := range live {
		if replacement := aliases[fmt.Sprint(p["dialer-proxy"])]; replacement != "" {
			p["dialer-proxy"] = replacement
		}
		name, _ := p["name"].(string)
		if name == "" {
			name = "节点"
		}
		names[name]++
		if names[name] > 1 {
			p["name"] = fmt.Sprintf("%s (%d)", name, names[name])
		} else {
			p["name"] = name
		}
	}
	hostCountryMap := h.buildProxyHostCountryMap(ctx)
	sortGenerationNodes(live, cfg, hostCountryMap)
	nodesMeta := make([]previewNodeSummary, 0, len(live))
	for _, p := range live {
		srcIdx, _ := p["_rd_source_index"].(int)
		delete(p, "_rd_source_index")
		cc := resolveProxyCountryCode(p, hostCountryMap)
		if cc == "UN" {
			cc = ""
		}
		nodesMeta = append(nodesMeta, previewNodeSummary{
			Key:         generationFingerprint(p),
			Name:        fmt.Sprint(p["name"]),
			Type:        strings.ToLower(fmt.Sprint(p["type"])),
			CountryCode: cc,
			SourceIndex: srcIdx,
		})
	}
	stats.Nodes = nodesMeta
	stats.Output = len(live)
	return live, stats, nil
}

func buildServerHostCountryMap(ctx context.Context, repo *storage.TrafficRepository) map[string]string {
	out := make(map[string]string)
	if repo == nil {
		return out
	}
	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return out
	}
	for _, srv := range servers {
		cc := resolveServerCountryCode(ctx, repo, srv)
		if cc == "" {
			continue
		}
		for _, host := range []string{srv.IPAddress, srv.IPAddressV6, srv.Domain} {
			hKey := strings.ToLower(strings.TrimSpace(host))
			if hKey != "" {
				out[hKey] = cc
			}
		}
	}
	return out
}

func (h *SubscriptionHandler) buildProxyHostCountryMap(ctx context.Context) map[string]string {
	if h == nil {
		return make(map[string]string)
	}
	return buildServerHostCountryMap(ctx, h.repo)
}

func resolveProxyCountryCode(p map[string]any, hostCountryMap map[string]string) string {
	return resolveProxyCountryCodeWithLandingProbe(p, hostCountryMap)
}

func generationCustomOrderRank(customOrder []string) map[string]int {
	if len(customOrder) == 0 {
		return nil
	}
	rank := make(map[string]int, len(customOrder))
	for idx, key := range customOrder {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if _, exists := rank[trimmed]; !exists {
			rank[trimmed] = idx
		}
	}
	return rank
}

func proxyCustomRank(p map[string]any, rank map[string]int, fallback int) int {
	if len(rank) == 0 {
		return fallback
	}
	// Fingerprint ignores temporary internal metadata.
	clean := make(map[string]any, len(p))
	for k, v := range p {
		if k != "name" && k != "_rd_source_index" {
			clean[k] = v
		}
	}
	b, _ := json.Marshal(clean)
	sum := sha256.Sum256(b)
	fp := hex.EncodeToString(sum[:])
	if pos, ok := rank[fp]; ok {
		return pos
	}
	if pos, ok := rank[fmt.Sprint(p["name"])]; ok {
		return pos
	}
	return len(rank) + fallback
}

func sortGenerationNodes(live []map[string]any, cfg storage.SubscriptionProcessing, hostCountryMap map[string]string) {
	desc := cfg.SortDirection == "desc"
	customRank := generationCustomOrderRank(cfg.CustomOrder)
	switch cfg.Sort {
	case "name":
		sort.SliceStable(live, func(i, j int) bool {
			ni := strings.ToLower(fmt.Sprint(live[i]["name"]))
			nj := strings.ToLower(fmt.Sprint(live[j]["name"]))
			if ni == nj {
				ri, rj := fmt.Sprint(live[i]["name"]), fmt.Sprint(live[j]["name"])
				if desc {
					return ri > rj
				}
				return ri < rj
			}
			if desc {
				return ni > nj
			}
			return ni < nj
		})
	case "type":
		typeRank := make(map[string]int, len(cfg.TypeOrder))
		for idx, typ := range cfg.TypeOrder {
			norm := strings.ToLower(strings.TrimSpace(typ))
			if norm == "" {
				continue
			}
			if _, exists := typeRank[norm]; !exists {
				typeRank[norm] = idx
			}
		}
		unknownRank := len(cfg.TypeOrder)
		type item struct {
			proxy  map[string]any
			tRank  int
			typ    string
			cRank  int
		}
		items := make([]item, len(live))
		for i, p := range live {
			typ := strings.ToLower(strings.TrimSpace(fmt.Sprint(p["type"])))
			tr, ok := typeRank[typ]
			if !ok {
				tr = unknownRank
			}
			items[i] = item{proxy: p, tRank: tr, typ: typ, cRank: proxyCustomRank(p, customRank, i)}
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].tRank != items[j].tRank {
				return items[i].tRank < items[j].tRank
			}
			if items[i].typ != items[j].typ {
				return items[i].typ < items[j].typ
			}
			if len(customRank) > 0 && items[i].cRank != items[j].cRank {
				return items[i].cRank < items[j].cRank
			}
			return strings.ToLower(fmt.Sprint(items[i].proxy["name"])) < strings.ToLower(fmt.Sprint(items[j].proxy["name"]))
		})
		for i, it := range items {
			live[i] = it.proxy
		}
		if desc {
			reverseProxySlice(live)
		}
	case "region":
		regionRank := make(map[string]int, len(cfg.RegionOrder))
		for idx, code := range cfg.RegionOrder {
			norm := strings.ToUpper(strings.TrimSpace(code))
			if norm == "" {
				continue
			}
			if _, exists := regionRank[norm]; !exists {
				regionRank[norm] = idx
			}
		}
		unknownRank := len(cfg.RegionOrder)
		type item struct {
			proxy map[string]any
			rRank int
			code  string
			cRank int
		}
		items := make([]item, len(live))
		for i, p := range live {
			cc := resolveProxyCountryCode(p, hostCountryMap)
			rr, ok := regionRank[cc]
			if !ok {
				rr = unknownRank
			}
			items[i] = item{proxy: p, rRank: rr, code: cc, cRank: proxyCustomRank(p, customRank, i)}
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].rRank != items[j].rRank {
				return items[i].rRank < items[j].rRank
			}
			if items[i].code != items[j].code {
				if items[i].code == "UN" {
					return false
				}
				if items[j].code == "UN" {
					return true
				}
				return items[i].code < items[j].code
			}
			if len(customRank) > 0 && items[i].cRank != items[j].cRank {
				return items[i].cRank < items[j].cRank
			}
			return strings.ToLower(fmt.Sprint(items[i].proxy["name"])) < strings.ToLower(fmt.Sprint(items[j].proxy["name"]))
		})
		for i, it := range items {
			live[i] = it.proxy
		}
		if desc {
			reverseProxySlice(live)
		}
	case "custom":
		if len(customRank) > 0 {
			type indexedNode struct {
				proxy map[string]any
				rank  int
			}
			items := make([]indexedNode, len(live))
			for i, p := range live {
				items[i] = indexedNode{proxy: p, rank: proxyCustomRank(p, customRank, i)}
			}
			sort.SliceStable(items, func(i, j int) bool {
				return items[i].rank < items[j].rank
			})
			for i, item := range items {
				live[i] = item.proxy
			}
		}
		if desc {
			reverseProxySlice(live)
		}
	default:
		if len(customRank) > 0 {
			type indexedNode struct {
				proxy     map[string]any
				srcIndex  int
				cRank     int
			}
			items := make([]indexedNode, len(live))
			for i, p := range live {
				srcIdx, _ := p["_rd_source_index"].(int)
				items[i] = indexedNode{proxy: p, srcIndex: srcIdx, cRank: proxyCustomRank(p, customRank, i)}
			}
			sort.SliceStable(items, func(i, j int) bool {
				if items[i].srcIndex != items[j].srcIndex {
					return items[i].srcIndex < items[j].srcIndex
				}
				return items[i].cRank < items[j].cRank
			})
			for i, item := range items {
				live[i] = item.proxy
			}
		}
		if desc {
			reverseProxySlice(live)
		}
	}
}

func reverseProxySlice(items []map[string]any) {
	for l, r := 0, len(items)-1; l < r; l, r = l+1, r-1 {
		items[l], items[r] = items[r], items[l]
	}
}

func generationOutput(g *storage.SubscriptionGeneration, client string) storage.SubscriptionOutput {
	if client == "clash" {
		client = "clashmeta"
	}
	for _, p := range g.Outputs {
		if p.Client == client {
			return p
		}
	}
	if client == "" {
		return g.Outputs[0]
	}
	p := g.Outputs[0]
	p.Client = client
	if client == "v2ray" || client == "uri" || client == "shadowrocket" {
		p.Mode = "nodes"
		p.TemplateFilename = ""
	}
	return p
}

func (h *SubscriptionHandler) generateSubscription(ctx context.Context, f storage.SubscribeFile, client string) ([]byte, generationPreview, error) {
	var stats generationPreview
	if err := h.validateGeneration(ctx, f); err != nil {
		return nil, stats, err
	}
	nodes, original, err := h.generationSources(ctx, f)
	if err != nil {
		return nil, stats, err
	}
	nodes, stats, err = h.processGenerationNodes(ctx, f, nodes)
	if err != nil {
		return nil, stats, err
	}
	out := generationOutput(f.Generation, client)
	stats.Client = out.Client
	var warnings []string
	nodes, warnings = compatibleGenerationNodes(nodes, out)
	stats.Warnings = append(stats.Warnings, warnings...)
	stats.Output = len(nodes)
	if len(nodes) == 0 {
		return nil, stats, errors.New("所选客户端不支持当前来源的节点协议，请切换客户端或来源")
	}
	var data []byte
	switch out.Mode {
	case "source":
		if original == nil {
			return nil, stats, errors.New("所选来源不含可继承的完整配置")
		}
		original["proxies"] = nodes
		// Drop dangling references to filtered nodes without changing the user's rules.
		data, err = yaml.Marshal(original)
		if err == nil {
			data, err = repairGenerationReferences(data, nodes)
		}
	case "nodes":
		data, err = yaml.Marshal(map[string]any{"proxies": nodes})
	default:
		if out.RuleMode == "custom" {
			data, err = renderCustomSubscriptionRules(ctx, h.repo, nodes, out)
			break
		}
		if out.TemplateFilename == builtInSubscriptionTemplate {
			data, err = builtInSubscriptionConfig(nodes)
			break
		}
		template, readErr := os.ReadFile(filepath.Join("rule_templates", out.TemplateFilename))
		if readErr != nil {
			return nil, stats, readErr
		}
		var rendered string
		rendered, err = renderTemplateWithProxyProviders(ctx, h.repo, string(template), nodes, subscriptionGenerationRenderOwner(ctx, h.repo, f.CreatedBy), true)
		data = []byte(rendered)
	}
	if err != nil {
		return nil, stats, err
	}
	stats.Content = string(data)
	return data, stats, nil
}

func repairGenerationReferences(data []byte, nodes []map[string]any) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	valid := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true}
	for _, p := range nodes {
		valid[fmt.Sprint(p["name"])] = true
	}
	groups, _ := doc["proxy-groups"].([]any)
	for _, g := range groups {
		if group, ok := g.(map[string]any); ok {
			valid[fmt.Sprint(group["name"])] = true
		}
	}
	for _, g := range groups {
		group, ok := g.(map[string]any)
		if !ok {
			continue
		}
		refs, ok := group["proxies"].([]any)
		if !ok {
			continue
		}
		kept := []any{}
		for _, ref := range refs {
			if valid[fmt.Sprint(ref)] {
				kept = append(kept, ref)
			}
		}
		if len(kept) == 0 && group["use"] == nil {
			kept = []any{"DIRECT"}
		}
		group["proxies"] = kept
	}
	return yaml.Marshal(doc)
}

func (h *subscribeFilesHandler) handleGeneration(w http.ResponseWriter, r *http.Request, preview bool) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("请先登录"))
		return
	}
	// Global API credentials are an authorization source, not a durable user.
	// Store the recipe under an active administrator so later node resolution
	// and background checks use a real account's permissions and credentials.
	if auth.IsGlobalAPIToken(r.Context()) {
		owner, err := h.repo.FindActiveAdminUsername(r.Context())
		if err != nil || owner == "" {
			writeError(w, http.StatusServiceUnavailable, errors.New("管理员账号不可用"))
			return
		}
		username = owner
	}
	var req generationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}
	admin := userIsAdmin(r.Context(), h.repo, username)
	if !admin {
		ent, err := ResolveUserServiceEntitlements(r.Context(), h.repo, username, time.Now().UTC())
		if err != nil || !ent.Subscription {
			writeError(w, http.StatusForbidden, errors.New("无有效订阅权限"))
			return
		}
	}
	file := storage.SubscribeFile{
		ID:                        req.ID,
		Name:                      strings.TrimSpace(req.Name),
		Description:               strings.TrimSpace(req.Description),
		Filename:                  strings.TrimSpace(req.Filename),
		Type:                      storage.SubscribeTypeCreate,
		CreatedBy:                 username,
		SelectedNodeIDs:           req.SelectedNodeIDs,
		SelectedCustomRuleIDs:     req.SelectedCustomRuleIDs,
		SelectedOverrideScriptIDs: req.SelectedOverrideScriptIDs,
		AutoSyncCustomRules:       len(req.SelectedCustomRuleIDs) > 0,
		Generation:                req.Generation,
	}
	if file.ID > 0 {
		existing, err := h.repo.GetSubscribeFileByID(r.Context(), file.ID)
		if err != nil || (!admin && existing.CreatedBy != username) {
			writeError(w, http.StatusNotFound, storage.ErrSubscribeFileNotFound)
			return
		}
		file = existing
		if req.Generation != nil && req.Generation.Kind != subscriptionKind(existing) {
			writeBadRequest(w, "不能在编辑时变更订阅分类")
			return
		}
		file.Generation = req.Generation
		if req.SelectedNodeIDs != nil {
			file.SelectedNodeIDs = req.SelectedNodeIDs
		}
		if req.SelectedCustomRuleIDs != nil {
			file.SelectedCustomRuleIDs = req.SelectedCustomRuleIDs
			if len(req.SelectedCustomRuleIDs) > 0 {
				file.AutoSyncCustomRules = true
			}
		}
		if req.SelectedOverrideScriptIDs != nil {
			file.SelectedOverrideScriptIDs = req.SelectedOverrideScriptIDs
		}
		if req.Name != "" {
			file.Name = strings.TrimSpace(req.Name)
		}
	}
	if file.Generation != nil && file.Generation.Kind == "external" && file.ID == 0 {
		writeBadRequest(w, "请先导入外部订阅再设置输出")
		return
	}
	if len(req.TrafficLimit) > 0 && string(req.TrafficLimit) != "null" {
		writeBadRequest(w, "订阅不单独设置流量限额，请在用户管理中配置用户的授权额度")
		return
	}
	if err := validateSubscriptionNodeSelectionEdit(r.Context(), h.repo, file); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	generator := NewSubscriptionHandlerConcrete(h.repo, "subscribes")
	data, result, err := generator.generateSubscription(r.Context(), file, "")
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	// Validate every saved target, so a second output cannot silently lose its
	// template or fail later when imported into a different client.
	for i, out := range file.Generation.Outputs {
		targetData, targetResult := data, result
		if i > 0 {
			targetData, targetResult, err = generator.generateSubscription(r.Context(), file, out.Client)
			if err != nil {
				writeError(w, 422, fmt.Errorf("%s: %w", out.Client, err))
				return
			}
		}
		converted, convErr := generator.convertGenerationOutput(r.Context(), targetData, out)
		if convErr != nil {
			writeError(w, 422, fmt.Errorf("%s: %w", out.Client, convErr))
			return
		}
		if (out.Client == "" || out.Client == "clashmeta") && len(file.SelectedCustomRuleIDs) > 0 {
			if applied, _, applyErr := applyCustomRulesToYamlForFile(r.Context(), h.repo, converted, file); applyErr == nil {
				converted = applied
			}
		}
		targetResult.Content = string(converted)
		result.Outputs = append(result.Outputs, targetResult)
		if i == 0 {
			result.Content = targetResult.Content
		}
	}
	if preview {
		respondJSON(w, http.StatusOK, result)
		return
	}
	if file.Name == "" {
		writeBadRequest(w, "请输入订阅名称")
		return
	}
	if file.ID == 0 {
		if file.Filename == "" {
			file.Filename = file.Name
		}
		if filepath.Ext(file.Filename) == "" {
			file.Filename += ".yaml"
		}
		if err := storage.ValidateSubscribeFilename(file.Filename); err != nil {
			writeBadRequest(w, "文件名必须为 .yaml 或 .yml 文件名")
			return
		}
		if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		unlock, err := lockSubscriptionFilenames(file.Filename)
		if err != nil {
			writeError(w, 500, err)
			return
		}
		defer unlock()
		protected, err := protectWireGuardSubscriptionContent(r.Context(), h.repo, file.Filename, string(data), false)
		if err != nil {
			writeError(w, 422, err)
			return
		}
		path := filepath.Join("subscribes", file.Filename)
		ownership, err := writeNewPrivateSubscriptionFile(path, []byte(protected))
		if err != nil {
			writeError(w, http.StatusConflict, errors.New("该文件名已存在，请更换文件名"))
			return
		}
		created, err := h.repo.CreateSubscribeFile(r.Context(), file)
		if err != nil {
			_ = removeSubscriptionFileIfOwned(path, ownership)
			writeError(w, http.StatusConflict, err)
			return
		}
		respondJSON(w, http.StatusCreated, map[string]any{"file": convertSubscribeFile(created), "preview": result})
		return
	}
	// Editing an external source never overwrites its original imported content.
	updated, err := h.repo.UpdateSubscribeFile(r.Context(), file)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"file": convertSubscribeFile(updated), "preview": result})
}

// Background checks run from the panel's network, through the real proxy
// protocol. Missing cores/configuration stay unknown, not falsely "dead".
func StartSubscriptionHealthUpdater(ctx context.Context, repo *storage.TrafficRepository) {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			runSubscriptionHealthChecks(ctx, repo)
			timer.Reset(5 * time.Minute)
		}
	}
}
func runSubscriptionHealthChecks(ctx context.Context, repo *storage.TrafficRepository) {
	if !speedtest.GetMihomoCoreStatus(ctx).Ready {
		return
	}
	files, err := repo.ListSubscribeFiles(ctx)
	if err != nil {
		return
	}
	generator := NewSubscriptionHandlerConcrete(repo, "subscribes")
	seen := map[string]bool{}
	targets := []speedtest.ProtocolLatencyTarget{}
	owners := []string{}
	keys := []string{}
	for _, f := range files {
		if f.Generation == nil || !f.Generation.Processing.RemoveDead {
			continue
		}
		nodes, _, err := generator.generationSources(ctx, f)
		if err != nil {
			continue
		}
		for _, p := range nodes {
			key := generationFingerprint(p)
			scoped := f.CreatedBy + ":" + key
			if seen[scoped] {
				continue
			}
			seen[scoped] = true
			// Chained nodes need a full resolved dialer chain; leave them unknown here.
			if p["dialer-proxy"] != nil {
				continue
			}
			raw, err := json.Marshal(p)
			if err != nil {
				continue
			}
			if err := validatePublicMihomoProbeOverrides(string(raw)); err != nil {
				continue
			}
			host, _ := p["server"].(string)
			probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			ip, err := resolvePublicProbeHost(probeCtx, host)
			cancel()
			if err != nil {
				continue
			}
			targets = append(targets, speedtest.ProtocolLatencyTarget{ClashConfig: string(raw), Hosts: map[string]string{host: ip}, Timeout: 5 * time.Second})
			owners = append(owners, f.CreatedBy)
			keys = append(keys, key)
			if len(targets) >= 100 {
				break
			}
		}
		if len(targets) >= 100 {
			break
		}
	}
	if len(targets) == 0 {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	results := (localMihomoLatencyProber{}).Probe(checkCtx, targets)
	for i, result := range results {
		if i >= len(keys) {
			break
		}
		if result.Err != nil && (strings.Contains(result.Err.Error(), "核心") || strings.Contains(result.Err.Error(), "start") || strings.Contains(result.Err.Error(), "unsupported")) {
			continue
		}
		_ = repo.RecordSubscriptionNodeHealth(ctx, owners[i], keys[i], result.Err == nil, result.Latency)
	}
}

// Normalize external URI/Base64 inputs into the same canonical node document.
func normalizeImportedSubscription(raw []byte) ([]byte, error) {
	var doc map[string]any
	if yaml.Unmarshal(raw, &doc) == nil && doc != nil {
		if _, ok := doc["proxies"]; ok {
			return raw, nil
		}
		if _, ok := doc["proxy-providers"]; ok {
			return raw, nil
		}
	}
	nodes, err := proxyparser.ParseSubscription(string(raw))
	if err != nil || len(nodes) == 0 {
		return nil, errors.New("无法识别订阅内容，请使用 Clash YAML、JSON 或 URI / Base64 节点订阅")
	}
	return yaml.Marshal(map[string]any{"proxies": nodes})
}

// A separate route export makes the URI subscription limitation explicit.
func (h *subscribeFilesHandler) handleGenerationRouteExport(w http.ResponseWriter, r *http.Request, idStr string) {
	owner := auth.UsernameFromContext(r.Context())
	if owner == "" {
		writeError(w, http.StatusUnauthorized, errors.New("请先登录"))
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeBadRequest(w, "无效订阅 ID")
		return
	}
	f, err := h.repo.GetSubscribeFileByID(r.Context(), id)
	if err != nil || (!userIsAdmin(r.Context(), h.repo, owner) && f.CreatedBy != owner) {
		writeError(w, 404, storage.ErrSubscribeFileNotFound)
		return
	}
	var doc map[string]any
	generator := NewSubscriptionHandlerConcrete(h.repo, "subscribes")
	if f.Generation == nil {
		writeBadRequest(w, "请先配置分流模板")
		return
	}
	var chosen *storage.SubscriptionOutput
	for _, out := range f.Generation.Outputs {
		if (out.Client == "v2ray" || out.Client == "uri") && (out.RuleMode == "custom" || out.TemplateFilename != "") {
			candidate := out
			chosen = &candidate
			break
		}
	}
	if chosen == nil {
		for _, out := range f.Generation.Outputs {
			if out.Mode == "full" {
				candidate := out
				chosen = &candidate
				break
			}
		}
	}
	if chosen == nil {
		writeBadRequest(w, "请先配置自定义规则或规则模板")
		return
	}
	clone := *f.Generation
	chosen.Client, chosen.Mode = "clashmeta", "full"
	clone.Outputs = []storage.SubscriptionOutput{*chosen}
	f.Generation = &clone
	data, _, err := generator.generateSubscription(r.Context(), f, "")
	if err != nil {
		writeError(w, 422, err)
		return
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		writeError(w, 422, err)
		return
	}
	native, err := generationXrayRouting(doc)
	if err != nil {
		writeError(w, 422, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="routing.json"`)
	respondJSON(w, 200, native)
}
