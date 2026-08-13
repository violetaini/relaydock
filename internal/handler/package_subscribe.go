package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/proxyparser/substore"
	"github.com/violetaini/relaydock/internal/storage"

	"gopkg.in/yaml.v3"
)

type PackageSubscribeHandler struct {
	repo *storage.TrafficRepository
}

func NewPackageSubscribeHandler(repo *storage.TrafficRepository) http.Handler {
	return &PackageSubscribeHandler{repo: repo}
}

func (h *PackageSubscribeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only GET is supported"))
		return
	}

	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	user, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if user.PackageID == 0 && user.Role == storage.RoleAdmin {
		h.serveAllNodes(w, r, user)
		return
	}

	managedNodeIDs, err := effectiveManagedNodeIDs(r.Context(), h.repo, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	directNodeIDs, err := h.repo.ListEffectiveDirectNodeIDs(r.Context(), username, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var pkg *storage.Package
	packageActive := packageAssignmentActive(user, time.Now())
	if packageActive {
		if overLimit, limitErr := h.repo.IsUserOverLimit(r.Context(), username); limitErr != nil {
			writeError(w, http.StatusInternalServerError, limitErr)
			return
		} else if overLimit {
			packageActive = false
		}
	}
	if packageActive {
		pkg, err = h.repo.GetPackage(r.Context(), user.PackageID)
		if err != nil {
			if !errors.Is(err, storage.ErrPackageNotFound) {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			pkg = nil
		}
	}
	if pkg == nil && len(managedNodeIDs) == 0 && len(directNodeIDs) == 0 {
		writeError(w, http.StatusNotFound, errors.New("无有效套餐或授权节点"))
		return
	}
	renderPackage := pkg
	if renderPackage == nil {
		renderPackage = &storage.Package{Name: "authorized-nodes"}
	}

	// Build user credential lookup for per-user proxy configs
	credMap := h.buildUserCredentialMap(r, username)

	// 节点名称倍率前缀:开关开启时,套餐内倍率 != 1 的节点 name 加上 "{Left}{mult}{Right}" 前缀
	// renameMap 收集所有重命名,后面要同步 proxy-groups 里"按全名引用"的列表,避免组找不到节点
	sysCfg, _ := h.repo.GetSystemConfig(r.Context())
	renameMap := make(map[string]string)
	recordRename := func(oldName, newName string, did bool) {
		if did && oldName != "" && newName != "" && oldName != newName {
			renameMap[oldName] = newName
		}
	}

	// 按用户 node_order 重排 pkg.Nodes。
	// 用户拖过节点顺序 → settings.NodeOrder 非空 → 按其位置排;
	// 没拖过 → fallback 用 admin 的顺序(过滤掉用户没绑的节点) — 跟 /api/user/config GET 一致。
	// nodeOrder 中没有的节点(套餐里新加的)排到最末,保持 pkg.Nodes 原顺序。
	orderedNodeIDs := make([]int64, 0, len(managedNodeIDs))
	seenNodeIDs := make(map[int64]bool)
	if pkg != nil {
		for _, nodeID := range orderPackageNodes(r.Context(), h.repo, username, pkg.Nodes) {
			if !seenNodeIDs[nodeID] {
				orderedNodeIDs = append(orderedNodeIDs, nodeID)
				seenNodeIDs[nodeID] = true
			}
		}
	}
	for _, nodeID := range managedNodeIDs {
		if !seenNodeIDs[nodeID] {
			orderedNodeIDs = append(orderedNodeIDs, nodeID)
			seenNodeIDs[nodeID] = true
		}
	}
	for _, nodeID := range directNodeIDs {
		if !seenNodeIDs[nodeID] {
			orderedNodeIDs = append(orderedNodeIDs, nodeID)
			seenNodeIDs[nodeID] = true
		}
	}

	// Load nodes from package
	var proxies []map[string]any
	for _, nodeID := range orderedNodeIDs {
		node, err := h.repo.GetNodeByID(r.Context(), nodeID)
		if err != nil || !node.Enabled {
			continue
		}
		// routed 节点:克隆父 inbound 的 clash 模板,替换 uuid 为该用户子账号 uuid + 节点名
		if node.NodeType == "routed" {
			if proxyConfig, ok := buildRoutedProxyForUser(r.Context(), h.repo, node, username); ok {
				recordRename(applyMultiplierPrefix(proxyConfig, node, renderPackage, &sysCfg))
				proxies = append(proxies, proxyConfig)
			}
			continue
		}
		if node.ClashConfig == "" {
			continue
		}
		var proxyConfig map[string]any
		if err := json.Unmarshal([]byte(node.ClashConfig), &proxyConfig); err != nil {
			continue
		}
		delete(proxyConfig, storage.ManagedShadowsocksMultiUserMarker)
		if !applyUserCredentials(proxyConfig, node, credMap) {
			continue
		}
		recordRename(applyMultiplierPrefix(proxyConfig, node, renderPackage, &sysCfg))
		proxies = append(proxies, proxyConfig)
	}

	// 追加用户私有路由出站(routed_owner='user' && username=<creator>):不依赖套餐分配,
	// 创建者一人独享。其 routed 子账号 email 已通过 user_subaccounts 维护,buildRoutedProxyForUser
	// 复用同一套替换 uuid 逻辑。
	if userRouted, err := h.repo.ListUserRoutedOutbounds(r.Context(), username); err == nil {
		for _, n := range userRouted {
			if !n.Enabled {
				continue
			}
			if proxyConfig, ok := buildRoutedProxyForUser(r.Context(), h.repo, n.Node, username); ok {
				recordRename(applyMultiplierPrefix(proxyConfig, n.Node, renderPackage, &sysCfg))
				proxies = append(proxies, proxyConfig)
			}
		}
	}

	if len(proxies) == 0 {
		writeError(w, http.StatusNotFound, errors.New("无可用节点"))
		return
	}

	// Load template: 套餐模板 > 系统默认 > 目录第一个
	templateContent, err := h.loadTemplate(r, pkg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Process template with nodes and the requesting user's Provider namespace.
	result, err := renderTemplateWithProxyProviders(
		r.Context(),
		h.repo,
		templateContent,
		proxies,
		username,
		proxyProviderRequiresServerMaterialization(r.URL.Query().Get("t")),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 节点名重命名了 → 同步 proxy-groups 里手写的全名引用(模板若用 filter 自动会用新名,这里兜底全名引用场景)
	if len(renameMap) > 0 {
		if rewritten, rerr := rewriteProxyGroupRefs([]byte(result), renameMap); rerr == nil {
			result = string(rewritten)
		}
	}

	// 通知 admin "用户拉了套餐订阅" + 静默期记录访问 IP — 跟 SubscriptionHandler L286 同款。
	// 之前套餐订阅这条路径完全没有这两个调用,所以 admin tg 从来收不到「用户拉套餐订阅」通知。
	// 放在这里:此前所有可能失败的步骤(查套餐 / 拼节点 / 加模板 / 渲染)都已成功,
	// 仅剩格式转换 + 写响应。语义清晰:订阅会真正发出去时才通知,提前 writeError 不会触发。
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = "unknown"
	}
	SendSubscribeFetchNotification(r.Context(), username, ua, GetClientIP(r))
	if silentMgr := GetSilentModeManager(); silentMgr != nil {
		silentMgr.RecordSubscriptionAccessWithIP(username, GetClientIP(r))
	}

	// Format conversion
	clientType := strings.TrimSpace(r.URL.Query().Get("t"))
	if clientType == "" || clientType == "clash" || clientType == "clashmeta" {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		// 显式带 t=clash/clashmeta 通常是浏览器/调试预览,不想被强制下载;只有完全不带 t(典型 Clash 客户端拉取)才下发 attachment
		if clientType == "" {
			w.Header().Set("Content-Disposition", "attachment; filename=\""+renderPackage.Name+".yaml\"")
		}
		if pkg != nil {
			h.writeTrafficHeader(r.Context(), w, user, pkg)
		}
		w.Write([]byte(result))
		return
	}

	converted, err := h.convertFormat(r, []byte(result), clientType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if pkg != nil {
		h.writeTrafficHeader(r.Context(), w, user, pkg)
	}
	w.Write(converted)
}

// orderPackageNodes 按用户 node_order 重排套餐节点 ID 列表。
//   - settings.NodeOrder 非空 → 按其位置排;不在 NodeOrder 里的(新加节点)排到末尾
//   - settings.NodeOrder 空 → fallback admin 顺序(跟 /api/user/config GET 一致)
//   - 仍空 → 直接返回 pkg.Nodes 原顺序
//
// 套餐里有但 NodeOrder 里没有的节点(管理员后加的)按 pkg.Nodes 原顺序追加在末尾。
func orderPackageNodes(ctx context.Context, repo *storage.TrafficRepository, username string, pkgNodes []int64) []int64 {
	if len(pkgNodes) == 0 {
		return pkgNodes
	}
	var nodeOrder []int64
	if settings, err := repo.GetUserSettings(ctx, username); err == nil {
		nodeOrder = settings.NodeOrder
	}
	if len(nodeOrder) == 0 {
		nodeOrder = computeFallbackNodeOrder(ctx, repo, username)
	}
	if len(nodeOrder) == 0 {
		return pkgNodes
	}

	pkgSet := make(map[int64]bool, len(pkgNodes))
	for _, id := range pkgNodes {
		pkgSet[id] = true
	}
	orderPos := make(map[int64]int, len(nodeOrder))
	for i, id := range nodeOrder {
		orderPos[id] = i
	}

	ordered := make([]int64, 0, len(pkgNodes))
	var trailing []int64
	for _, id := range pkgNodes {
		if _, ok := orderPos[id]; !ok {
			trailing = append(trailing, id)
		}
	}
	// 在 nodeOrder 里的节点按位置排
	for _, id := range nodeOrder {
		if pkgSet[id] {
			ordered = append(ordered, id)
		}
	}
	// 不在 nodeOrder 里的(套餐新加,用户还没拖过)按 pkg.Nodes 原顺序追加
	ordered = append(ordered, trailing...)
	return ordered
}

// loadTemplate 优先级:套餐绑的模板 → 系统默认模板 → rule_templates 目录第一个 yaml。
// pkg 为 nil 时跳过套餐模板这一级(serveAllNodes 等无套餐上下文场景)。
func (h *PackageSubscribeHandler) loadTemplate(r *http.Request, pkg *storage.Package) (string, error) {
	templatesDir := "rule_templates"

	var candidates []string
	if pkg != nil && strings.TrimSpace(pkg.TemplateFilename) != "" {
		candidates = append(candidates, pkg.TemplateFilename)
	}
	if cfg, err := h.repo.GetSystemConfig(r.Context()); err == nil && cfg.DefaultTemplateFilename != "" {
		candidates = append(candidates, cfg.DefaultTemplateFilename)
	}
	for _, name := range candidates {
		content, err := os.ReadFile(filepath.Join(templatesDir, name))
		if err == nil {
			return string(content), nil
		}
	}

	entries, err := os.ReadDir(templatesDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			content, err := os.ReadFile(filepath.Join(templatesDir, e.Name()))
			if err == nil {
				return string(content), nil
			}
		}
	}
	return "", errors.New("未找到可用模板，请管理员配置模板")
}

func (h *PackageSubscribeHandler) serveAllNodes(w http.ResponseWriter, r *http.Request, user storage.User) {
	allNodes, err := h.repo.ListAllNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var proxies []map[string]any
	for _, node := range allNodes {
		if !node.Enabled || node.ClashConfig == "" {
			continue
		}
		var proxyConfig map[string]any
		if err := json.Unmarshal([]byte(node.ClashConfig), &proxyConfig); err != nil {
			continue
		}
		delete(proxyConfig, storage.ManagedShadowsocksMultiUserMarker)
		proxies = append(proxies, proxyConfig)
	}
	if len(proxies) == 0 {
		writeError(w, http.StatusNotFound, errors.New("无可用节点"))
		return
	}
	// serveAllNodes 是"无套餐上下文,导出全部节点"的旁路调试入口 — 传 nil 走系统默认模板。
	templateContent, err := h.loadTemplate(r, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	result, err := renderTemplateWithProxyProviders(
		r.Context(),
		h.repo,
		templateContent,
		proxies,
		user.Username,
		proxyProviderRequiresServerMaterialization(r.URL.Query().Get("t")),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	clientType := strings.TrimSpace(r.URL.Query().Get("t"))
	if clientType == "" || clientType == "clash" || clientType == "clashmeta" {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		if clientType == "" {
			w.Header().Set("Content-Disposition", `attachment; filename="all-nodes.yaml"`)
		}
		w.Write([]byte(result))
		return
	}
	converted, err := h.convertFormat(r, []byte(result), clientType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(converted)
}

func (h *PackageSubscribeHandler) writeTrafficHeader(ctx context.Context, w http.ResponseWriter, user storage.User, pkg *storage.Package) {
	limitBytes := resolveTrafficLimitBytes(&user, pkg)
	if limitBytes <= 0 {
		return
	}
	// 已用流量在采集时按当时的套餐模式和节点倍率固化，确保客户端
	// 显示与限额判定一致，且套餐变更不会重算历史流量。
	// 之前这里硬编码 download=0,导致客户端永远显示已用 0。
	used, _ := h.repo.GetUserBillableTraffic(ctx, user.Username)
	info := fmt.Sprintf("upload=0; download=%d; total=%d", used, limitBytes)
	if user.PackageEndDate != nil {
		info += fmt.Sprintf("; expire=%d", user.PackageEndDate.Unix())
	}
	w.Header().Set("subscription-userinfo", info)
}

func (h *PackageSubscribeHandler) convertFormat(r *http.Request, yamlData []byte, clientType string) ([]byte, error) {
	var rootNode yaml.Node
	if err := yaml.Unmarshal(yamlData, &rootNode); err != nil {
		return nil, err
	}

	config, err := yamlNodeToMap(&rootNode)
	if err != nil {
		return nil, err
	}

	proxiesRaw, ok := config["proxies"]
	if !ok {
		return nil, errors.New("no proxies in config")
	}

	proxiesArray, ok := proxiesRaw.([]interface{})
	if !ok {
		return nil, errors.New("proxies is not an array")
	}

	var proxies []substore.Proxy
	for _, p := range proxiesArray {
		proxyMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		proxies = append(proxies, substore.Proxy(proxyMap))
	}

	if clientType == "clash-to-surge" {
		sub := NewSubscriptionHandlerConcrete(h.repo, "subscribes")
		return sub.convertClashToSurge(config, proxies)
	}

	// shadowrocket / clash-to-shadowrocket 显式取对应 producer(工厂里两者都注册成 "shadowrocket");其余走工厂。
	producer := shadowrocketProducerFor(clientType)
	if producer == nil {
		producer, err = substore.GetDefaultFactory().GetProducer(clientType)
		if err != nil {
			return nil, err
		}
	}

	systemConfig, _ := h.repo.GetSystemConfig(r.Context())
	opts := &substore.ProduceOptions{
		FullConfig:              config,
		ClientCompatibilityMode: systemConfig.ClientCompatibilityMode,
	}

	result, err := producer.Produce(proxies, clientType, opts)
	if err != nil {
		return nil, err
	}

	switch v := result.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("unexpected produce result type: %T", result)
	}
}

type credKey struct {
	serverName string
	inboundTag string
}

func (h *PackageSubscribeHandler) buildUserCredentialMap(r *http.Request, username string) map[credKey]string {
	ctx := r.Context()
	userConfigs, err := h.repo.GetUserInboundConfigs(ctx, username)
	if err != nil || len(userConfigs) == 0 {
		return nil
	}
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil
	}
	idToName := make(map[int64]string, len(servers))
	for _, s := range servers {
		idToName[s.ID] = s.Name
	}
	m := make(map[credKey]string, len(userConfigs))
	for _, cfg := range userConfigs {
		if name, ok := idToName[cfg.ServerID]; ok {
			m[credKey{name, cfg.InboundTag}] = cfg.CredentialJSON
		}
	}
	return m
}

// rewriteProxyGroupRefs 给定 YAML 文档 + 节点名映射,把每个 proxy-group 的 proxies 数组里
// 命中的旧名替换为新名。模板若用 filter/regex 选节点会自动用 proxies 数组里的新名,
// 这里专门兜底"模板里手写全名引用"的场景,避免代理组指向不存在的节点。
// 解析失败 / proxy-groups 缺失 → 原样返回。
func rewriteProxyGroupRefs(data []byte, rename map[string]string) ([]byte, error) {
	if len(rename) == 0 || len(data) == 0 {
		return data, nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return data, err
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return data, nil
	}
	doc := root.Content[0]
	modified := false
	for i := 0; i < len(doc.Content)-1; i += 2 {
		if doc.Content[i].Value != "proxy-groups" {
			continue
		}
		groups := doc.Content[i+1]
		if groups.Kind != yaml.SequenceNode {
			break
		}
		for _, g := range groups.Content {
			if g.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j < len(g.Content)-1; j += 2 {
				if g.Content[j].Value != "proxies" {
					continue
				}
				pxs := g.Content[j+1]
				if pxs.Kind != yaml.SequenceNode {
					continue
				}
				for _, pn := range pxs.Content {
					if pn.Kind != yaml.ScalarNode {
						continue
					}
					if newName, ok := rename[pn.Value]; ok {
						pn.Value = newName
						modified = true
					}
				}
			}
		}
		break
	}
	if !modified {
		return data, nil
	}
	out, err := MarshalYAMLWithIndent(&root)
	if err != nil {
		return data, err
	}
	return []byte(RemoveUnicodeEscapeQuotes(string(out))), nil
}

// applyMultiplierPrefix 按系统开关给节点名加倍率前缀,效果 "「2」原节点名"。
//   - 开关关 / 套餐空 / 节点倍率 == 1 → 不动 name,返回 ("","",false)
//   - routed 子节点通过 ParentNodeID 自动回退到父物理节点的套餐倍率
//   - 前缀左右分隔符由 SystemConfig.NodeNameMultiplierLeft / Right 决定,默认 「」
//   - 返回 (oldName, newName, true) 给调用方收集 renameMap,后续要同步 proxy-groups 引用
func applyMultiplierPrefix(proxy map[string]any, node storage.Node, pkg *storage.Package, cfg *storage.SystemConfig) (string, string, bool) {
	if proxy == nil || cfg == nil || pkg == nil || !cfg.NodeNameMultiplierPrefixEnabled {
		return "", "", false
	}
	mult := pkg.MultiplierForNode(node.ID)
	if mult == 1.0 {
		return "", "", false
	}
	name, _ := proxy["name"].(string)
	if name == "" {
		name = node.NodeName
	}
	left := cfg.NodeNameMultiplierLeft
	if left == "" {
		left = "「"
	}
	right := cfg.NodeNameMultiplierRight
	if right == "" {
		right = "」"
	}
	// 整数倍率不带小数(2 → "2" 而非 "2.0")
	var multStr string
	if mult == float64(int64(mult)) {
		multStr = strconv.FormatInt(int64(mult), 10)
	} else {
		multStr = strconv.FormatFloat(mult, 'f', -1, 64)
	}
	newName := left + multStr + right + name
	proxy["name"] = newName
	return name, newName, true
}

func applyUserCredentials(proxy map[string]any, node storage.Node, credMap map[credKey]string) bool {
	defer delete(proxy, storage.ManagedShadowsocksMultiUserMarker)
	managed := strings.TrimSpace(node.OriginalServer) != "" || strings.TrimSpace(node.InboundTag) != ""
	if !managed {
		return true
	}
	// A panel-created WireGuard inbound has one static client peer. Its private
	// key is encrypted at rest and hydrated only when the node is read, so it can
	// be published unchanged without a user_inbound_configs credential record.
	// This intentionally means users assigned the same node share that peer.
	if strings.EqualFold(strings.TrimSpace(node.Protocol), "wireguard") {
		if proxy == nil || strings.TrimSpace(node.OriginalServer) == "" || strings.TrimSpace(node.InboundTag) == "" {
			return false
		}
		privateKey, _ := proxy["private-key"].(string)
		publicKey, _ := proxy["public-key"].(string)
		return strings.TrimSpace(privateKey) != "" && strings.TrimSpace(publicKey) != ""
	}
	// A half-associated node is not safe to publish: without both coordinates
	// there is no unambiguous per-user credential lookup.
	if proxy == nil || strings.TrimSpace(node.OriginalServer) == "" || strings.TrimSpace(node.InboundTag) == "" || credMap == nil {
		return false
	}
	credJSON, ok := credMap[credKey{node.OriginalServer, node.InboundTag}]
	if !ok {
		return false
	}
	var cred map[string]any
	if err := json.Unmarshal([]byte(credJSON), &cred); err != nil {
		return false
	}
	return applyCredToProxy(proxy, node.Protocol, cred)
}

// applyCredToProxy 按协议把用户凭据(cred = credential_json 解析结果)写进 clash proxy 的对应字段。
// 物理节点(applyUserCredentials)和 routed 节点(buildRoutedProxyForUser)共用,避免协议分支两处维护
// 不一致(历史 bug:routed 只覆盖了 uuid,导致 SS/Trojan/HY2 保留创建者凭据)。
func applyCredToProxy(proxy map[string]any, protocol string, cred map[string]any) bool {
	if proxy == nil || cred == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vless":
		if id, ok := cred["id"].(string); ok && id != "" {
			proxy["uuid"] = id
			syncVLESSFlow(proxy, cred)
			return true
		}
	case "vmess":
		if id, ok := cred["id"].(string); ok && id != "" {
			proxy["uuid"] = id
			return true
		}
	case "ss", "shadowsocks":
		delete(proxy, storage.ManagedShadowsocksMultiUserMarker)
		if userPass, ok := cred["password"].(string); ok && userPass != "" {
			cipher, _ := proxy["cipher"].(string)
			cipher = strings.ToLower(strings.TrimSpace(cipher))
			if strings.HasPrefix(cipher, "2022-") {
				if nodePass, ok := proxy["password"].(string); ok && nodePass != "" {
					// 兜底:存量 clash_config 可能还是老格式 "master:firstClient" — 剥掉冒号后段,
					// 只保留 master,再拼当前用户密码,得到正确的两段。新节点直接 nodePass 就是 master 一段。
					if idx := strings.Index(nodePass, ":"); idx >= 0 {
						nodePass = nodePass[:idx]
					}
					if nodePass != "" {
						proxy["password"] = nodePass + ":" + userPass
						return true
					}
				}
			} else if cipher == "aes-128-gcm" || cipher == "aes-256-gcm" {
				method, _ := cred["method"].(string)
				if !strings.EqualFold(strings.TrimSpace(method), cipher) {
					return false
				}
				proxy["password"] = userPass
				return true
			}
		}
	case "trojan", "anytls":
		if password, ok := cred["password"].(string); ok && password != "" {
			proxy["password"] = password
			return true
		}
	case "snell":
		// Snell v4/v5:每用户 psk → clash snell 节点的 psk 字段(逐用户独立密钥)。
		if psk, ok := cred["psk"].(string); ok && psk != "" {
			proxy["psk"] = psk
			return true
		}
	case "hysteria2", "hysteria", "hy2":
		// HY2 客户端凭据 auth → clash hysteria2 节点的 password 字段。
		if auth, ok := cred["auth"].(string); ok && auth != "" {
			proxy["password"] = auth
			return true
		}
	case "socks", "http":
		user, userOK := cred["user"].(string)
		pass, passOK := cred["pass"].(string)
		if userOK && passOK && user != "" && pass != "" {
			proxy["username"] = user
			proxy["password"] = pass
			return true
		}
	}
	return false
}

func syncVLESSFlow(proxy map[string]any, cred map[string]any) {
	flow, _ := cred["flow"].(string)
	if flow = strings.TrimSpace(flow); flow != "" {
		proxy["flow"] = flow
		return
	}
	delete(proxy, "flow")
}

// buildRoutedProxyForUser 为某用户 + 某 routed 节点生成订阅条目:
//   - 取父物理节点的 ClashConfig 作为协议/streamSettings 模板
//   - 用 user_subaccounts.credential_json 里的 uuid 覆盖
//   - 节点名换成 routed 节点的 NodeName
//
// 返回 (proxy_map, true) 或 (nil, false)(用户未绑定子账号 / 未 active / 父节点不可用 → 跳过)。
func buildRoutedProxyForUser(ctx context.Context, repo *storage.TrafficRepository, routedNode storage.Node, username string) (map[string]any, bool) {
	// 子账号必须 is_active=1,否则该用户当前没有访问权(下线 / 未绑套餐 / 暂停)
	sa, err := repo.GetUserSubaccount(ctx, routedNode.ID, username)
	if err != nil || sa == nil || !sa.IsActive {
		return nil, false
	}

	// clash_config 来源优先级:
	//   1. 父节点的 clash_config(绑定到普通 inbound 物理节点的标准 routed)
	//   2. routed 节点自身的 clash_config(纯出站 server 场景:server 上没默认 inbound,
	//      同步入站时识别不出 parent,但 routed 节点入库时已克隆了完整可连配置)
	var clashJSON string
	if routedNode.ParentNodeID != nil && *routedNode.ParentNodeID > 0 {
		if parent, perr := repo.GetNodeByID(ctx, *routedNode.ParentNodeID); perr == nil && parent.Enabled && parent.ClashConfig != "" {
			clashJSON = parent.ClashConfig
		}
	}
	if clashJSON == "" && strings.TrimSpace(routedNode.ClashConfig) != "" {
		clashJSON = routedNode.ClashConfig
	}
	if clashJSON == "" {
		return nil, false
	}

	var proxy map[string]any
	if err := json.Unmarshal([]byte(clashJSON), &proxy); err != nil {
		return nil, false
	}
	// 按协议覆盖当前用户在该 routed 节点上的凭据(vless/vmess→uuid;ss→master:userPass;trojan→password;
	// hy2→auth)。此前只覆盖了 uuid,导致 SS/Trojan/HY2 保留了模板里创建者的凭据 → 用户串到创建者身份、
	// 匹配不到 routed 路由规则而走错出口。改用与物理节点一致的 applyCredToProxy。
	var cred map[string]any
	if err := json.Unmarshal([]byte(sa.CredentialJSON), &cred); err != nil {
		return nil, false
	}
	if canonicalManagedProtocol(routedNode.Protocol) == "shadowsocks" {
		cipher, _ := proxy["cipher"].(string)
		if isClassicManagedShadowsocksCipher(cipher) {
			if !reconcileRoutedClassicCredentialFromSnapshot(ctx, repo, routedNode, sa, cred, cipher) {
				return nil, false
			}
		}
	}
	if !applyCredToProxy(proxy, routedNode.Protocol, cred) {
		return nil, false
	}
	proxy["name"] = routedNode.NodeName
	return proxy, true
}

// reconcileRoutedClassicCredentialFromSnapshot validates and, when necessary,
// upgrades routed classic-SS credentials against the latest persisted Agent
// snapshot. The database row is not authoritative for a live password or
// cipher: even rows that already contain method must match the live client,
// otherwise subscription generation fails closed instead of exporting a
// relabeled credential.
func reconcileRoutedClassicCredentialFromSnapshot(ctx context.Context, repo *storage.TrafficRepository, node storage.Node, sa *storage.UserSubaccount, credential map[string]any, cipher string) bool {
	if repo == nil || sa == nil || credential == nil {
		return false
	}
	wantCipher := strings.ToLower(strings.TrimSpace(cipher))
	server, err := repo.GetRemoteServerByName(ctx, node.OriginalServer)
	if err != nil || server == nil {
		return false
	}
	snapshot, err := repo.GetCurrentXraySnapshot(ctx, server.ID)
	if err != nil || snapshot == nil {
		return false
	}
	inbounds, err := xrayConfigInbounds(snapshot.ConfigJSON)
	if err != nil {
		return false
	}
	inbound := inbounds[strings.TrimSpace(node.InboundTag)]
	settings, _ := inbound["settings"].(map[string]interface{})
	clients, _ := settings["clients"].([]interface{})
	for _, raw := range clients {
		client, _ := raw.(map[string]interface{})
		if client == nil || strings.TrimSpace(fmt.Sprint(client["email"])) != strings.TrimSpace(sa.Email) {
			continue
		}
		liveMethod := strings.ToLower(strings.TrimSpace(fmt.Sprint(client["method"])))
		livePassword := strings.TrimSpace(fmt.Sprint(client["password"]))
		if liveMethod != wantCipher || livePassword == "" || livePassword == "<nil>" {
			continue
		}
		oldMethod, methodPresent := credential["method"]
		if methodPresent {
			method, ok := oldMethod.(string)
			if !ok || strings.ToLower(strings.TrimSpace(method)) != wantCipher {
				return false
			}
		}
		oldPassword := strings.TrimSpace(fmt.Sprint(credential["password"]))
		oldEmail, _ := credential["email"].(string)
		oldEmail = strings.TrimSpace(oldEmail)
		if oldPassword == "<nil>" {
			oldPassword = ""
		}
		if (oldPassword != "" && oldPassword != livePassword) ||
			(oldEmail != "" && oldEmail != strings.TrimSpace(sa.Email)) {
			return false
		}
		original, _ := json.Marshal(credential)
		credential["password"] = livePassword
		credential["method"] = wantCipher
		credential["email"] = sa.Email
		encoded, err := json.Marshal(credential)
		if err != nil {
			return false
		}
		if string(original) != string(encoded) {
			if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
				ID: sa.ID, Username: sa.Username, RoutedNodeID: sa.RoutedNodeID,
				Email: sa.Email, CredentialJSON: string(encoded), IsActive: sa.IsActive,
			}); err != nil {
				return false
			}
		}
		return true
	}
	return false
}
