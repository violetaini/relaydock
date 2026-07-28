package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"miaomiaowux/internal/logger"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"

	"github.com/MMWOrg/mmwX-plugins/proxyparser"
	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
	"gopkg.in/yaml.v3"
)

// ConvertNilToEmptyStringInMap 递归地将 nil 值转换为映射中的空字符串
func convertNilToEmptyStringInMap(m map[string]any) {
	for k, v := range m {
		if v == nil {
			m[k] = ""
		} else if subMap, ok := v.(map[string]any); ok {
			convertNilToEmptyStringInMap(subMap)
		} else if slice, ok := v.([]any); ok {
			for i, item := range slice {
				if item == nil {
					slice[i] = ""
				} else if itemMap, ok := item.(map[string]any); ok {
					convertNilToEmptyStringInMap(itemMap)
				}
			}
		}
	}
}

// 安全地进行 URL 解码，解码失败时返回原字符串
func safeURLDecode(s string) string {
	if s == "" {
		return s
	}
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

// decodeProxyURLFields 对代理节点中可能包含 URL 编码的字段进行解码
// 主要处理 path、host 等字段，支持 ws-opts、h2-opts、grpc-opts 等传输层配置
func decodeProxyURLFields(proxy map[string]any) {
	// 处理 ws-opts
	if wsOpts, ok := proxy["ws-opts"].(map[string]any); ok {
		if path, ok := wsOpts["path"].(string); ok {
			wsOpts["path"] = safeURLDecode(path)
		}
		if headers, ok := wsOpts["headers"].(map[string]any); ok {
			if host, ok := headers["Host"].(string); ok {
				headers["Host"] = safeURLDecode(host)
			}
		}
	}

	// 处理 h2-opts
	if h2Opts, ok := proxy["h2-opts"].(map[string]any); ok {
		if path, ok := h2Opts["path"].(string); ok {
			h2Opts["path"] = safeURLDecode(path)
		}
		if host, ok := h2Opts["host"].(string); ok {
			h2Opts["host"] = safeURLDecode(host)
		}
		// host 也可能是数组
		if hosts, ok := h2Opts["host"].([]any); ok {
			for i, h := range hosts {
				if hs, ok := h.(string); ok {
					hosts[i] = safeURLDecode(hs)
				}
			}
		}
	}

	// 处理 grpc-opts
	if grpcOpts, ok := proxy["grpc-opts"].(map[string]any); ok {
		if serviceName, ok := grpcOpts["grpc-service-name"].(string); ok {
			grpcOpts["grpc-service-name"] = safeURLDecode(serviceName)
		}
	}

	// 处理顶层的 path 和 host 字段（某些协议可能直接放在顶层）
	if path, ok := proxy["path"].(string); ok {
		proxy["path"] = safeURLDecode(path)
	}
	if host, ok := proxy["host"].(string); ok {
		proxy["host"] = safeURLDecode(host)
	}

	// 处理 sni 和 servername 字段（TLS 相关）
	if sni, ok := proxy["sni"].(string); ok {
		proxy["sni"] = safeURLDecode(sni)
	}
	if servername, ok := proxy["servername"].(string); ok {
		proxy["servername"] = safeURLDecode(servername)
	}
}

type nodesHandler struct {
	repo            *storage.TrafficRepository
	subscribeDir    string
	yamlSyncManager *YAMLSyncManager
	remoteManage    *RemoteManageHandler
}

// 返回一个管理代理节点的仅管理处理程序。
func NewNodesHandler(repo *storage.TrafficRepository, subscribeDir string, remoteManage *RemoteManageHandler) http.Handler {
	if repo == nil {
		panic("nodes handler requires repository")
	}

	return &nodesHandler{
		repo:            repo,
		subscribeDir:    subscribeDir,
		yamlSyncManager: NewYAMLSyncManager(subscribeDir),
		remoteManage:    remoteManage,
	}
}

// fetchNodeForAccess 按权限获取节点:管理员可取任意节点,普通用户只能取自己创建的(否则 NotFound)。
func (h *nodesHandler) fetchNodeForAccess(ctx context.Context, id int64, username string, isAdmin bool) (storage.Node, error) {
	if isAdmin {
		return h.repo.GetNodeByID(ctx, id)
	}
	return h.repo.GetNode(ctx, id, username)
}

// deleteNodeForAccess 按权限删除节点:管理员可删任意,普通用户只能删自己的。
func (h *nodesHandler) deleteNodeForAccess(ctx context.Context, id int64, username string, isAdmin bool) error {
	if isAdmin {
		return h.repo.DeleteNodeByID(ctx, id)
	}
	return h.repo.DeleteNode(ctx, id, username)
}

func (h *nodesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/nodes")
	path = strings.Trim(path, "/")

	// 普通用户开放:列表 / 单节点分享 URI / 标签 / 解析订阅 / 批量导入(自己的外部节点) / 查看关联入站。
	// 仅管理员:手动单个新增、改名/改标签/改服务器/改配置、删除/清空/批量删改
	//（这些写操作会同步到共享 YAML 订阅文件,影响管理员)。
	isAdmin := userIsAdmin(r.Context(), h.repo, auth.UsernameFromContext(r.Context()))
	denyNonAdmin := func() bool {
		if !isAdmin {
			writeError(w, http.StatusForbidden, errors.New("该操作仅管理员可用"))
			return true
		}
		return false
	}

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.handleList(w, r)
	case path == "" && r.Method == http.MethodPost:
		if denyNonAdmin() {
			return
		}
		h.handleCreate(w, r)
	case path == "batch" && r.Method == http.MethodPost:
		h.handleBatchCreate(w, r)
	case path == "fetch-subscription" && r.Method == http.MethodPost:
		h.handleFetchSubscription(w, r)
	case path == "parse-uris" && r.Method == http.MethodPost:
		h.handleParseURIs(w, r)
	case strings.HasSuffix(path, "/related-inbounds") && r.Method == http.MethodGet:
		idSegment := strings.TrimSuffix(path, "/related-inbounds")
		h.handleGetRelatedInbounds(w, r, idSegment)
	case strings.HasSuffix(path, "/uri") && r.Method == http.MethodGet:
		idSegment := strings.TrimSuffix(path, "/uri")
		h.handleGetURI(w, r, idSegment)
	case strings.HasSuffix(path, "/server") && r.Method == http.MethodPut:
		if denyNonAdmin() {
			return
		}
		idSegment := strings.TrimSuffix(path, "/server")
		h.handleUpdateServer(w, r, idSegment)
	case strings.HasSuffix(path, "/restore-server") && r.Method == http.MethodPut:
		if denyNonAdmin() {
			return
		}
		idSegment := strings.TrimSuffix(path, "/restore-server")
		h.handleRestoreServer(w, r, idSegment)
	case strings.HasSuffix(path, "/config") && r.Method == http.MethodPut:
		if denyNonAdmin() {
			return
		}
		idSegment := strings.TrimSuffix(path, "/config")
		h.handleUpdateConfig(w, r, idSegment)
	case strings.HasSuffix(path, "/relay") && r.Method == http.MethodPut:
		if denyNonAdmin() {
			return
		}
		h.handleSetRelay(w, r, strings.TrimSuffix(path, "/relay"))
	case strings.HasSuffix(path, "/relay") && r.Method == http.MethodDelete:
		if denyNonAdmin() {
			return
		}
		h.handleCancelRelay(w, r, strings.TrimSuffix(path, "/relay"))
	case path != "" && path != "batch" && path != "fetch-subscription" && !strings.HasSuffix(path, "/server") && !strings.HasSuffix(path, "/restore-server") && !strings.HasSuffix(path, "/config") && !strings.HasSuffix(path, "/relay") && !strings.HasSuffix(path, "/related-inbounds") && (r.Method == http.MethodPut || r.Method == http.MethodPatch):
		// 普通用户也放行:handleUpdate 内部按归属限制 —— fetchNodeForAccess 只取本人节点(套餐/admin
		// 节点取不到 → 404),且普通用户被强制为"只能改名称"。归属自己的节点(含自建路由出站)可改名。
		h.handleUpdate(w, r, path)
	case path != "" && path != "batch" && path != "fetch-subscription" && !strings.HasSuffix(path, "/relay") && !strings.HasSuffix(path, "/related-inbounds") && r.Method == http.MethodDelete:
		if denyNonAdmin() {
			return
		}
		h.handleDelete(w, r, path)
	case path == "clear" && r.Method == http.MethodPost:
		if denyNonAdmin() {
			return
		}
		h.handleClearAll(w, r)
	case path == "batch-delete" && r.Method == http.MethodPost:
		if denyNonAdmin() {
			return
		}
		h.handleBatchDelete(w, r)
	case path == "batch-rename" && r.Method == http.MethodPost:
		if denyNonAdmin() {
			return
		}
		h.handleBatchRename(w, r)
	case path == "tags" && r.Method == http.MethodGet:
		h.handleListTags(w, r)
	default:
		allowed := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
		methodNotAllowed(w, allowed...)
	}
}

func (h *nodesHandler) handleGetURI(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}
	nodeID, err := strconv.ParseInt(strings.Trim(idSegment, "/"), 10, 64)
	if err != nil || nodeID <= 0 {
		writeBadRequest(w, "无效的节点 ID")
		return
	}

	var node storage.Node
	if userIsAdmin(r.Context(), h.repo, username) {
		node, err = h.repo.GetNodeByID(r.Context(), nodeID)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("节点不存在"))
			return
		}
	} else {
		visible, listErr := collectUserVisibleNodes(r.Context(), h.repo, username)
		if listErr != nil {
			writeError(w, http.StatusInternalServerError, listErr)
			return
		}
		visible = substituteNodesForUser(r.Context(), h.repo, username, visible)
		found := false
		for _, candidate := range visible {
			if candidate.ID == nodeID {
				node = candidate
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusNotFound, errors.New("节点不存在或当前用户无权访问"))
			return
		}
	}

	item, err := makeNodeURIItem(username, node, substore.NewURIProducer())
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"item": item})
}

func (h *nodesHandler) handleList(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	// 数据隔离:管理员看全部节点,但屏蔽"普通用户私有"节点。
	// 反向过滤逻辑:只有当节点 username 属于现存普通用户时才屏蔽;
	// admin 用户/legacy "admin" 字面字符串/已不存在的用户名 → 一律保留。
	//
	// 例外:?include_private=1 — 套餐管理 tooltip / 节点关联 dialog 等需要 id→name 全量映射,
	// 不能漏 routed_owner='user' 子节点或用户私有节点,否则 tooltip 显示成 "node-272" 这种 fallback。
	// 仅 admin 视角生效(普通用户走下面 user 路径,不进这个 if)。
	if userIsAdmin(r.Context(), h.repo, username) {
		nodes, err := h.repo.ListAllNodes(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if r.URL.Query().Get("include_private") == "1" {
			respondJSON(w, http.StatusOK, map[string]any{"nodes": convertNodes(nodes)})
			return
		}
		nonAdmins, err := h.repo.ListNonAdminUsernames(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		filtered := make([]storage.Node, 0, len(nodes))
		for _, n := range nodes {
			if nonAdmins[n.Username] {
				continue
			}
			filtered = append(filtered, n)
		}
		respondJSON(w, http.StatusOK, map[string]any{"nodes": convertNodes(filtered)})
		return
	}

	// 普通用户:自己导入的节点 + 绑定套餐内的节点(只读)。
	nodes, err := collectUserVisibleNodes(r.Context(), h.repo, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 安全:把每个节点的 clash_config 里 admin uuid/password 等凭据替换为本用户的凭据。
	// 不替换 = 把 admin 凭据原样下发给所有能看到节点的普通用户(节点管理眼睛图标会显示)。
	// routed 节点没有用户子账号的 → 完全过滤掉(用户无访问权,不该出现在列表)。
	nodes = substituteNodesForUser(r.Context(), h.repo, username, nodes)

	// 节点级倍率:根据用户绑定套餐查 multiplier(routed 子节点用 parent 回退),仅当 != 1 时写入响应
	dto := convertNodes(nodes)
	// 安全:普通用户视角绝不暴露中转节点的真实源站地址。clash/parsed 的 server/port 已是中转地址,
	// relay_orig_*(被中转替换掉的真实地址)只供 admin 管理/取消中转。剥离后前端 relay_orig_server
	// 为空 → 不显示"原服务器"行,只显示中转地址。
	for i := range dto {
		dto[i].RelayOrigServer = ""
		dto[i].RelayOrigPort = 0
	}
	if user, uerr := h.repo.GetUser(r.Context(), username); uerr == nil && user.PackageID > 0 {
		if pkg, perr := h.repo.GetPackage(r.Context(), user.PackageID); perr == nil && pkg != nil && len(pkg.NodeMultipliers) > 0 {
			for i, n := range nodes {
				m := pkg.MultiplierForNode(n.ID)
				if m != 1.0 {
					dto[i].Multiplier = m
				}
			}
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"nodes": dto,
	})
}

// claimNodeIfHostMatchesServer associates an imported node with a managed
// server when its origin host matches that server.
func (h *nodesHandler) claimNodeIfHostMatchesServer(ctx context.Context, node *storage.Node) {
	if h.remoteManage == nil || node == nil {
		return
	}
	// 优先 ClashConfig(从 yaml 转过来的标准结构,server 字段稳定),fallback ParsedConfig。
	configJSON := node.ClashConfig
	if strings.TrimSpace(configJSON) == "" {
		configJSON = node.ParsedConfig
	}
	srv, err := h.remoteManage.MatchRemoteServerByNodeHost(ctx, configJSON, node.RelayOrigServer)
	if err != nil || srv == nil {
		return
	}
	node.OriginalServer = srv.Name
	if strings.TrimSpace(node.Tag) == "" {
		node.Tag = fmt.Sprintf("远程:%s", srv.Name)
	}
}

// prepareImportedNode enforces the trust boundary between ordinary imports and
// nodes managed by an Agent. Only administrators may associate an imported
// node with a managed server/inbound; ordinary users always create external
// nodes, even when their payload or proxy host resembles a managed server.
func (h *nodesHandler) prepareImportedNode(ctx context.Context, node *storage.Node, isAdmin bool) {
	if node == nil {
		return
	}
	if !isAdmin {
		node.OriginalServer = ""
		node.InboundTag = ""
		return
	}
	h.claimNodeIfHostMatchesServer(ctx, node)
}

// buildUserCredMapForCreator 给某个用户构造 (server_name, inbound_tag) → credential_json 映射,
// 给 applyUserCredentials 用。从 user_inbound_configs 表拉,跟 PackageSubscribeHandler.buildUserCredentialMap 同源。
//
// 复用点:nodes.go substituteNodesForUser + subscription.go generateFromTemplate(模板订阅) 都用这个。
// 抽成包级函数避免重复 + 也避免漏改一处的安全隐患。
func buildUserCredMapForCreator(ctx context.Context, repo *storage.TrafficRepository, username string) map[credKey]string {
	if username == "" {
		return nil
	}
	userConfigs, err := repo.GetUserInboundConfigs(ctx, username)
	if err != nil || len(userConfigs) == 0 {
		return nil
	}
	servers, err := repo.ListRemoteServers(ctx)
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

// substituteNodesForUser 把节点列表里的 clash_config 替换成该用户视角的版本。
//   - 普通节点:applyUserCredentials 改 uuid / password 等
//   - routed 节点:buildRoutedProxyForUser 用 user_subaccounts 凭据重建(没子账号即 drop)
//
// 受管节点替换/重建失败时必须丢弃，绝不能把 admin 原始凭据作为回退值下发。
// collectUserVisibleNodes 收集某用户可见的节点:自己导入的 + 套餐 pkg.Nodes + 套餐内 shared routed 子节点(去重)。
// 与 handleList 普通用户路径口径一致;不做凭据替换(调用方按需 substituteNodesForUser)。
func collectUserVisibleNodes(ctx context.Context, repo *storage.TrafficRepository, username string) ([]storage.Node, error) {
	nodes, err := repo.ListNodes(ctx, username)
	if err != nil {
		return nil, err
	}
	seen := make(map[int64]bool, len(nodes))
	for _, n := range nodes {
		seen[n.ID] = true
	}
	if user, uerr := repo.GetUser(ctx, username); uerr == nil && user.IsActive && user.PackageID > 0 &&
		(user.PackageEndDate == nil || time.Now().Before(*user.PackageEndDate)) {
		overLimit, limitErr := repo.IsUserOverLimit(ctx, username)
		if limitErr == nil && !overLimit {
			if pkg, perr := repo.GetPackage(ctx, user.PackageID); perr == nil && pkg != nil {
				for _, nid := range pkg.Nodes {
					if seen[nid] {
						continue
					}
					if pn, nerr := repo.GetNodeByID(ctx, nid); nerr == nil {
						nodes = append(nodes, pn)
						seen[nid] = true
					}
				}
				// 套餐内父节点派生的 shared routed 子节点也随套餐对用户可见(见 handleList 同段注释)。
				if children, cerr := repo.ListSharedRoutedByParentIDs(ctx, pkg.Nodes); cerr == nil {
					for _, cn := range children {
						if seen[cn.ID] {
							continue
						}
						nodes = append(nodes, cn)
						seen[cn.ID] = true
					}
				}
			}
		}
	}
	managedNodeIDs, managedErr := effectiveManagedNodeIDs(ctx, repo, username)
	if managedErr != nil {
		return nil, managedErr
	}
	for _, nodeID := range managedNodeIDs {
		if seen[nodeID] {
			continue
		}
		if node, nodeErr := repo.GetNodeByID(ctx, nodeID); nodeErr == nil {
			nodes = append(nodes, node)
			seen[nodeID] = true
		}
	}
	return nodes, nil
}

func substituteNodesForUser(ctx context.Context, repo *storage.TrafficRepository, username string, nodes []storage.Node) []storage.Node {
	if len(nodes) == 0 {
		return nodes
	}
	credMap := buildUserCredMapForCreator(ctx, repo, username)
	if credMap == nil {
		credMap = map[credKey]string{}
	}
	out := make([]storage.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.NodeType == "routed" {
			// routed 节点必须有 active 子账号才能给用户;没的话整个节点过滤掉,
			// 避免把 admin 的 routed 父凭据(uuid)泄露给无权用户。
			proxy, ok := buildRoutedProxyForUser(ctx, repo, n, username)
			if !ok {
				continue
			}
			if raw, err := json.Marshal(proxy); err == nil {
				n.ClashConfig = string(raw)
			}
			out = append(out, n)
			continue
		}
		if n.ClashConfig == "" {
			if strings.TrimSpace(n.OriginalServer) != "" || strings.TrimSpace(n.InboundTag) != "" {
				continue
			}
			out = append(out, n)
			continue
		}
		var proxy map[string]any
		if err := json.Unmarshal([]byte(n.ClashConfig), &proxy); err != nil {
			// Managed nodes fail closed: returning an unparsed config would expose
			// the template owner's credential. Personal external nodes remain usable.
			if strings.TrimSpace(n.OriginalServer) == "" && strings.TrimSpace(n.InboundTag) == "" {
				out = append(out, n)
			}
			continue
		}
		if !applyUserCredentials(proxy, n, credMap) {
			continue
		}
		raw, err := json.Marshal(proxy)
		if err != nil {
			continue
		}
		n.ClashConfig = string(raw)
		out = append(out, n)
	}
	return out
}

func (h *nodesHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	var req nodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}
	req.parseChainProxyNodeID()

	// 校验节点名称不为空
	if strings.TrimSpace(req.NodeName) == "" {
		logger.Info("[节点创建] 节点名称为空")
		writeBadRequest(w, "节点名称不能为空")
		return
	}

	// 校验节点名称是否重复（数据库层面）
	exists, err := h.repo.CheckNodeNameExists(r.Context(), req.NodeName, username, 0)
	if err != nil {
		logger.Info("[节点创建] 检查节点名称重复失败", "error", err)
		writeError(w, http.StatusInternalServerError, errors.New("服务器错误"))
		return
	}
	if exists {
		logger.Info("[节点创建] 节点名称重复", "node_name", req.NodeName)
		writeBadRequest(w, fmt.Sprintf("节点名称 \"%s\" 已存在，请使用其他名称", req.NodeName))
		return
	}

	// 校验Clash配置格式
	if req.ClashConfig != "" {
		var clashConfig map[string]interface{}
		if err := json.Unmarshal([]byte(req.ClashConfig), &clashConfig); err != nil {
			logger.Info("[节点创建] Clash配置格式错误", "error", err)
			writeBadRequest(w, "Clash配置格式错误")
			return
		}

		// 确保配置中的name与节点名称一致
		if configName, ok := clashConfig["name"].(string); !ok || configName != req.NodeName {
			logger.Info("[节点创建] 配置name不匹配: 节点名=, 配置名", "node_name", req.NodeName, "param", clashConfig["name"])
			writeBadRequest(w, "Clash配置中的name字段必须与节点名称一致")
			return
		}
	}

	logger.Info("[节点创建] 校验通过 - 节点名称, 用户", "node_name", req.NodeName, "user", username)

	node := storage.Node{
		Username:         username,
		RawURL:           req.RawURL,
		NodeName:         req.NodeName,
		Protocol:         req.Protocol,
		ParsedConfig:     req.ParsedConfig,
		ClashConfig:      req.ClashConfig,
		Enabled:          req.Enabled,
		Tag:              req.Tag,
		Tags:             req.Tags,
		InboundTag:       req.InboundTag,
		ChainProxyNodeID: req.ChainProxyNodeID,
	}

	// Only administrators may turn an import into a managed node.
	h.prepareImportedNode(r.Context(), &node, userIsAdmin(r.Context(), h.repo, username))

	// 中转:clash/parsed 的 server/port 换成中转地址,原服务器地址/端口记到 relay_orig_*。
	if rs := strings.TrimSpace(req.RelayServer); rs != "" {
		applyRelayToNode(&node, rs, req.RelayPort)
	}

	created, err := h.repo.CreateNode(r.Context(), node)
	if err != nil {
		logger.Info("[节点创建] 数据库创建失败", "error", err)
		writeError(w, http.StatusBadRequest, err)
		return
	}

	logger.Info("[节点创建] 成功 - ID, 节点名称", "id", created.ID, "node_name", created.NodeName)

	respondJSON(w, http.StatusCreated, map[string]any{
		"node": convertNode(created),
	})
}

func (h *nodesHandler) handleBatchCreate(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	var req struct {
		Nodes []nodeRequest `json:"nodes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if len(req.Nodes) == 0 {
		writeBadRequest(w, "节点列表不能为空")
		return
	}

	nodes := make([]storage.Node, 0, len(req.Nodes))
	relayReqs := make([]nodeRequest, 0, len(req.Nodes)) // 与 nodes 对齐,保留每个节点的中转意图
	for _, n := range req.Nodes {
		// 允许 Clash 订阅节点没有 RawURL，但必须有 NodeName 和 ClashConfig
		if n.NodeName == "" || n.ClashConfig == "" {
			continue
		}
		nodes = append(nodes, storage.Node{
			Username:     username,
			RawURL:       n.RawURL, // 可以为空（Clash 订阅节点）
			NodeName:     n.NodeName,
			Protocol:     n.Protocol,
			ParsedConfig: n.ParsedConfig,
			ClashConfig:  n.ClashConfig,
			Enabled:      n.Enabled,
			Tag:          n.Tag,
			InboundTag:   n.InboundTag,
		})
		relayReqs = append(relayReqs, n)
	}

	if len(nodes) == 0 {
		writeBadRequest(w, "没有有效的节点可以保存")
		return
	}

	// Only administrators may turn an import into a managed node. In particular,
	// ordinary users cannot smuggle inbound_tag through the batch endpoint.
	isAdmin := userIsAdmin(r.Context(), h.repo, username)
	for i := range nodes {
		h.prepareImportedNode(r.Context(), &nodes[i], isAdmin)
	}

	// 给填了中转的节点挂中转(与单个创建/编辑端点同一份 applyRelayToNode 逻辑)。
	for i := range nodes {
		if rs := strings.TrimSpace(relayReqs[i].RelayServer); rs != "" {
			applyRelayToNode(&nodes[i], rs, relayReqs[i].RelayPort)
		}
	}

	created, err := h.repo.BatchCreateNodes(r.Context(), nodes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"nodes": convertNodes(created),
	})
}

func (h *nodesHandler) handleUpdate(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的节点标识")
		return
	}

	isAdmin := userIsAdmin(r.Context(), h.repo, username)
	existing, err := h.fetchNodeForAccess(r.Context(), id, username, isAdmin)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	// 保存旧节点名称以进行 YAML 同步
	oldNodeName := existing.NodeName

	var req nodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}
	req.parseChainProxyNodeID()

	// 普通用户:只能改自己节点的「名称」。归属已由 fetchNodeForAccess 限制为本人节点(套餐/admin
	// 节点取不到 → 404)。强制只保留 NodeName、其余字段沿用原节点,防止越权改配置/协议/标签/启用状态。
	if !isAdmin {
		req = nodeRequest{NodeName: req.NodeName, Enabled: existing.Enabled}
	}

	// 如果节点名称被修改，需要校验新名称
	if req.NodeName != "" && req.NodeName != oldNodeName {
		// 校验节点名称不为空
		if strings.TrimSpace(req.NodeName) == "" {
			logger.Info("[节点更新] 节点名称为空")
			writeBadRequest(w, "节点名称不能为空")
			return
		}

		// 校验节点名称是否重复（在节点所有者的命名空间内）
		exists, err := h.repo.CheckNodeNameExists(r.Context(), req.NodeName, existing.Username, id)
		if err != nil {
			logger.Info("[节点更新] 检查节点名称重复失败", "error", err)
			writeError(w, http.StatusInternalServerError, errors.New("服务器错误"))
			return
		}
		if exists {
			logger.Info("[节点更新] 节点名称重复", "node_name", req.NodeName)
			writeBadRequest(w, fmt.Sprintf("节点名称 \"%s\" 已存在，请使用其他名称", req.NodeName))
			return
		}
	}

	// 如果Clash配置被修改，需要校验格式
	if req.ClashConfig != "" {
		var clashConfig map[string]interface{}
		if err := json.Unmarshal([]byte(req.ClashConfig), &clashConfig); err != nil {
			logger.Info("[节点更新] Clash配置格式错误", "error", err)
			writeBadRequest(w, "Clash配置格式错误")
			return
		}

		// 确保配置中的name与节点名称一致
		newNodeName := req.NodeName
		if newNodeName == "" {
			newNodeName = oldNodeName
		}
		if configName, ok := clashConfig["name"].(string); !ok || configName != newNodeName {
			logger.Info("[节点更新] 配置name不匹配: 节点名=, 配置名", "value", newNodeName, "param", clashConfig["name"])
			writeBadRequest(w, "Clash配置中的name字段必须与节点名称一致")
			return
		}
	}

	logger.Info("[节点更新] 校验通过 - 节点ID, 旧名称, 新名称", "value", id, "param", oldNodeName, "node_name", req.NodeName)

	// 更新字段
	if req.RawURL != "" {
		existing.RawURL = req.RawURL
	}
	if req.NodeName != "" {
		existing.NodeName = req.NodeName
	}
	if req.Protocol != "" {
		existing.Protocol = req.Protocol
	}
	if req.ParsedConfig != "" {
		existing.ParsedConfig = req.ParsedConfig
	}
	if req.ClashConfig != "" {
		existing.ClashConfig = req.ClashConfig
	}
	if req.Tag != "" {
		existing.Tag = req.Tag
	}
	// 多标签:前端发了 tags 则覆盖(空数组也是覆盖,代表"全部清空");没发的话保持旧值
	if req.Tags != nil {
		existing.Tags = req.Tags
	}
	existing.Enabled = req.Enabled
	if req.hasChainProxyNodeID() {
		existing.ChainProxyNodeID = req.ChainProxyNodeID
	}

	updated, err := h.repo.UpdateNode(r.Context(), existing)
	if err != nil {
		logger.Info("[节点更新] 数据库更新失败", "error", err)
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	logger.Info("[节点更新] 数据库更新成功 - 节点ID, 节点名称", "id", updated.ID, "node_name", updated.NodeName)

	// 使用同步管理器将节点更改同步到 YAML 文件
	if updated.ClashConfig != "" {
		newNodeName := updated.NodeName
		if err := h.yamlSyncManager.SyncNode(oldNodeName, newNodeName, updated.ClashConfig); err != nil {
			// 记录错误但不要使请求失败
			// 节点更新成功，YAML 同步已尽力
			// 如果需要，您可以在此处添加日志记录
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"node": convertNode(updated),
	})
}

func (h *nodesHandler) handleUpdateServer(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的节点标识")
		return
	}

	existing, err := h.fetchNodeForAccess(r.Context(), id, username, userIsAdmin(r.Context(), h.repo, username))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	var req struct {
		Server string `json:"server"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.Server == "" {
		writeBadRequest(w, "服务器地址不能为空")
		return
	}

	// 更新前保存原始域名到 OriginalDomain（专用字段，不能用 OriginalServer——那是服务器名/路由键）
	var currentClashConfig map[string]any
	if err := json.Unmarshal([]byte(existing.ClashConfig), &currentClashConfig); err == nil {
		if currentServer, ok := currentClashConfig["server"].(string); ok && currentServer != "" {
			existing.OriginalDomain = currentServer
		}
	}

	// 更新 ParsedConfig 中的 server 字段
	var parsedConfig map[string]any
	if err := json.Unmarshal([]byte(existing.ParsedConfig), &parsedConfig); err == nil {
		parsedConfig["server"] = req.Server
		if updatedParsed, err := json.Marshal(parsedConfig); err == nil {
			existing.ParsedConfig = string(updatedParsed)
		}
	}

	// 更新 ClashConfig 中的 server 字段
	var clashConfig map[string]any
	if err := json.Unmarshal([]byte(existing.ClashConfig), &clashConfig); err == nil {
		clashConfig["server"] = req.Server
		if updatedClash, err := json.Marshal(clashConfig); err == nil {
			existing.ClashConfig = string(updatedClash)
		}
	}

	// server 字段变了 → OriginalServer 必须重新校验:
	//   - 新 server 命中某 remote_server.{IP,Domain,PullAddress} → OS = 该 server.Name
	//   - 不命中任何 remote_server → 清空 OS(避免「VICTORIA 伪装节点残留 OS=GoMami」这种识别错位)
	// 这里复用 MatchRemoteServerByNodeHost 同一份匹配规则。
	if h.remoteManage != nil {
		if srv, _ := h.remoteManage.MatchRemoteServerByNodeHost(r.Context(), existing.ClashConfig, existing.RelayOrigServer); srv != nil {
			existing.OriginalServer = srv.Name
		} else {
			existing.OriginalServer = ""
		}
	}

	updated, err := h.repo.UpdateNode(r.Context(), existing)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	// 使用同步管理器将节点更改同步到 YAML 文件（服务器地址更新）
	if updated.ClashConfig != "" {
		nodeName := updated.NodeName
		if err := h.yamlSyncManager.SyncNode(nodeName, nodeName, updated.ClashConfig); err != nil {
			// 记录错误但不要使请求失败
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"node": convertNode(updated),
	})
}

func (h *nodesHandler) handleRestoreServer(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的节点标识")
		return
	}

	existing, err := h.fetchNodeForAccess(r.Context(), id, username, userIsAdmin(r.Context(), h.repo, username))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	// 检查原始域名是否存在
	if existing.OriginalDomain == "" {
		writeBadRequest(w, "节点没有保存原始域名")
		return
	}

	// 从 original_domain 恢复服务器地址
	originalServer := existing.OriginalDomain

	// 更新 ParsedConfig 中的 server 字段
	var parsedConfig map[string]any
	if err := json.Unmarshal([]byte(existing.ParsedConfig), &parsedConfig); err == nil {
		parsedConfig["server"] = originalServer
		if updatedParsed, err := json.Marshal(parsedConfig); err == nil {
			existing.ParsedConfig = string(updatedParsed)
		}
	}

	// 更新 ClashConfig 中的 server 字段
	var clashConfig map[string]any
	if err := json.Unmarshal([]byte(existing.ClashConfig), &clashConfig); err == nil {
		clashConfig["server"] = originalServer
		if updatedClash, err := json.Marshal(clashConfig); err == nil {
			existing.ClashConfig = string(updatedClash)
		}
	}

	// 恢复后清除 original_domain（OriginalServer 路由键保持不变）
	existing.OriginalDomain = ""

	updated, err := h.repo.UpdateNode(r.Context(), existing)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	// 使用同步管理器将节点更改同步到 YAML 文件（恢复服务器地址）
	if updated.ClashConfig != "" {
		nodeName := updated.NodeName
		if err := h.yamlSyncManager.SyncNode(nodeName, nodeName, updated.ClashConfig); err != nil {
			// 记录错误但不要使请求失败
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"node": convertNode(updated),
	})
}

// clashConfigServerPort 从 clash/parsed JSON 串里读出 server + port。ok=false 表示解析失败或缺 server。
func clashConfigServerPort(cfgJSON string) (server string, port int, ok bool) {
	var m map[string]any
	if json.Unmarshal([]byte(cfgJSON), &m) != nil {
		return "", 0, false
	}
	server, _ = m["server"].(string)
	switch v := m["port"].(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	}
	if server == "" {
		return "", 0, false
	}
	return server, port, true
}

// setClashConfigServerPort 把 clash/parsed JSON 串的 server/port 改成给定值,返回新串。
// 解析失败则原样返回(不破坏配置);port<=0 时只改 server、不动 port。
func setClashConfigServerPort(cfgJSON, server string, port int) string {
	var m map[string]any
	if json.Unmarshal([]byte(cfgJSON), &m) != nil {
		return cfgJSON
	}
	m["server"] = server
	if port > 0 {
		m["port"] = port
	}
	b, err := json.Marshal(m)
	if err != nil {
		return cfgJSON
	}
	return string(b)
}

// applyRelayToNode 给节点挂中转:首次设置时把当前 clash 的 server/port 记为「原服务器」(relay_orig_*),
// 再把 clash + parsed 的 server/port 都改成中转地址。已配置中转时再次调用=改中转目标,不重记原值。
// relayPort<=0 时沿用节点当前 clash 端口(满足「端口默认填节点端口」)。
func applyRelayToNode(n *storage.Node, relayServer string, relayPort int) {
	if strings.TrimSpace(n.RelayOrigServer) == "" {
		if s, p, ok := clashConfigServerPort(n.ClashConfig); ok {
			n.RelayOrigServer = s
			n.RelayOrigPort = p
		}
	}
	if relayPort <= 0 {
		if _, p, ok := clashConfigServerPort(n.ClashConfig); ok {
			relayPort = p
		}
	}
	n.ClashConfig = setClashConfigServerPort(n.ClashConfig, relayServer, relayPort)
	n.ParsedConfig = setClashConfigServerPort(n.ParsedConfig, relayServer, relayPort)
}

// cancelRelayOnNode 取消中转:把 clash + parsed 的 server/port 还原为 relay_orig_*,再清空这两列。
func cancelRelayOnNode(n *storage.Node) {
	if strings.TrimSpace(n.RelayOrigServer) == "" {
		return
	}
	n.ClashConfig = setClashConfigServerPort(n.ClashConfig, n.RelayOrigServer, n.RelayOrigPort)
	n.ParsedConfig = setClashConfigServerPort(n.ParsedConfig, n.RelayOrigServer, n.RelayOrigPort)
	n.RelayOrigServer = ""
	n.RelayOrigPort = 0
}

// handleSetRelay 设置/修改节点中转:PUT /api/admin/nodes/{id}/relay  {relay_server, relay_port}
func (h *nodesHandler) handleSetRelay(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}
	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的节点标识")
		return
	}
	existing, err := h.fetchNodeForAccess(r.Context(), id, username, userIsAdmin(r.Context(), h.repo, username))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	var req struct {
		RelayServer string `json:"relay_server"`
		RelayPort   int    `json:"relay_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}
	req.RelayServer = strings.TrimSpace(req.RelayServer)
	if req.RelayServer == "" {
		writeBadRequest(w, "中转服务器地址不能为空")
		return
	}
	if req.RelayPort < 0 || req.RelayPort > 65535 {
		writeBadRequest(w, "中转端口不合法")
		return
	}

	applyRelayToNode(&existing, req.RelayServer, req.RelayPort)

	updated, err := h.repo.UpdateNode(r.Context(), existing)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	if updated.ClashConfig != "" {
		_ = h.yamlSyncManager.SyncNode(updated.NodeName, updated.NodeName, updated.ClashConfig)
	}
	respondJSON(w, http.StatusOK, map[string]any{"node": convertNode(updated)})
}

// handleCancelRelay 取消节点中转:DELETE /api/admin/nodes/{id}/relay。clash server/port 还原为原服务器。
func (h *nodesHandler) handleCancelRelay(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}
	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的节点标识")
		return
	}
	existing, err := h.fetchNodeForAccess(r.Context(), id, username, userIsAdmin(r.Context(), h.repo, username))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	if strings.TrimSpace(existing.RelayOrigServer) == "" {
		writeBadRequest(w, "该节点未配置中转")
		return
	}

	cancelRelayOnNode(&existing)

	updated, err := h.repo.UpdateNode(r.Context(), existing)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	if updated.ClashConfig != "" {
		_ = h.yamlSyncManager.SyncNode(updated.NodeName, updated.NodeName, updated.ClashConfig)
	}
	respondJSON(w, http.StatusOK, map[string]any{"node": convertNode(updated)})
}

func (h *nodesHandler) handleUpdateConfig(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的节点标识")
		return
	}

	var req struct {
		ClashConfig string `json:"clash_config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	// 验证 JSON 格式
	var clashConfigMap map[string]interface{}
	if err := json.Unmarshal([]byte(req.ClashConfig), &clashConfigMap); err != nil {
		writeBadRequest(w, "Clash 配置格式不正确: "+err.Error())
		return
	}

	// 验证必填字段
	requiredFields := []string{"name", "type", "server", "port"}
	for _, field := range requiredFields {
		if _, ok := clashConfigMap[field]; !ok {
			writeBadRequest(w, fmt.Sprintf("配置缺少必需字段: %s", field))
			return
		}
	}

	// 获取现有节点(按权限:管理员任意,普通用户仅自己的)
	node, err := h.fetchNodeForAccess(r.Context(), id, username, userIsAdmin(r.Context(), h.repo, username))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	oldNodeName := node.NodeName

	// 更新节点的 ClashConfig 和 ParsedConfig
	node.ClashConfig = req.ClashConfig
	node.ParsedConfig = req.ClashConfig

	// 如果更改，请从配置中更新节点名称
	if nameValue, ok := clashConfigMap["name"]; ok {
		if newName, ok := nameValue.(string); ok && newName != "" {
			node.NodeName = newName
		}
	}

	// 更新数据库中的节点
	updated, err := h.repo.UpdateNode(r.Context(), node)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 使用同步管理器同步到 YAML 订阅文件
	if updated.ClashConfig != "" {
		// 如果节点名称发生更改，请将 YAML 文件中的旧名称更新为新名称
		newNodeName := updated.NodeName
		if err := h.yamlSyncManager.SyncNode(oldNodeName, newNodeName, updated.ClashConfig); err != nil {
			// 记录错误但不要使请求失败
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"node": convertNode(updated),
	})
}

func (h *nodesHandler) handleDelete(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的节点标识")
		return
	}

	// 检查delete_inbound参数是否设置
	deleteInbound := r.URL.Query().Get("delete_inbound") == "true"

	isAdmin := userIsAdmin(r.Context(), h.repo, username)

	// 在删除之前获取节点名称以进行 YAML 同步(按权限:管理员任意,普通用户仅自己的)
	// 如果没有找到节点，我们仍然继续删除（可能已经在其他地方删除了）
	node, err := h.fetchNodeForAccess(r.Context(), id, username, isAdmin)
	nodeNotFound := errors.Is(err, storage.ErrNodeNotFound)
	if err != nil && !nodeNotFound {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 如果找到节点并且delete_inbound为true，则删除关联的批次入站
	var deletedInboundCount int
	if !nodeNotFound && deleteInbound && node.NodeName != "" {
		// 获取带有匹配标签的批次入站
		batches, err := h.repo.GetBatchInboundsByTag(r.Context(), node.NodeName)
		if err == nil && len(batches) > 0 {
			// 删除批量入库记录
			if err := h.repo.DeleteBatchInboundsByTag(r.Context(), node.NodeName); err == nil {
				deletedInboundCount = len(batches)
			}
		}
	}

	// 远程闭环:routed 清 rule+outbound+client,physical 清 inbound(并兜底刷 nginx)。单删 / 批删共用 helper。
	if !nodeNotFound {
		h.cleanupRemoteForNode(r.Context(), &node)
	}

	// 删除节点(按权限:管理员任意,普通用户仅自己的)
	if err := h.deleteNodeForAccess(r.Context(), id, username, isAdmin); err != nil {
		if !errors.Is(err, storage.ErrNodeNotFound) {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// 未找到节点是可以接受的 - 它已被删除
	}

	// 使用同步管理器将删除同步到 YAML 文件
	if !nodeNotFound && node.NodeName != "" {
		if err := h.yamlSyncManager.DeleteNode(node.NodeName); err != nil {
			// 记录错误但不要使请求失败
		}
	}

	resp := map[string]any{"status": "deleted"}
	if deletedInboundCount > 0 {
		resp["deleted_inbound_count"] = deletedInboundCount
	}
	respondJSON(w, http.StatusOK, resp)
}

// 通过 inbound_tag 返回与节点关联的批次入站
func (h *nodesHandler) handleGetRelatedInbounds(w http.ResponseWriter, r *http.Request, idSegment string) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的节点标识")
		return
	}

	// 获取节点以找到其入站标签
	node, err := h.repo.GetNode(r.Context(), id, username)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrNodeNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	// 查找具有匹配标记的批次入站（如果设置了 InboundTag，则使用 InboundTag，否则回退到 NodeName 以实现向后兼容性）
	var inbounds []storage.BatchInbound
	searchTag := node.InboundTag
	if searchTag == "" {
		searchTag = node.NodeName
	}
	if searchTag != "" {
		inbounds, err = h.repo.GetBatchInboundsByTag(r.Context(), searchTag)
		if err != nil {
			// 不是严重错误，只是返回空列表
			inbounds = []storage.BatchInbound{}
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"node_name":   node.NodeName,
		"inbound_tag": node.InboundTag,
		"inbounds":    inbounds,
		"count":       len(inbounds),
	})
}

func (h *nodesHandler) handleClearAll(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	// 清空前先逐个清理 agent 侧残留(以该节点为出口的出站/路由、routed outbound、inbound clients),
	// 否则只删 DB 会在 agent 端留下孤儿出站/路由/入站(handleDelete/handleBatchDelete 走 cleanupRemoteForNode,清空之前漏了)。
	if nodes, err := h.repo.ListNodes(r.Context(), username); err == nil {
		for i := range nodes {
			h.cleanupRemoteForNode(r.Context(), &nodes[i])
		}
	}

	if err := h.repo.DeleteAllUserNodes(r.Context(), username); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (h *nodesHandler) handleBatchDelete(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	var req struct {
		NodeIDs []int64 `json:"node_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if len(req.NodeIDs) == 0 {
		writeBadRequest(w, "节点ID列表不能为空")
		return
	}

	isAdmin := userIsAdmin(r.Context(), h.repo, username)

	// 只处理调用者有权访问的节点(管理员任意,普通用户仅自己的)。
	// 保留完整 *storage.Node:后续 cleanupRemoteForNode 需要 NodeType + RoutedOutboundTag 判断分支,
	// 之前 nodeInfo 只存 inboundTag → routed 节点走 deleteRemoteInbound 误删父 inbound、漏清 outbound/rule。
	accessibleIDs := make([]int64, 0, len(req.NodeIDs))
	nodes := make([]storage.Node, 0, len(req.NodeIDs))
	for _, id := range req.NodeIDs {
		node, err := h.fetchNodeForAccess(r.Context(), id, username, isAdmin)
		if err != nil {
			continue
		}
		accessibleIDs = append(accessibleIDs, id)
		nodes = append(nodes, node)
	}

	// 远程闭环。先「整批一次」清理各服务器上以这些节点为落地出口的出站(每台服务器只 GET 一次 outbounds
	// + 并发 + 短超时),避免旧实现「每节点 × 每服务器」的 O(N×M) 串行远程调用 —— 那会让批量删外部节点
	// 撞上 N×M×(HTTP 30s 兜底)= 几分钟并超时失败。再逐节点清各自 OriginalServer 上的 inbound/routed
	// 出站(外部节点 OriginalServer 为空,自动跳过,基本不发远程请求)。
	h.cleanupOutboundsTargetingNodes(r.Context(), nodes)
	for i := range nodes {
		h.cleanupRemoteInboundForNode(r.Context(), &nodes[i])
	}

	// 从数据库中删除节点(按权限)
	deletedCount := 0
	for _, id := range accessibleIDs {
		if err := h.deleteNodeForAccess(r.Context(), id, username, isAdmin); err != nil {
			continue
		}
		deletedCount++
	}

	// 使用同步管理器批量同步删除 YAML 文件
	nodeNames := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if n.NodeName != "" {
			nodeNames = append(nodeNames, n.NodeName)
		}
	}
	if len(nodeNames) > 0 {
		if err := h.yamlSyncManager.BatchDeleteNodes(nodeNames); err != nil {
			// 记录错误但不要使请求失败
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status":  "deleted",
		"deleted": deletedCount,
		"total":   len(req.NodeIDs),
	})
}

// cleanupRemoteForNode 删节点(单删/批删)统一闭环入口:按节点类型选清理路径。
//   - routed:清 routing rule + outbound + inbound 内 admin/sub clients(对称 routed_outbound.create)
//   - physical:清 inbound(并在 WSS 场景兜底刷新 nginx,见 deleteRemoteInbound 末尾)
//   - 无 originalServer / 全空:跳过(纯导入节点,本来没远程资源)
//
// 设计:本 helper 替代各调用方手抄 if-else 的旧模式,降低单删/批删行为分歧风险(批删之前漏判 routed)。
// RoutedAdminEmail 不在 storage.Node 上(只在 RoutedNodeDetail),helper 内 routed 分支自动 fetch detail。
func (h *nodesHandler) cleanupRemoteForNode(ctx context.Context, node *storage.Node) {
	if node == nil {
		return
	}
	// 先清「以该节点为出口的出站」—— 这些 outbound + routing rule 可能在任意服务器上,与本节点的 OriginalServer 无关,
	// 故放在 OriginalServer 守卫之前(外部/手动节点也可能被别的节点当落地出口)。
	h.cleanupOutboundsTargetingNode(ctx, node)
	h.cleanupRemoteInboundForNode(ctx, node)
}

// cleanupRemoteInboundForNode 清节点自身在其 OriginalServer 上的 inbound / routed 出站。
// 外部/手动导入节点没有 OriginalServer,直接返回(不发远程请求)。
func (h *nodesHandler) cleanupRemoteInboundForNode(ctx context.Context, node *storage.Node) {
	if node == nil || node.OriginalServer == "" {
		return
	}
	if node.NodeType == "routed" && node.RoutedOutboundTag != "" {
		adminEmail := ""
		if detail, err := h.repo.GetRoutedNodeDetail(ctx, node.ID); err == nil {
			adminEmail = detail.RoutedAdminEmail
		}
		h.deleteRemoteRoutedOutbound(ctx, node.OriginalServer, node.RoutedOutboundTag, node.InboundTag, adminEmail, node.ID)
		return
	}
	if node.InboundTag != "" {
		h.deleteRemoteInbound(ctx, node.OriginalServer, node.InboundTag)
	}
}

// deleteRemoteRoutedOutbound:routed 节点删除时清掉服务器侧的 routing rule + outbound + inbound 内 admin/sub clients。
// 同 outboundTag 的 rule 可能不止一条(理论上 sync 单一对一,防御性地全删);outbound 按 tag 删一次。
// inbound 内的占位 client(admin 占位 + 全部 sub 子账号)对称 routed_outbound.create 的 add client 步骤,
// 不清会污染 inbound clients(后续重建会 dup,且数据冗余)。
func (h *nodesHandler) deleteRemoteRoutedOutbound(ctx context.Context, serverName, outboundTag, inboundTag, adminEmail string, nodeID int64) {
	if h.remoteManage == nil {
		return
	}
	server, err := h.repo.GetRemoteServerByName(ctx, serverName)
	if err != nil {
		log.Printf("[Nodes] routed delete: lookup server %q failed: %v", serverName, err)
		return
	}
	// 1. routing rules by outboundTag(全删,从后往前避免 index 漂移)
	if raw, err := h.remoteManage.forwardToRemoteServer(ctx, server.ID, "GET", "/api/child/routing", nil); err == nil {
		var resp struct {
			Success bool                   `json:"success"`
			Routing map[string]interface{} `json:"routing"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.Routing != nil {
			rules, _ := resp.Routing["rules"].([]interface{})
			for i := len(rules) - 1; i >= 0; i-- {
				rmap, _ := rules[i].(map[string]interface{})
				if t, _ := rmap["outboundTag"].(string); t == outboundTag {
					body, _ := json.Marshal(map[string]interface{}{"action": "remove_rule", "index": i})
					if _, err := h.remoteManage.forwardToRemoteServer(ctx, server.ID, "POST", "/api/child/routing", body); err != nil {
						log.Printf("[Nodes] routed delete: remove rule (server=%s tag=%s idx=%d) failed: %v", serverName, outboundTag, i, err)
					}
				}
			}
		}
	}
	// 2. outbound by tag
	rmOut, _ := json.Marshal(map[string]string{"action": "remove", "tag": outboundTag})
	if _, err := h.remoteManage.forwardToRemoteServer(ctx, server.ID, "POST", "/api/child/outbounds", rmOut); err != nil {
		log.Printf("[Nodes] routed delete: remove outbound (server=%s tag=%s) failed: %v", serverName, outboundTag, err)
	} else {
		log.Printf("[Nodes] routed delete: cleared rule+outbound %s on %s", outboundTag, serverName)
	}
	// 3. 清 inbound 内 admin/sub 占位 client(对称 routed_outbound.create:194-207)
	if inboundTag != "" {
		subaccs, _ := h.repo.ListSubaccountsByRoutedNode(ctx, nodeID)
		for _, sa := range subaccs {
			if sa.Email != "" {
				if err := removeClientFromInbound(ctx, h.remoteManage, server.ID, inboundTag, sa.Email); err != nil {
					log.Printf("[Nodes] routed delete: remove sub client (server=%s inbound=%s email=%s) failed: %v", serverName, inboundTag, sa.Email, err)
				}
			}
		}
		if adminEmail != "" {
			if err := removeClientFromInbound(ctx, h.remoteManage, server.ID, inboundTag, adminEmail); err != nil {
				log.Printf("[Nodes] routed delete: remove admin client (server=%s inbound=%s email=%s) failed: %v", serverName, inboundTag, adminEmail, err)
			}
		}
	}
}

// outboundTargetsAddr 判断一个 xray outbound 的目标地址是否落在 addrSet 且端口为 port。
// 兼容 vless/vmess(settings.vnext[])与 trojan/ss/anytls/...(settings.servers[])两种结构。
func outboundTargetsAddr(ob map[string]any, addrSet map[string]bool, port int) bool {
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return false
	}
	check := func(arrKey string) bool {
		arr, _ := settings[arrKey].([]interface{})
		for _, e := range arr {
			em, _ := e.(map[string]any)
			if em == nil {
				continue
			}
			addr, _ := em["address"].(string)
			if !addrSet[addr] {
				continue
			}
			p := 0
			switch v := em["port"].(type) {
			case float64:
				p = int(v)
			case int:
				p = v
			}
			if p == port {
				return true
			}
		}
		return false
	}
	return check("vnext") || check("servers")
}

// cleanupOutboundsTargetingNode 删节点 B 时,扫所有 connected 服务器的 xray outbounds,
// 凡目标地址 == B 的地址(B.clash server / B 所属 server 的 ip·域名·pull_address)且端口 == B 端口,
// 视为「以 B 为出口的出站」(landing/user/routed 三种来源统一覆盖)→ 删该 outbound + 引用其 tag 的 routing rule。
func (h *nodesHandler) cleanupOutboundsTargetingNode(ctx context.Context, node *storage.Node) {
	if node == nil {
		return
	}
	// 委托批量版:单删也享受「每台服务器只 GET 一次 + 并发 + 短超时」,避免单节点也要串行卡所有服务器。
	h.cleanupOutboundsTargetingNodes(ctx, []storage.Node{*node})
}

// outboundTarget 一个待删节点的落地地址集 + 端口,用于比对 agent 出站是否指向它。
type outboundTarget struct {
	addrSet map[string]bool
	port    int
}

// cleanupOutboundsTargetingNodes 批量清理「以这些节点为落地出口」的 agent 出站 + 引用它们的 routing rule。
//
// 关键:一台服务器的出站列表在整批删除期间不变,故对每台 connected 服务器**只 GET 一次** outbounds,
// 在内存里比对**所有**待删节点。相比旧的「每节点都遍历所有服务器」,远程调用从 O(N节点×M服务器) 降到 O(M服务器)。
// 每台并发 + 短超时:单台慢/不可达(WS RPC 超时→HTTP 兜底)不再拖垮整批(旧实现下 N×M×30s = 几分钟并超时失败)。
// 尽力而为:超时/失败即跳过,残留的失效出站无害(指向已删地址),后续可手动或重连时清理。
func (h *nodesHandler) cleanupOutboundsTargetingNodes(ctx context.Context, nodes []storage.Node) {
	if h.remoteManage == nil || len(nodes) == 0 {
		return
	}

	// 为每个节点算出 (addrSet, port);addrSet 空或 port==0 的节点无从比对,跳过。
	targets := make([]outboundTarget, 0, len(nodes))
	for i := range nodes {
		node := &nodes[i]
		var clash map[string]any
		if json.Unmarshal([]byte(node.ClashConfig), &clash) != nil {
			continue
		}
		port := 0
		switch v := clash["port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		}
		if port == 0 {
			continue
		}
		addrSet := map[string]bool{}
		if s, _ := clash["server"].(string); strings.TrimSpace(s) != "" {
			addrSet[s] = true
		}
		if node.OriginalServer != "" {
			if srv, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer); err == nil && srv != nil {
				for _, a := range []string{srv.IPAddress, srv.Domain, srv.PullAddress} {
					if a = strings.TrimSpace(a); a != "" {
						addrSet[a] = true
					}
				}
			}
		}
		if len(addrSet) == 0 {
			continue
		}
		targets = append(targets, outboundTarget{addrSet: addrSet, port: port})
	}
	if len(targets) == 0 {
		return
	}

	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return
	}

	// 每台 connected 服务器只 GET 一次 outbounds,并发(上限 8)+ 短超时(尽力而为)。
	const scanTimeout = 8 * time.Second
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range servers {
		srv := servers[i]
		if srv.Status != storage.RemoteServerStatusConnected {
			continue // 离线服务器跳过,残留待其重连后另行处理
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(srv storage.RemoteServer) {
			defer wg.Done()
			defer func() { <-sem }()

			sctx, cancel := context.WithTimeout(ctx, scanTimeout)
			raw, err := h.remoteManage.forwardToRemoteServer(sctx, srv.ID, "GET", "/api/child/outbounds", nil)
			cancel()
			if err != nil {
				return
			}
			var resp struct {
				Success   bool             `json:"success"`
				Outbounds []map[string]any `json:"outbounds"`
			}
			if json.Unmarshal(raw, &resp) != nil {
				return
			}
			for _, ob := range resp.Outbounds {
				tag, _ := ob["tag"].(string)
				if tag == "" {
					continue
				}
				for _, t := range targets {
					if outboundTargetsAddr(ob, t.addrSet, t.port) {
						h.removeOutboundAndRules(ctx, srv.ID, srv.Name, tag)
						break // 该出站已命中并删除,不再比对其它 target
					}
				}
			}
		}(srv)
	}
	wg.Wait()
}

// removeOutboundAndRules 删指定 server 上的 outbound(by tag)+ 所有引用该 outboundTag 的 routing rule
// (逆序删避免 index 漂移,复用 deleteRemoteRoutedOutbound 同款范式)+ best-effort 删 user_outbounds 行。
func (h *nodesHandler) removeOutboundAndRules(ctx context.Context, serverID int64, serverName, tag string) {
	if raw, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/routing", nil); err == nil {
		var resp struct {
			Success bool                   `json:"success"`
			Routing map[string]interface{} `json:"routing"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.Routing != nil {
			rules, _ := resp.Routing["rules"].([]interface{})
			for i := len(rules) - 1; i >= 0; i-- {
				rmap, _ := rules[i].(map[string]interface{})
				if t, _ := rmap["outboundTag"].(string); t == tag {
					body, _ := json.Marshal(map[string]interface{}{"action": "remove_rule", "index": i})
					if _, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", body); err != nil {
						log.Printf("[Nodes] cleanup outbound-target: remove rule (server=%s tag=%s idx=%d) failed: %v", serverName, tag, i, err)
					}
				}
			}
		}
	}
	rmOut, _ := json.Marshal(map[string]string{"action": "remove", "tag": tag})
	if _, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", rmOut); err != nil {
		log.Printf("[Nodes] cleanup outbound-target: remove outbound (server=%s tag=%s) failed: %v", serverName, tag, err)
	} else {
		log.Printf("[Nodes] cleanup outbound-target: removed outbound+rules %s on %s (targets deleted node)", tag, serverName)
	}
	_ = h.repo.DeleteUserOutboundByServerTag(ctx, serverID, tag)
}

func (h *nodesHandler) deleteRemoteInbound(ctx context.Context, serverName, inboundTag string) {
	if h.remoteManage == nil {
		return
	}

	server, err := h.repo.GetRemoteServerByName(ctx, serverName)
	if err != nil {
		log.Printf("[Nodes] Failed to find remote server %q for inbound cleanup: %v", serverName, err)
		return
	}

	// Serialize the pre-delete snapshot, delete and any dependent Reality/WSS
	// repair with managed inbound creation on the same server. The snapshot is
	// required because the Agent cannot classify the inbound after it is gone.
	lock := wssServerLock(server.ID)
	lock.Lock()
	defer lock.Unlock()
	realityDomains, removedInboundWasWSS, stateErr := h.remoteManage.getInboundRemovalSyncState(ctx, server.ID, inboundTag)
	if stateErr != nil {
		log.Printf("[Nodes] Failed to snapshot remote inbound %s on server %s before deletion: %v", inboundTag, serverName, stateErr)
	}

	body, _ := json.Marshal(map[string]string{
		"action": "remove",
		"tag":    inboundTag,
	})

	if _, err := h.remoteManage.forwardToRemoteServer(ctx, server.ID, "POST", "/api/child/inbounds", body); err != nil {
		log.Printf("[Nodes] Failed to delete remote inbound %s on server %s: %v", inboundTag, serverName, err)
		return
	}
	log.Printf("[Nodes] Deleted remote inbound %s on server %s", inboundTag, serverName)

	if stateErr != nil {
		// Do not guess after deletion. An unconditional WSS rewrite here can
		// disturb unrelated nginx sites when the removed inbound was plain WS.
		return
	}
	if len(realityDomains) > 0 {
		if err := h.remoteManage.restoreTunnelRouteForReality(ctx, server.ID, realityDomains); err != nil {
			log.Printf("[Nodes] Restore Reality route after delete inbound %s on server=%d failed: %v", inboundTag, server.ID, err)
		}
	}
	if removedInboundWasWSS {
		if err := h.remoteManage.SyncWSSNginx(ctx, server.ID); err != nil {
			log.Printf("[Nodes] SyncWSSNginx after delete inbound %s on server=%d failed: %v", inboundTag, server.ID, err)
		}
	}
}

func (h *nodesHandler) handleBatchRename(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	var req struct {
		Updates []struct {
			NodeID  int64  `json:"node_id"`
			NewName string `json:"new_name"`
		} `json:"updates"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if len(req.Updates) == 0 {
		writeBadRequest(w, "更新列表不能为空")
		return
	}

	isAdmin := userIsAdmin(r.Context(), h.repo, username)

	successCount := 0
	failCount := 0
	var updatedNodes []nodeDTO
	var yamlUpdates []NodeUpdate // 收集 YAML 同步更新

	for _, update := range req.Updates {
		if update.NewName == "" {
			failCount++
			continue
		}

		// 获取现有节点(按权限:管理员任意,普通用户仅自己的)
		node, err := h.fetchNodeForAccess(r.Context(), update.NodeID, username, isAdmin)
		if err != nil {
			failCount++
			continue
		}

		// 保存 YAML 同步的旧名称
		oldNodeName := node.NodeName

		// 更新节点名称
		node.NodeName = update.NewName

		// 更新 ClashConfig JSON 中的名称
		var clashConfig map[string]any
		if err := json.Unmarshal([]byte(node.ClashConfig), &clashConfig); err == nil {
			clashConfig["name"] = update.NewName
			if updatedClash, err := json.Marshal(clashConfig); err == nil {
				node.ClashConfig = string(updatedClash)
			}
		}

		// 更新 ParsedConfig JSON 中的名称
		var parsedConfig map[string]any
		if err := json.Unmarshal([]byte(node.ParsedConfig), &parsedConfig); err == nil {
			parsedConfig["name"] = update.NewName
			if updatedParsed, err := json.Marshal(parsedConfig); err == nil {
				node.ParsedConfig = string(updatedParsed)
			}
		}

		// 保存到数据库
		updated, err := h.repo.UpdateNode(r.Context(), node)
		if err != nil {
			failCount++
			continue
		}

		// 收集 YAML 同步更新（不立即同步）
		if updated.ClashConfig != "" {
			yamlUpdates = append(yamlUpdates, NodeUpdate{
				OldName:         oldNodeName,
				NewName:         update.NewName,
				ClashConfigJSON: updated.ClashConfig,
			})
		}

		successCount++
		updatedNodes = append(updatedNodes, convertNode(updated))
	}

	// 批量同步到 YAML 文件（只读写文件一次）
	if len(yamlUpdates) > 0 {
		if err := h.yamlSyncManager.BatchSyncNodes(yamlUpdates); err != nil {
			// 记录错误但不要使请求失败
			logger.Info("[批量重命名] YAML 同步失败", "error", err)
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status":  "renamed",
		"success": successCount,
		"failed":  failCount,
		"total":   len(req.Updates),
		"nodes":   updatedNodes,
	})
}

type nodeRequest struct {
	RawURL       string `json:"raw_url"`
	NodeName     string `json:"node_name"`
	Protocol     string `json:"protocol"`
	ParsedConfig string `json:"parsed_config"`
	ClashConfig  string `json:"clash_config"`
	Enabled      bool   `json:"enabled"`
	Tag          string `json:"tag"`
	// Tags 多标签数组 — 前端 multi-select 输出。storage.serializeNodeTags 会自动把 Tag 与 Tags 同步,
	// 任一字段为空都会用另一个兜底,所以老前端只发 Tag 也能正常工作。
	Tags                []string        `json:"tags,omitempty"`
	InboundTag          string          `json:"inbound_tag"`
	ChainProxyNodeID    *int64          `json:"-"`
	RawChainProxyNodeID json.RawMessage `json:"chain_proxy_node_id"`
	// 中转(relay):创建时若填写中转服务器,后端把 clash/parsed 的 server/port 换成中转地址,原值记到 relay_orig_*。
	RelayServer string `json:"relay_server"`
	RelayPort   int    `json:"relay_port"`
}

func (r *nodeRequest) hasChainProxyNodeID() bool {
	return r.RawChainProxyNodeID != nil
}

func (r *nodeRequest) parseChainProxyNodeID() {
	if r.RawChainProxyNodeID == nil || string(r.RawChainProxyNodeID) == "null" {
		r.ChainProxyNodeID = nil
		return
	}
	var id int64
	if json.Unmarshal(r.RawChainProxyNodeID, &id) == nil {
		r.ChainProxyNodeID = &id
	}
}

type nodeDTO struct {
	ID           int64  `json:"id"`
	RawURL       string `json:"raw_url"`
	NodeName     string `json:"node_name"`
	Protocol     string `json:"protocol"`
	ParsedConfig string `json:"parsed_config"`
	ClashConfig  string `json:"clash_config"`
	Enabled      bool   `json:"enabled"`
	// Tag 是用户自定义分类标签(VIP / Asia / 测试),前端节点页用它做过滤、分组显示、批量更新。
	// 必须下发,否则前端改了 tag 拉回来缺字段,显示永远是原状态,等同"修改不起作用"。
	Tag string `json:"tag"`
	// Tags 多标签数组;Tag 是 Tags[0] 的别名(向后兼容)。前端优先读 tags,fallback 用 tag。
	Tags              []string `json:"tags,omitempty"`
	OriginalServer    string   `json:"original_server"`
	OriginalDomain    string   `json:"original_domain"`
	InboundTag        string   `json:"inbound_tag"`
	ChainProxyNodeID  *int64   `json:"chain_proxy_node_id"`
	NodeType          string   `json:"node_type"`              // 'physical' | 'routed'
	ParentNodeID      *int64   `json:"parent_node_id"`         // routed 节点指向其父物理节点
	RoutedOutboundTag string   `json:"routed_outbound_tag"`    // routed 节点专用:绑定的出站 tag(便于 UI 直接展示)
	RoutedOwner       string   `json:"routed_owner,omitempty"` // routed 节点专用:'shared'(admin 套餐分配) | 'user'(用户私有)
	CreatedBy         string   `json:"created_by,omitempty"`   // routed 节点专用:创建者用户名(user 视角下用于鉴别"是不是我创建的")
	// Multiplier 仅在普通用户视角(其绑定套餐内有 NodeMultipliers 配置)下注入。admin 视角省略字段
	// (一个节点可能在多个套餐里有不同倍率,无法单值显示);== 1 时也省略,前端按"未设置"对待。
	Multiplier float64 `json:"multiplier,omitempty"`
	// 中转(relay):relay_orig_server 非空表示该节点已配置中转 —— clash server/port 是中转地址,
	// 这两个字段是被中转替换掉的原服务器地址/端口,前端在「服务器地址」下方显示 + 用于编辑/取消中转。
	RelayOrigServer string    `json:"relay_orig_server,omitempty"`
	RelayOrigPort   int       `json:"relay_orig_port,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type nodeURIItem struct {
	Username string `json:"username"`
	NodeID   int64  `json:"node_id"`
	NodeName string `json:"node_name"`
	Protocol string `json:"protocol"`
	NodeType string `json:"node_type"`
	URI      string `json:"uri"`
}

func makeNodeURIItem(username string, node storage.Node, producer *substore.URIProducer) (nodeURIItem, error) {
	if strings.TrimSpace(node.ClashConfig) == "" {
		return nodeURIItem{}, errors.New("当前节点没有可用于生成二维码的客户端配置")
	}
	var proxy map[string]any
	if err := json.Unmarshal([]byte(node.ClashConfig), &proxy); err != nil {
		return nodeURIItem{}, errors.New("当前节点的客户端配置格式无效")
	}
	protocol, _ := proxy["type"].(string)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = strings.ToLower(strings.TrimSpace(node.Protocol))
		proxy["type"] = protocol
	}
	// Clash 使用 socks，URI producer 使用 socks5；两者表示同一协议。
	if protocol == "socks" {
		protocol = "socks5"
		proxy["type"] = protocol
	}
	uri, err := producer.ProduceOne(substore.Proxy(proxy))
	if err != nil || strings.TrimSpace(uri) == "" {
		label := strings.ToUpper(strings.TrimSpace(node.Protocol))
		if label == "" {
			label = "当前协议"
		}
		return nodeURIItem{}, fmt.Errorf("%s 暂不支持生成单节点分享二维码", label)
	}
	return nodeURIItem{
		Username: username,
		NodeID:   node.ID,
		NodeName: node.NodeName,
		Protocol: node.Protocol,
		NodeType: node.NodeType,
		URI:      uri,
	}, nil
}

// NewNodeURIsHandler GET /api/admin/node-uris(admin):返回 每个用户 × 其可见节点 的成品分享 URI。
// 凭据用各用户子账户填充(substituteNodesForUser),URI 由后端 substore.URIProducer 生成 —— 不走前端。
func NewNodeURIsHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		users, err := repo.ListUsers(ctx, 10000)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		prod := substore.NewURIProducer()
		items := make([]nodeURIItem, 0)
		for _, u := range users {
			nodes, nerr := collectUserVisibleNodes(ctx, repo, u.Username)
			if nerr != nil {
				continue
			}
			// 注入该用户凭据;routed 无 active 子账号的节点会被过滤掉(只留用户有权的)。
			nodes = substituteNodesForUser(ctx, repo, u.Username, nodes)
			for _, n := range nodes {
				if strings.TrimSpace(n.ClashConfig) == "" {
					continue
				}
				item, perr := makeNodeURIItem(u.Username, n, prod)
				if perr != nil {
					continue
				}
				items = append(items, item)
			}
		}
		respondJSON(w, http.StatusOK, map[string]any{"items": items})
	})
}

func convertNode(node storage.Node) nodeDTO {
	return nodeDTO{
		ID:                node.ID,
		RawURL:            node.RawURL,
		NodeName:          node.NodeName,
		Protocol:          node.Protocol,
		ParsedConfig:      node.ParsedConfig,
		ClashConfig:       node.ClashConfig,
		Enabled:           node.Enabled,
		Tag:               node.Tag,
		Tags:              node.Tags,
		OriginalServer:    node.OriginalServer,
		OriginalDomain:    node.OriginalDomain,
		InboundTag:        node.InboundTag,
		ChainProxyNodeID:  node.ChainProxyNodeID,
		NodeType:          node.NodeType,
		ParentNodeID:      node.ParentNodeID,
		RoutedOutboundTag: node.RoutedOutboundTag,
		RoutedOwner:       node.RoutedOwner,
		CreatedBy:         node.Username, // nodes 表里 username = 创建/拥有者
		RelayOrigServer:   node.RelayOrigServer,
		RelayOrigPort:     node.RelayOrigPort,
		CreatedAt:         node.CreatedAt,
		UpdatedAt:         node.UpdatedAt,
	}
}

func convertNodes(nodes []storage.Node) []nodeDTO {
	result := make([]nodeDTO, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, convertNode(node))
	}
	return result
}

func (h *nodesHandler) handleFetchSubscription(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	var req struct {
		URL               string `json:"url"`
		UserAgent         string `json:"user_agent"`
		ForceNodeSkipCert bool   `json:"force_node_skip_cert"` // 是否给每个导入节点强制写 skip-cert-verify（默认 false，不污染）
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.URL == "" {
		writeBadRequest(w, "订阅URL是必填项")
		return
	}

	// 如果没有提供 User-Agent，使用默认值
	userAgent := req.UserAgent
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}

	// 创建HTTP客户端并获取订阅内容
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("无效的订阅URL"))
		return
	}

	// 添加User-Agent头
	httpReq.Header.Set("User-Agent", userAgent)

	logger.Info("[订阅获取] 开始请求外部订阅", "url", req.URL, "user_agent", userAgent)

	resp, err := client.Do(httpReq)
	if err != nil {
		logger.Info("[订阅获取] 请求失败", "url", req.URL, "error", err)
		writeError(w, http.StatusBadRequest, errors.New("无法获取订阅内容: "+err.Error()))
		return
	}
	defer resp.Body.Close()

	logger.Info("[订阅获取] 收到响应",
		"url", req.URL,
		"status_code", resp.StatusCode,
		"status", resp.Status,
		"content_type", resp.Header.Get("Content-Type"),
		"content_length", resp.ContentLength)

	// 读取响应内容（无论成功还是失败都需要读取以便记录日志）
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Info("[订阅获取] 读取响应体失败", "url", req.URL, "error", err)
		writeError(w, http.StatusInternalServerError, errors.New("读取订阅内容失败"))
		return
	}

	logger.Info("[订阅获取] 响应体大小", "url", req.URL, "size", len(body))

	if resp.StatusCode != http.StatusOK {
		// 记录详细的错误响应内容
		bodyPreview := string(body)
		if len(bodyPreview) > 500 {
			bodyPreview = bodyPreview[:500] + "...(截断)"
		}
		logger.Info("[订阅获取] 服务器返回错误状态",
			"url", req.URL,
			"status_code", resp.StatusCode,
			"status", resp.Status,
			"response_preview", bodyPreview)
		writeError(w, http.StatusBadRequest, fmt.Errorf("订阅服务器返回错误状态: %d %s", resp.StatusCode, resp.Status))
		return
	}

	// 预处理(base64 / v2ray URI 列表 → 经 proxyparser 统一解析为 proxies YAML)
	if pre, perr := preprocessSubscriptionContent(body); perr == nil {
		body = pre
	}

	// 解析YAML
	var clashConfig struct {
		Proxies []map[string]any `yaml:"proxies"`
	}

	if err := yaml.Unmarshal(body, &clashConfig); err != nil {
		// 记录解析失败时的内容预览
		bodyPreview := string(body)
		if len(bodyPreview) > 500 {
			bodyPreview = bodyPreview[:500] + "...(截断)"
		}
		logger.Info("[订阅获取] YAML解析失败", "url", req.URL, "error", err, "content_preview", bodyPreview)
		writeError(w, http.StatusBadRequest, errors.New("解析订阅内容失败: "+err.Error()))
		return
	}

	if len(clashConfig.Proxies) == 0 {
		// 记录没有找到节点时的内容预览
		bodyPreview := string(body)
		if len(bodyPreview) > 500 {
			bodyPreview = bodyPreview[:500] + "...(截断)"
		}
		logger.Info("[订阅获取] 订阅中没有找到代理节点", "url", req.URL, "content_preview", bodyPreview)
		writeError(w, http.StatusBadRequest, errors.New("订阅中没有找到代理节点"))
		return
	}

	logger.Info("[订阅获取] 成功解析订阅", "url", req.URL, "node_count", len(clashConfig.Proxies))

	// 将 nil 值转换为空字符串并解码所有代理中的 URL 编码字段
	for _, proxy := range clashConfig.Proxies {
		convertNilToEmptyStringInMap(proxy)
		decodeProxyURLFields(proxy)
		if req.ForceNodeSkipCert {
			proxy["skip-cert-verify"] = true
		}
	}

	// 从 Content-Disposition 头中提取订阅名称作为建议的标签
	suggestedTag := ""
	contentDisposition := resp.Header.Get("Content-Disposition")
	if contentDisposition != "" {
		suggestedTag = parseFilenameFromContentDisposition(contentDisposition)
		// 移除文件扩展名
		if suggestedTag != "" {
			suggestedTag = strings.TrimSuffix(suggestedTag, ".yaml")
			suggestedTag = strings.TrimSuffix(suggestedTag, ".yml")
			suggestedTag = strings.TrimSuffix(suggestedTag, ".txt")
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"proxies":       clashConfig.Proxies,
		"count":         len(clashConfig.Proxies),
		"suggested_tag": suggestedTag,
	})
}

// handleParseURIs 解析前端粘贴的节点文本,返回 clash 节点。
// 支持:Clash YAML(整份含 proxies: / 裸 `- name:` 列表 / 单条 {name:...})、多行 URI 链接、base64 订阅文本、
// Surge INI 行。前端直接把原始粘贴内容发来,由 parsePastedProxies 统一识别格式。
func (h *nodesHandler) handleParseURIs(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}
	var req struct {
		Content           string `json:"content"`
		ForceNodeSkipCert bool   `json:"force_node_skip_cert"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeBadRequest(w, "内容不能为空")
		return
	}
	proxies := parsePastedProxies(req.Content)
	if len(proxies) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("解析失败: 未识别到任何节点(支持 Clash YAML、URI 链接、base64 订阅文本)"))
		return
	}
	for _, proxy := range proxies {
		convertNilToEmptyStringInMap(proxy)
		decodeProxyURLFields(proxy)
		if req.ForceNodeSkipCert {
			proxy["skip-cert-verify"] = true
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"proxies": proxies,
		"count":   len(proxies),
	})
}

// parsePastedProxies 识别并解析"手动粘贴"的节点文本,返回 clash proxy 列表(map)。
// 顺序:①整份 Clash 配置 / base64 / URI 列表(复用订阅拉取同款 preprocess+yaml 管线)
//
//	②裸 `- name:` 列表(无 proxies: 头) ③单条 {name:...} ④proxyparser 兜底(URI/Surge INI)。
func parsePastedProxies(content string) []map[string]any {
	// ① preprocess 会把 base64 / URI 列表转成 proxies-YAML,整份 Clash 配置原样透传。
	body := []byte(content)
	if pre, perr := preprocessSubscriptionContent(body); perr == nil && len(pre) > 0 {
		body = pre
	}
	var full struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &full); err == nil && len(full.Proxies) > 0 {
		return full.Proxies
	}
	// ② 裸列表:用原始内容(避免 preprocess 干扰),`- name:` 序列直接解成 []map。
	var list []map[string]any
	if err := yaml.Unmarshal([]byte(content), &list); err == nil && len(list) > 0 && looksLikeProxy(list[0]) {
		return list
	}
	// ③ 单条代理:{name:..., type:..., server:...}
	var one map[string]any
	if err := yaml.Unmarshal([]byte(content), &one); err == nil && looksLikeProxy(one) {
		return []map[string]any{one}
	}
	// ④ 兜底:纯 URI / Surge INI(preprocess 未覆盖到的场景)
	if p, err := proxyparser.ParseSubscription(content); err == nil && len(p) > 0 {
		return p
	}
	return nil
}

// looksLikeProxy 判定一个 map 是否像 clash 代理节点(有 name 且有 type 或 server),
// 避免把任意 YAML map 误当节点。
func looksLikeProxy(m map[string]any) bool {
	if m == nil {
		return false
	}
	_, hasName := m["name"]
	_, hasType := m["type"]
	_, hasServer := m["server"]
	return hasName && (hasType || hasServer)
}

func (h *nodesHandler) handleListTags(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("用户未认证"))
		return
	}

	// 数据隔离:管理员看全部标签,普通用户只看自己节点的标签。
	var allNodes []storage.Node
	var err error
	if userIsAdmin(r.Context(), h.repo, username) {
		allNodes, err = h.repo.ListAllNodes(r.Context())
	} else {
		allNodes, err = h.repo.ListNodes(r.Context(), username)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	seen := make(map[string]bool)
	var tags []string
	for _, node := range allNodes {
		for _, t := range node.Tags {
			if t != "" && !seen[t] {
				seen[t] = true
				tags = append(tags, t)
			}
		}
	}
	if tags == nil {
		tags = []string{}
	}

	respondJSON(w, http.StatusOK, map[string]any{"tags": tags})
}
