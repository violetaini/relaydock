package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

// UserRoutedOutboundHandler 处理普通用户私有路由出站(routed_owner='user')的增删查。
//
// 与 admin 路径([routed_outbound.go])的差异:
//   - 鉴权:普通用户 token,不需要 admin 权限
//   - 不创建 admin 占位 client:rule.user 直接放调用者本人的子账号 email
//   - 节点 username/created_by 都是调用者本人,routed_owner='user'
//   - 删除时直接清 rule + outbound + 仅一个用户的 client(没有 admin 占位)
//   - 受配额限制 quota_routed_outbound(默认 2)
//
// 暂停/恢复:由 user 状态变更钩子(suspendUserRoutedOutbounds / resumeUserRoutedOutbounds)
// 触发,保留 outbound 配置,仅拆除/重建 rule+client,凭据保留在 user_subaccounts。
type UserRoutedOutboundHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
}

func NewUserRoutedOutboundHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler) *UserRoutedOutboundHandler {
	return &UserRoutedOutboundHandler{repo: repo, remoteManage: rm}
}

func (h *UserRoutedOutboundHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.list(w, r, username)
	case http.MethodPost:
		h.create(w, r, username)
	case http.MethodDelete:
		h.delete(w, r, username)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// GET /api/user/routed-outbound  列出当前用户私有路由出站
func (h *UserRoutedOutboundHandler) list(w http.ResponseWriter, r *http.Request, username string) {
	items, err := h.repo.ListUserRoutedOutbounds(r.Context(), username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("list: %v", err))
		return
	}
	// 同时回报配额 + 是否启用 + 今日操作次数,前端禁用按钮用
	used, _ := h.repo.CountUserRoutedOutbounds(r.Context(), username)
	usedToday, _ := h.repo.CountUserRoutedOutboundActionsToday(r.Context(), username)
	cfg := loadUserPermConfig(r.Context(), h.repo)
	respondJSON(w, http.StatusOK, map[string]any{
		"items":   sanitizeRoutedNodeDetailsForExternal(items),
		"enabled": cfg.RoutedOutboundEnabled,
		"quota":   map[string]int{"used": used, "max": cfg.QuotaRoutedOutbound},
		"daily":   map[string]int{"used": usedToday, "max": cfg.DailyLimitRoutedOutbound},
	})
}

type createUserRoutedReq struct {
	ParentNodeID int64                  `json:"parent_node_id"`
	TargetNodeID int64                  `json:"target_node_id"`
	Label        string                 `json:"label"`     // 可选,默认 "rout-<目标节点 slug>"
	Outbound     map[string]interface{} `json:"outbound"`  // 前端用 target node 的 clash_config 转出来,后端校验 server/port 一致
	NodeName     string                 `json:"node_name"` // 可选,默认 "<parent>-<label>"
}

// POST /api/user/routed-outbound  创建用户私有路由出站
func (h *UserRoutedOutboundHandler) create(w http.ResponseWriter, r *http.Request, username string) {
	ctx := r.Context()
	var req createUserRoutedReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ParentNodeID <= 0 || req.TargetNodeID <= 0 || req.Outbound == nil {
		writeJSONError(w, http.StatusBadRequest, "parent_node_id, target_node_id, outbound 都必填")
		return
	}

	// ====== 校验 ======
	// 1. 总配额(开关 + 上限)
	if err := checkUserQuota(ctx, h.repo, username, "routed_outbound"); err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	// 2. 每日操作次数(create + delete 之和):每次操作会触发 agent 重启 xray,频次受限。
	cfg := loadUserPermConfig(ctx, h.repo)
	if cfg.DailyLimitRoutedOutbound > 0 {
		usedToday, _ := h.repo.CountUserRoutedOutboundActionsToday(ctx, username)
		if usedToday >= cfg.DailyLimitRoutedOutbound {
			writeJSONError(w, http.StatusTooManyRequests,
				fmt.Sprintf("今日操作次数已达上限 (%d/%d),请明天再试", usedToday, cfg.DailyLimitRoutedOutbound))
			return
		}
	}

	// 3. 父节点:必须存在 + 物理节点 + 有 inbound_tag + 用户可见(在套餐里 / 是自己导入的)
	parent, err := h.repo.GetNodeByID(ctx, req.ParentNodeID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("父节点不存在: %v", err))
		return
	}
	if parent.NodeType != "" && parent.NodeType != "physical" {
		writeJSONError(w, http.StatusBadRequest, "父节点必须是物理节点")
		return
	}
	if strings.TrimSpace(parent.OriginalServer) == "" || strings.TrimSpace(parent.InboundTag) == "" {
		writeJSONError(w, http.StatusBadRequest, "父节点缺少 original_server 或 inbound_tag")
		return
	}
	if !h.userCanSeeNode(ctx, username, parent.ID) {
		writeJSONError(w, http.StatusForbidden, "无权访问该父节点")
		return
	}

	// 4. 目标节点:必须存在 + 用户可见 + 不是链式 + 不是 routed
	target, err := h.repo.GetNodeByID(ctx, req.TargetNodeID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("目标节点不存在: %v", err))
		return
	}
	if strings.Contains(target.Protocol, "⇋") {
		writeJSONError(w, http.StatusBadRequest, "目标不能是链式代理节点")
		return
	}
	if target.NodeType == "routed" {
		writeJSONError(w, http.StatusBadRequest, "目标不能是路由出站子节点")
		return
	}
	if !h.userCanSeeNode(ctx, username, target.ID) {
		writeJSONError(w, http.StatusForbidden, "无权访问该目标节点")
		return
	}

	// 5. Outbound 与 target_node 的 clash_config 必须 server/port 一致(防伪造)
	if err := verifyOutboundMatchesTarget(req.Outbound, target.ClashConfig); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("outbound 校验失败: %v", err))
		return
	}

	// 6. Label:用户没填 → 用目标节点名 slugify;然后整体 slug 校验
	rawLabel := strings.TrimSpace(req.Label)
	if rawLabel == "" {
		rawLabel = "rout-" + simpleSlug(target.NodeName)
	}
	if len(rawLabel) > 32 {
		rawLabel = rawLabel[:32]
	}
	labelSlug := slugify(rawLabel)
	if labelSlug == "" {
		writeJSONError(w, http.StatusBadRequest, "label 只能包含字母数字和短横线,长度 2-32")
		return
	}

	// 7. 同父节点 + 同用户 + 同 label 唯一性
	myExisting, _ := h.repo.ListUserRoutedOutbounds(ctx, username)
	shortID := fmt.Sprintf("p%d", parent.ID)
	outboundTag := fmt.Sprintf("routed:%s:u%s:%s", shortID, simpleSlug(username), labelSlug)
	marktag := outboundTag
	for _, ex := range myExisting {
		if ex.RoutedOutboundTag == outboundTag {
			writeJSONError(w, http.StatusConflict, fmt.Sprintf("已存在相同 label 的路由出站: %s", rawLabel))
			return
		}
	}

	// 8. 反查 server_id
	serverID, err := h.resolveServerIDByName(ctx, parent.OriginalServer)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("无法定位父节点所属 agent: %v", err))
		return
	}
	leasedCtx, release, ok := acquireRemoteServerMutationLeaseHTTP(w, h.repo, ctx, serverID)
	if !ok {
		return
	}
	defer release()
	ctx = leasedCtx

	// Re-read all server-bound inputs under the lease. The earlier reads only
	// discover/validate the request; they must not feed a remote transaction if
	// the parent was moved or the target changed while the lease was acquired.
	parent, err = h.repo.GetNodeByID(ctx, req.ParentNodeID)
	if err != nil || parent.InboundTag == "" || parent.OriginalServer == "" ||
		(parent.NodeType != "" && parent.NodeType != "physical") || !h.userCanSeeNode(ctx, username, req.ParentNodeID) {
		writeJSONError(w, http.StatusConflict, "父节点在创建期间发生变化,请重试")
		return
	}
	lockedServerID, err := h.resolveServerIDByName(ctx, parent.OriginalServer)
	if err != nil || lockedServerID != serverID {
		writeJSONError(w, http.StatusConflict, "父节点所属服务器在创建期间发生变化,请重试")
		return
	}
	target, err = h.repo.GetNodeByID(ctx, req.TargetNodeID)
	if err != nil || target.NodeType == "routed" || strings.Contains(target.Protocol, "⇋") ||
		!h.userCanSeeNode(ctx, username, req.TargetNodeID) {
		writeJSONError(w, http.StatusConflict, "目标节点在创建期间发生变化,请重试")
		return
	}
	if err := verifyOutboundMatchesTarget(req.Outbound, target.ClashConfig); err != nil {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("目标节点在创建期间发生变化: %v", err))
		return
	}
	myExisting, _ = h.repo.ListUserRoutedOutbounds(ctx, username)
	for _, ex := range myExisting {
		if ex.RoutedOutboundTag == outboundTag {
			writeJSONError(w, http.StatusConflict, fmt.Sprintf("已存在相同 label 的路由出站: %s", rawLabel))
			return
		}
	}

	// ====== 执行 ======
	// 用户子账号 email = `<username>__<short>__<label>`,cred 按父 inbound 协议正确生成主字段(参见 generateRoutedClientCred)
	userEmail := fmt.Sprintf("%s__%s__%s", username, shortID, labelSlug)
	userCred, _, err := generateRoutedClientCred(parent.Protocol, routedShadowsocksMethod(parent), userEmail)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("生成 client 凭据失败: %v", err))
		return
	}
	// VLESS Reality 需要继承父 inbound 第一个 client 的 flow
	flow, err := h.peekInboundFirstClientFlow(ctx, serverID, parent.InboundTag)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("读取父 inbound 失败: %v", err))
		return
	}
	if flow != "" {
		userCred["flow"] = flow
	}

	// 强制 outbound.tag
	outboundCopy := cloneMap(req.Outbound)
	outboundCopy["tag"] = outboundTag

	// === Step 1: 加用户子账号 client(幂等,没有 admin 占位)===
	// 同 routed_outbound.go Step 1:agent matchClientCredential 现在只看 primary key,
	// 同 email 不同 uuid 不再被去重 → 重复 add 后 xray "User already exists" 启动失败。
	pkField := primaryKeyFieldForProtocol(parent.Protocol)
	if existingUUID, existingFlow, perr := peekInboundClientByEmail(ctx, h.remoteManage, serverID, parent.InboundTag, userEmail); perr == nil && existingUUID != "" {
		log.Printf("[UserRoutedCreate] inbound %s already has client email=%s pk=%s — reusing", parent.InboundTag, userEmail, existingUUID)
		userCred[pkField] = existingUUID
		if existingFlow != "" {
			userCred["flow"] = existingFlow
		}
	} else if err := addClientToInbound(ctx, h.remoteManage, serverID, parent.InboundTag, userCred); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("加 client 失败: %v", err))
		return
	}

	// === Step 2: 加 outbound ===
	addOutBody, _ := json.Marshal(map[string]interface{}{"action": "add", "outbound": outboundCopy})
	addOutResponse, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", addOutBody)
	if err == nil {
		err = applyAgentConfigMutationACK(ctx, h.remoteManage, serverID, "UserRoutedOutboundAdd", addOutResponse)
	}
	if err != nil {
		removeClientFromInbound(ctx, h.remoteManage, serverID, parent.InboundTag, userEmail)
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("加 outbound 失败: %v", err))
		return
	}

	// === Step 3: 加 routing rule (user=[userEmail], 没有 admin 占位) ===
	rule := map[string]interface{}{
		"type":        "field",
		"marktag":     marktag,
		"user":        []string{userEmail},
		"inboundTag":  []string{parent.InboundTag},
		"outboundTag": outboundTag,
	}
	addRuleBody, _ := json.Marshal(map[string]interface{}{"action": "add_rule", "rule": rule})
	addRuleResponse, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", addRuleBody)
	if err == nil {
		err = applyAgentConfigMutationACK(ctx, h.remoteManage, serverID, "UserRoutedRuleAdd", addRuleResponse)
	}
	if err != nil {
		removeOutBody, _ := json.Marshal(map[string]string{"action": "remove", "tag": outboundTag})
		h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", removeOutBody)
		removeClientFromInbound(ctx, h.remoteManage, serverID, parent.InboundTag, userEmail)
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("加 routing rule 失败: %v", err))
		return
	}

	// === Step 4: 持久化 routed 节点 ===
	parentID := parent.ID
	nodeName := strings.TrimSpace(req.NodeName)
	if nodeName == "" {
		nodeName = fmt.Sprintf("%s-%s", parent.NodeName, rawLabel)
	}
	clashWithUser := cloneClashWithCredential(parent.ClashConfig, parent.Protocol, userCred, nodeName)
	parsedWithUser, _, _, _ := sanitizeManagedShadowsocksConfig(parent.ParsedConfig)
	outboundJSONBytes, _ := json.Marshal(outboundCopy)
	credBytes, _ := json.Marshal(userCred)
	detail := storage.RoutedNodeDetail{
		Node: storage.Node{
			Username:       username, // 属于创建者,节点管理页只有他能看到
			RawURL:         parent.RawURL,
			NodeName:       nodeName,
			Protocol:       parent.Protocol,
			ParsedConfig:   parsedWithUser,
			ClashConfig:    clashWithUser,
			Enabled:        true,
			Tag:            "路由出站",
			OriginalServer: parent.OriginalServer,
			OriginalDomain: parent.OriginalDomain,
			InboundTag:     parent.InboundTag,
			NodeType:       "routed",
			ParentNodeID:   &parentID,
			RoutedOwner:    "user",
		},
		RoutedOutboundTag:     outboundTag,
		RoutedOutboundJSON:    string(outboundJSONBytes),
		RoutedRuleMarktag:     marktag,
		RoutedAdminEmail:      "", // 用户路径无 admin 占位
		RoutedAdminCredential: "",
	}
	created, err := h.repo.CreateRoutedNode(ctx, detail)
	if err != nil {
		rollbackRoutedOutboundCreate(ctx, h.remoteManage, serverID, parent.InboundTag, marktag, outboundTag, userEmail)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("DB 写入失败,远端变更已回滚: %v", err))
		return
	}
	created = sanitizeRoutedNodeDetailForExternal(created)

	// 写 user_subaccounts(凭据存档,暂停/续费用得上)
	if _, err := h.repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username:       username,
		RoutedNodeID:   created.ID,
		Email:          userEmail,
		CredentialJSON: string(credBytes),
		IsActive:       true,
	}); err != nil {
		rollbackRoutedOutboundCreate(ctx, h.remoteManage, serverID, parent.InboundTag, marktag, outboundTag, userEmail)
		if deleteErr := h.repo.DeleteRoutedNode(ctx, created.ID); deleteErr != nil {
			log.Printf("[UserRoutedOutbound] rollback DB node %d failed: %v", created.ID, deleteErr)
		}
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("保存用户凭据失败,远端变更已回滚: %v", err))
		return
	}

	// 记录每日操作次数(成功路径才计数,失败/校验拒绝不计)
	if err := h.repo.LogUserRoutedOutboundAction(ctx, username, "create"); err != nil {
		log.Printf("[UserRoutedOutbound] LogAction create failed (continue): %v", err)
	}

	log.Printf("[UserRoutedOutbound] created routed node id=%d tag=%s user=%s parent=%d", created.ID, outboundTag, username, parent.ID)
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "node": created})
}

// DELETE /api/user/routed-outbound?id=X  删除自己的路由出站
func (h *UserRoutedOutboundHandler) delete(w http.ResponseWriter, r *http.Request, username string) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "id 必填")
		return
	}
	detail, err := h.repo.GetRoutedNodeDetail(ctx, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("节点不存在: %v", err))
		return
	}
	if detail.RoutedOwner != "user" || detail.Username != username {
		writeJSONError(w, http.StatusForbidden, "只能删除自己创建的路由出站")
		return
	}

	// 每日操作次数限制(删除也会触发 agent 重启 xray,所以同样受限)
	cfg := loadUserPermConfig(ctx, h.repo)
	if cfg.DailyLimitRoutedOutbound > 0 {
		usedToday, _ := h.repo.CountUserRoutedOutboundActionsToday(ctx, username)
		if usedToday >= cfg.DailyLimitRoutedOutbound {
			writeJSONError(w, http.StatusTooManyRequests,
				fmt.Sprintf("今日操作次数已达上限 (%d/%d),请明天再试", usedToday, cfg.DailyLimitRoutedOutbound))
			return
		}
	}

	serverID, err := h.resolveServerIDByName(ctx, detail.OriginalServer)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("无法定位 Agent: %v", err))
		return
	}
	leasedCtx, release, ok := acquireRemoteServerMutationLeaseHTTP(w, h.repo, ctx, serverID)
	if !ok {
		return
	}
	defer release()
	ctx = leasedCtx
	detail, err = h.repo.GetRoutedNodeDetail(ctx, id)
	if err != nil || detail.RoutedOwner != "user" || detail.Username != username {
		writeJSONError(w, http.StatusConflict, "节点在删除期间发生变化,请重试")
		return
	}
	lockedServerID, err := h.resolveServerIDByName(ctx, detail.OriginalServer)
	if err != nil || lockedServerID != serverID {
		writeJSONError(w, http.StatusConflict, "节点所属服务器在删除期间发生变化,请重试")
		return
	}
	if err := removeRuleByMarktag(ctx, h.remoteManage, serverID, detail.RoutedRuleMarktag); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("删除 routing rule 失败: %v", err))
		return
	}
	rmOutBody, _ := json.Marshal(map[string]string{"action": "remove", "tag": detail.RoutedOutboundTag})
	rmOutResponse, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", rmOutBody)
	if err == nil {
		err = applyAgentConfigMutationACK(ctx, h.remoteManage, serverID, "UserRoutedOutboundRemove", rmOutResponse)
	}
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("删除 outbound 失败: %v", err))
		return
	}
	subaccs, _ := h.repo.ListSubaccountsByRoutedNode(ctx, id)
	for _, sa := range subaccs {
		if err := removeClientFromInbound(ctx, h.remoteManage, serverID, detail.InboundTag, sa.Email); err != nil {
			writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("删除 client 失败: %v", err))
			return
		}
	}

	if err := h.repo.DeleteRoutedNode(ctx, id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("DB 删除失败: %v", err))
		return
	}
	if err := h.repo.LogUserRoutedOutboundAction(ctx, username, "delete"); err != nil {
		log.Printf("[UserRoutedOutbound] LogAction delete failed (continue): %v", err)
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ===== helpers =====

func (h *UserRoutedOutboundHandler) resolveServerIDByName(ctx context.Context, serverName string) (int64, error) {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return 0, err
	}
	for _, s := range servers {
		if s.Name == serverName {
			return s.ID, nil
		}
	}
	return 0, errors.New("server not found: " + serverName)
}

func (h *UserRoutedOutboundHandler) peekInboundFirstClientFlow(ctx context.Context, serverID int64, inboundTag string) (string, error) {
	result, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return "", err
	}
	for _, ib := range resp.Inbounds {
		if tag, _ := ib["tag"].(string); tag != inboundTag {
			continue
		}
		settings, _ := ib["settings"].(map[string]interface{})
		if settings == nil {
			return "", nil
		}
		clients, _ := settings["clients"].([]interface{})
		if len(clients) == 0 {
			return "", nil
		}
		first, _ := clients[0].(map[string]interface{})
		flow, _ := first["flow"].(string)
		return flow, nil
	}
	return "", fmt.Errorf("inbound %s not found", inboundTag)
}

// userCanSeeNode 判断用户能否在节点管理页看到该节点。
// 命中任一即视为可见:
//   - 节点 username = 调用者(自己导入的)
//   - 节点通过套餐分配到用户(GetUserPackageNodes / 类似查询)
//   - 节点是该用户的 routed 子节点
//
// 父节点要求"用户可见"是因为路由出站会改父 inbound 配置 — 用户对没分配的节点不应有这种能力。
func (h *UserRoutedOutboundHandler) userCanSeeNode(ctx context.Context, username string, nodeID int64) bool {
	// 1. 自己的节点
	if _, err := h.repo.GetNode(ctx, nodeID, username); err == nil {
		return true
	}
	// 2. 套餐分配的节点
	u, err := h.repo.GetUser(ctx, username)
	if err != nil || u.PackageID == 0 {
		return false
	}
	pkg, err := h.repo.GetPackage(ctx, u.PackageID)
	if err != nil || pkg == nil {
		return false
	}
	for _, id := range pkg.Nodes {
		if id == nodeID {
			return true
		}
	}
	return false
}

// verifyOutboundMatchesTarget 校验前端传来的 outbound 与目标节点 clash_config 的 server/port 一致。
// 防止用户伪造 outbound 把流量导向任意地址。
func verifyOutboundMatchesTarget(outbound map[string]interface{}, targetClashJSON string) error {
	if targetClashJSON == "" {
		return errors.New("目标节点 clash_config 为空")
	}
	var clash map[string]interface{}
	if err := json.Unmarshal([]byte(targetClashJSON), &clash); err != nil {
		return fmt.Errorf("解析目标 clash: %w", err)
	}
	wantServer, _ := clash["server"].(string)
	wantPort := toInt(clash["port"])
	if wantServer == "" || wantPort == 0 {
		return errors.New("目标节点缺少 server/port")
	}

	gotServer, gotPort := extractOutboundAddr(outbound)
	if gotServer == "" || gotPort == 0 {
		return errors.New("outbound 缺少 server/port")
	}
	if gotServer != wantServer || gotPort != wantPort {
		return fmt.Errorf("outbound 地址 %s:%d 与目标节点 %s:%d 不一致", gotServer, gotPort, wantServer, wantPort)
	}
	return nil
}

func extractOutboundAddr(outbound map[string]interface{}) (string, int) {
	settings, _ := outbound["settings"].(map[string]interface{})
	if settings == nil {
		return "", 0
	}
	if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
		if m, ok := vnext[0].(map[string]interface{}); ok {
			return strOf(m["address"]), toInt(m["port"])
		}
	}
	if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
		if m, ok := servers[0].(map[string]interface{}); ok {
			return strOf(m["address"]), toInt(m["port"])
		}
	}
	return "", 0
}

func strOf(v interface{}) string {
	s, _ := v.(string)
	return s
}

// suspendUserPrivateRouted 用户停用/到期时调用:对该用户所有 routed_owner='user' 节点拆除 xray
// 配置 (rule + client),outbound 配置保留;凭据保留在 user_subaccounts(is_active=false)。
//
// 设计:rule 整条删除而不是 user[] 移除 email — 因为用户私有路由出站的 rule.user 只有
// 创建者一个,移除后 user[] 为空会被 xray 视作"不限 user",意外命中其他用户。删整条 rule
// 干净安全,恢复时根据 DB 元数据重建。
func suspendUserPrivateRouted(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, username string) {
	if rm == nil {
		return
	}
	nodes, err := repo.ListUserRoutedOutbounds(ctx, username)
	if err != nil {
		log.Printf("[SuspendUserRouted] list %s failed: %v", username, err)
		return
	}
	for _, n := range nodes {
		serverID, err := resolveServerIDByNameRepo(ctx, repo, n.OriginalServer)
		if err != nil {
			log.Printf("[SuspendUserRouted] resolve server for node %d failed (continue): %v", n.ID, err)
			continue
		}
		leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
		if err != nil {
			log.Printf("[SuspendUserRouted] node %d deferred: %v", n.ID, err)
			continue
		}
		func() {
			defer release()
			current, err := repo.GetRoutedNodeDetail(leasedCtx, n.ID)
			if err != nil || current.OriginalServer != n.OriginalServer {
				log.Printf("[SuspendUserRouted] node %d changed while acquiring lease; retry later", n.ID)
				return
			}
			sa, _ := repo.GetUserSubaccount(leasedCtx, n.ID, username)
			if sa == nil {
				return
			}
			if err := removeRuleByMarktag(leasedCtx, rm, serverID, current.RoutedRuleMarktag); err != nil {
				log.Printf("[SuspendUserRouted] remove rule node %d failed: %v", n.ID, err)
				return
			}
			if err := removeClientFromInbound(leasedCtx, rm, serverID, current.InboundTag, sa.Email); err != nil {
				log.Printf("[SuspendUserRouted] remove client node %d failed: %v", n.ID, err)
				return
			}
			if err := repo.SetSubaccountActive(leasedCtx, sa.ID, false); err != nil {
				log.Printf("[SuspendUserRouted] mark inactive node %d failed: %v", n.ID, err)
			}
		}()
	}
}

// resumeUserPrivateRouted 用户续费/启用时调用:恢复该用户所有 routed_owner='user' 节点的
// xray 配置 (重建 rule + 加回 client),凭据从 user_subaccounts 取。
func resumeUserPrivateRouted(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, username string) {
	if rm == nil {
		return
	}
	nodes, err := repo.ListUserRoutedOutbounds(ctx, username)
	if err != nil {
		log.Printf("[ResumeUserRouted] list %s failed: %v", username, err)
		return
	}
	for _, n := range nodes {
		serverID, err := resolveServerIDByNameRepo(ctx, repo, n.OriginalServer)
		if err != nil {
			log.Printf("[ResumeUserRouted] resolve server for node %d failed (continue): %v", n.ID, err)
			continue
		}
		leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
		if err != nil {
			log.Printf("[ResumeUserRouted] node %d deferred: %v", n.ID, err)
			continue
		}
		func() {
			defer release()
			current, err := repo.GetRoutedNodeDetail(leasedCtx, n.ID)
			if err != nil || current.OriginalServer != n.OriginalServer {
				log.Printf("[ResumeUserRouted] node %d changed while acquiring lease; retry later", n.ID)
				return
			}
			sa, err := repo.GetUserSubaccount(leasedCtx, n.ID, username)
			if err != nil || sa == nil {
				log.Printf("[ResumeUserRouted] node %d no subaccount for %s, skip", n.ID, username)
				return
			}
			var cred map[string]interface{}
			if err := json.Unmarshal([]byte(sa.CredentialJSON), &cred); err != nil {
				log.Printf("[ResumeUserRouted] parse credential for node %d failed: %v", n.ID, err)
				return
			}
			if err := addClientToInbound(leasedCtx, rm, serverID, current.InboundTag, cred); err != nil {
				log.Printf("[ResumeUserRouted] addClient node %d failed (continue): %v", n.ID, err)
				return
			}
			rule := map[string]interface{}{
				"type":        "field",
				"marktag":     current.RoutedRuleMarktag,
				"user":        []string{sa.Email},
				"inboundTag":  []string{current.InboundTag},
				"outboundTag": current.RoutedOutboundTag,
			}
			body, _ := json.Marshal(map[string]interface{}{"action": "add_rule", "rule": rule})
			response, err := rm.forwardToRemoteServer(leasedCtx, serverID, "POST", "/api/child/routing", body)
			if err == nil {
				err = applyAgentConfigMutationACK(leasedCtx, rm, serverID, "ResumeUserRoutedRule", response)
			}
			if err != nil {
				log.Printf("[ResumeUserRouted] add_rule node %d failed (continue): %v", n.ID, err)
				_ = removeClientFromInbound(leasedCtx, rm, serverID, current.InboundTag, sa.Email)
				return
			}
			if err := repo.SetSubaccountActive(leasedCtx, sa.ID, true); err != nil {
				log.Printf("[ResumeUserRouted] mark active node %d failed: %v", n.ID, err)
			}
		}()
	}
}

// deleteUserPrivateRoutedAll 用户账户删除时调用:清理该用户所有 routed_owner='user' 节点的
// xray 配置(rule + outbound + client)和 DB 行(user_subaccounts 通过 FK 级联)。
// Remote cleanup is a hard boundary: retaining the DB row is what makes an
// offline or partially failed deletion retryable.
func deleteUserPrivateRoutedAll(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, username string) error {
	nodes, err := repo.ListUserRoutedOutbounds(ctx, username)
	if err != nil {
		return fmt.Errorf("list private routed nodes: %w", err)
	}
	if len(nodes) > 0 && rm == nil {
		return errors.New("remote manager is unavailable for private routed cleanup")
	}
	for _, n := range nodes {
		serverID, err := resolveServerIDByNameRepo(ctx, repo, n.OriginalServer)
		if err != nil {
			return fmt.Errorf("resolve server for private routed node %d: %w", n.ID, err)
		}
		leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
		if err != nil {
			return fmt.Errorf("acquire private routed node %d mutation lease: %w", n.ID, err)
		}
		err = func() error {
			defer release()
			current, err := repo.GetRoutedNodeDetail(leasedCtx, n.ID)
			if err != nil {
				return fmt.Errorf("reload private routed node %d: %w", n.ID, err)
			}
			if current.OriginalServer != n.OriginalServer {
				return fmt.Errorf("private routed node %d server changed; retry required", n.ID)
			}
			if err := removeRuleByMarktag(leasedCtx, rm, serverID, current.RoutedRuleMarktag); err != nil {
				return fmt.Errorf("remove rule for private routed node %d: %w", n.ID, err)
			}
			rmOutBody, _ := json.Marshal(map[string]string{"action": "remove", "tag": current.RoutedOutboundTag})
			outboundResponse, err := rm.forwardToRemoteServer(leasedCtx, serverID, "POST", "/api/child/outbounds", rmOutBody)
			if err == nil {
				err = applyAgentConfigMutationACK(leasedCtx, rm, serverID, "DeleteUserRoutedOutbound", outboundResponse)
			}
			if err != nil {
				return fmt.Errorf("remove outbound for private routed node %d: %w", n.ID, err)
			}
			sa, subaccountErr := repo.GetUserSubaccount(leasedCtx, n.ID, username)
			if subaccountErr != nil && !errors.Is(subaccountErr, sql.ErrNoRows) {
				return fmt.Errorf("load private routed credential for node %d: %w", n.ID, subaccountErr)
			}
			if sa != nil {
				if err := removeClientFromInbound(leasedCtx, rm, serverID, current.InboundTag, sa.Email); err != nil {
					return fmt.Errorf("remove client for private routed node %d: %w", n.ID, err)
				}
			}
			if err := repo.DeleteRoutedNode(leasedCtx, n.ID); err != nil {
				return fmt.Errorf("delete private routed node %d: %w", n.ID, err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// resolveServerIDByNameRepo 包级 server 反查,suspend/resume helpers 用(handler 方法版本不能在包级函数里调)。
func resolveServerIDByNameRepo(ctx context.Context, repo *storage.TrafficRepository, name string) (int64, error) {
	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return 0, err
	}
	for _, s := range servers {
		if s.Name == name {
			return s.ID, nil
		}
	}
	return 0, fmt.Errorf("server not found: %s", name)
}

// simpleSlug 转 [a-z0-9-]+,失败回退 "x"
func simpleSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			if b.Len() > 0 {
				b.WriteRune('-')
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "x"
	}
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}
