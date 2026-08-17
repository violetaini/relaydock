package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

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
	pusher       *LimiterConfigPusher
}

func NewUserRoutedOutboundHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler, pusher *LimiterConfigPusher) *UserRoutedOutboundHandler {
	return &UserRoutedOutboundHandler{repo: repo, remoteManage: rm, pusher: pusher}
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
	leasedCtx, releaseAuthorization, err := h.repo.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("用户授权状态正在变更: %v", err))
		return
	}
	defer releaseAuthorization()
	ctx = leasedCtx
	currentUser, err := h.repo.GetUser(ctx, username)
	if err != nil || !currentUser.IsActive {
		writeJSONError(w, http.StatusForbidden, "用户当前不可创建路由出站")
		return
	}
	overLimit, err := h.repo.IsUserOverLimit(ctx, username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("读取流量限制状态失败: %v", err))
		return
	}
	if overLimit {
		writeJSONError(w, http.StatusForbidden, "流量已超限,暂不可创建路由出站")
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
	currentUser, err = h.repo.GetUser(ctx, username)
	if err != nil || !currentUser.IsActive {
		writeJSONError(w, http.StatusConflict, "用户授权状态在创建期间发生变化")
		return
	}
	overLimit, err = h.repo.IsUserOverLimit(ctx, username)
	if err != nil || overLimit {
		writeJSONError(w, http.StatusConflict, "用户流量授权状态在创建期间发生变化")
		return
	}

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
	shadowsocksMethod := routedShadowsocksMethod(parent)
	userCred, _, err := generateRoutedClientCred(parent.Protocol, shadowsocksMethod, userEmail)
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

	// Persist the complete retry authority before any rule or client can become
	// live. ManagedNodes can finish this activation after an Agent reconnects.
	parentID := parent.ID
	nodeName := strings.TrimSpace(req.NodeName)
	if nodeName == "" {
		nodeName = fmt.Sprintf("%s-%s", parent.NodeName, rawLabel)
	}
	clashWithUser := cloneClashWithCredential(parent.ClashConfig, parent.Protocol, userCred, nodeName)
	parsedWithUser := clashWithUser
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
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("保存路由出站失败: %v", err))
		return
	}
	subaccountID, err := h.repo.ReserveUserSubaccountActivation(ctx, storage.UserSubaccount{
		Username:       username,
		RoutedNodeID:   created.ID,
		Email:          userEmail,
		CredentialJSON: string(credBytes),
	})
	if err != nil {
		if deleteErr := h.repo.DeleteRoutedNode(ctx, created.ID); deleteErr != nil {
			log.Printf("[UserRoutedOutbound] rollback DB node %d failed: %v", created.ID, deleteErr)
		}
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("保存用户激活状态失败: %v", err))
		return
	}

	// DB creation consumes the action quota even if the Agent must converge it
	// asynchronously; retrying the same durable row does not consume it again.
	if err := h.repo.LogUserRoutedOutboundAction(ctx, username, "create"); err != nil {
		log.Printf("[UserRoutedOutbound] LogAction create failed (continue): %v", err)
	}
	sa, err := h.repo.GetUserSubaccount(ctx, created.ID, username)
	if err != nil || sa == nil || sa.ID != subaccountID {
		activationErr := errors.Join(err, errors.New("reserved private routed activation could not be reloaded"))
		log.Printf("[UserRoutedOutbound] activation pending node=%d user=%s: %v", created.ID, username, activationErr)
		respondJSON(w, http.StatusAccepted, map[string]any{
			"success": false, "status": "activation_pending", "node": sanitizeRoutedNodeDetailForExternal(created),
		})
		return
	}
	if err := activatePrivateRoutedSubaccountLocked(ctx, h.remoteManage, h.repo, h.pusher, serverID, created, *sa); err != nil {
		log.Printf("[UserRoutedOutbound] activation pending node=%d user=%s: %v", created.ID, username, err)
		respondJSON(w, http.StatusAccepted, map[string]any{
			"success": false, "status": "activation_pending", "node": sanitizeRoutedNodeDetailForExternal(created),
		})
		return
	}

	log.Printf("[UserRoutedOutbound] created routed node id=%d tag=%s user=%s parent=%d", created.ID, outboundTag, username, parent.ID)
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "node": sanitizeRoutedNodeDetailForExternal(created)})
}

// DELETE /api/user/routed-outbound?id=X  删除自己的路由出站
func (h *UserRoutedOutboundHandler) delete(w http.ResponseWriter, r *http.Request, username string) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "id 必填")
		return
	}
	leasedCtx, releaseAuthorization, err := h.repo.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("用户授权状态正在变更: %v", err))
		return
	}
	defer releaseAuthorization()
	ctx = leasedCtx
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
	serverLeasedCtx, release, ok := acquireRemoteServerMutationLeaseHTTP(w, h.repo, ctx, serverID)
	if !ok {
		return
	}
	defer release()
	ctx = serverLeasedCtx
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
	if err := h.repo.PrepareUserPrivateRoutedDelete(ctx, id, username); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("保存删除意图失败: %v", err))
		return
	}
	detail.Enabled = false
	subaccs, err := h.repo.ListSubaccountsByRoutedNode(ctx, id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("读取 client 状态失败: %v", err))
		return
	}
	if len(subaccs) == 0 {
		writeJSONError(w, http.StatusConflict, "路由出站缺少可撤销的 client 凭据")
		return
	}
	failDelete := func(cause error) {
		for _, sa := range subaccs {
			if persistErr := h.repo.MarkUserSubaccountRevokeFailed(ctx, sa.ID); persistErr != nil {
				cause = errors.Join(cause, persistErr)
			}
		}
		log.Printf("[UserRoutedOutbound] delete pending node=%d user=%s: %v", id, username, cause)
		respondJSON(w, http.StatusAccepted, map[string]any{
			"success": false, "status": "delete_pending", "message": "远端删除待重试",
		})
	}
	if err := reconcilePrivateRoutedDeleteLocked(ctx, h.remoteManage, h.repo, h.pusher, serverID, detail, subaccs); err != nil {
		failDelete(err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true})
}

func reconcilePrivateRoutedDeleteLocked(
	ctx context.Context,
	rm *RemoteManageHandler,
	repo *storage.TrafficRepository,
	pusher *LimiterConfigPusher,
	serverID int64,
	node storage.RoutedNodeDetail,
	subaccounts []storage.UserSubaccount,
) error {
	if node.Enabled {
		return errors.New("private routed delete intent is not durable")
	}
	if len(subaccounts) == 0 {
		return errors.New("private routed delete is missing credential authority")
	}
	if err := pushPrivateRoutedLimiterChecked(ctx, repo, pusher, serverID); err != nil {
		return fmt.Errorf("publish private routed delete deny: %w", err)
	}
	if rm == nil {
		return errors.New("remote manager is unavailable for private routed deletion")
	}
	if err := removePrivateRoutedRuleByMarktag(ctx, rm, serverID, node.RoutedRuleMarktag); err != nil {
		return fmt.Errorf("remove private routed delete rule: %w", err)
	}
	for _, subaccount := range subaccounts {
		if err := removePrivateRoutedClient(ctx, rm, serverID, node.InboundTag, subaccount.Email); err != nil {
			return fmt.Errorf("remove private routed delete client %s: %w", subaccount.Email, err)
		}
	}
	if err := removePrivateRoutedOutbound(ctx, rm, serverID, node.RoutedOutboundTag); err != nil {
		return fmt.Errorf("remove private routed delete outbound: %w", err)
	}
	if err := repo.FinalizeUserPrivateRoutedDelete(ctx, node.ID, node.Username); err != nil {
		return fmt.Errorf("finalize private routed delete: %w", err)
	}
	// Removing a stale deny bucket is not an access-enabling boundary. A later
	// periodic push can safely retry if the Agent is unavailable after deletion.
	if err := pushPrivateRoutedLimiterChecked(ctx, repo, pusher, serverID); err != nil {
		log.Printf("[UserRoutedOutbound] post-delete limiter cleanup pending node=%d: %v", node.ID, err)
	}
	return nil
}

func removePrivateRoutedOutbound(ctx context.Context, rm *RemoteManageHandler, serverID int64, tag string) error {
	present, err := privateRoutedOutboundPresent(ctx, rm, serverID, tag)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"action": "remove", "tag": tag})
	response, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", body)
	if err != nil {
		return err
	}
	return requirePrivateRoutedMutationACK(response, "remove private routed outbound")
}

func privateRoutedOutboundPresent(ctx context.Context, rm *RemoteManageHandler, serverID int64, tag string) (bool, error) {
	if rm == nil || strings.TrimSpace(tag) == "" {
		return false, errors.New("private routed outbound inventory requires a tag and remote manager")
	}
	response, err := rm.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/outbounds", nil)
	if err != nil {
		return false, fmt.Errorf("read private routed outbound inventory: %w", err)
	}
	var inventory struct {
		Success   bool             `json:"success"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(response, &inventory); err != nil {
		return false, fmt.Errorf("decode private routed outbound inventory: %w", err)
	}
	if !inventory.Success {
		return false, errors.New("Agent did not acknowledge private routed outbound inventory")
	}
	for _, outbound := range inventory.Outbounds {
		if outboundTag, _ := outbound["tag"].(string); outboundTag == tag {
			return true, nil
		}
	}
	return false, nil
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
	// 2. 当前有效套餐分配的节点。套餐过期、尚未生效或超额时必须
	// 与节点列表/订阅保持一致，否则这里会成为创建路由出站的授权绕过。
	u, err := h.repo.GetUser(ctx, username)
	if err != nil {
		return false
	}
	if packageAssignmentActive(u, time.Now()) {
		overLimit, limitErr := h.repo.IsUserOverLimit(ctx, username)
		if limitErr != nil {
			return false
		}
		if !overLimit {
			pkg, packageErr := h.repo.GetPackage(ctx, u.PackageID)
			if packageErr != nil {
				return false
			}
			for _, id := range pkg.Nodes {
				if id == nodeID {
					return true
				}
			}
		}
	}

	// 3. 个性化服务器授权和固定节点授权。
	managedNodeIDs, err := effectiveManagedNodeIDs(ctx, h.repo, username)
	if err != nil {
		return false
	}
	for _, id := range managedNodeIDs {
		if id == nodeID {
			return true
		}
	}
	directNodeIDs, err := h.repo.ListEffectiveDirectNodeIDs(ctx, username, time.Now().UTC())
	if err != nil {
		return false
	}
	for _, id := range directNodeIDs {
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
func suspendUserPrivateRouted(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, pusher *LimiterConfigPusher, username string) error {
	leasedCtx, releaseAuthorization, err := repo.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		return fmt.Errorf("acquire private routed authorization lease for %s: %w", username, err)
	}
	defer releaseAuthorization()
	ctx = leasedCtx

	nodes, err := repo.ListUserRoutedOutbounds(ctx, username)
	if err != nil {
		return fmt.Errorf("list private routed nodes for %s: %w", username, err)
	}
	if err := repo.PrepareUserPrivateSubaccountRevokes(ctx, username); err != nil {
		return fmt.Errorf("prepare private routed revokes for %s: %w", username, err)
	}
	serverIDs, err := repo.ListServerIDsForUserSubaccounts(ctx, username)
	if err != nil {
		return fmt.Errorf("list private routed servers for %s: %w", username, err)
	}
	serverLeasedCtx, releaseServers, err := acquireRemoteServerMutationLeases(ctx, repo, serverIDs)
	if err != nil {
		return fmt.Errorf("acquire private routed server leases for %s: %w", username, err)
	}
	defer releaseServers()
	ctx = serverLeasedCtx
	embeddedServerIDs, err := embeddedLimiterServerIDsForIDs(ctx, repo, serverIDs)
	if err != nil {
		return fmt.Errorf("resolve private routed limiter servers for %s: %w", username, err)
	}
	if len(embeddedServerIDs) > 0 && pusher == nil {
		return errors.New("limiter pusher is required to revoke private routed access")
	}
	for _, serverID := range embeddedServerIDs {
		if err := pusher.pushToServerCheckedLeased(ctx, serverID); err != nil {
			return fmt.Errorf("publish private routed deny on server %d: %w", serverID, err)
		}
	}
	var suspendErrs []error
	for _, n := range nodes {
		sa, err := repo.GetUserSubaccount(ctx, n.ID, username)
		if err != nil {
			nodeErr := fmt.Errorf("load private routed credential for node %d: %w", n.ID, err)
			log.Printf("[SuspendUserRouted] %v", nodeErr)
			suspendErrs = append(suspendErrs, nodeErr)
			continue
		}
		if sa == nil {
			nodeErr := fmt.Errorf("private routed node %d has no credential record", n.ID)
			log.Printf("[SuspendUserRouted] %v", nodeErr)
			suspendErrs = append(suspendErrs, nodeErr)
			continue
		}
		if !sa.IsActive && !sa.RevokePending {
			continue
		}
		// Persist the fail-closed state before even resolving the Agent. A stale
		// or missing server mapping must remain visible to the reconciler.
		if err := repo.MarkUserSubaccountRevokePending(ctx, sa.ID); err != nil {
			nodeErr := fmt.Errorf("mark private routed node %d revoke pending: %w", n.ID, err)
			log.Printf("[SuspendUserRouted] %v", nodeErr)
			suspendErrs = append(suspendErrs, nodeErr)
			continue
		}
		serverID, err := resolveServerIDByNameRepo(ctx, repo, n.OriginalServer)
		if err != nil {
			nodeErr := fmt.Errorf("resolve server for private routed node %d: %w", n.ID, err)
			log.Printf("[SuspendUserRouted] %v", nodeErr)
			suspendErrs = append(suspendErrs, nodeErr)
			continue
		}
		leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
		if err != nil {
			nodeErr := fmt.Errorf("acquire private routed node %d mutation lease: %w", n.ID, err)
			log.Printf("[SuspendUserRouted] %v", nodeErr)
			suspendErrs = append(suspendErrs, nodeErr)
			continue
		}
		nodeErr := func() error {
			defer release()
			current, err := repo.GetRoutedNodeDetail(leasedCtx, n.ID)
			if err != nil {
				return fmt.Errorf("reload private routed node %d: %w", n.ID, err)
			}
			if current.OriginalServer != n.OriginalServer {
				return fmt.Errorf("private routed node %d changed while acquiring lease; retry required", n.ID)
			}
			if !current.Enabled {
				subaccounts, err := repo.ListSubaccountsByRoutedNode(leasedCtx, n.ID)
				if err != nil {
					return err
				}
				return reconcilePrivateRoutedDeleteLocked(leasedCtx, rm, repo, pusher, serverID, current, subaccounts)
			}
			sa, err = repo.GetUserSubaccount(leasedCtx, n.ID, username)
			if err != nil {
				return fmt.Errorf("load private routed credential for node %d: %w", n.ID, err)
			}
			if sa == nil {
				return fmt.Errorf("private routed node %d has no credential record", n.ID)
			}
			if !sa.RevokePending {
				return nil
			}
			failRevoke := func(cause error) error {
				if persistErr := repo.MarkUserSubaccountRevokeFailed(leasedCtx, sa.ID); persistErr != nil {
					return errors.Join(cause, persistErr)
				}
				return cause
			}
			if rm == nil {
				return failRevoke(errors.New("remote manager is unavailable"))
			}
			if err := removeRuleByMarktag(leasedCtx, rm, serverID, current.RoutedRuleMarktag); err != nil {
				return failRevoke(fmt.Errorf("remove rule for private routed node %d: %w", n.ID, err))
			}
			if err := removeClientFromInbound(leasedCtx, rm, serverID, current.InboundTag, sa.Email); err != nil {
				return failRevoke(fmt.Errorf("remove client for private routed node %d: %w", n.ID, err))
			}
			if err := repo.CompleteUserSubaccountRevoke(leasedCtx, sa.ID); err != nil {
				return failRevoke(fmt.Errorf("mark private routed node %d inactive: %w", n.ID, err))
			}
			return nil
		}()
		if nodeErr != nil {
			log.Printf("[SuspendUserRouted] user=%s: %v", username, nodeErr)
			suspendErrs = append(suspendErrs, nodeErr)
		}
	}
	return errors.Join(suspendErrs...)
}

// retryPendingUserPrivateRoutedRevokes is intentionally driven by the durable
// subaccount marker rather than by user activity. Disabled/over-limit users
// must keep retrying after an Agent reconnect, while active rows are skipped by
// suspendUserPrivateRouted's state check.
func retryPendingUserPrivateRoutedRevokes(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, pusher *LimiterConfigPusher) []error {
	pending, err := repo.ListPendingUserSubaccountRevokes(ctx, 200)
	if err != nil {
		return []error{err}
	}
	usernames := make(map[string]struct{}, len(pending))
	deleteTargets := make(map[int64]storage.UserSubaccount)
	errs := make([]error, 0)
	for _, subaccount := range pending {
		node, nodeErr := repo.GetRoutedNodeDetail(ctx, subaccount.RoutedNodeID)
		if nodeErr != nil {
			errs = append(errs, fmt.Errorf("load pending private routed node %d: %w", subaccount.RoutedNodeID, nodeErr))
			continue
		}
		if !node.Enabled {
			current, exists := deleteTargets[node.ID]
			if !exists || (current.Username != node.Username && subaccount.Username == node.Username) {
				deleteTargets[node.ID] = subaccount
			}
			continue
		}
		usernames[subaccount.Username] = struct{}{}
	}
	for _, subaccount := range deleteTargets {
		if err := reconcilePendingPrivateRoutedDelete(ctx, rm, repo, pusher, subaccount); err != nil {
			errs = append(errs, fmt.Errorf("delete private routed node %d: %w", subaccount.RoutedNodeID, err))
		}
	}
	for username := range usernames {
		if err := suspendUserPrivateRouted(ctx, rm, repo, pusher, username); err != nil {
			errs = append(errs, fmt.Errorf("user %s: %w", username, err))
		}
	}
	return errs
}

func reconcilePendingPrivateRoutedDelete(
	ctx context.Context,
	rm *RemoteManageHandler,
	repo *storage.TrafficRepository,
	pusher *LimiterConfigPusher,
	subaccount storage.UserSubaccount,
) error {
	leasedCtx, releaseAuthorization, err := repo.AcquireUserAuthorizationLease(ctx, subaccount.Username)
	if err != nil {
		return err
	}
	defer releaseAuthorization()
	ctx = leasedCtx
	node, err := repo.GetRoutedNodeDetail(ctx, subaccount.RoutedNodeID)
	if err != nil {
		return err
	}
	if node.Enabled {
		return errors.New("private routed node no longer has delete intent")
	}
	originalServer := node.OriginalServer
	serverID, err := resolveServerIDByNameRepo(ctx, repo, originalServer)
	if err != nil {
		return err
	}
	serverLeasedCtx, releaseServer, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
	if err != nil {
		return err
	}
	defer releaseServer()
	ctx = serverLeasedCtx
	node, err = repo.GetRoutedNodeDetail(ctx, subaccount.RoutedNodeID)
	if err != nil {
		return err
	}
	if node.Enabled || node.Username != subaccount.Username || node.OriginalServer != originalServer {
		return errors.New("private routed delete intent changed while acquiring lease")
	}
	lockedServerID, err := resolveServerIDByNameRepo(ctx, repo, node.OriginalServer)
	if err != nil || lockedServerID != serverID {
		return errors.New("private routed delete server mapping changed while acquiring lease")
	}
	subaccounts, err := repo.ListSubaccountsByRoutedNode(ctx, node.ID)
	if err != nil {
		return err
	}
	return reconcilePrivateRoutedDeleteLocked(ctx, rm, repo, pusher, serverID, node, subaccounts)
}

func retryPendingUserPrivateRoutedActivations(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, pusher *LimiterConfigPusher) []error {
	pending, err := repo.ListPendingUserSubaccountActivations(ctx, 200)
	if err != nil {
		return []error{err}
	}
	usernames := make(map[string]struct{}, len(pending))
	for _, subaccount := range pending {
		usernames[subaccount.Username] = struct{}{}
	}
	errList := make([]error, 0)
	for username := range usernames {
		if err := resumeUserPrivateRouted(ctx, rm, repo, pusher, username); err != nil {
			errList = append(errList, fmt.Errorf("user %s: %w", username, err))
		}
	}
	return errList
}

func embeddedLimiterServerIDsForIDs(ctx context.Context, repo *storage.TrafficRepository, candidates []int64) ([]int64, error) {
	seen := make(map[int64]struct{}, len(candidates))
	serverIDs := make([]int64, 0, len(candidates))
	for _, serverID := range candidates {
		if serverID <= 0 {
			continue
		}
		if _, exists := seen[serverID]; exists {
			continue
		}
		server, err := repo.GetRemoteServer(ctx, serverID)
		if err != nil {
			return nil, err
		}
		if server.XrayMode != "embedded" {
			continue
		}
		seen[serverID] = struct{}{}
		serverIDs = append(serverIDs, serverID)
	}
	sort.Slice(serverIDs, func(i, j int) bool { return serverIDs[i] < serverIDs[j] })
	return serverIDs, nil
}

func pushPrivateRoutedLimiterChecked(ctx context.Context, repo *storage.TrafficRepository, pusher *LimiterConfigPusher, serverID int64) error {
	server, err := repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return err
	}
	if server.XrayMode != "embedded" {
		return nil
	}
	if pusher == nil {
		return errors.New("limiter pusher is required for private routed access")
	}
	return pusher.pushToServerCheckedLeased(ctx, serverID)
}

func preservePrivateRoutedResumeDeny(
	ctx context.Context,
	rm *RemoteManageHandler,
	repo *storage.TrafficRepository,
	pusher *LimiterConfigPusher,
	serverID int64,
	node storage.RoutedNodeDetail,
	subaccount storage.UserSubaccount,
	cause error,
) error {
	markErr := repo.FailUserSubaccountActivation(ctx, subaccount.ID)
	pushErr := pushPrivateRoutedLimiterChecked(ctx, repo, pusher, serverID)
	var ruleErr, clientErr error
	if rm != nil {
		ruleErr = removePrivateRoutedRuleByMarktag(ctx, rm, serverID, node.RoutedRuleMarktag)
		clientErr = removePrivateRoutedClient(ctx, rm, serverID, node.InboundTag, subaccount.Email)
	}
	return errors.Join(cause, markErr, pushErr, ruleErr, clientErr)
}

// resumeUserPrivateRouted 用户续费/启用时调用:恢复该用户所有 routed_owner='user' 节点的
// xray 配置 (重建 rule + 加回 client),凭据从 user_subaccounts 取。
func resumeUserPrivateRouted(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, pusher *LimiterConfigPusher, username string) error {
	leasedCtx, releaseAuthorization, err := repo.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		return fmt.Errorf("acquire private routed authorization lease for %s: %w", username, err)
	}
	defer releaseAuthorization()
	ctx = leasedCtx

	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return fmt.Errorf("load private routed activation user %s: %w", username, err)
	}
	if !user.IsActive {
		return storage.ErrUserInactive
	}
	overLimit, err := repo.IsUserOverLimit(ctx, username)
	if err != nil {
		return fmt.Errorf("load private routed over-limit state for %s: %w", username, err)
	}
	if overLimit {
		return errors.New("private routed activation is blocked while user is over limit")
	}
	if err := repo.PrepareUserPrivateSubaccountActivations(ctx, username); err != nil {
		return err
	}
	nodes, err := repo.ListUserRoutedOutbounds(ctx, username)
	if err != nil {
		return fmt.Errorf("list private routed nodes for %s: %w", username, err)
	}
	type activationTarget struct {
		node     storage.RoutedNodeDetail
		serverID int64
	}
	targets := make([]activationTarget, 0, len(nodes))
	serverIDs := make([]int64, 0, len(nodes))
	var activationErrs []error
	for _, node := range nodes {
		// A disabled node carries durable delete intent. Do not let a stale
		// activation_pending bit (for example after a crash between state
		// writes) turn a delete into a resume attempt.
		if !node.Enabled {
			continue
		}
		sa, subaccountErr := repo.GetUserSubaccount(ctx, node.ID, username)
		if subaccountErr != nil {
			activationErrs = append(activationErrs, fmt.Errorf("load private routed subaccount node %d: %w", node.ID, subaccountErr))
			continue
		}
		if sa == nil || !sa.ActivationPending {
			continue
		}
		serverID, resolveErr := resolveServerIDByNameRepo(ctx, repo, node.OriginalServer)
		if resolveErr != nil {
			activationErrs = append(activationErrs, fmt.Errorf("resolve server for private routed node %d: %w", node.ID, resolveErr))
			continue
		}
		serverIDs = append(serverIDs, serverID)
		targets = append(targets, activationTarget{node: node, serverID: serverID})
	}
	if len(targets) == 0 {
		return errors.Join(activationErrs...)
	}
	if rm == nil {
		return errors.Join(errors.Join(activationErrs...), errors.New("remote manager is unavailable for private routed activation"))
	}
	serverLeasedCtx, releaseServers, err := acquireRemoteServerMutationLeases(ctx, repo, serverIDs)
	if err != nil {
		return errors.Join(errors.Join(activationErrs...), fmt.Errorf("acquire private routed server leases for %s: %w", username, err))
	}
	defer releaseServers()
	ctx = serverLeasedCtx
	for _, target := range targets {
		n := target.node
		serverID := target.serverID
		leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
		if err != nil {
			activationErrs = append(activationErrs, fmt.Errorf("acquire private routed node %d mutation lease: %w", n.ID, err))
			continue
		}
		nodeErr := func() error {
			defer release()
			current, err := repo.GetRoutedNodeDetail(leasedCtx, n.ID)
			if err != nil || current.OriginalServer != n.OriginalServer {
				return fmt.Errorf("private routed node %d changed while acquiring lease", n.ID)
			}
			if !current.Enabled {
				return nil
			}
			sa, err := repo.GetUserSubaccount(leasedCtx, n.ID, username)
			if err != nil {
				return fmt.Errorf("load private routed subaccount node %d: %w", n.ID, err)
			}
			if sa == nil {
				return fmt.Errorf("private routed node %d has no subaccount", n.ID)
			}
			if !sa.ActivationPending {
				return nil
			}
			return activatePrivateRoutedSubaccountLocked(leasedCtx, rm, repo, pusher, serverID, current, *sa)
		}()
		if nodeErr != nil {
			activationErrs = append(activationErrs, fmt.Errorf("activate private routed node %d: %w", n.ID, nodeErr))
		}
	}
	return errors.Join(activationErrs...)
}

func activatePrivateRoutedSubaccountLocked(
	ctx context.Context,
	rm *RemoteManageHandler,
	repo *storage.TrafficRepository,
	pusher *LimiterConfigPusher,
	serverID int64,
	node storage.RoutedNodeDetail,
	sa storage.UserSubaccount,
) error {
	fail := func(cause error) error {
		return preservePrivateRoutedResumeDeny(ctx, rm, repo, pusher, serverID, node, sa, cause)
	}
	if err := repo.FailUserSubaccountActivation(ctx, sa.ID); err != nil {
		return fmt.Errorf("establish routed activation deny: %w", err)
	}
	if err := pushPrivateRoutedLimiterChecked(ctx, repo, pusher, serverID); err != nil {
		return fmt.Errorf("publish routed activation deny: %w", err)
	}
	if err := removePrivateRoutedRuleByMarktag(ctx, rm, serverID, node.RoutedRuleMarktag); err != nil {
		return fail(fmt.Errorf("settle old routed rule: %w", err))
	}
	if err := removePrivateRoutedClient(ctx, rm, serverID, node.InboundTag, sa.Email); err != nil {
		return fail(fmt.Errorf("settle old routed client: %w", err))
	}

	var credential map[string]interface{}
	if err := json.Unmarshal([]byte(sa.CredentialJSON), &credential); err != nil {
		return fail(fmt.Errorf("parse routed credential: %w", err))
	}
	method := routedExpectedShadowsocksMethod(ctx, repo, node)
	if canonicalManagedProtocol(node.Protocol) == "shadowsocks" && isClassicManagedShadowsocksCipher(method) {
		var credentialJSON string
		var changed, clientMissing bool
		var err error
		credential, credentialJSON, changed, clientMissing, err = reconcileRoutedClassicCredential(
			ctx, rm, serverID, node.InboundTag, node.Protocol, method, sa.Email, credential,
		)
		if err != nil {
			return fail(fmt.Errorf("reconcile routed Shadowsocks credential: %w", err))
		}
		_ = clientMissing
		if changed {
			if err := repo.UpdateUserSubaccountCredential(ctx, sa.ID, credentialJSON); err != nil {
				return fail(fmt.Errorf("persist routed Shadowsocks credential: %w", err))
			}
			sa.CredentialJSON = credentialJSON
		}
	}
	if err := ensurePrivateRoutedOutbound(ctx, rm, serverID, node); err != nil {
		return fail(err)
	}
	if err := addPrivateRoutedRule(ctx, rm, serverID, node, sa.Email); err != nil {
		return fail(err)
	}
	if err := repo.StageUserSubaccountActivationPolicy(ctx, sa.ID); err != nil {
		return fail(fmt.Errorf("stage routed normal limiter policy: %w", err))
	}
	if err := pushPrivateRoutedLimiterChecked(ctx, repo, pusher, serverID); err != nil {
		return fail(fmt.Errorf("publish routed normal limiter policy: %w", err))
	}
	clientOutcome, err := addClientToInboundDeferred(ctx, rm, serverID, node.InboundTag, credential)
	if err != nil {
		return fail(err)
	}
	if clientOutcome.RuntimeDeferred {
		return fail(fmt.Errorf("server %d Agent deferred routed client runtime activation", serverID))
	}
	if err := repo.CompleteUserSubaccountActivation(ctx, sa.ID); err != nil {
		return fail(err)
	}
	return nil
}

func ensurePrivateRoutedOutbound(ctx context.Context, rm *RemoteManageHandler, serverID int64, node storage.RoutedNodeDetail) error {
	var outbound map[string]interface{}
	if err := json.Unmarshal([]byte(node.RoutedOutboundJSON), &outbound); err != nil {
		return fmt.Errorf("parse private routed outbound: %w", err)
	}
	present, err := privateRoutedOutboundPresent(ctx, rm, serverID, node.RoutedOutboundTag)
	if err != nil {
		return err
	}
	if present {
		// Activation starts from a durable deny with no rule/client. Replacing an
		// existing outbound is therefore safe and turns response-loss/runtime-
		// warning retries into a fresh mutation with a strict ACK.
		if err := removePrivateRoutedOutbound(ctx, rm, serverID, node.RoutedOutboundTag); err != nil {
			return fmt.Errorf("settle existing private routed outbound: %w", err)
		}
	}
	body, _ := json.Marshal(map[string]interface{}{"action": "add", "outbound": outbound})
	response, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", body)
	if err != nil {
		return fmt.Errorf("ensure private routed outbound: %w", err)
	}
	return requirePrivateRoutedMutationACK(response, "ensure private routed outbound")
}

func addPrivateRoutedRule(ctx context.Context, rm *RemoteManageHandler, serverID int64, node storage.RoutedNodeDetail, email string) error {
	rule := map[string]interface{}{
		"type": "field", "marktag": node.RoutedRuleMarktag, "user": []string{email},
		"inboundTag": []string{node.InboundTag}, "outboundTag": node.RoutedOutboundTag,
	}
	body, _ := json.Marshal(map[string]interface{}{"action": "add_rule", "rule": rule})
	response, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", body)
	if err != nil {
		return fmt.Errorf("add private routed rule: %w", err)
	}
	return requirePrivateRoutedMutationACK(response, "add private routed rule")
}

func requirePrivateRoutedMutationACK(body []byte, label string) error {
	deferred, err := inspectAgentConfigMutationACK(body)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if deferred {
		return fmt.Errorf("%s: Agent deferred runtime apply", label)
	}
	return nil
}

func removePrivateRoutedClient(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag, email string) error {
	outcome, err := removeClientFromInboundDeferred(ctx, rm, serverID, inboundTag, email)
	if err != nil {
		return err
	}
	if outcome.RuntimeDeferred {
		return fmt.Errorf("server %d Agent deferred private routed client removal", serverID)
	}
	return nil
}

func removePrivateRoutedRuleByMarktag(ctx context.Context, rm *RemoteManageHandler, serverID int64, marktag string) error {
	for attempts := 0; attempts < 32; attempts++ {
		result, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/routing", nil)
		if err != nil {
			return err
		}
		var response struct {
			Success bool                   `json:"success"`
			Routing map[string]interface{} `json:"routing"`
		}
		if err := json.Unmarshal(result, &response); err != nil {
			return err
		}
		if !response.Success {
			return errors.New("Agent did not acknowledge routing snapshot")
		}
		rules, _ := response.Routing["rules"].([]interface{})
		index := -1
		for i, rawRule := range rules {
			rule, _ := rawRule.(map[string]interface{})
			if tag, _ := rule["marktag"].(string); tag == marktag {
				index = i
				break
			}
		}
		if index < 0 {
			return nil
		}
		body, _ := json.Marshal(map[string]interface{}{"action": "remove_rule", "index": index})
		mutation, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", body)
		if err != nil {
			return err
		}
		if err := requirePrivateRoutedMutationACK(mutation, "remove private routed rule"); err != nil {
			return err
		}
	}
	return fmt.Errorf("too many duplicate private routed rules for marktag %s", marktag)
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
