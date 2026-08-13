package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type UserNodesHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
}

func NewUserNodesHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler) *UserNodesHandler {
	return &UserNodesHandler{repo: repo, remoteManage: rm}
}

type userNodeInfo struct {
	ID             int64  `json:"id"`
	NodeName       string `json:"node_name"`
	Protocol       string `json:"protocol"`
	OriginalServer string `json:"original_server"`
	InboundTag     string `json:"inbound_tag"`
	Enabled        bool   `json:"enabled"`
	Tag            string `json:"tag"`
}

// HandleListNodes GET /api/user/nodes — 返回用户套餐内的节点列表
func (h *UserNodesHandler) HandleListNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取用户失败")
		return
	}
	nodeIDs := make([]int64, 0)
	seen := make(map[int64]bool)
	packageAllowed := packageAssignmentActive(user, time.Now())
	if packageAllowed {
		if overLimit, limitErr := h.repo.IsUserOverLimit(ctx, username); limitErr != nil || overLimit {
			packageAllowed = false
		}
	}
	if packageAllowed {
		pkg, packageErr := h.repo.GetPackage(ctx, user.PackageID)
		if packageErr == nil && pkg != nil {
			for _, nodeID := range pkg.Nodes {
				if !seen[nodeID] {
					nodeIDs = append(nodeIDs, nodeID)
					seen[nodeID] = true
				}
			}
		}
	}
	managedNodeIDs, err := effectiveManagedNodeIDs(ctx, h.repo, username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取自选节点失败")
		return
	}
	for _, nodeID := range managedNodeIDs {
		if !seen[nodeID] {
			nodeIDs = append(nodeIDs, nodeID)
			seen[nodeID] = true
		}
	}
	directNodeIDs, err := h.repo.ListEffectiveDirectNodeIDs(ctx, username, time.Now().UTC())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取固定授权节点失败")
		return
	}
	for _, nodeID := range directNodeIDs {
		if !seen[nodeID] {
			nodeIDs = append(nodeIDs, nodeID)
			seen[nodeID] = true
		}
	}

	var nodes []userNodeInfo
	for _, nodeID := range nodeIDs {
		node, err := h.repo.GetNodeByID(ctx, nodeID)
		if err != nil || !node.Enabled {
			continue
		}
		if node.InboundTag == "" || node.OriginalServer == "" {
			continue
		}
		nodes = append(nodes, userNodeInfo{
			ID:             node.ID,
			NodeName:       node.NodeName,
			Protocol:       node.Protocol,
			OriginalServer: node.OriginalServer,
			InboundTag:     node.InboundTag,
			Enabled:        node.Enabled,
			Tag:            node.Tag,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"nodes":   nodes,
	})
}

type addOutboundRequest struct {
	NodeID   int64                  `json:"node_id"`
	Outbound map[string]interface{} `json:"outbound"`
}

// HandleOutbound 处理出站的增删操作: POST 添加, DELETE 删除
func (h *UserNodesHandler) HandleOutbound(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handleAddOutbound(w, r)
	case http.MethodDelete:
		h.handleRemoveOutbound(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *UserNodesHandler) handleAddOutbound(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req addOutboundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if req.NodeID <= 0 || req.Outbound == nil {
		writeJSONError(w, http.StatusBadRequest, "node_id 和 outbound 为必填项")
		return
	}

	outboundTag, _ := req.Outbound["tag"].(string)
	if outboundTag == "" {
		writeJSONError(w, http.StatusBadRequest, "outbound 必须包含 tag")
		return
	}

	// 校验节点属于用户的套餐
	node, serverID, err := h.validateNodeAccess(ctx, username, req.NodeID)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	leasedCtx, release, ok := acquireRemoteServerMutationLeaseHTTP(w, h.repo, ctx, serverID)
	if !ok {
		return
	}
	defer release()
	ctx = leasedCtx
	node, lockedServerID, err := h.validateNodeAccess(ctx, username, req.NodeID)
	if err != nil || lockedServerID != serverID {
		writeJSONError(w, http.StatusConflict, "节点授权或所属服务器发生变化,请重试")
		return
	}

	// 获取用户在该入站中的 email
	email, err := h.getUserEmailForInbound(ctx, username, serverID, node.InboundTag)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 为出站 tag 添加用户前缀，防止冲突
	namespacedTag := fmt.Sprintf("user_%s_%s", username, outboundTag)
	req.Outbound["tag"] = namespacedTag

	// 1. 添加出站到子服务器
	outboundBody, _ := json.Marshal(map[string]interface{}{
		"action":   "add",
		"outbound": req.Outbound,
	})
	result, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", outboundBody)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("添加出站失败: %v", err))
		return
	}

	var outboundResp map[string]interface{}
	json.Unmarshal(result, &outboundResp)
	if success, _ := outboundResp["success"].(bool); !success {
		msg, _ := outboundResp["error"].(string)
		if msg == "" {
			msg, _ = outboundResp["message"].(string)
		}
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("添加出站失败: %s", msg))
		return
	}

	// 2. 添加路由规则：user=[email] + inboundTag → outboundTag
	rule := map[string]interface{}{
		"type":        "field",
		"user":        []string{email},
		"inboundTag":  []string{node.InboundTag},
		"outboundTag": namespacedTag,
	}
	routingBody, _ := json.Marshal(map[string]interface{}{
		"action": "add_rule",
		"rule":   rule,
	})
	routingResult, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", routingBody)
	if err != nil {
		h.rollbackAddedUserOutbound(ctx, serverID, email, namespacedTag)
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("添加路由规则失败: %v", err))
		return
	}
	var routingResp map[string]interface{}
	if err := json.Unmarshal(routingResult, &routingResp); err != nil {
		h.rollbackAddedUserOutbound(ctx, serverID, email, namespacedTag)
		writeJSONError(w, http.StatusBadGateway, "添加路由规则返回无效")
		return
	}
	if success, _ := routingResp["success"].(bool); !success {
		h.rollbackAddedUserOutbound(ctx, serverID, email, namespacedTag)
		writeJSONError(w, http.StatusBadGateway, "添加路由规则未被 Agent 确认")
		return
	}

	// 3. 保存记录
	outboundJSON, _ := json.Marshal(req.Outbound)
	if err := h.repo.SaveUserOutbound(ctx, storage.UserOutbound{
		Username:     username,
		ServerID:     serverID,
		InboundTag:   node.InboundTag,
		OutboundTag:  namespacedTag,
		OutboundJSON: string(outboundJSON),
	}); err != nil {
		h.rollbackAddedUserOutbound(ctx, serverID, email, namespacedTag)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("保存出站记录失败: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"message":      "出站添加成功",
		"outbound_tag": namespacedTag,
	})
}

type removeOutboundRequest struct {
	NodeID      int64  `json:"node_id"`
	OutboundTag string `json:"outbound_tag"`
}

func (h *UserNodesHandler) handleRemoveOutbound(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req removeOutboundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if req.NodeID <= 0 || req.OutboundTag == "" {
		writeJSONError(w, http.StatusBadRequest, "node_id 和 outbound_tag 为必填项")
		return
	}

	// 校验节点属于用户的套餐
	node, serverID, err := h.validateNodeAccess(ctx, username, req.NodeID)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	leasedCtx, release, ok := acquireRemoteServerMutationLeaseHTTP(w, h.repo, ctx, serverID)
	if !ok {
		return
	}
	defer release()
	ctx = leasedCtx
	node, lockedServerID, err := h.validateNodeAccess(ctx, username, req.NodeID)
	if err != nil || lockedServerID != serverID {
		writeJSONError(w, http.StatusConflict, "节点授权或所属服务器发生变化,请重试")
		return
	}

	// 校验出站记录属于该用户
	existing, err := h.repo.GetUserOutbound(ctx, username, serverID, req.OutboundTag)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "出站记录不存在")
		return
	}

	// 获取用户 email 用于匹配路由规则
	email, _ := h.getUserEmailForInbound(ctx, username, serverID, node.InboundTag)

	// 1. 先删除路由规则（通过匹配 user+outboundTag）
	if email != "" {
		if err := h.removeRoutingRule(ctx, serverID, email, req.OutboundTag); err != nil {
			writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("删除路由规则失败: %v", err))
			return
		}
	}

	// 2. 删除出站
	removeBody, _ := json.Marshal(map[string]interface{}{
		"action": "remove",
		"tag":    req.OutboundTag,
	})
	removeResult, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", removeBody)
	if err == nil {
		err = applyAgentConfigMutationACK(ctx, h.remoteManage, serverID, "UserOutboundRemove", removeResult)
	}
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("删除出站失败: %v", err))
		return
	}

	// 3. 删除数据库记录
	if err := h.repo.DeleteUserOutbound(ctx, username, serverID, req.OutboundTag); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("删除出站记录失败: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "出站删除成功",
	})
}

// HandleListOutbounds GET /api/user/nodes/outbounds — 查看用户添加的所有出站
func (h *UserNodesHandler) HandleListOutbounds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	outbounds, err := h.repo.GetUserOutbounds(ctx, username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "获取出站列表失败")
		return
	}

	type outboundInfo struct {
		ID          int64                  `json:"id"`
		ServerID    int64                  `json:"server_id"`
		InboundTag  string                 `json:"inbound_tag"`
		OutboundTag string                 `json:"outbound_tag"`
		Outbound    map[string]interface{} `json:"outbound"`
		CreatedAt   string                 `json:"created_at"`
	}

	var items []outboundInfo
	for _, o := range outbounds {
		var outboundConfig map[string]interface{}
		json.Unmarshal([]byte(o.OutboundJSON), &outboundConfig)
		items = append(items, outboundInfo{
			ID:          o.ID,
			ServerID:    o.ServerID,
			InboundTag:  o.InboundTag,
			OutboundTag: o.OutboundTag,
			Outbound:    outboundConfig,
			CreatedAt:   o.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"outbounds": items,
	})
}

// validateNodeAccess 校验节点属于用户套餐，返回节点信息和服务器ID
func (h *UserNodesHandler) validateNodeAccess(ctx context.Context, username string, nodeID int64) (storage.Node, int64, error) {
	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		return storage.Node{}, 0, fmt.Errorf("获取用户失败")
	}
	found := false
	packageAllowed := packageAssignmentActive(user, time.Now())
	if packageAllowed {
		if overLimit, limitErr := h.repo.IsUserOverLimit(ctx, username); limitErr != nil || overLimit {
			packageAllowed = false
		}
	}
	if packageAllowed {
		if pkg, packageErr := h.repo.GetPackage(ctx, user.PackageID); packageErr == nil && pkg != nil {
			for _, nid := range pkg.Nodes {
				if nid == nodeID {
					found = true
					break
				}
			}
		}
	}
	if !found {
		found = hasEffectiveManagedNodeAccess(ctx, h.repo, username, nodeID)
	}
	if !found {
		directNodeIDs, directErr := h.repo.ListEffectiveDirectNodeIDs(ctx, username, time.Now().UTC())
		if directErr != nil {
			return storage.Node{}, 0, fmt.Errorf("获取固定授权节点失败")
		}
		for _, directNodeID := range directNodeIDs {
			if directNodeID == nodeID {
				found = true
				break
			}
		}
	}
	if !found {
		return storage.Node{}, 0, fmt.Errorf("您无权使用该节点")
	}

	node, err := h.repo.GetNodeByID(ctx, nodeID)
	if err != nil {
		return storage.Node{}, 0, fmt.Errorf("节点不存在")
	}
	if !node.Enabled {
		return storage.Node{}, 0, fmt.Errorf("节点已停用")
	}
	if node.InboundTag == "" || node.OriginalServer == "" {
		return storage.Node{}, 0, fmt.Errorf("该节点未关联远程服务器")
	}

	server, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
	if err != nil {
		return storage.Node{}, 0, fmt.Errorf("远程服务器不存在: %s", node.OriginalServer)
	}

	return node, server.ID, nil
}

// getUserEmailForInbound 获取用户在指定服务器入站中的 email
func (h *UserNodesHandler) getUserEmailForInbound(ctx context.Context, username string, serverID int64, inboundTag string) (string, error) {
	cfg, err := h.repo.GetUserInboundConfig(ctx, username, serverID, inboundTag)
	if err != nil {
		return "", fmt.Errorf("未找到用户在该节点的凭据，请确认套餐已正确分配")
	}

	var cred map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.CredentialJSON), &cred); err != nil {
		return "", fmt.Errorf("解析凭据失败")
	}

	email, _ := cred["email"].(string)
	if email == "" {
		// socks/http 协议使用 user 字段
		email, _ = cred["user"].(string)
	}
	if email == "" {
		return "", fmt.Errorf("凭据中未找到 email")
	}

	return email, nil
}

// removeRoutingRule 从子服务器的路由配置中删除匹配的规则
func (h *UserNodesHandler) removeRoutingRule(ctx context.Context, serverID int64, email, outboundTag string) error {
	result, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/routing", nil)
	if err != nil {
		return fmt.Errorf("获取路由配置: %w", err)
	}

	var resp struct {
		Success bool                   `json:"success"`
		Routing map[string]interface{} `json:"routing"`
	}
	if err := json.Unmarshal(result, &resp); err != nil || !resp.Success {
		return errors.New("Agent 未确认路由配置快照")
	}

	rules, _ := resp.Routing["rules"].([]interface{})
	removeIndex := -1
	for i, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		ruleOutbound, _ := rule["outboundTag"].(string)
		if ruleOutbound != outboundTag {
			continue
		}
		users, _ := rule["user"].([]interface{})
		for _, u := range users {
			if s, ok := u.(string); ok && s == email {
				removeIndex = i
				break
			}
		}
		if removeIndex >= 0 {
			break
		}
	}

	if removeIndex < 0 {
		return nil
	}

	removeBody, _ := json.Marshal(map[string]interface{}{
		"action": "remove_rule",
		"index":  removeIndex,
	})
	response, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/routing", removeBody)
	if err != nil {
		return err
	}
	return applyAgentConfigMutationACK(ctx, h.remoteManage, serverID, "UserOutboundRuleRemove", response)
}

func (h *UserNodesHandler) rollbackAddedOutbound(ctx context.Context, serverID int64, outboundTag string) {
	removeBody, _ := json.Marshal(map[string]interface{}{"action": "remove", "tag": outboundTag})
	if response, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/outbounds", removeBody); err != nil {
		log.Printf("[UserNodes] rollback outbound %s on server %d failed: %v", outboundTag, serverID, err)
	} else if err := applyAgentConfigMutationACK(ctx, h.remoteManage, serverID, "UserOutboundRollback", response); err != nil {
		log.Printf("[UserNodes] rollback outbound %s on server %d was not acknowledged: %v", outboundTag, serverID, err)
	}
}

func (h *UserNodesHandler) rollbackAddedUserOutbound(ctx context.Context, serverID int64, email, outboundTag string) {
	if err := h.removeRoutingRule(ctx, serverID, email, outboundTag); err != nil {
		log.Printf("[UserNodes] rollback routing rule for outbound %s on server %d failed: %v", outboundTag, serverID, err)
	}
	h.rollbackAddedOutbound(ctx, serverID, outboundTag)
}
