package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

// HandleForwardNodeTarget changes an existing listener, not a new clone. All
// network destinations and credentials come from a trusted stored node.
func (h *RemoteManageHandler) HandleForwardNodeTarget(w http.ResponseWriter, r *http.Request) {
	if !userIsAdmin(r.Context(), h.repo, auth.UsernameFromContext(r.Context())) {
		remoteWriteError(w, 403, "仅管理员可修改转发目标")
		return
	}
	if r.Method != http.MethodPost {
		remoteWriteError(w, 405, "Method not allowed")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/forward-nodes/"), "/"), "/")
	if len(parts) != 2 || parts[1] != "target" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		remoteWriteError(w, 400, "无效的节点标识")
		return
	}
	var req struct {
		TargetID             int64    `json:"target_node_id"`
		TargetHost           *string  `json:"target_host"`
		ExpectedHost         *string  `json:"expected_target_host"`
		ExpectedTarget       *int64   `json:"expected_target_node_id"`
		UseServerDomain      *bool    `json:"use_server_domain"`
		ExpectedServerDomain *string  `json:"expected_server_domain"`
		Name                 string   `json:"node_name"`
		Tags                 []string `json:"tags"`
		Enabled              bool     `json:"enabled"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || req.TargetID <= 0 || req.ExpectedTarget == nil || strings.TrimSpace(req.Name) == "" || len(req.Name) > 256 || len(req.Tags) > 64 {
		remoteWriteError(w, 400, "请提供有效的目标节点和节点名称")
		return
	}
	entry, err := h.repo.GetNodeByID(r.Context(), id)
	if err != nil {
		remoteWriteError(w, 404, "转发节点不存在")
		return
	}
	if entry.NodeType != "forwarded" || !isDatabaseManagedNode(&entry) || strings.EqualFold(entry.Protocol, "wireguard") {
		remoteWriteError(w, 400, "仅受管任意门转发入口支持切换目标")
		return
	}
	server, err := h.repo.GetRemoteServerByName(r.Context(), entry.OriginalServer)
	if err != nil || server == nil {
		remoteWriteError(w, 409, "转发入口服务器不存在")
		return
	}
	target, err := h.repo.GetNodeByID(r.Context(), req.TargetID)
	if err != nil {
		remoteWriteError(w, 400, "目标节点不存在")
		return
	}
	targetServer, err := h.repo.GetRemoteServerByName(r.Context(), target.OriginalServer)
	if err != nil || targetServer == nil {
		remoteWriteError(w, 409, "目标节点所属服务器不存在，请刷新")
		return
	}
	ctx, release, err := acquireForwardNodeServerLeases(r.Context(), h.repo, server.ID, targetServer.ID)
	if err != nil {
		remoteWriteError(w, 409, "服务器正在变更，请稍后重试")
		return
	}
	defer release()
	// Read again under the same lease used by inbound edits and reconciliation.
	entry, err = h.repo.GetNodeByID(ctx, id)
	if err != nil || entry.OriginalServer != server.Name || entry.NodeType != "forwarded" {
		remoteWriteError(w, 409, "转发入口已变化，请刷新")
		return
	}
	links, err := h.repo.ForwardNodeTargets(ctx)
	if err != nil {
		remoteWriteError(w, 500, "读取绑定失败")
		return
	}
	if links[id] != *req.ExpectedTarget {
		remoteWriteError(w, 409, "转发绑定已变化，请刷新后重试")
		return
	}
	hosts, err := h.repo.ForwardNodeTargetHosts(ctx)
	if err != nil {
		remoteWriteError(w, 500, "读取目标域名失败")
		return
	}
	if req.ExpectedHost != nil && *req.ExpectedHost != hosts[id] {
		remoteWriteError(w, 409, "目标域名已变化，请刷新后重试")
		return
	}
	override := ""
	if req.TargetID == links[id] {
		override = hosts[id]
	}
	if req.TargetHost != nil {
		override, err = normalizeForwardTargetDomain(*req.TargetHost)
		if err != nil {
			remoteWriteError(w, 400, err.Error())
			return
		}
	}
	for child, parent := range links {
		if parent == id && child != id {
			remoteWriteError(w, 409, "此入口仍被其他转发节点引用，请先调整下级入口")
			return
		}
	}
	target, err = h.repo.GetNodeByID(ctx, req.TargetID)
	if err != nil || target.ID == id || !target.Enabled || !isDatabaseManagedNode(&target) || target.NodeType == "routed" || target.NodeType == "forwarded" || strings.EqualFold(target.Protocol, "wireguard") {
		remoteWriteError(w, 400, "请选择已启用的受管代理节点，不能选择自身、转发入口或路由出站")
		return
	}
	if target.OriginalServer != targetServer.Name {
		remoteWriteError(w, 409, "目标节点所属服务器已变化，请刷新")
		return
	}
	targetServer, err = h.repo.GetRemoteServer(ctx, targetServer.ID)
	if err != nil || targetServer == nil {
		remoteWriteError(w, 409, "目标服务器已变化，请刷新")
		return
	}
	if req.ExpectedServerDomain != nil && *req.ExpectedServerDomain != targetServer.Domain {
		remoteWriteError(w, 409, "服务器节点域名已变化，请刷新后重试")
		return
	}
	useDomain := override != ""
	if req.UseServerDomain != nil {
		useDomain = *req.UseServerDomain
	}
	var domainChanges, rollbackDomains []storage.ForwardServerDomainChange
	if useDomain {
		configured, domainErr := normalizeForwardTargetDomain(targetServer.Domain)
		if domainErr != nil {
			remoteWriteError(w, 400, "服务器管理中的节点域名无效，请先修正")
			return
		}
		if configured != "" {
			if req.TargetHost != nil && override != "" && override != configured {
				remoteWriteError(w, 409, "服务器已配置节点域名，请到服务器管理修改")
				return
			}
			override = configured
		} else {
			if override == "" {
				remoteWriteError(w, 400, "请填写节点域名，保存后将同步到服务器管理")
				return
			}
			domainChanges = append(domainChanges, storage.ForwardServerDomainChange{ServerID: targetServer.ID, Before: targetServer.Domain, After: override})
			rollbackDomains = append(rollbackDomains, storage.ForwardServerDomainChange{ServerID: targetServer.ID, Before: override, After: targetServer.Domain})
		}
	} else {
		override = ""
	}
	var targetConfig, entryConfig map[string]interface{}
	if json.Unmarshal([]byte(target.ClashConfig), &targetConfig) != nil || json.Unmarshal([]byte(entry.ClashConfig), &entryConfig) != nil || targetConfig == nil || entryConfig == nil {
		remoteWriteError(w, 400, "节点订阅配置无效")
		return
	}
	host, ok := targetConfig["server"].(string)
	if req.UseServerDomain != nil && !useDomain && net.ParseIP(targetServer.IPAddress) != nil {
		host = targetServer.IPAddress
		ok = true
	}
	port, portOK := targetConfig["port"].(float64)
	protocol, _ := targetConfig["type"].(string)
	if protocol == "tunnel" || protocol == "dokodemo-door" || protocol == "anydoor" || strings.HasPrefix(target.InboundTag, "anydoor-") {
		remoteWriteError(w, 400, "请选择代理节点，不能选择转发入口")
		return
	}
	if !ok || strings.TrimSpace(host) == "" || strings.ContainsAny(host, " /\\\r\n\t") || !portOK || port < 1 || port > 65535 || port != float64(int(port)) || protocol == "" {
		remoteWriteError(w, 400, "目标节点地址或协议无效")
		return
	}
	if override != "" {
		host = override
	}
	if strings.EqualFold(strings.Trim(host, "[]"), strings.Trim(wireGuardStringValue(entryConfig["server"]), "[]")) && port == entryConfig["port"] {
		remoteWriteError(w, 400, "转发目标不能指向入口自身")
		return
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		host = ip.String()
	}
	desired, err := h.repo.GetDesiredInbound(ctx, server.ID, entry.InboundTag)
	if err != nil || desired == nil || desired.DesiredState != storage.DesiredInboundStateActive {
		remoteWriteError(w, 409, "入口入站不存在或已删除")
		return
	}
	owner, err := h.repo.FindInboundMutationID(ctx, server.ID, entry.InboundTag)
	if err != nil || desired.MutationID == "" || (owner != "" && owner != desired.MutationID) || (entry.InboundMutationID != "" && entry.InboundMutationID != desired.MutationID) {
		remoteWriteError(w, 409, "入口所有权已变化，请刷新后重试")
		return
	}
	var inbound map[string]interface{}
	if json.Unmarshal(desired.InboundJSON, &inbound) != nil {
		remoteWriteError(w, 409, "入口配置无效")
		return
	}
	kind := strings.ToLower(wireGuardStringValue(inbound["protocol"]))
	settings, ok := inbound["settings"].(map[string]interface{})
	if !ok || (kind != "tunnel" && kind != "dokodemo-door" && kind != "anydoor") {
		remoteWriteError(w, 400, "入口不是任意门转发")
		return
	}
	settings["address"] = host
	settings["port"] = int(port)
	inbound["tag"] = entry.InboundTag
	nextDesired := *desired
	nextDesired.InboundJSON, _ = json.Marshal(inbound)
	next := entry
	next.NodeName = strings.TrimSpace(req.Name)
	next.Tags = req.Tags
	next.Tag = ""
	next.Enabled = req.Enabled
	next.Protocol = target.Protocol
	next.RawURL = ""
	delete(targetConfig, storage.ManagedShadowsocksMultiUserMarker)
	targetConfig["name"] = next.NodeName
	targetConfig["server"] = entryConfig["server"]
	targetConfig["port"] = entryConfig["port"]
	config, _ := json.Marshal(targetConfig)
	next.ClashConfig = string(config)
	next.ParsedConfig = string(config)
	// Durable intent comes first, so a process crash can be reconciled safely.
	if err := h.repo.ReplaceForwardNode(ctx, entry, next, &target, target.ID, override, *desired, nextDesired, domainChanges...); err != nil {
		remoteWriteError(w, 409, "保存失败，节点或入站已变化，请刷新重试")
		return
	}
	// Continue if the browser disconnects: complete or compensate the operation.
	operation, cancel := context.WithTimeout(context.WithoutCancel(ctx), 65*time.Second)
	defer cancel()
	if err := h.applyDatabaseInboundMutation(operation, server.ID, "add", entry.InboundTag, desired.MutationID, inbound); err != nil {
		rollback, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), 40*time.Second)
		defer cancelRollback()
		if rollbackErr := h.repo.ReplaceForwardNode(rollback, next, entry, nil, links[id], hosts[id], nextDesired, *desired, rollbackDomains...); rollbackErr != nil {
			remoteWriteError(w, 503, "服务器确认失败，保存状态待核对，请刷新后检查绑定")
			return
		}
		var oldInbound map[string]interface{}
		_ = json.Unmarshal(desired.InboundJSON, &oldInbound)
		oldInbound["tag"] = entry.InboundTag
		if rollbackErr := h.applyDatabaseInboundMutation(rollback, server.ID, "add", entry.InboundTag, desired.MutationID, oldInbound); rollbackErr != nil {
			remoteWriteError(w, 503, "切换未完成，已保留原绑定，等待服务器恢复同步")
			return
		}
		remoteWriteError(w, 502, "服务器未确认切换，已恢复原转发目标，请稍后重试")
		return
	}
	warning := ""
	if h.forwardNodeYAMLSync != nil {
		if err := h.forwardNodeYAMLSync.SyncNode(entry.NodeName, next.NodeName, next.ClashConfig); err != nil {
			warning = "转发已生效，但静态订阅文件同步失败，请重新生成订阅"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "forward_node_id": target.ID, "forward_target_host": override, "server_domain_synced": len(domainChanges) > 0, "warning": warning})
}

// Acquire all involved server locks in stable order, including the owner of the
// domain field, so opposite-direction edits cannot deadlock or overwrite it.
func acquireForwardNodeServerLeases(ctx context.Context, repo *storage.TrafficRepository, ids ...int64) (context.Context, func(), error) {
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	releases := []func(){}
	release := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	for i, id := range ids {
		if i > 0 && id == ids[i-1] {
			continue
		}
		next, done, err := repo.AcquireRemoteServerExclusiveMutationLease(ctx, id)
		if err != nil {
			release()
			return nil, nil, err
		}
		ctx = next
		releases = append(releases, done)
	}
	return ctx, release, nil
}

// DNS is intentionally not resolved at save time. The Agent receives the
// hostname so new connections can follow DDNS updates instead of a saved IP.
func normalizeForwardTargetDomain(raw string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if host == "" {
		return "", nil
	}
	invalid := errors.New("请填写有效域名，不含协议、路径、端口或 IP 地址")
	if len(host) > 253 || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "", invalid
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", invalid
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", invalid
			}
		}
	}
	return host, nil
}
