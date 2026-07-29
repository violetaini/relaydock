package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/traffic"
	"github.com/violetaini/relaydock/internal/version"
)

// TrafficHandler 处理与流量相关的 API 请求
type TrafficHandler struct {
	repo      *storage.TrafficRepository
	collector *traffic.Collector
}

// 创建一个新的流量处理程序
func NewTrafficHandler(repo *storage.TrafficRepository, collector *traffic.Collector) *TrafficHandler {
	return &TrafficHandler{
		repo:      repo,
		collector: collector,
	}
}

// SerHTTP 路由流量 API 请求
func (h *TrafficHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/traffic")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "" || path == "servers":
		h.handleServers(w, r)
	case strings.HasPrefix(path, "servers/"):
		h.handleServerDetail(w, r, strings.TrimPrefix(path, "servers/"))
	case path == "users":
		h.handleUsers(w, r)
	case strings.HasPrefix(path, "users/"):
		h.handleUserDetail(w, r, strings.TrimPrefix(path, "users/"))
	case path == "snapshots":
		h.handleSnapshots(w, r)
	case path == "node-snapshots":
		h.handleNodeSnapshots(w, r)
	case path == "user-snapshots":
		h.handleUserSnapshots(w, r)
	case path == "server-system-snapshots":
		h.handleServerSystemSnapshots(w, r)
	case path == "user-nodes":
		h.handleUserNodes(w, r)
	case path == "node-users":
		h.handleNodeUsers(w, r)
	case path == "node-totals":
		h.handleNodeTotals(w, r)
	case path == "user-connections":
		h.handleUserConnections(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleUserNodes 返回某用户在每个节点上的流量(细分到 routed 子账号 / 普通 inbound),
// 数据来源: user_email_traffic + user_subaccounts 反查 routed_node_id + user_inbound_configs 反查
// 该用户在某 server 上的 inbound 节点。
//
// GET /api/admin/traffic/user-nodes?username=share
//
// 响应: { items: [ { node_id, node_name, server_name, uplink, downlink, last_uplink, last_downlink } ] }
func (h *TrafficHandler) handleUserNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	baseUp, baseDown := h.emailBaseline(ctx, date)

	// 统一归因器:每条 email 确定性归到"恰好一个用户 + 一/多个节点"。
	// routed email(含被停用的子账号 / admin 占位)永不落父入站,消除父/routed 双算。
	attr, err := h.buildEmailAttributor(ctx)
	if err != nil {
		log.Printf("[Traffic API] user-nodes: build attributor failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "build attribution failed"})
		return
	}
	allEmailTraffic, err := h.repo.ListUserEmailTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] user-nodes: list user_email_traffic failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "list email traffic failed"})
		return
	}

	type item struct {
		NodeID       int64  `json:"node_id"`
		NodeName     string `json:"node_name"`
		ServerName   string `json:"server_name"`
		Uplink       int64  `json:"uplink"`
		Downlink     int64  `json:"downlink"`
		LastUplink   int64  `json:"last_uplink"`
		LastDownlink int64  `json:"last_downlink"`
	}
	byNode := make(map[int64]*item)

	addToNode := func(ns nodeShare, uet storage.UserEmailTraffic) {
		if existing, ok := byNode[ns.NodeID]; ok {
			existing.Uplink += uet.Uplink
			existing.Downlink += uet.Downlink
			existing.LastUplink += uet.LastUplink
			existing.LastDownlink += uet.LastDownlink
			return
		}
		byNode[ns.NodeID] = &item{
			NodeID:       ns.NodeID,
			NodeName:     ns.NodeName,
			ServerName:   ns.ServerName,
			Uplink:       uet.Uplink,
			Downlink:     uet.Downlink,
			LastUplink:   uet.LastUplink,
			LastDownlink: uet.LastDownlink,
		}
	}

	for _, uet := range allEmailTraffic {
		at := attr.classify(uet.Email, uet.ServerID)
		if at.Username != username {
			continue
		}
		uet = subEmailBaseline(uet, baseUp, baseDown)
		for _, ns := range at.Shares {
			addToNode(ns, scaledEmailTraffic(uet, ns.Scale))
		}
	}

	out := make([]item, 0, len(byNode))
	for _, it := range byNode {
		out = append(out, *it)
	}
	// 按总流量降序
	sort.Slice(out, func(i, j int) bool {
		return (out[i].Uplink + out[i].Downlink) > (out[j].Uplink + out[j].Downlink)
	})

	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": out})
}

// handleNodeUsers 返回某节点上各用户的流量(节点视图 drilldown 反向用)。
// 走 user_email_traffic + user_subaccounts/user_inbound_configs 反查,与 handleUserNodes 对称。
//
// GET /api/admin/traffic/node-users?node_id=42
//
// 响应: { items: [ { username, uplink, downlink, last_uplink, last_downlink } ] }
func (h *TrafficHandler) handleNodeUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodeIDStr := strings.TrimSpace(r.URL.Query().Get("node_id"))
	nodeID, err := strconv.ParseInt(nodeIDStr, 10, 64)
	if err != nil || nodeID <= 0 {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	baseUp, baseDown := h.emailBaseline(ctx, date)

	// 校验节点存在(404)。
	if _, err := h.repo.GetNodeByID(ctx, nodeID); err != nil {
		h.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": "node not found"})
		return
	}

	// 统一归因器(与 user-nodes 共用):每条 email 归到"恰好一个用户 + 一/多个节点"。
	// routed/物理由归因器判定,本接口只挑"归到本节点"的 share,天然不会把 routed 流量算到父入站。
	attr, err := h.buildEmailAttributor(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-users: build attributor failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "build attribution failed"})
		return
	}

	allEmailTraffic, err := h.repo.ListUserEmailTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-users: list user_email_traffic failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "list email traffic failed"})
		return
	}

	type item struct {
		Username     string `json:"username"`
		Uplink       int64  `json:"uplink"`
		Downlink     int64  `json:"downlink"`
		LastUplink   int64  `json:"last_uplink"`
		LastDownlink int64  `json:"last_downlink"`
	}
	byUser := make(map[string]*item)
	// 字段语义:Uplink/Downlink 用 cycle-delta(uet.Uplink/Downlink)— 跟对称的 user-nodes 接口一致,
	// 且 collector 的 XrayRestartDetector 已正确累加 xray 重启前的流量。LastUplink/LastDownlink 仍保留
	// cumulative 原值供参考。(旧实现曾故意用 cumulative 避免"用户>节点",但导致两个详情接口口径不一致
	// 且重启后丢失之前流量,已改回 cycle-delta。)
	addUser := func(username string, uet storage.UserEmailTraffic) {
		if existing, ok := byUser[username]; ok {
			existing.Uplink += uet.Uplink
			existing.Downlink += uet.Downlink
			existing.LastUplink += uet.LastUplink
			existing.LastDownlink += uet.LastDownlink
			return
		}
		byUser[username] = &item{
			Username:     username,
			Uplink:       uet.Uplink,
			Downlink:     uet.Downlink,
			LastUplink:   uet.LastUplink,
			LastDownlink: uet.LastDownlink,
		}
	}

	for _, uet := range allEmailTraffic {
		at := attr.classify(uet.Email, uet.ServerID)
		if at.Username == "" {
			continue
		}
		// 挑该 email 归到本节点的 share(通常至多一个)。
		var hit *nodeShare
		for i := range at.Shares {
			if at.Shares[i].NodeID == nodeID {
				hit = &at.Shares[i]
				break
			}
		}
		if hit == nil {
			continue
		}
		e := subEmailBaseline(uet, baseUp, baseDown)
		addUser(at.Username, scaledEmailTraffic(e, hit.Scale))
	}

	out := make([]item, 0, len(byUser))
	for _, it := range byUser {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].Uplink + out[i].Downlink) > (out[j].Uplink + out[j].Downlink)
	})

	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": out})
}

// handleNodeTotals 返回每个节点(物理入站 + routed 出站)的 email 派生总量,与 node-users / user-nodes
// 同源同口径:物理节点 = 其非-routed 用户 email 之和(**自动排除被路由出去的流量**);routed 节点 =
// 其子账号 email 之和。取代"节点视图直接用 node_traffic 入站总量(含 routed)"的旧口径,消除父/routed 双算。
// 支持 date(当日/本周/本月,服务端减 email 快照)。
//
// GET /api/admin/traffic/node-totals?date=2026-07-08
// 响应: { items: [ { node_id, node_name, server_name, node_type, uplink, downlink, last_uplink, last_downlink } ] }
func (h *TrafficHandler) handleNodeTotals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	baseUp, baseDown := h.emailBaseline(ctx, date)

	attr, err := h.buildEmailAttributor(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-totals: build attributor failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "build attribution failed"})
		return
	}
	nodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-totals: list nodes failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "list nodes failed"})
		return
	}
	nodeTypeByID := make(map[int64]string, len(nodes))
	for _, n := range nodes {
		nodeTypeByID[n.ID] = n.NodeType
	}
	allEmailTraffic, err := h.repo.ListUserEmailTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] node-totals: list user_email_traffic failed: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "list email traffic failed"})
		return
	}

	type item struct {
		NodeID       int64  `json:"node_id"`
		NodeName     string `json:"node_name"`
		ServerName   string `json:"server_name"`
		NodeType     string `json:"node_type"`
		Uplink       int64  `json:"uplink"`
		Downlink     int64  `json:"downlink"`
		LastUplink   int64  `json:"last_uplink"`
		LastDownlink int64  `json:"last_downlink"`
	}
	byNode := make(map[int64]*item)
	emailSumByServer := make(map[int64]int64) // 对账用:每 server 归因成功的 email 总和

	for _, uet := range allEmailTraffic {
		at := attr.classify(uet.Email, uet.ServerID)
		if at.Username == "" {
			continue
		}
		e := subEmailBaseline(uet, baseUp, baseDown)
		emailSumByServer[uet.ServerID] += e.Uplink + e.Downlink
		for _, ns := range at.Shares {
			s := scaledEmailTraffic(e, ns.Scale)
			it, ok := byNode[ns.NodeID]
			if !ok {
				it = &item{NodeID: ns.NodeID, NodeName: ns.NodeName, ServerName: ns.ServerName, NodeType: nodeTypeByID[ns.NodeID]}
				byNode[ns.NodeID] = it
			}
			it.Uplink += s.Uplink
			it.Downlink += s.Downlink
			it.LastUplink += s.LastUplink
			it.LastDownlink += s.LastDownlink
		}
	}

	// 对账参照(仅未选日期=全周期 cycle-delta 时,口径与 node_traffic 一致才有意义):
	// Σ归因 email 应 ≈ Σnode_traffic 入站(routed+非routed 都源自入站)。漂移过大 → xray 有未按 user 计数的流量。
	if date == "" {
		if nts, e2 := h.repo.GetAllNodeTraffic(ctx); e2 == nil {
			inboundByServer := make(map[int64]int64)
			for _, nt := range nts {
				if nt.Type == "inbound" {
					inboundByServer[nt.ServerID] += nt.Uplink + nt.Downlink
				}
			}
			for sid, inb := range inboundByServer {
				em := emailSumByServer[sid]
				if inb > 0 {
					driftPct := float64(inb-em) * 100 / float64(inb)
					if driftPct > 15 || driftPct < -15 {
						log.Printf("[Traffic API] node-totals reconcile: server %d inbound=%d email_sum=%d drift=%.1f%%", sid, inb, em, driftPct)
					}
				}
			}
		}
	}

	out := make([]item, 0, len(byNode))
	for _, it := range byNode {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		return (out[i].Uplink + out[i].Downlink) > (out[j].Uplink + out[j].Downlink)
	})

	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": out})
}

// handleUserConnections 返回各用户当前并发连接数(跨所有 server 按 username 聚合)。
// 数据来自 agent 每次 traffic 上报的 conn_counts(内存、实时、非持久)。用户视图「当前连接数」列用。
// GET /api/admin/traffic/user-connections → { success, connections: { "<username>": <n> } }
func (h *TrafficHandler) handleUserConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"success": true, "connections": AggregateUserConnCounts()})
}

// emailBaseline 加载 <= date 的 email 级 baseline,key = "<server_id>|<email>"。
// date 为空(未选时间范围)→ 返回 nil,subEmailBaseline 不做减法,详情显示全周期 cycle-delta。
func (h *TrafficHandler) emailBaseline(ctx context.Context, date string) (up, down map[string]int64) {
	if date == "" {
		return nil, nil
	}
	snaps, err := h.repo.GetUserEmailTrafficSnapshots(ctx, date)
	if err != nil {
		log.Printf("[Traffic API] email baseline load failed: %v", err)
		return nil, nil
	}
	up = make(map[string]int64, len(snaps))
	down = make(map[string]int64, len(snaps))
	for _, s := range snaps {
		k := strconv.FormatInt(s.ServerID, 10) + "|" + s.Email
		up[k] = s.Uplink
		down[k] = s.Downlink
	}
	return up, down
}

// subEmailBaseline 把 uet 的 cycle-delta(Uplink/Downlink)减去 date 时的 baseline → "自 date 起的增量"。
// clamp 到 0 防 baseline > 当前(快照后 xray 重置等)。Last* 是 cumulative 参考值,不减。
// up == nil(date 为空)直接原样返回。
func subEmailBaseline(uet storage.UserEmailTraffic, up, down map[string]int64) storage.UserEmailTraffic {
	if up == nil {
		return uet
	}
	k := strconv.FormatInt(uet.ServerID, 10) + "|" + uet.Email
	if b, ok := up[k]; ok {
		if uet.Uplink > b {
			uet.Uplink -= b
		} else {
			uet.Uplink = 0
		}
	}
	if b, ok := down[k]; ok {
		if uet.Downlink > b {
			uet.Downlink -= b
		} else {
			uet.Downlink = 0
		}
	}
	return uet
}

// ServerTrafficResponse 表示服务器的流量数据
type ServerTrafficResponse struct {
	ServerID   int64                 `json:"server_id"`
	ServerName string                `json:"server_name"`
	Inbounds   []storage.NodeTraffic `json:"inbounds"`
	Outbounds  []storage.NodeTraffic `json:"outbounds"`
	Users      []storage.UserTraffic `json:"users"`
}

// ServersTrafficResponse 表示所有服务器的流量数据
type ServersTrafficResponse struct {
	Success bool                    `json:"success"`
	Servers []ServerTrafficResponse `json:"servers"`
}

func (h *TrafficHandler) handleServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to list servers: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to list servers",
		})
		return
	}

	// 获取所有节点流量
	allNodeTraffic, err := h.repo.GetAllNodeTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to get node traffic: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get node traffic",
		})
		return
	}

	allUserTraffic, err := h.repo.GetAllUserTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to get user traffic: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get user traffic",
		})
		return
	}

	// 按服务器分组
	nodeByServer := make(map[int64][]storage.NodeTraffic)
	userByServer := make(map[int64][]storage.UserTraffic)

	for _, t := range allNodeTraffic {
		nodeByServer[t.ServerID] = append(nodeByServer[t.ServerID], t)
	}
	for _, t := range allUserTraffic {
		userByServer[t.ServerID] = append(userByServer[t.ServerID], t)
	}

	// 建立服务器 ID → 名称映射
	serverNameMap := make(map[int64]string)
	for _, server := range servers {
		serverNameMap[server.ID] = server.Name
	}

	// 收集所有出现过的 server_id
	allServerIDs := make(map[int64]bool)
	for sid := range nodeByServer {
		allServerIDs[sid] = true
	}
	for sid := range userByServer {
		allServerIDs[sid] = true
	}

	// 建立响应
	var result []ServerTrafficResponse
	for sid := range allServerIDs {
		name, ok := serverNameMap[sid]
		if !ok {
			name = fmt.Sprintf("未知服务器-%d", sid)
		}
		nodeTraffic := nodeByServer[sid]
		// 节点流量始终上下行双向显示,**不再**应用 server.traffic_stats_mode。
		// 原 mode swap 逻辑误把 server 级计费规则(upload/download)套到节点字段上,
		// 让 upload mode server 上所有节点的 downlink 被错误清零(包括 routed 出站节点)。
		// server 视图的「used」计算独立 — 走 storage.GetServerTrafficUsed(),那条路径才正确处理 mode。
		var inbounds, outbounds []storage.NodeTraffic
		for _, t := range nodeTraffic {
			if t.Type == "inbound" {
				inbounds = append(inbounds, t)
			} else {
				outbounds = append(outbounds, t)
			}
		}

		result = append(result, ServerTrafficResponse{
			ServerID:   sid,
			ServerName: name,
			Inbounds:   inbounds,
			Outbounds:  outbounds,
			Users:      userByServer[sid],
		})
	}

	h.writeJSON(w, http.StatusOK, ServersTrafficResponse{
		Success: true,
		Servers: result,
	})
}

func (h *TrafficHandler) handleServerDetail(w http.ResponseWriter, r *http.Request, serverIDStr string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID, err := strconv.ParseInt(serverIDStr, 10, 64)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Invalid server ID",
		})
		return
	}

	ctx := r.Context()

	// 获取服务器信息
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		h.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "Server not found",
		})
		return
	}

	// 获取节点流量
	nodeTraffic, err := h.repo.GetNodeTrafficByServer(ctx, serverID)
	if err != nil {
		log.Printf("[Traffic API] Failed to get node traffic for server %d: %v", serverID, err)
		nodeTraffic = []storage.NodeTraffic{}
	}

	var inbounds, outbounds []storage.NodeTraffic
	for _, t := range nodeTraffic {
		if t.Type == "inbound" {
			inbounds = append(inbounds, t)
		} else {
			outbounds = append(outbounds, t)
		}
	}

	// 获取用户流量
	userTraffic, err := h.repo.GetUserTrafficByServer(ctx, serverID)
	if err != nil {
		log.Printf("[Traffic API] Failed to get user traffic for server %d: %v", serverID, err)
		userTraffic = []storage.UserTraffic{}
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"server": ServerTrafficResponse{
			ServerID:   server.ID,
			ServerName: server.Name,
			Inbounds:   inbounds,
			Outbounds:  outbounds,
			Users:      userTraffic,
		},
	})
}

// UserTrafficSummary 表示用户在所有服务器上的聚合流量
type UserTrafficSummary struct {
	Username      string                `json:"username"`
	TotalUplink   int64                 `json:"total_uplink"`
	TotalDownlink int64                 `json:"total_downlink"`
	CycleUplink   int64                 `json:"cycle_uplink"`
	CycleDownlink int64                 `json:"cycle_downlink"`
	Servers       []storage.UserTraffic `json:"servers"`
}

func (h *TrafficHandler) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	allUserTraffic, err := h.repo.GetAllUserTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to get user traffic: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get user traffic",
		})
		return
	}

	// 按用户名聚合
	userMap := make(map[string]*UserTrafficSummary)
	for _, t := range allUserTraffic {
		if _, ok := userMap[t.Username]; !ok {
			userMap[t.Username] = &UserTrafficSummary{
				Username: t.Username,
			}
		}
		summary := userMap[t.Username]
		summary.TotalUplink += t.TotalUplink + t.Uplink
		summary.TotalDownlink += t.TotalDownlink + t.Downlink
		summary.CycleUplink += t.Uplink
		summary.CycleDownlink += t.Downlink
		summary.Servers = append(summary.Servers, t)
	}

	// 转换为切片
	var result []UserTrafficSummary
	for _, summary := range userMap {
		result = append(result, *summary)
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"users":   result,
	})
}

func (h *TrafficHandler) handleUserDetail(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method == http.MethodDelete {
		// 重置用户流量周期
		h.handleResetUserCycle(w, r, username)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// 获取该用户的所有用户流量
	allUserTraffic, err := h.repo.GetAllUserTraffic(ctx)
	if err != nil {
		log.Printf("[Traffic API] Failed to get user traffic: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get user traffic",
		})
		return
	}

	// 按用户名过滤
	var userTraffic []storage.UserTraffic
	for _, t := range allUserTraffic {
		if t.Username == username {
			userTraffic = append(userTraffic, t)
		}
	}

	if len(userTraffic) == 0 {
		h.writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"success": false,
			"error":   "User traffic not found",
		})
		return
	}

	// 计算总结
	var totalUplink, totalDownlink, cycleUplink, cycleDownlink int64
	for _, t := range userTraffic {
		totalUplink += t.TotalUplink + t.Uplink
		totalDownlink += t.TotalDownlink + t.Downlink
		cycleUplink += t.Uplink
		cycleDownlink += t.Downlink
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"user": UserTrafficSummary{
			Username:      username,
			TotalUplink:   totalUplink,
			TotalDownlink: totalDownlink,
			CycleUplink:   cycleUplink,
			CycleDownlink: cycleDownlink,
			Servers:       userTraffic,
		},
	})
}

func (h *TrafficHandler) handleResetUserCycle(w http.ResponseWriter, r *http.Request, username string) {
	ctx := r.Context()

	if err := h.repo.ResetUserTrafficCycle(ctx, username); err != nil {
		log.Printf("[Traffic API] Failed to reset user cycle for %s: %v", username, err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to reset user cycle",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "User cycle reset successfully",
	})
}

func (h *TrafficHandler) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// 解析查询参数
	serverIDStr := r.URL.Query().Get("server_id")
	daysStr := r.URL.Query().Get("days")

	var serverID int64
	if serverIDStr != "" {
		var err error
		serverID, err = strconv.ParseInt(serverIDStr, 10, 64)
		if err != nil {
			serverID = 0
		}
	}

	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	snapshots, err := h.repo.GetTrafficSnapshots(ctx, serverID, days)
	if err != nil {
		log.Printf("[Traffic API] Failed to get snapshots: %v", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to get snapshots",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"snapshots": snapshots,
	})
}

func (h *TrafficHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// RemoteTrafficHandler 处理来自远程服务器的流量报告
type RemoteTrafficHandler struct {
	repo      *storage.TrafficRepository
	collector *traffic.Collector
	crypto    *CryptoConfig
}

// 创建一个新的远程流量处理程序
func NewRemoteTrafficHandler(repo *storage.TrafficRepository, collector *traffic.Collector, crypto *CryptoConfig) *RemoteTrafficHandler {
	return &RemoteTrafficHandler{
		repo:      repo,
		collector: collector,
		crypto:    crypto,
	}
}

// RemoteTrafficRequest 表示来自远程服务器的流量报告
type RemoteTrafficRequest struct {
	Stats *traffic.XrayStats `json:"stats,omitempty"`
	// System 系统级网卡累计 RX/TX(来自 agent /proc/net/dev),用于 server.traffic_source='system' 路径。
	// nil = 老 agent 不支持上报,server 视图自动回退 xray 数据源。
	System *RemoteSystemTraffic `json:"system,omitempty"`
}

// RemoteSystemTraffic 内嵌于 RemoteTrafficRequest,跟 agent 端 sendTrafficData / sendTrafficHTTP 的字段对齐。
type RemoteSystemTraffic struct {
	RxTotal      int64 `json:"rx_total"`
	TxTotal      int64 `json:"tx_total"`
	BootTimeUnix int64 `json:"boot_time_unix"`
}

// 处理来自远程服务器的 POST 请求
func (h *RemoteTrafficHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !version.IsAgentUserAgent(r.Header.Get("User-Agent")) {
		h.writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "Forbidden",
		})
		return
	}

	ctx := r.Context()

	// 加密中间件处理
	crypto, err := handleHTTPCrypto(r, w, h.crypto)
	if crypto == nil {
		return
	}
	_ = err

	token := crypto.Token
	if token == "" {
		h.writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"error":   "Missing authentication token",
		})
		return
	}

	// 验证令牌并获取远程服务器
	remoteServer, err := h.repo.GetRemoteServerByToken(ctx, token)
	if err != nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"error":   "Invalid token",
		})
		return
	}

	// 解析请求体
	var req RemoteTrafficRequest
	if err := json.Unmarshal(crypto.Body, &req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	if req.Stats == nil {
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "No stats to process",
		})
		return
	}

	// 为该远程查找或创建相应的 XrayServer
	// 现在，我们使用远程服务器 ID 作为伪服务器 ID
	// 在实际实现中，您可能希望将远程服务器与 xray_servers 相关联
	serverID := remoteServer.ID

	// 更新流量报告上的 last_heartbeat — 这取代了单独心跳的需要;
	// 同时检测离线→在线翻转,补发 TG 上线通知(WS 模式 auth 已经发过,
	// HTTP push 模式以前只在这里悄悄翻状态,所以下线通知有、上线通知没有)。
	prevStatus, serverName, serverIP, prevNotified, uErr := h.repo.UpdateRemoteServerLastActivity(ctx, serverID)
	if uErr != nil {
		log.Printf("[Remote Traffic] Failed to update last activity for %s: %v", remoteServer.Name, uErr)
	} else if prevStatus == storage.RemoteServerStatusOffline && prevNotified {
		// 只有下线通知已发过(离线满容忍阈值)才补发上线通知;阈值内恢复(prevNotified=0)保持静默。
		SendServerOnlineNotification(ctx, serverName, serverIP)
	}

	// 处理指标 — remoteServer 已经从 db 取过,直接用其 XrayBootTime
	if err := h.collector.ProcessRemoteMetrics(ctx, serverID, req.Stats, remoteServer.XrayBootTime); err != nil {
		log.Printf("[Remote Traffic] Failed to process metrics from %s: %v", remoteServer.Name, err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "Failed to process metrics",
		})
		return
	}

	// 系统级网卡累计:把 delta 累加到 server.system_*_cycle(用于 traffic_source='system')。
	// 老 agent 不上报 → req.System == nil → 跳过,server 视图自动回退 xray 路径。
	// 失败只 log 不阻塞 traffic 流程 — system 数据不可用顶多让 server 视图显示偏小,不致命。
	if req.System != nil {
		if err := h.repo.UpsertRemoteServerSystemTraffic(ctx, serverID, req.System.RxTotal, req.System.TxTotal, req.System.BootTimeUnix); err != nil {
			log.Printf("[Remote Traffic] Failed to upsert system traffic for %s: %v", remoteServer.Name, err)
		}
	}

	// 在 traffic 上报响应里捎带最新的 config 更新(HTTP-mode agent 没有持久连接,
	// 走 traffic POST 的 response 把变化推回去,agent 收到后调 handleConfigUpdate 应用)。
	configUpdates := map[string]string{}
	if val, _ := h.repo.GetSystemSetting(ctx, "dashboard_refresh_interval_ms"); val != "" {
		configUpdates["traffic_report_interval_ms"] = val
	}
	respData, _ := json.Marshal(map[string]interface{}{
		"success":        true,
		"message":        "Traffic data received",
		"config_updates": configUpdates,
	})
	writeHTTPCryptoResponse(w, crypto.Session, respData)
}

func (h *RemoteTrafficHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *TrafficHandler) handleNodeSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := r.URL.Query().Get("date")
	if date == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "date is required"})
		return
	}
	snapshots, err := h.repo.GetNodeTrafficSnapshots(r.Context(), date)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "snapshots": snapshots})
}

func (h *TrafficHandler) handleUserSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := r.URL.Query().Get("date")
	if date == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "date is required"})
		return
	}
	snapshots, err := h.repo.GetUserTrafficSnapshots(r.Context(), date)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "snapshots": snapshots})
}

// handleServerSystemSnapshots 返回每个 server 在 <= date 的最新一份 system_rx_cycle / system_tx_cycle baseline。
// 前端 server 视图 traffic_source='system' 模式下用 (当前 cycle - baseline) 算今日/本周/本月增量,
// 跟 node-snapshots / user-snapshots 用于 xray path 的语义平行。
func (h *TrafficHandler) handleServerSystemSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := r.URL.Query().Get("date")
	if date == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "date is required"})
		return
	}
	snapshots, err := h.repo.GetServerSystemTrafficSnapshots(r.Context(), date)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "snapshots": snapshots})
}
