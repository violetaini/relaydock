package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/storage"

	"github.com/google/uuid"
)

// 链式端口转发编排:选有序 N 台服务器,建 N 条单跳 dokodemo tunnel 首尾相接。
//   A 监听 P → B:P ；B 监听 P → C:P ；… ；出口监听 P → 最终目标。
// 每跳 = 一个 protocol:"tunnel"(dokodemo)入站,target 烤进 settings.address/port,走默认 direct 出站。
// tag 命名 `tunnel-<label>-h<i>`(i 从 0),聚合视图按此分组成一条链;删除由前端逐跳走通用 inbound remove。
// agent/xray 无需改动。

type TunnelChainHandler struct {
	repo     *storage.TrafficRepository
	rm       *RemoteManageHandler
	createMu sync.Mutex
}

func NewTunnelChainHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler) *TunnelChainHandler {
	return &TunnelChainHandler{repo: repo, rm: rm}
}

type createChainReq struct {
	Label         string  `json:"label"`
	ServerIDs     []int64 `json:"server_ids"`
	EntryPort     int     `json:"entry_port"` // 0 = 随机
	TargetAddress string  `json:"target_address"`
	TargetPort    int     `json:"target_port"`
}

type chainHopResult struct {
	ServerID      int64  `json:"server_id"`
	ServerName    string `json:"server_name"`
	Tag           string `json:"tag"`
	ListenPort    int    `json:"listen_port"`
	TargetAddress string `json:"target_address"`
	TargetPort    int    `json:"target_port"`
}

func (h *TunnelChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
		return
	}
	h.create(w, r)
}

func (h *TunnelChainHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createChainReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	label := slugify(req.Label)
	if label == "" {
		writeError(w, http.StatusBadRequest, errors.New("label 只能含字母数字和短横线,长度 2-32"))
		return
	}
	if len(req.ServerIDs) < 2 {
		writeError(w, http.StatusBadRequest, errors.New("链式转发至少需要 2 台服务器"))
		return
	}
	if strings.TrimSpace(req.TargetAddress) == "" || req.TargetPort <= 0 || req.TargetPort > 65535 {
		writeError(w, http.StatusBadRequest, errors.New("最终目标 address/port 无效"))
		return
	}
	if (req.EntryPort != 0 && req.EntryPort < 1024) || req.EntryPort > 65535 {
		writeError(w, http.StatusBadRequest, errors.New("入口端口必须为 0（自动）或 1024-65535"))
		return
	}
	seenServerIDs := make(map[int64]struct{}, len(req.ServerIDs))
	for _, serverID := range req.ServerIDs {
		if _, exists := seenServerIDs[serverID]; exists {
			writeError(w, http.StatusBadRequest, fmt.Errorf("服务器 %d 不能在同一条链路中重复出现", serverID))
			return
		}
		seenServerIDs[serverID] = struct{}{}
	}
	// Labels are the only durable identity of a legacy chain. Serialize creates
	// so two disjoint requests cannot both pass the global label preflight.
	h.createMu.Lock()
	defer h.createMu.Unlock()
	ctx := r.Context()

	n := len(req.ServerIDs)
	servers := make([]*storage.RemoteServer, n)
	hosts := make([]string, n)
	for i, sid := range req.ServerIDs {
		s, err := h.repo.GetRemoteServer(ctx, sid)
		if err != nil || s == nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("服务器 %d 不存在", sid))
			return
		}
		servers[i] = s
		hosts[i] = serverEntryHost(s)
		if hosts[i] == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("服务器 %s 缺少可达地址(ip/domain)", s.Name))
			return
		}
	}

	// Hold every involved server lease before the first Agent request. Sorting
	// the unique IDs gives every multi-server operation the same lock order and
	// prevents two reversed chains from deadlocking when an installer is queued.
	leasedCtx, releaseLeases, err := h.acquireMutationLeases(ctx, req.ServerIDs)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteInstallationActive) {
			writeError(w, http.StatusConflict, err)
		} else {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("获取服务器变更锁失败: %w", err))
		}
		return
	}
	defer releaseLeases()
	ctx = leasedCtx

	allServers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("读取服务器列表失败: %w", err))
		return
	}
	selectedIDs := make(map[int64]struct{}, n)
	for _, serverID := range req.ServerIDs {
		selectedIDs[serverID] = struct{}{}
	}
	inventories := make(map[int64]tunnelServerInventory, len(allServers))
	for i := range allServers {
		candidate := &allServers[i]
		_, selected := selectedIDs[candidate.ID]
		if !selected && candidate.Status != storage.RemoteServerStatusConnected {
			continue
		}
		inventory, inventoryErr := h.serverInventory(ctx, candidate.ID)
		if inventoryErr != nil {
			writeError(w, http.StatusBadGateway, fmt.Errorf("无法确认服务器 %s 的链路标签和端口: %w", candidate.Name, inventoryErr))
			return
		}
		inventories[candidate.ID] = inventory
		for tag := range inventory.tags {
			existingLabel, _, chainTag := parseChainTag(tag)
			if chainTag && existingLabel == label {
				writeError(w, http.StatusConflict, fmt.Errorf("链路名称 %s 已被服务器 %s 的入站 %s 使用", label, candidate.Name, tag))
				return
			}
		}
	}

	used := make([]map[int]bool, n)
	for i, sid := range req.ServerIDs {
		inventory, ok := inventories[sid]
		if !ok {
			writeError(w, http.StatusBadGateway, fmt.Errorf("服务器 %s 缺少端口预检结果", servers[i].Name))
			return
		}
		used[i] = inventory.ports
	}

	// 一条链的所有服务器必须监听同一端口。显式端口冲突时直接失败，
	// 自动模式则从所有服务器空闲端口的交集中挑选一个。
	sharedPort := req.EntryPort
	if sharedPort > 0 {
		for i := range used {
			if used[i][sharedPort] {
				writeError(w, http.StatusConflict, fmt.Errorf("端口 %d 已被服务器 %s 占用，链路所有跳必须使用同一端口", sharedPort, servers[i].Name))
				return
			}
		}
	} else {
		sharedPort = randomCommonFreePort(used)
		if sharedPort == 0 {
			writeError(w, http.StatusConflict, errors.New("所有服务器没有共同可用的转发端口"))
			return
		}
	}
	ports := make([]int, n)
	for i := range ports {
		ports[i] = sharedPort
	}

	// 逐跳下发;记录已建以便回滚。
	type created struct {
		sid        int64
		tag        string
		mutationID string
	}
	var done []created
	rollback := func() error {
		var rollbackErrors []error
		for i := len(done) - 1; i >= 0; i-- {
			c := done[i]
			body, _ := json.Marshal(map[string]any{"action": "remove", "tag": c.tag, "mutation_id": c.mutationID})
			// Preserve the chained lease values even if the client disconnected.
			// The rollback stays synchronous and all leases remain held until the
			// Agent has acknowledged every attempted removal.
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
			result, err := h.rm.ForwardToServer(rctx, c.sid, http.MethodPost, "/api/child/inbounds", body)
			cancel()
			if err == nil {
				err = validateTunnelChainMutationACK(result)
			}
			if err == nil {
				_, err = h.repo.DeleteRemoteInboundOwnershipIfMutation(ctx, c.sid, c.tag, c.mutationID)
			}
			if err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("服务器 %d 删除 %s: %w", c.sid, c.tag, err))
			}
		}
		return errors.Join(rollbackErrors...)
	}

	chainMutationID := uuid.NewString()
	hops := make([]chainHopResult, n)
	for i := 0; i < n; i++ {
		var tHost string
		var tPort int
		if i < n-1 {
			// Keep the public entry address stable, but prefer native IPv6 between
			// dual-stack relays. This avoids IPv4 UDP state/NAT devices breaking
			// the reverse association after more than one tunnel hop.
			tHost, tPort = serverHopHost(servers[i], servers[i+1]), ports[i+1]
		} else {
			tHost, tPort = strings.TrimSpace(req.TargetAddress), req.TargetPort // 出口 → 最终目标
		}
		tag := fmt.Sprintf("tunnel-%s-h%d", label, i)
		mutationID := fmt.Sprintf("tunnel-chain:%s:h%d", chainMutationID, i)
		inbound := map[string]any{
			"tag":      tag,
			"protocol": "tunnel",
			"port":     ports[i],
			// Explicitly disable transparent-redirection destination recovery. A
			// chained UDP hop already has a fixed target; relying on the protocol
			// default can lose the reverse association between adjacent relays.
			"settings": map[string]any{
				"address": tHost, "port": tPort, "network": "tcp,udp", "followRedirect": false,
			},
		}
		body, _ := json.Marshal(map[string]any{"action": "add", "inbound": inbound, "mutation_id": mutationID})
		if err := h.repo.SetRemoteInboundOwnership(ctx, req.ServerIDs[i], tag, mutationID); err != nil {
			if rollbackErr := rollback(); rollbackErr != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("第 %d 跳(%s)无法预存入站所有权: %v; 已建入站回滚未完整确认: %v", i+1, servers[i].Name, err, rollbackErr))
			} else {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("第 %d 跳(%s)无法预存入站所有权: %v", i+1, servers[i].Name, err))
			}
			return
		}
		// The request can reach the Agent and mutate runtime state before a
		// transport error (for example a dropped response) reaches us. Treat this
		// hop as possibly created before sending it so rollback confirms removal
		// instead of leaving an untracked listener behind.
		done = append(done, created{sid: req.ServerIDs[i], tag: tag, mutationID: mutationID})
		hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		result, err := h.rm.ForwardToServer(hctx, req.ServerIDs[i], http.MethodPost, "/api/child/inbounds", body)
		cancel()
		if err == nil {
			// A 2xx response may still carry a warning or malformed legacy body;
			// both are failures and must use the same rollback path.
			err = validateTunnelChainMutationACK(result)
		}
		if err != nil {
			if rollbackErr := rollback(); rollbackErr != nil {
				writeError(w, http.StatusBadGateway, fmt.Errorf("第 %d 跳(%s)下发失败: %v; 回滚未完整确认: %v", i+1, servers[i].Name, err, rollbackErr))
			} else {
				writeError(w, http.StatusBadGateway, fmt.Errorf("第 %d 跳(%s)下发失败,已确认回滚: %v", i+1, servers[i].Name, err))
			}
			return
		}
		hops[i] = chainHopResult{
			ServerID: req.ServerIDs[i], ServerName: servers[i].Name, Tag: tag,
			ListenPort: ports[i], TargetAddress: tHost, TargetPort: tPort,
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"label":      label,
		"entry_host": hosts[0],
		"entry_port": ports[0],
		"hops":       hops,
	})
}

func (h *TunnelChainHandler) acquireMutationLeases(ctx context.Context, serverIDs []int64) (context.Context, func(), error) {
	uniqueIDs := make(map[int64]struct{}, len(serverIDs))
	for _, serverID := range serverIDs {
		uniqueIDs[serverID] = struct{}{}
	}
	orderedIDs := make([]int64, 0, len(uniqueIDs))
	for serverID := range uniqueIDs {
		orderedIDs = append(orderedIDs, serverID)
	}
	sort.Slice(orderedIDs, func(i, j int) bool { return orderedIDs[i] < orderedIDs[j] })

	leasedCtx := ctx
	releases := make([]func(), 0, len(orderedIDs))
	releaseAll := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	for _, serverID := range orderedIDs {
		nextCtx, release, err := h.repo.AcquireRemoteServerExclusiveMutationLease(leasedCtx, serverID)
		if err != nil {
			releaseAll()
			return nil, func() {}, err
		}
		leasedCtx = nextCtx
		releases = append(releases, release)
	}
	return leasedCtx, releaseAll, nil
}

type tunnelServerInventory struct {
	ports map[int]bool
	tags  map[string]struct{}
}

// serverInventory fetches the durable Xray config used for both tag identity
// and port availability checks. Failure is returned to the caller: replacing a
// same-tag inbound without a trustworthy preflight is destructive.
func (h *TunnelChainHandler) serverInventory(ctx context.Context, serverID int64) (tunnelServerInventory, error) {
	inventory := tunnelServerInventory{ports: map[int]bool{}, tags: map[string]struct{}{}}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	result, err := h.rm.ForwardToServer(cctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return inventory, err
	}
	var envelope struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(result, &envelope); err != nil {
		return inventory, fmt.Errorf("invalid Agent config envelope: %w", err)
	}
	if strings.TrimSpace(envelope.Config) == "" {
		return inventory, errors.New("Agent config envelope is missing config")
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(envelope.Config), &cfg); err != nil {
		return inventory, fmt.Errorf("invalid Xray config: %w", err)
	}
	inbounds, _ := cfg["inbounds"].([]any)
	for _, ibAny := range inbounds {
		if ib, ok := ibAny.(map[string]any); ok {
			if p := toInt(ib["port"]); p > 0 {
				inventory.ports[p] = true
			}
			if tag, _ := ib["tag"].(string); strings.TrimSpace(tag) != "" {
				inventory.tags[strings.TrimSpace(tag)] = struct{}{}
			}
		}
	}
	return inventory, nil
}

func validateTunnelChainMutationACK(body []byte) error {
	var ack struct {
		Success        *bool  `json:"success"`
		Error          string `json:"error"`
		Message        string `json:"message"`
		Warning        string `json:"warning"`
		RuntimeWarning string `json:"runtime_warning"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return fmt.Errorf("invalid Agent mutation ACK: %w", err)
	}
	if ack.Success == nil || !*ack.Success {
		detail := strings.TrimSpace(ack.Error)
		if detail == "" {
			detail = strings.TrimSpace(ack.Message)
		}
		if detail == "" {
			detail = "Agent did not acknowledge the mutation"
		}
		return errors.New(detail)
	}
	if warning := strings.TrimSpace(ack.Warning); warning != "" {
		return fmt.Errorf("Agent mutation warning: %s", warning)
	}
	if warning := strings.TrimSpace(ack.RuntimeWarning); warning != "" {
		return fmt.Errorf("Agent runtime warning: %s", warning)
	}
	return nil
}

// serverEntryHost returns a client-facing address, preferring the historically
// compatible IPv4/domain fields and falling back to an enabled IPv6 address.
func serverEntryHost(s *storage.RemoteServer) string {
	for _, v := range []string{s.IPAddress, s.Domain, s.PullAddress} {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if s.IPv6Enabled && strings.TrimSpace(s.IPAddressV6) != "" {
		return strings.TrimSpace(s.IPAddressV6)
	}
	return ""
}

// serverHopHost selects the address used only between adjacent relays. Native
// IPv6 is preferred when both ends have reported it and IPv6 remains enabled;
// otherwise the next server's regular entry address is used.
func serverHopHost(current, next *storage.RemoteServer) string {
	if current.IPv6Enabled && next.IPv6Enabled &&
		strings.TrimSpace(current.IPAddressV6) != "" && strings.TrimSpace(next.IPAddressV6) != "" {
		return strings.TrimSpace(next.IPAddressV6)
	}
	return serverEntryHost(next)
}

func commonPortAvailable(used []map[int]bool, port int) bool {
	for _, ports := range used {
		if ports[port] {
			return false
		}
	}
	return true
}

// randomCommonFreePort 在 [20000,60000) 选择所有服务器都未使用的端口。
func randomCommonFreePort(used []map[int]bool) int {
	for i := 0; i < 200; i++ {
		p := 20000 + rand.Intn(40000)
		if commonPortAvailable(used, p) {
			return p
		}
	}
	// 随机采样未命中时线性查找，确保只在交集确实为空时失败。
	for p := 20000; p < 60000; p++ {
		if commonPortAvailable(used, p) {
			return p
		}
	}
	return 0
}
