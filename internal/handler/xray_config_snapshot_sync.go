package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// expectRecoveryFlags 标记哪些 server 处于"用户期望恢复"状态(用户在 UI 点了恢复 Popover)。
// in-memory,重启清空 — 重启场景下用户重新点恢复即可。这是 transient signal,不值得加 DB column。
//
// 行为:next time WS reconnect 时(SyncXrayConfigOnReconnect),如果 flag 命中,
// 直接自动 PUT current snapshot 覆盖 agent 默认空配置,不走 pending_recovery 等手动决策路径。
var expectRecoveryFlags sync.Map // serverID (int64) -> bool

// SetExpectRecovery 用户点了恢复 Popover → master 记下"下次 agent 连上请自动下发"。
func (h *RemoteManageHandler) SetExpectRecovery(serverID int64) {
	expectRecoveryFlags.Store(serverID, true)
}

// consumeExpectRecovery: 检测 flag,返回是否被标记,并 atomically 清掉(只触发一次)。
func (h *RemoteManageHandler) consumeExpectRecovery(serverID int64) bool {
	_, exists := expectRecoveryFlags.LoadAndDelete(serverID)
	return exists
}

// SyncXrayConfigOnReconnect treats Agent state as observation only. Reconnects
// converge hot-add/remove capable inbounds to the durable database intent and
// never promote Agent-only listeners into snapshots or nodes.
func (h *RemoteManageHandler) SyncXrayConfigOnReconnect(ctx context.Context, serverID int64, prevStatus string) {
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !remoteInstallationAllowsAutoDeploy(fctx, h.repo, serverID, "Xray snapshot sync") {
		return
	}
	expectRecovery := strings.EqualFold(strings.TrimSpace(prevStatus), storage.RemoteServerStatusOffline) && h.consumeExpectRecovery(serverID)
	leasedCtx, release, err := h.repo.AcquireRemoteServerExclusiveMutationLease(fctx, serverID)
	if err != nil {
		log.Printf("[XrayAuthority] reconnect server=%d lease failed: %v", serverID, err)
		return
	}
	defer release()
	if expectRecovery {
		if err := h.restoreDatabaseXraySnapshotLeased(leasedCtx, serverID); err != nil {
			// The flag is transient, but a failed restore must remain retryable on
			// the next reconnect instead of silently degrading to inbound-only sync.
			h.SetExpectRecovery(serverID)
			log.Printf("[XrayAuthority] explicit recovery server=%d failed: %v", serverID, err)
			return
		}
		log.Printf("[XrayAuthority] explicit recovery server=%d restored the database snapshot", serverID)
		return
	}
	result, reconcileErr := h.reconcileDatabaseOwnedInboundsLeased(leasedCtx, serverID, "")
	h.logDatabaseInboundReconcile(serverID, "reconnect", result, reconcileErr)
}

// restoreDatabaseXraySnapshotLeased is reserved for the explicit disaster-
// recovery workflow. Normal reconnects use hot inbound reconciliation and do
// not write the full config. The caller must hold the server mutation lease.
func (h *RemoteManageHandler) restoreDatabaseXraySnapshotLeased(ctx context.Context, serverID int64) error {
	current, err := h.repo.GetCurrentXraySnapshot(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load current Xray snapshot: %w", err)
	}
	if current == nil || strings.TrimSpace(current.ConfigJSON) == "" {
		return errors.New("no database Xray snapshot is available")
	}
	configJSON, err := h.canonicalizeDatabaseInbounds(ctx, serverID, current.ConfigJSON)
	if err != nil {
		return fmt.Errorf("canonicalize database inbounds: %w", err)
	}

	testBody, err := json.Marshal(map[string]string{"config": configJSON})
	if err != nil {
		return err
	}
	raw, err := h.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/xray/test-config", testBody)
	if err != nil {
		return fmt.Errorf("test database Xray snapshot: %w", err)
	}
	var tested struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &tested); err != nil {
		return fmt.Errorf("decode Xray snapshot test: %w", err)
	}
	if !tested.OK {
		message := strings.TrimSpace(tested.Error)
		if message == "" {
			message = "Agent rejected the database Xray snapshot"
		}
		return errors.New(message)
	}

	putBody, err := json.Marshal(map[string]interface{}{"config": configJSON, "force": true})
	if err != nil {
		return err
	}
	if _, err := h.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/xray/config", putBody); err != nil {
		return fmt.Errorf("restore database Xray snapshot: %w", err)
	}
	// The Agent config endpoint only persists the file. Disaster recovery must
	// not report success until the running process has loaded and passed the
	// normal restart health check. This restart is limited to the explicit
	// recovery action; ordinary inbound reconciliation remains hot.
	if err := h.restartXrayWithRecovery(ctx, serverID, "XrayDatabaseRecovery"); err != nil {
		return fmt.Errorf("activate restored database Xray snapshot: %w", err)
	}
	if _, err := h.repo.UpsertCurrentXraySnapshot(ctx, serverID, configJSON, storage.XraySnapshotSourceMasterWrite); err != nil {
		return fmt.Errorf("persist restored Xray snapshot: %w", err)
	}
	if h.inboundCache != nil {
		h.inboundCache.SyncFromConfig(serverID, configJSON)
	}
	return h.repo.DiscardPendingXrayRecovery(ctx, serverID)
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// xrayMutatingPathPrefixes — agent 端会改 /etc/xray/config.json 的所有 endpoint 前缀。
// master 经 forwardToRemoteServer 命中其中之一且非 GET 时,defer hook 会触发 refresh snapshot。
//
// 不包含的 endpoint(也改不到 xray config):
//   - /api/child/services/control(start/stop xray,但不改文件)
//   - /api/child/limiter(限速配置,独立持久化层)
//   - /api/child/nginx/*(nginx 配置无关 xray)
//   - /api/child/cert/*, /api/child/scan(证书 / 扫描,无 xray)
//   - /api/child/agent/*(agent 自管理 — 但 switch-xray-mode 例外,可能换 xray 跑法间接影响)
var xrayMutatingPathPrefixes = []string{
	"/api/child/inbounds",
	"/api/child/outbounds",
	"/api/child/routing",
	"/api/child/batch-apply",
	"/api/child/xray/config",
	"/api/child/xray/config/files",
	"/api/child/xray/system-config",
	"/api/child/external-xray/takeover",
}

func shouldRefreshXraySnapshotAfter(method, path string) bool {
	if method == "" || method == "GET" || method == "HEAD" || method == "OPTIONS" {
		return false
	}
	// 去掉 query string
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	for _, p := range xrayMutatingPathPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func agentMutationAcknowledged(path string, requestBody, raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var response struct {
		Success *bool `json:"success"`
		OK      *bool `json:"ok"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return false
	}
	acknowledged := response.OK != nil && *response.OK
	if response.Success != nil {
		acknowledged = *response.Success
	}
	if !acknowledged {
		return false
	}
	cleanPath := strings.TrimSuffix(strings.SplitN(path, "?", 2)[0], "/")
	if cleanPath != "/api/child/inbounds" {
		return true
	}
	var request struct {
		MutationID string `json:"mutation_id"`
	}
	var inboundResponse struct {
		MutationID string `json:"mutation_id"`
		Superseded bool   `json:"superseded"`
	}
	if err := json.Unmarshal(requestBody, &request); err != nil || json.Unmarshal(raw, &inboundResponse) != nil {
		return false
	}
	if inboundResponse.Superseded {
		return false
	}
	return strings.TrimSpace(request.MutationID) == "" ||
		strings.TrimSpace(request.MutationID) == strings.TrimSpace(inboundResponse.MutationID)
}

// refreshXraySnapshot is intentionally a database-authority reconcile. A
// successful Agent write may trigger it, but the Agent response is never
// promoted to desired state.
func (h *RemoteManageHandler) refreshXraySnapshot(ctx context.Context, serverID int64) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	leasedCtx, release, err := h.repo.AcquireRemoteServerExclusiveMutationLease(ctx, serverID)
	if err != nil {
		log.Printf("[XrayAuthority] post-write server=%d lease failed: %v", serverID, err)
		return
	}
	defer release()
	leasedCtx = suppressDatabaseInboundPostWrite(leasedCtx)
	result, reconcileErr := h.reconcileDatabaseOwnedInboundsLeased(leasedCtx, serverID, "")
	h.logDatabaseInboundReconcile(serverID, "post_write", result, reconcileErr)
}

// mergeAgentOnlyInboundsOutbounds 在 baseCfg(要下发的 snapshot)基础上,把 agentCfg(agent 当前实配)里
// base 缺失的 inbound / outbound 按 tag 并回来,返回合并后的 config JSON 和新增条数。
//
// 场景:federation 双方各自往同一台 agent 加入站后,若某方的 current snapshot 落后(写后 refresh 抖动/
// 超时漏了对方入站),掉线自动恢复(expect_recovery)会用这份落后 snapshot 全量覆盖 agent → 抹掉对方入站
// ("共享入站一觉醒来只剩自己的")。恢复前先把 agent 实配里 base 缺的 inbound/outbound 并回来,避免误删。
//
// 只并 inbound/outbound(都有唯一 tag,可安全去重);routing 用 base 的(routing rule 无 tag,无脑并集会
// 引入重复/歧义)。任一解析失败 → 原样返回 base,绝不因合并逻辑本身让恢复失败。
func mergeAgentOnlyInboundsOutbounds(baseCfgJSON, agentCfgJSON string) (string, int) {
	var base, agent map[string]any
	if json.Unmarshal([]byte(baseCfgJSON), &base) != nil {
		return baseCfgJSON, 0
	}
	if json.Unmarshal([]byte(agentCfgJSON), &agent) != nil {
		return baseCfgJSON, 0
	}
	added := 0
	for _, key := range []string{"inbounds", "outbounds"} {
		baseArr, _ := base[key].([]any)
		agentArr, _ := agent[key].([]any)
		if len(agentArr) == 0 {
			continue
		}
		have := make(map[string]bool, len(baseArr))
		for _, it := range baseArr {
			if m, ok := it.(map[string]any); ok {
				if tag, _ := m["tag"].(string); tag != "" {
					have[tag] = true
				}
			}
		}
		for _, it := range agentArr {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			tag, _ := m["tag"].(string)
			if tag == "" || have[tag] {
				continue
			}
			baseArr = append(baseArr, it)
			added++
		}
		base[key] = baseArr
	}
	if added == 0 {
		return baseCfgJSON, 0
	}
	merged, err := json.Marshal(base)
	if err != nil {
		return baseCfgJSON, 0
	}
	return string(merged), added
}

// CorrectXrayModeDrift detects an Agent-reported Xray mode mismatch after
// authentication. Mode changes alter the running topology and can interrupt
// proxy traffic, so reconnects never correct them automatically. Administrators
// must make an explicit mode change through the panel.
func (h *RemoteManageHandler) CorrectXrayModeDrift(ctx context.Context, serverID int64, agentMode string) {
	if h == nil || h.repo == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reportedMode := strings.ToLower(strings.TrimSpace(agentMode))
	if reportedMode != "embedded" && reportedMode != "external" {
		return
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil || server == nil {
		if err != nil {
			log.Printf("[XrayModeDrift] server=%d could not read expected mode: %v", serverID, err)
		}
		return
	}
	expectedMode := strings.ToLower(strings.TrimSpace(server.XrayMode))
	if expectedMode == "" {
		expectedMode = "external"
	}
	if expectedMode == reportedMode {
		return
	}
	log.Printf("[XrayModeDrift] server=%d expected=%s reported=%s; leaving Agent mode unchanged until an administrator explicitly changes it", serverID, expectedMode, reportedMode)
}
