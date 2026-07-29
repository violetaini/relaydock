package handler

import (
	"context"
	"encoding/json"
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

// SyncXrayConfigOnReconnect 在 agent WS 重连成功后由 RemoteWSHandler 异步触发。
//
// 行为:拉 agent 当前 xray config.json,与主控 current snapshot 比对,按 prevStatus 分流:
//   - prevStatus == "offline":写 pending_recovery,不动 current(VPS 跑路换机场景 — 等用户决策)
//   - 其它(首次连接 / connected 期 reconnect):UpsertCurrent
//     (用户 SSH 修复坏配置后重启 agent 的场景 — 自动接受 agent 现状)
//
// 拉失败 / 解析失败:静默跳过,等下次 reconnect 再来 — agent 端 xray 还没装 / 没启动很正常。
func (h *RemoteManageHandler) SyncXrayConfigOnReconnect(ctx context.Context, serverID int64, prevStatus string) {
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !remoteInstallationAllowsAutoDeploy(fctx, h.repo, serverID, "Xray snapshot sync") {
		return
	}

	raw, err := h.forwardToRemoteServer(fctx, serverID, "GET", "/api/child/xray/config", nil)
	if err != nil {
		// xray 未安装 / 配置文件不存在 → agent 返回 404,这里也 silent skip
		log.Printf("[XraySync] server=%d fetch agent xray config skipped: %v", serverID, err)
		return
	}

	var resp struct {
		Success bool   `json:"success"`
		Path    string `json:"path"`
		Config  string `json:"config"`
	}
	if jerr := json.Unmarshal(raw, &resp); jerr != nil || !resp.Success || strings.TrimSpace(resp.Config) == "" {
		log.Printf("[XraySync] server=%d parse agent xray config skipped: jerr=%v success=%v", serverID, jerr, resp.Success)
		return
	}
	// The install lock may have been acquired while the remote GET was in
	// flight. Never snapshot or restore a transient config that may roll back.
	if !remoteInstallationAllowsAutoDeploy(fctx, h.repo, serverID, "Xray snapshot sync") {
		return
	}

	if strings.EqualFold(strings.TrimSpace(prevStatus), "offline") {
		// 用户在 UI 点过恢复 Popover → 直接下发 current,不走 pending_recovery 等待决策。
		// 典型场景:VPS 跑路换机,新 agent 装好后连上来,主控自动把 last snapshot 覆盖过去。
		if h.consumeExpectRecovery(serverID) {
			current, cerr := h.repo.GetCurrentXraySnapshot(fctx, serverID)
			if cerr != nil || current == nil {
				log.Printf("[XraySync] server=%d expect_recovery set but no current snapshot: %v", serverID, cerr)
				return
			}
			// 恢复前 merge:把 agent 实配(resp.Config)里 current 落后缺失的 inbound/outbound 并回来,
			// 避免用落后 snapshot 全量覆盖抹掉 federation 对方新加的入站("共享入站一觉醒来消失")。
			cfgToApply, mergedN := mergeAgentOnlyInboundsOutbounds(current.ConfigJSON, resp.Config)
			if mergedN > 0 {
				log.Printf("[XraySync] server=%d expect_recovery: merged %d agent-only inbound/outbound into snapshot before restore", serverID, mergedN)
			}
			// test → PUT
			testBody, _ := json.Marshal(map[string]string{"config": cfgToApply})
			if raw, terr := h.forwardToRemoteServer(fctx, serverID, "POST", "/api/child/xray/test-config", testBody); terr == nil {
				var tr struct {
					Ok    bool   `json:"ok"`
					Error string `json:"error"`
				}
				_ = json.Unmarshal(raw, &tr)
				if !tr.Ok {
					log.Printf("[XraySync] server=%d expect_recovery: snapshot failed test on new agent: %s", serverID, tr.Error)
					return
				}
			}
			putBody, _ := json.Marshal(map[string]interface{}{"config": cfgToApply, "force": true})
			if perr := withRemoteInstallationSafeMutation(fctx, h.repo, serverID, "Xray snapshot restore", func(actionCtx context.Context) error {
				_, err := h.forwardToRemoteServer(actionCtx, serverID, "POST", "/api/child/xray/config", putBody)
				return err
			}); perr != nil {
				// consumeExpectRecovery ran before the remote validation. Preserve the
				// user's recovery intent so a post-finalize reconnect/trigger can retry.
				h.SetExpectRecovery(serverID)
				log.Printf("[XraySync] server=%d expect_recovery PUT failed: %v", serverID, perr)
				return
			}
			log.Printf("[XraySync] server=%d expect_recovery: auto-restored current snapshot (hash=%s)", serverID, shortHash(current.ConfigHash))
			return
		}

		var wrote bool
		werr := withRemoteInstallationSafeMutation(fctx, h.repo, serverID, "Xray pending recovery", func(actionCtx context.Context) error {
			var err error
			wrote, err = h.repo.WritePendingXrayRecovery(actionCtx, serverID, resp.Config, storage.XraySnapshotSourceAgentReport)
			return err
		})
		if werr != nil {
			log.Printf("[XraySync] server=%d write pending recovery failed: %v", serverID, werr)
			return
		}
		if wrote {
			log.Printf("[XraySync] server=%d offline→online with config drift — pending_recovery written, awaiting user decision", serverID)
		} else {
			log.Printf("[XraySync] server=%d offline→online but config matches current — no pending needed", serverID)
		}
		return
	}

	var snap *storage.ServerXrayConfigSnapshot
	werr := withRemoteInstallationSafeMutation(fctx, h.repo, serverID, "Xray snapshot upsert", func(actionCtx context.Context) error {
		var err error
		snap, err = h.repo.UpsertCurrentXraySnapshot(actionCtx, serverID, resp.Config, storage.XraySnapshotSourceAgentReport)
		if err == nil && h.inboundCache != nil {
			h.inboundCache.SyncFromConfig(serverID, resp.Config)
		}
		return err
	})
	if werr != nil {
		log.Printf("[XraySync] server=%d upsert current failed: %v", serverID, werr)
		return
	}
	if snap != nil && snap.ConfigHash != "" {
		log.Printf("[XraySync] server=%d current snapshot synced (hash=%s)", serverID, shortHash(snap.ConfigHash))
	}
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
	"/api/child/xray/config-files",
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

// refreshXraySnapshot 异步拉一次 agent 当前 xray config 并 upsert 到 current snapshot,
// 由 forwardToRemoteServer defer hook 在 master 写操作成功后触发。
//
// 注意:本函数内部也调 forwardToRemoteServer GET,GET 不触发递归 refresh(shouldRefreshXraySnapshotAfter 返回 false)。
func (h *RemoteManageHandler) refreshXraySnapshot(serverID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/xray/config", nil)
	if err != nil {
		log.Printf("[XraySync] refresh after master write skipped for server=%d: %v", serverID, err)
		return
	}
	var resp struct {
		Success bool   `json:"success"`
		Config  string `json:"config"`
	}
	if jerr := json.Unmarshal(raw, &resp); jerr != nil || !resp.Success || strings.TrimSpace(resp.Config) == "" {
		log.Printf("[XraySync] refresh parse skipped for server=%d: jerr=%v success=%v", serverID, jerr, resp.Success)
		return
	}
	var snap *storage.ServerXrayConfigSnapshot
	werr := withRemoteInstallationSafeMutation(ctx, h.repo, serverID, "Xray snapshot refresh", func(actionCtx context.Context) error {
		var err error
		snap, err = h.repo.UpsertCurrentXraySnapshot(actionCtx, serverID, resp.Config, storage.XraySnapshotSourceMasterWrite)
		if err == nil && h.inboundCache != nil {
			h.inboundCache.SyncFromConfig(serverID, resp.Config)
		}
		return err
	})
	if werr != nil {
		log.Printf("[XraySync] refresh upsert failed for server=%d: %v", serverID, werr)
		return
	}
	if snap != nil && snap.ConfigHash != "" {
		log.Printf("[XraySync] refresh after master write ok server=%d (hash=%s)", serverID, shortHash(snap.ConfigHash))
	}
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

// CorrectXrayModeDrift 校正 embedded→external 漂移(agent WS auth 成功后由 RemoteWSHandler 异步触发)。
// agentMode = agent 随 auth 上报的当前实际 xray_mode。
//
// 只处理"DB=embedded 但 agent=external"这一个安全方向:这里下发
// switch-xray-mode(embedded) 让 agent 回到数据库记录的运行模式。
// 反向(DB=external → 切 embedded 或 agent=embedded → 切 external)
// 都不自动,避免把好端端的 external 服务器搞挂。agent 收到后改 config.yaml + 自重启,重连即 embedded。
func (h *RemoteManageHandler) CorrectXrayModeDrift(ctx context.Context, serverID int64, agentMode string) {
	if strings.TrimSpace(agentMode) != "external" {
		return
	}
	if !remoteInstallationAllowsAutoDeploy(ctx, h.repo, serverID, "Xray mode drift") {
		return
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil || server == nil || server.XrayMode != "embedded" {
		return
	}
	log.Printf("[XrayModeDrift] server=%d DB=embedded but agent=external → auto-switch agent back to embedded", serverID)
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"xray_mode": "embedded"})
	if perr := withRemoteInstallationSafeMutation(fctx, h.repo, serverID, "Xray mode drift", func(actionCtx context.Context) error {
		_, err := h.forwardToRemoteServer(actionCtx, serverID, "POST", "/api/child/agent/switch-xray-mode", body)
		return err
	}); perr != nil {
		log.Printf("[XrayModeDrift] server=%d auto-switch to embedded failed: %v", serverID, perr)
		return
	}
	log.Printf("[XrayModeDrift] server=%d switch-xray-mode(embedded) sent; agent will restart into embedded", serverID)
}
