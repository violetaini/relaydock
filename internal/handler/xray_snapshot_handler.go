package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

// XraySnapshotHandler 处理主控维护的 server xray 配置快照相关的 admin API。
//
// 路由总入口 /api/admin/xray-snapshots/,内部按 path 后缀分支:
//   - GET  /api/admin/xray-snapshots/recovery-status?server_id=X  → 该 server 是否有 pending_recovery
//   - POST /api/admin/xray-snapshots/recovery-apply?server_id=X   → master current PUT 到 agent(用户跑路换机一键恢复)
//   - POST /api/admin/xray-snapshots/recovery-accept?server_id=X  → 接受 pending → 升级为 current
//   - GET  /api/admin/xray-snapshots/list?server_id=X             → 该 server 全部历史 snapshot
//   - POST /api/admin/xray-snapshots/restore?snapshot_id=N        → 把指定历史 snapshot 下发到 agent
type XraySnapshotHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
}

func NewXraySnapshotHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler) *XraySnapshotHandler {
	return &XraySnapshotHandler{repo: repo, remoteManage: rm}
}

func (h *XraySnapshotHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/xray-snapshots/")
	switch path {
	case "recovery-status":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleRecoveryStatus(w, r)
	case "recovery-apply":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleRecoveryApply(w, r)
	case "recovery-accept":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleRecoveryAccept(w, r)
	case "list":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleList(w, r)
	case "restore":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleRestore(w, r)
	case "expect-recovery":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleExpectRecovery(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleExpectRecovery: 用户在 UI 点恢复 Popover 时调用,登记"下次 agent 连上请自动下发 last snapshot"。
// in-memory flag,主控重启清空。
func (h *XraySnapshotHandler) handleExpectRecovery(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerIDQuery(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	h.remoteManage.SetExpectRecovery(serverID)
	log.Printf("[XraySnapshot] server=%d expect_recovery marker set", serverID)
	respondJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func parseServerIDQuery(r *http.Request) (int64, error) {
	raw := r.URL.Query().Get("server_id")
	if raw == "" {
		return 0, errors.New("server_id required")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid server_id")
	}
	return id, nil
}

func (h *XraySnapshotHandler) handleRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerIDQuery(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	pending, perr := h.repo.GetPendingXrayRecovery(r.Context(), serverID)
	if perr != nil {
		writeJSONError(w, http.StatusInternalServerError, perr.Error())
		return
	}
	current, cerr := h.repo.GetCurrentXraySnapshot(r.Context(), serverID)
	if cerr != nil {
		writeJSONError(w, http.StatusInternalServerError, cerr.Error())
		return
	}

	// with_config=true 时返回完整 config_json — 用于前端 dialog 渲染 diff。
	// 默认不带(banner 15s 轮询不需要拉几十 KB 配置),只在用户打开决策 dialog 时显式请求一次。
	withConfig := r.URL.Query().Get("with_config") == "true"

	resp := map[string]interface{}{
		"has_pending": pending != nil,
		"has_current": current != nil,
	}
	if pending != nil {
		entry := map[string]interface{}{
			"id":          pending.ID,
			"config_hash": pending.ConfigHash,
			"source":      pending.Source,
			"created_at":  pending.CreatedAt,
		}
		if withConfig {
			entry["config_json"] = pending.ConfigJSON
		}
		resp["pending"] = entry
	}
	if current != nil {
		entry := map[string]interface{}{
			"id":          current.ID,
			"config_hash": current.ConfigHash,
			"source":      current.Source,
			"created_at":  current.CreatedAt,
		}
		if withConfig {
			entry["config_json"] = current.ConfigJSON
		}
		resp["current"] = entry
	}
	respondJSON(w, http.StatusOK, resp)
}

// handleRecoveryApply: 用 master DB current snapshot 覆盖 agent xray config。
// 路径:test → PUT /api/child/xray/config → 成功后丢弃 pending(若有)。
// 失败:agent 端 test 不通过 → 把详细错误回给前端,不写 agent。
func (h *XraySnapshotHandler) handleRecoveryApply(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerIDQuery(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	current, cerr := h.repo.GetCurrentXraySnapshot(r.Context(), serverID)
	if cerr != nil {
		writeJSONError(w, http.StatusInternalServerError, cerr.Error())
		return
	}
	if current == nil {
		writeBadRequest(w, "no current snapshot to restore")
		return
	}
	if err := h.applyConfigToAgent(r, serverID, current.ConfigJSON); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// 成功 → 丢 pending(如果有)
	_ = h.repo.DiscardPendingXrayRecovery(r.Context(), serverID)
	log.Printf("[XraySnapshot] server=%d recovery-apply ok (restored hash=%s)", serverID, shortHash(current.ConfigHash))
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"applied_id":  current.ID,
		"config_hash": current.ConfigHash,
	})
}

// handleRecoveryAccept: 用户在 UI 选"接受 agent 当前配置" → 把 pending 升级为 current,旧 current 置 old。
// 不调 agent — agent 端配置本来就是 pending 的内容。
func (h *XraySnapshotHandler) handleRecoveryAccept(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerIDQuery(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if aerr := h.repo.AcceptPendingXrayRecovery(r.Context(), serverID); aerr != nil {
		writeJSONError(w, http.StatusBadRequest, aerr.Error())
		return
	}
	log.Printf("[XraySnapshot] server=%d recovery-accept ok", serverID)
	respondJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (h *XraySnapshotHandler) handleList(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerIDQuery(r)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	limit := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, _ := strconv.Atoi(l); n > 0 {
			limit = n
		}
	}
	list, lerr := h.repo.ListXraySnapshots(r.Context(), serverID, limit)
	if lerr != nil {
		writeJSONError(w, http.StatusInternalServerError, lerr.Error())
		return
	}
	// 前端不需要每一条都传 config_json(动辄几十 KB),按需通过 ?with_config=true 拿
	withConfig := r.URL.Query().Get("with_config") == "true"
	items := make([]map[string]interface{}, 0, len(list))
	for _, s := range list {
		entry := map[string]interface{}{
			"id":          s.ID,
			"config_hash": s.ConfigHash,
			"source":      s.Source,
			"status":      s.Status,
			"created_at":  s.CreatedAt,
			"size_bytes":  len(s.ConfigJSON),
		}
		if withConfig {
			entry["config_json"] = s.ConfigJSON
		}
		items = append(items, entry)
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"total": len(items),
	})
}

// handleRestore: 把指定历史 snapshot 下发到 agent。test → PUT。不动 snapshot 表的状态
// (restore 后 master 写后 refresh hook 会自动把"现在的 agent 配置"upsert 成新 current,
//
//	原来的 current 自然变 old —— 选中的历史 snapshot 在 history 列表里仍叫 old)。
func (h *XraySnapshotHandler) handleRestore(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("snapshot_id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "invalid snapshot_id")
		return
	}
	snap, gerr := h.repo.GetXraySnapshotByID(r.Context(), id)
	if gerr != nil {
		writeJSONError(w, http.StatusInternalServerError, gerr.Error())
		return
	}
	if snap == nil {
		writeBadRequest(w, "snapshot not found")
		return
	}
	if err := h.applyConfigToAgent(r, snap.ServerID, snap.ConfigJSON); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("[XraySnapshot] server=%d restore snapshot id=%d hash=%s ok", snap.ServerID, snap.ID, shortHash(snap.ConfigHash))
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"server_id":   snap.ServerID,
		"config_hash": snap.ConfigHash,
	})
}

// applyConfigToAgent: test → PUT /api/child/xray/config → restart xray。
// test 失败 / PUT 失败 / restart 失败 → 返回 wrapped error,调用方 4xx 给前端。
// agent 端 setXrayConfig 只写盘不重启,所以下发完必须显式 restart 让新配置生效,
// 否则用户在 UI 看到"恢复成功"但 agent 实际还在跑旧配置 — 跟其他下发路径(deploy_tunnel
// / deploy_fallback / remote_reality_domains)的"PUT + restartXrayWithRecovery"约定一致。
func (h *XraySnapshotHandler) applyConfigToAgent(r *http.Request, serverID int64, configJSON string) error {
	ctx, release, err := h.repo.AcquireRemoteServerMutationLease(r.Context(), serverID)
	if err != nil {
		return err
	}
	defer release()

	// 1) agent test-config 验证
	testBody, _ := json.Marshal(map[string]string{"config": configJSON})
	raw, err := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/xray/test-config", testBody)
	if err != nil {
		return fmt.Errorf("agent test-config failed: %w", err)
	}
	var testResp struct {
		Ok     bool   `json:"ok"`
		Error  string `json:"error"`
		Output string `json:"output"`
		Method string `json:"method"`
	}
	if jerr := json.Unmarshal(raw, &testResp); jerr != nil {
		return fmt.Errorf("agent test-config response parse: %w", jerr)
	}
	if !testResp.Ok {
		// 把 xray 原始错误带回前端
		detail := testResp.Error
		if testResp.Output != "" {
			detail = detail + " | " + testResp.Output
		}
		return fmt.Errorf("xray config test failed (%s): %s", testResp.Method, detail)
	}

	// 2) PUT config(setXrayConfig 默认会再 test 一次,这里 force=true 跳过 — 上面已经测过)
	putBody, _ := json.Marshal(map[string]interface{}{"config": configJSON, "force": true})
	if _, perr := h.remoteManage.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/xray/config", putBody); perr != nil {
		return fmt.Errorf("agent PUT config failed: %w", perr)
	}

	// 3) restart xray 让新配置生效
	if rerr := h.remoteManage.restartXrayWithRecovery(ctx, serverID, "XraySnapshotApply"); rerr != nil {
		return fmt.Errorf("agent restart xray failed: %w", rerr)
	}
	return nil
}
