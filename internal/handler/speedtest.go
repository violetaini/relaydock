package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/speedtest"
	"github.com/violetaini/relaydock/internal/storage"
)

// 节点测速(Phase 1:主控本机用 mihomo 内核测单节点)。

type SpeedTestHandler struct {
	repo              *storage.TrafficRepository
	capabilityManager *capabilities.Manager
	testerWS          *SpeedTesterWSHandler // 家用测速端(Phase 2);nil 时只支持本机测速
}

func NewSpeedTestHandler(repo *storage.TrafficRepository, manager *capabilities.Manager) *SpeedTestHandler {
	return &SpeedTestHandler{repo: repo, capabilityManager: manager}
}

// SetTesterWS 注入家用测速端 WS handler,启用"经家用测速端测速"。
func (h *SpeedTestHandler) SetTesterWS(t *SpeedTesterWSHandler) { h.testerWS = t }

func (h *SpeedTestHandler) enabled() bool {
	if h.capabilityManager == nil {
		return false
	}
	return h.capabilityManager.HasFeature(capabilities.FeatureSpeedTest)
}

func (h *SpeedTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.enabled() {
		writeError(w, http.StatusForbidden, errors.New("当前构建未启用节点测速"))
		return
	}
	switch {
	case r.URL.Path == "/api/admin/speedtest/run" && r.Method == http.MethodPost:
		h.handleRun(w, r)
	case r.URL.Path == "/api/admin/speedtest/results" && r.Method == http.MethodGet:
		h.handleResults(w, r)
	case r.URL.Path == "/api/admin/speedtest/mihomo-status" && r.Method == http.MethodGet:
		ready, path := speedtest.MihomoStatus()
		respondJSON(w, http.StatusOK, map[string]any{"success": true, "ready": ready, "path": path})
	case r.URL.Path == "/api/admin/speedtest/testers" && r.Method == http.MethodGet:
		h.handleTestersList(w, r)
	case r.URL.Path == "/api/admin/speedtest/testers/create" && r.Method == http.MethodPost:
		h.handleTesterCreate(w, r)
	case r.URL.Path == "/api/admin/speedtest/testers/revoke" && r.Method == http.MethodPost:
		h.handleTesterRevoke(w, r)
	case r.URL.Path == "/api/admin/speedtest/testers/rotate-token" && r.Method == http.MethodPost:
		h.handleTesterRotateToken(w, r)
	default:
		writeError(w, http.StatusNotFound, errors.New("not found"))
	}
}

func (h *SpeedTestHandler) handleRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID      int64  `json:"node_id"`
		Bytes       int64  `json:"bytes,omitempty"`
		URL         string `json:"url,omitempty"`
		TesterID    int64  `json:"tester_id,omitempty"`    // >0 = 经家用测速端测;否则主控本机
		Threads     int    `json:"threads,omitempty"`      // 并发下载线程数(默认 1)
		LatencyOnly bool   `json:"latency_only,omitempty"` // true 仅测真连接延迟(Cloudflare 204)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID <= 0 {
		writeBadRequest(w, "node_id 必填")
		return
	}
	ctx := r.Context()
	node, err := h.repo.GetNodeByID(ctx, req.NodeID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("节点不存在"))
		return
	}
	if node.ClashConfig == "" {
		writeBadRequest(w, "该节点无 clash 配置,无法测速")
		return
	}

	// 经家用测速端时先校验其已启用,避免起一个注定失败的后台任务
	source := "master_local"
	if req.TesterID > 0 {
		if h.testerWS == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("家用测速端未启用"))
			return
		}
		source = "home_tester"
	}

	// 先落一条 running 记录,立即返回;真正测速在后台异步跑(脱离本 HTTP 请求上下文),
	// 这样用户点完即可离开/切页,测速照常完成并落库,前端轮询结果表即可看到。
	rec := storage.SpeedTestResult{
		NodeID:    node.ID,
		NodeName:  node.NodeName,
		Source:    source,
		TestBytes: req.Bytes,
		TestedBy:  auth.UsernameFromContext(ctx),
		Status:    "running",
	}
	id, ierr := h.repo.InsertSpeedTestResult(ctx, rec)
	if ierr != nil {
		writeError(w, http.StatusInternalServerError, ierr)
		return
	}
	rec.ID = id
	rec.CreatedAt = time.Now()

	go h.runSpeedTestAsync(id, req.TesterID, node.ClashConfig, req.Bytes, req.URL, req.Threads, req.LatencyOnly)

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "result": rec})
}

// runSpeedTestAsync 后台执行测速并回填结果记录。用独立 context(带超时),不受触发请求生命周期影响。
func (h *SpeedTestHandler) runSpeedTestAsync(recID, testerID int64, clashConfig string, bytes int64, url string, threads int, latencyOnly bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if h.capabilityManager != nil && !h.capabilityManager.HasFeature(capabilities.FeatureSpeedTest) {
		_ = h.repo.UpdateSpeedTestResult(ctx, recID, 0, 0, 0, "failed", "tester unreachable", "")
		return
	}

	var res speedtest.Result
	var terr error
	if testerID > 0 {
		res, terr = h.testerWS.Dispatch(ctx, testerID, clashConfig, bytes, url, threads, latencyOnly)
	} else {
		bin, merr := speedtest.EnsureMihomo(ctx)
		if merr != nil {
			terr = merr
		} else {
			res, terr = speedtest.RunNodeTest(ctx, bin, clashConfig, speedtest.Options{
				TestBytes: bytes, TestURL: url, Threads: threads, LatencyOnly: latencyOnly,
			})
		}
	}

	status, errMsg := "ok", ""
	if terr != nil {
		status, errMsg = "failed", terr.Error()
	}
	_ = h.repo.UpdateSpeedTestResult(ctx, recID, res.DownMbps, res.LatencyMs, res.Bytes, status, errMsg, res.EgressIP)
}

func (h *SpeedTestHandler) handleTesterCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	token := hex.EncodeToString(buf)
	id, err := h.repo.CreateSpeedTester(r.Context(), req.Name, hashShareToken(token), auth.UsernameFromContext(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// token 仅此一次返回(只存哈希)
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "id": id, "token": token})
}

func (h *SpeedTestHandler) handleTestersList(w http.ResponseWriter, r *http.Request) {
	list, err := h.repo.ListSpeedTesters(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, t := range list {
		online := h.testerWS != nil && h.testerWS.Online(t.ID)
		out = append(out, map[string]any{
			"id": t.ID, "name": t.Name, "created_by": t.CreatedBy,
			"last_seen": t.LastSeen, "created_at": t.CreatedAt, "online": online,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "testers": out})
}

func (h *SpeedTestHandler) handleTesterRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		writeBadRequest(w, "id 必填")
		return
	}
	if err := h.repo.DeleteSpeedTester(r.Context(), req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handleTesterRotateToken 为指定测速端轮换 token,返回新 token + tester 名称。
// 用于「离线测速端重新展示安装命令」:库里只存 hash,原 token 不可恢复,只能轮换重发。
// 旧 token 同时失效;在线测速端会因 token 不匹配下次重连失败(其实在线就不该用这接口)。
func (h *SpeedTestHandler) handleTesterRotateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		writeBadRequest(w, "id 必填")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	token := hex.EncodeToString(buf)
	if err := h.repo.UpdateSpeedTesterToken(r.Context(), req.ID, hashShareToken(token)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "id": req.ID, "token": token})
}

func (h *SpeedTestHandler) handleResults(w http.ResponseWriter, r *http.Request) {
	// latest=1:每节点最新一条(节点行内徽章用)
	if r.URL.Query().Get("latest") == "1" {
		list, err := h.repo.ListLatestSpeedTestResults(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"success": true, "results": list})
		return
	}
	nodeID, _ := strconv.ParseInt(r.URL.Query().Get("node_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := h.repo.ListSpeedTestResults(r.Context(), nodeID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "results": list})
}
