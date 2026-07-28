// remote_warp.go — master 端 WARP 出站管理 API,转发到 agent /api/child/warp/*。
// 复用 RemoteManageHandler.forwardToRemoteServer(WS RPC 优先 → HTTP fallback)。

package handler

import (
	"context"
	"io"
	"net/http"
	"strconv"
)

// HandleWarpInstall POST /api/admin/remote/warp/install?server_id=N
// 让 agent 注册 Cloudflare WARP + 注入 warp-v4 / warp-v6 双 outbound。
func (h *RemoteManageHandler) HandleWarpInstall(w http.ResponseWriter, r *http.Request) {
	id, ok := parseWarpServerID(w, r, http.MethodPost)
	if !ok {
		return
	}
	ctx, release, ok := h.acquireWarpMutationLease(w, r.Context(), id)
	if !ok {
		return
	}
	defer release()
	result, err := h.forwardToRemoteServer(ctx, id, http.MethodPost, "/api/child/warp/install", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeWarpResult(w, result)
}

// HandleWarpStatus GET /api/admin/remote/warp/status?server_id=N
func (h *RemoteManageHandler) HandleWarpStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := parseWarpServerID(w, r, http.MethodGet)
	if !ok {
		return
	}
	result, err := h.forwardToRemoteServer(r.Context(), id, http.MethodGet, "/api/child/warp/status", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeWarpResult(w, result)
}

// HandleWarpLicense POST /api/admin/remote/warp/license?server_id=N
// body 透传到 agent: {"license":"..."}
func (h *RemoteManageHandler) HandleWarpLicense(w http.ResponseWriter, r *http.Request) {
	id, ok := parseWarpServerID(w, r, http.MethodPost)
	if !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "read body failed")
		return
	}
	ctx, release, ok := h.acquireWarpMutationLease(w, r.Context(), id)
	if !ok {
		return
	}
	defer release()
	result, err := h.forwardToRemoteServer(ctx, id, http.MethodPost, "/api/child/warp/license", body)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeWarpResult(w, result)
}

// HandleWarpRemove POST /api/admin/remote/warp/remove?server_id=N
// 注销 Cloudflare 账号 + 删除本地状态 + 移除 xray outbound。
func (h *RemoteManageHandler) HandleWarpRemove(w http.ResponseWriter, r *http.Request) {
	id, ok := parseWarpServerID(w, r, http.MethodPost)
	if !ok {
		return
	}
	ctx, release, ok := h.acquireWarpMutationLease(w, r.Context(), id)
	if !ok {
		return
	}
	defer release()
	result, err := h.forwardToRemoteServer(ctx, id, http.MethodPost, "/api/child/warp/remove", nil)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeWarpResult(w, result)
}

func (h *RemoteManageHandler) acquireWarpMutationLease(w http.ResponseWriter, ctx context.Context, serverID int64) (context.Context, func(), bool) {
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, serverID)
	if err != nil {
		remoteWriteForwardError(w, err)
		return nil, nil, false
	}
	return leasedCtx, release, true
}

// parseWarpServerID 共享的 server_id 校验。expectedMethod 不匹配时返回 405。
func parseWarpServerID(w http.ResponseWriter, r *http.Request, expectedMethod string) (int64, bool) {
	if r.Method != expectedMethod {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return 0, false
	}
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return 0, false
	}
	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return 0, false
	}
	return id, true
}

func writeWarpResult(w http.ResponseWriter, result []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}
