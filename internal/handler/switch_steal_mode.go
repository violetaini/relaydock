package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
)

type switchStealModeRequest struct {
	StealMode string `json:"steal_mode"`
}

func (h *RemoteManageHandler) HandleSwitchStealMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil || id <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var req switchStealModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.StealMode != "default" {
		remoteWriteError(w, http.StatusBadRequest, "接管模式 tunnel 与 fallback 已彻底退役，仅支持标准模式 (default)")
		return
	}

	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}

	oldMode := server.StealMode
	if oldMode == "" {
		oldMode = "tunnel"
	}
	if oldMode == req.StealMode {
		remoteWriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "模式未变更"})
		return
	}

	// A mode change rewrites both Xray and Nginx state. The current Agent cannot
	// atomically snapshot and restore every Nginx file, so fail before mutation.
	remoteWriteError(w, http.StatusConflict, "运行时切换接管模式暂不支持安全回滚；请按目标模式重新安装服务器或重建节点")
}
