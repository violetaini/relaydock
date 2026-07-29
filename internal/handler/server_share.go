package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/storage"
)

// 服务器分享:拥有方为某台 remote_server 生成/管理分享令牌,
// 其他 RelayDock 主控凭令牌通过 /api/federation/* 间接管理该服务器。

type ServerShareHandler struct {
	repo              *storage.TrafficRepository
	capabilityManager *capabilities.Manager
}

func NewServerShareHandler(repo *storage.TrafficRepository, manager *capabilities.Manager) *ServerShareHandler {
	return &ServerShareHandler{repo: repo, capabilityManager: manager}
}

func hashShareToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h *ServerShareHandler) enabled() bool {
	if h.capabilityManager == nil {
		return false
	}
	return h.capabilityManager.HasFeature(capabilities.FeatureServerShare)
}

func (h *ServerShareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.enabled() {
		writeError(w, http.StatusForbidden, errors.New("当前构建未启用服务器分享"))
		return
	}

	switch {
	case r.URL.Path == "/api/admin/server-share/create" && r.Method == http.MethodPost:
		h.handleCreate(w, r)
	case r.URL.Path == "/api/admin/server-share/list" && r.Method == http.MethodGet:
		h.handleList(w, r)
	case r.URL.Path == "/api/admin/server-share/revoke" && r.Method == http.MethodPost:
		h.handleRevoke(w, r)
	default:
		writeError(w, http.StatusNotFound, errors.New("not found"))
	}
}

func (h *ServerShareHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID int64  `json:"server_id"`
		Label    string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServerID <= 0 {
		writeError(w, http.StatusBadRequest, errors.New("server_id required"))
		return
	}
	// 校验服务器存在
	if _, err := h.repo.GetRemoteServer(r.Context(), req.ServerID); err != nil {
		writeError(w, http.StatusNotFound, errors.New("server not found"))
		return
	}

	token, err := generateSecureToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	id, err := h.repo.CreateSharedServer(r.Context(), req.ServerID, hashShareToken(token), req.Label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// share_token 只在创建时明文返回一次
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":          id,
		"server_id":   req.ServerID,
		"share_token": token,
	})
}

func (h *ServerShareHandler) handleList(w http.ResponseWriter, r *http.Request) {
	serverID, _ := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if serverID <= 0 {
		writeError(w, http.StatusBadRequest, errors.New("server_id required"))
		return
	}
	shares, err := h.repo.ListSharedServers(r.Context(), serverID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"shares": shares})
}

func (h *ServerShareHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		writeError(w, http.StatusBadRequest, errors.New("id required"))
		return
	}
	if err := h.repo.RevokeSharedServer(r.Context(), req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "revoked"})
}
