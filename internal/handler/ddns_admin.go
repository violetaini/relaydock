package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/ddns"
	"github.com/violetaini/relaydock/internal/storage"
)

// DDNSAdminHandler 暴露 DDNS 状态查询 + 手动触发 API
type DDNSAdminHandler struct {
	repo    *storage.TrafficRepository
	manager *ddns.Manager
}

func NewDDNSAdminHandler(repo *storage.TrafficRepository, manager *ddns.Manager) *DDNSAdminHandler {
	return &DDNSAdminHandler{repo: repo, manager: manager}
}

func (h *DDNSAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 路径形如 /api/admin/servers/{id}/ddns-status 或 /api/admin/servers/{id}/ddns-test
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/servers/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	idStr, action := parts[0], parts[1]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid server id")
		return
	}

	switch action {
	case "ddns-status":
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.handleStatus(w, r, id)
	case "ddns-test":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.handleTest(w, r, id)
	default:
		writeJSONError(w, http.StatusNotFound, "not found")
	}
}

func (h *DDNSAdminHandler) handleStatus(w http.ResponseWriter, r *http.Request, id int64) {
	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			writeJSONError(w, http.StatusNotFound, "server not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// 拼一个 DNS provider 名(若已配置 + 有匹配)给 Tooltip 显示用
	providerName := ""
	providerID := server.DDNSProviderID
	if providerID == 0 && server.DDNSEnabled {
		// 自动模式 — 查匹配证书
		if cert, cerr := h.repo.FindCertificateForDomain(r.Context(), server.PullAddress); cerr == nil {
			providerID = cert.DNSProviderID
		}
	}
	if providerID > 0 {
		if dp, perr := h.repo.GetDNSProvider(r.Context(), providerID); perr == nil {
			providerName = dp.Name + " (" + dp.ProviderType + ")"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":             true,
		"id":                  server.ID,
		"name":                server.Name,
		"ddns_enabled":        server.DDNSEnabled,
		"ddns_provider_id":    server.DDNSProviderID,
		"ddns_provider_name":  providerName,
		"ddns_last_synced_at": server.DDNSLastSyncedAt,
		"ddns_last_error":     server.DDNSLastError,
		"ddns_pending":        server.DDNSPending,
		"pull_address":        server.PullAddress,
		"ip_address":          server.IPAddress,
		"ip_address_v6":       server.IPAddressV6,
	})
}

func (h *DDNSAdminHandler) handleTest(w http.ResponseWriter, r *http.Request, id int64) {
	if h.manager == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "DDNS manager not initialized")
		return
	}
	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			writeJSONError(w, http.StatusNotFound, "server not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !server.DDNSEnabled {
		writeJSONError(w, http.StatusBadRequest, "DDNS not enabled for this server")
		return
	}
	// 异步触发,立即返回。前端通过定时 poll ddns-status 拿到 pending/success/fail
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		h.manager.Trigger(ctx, server)
	}()
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "DDNS sync triggered"})
}
