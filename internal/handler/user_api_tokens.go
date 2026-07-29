package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

// 每用户 API 令牌管理(供 MCP / 程序化访问)。明文仅创建时返回一次。
// GET    /api/user/api-tokens        列出当前用户的令牌(元数据,无明文)
// POST   /api/user/api-tokens        创建一枚新令牌,返回明文(仅此一次)
// DELETE /api/user/api-tokens/{id}   吊销当前用户名下的令牌
type userAPITokensHandler struct {
	repo *storage.TrafficRepository
}

func NewUserAPITokensHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("user api tokens handler requires repository")
	}
	return &userAPITokensHandler{repo: repo}
}

func (h *userAPITokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if strings.TrimSpace(username) == "" {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/user/api-tokens")
	rest = strings.Trim(rest, "/")

	switch {
	case rest == "" && r.Method == http.MethodGet:
		h.handleList(w, r, username)
	case rest == "" && r.Method == http.MethodPost:
		h.handleCreate(w, r, username)
	case rest != "" && r.Method == http.MethodDelete:
		h.handleRevoke(w, r, username, rest)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("unsupported method"))
	}
}

func (h *userAPITokensHandler) handleList(w http.ResponseWriter, r *http.Request, username string) {
	tokens, err := h.repo.ListUserAPITokens(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "tokens": tokens})
}

func (h *userAPITokensHandler) handleCreate(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "API Token"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	token, err := h.repo.CreateUserAPIToken(r.Context(), username, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// token 明文仅此一次返回
	respondJSON(w, http.StatusCreated, map[string]any{"success": true, "token": token, "name": name})
}

func (h *userAPITokensHandler) handleRevoke(w http.ResponseWriter, r *http.Request, username, idStr string) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的令牌 ID")
		return
	}
	if err := h.repo.RevokeUserAPIToken(r.Context(), username, id); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true})
}
