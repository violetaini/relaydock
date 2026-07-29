package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type userTokenHandler struct {
	repo *storage.TrafficRepository
}

type userTokenResponse struct {
	Token               string `json:"token"`
	UserShortCode       string `json:"user_short_code,omitempty"`        // 有效短码(自定义优先,自定义为空时回退到自动)
	CustomUserShortCode string `json:"custom_user_short_code,omitempty"` // 自定义短码(可空,留空时使用自动)
}

// 返回一个经过身份验证的处理程序，用于检索和重置用户令牌。
func NewUserTokenHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("user token handler requires repository")
	}

	return &userTokenHandler{repo: repo}
}

func (h *userTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r, username)
	case http.MethodPost:
		h.handleReset(w, r, username)
	case http.MethodPut:
		h.handleUpdateShortCode(w, r, username)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("only GET / POST / PUT are supported"))
	}
}

// handleUpdateShortCode PUT /api/user/token  body: {"custom_user_short_code": "abc"}
// 修改当前用户自己的 custom_user_short_code(任何已认证用户都能改自己的;不能改别人的)
// 空字符串 = 清空自定义短码,恢复用自动 user_short_code
func (h *userTokenHandler) handleUpdateShortCode(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		CustomUserShortCode string `json:"custom_user_short_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	// 越权防护:不能跟其它用户的 username / 有效短码撞,也不能用系统保留字。
	if err := validateCustomUserShortCode(r.Context(), h.repo, req.CustomUserShortCode, username); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.repo.UpdateUserCustomShortCode(r.Context(), username, req.CustomUserShortCode); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// 返回更新后的完整状态(token + 新有效短码 + 新 custom 短码)
	token, _ := h.repo.GetOrCreateUserToken(r.Context(), username)
	respondWithTokenBundle(w, h.repo, r, token, username)
}

func (h *userTokenHandler) handleGet(w http.ResponseWriter, r *http.Request, username string) {
	token, err := h.repo.GetOrCreateUserToken(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	respondWithTokenBundle(w, h.repo, r, token, username)
}

func (h *userTokenHandler) handleReset(w http.ResponseWriter, r *http.Request, username string) {
	token, err := h.repo.ResetUserToken(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	respondWithTokenBundle(w, h.repo, r, token, username)
}

func respondWithTokenBundle(w http.ResponseWriter, repo *storage.TrafficRepository, r *http.Request, token, username string) {
	effective, _ := repo.GetEffectiveUserShortCode(r.Context(), username)
	customCode, _ := repo.GetUserCustomShortCode(r.Context(), username)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(userTokenResponse{
		Token:               token,
		UserShortCode:       effective,
		CustomUserShortCode: customCode,
	})
}
