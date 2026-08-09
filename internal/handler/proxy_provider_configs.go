package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

// ProxyProviderConfigsHandler 提供普通用户 / 管理员管理自己的"代理集合"(Clash proxy-provider)配置。
// 全部走 RequireToken,内部按 username 做数据隔离;admin 也只能看 / 改自己创建的(不跨用户)。
//
// 路由: /api/user/proxy-provider-configs
//   - GET                              → 列表(只返当前用户的)
//   - POST  body=ProxyProviderConfigDTO → 创建
//   - PUT   ?id=X body=ProxyProviderConfigDTO → 更新(必须属于当前用户)
//   - DELETE ?id=X                      → 删除(必须属于当前用户)
type ProxyProviderConfigsHandler struct {
	repo *storage.TrafficRepository
}

func NewProxyProviderConfigsHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("proxy provider configs handler requires repository")
	}
	return &ProxyProviderConfigsHandler{repo: repo}
}

// ProxyProviderConfigDTO 跟前端 snake_case 字段一一对应。
type ProxyProviderConfigDTO struct {
	ID                        int64     `json:"id"`
	Username                  string    `json:"username,omitempty"`
	ExternalSubscriptionID    int64     `json:"external_subscription_id"`
	Name                      string    `json:"name"`
	Type                      string    `json:"type"`
	Interval                  int       `json:"interval"`
	Proxy                     string    `json:"proxy"`
	SizeLimit                 int       `json:"size_limit"`
	Header                    string    `json:"header"`
	HealthCheckEnabled        bool      `json:"health_check_enabled"`
	HealthCheckURL            string    `json:"health_check_url"`
	HealthCheckInterval       int       `json:"health_check_interval"`
	HealthCheckTimeout        int       `json:"health_check_timeout"`
	HealthCheckLazy           bool      `json:"health_check_lazy"`
	HealthCheckExpectedStatus int       `json:"health_check_expected_status"`
	Filter                    string    `json:"filter"`
	ExcludeFilter             string    `json:"exclude_filter"`
	ExcludeType               string    `json:"exclude_type"`
	GeoIPFilter               string    `json:"geo_ip_filter"`
	Override                  string    `json:"override"`
	ProcessMode               string    `json:"process_mode"`
	CreatedAt                 time.Time `json:"created_at,omitempty"`
	UpdatedAt                 time.Time `json:"updated_at,omitempty"`
}

func toDTO(c storage.ProxyProviderConfig) ProxyProviderConfigDTO {
	return ProxyProviderConfigDTO{
		ID:                        c.ID,
		Username:                  c.Username,
		ExternalSubscriptionID:    c.ExternalSubscriptionID,
		Name:                      c.Name,
		Type:                      c.Type,
		Interval:                  c.Interval,
		Proxy:                     c.Proxy,
		SizeLimit:                 c.SizeLimit,
		Header:                    c.Header,
		HealthCheckEnabled:        c.HealthCheckEnabled,
		HealthCheckURL:            c.HealthCheckURL,
		HealthCheckInterval:       c.HealthCheckInterval,
		HealthCheckTimeout:        c.HealthCheckTimeout,
		HealthCheckLazy:           c.HealthCheckLazy,
		HealthCheckExpectedStatus: c.HealthCheckExpectedStatus,
		Filter:                    c.Filter,
		ExcludeFilter:             c.ExcludeFilter,
		ExcludeType:               c.ExcludeType,
		GeoIPFilter:               c.GeoIPFilter,
		Override:                  c.Override,
		ProcessMode:               c.ProcessMode,
		CreatedAt:                 c.CreatedAt,
		UpdatedAt:                 c.UpdatedAt,
	}
}

func (d ProxyProviderConfigDTO) toStorage(username string) *storage.ProxyProviderConfig {
	return &storage.ProxyProviderConfig{
		ID:                        d.ID,
		Username:                  username, // 强制覆盖,避免 body 伪造别人的 username
		ExternalSubscriptionID:    d.ExternalSubscriptionID,
		Name:                      strings.TrimSpace(d.Name),
		Type:                      d.Type,
		Interval:                  d.Interval,
		Proxy:                     d.Proxy,
		SizeLimit:                 d.SizeLimit,
		Header:                    d.Header,
		HealthCheckEnabled:        d.HealthCheckEnabled,
		HealthCheckURL:            d.HealthCheckURL,
		HealthCheckInterval:       d.HealthCheckInterval,
		HealthCheckTimeout:        d.HealthCheckTimeout,
		HealthCheckLazy:           d.HealthCheckLazy,
		HealthCheckExpectedStatus: d.HealthCheckExpectedStatus,
		Filter:                    d.Filter,
		ExcludeFilter:             d.ExcludeFilter,
		ExcludeType:               d.ExcludeType,
		GeoIPFilter:               d.GeoIPFilter,
		Override:                  d.Override,
		ProcessMode:               d.ProcessMode,
	}
}

func (h *ProxyProviderConfigsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleList(w, r, username)
	case http.MethodPost:
		h.handleCreate(w, r, username)
	case http.MethodPut:
		h.handleUpdate(w, r, username)
	case http.MethodDelete:
		h.handleDelete(w, r, username)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("only GET / POST / PUT / DELETE are supported"))
	}
}

func (h *ProxyProviderConfigsHandler) handleList(w http.ResponseWriter, r *http.Request, username string) {
	configs, err := h.repo.ListProxyProviderConfigs(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]ProxyProviderConfigDTO, 0, len(configs))
	for _, c := range configs {
		out = append(out, toDTO(c))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (h *ProxyProviderConfigsHandler) handleCreate(w http.ResponseWriter, r *http.Request, username string) {
	var dto ProxyProviderConfigDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	if strings.TrimSpace(dto.Name) == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}
	if !h.requireOwnedExternalSubscription(w, r, dto.ExternalSubscriptionID, username) {
		return
	}
	cfg := dto.toStorage(username)
	id, err := h.repo.CreateProxyProviderConfig(r.Context(), cfg)
	if err != nil {
		if errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
			writeError(w, http.StatusNotFound, errors.New("external subscription not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	cfg.ID = id
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toDTO(*cfg))
}

func (h *ProxyProviderConfigsHandler) handleUpdate(w http.ResponseWriter, r *http.Request, username string) {
	id, err := parseIDQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// 必须属于当前用户(数据隔离)
	existing, err := h.repo.GetProxyProviderConfig(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if existing.Username != username {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}

	var dto ProxyProviderConfigDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	if !h.requireOwnedExternalSubscription(w, r, dto.ExternalSubscriptionID, username) {
		return
	}
	dto.ID = id
	// username 始终来自认证上下文；来源订阅可切换，但必须属于同一用户。
	cfg := dto.toStorage(username)
	cfg.ID = id

	if err := h.repo.UpdateProxyProviderConfig(r.Context(), cfg); err != nil {
		if errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
			writeError(w, http.StatusNotFound, errors.New("external subscription not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toDTO(*cfg))
}

func (h *ProxyProviderConfigsHandler) requireOwnedExternalSubscription(w http.ResponseWriter, r *http.Request, id int64, username string) bool {
	if id <= 0 {
		writeError(w, http.StatusBadRequest, errors.New("external_subscription_id must be greater than zero"))
		return false
	}

	if _, err := h.repo.GetExternalSubscription(r.Context(), id, username); err != nil {
		if errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
			// GetExternalSubscription 同时按 ID 和 owner 查询，故不存在与他人资源对外呈现相同结果。
			writeError(w, http.StatusNotFound, errors.New("external subscription not found"))
			return false
		}
		writeError(w, http.StatusInternalServerError, err)
		return false
	}

	return true
}

func (h *ProxyProviderConfigsHandler) handleDelete(w http.ResponseWriter, r *http.Request, username string) {
	id, err := parseIDQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// DeleteProxyProviderConfig 内部校验 username,这里再 pre-check 一道返回更合适的状态码。
	existing, err := h.repo.GetProxyProviderConfig(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if existing.Username != username {
		writeError(w, http.StatusForbidden, errors.New("该操作仅可对自己创建的代理集合进行"))
		return
	}
	if err := h.repo.DeleteProxyProviderConfig(r.Context(), id, username); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func parseIDQuery(r *http.Request) (int64, error) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		return 0, errors.New("id is required")
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}
