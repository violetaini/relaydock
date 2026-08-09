package handler

import (
	"encoding/json"
	"errors"
	"github.com/violetaini/relaydock/internal/logger"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/safefetch"
	"github.com/violetaini/relaydock/internal/storage"
)

type externalSubscriptionRequest struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	UserAgent   string `json:"user_agent"`
	TrafficMode string `json:"traffic_mode"` // 流量统计方式: "download", "upload", "both"
}

type externalSubscriptionResponse struct {
	ID          int64   `json:"id"`
	Username    string  `json:"username"` // owner;管理员列表视图展示归属用户,普通用户即自己
	Name        string  `json:"name"`
	URL         string  `json:"url"`
	UserAgent   string  `json:"user_agent"`
	NodeCount   int     `json:"node_count"`
	LastSyncAt  *string `json:"last_sync_at"`
	Upload      int64   `json:"upload"`       // 已上传流量（字节）
	Download    int64   `json:"download"`     // 已下载流量（字节）
	Total       int64   `json:"total"`        // 总流量（字节）
	Expire      *string `json:"expire"`       // 过期时间
	TrafficMode string  `json:"traffic_mode"` // 流量统计方式: "download", "upload", "both"
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

func NewExternalSubscriptionsHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("external subscriptions handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := auth.UsernameFromContext(r.Context())
		if strings.TrimSpace(username) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		// 管理员可查看/编辑/删除所有用户的外部订阅;普通用户仅限自己的(照 nodes.go 的 isAdmin 分支)。
		isAdmin := userIsAdmin(r.Context(), repo, username)

		switch r.Method {
		case http.MethodGet:
			handleListExternalSubscriptions(w, r, repo, username, isAdmin)
		case http.MethodPost:
			handleCreateExternalSubscription(w, r, repo, username)
		case http.MethodPut:
			handleUpdateExternalSubscription(w, r, repo, username, isAdmin)
		case http.MethodDelete:
			handleDeleteExternalSubscription(w, r, repo, username, isAdmin)
		default:
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		}
	})
}

// fetchExternalSubForAccess 管理员按 ID 取任意订阅,普通用户按 (id, 自己) 取。
func fetchExternalSubForAccess(r *http.Request, repo *storage.TrafficRepository, id int64, username string, isAdmin bool) (storage.ExternalSubscription, error) {
	if isAdmin {
		return repo.GetExternalSubscriptionByID(r.Context(), id)
	}
	return repo.GetExternalSubscription(r.Context(), id, username)
}

// updateExternalSubForAccess 管理员按 ID 更新(owner 不变),普通用户按 owner 作用域更新。
func updateExternalSubForAccess(r *http.Request, repo *storage.TrafficRepository, sub storage.ExternalSubscription, isAdmin bool) error {
	if isAdmin {
		return repo.UpdateExternalSubscriptionByID(r.Context(), sub)
	}
	return repo.UpdateExternalSubscription(r.Context(), sub)
}

// deleteExternalSubForAccess 管理员按 ID 删除,普通用户按 owner 作用域删除。
func deleteExternalSubForAccess(r *http.Request, repo *storage.TrafficRepository, id int64, username string, isAdmin bool) error {
	if isAdmin {
		return repo.DeleteExternalSubscriptionByID(r.Context(), id)
	}
	return repo.DeleteExternalSubscription(r.Context(), id, username)
}

func handleListExternalSubscriptions(w http.ResponseWriter, r *http.Request, repo *storage.TrafficRepository, username string, isAdmin bool) {
	var subs []storage.ExternalSubscription
	var err error
	if isAdmin {
		subs, err = repo.ListAllExternalSubscriptions(r.Context()) // 管理员看全部(含 owner)
	} else {
		subs, err = repo.ListExternalSubscriptions(r.Context(), username)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := make([]externalSubscriptionResponse, 0, len(subs))
	for _, sub := range subs {
		var lastSyncAt *string
		if sub.LastSyncAt != nil {
			formatted := sub.LastSyncAt.Format(time.RFC3339)
			lastSyncAt = &formatted
		}

		var expire *string
		if sub.Expire != nil {
			formatted := sub.Expire.Format(time.RFC3339)
			expire = &formatted
		}

		resp = append(resp, externalSubscriptionResponse{
			ID:          sub.ID,
			Username:    sub.Username,
			Name:        sub.Name,
			URL:         sub.URL,
			UserAgent:   sub.UserAgent,
			NodeCount:   sub.NodeCount,
			LastSyncAt:  lastSyncAt,
			Upload:      sub.Upload,
			Download:    sub.Download,
			Total:       sub.Total,
			Expire:      expire,
			TrafficMode: sub.TrafficMode,
			CreatedAt:   sub.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   sub.UpdatedAt.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func handleCreateExternalSubscription(w http.ResponseWriter, r *http.Request, repo *storage.TrafficRepository, username string) {
	var payload externalSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	name := strings.TrimSpace(payload.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, errors.New("subscription name is required"))
		return
	}

	url := strings.TrimSpace(payload.URL)
	if url == "" {
		writeError(w, http.StatusBadRequest, errors.New("subscription url is required"))
		return
	}

	// 获取订阅以获取交通信息
	var trafficUpload, trafficDownload, trafficTotal int64
	var trafficExpire *time.Time

	userAgent := payload.UserAgent
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}

	client := safefetch.NewClient(30*time.Second, maxSubscriptionBytes)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		logger.Info("[外部订阅] 创建请求失败", "name", name, "error", sanitizeSubscriptionRequestError(err))
	} else {
		req.Header.Set("User-Agent", userAgent)
		logger.Info("[外部订阅] 获取流量信息", "name", name)
		resp, err := client.Do(req)
		if err != nil {
			logger.Info("[外部订阅] 请求失败", "name", name, "error", sanitizeSubscriptionRequestError(err))
		} else {
			defer resp.Body.Close()
			logger.Info("[外部订阅] 响应状态", "name", name, "status_code", resp.StatusCode)
			if resp.StatusCode == http.StatusOK {
				// 解析订阅用户信息标头以获取流量信息
				userInfo := resp.Header.Get("subscription-userinfo")
				if userInfo != "" {
					trafficUpload, trafficDownload, trafficTotal, trafficExpire = ParseTrafficInfoHeader(userInfo)
					logger.Info("[外部订阅] 解析流量信息", "upload", trafficUpload, "download", trafficDownload, "total", trafficTotal)
				}
			}
		}
	}

	now := time.Now()
	sub := storage.ExternalSubscription{
		Username:    username,
		Name:        name,
		URL:         url,
		UserAgent:   payload.UserAgent,   // 会在存储层使用默认值如果为空
		TrafficMode: payload.TrafficMode, // 会在存储层使用默认值如果为空
		NodeCount:   0,
		LastSyncAt:  &now,
		Upload:      trafficUpload,
		Download:    trafficDownload,
		Total:       trafficTotal,
		Expire:      trafficExpire,
	}

	id, err := repo.CreateExternalSubscription(r.Context(), sub)
	if err != nil {
		if errors.Is(err, storage.ErrExternalSubscriptionExists) {
			writeError(w, http.StatusConflict, errors.New("subscription with this URL already exists"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	created, err := repo.GetExternalSubscription(r.Context(), id, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var lastSyncAt *string
	if created.LastSyncAt != nil {
		formatted := created.LastSyncAt.Format(time.RFC3339)
		lastSyncAt = &formatted
	}

	var expire *string
	if created.Expire != nil {
		formatted := created.Expire.Format(time.RFC3339)
		expire = &formatted
	}

	resp := externalSubscriptionResponse{
		ID:          created.ID,
		Name:        created.Name,
		URL:         created.URL,
		UserAgent:   created.UserAgent,
		NodeCount:   created.NodeCount,
		LastSyncAt:  lastSyncAt,
		Upload:      created.Upload,
		Download:    created.Download,
		Total:       created.Total,
		Expire:      expire,
		TrafficMode: created.TrafficMode,
		CreatedAt:   created.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   created.UpdatedAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func handleUpdateExternalSubscription(w http.ResponseWriter, r *http.Request, repo *storage.TrafficRepository, username string, isAdmin bool) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, errors.New("subscription id is required"))
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid subscription id"))
		return
	}

	var payload externalSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	name := strings.TrimSpace(payload.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, errors.New("subscription name is required"))
		return
	}

	url := strings.TrimSpace(payload.URL)
	if url == "" {
		writeError(w, http.StatusBadRequest, errors.New("subscription url is required"))
		return
	}

	existing, err := fetchExternalSubForAccess(r, repo, id, username, isAdmin)
	if err != nil {
		if errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
			writeError(w, http.StatusNotFound, errors.New("subscription not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 如果没有传 TrafficMode，保留现有的
	trafficMode := payload.TrafficMode
	if trafficMode == "" {
		trafficMode = existing.TrafficMode
	}

	sub := storage.ExternalSubscription{
		ID:          id,
		Username:    existing.Username, // 保持原 owner(管理员改他人订阅时不能把 owner 改成自己)
		Name:        name,
		URL:         url,
		UserAgent:   payload.UserAgent, // 会在存储层使用默认值如果为空
		TrafficMode: trafficMode,
		NodeCount:   existing.NodeCount,
		LastSyncAt:  existing.LastSyncAt,
		Upload:      existing.Upload,
		Download:    existing.Download,
		Total:       existing.Total,
		Expire:      existing.Expire,
	}

	if err := updateExternalSubForAccess(r, repo, sub, isAdmin); err != nil {
		if errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
			writeError(w, http.StatusNotFound, errors.New("subscription not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	updated, err := fetchExternalSubForAccess(r, repo, id, username, isAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var lastSyncAt *string
	if updated.LastSyncAt != nil {
		formatted := updated.LastSyncAt.Format(time.RFC3339)
		lastSyncAt = &formatted
	}

	var expire *string
	if updated.Expire != nil {
		formatted := updated.Expire.Format(time.RFC3339)
		expire = &formatted
	}

	resp := externalSubscriptionResponse{
		ID:          updated.ID,
		Username:    updated.Username,
		Name:        updated.Name,
		URL:         updated.URL,
		UserAgent:   updated.UserAgent,
		NodeCount:   updated.NodeCount,
		LastSyncAt:  lastSyncAt,
		Upload:      updated.Upload,
		Download:    updated.Download,
		Total:       updated.Total,
		Expire:      expire,
		TrafficMode: updated.TrafficMode,
		CreatedAt:   updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   updated.UpdatedAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func handleDeleteExternalSubscription(w http.ResponseWriter, r *http.Request, repo *storage.TrafficRepository, username string, isAdmin bool) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, errors.New("subscription id is required"))
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid subscription id"))
		return
	}

	if err := deleteExternalSubForAccess(r, repo, id, username, isAdmin); err != nil {
		if errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
			writeError(w, http.StatusNotFound, errors.New("subscription not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// 返回一个处理程序，该处理程序列出来自外部订阅的节点名称
func NewExternalSubscriptionNodesHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}

		username := auth.UsernameFromContext(r.Context())
		if strings.TrimSpace(username) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}

		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			writeError(w, http.StatusBadRequest, errors.New("subscription id is required"))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid subscription id"))
			return
		}

		// 获取外部订阅
		sub, err := repo.GetExternalSubscription(r.Context(), id, username)
		if err != nil {
			if errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
				writeError(w, http.StatusNotFound, errors.New("subscription not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// 获取节点信息列表（名称和服务器地址）
		nodes, err := fetchSubscriptionNodes(&sub)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// 提取节点名称
		nodeNames := make([]string, len(nodes))
		for i, node := range nodes {
			nodeNames[i] = node.Name
		}

		logger.Info("[外部订阅节点] 返回节点列表", "subscription", sub.Name, "count", len(nodeNames))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node_names": nodeNames,
			"nodes":      nodes,
			"count":      len(nodes),
		})
	})
}

// 返回一个处理程序，用于检查过滤器是否与任何节点匹配
func NewExternalSubscriptionCheckFilterHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}

		username := auth.UsernameFromContext(r.Context())
		if strings.TrimSpace(username) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}

		var req struct {
			SubscriptionID int64  `json:"subscription_id"`
			Filter         string `json:"filter"`
			ExcludeFilter  string `json:"exclude_filter"`
			GeoIPFilter    string `json:"geo_ip_filter"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// 获取外部订阅
		sub, err := repo.GetExternalSubscription(r.Context(), req.SubscriptionID, username)
		if err != nil {
			if errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
				writeError(w, http.StatusNotFound, errors.New("subscription not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// 检查过滤条件是否有匹配的节点
		matchCount, err := checkFilterMatches(&sub, req.Filter, req.ExcludeFilter, req.GeoIPFilter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"has_matches": matchCount > 0,
			"match_count": matchCount,
		})
	})
}
