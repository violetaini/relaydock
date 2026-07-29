package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type userConfigRequest struct {
	ForceSyncExternal       bool     `json:"force_sync_external"`
	MatchRule               string   `json:"match_rule"`
	SyncScope               string   `json:"sync_scope"`
	KeepNodeName            bool     `json:"keep_node_name"`
	CacheExpireMinutes      int      `json:"cache_expire_minutes"`
	SyncTraffic             bool     `json:"sync_traffic"`
	NodeNameFilter          string   `json:"node_name_filter"`
	AppendSubInfo           bool     `json:"append_sub_info"`
	CustomRulesEnabled      bool     `json:"custom_rules_enabled"`
	EnableShortLink         bool     `json:"enable_short_link"`
	UseNewTemplateSystem    *bool    `json:"use_new_template_system"` // nil表示不提供，默认true
	EnableProxyProvider     bool     `json:"enable_proxy_provider"`
	NodeOrder               *[]int64 `json:"node_order"` // 指针:nil=未提供(如系统设置页)→保留原值,非nil=覆盖。防止其它设置页误清节点顺序
	ProxyGroupsSourceURL    string   `json:"proxy_groups_source_url"`
	ClientCompatibilityMode bool     `json:"client_compatibility_mode"` // 自动过滤客户端不兼容的节点
}

type userConfigResponse struct {
	ForceSyncExternal       bool    `json:"force_sync_external"`
	MatchRule               string  `json:"match_rule"`
	SyncScope               string  `json:"sync_scope"`
	KeepNodeName            bool    `json:"keep_node_name"`
	CacheExpireMinutes      int     `json:"cache_expire_minutes"`
	SyncTraffic             bool    `json:"sync_traffic"`
	NodeNameFilter          string  `json:"node_name_filter"`
	AppendSubInfo           bool    `json:"append_sub_info"`
	CustomRulesEnabled      bool    `json:"custom_rules_enabled"`
	EnableShortLink         bool    `json:"enable_short_link"`
	UseNewTemplateSystem    bool    `json:"use_new_template_system"`
	EnableProxyProvider     bool    `json:"enable_proxy_provider"`
	NodeOrder               []int64 `json:"node_order"` // 节点显示顺序（节点 ID 数组）
	ProxyGroupsSourceURL    string  `json:"proxy_groups_source_url"`
	ClientCompatibilityMode bool    `json:"client_compatibility_mode"` // 自动过滤客户端不兼容的节点
}

func NewUserConfigHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("user config handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := auth.UsernameFromContext(r.Context())
		if strings.TrimSpace(username) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}

		switch r.Method {
		case http.MethodGet:
			handleGetUserConfig(w, r, repo, username)
		case http.MethodPut:
			handleUpdateUserConfig(w, r, repo, username)
		default:
			writeError(w, http.StatusMethodNotAllowed, errors.New("only GET and PUT are supported"))
		}
	})
}

func handleGetUserConfig(w http.ResponseWriter, r *http.Request, repo *storage.TrafficRepository, username string) {
	// 获取系统配置
	systemConfig, err := repo.GetSystemConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("get system config: %w", err))
		return
	}

	settings, err := repo.GetUserSettings(r.Context(), username)
	if err != nil {
		if errors.Is(err, storage.ErrUserSettingsNotFound) {
			// 如果找不到则返回默认设置(NodeOrder 用 admin 排序作 fallback)
			resp := userConfigResponse{
				ForceSyncExternal:       false,
				MatchRule:               "node_name",
				SyncScope:               "saved_only",
				KeepNodeName:            true,
				CacheExpireMinutes:      0,
				SyncTraffic:             false,
				NodeNameFilter:          "剩余|流量|到期|订阅|时间|重置",
				AppendSubInfo:           false,
				CustomRulesEnabled:      true, // 自定义规则始终启用
				EnableShortLink:         false,
				UseNewTemplateSystem:    true, // 默认使用新模板系统
				EnableProxyProvider:     false,
				NodeOrder:               computeFallbackNodeOrder(r.Context(), repo, username),
				ProxyGroupsSourceURL:    systemConfig.ProxyGroupsSourceURL,
				ClientCompatibilityMode: systemConfig.ClientCompatibilityMode,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// NodeOrder 空时:沿用最早 admin 用户的排序,过滤掉当前用户看不见的节点 ID。
	// 用户首次进节点管理页面就能看到跟管理员一致的顺序,而不是"按 created_at desc 一锅乱"。
	nodeOrder := settings.NodeOrder
	if len(nodeOrder) == 0 {
		nodeOrder = computeFallbackNodeOrder(r.Context(), repo, username)
	}

	resp := userConfigResponse{
		ForceSyncExternal:       settings.ForceSyncExternal,
		MatchRule:               settings.MatchRule,
		SyncScope:               settings.SyncScope,
		KeepNodeName:            settings.KeepNodeName,
		CacheExpireMinutes:      settings.CacheExpireMinutes,
		SyncTraffic:             settings.SyncTraffic,
		NodeNameFilter:          settings.NodeNameFilter,
		AppendSubInfo:           settings.AppendSubInfo,
		CustomRulesEnabled:      true, // 自定义规则始终启用
		EnableShortLink:         settings.EnableShortLink,
		UseNewTemplateSystem:    settings.UseNewTemplateSystem,
		EnableProxyProvider:     settings.EnableProxyProvider,
		NodeOrder:               nodeOrder,
		ProxyGroupsSourceURL:    systemConfig.ProxyGroupsSourceURL,
		ClientCompatibilityMode: systemConfig.ClientCompatibilityMode,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// computeFallbackNodeOrder 返回最早 admin 用户的 NodeOrder 经过"当前 user 可见节点"过滤的结果。
// 用于普通用户第一次进节点管理 / 未自定义排序时,沿用 admin 已调好的顺序,而不是按 created_at 的杂乱顺序。
// 返回空数组的情况:用户自己就是 admin / 找不到 admin / admin 自己也没排过 / 没有可见节点。
func computeFallbackNodeOrder(ctx context.Context, repo *storage.TrafficRepository, username string) []int64 {
	empty := []int64{}
	if repo == nil || username == "" {
		return empty
	}
	// 找最早创建的 admin 用户(ListUsers ORDER BY created_at ASC)
	users, err := repo.ListUsers(ctx, 1000)
	if err != nil {
		return empty
	}
	var adminUsername string
	for _, u := range users {
		if u.Role == storage.RoleAdmin && u.Username != username {
			adminUsername = u.Username
			break
		}
	}
	if adminUsername == "" {
		return empty
	}
	// 拿 admin 的 NodeOrder
	adminSettings, err := repo.GetUserSettings(ctx, adminUsername)
	if err != nil || len(adminSettings.NodeOrder) == 0 {
		return empty
	}
	// 当前用户可见节点 ID 集合
	visible := gatherUserVisibleNodeIDs(ctx, repo, username)
	if len(visible) == 0 {
		return empty
	}
	// 按 admin 顺序过滤
	filtered := make([]int64, 0, len(adminSettings.NodeOrder))
	for _, id := range adminSettings.NodeOrder {
		if visible[id] {
			filtered = append(filtered, id)
		}
	}
	return filtered
}

// gatherUserVisibleNodeIDs 返回 user 能在节点管理里看到的所有节点 ID 集合 = 自己导入 + 绑定套餐节点。
// 跟 nodesHandler.handleList 普通用户分支保持一致;权限收敛点,排序 fallback 也要复用同一口径。
func gatherUserVisibleNodeIDs(ctx context.Context, repo *storage.TrafficRepository, username string) map[int64]bool {
	set := make(map[int64]bool)
	if nodes, err := repo.ListNodes(ctx, username); err == nil {
		for _, n := range nodes {
			set[n.ID] = true
		}
	}
	if user, err := repo.GetUser(ctx, username); err == nil && user.PackageID > 0 {
		if pkg, err := repo.GetPackage(ctx, user.PackageID); err == nil && pkg != nil {
			for _, nid := range pkg.Nodes {
				set[nid] = true
			}
		}
	}
	return set
}

func handleUpdateUserConfig(w http.ResponseWriter, r *http.Request, repo *storage.TrafficRepository, username string) {
	var payload userConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 验证匹配规则
	matchRule := strings.TrimSpace(payload.MatchRule)
	if matchRule == "" {
		matchRule = "node_name"
	}
	if matchRule != "node_name" && matchRule != "server_port" && matchRule != "type_server_port" {
		writeError(w, http.StatusBadRequest, errors.New("match_rule must be 'node_name', 'server_port', or 'type_server_port'"))
		return
	}

	// 验证同步范围
	syncScope := strings.TrimSpace(payload.SyncScope)
	if syncScope == "" {
		syncScope = "saved_only"
	}
	if syncScope != "saved_only" && syncScope != "all" {
		writeError(w, http.StatusBadRequest, errors.New("sync_scope must be 'saved_only' or 'all'"))
		return
	}

	// 验证缓存过期分钟
	cacheExpireMinutes := payload.CacheExpireMinutes
	if cacheExpireMinutes < 0 {
		cacheExpireMinutes = 0
	}

	// 处理use_new_template_system，如果没有提供则默认为true
	useNewTemplateSystem := true
	if payload.UseNewTemplateSystem != nil {
		useNewTemplateSystem = *payload.UseNewTemplateSystem
	}

	// 验证并清理代理组源 URL
	proxyGroupsSourceURL := strings.TrimSpace(payload.ProxyGroupsSourceURL)
	if err := validateProxyGroupsSourceURL(proxyGroupsSourceURL); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// node_order 用指针区分"未提供"与"显式清空":系统设置页等不管节点顺序的调用不会带 node_order,
	// payload.NodeOrder==nil 时必须保留已存顺序,否则整行 upsert 会把它清空 → 节点管理页乱序(与旁边
	// system_config "先读全量再改" 同理)。非 nil(节点管理页拖拽排序)才覆盖。
	nodeOrder := []int64{}
	if payload.NodeOrder != nil {
		nodeOrder = *payload.NodeOrder
	} else if existing, err := repo.GetUserSettings(r.Context(), username); err == nil {
		nodeOrder = existing.NodeOrder
	}

	settings := storage.UserSettings{
		Username:             username,
		ForceSyncExternal:    payload.ForceSyncExternal,
		MatchRule:            matchRule,
		SyncScope:            syncScope,
		KeepNodeName:         payload.KeepNodeName,
		CacheExpireMinutes:   cacheExpireMinutes,
		SyncTraffic:          payload.SyncTraffic,
		NodeNameFilter:       payload.NodeNameFilter,
		AppendSubInfo:        payload.AppendSubInfo,
		CustomRulesEnabled:   true, // 自定义规则始终启用
		EnableShortLink:      payload.EnableShortLink,
		UseNewTemplateSystem: useNewTemplateSystem,
		EnableProxyProvider:  payload.EnableProxyProvider,
		NodeOrder:            nodeOrder,
	}

	if err := repo.UpsertUserSettings(r.Context(), settings); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 只更新 system_config 的这两项。必须先读全量再改,否则 UpdateSystemConfig 会把其它系统设置
	// (短链接 / 通知 / 各间隔 / 静默模式 / 管理功能 / 默认模板 …)全部清零 —— 这正是"系统设置概率性重置"的根因。
	systemConfig, err := repo.GetSystemConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("get system config: %w", err))
		return
	}
	systemConfig.ProxyGroupsSourceURL = proxyGroupsSourceURL
	systemConfig.ClientCompatibilityMode = payload.ClientCompatibilityMode
	if err := repo.UpdateSystemConfig(r.Context(), systemConfig); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("update system config: %w", err))
		return
	}

	resp := userConfigResponse{
		ForceSyncExternal:       settings.ForceSyncExternal,
		MatchRule:               settings.MatchRule,
		SyncScope:               settings.SyncScope,
		KeepNodeName:            settings.KeepNodeName,
		CacheExpireMinutes:      settings.CacheExpireMinutes,
		SyncTraffic:             settings.SyncTraffic,
		NodeNameFilter:          settings.NodeNameFilter,
		AppendSubInfo:           settings.AppendSubInfo,
		CustomRulesEnabled:      true, // 自定义规则始终启用
		EnableShortLink:         settings.EnableShortLink,
		UseNewTemplateSystem:    settings.UseNewTemplateSystem,
		EnableProxyProvider:     settings.EnableProxyProvider,
		NodeOrder:               settings.NodeOrder,
		ProxyGroupsSourceURL:    proxyGroupsSourceURL,
		ClientCompatibilityMode: payload.ClientCompatibilityMode,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// validateProxyGroupsSourceURL 验证代理组远程地址的合法性
// 空字符串是合法的(表示使用默认或环境变量配置)
func validateProxyGroupsSourceURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}

	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("proxy_groups_source_url 格式无效: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return errors.New("proxy_groups_source_url 仅支持 http 或 https 协议")
	}

	return nil
}
