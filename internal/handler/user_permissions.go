package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

// 用户权限 / 配额功能(全局统一配置,存 system_settings)。
//
// 设计:管理员在「系统设置」配置一份全局策略:
//   - 普通用户可见哪些页面(user_perm_pages, JSON 数组)
//   - 每个普通用户能创建多少模板 / 覆写规则 / 订阅(配额, 0 = 不限)
// 普通用户登录后,前端通过 /api/user/permissions 拿到自己适用的策略(可见页面 + 配额 + 当前已用量)。
//
// 数据隔离(普通用户只看自己创建的)在各资源 handler 里按 created_by/username 过滤,本文件只管"策略 + 配额校验"。

const (
	settingUserPeracmPages    = "user_perm_pages"      // JSON array, e.g. ["subscription","generator","templates","subscribe-files","custom-rules"]
	settingUserQuotaTemplate  = "user_quota_template"  // int 字符串, 0=不限
	settingUserQuotaOverride  = "user_quota_override"  // int
	settingUserQuotaSubscribe = "user_quota_subscribe" // int
	// 路由出站(用户私有,routed_owner='user')开关 + 配额。
	// settingUserRoutedOutboundEnabled: "1" = 开启,其它/未设置 = 关闭(默认关闭)
	// settingUserQuotaRoutedOutbound: 未设置/0 = 默认 2;>0 = 具体上限。不支持"不限"。
	// settingUserRoutedOutboundDailyLimit: 每日操作次数限制(create + delete 之和),
	//   未设置/0 = 默认 5。每次操作都会触发 agent 重启 xray,频次受限避免滥用。
	settingUserRoutedOutboundEnabled    = "user_routed_outbound_enabled"
	settingUserQuotaRoutedOutbound      = "user_quota_routed_outbound"
	settingUserRoutedOutboundDailyLimit = "user_routed_outbound_daily_limit"
	defaultUserQuotaRoutedOutbound      = 2
	defaultUserRoutedOutboundDailyLimit = 5
)

// 合法的可见页面 key(白名单,防止前端传入任意路由)。
var validUserPages = map[string]bool{
	"subscription":    true, // 订阅链接
	"generator":       true, // 生成订阅
	"templates":       true, // 模板管理
	"subscribe-files": true, // 订阅管理
	"custom-rules":    true, // 覆写管理
	"nodes":           true, // 节点管理(普通用户:只读自己导入的+套餐节点、可导入、用于出站)
}

// UserPermissionsConfig 是全局用户权限策略。
type UserPermissionsConfig struct {
	Pages          []string `json:"pages"`          // 普通用户可见页面
	QuotaTemplate  int      `json:"quota_template"` // 0 = 不限
	QuotaOverride  int      `json:"quota_override"`
	QuotaSubscribe int      `json:"quota_subscribe"`
	// 路由出站(用户私有):必须先开启才能创建;未开启时 quota 字段无意义。
	RoutedOutboundEnabled    bool `json:"routed_outbound_enabled"`
	QuotaRoutedOutbound      int  `json:"quota_routed_outbound"`       // 未设置/0 默认 2;>0 具体上限
	DailyLimitRoutedOutbound int  `json:"daily_limit_routed_outbound"` // 每日操作次数(create+delete);未设置/0 默认 5
}

type UserPermissionsHandler struct {
	repo *storage.TrafficRepository
}

func NewUserPermissionsHandler(repo *storage.TrafficRepository) *UserPermissionsHandler {
	return &UserPermissionsHandler{repo: repo}
}

// loadUserPermConfig 从 system_settings 读全局策略(包级,供其他 handler 复用)。
func loadUserPermConfig(ctx context.Context, repo *storage.TrafficRepository) UserPermissionsConfig {
	cfg := UserPermissionsConfig{Pages: []string{}}
	if raw, _ := repo.GetSystemSetting(ctx, settingUserPeracmPages); raw != "" {
		var pages []string
		if json.Unmarshal([]byte(raw), &pages) == nil {
			for _, p := range pages {
				if validUserPages[p] {
					cfg.Pages = append(cfg.Pages, p)
				}
			}
		}
	}
	atoi := func(key string) int {
		if v, _ := repo.GetSystemSetting(ctx, key); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				return n
			}
		}
		return 0
	}
	cfg.QuotaTemplate = atoi(settingUserQuotaTemplate)
	cfg.QuotaOverride = atoi(settingUserQuotaOverride)
	cfg.QuotaSubscribe = atoi(settingUserQuotaSubscribe)
	// 路由出站开关 + 配额
	if raw, _ := repo.GetSystemSetting(ctx, settingUserRoutedOutboundEnabled); raw == "1" {
		cfg.RoutedOutboundEnabled = true
	}
	if v := atoi(settingUserQuotaRoutedOutbound); v > 0 {
		cfg.QuotaRoutedOutbound = v
	} else {
		cfg.QuotaRoutedOutbound = defaultUserQuotaRoutedOutbound
	}
	if v := atoi(settingUserRoutedOutboundDailyLimit); v > 0 {
		cfg.DailyLimitRoutedOutbound = v
	} else {
		cfg.DailyLimitRoutedOutbound = defaultUserRoutedOutboundDailyLimit
	}
	return cfg
}

// userIsAdmin 判断用户是否管理员(admin 不受数据隔离 / 配额限制)。
func userIsAdmin(ctx context.Context, repo *storage.TrafficRepository, username string) bool {
	if username == "" {
		return false
	}
	u, err := repo.GetUser(ctx, username)
	return err == nil && u.Role == storage.RoleAdmin
}

// checkUserQuota 包级配额校验,供各 create handler 调用。admin 不受限。
func checkUserQuota(ctx context.Context, repo *storage.TrafficRepository, username, resource string) error {
	if userIsAdmin(ctx, repo, username) {
		return nil
	}
	cfg := loadUserPermConfig(ctx, repo)
	var used, max int
	switch resource {
	case "template":
		used, _ = repo.CountUserTemplates(ctx, username)
		max = cfg.QuotaTemplate
	case "override":
		// 「覆写」= 覆写脚本(override_scripts) + 覆写规则(custom_rules) 之和
		ovr, _ := repo.CountUserOverrideScripts(ctx, username)
		cr, _ := repo.CountUserCustomRules(ctx, username)
		used = ovr + cr
		max = cfg.QuotaOverride
	case "subscribe":
		used, _ = repo.CountUserSubscribeFiles(ctx, username)
		max = cfg.QuotaSubscribe
	case "routed_outbound":
		if !cfg.RoutedOutboundEnabled {
			return fmt.Errorf("路由出站功能未开放,请联系管理员开启")
		}
		used, _ = repo.CountUserRoutedOutbounds(ctx, username)
		max = cfg.QuotaRoutedOutbound
	default:
		return nil
	}
	if max > 0 && used >= max {
		return fmt.Errorf("已达到%s数量上限 (%d/%d)", quotaLabel(resource), used, max)
	}
	return nil
}

func (h *UserPermissionsHandler) loadConfig(ctx context.Context) UserPermissionsConfig {
	return loadUserPermConfig(ctx, h.repo)
}

// AdminGet 返回当前全局策略(管理员配置 dialog 用)。
func (h *UserPermissionsHandler) AdminGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true, "config": h.loadConfig(r.Context())})
}

// AdminSet 写入全局策略。
func (h *UserPermissionsHandler) AdminSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req UserPermissionsConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	// 过滤非法 page key
	pages := make([]string, 0, len(req.Pages))
	for _, p := range req.Pages {
		if validUserPages[p] {
			pages = append(pages, p)
		}
	}
	pagesJSON, _ := json.Marshal(pages)
	clamp := func(n int) int {
		if n < 0 {
			return 0
		}
		return n
	}
	ctx := r.Context()
	_ = h.repo.SetSystemSetting(ctx, settingUserPeracmPages, string(pagesJSON))
	_ = h.repo.SetSystemSetting(ctx, settingUserQuotaTemplate, strconv.Itoa(clamp(req.QuotaTemplate)))
	_ = h.repo.SetSystemSetting(ctx, settingUserQuotaOverride, strconv.Itoa(clamp(req.QuotaOverride)))
	_ = h.repo.SetSystemSetting(ctx, settingUserQuotaSubscribe, strconv.Itoa(clamp(req.QuotaSubscribe)))
	enabledVal := "0"
	if req.RoutedOutboundEnabled {
		enabledVal = "1"
	}
	_ = h.repo.SetSystemSetting(ctx, settingUserRoutedOutboundEnabled, enabledVal)
	_ = h.repo.SetSystemSetting(ctx, settingUserQuotaRoutedOutbound, strconv.Itoa(clamp(req.QuotaRoutedOutbound)))
	_ = h.repo.SetSystemSetting(ctx, settingUserRoutedOutboundDailyLimit, strconv.Itoa(clamp(req.DailyLimitRoutedOutbound)))
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true})
}

// UserGet 返回当前登录普通用户适用的策略 + 已用量(前端动态菜单 + 配额提示用)。
func (h *UserPermissionsHandler) UserGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	username := auth.UsernameFromContext(ctx)
	cfg := h.loadConfig(ctx)

	// admin 看全部页面(不受策略限制),配额不适用。
	isAdmin := userIsAdmin(ctx, h.repo, username)

	usedTpl, _ := h.repo.CountUserTemplates(ctx, username)
	ovrScripts, _ := h.repo.CountUserOverrideScripts(ctx, username)
	ovrRules, _ := h.repo.CountUserCustomRules(ctx, username)
	usedOvr := ovrScripts + ovrRules // 覆写 = 脚本 + 规则
	usedSub, _ := h.repo.CountUserSubscribeFiles(ctx, username)
	usedRouted, _ := h.repo.CountUserRoutedOutbounds(ctx, username)

	writeJSONResp(w, http.StatusOK, map[string]any{
		"success":                 true,
		"is_admin":                isAdmin,
		"pages":                   cfg.Pages,
		"routed_outbound_enabled": cfg.RoutedOutboundEnabled,
		"quota": map[string]any{
			"template":        map[string]int{"used": usedTpl, "max": cfg.QuotaTemplate},
			"override":        map[string]int{"used": usedOvr, "max": cfg.QuotaOverride},
			"subscribe":       map[string]int{"used": usedSub, "max": cfg.QuotaSubscribe},
			"routed_outbound": map[string]int{"used": usedRouted, "max": cfg.QuotaRoutedOutbound},
		},
	})
}

// 配额校验:供各 create handler 调用。admin 不受配额限制。
// resource: "template" | "override" | "subscribe"。返回 error 非空表示超额(应拒绝创建)。
func (h *UserPermissionsHandler) CheckQuota(ctx context.Context, username, resource string) error {
	return checkUserQuota(ctx, h.repo, username, resource)
}

func quotaLabel(resource string) string {
	switch resource {
	case "template":
		return "模板"
	case "override":
		return "覆写规则"
	case "subscribe":
		return "订阅"
	case "routed_outbound":
		return "路由出站"
	}
	return resource
}

func writeJSONResp(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
