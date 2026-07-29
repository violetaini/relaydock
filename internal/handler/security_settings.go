package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/captcha"
	"github.com/violetaini/relaydock/internal/storage"
)

// SecuritySettingsHandler 处理 /api/admin/security-settings 的 GET/PUT。
//
// 9 个 system_settings KV(snake_case,跟现有 `notify_traffic_threshold_percent` 同款风格):
//   - 登录限流:login_rate_max_attempts / login_rate_window_minutes / login_rate_lock_minutes
//   - 暴力防护:brute_force_enabled / brute_force_max_failures / brute_force_window_minutes / brute_force_block_minutes
//   - 订阅频率:sub_rate_enabled / sub_rate_limit / sub_rate_window_minutes
//
// PUT 写完后调 GetLoginRateLimiter().UpdateConfig / GetBruteForceProtector().UpdateConfig /
// GetSubscriptionRateLimiter().UpdateConfig 热更新,无需重启主控。

type securitySettingsResponse struct {
	LoginRateMaxAttempts    int  `json:"login_rate_max_attempts"`
	LoginRateWindowMinutes  int  `json:"login_rate_window_minutes"`
	LoginRateLockMinutes    int  `json:"login_rate_lock_minutes"`
	BruteForceEnabled       bool `json:"brute_force_enabled"`
	BruteForceMaxFailures   int  `json:"brute_force_max_failures"`
	BruteForceWindowMinutes int  `json:"brute_force_window_minutes"`
	BruteForceBlockMinutes  int  `json:"brute_force_block_minutes"`
	SubRateEnabled          bool `json:"sub_rate_enabled"`
	SubRateLimit            int  `json:"sub_rate_limit"`
	SubRateWindowMinutes    int  `json:"sub_rate_window_minutes"`
	// SkipLocalIP 命中本地/私有/loopback IP 时,跳过封禁与频率限制,
	// 防反代/docker 未传 XFF 时一次封禁打死所有真实用户。
	SkipLocalIP bool `json:"skip_local_ip"`

	// Cloudflare Turnstile 人机验证(登录页)。两 key 都填才启用,任一空 → 自动降级跳过。
	// GET 时 secret_key 走 maskSecret() 输出 `xxxx****yyyy`,前端 PUT 把 mask 占位回传时 writeSecurityKVs 跳过该字段。
	TurnstileSiteKey   string `json:"turnstile_site_key"`
	TurnstileSecretKey string `json:"turnstile_secret_key"`
}

// 默认值 — 跟 NewXxxProtector hardcoded 默认值一致,KV 缺失时返回这套。
var securityDefaults = securitySettingsResponse{
	LoginRateMaxAttempts:    5,
	LoginRateWindowMinutes:  60,
	LoginRateLockMinutes:    60,
	BruteForceEnabled:       true,
	BruteForceMaxFailures:   5,
	BruteForceWindowMinutes: 1440,
	BruteForceBlockMinutes:  1440,
	SubRateEnabled:          true,
	SubRateLimit:            60,
	SubRateWindowMinutes:    1,
	SkipLocalIP:             true,
	TurnstileSiteKey:        "",
	TurnstileSecretKey:      "",
}

type SecuritySettingsHandler struct {
	repo *storage.TrafficRepository
}

func NewSecuritySettingsHandler(repo *storage.TrafficRepository) *SecuritySettingsHandler {
	return &SecuritySettingsHandler{repo: repo}
}

func (h *SecuritySettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
	case http.MethodPut, http.MethodPost:
		h.handlePut(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *SecuritySettingsHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	resp := LoadSecuritySettings(r.Context(), h.repo)
	respondJSON(w, http.StatusOK, resp)
}

func (h *SecuritySettingsHandler) handlePut(w http.ResponseWriter, r *http.Request) {
	var payload securitySettingsResponse
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if msg := validateSecurityPayload(&payload); msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}

	// 批量写 KV(任一失败就回 500,前端会重试)
	if err := writeSecurityKVs(r.Context(), h.repo, &payload); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}

	// 热更新 3 个单例 — 立即生效不需要重启
	if rl := GetLoginRateLimiter(); rl != nil {
		rl.UpdateConfig(payload.LoginRateMaxAttempts, payload.LoginRateWindowMinutes, payload.LoginRateLockMinutes)
	}
	if bfp := GetBruteForceProtector(); bfp != nil {
		bfp.UpdateConfig(payload.BruteForceEnabled, payload.BruteForceMaxFailures, payload.BruteForceWindowMinutes, payload.BruteForceBlockMinutes)
	}
	if srl := GetSubscriptionRateLimiter(); srl != nil {
		srl.UpdateConfig(payload.SubRateEnabled, payload.SubRateLimit, payload.SubRateWindowMinutes)
	}
	// skip_local_ip 单独走 Set 接口,避免 3 个 UpdateConfig 签名扩散
	if rl := GetLoginRateLimiter(); rl != nil {
		rl.SetSkipLocalIP(payload.SkipLocalIP)
	}
	if bfp := GetBruteForceProtector(); bfp != nil {
		bfp.SetSkipLocalIP(payload.SkipLocalIP)
	}
	if srl := GetSubscriptionRateLimiter(); srl != nil {
		srl.SetSkipLocalIP(payload.SkipLocalIP)
	}
	log.Printf("[SecuritySettings] thresholds updated: login=%d/%dmin/%dmin brute=%v/%d/%dmin/%dmin sub=%v/%d/%dmin skip_local_ip=%v",
		payload.LoginRateMaxAttempts, payload.LoginRateWindowMinutes, payload.LoginRateLockMinutes,
		payload.BruteForceEnabled, payload.BruteForceMaxFailures, payload.BruteForceWindowMinutes, payload.BruteForceBlockMinutes,
		payload.SubRateEnabled, payload.SubRateLimit, payload.SubRateWindowMinutes,
		payload.SkipLocalIP)

	respondJSON(w, http.StatusOK, payload)
}

func validateSecurityPayload(p *securitySettingsResponse) string {
	checks := map[string]int{
		"login_rate_max_attempts":    p.LoginRateMaxAttempts,
		"login_rate_window_minutes":  p.LoginRateWindowMinutes,
		"login_rate_lock_minutes":    p.LoginRateLockMinutes,
		"brute_force_max_failures":   p.BruteForceMaxFailures,
		"brute_force_window_minutes": p.BruteForceWindowMinutes,
		"brute_force_block_minutes":  p.BruteForceBlockMinutes,
		"sub_rate_limit":             p.SubRateLimit,
		"sub_rate_window_minutes":    p.SubRateWindowMinutes,
	}
	for name, v := range checks {
		if v <= 0 {
			return fmt.Sprintf("%s must be > 0", name)
		}
	}
	// Turnstile sitekey 合法值是 24 位定长(真 key 0x... / 测试 key 1x|2x|3x...)。
	// 这里拦明显非法的短值,主要防浏览器密码管理器把用户名("admin")自动填进 sitekey 文本框、
	// 再被 onBlur 静默存盘 → enabled=true → 用非法 sitekey 渲染 widget 把管理员锁在登录页外。
	if sk := strings.TrimSpace(p.TurnstileSiteKey); sk != "" && len(sk) < 20 {
		return "turnstile_site_key 格式不正确(疑似浏览器自动填充误填);如未使用人机验证请留空"
	}
	return ""
}

// LoadSecuritySettings 从 system_settings 读 9 个 KV,缺失/非法值 fallback 到 securityDefaults。
// 启动时 main.go 也调它来初始化限流器。
func LoadSecuritySettings(ctx context.Context, repo *storage.TrafficRepository) securitySettingsResponse {
	resp := securityDefaults
	if repo == nil {
		return resp
	}

	resp.LoginRateMaxAttempts = readIntSetting(ctx, repo, "login_rate_max_attempts", resp.LoginRateMaxAttempts)
	resp.LoginRateWindowMinutes = readIntSetting(ctx, repo, "login_rate_window_minutes", resp.LoginRateWindowMinutes)
	resp.LoginRateLockMinutes = readIntSetting(ctx, repo, "login_rate_lock_minutes", resp.LoginRateLockMinutes)
	resp.BruteForceEnabled = readBoolSetting(ctx, repo, "brute_force_enabled", resp.BruteForceEnabled)
	resp.BruteForceMaxFailures = readIntSetting(ctx, repo, "brute_force_max_failures", resp.BruteForceMaxFailures)
	resp.BruteForceWindowMinutes = readIntSetting(ctx, repo, "brute_force_window_minutes", resp.BruteForceWindowMinutes)
	resp.BruteForceBlockMinutes = readIntSetting(ctx, repo, "brute_force_block_minutes", resp.BruteForceBlockMinutes)
	resp.SubRateEnabled = readBoolSetting(ctx, repo, "sub_rate_enabled", resp.SubRateEnabled)
	resp.SubRateLimit = readIntSetting(ctx, repo, "sub_rate_limit", resp.SubRateLimit)
	resp.SubRateWindowMinutes = readIntSetting(ctx, repo, "sub_rate_window_minutes", resp.SubRateWindowMinutes)
	resp.SkipLocalIP = readBoolSetting(ctx, repo, "skip_local_ip", resp.SkipLocalIP)
	resp.TurnstileSiteKey = readStringSetting(ctx, repo, "turnstile_site_key", "")
	// secret_key 输出 mask,不直接吐明文给前端(虽然是 admin auth,但避免 devtools/日志泄露)
	resp.TurnstileSecretKey = maskSecret(readStringSetting(ctx, repo, "turnstile_secret_key", ""))
	return resp
}

func readStringSetting(ctx context.Context, repo *storage.TrafficRepository, key, fallback string) string {
	v, err := repo.GetSystemSetting(ctx, key)
	if err != nil {
		return fallback
	}
	return v
}

// maskSecret 输出 `xxxx****yyyy` — 前 4 + 后 4 字符,中间 ****。短 secret(<12)返回 `****`,
// 空字符串原样返回 `""`,前端据此判断"未配置"。PUT 时 isMaskedSecret 识别这个占位避免误写。
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) < 12 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

func isMaskedSecret(s string) bool {
	return strings.Contains(s, "****")
}

func writeSecurityKVs(ctx context.Context, repo *storage.TrafficRepository, p *securitySettingsResponse) error {
	pairs := map[string]string{
		"login_rate_max_attempts":    strconv.Itoa(p.LoginRateMaxAttempts),
		"login_rate_window_minutes":  strconv.Itoa(p.LoginRateWindowMinutes),
		"login_rate_lock_minutes":    strconv.Itoa(p.LoginRateLockMinutes),
		"brute_force_enabled":        strconv.FormatBool(p.BruteForceEnabled),
		"brute_force_max_failures":   strconv.Itoa(p.BruteForceMaxFailures),
		"brute_force_window_minutes": strconv.Itoa(p.BruteForceWindowMinutes),
		"brute_force_block_minutes":  strconv.Itoa(p.BruteForceBlockMinutes),
		"sub_rate_enabled":           strconv.FormatBool(p.SubRateEnabled),
		"sub_rate_limit":             strconv.Itoa(p.SubRateLimit),
		"sub_rate_window_minutes":    strconv.Itoa(p.SubRateWindowMinutes),
		"skip_local_ip":              strconv.FormatBool(p.SkipLocalIP),
		"turnstile_site_key":         strings.TrimSpace(p.TurnstileSiteKey),
	}
	for k, v := range pairs {
		if err := repo.SetSystemSetting(ctx, k, v); err != nil {
			return fmt.Errorf("set %s: %w", k, err)
		}
	}
	// secret_key 特殊处理:收到 mask 占位(`xxxx****yyyy`)表示前端没改,保留原值不动。
	// 真要清空 secret → 把 site_key 留空即可触发 Turnstile.Enabled()=false 整体降级。
	secret := strings.TrimSpace(p.TurnstileSecretKey)
	if secret != "" && !isMaskedSecret(secret) {
		if err := repo.SetSystemSetting(ctx, "turnstile_secret_key", secret); err != nil {
			return fmt.Errorf("set turnstile_secret_key: %w", err)
		}
	} else if secret == "" {
		// 主动清空(纯空串,跟 mask 占位区分):清掉 secret_key
		if err := repo.SetSystemSetting(ctx, "turnstile_secret_key", ""); err != nil {
			return fmt.Errorf("clear turnstile_secret_key: %w", err)
		}
	}
	return nil
}

func readIntSetting(ctx context.Context, repo *storage.TrafficRepository, key string, fallback int) int {
	v, err := repo.GetSystemSetting(ctx, key)
	if err != nil || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func readBoolSetting(ctx context.Context, repo *storage.TrafficRepository, key string, fallback bool) bool {
	v, err := repo.GetSystemSetting(ctx, key)
	if err != nil || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// TurnstileTestHandler 接收前端"测试当前 turnstile 配置是否正确"的 widget token。
// 后端用 DB 里已保存的 secret_key 调 cloudflare siteverify,返回完整结果(含 error_codes / hostname)
// 给前端做诊断 — 用户填完两 key 不再担心"登录页用不了才发现配错"。
//
// 路由:POST /api/admin/security-settings/turnstile/test
// Body: {"token": "<widget 拿到的 token>"}
// Resp: {"success": bool, "error_codes": [...], "hostname": "...", "skipped": bool}
type TurnstileTestHandler struct {
	verifier *captcha.Turnstile
}

func NewTurnstileTestHandler(verifier *captcha.Turnstile) *TurnstileTestHandler {
	return &TurnstileTestHandler{verifier: verifier}
}

func (h *TurnstileTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.verifier == nil {
		writeJSONError(w, http.StatusInternalServerError, "turnstile verifier not configured")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	result, err := h.verifier.VerifyDetailed(r.Context(), req.Token, GetClientIP(r))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "cloudflare siteverify failed: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, result)
}
