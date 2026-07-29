package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/violetaini/relaydock/internal/agentlog"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/traffic"
)

type SystemSettingsHandler struct {
	repo      *storage.TrafficRepository
	crypto    *CryptoConfig
	collector *traffic.Collector // 可选,SetIntervals 时调 hot-reload ticker;nil 时仅落库
	wsHandler *RemoteWSHandler   // 可选,SetDashboardRefresh 后广播 config_update 给所有 WS-mode agent
}

func NewSystemSettingsHandler(repo *storage.TrafficRepository, crypto *CryptoConfig) *SystemSettingsHandler {
	return &SystemSettingsHandler{repo: repo, crypto: crypto}
}

// SetCollector 注入 traffic.Collector 让 SetIntervals 修改间隔后立即热重载 ticker。
// main.go 在创建 collector 之后调用一次。
func (h *SystemSettingsHandler) SetCollector(c *traffic.Collector) { h.collector = c }

// SetWSHandler 注入 WS handler 让 SetDashboardRefresh 后向所有 agent 广播 config_update。
func (h *SystemSettingsHandler) SetWSHandler(ws *RemoteWSHandler) { h.wsHandler = ws }

type GetAPITokenResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

// 返回当前的 API token
func (h *SystemSettingsHandler) GetAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	token, err := h.repo.GetAPIToken(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(GetAPITokenResponse{
			Success: false,
			Message: "获取 API token 失败",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetAPITokenResponse{
		Success: true,
		Token:   token,
	})
}

// 生成新的 API token
func (h *SystemSettingsHandler) RegenerateAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	token, err := h.repo.RegenerateAPIToken(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(GetAPITokenResponse{
			Success: false,
			Message: "重新生成 API token 失败",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetAPITokenResponse{
		Success: true,
		Token:   token,
		Message: "API token 重新生成成功",
	})
}

// 获取主服务器地址
func (h *SystemSettingsHandler) GetMasterURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	value, err := h.repo.GetSystemSetting(r.Context(), "master_url")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取主服务器地址失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "master_url": value})
}

func normalizeMasterURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return "", errors.New("地址不能包含空白或控制字符")
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("地址格式无效: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("地址协议必须为 http 或 https")
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("地址只能包含协议、主机和可选端口")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", errors.New("地址不能包含路径")
	}

	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return "", errors.New("地址缺少主机名")
	}
	ip := net.ParseIP(host)
	if ip == nil && !validMasterHostname(host) {
		return "", errors.New("主机名格式无效")
	}
	if ip != nil {
		host = ip.String()
	}

	port := parsed.Port()
	if port == "" && strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("端口不能为空")
	}
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("端口必须为 1-65535")
		}
		host = net.JoinHostPort(host, port)
	} else if ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

func validMasterHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// defaultMasterScheme keeps loopback development usable without ever placing a
// node bearer token on plaintext transport to a non-loopback host. Reverse
// proxies should configure master_url explicitly; forwarded headers are not
// trusted here because the application may also be reachable directly.
func defaultMasterScheme(host string, hasTLS bool) string {
	if hasTLS {
		return "https"
	}
	hostname := host
	if parsed, err := url.Parse("//" + host); err == nil && parsed.Hostname() != "" {
		hostname = parsed.Hostname()
	}
	hostname = strings.Trim(strings.TrimSpace(hostname), "[]")
	if strings.EqualFold(hostname, "localhost") {
		return "http"
	}
	if ip := net.ParseIP(hostname); ip != nil && ip.IsLoopback() {
		return "http"
	}
	return "https"
}

func masterURLAllowsNodeInstall(normalized string) bool {
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if hostname == "localhost" {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// 设置主服务器地址
func (h *SystemSettingsHandler) SetMasterURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MasterURL string `json:"master_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	normalized, err := normalizeMasterURL(req.MasterURL)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": err.Error()})
		return
	}

	if err := h.repo.SetSystemSetting(r.Context(), "master_url", normalized); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "主服务器地址已更新"})
}

// 伪装探针配置的 4 个 KV 键。
const (
	probeDisguiseEnabledKey   = "probe_disguise_enabled"    // "1"/"" 开关
	probeDisguiseTitleKey     = "probe_disguise_title"      // 伪装页标题(管理员自定义)
	probeDisguiseServerIDsKey = "probe_disguise_server_ids" // JSON int64 数组:展示哪些服务器
	probeDisguiseShowNameKey  = "probe_disguise_show_name"  // "1"/"" 是否显示服务器名
)

// GetProbeDisguise 返回伪装探针配置(管理端)。
func (h *SystemSettingsHandler) GetProbeDisguise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	enabled, _ := h.repo.GetSystemSetting(ctx, probeDisguiseEnabledKey)
	title, _ := h.repo.GetSystemSetting(ctx, probeDisguiseTitleKey)
	showName, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowNameKey)
	idsRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguiseServerIDsKey)

	ids := []int64{}
	if idsRaw != "" {
		_ = json.Unmarshal([]byte(idsRaw), &ids)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":    true,
		"enabled":    enabled == "1",
		"title":      title,
		"server_ids": ids,
		"show_name":  showName == "1",
	})
}

// SetProbeDisguise 写入伪装探针配置(管理端)。
func (h *SystemSettingsHandler) SetProbeDisguise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled   bool    `json:"enabled"`
		Title     string  `json:"title"`
		ServerIDs []int64 `json:"server_ids"`
		ShowName  bool    `json:"show_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	ctx := r.Context()
	boolStr := func(b bool) string {
		if b {
			return "1"
		}
		return ""
	}
	if req.ServerIDs == nil {
		req.ServerIDs = []int64{}
	}
	idsJSON, _ := json.Marshal(req.ServerIDs)

	for _, kv := range []struct{ k, v string }{
		{probeDisguiseEnabledKey, boolStr(req.Enabled)},
		{probeDisguiseTitleKey, req.Title},
		{probeDisguiseShowNameKey, boolStr(req.ShowName)},
		{probeDisguiseServerIDsKey, string(idsJSON)},
	} {
		if err := h.repo.SetSystemSetting(ctx, kv.k, kv.v); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "伪装探针配置已更新"})
}

// defaultRedeemTemplate 兑换码复制文案的默认模板。占位符:
//
//	{兑换码}     — 具体兑换码
//	{机器人地址} — TG 机器人链接(由 tgbot miniapp 端按 getMe 自动注入,如 https://t.me/xxx_bot)
//	{主控域名}   — master_url 完整 URL
const defaultRedeemTemplate = `使用教程
打开这个机器人 {机器人地址}
点左下角我的面板，然后输入兑换码注册
{兑换码}

如果需要自定义出站落地，需要登录 RelayDock
{主控域名}`

// GetRedeemTemplate 返回兑换码复制文案模板;未配置时返回内置默认模板。
func (h *SystemSettingsHandler) GetRedeemTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	value, err := h.repo.GetSystemSetting(r.Context(), "redeem_copy_template")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取兑换码文案失败"})
		return
	}
	if value == "" {
		value = defaultRedeemTemplate
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "redeem_template": value})
}

// SetRedeemTemplate 保存兑换码复制文案模板(多行文本)。
func (h *SystemSettingsHandler) SetRedeemTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RedeemTemplate string `json:"redeem_template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if err := h.repo.SetSystemSetting(r.Context(), "redeem_copy_template", req.RedeemTemplate); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "兑换码文案已更新"})
}

func (h *SystemSettingsHandler) GetShortLinkEnabled(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "enable_short_link": cfg.EnableShortLink})
}

func (h *SystemSettingsHandler) SetShortLinkEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnableShortLink bool `json:"enable_short_link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.EnableShortLink = req.EnableShortLink
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "短链接设置已更新"})
}

// dashboardRefreshKey 是前端 dashboard 轮询间隔的 system_settings key,毫秒。
// 跟 traffic_collect_interval(master collector 内部 polling)解耦:
// agent 5s push 决定数据新鲜度,collector 60s 只是兜底;前端轮询频率是 UX 选项,默认 5000ms。
const dashboardRefreshKey = "dashboard_refresh_interval_ms"
const dashboardRefreshDefault = 5000

// GetPublicIntervals 给所有登录用户(包括普通用户),返回前端 dashboard 应用的轮询间隔(ms)。
func (h *SystemSettingsHandler) GetPublicIntervals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	val, _ := h.repo.GetSystemSetting(r.Context(), dashboardRefreshKey)
	ms := dashboardRefreshDefault
	if val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 1000 && n <= 60000 {
			ms = n
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":             true,
		"refetch_interval_ms": ms,
	})
}

// SetDashboardRefresh admin-only,设置前端 dashboard 轮询间隔(ms)。生效:下次前端拉到该值。
// clamp 到 [1000, 60000] 范围,默认 5000。
func (h *SystemSettingsHandler) SetDashboardRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RefetchIntervalMs int `json:"refetch_interval_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.RefetchIntervalMs < 1000 {
		req.RefetchIntervalMs = 1000
	}
	if req.RefetchIntervalMs > 60000 {
		req.RefetchIntervalMs = 60000
	}
	if err := h.repo.SetSystemSetting(r.Context(), dashboardRefreshKey, strconv.Itoa(req.RefetchIntervalMs)); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	// 同步给所有 agent (用于 traffic 上报 ticker):WS-mode 立即推 config_update,
	// HTTP-mode 通过下次 traffic POST 的 response 携带 (见 RemoteTrafficHandler),
	// Pull-mode 因 master 是 GET agent,无现成回带通道,需要 agent 端轮询/重启生效。
	if h.wsHandler != nil {
		h.wsHandler.BroadcastConfigUpdate(map[string]string{
			"traffic_report_interval_ms": strconv.Itoa(req.RefetchIntervalMs),
		})
	}
	// 主控本机自采也跟随同一个「上报间隔」,与 agent 保持一致(热重载,无需重启)。
	if h.collector != nil {
		h.collector.SetInterval(time.Duration(req.RefetchIntervalMs) * time.Millisecond)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "refetch_interval_ms": req.RefetchIntervalMs})
}

func (h *SystemSettingsHandler) GetIntervals(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	// report_interval(秒):即 dashboard_refresh_interval_ms / 1000,这是会同步给所有 agent
	// 的「上报间隔」,主控本机自采也跟随它(见 SetIntervals / SetDashboardRefresh)。
	reportSec := dashboardRefreshDefault / 1000
	if val, _ := h.repo.GetSystemSetting(r.Context(), dashboardRefreshKey); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 1000 && n <= 60000 {
			reportSec = n / 1000
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":                  true,
		"speed_collect_interval":   cfg.SpeedCollectInterval,
		"traffic_collect_interval": cfg.TrafficCollectInterval,
		"traffic_check_interval":   cfg.TrafficCheckInterval,
		"heartbeat_interval":       cfg.HeartbeatInterval,
		"report_interval":          reportSec,
	})
}

func (h *SystemSettingsHandler) SetIntervals(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SpeedCollectInterval   int `json:"speed_collect_interval"`
		TrafficCollectInterval int `json:"traffic_collect_interval"`
		TrafficCheckInterval   int `json:"traffic_check_interval"`
		HeartbeatInterval      int `json:"heartbeat_interval"`
		ReportInterval         int `json:"report_interval"` // 秒,会同步给所有 agent 的「上报间隔」;主控自采也跟随它
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.SpeedCollectInterval < 1 {
		req.SpeedCollectInterval = 3
	}
	if req.TrafficCollectInterval < 10 {
		req.TrafficCollectInterval = 60
	}
	if req.TrafficCheckInterval < 10 {
		req.TrafficCheckInterval = 120
	}
	if req.HeartbeatInterval < 5 {
		req.HeartbeatInterval = 30
	}
	// 上报间隔(秒)→ dashboard_refresh_interval_ms,clamp 到 [1,60]s。
	if req.ReportInterval < 1 {
		req.ReportInterval = dashboardRefreshDefault / 1000
	}
	if req.ReportInterval > 60 {
		req.ReportInterval = 60
	}

	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.SpeedCollectInterval = req.SpeedCollectInterval
	cfg.TrafficCollectInterval = req.TrafficCollectInterval
	cfg.TrafficCheckInterval = req.TrafficCheckInterval
	cfg.HeartbeatInterval = req.HeartbeatInterval
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	// 「上报间隔」落库为 dashboard_refresh_interval_ms,并同步给所有 agent。
	reportMs := req.ReportInterval * 1000
	if err := h.repo.SetSystemSetting(r.Context(), dashboardRefreshKey, strconv.Itoa(reportMs)); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	if h.wsHandler != nil {
		h.wsHandler.BroadcastConfigUpdate(map[string]string{
			"traffic_report_interval_ms": strconv.Itoa(reportMs),
		})
	}
	// 热重载 master 端 collector ticker,无需重启服务。speed 用 speed_collect_interval,
	// traffic 采集跟随「上报间隔」(与 agent 一致)。
	// (traffic_check_interval / heartbeat_interval 需要其他子系统也支持热重载,目前仅落库。)
	hotReloaded := false
	if h.collector != nil {
		h.collector.SetInterval(time.Duration(reportMs) * time.Millisecond)
		h.collector.SetSpeedInterval(time.Duration(req.SpeedCollectInterval) * time.Second)
		hotReloaded = true
	}
	msg := "定时配置已更新"
	if hotReloaded {
		msg += "(traffic/speed 采集 ticker 已热重载,立即生效)"
	} else {
		msg += "(重启服务后生效)"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": msg,
	})
}

func (h *SystemSettingsHandler) GetAgentLogEnabled(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "agent_log_enabled": cfg.AgentLogEnabled})
}

func (h *SystemSettingsHandler) SetAgentLogEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentLogEnabled bool `json:"agent_log_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.AgentLogEnabled = req.AgentLogEnabled
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	agentlog.SetEnabled(req.AgentLogEnabled)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "Agent日志设置已更新"})
}

func (h *SystemSettingsHandler) GetOverrideScriptsEnabled(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "enable_override_scripts": cfg.EnableOverrideScripts})
}

func (h *SystemSettingsHandler) SetOverrideScriptsEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnableOverrideScripts bool `json:"enable_override_scripts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.EnableOverrideScripts = req.EnableOverrideScripts
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "覆写脚本设置已更新"})
}

// GetSubscriptionOutputFormat / SetSubscriptionOutputFormat — Clash 订阅序列化格式 yaml/json 切换
func (h *SystemSettingsHandler) GetSubscriptionOutputFormat(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	format := cfg.SubscriptionOutputFormat
	if format == "" {
		format = "yaml"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "subscription_output_format": format})
}

func (h *SystemSettingsHandler) SetSubscriptionOutputFormat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubscriptionOutputFormat string `json:"subscription_output_format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	// 二值校验:仅接受 'yaml' 或 'json',其余拒绝(避免误存 db / 后端误判 → 静默回落 yaml 的暗坑)
	if req.SubscriptionOutputFormat != "yaml" && req.SubscriptionOutputFormat != "json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "格式必须为 yaml 或 json"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.SubscriptionOutputFormat = req.SubscriptionOutputFormat
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "订阅序列化格式已更新"})
}

// DefaultThemeKey 是「默认主题」系统设置的 KV 键。值:"flat"(现代扁平,默认)/ "pixel" / "anime"。
// 无 mmw-theme-style cookie 的用户首屏用它决定初始主题(由 web.SetDefaultTheme 注入 index.html)。
const DefaultThemeKey = "default_theme"

func (h *SystemSettingsHandler) GetDefaultTheme(w http.ResponseWriter, r *http.Request) {
	value, _ := h.repo.GetSystemSetting(r.Context(), DefaultThemeKey)
	if value != "flat" && value != "pixel" && value != "anime" {
		value = "flat"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "default_theme": value})
}

func (h *SystemSettingsHandler) SetDefaultTheme(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DefaultTheme string `json:"default_theme"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.DefaultTheme != "flat" && req.DefaultTheme != "pixel" && req.DefaultTheme != "anime" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "主题必须为 flat / pixel / anime"})
		return
	}
	if err := h.repo.SetSystemSetting(r.Context(), DefaultThemeKey, req.DefaultTheme); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "默认主题已更新"})
}

// LoginWallpaperKey 是「自定义登录页壁纸」的 KV 键(存图片 URL,可为空)。
const LoginWallpaperKey = "login_wallpaper"

func (h *SystemSettingsHandler) GetLoginWallpaper(w http.ResponseWriter, r *http.Request) {
	value, _ := h.repo.GetSystemSetting(r.Context(), LoginWallpaperKey)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "login_wallpaper": value})
}

func (h *SystemSettingsHandler) SetLoginWallpaper(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LoginWallpaper string `json:"login_wallpaper"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	v := strings.TrimSpace(req.LoginWallpaper)
	if len(v) > 2000 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "URL 过长"})
		return
	}
	if err := h.repo.SetSystemSetting(r.Context(), LoginWallpaperKey, v); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "登录页壁纸已更新"})
}

// GetLoginWallpaperPublic 公开读取(登录页未鉴权时用)。
func (h *SystemSettingsHandler) GetLoginWallpaperPublic(w http.ResponseWriter, r *http.Request) {
	value, _ := h.repo.GetSystemSetting(r.Context(), LoginWallpaperKey)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"login_wallpaper": value})
}

func (h *SystemSettingsHandler) GetSilentMode(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":             true,
		"silent_mode":         cfg.SilentMode,
		"silent_mode_timeout": cfg.SilentModeTimeout,
	})
}

func (h *SystemSettingsHandler) SetSilentMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SilentMode        bool `json:"silent_mode"`
		SilentModeTimeout int  `json:"silent_mode_timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.SilentModeTimeout <= 0 {
		req.SilentModeTimeout = 15
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.SilentMode = req.SilentMode
	cfg.SilentModeTimeout = req.SilentModeTimeout
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "静默模式设置已更新"})
}

func (h *SystemSettingsHandler) GetRequireEncryption(w http.ResponseWriter, r *http.Request) {
	value, _ := h.repo.GetSystemSetting(r.Context(), "require_encryption")
	enabled := value == "true"
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "require_encryption": enabled})
}

func (h *SystemSettingsHandler) SetRequireEncryption(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequireEncryption bool `json:"require_encryption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	value := "false"
	if req.RequireEncryption {
		value = "true"
	}
	if err := h.repo.SetSystemSetting(r.Context(), "require_encryption", value); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}

	if h.crypto != nil {
		h.crypto.SetRequireEncryption(req.RequireEncryption)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "加密设置已更新"})
}

func (h *SystemSettingsHandler) GetManagementFeaturesEnabled(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "enable_management_features": cfg.EnableManagementFeatures})
}

func (h *SystemSettingsHandler) SetManagementFeaturesEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnableManagementFeatures bool `json:"enable_management_features"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.EnableManagementFeatures = req.EnableManagementFeatures
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "管理功能设置已更新"})
}

// 兼容旧版面板短链接(/<code> 自动尝试匹配 /x/<code>)— 默认 false。
// 开启后,根路径下单段 alphanumeric 路径会先尝试当作短链;命中返回订阅,未命中计入暴力枚举失败。
func (h *SystemSettingsHandler) GetMmwShortLinkCompat(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "enable_mmw_short_link_compat": cfg.EnableMmwShortLinkCompat})
}

func (h *SystemSettingsHandler) SetMmwShortLinkCompat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnableMmwShortLinkCompat bool `json:"enable_mmw_short_link_compat"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.EnableMmwShortLinkCompat = req.EnableMmwShortLinkCompat
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "旧版短链接兼容设置已更新"})
}

func (h *SystemSettingsHandler) GetDefaultTemplate(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "default_template_filename": cfg.DefaultTemplateFilename})
}

func (h *SystemSettingsHandler) SetDefaultTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DefaultTemplateFilename string `json:"default_template_filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	if req.DefaultTemplateFilename != "" {
		filePath := filepath.Join("rule_templates", req.DefaultTemplateFilename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "模板文件不存在"})
			return
		}
	}

	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.DefaultTemplateFilename = req.DefaultTemplateFilename
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "默认模板已更新"})
}

// 节点名称倍率前缀:开关 + 左右分隔符。
// 开启后订阅生成时,套餐内 multiplier != 1 的节点 name 前面会拼上 "{left}{mult}{right}"。
func (h *SystemSettingsHandler) GetNodeNameMultiplierPrefix(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"enabled": cfg.NodeNameMultiplierPrefixEnabled,
		"left":    cfg.NodeNameMultiplierLeft,
		"right":   cfg.NodeNameMultiplierRight,
	})
}

func (h *SystemSettingsHandler) SetNodeNameMultiplierPrefix(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool   `json:"enabled"`
		Left    string `json:"left"`
		Right   string `json:"right"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	cfg, err := h.repo.GetSystemConfig(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "获取设置失败"})
		return
	}
	cfg.NodeNameMultiplierPrefixEnabled = req.Enabled
	// 留 1 个字符的小白名单宽松:空字符串兜底回默认,避免 UI 提交空导致 "2原名" 无分隔
	if strings.TrimSpace(req.Left) == "" {
		cfg.NodeNameMultiplierLeft = "「"
	} else {
		cfg.NodeNameMultiplierLeft = req.Left
	}
	if strings.TrimSpace(req.Right) == "" {
		cfg.NodeNameMultiplierRight = "」"
	} else {
		cfg.NodeNameMultiplierRight = req.Right
	}
	if err := h.repo.UpdateSystemConfig(r.Context(), cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "保存失败"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "倍率前缀设置已更新"})
}
