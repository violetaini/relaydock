package handler

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/storage"
)

// 系统设置中的 OAuth 键名常量
const (
	SettingOAuthGitHubEnabled      = "oauth_github_enabled"
	SettingOAuthGitHubClientID     = "oauth_github_client_id"
	SettingOAuthGitHubClientSecret = "oauth_github_client_secret"

	SettingOAuthGoogleEnabled      = "oauth_google_enabled"
	SettingOAuthGoogleClientID     = "oauth_google_client_id"
	SettingOAuthGoogleClientSecret = "oauth_google_client_secret"

	SettingOAuthOIDCEnabled        = "oauth_oidc_enabled"
	SettingOAuthOIDCIssuer         = "oauth_oidc_issuer"
	SettingOAuthOIDCClientID       = "oauth_oidc_client_id"
	SettingOAuthOIDCClientSecret   = "oauth_oidc_client_secret"
	SettingOAuthOIDCDisplayName    = "oauth_oidc_display_name"

	SettingOAuthAutoRegister  = "oauth_auto_register"
	SettingOAuthAutoLinkEmail = "oauth_auto_link_email"

	oauthStateCookieName = "relaydock_oauth_state"
)

// OAuthConfig 代表 OAuth / OIDC 的完整配置（管理端使用）
type OAuthConfig struct {
	GitHubEnabled      bool   `json:"github_enabled"`
	GitHubClientID     string `json:"github_client_id"`
	GitHubClientSecret string `json:"github_client_secret"`

	GoogleEnabled      bool   `json:"google_enabled"`
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"google_client_secret"`

	OIDCEnabled      bool   `json:"oidc_enabled"`
	OIDCIssuer       string `json:"oidc_issuer"`
	OIDCClientID     string `json:"oidc_client_id"`
	OIDCClientSecret string `json:"oidc_client_secret"`
	OIDCDisplayName  string `json:"oidc_display_name"`

	AutoRegister  bool `json:"auto_register"`
	AutoLinkEmail bool `json:"auto_link_email"`

	CallbackURLs map[string]string `json:"callback_urls,omitempty"`
}

// OAuthPublicProvider 代表公开给登录页面的第三方登录选项
type OAuthPublicProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// OAuthPublicResponse 登录页获取公开配置的响应结构
type OAuthPublicResponse struct {
	Providers    []OAuthPublicProvider `json:"providers"`
	AutoRegister bool                  `json:"auto_register"`
}

// OAuthUserProfile 统一的第三方用户资料归一化模型
type OAuthUserProfile struct {
	Provider      string
	OAuthID       string
	Email         string
	EmailVerified bool
	Name          string
	AvatarURL     string
}

type oidcDiscoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type oauthStateData struct {
	Nonce     string `json:"n"`
	Provider  string `json:"p"`
	Bind      bool   `json:"b,omitempty"`
	Username  string `json:"u,omitempty"`
	Silent    bool   `json:"s,omitempty"`
	ExpiresAt int64  `json:"e"`
}

type oauthExchangeItem struct {
	Token     string
	Username  string
	ExpiresAt time.Time
}

// OAuthHandler 处理第三方快捷登录 (GitHub, Google, Generic OIDC)
type OAuthHandler struct {
	repo        *storage.TrafficRepository
	tokens      *auth.TokenStore
	httpClient  *http.Client
	stateSecret []byte

	oidcCacheMu sync.RWMutex
	oidcCache   map[string]cachedDiscovery

	exchangeMu    sync.Mutex
	exchangeCodes map[string]oauthExchangeItem
}

type cachedDiscovery struct {
	doc       oidcDiscoveryDoc
	fetchedAt time.Time
}

// NewOAuthHandler 创建 OAuthHandler 实例
func NewOAuthHandler(repo *storage.TrafficRepository, tokens *auth.TokenStore) *OAuthHandler {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		secret = []byte("relaydock_oauth_default_state_secret_fallback_32b")
	}
	return &OAuthHandler{
		repo:          repo,
		tokens:        tokens,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		stateSecret:   secret,
		oidcCache:     make(map[string]cachedDiscovery),
		exchangeCodes: make(map[string]oauthExchangeItem),
	}
}

// SetHTTPClient 允许在测试或反向代理环境中注入自定义 HTTP 客户端
func (h *OAuthHandler) SetHTTPClient(client *http.Client) {
	if client != nil {
		h.httpClient = client
	}
}

// GetPublicProviders 公开接口: 供前端登录界面检测当前启用了哪些第三方登录
func (h *OAuthHandler) GetPublicProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg, err := h.loadConfig(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to load oauth config: "+err.Error())
		return
	}

	var list []OAuthPublicProvider
	if cfg.GitHubEnabled && cfg.GitHubClientID != "" {
		list = append(list, OAuthPublicProvider{ID: "github", Name: "GitHub"})
	}
	if cfg.GoogleEnabled && cfg.GoogleClientID != "" {
		list = append(list, OAuthPublicProvider{ID: "google", Name: "Google"})
	}
	if cfg.OIDCEnabled && cfg.OIDCClientID != "" && cfg.OIDCIssuer != "" {
		displayName := strings.TrimSpace(cfg.OIDCDisplayName)
		if displayName == "" {
			displayName = "OIDC"
		}
		list = append(list, OAuthPublicProvider{ID: "oidc", Name: displayName})
	}

	respondJSON(w, http.StatusOK, OAuthPublicResponse{
		Providers:    list,
		AutoRegister: cfg.AutoRegister,
	})
}

// ExchangeOAuthCode 公开接口: 客户端使用一次性授权码兑换会话 Token
func (h *OAuthHandler) ExchangeOAuthCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	code := strings.TrimSpace(req.Code)
	if code == "" {
		writeJSONError(w, http.StatusBadRequest, "Code is required")
		return
	}

	h.exchangeMu.Lock()
	item, ok := h.exchangeCodes[code]
	if ok {
		delete(h.exchangeCodes, code) // 单次使用，立即作废
	}
	h.exchangeMu.Unlock()

	if !ok || time.Now().After(item.ExpiresAt) {
		writeJSONError(w, http.StatusUnauthorized, "invalid_or_expired_code")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"token":      item.Token,
		"username":   item.Username,
		"expires_at": item.ExpiresAt.Unix(),
	})
}

func (h *OAuthHandler) createExchangeCode(token, username string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		b = []byte(fmt.Sprintf("%d-%s", time.Now().UnixNano(), username))
	}
	code := "rd_auth_" + hex.EncodeToString(b)

	h.exchangeMu.Lock()
	defer h.exchangeMu.Unlock()

	now := time.Now()
	// 清理过期项
	for k, v := range h.exchangeCodes {
		if now.After(v.ExpiresAt) {
			delete(h.exchangeCodes, k)
		}
	}

	h.exchangeCodes[code] = oauthExchangeItem{
		Token:     token,
		Username:  username,
		ExpiresAt: now.Add(60 * time.Second),
	}
	return code
}

// GetAdminConfig 管理员获取 OAuth 设置与回调地址
func (h *OAuthHandler) GetAdminConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg, err := h.loadConfig(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to load oauth config: "+err.Error())
		return
	}

	baseURL := getRequestBaseURL(r)
	cfg.CallbackURLs = map[string]string{
		"github": baseURL + "/api/oauth/github/callback",
		"google": baseURL + "/api/oauth/google/callback",
		"oidc":   baseURL + "/api/oauth/oidc/callback",
	}

	// 脱敏 Client Secret
	cfg.GitHubClientSecret = maskSecret(cfg.GitHubClientSecret)
	cfg.GoogleClientSecret = maskSecret(cfg.GoogleClientSecret)
	cfg.OIDCClientSecret = maskSecret(cfg.OIDCClientSecret)

	respondJSON(w, http.StatusOK, cfg)
}

// SaveAdminConfig 管理员保存 OAuth 设置
func (h *OAuthHandler) SaveAdminConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req OAuthConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	ctx := r.Context()
	oldCfg, err := h.loadConfig(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to read current config: "+err.Error())
		return
	}

	// 若传入的 Secret 包含掩码 '*' 或为空，则保留原本已存储的 Secret
	ghSecret := req.GitHubClientSecret
	if strings.Contains(ghSecret, "*") || strings.TrimSpace(ghSecret) == "" {
		ghSecret = oldCfg.GitHubClientSecret
	}
	googleSecret := req.GoogleClientSecret
	if strings.Contains(googleSecret, "*") || strings.TrimSpace(googleSecret) == "" {
		googleSecret = oldCfg.GoogleClientSecret
	}
	oidcSecret := req.OIDCClientSecret
	if strings.Contains(oidcSecret, "*") || strings.TrimSpace(oidcSecret) == "" {
		oidcSecret = oldCfg.OIDCClientSecret
	}

	// 写入 system_settings
	kvs := map[string]string{
		SettingOAuthGitHubEnabled:      boolToStr(req.GitHubEnabled),
		SettingOAuthGitHubClientID:     strings.TrimSpace(req.GitHubClientID),
		SettingOAuthGitHubClientSecret: strings.TrimSpace(ghSecret),

		SettingOAuthGoogleEnabled:      boolToStr(req.GoogleEnabled),
		SettingOAuthGoogleClientID:     strings.TrimSpace(req.GoogleClientID),
		SettingOAuthGoogleClientSecret: strings.TrimSpace(googleSecret),

		SettingOAuthOIDCEnabled:      boolToStr(req.OIDCEnabled),
		SettingOAuthOIDCIssuer:       strings.TrimSpace(req.OIDCIssuer),
		SettingOAuthOIDCClientID:     strings.TrimSpace(req.OIDCClientID),
		SettingOAuthOIDCClientSecret: strings.TrimSpace(oidcSecret),
		SettingOAuthOIDCDisplayName:  strings.TrimSpace(req.OIDCDisplayName),

		SettingOAuthAutoRegister:  boolToStr(req.AutoRegister),
		SettingOAuthAutoLinkEmail: boolToStr(req.AutoLinkEmail),
	}

	for k, v := range kvs {
		if err := h.repo.SetSystemSetting(ctx, k, v); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to save setting "+k+": "+err.Error())
			return
		}
	}

	// 清理 OIDC 发现缓存
	h.oidcCacheMu.Lock()
	h.oidcCache = make(map[string]cachedDiscovery)
	h.oidcCacheMu.Unlock()

	respondJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// GetUserIdentities 获取当前登录用户已绑定的第三方身份列表
func (h *OAuthHandler) GetUserIdentities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	list, err := h.repo.GetUserOAuthIdentities(r.Context(), username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to fetch identities: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, list)
}

// UnbindUserIdentity 解除第三方绑定
func (h *OAuthHandler) UnbindUserIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		writeJSONError(w, http.StatusBadRequest, "Provider is required")
		return
	}

	if err := h.repo.UnbindOAuthIdentity(r.Context(), username, provider); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to unbind: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "unbound"})
}

// PrepareBind 为已登录用户生成绑定第三方的跳转地址并设置防 CSRF Cookie
func (h *OAuthHandler) PrepareBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	authURL, err := h.buildAuthURL(w, r, provider, true, username, false)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"url": authURL})
}

// HandleLogin 发起第三方授权跳转: /api/oauth/{provider}/login?bind=true&silent=true
func (h *OAuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request, provider string) {
	bind := r.URL.Query().Get("bind") == "true"
	silent := r.URL.Query().Get("silent") == "true"
	var username string
	if bind {
		username = auth.UsernameFromContext(r.Context())
		if username == "" {
			// 未登录无法绑定
			http.Redirect(w, r, "/?oauth_error=login_required_to_bind", http.StatusFound)
			return
		}
	}

	authURL, err := h.buildAuthURL(w, r, provider, bind, username, silent)
	if err != nil {
		http.Redirect(w, r, "/?oauth_error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *OAuthHandler) buildAuthURL(w http.ResponseWriter, r *http.Request, provider string, bind bool, username string, silent bool) (string, error) {
	ctx := r.Context()
	cfg, err := h.loadConfig(ctx)
	if err != nil {
		return "", errors.New("config_error")
	}

	provider = strings.ToLower(strings.TrimSpace(provider))
	baseURL := getRequestBaseURL(r)
	redirectURI := fmt.Sprintf("%s/api/oauth/%s/callback", baseURL, provider)

	// 生成安全加密状态参数与防 CSRF Cookie
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	stateToken := h.generateStateToken(oauthStateData{
		Nonce:     nonce,
		Provider:  provider,
		Bind:      bind,
		Username:  username,
		Silent:    silent,
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	})

	setOAuthCookie(w, r, oauthStateCookieName, nonce, 600)

	switch provider {
	case "github":
		if !cfg.GitHubEnabled || cfg.GitHubClientID == "" {
			return "", errors.New("provider_disabled")
		}
		return fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
			url.QueryEscape(cfg.GitHubClientID),
			url.QueryEscape(redirectURI),
			url.QueryEscape("read:user user:email"),
			url.QueryEscape(stateToken),
		), nil

	case "google":
		if !cfg.GoogleEnabled || cfg.GoogleClientID == "" {
			return "", errors.New("provider_disabled")
		}
		prompt := "select_account"
		if silent {
			prompt = "none"
		}
		return fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&access_type=offline&prompt=%s",
			url.QueryEscape(cfg.GoogleClientID),
			url.QueryEscape(redirectURI),
			url.QueryEscape("openid email profile"),
			url.QueryEscape(stateToken),
			url.QueryEscape(prompt),
		), nil

	case "oidc":
		if !cfg.OIDCEnabled || cfg.OIDCClientID == "" || cfg.OIDCIssuer == "" {
			return "", errors.New("provider_disabled")
		}
		doc, err := h.getOIDCDiscovery(ctx, cfg.OIDCIssuer)
		if err != nil {
			logger.Error("[OAuth] OIDC Discovery 失败", "issuer", cfg.OIDCIssuer, "err", err)
			return "", errors.New("oidc_discovery_failed")
		}
		authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&nonce=%s",
			doc.AuthorizationEndpoint,
			url.QueryEscape(cfg.OIDCClientID),
			url.QueryEscape(redirectURI),
			url.QueryEscape("openid email profile"),
			url.QueryEscape(stateToken),
			url.QueryEscape(nonce),
		)
		if silent {
			authURL += "&prompt=none"
		}
		return authURL, nil

	default:
		return "", errors.New("unsupported_provider")
	}
}

// HandleCallback 处理第三方授权回调: /api/oauth/{provider}/callback?code=...&state=...
func (h *OAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request, provider string) {
	ctx := r.Context()
	provider = strings.ToLower(strings.TrimSpace(provider))

	// 1. 检查是否存在上游错误（例如用户取消授权或静默检测未登录）
	if upstreamErr := r.URL.Query().Get("error"); upstreamErr != "" {
		stateParam := r.URL.Query().Get("state")
		if stateParam != "" {
			stateData, err := h.verifyStateToken(stateParam)
			if err == nil && stateData != nil && stateData.Silent {
				// 静默检测时，若用户在 SSO 端未登录或未授权，属于预期状态，不抛出异常警告，直接回到登录页面
				isSilentGuest := upstreamErr == "login_required" ||
					upstreamErr == "interaction_required" ||
					upstreamErr == "consent_required" ||
					upstreamErr == "account_selection_required"
				if isSilentGuest {
					clearOAuthCookie(w, r, oauthStateCookieName)
					logger.Info("[OAuth] SSO 静默检测完成: 用户未在 SSO 端登录，安全停留在面板登录页",
						"provider", provider, "reason", upstreamErr)
					http.Redirect(w, r, "/?sso_silent=guest", http.StatusFound)
					return
				}
			}
		}

		logger.Warn("[OAuth] 第三方授权上游返回错误", "provider", provider, "error", upstreamErr)
		http.Redirect(w, r, "/?oauth_error="+url.QueryEscape(upstreamErr), http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		http.Redirect(w, r, "/?oauth_error=missing_code_or_state", http.StatusFound)
		return
	}

	// 2. 校验防 CSRF Cookie 与签名 State
	cookieNonce := getOAuthCookie(r, oauthStateCookieName)
	clearOAuthCookie(w, r, oauthStateCookieName)

	stateData, err := h.verifyStateToken(stateParam)
	if err != nil {
		logger.Warn("[OAuth] State 校验失败", "provider", provider, "err", err)
		http.Redirect(w, r, "/?oauth_error=invalid_state", http.StatusFound)
		return
	}

	if stateData.Provider != provider || stateData.Nonce != cookieNonce || cookieNonce == "" {
		logger.Warn("[OAuth] CSRF Nonce 或提供商不匹配", "expected_provider", provider, "got", stateData.Provider)
		http.Redirect(w, r, "/?oauth_error=csrf_validation_failed", http.StatusFound)
		return
	}

	if time.Now().Unix() > stateData.ExpiresAt {
		http.Redirect(w, r, "/?oauth_error=state_expired", http.StatusFound)
		return
	}

	// 3. 读取配置并执行 Token 兑换及用户信息拉取
	cfg, err := h.loadConfig(ctx)
	if err != nil {
		http.Redirect(w, r, "/?oauth_error=config_error", http.StatusFound)
		return
	}

	baseURL := getRequestBaseURL(r)
	redirectURI := fmt.Sprintf("%s/api/oauth/%s/callback", baseURL, provider)

	var profile *OAuthUserProfile
	switch provider {
	case "github":
		profile, err = h.exchangeGitHub(ctx, cfg, code, redirectURI)
	case "google":
		profile, err = h.exchangeGoogle(ctx, cfg, code, redirectURI)
	case "oidc":
		profile, err = h.exchangeOIDC(ctx, cfg, code, redirectURI, stateData.Nonce)
	default:
		err = errors.New("unsupported provider")
	}

	if err != nil {
		logger.Error("[OAuth] 换取凭证或获取个人信息失败", "provider", provider, "err", err)
		http.Redirect(w, r, "/?oauth_error=exchange_failed", http.StatusFound)
		return
	}

	if profile == nil || profile.OAuthID == "" {
		http.Redirect(w, r, "/?oauth_error=profile_not_found", http.StatusFound)
		return
	}

	// 4. 处理绑定分支 (Bind mode)
	if stateData.Bind {
		if stateData.Username == "" {
			http.Redirect(w, r, "/?oauth_error=binding_session_lost", http.StatusFound)
			return
		}

		// 检查此第三方账号是否已被其他用户绑定
		existing, err := h.repo.GetOAuthIdentity(ctx, provider, profile.OAuthID)
		if err == nil && existing != nil && existing.Username != stateData.Username {
			http.Redirect(w, r, "/?oauth_error=already_bound_to_other_user", http.StatusFound)
			return
		}

		// 执行绑定
		identity := &storage.UserOAuthIdentity{
			Username:  stateData.Username,
			Provider:  provider,
			OAuthID:   profile.OAuthID,
			Email:     profile.Email,
			Name:      profile.Name,
			AvatarURL: profile.AvatarURL,
		}
		if err := h.repo.BindOAuthIdentity(ctx, identity); err != nil {
			logger.Error("[OAuth] 绑定第三方账号失败", "user", stateData.Username, "provider", provider, "err", err)
			http.Redirect(w, r, "/?oauth_error=bind_failed", http.StatusFound)
			return
		}

		logger.Info("[OAuth] 用户成功绑定第三方账号", "user", stateData.Username, "provider", provider)
		http.Redirect(w, r, fmt.Sprintf("/?oauth_success=bound&provider=%s", url.QueryEscape(provider)), http.StatusFound)
		return
	}

	// 5. 处理登录分支 (Login mode)
	var targetUser *storage.User

	// 5.1 先通过 provider + oauth_id 查找是否已绑定用户
	existingIdentity, err := h.repo.GetOAuthIdentity(ctx, provider, profile.OAuthID)
	if err == nil && existingIdentity != nil && existingIdentity.Username != "" {
		u, err := h.repo.GetUser(ctx, existingIdentity.Username)
		if err == nil {
			targetUser = &u
		}
	}

	// 5.2 如果未绑定且开启了邮箱自动关联，则通过第三方邮箱查找已有用户
	if targetUser == nil && cfg.AutoLinkEmail && profile.Email != "" {
		if !profile.EmailVerified {
			logger.Warn("[OAuth] 第三方账号邮箱未通过身份提供商验证，跳过自动关联以防未授权接管", "provider", provider, "email", profile.Email)
		} else {
			matched, err := h.repo.GetUserByEmail(ctx, profile.Email)
			if err == nil && matched.Username != "" {
				targetUser = &matched
				// 自动建立绑定关联
				_ = h.repo.BindOAuthIdentity(ctx, &storage.UserOAuthIdentity{
					Username:  matched.Username,
					Provider:  provider,
					OAuthID:   profile.OAuthID,
					Email:     profile.Email,
					Name:      profile.Name,
					AvatarURL: profile.AvatarURL,
				})
				logger.Info("[OAuth] 第三方账号邮箱匹配已有用户，自动建立绑定", "user", matched.Username, "provider", provider, "email", profile.Email)
			}
		}
	}

	// 5.3 如果仍未找到对应用户，检查是否允许新用户快捷注册
	if targetUser == nil {
		if !cfg.AutoRegister {
			logger.Warn("[OAuth] 系统未开启快捷注册，拒绝新第三方账号登录", "provider", provider, "oauth_id", profile.OAuthID)
			http.Redirect(w, r, "/?oauth_error=registration_disabled", http.StatusFound)
			return
		}

		// 为新用户生成唯一的有效用户名
		username := h.generateUniqueUsername(ctx, profile.Name, provider, profile.OAuthID)
		randomPwdBytes := make([]byte, 24)
		_, _ = rand.Read(randomPwdBytes)
		randomPwd := hex.EncodeToString(randomPwdBytes)
		hash, err := bcrypt.GenerateFromPassword([]byte(randomPwd), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("[OAuth] 密码哈希生成失败", "err", err)
			http.Redirect(w, r, "/?oauth_error=register_failed", http.StatusFound)
			return
		}

		nickname := profile.Name
		if strings.TrimSpace(nickname) == "" {
			nickname = username
		}

		// 创建新用户
		if err := h.repo.CreateUser(ctx, username, profile.Email, nickname, string(hash), storage.RoleUser, "Auto registered via "+provider); err != nil {
			logger.Error("[OAuth] 快捷注册创建用户失败", "username", username, "err", err)
			http.Redirect(w, r, "/?oauth_error=register_failed", http.StatusFound)
			return
		}

		// 更新头像
		if profile.AvatarURL != "" {
			_ = h.repo.UpdateUserProfile(ctx, username, storage.UserProfileUpdate{
				Nickname:  nickname,
				Email:     profile.Email,
				AvatarURL: profile.AvatarURL,
			})
		}

		// 初始化用户 Token
		_, _ = h.repo.GetOrCreateUserToken(ctx, username)

		// 绑定第三方身份
		_ = h.repo.BindOAuthIdentity(ctx, &storage.UserOAuthIdentity{
			Username:  username,
			Provider:  provider,
			OAuthID:   profile.OAuthID,
			Email:     profile.Email,
			Name:      nickname,
			AvatarURL: profile.AvatarURL,
		})

		created, err := h.repo.GetUser(ctx, username)
		if err != nil {
			http.Redirect(w, r, "/?oauth_error=register_failed", http.StatusFound)
			return
		}
		targetUser = &created
		logger.Info("[OAuth] 第三方账号首次登录，成功自动注册新用户", "username", username, "provider", provider)
	}

	// 5.4 校验用户状态
	if !targetUser.IsActive {
		logger.Warn("[OAuth] 用户账号已被禁用", "username", targetUser.Username)
		http.Redirect(w, r, "/?oauth_error=account_disabled", http.StatusFound)
		return
	}

	// 5.5 签发会话 Token 与一次性授权兑换码，杜绝令牌在 URL 中明文暴露
	token, _, err := createLoginSession(ctx, h.tokens, h.repo, *targetUser, true)
	if err != nil {
		logger.Error("[OAuth] 创建会话失败", "username", targetUser.Username, "err", err)
		http.Redirect(w, r, "/?oauth_error=session_error", http.StatusFound)
		return
	}

	exchangeCode := h.createExchangeCode(token, targetUser.Username)
	logger.Info("[OAuth] 快捷登录成功，签发授权兑换码", "username", targetUser.Username, "provider", provider)
	http.Redirect(w, r, fmt.Sprintf("/?oauth_code=%s", url.QueryEscape(exchangeCode)), http.StatusFound)
}

// === 第三方提供商具体交换与用户资料抓取 ===

func (h *OAuthHandler) exchangeGitHub(ctx context.Context, cfg *OAuthConfig, code, redirectURI string) (*OAuthUserProfile, error) {
	// 1. 换取 access_token
	data := url.Values{}
	data.Set("client_id", cfg.GitHubClientID)
	data.Set("client_secret", cfg.GitHubClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github token error status %d: %s", resp.StatusCode, string(b))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode github token resp: %w", err)
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("github oauth error: %s (%s)", tokenResp.Error, tokenResp.ErrorDesc)
	}
	if tokenResp.AccessToken == "" {
		return nil, errors.New("github returned empty access_token")
	}

	// 2. 拉取用户信息
	uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	uReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	uReq.Header.Set("User-Agent", "RelayDock")

	uResp, err := h.httpClient.Do(uReq)
	if err != nil {
		return nil, fmt.Errorf("github user request: %w", err)
	}
	defer uResp.Body.Close()

	var ghUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(uResp.Body).Decode(&ghUser); err != nil {
		return nil, fmt.Errorf("decode github user resp: %w", err)
	}

	profile := &OAuthUserProfile{
		Provider:      "github",
		OAuthID:       strconv.FormatInt(ghUser.ID, 10),
		Email:         strings.TrimSpace(ghUser.Email),
		EmailVerified: false,
		Name:          strings.TrimSpace(ghUser.Name),
		AvatarURL:     strings.TrimSpace(ghUser.AvatarURL),
	}
	if profile.Name == "" {
		profile.Name = ghUser.Login
	}

	// 3. 额外请求 /user/emails 获取主邮箱及验证状态
	eReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err == nil {
		eReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		eReq.Header.Set("User-Agent", "RelayDock")
		if eResp, err := h.httpClient.Do(eReq); err == nil {
			defer eResp.Body.Close()
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if json.NewDecoder(eResp.Body).Decode(&emails) == nil {
				for _, item := range emails {
					if item.Primary && item.Verified {
						profile.Email = item.Email
						profile.EmailVerified = true
						break
					}
				}
				if profile.Email == "" || !profile.EmailVerified {
					for _, item := range emails {
						if item.Verified {
							profile.Email = item.Email
							profile.EmailVerified = true
							break
						}
					}
				}
			}
		}
	}

	return profile, nil
}

func (h *OAuthHandler) exchangeGoogle(ctx context.Context, cfg *OAuthConfig, code, redirectURI string) (*OAuthUserProfile, error) {
	// 1. 换取 token
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", cfg.GoogleClientID)
	data.Set("client_secret", cfg.GoogleClientSecret)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google token status %d: %s", resp.StatusCode, string(b))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IdToken     string `json:"id_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode google token: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, errors.New("google returned empty access_token")
	}

	// 2. 获取 userinfo
	uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, err
	}
	uReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	uResp, err := h.httpClient.Do(uReq)
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	defer uResp.Body.Close()

	var gUser struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(uResp.Body).Decode(&gUser); err != nil {
		return nil, fmt.Errorf("decode google userinfo: %w", err)
	}

	return &OAuthUserProfile{
		Provider:      "google",
		OAuthID:       gUser.Sub,
		Email:         strings.TrimSpace(gUser.Email),
		EmailVerified: gUser.EmailVerified,
		Name:          strings.TrimSpace(gUser.Name),
		AvatarURL:     strings.TrimSpace(gUser.Picture),
	}, nil
}

func (h *OAuthHandler) exchangeOIDC(ctx context.Context, cfg *OAuthConfig, code, redirectURI, expectedNonce string) (*OAuthUserProfile, error) {
	doc, err := h.getOIDCDiscovery(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, err
	}

	// 1. 换取 Token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", cfg.OIDCClientID)
	data.Set("client_secret", cfg.OIDCClientSecret)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("oidc token status %d: %s", resp.StatusCode, string(b))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode oidc token: %w", err)
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("oidc error: %s (%s)", tokenResp.Error, tokenResp.ErrorDesc)
	}
	if tokenResp.AccessToken == "" && tokenResp.IDToken == "" {
		return nil, errors.New("oidc returned neither access_token nor id_token")
	}

	var claims *oidcIDTokenClaims
	if tokenResp.IDToken != "" {
		parsedClaims, err := parseAndValidateIDToken(tokenResp.IDToken, cfg.OIDCIssuer, cfg.OIDCClientID, expectedNonce)
		if err != nil {
			logger.Warn("[OAuth] OIDC id_token 校验未通过", "err", err)
			return nil, fmt.Errorf("validate id_token: %w", err)
		}
		claims = parsedClaims
	}

	// 2. 获取 userinfo (若提供了 access_token 且存在 userinfo_endpoint)
	var oidcUser struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     any    `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Picture           string `json:"picture"`
	}

	if tokenResp.AccessToken != "" && doc.UserinfoEndpoint != "" {
		uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserinfoEndpoint, nil)
		if err == nil {
			uReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
			if uResp, err := h.httpClient.Do(uReq); err == nil {
				defer uResp.Body.Close()
				if uResp.StatusCode == http.StatusOK {
					_ = json.NewDecoder(uResp.Body).Decode(&oidcUser)
				}
			}
		}
	}

	// 3. 校验并汇聚资料
	sub := ""
	if claims != nil {
		sub = claims.Subject
		if oidcUser.Sub != "" && oidcUser.Sub != claims.Subject {
			return nil, fmt.Errorf("oidc sub mismatch between id_token (%s) and userinfo (%s)", claims.Subject, oidcUser.Sub)
		}
	} else {
		sub = oidcUser.Sub
	}
	if sub == "" {
		return nil, errors.New("oidc returned empty sub")
	}

	email := strings.TrimSpace(oidcUser.Email)
	if email == "" && claims != nil {
		email = strings.TrimSpace(claims.Email)
	}

	emailVerified := parseEmailVerified(oidcUser.EmailVerified)
	if !emailVerified && claims != nil {
		emailVerified = parseEmailVerified(claims.EmailVerified)
	}

	displayName := strings.TrimSpace(oidcUser.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(oidcUser.PreferredUsername)
	}
	if displayName == "" && claims != nil {
		displayName = strings.TrimSpace(claims.Name)
		if displayName == "" {
			displayName = strings.TrimSpace(claims.PreferredName)
		}
	}

	picture := strings.TrimSpace(oidcUser.Picture)
	if picture == "" && claims != nil {
		picture = strings.TrimSpace(claims.Picture)
	}

	return &OAuthUserProfile{
		Provider:      "oidc",
		OAuthID:       sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          displayName,
		AvatarURL:     picture,
	}, nil
}

type oidcIDTokenClaims struct {
	Issuer        string          `json:"iss"`
	Audience      json.RawMessage `json:"aud"`
	Subject       string          `json:"sub"`
	ExpiresAt     int64           `json:"exp"`
	IssuedAt      int64           `json:"iat"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified any             `json:"email_verified"`
	Name          string          `json:"name"`
	PreferredName string          `json:"preferred_username"`
	Picture       string          `json:"picture"`
}

func parseAndValidateIDToken(rawToken, expectedIssuer, expectedClientID, expectedNonce string) (*oidcIDTokenClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid jwt format")
	}

	payloadB64 := parts[1]
	var payloadBytes []byte
	var err error
	if payloadBytes, err = base64.RawURLEncoding.DecodeString(payloadB64); err != nil {
		if payloadBytes, err = base64.URLEncoding.DecodeString(payloadB64); err != nil {
			return nil, fmt.Errorf("decode id_token payload: %w", err)
		}
	}

	var claims oidcIDTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal id_token claims: %w", err)
	}

	if claims.Subject == "" {
		return nil, errors.New("oidc id_token missing sub")
	}

	// 校验 Issuer
	cleanExpectedIss := strings.TrimRight(strings.TrimSpace(expectedIssuer), "/")
	cleanIss := strings.TrimRight(strings.TrimSpace(claims.Issuer), "/")
	if cleanExpectedIss != "" && cleanIss != "" && cleanExpectedIss != cleanIss {
		return nil, fmt.Errorf("oidc id_token issuer mismatch: got %q, expected %q", claims.Issuer, expectedIssuer)
	}

	// 校验 Audience (支持 string 与 []string)
	if expectedClientID != "" && len(claims.Audience) > 0 {
		var singleAud string
		if err := json.Unmarshal(claims.Audience, &singleAud); err == nil {
			if singleAud != expectedClientID {
				return nil, fmt.Errorf("oidc id_token aud mismatch: got %q, expected %q", singleAud, expectedClientID)
			}
		} else {
			var multiAud []string
			if err := json.Unmarshal(claims.Audience, &multiAud); err == nil {
				found := false
				for _, aud := range multiAud {
					if aud == expectedClientID {
						found = true
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("oidc id_token aud does not contain client_id %q", expectedClientID)
				}
			} else {
				return nil, errors.New("oidc id_token invalid aud claim format")
			}
		}
	}

	// 校验过期时间 (容差 120 秒)
	if claims.ExpiresAt > 0 {
		if time.Now().Unix() > claims.ExpiresAt+120 {
			return nil, errors.New("oidc id_token expired")
		}
	}

	// 校验 Nonce 防重放
	if expectedNonce != "" && claims.Nonce != "" {
		if claims.Nonce != expectedNonce {
			return nil, fmt.Errorf("oidc id_token nonce mismatch: got %q, expected %q", claims.Nonce, expectedNonce)
		}
	}

	return &claims, nil
}

func parseEmailVerified(v any) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.EqualFold(val, "true") || val == "1"
	case float64:
		return val == 1
	default:
		return false
	}
}

// getOIDCDiscovery 解析并缓存 OIDC Well-Known 配置
func (h *OAuthHandler) getOIDCDiscovery(ctx context.Context, issuer string) (oidcDiscoveryDoc, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return oidcDiscoveryDoc{}, errors.New("empty oidc issuer")
	}

	h.oidcCacheMu.RLock()
	cached, ok := h.oidcCache[issuer]
	h.oidcCacheMu.RUnlock()
	if ok && time.Since(cached.fetchedAt) < 1*time.Hour {
		return cached.doc, nil
	}

	wellKnownURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return oidcDiscoveryDoc{}, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return oidcDiscoveryDoc{}, fmt.Errorf("fetch oidc well-known (%s): %w", wellKnownURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return oidcDiscoveryDoc{}, fmt.Errorf("fetch oidc well-known (%s) status %d", wellKnownURL, resp.StatusCode)
	}

	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return oidcDiscoveryDoc{}, fmt.Errorf("decode oidc well-known: %w", err)
	}

	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return oidcDiscoveryDoc{}, errors.New("invalid oidc discovery: missing endpoints")
	}
	if doc.UserinfoEndpoint == "" {
		// 部分 OIDC 提供商 userinfo 与 token 同域
		doc.UserinfoEndpoint = issuer + "/userinfo"
	}

	h.oidcCacheMu.Lock()
	h.oidcCache[issuer] = cachedDiscovery{doc: doc, fetchedAt: time.Now()}
	h.oidcCacheMu.Unlock()

	return doc, nil
}

// === 内部工具函数 ===

func (h *OAuthHandler) loadConfig(ctx context.Context) (*OAuthConfig, error) {
	if h.repo == nil {
		return nil, errors.New("repository is nil")
	}

	cfg := &OAuthConfig{
		AutoRegister:  true,
		AutoLinkEmail: true,
	}

	getBool := func(k string, def bool) bool {
		val, err := h.repo.GetSystemSetting(ctx, k)
		if err != nil || val == "" {
			return def
		}
		return val == "1" || strings.ToLower(val) == "true"
	}
	getStr := func(k string) string {
		val, _ := h.repo.GetSystemSetting(ctx, k)
		return val
	}

	cfg.GitHubEnabled = getBool(SettingOAuthGitHubEnabled, false)
	cfg.GitHubClientID = getStr(SettingOAuthGitHubClientID)
	cfg.GitHubClientSecret = getStr(SettingOAuthGitHubClientSecret)

	cfg.GoogleEnabled = getBool(SettingOAuthGoogleEnabled, false)
	cfg.GoogleClientID = getStr(SettingOAuthGoogleClientID)
	cfg.GoogleClientSecret = getStr(SettingOAuthGoogleClientSecret)

	cfg.OIDCEnabled = getBool(SettingOAuthOIDCEnabled, false)
	cfg.OIDCIssuer = getStr(SettingOAuthOIDCIssuer)
	cfg.OIDCClientID = getStr(SettingOAuthOIDCClientID)
	cfg.OIDCClientSecret = getStr(SettingOAuthOIDCClientSecret)
	cfg.OIDCDisplayName = getStr(SettingOAuthOIDCDisplayName)

	cfg.AutoRegister = getBool(SettingOAuthAutoRegister, true)
	cfg.AutoLinkEmail = getBool(SettingOAuthAutoLinkEmail, true)

	return cfg, nil
}

func (h *OAuthHandler) generateStateToken(data oauthStateData) string {
	jsonBytes, _ := json.Marshal(data)
	payloadB64 := base64.RawURLEncoding.EncodeToString(jsonBytes)

	mac := hmac.New(sha256.New, h.stateSecret)
	mac.Write([]byte(payloadB64))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	return payloadB64 + "." + sigHex
}

func (h *OAuthHandler) verifyStateToken(token string) (*oauthStateData, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid state format")
	}

	payloadB64 := parts[0]
	sigHex := parts[1]

	mac := hmac.New(sha256.New, h.stateSecret)
	mac.Write([]byte(payloadB64))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sigHex), []byte(expectedSig)) {
		return nil, errors.New("invalid state signature")
	}

	jsonBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decode state payload: %w", err)
	}

	var data oauthStateData
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return nil, fmt.Errorf("unmarshal state data: %w", err)
	}

	return &data, nil
}

func (h *OAuthHandler) generateUniqueUsername(ctx context.Context, preferred, provider, oauthID string) string {
	clean := strings.ToLower(strings.TrimSpace(preferred))
	var b strings.Builder
	for _, r := range clean {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	candidate := b.String()
	if len(candidate) < 3 || storage.IsReservedUsername(candidate) {
		candidate = provider + "_" + oauthID
	}
	if len(candidate) > 20 {
		candidate = candidate[:20]
	}

	base := candidate
	for i := 1; i <= 50; i++ {
		_, err := h.repo.GetUser(ctx, candidate)
		if errors.Is(err, storage.ErrUserNotFound) {
			return candidate
		}
		candidate = fmt.Sprintf("%s_%d", base, i)
	}
	return fmt.Sprintf("%s_%d", base, time.Now().Unix()%10000)
}

func getRequestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if fHost := r.Header.Get("X-Forwarded-Host"); fHost != "" {
		host = fHost
	}
	return scheme + "://" + host
}

func setOAuthCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
	})
}

func getOAuthCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func clearOAuthCookie(w http.ResponseWriter, r *http.Request, name string) {
	setOAuthCookie(w, r, name, "", -1)
}

func boolToStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
