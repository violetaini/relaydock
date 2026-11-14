package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func setupTestOAuthEnv(t *testing.T) (*OAuthHandler, *storage.TrafficRepository, *auth.TokenStore) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "oauth-test.db")
	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatalf("failed to create test repo: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	tokenStore := auth.NewTokenStore(24 * time.Hour)
	handler := NewOAuthHandler(repo, tokenStore)
	return handler, repo, tokenStore
}

func TestOAuth_PublicProviders(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	// 初始状态：无启用的提供商
	req := httptest.NewRequest(http.MethodGet, "/api/public/oauth/providers", nil)
	rec := httptest.NewRecorder()
	h.GetPublicProviders(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp OAuthPublicResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Providers) != 0 {
		t.Fatalf("expected 0 providers, got %d", len(resp.Providers))
	}
	if !resp.AutoRegister {
		t.Fatal("expected default auto_register to be true")
	}

	// 启用 GitHub 与 OIDC
	_ = repo.SetSystemSetting(ctx, SettingOAuthGitHubEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthGitHubClientID, "gh-client-123")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCIssuer, "https://sso.example.com")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCClientID, "oidc-client-456")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCDisplayName, "CustomSSO")

	rec2 := httptest.NewRecorder()
	h.GetPublicProviders(rec2, req)

	var resp2 OAuthPublicResponse
	if err := json.NewDecoder(rec2.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode response 2: %v", err)
	}
	if len(resp2.Providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(resp2.Providers))
	}
	if resp2.Providers[0].ID != "github" || resp2.Providers[0].Name != "GitHub" {
		t.Errorf("unexpected provider 0: %+v", resp2.Providers[0])
	}
	if resp2.Providers[1].ID != "oidc" || resp2.Providers[1].Name != "CustomSSO" {
		t.Errorf("unexpected provider 1: %+v", resp2.Providers[1])
	}
}

func TestOAuth_AdminConfig(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	// 保存配置
	savePayload := OAuthConfig{
		GitHubEnabled:      true,
		GitHubClientID:     "my-gh-client",
		GitHubClientSecret: "super-secret-gh-key-9999",
		GoogleEnabled:      true,
		GoogleClientID:     "my-google-client",
		GoogleClientSecret: "super-secret-google-key",
		AutoRegister:       false,
		AutoLinkEmail:      true,
	}
	body, _ := json.Marshal(savePayload)
	reqSave := httptest.NewRequest(http.MethodPost, "/api/admin/oauth/config", bytes.NewReader(body))
	recSave := httptest.NewRecorder()
	h.SaveAdminConfig(recSave, reqSave)

	if recSave.Code != http.StatusOK {
		t.Fatalf("save config failed, code: %d, body: %s", recSave.Code, recSave.Body.String())
	}

	// 读取配置，验证 Secret 脱敏与 Callback URLs
	reqGet := httptest.NewRequest(http.MethodGet, "/api/admin/oauth/config", nil)
	reqGet.Host = "panel.example.com"
	recGet := httptest.NewRecorder()
	h.GetAdminConfig(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("get config failed, code: %d", recGet.Code)
	}

	var loaded OAuthConfig
	if err := json.NewDecoder(recGet.Body).Decode(&loaded); err != nil {
		t.Fatalf("decode config: %v", err)
	}

	if !loaded.GitHubEnabled || loaded.GitHubClientID != "my-gh-client" {
		t.Errorf("unexpected github config: %+v", loaded)
	}
	if !strings.Contains(loaded.GitHubClientSecret, "*") {
		t.Errorf("expected secret to be masked, got: %s", loaded.GitHubClientSecret)
	}
	if loaded.CallbackURLs["github"] != "http://panel.example.com/api/oauth/github/callback" {
		t.Errorf("unexpected callback url: %s", loaded.CallbackURLs["github"])
	}

	// 再次保存，回传带有掩码的 Secret，确认原 Secret 未被覆写
	saveAgain := loaded
	bodyAgain, _ := json.Marshal(saveAgain)
	reqAgain := httptest.NewRequest(http.MethodPost, "/api/admin/oauth/config", bytes.NewReader(bodyAgain))
	recAgain := httptest.NewRecorder()
	h.SaveAdminConfig(recAgain, reqAgain)

	rawSecret, _ := repo.GetSystemSetting(ctx, SettingOAuthGitHubClientSecret)
	if rawSecret != "super-secret-gh-key-9999" {
		t.Fatalf("raw secret overwritten by mask! got %q", rawSecret)
	}
}

func TestOAuth_PrepareBindAndUnbind(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	// 创建测试用户
	hash, _ := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.MinCost)
	if err := repo.CreateUser(ctx, "tester", "tester@example.com", "Tester", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}

	_ = repo.SetSystemSetting(ctx, SettingOAuthGitHubEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthGitHubClientID, "gh-client-abc")

	// 模拟已登录用户的请求
	body := `{"provider":"github"}`
	req := httptest.NewRequest(http.MethodPost, "/api/user/oauth/prepare-bind", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUsername(req.Context(), "tester"))
	rec := httptest.NewRecorder()
	h.PrepareBind(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body: %s", rec.Code, rec.Body.String())
	}

	var bindResp struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&bindResp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bindResp.URL, "https://github.com/login/oauth/authorize") {
		t.Fatalf("unexpected auth url: %s", bindResp.URL)
	}

	// 检查 Cookie 是否包含防 CSRF nonce
	cookies := rec.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == oauthStateCookieName {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil || stateCookie.Value == "" {
		t.Fatal("expected state cookie to be set")
	}

	// 手动绑定一个第三方身份并测试 GetUserIdentities & UnbindUserIdentity
	err := repo.BindOAuthIdentity(ctx, &storage.UserOAuthIdentity{
		Username:  "tester",
		Provider:  "github",
		OAuthID:   "gh_999",
		Email:     "gh_test@example.com",
		Name:      "OctoCat",
		AvatarURL: "https://avatar.example.com/cat.png",
	})
	if err != nil {
		t.Fatal(err)
	}

	reqList := httptest.NewRequest(http.MethodGet, "/api/user/oauth/identities", nil)
	reqList = reqList.WithContext(auth.ContextWithUsername(reqList.Context(), "tester"))
	recList := httptest.NewRecorder()
	h.GetUserIdentities(recList, reqList)

	var list []storage.UserOAuthIdentity
	_ = json.NewDecoder(recList.Body).Decode(&list)
	if len(list) != 1 || list[0].OAuthID != "gh_999" {
		t.Fatalf("unexpected identities: %+v", list)
	}

	// 解绑
	reqUnbind := httptest.NewRequest(http.MethodPost, "/api/user/oauth/unbind", strings.NewReader(`{"provider":"github"}`))
	reqUnbind = reqUnbind.WithContext(auth.ContextWithUsername(reqUnbind.Context(), "tester"))
	recUnbind := httptest.NewRecorder()
	h.UnbindUserIdentity(recUnbind, reqUnbind)

	if recUnbind.Code != http.StatusOK {
		t.Fatalf("expected 200 on unbind, got %d", recUnbind.Code)
	}

	// 再次查询确认已解绑
	recList2 := httptest.NewRecorder()
	h.GetUserIdentities(recList2, reqList)
	var list2 []storage.UserOAuthIdentity
	_ = json.NewDecoder(recList2.Body).Decode(&list2)
	if len(list2) != 0 {
		t.Fatalf("expected 0 identities after unbind, got %d", len(list2))
	}
}

func TestOAuth_HandleCallback_AutoRegister(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	_ = repo.SetSystemSetting(ctx, SettingOAuthGitHubEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthGitHubClientID, "gh-client-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthGitHubClientSecret, "gh-secret-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthAutoRegister, "1")

	// 生成合法的 state 与 cookie
	nonce := "random_nonce_12345"
	stateToken := h.generateStateToken(oauthStateData{
		Nonce:     nonce,
		Provider:  "github",
		Bind:      false,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})

	// 使用 Mock GitHub 服务器接管网络请求
	mockGitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "mock_gho_token_987",
			})
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         1234567,
				"login":      "github_coder",
				"name":       "Coder",
				"email":      "coder@github.example",
				"avatar_url": "https://avatars.example.com/coder",
			})
		case "/user/emails":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"email": "coder@github.example", "primary": true, "verified": true},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockGitHub.Close()

	// 临时修改 mock 客户端传输层，将发往 github.com 的请求重定向到 mockGitHub
	h.SetHTTPClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			targetURL := mockGitHub.URL + req.URL.Path
			newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, targetURL, req.Body)
			newReq.Header = req.Header
			return http.DefaultClient.Do(newReq)
		}),
	})

	// 模拟回调请求
	req := httptest.NewRequest(http.MethodGet, "/api/oauth/github/callback?code=mock_code&state="+stateToken, nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: nonce})
	rec := httptest.NewRecorder()

	h.HandleCallback(rec, req, "github")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect 302, got %d, body: %s", rec.Code, rec.Body.String())
	}

	redirectURL := rec.Header().Get("Location")
	if !strings.Contains(redirectURL, "oauth_token=") {
		t.Fatalf("expected redirect with oauth_token, got: %s", redirectURL)
	}

	// 验证新用户已成功自动创建并绑定
	ident, err := repo.GetOAuthIdentity(ctx, "github", "1234567")
	if err != nil {
		t.Fatalf("failed to get created identity: %v", err)
	}
	if ident.Email != "coder@github.example" {
		t.Errorf("unexpected email in identity: %s", ident.Email)
	}

	user, err := repo.GetUser(ctx, ident.Username)
	if err != nil {
		t.Fatalf("failed to find created user %q: %v", ident.Username, err)
	}
	if user.Email != "coder@github.example" {
		t.Errorf("unexpected user email: %s", user.Email)
	}
}

func TestOAuth_HandleCallback_AutoLinkEmail(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	// 先创建一个本地用户
	hash, _ := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.MinCost)
	if err := repo.CreateUser(ctx, "existing_alice", "alice@example.com", "Alice", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}

	_ = repo.SetSystemSetting(ctx, SettingOAuthGoogleEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthGoogleClientID, "g-client-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthGoogleClientSecret, "g-secret-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthAutoRegister, "0") // 禁用自动注册
	_ = repo.SetSystemSetting(ctx, SettingOAuthAutoLinkEmail, "1") // 启用邮箱自动关联

	nonce := "nonce_google_test"
	stateToken := h.generateStateToken(oauthStateData{
		Nonce:     nonce,
		Provider:  "google",
		Bind:      false,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})

	mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "mock_google_token_111",
			})
		case "/oauth2/v3/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            "google_sub_999",
				"email":          "alice@example.com", // 与本地 existing_alice 邮箱一致
				"email_verified": true,
				"name":           "Alice Google",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockGoogle.Close()

	h.SetHTTPClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			if strings.HasSuffix(path, "/token") {
				path = "/token"
			}
			targetURL := mockGoogle.URL + path
			newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, targetURL, req.Body)
			newReq.Header = req.Header
			return http.DefaultClient.Do(newReq)
		}),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/oauth/google/callback?code=mock_code&state="+stateToken, nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: nonce})
	rec := httptest.NewRecorder()

	h.HandleCallback(rec, req, "google")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "oauth_token=") || !strings.Contains(loc, "oauth_username=existing_alice") {
		t.Fatalf("expected logged in as existing_alice, got location: %s", loc)
	}

	// 确认绑定记录已写入
	ident, err := repo.GetOAuthIdentity(ctx, "google", "google_sub_999")
	if err != nil {
		t.Fatalf("expected identity bound to existing_alice: %v", err)
	}
	if ident.Username != "existing_alice" {
		t.Errorf("expected username existing_alice, got %s", ident.Username)
	}
}

func TestOAuth_HandleCallback_OIDC(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	mockOIDC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": "https://auth.example.com/oauth/authorize",
				"token_endpoint":         "https://auth.example.com/oauth/token",
				"userinfo_endpoint":      "https://auth.example.com/oauth/userinfo",
			})
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "mock_oidc_access_token_123",
			})
		case "/oauth/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":                "authentik_user_777",
				"email":              "bob@authentik.example",
				"preferred_username": "bob_sso",
				"name":               "Bob SSO",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockOIDC.Close()

	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCIssuer, mockOIDC.URL)
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCClientID, "oidc-client-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCClientSecret, "oidc-secret-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthAutoRegister, "1")

	nonce := "nonce_oidc_test"
	stateToken := h.generateStateToken(oauthStateData{
		Nonce:     nonce,
		Provider:  "oidc",
		Bind:      false,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})

	h.SetHTTPClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			targetURL := mockOIDC.URL + path
			newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, targetURL, req.Body)
			newReq.Header = req.Header
			return http.DefaultClient.Do(newReq)
		}),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/oauth/oidc/callback?code=mock_code&state="+stateToken, nil)
	req.AddCookie(&http.Cookie{Name: oauthStateCookieName, Value: nonce})
	rec := httptest.NewRecorder()

	h.HandleCallback(rec, req, "oidc")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect 302, got %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "oauth_token=") {
		t.Fatalf("expected logged in via oidc, got location: %s", loc)
	}

	// 确认绑定与用户创建
	ident, err := repo.GetOAuthIdentity(ctx, "oidc", "authentik_user_777")
	if err != nil {
		t.Fatalf("expected identity created: %v", err)
	}
	if ident.Email != "bob@authentik.example" {
		t.Errorf("unexpected email in identity: %s", ident.Email)
	}
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
