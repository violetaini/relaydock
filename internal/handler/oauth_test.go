package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if !strings.Contains(redirectURL, "oauth_code=") {
		t.Fatalf("expected redirect with oauth_code, got: %s", redirectURL)
	}

	u, _ := url.Parse(redirectURL)
	code := u.Query().Get("oauth_code")
	if code == "" {
		t.Fatalf("missing oauth_code in redirect: %s", redirectURL)
	}

	// 验证一次性兑换
	exchBody, _ := json.Marshal(map[string]string{"code": code})
	exchReq := httptest.NewRequest(http.MethodPost, "/api/public/oauth/exchange", bytes.NewReader(exchBody))
	exchRec := httptest.NewRecorder()
	for _, c := range rec.Result().Cookies() {
		exchReq.AddCookie(c)
	}
	h.ExchangeOAuthCode(exchRec, exchReq)

	if exchRec.Code != http.StatusOK {
		t.Fatalf("expected exchange 200, got %d, body: %s", exchRec.Code, exchRec.Body.String())
	}

	var exchResp struct {
		Token    string `json:"token"`
		Username string `json:"username"`
	}
	_ = json.NewDecoder(exchRec.Body).Decode(&exchResp)
	if exchResp.Token == "" || exchResp.Username != "coder" {
		t.Fatalf("unexpected exchange resp: %+v", exchResp)
	}

	// 重复使用同一授权码必须失败 (防重放)
	exchRec2 := httptest.NewRecorder()
	exchReq2 := httptest.NewRequest(http.MethodPost, "/api/public/oauth/exchange", bytes.NewReader(exchBody))
	h.ExchangeOAuthCode(exchRec2, exchReq2)
	if exchRec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected second exchange to fail with 401, got %d", exchRec2.Code)
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
	_ = repo.SetSystemSetting(ctx, SettingOAuthAutoRegister, "0")  // 禁用自动注册
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
	if !strings.Contains(loc, "oauth_code=") {
		t.Fatalf("expected redirect with oauth_code, got location: %s", loc)
	}

	u, _ := url.Parse(loc)
	code := u.Query().Get("oauth_code")
	exchBody, _ := json.Marshal(map[string]string{"code": code})
	exchReq := httptest.NewRequest(http.MethodPost, "/api/public/oauth/exchange", bytes.NewReader(exchBody))
	exchRec := httptest.NewRecorder()
	for _, c := range rec.Result().Cookies() {
		exchReq.AddCookie(c)
	}
	h.ExchangeOAuthCode(exchRec, exchReq)

	if exchRec.Code != http.StatusOK {
		t.Fatalf("expected exchange 200, got %d", exchRec.Code)
	}
	var exchResp struct {
		Username string `json:"username"`
	}
	_ = json.NewDecoder(exchRec.Body).Decode(&exchResp)
	if exchResp.Username != "existing_alice" {
		t.Fatalf("expected existing_alice, got %s", exchResp.Username)
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

var testOIDCKey, _ = rsa.GenerateKey(rand.Reader, 2048)

func createMockJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sum := sha256.Sum256([]byte(header + "." + payload))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, testOIDCKey, crypto.SHA256, sum[:])
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestOAuth_HandleCallback_OIDC(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	nonce := "nonce_oidc_test"
	var mockServerURL string

	mockOIDC := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "test", "n": base64.RawURLEncoding.EncodeToString(testOIDCKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(testOIDCKey.E)).Bytes())}}})
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": mockServerURL, "jwks_uri": mockServerURL + "/jwks",
				"authorization_endpoint": mockServerURL + "/oauth/authorize",
				"token_endpoint":         mockServerURL + "/oauth/token",
				"userinfo_endpoint":      mockServerURL + "/oauth/userinfo",
			})
		case "/oauth/token":
			idToken := createMockJWT(map[string]any{
				"iss":            mockServerURL,
				"aud":            "oidc-client-1",
				"sub":            "authentik_user_777",
				"nonce":          nonce,
				"exp":            time.Now().Add(10 * time.Minute).Unix(),
				"email":          "bob@authentik.example",
				"email_verified": true,
			})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "mock_oidc_access_token_123",
				"id_token":     idToken,
			})
		case "/oauth/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":                "authentik_user_777",
				"email":              "bob@authentik.example",
				"email_verified":     true,
				"preferred_username": "bob_sso",
				"name":               "Bob SSO",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockOIDC.Close()
	mockServerURL = mockOIDC.URL
	h.SetHTTPClient(mockOIDC.Client())

	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCIssuer, mockServerURL)
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCClientID, "oidc-client-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCClientSecret, "oidc-secret-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthAutoRegister, "1")

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
			return mockOIDC.Client().Do(newReq)
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
	if !strings.Contains(loc, "oauth_code=") {
		t.Fatalf("expected logged in via oidc with oauth_code, got location: %s", loc)
	}

	u, _ := url.Parse(loc)
	code := u.Query().Get("oauth_code")
	exchBody, _ := json.Marshal(map[string]string{"code": code})
	exchReq := httptest.NewRequest(http.MethodPost, "/api/public/oauth/exchange", bytes.NewReader(exchBody))
	exchRec := httptest.NewRecorder()
	for _, c := range rec.Result().Cookies() {
		exchReq.AddCookie(c)
	}
	h.ExchangeOAuthCode(exchRec, exchReq)

	if exchRec.Code != http.StatusOK {
		t.Fatalf("expected exchange 200, got %d", exchRec.Code)
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

func TestOAuth_SilentSSO(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	mockOIDC := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": "https://sso.example.com", "jwks_uri": "https://sso.example.com/jwks",
			"authorization_endpoint": "https://sso.example.com/oauth/authorize",
			"token_endpoint":         "https://sso.example.com/oauth/token",
			"userinfo_endpoint":      "https://sso.example.com/oauth/userinfo",
		})
	}))
	defer mockOIDC.Close()

	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCIssuer, "https://sso.example.com")
	_ = repo.SetSystemSetting(ctx, SettingOAuthOIDCClientID, "client-test")

	h.SetHTTPClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			targetURL := mockOIDC.URL + req.URL.Path
			newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, targetURL, req.Body)
			newReq.Header = req.Header
			return mockOIDC.Client().Do(newReq)
		}),
	})

	// 1. 发起静默登录检测
	reqLogin := httptest.NewRequest(http.MethodGet, "/api/oauth/oidc/login?silent=true", nil)
	recLogin := httptest.NewRecorder()
	h.HandleLogin(recLogin, reqLogin, "oidc")

	if recLogin.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", recLogin.Code)
	}
	targetURL := recLogin.Header().Get("Location")
	if !strings.Contains(targetURL, "prompt=none") {
		t.Fatalf("expected prompt=none in silent auth url, got: %s", targetURL)
	}

	u, _ := url.Parse(targetURL)
	stateParam := u.Query().Get("state")
	stateData, err := h.verifyStateToken(stateParam)
	if err != nil {
		t.Fatalf("verify state token failed: %v", err)
	}
	if !stateData.Silent {
		t.Fatal("expected stateData.Silent to be true")
	}

	// 2. 模拟 SSO 端因用户未登录返回 login_required
	reqCallback := httptest.NewRequest(http.MethodGet, "/api/oauth/oidc/callback?error=login_required&state="+stateParam, nil)
	recCallback := httptest.NewRecorder()
	h.HandleCallback(recCallback, reqCallback, "oidc")

	if recCallback.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", recCallback.Code)
	}
	cbLoc := recCallback.Header().Get("Location")
	if cbLoc != "/?sso_silent=guest" {
		t.Fatalf("expected redirect to /?sso_silent=guest, got: %s", cbLoc)
	}

	// 3. 对比: 非静默登录请求若返回 error=login_required，则应重定向至 oauth_error
	nonSilentState := h.generateStateToken(oauthStateData{
		Nonce:     "ns_nonce",
		Provider:  "oidc",
		Silent:    false,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})
	reqNormal := httptest.NewRequest(http.MethodGet, "/api/oauth/oidc/callback?error=login_required&state="+nonSilentState, nil)
	recNormal := httptest.NewRecorder()
	h.HandleCallback(recNormal, reqNormal, "oidc")

	if recNormal.Header().Get("Location") != "/?oauth_error=login_required" {
		t.Fatalf("expected oauth_error=login_required for non-silent, got: %s", recNormal.Header().Get("Location"))
	}
}

func TestOAuth_AutoLinkEmail_UnverifiedRejected(t *testing.T) {
	h, repo, _ := setupTestOAuthEnv(t)
	ctx := context.Background()

	// 创建本地已有用户
	hash, _ := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.MinCost)
	if err := repo.CreateUser(ctx, "victim_user", "victim@example.com", "Victim", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}

	_ = repo.SetSystemSetting(ctx, SettingOAuthGoogleEnabled, "1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthGoogleClientID, "g-client-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthGoogleClientSecret, "g-secret-1")
	_ = repo.SetSystemSetting(ctx, SettingOAuthAutoRegister, "0")  // 关闭注册
	_ = repo.SetSystemSetting(ctx, SettingOAuthAutoLinkEmail, "1") // 开启自动关联

	nonce := "nonce_unverified_test"
	stateToken := h.generateStateToken(oauthStateData{
		Nonce:     nonce,
		Provider:  "google",
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})

	// 模拟第三方返回该邮箱但 email_verified 为 false
	mockGoogle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "mock_tok"})
		case "/oauth2/v3/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            "attacker_sub_666",
				"email":          "victim@example.com",
				"email_verified": false, // 未验证邮箱！
				"name":           "Attacker",
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

	// 自动关联被拒绝，由于 auto_register=false，返回 registration_disabled
	if rec.Header().Get("Location") != "/?oauth_error=registration_disabled" {
		t.Fatalf("expected registration_disabled due to unverified email rejected, got: %s", rec.Header().Get("Location"))
	}

	// 确认 victim_user 未被第三方身份绑定
	ident, _ := repo.GetOAuthIdentity(ctx, "google", "attacker_sub_666")
	if ident != nil {
		t.Fatal("security breach: unverified email was erroneously linked to victim!")
	}
}

func TestOAuth_OIDC_IDTokenValidation(t *testing.T) {
	expectedIssuer := "https://sso.example.com"
	expectedClientID := "my-panel-client"
	expectedNonce := "secure-nonce-123"

	// 1. 合法 ID Token
	validToken := createMockJWT(map[string]any{
		"iss":            expectedIssuer,
		"aud":            expectedClientID,
		"sub":            "user-1",
		"nonce":          expectedNonce,
		"exp":            time.Now().Add(10 * time.Minute).Unix(),
		"email":          "test@example.com",
		"email_verified": true,
	})
	claims, err := parseAndValidateIDToken(validToken, expectedIssuer, expectedClientID, expectedNonce)
	if err != nil {
		t.Fatalf("expected valid token to pass, got: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("expected sub user-1, got %s", claims.Subject)
	}

	// 2. Issuer 不匹配
	badIssToken := createMockJWT(map[string]any{
		"iss":   "https://evil-issuer.com",
		"aud":   expectedClientID,
		"sub":   "user-1",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"nonce": expectedNonce,
	})
	if _, err := parseAndValidateIDToken(badIssToken, expectedIssuer, expectedClientID, expectedNonce); err == nil {
		t.Fatal("expected error on mismatched issuer, got nil")
	}

	// 3. Audience 不匹配
	badAudToken := createMockJWT(map[string]any{
		"iss":   expectedIssuer,
		"aud":   "wrong-client-id",
		"sub":   "user-1",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"nonce": expectedNonce,
	})
	if _, err := parseAndValidateIDToken(badAudToken, expectedIssuer, expectedClientID, expectedNonce); err == nil {
		t.Fatal("expected error on mismatched audience, got nil")
	}

	// 4. Nonce 不匹配
	badNonceToken := createMockJWT(map[string]any{
		"iss":   expectedIssuer,
		"aud":   expectedClientID,
		"sub":   "user-1",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"nonce": "tampered-nonce",
	})
	if _, err := parseAndValidateIDToken(badNonceToken, expectedIssuer, expectedClientID, expectedNonce); err == nil {
		t.Fatal("expected error on mismatched nonce, got nil")
	}

	// 5. 过期 Token
	expiredToken := createMockJWT(map[string]any{
		"iss":   expectedIssuer,
		"aud":   expectedClientID,
		"sub":   "user-1",
		"exp":   time.Now().Add(-10 * time.Minute).Unix(),
		"nonce": expectedNonce,
	})
	if _, err := parseAndValidateIDToken(expiredToken, expectedIssuer, expectedClientID, expectedNonce); err == nil {
		t.Fatal("expected error on expired token, got nil")
	}
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
