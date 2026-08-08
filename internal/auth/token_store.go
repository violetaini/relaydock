package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type session struct {
	username string
	expiry   time.Time
	service  bool
}

type websocketTicket struct {
	username     string
	sessionToken string
	expiry       time.Time
}

type contextKey string

const (
	userContextKey         contextKey = "github.com/violetaini/relaydock/auth/username"
	sessionTokenContextKey contextKey = "github.com/violetaini/relaydock/auth/session-token"
	authSourceContextKey   contextKey = "github.com/violetaini/relaydock/auth/source"
)

type authSourceMarker struct{}

const GlobalAPITokenSubject = "api-token-admin"

const AuthHeader = "Authorization"

type TokenStore struct {
	mu      sync.RWMutex
	tokens  map[string]session
	tickets map[string]websocketTicket
	ttl     time.Duration
	secret  []byte // HMAC signing secret; nil = use plain random tokens
}

func NewTokenStore(ttl time.Duration) *TokenStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &TokenStore{
		tokens:  make(map[string]session),
		tickets: make(map[string]websocketTicket),
		ttl:     ttl,
	}
}

func (s *TokenStore) SetSecret(secret string) {
	if secret != "" {
		s.secret = []byte(secret)
	}
}

func (s *TokenStore) Issue(username string) (string, time.Time, error) {
	return s.IssueWithTTL(username, s.ttl)
}

// 使用自定义 TTL 为指定用户名创建新令牌。
func (s *TokenStore) IssueWithTTL(username string, ttl time.Duration) (string, time.Time, error) {
	return s.issueWithTTL(username, ttl, false)
}

// IssueServiceWithTTL creates an in-process service credential. Service
// credentials remain attached to their account for authorization checks, but
// are not browser login sessions and therefore survive password rotation.
func (s *TokenStore) IssueServiceWithTTL(username string, ttl time.Duration) (string, time.Time, error) {
	return s.issueWithTTL(username, ttl, true)
}

func (s *TokenStore) issueWithTTL(username string, ttl time.Duration, service bool) (string, time.Time, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", time.Time{}, errors.New("username is required")
	}

	if ttl <= 0 {
		ttl = s.ttl
	}

	token, err := s.generateToken()
	if err != nil {
		return "", time.Time{}, err
	}

	expiry := time.Now().Add(ttl)

	s.mu.Lock()
	s.tokens[token] = session{username: username, expiry: expiry, service: service}
	s.mu.Unlock()

	return token, expiry, nil
}

func (s *TokenStore) Validate(token string) bool {
	_, ok := s.Lookup(token)
	return ok
}

// StartCleanup 周期扫描删除过期 token。
// 必要性:tokens map 平时只在 Lookup 命中过期 / Revoke 时删,过期后不再被 Lookup 的 token
// (登出未 Revoke、客户端换新 token)会永久驻留 → 长期运行缓慢泄漏。阻塞调用,需 go 启动。
func (s *TokenStore) StartCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpired()
		}
	}
}

// cleanupExpired 删除所有已过期的 token(单独抽出便于测试)。
func (s *TokenStore) cleanupExpired() {
	now := time.Now()
	s.mu.Lock()
	for token, sess := range s.tokens {
		if now.After(sess.expiry) {
			delete(s.tokens, token)
		}
	}
	for ticket, sess := range s.tickets {
		if now.After(sess.expiry) {
			delete(s.tickets, ticket)
		}
	}
	s.mu.Unlock()
}

func (s *TokenStore) Revoke(token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}

	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
}

// RevokeUser removes interactive login sessions belonging to username. Service
// credentials have an independent lifecycle and are intentionally preserved
// across password changes.
func (s *TokenStore) RevokeUser(username string) {
	s.revokeUser(username, false)
}

// RevokeAllForUser removes interactive and service credentials. Account
// disable/delete flows must use this stronger operation.
func (s *TokenStore) RevokeAllForUser(username string) {
	s.revokeUser(username, true)
}

func (s *TokenStore) revokeUser(username string, includeServices bool) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}

	s.mu.Lock()
	for token, sess := range s.tokens {
		if sess.username == username && (includeServices || !sess.service) {
			delete(s.tokens, token)
		}
	}
	for ticket, sess := range s.tickets {
		if sess.username == username {
			if parent, ok := s.tokens[sess.sessionToken]; ok && parent.service && !includeServices {
				continue
			}
			delete(s.tickets, ticket)
		}
	}
	s.mu.Unlock()
}

func (s *TokenStore) RevokeAll() {
	s.mu.Lock()
	s.tokens = make(map[string]session)
	s.tickets = make(map[string]websocketTicket)
	s.mu.Unlock()
}

// 将会话添加到内存存储中。用于在启动时从数据库恢复会话。
func (s *TokenStore) LoadSession(token, username string, expiry time.Time) {
	token = strings.TrimSpace(token)
	username = strings.TrimSpace(username)
	if token == "" || username == "" {
		return
	}

	// 跳过过期的会话
	if time.Now().After(expiry) {
		return
	}

	s.mu.Lock()
	s.tokens[token] = session{username: username, expiry: expiry}
	s.mu.Unlock()
}

// 将内存中的会话从 oldUsername 重写为 newUsername。
func (s *TokenStore) UpdateUsername(oldUsername, newUsername string) {
	oldUsername = strings.TrimSpace(oldUsername)
	newUsername = strings.TrimSpace(newUsername)
	if oldUsername == "" || newUsername == "" || oldUsername == newUsername {
		return
	}

	s.mu.Lock()
	for token, sess := range s.tokens {
		if sess.username == oldUsername {
			sess.username = newUsername
			s.tokens[token] = sess
		}
	}
	for ticket, sess := range s.tickets {
		if sess.username == oldUsername {
			sess.username = newUsername
			s.tickets[ticket] = sess
		}
	}
	s.mu.Unlock()
}

// IssueWebSocketTicket creates a short-lived, one-time credential for browser
// WebSocket handshakes. Long-lived bearer tokens must not appear in URLs.
func (s *TokenStore) IssueWebSocketTicket(username, sessionToken string, ttl time.Duration) (string, time.Time, error) {
	username = strings.TrimSpace(username)
	sessionToken = strings.TrimSpace(sessionToken)
	if username == "" || sessionToken == "" {
		return "", time.Time{}, errors.New("username and session token are required")
	}
	if owner, ok := s.Lookup(sessionToken); !ok || owner != username {
		return "", time.Time{}, errors.New("active browser session is required")
	}
	if ttl <= 0 || ttl > time.Minute {
		ttl = 30 * time.Second
	}
	ticket, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiry := time.Now().Add(ttl)
	s.mu.Lock()
	now := time.Now()
	oldestTicket := ""
	oldestExpiry := time.Time{}
	userTicketCount := 0
	for existing, pending := range s.tickets {
		if now.After(pending.expiry) {
			delete(s.tickets, existing)
			continue
		}
		if pending.username == username {
			userTicketCount++
			if oldestTicket == "" || pending.expiry.Before(oldestExpiry) {
				oldestTicket, oldestExpiry = existing, pending.expiry
			}
		}
	}
	if userTicketCount >= maxWebSocketTicketsPerUser && oldestTicket != "" {
		delete(s.tickets, oldestTicket)
	}
	s.tickets[ticket] = websocketTicket{username: username, sessionToken: sessionToken, expiry: expiry}
	s.mu.Unlock()
	return ticket, expiry, nil
}

const maxWebSocketTicketsPerUser = 4

// ConsumeWebSocketTicket validates and atomically removes a ticket so replayed
// handshake URLs cannot establish a second connection.
func (s *TokenStore) ConsumeWebSocketTicket(ticket string) (username, sessionToken string, ok bool) {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" {
		return "", "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.tickets[ticket]
	if !ok {
		return "", "", false
	}
	delete(s.tickets, ticket)
	if time.Now().After(sess.expiry) {
		return "", "", false
	}
	activeUsername, active := s.tokens[sess.sessionToken]
	if !active || time.Now().After(activeUsername.expiry) || activeUsername.username != sess.username {
		return "", "", false
	}
	return sess.username, sess.sessionToken, true
}

// 如果会话有效，查找将返回与所提供的令牌关联的用户名。
func (s *TokenStore) Lookup(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}

	// 如果设置了 secret，验证 HMAC 签名
	if s.secret != nil {
		parts := strings.SplitN(token, ".", 2)
		if len(parts) != 2 {
			return "", false
		}
		mac := hmac.New(sha256.New, s.secret)
		mac.Write([]byte(parts[0]))
		expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
			return "", false
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.tokens[token]
	if !ok {
		return "", false
	}

	if time.Now().After(session.expiry) {
		delete(s.tokens, token)
		return "", false
	}

	return session.username, true
}

func ContextWithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, userContextKey, username)
}

func ContextWithSessionToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sessionTokenContextKey, token)
}

// ContextWithGlobalAPIToken records the authenticated source separately from
// the display subject. A username can never forge this marker.
func ContextWithGlobalAPIToken(ctx context.Context) context.Context {
	ctx = ContextWithUsername(ctx, GlobalAPITokenSubject)
	return context.WithValue(ctx, authSourceContextKey, authSourceMarker{})
}

func IsGlobalAPIToken(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, ok := ctx.Value(authSourceContextKey).(authSourceMarker)
	return ok
}

// 从请求上下文中检索经过身份验证的用户名。
func UsernameFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	username, _ := ctx.Value(userContextKey).(string)
	return username
}

func SessionTokenFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	token, _ := ctx.Value(sessionTokenContextKey).(string)
	return token
}

// 返回用户名（如果存在），否则返回提供的后备值。
func UsernameOrDefault(ctx context.Context, fallback string) string {
	if name := UsernameFromContext(ctx); name != "" {
		return name
	}
	return fallback
}

func randomToken(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *TokenStore) generateToken() (string, error) {
	raw, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if s.secret == nil {
		return raw, nil
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(raw))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return raw + "." + sig, nil
}

func RequireToken(store *TokenStore, repo UserRepository, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveUser := func(username string) bool {
			if repo != nil {
				user, err := repo.GetUser(r.Context(), username)
				if err != nil || !user.IsActive {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"forbidden"}`))
					return false
				}
			}
			ctx := ContextWithUsername(r.Context(), username)
			next.ServeHTTP(w, r.WithContext(ctx))
			return true
		}

		token := BearerToken(r)

		// 1) 会话 token
		if username, ok := store.Lookup(token); ok {
			serveUser(username)
			return
		}

		if repo != nil {
			// 2) 每用户 API 令牌(MCP / 程序化访问):解析为真实用户名,权限随该用户登录态
			if username, ok := repo.ResolveAPIToken(r.Context(), token); ok && username != "" {
				serveUser(username)
				return
			}

			// 3) 全局 API token，授予管理员权限。
			apiToken, err := repo.GetAPIToken(r.Context())
			if err == nil && token == apiToken && apiToken != "" {
				ctx := ContextWithGlobalAPIToken(r.Context())
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		WriteUnauthorizedResponse(w)
	})
}

// BearerToken returns an Authorization bearer token. A single raw header value
// remains accepted for compatibility with existing API clients. Query
// parameters are intentionally excluded so session credentials stay out of
// access logs, referrers and copied URLs.
func BearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(r.Header.Get(AuthHeader)))
	if len(fields) == 1 {
		return fields[0]
	}
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
		return strings.TrimSpace(fields[1])
	}
	return ""
}

// RequireWebSocketTicket authenticates one WebSocket upgrade using a
// short-lived ticket. The ticket is consumed before the handler runs.
func RequireWebSocketTicket(store *TokenStore, repo UserRepository, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, sessionToken, ok := store.ConsumeWebSocketTicket(r.URL.Query().Get("ticket"))
		if !ok {
			WriteUnauthorizedResponse(w)
			return
		}
		if repo != nil {
			user, err := repo.GetUser(r.Context(), username)
			if err != nil || !user.IsActive {
				WriteUnauthorizedResponse(w)
				return
			}
		}
		ctx := ContextWithUsername(r.Context(), username)
		ctx = ContextWithSessionToken(ctx, sessionToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserRepository 提供用户信息以进行授权检查。
type UserRepository interface {
	GetUser(ctx context.Context, username string) (User, error)
	GetAPIToken(ctx context.Context) (string, error)
	// ResolveAPIToken 用每用户 API 令牌(明文)解析所属用户名;未命中返回 ok=false。
	ResolveAPIToken(ctx context.Context, token string) (username string, ok bool)
}

// 角色常量。与 storage 包的 RoleAdmin / RoleUser 保持同步,但放在 auth 包内避免循环依赖。
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User表示授权所需的基本用户信息。
type User struct {
	Username string
	Role     string
	IsActive bool
}

// 确保已认证的用户具有管理员角色
func RequireAdmin(store *TokenStore, repo UserRepository, next http.Handler) http.Handler {
	return RequireToken(store, repo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := UsernameFromContext(r.Context())
		if username == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		}

		// The global API token carries an unforgeable authentication-source
		// marker. User-controlled usernames are never treated as credentials.
		if IsGlobalAPIToken(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}

		user, err := repo.GetUser(r.Context(), username)
		if err != nil || !user.IsActive || user.Role != RoleAdmin {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		}

		next.ServeHTTP(w, r)
	}))
}

func WriteUnauthorizedResponse(w http.ResponseWriter) {
	if w == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code": http.StatusUnauthorized,
		"msg":  "无效凭据",
	})
}
