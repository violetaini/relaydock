package handler

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/captcha"
	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/storage"
)

type loginRequest struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	RememberMe     bool   `json:"remember_me"`
	TurnstileToken string `json:"turnstile_token"`
}

type loginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Nickname  string    `json:"nickname"`
	Avatar    string    `json:"avatar_url"`
	Role      string    `json:"role"`
	IsAdmin   bool      `json:"is_admin"`
}

type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const maxLoginUsernameLength = 128

// GetClientIP trusts proxy headers only when the direct peer is loopback or is
// explicitly listed in ARCWAY_TRUSTED_PROXY_CIDRS. The bundled Nginx config
// overwrites X-Real-IP, preventing clients from supplying their own limiter key.
func GetClientIP(r *http.Request) string {
	remote := remoteIP(r.RemoteAddr)
	if isTrustedProxy(remote) {
		if forwarded := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); forwarded != nil {
			return forwarded.String()
		}
	}
	return remote.String()
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.Trim(strings.TrimSpace(remoteAddr), "[]"))
}

func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, raw := range strings.Split(os.Getenv("ARCWAY_TRUSTED_PROXY_CIDRS"), ",") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func NewLoginHandler(manager *auth.Manager, tokens *auth.TokenStore, repo *storage.TrafficRepository, rateLimiter *LoginRateLimiter, twoFactorStore *auth.TwoFactorPendingStore, turnstile *captcha.Turnstile) http.Handler {
	if manager == nil || tokens == nil {
		panic("login handler requires manager and token store")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var payload loginRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if strings.TrimSpace(payload.Username) == "" || payload.Password == "" {
			writeError(w, http.StatusBadRequest, errors.New("username and password are required"))
			return
		}

		username := strings.TrimSpace(payload.Username)
		if len(username) > maxLoginUsernameLength {
			writeError(w, http.StatusBadRequest, errors.New("username is too long"))
			return
		}
		clientIP := GetClientIP(r)

		if rateLimiter != nil {
			if err := rateLimiter.Reserve(clientIP, username); err != nil {
				writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts, please try again later"))
				return
			}
		}

		// Turnstile 人机验证:Enabled 内部已查 DB 看两 key 是否都填,未填则放行。
		// 失败按现有协议用 400,不混淆 401 invalid credentials 的语义。
		if turnstile != nil && !turnstile.Verify(r.Context(), payload.TurnstileToken, clientIP) {
			if rateLimiter != nil {
				rateLimiter.Release(clientIP, username)
			}
			writeError(w, http.StatusBadRequest, errors.New("captcha verification failed"))
			return
		}

		var (
			user           storage.User
			twoFactorToken string
			token          string
			expiry         time.Time
		)
		ok, err := manager.AuthenticateAndRun(r.Context(), username, payload.Password, func(authenticated storage.User) error {
			user = authenticated
			if user.TOTPEnabled && twoFactorStore != nil {
				issued, err := twoFactorStore.Issue(username, payload.RememberMe)
				if err != nil {
					return err
				}
				twoFactorToken = issued
				return nil
			}
			if repo != nil {
				if _, err := repo.GetOrCreateUserToken(r.Context(), username); err != nil {
					return err
				}
			}
			issued, expiresAt, err := createLoginSession(r.Context(), tokens, repo, user, payload.RememberMe)
			if err != nil {
				return err
			}
			token, expiry = issued, expiresAt
			return nil
		})
		if err != nil {
			if rateLimiter != nil {
				rateLimiter.Release(clientIP, username)
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if !ok {
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, username)
			}
			logger.Warn("🔐 [LOGIN_FAIL] 登录失败",
				"username", username,
				"client_ip", clientIP,
				"time", time.Now().Format("2006-01-02 15:04:05"))
			writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
			return
		}

		if twoFactorToken != "" {
			if rateLimiter != nil {
				rateLimiter.Release(clientIP, username)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requires_2fa":     true,
				"two_factor_token": twoFactorToken,
			})
			return
		}

		if rateLimiter != nil {
			rateLimiter.RecordSuccess(clientIP, username)
		}

		writeLoginSession(w, r, token, expiry, user, payload.RememberMe)
	})
}

func NewCredentialsHandler(manager *auth.Manager, tokens *auth.TokenStore, repo *storage.TrafficRepository, twoFactorStore *auth.TwoFactorPendingStore, pushers ...*LimiterConfigPusher) http.Handler {
	if manager == nil || tokens == nil || repo == nil {
		panic("credentials handler requires manager and token store")
	}
	var pusher *LimiterConfigPusher
	if len(pushers) > 0 {
		pusher = pushers[0]
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only PUT is supported"))
			return
		}

		var payload credentialsRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		trimmedUsername := strings.TrimSpace(payload.Username)

		if trimmedUsername == "" && payload.Password == "" {
			writeError(w, http.StatusBadRequest, errors.New("username or password must be provided"))
			return
		}
		if trimmedUsername != "" {
			if err := validateUsername(trimmedUsername); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}

		currentUsername := auth.UsernameFromContext(r.Context())
		_, err := manager.UpdateAndRun(r.Context(), currentUsername, trimmedUsername, payload.Password, func(updated string) {
			if updated != currentUsername {
				// Service sessions (notably the embedded Telegram bot) survive
				// credential rotation, so move their identity before revoking the
				// renamed account's interactive sessions.
				tokens.UpdateUsername(currentUsername, updated)
				if limiter := GetLoginRateLimiter(); limiter != nil {
					limiter.RenameUsername(currentUsername, updated)
				}
			}
			tokens.RevokeUser(updated)
			if twoFactorStore != nil {
				twoFactorStore.RevokeUser(currentUsername)
				twoFactorStore.RevokeUser(updated)
			}
		})
		if err != nil {
			if errors.Is(err, storage.ErrUserExists) {
				writeError(w, http.StatusConflict, err)
				return
			}
			if errors.Is(err, storage.ErrReservedUsername) {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			if errors.Is(err, storage.ErrUsernameRenameRequiresCredentialMigration) {
				writeError(w, http.StatusConflict, errors.New("该账号已配置远端节点凭据或出站，请先解绑相关配置再修改用户名；密码可单独修改"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		updatedUsername := currentUsername
		if trimmedUsername != "" {
			updatedUsername = trimmedUsername
		}
		if pusher != nil && updatedUsername != currentUsername {
			pusher.PushToAllServersForUser(r.Context(), updatedUsername)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	})
}

func NewLogoutHandler(tokens *auth.TokenStore, repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}
		token := auth.BearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}
		if repo != nil {
			if err := repo.DeleteSession(r.Context(), token); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		tokens.Revoke(token)
		w.WriteHeader(http.StatusNoContent)
	})
}

func NewWebSocketTicketHandler(tokens *auth.TokenStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}
		ticket, expiry, err := tokens.IssueWebSocketTicket(
			auth.UsernameFromContext(r.Context()),
			auth.BearerToken(r),
			30*time.Second,
		)
		if err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		respondJSON(w, http.StatusCreated, map[string]any{"ticket": ticket, "expires_at": expiry})
	})
}
