package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/storage"
)

const maxTwoFactorLoginBodyBytes int64 = 16 << 10

func NewTwoFactorLoginHandler(manager *auth.Manager, tokens *auth.TokenStore, repo *storage.TrafficRepository, tfStore *auth.TwoFactorPendingStore, rateLimiter *LoginRateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxTwoFactorLoginBodyBytes)
		var payload struct {
			TwoFactorToken string `json:"two_factor_token"`
			Code           string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		payload.TwoFactorToken = strings.TrimSpace(payload.TwoFactorToken)
		payload.Code = strings.TrimSpace(payload.Code)
		if len(payload.TwoFactorToken) > 256 || len(payload.Code) > 32 {
			writeError(w, http.StatusBadRequest, errors.New("invalid 2FA request"))
			return
		}
		clientIP := GetClientIP(r)
		if rateLimiter != nil {
			if err := rateLimiter.Reserve(clientIP, ""); err != nil {
				writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts, please try again later"))
				return
			}
		}

		username, rememberMe, ok := tfStore.Acquire(payload.TwoFactorToken)
		if !ok {
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, "")
			}
			writeError(w, http.StatusUnauthorized, errors.New("invalid or expired 2FA token"))
			return
		}
		if rateLimiter != nil {
			if err := rateLimiter.AttachAccount(username); err != nil {
				rateLimiter.Release(clientIP, "")
				tfStore.Finish(payload.TwoFactorToken, false)
				writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts, please try again later"))
				return
			}
		}

		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			tfStore.Finish(payload.TwoFactorToken, false)
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, username)
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if !auth.ValidateTOTPCode(user.TOTPSecret, payload.Code) {
			tfStore.Finish(payload.TwoFactorToken, false)
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, username)
			}
			writeError(w, http.StatusUnauthorized, errors.New("invalid 2FA code"))
			return
		}

		var token string
		var expiry time.Time
		err = manager.RunForActiveUser(r.Context(), username, func(active storage.User) error {
			if !tfStore.IsAcquired(payload.TwoFactorToken) {
				return errors.New("2FA challenge was revoked")
			}
			token, expiry, err = createLoginSession(r.Context(), tokens, repo, active, rememberMe)
			if err != nil {
				return err
			}
			if !tfStore.Finish(payload.TwoFactorToken, true) {
				tokens.Revoke(token)
				if repo != nil {
					_ = repo.DeleteSession(r.Context(), token)
				}
				return errors.New("2FA challenge was revoked")
			}
			return nil
		})
		if err != nil {
			tfStore.Finish(payload.TwoFactorToken, false)
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, username)
			}
			writeError(w, http.StatusUnauthorized, errors.New("invalid or expired 2FA token"))
			return
		}
		if rateLimiter != nil {
			rateLimiter.RecordSuccess(clientIP, username)
		}
		writeLoginSession(w, r, token, expiry, user, rememberMe)
	})
}

func NewRecoveryLoginHandler(manager *auth.Manager, tokens *auth.TokenStore, repo *storage.TrafficRepository, tfStore *auth.TwoFactorPendingStore, rateLimiter *LoginRateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxTwoFactorLoginBodyBytes)
		var payload struct {
			TwoFactorToken string `json:"two_factor_token"`
			RecoveryCode   string `json:"recovery_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		payload.TwoFactorToken = strings.TrimSpace(payload.TwoFactorToken)
		payload.RecoveryCode = strings.TrimSpace(payload.RecoveryCode)
		if len(payload.TwoFactorToken) > 256 || len(payload.RecoveryCode) > 128 {
			writeError(w, http.StatusBadRequest, errors.New("invalid recovery request"))
			return
		}
		clientIP := GetClientIP(r)
		if rateLimiter != nil {
			if err := rateLimiter.Reserve(clientIP, ""); err != nil {
				writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts, please try again later"))
				return
			}
		}

		username, rememberMe, ok := tfStore.Acquire(payload.TwoFactorToken)
		if !ok {
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, "")
			}
			writeError(w, http.StatusUnauthorized, errors.New("invalid or expired 2FA token"))
			return
		}
		if rateLimiter != nil {
			if err := rateLimiter.AttachAccount(username); err != nil {
				rateLimiter.Release(clientIP, "")
				tfStore.Finish(payload.TwoFactorToken, false)
				writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts, please try again later"))
				return
			}
		}

		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			tfStore.Finish(payload.TwoFactorToken, false)
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, username)
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		hashedCodes, err := parseRecoveryCodes(user.RecoveryCodes)
		if err != nil {
			tfStore.Finish(payload.TwoFactorToken, false)
			if rateLimiter != nil {
				rateLimiter.Release(clientIP, username)
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		valid, _ := auth.ValidateRecoveryCode(payload.RecoveryCode, hashedCodes)
		if !valid {
			tfStore.Finish(payload.TwoFactorToken, false)
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, username)
			}
			writeError(w, http.StatusUnauthorized, errors.New("invalid recovery code"))
			return
		}

		var token string
		var expiry time.Time
		err = manager.RunForActiveUser(r.Context(), username, func(active storage.User) error {
			if !tfStore.IsAcquired(payload.TwoFactorToken) {
				return errors.New("2FA challenge was revoked")
			}
			if err := repo.DisableUserTOTP(r.Context(), username); err != nil {
				return err
			}
			token, expiry, err = createLoginSession(r.Context(), tokens, repo, active, rememberMe)
			if err != nil {
				return err
			}
			if !tfStore.Finish(payload.TwoFactorToken, true) {
				tokens.Revoke(token)
				if repo != nil {
					_ = repo.DeleteSession(r.Context(), token)
				}
				return errors.New("2FA challenge was revoked")
			}
			return nil
		})
		if err != nil {
			tfStore.Finish(payload.TwoFactorToken, false)
			if rateLimiter != nil {
				rateLimiter.RecordFailure(clientIP, username)
			}
			writeError(w, http.StatusUnauthorized, errors.New("invalid or expired 2FA token"))
			return
		}
		if rateLimiter != nil {
			rateLimiter.RecordSuccess(clientIP, username)
		}
		writeLoginSession(w, r, token, expiry, user, rememberMe)
	})
}

func NewTwoFactorStatusHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only GET is supported"))
			return
		}

		username := auth.UsernameFromContext(r.Context())
		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{
			"enabled": user.TOTPEnabled,
		})
	})
}

func NewTwoFactorSetupHandler(manager *auth.Manager, repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		username := auth.UsernameFromContext(r.Context())

		var payload struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if err := manager.ValidatePassword(r.Context(), username, payload.Password); err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("invalid password"))
			return
		}

		key, err := auth.GenerateTOTPKey(username, "RelayDock")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if err := repo.SetUserTOTPSecret(r.Context(), username, key.Secret()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"secret": key.Secret(),
			"url":    key.URL(),
		})
	})
}

func NewTwoFactorVerifySetupHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		username := auth.UsernameFromContext(r.Context())
		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if user.TOTPSecret == "" {
			writeError(w, http.StatusBadRequest, errors.New("2FA setup not initiated"))
			return
		}

		var payload struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if !auth.ValidateTOTPCode(user.TOTPSecret, strings.TrimSpace(payload.Code)) {
			writeError(w, http.StatusUnauthorized, errors.New("invalid 2FA code"))
			return
		}

		plain, hashed, err := auth.GenerateRecoveryCodes(8)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		hashedJSON, _ := json.Marshal(hashed)
		if err := repo.EnableUserTOTP(r.Context(), username, string(hashedJSON)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{
			"recovery_codes": plain,
		})
	})
}

func NewTwoFactorDisableHandler(manager *auth.Manager, repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		username := auth.UsernameFromContext(r.Context())
		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if !user.TOTPEnabled {
			writeError(w, http.StatusBadRequest, errors.New("2FA is not enabled"))
			return
		}

		var payload struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if !auth.ValidateTOTPCode(user.TOTPSecret, strings.TrimSpace(payload.Code)) {
			writeError(w, http.StatusUnauthorized, errors.New("invalid 2FA code"))
			return
		}

		if err := repo.DisableUserTOTP(r.Context(), username); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "disabled"})
	})
}

func createLoginSession(ctx context.Context, tokens *auth.TokenStore, repo *storage.TrafficRepository, user storage.User, rememberMe bool) (string, time.Time, error) {
	var ttl time.Duration
	if rememberMe {
		ttl = 30 * 24 * time.Hour
	} else {
		ttl = 24 * time.Hour
	}

	token, expiry, err := tokens.IssueWithTTL(user.Username, ttl)
	if err != nil {
		return "", time.Time{}, err
	}

	if repo != nil {
		if err := repo.CreateSession(ctx, token, user.Username, expiry); err != nil {
			tokens.Revoke(token)
			return "", time.Time{}, err
		}
	}
	return token, expiry, nil
}

func writeLoginSession(w http.ResponseWriter, r *http.Request, token string, expiry time.Time, user storage.User, rememberMe bool) {
	clientIP := GetClientIP(r)
	logger.Info("[认证] 登录成功",
		"username", user.Username,
		"client_ip", clientIP,
		"remember_me", rememberMe,
		"expires_at", expiry.Format("2006-01-02 15:04:05"))

	SendLoginNotification(r.Context(), user.Username, clientIP)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(loginResponse{
		Token:     token,
		ExpiresAt: expiry,
		Username:  user.Username,
		Email:     user.Email,
		Nickname:  user.Nickname,
		Avatar:    user.AvatarURL,
		Role:      user.Role,
		IsAdmin:   user.Role == storage.RoleAdmin,
	})
}

func parseRecoveryCodes(raw string) ([]string, error) {
	var codes []string
	if err := json.Unmarshal([]byte(raw), &codes); err != nil {
		return nil, fmt.Errorf("parse recovery codes: %w", err)
	}
	return codes, nil
}
