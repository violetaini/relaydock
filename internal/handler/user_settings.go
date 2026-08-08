package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type userSettingsRequest struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Nickname  string `json:"nickname"`
	AvatarURL string `json:"avatar_url"`
}

type userSettingsResponse struct {
	Profile profileResponse `json:"profile"`
}

func NewUserSettingsHandler(repo *storage.TrafficRepository, tokens *auth.TokenStore, pushers ...*LimiterConfigPusher) http.Handler {
	if repo == nil || tokens == nil {
		panic("user settings handler requires repository and token store")
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

		username := auth.UsernameFromContext(r.Context())
		if strings.TrimSpace(username) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}

		var payload userSettingsRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		currentUser, err := repo.GetUser(r.Context(), username)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusUnauthorized, errors.New("user not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		desiredUsername := strings.TrimSpace(payload.Username)
		if desiredUsername == "" {
			desiredUsername = username
		}

		if desiredUsername != username {
			if currentUser.Role == storage.RoleAdmin {
				writeError(w, http.StatusBadRequest, errors.New("管理员用户名不可修改"))
				return
			}
			if err := validateUsername(desiredUsername); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}

			if err := repo.RenameUserAndRun(r.Context(), username, desiredUsername, func() {
				tokens.UpdateUsername(username, desiredUsername)
				if limiter := GetLoginRateLimiter(); limiter != nil {
					limiter.RenameUsername(username, desiredUsername)
				}
			}); err != nil {
				if errors.Is(err, storage.ErrUserExists) || strings.Contains(strings.ToLower(err.Error()), "unique") {
					writeError(w, http.StatusConflict, errors.New("用户名已存在"))
					return
				}
				if errors.Is(err, storage.ErrReservedUsername) {
					writeError(w, http.StatusBadRequest, errors.New("该用户名为系统保留名称"))
					return
				}
				if errors.Is(err, storage.ErrUsernameRenameRequiresCredentialMigration) {
					writeError(w, http.StatusConflict, errors.New("该账号已配置远端节点凭据或出站，请先解绑相关配置再修改用户名"))
					return
				}
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if pusher != nil {
				pusher.PushToAllServersForUser(r.Context(), desiredUsername)
			}
			username = desiredUsername
		}

		update := storage.UserProfileUpdate{
			Email:     payload.Email,
			Nickname:  payload.Nickname,
			AvatarURL: payload.AvatarURL,
		}

		if err := repo.UpdateUserProfile(r.Context(), username, update); err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, errors.New("user not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		resp := profileResponse{
			Username: user.Username,
			Email:    user.Email,
			Nickname: user.Nickname,
			Avatar:   user.AvatarURL,
			Role:     user.Role,
			IsAdmin:  user.Role == storage.RoleAdmin,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(userSettingsResponse{Profile: resp})
	})
}
