package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

const userTrafficLimitBytesPerGB = 1024 * 1024 * 1024

// NewUserTrafficLimitHandler remains as a compatibility endpoint. Aggregate
// package traffic is retired; null only clears a legacy stored override.
func NewUserTrafficLimitHandler(repo *storage.TrafficRepository) http.Handler {
	type request struct {
		Username               string   `json:"username"`
		TrafficLimitOverrideGB *float64 `json:"traffic_limit_override_gb"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only PUT or POST is supported"))
			return
		}

		var payload request
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
			return
		}
		username := strings.TrimSpace(payload.Username)
		if username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}

		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, err)
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if user.Role == storage.RoleAdmin {
			writeError(w, http.StatusBadRequest, errors.New("管理员账户不支持用户流量覆写"))
			return
		}
		if payload.TrafficLimitOverrideGB != nil {
			writeError(w, http.StatusBadRequest, errors.New("套餐总流量已停用，请配置节点、服务器或转发明细额度"))
			return
		}

		if err := repo.UpdateUserTrafficLimitOverride(r.Context(), username, nil); err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, err)
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	})
}
