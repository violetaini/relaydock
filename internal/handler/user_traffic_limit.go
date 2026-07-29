package handler

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

const userTrafficLimitBytesPerGB = 1024 * 1024 * 1024

// NewUserTrafficLimitHandler updates the optional total traffic cap for a user's
// current package. JSON null inherits the package, zero explicitly means
// unlimited, and a positive number overrides the package cap in GB.
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
		if payload.TrafficLimitOverrideGB != nil && user.PackageID <= 0 {
			writeError(w, http.StatusConflict, errors.New("请先为用户分配套餐，再设置总流量覆写"))
			return
		}

		var limitBytes *int64
		if payload.TrafficLimitOverrideGB != nil {
			gb := *payload.TrafficLimitOverrideGB
			if math.IsNaN(gb) || math.IsInf(gb, 0) || gb < 0 || gb > float64(math.MaxInt64)/userTrafficLimitBytesPerGB {
				writeError(w, http.StatusBadRequest, errors.New("traffic_limit_override_gb 必须是有效的非负数"))
				return
			}
			bytes := int64(math.Round(gb * userTrafficLimitBytesPerGB))
			limitBytes = &bytes
		}

		if err := repo.UpdateUserTrafficLimitOverride(r.Context(), username, limitBytes); err != nil {
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
