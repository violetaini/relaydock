package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/storage"
)

// NewUserNodeLimitsHandler 处理 PUT /api/admin/users/node-limits — 设置用户级 per-node 限速 / 流量 / 客户端数覆盖。
// payload:{ username, node_speed_overrides: {id: mbps}, node_traffic_overrides: {id: gb}, node_device_overrides: {id: count} }。
// 任一 map 含 > 0 的值都视为启用 limiter。0 表示显式不限速。
// 保存后 checked 推下发,Agent 确认新一轮 limiter config 后接口才返回成功。
func NewUserNodeLimitsHandler(repo *storage.TrafficRepository, pusher *LimiterConfigPusher, capabilityManager *capabilities.Manager) http.Handler {
	type req struct {
		Username             string            `json:"username"`
		NodeSpeedOverrides   map[int64]float64 `json:"node_speed_overrides"`
		NodeTrafficOverrides map[int64]float64 `json:"node_traffic_overrides"`
		NodeDeviceOverrides  map[int64]int     `json:"node_device_overrides"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var body req
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
			return
		}

		username := strings.TrimSpace(body.Username)
		if username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}
		current, err := repo.GetUser(r.Context(), username)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, err)
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		trafficProvided := body.NodeTrafficOverrides != nil
		if !trafficProvided {
			body.NodeTrafficOverrides = current.NodeTrafficLimitOverrides
		}

		// 校验:不允许负数
		for _, v := range body.NodeSpeedOverrides {
			if v < 0 {
				writeError(w, http.StatusBadRequest, errors.New("node_speed_overrides 不能为负"))
				return
			}
		}
		if !validNodeTrafficLimits(body.NodeTrafficOverrides) {
			writeError(w, http.StatusBadRequest, errors.New("node_traffic_overrides 必须是有限的非负 GB 值"))
			return
		}
		for _, v := range body.NodeDeviceOverrides {
			if v < 0 {
				writeError(w, http.StatusBadRequest, errors.New("node_device_overrides 不能为负"))
				return
			}
		}

		var pkg *storage.Package
		if current.AuthorizationMode == storage.AuthorizationModePackage && current.PackageID > 0 {
			pkg, err = repo.GetPackage(r.Context(), current.PackageID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		candidate := current
		candidate.NodeTrafficLimitOverrides = body.NodeTrafficOverrides
		effectiveTraffic := effectiveNodeTrafficLimits(&candidate, pkg)

		// 任何 per-node 限速 > 0 都视为启用 limiter(0 = 显式不限速)。
		if (hasNonZeroLimit(body.NodeSpeedOverrides) || hasNonZeroLimit(effectiveTraffic) || hasNonZeroIntLimit(body.NodeDeviceOverrides)) &&
			capabilityManager != nil && !capabilityManager.HasFeature(capabilities.FeatureLimiter) {
			http.Error(w, "当前构建未启用限速器", http.StatusForbidden)
			return
		}
		if trafficProvided {
			if pusher == nil {
				writeError(w, http.StatusServiceUnavailable, errors.New("fixed-node traffic quota refresh is unavailable"))
				return
			}
			if err := requireNodeTrafficCapabilities(r.Context(), repo, pusher, effectiveTraffic); err != nil {
				writeError(w, http.StatusUnprocessableEntity, err)
				return
			}
		}

		if err := repo.UpdateUserNodeLimitsWithTraffic(r.Context(), username, body.NodeSpeedOverrides, body.NodeTrafficOverrides, body.NodeDeviceOverrides); err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeError(w, http.StatusNotFound, err)
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if pusher != nil {
			if err := pusher.PushToAllServersForUserChecked(r.Context(), username); err != nil {
				writeError(w, http.StatusBadGateway, fmt.Errorf("user node limits saved but Agent refresh failed: %w", err))
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"message": "User node limits updated",
		})
	})
}
