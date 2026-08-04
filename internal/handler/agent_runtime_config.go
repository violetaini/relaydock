package handler

import (
	"context"
	"strconv"

	"github.com/violetaini/relaydock/internal/storage"
)

const xrayAuthorizedConfigKey = "xray_authorized"

// xrayAuthorizedForServer is the single control-plane policy for the Agent's
// Xray runtime gate. Local Arcway installations have no commercial license or
// server quota, so every registered server is authorized. Keeping this in one
// place means a future policy change has one explicit outbound contract.
func xrayAuthorizedForServer(_ context.Context, _ *storage.TrafficRepository, _ int64) bool {
	return true
}

// agentRuntimeConfigUpdates is sent on both persistent WebSocket connections
// and HTTP traffic replies. xray_authorized is capability-gated: old Agents
// interpreted it as permission to start/stop the entire Xray process, which
// could revive a core an administrator deliberately stopped. Safe Agents
// explicitly advertise XrayAuthorizationV2 and receive the policy key that
// clears any stale false value from the former quota mechanism.
func agentRuntimeConfigUpdates(ctx context.Context, repo *storage.TrafficRepository, serverID int64, capabilities AgentCapabilities) map[string]string {
	if ctx == nil {
		ctx = context.Background()
	}

	updates := ProbeConfigUpdates(ctx, repo, serverID)
	if capabilities.XrayAuthorizationV2 {
		updates[xrayAuthorizedConfigKey] = strconv.FormatBool(xrayAuthorizedForServer(ctx, repo, serverID))
	}
	if repo != nil {
		if interval, _ := repo.GetSystemSetting(ctx, "dashboard_refresh_interval_ms"); interval != "" {
			updates["traffic_report_interval_ms"] = interval
		}
	}
	return updates
}
