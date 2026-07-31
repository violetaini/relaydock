package handler

import (
	"context"
	"encoding/json"

	"github.com/violetaini/relaydock/internal/storage"
)

// ProbeConfigUpdates builds the per-server collection policy carried over the
// existing config_update channel.  Sending explicit zeroes matters: a server
// removed from the public probe must stop collecting rather than retain an old
// enabled setting until it restarts.
func ProbeConfigUpdates(ctx context.Context, repo *storage.TrafficRepository, serverID int64) map[string]string {
	updates := map[string]string{
		"probe_collect_cpu":  "0",
		"probe_collect_mem":  "0",
		"probe_collect_disk": "0",
	}
	if repo == nil || serverID <= 0 {
		return updates
	}
	if ctx == nil {
		ctx = context.Background()
	}
	enabled, _ := repo.GetSystemSetting(ctx, probeDisguiseEnabledKey)
	if enabled != "1" {
		return updates
	}
	raw, _ := repo.GetSystemSetting(ctx, probeDisguiseServerIDsKey)
	var ids []int64
	if json.Unmarshal([]byte(raw), &ids) != nil {
		return updates
	}
	selected := false
	for _, id := range ids {
		if id == serverID {
			selected = true
			break
		}
	}
	if !selected {
		return updates
	}
	if value, _ := repo.GetSystemSetting(ctx, probeDisguiseMetricCPUKey); value != "0" {
		updates["probe_collect_cpu"] = "1"
	}
	if value, _ := repo.GetSystemSetting(ctx, probeDisguiseMetricMemKey); value != "0" {
		updates["probe_collect_mem"] = "1"
	}
	if value, _ := repo.GetSystemSetting(ctx, probeDisguiseMetricDiskKey); value != "0" {
		updates["probe_collect_disk"] = "1"
	}
	return updates
}
