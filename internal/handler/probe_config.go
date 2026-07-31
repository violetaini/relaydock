package handler

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

// probeDisguiseServerSelection distinguishes an unset selection from an
// explicitly saved empty array.  The former means every remote server; the
// latter intentionally hides every server from the public page.  A malformed
// stored value is treated as an explicit empty selection so corrupted settings
// cannot accidentally make every server public.
func probeDisguiseServerSelection(ctx context.Context, repo *storage.TrafficRepository) (map[int64]struct{}, bool) {
	selected := make(map[int64]struct{})
	if repo == nil {
		return selected, true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := repo.GetSystemSetting(ctx, probeDisguiseServerIDsKey)
	if err != nil || strings.TrimSpace(raw) == "" {
		return selected, false
	}
	var ids []int64
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return selected, true
	}
	for _, id := range ids {
		if id > 0 {
			selected[id] = struct{}{}
		}
	}
	return selected, true
}

// ProbeConfigUpdates builds the host-health collection policy carried over the
// existing config_update channel.  The Agent protocol keeps its historical
// probe_collect_* names, but these readings now power authenticated service
// management as well as the optional public disguise.  Public visibility is
// filtered when serializing the public DTO; it must not turn off the data that
// administrators need on every managed server.
func ProbeConfigUpdates(ctx context.Context, repo *storage.TrafficRepository, serverID int64) map[string]string {
	updates := map[string]string{
		"probe_collect_cpu":  "0",
		"probe_collect_mem":  "0",
		"probe_collect_disk": "0",
	}
	if repo == nil || serverID <= 0 {
		return updates
	}
	updates["probe_collect_cpu"] = "1"
	updates["probe_collect_mem"] = "1"
	updates["probe_collect_disk"] = "1"
	return updates
}
