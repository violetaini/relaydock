package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// HandleManagedRealityCompatibility hot-replaces only panel-owned REALITY
// inbounds that have no usable minClientVer. It deliberately does not restart
// Xray: the Agent applies the one inbound through its runtime API and persists
// it atomically.
func (h *RemoteManageHandler) HandleManagedRealityCompatibility(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if h == nil || h.repo == nil {
		remoteWriteError(w, http.StatusServiceUnavailable, "remote server storage unavailable")
		return
	}

	serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "valid server_id required")
		return
	}

	ctx, release, err := h.repo.AcquireRemoteServerExclusiveMutationLease(r.Context(), serverID)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}
	defer release()

	result := managedRealityCompatibilityResult{}
	if _, err := h.repo.GetRemoteServer(ctx, serverID); err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		remoteWriteForwardError(w, fmt.Errorf("get Agent inbounds: %w", err))
		return
	}
	var inventory managedRealityCompatibilityInventory
	if err := json.Unmarshal(raw, &inventory); err != nil {
		remoteWriteError(w, http.StatusBadGateway, "parse Agent inbounds: "+err.Error())
		return
	}
	if !inventory.Success {
		remoteWriteError(w, http.StatusBadGateway, "Agent did not acknowledge inbound inventory")
		return
	}

	for _, inbound := range inventory.Inbounds {
		if !isRealityInbound(inbound) {
			continue
		}
		mutationID, owned, ownershipErr := h.managedRealityInboundOwner(ctx, serverID, inbound, inventory)
		if ownershipErr != nil {
			remoteWriteError(w, http.StatusInternalServerError, ownershipErr.Error())
			return
		}
		if !owned || !applyManagedRealityCompatibilityToInbound(inbound) {
			result.Skipped++
			continue
		}
		if err := h.replaceInboundForSync(ctx, serverID, inbound, mutationID); err != nil {
			remoteWriteForwardError(w, fmt.Errorf("hot-replace Reality inbound %q: %w", strings.TrimSpace(wireGuardStringValue(inbound["tag"])), err))
			return
		}
		result.Updated++
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"updated": result.Updated,
		"skipped": result.Skipped,
	})
}

type managedRealityCompatibilityResult struct {
	Updated int
	Skipped int
}

type managedRealityCompatibilityInventory struct {
	Success            bool                     `json:"success"`
	Inbounds           []map[string]interface{} `json:"inbounds"`
	MutationFenceKnown bool                     `json:"mutation_fence_known"`
	MutationOwners     map[string]string        `json:"mutation_owners"`
}

func isRealityInbound(inbound map[string]interface{}) bool {
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})
	security, _ := streamSettings["security"].(string)
	return strings.EqualFold(strings.TrimSpace(security), "reality")
}

// managedRealityInboundOwner requires matching ownership evidence from the
// Agent and the control-plane database. A user-created inbound must therefore
// never be replaced merely because it happens to use REALITY.
func (h *RemoteManageHandler) managedRealityInboundOwner(ctx context.Context, serverID int64, inbound map[string]interface{}, inventory managedRealityCompatibilityInventory) (string, bool, error) {
	if !inventory.MutationFenceKnown {
		return "", false, nil
	}
	tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
	if tag == "" {
		return "", false, nil
	}
	if known, _ := inbound["_mutation_fence_known"].(bool); !known {
		return "", false, nil
	}
	agentOwner := strings.TrimSpace(wireGuardStringValue(inbound["_mutation_id"]))
	if agentOwner == "" {
		agentOwner = strings.TrimSpace(inventory.MutationOwners[tag])
	}
	if agentOwner == "" {
		return "", false, nil
	}
	storedOwner, err := h.repo.GetRemoteInboundOwnership(ctx, serverID, tag)
	if err != nil {
		return "", false, fmt.Errorf("read inbound ownership for %q: %w", tag, err)
	}
	if storedOwner == "" || storedOwner != agentOwner {
		return "", false, nil
	}
	return agentOwner, true, nil
}
