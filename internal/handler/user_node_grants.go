package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type directNodeGrantResponse struct {
	ID            int64      `json:"id"`
	Username      string     `json:"username"`
	NodeID        int64      `json:"node_id"`
	NodeName      string     `json:"node_name"`
	Protocol      string     `json:"protocol"`
	ServerID      int64      `json:"server_id"`
	ServerName    string     `json:"server_name"`
	InboundTag    string     `json:"inbound_tag"`
	SourceType    string     `json:"source_type"`
	DesiredState  string     `json:"desired_state"`
	ObservedState string     `json:"observed_state"`
	State         string     `json:"state"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	Version       int64      `json:"version"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (h *ManagedNodesHandler) directNodeGrantResponse(ctx context.Context, item storage.UserNodeGrantWithSource) directNodeGrantResponse {
	response := directNodeGrantResponse{
		ID: item.Grant.ID, Username: item.Grant.Username, NodeID: item.Grant.NodeID,
		ServerID: item.Source.ServerID, InboundTag: item.Source.InboundTag,
		SourceType: item.Grant.SourceType, DesiredState: item.Source.DesiredState,
		ObservedState: item.Source.ObservedState, State: managedSelectionState(&item.Source),
		ExpiresAt: item.Source.ExpiresAt, LastError: item.Source.LastError,
		Version: item.Grant.Version, CreatedBy: item.Grant.CreatedBy,
		CreatedAt: item.Grant.CreatedAt, UpdatedAt: item.Grant.UpdatedAt,
	}
	if node, err := h.repo.GetNodeByID(ctx, item.Grant.NodeID); err == nil {
		response.NodeName = node.NodeName
		response.Protocol = node.Protocol
	}
	if server, err := h.repo.GetRemoteServer(ctx, item.Source.ServerID); err == nil {
		response.ServerName = server.Name
	}
	return response
}

func writeDirectNodeGrantError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrUserNodeGrantNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "error": err.Error()})
	case errors.Is(err, storage.ErrUserNodeGrantConflict):
		writeJSON(w, http.StatusConflict, map[string]any{"success": false, "error": err.Error()})
	default:
		writeManagedError(w, err)
	}
}

// HandleAdminUserNodeGrants manages fixed, manually-assigned nodes. It never
// serializes user_inbound_configs or any node owner credential.
func (h *ManagedNodesHandler) HandleAdminUserNodeGrants(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		writeDirectNodeGrantError(w, storage.ErrManagedInvalidArgument)
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := h.repo.ListUserNodeGrants(r.Context(), username)
		if err != nil {
			writeDirectNodeGrantError(w, err)
			return
		}
		responses := make([]directNodeGrantResponse, 0, len(items))
		for _, item := range items {
			responses = append(responses, h.directNodeGrantResponse(r.Context(), item))
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": responses})
	case http.MethodPost:
		var request struct {
			NodeID    int64      `json:"node_id"`
			ExpiresAt *time.Time `json:"expires_at"`
		}
		if err := decodeManagedJSON(r, &request); err != nil {
			writeDirectNodeGrantError(w, err)
			return
		}
		var previous *storage.UserNodeGrantWithSource
		if existing, existingErr := h.repo.ListUserNodeGrants(r.Context(), username); existingErr == nil {
			for i := range existing {
				if existing[i].Grant.NodeID == request.NodeID {
					candidate := existing[i]
					previous = &candidate
					break
				}
			}
		}
		item, created, err := h.repo.UpsertManualUserNodeGrant(r.Context(), username,
			request.NodeID, request.ExpiresAt, managedActor(r))
		if err != nil {
			writeDirectNodeGrantError(w, err)
			return
		}
		provisionErr := h.reconcileSource(r.Context(), item.Source)
		if provisionErr != nil && (previous == nil || previous.Source.ObservedState != storage.ManagedObservedActive) {
			if _, rollbackErr := h.repo.SetUserNodeGrantDesiredState(r.Context(), item.Grant.ID,
				username, storage.ManagedDesiredInactive, managedActor(r)); rollbackErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"success": false, "error": "remote provisioning failed and local authorization rollback failed",
				})
				return
			}
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"success": false, "error": "remote provisioning failed; authorization remains inactive",
			})
			return
		}
		if current, getErr := h.repo.GetUserNodeGrant(r.Context(), item.Grant.ID); getErr == nil {
			item = current
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		if provisionErr != nil {
			status = http.StatusAccepted
		}
		writeJSON(w, status, map[string]any{
			"success": true, "pending": provisionErr != nil,
			"item": h.directNodeGrantResponse(r.Context(), *item),
		})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ManagedNodesHandler) getDirectNodeGrantForRequest(r *http.Request) (*storage.UserNodeGrantWithSource, error) {
	id, err := managedRequestID(r, "id")
	if err != nil {
		return nil, err
	}
	item, err := h.repo.GetUserNodeGrant(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if item.Grant.Username != strings.TrimSpace(r.PathValue("username")) ||
		item.Grant.SourceType != storage.GrantSourceManual {
		return nil, storage.ErrUserNodeGrantNotFound
	}
	return item, nil
}

func (h *ManagedNodesHandler) HandleAdminUserNodeGrant(w http.ResponseWriter, r *http.Request) {
	item, err := h.getDirectNodeGrantForRequest(r)
	if err != nil {
		writeDirectNodeGrantError(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true, "item": h.directNodeGrantResponse(r.Context(), *item),
		})
	case http.MethodDelete:
		updated, err := h.repo.SetUserNodeGrantDesiredState(r.Context(), item.Grant.ID,
			item.Grant.Username, storage.ManagedDesiredInactive, managedActor(r))
		if err != nil {
			writeDirectNodeGrantError(w, err)
			return
		}
		cleanupErr := h.reconcileSource(r.Context(), updated.Source)
		if current, getErr := h.repo.GetUserNodeGrant(r.Context(), item.Grant.ID); getErr == nil {
			updated = current
		}
		status := http.StatusOK
		if cleanupErr != nil {
			status = http.StatusAccepted
		}
		writeJSON(w, status, map[string]any{
			"success": true, "pending": cleanupErr != nil,
			"item": h.directNodeGrantResponse(r.Context(), *updated),
		})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ManagedNodesHandler) HandleAdminUserNodeGrantRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	item, err := h.getDirectNodeGrantForRequest(r)
	if err != nil {
		writeDirectNodeGrantError(w, err)
		return
	}
	reconcileErr := h.reconcileSource(r.Context(), item.Source)
	if current, getErr := h.repo.GetUserNodeGrant(r.Context(), item.Grant.ID); getErr == nil {
		item = current
	}
	status := http.StatusOK
	if reconcileErr != nil {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{
		"success": true, "pending": reconcileErr != nil,
		"item": h.directNodeGrantResponse(r.Context(), *item),
	})
}
