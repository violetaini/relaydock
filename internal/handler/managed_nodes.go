package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

const (
	managedReconcileInterval     = 15 * time.Second
	managedReconcileStartupDelay = 5 * time.Second
)

var ErrManagedAgentIncompatible = errors.New("target agent is not ready for managed nodes")

type ManagedNodesHandler struct {
	repo            *storage.TrafficRepository
	remoteManage    *RemoteManageHandler
	limiter         *LimiterConfigPusher
	guardHTTPClient *http.Client
	reconcileMu     sync.Mutex
	reconcileWG     sync.WaitGroup
}

func NewManagedNodesHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, limiter *LimiterConfigPusher) *ManagedNodesHandler {
	return &ManagedNodesHandler{
		repo: repo, remoteManage: remoteManage, limiter: limiter,
		guardHTTPClient: &http.Client{Timeout: 4 * time.Second},
	}
}

type managedOfferResponse struct {
	storage.SelfServiceNodeOffer
	NodeName        string `json:"node_name"`
	Protocol        string `json:"protocol"`
	ProtocolProfile string `json:"protocol_profile"`
	ServerName      string `json:"server_name"`
	ServerStatus    string `json:"server_status"`
	AgentReady      bool   `json:"agent_ready"`
	AgentError      string `json:"agent_error,omitempty"`
}

type managedGrantResponse struct {
	storage.UserServerGrant
	ServerName        string `json:"server_name"`
	ServerStatus      string `json:"server_status"`
	State             string `json:"state"`
	OfferCount        int    `json:"offer_count"`
	ActiveNodeCount   int    `json:"active_node_count"`
	UsedUplinkBytes   int64  `json:"used_uplink_bytes"`
	UsedDownlinkBytes int64  `json:"used_downlink_bytes"`
	BilledBytes       int64  `json:"billed_bytes"`
	LastError         string `json:"last_error,omitempty"`
}

type managedSelectionResponse struct {
	ID                       int64    `json:"id"`
	GrantID                  int64    `json:"grant_id"`
	OfferID                  int64    `json:"offer_id"`
	NodeID                   int64    `json:"node_id"`
	NodeName                 string   `json:"node_name"`
	ServerID                 int64    `json:"server_id"`
	ServerName               string   `json:"server_name"`
	Protocol                 string   `json:"protocol"`
	DesiredEnabled           bool     `json:"desired_enabled"`
	State                    string   `json:"state"`
	EffectiveSpeedLimitMbps  float64  `json:"effective_speed_limit_mbps"`
	EffectiveConnectionLimit int      `json:"effective_connection_limit"`
	EffectiveBillingMode     string   `json:"effective_billing_mode"`
	SpeedLimitOverrideMbps   *float64 `json:"speed_limit_override_mbps,omitempty"`
	ConnectionLimitOverride  *int     `json:"connection_limit_override,omitempty"`
	BillingModeOverride      *string  `json:"billing_mode_override,omitempty"`
	LastError                string   `json:"last_error,omitempty"`
}

type managedCatalogResponse struct {
	OfferID           int64      `json:"offer_id"`
	NodeID            int64      `json:"node_id"`
	NodeName          string     `json:"node_name"`
	ServerID          int64      `json:"server_id"`
	ServerName        string     `json:"server_name"`
	ServerStatus      string     `json:"server_status"`
	Protocol          string     `json:"protocol"`
	ProtocolProfile   string     `json:"protocol_profile"`
	GrantID           int64      `json:"grant_id"`
	GrantState        string     `json:"grant_state"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	CanCreate         bool       `json:"can_create"`
	DisabledReason    string     `json:"disabled_reason,omitempty"`
	Selected          bool       `json:"selected"`
	SelectionID       int64      `json:"selection_id,omitempty"`
	SpeedLimitMbps    float64    `json:"speed_limit_mbps"`
	ConnectionLimit   int        `json:"connection_limit"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes"`
	BillingMode       string     `json:"billing_mode"`
}

func managedGrantState(grant storage.UserServerGrant, userActive bool, billedBytes int64, now time.Time) string {
	return grant.StateAt(now, userActive, billedBytes)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func laterOptionalExpiry(hasLeft bool, left *time.Time, hasRight bool, right *time.Time) (bool, *time.Time) {
	if !hasLeft {
		return hasRight, right
	}
	if !hasRight {
		return true, left
	}
	if left == nil || right == nil {
		return true, nil
	}
	if right.After(*left) {
		value := right.UTC()
		return true, &value
	}
	value := left.UTC()
	return true, &value
}

// effectiveInboundExpiry resolves the credential deadline across every active
// authorization source. A nil deadline means at least one source is perpetual.
func (h *ManagedNodesHandler) effectiveInboundExpiry(ctx context.Context, source storage.UserInboundAccessSource, now time.Time) (bool, *time.Time, error) {
	hasManaged, managedExpiry, err := h.repo.HasEffectiveUserInboundAccess(ctx, source.Username, source.ServerID, source.InboundTag, 0, now)
	if err != nil {
		return false, nil, err
	}
	hasPackage, packageExpiry, err := hasLegacyPackageInboundAccess(ctx, h.repo, source.Username, source.ServerID, source.InboundTag, now)
	if err != nil {
		return false, nil, err
	}
	hasAccess, expiry := laterOptionalExpiry(hasManaged, managedExpiry, hasPackage, packageExpiry)
	return hasAccess, expiry, nil
}

func managedGrantSuspendReason(state string) string {
	switch state {
	case storage.ManagedGrantExpired:
		return storage.ManagedSuspendExpired
	case storage.ManagedGrantOverLimit:
		return storage.ManagedSuspendQuotaExceeded
	case storage.ManagedGrantUserDisabled:
		return storage.ManagedSuspendUserDisabled
	case storage.ManagedGrantSuspended, storage.ManagedGrantScheduled:
		return storage.ManagedSuspendAdminDisabled
	default:
		return storage.ManagedSuspendNone
	}
}

func managedSelectionState(source *storage.UserInboundAccessSource) string {
	if source == nil {
		return "error"
	}
	if source.LastError != "" && source.AppliedGeneration != source.Generation {
		return "error"
	}
	switch source.DesiredState {
	case storage.ManagedDesiredActive:
		if source.ObservedState == storage.ManagedObservedActive && source.AppliedGeneration == source.Generation {
			return "active"
		}
		return "provisioning"
	case storage.ManagedDesiredInactive, storage.ManagedDesiredDeleted:
		if source.ObservedState == storage.ManagedObservedInactive && source.AppliedGeneration == source.Generation {
			return "inactive"
		}
		return "suspending"
	default:
		return "error"
	}
}

func managedRequestID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue(name)), 10, 64)
	if err != nil || id <= 0 {
		return 0, storage.ErrManagedInvalidArgument
	}
	return id, nil
}

func managedActor(r *http.Request) string {
	actor := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
	if actor == "" {
		return "system"
	}
	return actor
}

func writeManagedError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "managed node operation failed"
	switch {
	case errors.Is(err, storage.ErrManagedInvalidArgument):
		status, message = http.StatusBadRequest, err.Error()
	case errors.Is(err, storage.ErrSelfServiceNodeOfferNotFound),
		errors.Is(err, storage.ErrUserServerGrantNotFound),
		errors.Is(err, storage.ErrUserNodeSelectionNotFound),
		errors.Is(err, storage.ErrManagedAccessSourceNotFound),
		errors.Is(err, storage.ErrUserNotFound),
		errors.Is(err, storage.ErrRemoteServerNotFound):
		status, message = http.StatusNotFound, err.Error()
	case errors.Is(err, storage.ErrSelfServiceNodeOfferExists),
		errors.Is(err, storage.ErrUserServerGrantExists),
		errors.Is(err, storage.ErrManagedVersionConflict),
		errors.Is(err, storage.ErrManagedGenerationConflict),
		errors.Is(err, storage.ErrManagedAccessConflict),
		errors.Is(err, storage.ErrManagedBillingModeConflict),
		errors.Is(err, storage.ErrManagedResourceInUse):
		status, message = http.StatusConflict, err.Error()
	case errors.Is(err, storage.ErrManagedGrantInactive),
		errors.Is(err, storage.ErrManagedProtocolNotAllowed),
		errors.Is(err, storage.ErrManagedActiveNodeLimit),
		errors.Is(err, storage.ErrManagedTrafficLimit),
		errors.Is(err, storage.ErrManagedServerMismatch):
		status, message = http.StatusForbidden, err.Error()
	case errors.Is(err, ErrManagedAgentIncompatible):
		status, message = http.StatusUnprocessableEntity, err.Error()
	}
	writeJSON(w, status, map[string]interface{}{"success": false, "error": message})
}

func (h *ManagedNodesHandler) findServerForNode(ctx context.Context, node storage.Node) (*storage.RemoteServer, error) {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range servers {
		if servers[i].Name == node.OriginalServer {
			return &servers[i], nil
		}
	}
	return nil, storage.ErrManagedServerMismatch
}

func validateSelfServiceNodeProtocol(node storage.Node) error {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(node.InboundTag)), "anydoor-") {
		return fmt.Errorf("%w: Tunnel 任意门节点不能发布到用户自助目录", storage.ErrManagedInvalidArgument)
	}
	if storage.SelfServiceNodeProtocolEligible(node.Protocol, node.ClashConfig) {
		return nil
	}
	if canonicalManagedProtocol(node.Protocol) == "shadowsocks" {
		return fmt.Errorf("%w: Shadowsocks 2022 自助发布仅支持 2022-blake3-aes-128-gcm 或 2022-blake3-aes-256-gcm", storage.ErrManagedInvalidArgument)
	}
	return fmt.Errorf("%w: 协议不支持独立的用户凭据，不能发布到用户自助目录", storage.ErrManagedInvalidArgument)
}

type managedSelectionOfferPolicy struct {
	available  bool
	mustRevoke bool
}

func (h *ManagedNodesHandler) selectionOfferPolicy(ctx context.Context, grant storage.UserServerGrant, selection storage.UserNodeSelection) managedSelectionOfferPolicy {
	offer, err := h.repo.GetSelfServiceNodeOffer(ctx, selection.OfferID)
	if err != nil {
		return managedSelectionOfferPolicy{}
	}
	node, err := h.repo.GetNodeByID(ctx, offer.NodeID)
	if err != nil {
		return managedSelectionOfferPolicy{}
	}
	protocolAllowed := grant.AllowsNodeProtocol(node.Protocol, node.ClashConfig) && storage.SelfServiceNodeOfferProtocolEligible(*offer, node)
	policy := managedSelectionOfferPolicy{mustRevoke: !protocolAllowed}
	credentialSafe := true
	if selection.CredentialConfigID == nil {
		if selection.AccessSourceID == nil {
			credentialSafe = false
		} else {
			source, sourceErr := h.repo.GetUserInboundAccessSource(ctx, *selection.AccessSourceID)
			if sourceErr != nil {
				credentialSafe = false
			} else if source.AppliedGeneration != 0 || source.ObservedState == storage.ManagedObservedActive {
				credentialSafe = false
				policy.mustRevoke = true
			}
		}
	} else {
		credential, credentialErr := h.repo.GetUserInboundConfig(ctx, grant.Username, offer.ServerID, offer.InboundTag)
		switch {
		case errors.Is(credentialErr, sql.ErrNoRows):
			credentialSafe = false
			policy.mustRevoke = true
		case credentialErr != nil:
			credentialSafe = false
		case credential.ID != *selection.CredentialConfigID ||
			!storage.SelfServiceCredentialProtocolMatches(credential.Protocol, node.Protocol):
			credentialSafe = false
			policy.mustRevoke = true
		}
	}
	server, err := h.repo.GetRemoteServer(ctx, offer.ServerID)
	if err != nil {
		return policy
	}
	policy.available = !policy.mustRevoke && credentialSafe && offer.ServerID == grant.ServerID &&
		storage.SelfServiceNodeOfferAvailable(*offer, node, *server)
	return policy
}

func (h *ManagedNodesHandler) selectionOfferAvailable(ctx context.Context, grant storage.UserServerGrant, selection storage.UserNodeSelection) bool {
	return h.selectionOfferPolicy(ctx, grant, selection).available
}

func (h *ManagedNodesHandler) requireManagedAgentCapabilities(ctx context.Context, serverID int64) error {
	capabilities, err := h.managedConnectionCapabilities(serverID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrManagedAgentIncompatible, err)
	}
	if managedAgentHasNativeExpiry(capabilities) {
		return nil
	}
	if !capabilities.RPC {
		return fmt.Errorf("%w: missing rpc capability; upgrade and reconnect relaydock-agent", ErrManagedAgentIncompatible)
	}
	if err := h.requireManagedExpiryGuard(ctx, serverID); err != nil {
		return fmt.Errorf("%w: durable client expiry guard is unavailable", ErrManagedAgentIncompatible)
	}
	return nil
}

// reconcileSource serializes remote mutations and always reloads the latest
// generation after acquiring the lock. This prevents a delayed stale add from
// landing after a newer revoke has already completed.
func (h *ManagedNodesHandler) reconcileSource(ctx context.Context, source storage.UserInboundAccessSource) error {
	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()
	return h.reconcileSourceCurrentLocked(ctx, source.ID)
}

func (h *ManagedNodesHandler) reconcileSourceCurrentLocked(ctx context.Context, sourceID int64) error {
	source, err := h.repo.GetUserInboundAccessSource(ctx, sourceID)
	if err != nil {
		return err
	}
	return h.reconcileSourceLocked(ctx, *source)
}

func (h *ManagedNodesHandler) reconcileSourceLocked(ctx context.Context, source storage.UserInboundAccessSource) error {
	recycleCredential := false
	if source.SourceType == storage.ManagedSourceSelection {
		selection, err := h.repo.GetUserNodeSelection(ctx, source.SourceID)
		if err != nil {
			return err
		}
		offer, err := h.repo.GetSelfServiceNodeOffer(ctx, selection.OfferID)
		if err != nil {
			return err
		}
		node, err := h.repo.GetNodeByID(ctx, offer.NodeID)
		if err != nil {
			return err
		}
		grant, err := h.repo.GetUserServerGrant(ctx, selection.GrantID)
		if err != nil {
			return err
		}
		if selection.CredentialConfigID != nil {
			credential, credentialErr := h.repo.GetUserInboundConfig(ctx, source.Username, source.ServerID, source.InboundTag)
			switch {
			case errors.Is(credentialErr, sql.ErrNoRows):
				recycleCredential = true
			case credentialErr != nil:
				return credentialErr
			case credential.ID != *selection.CredentialConfigID ||
				!storage.SelfServiceCredentialProtocolMatches(credential.Protocol, node.Protocol):
				recycleCredential = true
			}
		} else if source.AppliedGeneration != 0 || source.ObservedState == storage.ManagedObservedActive {
			// A successfully applied selection must always have a credential
			// snapshot. Old/corrupt rows without one are revoked and cleaned up;
			// only never-applied provisioning sources may proceed without it.
			recycleCredential = true
		}
		if selection.AccessSourceID == nil || *selection.AccessSourceID != source.ID ||
			grant.Username != source.Username || grant.ServerID != source.ServerID ||
			offer.ServerID != source.ServerID || offer.NodeID != source.NodeID || offer.InboundTag != source.InboundTag {
			return storage.ErrManagedServerMismatch
		}
		protocolEligible := storage.SelfServiceNodeOfferProtocolEligible(*offer, node)
		protocolAllowed := grant.AllowsNodeProtocol(node.Protocol, node.ClashConfig) && protocolEligible
		if !protocolEligible {
			recycleCredential = true
		}
		if selection.DesiredEnabled && (recycleCredential || !protocolAllowed) {
			deactivated, err := h.repo.DeactivateUserNodeSelection(ctx, source.Username, selection.ID, "reconciler",
				storage.ManagedSuspendAdminDisabled, time.Now().UTC())
			if err != nil {
				return err
			}
			source = deactivated.Source
		}

		if source.DesiredState == storage.ManagedDesiredActive {
			server, err := h.repo.GetRemoteServer(ctx, offer.ServerID)
			if err != nil {
				return err
			}
			if grant.Username != source.Username || grant.ServerID != source.ServerID || offer.ServerID != source.ServerID ||
				offer.NodeID != source.NodeID || offer.InboundTag != source.InboundTag ||
				selection.AccessSourceID == nil || *selection.AccessSourceID != source.ID {
				return storage.ErrManagedServerMismatch
			}
			structureValid := storage.SelfServiceNodeOfferStructureValid(*offer, node, *server)
			if !selection.DesiredEnabled || !offer.Enabled || !node.Enabled || !structureValid {
				updated, err := h.repo.SetUserInboundAccessSourceState(ctx, source.ID, source.Generation,
					storage.ManagedDesiredInactive, storage.ManagedSuspendAdminDisabled, "reconciler", source.ExpiresAt)
				if err != nil {
					return err
				}
				source = *updated
			}
		}
	}
	if h.remoteManage == nil {
		return errors.New("remote manager is not available")
	}
	return h.repo.WithRemoteServerMutationLease(ctx, source.ServerID, func(leasedCtx context.Context) error {
		return h.reconcileSourceMutationLocked(leasedCtx, source, recycleCredential)
	})
}

// reconcileSourceMutationLocked keeps the limiter replacement, expiry guard,
// and client add/remove in one server mutation transaction. Nested remote
// helpers reuse the lease through ctx, so an installation Begin cannot split
// the policy update from the credential mutation.
func (h *ManagedNodesHandler) reconcileSourceMutationLocked(ctx context.Context, source storage.UserInboundAccessSource, recycleCredential bool) error {
	now := time.Now().UTC()
	if source.DesiredState == storage.ManagedDesiredActive && source.ExpiresAt != nil && !now.Before(*source.ExpiresAt) {
		updated, err := h.repo.SetUserInboundAccessSourceState(ctx, source.ID, source.Generation,
			storage.ManagedDesiredInactive, storage.ManagedSuspendExpired, "reconciler", source.ExpiresAt)
		if err != nil {
			return err
		}
		source = *updated
	}

	var applyErr error
	if source.DesiredState == storage.ManagedDesiredActive {
		user, err := h.repo.GetUser(ctx, source.Username)
		if err != nil {
			applyErr = err
		} else if !user.IsActive {
			updated, updateErr := h.repo.SetUserInboundAccessSourceState(ctx, source.ID, source.Generation,
				storage.ManagedDesiredInactive, storage.ManagedSuspendUserDisabled, "reconciler", source.ExpiresAt)
			if updateErr != nil {
				applyErr = updateErr
			} else {
				source = *updated
			}
		} else if capabilityErr := h.requireManagedAgentCapabilities(ctx, source.ServerID); capabilityErr != nil {
			// Keep the source pending without reserving or exposing a credential.
			// A later Agent upgrade/reconnect can satisfy the handshake and retry.
			applyErr = capabilityErr
		} else if hasAccess, notAfter, expiryErr := h.effectiveInboundExpiry(ctx, source, now); expiryErr != nil {
			applyErr = expiryErr
		} else if !hasAccess {
			applyErr = errors.New("managed access is no longer effective")
		} else {
			credential, prepareErr := prepareUserInboundCredential(ctx, h.remoteManage, h.repo, user, source.ServerID, source.InboundTag)
			if prepareErr != nil {
				applyErr = prepareErr
			} else {
				// Reservation makes the limiter builder aware of this user. Publish the
				// policy before add-client makes the credential usable.
				if h.limiter == nil {
					applyErr = errors.New("limiter pusher is not available")
				} else {
					applyErr = h.limiter.PushToServerChecked(ctx, source.ServerID)
				}
				if applyErr == nil {
					applyErr = h.ensureManagedClientExpiry(ctx, source.ServerID, source.InboundTag, credential, notAfter)
				}
				if applyErr == nil {
					applyErr = applyPreparedInboundCredentialForUser(ctx, h.remoteManage, h.repo, source.Username, source.ServerID, source.InboundTag, credential, notAfter)
				}
			}
		}
		if applyErr == nil {
			credential, err := h.repo.GetUserInboundConfig(ctx, source.Username, source.ServerID, source.InboundTag)
			if err != nil {
				applyErr = err
			} else if credential != nil && source.SourceType == storage.ManagedSourceSelection {
				selection, selectionErr := h.repo.GetUserNodeSelection(ctx, source.SourceID)
				if selectionErr != nil {
					applyErr = selectionErr
				} else if selection.CredentialConfigID == nil {
					applyErr = h.repo.SetUserNodeSelectionCredential(ctx, selection.ID, credential.ID)
				}
			}
		}
	}

	if applyErr == nil && source.DesiredState != storage.ManagedDesiredActive {
		hasOther, notAfter, err := h.effectiveInboundExpiry(ctx, source, now)
		if err != nil {
			applyErr = err
		} else if hasOther {
			user, userErr := h.repo.GetUser(ctx, source.Username)
			if userErr != nil {
				applyErr = userErr
			} else if h.limiter == nil {
				applyErr = errors.New("limiter pusher is not available")
			} else if limiterErr := h.limiter.PushToServerChecked(ctx, source.ServerID); limiterErr != nil {
				applyErr = limiterErr
			} else {
				// The shared credential stays, but its Agent-side timer must follow
				// the remaining sources rather than the source just revoked.
				credential, prepareErr := prepareUserInboundCredential(ctx, h.remoteManage, h.repo, user, source.ServerID, source.InboundTag)
				if prepareErr != nil {
					applyErr = prepareErr
				} else if expiryErr := h.ensureManagedClientExpiry(ctx, source.ServerID, source.InboundTag, credential, notAfter); expiryErr != nil {
					applyErr = expiryErr
				} else {
					applyErr = applyPreparedInboundCredentialForUser(ctx, h.remoteManage, h.repo, source.Username, source.ServerID, source.InboundTag, credential, notAfter)
				}
			}
		} else {
			credential, credentialErr := h.repo.GetUserInboundConfig(ctx, source.Username, source.ServerID, source.InboundTag)
			if errors.Is(credentialErr, sql.ErrNoRows) {
				credentialErr = nil
			}
			if credentialErr != nil {
				applyErr = credentialErr
			} else if credential != nil {
				applyErr = removeUserFromInbound(ctx, h.remoteManage, *credential)
				if applyErr == nil {
					var saved map[string]interface{}
					if err := json.Unmarshal([]byte(credential.CredentialJSON), &saved); err != nil {
						applyErr = fmt.Errorf("parse credential for expiry cleanup: %w", err)
					} else {
						applyErr = h.ensureManagedClientExpiry(ctx, source.ServerID, source.InboundTag, saved, nil)
					}
				}
			}
			if applyErr == nil && recycleCredential && source.SourceType == storage.ManagedSourceSelection {
				if credential != nil {
					applyErr = h.repo.DeleteUserInboundConfig(ctx, source.Username, source.ServerID, source.InboundTag)
				}
				if applyErr == nil {
					selection, selectionErr := h.repo.GetUserNodeSelection(ctx, source.SourceID)
					if selectionErr != nil {
						applyErr = selectionErr
					} else if selection.CredentialConfigID != nil {
						applyErr = h.repo.ClearUserNodeSelectionCredential(ctx, selection.ID, *selection.CredentialConfigID)
					}
				}
			}
		}
	}

	if applyErr != nil {
		delay := time.Duration(1<<min(source.RetryCount, 6)) * 15 * time.Second
		_, _ = h.repo.MarkUserInboundAccessSourceFailed(ctx, source.ID, source.Generation, applyErr.Error(), now.Add(delay))
		return applyErr
	}

	observed := storage.ManagedObservedInactive
	if source.DesiredState == storage.ManagedDesiredActive {
		observed = storage.ManagedObservedActive
	}
	if _, err := h.repo.MarkUserInboundAccessSourceApplied(ctx, source.ID, source.Generation, observed, now); err != nil {
		return err
	}
	if h.limiter != nil {
		h.limiter.PushToServer(ctx, source.ServerID)
	}
	return nil
}

func (h *ManagedNodesHandler) StartReconciler(ctx context.Context) {
	h.reconcileWG.Add(1)
	go func() {
		defer h.reconcileWG.Done()
		ticker := time.NewTicker(managedReconcileInterval)
		defer ticker.Stop()
		startup := time.NewTimer(managedReconcileStartupDelay)
		defer startup.Stop()
		select {
		case <-ctx.Done():
			return
		case <-startup.C:
		}
		h.reconcileAll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.reconcileAll(ctx)
			}
		}
	}()
}

func (h *ManagedNodesHandler) WaitForReconciler() {
	h.reconcileWG.Wait()
}

func (h *ManagedNodesHandler) reconcileAll(ctx context.Context) {
	if !h.reconcileMu.TryLock() {
		return
	}
	defer h.reconcileMu.Unlock()

	now := time.Now().UTC()
	h.syncManagedUsage(ctx, now)
	grants, err := h.repo.ListAllUserServerGrants(ctx)
	if err == nil {
		for _, grant := range grants {
			user, userErr := h.repo.GetUser(ctx, grant.Username)
			_, _, billed, usageErr := h.repo.GetUserServerGrantUsage(ctx, grant.ID)
			if userErr != nil || usageErr != nil {
				continue
			}
			state := managedGrantState(grant, user.IsActive, billed, now)
			grantDesired := storage.ManagedDesiredActive
			if state != storage.ManagedGrantActive {
				grantDesired = storage.ManagedDesiredInactive
			}
			selections, listErr := h.repo.ListUserNodeSelections(ctx, grant.Username, false)
			if listErr != nil {
				continue
			}
			for _, selection := range selections {
				if selection.GrantID != grant.ID || selection.AccessSourceID == nil {
					continue
				}
				source, sourceErr := h.repo.GetUserInboundAccessSource(ctx, *selection.AccessSourceID)
				if sourceErr != nil {
					continue
				}
				policy := h.selectionOfferPolicy(ctx, grant, selection)
				if policy.mustRevoke && selection.DesiredEnabled {
					deactivated, deactivateErr := h.repo.DeactivateUserNodeSelection(ctx, grant.Username, selection.ID,
						"reconciler", storage.ManagedSuspendAdminDisabled, now)
					if deactivateErr != nil {
						continue
					}
					selection = deactivated.Selection
					source = &deactivated.Source
				}
				desired := grantDesired
				if !selection.DesiredEnabled || !policy.available {
					desired = storage.ManagedDesiredInactive
				}
				if source.DesiredState == desired && sameOptionalTime(source.ExpiresAt, grant.ExpiresAt) {
					continue
				}
				reason := managedGrantSuspendReason(state)
				if desired == storage.ManagedDesiredInactive && state == storage.ManagedGrantActive {
					reason = storage.ManagedSuspendAdminDisabled
				}
				_, _ = h.repo.SetUserInboundAccessSourceState(ctx, source.ID, source.Generation,
					desired, reason, "reconciler", grant.ExpiresAt)
			}
		}
	}

	pending, err := h.repo.ListPendingUserInboundAccessSources(ctx, now, 200, 0)
	if err != nil {
		log.Printf("[ManagedNodes] list pending sources failed: %v", err)
		return
	}
	for _, source := range pending {
		if err := h.reconcileSourceCurrentLocked(ctx, source.ID); err != nil {
			log.Printf("[ManagedNodes] reconcile source=%d server=%d failed: %v", source.ID, source.ServerID, err)
		}
	}
	h.finalizeReadyUserDeletions(ctx)
}

func (h *ManagedNodesHandler) finalizeReadyUserDeletions(ctx context.Context) {
	usernames, err := h.repo.ListPendingUserDeletions(ctx, 100)
	if err != nil {
		log.Printf("[ManagedNodes] list pending user deletions failed: %v", err)
		return
	}
	for _, username := range usernames {
		ready, readyErr := h.repo.IsUserDeletionReady(ctx, username)
		if readyErr != nil {
			log.Printf("[ManagedNodes] check user deletion user=%s failed: %v", username, readyErr)
			continue
		}
		if !ready {
			continue
		}
		if cleanupErr := deleteUserPrivateRoutedAll(ctx, h.remoteManage, h.repo, username); cleanupErr != nil {
			log.Printf("[ManagedNodes] clean private routed access user=%s failed: %v", username, cleanupErr)
			_ = h.repo.RecordUserDeletionFailure(ctx, username, cleanupErr.Error())
			continue
		}
		if finalizeErr := h.repo.FinalizeUserDeletion(ctx, username, "reconciler"); finalizeErr != nil &&
			!errors.Is(finalizeErr, storage.ErrUserDeletionNotPrepared) &&
			!errors.Is(finalizeErr, storage.ErrUserNotFound) {
			log.Printf("[ManagedNodes] finalize user deletion user=%s failed: %v", username, finalizeErr)
			_ = h.repo.RecordUserDeletionFailure(ctx, username, finalizeErr.Error())
		}
	}
}

func nextManagedMonthlyReset(now time.Time, day int, timezone string) time.Time {
	return storage.NextManagedMonthlyReset(now, day, timezone)
}

func managedCredentialEmail(raw string) string {
	var credential map[string]interface{}
	if json.Unmarshal([]byte(raw), &credential) != nil {
		return ""
	}
	if email, _ := credential["email"].(string); strings.TrimSpace(email) != "" {
		return strings.TrimSpace(email)
	}
	if user, _ := credential["user"].(string); strings.TrimSpace(user) != "" {
		return strings.TrimSpace(user)
	}
	return ""
}

func (h *ManagedNodesHandler) syncManagedSelectionUsage(ctx context.Context, grant storage.UserServerGrant, selection storage.UserNodeSelection, now time.Time) error {
	if selection.GrantID != grant.ID || !selection.DesiredEnabled || selection.AccessSourceID == nil {
		return nil
	}
	user, err := h.repo.GetUser(ctx, grant.Username)
	if err != nil {
		return err
	}
	_, _, billed, err := h.repo.GetUserServerGrantUsage(ctx, grant.ID)
	if err != nil {
		return err
	}
	if grant.StateAt(now, user.IsActive, billed) != storage.ManagedGrantActive {
		return nil
	}
	offer, err := h.repo.GetSelfServiceNodeOffer(ctx, selection.OfferID)
	if err != nil || !offer.Enabled || offer.ServerID != grant.ServerID {
		return nil
	}
	node, err := h.repo.GetNodeByID(ctx, offer.NodeID)
	if err != nil || !node.Enabled {
		return nil
	}
	source, err := h.repo.GetUserInboundAccessSource(ctx, *selection.AccessSourceID)
	if err != nil {
		return err
	}
	if source.SourceType != storage.ManagedSourceSelection || source.SourceID != selection.ID ||
		source.Username != grant.Username || source.ServerID != offer.ServerID ||
		source.NodeID != offer.NodeID || source.InboundTag != offer.InboundTag ||
		source.DesiredState != storage.ManagedDesiredActive || source.SuspendReason != storage.ManagedSuspendNone ||
		now.Before(source.StartsAt) || source.ExpiresAt != nil && !now.Before(*source.ExpiresAt) {
		return nil
	}
	credential, err := h.repo.GetUserInboundConfig(ctx, grant.Username, offer.ServerID, offer.InboundTag)
	if err != nil || credential == nil {
		return nil
	}
	email := managedCredentialEmail(credential.CredentialJSON)
	if email == "" {
		return nil
	}
	traffic, err := h.repo.GetUserEmailTraffic(ctx, offer.ServerID, email)
	if err != nil || traffic == nil {
		return nil
	}
	epoch := fmt.Sprintf("server-%d", offer.ServerID)
	if server, serverErr := h.repo.GetRemoteServer(ctx, offer.ServerID); serverErr == nil && server != nil {
		epoch = fmt.Sprintf("server-%d-xray-%d", offer.ServerID, server.XrayBootCount)
	}
	packageAccess, _, err := hasLegacyPackageInboundAccess(ctx, h.repo, grant.Username, offer.ServerID, offer.InboundTag, now)
	if err != nil {
		return err
	}
	if packageAccess {
		_, err = h.repo.RebaseUserNodeSelectionUsage(ctx, selection.ID, traffic.LastUplink, traffic.LastDownlink, epoch, now)
		return err
	}
	_, err = h.repo.AccumulateUserNodeSelectionUsage(ctx, selection.ID, traffic.LastUplink, traffic.LastDownlink, epoch, now)
	return err
}

func (h *ManagedNodesHandler) syncManagedGrantUsage(ctx context.Context, grant storage.UserServerGrant, now time.Time) {
	selections, err := h.repo.ListUserNodeSelections(ctx, grant.Username, false)
	if err != nil {
		log.Printf("[ManagedNodes] list usage selections grant=%d failed: %v", grant.ID, err)
		return
	}
	for _, selection := range selections {
		if selection.GrantID != grant.ID {
			continue
		}
		if err := h.syncManagedSelectionUsage(ctx, grant, selection, now); err != nil {
			log.Printf("[ManagedNodes] collect usage selection=%d failed: %v", selection.ID, err)
		}
	}
}

func (h *ManagedNodesHandler) syncCurrentManagedSelectionUsage(ctx context.Context, selection storage.UserNodeSelection, now time.Time) {
	grant, err := h.repo.GetUserServerGrant(ctx, selection.GrantID)
	if err != nil {
		log.Printf("[ManagedNodes] read grant before final usage selection=%d failed: %v", selection.ID, err)
		return
	}
	if err := h.syncManagedSelectionUsage(ctx, *grant, selection, now); err != nil {
		log.Printf("[ManagedNodes] final usage selection=%d failed: %v", selection.ID, err)
	}
}

func (h *ManagedNodesHandler) syncManagedUsage(ctx context.Context, now time.Time) {
	grants, err := h.repo.ListAllUserServerGrants(ctx)
	if err != nil {
		return
	}
	for _, grant := range grants {
		if grant.ResetPolicy == storage.ManagedResetMonthly && grant.NextResetAt != nil && !now.Before(*grant.NextResetAt) {
			next := nextManagedMonthlyReset(now, grant.ResetDay, grant.BillingTimezone)
			location, locationErr := time.LoadLocation(grant.BillingTimezone)
			if locationErr != nil {
				location = time.UTC
			}
			cycleStart := next.In(location).AddDate(0, -1, 0).UTC()
			if err := h.repo.ResetUserServerGrantUsage(ctx, grant.ID, cycleStart, &next, "reconciler"); err != nil {
				log.Printf("[ManagedNodes] reset usage grant=%d failed: %v", grant.ID, err)
				continue
			}
			grant.NextResetAt = &next
		}
		h.syncManagedGrantUsage(ctx, grant, now)
	}
}

func decodeManagedJSON(r *http.Request, target interface{}) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid request body", storage.ErrManagedInvalidArgument)
	}
	return nil
}

func (h *ManagedNodesHandler) offerResponse(ctx context.Context, offer storage.SelfServiceNodeOffer) managedOfferResponse {
	response := managedOfferResponse{SelfServiceNodeOffer: offer}
	if node, err := h.repo.GetNodeByID(ctx, offer.NodeID); err == nil {
		response.NodeName = node.NodeName
		response.Protocol = node.Protocol
		response.ProtocolProfile, _ = storage.SelfServiceNodeProtocolProfile(node.Protocol, node.ClashConfig)
	}
	if server, err := h.repo.GetRemoteServer(ctx, offer.ServerID); err == nil && server != nil {
		response.ServerName = server.Name
		response.ServerStatus = server.Status
	}
	if err := h.requireManagedAgentCapabilities(ctx, offer.ServerID); err != nil {
		response.AgentError = err.Error()
	} else {
		response.AgentReady = true
	}
	return response
}

func (h *ManagedNodesHandler) HandleOffers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		offers, err := h.repo.ListSelfServiceNodeOffers(r.Context(), true)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		items := make([]managedOfferResponse, 0, len(offers))
		for _, offer := range offers {
			items = append(items, h.offerResponse(r.Context(), offer))
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "offers": items})
	case http.MethodPost:
		var request struct {
			NodeID    int64 `json:"node_id"`
			Enabled   *bool `json:"enabled"`
			SortOrder int   `json:"sort_order"`
		}
		if err := decodeManagedJSON(r, &request); err != nil {
			writeManagedError(w, err)
			return
		}
		node, err := h.repo.GetNodeByID(r.Context(), request.NodeID)
		if err != nil {
			writeManagedError(w, storage.ErrManagedInvalidArgument)
			return
		}
		if err := validateSelfServiceNodeProtocol(node); err != nil {
			writeManagedError(w, err)
			return
		}
		server, err := h.findServerForNode(r.Context(), node)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		if err := h.requireManagedAgentCapabilities(r.Context(), server.ID); err != nil {
			writeManagedError(w, err)
			return
		}
		offer, err := h.repo.CreateSelfServiceNodeOffer(r.Context(), request.NodeID, server.ID, managedActor(r))
		if err != nil {
			writeManagedError(w, err)
			return
		}
		enabled := true
		if request.Enabled != nil {
			enabled = *request.Enabled
		}
		if !enabled || request.SortOrder != 0 {
			offer, err = h.repo.UpdateSelfServiceNodeOffer(r.Context(), offer.ID, enabled, request.SortOrder)
			if err != nil {
				writeManagedError(w, err)
				return
			}
		}
		writeJSON(w, http.StatusCreated, map[string]interface{}{"success": true, "offer": h.offerResponse(r.Context(), *offer)})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ManagedNodesHandler) HandleOffer(w http.ResponseWriter, r *http.Request) {
	id, err := managedRequestID(r, "id")
	if err != nil {
		writeManagedError(w, err)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var request struct {
			Enabled   bool `json:"enabled"`
			SortOrder int  `json:"sort_order"`
		}
		if err := decodeManagedJSON(r, &request); err != nil {
			writeManagedError(w, err)
			return
		}
		if request.Enabled {
			existing, getErr := h.repo.GetSelfServiceNodeOffer(r.Context(), id)
			if getErr != nil {
				writeManagedError(w, getErr)
				return
			}
			node, nodeErr := h.repo.GetNodeByID(r.Context(), existing.NodeID)
			if nodeErr != nil {
				writeManagedError(w, nodeErr)
				return
			}
			if protocolErr := validateSelfServiceNodeProtocol(node); protocolErr != nil {
				writeManagedError(w, protocolErr)
				return
			}
			if capabilityErr := h.requireManagedAgentCapabilities(r.Context(), existing.ServerID); capabilityErr != nil {
				writeManagedError(w, capabilityErr)
				return
			}
		}
		offer, err := h.repo.UpdateSelfServiceNodeOffer(r.Context(), id, request.Enabled, request.SortOrder)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		go h.reconcileAll(context.Background())
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "offer": h.offerResponse(r.Context(), *offer)})
	case http.MethodDelete:
		if err := h.repo.DeleteSelfServiceNodeOffer(r.Context(), id); err != nil {
			writeManagedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

type managedGrantRequest struct {
	ServerID                int64      `json:"server_id"`
	Enabled                 bool       `json:"enabled"`
	StartsAt                time.Time  `json:"starts_at"`
	ExpiresAt               *time.Time `json:"expires_at"`
	MaxActiveNodes          int        `json:"max_active_nodes"`
	SpeedLimitMbps          float64    `json:"speed_limit_mbps"`
	ConnectionLimit         int        `json:"connection_limit"`
	TrafficLimitBytes       int64      `json:"traffic_limit_bytes"`
	BillingMode             string     `json:"billing_mode"`
	ResetPolicy             string     `json:"reset_policy"`
	ResetDay                int        `json:"reset_day"`
	AllowedProtocols        *[]string  `json:"allowed_protocols"`
	AllowedProtocolProfiles *[]string  `json:"allowed_protocol_profiles"`
	Version                 int64      `json:"version"`
}

func (request managedGrantRequest) grant(username, actor string, existing *storage.UserServerGrant) storage.UserServerGrant {
	grant := storage.UserServerGrant{
		Username:          username,
		ServerID:          request.ServerID,
		Enabled:           request.Enabled,
		StartsAt:          request.StartsAt.UTC(),
		ExpiresAt:         request.ExpiresAt,
		MaxActiveNodes:    request.MaxActiveNodes,
		SpeedLimitMbps:    request.SpeedLimitMbps,
		ConnectionLimit:   request.ConnectionLimit,
		TrafficLimitBytes: request.TrafficLimitBytes,
		BillingMode:       request.BillingMode,
		ResetPolicy:       request.ResetPolicy,
		ResetDay:          request.ResetDay,
		BillingTimezone:   "Asia/Shanghai",
		CreatedBy:         actor,
	}
	if request.AllowedProtocols != nil {
		grant.AllowedProtocols = append([]string(nil), (*request.AllowedProtocols)...)
	}
	if request.AllowedProtocolProfiles != nil {
		grant.AllowedProtocolProfiles = append([]string(nil), (*request.AllowedProtocolProfiles)...)
	}
	if grant.ExpiresAt != nil {
		expires := grant.ExpiresAt.UTC()
		grant.ExpiresAt = &expires
	}
	if existing != nil {
		grant.ID = existing.ID
		grant.Username = existing.Username
		grant.ServerID = existing.ServerID
		grant.BillingTimezone = existing.BillingTimezone
		grant.NextResetAt = existing.NextResetAt
		grant.CreatedBy = existing.CreatedBy
		grant.CreatedAt = existing.CreatedAt
		grant.Version = existing.Version
		if request.AllowedProtocols == nil {
			grant.AllowedProtocols = append([]string(nil), existing.AllowedProtocols...)
		}
		if request.AllowedProtocolProfiles == nil {
			grant.AllowedProtocolProfiles = append([]string(nil), existing.AllowedProtocolProfiles...)
		}
	}
	return grant
}

func (h *ManagedNodesHandler) grantResponses(ctx context.Context, username string) ([]managedGrantResponse, error) {
	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}
	grants, err := h.repo.ListUserServerGrants(ctx, username)
	if err != nil {
		return nil, err
	}
	offers, _ := h.repo.ListSelfServiceNodeOffers(ctx, true)
	selections, _ := h.repo.ListUserNodeSelections(ctx, username, false)
	sources, _ := h.repo.ListUserInboundAccessSources(ctx, username, 0)
	servers, _ := h.repo.ListRemoteServers(ctx)

	offerCounts := make(map[int64]int)
	for _, offer := range offers {
		if offer.Enabled {
			offerCounts[offer.ServerID]++
		}
	}
	activeCounts := make(map[int64]int)
	for _, selection := range selections {
		if selection.DesiredEnabled {
			activeCounts[selection.GrantID]++
		}
	}
	serverMap := make(map[int64]storage.RemoteServer, len(servers))
	for _, server := range servers {
		serverMap[server.ID] = server
	}
	lastError := make(map[int64]string)
	for _, source := range sources {
		if source.LastError != "" && lastError[source.ServerID] == "" {
			lastError[source.ServerID] = source.LastError
		}
	}

	now := time.Now().UTC()
	responses := make([]managedGrantResponse, 0, len(grants))
	for _, grant := range grants {
		uplink, downlink, billed, usageErr := h.repo.GetUserServerGrantUsage(ctx, grant.ID)
		if usageErr != nil {
			return nil, usageErr
		}
		server := serverMap[grant.ServerID]
		responses = append(responses, managedGrantResponse{
			UserServerGrant:   grant,
			ServerName:        server.Name,
			ServerStatus:      server.Status,
			State:             managedGrantState(grant, user.IsActive, billed, now),
			OfferCount:        offerCounts[grant.ServerID],
			ActiveNodeCount:   activeCounts[grant.ID],
			UsedUplinkBytes:   uplink,
			UsedDownlinkBytes: downlink,
			BilledBytes:       billed,
			LastError:         lastError[grant.ServerID],
		})
	}
	return responses, nil
}

func (h *ManagedNodesHandler) syncGrantSources(ctx context.Context, grant storage.UserServerGrant, actor string) []error {
	user, err := h.repo.GetUser(ctx, grant.Username)
	if err != nil {
		return []error{err}
	}
	_, _, billed, err := h.repo.GetUserServerGrantUsage(ctx, grant.ID)
	if err != nil {
		return []error{err}
	}
	state := managedGrantState(grant, user.IsActive, billed, time.Now().UTC())
	selections, err := h.repo.ListUserNodeSelections(ctx, grant.Username, false)
	if err != nil {
		return []error{err}
	}
	errorsFound := make([]error, 0)
	for _, selection := range selections {
		if selection.GrantID != grant.ID || selection.AccessSourceID == nil {
			continue
		}
		source, sourceErr := h.repo.GetUserInboundAccessSource(ctx, *selection.AccessSourceID)
		if sourceErr != nil {
			errorsFound = append(errorsFound, sourceErr)
			continue
		}
		policy := h.selectionOfferPolicy(ctx, grant, selection)
		if policy.mustRevoke && selection.DesiredEnabled {
			deactivated, deactivateErr := h.repo.DeactivateUserNodeSelection(ctx, grant.Username, selection.ID,
				actor, storage.ManagedSuspendAdminDisabled, time.Now().UTC())
			if deactivateErr != nil {
				errorsFound = append(errorsFound, deactivateErr)
				continue
			}
			selection = deactivated.Selection
			source = &deactivated.Source
		}
		desired := storage.ManagedDesiredActive
		offerAvailable := policy.available
		if state != storage.ManagedGrantActive || !selection.DesiredEnabled || !offerAvailable {
			desired = storage.ManagedDesiredInactive
		}
		if source.DesiredState != desired || !sameOptionalTime(source.ExpiresAt, grant.ExpiresAt) {
			reason := managedGrantSuspendReason(state)
			if desired == storage.ManagedDesiredInactive && state == storage.ManagedGrantActive && !offerAvailable {
				reason = storage.ManagedSuspendAdminDisabled
			}
			updated, updateErr := h.repo.SetUserInboundAccessSourceState(ctx, source.ID, source.Generation,
				desired, reason, actor, grant.ExpiresAt)
			if updateErr != nil {
				errorsFound = append(errorsFound, updateErr)
				continue
			}
			source = updated
		}
		if reconcileErr := h.reconcileSource(ctx, *source); reconcileErr != nil {
			errorsFound = append(errorsFound, reconcileErr)
		}
	}
	if h.limiter != nil {
		h.limiter.PushToServer(ctx, grant.ServerID)
	}
	return errorsFound
}

func (h *ManagedNodesHandler) HandleAdminGrants(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	switch r.Method {
	case http.MethodGet:
		grants, err := h.grantResponses(r.Context(), username)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "grants": grants})
	case http.MethodPost:
		var request managedGrantRequest
		if err := decodeManagedJSON(r, &request); err != nil {
			writeManagedError(w, err)
			return
		}
		grant, err := h.repo.CreateUserServerGrant(r.Context(), request.grant(username, managedActor(r), nil))
		if err != nil {
			writeManagedError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]interface{}{"success": true, "grant": grant})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ManagedNodesHandler) HandleAdminGrant(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PathValue("username"))
	id, err := managedRequestID(r, "id")
	if err != nil || username == "" {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	existing, err := h.repo.GetUserServerGrant(r.Context(), id)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	if existing.Username != username {
		writeManagedError(w, storage.ErrUserServerGrantNotFound)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var request managedGrantRequest
		if err := decodeManagedJSON(r, &request); err != nil {
			writeManagedError(w, err)
			return
		}
		if request.ServerID != 0 && request.ServerID != existing.ServerID {
			writeManagedError(w, storage.ErrManagedServerMismatch)
			return
		}
		h.syncManagedGrantUsage(r.Context(), *existing, time.Now().UTC())
		grant, err := h.repo.UpdateUserServerGrant(r.Context(), request.grant(username, managedActor(r), existing), request.Version, managedActor(r))
		if err != nil {
			writeManagedError(w, err)
			return
		}
		pending := len(h.syncGrantSources(r.Context(), *grant, managedActor(r))) > 0
		status := http.StatusOK
		if pending {
			status = http.StatusAccepted
		}
		writeJSON(w, status, map[string]interface{}{"success": true, "grant": grant, "pending": pending})
	case http.MethodDelete:
		h.syncManagedGrantUsage(r.Context(), *existing, time.Now().UTC())
		disabled := *existing
		disabled.Enabled = false
		updated, err := h.repo.UpdateUserServerGrant(r.Context(), disabled, existing.Version, managedActor(r))
		if err != nil {
			writeManagedError(w, err)
			return
		}
		if failures := h.syncGrantSources(r.Context(), *updated, managedActor(r)); len(failures) > 0 {
			writeJSON(w, http.StatusAccepted, map[string]interface{}{
				"success": true, "pending": true, "message": "Access disabled; remote cleanup will retry",
			})
			return
		}
		if err := h.repo.DeleteUserServerGrant(r.Context(), updated.ID, updated.Version, managedActor(r)); err != nil {
			writeManagedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ManagedNodesHandler) HandleAdminGrantRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	id, err := managedRequestID(r, "id")
	if err != nil {
		writeManagedError(w, err)
		return
	}
	grant, err := h.repo.GetUserServerGrant(r.Context(), id)
	if err != nil || grant.Username != username {
		writeManagedError(w, storage.ErrUserServerGrantNotFound)
		return
	}
	failures := h.syncGrantSources(r.Context(), *grant, managedActor(r))
	status := http.StatusOK
	if len(failures) > 0 {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"success": true, "pending": len(failures) > 0})
}

func (h *ManagedNodesHandler) selectionResponses(ctx context.Context, username string) ([]managedSelectionResponse, error) {
	selections, err := h.repo.ListUserNodeSelections(ctx, username, false)
	if err != nil {
		return nil, err
	}
	grants, err := h.repo.ListUserServerGrants(ctx, username)
	if err != nil {
		return nil, err
	}
	offers, err := h.repo.ListSelfServiceNodeOffers(ctx, true)
	if err != nil {
		return nil, err
	}
	grantMap := make(map[int64]storage.UserServerGrant, len(grants))
	for _, grant := range grants {
		grantMap[grant.ID] = grant
	}
	offerMap := make(map[int64]storage.SelfServiceNodeOffer, len(offers))
	for _, offer := range offers {
		offerMap[offer.ID] = offer
	}

	responses := make([]managedSelectionResponse, 0, len(selections))
	for _, selection := range selections {
		grant, grantOK := grantMap[selection.GrantID]
		offer, offerOK := offerMap[selection.OfferID]
		if !grantOK || !offerOK {
			continue
		}
		var source *storage.UserInboundAccessSource
		if selection.AccessSourceID != nil {
			source, _ = h.repo.GetUserInboundAccessSource(ctx, *selection.AccessSourceID)
		}
		node, _ := h.repo.GetNodeByID(ctx, offer.NodeID)
		server, _ := h.repo.GetRemoteServer(ctx, offer.ServerID)
		speed := grant.SpeedLimitMbps
		if selection.SpeedLimitOverrideMbps != nil {
			speed = *selection.SpeedLimitOverrideMbps
		}
		connections := grant.ConnectionLimit
		if selection.ConnectionLimitOverride != nil {
			connections = *selection.ConnectionLimitOverride
		}
		billing := grant.BillingMode
		if selection.BillingModeOverride != nil {
			billing = *selection.BillingModeOverride
		}
		response := managedSelectionResponse{
			ID:                       selection.ID,
			GrantID:                  selection.GrantID,
			OfferID:                  selection.OfferID,
			NodeID:                   offer.NodeID,
			NodeName:                 node.NodeName,
			ServerID:                 offer.ServerID,
			Protocol:                 node.Protocol,
			DesiredEnabled:           selection.DesiredEnabled,
			State:                    managedSelectionState(source),
			EffectiveSpeedLimitMbps:  speed,
			EffectiveConnectionLimit: connections,
			EffectiveBillingMode:     billing,
			SpeedLimitOverrideMbps:   selection.SpeedLimitOverrideMbps,
			ConnectionLimitOverride:  selection.ConnectionLimitOverride,
			BillingModeOverride:      selection.BillingModeOverride,
		}
		if server != nil {
			response.ServerName = server.Name
		}
		if source != nil {
			response.LastError = source.LastError
		}
		responses = append(responses, response)
	}
	return responses, nil
}

func (h *ManagedNodesHandler) HandleAdminManagedNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	items, err := h.selectionResponses(r.Context(), username)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "items": items})
}

func (h *ManagedNodesHandler) getAdminSelection(r *http.Request) (*storage.UserNodeSelection, error) {
	id, err := managedRequestID(r, "id")
	if err != nil {
		return nil, err
	}
	selection, err := h.repo.GetUserNodeSelection(r.Context(), id)
	if err != nil {
		return nil, err
	}
	grant, err := h.repo.GetUserServerGrant(r.Context(), selection.GrantID)
	if err != nil {
		return nil, err
	}
	if grant.Username != strings.TrimSpace(r.PathValue("username")) {
		return nil, storage.ErrUserNodeSelectionNotFound
	}
	return selection, nil
}

func (h *ManagedNodesHandler) HandleAdminManagedNodeLimits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	selection, err := h.getAdminSelection(r)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	var request struct {
		SpeedLimitMbps  *float64 `json:"speed_limit_override_mbps"`
		ConnectionLimit *int     `json:"connection_limit_override"`
		BillingMode     *string  `json:"billing_mode_override"`
	}
	if err := decodeManagedJSON(r, &request); err != nil {
		writeManagedError(w, err)
		return
	}
	updated, err := h.repo.UpdateUserNodeSelectionLimits(r.Context(), selection.ID, request.SpeedLimitMbps,
		request.ConnectionLimit, request.BillingMode, managedActor(r))
	if err != nil {
		writeManagedError(w, err)
		return
	}
	status := http.StatusOK
	pendingError := ""
	if updated.AccessSourceID != nil {
		source, sourceErr := h.repo.GetUserInboundAccessSource(r.Context(), *updated.AccessSourceID)
		if sourceErr != nil {
			status = http.StatusAccepted
			pendingError = sourceErr.Error()
		} else if reconcileErr := h.reconcileSource(r.Context(), *source); reconcileErr != nil {
			status = http.StatusAccepted
			pendingError = reconcileErr.Error()
		}
	}
	writeJSON(w, status, map[string]interface{}{
		"success": true, "selection": updated, "pending": status == http.StatusAccepted,
		"pending_error": pendingError,
	})
}

func (h *ManagedNodesHandler) HandleAdminManagedNodeRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	selection, err := h.getAdminSelection(r)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	if selection.AccessSourceID == nil {
		writeManagedError(w, storage.ErrManagedAccessSourceNotFound)
		return
	}
	source, err := h.repo.GetUserInboundAccessSource(r.Context(), *selection.AccessSourceID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	status := http.StatusOK
	if err := h.reconcileSource(r.Context(), *source); err != nil {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"success": true, "pending": status == http.StatusAccepted})
}

func (h *ManagedNodesHandler) catalogResponses(ctx context.Context, username string) ([]managedCatalogResponse, error) {
	entries, err := h.repo.ListManagedNodeCatalog(ctx, username, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	responses := make([]managedCatalogResponse, 0, len(entries))
	for _, entry := range entries {
		server, _ := h.repo.GetRemoteServer(ctx, entry.Offer.ServerID)
		selected := entry.Selection != nil && entry.Selection.DesiredEnabled
		selectionID := int64(0)
		if entry.Selection != nil {
			selectionID = entry.Selection.ID
		}
		response := managedCatalogResponse{
			OfferID:           entry.Offer.ID,
			NodeID:            entry.Offer.NodeID,
			NodeName:          entry.NodeName,
			ServerID:          entry.Offer.ServerID,
			ServerName:        entry.ServerName,
			Protocol:          entry.Protocol,
			ProtocolProfile:   entry.ProtocolProfile,
			GrantID:           entry.Grant.ID,
			GrantState:        entry.GrantStatus,
			ExpiresAt:         entry.Grant.ExpiresAt,
			CanCreate:         entry.CanCreate,
			DisabledReason:    entry.DenyReason,
			Selected:          selected,
			SelectionID:       selectionID,
			SpeedLimitMbps:    entry.Grant.SpeedLimitMbps,
			ConnectionLimit:   entry.Grant.ConnectionLimit,
			TrafficLimitBytes: entry.Grant.TrafficLimitBytes,
			BillingMode:       entry.Grant.BillingMode,
		}
		if server != nil {
			response.ServerStatus = server.Status
			if response.ServerName == "" {
				response.ServerName = server.Name
			}
		}
		if node, nodeErr := h.repo.GetNodeByID(ctx, entry.Offer.NodeID); nodeErr == nil {
			if protocolErr := validateSelfServiceNodeProtocol(node); protocolErr != nil {
				response.CanCreate = false
				response.DisabledReason = protocolErr.Error()
			}
		}
		responses = append(responses, response)
	}
	return responses, nil
}

func (h *ManagedNodesHandler) requireActiveManagedUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	username := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return "", false
	}
	user, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeManagedError(w, err)
		return "", false
	}
	if !user.IsActive {
		writeJSONError(w, http.StatusForbidden, "user is disabled")
		return "", false
	}
	return username, true
}

func (h *ManagedNodesHandler) HandleUserManagedNodes(w http.ResponseWriter, r *http.Request) {
	username, ok := h.requireActiveManagedUser(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		catalog, err := h.catalogResponses(r.Context(), username)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		selected, err := h.selectionResponses(r.Context(), username)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		grants, err := h.grantResponses(r.Context(), username)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true, "grants": grants, "selected": selected, "catalog": catalog,
		})
	case http.MethodPost:
		var request struct {
			OfferID int64 `json:"offer_id"`
		}
		if err := decodeManagedJSON(r, &request); err != nil {
			writeManagedError(w, err)
			return
		}
		offer, offerErr := h.repo.GetSelfServiceNodeOffer(r.Context(), request.OfferID)
		if offerErr != nil {
			writeManagedError(w, offerErr)
			return
		}
		node, nodeErr := h.repo.GetNodeByID(r.Context(), offer.NodeID)
		if nodeErr != nil {
			writeManagedError(w, nodeErr)
			return
		}
		if protocolErr := validateSelfServiceNodeProtocol(node); protocolErr != nil {
			writeManagedError(w, protocolErr)
			return
		}
		result, err := h.repo.ActivateUserNodeSelection(r.Context(), username, request.OfferID, username, time.Now().UTC())
		if err != nil {
			writeManagedError(w, err)
			return
		}
		status := http.StatusCreated
		pending := false
		pendingError := ""
		if err := h.reconcileSource(r.Context(), result.Source); err != nil {
			log.Printf("[ManagedNodes] user provision selection=%d failed: %v", result.Selection.ID, err)
			status = http.StatusAccepted
			pending = true
			pendingError = err.Error()
		}
		writeJSON(w, status, map[string]interface{}{
			"success": true, "selection": result.Selection, "created": result.Created,
			"pending": pending, "pending_error": pendingError,
		})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ManagedNodesHandler) HandleUserManagedNode(w http.ResponseWriter, r *http.Request) {
	username, ok := h.requireActiveManagedUser(w, r)
	if !ok {
		return
	}
	id, err := managedRequestID(r, "id")
	if err != nil {
		writeManagedError(w, err)
		return
	}
	selection, err := h.repo.GetUserNodeSelectionForUser(r.Context(), id, username)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		now := time.Now().UTC()
		h.syncCurrentManagedSelectionUsage(r.Context(), *selection, now)
		result, err := h.repo.DeactivateUserNodeSelection(r.Context(), username, selection.ID, username,
			storage.ManagedSuspendUserDisabled, now)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		status := http.StatusOK
		if err := h.reconcileSource(r.Context(), result.Source); err != nil {
			log.Printf("[ManagedNodes] user deprovision selection=%d failed: %v", result.Selection.ID, err)
			status = http.StatusAccepted
		}
		writeJSON(w, status, map[string]interface{}{"success": true, "pending": status == http.StatusAccepted})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ManagedNodesHandler) HandleUserManagedNodeRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	username, ok := h.requireActiveManagedUser(w, r)
	if !ok {
		return
	}
	id, err := managedRequestID(r, "id")
	if err != nil {
		writeManagedError(w, err)
		return
	}
	selection, err := h.repo.GetUserNodeSelectionForUser(r.Context(), id, username)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	if selection.AccessSourceID == nil {
		writeManagedError(w, storage.ErrManagedAccessSourceNotFound)
		return
	}
	grant, err := h.repo.GetUserServerGrant(r.Context(), selection.GrantID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	offer, err := h.repo.GetSelfServiceNodeOffer(r.Context(), selection.OfferID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	node, err := h.repo.GetNodeByID(r.Context(), offer.NodeID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	protocolErr := validateSelfServiceNodeProtocol(node)
	if !grant.AllowsNodeProtocol(node.Protocol, node.ClashConfig) || protocolErr != nil {
		result, deactivateErr := h.repo.DeactivateUserNodeSelection(r.Context(), username, selection.ID, username,
			storage.ManagedSuspendAdminDisabled, time.Now().UTC())
		if deactivateErr != nil {
			writeManagedError(w, deactivateErr)
			return
		}
		if reconcileErr := h.reconcileSource(r.Context(), result.Source); reconcileErr != nil {
			log.Printf("[ManagedNodes] protocol-policy cleanup selection=%d failed: %v", selection.ID, reconcileErr)
		}
		if protocolErr != nil {
			writeManagedError(w, protocolErr)
		} else {
			writeManagedError(w, fmt.Errorf("%w: %s", storage.ErrManagedProtocolNotAllowed, strings.ToLower(strings.TrimSpace(node.Protocol))))
		}
		return
	}
	source, err := h.repo.GetUserInboundAccessSource(r.Context(), *selection.AccessSourceID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	status := http.StatusOK
	pendingError := ""
	if err := h.reconcileSource(r.Context(), *source); err != nil {
		status = http.StatusAccepted
		pendingError = err.Error()
	}
	writeJSON(w, status, map[string]interface{}{
		"success": true, "pending": status == http.StatusAccepted, "pending_error": pendingError,
	})
}
