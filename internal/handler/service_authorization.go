package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type serviceAuthorizationPackageRequest struct {
	PackageID  int64  `json:"package_id"`
	StartDate  string `json:"start_date"`
	ExpireDate string `json:"expire_date"`
	IsReset    *bool  `json:"is_reset"`
	ResetDay   *int   `json:"reset_day"`
}

type serviceAuthorizationFixedNodeGrant struct {
	NodeID    int64      `json:"node_id"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type serviceAuthorizationServerGrant struct {
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
	AllowedProtocols        []string   `json:"allowed_protocols"`
	AllowedProtocolProfiles []string   `json:"allowed_protocol_profiles"`
}

type serviceAuthorizationForwardingGrant struct {
	TunnelID                  int64      `json:"tunnel_id"`
	Enabled                   bool       `json:"enabled"`
	StartsAt                  time.Time  `json:"starts_at"`
	ExpiresAt                 *time.Time `json:"expires_at"`
	MaxActiveForwards         int        `json:"max_active_forwards"`
	PerForwardSpeedMbps       float64    `json:"per_forward_speed_mbps"`
	PerForwardConnectionLimit int        `json:"per_forward_connection_limit"`
	TrafficLimitBytes         int64      `json:"traffic_limit_bytes"`
	BillingModeOverride       string     `json:"billing_mode_override"`
	AllowCustomPublicTarget   bool       `json:"allow_custom_public_target"`
}

type serviceAuthorizationCustomRequest struct {
	FixedNodeGrants  *[]serviceAuthorizationFixedNodeGrant  `json:"fixed_node_grants"`
	ServerGrants     *[]serviceAuthorizationServerGrant     `json:"server_grants"`
	ForwardingGrants *[]serviceAuthorizationForwardingGrant `json:"forwarding_grants"`
}

type serviceAuthorizationRequest struct {
	Usernames []string                            `json:"usernames,omitempty"`
	Mode      string                              `json:"mode"`
	Package   *serviceAuthorizationPackageRequest `json:"package,omitempty"`
	Custom    *serviceAuthorizationCustomRequest  `json:"custom,omitempty"`
}

type serviceAuthorizationResult struct {
	Username string   `json:"username"`
	Mode     string   `json:"mode"`
	Status   string   `json:"status"`
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

type parsedPackageAuthorization struct {
	packageID int64
	startsAt  time.Time
	expiresAt time.Time
	isReset   bool
	resetDay  int
}

type customAuthorizationSnapshot struct {
	fixed        []serviceAuthorizationFixedNodeGrant
	servers      []serviceAuthorizationServerGrant
	forwarding   []serviceAuthorizationForwardingGrant
	activeChilds authorizationChildState
}

type authorizationChildState struct {
	selectionOfferIDs []int64
	forwardPublicIDs  []string
}

type ServiceAuthorizationHandler struct {
	repo       *storage.TrafficRepository
	packages   *PackageAssignHandler
	managed    *ManagedNodesHandler
	forwarding *ForwardingHandler
}

func NewServiceAuthorizationHandler(repo *storage.TrafficRepository, packages *PackageAssignHandler, managed *ManagedNodesHandler, forwarding *ForwardingHandler) *ServiceAuthorizationHandler {
	if repo == nil || packages == nil || managed == nil || forwarding == nil {
		panic("service authorization handler requires all dependencies")
	}
	// Package switches must use the same reconcilers as the standalone grant
	// endpoints so their remote cleanup and rollback share one mutation lock.
	packages.managed = managed
	packages.forwarding = forwarding
	return &ServiceAuthorizationHandler{repo: repo, packages: packages, managed: managed, forwarding: forwarding}
}

func (h *ServiceAuthorizationHandler) HandleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var request serviceAuthorizationRequest
	if err := decodeServiceAuthorizationJSON(w, r, &request); err != nil {
		return
	}
	if err := h.serveRequest(w, r, request, request.Usernames, true); err != nil {
		writeServiceAuthorizationError(w, err)
	}
}

func (h *ServiceAuthorizationHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		writeServiceAuthorizationError(w, storage.ErrManagedInvalidArgument)
		return
	}
	if r.Method == http.MethodGet {
		h.writeCurrent(w, r, username)
		return
	}
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var request serviceAuthorizationRequest
	if err := decodeServiceAuthorizationJSON(w, r, &request); err != nil {
		return
	}
	if len(request.Usernames) != 0 {
		writeServiceAuthorizationError(w, fmt.Errorf("%w: usernames is only valid for batch requests", storage.ErrManagedInvalidArgument))
		return
	}
	if err := h.serveRequest(w, r, request, []string{username}, false); err != nil {
		writeServiceAuthorizationError(w, err)
	}
}

func decodeServiceAuthorizationJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid request body"})
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid request body"})
		return storage.ErrManagedInvalidArgument
	}
	return nil
}

func (h *ServiceAuthorizationHandler) serveRequest(w http.ResponseWriter, r *http.Request, request serviceAuthorizationRequest, usernames []string, batch bool) error {
	mode, parsedPackage, err := h.validateRequest(r.Context(), &request, usernames)
	if err != nil {
		return err
	}
	actor := managedActor(r)
	results := make([]serviceAuthorizationResult, 0, len(usernames))
	applied := make([]string, 0, len(usernames))
	allSucceeded := true
	for _, username := range usernames {
		var warnings []string
		resultStatus := "applied"
		var packageIDs []int64
		if mode == storage.AuthorizationModePackage && parsedPackage != nil {
			packageIDs = []int64{parsedPackage.packageID}
		}
		err = withStableUserPackageAuthorizationLease(r.Context(), h.repo, username, packageIDs, func(leasedCtx context.Context, _ storage.User) error {
			var applyErr error
			if mode == storage.AuthorizationModePackage {
				warnings, resultStatus, applyErr = h.applyPackage(leasedCtx, username, *parsedPackage, actor)
			} else {
				warnings, resultStatus, applyErr = h.applyCustom(leasedCtx, username, *request.Custom, actor)
			}
			return applyErr
		})
		if err != nil && resultStatus == "applied" {
			resultStatus = "failed"
		}
		result := serviceAuthorizationResult{Username: username, Mode: mode, Status: resultStatus, Warnings: warnings}
		if err != nil {
			allSucceeded = false
			result.Error = err.Error()
		} else {
			applied = append(applied, username)
		}
		results = append(results, result)
	}

	status := http.StatusOK
	if !allSucceeded {
		status = http.StatusMultiStatus
		if !batch && len(results) == 1 {
			status = http.StatusConflict
		}
	}
	response := map[string]any{"success": allSucceeded, "results": results, "applied_users": applied}
	if !batch && len(results) == 1 {
		response["result"] = results[0]
		if results[0].Error != "" {
			response["error"] = results[0].Error
		}
	}
	writeJSON(w, status, response)
	return nil
}
func (h *ServiceAuthorizationHandler) validateRequest(ctx context.Context, request *serviceAuthorizationRequest, usernames []string) (string, *parsedPackageAuthorization, error) {
	mode, err := storage.NormalizeAuthorizationMode(request.Mode)
	if err != nil {
		return "", nil, err
	}
	if len(usernames) == 0 {
		return "", nil, fmt.Errorf("%w: usernames must not be empty", storage.ErrManagedInvalidArgument)
	}
	seenUsers := make(map[string]struct{}, len(usernames))
	for i := range usernames {
		usernames[i] = strings.TrimSpace(usernames[i])
		if usernames[i] == "" {
			return "", nil, fmt.Errorf("%w: username must not be empty", storage.ErrManagedInvalidArgument)
		}
		if _, duplicate := seenUsers[usernames[i]]; duplicate {
			return "", nil, fmt.Errorf("%w: duplicate username %s", storage.ErrManagedInvalidArgument, usernames[i])
		}
		seenUsers[usernames[i]] = struct{}{}
		user, userErr := h.repo.GetUser(ctx, usernames[i])
		if userErr != nil {
			return "", nil, fmt.Errorf("validate user %s: %w", usernames[i], userErr)
		}
		if user.Role == storage.RoleAdmin || storage.IsReservedUsername(user.Username) {
			return "", nil, fmt.Errorf("%w: admin accounts cannot receive service authorization", storage.ErrAuthorizationModeConflict)
		}
	}

	if mode == storage.AuthorizationModePackage {
		if request.Package == nil || request.Custom != nil {
			return "", nil, fmt.Errorf("%w: package mode requires only package", storage.ErrManagedInvalidArgument)
		}
		parsed, parseErr := h.validatePackageRequest(ctx, *request.Package)
		return mode, parsed, parseErr
	}
	if request.Custom == nil || request.Package != nil {
		return "", nil, fmt.Errorf("%w: custom mode requires only custom", storage.ErrManagedInvalidArgument)
	}
	if err := h.validateCustomRequest(ctx, request.Custom); err != nil {
		return "", nil, err
	}
	return mode, nil, nil
}

func (h *ServiceAuthorizationHandler) validatePackageRequest(ctx context.Context, request serviceAuthorizationPackageRequest) (*parsedPackageAuthorization, error) {
	if request.PackageID <= 0 {
		return nil, fmt.Errorf("%w: package_id is required", storage.ErrManagedInvalidArgument)
	}
	pkg, err := h.repo.GetPackage(ctx, request.PackageID)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	if request.StartDate != "" {
		start, err = time.ParseInLocation("2006-01-02", request.StartDate, time.Local)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid start_date", storage.ErrManagedInvalidArgument)
		}
	}
	if start.After(time.Now().Add(time.Minute)) {
		return nil, errInvalidPackageWindow
	}
	expires := start.AddDate(0, 0, pkg.CycleDays)
	if request.ExpireDate != "" {
		expires, err = time.ParseInLocation("2006-01-02", request.ExpireDate, time.Local)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expire_date", storage.ErrManagedInvalidArgument)
		}
	}
	if !expires.After(start) || !expires.After(time.Now()) {
		return nil, errInvalidPackageWindow
	}
	isReset, resetDay := pkg.IsReset, pkg.ResetDay
	if request.IsReset != nil {
		isReset = *request.IsReset
	}
	if request.ResetDay != nil {
		resetDay = *request.ResetDay
	}
	if isReset && resetDay == 0 {
		resetDay = time.Now().Day()
		if resetDay > 28 {
			resetDay = 28
		}
	}
	if isReset && (resetDay < 1 || resetDay > 31) {
		return nil, fmt.Errorf("%w: reset_day must be between 1 and 31", storage.ErrManagedInvalidArgument)
	}
	return &parsedPackageAuthorization{packageID: request.PackageID, startsAt: start, expiresAt: expires, isReset: isReset, resetDay: resetDay}, nil
}

func (h *ServiceAuthorizationHandler) validateCustomRequest(ctx context.Context, request *serviceAuthorizationCustomRequest) error {
	if request.FixedNodeGrants == nil || request.ServerGrants == nil || request.ForwardingGrants == nil {
		return fmt.Errorf("%w: all custom grant arrays must be explicitly present", storage.ErrManagedInvalidArgument)
	}
	now := time.Now().UTC()
	seenNodes := make(map[int64]struct{}, len(*request.FixedNodeGrants))
	for _, grant := range *request.FixedNodeGrants {
		if grant.NodeID <= 0 {
			return fmt.Errorf("%w: invalid fixed node id", storage.ErrManagedInvalidArgument)
		}
		if _, duplicate := seenNodes[grant.NodeID]; duplicate {
			return fmt.Errorf("%w: duplicate fixed node %d", storage.ErrManagedInvalidArgument, grant.NodeID)
		}
		seenNodes[grant.NodeID] = struct{}{}
		node, err := h.repo.GetNodeByID(ctx, grant.NodeID)
		if err != nil {
			return err
		}
		server, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
		if err != nil || !storage.DirectNodeGrantEligible(node, *server) {
			return storage.ErrManagedServerMismatch
		}
		if canonicalManagedProtocol(node.Protocol) == "wireguard" {
			provisionable, provenanceErr := h.repo.ManagedWireGuardNodeProvisionable(ctx, node.ID)
			if provenanceErr != nil {
				return provenanceErr
			}
			if !provisionable {
				return storage.ErrManagedServerMismatch
			}
		}
		if grant.ExpiresAt != nil && !grant.ExpiresAt.After(now) {
			return fmt.Errorf("%w: fixed node expiry must be in the future", storage.ErrManagedInvalidArgument)
		}
	}
	seenServers := make(map[int64]struct{}, len(*request.ServerGrants))
	for _, grant := range *request.ServerGrants {
		if grant.ServerID <= 0 || !grant.Enabled || grant.StartsAt.IsZero() || grant.MaxActiveNodes < 0 ||
			grant.SpeedLimitMbps < 0 || grant.ConnectionLimit < 0 || grant.TrafficLimitBytes < 0 {
			return fmt.Errorf("%w: invalid server grant", storage.ErrManagedInvalidArgument)
		}
		if _, duplicate := seenServers[grant.ServerID]; duplicate {
			return fmt.Errorf("%w: duplicate server %d", storage.ErrManagedInvalidArgument, grant.ServerID)
		}
		seenServers[grant.ServerID] = struct{}{}
		if _, err := h.repo.GetRemoteServer(ctx, grant.ServerID); err != nil {
			return err
		}
		if grant.ExpiresAt != nil && !grant.ExpiresAt.After(grant.StartsAt) {
			return fmt.Errorf("%w: server grant expiry must follow starts_at", storage.ErrManagedInvalidArgument)
		}
		if grant.BillingMode != storage.ManagedBillingDownload && grant.BillingMode != storage.ManagedBillingBoth {
			return fmt.Errorf("%w: invalid server billing_mode", storage.ErrManagedInvalidArgument)
		}
		if grant.ResetPolicy != storage.ManagedResetNone && grant.ResetPolicy != storage.ManagedResetMonthly {
			return fmt.Errorf("%w: invalid server reset_policy", storage.ErrManagedInvalidArgument)
		}
	}
	seenTunnels := make(map[int64]struct{}, len(*request.ForwardingGrants))
	for _, grant := range *request.ForwardingGrants {
		if grant.TunnelID <= 0 || !grant.Enabled || grant.StartsAt.IsZero() || grant.MaxActiveForwards < 0 ||
			grant.PerForwardSpeedMbps != 0 || grant.PerForwardConnectionLimit != 0 || grant.TrafficLimitBytes < 0 || grant.AllowCustomPublicTarget {
			return fmt.Errorf("%w: invalid forwarding grant", storage.ErrForwardingInvalid)
		}
		if _, duplicate := seenTunnels[grant.TunnelID]; duplicate {
			return fmt.Errorf("%w: duplicate tunnel %d", storage.ErrManagedInvalidArgument, grant.TunnelID)
		}
		seenTunnels[grant.TunnelID] = struct{}{}
		if _, err := h.repo.GetTunnelTemplateByID(ctx, grant.TunnelID); err != nil {
			return err
		}
		if grant.ExpiresAt != nil && !grant.ExpiresAt.After(grant.StartsAt) {
			return fmt.Errorf("%w: forwarding grant expiry must follow starts_at", storage.ErrManagedInvalidArgument)
		}
		switch grant.BillingModeOverride {
		case storage.ManagedBillingDownload, storage.ManagedBillingUpload, storage.ManagedBillingBoth:
		default:
			return fmt.Errorf("%w: invalid forwarding billing_mode_override", storage.ErrForwardingInvalid)
		}
	}
	return nil
}

func (h *ServiceAuthorizationHandler) writeCurrent(w http.ResponseWriter, r *http.Request, username string) {
	user, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeServiceAuthorizationError(w, err)
		return
	}
	snapshot, err := h.captureCustomSnapshot(r.Context(), username)
	if err != nil {
		writeServiceAuthorizationError(w, err)
		return
	}
	authorizationMode := user.AuthorizationMode
	if user.PackageID > 0 {
		authorizationMode = storage.AuthorizationModePackage
	}
	response := map[string]any{
		"success":            true,
		"username":           username,
		"authorization_mode": authorizationMode,
		"custom": map[string]any{
			"fixed_node_grants": snapshot.fixed,
			"server_grants":     snapshot.servers,
			"forwarding_grants": snapshot.forwarding,
		},
	}
	if user.PackageID > 0 {
		response["package"] = map[string]any{
			"package_id": user.PackageID, "start_date": user.PackageStartDate,
			"expire_date": user.PackageEndDate, "is_reset": user.IsReset, "reset_day": user.ResetDay,
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *ServiceAuthorizationHandler) captureCustomSnapshot(ctx context.Context, username string) (customAuthorizationSnapshot, error) {
	snapshot := customAuthorizationSnapshot{fixed: []serviceAuthorizationFixedNodeGrant{}, servers: []serviceAuthorizationServerGrant{}, forwarding: []serviceAuthorizationForwardingGrant{}}
	fixed, err := h.repo.ListUserNodeGrants(ctx, username)
	if err != nil {
		return snapshot, err
	}
	for _, item := range fixed {
		if item.Grant.SourceType == storage.GrantSourceManual && item.Source.DesiredState == storage.ManagedDesiredActive {
			snapshot.fixed = append(snapshot.fixed, serviceAuthorizationFixedNodeGrant{NodeID: item.Grant.NodeID, ExpiresAt: item.Source.ExpiresAt})
		}
	}
	servers, err := h.repo.ListUserServerGrants(ctx, username)
	if err != nil {
		return snapshot, err
	}
	for _, grant := range servers {
		if grant.SourceType != storage.GrantSourceManual || !grant.Enabled {
			continue
		}
		snapshot.servers = append(snapshot.servers, serviceAuthorizationServerGrant{
			ServerID: grant.ServerID, Enabled: true, StartsAt: grant.StartsAt, ExpiresAt: grant.ExpiresAt,
			MaxActiveNodes: grant.MaxActiveNodes, SpeedLimitMbps: grant.SpeedLimitMbps,
			ConnectionLimit: grant.ConnectionLimit, TrafficLimitBytes: grant.TrafficLimitBytes,
			BillingMode: grant.BillingMode, ResetPolicy: grant.ResetPolicy, ResetDay: grant.ResetDay,
			AllowedProtocols:        append([]string(nil), grant.AllowedProtocols...),
			AllowedProtocolProfiles: append([]string(nil), grant.AllowedProtocolProfiles...),
		})
	}
	forwarding, err := h.repo.ListUserTunnelGrants(ctx, username)
	if err != nil {
		return snapshot, err
	}
	for _, grant := range forwarding {
		if grant.SourceType != storage.GrantSourceManual || !grant.Enabled || grant.BillingModeOverride == nil {
			continue
		}
		snapshot.forwarding = append(snapshot.forwarding, serviceAuthorizationForwardingGrant{
			TunnelID: grant.TunnelID, Enabled: true, StartsAt: grant.StartsAt, ExpiresAt: grant.ExpiresAt,
			MaxActiveForwards: grant.MaxActiveForwards, PerForwardSpeedMbps: grant.PerForwardSpeedMbps,
			PerForwardConnectionLimit: grant.PerForwardConnectionLimit, TrafficLimitBytes: grant.TrafficLimitBytes,
			BillingModeOverride: *grant.BillingModeOverride, AllowCustomPublicTarget: grant.AllowCustomPublicTarget,
		})
	}
	snapshot.activeChilds, err = h.captureAuthorizationChildState(ctx, username, storage.GrantSourceManual)
	if err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (h *ServiceAuthorizationHandler) captureAuthorizationChildState(ctx context.Context, username, sourceType string) (authorizationChildState, error) {
	state := authorizationChildState{selectionOfferIDs: []int64{}, forwardPublicIDs: []string{}}
	serverGrants, err := h.repo.ListUserServerGrants(ctx, username)
	if err != nil {
		return state, err
	}
	serverGrantIDs := make(map[int64]struct{})
	for _, grant := range serverGrants {
		if grant.SourceType == sourceType {
			serverGrantIDs[grant.ID] = struct{}{}
		}
	}
	selections, err := h.repo.ListUserNodeSelections(ctx, username, true)
	if err != nil {
		return state, err
	}
	for _, selection := range selections {
		if _, ok := serverGrantIDs[selection.GrantID]; ok && selection.DesiredEnabled {
			state.selectionOfferIDs = append(state.selectionOfferIDs, selection.OfferID)
		}
	}

	tunnelGrants, err := h.repo.ListUserTunnelGrants(ctx, username)
	if err != nil {
		return state, err
	}
	tunnelGrantIDs := make(map[int64]struct{})
	for _, grant := range tunnelGrants {
		if grant.SourceType == sourceType {
			tunnelGrantIDs[grant.ID] = struct{}{}
		}
	}
	forwards, err := h.repo.ListUserForwards(ctx, username)
	if err != nil {
		return state, err
	}
	for _, forward := range forwards {
		if _, ok := tunnelGrantIDs[forward.GrantID]; ok && forward.DesiredState == storage.ForwardDesiredActive {
			state.forwardPublicIDs = append(state.forwardPublicIDs, forward.PublicID)
		}
	}
	sort.Slice(state.selectionOfferIDs, func(i, j int) bool { return state.selectionOfferIDs[i] < state.selectionOfferIDs[j] })
	sort.Strings(state.forwardPublicIDs)
	return state, nil
}

func customRequestFromSnapshot(snapshot customAuthorizationSnapshot) serviceAuthorizationCustomRequest {
	fixed := append([]serviceAuthorizationFixedNodeGrant(nil), snapshot.fixed...)
	servers := append([]serviceAuthorizationServerGrant(nil), snapshot.servers...)
	forwarding := append([]serviceAuthorizationForwardingGrant(nil), snapshot.forwarding...)
	return serviceAuthorizationCustomRequest{
		FixedNodeGrants: &fixed, ServerGrants: &servers, ForwardingGrants: &forwarding,
	}
}

func emptyCustomAuthorizationRequest() serviceAuthorizationCustomRequest {
	return customRequestFromSnapshot(customAuthorizationSnapshot{
		fixed: []serviceAuthorizationFixedNodeGrant{}, servers: []serviceAuthorizationServerGrant{}, forwarding: []serviceAuthorizationForwardingGrant{},
	})
}

func (h *ServiceAuthorizationHandler) applyPackage(ctx context.Context, username string, request parsedPackageAuthorization, actor string) ([]string, string, error) {
	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		return nil, "failed", err
	}
	if user.AuthorizationMode == storage.AuthorizationModePackage {
		warnings, err := h.packages.AssignAndProvision(ctx, username, request.packageID, request.startsAt, request.expiresAt, request.isReset, request.resetDay)
		return sortedWarnings(warnings), applyResultStatus(err), err
	}

	snapshot, err := h.captureCustomSnapshot(ctx, username)
	if err != nil {
		return nil, "failed", err
	}
	hadManagedCreations, err := userHasManagedNodeCreations(ctx, h.repo, username)
	if err != nil {
		return nil, "failed", err
	}
	if err := h.repo.PreparePackageAuthorizationTransition(ctx, username); err != nil {
		return nil, "failed", err
	}
	cleanupWarnings := h.reconcileAuthorizationTombstones(ctx, username, storage.GrantSourceManual, actor)
	if len(cleanupWarnings) > 0 {
		if hadManagedCreations {
			return nil, "failed", fmt.Errorf("custom authorization cleanup remains pending: %s", strings.Join(cleanupWarnings, "; "))
		}
		restoreErr := h.restoreCustomAuthorization(ctx, username, snapshot, actor)
		return nil, rollbackResultStatus(restoreErr), errors.Join(fmt.Errorf("custom authorization cleanup is incomplete: %s", strings.Join(cleanupWarnings, "; ")), restoreErr)
	}

	warnings, assignErr := h.packages.AssignAndProvision(ctx, username, request.packageID, request.startsAt, request.expiresAt, request.isReset, request.resetDay)
	if assignErr == nil {
		return sortedWarnings(warnings), "applied", nil
	}
	if hadManagedCreations {
		return nil, "failed", assignErr
	}
	restoreErr := h.restoreCustomAuthorization(ctx, username, snapshot, actor)
	return nil, rollbackResultStatus(restoreErr), errors.Join(assignErr, restoreErr)
}

func (h *ServiceAuthorizationHandler) applyCustom(ctx context.Context, username string, request serviceAuthorizationCustomRequest, actor string) ([]string, string, error) {
	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		return nil, "failed", err
	}
	if user.AuthorizationMode == storage.AuthorizationModePackage {
		if user.PackageID <= 0 {
			// A custom -> package switch can remain in this fail-closed state while
			// manual child cleanup is pending. It is not an assigned package and
			// therefore cannot go through package unbind/restore. Let an operator
			// cancel the transition by first converging those manual tombstones.
			cleanupWarnings := h.reconcileAuthorizationTombstones(ctx, username, storage.GrantSourceManual, actor)
			if len(cleanupWarnings) > 0 {
				return nil, "failed", fmt.Errorf("custom authorization cleanup remains pending: %s", strings.Join(cleanupWarnings, "; "))
			}
			if err := h.repo.CancelPackageAuthorizationTransition(ctx, username); err != nil {
				return nil, "failed", fmt.Errorf("cancel package authorization transition: %w", err)
			}
			cleanupWarnings, provisionWarnings, applyErr := h.applyCustomDesired(ctx, username, request, actor)
			if applyErr == nil && len(cleanupWarnings) == 0 {
				return sortedWarnings(provisionWarnings), "applied", nil
			}
			if applyErr == nil {
				applyErr = fmt.Errorf("custom authorization cleanup remains pending: %s", strings.Join(cleanupWarnings, "; "))
			}
			return nil, "failed", applyErr
		}
		previous := user
		hadManagedCreations, creationErr := userHasManagedNodeCreations(ctx, h.repo, username)
		if creationErr != nil {
			return nil, "failed", creationErr
		}
		packageChildren, snapshotErr := h.captureAuthorizationChildState(ctx, username, storage.GrantSourcePackage)
		if snapshotErr != nil {
			return nil, "failed", snapshotErr
		}
		if err := unbindUserPackageWithOptions(ctx, h.repo, h.packages.remoteManage, h.packages.pusher, username, false); err != nil {
			if hadManagedCreations {
				return nil, "failed", err
			}
			restoreWarnings, restoreErr := h.restorePackageAuthorization(ctx, previous, packageChildren, actor)
			if len(restoreWarnings) > 0 {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("package restore warnings: %s", strings.Join(restoreWarnings, "; ")))
			}
			return nil, rollbackResultStatus(restoreErr), errors.Join(err, restoreErr)
		}
		packageCleanupWarnings := h.reconcileAuthorizationTombstones(ctx, username, storage.GrantSourcePackage, actor)
		if len(packageCleanupWarnings) > 0 {
			if hadManagedCreations {
				return nil, "failed", fmt.Errorf("package authorization cleanup remains pending: %s", strings.Join(packageCleanupWarnings, "; "))
			}
			restoreWarnings, restoreErr := h.restorePackageAuthorization(ctx, previous, packageChildren, actor)
			if len(restoreWarnings) > 0 {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("package restore warnings: %s", strings.Join(restoreWarnings, "; ")))
			}
			cleanupErr := fmt.Errorf("package authorization cleanup is incomplete: %s", strings.Join(packageCleanupWarnings, "; "))
			return nil, rollbackResultStatus(restoreErr), errors.Join(cleanupErr, restoreErr)
		}
		cleanupWarnings, provisionWarnings, applyErr := h.applyCustomDesired(ctx, username, request, actor)
		if applyErr == nil && len(cleanupWarnings) == 0 {
			if cleanupErr := h.deletePackageSubscription(ctx, username); cleanupErr != nil {
				provisionWarnings = append(provisionWarnings, cleanupErr.Error())
			}
			return sortedWarnings(provisionWarnings), "applied", nil
		}
		if hadManagedCreations {
			if applyErr == nil {
				applyErr = fmt.Errorf("custom authorization cleanup remains pending: %s", strings.Join(cleanupWarnings, "; "))
			}
			return nil, "failed", applyErr
		}
		cleanupRestoreWarnings, provisionRestoreWarnings, cleanupRestoreErr := h.applyCustomDesired(ctx, username, emptyCustomAuthorizationRequest(), actor)
		restoreWarnings, restoreErr := h.restorePackageAuthorization(ctx, previous, packageChildren, actor)
		if cleanupRestoreErr != nil || len(cleanupRestoreWarnings) > 0 || len(provisionRestoreWarnings) > 0 {
			restoreErr = errors.Join(restoreErr, cleanupRestoreErr,
				warningsError("custom cleanup rollback warnings", append(cleanupRestoreWarnings, provisionRestoreWarnings...)))
		}
		baseErr := applyErr
		if baseErr == nil {
			baseErr = fmt.Errorf("custom authorization cleanup is incomplete: %s", strings.Join(cleanupWarnings, "; "))
		}
		if len(restoreWarnings) > 0 {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("package restore warnings: %s", strings.Join(restoreWarnings, "; ")))
		}
		return nil, rollbackResultStatus(restoreErr), errors.Join(baseErr, restoreErr)
	}

	snapshot, err := h.captureCustomSnapshot(ctx, username)
	if err != nil {
		return nil, "failed", err
	}
	cleanupWarnings, provisionWarnings, applyErr := h.applyCustomDesired(ctx, username, request, actor)
	if applyErr == nil && len(cleanupWarnings) == 0 {
		return sortedWarnings(provisionWarnings), "applied", nil
	}
	restoreErr := h.restoreCustomAuthorization(ctx, username, snapshot, actor)
	if applyErr == nil {
		applyErr = fmt.Errorf("custom authorization cleanup is incomplete: %s", strings.Join(cleanupWarnings, "; "))
	}
	return nil, rollbackResultStatus(restoreErr), errors.Join(applyErr, restoreErr)
}

func applyResultStatus(err error) string {
	if err != nil {
		return "failed"
	}
	return "applied"
}

func rollbackResultStatus(rollbackErr error) string {
	if rollbackErr != nil {
		return "rollback_failed"
	}
	return "rolled_back"
}

func warningsError(label string, warnings []string) error {
	if len(warnings) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %s", label, strings.Join(warnings, "; "))
}

func (h *ServiceAuthorizationHandler) restorePackageAuthorization(ctx context.Context, previous storage.User, childState authorizationChildState, actor string) ([]string, error) {
	if previous.PackageID <= 0 || previous.PackageStartDate == nil || previous.PackageEndDate == nil {
		return nil, fmt.Errorf("restore package authorization: incomplete package assignment snapshot")
	}
	warnings, err := h.packages.AssignAndProvision(ctx, previous.Username, previous.PackageID,
		*previous.PackageStartDate, *previous.PackageEndDate, previous.IsReset, previous.ResetDay)
	if err != nil {
		return sortedWarnings(warnings), err
	}
	if err := h.repo.UpdateUserTrafficLimitOverride(ctx, previous.Username, previous.TrafficLimitOverride); err != nil {
		return sortedWarnings(warnings), err
	}
	if err := h.restoreAuthorizationChildState(ctx, previous.Username, childState, actor); err != nil {
		return sortedWarnings(warnings), err
	}
	return sortedWarnings(warnings), nil
}

func (h *ServiceAuthorizationHandler) deletePackageSubscription(ctx context.Context, username string) error {
	file, err := h.repo.GetUserPackageSubscription(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read package subscription: %w", err)
	}
	if file.ID <= 0 {
		return nil
	}
	if err := deleteSubscribeFileAndPhysical(ctx, h.repo, "subscribes", file); err != nil {
		return fmt.Errorf("delete package subscription: %w", err)
	}
	return nil
}

func (h *ServiceAuthorizationHandler) restoreCustomAuthorization(ctx context.Context, username string, snapshot customAuthorizationSnapshot, actor string) error {
	if err := h.repo.CancelPackageAuthorizationTransition(ctx, username); err != nil {
		return fmt.Errorf("restore custom authorization mode: %w", err)
	}
	cleanupWarnings, provisionWarnings, err := h.applyCustomDesired(ctx, username, customRequestFromSnapshot(snapshot), actor)
	if childErr := h.restoreAuthorizationChildState(ctx, username, snapshot.activeChilds, actor); childErr != nil {
		err = errors.Join(err, childErr)
	}
	warnings := append(cleanupWarnings, provisionWarnings...)
	if len(warnings) > 0 {
		err = errors.Join(err, fmt.Errorf("restore custom authorization warnings: %s", strings.Join(warnings, "; ")))
	}
	return err
}

func (h *ServiceAuthorizationHandler) restoreAuthorizationChildState(ctx context.Context, username string, state authorizationChildState, actor string) error {
	var restoreErrs []error
	for _, offerID := range state.selectionOfferIDs {
		result, err := h.repo.ActivateUserNodeSelection(ctx, username, offerID, actor, time.Now().UTC())
		if err == nil {
			err = h.managed.reconcileSource(ctx, result.Source)
		}
		if err != nil {
			restoreErrs = append(restoreErrs, fmt.Errorf("restore node selection offer %d: %w", offerID, err))
		}
	}
	for _, publicID := range state.forwardPublicIDs {
		forward, err := h.repo.GetUserForward(ctx, publicID, username)
		if err == nil && (forward.DesiredState != storage.ForwardDesiredActive || forward.ObservedState != storage.ForwardObservedActive) {
			err = h.forwarding.resumeForward(ctx, forward, actor)
		}
		if err != nil {
			restoreErrs = append(restoreErrs, fmt.Errorf("restore forward %s: %w", publicID, err))
		}
	}
	return errors.Join(restoreErrs...)
}

func (h *ServiceAuthorizationHandler) reconcileAuthorizationTombstones(ctx context.Context, username, sourceType, actor string) []string {
	warnings := make([]string, 0)
	fixed, err := h.repo.ListUserNodeGrants(ctx, username)
	if err != nil {
		return []string{err.Error()}
	}
	for _, item := range fixed {
		if item.Grant.SourceType != sourceType || item.Source.DesiredState == storage.ManagedDesiredActive {
			continue
		}
		if err := h.managed.reconcileSource(ctx, item.Source); err != nil {
			warnings = append(warnings, fmt.Sprintf("fixed node %d: %v", item.Grant.NodeID, err))
		}
	}
	servers, err := h.repo.ListUserServerGrants(ctx, username)
	if err != nil {
		warnings = append(warnings, err.Error())
	} else {
		for _, grant := range servers {
			if grant.SourceType != sourceType || grant.Enabled {
				continue
			}
			for _, reconcileErr := range h.managed.syncGrantSources(ctx, grant, actor) {
				warnings = append(warnings, fmt.Sprintf("server %d: %v", grant.ServerID, reconcileErr))
			}
		}
	}
	tunnels, err := h.repo.ListUserTunnelGrants(ctx, username)
	if err != nil {
		warnings = append(warnings, err.Error())
	} else {
		for i := range tunnels {
			if tunnels[i].SourceType == sourceType && !tunnels[i].Enabled {
				for _, suspendErr := range h.suspendGrantForwards(ctx, username, tunnels[i].ID) {
					warnings = append(warnings, fmt.Sprintf("tunnel %d: %v", tunnels[i].TunnelID, suspendErr))
				}
			}
		}
	}
	return sortedWarnings(warnings)
}

func (h *ServiceAuthorizationHandler) suspendGrantForwards(ctx context.Context, username string, grantID int64) []error {
	forwards, err := h.repo.ListUserForwards(ctx, username)
	if err != nil {
		return []error{err}
	}
	errs := make([]error, 0)
	for i := range forwards {
		forward := &forwards[i]
		if forward.GrantID != grantID || forward.DesiredState == storage.ForwardDesiredDeleted {
			continue
		}
		if forward.ObservedState == storage.ForwardObservedSuspended {
			continue
		}
		if forward.DesiredState == storage.ForwardDesiredActive {
			err = h.forwarding.systemSuspendForward(ctx, forward, "grant_inactive")
		} else {
			err = h.forwarding.retryInactiveForwardSuspend(ctx, forward)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("forward %s: %w", forward.PublicID, err))
		}
	}
	return errs
}

func (h *ServiceAuthorizationHandler) applyCustomDesired(ctx context.Context, username string, request serviceAuthorizationCustomRequest, actor string) ([]string, []string, error) {
	cleanupWarnings := make([]string, 0)
	provisionWarnings := make([]string, 0)
	desiredFixed := make(map[int64]serviceAuthorizationFixedNodeGrant, len(*request.FixedNodeGrants))
	for _, grant := range *request.FixedNodeGrants {
		desiredFixed[grant.NodeID] = grant
	}
	desiredServers := make(map[int64]serviceAuthorizationServerGrant, len(*request.ServerGrants))
	for _, grant := range *request.ServerGrants {
		desiredServers[grant.ServerID] = grant
	}
	desiredTunnels := make(map[int64]serviceAuthorizationForwardingGrant, len(*request.ForwardingGrants))
	for _, grant := range *request.ForwardingGrants {
		desiredTunnels[grant.TunnelID] = grant
	}

	fixed, err := h.repo.ListUserNodeGrants(ctx, username)
	if err != nil {
		return nil, nil, err
	}
	for _, item := range fixed {
		if item.Grant.SourceType != storage.GrantSourceManual || item.Source.DesiredState != storage.ManagedDesiredActive {
			continue
		}
		if _, keep := desiredFixed[item.Grant.NodeID]; keep {
			continue
		}
		updated, updateErr := h.repo.SetUserNodeGrantDesiredState(ctx, item.Grant.ID, username, storage.ManagedDesiredInactive, actor)
		if updateErr != nil {
			return cleanupWarnings, provisionWarnings, updateErr
		}
		if reconcileErr := h.managed.reconcileSource(ctx, updated.Source); reconcileErr != nil {
			cleanupWarnings = append(cleanupWarnings, fmt.Sprintf("fixed node %d cleanup: %v", item.Grant.NodeID, reconcileErr))
		}
	}

	servers, err := h.repo.ListUserServerGrants(ctx, username)
	if err != nil {
		return cleanupWarnings, provisionWarnings, err
	}
	for _, grant := range servers {
		if grant.SourceType != storage.GrantSourceManual || !grant.Enabled {
			continue
		}
		if _, keep := desiredServers[grant.ServerID]; keep {
			continue
		}
		disabled := grant
		disabled.Enabled = false
		updated, updateErr := h.repo.UpdateUserServerGrant(ctx, disabled, grant.Version, actor)
		if updateErr != nil {
			return cleanupWarnings, provisionWarnings, updateErr
		}
		for _, reconcileErr := range h.managed.syncGrantSources(ctx, *updated, actor) {
			cleanupWarnings = append(cleanupWarnings, fmt.Sprintf("server %d cleanup: %v", grant.ServerID, reconcileErr))
		}
	}

	tunnels, err := h.repo.ListUserTunnelGrants(ctx, username)
	if err != nil {
		return cleanupWarnings, provisionWarnings, err
	}
	for _, grant := range tunnels {
		if grant.SourceType != storage.GrantSourceManual || !grant.Enabled {
			continue
		}
		if _, keep := desiredTunnels[grant.TunnelID]; keep {
			continue
		}
		disabled := grant
		disabled.Enabled = false
		_, updateErr := h.repo.UpdateUserTunnelGrant(ctx, grant.PublicID, username, disabled, grant.Version, actor)
		if updateErr != nil {
			return cleanupWarnings, provisionWarnings, updateErr
		}
		for _, suspendErr := range h.suspendGrantForwards(ctx, username, grant.ID) {
			cleanupWarnings = append(cleanupWarnings, fmt.Sprintf("tunnel %d cleanup: %v", grant.TunnelID, suspendErr))
		}
	}

	for _, desired := range *request.FixedNodeGrants {
		item, _, upsertErr := h.repo.UpsertManualUserNodeGrant(ctx, username, desired.NodeID, desired.ExpiresAt, actor)
		if upsertErr != nil {
			return cleanupWarnings, provisionWarnings, upsertErr
		}
		if reconcileErr := h.managed.reconcileSource(ctx, item.Source); reconcileErr != nil {
			provisionWarnings = append(provisionWarnings, fmt.Sprintf("fixed node %d remains pending: %v", desired.NodeID, reconcileErr))
		}
	}

	servers, err = h.repo.ListUserServerGrants(ctx, username)
	if err != nil {
		return cleanupWarnings, provisionWarnings, err
	}
	serverExisting := make(map[int64]storage.UserServerGrant, len(servers))
	for _, grant := range servers {
		serverExisting[grant.ServerID] = grant
	}
	for _, desired := range *request.ServerGrants {
		model := storage.UserServerGrant{
			Username: username, ServerID: desired.ServerID, Enabled: true, StartsAt: desired.StartsAt.UTC(), ExpiresAt: desired.ExpiresAt,
			MaxActiveNodes: desired.MaxActiveNodes, SpeedLimitMbps: desired.SpeedLimitMbps,
			ConnectionLimit: desired.ConnectionLimit, TrafficLimitBytes: desired.TrafficLimitBytes,
			BillingMode: desired.BillingMode, ResetPolicy: desired.ResetPolicy, ResetDay: desired.ResetDay,
			BillingTimezone: "Asia/Shanghai", AllowedProtocols: append([]string(nil), desired.AllowedProtocols...),
			AllowedProtocolProfiles: append([]string(nil), desired.AllowedProtocolProfiles...),
			SourceType:              storage.GrantSourceManual, CreatedBy: actor,
		}
		var updated *storage.UserServerGrant
		if existing, exists := serverExisting[desired.ServerID]; exists && existing.SourceType == storage.GrantSourceManual {
			model.ID, model.CreatedBy, model.CreatedAt = existing.ID, existing.CreatedBy, existing.CreatedAt
			updated, err = h.repo.UpdateUserServerGrant(ctx, model, existing.Version, actor)
		} else {
			updated, err = h.repo.CreateUserServerGrant(ctx, model)
		}
		if err != nil {
			return cleanupWarnings, provisionWarnings, err
		}
		for _, reconcileErr := range h.managed.syncGrantSources(ctx, *updated, actor) {
			provisionWarnings = append(provisionWarnings, fmt.Sprintf("server %d remains pending: %v", desired.ServerID, reconcileErr))
		}
	}

	tunnels, err = h.repo.ListUserTunnelGrants(ctx, username)
	if err != nil {
		return cleanupWarnings, provisionWarnings, err
	}
	tunnelExisting := make(map[int64]storage.UserTunnelGrant, len(tunnels))
	for _, grant := range tunnels {
		tunnelExisting[grant.TunnelID] = grant
	}
	for _, desired := range *request.ForwardingGrants {
		billingMode := desired.BillingModeOverride
		model := storage.UserTunnelGrant{
			Username: username, TunnelID: desired.TunnelID, Enabled: true, StartsAt: desired.StartsAt.UTC(), ExpiresAt: desired.ExpiresAt,
			MaxActiveForwards: desired.MaxActiveForwards, PerForwardSpeedMbps: desired.PerForwardSpeedMbps,
			PerForwardConnectionLimit: desired.PerForwardConnectionLimit, TrafficLimitBytes: desired.TrafficLimitBytes,
			BillingModeOverride: &billingMode, AllowManagedTarget: true, AllowCustomPublicTarget: false,
			SourceType: storage.GrantSourceManual, CreatedBy: actor,
		}
		var updated *storage.UserTunnelGrant
		if existing, exists := tunnelExisting[desired.TunnelID]; exists && existing.SourceType == storage.GrantSourceManual {
			updated, err = h.repo.UpdateUserTunnelGrant(ctx, existing.PublicID, username, model, existing.Version, actor)
		} else {
			updated, err = h.repo.CreateUserTunnelGrant(ctx, model)
		}
		if err != nil {
			return cleanupWarnings, provisionWarnings, err
		}
		h.forwarding.reconcileGrantForwards(ctx, updated)
	}
	return sortedWarnings(cleanupWarnings), sortedWarnings(provisionWarnings), nil
}

func writeServiceAuthorizationError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, storage.ErrManagedInvalidArgument), errors.Is(err, storage.ErrInvalidAuthorizationMode),
		errors.Is(err, storage.ErrForwardingInvalid), errors.Is(err, errInvalidPackageWindow):
		status = http.StatusBadRequest
	case errors.Is(err, storage.ErrUserNotFound), errors.Is(err, storage.ErrPackageNotFound),
		errors.Is(err, storage.ErrNodeNotFound), errors.Is(err, storage.ErrRemoteServerNotFound),
		errors.Is(err, storage.ErrTunnelTemplateNotFound):
		status = http.StatusNotFound
	case errors.Is(err, storage.ErrAuthorizationModeConflict), errors.Is(err, storage.ErrManagedAccessConflict),
		errors.Is(err, storage.ErrManagedBillingModeConflict), errors.Is(err, storage.ErrForwardingConflict):
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]any{"success": false, "error": err.Error()})
}

func sortedWarnings(warnings []string) []string {
	if len(warnings) == 0 {
		return nil
	}
	sort.Strings(warnings)
	return warnings
}
