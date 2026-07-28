package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
)

// ForwardingHandler owns the durable, user-authorized forwarding control plane.
// Authentication remains at the router boundary: admin methods require
// RequireAdmin, while user methods require RequireToken.
type ForwardingHandler struct {
	repo            *storage.TrafficRepository
	deployer        ForwardTunnelDeployer
	reconcileMu     sync.Mutex
	reconcileCancel context.CancelFunc
	reconcileWG     sync.WaitGroup
}

func NewForwardingHandler(repo *storage.TrafficRepository, deployer ForwardTunnelDeployer) *ForwardingHandler {
	return &ForwardingHandler{repo: repo, deployer: deployer}
}

// ForwardTunnelSpec is the controller-to-Agent contract. The expiry-guard
// client implements this interface using authenticated /v1/tunnels calls; the
// legacy adapter exists only for compatibility during rolling upgrades.
type ForwardTunnelSpec struct {
	ResourceID   string
	Generation   int64
	ServerID     int64
	Tag          string
	Network      string
	ListenPort   int
	TargetHost   string
	TargetPort   int
	SourceCIDRs  []string
	HardNotAfter *time.Time
	LeaseUntil   time.Time
}

type ForwardTunnelDeployer interface {
	Apply(context.Context, ForwardTunnelSpec) error
	Suspend(context.Context, int64, string, int64) error
	Remove(context.Context, int64, string, int64) error
}

type ForwardTunnelReadiness interface {
	Probe(context.Context, int64) error
}

var ErrForwardTunnelPortInUse = errors.New("managed tunnel port is already in use")
var ErrForwardTunnelCapability = errors.New("managed tunnel capability is unavailable")

const forwardTunnelLeaseDuration = 5 * time.Minute

func (h *ForwardingHandler) SetTunnelDeployer(deployer ForwardTunnelDeployer) {
	h.deployer = deployer
}

type tunnelTemplateRequest struct {
	Name                   string  `json:"name"`
	Description            string  `json:"description"`
	State                  string  `json:"state"`
	BillingMode            string  `json:"billing_mode"`
	TrafficMultiplierMilli int     `json:"traffic_multiplier_milli"`
	MaxTotalForwards       int     `json:"max_total_forwards"`
	PortRangeStart         int     `json:"port_range_start"`
	PortRangeEnd           int     `json:"port_range_end"`
	ServerIDs              []int64 `json:"server_ids"`
	Version                int64   `json:"version"`
}

func (q tunnelTemplateRequest) model(actor string) storage.TunnelTemplate {
	hops := make([]storage.TunnelTemplateHop, len(q.ServerIDs))
	for i, serverID := range q.ServerIDs {
		hops[i] = storage.TunnelTemplateHop{Position: i, ServerID: serverID}
	}
	return storage.TunnelTemplate{
		Name: q.Name, Description: q.Description, State: q.State, Network: storage.ForwardNetworkTCPUDP,
		BillingMode: q.BillingMode, TrafficMultiplierMilli: q.TrafficMultiplierMilli,
		MaxTotalForwards: q.MaxTotalForwards, AllowManagedTarget: true,
		PortRangeStart: q.PortRangeStart, PortRangeEnd: q.PortRangeEnd,
		CreatedBy: actor, Hops: hops,
	}
}

func writeForwardingError(w http.ResponseWriter, err error) {
	status, message := http.StatusInternalServerError, "forwarding operation failed"
	switch {
	case errors.Is(err, storage.ErrForwardingInvalid):
		status, message = http.StatusBadRequest, err.Error()
	case errors.Is(err, storage.ErrTunnelTemplateNotFound), errors.Is(err, storage.ErrTunnelGrantNotFound),
		errors.Is(err, storage.ErrUserForwardNotFound), errors.Is(err, storage.ErrNodeNotFound),
		errors.Is(err, storage.ErrUserNotFound), errors.Is(err, storage.ErrRemoteServerNotFound):
		status, message = http.StatusNotFound, err.Error()
	case errors.Is(err, storage.ErrForwardingConflict), errors.Is(err, storage.ErrForwardingLimit),
		errors.Is(err, storage.ErrRemoteInstallationActive), errors.Is(err, storage.ErrUserDeletionPending):
		status, message = http.StatusConflict, err.Error()
	case errors.Is(err, storage.ErrForwardingForbidden):
		status, message = http.StatusForbidden, err.Error()
	case errors.Is(err, ErrForwardTunnelCapability):
		status, message = http.StatusUnprocessableEntity, err.Error()
	}
	writeJSON(w, status, map[string]any{"success": false, "error": message})
}

func decodeForwardingJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid request body"})
		return false
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid request body"})
		return false
	}
	return true
}

// HandleAdminTunnelTemplates handles GET/POST /api/admin/tunnel-templates.
func (h *ForwardingHandler) HandleAdminTunnelTemplates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := h.repo.ListTunnelTemplates(r.Context())
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "tunnels": items})
	case http.MethodPost:
		var req tunnelTemplateRequest
		if !decodeForwardingJSON(w, r, &req) {
			return
		}
		ctx, release, err := h.acquireTemplateMutationLeases(r.Context(), req.ServerIDs)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		defer release()
		if err := h.probeTunnelServerCapabilities(ctx, req.ServerIDs); err != nil {
			writeForwardingError(w, err)
			return
		}
		item, err := h.repo.CreateTunnelTemplate(ctx, req.model(managedActor(r)))
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"success": true, "tunnel": item})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// HandleAdminTunnelTemplate handles GET/PUT/DELETE /api/admin/tunnel-templates/{id}.
func (h *ForwardingHandler) HandleAdminTunnelTemplate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeForwardingError(w, storage.ErrForwardingInvalid)
		return
	}
	switch r.Method {
	case http.MethodGet:
		item, err := h.repo.GetTunnelTemplate(r.Context(), id)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "tunnel": item})
	case http.MethodPut:
		var req tunnelTemplateRequest
		if !decodeForwardingJSON(w, r, &req) {
			return
		}
		ctx, release, err := h.acquireTemplateMutationLeases(r.Context(), req.ServerIDs)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		defer release()
		if err := h.probeTunnelServerCapabilities(ctx, req.ServerIDs); err != nil {
			writeForwardingError(w, err)
			return
		}
		item, err := h.repo.UpdateTunnelTemplate(ctx, id, req.model(managedActor(r)), req.Version, managedActor(r))
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "tunnel": item})
	case http.MethodDelete:
		if err := h.repo.DeleteTunnelTemplate(r.Context(), id, managedActor(r)); err != nil {
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *ForwardingHandler) acquireTemplateMutationLeases(ctx context.Context, serverIDs []int64) (context.Context, func(), error) {
	unique := make(map[int64]struct{}, len(serverIDs))
	for _, serverID := range serverIDs {
		if serverID <= 0 {
			return nil, func() {}, storage.ErrForwardingInvalid
		}
		unique[serverID] = struct{}{}
	}
	ordered := make([]int64, 0, len(unique))
	for serverID := range unique {
		ordered = append(ordered, serverID)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	leasedCtx := ctx
	releases := make([]func(), 0, len(ordered))
	releaseAll := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	for _, serverID := range ordered {
		nextCtx, release, err := h.repo.AcquireRemoteServerMutationLease(leasedCtx, serverID)
		if err != nil {
			releaseAll()
			return nil, func() {}, err
		}
		leasedCtx = nextCtx
		releases = append(releases, release)
	}
	return leasedCtx, releaseAll, nil
}

// HandleAdminTunnelTemplatePreflight validates an ordered route without writing it.
func (h *ForwardingHandler) HandleAdminTunnelTemplatePreflight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req tunnelTemplateRequest
	if !decodeForwardingJSON(w, r, &req) {
		return
	}
	if len(req.ServerIDs) < 1 || len(req.ServerIDs) > 8 {
		writeForwardingError(w, storage.ErrForwardingInvalid)
		return
	}
	seen := map[int64]bool{}
	servers := make([]map[string]any, 0, len(req.ServerIDs))
	for _, id := range req.ServerIDs {
		if id <= 0 || seen[id] {
			writeForwardingError(w, storage.ErrForwardingInvalid)
			return
		}
		seen[id] = true
		server, err := h.repo.GetRemoteServer(r.Context(), id)
		if err != nil || server == nil {
			writeForwardingError(w, storage.ErrForwardingInvalid)
			return
		}
		host := strings.TrimSpace(server.IPAddress)
		if _, parseErr := netip.ParseAddr(host); parseErr != nil {
			host = strings.TrimSpace(server.IPAddressV6)
		}
		_, hostErr := netip.ParseAddr(host)
		if server.IsFederated || hostErr != nil ||
			!server.XrayRunning || (server.Status != "online" && server.Status != "connected") {
			writeForwardingError(w, storage.ErrForwardingInvalid)
			return
		}
		servers = append(servers, map[string]any{"id": server.ID, "name": server.Name, "status": server.Status, "ready": true})
	}
	if err := h.probeTunnelServerCapabilities(r.Context(), req.ServerIDs); err != nil {
		writeForwardingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "network": storage.ForwardNetworkTCPUDP, "servers": servers})
}

func (h *ForwardingHandler) probeTunnelServerCapabilities(ctx context.Context, serverIDs []int64) error {
	readiness, ok := h.deployer.(ForwardTunnelReadiness)
	if !ok || readiness == nil {
		return ErrForwardTunnelCapability
	}
	for _, serverID := range serverIDs {
		server, err := h.repo.GetRemoteServer(ctx, serverID)
		if err != nil || server == nil {
			return fmt.Errorf("%w: server %d is unavailable", ErrForwardTunnelCapability, serverID)
		}
		address, err := netip.ParseAddr(strings.TrimSpace(server.IPAddress))
		if err != nil || !address.Is4() {
			return fmt.Errorf("%w: server %d requires an IPv4 address", ErrForwardTunnelCapability, serverID)
		}
		if err := readiness.Probe(ctx, serverID); err != nil {
			return fmt.Errorf("%w: server %d: %v", ErrForwardTunnelCapability, serverID, err)
		}
	}
	return nil
}

func (h *ForwardingHandler) HandleAdminTunnelTemplateState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		State   string `json:"state"`
		Version int64  `json:"version"`
	}
	if !decodeForwardingJSON(w, r, &req) {
		return
	}
	item, err := h.repo.SetTunnelTemplateState(r.Context(), strings.TrimSpace(r.PathValue("id")), req.State, req.Version, managedActor(r))
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	h.reconcileForwards(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "tunnel": item})
}

type tunnelGrantRequest struct {
	TunnelID                  string     `json:"tunnel_id"`
	Enabled                   *bool      `json:"enabled"`
	StartsAt                  *time.Time `json:"starts_at"`
	ExpiresAt                 *time.Time `json:"expires_at"`
	MaxActiveForwards         int        `json:"max_active_forwards"`
	PerForwardSpeedMbps       float64    `json:"per_forward_speed_mbps"`
	PerForwardConnectionLimit int        `json:"per_forward_connection_limit"`
	TrafficLimitBytes         int64      `json:"traffic_limit_bytes"`
	BillingModeOverride       *string    `json:"billing_mode_override"`
	AllowCustomPublicTarget   bool       `json:"allow_custom_public_target"`
	Version                   int64      `json:"version"`
}

func (h *ForwardingHandler) grantModel(ctx context.Context, username string, req tunnelGrantRequest, existing *storage.UserTunnelGrant, actor string) (storage.UserTunnelGrant, error) {
	var tunnelID int64
	if existing != nil {
		tunnelID = existing.TunnelID
	} else {
		t, err := h.repo.GetTunnelTemplate(ctx, req.TunnelID)
		if err != nil {
			return storage.UserTunnelGrant{}, err
		}
		tunnelID = t.ID
	}
	// Limiter support for raw tunnel inbounds is not present in the current Agent;
	// reject non-zero limits instead of claiming they are enforced.
	if req.PerForwardSpeedMbps != 0 || req.PerForwardConnectionLimit != 0 || req.AllowCustomPublicTarget {
		return storage.UserTunnelGrant{}, storage.ErrForwardingInvalid
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	}
	starts := time.Now().UTC()
	if req.StartsAt != nil {
		starts = req.StartsAt.UTC()
	} else if existing != nil {
		starts = existing.StartsAt
	}
	return storage.UserTunnelGrant{
		Username: username, TunnelID: tunnelID, Enabled: enabled, StartsAt: starts,
		ExpiresAt: req.ExpiresAt, MaxActiveForwards: req.MaxActiveForwards,
		PerForwardSpeedMbps:       req.PerForwardSpeedMbps,
		PerForwardConnectionLimit: req.PerForwardConnectionLimit,
		TrafficLimitBytes:         req.TrafficLimitBytes, BillingModeOverride: req.BillingModeOverride,
		AllowManagedTarget: true, CreatedBy: actor,
	}, nil
}

// HandleAdminUserTunnelGrants handles GET/POST /api/admin/users/{username}/tunnel-grants.
func (h *ForwardingHandler) HandleAdminUserTunnelGrants(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PathValue("username"))
	if username == "" {
		writeForwardingError(w, storage.ErrForwardingInvalid)
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := h.repo.ListUserTunnelGrants(r.Context(), username)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "grants": items})
	case http.MethodPost:
		var req tunnelGrantRequest
		if !decodeForwardingJSON(w, r, &req) {
			return
		}
		model, err := h.grantModel(r.Context(), username, req, nil, managedActor(r))
		if err == nil {
			_, err = h.repo.GetUser(r.Context(), username)
		}
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		item, err := h.repo.CreateUserTunnelGrant(r.Context(), model)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"success": true, "grant": item})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// HandleAdminUserTunnelGrant handles PUT/DELETE /api/admin/users/{username}/tunnel-grants/{id}.
func (h *ForwardingHandler) HandleAdminUserTunnelGrant(w http.ResponseWriter, r *http.Request) {
	username, id := strings.TrimSpace(r.PathValue("username")), strings.TrimSpace(r.PathValue("id"))
	if username == "" || id == "" {
		writeForwardingError(w, storage.ErrForwardingInvalid)
		return
	}
	current, err := h.repo.GetUserTunnelGrant(r.Context(), id, username)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req tunnelGrantRequest
		if !decodeForwardingJSON(w, r, &req) {
			return
		}
		model, err := h.grantModel(r.Context(), username, req, current, managedActor(r))
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		item, err := h.repo.UpdateUserTunnelGrant(r.Context(), id, username, model, req.Version, managedActor(r))
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		h.reconcileGrantForwards(r.Context(), item)
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "grant": item})
	case http.MethodDelete:
		if err := h.repo.DeleteUserTunnelGrant(r.Context(), id, username, managedActor(r)); err != nil {
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *ForwardingHandler) HandleAdminUserTunnelGrantAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	username, id := strings.TrimSpace(r.PathValue("username")), strings.TrimSpace(r.PathValue("id"))
	action := strings.TrimSpace(r.PathValue("action"))
	if username == "" || id == "" || (action != "suspend" && action != "resume") {
		writeForwardingError(w, storage.ErrForwardingInvalid)
		return
	}
	current, err := h.repo.GetUserTunnelGrant(r.Context(), id, username)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	var body struct {
		Version int64 `json:"version"`
	}
	if r.ContentLength != 0 && !decodeForwardingJSON(w, r, &body) {
		return
	}
	if body.Version == 0 {
		body.Version = current.Version
	}
	model := *current
	model.Enabled = action == "resume"
	item, err := h.repo.UpdateUserTunnelGrant(r.Context(), id, username, model, body.Version, managedActor(r))
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	if action == "suspend" {
		forwards, _ := h.repo.ListUserForwards(r.Context(), username)
		for i := range forwards {
			if forwards[i].GrantID == current.ID && forwards[i].DesiredState == storage.ForwardDesiredActive {
				_ = h.systemSuspendForward(r.Context(), &forwards[i], "grant_inactive")
			}
		}
	} else {
		h.reconcileGrantForwards(r.Context(), item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "grant": item})
}

func (h *ForwardingHandler) reconcileGrantForwards(ctx context.Context, grant *storage.UserTunnelGrant) {
	if grant == nil || h.deployer == nil {
		return
	}
	grants, err := h.repo.ListUserTunnelGrants(ctx, grant.Username)
	if err != nil {
		return
	}
	state := ""
	for _, item := range grants {
		if item.ID == grant.ID {
			state = item.State
			break
		}
	}
	forwards, err := h.repo.ListUserForwards(ctx, grant.Username)
	if err != nil {
		return
	}
	for i := range forwards {
		forward := &forwards[i]
		if forward.GrantID != grant.ID || forward.DesiredState != storage.ForwardDesiredActive {
			continue
		}
		if state != "active" && state != "tunnel_draining" {
			if forward.ObservedState != storage.ForwardObservedSuspended || forward.SuspendReason != "grant_inactive" {
				_ = h.systemSuspendForward(ctx, forward, "grant_inactive")
			}
			continue
		}
		candidate := forward
		if forward.ObservedState != storage.ForwardObservedActive {
			candidate, err = h.repo.PrepareUserForwardSystemApply(ctx, forward.PublicID, forward.Username)
		}
		if err == nil {
			_ = h.deployForward(ctx, candidate)
		}
	}
}

type userTunnelGrantResponse struct {
	ID                     string     `json:"id"`
	TunnelID               string     `json:"tunnel_id"`
	Name                   string     `json:"name"`
	TunnelName             string     `json:"tunnel_name"`
	Description            string     `json:"description"`
	State                  string     `json:"state"`
	Route                  []string   `json:"route"`
	StartsAt               time.Time  `json:"starts_at"`
	ExpiresAt              *time.Time `json:"expires_at,omitempty"`
	MaxActiveForwards      int        `json:"max_active_forwards"`
	ActiveForwardCount     int        `json:"active_forward_count"`
	TrafficLimitBytes      int64      `json:"traffic_limit_bytes"`
	UsedBytes              int64      `json:"used_bytes"`
	BillingMode            string     `json:"billing_mode"`
	TrafficMultiplierMilli int        `json:"traffic_multiplier_milli"`
}

func userGrantResponse(g storage.UserTunnelGrant) userTunnelGrantResponse {
	out := userTunnelGrantResponse{ID: g.PublicID, State: g.State, StartsAt: g.StartsAt, ExpiresAt: g.ExpiresAt, MaxActiveForwards: g.MaxActiveForwards, ActiveForwardCount: g.ActiveForwardCount, TrafficLimitBytes: g.TrafficLimitBytes, UsedBytes: g.UsedBytes}
	if g.Tunnel != nil {
		out.TunnelID, out.Name, out.TunnelName, out.Description = g.Tunnel.PublicID, g.Tunnel.Name, g.Tunnel.Name, g.Tunnel.Description
		out.BillingMode, out.TrafficMultiplierMilli = g.Tunnel.BillingMode, g.Tunnel.TrafficMultiplierMilli
		if g.BillingModeOverride != nil {
			out.BillingMode = *g.BillingModeOverride
		}
		for _, hop := range g.Tunnel.Hops {
			out.Route = append(out.Route, hop.ServerName)
		}
	}
	return out
}

// HandleUserTunnelGrants handles GET /api/user/tunnel-grants.
func (h *ForwardingHandler) HandleUserTunnelGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	username := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	items, err := h.repo.ListUserTunnelGrants(r.Context(), username)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	out := make([]userTunnelGrantResponse, 0, len(items))
	for _, item := range items {
		out = append(out, userGrantResponse(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "grants": out})
}

type createForwardRequest struct {
	GrantID            string   `json:"grant_id"`
	Name               string   `json:"name"`
	Network            string   `json:"network"`
	RequestedEntryPort int      `json:"requested_entry_port"`
	SourceCIDRs        []string `json:"source_cidrs"`
	Target             struct {
		Type   string `json:"type"`
		NodeID int64  `json:"node_id"`
	} `json:"target"`
}

type userForwardResponse struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	GrantID            string     `json:"grant_id"`
	TargetNodeID       int64      `json:"target_node_id"`
	TargetName         string     `json:"target_name,omitempty"`
	Network            string     `json:"network"`
	EntryHost          string     `json:"entry_host,omitempty"`
	EntryPort          int        `json:"entry_port"`
	RequestedEntryPort int        `json:"requested_entry_port"`
	DesiredState       string     `json:"desired_state"`
	ObservedState      string     `json:"observed_state"`
	SuspendReason      string     `json:"suspend_reason"`
	EffectiveExpiresAt *time.Time `json:"effective_expires_at,omitempty"`
	LastErrorCode      string     `json:"last_error_code,omitempty"`
	Route              []string   `json:"route"`
	SourceCIDRs        []string   `json:"source_cidrs"`
	UplinkBytes        int64      `json:"uplink_bytes"`
	DownlinkBytes      int64      `json:"downlink_bytes"`
	BilledBytes        int64      `json:"billed_bytes"`
	CreatedAt          time.Time  `json:"created_at"`
}

func (h *ForwardingHandler) userForwardDTO(ctx context.Context, f storage.UserForwardRule) userForwardResponse {
	out := userForwardResponse{ID: f.PublicID, Name: f.Name, TargetNodeID: f.TargetNodeID, Network: f.Network, SourceCIDRs: f.SourceCIDRs, EntryPort: f.AllocatedEntryPort, RequestedEntryPort: f.RequestedEntryPort, DesiredState: f.DesiredState, ObservedState: f.ObservedState, SuspendReason: f.SuspendReason, EffectiveExpiresAt: f.EffectiveExpiresAt, LastErrorCode: f.LastErrorCode, CreatedAt: f.CreatedAt}
	if g, err := h.repo.GetUserTunnelGrantByID(ctx, f.GrantID); err == nil {
		out.GrantID = g.PublicID
	}
	if n, err := h.repo.GetNodeByID(ctx, f.TargetNodeID); err == nil {
		out.TargetName = n.NodeName
	}
	for _, hop := range f.Hops {
		out.Route = append(out.Route, hop.ServerName)
	}
	if usage, err := h.repo.GetUserForwardUsage(ctx, f.ID); err == nil {
		out.UplinkBytes, out.DownlinkBytes = usage.UplinkBytes, usage.DownlinkBytes
		out.BilledBytes = usage.DownlinkBytes
		if f.BillingModeSnapshot == storage.ManagedBillingBoth {
			out.BilledBytes += usage.UplinkBytes
		}
		out.BilledBytes = out.BilledBytes * int64(f.TrafficMultiplierMilliSnapshot) / 1000
	}
	if len(f.Hops) > 0 {
		if s, err := h.repo.GetRemoteServer(ctx, f.Hops[0].ServerID); err == nil && s != nil {
			out.EntryHost = serverEntryHost(s)
		}
	}
	if f.ObservedState != storage.ForwardObservedActive {
		out.EntryHost = ""
	}
	return out
}

func (h *ForwardingHandler) resolveManagedForwardTarget(ctx context.Context, username string, nodeID int64) (storage.Node, string, int, *time.Time, error) {
	if !hasEffectiveManagedNodeAccess(ctx, h.repo, username, nodeID) {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingForbidden
	}
	raw, err := h.repo.GetNodeByID(ctx, nodeID)
	if err != nil || !raw.Enabled || (raw.NodeType != "" && raw.NodeType != "physical") ||
		strings.TrimSpace(raw.OriginalServer) == "" || strings.TrimSpace(raw.InboundTag) == "" {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingForbidden
	}
	userNodes := substituteNodesForUser(ctx, h.repo, username, []storage.Node{raw})
	if len(userNodes) != 1 || userNodes[0].ID != nodeID {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingForbidden
	}
	node := userNodes[0]
	if node.NodeType != "" && node.NodeType != "physical" {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingInvalid
	}
	_, port, ok := clashConfigServerPort(node.ClashConfig)
	if !ok {
		_, port, ok = clashConfigServerPort(node.ParsedConfig)
	}
	if !ok || port < 1 || port > 65535 {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingInvalid
	}
	serverByName, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
	if err != nil || serverByName == nil {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingInvalid
	}
	server, err := h.repo.GetRemoteServer(ctx, serverByName.ID)
	if err != nil || server == nil || server.IsFederated || !server.XrayRunning ||
		(server.Status != "online" && server.Status != "connected") {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingInvalid
	}
	if _, err := h.repo.GetFederatedServer(ctx, server.ID); err == nil || !errors.Is(err, storage.ErrFederatedServerNotFound) {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingInvalid
	}
	host := strings.TrimSpace(server.IPAddress)
	if _, err := netip.ParseAddr(host); err != nil {
		host = strings.TrimSpace(server.IPAddressV6)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingInvalid
	}
	hasAccess, expiry, err := h.repo.HasEffectiveUserInboundAccess(ctx, username, server.ID, node.InboundTag, 0, time.Now().UTC())
	if err != nil || !hasAccess {
		return storage.Node{}, "", 0, nil, storage.ErrForwardingForbidden
	}
	return node, host, port, expiry, nil
}

func earlierForwardExpiry(left, right *time.Time) *time.Time {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	if right.Before(*left) {
		value := right.UTC()
		return &value
	}
	value := left.UTC()
	return &value
}

func validateCreateForwardRequest(req createForwardRequest) error {
	if strings.TrimSpace(req.GrantID) == "" || strings.TrimSpace(req.Name) == "" || req.Target.NodeID <= 0 {
		return storage.ErrForwardingInvalid
	}
	switch strings.ToLower(strings.TrimSpace(req.Network)) {
	case "", "tcp", "tcp_udp", "tcp,udp":
	default:
		return storage.ErrForwardingInvalid
	}
	if req.RequestedEntryPort != 0 && (req.RequestedEntryPort < 1024 || req.RequestedEntryPort > 65535) {
		return storage.ErrForwardingInvalid
	}
	if req.Target.Type != "" && req.Target.Type != "managed_node" {
		return storage.ErrForwardingForbidden
	}
	return nil
}

func validateRequestedForwardPort(port int, tunnel *storage.TunnelTemplate) error {
	if port == 0 {
		return nil
	}
	if tunnel == nil || port < tunnel.PortRangeStart || port > tunnel.PortRangeEnd {
		return storage.ErrForwardingInvalid
	}
	return nil
}

func normalizeForwardSourceCIDRs(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, storage.ErrForwardingInvalid
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var prefix netip.Prefix
		var err error
		if strings.Contains(raw, "/") {
			prefix, err = netip.ParsePrefix(raw)
		} else {
			var address netip.Addr
			address, err = netip.ParseAddr(raw)
			if err == nil {
				address = address.Unmap()
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
		}
		if err != nil {
			return nil, storage.ErrForwardingInvalid
		}
		address := prefix.Addr().Unmap()
		if address.Is4() && prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, storage.ErrForwardingInvalid
			}
			prefix = netip.PrefixFrom(address, prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		address = prefix.Addr()
		if prefix.Bits() == 0 || !address.IsGlobalUnicast() || address.IsUnspecified() || address.IsMulticast() {
			return nil, storage.ErrForwardingInvalid
		}
		seen[prefix.String()] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

// HandleUserForwardPreflight validates a user request without reserving ports.
func (h *ForwardingHandler) HandleUserForwardPreflight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req createForwardRequest
	if !decodeForwardingJSON(w, r, &req) {
		return
	}
	if err := validateCreateForwardRequest(req); err != nil {
		writeForwardingError(w, err)
		return
	}
	sourceCIDRs, err := normalizeForwardSourceCIDRs(req.SourceCIDRs)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	username := auth.UsernameFromContext(r.Context())
	g, err := h.repo.GetUserTunnelGrant(r.Context(), req.GrantID, username)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	grants, err := h.repo.ListUserTunnelGrants(r.Context(), username)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	state := ""
	for _, item := range grants {
		if item.ID == g.ID {
			state = item.State
		}
	}
	if state != "active" {
		writeForwardingError(w, storage.ErrForwardingForbidden)
		return
	}
	tunnel, err := h.repo.GetTunnelTemplateByID(r.Context(), g.TunnelID)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	if err := validateRequestedForwardPort(req.RequestedEntryPort, tunnel); err != nil {
		writeForwardingError(w, err)
		return
	}
	node, host, port, _, err := h.resolveManagedForwardTarget(r.Context(), username, req.Target.NodeID)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "network": storage.ForwardNetworkTCPUDP, "requested_entry_port": req.RequestedEntryPort, "source_cidrs": sourceCIDRs, "target": map[string]any{"node_id": node.ID, "name": node.NodeName, "host": host, "port": port}, "tunnel": userGrantResponse(func() storage.UserTunnelGrant {
		for _, v := range grants {
			if v.ID == g.ID {
				return v
			}
		}
		return *g
	}())})
}

// HandleUserForwards handles GET/POST /api/user/forwards.
func (h *ForwardingHandler) HandleUserForwards(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := h.repo.ListUserForwards(r.Context(), username)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		out := make([]userForwardResponse, 0, len(items))
		for _, item := range items {
			out = append(out, h.userForwardDTO(r.Context(), item))
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "forwards": out})
	case http.MethodPost:
		var req createForwardRequest
		if !decodeForwardingJSON(w, r, &req) {
			return
		}
		if err := validateCreateForwardRequest(req); err != nil {
			writeForwardingError(w, err)
			return
		}
		sourceCIDRs, err := normalizeForwardSourceCIDRs(req.SourceCIDRs)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		g, err := h.repo.GetUserTunnelGrant(r.Context(), req.GrantID, username)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		tunnel, err := h.repo.GetTunnelTemplateByID(r.Context(), g.TunnelID)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		if err := validateRequestedForwardPort(req.RequestedEntryPort, tunnel); err != nil {
			writeForwardingError(w, err)
			return
		}
		leaseHops := make([]storage.UserForwardHop, 0, len(tunnel.Hops))
		for _, hop := range tunnel.Hops {
			leaseHops = append(leaseHops, storage.UserForwardHop{ServerID: hop.ServerID})
		}
		leasedContext, release, err := h.acquireForwardLeases(r.Context(), leaseHops)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		defer release()
		node, host, port, expiry, err := h.resolveManagedForwardTarget(leasedContext, username, req.Target.NodeID)
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		expiry = earlierForwardExpiry(expiry, g.ExpiresAt)
		f, err := h.repo.CreateUserForward(leasedContext, storage.CreateUserForwardInput{Username: username, Name: req.Name, GrantPublicID: req.GrantID, TargetNodeID: node.ID, TargetHost: host, TargetPort: port, RequestedEntryPort: req.RequestedEntryPort, SourceCIDRs: sourceCIDRs, TunnelVersion: tunnel.Version, EffectiveExpiresAt: expiry, Actor: username})
		if err != nil {
			writeForwardingError(w, err)
			return
		}
		if err = h.deployForward(leasedContext, f); err != nil {
			payload := map[string]any{"success": false, "error": "forward deployment failed"}
			if latest, readErr := h.repo.GetUserForward(leasedContext, f.PublicID, username); readErr == nil && latest != nil {
				payload["forward"] = h.userForwardDTO(leasedContext, *latest)
			}
			status := http.StatusBadGateway
			if errors.Is(err, ErrForwardTunnelPortInUse) && req.RequestedEntryPort > 0 {
				status = http.StatusConflict
				payload["error"] = fmt.Sprintf("requested port %d is already in use", req.RequestedEntryPort)
			}
			writeJSON(w, status, payload)
			return
		}
		latest, err := h.repo.GetUserForward(leasedContext, f.PublicID, username)
		if err != nil || latest == nil {
			if err == nil {
				err = storage.ErrUserForwardNotFound
			}
			writeForwardingError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"success": true, "forward": h.userForwardDTO(leasedContext, *latest)})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// HandleAdminForwards handles GET /api/admin/forwards.
func (h *ForwardingHandler) HandleAdminForwards(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := h.repo.ListUserForwards(r.Context(), strings.TrimSpace(r.URL.Query().Get("username")))
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "forwards": items})
}

// HandleUserForward and HandleAdminForward dispatch item actions by the final path segment.
func (h *ForwardingHandler) HandleUserForward(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	h.handleForwardItem(w, r, strings.TrimSpace(username), false)
}
func (h *ForwardingHandler) HandleAdminForward(w http.ResponseWriter, r *http.Request) {
	h.handleForwardItem(w, r, "", true)
}

func (h *ForwardingHandler) handleForwardItem(w http.ResponseWriter, r *http.Request, username string, admin bool) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeForwardingError(w, storage.ErrForwardingInvalid)
		return
	}
	f, err := h.repo.GetUserForward(r.Context(), id, username)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	action := strings.TrimSpace(r.PathValue("action"))
	if action == "" && r.Method == http.MethodGet {
		if admin {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "forward": f})
		} else {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "forward": h.userForwardDTO(r.Context(), *f)})
		}
		return
	}
	if r.Method == http.MethodDelete {
		action = "delete"
	}
	if action == "client-config" && (r.Method == http.MethodGet || r.Method == http.MethodPost) {
		h.writeForwardClientConfig(w, r, f, username)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	actor := username
	if admin {
		actor = managedActor(r)
	}
	switch action {
	case "suspend":
		err = h.suspendForward(r.Context(), f, actor)
	case "resume", "retry":
		err = h.resumeForward(r.Context(), f, actor)
	case "delete", "force-cleanup":
		err = h.deleteForward(r.Context(), f, actor)
	default:
		writeJSONError(w, http.StatusNotFound, "unknown forwarding action")
		return
	}
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	latest, err := h.repo.GetUserForward(r.Context(), id, username)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	if admin {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "forward": latest})
	} else {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "forward": h.userForwardDTO(r.Context(), *latest)})
	}
}

func (h *ForwardingHandler) writeForwardClientConfig(w http.ResponseWriter, r *http.Request, f *storage.UserForwardRule, username string) {
	if f.ObservedState != storage.ForwardObservedActive {
		writeForwardingError(w, storage.ErrForwardingForbidden)
		return
	}
	node, _, _, _, err := h.resolveManagedForwardTarget(r.Context(), f.Username, f.TargetNodeID)
	if err != nil {
		writeForwardingError(w, err)
		return
	}
	entry := h.userForwardDTO(r.Context(), *f)
	if entry.EntryHost == "" {
		writeForwardingError(w, storage.ErrForwardingForbidden)
		return
	}
	cfg := setClashConfigServerPort(node.ClashConfig, entry.EntryHost, entry.EntryPort)
	var out any
	if json.Unmarshal([]byte(cfg), &out) != nil {
		out = cfg
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "config": out})
}

func (h *ForwardingHandler) acquireForwardLeases(ctx context.Context, hops []storage.UserForwardHop) (context.Context, func(), error) {
	ids := make([]int64, 0, len(hops))
	seen := map[int64]bool{}
	for _, hop := range hops {
		if !seen[hop.ServerID] {
			seen[hop.ServerID] = true
			ids = append(ids, hop.ServerID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	leased := ctx
	releases := []func(){}
	releaseAll := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	for _, id := range ids {
		next, release, err := h.repo.AcquireRemoteServerExclusiveMutationLease(leased, id)
		if err != nil {
			releaseAll()
			return nil, func() {}, err
		}
		leased = next
		releases = append(releases, release)
	}
	return leased, releaseAll, nil
}

func (h *ForwardingHandler) tunnelSpec(ctx context.Context, f *storage.UserForwardRule, index int) (ForwardTunnelSpec, error) {
	if h.deployer == nil || index < 0 || index >= len(f.Hops) {
		return ForwardTunnelSpec{}, errors.New("managed tunnel deployer is unavailable")
	}
	hop := f.Hops[index]
	spec := ForwardTunnelSpec{
		ResourceID: hop.ResourceID, Generation: hop.Generation, ServerID: hop.ServerID,
		Tag: hop.ResourceTag, Network: f.Network, ListenPort: hop.ListenPort, TargetHost: hop.NextHost,
		TargetPort: hop.NextPort, HardNotAfter: f.EffectiveExpiresAt,
		LeaseUntil: time.Now().UTC().Add(forwardTunnelLeaseDuration),
	}
	if spec.HardNotAfter == nil {
		perpetual := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
		spec.HardNotAfter = &perpetual
	}
	if index == 0 {
		spec.SourceCIDRs = append([]string(nil), f.SourceCIDRs...)
	}
	if index > 0 {
		previous, err := h.repo.GetRemoteServer(ctx, f.Hops[index-1].ServerID)
		if err != nil || previous == nil {
			return ForwardTunnelSpec{}, storage.ErrForwardingInvalid
		}
		for _, raw := range []string{previous.IPAddress, previous.IPAddressV6} {
			address, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			address = address.Unmap()
			spec.SourceCIDRs = append(spec.SourceCIDRs, netip.PrefixFrom(address, address.BitLen()).String())
		}
		if len(spec.SourceCIDRs) == 0 {
			return ForwardTunnelSpec{}, storage.ErrForwardingInvalid
		}
	}
	return spec, nil
}

func (h *ForwardingHandler) deployForwardOnce(ctx context.Context, f *storage.UserForwardRule) error {
	leased, release, err := h.acquireForwardLeases(ctx, f.Hops)
	if err != nil {
		return err
	}
	defer release()
	healthyRenewal := f.ObservedState == storage.ForwardObservedActive && f.Generation == f.AppliedGeneration
	leaseStillValid := healthyRenewal && time.Now().UTC().Before(f.UpdatedAt.Add(forwardTunnelLeaseDuration))
	if !healthyRenewal {
		_ = h.repo.MarkUserForwardDeployment(ctx, f.ID, storage.ForwardObservedProvisioning, false, "", "")
	}
	applied := []storage.UserForwardHop{}
	for i := len(f.Hops) - 1; i >= 0; i-- {
		hop := f.Hops[i]
		spec, specErr := h.tunnelSpec(leased, f, i)
		if specErr != nil {
			err = specErr
		} else {
			err = h.deployer.Apply(leased, spec)
		}
		if err != nil {
			if leaseStillValid {
				return err
			}
			for j := len(applied) - 1; j >= 0; j-- {
				_ = h.deployer.Suspend(leased, applied[j].ServerID, applied[j].ResourceID, applied[j].Generation)
				_ = h.repo.MarkUserForwardHop(ctx, applied[j].ID, storage.ForwardObservedSuspended, false, "")
			}
			_ = h.repo.MarkUserForwardHop(ctx, hop.ID, storage.ForwardObservedError, false, err.Error())
			_ = h.repo.MarkUserForwardDeployment(ctx, f.ID, storage.ForwardObservedError, false, "deployment_failed", err.Error())
			return err
		}
		applied = append(applied, hop)
		_ = h.repo.MarkUserForwardHop(ctx, hop.ID, storage.ForwardObservedActive, true, "")
	}
	return h.repo.MarkUserForwardDeployment(ctx, f.ID, storage.ForwardObservedActive, true, "", "")
}

func (h *ForwardingHandler) removeConflictedForwardResources(ctx context.Context, f *storage.UserForwardRule) error {
	leased, release, err := h.acquireForwardLeases(ctx, f.Hops)
	if err != nil {
		return err
	}
	defer release()
	pending := append([]storage.UserForwardHop(nil), f.Hops...)
	var lastErr error
	for attempt := 0; attempt < 3 && len(pending) > 0; attempt++ {
		retry := pending[:0]
		lastErr = nil
		for _, hop := range pending {
			if removeErr := h.deployer.Remove(leased, hop.ServerID, hop.ResourceID, hop.Generation+1); removeErr != nil {
				lastErr = errors.Join(lastErr, removeErr)
				retry = append(retry, hop)
			}
		}
		pending = retry
	}
	if len(pending) != 0 {
		return lastErr
	}
	return nil
}

func forwardNeedsPortConvergence(f *storage.UserForwardRule) bool {
	if f == nil || len(f.Hops) == 0 {
		return false
	}
	commonPort := f.Hops[0].ListenPort
	for i, hop := range f.Hops {
		if hop.ListenPort != commonPort {
			return true
		}
		if i+1 < len(f.Hops) && hop.NextPort != commonPort {
			return true
		}
	}
	return false
}

func (h *ForwardingHandler) deployForward(ctx context.Context, f *storage.UserForwardRule) error {
	current := f
	var err, cleanupWarning error
	if forwardNeedsPortConvergence(current) {
		if current.RequestedEntryPort > 0 {
			return fmt.Errorf("%w: fixed-port forward has inconsistent route ports", storage.ErrForwardingConflict)
		}
		legacy := current
		converged, reallocateErr := h.repo.ReallocateUserForwardPorts(ctx, current.PublicID, current.Username)
		if reallocateErr != nil {
			return reallocateErr
		}
		cleanupWarning = h.removeConflictedForwardResources(ctx, legacy)
		current = converged
	}
	for attempt := 0; attempt < 3; attempt++ {
		err = h.deployForwardOnce(ctx, current)
		if !errors.Is(err, ErrForwardTunnelPortInUse) {
			if err == nil && cleanupWarning != nil {
				log.Printf("[Forwarding] old conflicted resources could not be fully removed for %s: %v", current.PublicID, cleanupWarning)
				return nil
			}
			if err != nil && cleanupWarning != nil {
				return errors.Join(err, cleanupWarning)
			}
			return err
		}
		if current.RequestedEntryPort > 0 {
			return err
		}
		conflicted := current
		reallocated, reallocateErr := h.repo.ReallocateUserForwardPorts(ctx, current.PublicID, current.Username)
		if reallocateErr != nil {
			return errors.Join(err, reallocateErr)
		}
		cleanupWarning = errors.Join(cleanupWarning, h.removeConflictedForwardResources(ctx, conflicted))
		current = reallocated
	}
	return errors.Join(err, cleanupWarning)
}

func (h *ForwardingHandler) suspendForward(ctx context.Context, f *storage.UserForwardRule, actor string) error {
	if len(f.Hops) == 0 {
		return storage.ErrForwardingInvalid
	}
	updated, err := h.repo.SetUserForwardDesired(ctx, f.PublicID, f.Username, storage.ForwardDesiredInactive, storage.ForwardObservedProvisioning, "user_disabled", actor)
	if err != nil {
		return err
	}
	leased, release, err := h.acquireForwardLeases(ctx, updated.Hops[:1])
	if err != nil {
		return err
	}
	defer release()
	if h.deployer == nil {
		return errors.New("managed tunnel deployer is unavailable")
	}
	if err = h.deployer.Suspend(leased, updated.Hops[0].ServerID, updated.Hops[0].ResourceID, updated.Hops[0].Generation); err != nil {
		return err
	}
	_ = h.repo.MarkUserForwardHop(ctx, updated.Hops[0].ID, storage.ForwardObservedSuspended, true, "")
	return h.repo.MarkUserForwardDeployment(ctx, updated.ID, storage.ForwardObservedSuspended, true, "", "")
}

func (h *ForwardingHandler) resumeForward(ctx context.Context, f *storage.UserForwardRule, actor string) error {
	g, err := h.repo.GetUserTunnelGrantByID(ctx, f.GrantID)
	if err != nil {
		return err
	}
	grants, err := h.repo.ListUserTunnelGrants(ctx, f.Username)
	if err != nil {
		return err
	}
	state := ""
	for _, item := range grants {
		if item.ID == g.ID {
			state = item.State
		}
	}
	if state != "active" {
		return storage.ErrForwardingForbidden
	}
	if _, _, _, _, err = h.resolveManagedForwardTarget(ctx, f.Username, f.TargetNodeID); err != nil {
		return err
	}
	updated, err := h.repo.SetUserForwardDesired(ctx, f.PublicID, f.Username, storage.ForwardDesiredActive, storage.ForwardObservedPending, "none", actor)
	if err != nil {
		return err
	}
	return h.deployForward(ctx, updated)
}

func (h *ForwardingHandler) deleteForward(ctx context.Context, f *storage.UserForwardRule, actor string) error {
	// Capture the last counters while the Guard resource still exists. Metering
	// failure must not strand remote resources, so cleanup remains fail-open.
	_ = h.repo.SyncUserForwardUsage(ctx)
	updated := f
	var err error
	if f.DesiredState != storage.ForwardDesiredDeleted {
		updated, err = h.repo.SetUserForwardDesired(ctx, f.PublicID, f.Username, storage.ForwardDesiredDeleted, storage.ForwardObservedCleanupPending, "none", actor)
		if err != nil {
			return err
		}
	}
	leased, release, err := h.acquireForwardLeases(ctx, updated.Hops)
	if err != nil {
		return err
	}
	defer release()
	if h.deployer == nil {
		return errors.New("managed tunnel deployer is unavailable")
	}
	for i := 0; i < len(updated.Hops); i++ {
		if err = h.deployer.Remove(leased, updated.Hops[i].ServerID, updated.Hops[i].ResourceID, updated.Hops[i].Generation); err != nil {
			_ = h.repo.MarkUserForwardDeployment(ctx, updated.ID, storage.ForwardObservedCleanupPending, false, "cleanup_pending", err.Error())
			return err
		}
		_ = h.repo.MarkUserForwardHop(ctx, updated.Hops[i].ID, storage.ForwardObservedSuspended, true, "")
	}
	return h.repo.FinalizeUserForwardDelete(ctx, updated.ID)
}

const forwardingReconcileInterval = time.Minute

// StartReconciler renews active five-minute leases and converges expired,
// revoked, failed and cleanup-pending forwards. It is safe to call once during
// server startup; StopReconciler and WaitForReconciler provide orderly shutdown.
func (h *ForwardingHandler) StartReconciler(parent context.Context) {
	h.reconcileMu.Lock()
	defer h.reconcileMu.Unlock()
	if h.reconcileCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	h.reconcileCancel = cancel
	h.reconcileWG.Add(1)
	go func() {
		defer h.reconcileWG.Done()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		h.reconcileForwards(ctx)
		ticker := time.NewTicker(forwardingReconcileInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.reconcileForwards(ctx)
			}
		}
	}()
}

func (h *ForwardingHandler) StopReconciler() {
	h.reconcileMu.Lock()
	cancel := h.reconcileCancel
	h.reconcileCancel = nil
	h.reconcileMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (h *ForwardingHandler) WaitForReconciler() {
	h.reconcileWG.Wait()
}

func (h *ForwardingHandler) activeGrantForForward(ctx context.Context, f storage.UserForwardRule) bool {
	grants, err := h.repo.ListUserTunnelGrants(ctx, f.Username)
	if err != nil {
		return false
	}
	for _, grant := range grants {
		if grant.ID == f.GrantID {
			return grant.State == "active" || grant.State == "tunnel_draining"
		}
	}
	return false
}

func (h *ForwardingHandler) systemSuspendForward(ctx context.Context, f *storage.UserForwardRule, reason string) error {
	if len(f.Hops) == 0 || h.deployer == nil {
		return storage.ErrForwardingInvalid
	}
	updated, err := h.repo.PrepareUserForwardSystemSuspend(ctx, f.PublicID, f.Username, reason)
	if err != nil {
		return err
	}
	leased, release, err := h.acquireForwardLeases(ctx, updated.Hops[:1])
	if err != nil {
		return err
	}
	defer release()
	hop := updated.Hops[0]
	if err := h.deployer.Suspend(leased, hop.ServerID, hop.ResourceID, hop.Generation); err != nil {
		_ = h.repo.MarkUserForwardSystemState(ctx, updated.ID, storage.ForwardObservedError, reason, "suspend_failed", err.Error())
		return err
	}
	_ = h.repo.MarkUserForwardHop(ctx, hop.ID, storage.ForwardObservedSuspended, true, "")
	return h.repo.MarkUserForwardSystemState(ctx, updated.ID, storage.ForwardObservedSuspended, reason, "", "")
}

func (h *ForwardingHandler) retryInactiveForwardSuspend(ctx context.Context, f *storage.UserForwardRule) error {
	if len(f.Hops) == 0 || h.deployer == nil {
		return storage.ErrForwardingInvalid
	}
	leased, release, err := h.acquireForwardLeases(ctx, f.Hops[:1])
	if err != nil {
		return err
	}
	defer release()
	hop := f.Hops[0]
	if err := h.deployer.Suspend(leased, hop.ServerID, hop.ResourceID, hop.Generation); err != nil {
		_ = h.repo.MarkUserForwardDeployment(ctx, f.ID, storage.ForwardObservedError, false, "suspend_failed", err.Error())
		return err
	}
	_ = h.repo.MarkUserForwardHop(ctx, hop.ID, storage.ForwardObservedSuspended, true, "")
	return h.repo.MarkUserForwardDeployment(ctx, f.ID, storage.ForwardObservedSuspended, true, "", "")
}

func (h *ForwardingHandler) reconcileForwards(ctx context.Context) {
	if h.deployer == nil {
		return
	}
	_ = h.repo.SyncUserForwardUsage(ctx)
	items, err := h.repo.ListForwardReconcileCandidates(ctx)
	if err != nil {
		return
	}
	for i := range items {
		if ctx.Err() != nil {
			return
		}
		forward := &items[i]
		switch forward.DesiredState {
		case storage.ForwardDesiredDeleted:
			_ = h.deleteForward(ctx, forward, "system")
		case storage.ForwardDesiredInactive:
			if forward.ObservedState != storage.ForwardObservedSuspended {
				_ = h.retryInactiveForwardSuspend(ctx, forward)
			}
			continue
		case storage.ForwardDesiredActive:
			if !h.activeGrantForForward(ctx, *forward) {
				if forward.ObservedState == storage.ForwardObservedSuspended && forward.SuspendReason == "grant_inactive" {
					continue
				}
				_ = h.systemSuspendForward(ctx, forward, "grant_inactive")
				continue
			}
			if _, _, _, _, err := h.resolveManagedForwardTarget(ctx, forward.Username, forward.TargetNodeID); err != nil {
				if forward.ObservedState == storage.ForwardObservedSuspended && forward.SuspendReason == "target_inactive" {
					continue
				}
				_ = h.systemSuspendForward(ctx, forward, "target_inactive")
				continue
			}
			candidate := forward
			if forward.ObservedState != storage.ForwardObservedActive {
				candidate, err = h.repo.PrepareUserForwardSystemApply(ctx, forward.PublicID, forward.Username)
				if err != nil {
					continue
				}
			}
			_ = h.deployForward(ctx, candidate)
		}
	}
}
