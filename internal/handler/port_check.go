package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

// PortCheckResult describes whether a TCP/UDP port is safe to bind on a server
// or across an entire forwarding tunnel chain.
type PortCheckResult struct {
	Success    bool   `json:"success"`
	Port       int    `json:"port"`
	Available  bool   `json:"available"`
	OccupiedBy string `json:"occupied_by,omitempty"`
	Network    string `json:"network,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	ServerID   int64  `json:"server_id,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func isWSSSharedPortProtocol(protocol string) bool {
	switch canonicalManagedProtocol(protocol) {
	case "vless-wss", "vmess-wss", "trojan-wss", "trojan-ws-tls", "ws-tls", "wss":
		return true
	default:
		return false
	}
}

func parsePortCheckNetworks(protocol, rawNetwork string) ([]string, error) {
	trimmed := strings.TrimSpace(strings.ToLower(rawNetwork))
	if trimmed != "" {
		trimmed = strings.ReplaceAll(trimmed, "+", ",")
		trimmed = strings.ReplaceAll(trimmed, "_", ",")
		seen := make(map[string]bool, 2)
		out := make([]string, 0, 2)
		for _, part := range strings.Split(trimmed, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			if p != "tcp" && p != "udp" {
				return nil, fmt.Errorf("unsupported network %q", p)
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		if len(out) == 0 {
			return []string{"tcp", "udp"}, nil
		}
		return out, nil
	}

	switch canonicalManagedProtocol(protocol) {
	case "wireguard", "hysteria":
		return []string{"udp"}, nil
	case "dokodemo-door", "tunnel", "anydoor", "chitanda", "shadowsocks":
		return []string{"tcp", "udp"}, nil
	case "vless", "vmess", "trojan", "vless-reality", "vless-tcp", "vless-wss",
		"vmess-wss", "trojan-wss", "trojan-tcp-tls", "trojan-reality", "trojan-ws-tls",
		"ws-tls", "wss", "socks", "http", "anytls", "mieru":
		return []string{"tcp"}, nil
	default:
		return []string{"tcp", "udp"}, nil
	}
}

func desiredInboundNetworks(inbound map[string]interface{}) []string {
	protocol, _ := inbound["protocol"].(string)
	var rawNet string
	if settings, ok := inbound["settings"].(map[string]interface{}); ok {
		rawNet, _ = settings["network"].(string)
	}
	nets, err := parsePortCheckNetworks(protocol, rawNet)
	if err != nil {
		return []string{"tcp", "udp"}
	}
	return nets
}

func firstOverlappingPortNetwork(a, b []string) string {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return x
			}
		}
	}
	return ""
}

func formatServerPortLabel(server *storage.RemoteServer, serverID int64) string {
	if server != nil && strings.TrimSpace(server.Name) != "" {
		return strings.TrimSpace(server.Name)
	}
	return fmt.Sprintf("节点 #%d", serverID)
}

func (h *RemoteManageHandler) checkServerPortAvailability(
	ctx context.Context,
	serverID int64,
	port int,
	protocol string,
	rawNetwork string,
	ignoreTag string,
) (PortCheckResult, error) {
	if h == nil || h.repo == nil {
		return PortCheckResult{}, fmt.Errorf("remote manage handler is not initialized")
	}
	if port < 1 || port > 65535 {
		return PortCheckResult{}, fmt.Errorf("port must be between 1 and 65535")
	}

	networks, err := parsePortCheckNetworks(protocol, rawNetwork)
	if err != nil {
		return PortCheckResult{}, err
	}
	ignoreTag = strings.TrimSpace(ignoreTag)

	if isWSSSharedPortProtocol(protocol) && port == 443 {
		return PortCheckResult{
			Success:    true,
			Port:       port,
			Available:  true,
			OccupiedBy: "shared_nginx",
			Network:    "tcp",
			Protocol:   protocol,
			ServerID:   serverID,
			Reason:     "443 端口由 Nginx TLS 复用承载当前 WSS 入站",
		}, nil
	}

	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return PortCheckResult{}, err
	}
	serverName := formatServerPortLabel(server, serverID)

	desiredInbounds, err := h.repo.ListActiveDesiredInbounds(ctx, serverID)
	if err != nil {
		return PortCheckResult{}, err
	}
	for _, desired := range desiredInbounds {
		if ignoreTag != "" && desired.InboundTag == ignoreTag {
			continue
		}
		inbound, decodeErr := decodeDesiredInbound(desired.InboundJSON)
		if decodeErr != nil {
			continue
		}
		desiredPort, ok := managedNumericInt(inbound["port"])
		if !ok || desiredPort != port {
			continue
		}
		conflictNet := firstOverlappingPortNetwork(networks, desiredInboundNetworks(inbound))
		if conflictNet == "" {
			continue
		}
		inboundProto, _ := inbound["protocol"].(string)
		return PortCheckResult{
			Success:    true,
			Port:       port,
			Available:  false,
			OccupiedBy: "desired_inbound",
			Network:    conflictNet,
			Tag:        desired.InboundTag,
			Protocol:   inboundProto,
			ServerID:   serverID,
			ServerName: serverName,
			Reason:     fmt.Sprintf("端口 %d 已被受管入站 %s (%s) 占用", port, desired.InboundTag, conflictNet),
		}, nil
	}

	if ownerType, allocNet, found, err := h.repo.FindOccupiedForwardPortAllocation(ctx, serverID, networks, port); err != nil {
		return PortCheckResult{}, err
	} else if found {
		return PortCheckResult{
			Success:    true,
			Port:       port,
			Available:  false,
			OccupiedBy: "forward_allocation",
			Network:    allocNet,
			ServerID:   serverID,
			ServerName: serverName,
			Reason:     fmt.Sprintf("端口 %d 已被转发规则端口池占用 (%s/%s)", port, ownerType, allocNet),
		}, nil
	}

	query := url.Values{}
	query.Set("port", strconv.Itoa(port))
	query.Set("network", strings.Join(networks, ","))
	if ignoreTag != "" {
		query.Set("ignore_tag", ignoreTag)
	}
	body, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/ports/check?"+query.Encode(), nil)
	if err != nil {
		return PortCheckResult{}, err
	}

	var agentResp PortCheckResult
	if err := json.Unmarshal(body, &agentResp); err != nil {
		return PortCheckResult{}, fmt.Errorf("invalid port check response from agent: %w", err)
	}
	agentResp.Success = true
	agentResp.Port = port
	agentResp.ServerID = serverID
	agentResp.ServerName = serverName
	if agentResp.Available && agentResp.Reason == "" {
		agentResp.Reason = fmt.Sprintf("端口 %d (%s) 可用", port, strings.Join(networks, "+"))
	}
	return agentResp, nil
}

// HandleRemotePortCheck handles GET /api/admin/remote/port-check.
func (h *RemoteManageHandler) HandleRemotePortCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	q := r.URL.Query()
	serverID, err := strconv.ParseInt(strings.TrimSpace(q.Get("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}
	port, err := strconv.Atoi(strings.TrimSpace(q.Get("port")))
	if err != nil || port < 1 || port > 65535 {
		remoteWriteError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}

	res, err := h.checkServerPortAvailability(
		r.Context(),
		serverID,
		port,
		q.Get("protocol"),
		q.Get("network"),
		q.Get("ignore_tag"),
	)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// HandleUserManagedNodeCreationPortCheck handles GET /api/user/managed-node-creation/port-check.
func (h *ManagedNodesHandler) HandleUserManagedNodeCreationPortCheck(w http.ResponseWriter, r *http.Request) {
	username, ok := h.requireActiveManagedUser(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	q := r.URL.Query()
	serverID, err := strconv.ParseInt(strings.TrimSpace(q.Get("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	if _, err := h.activeUserServerGrant(r.Context(), username, serverID); err != nil {
		writeManagedError(w, err)
		return
	}
	port, err := strconv.Atoi(strings.TrimSpace(q.Get("port")))
	if err != nil || port < 1 || port > 65535 {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	if h.remoteManage == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "remote manager unavailable")
		return
	}
	res, err := h.remoteManage.checkServerPortAvailability(
		r.Context(),
		serverID,
		port,
		q.Get("protocol"),
		q.Get("network"),
		"",
	)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Redact internal raw tag/details slightly? Keep non-sensitive occupied_by/reason for user clarity.
	res.Tag = ""
	writeJSON(w, http.StatusOK, res)
}

func (h *ForwardingHandler) resolveRemoteManager() *RemoteManageHandler {
	if h.remoteManage != nil {
		return h.remoteManage
	}
	if guardDeployer, ok := h.deployer.(*ForwardingGuardDeployer); ok && guardDeployer != nil && guardDeployer.managed != nil {
		return guardDeployer.managed.remoteManage
	}
	return nil
}

func (h *ForwardingHandler) checkForwardPortAcrossHops(
	ctx context.Context,
	tunnel *storage.TunnelTemplate,
	port int,
) (PortCheckResult, error) {
	if tunnel == nil {
		return PortCheckResult{}, storage.ErrTunnelTemplateNotFound
	}
	if port < tunnel.PortRangeStart || port > tunnel.PortRangeEnd {
		return PortCheckResult{
			Success:    true,
			Port:       port,
			Available:  false,
			OccupiedBy: "tunnel_range",
			Network:    "tcp,udp",
			Reason:     fmt.Sprintf("端口 %d 不在模板允许范围 %d-%d 内", port, tunnel.PortRangeStart, tunnel.PortRangeEnd),
		}, nil
	}
	rm := h.resolveRemoteManager()
	seenServers := make(map[int64]bool, len(tunnel.Hops))
	for _, hop := range tunnel.Hops {
		if seenServers[hop.ServerID] {
			continue
		}
		seenServers[hop.ServerID] = true
		if rm != nil {
			res, err := rm.checkServerPortAvailability(ctx, hop.ServerID, port, "dokodemo-door", "tcp,udp", "")
			if err != nil {
				return PortCheckResult{}, err
			}
			if !res.Available {
				label := res.ServerName
				if label == "" {
					label = fmt.Sprintf("节点 #%d", hop.ServerID)
				}
				res.Reason = fmt.Sprintf("中转节点 %s：%s", label, res.Reason)
				return res, nil
			}
		} else if ownerType, allocNet, found, err := h.repo.FindOccupiedForwardPortAllocation(ctx, hop.ServerID, []string{"tcp", "udp"}, port); err != nil {
			return PortCheckResult{}, err
		} else if found {
			return PortCheckResult{
				Success:    true,
				Port:       port,
				Available:  false,
				OccupiedBy: "forward_allocation",
				Network:    allocNet,
				ServerID:   hop.ServerID,
				Reason:     fmt.Sprintf("节点 #%d 端口 %d 已被转发规则端口池占用 (%s)", hop.ServerID, port, ownerType),
			}, nil
		}
	}
	return PortCheckResult{
		Success:   true,
		Port:      port,
		Available: true,
		Network:   "tcp,udp",
		Reason:    fmt.Sprintf("全链路共 %d 台节点均未占用端口 %d", len(seenServers), port),
	}, nil
}

// HandleUserForwardPortCheck handles GET /api/user/forwards/port-check.
func (h *ForwardingHandler) HandleUserForwardPortCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	username := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
	if username == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	q := r.URL.Query()
	grantID := strings.TrimSpace(q.Get("grant_id"))
	port, err := strconv.Atoi(strings.TrimSpace(q.Get("port")))
	if grantID == "" || err != nil || port < 1 || port > 65535 {
		writeForwardingError(w, storage.ErrForwardingInvalid)
		return
	}

	g, err := h.repo.GetUserTunnelGrant(r.Context(), grantID, username)
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
			break
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

	res, err := h.checkForwardPortAcrossHops(r.Context(), tunnel, port)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	res.Tag = ""
	writeJSON(w, http.StatusOK, res)
}
