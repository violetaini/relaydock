package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/probe"
	"github.com/violetaini/relaydock/internal/storage"
)

const maxConcurrentTCPing = 20

// TCPingRequest accepts node_id from the node workbench. Host/port/protocol are
// retained only for administrator API compatibility and are never trusted for
// ordinary users.
type TCPingRequest struct {
	NodeID   int64  `json:"node_id,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Timeout  int    `json:"timeout"`
	Protocol string `json:"protocol,omitempty"`
}

type TCPingResponse struct {
	Success bool    `json:"success"`
	Latency float64 `json:"latency"`
	Error   string  `json:"error,omitempty"`
	Probe   string  `json:"probe,omitempty"`
}

type remoteNodeProbeClient interface {
	ForwardToServer(ctx context.Context, serverID int64, method, path string, body []byte) ([]byte, error)
}

type tcpingHandler struct {
	repo   *storage.TrafficRepository
	remote remoteNodeProbeClient
	batch  bool
}

type resolvedTCPingRequest struct {
	request       TCPingRequest
	node          storage.Node
	hasNode       bool
	publicOnly    bool
	resolveStatus int
	resolveError  string
}

type managedInventoryCall struct {
	done    chan struct{}
	body    []byte
	latency float64
	err     error
}

type managedInventoryCache struct {
	mu    sync.Mutex
	calls map[int64]*managedInventoryCall
}

func NewTCPingHandler(repo *storage.TrafficRepository, remote remoteNodeProbeClient) http.Handler {
	if repo == nil {
		panic("tcping handler requires repository")
	}
	return &tcpingHandler{repo: repo, remote: remote}
}

func NewTCPingBatchHandler(repo *storage.TrafficRepository, remote remoteNodeProbeClient) http.Handler {
	if repo == nil {
		panic("tcping batch handler requires repository")
	}
	return &tcpingHandler{repo: repo, remote: remote, batch: true}
}

func (h *tcpingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
		return
	}
	if h.batch {
		h.handleBatch(w, r)
		return
	}
	h.handleOne(w, r)
}

func (h *tcpingHandler) handleOne(w http.ResponseWriter, r *http.Request) {
	var request TCPingRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	resolved, status, err := h.resolveRequests(r.Context(), []TCPingRequest{request})
	if err != nil {
		writeError(w, status, err)
		return
	}
	if resolved[0].resolveError != "" {
		writeError(w, resolved[0].resolveStatus, errors.New(resolved[0].resolveError))
		return
	}
	response := h.pingResolved(r.Context(), resolved[0], nil)
	respondJSON(w, http.StatusOK, response)
}

func (h *tcpingHandler) handleBatch(w http.ResponseWriter, r *http.Request) {
	var requests []TCPingRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&requests); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	if len(requests) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("no nodes to test"))
		return
	}
	if len(requests) > 200 {
		writeError(w, http.StatusBadRequest, errors.New("max 200 nodes allowed"))
		return
	}

	resolved, status, err := h.resolveRequests(r.Context(), requests)
	if err != nil {
		writeError(w, status, err)
		return
	}

	results := make([]TCPingResponse, len(resolved))
	inventoryCache := &managedInventoryCache{calls: make(map[int64]*managedInventoryCall)}
	semaphore := make(chan struct{}, maxConcurrentTCPing)
	var wait sync.WaitGroup
	wait.Add(len(resolved))
	for index := range resolved {
		go func(index int) {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-r.Context().Done():
				results[index] = TCPingResponse{Success: false, Error: "request cancelled"}
				return
			}
			results[index] = h.pingResolved(r.Context(), resolved[index], inventoryCache)
		}(index)
	}
	wait.Wait()
	respondJSON(w, http.StatusOK, results)
}

func (h *tcpingHandler) resolveRequests(ctx context.Context, requests []TCPingRequest) ([]resolvedTCPingRequest, int, error) {
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		return nil, http.StatusUnauthorized, errors.New("用户未认证")
	}
	isAdmin := username == "api-token-admin" || userIsAdmin(ctx, h.repo, username)

	visible := map[int64]storage.Node{}
	if !isAdmin {
		nodes, err := collectUserVisibleNodes(ctx, h.repo, username)
		if err != nil {
			return nil, http.StatusInternalServerError, errors.New("无法读取可用节点")
		}
		for _, node := range substituteNodesForUser(ctx, h.repo, username, nodes) {
			visible[node.ID] = node
		}
	}

	resolved := make([]resolvedTCPingRequest, len(requests))
	for index, request := range requests {
		request.Protocol = canonicalProbeProtocol(request.Protocol)
		if request.NodeID <= 0 {
			if !isAdmin {
				resolved[index] = resolvedTCPingRequest{resolveStatus: http.StatusForbidden, resolveError: "普通用户只能测试自己可见的节点"}
				continue
			}
			request.Host = strings.TrimSpace(request.Host)
			if request.Host == "" || request.Port <= 0 || request.Port > 65535 {
				resolved[index] = resolvedTCPingRequest{resolveStatus: http.StatusBadRequest, resolveError: "invalid host or port"}
				continue
			}
			resolved[index] = resolvedTCPingRequest{request: request}
			continue
		}

		var node storage.Node
		var err error
		if isAdmin {
			node, err = h.repo.GetNodeByID(ctx, request.NodeID)
		} else {
			var found bool
			node, found = visible[request.NodeID]
			if !found {
				err = storage.ErrNodeNotFound
			}
		}
		if err != nil {
			resolved[index] = resolvedTCPingRequest{resolveStatus: http.StatusNotFound, resolveError: "节点不存在或当前用户无权访问"}
			continue
		}

		request.Protocol = canonicalProbeProtocol(node.Protocol)
		request.Host, request.Port, err = nodeProbeAddress(node)
		if err != nil {
			resolved[index] = resolvedTCPingRequest{resolveStatus: http.StatusUnprocessableEntity, resolveError: fmt.Sprintf("节点 %d 缺少有效的服务器地址", node.ID)}
			continue
		}
		resolved[index] = resolvedTCPingRequest{
			request: request, node: node, hasNode: true,
			publicOnly: !isAdmin && request.Protocol != "wireguard",
		}
	}
	return resolved, http.StatusOK, nil
}

func canonicalProbeProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "wg" {
		return "wireguard"
	}
	return protocol
}

func nodeProbeAddress(node storage.Node) (string, int, error) {
	for _, raw := range []string{node.ClashConfig, node.ParsedConfig} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var config map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			continue
		}
		var host string
		if err := json.Unmarshal(config["server"], &host); err != nil {
			continue
		}
		port, err := jsonInteger(config["port"])
		if strings.TrimSpace(host) != "" && err == nil && port > 0 && port <= 65535 {
			return strings.TrimSpace(host), port, nil
		}
	}
	return "", 0, errors.New("missing server or port")
}

func jsonInteger(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, errors.New("missing number")
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		value, err := strconv.Atoi(number.String())
		if err == nil {
			return value, nil
		}
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, errors.New("invalid number")
	}
	return strconv.Atoi(strings.TrimSpace(text))
}

func resolvePublicProbeHost(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		if !isPublicProbeIP(ip) {
			return "", errors.New("non-public address")
		}
		return ip.String(), nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return "", errors.New("address resolution failed")
	}
	for _, address := range addresses {
		if !isPublicProbeIP(address.IP) {
			return "", errors.New("hostname resolves to a non-public address")
		}
	}
	return addresses[0].IP.String(), nil
}

func isPublicProbeIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	if ipv4 := ip.To4(); ipv4 != nil && ipv4[0] == 100 && ipv4[1]&0xc0 == 0x40 {
		return false
	}
	return true
}

func normalizedTCPingTimeout(milliseconds int) time.Duration {
	if milliseconds <= 0 {
		milliseconds = 5000
	}
	if milliseconds > 30000 {
		milliseconds = 30000
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func (h *tcpingHandler) pingResolved(ctx context.Context, resolved resolvedTCPingRequest, inventoryCache *managedInventoryCache) TCPingResponse {
	if resolved.resolveError != "" {
		return TCPingResponse{Success: false, Error: resolved.resolveError}
	}
	timeout := normalizedTCPingTimeout(resolved.request.Timeout)
	if resolved.request.Protocol == "wireguard" {
		if !resolved.hasNode || strings.TrimSpace(resolved.node.OriginalServer) == "" || strings.TrimSpace(resolved.node.InboundTag) == "" {
			return TCPingResponse{
				Success: false,
				Error:   "外部 WireGuard 需要专用探测 Peer，无法安全主动探测",
				Probe:   "managed_wireguard",
			}
		}
		return h.probeManagedWireGuard(ctx, resolved, timeout, inventoryCache)
	}
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if resolved.publicOnly {
		host, err := resolvePublicProbeHost(probeContext, resolved.request.Host)
		if err != nil {
			return TCPingResponse{Success: false, Error: "节点服务器地址不可由普通用户探测"}
		}
		resolved.request.Host = host
	}
	return pingNetwork(probeContext, resolved.request, timeout)
}

func (h *tcpingHandler) probeManagedWireGuard(ctx context.Context, resolved resolvedTCPingRequest, timeout time.Duration, inventoryCache *managedInventoryCache) TCPingResponse {
	response := TCPingResponse{Probe: "managed_wireguard"}
	if h.remote == nil {
		response.Error = "受管服务器探测通道不可用"
		return response
	}
	server, err := h.repo.GetRemoteServerByName(ctx, resolved.node.OriginalServer)
	if err != nil || server == nil {
		response.Error = "找不到 WireGuard 所属的受管服务器"
		return response
	}

	body, latency, err := loadManagedInventory(ctx, inventoryCache, h.remote, server.ID, timeout)
	if err != nil {
		log.Printf("[Node Probe] managed WireGuard node=%d server=%d tag=%q failed: %v", resolved.node.ID, server.ID, resolved.node.InboundTag, err)
		response.Error = "受管服务器控制链路不可用"
		return response
	}
	if err := inspectManagedWireGuardInventory(body, resolved.node.InboundTag, managedWireGuardInboundPort(resolved)); err != nil {
		log.Printf("[Node Probe] managed WireGuard node=%d server=%d tag=%q unhealthy: %v", resolved.node.ID, server.ID, resolved.node.InboundTag, err)
		response.Error = err.Error()
		return response
	}
	response.Success = true
	response.Latency = latency
	log.Printf("[Node Probe] managed WireGuard node=%d server=%d tag=%q running, management RTT %.2fms", resolved.node.ID, server.ID, resolved.node.InboundTag, latency)
	return response
}

func managedWireGuardInboundPort(resolved resolvedTCPingRequest) int {
	if strings.TrimSpace(resolved.node.RelayOrigServer) != "" {
		if resolved.node.RelayOrigPort > 0 && resolved.node.RelayOrigPort <= 65535 {
			return resolved.node.RelayOrigPort
		}
		return 0
	}
	return resolved.request.Port
}

func loadManagedInventory(ctx context.Context, cache *managedInventoryCache, remote remoteNodeProbeClient, serverID int64, timeout time.Duration) ([]byte, float64, error) {
	if cache == nil {
		probeContext, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		started := time.Now()
		body, err := remote.ForwardToServer(probeContext, serverID, http.MethodGet, "/api/child/inbounds", nil)
		return body, float64(time.Since(started).Microseconds()) / 1000, err
	}

	cache.mu.Lock()
	call, exists := cache.calls[serverID]
	if !exists {
		call = &managedInventoryCall{done: make(chan struct{})}
		cache.calls[serverID] = call
	}
	cache.mu.Unlock()
	if exists {
		select {
		case <-call.done:
			return call.body, call.latency, call.err
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}

	probeContext, cancel := context.WithTimeout(ctx, timeout)
	started := time.Now()
	call.body, call.err = remote.ForwardToServer(probeContext, serverID, http.MethodGet, "/api/child/inbounds", nil)
	call.latency = float64(time.Since(started).Microseconds()) / 1000
	cancel()
	close(call.done)
	return call.body, call.latency, call.err
}

func inspectManagedWireGuardInventory(body []byte, expectedTag string, expectedPort int) error {
	var inventory struct {
		Success  *bool `json:"success"`
		Inbounds []struct {
			Tag           string          `json:"tag"`
			Protocol      string          `json:"protocol"`
			Port          json.RawMessage `json:"port"`
			RuntimeStatus string          `json:"_runtime_status"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(body, &inventory); err != nil {
		return errors.New("受管服务器返回了无效的入站状态")
	}
	if inventory.Success != nil && !*inventory.Success {
		return errors.New("受管服务器无法读取 WireGuard 入站状态")
	}
	expectedTag = strings.TrimSpace(expectedTag)
	for _, inbound := range inventory.Inbounds {
		if strings.TrimSpace(inbound.Tag) != expectedTag {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(inbound.Protocol), "wireguard") {
			return errors.New("对应入站已不再是 WireGuard")
		}
		if expectedPort > 0 && len(inbound.Port) > 0 {
			if port, err := jsonInteger(inbound.Port); err == nil && port != expectedPort {
				return errors.New("WireGuard 入站端口与节点配置不一致")
			}
		}
		if strings.TrimSpace(inbound.RuntimeStatus) != "running" {
			return errors.New("WireGuard 入站当前未运行")
		}
		return nil
	}
	return errors.New("受管服务器上未找到对应的 WireGuard 入站")
}

func pingNetwork(ctx context.Context, request TCPingRequest, timeout time.Duration) TCPingResponse {
	address := net.JoinHostPort(request.Host, strconv.Itoa(request.Port))
	if probe.IsUDPProtocol(request.Protocol) {
		rtt, err := probe.UDPProbe(ctx, request.Host, request.Port, request.Protocol, timeout)
		if err != nil {
			log.Printf("[Node Probe] UDP %s (%s) failed: %v", address, request.Protocol, err)
			return TCPingResponse{Success: false, Error: err.Error(), Probe: "quic"}
		}
		latency := float64(rtt.Microseconds()) / 1000
		return TCPingResponse{Success: true, Latency: latency, Probe: "quic"}
	}

	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	connection, err := (&net.Dialer{}).DialContext(probeContext, "tcp", address)
	latency := float64(time.Since(started).Microseconds()) / 1000
	if err != nil {
		log.Printf("[Node Probe] TCP %s failed: %v", address, err)
		return TCPingResponse{Success: false, Error: err.Error(), Probe: "tcp"}
	}
	_ = connection.Close()
	return TCPingResponse{Success: true, Latency: latency, Probe: "tcp"}
}
