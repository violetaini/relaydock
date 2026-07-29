package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/speedtest"
	"github.com/violetaini/relaydock/internal/storage"
)

const maxTCPingBatch = 200
const maxProbeDialerChainDepth = 8
const maxTCPingBatchDuration = 75 * time.Second

// TCPingRequest keeps its historical JSON shape, but protocol latency requires
// node_id. Host/port cannot describe the credentials needed for a real Mihomo
// protocol test and are therefore no longer accepted as an alternate target.
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

type protocolLatencyProbeClient interface {
	Probe(ctx context.Context, targets []speedtest.ProtocolLatencyTarget) []speedtest.ProtocolLatencyResult
}

type localMihomoLatencyProber struct{}

func (localMihomoLatencyProber) Probe(ctx context.Context, targets []speedtest.ProtocolLatencyTarget) []speedtest.ProtocolLatencyResult {
	bin, err := speedtest.EnsureMihomo(ctx)
	if err == nil {
		return speedtest.ProbeProtocolLatency(ctx, bin, targets)
	}
	results := make([]speedtest.ProtocolLatencyResult, len(targets))
	for index := range results {
		results[index].Err = fmt.Errorf("Mihomo 核心不可用: %w", err)
	}
	return results
}

type tcpingHandler struct {
	repo   *storage.TrafficRepository
	remote remoteNodeProbeClient
	prober protocolLatencyProbeClient
	batch  bool
}

type resolvedTCPingRequest struct {
	request       TCPingRequest
	node          storage.Node
	dialerChain   []storage.Node
	publicOnly    bool
	resolveStatus int
	resolveError  string
}

type cachedWireGuardProbePeer struct {
	peer *storage.WireGuardProbePeer
	err  error
}

func NewTCPingHandler(repo *storage.TrafficRepository, remote remoteNodeProbeClient) http.Handler {
	return newTCPingHandler(repo, remote, false, localMihomoLatencyProber{})
}

func NewTCPingBatchHandler(repo *storage.TrafficRepository, remote remoteNodeProbeClient) http.Handler {
	return newTCPingHandler(repo, remote, true, localMihomoLatencyProber{})
}

func newTCPingHandler(repo *storage.TrafficRepository, remote remoteNodeProbeClient, batch bool, prober protocolLatencyProbeClient) http.Handler {
	if repo == nil {
		panic("tcping handler requires repository")
	}
	return &tcpingHandler{repo: repo, remote: remote, prober: prober, batch: batch}
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
	respondJSON(w, http.StatusOK, h.probeResolved(r.Context(), resolved)[0])
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
	if len(requests) > maxTCPingBatch {
		writeError(w, http.StatusBadRequest, fmt.Errorf("max %d nodes allowed", maxTCPingBatch))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), maxTCPingBatchDuration)
	defer cancel()
	resolved, status, err := h.resolveRequests(ctx, requests)
	if err != nil {
		writeError(w, status, err)
		return
	}
	respondJSON(w, http.StatusOK, h.probeResolved(ctx, resolved))
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
		if request.NodeID <= 0 {
			resolved[index] = resolvedTCPingRequest{
				resolveStatus: http.StatusBadRequest,
				resolveError:  "真实协议延迟测试必须提供 node_id",
			}
			continue
		}

		node, err := h.authorizedProbeNode(ctx, request.NodeID, isAdmin, visible)
		if err != nil {
			resolved[index] = resolvedTCPingRequest{resolveStatus: http.StatusNotFound, resolveError: "节点不存在或当前用户无权访问"}
			continue
		}
		chain, err := h.resolveProbeDialerChain(ctx, node, isAdmin, visible)
		if err != nil {
			resolved[index] = resolvedTCPingRequest{resolveStatus: http.StatusUnprocessableEntity, resolveError: err.Error()}
			continue
		}
		request.Protocol = canonicalProbeProtocol(node.Protocol)
		request.Host, request.Port, err = nodeProbeAddress(node)
		if err != nil {
			resolved[index] = resolvedTCPingRequest{resolveStatus: http.StatusUnprocessableEntity, resolveError: fmt.Sprintf("节点 %d 缺少有效的服务器地址", node.ID)}
			continue
		}
		resolved[index] = resolvedTCPingRequest{
			request: request, node: node, dialerChain: chain, publicOnly: !isAdmin,
		}
	}
	return resolved, http.StatusOK, nil
}

func (h *tcpingHandler) authorizedProbeNode(ctx context.Context, nodeID int64, isAdmin bool, visible map[int64]storage.Node) (storage.Node, error) {
	if isAdmin {
		return h.repo.GetNodeByID(ctx, nodeID)
	}
	node, ok := visible[nodeID]
	if !ok {
		return storage.Node{}, storage.ErrNodeNotFound
	}
	return node, nil
}

func (h *tcpingHandler) resolveProbeDialerChain(ctx context.Context, node storage.Node, isAdmin bool, visible map[int64]storage.Node) ([]storage.Node, error) {
	chain := make([]storage.Node, 0)
	seen := map[int64]struct{}{node.ID: {}}
	current := node
	for current.ChainProxyNodeID != nil {
		if len(chain) >= maxProbeDialerChainDepth {
			return nil, fmt.Errorf("节点前置代理链超过 %d 层", maxProbeDialerChainDepth)
		}
		nextID := *current.ChainProxyNodeID
		if nextID <= 0 {
			return nil, errors.New("节点前置代理引用无效")
		}
		if _, duplicate := seen[nextID]; duplicate {
			return nil, errors.New("节点前置代理链存在循环")
		}
		next, err := h.authorizedProbeNode(ctx, nextID, isAdmin, visible)
		if err != nil {
			return nil, errors.New("节点前置代理不存在或当前用户无权访问")
		}
		seen[nextID] = struct{}{}
		chain = append(chain, next)
		current = next
	}
	return chain, nil
}

func (h *tcpingHandler) probeResolved(ctx context.Context, resolved []resolvedTCPingRequest) []TCPingResponse {
	responses := make([]TCPingResponse, len(resolved))
	targets := make([]speedtest.ProtocolLatencyTarget, 0, len(resolved))
	targetIndexes := make([]int, 0, len(resolved))
	wireGuardCache := make(map[string]cachedWireGuardProbePeer)

	for index, item := range resolved {
		if item.resolveError != "" {
			responses[index] = TCPingResponse{Error: item.resolveError, Probe: "mihomo_url_test"}
			continue
		}
		target, err := h.prepareMihomoLatencyTarget(ctx, item, wireGuardCache)
		if err != nil {
			responses[index] = TCPingResponse{Error: err.Error(), Probe: "mihomo_url_test"}
			continue
		}
		targets = append(targets, target)
		targetIndexes = append(targetIndexes, index)
	}
	if len(targets) == 0 {
		return responses
	}
	if h.prober == nil {
		for _, index := range targetIndexes {
			responses[index] = TCPingResponse{Error: "Mihomo 协议探测器不可用", Probe: "mihomo_url_test"}
		}
		return responses
	}
	probeResults := h.prober.Probe(ctx, targets)
	if len(probeResults) != len(targets) {
		for _, index := range targetIndexes {
			responses[index] = TCPingResponse{Error: "Mihomo 返回的节点结果数量不匹配", Probe: "mihomo_url_test"}
		}
		return responses
	}
	for targetIndex, result := range probeResults {
		responseIndex := targetIndexes[targetIndex]
		if result.Err != nil {
			responses[responseIndex] = TCPingResponse{Error: result.Err.Error(), Probe: "mihomo_url_test"}
			continue
		}
		responses[responseIndex] = TCPingResponse{Success: true, Latency: result.Latency, Probe: "mihomo_url_test"}
	}
	return responses
}

func (h *tcpingHandler) prepareMihomoLatencyTarget(ctx context.Context, resolved resolvedTCPingRequest, wireGuardCache map[string]cachedWireGuardProbePeer) (speedtest.ProtocolLatencyTarget, error) {
	timeout := normalizedTCPingTimeout(resolved.request.Timeout)
	nodes := make([]storage.Node, 0, len(resolved.dialerChain)+1)
	nodes = append(nodes, resolved.node)
	nodes = append(nodes, resolved.dialerChain...)
	configs := make([]string, 0, len(nodes))
	hosts := make(map[string]string)
	for _, node := range nodes {
		config, err := h.mihomoProbeConfigForNode(ctx, node, wireGuardCache, timeout)
		if err != nil {
			return speedtest.ProtocolLatencyTarget{}, err
		}
		if resolved.publicOnly {
			if err := validatePublicMihomoProbeOverrides(config); err != nil {
				return speedtest.ProtocolLatencyTarget{}, err
			}
			host, _, addressErr := nodeProbeAddress(storage.Node{ClashConfig: config})
			if addressErr != nil {
				return speedtest.ProtocolLatencyTarget{}, errors.New("节点 Mihomo 配置缺少有效服务器地址")
			}
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			publicIP, resolveErr := resolvePublicProbeHost(probeCtx, host)
			cancel()
			if resolveErr != nil {
				return speedtest.ProtocolLatencyTarget{}, errors.New("节点服务器地址不可由普通用户探测")
			}
			if net.ParseIP(strings.TrimSpace(host)) == nil {
				hosts[strings.TrimSpace(host)] = publicIP
			}
		}
		configs = append(configs, config)
	}
	return speedtest.ProtocolLatencyTarget{
		ClashConfig: configs[0], DialerChain: configs[1:], Hosts: hosts,
		Timeout: timeout,
	}, nil
}

func (h *tcpingHandler) mihomoProbeConfigForNode(ctx context.Context, node storage.Node, cache map[string]cachedWireGuardProbePeer, timeout time.Duration) (string, error) {
	config := strings.TrimSpace(node.ClashConfig)
	if config == "" {
		config = strings.TrimSpace(node.ParsedConfig)
	}
	if config == "" {
		return "", fmt.Errorf("节点 %d 缺少 Mihomo 配置", node.ID)
	}
	configProtocol, err := mihomoProbeConfigProtocol(config)
	if err != nil {
		return "", fmt.Errorf("节点 %d 的 Mihomo 配置缺少有效协议类型", node.ID)
	}
	if canonicalProbeProtocolFamily(node.Protocol) != canonicalProbeProtocolFamily(configProtocol) {
		return "", fmt.Errorf("节点 %d 的协议与 Mihomo 配置不一致", node.ID)
	}
	if canonicalProbeProtocol(configProtocol) != "wireguard" {
		return config, nil
	}
	if strings.TrimSpace(node.OriginalServer) == "" || strings.TrimSpace(node.InboundTag) == "" {
		return "", errors.New("外部 WireGuard 需要专用探测 Peer，无法安全进行 Mihomo 实测")
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	peer, err := h.ensureManagedWireGuardProbePeer(probeCtx, node, cache)
	if err != nil {
		return "", err
	}
	return buildWireGuardMihomoProbeConfig(config, peer)
}

func mihomoProbeConfigProtocol(config string) (string, error) {
	var proxy map[string]interface{}
	if err := json.Unmarshal([]byte(config), &proxy); err != nil || proxy == nil {
		return "", errors.New("invalid Mihomo proxy config")
	}
	protocol := strings.TrimSpace(wireGuardStringValue(proxy["type"]))
	if protocol == "" {
		return "", errors.New("missing Mihomo proxy type")
	}
	return protocol, nil
}

func canonicalProbeProtocolFamily(protocol string) string {
	protocol = canonicalProbeProtocol(protocol)
	switch protocol {
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "socks", "socks5":
		return "socks"
	case "hysteria", "hysteria2":
		return "hysteria"
	default:
		return protocol
	}
}

func validatePublicMihomoProbeOverrides(config string) error {
	var proxy map[string]interface{}
	if err := json.Unmarshal([]byte(config), &proxy); err != nil || proxy == nil {
		return errors.New("节点 Mihomo 配置无效")
	}
	protocol := canonicalProbeProtocol(wireGuardStringValue(proxy["type"]))
	if protocol == "tuic" {
		if override := strings.TrimSpace(wireGuardStringValue(proxy["ip"])); override != "" {
			ip := net.ParseIP(override)
			if ip == nil || !isPublicProbeIP(ip) {
				return errors.New("节点包含普通用户不可用的 TUIC 目标地址覆盖")
			}
		}
	}
	if protocol == "wireguard" {
		if _, exists := proxy["peers"]; exists {
			return errors.New("多 Peer WireGuard 需要专用探测配置")
		}
	}
	if containsMihomoAuxiliaryEndpoint(proxy) {
		return errors.New("节点包含普通用户不可验证的辅助连接目标")
	}
	return nil
}

func containsMihomoAuxiliaryEndpoint(value interface{}) bool {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", "-"))
			if normalized == "download-settings" || normalized == "server-url" || normalized == "stun-servers" {
				return true
			}
			if containsMihomoAuxiliaryEndpoint(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range typed {
			if containsMihomoAuxiliaryEndpoint(child) {
				return true
			}
		}
	}
	return false
}

func canonicalProbeProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	switch protocol {
	case "wg":
		return "wireguard"
	case "hy2":
		return "hysteria2"
	default:
		return protocol
	}
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
		if (err != nil || port <= 0) && canonicalProbeProtocol(jsonRawString(config["type"])) == "mieru" {
			port, err = firstMieruPort(config["port-range"])
		}
		if strings.TrimSpace(host) != "" && err == nil && port > 0 && port <= 65535 {
			return strings.TrimSpace(host), port, nil
		}
	}
	return "", 0, errors.New("missing server or port")
}

func jsonRawString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func firstMieruPort(raw json.RawMessage) (int, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, errors.New("invalid Mieru port range")
	}
	firstRange := strings.TrimSpace(strings.SplitN(value, ",", 2)[0])
	startText, endText, hasRange := strings.Cut(firstRange, "-")
	start, err := strconv.Atoi(strings.TrimSpace(startText))
	if err != nil || start <= 0 || start > 65535 {
		return 0, errors.New("invalid Mieru port range")
	}
	if hasRange {
		end, endErr := strconv.Atoi(strings.TrimSpace(endText))
		if endErr != nil || end < start || end > 65535 {
			return 0, errors.New("invalid Mieru port range")
		}
	}
	return start, nil
}

func jsonInteger(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, errors.New("missing number")
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		if value, err := strconv.Atoi(number.String()); err == nil {
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
	if milliseconds < 500 {
		milliseconds = 500
	}
	if milliseconds > 30000 {
		milliseconds = 30000
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func (h *tcpingHandler) ensureManagedWireGuardProbePeer(ctx context.Context, node storage.Node, cache map[string]cachedWireGuardProbePeer) (*storage.WireGuardProbePeer, error) {
	cacheKey := strings.TrimSpace(node.OriginalServer) + "\x00" + strings.TrimSpace(node.InboundTag)
	if cached, ok := cache[cacheKey]; ok {
		return cached.peer, cached.err
	}
	peer, err := h.ensureManagedWireGuardProbePeerUncached(ctx, node)
	cache[cacheKey] = cachedWireGuardProbePeer{peer: peer, err: err}
	return peer, err
}

func (h *tcpingHandler) ensureManagedWireGuardProbePeerUncached(ctx context.Context, node storage.Node) (*storage.WireGuardProbePeer, error) {
	server, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
	if err != nil || server == nil {
		return nil, errors.New("找不到 WireGuard 所属的受管服务器")
	}
	resource, err := h.repo.GetManagedInboundResourceByServerTag(ctx, server.ID, node.InboundTag)
	if err != nil || resource == nil || canonicalProbeProtocol(resource.Protocol) != "wireguard" {
		return nil, errors.New("找不到 WireGuard 专用探测资源")
	}
	if strings.TrimSpace(resource.MutationID) == "" {
		return nil, errors.New("该受管 WireGuard 入站缺少可信的变更所有权，无法安全添加探测 Peer")
	}
	peer, peerErr := h.repo.GetWireGuardProbePeer(ctx, resource.ID)
	if peerErr == nil && peer.State == storage.WireGuardProbePeerStateActive {
		return peer, nil
	}
	if peerErr != nil && !errors.Is(peerErr, storage.ErrWireGuardProbePeerNotFound) {
		return nil, errors.New("无法读取 WireGuard 专用探测凭据")
	}
	if h.remote == nil {
		return nil, errors.New("受管服务器探测通道不可用")
	}

	leasedCtx, release, err := h.repo.AcquireRemoteServerExclusiveMutationLease(ctx, server.ID)
	if err != nil {
		return nil, errors.New("WireGuard 探测 Peer 正在被其他服务器变更占用")
	}
	defer release()

	resource, err = h.repo.GetManagedInboundResourceByServerTag(leasedCtx, server.ID, node.InboundTag)
	if err != nil || resource == nil || canonicalProbeProtocol(resource.Protocol) != "wireguard" {
		return nil, errors.New("找不到 WireGuard 专用探测资源")
	}
	if strings.TrimSpace(resource.MutationID) == "" {
		return nil, errors.New("该受管 WireGuard 入站缺少可信的变更所有权，无法安全添加探测 Peer")
	}
	peer, err = h.repo.GetWireGuardProbePeer(leasedCtx, resource.ID)
	if err == nil && peer.State == storage.WireGuardProbePeerStateActive {
		return peer, nil
	}
	if err != nil && !errors.Is(err, storage.ErrWireGuardProbePeerNotFound) {
		return nil, errors.New("无法读取 WireGuard 专用探测凭据")
	}
	peerMissing := errors.Is(err, storage.ErrWireGuardProbePeerNotFound)
	body, err := h.remote.ForwardToServer(leasedCtx, server.ID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return nil, errors.New("无法读取受管 WireGuard 入站")
	}
	inbound, err := managedWireGuardInboundForMutation(
		body,
		node.InboundTag,
		managedWireGuardInboundPort(node),
		resource.MutationID,
	)
	if err != nil {
		return nil, err
	}

	if peerMissing {
		peer, err = createWireGuardProbePeerForInbound(leasedCtx, h.repo, resource.ID, inbound)
	}
	if err != nil {
		return nil, errors.New("无法准备 WireGuard 专用探测凭据")
	}
	present, err := wireGuardInboundHasProbePeer(inbound, peer)
	if err != nil {
		return nil, err
	}
	if !present {
		if err := appendWireGuardProbePeer(inbound, peer); err != nil {
			return nil, err
		}
		stripManagedInboundRuntimeFields(inbound)
		payload, marshalErr := json.Marshal(map[string]interface{}{
			"action": "add", "inbound": inbound, "mutation_id": resource.MutationID,
		})
		if marshalErr != nil {
			return nil, errors.New("无法生成 WireGuard 探测 Peer 变更")
		}
		result, forwardErr := h.remote.ForwardToServer(leasedCtx, server.ID, http.MethodPost, "/api/child/inbounds", payload)
		if forwardErr != nil {
			return nil, errors.New("Agent 未能配置 WireGuard 专用探测 Peer")
		}
		if ackErr := validateManagedWireGuardMutationACK(result, resource.MutationID); ackErr != nil {
			return nil, errors.New("Agent 未确认 WireGuard 专用探测 Peer")
		}
	}
	if err := updateWireGuardProbeResourceMetadata(leasedCtx, h.repo, resource, inbound); err != nil {
		return nil, errors.New("WireGuard 探测 Peer 已配置，但公开元数据同步失败")
	}
	peer, err = h.repo.MarkWireGuardProbePeerActive(leasedCtx, resource.ID)
	if err != nil {
		return nil, errors.New("WireGuard 探测 Peer 状态保存失败")
	}
	return peer, nil
}

func managedWireGuardInboundPort(node storage.Node) int {
	if strings.TrimSpace(node.RelayOrigServer) != "" {
		if node.RelayOrigPort > 0 && node.RelayOrigPort <= 65535 {
			return node.RelayOrigPort
		}
		return 0
	}
	_, port, _ := nodeProbeAddress(node)
	return port
}

func managedWireGuardInboundFromInventory(body []byte, expectedTag string, expectedPort int) (map[string]interface{}, error) {
	return managedWireGuardInboundForMutation(body, expectedTag, expectedPort, "")
}

func managedWireGuardInboundForMutation(body []byte, expectedTag string, expectedPort int, expectedMutationID string) (map[string]interface{}, error) {
	var inventory struct {
		Success            *bool                    `json:"success"`
		MutationFenceKnown bool                     `json:"mutation_fence_known"`
		MutationOwners     map[string]string        `json:"mutation_owners"`
		Inbounds           []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(body, &inventory); err != nil {
		return nil, errors.New("受管服务器返回了无效的入站状态")
	}
	if inventory.Success == nil || !*inventory.Success {
		return nil, errors.New("受管服务器无法读取 WireGuard 入站状态")
	}
	expectedTag = strings.TrimSpace(expectedTag)
	expectedMutationID = strings.TrimSpace(expectedMutationID)
	if expectedMutationID != "" {
		if !inventory.MutationFenceKnown {
			return nil, errors.New("Agent 未提供可信的 WireGuard 入站所有权清单")
		}
		if strings.TrimSpace(inventory.MutationOwners[expectedTag]) != expectedMutationID {
			return nil, errors.New("WireGuard 入站已由另一代配置持有，拒绝添加探测 Peer")
		}
	}
	var matched map[string]interface{}
	for _, inbound := range inventory.Inbounds {
		if strings.TrimSpace(wireGuardStringValue(inbound["tag"])) != expectedTag {
			continue
		}
		if matched != nil {
			return nil, errors.New("受管服务器返回了重复的 WireGuard 入站 Tag")
		}
		matched = inbound
	}
	if matched != nil {
		inbound := matched
		if canonicalProbeProtocol(wireGuardStringValue(inbound["protocol"])) != "wireguard" {
			return nil, errors.New("对应入站已不再是 WireGuard")
		}
		if expectedPort > 0 {
			port, ok := wireGuardNumericValue(inbound["port"])
			if !ok || port != float64(expectedPort) {
				return nil, errors.New("WireGuard 入站端口与节点配置不一致")
			}
		}
		if strings.TrimSpace(wireGuardStringValue(inbound["_runtime_status"])) != "running" {
			return nil, errors.New("WireGuard 入站当前未运行")
		}
		return inbound, nil
	}
	return nil, errors.New("受管服务器上未找到对应的 WireGuard 入站")
}

func inspectManagedWireGuardInventory(body []byte, expectedTag string, expectedPort int) error {
	_, err := managedWireGuardInboundFromInventory(body, expectedTag, expectedPort)
	return err
}

func createWireGuardProbePeerForInbound(ctx context.Context, repo *storage.TrafficRepository, resourceID int64, inbound map[string]interface{}) (*storage.WireGuardProbePeer, error) {
	peer, err := newWireGuardProbePeerForInbound(inbound)
	if err != nil {
		return nil, err
	}
	peer.ResourceID = resourceID
	return repo.CreateWireGuardProbePeer(ctx, peer)
}

func newWireGuardProbePeerForInbound(inbound map[string]interface{}) (storage.WireGuardProbePeer, error) {
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return storage.WireGuardProbePeer{}, err
	}
	privateKey := base64.StdEncoding.EncodeToString(privateBytes)
	publicKey, err := managedWireGuardPublicKey(privateKey)
	if err != nil {
		return storage.WireGuardProbePeer{}, err
	}
	addresses, err := allocateWireGuardProbeAddresses(inbound)
	if err != nil {
		return storage.WireGuardProbePeer{}, err
	}
	return storage.WireGuardProbePeer{
		PublicKey: publicKey, PrivateKey: privateKey,
		Addresses: addresses, State: storage.WireGuardProbePeerStatePending,
	}, nil
}

func allocateWireGuardProbeAddresses(inbound map[string]interface{}) ([]string, error) {
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		return nil, errors.New("WireGuard 入站缺少 settings")
	}
	occupied := make([]netip.Prefix, 0)
	seeds := make([]netip.Addr, 0)
	addValue := func(value string, seed bool) {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			if address, addressErr := netip.ParseAddr(value); addressErr == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
			} else {
				return
			}
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits())
		occupied = append(occupied, prefix)
		if seed && prefix.Bits() == prefix.Addr().BitLen() {
			seeds = append(seeds, prefix.Addr())
		}
	}
	for _, value := range wireGuardStringValues(settings["address"]) {
		addValue(value, false)
	}
	for _, rawPeer := range wireGuardInterfaceSlice(settings["peers"]) {
		peer, _ := rawPeer.(map[string]interface{})
		for _, value := range wireGuardStringValues(peer["allowedIPs"]) {
			addValue(value, true)
		}
	}
	if len(seeds) == 0 {
		return nil, errors.New("WireGuard 入站没有可用于分配探测地址的客户端主机地址")
	}
	usedFamily := make(map[bool]bool)
	addresses := make([]string, 0, 2)
	for _, seed := range seeds {
		isV4 := seed.Is4()
		if usedFamily[isV4] {
			continue
		}
		candidate := seed
		for attempts := 0; attempts < 65536; attempts++ {
			candidate = candidate.Next()
			if !candidate.IsValid() || candidate.IsUnspecified() || candidate.IsMulticast() {
				continue
			}
			conflict := false
			for _, prefix := range occupied {
				if prefix.Addr().Is4() == candidate.Is4() && prefix.Contains(candidate) {
					conflict = true
					break
				}
			}
			if conflict {
				continue
			}
			addresses = append(addresses, netip.PrefixFrom(candidate, candidate.BitLen()).String())
			usedFamily[isV4] = true
			break
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("WireGuard 入站没有可用的专用探测地址")
	}
	return addresses, nil
}

func wireGuardInboundHasProbePeer(inbound map[string]interface{}, probePeer *storage.WireGuardProbePeer) (bool, error) {
	_, peers, err := wireGuardInboundProbePeers(inbound)
	if err != nil {
		return false, err
	}
	probePrefixes, err := wireGuardProbePrefixes(probePeer.Addresses)
	if err != nil || len(probePrefixes) == 0 {
		return false, errors.New("WireGuard 专用探测地址无效")
	}
	matched := false
	for _, peer := range peers {
		peerAddresses := wireGuardStringValues(peer["allowedIPs"])
		peerPrefixes, prefixErr := wireGuardProbePrefixes(peerAddresses)
		if prefixErr != nil || len(peerPrefixes) == 0 {
			return false, errors.New("WireGuard 入站 Peer 的 allowedIPs 无效")
		}
		if !equalManagedWireGuardKeys(wireGuardStringValue(peer["publicKey"]), probePeer.PublicKey) {
			if wireGuardPrefixesOverlap(probePrefixes, peerPrefixes) {
				return false, errors.New("WireGuard 专用探测地址已被其他 Peer 占用")
			}
			continue
		}
		if matched {
			return false, errors.New("WireGuard 专用探测 Peer 公钥重复")
		}
		matched = true
		existing := normalizedWireGuardStrings(peerAddresses)
		expected := normalizedWireGuardStrings(probePeer.Addresses)
		if !sameWireGuardStringSet(existing, expected) {
			return false, errors.New("WireGuard 专用探测 Peer 的地址与本地记录不一致")
		}
	}
	return matched, nil
}

func wireGuardProbePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, errors.New("empty WireGuard address")
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, errors.New("invalid WireGuard address")
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		address := prefix.Addr()
		bits := prefix.Bits()
		if address.Is4In6() {
			address = address.Unmap()
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return nil, errors.New("invalid WireGuard prefix")
		}
		prefixes = append(prefixes, netip.PrefixFrom(address, bits).Masked())
	}
	return prefixes, nil
}

func wireGuardPrefixesOverlap(left, right []netip.Prefix) bool {
	for _, leftPrefix := range left {
		for _, rightPrefix := range right {
			if leftPrefix.Overlaps(rightPrefix) {
				return true
			}
		}
	}
	return false
}

func wireGuardInboundProbePeers(inbound map[string]interface{}) (map[string]interface{}, []map[string]interface{}, error) {
	settings, ok := inbound["settings"].(map[string]interface{})
	if !ok || settings == nil {
		return nil, nil, errors.New("WireGuard 入站缺少有效 settings")
	}
	rawPeers, exists := settings["peers"]
	if !exists {
		return nil, nil, errors.New("WireGuard 入站缺少 peers")
	}
	items := wireGuardInterfaceSlice(rawPeers)
	if items == nil {
		return nil, nil, errors.New("WireGuard 入站 peers 格式无效")
	}
	peers := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		peer, ok := item.(map[string]interface{})
		if !ok || peer == nil {
			return nil, nil, errors.New("WireGuard 入站 peer 格式无效")
		}
		peers = append(peers, peer)
	}
	return settings, peers, nil
}

func sameWireGuardStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		values[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := values[value]; !exists {
			return false
		}
	}
	return true
}

func appendWireGuardProbePeer(inbound map[string]interface{}, probePeer *storage.WireGuardProbePeer) error {
	present, err := wireGuardInboundHasProbePeer(inbound, probePeer)
	if err != nil {
		return err
	}
	if present {
		return errors.New("WireGuard 专用探测 Peer 已存在")
	}
	settings, peers, err := wireGuardInboundProbePeers(inbound)
	if err != nil {
		return err
	}
	items := make([]interface{}, 0, len(peers)+1)
	for _, peer := range peers {
		items = append(items, peer)
	}
	settings["peers"] = append(items, map[string]interface{}{
		"publicKey": probePeer.PublicKey, "allowedIPs": probePeer.Addresses, "keepAlive": 0,
	})
	return nil
}

func stripManagedInboundRuntimeFields(inbound map[string]interface{}) {
	for key := range inbound {
		if strings.HasPrefix(key, "_") {
			delete(inbound, key)
		}
	}
}

func updateWireGuardProbeResourceMetadata(ctx context.Context, repo *storage.TrafficRepository, resource *storage.ManagedInboundResource, inbound map[string]interface{}) error {
	metadata, err := managedWireGuardPublicMetadataFromInbound(inbound)
	if err != nil {
		return err
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	resource.PublicMetadataJSON = metadataJSON
	_, err = repo.UpsertManagedInboundResource(ctx, *resource)
	return err
}

func buildWireGuardMihomoProbeConfig(raw string, peer *storage.WireGuardProbePeer) (string, error) {
	var proxy map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &proxy); err != nil || proxy == nil {
		return "", errors.New("WireGuard 节点 Mihomo 配置无效")
	}
	if canonicalProbeProtocol(wireGuardStringValue(proxy["type"])) != "wireguard" {
		return "", errors.New("WireGuard 节点 Mihomo 配置协议不匹配")
	}
	proxy["private-key"] = peer.PrivateKey
	delete(proxy, "pre-shared-key")
	delete(proxy, "peers")
	delete(proxy, "ip")
	delete(proxy, "ipv6")
	for _, value := range peer.Addresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", errors.New("WireGuard 专用探测地址无效")
		}
		if prefix.Addr().Is4() {
			proxy["ip"] = prefix.Addr().String()
		} else {
			proxy["ipv6"] = prefix.Addr().String()
		}
	}
	encoded, err := json.Marshal(proxy)
	if err != nil {
		return "", errors.New("无法生成 WireGuard Mihomo 探测配置")
	}
	return string(encoded), nil
}
