package speedtest

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const mihomoWireGuardEgressPortEnv = "ARCWAY_MIHOMO_WIREGUARD_EGRESS_PORT"

type wireGuardRelayRouteKey struct {
	endpoint string
	index    uint32
}

type wireGuardRelayRoute struct {
	relay     *wireGuardLocalRelay
	localAddr *net.UDPAddr
}

type wireGuardRelayConfigError struct {
	err error
}

func (e *wireGuardRelayConfigError) Error() string { return e.err.Error() }
func (e *wireGuardRelayConfigError) Unwrap() error { return e.err }

// wireGuardRelayHub owns the single fixed-port Internet-facing UDP socket.
// Individual Mihomo WireGuard proxies get separate loopback listeners so their
// first handshake can be associated with the original remote endpoint.
type wireGuardRelayHub struct {
	conn *net.UDPConn

	mu        sync.RWMutex
	closed    bool
	routes    map[wireGuardRelayRouteKey]wireGuardRelayRoute
	endpoints map[string]int
	relays    map[*wireGuardLocalRelay]struct{}
	wait      sync.WaitGroup
	closeOnce sync.Once
}

type wireGuardLocalRelay struct {
	hub         *wireGuardRelayHub
	conn        *net.UDPConn
	endpoint    *net.UDPAddr
	endpointKey string
	wait        sync.WaitGroup
	closeOnce   sync.Once
}

var processWireGuardRelayHubState struct {
	sync.Mutex
	hub  *wireGuardRelayHub
	port int
}

func configuredMihomoWireGuardEgressPort() (int, bool, error) {
	raw, exists := os.LookupEnv(mihomoWireGuardEgressPortEnv)
	if !exists || strings.TrimSpace(raw) == "" {
		return 0, false, nil
	}
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, false, fmt.Errorf("%s 必须是 1 到 65535 之间的 UDP 端口", mihomoWireGuardEgressPortEnv)
	}
	return port, true, nil
}

func prepareMihomoWireGuardRelays(ctx context.Context, proxies []map[string]interface{}, hosts map[string]string) ([]io.Closer, error) {
	port, enabled, err := configuredMihomoWireGuardEgressPort()
	if err != nil || !enabled {
		return nil, err
	}

	type relayCandidate struct {
		proxy    map[string]interface{}
		endpoint *net.UDPAddr
	}
	candidates := make([]relayCandidate, 0)
	for _, proxy := range proxies {
		if !isDirectSimplifiedWireGuardProxy(proxy) {
			continue
		}
		server := strings.TrimSpace(fmt.Sprint(proxy["server"]))
		remotePort, err := parseWireGuardProxyPort(proxy["port"])
		if err != nil {
			return nil, &wireGuardRelayConfigError{err: errors.New("WireGuard 节点的 Mihomo 端口无效")}
		}
		endpoint, err := resolveWireGuardRelayEndpoint(ctx, server, remotePort, hosts)
		if err != nil {
			return nil, &wireGuardRelayConfigError{err: errors.New("无法解析 WireGuard 节点的 Mihomo 端点")}
		}
		candidates = append(candidates, relayCandidate{proxy: proxy, endpoint: endpoint})
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	hub, err := processWireGuardRelayHub(port)
	if err != nil {
		return nil, fmt.Errorf("创建 WireGuard Mihomo 固定出口: %w", err)
	}
	closers := make([]io.Closer, 0, len(candidates))
	for _, candidate := range candidates {
		relay, err := hub.newLocalRelay(candidate.endpoint)
		if err != nil {
			closeMihomoWireGuardRelays(closers)
			return nil, fmt.Errorf("创建 WireGuard Mihomo 本地中继: %w", err)
		}
		closers = append(closers, relay)
		candidate.proxy["server"] = "127.0.0.1"
		candidate.proxy["port"] = relay.localAddr().Port
	}
	return closers, nil
}

func isDirectSimplifiedWireGuardProxy(proxy map[string]interface{}) bool {
	if strings.ToLower(strings.TrimSpace(fmt.Sprint(proxy["type"]))) != "wireguard" {
		return false
	}
	if value := strings.TrimSpace(fmt.Sprint(proxy["dialer-proxy"])); value != "" && value != "<nil>" {
		return false
	}
	// Mihomo's full WireGuard syntax stores endpoints under peers. A single
	// loopback listener cannot represent multiple remote peers, so leave those
	// configurations untouched.
	if _, hasPeers := proxy["peers"]; hasPeers {
		return false
	}
	return true
}

func parseWireGuardProxyPort(value interface{}) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(value)))
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("invalid WireGuard port")
	}
	return port, nil
}

func resolveWireGuardRelayEndpoint(ctx context.Context, server string, port int, hosts map[string]string) (*net.UDPAddr, error) {
	server = strings.TrimSpace(server)
	if server == "" || server == "<nil>" {
		return nil, errors.New("missing WireGuard server")
	}
	address := strings.Trim(server, "[]")
	if pinned := pinnedWireGuardRelayHost(server, hosts); pinned != "" {
		ip := net.ParseIP(strings.Trim(pinned, "[]"))
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("pinned WireGuard endpoint is not an IPv4 address")
		}
		return &net.UDPAddr{IP: append(net.IP(nil), ip.To4()...), Port: port}, nil
	}
	if ip := net.ParseIP(address); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return &net.UDPAddr{IP: append(net.IP(nil), ipv4...), Port: port}, nil
		}
		return nil, errors.New("the fixed WireGuard egress relay currently requires an IPv4 endpoint")
	}

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, server)
	if err != nil {
		return nil, err
	}
	for _, candidate := range addresses {
		if ipv4 := candidate.IP.To4(); ipv4 != nil {
			return &net.UDPAddr{IP: append(net.IP(nil), ipv4...), Port: port}, nil
		}
	}
	return nil, errors.New("WireGuard endpoint has no IPv4 address")
}

func pinnedWireGuardRelayHost(server string, hosts map[string]string) string {
	server = strings.TrimSuffix(strings.TrimSpace(server), ".")
	for host, address := range hosts {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(host), "."), server) {
			return strings.TrimSpace(address)
		}
	}
	return ""
}

func processWireGuardRelayHub(port int) (*wireGuardRelayHub, error) {
	processWireGuardRelayHubState.Lock()
	defer processWireGuardRelayHubState.Unlock()
	if processWireGuardRelayHubState.hub != nil {
		if processWireGuardRelayHubState.port != port {
			return nil, errors.New("WireGuard Mihomo 固定出口端口在进程运行期间发生变化")
		}
		return processWireGuardRelayHubState.hub, nil
	}
	hub, err := newWireGuardRelayHub(&net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, err
	}
	processWireGuardRelayHubState.hub = hub
	processWireGuardRelayHubState.port = port
	return hub, nil
}

func newWireGuardRelayHub(listenAddr *net.UDPAddr) (*wireGuardRelayHub, error) {
	conn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	hub := &wireGuardRelayHub{
		conn: conn, routes: make(map[wireGuardRelayRouteKey]wireGuardRelayRoute),
		endpoints: make(map[string]int), relays: make(map[*wireGuardLocalRelay]struct{}),
	}
	hub.wait.Add(1)
	go hub.readReplies()
	return hub, nil
}

func (h *wireGuardRelayHub) newLocalRelay(endpoint *net.UDPAddr) (*wireGuardLocalRelay, error) {
	if endpoint == nil || endpoint.IP.To4() == nil || endpoint.Port < 1 || endpoint.Port > 65535 {
		return nil, errors.New("invalid WireGuard relay endpoint")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	endpoint = cloneUDPAddr(endpoint)
	relay := &wireGuardLocalRelay{
		hub: h, conn: conn, endpoint: endpoint, endpointKey: wireGuardRelayEndpointKey(endpoint),
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	h.relays[relay] = struct{}{}
	h.endpoints[relay.endpointKey]++
	h.mu.Unlock()

	relay.wait.Add(1)
	go relay.forwardRequests()
	return relay, nil
}

func (h *wireGuardRelayHub) readReplies() {
	defer h.wait.Done()
	buffer := make([]byte, 64*1024)
	for {
		count, source, err := h.conn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		receiverIndex, ok := wireGuardReceiverIndex(buffer[:count])
		if !ok {
			continue
		}
		key := wireGuardRelayRouteKey{endpoint: wireGuardRelayEndpointKey(source), index: receiverIndex}
		h.mu.RLock()
		_, endpointActive := h.endpoints[key.endpoint]
		route, exists := h.routes[key]
		h.mu.RUnlock()
		if !endpointActive || !exists {
			continue
		}
		_, _ = route.relay.conn.WriteToUDP(buffer[:count], route.localAddr)
	}
}

func (r *wireGuardLocalRelay) forwardRequests() {
	defer r.wait.Done()
	buffer := make([]byte, 64*1024)
	for {
		count, source, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if senderIndex, ok := wireGuardSenderIndex(buffer[:count]); ok {
			if !r.hub.registerRoute(r, senderIndex, source) {
				continue
			}
		}
		_, _ = r.hub.conn.WriteToUDP(buffer[:count], r.endpoint)
	}
}

func (h *wireGuardRelayHub) registerRoute(relay *wireGuardLocalRelay, index uint32, localAddr *net.UDPAddr) bool {
	key := wireGuardRelayRouteKey{endpoint: relay.endpointKey, index: index}
	route := wireGuardRelayRoute{relay: relay, localAddr: cloneUDPAddr(localAddr)}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	if _, active := h.relays[relay]; !active {
		return false
	}
	if existing, exists := h.routes[key]; exists {
		if existing.relay != relay || existing.localAddr.String() != route.localAddr.String() {
			// Never let one concurrent handshake steal another proxy's route. The
			// initiating WireGuard peer will retry with a fresh sender index.
			return false
		}
	}
	h.routes[key] = route
	return true
}

func wireGuardSenderIndex(packet []byte) (uint32, bool) {
	if len(packet) < 8 {
		return 0, false
	}
	switch binary.LittleEndian.Uint32(packet[:4]) {
	case 1, 2:
		return binary.LittleEndian.Uint32(packet[4:8]), true
	default:
		return 0, false
	}
}

func wireGuardReceiverIndex(packet []byte) (uint32, bool) {
	if len(packet) < 8 {
		return 0, false
	}
	switch binary.LittleEndian.Uint32(packet[:4]) {
	case 2:
		if len(packet) < 12 {
			return 0, false
		}
		return binary.LittleEndian.Uint32(packet[8:12]), true
	case 3, 4:
		return binary.LittleEndian.Uint32(packet[4:8]), true
	default:
		return 0, false
	}
}

func wireGuardRelayEndpointKey(address *net.UDPAddr) string {
	if address == nil {
		return ""
	}
	ip := address.IP
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(address.Port))
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func (r *wireGuardLocalRelay) localAddr() *net.UDPAddr {
	return cloneUDPAddr(r.conn.LocalAddr().(*net.UDPAddr))
}

func (r *wireGuardLocalRelay) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	r.closeOnce.Do(func() {
		r.hub.mu.Lock()
		delete(r.hub.relays, r)
		if count := r.hub.endpoints[r.endpointKey]; count <= 1 {
			delete(r.hub.endpoints, r.endpointKey)
		} else {
			r.hub.endpoints[r.endpointKey] = count - 1
		}
		for key, route := range r.hub.routes {
			if route.relay == r {
				delete(r.hub.routes, key)
			}
		}
		r.hub.mu.Unlock()
		closeErr = r.conn.Close()
		r.wait.Wait()
	})
	return closeErr
}

func (h *wireGuardRelayHub) Close() error {
	if h == nil {
		return nil
	}
	var closeErr error
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		relays := make([]*wireGuardLocalRelay, 0, len(h.relays))
		for relay := range h.relays {
			relays = append(relays, relay)
		}
		h.mu.Unlock()
		closeErr = h.conn.Close()
		for _, relay := range relays {
			_ = relay.Close()
		}
		h.wait.Wait()
	})
	return closeErr
}

func closeMihomoWireGuardRelays(relays []io.Closer) {
	for index := len(relays) - 1; index >= 0; index-- {
		if relays[index] != nil {
			_ = relays[index].Close()
		}
	}
}

func cloneProtocolLatencyProxy(proxy map[string]interface{}) map[string]interface{} {
	if proxy == nil {
		return nil
	}
	cloned := make(map[string]interface{}, len(proxy))
	for key, value := range proxy {
		cloned[key] = cloneProtocolLatencyProxyValue(value)
	}
	return cloned
}

func cloneProtocolLatencyProxyValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		return cloneProtocolLatencyProxy(typed)
	case []interface{}:
		cloned := make([]interface{}, len(typed))
		for index, item := range typed {
			cloned[index] = cloneProtocolLatencyProxyValue(item)
		}
		return cloned
	default:
		return value
	}
}
