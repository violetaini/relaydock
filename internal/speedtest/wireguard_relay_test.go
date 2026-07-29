package speedtest

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestConfiguredMihomoWireGuardEgressPort(t *testing.T) {
	t.Run("disabled when empty", func(t *testing.T) {
		t.Setenv(mihomoWireGuardEgressPortEnv, "")
		port, enabled, err := configuredMihomoWireGuardEgressPort()
		if err != nil || enabled || port != 0 {
			t.Fatalf("configured port = (%d, %v, %v), want disabled", port, enabled, err)
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Setenv(mihomoWireGuardEgressPortEnv, " 443 ")
		port, enabled, err := configuredMihomoWireGuardEgressPort()
		if err != nil || !enabled || port != 443 {
			t.Fatalf("configured port = (%d, %v, %v), want (443, true, nil)", port, enabled, err)
		}
	})

	for _, value := range []string{"0", "65536", "not-a-port"} {
		t.Run("invalid "+value, func(t *testing.T) {
			t.Setenv(mihomoWireGuardEgressPortEnv, value)
			if _, _, err := configuredMihomoWireGuardEgressPort(); err == nil {
				t.Fatalf("configuredMihomoWireGuardEgressPort() accepted %q", value)
			}
		})
	}
}

func TestMihomoWireGuardRelayUsesFixedSourcePortAndValidatesRemote(t *testing.T) {
	resetProcessWireGuardRelayHubForTest(t)
	remote := listenUDP4(t)
	defer remote.Close()
	egressPort := unusedUDP4Port(t)
	t.Setenv(mihomoWireGuardEgressPortEnv, strconv.Itoa(egressPort))

	proxy := map[string]interface{}{
		"name": "wireguard-probe", "type": "wireguard",
		"server": "edge.example.test", "port": remote.LocalAddr().(*net.UDPAddr).Port,
	}
	relays, err := prepareMihomoWireGuardRelays(t.Context(), []map[string]interface{}{proxy}, map[string]string{
		"EDGE.EXAMPLE.TEST.": "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("prepareMihomoWireGuardRelays() error = %v", err)
	}
	defer closeMihomoWireGuardRelays(relays)
	if len(relays) != 1 {
		t.Fatalf("relay count = %d, want 1", len(relays))
	}
	if proxy["server"] != "127.0.0.1" {
		t.Fatalf("rewritten server = %#v, want loopback", proxy["server"])
	}
	localPort, err := parseWireGuardProxyPort(proxy["port"])
	if err != nil || localPort == remote.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("rewritten port = %#v, want a distinct loopback relay port", proxy["port"])
	}

	client := listenUDP4(t)
	defer client.Close()
	const clientIndex = uint32(0x10203040)
	initiation := wireGuardTestPacket(1, clientIndex, 0)
	if _, err := client.WriteToUDP(initiation, loopbackUDPAddr(localPort)); err != nil {
		t.Fatalf("send initiation: %v", err)
	}
	forwarded, upstreamSource := readUDP4(t, remote, time.Second)
	if string(forwarded) != string(initiation) {
		t.Fatalf("forwarded initiation = %x, want %x", forwarded, initiation)
	}
	if upstreamSource.Port != egressPort {
		t.Fatalf("upstream source port = %d, want configured %d", upstreamSource.Port, egressPort)
	}

	response := wireGuardTestPacket(2, 0x50607080, clientIndex)
	attacker := listenUDP4(t)
	defer attacker.Close()
	if _, err := attacker.WriteToUDP(response, upstreamSource); err != nil {
		t.Fatalf("send spoofed response: %v", err)
	}
	assertUDPReadTimesOut(t, client, 100*time.Millisecond)

	if _, err := remote.WriteToUDP(response, upstreamSource); err != nil {
		t.Fatalf("send valid response: %v", err)
	}
	got, _ := readUDP4(t, client, time.Second)
	if string(got) != string(response) {
		t.Fatalf("relayed response = %x, want %x", got, response)
	}
}

func TestMihomoWireGuardRelayRoutesConcurrentSameEndpointFlowsAndCleansUp(t *testing.T) {
	resetProcessWireGuardRelayHubForTest(t)
	remote := listenUDP4(t)
	defer remote.Close()
	egressPort := unusedUDP4Port(t)
	t.Setenv(mihomoWireGuardEgressPortEnv, strconv.Itoa(egressPort))

	remotePort := remote.LocalAddr().(*net.UDPAddr).Port
	proxies := []map[string]interface{}{
		{"name": "wireguard-a", "type": "wireguard", "server": "127.0.0.1", "port": remotePort},
		{"name": "wireguard-b", "type": "wireguard", "server": "127.0.0.1", "port": remotePort},
	}
	relays, err := prepareMihomoWireGuardRelays(t.Context(), proxies, nil)
	if err != nil {
		t.Fatalf("prepareMihomoWireGuardRelays() error = %v", err)
	}
	if len(relays) != 2 {
		t.Fatalf("relay count = %d, want 2", len(relays))
	}
	closed := false
	defer func() {
		if !closed {
			closeMihomoWireGuardRelays(relays)
		}
	}()

	clients := []*net.UDPConn{listenUDP4(t), listenUDP4(t)}
	defer clients[0].Close()
	defer clients[1].Close()
	indexes := []uint32{0x11111111, 0x22222222}
	localPorts := make([]int, len(proxies))
	for index, proxy := range proxies {
		localPorts[index], err = parseWireGuardProxyPort(proxy["port"])
		if err != nil {
			t.Fatalf("parse rewritten proxy %d port: %v", index, err)
		}
		if _, err := clients[index].WriteToUDP(wireGuardTestPacket(1, indexes[index], 0), loopbackUDPAddr(localPorts[index])); err != nil {
			t.Fatalf("send initiation %d: %v", index, err)
		}
	}
	if localPorts[0] == localPorts[1] {
		t.Fatalf("two proxies share loopback relay port %d", localPorts[0])
	}

	upstreamSources := make(map[uint32]*net.UDPAddr, len(indexes))
	for range indexes {
		packet, source := readUDP4(t, remote, time.Second)
		index, ok := wireGuardSenderIndex(packet)
		if !ok {
			t.Fatalf("forwarded packet has no WireGuard sender index: %x", packet)
		}
		upstreamSources[index] = source
	}
	if len(upstreamSources) != 2 {
		t.Fatalf("forwarded sender indexes = %#v, want both flows", upstreamSources)
	}
	if upstreamSources[indexes[0]].String() != upstreamSources[indexes[1]].String() {
		t.Fatalf("flows used different upstream sockets: %v and %v", upstreamSources[indexes[0]], upstreamSources[indexes[1]])
	}

	for index := len(indexes) - 1; index >= 0; index-- {
		response := wireGuardTestPacket(2, uint32(0x33333333+index), indexes[index])
		if _, err := remote.WriteToUDP(response, upstreamSources[indexes[index]]); err != nil {
			t.Fatalf("send response %d: %v", index, err)
		}
	}
	for index, client := range clients {
		packet, _ := readUDP4(t, client, time.Second)
		receiver, ok := wireGuardReceiverIndex(packet)
		if !ok || receiver != indexes[index] {
			t.Fatalf("client %d received packet %x with receiver %x, want %x", index, packet, receiver, indexes[index])
		}
	}

	closeMihomoWireGuardRelays(relays)
	closed = true
	for index, client := range clients {
		if _, err := client.WriteToUDP(wireGuardTestPacket(1, indexes[index]+10, 0), loopbackUDPAddr(localPorts[index])); err != nil {
			t.Fatalf("send after relay cleanup %d: %v", index, err)
		}
	}
	assertUDPReadTimesOut(t, remote, 150*time.Millisecond)

	staleResponse := wireGuardTestPacket(4, 0, indexes[0])
	if _, err := remote.WriteToUDP(staleResponse, upstreamSources[indexes[0]]); err != nil {
		t.Fatalf("send stale response after cleanup: %v", err)
	}
	assertUDPReadTimesOut(t, clients[0], 150*time.Millisecond)
}

func TestPrepareMihomoWireGuardRelaysSkipsDialerAndFullPeerConfigs(t *testing.T) {
	t.Setenv(mihomoWireGuardEgressPortEnv, "54321")
	proxies := []map[string]interface{}{
		{
			"type": "wireguard", "server": "203.0.113.10", "port": 51820,
			"dialer-proxy": "upstream",
		},
		{
			"type": "wireguard", "server": "203.0.113.11", "port": 51821,
			"peers": []interface{}{},
		},
	}
	relays, err := prepareMihomoWireGuardRelays(t.Context(), proxies, nil)
	if err != nil {
		t.Fatalf("prepareMihomoWireGuardRelays() error = %v", err)
	}
	if len(relays) != 0 {
		t.Fatalf("relay count = %d, want skipped configs", len(relays))
	}
	if proxies[0]["server"] != "203.0.113.10" || proxies[0]["port"] != 51820 {
		t.Fatalf("dialer proxy was rewritten: %#v", proxies[0])
	}
	if proxies[1]["server"] != "203.0.113.11" || proxies[1]["port"] != 51821 {
		t.Fatalf("full peer proxy was rewritten: %#v", proxies[1])
	}
}

func TestStartMihomoLatencySessionRewritesOnlyItsWireGuardCopy(t *testing.T) {
	resetProcessWireGuardRelayHubForTest(t)
	root, err := os.MkdirTemp("/tmp", "arcway-wg-relay-test-")
	if err != nil {
		t.Fatalf("MkdirTemp(): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Chdir(root)
	helper, helperErrors := writeMihomoLatencyHelper(t)
	egressPort := unusedUDP4Port(t)
	t.Setenv(mihomoWireGuardEgressPortEnv, strconv.Itoa(egressPort))

	proxy := map[string]interface{}{
		"name": "arcway-probe-1", "type": "wireguard", "server": "127.0.0.1", "port": 51820,
	}
	targets := []preparedProtocolLatencyTarget{{
		name: "arcway-probe-1", proxies: []map[string]interface{}{proxy}, timeout: time.Second,
	}}
	session, err := startMihomoLatencySession(context.Background(), helper, targets)
	if err != nil {
		diagnostics, _ := os.ReadFile(helperErrors)
		t.Fatalf("startMihomoLatencySession() error = %v; helper diagnostics = %s", err, diagnostics)
	}
	defer session.stop()
	if proxy["server"] != "127.0.0.1" || proxy["port"] != 51820 {
		t.Fatalf("session rewrite mutated reusable prepared proxy: %#v", proxy)
	}
	if len(session.wireGuardRelays) != 1 {
		t.Fatalf("session WireGuard relay count = %d, want 1", len(session.wireGuardRelays))
	}
}

func TestCloneProtocolLatencyProxyIsDeep(t *testing.T) {
	original := map[string]interface{}{
		"server": "edge.example.test",
		"peers":  []interface{}{map[string]interface{}{"server": "peer.example.test"}},
	}
	cloned := cloneProtocolLatencyProxy(original)
	cloned["server"] = "127.0.0.1"
	cloned["peers"].([]interface{})[0].(map[string]interface{})["server"] = "127.0.0.2"
	if original["server"] != "edge.example.test" {
		t.Fatalf("top-level clone mutated original: %#v", original)
	}
	peer := original["peers"].([]interface{})[0].(map[string]interface{})
	if peer["server"] != "peer.example.test" {
		t.Fatalf("nested clone mutated original: %#v", original)
	}
}

func resetProcessWireGuardRelayHubForTest(t *testing.T) {
	t.Helper()
	reset := func() {
		processWireGuardRelayHubState.Lock()
		hub := processWireGuardRelayHubState.hub
		processWireGuardRelayHubState.hub = nil
		processWireGuardRelayHubState.port = 0
		processWireGuardRelayHubState.Unlock()
		_ = hub.Close()
	}
	reset()
	t.Cleanup(reset)
}

func listenUDP4(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", loopbackUDPAddr(0))
	if err != nil {
		t.Fatalf("ListenUDP(): %v", err)
	}
	return conn
}

func unusedUDP4Port(t *testing.T) int {
	t.Helper()
	conn := listenUDP4(t)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("close UDP port reservation: %v", err)
	}
	return port
}

func loopbackUDPAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

func readUDP4(t *testing.T, conn *net.UDPConn, timeout time.Duration) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	buffer := make([]byte, 64*1024)
	count, source, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("ReadFromUDP(): %v", err)
	}
	return append([]byte(nil), buffer[:count]...), source
}

func assertUDPReadTimesOut(t *testing.T, conn *net.UDPConn, timeout time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	buffer := make([]byte, 64)
	_, _, err := conn.ReadFromUDP(buffer)
	var networkErr net.Error
	if !errors.As(err, &networkErr) || !networkErr.Timeout() {
		t.Fatalf("ReadFromUDP() error = %v, want timeout", err)
	}
}

func wireGuardTestPacket(messageType, senderIndex, receiverIndex uint32) []byte {
	size := 8
	if messageType == 2 {
		size = 12
	}
	packet := make([]byte, size)
	binary.LittleEndian.PutUint32(packet[:4], messageType)
	if messageType == 3 || messageType == 4 {
		binary.LittleEndian.PutUint32(packet[4:8], receiverIndex)
	} else {
		binary.LittleEndian.PutUint32(packet[4:8], senderIndex)
	}
	if messageType == 2 {
		binary.LittleEndian.PutUint32(packet[8:12], receiverIndex)
	}
	return packet
}
