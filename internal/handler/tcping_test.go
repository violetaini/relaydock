package handler

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/speedtest"
	"github.com/violetaini/relaydock/internal/storage"
)

type fakeRemoteNodeProbeCall struct {
	serverID int64
	method   string
	path     string
	body     []byte
}

type fakeRemoteNodeProbeClient struct {
	mu       sync.Mutex
	calls    []fakeRemoteNodeProbeCall
	response []byte
	err      error
	forward  func(serverID int64, method, path string, body []byte) ([]byte, error)
}

func (f *fakeRemoteNodeProbeClient) ForwardToServer(_ context.Context, serverID int64, method, path string, body []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeRemoteNodeProbeCall{
		serverID: serverID, method: method, path: path, body: append([]byte(nil), body...),
	})
	forward := f.forward
	response := append([]byte(nil), f.response...)
	err := f.err
	f.mu.Unlock()
	if forward != nil {
		return forward(serverID, method, path, body)
	}
	return response, err
}

type fakeProtocolLatencyProber struct {
	mu      sync.Mutex
	targets []speedtest.ProtocolLatencyTarget
	results []speedtest.ProtocolLatencyResult
}

func (f *fakeProtocolLatencyProber) Probe(_ context.Context, targets []speedtest.ProtocolLatencyTarget) []speedtest.ProtocolLatencyResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets = append([]speedtest.ProtocolLatencyTarget(nil), targets...)
	return append([]speedtest.ProtocolLatencyResult(nil), f.results...)
}

func newTCPingTestRepository(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "tcping.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x51}, 32)); err != nil {
		_ = repo.Close()
		t.Fatalf("ConfigureNodeSecretEncryption: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func createTCPingAdmin(t *testing.T, repo *storage.TrafficRepository) {
	t.Helper()
	if err := repo.CreateUser(context.Background(), "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser admin: %v", err)
	}
}

func createTCPingNode(t *testing.T, repo *storage.TrafficRepository, name, protocol, server string, port int) storage.Node {
	t.Helper()
	config, err := json.Marshal(map[string]interface{}{
		"name": name, "type": protocol, "server": server, "port": port,
		"uuid": "00000000-0000-4000-8000-000000000001", "cipher": "aes-128-gcm", "password": "server-authoritative-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "admin", NodeName: name, Protocol: protocol,
		ParsedConfig: string(config), ClashConfig: string(config), Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode %s: %v", name, err)
	}
	return node
}

func wireGuardTCPingTestKeyPair(t *testing.T, fill byte) (string, string) {
	t.Helper()
	privateBytes := bytes.Repeat([]byte{fill}, 32)
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), base64.StdEncoding.EncodeToString(privateBytes)
}

func createTCPingWireGuardNode(t *testing.T, repo *storage.TrafficRepository) (storage.RemoteServer, storage.Node, *storage.ManagedInboundResource, string) {
	t.Helper()
	ctx := context.Background()
	server := storage.RemoteServer{
		Name: "Edge WG", Token: "agent-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "198.51.100.20", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	serverPublicKey, _ := wireGuardTCPingTestKeyPair(t, 0x31)
	_, customerPrivateKey := wireGuardTCPingTestKeyPair(t, 0x32)
	config, err := json.Marshal(map[string]interface{}{
		"name": "Managed WG", "type": "wireguard", "server": "wg.example.test", "port": 51820,
		"private-key": customerPrivateKey, "public-key": serverPublicKey, "ip": "10.66.66.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "Managed WG", Protocol: "wireguard",
		ParsedConfig: string(config), ClashConfig: string(config), Enabled: true,
		OriginalServer: server.Name, InboundTag: "wireguard-test",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	resource, err := repo.CreateManagedInboundResource(ctx, storage.ManagedInboundResource{
		ServerID: server.ID, DisplayName: "Managed WG", Protocol: "wireguard", InboundTag: "wireguard-test",
		MutationID: "wireguard-generation-1", EndpointHost: "wg.example.test", EndpointPort: 51820,
		PublicMetadataJSON: json.RawMessage(`{}`), CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("CreateManagedInboundResource: %v", err)
	}
	return server, node, resource, customerPrivateKey
}

func TestTCPingUsesNodeIDAndServerAuthoritativeMihomoConfig(t *testing.T) {
	repo := newTCPingTestRepository(t)
	createTCPingAdmin(t, repo)
	node := createTCPingNode(t, repo, "Authoritative VLESS", "vless", "203.0.113.40", 443)
	prober := &fakeProtocolLatencyProber{results: []speedtest.ProtocolLatencyResult{{Latency: 12.75}}}
	handler := newTCPingHandler(repo, nil, false, prober)

	requestBody, err := json.Marshal(TCPingRequest{
		NodeID: node.ID, Host: "127.0.0.1", Port: 1, Protocol: "wireguard", Timeout: 750,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/tcping", bytes.NewReader(requestBody))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response TCPingResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Success || response.Latency != 12.75 || response.Probe != "mihomo_url_test" || response.Error != "" {
		t.Fatalf("unexpected response: %+v", response)
	}
	prober.mu.Lock()
	defer prober.mu.Unlock()
	if len(prober.targets) != 1 {
		t.Fatalf("targets=%d want 1", len(prober.targets))
	}
	target := prober.targets[0]
	if target.ClashConfig != node.ClashConfig {
		t.Fatalf("target config did not come from stored node\ngot:  %s\nwant: %s", target.ClashConfig, node.ClashConfig)
	}
	if target.Timeout != 750*time.Millisecond || len(target.DialerChain) != 0 || len(target.Hosts) != 0 {
		t.Fatalf("unexpected authoritative target: %+v", target)
	}
	if bytes.Contains([]byte(target.ClashConfig), []byte("127.0.0.1")) {
		t.Fatalf("request-supplied host reached Mihomo target: %s", target.ClashConfig)
	}
}

func TestTCPingRejectsArbitraryTargetWithoutNodeID(t *testing.T) {
	repo := newTCPingTestRepository(t)
	createTCPingAdmin(t, repo)
	prober := &fakeProtocolLatencyProber{}
	handler := newTCPingHandler(repo, nil, false, prober)
	request := httptest.NewRequest(http.MethodPost, "/api/admin/tcping", bytes.NewBufferString(`{"host":"127.0.0.1","port":22}`))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	prober.mu.Lock()
	defer prober.mu.Unlock()
	if len(prober.targets) != 0 {
		t.Fatalf("arbitrary endpoint reached prober: %+v", prober.targets)
	}
}

func TestTCPingBatchPreservesOrderAndKeepsPerItemErrors(t *testing.T) {
	repo := newTCPingTestRepository(t)
	createTCPingAdmin(t, repo)
	first := createTCPingNode(t, repo, "First VLESS", "vless", "203.0.113.41", 443)
	second := createTCPingNode(t, repo, "Second Shadowsocks", "ss", "203.0.113.42", 8443)
	third := createTCPingNode(t, repo, "Third Trojan", "trojan", "203.0.113.43", 9443)
	prober := &fakeProtocolLatencyProber{results: []speedtest.ProtocolLatencyResult{
		{Latency: 21.5},
		{Latency: 32.25},
		{Err: errors.New("协议握手失败")},
	}}
	handler := newTCPingHandler(repo, nil, true, prober)
	body, err := json.Marshal([]TCPingRequest{
		{NodeID: first.ID, Timeout: 1000},
		{NodeID: 999999, Timeout: 1000},
		{NodeID: second.ID, Timeout: 2000},
		{NodeID: third.ID, Timeout: 3000},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/tcping/batch", bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var responses []TCPingResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &responses); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(responses) != 4 {
		t.Fatalf("unexpected responses: %+v", responses)
	}
	if !responses[0].Success || responses[0].Latency != 21.5 || responses[0].Probe != "mihomo_url_test" {
		t.Fatalf("first response lost position: %+v", responses[0])
	}
	if responses[1].Success || responses[1].Error == "" || responses[1].Probe != "mihomo_url_test" {
		t.Fatalf("missing-node item error lost position: %+v", responses[1])
	}
	if !responses[2].Success || responses[2].Latency != 32.25 || responses[2].Probe != "mihomo_url_test" {
		t.Fatalf("second response lost position: %+v", responses[2])
	}
	if responses[3].Success || !bytes.Contains([]byte(responses[3].Error), []byte("协议握手失败")) || responses[3].Probe != "mihomo_url_test" {
		t.Fatalf("probe item error lost position: %+v", responses[3])
	}

	prober.mu.Lock()
	defer prober.mu.Unlock()
	if len(prober.targets) != 3 {
		t.Fatalf("targets=%d want 3", len(prober.targets))
	}
	for index, want := range []storage.Node{first, second, third} {
		if prober.targets[index].ClashConfig != want.ClashConfig {
			t.Fatalf("target %d order/config mismatch: %s", index, prober.targets[index].ClashConfig)
		}
	}
}

func TestTCPingManagedWireGuardUsesDedicatedProbePeerForMihomo(t *testing.T) {
	repo := newTCPingTestRepository(t)
	createTCPingAdmin(t, repo)
	server, node, resource, customerPrivateKey := createTCPingWireGuardNode(t, repo)
	serverPublicKey, serverPrivateKey := wireGuardTCPingTestKeyPair(t, 0x31)
	customerPublicKey, _ := wireGuardTCPingTestKeyPair(t, 0x32)
	inventory, err := json.Marshal(map[string]interface{}{
		"success":              true,
		"mutation_fence_known": true,
		"mutation_owners":      map[string]string{"wireguard-test": resource.MutationID},
		"inbounds": []map[string]interface{}{{
			"tag": "wireguard-test", "protocol": "wireguard", "port": 51820, "_runtime_status": "running",
			"settings": map[string]interface{}{
				"secretKey": serverPrivateKey,
				"address":   []string{"10.66.66.1/32"},
				"mtu":       1420,
				"peers": []map[string]interface{}{{
					"publicKey": customerPublicKey, "allowedIPs": []string{"10.66.66.2/32"}, "keepAlive": 25,
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := &fakeRemoteNodeProbeClient{}
	remote.forward = func(serverID int64, method, path string, _ []byte) ([]byte, error) {
		if serverID != server.ID || path != "/api/child/inbounds" {
			return nil, errors.New("unexpected Agent target")
		}
		switch method {
		case http.MethodGet:
			return inventory, nil
		case http.MethodPost:
			return []byte(`{"success":true,"mutation_id":"wireguard-generation-1"}`), nil
		default:
			return nil, errors.New("unexpected Agent method")
		}
	}
	prober := &fakeProtocolLatencyProber{results: []speedtest.ProtocolLatencyResult{{Latency: 45.5}}}
	handler := newTCPingHandler(repo, remote, false, prober)
	body, err := json.Marshal(TCPingRequest{
		NodeID: node.ID, Host: "127.0.0.1", Port: 1, Protocol: "vless", Timeout: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/tcping", bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response TCPingResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.Latency != 45.5 || response.Probe != "mihomo_url_test" || response.Error != "" {
		t.Fatalf("unexpected response: %+v", response)
	}

	prober.mu.Lock()
	if len(prober.targets) != 1 {
		prober.mu.Unlock()
		t.Fatalf("targets=%d want 1", len(prober.targets))
	}
	target := prober.targets[0]
	prober.mu.Unlock()
	var proxy map[string]interface{}
	if err := json.Unmarshal([]byte(target.ClashConfig), &proxy); err != nil {
		t.Fatalf("decode Mihomo WireGuard target: %v", err)
	}
	probePrivateKey := wireGuardStringValue(proxy["private-key"])
	if probePrivateKey == "" || probePrivateKey == customerPrivateKey || probePrivateKey == serverPrivateKey {
		t.Fatalf("Mihomo received a non-dedicated private key: %q", probePrivateKey)
	}
	if wireGuardStringValue(proxy["public-key"]) != serverPublicKey || wireGuardStringValue(proxy["ip"]) != "10.66.66.3" {
		t.Fatalf("unexpected WireGuard probe config: %s", target.ClashConfig)
	}
	storedPeer, err := repo.GetWireGuardProbePeer(context.Background(), resource.ID)
	if err != nil {
		t.Fatalf("GetWireGuardProbePeer: %v", err)
	}
	if storedPeer.PrivateKey != probePrivateKey || storedPeer.State != storage.WireGuardProbePeerStateActive {
		t.Fatalf("Mihomo target did not use active stored probe peer: %+v", storedPeer)
	}

	remote.mu.Lock()
	calls := append([]fakeRemoteNodeProbeCall(nil), remote.calls...)
	remote.mu.Unlock()
	if len(calls) != 2 || calls[0].method != http.MethodGet || calls[1].method != http.MethodPost {
		t.Fatalf("unexpected Agent calls: %+v", calls)
	}
	if calls[0].serverID != server.ID || calls[0].path != "/api/child/inbounds" || len(calls[0].body) != 0 {
		t.Fatalf("unexpected inventory call: %+v", calls[0])
	}
	var mutation struct {
		Action     string                 `json:"action"`
		MutationID string                 `json:"mutation_id"`
		Inbound    map[string]interface{} `json:"inbound"`
	}
	if err := json.Unmarshal(calls[1].body, &mutation); err != nil {
		t.Fatalf("decode Agent mutation: %v body=%s", err, calls[1].body)
	}
	if mutation.Action != "add" || mutation.MutationID != resource.MutationID {
		t.Fatalf("unexpected Agent mutation: %+v", mutation)
	}
	settings, _ := mutation.Inbound["settings"].(map[string]interface{})
	foundProbePeer := false
	for _, rawPeer := range wireGuardInterfaceSlice(settings["peers"]) {
		peer, _ := rawPeer.(map[string]interface{})
		if equalManagedWireGuardKeys(wireGuardStringValue(peer["publicKey"]), storedPeer.PublicKey) {
			foundProbePeer = true
		}
		if wireGuardStringValue(peer["privateKey"]) != "" {
			t.Fatalf("Agent peer payload exposed a private key: %+v", peer)
		}
	}
	if !foundProbePeer {
		t.Fatalf("Agent mutation omitted dedicated probe public key: %s", calls[1].body)
	}

	remote.mu.Lock()
	remote.forward = func(_ int64, _, _ string, _ []byte) ([]byte, error) {
		return nil, errors.New("active probe peer must not contact the Agent")
	}
	remote.mu.Unlock()
	secondRequest := httptest.NewRequest(http.MethodPost, "/api/admin/tcping", bytes.NewReader(body))
	secondRequest = secondRequest.WithContext(auth.ContextWithUsername(secondRequest.Context(), "admin"))
	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, secondRequest)
	if secondRecorder.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", secondRecorder.Code, secondRecorder.Body.String())
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if len(remote.calls) != 2 {
		t.Fatalf("active probe peer repeated Agent access: %+v", remote.calls)
	}
}

func TestTCPingManagedWireGuardSanitizesAgentACKError(t *testing.T) {
	repo := newTCPingTestRepository(t)
	createTCPingAdmin(t, repo)
	_, node, resource, _ := createTCPingWireGuardNode(t, repo)
	_, serverPrivateKey := wireGuardTCPingTestKeyPair(t, 0x31)
	customerPublicKey, _ := wireGuardTCPingTestKeyPair(t, 0x32)
	inventory, err := json.Marshal(map[string]interface{}{
		"success":              true,
		"mutation_fence_known": true,
		"mutation_owners":      map[string]string{"wireguard-test": resource.MutationID},
		"inbounds": []map[string]interface{}{{
			"tag": "wireguard-test", "protocol": "wireguard", "port": 51820, "_runtime_status": "running",
			"settings": map[string]interface{}{
				"secretKey": serverPrivateKey,
				"address":   []string{"10.66.66.1/32"},
				"peers": []map[string]interface{}{{
					"publicKey": customerPublicKey, "allowedIPs": []string{"10.66.66.2/32"},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "agent-password-must-not-leak"
	remote := &fakeRemoteNodeProbeClient{}
	remote.forward = func(_ int64, method, _ string, _ []byte) ([]byte, error) {
		if method == http.MethodGet {
			return inventory, nil
		}
		return []byte(`{"success":false,"mutation_id":"wrong-generation","error":"password=` + secret + `"}`), nil
	}
	prober := &fakeProtocolLatencyProber{}
	handler := newTCPingHandler(repo, remote, false, prober)
	body, err := json.Marshal(TCPingRequest{NodeID: node.ID, Timeout: 1000})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/tcping", bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response TCPingResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Success || response.Error != "Agent 未确认 WireGuard 专用探测 Peer" || strings.Contains(response.Error, secret) {
		t.Fatalf("unexpected sanitized response: %+v", response)
	}
	prober.mu.Lock()
	defer prober.mu.Unlock()
	if len(prober.targets) != 0 {
		t.Fatalf("failed Agent mutation reached Mihomo prober: %+v", prober.targets)
	}
}

func TestMihomoProbeConfigRejectsProtocolMismatch(t *testing.T) {
	handler := &tcpingHandler{}
	config := `{"name":"spoofed","type":"wireguard","server":"127.0.0.1","port":51820,"private-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`
	_, err := handler.mihomoProbeConfigForNode(context.Background(), storage.Node{
		ID: 7, Protocol: "vless", ClashConfig: config,
	}, make(map[string]cachedWireGuardProbePeer), time.Second)
	if err == nil || !strings.Contains(err.Error(), "协议与 Mihomo 配置不一致") {
		t.Fatalf("mihomoProbeConfigForNode() error = %v, want protocol mismatch", err)
	}
}

func TestNodeProbeAddressSupportsMieruPortRange(t *testing.T) {
	host, port, err := nodeProbeAddress(storage.Node{ClashConfig: `{"type":"mieru","server":"mieru.example.test","port-range":"5000-5010"}`})
	if err != nil {
		t.Fatalf("nodeProbeAddress() error = %v", err)
	}
	if host != "mieru.example.test" || port != 5000 {
		t.Fatalf("nodeProbeAddress() = %s:%d, want mieru.example.test:5000", host, port)
	}
	for _, invalid := range []string{"", "0-10", "6000-5000", "5000-70000", "invalid"} {
		_, _, err := nodeProbeAddress(storage.Node{ClashConfig: `{"type":"mieru","server":"mieru.example.test","port-range":` + strconv.Quote(invalid) + `}`})
		if err == nil {
			t.Fatalf("nodeProbeAddress() accepted invalid Mieru port-range %q", invalid)
		}
	}
}

func TestValidatePublicMihomoProbeOverrides(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{name: "TUIC private ip override", config: `{"type":"tuic","server":"1.1.1.1","port":443,"ip":"127.0.0.1"}`, wantErr: true},
		{name: "TUIC invalid ip override", config: `{"type":"tuic","server":"1.1.1.1","port":443,"ip":"internal.example"}`, wantErr: true},
		{name: "TUIC public ip override", config: `{"type":"tuic","server":"1.1.1.1","port":443,"ip":"8.8.8.8"}`},
		{name: "WireGuard peers", config: `{"type":"wireguard","server":"1.1.1.1","port":51820,"peers":[]}`, wantErr: true},
		{name: "download settings", config: `{"type":"vless","server":"1.1.1.1","port":443,"download-settings":{}}`, wantErr: true},
		{name: "nested server URL", config: `{"type":"vless","server":"1.1.1.1","port":443,"plugin-opts":{"server_url":"http://127.0.0.1"}}`, wantErr: true},
		{name: "ordinary proxy", config: `{"type":"vless","server":"1.1.1.1","port":443}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePublicMihomoProbeOverrides(test.config)
			if test.wantErr && err == nil {
				t.Fatal("validatePublicMihomoProbeOverrides() error = nil, want rejection")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validatePublicMihomoProbeOverrides() error = %v", err)
			}
		})
	}
}

func TestWireGuardProbePeerHelpersRejectMalformedInbound(t *testing.T) {
	probePeer := &storage.WireGuardProbePeer{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Addresses: []string{"10.66.66.3/32"},
	}
	tests := []struct {
		name    string
		inbound map[string]interface{}
	}{
		{name: "missing settings", inbound: map[string]interface{}{}},
		{name: "invalid settings", inbound: map[string]interface{}{"settings": "invalid"}},
		{name: "missing peers", inbound: map[string]interface{}{"settings": map[string]interface{}{}}},
		{name: "invalid peers", inbound: map[string]interface{}{"settings": map[string]interface{}{"peers": "invalid"}}},
		{name: "invalid peer item", inbound: map[string]interface{}{"settings": map[string]interface{}{"peers": []interface{}{"invalid"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := wireGuardInboundHasProbePeer(test.inbound, probePeer); err == nil {
				t.Fatal("wireGuardInboundHasProbePeer() error = nil, want malformed inbound rejection")
			}
			if err := appendWireGuardProbePeer(test.inbound, probePeer); err == nil {
				t.Fatal("appendWireGuardProbePeer() error = nil, want malformed inbound rejection")
			}
		})
	}
}

func TestWireGuardInboundHasProbePeerRejectsAddressConflicts(t *testing.T) {
	probePublicKey, _ := wireGuardTCPingTestKeyPair(t, 0x41)
	otherPublicKey, _ := wireGuardTCPingTestKeyPair(t, 0x42)
	probePeer := &storage.WireGuardProbePeer{
		PublicKey: probePublicKey,
		Addresses: []string{"10.66.66.3/32"},
	}
	tests := []struct {
		name  string
		peers []map[string]interface{}
		want  string
	}{
		{
			name: "missing probe peer address occupied",
			peers: []map[string]interface{}{{
				"publicKey": otherPublicKey, "allowedIPs": []string{"10.66.66.0/24"},
			}},
			want: "已被其他 Peer 占用",
		},
		{
			name: "existing probe peer address also occupied",
			peers: []map[string]interface{}{
				{"publicKey": probePublicKey, "allowedIPs": []string{"10.66.66.3/32"}},
				{"publicKey": otherPublicKey, "allowedIPs": []string{"10.66.66.3/32"}},
			},
			want: "已被其他 Peer 占用",
		},
		{
			name: "duplicate probe public key",
			peers: []map[string]interface{}{
				{"publicKey": probePublicKey, "allowedIPs": []string{"10.66.66.3/32"}},
				{"publicKey": probePublicKey, "allowedIPs": []string{"10.66.66.3/32"}},
			},
			want: "公钥重复",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inbound := map[string]interface{}{"settings": map[string]interface{}{"peers": test.peers}}
			_, err := wireGuardInboundHasProbePeer(inbound, probePeer)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wireGuardInboundHasProbePeer() error = %v, want %q", err, test.want)
			}
			if appendErr := appendWireGuardProbePeer(inbound, probePeer); appendErr == nil || !strings.Contains(appendErr.Error(), test.want) {
				t.Fatalf("appendWireGuardProbePeer() error = %v, want %q", appendErr, test.want)
			}
		})
	}
}

func TestManagedWireGuardInboundPortUsesOriginalPortAfterRelay(t *testing.T) {
	node := storage.Node{RelayOrigServer: "wg-origin.example.test", RelayOrigPort: 51820}
	if got := managedWireGuardInboundPort(node); got != 51820 {
		t.Fatalf("port=%d want 51820", got)
	}
	if got := canonicalProbeProtocol(" WG "); got != "wireguard" {
		t.Fatalf("protocol=%q want wireguard", got)
	}
}

func TestInspectManagedWireGuardInventoryRequiresMatchingRunningInbound(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "missing", body: `{"success":true,"inbounds":[]}`, want: "未找到"},
		{name: "wrong protocol", body: `{"success":true,"inbounds":[{"tag":"wg","protocol":"vless","port":51820,"_runtime_status":"running"}]}`, want: "不再是 WireGuard"},
		{name: "wrong port", body: `{"success":true,"inbounds":[{"tag":"wg","protocol":"wireguard","port":51821,"_runtime_status":"running"}]}`, want: "端口"},
		{name: "stopped", body: `{"success":true,"inbounds":[{"tag":"wg","protocol":"wireguard","port":"51820","_runtime_status":"not_running"}]}`, want: "未运行"},
		{name: "running", body: `{"success":true,"inbounds":[{"tag":"wg","protocol":"wireguard","port":"51820","_runtime_status":"running"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := inspectManagedWireGuardInventory([]byte(test.body), "wg", 51820)
			if test.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.want)) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestPublicProbeAddressGuard(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1"} {
		if isPublicProbeIP(net.ParseIP(value)) {
			t.Fatalf("expected %s to be blocked", value)
		}
	}
	if !isPublicProbeIP(net.ParseIP("1.1.1.1")) || !isPublicProbeIP(net.ParseIP("2606:4700:4700::1111")) {
		t.Fatal("expected public resolver addresses to be allowed")
	}
}
