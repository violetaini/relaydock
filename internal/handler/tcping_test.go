package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type fakeRemoteNodeProbeClient struct {
	mu       sync.Mutex
	serverID int64
	method   string
	path     string
	body     []byte
	response []byte
	err      error
	calls    int
}

func (f *fakeRemoteNodeProbeClient) ForwardToServer(_ context.Context, serverID int64, method, path string, body []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.serverID = serverID
	f.method = method
	f.path = path
	f.body = append([]byte(nil), body...)
	f.calls++
	return append([]byte(nil), f.response...), f.err
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

func createTCPingWireGuardNode(t *testing.T, repo *storage.TrafficRepository) (storage.RemoteServer, storage.Node) {
	t.Helper()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser admin: %v", err)
	}
	server := storage.RemoteServer{
		Name: "Edge WG", Token: "agent-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "198.51.100.20", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	config, err := json.Marshal(map[string]interface{}{
		"name": "Managed WG", "type": "wireguard", "server": "wg.example.test", "port": 51820,
		"private-key": privateKey, "public-key": publicKey, "ip": "10.66.66.2/32",
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
	return server, node
}

func TestTCPingManagedWireGuardUsesAuthorizedNodeAndReportsManagementRTT(t *testing.T) {
	repo := newTCPingTestRepository(t)
	server, node := createTCPingWireGuardNode(t, repo)
	remote := &fakeRemoteNodeProbeClient{response: []byte(`{
		"success":true,
		"inbounds":[{"tag":"wireguard-test","protocol":"wireguard","port":51820,"_runtime_status":"running"}]
	}`)}
	handler := NewTCPingHandler(repo, remote)

	requestBody := []byte(`{"node_id":` + strconv.FormatInt(node.ID, 10) + `,"host":"127.0.0.1","port":1,"protocol":"vless","timeout":5000}`)
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
	if !response.Success || response.Probe != "managed_wireguard" || response.Error != "" {
		t.Fatalf("unexpected response: %+v", response)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.serverID != server.ID || remote.method != http.MethodGet || remote.path != "/api/child/inbounds" || len(remote.body) != 0 {
		t.Fatalf("unexpected remote probe: server=%d method=%s path=%s body=%q", remote.serverID, remote.method, remote.path, remote.body)
	}
}

func TestTCPingRejectsArbitraryTargetForOrdinaryUser(t *testing.T) {
	repo := newTCPingTestRepository(t)
	if err := repo.CreateUser(context.Background(), "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	handler := NewTCPingHandler(repo, &fakeRemoteNodeProbeClient{})
	request := httptest.NewRequest(http.MethodPost, "/api/admin/tcping", bytes.NewBufferString(`{"host":"127.0.0.1","port":22}`))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "alice"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestTCPingBatchCoalescesManagedInventoryAndKeepsItemErrors(t *testing.T) {
	repo := newTCPingTestRepository(t)
	_, first := createTCPingWireGuardNode(t, repo)
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	config := `{"name":"Managed WG 2","type":"wireguard","server":"wg.example.test","port":51820,"private-key":"` + privateKey + `","public-key":"` + publicKey + `","ip":"10.66.66.3/32"}`
	second, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "admin", NodeName: "Managed WG 2", Protocol: "wireguard",
		ParsedConfig: config, ClashConfig: config, Enabled: true,
		OriginalServer: "Edge WG", InboundTag: "wireguard-test-2",
	})
	if err != nil {
		t.Fatalf("CreateNode second: %v", err)
	}
	remote := &fakeRemoteNodeProbeClient{response: []byte(`{
		"success":true,
		"inbounds":[
			{"tag":"wireguard-test","protocol":"wireguard","port":51820,"_runtime_status":"running"},
			{"tag":"wireguard-test-2","protocol":"wireguard","port":51820,"_runtime_status":"running"}
		]
	}`)}
	handler := NewTCPingBatchHandler(repo, remote)
	body := `[{"node_id":` + strconv.FormatInt(first.ID, 10) + `},{"node_id":999999},{"node_id":` + strconv.FormatInt(second.ID, 10) + `}]`
	request := httptest.NewRequest(http.MethodPost, "/api/admin/tcping/batch", bytes.NewBufferString(body))
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
	if len(responses) != 3 || !responses[0].Success || responses[1].Success || responses[1].Error == "" || !responses[2].Success {
		t.Fatalf("unexpected responses: %+v", responses)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.calls != 1 {
		t.Fatalf("inventory calls=%d want 1", remote.calls)
	}
}

func TestManagedWireGuardInboundPortUsesOriginalPortAfterRelay(t *testing.T) {
	resolved := resolvedTCPingRequest{
		request: TCPingRequest{Port: 443},
		node:    storage.Node{RelayOrigServer: "wg-origin.example.test", RelayOrigPort: 51820},
	}
	if got := managedWireGuardInboundPort(resolved); got != 51820 {
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
