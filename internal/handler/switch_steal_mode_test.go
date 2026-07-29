package handler

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func newSwitchModeTestHandler(t *testing.T) (*RemoteManageHandler, *storage.TrafficRepository, *storage.RemoteServer, *atomic.Int64) {
	t.Helper()
	var agentRequests atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentRequests.Add(1)
		http.Error(w, "runtime mode switch must not reach the Agent", http.StatusInternalServerError)
	}))
	t.Cleanup(agent.Close)
	parsed, err := url.Parse(agent.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "switch-mode.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.CreateUser(context.Background(), "owner", "owner@example.test", "owner", "test-hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	server := &storage.RemoteServer{
		Name: "switch-edge", Token: "switch-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: host, ListenPort: port, Domain: "edge.example.test", XrayMode: "embedded",
		Use443: true, StealSelf: true, StealMode: "tunnel",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "owner", NodeName: "old-node", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "user-reality",
		ClashConfig: `{"name":"old-node","type":"vless","server":"edge.example.test","port":443,"uuid":"test-user-id"}`,
	}); err != nil {
		t.Fatal(err)
	}
	return NewRemoteManageHandler(repo, nil), repo, server, &agentRequests
}

func performSwitchRequest(t *testing.T, handler *RemoteManageHandler, serverID int64, mode string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/remote/switch-steal-mode?server_id="+strconv.FormatInt(serverID, 10),
		strings.NewReader(`{"steal_mode":"`+mode+`"}`),
	)
	recorder := httptest.NewRecorder()
	handler.HandleSwitchStealMode(recorder, req)
	return recorder
}

func TestHandleSwitchStealModeFailsClosedBeforeAnyMutation(t *testing.T) {
	handler, repo, server, agentRequests := newSwitchModeTestHandler(t)
	before, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}

	response := performSwitchRequest(t, handler, server.ID, "default")
	if response.Code != http.StatusConflict {
		t.Fatalf("switch response=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "重新安装") || !strings.Contains(response.Body.String(), "重建节点") {
		t.Fatalf("switch response does not explain the recovery path: %s", response.Body.String())
	}
	if got := agentRequests.Load(); got != 0 {
		t.Fatalf("failed-closed switch sent %d request(s) to the Agent", got)
	}

	after, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.StealMode != before.StealMode || after.StealSelf != before.StealSelf || after.Use443 != before.Use443 || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("failed-closed switch changed database state\nbefore=%#v\n after=%#v", before, after)
	}
	nodes, err := repo.ListNodes(context.Background(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].NodeName != "old-node" {
		t.Fatalf("failed-closed switch changed nodes: %#v", nodes)
	}
}

func TestHandleSwitchStealModeSameModeIsReadOnly(t *testing.T) {
	handler, repo, server, agentRequests := newSwitchModeTestHandler(t)
	before, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}

	response := performSwitchRequest(t, handler, server.ID, "tunnel")
	if response.Code != http.StatusOK {
		t.Fatalf("same-mode response=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := agentRequests.Load(); got != 0 {
		t.Fatalf("same-mode request sent %d request(s) to the Agent", got)
	}
	after, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.UpdatedAt.Equal(before.UpdatedAt) || after.StealMode != before.StealMode || after.StealSelf != before.StealSelf || after.Use443 != before.Use443 {
		t.Fatalf("same-mode request was not read-only\nbefore=%#v\n after=%#v", before, after)
	}
}

func TestHandleSwitchStealModeStillValidatesInput(t *testing.T) {
	handler, _, server, agentRequests := newSwitchModeTestHandler(t)
	response := performSwitchRequest(t, handler, server.ID, "unsupported")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid-mode response=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if got := agentRequests.Load(); got != 0 {
		t.Fatalf("invalid-mode request sent %d request(s) to the Agent", got)
	}
}
