package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestAgentCapabilitiesParseAndFailClosed(t *testing.T) {
	var oldPayload WSAuthPayload
	if err := json.Unmarshal([]byte(`{"token":"old","capabilities":{"rpc":true,"stream":true}}`), &oldPayload); err != nil {
		t.Fatalf("parse old auth payload: %v", err)
	}
	wantMissing := []string{"managed_clients_v1", "client_expiry", "limiter_replace", "limiter_replace_ack"}
	if got := oldPayload.Capabilities.MissingManagedNodeCapabilities(); fmt.Sprint(got) != fmt.Sprint(wantMissing) {
		t.Fatalf("old Agent missing=%v want=%v", got, wantMissing)
	}

	var currentPayload WSAuthPayload
	if err := json.Unmarshal([]byte(`{"token":"current","capabilities":{"rpc":true,"stream":true,"managed_clients_v1":true,"client_expiry":true,"limiter_replace":true,"limiter_replace_ack":true,"agent_uninstall_v2":true,"limiter_denied_v1":true}}`), &currentPayload); err != nil {
		t.Fatalf("parse current auth payload: %v", err)
	}
	if missing := currentPayload.Capabilities.MissingManagedNodeCapabilities(); len(missing) != 0 {
		t.Fatalf("current Agent unexpectedly missing capabilities: %v", missing)
	}
	if !currentPayload.Capabilities.AgentUninstallV2 {
		t.Fatal("current Agent did not advertise agent_uninstall_v2")
	}
	if !currentPayload.Capabilities.LimiterDeniedV1 {
		t.Fatal("current Agent did not advertise limiter_denied_v1")
	}
}

func TestManagedOfferRejectsOldAgentCapabilities(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	server := &storage.RemoteServer{
		Name: "edge-old-agent", Token: "old-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "203.0.113.61", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "old-agent-node", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"old-agent-node","type":"vless","server":"203.0.113.61","port":443,"uuid":"owner-id"}`,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	remote := managedRemoteWithCapabilities(repo, server.ID, AgentCapabilities{RPC: true, Stream: true})
	handler := NewManagedNodesHandler(repo, remote, NewLimiterConfigPusher(repo, nil))
	handler.guardHTTPClient.Timeout = 10 * time.Millisecond
	request := httptest.NewRequest(http.MethodPost, "/api/admin/managed-node-offers",
		strings.NewReader(fmt.Sprintf(`{"node_id":%d}`, node.ID)))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "owner"))
	response := httptest.NewRecorder()

	handler.HandleOffers(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusUnprocessableEntity, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "expiry guard") {
		t.Fatalf("response does not explain missing expiry guard: %s", response.Body.String())
	}
	offers, err := repo.ListSelfServiceNodeOffers(ctx, true)
	if err != nil {
		t.Fatalf("list offers: %v", err)
	}
	if len(offers) != 0 {
		t.Fatalf("offer was persisted for incompatible Agent: %#v", offers)
	}
}

func TestManagedSelectionStaysPendingForOldAgent(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "alice")
	servers, err := fixture.repo.ListRemoteServers(context.Background())
	if err != nil || len(servers) != 1 {
		t.Fatalf("resolve fixture server: servers=%v err=%v", servers, err)
	}
	remote := managedRemoteWithCapabilities(fixture.repo, servers[0].ID, AgentCapabilities{RPC: true, Stream: true})
	fixture.handler = NewManagedNodesHandler(fixture.repo, remote, NewLimiterConfigPusher(fixture.repo, nil))
	fixture.handler.guardHTTPClient.Timeout = 10 * time.Millisecond

	request := managedUserHTTPRequest(http.MethodPost, "/api/user/managed-nodes", "alice",
		fmt.Sprintf(`{"offer_id":%d}`, fixture.offer.ID))
	response := httptest.NewRecorder()
	fixture.handler.HandleUserManagedNodes(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusAccepted, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"pending":true`) ||
		!strings.Contains(response.Body.String(), "expiry guard") {
		t.Fatalf("pending response does not explain Agent incompatibility: %s", response.Body.String())
	}
	credential, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", servers[0].ID, fixture.offer.InboundTag)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("read credential reservation: %v", err)
	}
	if credential != nil {
		t.Fatalf("credential was reserved before capability gate: %#v", credential)
	}
}
