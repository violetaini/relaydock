package handler

import (
	"context"
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

func TestValidateSelfServiceNodeProtocol(t *testing.T) {
	tests := []struct {
		name        string
		protocol    string
		inboundTag  string
		clashConfig string
		wantErr     bool
	}{
		{
			name:        "VLESS does not use a shared Shadowsocks password",
			protocol:    "vless",
			clashConfig: `{"type":"vless"}`,
		},
		{
			name:        "Tunnel clone cannot be self-service published",
			protocol:    "vless",
			inboundTag:  "  AnYdOoR-edge-2033  ",
			clashConfig: `{"type":"vless"}`,
			wantErr:     true,
		},
		{
			name:        "Shadowsocks 2022 AES 128",
			protocol:    "shadowsocks",
			clashConfig: `{"cipher":"2022-blake3-aes-128-gcm"}`,
		},
		{
			name:        "Shadowsocks 2022 AES 256 through SS alias",
			protocol:    "ss",
			clashConfig: `{"method":"2022-blake3-aes-256-gcm"}`,
		},
		{
			name:        "Shadowsocks 2022 ChaCha is not supported for self service",
			protocol:    "shadowsocks",
			clashConfig: `{"cipher":"2022-blake3-chacha20-poly1305"}`,
			wantErr:     true,
		},
		{
			name:        "classic AES 128",
			protocol:    "shadowsocks",
			clashConfig: `{"cipher":"aes-128-gcm"}`,
			wantErr:     true,
		},
		{
			name:        "classic AES 256",
			protocol:    "ss",
			clashConfig: `{"cipher":"aes-256-gcm"}`,
			wantErr:     true,
		},
		{
			name:        "classic ChaCha20",
			protocol:    "shadowsocks",
			clashConfig: `{"method":"chacha20-ietf-poly1305"}`,
			wantErr:     true,
		},
		{
			name:        "missing cipher",
			protocol:    "shadowsocks",
			clashConfig: `{"type":"ss"}`,
			wantErr:     true,
		},
		{
			name:        "malformed configuration",
			protocol:    "shadowsocks",
			clashConfig: `{"cipher":`,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSelfServiceNodeProtocol(storage.Node{
				Protocol:    tt.protocol,
				InboundTag:  tt.inboundTag,
				ClashConfig: tt.clashConfig,
			})
			if tt.wantErr {
				if !errors.Is(err, storage.ErrManagedInvalidArgument) {
					t.Fatalf("error = %v, want %v", err, storage.ErrManagedInvalidArgument)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestManagedOfferPostRejectsClassicShadowsocksWithoutPersisting(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	server := createSelfServiceProtocolTestServer(t, repo)
	node := createSelfServiceProtocolTestNode(t, repo, *server, "classic-post", `{"cipher":"aes-256-gcm"}`)
	handler := NewManagedNodesHandler(repo, nil, nil)

	request := httptest.NewRequest(http.MethodPost, "/api/admin/managed-node-offers",
		strings.NewReader(fmt.Sprintf(`{"node_id":%d}`, node.ID)))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "owner"))
	response := httptest.NewRecorder()

	handler.HandleOffers(response, request)

	assertClassicShadowsocksRejected(t, response)
	offers, err := repo.ListSelfServiceNodeOffers(ctx, true)
	if err != nil {
		t.Fatalf("list offers: %v", err)
	}
	if len(offers) != 0 {
		t.Fatalf("classic Shadowsocks offer was persisted: %#v", offers)
	}
}

func TestManagedOfferPutCannotReenableClassicShadowsocks(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	server := createSelfServiceProtocolTestServer(t, repo)
	node := createSelfServiceProtocolTestNode(t, repo, *server, "classic-put", `{"cipher":"2022-blake3-aes-128-gcm"}`)
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "owner")
	if err != nil {
		t.Fatalf("create SS2022 offer: %v", err)
	}
	if _, err := repo.UpdateSelfServiceNodeOffer(ctx, offer.ID, false, 17); err != nil {
		t.Fatalf("disable SS2022 offer: %v", err)
	}
	node.ClashConfig = `{"cipher":"chacha20-ietf-poly1305"}`
	if _, err := repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("replace node with classic Shadowsocks config: %v", err)
	}
	handler := NewManagedNodesHandler(repo, nil, nil)

	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/admin/managed-node-offers/%d", offer.ID),
		strings.NewReader(`{"enabled":true,"sort_order":99}`))
	request.SetPathValue("id", fmt.Sprintf("%d", offer.ID))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "owner"))
	response := httptest.NewRecorder()

	handler.HandleOffer(response, request)

	assertClassicShadowsocksRejected(t, response)
	stored, err := repo.GetSelfServiceNodeOffer(ctx, offer.ID)
	if err != nil {
		t.Fatalf("read offer after rejected update: %v", err)
	}
	if stored.Enabled || stored.SortOrder != 17 {
		t.Fatalf("rejected update mutated offer: %#v", stored)
	}
}

func TestManagedUserCannotActivateClassicShadowsocksOffer(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := createSelfServiceProtocolTestServer(t, repo)
	node := createSelfServiceProtocolTestNode(t, repo, *server, "classic-user", `{"cipher":"2022-blake3-aes-256-gcm"}`)
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "owner")
	if err != nil {
		t.Fatalf("create SS2022 offer: %v", err)
	}
	node.ClashConfig = `{"cipher":"aes-128-gcm"}`
	if _, err := repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("replace node with classic Shadowsocks config: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveNodes: 1,
		BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "owner",
	}); err != nil {
		t.Fatalf("create user server grant: %v", err)
	}
	handler := NewManagedNodesHandler(repo, nil, nil)

	request := managedUserHTTPRequest(http.MethodPost, "/api/user/managed-nodes", "alice",
		fmt.Sprintf(`{"offer_id":%d}`, offer.ID))
	response := httptest.NewRecorder()

	handler.HandleUserManagedNodes(response, request)

	assertClassicShadowsocksRejected(t, response)
	selections, err := repo.ListUserNodeSelections(ctx, "alice", true)
	if err != nil {
		t.Fatalf("list selections: %v", err)
	}
	if len(selections) != 0 {
		t.Fatalf("classic Shadowsocks activation persisted a selection: %#v", selections)
	}
	sources, err := repo.ListUserInboundAccessSources(ctx, "alice", server.ID)
	if err != nil {
		t.Fatalf("list access sources: %v", err)
	}
	if len(sources) != 0 {
		t.Fatalf("classic Shadowsocks activation persisted an access source: %#v", sources)
	}
}

func createSelfServiceProtocolTestServer(t *testing.T, repo *storage.TrafficRepository) *storage.RemoteServer {
	t.Helper()
	server := &storage.RemoteServer{
		Name: "edge-self-service-protocol", Token: "edge-token", IPAddress: "203.0.113.90",
		XrayMode: "embedded", Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	return server
}

func createSelfServiceProtocolTestNode(t *testing.T, repo *storage.TrafficRepository, server storage.RemoteServer, name, clashConfig string) storage.Node {
	t.Helper()
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(clashConfig), &config); err != nil {
		t.Fatalf("test node config is invalid: %v", err)
	}
	config["name"] = name
	config["type"] = "ss"
	config["server"] = server.IPAddress
	config["port"] = 8388
	config["password"] = "owner-secret"
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("encode test node config: %v", err)
	}
	node, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "owner", NodeName: name, Protocol: "shadowsocks", Enabled: true,
		OriginalServer: server.Name, InboundTag: name + "-in", ClashConfig: string(encoded),
	})
	if err != nil {
		t.Fatalf("create Shadowsocks node: %v", err)
	}
	return node
}

func assertClassicShadowsocksRejected(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Shadowsocks 自助发布") {
		t.Fatalf("response does not explain the safe protocol requirement: %s", response.Body.String())
	}
}
