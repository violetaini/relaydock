package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type managedUserHTTPFixture struct {
	repo       *storage.TrafficRepository
	handler    *ManagedNodesHandler
	node       storage.Node
	offer      *storage.SelfServiceNodeOffer
	activation *storage.SelectionActivationResult
}

func newManagedUserHTTPFixture(t *testing.T, username string) managedUserHTTPFixture {
	t.Helper()
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, username, storage.RoleUser)

	server := &storage.RemoteServer{
		Name:      "edge-http-test",
		Token:     "server-token-must-not-leak",
		IPAddress: "203.0.113.20",
		XrayMode:  "embedded",
		Status:    storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username:       "owner",
		NodeName:       "private-node-must-not-leak",
		Protocol:       "vless",
		Enabled:        true,
		OriginalServer: server.Name,
		InboundTag:     "private-inbound-must-not-leak",
		ClashConfig:    `{"name":"managed-http","type":"vless","server":"203.0.113.20","port":443,"uuid":"owner-secret-must-not-leak"}`,
	})
	if err != nil {
		t.Fatalf("create managed node: %v", err)
	}
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "owner")
	if err != nil {
		t.Fatalf("create managed offer: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username:        username,
		ServerID:        server.ID,
		Enabled:         true,
		StartsAt:        now.Add(-time.Hour),
		ExpiresAt:       &expires,
		MaxActiveNodes:  1,
		BillingMode:     storage.ManagedBillingDownload,
		ResetPolicy:     storage.ManagedResetNone,
		ResetDay:        1,
		BillingTimezone: "Asia/Shanghai",
		CreatedBy:       "owner",
	}); err != nil {
		t.Fatalf("create managed grant: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, username, offer.ID, username, now)
	if err != nil {
		t.Fatalf("activate managed selection: %v", err)
	}

	return managedUserHTTPFixture{
		repo:       repo,
		handler:    NewManagedNodesHandler(repo, nil, nil),
		node:       node,
		offer:      offer,
		activation: activation,
	}
}

func managedUserHTTPRequest(method, target, username, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	return request.WithContext(auth.ContextWithUsername(request.Context(), username))
}

func TestManagedUserHTTPRejectsInactiveUser(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "alice")
	if err := fixture.repo.UpdateUserStatus(context.Background(), "alice", false); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	tests := []struct {
		name   string
		method string
		body   string
	}{
		{name: "list", method: http.MethodGet},
		{name: "create", method: http.MethodPost, body: fmt.Sprintf(`{"offer_id":%d}`, fixture.offer.ID)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := managedUserHTTPRequest(tt.method, "/api/user/managed-nodes", "alice", tt.body)

			fixture.handler.HandleUserManagedNodes(response, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusForbidden, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "user is disabled") {
				t.Fatalf("response did not explain disabled account: %s", response.Body.String())
			}
		})
	}
}

func TestManagedUserHTTPCrossUserSelectionReturnsGenericNotFound(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "alice")
	createManagedSecurityTestUser(t, fixture.repo, "bob", storage.RoleUser)
	selectionID := fixture.activation.Selection.ID
	before, err := fixture.repo.GetUserNodeSelection(context.Background(), selectionID)
	if err != nil {
		t.Fatalf("read selection before request: %v", err)
	}

	tests := []struct {
		name    string
		method  string
		target  string
		handler http.HandlerFunc
	}{
		{name: "delete", method: http.MethodDelete, target: fmt.Sprintf("/api/user/managed-nodes/%d", selectionID), handler: fixture.handler.HandleUserManagedNode},
		{name: "retry", method: http.MethodPost, target: fmt.Sprintf("/api/user/managed-nodes/%d/retry", selectionID), handler: fixture.handler.HandleUserManagedNodeRetry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := managedUserHTTPRequest(tt.method, tt.target, "bob", "")
			request.SetPathValue("id", fmt.Sprintf("%d", selectionID))

			tt.handler(response, request)

			if response.Code != http.StatusNotFound {
				t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusNotFound, response.Body.String())
			}
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode response: %v body=%s", err, response.Body.String())
			}
			if len(payload) != 2 || payload["success"] == nil || payload["error"] == nil {
				t.Fatalf("not-found response leaked structured data: %s", response.Body.String())
			}
			body := response.Body.String()
			for _, secret := range []string{"alice", fixture.node.NodeName, fixture.node.InboundTag, "owner-secret-must-not-leak", fmt.Sprintf(`"id":%d`, selectionID)} {
				if strings.Contains(body, secret) {
					t.Fatalf("not-found response leaked %q: %s", secret, body)
				}
			}
		})
	}

	after, err := fixture.repo.GetUserNodeSelection(context.Background(), selectionID)
	if err != nil {
		t.Fatalf("read selection after requests: %v", err)
	}
	if after.DesiredEnabled != before.DesiredEnabled || after.AccessSourceID == nil || before.AccessSourceID == nil || *after.AccessSourceID != *before.AccessSourceID {
		t.Fatalf("cross-user request mutated selection: before=%#v after=%#v", before, after)
	}
}

func TestManagedUserHTTPProvisioningSelectionIsNotEffective(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "alice")
	response := httptest.NewRecorder()
	request := managedUserHTTPRequest(http.MethodGet, "/api/user/managed-nodes", "alice", "")

	fixture.handler.HandleUserManagedNodes(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	var payload struct {
		Success  bool `json:"success"`
		Selected []struct {
			ID    int64  `json:"id"`
			State string `json:"state"`
		} `json:"selected"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
	if !payload.Success || len(payload.Selected) != 1 {
		t.Fatalf("unexpected managed-node response: %s", response.Body.String())
	}
	if payload.Selected[0].ID != fixture.activation.Selection.ID || payload.Selected[0].State != "provisioning" {
		t.Fatalf("selection was not reported as provisioning: %#v", payload.Selected[0])
	}

	ids, err := effectiveManagedNodeIDs(context.Background(), fixture.repo, "alice")
	if err != nil {
		t.Fatalf("resolve effective managed nodes: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("provisioning selection became effective: %v", ids)
	}
}
