package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type userDeleteLifecycleFixture struct {
	repo      *storage.TrafficRepository
	handler   http.Handler
	managed   *ManagedNodesHandler
	selection *storage.SelectionActivationResult
}

func newUserDeleteLifecycleFixture(t *testing.T) userDeleteLifecycleFixture {
	t.Helper()
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "offline-delete-edge", Token: "token", Status: storage.RemoteServerStatusOffline,
		IPAddress: "203.0.113.40", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "delete-managed", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "delete-in",
		ClashConfig: `{"name":"delete-managed","type":"vless","server":"203.0.113.40","port":443,"uuid":"owner-uuid"}`,
	})
	if err != nil {
		t.Fatalf("create managed node: %v", err)
	}
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "owner")
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveNodes: 1,
		BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "owner",
	}); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	selection, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate selection: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "delete-in", Protocol: "vless",
		CredentialJSON: `{"id":"alice-delete-uuid","email":"alice__delete-in"}`,
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	remote := NewRemoteManageHandler(repo, nil)
	managed := NewManagedNodesHandler(repo, remote, nil)
	return userDeleteLifecycleFixture{
		repo: repo, handler: NewUserDeleteHandler(repo, remote, nil, managed), managed: managed, selection: selection,
	}
}

func newUserDeleteHTTPRequest(t *testing.T, username string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/admin/users/delete",
		strings.NewReader(`{"username":"`+username+`"}`))
	return request.WithContext(auth.ContextWithUsername(request.Context(), "owner"))
}

func TestUserDeleteKeepsRetryTombstoneWhenAgentOffline(t *testing.T) {
	fixture := newUserDeleteLifecycleFixture(t)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, newUserDeleteHTTPRequest(t, "alice"))

	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusAccepted, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
	if payload["status"] != "deletion_pending" {
		t.Fatalf("unexpected pending response: %#v", payload)
	}
	user, err := fixture.repo.GetUser(context.Background(), "alice")
	if err != nil || user.IsActive {
		t.Fatalf("pending deletion did not retain a disabled user: user=%#v err=%v", user, err)
	}
	pending, err := fixture.repo.IsUserDeletionPending(context.Background(), "alice")
	if err != nil || !pending {
		t.Fatalf("deletion tombstone missing: pending=%v err=%v", pending, err)
	}
	configs, err := fixture.repo.GetUserInboundConfigs(context.Background(), "alice")
	if err != nil || len(configs) != 1 || configs[0].CredentialJSON == "" {
		t.Fatalf("credential needed for retry was removed: configs=%#v err=%v", configs, err)
	}
	sources, err := fixture.repo.ListUserInboundAccessSources(context.Background(), "alice", 0)
	if err != nil || len(sources) < 2 {
		t.Fatalf("retryable sources missing: sources=%#v err=%v", sources, err)
	}
	for _, source := range sources {
		if source.DesiredState != storage.ManagedDesiredInactive {
			t.Fatalf("source %d was not revoked locally: %#v", source.ID, source)
		}
		if source.Generation == source.AppliedGeneration || source.LastError == "" {
			t.Fatalf("offline source %d was not retained as failed work: %#v", source.ID, source)
		}
	}
	if _, err := fixture.repo.GetUserNodeSelection(context.Background(), fixture.selection.Selection.ID); err != nil {
		t.Fatalf("selection was deleted before remote revoke: %v", err)
	}
	if err := fixture.repo.CreateUser(context.Background(), "alice", "new@example.test", "New", "hash", storage.RoleUser, ""); !errors.Is(err, storage.ErrUserExists) {
		t.Fatalf("same-name account was recreated over tombstone: %v", err)
	}

	statusResponse := httptest.NewRecorder()
	statusRequest := httptest.NewRequest(http.MethodPost, "/api/admin/users/status",
		strings.NewReader(`{"username":"alice","is_active":true}`))
	NewUserStatusHandler(fixture.repo, nil, nil).ServeHTTP(statusResponse,
		statusRequest.WithContext(auth.ContextWithUsername(statusRequest.Context(), "owner")))
	if statusResponse.Code != http.StatusConflict {
		t.Fatalf("pending deletion was re-enabled: status=%d body=%s", statusResponse.Code, statusResponse.Body.String())
	}
}

func TestUserDeleteReconcilerFinalizesAndSameNameStartsClean(t *testing.T) {
	fixture := newUserDeleteLifecycleFixture(t)
	first := httptest.NewRecorder()
	fixture.handler.ServeHTTP(first, newUserDeleteHTTPRequest(t, "alice"))
	if first.Code != http.StatusAccepted {
		t.Fatalf("initial status=%d body=%s", first.Code, first.Body.String())
	}

	sources, err := fixture.repo.ListUserInboundAccessSources(context.Background(), "alice", 0)
	if err != nil {
		t.Fatalf("list pending sources: %v", err)
	}
	for _, source := range sources {
		if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(context.Background(), source.ID,
			source.Generation, storage.ManagedObservedInactive, time.Now().UTC()); err != nil {
			t.Fatalf("simulate successful revoke for source %d: %v", source.ID, err)
		}
	}

	fixture.managed.reconcileAll(context.Background())
	if _, err := fixture.repo.GetUser(context.Background(), "alice"); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("user survived automatic finalized deletion: %v", err)
	}
	if err := fixture.repo.CreateUser(context.Background(), "alice", "new@example.test", "New Alice", "new-hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("recreate same-name user: %v", err)
	}
	grants, err := fixture.repo.ListUserServerGrants(context.Background(), "alice")
	if err != nil || len(grants) != 0 {
		t.Fatalf("new user inherited grants: grants=%#v err=%v", grants, err)
	}
	newSources, err := fixture.repo.ListUserInboundAccessSources(context.Background(), "alice", 0)
	if err != nil || len(newSources) != 0 {
		t.Fatalf("new user inherited sources: sources=%#v err=%v", newSources, err)
	}
	configs, err := fixture.repo.GetUserInboundConfigs(context.Background(), "alice")
	if err != nil || len(configs) != 0 {
		t.Fatalf("new user inherited credentials: configs=%#v err=%v", configs, err)
	}
	pending, err := fixture.repo.IsUserDeletionPending(context.Background(), "alice")
	if err != nil || pending {
		t.Fatalf("new user inherited deletion tombstone: pending=%v err=%v", pending, err)
	}
}
