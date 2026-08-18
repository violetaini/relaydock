package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type effectiveAuthorizationFixture struct {
	repo   *storage.TrafficRepository
	dbPath string
	server storage.RemoteServer
	node   storage.Node
}

func newEffectiveAuthorizationFixture(t *testing.T) effectiveAuthorizationFixture {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "effective-authorization.db")
	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := storage.RemoteServer{
		Name: "effective-edge", Token: "effective-edge-token",
		Status: storage.RemoteServerStatusConnected, IPAddress: "203.0.113.40",
		XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush,
	}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "Effective VLESS", Protocol: "vless",
		ClashConfig: `{"name":"Effective VLESS","type":"vless","server":"203.0.113.40","port":443,"uuid":"owner-secret"}`,
		Enabled:     true, OriginalServer: server.Name, InboundTag: "effective-vless-in",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	return effectiveAuthorizationFixture{repo: repo, dbPath: dbPath, server: server, node: node}
}

func makeEffectiveDirectNode(t *testing.T, fixture effectiveAuthorizationFixture) *storage.UserNodeGrantWithSource {
	t.Helper()
	ctx := context.Background()
	grant, _, err := fixture.repo.UpsertManualUserNodeGrant(ctx, "alice", fixture.node.ID, nil, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	if err := fixture.repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: fixture.server.ID, InboundTag: fixture.node.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"alice-user-id"}`,
	}); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}
	credential, err := fixture.repo.GetUserInboundConfig(ctx, "alice", fixture.server.ID, fixture.node.InboundTag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	if err := fixture.repo.SetUserNodeGrantCredential(ctx, grant.Grant.ID, credential.ID); err != nil {
		t.Fatalf("SetUserNodeGrantCredential: %v", err)
	}
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, grant.Source.ID, grant.Source.Generation,
		storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("MarkUserInboundAccessSourceApplied: %v", err)
	}
	return grant
}

func makeEffectiveManagedPackageNode(t *testing.T, fixture effectiveAuthorizationFixture, now time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	offer, err := fixture.repo.CreateSelfServiceNodeOffer(ctx, fixture.node.ID, fixture.server.ID, "admin")
	if err != nil {
		t.Fatalf("CreateSelfServiceNodeOffer: %v", err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "managed-node-package", TrafficLimitBytes: 1024, CycleDays: 30,
		ServerGrants: []storage.PackageServerGrant{{
			ServerID: fixture.server.ID, MaxActiveNodes: 1,
			BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone, ResetDay: 1,
		}},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if _, err := fixture.repo.AssignPackageBundleToUser(ctx, "alice", packageID,
		now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("AssignPackageBundleToUser: %v", err)
	}
	activation, err := fixture.repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("ActivateUserNodeSelection: %v", err)
	}
	if err := fixture.repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: fixture.server.ID, InboundTag: fixture.node.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"alice-managed-id"}`,
	}); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}
	credential, err := fixture.repo.GetUserInboundConfig(ctx, "alice", fixture.server.ID, fixture.node.InboundTag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	if err := fixture.repo.SetUserNodeSelectionCredential(ctx, activation.Selection.ID, credential.ID); err != nil {
		t.Fatalf("SetUserNodeSelectionCredential: %v", err)
	}
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID,
		activation.Source.Generation, storage.ManagedObservedActive, now); err != nil {
		t.Fatalf("MarkUserInboundAccessSourceApplied: %v", err)
	}
	return packageID
}

func TestResolveEffectiveUserNodeIDsPackageExpiryAndOverLimit(t *testing.T) {
	fixture := newEffectiveAuthorizationFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	disabled, err := fixture.repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "Disabled", Protocol: "vless", Enabled: false,
		OriginalServer: fixture.server.Name, InboundTag: "disabled-in",
		ClashConfig: `{"name":"Disabled","type":"vless","server":"203.0.113.41","port":443}`,
	})
	if err != nil {
		t.Fatalf("CreateNode disabled: %v", err)
	}
	missingCoordinates, err := fixture.repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "Missing Coordinates", Protocol: "vless", Enabled: true,
		ClashConfig: `{"name":"Missing Coordinates","type":"vless","server":"203.0.113.42","port":443}`,
	})
	if err != nil {
		t.Fatalf("CreateNode missing coordinates: %v", err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "effective-package", TrafficLimitBytes: 1024, CycleDays: 30,
		Nodes: []int64{fixture.node.ID, disabled.ID, missingCoordinates.ID},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if _, err := fixture.repo.AssignPackageBundleToUser(ctx, "alice", packageID,
		now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("AssignPackageBundleToUser: %v", err)
	}

	ids, err := ResolveEffectiveUserNodeIDs(ctx, fixture.repo, "alice", now)
	if err != nil || !reflect.DeepEqual(ids, []int64{fixture.node.ID}) {
		t.Fatalf("active package nodes=%v err=%v", ids, err)
	}
	entitlements, err := ResolveUserServiceEntitlements(ctx, fixture.repo, "alice", now)
	if err != nil || !entitlements.Nodes || !entitlements.Subscription {
		t.Fatalf("active package entitlements=%+v err=%v", entitlements, err)
	}

	if err := fixture.repo.UpdateUserOverLimit(ctx, "alice", true); err != nil {
		t.Fatalf("UpdateUserOverLimit: %v", err)
	}
	ids, err = ResolveEffectiveUserNodeIDs(ctx, fixture.repo, "alice", now)
	if err != nil || len(ids) != 0 {
		t.Fatalf("over-limit package nodes=%v err=%v", ids, err)
	}
	entitlements, err = ResolveUserServiceEntitlements(ctx, fixture.repo, "alice", now)
	if err != nil || entitlements.Nodes || entitlements.Subscription {
		t.Fatalf("over-limit package entitlements=%+v err=%v", entitlements, err)
	}

	if err := fixture.repo.UpdateUserOverLimit(ctx, "alice", false); err != nil {
		t.Fatalf("clear over limit: %v", err)
	}
	ids, err = ResolveEffectiveUserNodeIDs(ctx, fixture.repo, "alice", now.Add(2*time.Hour))
	if err != nil || len(ids) != 0 {
		t.Fatalf("expired package nodes=%v err=%v", ids, err)
	}
	entitlements, err = ResolveUserServiceEntitlements(ctx, fixture.repo, "alice", now.Add(2*time.Hour))
	if err != nil || entitlements.Nodes || entitlements.Subscription {
		t.Fatalf("expired package entitlements=%+v err=%v", entitlements, err)
	}
}

func TestUserAndTelegramNodeListsShareEffectiveCustomNodes(t *testing.T) {
	fixture := newEffectiveAuthorizationFixture(t)
	makeEffectiveDirectNode(t, fixture)

	webRequest := httptest.NewRequest(http.MethodGet, "/api/user/nodes", nil)
	webRequest = webRequest.WithContext(auth.ContextWithUsername(webRequest.Context(), "alice"))
	webResponse := httptest.NewRecorder()
	NewUserNodesHandler(fixture.repo, nil).HandleListNodes(webResponse, webRequest)
	if webResponse.Code != http.StatusOK {
		t.Fatalf("web nodes status=%d body=%s", webResponse.Code, webResponse.Body.String())
	}
	var webBody struct {
		Nodes []struct {
			ID int64 `json:"id"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(webResponse.Body.Bytes(), &webBody); err != nil {
		t.Fatalf("decode web nodes: %v", err)
	}

	tgRequest := httptest.NewRequest(http.MethodGet, "/api/admin/tgbot/user-nodes?username=alice", nil)
	tgResponse := httptest.NewRecorder()
	NewTGBotAPIHandler(fixture.repo).userNodes(tgResponse, tgRequest)
	if tgResponse.Code != http.StatusOK {
		t.Fatalf("telegram nodes status=%d body=%s", tgResponse.Code, tgResponse.Body.String())
	}
	var tgBody struct {
		Nodes []struct {
			ID int64 `json:"id"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(tgResponse.Body.Bytes(), &tgBody); err != nil {
		t.Fatalf("decode telegram nodes: %v", err)
	}
	if len(webBody.Nodes) != 1 || len(tgBody.Nodes) != 1 ||
		webBody.Nodes[0].ID != fixture.node.ID || tgBody.Nodes[0].ID != fixture.node.ID {
		t.Fatalf("web nodes=%+v telegram nodes=%+v", webBody.Nodes, tgBody.Nodes)
	}
}

func TestResolveEffectiveUserNodeIDsRejectsStaleManualGrantInPackageMode(t *testing.T) {
	fixture := newEffectiveAuthorizationFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	direct := makeEffectiveDirectNode(t, fixture)
	if err := fixture.repo.PreparePackageAuthorizationTransition(ctx, "alice"); err != nil {
		t.Fatalf("PreparePackageAuthorizationTransition: %v", err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "empty-package", TrafficLimitBytes: 1024, CycleDays: 30,
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if _, err := fixture.repo.AssignPackageBundleToUser(ctx, "alice", packageID,
		now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("AssignPackageBundleToUser: %v", err)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, direct.Source.ID)
	if err != nil {
		t.Fatalf("GetUserInboundAccessSource: %v", err)
	}
	source, err = fixture.repo.SetUserInboundAccessSourceState(ctx, source.ID, source.Generation,
		storage.ManagedDesiredActive, storage.ManagedSuspendNone, "test-corruption", nil)
	if err != nil {
		t.Fatalf("reactivate stale direct source: %v", err)
	}
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, source.ID, source.Generation,
		storage.ManagedObservedActive, now); err != nil {
		t.Fatalf("apply stale direct source: %v", err)
	}
	checkAt := time.Now().UTC().Add(time.Second)
	rawIDs, err := fixture.repo.ListEffectiveDirectNodeIDs(ctx, "alice", checkAt)
	if err != nil || !reflect.DeepEqual(rawIDs, []int64{fixture.node.ID}) {
		t.Fatalf("stale direct fixture was not effective: ids=%v err=%v", rawIDs, err)
	}
	ids, err := ResolveEffectiveUserNodeIDs(ctx, fixture.repo, "alice", checkAt)
	if err != nil || len(ids) != 0 {
		t.Fatalf("package mode exposed stale manual node: ids=%v err=%v", ids, err)
	}
}

func TestResolveEffectiveUserNodeIDsFiltersPackageSelectionsByModeAndLimit(t *testing.T) {
	fixture := newEffectiveAuthorizationFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	makeEffectiveManagedPackageNode(t, fixture, now)

	ids, err := ResolveEffectiveUserNodeIDs(ctx, fixture.repo, "alice", now)
	if err != nil || !reflect.DeepEqual(ids, []int64{fixture.node.ID}) {
		t.Fatalf("active package selection ids=%v err=%v", ids, err)
	}
	if err := fixture.repo.UpdateUserOverLimit(ctx, "alice", true); err != nil {
		t.Fatalf("UpdateUserOverLimit: %v", err)
	}
	ids, err = ResolveEffectiveUserNodeIDs(ctx, fixture.repo, "alice", now)
	if err != nil || len(ids) != 0 {
		t.Fatalf("over-limit package selection ids=%v err=%v", ids, err)
	}
	if err := fixture.repo.UpdateUserOverLimit(ctx, "alice", false); err != nil {
		t.Fatalf("clear over limit: %v", err)
	}

	db, err := sql.Open("sqlite", fixture.dbPath)
	if err != nil {
		t.Fatalf("open fixture database: %v", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `UPDATE users SET authorization_mode='custom', package_id=NULL WHERE username='alice'`); err != nil {
		t.Fatalf("inject stale package grant: %v", err)
	}
	ids, err = ResolveEffectiveUserNodeIDs(ctx, fixture.repo, "alice", now)
	if err != nil || len(ids) != 0 {
		t.Fatalf("custom mode exposed stale package selection: ids=%v err=%v", ids, err)
	}
}

func TestUserPermissionsMergeAuthorizationDerivedPages(t *testing.T) {
	fixture := newEffectiveAuthorizationFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := fixture.repo.UpdateRemoteServerXrayStatus(ctx, fixture.server.ID, true, "test"); err != nil {
		t.Fatalf("UpdateRemoteServerXrayStatus: %v", err)
	}
	expires := now.Add(time.Hour)
	if _, err := fixture.repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: fixture.server.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires,
		BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
	}); err != nil {
		t.Fatalf("CreateUserServerGrant: %v", err)
	}
	tunnel, err := fixture.repo.CreateTunnelTemplate(ctx, storage.TunnelTemplate{
		Name: "effective-tunnel", State: storage.TunnelStateActive,
		BillingMode: storage.ManagedBillingDownload, TrafficMultiplierMilli: 1000,
		CreatedBy: "admin", Hops: []storage.TunnelTemplateHop{{ServerID: fixture.server.ID}},
	})
	if err != nil {
		t.Fatalf("CreateTunnelTemplate: %v", err)
	}
	billingMode := storage.ManagedBillingDownload
	if _, err := fixture.repo.CreateUserTunnelGrant(ctx, storage.UserTunnelGrant{
		Username: "alice", TunnelID: tunnel.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveForwards: 1,
		BillingModeOverride: &billingMode, CreatedBy: "admin",
	}); err != nil {
		t.Fatalf("CreateUserTunnelGrant: %v", err)
	}
	subscription, err := fixture.repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
		Name: "assigned", Type: storage.SubscribeTypeCreate, Filename: "assigned.yaml", CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateSubscribeFile: %v", err)
	}
	if err := fixture.repo.AssignSubscriptionToUser(ctx, "alice", subscription.ID); err != nil {
		t.Fatalf("AssignSubscriptionToUser: %v", err)
	}
	if err := fixture.repo.SetSystemSetting(ctx, settingUserPeracmPages, `["templates","nodes","templates"]`); err != nil {
		t.Fatalf("SetSystemSetting: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/user/permissions", nil)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "alice"))
	response := httptest.NewRecorder()
	NewUserPermissionsHandler(fixture.repo).UserGet(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("permissions status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Pages        []string                `json:"pages"`
		Entitlements UserServiceEntitlements `json:"service_entitlements"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode permissions: %v", err)
	}
	wantPages := []string{"templates", "nodes", "subscription", "forwarding"}
	if !reflect.DeepEqual(body.Pages, wantPages) {
		t.Fatalf("pages=%v want=%v", body.Pages, wantPages)
	}
	if body.Entitlements.Nodes || !body.Entitlements.Servers || !body.Entitlements.Subscription ||
		!body.Entitlements.Forwarding {
		t.Fatalf("service entitlements=%+v", body.Entitlements)
	}
}

func TestUserPermissionsGlobalAPITokenDoesNotResolveSyntheticUser(t *testing.T) {
	fixture := newEffectiveAuthorizationFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/api/user/permissions", nil)
	request = request.WithContext(auth.ContextWithGlobalAPIToken(request.Context()))
	response := httptest.NewRecorder()

	NewUserPermissionsHandler(fixture.repo).UserGet(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("global API token status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		IsAdmin bool                    `json:"is_admin"`
		Pages   []string                `json:"pages"`
		Service UserServiceEntitlements `json:"service_entitlements"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode permissions: %v", err)
	}
	if !body.IsAdmin || len(body.Service.pages()) != 0 {
		t.Fatalf("global API token permissions=%+v", body)
	}
}
