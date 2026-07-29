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

func TestManagedGrantProtocolPolicyAPIRoundTripAndOmittedUpdate(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "edge-grant-protocol-api", Token: "edge-token", XrayMode: "embedded",
		Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	handler := NewManagedNodesHandler(repo, nil, nil)
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)

	createBody := managedGrantProtocolRequestBody(server.ID, now.Add(-time.Hour), expires, 0,
		[]string{"SS", "vless", "ss"}, []string{"SHADOWSOCKS-2022", "vless-wss", "shadowsocks-2022"}, true)
	request := httptest.NewRequest(http.MethodPost, "/api/admin/users/alice/server-grants", strings.NewReader(createBody))
	request.SetPathValue("username", "alice")
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "owner"))
	response := httptest.NewRecorder()
	handler.HandleAdminGrants(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		Grant storage.UserServerGrant `json:"grant"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if got := strings.Join(created.Grant.AllowedProtocols, ","); got != "shadowsocks,vless" {
		t.Fatalf("created allowed protocols=%q", got)
	}
	if got := strings.Join(created.Grant.AllowedProtocolProfiles, ","); got != "shadowsocks-2022,vless-wss" {
		t.Fatalf("created allowed protocol profiles=%q", got)
	}

	// A pre-feature client does not send allowed_protocols on PUT. The server
	// must retain the current policy instead of silently reverting to all.
	updateBody := managedGrantProtocolRequestBody(server.ID, now.Add(-time.Hour), expires, created.Grant.Version, nil, nil, false)
	request = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/admin/users/alice/server-grants/%d", created.Grant.ID), strings.NewReader(updateBody))
	request.SetPathValue("username", "alice")
	request.SetPathValue("id", fmt.Sprint(created.Grant.ID))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "owner"))
	response = httptest.NewRecorder()
	handler.HandleAdminGrant(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	var updated struct {
		Grant storage.UserServerGrant `json:"grant"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if got := strings.Join(updated.Grant.AllowedProtocols, ","); got != "shadowsocks,vless" {
		t.Fatalf("omitted update replaced allowed protocols=%q", got)
	}
	if got := strings.Join(updated.Grant.AllowedProtocolProfiles, ","); got != "shadowsocks-2022,vless-wss" {
		t.Fatalf("omitted update replaced allowed protocol profiles=%q", got)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/admin/users/alice/server-grants", nil)
	request.SetPathValue("username", "alice")
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "owner"))
	response = httptest.NewRecorder()
	handler.HandleAdminGrants(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", response.Code, response.Body.String())
	}
	var listed struct {
		Grants []storage.UserServerGrant `json:"grants"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listed.Grants) != 1 || strings.Join(listed.Grants[0].AllowedProtocols, ",") != "shadowsocks,vless" ||
		strings.Join(listed.Grants[0].AllowedProtocolProfiles, ",") != "shadowsocks-2022,vless-wss" {
		t.Fatalf("listed grants=%#v", listed.Grants)
	}
}

func TestManagedGrantProtocolPolicyAPIRejectsMismatchedProfileFamilies(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{Name: "edge-profile-mismatch", Token: "token", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	body := managedGrantProtocolRequestBody(server.ID, now.Add(-time.Hour), now.Add(time.Hour), 0,
		[]string{"vmess"}, []string{"vless-wss"}, true)
	request := httptest.NewRequest(http.MethodPost, "/api/admin/users/alice/server-grants", strings.NewReader(body))
	request.SetPathValue("username", "alice")
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "owner"))
	response := httptest.NewRecorder()
	NewManagedNodesHandler(repo, nil, nil).HandleAdminGrants(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "allowed_protocols") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	grants, err := repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(grants) != 0 {
		t.Fatalf("mismatched request persisted grants=%#v err=%v", grants, err)
	}
}

func TestManagedGrantProtocolPolicyBlocksUserActivationAndRetry(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "alice")
	ctx := context.Background()
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, fixture.activation.Source.ID,
		fixture.activation.Source.Generation, storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("mark initial source applied: %v", err)
	}
	grant, err := fixture.repo.GetUserServerGrant(ctx, fixture.activation.Selection.GrantID)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	grant.AllowedProtocols = []string{"vmess"}
	grant, err = fixture.repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "owner")
	if err != nil {
		t.Fatalf("restrict grant: %v", err)
	}

	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil {
		t.Fatalf("get restricted selection: %v", err)
	}
	if selection.DesiredEnabled {
		t.Fatal("restricted selection remained enabled")
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil {
		t.Fatalf("get restricted source: %v", err)
	}
	if source.DesiredState != storage.ManagedDesiredInactive || source.SuspendReason != storage.ManagedSuspendAdminDisabled {
		t.Fatalf("restricted source=%#v", source)
	}
	if ids, err := effectiveManagedNodeIDs(ctx, fixture.repo, "alice"); err != nil || len(ids) != 0 {
		t.Fatalf("restricted node remained effective: ids=%v err=%v", ids, err)
	}

	request := managedUserHTTPRequest(http.MethodPost, "/api/user/managed-nodes", "alice",
		fmt.Sprintf(`{"offer_id":%d}`, fixture.offer.ID))
	response := httptest.NewRecorder()
	fixture.handler.HandleUserManagedNodes(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "protocol") {
		t.Fatalf("activation status=%d body=%s", response.Code, response.Body.String())
	}

	request = managedUserHTTPRequest(http.MethodPost,
		fmt.Sprintf("/api/user/managed-nodes/%d/retry", selection.ID), "alice", "")
	request.SetPathValue("id", fmt.Sprint(selection.ID))
	response = httptest.NewRecorder()
	fixture.handler.HandleUserManagedNodeRetry(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "protocol") {
		t.Fatalf("retry status=%d body=%s", response.Code, response.Body.String())
	}
	selection, err = fixture.repo.GetUserNodeSelection(ctx, selection.ID)
	if err != nil || selection.DesiredEnabled {
		t.Fatalf("retry re-enabled selection=%#v err=%v", selection, err)
	}
}

func TestManagedCatalogResponseIncludesProtocolProfile(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "profile-catalog-user")
	node := fixture.node
	node.ClashConfig = `{"name":"managed-ws","type":"vless","network":"ws"}`
	if _, err := fixture.repo.UpdateNode(context.Background(), node); err != nil {
		t.Fatalf("set catalog profile: %v", err)
	}
	request := managedUserHTTPRequest(http.MethodGet, "/api/user/managed-nodes", "profile-catalog-user", "")
	response := httptest.NewRecorder()
	fixture.handler.HandleUserManagedNodes(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Catalog []struct {
			ProtocolProfile string `json:"protocol_profile"`
		} `json:"catalog"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if len(payload.Catalog) != 1 || payload.Catalog[0].ProtocolProfile != "vless-ws" {
		t.Fatalf("catalog profiles=%#v", payload.Catalog)
	}
}

func TestManagedProtocolProfileDriftRevokesDuringReconcile(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "profile-drift-user")
	ctx := context.Background()
	node := fixture.node
	node.ClashConfig = `{"name":"managed-ws","type":"vless","network":"ws"}`
	if _, err := fixture.repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("set initial node profile: %v", err)
	}
	grant, err := fixture.repo.GetUserServerGrant(ctx, fixture.activation.Selection.GrantID)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	grant.AllowedProtocols = []string{"vless"}
	grant.AllowedProtocolProfiles = []string{"vless-ws"}
	if _, err := fixture.repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "owner"); err != nil {
		t.Fatalf("set exact profile grant: %v", err)
	}

	node.ClashConfig = `{"name":"managed-wss","type":"vless","network":"ws","tls":true}`
	if _, err := fixture.repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift node profile: %v", err)
	}
	if err := fixture.handler.reconcileSource(ctx, fixture.activation.Source); err == nil {
		t.Fatal("reconcile without remote manager unexpectedly succeeded")
	}
	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil || selection.DesiredEnabled {
		t.Fatalf("profile drift did not revoke selection=%#v err=%v", selection, err)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil || source.DesiredState != storage.ManagedDesiredInactive || source.SuspendReason != storage.ManagedSuspendAdminDisabled {
		t.Fatalf("profile drift did not revoke source=%#v err=%v", source, err)
	}
}

func TestEffectiveManagedNodeIDsRejectsPublishedProtocolDrift(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "alice")
	ctx := context.Background()
	linkManagedHandlerCredentialForTest(t, fixture, "alice", "vless")
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, fixture.activation.Source.ID,
		fixture.activation.Source.Generation, storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("mark source applied: %v", err)
	}
	if ids, err := effectiveManagedNodeIDs(ctx, fixture.repo, "alice"); err != nil || len(ids) != 1 {
		t.Fatalf("initial effective nodes=%v err=%v", ids, err)
	}
	node := fixture.node
	node.Protocol = "shadowsocks"
	node.ClashConfig = `{"name":"drifted","type":"ss","server":"203.0.113.20","port":443,"cipher":"aes-128-gcm","password":"shared"}`
	if _, err := fixture.repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift node to classic Shadowsocks: %v", err)
	}
	if ids, err := effectiveManagedNodeIDs(ctx, fixture.repo, "alice"); err != nil || len(ids) != 0 {
		t.Fatalf("drifted protocol remained effective: ids=%v err=%v", ids, err)
	}
	if err := fixture.handler.reconcileSource(ctx, fixture.activation.Source); err == nil {
		t.Fatal("reconcile without a remote manager unexpectedly succeeded")
	}
	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil || selection.DesiredEnabled {
		t.Fatalf("reconcile did not revoke drifted selection=%#v err=%v", selection, err)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil || source.DesiredState != storage.ManagedDesiredInactive ||
		source.SuspendReason != storage.ManagedSuspendAdminDisabled {
		t.Fatalf("reconcile did not revoke drifted source=%#v err=%v", source, err)
	}
}

func TestManagedProtocolReconcilePreservesSelectionOnTemporaryUnavailability(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "alice")
	ctx := context.Background()
	if _, err := fixture.repo.UpdateSelfServiceNodeOffer(ctx, fixture.offer.ID, false, fixture.offer.SortOrder); err != nil {
		t.Fatalf("disable offer: %v", err)
	}
	if err := fixture.handler.reconcileSource(ctx, fixture.activation.Source); err == nil {
		t.Fatal("reconcile without a remote manager unexpectedly succeeded")
	}
	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil || !selection.DesiredEnabled {
		t.Fatalf("temporary offer disable erased selection=%#v err=%v", selection, err)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil || source.DesiredState != storage.ManagedDesiredInactive {
		t.Fatalf("temporary offer disable did not suspend source=%#v err=%v", source, err)
	}

	readFailure := newManagedUserHTTPFixture(t, "bob")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := readFailure.handler.reconcileSource(canceled, readFailure.activation.Source); err == nil {
		t.Fatal("canceled reconcile unexpectedly succeeded")
	}
	selection, err = readFailure.repo.GetUserNodeSelection(context.Background(), readFailure.activation.Selection.ID)
	if err != nil || !selection.DesiredEnabled {
		t.Fatalf("read failure erased selection=%#v err=%v", selection, err)
	}
}

func TestManagedStructuralDriftFailsClosedWithoutErasingSelection(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "structural-user")
	ctx := context.Background()
	linkManagedHandlerCredentialForTest(t, fixture, "structural-user", "vless")
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, fixture.activation.Source.ID,
		fixture.activation.Source.Generation, storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("mark source applied: %v", err)
	}
	node := fixture.node
	node.OriginalServer = "wrong-edge"
	if _, err := fixture.repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift node origin: %v", err)
	}
	if ids, err := effectiveManagedNodeIDs(ctx, fixture.repo, "structural-user"); err != nil || len(ids) != 0 {
		t.Fatalf("structurally drifted node remained effective: ids=%v err=%v", ids, err)
	}
	if err := fixture.handler.reconcileSource(ctx, fixture.activation.Source); err == nil {
		t.Fatal("reconcile without a remote manager unexpectedly succeeded")
	}
	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil || !selection.DesiredEnabled {
		t.Fatalf("structural drift erased user selection=%#v err=%v", selection, err)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil || source.DesiredState != storage.ManagedDesiredInactive {
		t.Fatalf("structural drift did not suspend source=%#v err=%v", source, err)
	}
}

func TestManagedCredentialProtocolSnapshotRevokesAllowedProtocolDrift(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "credential-user")
	ctx := context.Background()
	if err := fixture.repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "credential-user", ServerID: fixture.offer.ServerID, InboundTag: fixture.offer.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"old-vless-credential"}`,
	}); err != nil {
		t.Fatalf("save credential snapshot: %v", err)
	}
	credential, err := fixture.repo.GetUserInboundConfig(ctx, "credential-user", fixture.offer.ServerID, fixture.offer.InboundTag)
	if err != nil {
		t.Fatalf("get credential snapshot: %v", err)
	}
	if err := fixture.repo.SetUserNodeSelectionCredential(ctx, fixture.activation.Selection.ID, credential.ID); err != nil {
		t.Fatalf("link credential snapshot: %v", err)
	}
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, fixture.activation.Source.ID,
		fixture.activation.Source.Generation, storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("mark source applied: %v", err)
	}

	node := fixture.node
	node.Protocol = "vmess"
	node.ClashConfig = `{"name":"managed-vmess","type":"vmess","server":"203.0.113.20","port":443,"uuid":"owner"}`
	if _, err := fixture.repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift node protocol: %v", err)
	}
	if ids, err := effectiveManagedNodeIDs(ctx, fixture.repo, "credential-user"); err != nil || len(ids) != 0 {
		t.Fatalf("old credential remained effective after protocol drift: ids=%v err=%v", ids, err)
	}
	if err := fixture.handler.reconcileSource(ctx, fixture.activation.Source); err == nil {
		t.Fatal("reconcile without a remote manager unexpectedly succeeded")
	}
	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil || selection.DesiredEnabled {
		t.Fatalf("protocol snapshot mismatch did not revoke selection=%#v err=%v", selection, err)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil || source.DesiredState != storage.ManagedDesiredInactive ||
		source.SuspendReason != storage.ManagedSuspendAdminDisabled {
		t.Fatalf("protocol snapshot mismatch did not revoke source=%#v err=%v", source, err)
	}
}

func TestManagedReconcileAllSchedulesCredentialProtocolDriftCleanup(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "scheduled-drift-user")
	ctx := context.Background()
	linkManagedHandlerCredentialForTest(t, fixture, "scheduled-drift-user", "vless")
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, fixture.activation.Source.ID,
		fixture.activation.Source.Generation, storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("mark source applied: %v", err)
	}
	node := fixture.node
	node.Protocol = "vmess"
	node.ClashConfig = `{"name":"managed-vmess","type":"vmess","server":"203.0.113.20","port":443,"uuid":"owner"}`
	if _, err := fixture.repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift node protocol: %v", err)
	}

	fixture.handler.reconcileAll(ctx)
	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil || selection.DesiredEnabled {
		t.Fatalf("scheduled reconcile did not revoke drifted selection=%#v err=%v", selection, err)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil || source.DesiredState != storage.ManagedDesiredInactive ||
		source.Generation == fixture.activation.Source.Generation {
		t.Fatalf("scheduled reconcile did not queue cleanup source=%#v err=%v", source, err)
	}
}

func TestManagedReconcileAllRevokesDriftedCredentialFromInactiveSource(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "inactive-drift-user")
	ctx := context.Background()
	linkManagedHandlerCredentialForTest(t, fixture, "inactive-drift-user", "vless")
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, fixture.activation.Source.ID,
		fixture.activation.Source.Generation, storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("mark source applied: %v", err)
	}
	if _, err := fixture.repo.UpdateSelfServiceNodeOffer(ctx, fixture.offer.ID, false, fixture.offer.SortOrder); err != nil {
		t.Fatalf("temporarily disable offer: %v", err)
	}
	if err := fixture.handler.reconcileSource(ctx, fixture.activation.Source); err == nil {
		t.Fatal("temporary suspension without remote manager unexpectedly succeeded")
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil || source.DesiredState != storage.ManagedDesiredInactive {
		t.Fatalf("temporary offer suspension did not make source inactive=%#v err=%v", source, err)
	}
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, source.ID, source.Generation,
		storage.ManagedObservedInactive, time.Now().UTC()); err != nil {
		t.Fatalf("mark temporary suspension applied: %v", err)
	}
	node := fixture.node
	node.Protocol = "vmess"
	node.ClashConfig = `{"name":"managed-vmess","type":"vmess","server":"203.0.113.20","port":443,"uuid":"owner"}`
	if _, err := fixture.repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift inactive node protocol: %v", err)
	}
	if _, err := fixture.repo.UpdateSelfServiceNodeOffer(ctx, fixture.offer.ID, true, fixture.offer.SortOrder); err != nil {
		t.Fatalf("restore offer: %v", err)
	}

	fixture.handler.reconcileAll(ctx)
	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil || selection.DesiredEnabled {
		t.Fatalf("inactive drifted selection was not revoked=%#v err=%v", selection, err)
	}
	source, err = fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil || source.Generation == source.AppliedGeneration || source.DesiredState != storage.ManagedDesiredInactive {
		t.Fatalf("inactive drift cleanup was not requeued=%#v err=%v", source, err)
	}
}

func TestManagedAppliedSourceWithoutCredentialSnapshotIsRevoked(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "missing-snapshot-user")
	ctx := context.Background()
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, fixture.activation.Source.ID,
		fixture.activation.Source.Generation, storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("mark source applied without snapshot: %v", err)
	}
	if ids, err := effectiveManagedNodeIDs(ctx, fixture.repo, "missing-snapshot-user"); err != nil || len(ids) != 0 {
		t.Fatalf("snapshot-less applied source became effective: ids=%v err=%v", ids, err)
	}
	if err := fixture.handler.reconcileSource(ctx, fixture.activation.Source); err == nil {
		t.Fatal("reconcile without a remote manager unexpectedly succeeded")
	}
	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil || selection.DesiredEnabled {
		t.Fatalf("snapshot-less applied selection was not revoked=%#v err=%v", selection, err)
	}
}

func linkManagedHandlerCredentialForTest(t *testing.T, fixture managedUserHTTPFixture, username, protocol string) *storage.UserInboundConfig {
	t.Helper()
	ctx := context.Background()
	if err := fixture.repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: username, ServerID: fixture.offer.ServerID, InboundTag: fixture.offer.InboundTag,
		Protocol: protocol, CredentialJSON: `{"id":"managed-handler-test-credential"}`,
	}); err != nil {
		t.Fatalf("save managed handler credential: %v", err)
	}
	credential, err := fixture.repo.GetUserInboundConfig(ctx, username, fixture.offer.ServerID, fixture.offer.InboundTag)
	if err != nil {
		t.Fatalf("read managed handler credential: %v", err)
	}
	if err := fixture.repo.SetUserNodeSelectionCredential(ctx, fixture.activation.Selection.ID, credential.ID); err != nil {
		t.Fatalf("link managed handler credential: %v", err)
	}
	return credential
}

func managedGrantProtocolRequestBody(serverID int64, startsAt, expiresAt time.Time, version int64,
	allowed, profiles []string, includeAllowed bool,
) string {
	payload := map[string]any{
		"server_id": serverID, "enabled": true, "starts_at": startsAt, "expires_at": expiresAt,
		"max_active_nodes": 3, "speed_limit_mbps": 25, "connection_limit": 4,
		"traffic_limit_bytes": int64(1024), "billing_mode": storage.ManagedBillingDownload,
		"reset_policy": storage.ManagedResetNone, "reset_day": 1, "version": version,
	}
	if includeAllowed {
		payload["allowed_protocols"] = allowed
		payload["allowed_protocol_profiles"] = profiles
	}
	encoded, _ := json.Marshal(payload)
	return string(encoded)
}
