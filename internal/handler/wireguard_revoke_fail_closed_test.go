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
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type wireGuardRevokeAgent struct {
	mu              sync.Mutex
	settings        map[string]interface{}
	failRemove      int
	failAdd         int
	failLimiterAt   int
	removeCalls     int
	addCalls        int
	limiterHits     int
	events          []string
	limiterPayloads []WSLimiterConfigPayload
	removeStarted   chan struct{}
	allowRemove     <-chan struct{}
}

func (a *wireGuardRevokeAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"inbounds": []interface{}{map[string]interface{}{
				"tag": "wg-revoke", "protocol": "wireguard", "settings": a.settings,
			}},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
		var payload WSLimiterConfigPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		a.mu.Lock()
		a.limiterHits++
		limiterHit := a.limiterHits
		a.events = append(a.events, "limiter")
		a.limiterPayloads = append(a.limiterPayloads, payload)
		fail := a.failLimiterAt > 0 && limiterHit == a.failLimiterAt
		a.mu.Unlock()
		if fail {
			http.Error(w, "forced WireGuard limiter failure", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		var request struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.Action == "remove-client" {
			a.mu.Lock()
			a.removeCalls++
			a.events = append(a.events, "remove")
			fail := a.failRemove > 0
			if fail {
				a.failRemove--
			}
			started, allow := a.removeStarted, a.allowRemove
			a.mu.Unlock()
			if started != nil {
				select {
				case started <- struct{}{}:
				default:
				}
			}
			if allow != nil {
				<-allow
			}
			if fail {
				http.Error(w, "forced WireGuard remove failure", http.StatusBadGateway)
				return
			}
		} else {
			a.mu.Lock()
			a.addCalls++
			a.events = append(a.events, "peer")
			fail := a.failAdd > 0
			if fail {
				a.failAdd--
			}
			a.mu.Unlock()
			if fail {
				http.Error(w, "forced WireGuard add failure", http.StatusBadGateway)
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "changed": true})
	default:
		http.NotFound(w, r)
	}
}

func (a *wireGuardRevokeAgent) counts() (removeCalls, addCalls, limiterHits int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.removeCalls, a.addCalls, a.limiterHits
}

func (a *wireGuardRevokeAgent) snapshot() ([]string, []WSLimiterConfigPayload) {
	a.mu.Lock()
	defer a.mu.Unlock()
	events := append([]string(nil), a.events...)
	payloads := append([]WSLimiterConfigPayload(nil), a.limiterPayloads...)
	return events, payloads
}

func wireGuardRevokePayloadHasMapping(payload WSLimiterConfigPayload) bool {
	if payload.InboundTag != "wg-revoke" {
		return false
	}
	hasUser := false
	for _, user := range payload.Users {
		if user.Email == "alice__wg-revoke" {
			hasUser = true
			break
		}
	}
	if !hasUser {
		return false
	}
	for _, peer := range payload.WireGuardPeers {
		if peer.Address == "10.88.0.2/32" && peer.Email == "alice__wg-revoke" {
			return true
		}
	}
	return false
}

func wireGuardRevokePayloadsHaveMapping(payloads []WSLimiterConfigPayload) bool {
	for _, payload := range payloads {
		if wireGuardRevokePayloadHasMapping(payload) {
			return true
		}
	}
	return false
}

func wireGuardRevokeLatestUserLimit(payloads []WSLimiterConfigPayload) (WSUserLimitInfo, bool) {
	for payloadIndex := len(payloads) - 1; payloadIndex >= 0; payloadIndex-- {
		if payloads[payloadIndex].InboundTag != "wg-revoke" {
			continue
		}
		for _, user := range payloads[payloadIndex].Users {
			if user.Email == "alice__wg-revoke" {
				return user, true
			}
		}
	}
	return WSUserLimitInfo{}, false
}

func wireGuardRevokeEveryPeerHadMappedLimiter(events []string, payloads []WSLimiterConfigPayload) bool {
	payloadIndex := 0
	mappedLimiterReady := false
	for _, event := range events {
		switch event {
		case "limiter":
			if payloadIndex >= len(payloads) {
				return false
			}
			mappedLimiterReady = wireGuardRevokePayloadHasMapping(payloads[payloadIndex])
			payloadIndex++
		case "peer":
			if !mappedLimiterReady {
				return false
			}
			mappedLimiterReady = false
		}
	}
	return true
}

func newWireGuardRevokeFixture(t *testing.T, agent *wireGuardRevokeAgent) (*storage.TrafficRepository, *storage.RemoteServer, *RemoteManageHandler, *LimiterConfigPusher) {
	t.Helper()
	repo := newWireGuardCredentialTestRepo(t)
	agentServer := httptest.NewServer(agent)
	t.Cleanup(agentServer.Close)
	server := &storage.RemoteServer{
		Name: "wg-revoke-edge", Token: "token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket, IPAddress: "127.0.0.1",
		ListenPort: testServerPort(t, agentServer.URL), XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	capabilities := managedReadyAgentCapabilities()
	capabilities.WireGuardPeerUsersV1 = true
	ws := NewRemoteWSHandler(repo, nil)
	ws.conns.Store(server.ID, &RemoteWSConnection{
		ServerID: server.ID, Capabilities: capabilities,
	})
	return repo, server, NewRemoteManageHandler(repo, ws), NewLimiterConfigPusher(repo, nil)
}

func saveWireGuardRevokeCredential(t *testing.T, repo *storage.TrafficRepository, username string, serverID int64, serverPublicKey string) {
	t.Helper()
	privateKey, publicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generate WireGuard keypair: %v", err)
	}
	encryptedPrivateKey, err := repo.SealWireGuardUserPrivateKey(username, serverID, "wg-revoke", privateKey)
	if err != nil {
		t.Fatalf("seal WireGuard key: %v", err)
	}
	credentialJSON, err := json.Marshal(wireGuardUserCredentialRecord{
		EncryptedPrivateKey: encryptedPrivateKey,
		PublicKey:           publicKey,
		ServerPublicKey:     serverPublicKey,
		Address:             []string{"10.88.0.2/32"},
		MTU:                 1280,
		KeepAlive:           17,
	})
	if err != nil {
		t.Fatalf("marshal WireGuard credential: %v", err)
	}
	if err := repo.SaveUserInboundConfig(context.Background(), storage.UserInboundConfig{
		Username: username, ServerID: serverID, InboundTag: "wg-revoke",
		Protocol: "wireguard", CredentialJSON: string(credentialJSON),
	}); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}
}

func assignWireGuardRevokePackage(t *testing.T, repo *storage.TrafficRepository, username string, server *storage.RemoteServer, settings map[string]interface{}, limitBytes int64) int64 {
	t.Helper()
	node, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "admin", NodeName: "wg-revoke", Protocol: "wireguard", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-revoke",
		ClashConfig: `{"name":"wg-revoke","type":"wireguard","server":"203.0.113.10","port":51820,"private-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public-key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}`,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	inbound := map[string]interface{}{
		"tag": "wg-revoke", "listen": "0.0.0.0", "port": float64(51820), "protocol": "wireguard",
		"settings": settings,
	}
	seedHandlerManagedWireGuardProvenance(t, repo, server, &node, inbound, "managed-wireguard:wg-revoke", true)
	packageID, err := repo.CreatePackage(context.Background(), storage.Package{
		Name: "wg-revoke-package", TrafficLimitBytes: limitBytes, CycleDays: 30,
		Nodes: []int64{node.ID}, SpeedLimitMbps: 5, DeviceLimit: 2,
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	start, end := time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(context.Background(), username, packageID, start, end, false, 1); err != nil {
		t.Fatalf("AssignPackageToUser: %v", err)
	}
	return packageID
}

func TestUserStatusDisableFailsClosedWhenWireGuardRemoveFails(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)

	request := httptest.NewRequest(http.MethodPost, "/api/admin/users/status",
		strings.NewReader(`{"username":"alice","is_active":false}`))
	response := httptest.NewRecorder()
	NewUserStatusHandler(repo, remote, pusher, nil).ServeHTTP(response, request)
	if response.Code < 400 {
		t.Fatalf("status=%d body=%s, want remote failure", response.Code, response.Body.String())
	}
	user, err := repo.GetUser(context.Background(), "alice")
	if err != nil || !user.IsActive {
		t.Fatalf("disable failure changed active state: user=%+v err=%v", user, err)
	}
	if _, err := repo.GetUserInboundConfig(context.Background(), "alice", server.ID, "wg-revoke"); err != nil {
		t.Fatalf("disable failure removed saved credential: %v", err)
	}
	removeCalls, _, limiterHits := agent.counts()
	if removeCalls != 1 {
		t.Fatalf("remove calls=%d, want 1", removeCalls)
	}
	if limiterHits != 0 {
		t.Fatalf("limiter was pushed after failed disable; hits=%d", limiterHits)
	}
}

func TestUserStatusDisableSerializesAuthorityUntilInactiveStateCommits(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	removeStarted := make(chan struct{}, 1)
	allowRemove := make(chan struct{})
	agent := &wireGuardRevokeAgent{
		settings: settings, removeStarted: removeStarted, allowRemove: allowRemove,
	}
	repo, server, remote, _ := newWireGuardRevokeFixture(t, agent)
	assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)

	response := httptest.NewRecorder()
	disableDone := make(chan struct{})
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/api/admin/users/status",
			strings.NewReader(`{"username":"alice","is_active":false}`))
		NewUserStatusHandler(repo, remote, nil, nil).ServeHTTP(response, request)
		close(disableDone)
	}()
	select {
	case <-removeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("disable did not reach remote WireGuard removal")
	}

	authorityObservedActive := make(chan bool, 1)
	authorityErr := make(chan error, 1)
	go func() {
		leasedCtx, release, err := repo.AcquireRemoteServerExclusiveMutationLease(context.Background(), server.ID)
		if err != nil {
			authorityErr <- err
			return
		}
		defer release()
		user, err := repo.GetUser(leasedCtx, "alice")
		if err != nil {
			authorityErr <- err
			return
		}
		authorityObservedActive <- user.IsActive
	}()
	select {
	case active := <-authorityObservedActive:
		t.Fatalf("authority acquired server lease before revoke committed; active=%v", active)
	case err := <-authorityErr:
		t.Fatalf("authority lease failed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(allowRemove)
	select {
	case <-disableDone:
	case <-time.After(2 * time.Second):
		t.Fatal("disable did not finish after remote removal was released")
	}
	if response.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case active := <-authorityObservedActive:
		if active {
			t.Fatal("authority observed the user active after revoke transaction released")
		}
	case err := <-authorityErr:
		t.Fatalf("authority lease failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("authority did not acquire server lease after disable committed")
	}
}

func TestTrafficLimitEnforcerRetriesWireGuardRevokeBeforeMarkingOverLimit(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	assignWireGuardRevokePackage(t, repo, "alice", server, settings, 100)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	ctx := context.Background()
	if err := repo.UpsertUserTraffic(ctx, server.ID, "alice", 0, 0, false); err != nil {
		t.Fatalf("seed traffic: %v", err)
	}
	if err := repo.UpsertUserTraffic(ctx, server.ID, "alice", 60, 50, false); err != nil {
		t.Fatalf("accumulate traffic: %v", err)
	}

	enforcer := NewTrafficLimitEnforcer(repo, remote, pusher)
	enforcer.CheckAll(ctx)
	over, err := repo.IsUserOverLimit(ctx, "alice")
	if err != nil || over {
		t.Fatalf("failed revoke over-limit state=(%v,%v), want false", over, err)
	}
	removeCalls, _, _ := agent.counts()
	if removeCalls != 1 {
		t.Fatalf("first CheckAll remove calls=%d, want 1", removeCalls)
	}

	enforcer.CheckAll(ctx)
	over, err = repo.IsUserOverLimit(ctx, "alice")
	if err != nil || !over {
		t.Fatalf("successful retry over-limit state=(%v,%v), want true", over, err)
	}
	removeCalls, _, _ = agent.counts()
	if removeCalls != 2 {
		t.Fatalf("second CheckAll remove calls=%d, want 2", removeCalls)
	}
}

func TestTrafficLimitEnforcerRetriesWireGuardRestoreWithMappedLimiter(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	assignWireGuardRevokePackage(t, repo, "alice", server, settings, 100)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	ctx := context.Background()
	if err := repo.UpdateUserOverLimit(ctx, "alice", true); err != nil {
		t.Fatalf("mark over-limit: %v", err)
	}
	agent.mu.Lock()
	agent.failAdd = 1
	agent.mu.Unlock()

	enforcer := NewTrafficLimitEnforcer(repo, remote, pusher)
	enforcer.CheckAll(ctx)
	over, err := repo.IsUserOverLimit(ctx, "alice")
	if err != nil || !over {
		t.Fatalf("failed add after restore over-limit state=(%v,%v), want true", over, err)
	}
	_, addCalls, limiterHits := agent.counts()
	if addCalls != 1 {
		t.Fatalf("restore add calls=%d, want 1", addCalls)
	}
	if limiterHits == 0 {
		t.Fatal("restore did not push limiter mapping before WireGuard peer add")
	}

	enforcer.CheckAll(ctx)
	over, err = repo.IsUserOverLimit(ctx, "alice")
	if err != nil || over {
		t.Fatalf("successful restore over-limit state=(%v,%v), want false", over, err)
	}
	_, addCalls, _ = agent.counts()
	if addCalls != 2 {
		t.Fatalf("retry restore add calls=%d, want 2", addCalls)
	}
	events, limiterPayloads := agent.snapshot()
	if !wireGuardRevokeEveryPeerHadMappedLimiter(events, limiterPayloads) {
		t.Fatalf("restore events=%v payloads=%#v, want every peer add preceded by mapped limiter ACK", events, limiterPayloads)
	}
	limit, ok := wireGuardRevokeLatestUserLimit(limiterPayloads)
	if !ok || limit.SpeedLimit != 625_000 || limit.DeviceLimit != 2 {
		t.Fatalf("final restored limiter=%+v found=%v, want normal package policy", limit, ok)
	}
}

func TestTrafficLimitEnforcerNormalLimiterFailureRestoresWireGuardTombstone(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failLimiterAt: 2}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	assignWireGuardRevokePackage(t, repo, "alice", server, settings, 100)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	ctx := context.Background()
	if err := repo.UpdateUserOverLimit(ctx, "alice", true); err != nil {
		t.Fatalf("mark over-limit: %v", err)
	}

	enforcer := NewTrafficLimitEnforcer(repo, remote, pusher)
	enforcer.CheckAll(ctx)
	over, err := repo.IsUserOverLimit(ctx, "alice")
	if err != nil || !over {
		t.Fatalf("normal limiter failure over-limit state=(%v,%v), want retryable true", over, err)
	}
	_, addCalls, limiterHits := agent.counts()
	if addCalls != 1 || limiterHits != 3 {
		t.Fatalf("failed normal policy addCalls=%d limiterHits=%d, want peer plus tombstone/normal/tombstone", addCalls, limiterHits)
	}
	_, limiterPayloads := agent.snapshot()
	limit, ok := wireGuardRevokeLatestUserLimit(limiterPayloads)
	if !ok || limit.SpeedLimit != revocationResidualDenySpeedBytes ||
		limit.DeviceLimit != revocationResidualDenyConnectionLimit {
		t.Fatalf("rollback limiter=%+v found=%v, want checked tombstone", limit, ok)
	}

	enforcer.CheckAll(ctx)
	over, err = repo.IsUserOverLimit(ctx, "alice")
	if err != nil || over {
		t.Fatalf("retry restore over-limit state=(%v,%v), want false", over, err)
	}
	_, limiterPayloads = agent.snapshot()
	limit, ok = wireGuardRevokeLatestUserLimit(limiterPayloads)
	if !ok || limit.SpeedLimit != 625_000 || limit.DeviceLimit != 2 {
		t.Fatalf("retry final limiter=%+v found=%v, want normal package policy", limit, ok)
	}
}

func TestLimiterKeepsWireGuardMappingForPendingDeletionUntilFinalized(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	ctx := context.Background()

	request := httptest.NewRequest(http.MethodPost, "/api/admin/users/delete", strings.NewReader(`{"username":"alice"}`))
	response := httptest.NewRecorder()
	NewUserDeleteHandler(repo, remote, nil).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("first delete status=%d body=%s, want pending", response.Code, response.Body.String())
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.IsActive {
		t.Fatalf("pending deletion user active=%v err=%v", user.IsActive, err)
	}
	pending, err := repo.IsUserDeletionPending(ctx, "alice")
	if err != nil || !pending {
		t.Fatalf("deletion pending=%v err=%v, want true", pending, err)
	}
	// Reproduce the dangerous managed-only edge: the final package/grant is
	// already gone while the Agent still retains the peer. Zero limiter values
	// must not turn that deletion residue into unlimited access.
	if err := repo.RemovePackageFromUser(ctx, "alice"); err != nil {
		t.Fatalf("remove package during pending deletion: %v", err)
	}

	if err := pusher.PushToServerChecked(ctx, server.ID); err != nil {
		t.Fatalf("push limiter after failed deletion revoke: %v", err)
	}
	_, payloads := agent.snapshot()
	if !wireGuardRevokePayloadsHaveMapping(payloads) {
		t.Fatalf("pending deletion limiter payloads missing WireGuard mapping: %#v", payloads)
	}
	var tombstoneLimit *WSUserLimitInfo
	for payloadIndex := range payloads {
		if payloads[payloadIndex].InboundTag != "wg-revoke" {
			continue
		}
		for userIndex := range payloads[payloadIndex].Users {
			if payloads[payloadIndex].Users[userIndex].Email == "alice__wg-revoke" {
				limit := payloads[payloadIndex].Users[userIndex]
				tombstoneLimit = &limit
			}
		}
	}
	if tombstoneLimit == nil || tombstoneLimit.SpeedLimit != revocationResidualDenySpeedBytes ||
		tombstoneLimit.DeviceLimit != revocationResidualDenyConnectionLimit {
		t.Fatalf("pending deletion limiter=%+v, want strict non-zero tombstone", tombstoneLimit)
	}

	sources, err := repo.ListUserInboundAccessSources(ctx, "alice", server.ID)
	if err != nil {
		t.Fatalf("list deletion sources: %v", err)
	}
	if len(sources) == 0 {
		t.Fatal("prepared deletion did not retain a revocation source")
	}
	for _, source := range sources {
		if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, source.ID, source.Generation,
			storage.ManagedObservedInactive, time.Now().UTC()); err != nil {
			t.Fatalf("mark deletion source applied: %v", err)
		}
	}
	if err := repo.FinalizeUserDeletion(ctx, "alice", "admin"); err != nil {
		t.Fatalf("FinalizeUserDeletion: %v", err)
	}
	if _, err := repo.GetUser(ctx, "alice"); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("user survived deletion finalization: %v", err)
	}
	if err := pusher.PushToServerChecked(ctx, server.ID); err != nil {
		t.Fatalf("push limiter after deletion finalization: %v", err)
	}
	_, payloads = agent.snapshot()
	if len(payloads) == 0 {
		t.Fatal("no limiter payloads captured")
	}
	if wireGuardRevokePayloadHasMapping(payloads[len(payloads)-1]) {
		t.Fatalf("finalized deletion limiter payload retained WireGuard mapping: %#v", payloads[len(payloads)-1])
	}
}

func TestManagedReconcilerRetriesDirectWireGuardRevokeAfterProvenanceDrift(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()

	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "wg-revoke", Protocol: "wireguard", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-revoke",
		ClashConfig: `{"name":"wg-revoke","type":"wireguard","server":"203.0.113.10","port":51820,"private-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public-key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}`,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	inbound := map[string]interface{}{
		"tag": "wg-revoke", "listen": "0.0.0.0", "port": float64(51820), "protocol": "wireguard",
		"settings": settings,
	}
	const mutationID = "managed-wireguard:direct-revoke"
	seedHandlerManagedWireGuardProvenance(t, repo, server, &node, inbound, mutationID, true)
	provisionable, err := repo.ManagedWireGuardNodeProvisionable(ctx, node.ID)
	if err != nil || !provisionable {
		t.Fatalf("managed WireGuard provenance valid=%v err=%v, want true", provisionable, err)
	}

	item, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke")
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	if err := repo.SetUserNodeGrantCredential(ctx, item.Grant.ID, credential.ID); err != nil {
		t.Fatalf("SetUserNodeGrantCredential: %v", err)
	}
	applied, err := repo.MarkUserInboundAccessSourceApplied(ctx, item.Source.ID, item.Source.Generation,
		storage.ManagedObservedActive, time.Now().UTC())
	if err != nil {
		t.Fatalf("MarkUserInboundAccessSourceApplied: %v", err)
	}

	deleted, err := repo.DeleteRemoteInboundOwnershipIfMutation(ctx, server.ID, node.InboundTag, mutationID)
	if err != nil || deleted != 1 {
		t.Fatalf("delete managed WireGuard ownership rows=%d err=%v, want 1", deleted, err)
	}
	handler := NewManagedNodesHandler(repo, remote, pusher)

	handler.reconcileAll(ctx)
	current, err := repo.GetUserInboundAccessSource(ctx, applied.ID)
	if err != nil {
		t.Fatalf("GetUserInboundAccessSource after failed revoke: %v", err)
	}
	if current.DesiredState != storage.ManagedDesiredInactive ||
		current.ObservedState != storage.ManagedObservedActive ||
		current.Generation == current.AppliedGeneration || current.RetryCount == 0 ||
		current.LastError == "" || current.NextRetryAt == nil {
		t.Fatalf("failed provenance revoke was not retained for retry: %+v", current)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); err != nil {
		t.Fatalf("failed revoke removed credential before Agent ACK: %v", err)
	}
	currentGrant, err := repo.GetUserNodeGrant(ctx, item.Grant.ID)
	if err != nil || currentGrant.Grant.CredentialConfigID == nil ||
		*currentGrant.Grant.CredentialConfigID != credential.ID {
		t.Fatalf("failed revoke cleared credential link: grant=%+v err=%v", currentGrant, err)
	}
	removeCalls, _, _ := agent.counts()
	if removeCalls != 1 {
		t.Fatalf("first reconcile remove calls=%d, want 1", removeCalls)
	}
	events, limiterPayloads := agent.snapshot()
	if len(events) < 2 || events[0] != "limiter" || events[1] != "remove" {
		t.Fatalf("failed direct revoke events=%v, want checked limiter before remove", events)
	}
	residualLimit, ok := wireGuardRevokeLatestUserLimit(limiterPayloads)
	if !ok || residualLimit.SpeedLimit != revocationResidualDenySpeedBytes ||
		residualLimit.DeviceLimit != revocationResidualDenyConnectionLimit {
		t.Fatalf("failed direct revoke limiter=%+v found=%v, want strict residual", residualLimit, ok)
	}

	if _, err := repo.MarkUserInboundAccessSourceFailed(ctx, current.ID, current.Generation,
		"retry now", time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatalf("make provenance revoke retry due: %v", err)
	}
	handler.reconcileAll(ctx)
	current, err = repo.GetUserInboundAccessSource(ctx, applied.ID)
	if err != nil {
		t.Fatalf("GetUserInboundAccessSource after successful retry: %v", err)
	}
	if current.DesiredState != storage.ManagedDesiredInactive ||
		current.ObservedState != storage.ManagedObservedInactive ||
		current.Generation != current.AppliedGeneration || current.RetryCount != 0 ||
		current.LastError != "" || current.NextRetryAt != nil {
		t.Fatalf("successful provenance revoke did not converge inactive: %+v", current)
	}
	removeCalls, _, _ = agent.counts()
	if removeCalls != 2 {
		t.Fatalf("successful retry remove calls=%d, want 2", removeCalls)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("successful provenance revoke retained credential: %v", err)
	}
	currentGrant, err = repo.GetUserNodeGrant(ctx, item.Grant.ID)
	if err != nil || currentGrant.Grant.CredentialConfigID != nil {
		t.Fatalf("successful provenance revoke retained credential link: grant=%+v err=%v", currentGrant, err)
	}
	_, limiterPayloads = agent.snapshot()
	if len(limiterPayloads) == 0 || wireGuardRevokePayloadHasMapping(limiterPayloads[len(limiterPayloads)-1]) {
		t.Fatalf("successful direct revoke retained limiter mapping: %#v", limiterPayloads)
	}
}

func TestManagedSelectionWireGuardRevokePublishesTombstoneBeforeRemoveAndClearsMapping(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()

	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "wg-revoke", Protocol: "wireguard", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-revoke",
		ClashConfig: `{"name":"wg-revoke","type":"wireguard","server":"203.0.113.10","port":51820,"private-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public-key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}`,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	inbound := map[string]interface{}{
		"tag": "wg-revoke", "listen": "0.0.0.0", "port": float64(51820), "protocol": "wireguard",
		"settings": settings,
	}
	seedHandlerManagedWireGuardProvenance(t, repo, server, &node, inbound,
		"managed-wireguard:selection-revoke", true)
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "admin")
	if err != nil {
		t.Fatalf("CreateSelfServiceNodeOffer: %v", err)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expiresAt, MaxActiveNodes: 1,
		SpeedLimitMbps: 5, ConnectionLimit: 2, BillingMode: storage.ManagedBillingBoth,
		ResetPolicy: storage.ManagedResetNone, ResetDay: 1, BillingTimezone: "Asia/Shanghai",
		AllowedProtocols: []string{"wireguard"}, CreatedBy: "admin",
	}); err != nil {
		t.Fatalf("CreateUserServerGrant: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("ActivateUserNodeSelection: %v", err)
	}
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke")
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	if err := repo.SetUserNodeSelectionCredential(ctx, activation.Selection.ID, credential.ID); err != nil {
		t.Fatalf("SetUserNodeSelectionCredential: %v", err)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID,
		activation.Source.Generation, storage.ManagedObservedActive, now); err != nil {
		t.Fatalf("MarkUserInboundAccessSourceApplied: %v", err)
	}
	deactivation, err := repo.DeactivateUserNodeSelection(ctx, "alice", activation.Selection.ID, "alice",
		storage.ManagedSuspendAdminDisabled, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("DeactivateUserNodeSelection: %v", err)
	}

	handler := NewManagedNodesHandler(repo, remote, pusher)
	if err := handler.reconcileSource(ctx, deactivation.Source); err == nil {
		t.Fatal("first selection revoke succeeded despite forced Agent remove failure")
	}
	current, err := repo.GetUserInboundAccessSource(ctx, deactivation.Source.ID)
	if err != nil {
		t.Fatalf("GetUserInboundAccessSource after failed revoke: %v", err)
	}
	if current.DesiredState != storage.ManagedDesiredInactive ||
		current.ObservedState != storage.ManagedObservedActive ||
		current.Generation == current.AppliedGeneration || current.RetryCount == 0 ||
		current.LastError == "" || current.NextRetryAt == nil {
		t.Fatalf("failed selection revoke was not retained for retry: %+v", current)
	}
	events, limiterPayloads := agent.snapshot()
	if len(events) != 2 || events[0] != "limiter" || events[1] != "remove" {
		t.Fatalf("failed selection revoke events=%v, want checked limiter before remove", events)
	}
	residualLimit, ok := wireGuardRevokeLatestUserLimit(limiterPayloads)
	if !ok || residualLimit.SpeedLimit != revocationResidualDenySpeedBytes ||
		residualLimit.DeviceLimit != revocationResidualDenyConnectionLimit {
		t.Fatalf("failed selection revoke limiter=%+v found=%v, want 1 B/s and 1 connection", residualLimit, ok)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); err != nil {
		t.Fatalf("failed selection revoke removed credential before Agent ACK: %v", err)
	}

	if _, err := repo.MarkUserInboundAccessSourceFailed(ctx, current.ID, current.Generation,
		"retry now", time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatalf("make selection revoke retry due: %v", err)
	}
	handler.reconcileAll(ctx)
	current, err = repo.GetUserInboundAccessSource(ctx, deactivation.Source.ID)
	if err != nil {
		t.Fatalf("GetUserInboundAccessSource after successful retry: %v", err)
	}
	if current.DesiredState != storage.ManagedDesiredInactive ||
		current.ObservedState != storage.ManagedObservedInactive ||
		current.Generation != current.AppliedGeneration || current.RetryCount != 0 ||
		current.LastError != "" || current.NextRetryAt != nil {
		t.Fatalf("successful selection revoke did not converge inactive: %+v", current)
	}
	removeCalls, _, _ := agent.counts()
	if removeCalls != 2 {
		t.Fatalf("selection revoke remove calls=%d, want 2", removeCalls)
	}
	events, limiterPayloads = agent.snapshot()
	if len(events) != 5 || events[2] != "limiter" || events[3] != "remove" || events[4] != "limiter" {
		t.Fatalf("selection retry events=%v, want tombstone/remove/final limiter", events)
	}
	if len(limiterPayloads) == 0 || wireGuardRevokePayloadHasMapping(limiterPayloads[len(limiterPayloads)-1]) {
		t.Fatalf("successful selection revoke retained limiter mapping: %#v", limiterPayloads)
	}
}

func TestStalePackageWireGuardRevokeFailsClosedAndRetries(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		invalidatePkg func(*testing.T, context.Context, *storage.TrafficRepository, *storage.RemoteServer, int64)
	}{
		{
			name: "template removal",
			invalidatePkg: func(t *testing.T, ctx context.Context, repo *storage.TrafficRepository, _ *storage.RemoteServer, packageID int64) {
				t.Helper()
				pkg, err := repo.GetPackage(ctx, packageID)
				if err != nil {
					t.Fatalf("GetPackage: %v", err)
				}
				pkg.Nodes = []int64{}
				if err := repo.UpdatePackage(ctx, *pkg); err != nil {
					t.Fatalf("remove WireGuard node from package template: %v", err)
				}
			},
		},
		{
			name: "provenance drift",
			invalidatePkg: func(t *testing.T, ctx context.Context, repo *storage.TrafficRepository, server *storage.RemoteServer, packageID int64) {
				t.Helper()
				pkg, err := repo.GetPackage(ctx, packageID)
				if err != nil || len(pkg.Nodes) != 1 {
					t.Fatalf("GetPackage nodes=%v err=%v", pkg.Nodes, err)
				}
				node, err := repo.GetNodeByID(ctx, pkg.Nodes[0])
				if err != nil {
					t.Fatalf("GetNodeByID: %v", err)
				}
				deleted, err := repo.DeleteRemoteInboundOwnershipIfMutation(
					ctx, server.ID, node.InboundTag, node.InboundMutationID,
				)
				if err != nil || deleted != 1 {
					t.Fatalf("delete WireGuard ownership rows=%d err=%v, want 1", deleted, err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			settings, serverPublicKey := wireGuardCredentialTestSettings(t)
			agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
			repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
			ctx := context.Background()
			packageID := assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
			saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
			testCase.invalidatePkg(t, ctx, repo, server, packageID)

			cfg, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke")
			if err != nil {
				t.Fatalf("GetUserInboundConfig: %v", err)
			}
			hasAccess, _, err := effectiveUserInboundAuthorization(
				ctx, repo, "alice", server.ID, "wg-revoke", time.Now().UTC(),
			)
			if err != nil || hasAccess {
				t.Fatalf("stale package credential effective=%v err=%v, want false", hasAccess, err)
			}

			retained, err := removeStalePackageUserInboundConfig(ctx, remote, repo, pusher, *cfg)
			if err == nil || retained {
				t.Fatalf("first stale package revoke retained=%v err=%v, want failed removal", retained, err)
			}
			if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); err != nil {
				t.Fatalf("failed stale package revoke removed credential: %v", err)
			}
			events, limiterPayloads := agent.snapshot()
			if len(events) != 2 || events[0] != "limiter" || events[1] != "remove" {
				t.Fatalf("failed stale package revoke events=%v, want limiter before remove", events)
			}
			residualLimit, ok := wireGuardRevokeLatestUserLimit(limiterPayloads)
			if !ok || residualLimit.SpeedLimit != revocationResidualDenySpeedBytes ||
				residualLimit.DeviceLimit != revocationResidualDenyConnectionLimit {
				t.Fatalf("failed stale package revoke limiter=%+v found=%v, want 1 B/s and 1 connection", residualLimit, ok)
			}
			hasAccess, _, err = effectiveUserInboundAuthorization(
				ctx, repo, "alice", server.ID, "wg-revoke", time.Now().UTC(),
			)
			if err != nil || hasAccess {
				t.Fatalf("residual limiter became authorization=%v err=%v", hasAccess, err)
			}
			if err := pusher.PushToServerChecked(ctx, server.ID); err != nil {
				t.Fatalf("refresh limiter while stale package removal is pending: %v", err)
			}
			_, limiterPayloads = agent.snapshot()
			residualLimit, ok = wireGuardRevokeLatestUserLimit(limiterPayloads)
			if !ok || residualLimit.SpeedLimit != revocationResidualDenySpeedBytes ||
				residualLimit.DeviceLimit != revocationResidualDenyConnectionLimit {
				t.Fatalf("ordinary limiter refresh dropped stale package tombstone: limit=%+v found=%v", residualLimit, ok)
			}

			retained, err = removeStalePackageUserInboundConfig(ctx, remote, repo, pusher, *cfg)
			if err != nil || retained {
				t.Fatalf("retry stale package revoke retained=%v err=%v, want removed", retained, err)
			}
			if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("successful stale package revoke retained credential: %v", err)
			}
			removeCalls, _, _ := agent.counts()
			if removeCalls != 2 {
				t.Fatalf("stale package revoke remove calls=%d, want 2", removeCalls)
			}
			events, limiterPayloads = agent.snapshot()
			if len(events) != 6 || events[2] != "limiter" || events[3] != "limiter" ||
				events[4] != "remove" || events[5] != "limiter" {
				t.Fatalf("stale package retry events=%v, want tombstone/remove/final limiter", events)
			}
			if len(limiterPayloads) == 0 || wireGuardRevokePayloadHasMapping(limiterPayloads[len(limiterPayloads)-1]) {
				t.Fatalf("successful stale package revoke retained limiter mapping: %#v", limiterPayloads)
			}
		})
	}
}

func TestManagedReconcilerScansDirectWireGuardProvenanceBeyondFirstPage(t *testing.T) {
	validSettings, _ := wireGuardCredentialTestSettings(t)
	repo, server, _, _ := newWireGuardRevokeFixture(t, &wireGuardRevokeAgent{settings: validSettings})
	ctx := context.Background()

	validNode, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "wg-valid-page", Protocol: "wireguard", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-valid-page",
		ClashConfig: `{"name":"wg-valid-page","type":"wireguard","server":"203.0.113.10","port":51820,"private-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public-key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}`,
	})
	if err != nil {
		t.Fatalf("create valid WireGuard node: %v", err)
	}
	validInbound := map[string]interface{}{
		"tag": "wg-valid-page", "listen": "0.0.0.0", "port": float64(51820), "protocol": "wireguard",
		"settings": validSettings,
	}
	seedHandlerManagedWireGuardProvenance(t, repo, server, &validNode, validInbound,
		"managed-wireguard:valid-page", true)

	var lastValid *storage.UserNodeGrantWithSource
	for index := 0; index < 201; index++ {
		username := fmt.Sprintf("wg-page-user-%03d", index)
		createManagedSecurityTestUser(t, repo, username, storage.RoleUser)
		item, _, grantErr := repo.UpsertManualUserNodeGrant(ctx, username, validNode.ID, nil, "admin")
		if grantErr != nil {
			t.Fatalf("create valid grant %d: %v", index, grantErr)
		}
		applied, applyErr := repo.MarkUserInboundAccessSourceApplied(ctx, item.Source.ID, item.Source.Generation,
			storage.ManagedObservedActive, time.Now().UTC())
		if applyErr != nil {
			t.Fatalf("mark valid grant %d applied: %v", index, applyErr)
		}
		item.Source = *applied
		lastValid = item
	}

	invalidSettings, _ := wireGuardCredentialTestSettings(t)
	invalidNode, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "wg-invalid-tail", Protocol: "wireguard", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-invalid-tail",
		ClashConfig: `{"name":"wg-invalid-tail","type":"wireguard","server":"203.0.113.10","port":51821,"private-key":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=","public-key":"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="}`,
	})
	if err != nil {
		t.Fatalf("create invalid-tail WireGuard node: %v", err)
	}
	invalidInbound := map[string]interface{}{
		"tag": "wg-invalid-tail", "listen": "0.0.0.0", "port": float64(51821), "protocol": "wireguard",
		"settings": invalidSettings,
	}
	const invalidMutationID = "managed-wireguard:invalid-tail"
	seedHandlerManagedWireGuardProvenance(t, repo, server, &invalidNode, invalidInbound,
		invalidMutationID, true)
	invalid, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", invalidNode.ID, nil, "admin")
	if err != nil {
		t.Fatalf("create invalid-tail direct grant: %v", err)
	}
	invalidApplied, err := repo.MarkUserInboundAccessSourceApplied(ctx, invalid.Source.ID,
		invalid.Source.Generation, storage.ManagedObservedActive, time.Now().UTC())
	if err != nil {
		t.Fatalf("mark invalid-tail grant applied: %v", err)
	}
	deleted, err := repo.DeleteRemoteInboundOwnershipIfMutation(ctx, server.ID, invalidNode.InboundTag, invalidMutationID)
	if err != nil || deleted != 1 {
		t.Fatalf("delete invalid-tail ownership rows=%d err=%v, want 1", deleted, err)
	}

	NewManagedNodesHandler(repo, nil, nil).reconcileAll(ctx)

	validCurrent, err := repo.GetUserInboundAccessSource(ctx, lastValid.Source.ID)
	if err != nil {
		t.Fatalf("load last valid grant source: %v", err)
	}
	if validCurrent.DesiredState != storage.ManagedDesiredActive ||
		validCurrent.Generation != validCurrent.AppliedGeneration {
		t.Fatalf("valid grant at page boundary was revoked: %+v", validCurrent)
	}
	invalidCurrent, err := repo.GetUserInboundAccessSource(ctx, invalidApplied.ID)
	if err != nil {
		t.Fatalf("load invalid-tail source: %v", err)
	}
	if invalidCurrent.DesiredState != storage.ManagedDesiredInactive ||
		invalidCurrent.ObservedState != storage.ManagedObservedActive ||
		invalidCurrent.Generation == invalidCurrent.AppliedGeneration {
		t.Fatalf("invalid grant after first page was not queued for revoke: %+v", invalidCurrent)
	}
	pending, err := repo.ListPendingUserInboundAccessSources(ctx, time.Now().UTC(), 10, server.ID)
	if err != nil || len(pending) != 1 || pending[0].ID != invalidCurrent.ID {
		t.Fatalf("pending revoke queue=%+v err=%v, want invalid tail source %d", pending, err, invalidCurrent.ID)
	}
}
