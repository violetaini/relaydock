package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type packageLeaseAgent struct {
	requests          atomic.Int64
	addClientCalls    atomic.Int64
	removeClientCalls atomic.Int64
	failRemoveAt      int64
	serviceControls   atomic.Int64
	restartStarted    chan struct{}
	releaseRestart    <-chan struct{}
	restartOnce       sync.Once
	batchResult       string
	runtimeWarnings   []string
	xrayRunning       *bool
}

func (a *packageLeaseAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.requests.Add(1)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"inbounds": []any{map[string]any{
				"tag": "vless-in", "protocol": "vless",
				"settings": map[string]any{"clients": []any{map[string]any{"id": "owner-id", "flow": "xtls-rprx-vision"}}},
			}},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/batch-apply":
		result := a.batchResult
		if result == "" {
			result = "ok"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":          true,
			"inbound_results":  []string{result},
			"runtime_warnings": a.runtimeWarnings,
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		var request map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request["action"] == "remove-client" {
			call := a.removeClientCalls.Add(1)
			if a.failRemoveAt > 0 && call == a.failRemoveAt {
				http.Error(w, "forced remove failure", http.StatusBadGateway)
				return
			}
		} else {
			a.addClientCalls.Add(1)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control":
		a.serviceControls.Add(1)
		if a.restartStarted != nil {
			a.restartOnce.Do(func() { close(a.restartStarted) })
			if a.releaseRestart != nil {
				<-a.releaseRestart
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/services/status":
		running := true
		if a.xrayRunning != nil {
			running = *a.xrayRunning
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "xray": map[string]any{"installed": true, "running": running}})
	default:
		http.NotFound(w, r)
	}
}

func TestPackageDeleteFailureRestoresPreviouslyUnboundUsers(t *testing.T) {
	agent := &packageLeaseAgent{failRemoveAt: 2}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "bob", "bob@example.test", "bob", "test-hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "package-delete-node", Protocol: "vless",
		OriginalServer: server.Name, InboundTag: "vless-in", Enabled: true,
		ClashConfig: `{"name":"package-delete-node","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "package-delete-rollback", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	for _, username := range []string{"alice", "bob"} {
		if err := repo.AssignPackageToUser(ctx, username, packageID, start, end, false, 1); err != nil {
			t.Fatalf("assign %s: %v", username, err)
		}
		credential := fmt.Sprintf(`{"id":"%s-id","email":"%s__vless-in"}`, username, username)
		if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
			Username: username, ServerID: server.ID, InboundTag: "vless-in", Protocol: "vless", CredentialJSON: credential,
		}); err != nil {
			t.Fatalf("save %s credential: %v", username, err)
		}
	}

	request := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/admin/packages/%d", packageID), nil)
	recorder := httptest.NewRecorder()
	NewPackageDeleteHandler(repo, remote, nil).ServeHTTP(recorder, request)
	if recorder.Code < 400 {
		t.Fatalf("package deletion status=%d body=%s, want failure", recorder.Code, recorder.Body.String())
	}
	if _, err := repo.GetPackage(ctx, packageID); err != nil {
		t.Fatalf("package was deleted after partial unbind: %v", err)
	}
	for _, username := range []string{"alice", "bob"} {
		user, err := repo.GetUser(ctx, username)
		if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != packageID {
			t.Fatalf("user %s was not restored: user=%+v err=%v", username, user, err)
		}
		if config, configErr := repo.GetUserInboundConfig(ctx, username, server.ID, "vless-in"); configErr != nil || config == nil {
			t.Fatalf("user %s credential was not restored: config=%+v err=%v", username, config, configErr)
		}
	}
}

func TestPackageSwitchRevokeFailureRestoresEarlierRevocations(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	oldNodeA, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "old-a", Protocol: "vless", OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"old-a","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldNodeB, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "old-b", Protocol: "vless", OriginalServer: "missing-server", InboundTag: "missing-in",
		ClashConfig: `{"name":"old-b","type":"vless","server":"missing.example.test","port":443,"uuid":"owner-id-2"}`, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldPackage, _ := repo.CreatePackage(ctx, storage.Package{Name: "old-partial-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{oldNodeA.ID, oldNodeB.ID}})
	newPackage, _ := repo.CreatePackage(ctx, storage.Package{Name: "new-empty-package", TrafficLimitBytes: 1024, CycleDays: 30})
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", oldPackage, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	credentialJSON := `{"id":"alice-id","email":"alice__vless-in"}`
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "vless-in", Protocol: "vless", CredentialJSON: credentialJSON,
	}); err != nil {
		t.Fatal(err)
	}

	assign := NewPackageAssignHandler(repo, remote, nil)
	if _, err := assign.AssignAndProvision(ctx, "alice", newPackage, start, end, false, 1); err == nil {
		t.Fatal("package switch unexpectedly succeeded despite missing old-package server")
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.PackageID != oldPackage {
		t.Fatalf("revoke failure changed package: user=%+v err=%v", user, err)
	}
	config, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in")
	if err != nil || config == nil || config.CredentialJSON != credentialJSON {
		t.Fatalf("earlier revocation was not restored: config=%+v err=%v", config, err)
	}
	if got := agent.removeClientCalls.Load(); got != 1 {
		t.Fatalf("partial revoke made %d remove-client calls, want 1", got)
	}
	if got := agent.addClientCalls.Load(); got != 1 {
		t.Fatalf("partial revoke compensation made %d add-client calls, want 1", got)
	}
}

func newPackageLeaseFixture(t *testing.T, agent http.Handler) (*storage.TrafficRepository, *storage.RemoteServer, *RemoteManageHandler) {
	t.Helper()
	repo, server, remote, _ := newPackageLeaseFixtureWithDBPath(t, agent)
	return repo, server, remote
}

func newPackageLeaseFixtureWithDBPath(t *testing.T, agent http.Handler) (*storage.TrafficRepository, *storage.RemoteServer, *RemoteManageHandler, string) {
	t.Helper()
	agentServer := httptest.NewServer(agent)
	t.Cleanup(agentServer.Close)
	dbPath := filepath.Join(t.TempDir(), "package-lease.db")
	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name:           "package-lease-edge",
		Token:          "package-lease-token",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket,
		IPAddress:      "127.0.0.1",
		ListenPort:     testServerPort(t, agentServer.URL),
		Domain:         "edge.example.test",
		Use443:         true,
		StealSelf:      true,
		StealMode:      "tunnel",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(context.Background(), "alice", "alice@example.test", "alice", "test-hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	return repo, server, NewRemoteManageHandler(repo, nil), dbPath
}

func TestPackageUpdateSnapshotBlocksLateAssignmentUntilTemplateCommit(t *testing.T) {
	repo, _, remote := newPackageLeaseFixture(t, &packageLeaseAgent{})
	ctx := context.Background()
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "package-update-snapshot", TrafficLimitBytes: 1024, CycleDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}

	snapshotted := make(chan struct{})
	continueUpdate := make(chan struct{})
	releasedUpdate := false
	defer func() {
		if !releasedUpdate {
			close(continueUpdate)
		}
	}()
	update := NewPackageUpdateHandler(repo, remote, nil)
	update.afterUserSnapshotForTest = func() {
		close(snapshotted)
		<-continueUpdate
	}
	body, err := json.Marshal(updatePackageRequest{
		ID: packageID, Name: "package-update-snapshot", TrafficLimitGB: 2, CycleDays: 30, Nodes: []int64{},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	updateDone := make(chan struct{})
	go func() {
		defer close(updateDone)
		update.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/api/admin/packages", bytes.NewReader(body)))
	}()
	select {
	case <-snapshotted:
	case <-time.After(5 * time.Second):
		t.Fatal("package update did not reach the bound-user snapshot")
	}

	assignmentDone := make(chan error, 1)
	go func() {
		start := time.Now().Add(-time.Minute)
		_, assignErr := NewPackageAssignHandler(repo, remote, nil).AssignAndProvision(
			ctx, "alice", packageID, start, start.Add(time.Hour), false, 1,
		)
		assignmentDone <- assignErr
	}()
	select {
	case assignErr := <-assignmentDone:
		t.Fatalf("late assignment crossed the package update snapshot: %v", assignErr)
	case <-time.After(100 * time.Millisecond):
	}

	close(continueUpdate)
	releasedUpdate = true
	select {
	case <-updateDone:
		if recorder.Code != http.StatusOK {
			t.Fatalf("package update status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("package update remained blocked")
	}
	select {
	case assignErr := <-assignmentDone:
		if assignErr != nil {
			t.Fatalf("late assignment after package update: %v", assignErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("late assignment remained blocked after package update")
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.PackageID != packageID {
		t.Fatalf("late assignment was not persisted: user=%+v err=%v", user, err)
	}
}

func TestPackageSwitchWaitsForBothPackageLeases(t *testing.T) {
	for _, held := range []string{"old", "new"} {
		t.Run(held, func(t *testing.T) {
			repo, _, remote := newPackageLeaseFixture(t, &packageLeaseAgent{})
			ctx := context.Background()
			oldPackageID, err := repo.CreatePackage(ctx, storage.Package{
				Name: "package-switch-old-" + held, TrafficLimitBytes: 1024, CycleDays: 30,
			})
			if err != nil {
				t.Fatal(err)
			}
			newPackageID, err := repo.CreatePackage(ctx, storage.Package{
				Name: "package-switch-new-" + held, TrafficLimitBytes: 2048, CycleDays: 30,
			})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now().Add(-time.Minute)
			end := start.Add(time.Hour)
			if err := repo.AssignPackageToUser(ctx, "alice", oldPackageID, start, end, false, 1); err != nil {
				t.Fatal(err)
			}
			heldPackageID := oldPackageID
			if held == "new" {
				heldPackageID = newPackageID
			}
			_, release, err := repo.AcquirePackageAuthorizationLease(ctx, heldPackageID)
			if err != nil {
				t.Fatal(err)
			}
			released := false
			defer func() {
				if !released {
					release()
				}
			}()

			done := make(chan error, 1)
			go func() {
				_, assignErr := NewPackageAssignHandler(repo, remote, nil).AssignAndProvision(
					ctx, "alice", newPackageID, start, end, false, 1,
				)
				done <- assignErr
			}()
			select {
			case assignErr := <-done:
				t.Fatalf("package switch crossed held %s package lease: %v", held, assignErr)
			case <-time.After(100 * time.Millisecond):
			}
			release()
			released = true
			select {
			case assignErr := <-done:
				if assignErr != nil {
					t.Fatalf("package switch after releasing %s lease: %v", held, assignErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("package switch remained blocked after releasing %s lease", held)
			}
		})
	}
}

func TestPackageUpdateWorkerSkipsNodeRemovedByNewerTemplate(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "stale-package-add", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-stale",
		ClashConfig: `{"name":"stale-package-add","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "package-stale-worker", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Minute)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, start.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}

	NewPackageUpdateHandler(repo, remote, nil).syncInboundUsersAfterNodeChange(
		ctx, packageID, []int64{}, []int64{node.ID},
	)
	if got := agent.requests.Load(); got != 0 {
		t.Fatalf("stale package worker made %d Agent request(s)", got)
	}
}

func TestPackageExpiryRetainsAssignmentWhenPrivateRoutedRevokeFails(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	parent, err := repo.CreateNode(ctx, storage.Node{
		Username: "alice", NodeName: "private-parent", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"private-parent","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	parentID := parent.ID
	private, err := repo.CreateRoutedNode(ctx, storage.RoutedNodeDetail{
		Node: storage.Node{
			Username: "alice", NodeName: "private-routed", Protocol: "vless", Enabled: true,
			OriginalServer: server.Name, InboundTag: "vless-in", ParentNodeID: &parentID, RoutedOwner: "user",
		},
		RoutedOutboundTag: "private-out", RoutedRuleMarktag: "private-rule",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username: "alice", RoutedNodeID: private.ID, Email: "alice__private",
		CredentialJSON: `{"id":"private-id","email":"alice__private"}`, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "expired-private-routed", TrafficLimitBytes: 1024, CycleDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end, false, 1); err != nil {
		t.Fatal(err)
	}

	// packageLeaseAgent intentionally has no routing endpoint, so the private
	// routed rule revoke fails before the assignment can be cleared.
	NewTrafficLimitEnforcer(repo, remote, nil).CheckAll(ctx)

	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != packageID {
		t.Fatalf("expired assignment was cleared despite failed revoke: %+v", user)
	}
	subaccount, err := repo.GetUserSubaccount(ctx, private.ID, "alice")
	if err != nil || subaccount == nil || subaccount.IsActive || !subaccount.RevokePending {
		t.Fatalf("failed revoke did not persist inactive retry state: account=%+v err=%v", subaccount, err)
	}
}

func packageBatchItem(serverID int64) InboundClientAddItem {
	return InboundClientAddItem{
		Username:   "alice",
		ServerID:   serverID,
		InboundTag: "vless-in",
		Protocol:   "vless",
		Settings: map[string]any{
			"clients": []any{map[string]any{"id": "owner-id", "flow": "xtls-rprx-vision"}},
		},
	}
}

func authorizeInboundBatchFixture(t *testing.T, repo *storage.TrafficRepository, server *storage.RemoteServer) {
	t.Helper()
	ctx := context.Background()
	if err := repo.UpdateRemoteServerXrayMode(ctx, server.ID, "embedded"); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "batch-authorized", Protocol: "vless",
		OriginalServer: server.Name, InboundTag: "vless-in", Enabled: true,
		ClashConfig: `{"name":"batch-authorized","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestPackageImportedWireGuardNodeSkipsPerUserCredentialProvisioning(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x57}, 32)); err != nil {
		t.Fatalf("ConfigureNodeSecretEncryption: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "wireguard-static", Protocol: "wireguard",
		ClashConfig: `{"name":"wireguard-static","type":"wireguard","server":"198.51.100.10","port":51820,"private-key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","public-key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}`,
		Enabled:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "wireguard-static-package", TrafficLimitBytes: 1024, CycleDays: 30,
		Nodes: []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	warnings, err := NewPackageAssignHandler(repo, remote, nil).AssignAndProvision(
		ctx, "alice", pkgID, start, end, false, 1,
	)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("AssignAndProvision warnings=%v err=%v", warnings, err)
	}
	if got := agent.requests.Load(); got != 0 {
		t.Fatalf("WireGuard package node made %d Agent requests, want 0", got)
	}
	if config, configErr := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wireguard-bd61c6"); configErr == nil || config != nil {
		t.Fatalf("WireGuard package node created per-user credential: config=%+v err=%v", config, configErr)
	}
}

func TestInboundBatchActiveInstallationDoesNotReachAgentOrReserveCredential(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "package-batch-active", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	err := applyInboundClientsBatchToAgent(ctx, remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)})
	if !errors.Is(err, storage.ErrRemoteInstallationActive) {
		t.Fatalf("applyInboundClientsBatchToAgent error=%v, want ErrRemoteInstallationActive", err)
	}
	if got := agent.requests.Load(); got != 0 {
		t.Fatalf("active installation reached Agent %d time(s)", got)
	}
	if config, _ := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); config != nil {
		t.Fatalf("active installation reserved credential: %+v", config)
	}
}

func TestInboundBatchNoOpDoesNotRestartXray(t *testing.T) {
	restartStarted := make(chan struct{})
	agent := &packageLeaseAgent{
		restartStarted: restartStarted,
		batchResult:    "ok (no-op)",
	}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	authorizeInboundBatchFixture(t, repo, server)

	if err := applyInboundClientsBatchToAgent(context.Background(), remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)}); err != nil {
		t.Fatalf("applyInboundClientsBatchToAgent: %v", err)
	}
	select {
	case <-restartStarted:
		t.Fatal("idempotent inbound batch unexpectedly restarted Xray")
	case <-time.After(100 * time.Millisecond):
	}

	config, err := repo.GetUserInboundConfig(context.Background(), "alice", server.ID, "vless-in")
	if err != nil || config == nil {
		t.Fatalf("credential was not reserved before Agent publish: config=%+v err=%v", config, err)
	}
}

func TestInboundBatchRuntimeWarningDoesNotRestartXray(t *testing.T) {
	agent := &packageLeaseAgent{runtimeWarnings: []string{"vless-in: runtime apply deferred"}}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	authorizeInboundBatchFixture(t, repo, server)

	if err := applyInboundClientsBatchToAgent(context.Background(), remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)}); err != nil {
		t.Fatalf("applyInboundClientsBatchToAgent: %v", err)
	}
	if got := agent.serviceControls.Load(); got != 0 {
		t.Fatalf("runtime warning made %d Xray control request(s)", got)
	}
}

func TestSamePackageAssignmentRepairsMissingInboundCredential(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "managed", Protocol: "vless", OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"managed","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`,
		Enabled:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "retry-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	if config, _ := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); config != nil {
		t.Fatalf("fixture unexpectedly already has a credential: %+v", config)
	}

	assign := NewPackageAssignHandler(repo, remote, nil)
	warnings, err := assign.AssignAndProvision(ctx, "alice", packageID, start, end, false, 1)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("same-package repair warnings=%v err=%v", warnings, err)
	}
	if config, configErr := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); configErr != nil || config == nil {
		t.Fatalf("missing credential was not repaired: config=%+v err=%v", config, configErr)
	}
	if got := agent.addClientCalls.Load(); got != 1 {
		t.Fatalf("same-package repair made %d add-client calls, want 1", got)
	}
}

func TestPackageReconcilerRevokesInboundRemovedFromTemplate(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "removed", Protocol: "vless", OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"removed","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "cleanup-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "vless-in", Protocol: "vless",
		CredentialJSON: `{"id":"alice-id","email":"alice__vless-in"}`,
	}); err != nil {
		t.Fatal(err)
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Nodes = nil
	if err := repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}

	NewPackageAssignHandler(repo, remote, nil).reconcileAssignments(ctx)

	if got := agent.removeClientCalls.Load(); got != 1 {
		t.Fatalf("reconciler made %d remove-client calls, want 1", got)
	}
	if config, _ := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); config != nil {
		t.Fatalf("credential removed from package template remains: %+v", config)
	}
}

func TestPackageReconcilerDoesNotPreserveInactiveDirectCredential(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	if err := repo.UpdateRemoteServerXrayMode(ctx, server.ID, "embedded"); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "direct", Protocol: "vless", OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"direct","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "direct-cleanup-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialJSON := `{"id":"alice-id","email":"alice__vless-in"}`
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "vless-in", Protocol: "vless", CredentialJSON: credentialJSON,
	}); err != nil {
		t.Fatal(err)
	}
	config, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in")
	if err != nil || config == nil {
		t.Fatalf("load retained credential: config=%+v err=%v", config, err)
	}
	grant, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetUserNodeGrantCredential(ctx, grant.Grant.ID, config.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, grant.Source.ID, grant.Source.Generation, storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := repo.PreparePackageAuthorizationTransition(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Nodes = nil
	if err := repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}

	NewPackageAssignHandler(repo, remote, nil).reconcileAssignments(ctx)

	if got := agent.removeClientCalls.Load(); got != 1 {
		t.Fatalf("reconciler made %d remove-client calls, want 1", got)
	}
	if stored, _ := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); stored != nil {
		t.Fatalf("inactive direct credential was retained: %+v", stored)
	}
}

func TestPackageReconcilerRevokesSharedRoutedAndPreservesUserOwned(t *testing.T) {
	agent := newRoutedHotAgent()
	repo, _, remote, shared := newRoutedHotNode(t, agent)
	ctx := context.Background()
	private, err := repo.CreateRoutedNode(ctx, storage.RoutedNodeDetail{
		Node: storage.Node{
			Username: "alice", NodeName: "Private routed", Protocol: "vless", Enabled: true,
			OriginalServer: shared.OriginalServer, InboundTag: shared.InboundTag,
			ParentNodeID: shared.ParentNodeID, RoutedOwner: "user",
		},
		RoutedOutboundTag: "private-out", RoutedRuleMarktag: "private-rule",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username: "alice", RoutedNodeID: shared.ID, Email: "alice__shared",
		CredentialJSON: `{"id":"shared-id","email":"alice__shared"}`, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username: "alice", RoutedNodeID: private.ID, Email: "alice__private",
		CredentialJSON: `{"id":"private-id","email":"alice__private"}`, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "routed-cleanup-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{shared.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Nodes = nil
	if err := repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}

	NewPackageAssignHandler(repo, remote, nil).reconcileAssignments(ctx)

	sharedAccount, err := repo.GetUserSubaccount(ctx, shared.ID, "alice")
	if err != nil || sharedAccount == nil || sharedAccount.IsActive {
		t.Fatalf("shared routed subaccount was not revoked: account=%+v err=%v", sharedAccount, err)
	}
	privateAccount, err := repo.GetUserSubaccount(ctx, private.ID, "alice")
	if err != nil || privateAccount == nil || !privateAccount.IsActive {
		t.Fatalf("user-owned routed subaccount was not preserved: account=%+v err=%v", privateAccount, err)
	}
	if _, removes := agent.inboundCounts(); removes != 1 {
		t.Fatalf("reconciler made %d routed inbound removals, want 1", removes)
	}
}

func TestPackageSwitchRevokesOldExclusiveInboundCredential(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	oldNode, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "old", Protocol: "vless", OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"old","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	newNode, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "new", Protocol: "vless", OriginalServer: server.Name, InboundTag: "vless-new",
		ClashConfig: `{"name":"new","type":"vless","server":"edge.example.test","port":8443,"uuid":"owner-id-2"}`, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldPackage, _ := repo.CreatePackage(ctx, storage.Package{Name: "old-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{oldNode.ID}})
	newPackage, _ := repo.CreatePackage(ctx, storage.Package{Name: "new-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{newNode.ID}})
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", oldPackage, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "vless-in", Protocol: "vless",
		CredentialJSON: `{"id":"alice-id","email":"alice__vless-in"}`,
	}); err != nil {
		t.Fatal(err)
	}

	assign := NewPackageAssignHandler(repo, remote, nil)
	if _, err := assign.AssignAndProvision(ctx, "alice", newPackage, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	if got := agent.removeClientCalls.Load(); got != 1 {
		t.Fatalf("package switch made %d remove-client calls, want 1", got)
	}
	if config, _ := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); config != nil {
		t.Fatalf("old package credential remains after switch: %+v", config)
	}
}

func TestPackageSwitchAssignmentFailureRestoresOldInboundCredential(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote, dbPath := newPackageLeaseFixtureWithDBPath(t, agent)
	ctx := context.Background()
	if err := repo.UpdateRemoteServerXrayMode(ctx, server.ID, "embedded"); err != nil {
		t.Fatal(err)
	}
	oldNode, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "old", Protocol: "vless", OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"old","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	newNode, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "new", Protocol: "vless", OriginalServer: server.Name, InboundTag: "vless-new",
		ClashConfig: `{"name":"new","type":"vless","server":"edge.example.test","port":8443,"uuid":"owner-id-2"}`, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldPackage, _ := repo.CreatePackage(ctx, storage.Package{Name: "old-failure-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{oldNode.ID}})
	newPackage, _ := repo.CreatePackage(ctx, storage.Package{Name: "new-conflicting-package", TrafficLimitBytes: 1024, CycleDays: 30, Nodes: []int64{newNode.ID}})
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", oldPackage, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	credentialJSON := `{"id":"alice-id","email":"alice__vless-in"}`
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "vless-in", Protocol: "vless", CredentialJSON: credentialJSON,
	}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TRIGGER reject_package_switch
BEFORE UPDATE OF package_id ON users
WHEN OLD.username='alice' AND NEW.package_id != OLD.package_id
BEGIN SELECT RAISE(ABORT, 'forced package switch failure'); END`); err != nil {
		t.Fatal(err)
	}

	assign := NewPackageAssignHandler(repo, remote, nil)
	if _, err := assign.AssignAndProvision(ctx, "alice", newPackage, start, end, false, 1); err == nil || !strings.Contains(err.Error(), "forced package switch failure") {
		t.Fatalf("package switch error=%v, want forced persistence failure", err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.PackageID != oldPackage {
		t.Fatalf("failed switch persisted package=%d, want old package %d", user.PackageID, oldPackage)
	}
	config, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in")
	if err != nil || config == nil || config.CredentialJSON != credentialJSON {
		t.Fatalf("old credential was not restored: config=%+v err=%v", config, err)
	}
	if got := agent.removeClientCalls.Load(); got != 1 {
		t.Fatalf("failed switch made %d remove-client calls, want 1", got)
	}
	if got := agent.addClientCalls.Load(); got != 1 {
		t.Fatalf("failed switch compensation made %d add-client calls, want 1", got)
	}
}

func TestAssignAndProvisionRejectsInvalidOrFutureWindow(t *testing.T) {
	repo, _, remote := newPackageLeaseFixture(t, &packageLeaseAgent{})
	ctx := context.Background()
	packageID, err := repo.CreatePackage(ctx, storage.Package{Name: "window-package", TrafficLimitBytes: 1024, CycleDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	assign := NewPackageAssignHandler(repo, remote, nil)
	now := time.Now()
	for _, test := range []struct {
		name  string
		start time.Time
		end   time.Time
	}{
		{name: "future", start: now.Add(time.Hour), end: now.Add(25 * time.Hour)},
		{name: "reversed", start: now, end: now.Add(-time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := assign.AssignAndProvision(ctx, "alice", packageID, test.start, test.end, false, 1); !errors.Is(err, errInvalidPackageWindow) {
				t.Fatalf("AssignAndProvision error=%v, want invalid window", err)
			}
		})
	}
}

func TestPackageInboundUnbindActiveInstallationKeepsRemoteAndDatabaseState(t *testing.T) {
	agent := &packageLeaseAgent{}
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	config := storage.UserInboundConfig{
		Username:       "alice",
		ServerID:       server.ID,
		InboundTag:     "vless-in",
		Protocol:       "vless",
		CredentialJSON: `{"id":"alice-id","email":"alice__vless-in"}`,
	}
	if err := repo.SaveUserInboundConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "package-unbind-active", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	_, err := removePackageUserInboundConfig(ctx, remote, repo, nil, config)
	if !errors.Is(err, storage.ErrRemoteInstallationActive) {
		t.Fatalf("removePackageUserInboundConfig error=%v, want ErrRemoteInstallationActive", err)
	}
	if got := agent.requests.Load(); got != 0 {
		t.Fatalf("active installation reached Agent %d time(s)", got)
	}
	if stored, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in"); err != nil || stored == nil {
		t.Fatalf("active installation removed credential state: stored=%+v err=%v", stored, err)
	}
}

func TestInboundBatchRejectionIsReportedWithoutPerItemFallback(t *testing.T) {
	var addClientCalls atomic.Int64
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/batch-apply":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "rejected for test"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			addClientCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true})
		default:
			http.NotFound(w, r)
		}
	})
	repo, server, remote := newPackageLeaseFixture(t, agent)

	warnings := applyInboundBatchOrFallback(
		context.Background(), remote, repo, server.ID, []InboundClientAddItem{packageBatchItem(server.ID)}, "PackageLeaseTest",
	)
	if len(warnings) == 0 {
		t.Fatal("rejected batch was reported as success")
	}
	if got := addClientCalls.Load(); got != 0 {
		t.Fatalf("rejected batch unexpectedly fell back to add-client %d time(s)", got)
	}
}
