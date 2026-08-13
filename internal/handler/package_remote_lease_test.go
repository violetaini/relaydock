package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
			a.removeClientCalls.Add(1)
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
	agentServer := httptest.NewServer(agent)
	t.Cleanup(agentServer.Close)
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	if err := repo.CreateUser(context.Background(), "alice", "alice@example.test", "alice", "test-hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	return repo, server, NewRemoteManageHandler(repo, nil)
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

func TestPackageReconcilerPreservesDirectCredentialRemovedFromTemplate(t *testing.T) {
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
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end, false, 1); err != nil {
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
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Nodes = nil
	if err := repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}

	NewPackageAssignHandler(repo, remote, nil).reconcileAssignments(ctx)

	if got := agent.removeClientCalls.Load(); got != 0 {
		t.Fatalf("reconciler removed direct credential %d time(s)", got)
	}
	stored, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in")
	if err != nil || stored == nil || stored.CredentialJSON != credentialJSON {
		t.Fatalf("direct credential was not retained: config=%+v err=%v", stored, err)
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
	repo, server, remote := newPackageLeaseFixture(t, agent)
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
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, newNode.ID, server.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true, StartsAt: start, ExpiresAt: &end,
		MaxActiveNodes: 1, BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "admin", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if grant.SourceType != storage.GrantSourceManual {
		t.Fatalf("fixture grant source=%q, want manual", grant.SourceType)
	}

	assign := NewPackageAssignHandler(repo, remote, nil)
	if _, err := assign.AssignAndProvision(ctx, "alice", newPackage, start, end, false, 1); !errors.Is(err, storage.ErrManagedAccessConflict) {
		t.Fatalf("package switch error=%v, want ErrManagedAccessConflict", err)
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

	_, err := removePackageUserInboundConfig(ctx, remote, repo, config)
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
