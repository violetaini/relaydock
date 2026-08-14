package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type fakeForwardTunnelDeployer struct {
	mu                 sync.Mutex
	generation         map[string]int64
	state              map[string]string
	applyCalls         int
	suspendCalls       int
	removeCalls        int
	failApplyServer    int64
	failSuspendOnce    bool
	portConflictServer int64
	portConflictOnce   bool
	failRemoveResource string
	failRemoveOnce     bool
	specs              []ForwardTunnelSpec
	operations         []string
}

type blockingProbeForwardTunnelDeployer struct {
	*fakeForwardTunnelDeployer
	probeOnce sync.Once
	entered   chan struct{}
	release   chan struct{}
}

func (d *blockingProbeForwardTunnelDeployer) Probe(ctx context.Context, _ int64) error {
	d.probeOnce.Do(func() { close(d.entered) })
	select {
	case <-d.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newFakeForwardTunnelDeployer() *fakeForwardTunnelDeployer {
	return &fakeForwardTunnelDeployer{generation: map[string]int64{}, state: map[string]string{}}
}

func (d *fakeForwardTunnelDeployer) Probe(context.Context, int64) error { return nil }

func (d *fakeForwardTunnelDeployer) Apply(_ context.Context, spec ForwardTunnelSpec) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.applyCalls++
	d.specs = append(d.specs, spec)
	d.operations = append(d.operations, "apply:"+spec.ResourceID)
	if d.portConflictOnce && d.portConflictServer == spec.ServerID {
		d.portConflictOnce = false
		return ErrForwardTunnelPortInUse
	}
	if d.failApplyServer == spec.ServerID {
		return errors.New("temporary apply failure")
	}
	current := d.generation[spec.ResourceID]
	if spec.Generation < current || (spec.Generation == current && d.state[spec.ResourceID] == "suspended") {
		return errors.New("generation conflict")
	}
	d.generation[spec.ResourceID] = spec.Generation
	d.state[spec.ResourceID] = "active"
	return nil
}

func (d *fakeForwardTunnelDeployer) Suspend(_ context.Context, _ int64, resourceID string, generation int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.suspendCalls++
	if d.failSuspendOnce {
		d.failSuspendOnce = false
		return errors.New("temporary suspend failure")
	}
	if generation < d.generation[resourceID] {
		return errors.New("stale generation")
	}
	d.generation[resourceID] = generation
	d.state[resourceID] = "suspended"
	return nil
}

func (d *fakeForwardTunnelDeployer) Remove(_ context.Context, _ int64, resourceID string, generation int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeCalls++
	d.operations = append(d.operations, "remove:"+resourceID)
	if d.failRemoveOnce && d.failRemoveResource == resourceID {
		d.failRemoveOnce = false
		return errors.New("temporary remove failure")
	}
	if generation < d.generation[resourceID] {
		return errors.New("stale generation")
	}
	d.generation[resourceID], d.state[resourceID] = generation, "deleted"
	return nil
}

type forwardingHandlerFixture struct {
	repo        *storage.TrafficRepository
	handler     *ForwardingHandler
	deployer    *fakeForwardTunnelDeployer
	grant       *storage.UserTunnelGrant
	forward     *storage.UserForwardRule
	nodeID      int64
	selectionID int64
	dbPath      string
}

func newForwardingHandlerFixture(t *testing.T) forwardingHandlerFixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "forwarding-handler.db")
	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	servers := make([]storage.RemoteServer, 2)
	for i := range servers {
		servers[i] = storage.RemoteServer{Name: []string{"entry", "target"}[i], Token: []string{"entry-token", "target-token"}[i], Status: storage.RemoteServerStatusConnected, IPAddress: []string{"203.0.113.10", "198.51.100.20"}[i], XrayMode: "embedded"}
		if err := repo.CreateRemoteServer(ctx, &servers[i]); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.UpdateRemoteServerXrayStatus(ctx, servers[i].ID, true, "test"); err != nil {
			t.Fatal(err)
		}
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "Reality target", Protocol: "vless", Enabled: true,
		OriginalServer: servers[1].Name, InboundTag: "vless-reality",
		ClashConfig: `{"name":"Reality target","type":"vless","server":"198.51.100.20","port":443,"uuid":"admin-secret","servername":"www.example.com"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, servers[1].ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	managedExpires := now.Add(2 * time.Hour)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: servers[1].ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &managedExpires, MaxActiveNodes: 1,
		BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID, activation.Source.Generation,
		storage.ManagedObservedActive, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{Username: "alice", ServerID: servers[1].ID, InboundTag: node.InboundTag, Protocol: "vless", CredentialJSON: `{"id":"alice-user-id"}`}); err != nil {
		t.Fatal(err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, "alice", servers[1].ID, node.InboundTag)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetUserNodeSelectionCredential(ctx, activation.Selection.ID, credential.ID); err != nil {
		t.Fatal(err)
	}
	tunnel, err := repo.CreateTunnelTemplate(ctx, storage.TunnelTemplate{Name: "two hop", State: storage.TunnelStateActive, BillingMode: storage.ManagedBillingDownload, TrafficMultiplierMilli: 1000, CreatedBy: "admin", Hops: []storage.TunnelTemplateHop{{ServerID: servers[0].ID}, {ServerID: servers[1].ID}}})
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Hour)
	billingMode := storage.ManagedBillingDownload
	grant, err := repo.CreateUserTunnelGrant(ctx, storage.UserTunnelGrant{Username: "alice", TunnelID: tunnel.ID, Enabled: true, StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveForwards: 4, BillingModeOverride: &billingMode, AllowManagedTarget: true, CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	forward, err := repo.CreateUserForward(ctx, storage.CreateUserForwardInput{Username: "alice", Name: "reality", GrantPublicID: grant.PublicID, TargetNodeID: node.ID, TargetHost: servers[1].IPAddress, TargetPort: 443, EffectiveExpiresAt: &expires, Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	deployer := newFakeForwardTunnelDeployer()
	handler := NewForwardingHandler(repo, deployer)
	if err := handler.deployForward(ctx, forward); err != nil {
		t.Fatal(err)
	}
	forward, err = repo.GetUserForward(ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	return forwardingHandlerFixture{repo: repo, handler: handler, deployer: deployer, grant: grant, forward: forward, nodeID: node.ID, selectionID: activation.Selection.ID, dbPath: dbPath}
}

func TestUserForwardDTOBillsUploadMode(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	upload := storage.ManagedBillingUpload
	input := *fixture.grant
	input.BillingModeOverride = &upload
	if _, err := fixture.repo.UpdateUserTunnelGrant(ctx, fixture.grant.PublicID, "alice", input, fixture.grant.Version, "admin"); err != nil {
		t.Fatal(err)
	}
	entry := fixture.forward.Hops[0]
	if err := fixture.repo.UpsertNodeTraffic(ctx, entry.ServerID, entry.ResourceTag, "inbound", 30, 70, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.SyncUserForwardUsage(ctx); err != nil {
		t.Fatal(err)
	}
	forward, err := fixture.repo.GetUserForward(ctx, fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	dto := fixture.handler.userForwardDTO(ctx, *forward)
	if dto.UplinkBytes != 30 || dto.DownlinkBytes != 70 || dto.BilledBytes != 30 {
		t.Fatalf("upload DTO usage=%d/%d billed=%d want=30/70 billed=30", dto.UplinkBytes, dto.DownlinkBytes, dto.BilledBytes)
	}
}

func TestForwardingReconcileGenerationSuspendResumeAndHealthyRenew(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	initialGeneration := fixture.forward.Generation
	fixture.handler.reconcileForwards(ctx)
	renewed, err := fixture.repo.GetUserForward(ctx, fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Generation != initialGeneration {
		t.Fatalf("healthy renewal bumped generation: got=%d want=%d", renewed.Generation, initialGeneration)
	}
	disabled := *fixture.grant
	disabled.Enabled = false
	disabledGrant, err := fixture.repo.UpdateUserTunnelGrant(ctx, fixture.grant.PublicID, "alice", disabled, fixture.grant.Version, "admin")
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.reconcileForwards(ctx)
	suspended, err := fixture.repo.GetUserForward(ctx, fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if suspended.DesiredState != storage.ForwardDesiredActive || suspended.ObservedState != storage.ForwardObservedSuspended || suspended.Generation <= initialGeneration {
		t.Fatalf("unexpected system suspension: %+v", suspended)
	}
	suspendGeneration := suspended.Generation
	enabled := *disabledGrant
	enabled.Enabled = true
	newExpiry := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	enabled.ExpiresAt = &newExpiry
	if _, err := fixture.repo.UpdateUserTunnelGrant(ctx, fixture.grant.PublicID, "alice", enabled, disabledGrant.Version, "admin"); err != nil {
		t.Fatal(err)
	}
	fixture.handler.reconcileForwards(ctx)
	resumed, err := fixture.repo.GetUserForward(ctx, fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ObservedState != storage.ForwardObservedActive || resumed.Generation <= suspendGeneration {
		t.Fatalf("forward did not resume with a newer generation: %+v", resumed)
	}
	if resumed.EffectiveExpiresAt == nil || !resumed.EffectiveExpiresAt.Equal(newExpiry) {
		t.Fatalf("effective expiry=%v want=%v", resumed.EffectiveExpiresAt, newExpiry)
	}
	stableGeneration := resumed.Generation
	fixture.handler.reconcileForwards(ctx)
	stable, _ := fixture.repo.GetUserForward(ctx, fixture.forward.PublicID, "alice")
	if stable.Generation != stableGeneration {
		t.Fatalf("second healthy renewal bumped generation: %d -> %d", stableGeneration, stable.Generation)
	}
}

func TestForwardingHealthyRenewFailureDoesNotSuspendExistingHops(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	beforeSuspends := fixture.deployer.suspendCalls
	fixture.deployer.failApplyServer = fixture.forward.Hops[0].ServerID
	if err := fixture.handler.deployForward(context.Background(), fixture.forward); err == nil {
		t.Fatal("expected renewal failure")
	}
	if fixture.deployer.suspendCalls != beforeSuspends {
		t.Fatalf("healthy renewal failure suspended existing hop: before=%d after=%d", beforeSuspends, fixture.deployer.suspendCalls)
	}
	latest, err := fixture.repo.GetUserForward(context.Background(), fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if latest.ObservedState != storage.ForwardObservedActive || fixture.handler.userForwardDTO(context.Background(), *latest).EntryHost == "" {
		t.Fatalf("healthy lease was hidden after renewal failure: %+v", latest)
	}
}

func TestForwardingInactiveProvisioningRetriesSameGeneration(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	fixture.deployer.failSuspendOnce = true
	if err := fixture.handler.suspendForward(context.Background(), fixture.forward, "alice"); err == nil {
		t.Fatal("expected first suspend failure")
	}
	pending, err := fixture.repo.GetUserForward(context.Background(), fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	generation := pending.Generation
	if pending.DesiredState != storage.ForwardDesiredInactive {
		t.Fatalf("desired=%s", pending.DesiredState)
	}
	fixture.handler.reconcileForwards(context.Background())
	suspended, err := fixture.repo.GetUserForward(context.Background(), fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if suspended.ObservedState != storage.ForwardObservedSuspended || suspended.Generation != generation {
		t.Fatalf("inactive retry changed generation or failed: %+v", suspended)
	}
}

func TestForwardingPortConflictReallocatesIdentityAndRetries(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	second, err := fixture.repo.CreateUserForward(ctx, storage.CreateUserForwardInput{
		Username: "alice", Name: "port retry", GrantPublicID: fixture.grant.PublicID,
		TargetNodeID: fixture.forward.TargetNodeID, TargetHost: fixture.forward.TargetHost,
		TargetPort: fixture.forward.TargetPort, EffectiveExpiresAt: fixture.grant.ExpiresAt, Actor: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldEntryPort := second.AllocatedEntryPort
	oldResourceIDs := make([]string, len(second.Hops))
	oldGenerations := make([]int64, len(second.Hops))
	for i := range second.Hops {
		oldResourceIDs[i], oldGenerations[i] = second.Hops[i].ResourceID, second.Hops[i].Generation
	}
	fixture.deployer.portConflictServer = second.Hops[0].ServerID
	fixture.deployer.portConflictOnce = true
	fixture.deployer.failRemoveResource = second.Hops[1].ResourceID
	fixture.deployer.failRemoveOnce = true
	if err := fixture.handler.deployForward(ctx, second); err != nil {
		t.Fatalf("deploy after port reallocation: %v", err)
	}
	updated, err := fixture.repo.GetUserForward(ctx, second.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ObservedState != storage.ForwardObservedActive || updated.AllocatedEntryPort == oldEntryPort {
		t.Fatalf("port conflict did not replace entry port: before=%d after=%d state=%s", oldEntryPort, updated.AllocatedEntryPort, updated.ObservedState)
	}
	for i := range updated.Hops {
		if updated.Hops[i].ResourceID == oldResourceIDs[i] || updated.Hops[i].Generation <= oldGenerations[i] {
			t.Fatalf("hop %d identity was not durably replaced: before=%s/%d after=%s/%d", i,
				oldResourceIDs[i], oldGenerations[i], updated.Hops[i].ResourceID, updated.Hops[i].Generation)
		}
	}
	if fixture.deployer.removeCalls < len(second.Hops)+1 {
		t.Fatalf("partial cleanup was not retried: remove calls=%d", fixture.deployer.removeCalls)
	}
}

func TestForwardNeedsPortConvergence(t *testing.T) {
	base := []storage.UserForwardHop{
		{ListenPort: 2033, NextPort: 2033},
		{ListenPort: 2033, NextPort: 443},
	}
	tests := []struct {
		name string
		hops []storage.UserForwardHop
		want bool
	}{
		{name: "common route", hops: base},
		{name: "different listen port", hops: []storage.UserForwardHop{{ListenPort: 2033, NextPort: 2034}, {ListenPort: 2034, NextPort: 443}}, want: true},
		{name: "different intermediate next port", hops: []storage.UserForwardHop{{ListenPort: 2033, NextPort: 2040}, {ListenPort: 2033, NextPort: 443}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := forwardNeedsPortConvergence(&storage.UserForwardRule{Hops: test.hops}); got != test.want {
				t.Fatalf("forwardNeedsPortConvergence()=%t want=%t", got, test.want)
			}
		})
	}
}

func TestForwardingLegacyRouteConvergesBeforeDeploymentAndCleansOldIdentities(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	oldPort := fixture.forward.Hops[0].ListenPort
	legacyPort := oldPort + 1
	if legacyPort > 65535 {
		legacyPort = oldPort - 1
	}
	db, err := sql.Open("sqlite", fixture.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE user_forward_hops SET next_port=? WHERE id=?`, legacyPort, fixture.forward.Hops[0].ID); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE user_forward_hops SET listen_port=? WHERE id=?`, legacyPort, fixture.forward.Hops[1].ID); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := fixture.repo.GetUserForward(ctx, fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !forwardNeedsPortConvergence(legacy) || legacy.RequestedEntryPort != 0 {
		t.Fatalf("legacy route was not recognized for automatic convergence: %+v", legacy)
	}
	oldResourceIDs := make(map[string]bool, len(legacy.Hops))
	for _, hop := range legacy.Hops {
		oldResourceIDs[hop.ResourceID] = true
	}
	fixture.deployer.mu.Lock()
	fixture.deployer.applyCalls = 0
	fixture.deployer.removeCalls = 0
	fixture.deployer.specs = nil
	fixture.deployer.operations = nil
	fixture.deployer.mu.Unlock()

	if err := fixture.handler.deployForward(ctx, legacy); err != nil {
		t.Fatalf("deploy converged legacy route: %v", err)
	}
	updated, err := fixture.repo.GetUserForward(ctx, legacy.PublicID, legacy.Username)
	if err != nil {
		t.Fatal(err)
	}
	if forwardNeedsPortConvergence(updated) {
		t.Fatalf("route did not converge: %+v", updated.Hops)
	}
	commonPort := updated.Hops[0].ListenPort
	if updated.AllocatedEntryPort != commonPort || commonPort == oldPort || commonPort == legacyPort {
		t.Fatalf("converged entry port=%d allocated=%d old=%d legacy=%d", commonPort, updated.AllocatedEntryPort, oldPort, legacyPort)
	}
	for i, hop := range updated.Hops {
		if oldResourceIDs[hop.ResourceID] {
			t.Fatalf("hop %d retained legacy identity %q", i, hop.ResourceID)
		}
	}

	fixture.deployer.mu.Lock()
	defer fixture.deployer.mu.Unlock()
	seenApply := false
	removeCount := 0
	for _, operation := range fixture.deployer.operations {
		switch {
		case strings.HasPrefix(operation, "apply:"):
			seenApply = true
		case strings.HasPrefix(operation, "remove:"):
			if seenApply {
				t.Fatalf("legacy cleanup ran after new deployment: operations=%v", fixture.deployer.operations)
			}
			removeCount++
		}
	}
	if removeCount != len(legacy.Hops) || len(fixture.deployer.specs) != len(updated.Hops) {
		t.Fatalf("cleanup/deploy calls: removes=%d applies=%d operations=%v", removeCount, len(fixture.deployer.specs), fixture.deployer.operations)
	}
	for resourceID := range oldResourceIDs {
		if fixture.deployer.state[resourceID] != "deleted" {
			t.Fatalf("legacy identity %q state=%q", resourceID, fixture.deployer.state[resourceID])
		}
	}
	for _, spec := range fixture.deployer.specs {
		if spec.ListenPort != commonPort || fixture.deployer.state[spec.ResourceID] != "active" {
			t.Fatalf("new deployment was not converged and active: %+v state=%q", spec, fixture.deployer.state[spec.ResourceID])
		}
	}
}

func TestForwardingLegacyRouteDoesNotMoveExplicitPort(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	fixedPort := fixture.forward.Hops[0].ListenPort
	legacyPort := fixedPort + 1
	if legacyPort > 65535 {
		legacyPort = fixedPort - 1
	}
	db, err := sql.Open("sqlite", fixture.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE user_forward_rules SET requested_entry_port=? WHERE id=?`, fixedPort, fixture.forward.ID); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE user_forward_hops SET listen_port=? WHERE id=?`, legacyPort, fixture.forward.Hops[1].ID); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := fixture.repo.GetUserForward(ctx, fixture.forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	fixture.deployer.mu.Lock()
	fixture.deployer.operations = nil
	fixture.deployer.mu.Unlock()
	if err := fixture.handler.deployForward(ctx, legacy); !errors.Is(err, storage.ErrForwardingConflict) {
		t.Fatalf("explicit inconsistent route error=%v", err)
	}
	latest, err := fixture.repo.GetUserForward(ctx, legacy.PublicID, legacy.Username)
	if err != nil {
		t.Fatal(err)
	}
	if latest.RequestedEntryPort != fixedPort || latest.Hops[1].ListenPort != legacyPort {
		t.Fatalf("explicit route was mutated: requested=%d hops=%+v", latest.RequestedEntryPort, latest.Hops)
	}
	fixture.deployer.mu.Lock()
	defer fixture.deployer.mu.Unlock()
	if len(fixture.deployer.operations) != 0 {
		t.Fatalf("explicit route performed remote mutations: %v", fixture.deployer.operations)
	}
}

func TestForwardingExplicitPortConflictDoesNotChangeRequestedPort(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	forward, err := fixture.repo.CreateUserForward(ctx, storage.CreateUserForwardInput{
		Username: "alice", Name: "fixed port", GrantPublicID: fixture.grant.PublicID,
		TargetNodeID: fixture.forward.TargetNodeID, TargetHost: fixture.forward.TargetHost,
		TargetPort: fixture.forward.TargetPort, RequestedEntryPort: 2033,
		EffectiveExpiresAt: fixture.grant.ExpiresAt, Actor: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.deployer.portConflictServer = forward.Hops[0].ServerID
	fixture.deployer.portConflictOnce = true
	if err := fixture.handler.deployForward(ctx, forward); !errors.Is(err, ErrForwardTunnelPortInUse) {
		t.Fatalf("explicit conflict error=%v", err)
	}
	if fixture.deployer.removeCalls != 0 {
		t.Fatalf("explicit conflict removed fixed identities: remove calls=%d", fixture.deployer.removeCalls)
	}
	updated, err := fixture.repo.GetUserForward(ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if updated.AllocatedEntryPort != 2033 || updated.RequestedEntryPort != 2033 {
		t.Fatalf("explicit port changed after conflict: requested=%d allocated=%d", updated.RequestedEntryPort, updated.AllocatedEntryPort)
	}
}

func TestForwardingExhaustedAutomaticRangeKeepsRetryableIdentity(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	forward, err := fixture.repo.CreateUserForward(ctx, storage.CreateUserForwardInput{
		Username: "alice", Name: "single candidate", GrantPublicID: fixture.grant.PublicID,
		TargetNodeID: fixture.forward.TargetNodeID, TargetHost: fixture.forward.TargetHost,
		TargetPort: fixture.forward.TargetPort, EffectiveExpiresAt: fixture.grant.ExpiresAt, Actor: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := fixture.repo.GetTunnelTemplateByID(ctx, fixture.grant.TunnelID)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.PortRangeStart = forward.AllocatedEntryPort
	tunnel.PortRangeEnd = forward.AllocatedEntryPort
	if _, err := fixture.repo.UpdateTunnelTemplate(ctx, tunnel.PublicID, *tunnel, tunnel.Version, "admin"); err != nil {
		t.Fatal(err)
	}
	resourceIDs := make([]string, len(forward.Hops))
	for i := range forward.Hops {
		resourceIDs[i] = forward.Hops[i].ResourceID
	}
	fixture.deployer.portConflictServer = forward.Hops[0].ServerID
	fixture.deployer.portConflictOnce = true
	if err := fixture.handler.deployForward(ctx, forward); !errors.Is(err, storage.ErrForwardingLimit) {
		t.Fatalf("exhausted range error=%v", err)
	}
	if fixture.deployer.removeCalls != 0 {
		t.Fatalf("failed reallocation removed retryable identities: calls=%d", fixture.deployer.removeCalls)
	}
	updated, err := fixture.repo.GetUserForward(ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	for i := range updated.Hops {
		if updated.Hops[i].ResourceID != resourceIDs[i] {
			t.Fatalf("hop %d identity changed after failed reallocation", i)
		}
	}
}

func TestForwardClientConfigUsesUserCredentialView(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/user/forwards/"+fixture.forward.PublicID+"/client-config", nil)
	fixture.handler.writeForwardClientConfig(response, request, fixture.forward, "alice")
	if response.Code != 200 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, "admin-secret") || !strings.Contains(body, "alice-user-id") {
		t.Fatalf("client config credential isolation failed: %s", body)
	}
}

func TestResolveManagedForwardTargetRejectsPackageOnlyVisibility(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	result, err := fixture.repo.DeactivateUserNodeSelection(ctx, "alice", fixture.selectionID, "alice",
		storage.ManagedSuspendUserDisabled, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, result.Source.ID, result.Source.Generation,
		storage.ManagedObservedInactive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "legacy visibility", CycleDays: 30, ResetDay: 1,
		Nodes: []int64{fixture.nodeID}, TrafficMode: "oneway",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := fixture.repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	visible, err := collectUserVisibleNodes(ctx, fixture.repo, "alice")
	if err != nil || len(visible) == 0 {
		t.Fatalf("package node is not visible for test setup: visible=%v err=%v", visible, err)
	}
	if _, _, _, _, err := fixture.handler.resolveManagedForwardTarget(ctx, "alice", fixture.nodeID); !errors.Is(err, storage.ErrForwardingForbidden) {
		t.Fatalf("package-only target error=%v, want forbidden", err)
	}
}

func TestResolveManagedForwardTargetAcceptsDirectOnlyAccess(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	result, err := fixture.repo.DeactivateUserNodeSelection(ctx, "alice", fixture.selectionID, "alice",
		storage.ManagedSuspendUserDisabled, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, result.Source.ID, result.Source.Generation,
		storage.ManagedObservedInactive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(90 * time.Minute)
	direct, _, err := fixture.repo.UpsertManualUserNodeGrant(ctx, "alice", fixture.nodeID, &expiresAt, "admin")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := fixture.repo.GetUserInboundConfig(ctx, "alice", direct.Source.ServerID, direct.Source.InboundTag)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.SetUserNodeGrantCredential(ctx, direct.Grant.ID, credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, direct.Source.ID, direct.Source.Generation,
		storage.ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	node, host, port, expiry, err := fixture.handler.resolveManagedForwardTarget(ctx, "alice", fixture.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if node.ID != fixture.nodeID || host != "198.51.100.20" || port != 443 {
		t.Fatalf("resolved target=%d %s:%d", node.ID, host, port)
	}
	if expiry == nil || !expiry.Equal(expiresAt) {
		t.Fatalf("expiry=%v want=%v", expiry, expiresAt)
	}
}

func TestTunnelSpecNormalizesPreviousHopHostCIDRs(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	if _, _, err := fixture.repo.UpdateRemoteServerHeartbeat(ctx, "entry-token", "::ffff:192.0.2.9", "2001:db8::9"); err != nil {
		t.Fatal(err)
	}
	spec, err := fixture.handler.tunnelSpec(ctx, fixture.forward, 1)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Network != "tcp_udp" {
		t.Fatalf("network=%q", spec.Network)
	}
	want := map[string]bool{"192.0.2.9/32": true, "2001:db8::9/128": true}
	if len(spec.SourceCIDRs) != len(want) {
		t.Fatalf("source CIDRs=%v", spec.SourceCIDRs)
	}
	for _, cidr := range spec.SourceCIDRs {
		if !want[cidr] {
			t.Fatalf("unexpected normalized CIDR %q in %v", cidr, spec.SourceCIDRs)
		}
	}
}

func TestForwardingAllHopsShareOneTCPUDPPort(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	if len(fixture.forward.Hops) < 2 {
		t.Fatalf("hops=%d", len(fixture.forward.Hops))
	}
	port := fixture.forward.Hops[0].ListenPort
	for i, hop := range fixture.forward.Hops {
		if hop.ListenPort != port {
			t.Fatalf("hop %d listen port=%d want=%d", i, hop.ListenPort, port)
		}
		if i+1 < len(fixture.forward.Hops) && hop.NextPort != port {
			t.Fatalf("hop %d next port=%d want=%d", i, hop.NextPort, port)
		}
	}
	fixture.deployer.mu.Lock()
	defer fixture.deployer.mu.Unlock()
	for _, spec := range fixture.deployer.specs {
		if spec.Network != "tcp_udp" {
			t.Fatalf("deployed network=%q", spec.Network)
		}
	}
}

func TestProbeTunnelServerCapabilitiesRejectsIPv6OnlyServer(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "forwarding-ipv6.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := storage.RemoteServer{
		Name: "ipv6-only", Token: "ipv6-token", Status: storage.RemoteServerStatusConnected,
		IPAddressV6: "2001:db8::10", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), &server); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateRemoteServerXrayStatus(context.Background(), server.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	handler := NewForwardingHandler(repo, newFakeForwardTunnelDeployer())
	if err := handler.probeTunnelServerCapabilities(context.Background(), []int64{server.ID}); !errors.Is(err, ErrForwardTunnelCapability) {
		t.Fatalf("IPv6-only capability error=%v", err)
	}
}

func TestDecodeForwardingJSONRejectsTrailingValue(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"one"} {"name":"two"}`))
	var body struct {
		Name string `json:"name"`
	}
	if decodeForwardingJSON(response, request, &body) {
		t.Fatal("accepted a second JSON value")
	}
	if response.Code != 400 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestNormalizeForwardSourceCIDRsRejectsBroadMappedPrefix(t *testing.T) {
	if _, err := normalizeForwardSourceCIDRs([]string{"::ffff:192.0.2.1/64"}); !errors.Is(err, storage.ErrForwardingInvalid) {
		t.Fatalf("mapped /64 error=%v", err)
	}
	values, err := normalizeForwardSourceCIDRs([]string{"198.51.100.7", "198.51.100.7/32"})
	if err != nil || len(values) != 1 || values[0] != "198.51.100.7/32" {
		t.Fatalf("normalized=%v err=%v", values, err)
	}
}

func TestTunnelTemplateWritesHoldServerMutationLeasesAcrossProbeAndCommit(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			fixture := newForwardingHandlerFixture(t)
			template, err := fixture.repo.GetTunnelTemplateByID(context.Background(), fixture.grant.TunnelID)
			if err != nil {
				t.Fatal(err)
			}
			serverIDs := make([]int64, 0, len(template.Hops))
			for _, hop := range template.Hops {
				serverIDs = append(serverIDs, hop.ServerID)
			}
			blocking := &blockingProbeForwardTunnelDeployer{
				fakeForwardTunnelDeployer: newFakeForwardTunnelDeployer(),
				entered:                   make(chan struct{}), release: make(chan struct{}),
			}
			fixture.handler.SetTunnelDeployer(blocking)
			payload, err := json.Marshal(tunnelTemplateRequest{
				Name: "lease protected", State: storage.TunnelStateActive,
				BillingMode: storage.ManagedBillingDownload, TrafficMultiplierMilli: 1000,
				PortRangeStart: 22000, PortRangeEnd: 23000,
				ServerIDs: serverIDs, Version: template.Version,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(method, "/api/admin/tunnel-templates", bytes.NewReader(payload))
			response := httptest.NewRecorder()
			handlerDone := make(chan struct{})
			go func() {
				if method == http.MethodPost {
					fixture.handler.HandleAdminTunnelTemplates(response, request)
				} else {
					request.SetPathValue("id", template.PublicID)
					fixture.handler.HandleAdminTunnelTemplate(response, request)
				}
				close(handlerDone)
			}()
			select {
			case <-blocking.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("template capability probe did not start")
			}

			exclusiveAcquired := make(chan struct{})
			exclusiveDone := make(chan error, 1)
			go func() {
				_, release, err := fixture.repo.AcquireRemoteServerExclusiveMutationLease(context.Background(), serverIDs[0])
				if err == nil {
					close(exclusiveAcquired)
					release()
				}
				exclusiveDone <- err
			}()
			select {
			case <-exclusiveAcquired:
				t.Fatal("exclusive delete lease entered while template write was between probe and commit")
			case <-time.After(100 * time.Millisecond):
			}

			close(blocking.release)
			select {
			case <-handlerDone:
			case <-time.After(2 * time.Second):
				t.Fatal("template handler did not release leases")
			}
			select {
			case err := <-exclusiveDone:
				if err != nil {
					t.Fatalf("exclusive lease failed after template handler: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("exclusive lease remained blocked after template handler")
			}
		})
	}
}
