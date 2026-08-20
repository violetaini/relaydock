package handler

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func packageWireGuardCleanupSource(
	t *testing.T,
	repo *storage.TrafficRepository,
	cfg *storage.UserInboundConfig,
) storage.UserInboundAccessSource {
	t.Helper()
	sources, err := repo.ListUserInboundAccessSources(context.Background(), cfg.Username, cfg.ServerID)
	if err != nil {
		t.Fatalf("ListUserInboundAccessSources: %v", err)
	}
	for _, source := range sources {
		if source.SourceType == storage.ManagedSourceLegacyReview && source.SourceID == cfg.ID {
			return source
		}
	}
	t.Fatalf("package WireGuard cleanup source for credential %d not found: %+v", cfg.ID, sources)
	return storage.UserInboundAccessSource{}
}

func retryPackageWireGuardCleanup(
	t *testing.T,
	repo *storage.TrafficRepository,
	remote *RemoteManageHandler,
	pusher *LimiterConfigPusher,
	sourceID int64,
) {
	t.Helper()
	pending, err := repo.ListPendingUserInboundAccessSources(
		context.Background(), time.Now().UTC().Add(time.Hour), 100, 0,
	)
	if err != nil {
		t.Fatalf("ListPendingUserInboundAccessSources: %v", err)
	}
	for _, source := range pending {
		if source.ID != sourceID {
			continue
		}
		if err := NewManagedNodesHandler(repo, remote, pusher).reconcileSource(context.Background(), source); err != nil {
			t.Fatalf("managed cleanup retry: %v", err)
		}
		return
	}
	t.Fatalf("cleanup source %d was not pending: %+v", sourceID, pending)
}

func assertPackageWireGuardCleanupSucceeded(
	t *testing.T,
	repo *storage.TrafficRepository,
	agent *wireGuardRevokeAgent,
	cfg *storage.UserInboundConfig,
	sourceID int64,
) {
	t.Helper()
	if _, err := repo.GetUserInboundConfig(context.Background(), cfg.Username, cfg.ServerID, cfg.InboundTag); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("credential remained after cleanup: %v", err)
	}
	source, err := repo.GetUserInboundAccessSource(context.Background(), sourceID)
	if err != nil {
		t.Fatalf("GetUserInboundAccessSource: %v", err)
	}
	if source.DesiredState != storage.ManagedDesiredInactive ||
		source.ObservedState != storage.ManagedObservedInactive ||
		source.Generation != source.AppliedGeneration {
		t.Fatalf("cleanup source did not converge: %+v", source)
	}
	events, payloads := agent.snapshot()
	if !wireGuardRevokeEveryRemoveHadTombstone(events, payloads) {
		t.Fatalf("WireGuard removals were not preceded by strict tombstones: events=%v payloads=%#v", events, payloads)
	}
	for i := len(payloads) - 1; i >= 0; i-- {
		if payloads[i].InboundTag != cfg.InboundTag {
			continue
		}
		if wireGuardRevokePayloadHasMapping(payloads[i]) {
			t.Fatalf("final checked limiter payload retained removed mapping: %#v", payloads[i])
		}
		return
	}
	t.Fatal("no final limiter payload was published")
}

func TestPackageTemplateRejectsConflictingProtocolsAtSameInbound(t *testing.T) {
	settings, _ := wireGuardCredentialTestSettings(t)
	repo, server, _, _ := newWireGuardRevokeFixture(t, &wireGuardRevokeAgent{settings: settings})
	packageID := assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	pkg, err := repo.GetPackage(context.Background(), packageID)
	if err != nil || len(pkg.Nodes) != 1 {
		t.Fatalf("load WireGuard package: pkg=%+v err=%v", pkg, err)
	}
	conflict, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "admin", NodeName: "same-coordinate-vless", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-revoke",
		ClashConfig: `{"name":"same-coordinate-vless","type":"vless","server":"203.0.113.10","port":443,"uuid":"owner-id"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePackageNodeProtocolConflicts(context.Background(), repo, []int64{pkg.Nodes[0], conflict.ID}); err == nil {
		t.Fatal("conflicting WireGuard/VLESS package coordinates were accepted")
	}
	if err := validatePackageNodeProtocolConflicts(context.Background(), repo, pkg.Nodes); err != nil {
		t.Fatalf("valid single-protocol package rejected: %v", err)
	}
}

func TestPackageTemplateWireGuardLimiterFailureRestoresOldAccessBeforeCommit(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failLimiterAt: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()
	packageID := assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	current, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	target := *current
	target.Nodes = []int64{}
	target.NodeSpeedLimits = map[int64]float64{}
	target.NodeDeviceLimits = map[int64]int{}
	users, err := repo.ListUsersWithPackage(ctx)
	if err != nil {
		t.Fatal(err)
	}

	handler := NewPackageUpdateHandler(repo, remote, pusher)
	if plans, err := handler.stagePackageTemplateRevocations(ctx, current, &target, users); err == nil {
		t.Fatalf("template staging succeeded without limiter ACK: plans=%+v", plans)
	}
	persisted, err := repo.GetPackage(ctx, packageID)
	if err != nil || len(persisted.Nodes) != len(current.Nodes) {
		t.Fatalf("failed preflight changed package template: package=%+v err=%v", persisted, err)
	}
	removeCalls, _, limiterHits := agent.counts()
	if removeCalls != 0 || limiterHits < 2 {
		t.Fatalf("remove calls=%d limiter hits=%d, want no remove and restored old policy", removeCalls, limiterHits)
	}
	_, payloads := agent.snapshot()
	limit, ok := wireGuardRevokeLatestUserLimit(payloads)
	if !ok || limit.Denied || limit.SpeedLimit != 0 || limit.DeviceLimit != 2 {
		t.Fatalf("failed preflight did not restore normal package policy: limit=%+v found=%v", limit, ok)
	}
}

func TestPackageTemplateWireGuardRemovalIsDeniedAndDurablyRetriedAfterCommit(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()
	packageID := assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	cfg, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke")
	if err != nil {
		t.Fatal(err)
	}
	current, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	target := *current
	target.Nodes = []int64{}
	target.NodeSpeedLimits = map[int64]float64{}
	target.NodeDeviceLimits = map[int64]int{}
	users, err := repo.ListUsersWithPackage(ctx)
	if err != nil {
		t.Fatal(err)
	}

	handler := NewPackageUpdateHandler(repo, remote, pusher)
	plans, err := handler.stagePackageTemplateRevocations(ctx, current, &target, users)
	if err != nil {
		t.Fatalf("stage template revocation: %v", err)
	}
	removeCalls, _, _ := agent.counts()
	if removeCalls != 0 {
		t.Fatalf("WireGuard peer removed before target template commit: %d calls", removeCalls)
	}
	if _, err := repo.UpdatePackageBundle(ctx, target); err != nil {
		t.Fatalf("commit target template: %v", err)
	}
	warnings := handler.finishPackageTemplateRevocations(ctx, plans)
	if len(warnings["alice"]) == 0 {
		t.Fatalf("failed peer removal was not reported as durable cleanup: %#v", warnings)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); err != nil {
		t.Fatalf("failed peer removal deleted retry credential: %v", err)
	}
	source := packageWireGuardCleanupSource(t, repo, cfg)
	if source.Generation == source.AppliedGeneration || source.LastError == "" {
		t.Fatalf("failed template cleanup did not remain pending: %+v", source)
	}
	events, payloads := agent.snapshot()
	if !wireGuardRevokeEveryRemoveHadTombstone(events, payloads) {
		t.Fatalf("template removal order=%v payloads=%#v, want Denied before remove", events, payloads)
	}

	retryPackageWireGuardCleanup(t, repo, remote, pusher, source.ID)
	assertPackageWireGuardCleanupSucceeded(t, repo, agent, cfg, source.ID)
}

func TestPackageWireGuardUnbindFailureKeepsUnboundStateAndRetries(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()
	assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	cfg, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke")
	if err != nil {
		t.Fatal(err)
	}

	if err := unbindUserPackage(ctx, repo, remote, pusher, "alice"); err != nil {
		t.Fatalf("durable WireGuard unbind returned an error: %v", err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModeCustom || user.PackageID != 0 {
		t.Fatalf("failed peer removal rolled back package unbind: user=%+v err=%v", user, err)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); err != nil {
		t.Fatalf("failed peer removal deleted credential: %v", err)
	}
	source := packageWireGuardCleanupSource(t, repo, cfg)
	if source.DesiredState != storage.ManagedDesiredInactive || source.ObservedState != storage.ManagedObservedActive ||
		source.Generation == source.AppliedGeneration || source.LastError == "" {
		t.Fatalf("failed unbind did not retain pending cleanup: %+v", source)
	}
	events, payloads := agent.snapshot()
	if len(events) < 2 || !wireGuardRevokeEveryRemoveHadTombstone(events, payloads) ||
		len(payloads) == 0 || !wireGuardRevokePayloadHasTombstone(payloads[0]) {
		t.Fatalf("unbind order=%v payloads=%#v, want strict limiter before remove", events, payloads)
	}

	retryPackageWireGuardCleanup(t, repo, remote, pusher, source.ID)
	assertPackageWireGuardCleanupSucceeded(t, repo, agent, cfg, source.ID)
}

func TestPackageWireGuardUnbindLimiterFailureKeepsOldPackageAndPeer(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failLimiterAt: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()
	oldPackageID := assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)

	if err := unbindUserPackage(ctx, repo, remote, pusher, "alice"); err == nil {
		t.Fatal("unbind succeeded without an acknowledged WireGuard cleanup policy")
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.PackageID != oldPackageID || user.AuthorizationMode != storage.AuthorizationModePackage {
		t.Fatalf("limiter failure changed package authorization: user=%+v err=%v", user, err)
	}
	removeCalls, _, limiterHits := agent.counts()
	if removeCalls != 0 || limiterHits < 2 {
		t.Fatalf("remove calls=%d limiter hits=%d, want no remove and policy restoration", removeCalls, limiterHits)
	}
	_, payloads := agent.snapshot()
	limit, ok := wireGuardRevokeLatestUserLimit(payloads)
	if !ok || limit.SpeedLimit != 0 || limit.DeviceLimit != 2 {
		t.Fatalf("old package policy was not restored: limit=%+v found=%v payloads=%#v", limit, ok, payloads)
	}
}

func TestPackageWireGuardSwitchFailureKeepsNewPackageAndRetries(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failRemove: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()
	oldPackageID := assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	cfg, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke")
	if err != nil {
		t.Fatal(err)
	}
	newPackageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "wg-switch-empty", TrafficLimitBytes: 1024, CycleDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(24*time.Hour)
	assigner := NewPackageAssignHandler(repo, remote, pusher)
	warnings, err := assigner.AssignAndProvision(ctx, "alice", newPackageID, start, end, false, 1)
	if err != nil {
		t.Fatalf("durable WireGuard package switch returned an error: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("WireGuard package switch did not report pending cleanup")
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.PackageID != newPackageID || user.PackageID == oldPackageID {
		t.Fatalf("failed peer removal restored old package: user=%+v err=%v", user, err)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); err != nil {
		t.Fatalf("failed switch cleanup deleted credential: %v", err)
	}
	source := packageWireGuardCleanupSource(t, repo, cfg)
	if source.Generation == source.AppliedGeneration || source.LastError == "" {
		t.Fatalf("failed switch did not retain pending cleanup: %+v", source)
	}
	events, payloads := agent.snapshot()
	if len(events) < 2 || !wireGuardRevokeEveryRemoveHadTombstone(events, payloads) ||
		len(payloads) == 0 || !wireGuardRevokePayloadHasTombstone(payloads[0]) {
		t.Fatalf("switch order=%v payloads=%#v, want strict limiter before remove", events, payloads)
	}

	retryPackageWireGuardCleanup(t, repo, remote, pusher, source.ID)
	assertPackageWireGuardCleanupSucceeded(t, repo, agent, cfg, source.ID)
}

func TestPackageWireGuardSwitchLimiterFailureKeepsOldPackage(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings, failLimiterAt: 1}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()
	oldPackageID := assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	newPackageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "wg-switch-empty-policy-failure", TrafficLimitBytes: 1024, CycleDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(24*time.Hour)
	if _, err := NewPackageAssignHandler(repo, remote, pusher).AssignAndProvision(
		ctx, "alice", newPackageID, start, end, false, 1,
	); err == nil {
		t.Fatal("package switch succeeded without an acknowledged WireGuard cleanup policy")
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.PackageID != oldPackageID {
		t.Fatalf("limiter failure changed package assignment: user=%+v err=%v", user, err)
	}
	removeCalls, _, _ := agent.counts()
	if removeCalls != 0 {
		t.Fatalf("limiter failure made %d remove calls, want 0", removeCalls)
	}
}

func TestPackageWireGuardSwitchPreservesSharedInboundTarget(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()
	oldPackageID := assignWireGuardRevokePackage(t, repo, "alice", server, settings, 1024)
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)
	oldPackage, err := repo.GetPackage(ctx, oldPackageID)
	if err != nil || len(oldPackage.Nodes) != 1 {
		t.Fatalf("GetPackage: package=%+v err=%v", oldPackage, err)
	}
	newPackageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "wg-switch-shared", TrafficLimitBytes: 2048, CycleDays: 30,
		Nodes: []int64{oldPackage.Nodes[0]}, SpeedLimitMbps: 7, DeviceLimit: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(24*time.Hour)
	if _, err := NewPackageAssignHandler(repo, remote, pusher).AssignAndProvision(
		ctx, "alice", newPackageID, start, end, false, 1,
	); err != nil {
		t.Fatalf("switch to shared WireGuard inbound: %v", err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.PackageID != newPackageID {
		t.Fatalf("shared inbound switch did not persist: user=%+v err=%v", user, err)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); err != nil {
		t.Fatalf("shared target credential was deleted: %v", err)
	}
	removeCalls, _, _ := agent.counts()
	if removeCalls != 0 {
		t.Fatalf("shared WireGuard inbound made %d remove calls, want 0", removeCalls)
	}
	sources, err := repo.ListUserInboundAccessSources(ctx, "alice", server.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		if source.SourceType == storage.ManagedSourceLegacyReview {
			t.Fatalf("shared WireGuard target incorrectly queued cleanup: %+v", source)
		}
	}
}

func TestManagedUserDisableWireGuardCleanupRetainsCredential(t *testing.T) {
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)
	agent := &wireGuardRevokeAgent{settings: settings}
	repo, server, remote, pusher := newWireGuardRevokeFixture(t, agent)
	ctx := context.Background()
	saveWireGuardRevokeCredential(t, repo, "alice", server.ID, serverPublicKey)

	sources, err := repo.PrepareUserDisable(ctx, "alice")
	if err != nil || len(sources) != 1 {
		t.Fatalf("PrepareUserDisable sources=%+v err=%v", sources, err)
	}
	if sources[0].SuspendReason != storage.ManagedSuspendUserDisabled {
		t.Fatalf("disable source reason=%q", sources[0].SuspendReason)
	}
	if err := NewManagedNodesHandler(repo, remote, pusher).reconcileSource(ctx, sources[0]); err != nil {
		t.Fatalf("reconcile user disable: %v", err)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-revoke"); err != nil {
		t.Fatalf("user disable removed reusable WireGuard credential: %v", err)
	}
	settled, err := repo.GetUserInboundAccessSource(ctx, sources[0].ID)
	if err != nil || settled.ObservedState != storage.ManagedObservedInactive ||
		settled.Generation != settled.AppliedGeneration {
		t.Fatalf("disable source did not converge: source=%+v err=%v", settled, err)
	}
}
