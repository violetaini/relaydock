package storage

import (
	"errors"
	"testing"
	"time"
)

func TestPackageAssignmentRejectsManagedGrantBeforeOverlap(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, node, _ := seedManagedNodesTest(t, repo)
	now := time.Now().UTC()
	createManagedGrantForTest(t, repo, ctx, server.ID, now)
	packageID, err := repo.CreatePackage(ctx, Package{Name: "overlap", Nodes: []int64{node.ID}})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); !errors.Is(err, ErrAuthorizationModeConflict) {
		t.Fatalf("AssignPackageToUser error = %v, want %v", err, ErrAuthorizationModeConflict)
	}
}

func TestAuthorizationModeRejectsManagedPackageOverlap(t *testing.T) {
	t.Run("assignment", func(t *testing.T) {
		repo, _ := newManagedNodesTestRepository(t)
		ctx, server, node, offer := seedManagedNodesTest(t, repo)
		now := time.Now().UTC()
		createManagedGrantForTest(t, repo, ctx, server.ID, now)
		if _, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now); err != nil {
			t.Fatalf("ActivateUserNodeSelection: %v", err)
		}
		packageID, err := repo.CreatePackage(ctx, Package{Name: "assignment-overlap", Nodes: []int64{node.ID}})
		if err != nil {
			t.Fatalf("CreatePackage: %v", err)
		}
		if err := repo.AssignPackageToUser(ctx, "alice", packageID, now, now.Add(time.Hour), false, 1); !errors.Is(err, ErrAuthorizationModeConflict) {
			t.Fatalf("AssignPackageToUser error = %v, want %v", err, ErrAuthorizationModeConflict)
		}
	})

	t.Run("manual grant while package assigned", func(t *testing.T) {
		repo, _ := newManagedNodesTestRepository(t)
		ctx, server, _, _ := seedManagedNodesTest(t, repo)
		now := time.Now().UTC()
		packageID, err := repo.CreatePackage(ctx, Package{Name: "updated-overlap"})
		if err != nil {
			t.Fatalf("CreatePackage: %v", err)
		}
		if err := repo.AssignPackageToUser(ctx, "alice", packageID, now, now.Add(time.Hour), false, 1); err != nil {
			t.Fatalf("AssignPackageToUser: %v", err)
		}
		if _, err := repo.CreateUserServerGrant(ctx, UserServerGrant{
			Username: "alice", ServerID: server.ID, Enabled: true, StartsAt: now,
			BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone, ResetDay: 1, CreatedBy: "admin",
		}); !errors.Is(err, ErrAuthorizationModeConflict) {
			t.Fatalf("CreateUserServerGrant error = %v, want %v", err, ErrAuthorizationModeConflict)
		}
	})
}

func TestManagedSelectionReactivationHonorsCurrentNodeCap(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, firstOffer := seedManagedNodesTest(t, repo)
	secondNode, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://managed-two", NodeName: "Managed VLESS Two",
		Protocol: "vless", ParsedConfig: `{}`, ClashConfig: `{}`, Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-two-in",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	secondOffer, err := repo.CreateSelfServiceNodeOffer(ctx, secondNode.ID, server.ID, "admin")
	if err != nil {
		t.Fatalf("CreateSelfServiceNodeOffer: %v", err)
	}
	now := time.Now().UTC()
	grant := createManagedGrantForTest(t, repo, ctx, server.ID, now)
	first, err := repo.ActivateUserNodeSelection(ctx, "alice", firstOffer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate first: %v", err)
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", secondOffer.ID, "alice", now); err != nil {
		t.Fatalf("activate second: %v", err)
	}
	if _, err := repo.DeactivateUserNodeSelection(ctx, "alice", first.Selection.ID, "alice", ManagedSuspendUserDisabled, now); err != nil {
		t.Fatalf("deactivate first: %v", err)
	}
	grant.MaxActiveNodes = 1
	grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("UpdateUserServerGrant: %v", err)
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", firstOffer.ID, "alice", now); !errors.Is(err, ErrManagedActiveNodeLimit) {
		t.Fatalf("reactivation error = %v, want %v", err, ErrManagedActiveNodeLimit)
	}
}

func TestManagedMonthlyResetScheduleIsInitializedAndRecomputed(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, _ := seedManagedNodesTest(t, repo)
	now := time.Now().UTC()
	expires := now.AddDate(0, 3, 0)
	grant, err := repo.CreateUserServerGrant(ctx, UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true, StartsAt: now.Add(-time.Hour), ExpiresAt: &expires,
		BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetMonthly, ResetDay: 15,
		BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateUserServerGrant: %v", err)
	}
	if grant.NextResetAt == nil || !grant.NextResetAt.After(now) || grant.NextResetAt.In(mustLocation(t, "Asia/Shanghai")).Day() != 15 {
		t.Fatalf("unexpected initial reset schedule: %#v", grant.NextResetAt)
	}
	initial := *grant.NextResetAt
	grant.ResetDay = 20
	grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("UpdateUserServerGrant: %v", err)
	}
	if grant.NextResetAt == nil || grant.NextResetAt.Equal(initial) || grant.NextResetAt.In(mustLocation(t, "Asia/Shanghai")).Day() != 20 {
		t.Fatalf("reset schedule was not recomputed: initial=%v updated=%v", initial, grant.NextResetAt)
	}
	grant.ResetPolicy = ManagedResetNone
	grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("disable reset policy: %v", err)
	}
	if grant.NextResetAt != nil {
		t.Fatalf("disabled reset retained next_reset_at=%v", grant.NextResetAt)
	}

	location := mustLocation(t, "Asia/Shanghai")
	lateJanuary := time.Date(2026, time.January, 31, 12, 0, 0, 0, location)
	next := NextManagedMonthlyReset(lateJanuary, 28, "Asia/Shanghai").In(location)
	if next.Year() != 2026 || next.Month() != time.February || next.Day() != 28 || next.Hour() != 0 {
		t.Fatalf("cross-month reset = %v", next)
	}
	catchUp := NextManagedMonthlyReset(time.Date(2026, time.July, 19, 8, 0, 0, 0, location), 1, "Asia/Shanghai").In(location)
	if catchUp.Month() != time.August || catchUp.Day() != 1 {
		t.Fatalf("catch-up reset = %v", catchUp)
	}
}

func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	location, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("LoadLocation(%q): %v", name, err)
	}
	return location
}

func TestManagedBillingModeCannotChangeAfterUsage(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, offer := seedManagedNodesTest(t, repo)
	now := time.Now().UTC()
	grant := createManagedGrantForTest(t, repo, ctx, server.ID, now)
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("ActivateUserNodeSelection: %v", err)
	}
	if _, err := repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 100, 100, "epoch", now); err != nil {
		t.Fatalf("baseline usage: %v", err)
	}
	if _, err := repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 200, 300, "epoch", now.Add(time.Second)); err != nil {
		t.Fatalf("accumulate usage: %v", err)
	}
	grant.BillingMode = ManagedBillingBoth
	if _, err := repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin"); !errors.Is(err, ErrManagedBillingModeConflict) {
		t.Fatalf("grant billing change error = %v, want %v", err, ErrManagedBillingModeConflict)
	}
	both := ManagedBillingBoth
	if _, err := repo.UpdateUserNodeSelectionLimits(ctx, activation.Selection.ID, nil, nil, &both, "admin"); !errors.Is(err, ErrManagedBillingModeConflict) {
		t.Fatalf("selection billing change error = %v, want %v", err, ErrManagedBillingModeConflict)
	}
}

func TestRebaseManagedUsageSkipsOverlapWithoutRetroactiveCharge(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, offer := seedManagedNodesTest(t, repo)
	now := time.Now().UTC()
	createManagedGrantForTest(t, repo, ctx, server.ID, now)
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("ActivateUserNodeSelection: %v", err)
	}
	if _, err := repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 100, 100, "epoch", now); err != nil {
		t.Fatalf("baseline usage: %v", err)
	}
	if _, err := repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 200, 300, "epoch", now.Add(time.Second)); err != nil {
		t.Fatalf("accumulate usage: %v", err)
	}
	if _, err := repo.RebaseUserNodeSelectionUsage(ctx, activation.Selection.ID, 1_000, 2_000, "epoch", now.Add(2*time.Second)); err != nil {
		t.Fatalf("RebaseUserNodeSelectionUsage: %v", err)
	}
	usage, err := repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 1_010, 2_030, "epoch", now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("post-rebase usage: %v", err)
	}
	if usage.UplinkBytes != 110 || usage.DownlinkBytes != 230 {
		t.Fatalf("post-rebase usage = up:%d down:%d, want up:110 down:230", usage.UplinkBytes, usage.DownlinkBytes)
	}
}
