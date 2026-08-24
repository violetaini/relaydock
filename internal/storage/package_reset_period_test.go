package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestPackageNodeTrafficResetPeriodPersistsAndPropagates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	for _, username := range []string{"alice", "bob"} {
		if err := repo.EnsureUser(ctx, username, "hash"); err != nil {
			t.Fatalf("EnsureUser(%s): %v", username, err)
		}
	}

	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "annual-reset", CycleDays: 365, IsReset: true, ResetDay: 31,
		NodeTrafficResetPeriod: NodeTrafficResetYearly,
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	stored, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if stored.NodeTrafficResetPeriod != NodeTrafficResetYearly {
		t.Fatalf("package reset period=%q want=%q", stored.NodeTrafficResetPeriod, NodeTrafficResetYearly)
	}
	byName, err := repo.GetPackageByName(ctx, stored.Name)
	if err != nil || byName.NodeTrafficResetPeriod != NodeTrafficResetYearly {
		t.Fatalf("GetPackageByName period=%q err=%v", byName.NodeTrafficResetPeriod, err)
	}
	listed, err := repo.ListPackages(ctx)
	if err != nil || len(listed) != 1 || listed[0].NodeTrafficResetPeriod != NodeTrafficResetYearly {
		t.Fatalf("ListPackages=%+v err=%v", listed, err)
	}

	now := time.Now().UTC()
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", packageID, now, now.AddDate(1, 0, 0), true, 7); err != nil {
		t.Fatalf("AssignPackageBundleToUser(alice): %v", err)
	}
	if _, err := repo.AssignPackageBundleToUser(ctx, "bob", packageID, now, now.AddDate(1, 0, 0), false, 9); err != nil {
		t.Fatalf("AssignPackageBundleToUser(bob): %v", err)
	}
	for _, username := range []string{"alice", "bob"} {
		user, err := repo.GetUser(ctx, username)
		if err != nil || user.NodeTrafficResetPeriod != NodeTrafficResetYearly {
			t.Fatalf("GetUser(%s) period=%q err=%v", username, user.NodeTrafficResetPeriod, err)
		}
	}

	stored.NodeTrafficResetPeriod = NodeTrafficResetQuarterly
	if _, err := repo.UpdatePackageBundle(ctx, *stored); err != nil {
		t.Fatalf("UpdatePackageBundle: %v", err)
	}
	alice, err := repo.GetUser(ctx, "alice")
	if err != nil || alice.NodeTrafficResetPeriod != NodeTrafficResetQuarterly || !alice.IsReset || alice.ResetDay != 7 {
		t.Fatalf("alice after update=%+v err=%v", alice, err)
	}
	bob, err := repo.GetUser(ctx, "bob")
	if err != nil || bob.NodeTrafficResetPeriod != NodeTrafficResetQuarterly || bob.IsReset || bob.ResetDay != 9 {
		t.Fatalf("bob override after update=%+v err=%v", bob, err)
	}

	if err := repo.RemovePackageFromUser(ctx, "alice"); err != nil {
		t.Fatalf("RemovePackageFromUser: %v", err)
	}
	alice, err = repo.GetUser(ctx, "alice")
	if err != nil || alice.NodeTrafficResetPeriod != NodeTrafficResetMonthly {
		t.Fatalf("alice after removal=%+v err=%v", alice, err)
	}
}

func TestNodeTrafficResetPeriodMigratesLegacySchemaWithoutEnablingReset(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "legacy-reset-period.db")
	repo, err := NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	if err := repo.EnsureUser(ctx, "legacy", "hash"); err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "legacy", CycleDays: 30, IsReset: false, ResetDay: 1,
		NodeTrafficResetPeriod: NodeTrafficResetYearly,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := repo.AssignPackageBundleToUser(ctx, "legacy", packageID, now, now.AddDate(0, 1, 0), false, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`ALTER TABLE packages DROP COLUMN node_traffic_reset_period`); err != nil {
		t.Fatalf("drop package reset period: %v", err)
	}
	if _, err := repo.db.Exec(`ALTER TABLE users DROP COLUMN node_traffic_reset_period`); err != nil {
		t.Fatalf("drop user reset period: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err = NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatalf("reopen legacy repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil || pkg.NodeTrafficResetPeriod != NodeTrafficResetMonthly || pkg.IsReset {
		t.Fatalf("migrated package=%+v err=%v", pkg, err)
	}
	user, err := repo.GetUser(ctx, "legacy")
	if err != nil || user.NodeTrafficResetPeriod != NodeTrafficResetMonthly || user.IsReset {
		t.Fatalf("migrated user=%+v err=%v", user, err)
	}
}

func TestPackageNodeTrafficResetPeriodDefaultsAndRejectsInvalid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	packageID, err := repo.CreatePackage(ctx, Package{Name: "legacy-default", CycleDays: 30, IsReset: false, ResetDay: 1})
	if err != nil {
		t.Fatalf("CreatePackage default: %v", err)
	}
	stored, err := repo.GetPackage(ctx, packageID)
	if err != nil || stored.NodeTrafficResetPeriod != NodeTrafficResetMonthly || stored.IsReset {
		t.Fatalf("default package=%+v err=%v", stored, err)
	}
	if _, err := repo.CreatePackage(ctx, Package{
		Name: "invalid-period", CycleDays: 30, IsReset: true, ResetDay: 1,
		NodeTrafficResetPeriod: "weekly",
	}); err == nil {
		t.Fatal("CreatePackage accepted invalid reset period")
	}
}
