package storage

import (
	"context"
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestUserTrafficLimitOverrideMigrationAndPackageLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic-limit-override.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	packageA, err := repo.CreatePackage(ctx, Package{Name: "A", TrafficLimitBytes: 1000, CycleDays: 30, ResetDay: 1})
	if err != nil {
		t.Fatalf("CreatePackage A: %v", err)
	}
	packageB, err := repo.CreatePackage(ctx, Package{Name: "B", TrafficLimitBytes: 2000, CycleDays: 30, ResetDay: 1})
	if err != nil {
		t.Fatalf("CreatePackage B: %v", err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", packageA, now, now.Add(30*24*time.Hour), false, 1); err != nil {
		t.Fatalf("AssignPackageToUser A: %v", err)
	}
	override := int64(750)
	if err := repo.UpdateUserTrafficLimitOverride(ctx, "alice", &override); err != nil {
		t.Fatalf("UpdateUserTrafficLimitOverride: %v", err)
	}

	assertOverride := func(want *int64) {
		t.Helper()
		user, err := repo.GetUser(ctx, "alice")
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if want == nil {
			if user.TrafficLimitOverride != nil {
				t.Fatalf("override=%v, want nil", *user.TrafficLimitOverride)
			}
			return
		}
		if user.TrafficLimitOverride == nil || *user.TrafficLimitOverride != *want {
			t.Fatalf("override=%v, want %d", user.TrafficLimitOverride, *want)
		}
	}
	assertOverride(&override)

	if err := repo.AssignPackageToUser(ctx, "alice", packageA, now, now.Add(60*24*time.Hour), false, 1); err != nil {
		t.Fatalf("renew package A: %v", err)
	}
	// Aggregate limits are retired, so every package assignment/renewal clears
	// legacy rows instead of carrying them into the new authorization window.
	assertOverride(nil)
	if err := repo.AssignPackageToUser(ctx, "alice", packageB, now, now.Add(30*24*time.Hour), false, 1); err != nil {
		t.Fatalf("switch to package B: %v", err)
	}
	assertOverride(nil)

	zero := int64(0)
	if err := repo.UpdateUserTrafficLimitOverride(ctx, "alice", &zero); err != nil {
		t.Fatalf("set explicit unlimited: %v", err)
	}
	assertOverride(&zero)
	if err := repo.RemovePackageFromUser(ctx, "alice"); err != nil {
		t.Fatalf("RemovePackageFromUser: %v", err)
	}
	assertOverride(nil)
	if err := repo.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening runs the idempotent ALTER migration and preserves NULL semantics.
	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("reopen repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	assertOverride(nil)
}

func TestUserNodeTrafficLimitOverridesMigratePersistAndList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-traffic-limit-overrides.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	traffic := map[int64]float64{7: 0, 8: 1.25}
	if err := repo.UpdateUserNodeLimitsWithTraffic(ctx, "alice", map[int64]float64{7: 8}, traffic, map[int64]int{7: 2}); err != nil {
		t.Fatalf("UpdateUserNodeLimitsWithTraffic: %v", err)
	}
	assertStored := func(repo *TrafficRepository) {
		t.Helper()
		user, err := repo.GetUser(ctx, "alice")
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if value, ok := user.NodeTrafficLimitOverrides[7]; !ok || value != 0 || user.NodeTrafficLimitOverrides[8] != 1.25 {
			t.Fatalf("GetUser node traffic overrides=%v", user.NodeTrafficLimitOverrides)
		}
		users, err := repo.ListUsers(ctx, 10)
		if err != nil || len(users) != 1 || users[0].NodeTrafficLimitOverrides[8] != 1.25 {
			t.Fatalf("ListUsers=%+v err=%v", users, err)
		}
	}
	assertStored(repo)
	if err := repo.UpdateUserNodeLimitsWithTraffic(ctx, "alice", nil, map[int64]float64{8: math.Inf(1)}, nil); err == nil {
		t.Fatal("infinite traffic override was accepted")
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("idempotent reopen migration: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	assertStored(repo)
	var columns int
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='node_traffic_limit_overrides'`).Scan(&columns); err != nil || columns != 1 {
		t.Fatalf("node traffic override column count=%d err=%v", columns, err)
	}
}
