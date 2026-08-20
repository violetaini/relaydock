package storage

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"
)

func assertRetiredPackageAggregates(t *testing.T, repo *TrafficRepository, packageID int64, wantReset bool) *Package {
	t.Helper()
	stored, err := repo.GetPackage(context.Background(), packageID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.TrafficLimitBytes != 0 || stored.TrafficLimitGB != 0 || stored.SpeedLimitMbps != 0 || len(stored.AutoSpeedRules) != 0 {
		t.Fatalf("retired aggregate limits were persisted: %+v", stored)
	}
	if stored.IsReset != wantReset {
		t.Fatalf("is_reset=%t want=%t", stored.IsReset, wantReset)
	}
	var rawAutoSpeed string
	if err := repo.db.QueryRow(`SELECT COALESCE(auto_speed_limit_json, '') FROM packages WHERE id=?`, packageID).Scan(&rawAutoSpeed); err != nil {
		t.Fatal(err)
	}
	if rawAutoSpeed != "" {
		t.Fatalf("auto_speed_limit_json=%q want empty", rawAutoSpeed)
	}
	return stored
}

func TestPackageLimitContractStartupClearsLegacyUserAggregates(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "legacy-user-aggregates.db")
	repo, err := NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.EnsureUser(ctx, "legacy", "hash"); err != nil {
		t.Fatal(err)
	}
	traffic, speed := int64(1234), 56.0
	devices := 7
	if err := repo.UpdateUserTrafficLimitOverride(ctx, "legacy", &traffic); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateUserLimitOverrides(ctx, "legacy", &speed, &devices); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err = NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	user, err := repo.GetUser(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if user.TrafficLimitOverride != nil || user.SpeedLimitOverride != nil {
		t.Fatalf("legacy aggregate overrides survived startup: traffic=%v speed=%v", user.TrafficLimitOverride, user.SpeedLimitOverride)
	}
	if user.DeviceLimitOverride == nil || *user.DeviceLimitOverride != devices {
		t.Fatalf("detailed device override was cleared: %v", user.DeviceLimitOverride)
	}
}

func TestPackageLimitContractAggregateNormalization(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "retired-aggregates-create", TrafficLimitBytes: 123456, TrafficLimitGB: 987,
		CycleDays: 30, IsReset: false, ResetDay: 17, SpeedLimitMbps: 88,
		AutoSpeedRules: []AutoSpeedLimitRule{{
			Type: "sustained", ThresholdMbps: 50, SustainedSeconds: 10, LimitMbps: 5, LimitDuration: 60,
		}},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	stored := assertRetiredPackageAggregates(t, repo, packageID, false)

	stored.TrafficLimitBytes = 654321
	stored.TrafficLimitGB = 456
	stored.SpeedLimitMbps = 44
	stored.AutoSpeedRules = []AutoSpeedLimitRule{{
		Type: "burst", ThresholdMbps: 30, SustainedSeconds: 2, WindowSeconds: 20,
		BurstCount: 3, LimitMbps: 4, LimitDuration: 90,
	}}
	stored.IsReset = false
	stored.ResetDay = 9
	if err := repo.UpdatePackage(ctx, *stored); err != nil {
		t.Fatalf("UpdatePackage: %v", err)
	}
	assertRetiredPackageAggregates(t, repo, packageID, false)
}

func TestPackageLimitContractForwardingGrantValidation(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	serverID := addPackageBundleServer(t, repo, "package-speed-server")
	tunnelID := addPackageBundleTunnel(t, repo, serverID, "package-speed-tunnel")

	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "package-finite-forward-speed", CycleDays: 30, ResetDay: 1,
		ForwardingGrants: []PackageForwardingGrant{{
			TunnelID: tunnelID, MaxActiveForwards: 2, PerForwardSpeedMbps: 12.5,
			BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth),
		}},
	})
	if err != nil {
		t.Fatalf("finite package forwarding speed: %v", err)
	}
	stored, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.ForwardingGrants) != 1 || stored.ForwardingGrants[0].PerForwardSpeedMbps != 12.5 {
		t.Fatalf("stored forwarding grant=%+v", stored.ForwardingGrants)
	}
	stored.ForwardingGrants[0].PerForwardSpeedMbps = 37.5
	if err := repo.UpdatePackage(ctx, *stored); err != nil {
		t.Fatalf("update finite package forwarding speed: %v", err)
	}
	stored, err = repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ForwardingGrants[0].PerForwardSpeedMbps != 37.5 {
		t.Fatalf("updated forwarding speed=%v want=37.5", stored.ForwardingGrants[0].PerForwardSpeedMbps)
	}

	for _, testCase := range []struct {
		name            string
		speed           float64
		connectionLimit int
	}{
		{name: "nan", speed: math.NaN()},
		{name: "positive infinity", speed: math.Inf(1)},
		{name: "negative infinity", speed: math.Inf(-1)},
		{name: "connection limit", speed: 10, connectionLimit: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := repo.CreatePackage(ctx, Package{
				Name: "invalid-package-forward-" + testCase.name, CycleDays: 30, ResetDay: 1,
				ForwardingGrants: []PackageForwardingGrant{{
					TunnelID: tunnelID, PerForwardSpeedMbps: testCase.speed,
					PerForwardConnectionLimit: testCase.connectionLimit,
					BillingModeOverride:       forwardingBillingModePtr(ManagedBillingBoth),
				}},
			})
			if err == nil {
				t.Fatal("invalid package forwarding grant was accepted")
			}
			if testCase.connectionLimit == 0 && !errors.Is(err, ErrForwardingInvalid) {
				t.Fatalf("error=%v want %v", err, ErrForwardingInvalid)
			}
		})
	}
}

func TestPackageLimitContractManualTunnelGrantValidation(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		speed     float64
		wantError bool
	}{
		{name: "finite", speed: 18.75},
		{name: "nan", speed: math.NaN(), wantError: true},
		{name: "positive infinity", speed: math.Inf(1), wantError: true},
		{name: "negative infinity", speed: math.Inf(-1), wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newForwardingStorageFixture(t)
			now := time.Now().UTC()
			grant, err := fixture.repo.CreateUserTunnelGrant(fixture.ctx, UserTunnelGrant{
				Username: "bob", TunnelID: fixture.tunnel.ID, Enabled: true, StartsAt: now,
				MaxActiveForwards: 2, PerForwardSpeedMbps: testCase.speed,
				BillingModeOverride: forwardingBillingModePtr(ManagedBillingDownload),
				AllowManagedTarget:  true, CreatedBy: "admin",
			})
			if testCase.wantError {
				if !errors.Is(err, ErrForwardingInvalid) {
					t.Fatalf("CreateUserTunnelGrant error=%v want=%v", err, ErrForwardingInvalid)
				}
				return
			}
			if err != nil {
				t.Fatalf("finite manual forwarding speed: %v", err)
			}
			if grant.PerForwardSpeedMbps != testCase.speed {
				t.Fatalf("stored manual forwarding speed=%v want=%v", grant.PerForwardSpeedMbps, testCase.speed)
			}
		})
	}
}
