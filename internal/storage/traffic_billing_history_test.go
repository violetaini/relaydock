package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectionTimeBillingPreservesHistoricalMultipliers(t *testing.T) {
	ctx := context.Background()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "billing-history.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	server := &RemoteServer{Name: "edge-billing", Token: "edge-billing-token"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username:       "admin",
		RawURL:         "vless://billing-test",
		NodeName:       "billing-node",
		Protocol:       "vless",
		ClashConfig:    `{}`,
		Enabled:        true,
		OriginalServer: server.Name,
		InboundTag:     "vless-in",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	pkg := Package{
		Name:            "billing-package",
		Nodes:           []int64{node.ID},
		TrafficMode:     "oneway",
		NodeMultipliers: map[int64]float64{node.ID: 2},
	}
	pkg.ID, err = repo.CreatePackage(ctx, pkg)
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, package_id) VALUES (?, ?, ?)`,
		"alice", "test-hash", pkg.ID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	repo.invalidateTrafficBillingCache()

	record := func(rawUplink int64) {
		t.Helper()
		resolved, err := repo.ResolveUserTrafficBilling(ctx, server.ID, []string{"alice__vless-in"})
		if err != nil {
			t.Fatalf("ResolveUserTrafficBilling: %v", err)
		}
		billing := resolved["alice__vless-in"]
		if err := repo.UpsertUserTrafficBatch(ctx, server.ID, []UserTrafficSample{{
			Email:             "alice__vless-in",
			Username:          billing.Username,
			Uplink:            rawUplink,
			BillingMultiplier: billing.Multiplier,
		}}, false); err != nil {
			t.Fatalf("UpsertUserTrafficBatch: %v", err)
		}
	}

	record(100) // first observation is a baseline
	record(200) // +100 * 2
	if used, err := repo.GetUserBillableTraffic(ctx, "alice"); err != nil || used != 200 {
		t.Fatalf("billable after x2 delta = %d, %v; want 200", used, err)
	}

	pkg.NodeMultipliers[node.ID] = 5
	if err := repo.UpdatePackage(ctx, pkg); err != nil {
		t.Fatalf("UpdatePackage x5: %v", err)
	}
	record(300) // +100 * 5; previous 200 must stay unchanged
	if used, err := repo.GetUserBillableTraffic(ctx, "alice"); err != nil || used != 700 {
		t.Fatalf("billable after x5 delta = %d, %v; want 700", used, err)
	}

	pkg.TrafficMode = "twoway"
	if err := repo.UpdatePackage(ctx, pkg); err != nil {
		t.Fatalf("UpdatePackage twoway: %v", err)
	}
	record(400) // +100 * (5 * 2)
	if used, err := repo.GetUserBillableTraffic(ctx, "alice"); err != nil || used != 1700 {
		t.Fatalf("billable after twoway delta = %d, %v; want 1700", used, err)
	}

	resetAt := time.Now()
	if err := repo.ResetUserTrafficCycleAt(ctx, "alice", resetAt); err != nil {
		t.Fatalf("ResetUserTrafficCycleAt: %v", err)
	}
	if used, err := repo.GetUserBillableTraffic(ctx, "alice"); err != nil || used != 0 {
		t.Fatalf("billable after reset = %d, %v; want 0", used, err)
	}
	record(500)
	if used, err := repo.GetUserBillableTraffic(ctx, "alice"); err != nil || used != 1000 {
		t.Fatalf("billable after post-reset delta = %d, %v; want 1000", used, err)
	}
}

func TestCollectionTimeBillingPreservesDeletedSubaccountAttribution(t *testing.T) {
	ctx := context.Background()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "billing-attribution.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	server := &RemoteServer{Name: "edge-attribution", Token: "edge-attribution-token"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`,
		"alice", "test-hash"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO user_subaccounts
		(username, routed_node_id, email, credential_json) VALUES (?, ?, ?, ?)`,
		"alice", 42, "opaque-client-id", `{}`); err != nil {
		t.Fatalf("insert subaccount: %v", err)
	}
	repo.invalidateTrafficBillingCache()

	record := func(rawUplink int64) {
		t.Helper()
		resolved, err := repo.ResolveUserTrafficBilling(ctx, server.ID, []string{"opaque-client-id"})
		if err != nil {
			t.Fatalf("ResolveUserTrafficBilling: %v", err)
		}
		billing := resolved["opaque-client-id"]
		if err := repo.UpsertUserTrafficBatch(ctx, server.ID, []UserTrafficSample{{
			Email:             "opaque-client-id",
			Username:          billing.Username,
			Uplink:            rawUplink,
			BillingMultiplier: billing.Multiplier,
		}}, false); err != nil {
			t.Fatalf("UpsertUserTrafficBatch: %v", err)
		}
	}

	record(100)
	record(250)
	if _, err := repo.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE email = ?`, "opaque-client-id"); err != nil {
		t.Fatalf("delete subaccount: %v", err)
	}
	repo.invalidateTrafficBillingCache()

	if used, err := repo.GetUserBillableTraffic(ctx, "alice"); err != nil || used != 150 {
		t.Fatalf("billable after deleting subaccount = %d, %v; want 150", used, err)
	}
	if err := repo.ResetUserTrafficCycle(ctx, "alice"); err != nil {
		t.Fatalf("reset after deleting subaccount: %v", err)
	}
	if used, err := repo.GetUserBillableTraffic(ctx, "alice"); err != nil || used != 0 {
		t.Fatalf("billable after reset with deleted subaccount = %d, %v; want 0", used, err)
	}
}

func TestCollectionTimeBillingCarriesFractionAcrossSmallDeltas(t *testing.T) {
	ctx := context.Background()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "billing-fraction.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	server := &RemoteServer{Name: "edge-fraction", Token: "edge-fraction-token"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	record := func(counter int64) {
		t.Helper()
		if err := repo.UpsertUserTrafficBatch(ctx, server.ID, []UserTrafficSample{{
			Email:             "alice__fraction",
			Username:          "alice",
			Uplink:            counter,
			BillingMultiplier: 0.5,
		}}, false); err != nil {
			t.Fatalf("UpsertUserTrafficBatch(%d): %v", counter, err)
		}
	}

	record(0)
	for counter := int64(1); counter <= 100; counter++ {
		record(counter)
	}
	if used, err := repo.GetUserBillableTraffic(ctx, "alice"); err != nil || used != 50 {
		t.Fatalf("billable after 100 one-byte deltas at 0.5x = %d, %v; want 50", used, err)
	}
}
