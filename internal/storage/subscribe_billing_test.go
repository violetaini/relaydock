package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSubscribeMultipliersAppliedInBillingAndNodeTraffic(t *testing.T) {
	ctx := context.Background()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "sub-billing.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	server := &RemoteServer{Name: "billing-edge", Token: "tok-bill"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	createNode := func(name, tag, nodeTag string) Node {
		n, cErr := repo.CreateNode(ctx, Node{
			Username:       "admin",
			RawURL:         "vless://" + name,
			NodeName:       name,
			Tag:            nodeTag,
			Protocol:       "vless",
			ClashConfig:    `{}`,
			Enabled:        true,
			OriginalServer: server.Name,
			InboundTag:     tag,
		})
		if cErr != nil {
			t.Fatalf("CreateNode %s: %v", name, cErr)
		}
		return n
	}
	nodeDirectSub := createNode("n-sub1", "in-sub1", "")
	nodeTaggedSub := createNode("n-sub2", "in-sub2", "vip-tag")
	nodeOverride := createNode("n-override", "in-override", "")

	sub1, err := repo.CreateSubscribeFile(ctx, SubscribeFile{
		Name: "Sub-1", Type: SubscribeTypeCreate, Filename: "sub1.yaml",
		CreatedBy: "admin", SelectedNodeIDs: []int64{nodeDirectSub.ID, nodeOverride.ID},
	})
	if err != nil {
		t.Fatalf("CreateSubscribeFile sub1: %v", err)
	}
	sub2, err := repo.CreateSubscribeFile(ctx, SubscribeFile{
		Name: "Sub-2-Tags", Type: SubscribeTypeCreate, Filename: "sub2.yaml",
		CreatedBy: "admin", SelectedTags: []string{"vip-tag"},
	})
	if err != nil {
		t.Fatalf("CreateSubscribeFile sub2: %v", err)
	}

	pkgID, err := repo.CreatePackage(ctx, Package{
		Name:             "sub-mult-pkg",
		TrafficMode:      "twoway", // doubles effective multiplier
		SubscribeFileIDs: []int64{sub1.ID, sub2.ID},
		NodeMultipliers: map[int64]float64{
			nodeOverride.ID: 3.0, // explicit node override > sub1's 2.5
		},
		SubscribeMultipliers: map[int64]float64{
			sub1.ID: 2.5,
			sub2.ID: 0.5,
		},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, package_id, authorization_mode) VALUES (?, ?, ?, 'package')`,
		"alice", "hash", pkgID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	repo.invalidateTrafficBillingCache()

	emails := []string{"alice__in-sub1", "alice__in-sub2", "alice__in-override"}
	resolved, err := repo.ResolveUserTrafficBilling(ctx, server.ID, emails)
	if err != nil {
		t.Fatalf("ResolveUserTrafficBilling: %v", err)
	}
	if got := resolved["alice__in-sub1"].Multiplier; got != 5.0 {
		t.Fatalf("sub1 node multiplier = %v, want 5.0 (2.5 * twoway 2)", got)
	}
	if got := resolved["alice__in-sub2"].Multiplier; got != 1.0 {
		t.Fatalf("sub2 tag node multiplier = %v, want 1.0 (0.5 * twoway 2)", got)
	}
	if got := resolved["alice__in-override"].Multiplier; got != 6.0 {
		t.Fatalf("explicit node override multiplier = %v, want 6.0 (3.0 * twoway 2)", got)
	}

	// Verify collection-time accrual + GetUserNodeTraffic agreement.
	record := func(uplink int64) {
		var samples []UserTrafficSample
		for _, em := range emails {
			samples = append(samples, UserTrafficSample{
				Email:             em,
				Username:          "alice",
				Uplink:            uplink,
				BillingMultiplier: resolved[em].Multiplier,
			})
		}
		if err := repo.UpsertUserTrafficBatch(ctx, server.ID, samples, false); err != nil {
			t.Fatalf("UpsertUserTrafficBatch: %v", err)
		}
	}
	record(0)   // baseline
	record(100) // +100 raw bytes each

	pkg, err := repo.GetPackage(ctx, pkgID)
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	nodeUsage, err := repo.GetUserNodeTraffic(ctx, "alice", []int64{nodeDirectSub.ID, nodeTaggedSub.ID, nodeOverride.ID}, pkg)
	if err != nil {
		t.Fatalf("GetUserNodeTraffic: %v", err)
	}
	if nodeUsage[nodeDirectSub.ID] != 500 || nodeUsage[nodeTaggedSub.ID] != 100 || nodeUsage[nodeOverride.ID] != 600 {
		t.Fatalf("unexpected GetUserNodeTraffic=%v want sub1=500 sub2=100 override=600", nodeUsage)
	}

	// Updating subscribe_files to include another existing node must invalidate billing cache immediately.
	nodeExistingNotInSub := createNode("n-late", "in-late", "")
	// Warm billing cache first before attaching nodeExistingNotInSub to sub1.
	warmResolved, err := repo.ResolveUserTrafficBilling(ctx, server.ID, []string{"alice__in-late"})
	if err != nil {
		t.Fatalf("warm ResolveUserTrafficBilling: %v", err)
	}
	if got := warmResolved["alice__in-late"].Multiplier; got != 2.0 {
		t.Fatalf("unlinked node multiplier = %v, want 2.0 (1.0 * twoway 2)", got)
	}
	sub1.SelectedNodeIDs = append(sub1.SelectedNodeIDs, nodeExistingNotInSub.ID)
	if _, err := repo.UpdateSubscribeFile(ctx, sub1); err != nil {
		t.Fatalf("UpdateSubscribeFile: %v", err)
	}
	resolvedLate, err := repo.ResolveUserTrafficBilling(ctx, server.ID, []string{"alice__in-late"})
	if err != nil {
		t.Fatalf("ResolveUserTrafficBilling late node: %v", err)
	}
	if got := resolvedLate["alice__in-late"].Multiplier; got != 5.0 {
		t.Fatalf("late sub node multiplier after UpdateSubscribeFile = %v, want 5.0", got)
	}
}
