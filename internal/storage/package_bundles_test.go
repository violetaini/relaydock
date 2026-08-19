package storage

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func packageBundleTestRepo(t *testing.T) *TrafficRepository {
	t.Helper()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "package-bundle.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func addPackageBundleServer(t *testing.T, repo *TrafficRepository, name string) int64 {
	t.Helper()
	result, err := repo.db.Exec(`INSERT INTO remote_servers(name,token,status,ip_address,xray_running) VALUES(?,?,'connected','127.0.0.1',1)`, name, name+"-token")
	if err != nil {
		t.Fatalf("insert remote server: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

func TestDirectNodeGrantMigrationAndDesiredState(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "direct-server")
	if _, err := repo.db.Exec(`UPDATE remote_servers SET xray_mode='embedded' WHERE id=?`, serverID); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "direct-node", Protocol: "vless", Enabled: true,
		OriginalServer: "direct-server", InboundTag: "vless-in",
		ClashConfig: `{"name":"direct-node","type":"vless","server":"203.0.113.10","port":443}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	item, created, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil || !created {
		t.Fatalf("UpsertManualUserNodeGrant created=%v err=%v", created, err)
	}
	if item.Grant.SourceType != GrantSourceManual || item.Source.SourceType != ManagedSourceDirect ||
		item.Source.DesiredState != ManagedDesiredActive || item.Source.ObservedState != ManagedObservedUnknown {
		t.Fatalf("unexpected direct grant: %+v", item)
	}
	if _, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin"); err != nil {
		t.Fatalf("idempotent direct grant update: %v", err)
	}
}

func addPackageBundleTunnel(t *testing.T, repo *TrafficRepository, serverID int64, name string) int64 {
	t.Helper()
	item, err := repo.CreateTunnelTemplate(context.Background(), TunnelTemplate{
		Name: name, State: TunnelStateActive, Network: ForwardNetworkTCPUDP,
		BillingMode: ManagedBillingBoth, TrafficMultiplierMilli: 1000,
		AllowManagedTarget: true, PortRangeStart: 20000, PortRangeEnd: 20100, CreatedBy: "admin",
		Hops: []TunnelTemplateHop{{ServerID: serverID}},
	})
	if err != nil {
		t.Fatalf("CreateTunnelTemplate: %v", err)
	}
	return item.ID
}

func TestPackageBundleMaterializesUpdatesAndRevokesGrants(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	serverID := addPackageBundleServer(t, repo, "bundle-server")
	tunnelID := addPackageBundleTunnel(t, repo, serverID, "bundle-tunnel")
	pkg := Package{
		Name: "bundle", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants:     []PackageServerGrant{{ServerID: serverID, MaxActiveNodes: 2, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone}},
		ForwardingGrants: []PackageForwardingGrant{{TunnelID: tunnelID, MaxActiveForwards: 3, BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth)}},
	}
	packageID, err := repo.CreatePackage(ctx, pkg)
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	start := time.Now().UTC().Add(-time.Minute)
	end := start.Add(30 * 24 * time.Hour)
	warnings, err := repo.AssignPackageBundleToUser(ctx, "alice", packageID, start, end, false, 1)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("AssignPackageBundleToUser warnings=%v err=%v", warnings, err)
	}
	serverGrants, err := repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(serverGrants) != 1 {
		t.Fatalf("ListUserServerGrants=%v err=%v", serverGrants, err)
	}
	if serverGrants[0].SourceType != GrantSourcePackage || serverGrants[0].SourcePackageID == nil || *serverGrants[0].SourcePackageID != packageID {
		t.Fatalf("server grant source=%+v", serverGrants[0])
	}
	tunnelGrants, err := repo.ListUserTunnelGrants(ctx, "alice")
	if err != nil || len(tunnelGrants) != 1 {
		t.Fatalf("ListUserTunnelGrants=%v err=%v", tunnelGrants, err)
	}
	if tunnelGrants[0].SourceType != GrantSourcePackage || tunnelGrants[0].SourcePackageID == nil || *tunnelGrants[0].SourcePackageID != packageID {
		t.Fatalf("tunnel grant source=%+v", tunnelGrants[0])
	}

	stored, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	stored.ServerGrants[0].MaxActiveNodes = 7
	stored.ForwardingGrants = nil
	if warningsByUser, err := repo.UpdatePackageBundle(ctx, *stored); err != nil || len(warningsByUser) != 0 {
		t.Fatalf("UpdatePackageBundle warnings=%v err=%v", warningsByUser, err)
	}
	serverGrants, _ = repo.ListUserServerGrants(ctx, "alice")
	if serverGrants[0].MaxActiveNodes != 7 || !serverGrants[0].Enabled {
		t.Fatalf("updated server grant=%+v", serverGrants[0])
	}
	tunnelGrants, _ = repo.ListUserTunnelGrants(ctx, "alice")
	if len(tunnelGrants) != 0 {
		t.Fatalf("unused removed package tunnel grant should be deleted: %+v", tunnelGrants)
	}

	if err := repo.RemovePackageFromUser(ctx, "alice"); err != nil {
		t.Fatalf("RemovePackageFromUser: %v", err)
	}
	serverGrants, _ = repo.ListUserServerGrants(ctx, "alice")
	if len(serverGrants) != 0 {
		t.Fatalf("unused unassigned package server grant should be deleted: %+v", serverGrants)
	}
}

func TestPackageServerGrantProtocolPolicyMaterializesAndRejectsSelection(t *testing.T) {
	ctx, repo := context.Background(), packageBundleTestRepo(t)
	_, server, node, offer := seedManagedNodesTest(t, repo)
	node.ClashConfig = `{"type":"vless","network":"ws"}`
	node.ParsedConfig = node.ClashConfig
	if _, err := repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("update managed node profile: %v", err)
	}

	pkgID, err := repo.CreatePackage(ctx, Package{
		Name: "protocol-scoped-bundle", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []PackageServerGrant{{
			ServerID: server.ID, MaxActiveNodes: 2, BillingMode: ManagedBillingDownload,
			ResetPolicy: ManagedResetNone, AllowedProtocols: []string{"vless"},
			AllowedProtocolProfiles: []string{"vless-wss"},
		}},
	})
	if err != nil {
		t.Fatalf("create protocol-scoped package: %v", err)
	}
	start := time.Now().UTC().Add(-time.Minute)
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", pkgID, start, start.Add(24*time.Hour), false, 1); err != nil {
		t.Fatalf("assign protocol-scoped package: %v", err)
	}

	grants, err := repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(grants) != 1 {
		t.Fatalf("materialized grants=%+v err=%v", grants, err)
	}
	grant := grants[0]
	if grant.SourceType != GrantSourcePackage || !reflect.DeepEqual(grant.AllowedProtocols, []string{"vless"}) ||
		!reflect.DeepEqual(grant.AllowedProtocolProfiles, []string{"vless-wss"}) {
		t.Fatalf("materialized protocol policy lost: %+v", grant)
	}
	catalog, err := repo.ListManagedNodeCatalog(ctx, "alice", start.Add(time.Minute))
	if err != nil || len(catalog) != 1 {
		t.Fatalf("catalog=%+v err=%v", catalog, err)
	}
	if catalog[0].CanCreate || catalog[0].DenyReason != "protocol_not_allowed" || catalog[0].ProtocolProfile != "vless-ws" {
		t.Fatalf("disallowed profile escaped package policy: %+v", catalog[0])
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", start.Add(time.Minute)); !errors.Is(err, ErrManagedProtocolNotAllowed) {
		t.Fatalf("activation error=%v, want %v", err, ErrManagedProtocolNotAllowed)
	}

	stored, err := repo.GetPackage(ctx, pkgID)
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	stored.ServerGrants[0].AllowedProtocolProfiles = []string{"vless-ws"}
	if _, err := repo.UpdatePackageBundle(ctx, *stored); err != nil {
		t.Fatalf("update package protocol profile: %v", err)
	}
	grants, err = repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(grants) != 1 || !reflect.DeepEqual(grants[0].AllowedProtocolProfiles, []string{"vless-ws"}) {
		t.Fatalf("updated materialized protocol policy=%+v err=%v", grants, err)
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", start.Add(2*time.Minute)); err != nil {
		t.Fatalf("activation after allowing matching profile: %v", err)
	}
}

func TestPackageForwardingGrantRequiresExplicitBillingMode(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	serverID := addPackageBundleServer(t, repo, "explicit-billing-server")
	tunnelID := addPackageBundleTunnel(t, repo, serverID, "explicit-billing-tunnel")
	base := Package{
		Name: "missing-forward-billing", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ForwardingGrants: []PackageForwardingGrant{{TunnelID: tunnelID}},
	}
	if _, err := repo.CreatePackage(ctx, base); !errors.Is(err, ErrForwardingInvalid) {
		t.Fatalf("package without forwarding billing mode error=%v want=%v", err, ErrForwardingInvalid)
	}
	base.Name = "upload-forward-billing"
	base.ForwardingGrants[0].BillingModeOverride = forwardingBillingModePtr(ManagedBillingUpload)
	if _, err := repo.CreatePackage(ctx, base); err != nil {
		t.Fatalf("package with upload billing mode: %v", err)
	}
}

func TestPackageForwardingBillingChangeUpdatesUnusedSnapshotsAndRejectsUsed(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "package-billing-server")
	tunnelID := addPackageBundleTunnel(t, repo, serverID, "package-billing-tunnel")
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "package-billing", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ForwardingGrants: []PackageForwardingGrant{{
			TunnelID: tunnelID, MaxActiveForwards: 2,
			BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", packageID, now, now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	grants, err := repo.ListUserTunnelGrants(ctx, "alice")
	if err != nil || len(grants) != 1 {
		t.Fatalf("materialized forwarding grants=%+v err=%v", grants, err)
	}
	forward, err := repo.CreateUserForward(ctx, CreateUserForwardInput{
		Username: "alice", Name: "package-billing-forward", GrantPublicID: grants[0].PublicID,
		TargetNodeID: 42, TargetHost: "198.51.100.42", TargetPort: 443, Actor: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.ForwardingGrants[0].BillingModeOverride = forwardingBillingModePtr(ManagedBillingUpload)
	if _, err := repo.UpdatePackageBundle(ctx, *pkg); err != nil {
		t.Fatalf("change unused package forwarding billing mode: %v", err)
	}
	forward, err = repo.GetUserForward(ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if forward.BillingModeSnapshot != ManagedBillingUpload {
		t.Fatalf("package-updated forward snapshot=%q want=%q", forward.BillingModeSnapshot, ManagedBillingUpload)
	}
	entry := forward.Hops[0]
	if err := repo.UpsertNodeTraffic(ctx, entry.ServerID, entry.ResourceTag, "inbound", 25, 75, false); err != nil {
		t.Fatal(err)
	}
	if err := repo.SyncUserForwardUsage(ctx); err != nil {
		t.Fatal(err)
	}
	pkg, err = repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.ForwardingGrants[0].BillingModeOverride = forwardingBillingModePtr(ManagedBillingDownload)
	if _, err := repo.UpdatePackageBundle(ctx, *pkg); !errors.Is(err, ErrForwardingBillingModeConflict) {
		t.Fatalf("change used package forwarding billing mode error=%v want=%v", err, ErrForwardingBillingModeConflict)
	}
	pkg, err = repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.ForwardingGrants[0].BillingModeOverride == nil || *pkg.ForwardingGrants[0].BillingModeOverride != ManagedBillingUpload {
		t.Fatalf("failed package update changed template: %+v", pkg.ForwardingGrants)
	}
	forward, err = repo.GetUserForward(ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if forward.BillingModeSnapshot != ManagedBillingUpload {
		t.Fatalf("failed package update changed snapshot: %+v", forward)
	}
}

func TestUpdatePackageBundleBackfillsLegacyAssignmentWindow(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "legacy", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "legacy-window-server")
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "legacy-window", TrafficLimitBytes: 1024, CycleDays: 14, ResetDay: 1,
		ServerGrants: []PackageServerGrant{{
			ServerID: serverID, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE users SET package_id=?, package_start_date=NULL, package_end_date=NULL WHERE username='legacy'`, packageID); err != nil {
		t.Fatal(err)
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	if _, err := repo.UpdatePackageBundle(ctx, *pkg); err != nil {
		t.Fatalf("UpdatePackageBundle: %v", err)
	}
	user, err := repo.GetUser(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if user.PackageStartDate == nil || user.PackageEndDate == nil {
		t.Fatalf("legacy package window was not persisted: %+v", user)
	}
	if user.PackageStartDate.Before(before) || !user.PackageEndDate.Equal(user.PackageStartDate.AddDate(0, 0, pkg.CycleDays)) {
		t.Fatalf("unexpected backfilled window start=%v end=%v", user.PackageStartDate, user.PackageEndDate)
	}
	grants, err := repo.ListUserServerGrants(ctx, "legacy")
	if err != nil || len(grants) != 1 || grants[0].ExpiresAt == nil {
		t.Fatalf("materialized grants=%+v err=%v", grants, err)
	}
	if !grants[0].StartsAt.Equal(*user.PackageStartDate) || !grants[0].ExpiresAt.Equal(*user.PackageEndDate) {
		t.Fatalf("assignment and grant windows diverged: user=%v..%v grant=%v..%v",
			user.PackageStartDate, user.PackageEndDate, grants[0].StartsAt, grants[0].ExpiresAt)
	}
}

func TestPackageBundleRejectsActiveManualGrant(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "manual-server")
	now := time.Now().UTC()
	manual, err := repo.CreateUserServerGrant(ctx, UserServerGrant{
		Username: "alice", ServerID: serverID, Enabled: true, StartsAt: now,
		MaxActiveNodes: 9, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone,
		ResetDay: 1, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateUserServerGrant: %v", err)
	}
	if manual.SourceType != GrantSourceManual {
		t.Fatalf("manual source=%q", manual.SourceType)
	}
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "manual-preserving", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []PackageServerGrant{{ServerID: serverID, MaxActiveNodes: 1, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone}},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	warnings, err := repo.AssignPackageBundleToUser(ctx, "alice", packageID, now, now.Add(24*time.Hour), false, 1)
	if !errors.Is(err, ErrAuthorizationModeConflict) || len(warnings) != 0 {
		t.Fatalf("warnings=%v err=%v, want authorization mode conflict", warnings, err)
	}
	got, err := repo.GetUserServerGrant(ctx, manual.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxActiveNodes != 9 || got.SourceType != GrantSourceManual || !got.Enabled {
		t.Fatalf("manual grant was overwritten: %+v", got)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != AuthorizationModeCustom || user.PackageID != 0 {
		t.Fatalf("failed assignment changed user: user=%+v err=%v", user, err)
	}
}

func TestPackageBundleFutureAssignmentCreatesScheduledGrants(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "future-server")
	tunnelID := addPackageBundleTunnel(t, repo, serverID, "future-tunnel")
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "future", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []PackageServerGrant{{
			ServerID: serverID, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone,
		}},
		ForwardingGrants: []PackageForwardingGrant{{TunnelID: tunnelID, BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	start := now.Add(time.Hour)
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", packageID, start, start.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	serverGrants, _ := repo.ListUserServerGrants(ctx, "alice")
	if len(serverGrants) != 1 || serverGrants[0].StateAt(now, true, 0) != ManagedGrantScheduled {
		t.Fatalf("future server grant should be scheduled: %+v", serverGrants)
	}
	tunnelGrants, _ := repo.ListUserTunnelGrants(ctx, "alice")
	if len(tunnelGrants) != 1 || tunnelGrants[0].StateAt(now, true, TunnelStateActive, 0) != "scheduled" {
		t.Fatalf("future tunnel grant should be scheduled: %+v", tunnelGrants)
	}
}

func TestPackageBundleSwitchTransfersSourceWithoutReactivatingSelection(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "switch-server")
	makePackage := func(name string, maxNodes int) int64 {
		id, err := repo.CreatePackage(ctx, Package{
			Name: name, TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
			ServerGrants: []PackageServerGrant{{
				ServerID: serverID, MaxActiveNodes: maxNodes,
				BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	firstPackageID := makePackage("first", 1)
	secondPackageID := makePackage("second", 2)
	now := time.Now().UTC()
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", firstPackageID, now, now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	grants, _ := repo.ListUserServerGrants(ctx, "alice")
	if len(grants) != 1 {
		t.Fatalf("first package grant: %+v", grants)
	}
	if _, err := repo.db.Exec(`INSERT INTO user_node_selections(grant_id,offer_id,desired_enabled) VALUES(?,?,1)`, grants[0].ID, 999); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", secondPackageID, now, now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	grants, _ = repo.ListUserServerGrants(ctx, "alice")
	if len(grants) != 1 || grants[0].SourcePackageID == nil || *grants[0].SourcePackageID != secondPackageID || grants[0].MaxActiveNodes != 2 {
		t.Fatalf("package grant source was not transferred: %+v", grants)
	}
	var desiredEnabled int
	if err := repo.db.QueryRow(`SELECT desired_enabled FROM user_node_selections WHERE grant_id=?`, grants[0].ID).Scan(&desiredEnabled); err != nil {
		t.Fatal(err)
	}
	if desiredEnabled != 0 {
		t.Fatalf("old package selection was silently reactivated: desired_enabled=%d", desiredEnabled)
	}
}

func TestPackageBundleRevokedTombstonesCanBecomeManualGrants(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "tombstone-server")
	tunnelID := addPackageBundleTunnel(t, repo, serverID, "tombstone-tunnel")
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "tombstones", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []PackageServerGrant{{
			ServerID: serverID, MaxActiveNodes: 2, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone,
		}},
		ForwardingGrants: []PackageForwardingGrant{{TunnelID: tunnelID, MaxActiveForwards: 2, BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", packageID, now, now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	serverGrants, _ := repo.ListUserServerGrants(ctx, "alice")
	tunnelGrants, _ := repo.ListUserTunnelGrants(ctx, "alice")
	if _, err := repo.db.Exec(`INSERT INTO user_node_selections(grant_id,offer_id,desired_enabled) VALUES(?,?,1)`, serverGrants[0].ID, 999); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`INSERT INTO user_forward_rules(public_id,grant_id,username,name,target_type,target_node_id,target_host,target_port,network,source_cidrs,billing_mode_snapshot,traffic_multiplier_milli_snapshot) VALUES('fwd_tombstone',?,'alice','old','managed_node',999,'127.0.0.1',80,'tcp_udp','[]','both',1000)`, tunnelGrants[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.RemovePackageFromUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(48 * time.Hour)
	manualServer, err := repo.CreateUserServerGrant(ctx, UserServerGrant{
		Username: "alice", ServerID: serverID, Enabled: true, StartsAt: now, ExpiresAt: &expires,
		MaxActiveNodes: 5, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone, ResetDay: 1, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if manualServer.ID != serverGrants[0].ID || manualServer.SourceType != GrantSourceManual {
		t.Fatalf("server tombstone was not adopted: %+v", manualServer)
	}
	manualTunnel, err := repo.CreateUserTunnelGrant(ctx, UserTunnelGrant{
		Username: "alice", TunnelID: tunnelID, Enabled: true, StartsAt: now, ExpiresAt: &expires,
		MaxActiveForwards: 5, BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth),
		AllowManagedTarget: true, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if manualTunnel.ID != tunnelGrants[0].ID || manualTunnel.SourceType != GrantSourceManual {
		t.Fatalf("tunnel tombstone was not adopted: %+v", manualTunnel)
	}
	var selectionDesired int
	if err := repo.db.QueryRow(`SELECT desired_enabled FROM user_node_selections WHERE grant_id=?`, manualServer.ID).Scan(&selectionDesired); err != nil {
		t.Fatal(err)
	}
	var forwardDesired string
	if err := repo.db.QueryRow(`SELECT desired_state FROM user_forward_rules WHERE grant_id=?`, manualTunnel.ID).Scan(&forwardDesired); err != nil {
		t.Fatal(err)
	}
	if selectionDesired != 0 || forwardDesired != ForwardDesiredInactive {
		t.Fatalf("adoption reactivated old children: selection=%d forward=%s", selectionDesired, forwardDesired)
	}
}

func TestPackageBundleUpdateRejectsActiveNodeLimitNarrowing(t *testing.T) {
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "narrow-server")
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "narrow", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []PackageServerGrant{{
			ServerID: serverID, MaxActiveNodes: 2, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", packageID, now, now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	grants, _ := repo.ListUserServerGrants(ctx, "alice")
	if _, err := repo.db.Exec(`INSERT INTO user_node_selections(grant_id,offer_id,desired_enabled) VALUES(?,?,1),(?,?,1)`, grants[0].ID, 998, grants[0].ID, 999); err != nil {
		t.Fatal(err)
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.ServerGrants[0].MaxActiveNodes = 1
	if _, err := repo.UpdatePackageBundle(ctx, *pkg); !errors.Is(err, ErrManagedActiveNodeLimit) {
		t.Fatalf("expected active node limit conflict, got %v", err)
	}
	grants, _ = repo.ListUserServerGrants(ctx, "alice")
	if grants[0].MaxActiveNodes != 2 {
		t.Fatalf("failed package update was partially committed: %+v", grants[0])
	}
}
