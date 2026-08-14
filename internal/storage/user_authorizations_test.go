package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type authorizationModeFixture struct {
	repo      *TrafficRepository
	serverID  int64
	nodeID    int64
	tunnelID  int64
	packageID int64
}

func newAuthorizationModeFixture(t *testing.T) authorizationModeFixture {
	t.Helper()
	ctx := context.Background()
	repo := packageBundleTestRepo(t)
	if err := repo.EnsureUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	serverID := addPackageBundleServer(t, repo, "authorization-server")
	if _, err := repo.db.Exec(`UPDATE remote_servers SET xray_mode='embedded' WHERE id=?`, serverID); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "authorization-node", Protocol: "vless", Enabled: true,
		OriginalServer: "authorization-server", InboundTag: "vless-in",
		ClashConfig: `{"name":"authorization-node","type":"vless","server":"203.0.113.10","port":443}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnelID := addPackageBundleTunnel(t, repo, serverID, "authorization-tunnel")
	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "authorization-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authorizationModeFixture{repo: repo, serverID: serverID, nodeID: node.ID, tunnelID: tunnelID, packageID: packageID}
}

func TestPackageAssignmentRejectsEveryActiveManualAuthorization(t *testing.T) {
	tests := []struct {
		name  string
		grant func(*testing.T, authorizationModeFixture)
	}{
		{name: "direct node", grant: func(t *testing.T, f authorizationModeFixture) {
			if _, _, err := f.repo.UpsertManualUserNodeGrant(context.Background(), "alice", f.nodeID, nil, "admin"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "server", grant: func(t *testing.T, f authorizationModeFixture) {
			if _, err := f.repo.CreateUserServerGrant(context.Background(), UserServerGrant{
				Username: "alice", ServerID: f.serverID, Enabled: true, StartsAt: time.Now().UTC(),
				BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone, ResetDay: 1, CreatedBy: "admin",
			}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "forwarding", grant: func(t *testing.T, f authorizationModeFixture) {
			if _, err := f.repo.CreateUserTunnelGrant(context.Background(), UserTunnelGrant{
				Username: "alice", TunnelID: f.tunnelID, Enabled: true, StartsAt: time.Now().UTC(),
				MaxActiveForwards: 1, BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth),
				AllowManagedTarget: true, CreatedBy: "admin",
			}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newAuthorizationModeFixture(t)
			tt.grant(t, fixture)
			now := time.Now().UTC()
			if _, err := fixture.repo.AssignPackageBundleToUser(ctx, "alice", fixture.packageID, now, now.Add(time.Hour), false, 1); !errors.Is(err, ErrAuthorizationModeConflict) {
				t.Fatalf("AssignPackageBundleToUser error = %v, want %v", err, ErrAuthorizationModeConflict)
			}
			user, err := fixture.repo.GetUser(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if user.AuthorizationMode != AuthorizationModeCustom || user.PackageID != 0 {
				t.Fatalf("failed assignment changed user: %+v", user)
			}
		})
	}
}

func TestPackageModeBlocksManualReactivationUntilPackageRemoval(t *testing.T) {
	ctx := context.Background()
	f := newAuthorizationModeFixture(t)
	direct, _, err := f.repo.UpsertManualUserNodeGrant(ctx, "alice", f.nodeID, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.SetUserNodeGrantDesiredState(ctx, direct.Grant.ID, "alice", ManagedDesiredInactive, "admin"); err != nil {
		t.Fatal(err)
	}
	serverGrant, err := f.repo.CreateUserServerGrant(ctx, UserServerGrant{
		Username: "alice", ServerID: f.serverID, Enabled: false, StartsAt: time.Now().UTC(),
		BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone, ResetDay: 1, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnelGrant, err := f.repo.CreateUserTunnelGrant(ctx, UserTunnelGrant{
		Username: "alice", TunnelID: f.tunnelID, Enabled: false, StartsAt: time.Now().UTC(),
		MaxActiveForwards: 1, BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth),
		AllowManagedTarget: true, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := f.repo.AssignPackageBundleToUser(ctx, "alice", f.packageID, now, now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	user, err := f.repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.AuthorizationMode != AuthorizationModePackage || user.PackageID != f.packageID {
		t.Fatalf("unexpected package assignment: %+v", user)
	}
	if _, err := f.repo.SetUserNodeGrantDesiredState(ctx, direct.Grant.ID, "alice", ManagedDesiredActive, "admin"); !errors.Is(err, ErrAuthorizationModeConflict) {
		t.Fatalf("activate direct grant error = %v", err)
	}
	serverGrant.Enabled = true
	if _, err := f.repo.UpdateUserServerGrant(ctx, *serverGrant, serverGrant.Version, "admin"); !errors.Is(err, ErrAuthorizationModeConflict) {
		t.Fatalf("enable server grant error = %v", err)
	}
	tunnelGrant.Enabled = true
	if _, err := f.repo.UpdateUserTunnelGrant(ctx, tunnelGrant.PublicID, "alice", *tunnelGrant, tunnelGrant.Version, "admin"); !errors.Is(err, ErrAuthorizationModeConflict) {
		t.Fatalf("enable tunnel grant error = %v", err)
	}

	if err := f.repo.RemovePackageFromUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.SetUserNodeGrantDesiredState(ctx, direct.Grant.ID, "alice", ManagedDesiredActive, "admin"); err != nil {
		t.Fatalf("activate direct grant after removal: %v", err)
	}
	if _, err := f.repo.UpdateUserServerGrant(ctx, *serverGrant, serverGrant.Version, "admin"); err != nil {
		t.Fatalf("enable server grant after removal: %v", err)
	}
	if _, err := f.repo.UpdateUserTunnelGrant(ctx, tunnelGrant.PublicID, "alice", *tunnelGrant, tunnelGrant.Version, "admin"); err != nil {
		t.Fatalf("enable tunnel grant after removal: %v", err)
	}
	user, err = f.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != AuthorizationModeCustom || user.PackageID != 0 {
		t.Fatalf("unexpected custom assignment after removal: user=%+v err=%v", user, err)
	}
}

func TestPackageGrantTombstonesCannotBeMutatedThroughManualAPIs(t *testing.T) {
	ctx := context.Background()
	f := newAuthorizationModeFixture(t)
	pkg, err := f.repo.CreatePackage(ctx, Package{
		Name: "package-tombstones", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []PackageServerGrant{{
			ServerID: f.serverID, BillingMode: ManagedBillingDownload,
			ResetPolicy: ManagedResetNone, ResetDay: 1,
		}},
		ForwardingGrants: []PackageForwardingGrant{{
			TunnelID: f.tunnelID, MaxActiveForwards: 1,
			BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := f.repo.AssignPackageBundleToUser(ctx, "alice", pkg, now, now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.db.ExecContext(ctx, `UPDATE user_server_grants SET enabled=0 WHERE username='alice';
UPDATE user_tunnel_grants SET enabled=0 WHERE username='alice';
UPDATE users SET package_id=NULL,authorization_mode='custom' WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	servers, err := f.repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(servers) != 1 || servers[0].SourceType != GrantSourcePackage || servers[0].Enabled {
		t.Fatalf("server tombstone: grants=%+v err=%v", servers, err)
	}
	server := servers[0]
	server.Enabled = true
	if _, err := f.repo.UpdateUserServerGrant(ctx, server, server.Version, "admin"); !errors.Is(err, ErrAuthorizationModeConflict) {
		t.Fatalf("package server tombstone update error=%v", err)
	}
	tunnels, err := f.repo.ListUserTunnelGrants(ctx, "alice")
	if err != nil || len(tunnels) != 1 || tunnels[0].SourceType != GrantSourcePackage || tunnels[0].Enabled {
		t.Fatalf("tunnel tombstone: grants=%+v err=%v", tunnels, err)
	}
	tunnel := tunnels[0]
	tunnel.Enabled = true
	if _, err := f.repo.UpdateUserTunnelGrant(ctx, tunnel.PublicID, "alice", tunnel, tunnel.Version, "admin"); !errors.Is(err, ErrAuthorizationModeConflict) {
		t.Fatalf("package tunnel tombstone update error=%v", err)
	}
	if err := f.repo.DeleteUserTunnelGrant(ctx, tunnel.PublicID, "alice", "admin"); !errors.Is(err, ErrAuthorizationModeConflict) {
		t.Fatalf("package tunnel tombstone delete error=%v", err)
	}
}

func TestAuthorizationModeMigrationDeactivatesOppositeSourcesIdempotently(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "authorization-migration.db")
	repo, err := NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"package-user", "custom-user"} {
		if err := repo.EnsureUser(ctx, username, "hash"); err != nil {
			t.Fatal(err)
		}
	}
	serverID := addPackageBundleServer(t, repo, "migration-server")
	if _, err := repo.db.Exec(`UPDATE remote_servers SET xray_mode='embedded' WHERE id=?`, serverID); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username: "admin", NodeName: "migration-node", Protocol: "vless", Enabled: true,
		OriginalServer: "migration-server", InboundTag: "vless-in",
		ClashConfig: `{"name":"migration-node","type":"vless","server":"203.0.113.11","port":443}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnelID := addPackageBundleTunnel(t, repo, serverID, "migration-tunnel")
	now := time.Now().UTC()
	manualDirect, _, err := repo.UpsertManualUserNodeGrant(ctx, "package-user", node.ID, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	manualServer, err := repo.CreateUserServerGrant(ctx, UserServerGrant{
		Username: "package-user", ServerID: serverID, Enabled: true, StartsAt: now,
		BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone, ResetDay: 1, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	manualTunnel, err := repo.CreateUserTunnelGrant(ctx, UserTunnelGrant{
		Username: "package-user", TunnelID: tunnelID, Enabled: true, StartsAt: now,
		MaxActiveForwards: 1, BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth),
		AllowManagedTarget: true, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	offerResult, err := repo.db.Exec(`INSERT INTO self_service_node_offers(node_id,server_id,inbound_tag,created_by) VALUES(?,?,?,'admin')`, node.ID, serverID, node.InboundTag)
	if err != nil {
		t.Fatal(err)
	}
	offerID, _ := offerResult.LastInsertId()
	selectionResult, err := repo.db.Exec(`INSERT INTO user_node_selections(grant_id,offer_id,desired_enabled) VALUES(?,?,1)`, manualServer.ID, offerID)
	if err != nil {
		t.Fatal(err)
	}
	selectionID, _ := selectionResult.LastInsertId()
	sourceResult, err := repo.db.Exec(`INSERT INTO user_inbound_access_sources(username,server_id,inbound_tag,node_id,source_type,source_id,desired_state,starts_at) VALUES(?,?,?,?,? ,?,'active',?)`, "package-user", serverID, node.InboundTag, node.ID, ManagedSourceSelection, selectionID, now)
	if err != nil {
		t.Fatal(err)
	}
	selectionSourceID, _ := sourceResult.LastInsertId()
	if _, err := repo.db.Exec(`UPDATE user_node_selections SET access_source_id=? WHERE id=?`, selectionSourceID, selectionID); err != nil {
		t.Fatal(err)
	}
	forwardResult, err := repo.db.Exec(`INSERT INTO user_forward_rules(public_id,grant_id,username,name,target_type,target_node_id,target_host,target_port,network,source_cidrs,billing_mode_snapshot,traffic_multiplier_milli_snapshot) VALUES('fwd_auth_migration',?,'package-user','old','managed_node',?,'127.0.0.1',80,'tcp_udp','[]','both',1000)`, manualTunnel.ID, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	forwardID, _ := forwardResult.LastInsertId()
	if _, err := repo.db.Exec(`INSERT INTO user_forward_hops(forward_id,template_hop_id,position,server_id,resource_id,resource_tag,listen_port) VALUES(?,1,0,?,'res_auth_migration','tag_auth_migration',20080)`, forwardID, serverID); err != nil {
		t.Fatal(err)
	}

	packageID, err := repo.CreatePackage(ctx, Package{
		Name: "migration-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants:     []PackageServerGrant{{ServerID: serverID, BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone, ResetDay: 1}},
		ForwardingGrants: []PackageForwardingGrant{{TunnelID: tunnelID, MaxActiveForwards: 1, BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AssignPackageBundleToUser(ctx, "custom-user", packageID, now, now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`UPDATE users SET package_id=?,authorization_mode='custom' WHERE username='package-user'`, packageID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`UPDATE users SET package_id=NULL,authorization_mode='custom' WHERE username='custom-user'`); err != nil {
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
	packageUser, err := repo.GetUser(ctx, "package-user")
	if err != nil || packageUser.AuthorizationMode != AuthorizationModePackage {
		t.Fatalf("package user mode: user=%+v err=%v", packageUser, err)
	}
	customUser, err := repo.GetUser(ctx, "custom-user")
	if err != nil || customUser.AuthorizationMode != AuthorizationModeCustom {
		t.Fatalf("custom user mode: user=%+v err=%v", customUser, err)
	}
	manualDirect, err = repo.GetUserNodeGrant(ctx, manualDirect.Grant.ID)
	if err != nil || manualDirect.Source.DesiredState != ManagedDesiredInactive || manualDirect.Source.SuspendReason != ManagedSuspendAdminDisabled {
		t.Fatalf("manual direct tombstone: grant=%+v err=%v", manualDirect, err)
	}
	manualServer, err = repo.GetUserServerGrant(ctx, manualServer.ID)
	if err != nil || manualServer.Enabled {
		t.Fatalf("manual server tombstone: grant=%+v err=%v", manualServer, err)
	}
	manualTunnel, err = repo.GetUserTunnelGrant(ctx, manualTunnel.PublicID, "package-user")
	if err != nil || manualTunnel.Enabled {
		t.Fatalf("manual tunnel tombstone: grant=%+v err=%v", manualTunnel, err)
	}
	var selectionDesired int
	var selectionState, forwardState, forwardReason, hopState string
	var directGeneration, selectionGeneration, forwardGeneration, hopGeneration int64
	if err := repo.db.QueryRow(`SELECT desired_enabled FROM user_node_selections WHERE id=?`, selectionID).Scan(&selectionDesired); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT desired_state,generation FROM user_inbound_access_sources WHERE id=?`, manualDirect.Source.ID).Scan(&selectionState, &directGeneration); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT desired_state,generation FROM user_inbound_access_sources WHERE id=?`, selectionSourceID).Scan(&selectionState, &selectionGeneration); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT desired_state,suspend_reason,generation FROM user_forward_rules WHERE id=?`, forwardID).Scan(&forwardState, &forwardReason, &forwardGeneration); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT desired_state,generation FROM user_forward_hops WHERE forward_id=?`, forwardID).Scan(&hopState, &hopGeneration); err != nil {
		t.Fatal(err)
	}
	if selectionDesired != 0 || selectionState != ManagedDesiredInactive || forwardState != ForwardDesiredInactive || forwardReason != "grant_inactive" || hopState != ForwardDesiredInactive {
		t.Fatalf("children not deactivated: selection=%d/%s forward=%s/%s hop=%s", selectionDesired, selectionState, forwardState, forwardReason, hopState)
	}
	for _, username := range []string{"custom-user"} {
		serverGrants, err := repo.ListUserServerGrants(ctx, username)
		if err != nil || len(serverGrants) != 1 || serverGrants[0].Enabled {
			t.Fatalf("custom package server tombstone: grants=%+v err=%v", serverGrants, err)
		}
		tunnelGrants, err := repo.ListUserTunnelGrants(ctx, username)
		if err != nil || len(tunnelGrants) != 1 || tunnelGrants[0].Enabled {
			t.Fatalf("custom package tunnel tombstone: grants=%+v err=%v", tunnelGrants, err)
		}
	}

	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var gotDirect, gotSelection, gotForward, gotHop int64
	if err := repo.db.QueryRow(`SELECT generation FROM user_inbound_access_sources WHERE id=?`, manualDirect.Source.ID).Scan(&gotDirect); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT generation FROM user_inbound_access_sources WHERE id=?`, selectionSourceID).Scan(&gotSelection); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT generation FROM user_forward_rules WHERE id=?`, forwardID).Scan(&gotForward); err != nil {
		t.Fatal(err)
	}
	if err := repo.db.QueryRow(`SELECT generation FROM user_forward_hops WHERE forward_id=?`, forwardID).Scan(&gotHop); err != nil {
		t.Fatal(err)
	}
	if gotDirect != directGeneration || gotSelection != selectionGeneration || gotForward != forwardGeneration || gotHop != hopGeneration {
		t.Fatalf("migration was not idempotent: got=%d/%d/%d/%d want=%d/%d/%d/%d", gotDirect, gotSelection, gotForward, gotHop, directGeneration, selectionGeneration, forwardGeneration, hopGeneration)
	}
}
