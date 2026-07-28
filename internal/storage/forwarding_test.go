package storage

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"miaomiaowux/internal/tunnelidentity"
)

type forwardingStorageFixture struct {
	repo    *TrafficRepository
	ctx     context.Context
	tunnel  *TunnelTemplate
	grant   *UserTunnelGrant
	servers []RemoteServer
}

func newForwardingStorageFixture(t *testing.T) forwardingStorageFixture {
	t.Helper()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "forwarding.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	for _, username := range []string{"admin", "alice", "bob"} {
		role := RoleUser
		if username == "admin" {
			role = RoleAdmin
		}
		if err := repo.CreateUser(ctx, username, username+"@example.test", username, "hash", role, ""); err != nil {
			t.Fatalf("CreateUser(%s): %v", username, err)
		}
	}
	servers := make([]RemoteServer, 2)
	for i := range servers {
		servers[i] = RemoteServer{Name: "edge-" + string(rune('a'+i)), Token: "token-" + string(rune('a'+i)), Status: RemoteServerStatusConnected, IPAddress: "203.0.113." + string(rune('1'+i)), XrayMode: "embedded"}
		if err := repo.CreateRemoteServer(ctx, &servers[i]); err != nil {
			t.Fatalf("CreateRemoteServer: %v", err)
		}
		if _, err := repo.UpdateRemoteServerXrayStatus(ctx, servers[i].ID, true, "test"); err != nil {
			t.Fatalf("UpdateRemoteServerXrayStatus: %v", err)
		}
	}
	tunnel, err := repo.CreateTunnelTemplate(ctx, TunnelTemplate{
		Name: "HK to US", State: TunnelStateActive, Network: ForwardNetworkTCP, BillingMode: ManagedBillingBoth,
		TrafficMultiplierMilli: 2000, AllowManagedTarget: true, PortRangeStart: 39000, PortRangeEnd: 40000, CreatedBy: "admin",
		Hops: []TunnelTemplateHop{{ServerID: servers[0].ID}, {ServerID: servers[1].ID}},
	})
	if err != nil {
		t.Fatalf("CreateTunnelTemplate: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	grant, err := repo.CreateUserTunnelGrant(ctx, UserTunnelGrant{
		Username: "alice", TunnelID: tunnel.ID, Enabled: true, StartsAt: now.Add(-time.Hour),
		ExpiresAt: &expires, MaxActiveForwards: 100, BillingModeOverride: nil,
		AllowManagedTarget: true, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateUserTunnelGrant: %v", err)
	}
	return forwardingStorageFixture{repo: repo, ctx: ctx, tunnel: tunnel, grant: grant, servers: servers}
}

func (f forwardingStorageFixture) createForward(t *testing.T, name string) *UserForwardRule {
	t.Helper()
	forward, err := f.repo.CreateUserForward(f.ctx, CreateUserForwardInput{
		Username: "alice", Name: name, GrantPublicID: f.grant.PublicID,
		TargetNodeID: 42, TargetHost: "198.51.100.42", TargetPort: 443,
		SourceCIDRs: []string{"198.51.100.0/24"}, EffectiveExpiresAt: f.grant.ExpiresAt,
		Actor: "alice",
	})
	if err != nil {
		t.Fatalf("CreateUserForward: %v", err)
	}
	return forward
}

func TestForwardingStorageOwnershipPortsAndIdentity(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	first := fixture.createForward(t, "first")
	second := fixture.createForward(t, "second")
	if len(first.Hops) != 2 || len(second.Hops) != 2 {
		t.Fatalf("unexpected hops: first=%d second=%d", len(first.Hops), len(second.Hops))
	}
	for i, hop := range first.Hops {
		if hop.ListenPort < 1024 || hop.ListenPort > 65535 {
			t.Fatalf("hop %d port=%d outside dedicated pool", i, hop.ListenPort)
		}
		if hop.ResourceID == "" || hop.ResourceTag != tunnelidentity.Tag(hop.ResourceID) {
			t.Fatalf("hop identity mismatch: %+v", hop)
		}
		if hop.ListenPort == second.Hops[i].ListenPort {
			t.Fatalf("server %d reused port %d", hop.ServerID, hop.ListenPort)
		}
		if hop.ListenPort != first.AllocatedEntryPort || second.Hops[i].ListenPort != second.AllocatedEntryPort {
			t.Fatalf("route does not use one common port: first=%+v second=%+v", first.Hops, second.Hops)
		}
		if i < len(first.Hops)-1 && hop.NextPort != first.AllocatedEntryPort {
			t.Fatalf("hop %d next port=%d want common port %d", i, hop.NextPort, first.AllocatedEntryPort)
		}
	}
	if _, err := fixture.repo.GetUserForward(fixture.ctx, first.PublicID, "bob"); !errors.Is(err, ErrUserForwardNotFound) {
		t.Fatalf("cross-user lookup error=%v, want not found", err)
	}
	audits, err := fixture.repo.ListForwardAudit(fixture.ctx, "alice", "user_forward", first.ID, 10)
	if err != nil || len(audits) != 1 || audits[0].Action != "create" {
		t.Fatalf("unexpected audit: %+v err=%v", audits, err)
	}
}

func TestDeleteRemoteServerRejectsForwardingReferences(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	serverID := fixture.servers[0].ID
	if err := fixture.repo.ValidateRemoteServerDeletion(fixture.ctx, serverID); !errors.Is(err, ErrForwardingConflict) {
		t.Fatalf("ValidateRemoteServerDeletion error=%v, want forwarding conflict", err)
	}
	if err := fixture.repo.DeleteRemoteServer(fixture.ctx, serverID); !errors.Is(err, ErrForwardingConflict) {
		t.Fatalf("DeleteRemoteServer error=%v, want forwarding conflict", err)
	}
	if server, err := fixture.repo.GetRemoteServer(fixture.ctx, serverID); err != nil || server == nil {
		t.Fatalf("referenced server was deleted: server=%v err=%v", server, err)
	}
}

func TestForwardingConcurrentPortAllocation(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	const count = 12
	ports := make(chan int, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			forward, err := fixture.repo.CreateUserForward(fixture.ctx, CreateUserForwardInput{
				Username: "alice", Name: "concurrent-" + time.Now().Add(time.Duration(i)).Format("150405.000000000"),
				GrantPublicID: fixture.grant.PublicID, TargetNodeID: int64(100 + i),
				TargetHost: "198.51.100.42", TargetPort: 443, Actor: "alice",
			})
			if err != nil {
				errs <- err
				return
			}
			ports <- forward.AllocatedEntryPort
		}(i)
	}
	wg.Wait()
	close(errs)
	close(ports)
	for err := range errs {
		t.Errorf("concurrent CreateUserForward: %v", err)
	}
	seen := map[int]bool{}
	for port := range ports {
		if seen[port] {
			t.Fatalf("duplicate entry port %d", port)
		}
		seen[port] = true
	}
	if len(seen) != count {
		t.Fatalf("created=%d want=%d", len(seen), count)
	}
}

func TestForwardingTCPUDPExplicitCommonPortAndAtomicConflict(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	third := RemoteServer{
		Name: "edge-c", Token: "token-c", Status: RemoteServerStatusConnected,
		IPAddress: "203.0.113.3", XrayMode: "embedded",
	}
	if err := fixture.repo.CreateRemoteServer(fixture.ctx, &third); err != nil {
		t.Fatalf("CreateRemoteServer(third): %v", err)
	}
	if _, err := fixture.repo.UpdateRemoteServerXrayStatus(fixture.ctx, third.ID, true, "test"); err != nil {
		t.Fatalf("UpdateRemoteServerXrayStatus(third): %v", err)
	}

	tunnel, err := fixture.repo.CreateTunnelTemplate(fixture.ctx, TunnelTemplate{
		Name: "three-hop tcp+udp", State: TunnelStateActive, Network: ForwardNetworkTCPUDP,
		BillingMode: ManagedBillingBoth, TrafficMultiplierMilli: 1000,
		AllowManagedTarget: true, PortRangeStart: 2033, PortRangeEnd: 2034, CreatedBy: "admin",
		Hops: []TunnelTemplateHop{
			{ServerID: fixture.servers[0].ID},
			{ServerID: fixture.servers[1].ID},
			{ServerID: third.ID},
		},
	})
	if err != nil {
		t.Fatalf("CreateTunnelTemplate: %v", err)
	}
	var allocated int
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM server_port_allocations WHERE server_id IN (?,?,?)`, fixture.servers[0].ID, fixture.servers[1].ID, third.ID).Scan(&allocated); err != nil {
		t.Fatalf("count allocations after template creation: %v", err)
	}
	if allocated != 0 {
		t.Fatalf("template creation reserved %d ports", allocated)
	}

	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	grant, err := fixture.repo.CreateUserTunnelGrant(fixture.ctx, UserTunnelGrant{
		Username: "alice", TunnelID: tunnel.ID, Enabled: true, StartsAt: now.Add(-time.Hour),
		ExpiresAt: &expires, MaxActiveForwards: 10, AllowManagedTarget: true, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateUserTunnelGrant: %v", err)
	}

	create := func(name string, port int) (*UserForwardRule, error) {
		return fixture.repo.CreateUserForward(fixture.ctx, CreateUserForwardInput{
			Username: "alice", Name: name, GrantPublicID: grant.PublicID,
			TargetNodeID: 2033, TargetHost: "198.51.100.42", TargetPort: 8443,
			RequestedEntryPort: port, EffectiveExpiresAt: &expires, Actor: "alice",
		})
	}
	for i, conflictNetwork := range []string{ForwardNetworkTCP, ForwardNetworkUDP} {
		port := 2033 + i
		if _, err := fixture.repo.db.ExecContext(fixture.ctx, `INSERT INTO server_port_allocations(server_id,network,port,owner_type,owner_id) VALUES(?,?,?,'test',?)`, fixture.servers[1].ID, conflictNetwork, port, 900+i); err != nil {
			t.Fatalf("seed %s conflict: %v", conflictNetwork, err)
		}
		if _, err := create("conflict-"+conflictNetwork, port); !errors.Is(err, ErrForwardingConflict) {
			t.Fatalf("explicit port with %s conflict error=%v, want conflict", conflictNetwork, err)
		}
		var rules int
		if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id=?`, grant.ID).Scan(&rules); err != nil {
			t.Fatalf("count rolled-back forwards: %v", err)
		}
		if rules != 0 {
			t.Fatalf("explicit conflict left %d partial forward rules", rules)
		}
		if _, err := fixture.repo.db.ExecContext(fixture.ctx, `DELETE FROM server_port_allocations WHERE owner_type='test' AND owner_id=?`, 900+i); err != nil {
			t.Fatalf("remove seeded conflict: %v", err)
		}
	}

	forward, err := create("same-2033", 2033)
	if err != nil {
		t.Fatalf("CreateUserForward: %v", err)
	}
	if forward.Network != ForwardNetworkTCPUDP || forward.RequestedEntryPort != 2033 || forward.AllocatedEntryPort != 2033 || len(forward.Hops) != 3 {
		t.Fatalf("unexpected explicit forward: %+v", forward)
	}
	for i, hop := range forward.Hops {
		if hop.ListenPort != 2033 {
			t.Fatalf("hop %d listen port=%d want 2033", i, hop.ListenPort)
		}
		if i < len(forward.Hops)-1 && hop.NextPort != 2033 {
			t.Fatalf("hop %d next port=%d want 2033", i, hop.NextPort)
		}
	}
	protocolCounts := map[string]int{}
	rows, err := fixture.repo.db.QueryContext(fixture.ctx, `SELECT network,COUNT(*) FROM server_port_allocations WHERE owner_type='forward_hop' AND owner_id IN (SELECT id FROM user_forward_hops WHERE forward_id=?) GROUP BY network`, forward.ID)
	if err != nil {
		t.Fatalf("query protocol allocations: %v", err)
	}
	for rows.Next() {
		var network string
		var count int
		if err := rows.Scan(&network, &count); err != nil {
			rows.Close()
			t.Fatalf("scan protocol allocation: %v", err)
		}
		protocolCounts[network] = count
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close protocol allocations: %v", err)
	}
	if protocolCounts[ForwardNetworkTCP] != 3 || protocolCounts[ForwardNetworkUDP] != 3 {
		t.Fatalf("protocol allocations=%v, want tcp=3 udp=3", protocolCounts)
	}
	if _, err := fixture.repo.ReallocateUserForwardPorts(fixture.ctx, forward.PublicID, "alice"); !errors.Is(err, ErrForwardingConflict) {
		t.Fatalf("explicit forward reallocation error=%v, want conflict", err)
	}
	if _, err := create("duplicate-2033", 2033); !errors.Is(err, ErrForwardingConflict) {
		t.Fatalf("duplicate explicit port error=%v, want conflict", err)
	}
	var rules, reservations int
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id=?`, grant.ID).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM server_port_allocations WHERE owner_type='forward_hop' AND owner_id IN (SELECT id FROM user_forward_hops WHERE forward_id=?)`, forward.ID).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if rules != 1 || reservations != 6 {
		t.Fatalf("conflict was not atomic: rules=%d reservations=%d", rules, reservations)
	}
}

func TestForwardingConstraintMigrationPreservesLegacyTCPData(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	legacyForward := fixture.createForward(t, "legacy-tcp")
	legacyPorts := []int{39001, 39002}
	if len(legacyForward.Hops) != len(legacyPorts) {
		t.Fatalf("legacy hops=%d want=%d", len(legacyForward.Hops), len(legacyPorts))
	}
	tx, err := fixture.repo.db.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(fixture.ctx, `DELETE FROM server_port_allocations WHERE owner_type='forward_hop' AND owner_id IN (SELECT id FROM user_forward_hops WHERE forward_id=?)`, legacyForward.ID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	for i, hop := range legacyForward.Hops {
		nextPort := legacyForward.TargetPort
		if i+1 < len(legacyForward.Hops) {
			nextPort = legacyPorts[i+1]
		}
		if _, err := tx.ExecContext(fixture.ctx, `UPDATE user_forward_hops SET listen_port=?,next_port=?,observed_state='active',applied_generation=generation WHERE id=?`, legacyPorts[i], nextPort, hop.ID); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(fixture.ctx, `INSERT INTO server_port_allocations(server_id,network,port,owner_type,owner_id) VALUES(?,'tcp',?,'forward_hop',?)`, hop.ServerID, legacyPorts[i], hop.ID); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(fixture.ctx, `UPDATE user_forward_rules SET allocated_entry_port=?,observed_state='active',applied_generation=generation WHERE id=?`, legacyPorts[0], legacyForward.ID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	legacyGeneration := legacyForward.Generation

	_, err = fixture.repo.db.ExecContext(fixture.ctx, `
DROP TABLE IF EXISTS tunnel_templates_legacy;
CREATE TABLE tunnel_templates_legacy (
 id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','draining','suspended')),
 network TEXT NOT NULL DEFAULT 'tcp' CHECK(network = 'tcp'),
 billing_mode TEXT NOT NULL DEFAULT 'both' CHECK(billing_mode IN ('download','both')),
 traffic_multiplier_milli INTEGER NOT NULL DEFAULT 1000 CHECK(traffic_multiplier_milli > 0),
 max_total_forwards INTEGER NOT NULL DEFAULT 0 CHECK(max_total_forwards >= 0),
 allow_managed_target INTEGER NOT NULL DEFAULT 1 CHECK(allow_managed_target IN (0,1)),
 allow_custom_public_target INTEGER NOT NULL DEFAULT 0 CHECK(allow_custom_public_target = 0),
 port_range_start INTEGER NOT NULL DEFAULT 39000 CHECK(port_range_start BETWEEN 39000 AND 40000),
 port_range_end INTEGER NOT NULL DEFAULT 40000 CHECK(port_range_end BETWEEN 39000 AND 40000),
 version INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(port_range_start <= port_range_end)
);
INSERT INTO tunnel_templates_legacy(id,public_id,name,description,state,network,billing_mode,traffic_multiplier_milli,max_total_forwards,allow_managed_target,allow_custom_public_target,port_range_start,port_range_end,version,created_by,created_at,updated_at)
SELECT id,public_id,name,description,state,CASE WHEN network='tcp_udp' THEN 'tcp' ELSE network END,billing_mode,traffic_multiplier_milli,max_total_forwards,allow_managed_target,allow_custom_public_target,port_range_start,port_range_end,version,created_by,created_at,updated_at FROM tunnel_templates;
DROP TABLE tunnel_templates;
ALTER TABLE tunnel_templates_legacy RENAME TO tunnel_templates;

DROP TABLE IF EXISTS user_forward_rules_legacy;
CREATE TABLE user_forward_rules_legacy AS
SELECT id,public_id,grant_id,username,name,target_type,target_node_id,target_host,target_port,CASE WHEN network='tcp_udp' THEN 'tcp' ELSE network END AS network,source_cidrs,allocated_entry_port,desired_state,observed_state,suspend_reason,generation,applied_generation,effective_expires_at,billing_mode_snapshot,traffic_multiplier_milli_snapshot,last_error_code,last_error_detail,created_at,updated_at FROM user_forward_rules;
DROP TABLE user_forward_rules;
ALTER TABLE user_forward_rules_legacy RENAME TO user_forward_rules;
`)
	if err != nil {
		t.Fatalf("install legacy forwarding schema: %v", err)
	}

	if err := fixture.repo.migrateForwarding(); err != nil {
		t.Fatalf("migrateForwarding: %v", err)
	}
	if err := fixture.repo.migrateForwarding(); err != nil {
		t.Fatalf("migrateForwarding idempotent rerun: %v", err)
	}

	tunnel, err := fixture.repo.GetTunnelTemplate(fixture.ctx, fixture.tunnel.PublicID)
	if err != nil {
		t.Fatalf("GetTunnelTemplate after migration: %v", err)
	}
	if tunnel.Network != ForwardNetworkTCPUDP || tunnel.PortRangeStart != 39000 || tunnel.PortRangeEnd != 40000 {
		t.Fatalf("legacy tunnel changed during migration: %+v", tunnel)
	}
	forward, err := fixture.repo.GetUserForward(fixture.ctx, legacyForward.PublicID, "alice")
	if err != nil {
		t.Fatalf("GetUserForward after migration: %v", err)
	}
	if forward.Network != ForwardNetworkTCPUDP || forward.RequestedEntryPort != 0 || forward.AllocatedEntryPort != legacyPorts[0] {
		t.Fatalf("legacy forward changed during migration: %+v", forward)
	}
	if forward.Generation != legacyGeneration+1 || forward.AppliedGeneration != 0 || forward.ObservedState != ForwardObservedPending {
		t.Fatalf("legacy forward was not queued for tcp_udp apply: %+v", forward)
	}
	for i, hop := range forward.Hops {
		if hop.ListenPort != legacyPorts[i] || hop.Generation != legacyForward.Hops[i].Generation+1 || hop.AppliedGeneration != 0 || hop.ObservedState != ForwardObservedPending {
			t.Fatalf("legacy hop %d migration mismatch: %+v", i, hop)
		}
	}
	var allocationCount int
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM server_port_allocations WHERE owner_type='forward_hop' AND owner_id IN (SELECT id FROM user_forward_hops WHERE forward_id=?)`, forward.ID).Scan(&allocationCount); err != nil {
		t.Fatalf("count migrated allocations: %v", err)
	}
	if allocationCount != len(forward.Hops)*2 {
		t.Fatalf("migrated allocation count=%d want=%d", allocationCount, len(forward.Hops)*2)
	}
	var requestedColumn, templateConstraint, forwardConstraint int
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM pragma_table_info('user_forward_rules') WHERE name='requested_entry_port'`).Scan(&requestedColumn); err != nil {
		t.Fatalf("inspect requested_entry_port: %v", err)
	}
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT instr(lower(sql),'tcp_udp')>0 AND instr(lower(sql),'between 1024 and 65535')>0 FROM sqlite_master WHERE type='table' AND name='tunnel_templates'`).Scan(&templateConstraint); err != nil {
		t.Fatalf("inspect tunnel template constraints: %v", err)
	}
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT instr(lower(sql),'tcp_udp')>0 AND instr(lower(sql),'requested_entry_port')>0 FROM sqlite_master WHERE type='table' AND name='user_forward_rules'`).Scan(&forwardConstraint); err != nil {
		t.Fatalf("inspect forward constraints: %v", err)
	}
	if requestedColumn != 1 || templateConstraint != 1 || forwardConstraint != 1 {
		t.Fatalf("migration schema incomplete: requested=%d template=%d forward=%d", requestedColumn, templateConstraint, forwardConstraint)
	}

	created, err := fixture.repo.CreateTunnelTemplate(fixture.ctx, TunnelTemplate{
		Name: "post-migration 2033", Network: ForwardNetworkTCPUDP,
		BillingMode: ManagedBillingBoth, TrafficMultiplierMilli: 1000,
		PortRangeStart: 2033, PortRangeEnd: 2033, CreatedBy: "admin",
		Hops: []TunnelTemplateHop{{ServerID: fixture.servers[0].ID}, {ServerID: fixture.servers[1].ID}},
	})
	if err != nil {
		t.Fatalf("create tcp_udp template after migration: %v", err)
	}
	if created.Network != ForwardNetworkTCPUDP || created.PortRangeStart != 2033 || created.PortRangeEnd != 2033 {
		t.Fatalf("unexpected post-migration template: %+v", created)
	}
}

func TestForwardingMigrationSkipsConflictingUDPAllocation(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	forward := fixture.createForward(t, "legacy-conflict")
	hop := forward.Hops[0]
	if _, err := fixture.repo.db.ExecContext(fixture.ctx, `DELETE FROM server_port_allocations WHERE network='udp' AND owner_type='forward_hop' AND owner_id IN (SELECT id FROM user_forward_hops WHERE forward_id=?)`, forward.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.db.ExecContext(fixture.ctx, `UPDATE user_forward_rules SET network='tcp',observed_state='active',applied_generation=generation WHERE id=?`, forward.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.db.ExecContext(fixture.ctx, `UPDATE user_forward_hops SET observed_state='active',applied_generation=generation WHERE forward_id=?`, forward.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.db.ExecContext(fixture.ctx, `INSERT INTO server_port_allocations(server_id,network,port,owner_type,owner_id) VALUES(?,'udp',?,'test',991)`, hop.ServerID, hop.ListenPort); err != nil {
		t.Fatal(err)
	}

	if err := fixture.repo.migrateForwardingChecks(); err != nil {
		t.Fatalf("migration must not fail on conflicting UDP allocation: %v", err)
	}
	migrated, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Network != ForwardNetworkTCPUDP || migrated.ObservedState != ForwardObservedPending || migrated.AppliedGeneration != 0 || migrated.Generation != forward.Generation+1 {
		t.Fatalf("conflicted legacy forward was not queued for reconciliation: %+v", migrated)
	}
	var conflictingOwner, hopUDP int
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM server_port_allocations WHERE server_id=? AND network='udp' AND port=? AND owner_type='test' AND owner_id=991`, hop.ServerID, hop.ListenPort).Scan(&conflictingOwner); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM server_port_allocations WHERE network='udp' AND owner_type='forward_hop' AND owner_id=?`, hop.ID).Scan(&hopUDP); err != nil {
		t.Fatal(err)
	}
	if conflictingOwner != 1 || hopUDP != 0 {
		t.Fatalf("unexpected UDP allocations: conflicting_owner=%d hop_udp=%d", conflictingOwner, hopUDP)
	}
}

func TestForwardingMigrationSerializesConcurrentCanonicalization(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	forward := fixture.createForward(t, "concurrent-migration")
	if _, err := fixture.repo.db.ExecContext(fixture.ctx, `UPDATE user_forward_rules SET network='tcp',observed_state='active',applied_generation=generation WHERE id=?`, forward.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.db.ExecContext(fixture.ctx, `UPDATE user_forward_hops SET observed_state='active',applied_generation=generation WHERE forward_id=?`, forward.ID); err != nil {
		t.Fatal(err)
	}

	blocker, err := fixture.repo.db.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(fixture.ctx, `UPDATE users SET updated_at=updated_at WHERE username='bob'`); err != nil {
		_ = blocker.Rollback()
		t.Fatal(err)
	}

	started := make(chan struct{}, 2)
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			started <- struct{}{}
			done <- fixture.repo.migrateForwardingChecks()
		}()
	}
	<-started
	<-started
	// Both migrations are now contending behind the existing SQLite writer.
	// Releasing it makes BEGIN IMMEDIATE serialize their schema reads and writes.
	time.Sleep(50 * time.Millisecond)
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent migration %d: %v", i, err)
		}
	}

	migrated, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Network != ForwardNetworkTCPUDP || migrated.Generation != forward.Generation+1 || migrated.AppliedGeneration != 0 || migrated.ObservedState != ForwardObservedPending {
		t.Fatalf("concurrent migration was not idempotent: before=%+v after=%+v", forward, migrated)
	}
	for i, hop := range migrated.Hops {
		if hop.Generation != forward.Hops[i].Generation+1 || hop.AppliedGeneration != 0 || hop.ObservedState != ForwardObservedPending {
			t.Fatalf("hop %d was canonicalized more than once: before=%+v after=%+v", i, forward.Hops[i], hop)
		}
	}
}

func TestForwardingReallocationSerializesWithDesiredStateChange(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	forward := fixture.createForward(t, "reallocate-delete-race")

	blocker, err := fixture.repo.db.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(fixture.ctx, `UPDATE user_forward_rules SET desired_state='deleted' WHERE id=?`, forward.ID); err != nil {
		_ = blocker.Rollback()
		t.Fatal(err)
	}

	reallocateDone := make(chan error, 1)
	go func() {
		_, reallocateErr := fixture.repo.ReallocateUserForwardPorts(context.Background(), forward.PublicID, "alice")
		reallocateDone <- reallocateErr
	}()
	waitForManagedNodeLease(t, fixture.repo, func() { _ = blocker.Rollback() })

	desiredDone := make(chan error, 1)
	go func() {
		_, desiredErr := fixture.repo.SetUserForwardDesired(context.Background(), forward.PublicID, "alice", ForwardDesiredDeleted, ForwardObservedCleanupPending, "none", "alice")
		desiredDone <- desiredErr
	}()
	select {
	case err := <-desiredDone:
		_ = blocker.Rollback()
		t.Fatalf("desired-state update bypassed reallocation lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-reallocateDone; !errors.Is(err, ErrForwardingConflict) {
		t.Fatalf("reallocation error=%v want=%v", err, ErrForwardingConflict)
	}
	if err := <-desiredDone; err != nil {
		t.Fatalf("SetUserForwardDesired: %v", err)
	}

	after, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if after.AllocatedEntryPort != forward.AllocatedEntryPort || len(after.Hops) != len(forward.Hops) {
		t.Fatalf("conflicted reallocation changed route: before=%+v after=%+v", forward, after)
	}
	for i, hop := range after.Hops {
		if hop.ListenPort != forward.Hops[i].ListenPort || hop.ResourceID != forward.Hops[i].ResourceID || hop.ResourceTag != forward.Hops[i].ResourceTag {
			t.Fatalf("conflicted reallocation changed hop %d: before=%+v after=%+v", i, forward.Hops[i], hop)
		}
	}
	var allocations int
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*) FROM server_port_allocations WHERE owner_type='forward_hop' AND owner_id IN (SELECT id FROM user_forward_hops WHERE forward_id=?)`, forward.ID).Scan(&allocations); err != nil {
		t.Fatal(err)
	}
	if allocations != len(forward.Hops)*2 {
		t.Fatalf("conflicted reallocation changed allocations: got=%d want=%d", allocations, len(forward.Hops)*2)
	}
}

func TestForwardingMutationsSharePortAllocationLease(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context, forwardingStorageFixture, *UserForwardRule) error
	}{
		{
			name: "reallocate",
			run: func(ctx context.Context, fixture forwardingStorageFixture, forward *UserForwardRule) error {
				_, err := fixture.repo.ReallocateUserForwardPorts(ctx, forward.PublicID, "alice")
				return err
			},
		},
		{
			name: "system suspend",
			run: func(ctx context.Context, fixture forwardingStorageFixture, forward *UserForwardRule) error {
				_, err := fixture.repo.PrepareUserForwardSystemSuspend(ctx, forward.PublicID, "alice", "quota_exceeded")
				return err
			},
		},
		{
			name: "system apply",
			run: func(ctx context.Context, fixture forwardingStorageFixture, forward *UserForwardRule) error {
				_, err := fixture.repo.PrepareUserForwardSystemApply(ctx, forward.PublicID, "alice")
				return err
			},
		},
		{
			name: "desired state",
			run: func(ctx context.Context, fixture forwardingStorageFixture, forward *UserForwardRule) error {
				_, err := fixture.repo.SetUserForwardDesired(ctx, forward.PublicID, "alice", ForwardDesiredInactive, ForwardObservedProvisioning, "user_disabled", "alice")
				return err
			},
		},
		{
			name: "finalize delete",
			run: func(ctx context.Context, fixture forwardingStorageFixture, forward *UserForwardRule) error {
				return fixture.repo.FinalizeUserForwardDelete(ctx, forward.ID)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newForwardingStorageFixture(t)
			forward := fixture.createForward(t, test.name)
			fixture.repo.managedNodeMu.Lock()
			locked := true
			defer func() {
				if locked {
					fixture.repo.managedNodeMu.Unlock()
				}
			}()

			done := make(chan error, 1)
			go func() {
				done <- test.run(context.Background(), fixture, forward)
			}()
			select {
			case err := <-done:
				fixture.repo.managedNodeMu.Unlock()
				locked = false
				t.Fatalf("operation bypassed port-allocation lease: %v", err)
			case <-time.After(50 * time.Millisecond):
			}

			fixture.repo.managedNodeMu.Unlock()
			locked = false
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("operation failed after lease release: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("operation did not finish after port-allocation lease release")
			}
		})
	}
}

func TestForwardingGrantExpiryBumpsGenerationAndUsageBillsEntryOnce(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	forward := fixture.createForward(t, "metered")
	entry := forward.Hops[0]
	middle := forward.Hops[1]
	if err := fixture.repo.UpsertNodeTraffic(fixture.ctx, entry.ServerID, entry.ResourceTag, "inbound", 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.UpsertNodeTraffic(fixture.ctx, entry.ServerID, entry.ResourceTag, "inbound", 100, 200, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.UpsertNodeTraffic(fixture.ctx, middle.ServerID, middle.ResourceTag, "inbound", 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.UpsertNodeTraffic(fixture.ctx, middle.ServerID, middle.ResourceTag, "inbound", 10_000, 20_000, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.SyncUserForwardUsage(fixture.ctx); err != nil {
		t.Fatalf("SyncUserForwardUsage: %v", err)
	}
	usage, err := fixture.repo.GetUserForwardUsage(fixture.ctx, forward.ID)
	if err != nil || usage.UplinkBytes != 100 || usage.DownlinkBytes != 200 {
		t.Fatalf("entry usage=%+v err=%v", usage, err)
	}
	grants, err := fixture.repo.ListUserTunnelGrants(fixture.ctx, "alice")
	if err != nil || len(grants) != 1 || grants[0].UsedBytes != 600 {
		t.Fatalf("billed grant=%+v err=%v", grants, err)
	}
	download := ManagedBillingDownload
	modeInput := *fixture.grant
	modeInput.BillingModeOverride = &download
	modeGrant, err := fixture.repo.UpdateUserTunnelGrant(fixture.ctx, fixture.grant.PublicID, "alice", modeInput, fixture.grant.Version, "admin")
	if err != nil {
		t.Fatalf("set download billing: %v", err)
	}
	second := fixture.createForward(t, "download-only")
	if err := fixture.repo.UpsertNodeTraffic(fixture.ctx, second.Hops[0].ServerID, second.Hops[0].ResourceTag, "inbound", 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.UpsertNodeTraffic(fixture.ctx, second.Hops[0].ServerID, second.Hops[0].ResourceTag, "inbound", 100, 50, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.SyncUserForwardUsage(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	grants, err = fixture.repo.ListUserTunnelGrants(fixture.ctx, "alice")
	if err != nil || len(grants) != 1 || grants[0].UsedBytes != 700 {
		t.Fatalf("mixed both/download 2x billing=%+v err=%v", grants, err)
	}
	beforeExpiry, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	newExpiry := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
	updatedInput := *modeGrant
	updatedInput.ExpiresAt = &newExpiry
	updated, err := fixture.repo.UpdateUserTunnelGrant(fixture.ctx, fixture.grant.PublicID, "alice", updatedInput, modeGrant.Version, "admin")
	if err != nil {
		t.Fatalf("UpdateUserTunnelGrant: %v", err)
	}
	if updated.ExpiresAt == nil || !updated.ExpiresAt.Equal(newExpiry) {
		t.Fatalf("grant expiry=%v want=%v", updated.ExpiresAt, newExpiry)
	}
	refreshed, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Generation != beforeExpiry.Generation+1 || refreshed.Hops[0].Generation != beforeExpiry.Hops[0].Generation+1 {
		t.Fatalf("generation not bumped: forward=%d hop=%d", refreshed.Generation, refreshed.Hops[0].Generation)
	}
	if refreshed.EffectiveExpiresAt == nil || !refreshed.EffectiveExpiresAt.Equal(newExpiry) {
		t.Fatalf("effective expiry=%v want=%v", refreshed.EffectiveExpiresAt, newExpiry)
	}
}

func TestForwardingSeedsEntryTrafficBaselineBeforeFirstCollectorSample(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	forward := fixture.createForward(t, "first-sample")
	entry := forward.Hops[0]

	// This is deliberately the collector's first non-zero sample. Forward
	// creation must already have inserted the zero baseline for this tag.
	if err := fixture.repo.UpsertNodeTraffic(fixture.ctx, entry.ServerID, entry.ResourceTag, "inbound", 100, 200, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.SyncUserForwardUsage(fixture.ctx); err != nil {
		t.Fatalf("SyncUserForwardUsage: %v", err)
	}
	usage, err := fixture.repo.GetUserForwardUsage(fixture.ctx, forward.ID)
	if err != nil || usage.UplinkBytes != 100 || usage.DownlinkBytes != 200 {
		t.Fatalf("first collector sample was not billed: usage=%+v err=%v", usage, err)
	}
	grants, err := fixture.repo.ListUserTunnelGrants(fixture.ctx, "alice")
	if err != nil || len(grants) != 1 || grants[0].UsedBytes != 600 {
		t.Fatalf("first collector sample grant billing=%+v err=%v", grants, err)
	}
}

func TestForwardingDeleteArchivesUsageAndRecreateCannotResetQuota(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	grantInput := *fixture.grant
	grantInput.TrafficLimitBytes = 1200
	grant, err := fixture.repo.UpdateUserTunnelGrant(fixture.ctx, fixture.grant.PublicID, "alice", grantInput, fixture.grant.Version, "admin")
	if err != nil {
		t.Fatalf("set traffic limit: %v", err)
	}

	recordAndDelete := func(name string) {
		t.Helper()
		forward := fixture.createForward(t, name)
		entry := forward.Hops[0]
		if err := fixture.repo.UpsertNodeTraffic(fixture.ctx, entry.ServerID, entry.ResourceTag, "inbound", 100, 200, false); err != nil {
			t.Fatal(err)
		}
		if err := fixture.repo.SyncUserForwardUsage(fixture.ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.repo.SetUserForwardDesired(fixture.ctx, forward.PublicID, "alice", ForwardDesiredDeleted, ForwardObservedCleanupPending, "none", "alice"); err != nil {
			t.Fatal(err)
		}
		if err := fixture.repo.FinalizeUserForwardDelete(fixture.ctx, forward.ID); err != nil {
			t.Fatal(err)
		}
		if err := fixture.repo.FinalizeUserForwardDelete(fixture.ctx, forward.ID); err != nil {
			t.Fatalf("repeated finalization must be idempotent: %v", err)
		}
	}

	recordAndDelete("first")
	grants, err := fixture.repo.ListUserTunnelGrants(fixture.ctx, "alice")
	if err != nil || len(grants) != 1 || grants[0].UsedBytes != 600 {
		t.Fatalf("archived usage after first delete=%+v err=%v", grants, err)
	}
	recordAndDelete("replacement")
	grants, err = fixture.repo.ListUserTunnelGrants(fixture.ctx, "alice")
	if err != nil || len(grants) != 1 || grants[0].UsedBytes != 1200 || grants[0].State != "over_limit" {
		t.Fatalf("archived usage after recreate=%+v err=%v", grants, err)
	}
	_, err = fixture.repo.CreateUserForward(fixture.ctx, CreateUserForwardInput{
		Username: "alice", Name: "quota-reset-attempt", GrantPublicID: grant.PublicID,
		TargetNodeID: 42, TargetHost: "198.51.100.42", TargetPort: 443, Actor: "alice",
	})
	if !errors.Is(err, ErrForwardingForbidden) {
		t.Fatalf("create after exhausted archived quota error=%v, want forbidden", err)
	}
}
