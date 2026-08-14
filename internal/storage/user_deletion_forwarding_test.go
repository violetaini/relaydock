package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestTunnelGrantCreationSerializesWithUserDeletion(t *testing.T) {
	fixture := newForwardingStorageFixture(t)

	// Hold SQLite's writer lock so CreateUserTunnelGrant remains inside the
	// provisioning lease long enough to deterministically start deletion behind
	// it. WAL still permits the lease's user/tombstone reads.
	blocker, err := fixture.repo.db.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatalf("begin write blocker: %v", err)
	}
	if _, err := blocker.ExecContext(fixture.ctx, `UPDATE users SET updated_at=updated_at WHERE username='bob'`); err != nil {
		_ = blocker.Rollback()
		t.Fatalf("acquire write blocker: %v", err)
	}

	grantInput := UserTunnelGrant{
		Username: "bob", TunnelID: fixture.tunnel.ID, Enabled: true,
		StartsAt: time.Now().UTC().Add(-time.Hour), MaxActiveForwards: 1,
		BillingModeOverride: forwardingBillingModePtr(ManagedBillingBoth),
		AllowManagedTarget:  true, CreatedBy: "admin",
	}
	grantDone := make(chan struct {
		grant *UserTunnelGrant
		err   error
	}, 1)
	go func() {
		grant, createErr := fixture.repo.CreateUserTunnelGrant(context.Background(), grantInput)
		grantDone <- struct {
			grant *UserTunnelGrant
			err   error
		}{grant: grant, err: createErr}
	}()

	waitForUserAuthorizationLease(t, fixture.repo, "bob", func() { _ = blocker.Rollback() })

	deletionDone := make(chan error, 1)
	go func() {
		_, deleteErr := fixture.repo.PrepareUserDeletion(context.Background(), "bob", "admin")
		deletionDone <- deleteErr
	}()
	select {
	case err := <-deletionDone:
		_ = blocker.Rollback()
		t.Fatalf("deletion bypassed grant provisioning lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := blocker.Commit(); err != nil {
		t.Fatalf("release write blocker: %v", err)
	}

	created := <-grantDone
	if created.err != nil {
		t.Fatalf("CreateUserTunnelGrant: %v", created.err)
	}
	if err := <-deletionDone; err != nil {
		t.Fatalf("PrepareUserDeletion: %v", err)
	}
	grant, err := fixture.repo.GetUserTunnelGrant(fixture.ctx, created.grant.PublicID, "bob")
	if err != nil || grant.Enabled {
		t.Fatalf("deletion did not disable concurrent grant: grant=%+v err=%v", grant, err)
	}

	update := *grant
	update.Enabled = true
	if _, err := fixture.repo.UpdateUserTunnelGrant(fixture.ctx, grant.PublicID, "bob", update, grant.Version, "admin"); !errors.Is(err, ErrUserDeletionPending) {
		t.Fatalf("grant update during deletion error=%v want=%v", err, ErrUserDeletionPending)
	}
	if _, err := fixture.repo.CreateUserTunnelGrant(fixture.ctx, grantInput); !errors.Is(err, ErrUserDeletionPending) {
		t.Fatalf("grant create during deletion error=%v want=%v", err, ErrUserDeletionPending)
	}
}

func waitForUserAuthorizationLease(t *testing.T, repo *TrafficRepository, username string, cleanup func()) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		value, ok := repo.userAuthorizationLeases.Load(username)
		if ok {
			lease := value.(*sync.Mutex)
			if !lease.TryLock() {
				return
			}
			lease.Unlock()
		}
		if time.Now().After(deadline) {
			cleanup()
			t.Fatal("operation did not acquire user authorization lease")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTunnelGrantDeleteCannotOrphanConcurrentForward(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	blocker, err := fixture.repo.db.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatalf("begin write blocker: %v", err)
	}
	if _, err := blocker.ExecContext(fixture.ctx, `UPDATE users SET updated_at=updated_at WHERE username='bob'`); err != nil {
		_ = blocker.Rollback()
		t.Fatalf("acquire write blocker: %v", err)
	}

	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- fixture.repo.DeleteUserTunnelGrant(context.Background(), fixture.grant.PublicID, "alice", "admin")
	}()
	waitForManagedNodeLease(t, fixture.repo, func() { _ = blocker.Rollback() })

	createDone := make(chan error, 1)
	go func() {
		_, createErr := fixture.repo.CreateUserForward(context.Background(), CreateUserForwardInput{
			Username: "alice", Name: "must-not-orphan", GrantPublicID: fixture.grant.PublicID,
			TargetNodeID: 42, TargetHost: "198.51.100.42", TargetPort: 443, Actor: "alice",
		})
		createDone <- createErr
	}()
	select {
	case err := <-createDone:
		_ = blocker.Rollback()
		t.Fatalf("forward creation bypassed grant deletion lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := blocker.Commit(); err != nil {
		t.Fatalf("release write blocker: %v", err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatalf("DeleteUserTunnelGrant: %v", err)
	}
	if err := <-createDone; !errors.Is(err, ErrTunnelGrantNotFound) {
		t.Fatalf("concurrent forward error=%v want=%v", err, ErrTunnelGrantNotFound)
	}
	var forwards int
	if err := fixture.repo.db.QueryRowContext(fixture.ctx,
		`SELECT COUNT(*) FROM user_forward_rules WHERE username='alice'`).Scan(&forwards); err != nil {
		t.Fatalf("count orphan forwards: %v", err)
	}
	if forwards != 0 {
		t.Fatalf("grant deletion left %d orphan forwards", forwards)
	}
}

func waitForManagedNodeLease(t *testing.T, repo *TrafficRepository, cleanup func()) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if repo.managedNodeMu.TryLock() {
			repo.managedNodeMu.Unlock()
			if time.Now().After(deadline) {
				cleanup()
				t.Fatal("operation did not acquire managed-node lease")
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		return
	}
}

func TestUserDeletionWaitsForForwardCleanupAndRetainsPorts(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	forward := fixture.createForward(t, "delete-me")

	for _, hop := range forward.Hops {
		if err := fixture.repo.MarkUserForwardHop(fixture.ctx, hop.ID, ForwardObservedActive, true, ""); err != nil {
			t.Fatalf("mark hop active: %v", err)
		}
	}
	if err := fixture.repo.MarkUserForwardDeployment(fixture.ctx, forward.ID, ForwardObservedActive, true, "", ""); err != nil {
		t.Fatalf("mark forward active: %v", err)
	}
	active, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatalf("GetUserForward(active): %v", err)
	}

	if _, err := fixture.repo.PrepareUserDeletion(fixture.ctx, "alice", "admin"); err != nil {
		t.Fatalf("PrepareUserDeletion: %v", err)
	}
	prepared, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatalf("GetUserForward(prepared): %v", err)
	}
	if prepared.DesiredState != ForwardDesiredDeleted || prepared.ObservedState != ForwardObservedCleanupPending {
		t.Fatalf("forward was not queued for cleanup: %+v", prepared)
	}
	if prepared.Generation != active.Generation+1 {
		t.Fatalf("forward generation=%d want=%d", prepared.Generation, active.Generation+1)
	}
	for i, hop := range prepared.Hops {
		if hop.DesiredState != ForwardDesiredDeleted || hop.Generation != active.Hops[i].Generation+1 {
			t.Fatalf("hop %d was not queued once: before=%+v after=%+v", i, active.Hops[i], hop)
		}
	}
	grant, err := fixture.repo.GetUserTunnelGrant(fixture.ctx, fixture.grant.PublicID, "alice")
	if err != nil || grant.Enabled {
		t.Fatalf("tunnel grant remained enabled: grant=%+v err=%v", grant, err)
	}
	assertUserForwardAllocationCount(t, fixture, forward, len(forward.Hops)*2)

	// Preparation is repeatable while a Guard is offline: it neither releases
	// ports nor makes each retry use a different remote generation.
	if _, err := fixture.repo.PrepareUserDeletion(fixture.ctx, "alice", "admin"); err != nil {
		t.Fatalf("repeat PrepareUserDeletion: %v", err)
	}
	repeated, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatalf("GetUserForward(repeated): %v", err)
	}
	if repeated.Generation != prepared.Generation || repeated.Hops[0].Generation != prepared.Hops[0].Generation {
		t.Fatalf("repeat preparation changed cleanup generation: first=%+v second=%+v", prepared, repeated)
	}
	assertUserForwardAllocationCount(t, fixture, forward, len(forward.Hops)*2)

	ready, err := fixture.repo.IsUserDeletionReady(fixture.ctx, "alice")
	if err != nil || ready {
		t.Fatalf("unacknowledged forward cleanup reported ready: ready=%v err=%v", ready, err)
	}
	if err := fixture.repo.FinalizeUserDeletion(fixture.ctx, "alice", "admin"); !errors.Is(err, ErrUserDeletionPending) {
		t.Fatalf("unsafe finalization error=%v want=%v", err, ErrUserDeletionPending)
	}

	if err := fixture.repo.MarkUserForwardHop(fixture.ctx, repeated.Hops[0].ID, ForwardObservedSuspended, true, ""); err != nil {
		t.Fatalf("ack first hop cleanup: %v", err)
	}
	ready, err = fixture.repo.IsUserDeletionReady(fixture.ctx, "alice")
	if err != nil || ready {
		t.Fatalf("partial forward cleanup reported ready: ready=%v err=%v", ready, err)
	}
	if err := fixture.repo.MarkUserForwardHop(fixture.ctx, repeated.Hops[1].ID, ForwardObservedSuspended, true, ""); err != nil {
		t.Fatalf("ack final hop cleanup: %v", err)
	}
	ready, err = fixture.repo.IsUserDeletionReady(fixture.ctx, "alice")
	if err != nil || !ready {
		t.Fatalf("fully acknowledged forward cleanup not ready: ready=%v err=%v", ready, err)
	}
	// The acknowledged crash window still owns its ports until finalization.
	assertUserForwardAllocationCount(t, fixture, forward, len(forward.Hops)*2)
}

func TestFinalizeUserDeletionPurgesForwardingStateForReplacement(t *testing.T) {
	fixture := newForwardingStorageFixture(t)
	forward := fixture.createForward(t, "orphan-proof")
	if _, err := fixture.repo.db.ExecContext(fixture.ctx, `INSERT INTO user_tunnel_grant_usage_archive(grant_id,billed_bytes) VALUES(?,?)`, fixture.grant.ID, 1234); err != nil {
		t.Fatalf("insert archived usage: %v", err)
	}
	if _, err := fixture.repo.PrepareUserDeletion(fixture.ctx, "alice", "admin"); err != nil {
		t.Fatalf("PrepareUserDeletion: %v", err)
	}
	prepared, err := fixture.repo.GetUserForward(fixture.ctx, forward.PublicID, "alice")
	if err != nil {
		t.Fatalf("GetUserForward: %v", err)
	}
	for _, hop := range prepared.Hops {
		if err := fixture.repo.MarkUserForwardHop(fixture.ctx, hop.ID, ForwardObservedSuspended, true, ""); err != nil {
			t.Fatalf("ack hop cleanup: %v", err)
		}
	}
	if err := fixture.repo.FinalizeUserDeletion(fixture.ctx, "alice", "admin"); err != nil {
		t.Fatalf("FinalizeUserDeletion: %v", err)
	}

	checks := []struct {
		name  string
		query string
		arg   any
	}{
		{"allocations", `SELECT COUNT(*) FROM server_port_allocations WHERE owner_type='forward_hop' AND owner_id IN (?,?)`, []int64{forward.Hops[0].ID, forward.Hops[1].ID}},
		{"usage", `SELECT COUNT(*) FROM user_forward_usage WHERE forward_id=?`, forward.ID},
		{"hops", `SELECT COUNT(*) FROM user_forward_hops WHERE forward_id=?`, forward.ID},
		{"rules", `SELECT COUNT(*) FROM user_forward_rules WHERE username=?`, "alice"},
		{"archived usage", `SELECT COUNT(*) FROM user_tunnel_grant_usage_archive WHERE grant_id=?`, fixture.grant.ID},
		{"grants", `SELECT COUNT(*) FROM user_tunnel_grants WHERE username=?`, "alice"},
	}
	for _, check := range checks {
		var count int
		var err error
		if ids, ok := check.arg.([]int64); ok {
			err = fixture.repo.db.QueryRowContext(fixture.ctx, check.query, ids[0], ids[1]).Scan(&count)
		} else {
			err = fixture.repo.db.QueryRowContext(fixture.ctx, check.query, check.arg).Scan(&count)
		}
		if err != nil {
			t.Fatalf("count %s: %v", check.name, err)
		}
		if count != 0 {
			t.Fatalf("%s survived finalization: %d", check.name, count)
		}
	}

	if err := fixture.repo.CreateUser(fixture.ctx, "alice", "replacement@example.test", "Replacement", "hash", RoleUser, ""); err != nil {
		t.Fatalf("create replacement user: %v", err)
	}
	grants, err := fixture.repo.ListUserTunnelGrants(fixture.ctx, "alice")
	if err != nil || len(grants) != 0 {
		t.Fatalf("replacement inherited tunnel grants: grants=%+v err=%v", grants, err)
	}
	forwards, err := fixture.repo.ListUserForwards(fixture.ctx, "alice")
	if err != nil || len(forwards) != 0 {
		t.Fatalf("replacement inherited forwards: forwards=%+v err=%v", forwards, err)
	}
}

func assertUserForwardAllocationCount(t *testing.T, fixture forwardingStorageFixture, forward *UserForwardRule, want int) {
	t.Helper()
	var count int
	if err := fixture.repo.db.QueryRowContext(fixture.ctx, `SELECT COUNT(*)
FROM server_port_allocations
WHERE owner_type='forward_hop' AND owner_id IN (?,?)`, forward.Hops[0].ID, forward.Hops[1].ID).Scan(&count); err != nil {
		t.Fatalf("count forward allocations: %v", err)
	}
	if count != want {
		t.Fatalf("forward allocation count=%d want=%d", count, want)
	}
}
