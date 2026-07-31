package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTrafficCycleResetRepository(t *testing.T) *TrafficRepository {
	t.Helper()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "traffic-cycle-reset.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func TestConcurrentUserTrafficBatchesDoNotLoseWritersToLockUpgrade(t *testing.T) {
	repo := newTrafficCycleResetRepository(t)
	ctx := context.Background()
	server := &RemoteServer{Name: "concurrent-edge", Token: "concurrent-edge-token"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	const writers = 16
	start := make(chan struct{})
	errors := make(chan error, writers)
	var wait sync.WaitGroup
	for i := 0; i < writers; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errors <- repo.UpsertUserTrafficBatch(ctx, server.ID, []UserTrafficSample{{
				Email:             fmt.Sprintf("alice__writer-%d", index),
				Username:          "alice",
				Uplink:            int64(index + 1),
				BillingMultiplier: 1,
			}}, false)
		}(i)
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent batch: %v", err)
		}
	}

	var rows int
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_email_traffic WHERE server_id = ?`, server.ID).Scan(&rows); err != nil {
		t.Fatalf("count email traffic rows: %v", err)
	}
	if rows != writers {
		t.Fatalf("persisted email rows=%d, want %d", rows, writers)
	}
}

func TestResetUserTrafficCycleAtCommitsCycleTimestampAndWarningTogether(t *testing.T) {
	repo := newTrafficCycleResetRepository(t)
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, `INSERT INTO xray_servers (id, name, host, port) VALUES (1, 'edge', '127.0.0.1', 10001)`); err != nil {
		t.Fatalf("insert xray server: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, `
INSERT INTO user_traffic
    (server_id, username, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink)
VALUES (1, 'alice', 120, 30, 500, 200, 120, 30)`); err != nil {
		t.Fatalf("insert user traffic: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, `
INSERT INTO user_email_traffic
    (server_id, email, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink,
     cycle_base_uplink, cycle_base_downlink)
VALUES (1, 'alice__edge-in', 90, 20, 400, 100, 90, 20, 10, 5)`); err != nil {
		t.Fatalf("insert user email traffic: %v", err)
	}
	claimed, err := repo.ClaimUserTrafficThresholdNotification(ctx, "alice", 1000)
	if err != nil || !claimed {
		t.Fatalf("initial threshold claim=(%v, %v), want true, nil", claimed, err)
	}

	resetAt := time.Date(2026, time.July, 31, 8, 5, 0, 0, time.UTC)
	if err := repo.ResetUserTrafficCycleAt(ctx, "alice", resetAt); err != nil {
		t.Fatalf("ResetUserTrafficCycleAt: %v", err)
	}

	var uplink, downlink int64
	if err := repo.db.QueryRowContext(ctx, `SELECT uplink, downlink FROM user_traffic WHERE username = 'alice'`).Scan(&uplink, &downlink); err != nil {
		t.Fatalf("read user traffic: %v", err)
	}
	if uplink != 0 || downlink != 0 {
		t.Fatalf("user cycle=(%d,%d), want zero", uplink, downlink)
	}
	var baseUplink, baseDownlink int64
	if err := repo.db.QueryRowContext(ctx, `SELECT cycle_base_uplink, cycle_base_downlink FROM user_email_traffic WHERE email = 'alice__edge-in'`).Scan(&baseUplink, &baseDownlink); err != nil {
		t.Fatalf("read email traffic baseline: %v", err)
	}
	if baseUplink != 90 || baseDownlink != 20 {
		t.Fatalf("email baseline=(%d,%d), want (90,20)", baseUplink, baseDownlink)
	}
	var lastReset time.Time
	if err := repo.db.QueryRowContext(ctx, `SELECT last_reset_at FROM users WHERE username = 'alice'`).Scan(&lastReset); err != nil {
		t.Fatalf("read last_reset_at: %v", err)
	}
	if !lastReset.Equal(resetAt) {
		t.Fatalf("last_reset_at=%s, want %s", lastReset, resetAt)
	}
	var warningCount int
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_traffic_threshold_notified WHERE username = 'alice'`).Scan(&warningCount); err != nil {
		t.Fatalf("count warning marker: %v", err)
	}
	if warningCount != 0 {
		t.Fatalf("warning markers=%d, want 0", warningCount)
	}
}

func TestUserTrafficThresholdClaimIsIdempotentAndTracksLimit(t *testing.T) {
	repo := newTrafficCycleResetRepository(t)
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	for i, tc := range []struct {
		limit int64
		want  bool
	}{{1000, true}, {1000, false}, {2000, true}, {2000, false}} {
		claimed, err := repo.ClaimUserTrafficThresholdNotification(ctx, "alice", tc.limit)
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		if claimed != tc.want {
			t.Fatalf("claim %d=%v, want %v", i, claimed, tc.want)
		}
	}
	if err := repo.ResetUserTrafficCycle(ctx, "alice"); err != nil {
		t.Fatalf("manual ResetUserTrafficCycle: %v", err)
	}
	claimed, err := repo.ClaimUserTrafficThresholdNotification(ctx, "alice", 2000)
	if err != nil || !claimed {
		t.Fatalf("claim after reset=(%v, %v), want true, nil", claimed, err)
	}
}

func TestResetRemoteServerTrafficCycleAtCommitsOffsetTimestampAndWarningTogether(t *testing.T) {
	repo := newTrafficCycleResetRepository(t)
	ctx := context.Background()
	server := &RemoteServer{Name: "edge", Token: "edge-token", TrafficSource: "xray", TrafficStatsMode: "both"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, `
INSERT INTO node_traffic (server_id, tag, type, uplink, downlink, last_uplink, last_downlink)
VALUES (?, 'edge-in', 'inbound', 400, 100, 400, 100)`, server.ID); err != nil {
		t.Fatalf("insert node traffic: %v", err)
	}
	if err := repo.MarkTrafficThresholdNotified(ctx, server.ID); err != nil {
		t.Fatalf("MarkTrafficThresholdNotified: %v", err)
	}

	resetAt := time.Date(2026, time.July, 31, 8, 5, 0, 0, time.UTC)
	if err := repo.ResetRemoteServerTrafficCycleAt(ctx, server.ID, resetAt); err != nil {
		t.Fatalf("ResetRemoteServerTrafficCycleAt: %v", err)
	}
	var offset int64
	var lastReset time.Time
	if err := repo.db.QueryRowContext(ctx, `SELECT traffic_used_offset, last_traffic_reset_at FROM remote_servers WHERE id = ?`, server.ID).Scan(&offset, &lastReset); err != nil {
		t.Fatalf("read reset server: %v", err)
	}
	if offset != -500 {
		t.Fatalf("traffic_used_offset=%d, want -500", offset)
	}
	if !lastReset.Equal(resetAt) {
		t.Fatalf("last_traffic_reset_at=%s, want %s", lastReset, resetAt)
	}
	notified, err := repo.IsTrafficThresholdNotified(ctx, server.ID)
	if err != nil {
		t.Fatalf("IsTrafficThresholdNotified: %v", err)
	}
	if notified {
		t.Fatal("server threshold marker survived cycle reset")
	}
}
