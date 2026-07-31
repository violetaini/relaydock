package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentCurrentXraySnapshotsKeepSingleHead(t *testing.T) {
	ctx := context.Background()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "xray-snapshots.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	server := &RemoteServer{Name: "snapshot-edge", Token: "snapshot-token"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
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
			_, err := repo.UpsertCurrentXraySnapshot(ctx, server.ID,
				fmt.Sprintf(`{"inbounds":[{"tag":"writer-%d"}]}`, index),
				XraySnapshotSourceAgentReport)
			errors <- err
		}(i)
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent upsert: %v", err)
		}
	}

	var currentCount, oldCount int
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_xray_config_snapshots
		WHERE server_id = ? AND status = ?`, server.ID, XraySnapshotStatusCurrent).Scan(&currentCount); err != nil {
		t.Fatalf("count current snapshots: %v", err)
	}
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_xray_config_snapshots
		WHERE server_id = ? AND status = ?`, server.ID, XraySnapshotStatusOld).Scan(&oldCount); err != nil {
		t.Fatalf("count old snapshots: %v", err)
	}
	if currentCount != 1 || oldCount != writers-1 {
		t.Fatalf("snapshot chain current=%d old=%d, want 1/%d", currentCount, oldCount, writers-1)
	}
}

func TestConcurrentPendingXraySnapshotsKeepLatestCandidateOnly(t *testing.T) {
	ctx := context.Background()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "xray-pending.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	server := &RemoteServer{Name: "pending-edge", Token: "pending-token"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if _, err := repo.UpsertCurrentXraySnapshot(ctx, server.ID, `{"inbounds":[]}`, XraySnapshotSourceMasterWrite); err != nil {
		t.Fatalf("seed current snapshot: %v", err)
	}

	const writers = 12
	start := make(chan struct{})
	errors := make(chan error, writers)
	var wait sync.WaitGroup
	for i := 0; i < writers; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, err := repo.WritePendingXrayRecovery(ctx, server.ID,
				fmt.Sprintf(`{"outbounds":[{"tag":"pending-%d"}]}`, index),
				XraySnapshotSourceAgentReport)
			errors <- err
		}(i)
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent pending write: %v", err)
		}
	}

	var pendingCount int
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_xray_config_snapshots
		WHERE server_id = ? AND status = ?`, server.ID, XraySnapshotStatusPendingRecovery).Scan(&pendingCount); err != nil {
		t.Fatalf("count pending snapshots: %v", err)
	}
	if pendingCount != 1 {
		t.Fatalf("pending snapshot count=%d, want 1", pendingCount)
	}
}

func TestCanceledImmediateCommitDoesNotLeakWriterLock(t *testing.T) {
	ctx := context.Background()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "xray-canceled-commit.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	conn, err := repo.beginImmediateTransaction(ctx)
	if err != nil {
		t.Fatalf("begin first immediate transaction: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_ = finishImmediateTransaction(canceled, conn, true)

	next, err := repo.beginImmediateTransaction(ctx)
	if err != nil {
		t.Fatalf("writer lock leaked after canceled commit: %v", err)
	}
	if err := finishImmediateTransaction(ctx, next, false); err != nil {
		t.Fatalf("rollback second immediate transaction: %v", err)
	}
}
