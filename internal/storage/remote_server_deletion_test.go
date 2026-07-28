package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoteServerDeletionTaskPersistsAndConsumesCallbackOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remote-deletion.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	server := &RemoteServer{Name: "delete-edge", Token: "delete-edge-token", Status: RemoteServerStatusConnected}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	tokenHash := strings.Repeat("a", 64)
	if _, err := repo.CreateRemoteServerDeletionTask(context.Background(), server.ID, tokenHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerDeletionDispatched(context.Background(), server.ID, tokenHash, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	cleanupID := "0123456789abcdef0123456789abcdef"
	task, err := repo.ConsumeRemoteServerDeletionCallback(context.Background(), tokenHash, cleanupID, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != RemoteServerDeletionAgentUninstalled || task.CleanupID != cleanupID || !task.CallbackConsumed {
		t.Fatalf("unexpected persisted task: %+v", task)
	}
	if _, err := repo.ConsumeRemoteServerDeletionCallback(context.Background(), tokenHash, cleanupID, true, ""); !errors.Is(err, ErrRemoteServerDeletionCallbackUsed) {
		t.Fatalf("callback replay error=%v", err)
	}
}

func TestRemoteServerDeletionTaskRejectsExpiredAndMismatchedCallback(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "remote-deletion.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	server := &RemoteServer{Name: "delete-edge", Token: "delete-edge-token", Status: RemoteServerStatusConnected}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	tokenHash := strings.Repeat("b", 64)
	if _, err := repo.CreateRemoteServerDeletionTask(context.Background(), server.ID, tokenHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	cleanupID := "0123456789abcdef0123456789abcdef"
	if err := repo.MarkRemoteServerDeletionDispatched(context.Background(), server.ID, tokenHash, cleanupID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConsumeRemoteServerDeletionCallback(context.Background(), tokenHash, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, ""); !errors.Is(err, ErrRemoteServerDeletionCleanupID) {
		t.Fatalf("cleanup mismatch error=%v", err)
	}
	if _, err := repo.db.Exec(`UPDATE remote_server_deletion_tasks SET expires_at = ? WHERE server_id = ?`, time.Now().Add(-time.Minute), server.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConsumeRemoteServerDeletionCallback(context.Background(), tokenHash, cleanupID, true, ""); !errors.Is(err, ErrRemoteServerDeletionTokenExpired) {
		t.Fatalf("expired callback error=%v", err)
	}
}

func TestRemoteServerDeletionPendingTaskCanBeAtomicallyReplacedAfterFailure(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "remote-deletion.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	server := &RemoteServer{Name: "delete-edge", Token: "delete-edge-token", Status: RemoteServerStatusConnected}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	firstHash, secondHash := strings.Repeat("c", 64), strings.Repeat("d", 64)
	if _, err := repo.CreateRemoteServerDeletionTask(context.Background(), server.ID, firstHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRemoteServerDeletionTask(context.Background(), server.ID, secondHash, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("active pending task was replaced without an explicit failure transition")
	}
	if err := repo.FailRemoteServerDeletionTask(context.Background(), server.ID, "pre-dispatch restart"); err != nil {
		t.Fatal(err)
	}
	task, err := repo.CreateRemoteServerDeletionTask(context.Background(), server.ID, secondHash, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if task.TokenHash != secondHash || task.Status != RemoteServerDeletionPending || task.CallbackConsumed {
		t.Fatalf("unexpected replacement task: %+v", task)
	}
}

func TestDeleteRemoteServerRevokesOwnedSharesAndFederationRelationTransactionally(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "remote-deletion.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	server := &RemoteServer{Name: "delete-edge", Token: "delete-edge-token", Status: RemoteServerStatusConnected}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	shareHash := strings.Repeat("9", 64)
	if _, err := repo.CreateSharedServer(context.Background(), server.ID, shareHash, "consumer"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetFederatedServer(context.Background(), server.ID, "https://owner.example.test", "federation-token", "shared-"); err != nil {
		t.Fatal(err)
	}
	counts, err := repo.GetRemoteServerDeleteCounts(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if counts.SharedServerTokens != 1 || counts.FederationRelations != 1 {
		t.Fatalf("share impact not counted: %+v", counts)
	}
	if err := repo.DeleteRemoteServer(context.Background(), server.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetSharedServerByTokenHash(context.Background(), shareHash); !errors.Is(err, ErrSharedServerNotFound) {
		t.Fatalf("share token remained usable after server deletion: %v", err)
	}
	if _, err := repo.GetFederatedServer(context.Background(), server.ID); !errors.Is(err, ErrFederatedServerNotFound) {
		t.Fatalf("federation relation remained after server deletion: %v", err)
	}
}

func TestPostDispatchErrorCannotDowngradeConfirmedAgentUninstall(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "remote-deletion.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	server := &RemoteServer{Name: "delete-edge", Token: "delete-edge-token", Status: RemoteServerStatusConnected}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	tokenHash := strings.Repeat("8", 64)
	if _, err := repo.CreateRemoteServerDeletionTask(context.Background(), server.ID, tokenHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRemoteServerDeletionDispatched(context.Background(), server.ID, tokenHash, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConsumeRemoteServerDeletionCallback(context.Background(), tokenHash, "0123456789abcdef0123456789abcdef", true, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.KeepRemoteServerDeletionDispatched(context.Background(), server.ID, "late acknowledgement mismatch"); err != nil {
		t.Fatal(err)
	}
	task, err := repo.GetRemoteServerDeletionTask(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != RemoteServerDeletionAgentUninstalled || !task.CallbackConsumed {
		t.Fatalf("confirmed task was downgraded: %+v", task)
	}
}
