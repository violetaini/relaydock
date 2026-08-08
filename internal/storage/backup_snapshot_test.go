package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCreateConsistentSnapshotDuringConcurrentWrites(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "arcway.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	if _, err := repo.db.Exec(`
		CREATE TABLE backup_consistency (id INTEGER PRIMARY KEY, value INTEGER NOT NULL);
		INSERT INTO backup_consistency (id, value) VALUES (1, 0), (2, 0);
		CREATE TABLE backup_padding (payload BLOB NOT NULL);
		INSERT INTO backup_padding (payload) VALUES (zeroblob(8388608));
	`); err != nil {
		t.Fatalf("prepare snapshot fixture: %v", err)
	}

	stopWriter := make(chan struct{})
	started := make(chan struct{})
	writerErr := make(chan error, 1)
	var startedOnce sync.Once
	go func() {
		for value := 1; ; value++ {
			select {
			case <-stopWriter:
				writerErr <- nil
				return
			default:
			}
			tx, err := repo.db.BeginTx(context.Background(), nil)
			if err != nil {
				writerErr <- err
				return
			}
			if _, err = tx.Exec(`UPDATE backup_consistency SET value = ? WHERE id = 1`, value); err == nil {
				_, err = tx.Exec(`UPDATE backup_consistency SET value = ? WHERE id = 2`, value)
			}
			if err == nil {
				err = tx.Commit()
			} else {
				_ = tx.Rollback()
			}
			if err != nil {
				writerErr <- err
				return
			}
			startedOnce.Do(func() { close(started) })
		}
	}()
	select {
	case <-started:
	case err := <-writerErr:
		t.Fatalf("concurrent writer failed before snapshot: %v", err)
	}

	snapshotPath, cleanup, err := repo.CreateConsistentSnapshot(context.Background())
	if err != nil {
		close(stopWriter)
		<-writerErr
		t.Fatalf("CreateConsistentSnapshot: %v", err)
	}
	defer cleanup()
	close(stopWriter)
	if err := <-writerErr; err != nil {
		t.Fatalf("concurrent writer: %v", err)
	}

	info, err := os.Stat(snapshotPath)
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("snapshot mode=%#o, want 0600", got)
	}
	directoryInfo, err := os.Stat(filepath.Dir(snapshotPath))
	if err != nil {
		t.Fatalf("stat snapshot directory: %v", err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("snapshot directory mode=%#o, want 0700", got)
	}
	for _, sidecar := range []string{snapshotPath + "-wal", snapshotPath + "-shm"} {
		if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
			t.Fatalf("standalone snapshot unexpectedly has sidecar %s: %v", sidecar, err)
		}
	}

	db, err := sql.Open("sqlite", "file:"+snapshotPath+"?mode=ro")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer db.Close()
	var quickCheck string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&quickCheck); err != nil {
		t.Fatalf("quick_check snapshot: %v", err)
	}
	if quickCheck != "ok" {
		t.Fatalf("snapshot quick_check=%q, want ok", quickCheck)
	}
	var first, second int
	if err := db.QueryRow(`SELECT
		MAX(CASE WHEN id = 1 THEN value END),
		MAX(CASE WHEN id = 2 THEN value END)
		FROM backup_consistency`).Scan(&first, &second); err != nil {
		t.Fatalf("read snapshot consistency values: %v", err)
	}
	if first != second {
		t.Fatalf("snapshot observed partial transaction: first=%d second=%d", first, second)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close snapshot database: %v", err)
	}

	directory := filepath.Dir(snapshotPath)
	cleanup()
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("snapshot cleanup left staging directory: %v", err)
	}
	cleanup()
}
