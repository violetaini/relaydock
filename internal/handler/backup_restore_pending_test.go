package handler

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyPendingBackupRestoreRollsBackAllRootsOnFailure(t *testing.T) {
	root := t.TempDir()
	restoredDatabase := validSQLiteBackupBytes(t)
	mustWriteTestFile(t, filepath.Join(root, "data", "arcway.db"), "live-db")
	mustWriteTestFile(t, filepath.Join(root, "data", "live-only.txt"), "live")
	mustWriteTestFile(t, filepath.Join(root, "subscribes", "live.yaml"), "live")

	reader := testZipReaderBytes(t, map[string][]byte{
		"data/arcway.db":           restoredDatabase,
		"subscribes/restored.yaml": []byte("restored"),
	})
	if err := extractZipReaderAt(reader, root); err != nil {
		t.Fatalf("stage pending restore: %v", err)
	}

	pendingSubscribes := filepath.Join(root, pendingRestoreDirName, "subscribes")
	liveSubscribes := filepath.Join(root, "subscribes")
	injected := false
	rename := func(source, destination string) error {
		if !injected && source == pendingSubscribes && destination == liveSubscribes {
			injected = true
			return errors.New("injected second-root activation failure")
		}
		return os.Rename(source, destination)
	}
	applied, err := applyPendingBackupRestoreAt(root, rename)
	if err == nil || applied {
		t.Fatalf("apply result applied=%v err=%v, want rolled-back failure", applied, err)
	}
	if !injected {
		t.Fatal("rename failure was not injected")
	}

	for filename, want := range map[string]string{
		"data/arcway.db":       "live-db",
		"data/live-only.txt":   "live",
		"subscribes/live.yaml": "live",
	} {
		got, readErr := os.ReadFile(filepath.Join(root, filename))
		if readErr != nil || string(got) != want {
			t.Fatalf("live %s=%q, %v; want %q", filename, got, readErr, want)
		}
	}
	pendingDatabase, readErr := os.ReadFile(filepath.Join(root, pendingRestoreDirName, "data", "arcway.db"))
	if readErr != nil || !bytes.Equal(pendingDatabase, restoredDatabase) {
		t.Fatalf("pending database differs after rollback: %v", readErr)
	}
	for filename, want := range map[string]string{
		"subscribes/restored.yaml": "restored",
	} {
		got, readErr := os.ReadFile(filepath.Join(root, pendingRestoreDirName, filename))
		if readErr != nil || string(got) != want {
			t.Fatalf("pending %s=%q, %v; want %q", filename, got, readErr, want)
		}
	}
	if _, statErr := os.Stat(filepath.Join(root, restoreRollbackDirName)); !os.IsNotExist(statErr) {
		t.Fatalf("rollback state remained after successful rollback: %v", statErr)
	}

	applied, err = ApplyPendingBackupRestore(root)
	if err != nil || !applied {
		t.Fatalf("retry apply: applied=%v err=%v", applied, err)
	}
}

func TestApplyPendingBackupRestoreRecoversInterruptedApplyBeforeRetry(t *testing.T) {
	root := t.TempDir()
	restoredDatabase := validSQLiteBackupBytes(t)
	mustWriteTestFile(t, filepath.Join(root, "data", "arcway.db"), "live-db")
	mustWriteTestFile(t, filepath.Join(root, "data", "live-only.txt"), "live")
	mustWriteTestFile(t, filepath.Join(root, "subscribes", "live.yaml"), "live")

	reader := testZipReaderBytes(t, map[string][]byte{
		"data/arcway.db":           restoredDatabase,
		"subscribes/restored.yaml": []byte("restored"),
	})
	if err := extractZipReaderAt(reader, root); err != nil {
		t.Fatalf("stage pending restore: %v", err)
	}

	pending := filepath.Join(root, pendingRestoreDirName)
	manifest, err := readRestoreManifest(pending)
	if err != nil {
		t.Fatalf("read pending manifest: %v", err)
	}
	rollback := filepath.Join(root, restoreRollbackDirName)
	if err := os.Mkdir(rollback, 0700); err != nil {
		t.Fatalf("create simulated rollback state: %v", err)
	}
	if err := writeRestoreManifest(rollback, manifest); err != nil {
		t.Fatalf("write simulated rollback manifest: %v", err)
	}
	if err := os.Rename(filepath.Join(root, "data"), filepath.Join(rollback, "data")); err != nil {
		t.Fatalf("preserve live data in simulated interrupted apply: %v", err)
	}
	if err := os.Rename(filepath.Join(pending, "data"), filepath.Join(root, "data")); err != nil {
		t.Fatalf("activate data in simulated interrupted apply: %v", err)
	}

	applied, err := ApplyPendingBackupRestore(root)
	if err != nil || !applied {
		t.Fatalf("recover and retry interrupted apply: applied=%v err=%v", applied, err)
	}
	restoredOnDisk, err := os.ReadFile(filepath.Join(root, "data", "arcway.db"))
	if err != nil || !bytes.Equal(restoredOnDisk, restoredDatabase) {
		t.Fatalf("restored database differs after interrupted recovery: %v", err)
	}
	subscription, err := os.ReadFile(filepath.Join(root, "subscribes", "restored.yaml"))
	if err != nil || string(subscription) != "restored" {
		t.Fatalf("restored subscription after interrupted recovery=%q, %v", subscription, err)
	}
	for _, filename := range []string{
		filepath.Join(root, "data", "live-only.txt"),
		filepath.Join(root, "subscribes", "live.yaml"),
		pending,
		rollback,
		filepath.Join(root, restoreCommittedDirName),
	} {
		if _, statErr := os.Stat(filename); !os.IsNotExist(statErr) {
			t.Fatalf("obsolete restore state survived at %s: %v", filename, statErr)
		}
	}
}

func TestApplyPendingBackupRestoreNoPendingIsNoop(t *testing.T) {
	applied, err := ApplyPendingBackupRestore(t.TempDir())
	if err != nil || applied {
		t.Fatalf("ApplyPendingBackupRestore without pending: applied=%v err=%v", applied, err)
	}
}
