package handler

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"miaomiaowux/internal/storage"
)

func prepareSubscriptionRecoveryTest(t *testing.T) (*storage.TrafficRepository, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("ARCWAY_SUBSCRIPTION_STORE_LOCK_PATH", filepath.Join(root, "locks", "subscription-store.lock"))
	directory := filepath.Join(root, "subscribes")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return newManagedSecurityTestRepo(t), directory
}

func writeRecoverySubscription(t *testing.T, directory, filename string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, filename), []byte("proxies: []\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func createRecoverySubscriptionRow(t *testing.T, repo *storage.TrafficRepository, filename string) storage.SubscribeFile {
	t.Helper()
	file, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name: strings.TrimSuffix(filename, filepath.Ext(filename)), Type: storage.SubscribeTypeUpload, Filename: filename,
	})
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestSubscriptionStoreLegacyBootstrapRunsOnlyOnce(t *testing.T) {
	repo, directory := prepareSubscriptionRecoveryTest(t)
	writeRecoverySubscription(t, directory, "legacy.yaml")

	result, err := ReconcileSubscriptionStore(context.Background(), repo, directory)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 || result.Orphaned != 0 {
		t.Fatalf("first recovery result = %#v", result)
	}
	if _, err := repo.GetSubscribeFileByFilename(context.Background(), "legacy.yaml"); err != nil {
		t.Fatalf("legacy file was not registered: %v", err)
	}
	marker, err := repo.GetSystemSetting(context.Background(), subscriptionStoreAuthoritativeSetting)
	if err != nil || marker != "1" {
		t.Fatalf("bootstrap marker=%q err=%v", marker, err)
	}
	info, err := os.Stat(filepath.Join(directory, "legacy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("legacy file mode=%o, want 600", info.Mode().Perm())
	}

	result, err = ReconcileSubscriptionStore(context.Background(), repo, directory)
	if err != nil || result.Imported != 0 || result.Orphaned != 0 {
		t.Fatalf("second recovery result=%#v err=%v", result, err)
	}
}

func TestSubscriptionStoreRecoveryQuarantinesRenameCrashWindows(t *testing.T) {
	for _, test := range []struct {
		name      string
		canonical string
		orphan    string
	}{
		{name: "before database commit", canonical: "old.yaml", orphan: "new.yaml"},
		{name: "after database commit", canonical: "new.yaml", orphan: "old.yaml"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo, directory := prepareSubscriptionRecoveryTest(t)
			if err := repo.SetSystemSetting(context.Background(), subscriptionStoreAuthoritativeSetting, "1"); err != nil {
				t.Fatal(err)
			}
			createRecoverySubscriptionRow(t, repo, test.canonical)
			writeRecoverySubscription(t, directory, test.canonical)
			writeRecoverySubscription(t, directory, test.orphan)

			result, err := ReconcileSubscriptionStore(context.Background(), repo, directory)
			if err != nil {
				t.Fatal(err)
			}
			if result.Imported != 0 || result.Orphaned != 1 {
				t.Fatalf("recovery result=%#v", result)
			}
			if _, err := os.Stat(filepath.Join(directory, test.canonical)); err != nil {
				t.Fatalf("canonical file was lost: %v", err)
			}
			if _, err := os.Stat(filepath.Join(directory, test.orphan)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("orphan remained active: %v", err)
			}
			entries, err := os.ReadDir(filepath.Join(directory, ".orphaned"))
			if err != nil || len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".blob" {
				t.Fatalf("quarantined entries=%v err=%v", entries, err)
			}
			info, err := entries[0].Info()
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatalf("orphan mode=%o, want 600", info.Mode().Perm())
			}
		})
	}
}

func TestSubscriptionStoreRecoveryNeverRevivesDeleteLastOrphan(t *testing.T) {
	repo, directory := prepareSubscriptionRecoveryTest(t)
	if err := repo.SetSystemSetting(context.Background(), subscriptionStoreAuthoritativeSetting, "1"); err != nil {
		t.Fatal(err)
	}
	writeRecoverySubscription(t, directory, "deleted-last.yaml")

	result, err := ReconcileSubscriptionStore(context.Background(), repo, directory)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 0 || result.Orphaned != 1 {
		t.Fatalf("recovery result=%#v", result)
	}
	files, err := repo.ListSubscribeFiles(context.Background())
	if err != nil || len(files) != 0 {
		t.Fatalf("orphan was revived: files=%#v err=%v", files, err)
	}
	result, err = ReconcileSubscriptionStore(context.Background(), repo, directory)
	if err != nil || result.Imported != 0 || result.Orphaned != 0 {
		t.Fatalf("empty authoritative recovery result=%#v err=%v", result, err)
	}
}

func TestSubscriptionStoreRecoveryFailsWhenCanonicalFileIsMissing(t *testing.T) {
	repo, directory := prepareSubscriptionRecoveryTest(t)
	if err := repo.SetSystemSetting(context.Background(), subscriptionStoreAuthoritativeSetting, "1"); err != nil {
		t.Fatal(err)
	}
	createRecoverySubscriptionRow(t, repo, "missing.yaml")

	_, err := ReconcileSubscriptionStore(context.Background(), repo, directory)
	if err == nil || !strings.Contains(err.Error(), "missing its file") {
		t.Fatalf("missing canonical file error=%v", err)
	}
}

func TestSubscriptionStoreRecoveryQuarantinesHiddenTemporaryFile(t *testing.T) {
	repo, directory := prepareSubscriptionRecoveryTest(t)
	if err := repo.SetSystemSetting(context.Background(), subscriptionStoreAuthoritativeSetting, "1"); err != nil {
		t.Fatal(err)
	}
	writeRecoverySubscription(t, directory, ".arcway-subscription-crash")

	result, err := ReconcileSubscriptionStore(context.Background(), repo, directory)
	if err != nil || result.Orphaned != 1 {
		t.Fatalf("temporary recovery result=%#v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".arcway-subscription-crash")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hidden temporary file remained active: %v", err)
	}
}

func TestSubscriptionStoreRecoveryRecognizesActiveSubscriptionLinkFile(t *testing.T) {
	repo, directory := prepareSubscriptionRecoveryTest(t)
	if err := repo.SetSystemSetting(context.Background(), subscriptionStoreAuthoritativeSetting, "1"); err != nil {
		t.Fatal(err)
	}
	writeRecoverySubscription(t, directory, "linked-rule.yaml")
	if _, err := repo.CreateSubscriptionLink(context.Background(), storage.SubscriptionLink{
		Name: "linked rule", Type: "clash", RuleFilename: "linked-rule.yaml",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := ReconcileSubscriptionStore(context.Background(), repo, directory)
	if err != nil || result.Orphaned != 0 || result.Imported != 0 {
		t.Fatalf("linked rule recovery result=%#v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "linked-rule.yaml")); err != nil {
		t.Fatalf("active subscription link file was quarantined: %v", err)
	}
}

func TestSubscriptionStoreLockHelperProcess(t *testing.T) {
	if os.Getenv("ARCWAY_SUBSCRIPTION_LOCK_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("locked\n")
	_, _ = io.Copy(io.Discard, os.Stdin)
	unlock()
}

func TestSubscriptionStoreLockSerializesProcesses(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, "locks", "subscription-store.lock")
	t.Setenv("ARCWAY_SUBSCRIPTION_STORE_LOCK_PATH", lockPath)
	command := exec.Command(os.Args[0], "-test.run=^TestSubscriptionStoreLockHelperProcess$")
	command.Env = append(os.Environ(), "ARCWAY_SUBSCRIPTION_LOCK_HELPER=1", "ARCWAY_SUBSCRIPTION_STORE_LOCK_PATH="+lockPath)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	})
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "locked" {
		t.Fatalf("helper failed to acquire lock: line=%q err=%v", scanner.Text(), scanner.Err())
	}

	acquired := make(chan func(), 1)
	failed := make(chan error, 1)
	go func() {
		unlock, err := lockSubscriptionStore()
		if err != nil {
			failed <- err
			return
		}
		acquired <- unlock
	}()
	select {
	case unlock := <-acquired:
		unlock()
		t.Fatal("parent acquired store lock while helper still held it")
	case err := <-failed:
		t.Fatalf("parent lock failed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	select {
	case unlock := <-acquired:
		unlock()
	case err := <-failed:
		t.Fatalf("parent lock failed after release: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("parent did not acquire store lock after helper released it")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(lockPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("lock mode=%o, want 600", info.Mode().Perm())
		}
	}
}

func TestSubscriptionStoreLockPreservesExistingParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions are not available")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "shared-parent")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCWAY_SUBSCRIPTION_STORE_LOCK_PATH", filepath.Join(parent, "subscription-store.lock"))

	unlock, err := lockSubscriptionStore()
	if err != nil {
		t.Fatal(err)
	}
	unlock()

	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("existing lock parent mode=%o, want unchanged 755", info.Mode().Perm())
	}
}
