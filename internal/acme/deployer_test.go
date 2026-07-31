package acme

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeployCertFilesAtomicallyReplacesPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls", "server.pem")
	keyPath := filepath.Join(dir, "tls", "server.key")
	if err := DeployCertFiles("new-cert", "new-key", certPath, keyPath); err != nil {
		t.Fatalf("DeployCertFiles: %v", err)
	}
	assertFileContent(t, certPath, "new-cert")
	assertFileContent(t, keyPath, "new-key")
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key mode = %v, err=%v; want 0600", infoMode(info), err)
	}
	assertNoCertTemps(t, filepath.Dir(certPath))
}

func TestDeployRollbackRestoresOldPairAndReloadsOldState(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, []byte("old-cert"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key"), 0600); err != nil {
		t.Fatal(err)
	}

	restarts := 0
	err := deployWithReloaders("new-cert", "new-key", certPath, keyPath, "xray", func() error {
		return nil
	}, func() error {
		restarts++
		if restarts == 1 {
			return errors.New("new certificate rejected")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "new certificate rejected") {
		t.Fatalf("expected reload failure, got %v", err)
	}
	if restarts != 2 {
		t.Fatalf("restart calls = %d, want failed reload plus recovery reload", restarts)
	}
	assertFileContent(t, certPath, "old-cert")
	assertFileContent(t, keyPath, "old-key")
	if info, statErr := os.Stat(certPath); statErr != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("restored cert mode = %v, err=%v; want 0640", infoMode(info), statErr)
	}
	assertNoCertTemps(t, dir)
}

func TestDeployRollbackRemovesFilesFromFailedFirstDeployment(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server.key")
	restarts := 0
	err := deployWithReloaders("new-cert", "new-key", certPath, keyPath, "xray", nil, func() error {
		restarts++
		if restarts == 1 {
			return errors.New("start failed")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected reload failure")
	}
	for _, path := range []string{certPath, keyPath} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s still exists after rollback: %v", path, statErr)
		}
	}
}

func TestDeployStagingFailureLeavesOldPairUntouched(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	keyParent := filepath.Join(dir, "not-a-directory")
	keyPath := filepath.Join(keyParent, "server.key")
	if err := os.WriteFile(certPath, []byte("old-cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyParent, []byte("block directory creation"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := DeployCertFiles("new-cert", "new-key", certPath, keyPath); err == nil {
		t.Fatal("expected private key staging failure")
	}
	assertFileContent(t, certPath, "old-cert")
	assertNoCertTemps(t, dir)
}

func TestDeployPreservesSymlinkAndUpdatesItsTarget(t *testing.T) {
	dir := t.TempDir()
	actualCert := filepath.Join(dir, "actual.pem")
	actualKey := filepath.Join(dir, "actual.key")
	certLink := filepath.Join(dir, "server.pem")
	keyLink := filepath.Join(dir, "server.key")
	if err := os.WriteFile(actualCert, []byte("old-cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actualKey, []byte("old-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actualCert, certLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actualKey, keyLink); err != nil {
		t.Fatal(err)
	}
	if err := DeployCertFiles("new-cert", "new-key", certLink, keyLink); err != nil {
		t.Fatalf("DeployCertFiles through symlink: %v", err)
	}
	if info, err := os.Lstat(certLink); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("certificate symlink was replaced: mode=%v err=%v", infoMode(info), err)
	}
	assertFileContent(t, actualCert, "new-cert")
	assertFileContent(t, actualKey, "new-key")
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func assertNoCertTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary certificate files remain: %v", matches)
	}
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}
