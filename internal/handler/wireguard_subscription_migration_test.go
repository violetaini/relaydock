package handler

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func writeWireGuardMigrationFixtureFile(t *testing.T, directory, name, content string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	return path
}

func readWireGuardMigrationFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func ruleVersionContentsForMigrationTest(t *testing.T, repo *storage.TrafficRepository, filename string) []string {
	t.Helper()
	versions, err := repo.ListRuleVersions(context.Background(), filename, 100)
	if err != nil {
		t.Fatal(err)
	}
	contents := make([]string, len(versions))
	for index := range versions {
		contents[index] = versions[index].Content
	}
	return contents
}

func TestProtectPersistedWireGuardSubscriptionSecretsMigratesFilesAndHistoryIdempotently(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	ctx := context.Background()
	directory := filepath.Join(t.TempDir(), "subscriptions")
	if err := os.Mkdir(directory, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0777); err != nil {
		t.Fatal(err)
	}

	legacy := managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey)
	legacyPath := writeWireGuardMigrationFixtureFile(t, directory, "legacy.yaml", legacy)
	ordinary := "mode: rule\nproxies:\n  - name: ordinary\n    type: vless\n    uuid: test-uuid\n"
	ordinaryPath := writeWireGuardMigrationFixtureFile(t, directory, "ordinary.yml", ordinary)
	if _, err := repo.SaveRuleVersion(ctx, "legacy.yaml", legacy, "admin"); err != nil {
		t.Fatal(err)
	}

	if err := ProtectPersistedWireGuardSubscriptionSecrets(ctx, repo, directory); err != nil {
		t.Fatal(err)
	}
	protectedFile := readWireGuardMigrationFixtureFile(t, legacyPath)
	if bytes.Contains(protectedFile, []byte(subscriptionTestWireGuardPrivateKey)) ||
		!bytes.Contains(protectedFile, []byte(wireGuardSubscriptionSecretPrefix)) {
		t.Fatalf("legacy file was not protected: %s", protectedFile)
	}
	hydratedFile, err := hydrateWireGuardSubscriptionContent(ctx, repo, "legacy.yaml", string(protectedFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hydratedFile, subscriptionTestWireGuardPrivateKey) || strings.Contains(hydratedFile, wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("file did not hydrate back to its private key: %s", hydratedFile)
	}

	history := ruleVersionContentsForMigrationTest(t, repo, "legacy.yaml")
	if len(history) != 1 || strings.Contains(history[0], subscriptionTestWireGuardPrivateKey) ||
		!strings.Contains(history[0], wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("legacy history was not protected: %#v", history)
	}
	hydratedHistory, err := hydrateWireGuardSubscriptionContent(ctx, repo, "legacy.yaml", history[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hydratedHistory, subscriptionTestWireGuardPrivateKey) || strings.Contains(hydratedHistory, wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("history did not hydrate back to its private key: %s", hydratedHistory)
	}
	if got := string(readWireGuardMigrationFixtureFile(t, ordinaryPath)); got != ordinary {
		t.Fatalf("ordinary subscription content changed: %q", got)
	}

	if runtime.GOOS != "windows" {
		directoryInfo, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if got := directoryInfo.Mode().Perm(); got != 0700 {
			t.Fatalf("subscription directory mode=%o, want 700", got)
		}
		for _, path := range []string{legacyPath, ordinaryPath} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Fatalf("subscription file %s mode=%o, want 600", filepath.Base(path), got)
			}
		}
	}

	fileBeforeRetry := append([]byte(nil), protectedFile...)
	historyBeforeRetry := history[0]
	if err := ProtectPersistedWireGuardSubscriptionSecrets(ctx, repo, directory); err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
	if got := readWireGuardMigrationFixtureFile(t, legacyPath); !bytes.Equal(got, fileBeforeRetry) {
		t.Fatalf("idempotent retry rewrote ciphertext:\nbefore: %s\nafter:  %s", fileBeforeRetry, got)
	}
	historyAfterRetry := ruleVersionContentsForMigrationTest(t, repo, "legacy.yaml")
	if len(historyAfterRetry) != 1 || historyAfterRetry[0] != historyBeforeRetry {
		t.Fatalf("idempotent retry changed history: before=%q after=%#v", historyBeforeRetry, historyAfterRetry)
	}
}

func TestProtectPersistedWireGuardSubscriptionSecretsPreflightIsAtomic(t *testing.T) {
	t.Run("invalid private key in a file", func(t *testing.T) {
		repo, _ := newWireGuardSubscriptionTestRepo(t)
		ctx := context.Background()
		directory := t.TempDir()
		good := managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey)
		invalid := managedWireGuardSubscriptionYAML("not-a-wireguard-private-key")
		goodPath := writeWireGuardMigrationFixtureFile(t, directory, "00-good.yaml", good)
		invalidPath := writeWireGuardMigrationFixtureFile(t, directory, "99-invalid.yaml", invalid)
		if _, err := repo.SaveRuleVersion(ctx, "history.yaml", good, "admin"); err != nil {
			t.Fatal(err)
		}
		historyBefore := ruleVersionContentsForMigrationTest(t, repo, "history.yaml")

		if err := ProtectPersistedWireGuardSubscriptionSecrets(ctx, repo, directory); err == nil {
			t.Fatal("migration with an invalid private key unexpectedly succeeded")
		}
		if got := readWireGuardMigrationFixtureFile(t, goodPath); !bytes.Equal(got, []byte(good)) {
			t.Fatalf("valid file was partially migrated before preflight failed: %s", got)
		}
		if got := readWireGuardMigrationFixtureFile(t, invalidPath); !bytes.Equal(got, []byte(invalid)) {
			t.Fatalf("invalid file changed after rejected preflight: %s", got)
		}
		if got := ruleVersionContentsForMigrationTest(t, repo, "history.yaml"); !equalMigrationTestStrings(got, historyBefore) {
			t.Fatalf("history was partially migrated: before=%#v after=%#v", historyBefore, got)
		}
	})

	t.Run("ciphertext marker belongs to another scope", func(t *testing.T) {
		repo, _ := newWireGuardSubscriptionTestRepo(t)
		ctx := context.Background()
		directory := t.TempDir()
		good := managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey)
		goodPath := writeWireGuardMigrationFixtureFile(t, directory, "00-good.yaml", good)
		foreignMarker, err := protectWireGuardSubscriptionContent(ctx, repo, "foreign-scope.yaml", good, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.SaveRuleVersion(ctx, "10-good-history.yaml", good, "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.SaveRuleVersion(ctx, "99-wrong-scope.yaml", foreignMarker, "admin"); err != nil {
			t.Fatal(err)
		}
		goodHistoryBefore := ruleVersionContentsForMigrationTest(t, repo, "10-good-history.yaml")
		wrongHistoryBefore := ruleVersionContentsForMigrationTest(t, repo, "99-wrong-scope.yaml")

		err = ProtectPersistedWireGuardSubscriptionSecrets(ctx, repo, directory)
		if !errors.Is(err, errUntrustedWireGuardSecret) {
			t.Fatalf("wrong-scope marker error=%v, want untrusted marker", err)
		}
		if got := readWireGuardMigrationFixtureFile(t, goodPath); !bytes.Equal(got, []byte(good)) {
			t.Fatalf("file was partially migrated before history preflight failed: %s", got)
		}
		if got := ruleVersionContentsForMigrationTest(t, repo, "10-good-history.yaml"); !equalMigrationTestStrings(got, goodHistoryBefore) {
			t.Fatalf("valid history was partially migrated: before=%#v after=%#v", goodHistoryBefore, got)
		}
		if got := ruleVersionContentsForMigrationTest(t, repo, "99-wrong-scope.yaml"); !equalMigrationTestStrings(got, wrongHistoryBefore) {
			t.Fatalf("wrong-scope history changed after rejection: before=%#v after=%#v", wrongHistoryBefore, got)
		}
	})
}

func equalMigrationTestStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
