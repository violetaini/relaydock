package storage

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newProxyProviderTokenFixture(t *testing.T) (*TrafficRepository, int64, int64) {
	t.Helper()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "proxy-provider-tokens.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x61}, 32)); err != nil {
		t.Fatalf("ConfigureNodeSecretEncryption: %v", err)
	}
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "test-hash", RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sourceID, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{
		Username: "alice",
		Name:     "upstream",
		URL:      "https://airport.example/sub?token=upstream-secret",
	})
	if err != nil {
		t.Fatalf("CreateExternalSubscription: %v", err)
	}
	providerID, err := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{
		Username:               "alice",
		ExternalSubscriptionID: sourceID,
		Name:                   "airport",
		Type:                   "http",
		Interval:               3600,
		ProcessMode:            "client",
	})
	if err != nil {
		t.Fatalf("CreateProxyProviderConfig: %v", err)
	}
	return repo, sourceID, providerID
}

func TestProxyProviderAccessTokenIsStableOpaqueAndEncrypted(t *testing.T) {
	repo, _, providerID := newProxyProviderTokenFixture(t)
	ctx := context.Background()

	const workers = 12
	tokens := make([]string, workers)
	errorsByWorker := make([]error, workers)
	var wait sync.WaitGroup
	for index := range tokens {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			tokens[index], errorsByWorker[index] = repo.EnsureProxyProviderAccessToken(ctx, providerID, "alice")
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByWorker {
		if err != nil {
			t.Fatalf("EnsureProxyProviderAccessToken[%d]: %v", index, err)
		}
		if tokens[index] != tokens[0] {
			t.Fatalf("concurrent token[%d]=%q, want stable %q", index, tokens[index], tokens[0])
		}
	}
	if !strings.HasPrefix(tokens[0], proxyProviderAccessTokenPrefix) || len(tokens[0]) != len(proxyProviderAccessTokenPrefix)+43 {
		t.Fatalf("unexpected token shape: %q", tokens[0])
	}

	var tokenHash, ciphertext string
	if err := repo.db.QueryRow(`SELECT access_token_hash, access_token_ciphertext FROM proxy_provider_configs WHERE id = ?`, providerID).Scan(&tokenHash, &ciphertext); err != nil {
		t.Fatalf("read stored token state: %v", err)
	}
	if tokenHash != hashProxyProviderAccessToken(tokens[0]) {
		t.Fatalf("stored token hash=%q, want SHA-256 hash", tokenHash)
	}
	if ciphertext == "" || strings.Contains(ciphertext, tokens[0]) {
		t.Fatalf("token ciphertext is empty or contains plaintext: %q", ciphertext)
	}

	cfg, sub, err := repo.ResolveProxyProviderAccess(ctx, tokens[0])
	if err != nil {
		t.Fatalf("ResolveProxyProviderAccess: %v", err)
	}
	if cfg.ID != providerID || cfg.Username != "alice" || sub.ID != cfg.ExternalSubscriptionID || sub.Username != "alice" {
		t.Fatalf("resolved resources are not owner-bound: cfg=%#v sub=%#v", cfg, sub)
	}
}

func TestProxyProviderAccessTokenRotationAndRevocation(t *testing.T) {
	t.Run("rotation invalidates old token", func(t *testing.T) {
		repo, _, providerID := newProxyProviderTokenFixture(t)
		ctx := context.Background()
		oldToken, err := repo.EnsureProxyProviderAccessToken(ctx, providerID, "alice")
		if err != nil {
			t.Fatal(err)
		}
		newToken, err := repo.RotateProxyProviderAccessToken(ctx, providerID, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if newToken == oldToken {
			t.Fatal("rotation returned the old token")
		}
		if _, _, err := repo.ResolveProxyProviderAccess(ctx, oldToken); !errors.Is(err, ErrProxyProviderAccessNotFound) {
			t.Fatalf("old token error=%v, want not found", err)
		}
		if _, _, err := repo.ResolveProxyProviderAccess(ctx, newToken); err != nil {
			t.Fatalf("new token did not resolve: %v", err)
		}
		if _, err := repo.RotateProxyProviderAccessToken(ctx, providerID, "bob"); !errors.Is(err, ErrProxyProviderAccessNotFound) {
			t.Fatalf("foreign rotation error=%v, want not found", err)
		}
	})

	t.Run("delete invalidates token", func(t *testing.T) {
		repo, _, providerID := newProxyProviderTokenFixture(t)
		ctx := context.Background()
		token, _ := repo.EnsureProxyProviderAccessToken(ctx, providerID, "alice")
		if err := repo.DeleteProxyProviderConfig(ctx, providerID, "alice"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := repo.ResolveProxyProviderAccess(ctx, token); !errors.Is(err, ErrProxyProviderAccessNotFound) {
			t.Fatalf("deleted provider token error=%v, want not found", err)
		}
	})

	t.Run("disabled owner invalidates token", func(t *testing.T) {
		repo, _, providerID := newProxyProviderTokenFixture(t)
		ctx := context.Background()
		token, _ := repo.EnsureProxyProviderAccessToken(ctx, providerID, "alice")
		if _, err := repo.db.Exec(`UPDATE users SET is_active = 0 WHERE username = 'alice'`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := repo.ResolveProxyProviderAccess(ctx, token); !errors.Is(err, ErrProxyProviderAccessNotFound) {
			t.Fatalf("disabled owner token error=%v, want not found", err)
		}
	})

	t.Run("detached source invalidates token", func(t *testing.T) {
		repo, sourceID, providerID := newProxyProviderTokenFixture(t)
		ctx := context.Background()
		token, _ := repo.EnsureProxyProviderAccessToken(ctx, providerID, "alice")
		if _, err := repo.db.Exec(`DELETE FROM external_subscriptions WHERE id = ?`, sourceID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := repo.ResolveProxyProviderAccess(ctx, token); !errors.Is(err, ErrProxyProviderAccessNotFound) {
			t.Fatalf("detached source token error=%v, want not found", err)
		}
	})
}

func TestConfigureNodeSecretEncryptionRejectsWrongKeyForProviderTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-provider-key.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	correctKey := bytes.Repeat([]byte{0x71}, 32)
	if err := repo.ConfigureNodeSecretEncryption(correctKey); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "test-hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	sourceID, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{Username: "alice", Name: "source", URL: "https://example.test/sub"})
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{Username: "alice", ExternalSubscriptionID: sourceID, Name: "provider", Type: "http", ProcessMode: "client"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.EnsureProxyProviderAccessToken(ctx, providerID, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x72}, 32)); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("wrong-key error=%v, want decrypt failure", err)
	}
}

func TestProxyProviderAccessTokenSurvivesUsernameRenameAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-provider-rename.db")
	key := bytes.Repeat([]byte{0x73}, 32)
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ConfigureNodeSecretEncryption(key); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "test-hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	sourceID, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{
		Username: "alice",
		Name:     "source",
		URL:      "https://example.test/sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{
		Username:               "alice",
		ExternalSubscriptionID: sourceID,
		Name:                   "provider",
		Type:                   "http",
		ProcessMode:            "client",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := repo.EnsureProxyProviderAccessToken(ctx, providerID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RenameUser(ctx, "alice", "renamed"); err != nil {
		t.Fatal(err)
	}
	cfg, sub, err := repo.ResolveProxyProviderAccess(ctx, token)
	if err != nil {
		t.Fatalf("resolve after rename: %v", err)
	}
	if cfg.Username != "renamed" || sub.Username != "renamed" {
		t.Fatalf("renamed provider ownership = %#v / %#v", cfg, sub)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.ConfigureNodeSecretEncryption(key); err != nil {
		t.Fatalf("configure encryption after rename: %v", err)
	}
	if _, _, err := reopened.ResolveProxyProviderAccess(ctx, token); err != nil {
		t.Fatalf("resolve after reopen: %v", err)
	}
}

func TestProxyProviderNamesAreUniquePerOwner(t *testing.T) {
	repo, _, _ := newProxyProviderTokenFixture(t)
	ctx := context.Background()
	secondSource, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{
		Username: "alice",
		Name:     "second source",
		URL:      "https://second.example/sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{
		Username:               "alice",
		ExternalSubscriptionID: secondSource,
		Name:                   "airport",
		Type:                   "http",
		ProcessMode:            "client",
	}); !errors.Is(err, ErrProxyProviderConfigExists) {
		t.Fatalf("duplicate provider error=%v, want ErrProxyProviderConfigExists", err)
	}

	if err := repo.CreateUser(ctx, "bob", "bob@example.test", "Bob", "test-hash", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	bobSource, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{Username: "bob", Name: "source", URL: "https://bob.example/sub"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{
		Username:               "bob",
		ExternalSubscriptionID: bobSource,
		Name:                   "airport",
		Type:                   "http",
		ProcessMode:            "client",
	}); err != nil {
		t.Fatalf("same name for another owner was rejected: %v", err)
	}
}

func TestProxyProviderLegacyDuplicateMigrationStillEnforcesNewNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-provider-legacy-duplicates.db")
	ctx := context.Background()
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"alice", "bob"} {
		if err := repo.CreateUser(ctx, username, username+"@example.test", username, "test-hash", RoleUser, ""); err != nil {
			t.Fatal(err)
		}
	}
	aliceSource, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{
		Username: "alice", Name: "alice source", URL: "https://alice.example/sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{
		Username: "alice", ExternalSubscriptionID: aliceSource, Name: "legacy", Type: "http", ProcessMode: "client",
	}); err != nil {
		t.Fatal(err)
	}

	// Recreate the state produced by an older build: duplicate legacy rows and
	// no owner/name index or trigger. The next open must preserve those rows but
	// still enforce uniqueness for every subsequent write.
	if _, err := repo.db.Exec(`
		DROP INDEX IF EXISTS idx_proxy_provider_configs_owner_name;
		DROP TRIGGER IF EXISTS trg_proxy_provider_configs_owner_name_insert;
		DROP TRIGGER IF EXISTS trg_proxy_provider_configs_owner_name_update;
		INSERT INTO proxy_provider_configs (username, external_subscription_id, name, type, process_mode)
		VALUES ('alice', ?, 'legacy', 'http', 'client')
	`, aliceSource); err != nil {
		t.Fatalf("create legacy duplicate state: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("reopen legacy database: %v", err)
	}
	defer repo.Close()
	var triggerCount int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'trg_proxy_provider_configs_owner_name_%'`).Scan(&triggerCount); err != nil {
		t.Fatal(err)
	}
	if triggerCount != 2 {
		t.Fatalf("owner/name trigger count=%d, want 2", triggerCount)
	}
	var duplicateCount int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM proxy_provider_configs WHERE username = 'alice' AND name = 'legacy'`).Scan(&duplicateCount); err != nil {
		t.Fatal(err)
	}
	if duplicateCount != 2 {
		t.Fatalf("legacy rows=%d, want preserved duplicate pair", duplicateCount)
	}
	if _, err := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{
		Username: "alice", ExternalSubscriptionID: aliceSource, Name: "legacy", Type: "http", ProcessMode: "client",
	}); !errors.Is(err, ErrProxyProviderConfigExists) {
		t.Fatalf("extended legacy duplicate error=%v, want ErrProxyProviderConfigExists", err)
	}

	bobSource, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{
		Username: "bob", Name: "bob source", URL: "https://bob.example/sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 8
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, createErr := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{
				Username: "bob", ExternalSubscriptionID: bobSource, Name: "concurrent", Type: "http", ProcessMode: "client",
			})
			errorsByWorker <- createErr
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	succeeded := 0
	conflicted := 0
	for createErr := range errorsByWorker {
		switch {
		case createErr == nil:
			succeeded++
		case errors.Is(createErr, ErrProxyProviderConfigExists):
			conflicted++
		default:
			t.Fatalf("concurrent create returned unexpected error: %v", createErr)
		}
	}
	if succeeded != 1 || conflicted != workers-1 {
		t.Fatalf("concurrent creates succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}
