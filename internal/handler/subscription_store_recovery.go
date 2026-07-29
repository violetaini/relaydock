package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

const subscriptionStoreAuthoritativeSetting = "_subscription_file_registry_authoritative_v1"

type SubscriptionStoreRecoveryResult struct {
	Imported int
	Orphaned int
}

// ReconcileSubscriptionStore makes subscribe_files authoritative. The first
// run imports legacy YAML files and persists a one-way marker. Every later run
// quarantines unowned files, including crash remnants, instead of reviving
// them as subscriptions.
func ReconcileSubscriptionStore(ctx context.Context, repo *storage.TrafficRepository, baseDir string) (SubscriptionStoreRecoveryResult, error) {
	var result SubscriptionStoreRecoveryResult
	if repo == nil {
		return result, errors.New("subscription repository is required")
	}
	baseDir = filepath.Clean(strings.TrimSpace(baseDir))
	if baseDir == "." || baseDir == "" {
		return result, errors.New("subscription directory is required")
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		return result, err
	}
	defer unlock()

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return result, fmt.Errorf("create subscription directory: %w", err)
	}
	if err := os.Chmod(baseDir, 0700); err != nil {
		return result, fmt.Errorf("restrict subscription directory: %w", err)
	}
	marker, err := repo.GetSystemSetting(ctx, subscriptionStoreAuthoritativeSetting)
	if err != nil {
		return result, fmt.Errorf("read subscription registry marker: %w", err)
	}
	legacyBootstrap := strings.TrimSpace(marker) != "1"

	files, err := repo.ListSubscribeFiles(ctx)
	if err != nil {
		return result, fmt.Errorf("list canonical subscriptions: %w", err)
	}
	canonical := make(map[string]string, len(files))
	for _, file := range files {
		canonical[file.Filename] = fmt.Sprintf("subscribe_files id=%d", file.ID)
	}
	links, err := repo.ListSubscriptionLinks(ctx)
	if err != nil {
		return result, fmt.Errorf("list canonical subscription links: %w", err)
	}
	for _, link := range links {
		owner := fmt.Sprintf("subscription_links id=%d", link.ID)
		if existing := canonical[link.RuleFilename]; existing != "" {
			owner = existing + ", " + owner
		}
		canonical[link.RuleFilename] = owner
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return result, fmt.Errorf("read subscription directory: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == ".keep.yaml" {
			continue
		}
		_, owned := canonical[name]
		isYAML := strings.EqualFold(filepath.Ext(name), ".yaml") || strings.EqualFold(filepath.Ext(name), ".yml")
		isTemporary := strings.HasPrefix(name, ".")
		if !isYAML && !isTemporary {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return result, fmt.Errorf("inspect subscription directory entry %q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return result, fmt.Errorf("subscription directory entry %q is not a regular file", name)
		}
		if owned {
			continue
		}
		if legacyBootstrap && isYAML && !isTemporary {
			if err := storage.ValidateSubscribeFilename(name); err != nil {
				return result, fmt.Errorf("invalid legacy subscription filename %q: %w", name, err)
			}
			base := strings.TrimSuffix(name, filepath.Ext(name))
			created, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
				Name:        base,
				Description: "自动同步的旧版订阅文件",
				Type:        storage.SubscribeTypeUpload,
				Filename:    name,
			})
			if err != nil {
				return result, fmt.Errorf("import legacy subscription %q: %w", name, err)
			}
			canonical[name] = fmt.Sprintf("subscribe_files id=%d", created.ID)
			result.Imported++
			continue
		}
		if _, err := quarantineSubscriptionStoreFile(baseDir, name); err != nil {
			return result, err
		}
		result.Orphaned++
	}

	if err := verifyCanonicalSubscriptionFiles(baseDir, canonical); err != nil {
		return result, err
	}
	if legacyBootstrap {
		if err := repo.SetSystemSetting(ctx, subscriptionStoreAuthoritativeSetting, "1"); err != nil {
			return result, fmt.Errorf("persist subscription registry marker: %w", err)
		}
	}
	return result, nil
}

func verifyCanonicalSubscriptionFiles(baseDir string, canonical map[string]string) error {
	for filename, owner := range canonical {
		if err := storage.ValidateSubscribeFilename(filename); err != nil {
			return fmt.Errorf("invalid canonical subscription filename for %s: %w", owner, err)
		}
		path := filepath.Join(baseDir, filename)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("canonical subscription %q (%s) is missing its file", filename, owner)
		}
		if err != nil {
			return fmt.Errorf("inspect canonical subscription %q: %w", filename, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("canonical subscription %q is not a regular file", filename)
		}
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("restrict canonical subscription %q: %w", filename, err)
		}
	}
	return nil
}

func quarantineSubscriptionStoreFile(baseDir, filename string) (string, error) {
	if filepath.Base(filename) != filename {
		return "", errors.New("orphaned subscription filename must be a basename")
	}
	source := filepath.Join(baseDir, filename)
	info, err := os.Lstat(source)
	if err != nil {
		return "", fmt.Errorf("inspect orphaned subscription %q: %w", filename, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("orphaned subscription %q is not a regular file", filename)
	}
	if err := os.Chmod(source, 0600); err != nil {
		return "", fmt.Errorf("restrict orphaned subscription %q: %w", filename, err)
	}
	orphanDir := filepath.Join(baseDir, ".orphaned")
	if err := os.MkdirAll(orphanDir, 0700); err != nil {
		return "", fmt.Errorf("create subscription orphan directory: %w", err)
	}
	if err := os.Chmod(orphanDir, 0700); err != nil {
		return "", fmt.Errorf("restrict subscription orphan directory: %w", err)
	}
	nameHash := sha256.Sum256([]byte(filename))
	for attempts := 0; attempts < 8; attempts++ {
		var nonce [8]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", fmt.Errorf("generate subscription orphan name: %w", err)
		}
		destination := filepath.Join(orphanDir, hex.EncodeToString(nameHash[:8])+"-"+hex.EncodeToString(nonce[:])+".blob")
		if _, err := os.Lstat(destination); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect subscription orphan destination: %w", err)
		}
		if err := os.Rename(source, destination); err != nil {
			return "", fmt.Errorf("quarantine orphaned subscription %q: %w", filename, err)
		}
		if err := os.Chmod(destination, 0600); err != nil {
			return "", fmt.Errorf("restrict quarantined subscription %q: %w", filename, err)
		}
		return destination, nil
	}
	return "", fmt.Errorf("allocate orphan destination for subscription %q", filename)
}
