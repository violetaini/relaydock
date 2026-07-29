package handler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/violetaini/relaydock/internal/storage"
)

var subscriptionStoreMutex sync.Mutex

// lockSubscriptionStore serializes the subscription database/file boundary
// across goroutines and processes. A single stable lock also covers directory
// scans, so startup recovery cannot race a create, rename, delete or YAML sync.
func lockSubscriptionStore() (func(), error) {
	subscriptionStoreMutex.Lock()
	path, err := subscriptionStoreLockPath()
	if err != nil {
		subscriptionStoreMutex.Unlock()
		return nil, err
	}
	osLock, err := acquireSubscriptionFilenameOSLock(path)
	if err != nil {
		subscriptionStoreMutex.Unlock()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = osLock.Close()
			subscriptionStoreMutex.Unlock()
		})
	}, nil
}

// lockSubscriptionFilenames keeps existing call sites explicit about which
// scope they touch while all scopes use the same store-wide lock. Validating
// here prevents a database-derived filename from becoming a filesystem path.
func lockSubscriptionFilenames(filenames ...string) (func(), error) {
	for _, filename := range filenames {
		filename = strings.TrimSpace(filename)
		if filename == "" {
			continue
		}
		if err := storage.ValidateSubscribeFilename(filename); err != nil {
			return nil, err
		}
	}
	return lockSubscriptionStore()
}

func subscriptionStoreLockPath() (string, error) {
	path := strings.TrimSpace(os.Getenv("ARCWAY_SUBSCRIPTION_STORE_LOCK_PATH"))
	if path == "" {
		root := strings.TrimSpace(os.Getenv("ARCWAY_SUBSCRIPTION_LOCK_DIR"))
		if root == "" {
			root = filepath.Join("data", "locks")
		}
		path = filepath.Join(root, "subscription-store.lock")
	}
	path = filepath.Clean(path)
	if path == "." || filepath.Base(path) == "." {
		return "", errors.New("subscription store lock path is invalid")
	}
	directory := filepath.Dir(path)
	info, statErr := os.Stat(directory)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		if err := os.MkdirAll(directory, 0700); err != nil {
			return "", fmt.Errorf("create subscription lock directory: %w", err)
		}
		if err := os.Chmod(directory, 0700); err != nil {
			return "", fmt.Errorf("restrict subscription lock directory: %w", err)
		}
	case statErr != nil:
		return "", fmt.Errorf("inspect subscription lock directory: %w", statErr)
	case !info.IsDir():
		return "", errors.New("subscription lock parent is not a directory")
	}
	return path, nil
}

func removeSubscriptionFileIfOwned(path string, ownership os.FileInfo) error {
	if ownership == nil {
		return nil
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(ownership, current) {
		return nil
	}
	return os.Remove(path)
}

func canonicalSubscriptionFilenames(ctx context.Context, repo *storage.TrafficRepository) (map[string]struct{}, error) {
	if repo == nil {
		return nil, errors.New("subscription repository is required")
	}
	files, err := repo.ListSubscribeFiles(ctx)
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{}, len(files))
	for _, file := range files {
		result[file.Filename] = struct{}{}
	}
	links, err := repo.ListSubscriptionLinks(ctx)
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		result[link.RuleFilename] = struct{}{}
	}
	return result, nil
}

// deleteSubscribeFileAndPhysical commits the database deletion first. If the
// process stops before physical cleanup, startup recovery quarantines the
// resulting orphan and never recreates its database owner.
func deleteSubscribeFileAndPhysical(ctx context.Context, repo *storage.TrafficRepository, baseDir string, file storage.SubscribeFile) error {
	if repo == nil {
		return errors.New("subscription repository is required")
	}
	if err := storage.ValidateSubscribeFilename(file.Filename); err != nil {
		return err
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		return err
	}
	defer unlock()

	current, err := repo.GetSubscribeFileByID(ctx, file.ID)
	if err != nil {
		return err
	}
	if current.Filename != file.Filename {
		return storage.ErrSubscribeFileChanged
	}
	if err := storage.ValidateSubscribeFilename(current.Filename); err != nil {
		return err
	}

	path := filepath.Join(baseDir, current.Filename)
	var ownership os.FileInfo
	if ownership, err = os.Lstat(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect subscription file before deletion: %w", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		ownership = nil
	}

	if err := repo.DeleteSubscribeFile(ctx, file.ID, current.Filename); err != nil {
		return err
	}
	activeLinks, err := repo.CountSubscriptionsByFilename(ctx, current.Filename)
	if err != nil {
		return fmt.Errorf("check remaining subscription link owners: %w", err)
	}
	if activeLinks > 0 {
		return nil
	}
	if err := removeSubscriptionFileIfOwned(path, ownership); err != nil {
		return fmt.Errorf("remove deleted subscription file: %w", err)
	}
	return nil
}
