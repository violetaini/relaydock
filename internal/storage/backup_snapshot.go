package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CreateConsistentSnapshot writes a transactionally consistent, standalone
// copy of the live SQLite database. VACUUM INTO reads from one SQLite snapshot,
// so commits that occur while it runs cannot produce a database assembled from
// mismatched main-file and WAL states.
//
// The returned cleanup function removes the private staging directory and is
// safe to call more than once.
func (r *TrafficRepository) CreateConsistentSnapshot(ctx context.Context) (snapshotPath string, cleanup func(), returnErr error) {
	if r == nil || r.db == nil {
		return "", nil, errors.New("traffic repository not initialized")
	}
	if ctx == nil {
		return "", nil, errors.New("snapshot context is required")
	}

	directory, err := os.MkdirTemp("", "arcway-db-snapshot-*")
	if err != nil {
		return "", nil, fmt.Errorf("create database snapshot directory: %w", err)
	}
	cleanupDirectory := func() { _ = os.RemoveAll(directory) }
	cleanup = cleanupDirectory
	defer func() {
		if returnErr != nil {
			cleanupDirectory()
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", nil, fmt.Errorf("restrict database snapshot directory: %w", err)
	}

	snapshotPath = filepath.Join(directory, "arcway.db")
	file, err := os.OpenFile(snapshotPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, fmt.Errorf("reserve database snapshot file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", nil, fmt.Errorf("close reserved database snapshot file: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `VACUUM INTO ?`, snapshotPath); err != nil {
		return "", nil, fmt.Errorf("create consistent database snapshot: %w", err)
	}
	if err := os.Chmod(snapshotPath, 0o600); err != nil {
		return "", nil, fmt.Errorf("restrict database snapshot: %w", err)
	}
	return snapshotPath, cleanup, nil
}
