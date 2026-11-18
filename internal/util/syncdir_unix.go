//go:build !windows

package util

import (
	"fmt"
	"os"
)

// SyncDir flushes directory metadata to disk on POSIX systems.
func SyncDir(dirPath string) error {
	directory, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
