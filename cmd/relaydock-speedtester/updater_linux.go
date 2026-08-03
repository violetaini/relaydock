//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func replaceSelfExecutable(temporaryPath, executablePath string) error {
	if err := os.Rename(temporaryPath, executablePath); err != nil {
		return fmt.Errorf("atomically replace running executable: %w", err)
	}
	// A rename is durable only after the containing directory is synced. Failure
	// here is reported even though the new binary is already usable.
	directory, err := os.Open(filepath.Dir(executablePath))
	if err != nil {
		return fmt.Errorf("open executable directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync executable directory: %w", err)
	}
	return nil
}
