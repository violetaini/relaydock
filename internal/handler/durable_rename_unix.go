//go:build !windows

package handler

import (
	"fmt"
	"os"
	"path/filepath"
)

func syncRenamedFileDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open renamed file directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync renamed file directory: %w", err)
	}
	return nil
}
