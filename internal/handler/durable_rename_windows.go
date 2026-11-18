//go:build windows

package handler

import (
	"fmt"
	"path/filepath"

	"github.com/violetaini/relaydock/internal/util"
)

func syncRenamedFileDirectory(path string) error {
	if err := util.SyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("flush renamed file directory: %w", err)
	}
	return nil
}
