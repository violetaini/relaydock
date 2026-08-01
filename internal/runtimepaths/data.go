// Package runtimepaths centralizes process-local storage locations shared by
// the control plane and its isolated update helper.
package runtimepaths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// DataDirectory returns the directory containing the control plane database
// and persistent keys. Both the main service and update helper must use this
// resolver so a rollback snapshots the database the service actually opens.
func DataDirectory() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("ARCWAY_DATA_DIR")); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", errors.New("ARCWAY_DATA_DIR must be an absolute path")
		}
		return filepath.Clean(configured), nil
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(workingDirectory, "data"), nil
}
