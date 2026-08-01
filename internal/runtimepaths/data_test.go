package runtimepaths

import (
	"path/filepath"
	"testing"
)

func TestDataDirectoryUsesAbsoluteEnvironmentOverride(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "arcway-data")
	t.Setenv("ARCWAY_DATA_DIR", directory)

	got, err := DataDirectory()
	if err != nil {
		t.Fatalf("DataDirectory() error = %v", err)
	}
	if got != directory {
		t.Fatalf("DataDirectory() = %q, want %q", got, directory)
	}
}

func TestDataDirectoryRejectsRelativeEnvironmentOverride(t *testing.T) {
	t.Setenv("ARCWAY_DATA_DIR", "relative-data")
	if _, err := DataDirectory(); err == nil {
		t.Fatal("DataDirectory() accepted a relative directory")
	}
}
