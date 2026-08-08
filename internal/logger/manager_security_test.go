package logger

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLogFileRejectsTraversalAndSymlinks(t *testing.T) {
	base := t.TempDir()
	manager := NewLogManager(base)
	valid := filepath.Join(base, "log_valid.txt")
	if err := os.WriteFile(valid, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := manager.ResolveLogFile("log_valid.txt")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != valid {
		t.Fatalf("resolved path = %q, want %q", resolved, valid)
	}

	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "log_link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	for _, filename := range []string{
		"../log_outside.txt",
		"log_/../../outside.txt",
		"other.txt",
		"log_link.txt",
	} {
		if _, err := manager.ResolveLogFile(filename); !errors.Is(err, ErrInvalidLogFilename) {
			t.Fatalf("ResolveLogFile(%q) error = %v", filename, err)
		}
	}
}
