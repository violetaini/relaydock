//go:build windows

package util

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// SyncDir flushes directory metadata to disk on Windows using FlushFileBuffers.
func SyncDir(dirPath string) error {
	cleanPath, err := filepath.Abs(dirPath)
	if err != nil {
		cleanPath = dirPath
	}
	directory, err := windows.UTF16PtrFromString(cleanPath)
	if err != nil {
		return fmt.Errorf("encode directory path: %w", err)
	}
	handle, err := windows.CreateFile(
		directory,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(handle)
	_ = windows.FlushFileBuffers(handle)
	return nil
}
