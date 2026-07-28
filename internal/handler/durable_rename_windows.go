//go:build windows

package handler

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func syncRenamedFileDirectory(path string) error {
	directory, err := windows.UTF16PtrFromString(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("encode renamed file directory: %w", err)
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
		return fmt.Errorf("open renamed file directory: %w", err)
	}
	defer windows.CloseHandle(handle)
	if err := windows.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("flush renamed file directory: %w", err)
	}
	return nil
}
