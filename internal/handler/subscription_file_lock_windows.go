//go:build windows

package handler

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type subscriptionFilenameOSLock struct {
	handle windows.Handle
}

func acquireSubscriptionFilenameOSLock(path string) (*subscriptionFilenameOSLock, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve subscription filename lock: %w", err)
	}
	digest := sha256.Sum256([]byte(absolute))
	name, err := windows.UTF16PtrFromString("Global\\ArcwaySubscription-" + fmt.Sprintf("%x", digest))
	if err != nil {
		return nil, fmt.Errorf("encode subscription filename lock: %w", err)
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return nil, fmt.Errorf("create subscription filename mutex: %w", err)
	}
	status, err := windows.WaitForSingleObject(handle, windows.INFINITE)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wait for subscription filename mutex: %w", err)
	}
	if status != windows.WAIT_OBJECT_0 && status != windows.WAIT_ABANDONED {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wait for subscription filename mutex: status=%d", status)
	}
	return &subscriptionFilenameOSLock{handle: handle}, nil
}

func (lock *subscriptionFilenameOSLock) Close() error {
	if lock == nil || lock.handle == 0 {
		return nil
	}
	releaseErr := windows.ReleaseMutex(lock.handle)
	closeErr := windows.CloseHandle(lock.handle)
	lock.handle = 0
	if releaseErr != nil {
		return releaseErr
	}
	return closeErr
}
