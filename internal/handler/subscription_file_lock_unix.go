//go:build !windows

package handler

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

type subscriptionFilenameOSLock struct {
	file *os.File
}

func acquireSubscriptionFilenameOSLock(path string) (*subscriptionFilenameOSLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open subscription filename lock: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict subscription filename lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock subscription filename: %w", err)
	}
	return &subscriptionFilenameOSLock{file: file}, nil
}

func (lock *subscriptionFilenameOSLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(err, closeErr)
}
