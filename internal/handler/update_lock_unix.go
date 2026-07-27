//go:build !windows

package handler

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

const defaultSystemUpdateLockPath = "/run/arcway-install.lock"

type systemUpdateLock struct {
	file *os.File
}

func acquireSystemUpdateLock() (*systemUpdateLock, error) {
	path := strings.TrimSpace(os.Getenv("ARCWAY_INSTALL_LOCK_FILE"))
	if path == "" {
		path = defaultSystemUpdateLockPath
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("打开安装锁 %s: %w", path, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w", errUpdateBusy)
		}
		return nil, fmt.Errorf("获取安装锁 %s: %w", path, err)
	}
	return &systemUpdateLock{file: file}, nil
}

func (lock *systemUpdateLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(err, closeErr)
}
