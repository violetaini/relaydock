//go:build !windows

package handler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// productWebLock uses the exact lock file used by scripts/deploy-frontend.sh.
// It prevents a manual deploy from racing a panel transaction at the two
// current/previous symlink swaps, while leaving ordinary static serving
// completely lock-free.
type productWebLock struct {
	file *os.File
}

func acquireProductWebLock(root string) (*productWebLock, error) {
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("unsafe managed frontend root: %s", root)
	}
	path := filepath.Join(root, ".deploy.lock")
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, fmt.Errorf("unsafe frontend deployment lock: %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errUpdateBusy
		}
		return nil, err
	}
	return &productWebLock{file: file}, nil
}

func (lock *productWebLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(err, closeErr)
}
