//go:build windows

package handler

// Windows does not support in-place panel updates, but this stub keeps the
// updater package cross-compilable for release assembly.
type productWebLock struct{}

func acquireProductWebLock(string) (*productWebLock, error) { return &productWebLock{}, nil }
func (lock *productWebLock) Close() error                   { return nil }
