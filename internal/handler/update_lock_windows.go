//go:build windows

package handler

// Windows cannot apply web updates, but this stub keeps cross-compilation working.
type systemUpdateLock struct{}

func acquireSystemUpdateLock() (*systemUpdateLock, error) {
	return &systemUpdateLock{}, nil
}

func (lock *systemUpdateLock) Close() error {
	return nil
}
