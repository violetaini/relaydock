//go:build linux

package main

import (
	"os"
	"syscall"
)

// restartAfterSelfUpdate replaces this process image with the executable that
// was atomically renamed into place. syscall.Exec only returns on failure.
func restartAfterSelfUpdate() (bool, error) {
	executable, err := os.Executable()
	if err != nil {
		return false, err
	}
	return false, syscall.Exec(executable, os.Args, os.Environ())
}
