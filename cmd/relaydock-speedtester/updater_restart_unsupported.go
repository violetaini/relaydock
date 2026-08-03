//go:build !linux && !windows

package main

import "fmt"

func restartAfterSelfUpdate() (bool, error) {
	return false, fmt.Errorf("automatic speedtester restart is unsupported on this operating system")
}
