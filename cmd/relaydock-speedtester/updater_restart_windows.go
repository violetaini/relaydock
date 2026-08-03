//go:build windows

package main

// The Windows replacement helper waits for this process to exit and launches
// the new executable itself.
func restartAfterSelfUpdate() (bool, error) {
	return true, nil
}
