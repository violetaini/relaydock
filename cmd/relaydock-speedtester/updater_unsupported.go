//go:build !linux && !windows

package main

import "fmt"

func replaceSelfExecutable(_, _ string) error {
	return fmt.Errorf("automatic speedtester replacement is unsupported on this operating system")
}
