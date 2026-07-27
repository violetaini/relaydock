//go:build !windows

package handler

import "syscall"

func replaceCurrentProcess(path string, args, env []string) error {
	return syscall.Exec(path, args, env)
}
