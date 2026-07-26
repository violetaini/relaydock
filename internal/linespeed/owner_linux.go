//go:build linux

package linespeed

import (
	"os"
	"syscall"
)

func trustedFileOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == 0 || int(stat.Uid) == os.Geteuid()
}
