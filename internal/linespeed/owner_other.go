//go:build !linux

package linespeed

import "os"

func trustedFileOwner(os.FileInfo) bool {
	return false
}
