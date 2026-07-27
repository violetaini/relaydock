//go:build windows

package handler

import "errors"

func replaceCurrentProcess(string, []string, []string) error {
	return errors.New("Windows 不支持网页内原地更新")
}
