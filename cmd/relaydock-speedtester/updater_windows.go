//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// replaceSelfExecutable cannot rename over a running .exe. It starts a small
// adjacent cmd script which waits for this process to exit, replaces the file,
// then launches the replacement. The strict path check keeps cmd metacharacters
// out of the generated script; unusual install paths fall back to the normal
// installer rather than risking an unsafe command.
func replaceSelfExecutable(temporaryPath, executablePath string) error {
	if !windowsUpdatePathSafe(temporaryPath) || !windowsUpdatePathSafe(executablePath) {
		return fmt.Errorf("automatic replacement is unavailable for this Windows install path; run the published installer once")
	}

	script, err := os.CreateTemp(filepath.Dir(executablePath), ".relaydock-speedtester-update-*.cmd")
	if err != nil {
		return fmt.Errorf("create Windows update helper: %w", err)
	}
	scriptPath := script.Name()
	if !windowsUpdatePathSafe(scriptPath) {
		_ = script.Close()
		_ = os.Remove(scriptPath)
		return fmt.Errorf("automatic replacement is unavailable for this Windows install path; run the published installer once")
	}

	contents := "@echo off\r\n" +
		"setlocal DisableDelayedExpansion\r\n" +
		":wait_for_speedtester\r\n" +
		"tasklist /FI \"PID eq " + strconv.Itoa(os.Getpid()) + "\" /NH | findstr /R /C:\"[ ]" + strconv.Itoa(os.Getpid()) + "[ ]\" >nul\r\n" +
		"if not errorlevel 1 (\r\n" +
		"  timeout /t 1 /nobreak >nul\r\n" +
		"  goto wait_for_speedtester\r\n" +
		")\r\n" +
		"move /Y \"" + temporaryPath + "\" \"" + executablePath + "\" >nul\r\n" +
		"if errorlevel 1 exit /b 1\r\n" +
		"start \"\" \"" + executablePath + "\"\r\n" +
		"del \"%~f0\"\r\n"
	if _, err := script.WriteString(contents); err != nil {
		_ = script.Close()
		_ = os.Remove(scriptPath)
		return fmt.Errorf("write Windows update helper: %w", err)
	}
	if err := script.Close(); err != nil {
		_ = os.Remove(scriptPath)
		return fmt.Errorf("close Windows update helper: %w", err)
	}
	if err := exec.Command("cmd.exe", "/D", "/S", "/C", `"`+scriptPath+`"`).Start(); err != nil {
		_ = os.Remove(scriptPath)
		return fmt.Errorf("start Windows update helper: %w", err)
	}
	return nil
}

func windowsUpdatePathSafe(path string) bool {
	if path == "" || strings.ContainsAny(path, "\"&|<>^%!()\r\n") {
		return false
	}
	return filepath.IsAbs(path)
}
