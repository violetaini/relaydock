package handler

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const speedtesterAssetDirEnv = "ARCWAY_SPEEDTESTER_ASSET_DIR"

var errSpeedtesterAssetNotFound = errors.New("speedtester asset not found")

// SpeedtesterAssetHandler serves self-contained installers and platform binaries.
// The installers download from the same control plane that generated the command.
type SpeedtesterAssetHandler struct{}

func NewSpeedtesterAssetHandler() *SpeedtesterAssetHandler { return &SpeedtesterAssetHandler{} }

func (h *SpeedtesterAssetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch r.URL.Path {
	case "/api/public/relaydock-speedtester/install.sh":
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write([]byte(speedtesterInstallShell))
	case "/api/public/relaydock-speedtester/install.ps1":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(speedtesterInstallPowerShell))
	case "/api/public/relaydock-speedtester/binary":
		h.serveBinary(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *SpeedtesterAssetHandler) serveBinary(w http.ResponseWriter, r *http.Request) {
	operatingSystem := strings.TrimSpace(r.URL.Query().Get("os"))
	arch := strings.TrimSpace(r.URL.Query().Get("arch"))
	if (operatingSystem != "linux" && operatingSystem != "windows") || (arch != "amd64" && arch != "arm64") {
		http.Error(w, "Unsupported platform", http.StatusBadRequest)
		return
	}
	name := fmt.Sprintf("relaydock-speedtester-%s-%s", operatingSystem, arch)
	if operatingSystem == "windows" {
		name += ".exe"
	}
	asset, err := openSpeedtesterAsset(name)
	if errors.Is(err, errSpeedtesterAssetNotFound) {
		http.Error(w, "Speedtester asset unavailable", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Speedtester asset unavailable", http.StatusInternalServerError)
		return
	}
	defer asset.Close()
	info, err := asset.Stat()
	if err != nil {
		http.Error(w, "Speedtester asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	http.ServeContent(w, r, name, info.ModTime(), asset)
}

func speedtesterAssetDirectories() []string {
	directories := make([]string, 0, 4)
	if configured := strings.TrimSpace(os.Getenv(speedtesterAssetDirEnv)); configured != "" {
		directories = append(directories, configured)
	}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		directories = append(directories, filepath.Join(directory, "speedtester-assets"))
	}
	if workingDirectory, err := os.Getwd(); err == nil {
		directories = append(directories, filepath.Join(workingDirectory, "speedtester-assets"))
	}

	seen := make(map[string]struct{}, len(directories))
	unique := make([]string, 0, len(directories))
	for _, directory := range directories {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			continue
		}
		absolute = filepath.Clean(absolute)
		if _, exists := seen[absolute]; exists {
			continue
		}
		seen[absolute] = struct{}{}
		unique = append(unique, absolute)
	}
	return unique
}

func openSpeedtesterAsset(name string) (*os.File, error) {
	allowed := map[string]bool{
		"relaydock-speedtester-linux-amd64":       true,
		"relaydock-speedtester-linux-arm64":       true,
		"relaydock-speedtester-windows-amd64.exe": true,
		"relaydock-speedtester-windows-arm64.exe": true,
	}
	if !allowed[name] {
		return nil, errSpeedtesterAssetNotFound
	}
	for _, directory := range speedtesterAssetDirectories() {
		path := filepath.Join(directory, name)
		linkInfo, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect speedtester asset: %w", err)
		}
		if !linkInfo.Mode().IsRegular() {
			return nil, errors.New("speedtester asset is not a regular file")
		}
		asset, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open speedtester asset: %w", err)
		}
		openedInfo, err := asset.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
			_ = asset.Close()
			return nil, errors.New("speedtester asset changed while opening")
		}
		return asset, nil
	}
	return nil, errSpeedtesterAssetNotFound
}

const speedtesterInstallShell = `#!/bin/sh
set -eu

fail() { echo "RelayDock speedtester install failed: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "run this installer as root"
: "${RELAYDOCK_MASTER_URL:?RELAYDOCK_MASTER_URL is required}"
: "${RELAYDOCK_SPEEDTEST_TOKEN:?RELAYDOCK_SPEEDTEST_TOKEN is required}"
: "${RELAYDOCK_SPEEDTEST_NAME:?RELAYDOCK_SPEEDTEST_NAME is required}"

case "$RELAYDOCK_MASTER_URL" in http://*|https://*) ;; *) fail "RELAYDOCK_MASTER_URL must use http or https" ;; esac
for value in "$RELAYDOCK_MASTER_URL" "$RELAYDOCK_SPEEDTEST_TOKEN" "$RELAYDOCK_SPEEDTEST_NAME"; do
    case "$value" in *'
'*|*''*) fail "environment values must be single-line" ;; esac
done

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac

TMP_FILE=$(mktemp)
trap 'rm -f "$TMP_FILE"' EXIT HUP INT TERM
DOWNLOAD_URL="${RELAYDOCK_MASTER_URL%/}/api/public/relaydock-speedtester/binary?os=linux&arch=${ARCH}"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$TMP_FILE"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_FILE" "$DOWNLOAD_URL"
else
    fail "curl or wget is required"
fi
[ -s "$TMP_FILE" ] || fail "downloaded binary is empty"

install -m 0755 "$TMP_FILE" /usr/local/bin/relaydock-speedtester
umask 077
escape_env() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
{
    printf 'RELAYDOCK_MASTER_URL="%s"\n' "$(escape_env "$RELAYDOCK_MASTER_URL")"
    printf 'RELAYDOCK_SPEEDTEST_TOKEN="%s"\n' "$(escape_env "$RELAYDOCK_SPEEDTEST_TOKEN")"
    printf 'RELAYDOCK_SPEEDTEST_NAME="%s"\n' "$(escape_env "$RELAYDOCK_SPEEDTEST_NAME")"
} > /etc/relaydock-speedtester.env
chmod 0600 /etc/relaydock-speedtester.env

cat > /etc/systemd/system/relaydock-speedtester.service <<'UNIT'
[Unit]
Description=RelayDock Speedtester
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/relaydock-speedtester.env
ExecStart=/usr/local/bin/relaydock-speedtester
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now relaydock-speedtester.service
systemctl is-active --quiet relaydock-speedtester.service || fail "service did not start"
echo "RelayDock speedtester installed"
`

const speedtesterInstallPowerShell = `#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

$master = [Environment]::GetEnvironmentVariable("RELAYDOCK_MASTER_URL", "Process")
$token = [Environment]::GetEnvironmentVariable("RELAYDOCK_SPEEDTEST_TOKEN", "Process")
$name = [Environment]::GetEnvironmentVariable("RELAYDOCK_SPEEDTEST_NAME", "Process")
if ([string]::IsNullOrWhiteSpace($master) -or [string]::IsNullOrWhiteSpace($token) -or [string]::IsNullOrWhiteSpace($name)) {
    throw "RELAYDOCK_MASTER_URL, RELAYDOCK_SPEEDTEST_TOKEN and RELAYDOCK_SPEEDTEST_NAME are required"
}
if ($master -notmatch '^https?://') { throw "RELAYDOCK_MASTER_URL must use http or https" }

$machineArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$arch = switch ($machineArch) {
    "x64" { "amd64" }
    "arm64" { "arm64" }
    default { throw "Unsupported architecture: $machineArch" }
}

$installDir = Join-Path $env:ProgramData "RelayDock\Speedtester"
$target = Join-Path $installDir "relaydock-speedtester.exe"
$download = "$($master.TrimEnd('/'))/api/public/relaydock-speedtester/binary?os=windows&arch=$arch"
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("relaydock-speedtester-" + [guid]::NewGuid().ToString("N") + ".exe")
try {
    Invoke-WebRequest -UseBasicParsing -Uri $download -OutFile $temporary
    if ((Get-Item $temporary).Length -le 0) { throw "Downloaded binary is empty" }
    Get-Process -Name "relaydock-speedtester" -ErrorAction SilentlyContinue | Stop-Process -Force
    Move-Item -Path $temporary -Destination $target -Force
} finally {
    Remove-Item $temporary -Force -ErrorAction SilentlyContinue
}

[Environment]::SetEnvironmentVariable("RELAYDOCK_MASTER_URL", $master, "Machine")
[Environment]::SetEnvironmentVariable("RELAYDOCK_SPEEDTEST_TOKEN", $token, "Machine")
[Environment]::SetEnvironmentVariable("RELAYDOCK_SPEEDTEST_NAME", $name, "Machine")
$taskCommand = '"' + $target + '"'
& schtasks.exe /Create /TN "RelayDock Speedtester" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR $taskCommand /F | Out-Null
Start-Process -FilePath $target -WindowStyle Hidden
Write-Host "RelayDock speedtester installed"
`
