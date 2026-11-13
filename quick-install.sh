#!/usr/bin/env bash
set -euo pipefail

# RelayDock One-Click Bootstrap Script
INSTALL_URL="https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh"
MIRROR_URL="https://mirror.ghproxy.com/https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh"

TMP_DIR="$(mktemp -d /tmp/relaydock-quick-install.XXXXXX)"
chmod 0700 "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

download_installer() {
    local target="$TMP_DIR/install.sh"
    if command -v curl >/dev/null 2>&1; then
        if curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 8 "$INSTALL_URL" -o "$target"; then
            return 0
        fi
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 "$MIRROR_URL" -o "$target" && return 0
    elif command -v wget >/dev/null 2>&1; then
        if wget -q --timeout=8 "$INSTALL_URL" -O "$target"; then
            return 0
        fi
        wget -q --timeout=10 "$MIRROR_URL" -O "$target" && return 0
    else
        printf 'ERROR: curl 或 wget 至少需要安装一个\n' >&2
        return 1
    fi
    return 1
}

download_installer
bash -n "$TMP_DIR/install.sh"

# 如果是通过管道 curl | bash 运行，尝试重新绑定标准输入到终端，保证交互菜单可用
if [ ! -t 0 ]; then
    { exec </dev/tty; } 2>/dev/null || true
fi

bash "$TMP_DIR/install.sh" "$@"
