#!/usr/bin/env bash
set -euo pipefail

INSTALL_URL="https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh"
TMP_DIR="$(mktemp -d /tmp/arcway-quick-install.XXXXXX)"
chmod 0700 "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL "$INSTALL_URL" -o "$TMP_DIR/install.sh"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$INSTALL_URL" -O "$TMP_DIR/install.sh"
else
    printf 'ERROR: curl 或 wget 至少需要安装一个\n' >&2
    exit 1
fi

bash -n "$TMP_DIR/install.sh"
bash "$TMP_DIR/install.sh" "$@"
