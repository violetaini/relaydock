#!/bin/sh
set -eu

readonly GITHUB_RELEASE_DOWNLOAD_BASE="https://github.com/violetaini/relaydock/releases/latest/download"
readonly SERVICE_NAME="relaydock-speedtester"
readonly TARGET="/usr/local/bin/${SERVICE_NAME}"
readonly ENV_FILE="/etc/${SERVICE_NAME}.env"
readonly UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

fail() {
  echo "RelayDock speedtester install failed: $*" >&2
  exit 1
}

[ "$(id -u)" = "0" ] || fail "run this installer as root"
: "${RELAYDOCK_MASTER_URL:?RELAYDOCK_MASTER_URL is required}"
: "${RELAYDOCK_SPEEDTEST_TOKEN:?RELAYDOCK_SPEEDTEST_TOKEN is required}"
: "${RELAYDOCK_SPEEDTEST_NAME:?RELAYDOCK_SPEEDTEST_NAME is required}"

case "$RELAYDOCK_MASTER_URL" in
  http://*|https://*) ;;
  *) fail "RELAYDOCK_MASTER_URL must use http or https" ;;
esac

newline='
'
carriage_return=$(printf '\r')
for value in "$RELAYDOCK_MASTER_URL" "$RELAYDOCK_SPEEDTEST_TOKEN" "$RELAYDOCK_SPEEDTEST_NAME"; do
  case "$value" in
    *"$newline"*|*"$carriage_return"*) fail "environment values must be single-line" ;;
  esac
done

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

download_base=${RELAYDOCK_SPEEDTESTER_DOWNLOAD_BASE:-$GITHUB_RELEASE_DOWNLOAD_BASE}
asset="relaydock-speedtester-linux-${arch}"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
binary="$tmp_dir/$asset"
checksums="$tmp_dir/checksums.txt"

download() {
  url=$1
  destination=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$destination"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$destination" "$url"
  else
    fail "curl or wget is required"
  fi
}

download "$download_base/checksums.txt" "$checksums"
download "$download_base/$asset" "$binary"
[ -s "$binary" ] || fail "downloaded binary is empty"

expected_sha=$(awk -v name="$asset" '$2 == name { print $1; exit }' "$checksums")
printf '%s' "$expected_sha" | grep -Eq '^[0-9a-fA-F]{64}$' || fail "release checksum is missing for $asset"
if command -v sha256sum >/dev/null 2>&1; then
  actual_sha=$(sha256sum "$binary" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
  actual_sha=$(shasum -a 256 "$binary" | awk '{ print $1 }')
else
  fail "sha256sum or shasum is required"
fi
[ "$actual_sha" = "$expected_sha" ] || fail "downloaded binary checksum does not match the GitHub Release"

staged_binary=$(mktemp "$(dirname "$TARGET")/.${SERVICE_NAME}.XXXXXX")
trap 'rm -rf "$tmp_dir" "$staged_binary"' EXIT HUP INT TERM
install -m 0755 "$binary" "$staged_binary"
mv -f "$staged_binary" "$TARGET"

umask 077
escape_env() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}
{
  printf 'RELAYDOCK_MASTER_URL="%s"\n' "$(escape_env "$RELAYDOCK_MASTER_URL")"
  printf 'RELAYDOCK_SPEEDTEST_TOKEN="%s"\n' "$(escape_env "$RELAYDOCK_SPEEDTEST_TOKEN")"
  printf 'RELAYDOCK_SPEEDTEST_NAME="%s"\n' "$(escape_env "$RELAYDOCK_SPEEDTEST_NAME")"
} > "$ENV_FILE"
chmod 0600 "$ENV_FILE"

cat > "$UNIT_FILE" <<'UNIT'
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
systemctl enable "$SERVICE_NAME.service"
if systemctl is-active --quiet "$SERVICE_NAME.service"; then
  systemctl restart "$SERVICE_NAME.service"
else
  systemctl start "$SERVICE_NAME.service"
fi
systemctl is-active --quiet "$SERVICE_NAME.service" || fail "service did not start"
echo "RelayDock speedtester installed from GitHub Release"
