#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <bundle-dir> <main-source-sha> <agent-source-sha> [--write-checksums]" >&2
  exit 2
fi

BUNDLE_DIR="$1"
MAIN_SOURCE_SHA="$2"
AGENT_SOURCE_SHA="$3"
MODE="${4:-}"

if [ -n "$MODE" ] && [ "$MODE" != "--write-checksums" ]; then
  echo "unknown option: $MODE" >&2
  exit 2
fi

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "release bundle directory does not exist: $BUNDLE_DIR" >&2
  exit 1
fi

EXPECTED_FILES=(
  arcway-linux-amd64
  arcway-linux-arm64
  arcway-darwin-amd64
  arcway-darwin-arm64
  arcway-windows-amd64.exe
  arcway-expiry-guard-linux-amd64
  arcway-expiry-guard-linux-arm64
  relaydock-agent-linux-amd64
  relaydock-agent-linux-arm64
  relaydock-speedtester-linux-amd64
  relaydock-speedtester-linux-arm64
  relaydock-speedtester-windows-amd64.exe
  relaydock-speedtester-windows-arm64.exe
)

for filename in "${EXPECTED_FILES[@]}"; do
  if [ ! -s "$BUNDLE_DIR/$filename" ]; then
    echo "missing or empty release asset: $filename" >&2
    exit 1
  fi
done

EXPECTED_LIST="$(printf '%s\n' "${EXPECTED_FILES[@]}" | LC_ALL=C sort)"
if [ -f "$BUNDLE_DIR/checksums.txt" ]; then
  EXPECTED_LIST="$(printf '%s\nchecksums.txt\n' "$EXPECTED_LIST" | LC_ALL=C sort)"
fi
ACTUAL_LIST="$(find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)"

if [ "$ACTUAL_LIST" != "$EXPECTED_LIST" ]; then
  echo "release bundle contains missing or unexpected files" >&2
  diff -u <(printf '%s\n' "$EXPECTED_LIST") <(printf '%s\n' "$ACTUAL_LIST") >&2 || true
  exit 1
fi

if find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
  echo "release bundle contains unexpected directories" >&2
  find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' >&2
  exit 1
fi

verify_go_binary() {
  local filename="$1"
  local source_sha="$2"
  local expected_goos="$3"
  local expected_goarch="$4"
  local metadata

  metadata="$(go version -m "$BUNDLE_DIR/$filename")"
  printf '%s\n' "$metadata" | grep -Fq "vcs.revision=$source_sha" || {
    echo "$filename was not built from expected revision $source_sha" >&2
    exit 1
  }
  printf '%s\n' "$metadata" | grep -Fq "GOOS=$expected_goos" || {
    echo "$filename has the wrong GOOS; expected $expected_goos" >&2
    exit 1
  }
  printf '%s\n' "$metadata" | grep -Fq "GOARCH=$expected_goarch" || {
    echo "$filename has the wrong GOARCH; expected $expected_goarch" >&2
    exit 1
  }
}

verify_go_binary arcway-linux-amd64 "$MAIN_SOURCE_SHA" linux amd64
verify_go_binary arcway-linux-arm64 "$MAIN_SOURCE_SHA" linux arm64
verify_go_binary arcway-darwin-amd64 "$MAIN_SOURCE_SHA" darwin amd64
verify_go_binary arcway-darwin-arm64 "$MAIN_SOURCE_SHA" darwin arm64
verify_go_binary arcway-windows-amd64.exe "$MAIN_SOURCE_SHA" windows amd64
verify_go_binary arcway-expiry-guard-linux-amd64 "$MAIN_SOURCE_SHA" linux amd64
verify_go_binary arcway-expiry-guard-linux-arm64 "$MAIN_SOURCE_SHA" linux arm64
verify_go_binary relaydock-agent-linux-amd64 "$AGENT_SOURCE_SHA" linux amd64
verify_go_binary relaydock-agent-linux-arm64 "$AGENT_SOURCE_SHA" linux arm64
verify_go_binary relaydock-speedtester-linux-amd64 "$MAIN_SOURCE_SHA" linux amd64
verify_go_binary relaydock-speedtester-linux-arm64 "$MAIN_SOURCE_SHA" linux arm64
verify_go_binary relaydock-speedtester-windows-amd64.exe "$MAIN_SOURCE_SHA" windows amd64
verify_go_binary relaydock-speedtester-windows-arm64.exe "$MAIN_SOURCE_SHA" windows arm64

chmod 0755 \
  "$BUNDLE_DIR"/arcway-linux-* \
  "$BUNDLE_DIR"/arcway-darwin-* \
  "$BUNDLE_DIR"/arcway-expiry-guard-linux-* \
  "$BUNDLE_DIR"/relaydock-agent-linux-* \
  "$BUNDLE_DIR"/relaydock-speedtester-linux-*

if [ "$MODE" = "--write-checksums" ]; then
  (
    cd "$BUNDLE_DIR"
    sha256sum "${EXPECTED_FILES[@]}" > checksums.txt
  )
fi

if [ -f "$BUNDLE_DIR/checksums.txt" ]; then
  (
    cd "$BUNDLE_DIR"
    sha256sum -c checksums.txt
  )
fi

echo "Verified ${#EXPECTED_FILES[@]} release assets."
