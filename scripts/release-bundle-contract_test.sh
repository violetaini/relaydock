#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WEB_BUILDER="$SCRIPT_DIR/build-release-web-bundle.sh"
VERIFIER="$SCRIPT_DIR/verify-release-bundle.sh"

MAIN_COMMIT=0123456789abcdef0123456789abcdef01234567
AGENT_COMMIT=89abcdef0123456789abcdef0123456789abcdef
RELEASE_TAG=v1.2.3

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/relaydock-release-contract.XXXXXXXX")"
PARSER_DIR=""
cleanup() {
  rm -rf -- "$TEST_ROOT"
  if [ -n "$PARSER_DIR" ]; then
    rm -rf -- "$PARSER_DIR"
  fi
}
trap cleanup EXIT

BUNDLE_DIR="$TEST_ROOT/bundle"
FAKE_BIN_DIR="$TEST_ROOT/bin"
EXTRACT_DIR="$TEST_ROOT/extracted"
mkdir -p "$BUNDLE_DIR" "$FAKE_BIN_DIR" "$EXTRACT_DIR"

"$WEB_BUILDER" \
  "$PROJECT_ROOT/internal/web/dist" \
  "$BUNDLE_DIR/relaydock-web.tar.gz" \
  "$RELEASE_TAG" \
  "$MAIN_COMMIT" \
  1
"$WEB_BUILDER" \
  "$PROJECT_ROOT/internal/web/dist" \
  "$TEST_ROOT/second-relaydock-web.tar.gz" \
  "$RELEASE_TAG" \
  "$MAIN_COMMIT" \
  1
cmp -s "$BUNDLE_DIR/relaydock-web.tar.gz" "$TEST_ROOT/second-relaydock-web.tar.gz" || {
  echo "deterministic frontend archive bytes changed between equivalent builds" >&2
  exit 1
}

tar -xzf "$BUNDLE_DIR/relaydock-web.tar.gz" -C "$EXTRACT_DIR"
grep -Fq '"schema": 1' "$EXTRACT_DIR/relaydock-release.json"
grep -Fq '"release_id": "v1.2.3"' "$EXTRACT_DIR/relaydock-release.json"
grep -Fq "\"backend_commit\": \"$MAIN_COMMIT\"" "$EXTRACT_DIR/relaydock-release.json"
grep -Fq '"api_contract": 1' "$EXTRACT_DIR/relaydock-release.json"

COMPONENT_ASSETS=(
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
for asset in "${COMPONENT_ASSETS[@]}"; do
  printf 'test asset: %s\n' "$asset" >"$BUNDLE_DIR/$asset"
done

cat >"$FAKE_BIN_DIR/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ] || [ "$1" != "version" ] || [ "$2" != "-m" ]; then
  echo "unexpected fake go invocation: $*" >&2
  exit 2
fi

asset="$(basename "$3")"
case "$asset" in
  arcway-linux-amd64|arcway-expiry-guard-linux-amd64|relaydock-speedtester-linux-amd64)
    source="$TEST_MAIN_COMMIT"; goos=linux; goarch=amd64 ;;
  arcway-linux-arm64|arcway-expiry-guard-linux-arm64|relaydock-speedtester-linux-arm64)
    source="$TEST_MAIN_COMMIT"; goos=linux; goarch=arm64 ;;
  arcway-darwin-amd64)
    source="$TEST_MAIN_COMMIT"; goos=darwin; goarch=amd64 ;;
  arcway-darwin-arm64)
    source="$TEST_MAIN_COMMIT"; goos=darwin; goarch=arm64 ;;
  arcway-windows-amd64.exe|relaydock-speedtester-windows-amd64.exe)
    source="$TEST_MAIN_COMMIT"; goos=windows; goarch=amd64 ;;
  relaydock-speedtester-windows-arm64.exe)
    source="$TEST_MAIN_COMMIT"; goos=windows; goarch=arm64 ;;
  relaydock-agent-linux-amd64)
    source="$TEST_AGENT_COMMIT"; goos=linux; goarch=amd64 ;;
  relaydock-agent-linux-arm64)
    source="$TEST_AGENT_COMMIT"; goos=linux; goarch=arm64 ;;
  *)
    echo "unknown release asset: $asset" >&2
    exit 2 ;;
esac

printf 'path\t%s\n' "$asset"
printf 'build\tvcs.revision=%s\n' "$source"
printf 'build\tGOOS=%s\n' "$goos"
printf 'build\tGOARCH=%s\n' "$goarch"
EOF
chmod 0755 "$FAKE_BIN_DIR/go"

TEST_MAIN_COMMIT="$MAIN_COMMIT" \
TEST_AGENT_COMMIT="$AGENT_COMMIT" \
PATH="$FAKE_BIN_DIR:$PATH" \
  "$VERIFIER" \
    "$BUNDLE_DIR" \
    "$MAIN_COMMIT" \
    "$AGENT_COMMIT" \
    --release-tag "$RELEASE_TAG" \
    --api-contract 1 \
    --write-manifest \
    --write-checksums

grep -Fq '"release_id": "v1.2.3"' "$BUNDLE_DIR/relaydock-release-manifest.json"
grep -Fq "\"backend_commit\": \"$MAIN_COMMIT\"" "$BUNDLE_DIR/relaydock-release-manifest.json"
grep -Fq "\"agent_commit\": \"$AGENT_COMMIT\"" "$BUNDLE_DIR/relaydock-release-manifest.json"
grep -Fq '"control_plane": {' "$BUNDLE_DIR/relaydock-release-manifest.json"
grep -Fq '"web": {' "$BUNDLE_DIR/relaydock-release-manifest.json"
grep -Fq '"version": "1.2.3"' "$BUNDLE_DIR/relaydock-release-manifest.json"
grep -Fq '"changed": true' "$BUNDLE_DIR/relaydock-release-manifest.json"
grep -Fq '"size": ' "$BUNDLE_DIR/relaydock-release-manifest.json"
grep -Fq 'relaydock-web.tar.gz' "$BUNDLE_DIR/checksums.txt"
grep -Fq 'relaydock-release-manifest.json' "$BUNDLE_DIR/checksums.txt"

node - "$BUNDLE_DIR/relaydock-release-manifest.json" <<'NODE'
const fs = require("fs");

const manifest = JSON.parse(fs.readFileSync(process.argv.at(-1), "utf8"));
const components = manifest.components;
const expected = {
  control_plane: ["1.2.3", 5],
  web: ["v1.2.3", 1],
  guard_assets: ["1.2.3", 2],
  agent_install_assets: ["89abcdef0123456789abcdef0123456789abcdef", 2],
  speedtester_assets: ["1.2.3", 4],
};

if (manifest.schema !== 1 || manifest.release_id !== "v1.2.3" ||
    manifest.backend_commit !== "0123456789abcdef0123456789abcdef01234567" ||
    manifest.api_contract !== 1 || Object.keys(components).length !== Object.keys(expected).length) {
  throw new Error("unexpected release manifest header");
}
for (const [name, [version, assetCount]] of Object.entries(expected)) {
  const component = components[name];
  if (!component || component.version !== version || component.api_contract !== 1 || component.changed !== true || component.assets.length !== assetCount) {
    throw new Error(`unexpected ${name} component`);
  }
  for (const asset of component.assets) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(asset.name) || !/^[a-f0-9]{64}$/.test(asset.sha256) || !Number.isInteger(asset.size) || asset.size < 1) {
      throw new Error(`invalid asset in ${name}`);
    }
  }
}
NODE

if command -v go >/dev/null 2>&1; then
  PARSER_DIR="$(mktemp -d "$PROJECT_ROOT/.release-contract-parser.XXXXXXXX")"
  cat >"$PARSER_DIR/main.go" <<'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/violetaini/relaydock/internal/productrelease"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	manifest, err := productrelease.Parse(raw)
	if err != nil {
		panic(err)
	}
	control := manifest.Components[productrelease.ComponentControlPlane]
	web := manifest.Components[productrelease.ComponentWeb]
	if manifest.ReleaseID != "v1.2.3" || control.Version != "1.2.3" || !control.Changed || len(web.Assets) != 1 || web.Assets[0].Name != "relaydock-web.tar.gz" || web.Assets[0].Size < 1 || len(manifest.AssetNames()) != 14 {
		panic(fmt.Sprintf("unexpected manifest: %+v", manifest))
	}
	metadataRaw, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	var metadata productrelease.WebMetadata
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		panic(err)
	}
	if err := metadata.Validate(); err != nil || metadata.ReleaseID != manifest.ReleaseID || metadata.APIContract != web.APIContract {
		panic(fmt.Sprintf("unexpected web metadata: %+v, %v", metadata, err))
	}
}
EOF
  (
    cd "$PROJECT_ROOT"
    go run "$PARSER_DIR/main.go" "$BUNDLE_DIR/relaydock-release-manifest.json" "$EXTRACT_DIR/relaydock-release.json"
  )
else
  echo "Go is unavailable; validated the release manifest structure without the Go parser." >&2
fi

TEST_MAIN_COMMIT="$MAIN_COMMIT" \
TEST_AGENT_COMMIT="$AGENT_COMMIT" \
PATH="$FAKE_BIN_DIR:$PATH" \
  "$VERIFIER" \
    "$BUNDLE_DIR" \
    "$MAIN_COMMIT" \
    "$AGENT_COMMIT" \
    --release-tag "$RELEASE_TAG" \
    --api-contract 1

if RELAYDOCK_RELEASE_SCOPE=frontend-only \
  TEST_MAIN_COMMIT="$MAIN_COMMIT" \
  TEST_AGENT_COMMIT="$AGENT_COMMIT" \
  PATH="$FAKE_BIN_DIR:$PATH" \
  "$VERIFIER" \
    "$BUNDLE_DIR" \
    "$MAIN_COMMIT" \
    "$AGENT_COMMIT" \
    --release-tag "$RELEASE_TAG" \
    --api-contract 1 \
    --write-manifest >/dev/null 2>&1; then
  echo "verifier accepted an unsafe frontend-only stable release" >&2
  exit 1
fi

printf 'unexpected\n' >"$BUNDLE_DIR/unexpected-asset"
if TEST_MAIN_COMMIT="$MAIN_COMMIT" \
  TEST_AGENT_COMMIT="$AGENT_COMMIT" \
  PATH="$FAKE_BIN_DIR:$PATH" \
  "$VERIFIER" \
    "$BUNDLE_DIR" \
    "$MAIN_COMMIT" \
    "$AGENT_COMMIT" \
    --release-tag "$RELEASE_TAG" \
    --api-contract 1 >/dev/null 2>&1; then
  echo "verifier accepted an unexpected release asset" >&2
  exit 1
fi

echo "release bundle contract test passed"
