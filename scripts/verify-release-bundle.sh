#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: verify-release-bundle.sh <bundle-dir> <main-source-sha> <agent-source-sha> \
  --release-tag vX.Y.Z [--api-contract N] [--write-manifest] [--write-checksums]

The bundle must contain every binary asset plus relaydock-web.tar.gz. Without
the write flags, relaydock-release-manifest.json and checksums.txt must already
exist and match the deterministic release contract.
EOF
}

if [ "$#" -lt 3 ]; then
  usage
  exit 2
fi

BUNDLE_DIR="$1"
MAIN_SOURCE_SHA="$2"
AGENT_SOURCE_SHA="$3"
shift 3

RELEASE_TAG="${GITHUB_REF_NAME:-}"
API_CONTRACT=1
WRITE_MANIFEST=0
WRITE_CHECKSUMS=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release-tag)
      RELEASE_TAG="${2:?missing value for --release-tag}"
      shift 2
      ;;
    --api-contract)
      API_CONTRACT="${2:?missing value for --api-contract}"
      shift 2
      ;;
    --write-manifest)
      WRITE_MANIFEST=1
      shift
      ;;
    --write-checksums)
      WRITE_CHECKSUMS=1
      shift
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "release bundle directory does not exist: $BUNDLE_DIR" >&2
  exit 1
fi
if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "release tag must use vX.Y.Z: ${RELEASE_TAG:-<missing>}" >&2
  exit 2
fi
for source_sha in "$MAIN_SOURCE_SHA" "$AGENT_SOURCE_SHA"; do
  if [[ ! "$source_sha" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    echo "source commit must be a 40-character SHA-1: $source_sha" >&2
    exit 2
  fi
done
if [[ ! "$API_CONTRACT" =~ ^[1-9][0-9]*$ ]]; then
  echo "API contract must be a positive integer: $API_CONTRACT" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_METADATA_WRITER="$SCRIPT_DIR/write-release-web-metadata.sh"
MANIFEST_WRITER="$SCRIPT_DIR/write-release-manifest.sh"
for helper in "$WEB_METADATA_WRITER" "$MANIFEST_WRITER"; do
  if [ ! -x "$helper" ]; then
    echo "required release helper is not executable: $helper" >&2
    exit 1
  fi
done

CONTROL_PLANE_ASSETS=(
  arcway-linux-amd64
  arcway-linux-arm64
  arcway-darwin-amd64
  arcway-darwin-arm64
  arcway-windows-amd64.exe
)
GUARD_ASSETS=(
  arcway-expiry-guard-linux-amd64
  arcway-expiry-guard-linux-arm64
)
AGENT_ASSETS=(
  relaydock-agent-linux-amd64
  relaydock-agent-linux-arm64
)
SPEEDTESTER_ASSETS=(
  relaydock-speedtester-linux-amd64
  relaydock-speedtester-linux-arm64
  relaydock-speedtester-windows-amd64.exe
  relaydock-speedtester-windows-arm64.exe
)
FRONTEND_ASSETS=(relaydock-web.tar.gz)
COMPONENT_ASSETS=(
  "${CONTROL_PLANE_ASSETS[@]}"
  "${GUARD_ASSETS[@]}"
  "${AGENT_ASSETS[@]}"
  "${SPEEDTESTER_ASSETS[@]}"
  "${FRONTEND_ASSETS[@]}"
)
MANIFEST_FILE=relaydock-release-manifest.json
CHECKSUM_FILE=checksums.txt
CHECKSUM_INPUTS=("${COMPONENT_ASSETS[@]}" "$MANIFEST_FILE")
ALLOWED_FILES=("${CHECKSUM_INPUTS[@]}" "$CHECKSUM_FILE")

contains_allowed_file() {
  local candidate="$1"
  local allowed
  for allowed in "${ALLOWED_FILES[@]}"; do
    if [ "$candidate" = "$allowed" ]; then
      return 0
    fi
  done
  return 1
}

for filename in "${COMPONENT_ASSETS[@]}"; do
  if [ ! -s "$BUNDLE_DIR/$filename" ] || [ -L "$BUNDLE_DIR/$filename" ]; then
    echo "missing or unsafe release asset: $filename" >&2
    exit 1
  fi
done

if find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
  echo "release bundle contains a non-regular top-level entry" >&2
  find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 ! -type f -printf '%f\n' >&2
  exit 1
fi
while IFS= read -r filename; do
  if ! contains_allowed_file "$filename"; then
    echo "release bundle contains an unexpected file: $filename" >&2
    exit 1
  fi
done < <(find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -type f -printf '%f\n')

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

verify_web_archive() (
  set -euo pipefail

  archive="$BUNDLE_DIR/relaydock-web.tar.gz"
  extract_dir="$(mktemp -d "${TMPDIR:-/tmp}/relaydock-web-verify.XXXXXXXX")"
  expected_metadata="$(mktemp "${TMPDIR:-/tmp}/relaydock-web-metadata.XXXXXXXX")"
  cleanup() {
    rm -rf -- "$extract_dir"
    rm -f -- "$expected_metadata"
  }
  trap cleanup EXIT

  while IFS= read -r member; do
    case "$member" in
      ./|.)
        continue
        ;;
      ./*)
        relative="${member#./}"
        relative="${relative%/}"
        ;;
      *)
        echo "frontend archive contains an unsafe member path: $member" >&2
        exit 1
        ;;
    esac
    if [ -z "$relative" ] || [[ "$relative" == /* || "$relative" == ../* || "$relative" == *"/../"* || "$relative" == */.. || "$relative" == *"//"* || "$relative" == *"/./"* || "$relative" == ./* ]]; then
      echo "frontend archive contains an unsafe member path: $member" >&2
      exit 1
    fi
  done < <(tar -tzf "$archive")

  if ! tar -tvzf "$archive" | awk 'substr($1, 1, 1) == "-" || substr($1, 1, 1) == "d" { next } { exit 1 }'; then
    echo "frontend archive may only contain regular files and directories" >&2
    exit 1
  fi
  tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$extract_dir"
  if find "$extract_dir" -type l -print -quit | grep -q .; then
    echo "frontend archive contains symbolic links" >&2
    exit 1
  fi
  if find "$extract_dir" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then
    echo "frontend archive contains unsupported file types" >&2
    exit 1
  fi
  if [ ! -s "$extract_dir/index.html" ] || [ ! -d "$extract_dir/assets" ]; then
    echo "frontend archive is missing index.html or assets" >&2
    exit 1
  fi
  if ! grep -q '__RELAYDOCK_DEFAULT_THEME__' "$extract_dir/index.html"; then
    echo "frontend archive index.html is missing the default theme placeholder" >&2
    exit 1
  fi
  "$WEB_METADATA_WRITER" "$expected_metadata" "$RELEASE_TAG" "$MAIN_SOURCE_SHA" "$API_CONTRACT"
  if [ ! -f "$extract_dir/relaydock-release.json" ] || ! cmp -s "$expected_metadata" "$extract_dir/relaydock-release.json"; then
    echo "frontend archive release metadata does not match this release" >&2
    exit 1
  fi

  mapfile -t referenced_assets < <(grep -oE '/assets/[A-Za-z0-9._/-]+' "$extract_dir/index.html" | LC_ALL=C sort -u)
  if [ "${#referenced_assets[@]}" -eq 0 ]; then
    echo "frontend archive index.html does not reference local assets" >&2
    exit 1
  fi
  for asset in "${referenced_assets[@]}"; do
    relative="${asset#/}"
    if [[ "$relative" == *"/../"* || "$relative" == ../* || "$relative" == */.. ]] || [ ! -f "$extract_dir/$relative" ] || [ -L "$extract_dir/$relative" ]; then
      echo "frontend archive references a missing or unsafe asset: $asset" >&2
      exit 1
    fi
  done
)

verify_web_archive

chmod 0755 \
  "$BUNDLE_DIR"/arcway-linux-* \
  "$BUNDLE_DIR"/arcway-darwin-* \
  "$BUNDLE_DIR"/arcway-expiry-guard-linux-* \
  "$BUNDLE_DIR"/relaydock-agent-linux-* \
  "$BUNDLE_DIR"/relaydock-speedtester-linux-*

EXPECTED_MANIFEST="$(mktemp "${TMPDIR:-/tmp}/relaydock-release-manifest.XXXXXXXX")"
EXPECTED_CHECKSUMS="$(mktemp "${TMPDIR:-/tmp}/relaydock-release-checksums.XXXXXXXX")"
cleanup_metadata() {
  rm -f -- "$EXPECTED_MANIFEST" "$EXPECTED_CHECKSUMS"
}
trap cleanup_metadata EXIT

"$MANIFEST_WRITER" \
  "$BUNDLE_DIR" \
  "$EXPECTED_MANIFEST" \
  "$RELEASE_TAG" \
  "$MAIN_SOURCE_SHA" \
  "$AGENT_SOURCE_SHA" \
  "$API_CONTRACT"

if [ "$WRITE_MANIFEST" -eq 1 ]; then
  mv -f -- "$EXPECTED_MANIFEST" "$BUNDLE_DIR/$MANIFEST_FILE"
  EXPECTED_MANIFEST=""
elif [ ! -f "$BUNDLE_DIR/$MANIFEST_FILE" ] || ! cmp -s "$EXPECTED_MANIFEST" "$BUNDLE_DIR/$MANIFEST_FILE"; then
  echo "release manifest is missing or does not match the verified bundle" >&2
  exit 1
fi

(
  cd "$BUNDLE_DIR"
  sha256sum "${CHECKSUM_INPUTS[@]}" >"$EXPECTED_CHECKSUMS"
)
if [ "$WRITE_CHECKSUMS" -eq 1 ]; then
  mv -f -- "$EXPECTED_CHECKSUMS" "$BUNDLE_DIR/$CHECKSUM_FILE"
  EXPECTED_CHECKSUMS=""
elif [ ! -f "$BUNDLE_DIR/$CHECKSUM_FILE" ] || ! cmp -s "$EXPECTED_CHECKSUMS" "$BUNDLE_DIR/$CHECKSUM_FILE"; then
  echo "checksums.txt is missing or does not match the verified bundle" >&2
  exit 1
fi

(
  cd "$BUNDLE_DIR"
  sha256sum -c "$CHECKSUM_FILE"
)

echo "Verified ${#COMPONENT_ASSETS[@]} component assets plus release metadata."
