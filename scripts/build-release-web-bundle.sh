#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <frontend-dist-dir> <output-archive> <release-tag> <backend-commit> [api-contract]" >&2
}

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
  usage
  exit 2
fi

DIST_DIR="$1"
OUTPUT_ARCHIVE="$2"
RELEASE_TAG="$3"
BACKEND_COMMIT="$4"
API_CONTRACT="${5:-1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
METADATA_WRITER="$SCRIPT_DIR/write-release-web-metadata.sh"

if [ ! -x "$METADATA_WRITER" ]; then
  echo "release metadata writer is not executable: $METADATA_WRITER" >&2
  exit 1
fi
if [ ! -d "$DIST_DIR" ] || [ ! -f "$DIST_DIR/index.html" ] || [ ! -d "$DIST_DIR/assets" ]; then
  echo "frontend dist directory is incomplete: $DIST_DIR" >&2
  exit 1
fi
if find "$DIST_DIR" -type l -print -quit | grep -q .; then
  echo "frontend dist may not contain symbolic links" >&2
  exit 1
fi
if find "$DIST_DIR" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then
  echo "frontend dist may only contain regular files and directories" >&2
  exit 1
fi
if ! grep -q '__RELAYDOCK_DEFAULT_THEME__' "$DIST_DIR/index.html"; then
  echo "frontend index.html is missing the default theme placeholder" >&2
  exit 1
fi

mapfile -t REFERENCED_ASSETS < <(grep -oE '/assets/[A-Za-z0-9._/-]+' "$DIST_DIR/index.html" | LC_ALL=C sort -u)
if [ "${#REFERENCED_ASSETS[@]}" -eq 0 ]; then
  echo "frontend index.html does not reference local assets" >&2
  exit 1
fi
for asset in "${REFERENCED_ASSETS[@]}"; do
  relative="${asset#/}"
  if [[ "$relative" == *"/../"* || "$relative" == ../* || "$relative" == */.. ]]; then
    echo "frontend index.html references an unsafe asset path: $asset" >&2
    exit 1
  fi
  if [ ! -f "$DIST_DIR/$relative" ] || [ -L "$DIST_DIR/$relative" ]; then
    echo "frontend index.html references a missing asset: $asset" >&2
    exit 1
  fi
done

OUTPUT_DIR="$(dirname "$OUTPUT_ARCHIVE")"
if [ ! -d "$OUTPUT_DIR" ]; then
  echo "output directory does not exist: $OUTPUT_DIR" >&2
  exit 1
fi
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
OUTPUT_ARCHIVE="$OUTPUT_DIR/$(basename "$OUTPUT_ARCHIVE")"

STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/relaydock-web.XXXXXXXX")"
TEMP_ARCHIVE="$(mktemp "$OUTPUT_DIR/.relaydock-web.XXXXXXXX.tar.gz")"
cleanup() {
  rm -rf -- "$STAGING_DIR"
  rm -f -- "$TEMP_ARCHIVE"
}
trap cleanup EXIT

cp -a "$DIST_DIR/." "$STAGING_DIR/"
"$METADATA_WRITER" "$STAGING_DIR/relaydock-release.json" "$RELEASE_TAG" "$BACKEND_COMMIT" "$API_CONTRACT"

# Normalize every metadata field tar records so equivalent frontend trees always
# produce the same archive bytes regardless of checkout owner or mtimes.
tar \
  --format=posix \
  --sort=name \
  --mtime='@0' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --mode='u=rwX,go=rX' \
  --pax-option=delete=atime,delete=ctime \
  -C "$STAGING_DIR" \
  -cf - . | gzip -n >"$TEMP_ARCHIVE"

mv -f -- "$TEMP_ARCHIVE" "$OUTPUT_ARCHIVE"
trap - EXIT
rm -rf -- "$STAGING_DIR"
