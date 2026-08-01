#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <output-file> <release-tag> <backend-commit> [api-contract]" >&2
}

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  usage
  exit 2
fi

OUTPUT_FILE="$1"
RELEASE_TAG="$2"
BACKEND_COMMIT="$3"
API_CONTRACT="${4:-1}"

if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "release tag must use vX.Y.Z: $RELEASE_TAG" >&2
  exit 2
fi
if [[ ! "$BACKEND_COMMIT" =~ ^[0-9A-Fa-f]{40}$ ]]; then
  echo "backend commit must be a 40-character SHA-1: $BACKEND_COMMIT" >&2
  exit 2
fi
if [[ ! "$API_CONTRACT" =~ ^[1-9][0-9]*$ ]]; then
  echo "API contract must be a positive integer: $API_CONTRACT" >&2
  exit 2
fi

OUTPUT_DIR="$(dirname "$OUTPUT_FILE")"
if [ ! -d "$OUTPUT_DIR" ]; then
  echo "output directory does not exist: $OUTPUT_DIR" >&2
  exit 1
fi

BACKEND_COMMIT="$(tr '[:upper:]' '[:lower:]' <<<"$BACKEND_COMMIT")"
TEMP_FILE="$(mktemp "$OUTPUT_DIR/.relaydock-release.XXXXXXXX")"
cleanup() {
  rm -f -- "$TEMP_FILE"
}
trap cleanup EXIT

cat >"$TEMP_FILE" <<EOF
{
  "schema": 1,
  "release_id": "$RELEASE_TAG",
  "backend_commit": "$BACKEND_COMMIT",
  "api_contract": $API_CONTRACT
}
EOF

chmod 0644 "$TEMP_FILE"
mv -f -- "$TEMP_FILE" "$OUTPUT_FILE"
trap - EXIT
