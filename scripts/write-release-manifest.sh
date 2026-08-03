#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: write-release-manifest.sh <bundle-dir> <output-file> <release-tag> <backend-commit> <agent-commit> [api-contract]

Stable releases are coordinated product releases: their tag must match the
control-plane version and all panel-managed components are marked as changed.
The Agent commit remains release provenance; Agent binaries are delivered by
the GitHub Release checksums rather than as a panel-managed component.
EOF
}

if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
  usage
  exit 2
fi

BUNDLE_DIR="$1"
OUTPUT_FILE="$2"
RELEASE_TAG="$3"
BACKEND_COMMIT="$4"
AGENT_COMMIT="$5"
API_CONTRACT="${6:-1}"
RELEASE_SCOPE="${RELAYDOCK_RELEASE_SCOPE:-full}"
CONTROL_PLANE_VERSION="${RELEASE_TAG#v}"

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "release bundle directory does not exist: $BUNDLE_DIR" >&2
  exit 1
fi
if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "release tag must use vX.Y.Z: $RELEASE_TAG" >&2
  exit 2
fi
for value in "$BACKEND_COMMIT" "$AGENT_COMMIT"; do
  if [[ ! "$value" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    echo "source commit must be a 40-character SHA-1: $value" >&2
    exit 2
  fi
done
if [[ ! "$API_CONTRACT" =~ ^[1-9][0-9]*$ ]]; then
  echo "API contract must be a positive integer: $API_CONTRACT" >&2
  exit 2
fi
if [[ ! "$CONTROL_PLANE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "control-plane version must use X.Y.Z: $CONTROL_PLANE_VERSION" >&2
  exit 2
fi
if [ "$RELEASE_SCOPE" != "full" ]; then
  echo "stable releases only support the full release scope" >&2
  exit 2
fi

BACKEND_COMMIT="$(tr '[:upper:]' '[:lower:]' <<<"$BACKEND_COMMIT")"
AGENT_COMMIT="$(tr '[:upper:]' '[:lower:]' <<<"$AGENT_COMMIT")"

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
FRONTEND_ASSETS=(relaydock-web.tar.gz)

asset_metadata() {
  local filename="$1"
  local path="$BUNDLE_DIR/$filename"
  local digest size
  if [ ! -s "$path" ] || [ -L "$path" ]; then
    echo "missing or unsafe release asset: $filename" >&2
    exit 1
  fi
  digest="$(sha256sum "$path" | awk '{print $1}')"
  size="$(wc -c <"$path" | tr -d '[:space:]')"
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "unable to calculate SHA-256 for release asset: $filename" >&2
    exit 1
  fi
  if [[ ! "$size" =~ ^[1-9][0-9]*$ ]]; then
    echo "unable to calculate release asset size: $filename" >&2
    exit 1
  fi
  printf '%s\t%s' "$digest" "$size"
}

write_component() {
  local name="$1"
  local component_version="$2"
  local changed="$3"
  shift 3
  local assets=("$@")
  local index filename digest size metadata

  printf '    "%s": {\n' "$name"
  printf '      "version": "%s",\n' "$component_version"
  printf '      "api_contract": %s,\n' "$API_CONTRACT"
  printf '      "changed": %s,\n' "$changed"
  printf '      "assets": [\n'
  for index in "${!assets[@]}"; do
    filename="${assets[$index]}"
    metadata="$(asset_metadata "$filename")"
    IFS=$'\t' read -r digest size <<<"$metadata"
    printf '        {"name": "%s", "sha256": "%s", "size": %s}' "$filename" "$digest" "$size"
    if [ "$index" -lt "$(( ${#assets[@]} - 1 ))" ]; then
      printf ','
    fi
    printf '\n'
  done
  printf '      ]\n'
  printf '    }'
}

CONTROL_PLANE_CHANGED=true
GUARD_CHANGED=true
WEB_CHANGED=true

OUTPUT_DIR="$(dirname "$OUTPUT_FILE")"
if [ ! -d "$OUTPUT_DIR" ]; then
  echo "output directory does not exist: $OUTPUT_DIR" >&2
  exit 1
fi
TEMP_FILE="$(mktemp "$OUTPUT_DIR/.relaydock-release-manifest.XXXXXXXX")"
cleanup() {
  rm -f -- "$TEMP_FILE"
}
trap cleanup EXIT

{
  printf '{\n'
  printf '  "schema": 1,\n'
  printf '  "release_id": "%s",\n' "$RELEASE_TAG"
  printf '  "backend_commit": "%s",\n' "$BACKEND_COMMIT"
  printf '  "agent_commit": "%s",\n' "$AGENT_COMMIT"
  printf '  "api_contract": %s,\n' "$API_CONTRACT"
  printf '  "components": {\n'
  write_component "control_plane" "$CONTROL_PLANE_VERSION" "$CONTROL_PLANE_CHANGED" "${CONTROL_PLANE_ASSETS[@]}"
  printf ',\n'
  write_component "web" "$RELEASE_TAG" "$WEB_CHANGED" "${FRONTEND_ASSETS[@]}"
  printf ',\n'
  write_component "guard_assets" "$CONTROL_PLANE_VERSION" "$GUARD_CHANGED" "${GUARD_ASSETS[@]}"
  printf '\n'
  printf '  }\n'
  printf '}\n'
} >"$TEMP_FILE"

chmod 0644 "$TEMP_FILE"
mv -f -- "$TEMP_FILE" "$OUTPUT_FILE"
trap - EXIT
