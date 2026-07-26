#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

CURRENT_VERSION="$(sed -n 's/.*const Version = "\([^"]*\)".*/\1/p' internal/version/version.go)"
BUMP="${1:-patch}"

case "$BUMP" in
    major) NEW_VERSION="$(awk -F. '{printf "%d.0.0", $1 + 1}' <<<"$CURRENT_VERSION")" ;;
    minor) NEW_VERSION="$(awk -F. '{printf "%d.%d.0", $1, $2 + 1}' <<<"$CURRENT_VERSION")" ;;
    patch) NEW_VERSION="$(awk -F. '{printf "%d.%d.%d", $1, $2, $3 + 1}' <<<"$CURRENT_VERSION")" ;;
    [0-9]*.[0-9]*.[0-9]*) NEW_VERSION="$BUMP" ;;
    *) echo "ERROR: expected major, minor, patch, or X.Y.Z" >&2; exit 1 ;;
esac

bash scripts/sync-version.sh "$NEW_VERSION"
git add internal/version/version.go
git commit -m "release: v$NEW_VERSION"
git tag "v$NEW_VERSION"
git push origin main
git push origin "v$NEW_VERSION"

echo "RelayDock Backend v$NEW_VERSION tagged. GitHub Actions will publish binaries and GHCR."
echo "Release: https://github.com/violetaini/relaydock/releases/tag/v$NEW_VERSION"
