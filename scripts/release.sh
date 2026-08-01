#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

CURRENT_VERSION="$(sed -n 's/.*const Version = "\([^"]*\)".*/\1/p' internal/version/version.go)"
BUMP="${1:-patch}"

command -v gh >/dev/null || { echo "ERROR: gh is required to start the manual release build" >&2; exit 1; }
if ! gh auth status >/dev/null 2>&1; then
    echo "ERROR: gh is not authenticated; no commit or tag was created" >&2
    exit 1
fi
if ! gh workflow view build.yml --repo violetaini/relaydock >/dev/null; then
    echo "ERROR: cannot access the release workflow; no commit or tag was created" >&2
    exit 1
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "ERROR: release requires a clean worktree" >&2
    exit 1
fi

case "$BUMP" in
    major) NEW_VERSION="$(awk -F. '{printf "%d.0.0", $1 + 1}' <<<"$CURRENT_VERSION")" ;;
    minor) NEW_VERSION="$(awk -F. '{printf "%d.%d.0", $1, $2 + 1}' <<<"$CURRENT_VERSION")" ;;
    patch) NEW_VERSION="$(awk -F. '{printf "%d.%d.%d", $1, $2, $3 + 1}' <<<"$CURRENT_VERSION")" ;;
    [0-9]*.[0-9]*.[0-9]*) NEW_VERSION="$BUMP" ;;
    *) echo "ERROR: expected major, minor, patch, or X.Y.Z" >&2; exit 1 ;;
esac

if git ls-remote --exit-code --tags origin "refs/tags/v$NEW_VERSION" >/dev/null 2>&1; then
    echo "ERROR: v$NEW_VERSION already exists on origin; choose a new version" >&2
    exit 1
fi

bash scripts/sync-version.sh "$NEW_VERSION"
git add internal/version/version.go
git commit -m "release: v$NEW_VERSION"
git tag -a "v$NEW_VERSION" -m "RelayDock v$NEW_VERSION"
git push --atomic origin main "refs/tags/v$NEW_VERSION"

if ! gh workflow run build.yml \
    --repo violetaini/relaydock \
    --ref "v$NEW_VERSION" \
    -f publish=true; then
    echo "ERROR: v$NEW_VERSION was pushed, but the release workflow was not started." >&2
    echo "Retry: gh workflow run build.yml --repo violetaini/relaydock --ref v$NEW_VERSION -f publish=true" >&2
    exit 1
fi

echo "RelayDock Backend v$NEW_VERSION tagged. The explicitly requested GitHub build has been started."
echo "Release: https://github.com/violetaini/relaydock/releases/tag/v$NEW_VERSION"
