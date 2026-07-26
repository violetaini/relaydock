#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION="${1:-}"

if [ -z "$VERSION" ]; then
    VERSION="$(sed -n 's/.*const Version = "\([^"]*\)".*/\1/p' "$PROJECT_ROOT/internal/version/version.go")"
fi

if [ -z "$VERSION" ]; then
    echo "ERROR: unable to determine the Arcway version" >&2
    exit 1
fi

sed -i "s/const Version = \".*\"/const Version = \"$VERSION\"/" \
    "$PROJECT_ROOT/internal/version/version.go"

echo "RelayDock Backend version synchronized: $VERSION"
