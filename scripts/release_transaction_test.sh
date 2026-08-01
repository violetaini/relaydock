#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/relaydock-release-transaction.XXXXXXXX")"

cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/scripts" "$TEST_ROOT/internal/version" "$TEST_ROOT/bin"
cp "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/sync-version.sh" "$TEST_ROOT/scripts/"
printf 'package version\n\nconst Version = "0.6.6"\n' >"$TEST_ROOT/internal/version/version.go"

git_log="$TEST_ROOT/git.log"
cat >"$TEST_ROOT/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$GIT_LOG"
case "$1" in
  diff|add|commit|tag|push)
    exit 0
    ;;
  ls-remote)
    exit 2
    ;;
  *)
    echo "unexpected git command: $*" >&2
    exit 2
    ;;
esac
EOF
chmod 0755 "$TEST_ROOT/bin/git"

if PATH="$TEST_ROOT/bin:/usr/bin:/bin" GIT_LOG="$git_log" bash "$TEST_ROOT/scripts/release.sh" 0.6.7 >/dev/null 2>&1; then
  echo "release script unexpectedly passed without gh" >&2
  exit 1
fi
if [[ -s "$git_log" ]]; then
  echo "release script touched git before its gh prerequisite check" >&2
  exit 1
fi
grep -Fq 'Version = "0.6.6"' "$TEST_ROOT/internal/version/version.go"

cat >"$TEST_ROOT/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "auth status"|"workflow view"|"workflow run") exit 0 ;;
  *)
    echo "unexpected gh command: $*" >&2
    exit 2
    ;;
esac
EOF
chmod 0755 "$TEST_ROOT/bin/gh"

PATH="$TEST_ROOT/bin:/usr/bin:/bin" GIT_LOG="$git_log" bash "$TEST_ROOT/scripts/release.sh" 0.6.7 >/dev/null
grep -Fq 'Version = "0.6.7"' "$TEST_ROOT/internal/version/version.go"
grep -Fxq 'add internal/version/version.go' "$git_log"
grep -Fxq 'commit -m release: v0.6.7' "$git_log"
grep -Fxq 'tag -a v0.6.7 -m RelayDock v0.6.7' "$git_log"
grep -Fxq 'push --atomic origin main refs/tags/v0.6.7' "$git_log"

echo "release transaction preflight test passed"
