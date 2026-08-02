#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/relaydock-release-transaction.XXXXXXXX")"

cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/scripts" "$TEST_ROOT/internal/version" "$TEST_ROOT/bin" "$TEST_ROOT/docs/release-notes"
cp "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/sync-version.sh" "$SCRIPT_DIR/verify-release-notes.sh" "$TEST_ROOT/scripts/"
printf 'package version\n\nconst Version = "0.6.6"\n' >"$TEST_ROOT/internal/version/version.go"

git_log="$TEST_ROOT/git.log"
cat >"$TEST_ROOT/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$GIT_LOG"
case "$1" in
  status)
    if [ "${MOCK_GIT_DIRTY:-}" = 1 ]; then
      printf '%s\n' '?? stray-file'
    fi
    exit 0
    ;;
  add|commit|tag|push|ls-files)
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

if PATH="$TEST_ROOT/bin:/usr/bin:/bin" GIT_LOG="$git_log" bash "$TEST_ROOT/scripts/release.sh" 0.6.7 >/dev/null 2>&1; then
  echo "release script unexpectedly passed without release notes" >&2
  exit 1
fi
grep -Fq 'Version = "0.6.6"' "$TEST_ROOT/internal/version/version.go"
if grep -Eq '^(add|commit|tag|push) ' "$git_log"; then
  echo "release script mutated git before release notes validation" >&2
  exit 1
fi

cat >"$TEST_ROOT/docs/release-notes/v0.6.7.md" <<'EOF'
# 更新日志

## v0.6.7 (2026-08-02)

### 本次更新
- 修复发布说明契约测试。

### 影响与兼容性
- 适用于所有稳定发布。

## 更新版本
- 使用与部署方式匹配的更新路径。

## 操作方法
1. 检查更新说明。

## 验证
- 发布前已完成验证。

## 完整变更
- https://github.com/violetaini/relaydock/compare/v0.6.6...v0.6.7
EOF
: >"$git_log"

if MOCK_GIT_DIRTY=1 PATH="$TEST_ROOT/bin:/usr/bin:/bin" GIT_LOG="$git_log" bash "$TEST_ROOT/scripts/release.sh" 0.6.7 >/dev/null 2>&1; then
  echo "release script unexpectedly passed with untracked files" >&2
  exit 1
fi
grep -Fq 'Version = "0.6.6"' "$TEST_ROOT/internal/version/version.go"
if grep -Eq '^(add|commit|tag|push) ' "$git_log"; then
  echo "release script mutated git with an unclean worktree" >&2
  exit 1
fi
: >"$git_log"

PATH="$TEST_ROOT/bin:/usr/bin:/bin" GIT_LOG="$git_log" bash "$TEST_ROOT/scripts/release.sh" 0.6.7 >/dev/null
grep -Fq 'Version = "0.6.7"' "$TEST_ROOT/internal/version/version.go"
grep -Fxq 'add internal/version/version.go' "$git_log"
grep -Fxq 'commit -m release: v0.6.7' "$git_log"
grep -Fxq 'tag -a v0.6.7 -m RelayDock v0.6.7' "$git_log"
grep -Fxq 'push --atomic origin main refs/tags/v0.6.7' "$git_log"

echo "release transaction preflight test passed"
