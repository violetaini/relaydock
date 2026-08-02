#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/relaydock-release-notes.XXXXXXXX")"

cleanup() {
  find "$TEST_ROOT" -depth -delete
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/scripts" "$TEST_ROOT/docs/release-notes"
cp "$SCRIPT_DIR/verify-release-notes.sh" "$TEST_ROOT/scripts/"

cat >"$TEST_ROOT/docs/release-notes/v1.2.3.md" <<'EOF'
# 更新日志

## v1.2.3 (2026-08-02)

### 本次更新
- 增加发布说明验证。

### 影响与兼容性
- 不改变运行时兼容性。

## 更新版本
- 使用稳定发布包更新。

## 操作方法
1. 阅读说明后确认更新。

## 验证
- 已通过发布说明契约测试。

## 完整变更
- https://github.com/violetaini/relaydock/compare/v1.2.2...v1.2.3
EOF

bash "$TEST_ROOT/scripts/verify-release-notes.sh" v1.2.3

sed -i 's/增加发布说明验证。/TODO: 填写更新内容。/' "$TEST_ROOT/docs/release-notes/v1.2.3.md"
if bash "$TEST_ROOT/scripts/verify-release-notes.sh" v1.2.3 >/dev/null 2>&1; then
  echo "release notes verifier accepted a placeholder" >&2
  exit 1
fi

sed -i 's/TODO: 填写更新内容。/增加发布说明验证。/' "$TEST_ROOT/docs/release-notes/v1.2.3.md"
sed -i 's#https://github.com/violetaini/relaydock/compare/v1.2.2...v1.2.3#https://example.invalid/release-notes#' "$TEST_ROOT/docs/release-notes/v1.2.3.md"
if bash "$TEST_ROOT/scripts/verify-release-notes.sh" v1.2.3 >/dev/null 2>&1; then
  echo "release notes verifier accepted a missing compare link" >&2
  exit 1
fi

find "$TEST_ROOT/docs/release-notes/v1.2.3.md" -depth -delete
if bash "$TEST_ROOT/scripts/verify-release-notes.sh" v1.2.3 >/dev/null 2>&1; then
  echo "release notes verifier accepted a missing file" >&2
  exit 1
fi

echo "release notes contract test passed"
