#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RELEASE_TAG="${1:-}"

if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: expected release tag in the form vX.Y.Z" >&2
  exit 1
fi

NOTES_PATH="$PROJECT_ROOT/docs/release-notes/$RELEASE_TAG.md"
if [[ ! -f "$NOTES_PATH" ]]; then
  echo "ERROR: missing release notes: $NOTES_PATH" >&2
  exit 1
fi

if [[ "$(head -n 1 "$NOTES_PATH")" != '# 更新日志' ]]; then
  echo "ERROR: release notes must start with the 更新日志 heading" >&2
  exit 1
fi

TAG_PATTERN="${RELEASE_TAG//./\\.}"
if ! grep -Eq "^## ${TAG_PATTERN} \\([0-9]{4}-[0-9]{2}-[0-9]{2}\\)$" "$NOTES_PATH"; then
  echo "ERROR: release notes must include a dated $RELEASE_TAG heading" >&2
  exit 1
fi

required_sections=(
  '### 本次更新'
  '### 影响与兼容性'
  '## 更新版本'
  '## 操作方法'
  '## 验证'
  '## 完整变更'
)

section_has_content() {
  local heading="$1"
  awk -v heading="$heading" '
    $0 == heading { in_section = 1; next }
    in_section && /^#/ { exit has_content ? 0 : 1 }
    in_section && NF { has_content = 1 }
    END { exit (in_section && has_content) ? 0 : 1 }
  ' "$NOTES_PATH"
}

for section in "${required_sections[@]}"; do
  if ! grep -Fqx "$section" "$NOTES_PATH" || ! section_has_content "$section"; then
    echo "ERROR: release notes section is missing or empty: $section" >&2
    exit 1
  fi
done

if ! grep -Eq "https://github\\.com/violetaini/relaydock/compare/v[0-9]+\\.[0-9]+\\.[0-9]+\\.\\.\\.${TAG_PATTERN}([/?#)]|$)" "$NOTES_PATH"; then
  echo "ERROR: release notes must link the preceding stable tag to $RELEASE_TAG" >&2
  exit 1
fi

if grep -Eqi 'TODO|TBD|\{\{|\[填写' "$NOTES_PATH"; then
  echo "ERROR: release notes still contain a template placeholder" >&2
  exit 1
fi

echo "Release notes verified: ${NOTES_PATH#$PROJECT_ROOT/}"
