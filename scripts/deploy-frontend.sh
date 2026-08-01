#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

MODE="deploy"
DEPLOY_HOST="${ARCWAY_DEPLOY_HOST:-}"
DEPLOY_PORT="${ARCWAY_DEPLOY_PORT:-22}"
DEPLOY_USER="${ARCWAY_DEPLOY_USER:-root}"
FRONTEND_DIR="${ARCWAY_FRONTEND_DIR:-$PROJECT_ROOT/../arcway-frontend}"
REMOTE_ROOT="${ARCWAY_WEB_DEPLOY_ROOT:-/opt/arcway/web}"
RELEASE_ID=""
SKIP_BUILD=0

usage() {
    cat <<'EOF'
Usage:
  scripts/deploy-frontend.sh [deploy] --host HOST [options]
  scripts/deploy-frontend.sh rollback --host HOST [--release RELEASE] [options]

Options:
  --host HOST             SSH host (or set ARCWAY_DEPLOY_HOST)
  --port PORT             SSH port (default: 22)
  --user USER             SSH user (default: root)
  --frontend-dir PATH     frontend checkout (default: ../arcway-frontend)
  --remote-root PATH      release root (default: /opt/arcway/web)
  --release RELEASE       release id; rollback defaults to the previous release
  --skip-build            deploy the existing frontend dist directory
  -h, --help              show this help

The Arcway service must use ARCWAY_WEB_ROOT=<remote-root>/current.
EOF
}

if [[ "${1:-}" == "deploy" || "${1:-}" == "rollback" ]]; then
    MODE="$1"
    shift
fi

while (($#)); do
    case "$1" in
        --host) DEPLOY_HOST="${2:?missing value for --host}"; shift 2 ;;
        --port) DEPLOY_PORT="${2:?missing value for --port}"; shift 2 ;;
        --user) DEPLOY_USER="${2:?missing value for --user}"; shift 2 ;;
        --frontend-dir) FRONTEND_DIR="${2:?missing value for --frontend-dir}"; shift 2 ;;
        --remote-root) REMOTE_ROOT="${2:?missing value for --remote-root}"; shift 2 ;;
        --release) RELEASE_ID="${2:?missing value for --release}"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$DEPLOY_HOST" ]] || { echo "ERROR: --host is required" >&2; exit 2; }
[[ "$DEPLOY_PORT" =~ ^[0-9]+$ ]] || { echo "ERROR: invalid SSH port" >&2; exit 2; }
REMOTE_ROOT="${REMOTE_ROOT%/}"
[[ "$REMOTE_ROOT" =~ ^(/[A-Za-z0-9._-]+){3,}$ && "/$REMOTE_ROOT/" != *"/../"* && "/$REMOTE_ROOT/" != *"/./"* ]] || {
    echo "ERROR: --remote-root must be an absolute path with at least three safe components" >&2
    exit 2
}
if [[ -n "$RELEASE_ID" && ! "$RELEASE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "ERROR: release id may contain only letters, digits, dot, underscore, and dash" >&2
    exit 2
fi

SSH_ARGS=(-o BatchMode=yes -o ConnectTimeout=10 -p "$DEPLOY_PORT")
SSH_TARGET="$DEPLOY_USER@$DEPLOY_HOST"

if [[ "$MODE" == "rollback" ]]; then
    rollback_release="${RELEASE_ID:--}"
    ssh "${SSH_ARGS[@]}" "$SSH_TARGET" bash -s -- rollback "$REMOTE_ROOT" "$rollback_release" <<'REMOTE'
set -euo pipefail
mode="$1"
root="$2"
requested_release="$3"
[[ "$requested_release" == "-" ]] && requested_release=""
releases="$root/releases"

normalize_managed_target() {
    local target="$1"
    if [[ "$target" == /* ]]; then
        [[ "$target" == "$root/releases/"* ]] || return 1
        target="releases/${target#"$root/releases/"}"
    fi
    [[ "$target" =~ ^releases/([A-Za-z0-9][A-Za-z0-9._-]*)$ ]] || return 1
    printf '%s\n' "$target"
}

[[ "$mode" == "rollback" && "$root" =~ ^(/[A-Za-z0-9._-]+){3,}$ && "/$root/" != *"/../"* && "/$root/" != *"/./"* ]] || exit 2
[[ -d "$root" && ! -L "$root" && -d "$releases" && ! -L "$releases" ]] || {
    echo "ERROR: no switchable frontend releases found under $root" >&2
    exit 1
}
for managed_dir in "$root" "$releases"; do
    [[ "$(stat -c %u "$managed_dir")" == "$(id -u)" ]] || { echo "ERROR: managed directory has the wrong owner: $managed_dir" >&2; exit 1; }
    if find "$managed_dir" -maxdepth 0 -perm /0022 -print -quit | grep -q .; then
        echo "ERROR: managed directory is group- or world-writable: $managed_dir" >&2
        exit 1
    fi
done
command -v flock >/dev/null || { echo "ERROR: flock is required on the server" >&2; exit 1; }
lock="$root/.deploy.lock"
if [[ ! -e "$lock" && ! -L "$lock" ]]; then
    (umask 077; set -o noclobber; : > "$lock") 2>/dev/null || true
fi
[[ -f "$lock" && ! -L "$lock" && "$(stat -c %u "$lock")" == "$(id -u)" ]] || { echo "ERROR: unsafe deploy lock: $lock" >&2; exit 1; }
chmod 0600 "$lock"
exec 9<>"$lock"
flock -x 9
[[ -L "$root/current" ]] || { echo "ERROR: current release link is missing" >&2; exit 1; }

current_target="$(normalize_managed_target "$(readlink "$root/current")")" || {
    echo "ERROR: current link does not point to a managed release" >&2
    exit 1
}
current_release="${current_target#releases/}"
current_dir="$releases/$current_release"
[[ -d "$current_dir" && ! -L "$current_dir" && -d "$current_dir/assets" && ! -L "$current_dir/assets" ]] || {
    echo "ERROR: current release is missing or unsafe" >&2
    exit 1
}
if find "$current_dir" -type l -print -quit | grep -q .; then
    echo "ERROR: current release contains symbolic links" >&2
    exit 1
fi
release="$requested_release"
if [[ -z "$release" ]]; then
    if [[ -L "$root/previous" ]]; then
        if previous_target="$(normalize_managed_target "$(readlink "$root/previous")")" && [[ -d "$root/$previous_target" && ! -L "$root/$previous_target" ]]; then
            release="${previous_target#releases/}"
        fi
    fi
    if [[ -z "$release" ]]; then
        release="$(find "$releases" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r | while read -r candidate; do
            if [[ "$candidate" != "$current_release" && "$candidate" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
                printf '%s\n' "$candidate"
                break
            fi
        done)"
    fi
fi
[[ "$release" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && -d "$releases/$release" && ! -L "$releases/$release" && "$release" != "$current_release" ]] || {
    echo "ERROR: rollback release not found: ${release:-<none>}" >&2
    exit 1
}

index="$releases/$release/index.html"
[[ -s "$index" && ! -L "$index" && -d "$releases/$release/assets" && ! -L "$releases/$release/assets" ]] || {
    echo "ERROR: rollback release is incomplete: $release" >&2
    exit 1
}
if find "$releases/$release" -type l -print -quit | grep -q .; then
    echo "ERROR: rollback release contains symbolic links: $release" >&2
    exit 1
fi
grep -q '__RELAYDOCK_DEFAULT_THEME__' "$index" || {
    echo "ERROR: rollback release has an invalid index.html" >&2
    exit 1
}
mapfile -t rollback_assets < <(grep -oE '/assets/[A-Za-z0-9._/-]+' "$index" | sort -u)
((${#rollback_assets[@]} > 0)) || { echo "ERROR: rollback release does not reference any assets" >&2; exit 1; }
for asset in "${rollback_assets[@]}"; do
    [[ -f "$releases/$release/${asset#/}" ]] || { echo "ERROR: rollback asset is missing: $asset" >&2; exit 1; }
done
cp -aln "$current_dir/assets/." "$releases/$release/assets/"
if find "$releases/$release" -type l -print -quit | grep -q .; then
    echo "ERROR: rollback release became unsafe while merging assets" >&2
    exit 1
fi

previous_link="$root/.previous-rollback-$$"
if [[ -e "$root/previous" && ! -L "$root/previous" ]]; then
    echo "ERROR: $root/previous exists but is not a managed symbolic link" >&2
    exit 1
fi
ln -s "releases/$current_release" "$previous_link"
mv -Tf "$previous_link" "$root/previous"
next_link="$root/.current-rollback-$$"
ln -s "releases/$release" "$next_link"
mv -Tf "$next_link" "$root/current"
echo "Frontend rolled back: $current_release -> $release"
REMOTE
    exit 0
fi

required_commands=(tar scp ssh sha256sum)
if [[ "$SKIP_BUILD" != "1" ]]; then
    required_commands+=(npm)
fi
for command in "${required_commands[@]}"; do
    command -v "$command" >/dev/null || { echo "ERROR: required command not found: $command" >&2; exit 1; }
done
[[ -f "$FRONTEND_DIR/package.json" ]] || { echo "ERROR: frontend checkout not found: $FRONTEND_DIR" >&2; exit 1; }

if [[ "$SKIP_BUILD" != "1" ]]; then
    npm --prefix "$FRONTEND_DIR" run build
fi

DIST_DIR="$FRONTEND_DIR/dist"
[[ -s "$DIST_DIR/index.html" && -d "$DIST_DIR/assets" ]] || {
    echo "ERROR: frontend dist is incomplete: $DIST_DIR" >&2
    exit 1
}
grep -q '__RELAYDOCK_DEFAULT_THEME__' "$DIST_DIR/index.html" || {
    echo "ERROR: frontend index.html is missing the theme placeholder" >&2
    exit 1
}
mapfile -t LOCAL_ASSETS < <(grep -oE '/assets/[A-Za-z0-9._/-]+' "$DIST_DIR/index.html" | sort -u)
((${#LOCAL_ASSETS[@]} > 0)) || { echo "ERROR: frontend index.html does not reference any assets" >&2; exit 1; }
for asset in "${LOCAL_ASSETS[@]}"; do
    [[ -f "$DIST_DIR/${asset#/}" ]] || { echo "ERROR: referenced asset is missing: $asset" >&2; exit 1; }
done

if [[ -z "$RELEASE_ID" ]]; then
    git_id="$(git -C "$FRONTEND_DIR" rev-parse --short HEAD 2>/dev/null || printf 'worktree')"
    RELEASE_ID="$(date -u +%Y%m%dT%H%M%SZ)-$git_id-$$"
fi

ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/arcway-web.XXXXXX.tar.gz")"
REMOTE_ARCHIVE=""
cleanup_local() {
    rm -f "$ARCHIVE"
    if [[ -n "$REMOTE_ARCHIVE" ]]; then
        ssh "${SSH_ARGS[@]}" "$SSH_TARGET" bash -s -- "$REMOTE_ROOT" "$REMOTE_ARCHIVE" >/dev/null 2>&1 <<'REMOTE_CLEANUP' || true
set -euo pipefail
root="$1"
archive="$2"
name="${archive#"$root/.uploads/"}"
if [[ "$archive" == "$root/.uploads/$name" && "$name" =~ ^frontend\.[A-Za-z0-9]{8}\.tar\.gz$ && -f "$archive" && ! -L "$archive" ]]; then
    rm -f -- "$archive"
fi
REMOTE_CLEANUP
    fi
}
trap cleanup_local EXIT
tar -C "$DIST_DIR" -czf "$ARCHIVE" .
ARCHIVE_HASH="$(sha256sum "$ARCHIVE" | cut -c1-64)"

REMOTE_ARCHIVE="$(ssh "${SSH_ARGS[@]}" "$SSH_TARGET" bash -s -- "$REMOTE_ROOT" <<'REMOTE_PREPARE'
set -euo pipefail
root="$1"
[[ "$root" =~ ^(/[A-Za-z0-9._-]+){3,}$ && "/$root/" != *"/../"* && "/$root/" != *"/./"* && ! -L "$root" ]] || exit 2
install -d -m 0755 "$root"
[[ -d "$root" && ! -L "$root" && "$(stat -c %u "$root")" == "$(id -u)" ]] || {
    echo "ERROR: frontend root is not owned by the deploy user: $root" >&2
    exit 1
}
uploads="$root/.uploads"
if [[ -e "$uploads" || -L "$uploads" ]]; then
    [[ -d "$uploads" && ! -L "$uploads" && "$(stat -c %u "$uploads")" == "$(id -u)" ]] || {
        echo "ERROR: unsafe frontend upload directory: $uploads" >&2
        exit 1
    }
else
    install -d -m 0700 "$uploads"
fi
chmod 0700 "$uploads"
mktemp "$uploads/frontend.XXXXXXXX.tar.gz"
REMOTE_PREPARE
)"
remote_archive_name="${REMOTE_ARCHIVE#"$REMOTE_ROOT/.uploads/"}"
[[ "$REMOTE_ARCHIVE" == "$REMOTE_ROOT/.uploads/$remote_archive_name" && "$remote_archive_name" =~ ^frontend\.[A-Za-z0-9]{8}\.tar\.gz$ ]] || {
    echo "ERROR: server returned an unsafe upload path" >&2
    exit 1
}
scp -q -P "$DEPLOY_PORT" -o BatchMode=yes -o ConnectTimeout=10 "$ARCHIVE" "$SSH_TARGET:$REMOTE_ARCHIVE"

ssh "${SSH_ARGS[@]}" "$SSH_TARGET" bash -s -- deploy "$REMOTE_ROOT" "$RELEASE_ID" "$REMOTE_ARCHIVE" "$ARCHIVE_HASH" <<'REMOTE'
set -euo pipefail
mode="$1"
root="$2"
release="$3"
archive="$4"
expected_hash="$5"

[[ "$mode" == "deploy" && "$root" =~ ^(/[A-Za-z0-9._-]+){3,}$ && "/$root/" != *"/../"* && "/$root/" != *"/./"* ]] || exit 2
[[ "$release" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || exit 2
archive_name="${archive#"$root/.uploads/"}"
[[ -d "$root" && ! -L "$root" && -d "$root/.uploads" && ! -L "$root/.uploads" ]] || exit 2
[[ "$archive" == "$root/.uploads/$archive_name" && "$archive_name" =~ ^frontend\.[A-Za-z0-9]{8}\.tar\.gz$ && -f "$archive" && ! -L "$archive" ]] || exit 2
[[ "$(stat -c %u "$root")" == "$(id -u)" && "$(stat -c %u "$root/.uploads")" == "$(id -u)" && "$(stat -c %u "$archive")" == "$(id -u)" ]] || exit 2
trap 'rm -f "$archive"' EXIT
[[ "$expected_hash" =~ ^[a-f0-9]{64}$ ]] || exit 2
[[ "$(sha256sum "$archive" | cut -c1-64)" == "$expected_hash" ]] || {
    echo "ERROR: uploaded frontend archive checksum mismatch" >&2
    exit 1
}

[[ "$(stat -c %u "$root")" == "$(id -u)" ]] || { echo "ERROR: frontend root has the wrong owner" >&2; exit 1; }
if find "$root" -maxdepth 0 -perm /0022 -print -quit | grep -q .; then
    echo "ERROR: frontend root is group- or world-writable" >&2
    exit 1
fi
command -v flock >/dev/null || { echo "ERROR: flock is required on the server" >&2; exit 1; }
lock="$root/.deploy.lock"
if [[ ! -e "$lock" && ! -L "$lock" ]]; then
    (umask 077; set -o noclobber; : > "$lock") 2>/dev/null || true
fi
[[ -f "$lock" && ! -L "$lock" && "$(stat -c %u "$lock")" == "$(id -u)" ]] || { echo "ERROR: unsafe deploy lock: $lock" >&2; exit 1; }
chmod 0600 "$lock"
exec 9<>"$lock"
flock -x 9

releases="$root/releases"
target="$releases/$release"
staging="$releases/.staging-$release"

normalize_managed_target() {
    local target="$1"
    if [[ "$target" == /* ]]; then
        [[ "$target" == "$root/releases/"* ]] || return 1
        target="releases/${target#"$root/releases/"}"
    fi
    [[ "$target" =~ ^releases/([A-Za-z0-9][A-Za-z0-9._-]*)$ ]] || return 1
    printf '%s\n' "$target"
}

if [[ -e "$releases" || -L "$releases" ]]; then
    [[ -d "$releases" && ! -L "$releases" && "$(stat -c %u "$releases")" == "$(id -u)" ]] || { echo "ERROR: unsafe releases directory: $releases" >&2; exit 1; }
    if find "$releases" -maxdepth 0 -perm /0022 -print -quit | grep -q .; then
        echo "ERROR: releases directory is group- or world-writable" >&2
        exit 1
    fi
else
    mkdir -m 0755 "$releases"
fi
[[ ! -e "$target" && ! -L "$target" && ! -e "$staging" ]] || {
    echo "ERROR: release already exists: $release" >&2
    exit 1
}

mkdir "$staging"
cleanup() {
    rm -f "$archive"
    if [[ -d "$staging" ]]; then
        find "$staging" -mindepth 1 -delete
        rmdir "$staging"
    fi
}
trap cleanup EXIT

tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$staging"
if find "$staging" -type l -print -quit | grep -q .; then
    echo "ERROR: frontend release may not contain symbolic links" >&2
    exit 1
fi
[[ -s "$staging/index.html" && -d "$staging/assets" ]] || {
    echo "ERROR: uploaded frontend release is incomplete" >&2
    exit 1
}
grep -q '__RELAYDOCK_DEFAULT_THEME__' "$staging/index.html" || {
    echo "ERROR: uploaded index.html is invalid" >&2
    exit 1
}
mapfile -t uploaded_assets < <(grep -oE '/assets/[A-Za-z0-9._/-]+' "$staging/index.html" | sort -u)
((${#uploaded_assets[@]} > 0)) || { echo "ERROR: uploaded index.html does not reference any assets" >&2; exit 1; }
for asset in "${uploaded_assets[@]}"; do
    [[ -f "$staging/${asset#/}" ]] || { echo "ERROR: uploaded asset is missing: $asset" >&2; exit 1; }
done

current_target=""
if [[ -e "$root/current" && ! -L "$root/current" ]]; then
    echo "ERROR: $root/current exists but is not a managed symbolic link" >&2
    exit 1
fi
if [[ -L "$root/current" ]]; then
    current_target="$(normalize_managed_target "$(readlink "$root/current")")" || {
        echo "ERROR: current link does not point to a managed release" >&2
        exit 1
    }
    [[ -d "$root/$current_target" && ! -L "$root/$current_target" ]] || {
        echo "ERROR: current link does not point to a managed release" >&2
        exit 1
    }
    [[ -d "$root/$current_target/assets" && ! -L "$root/$current_target/assets" ]] || {
        echo "ERROR: current release has no safe assets directory" >&2
        exit 1
    }
    if find "$root/$current_target" -type l -print -quit | grep -q .; then
        echo "ERROR: current release contains symbolic links" >&2
        exit 1
    fi
    cp -aln "$root/$current_target/assets/." "$staging/assets/"
fi
if find "$staging" -type l -print -quit | grep -q .; then
    echo "ERROR: merged frontend release contains symbolic links" >&2
    exit 1
fi

find "$staging" -type d -exec chmod 0755 {} +
find "$staging" -type f -exec chmod 0644 {} +
mv "$staging" "$target"

next_link="$root/.current-$release-$$"
if [[ -n "$current_target" ]]; then
    if [[ -e "$root/previous" && ! -L "$root/previous" ]]; then
        echo "ERROR: $root/previous exists but is not a managed symbolic link" >&2
        exit 1
    fi
    previous_link="$root/.previous-$release-$$"
    ln -s "$current_target" "$previous_link"
    mv -Tf "$previous_link" "$root/previous"
fi
ln -s "releases/$release" "$next_link"
mv -Tf "$next_link" "$root/current"
rm -f "$archive"
trap - EXIT
echo "Frontend activated without service restart: $release"
echo "Release path: $target"
REMOTE
REMOTE_ARCHIVE=""
