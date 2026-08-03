#!/bin/bash

# RelayDock - Xray shared-node control plane installer
# 适用于 Debian/Ubuntu Linux 系统

set -e

# 配置
GITHUB_REPO="violetaini/relaydock"
VERSION=""  # 将自动获取最新版本
BINARY_NAME=""  # 将根据架构自动设置
INSTALL_DIR="${ARCWAY_INSTALL_DIR:-/usr/local/bin}"
SERVICE_NAME="arcway"
DATA_DIR="${ARCWAY_DATA_DIR:-/etc/arcway}"
CONFIG_DIR="${ARCWAY_CONFIG_DIR:-$DATA_DIR}"
GUARD_ASSET_DIR="${ARCWAY_GUARD_ASSET_DIR:-/usr/local/lib/arcway/guard-assets}"
SYSTEMD_UNIT_DIR="${ARCWAY_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
SERVICE_FILE="$SYSTEMD_UNIT_DIR/${SERVICE_NAME}.service"
INSTALL_LOCK_FILE="${ARCWAY_INSTALL_LOCK_FILE:-/run/arcway-install.lock}"
PANEL_SOURCE_IPS="${ARCWAY_PANEL_IPS:-}"
DATABASE_PATH="${ARCWAY_DATABASE_PATH:-}"
TMP_DIR=""
UPDATE_TRANSACTION_ACTIVE=false
UPDATE_BACKUP_DIR=""
OLD_SERVICE_ACTIVE=false
OLD_SERVICE_PRESENT=false
OLD_SERVICE_ENABLE_STATE=""
UPDATE_TRACKED_PATHS=()
UPDATE_MANAGED_DIRS=()
UPDATE_MANAGED_DIR_STATES=()
UPDATE_MANAGED_DIR_MODES=()
ATOMIC_STAGE_PATHS=()
GUARD_PARENT_DIR=""
OLD_GUARD_PARENT_PRESENT=false
PRESERVE_TMP_DIR=false

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Preserve locations from installations created before the /usr/local layout.
detect_existing_installation_paths() {
    [ -f "$SERVICE_FILE" ] || return 0

    local existing_exec=""
    local existing_working_dir=""
    local existing_database=""
    local existing_guard_dir=""
    local existing_env_file=""

    existing_exec=$(sed -n 's/^ExecStart=\([^[:space:]]*\).*$/\1/p' "$SERVICE_FILE" | head -n 1)
    existing_working_dir=$(sed -n 's/^WorkingDirectory=\([^[:space:]]*\).*$/\1/p' "$SERVICE_FILE" | head -n 1)
    existing_database=$(sed -n 's/^Environment="DATABASE_PATH=\(.*\)"$/\1/p' "$SERVICE_FILE" | head -n 1)
    existing_guard_dir=$(sed -n 's/^Environment="ARCWAY_GUARD_ASSET_DIR=\(.*\)"$/\1/p' "$SERVICE_FILE" | head -n 1)
    existing_env_file=$(sed -n 's/^EnvironmentFile=-\{0,1\}\([^[:space:]]*\).*$/\1/p' "$SERVICE_FILE" | head -n 1)

    if [ -n "$existing_env_file" ] && [ -f "$existing_env_file" ]; then
        if [ -z "$existing_database" ]; then
            existing_database=$(sed -n 's/^DATABASE_PATH=\(.*\)$/\1/p' "$existing_env_file" | head -n 1)
        fi
        if [ -z "$existing_guard_dir" ]; then
            existing_guard_dir=$(sed -n 's/^ARCWAY_GUARD_ASSET_DIR=\(.*\)$/\1/p' "$existing_env_file" | head -n 1)
        fi
    fi

    existing_database=${existing_database#\"}
    existing_database=${existing_database%\"}
    existing_guard_dir=${existing_guard_dir#\"}
    existing_guard_dir=${existing_guard_dir%\"}

    if [ "${ARCWAY_INSTALL_DIR+x}" != "x" ] && [ -n "$existing_exec" ] && [ "$(basename "$existing_exec")" = "$SERVICE_NAME" ]; then
        INSTALL_DIR=$(dirname "$existing_exec")
    fi
    if [ "${ARCWAY_DATA_DIR+x}" != "x" ]; then
        if [ -n "$existing_database" ]; then
            DATA_DIR=$(dirname "$existing_database")
        elif [ -n "$existing_working_dir" ] && [ -d "$existing_working_dir/data" ]; then
            DATA_DIR="$existing_working_dir/data"
        elif [ -n "$existing_working_dir" ] && [ -f "$existing_working_dir/.version" ]; then
            DATA_DIR="$existing_working_dir"
        fi
    fi
    if [ "${ARCWAY_CONFIG_DIR+x}" != "x" ] && [ -n "$existing_env_file" ]; then
        CONFIG_DIR=$(dirname "$existing_env_file")
    fi
    if [ "${ARCWAY_GUARD_ASSET_DIR+x}" != "x" ] && [ -n "$existing_guard_dir" ]; then
        GUARD_ASSET_DIR="$existing_guard_dir"
    fi

    if [ -n "$existing_exec" ]; then
        echo_info "检测到现有安装布局: $INSTALL_DIR（数据目录: $DATA_DIR）"
    fi
}

acquire_install_lock() {
    if ! command -v flock >/dev/null 2>&1; then
        echo_error "系统缺少 flock，无法安全执行安装事务"
        return 1
    fi
    if ! { exec 9>"$INSTALL_LOCK_FILE"; }; then
        echo_error "无法打开安装锁: $INSTALL_LOCK_FILE"
        return 1
    fi
    if ! flock -n 9; then
        echo_error "另一个 RelayDock 安装或更新进程正在运行"
        return 1
    fi
}

register_atomic_stage() {
    ATOMIC_STAGE_PATHS+=("$1")
}

new_atomic_stage() {
    target=$1
    suffix=${2:-file}
    target_dir=$(dirname "$target")
    target_base=$(basename "$target")
    ATOMIC_STAGE_PATH="$target_dir/.${target_base}.arcway-stage.$$.$RANDOM.$suffix"
    register_atomic_stage "$ATOMIC_STAGE_PATH"
}

atomic_install_file() {
    source_path=$1
    target_path=$2
    target_mode=$3
    mkdir -p "$(dirname "$target_path")" || return 1
    new_atomic_stage "$target_path" || return 1
    install -m "$target_mode" "$source_path" "$ATOMIC_STAGE_PATH" || return 1
    mv -fT -- "$ATOMIC_STAGE_PATH" "$target_path"
}

atomic_copy_file() {
    source_path=$1
    target_path=$2
    mkdir -p "$(dirname "$target_path")" || return 1
    new_atomic_stage "$target_path" || return 1
    cp -a -- "$source_path" "$ATOMIC_STAGE_PATH" || return 1
    mv -fT -- "$ATOMIC_STAGE_PATH" "$target_path"
}

atomic_write_version() {
    target_path=$1
    mkdir -p "$(dirname "$target_path")" || return 1
    new_atomic_stage "$target_path" || return 1
    if ! printf '%s\n' "$VERSION" > "$ATOMIC_STAGE_PATH"; then
        return 1
    fi
    chmod 0644 "$ATOMIC_STAGE_PATH" || return 1
    mv -fT -- "$ATOMIC_STAGE_PATH" "$target_path"
}

atomic_remove_file() {
    target_path=$1
    if [ ! -e "$target_path" ] && [ ! -L "$target_path" ]; then
        return 0
    fi
    new_atomic_stage "$target_path" removed || return 1
    mv -fT -- "$target_path" "$ATOMIC_STAGE_PATH" || return 1
    rm -f -- "$ATOMIC_STAGE_PATH"
}

arcway_test_failpoint() {
    if [ "${ARCWAY_TEST_FAILPOINT:-}" = "$1" ]; then
        echo_error "触发安装事务测试故障点: $1"
        return 1
    fi
}

# 检查是否为 root 用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo_error "请使用 root 权限运行此脚本"
        echo_info "使用命令: sudo bash install.sh"
        exit 1
    fi
}

# 检查系统架构
check_architecture() {
    ARCH=$(uname -m)
    echo_info "检测到系统架构: $ARCH"

    case "$ARCH" in
        x86_64|amd64)
            BINARY_NAME="arcway-linux-amd64"
            echo_info "使用 AMD64 版本"
            ;;
        aarch64|arm64)
            BINARY_NAME="arcway-linux-arm64"
            echo_info "使用 ARM64 版本"
            ;;
        *)
            echo_error "不支持的架构: $ARCH"
            echo_error "支持的架构: x86_64 (amd64), aarch64 (arm64)"
            exit 1
            ;;
    esac
}

# 安装依赖
install_dependencies() {
    local packages=()
    command -v wget >/dev/null 2>&1 || packages+=(wget)
    command -v curl >/dev/null 2>&1 || packages+=(curl)
    command -v jq >/dev/null 2>&1 || packages+=(jq)
    command -v systemctl >/dev/null 2>&1 || packages+=(systemd)
    command -v sha256sum >/dev/null 2>&1 || packages+=(coreutils)

    if [ "${#packages[@]}" -eq 0 ]; then
        echo_info "安装依赖已就绪"
        return 0
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        echo_error "缺少依赖且当前系统没有 apt: ${packages[*]}"
        return 1
    fi

    echo_info "安装缺少的依赖: ${packages[*]}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" >/dev/null 2>&1
}

# 获取最新版本号
get_latest_version() {
    if [ -z "$VERSION" ]; then
        echo_info "获取最新版本..."
        VERSION=$(curl -sL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | jq -r '.tag_name')
        if [ -z "$VERSION" ] || [ "$VERSION" = "null" ]; then
            echo_error "无法获取最新版本号，请检查网络连接"
            exit 1
        fi
        echo_info "最新版本: $VERSION"
    fi
}

# 下载二进制文件
download_binary() {
    echo_info "下载 $SERVICE_NAME $VERSION..."
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${BINARY_NAME}"

    if [ -z "$TMP_DIR" ]; then
        TMP_DIR=$(mktemp -d)
        chmod 700 "$TMP_DIR"
    fi
    if wget -q --show-progress "$DOWNLOAD_URL" -O "$TMP_DIR/$BINARY_NAME"; then
        echo_info "下载完成"
    else
        echo_error "下载失败，请检查网络连接或版本号"
        exit 1
    fi

    for guard in arcway-expiry-guard-linux-amd64 arcway-expiry-guard-linux-arm64; do
        if ! wget -q "https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${guard}" -O "$TMP_DIR/$guard"; then
            echo_error "下载到期守护程序失败: $guard"
            exit 1
        fi
    done

    if ! wget -q "https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/checksums.txt" -O "$TMP_DIR/checksums.txt"; then
        echo_error "下载校验和失败"
        exit 1
    fi
    for asset in \
        "$BINARY_NAME" \
        arcway-expiry-guard-linux-amd64 \
        arcway-expiry-guard-linux-arm64; do
        expected=$(awk -v name="$asset" '$2 == name { print $1; exit }' "$TMP_DIR/checksums.txt")
        actual=$(sha256sum "$TMP_DIR/$asset" | awk '{ print $1 }')
        if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
            echo_error "SHA-256 校验失败: $asset"
            exit 1
        fi
    done
    echo_info "SHA-256 校验通过"
}

# 安装二进制文件
install_binary() {
    echo_info "安装二进制文件..."
    if ! atomic_install_file "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$SERVICE_NAME" 0755; then
        return 1
    fi
    if ! arcway_test_failpoint after_binary_swap; then
        return 1
    fi
    install -d -m 0755 "$GUARD_ASSET_DIR"
    guard_index=0
    for guard in arcway-expiry-guard-linux-amd64 arcway-expiry-guard-linux-arm64; do
        if ! atomic_install_file "$TMP_DIR/$guard" "$GUARD_ASSET_DIR/$guard" 0755; then
            return 1
        fi
        guard_index=$((guard_index + 1))
        if [ "$guard_index" -eq 1 ]; then
            if ! arcway_test_failpoint after_first_guard_swap; then
                return 1
            fi
        fi
    done
    echo_info "已安装到 $INSTALL_DIR/$SERVICE_NAME"
}

# 创建数据目录
create_directories() {
    echo_info "创建数据目录..."
    mkdir -p "$DATA_DIR"
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$DATA_DIR"
    chmod 700 "$CONFIG_DIR"
}

track_transaction_directory() {
    managed_dir=$1
    for existing_dir in "${UPDATE_MANAGED_DIRS[@]}"; do
        if [ "$existing_dir" = "$managed_dir" ]; then
            return 0
        fi
    done

    UPDATE_MANAGED_DIRS+=("$managed_dir")
    if [ -d "$managed_dir" ]; then
        UPDATE_MANAGED_DIR_STATES+=("directory")
        UPDATE_MANAGED_DIR_MODES+=("$(stat -c '%a' "$managed_dir")")
    elif [ -e "$managed_dir" ] || [ -L "$managed_dir" ]; then
        UPDATE_MANAGED_DIR_STATES+=("other")
        UPDATE_MANAGED_DIR_MODES+=("")
    else
        UPDATE_MANAGED_DIR_STATES+=("missing")
        UPDATE_MANAGED_DIR_MODES+=("")
    fi
}

begin_update_transaction() {
    if [ -z "$TMP_DIR" ] || [ ! -d "$TMP_DIR" ]; then
        echo_error "更新临时目录不存在，拒绝修改当前安装"
        return 1
    fi
    UPDATE_BACKUP_DIR="$TMP_DIR/rollback"
    mkdir -p "$UPDATE_BACKUP_DIR"
    PRESERVE_TMP_DIR=false
    OLD_SERVICE_ACTIVE=false
    OLD_SERVICE_PRESENT=false
    OLD_SERVICE_ENABLE_STATE=""
    if systemctl cat "${SERVICE_NAME}.service" >/dev/null 2>&1; then
        OLD_SERVICE_PRESENT=true
        OLD_SERVICE_ENABLE_STATE=$(systemctl is-enabled "${SERVICE_NAME}.service" 2>/dev/null || true)
        case "$OLD_SERVICE_ENABLE_STATE" in
            enabled|enabled-runtime|disabled|static)
                ;;
            *)
                echo_error "服务启用状态不受支持: ${OLD_SERVICE_ENABLE_STATE:-unknown}"
                echo_error "仅允许 enabled、enabled-runtime、disabled 或 static，尚未修改现有安装"
                return 1
                ;;
        esac
        if systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
            OLD_SERVICE_ACTIVE=true
        fi
    fi

    UPDATE_TRACKED_PATHS=(
        "$INSTALL_DIR/$SERVICE_NAME"
        "$INSTALL_DIR/${SERVICE_NAME}.bak"
        "$GUARD_ASSET_DIR/arcway-expiry-guard-linux-amd64"
        "$GUARD_ASSET_DIR/arcway-expiry-guard-linux-arm64"
        "$SERVICE_FILE"
        "$DATA_DIR/.version"
    )
    UPDATE_MANAGED_DIRS=()
    UPDATE_MANAGED_DIR_STATES=()
    UPDATE_MANAGED_DIR_MODES=()
    track_transaction_directory "$DATA_DIR"
    track_transaction_directory "$CONFIG_DIR"
    track_transaction_directory "$GUARD_ASSET_DIR"
    GUARD_PARENT_DIR=$(dirname "$GUARD_ASSET_DIR")
    OLD_GUARD_PARENT_PRESENT=false
    if [ -d "$GUARD_PARENT_DIR" ]; then
        OLD_GUARD_PARENT_PRESENT=true
    fi
    for tracked_path in "${UPDATE_TRACKED_PATHS[@]}"; do
        backup_path="$UPDATE_BACKUP_DIR$tracked_path"
        mkdir -p "$(dirname "$backup_path")"
        if [ -e "$tracked_path" ] || [ -L "$tracked_path" ]; then
            cp -a "$tracked_path" "$backup_path"
        else
            : > "$backup_path.arcway-missing"
        fi
    done
    UPDATE_TRANSACTION_ACTIVE=true
}

stop_service_for_transaction() {
    service_unit="${SERVICE_NAME}.service"
    if ! systemctl cat "$service_unit" >/dev/null 2>&1; then
        echo_info "服务未加载，无需停止"
        return 0
    fi

    echo_info "停止服务..."
    if ! systemctl stop "$service_unit"; then
        echo_error "停止服务失败，拒绝继续替换文件"
        return 1
    fi

    stop_attempt=0
    while [ "$stop_attempt" -lt 10 ]; do
        if ! active_state=$(systemctl show --property=ActiveState --value "$service_unit" 2>/dev/null); then
            echo_error "无法确认服务停止状态，拒绝继续替换文件"
            return 1
        fi
        case "$active_state" in
            inactive|failed)
                echo_info "服务已停止（状态: $active_state）"
                return 0
                ;;
        esac
        stop_attempt=$((stop_attempt + 1))
        sleep 1
    done

    echo_error "服务停止超时（当前状态: ${active_state:-unknown}），拒绝继续替换文件"
    return 1
}

database_has_state() {
    candidate=$1
    [ -e "$candidate" ] || [ -e "$candidate-wal" ] || [ -e "$candidate-shm" ]
}

resolve_database_path() {
    # ARCWAY_DATABASE_PATH is an explicit operator override and always wins.
    if [ -n "$DATABASE_PATH" ]; then
        return 0
    fi

    service_working_dir=""
    service_database=""
    service_env_file=""
    if [ -f "$SERVICE_FILE" ]; then
        service_working_dir=$(sed -n 's/^WorkingDirectory=\([^[:space:]]*\).*$/\1/p' "$SERVICE_FILE" | head -n 1)
        service_database=$(sed -n 's/^Environment="DATABASE_PATH=\(.*\)"$/\1/p' "$SERVICE_FILE" | head -n 1)
        service_env_file=$(sed -n 's/^EnvironmentFile=-\{0,1\}\([^[:space:]]*\).*$/\1/p' "$SERVICE_FILE" | head -n 1)
    fi
    if [ -z "$service_database" ] && [ -n "$service_env_file" ] && [ -f "$service_env_file" ]; then
        service_database=$(sed -n 's/^DATABASE_PATH=\(.*\)$/\1/p' "$service_env_file" | head -n 1)
    fi
    service_database=${service_database#\"}
    service_database=${service_database%\"}

    # Prefer an existing Arcway database over an unused service override.
    for candidate in \
        "${service_working_dir:+$service_working_dir/data/arcway.db}" \
        "$DATA_DIR/arcway.db" \
        "$DATA_DIR/data/arcway.db" \
        "$service_database"; do
        if [ -n "$candidate" ] && database_has_state "$candidate"; then
            DATABASE_PATH=$candidate
            return 0
        fi
    done

    if [ -n "$service_working_dir" ]; then
        DATABASE_PATH="$service_working_dir/data/arcway.db"
    elif [ -n "$service_database" ]; then
        DATABASE_PATH=$service_database
    else
        DATABASE_PATH="$DATA_DIR/data/arcway.db"
    fi
}

snapshot_database_after_stop() {
    resolve_database_path
    case "$DATABASE_PATH" in
        /*) ;;
        *)
            echo_error "数据库路径必须是绝对路径: $DATABASE_PATH"
            return 1
            ;;
    esac
    case "$DATABASE_PATH" in
        *$'\n'*|*$'\r'*)
            echo_error "数据库路径包含非法换行"
            return 1
            ;;
    esac

    echo_info "数据库事务快照: $DATABASE_PATH"

    for tracked_path in "$DATABASE_PATH" "$DATABASE_PATH-wal" "$DATABASE_PATH-shm"; do
        UPDATE_TRACKED_PATHS+=("$tracked_path")
        backup_path="$UPDATE_BACKUP_DIR$tracked_path"
        mkdir -p "$(dirname "$backup_path")" || return 1
        if [ -e "$tracked_path" ] || [ -L "$tracked_path" ]; then
            cp -a -- "$tracked_path" "$backup_path" || return 1
        else
            : > "$backup_path.arcway-missing" || return 1
        fi
    done
}

rollback_update_transaction() {
    echo_error "安装或更新失败，正在恢复原状态..."
    rollback_failed=false
    if systemctl cat "${SERVICE_NAME}.service" >/dev/null 2>&1; then
        if ! stop_service_for_transaction >/dev/null 2>&1; then
            rollback_failed=true
        fi
        # 先移除本次事务可能创建的持久/runtime 链接及 mask，再恢复旧 unit 和精确启用状态。
        if ! systemctl disable "${SERVICE_NAME}.service" >/dev/null 2>&1; then
            rollback_failed=true
        fi
        if ! systemctl disable --runtime "${SERVICE_NAME}.service" >/dev/null 2>&1; then
            rollback_failed=true
        fi
        if ! systemctl unmask "${SERVICE_NAME}.service" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    fi
    for tracked_path in "${UPDATE_TRACKED_PATHS[@]}"; do
        backup_path="$UPDATE_BACKUP_DIR$tracked_path"
        if [ -e "$backup_path.arcway-missing" ]; then
            if ! atomic_remove_file "$tracked_path"; then
                rollback_failed=true
            fi
        elif [ -e "$backup_path" ] || [ -L "$backup_path" ]; then
            if ! atomic_copy_file "$backup_path" "$tracked_path"; then
                rollback_failed=true
            fi
        fi
    done

    managed_dir_index=0
    while [ "$managed_dir_index" -lt "${#UPDATE_MANAGED_DIRS[@]}" ]; do
        managed_dir=${UPDATE_MANAGED_DIRS[$managed_dir_index]}
        managed_dir_state=${UPDATE_MANAGED_DIR_STATES[$managed_dir_index]}
        managed_dir_mode=${UPDATE_MANAGED_DIR_MODES[$managed_dir_index]}
        if [ "$managed_dir_state" = "missing" ]; then
            if ! rm -rf "$managed_dir"; then
                rollback_failed=true
            fi
        elif [ "$managed_dir_state" = "directory" ]; then
            if [ ! -d "$managed_dir" ] || ! chmod "$managed_dir_mode" "$managed_dir"; then
                rollback_failed=true
            fi
        fi
        managed_dir_index=$((managed_dir_index + 1))
    done
    if [ "$OLD_GUARD_PARENT_PRESENT" = false ] && [ -n "$GUARD_PARENT_DIR" ]; then
        rmdir "$GUARD_PARENT_DIR" >/dev/null 2>&1 || true
    fi
    if ! systemctl daemon-reload >/dev/null 2>&1; then
        rollback_failed=true
    fi
    if [ "$OLD_SERVICE_PRESENT" = true ]; then
        case "$OLD_SERVICE_ENABLE_STATE" in
            enabled)
                if ! systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1; then
                    rollback_failed=true
                fi
                ;;
            enabled-runtime)
                if ! systemctl enable --runtime "${SERVICE_NAME}.service" >/dev/null 2>&1; then
                    rollback_failed=true
                fi
                ;;
            disabled|static)
                ;;
            *)
                rollback_failed=true
                ;;
        esac
        restored_enable_state=$(systemctl is-enabled "${SERVICE_NAME}.service" 2>/dev/null || true)
        if [ "$restored_enable_state" != "$OLD_SERVICE_ENABLE_STATE" ]; then
            rollback_failed=true
        fi
        if [ "$OLD_SERVICE_ACTIVE" = true ]; then
            if ! systemctl start "${SERVICE_NAME}.service" >/dev/null 2>&1 ||
                ! systemctl is-active --quiet "${SERVICE_NAME}.service" >/dev/null 2>&1; then
                rollback_failed=true
            fi
        elif systemctl is-active --quiet "${SERVICE_NAME}.service" >/dev/null 2>&1; then
            rollback_failed=true
        fi
    fi
    UPDATE_TRANSACTION_ACTIVE=false
    if [ "$rollback_failed" = true ]; then
        echo_error "自动恢复未完全成功，请立即检查文件和服务状态"
        return 1
    fi
    echo_error "已恢复原状态；请查看日志: journalctl -u $SERVICE_NAME -n 50"
    return 0
}

commit_update_transaction() {
    UPDATE_TRANSACTION_ACTIVE=false
}

verify_and_commit_systemd_unit() {
    staged_unit=$1
    if ! command -v systemd-analyze >/dev/null 2>&1; then
        echo_error "系统缺少 systemd-analyze，拒绝替换服务 unit"
        return 1
    fi
    if ! systemd-analyze verify "$staged_unit"; then
        echo_error "systemd unit 校验失败，拒绝替换当前 unit"
        return 1
    fi
    chmod 0644 "$staged_unit" || return 1
    mv -fT -- "$staged_unit" "$SERVICE_FILE"
}

# 创建 systemd 服务
create_systemd_service() {
    echo_info "创建 systemd 服务..."

    if [ "${ARCWAY_PANEL_IPS+x}" != "x" ] && [ -z "$PANEL_SOURCE_IPS" ] && [ -f "$SERVICE_FILE" ]; then
        PANEL_SOURCE_IPS=$(sed -n 's/^Environment="ARCWAY_PANEL_IPS=\(.*\)"$/\1/p' "$SERVICE_FILE" | head -n 1)
    fi

    # 覆盖安装时沿用当前端口；显式 PORT 始终优先。
    CURRENT_SERVICE_PORT=""
    if [ -f "$SERVICE_FILE" ]; then
        CURRENT_SERVICE_PORT=$(sed -n 's/^Environment="PORT=\([0-9]*\)"$/\1/p' "$SERVICE_FILE" | head -n 1)
    fi
    DEFAULT_PORT=${CURRENT_SERVICE_PORT:-12889}

    # 询问端口号（支持非交互式环境）
    echo ""
    if [ -n "${PORT:-}" ]; then
        PORT_INPUT=$PORT
        echo_info "使用环境变量指定的端口: $PORT_INPUT"
    elif [ -t 0 ]; then
        # 交互式环境，可以读取用户输入
        read -r -p "请输入端口号（默认 $DEFAULT_PORT，直接回车使用默认值）: " PORT_INPUT
        if [ -z "$PORT_INPUT" ]; then
            PORT_INPUT=$DEFAULT_PORT
        fi
    else
        # 非交互式环境（如管道），使用默认值
        PORT_INPUT=$DEFAULT_PORT
        echo_info "使用端口: $PORT_INPUT"
    fi

    case "$PORT_INPUT" in
        ''|*[!0-9]*)
            echo_error "端口必须是 1 到 65535 之间的整数"
            return 1
            ;;
    esac
    if [ "$PORT_INPUT" -lt 1 ] || [ "$PORT_INPUT" -gt 65535 ]; then
        echo_error "端口必须是 1 到 65535 之间的整数"
        return 1
    fi

    mkdir -p "$(dirname "$SERVICE_FILE")"
    new_atomic_stage "$SERVICE_FILE" service
    staged_unit=$ATOMIC_STAGE_PATH
    cat > "$staged_unit" <<EOF
[Unit]
Description=RelayDock shared-node control plane
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=$DATA_DIR
ExecStart=$INSTALL_DIR/$SERVICE_NAME
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# 环境变量
Environment="PORT=$PORT_INPUT"
Environment="DATABASE_PATH=$DATA_DIR/data/arcway.db"
Environment="LOG_LEVEL=info"
Environment="ARCWAY_GUARD_ASSET_DIR=$GUARD_ASSET_DIR"
Environment="ARCWAY_PANEL_IPS=$PANEL_SOURCE_IPS"

# 安全选项
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    if ! verify_and_commit_systemd_unit "$staged_unit"; then
        return 1
    fi
    if ! systemctl daemon-reload; then
        echo_error "systemd daemon-reload 失败"
        return 1
    fi
    echo_info "systemd 服务已创建（端口: $PORT_INPUT）"
}

update_systemd_service_settings() {
    port_value=$1
    if [ ! -f "$SERVICE_FILE" ]; then
        echo_error "现有 systemd unit 不存在: $SERVICE_FILE"
        return 1
    fi

    new_atomic_stage "$SERVICE_FILE" service
    staged_unit=$ATOMIC_STAGE_PATH
    cp -a -- "$SERVICE_FILE" "$staged_unit" || return 1
    sed -i "s/Environment=\"PORT=[0-9]*\"/Environment=\"PORT=$port_value\"/" "$staged_unit" || return 1

    panel_ips_env_exists=false
    if grep -q '^Environment="ARCWAY_PANEL_IPS=' "$staged_unit"; then
        panel_ips_env_exists=true
    fi
    if [ "${ARCWAY_PANEL_IPS+x}" = "x" ] || [ "$panel_ips_env_exists" = false ]; then
        escaped_panel_source_ips=$(printf '%s' "$PANEL_SOURCE_IPS" | sed 's/[&|\\]/\\&/g')
        if [ "$panel_ips_env_exists" = true ]; then
            sed -i "s|^Environment=\"ARCWAY_PANEL_IPS=.*\"$|Environment=\"ARCWAY_PANEL_IPS=$escaped_panel_source_ips\"|" "$staged_unit"
        elif grep -q '^Environment="ARCWAY_GUARD_ASSET_DIR=' "$staged_unit"; then
            sed -i "/^Environment=\"ARCWAY_GUARD_ASSET_DIR=/a Environment=\"ARCWAY_PANEL_IPS=$escaped_panel_source_ips\"" "$staged_unit"
        else
            sed -i "/^\[Install\]/i Environment=\"ARCWAY_PANEL_IPS=$escaped_panel_source_ips\"" "$staged_unit"
        fi
    fi

    # Agent and speedtester binaries are fetched directly from GitHub by their
    # own installers. Drop obsolete panel-local unit settings, but do not
    # touch a legacy asset directory or operator-managed EnvironmentFile.
    sed -i '/^Environment="ARCWAY_AGENT_ASSET_DIR=/d' "$staged_unit"
    sed -i '/^Environment="ARCWAY_SPEEDTESTER_ASSET_DIR=/d' "$staged_unit"

    if ! verify_and_commit_systemd_unit "$staged_unit"; then
        return 1
    fi
    if ! systemctl daemon-reload; then
        echo_error "systemd daemon-reload 失败"
        return 1
    fi
}

# 启动服务
start_service() {
    echo_info "启动服务..."
    if ! systemctl enable "${SERVICE_NAME}.service"; then
        echo_error "设置服务开机启动失败"
        return 1
    fi
    if ! systemctl start "${SERVICE_NAME}.service"; then
        echo_error "启动服务命令执行失败"
        return 1
    fi
    sleep 2

    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        echo_info "服务启动成功！"
        return 0
    else
        echo_error "服务启动失败"
        return 1
    fi
}

# 显示状态
show_status() {
    # 从 systemd 服务文件中读取端口号
    CONFIGURED_PORT=$(grep "Environment=\"PORT=" "$SERVICE_FILE" | sed 's/.*PORT=\([0-9]*\).*/\1/')
    CONFIGURED_PORT=${CONFIGURED_PORT:-12889}

    echo ""
    echo "======================================"
    echo_info "RelayDock 安装完成！"
    echo "======================================"
    echo ""
    echo "📦 安装位置: $INSTALL_DIR/$SERVICE_NAME"
    echo "💾 数据目录: $DATA_DIR"
    echo "🌐 访问地址: http://$(hostname -I | awk '{print $1}'):$CONFIGURED_PORT"
    echo ""
    echo "常用命令:"
    echo "  启动服务: systemctl start $SERVICE_NAME"
    echo "  停止服务: systemctl stop $SERVICE_NAME"
    echo "  重启服务: systemctl restart $SERVICE_NAME"
    echo "  查看状态: systemctl status $SERVICE_NAME"
    echo "  查看日志: journalctl -u $SERVICE_NAME -f"
    echo "  更新、重装与卸载: 请按项目 README 下载脚本后执行对应操作"
    echo "  使用说明: https://github.com/${GITHUB_REPO}#更新已安装的-relaydock"
    echo ""
    echo "⚠️  首次访问需要完成初始化配置"
    echo ""
}

# 更新服务
update_service() {
    echo_info "开始更新 RelayDock..."
    echo ""

    # 检查服务是否已安装
    if [ ! -f "$INSTALL_DIR/$SERVICE_NAME" ]; then
        echo_error "未检测到已安装的服务，请先使用安装模式"
        exit 1
    fi

    # 显示当前版本
    if [ -f "$DATA_DIR/.version" ]; then
        CURRENT_VERSION=$(cat "$DATA_DIR/.version")
        echo_info "当前版本: $CURRENT_VERSION"
    fi
    echo_info "目标版本: $VERSION"
    echo ""

    # 下载和校验必须先完成，网络失败时保持当前服务运行。
    download_binary
    begin_update_transaction

    if ! stop_service_for_transaction; then
        return 1
    fi
    snapshot_database_after_stop

    # 备份当前二进制文件
    if [ -f "$INSTALL_DIR/$SERVICE_NAME" ]; then
        echo_info "备份当前版本..."
        atomic_copy_file "$INSTALL_DIR/$SERVICE_NAME" "$INSTALL_DIR/${SERVICE_NAME}.bak"
    fi

    # 安装已校验的新版本
    install_binary

    # 保存版本信息
    atomic_write_version "$DATA_DIR/.version"

    # 询问是否修改端口（支持非交互式环境）
    CURRENT_PORT=$(grep "Environment=\"PORT=" "$SERVICE_FILE" 2>/dev/null | sed 's/.*PORT=\([0-9]*\).*/\1/')
    CURRENT_PORT=${CURRENT_PORT:-12889}
    echo ""
    if [ -t 0 ]; then
        # 交互式环境
        read -r -p "请输入端口号（默认 $CURRENT_PORT，直接回车使用默认值）: " PORT_INPUT
        if [ -z "$PORT_INPUT" ]; then
            PORT_INPUT=$CURRENT_PORT
        fi
    else
        # 非交互式环境，保持当前端口或使用环境变量
        PORT_INPUT=${PORT:-$CURRENT_PORT}
        echo_info "使用端口: $PORT_INPUT"
    fi

    # 在同目录暂存并校验 unit 后原子替换。
    update_systemd_service_settings "$PORT_INPUT"

    if ! start_service; then
        return 1
    fi
    commit_update_transaction
    echo ""
    echo "======================================"
    echo_info "更新完成！"
    echo "======================================"
    echo ""
    echo "📦 版本: $VERSION"
    echo "🌐 访问地址: http://$(hostname -I | awk '{print $1}'):$PORT_INPUT"
    echo ""
    echo "上一版本二进制备份: $INSTALL_DIR/${SERVICE_NAME}.bak"
    echo ""
}

# 卸载服务
uninstall_service() {
    echo_info "开始卸载 RelayDock..."
    echo ""

    # 检查服务是否已安装
    if [ ! -f "$INSTALL_DIR/$SERVICE_NAME" ]; then
        echo_error "未检测到已安装的服务"
        exit 1
    fi

    # 显示当前版本
    if [ -f "$DATA_DIR/.version" ]; then
        CURRENT_VERSION=$(cat "$DATA_DIR/.version")
        echo_info "当前版本: $CURRENT_VERSION"
        echo ""
    fi

    # 停止并禁用服务
    echo_info "停止并禁用服务..."
    systemctl stop ${SERVICE_NAME}.service || true
    systemctl disable ${SERVICE_NAME}.service || true
    echo_info "✓ 服务已停止"
    echo ""

    # 询问是否保留配置和数据
    KEEP_DATA=${ARCWAY_KEEP_DATA:-true}
    if [ -t 0 ]; then
        # 交互式环境
        echo "是否保留配置和数据？"
        echo "  1) 完全删除（删除所有文件和数据）"
        echo "  2) 保留数据（保留 $DATA_DIR 和 $CONFIG_DIR 目录）"
        read -r -p "请选择 (1/2，默认 2): " CHOICE

        if [ "$CHOICE" = "1" ]; then
            KEEP_DATA=false
        else
            KEEP_DATA=true
        fi
    else
        # 非交互式环境默认保留数据；仅显式 ARCWAY_KEEP_DATA=false 时删除。
        if [ "$KEEP_DATA" = "true" ]; then
            echo_info "保留数据模式"
        else
            echo_warn "ARCWAY_KEEP_DATA=false：将删除全部配置和数据"
            echo_info "完全删除模式"
        fi
    fi
    echo ""

    # 删除 systemd 服务文件
    echo_info "删除 systemd 服务..."
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo_info "✓ systemd 服务已删除"
    echo ""

    # 删除二进制文件
    echo_info "删除程序文件..."
    rm -f "$INSTALL_DIR/$SERVICE_NAME" "$INSTALL_DIR/${SERVICE_NAME}.bak"
    rm -f "$INSTALL_DIR"/.arcway.arcway-stage.*
    rm -rf "$GUARD_ASSET_DIR"
    # Legacy speedtester assets are intentionally left untouched. They are no
    # longer managed by the panel and may be owned by an operator.
    echo_info "✓ 程序文件已删除"
    echo ""

    # 根据选择删除或保留数据
    if [ "$KEEP_DATA" = "false" ]; then
        echo_info "删除数据和配置..."
        rm -rf "$DATA_DIR" "$CONFIG_DIR"
        echo_info "✓ 数据和配置已删除"
        echo ""
        echo "======================================"
        echo_info "卸载完成！所有文件已删除"
        echo "======================================"
    else
        echo_info "保留数据目录: $DATA_DIR"
        echo_info "保留配置目录: $CONFIG_DIR"
        echo ""
        echo "======================================"
        echo_info "卸载完成！配置和数据已保留"
        echo "======================================"
        echo ""
        echo "如需重新安装:"
        echo "  请查看 https://github.com/${GITHUB_REPO}#快速安装"
    fi
    echo ""
}

# 覆盖安装（全量重装，保留数据）
reinstall_service() {
    echo_info "开始覆盖安装 RelayDock..."
    echo ""

    # 下载和校验必须先完成，网络失败时保持当前服务运行。
    download_binary
    begin_update_transaction

    if ! stop_service_for_transaction; then
        return 1
    fi
    snapshot_database_after_stop

    # 备份当前二进制文件
    if [ -f "$INSTALL_DIR/$SERVICE_NAME" ]; then
        echo_info "备份当前版本..."
        atomic_copy_file "$INSTALL_DIR/$SERVICE_NAME" "$INSTALL_DIR/${SERVICE_NAME}.bak"
    fi

    # 全量覆盖：安装、重建目录和服务
    install_binary
    create_directories
    create_systemd_service

    # 保存版本信息
    atomic_write_version "$DATA_DIR/.version"

    if ! start_service; then
        return 1
    fi
    commit_update_transaction
    show_status
    echo_info "覆盖安装完成！数据已保留。"
    echo ""
    echo "上一版本二进制备份: $INSTALL_DIR/${SERVICE_NAME}.bak"
    echo ""
}

# 主函数
main() {
    check_root
    acquire_install_lock
    detect_existing_installation_paths "${1:-}"

    # 检查命令行参数
    if [ "$1" = "update" ]; then
        echo_info "进入更新模式..."
        check_architecture
        install_dependencies
        get_latest_version
        update_service
    elif [ "$1" = "reinstall" ]; then
        echo_info "进入覆盖安装模式..."
        check_architecture
        install_dependencies
        get_latest_version
        reinstall_service
    elif [ "$1" = "uninstall" ]; then
        echo_info "进入卸载模式..."
        uninstall_service
    else
        echo_info "开始安装 RelayDock..."
        echo ""

        check_architecture
        install_dependencies
        get_latest_version
        download_binary
        begin_update_transaction
        if ! stop_service_for_transaction; then
            return 1
        fi
        snapshot_database_after_stop
        install_binary
        create_directories
        create_systemd_service

        # 保存版本信息
        atomic_write_version "$DATA_DIR/.version"

        if ! start_service; then
            echo_error "安装过程中出现错误，请查看日志: journalctl -u $SERVICE_NAME -n 50"
            return 1
        fi
        commit_update_transaction
        show_status
    fi
}

cleanup() {
    for atomic_stage in "${ATOMIC_STAGE_PATHS[@]}"; do
        if [ -n "$atomic_stage" ]; then
            rm -f -- "$atomic_stage" || true
        fi
    done
    if [ "$PRESERVE_TMP_DIR" = true ]; then
        echo_warn "事务备份已保留: $UPDATE_BACKUP_DIR"
        return 0
    fi
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

finish() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ] && [ "$UPDATE_TRANSACTION_ACTIVE" = true ]; then
        if ! rollback_update_transaction; then
            PRESERVE_TMP_DIR=true
            echo_error "回滚需要人工处理，原始退出状态: $status"
        fi
    fi
    cleanup
    exit "$status"
}

trap finish EXIT
trap 'exit 130' HUP INT TERM
main "$@"
