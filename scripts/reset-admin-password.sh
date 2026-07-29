#!/usr/bin/env bash
# reset-admin-password.sh — reset an Arcway administrator password locally.
#
# 设计意图:admin 忘密码 / TOTP 丢失 / 误操作锁死自己 时的本地救场工具。
# 不通过任何远程服务(License、API 等)修改数据库,杜绝"中心服务被攻破 → 全用户主控沦陷"的风险。
#
# 兼容:
#   - Arcway systemd deployment (default /etc/arcway/arcway.db)
#   - Docker / docker-compose(从容器挂载点找到宿主机 db 路径)
#   - 二进制直跑(从进程 cwd / 命令行找到 db)
#
# 用法:
#   sudo bash reset-admin-password.sh                       # 交互式
#   sudo bash reset-admin-password.sh --db /path/to/arcway.db # 显式指定 db
#   sudo bash reset-admin-password.sh --no-restart          # 不重启服务
#
# 退出码:0 成功;1 找不到 db;2 找不到用户;3 hash 失败;4 写库失败;5 用户取消。

set -euo pipefail

#─── 输出样式 ──────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[FAIL]${NC} $*" >&2; }

#─── 参数解析 ──────────────────────────────────────────────
DB_PATH=""
RESTART=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --db)        DB_PATH="$2"; shift 2 ;;
        --no-restart) RESTART=0; shift ;;
        -h|--help)
            sed -n '2,18p' "$0"; exit 0 ;;
        *)
            err "未知参数: $1"; exit 2 ;;
    esac
done

#─── 1. 探测系统 + 包管理器 ────────────────────────────────
OS=""; PKG_INSTALL=""
detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS="$ID"
    elif command -v lsb_release &>/dev/null; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    else
        OS="unknown"
    fi
    case "$OS" in
        debian|ubuntu|linuxmint|raspbian) PKG_INSTALL="apt-get install -y" ;;
        rhel|centos|rocky|almalinux|fedora) PKG_INSTALL="yum install -y" ;;
        alpine) PKG_INSTALL="apk add --no-cache" ;;
        arch|manjaro) PKG_INSTALL="pacman -S --noconfirm" ;;
        *) PKG_INSTALL="" ;;
    esac
}
detect_os
info "系统: $OS"

#─── 2. 找到 Arcway 数据库 ─────────────────────────────────
# 探测顺序:
#   1) --db 参数显式指定
#   2) /etc/arcway/data/arcway.db(一键安装默认)
#   3) Docker 容器挂载点:看 Arcway 进程的 mount,找宿主机映射
#   4) 进程 cwd:从运行中的 Arcway 进程拿当前工作目录,拼 data/arcway.db
#   5) systemd unit:从 arcway.service 读 WorkingDirectory,拼 data/arcway.db
#   7) find 兜底全盘扫描
find_db_via_process() {
    # 跑在宿主机:查找 Arcway 进程。
    local pids
    pids=$(pgrep -f '(^|/)arcway($|[[:space:]])' 2>/dev/null | head -3 || true)
    for pid in $pids; do
        local cwd
        cwd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)
        if [[ -n "$cwd" ]]; then
            for cand in "$cwd/data/arcway.db" "$cwd/arcway.db"; do
                if [[ -f "$cand" ]]; then echo "$cand"; return 0; fi
            done
        fi
    done
    return 1
}

find_db_via_docker() {
    if ! command -v docker &>/dev/null; then return 1; fi
    # 找运行中的 Arcway 容器。
    local cids
    cids=$(docker ps --filter "name=arcway" --format '{{.ID}}' 2>/dev/null | head -3 || true)
    if [[ -z "$cids" ]]; then
        cids=$(docker ps --format '{{.ID}} {{.Image}}' 2>/dev/null | grep -Ei 'arcway' | awk '{print $1}' | head -3 || true)
    fi
    for cid in $cids; do
        # docker inspect 看 mounts,找映射到 /etc/arcway 或 /app 之类的卷
        local mounts
        mounts=$(docker inspect "$cid" --format '{{range .Mounts}}{{.Source}}::{{.Destination}}{{"\n"}}{{end}}' 2>/dev/null || true)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local src="${line%%::*}"
            local dst="${line##*::}"
            # dst 是容器内路径,常见 /etc/arcway 或 /app/data
            for cand in "$src/data/arcway.db" "$src/arcway.db"; do
                if [[ -f "$cand" ]]; then echo "$cand"; return 0; fi
            done
            # 如果 dst 是某个特定路径(/app, /etc/arcway),按容器结构推
            case "$dst" in
                /etc/arcway|/etc/arcway/data|/data|/app|/app/data)
                    for cand in "$src/arcway.db" "$src/data/arcway.db"; do
                        if [[ -f "$cand" ]]; then echo "$cand"; return 0; fi
                    done
                    ;;
            esac
        done <<<"$mounts"
    done
    return 1
}

find_db_via_systemd() {
    local workdir
    workdir=$(systemctl show arcway 2>/dev/null | grep -E '^WorkingDirectory=' | head -1 | cut -d= -f2 || true)
    if [[ -n "$workdir" && "$workdir" != "/" ]]; then
        for cand in "$workdir/data/arcway.db" "$workdir/arcway.db"; do
            if [[ -f "$cand" ]]; then echo "$cand"; return 0; fi
        done
    fi
    return 1
}

find_db_via_scan() {
    # 全盘扫描兜底 — 只搜常见路径以免无限慢
    local found
    found=$(find /etc /opt /root /var /srv /home -maxdepth 5 -name 'arcway.db' 2>/dev/null | head -3 || true)
    if [[ -z "$found" ]]; then return 1; fi
    if [[ $(echo "$found" | wc -l) -eq 1 ]]; then
        echo "$found"; return 0
    fi
    # 多个匹配 → 让用户选
    warn "找到多个候选 db 文件:"
    local i=1; local arr=()
    while IFS= read -r line; do
        arr+=("$line"); echo "  [$i] $line"; ((i++))
    done <<<"$found"
    echo -n "选择 [1-$((i-1))]: "; read -r idx
    if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#arr[@]} )); then
        echo "${arr[$((idx-1))]}"; return 0
    fi
    return 1
}

if [[ -z "$DB_PATH" ]]; then
    info "探测 Arcway 数据库路径..."
    for cand in /etc/arcway/arcway.db /etc/arcway/data/arcway.db; do
        if [[ -f "$cand" ]]; then DB_PATH="$cand"; break; fi
    done
    if [[ -z "$DB_PATH" ]]; then DB_PATH=$(find_db_via_docker 2>/dev/null || true); fi
    if [[ -z "$DB_PATH" ]]; then DB_PATH=$(find_db_via_process 2>/dev/null || true); fi
    if [[ -z "$DB_PATH" ]]; then DB_PATH=$(find_db_via_systemd 2>/dev/null || true); fi
    if [[ -z "$DB_PATH" ]]; then DB_PATH=$(find_db_via_scan 2>/dev/null || true); fi
fi

if [[ -z "$DB_PATH" || ! -f "$DB_PATH" ]]; then
    err "找不到 Arcway 数据库。可手动指定:bash $0 --db /path/to/arcway.db"
    exit 1
fi
ok "数据库: $DB_PATH"

#─── 3. 准备工具:sqlite3 + bcrypt 生成器 ──────────────────
ensure_pkg() {
    local cmd="$1"; local pkg="$2"
    if command -v "$cmd" &>/dev/null; then return 0; fi
    if [[ -z "$PKG_INSTALL" ]]; then
        err "缺少 $cmd 且不识别本系统包管理器,请手动安装"; return 1
    fi
    info "$cmd 未安装,正在安装 $pkg..."
    if [[ "$PKG_INSTALL" == apt-get* ]]; then apt-get update -y >/dev/null 2>&1 || true; fi
    if ! $PKG_INSTALL "$pkg" >/dev/null 2>&1; then
        err "$pkg 安装失败,请手动 $PKG_INSTALL $pkg"; return 1
    fi
    if ! command -v "$cmd" &>/dev/null; then
        err "$pkg 已装但 $cmd 仍找不到"; return 1
    fi
    ok "$pkg 安装完成"
}

if ! ensure_pkg sqlite3 sqlite3; then exit 1; fi

# bcrypt 生成器:优先 htpasswd(轻量),fallback 到 python3 + bcrypt
HASHER=""
detect_hasher() {
    if command -v htpasswd &>/dev/null; then HASHER="htpasswd"; return 0; fi
    if command -v python3 &>/dev/null && python3 -c 'import bcrypt' 2>/dev/null; then
        HASHER="python"; return 0
    fi
    return 1
}
if ! detect_hasher; then
    # 优先装 htpasswd(更小,跨系统支持好)
    case "$OS" in
        debian|ubuntu|linuxmint|raspbian) ensure_pkg htpasswd apache2-utils || true ;;
        rhel|centos|rocky|almalinux|fedora) ensure_pkg htpasswd httpd-tools || true ;;
        alpine) ensure_pkg htpasswd apache2-utils || true ;;
        arch|manjaro) ensure_pkg htpasswd apache ;;
        *) ;;
    esac
    if ! detect_hasher; then
        # 退而求其次:python bcrypt
        if command -v python3 &>/dev/null; then
            info "尝试用 pip 安装 python bcrypt..."
            python3 -m pip install --quiet bcrypt 2>/dev/null || \
                (ensure_pkg pip3 python3-pip && python3 -m pip install --quiet bcrypt) || true
            detect_hasher || true
        fi
    fi
fi
if [[ -z "$HASHER" ]]; then
    err "无法准备 bcrypt 生成工具。请手动安装 apache2-utils(htpasswd)或 python3-bcrypt"
    exit 3
fi
ok "bcrypt 工具: $HASHER"

#─── 4. 列出 admin 用户 ────────────────────────────────────
mapfile -t ADMINS < <(sqlite3 "$DB_PATH" \
    "SELECT username FROM users WHERE role='admin' AND is_active=1 ORDER BY username;" 2>/dev/null || true)
if [[ ${#ADMINS[@]} -eq 0 ]]; then
    err "未找到任何 active admin 用户。是不是动错了 db?"
    exit 2
fi

TARGET=""
if [[ ${#ADMINS[@]} -eq 1 ]]; then
    TARGET="${ADMINS[0]}"
    info "唯一管理员: ${BOLD}$TARGET${NC}"
    echo -n "确认重置此用户的密码 [y/N]: "; read -r confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { warn "已取消"; exit 5; }
else
    echo
    echo -e "${BOLD}发现 ${#ADMINS[@]} 个管理员账号:${NC}"
    for i in "${!ADMINS[@]}"; do
        printf "  ${BOLD}[%d]${NC} %s\n" $((i+1)) "${ADMINS[$i]}"
    done
    echo
    while [[ -z "$TARGET" ]]; do
        echo -n "选择要重置的管理员编号 [1-${#ADMINS[@]}]: "; read -r idx
        if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#ADMINS[@]} )); then
            TARGET="${ADMINS[$((idx-1))]}"
        else
            warn "输入无效"
        fi
    done
    info "已选择: ${BOLD}$TARGET${NC}"
fi

#─── 5. 输入新密码(隐藏,两次确认) ──────────────────────
# 关键:所有用户提示输出到 stderr (>&2),只把最终密码 echo 到 stdout — 否则
# NEW_PASS=$(prompt_password) 会把提示文字一起捕获到密码里。
prompt_password() {
    local pw1 pw2
    while true; do
        printf "请输入新密码(至少 8 位,不显示): " >&2; read -rs pw1; echo >&2
        if (( ${#pw1} < 8 )); then warn "密码至少 8 位"; continue; fi
        printf "再次输入新密码: " >&2; read -rs pw2; echo >&2
        if [[ "$pw1" != "$pw2" ]]; then warn "两次输入不一致,重来"; continue; fi
        printf '%s' "$pw1"; return 0
    done
}
NEW_PASS=$(prompt_password)

#─── 6. 生成 bcrypt hash ──────────────────────────────────
hash_password() {
    local plain="$1"
    case "$HASHER" in
        htpasswd)
            # htpasswd -bnBC 10 '' 'pw' → 输出 ":$2y$10$..." ,改成 $2a$ 兼容 Go bcrypt。
            htpasswd -bnBC 10 '' "$plain" 2>/dev/null | tr -d ':\n' | sed 's/^\$2y\$/$2a$/'
            ;;
        python)
            python3 -c "
import bcrypt,sys
p=sys.argv[1].encode()
print(bcrypt.hashpw(p, bcrypt.gensalt(rounds=10)).decode())
" "$plain"
            ;;
    esac
}
HASH=$(hash_password "$NEW_PASS")
if [[ -z "$HASH" || "${HASH:0:4}" != "\$2a\$" && "${HASH:0:4}" != "\$2b\$" ]]; then
    err "生成 bcrypt hash 失败(输出: $HASH)"
    exit 3
fi
ok "已生成 bcrypt hash"

#─── 7. 停服务 → 备份 → 写库 → 启动 ───────────────────────
# 简洁逻辑:既然改完反正要重启,直接先停服务再改 db,完成后重启。
# 避免 sqlite "database is locked" 这种竞态。
SERVICE_TYPE=""  # systemd / docker-<cid> / none

detect_running_service() {
    if systemctl is-active --quiet arcway 2>/dev/null; then
        SERVICE_TYPE="systemd"
        return
    fi
    if command -v docker &>/dev/null; then
        local cid
        cid=$(docker ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null | grep -Ei 'arcway|relaydock' | awk '{print $1}' | head -1 || true)
        if [[ -n "$cid" ]]; then
            SERVICE_TYPE="docker-$cid"
            return
        fi
    fi
    SERVICE_TYPE="none"
}

stop_service() {
    case "$SERVICE_TYPE" in
        systemd)
            info "停止 systemd arcway 服务..."
            systemctl stop arcway ;;
        docker-*)
            local cid="${SERVICE_TYPE#docker-}"
            info "停止 docker 容器 $cid..."
            docker stop "$cid" >/dev/null ;;
        none)
            info "未发现运行中的 Arcway 服务,跳过停止" ;;
    esac
}

start_service() {
    case "$SERVICE_TYPE" in
        systemd)
            info "启动 systemd arcway 服务..."
            systemctl start arcway && ok "Arcway 服务已启动" || warn "systemctl start 失败,请手动启动" ;;
        docker-*)
            local cid="${SERVICE_TYPE#docker-}"
            info "启动 docker 容器 $cid..."
            docker start "$cid" >/dev/null && ok "RelayDock 容器已启动" || warn "docker start 失败,请手动启动" ;;
        none)
            info "Arcway 之前未运行,无需启动" ;;
    esac
}

detect_running_service

# 探测后停服务(这会释放 WAL 锁,sqlite3 命令行可独占写入)
stop_service

# 给 sqlite 一点时间释放 WAL/SHM 文件锁
sleep 1

BACKUP="${DB_PATH}.bak-$(date +%Y%m%d%H%M%S)"
cp -a "$DB_PATH" "$BACKUP" || { err "备份失败"; start_service; exit 4; }
ok "已备份: $BACKUP"

# 写入 — 此时 Arcway 已停,sqlite3 独占写入,不会有 locked 错误
if ! sqlite3 "$DB_PATH" <<SQL
UPDATE users
SET password_hash = '$HASH',
    updated_at    = CURRENT_TIMESTAMP
WHERE username = '$TARGET' AND role = 'admin';
UPDATE users
SET totp_enabled = 0, totp_secret = ''
WHERE username = '$TARGET' AND role = 'admin';
SQL
then
    err "UPDATE 失败,回滚备份并重启服务"
    cp -af "$BACKUP" "$DB_PATH"
    start_service
    exit 4
fi
ok "数据库已更新"

#─── 8. 启动 Arcway 让新密码生效 ────────────────────────────
if (( RESTART == 1 )); then
    start_service
else
    info "已跳过启动(--no-restart);记得手动启动 Arcway 才能用新密码登录"
fi

#─── 9. 完成 ────────────────────────────────────────────
echo
echo -e "${GREEN}${BOLD}✔ 密码已更新${NC}"
echo "  用户名: $TARGET"
echo "  新密码: ${BOLD}(刚才你输入的那个)${NC}"
echo "  备份  : $BACKUP"
echo
echo "下一步:打开 RelayDock 主控登录页,用新密码登录。"
echo "建议:登录后在「系统设置 → 修改密码」再手动设一次,并新建第二个 admin 账号作为备份。"
