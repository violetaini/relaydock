#!/bin/sh
set -e

# Get PUID and PGID from environment variables (default to 1000)
PUID=${PUID:-1000}
PGID=${PGID:-1000}

echo "Starting with UID: $PUID, GID: $PGID"

# Update user and group IDs if they differ from default
if [ "$PUID" != "1000" ] || [ "$PGID" != "1000" ]; then
    echo "Updating appuser UID to $PUID and GID to $PGID"

    # Remove existing user/group
    userdel appuser 2>/dev/null || true
    groupdel appuser 2>/dev/null || true

    # Create new user/group with specified IDs
    groupadd -g "$PGID" appuser
    useradd -u "$PUID" -g appuser -m appuser
fi

# Create and fix permissions for mounted data directories
mkdir -p /app/data /app/subscribes /app/rule_templates

echo "Fixing permissions for mounted volumes..."
chown -R appuser:appuser /app/data /app/subscribes /app/rule_templates

# Docker updates are image-based. Older releases could leave an in-app updated
# binary in the persistent data volume; never let it override a newly pulled image.
UPDATED_SERVER="/app/data/server"
ORIGINAL_SERVER="/app/server"

if [ -f "$UPDATED_SERVER" ] && [ -x "$UPDATED_SERVER" ]; then
    echo "Ignoring legacy updated binary at $UPDATED_SERVER; Docker uses the image binary."
fi
SERVER_BINARY="$ORIGINAL_SERVER"

# Set DOCKER environment variable for in-app update detection
export DOCKER=1

# 权限策略:默认以 root 跑 — mmwx 业务路径(/usr/local/nginx/cert 证书部署、
# /usr/local/etc/xray/ xray 配置、ACME HTTP-01 起 80/443、systemctl 控服务)
# 天生就是 root 视野;降级 appuser 反而要给每个硬编码路径打补丁,治标不治本。
# 容器内 root ≠ 宿主 root(namespace 隔离),安全风险可控。
#
# 安全意识强的用户:docker-compose 加 MMWX_DROP_PRIVS=1 切回 appuser 降权模式,
# 但这种情况下证书 / 嵌入式 xray / ACME 等可能因路径权限失败,得自己挂 volume + chown。
if [ "${MMWX_DROP_PRIVS:-0}" = "1" ]; then
    echo "MMWX_DROP_PRIVS=1, dropping privileges to appuser..."
    exec gosu appuser "$SERVER_BINARY"
else
    echo "Starting application as root (set MMWX_DROP_PRIVS=1 to run as appuser)..."
    exec "$SERVER_BINARY"
fi
