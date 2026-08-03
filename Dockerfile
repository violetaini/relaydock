# Build stage for backend
FROM golang:1.26-bookworm AS backend-builder

# Declare build arguments for multi-platform support
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Install build dependencies (gcc needed for CGO)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# The backend embeds a reviewed frontend snapshot at compile time.
RUN test -s internal/web/dist/index.html \
    && test -n "$(find internal/web/dist/assets -type f -print -quit)"

# Build backend with optimizations (CGO enabled for SQLite WAL support)
# Use TARGETOS and TARGETARCH for multi-platform builds
RUN CGO_ENABLED=1 GOOS=${TARGETOS:-$(go env GOOS)} GOARCH=${TARGETARCH:-$(go env GOARCH)} go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /app/server \
    ./cmd/server

RUN mkdir -p /app/guard-assets \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -trimpath -ldflags="-s -w" \
        -o /app/guard-assets/arcway-expiry-guard-linux-amd64 \
        ./cmd/arcway-expiry-guard \
    && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
        -trimpath -ldflags="-s -w" \
        -o /app/guard-assets/arcway-expiry-guard-linux-arm64 \
        ./cmd/arcway-expiry-guard

# Final stage - 用 nginx 官方 Docker base(mainline-bookworm),跟 install-nginx.sh 同款"最新 nginx mainline"语义。
# 该镜像默认编译 --with-http_v3_module 且静态链 QuicTLS,完整支持 listen ... quic;
# 之前 debian:bookworm-slim apt 装的 nginx 1.22.1 不带 HTTP/3 模块,EnableHTTPS 写入含 quic 指令的
# nginx.conf 后 nginx -t 报 "invalid parameter quic" 启动失败。
# base 仍是 debian bookworm 系列,其它 apt 包(gosu/wget/ca-certificates)正常装。
FROM nginx:mainline-bookworm

WORKDIR /app

# Install ca-certificates for HTTPS requests, gosu for privilege dropping。
#
# nginx 由 base image (nginx:mainline-bookworm) 预装:二进制 /usr/sbin/nginx 跟 apt 装的同位置,
# 配置 /etc/nginx/* 路径不变,现有 /usr/local/nginx/* symlink 链路零改动。
# 历史上 EnableHTTPS 会调 install-nginx.sh 编译 + systemctl 装 nginx,容器里没 systemd,装不上。
# 业务代码硬编码 /usr/local/nginx/* 路径全部通过 symlink 兜底;容器内 reload 走 `nginx -s reload`/`nginx`,
# 由 ensureNginxRunning 处理。
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    gosu \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/nginx/sbin /etc/nginx/cert /etc/nginx/servers /etc/nginx/stream_servers /etc/nginx/html \
    && ln -sfn /usr/sbin/nginx           /usr/local/nginx/sbin/nginx \
    && ln -sfn /etc/nginx/nginx.conf     /usr/local/nginx/nginx.conf \
    && ln -sfn /etc/nginx/cert           /usr/local/nginx/cert \
    && ln -sfn /etc/nginx/servers        /usr/local/nginx/servers \
    && ln -sfn /etc/nginx/stream_servers /usr/local/nginx/stream_servers \
    && ln -sfn /etc/nginx/html           /usr/local/nginx/html

# Create non-root user
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -m appuser

# Copy binary from builder
COPY --from=backend-builder /app/server /app/server
COPY --from=backend-builder /app/guard-assets /app/guard-assets

# Copy rule templates directory
COPY --from=backend-builder /app/rule_templates /app/rule_templates

# Copy entrypoint script
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set proper ownership for app files
RUN chown -R appuser:appuser /app/server /app/guard-assets /app/rule_templates

# Volume for persistent data
VOLUME ["/app/data", "/app/subscribes"]

# Bind 0.0.0.0 by default — Docker port mapping requires the server to listen on
# all interfaces inside the container. The application-layer host enforcement
# (internal/handler/host_enforcement.go) still blocks direct IP+port access when
# HTTPS is configured, so security parity with the bare-metal "bind loopback" mode
# is preserved.
ENV BIND_HOST=0.0.0.0
ENV ARCWAY_GUARD_ASSET_DIR=/app/guard-assets

# Expose port
EXPOSE 12889

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:12889/ || exit 1

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Run the application
CMD ["/app/server"]
