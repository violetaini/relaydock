<div align="center">
  <img src="docs/assets/avatar.webp" alt="RelayDock" width="120" />

# **RelayDock**

[![Release](https://img.shields.io/github/v/release/violetaini/relaydock?style=for-the-badge&logo=github)](https://github.com/violetaini/relaydock/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/violetaini/relaydock/build.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/violetaini/relaydock/actions/workflows/build.yml)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go&logoColor=white)](go.mod)
[![License](https://img.shields.io/badge/License-MIT-2ea44f?style=for-the-badge)](LICENSE)

多服务器 Xray 节点、用户授权与订阅管理面板

[功能](#核心功能) · [快速安装](#快速安装) · [更新](#更新已安装的-relaydock) · [Docker](#docker) · [源码构建](#源码构建) · [前端项目](https://github.com/violetaini/relaydock-frontend)
</div>

RelayDock 面向合租节点和小型代理服务运营场景。管理员集中接入服务器、授权用户可使用的服务器与有效期；用户在授权范围内自助创建节点，面板统一处理订阅、流量、限速和生命周期。

> [!IMPORTANT]
> RelayDock 会管理远端 Xray、Nginx、证书和防火墙配置。请先备份现有服务，仅在自己拥有或获准管理的服务器上使用。

## 核心功能

- 多服务器集中管理，以及入站、出站、路由、Xray 配置和服务控制
- 按用户授权可用服务器、有效期和具体协议组合；用户在授权范围内自助创建节点
- VLESS、VMess、Trojan、Shadowsocks 2022、Hysteria2、SOCKS5、HTTP、WireGuard 等常见协议
- TCP、WebSocket、gRPC、TLS、REALITY 等常用组合，并兼容 AnyTLS、Snell 等订阅节点
- 直接创建 WireGuard 入站；客户端密钥加密保存为普通节点，可用于节点管理、套餐、订阅、分享和二维码
- 1 至 8 跳 TCP/UDP 隧道和 Tunnel（任意门），各跳可使用相同端口
- 主控和受管服务器均可安装、控制并运行 Ookla Speedtest CLI
- 用户、套餐、订阅、模板、规则、可编辑 DNS 凭据、证书和 DDNS 管理
- 上传、下载或双向流量计费，以及流量、速率和设备限制
- 节点 Agent、到期守卫、端口防火墙同步、日志与通知
- 内嵌 RelayDock Console，单个后端即可提供完整管理界面

## 运行环境

一键安装脚本当前适用于以下环境：

| 项目 | 支持范围 |
| --- | --- |
| 操作系统 | Debian / Ubuntu，使用 `apt` 与 `systemd` |
| CPU 架构 | AMD64 (`x86_64`) / ARM64 (`aarch64`) |
| 权限 | `root`，或可使用 `sudo` 的用户 |
| 网络 | 可访问 GitHub API、Release 与 Raw 内容 |

其他 Linux 发行版可以从源码运行，但不在当前安装脚本的支持范围内。

## 快速安装

安装器会从 GitHub Release 下载控制端、节点到期守卫和两种 Linux 架构的受管 Agent 安装包，并使用 Release 中发布的 SHA-256 清单完成校验后再替换文件。

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh | sudo bash
```

安装完成后访问：

```text
http://SERVER_IP:12889
```

首次访问会进入初始化向导，由你创建第一个管理员账号；项目不提供默认用户名或默认密码。安装路径保持兼容：二进制为 `/usr/local/bin/arcway`，数据目录为 `/etc/arcway`，systemd 服务名为 `arcway`。

自定义面板端口：

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh | sudo env PORT=18080 bash
```

### 重装与卸载

以下命令采用安全的非交互默认值：重装保留当前端口，卸载保留 `/etc/arcway` 数据。覆盖重装前仍应先备份：

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh | sudo bash -s -- reinstall
```

卸载程序但保留数据：

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh | sudo bash -s -- uninstall
```

彻底卸载并删除 `/etc/arcway` 前请先备份：

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh | sudo env ARCWAY_KEEP_DATA=false bash -s -- uninstall
```

常用运维命令：

```bash
systemctl status arcway
journalctl -u arcway -f
systemctl restart arcway
```

## 更新已安装的 RelayDock

更新前请先在面板下载一份加密备份，并阅读目标版本的 Release Notes。不要用仅包含旧程序的 `.bak` 文件代替数据备份。

### 面板一键更新（裸机 / systemd）

管理员进入 **系统设置 → 系统更新**，依次点击 **检查更新** 和 **立即更新**。面板会下载最新 GitHub Release，校验控制端、守卫程序及 Agent 安装资产的 SHA-256 和可执行文件架构，全部验证通过后才备份、原子替换并重启；更新期间页面会短暂断开，服务恢复后重新加载即可。

从不含“系统更新”入口的旧版本首次升级到 `v0.5.1` 或更高版本时，需要先执行下方的裸机命令行更新。升级完成后，使用内嵌前端的实例可直接在面板更新；配置了外置前端的实例仍需在每次更新后单独发布前端。

网页一键更新仅用于裸机或 systemd 安装。Docker 容器必须按下方 Compose 方式更新镜像，面板不会在容器内应用更新。

### 裸机命令行更新

通过一键安装脚本部署的实例也可以执行：

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/relaydock/main/install.sh | sudo bash -s -- update
```

安装器会保留当前端口和 `/etc/arcway` 数据。它会先下载并校验新版本，再停止服务并建立事务快照；更新过程失败或新服务无法启动时，会尝试恢复原二进制、守卫与 Agent 安装资产、systemd 配置和数据库。

### Docker Compose 更新

进入最初保存 `docker-compose.yml` 的目录后执行：

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 arcway
```

Compose 会重新创建容器，但 `./data` 挂载目录不会被删除。需要回退镜像时，将 `docker-compose.yml` 中的 `latest` 改为上一个可用版本标签，再执行 `docker compose pull && docker compose up -d`。

### 外置前端与回滚

如果配置了 `ARCWAY_WEB_ROOT`，上述面板或命令行更新会更新控制端、二进制内嵌的备用页面、守卫程序和 Agent 安装资产，但不会替换外置前端。外置前端仍需使用[前端快速发布](#前端快速发布)脚本独立更新或回滚。

面板更新会为控制端、守卫程序和 Agent 安装资产分别留下 `.bak`。它能在文件替换失败或新程序无法执行时立即恢复，但新程序已经执行后才因配置、端口或数据库问题退出，仍需管理员按 systemd 日志手工回退。默认控制端备份路径为 `/usr/local/bin/arcway.bak`，自定义安装路径以 systemd 的 `ExecStart` 为准。版本升级可能包含数据库迁移，因此在更新成功后又决定降级时，应同时恢复更新前的数据备份，不能只替换旧二进制。操作前先停止 `arcway` 服务，并保留当前文件以便排查。

## Docker

需要 Docker Engine 和 Docker Compose v2。仓库中的 Compose 使用主机网络，以便面板管理动态节点端口、Nginx、ACME 和 Agent 回连。

```bash
git clone https://github.com/violetaini/relaydock.git
cd relaydock
docker compose pull
docker compose up -d
```

查看状态与日志：

```bash
docker compose ps
docker compose logs -f arcway
```

默认镜像为 `ghcr.io/violetaini/relaydock:latest`，支持 AMD64 和 ARM64。Compose 将数据库目录映射到当前目录的 `data/`；升级或删除容器前，仍建议先从面板下载加密备份。

## 端口与数据

| 用途 | 默认值 | 说明 |
| --- | --- | --- |
| 面板 HTTP/API | TCP `12889` | 可在安装时修改，生产环境建议经 HTTPS 反向代理访问 |
| HTTPS / ACME | TCP `80`、`443` | 仅在启用证书、HTTP-01 或内置 Nginx 时需要 |
| 节点与 Agent | 按配置分配 | 在面板创建服务器和节点时确定，按实际协议开放 TCP/UDP |
| 用户转发端口 | 模板指定的 TCP/UDP 范围 | 范围只限制可选端口，不会预占；各跳可以使用同一个端口 |

裸机安装的数据库、订阅和运行数据都位于 `/etc/arcway/`。推荐使用面板的加密备份功能；进行系统迁移或人工备份时，应先停止服务再复制整个目录：

```bash
sudo systemctl stop arcway
sudo cp -a /etc/arcway /path/to/backup/arcway
sudo systemctl start arcway
```

备份中含管理员资料、节点凭据和密钥，请加密保存并限制访问权限。

## 部署建议

- 为面板配置 HTTPS，并使用独立的高强度管理员密码和两步验证。
- `master_url` 应填写节点能够直连的 HTTPS 源站地址。使用 CDN 时，建议为节点控制单独准备 DNS-only 域名。
- 面板位于 NAT 后或公共域名经过 CDN 时，可通过 `ARCWAY_PANEL_IPS` 指定远端服务器实际看到的面板出口地址。
- 远端节点安装命令依赖 `curl` 和可用的 `nftables`；接管外置 Xray 或 Nginx 前，请先确认原服务和配置有效。
- 转发管理依赖节点到期守卫和 `nftables`。控制面离线时，未续租的转发会在五分钟内自动撤下。
- 仅开放实际需要的面板、Agent 和节点端口，并定期检查日志、更新版本和下载备份。

## 源码构建

后端需要 Go 1.26。仓库已提交审核过的前端构建快照到 `internal/web/dist/`，因此单独检出后端即可测试和构建。

```bash
git clone https://github.com/violetaini/relaydock.git
cd relaydock
go mod verify
go test ./...
go build -trimpath -o arcway ./cmd/server
PORT=12889 DATABASE_PATH=./data/arcway.db ./arcway
```

也可以执行 `./build.sh` 构建发布用二进制。

## 前后端关系

- [relaydock](https://github.com/violetaini/relaydock) 是主仓库，提供 API、远端管理能力、安装与发布，并内嵌 Web 控制台。
- [relaydock-frontend](https://github.com/violetaini/relaydock-frontend) 是独立的 React / TypeScript 前端源码。
- [relaydock-agent](https://github.com/violetaini/relaydock-agent) 是受管服务器 Agent 源码及带签名的自升级发布源。

发布新前端时，先在前端仓库执行 `npm ci --include=dev && npm run build`，再用生成的 `dist/` 整体替换本仓库的 `internal/web/dist/`。不要手工编辑已构建的哈希资源。

### 前端快速发布

生产主控可通过 `ARCWAY_WEB_ROOT` 从磁盘加载完整前端版本；目录不可用或校验失败时会自动回退二进制内嵌页面。推荐使用不可变版本目录和一个稳定软链：

```text
/opt/arcway/web/
├── releases/<release-id>/
├── previous -> releases/<previous-release-id>
└── current  -> releases/<release-id>
```

在 systemd 的环境文件中配置一次并重启主控：

```bash
ARCWAY_WEB_ROOT=/opt/arcway/web/current
systemctl restart arcway
```

此后界面更新不再需要重新编译 Go 后端或重启服务。在后端仓库运行：

```bash
./scripts/deploy-frontend.sh --host CONTROL_PLANE --port 22
```

脚本会执行前端生产构建、上传并校验完整版本，然后原子切换 `current`。旧版本会保留；回滚同样不重启服务：

```bash
./scripts/deploy-frontend.sh rollback --host CONTROL_PLANE --port 22
```

可通过 `ARCWAY_DEPLOY_HOST`、`ARCWAY_DEPLOY_PORT`、`ARCWAY_DEPLOY_USER`、`ARCWAY_FRONTEND_DIR` 和 `ARCWAY_WEB_DEPLOY_ROOT` 设置发布脚本的默认参数。主控进程的 `ARCWAY_WEB_ROOT` 则指向版本根目录下的 `current` 软链。

## 许可与致谢

RelayDock 基于 [iluobei/miaomiaowuX](https://github.com/iluobei/miaomiaowuX) 的公开代码继续开发，感谢原作者的开源工作。原项目的 MIT 许可与版权声明保留在 [LICENSE](LICENSE) 中。
