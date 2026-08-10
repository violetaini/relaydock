# RelayDock 项目状态与发布进展

更新时间：2026-08-10

## 当前结论

RelayDock 是一个由 Go 控制面、React 管理控制台和受管服务器 Agent
组成的多服务器 Xray 运维与订阅交付系统。当前正式版本为
[`v0.6.16`](https://github.com/violetaini/relaydock/releases/tag/v0.6.16)：

- 后端发布提交：`a2a82f65db96a992db4908a20507bc376992cbdd`
- 前端源码提交：`8b7eaa63fff50fbd58d2c72b9d1acb7dbc86b129`
- Agent 发布提交：`7953f242169d320966c73dcf20fa6ee62bf7bb8f`
- 产品发布协议：`1`
- 正式生产地址：[arcway.chitanda.org](https://arcway.chitanda.org)

该版本建立了完整产品发布事务。后端、网页、到期守卫和测速组件由同一个
GitHub Release 清单约束，不再把“更新后端”和“更新前端”视为两件互不相关的
操作。受管 Agent 由节点安装脚本从对应版本 GitHub Release 直接下载并校验，
不再通过面板托管的本地资产端点分发。

## 代码库与运行架构

| 范围 | 仓库或组件 | 职责 |
| --- | --- | --- |
| 控制面 | [`violetaini/relaydock`](https://github.com/violetaini/relaydock) | Go API、数据库、远端服务器管理、安装器、发布工作流、内嵌前端与产品更新事务 |
| 管理控制台 | [`violetaini/relaydock-frontend`](https://github.com/violetaini/relaydock-frontend) | React / TypeScript 控制台、公开探针页、响应式交互与设置页面 |
| 受管节点 | [`violetaini/relaydock-agent`](https://github.com/violetaini/relaydock-agent) | 与控制面建立加密连接、汇报节点状态、流量和服务数据，并执行经授权的管理操作；节点安装器从控制面同版本 GitHub Release 直接下载二进制 |
| 生产运行时 | `arcway.service` | 运行控制面；可从内嵌前端或受管外置前端目录提供网页 |

前端源码独立维护，但正式发布时构建产物会同步进入后端的
`internal/web/dist/`。产品包中的网页归档还带有
`relaydock-release.json`，用于证明正在提供的网页版本、后端提交和 API
协议。

## 已实现能力

### 控制面与节点运维

- 多服务器、入站、出站、路由、Xray、Nginx、证书、防火墙、DDNS 和服务管理。
- 用户、套餐、订阅、流量、速率、设备和授权范围管理。
- VLESS、VMess、Trojan、Shadowsocks 2022、Hysteria2、WireGuard、SOCKS5、HTTP
  等协议及 TCP、WebSocket、gRPC、TLS、REALITY 等常用传输组合。
- TCP/UDP 多跳转发、测速、流量明细、备份恢复和审计能力。
- Agent、到期守卫、端口防火墙同步、远端日志与状态回传。
- 用户级 Proxy Provider 管理、凭证轮换与撤销、租户隔离、节点过滤和 Mihomo
  原生 Provider 交付。
- 可选的 Telegram Bot 与 Mini App，支持邀请注册或绑定、账户查询、通知和受控
  管理操作。
- Xray 路由规则可原子同步运行态与配置文件，并具备并发冲突检测、失败回滚和旧
  Agent 兼容回退。

当 Agent 使用外部 Xray 模式时，Agent 不安装或升级 Xray；安装、启动和更新
由管理员从面板控制。Mihomo 与 Xray 核心更新同样保持用户可控，规则和 geodata
默认自动更新。

### 品牌与公开探针体验

- 管理员可在“系统设置”配置项目名称、Logo 和浏览器图标；留空时使用
  RelayDock 默认品牌。
- 公开探针默认启用，品牌配置在登录前同样生效。
- 公开探针页通过 `/api/public/probe-ws` 接收实时帧，并以约 1 秒的 REST
  请求作为断线回退。
- 探针卡片支持更宽的桌面布局、移动端单列展示、国旗透明背景和基线对齐，
  节点状态、CPU、内存、磁盘、流量与上下行速率均可实时展示。
- 控制台中的服务器管理也使用 1 秒刷新间隔，并优先使用实时通道；连接中断时
  保留轮询回退。
- 探针页与控制台间使用当前页面内导航，避免错误打开新标签页。

## 近期进展

| 时间 | 交付内容 | 状态 |
| --- | --- | --- |
| 2026-07 | 完成本地能力迁移，移除外部授权依赖；前后端独立仓库与内嵌构建链稳定运行。 | 已完成 |
| 2026-07 至 2026-08 | 完成公开探针的实时数据通道、品牌配置、宽屏与移动端体验修正，以及服务器管理的秒级刷新回退。 | 已完成 |
| 2026-08-02 | 发布并部署 `v0.6.6`，建立完整产品 Release 清单、原子切换、健康门槛、恢复状态和生产验收记录。 | 已完成 |
| 2026-08-10 | 发布并部署 `v0.6.16`，交付 Proxy Provider、Telegram 集成、Xray 路由原子同步，以及会话、备份恢复、证书和模板安全加固。 | 已完成 |

## `v0.6.16` 完整产品发布

### 发布内容

每个稳定产品 Release 都必须含有 `checksums.txt` 和
`relaydock-release-manifest.json`，并由清单声明以下四类受管组件：

| 组件 | 内容 |
| --- | --- |
| `control_plane` | 各受支持平台的控制面二进制 |
| `web` | 带版本元数据的 `relaydock-web.tar.gz` |
| `guard_assets` | Linux AMD64 / ARM64 到期守卫 |
| `speedtester_assets` | Linux 与 Windows 的测速组件 |

Linux AMD64 / ARM64 Agent 二进制仍随 GitHub Release 提供，并由节点安装脚本
直接下载对应版本的 `checksums.txt` 后校验；它不是面板一键更新管理的本地组件。

测速端同样只从 GitHub Release 下载。控制面不再提供测速端的公开安装脚本、
二进制下载接口或本地缓存；面板只生成配对信息和 GitHub 安装命令。

稳定发布要求 Git 标签、后端版本、发布清单 `release_id` 和 API 协议一致。发布
工作流拒绝将稳定版本声明为仅前端更新，以避免出现前端已更新、控制端尚未更新
的半发布状态。

### 面板一键更新的事务边界

管理员在“系统设置 → 系统更新”执行检查和更新时，控制面会：

1. 读取 GitHub Release、清单、GitHub 资产摘要、文件大小和 SHA-256。
2. 校验版本、组件归属、API 协议和本机 CPU 架构，并把所有必需资产下载到私有暂存区。
3. 保存可恢复的状态和数据库快照，锁定并持久化更新作业，防止并发或重启导致重复切换。
4. 原子替换控制面与本地资产；外置前端使用不可变版本目录，并将
   `current` / `previous` 链接原子切换。
5. 通过服务状态、控制面健康接口、网页版本元数据和 API 协议检查后，写入
   `installed-release.json`。
6. 任一阶段失败时恢复旧二进制、资产、数据库快照和网页链接；未完成事务会由
   独立 systemd helper 恢复，面板在恢复期间拒绝新更新请求。

这套路径适用于裸机 / systemd 部署。Docker 仍应通过 Compose 拉取并重建指定
镜像，面板不会在容器内替换运行文件。

### 外置前端约定

受管外置前端目录使用以下结构：

```text
<web-root>/
├── releases/<release-id>/
├── previous -> releases/<previous-release-id>
└── current  -> releases/<release-id>
```

控制面通过 `ARCWAY_WEB_ROOT` 指向 `current`；可选的
`ARCWAY_UPDATE_WEB_HEALTH_URL` 指向公开的
`/relaydock-release.json`。首次从未受管外置目录迁移时，更新器会将该网页视为
待迁移状态，而不是错误地认定为最新版本。

## 已完成的验证

### 自动化验证

- 前端：类型检查、生产构建和 383 个单元测试通过。
- 后端：`go test ./...`、`go vet ./...` 和控制面构建通过。
- 发布：发布清单契约、前端部署脚本、发布前置检查和事务脚本测试通过。
- 回滚：隔离环境分别验证了成功切换与健康检查失败后的完整恢复。
- GitHub：`v0.6.16` 的 17 个 CI / 构建 / 发布作业全部成功，发布的 16 个资产
  都通过 GitHub 资产摘要、`checksums.txt`、发布清单大小、SHA-256 和完整 bundle
  contract 验证。
- GHCR：`0.6.16`、`0.6` 和 `latest` 均指向 multi-arch index
  `sha256:70840fd776ff389a1526a33cd70f3479b404689593c200728d68cd1633fe4f61`，
  包含 Linux AMD64 与 ARM64 镜像。

### 生产验收

`v0.6.16` 已使用 GitHub Release 官方资产实际部署到生产控制面。验收包括：

- `arcway.service` 正常运行并报告 `version=0.6.16`；控制面二进制 SHA-256 为
  `7221971d39f9f72aa4317226dd6d3966a652ed918ce0a214b8809bcc8a92cfbb`，与
  Release 中 `arcway-linux-amd64` 完全一致。
- 网页 `current` 指向 `releases/v0.6.16-a2a82f65`，`previous` 保留
  `releases/20260810T-proxy-provider-8b7eaa6`；公开 `relaydock-release.json`
  返回 `application/json`，其版本、后端提交和 API 协议均与 Release 清单一致。
- 更新前已保存当前二进制和一致性 SQLite 快照；部署后数据库
  `PRAGMA integrity_check` 返回 `ok`。
- 首页与当前 hashed JavaScript 资产均返回 HTTP 200，缺失的 Proxy Provider
  资源返回预期 HTTP 404。
- 三台受管服务器 `Edge 154`、`Edge 170`、`Oracle` 均重新建立连接，Xray 状态
  正常，服务器 1、2、11 持续上报实时 metrics。
- 部署后未发现 warning、panic、fatal 或迁移错误。

本次发布仅触发一次 `publish=true` 工作流，并在下载、校验官方资产后进行一次
协调的控制面与网页切换；错误的未发布 `v0.6.15` 标签已删除且不会复用。

## 运维规则

- 只使用 GitHub Release 中同时存在清单和校验和的稳定产品包；不要手工替换单个
  二进制或单独覆盖前端目录。
- 更新前下载并验证加密备份。发生数据库迁移后，回退时必须同时恢复相应的数据备份，
  不能只降级二进制。
- 发布版本不得重打同名标签；若一次发布被取消或失败，修复后必须使用新版本号。
- 观察当前线上版本可读取：

  ```text
  https://<panel-domain>/relaydock-release.json
  ```

- 一键更新只适用于裸机 / systemd。Docker、手工托管且不符合 `current` /
  `previous` 结构的外置前端，应遵循 README 中对应的部署流程。

## 后续维护

每次稳定发布后应更新本文件中的版本、提交、验证结果和已知限制，并同步检查：

1. 后端 `internal/web/dist/` 是否与前端 `dist/` 一致。
2. Release 是否包含完整资产、清单和 `checksums.txt`。
3. API 协议、网页元数据和已安装状态是否相同。
4. 控制面及全部受管服务器的实时连接、心跳、流量与服务状态是否正常。

日常更新、兼容迁移、外置前端和故障恢复的具体步骤见
[更新与发布运维手册](operations/update-runbook.md)。

详细安装、Docker、备份和手动回滚说明见项目根目录 [README](../README.md)。
