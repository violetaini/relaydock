# RelayDock 项目状态与发布进展

更新时间：2026-08-02

## 当前结论

RelayDock 是一个由 Go 控制面、React 管理控制台和受管服务器 Agent
组成的多服务器 Xray 运维与订阅交付系统。当前正式版本为
[`v0.6.6`](https://github.com/violetaini/relaydock/releases/tag/v0.6.6)：

- 后端提交：`74555fd1ef64e930989b10fa638d382f68ce134c`
- 前端提交：`95fd6249f196f0b8c99e556d2edd77d0e61aa2a7`
- 产品发布协议：`1`
- 正式生产地址：[arcway.chitanda.org](https://arcway.chitanda.org)

该版本建立了完整产品发布事务。后端、网页、受管 Agent 安装包、到期守卫
和测速组件由同一个 GitHub Release 清单约束，不再把“更新后端”和“更新
前端”视为两件互不相关的操作。

## 代码库与运行架构

| 范围 | 仓库或组件 | 职责 |
| --- | --- | --- |
| 控制面 | [`violetaini/relaydock`](https://github.com/violetaini/relaydock) | Go API、数据库、远端服务器管理、安装器、发布工作流、内嵌前端与产品更新事务 |
| 管理控制台 | [`violetaini/relaydock-frontend`](https://github.com/violetaini/relaydock-frontend) | React / TypeScript 控制台、公开探针页、响应式交互与设置页面 |
| 受管节点 | [`violetaini/relaydock-agent`](https://github.com/violetaini/relaydock-agent) | 与控制面建立加密连接、汇报节点状态、流量和服务数据，并执行经授权的管理操作 |
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
- TCP/UDP 多跳隧道、Tunnel（任意门）、测速、流量明细、备份恢复和审计能力。
- Agent、到期守卫、端口防火墙同步、远端日志与状态回传。

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

## `v0.6.6` 完整产品发布

### 发布内容

每个稳定产品 Release 都必须含有 `checksums.txt` 和
`relaydock-release-manifest.json`，并由清单声明以下五类组件：

| 组件 | 内容 |
| --- | --- |
| `control_plane` | 各受支持平台的控制面二进制 |
| `web` | 带版本元数据的 `relaydock-web.tar.gz` |
| `guard_assets` | Linux AMD64 / ARM64 到期守卫 |
| `agent_install_assets` | Linux AMD64 / ARM64 受管 Agent 安装资产 |
| `speedtester_assets` | Linux 与 Windows 的测速组件 |

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

- 前端：类型检查、生产构建和 295 个单元测试通过。
- 后端：`go test ./...`、`go vet ./...` 和控制面构建通过。
- 发布：发布清单契约、前端部署脚本、发布前置检查和事务脚本测试通过。
- 回滚：隔离环境分别验证了成功切换与健康检查失败后的完整恢复。
- GitHub：`v0.6.6` 的 17 个 CI / 构建 / 发布作业全部成功，发布的 16 个资产
  都通过 `checksums.txt`、清单大小和 SHA-256 验证。

### 生产验收

`v0.6.6` 已实际部署到生产控制面。验收包括：

- `arcway.service` 正常运行，网页 `current` 指向 `releases/v0.6.6`，前端元数据
  与后端提交和 API 协议匹配。
- 控制面、守卫、Agent 和测速资产与 Release 的 9 个实际部署文件逐一进行哈希对比。
- 三台受管服务器 `Edge 154`、`Edge 170`、`Oracle` 均保持连接且 Xray 正在运行。
- 公共 WebSocket 连续四帧间隔约为 `995ms`、`1000ms`、`999ms`；REST 回退轮询约
  `1.1s`。三台服务器的流量均持续增长。
- 三台服务器的心跳、速度时间戳和系统流量时间戳均在 2.2 秒采样窗口内更新。
- 部署后未发现控制面错误级日志。

为避免在当前已经是 `v0.6.6` 的生产实例上重复执行同版本更新，面板触发的常规
更新路径没有被再次人为重放。首次迁移使用了经过成功和失败回滚演练的兼容引导
流程；下一次存在真实新版本时，应从面板执行一次常规完整更新，并将结果记录到
本文件。

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
