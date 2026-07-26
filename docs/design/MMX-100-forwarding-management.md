# MMX-100：管理员隧道与用户转发管理设计

## 1. 状态与目标

- 状态：首版已在 RelayDock v0.4.0 实施。
- 产品名称：转发管理。
- 目标：管理员使用 RelayDock 受管服务器创建可复用的单跳或多跳隧道，并把隧道使用权授权给用户；用户只能在有效授权范围内创建、暂停和删除自己的转发。
- 权限定义：首版“admin 组”对应现有 `RequireAdmin` 权限。隧道授权只授予使用权，不授予服务器、隧道或其他用户数据的管理权。

首版业务流程固定为：

```text
管理员添加服务器
        ↓
管理员创建隧道模板（香港 → 日本 → 美国）
        ↓
管理员授权用户（有效期、数量、速率、连接数、流量）
        ↓
用户选择获授权隧道和最终目标，创建转发
        ↓
RelayDock 为该转发选择一个路线端口并逐跳下发
        ↓
用户使用“入口地址:端口”连接最终服务
```

## 2. 产品术语

### 2.1 隧道模板

管理员维护的有序服务器路线，例如：

```text
HK-01 → JP-02 → US-01
```

模板本身不绑定用户、不绑定最终目标，也不预先占用转发端口。它定义可用路线、网络类型、计费规则和安全上限。模板端口范围只约束创建转发时的候选端口，不代表整段端口归隧道独占。

首版允许 1 至 8 台服务器；后端保留可配置上限，但不允许无限跳数：

- 1 台服务器表示单跳转发。
- 2 台及以上表示多跳转发。
- 同一台服务器不能在同一个模板中重复出现。
- 首版只允许本主控直接管理的服务器，不允许联邦分享服务器进入路线。

### 2.2 隧道授权

管理员把一个隧道模板授权给一个用户，并限定生效时间、最大转发数、流量、速率、连接数和目标类型。授权不会把服务器授权或管理员权限传递给用户。

### 2.3 用户转发

用户在一条有效隧道授权上创建的实际转发实例，包含：

- 最终目标。
- 网络类型；控制面固定为同时转发 TCP+UDP 的 `tcp_udp`。
- 路线端口；可自动选择，也可通过 `requested_entry_port` 显式请求。
- 每一跳实际监听端口；同一条路线的所有 hop 使用同一个路线端口。
- 生效状态、用量和到期时间。

每个用户转发沿路线拥有独立的入站和端口，用户之间不共享可修改的 Xray 配置。

例如显式请求端口 2033 的三跳路线固定为：

```text
A:2033 -> B:2033 -> C:2033 -> 最终目标:目标端口
```

控制面和数据库使用规范值 `tcp_udp`；下发到 Xray `dokodemo-door` 时使用 `settings.network = "tcp,udp"`。

## 3. 权限矩阵

| 操作 | 管理员 | 获授权用户 | 未授权用户 |
|---|---:|---:|---:|
| 添加、编辑、删除服务器 | 是 | 否 | 否 |
| 创建、排序、停止新建、紧急停用隧道模板 | 是 | 否 | 否 |
| 查看完整服务器路线和运维详情 | 是 | 否 | 否 |
| 创建、编辑、撤销隧道授权 | 是 | 否 | 否 |
| 查看自己的隧道授权 | 是 | 是 | 否 |
| 在获授权隧道上创建转发 | 是 | 是 | 否 |
| 暂停、恢复、删除自己的转发 | 是 | 是 | 否 |
| 管理其他用户的转发 | 是 | 否 | 否 |
| 查看 Agent 地址、Token 或原始 Xray JSON | 是 | 否 | 否 |

所有用户 API 都从登录身份取得 `username`，请求体不得提交或覆盖所有者。跨用户访问统一返回 `404`，避免通过 ID 探测资源是否存在。

## 4. 首版范围

### 4.1 上线必需

1. 管理员创建、停止新建、紧急停用和查看 1 至 8 跳隧道模板。
2. 管理员按“用户 × 隧道”创建、续期、暂停和撤销授权。
3. 用户在自己的有效授权上创建、暂停、恢复和删除 TCP+UDP 同时转发。
4. 在模板端口范围内自动选择或显式请求一个路线端口，全部 hop 使用该端口，并在数据库中按实际 hop 强一致预留。
5. 支持把用户已有且符合首版安全条件的受管物理节点作为目标。
6. 按用户转发执行有效期、授权总流量限制和上传+下载/仅下载计费；首版节点守卫不具备可靠的每转发速率与连接数限制，因此 API 拒绝非零值，界面保持禁用。
7. 控制端或 Agent 离线时保留期望状态，恢复后自动补偿或清理。
8. 完整的管理员审计、状态展示、重试和诊断入口。

### 4.2 后续版本

- 用户自定义公网 IP、域名和端口目标。
- 多目标和负载均衡。
- 跨主控联邦服务器路线。
- 隧道跳间的独立 TLS/WSS 等封装。
- 按用户聚合的实时总速率整形。
- 非管理员运维角色和更细粒度 RBAC。

首版页面可以展示后续能力，但必须禁用并标注“暂未支持”，不能提交后静默降级。

## 5. 核心不变量

1. 只有管理员可以改变隧道的服务器集合和顺序。
2. 用户创建转发时只提交 `tunnel_grant_id`，后端必须重新解析授权、模板和服务器路线，不能接受用户提交的 `server_ids`。
3. 服务器授权、节点授权和隧道授权是三类独立权限，任何一类都不能隐式推导另一类。
4. 隧道模板的限制是上限；用户授权只能继承或收紧，不能放宽模板策略。
5. 一个用户转发的每一跳都必须有本地主记录、同一路线端口的实际预留和期望状态，不能再依靠远端 Tag 反推业务数据。
6. 用户只有在所有跳都确认生效后才能获得可用入口。
7. 下发顺序固定为出口到入口，入口最后启用；删除顺序固定为入口到出口，先切断新流量。
8. 授权撤销、到期、超额或用户停用后，本地 API 和配置输出立即拒绝；运行中的远端入口通过短期可续租约在有界时间内停用，不能只等主控在线清理。
9. 用户计费流量只在入口统计一次，多跳服务器流量不能重复扣费。
10. 普通用户永远不能读取 Agent 凭据、原始入站、其他用户端口或内部跳间地址。

## 6. 数据模型

### 6.1 `tunnel_templates`

隧道模板的业务主记录。

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 内部 ID |
| `public_id` | TEXT UNIQUE | API 使用的不可猜测 ID |
| `name` | TEXT NOT NULL | 管理员可读名称 |
| `description` | TEXT NOT NULL DEFAULT '' | 备注 |
| `state` | TEXT NOT NULL DEFAULT 'active' | `active/draining/suspended/deleted` |
| `network` | TEXT NOT NULL DEFAULT 'tcp_udp' | TCP+UDP 同时转发的控制面规范值 `tcp_udp` |
| `billing_mode` | TEXT NOT NULL DEFAULT 'both' | `download` 或 `both` |
| `traffic_multiplier_milli` | INTEGER NOT NULL DEFAULT 1000 | 流量倍率，1000 表示 1.0 倍 |
| `max_total_forwards` | INTEGER NOT NULL DEFAULT 0 | 模板总转发数，0 表示不限 |
| `allow_managed_target` | INTEGER NOT NULL DEFAULT 1 | 允许选择已有可访问节点 |
| `allow_custom_public_target` | INTEGER NOT NULL DEFAULT 0 | 允许自填公网目标 |
| `entry_source_policy` | TEXT NOT NULL DEFAULT 'optional_allowlist' | `open/optional_allowlist/required_allowlist` |
| `port_range_start` | INTEGER NOT NULL | 自动分配端口起点 |
| `port_range_end` | INTEGER NOT NULL | 自动分配端口终点 |
| `version` | INTEGER NOT NULL DEFAULT 1 | 管理并发编辑 |
| `created_by` | TEXT NOT NULL | 创建管理员 |
| `created_at` | TIMESTAMP NOT NULL | 创建时间 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |
| `deleted_at` | TIMESTAMP NULL | 软删除时间 |

约束：

- `port_range_start/end` 必须在 1024 至 65535，且起点不大于终点。
- 端口范围只限制自动选择和 `requested_entry_port` 的候选值；创建或编辑模板不会向 `server_port_allocations` 写入整段预留。
- 节点管理和其他受管入站可以使用范围内端口。创建实际转发时，分配器只排除数据库中已登记的实际占用；Guard 下发时还会按每台服务器的实时 Xray 入站做最终冲突检查。
- 倍率使用整数存储，避免浮点累计误差。
- 首版忽略并强制保持 `allow_custom_public_target = 0`，直到固定拨号地址策略通过安全回归。
- `active`：允许创建、恢复和自动修复转发。
- `draining`：停止新授权、新建和用户主动恢复；已经运行且期望为 active 的转发继续运行并允许 reconciler 修复。
- `suspended`：紧急停用全部转发，停止续租并排队停用所有入口。
- `deleted`：只保留审计和待清理记录。
- 存在未删除转发时，服务器路线和网络类型不可直接修改。管理员应克隆为新模板，迁移授权后再清理旧模板。
- 删除模板时若仍有转发，默认返回冲突；强制删除必须先把相关转发置为删除并完成或排队远端清理。

### 6.2 `tunnel_template_hops`

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 跳 ID |
| `tunnel_id` | INTEGER NOT NULL | 模板 ID |
| `position` | INTEGER NOT NULL | 从 0 开始的顺序 |
| `server_id` | INTEGER NOT NULL | 受管服务器 |
| `connect_host_override` | TEXT NULL | 管理员显式指定的跳间地址 |
| `created_at` | TIMESTAMP NOT NULL | 创建时间 |

约束：

- `UNIQUE(tunnel_id, position)`。
- `UNIQUE(tunnel_id, server_id)`。
- 服务器必须存在、非联邦、已连接并具备转发所需能力。
- 默认使用服务器的受管互联地址；不得把 Agent 管理地址直接展示给用户。

### 6.3 `user_tunnel_grants`

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 授权 ID |
| `public_id` | TEXT UNIQUE | 用户 API 使用 ID |
| `username` | TEXT NOT NULL | 被授权用户 |
| `tunnel_id` | INTEGER NOT NULL | 隧道模板 |
| `enabled` | INTEGER NOT NULL DEFAULT 1 | 管理员开关 |
| `starts_at` | TIMESTAMP NOT NULL | 生效时间，UTC |
| `expires_at` | TIMESTAMP NULL | 到期时间，NULL 表示长期 |
| `max_active_forwards` | INTEGER NOT NULL DEFAULT 1 | 最大同时启用转发数 |
| `per_forward_speed_mbps` | REAL NOT NULL DEFAULT 0 | 每条转发速率，0 表示不限 |
| `per_forward_connection_limit` | INTEGER NOT NULL DEFAULT 0 | 每条转发并发连接数 |
| `traffic_limit_bytes` | INTEGER NOT NULL DEFAULT 0 | 授权周期总流量 |
| `billing_mode_override` | TEXT NULL | NULL 继承模板 |
| `allow_managed_target` | INTEGER NOT NULL DEFAULT 1 | 授权是否允许已有节点目标 |
| `allow_custom_public_target` | INTEGER NOT NULL DEFAULT 0 | 授权是否允许自填公网目标 |
| `reset_policy` | TEXT NOT NULL DEFAULT 'none' | `none/monthly` |
| `reset_day` | INTEGER NOT NULL DEFAULT 1 | 月度重置日 1 至 28 |
| `billing_timezone` | TEXT NOT NULL DEFAULT 'Asia/Shanghai' | 周期时区 |
| `next_reset_at` | TIMESTAMP NULL | 下次重置 UTC 时间 |
| `version` | INTEGER NOT NULL DEFAULT 1 | 乐观锁版本 |
| `created_by` | TEXT NOT NULL | 创建管理员 |
| `created_at` | TIMESTAMP NOT NULL | 创建时间 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |

约束：

- `UNIQUE(username, tunnel_id)`。
- 授权的目标类型必须是模板允许类型的子集。
- 首版授权 API 拒绝 `allow_custom_public_target = 1`。
- 管理员降低 `max_active_forwards` 到当前数量以下时，API 返回冲突清单，不随机停用转发。
- 撤权、到期或超额时暂停该授权下全部转发；续期或重置后仅自动恢复此前由系统暂停且用户期望状态仍为启用的转发。

授权有效状态由后端计算：

- `scheduled`：尚未到 `starts_at`。
- `active`：用户和授权启用、模板为 `active`、未到期且未超额。
- `suspended`：管理员关闭授权。
- `expired`：超过 `expires_at`。
- `over_limit`：当期计费流量达到额度。
- `tunnel_draining`：模板停止新建；已运行转发可继续并自动修复，但不能创建或由用户主动恢复。
- `tunnel_unavailable`：模板紧急停用、路线不完整或安全能力不满足。
- `user_disabled`：用户账号停用。

### 6.4 `user_forward_rules`

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 转发 ID |
| `public_id` | TEXT UNIQUE | 用户可见 ID |
| `grant_id` | INTEGER NOT NULL | 所属隧道授权 |
| `username` | TEXT NOT NULL | 所有者，冗余用于强制隔离 |
| `name` | TEXT NOT NULL | 用户可读名称 |
| `target_type` | TEXT NOT NULL | `managed_node/custom_public` |
| `target_node_id` | INTEGER NULL | 已有节点目标 |
| `target_host` | TEXT NOT NULL | 规范化后的目标地址快照 |
| `target_port` | INTEGER NOT NULL | 最终目标端口 |
| `network` | TEXT NOT NULL DEFAULT 'tcp_udp' | 实际网络类型，固定为 `tcp_udp` |
| `requested_entry_port` | INTEGER NOT NULL DEFAULT 0 | 显式请求的路线端口；0 表示自动选择 |
| `allocated_entry_port` | INTEGER NULL | 已分配的路线公共端口，所有 hop 相同 |
| `source_cidrs` | TEXT NOT NULL DEFAULT '[]' | 入口来源白名单，规范化 JSON |
| `desired_state` | TEXT NOT NULL | `active/inactive/deleted` |
| `observed_state` | TEXT NOT NULL | 实际状态 |
| `suspend_reason` | TEXT NOT NULL DEFAULT 'none' | 暂停原因 |
| `generation` | INTEGER NOT NULL DEFAULT 1 | 期望版本 |
| `applied_generation` | INTEGER NOT NULL DEFAULT 0 | 已应用版本 |
| `effective_expires_at` | TIMESTAMP NULL | 授权和其他限制计算出的最早到期时间 |
| `lease_until` | TIMESTAMP NULL | Agent 当前短租约截止时间 |
| `billing_mode_snapshot` | TEXT NOT NULL | 本计费周期采用的方向快照 |
| `traffic_multiplier_milli_snapshot` | INTEGER NOT NULL | 本计费周期采用的倍率快照 |
| `last_error_code` | TEXT NOT NULL DEFAULT '' | 可公开错误分类 |
| `last_error_detail` | TEXT NOT NULL DEFAULT '' | 仅管理员可见的脱敏详情 |
| `created_at` | TIMESTAMP NOT NULL | 创建时间 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |
| `deleted_at` | TIMESTAMP NULL | 软删除时间 |

`observed_state` 使用：

- `pending`：已写入本地，等待 Worker。
- `provisioning`：正在逐跳下发。
- `active`：所有跳和限制均已确认。
- `degraded`：至少一跳失联，但没有确认配置已消失。
- `suspended`：入口已停用或到期策略已生效。
- `cleanup_pending`：本地已删除，远端仍待清理。
- `error`：不可自动恢复的校验或配置错误。

### 6.5 `user_forward_hops`

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 实例跳 ID |
| `forward_id` | INTEGER NOT NULL | 用户转发 |
| `template_hop_id` | INTEGER NOT NULL | 模板跳快照来源 |
| `position` | INTEGER NOT NULL | 路线顺序 |
| `server_id` | INTEGER NOT NULL | 实际服务器 |
| `resource_tag` | TEXT NOT NULL UNIQUE | 不含用户名的随机 Tag |
| `listen_port` | INTEGER NOT NULL | 本跳监听端口；同一转发所有 hop 相同 |
| `next_host` | TEXT NOT NULL | 下一跳或最终目标 |
| `next_port` | INTEGER NOT NULL | 下一跳使用同一路线端口；最后一跳使用目标端口 |
| `desired_state` | TEXT NOT NULL | 期望状态 |
| `observed_state` | TEXT NOT NULL | Agent 观察状态 |
| `generation` | INTEGER NOT NULL DEFAULT 1 | 期望版本 |
| `applied_generation` | INTEGER NOT NULL DEFAULT 0 | 已应用版本 |
| `retry_count` | INTEGER NOT NULL DEFAULT 0 | 重试次数 |
| `next_retry_at` | TIMESTAMP NULL | 下次重试时间 |
| `last_error` | TEXT NOT NULL DEFAULT '' | 脱敏错误 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |

Tag 由随机 `resource_id` 确定性派生为 `rd-tun-<digest>`，不能包含用户名、目标域名或其他隐私信息。

### 6.6 `server_port_allocations`

这是全部 RelayDock 受管入站共用的端口所有权表，不是隧道功能的私有表。节点创建、安装器、旧版 Tunnel 迁移和新转发都必须接入同一分配器。

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 预留 ID |
| `server_id` | INTEGER NOT NULL | 服务器 |
| `network` | TEXT NOT NULL | 套接字占用维度 `tcp` 或 `udp`；`tcp_udp` 转发同时写入两条预留 |
| `port` | INTEGER NOT NULL | 端口 |
| `owner_type` | TEXT NOT NULL | `node/forward_hop/legacy_external/system` |
| `owner_id` | INTEGER NOT NULL | 所属资源 ID |
| `state` | TEXT NOT NULL | `reserved/applied/releasing` |
| `remote_revision` | TEXT NULL | Agent 确认时的配置版本 |
| `created_at` | TIMESTAMP NOT NULL | 创建时间 |

约束：`UNIQUE(server_id, network, port)` 和 `UNIQUE(owner_type, owner_id, network)`。配额计数、业务记录和实际 hop 端口预留必须在同一个短事务中原子提交。模板端口范围本身不产生预留；只有创建具体转发后，才为路线中每台服务器的同一端口分别写入 TCP、UDP 所有权记录。

升级时扫描所有可读远端入站并回填 `legacy_external` 占用。端口分配失败必须整体回滚本地事务，不能依赖“随机碰撞后让 Agent 报错”。读取远端配置失败时应失败关闭；Agent 仍须在原子应用操作中检查实时配置版本和端口占用，因为数据库无法约束用户在服务器上手工修改 Xray。

### 6.7 用量与审计

`user_forward_usage` 按转发保存入口原始计数游标、计数代次、周期上行和下行。`user_tunnel_grant_usage` 可作为授权周期汇总缓存，但事实来源仍是各转发入口用量。

`tunnel_audit_events` 记录模板、授权、转发、自动暂停、重试、清理和管理员强制操作。日志不保存 Token、UUID、密码、Reality 私钥或完整 Xray JSON。

## 7. 目标类型与安全策略

### 7.1 已有节点目标

这是默认且最安全的入口。首版只接受 RelayDock 已发布并可确认原始入站的受管物理节点，不接受外部导入、routed、tunnel 或已经二次改写地址的节点。用户提交 `node_id` 后，后端通过统一节点访问解析器确认用户仍有任一有效访问来源，再读取不可被前端覆盖的规范化原始目标地址和端口。

目标预检还必须检查协议白名单、目标端口、路线回环和 RelayDock 控制端口。目标节点失去某一个套餐或授权来源时，应重新运行统一访问解析器；只要还有其他有效来源就不能误停转发。

若目标是 VLESS Reality、Trojan TLS、VMess WS 等代理节点，RelayDock 可生成“经隧道连接”的配置：

- 只把连接地址和端口替换为转发入口。
- 保留原目标的 UUID、密码、SNI、Host、Path、Reality 公钥、Short ID、Fingerprint 和 Flow。
- 用户失去目标节点权限时，相关转发立即进入暂停并排队清理。

### 7.2 自定义公网目标

该能力不进入首版用户闭环。目标拨号策略和安全回归完成后，只有模板和用户授权都显式允许时才出现：

1. 禁止 loopback、链路本地、私网、ULA、组播、未指定地址和云元数据地址。
2. 域名在创建、启用和实际出口应用时解析并重新校验；Agent 最终接收校验通过的 IP 字面值而不是原始域名，并由 reconciler 受控刷新，防止 DNS rebinding。
3. 默认禁止 RelayDock 控制面、Agent 管理端口、数据库和本机管理端口。
4. 目标变更必须创建新 generation 并完整重新预检，不能只改最后一跳。
5. 自定义公网目标必须填写来源 CIDR 白名单；已有节点目标可由模板决定白名单是可选还是必填。
6. 所有解析结果和拒绝原因写脱敏审计。

管理员后续可维护目标允许列表；允许列表规则只能收紧上述基础拦截，不能绕过系统保留地址保护。

### 7.3 传输安全说明

首版基于 Xray `dokodemo-door` 的链式端口转发，负责搬运字节，不等于自动加密的站点到站点隧道：

- 目标协议本身使用 Reality/TLS 时，其端到端数据仍由目标协议加密。
- 自定义明文 TCP 或 UDP 服务不会因为经过 RelayDock 转发而自动变成加密流量。
- UI 使用“TCP+UDP 转发/多跳转发”，不能把直连转发宣传为“加密隧道”。

## 8. 下发、回滚与恢复

### 8.1 创建

1. 在一个数据库事务内锁定授权和模板，重新计算有效权限与配额。
2. 为全部服务器按稳定的 `server_id` 顺序取得真正的独占配置变更锁；安装器、节点管理和旧版 Tunnel 等其他入站写接口必须共享同一把锁。现有只阻断安装流程的 mutation lease 不满足该要求，实施时必须替换。
3. 在模板定义的候选范围内选择一个对所有 hop 都没有数据库占用的公共端口；范围起止必须位于 1024 至 65535。若请求包含 `requested_entry_port`，只验证该端口。随后为每台 hop 服务器的同一端口分别预留 TCP 和 UDP；Guard 应用资源时读取 Agent 当前入站并再次拒绝实时占用。自动选择遇到实时冲突时换用新的公共端口和资源身份，显式端口冲突则直接返回。
4. 写入 `user_forward_rules`、`user_forward_hops` 和 outbox 任务后提交事务。
5. Worker 从出口跳向入口跳依次应用，入口最后启用。
6. 每个 Agent 请求携带 `resource_id + generation + network=tcp_udp + hard_not_after + lease_until`，重复请求必须幂等；Guard 生成的 Xray `dokodemo-door` 入站固定使用 `settings.network = "tcp,udp"`。
7. 全部确认后标记 `active`，此时用户才可复制入口或生成配置。

### 8.2 失败回滚

- 尚未启用入口时，反向删除已经创建的出口和中间跳。
- Agent 离线或删除未确认时保留 `cleanup_pending`，端口预留不可提前释放。
- 旧 generation 的回执不能覆盖新状态。
- 重试采用指数退避，并提供管理员立即重试入口。

### 8.3 暂停和删除

- 用户暂停：先停入口，保留中间跳和端口，便于快速恢复；长时间暂停可由清理策略回收。
- 到期、撤权、超额或用户停用：先停入口，并异步删除全部跳。
- 用户删除：入口到出口依次删除，全部确认后才释放端口。
- Agent 与主控失联：本地立即隐藏入口和生成配置；Agent 在 `lease_until` 到点后自行停用入站，重启后也不能恢复已过期资源。

### 8.4 模板变更

- 名称、备注和普通展示字段可原地修改。
- 有活动转发时，服务器路径、网络类型和端口池不可原地修改。
- 管理员通过“克隆模板”创建新路线，再批量迁移授权；现有转发继续使用旧路线直到用户或管理员重建。

## 9. Agent 能力要求

服务器进入可授权隧道前必须上报：

- `managed_tunnel_v1`：按资源 ID 和 generation 幂等应用、查询、停用和删除转发入站。
- `inbound_expiry_v1`：Agent 持久化绝对 `hard_not_after` 和短期 `lease_until`，任一个到期都本地停用，重启后不能恢复过期资源。
- `inbound_acl_v1`：限制中间跳只接受上一跳服务器实际出口地址，并支持入口来源 CIDR；允许和默认拒绝规则必须同时覆盖 TCP、UDP。
- `tunnel_networks`：必须包含控制面规范值 `tcp_udp`；只广告 `tcp` 的旧 Guard 不满足当前转发要求。
- `inbound_limiter_v1`：按转发入站执行速率和连接数限制。
- `inbound_stats_v1`：返回稳定的入站上下行计数和计数代次。

创建模板时由前一跳发起探测，后一跳 Agent 观察并返回实际来源 CIDR；该结果持久化为跳快照，并由 Agent 原子安装入站和防火墙规则。NAT 出口不稳定或无法确认时预检失败，管理员必须先配置稳定互联地址。每一跳只信任直接上一跳，不能笼统信任入口或整组服务器，也不能用“下一跳连接地址”反推来源 IP。缺少任一首版能力的服务器可以继续作为普通节点，但不能加入可授权隧道。

主控每 60 秒为仍有效且未超额的转发续租，默认一次续租 5 分钟。管理员提前撤权或主控失联时，远端最迟在 5 分钟加允许的时钟误差内停用；分布式系统无法承诺离线 Agent 上瞬时撤权。服务器必须保持时间同步，时钟偏差超过 30 秒时停止新建并在面板告警。

## 10. 流量、限速与到期

### 10.1 计费

只采集入口跳作为用户账单来源：

```text
download：入口向用户发送的字节 × 模板倍率
both：（用户发往入口 + 入口发往用户）× 模板倍率
```

中间跳和出口跳的计数只供管理员查看线路负载与故障，不参与用户扣费。这样三跳路线不会被按三份流量重复计算。

### 10.2 限速

首版 `per_forward_speed_mbps` 和 `per_forward_connection_limit` 明确定义为每条转发限制，不冒充用户所有转发的聚合限速。聚合限速需要 Agent 的组级整形能力，后续单独实现。

速率和连接数只在入口执行，避免每一跳重复整形。授权总流量由主控汇总所有入口计数并判定，主控只在未超额时续租。最大超额量仍受采集周期、所有活动转发的速率和剩余租约影响，UI 必须说明流量统计存在短暂延迟。

计费方向和倍率在计费周期开始时写入 usage 快照；周期已有用量后，模板或授权变更只能从下个周期生效，不能追溯重算。Agent 必须持久化累计计数或报告稳定的 counter epoch，使 Xray 或 Agent 重启不会把已消费流量清零。

### 10.3 有效期

转发有效期取以下时间的最早值：

- 隧道授权 `expires_at`。
- 目标节点访问权限到期时间（目标为已有节点时）。
- 管理员对该转发设置的更早截止时间（后续能力）。

每次续期、恢复和 reconcile 都重新计算，并把绝对 UTC 时间下发给每一跳 Agent。

## 11. API 草案

所有写接口使用 `Idempotency-Key`；更新接口提交 `version`，冲突返回 `409`。

### 11.1 管理员：隧道模板

- `GET /api/admin/tunnel-templates`
- `POST /api/admin/tunnel-templates/preflight`
- `POST /api/admin/tunnel-templates`
- `GET /api/admin/tunnel-templates/{id}`
- `PUT /api/admin/tunnel-templates/{id}`
- `POST /api/admin/tunnel-templates/{id}/clone`
- `PUT /api/admin/tunnel-templates/{id}/state`
  - 请求：`{ "state": "active|draining|suspended", "version": 3 }`
- `POST /api/admin/tunnel-templates/{id}/probe`
- `DELETE /api/admin/tunnel-templates/{id}`
- `GET /api/admin/tunnel-templates/{id}/diagnostics`

模板创建请求只接受服务器 ID 和顺序；服务器地址、Agent 能力和联邦属性由后端解析。

`probe` 创建最长 5 分钟的系统诊断任务，使用受控探测目标，不向普通用户暴露入口并在结束后强制清理。管理员如需长期实际转发，也必须给自己的账号或测试账号创建授权，不能绕过统一授权模型。

### 11.2 管理员：用户授权

- `GET /api/admin/users/{username}/tunnel-grants`
- `POST /api/admin/users/{username}/tunnel-grants`
- `PUT /api/admin/users/{username}/tunnel-grants/{id}`
- `POST /api/admin/users/{username}/tunnel-grants/{id}/suspend`
- `POST /api/admin/users/{username}/tunnel-grants/{id}/resume`
- `DELETE /api/admin/users/{username}/tunnel-grants/{id}`

同一组接口也可从隧道详情页调用，但后端保持一个实现，不能形成两套授权逻辑。

### 11.3 管理员：全部转发

- `GET /api/admin/forwards?username=&tunnel_id=&server_id=&state=`
- `GET /api/admin/forwards/{id}`
- `POST /api/admin/forwards/{id}/suspend`
- `POST /api/admin/forwards/{id}/resume`
- `POST /api/admin/forwards/{id}/retry`
- `POST /api/admin/forwards/{id}/force-cleanup`
- `DELETE /api/admin/forwards/{id}`

### 11.4 用户：我的转发

- `GET /api/user/tunnel-grants`
- `GET /api/user/forwards`
- `POST /api/user/forwards/preflight`
- `POST /api/user/forwards`
- `GET /api/user/forwards/{id}`
- `POST /api/user/forwards/{id}/suspend`
- `POST /api/user/forwards/{id}/resume`
- `POST /api/user/forwards/{id}/retry`
- `DELETE /api/user/forwards/{id}`
- `GET /api/user/forwards/{id}/client-config`

用户创建请求示例：

```json
{
  "grant_id": "grant_opaque_id",
  "name": "US-Reality",
  "target": {
    "type": "managed_node",
    "node_id": 42
  },
  "network": "tcp_udp",
  "requested_entry_port": 2033,
  "source_cidrs": []
}
```

`network` 的规范值为 `tcp_udp`；为兼容旧客户端，后端仍接受 `tcp` 并归一化为 `tcp_udp`。`requested_entry_port` 可省略或设为 0 以自动选择，也可显式设为 2033 等模板范围内的 1024 至 65535 端口；成功后 A-B-C 等全部 hop 都监听该端口。

响应只有在 `observed_state = active` 后才返回可用入口。异步创建返回任务 ID，前端轮询或通过事件流更新状态。

## 12. 页面设计

入口放在“节点管理 > 转发管理”，不再把用户功能放进“高级功能”。

### 12.1 普通用户

页面顶部展示：

- 运行中转发数 / 允许数量。
- 本周期已用 / 总流量。
- 可用隧道数。
- 最近授权到期时间。

页面包含两个主视图：

1. `我的转发`：名称、状态、入口、目标、路线摘要、协议、流量、限制、到期时间和操作。
2. `可用隧道`：管理员公开给该用户的路线名称、地区顺序、延迟摘要、限制和有效期；不展示管理地址或内部端口。

创建向导遵循用户自然操作顺序：

1. 选择已授权隧道。
2. 选择已有受管节点目标；后续版本在获准时可填写公网目标。
3. 设置名称、可选路线端口和来源白名单；网络类型固定展示为 TCP+UDP。
4. 预检并确认：展示路线、所有 hop 共用的端口、最终入口、有效期、限速、连接数、计费方向和倍率。

转发未完全生效前，复制按钮和客户端配置按钮必须禁用。已有节点目标生效后，可直接生成替换了地址和端口的完整客户端配置。

### 12.2 管理员

管理员在同一页面看到三个页签：

1. `隧道模板`：创建路线、拖动排序、能力预检、克隆、停止新建、紧急停用和诊断。
2. `用户授权`：按隧道或用户筛选，创建、续期、暂停和撤权。
3. `全部转发`：按用户、隧道、服务器、状态和协议筛选，查看每跳状态并重试或清理。

隧道编辑器采用从左到右的路线编排：

```text
[入口 HK-01] → [中转 JP-02] → [出口 US-01] → [用户目标]
```

服务器卡只显示名称、地区、在线状态、能力和可用端口池；Agent Token 等敏感信息不进入该页面。

用户管理中的“隧道授权”作为同一授权编辑器的快捷入口，保存后回到用户设置，不另造独立数据模型。

### 12.3 节点任意门

管理员可在节点管理的单行操作菜单中选择“任意门转发”，选择一台在线受管服务器和监听端口。控制端创建同时监听 TCP、UDP 的 `dokodemo-door` 入站，并克隆原节点客户端配置，只把连接地址和端口替换为任意门入口；重复的同服务器、同入站 Tag 事件必须更新已有克隆，不能产生重复节点。

任意门端口可以位于某个隧道模板的候选范围内。模板范围本身不产生占用，只有具体任意门或具体用户转发实际创建时才检查端口冲突。

## 13. 旧功能迁移

现有 `/api/admin/tunnel-chains` 和远端 `tunnel-<label>-h<n>` 没有数据库主记录，不能直接授权给用户。

迁移策略：

1. 旧功能保持管理员可见但标记为“旧版未托管转发”。
2. 新系统使用 `rd-tun-*` Tag，与旧 Tag 完全隔离。
3. 提供一次性导入预检：识别完整路线、端口和目标后，管理员确认才能创建模板或转发记录。
4. 无法证明完整性的散装入站只允许查看和清理，不允许授权。
5. 新页面稳定后，旧“高级功能 > Tunnel 管理”改为只读迁移入口，最终移除旧写接口，避免两套编排器同时修改 Xray。

### 13.1 TCP 转发升级为 TCP+UDP

1. 先升级或重装路线中每台服务器的 Agent 与 expiry Guard，使 `tunnel_networks` 上报 `tcp_udp`；旧 Guard 仍允许暂停和删除，但不能创建或续租新的 TCP+UDP generation。
2. 数据库迁移把旧 `tcp` 规则规范化为 `tcp_udp`，并将仍为 active 的 rule 与 hop 提升 generation、重置 applied 状态，强制 Guard 重新下发 Xray 入站。
3. 旧版多跳若各 hop 使用不同端口，reconciler 在下发前为整条路线重新选择一个公共端口和新资源身份，再清理旧资源；清理暂时失败时仍由旧资源短租约保证最终失效。
4. 回填 UDP 端口所有权时若发现其他资源已占用，不得让数据库永久启动失败；规则保持待调和，由公共端口重分配流程恢复。
5. 旧“高级功能 > Tunnel 管理”的链式创建会为每个 hop 的 Add/Remove 携带稳定 `mutation_id`。升级后的 Agent 将删除栅栏持久化到侧车文件，防止响应超时后迟到的 Add 在已确认删除后重新监听端口；旧 Agent 兼容忽略该字段，但不具备该保护，因此也应升级或重装。

## 14. 实施顺序

### 阶段 A：可靠性底座

- 数据表、迁移、Repository、审计和 outbox。
- Agent 五项能力与配置互斥锁。
- 全局端口所有权、Agent revision/CAS、generation 幂等和 reconciler。
- 目标校验、ACL 和本地到期保护。
- 先用 TCP+UDP 同时转发、公共路线端口和受管节点目标完成 Agent 技术验证，再开始普通用户页面。

### 阶段 B：管理员闭环

- 隧道模板 API 与页面。
- 用户隧道授权 API，并接入用户管理。
- 管理员创建测试转发、逐跳诊断和完整清理。

### 阶段 C：用户闭环

- 用户可用隧道和我的转发页面。
- 四步创建向导、预检、复制入口和节点配置生成。
- 到期、限额、流量、暂停与恢复。

### 阶段 D：扩展能力

- 多目标、负载均衡和联邦路线。
- 自定义公网目标及其固定拨号地址策略。
- 跳间额外加密传输和聚合速率整形。

阶段 A 和 B 必须先用管理员测试转发跑通创建、故障和清理，再开放阶段 C。不能把普通用户作为新编排器的首批测试者。

## 15. 验收标准

1. 普通用户不能通过前端或直接 API 创建、修改、排序或删除隧道模板。
2. 用户只能看到自己的授权和转发，篡改用户名、授权 ID、节点 ID 或模板 ID 均不能越权。
3. 两个并发创建请求不会在任何一台服务器上获得相同 TCP 或 UDP 端口；模板端口范围不会整段预占，也不会阻止节点使用范围内未被具体转发占用的端口。
4. 中间任一 Agent 下发失败时，入口不可用；已下发资源可回滚或明确进入待清理。
5. 创建时 Agent 离线、删除时 Agent 离线、主控重启和 Agent 重启后都能最终收敛。
6. 自然到期按 `hard_not_after` 停用；提前撤权或主控失联按短租约在 5 分钟加允许的时钟误差内停用。
7. 三跳转发产生 1 GiB 可计费流量时，用户账单只增加一次并正确应用倍率。
8. 已有节点目标生成的 Reality/TLS/WS 配置只替换入口地址和端口，SNI、Host、密钥和路径保持正确。
9. 自动分配和显式 `requested_entry_port=2033` 都使 A-B-C 等全部 hop 使用同一个端口；任一 hop 上 TCP 或 UDP 已占用时，显式请求返回冲突，自动分配改选另一公共端口。
10. 后续开放自定义目标前，必须验证其不能访问私网、loopback、链路本地、云元数据或 RelayDock 管理面。
11. 模板停止新建、模板紧急停用、授权撤销、用户停用、超额和手动暂停在 UI 中有不同原因，不以笼统“失败”代替。
12. 删除转发后，所有跳、ACL、限速规则和端口预留均被确认清理；离线服务器显示待清理且可重试。
13. 所有管理员变更和系统自动动作可在面板审计记录中追踪，但不泄露敏感配置。

## 16. 已确定的产品决策

- 添加服务器：仅管理员。
- 创建和编排隧道：仅管理员组。
- 授权隧道给用户：仅管理员组。
- 用户能力：使用授权创建自己的转发，不得改变路线。
- 路线能力：首版保留 RelayDock 的 1 至 8 跳，不采用固定双节点拓扑。
- 计费：入口只计一次，支持模板倍率。
- 首发协议：TCP+UDP 同时转发；控制面使用 `tcp_udp`，Xray `dokodemo-door` 使用 `tcp,udp`。
- 首发服务器：只支持本主控直接管理的服务器，不支持联邦分享服务器。
- 自定义目标：首版不开放；后续必须由模板和用户授权双重允许，并使用固定的已审核拨号 IP。

## 17. 参考

- 现有服务器授权设计：`docs/design/MMX-090-user-server-grants.md`。
- 现有旧版链路实现：`internal/handler/tunnel_chains.go`、`internal/handler/tunnels.go`。
- [Flux Panel 使用指南](https://brunuhville.github.io/flux-panel/guide.html)和[隧道数据模型](https://github.com/bqlpfy/flux-panel/blob/main/springboot-backend/src/main/java/com/admin/entity/Tunnel.java)的“管理员创建隧道、用户获得权限后创建转发”交互作为权限分层参考；RelayDock 不采用其固定双节点拓扑。
