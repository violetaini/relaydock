# RD-090：服务器授权与用户自助开通节点设计

## 1. 状态与目标

- 状态：设计基线，尚未实施
- 目标：管理员发布受管节点，并按“用户 × 服务器”授权；用户只能在有效授权范围内自助开通或停用自己的节点凭据。
- 业务定义：用户看到的“创建节点”是给管理员预建的 Xray inbound 签发该用户专属 client（UUID、密码等），不是让用户创建端口或提交 Xray JSON。

首版必须支持：

1. 管理员决定哪些受管节点可以被用户自助开通。
2. 管理员给一个用户授权一台或多台服务器，并分别设置有效期。
3. 用户在获授权服务器中自由选择已发布节点，开通后获得独立凭据。
4. 管理员按服务器授权设置默认限速、并发连接数、流量额度和计费方向，并可对单个已开通节点覆盖。
5. 到期、停用、超额或撤权后，本地权限立即失效；远端 Agent 离线时记录待清理并自动重试。
6. 套餐和服务器授权可以并存，任何一方失效都不能误删另一方仍需要的 client。

## 2. 首版边界

### 2.1 包含

- 物理节点发布/取消发布。
- 用户服务器授权的创建、编辑、续期、暂停和撤销。
- 用户自助开通、取消开通及状态查询。
- 用户专属凭据的幂等创建、恢复和清理。
- 授权维度的流量统计、额度判定、限速及并发连接限制。
- 管理端和用户端完整状态展示。
- 操作审计、失败重试和安全回归测试。

### 2.2 不包含

- 普通用户创建独立 inbound、端口、证书、Reality 密钥或路由规则。
- 普通用户读取服务器完整 inbound/client 列表。
- routed、tunnel、外部导入节点和联邦分享节点的自助开通；这些能力首版继续走原流程。
- 同一用户在同一物理节点上创建多个 client。首版固定为“一用户 × 一服务器 × 一 inbound = 一份凭据”。

## 3. 核心不变量

1. 只有管理员明确发布的节点才能出现在自助目录中。
2. 发布项必须绑定明确的 `server_id + inbound_tag`，不能依靠服务器名称或节点 Host 猜测归属。
3. 一个发布项唯一对应一个受管物理 inbound；同一 `server_id + inbound_tag` 不能发布两次。
4. 用户创建请求只接受发布项 ID；服务器、Tag、协议和凭据全部由后端解析。
5. 后端在每次创建、订阅生成、节点列表、复制配置和出站操作时实时校验授权，不依赖前端隐藏按钮。
6. 普通用户的凭据替换失败时必须丢弃该节点，绝不能回退返回管理员原始凭据。
7. client 是否应存在由统一访问解析器决定；任何套餐、授权或用户状态处理器都不得直接“删除该用户全部 client”。
8. 本地授权失效优先于远端清理结果：订阅和 API 立即拒绝，Agent 清理最终一致。

## 4. 数据模型

### 4.1 `self_service_node_offers`

管理员发布的自助节点目录，不直接修改普通 `nodes` 的归属语义。

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 发布项 ID |
| `node_id` | INTEGER NOT NULL UNIQUE | 对应 `nodes.id` |
| `server_id` | INTEGER NOT NULL | 对应 `xray_servers.id` |
| `inbound_tag` | TEXT NOT NULL | 发布时从节点读取并锁定 |
| `enabled` | INTEGER NOT NULL DEFAULT 1 | 是否允许新开通 |
| `sort_order` | INTEGER NOT NULL DEFAULT 0 | 用户目录顺序 |
| `created_by` | TEXT NOT NULL | 管理员用户名 |
| `created_at` | TIMESTAMP NOT NULL | 创建时间 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |

约束：

- `UNIQUE(server_id, inbound_tag)`。
- 仅允许 `nodes.node_type = 'physical'`、节点已启用、`inbound_tag` 非空且服务器存在。
- 首版服务器必须是 embedded Xray，并由 Agent 上报 `managed_clients_v1`、`client_expiry` 和 `limiter_replace` 能力；缺少任一能力都不能发布。
- 发布时读取远端 inbound，确认协议支持独立 client 且 Tag 与节点一致。
- 服务器或节点删除时先撤销发布，并触发相关实例回收。

### 4.2 `user_server_grants`

用户对某台服务器的授权，是该功能的业务主记录。

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 授权 ID |
| `username` | TEXT NOT NULL | 用户名 |
| `server_id` | INTEGER NOT NULL | 被授权服务器 |
| `enabled` | INTEGER NOT NULL DEFAULT 1 | 管理员暂停开关 |
| `starts_at` | TIMESTAMP NOT NULL | 生效时间，UTC |
| `expires_at` | TIMESTAMP NULL | 到期时间；NULL 表示长期 |
| `max_active_nodes` | INTEGER NOT NULL DEFAULT 0 | 最大已选择节点数；0 表示不限 |
| `speed_limit_mbps` | REAL NOT NULL DEFAULT 0 | 默认速率；0 表示不限 |
| `connection_limit` | INTEGER NOT NULL DEFAULT 0 | 默认并发连接数；0 表示不限 |
| `traffic_limit_bytes` | INTEGER NOT NULL DEFAULT 0 | 当前周期额度；0 表示不限 |
| `billing_mode` | TEXT NOT NULL DEFAULT 'download' | `download` 或 `both` |
| `reset_policy` | TEXT NOT NULL DEFAULT 'none' | `none` 或 `monthly` |
| `reset_day` | INTEGER NOT NULL DEFAULT 1 | 月度重置日 1-28 |
| `billing_timezone` | TEXT NOT NULL DEFAULT 'Asia/Shanghai' | 计算月度周期的 IANA 时区 |
| `next_reset_at` | TIMESTAMP NULL | 下次重置的绝对 UTC 时间 |
| `version` | INTEGER NOT NULL DEFAULT 1 | 管理端并发编辑控制 |
| `created_by` | TEXT NOT NULL | 创建管理员 |
| `created_at` | TIMESTAMP NOT NULL | 创建时间 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |

约束：

- `UNIQUE(username, server_id)`。
- `expires_at` 必须晚于 `starts_at`。
- `billing_mode = download` 表示只计算下行；`both` 表示上行加下行。不得复用现有套餐的倍数算法。
- 授权服务器必须仍具备发布时要求的 Agent 能力；能力降级时停止新开通并告警，不能静默承诺无法兑现的限制。
- 管理员把 `max_active_nodes` 调低到当前选择数以下时默认返回冲突清单，不得随机停用用户节点；管理员确认具体停用项后再保存。

有效状态由后端计算，不单独持久化：

- `scheduled`：当前时间早于 `starts_at`。
- `active`：开关开启且在有效期内。
- `suspended`：管理员关闭授权。
- `expired`：超过 `expires_at`。
- `over_limit`：当前周期计费流量达到额度。
- `user_disabled`：用户账号被停用。

### 4.3 `user_node_selections`

记录用户在某个授权下选择的发布节点。用户取消开通时保留软删除记录，以便审计和续期开回原凭据。

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 选择记录 ID |
| `grant_id` | INTEGER NOT NULL | 所属服务器授权 |
| `offer_id` | INTEGER NOT NULL | 发布项 |
| `credential_config_id` | INTEGER NULL | 对应 `user_inbound_configs.id` |
| `access_source_id` | INTEGER NULL | 对应本次选择产生的访问来源 |
| `desired_enabled` | INTEGER NOT NULL DEFAULT 1 | 用户是否仍选择该节点 |
| `speed_limit_override_mbps` | REAL NULL | NULL 继承授权，0 显式不限 |
| `connection_limit_override` | INTEGER NULL | NULL 继承授权，0 显式不限 |
| `billing_mode_override` | TEXT NULL | NULL 继承授权 |
| `activated_at` | TIMESTAMP NULL | 最近一次远端确认启用 |
| `deactivated_at` | TIMESTAMP NULL | 最近一次远端确认停用 |
| `created_at` | TIMESTAMP NOT NULL | 首次选择时间 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |

约束：

- `UNIQUE(grant_id, offer_id)`；重复 POST 返回同一记录，不重复生成 UUID。
- grant 和 offer 的 `server_id` 必须一致。
- 普通用户不能写任何 override 字段；这些字段只允许管理员修改。

### 4.4 `user_inbound_access_sources`

一份远端 client 可能来自套餐、用户自助选择或待人工确认的存量数据。该表是来源感知回收的依据，避免一个来源失效时误删另一个来源仍需要的 client。

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | INTEGER PK | 来源 ID |
| `username` | TEXT NOT NULL | 用户名 |
| `server_id` | INTEGER NOT NULL | 服务器 |
| `inbound_tag` | TEXT NOT NULL | 物理 inbound |
| `node_id` | INTEGER NOT NULL | 对应节点 |
| `source_type` | TEXT NOT NULL | `package`、`selection` 或 `legacy_review` |
| `source_id` | INTEGER NOT NULL | 套餐、selection 或迁移记录 ID |
| `desired_state` | TEXT NOT NULL | `active`、`inactive` 或 `deleted` |
| `observed_state` | TEXT NOT NULL | `unknown`、`active` 或 `inactive` |
| `suspend_reason` | TEXT NOT NULL | `none/expired/quota_exceeded/admin_disabled/user_disabled` |
| `generation` | INTEGER NOT NULL DEFAULT 1 | 期望状态版本 |
| `applied_generation` | INTEGER NOT NULL DEFAULT 0 | Agent 已确认版本 |
| `retry_count` | INTEGER NOT NULL DEFAULT 0 | 重试次数 |
| `next_retry_at` | TIMESTAMP NULL | 下次重试时间 |
| `last_error` | TEXT NOT NULL DEFAULT '' | 脱敏错误摘要 |
| `starts_at` | TIMESTAMP NOT NULL | 来源生效时间 |
| `expires_at` | TIMESTAMP NULL | 来源到期时间 |
| `created_at` | TIMESTAMP NOT NULL | 创建时间 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |

约束：

- `UNIQUE(username, server_id, inbound_tag, node_id, source_type, source_id)`。
- 每次期望状态变化都必须在同一事务内递增 `generation` 并写审计。
- Worker 执行和回写前必须重新读取 generation；旧任务不得覆盖新状态。
- 远端 client 的最终期望状态按同一 `username + server_id + inbound_tag` 下所有来源求 OR；至少一个有效来源为 active 时就不能删除。

套餐分配为每个套餐节点物化 `package` 来源；自助开通写 `selection` 来源。升级时无法解释的存量 `user_inbound_configs` 写成 `legacy_review`，默认保活并在面板提示管理员确认。

### 4.5 `user_node_selection_usage`

授权流量按 selection 独立记账，再按 grant 汇总。不能重置共享的 `user_traffic`，否则会影响该用户在其他服务器或套餐中的流量。

| 字段 | 类型 | 说明 |
|---|---|---|
| `selection_id` | INTEGER PK | 节点选择 ID |
| `grant_id` | INTEGER NOT NULL | 授权 ID |
| `cycle_started_at` | TIMESTAMP NOT NULL | 当前计费周期开始 |
| `uplink_bytes` | INTEGER NOT NULL DEFAULT 0 | 当前周期上行 |
| `downlink_bytes` | INTEGER NOT NULL DEFAULT 0 | 当前周期下行 |
| `last_raw_uplink` | INTEGER NOT NULL DEFAULT 0 | 上次 Agent 原始计数游标 |
| `last_raw_downlink` | INTEGER NOT NULL DEFAULT 0 | 上次 Agent 原始计数游标 |
| `counter_epoch` | TEXT NOT NULL DEFAULT '' | Xray/client 计数代次 |
| `last_reset_at` | TIMESTAMP NULL | 最近重置时间 |
| `updated_at` | TIMESTAMP NOT NULL | 更新时间 |

流量采集必须按 `server_id + client email` 精确映射到 selection，再根据该 selection 的有效计费模式计算，最后汇总为 grant 使用量。不能把同一用户在服务器上的流量平均分摊给多个 inbound。取消选择不删除当期 usage，重新开通也不重置；只有周期重置才清零，避免用户通过反复开关逃避计费。

### 4.6 `managed_access_audit`

记录授权创建/续期/暂停/撤销、用户开通/取消、远端同步、限额触发和恢复。审计详情只保存 ID、状态和错误分类，不保存 UUID、密码、Token 或完整 Xray 配置。

## 5. 统一访问解析器

新增 `ManagedNodeAccessResolver`，作为以下路径唯一的授权事实来源：

- 用户节点列表和可开通目录。
- 用户订阅、短链和临时订阅生成。
- 节点配置/URI 输出。
- 用户自定义出站的节点访问校验。
- client reconciler 的期望状态判断。
- 流量额度和 limiter 规则生成。

一个自助节点可使用必须同时满足：

```text
用户启用
AND 发布项启用且物理节点启用
AND 授权 enabled
AND starts_at <= now < expires_at（或无 expires_at）
AND 未超授权流量额度
AND selection.desired_enabled
AND access_source.desired_state == active
AND access_source.observed_state == active（订阅输出要求）
```

套餐仍作为另一种访问来源。实际删除某个 `user_inbound_configs` 对应的远端 client 前，必须查询 `user_inbound_access_sources`；只有最后一个有效来源消失时才执行 `remove-client`。

首版对同一用户、同一发布节点的套餐/授权重叠采用以下规则：

- 已由有效套餐提供的节点在自助目录显示“套餐已包含”，禁止重复开通。
- 套餐分配若与现有自助选择冲突，API 返回冲突节点清单，管理员先选择保留哪一种来源。
- 这样避免同一份无法区分来源的流量被两个额度重复扣除。

## 6. API 契约

所有时间使用 RFC3339 UTC；所有响应继续使用项目现有 JSON 错误模型。

### 6.1 管理员 API

#### 发布节点

- `GET /api/admin/self-service-node-offers`
- `POST /api/admin/self-service-node-offers`
  - 请求：`{ "node_id": 123 }`
  - 后端解析并校验服务器和 inbound，不接受客户端传 `server_id` 或 `inbound_tag`。
- `PUT /api/admin/self-service-node-offers/{id}`
  - 请求：`{ "enabled": true, "sort_order": 10 }`
- `DELETE /api/admin/self-service-node-offers/{id}`
  - 有已选择用户时必须二次确认；本地先停权，再进入远端清理。

#### 用户服务器授权

- `GET /api/admin/users/{username}/server-grants`
- `POST /api/admin/users/{username}/server-grants`
- `PUT /api/admin/users/{username}/server-grants/{id}`
- `DELETE /api/admin/users/{username}/server-grants/{id}`
- `POST /api/admin/users/{username}/server-grants/{id}/retry`
- `GET /api/admin/users/{username}/managed-nodes`
- `PUT /api/admin/users/{username}/managed-nodes/{selection_id}/limits`

创建/更新授权请求：

```json
{
  "server_id": 12,
  "enabled": true,
  "starts_at": "2026-07-19T00:00:00Z",
  "expires_at": "2026-08-19T00:00:00Z",
  "max_active_nodes": 0,
  "speed_limit_mbps": 100,
  "connection_limit": 5,
  "traffic_limit_bytes": 107374182400,
  "billing_mode": "download",
  "reset_policy": "monthly",
  "reset_day": 1,
  "version": 1
}
```

`version` 不匹配返回 `409 Conflict`，防止两个管理页面互相覆盖。

### 6.2 用户 API

- `GET /api/user/managed-nodes`
  - 返回 `selected`、`catalog`、授权摘要、有效策略、`can_create` 和后端给出的禁止原因。
- `POST /api/user/managed-nodes`
  - 请求：`{ "offer_id": 45 }`
  - 幂等；创建中返回 `202 Accepted`，已存在返回 `200 OK`。
- `DELETE /api/user/managed-nodes/{selection_id}`
  - 立即从订阅排除；远端离线时返回已接受，派生状态显示为 `suspending`。
- `POST /api/user/managed-nodes/{selection_id}/retry`
  - 只允许重试本人的 `error`/`provisioning` 记录。

关键错误：

- `404`：发布项不可见、selection 不属于当前用户或授权服务器不匹配，避免资源枚举。
- `403`：账号被停用或角色不允许该操作。
- `409`：授权未生效/已过期、名额已满、重复计费来源冲突或并发版本冲突。
- `422`：管理员配置了服务器无法兑现的 managed-client、到期或 limiter 策略。

## 7. 开通与回收状态机

访问来源保存期望状态、观察状态和版本，用户界面状态由它们派生：

```text
desired=active   + observed=active   -> active
desired=active   + observed!=active  -> provisioning
desired=inactive + observed=active   -> suspending
desired=inactive + observed=inactive -> suspended
连续同步失败                          -> error
```

### 7.1 开通

1. 事务内再次校验用户、授权、时间、发布项、服务器归属、名额和唯一性。
2. 创建或恢复 selection 及其 access source，设置 `desired_state = active` 并递增 generation。
3. 复用 `getOrCreateInboundCredential`，凭据先持久化再发远端，保证重试使用同一 UUID/密码。
4. 先向 Agent 安装该 client 的限速和 `not_after` 拒绝策略；策略未确认时不能添加 client。
5. 通过 Agent 原子 `add-client`，命令携带稳定的 `operation_id + generation`；成功后写 `observed_state = active` 和 `applied_generation`。
6. 全量刷新该服务器 limiter 配置。
7. 只有派生状态为 active 的记录进入订阅；处理中不输出不可用配置。

服务器离线时首版允许保留派生状态 `provisioning` 并自动重试，但 UI 必须明确显示“等待服务器上线”，不能显示已开通。

### 7.2 取消、到期、超额和暂停

1. 本地先令授权或 selection 失效，订阅和 API 立即过滤。
2. access source 变为 `desired_state = inactive`，设置原因并递增 generation。
3. 统一访问解析器确认没有其他有效来源后，Agent 原子 `remove-client`。
4. 删除 client 前触发一次最终流量采集；成功后写 `observed_state = inactive`，失败保存脱敏错误并指数退避重试。
5. 不删除 `user_inbound_configs`，保留凭据供续期恢复；用户永久删除时才最终清理。
6. 续期、解除暂停或重置额度后，仍为 `desired_enabled = 1` 的记录自动回到 `provisioning` 并恢复原凭据。

### 7.3 Reconciler

- 启动时立即跑一次，之后每 15 秒处理 `generation != applied_generation` 和待重试记录。
- Agent 连接成功后按 `server_id` 立即触发一次，不等待 ticker。
- 重试退避建议为 5 秒、15 秒、30 秒、1 分钟、5 分钟，之后固定 10 分钟。
- 每次操作都按 `username + server_id + inbound_tag` 串行；数据库唯一键负责凭据竞争，Agent 按 `operation_id + generation` 幂等。
- 所有 API 同步执行权限检查；reconciler 只负责让远端状态追上本地期望状态。
- Agent 必须持久化每个 client 的 `not_after`，即使主控失联也要在到期时本地拒绝或移除；否则无法承诺严格到期。该值按同一 client 的所有有效来源计算：有长期来源时为空，否则取最晚到期时间。
- 多主控场景不能只依赖当前进程内 `sync.Map` 凭据锁；插入凭据必须依赖数据库唯一键，冲突后重新读取获胜记录。

## 8. 流量、限速和额度

### 8.1 计费定义

- `download`：`billed = downlink_bytes`。
- `both`：`billed = uplink_bytes + downlink_bytes`。
- 不再使用现有套餐的 `TrafficMultiplier()`；当前“先上行加下行、twoway 再乘 2”的实现不适用于本功能。

### 8.2 精确归因

- 继续使用 `<username>__<inbound_tag>` client email，但记账时优先通过 `credential_config_id/server_id/email` 直接查 selection，不靠拆字符串猜测。
- 当前流量归因器会在同用户同服务器的多个 inbound 间均分某些 email；自助授权计费必须改为按 credential 的 Tag 精确命中。
- 为每次 client 重建或 Xray 重启记录计数 epoch/游标；原始计数回落时不能一直等待超过旧值，否则续期后会漏计。
- grant usage 只接收采集增量，不直接读取可被套餐重置的共享 `user_traffic`。
- 新开通以当前累计值建立计费游标；用户取消再恢复同一节点不得刷新周期用量，避免通过反复删除逃避计费。
- 计费模式在当前周期内固定；管理员修改时只能选择“下周期生效”或“立即结束并开启新周期”。
- 月度周期保存绝对 `next_reset_at` 和时区，主控跨月停机后只补重置一次。
- 若要求严格流量封顶，Agent 也要获得剩余额度并本地拒绝；仅靠分钟级采集一定存在少量超额窗口。

### 8.3 限制优先级

```text
selection override
  > server grant default
  > existing user global override
  > 0（不限）
```

套餐节点继续使用现有套餐优先级，不交叉继承授权值。

现有 `device_limit` 实际含义是并发连接数，新界面和 API 统一命名为“并发连接数”，不能宣传为唯一设备数。

limiter 下发必须是服务器全量 replace。即使某服务器最终规则数为 0，也必须向 Agent 下发空集合清除旧规则；当前空配置直接 return 的行为需要修正。

## 9. 前端设计

### 9.1 管理员

- 不新增顶层导航。
- “用户管理”每个普通用户增加“服务器授权”图标入口。
- 宽弹窗使用两个 Tab：`服务器授权`、`已开通节点`。
- 授权列表展示服务器在线状态、可发布节点数、有效期、名额、速率、并发、额度、计费方向及同步异常。
- 到期显示“续期”；暂停和撤权明确显示会影响的节点数量。
- “已开通节点”允许管理员设置 selection 级覆盖和手动重试。
- 管理员节点编辑增加“允许获授权用户自助开通”开关；不满足发布条件时禁用并显示具体原因。

### 9.2 普通用户

- 继续使用“节点管理”，增加 `我的节点` / `可开通节点` 分段控制。
- `我的节点` 显示 active、等待开通、已到期、清理待连接和失败状态。
- `可开通节点` 按授权服务器筛选，展示服务器、节点、协议、授权到期时间和有效策略。
- 用户点击“开通”只提交 `offer_id`；取消开通需要确认。
- 服务器离线、授权未生效/过期、名额已满或节点已取消发布时，按钮禁用且原因由后端返回。
- 已到期节点禁止复制配置并从订阅排除；续期后自动恢复时显示同步进度。

建议新增：

- `frontend/src/server-grants.tsx`
- `frontend/src/server-grants.css`
- `frontend/src/self-service-nodes.tsx`
- 对应单元测试文件

避免继续扩大现有较大的 `nodes-workbench.tsx` 和 `users-workbench.tsx`。

## 10. 必须先修的安全与兼容问题

1. 普通用户当前批量导入时可提交 `inbound_tag`，且 Host 匹配会自动认领受管服务器。普通用户导入必须强制清空 `original_server/inbound_tag`，不能伪造受管节点。
2. 普通用户节点凭据替换失败时，当前可能保留管理员配置。所有非管理员输出必须改成 fail closed。
3. `/api/admin/remote/inbounds` 保持管理员专用，不能通过改中间件直接开放。
4. 套餐到期/超额和用户停用目前会遍历并删除全部 `user_inbound_configs` client。必须改为经统一访问解析器按来源回收。
5. 普通用户节点列表、订阅生成、短链和出站校验目前分别实现套餐判断，必须统一，否则会出现页面可见但订阅不可用或反向绕过。
6. limiter 最后一条规则删除后必须向 Agent 发送空配置，避免旧限速规则残留。
7. 任何错误日志和审计不得包含 client credential、Agent token 或完整 inbound JSON。
8. 已发布 inbound 不允许原地修改协议；当前凭据复用路径在协议变化时可能生成与数据库不一致的新凭据，必须先撤销发布并显式迁移。
9. SQLite 当前没有为每个连接启用 `PRAGMA foreign_keys=ON`；在依赖级联约束前必须先清理孤儿数据并启用该 pragma，或由 repository 显式按顺序删除。

## 11. 实施顺序

### A. 权限与数据底座

- 修复普通用户受管节点认领和凭据回退漏洞。
- 新增发布项、授权、选择、访问来源、授权用量和审计表及 repository 单元测试。
- 新增发布项校验和统一访问解析器。

### B. 管理闭环

- 实现发布项与授权管理员 API。
- 实现“服务器授权”弹窗和节点发布开关。
- 加入审计和 optimistic version 检查。

### C. 用户自助闭环

- 实现用户目录、开通、取消和重试 API。
- 接入原子 add/remove client 与持久化状态机。
- 实现普通用户节点页两个视图。

### D. 全路径接入

- 节点列表、订阅、短链、URI 和出站校验全部改用统一访问解析器。
- 套餐回收、用户停用和用户删除改用来源感知的 reconciler。
- 修复 limiter 空配置清理。

### E. 计费与生命周期

- 接入精确 email 归因和 grant usage ledger。
- 实现 `download/both` 额度判定、月度重置和超额恢复。
- Agent 重连即时 reconcile，并处理 client/Xray 计数 epoch。

## 12. 验收矩阵

必须自动化覆盖：

1. 未授权用户无法看到或开通任何发布节点。
2. A 服务器授权不能用于 B 服务器节点，包括伪造请求。
3. 并发重复开通只生成一份凭据和一个远端 client。
4. 一个用户和另一个用户开通同节点时凭据完全隔离。
5. 到期后 API/订阅立即失效；Agent 在线时 client 被移除。
6. Agent 离线到期后派生状态为 `suspending`，重连后自动清理并变为 `suspended`。
7. 续期恢复原 UUID，不产生相同 email 的重复 client。
8. 用户取消一个节点不会删除其他用户或同用户其他节点的 client。
9. 套餐和授权来源互不误删；重叠时按首版冲突规则拒绝。
10. `download` 只计算下行，`both` 计算上下行之和，月度重置只影响对应 grant。
11. 限速优先级正确；删除最后一条规则后 Agent 旧规则被清空。
12. 非 embedded 服务器不能保存无法兑现的限速策略。
13. 普通用户导入节点不能伪造 `server_id/original_server/inbound_tag`。
14. 所有普通用户配置输出在凭据缺失或替换失败时过滤节点，不泄露管理员凭据。
15. 管理端和用户端在桌面及移动端覆盖加载、空数据、错误、离线、到期、处理中和失败状态。
16. DB 提交后宕机、Agent 执行后 ACK 丢失、ACK 后主控宕机以及旧 generation 乱序回包，重放后都收敛到最新期望状态。
17. 主控离线跨过到期时刻，Agent 仍按 `not_after` 本地拒绝；主控恢复后完成最终清理。

## 13. 上线判定

首版只有同时满足以下条件才允许部署：

- 数据迁移可在现有 SQLite 数据库上幂等执行并可回滚二进制。
- Go 单元/集成测试、前端类型检查/单测和关键 Playwright 流程全部通过。
- 两台 Agent 分别完成在线开通、离线回收、重连恢复和 limiter 清空验证。
- 生产订阅中只出现有效且凭据替换成功的自助节点。
- 数据库、日志、审计和前端响应中不存在管理员原始凭据泄露。
