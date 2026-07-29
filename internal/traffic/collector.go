package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// XrayMetrics 表示来自 Xray 的 /debug/vars 端点的指标响应
type XrayMetrics struct {
	Stats *XrayStats `json:"stats,omitempty"`
}

// XrayStats 包含入站、出站和用户流量统计信息
type XrayStats struct {
	Inbound  map[string]TrafficData `json:"inbound,omitempty"`
	Outbound map[string]TrafficData `json:"outbound,omitempty"`
	User     map[string]TrafficData `json:"user,omitempty"`
}

// TrafficData 包含上行链路和下行链路流量（以字节为单位）
type TrafficData struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

// XrayConfig 表示 xray config.json 的结构，用于读取 metrics 端口
type XrayConfig struct {
	Metrics *MetricsConfig `json:"metrics,omitempty"`
}

// MetricsConfig 表示 xray 配置中的指标部分
type MetricsConfig struct {
	Tag    string `json:"tag,omitempty"`
	Listen string `json:"listen,omitempty"`
}

// ServerSpeed 保存服务器的实时速度数据
type ServerSpeed struct {
	UploadSpeed   int64     // 字节/秒
	DownloadSpeed int64     // 字节/秒
	UpdatedAt     time.Time // 最后更新时间
}

// serverTrafficSnapshot 保存流量快照以进行速度计算
type serverTrafficSnapshot struct {
	uplink     int64
	downlink   int64
	sampleTime time.Time
}

// 收集器从 Xray 服务器收集流量数据
type Collector struct {
	repo               *storage.TrafficRepository
	httpClient         *http.Client
	interval           time.Duration
	speedInterval      time.Duration
	defaultMetricsPort int
	defaultMetricsHost string

	OnServerOffline func(ctx context.Context, serverName, ip string)

	// 已激活的 ticker 引用,用于支持 hot-reload(系统设置改 interval 时立即生效)。
	// 由 Start 内部赋值, SetInterval / SetSpeedInterval 在已运行时会 Reset。
	tickerMu      sync.Mutex
	tickerTraffic *time.Ticker
	tickerSpeed   *time.Ticker

	// 本地服务器的速度跟踪
	speedMu      sync.RWMutex
	serverSpeeds map[int64]*ServerSpeed           // serverID -> 速度数据
	lastTraffic  map[int64]*serverTrafficSnapshot // serverID -> 最后的流量快照

	// xray 重启检测器 — 用 agent 上报的 xray_boot_time 判定真重启,替代 new<last 启发式。
	// 历史 BUG 来源:启发式把 client 增删导致的 user counter reset 误判为 xray 重启
	// → user_email_traffic.total_downlink 渐进累积偏移(实测 382MB)。
	restartDetector *XrayRestartDetector
}

// 创建一个新的流量收集器
func NewCollector(repo *storage.TrafficRepository) *Collector {
	return &Collector{
		repo:               repo,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		interval:           1 * time.Minute,
		speedInterval:      3 * time.Second,
		defaultMetricsPort: 38889,       // 配置模板中的默认指标端口
		defaultMetricsHost: "127.0.0.1", // 默认指标主机
		restartDetector:    NewXrayRestartDetector(),
		serverSpeeds:       make(map[int64]*ServerSpeed),
		lastTraffic:        make(map[int64]*serverTrafficSnapshot),
	}
}

// SetInterval 设置 traffic 采集间隔。如果 Start() 已在跑,会立即 Reset ticker(hot-reload)。
func (c *Collector) SetInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	c.interval = interval
	c.tickerMu.Lock()
	if c.tickerTraffic != nil {
		c.tickerTraffic.Reset(interval)
	}
	c.tickerMu.Unlock()
}

// SetSpeedInterval 同 SetInterval,作用于 speed 采集 ticker。
func (c *Collector) SetSpeedInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}
	c.speedInterval = interval
	c.tickerMu.Lock()
	if c.tickerSpeed != nil {
		c.tickerSpeed.Reset(interval)
	}
	c.tickerMu.Unlock()
}

// 开始流量收集循环
func (c *Collector) Start(ctx context.Context) {
	log.Printf("[Traffic Collector] Starting with interval: %v", c.interval)

	// 开始后立即收集
	c.collectAll(ctx)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	c.tickerMu.Lock()
	c.tickerTraffic = ticker
	c.tickerMu.Unlock()
	defer func() {
		c.tickerMu.Lock()
		c.tickerTraffic = nil
		c.tickerMu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[Traffic Collector] Stopping...")
			return
		case <-ticker.C:
			c.collectAll(ctx)
		}
	}
}

// offlineThreshold 返回标记 server 离线的"心跳过期"阈值。
// 默认 90s — agent heartbeat 间隔 30s + 容忍 2 次延迟。原来硬编码 60s 太严格,只容 1 次,
// 国际线路 1-2s 抖动就触发 offline → 立刻又 online → 用户被 spam 通知。
// 通过 RELAYDOCK_OFFLINE_THRESHOLD_SECONDS 环境变量覆盖,值 < 30s 时回退默认避免低于心跳间隔。
func offlineThreshold() time.Duration {
	const defaultThreshold = 90 * time.Second
	if v := os.Getenv("RELAYDOCK_OFFLINE_THRESHOLD_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 30 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultThreshold
}

// 收集所有活动服务器的流量
func (c *Collector) collectAll(ctx context.Context) {
	// 首先，检查并标记离线远程服务器(阈值由 offlineThreshold 控制,默认 90s)。
	// 注意:MarkOffline 只改状态 + 记 offline_since,**不在这里直接发通知**。
	if _, err := c.repo.MarkOfflineRemoteServers(ctx, offlineThreshold()); err != nil {
		log.Printf("[Traffic Collector] Failed to mark offline servers: %v", err)
	}
	// 下线通知走"容忍阈值"防抖:离线持续满 tolerance 秒(且本周期没通知过)才发。阈值内又上线的
	// (抖动 / 主控升级重启后 agent 快速重连)其 offline_since 已被重连清空,永远走不到这里 → 一条不发。
	// 这是覆盖"主控重启刷通知"的关键:重启后 offline_since 从检测时刻重新计时,agent 阈值内重连即静默。
	tolerance := time.Duration(c.repo.GetServerNotifyToleranceSeconds(ctx)) * time.Second
	if toNotify, err := c.repo.TakeOfflineServersToNotify(ctx, tolerance); err != nil {
		log.Printf("[Traffic Collector] Failed to take offline servers to notify: %v", err)
	} else if c.OnServerOffline != nil {
		for _, s := range toNotify {
			c.OnServerOffline(ctx, s.Name, s.IP)
		}
	}

	// 从需要拉模式（显式拉模式或回退模式）的远程服务器收集
	remoteServers, err := c.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[Traffic Collector] Failed to list remote servers: %v", err)
		return
	}

	for _, remote := range remoteServers {
		if remote.Status == storage.RemoteServerStatusOffline && c.repo.ShouldUsePullMode(remote) {
			continue
		}
		if c.repo.ShouldUsePullMode(remote) {
			if err := c.CollectFromRemoteServer(ctx, remote); err != nil {
				log.Printf("[Traffic Collector] Failed to pull from remote server %s (%d): %v", remote.Name, remote.ID, err)
			}
		} else {
			c.checkAndTriggerFallback(ctx, remote)
		}
	}
}

// 检查服务器是否应回退到拉取模式
func (c *Collector) checkAndTriggerFallback(ctx context.Context, server storage.RemoteServer) {
	// 如果没有可用的拉取配置则跳过
	if server.PullAddress == "" || server.PullPort == 0 {
		return
	}

	// 如果已处于拉模式则跳过
	if server.FallbackToPull {
		return
	}

	// 检查最后一次心跳是否太旧（超过5分钟）
	offlineThreshold := 5 * time.Minute
	if server.LastHeartbeat == nil || time.Since(*server.LastHeartbeat) > offlineThreshold {
		// 增加失败计数并检查回退
		fallback, err := c.repo.IncrementRemoteServerPushFailCount(ctx, server.ID, 3) // 连续 3 次失败触发回退
		if err != nil {
			log.Printf("[Traffic Collector] Failed to increment push fail count for server %s: %v", server.Name, err)
			return
		}
		if fallback {
			log.Printf("[Traffic Collector] Server %s has been offline too long, fallback to pull mode", server.Name)
		}
	}
}

// 从 xray 配置文件中读取指标端口（子服务器模式使用）
func (c *Collector) GetMetricsPortFromConfig(configPath string) (string, int, error) {
	if configPath == "" {
		return "127.0.0.1", c.defaultMetricsPort, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "127.0.0.1", c.defaultMetricsPort, fmt.Errorf("read config file: %w", err)
	}

	var config XrayConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return "127.0.0.1", c.defaultMetricsPort, fmt.Errorf("parse config file: %w", err)
	}

	if config.Metrics == nil || config.Metrics.Listen == "" {
		return "", 0, fmt.Errorf("metrics not configured in xray config")
	}

	listen := config.Metrics.Listen
	host := "127.0.0.1"
	var port int

	if strings.Contains(listen, ":") {
		parts := strings.Split(listen, ":")
		if len(parts) == 2 {
			if parts[0] != "" {
				host = parts[0]
			}
			p, err := strconv.Atoi(parts[1])
			if err != nil {
				return "", 0, fmt.Errorf("invalid metrics port: %s", parts[1])
			}
			port = p
		}
	} else {
		p, err := strconv.Atoi(listen)
		if err != nil {
			return "", 0, fmt.Errorf("invalid metrics listen format: %s", listen)
		}
		port = p
	}

	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid metrics port: %d", port)
	}

	return host, port, nil
}

// 从 Xray 的 /debug/vars 端点获取指标
func (c *Collector) FetchMetrics(host string, port int) (*XrayMetrics, error) {
	url := fmt.Sprintf("http://%s:%d/debug/vars", host, port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var metrics XrayMetrics
	if err := json.Unmarshal(body, &metrics); err != nil {
		return nil, fmt.Errorf("unmarshal metrics: %w", err)
	}

	return &metrics, nil
}

// 处理并存储收集的指标
func (c *Collector) ProcessMetrics(ctx context.Context, serverID int64, metrics *XrayMetrics) error {
	if metrics == nil || metrics.Stats == nil {
		log.Printf("[Traffic Collector] No stats in metrics for server %d", serverID)
		return nil
	}

	stats := metrics.Stats

	// 计算总流量以进行速度计算
	var totalUplink, totalDownlink int64
	for _, data := range stats.Inbound {
		totalUplink += data.Uplink
		totalDownlink += data.Downlink
	}

	// 计算和更新速度
	c.updateServerSpeed(serverID, totalUplink, totalDownlink)

	// 本地 server(主控自跑 xray)— 没有 xray_boot_time 上报路径,boot 信息不可得 →
	// 退化成"非重启"路径(detector 看 nil 返回 false),用 max(0, new-last) 算 delta 不污染 total。
	isRestart := c.restartDetector.CheckAndUpdate(serverID, nil)

	// 处理入站流量
	for tag, data := range stats.Inbound {
		if err := c.repo.UpsertNodeTraffic(ctx, serverID, tag, "inbound", data.Uplink, data.Downlink, isRestart); err != nil {
			log.Printf("[Traffic Collector] Failed to upsert inbound traffic for %s: %v", tag, err)
		}
	}

	// 处理出站流量
	for tag, data := range stats.Outbound {
		if err := c.repo.UpsertNodeTraffic(ctx, serverID, tag, "outbound", data.Uplink, data.Downlink, isRestart); err != nil {
			log.Printf("[Traffic Collector] Failed to upsert outbound traffic for %s: %v", tag, err)
		}
	}

	// 处理用户流量。
	// xray stats 的 key 是 email,可能是:
	//   - 主账号 email(== RelayDock username),直接落库
	//   - 子账号 email(<username>__<routed_label>),通过 user_subaccounts 反查归到 username
	//   - _admin__ 前缀的占位 client,流量丢弃(管理员测试用,不属任何用户)
	aggregateAndUpsertUserTraffic(ctx, c.repo, serverID, stats.User, isRestart)

	log.Printf("[Traffic Collector] Processed metrics for server %d: %d inbounds, %d outbounds, %d users",
		serverID, len(stats.Inbound), len(stats.Outbound), len(stats.User))

	return nil
}

// 处理从远程服务器报告的指标
//
// xrayBootTime 来自 remote_servers 表(agent 心跳上报),用于判定 xray 是否真重启。
// 调用方传 nil 等价"未知" → 退化到"非重启"路径,Upsert* 用 max(0, new-last) 算 delta 不污染 total。
func (c *Collector) ProcessRemoteMetrics(ctx context.Context, serverID int64, stats *XrayStats, xrayBootTime *time.Time) error {
	if stats == nil {
		return nil
	}

	isRestart := c.restartDetector.CheckAndUpdate(serverID, xrayBootTime)

	// 处理入站流量
	for tag, data := range stats.Inbound {
		if err := c.repo.UpsertNodeTraffic(ctx, serverID, tag, "inbound", data.Uplink, data.Downlink, isRestart); err != nil {
			log.Printf("[Traffic Collector] Failed to upsert remote inbound traffic for %s: %v", tag, err)
		}
	}

	// 处理出站流量
	for tag, data := range stats.Outbound {
		if err := c.repo.UpsertNodeTraffic(ctx, serverID, tag, "outbound", data.Uplink, data.Downlink, isRestart); err != nil {
			log.Printf("[Traffic Collector] Failed to upsert remote outbound traffic for %s: %v", tag, err)
		}
	}

	// 用户流量同上 — 必须先按 username 聚合
	aggregateAndUpsertUserTraffic(ctx, c.repo, serverID, stats.User, isRestart)

	log.Printf("[Traffic Collector] Processed remote metrics for server %d: %d inbounds, %d outbounds, %d users",
		serverID, len(stats.Inbound), len(stats.Outbound), len(stats.User))

	return nil
}

// aggregateAndUpsertUserTraffic 把 stats.User(key=email)里所有归到同一 username 的 cumulative 计数器加总,
// 然后只对每个 username 调一次 UpsertUserTraffic。cumulative 计数器之和仍是 cumulative(每个组件计数器自身单调
// 递增),delta 计算照常成立。
//
// 同时**并行双写** user_email_traffic — 保留 email 维度,供前端 drilldown 看"用户每个节点的流量"。
// 老 user_traffic 是套餐扣减热路径,继续按 username 聚合;新表是 email 细分,只用于细粒度展示。
func aggregateAndUpsertUserTraffic(ctx context.Context, repo userTrafficRepo, serverID int64, userStats map[string]TrafficData, isXrayRestarted bool) {
	type sum struct{ uplink, downlink int64 }
	byUsername := make(map[string]*sum)
	for emailKey, data := range userStats {
		// 双写新表 — email 维度原样保留,即使 ResolveUsernameByEmail 解析不到 username 也写
		// (野 client 也算"该 server 的 email 流量",前端可显示成"未识别节点")
		if err := repo.UpsertUserEmailTraffic(ctx, serverID, emailKey, data.Uplink, data.Downlink, isXrayRestarted); err != nil {
			log.Printf("[Traffic Collector] Failed to upsert user email traffic for %s on server %d: %v", emailKey, serverID, err)
		}

		username := repo.ResolveUsernameByEmail(ctx, emailKey)
		if username == "" {
			continue
		}
		if s, ok := byUsername[username]; ok {
			s.uplink += data.Uplink
			s.downlink += data.Downlink
		} else {
			byUsername[username] = &sum{uplink: data.Uplink, downlink: data.Downlink}
		}
	}
	for username, s := range byUsername {
		if err := repo.UpsertUserTraffic(ctx, serverID, username, s.uplink, s.downlink, isXrayRestarted); err != nil {
			log.Printf("[Traffic Collector] Failed to upsert user traffic for %s on server %d: %v", username, serverID, err)
		}
	}
}

// userTrafficRepo 只取 collector 实际用到的方法,避免去 import 整个 storage 接口
type userTrafficRepo interface {
	ResolveUsernameByEmail(ctx context.Context, email string) string
	UpsertUserTraffic(ctx context.Context, serverID int64, username string, uplink, downlink int64, isXrayRestarted bool) error
	UpsertUserEmailTraffic(ctx context.Context, serverID int64, email string, uplink, downlink int64, isXrayRestarted bool) error
}

// 为所有服务器创建每日快照
func (c *Collector) CreateDailySnapshots(ctx context.Context) error {
	remoteServers, err := c.repo.ListRemoteServers(ctx)
	if err != nil {
		return fmt.Errorf("list remote servers: %w", err)
	}

	date := time.Now().Format("2006-01-02")
	for _, rs := range remoteServers {
		if err := c.repo.CreateTrafficSnapshot(ctx, rs.ID, date); err != nil {
			log.Printf("[Traffic Collector] Failed to create snapshot for server %s: %v", rs.Name, err)
		}
		if err := c.repo.CreateNodeTrafficSnapshots(ctx, rs.ID, date); err != nil {
			log.Printf("[Traffic Collector] Failed to create node snapshot for server %s: %v", rs.Name, err)
		}
		if err := c.repo.CreateUserTrafficSnapshots(ctx, rs.ID, date); err != nil {
			log.Printf("[Traffic Collector] Failed to create user snapshot for server %s: %v", rs.Name, err)
		}
		// email 级快照 — 节点详情/用户详情按时间范围算"用户在某节点的增量"时减它的 baseline。
		if err := c.repo.CreateUserEmailTrafficSnapshots(ctx, rs.ID, date); err != nil {
			log.Printf("[Traffic Collector] Failed to create user-email snapshot for server %s: %v", rs.Name, err)
		}
		// Server system traffic baseline — server 视图 traffic_source='system' 模式下今日/本周/本月按钮算增量用。
		// 即便该 server 当前 source='xray' 也照拍 — 用户后续切到 system 时,已有 baseline 可用。
		if err := c.repo.CreateServerSystemTrafficSnapshot(ctx, rs.ID, date); err != nil {
			log.Printf("[Traffic Collector] Failed to create server system snapshot for server %s: %v", rs.Name, err)
		}
	}

	log.Printf("[Traffic Collector] Created daily snapshots for %d servers", len(remoteServers))
	return nil
}

// 删除旧快照
func (c *Collector) CleanOldData(ctx context.Context, days int) error {
	if err := c.repo.CleanOldSnapshots(ctx, days); err != nil {
		return fmt.Errorf("clean old snapshots: %w", err)
	}
	log.Printf("[Traffic Collector] Cleaned snapshots older than %d days", days)
	return nil
}

// 以拉取模式从远程服务器拉取流量数据
func (c *Collector) CollectFromRemoteServer(ctx context.Context, server storage.RemoteServer) error {
	// 历史 BUG:这里原本是 `ConnectionMode != Pull`,但上游 collectAll 用 ShouldUsePullMode
	// 判断(auto + FallbackToPull = true 也返回 true)→ 两端语义不一致,
	// 导致 auto 模式 server fallback 到 pull 后,master 实际从未真 pull,
	// last_heartbeat 也不更新 → 60s 阈值频繁标 OFFLINE,只能等 agent 偶尔 WS 上来补一刀心跳。
	// 跟 PullSpeedFromRemoteServer(只看 PullAddress/Port)对齐成"ShouldUsePullMode 一刀切"。
	if !c.repo.ShouldUsePullMode(server) {
		return nil
	}

	if server.PullAddress == "" || server.PullPort == 0 {
		return fmt.Errorf("pull address or port not configured for server %s", server.Name)
	}

	url := fmt.Sprintf("http://%s:%d/api/child/traffic", server.PullAddress, server.PullPort)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// 添加身份验证令牌（首选 PullToken，回退到 Token）
	authToken := server.PullToken
	if authToken == "" {
		authToken = server.Token
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	// 解析响应
	var response struct {
		Success bool       `json:"success"`
		Stats   *XrayStats `json:"stats,omitempty"`
		Error   string     `json:"error,omitempty"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("remote server error: %s", response.Error)
	}

	// pull 成功本身就是一次有效"心跳"信号 — agent 还活着才能回 200。
	// 跟 remote_ws.go:904 同款,更新 last_heartbeat,让 MarkOfflineRemoteServers 看到活跃。
	// 之前 pull 路径漏调这一步 → fallback 期间 last_heartbeat 不更新 → 60s 阈值仍标 OFFLINE。
	// 注意 stats==nil 也算心跳(无流量但 agent 在线),所以放在 nil 检查之前。
	if _, _, _, _, err := c.repo.UpdateRemoteServerLastActivity(ctx, server.ID); err != nil {
		log.Printf("[Traffic Collector] Failed to update last activity for server %s after pull: %v", server.Name, err)
	}

	if response.Stats == nil {
		log.Printf("[Traffic Collector] No stats from remote server %s", server.Name)
		return nil
	}

	// 处理指标 — server 对象已含 XrayBootTime,直接传给 ProcessRemoteMetrics 做重启判定
	if err := c.ProcessRemoteMetrics(ctx, server.ID, response.Stats, server.XrayBootTime); err != nil {
		return fmt.Errorf("process metrics: %w", err)
	}

	// 更新上次拉取时间戳
	if err := c.repo.UpdateRemoteServerLastPull(ctx, server.ID); err != nil {
		log.Printf("[Traffic Collector] Failed to update last pull time for server %s: %v", server.Name, err)
	}

	log.Printf("[Traffic Collector] Pulled traffic from remote server %s: %d inbounds, %d outbounds, %d users",
		server.Name, len(response.Stats.Inbound), len(response.Stats.Outbound), len(response.Stats.User))

	return nil
}

// 启动拉模式服务器的速度收集循环
func (c *Collector) StartSpeedCollection(ctx context.Context) {
	ticker := time.NewTicker(c.speedInterval)
	defer ticker.Stop()
	c.tickerMu.Lock()
	c.tickerSpeed = ticker
	c.tickerMu.Unlock()
	defer func() {
		c.tickerMu.Lock()
		c.tickerSpeed = nil
		c.tickerMu.Unlock()
	}()

	log.Printf("[Speed Collector] Starting speed collection with %v interval", c.speedInterval)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[Speed Collector] Stopping...")
			return
		case <-ticker.C:
			c.collectSpeedFromPullServers(ctx)
		}
	}
}

// 使用拉模式从所有服务器收集速度
func (c *Collector) collectSpeedFromPullServers(ctx context.Context) {
	remoteServers, err := c.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[Speed Collector] Failed to list remote servers: %v", err)
		return
	}

	for _, remote := range remoteServers {
		// 跳过离线服务器以避免日志垃圾邮件
		if remote.Status == storage.RemoteServerStatusOffline {
			continue
		}
		// 仅使用拉模式从服务器收集
		if c.repo.ShouldUsePullMode(remote) {
			if err := c.PullSpeedFromRemoteServer(ctx, remote); err != nil {
				log.Printf("[Speed Collector] Failed to pull speed from server %s: %v", remote.Name, err)
			}
		}
	}
}

// 从远程服务器拉取速度数据
func (c *Collector) PullSpeedFromRemoteServer(ctx context.Context, server storage.RemoteServer) error {
	if server.PullAddress == "" || server.PullPort == 0 {
		return fmt.Errorf("pull address or port not configured for server %s", server.Name)
	}

	url := fmt.Sprintf("http://%s:%d/api/child/speed", server.PullAddress, server.PullPort)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// 添加身份验证令牌（首选 PullToken，回退到 Token）
	authToken := server.PullToken
	if authToken == "" {
		authToken = server.Token
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	// 解析响应
	var response struct {
		Success       bool   `json:"success"`
		UploadSpeed   int64  `json:"upload_speed"`
		DownloadSpeed int64  `json:"download_speed"`
		Error         string `json:"error,omitempty"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("remote server error: %s", response.Error)
	}

	// 数据库更新速度
	if err := c.repo.UpdateRemoteServerSpeed(ctx, server.ID, response.UploadSpeed, response.DownloadSpeed); err != nil {
		return fmt.Errorf("update speed: %w", err)
	}

	log.Printf("[Speed Collector] Pulled speed from server %s: ↑%d B/s ↓%d B/s",
		server.Name, response.UploadSpeed, response.DownloadSpeed)

	return nil
}

// 计算并更新本地服务器的速度
func (c *Collector) updateServerSpeed(serverID int64, currentUplink, currentDownlink int64) {
	c.speedMu.Lock()
	defer c.speedMu.Unlock()

	now := time.Now()

	last, exists := c.lastTraffic[serverID]

	// 更新最后的流量快照
	c.lastTraffic[serverID] = &serverTrafficSnapshot{
		uplink:     currentUplink,
		downlink:   currentDownlink,
		sampleTime: now,
	}

	// 如果我们有以前的数据，计算速度
	if exists && !last.sampleTime.IsZero() {
		elapsed := now.Sub(last.sampleTime).Seconds()
		if elapsed > 0 {
			// 计算字节差
			uplinkDiff := currentUplink - last.uplink
			downlinkDiff := currentDownlink - last.downlink

			// 处理计数器重置（如果重新启动 xray）
			if uplinkDiff < 0 {
				uplinkDiff = currentUplink
			}
			if downlinkDiff < 0 {
				downlinkDiff = currentDownlink
			}

			uploadSpeed := int64(float64(uplinkDiff) / elapsed)
			downloadSpeed := int64(float64(downlinkDiff) / elapsed)

			c.serverSpeeds[serverID] = &ServerSpeed{
				UploadSpeed:   uploadSpeed,
				DownloadSpeed: downloadSpeed,
				UpdatedAt:     now,
			}
		}
	}
}

// 返回本地服务器的当前速度
func (c *Collector) GetServerSpeed(serverID int64) *ServerSpeed {
	c.speedMu.RLock()
	defer c.speedMu.RUnlock()

	if speed, exists := c.serverSpeeds[serverID]; exists {
		// 返回副本以避免竞争条件
		return &ServerSpeed{
			UploadSpeed:   speed.UploadSpeed,
			DownloadSpeed: speed.DownloadSpeed,
			UpdatedAt:     speed.UpdatedAt,
		}
	}
	return nil
}

// 返回所有本地服务器的速度
func (c *Collector) GetAllServerSpeeds() map[int64]*ServerSpeed {
	c.speedMu.RLock()
	defer c.speedMu.RUnlock()

	result := make(map[int64]*ServerSpeed)
	for id, speed := range c.serverSpeeds {
		result[id] = &ServerSpeed{
			UploadSpeed:   speed.UploadSpeed,
			DownloadSpeed: speed.DownloadSpeed,
			UpdatedAt:     speed.UpdatedAt,
		}
	}
	return result
}
