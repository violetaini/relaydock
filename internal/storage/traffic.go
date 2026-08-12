package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/secretbox"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// parseNullTimeString 将 sql.NullString 解析为 *time.Time。
// Modernc.org/sqlite 将 time.Time 存储为 RFC3339 字符串，sql.NullTime 无法直接扫描。
func parseNullTimeString(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
	} {
		if t, err := time.Parse(layout, ns.String); err == nil {
			return &t
		}
	}
	return nil
}

const (
	pragmaJournalMode = "PRAGMA journal_mode=WAL;"

	// DSN 中嵌入的 per-connection pragma — modernc.org/sqlite 在 sql.Open 解析 file: URI 时
	// 把每条 _pragma 装进新连接的 init 钩子,新 conn 拿来时自动跑。原来 SetMaxOpenConns(1) +
	// 单次 db.Exec(pragmaJournalMode) 够用,改成多连接(L3:防 token 复用引爆的 DB 写脉冲
	// 饿死无关 server)后必须每 conn 都设 busy_timeout,否则锁竞争立刻报 SQLITE_BUSY。
	//   - busy_timeout=5000  写锁忙时自动等 5s(刚好匹配业务层 5s context),避免立刻失败
	//   - journal_mode=WAL   多 reader 并发 + 1 writer,跟现有 pragmaJournalMode 一致
	//   - synchronous=NORMAL WAL 推荐组合(FULL 仅在断电时多一层保护,代价是显著变慢)
	//   - journal_size_limit=64MB  checkpoint 后把 -wal 文件截回 ≤64MB(默认 -1=无限,-wal 只涨不缩)。
	//     配合 main.go 里周期性 wal_checkpoint(TRUNCATE),避免长跑容器里 arcway.db-wal 无界膨胀。
	sqliteDSNPragma = "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(normal)&_pragma=journal_size_limit(67108864)&_pragma=secure_delete(ON)"

	// 多连接数:实测 1 个 SQLite 数据库文件并发写仍串行(文件锁),但多 conn 让"读 / 短写"
	// 不会被"长写 / 等锁"完全堵死。8 ≈ 典型 server 数 + 后台采集/订阅生成的并发,留充裕度。
	sqliteMaxOpenConns = 8
	sqliteMaxIdleConns = 4
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

const (
	SubscriptionButtonQR     = "qr"
	SubscriptionButtonCopy   = "copy"
	SubscriptionButtonImport = "import"
)

// TrafficRecord 表示特定日期的聚合流量快照。
type TrafficRecord struct {
	Date           time.Time
	TotalLimit     int64
	TotalUsed      int64
	TotalRemaining int64
}

// TrafficRepository 管理流量使用快照的持久性。
type TrafficRepository struct {
	db                       *sql.DB
	authMutationMu           sync.RWMutex
	sessionRevokerMu         sync.RWMutex
	sessionRevoker           func(string)
	managedNodeMu            sync.Mutex
	remoteInstallationLeases sync.Map // serverID (int64) -> *sync.RWMutex
	nodeSecretMu             sync.RWMutex
	nodeSecretBox            *secretbox.Box
	billingCacheMu           sync.Mutex
	billingCache             map[int64]trafficBillingCacheEntry
}

// AuthMutationMutex is shared with auth.Manager so account lifecycle changes
// cannot race the final session-issuance callback after authentication.
func (r *TrafficRepository) AuthMutationMutex() *sync.RWMutex {
	if r == nil {
		return nil
	}
	return &r.authMutationMu
}

// SetSessionRevoker connects persistent account lifecycle changes to the
// process-local token store without making storage depend on auth.
func (r *TrafficRepository) SetSessionRevoker(revoke func(string)) {
	if r == nil {
		return
	}
	r.sessionRevokerMu.Lock()
	r.sessionRevoker = revoke
	r.sessionRevokerMu.Unlock()
}

func (r *TrafficRepository) revokeMemorySessions(username string) {
	r.sessionRevokerMu.RLock()
	revoke := r.sessionRevoker
	r.sessionRevokerMu.RUnlock()
	if revoke != nil {
		revoke(username)
	}
}

// SubscriptionLink 表示向客户端公开的可配置订阅条目。
type SubscriptionLink struct {
	ID           int64
	Name         string
	Type         string
	Description  string
	RuleFilename string
	Buttons      []string
	ShortURL     string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func normalizeSubscriptionButtons(input []string) []string {
	if len(input) == 0 {
		return append([]string(nil), defaultSubscriptionButtons...)
	}

	seen := make(map[string]struct{}, len(input))
	for _, button := range input {
		key := strings.ToLower(strings.TrimSpace(button))
		if _, ok := allowedSubscriptionButtons[key]; ok {
			seen[key] = struct{}{}
		}
	}

	if len(seen) == 0 {
		return append([]string(nil), defaultSubscriptionButtons...)
	}

	order := []string{SubscriptionButtonQR, SubscriptionButtonCopy, SubscriptionButtonImport}
	normalized := make([]string, 0, len(seen))
	for _, button := range order {
		if _, ok := seen[button]; ok {
			normalized = append(normalized, button)
		}
	}

	return normalized
}

func encodeSubscriptionButtons(input []string) (string, error) {
	normalized := normalizeSubscriptionButtons(input)
	data, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeSubscriptionButtons(encoded string) []string {
	if strings.TrimSpace(encoded) == "" {
		return append([]string(nil), defaultSubscriptionButtons...)
	}

	var raw []string
	if err := json.Unmarshal([]byte(encoded), &raw); err != nil {
		return append([]string(nil), defaultSubscriptionButtons...)
	}

	return normalizeSubscriptionButtons(raw)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSubscriptionLink(scanner rowScanner) (SubscriptionLink, error) {
	var (
		link    SubscriptionLink
		buttons string
	)

	if err := scanner.Scan(&link.ID, &link.Name, &link.Type, &link.Description, &link.RuleFilename, &buttons, &link.ShortURL, &link.CreatedAt, &link.UpdatedAt); err != nil {
		return SubscriptionLink{}, err
	}
	if err := ValidateSubscribeFilename(link.RuleFilename); err != nil {
		return SubscriptionLink{}, fmt.Errorf("invalid stored subscription rule filename for id %d: %w", link.ID, err)
	}

	link.Buttons = decodeSubscriptionButtons(buttons)

	return link, nil
}

var (
	ErrTokenNotFound                             = errors.New("token not found")
	ErrUserNotFound                              = errors.New("user not found")
	ErrUserExists                                = errors.New("user already exists")
	ErrUserInactive                              = errors.New("user is inactive")
	ErrReservedUsername                          = errors.New("username is reserved")
	ErrUsernameRenameRequiresCredentialMigration = errors.New("username cannot be changed while remote access is configured")
	ErrRuleVersionNotFound                       = errors.New("rule version not found")
	ErrSubscriptionNotFound                      = errors.New("subscription link not found")
	ErrSubscriptionExists                        = errors.New("subscription link already exists")
	ErrNodeNotFound                              = errors.New("node not found")
	ErrNodeMutationChanged                       = errors.New("node inbound mutation changed during operation")
	ErrSubscribeFileNotFound                     = errors.New("subscribe file not found")
	ErrSubscribeFileExists                       = errors.New("subscribe file already exists")
	ErrSubscribeFileChanged                      = errors.New("subscribe file changed during operation")
	ErrSubscribeFilenameHistory                  = errors.New("subscribe filename has archived history")
	ErrCustomShortCodeExists                     = errors.New("该短码已被占用，请更换一个")
	ErrSharedServerNotFound                      = errors.New("shared server not found")
	ErrFederatedServerNotFound                   = errors.New("federated server not found")
	ErrUserSettingsNotFound                      = errors.New("user settings not found")
	ErrExternalSubscriptionNotFound              = errors.New("external subscription not found")
	ErrExternalSubscriptionExists                = errors.New("external subscription already exists")
	ErrProxyProviderConfigExists                 = errors.New("proxy provider config already exists")
	ErrPackageNotFound                           = errors.New("package not found")
	ErrPackageExists                             = errors.New("package already exists")
	ErrRemoteServerNotFound                      = errors.New("remote server not found")
	ErrRemoteServerExists                        = errors.New("remote server already exists")
	ErrRemoteListenPortMismatch                  = errors.New("remote Agent listen port mismatch")
	ErrRemoteInstallationActive                  = errors.New("remote server installation is already active")
	ErrRemoteInstallationInvalid                 = errors.New("remote server installation is invalid or expired")
	ErrRemoteInstallationAborted                 = errors.New("remote server installation was aborted")
	ErrRemoteInstallationRollingBack             = errors.New("remote server installation is rolling back")
	ErrRemoteInstallationPolicy                  = errors.New("remote server installation policy changed")
	ErrRemoteInstallationNotReady                = errors.New("remote server installation is not ready")
	ErrRemoteInstallationNotPrepared             = errors.New("remote server installation is not prepared")
	ErrRemoteInstallTicketInvalid                = errors.New("remote server install ticket is invalid, expired, or already used")
	ErrCertificateNotFound                       = errors.New("certificate not found")
	ErrCertificateExists                         = errors.New("certificate already exists")
)

const ReservedGlobalAPITokenUsername = "api-token-admin"

func IsReservedUsername(username string) bool {
	return strings.EqualFold(strings.TrimSpace(username), ReservedGlobalAPITokenUsername)
}

// IsValidRemoteManagementListenPort reserves port+1 for the expiry guard.
// Zero means the Agent default and is resolved during first heartbeat.
func IsValidRemoteManagementListenPort(port int) bool {
	return port == 0 || (port >= 1024 && port <= 65534)
}

var (
	allowedSubscriptionButtons = map[string]struct{}{
		SubscriptionButtonQR:     {},
		SubscriptionButtonCopy:   {},
		SubscriptionButtonImport: {},
	}
	defaultSubscriptionButtons = []string{
		SubscriptionButtonQR,
		SubscriptionButtonCopy,
		SubscriptionButtonImport,
	}
)

const (
	TrafficMethodUp   = "up"
	TrafficMethodDown = "down"
	TrafficMethodBoth = "both"
)

// Package代表流量包模板
type Package struct {
	ID                int64             `json:"id"`
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	TrafficLimitGB    float64           `json:"traffic_limit_gb"`           // GB 流量限制
	TrafficLimitBytes int64             `json:"-"`                          // 流量限制（以字节为单位）（仅限内部使用）
	CycleDays         int               `json:"cycle_days"`                 // 包裹持续时间（天）
	IsReset           bool              `json:"is_reset"`                   // 流量是否按月重置
	ResetDay          int               `json:"reset_day"`                  // 重置的月份日期 (1-31)
	Nodes             []int64           `json:"nodes"`                      // 关联节点 ID
	NodeMultipliers   map[int64]float64 `json:"node_multipliers,omitempty"` // node_id → 倍率;遗留套餐为 nil = 全部按 1
	SpeedLimitMbps    float64           `json:"speed_limit_mbps"`           // 限速 (Mbps)，0=不限
	DeviceLimit       int               `json:"device_limit"`               // 设备数限制，0=不限
	// 套餐级 per-node 限速覆盖。map 含 key 即生效:0 = 显式不限速,>0 = 该值;不含 key = 继承 SpeedLimitMbps。
	NodeSpeedLimits map[int64]float64 `json:"node_speed_limits,omitempty"`
	// 套餐级 per-node 客户端数覆盖。语义同上。
	NodeDeviceLimits map[int64]int        `json:"node_device_limits,omitempty"`
	AutoSpeedRules   []AutoSpeedLimitRule `json:"auto_speed_rules,omitempty"`
	ShortCode        string               `json:"short_code"`
	TrafficMode      string               `json:"traffic_mode"`
	TemplateFilename string               `json:"template_filename"` // 套餐绑的 V3 模板;空 = 走系统默认模板
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
}

func (p *Package) TrafficMultiplier() int64 {
	if p.TrafficMode == "twoway" {
		return 2
	}
	return 1
}

// MultiplierForNode 返回某节点在该套餐内的倍率。**每个节点(含 routed 出站节点)的倍率都是独立的**:
// 只看该节点自己在 NodeMultipliers 里的配置,没配 → 1.0(默认权重)。
// 不再回退到父/根节点 —— routed 节点虽与根节点共用同一 inbound,但在 xray 里是不同的 user(email/UUID),
// 流量能按 email 精确归属到具体 routed 节点(见 GetUserWeightedTraffic 的子账号路径),故各算各的倍率,
// 不该被根节点倍率覆盖。
func (p *Package) MultiplierForNode(nodeID int64) float64 {
	if p == nil || len(p.NodeMultipliers) == 0 {
		return 1.0
	}
	if m, ok := p.NodeMultipliers[nodeID]; ok && m > 0 {
		return m
	}
	return 1.0
}

// serializeNodeMultipliers 把 map 序列化为 JSON,**清理掉不在 nodes 列表里的残留 key**
// (取消勾选节点时 UI 可能没同步删 map 项,在这里兜底);全部省略默认值 1.0 节省空间。
// nil/空/全是 1.0 → 返回 "{}"。
func serializeNodeMultipliers(m map[int64]float64, nodes []int64) string {
	if len(m) == 0 {
		return "{}"
	}
	keep := make(map[string]float64, len(m))
	allowed := make(map[int64]bool, len(nodes))
	for _, id := range nodes {
		allowed[id] = true
	}
	for id, v := range m {
		if !allowed[id] {
			continue
		}
		if v <= 0 || v == 1.0 {
			continue
		}
		keep[fmt.Sprintf("%d", id)] = v
	}
	if len(keep) == 0 {
		return "{}"
	}
	b, err := json.Marshal(keep)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// serializeNodeFloatMap 把 node_id → float 的 map 序列化为 JSON。
// 与 serializeNodeMultipliers 不同:**0 值必须保留**(0 = 显式不限速,有语义)。
// 当 nodes 非 nil 时按白名单过滤(套餐场景);nodes = nil 时不过滤(用户 override,套餐可能切换)。
func serializeNodeFloatMap(m map[int64]float64, nodes []int64) string {
	if len(m) == 0 {
		return "{}"
	}
	var allowed map[int64]bool
	if nodes != nil {
		allowed = make(map[int64]bool, len(nodes))
		for _, id := range nodes {
			allowed[id] = true
		}
	}
	keep := make(map[string]float64, len(m))
	for id, v := range m {
		if allowed != nil && !allowed[id] {
			continue
		}
		// 允许 0(显式不限速)。负数视为无效跳过。
		if v < 0 {
			continue
		}
		keep[fmt.Sprintf("%d", id)] = v
	}
	if len(keep) == 0 {
		return "{}"
	}
	b, err := json.Marshal(keep)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// serializeNodeIntMap 把 node_id → int 的 map 序列化为 JSON。语义同 serializeNodeFloatMap。
func serializeNodeIntMap(m map[int64]int, nodes []int64) string {
	if len(m) == 0 {
		return "{}"
	}
	var allowed map[int64]bool
	if nodes != nil {
		allowed = make(map[int64]bool, len(nodes))
		for _, id := range nodes {
			allowed[id] = true
		}
	}
	keep := make(map[string]int, len(m))
	for id, v := range m {
		if allowed != nil && !allowed[id] {
			continue
		}
		if v < 0 {
			continue
		}
		keep[fmt.Sprintf("%d", id)] = v
	}
	if len(keep) == 0 {
		return "{}"
	}
	b, err := json.Marshal(keep)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// unmarshalStringKeyedMap 把 {"123": 1.5} 这类 JSON 反序列化为 map[int64]float64。
// 出错时 *out 保持 nil。
func unmarshalStringKeyedMap(s string, out *map[int64]float64) {
	tmp := map[string]float64{}
	if err := json.Unmarshal([]byte(s), &tmp); err != nil || len(tmp) == 0 {
		return
	}
	m := make(map[int64]float64, len(tmp))
	for k, v := range tmp {
		id, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			continue
		}
		m[id] = v
	}
	if len(m) > 0 {
		*out = m
	}
}

// unmarshalStringKeyedIntMap 把 {"123": 5} 这类 JSON 反序列化为 map[int64]int。
func unmarshalStringKeyedIntMap(s string, out *map[int64]int) {
	tmp := map[string]int{}
	if err := json.Unmarshal([]byte(s), &tmp); err != nil || len(tmp) == 0 {
		return
	}
	m := make(map[int64]int, len(tmp))
	for k, v := range tmp {
		id, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			continue
		}
		m[id] = v
	}
	if len(m) > 0 {
		*out = m
	}
}

// SpeedLimitMbpsForNode 返回某节点在该套餐内的限速值,以及 map 是否含 key。
// found=true 时该值是套餐对此节点的"显式设置"(可能为 0,表示显式不限速);
// found=false 时调用方应继续 fallback 到 SpeedLimitMbps。
// routed 子节点(自身不在套餐 NodeSpeedLimits 里)传入 parentNodeID,自动回退到父物理节点。
func (p *Package) SpeedLimitMbpsForNode(nodeID int64, parentNodeID *int64) (float64, bool) {
	if p == nil {
		return 0, false
	}
	if v, ok := p.NodeSpeedLimits[nodeID]; ok {
		return v, true
	}
	if parentNodeID != nil {
		if v, ok := p.NodeSpeedLimits[*parentNodeID]; ok {
			return v, true
		}
	}
	return 0, false
}

// DeviceLimitForNode 返回某节点在该套餐内的客户端数,以及 map 是否含 key。语义同 SpeedLimitMbpsForNode。
func (p *Package) DeviceLimitForNode(nodeID int64, parentNodeID *int64) (int, bool) {
	if p == nil {
		return 0, false
	}
	if v, ok := p.NodeDeviceLimits[nodeID]; ok {
		return v, true
	}
	if parentNodeID != nil {
		if v, ok := p.NodeDeviceLimits[*parentNodeID]; ok {
			return v, true
		}
	}
	return 0, false
}

type AutoSpeedLimitRule struct {
	Type             string  `json:"type"`              // "sustained" | "burst"
	ThresholdMbps    float64 `json:"threshold_mbps"`    // 触发阈值 (Mbps)
	SustainedSeconds int     `json:"sustained_seconds"` // sustained: 持续时长; burst: 单次最短时长
	WindowSeconds    int     `json:"window_seconds"`    // burst: 时间窗口
	BurstCount       int     `json:"burst_count"`       // burst: 窗口内触发次数
	LimitMbps        float64 `json:"limit_mbps"`        // 限速后速率 (Mbps)
	LimitDuration    int     `json:"limit_duration"`    // 限速持续时间 (秒)
}

// Node代表存储在数据库中的代理节点。
type Node struct {
	ID                int64
	Username          string
	RawURL            string
	NodeName          string
	Protocol          string
	ParsedConfig      string
	ClashConfig       string
	Enabled           bool
	Tag               string
	Tags              []string // 多标签支持（兼容旧版单Tag）
	OriginalServer    string
	OriginalDomain    string // IP 解析功能专用：解析为 IP 前的原始域名（用于"恢复域名"）。与 OriginalServer（服务器名/路由键）严格区分
	InboundTag        string // 关联入站标签（用于将节点链接到入站）
	InboundMutationID string // 创建该远端入站的 mutation_id；删除时作为所有权 fencing token
	ChainProxyNodeID  *int64 // 链式代理目标节点 ID
	NodeType          string // 'physical' (默认)、'routed' (路由出站) 或 'forwarded' (转发克隆)
	ParentNodeID      *int64 // routed 节点指向其父物理节点
	RoutedOutboundTag string // routed 节点专用:绑定的 outbound tag(空 = 非 routed 节点);常用查询展示
	RoutedOwner       string // routed 节点专用:'shared'(默认,admin 创建,进入套餐池) | 'user'(用户私有路由出站)
	RelayOrigServer   string // 中转:配置中转后记录的原服务器地址(空=未配置中转);此时 clash server 为中转地址
	RelayOrigPort     int    // 中转:原服务器端口
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// RoutedNodeDetail 路由出站节点的完整元数据,通过专用 GetRoutedNodeDetail 读取。
// 包含 Node 基本字段 + routed_* 字段。
type RoutedNodeDetail struct {
	Node
	RoutedOutboundTag     string
	RoutedOutboundJSON    string
	RoutedRuleMarktag     string
	RoutedAdminEmail      string
	RoutedAdminCredential string
}

// SubscribeFile 表示订阅文件配置。
type SubscribeFile struct {
	ID                        int64
	Name                      string
	Description               string
	URL                       string
	Type                      string
	Filename                  string
	FileShortCode             string // 用于短链接的 3 字符代码（自动生成）
	CustomShortCode           string // 用户自定义短码（唯一，优先）
	AutoSyncCustomRules       bool
	TemplateFilename          string   // 绑定的 V3 模板文件名
	SelectedTags              []string // 选中的节点标签（DB 中 JSON 数组）— legacy,与 SelectedNodeIDs 二选一
	SelectedNodeIDs           []int64  // 选中的节点 ID（DB 中 JSON 数组）— 优先于 SelectedTags;空 → 回退 tag 过滤
	SelectedCustomRuleIDs     []int64  // 该订阅生效的覆写规则 ID（空=全部启用的生效）
	SelectedOverrideScriptIDs []int64  // 该订阅生效的覆写脚本 ID（空=全部启用的生效）
	StatsServerIDs            string   // 流量统计服务器 ID（逗号分隔 remote_servers.id）
	TrafficLimit              *float64 // 手动流量上限(GB)，nil=跟随服务器
	SortOrder                 int
	RawOutput                 bool
	CreatedBy                 string // 创建者用户名
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

// UserSettings 代表用户特定的配置。
type UserSettings struct {
	Username             string
	ForceSyncExternal    bool
	MatchRule            string     // "节点名称"或"服务器端口"
	SyncScope            string     // "saved_only"或"all" - 同步外部订阅的范围
	KeepNodeName         bool       // 同步时保留原始节点名称
	CacheExpireMinutes   int        // 缓存过期时间（分钟）
	SyncTraffic          bool       // 同步外部订阅的流量信息
	NodeNameFilter       string     // 正则表达式过滤节点名称
	AppendSubInfo        bool       // 同步外部订阅时把剩余流量/天数拼到节点名后
	CustomRulesEnabled   bool       // 启用自定义规则功能
	EnableShortLink      bool       // 启用订阅短链接功能
	UseNewTemplateSystem bool       // 使用新的模板系统（基于数据库），默认true
	EnableProxyProvider  bool       // 启用代理提供商功能
	NodeOrder            []int64    // 节点显示顺序（节点 ID 数组）
	DebugEnabled         bool       // 启用调试日志记录到文件
	DebugLogPath         string     // 当前调试日志文件的路径
	DebugStartedAt       *time.Time // 调试日志记录何时开始
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// SystemConfig 代表所有用户共享的全局系统配置。
type SystemConfig struct {
	ProxyGroupsSourceURL    string // 代理组配置的远程 URL
	ClientCompatibilityMode bool   // 自动过滤客户端不兼容的节点
	EnableShortLink         bool   // 全局启用订阅短链接
	SpeedCollectInterval    int    // 网速采集间隔（秒），默认 3
	TrafficCollectInterval  int    // 流量采集间隔（秒），默认 60
	TrafficCheckInterval    int    // 流量限额检查间隔（秒），默认 120
	HeartbeatInterval       int    // 心跳间隔（秒），默认 30
	AgentLogEnabled         bool   // 是否打印 agent 交互日志，默认关闭

	NotifyEnabled                 bool
	TelegramBotToken              string
	TelegramChatID                string
	NotifyLogin                   bool
	NotifySubscribeFetch          bool
	NotifyDailyTraffic            bool
	NotifyServerOffline           bool
	NotifyServerOnline            bool
	NotifyTrafficThreshold        bool
	NotifyDailyTrafficTime        string // "HH:MM"，默认 "08:00"
	NotifyTrafficThresholdPercent int    // 0-100，默认 80

	// Phase 2: 9 个新通知开关 + 2 个参数(默认全 false / 0,需 admin 在系统设置主动开)
	NotifyTrafficThreshold80      bool   // 用户流量达 80% 预警
	NotifyOverLimit               bool   // 用户流量超 100%(已踢)
	NotifyPackageExpiring         bool   // 套餐 N 天内到期
	NotifyPackageExpiringDays     int    // N 默认 3
	NotifyPackageExpired          bool   // 套餐已到期
	NotifyUserRegistered          bool   // 新用户注册
	NotifyTelegramBound           bool   // 用户首次绑定 TG
	NotifyCertResult              bool   // 证书申请成败
	NotifyAgentLongOffline        bool   // agent 长期离线
	NotifyAgentLongOfflineMinutes int    // 默认 30
	NotifyDeviceLimitExceeded     bool   // 设备数超限(agent 上报触发)
	EnableOverrideScripts         bool   // 启用覆写脚本功能
	SubscriptionOutputFormat      string // 订阅序列化格式: "yaml"(default) or "json"。仅影响 Clash 客户端输出。
	SilentMode                    bool   // 静默模式：所有请求返回404，仅订阅接口可用
	SilentModeTimeout             int    // 获取订阅后恢复访问的分钟数，默认15
	EnableManagementFeatures      bool   // 启用管理功能（模板、订阅管理等菜单）
	DefaultTemplateFilename       string // 默认模板文件名（rule_templates/目录下）
	// 根路径短链接:直接 GET /<code>(无 /x/ 前缀)会尝试匹配同 code 的 /x/ 短链;命中则放行,
	// 未命中按安全规则计入暴力枚举失败计数。
	EnableRootShortLinks bool

	// 节点名称倍率前缀:订阅生成时,套餐内 multiplier != 1 的节点 name 前面加
	// "{Left}{multiplier}{Right}" 前缀;Left/Right 默认 「」,用户可改。
	NodeNameMultiplierPrefixEnabled bool
	NodeNameMultiplierLeft          string
	NodeNameMultiplierRight         string
}

// ExternalSubscription表示用户导入的外部订阅URL。
type ExternalSubscription struct {
	ID          int64
	Username    string
	Name        string
	URL         string
	UserAgent   string // User-Agent 请求头
	NodeCount   int
	LastSyncAt  *time.Time
	Upload      int64      // 已上传流量（字节）
	Download    int64      // 已下载流量（字节）
	Total       int64      // 总流量（字节）
	Expire      *time.Time // 过期时间
	TrafficMode string     // 流量统计方式: "download", "upload", "both"
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CustomRule 表示 DNS、规则或规则提供者的自定义规则。
type CustomRule struct {
	ID        int64
	Name      string
	Type      string // "dns"、"规则"、"规则提供者"
	Mode      string // "替换"、"前置"
	Content   string
	Enabled   bool
	CreatedBy string // 创建者用户名(用户权限隔离);'' 视为 admin 历史数据
	CreatedAt time.Time
	UpdatedAt time.Time
}

// OverrideScript 表示 JavaScript 覆写脚本。
type OverrideScript struct {
	ID        int64
	Username  string
	Name      string
	Hook      string // "post_fetch" | "pre_save_nodes"
	Content   string
	Enabled   bool
	SortOrder int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CustomRuleApplication 跟踪自定义规则应用了哪些内容来订阅文件
type CustomRuleApplication struct {
	ID              int64
	SubscribeFileID int64
	CustomRuleID    int64
	RuleType        string // "dns"、"规则"、"规则提供者"
	RuleMode        string // "替换"、"前置"
	AppliedContent  string // 已应用的 JSON 序列化内容
	ContentHash     string // 内容的 SHA256 哈希值用于快速比较
	AppliedAt       time.Time
}

// ProxyProviderConfig 表示代理提供程序配置。
type ProxyProviderConfig struct {
	ID                        int64
	Username                  string
	ExternalSubscriptionID    int64
	Name                      string
	Type                      string
	Interval                  int
	Proxy                     string
	SizeLimit                 int
	Header                    string
	HealthCheckEnabled        bool
	HealthCheckURL            string
	HealthCheckInterval       int
	HealthCheckTimeout        int
	HealthCheckLazy           bool
	HealthCheckExpectedStatus int
	Filter                    string
	ExcludeFilter             string
	ExcludeType               string
	GeoIPFilter               string
	Override                  string
	ProcessMode               string
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

// XrayServer 表示 Xray 服务器配置。
type XrayServer struct {
	ID                   int64     `json:"id"`
	Name                 string    `json:"name"`
	Host                 string    `json:"host"`
	Port                 int       `json:"port"`
	Description          string    `json:"description,omitempty"`
	IsPrimary            bool      `json:"is_primary"`
	ProcessID            int       `json:"process_id"`
	ConfigPath           string    `json:"config_path,omitempty"`
	TrafficLimit         int64     `json:"traffic_limit"`
	TrafficResetDay      int       `json:"traffic_reset_day"`
	TrafficUsedOffset    int64     `json:"traffic_used_offset"`
	TrafficUsed          int64     `json:"traffic_used"`           // 计算字段
	CurrentUploadSpeed   int64     `json:"current_upload_speed"`   // 实时上传速度
	CurrentDownloadSpeed int64     `json:"current_download_speed"` // 实时下载速度
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// 远程服务器的连接模式常量。
const (
	ConnectionModePush      = "push"
	ConnectionModePull      = "pull"
	ConnectionModeWebSocket = "websocket"
	ConnectionModeAuto      = "auto"
)

// 远程服务器状态常量。
const (
	RemoteServerStatusPending   = "pending"
	RemoteServerStatusConnected = "connected"
	RemoteServerStatusOffline   = "offline"
)

// BatchInbound 表示批量入站配置。
type BatchInbound struct {
	ID        int64
	BatchID   string
	Tag       string
	ServerID  int64
	Protocol  string
	Port      int
	CreatedAt time.Time
}

// BatchOutb​​ound 表示批量出站配置。
type BatchOutbound struct {
	ID        int64
	BatchID   string
	Tag       string
	ServerID  int64
	Protocol  string
	CreatedAt time.Time
}

// RemoteServer 代表远程服务器配置。
type RemoteServer struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Token         string     `json:"token"` // 服务器令牌（代理持有，用于推送到服务器）- 保留用于向后兼容
	Status        string     `json:"status"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	IPAddress     string     `json:"ip_address,omitempty"`
	// IPAddressV6 由 agent 在 dual-stack 服务器上单独探测后上报。
	// 用途:master HTTP 反向请求时,v4 dial 失败 → fallback 试 v6。
	// 空值 = agent 不支持上报 / 服务器无 v6 → 退化为只走 v4(与历史行为一致)。
	IPAddressV6 string `json:"ip_address_v6,omitempty"`
	// IPv6Enabled 管理员开关(默认 true)。关闭后:服务管理不显示 v6、添加节点不可选 v6。
	// 与 ip_address_v6 是否为空解耦 —— 因为 agent 上报空 v6 时后端 COALESCE 会保留旧地址,
	// 单靠"地址是否为空"无法表达"用户主动关闭了 v6"。
	IPv6Enabled bool `json:"ipv6_enabled"`
	// OfflineNotified 当前离线周期是否已发过下线通知。配合 offline_since 做"容忍阈值"防抖:
	// 离线满阈值秒才发下线通知(offline_notified 置 1);重连时只有 offline_notified=1 才补发上线通知。
	OfflineNotified bool `json:"offline_notified"`
	// WarpInstalled agent 已注册 Cloudflare WARP(warp.json 存在 + device_id 非空)。
	// agent 在 auth + heartbeat 时上报;master 用来在 server 卡片渲染空心 W 图标 badge。
	WarpInstalled        bool       `json:"warp_installed"`
	Domain               string     `json:"domain,omitempty"`
	BootTime             *time.Time `json:"boot_time,omitempty"`
	XrayBootTime         *time.Time `json:"xray_boot_time,omitempty"`
	BootCount            int        `json:"boot_count"`
	XrayBootCount        int        `json:"xray_boot_count"`
	TokenExpiresAt       *time.Time `json:"token_expires_at,omitempty"`
	LastTokenRefresh     *time.Time `json:"last_token_refresh,omitempty"`
	ConnectionMode       string     `json:"connection_mode"`
	PullAddress          string     `json:"pull_address,omitempty"`
	PullPort             int        `json:"pull_port,omitempty"`
	PullToken            string     `json:"pull_token,omitempty"` // 代理令牌（服务器持有，用于从代理拉取）- 旧字段名称
	LastPullAt           *time.Time `json:"last_pull_at,omitempty"`
	PushFailCount        int        `json:"push_fail_count"`
	LastPushFail         *time.Time `json:"last_push_fail,omitempty"`
	FallbackToPull       bool       `json:"fallback_to_pull"`
	FallbackAt           *time.Time `json:"fallback_at,omitempty"`
	CurrentUploadSpeed   int64      `json:"current_upload_speed"`
	CurrentDownloadSpeed int64      `json:"current_download_speed"`
	SpeedUpdatedAt       *time.Time `json:"speed_updated_at,omitempty"`
	XrayRunning          bool       `json:"xray_running"`
	XrayVersion          string     `json:"xray_version,omitempty"`
	XrayScannedAt        *time.Time `json:"xray_scanned_at,omitempty"`
	ListenPort           int        `json:"listen_port,omitempty"`
	TrafficLimit         int64      `json:"traffic_limit"`
	TrafficResetDay      int        `json:"traffic_reset_day"`
	// 双令牌系统字段
	AgentToken            string     `json:"agent_token,omitempty"` // 代理令牌（服务器持有，用于从代理拉取）
	AgentTokenExpiresAt   *time.Time `json:"agent_token_expires_at,omitempty"`
	LastAgentTokenRefresh *time.Time `json:"last_agent_token_refresh,omitempty"`
	Use443                bool       `json:"use_443"`                       // 是否使用443端口与nginx+xray隧道
	StealSelf             bool       `json:"steal_self"`                    // 安装/重装时是否允许自动接管本机443
	StealMode             string     `json:"steal_mode,omitempty"`          // "tunnel" | "fallback"，默认 tunnel
	NginxMode             string     `json:"nginx_mode"`                    // "managed"(Arcway 管理) | "reuse_existing"(复用系统 Nginx)
	SiteType              string     `json:"site_type,omitempty"`           // "static" | "proxy"
	SiteValue             string     `json:"site_value,omitempty"`          // 静态路径或反向代理地址
	XrayMode              string     `json:"xray_mode"`                     // "external" (默认) 或 "embedded"
	TimeOffsetSeconds     *int64     `json:"time_offset_seconds,omitempty"` // agent 与主控的时钟偏差（秒）
	TrafficUsedOffset     int64      `json:"traffic_used_offset"`
	// 流量统计规则: "both"(默认,上行+下行) / "upload"(仅上行) / "download"(仅下行)
	// 影响:主控聚合该服务器节点流量时按规则累加。**用户流量不受此字段影响**,
	// 用户已用流量按套餐 traffic_mode(oneway/twoway)单独算。
	TrafficStatsMode string `json:"traffic_stats_mode"`
	// TrafficSource 服务器"已用流量"的数据源 — "xray"(默认,聚合 node_traffic,跟节点视图口径一致)
	// 或 "system"(用 agent 上报的 /proc/net/dev 累计 RX/TX,跟 VPS 服务商网卡计费口径一致)。
	// 节点视图 / 用户视图 / 套餐 enforcement 不受此字段影响,它们恒为 xray 维度。
	TrafficSource string `json:"traffic_source"`
	// SystemRxCycle / SystemTxCycle 当前 cycle(reset_day 之间)内累加的系统网卡 RX/TX 字节,
	// 用于 traffic_source='system' 时算 server.traffic_used = SystemRxCycle + SystemTxCycle + offset(按 stats_mode)。
	SystemRxCycle int64 `json:"system_rx_cycle"`
	SystemTxCycle int64 `json:"system_tx_cycle"`
	// SystemLastSeenRx / SystemLastSeenTx 上次 agent 上报的 /proc/net/dev 累计值,
	// 用于算 delta 与 reboot 检测:RX 倒退(同 boot_time 下)= /proc 异常,差跳过 1 次后续正常;
	// SystemBootTimeUnix 跟 agent 上报的值对比变化 → 正常 reboot,基线重建不计 delta。
	SystemLastSeenRx       int64      `json:"system_last_seen_rx"`
	SystemLastSeenTx       int64      `json:"system_last_seen_tx"`
	SystemBootTimeUnix     int64      `json:"system_boot_time_unix"`
	SystemTrafficUpdatedAt *time.Time `json:"system_traffic_updated_at,omitempty"`
	// DDNS 自动同步:agent 心跳上报 IP 变化时,主控自动调 DNS provider API 更新 pull_address 域名的 A/AAAA 记录
	DDNSEnabled      bool       `json:"ddns_enabled"`
	DDNSProviderID   int64      `json:"ddns_provider_id"` // 0=自动(按证书),>0=显式指定 dns_providers.id
	DDNSLastSyncedAt *time.Time `json:"ddns_last_synced_at,omitempty"`
	DDNSLastError    string     `json:"ddns_last_error,omitempty"`
	DDNSPending      bool       `json:"ddns_pending"` // 正在同步中
	// LastTrafficResetAt 最近一次按 traffic_reset_day 自动重置服务器流量的时间(防同月反复重置)
	LastTrafficResetAt *time.Time `json:"last_traffic_reset_at,omitempty"`
	IsFederated        bool       `json:"is_federated"`      // 是否为接入的"分享服务器"(联邦)，非持久化字段
	FederationPrefix   string     `json:"federation_prefix"` // 分享服务器上新增入站的 tag 前缀，非持久化字段
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// NodeTraffic 表示节点的流量统计信息。
type NodeTraffic struct {
	ID            int64     `json:"id"`
	ServerID      int64     `json:"server_id"`
	Tag           string    `json:"tag"`
	Type          string    `json:"type"`
	Uplink        int64     `json:"uplink"`
	Downlink      int64     `json:"downlink"`
	TotalUplink   int64     `json:"total_uplink"`
	TotalDownlink int64     `json:"total_downlink"`
	LastUplink    int64     `json:"last_uplink"`
	LastDownlink  int64     `json:"last_downlink"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ServerSystemTrafficSnapshot 每日 00:00 拍摄的"该 server 此时的 system_rx_cycle / system_tx_cycle"。
// 前端服务器视图 traffic_source='system' 模式下,用 (当前 cycle - 选定日期 baseline) 算今日/本周/本月增量。
type ServerSystemTrafficSnapshot struct {
	ServerID int64  `json:"server_id"`
	Date     string `json:"date"`
	RxCycle  int64  `json:"rx_cycle"`
	TxCycle  int64  `json:"tx_cycle"`
}

// UserTraffic 表示用户的流量统计信息。
type UserTraffic struct {
	ID            int64     `json:"id"`
	ServerID      int64     `json:"server_id"`
	Username      string    `json:"username"`
	Uplink        int64     `json:"uplink"`
	Downlink      int64     `json:"downlink"`
	TotalUplink   int64     `json:"total_uplink"`
	TotalDownlink int64     `json:"total_downlink"`
	LastUplink    int64     `json:"last_uplink"`
	LastDownlink  int64     `json:"last_downlink"`
	CycleStart    time.Time `json:"cycle_start"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TrafficSnapshot 代表每日流量快照。
type TrafficSnapshot struct {
	ID               int64
	ServerID         int64
	Date             string
	InboundUplink    int64
	InboundDownlink  int64
	OutboundUplink   int64
	OutboundDownlink int64
	UserUplink       int64
	UserDownlink     int64
	CreatedAt        time.Time
}

type NodeTrafficSnapshot struct {
	ID       int64  `json:"id"`
	ServerID int64  `json:"server_id"`
	Tag      string `json:"tag"`
	// Type 区分 'inbound' / 'outbound',前端按 type='inbound' 过滤减 server 视图 baseline,
	// 避免老 schema 无 type 时 sum(inbound+outbound snap) 大于 sum(inbound live) → 减出负数 clamp 0。
	Type     string `json:"type"`
	Date     string `json:"date"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

type UserTrafficSnapshot struct {
	ID       int64  `json:"id"`
	ServerID int64  `json:"server_id"`
	Username string `json:"username"`
	Date     string `json:"date"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

var (
	allowedTrafficMethods = map[string]struct{}{
		TrafficMethodUp:   {},
		TrafficMethodDown: {},
		TrafficMethodBoth: {},
	}
)

// 初始化存储在给定路径或 DSN 中的新的 SQLite 支持的存储库。
func NewTrafficRepository(path string) (*TrafficRepository, error) {
	if path == "" {
		return nil, errors.New("traffic repository path is empty")
	}

	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create traffic data directory: %w", err)
		}
	}

	// 把裸路径转成 file: URI 并挂载 per-connection pragma(busy_timeout / WAL / synchronous)。
	// :memory: 与已是 file: URI 的 DSN 保持原样;后者由调用方负责挂载需要的 pragma。
	dsn := path
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		dsn = "file:" + path + "?" + sqliteDSNPragma
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	db.SetMaxOpenConns(sqliteMaxOpenConns)
	db.SetMaxIdleConns(sqliteMaxIdleConns)
	// 空闲连接最多留 5 分钟就回收 — 释放其持有的 WAL 读快照,让 checkpoint 能抽干旧帧。
	// (不设时 idle conn 永不回收,长跑容器里旧读标记会一直钉住 WAL。)
	db.SetConnMaxIdleTime(5 * time.Minute)

	// 兜底再 Exec 一次 — DSN _pragma 在某些 modernc.org/sqlite 版本路径异常时可能不生效,
	// 这里在第一个 conn 上强制设一次 journal_mode 让整库进入 WAL(db-level、persistent),
	// 并设 journal_size_limit 让 checkpoint 后 -wal 文件缩回。
	if _, err := db.Exec(pragmaJournalMode); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_size_limit=67108864"); err != nil {
		log.Printf("[storage] set journal_size_limit failed (non-fatal): %v", err)
	}
	if _, err := db.Exec("PRAGMA secure_delete=ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable secure delete: %w", err)
	}

	repo := &TrafficRepository{db: db}
	if err := repo.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return repo, nil
}

// 关闭会释放底层数据库资源。
func (r *TrafficRepository) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

// Checkpoint 强制 WAL 检查点以确保所有数据都写入主数据库文件。
// 这在创建备份之前很有用。
func (r *TrafficRepository) Checkpoint() error {
	if r == nil || r.db == nil {
		return nil
	}
	_, err := r.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

func (r *TrafficRepository) migrate() error {
	const trafficSchema = `
CREATE TABLE IF NOT EXISTS traffic_records (
    date TEXT PRIMARY KEY,
    total_limit INTEGER NOT NULL,
    total_used INTEGER NOT NULL,
    total_remaining INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

	if _, err := r.db.Exec(trafficSchema); err != nil {
		return fmt.Errorf("migrate traffic_records: %w", err)
	}

	// 节点测速结果。source: master_local(主控本机) / 预留 home_tester。
	const speedTestResultsSchema = `
CREATE TABLE IF NOT EXISTS speed_test_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL,
    node_name TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'master_local',
    down_mbps REAL NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT -1,
    test_bytes INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ok',
    error TEXT NOT NULL DEFAULT '',
    tested_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_speed_test_node ON speed_test_results(node_id);
`
	if _, err := r.db.Exec(speedTestResultsSchema); err != nil {
		return fmt.Errorf("migrate speed_test_results: %w", err)
	}
	// 出口 IP 列(老库幂等加列):测速时经代理回显的对端 IP,用于核对出站链路是否符合预期。
	if err := r.ensureTableColumn("speed_test_results", "egress_ip", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate speed_test_results.egress_ip: %w", err)
	}

	// 家用测速端:反向 WS 连入主控,凭 token_hash 认证。
	const speedTestersSchema = `
CREATE TABLE IF NOT EXISTS speed_testers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL DEFAULT '',
    last_seen TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	if _, err := r.db.Exec(speedTestersSchema); err != nil {
		return fmt.Errorf("migrate speed_testers: %w", err)
	}

	// 服务器线路测速与节点代理测速语义不同，独立存储，避免 node_id=0 污染节点最新结果。
	const lineSpeedTestResultsSchema = `
CREATE TABLE IF NOT EXISTS line_speedtest_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('master', 'remote')),
    server_id INTEGER NOT NULL DEFAULT 0,
    server_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'failed')),
    error TEXT NOT NULL DEFAULT '',
    ping_ms REAL NOT NULL DEFAULT 0,
    download_mbps REAL NOT NULL DEFAULT 0,
    upload_mbps REAL NOT NULL DEFAULT 0,
    jitter_ms REAL,
    packet_loss_percent REAL,
    isp TEXT NOT NULL DEFAULT '',
    egress_ip TEXT NOT NULL DEFAULT '',
    test_server TEXT NOT NULL DEFAULT '',
    server_location TEXT NOT NULL DEFAULT '',
    implementation TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_line_speedtest_target
    ON line_speedtest_results(target_kind, server_id, id DESC);
`
	if _, err := r.db.Exec(lineSpeedTestResultsSchema); err != nil {
		return fmt.Errorf("migrate line_speedtest_results: %w", err)
	}
	// 异步任务无法跨主控进程恢复。启动时把遗留 running 明确收口，避免前端永久轮询。
	if _, err := r.db.Exec(`UPDATE line_speedtest_results
		SET status = 'failed', error = '主控重启，测速任务未完成', completed_at = CURRENT_TIMESTAMP
		WHERE status = 'running'`); err != nil {
		return fmt.Errorf("recover stale line speedtest jobs: %w", err)
	}

	const userTrafficRecordsSchema = `
CREATE TABLE IF NOT EXISTS user_traffic_records (
    username TEXT NOT NULL,
    date TEXT NOT NULL,
    total_limit INTEGER NOT NULL,
    total_used INTEGER NOT NULL,
    total_remaining INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (username, date)
);
`
	if _, err := r.db.Exec(userTrafficRecordsSchema); err != nil {
		return fmt.Errorf("migrate user_traffic_records: %w", err)
	}

	const userTokenSchema = `
CREATE TABLE IF NOT EXISTS user_tokens (
    username TEXT PRIMARY KEY,
    token TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

	if _, err := r.db.Exec(userTokenSchema); err != nil {
		return fmt.Errorf("migrate user_tokens: %w", err)
	}

	// 每用户 API 令牌(供 MCP / 程序化访问)。与订阅 token、全局 api_token 隔离;
	// 库里只存 token 的 sha256(token_hash),明文仅创建时返回一次。鉴权时按 hash 解析出 username,
	// 权限完全等同该用户登录态(普通用户令牌调 admin 接口会被 RequireAdmin 拦截)。
	const userAPITokenSchema = `
CREATE TABLE IF NOT EXISTS user_api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_user_api_tokens_username ON user_api_tokens(username);
`
	if _, err := r.db.Exec(userAPITokenSchema); err != nil {
		return fmt.Errorf("migrate user_api_tokens: %w", err)
	}

	// 如果 user_short_code 列不存在，则将其添加到 user_tokens 表中（3 字符代码）
	if err := r.ensureUserTokenColumn("user_short_code", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}

	// 为user_short_code创建唯一索引（仅适用于非空值）
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_tokens_user_short_code ON user_tokens(user_short_code) WHERE user_short_code != '';`); err != nil {
		return fmt.Errorf("create user_short_code index: %w", err)
	}

	// 为没有用户短代码的现有用户生成用户短代码
	if err := r.generateMissingUserShortCodes(); err != nil {
		return fmt.Errorf("generate missing user short codes: %w", err)
	}

	const sessionSchema = `
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    auth_epoch INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`

	if _, err := r.db.Exec(sessionSchema); err != nil {
		return fmt.Errorf("migrate sessions: %w", err)
	}
	if err := r.ensureTableColumn("sessions", "auth_epoch", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return fmt.Errorf("migrate sessions.auth_epoch: %w", err)
	}
	// Sessions created before credential/session revocation was made atomic may
	// survive a password change. Epoch 1 is also the column default so a brief
	// rollback to an older binary cannot mint sessions that a later upgrade trusts.
	if _, err := r.db.Exec(`DELETE FROM sessions WHERE auth_epoch < ?`, currentAuthSessionEpoch); err != nil {
		return fmt.Errorf("revoke legacy sessions: %w", err)
	}

	const userSchema = `
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    email TEXT,
    nickname TEXT,
    avatar_url TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

	if _, err := r.db.Exec(userSchema); err != nil {
		return fmt.Errorf("migrate users: %w", err)
	}

	if err := r.ensureUserColumn("email", "TEXT"); err != nil {
		return err
	}

	// users.email 反查索引 — ResolveUsernameByEmail 在 collector 每个 tick 对每个 email 都查一次,
	// 用户量上百时全表扫累积可观。email 字段允许 NULL,索引会忽略 NULL 行,体积小。
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`); err != nil {
		return fmt.Errorf("create idx_users_email: %w", err)
	}

	if err := r.ensureUserColumn("nickname", "TEXT"); err != nil {
		return err
	}

	if err := r.ensureUserColumn("avatar_url", "TEXT"); err != nil {
		return err
	}

	if err := r.syncNicknames(); err != nil {
		return err
	}

	if err := r.ensureUserColumn("role", "TEXT NOT NULL DEFAULT 'user'"); err != nil {
		return err
	}

	if err := r.ensureUserColumn("is_active", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}

	if err := r.ensureUserColumn("remark", "TEXT"); err != nil {
		return err
	}
	if err := r.ensureUserColumn("is_over_limit", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureUserColumn("totp_secret", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureUserColumn("totp_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureUserColumn("recovery_codes", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}

	// 给历史遗留、从未登录的用户补建 user_tokens(含 user_short_code),否则用户管理看不到订阅链接。
	// 必须在 users 与 user_tokens 表都建好后跑;新用户由 CreateUser 即时补齐。
	if err := r.ensureAllUsersHaveTokens(); err != nil {
		return fmt.Errorf("ensure all users have tokens: %w", err)
	}

	// === Telegram bot 相关 ===
	// users 加 3 列:tg_id / tg_handle / 绑定时间。tg_id 用 INTEGER 是因为 TG userId 是 int64,
	// 部分唯一索引(WHERE telegram_id IS NOT NULL)允许多用户都 NULL,但已绑必须唯一。
	if err := r.ensureUserColumn("telegram_id", "INTEGER"); err != nil {
		return err
	}
	if err := r.ensureUserColumn("telegram_username", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureUserColumn("telegram_bound_at", "TIMESTAMP"); err != nil {
		return err
	}
	// 用户自助通知开关(/notify on):默认关,开启后 bot 每日推流量 + 临期到期提醒。
	if err := r.ensureUserColumn("tg_notify_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 每月按 reset_day 自动重置流量周期 — 用 last_reset_at 防止 enforcer 同一天反复触发 reset
	if err := r.ensureUserColumn("last_reset_at", "TIMESTAMP"); err != nil {
		return err
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id) WHERE telegram_id IS NOT NULL;`); err != nil {
		return fmt.Errorf("create telegram_id index: %w", err)
	}

	// invite_codes:邀请码主表。kind=new 创建新账号,kind=bind 绑定到已有账号。
	// 设计要点:revoked + used_count < max_uses + expires_at(若设)未到 三者都满足才算"可用"。
	// package_id 仅 kind=new 时有用;kind=bind 必须填 bind_username,锁定到一个具体账号。
	const inviteCodeSchema = `
CREATE TABLE IF NOT EXISTS invite_codes (
    code           TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('new', 'bind')),
    bind_username  TEXT NOT NULL DEFAULT '',
    created_by     TEXT NOT NULL,
    package_id     INTEGER,
    max_uses       INTEGER NOT NULL DEFAULT 1,
    used_count     INTEGER NOT NULL DEFAULT 0,
    expires_at     TIMESTAMP,
    revoked        INTEGER NOT NULL DEFAULT 0,
    remark         TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    duration_months INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_created_by ON invite_codes(created_by);
CREATE INDEX IF NOT EXISTS idx_invite_codes_kind ON invite_codes(kind);
`
	if _, err := r.db.Exec(inviteCodeSchema); err != nil {
		return fmt.Errorf("migrate invite_codes: %w", err)
	}
	// 老库补列(已存在则忽略错误):kind=new 注册时账号有效期 = now + N 月。
	_, _ = r.db.Exec("ALTER TABLE invite_codes ADD COLUMN duration_months INTEGER NOT NULL DEFAULT 0")

	// invite_code_uses:邀请码使用记录(单次邀请码 max_uses=1 时唯一,但多次邀请码允许多行)。
	// 主键 (code, username) 防止同一用户重复消耗同一码。
	const inviteCodeUsesSchema = `
CREATE TABLE IF NOT EXISTS invite_code_uses (
    code       TEXT NOT NULL,
    username   TEXT NOT NULL,
    tg_id      INTEGER,
    used_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (code, username)
);
CREATE INDEX IF NOT EXISTS idx_invite_code_uses_username ON invite_code_uses(username);
`
	if _, err := r.db.Exec(inviteCodeUsesSchema); err != nil {
		return fmt.Errorf("migrate invite_code_uses: %w", err)
	}

	// tg_audit:所有 TG 操作审计(注册/绑定/解绑/admin 命令)。
	// 用于排查"TG 账号被盗后接管"事件;默认 90 天 retention(扫描任务可后续加)。
	const tgAuditSchema = `
CREATE TABLE IF NOT EXISTS tg_audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id     INTEGER,
    username  TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT '',
    at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_tg_audit_tg_id ON tg_audit(tg_id);
CREATE INDEX IF NOT EXISTS idx_tg_audit_username ON tg_audit(username);
CREATE INDEX IF NOT EXISTS idx_tg_audit_at ON tg_audit(at);
`
	if _, err := r.db.Exec(tgAuditSchema); err != nil {
		return fmt.Errorf("migrate tg_audit: %w", err)
	}

	const historySchema = `
CREATE TABLE IF NOT EXISTS rule_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    version INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(filename, version)
);
`

	if _, err := r.db.Exec(historySchema); err != nil {
		return fmt.Errorf("migrate rule_versions: %w", err)
	}

	const subscriptionSchema = `
CREATE TABLE IF NOT EXISTS subscription_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT '',
    description TEXT,
    rule_filename TEXT NOT NULL,
    buttons TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name)
);
`

	if _, err := r.db.Exec(subscriptionSchema); err != nil {
		return fmt.Errorf("migrate subscription_links: %w", err)
	}

	// 如果不存在，则将short_url列添加到subscription_links表中
	if err := r.ensureSubscriptionLinkColumn("short_url", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}

	// 为short_url创建唯一索引（仅适用于非空值）
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subscription_links_short_url ON subscription_links(short_url) WHERE short_url != '';`); err != nil {
		return fmt.Errorf("create short_url index: %w", err)
	}

	const nodesSchema = `
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    raw_url TEXT NOT NULL,
    node_name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    parsed_config TEXT NOT NULL,
    clash_config TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    tag TEXT NOT NULL DEFAULT '手动输入',
    tags TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_nodes_username ON nodes(username);
CREATE INDEX IF NOT EXISTS idx_nodes_protocol ON nodes(protocol);
CREATE INDEX IF NOT EXISTS idx_nodes_enabled ON nodes(enabled);
`

	if _, err := r.db.Exec(nodesSchema); err != nil {
		return fmt.Errorf("migrate nodes: %w", err)
	}

	// 如果现有节点表不存在，则将标签列添加到现有节点表中
	if err := r.ensureNodeColumn("tag", "TEXT NOT NULL DEFAULT '手动输入'"); err != nil {
		return err
	}

	// 多标签支持 — 兼容旧版架构:tag 是单标签兼容入口,tags 是 JSON 数组多标签。
	// 启动时一次性把已有 tag 同步进 tags(幂等):tags 为空 '[]' 且 tag 非空时,把 tag 包成单元素 JSON 数组。
	// 注意 SQL 字符串拼接里反斜杠转义:REPLACE 把 tag 内部的 " 转成 \" ,防止 JSON 解析失败。
	if err := r.ensureNodeColumn("tags", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	_, _ = r.db.Exec(`UPDATE nodes SET tags = '["' || REPLACE(tag, '"', '\"') || '"]'
                      WHERE (tags = '[]' OR tags = '') AND tag != '' AND tag IS NOT NULL`)

	// 如果不存在，则将original_server列添加到现有节点表中
	if err := r.ensureNodeColumn("original_server", "TEXT"); err != nil {
		return err
	}

	// IP 解析功能专用列：记录解析为 IP 前的原始域名（与 original_server 区分，后者是服务器名/路由键）
	if err := r.ensureNodeColumn("original_domain", "TEXT"); err != nil {
		return err
	}

	// 如果 inbound_tag 列不存在，则将其添加到现有节点表中
	if err := r.ensureNodeColumn("inbound_tag", "TEXT"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("inbound_mutation_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("chain_proxy_node_id", "INTEGER"); err != nil {
		return err
	}

	// 路由出站(routed node)字段:把一条 routing rule + 一个 outbound 当作虚拟节点
	// 挂在物理父节点下,被套餐绑定后自动给用户开子账号并加入 rule.user 数组。
	// node_type = 'physical' (默认) | 'routed' | 'forwarded'
	if err := r.ensureNodeColumn("node_type", "TEXT NOT NULL DEFAULT 'physical'"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("parent_node_id", "INTEGER"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("routed_outbound_tag", "TEXT"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("routed_outbound_json", "TEXT"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("routed_rule_marktag", "TEXT"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("routed_admin_email", "TEXT"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("routed_admin_credential", "TEXT"); err != nil {
		return err
	}
	// routed_owner: 'shared' (默认, 管理员创建, 进入套餐池) | 'user' (普通用户私有路由出站)
	if err := r.ensureNodeColumn("routed_owner", "TEXT NOT NULL DEFAULT 'shared'"); err != nil {
		return err
	}

	// 中转(relay):节点配置中转后,clash server/port 指向中转地址,这两列记原服务器地址/端口,
	// 用于列表展示「原服务器」+ 取消中转时还原。relay_orig_server 非空 ⟺ 该节点已配置中转。
	if err := r.ensureNodeColumn("relay_orig_server", "TEXT"); err != nil {
		return err
	}
	if err := r.ensureNodeColumn("relay_orig_port", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	const nodeSecretsSchema = `
CREATE TABLE IF NOT EXISTS node_secrets (
    node_id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER IF NOT EXISTS trg_nodes_delete_secret
AFTER DELETE ON nodes
BEGIN
    DELETE FROM node_secrets WHERE node_id = OLD.id;
END;
`
	if _, err := r.db.Exec(nodeSecretsSchema); err != nil {
		return fmt.Errorf("migrate node secrets: %w", err)
	}

	// 确保列存在后创建标签索引
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_nodes_tag ON nodes(tag);`); err != nil {
		return fmt.Errorf("create tag index: %w", err)
	}
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(node_type);`); err != nil {
		return fmt.Errorf("create node_type index: %w", err)
	}
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_nodes_parent ON nodes(parent_node_id);`); err != nil {
		return fmt.Errorf("create parent_node_id index: %w", err)
	}

	const subscribeFilesSchema = `
CREATE TABLE IF NOT EXISTS subscribe_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('create','import','upload','package')),
    filename TEXT NOT NULL,
    expire_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name)
);
CREATE INDEX IF NOT EXISTS idx_subscribe_files_type ON subscribe_files(type);
`

	if _, err := r.db.Exec(subscribeFilesSchema); err != nil {
		return fmt.Errorf("migrate subscribe_files: %w", err)
	}
	if err := r.ensureUniqueSubscribeFilenames(); err != nil {
		return err
	}

	// 用户-订阅关联表（多对多关系）
	// 关联到 subscribe_files 表
	const userSubscriptionsSchema = `
CREATE TABLE IF NOT EXISTS user_subscriptions (
    username TEXT NOT NULL,
    subscription_id INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (username, subscription_id),
    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY(subscription_id) REFERENCES subscribe_files(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_username ON user_subscriptions(username);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_subscription_id ON user_subscriptions(subscription_id);
`

	if _, err := r.db.Exec(userSubscriptionsSchema); err != nil {
		return fmt.Errorf("migrate user_subscriptions: %w", err)
	}

	const userSettingsSchema = `
CREATE TABLE IF NOT EXISTS user_settings (
    username TEXT PRIMARY KEY,
    force_sync_external INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
);
`

	if _, err := r.db.Exec(userSettingsSchema); err != nil {
		return fmt.Errorf("migrate user_settings: %w", err)
	}

	// 如果不存在，则将 match_rule 列添加到 user_settings 表中
	if err := r.ensureUserSettingsColumn("match_rule", "TEXT NOT NULL DEFAULT 'node_name'"); err != nil {
		return err
	}

	// 如果 user_settings 表不存在，则将其添加到 user_settings 表中
	if err := r.ensureUserSettingsColumn("cache_expire_minutes", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// 如果不存在，则将sync_traffic列添加到user_settings表中
	if err := r.ensureUserSettingsColumn("sync_traffic", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// 如果不存在，则将sync_scope列添加到user_settings表中
	if err := r.ensureUserSettingsColumn("sync_scope", "TEXT NOT NULL DEFAULT 'saved_only'"); err != nil {
		return err
	}

	// 如果不存在，则将 keep_node_name 列添加到 user_settings 表中
	if err := r.ensureUserSettingsColumn("keep_node_name", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}

	const externalSubscriptionsSchema = `
CREATE TABLE IF NOT EXISTS external_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    node_count INTEGER NOT NULL DEFAULT 0,
    last_sync_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE,
    UNIQUE(username, url)
);
CREATE INDEX IF NOT EXISTS idx_external_subscriptions_username ON external_subscriptions(username);
CREATE INDEX IF NOT EXISTS idx_external_subscriptions_url ON external_subscriptions(url);
`

	if _, err := r.db.Exec(externalSubscriptionsSchema); err != nil {
		return fmt.Errorf("migrate external_subscriptions: %w", err)
	}

	// 将流量字段添加到 external_subscriptions 表
	if err := r.ensureExternalSubscriptionColumn("upload", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureExternalSubscriptionColumn("download", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureExternalSubscriptionColumn("total", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureExternalSubscriptionColumn("expire", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureExternalSubscriptionColumn("user_agent", "TEXT NOT NULL DEFAULT 'clash-meta/2.4.0'"); err != nil {
		return err
	}
	if err := r.ensureExternalSubscriptionColumn("traffic_mode", "TEXT NOT NULL DEFAULT 'both'"); err != nil {
		return err
	}

	// 将 custom_rules_enabled 添加到 user_settings 表
	if err := r.ensureUserSettingsColumn("custom_rules_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// 将enable_short_link添加到user_settings表
	if err := r.ensureUserSettingsColumn("enable_short_link", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// 将 use_new_template_system 添加到 user_settings 表（默认 true）
	if err := r.ensureUserSettingsColumn("use_new_template_system", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}

	// 将enable_proxy_provider添加到user_settings表中
	if err := r.ensureUserSettingsColumn("enable_proxy_provider", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// 将node_name_filter添加到user_settings表（正则表达式过滤节点名称）
	if err := r.ensureUserSettingsColumn("node_name_filter", "TEXT NOT NULL DEFAULT '剩余|流量|到期|订阅|时间|重置'"); err != nil {
		return err
	}

	// 将node_order添加到user_settings表（用于显示顺序的节点ID的JSON数组）
	if err := r.ensureUserSettingsColumn("node_order", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}

	// 同步外部订阅时拼接订阅元信息(剩余流量/天数)到节点名。
	if err := r.ensureUserSettingsColumn("append_sub_info", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	// 将调试日志记录字段添加到 user_settings 表
	if err := r.ensureUserSettingsColumn("debug_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureUserSettingsColumn("debug_log_path", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureUserSettingsColumn("debug_started_at", "TIMESTAMP"); err != nil {
		return err
	}

	// 将 file_short_code 列添加到 subscribe_files 表（3 字符代码）
	if err := r.ensureSubscribeFileColumn("file_short_code", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}

	// 将 expire_at 列添加到 subscribe_files 表
	if err := r.ensureSubscribeFileColumn("expire_at", "TIMESTAMP"); err != nil {
		return err
	}

	// 在 subscribe_files 中为 file_short_code 创建唯一索引（仅适用于非空值）
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subscribe_files_file_short_code ON subscribe_files(file_short_code) WHERE file_short_code != '';`); err != nil {
		return fmt.Errorf("create subscribe_files file_short_code index: %w", err)
	}

	// 为没有的现有 subscribe_files 生成文件短代码
	if err := r.generateMissingFileShortCodes(); err != nil {
		return fmt.Errorf("generate missing file short codes: %w", err)
	}

	// 自定义短码支持
	if err := r.ensureSubscribeFileColumn("custom_short_code", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subscribe_files_custom_short_code ON subscribe_files(custom_short_code) WHERE custom_short_code != '';`); err != nil {
		return fmt.Errorf("create subscribe_files custom_short_code index: %w", err)
	}
	if err := r.ensureUserTokenColumn("custom_user_short_code", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_tokens_custom_user_short_code ON user_tokens(custom_user_short_code) WHERE custom_user_short_code != '';`); err != nil {
		return fmt.Errorf("create custom_user_short_code index: %w", err)
	}

	// 为全局设置创建system_config表
	const systemConfigSchema = `
CREATE TABLE IF NOT EXISTS system_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    proxy_groups_source_url TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	if _, err := r.db.Exec(systemConfigSchema); err != nil {
		return fmt.Errorf("migrate system_config: %w", err)
	}

	// 确保 system_config 恰好只有一行（单例模式）
	const ensureSystemConfigRow = `
INSERT INTO system_config (id, proxy_groups_source_url)
SELECT 1, ''
WHERE NOT EXISTS (SELECT 1 FROM system_config WHERE id = 1);
`
	if _, err := r.db.Exec(ensureSystemConfigRow); err != nil {
		return fmt.Errorf("seed system_config: %w", err)
	}

	// 将 client_compatibility_mode 列添加到 system_config 表
	if err := r.ensureSystemConfigColumn("client_compatibility_mode", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	if err := r.ensureSystemConfigColumn("enable_short_link", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}

	if err := r.ensureSystemConfigColumn("speed_collect_interval", "INTEGER NOT NULL DEFAULT 3"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("traffic_collect_interval", "INTEGER NOT NULL DEFAULT 60"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("traffic_check_interval", "INTEGER NOT NULL DEFAULT 120"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("heartbeat_interval", "INTEGER NOT NULL DEFAULT 30"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("agent_log_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	if err := r.ensureSystemConfigColumn("notify_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("telegram_bot_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("telegram_chat_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_login", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_subscribe_fetch", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_daily_traffic", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_server_offline", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_server_online", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_traffic_threshold", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_daily_traffic_time", "TEXT NOT NULL DEFAULT '08:00'"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_traffic_threshold_percent", "INTEGER NOT NULL DEFAULT 80"); err != nil {
		return err
	}

	// Phase 2: 9 个新通知开关 + 2 个数值参数(默认全 false / 默认值)
	if err := r.ensureSystemConfigColumn("notify_traffic_threshold_80", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_over_limit", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_package_expiring", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_package_expiring_days", "INTEGER NOT NULL DEFAULT 3"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_package_expired", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_user_registered", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_telegram_bound", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_cert_result", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_agent_long_offline", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_agent_long_offline_minutes", "INTEGER NOT NULL DEFAULT 30"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("notify_device_limit_exceeded", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}

	const customRulesSchema = `
CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('dns','rules','rule-providers')),
    mode TEXT NOT NULL CHECK (mode IN ('replace','prepend','append')),
    content TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, type)
);
CREATE INDEX IF NOT EXISTS idx_custom_rules_type ON custom_rules(type);
CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled ON custom_rules(enabled);
`

	if _, err := r.db.Exec(customRulesSchema); err != nil {
		return fmt.Errorf("migrate custom_rules: %w", err)
	}

	// 迁移现有的 custom_rules 表以支持"追加"模式
	if err := r.migrateCustomRulesAppendMode(); err != nil {
		return fmt.Errorf("migrate custom_rules append mode: %w", err)
	}

	// 将 auto_sync_custom_rules 列添加到 subscribe_files 表
	if err := r.ensureSubscribeFileColumn("auto_sync_custom_rules", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("template_filename", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("selected_custom_rule_ids", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("selected_override_script_ids", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("selected_tags", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	// 节点选择(取代 selected_tags 的精确粒度;非空 → 按 ID 过滤;空 → 回退 selected_tags 兼容老数据)
	if err := r.ensureSubscribeFileColumn("selected_node_ids", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("stats_server_ids", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("traffic_limit", "REAL"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("sort_order", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("raw_output", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSubscribeFileColumn("created_by", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}

	// 老 schema 的 subscribe_files.type CHECK 只允许 ('create','import','upload')，
	// 但代码层（subscribe_files.go SubscribeTypePackage）已经在写 'package'，导致 PackageAssign
	// 的 autoGenerateSubscription 写入失败。这里 idempotent rebuild 加上 'package'。
	if err := r.ensureSubscribeFileTypeAllowsPackage(); err != nil {
		return fmt.Errorf("migrate subscribe_files type CHECK: %w", err)
	}

	// 用户权限功能:custom_rules 加 created_by 列(custom_rules 表已在前面创建)。
	// templates 的 created_by 迁移下移到 templates 建表之后(见下方),否则全新库会因表未建而报错。
	// (override_scripts 已有 username, subscribe_files 已有 created_by。)历史行 created_by='' 视为 admin 创建。
	if err := r.ensureTableColumn("custom_rules", "created_by", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate custom_rules.created_by: %w", err)
	}

	// 创建 custom_rule_applications 表用于跟踪应用的内容
	const customRuleApplicationsSchema = `
CREATE TABLE IF NOT EXISTS custom_rule_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscribe_file_id INTEGER NOT NULL,
    custom_rule_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,
    rule_mode TEXT NOT NULL,
    applied_content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subscribe_file_id) REFERENCES subscribe_files(id) ON DELETE CASCADE,
    FOREIGN KEY (custom_rule_id) REFERENCES custom_rules(id) ON DELETE CASCADE,
    UNIQUE(subscribe_file_id, custom_rule_id, rule_type)
);
CREATE INDEX IF NOT EXISTS idx_custom_rule_applications_file ON custom_rule_applications(subscribe_file_id);
CREATE INDEX IF NOT EXISTS idx_custom_rule_applications_rule ON custom_rule_applications(custom_rule_id);
`

	if _, err := r.db.Exec(customRuleApplicationsSchema); err != nil {
		return fmt.Errorf("migrate custom_rule_applications: %w", err)
	}

	const overrideScriptsSchema = `
CREATE TABLE IF NOT EXISTS override_scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    hook TEXT NOT NULL,
    content TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_override_scripts_username ON override_scripts(username);
CREATE INDEX IF NOT EXISTS idx_override_scripts_hook ON override_scripts(hook);
`
	if _, err := r.db.Exec(overrideScriptsSchema); err != nil {
		return fmt.Errorf("migrate override_scripts: %w", err)
	}

	if err := r.ensureSystemConfigColumn("enable_override_scripts", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("ensure enable_override_scripts column: %w", err)
	}
	if err := r.ensureSystemConfigColumn("subscription_output_format", "TEXT NOT NULL DEFAULT 'yaml'"); err != nil {
		return fmt.Errorf("ensure subscription_output_format column: %w", err)
	}
	if err := r.ensureSystemConfigColumn("silent_mode", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("ensure silent_mode column: %w", err)
	}
	if err := r.ensureSystemConfigColumn("silent_mode_timeout", "INTEGER NOT NULL DEFAULT 15"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("enable_management_features", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("enable_root_short_links", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("default_template_filename", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// 节点名称倍率前缀:订阅生成时把套餐内 multiplier != 1 的节点 name 前缀加上 "{left}{mult}{right}"
	if err := r.ensureSystemConfigColumn("node_name_multiplier_prefix_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("node_name_multiplier_left", "TEXT NOT NULL DEFAULT '「'"); err != nil {
		return err
	}
	if err := r.ensureSystemConfigColumn("node_name_multiplier_right", "TEXT NOT NULL DEFAULT '」'"); err != nil {
		return err
	}

	const xrayServersSchema = `
CREATE TABLE IF NOT EXISTS xray_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    description TEXT,
    is_local INTEGER NOT NULL DEFAULT 0,
    is_primary INTEGER NOT NULL DEFAULT 0,
    process_id INTEGER NOT NULL DEFAULT 0,
    config_path TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, port)
);
CREATE INDEX IF NOT EXISTS idx_xray_servers_is_local ON xray_servers(is_local);
`

	if _, err := r.db.Exec(xrayServersSchema); err != nil {
		return fmt.Errorf("migrate xray_servers: %w", err)
	}

	// 如果不存在，则将 is_primary 列添加到 xray_servers（对于现有数据库）
	_, _ = r.db.Exec("ALTER TABLE xray_servers ADD COLUMN is_primary INTEGER NOT NULL DEFAULT 0")

	// 确保列存在后为 is_primary 创建索引
	_, _ = r.db.Exec("CREATE INDEX IF NOT EXISTS idx_xray_servers_is_primary ON xray_servers(is_primary)")

	// 添加流量限制并重置列到 xray_servers（如果不存在）
	_, _ = r.db.Exec("ALTER TABLE xray_servers ADD COLUMN traffic_limit INTEGER NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE xray_servers ADD COLUMN traffic_reset_day INTEGER NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE xray_servers ADD COLUMN traffic_used_offset INTEGER NOT NULL DEFAULT 0")

	// 包表 - 存储包模板
	const packagesSchema = `
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
    cycle_days INTEGER NOT NULL DEFAULT 30,
    is_reset INTEGER NOT NULL DEFAULT 0,
    reset_day INTEGER NOT NULL DEFAULT 1,
    nodes TEXT DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
`

	if _, err := r.db.Exec(packagesSchema); err != nil {
		return fmt.Errorf("migrate packages: %w", err)
	}

	// 如果不存在，则将节点列添加到包表中
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN nodes TEXT DEFAULT '[]'")

	// 如果不存在，则将 short_code 列添加到包表中
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN short_code TEXT DEFAULT ''")

	// 节点倍率(套餐级 per-node):JSON {"<node_id>": multiplier}。空 = 全部按 1.0
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN node_multipliers TEXT DEFAULT '{}'")

	// 为已有 package 补全短码
	if err := r.generateMissingPackageShortCodes(); err != nil {
		return fmt.Errorf("generate missing package short codes: %w", err)
	}

	// 如果不存在，则将 package_id 列添加到用户表中
	const addPackageIDColumn = `
ALTER TABLE users ADD COLUMN package_id INTEGER REFERENCES packages(id) ON DELETE SET NULL;
`
	// 如果列已存在则忽略错误
	_, _ = r.db.Exec(addPackageIDColumn)

	// 添加包裹分配跟踪字段（如果不存在）
	const addPackageFields = `
ALTER TABLE users ADD COLUMN package_start_date TIMESTAMP;
ALTER TABLE users ADD COLUMN package_end_date TIMESTAMP;
`
	_, _ = r.db.Exec("ALTER TABLE users ADD COLUMN package_start_date TIMESTAMP")
	_, _ = r.db.Exec("ALTER TABLE users ADD COLUMN package_end_date TIMESTAMP")
	_, _ = r.db.Exec("ALTER TABLE users ADD COLUMN is_reset INTEGER NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE users ADD COLUMN reset_day INTEGER NOT NULL DEFAULT 1")

	// 系统设置表 - 存储全局系统配置
	const systemSettingsSchema = `
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	if _, err := r.db.Exec(systemSettingsSchema); err != nil {
		return fmt.Errorf("迁移 system_settings: %w", err)
	}

	// 如果不存在则初始化 API token
	if err := r.initializeAPIToken(); err != nil {
		return fmt.Errorf("初始化 api token: %w", err)
	}

	// 远程服务器表 - 存储远程 RelayDock Agent 实例
	const remoteServersSchema = `
CREATE TABLE IF NOT EXISTS remote_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'connected', 'offline')),
    last_heartbeat TIMESTAMP,
    ip_address TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_remote_servers_token ON remote_servers(token);
CREATE INDEX IF NOT EXISTS idx_remote_servers_status ON remote_servers(status);
`
	if _, err := r.db.Exec(remoteServersSchema); err != nil {
		return fmt.Errorf("migrate remote_servers: %w", err)
	}

	// 安装事务锁跨进程持久化，避免 Agent 首连/scan_result 的自动配置在安装脚本
	// 尚可能回滚时改写 Xray 或 Nginx。nonce 只保存 SHA-256；ready_at 表示主控
	// 已完成管理面探测，prepared_at 表示 desired state 已下发，completed_at 是
	// 支持 Finalize 网络重试的完成墓碑。
	const remoteServerInstallationsSchema = `
CREATE TABLE IF NOT EXISTS remote_server_installations (
    server_id INTEGER PRIMARY KEY,
    nonce_hash TEXT NOT NULL CHECK (length(nonce_hash) = 64),
    started_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ready_at INTEGER,
    prepared_at INTEGER,
    completed_at INTEGER,
    rolling_back_at INTEGER,
    aborted_at INTEGER,
    FOREIGN KEY (server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
`
	if _, err := r.db.Exec(remoteServerInstallationsSchema); err != nil {
		return fmt.Errorf("migrate remote_server_installations: %w", err)
	}
	if err := r.ensureTableColumn("remote_server_installations", "prepared_at", "INTEGER"); err != nil {
		return fmt.Errorf("migrate remote_server_installations.prepared_at: %w", err)
	}
	if err := r.ensureTableColumn("remote_server_installations", "completed_at", "INTEGER"); err != nil {
		return fmt.Errorf("migrate remote_server_installations.completed_at: %w", err)
	}
	if err := r.ensureTableColumn("remote_server_installations", "rolling_back_at", "INTEGER"); err != nil {
		return fmt.Errorf("migrate remote_server_installations.rolling_back_at: %w", err)
	}
	if err := r.ensureTableColumn("remote_server_installations", "aborted_at", "INTEGER"); err != nil {
		return fmt.Errorf("migrate remote_server_installations.aborted_at: %w", err)
	}
	if err := r.ensureTableColumn("remote_server_installations", "started_at", "INTEGER"); err != nil {
		return fmt.Errorf("migrate remote_server_installations.started_at: %w", err)
	}
	// Legacy in-flight rows predate renewable leases. Their original start time
	// cannot be recovered, so pin it to their existing expiry rather than grant
	// them a fresh two-hour renewal window after an upgrade.
	if _, err := r.db.Exec(`UPDATE remote_server_installations SET started_at = expires_at WHERE started_at IS NULL`); err != nil {
		return fmt.Errorf("backfill remote_server_installations.started_at: %w", err)
	}

	// Admin-issued install commands carry a five-minute, single-consumption
	// download ticket. Only its SHA-256 digest is persisted; the long-lived node
	// token is never embedded in the command copied into shell history.
	const remoteServerInstallTicketsSchema = `
CREATE TABLE IF NOT EXISTS remote_server_install_tickets (
    ticket_hash TEXT PRIMARY KEY CHECK (length(ticket_hash) = 64),
    server_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    FOREIGN KEY (server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remote_server_install_tickets_server
    ON remote_server_install_tickets(server_id, expires_at);
`
	if _, err := r.db.Exec(remoteServerInstallTicketsSchema); err != nil {
		return fmt.Errorf("migrate remote_server_install_tickets: %w", err)
	}

	// 添加新列以进行重启检测和令牌刷新
	if err := r.ensureRemoteServerColumn("boot_time", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("xray_boot_time", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("boot_count", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("xray_boot_count", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("token_expires_at", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("last_token_refresh", "TIMESTAMP"); err != nil {
		return err
	}
	// 混合流量同步的连接模式字段
	if err := r.ensureRemoteServerColumn("connection_mode", "TEXT NOT NULL DEFAULT 'push'"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("pull_address", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("pull_port", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("pull_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("last_pull_at", "TIMESTAMP"); err != nil {
		return err
	}
	// 自动回退字段
	if err := r.ensureRemoteServerColumn("push_fail_count", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("last_push_fail", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("fallback_to_pull", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("fallback_at", "TIMESTAMP"); err != nil {
		return err
	}
	// 实时速度场
	if err := r.ensureRemoteServerColumn("current_upload_speed", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("current_download_speed", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("speed_updated_at", "TIMESTAMP"); err != nil {
		return err
	}
	// X 射线状态字段（来自扫描）
	if err := r.ensureRemoteServerColumn("xray_running", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("xray_version", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("xray_scanned_at", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("listen_port", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("traffic_limit", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("traffic_reset_day", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("domain", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// dual-stack IPv6 字段 — master HTTP 反向请求 v4 失败时 fallback 试 v6
	if err := r.ensureRemoteServerColumn("ip_address_v6", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// IPv6 启用开关(管理员控制)。默认 1(启用)保持历史行为:已有服务器不受影响。
	if err := r.ensureRemoteServerColumn("ipv6_enabled", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	// 上下线通知容忍阈值防抖:offline_since=检测到离线的时刻;offline_notified=本次离线周期是否已发下线通知。
	if err := r.ensureRemoteServerColumn("offline_since", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("offline_notified", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// WARP 安装状态 — agent 在 auth/heartbeat 时上报,master 用于 server 卡片 W badge 显示
	if err := r.ensureRemoteServerColumn("warp_installed", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 双令牌系统字段
	if err := r.ensureRemoteServerColumn("agent_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("agent_token_expires_at", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("last_agent_token_refresh", "TIMESTAMP"); err != nil {
		return err
	}
	// 443端口模式（nginx隧道）
	if err := r.ensureRemoteServerColumn("use_443", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 单独保存安装时的接管授权。历史 steal_mode 默认值曾是 tunnel，不能据此
	// 推断允许重装脚本接管 443；已有记录安全地迁移为关闭。
	if err := r.ensureRemoteServerColumn("steal_self", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("steal_mode", "TEXT NOT NULL DEFAULT 'tunnel'"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("nginx_mode", "TEXT NOT NULL DEFAULT 'managed'"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("site_type", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("site_value", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("time_offset_seconds", "INTEGER"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("xray_mode", "TEXT NOT NULL DEFAULT 'external'"); err != nil {
		return err
	}
	// External-mode Agent installation can intentionally finish before Xray is
	// present. Keep the deferred first configuration durable so a failed panel
	// deployment can be retried without treating it as an ordinary core update.
	if err := r.ensureRemoteServerColumn("xray_bootstrap_pending", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("traffic_used_offset", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 服务器层流量统计规则: both / upload / download
	// 影响节点流量聚合该服务器贡献的方向,用户流量仍按套餐 traffic_mode 算,二者独立。
	if err := r.ensureRemoteServerColumn("sort_order", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("traffic_stats_mode", "TEXT NOT NULL DEFAULT 'both'"); err != nil {
		return err
	}
	// traffic_source 决定 server.traffic_used 的数据源:
	//   'xray'(默认,向后兼容)  → SUM(node_traffic.uplink+downlink),跟现有口径一致
	//   'system'               → 服务器系统级网卡累计 RX/TX,跟 VPS 计费口径一致
	// 节点视图 / 用户视图 / 套餐 enforcement 永远走 xray 维度,不受此字段影响。
	if err := r.ensureRemoteServerColumn("traffic_source", "TEXT NOT NULL DEFAULT 'xray'"); err != nil {
		return err
	}
	// 系统流量 cycle 累计(reset_day 触发时归零)+ 上次 agent 上报快照(用于算 delta 与 reboot 检测)
	if err := r.ensureRemoteServerColumn("system_rx_cycle", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("system_tx_cycle", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("system_last_seen_rx", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("system_last_seen_tx", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// system_boot_time_unix 跟 agent 上报的 boot_time_unix 对比,变化 = 系统重启,重建基线不计 delta;
	// 不变但 rx_total 倒退 = 单次 /proc 异常,跳一次也不计 delta(防止瞬时回滚导致错误大 delta)。
	if err := r.ensureRemoteServerColumn("system_boot_time_unix", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("system_traffic_updated_at", "TIMESTAMP"); err != nil {
		return err
	}

	// DDNS 自动同步:agent 上报 IP 变化时,通过 DNS provider API 把 pull_address 域名的 A/AAAA 记录指到新 IP
	// ddns_provider_id=0 → 自动模式(用 FindCertificateForDomain 找匹配的通配符证书,取其 dns_provider_id)
	// ddns_provider_id>0 → 显式指定 DNS provider
	if err := r.ensureRemoteServerColumn("ddns_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("ddns_provider_id", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("ddns_last_synced_at", "TIMESTAMP"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("ddns_last_error", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := r.ensureRemoteServerColumn("ddns_pending", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// 服务器按 traffic_reset_day 自动重置流量时,记录上次重置时间(防同月反复)
	if err := r.ensureRemoteServerColumn("last_traffic_reset_at", "TIMESTAMP"); err != nil {
		return err
	}

	// 套餐限速字段
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN speed_limit_mbps REAL NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN device_limit INTEGER NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN auto_speed_limit_json TEXT DEFAULT ''")
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN traffic_mode TEXT NOT NULL DEFAULT 'oneway'")
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN template_filename TEXT NOT NULL DEFAULT ''")

	// 用户限速覆写字段
	_, _ = r.db.Exec("ALTER TABLE users ADD COLUMN speed_limit_override REAL")
	_, _ = r.db.Exec("ALTER TABLE users ADD COLUMN device_limit_override INTEGER")

	// 用户套餐总流量覆写(bytes)。NULL=继承套餐,0=显式不限,>0=覆写值。
	// 不设 DEFAULT,让历史用户迁移后保持既有的套餐口径。
	if err := r.ensureUserColumn("traffic_limit_override", "INTEGER"); err != nil {
		return err
	}

	// 套餐/用户 per-node 限速 + 客户端数(map[node_id] → 值;0=显式不限速,不含 key=继承上层)
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN node_speed_limits TEXT DEFAULT '{}'")
	_, _ = r.db.Exec("ALTER TABLE packages ADD COLUMN node_device_limits TEXT DEFAULT '{}'")
	_, _ = r.db.Exec("ALTER TABLE users ADD COLUMN node_speed_limit_overrides TEXT DEFAULT '{}'")
	_, _ = r.db.Exec("ALTER TABLE users ADD COLUMN node_device_limit_overrides TEXT DEFAULT '{}'")

	// 批量入站表 - 跟踪跨多个服务器批量添加的入站
	const batchInboundsSchema = `
CREATE TABLE IF NOT EXISTS batch_inbounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES xray_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_batch_inbounds_batch_id ON batch_inbounds(batch_id);
CREATE INDEX IF NOT EXISTS idx_batch_inbounds_server_id ON batch_inbounds(server_id);
CREATE INDEX IF NOT EXISTS idx_batch_inbounds_tag ON batch_inbounds(tag);
`
	if _, err := r.db.Exec(batchInboundsSchema); err != nil {
		return fmt.Errorf("migrate batch_inbounds: %w", err)
	}

	// 批量出站表 - 跟踪跨多个服务器批量添加的出站
	const batchOutboundsSchema = `
CREATE TABLE IF NOT EXISTS batch_outbounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES xray_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_batch_outbounds_batch_id ON batch_outbounds(batch_id);
CREATE INDEX IF NOT EXISTS idx_batch_outbounds_server_id ON batch_outbounds(server_id);
CREATE INDEX IF NOT EXISTS idx_batch_outbounds_tag ON batch_outbounds(tag);
`
	if _, err := r.db.Exec(batchOutboundsSchema); err != nil {
		return fmt.Errorf("migrate batch_outbounds: %w", err)
	}

	// 节点流量表 - 存储每个服务器的入站/出站流量
	const nodeTrafficSchema = `
CREATE TABLE IF NOT EXISTS node_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('inbound', 'outbound')),
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    total_uplink INTEGER NOT NULL DEFAULT 0,
    total_downlink INTEGER NOT NULL DEFAULT 0,
    last_uplink INTEGER NOT NULL DEFAULT 0,
    last_downlink INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, tag, type),
    FOREIGN KEY (server_id) REFERENCES xray_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_node_traffic_server_id ON node_traffic(server_id);
CREATE INDEX IF NOT EXISTS idx_node_traffic_tag ON node_traffic(tag);
CREATE INDEX IF NOT EXISTS idx_node_traffic_type ON node_traffic(type);
`
	if _, err := r.db.Exec(nodeTrafficSchema); err != nil {
		return fmt.Errorf("migrate node_traffic: %w", err)
	}

	// 用户流量表 - 存储每个服务器的用户流量
	const userTrafficSchema = `
CREATE TABLE IF NOT EXISTS user_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    total_uplink INTEGER NOT NULL DEFAULT 0,
    total_downlink INTEGER NOT NULL DEFAULT 0,
    last_uplink INTEGER NOT NULL DEFAULT 0,
    last_downlink INTEGER NOT NULL DEFAULT 0,
    cycle_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, username),
    FOREIGN KEY (server_id) REFERENCES xray_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_traffic_server_id ON user_traffic(server_id);
CREATE INDEX IF NOT EXISTS idx_user_traffic_username ON user_traffic(username);
`
	if _, err := r.db.Exec(userTrafficSchema); err != nil {
		return fmt.Errorf("migrate user_traffic: %w", err)
	}

	// user_email_traffic 跟 user_traffic 字段完全对齐,只是 key 换成 email — 保留 Xray stats 的
	// per-client 维度。collector 同一次循环里同时 UPSERT user_traffic(按 username 聚合,套餐扣减
	// 等热路径继续走它)和 user_email_traffic(per-email,前端 drilldown 等细粒度场景用)。
	// 必须在下面 rateCols 给本表加列之前建表,否则全新安装首启会报 no such table。
	const userEmailTrafficSchema = `
CREATE TABLE IF NOT EXISTS user_email_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    total_uplink INTEGER NOT NULL DEFAULT 0,
    total_downlink INTEGER NOT NULL DEFAULT 0,
    last_uplink INTEGER NOT NULL DEFAULT 0,
    last_downlink INTEGER NOT NULL DEFAULT 0,
    cycle_base_uplink INTEGER NOT NULL DEFAULT 0,
    cycle_base_downlink INTEGER NOT NULL DEFAULT 0,
    billable_bytes INTEGER NOT NULL DEFAULT 0,
    billable_fraction REAL NOT NULL DEFAULT 0,
    billable_initialized INTEGER NOT NULL DEFAULT 0,
    billable_username TEXT NOT NULL DEFAULT '',
    cycle_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, email),
    FOREIGN KEY (server_id) REFERENCES xray_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_email_traffic_server_id ON user_email_traffic(server_id);
CREATE INDEX IF NOT EXISTS idx_user_email_traffic_email ON user_email_traffic(email);
`
	if _, err := r.db.Exec(userEmailTrafficSchema); err != nil {
		return fmt.Errorf("migrate user_email_traffic: %w", err)
	}
	// 周期基线:月度重置时把 uplink/downlink 的当前值抬进 cycle_base_*,判定/展示只看 (uplink - base)。
	// 相比直接把 uplink 清零,这样保住了 total_* 的历史累计,也不需要动 collector 的 delta 逻辑。
	// 存量行 base=0 → 增量 == 当前累计值,与升级前行为完全一致。
	_, _ = r.db.Exec("ALTER TABLE user_email_traffic ADD COLUMN cycle_base_uplink INTEGER NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE user_email_traffic ADD COLUMN cycle_base_downlink INTEGER NOT NULL DEFAULT 0")
	// 计费用量在采集时按当时的套餐模式和节点倍率固化。存量行 initialized=0，
	// 首次采集/读取时按迁移时规则建立一次基线，之后套餐变更只影响新增流量。
	_, _ = r.db.Exec("ALTER TABLE user_email_traffic ADD COLUMN billable_bytes INTEGER NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE user_email_traffic ADD COLUMN billable_fraction REAL NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE user_email_traffic ADD COLUMN billable_initialized INTEGER NOT NULL DEFAULT 0")
	_, _ = r.db.Exec("ALTER TABLE user_email_traffic ADD COLUMN billable_username TEXT NOT NULL DEFAULT ''")

	// 流量快照表 - 存储每日流量快照以了解历史趋势
	const trafficSnapshotsSchema = `
CREATE TABLE IF NOT EXISTS traffic_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    inbound_uplink INTEGER NOT NULL DEFAULT 0,
    inbound_downlink INTEGER NOT NULL DEFAULT 0,
    outbound_uplink INTEGER NOT NULL DEFAULT 0,
    outbound_downlink INTEGER NOT NULL DEFAULT 0,
    user_uplink INTEGER NOT NULL DEFAULT 0,
    user_downlink INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, date),
    FOREIGN KEY (server_id) REFERENCES xray_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_traffic_snapshots_server_id ON traffic_snapshots(server_id);
CREATE INDEX IF NOT EXISTS idx_traffic_snapshots_date ON traffic_snapshots(date);
`
	if _, err := r.db.Exec(trafficSnapshotsSchema); err != nil {
		return fmt.Errorf("migrate traffic_snapshots: %w", err)
	}

	const nodeTrafficSnapshotsSchema = `
CREATE TABLE IF NOT EXISTS node_traffic_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    date TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, tag, date)
);
CREATE INDEX IF NOT EXISTS idx_node_traffic_snapshots_date ON node_traffic_snapshots(date);
`
	if _, err := r.db.Exec(nodeTrafficSnapshotsSchema); err != nil {
		return fmt.Errorf("migrate node_traffic_snapshots: %w", err)
	}

	// 老库快照表无 type 列 → 前端 serverOverviewList 无法过滤,sum(inbound+outbound snap) 远大于
	// sum(inbound live) → 减出负数 clamp 0 → 全部 server 今日/本周流量显示 0。
	// 兜底:ADD COLUMN type DEFAULT 'inbound' + 用 node_traffic 当前 (server_id, tag, type) 映射 backfill。
	// 已删除节点对应的历史 snapshot 行保持默认值 — server 视图也展示不到这些 tag,影响可忽略。
	if err := r.ensureTableColumn("node_traffic_snapshots", "type", "TEXT NOT NULL DEFAULT 'inbound'"); err != nil {
		return fmt.Errorf("ensure node_traffic_snapshots.type column: %w", err)
	}

	// backfill 与 rebuild 必须配套:
	// - 老 UNIQUE(server_id, tag, date) 下,(server,tag,date) 只能有一行 → UPDATE type 安全
	// - 新 UNIQUE(server_id, tag, type, date) 下,inbound/outbound 两行可共存 → 再跑 backfill
	//   会把 inbound 行 type 改成 outbound,撞上已存在的 outbound 行 → UNIQUE 冲突,启动失败
	// 所以:只在「即将 rebuild」时跑 backfill,且必须在 rebuild 之前(rebuild 会把 type 搬到新表)
	needsRebuild, err := r.nodeTrafficSnapshotsNeedsRebuild()
	if err != nil {
		log.Printf("[Migrate] check node_traffic_snapshots unique: %v", err)
	} else if needsRebuild {
		const backfillNodeSnapshotType = `
UPDATE node_traffic_snapshots AS s
SET type = (
    SELECT nt.type FROM node_traffic nt
    WHERE nt.server_id = s.server_id AND nt.tag = s.tag
    LIMIT 1
)
WHERE EXISTS (
    SELECT 1 FROM node_traffic nt
    WHERE nt.server_id = s.server_id AND nt.tag = s.tag AND nt.type = 'outbound'
)`
		if _, err := r.db.Exec(backfillNodeSnapshotType); err != nil {
			return fmt.Errorf("backfill node_traffic_snapshots.type: %w", err)
		}

		// 历史 bug:UNIQUE(server_id, tag, date) 没含 type → 同 (server, tag, date) 但不同 type
		// (一个 tag 同时是 inbound 和 outbound,常见于 routed 节点)的两行 INSERT 时,后者 ON CONFLICT
		// UPDATE 覆盖前者,snapshot 表只剩一行,字段值是「后插入那条 type 的数值」。
		// 前端按 type 分别查 baseline 时,某 type 的 baseline 拿到对手 type 的数值(uplink/downlink 错位),
		// downlink 被错位 baseline 减成 0 → 「下行 0」假象。
		// 修复:rebuild table 把 UNIQUE 改成 (server_id, tag, type, date)。
		log.Printf("[Migrate] node_traffic_snapshots UNIQUE missing type column, rebuilding table")
		if err := r.rebuildNodeTrafficSnapshots(); err != nil {
			return fmt.Errorf("rebuild node_traffic_snapshots: %w", err)
		}
	}

	const userTrafficSnapshotsSchema = `
CREATE TABLE IF NOT EXISTS user_traffic_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    date TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, username, date)
);
CREATE INDEX IF NOT EXISTS idx_user_traffic_snapshots_date ON user_traffic_snapshots(date);
`
	if _, err := r.db.Exec(userTrafficSnapshotsSchema); err != nil {
		return fmt.Errorf("migrate user_traffic_snapshots: %w", err)
	}

	// 用户-邮箱级流量快照 — 与 user_email_traffic 同粒度(server_id, email,其中 email=<username>__<inbound_tag>)。
	// 节点详情(node-users)/用户详情(user-nodes)按时间范围算"用户在某节点的增量"时,减这张表的 baseline。
	// user_traffic_snapshots 只到 username 级、且口径是 user_traffic 表,粒度和源都对不上详情(详情走 user_email_traffic),
	// 所以单独建一张 email 级快照表。存 cycle-delta(uplink/downlink),跟 user_email_traffic 一致。
	const userEmailTrafficSnapshotsSchema = `
CREATE TABLE IF NOT EXISTS user_email_traffic_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    date TEXT NOT NULL,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, email, date)
);
CREATE INDEX IF NOT EXISTS idx_user_email_traffic_snapshots_date ON user_email_traffic_snapshots(date);
`
	if _, err := r.db.Exec(userEmailTrafficSnapshotsSchema); err != nil {
		return fmt.Errorf("migrate user_email_traffic_snapshots: %w", err)
	}

	// 服务器系统级流量快照 — daily snapshot 之 system 维度。
	// 每天 00:00 跟 node_traffic_snapshots / user_traffic_snapshots 一起拍,记下"此刻的 rx_cycle / tx_cycle"。
	// 前端服务器视图 traffic_source='system' 模式下用 (当前 cycle - 该日 baseline) 算今日/本周/本月增量,
	// 跟 xray path 的 node snapshot 减法语义一致 — UI 三个时间按钮在 system 模式下也能工作。
	const serverSystemTrafficSnapshotsSchema = `
CREATE TABLE IF NOT EXISTS server_system_traffic_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    rx_cycle INTEGER NOT NULL DEFAULT 0,
    tx_cycle INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, date)
);
CREATE INDEX IF NOT EXISTS idx_server_system_traffic_snapshots_date ON server_system_traffic_snapshots(date);
`
	if _, err := r.db.Exec(serverSystemTrafficSnapshotsSchema); err != nil {
		return fmt.Errorf("migrate server_system_traffic_snapshots: %w", err)
	}

	// ACL4SSR 规则配置模板表
	const templatesSchema = `
CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'clash' CHECK (category IN ('clash','surge')),
    template_url TEXT NOT NULL DEFAULT '',
    rule_source TEXT NOT NULL DEFAULT '',
    use_proxy INTEGER NOT NULL DEFAULT 0,
    enable_include_all INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name)
);
CREATE INDEX IF NOT EXISTS idx_templates_category ON templates(category);
`

	if _, err := r.db.Exec(templatesSchema); err != nil {
		return fmt.Errorf("migrate templates: %w", err)
	}

	// 用户权限功能:templates 加 created_by 列(必须在 templates 建表之后,否则全新库会"no such table")。
	if err := r.ensureTableColumn("templates", "created_by", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate templates.created_by: %w", err)
	}

	// 代理提供商配置表
	const proxyProviderConfigsSchema = `
CREATE TABLE IF NOT EXISTS proxy_provider_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    external_subscription_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'http',
    interval INTEGER DEFAULT 3600,
    proxy TEXT DEFAULT 'DIRECT',
    size_limit INTEGER DEFAULT 0,
    header TEXT,
    health_check_enabled INTEGER DEFAULT 1,
    health_check_url TEXT DEFAULT 'https://www.gstatic.com/generate_204',
    health_check_interval INTEGER DEFAULT 300,
    health_check_timeout INTEGER DEFAULT 5000,
    health_check_lazy INTEGER DEFAULT 1,
    health_check_expected_status INTEGER DEFAULT 204,
    filter TEXT,
    exclude_filter TEXT,
    exclude_type TEXT,
    geo_ip_filter TEXT,
    override TEXT,
    process_mode TEXT DEFAULT 'client',
    access_token_hash TEXT NOT NULL DEFAULT '',
    access_token_ciphertext TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (external_subscription_id) REFERENCES external_subscriptions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_proxy_provider_configs_username ON proxy_provider_configs(username);
CREATE INDEX IF NOT EXISTS idx_proxy_provider_configs_external_subscription_id ON proxy_provider_configs(external_subscription_id);
`
	if _, err := r.db.Exec(proxyProviderConfigsSchema); err != nil {
		return fmt.Errorf("migrate proxy_provider_configs: %w", err)
	}

	// 添加 geo_ip_filter 列（为旧数据库迁移）
	if err := r.ensureProxyProviderConfigColumn("geo_ip_filter", "TEXT"); err != nil {
		return fmt.Errorf("ensure geo_ip_filter column: %w", err)
	}
	if err := r.ensureProxyProviderConfigColumn("access_token_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("ensure proxy provider access token hash: %w", err)
	}
	if err := r.ensureProxyProviderConfigColumn("access_token_ciphertext", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("ensure proxy provider access token ciphertext: %w", err)
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_provider_configs_access_token_hash ON proxy_provider_configs(access_token_hash) WHERE access_token_hash != ''`); err != nil {
		return fmt.Errorf("create proxy provider access token index: %w", err)
	}
	// Legacy databases can contain duplicate owner/name pairs that prevent a
	// unique index from being installed. Keep those rows available for manual
	// repair, while triggers prevent every new insert or rename from extending
	// the inconsistency. The error text intentionally contains "unique" so the
	// storage API maps trigger aborts to ErrProxyProviderConfigExists.
	const proxyProviderOwnerNameTriggers = `
CREATE TRIGGER IF NOT EXISTS trg_proxy_provider_configs_owner_name_insert
BEFORE INSERT ON proxy_provider_configs
WHEN NEW.name != '' AND EXISTS (
    SELECT 1 FROM proxy_provider_configs
    WHERE username = NEW.username AND name = NEW.name
)
BEGIN
    SELECT RAISE(ABORT, 'proxy provider owner-name unique conflict');
END;
CREATE TRIGGER IF NOT EXISTS trg_proxy_provider_configs_owner_name_update
BEFORE UPDATE OF username, name ON proxy_provider_configs
WHEN NEW.name != '' AND EXISTS (
    SELECT 1 FROM proxy_provider_configs
    WHERE username = NEW.username AND name = NEW.name AND id != OLD.id
)
BEGIN
    SELECT RAISE(ABORT, 'proxy provider owner-name unique conflict');
END;
`
	if _, err := r.db.Exec(proxyProviderOwnerNameTriggers); err != nil {
		return fmt.Errorf("create proxy provider owner-name triggers: %w", err)
	}
	var duplicateProviderNames int
	if err := r.db.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT username, name FROM proxy_provider_configs
			WHERE name != '' GROUP BY username, name HAVING COUNT(*) > 1
		)`).Scan(&duplicateProviderNames); err != nil {
		return fmt.Errorf("check duplicate proxy provider names: %w", err)
	}
	if duplicateProviderNames == 0 {
		if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_provider_configs_owner_name ON proxy_provider_configs(username, name) WHERE name != ''`); err != nil {
			return fmt.Errorf("create proxy provider owner-name index: %w", err)
		}
	} else {
		// Preserve legacy rows instead of making the service unbootable. The
		// triggers reject additional duplicates and the renderer fails closed
		// until an owner resolves the existing conflict.
		log.Printf("[Migrate] skipped proxy provider owner-name index: %d duplicate name group(s) require manual resolution", duplicateProviderNames)
	}

	// 证书表 - 存储由 ACME 管理的 SSL/TLS 证书
	const certificatesSchema = `
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    email TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT 'letsencrypt',
    cert_path TEXT,
    key_path TEXT,
    cert_pem TEXT,
    key_pem TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'valid', 'expired', 'failed')),
    expiry_date TIMESTAMP,
    issue_date TIMESTAMP,
    auto_renew INTEGER NOT NULL DEFAULT 1,
    challenge_mode TEXT NOT NULL DEFAULT 'standalone' CHECK (challenge_mode IN ('standalone', 'webroot', 'dns', 'manual')),
    webroot_path TEXT,
    remote_server_id INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    dns_provider_id INTEGER NOT NULL DEFAULT 0,
    deploy_target TEXT NOT NULL DEFAULT 'none',
    deploy_cert_path TEXT,
    deploy_key_path TEXT,
    auto_deploy INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain, remote_server_id)
);
CREATE INDEX IF NOT EXISTS idx_certificates_domain ON certificates(domain);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_remote_server_id ON certificates(remote_server_id);
CREATE INDEX IF NOT EXISTS idx_certificates_expiry_date ON certificates(expiry_date);
`
	if _, err := r.db.Exec(certificatesSchema); err != nil {
		return fmt.Errorf("migrate certificates: %w", err)
	}

	// 迁移：为现有数据库添加新列
	for _, col := range []struct{ name, def string }{
		{"dns_provider_id", "INTEGER NOT NULL DEFAULT 0"},
		{"deploy_target", "TEXT NOT NULL DEFAULT 'none'"},
		{"deploy_cert_path", "TEXT"},
		{"deploy_key_path", "TEXT"},
		{"auto_deploy", "INTEGER NOT NULL DEFAULT 0"},
	} {
		r.db.Exec(fmt.Sprintf("ALTER TABLE certificates ADD COLUMN %s %s", col.name, col.def))
	}

	// 迁移：如果 CHECK 约束已过时，则重建表（challenge_mode 中缺少 dns 或 manual）
	var checkSQL string
	row := r.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='certificates'`)
	if row.Scan(&checkSQL) == nil && (!strings.Contains(checkSQL, "'dns'") || !strings.Contains(checkSQL, "'manual'")) {
		r.db.Exec(`ALTER TABLE certificates RENAME TO _certificates_old`)
		r.db.Exec(certificatesSchema)
		r.db.Exec(`INSERT INTO certificates SELECT * FROM _certificates_old`)
		r.db.Exec(`DROP TABLE _certificates_old`)
	}

	// DNS 提供商表 - 存储可重复使用的 DNS API 凭据
	const dnsProvidersSchema = `
CREATE TABLE IF NOT EXISTS dns_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider_type TEXT NOT NULL,
    credentials TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	if _, err := r.db.Exec(dnsProvidersSchema); err != nil {
		return fmt.Errorf("migrate dns_providers: %w", err)
	}

	const userInboundConfigsSchema = `
CREATE TABLE IF NOT EXISTS user_inbound_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    inbound_tag TEXT NOT NULL,
    protocol TEXT NOT NULL,
    credential_json TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	if _, err := r.db.Exec(userInboundConfigsSchema); err != nil {
		return fmt.Errorf("migrate user_inbound_configs: %w", err)
	}
	// 历史去重(同 username+server_id+inbound_tag 保留最早一条)+ 唯一索引:根治并发绑套餐写入的
	// 「同用户同入站多条凭据」。加了唯一索引后 SaveUserInboundConfig 的 ON CONFLICT DO NOTHING 才生效,
	// DB 层兜底不再产生重复。DELETE 去重 + CREATE UNIQUE INDEX IF NOT EXISTS 均幂等,可每次启动跑。
	if _, err := r.db.Exec(`DELETE FROM user_inbound_configs WHERE id NOT IN (
		SELECT MIN(id) FROM user_inbound_configs GROUP BY username, server_id, inbound_tag)`); err != nil {
		return fmt.Errorf("dedup user_inbound_configs: %w", err)
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_inbound_configs_uniq
		ON user_inbound_configs(username, server_id, inbound_tag)`); err != nil {
		return fmt.Errorf("index user_inbound_configs: %w", err)
	}

	const userOutboundsSchema = `
CREATE TABLE IF NOT EXISTS user_outbounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    inbound_tag TEXT NOT NULL,
    outbound_tag TEXT NOT NULL,
    outbound_json TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
);
`
	if _, err := r.db.Exec(userOutboundsSchema); err != nil {
		return fmt.Errorf("migrate user_outbounds: %w", err)
	}

	// 用户子账号:一个 RelayDock 用户在某 routed 节点上的 Xray client 凭据。
	// is_active=0 表示已下线(从 inbound clients + routing rule.user 移除),但凭据保留供续费恢复用。
	const userSubaccountsSchema = `
CREATE TABLE IF NOT EXISTS user_subaccounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    routed_node_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    credential_json TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(routed_node_id, username),
    UNIQUE(routed_node_id, email),
    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_subacc_user ON user_subaccounts(username);
CREATE INDEX IF NOT EXISTS idx_subacc_email ON user_subaccounts(email);
CREATE INDEX IF NOT EXISTS idx_subacc_routed ON user_subaccounts(routed_node_id);
`
	if _, err := r.db.Exec(userSubaccountsSchema); err != nil {
		return fmt.Errorf("migrate user_subaccounts: %w", err)
	}

	// xray 配置快照:主控维护的 agent xray 完整 config.json 版本链,用于
	//   (1) 跑路兜底 — agent 端 VPS 跑路换机后,从主控下发 current 一键恢复
	//   (2) 反向兜底 — 主控端跑路新部署后,从 agent 自动拉回 current 反向恢复
	//   (3) 历史回滚 — 用户配置改错可挑历史 snapshot 下发回滚
	//   (4) inbound list cache 的 source — 套餐绑/解绑批量算 cred 时,从 current snapshot 派生 inbound protocol/settings
	// status 状态机:
	//   - 'current': 每 server 至多 1 行,代表"主控所知 agent 当前实际配置"
	//   - 'old':     被替换的历史版本,可用于回滚展示
	//   - 'pending_recovery': agent 之前 status=offline 后重连且 hash 漂移,master 不自动接管,
	//                        把上报内容写到这个状态等用户在 UI 决策(恢复 current / 接受为新 current)
	// source 标识:
	//   - 'agent_report':        首连 / 重连同步时由 agent 上报创建
	//   - 'master_write':        master 主动写 agent 配置后 refresh 创建
	//   - 'manual_accept':       用户在 UI 上接受 pending_recovery 升级为 current
	const xrayConfigSnapshotsSchema = `
CREATE TABLE IF NOT EXISTS server_xray_config_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id   INTEGER NOT NULL,
    config_json TEXT    NOT NULL,
    config_hash TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_xray_snap_server_status ON server_xray_config_snapshots(server_id, status);
CREATE INDEX IF NOT EXISTS idx_xray_snap_server_created ON server_xray_config_snapshots(server_id, created_at DESC);
`
	if _, err := r.db.Exec(xrayConfigSnapshotsSchema); err != nil {
		return fmt.Errorf("migrate server_xray_config_snapshots: %w", err)
	}
	// Repair any historical split-brain rows before enforcing the invariant.
	// The newest current snapshot wins; pending recovery also keeps only the
	// newest candidate. Old snapshots remain available for manual rollback.
	if _, err := r.db.Exec(`UPDATE server_xray_config_snapshots
		SET status = 'old'
		WHERE status = 'current'
		  AND id NOT IN (
			SELECT MAX(id) FROM server_xray_config_snapshots
			WHERE status = 'current' GROUP BY server_id
		  )`); err != nil {
		return fmt.Errorf("repair duplicate current xray snapshots: %w", err)
	}
	if _, err := r.db.Exec(`DELETE FROM server_xray_config_snapshots
		WHERE status = 'pending_recovery'
		  AND id NOT IN (
			SELECT MAX(id) FROM server_xray_config_snapshots
			WHERE status = 'pending_recovery' GROUP BY server_id
		  )`); err != nil {
		return fmt.Errorf("repair duplicate pending xray snapshots: %w", err)
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_xray_snap_one_current
		ON server_xray_config_snapshots(server_id) WHERE status = 'current'`); err != nil {
		return fmt.Errorf("enforce one current xray snapshot: %w", err)
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_xray_snap_one_pending
		ON server_xray_config_snapshots(server_id) WHERE status = 'pending_recovery'`); err != nil {
		return fmt.Errorf("enforce one pending xray snapshot: %w", err)
	}

	// 用户路由出站操作日志:记录每条创建/删除,用于每日次数限制。
	// 单条 routing 变更都会触发 agent 重启 xray,所以必须按"操作次数"限速而不仅按"当前持有数量"。
	const userRoutedOutboundActionsSchema = `
CREATE TABLE IF NOT EXISTS user_routed_outbound_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_uroa_user_time ON user_routed_outbound_actions(username, created_at);
`
	if _, err := r.db.Exec(userRoutedOutboundActionsSchema); err != nil {
		return fmt.Errorf("migrate user_routed_outbound_actions: %w", err)
	}

	const trafficThresholdNotifiedSchema = `
CREATE TABLE IF NOT EXISTS traffic_threshold_notified (
    server_id INTEGER PRIMARY KEY,
    notified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	if _, err := r.db.Exec(trafficThresholdNotifiedSchema); err != nil {
		return fmt.Errorf("migrate traffic_threshold_notified: %w", err)
	}

	const userTrafficThresholdNotifiedSchema = `
CREATE TABLE IF NOT EXISTS user_traffic_threshold_notified (
    username TEXT PRIMARY KEY,
    limit_bytes INTEGER NOT NULL,
    notified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
`
	if _, err := r.db.Exec(userTrafficThresholdNotifiedSchema); err != nil {
		return fmt.Errorf("migrate user_traffic_threshold_notified: %w", err)
	}

	const announcementSchema = `
CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL DEFAULT 'general',
    title TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    node_id INTEGER NOT NULL DEFAULT 0,
    via_bot INTEGER NOT NULL DEFAULT 1,
    via_miniapp INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    bot_delivered_at TIMESTAMP
);
`
	if _, err := r.db.Exec(announcementSchema); err != nil {
		return fmt.Errorf("migrate announcements: %w", err)
	}
	// Older announcement tables predate node targeting and bot delivery state.
	// CREATE TABLE IF NOT EXISTS does not add columns to those installations, so
	// repair them before creating an index or issuing the new SELECT statements.
	if err := r.ensureTableColumn("announcements", "node_id", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("migrate announcements node_id: %w", err)
	}
	if err := r.ensureTableColumn("announcements", "bot_delivered_at", "TIMESTAMP"); err != nil {
		return fmt.Errorf("migrate announcements bot_delivered_at: %w", err)
	}
	const announcementBotDeliverySchema = `
CREATE TABLE IF NOT EXISTS announcement_bot_deliveries (
    announcement_id INTEGER NOT NULL,
    telegram_id INTEGER NOT NULL,
    delivered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (announcement_id, telegram_id),
    FOREIGN KEY (announcement_id) REFERENCES announcements(id) ON DELETE CASCADE
);
`
	if _, err := r.db.Exec(announcementBotDeliverySchema); err != nil {
		return fmt.Errorf("migrate announcement_bot_deliveries: %w", err)
	}
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_announcements_active
		ON announcements(via_bot, via_miniapp, bot_delivered_at, expires_at, created_at)`); err != nil {
		return fmt.Errorf("migrate announcements index: %w", err)
	}

	// 服务器分享(联邦)相关表:必须在迁移阶段建好,因为 ListRemoteServers 会 EXISTS 查询 federated_servers。
	if err := r.ensureSharedServersTable(context.Background()); err != nil {
		return fmt.Errorf("migrate shared_servers: %w", err)
	}
	if err := r.ensureFederatedServersTable(context.Background()); err != nil {
		return fmt.Errorf("migrate federated_servers: %w", err)
	}
	if err := r.migrateManagedNodes(); err != nil {
		return err
	}
	if err := r.migrateManagedInboundResources(); err != nil {
		return err
	}
	if err := r.migrateWireGuardProbePeers(); err != nil {
		return err
	}
	if err := r.migrateRemoteInboundOwnership(); err != nil {
		return err
	}
	if err := r.migrateRemoteInboundDesired(); err != nil {
		return err
	}
	if err := r.migrateForwarding(); err != nil {
		return err
	}
	if err := r.migrateRemoteServerDeletionTasks(); err != nil {
		return err
	}

	// 一次性数据修复:旧 ResolveUsernameByEmail 不识别 users.email 作为主账号 inbound 的 client.email,
	// 把流量记到 username=email 的孤行(如 user_traffic.username='share@2ha.me' 而不是 'share')。
	// 修复后需把孤行 merge 回 username 行 — last_uplink/downlink 必须相加(下一轮 collector 会按合并后
	// 的 cumulative 算 delta,基线必须包含两个旧客户端的累计)。
	if err := r.mergeOrphanEmailTrafficRows(context.Background()); err != nil {
		return fmt.Errorf("migrate user_traffic email merge: %w", err)
	}
	if err := r.initializeLegacyBillableTraffic(context.Background()); err != nil {
		return fmt.Errorf("migrate collection-time billable traffic: %w", err)
	}

	// 一次性清理:扫 xray snapshot 表把已废弃 marktag(如 fix_openai)的 routing.rules 移除 + 重算 hash,
	// 跟 agent 端 removeDeprecatedRoutingRules 双端对齐,避免 agent 升级重启上报新 config 时
	// hash 不一致触发"配置漂移待恢复"提示。函数本身幂等,失败不阻塞启动。
	if err := r.MigrateRemoveDeprecatedRulesFromSnapshots(context.Background()); err != nil {
		log.Printf("[Migrate] remove deprecated routing rules from snapshots: %v", err)
	}

	return nil
}

// mergeOrphanEmailTrafficRows 一次性数据修复(幂等):
//
// 把 user_traffic 中 username 等于某个 users.email 的"孤行"合并到对应 username 行,
// last_*/total_* 相加(基线累计),然后删除孤行。同样处理 user_email_traffic.email 的展示一致性
// 不需要 — user_email_traffic 本就 by email,无需迁移。
//
// 幂等标记写入 system_settings,key='_migrate_merge_email_traffic_done'。下次启动检测到就跳过。
func (r *TrafficRepository) mergeOrphanEmailTrafficRows(ctx context.Context) error {
	const doneKey = "_migrate_merge_email_traffic_done"
	var done string
	_ = r.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = ?`, doneKey).Scan(&done)
	if done == "1" {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// 合并 — ON CONFLICT 时 total_*/last_* 相加,保留下一轮 delta 计算的基线正确。
	if _, err := tx.ExecContext(ctx, `
INSERT INTO user_traffic (server_id, username, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, cycle_start, updated_at)
SELECT src.server_id, u.username,
       src.uplink, src.downlink,
       src.total_uplink, src.total_downlink,
       src.last_uplink, src.last_downlink,
       src.cycle_start, src.updated_at
FROM user_traffic src
JOIN users u ON u.email = src.username
WHERE u.email IS NOT NULL AND u.email != '' AND u.username != u.email
ON CONFLICT(server_id, username) DO UPDATE SET
    total_uplink   = user_traffic.total_uplink   + excluded.total_uplink,
    total_downlink = user_traffic.total_downlink + excluded.total_downlink,
    last_uplink    = user_traffic.last_uplink    + excluded.last_uplink,
    last_downlink  = user_traffic.last_downlink  + excluded.last_downlink,
    updated_at     = CURRENT_TIMESTAMP
`); err != nil {
		return fmt.Errorf("merge orphan rows: %w", err)
	}

	// 删除已合并的孤行。
	if _, err := tx.ExecContext(ctx, `
DELETE FROM user_traffic
WHERE username IN (
    SELECT email FROM users WHERE email IS NOT NULL AND email != '' AND username != email
)
`); err != nil {
		return fmt.Errorf("delete merged rows: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO system_settings (key, value) VALUES (?, '1')
ON CONFLICT(key) DO UPDATE SET value = '1'
`, doneKey); err != nil {
		return fmt.Errorf("mark migration done: %w", err)
	}

	return tx.Commit()
}

// 返回按创建顺序排列的所有已配置订阅链接。
func (r *TrafficRepository) ListSubscriptionLinks(ctx context.Context) ([]SubscriptionLink, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, name, type, COALESCE(description, ''), rule_filename, buttons, COALESCE(short_url, ''), created_at, updated_at FROM subscription_links ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list subscription links: %w", err)
	}
	defer rows.Close()

	var links []SubscriptionLink
	for rows.Next() {
		link, err := scanSubscriptionLink(rows)
		if err != nil {
			return nil, fmt.Errorf("scan subscription link: %w", err)
		}
		links = append(links, link)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscription links: %w", err)
	}

	return links, nil
}

// 通过唯一名称检索订阅链接。
func (r *TrafficRepository) GetSubscriptionByName(ctx context.Context, name string) (SubscriptionLink, error) {
	var link SubscriptionLink
	if r == nil || r.db == nil {
		return link, errors.New("traffic repository not initialized")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return link, errors.New("subscription name is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT id, name, type, COALESCE(description, ''), rule_filename, buttons, COALESCE(short_url, ''), created_at, updated_at FROM subscription_links WHERE name = ? LIMIT 1`, name)
	result, err := scanSubscriptionLink(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return link, ErrSubscriptionNotFound
		}
		return link, fmt.Errorf("get subscription by name: %w", err)
	}

	return result, nil
}

// 通过标识符检索订阅链接。
func (r *TrafficRepository) GetSubscriptionByID(ctx context.Context, id int64) (SubscriptionLink, error) {
	var link SubscriptionLink
	if r == nil || r.db == nil {
		return link, errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return link, errors.New("subscription id is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT id, name, type, COALESCE(description, ''), rule_filename, buttons, COALESCE(short_url, ''), created_at, updated_at FROM subscription_links WHERE id = ? LIMIT 1`, id)
	result, err := scanSubscriptionLink(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return link, ErrSubscriptionNotFound
		}
		return link, fmt.Errorf("get subscription by id: %w", err)
	}

	return result, nil
}

// 返回最早创建的订阅链接。
func (r *TrafficRepository) GetFirstSubscriptionLink(ctx context.Context) (SubscriptionLink, error) {
	var link SubscriptionLink
	if r == nil || r.db == nil {
		return link, errors.New("traffic repository not initialized")
	}

	row := r.db.QueryRowContext(ctx, `SELECT id, name, type, COALESCE(description, ''), rule_filename, buttons, COALESCE(short_url, ''), created_at, updated_at FROM subscription_links ORDER BY id ASC LIMIT 1`)
	result, err := scanSubscriptionLink(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return link, ErrSubscriptionNotFound
		}
		return link, fmt.Errorf("get first subscription: %w", err)
	}

	return result, nil
}

// 插入新的订阅链接定义。
func (r *TrafficRepository) CreateSubscriptionLink(ctx context.Context, link SubscriptionLink) (SubscriptionLink, error) {
	if r == nil || r.db == nil {
		return SubscriptionLink{}, errors.New("traffic repository not initialized")
	}

	link.Name = strings.TrimSpace(link.Name)
	link.Type = strings.TrimSpace(link.Type)
	link.Description = strings.TrimSpace(link.Description)
	link.RuleFilename = strings.TrimSpace(link.RuleFilename)

	if link.Name == "" {
		return SubscriptionLink{}, errors.New("subscription name is required")
	}
	if link.Type == "" {
		link.Type = link.Name
	}
	if link.RuleFilename == "" {
		return SubscriptionLink{}, errors.New("rule filename is required")
	}
	if err := ValidateSubscribeFilename(link.RuleFilename); err != nil {
		return SubscriptionLink{}, err
	}

	encodedButtons, err := encodeSubscriptionButtons(link.Buttons)
	if err != nil {
		return SubscriptionLink{}, fmt.Errorf("encode subscription buttons: %w", err)
	}

	res, err := r.db.ExecContext(ctx, `INSERT INTO subscription_links (name, type, description, rule_filename, buttons) VALUES (?, ?, ?, ?, ?)`, link.Name, link.Type, link.Description, link.RuleFilename, encodedButtons)
	if err != nil {
		lowered := strings.ToLower(err.Error())
		if strings.Contains(lowered, "unique") {
			return SubscriptionLink{}, ErrSubscriptionExists
		}
		return SubscriptionLink{}, fmt.Errorf("create subscription link: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return SubscriptionLink{}, fmt.Errorf("fetch subscription id: %w", err)
	}

	return r.GetSubscriptionByID(ctx, id)
}

// 更新现有订阅链接。
func (r *TrafficRepository) UpdateSubscriptionLink(ctx context.Context, link SubscriptionLink) (SubscriptionLink, error) {
	if r == nil || r.db == nil {
		return SubscriptionLink{}, errors.New("traffic repository not initialized")
	}

	if link.ID <= 0 {
		return SubscriptionLink{}, errors.New("subscription id is required")
	}

	link.Name = strings.TrimSpace(link.Name)
	link.Type = strings.TrimSpace(link.Type)
	link.Description = strings.TrimSpace(link.Description)
	link.RuleFilename = strings.TrimSpace(link.RuleFilename)

	if link.Name == "" {
		return SubscriptionLink{}, errors.New("subscription name is required")
	}
	if link.Type == "" {
		link.Type = link.Name
	}
	if link.RuleFilename == "" {
		return SubscriptionLink{}, errors.New("rule filename is required")
	}
	if err := ValidateSubscribeFilename(link.RuleFilename); err != nil {
		return SubscriptionLink{}, err
	}

	encodedButtons, err := encodeSubscriptionButtons(link.Buttons)
	if err != nil {
		return SubscriptionLink{}, fmt.Errorf("encode subscription buttons: %w", err)
	}

	res, err := r.db.ExecContext(ctx, `UPDATE subscription_links SET name = ?, type = ?, description = ?, rule_filename = ?, buttons = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, link.Name, link.Type, link.Description, link.RuleFilename, encodedButtons, link.ID)
	if err != nil {
		lowered := strings.ToLower(err.Error())
		if strings.Contains(lowered, "unique") {
			return SubscriptionLink{}, ErrSubscriptionExists
		}
		return SubscriptionLink{}, fmt.Errorf("update subscription link: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return SubscriptionLink{}, fmt.Errorf("subscription update rows affected: %w", err)
	}
	if affected == 0 {
		return SubscriptionLink{}, ErrSubscriptionNotFound
	}

	return r.GetSubscriptionByID(ctx, link.ID)
}

// 删除订阅链接定义。
func (r *TrafficRepository) DeleteSubscriptionLink(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("subscription id is required")
	}

	res, err := r.db.ExecContext(ctx, `DELETE FROM subscription_links WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete subscription link: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("subscription delete rows affected: %w", err)
	}
	if affected == 0 {
		return ErrSubscriptionNotFound
	}

	return nil
}

// 返回引用给定规则文件名的订阅数量。
func (r *TrafficRepository) CountSubscriptionsByFilename(ctx context.Context, filename string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}

	filename = strings.TrimSpace(filename)
	if filename == "" {
		return 0, errors.New("rule filename is required")
	}
	if err := ValidateSubscribeFilename(filename); err != nil {
		return 0, err
	}

	var count int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM subscription_links WHERE rule_filename = ?`, filename).Scan(&count); err != nil {
		return 0, fmt.Errorf("count subscription by filename: %w", err)
	}

	return count, nil
}

func (r *TrafficRepository) ensureUserColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return fmt.Errorf("users table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE users ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

func (r *TrafficRepository) ensureUserTokenColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(user_tokens)`)
	if err != nil {
		return fmt.Errorf("user_tokens table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE user_tokens ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

func (r *TrafficRepository) ensureSubscriptionLinkColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(subscription_links)`)
	if err != nil {
		return fmt.Errorf("subscription_links table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE subscription_links ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

func (r *TrafficRepository) ensureNodeColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(nodes)`)
	if err != nil {
		return fmt.Errorf("nodes table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE nodes ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

// nodeTrafficSnapshotsNeedsRebuild 检测 node_traffic_snapshots 的 UNIQUE 约束是否漏 type 列。
// 用 PRAGMA index_list 找所有 UNIQUE index,逐个用 index_info 查列名集合;
// 任一 UNIQUE 同时包含 server_id+tag+date 但**不**包含 type → 旧 schema bug,需要 rebuild。
func (r *TrafficRepository) nodeTrafficSnapshotsNeedsRebuild() (bool, error) {
	rows, err := r.db.Query(`PRAGMA index_list(node_traffic_snapshots)`)
	if err != nil {
		return false, fmt.Errorf("index_list: %w", err)
	}
	defer rows.Close()
	type idxInfo struct {
		name   string
		unique int
	}
	var indexes []idxInfo
	for rows.Next() {
		var seq int
		var name, origin string
		var uniq, partial int
		if err := rows.Scan(&seq, &name, &uniq, &origin, &partial); err != nil {
			return false, fmt.Errorf("scan index_list: %w", err)
		}
		if uniq == 1 {
			indexes = append(indexes, idxInfo{name: name, unique: uniq})
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, idx := range indexes {
		cols, err := r.db.Query(fmt.Sprintf(`PRAGMA index_info(%q)`, idx.name))
		if err != nil {
			return false, fmt.Errorf("index_info %s: %w", idx.name, err)
		}
		colSet := make(map[string]bool)
		for cols.Next() {
			var seqno, cid int
			var colName string
			if err := cols.Scan(&seqno, &cid, &colName); err != nil {
				cols.Close()
				return false, fmt.Errorf("scan index_info: %w", err)
			}
			colSet[strings.ToLower(colName)] = true
		}
		cols.Close()
		// 旧 UNIQUE 形状:含 server_id + tag + date 但不含 type
		if colSet["server_id"] && colSet["tag"] && colSet["date"] && !colSet["type"] {
			return true, nil
		}
	}
	return false, nil
}

// rebuildNodeTrafficSnapshots 重建表把 UNIQUE 改为 (server_id, tag, type, date)。
// 流程:RENAME 旧表 → CREATE 新表 → COPY 数据 → DROP 旧表 → CREATE INDEX。
// 全程单事务,失败回滚。COPY 时用 GROUP BY (server_id, tag, type, date) 去重保住任意一份
// (历史 bug 期间多 type 行已被覆盖,COPY 时若有残留重复直接 max() 聚合,以最大值为准最接近真实)。
func (r *TrafficRepository) rebuildNodeTrafficSnapshots() error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmts := []string{
		`ALTER TABLE node_traffic_snapshots RENAME TO node_traffic_snapshots_old`,
		`CREATE TABLE node_traffic_snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			tag TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'inbound',
			date TEXT NOT NULL,
			uplink INTEGER NOT NULL DEFAULT 0,
			downlink INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(server_id, tag, type, date)
		)`,
		`INSERT INTO node_traffic_snapshots(server_id, tag, type, date, uplink, downlink, created_at)
			SELECT server_id, tag, COALESCE(type, 'inbound'), date, MAX(uplink), MAX(downlink), MAX(created_at)
			FROM node_traffic_snapshots_old
			GROUP BY server_id, tag, COALESCE(type, 'inbound'), date`,
		`DROP TABLE node_traffic_snapshots_old`,
		`CREATE INDEX IF NOT EXISTS idx_node_traffic_snapshots_date ON node_traffic_snapshots(date)`,
	}
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("rebuild step (%s): %w", strings.SplitN(s, " ", 3)[1], err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rebuild: %w", err)
	}
	log.Printf("[Migrate] node_traffic_snapshots rebuilt with UNIQUE(server_id, tag, type, date)")
	return nil
}

// ensureTableColumn 通用列迁移:表名作参数,列不存在时 ALTER ADD。
// 注意 table 必须是代码内写死的常量(非用户输入),避免 SQL 注入。
func (r *TrafficRepository) ensureTableColumn(table, name, definition string) error {
	rows, err := r.db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return fmt.Errorf("%s table info: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan %s table info: %w", table, err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}
	if _, err := r.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, name, definition)); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, name, err)
	}
	return nil
}

func (r *TrafficRepository) ensureUserSettingsColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(user_settings)`)
	if err != nil {
		return fmt.Errorf("user_settings table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE user_settings ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

func (r *TrafficRepository) migrateCustomRulesAppendMode() error {
	// 通过尝试插入虚拟行来检查表是否已经支持"追加"模式
	// 如果失败，我们需要重新创建表
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 检查追加模式是否已经支持
	_, err = tx.Exec(`INSERT INTO custom_rules (name, type, mode, content) VALUES ('__test_append__', 'rules', 'append', 'test')`)
	if err == nil {
		// 支持追加模式，清理测试行
		tx.Exec(`DELETE FROM custom_rules WHERE name = '__test_append__'`)
		tx.Commit()
		return nil
	}

	// 需要迁移 - 使用新约束重新创建表
	// 1. 重命名旧表
	if _, err := tx.Exec(`ALTER TABLE custom_rules RENAME TO custom_rules_old`); err != nil {
		return fmt.Errorf("rename old table: %w", err)
	}

	// 2. 使用更新的约束创建新表
	const newTableSchema = `
CREATE TABLE custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('dns','rules','rule-providers')),
    mode TEXT NOT NULL CHECK (mode IN ('replace','prepend','append')),
    content TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, type)
);
CREATE INDEX IF NOT EXISTS idx_custom_rules_type ON custom_rules(type);
CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled ON custom_rules(enabled);
`
	if _, err := tx.Exec(newTableSchema); err != nil {
		return fmt.Errorf("create new table: %w", err)
	}

	// 3.从旧表复制数据
	if _, err := tx.Exec(`
		INSERT INTO custom_rules (id, name, type, mode, content, enabled, created_at, updated_at)
		SELECT id, name, type, mode, content, enabled, created_at, updated_at
		FROM custom_rules_old
	`); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	// 4. 删除旧表
	if _, err := tx.Exec(`DROP TABLE custom_rules_old`); err != nil {
		return fmt.Errorf("drop old table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (r *TrafficRepository) ensureSubscribeFileColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(subscribe_files)`)
	if err != nil {
		return fmt.Errorf("subscribe_files table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE subscribe_files ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

// ensureSubscribeFileTypeAllowsPackage 把 subscribe_files.type 的 CHECK 约束扩成支持 'package'。
// 老 schema 是 CHECK (type IN ('create','import','upload'))，但代码层早就有 SubscribeTypePackage='package'，
// PackageAssign 自动生成订阅会因为约束失败。SQLite 不支持改 CHECK，只能 rebuild 表。
// idempotent：检测到 sql 里已有 'package' 直接 return。
func (r *TrafficRepository) ensureSubscribeFileTypeAllowsPackage() error {
	var schema string
	err := r.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='subscribe_files'`).Scan(&schema)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil // 表还不存在，新装会用包含 'package' 的 schema（本次部署同时改了 schema 常量）
		}
		return fmt.Errorf("read subscribe_files schema: %w", err)
	}
	if strings.Contains(schema, "'package'") {
		return nil
	}

	oldCheck := "CHECK (type IN ('create','import','upload'))"
	newCheck := "CHECK (type IN ('create','import','upload','package'))"
	if !strings.Contains(schema, oldCheck) {
		// 不是预期的老 CHECK，可能 schema 已经手动改过别的形态，保守起见不动
		return fmt.Errorf("subscribe_files schema 未找到预期 CHECK 子句，请手工检查:\n%s", schema)
	}

	newTableSQL := strings.Replace(schema, oldCheck, newCheck, 1)
	// 只替换 CREATE TABLE 语句里的表名（首个出现）
	newTableSQL = strings.Replace(newTableSQL, "subscribe_files", "subscribe_files_new", 1)

	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(newTableSQL); err != nil {
		return fmt.Errorf("create subscribe_files_new: %w  sql=%s", err, newTableSQL)
	}
	// 字段顺序一致，可以直接 SELECT *
	if _, err := tx.Exec("INSERT INTO subscribe_files_new SELECT * FROM subscribe_files"); err != nil {
		return fmt.Errorf("copy rows: %w", err)
	}
	if _, err := tx.Exec("DROP TABLE subscribe_files"); err != nil {
		return fmt.Errorf("drop old: %w", err)
	}
	if _, err := tx.Exec("ALTER TABLE subscribe_files_new RENAME TO subscribe_files"); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// 重建 indexes（DROP TABLE 把它们也带走了）
	idxStmts := []string{
		`CREATE INDEX IF NOT EXISTS idx_subscribe_files_type ON subscribe_files(type)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_subscribe_files_file_short_code ON subscribe_files(file_short_code) WHERE file_short_code != ''`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_subscribe_files_custom_short_code ON subscribe_files(custom_short_code) WHERE custom_short_code != ''`,
	}
	for _, s := range idxStmts {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("rebuild index: %w  sql=%s", err, s)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (r *TrafficRepository) ensureExternalSubscriptionColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(external_subscriptions)`)
	if err != nil {
		return fmt.Errorf("external_subscriptions table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE external_subscriptions ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

func (r *TrafficRepository) ensureProxyProviderConfigColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(proxy_provider_configs)`)
	if err != nil {
		return fmt.Errorf("proxy_provider_configs table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE proxy_provider_configs ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

func (r *TrafficRepository) ensureSystemConfigColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(system_config)`)
	if err != nil {
		return fmt.Errorf("system_config table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE system_config ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

func (r *TrafficRepository) ensureRemoteServerColumn(name, definition string) error {
	rows, err := r.db.Query(`PRAGMA table_info(remote_servers)`)
	if err != nil {
		return fmt.Errorf("remote_servers table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if strings.EqualFold(colName, name) {
			return nil
		}
	}

	alter := fmt.Sprintf("ALTER TABLE remote_servers ADD COLUMN %s %s", name, definition)
	if _, err := r.db.Exec(alter); err != nil {
		return fmt.Errorf("add column %s: %w", name, err)
	}

	return nil
}

func (r *TrafficRepository) syncNicknames() error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if _, err := r.db.Exec(`UPDATE users SET nickname = username WHERE nickname IS NULL OR nickname = ''`); err != nil {
		return fmt.Errorf("sync nicknames: %w", err)
	}

	return nil
}

// 更新提供的日期的聚合流量使用情况。
func (r *TrafficRepository) RecordDaily(ctx context.Context, date time.Time, totalLimit, totalUsed, totalRemaining int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	normalized := date.UTC().Format("2006-01-02")

	const stmt = `
INSERT INTO traffic_records (date, total_limit, total_used, total_remaining)
VALUES (?, ?, ?, ?)
ON CONFLICT(date) DO UPDATE SET
    total_limit = excluded.total_limit,
    total_used = excluded.total_used,
    total_remaining = excluded.total_remaining,
    created_at = CURRENT_TIMESTAMP;
`

	if _, err := r.db.ExecContext(ctx, stmt, normalized, totalLimit, totalUsed, totalRemaining); err != nil {
		return fmt.Errorf("upsert traffic record: %w", err)
	}

	return nil
}

// 返回最多请求数量的最新流量记录，按从最新到最旧的顺序排列。
func (r *TrafficRepository) ListRecent(ctx context.Context, limit int) ([]TrafficRecord, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if limit <= 0 {
		limit = 30
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT date, total_limit, total_used, total_remaining
FROM traffic_records
ORDER BY date DESC
LIMIT ?;
`, limit)
	if err != nil {
		return nil, fmt.Errorf("list recent traffic records: %w", err)
	}
	defer rows.Close()

	var records []TrafficRecord
	for rows.Next() {
		var (
			dateStr        string
			totalLimit     int64
			totalUsed      int64
			totalRemaining int64
		)

		if err := rows.Scan(&dateStr, &totalLimit, &totalUsed, &totalRemaining); err != nil {
			return nil, fmt.Errorf("scan traffic record: %w", err)
		}

		parsed, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("parse traffic record date: %w", err)
		}

		records = append(records, TrafficRecord{
			Date:           parsed,
			TotalLimit:     totalLimit,
			TotalUsed:      totalUsed,
			TotalRemaining: totalRemaining,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate traffic records: %w", err)
	}

	return records, nil
}

func (r *TrafficRepository) RecordUserDaily(ctx context.Context, username string, date time.Time, totalLimit, totalUsed, totalRemaining int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	normalized := date.UTC().Format("2006-01-02")
	const stmt = `
INSERT INTO user_traffic_records (username, date, total_limit, total_used, total_remaining)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(username, date) DO UPDATE SET
    total_limit = excluded.total_limit,
    total_used = excluded.total_used,
    total_remaining = excluded.total_remaining,
    created_at = CURRENT_TIMESTAMP;
`
	if _, err := r.db.ExecContext(ctx, stmt, username, normalized, totalLimit, totalUsed, totalRemaining); err != nil {
		return fmt.Errorf("upsert user traffic record: %w", err)
	}
	return nil
}

func (r *TrafficRepository) ListUserRecent(ctx context.Context, username string, limit int) ([]TrafficRecord, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if limit <= 0 {
		limit = 30
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT date, total_limit, total_used, total_remaining
FROM user_traffic_records
WHERE username = ?
ORDER BY date DESC
LIMIT ?;
`, username, limit)
	if err != nil {
		return nil, fmt.Errorf("list user recent traffic records: %w", err)
	}
	defer rows.Close()

	var records []TrafficRecord
	for rows.Next() {
		var (
			dateStr        string
			totalLimit     int64
			totalUsed      int64
			totalRemaining int64
		)
		if err := rows.Scan(&dateStr, &totalLimit, &totalUsed, &totalRemaining); err != nil {
			return nil, fmt.Errorf("scan user traffic record: %w", err)
		}
		parsed, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("parse user traffic record date: %w", err)
		}
		records = append(records, TrafficRecord{
			Date:           parsed,
			TotalLimit:     totalLimit,
			TotalUsed:      totalUsed,
			TotalRemaining: totalRemaining,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user traffic records: %w", err)
	}
	return records, nil
}

// 返回给定用户名的现有令牌或创建一个新令牌。
func (r *TrafficRepository) GetOrCreateUserToken(ctx context.Context, username string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("username is required")
	}

	const selectStmt = `SELECT token FROM user_tokens WHERE username = ? LIMIT 1;`
	var token string
	if err := r.db.QueryRowContext(ctx, selectStmt, username).Scan(&token); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("query user token: %w", err)
		}

		// 使用重试逻辑生成新令牌和用户短代码
		newToken := uuid.NewString()
		const maxRetries = 10
		for i := 0; i < maxRetries; i++ {
			newUserShortCode, err := generateUserShortCode()
			if err != nil {
				return "", fmt.Errorf("generate user short code: %w", err)
			}

			const insertStmt = `INSERT INTO user_tokens (username, token, user_short_code, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP);`
			if _, err := r.db.ExecContext(ctx, insertStmt, username, newToken, newUserShortCode); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique") && strings.Contains(strings.ToLower(err.Error()), "user_short_code") {
					// 用户短代码冲突，重试
					continue
				}
				return "", fmt.Errorf("insert user token: %w", err)
			}
			break
		}
		token = newToken
	}

	return token, nil
}

// 为提供的用户名生成并存储一个新令牌。
func (r *TrafficRepository) ResetUserToken(ctx context.Context, username string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("username is required")
	}

	newToken := uuid.NewString()

	// 生成具有重试逻辑的新用户短代码
	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		newUserShortCode, err := generateUserShortCode()
		if err != nil {
			return "", fmt.Errorf("generate user short code: %w", err)
		}

		const stmt = `
INSERT INTO user_tokens (username, token, user_short_code, updated_at)
VALUES (?, ?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(username) DO UPDATE SET
    token = excluded.token,
    user_short_code = excluded.user_short_code,
    updated_at = CURRENT_TIMESTAMP;
`

		if _, err := r.db.ExecContext(ctx, stmt, username, newToken, newUserShortCode); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") && strings.Contains(strings.ToLower(err.Error()), "user_short_code") {
				// 用户短代码冲突，重试
				continue
			}
			return "", fmt.Errorf("reset user token: %w", err)
		}

		return newToken, nil
	}

	return "", errors.New("failed to generate unique user short code after retries")
}

// 返回与提供的令牌关联的用户名（如果存在）。
func (r *TrafficRepository) ValidateUserToken(ctx context.Context, token string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("token is required")
	}

	const stmt = `SELECT username FROM user_tokens WHERE token = ? LIMIT 1;`
	var username string
	if err := r.db.QueryRowContext(ctx, stmt, token).Scan(&username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrTokenNotFound
		}
		return "", fmt.Errorf("query user token by value: %w", err)
	}

	return username, nil
}

// 为文件短代码生成随机的 3 个字符的字符串。
func generateFileShortCode() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 3

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}

	return string(bytes), nil
}

// 为用户短代码生成随机字符串,长度随机 3-10 位。
// 随机长度 + 不可由用户自定义,使短码不可枚举,从根本上消除"自定义短码冲突可用性预言机"问题。
func generateUserShortCode() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 先随机决定长度(3-10)
	lenByte := make([]byte, 1)
	if _, err := rand.Read(lenByte); err != nil {
		return "", fmt.Errorf("generate random length: %w", err)
	}
	length := 3 + int(lenByte[0])%8 // 3..10

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}

	return string(bytes), nil
}

// 为没有文件短代码的 subscribe_files 生成文件短代码。
func (r *TrafficRepository) generateMissingFileShortCodes() error {
	rows, err := r.db.Query(`SELECT id FROM subscribe_files WHERE file_short_code = '' OR file_short_code IS NULL`)
	if err != nil {
		return fmt.Errorf("query subscribe files without file short codes: %w", err)
	}
	defer rows.Close()

	var fileIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan file ID: %w", err)
		}
		fileIDs = append(fileIDs, id)
	}

	// 为每个文件生成文件短代码
	for _, id := range fileIDs {
		const maxRetries = 10
		for i := 0; i < maxRetries; i++ {
			newShortCode, err := generateFileShortCode()
			if err != nil {
				return fmt.Errorf("generate file short code: %w", err)
			}

			_, err = r.db.Exec(`UPDATE subscribe_files SET file_short_code = ? WHERE id = ?`, newShortCode, id)
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique") {
					continue // 使用新的短代码重试
				}
				return fmt.Errorf("update file short code for file %d: %w", id, err)
			}
			break // 成功，移至下一个文件
		}
	}

	return nil
}

// 为没有的 user_tokens 生成用户短代码。
func (r *TrafficRepository) generateMissingUserShortCodes() error {
	// 获取所有不带用户短代码的user_token
	rows, err := r.db.Query(`SELECT username FROM user_tokens WHERE user_short_code = '' OR user_short_code IS NULL`)
	if err != nil {
		return fmt.Errorf("query users without user short codes: %w", err)
	}
	defer rows.Close()

	var usernames []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return fmt.Errorf("scan username: %w", err)
		}
		usernames = append(usernames, username)
	}

	// 为每个用户生成用户短代码
	for _, username := range usernames {
		const maxRetries = 10
		for i := 0; i < maxRetries; i++ {
			newShortCode, err := generateUserShortCode()
			if err != nil {
				return fmt.Errorf("generate user short code: %w", err)
			}

			_, err = r.db.Exec(`UPDATE user_tokens SET user_short_code = ? WHERE username = ?`, newShortCode, username)
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique") {
					continue // 使用新的短代码重试
				}
				return fmt.Errorf("update user short code for user %s: %w", username, err)
			}
			break // 成功，移至下一个用户
		}
	}

	return nil
}

// ensureAllUsersHaveTokens 为 users 表里还没有 user_tokens 行的用户补建 token + user_short_code。
// 短码原本是懒生成(GetOrCreateUserToken,首次登录 / 访问订阅时才建行),导致管理员新建但从未登录的
// 用户在用户管理看不到订阅链接。启动迁移时一次性补齐历史遗留用户;新用户由 CreateUser 即时补齐。
func (r *TrafficRepository) ensureAllUsersHaveTokens() error {
	rows, err := r.db.Query(`SELECT username FROM users WHERE username NOT IN (SELECT username FROM user_tokens)`)
	if err != nil {
		return fmt.Errorf("query users without tokens: %w", err)
	}
	var usernames []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return fmt.Errorf("scan username: %w", err)
		}
		usernames = append(usernames, u)
	}
	rows.Close()

	for _, username := range usernames {
		token := uuid.NewString()
		const maxRetries = 10
		for i := 0; i < maxRetries; i++ {
			shortCode, err := generateUserShortCode()
			if err != nil {
				return fmt.Errorf("generate user short code: %w", err)
			}
			_, err = r.db.Exec(`INSERT INTO user_tokens (username, token, user_short_code, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`, username, token, shortCode)
			if err != nil {
				le := strings.ToLower(err.Error())
				if strings.Contains(le, "unique") && strings.Contains(le, "user_short_code") {
					continue // 短码冲突,换一个重试
				}
				if strings.Contains(le, "unique") {
					break // username 已存在(并发已补),跳过
				}
				return fmt.Errorf("insert user token for %s: %w", username, err)
			}
			break
		}
	}
	return nil
}

func generatePackageShortCode() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 3
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes), nil
}

func (r *TrafficRepository) generateMissingPackageShortCodes() error {
	rows, err := r.db.Query(`SELECT id FROM packages WHERE short_code = '' OR short_code IS NULL`)
	if err != nil {
		return fmt.Errorf("query packages without short codes: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan package ID: %w", err)
		}
		ids = append(ids, id)
	}

	for _, id := range ids {
		const maxRetries = 10
		for i := 0; i < maxRetries; i++ {
			code, err := generatePackageShortCode()
			if err != nil {
				return err
			}
			_, err = r.db.Exec(`UPDATE packages SET short_code = ? WHERE id = ?`, code, id)
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique") {
					continue
				}
				return fmt.Errorf("update package short code for %d: %w", id, err)
			}
			break
		}
	}
	return nil
}

func (r *TrafficRepository) GetAllPackageShortCodes(ctx context.Context) (map[string]int64, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT COALESCE(short_code, ''), id FROM packages WHERE short_code != ''`)
	if err != nil {
		return nil, fmt.Errorf("query all package short codes: %w", err)
	}
	defer rows.Close()

	codes := make(map[string]int64)
	for rows.Next() {
		var code string
		var id int64
		if err := rows.Scan(&code, &id); err != nil {
			return nil, fmt.Errorf("scan package short code: %w", err)
		}
		if code != "" {
			codes[code] = id
		}
	}
	return codes, rows.Err()
}

// ResetAllSubscriptionShortURLs 重置所有 subscribe_files 的文件短代码。
// 当用户单击设置中的"重置短链接"按钮时会调用此函数。
func (r *TrafficRepository) ResetAllSubscriptionShortURLs(ctx context.Context) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	// 获取所有 subscribe_files ID
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM subscribe_files`)
	if err != nil {
		return fmt.Errorf("query subscribe_files IDs: %w", err)
	}
	defer rows.Close()

	var fileIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan file ID: %w", err)
		}
		fileIDs = append(fileIDs, id)
	}

	// 重置每个 subscribe_file 的文件短代码
	for _, id := range fileIDs {
		if err := r.resetFileShortCode(ctx, id); err != nil {
			return fmt.Errorf("reset file short code for file %d: %w", id, err)
		}
	}

	return nil
}

// 重置单个 subscribe_file 的文件短代码。
func (r *TrafficRepository) resetFileShortCode(ctx context.Context, fileID int64) error {
	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		newShortCode, err := generateFileShortCode()
		if err != nil {
			return fmt.Errorf("generate file short code: %w", err)
		}

		const updateStmt = `UPDATE subscribe_files SET file_short_code = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;`
		_, err = r.db.ExecContext(ctx, updateStmt, newShortCode, fileID)
		if err != nil {
			// 检查是否违反唯一约束
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				continue // 使用不同的短代码重试
			}
			return fmt.Errorf("update file short code: %w", err)
		}

		return nil
	}

	return errors.New("failed to generate unique short URL after retries")
}

// 返回与短 URL 关联的订阅文件名。
func (r *TrafficRepository) GetSubscriptionByShortURL(ctx context.Context, shortcode string) (filename string, err error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}

	shortcode = strings.TrimSpace(shortcode)
	if shortcode == "" {
		return "", errors.New("shortcode is required")
	}

	const stmt = `SELECT rule_filename FROM subscription_links WHERE short_url = ? LIMIT 1;`
	if err := r.db.QueryRowContext(ctx, stmt, shortcode).Scan(&filename); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrSubscriptionNotFound
		}
		return "", fmt.Errorf("query subscription by short URL: %w", err)
	}
	if err := ValidateSubscribeFilename(filename); err != nil {
		return "", fmt.Errorf("invalid stored subscription rule filename: %w", err)
	}

	return filename, nil
}

// 返回与文件短代码关联的订阅文件名。
func (r *TrafficRepository) GetFilenameByFileShortCode(ctx context.Context, fileShortCode string) (filename string, err error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}

	fileShortCode = strings.TrimSpace(fileShortCode)
	if fileShortCode == "" {
		return "", errors.New("file short code is required")
	}

	const stmt = `SELECT filename FROM subscribe_files WHERE file_short_code = ? LIMIT 1;`
	if err := r.db.QueryRowContext(ctx, stmt, fileShortCode).Scan(&filename); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrSubscribeFileNotFound
		}
		return "", fmt.Errorf("query subscribe file by file short code: %w", err)
	}
	if err := ValidateSubscribeFilename(filename); err != nil {
		return "", fmt.Errorf("invalid stored subscribe filename: %w", err)
	}

	return filename, nil
}

// 返回与用户短代码关联的用户名。
func (r *TrafficRepository) GetUsernameByUserShortCode(ctx context.Context, userShortCode string) (username string, err error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}

	userShortCode = strings.TrimSpace(userShortCode)
	if userShortCode == "" {
		return "", errors.New("user short code is required")
	}

	const stmt = `SELECT username FROM user_tokens WHERE user_short_code = ? LIMIT 1;`
	if err := r.db.QueryRowContext(ctx, stmt, userShortCode).Scan(&username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("user not found")
		}
		return "", fmt.Errorf("query user by user short code: %w", err)
	}

	return username, nil
}

// 返回给定用户名的用户短代码。
func (r *TrafficRepository) GetUserShortCode(ctx context.Context, username string) (userShortCode string, err error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("username is required")
	}

	const stmt = `SELECT user_short_code FROM user_tokens WHERE username = ? LIMIT 1;`
	if err := r.db.QueryRowContext(ctx, stmt, username).Scan(&userShortCode); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("user short code not found")
		}
		return "", fmt.Errorf("query user short code: %w", err)
	}

	return userShortCode, nil
}

func (r *TrafficRepository) GetEffectiveUserShortCode(ctx context.Context, username string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("username is required")
	}
	var userCode, customCode string
	const stmt = `SELECT COALESCE(user_short_code, ''), COALESCE(custom_user_short_code, '') FROM user_tokens WHERE username = ? LIMIT 1;`
	if err := r.db.QueryRowContext(ctx, stmt, username).Scan(&userCode, &customCode); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("user short code not found")
		}
		return "", fmt.Errorf("query effective user short code: %w", err)
	}
	if customCode != "" {
		return customCode, nil
	}
	return userCode, nil
}

func (r *TrafficRepository) GetAllFileShortCodes(ctx context.Context) (map[string]string, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT COALESCE(file_short_code, ''), COALESCE(custom_short_code, ''), filename FROM subscribe_files`)
	if err != nil {
		return nil, fmt.Errorf("query all file short codes: %w", err)
	}
	defer rows.Close()

	codes := make(map[string]string)
	for rows.Next() {
		var fileCode, customCode, filename string
		if err := rows.Scan(&fileCode, &customCode, &filename); err != nil {
			return nil, fmt.Errorf("scan file short code: %w", err)
		}
		if customCode != "" {
			codes[customCode] = filename
		}
		if fileCode != "" {
			codes[fileCode] = filename
		}
	}
	return codes, rows.Err()
}

func (r *TrafficRepository) GetAllUserShortCodes(ctx context.Context) (map[string]string, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT COALESCE(user_short_code, ''), COALESCE(custom_user_short_code, ''), username FROM user_tokens`)
	if err != nil {
		return nil, fmt.Errorf("query all user short codes: %w", err)
	}
	defer rows.Close()

	codes := make(map[string]string)
	for rows.Next() {
		var userCode, customCode, username string
		if err := rows.Scan(&userCode, &customCode, &username); err != nil {
			return nil, fmt.Errorf("scan user short code: %w", err)
		}
		if customCode != "" {
			codes[customCode] = username
		}
		if userCode != "" {
			codes[userCode] = username
		}
	}
	return codes, rows.Err()
}

// ListUserShortCodeInfo 批量返回所有用户的 user_short_code 和 custom_user_short_code,
// 避免 user list handler N+1 query。复用已有的 UserShortCodeInfo struct(见下方)。
func (r *TrafficRepository) ListUserShortCodeInfo(ctx context.Context) (map[string]UserShortCodeInfo, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT username, COALESCE(user_short_code, ''), COALESCE(custom_user_short_code, '') FROM user_tokens`)
	if err != nil {
		return nil, fmt.Errorf("list user short code info: %w", err)
	}
	defer rows.Close()
	out := make(map[string]UserShortCodeInfo)
	for rows.Next() {
		var u UserShortCodeInfo
		if err := rows.Scan(&u.Username, &u.UserShortCode, &u.CustomUserShortCode); err != nil {
			return nil, fmt.Errorf("scan user short code info: %w", err)
		}
		out[u.Username] = u
	}
	return out, rows.Err()
}

func (r *TrafficRepository) UpdateUserCustomShortCode(ctx context.Context, username, code string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	code = strings.TrimSpace(code)

	if _, err := r.GetOrCreateUserToken(ctx, username); err != nil {
		return fmt.Errorf("ensure user token exists: %w", err)
	}

	res, err := r.db.ExecContext(ctx, `UPDATE user_tokens SET custom_user_short_code = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, code, username)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("该短码已被占用，请更换一个")
		}
		return fmt.Errorf("update user custom short code: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *TrafficRepository) GetUserCustomShortCode(ctx context.Context, username string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("username is required")
	}
	var code string
	const stmt = `SELECT COALESCE(custom_user_short_code, '') FROM user_tokens WHERE username = ? LIMIT 1;`
	if err := r.db.QueryRowContext(ctx, stmt, username).Scan(&code); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("query user custom short code: %w", err)
	}
	return code, nil
}

func (r *TrafficRepository) GetFilenameByCustomShortCode(ctx context.Context, code string) (filename string, err error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "", ErrSubscribeFileNotFound
	}
	const stmt = `SELECT filename FROM subscribe_files WHERE custom_short_code = ? LIMIT 1;`
	if err := r.db.QueryRowContext(ctx, stmt, code).Scan(&filename); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrSubscribeFileNotFound
		}
		return "", fmt.Errorf("query subscribe file by custom short code: %w", err)
	}
	if err := ValidateSubscribeFilename(filename); err != nil {
		return "", fmt.Errorf("invalid stored subscribe filename: %w", err)
	}
	return filename, nil
}

// 保留提供的文件名的新规则版本并返回新版本号。
func (r *TrafficRepository) SaveRuleVersion(ctx context.Context, filename, content, createdBy string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}

	filename = strings.TrimSpace(filename)
	createdBy = strings.TrimSpace(createdBy)
	if filename == "" {
		return 0, errors.New("filename is required")
	}
	if err := ValidateSubscribeFilename(filename); err != nil {
		return 0, err
	}
	if createdBy == "" {
		return 0, errors.New("createdBy is required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()

	var currentVersion sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT MAX(version) FROM rule_versions WHERE filename = ?`, filename).Scan(&currentVersion); err != nil {
		return 0, fmt.Errorf("query max version: %w", err)
	}

	newVersion := int64(1)
	if currentVersion.Valid {
		newVersion = currentVersion.Int64 + 1
	}

	if _, err = tx.ExecContext(ctx, `INSERT INTO rule_versions (filename, version, content, created_by) VALUES (?, ?, ?, ?)`, filename, newVersion, content, createdBy); err != nil {
		return 0, fmt.Errorf("insert rule version: %w", err)
	}

	return newVersion, nil
}

// SaveRuleVersionWithoutSubscribe archives a standalone rule only while no
// subscription owns the filename. The single INSERT statement is the database
// fence: if create/rename wins first it inserts zero rows; if this insert wins,
// create/rename observes the new history and refuses to claim the scope.
func (r *TrafficRepository) SaveRuleVersionWithoutSubscribe(ctx context.Context, filename, content, createdBy string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	filename = strings.TrimSpace(filename)
	createdBy = strings.TrimSpace(createdBy)
	if err := ValidateSubscribeFilename(filename); err != nil {
		return 0, err
	}
	if createdBy == "" {
		return 0, errors.New("createdBy is required")
	}
	var version int64
	err := r.db.QueryRowContext(ctx, `INSERT INTO rule_versions (filename, version, content, created_by)
		SELECT ?, COALESCE((SELECT MAX(version) FROM rule_versions WHERE filename = ?), 0) + 1, ?, ?
		WHERE NOT EXISTS (SELECT 1 FROM subscribe_files WHERE filename = ?)
		RETURNING version`, filename, filename, content, createdBy, filename).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrSubscribeFileChanged
	}
	if err != nil {
		return 0, fmt.Errorf("insert standalone rule version: %w", err)
	}
	return version, nil
}

// SaveRuleVersionForSubscribe fences an archived write to the subscription ID
// and filename observed by the caller. A concurrent rename that commits first
// makes the insert fail closed instead of recreating history under the old
// filename/scope.
func (r *TrafficRepository) SaveRuleVersionForSubscribe(ctx context.Context, subscribeID int64, filename, content, createdBy string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	filename = strings.TrimSpace(filename)
	createdBy = strings.TrimSpace(createdBy)
	if subscribeID <= 0 || filename == "" || createdBy == "" {
		return 0, errors.New("subscription id, filename and createdBy are required")
	}
	if err := ValidateSubscribeFilename(filename); err != nil {
		return 0, err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin fenced rule version: %w", err)
	}
	defer tx.Rollback()
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscribe_files WHERE id = ? AND filename = ?`, subscribeID, filename).Scan(&active); err != nil {
		return 0, fmt.Errorf("verify fenced rule version subscription: %w", err)
	}
	if active != 1 {
		return 0, ErrSubscribeFileChanged
	}

	var currentVersion sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(version) FROM rule_versions WHERE filename = ?`, filename).Scan(&currentVersion); err != nil {
		return 0, fmt.Errorf("query fenced max version: %w", err)
	}
	newVersion := int64(1)
	if currentVersion.Valid {
		newVersion = currentVersion.Int64 + 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO rule_versions (filename, version, content, created_by) VALUES (?, ?, ?, ?)`, filename, newVersion, content, createdBy); err != nil {
		return 0, fmt.Errorf("insert fenced rule version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit fenced rule version: %w", err)
	}
	return newVersion, nil
}

// ListAllRuleVersionContents returns every archived rule payload. It is kept
// separate from ListRuleVersions because startup migrations need the stable DB
// row ID and must not be limited to one filename or a display-oriented limit.
func (r *TrafficRepository) ListAllRuleVersionContents(ctx context.Context) ([]RuleVersionContent, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, filename, content FROM rule_versions ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query all rule version contents: %w", err)
	}
	defer rows.Close()

	var versions []RuleVersionContent
	for rows.Next() {
		var version RuleVersionContent
		if err := rows.Scan(&version.ID, &version.Filename, &version.Content); err != nil {
			return nil, fmt.Errorf("scan rule version content: %w", err)
		}
		if err := ValidateSubscribeFilename(version.Filename); err != nil {
			return nil, fmt.Errorf("invalid stored rule version filename for id %d: %w", version.ID, err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rule version contents: %w", err)
	}
	return versions, nil
}

// ListRuleVersionContentsByFilename returns every archived payload and its
// stable row ID for a filename-scoped secret rebind.
func (r *TrafficRepository) ListRuleVersionContentsByFilename(ctx context.Context, filename string) ([]RuleVersionContent, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return nil, errors.New("filename is required")
	}
	if err := ValidateSubscribeFilename(filename); err != nil {
		return nil, err
	}

	rows, err := r.db.QueryContext(ctx, `SELECT id, filename, content FROM rule_versions WHERE filename = ? ORDER BY id ASC`, filename)
	if err != nil {
		return nil, fmt.Errorf("query rule version contents by filename: %w", err)
	}
	defer rows.Close()

	var versions []RuleVersionContent
	for rows.Next() {
		var version RuleVersionContent
		if err := rows.Scan(&version.ID, &version.Filename, &version.Content); err != nil {
			return nil, fmt.Errorf("scan rule version content by filename: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rule version contents by filename: %w", err)
	}
	return versions, nil
}

// UpdateRuleVersionContents applies a startup content migration atomically.
// A missing row is treated as an error so a partially stale migration plan can
// never leave only some archived subscription versions updated.
func (r *TrafficRepository) UpdateRuleVersionContents(ctx context.Context, updates map[int64]string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if len(updates) == 0 {
		return nil
	}

	ids := make([]int64, 0, len(updates))
	for id := range updates {
		if id <= 0 {
			return fmt.Errorf("rule version id must be positive: %d", id)
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rule version content update: %w", err)
	}
	defer tx.Rollback()
	for _, id := range ids {
		result, err := tx.ExecContext(ctx, `UPDATE rule_versions SET content = ? WHERE id = ?`, updates[id], id)
		if err != nil {
			return fmt.Errorf("update rule version %d content: %w", id, err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("verify rule version %d content update: %w", id, err)
		}
		if updated != 1 {
			return fmt.Errorf("rule version %d not found", id)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rule version content update: %w", err)
	}
	// Rule-version migrations can replace legacy plaintext secret material.
	// Compact after commit so the previous payload is not recoverable from WAL
	// frames or freed SQLite pages.
	if _, err := r.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint rule version content update: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("compact rule version content update: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("finalize rule version content update: %w", err)
	}
	return nil
}

// 返回文件的最新规则版本。
func (r *TrafficRepository) ListRuleVersions(ctx context.Context, filename string, limit int) ([]RuleVersion, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	filename = strings.TrimSpace(filename)
	if filename == "" {
		return nil, errors.New("filename is required")
	}
	if err := ValidateSubscribeFilename(filename); err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 10
	}

	rows, err := r.db.QueryContext(ctx, `SELECT version, content, created_by, created_at FROM rule_versions WHERE filename = ? ORDER BY version DESC LIMIT ?`, filename, limit)
	if err != nil {
		return nil, fmt.Errorf("query rule versions: %w", err)
	}
	defer rows.Close()

	var versions []RuleVersion
	for rows.Next() {
		var rv RuleVersion
		rv.Filename = filename
		if err := rows.Scan(&rv.Version, &rv.Content, &rv.CreatedBy, &rv.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan rule version: %w", err)
		}
		versions = append(versions, rv)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rule versions: %w", err)
	}

	return versions, nil
}

// 返回所提供规则文件的最新存储版本。
func (r *TrafficRepository) LatestRuleVersion(ctx context.Context, filename string) (RuleVersion, error) {
	versions, err := r.ListRuleVersions(ctx, filename, 1)
	if err != nil {
		return RuleVersion{}, err
	}
	if len(versions) == 0 {
		return RuleVersion{}, ErrRuleVersionNotFound
	}
	return versions[0], nil
}

// RuleVersion 表示 YAML 规则文件的存档版本。
type RuleVersion struct {
	Filename  string
	Version   int64
	Content   string
	CreatedBy string
	CreatedAt time.Time
}

// RuleVersionContent is the minimal stable record used by content migrations.
type RuleVersionContent struct {
	ID       int64
	Filename string
	Content  string
}

// 用户代表存储在存储库中的经过身份验证的帐户。
type User struct {
	Username     string
	PasswordHash string
	Email        string
	Nickname     string
	AvatarURL    string
	Role         string
	IsActive     bool
	Remark       string
	PackageID    int64
	IsReset      bool
	ResetDay     int
	// LastResetAt 记录上次按 reset_day 自动重置流量周期的时间。
	// CheckAll 用它做"本月是否已重置"判定,避免 enforcer 每 5 min 跑一次时同一天反复 reset。
	// 空 = 从未重置过(刚装 / 刚分配套餐),CheckAll 在 reset_day 到了之后会触发首次 reset。
	LastResetAt         *time.Time
	PackageEndDate      *time.Time
	SpeedLimitOverride  *float64
	DeviceLimitOverride *int
	// TrafficLimitOverride 是当前套餐绑定的总流量覆写(bytes)。
	// nil=继承套餐,0=显式不限,>0=覆写值;它与按服务器授权的流量额度相互独立。
	TrafficLimitOverride *int64
	// 用户级 per-node 限速覆盖。map 含 key 即生效:0 = 显式不限速;>0 = 该值;不含 key = 沿用上层。
	NodeSpeedLimitOverrides map[int64]float64
	// 用户级 per-node 客户端数覆盖。语义同上。
	NodeDeviceLimitOverrides map[int64]int
	TOTPSecret               string
	TOTPEnabled              bool
	RecoveryCodes            string
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

// UserProfileUpdate 捕获用户的可编辑配置文件字段。
type UserProfileUpdate struct {
	Email     string
	Nickname  string
	AvatarURL string
}

// 插入或更新提供的用户。
func (r *TrafficRepository) EnsureUser(ctx context.Context, username, passwordHash string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if IsReservedUsername(username) {
		return ErrReservedUsername
	}
	if passwordHash == "" {
		return errors.New("password hash is required")
	}

	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	_, err := r.db.ExecContext(ctx, `INSERT INTO users (username, password_hash, nickname, role) VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash`, username, passwordHash, username, RoleUser)
	if err != nil {
		return fmt.Errorf("ensure user: %w", err)
	}

	return nil
}

// 使用提供的凭据插入一个全新的用户。如果用户名已存在，则返回 ErrUserExists。
func (r *TrafficRepository) CreateUser(ctx context.Context, username, email, nickname, passwordHash, role, remark string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	nickname = strings.TrimSpace(nickname)
	role = strings.TrimSpace(role)
	remark = strings.TrimSpace(remark)

	if username == "" {
		return errors.New("username is required")
	}
	if IsReservedUsername(username) {
		return ErrReservedUsername
	}
	if passwordHash == "" {
		return errors.New("password hash is required")
	}
	if nickname == "" {
		nickname = username
	}
	if role == "" {
		role = RoleUser
	}
	role = strings.ToLower(role)
	if role != RoleAdmin {
		role = RoleUser
	}

	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	_, err := r.db.ExecContext(ctx, `INSERT INTO users (username, password_hash, email, nickname, role, is_active, remark) VALUES (?, ?, ?, ?, ?, 1, ?)`, username, passwordHash, email, nickname, role, remark)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrUserExists
		}
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

// 通过用户名检索用户。
func (r *TrafficRepository) GetUser(ctx context.Context, username string) (User, error) {
	var user User
	if r == nil || r.db == nil {
		return user, errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return user, errors.New("username is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT username, password_hash, COALESCE(email, ''), COALESCE(nickname, ''), COALESCE(avatar_url, ''), COALESCE(role, ''), is_active, COALESCE(package_id, 0), COALESCE(is_reset, 0), COALESCE(reset_day, 1), package_end_date, speed_limit_override, device_limit_override, traffic_limit_override, COALESCE(node_speed_limit_overrides, '{}'), COALESCE(node_device_limit_overrides, '{}'), COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(recovery_codes, '[]'), created_at, updated_at FROM users WHERE username = ? LIMIT 1`, username)
	var active, isReset, totpEnabled int
	var endDate sql.NullTime
	var speedOverride sql.NullFloat64
	var deviceOverride sql.NullInt64
	var trafficOverride sql.NullInt64
	var nodeSpeedJSON, nodeDeviceJSON string
	if err := row.Scan(&user.Username, &user.PasswordHash, &user.Email, &user.Nickname, &user.AvatarURL, &user.Role, &active, &user.PackageID, &isReset, &user.ResetDay, &endDate, &speedOverride, &deviceOverride, &trafficOverride, &nodeSpeedJSON, &nodeDeviceJSON, &user.TOTPSecret, &totpEnabled, &user.RecoveryCodes, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user, ErrUserNotFound
		}
		return user, fmt.Errorf("get user: %w", err)
	}
	if user.Nickname == "" {
		user.Nickname = user.Username
	}
	if user.Role == "" {
		user.Role = RoleUser
	}
	user.IsActive = active != 0
	user.IsReset = isReset != 0
	user.TOTPEnabled = totpEnabled != 0
	if endDate.Valid {
		user.PackageEndDate = &endDate.Time
	}
	if speedOverride.Valid {
		v := speedOverride.Float64
		user.SpeedLimitOverride = &v
	}
	if deviceOverride.Valid {
		v := int(deviceOverride.Int64)
		user.DeviceLimitOverride = &v
	}
	if trafficOverride.Valid {
		v := trafficOverride.Int64
		user.TrafficLimitOverride = &v
	}
	if nodeSpeedJSON != "" && nodeSpeedJSON != "{}" {
		unmarshalStringKeyedMap(nodeSpeedJSON, &user.NodeSpeedLimitOverrides)
	}
	if nodeDeviceJSON != "" && nodeDeviceJSON != "{}" {
		unmarshalStringKeyedIntMap(nodeDeviceJSON, &user.NodeDeviceLimitOverrides)
	}

	return user, nil
}

// 返回最多按创建时间排序的限制用户。
func (r *TrafficRepository) ListUsers(ctx context.Context, limit int) ([]User, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if limit <= 0 {
		limit = 10
	}

	rows, err := r.db.QueryContext(ctx, `SELECT username, password_hash, COALESCE(email, ''), COALESCE(nickname, ''), COALESCE(avatar_url, ''), COALESCE(role, ''), is_active, COALESCE(remark, ''), COALESCE(package_id, 0), COALESCE(is_reset, 0), COALESCE(reset_day, 1), package_end_date, speed_limit_override, device_limit_override, traffic_limit_override, COALESCE(node_speed_limit_overrides, '{}'), COALESCE(node_device_limit_overrides, '{}'), created_at, updated_at FROM users ORDER BY created_at ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var active, isReset int
		var endDate sql.NullTime
		var speedOverride sql.NullFloat64
		var deviceOverride sql.NullInt64
		var trafficOverride sql.NullInt64
		var nodeSpeedJSON, nodeDeviceJSON string
		if err := rows.Scan(&user.Username, &user.PasswordHash, &user.Email, &user.Nickname, &user.AvatarURL, &user.Role, &active, &user.Remark, &user.PackageID, &isReset, &user.ResetDay, &endDate, &speedOverride, &deviceOverride, &trafficOverride, &nodeSpeedJSON, &nodeDeviceJSON, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if user.Nickname == "" {
			user.Nickname = user.Username
		}
		if user.Role == "" {
			user.Role = RoleUser
		}
		user.IsActive = active != 0
		user.IsReset = isReset != 0
		if endDate.Valid {
			user.PackageEndDate = &endDate.Time
		}
		if speedOverride.Valid {
			v := speedOverride.Float64
			user.SpeedLimitOverride = &v
		}
		if deviceOverride.Valid {
			v := int(deviceOverride.Int64)
			user.DeviceLimitOverride = &v
		}
		if trafficOverride.Valid {
			v := trafficOverride.Int64
			user.TrafficLimitOverride = &v
		}
		if nodeSpeedJSON != "" && nodeSpeedJSON != "{}" {
			unmarshalStringKeyedMap(nodeSpeedJSON, &user.NodeSpeedLimitOverrides)
		}
		if nodeDeviceJSON != "" && nodeDeviceJSON != "{}" {
			unmarshalStringKeyedIntMap(nodeDeviceJSON, &user.NodeDeviceLimitOverrides)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}

	return users, nil
}

// 更新指定用户的备注字段。
func (r *TrafficRepository) UpdateUserRemark(ctx context.Context, username, remark string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	const stmt = `UPDATE users SET remark = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`
	_, err := r.db.ExecContext(ctx, stmt, remark, username)
	if err != nil {
		return fmt.Errorf("update user remark: %w", err)
	}
	return nil
}

// 更新指定用户存储的密码哈希值。
func (r *TrafficRepository) UpdateUserPassword(ctx context.Context, username, passwordHash string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if passwordHash == "" {
		return errors.New("password hash is required")
	}

	res, err := r.db.ExecContext(ctx, `UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, passwordHash, username)
	if err != nil {
		return fmt.Errorf("update user password: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("password rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// UpdateUserPasswordAndDeleteSessions atomically changes a password and
// removes every persisted session for the account. This prevents an old
// bearer token from becoming valid again after a process restart.
func (r *TrafficRepository) UpdateUserPasswordAndDeleteSessions(ctx context.Context, username, passwordHash string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if passwordHash == "" {
		return errors.New("password hash is required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("update password begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		passwordHash, username)
	if err != nil {
		return fmt.Errorf("update user password: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("password rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE username = ?`, username); err != nil {
		return fmt.Errorf("delete changed-password sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("update password commit: %w", err)
	}
	return nil
}

type userIdentityColumn struct {
	table  string
	column string
}

var userIdentityColumnNames = map[string]struct{}{
	"username":          {},
	"created_by":        {},
	"bind_username":     {},
	"billable_username": {},
}

func quoteSQLiteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

// userIdentityColumns discovers account ownership columns from the live schema.
// Several optional subsystems create their tables in separate migrations, so a
// static table list would silently orphan data when one of those schemas grows.
func userIdentityColumns(ctx context.Context, tx *sql.Tx) ([]userIdentityColumn, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'users'
		ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list user-owned tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan user-owned table: %w", err)
		}
		tables = append(tables, table)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close user-owned table rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user-owned tables: %w", err)
	}

	columns := make([]userIdentityColumn, 0, len(tables))
	for _, table := range tables {
		columnRows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+quoteSQLiteIdentifier(table)+`)`)
		if err != nil {
			return nil, fmt.Errorf("inspect table %q: %w", table, err)
		}
		for columnRows.Next() {
			var (
				cid        int
				name       string
				columnType string
				notNull    int
				defaultVal sql.NullString
				primaryKey int
			)
			if err := columnRows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &primaryKey); err != nil {
				_ = columnRows.Close()
				return nil, fmt.Errorf("scan columns for table %q: %w", table, err)
			}
			if _, ok := userIdentityColumnNames[strings.ToLower(name)]; ok {
				columns = append(columns, userIdentityColumn{table: table, column: name})
			}
		}
		if err := columnRows.Close(); err != nil {
			return nil, fmt.Errorf("close columns for table %q: %w", table, err)
		}
		if err := columnRows.Err(); err != nil {
			return nil, fmt.Errorf("iterate columns for table %q: %w", table, err)
		}
	}
	return columns, nil
}

func (r *TrafficRepository) renameUserInTx(ctx context.Context, tx *sql.Tx, oldUsername, newUsername string) error {
	if IsReservedUsername(newUsername) {
		return ErrReservedUsername
	}
	var targetExists int
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)`, newUsername).Scan(&targetExists); err != nil {
		return fmt.Errorf("check target username: %w", err)
	}
	if targetExists != 0 {
		return ErrUserExists
	}
	// Remote client identities and routing rules can embed the username. Until
	// Agent and SQLite changes have a durable reconciliation journal, renaming
	// such an account would risk leaving the two systems permanently split.
	var hasRemoteBindings int
	if err := tx.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM user_inbound_configs WHERE username = ?)
		OR EXISTS(SELECT 1 FROM user_outbounds WHERE username = ?)
		OR EXISTS(SELECT 1 FROM user_subaccounts WHERE username = ?)`,
		oldUsername, oldUsername, oldUsername).Scan(&hasRemoteBindings); err != nil {
		return fmt.Errorf("check remote bindings before username rename: %w", err)
	}
	if hasRemoteBindings != 0 {
		return ErrUsernameRenameRequiresCredentialMigration
	}

	// This also protects installations that explicitly enable foreign_keys on
	// their DSN: all parent/child changes are checked only at commit time.
	if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
		return fmt.Errorf("defer username foreign keys: %w", err)
	}
	columns, err := userIdentityColumns(ctx, tx)
	if err != nil {
		return err
	}
	for _, target := range columns {
		query := `UPDATE ` + quoteSQLiteIdentifier(target.table) +
			` SET ` + quoteSQLiteIdentifier(target.column) + ` = ? WHERE ` +
			quoteSQLiteIdentifier(target.column) + ` = ?`
		if _, err := tx.ExecContext(ctx, query, newUsername, oldUsername); err != nil {
			return fmt.Errorf("rename %s.%s: %w", target.table, target.column, err)
		}
	}
	if err := r.resealProxyProviderAccessTokensForUsernameRename(ctx, tx, oldUsername, newUsername); err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		newUsername, oldUsername)
	if err != nil {
		return fmt.Errorf("rename user: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rename user rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *TrafficRepository) validateUsernameRename(ctx context.Context, oldUsername, newUsername string) error {
	var sourceExists, targetExists int
	if err := r.db.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM users WHERE username = ?),
		EXISTS(SELECT 1 FROM users WHERE username = ?)`, oldUsername, newUsername).Scan(&sourceExists, &targetExists); err != nil {
		return fmt.Errorf("validate username rename: %w", err)
	}
	if sourceExists == 0 {
		return ErrUserNotFound
	}
	if targetExists != 0 {
		return ErrUserExists
	}
	return nil
}

// UpdateCredentialsAndDeleteSessions atomically renames an account, updates
// its password when requested, and invalidates all persisted sessions.
func (r *TrafficRepository) UpdateCredentialsAndDeleteSessions(ctx context.Context, currentUsername, newUsername, passwordHash string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	currentUsername = strings.TrimSpace(currentUsername)
	newUsername = strings.TrimSpace(newUsername)
	if currentUsername == "" {
		return "", errors.New("current username is required")
	}
	if newUsername == "" {
		newUsername = currentUsername
	}
	if IsReservedUsername(newUsername) {
		return "", ErrReservedUsername
	}
	if newUsername == currentUsername && passwordHash == "" {
		return "", errors.New("username or password must be provided")
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()

	if newUsername != currentUsername {
		if err := r.validateUsernameRename(ctx, currentUsername, newUsername); err != nil {
			return "", err
		}
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("update credentials begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if newUsername != currentUsername {
		if err := r.renameUserInTx(ctx, tx, currentUsername, newUsername); err != nil {
			return "", err
		}
	}

	if passwordHash != "" {
		result, err := tx.ExecContext(ctx,
			`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
			passwordHash, newUsername)
		if err != nil {
			return "", fmt.Errorf("update user password: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return "", fmt.Errorf("password rows affected: %w", err)
		}
		if affected == 0 {
			return "", ErrUserNotFound
		}
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE username = ? OR username = ?`,
		currentUsername, newUsername); err != nil {
		return "", fmt.Errorf("delete changed-credentials sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("update credentials commit: %w", err)
	}
	r.invalidateTrafficBillingCache()
	return newUsername, nil
}

// 设置指定用户的角色。
func (r *TrafficRepository) UpdateUserRole(ctx context.Context, username, role string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	role = strings.TrimSpace(role)
	if username == "" {
		return errors.New("username is required")
	}
	if role == "" {
		role = RoleUser
	}
	role = strings.ToLower(role)
	if role != RoleAdmin {
		role = RoleUser
	}

	res, err := r.db.ExecContext(ctx, `UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, role, username)
	if err != nil {
		return fmt.Errorf("update user role: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("role rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// 更新指定用户的电子邮件。
func (r *TrafficRepository) UpdateUserEmail(ctx context.Context, username, email string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	if username == "" {
		return errors.New("username is required")
	}

	res, err := r.db.ExecContext(ctx, `UPDATE users SET email = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, email, username)
	if err != nil {
		return fmt.Errorf("update user email: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("email rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// 切换用户的活动状态。
func (r *TrafficRepository) UpdateUserStatus(ctx context.Context, username string, active bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if !active {
		return r.DisableUserAndDeleteSessions(ctx, username)
	}
	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	if pending, err := r.IsUserDeletionPending(ctx, username); err != nil {
		return err
	} else if pending {
		return ErrUserDeletionPending
	}

	res, err := r.db.ExecContext(ctx, `UPDATE users SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("update user status: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("status rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// DeleteUser is the storage-only safe wrapper. It can finalize accounts that
// have no remote work (or whose revocations were already applied), but it never
// discards credentials for an unapplied remote revoke. HTTP deletion uses the
// explicit Prepare/Reconcile/Finalize lifecycle so it can drive the Agent.
func (r *TrafficRepository) DeleteUser(ctx context.Context, username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	sources, err := r.PrepareUserDeletion(ctx, username, "storage.DeleteUser")
	if err != nil {
		return err
	}
	for _, source := range sources {
		if source.DesiredState != ManagedDesiredInactive ||
			source.ObservedState != ManagedObservedInactive ||
			source.Generation != source.AppliedGeneration {
			return ErrUserDeletionPending
		}
	}
	return r.FinalizeUserDeletion(ctx, username, "storage.DeleteUser")
}

// 更新与用户帐户关联的昵称。
func (r *TrafficRepository) UpdateUserNickname(ctx context.Context, username, nickname string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	nickname = strings.TrimSpace(nickname)

	if username == "" {
		return errors.New("username is required")
	}
	if nickname == "" {
		nickname = username
	}

	res, err := r.db.ExecContext(ctx, `UPDATE users SET nickname = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, nickname, username)
	if err != nil {
		return fmt.Errorf("update user nickname: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("nickname rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// 更新指定用户的可编辑配置文件字段。
func (r *TrafficRepository) UpdateUserProfile(ctx context.Context, username string, profile UserProfileUpdate) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	email := strings.TrimSpace(profile.Email)
	nickname := strings.TrimSpace(profile.Nickname)
	avatar := strings.TrimSpace(profile.AvatarURL)

	if nickname == "" {
		nickname = username
	}

	res, err := r.db.ExecContext(ctx, `UPDATE users SET email = ?, nickname = ?, avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, email, nickname, avatar, username)
	if err != nil {
		return fmt.Errorf("update user profile: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("profile rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// 更改用户名并更新相关表。
func (r *TrafficRepository) RenameUser(ctx context.Context, oldUsername, newUsername string) error {
	return r.RenameUserAndRun(ctx, oldUsername, newUsername, nil)
}

// RenameUserAndRun keeps the durable rename and its process-local identity
// migration in one authentication mutation critical section. The callback is
// invoked only after the database transaction commits successfully and must
// not call another account mutation method on this repository.
func (r *TrafficRepository) RenameUserAndRun(ctx context.Context, oldUsername, newUsername string, afterCommit func()) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	oldUsername = strings.TrimSpace(oldUsername)
	newUsername = strings.TrimSpace(newUsername)
	if oldUsername == "" || newUsername == "" {
		return errors.New("usernames are required")
	}
	if IsReservedUsername(newUsername) {
		return ErrReservedUsername
	}
	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	if err := r.validateUsernameRename(ctx, oldUsername, newUsername); err != nil {
		return err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rename user begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := r.renameUserInTx(ctx, tx, oldUsername, newUsername); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("rename user commit: %w", err)
	}
	r.invalidateTrafficBillingCache()
	if afterCommit != nil {
		afterCommit()
	}
	return nil
}

// Session 表示存储在数据库中的经过身份验证的会话。
type Session struct {
	Token     string
	Username  string
	ExpiresAt time.Time
	CreatedAt time.Time
}

const currentAuthSessionEpoch = 2

// 将新会话保存到数据库。
func (r *TrafficRepository) CreateSession(ctx context.Context, token, username string, expiresAt time.Time) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	token = strings.TrimSpace(token)
	username = strings.TrimSpace(username)
	if token == "" {
		return errors.New("token is required")
	}
	if username == "" {
		return errors.New("username is required")
	}

	const stmt = `INSERT INTO sessions (token, username, expires_at, auth_epoch)
		SELECT ?, ?, ?, ? WHERE EXISTS (
			SELECT 1 FROM users WHERE username = ? AND is_active = 1
		)`
	result, err := r.db.ExecContext(ctx, stmt, token, username, expiresAt, currentAuthSessionEpoch, username)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("create session rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserInactive
	}

	return nil
}

// 从数据库中删除会话。
func (r *TrafficRepository) DeleteSession(ctx context.Context, token string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("token is required")
	}

	const stmt = `DELETE FROM sessions WHERE token = ?`
	if _, err := r.db.ExecContext(ctx, stmt, token); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

// 删除特定用户的所有会话。
func (r *TrafficRepository) DeleteUserSessions(ctx context.Context, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	const stmt = `DELETE FROM sessions WHERE username = ?`
	if _, err := r.db.ExecContext(ctx, stmt, username); err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}

	return nil
}

// DisableUserAndDeleteSessions atomically marks an account inactive and removes
// all of its persisted login sessions. Keeping both writes in one transaction
// prevents a process restart between them from restoring a session that should
// have been revoked.
func (r *TrafficRepository) DisableUserAndDeleteSessions(ctx context.Context, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("disable user begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("disable user: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("disable user rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE username = ?`, username); err != nil {
		return fmt.Errorf("delete disabled user sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("disable user commit: %w", err)
	}
	r.revokeMemorySessions(username)
	return nil
}

// 从数据库中检索所有未过期的会话。
func (r *TrafficRepository) LoadSessions(ctx context.Context) ([]Session, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const stmt = `SELECT token, username, expires_at, created_at FROM sessions
		WHERE expires_at > datetime('now') AND auth_epoch = ? ORDER BY created_at ASC`
	rows, err := r.db.QueryContext(ctx, stmt, currentAuthSessionEpoch)
	if err != nil {
		return nil, fmt.Errorf("load sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		if err := rows.Scan(&session.Token, &session.Username, &session.ExpiresAt, &session.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}

// 从数据库中删除过期的会话。
func (r *TrafficRepository) CleanupExpiredSessions(ctx context.Context) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	const stmt = `DELETE FROM sessions WHERE expires_at <= datetime('now')`
	if _, err := r.db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("cleanup expired sessions: %w", err)
	}

	return nil
}

// 将订阅分配给用户。
func (r *TrafficRepository) AssignSubscriptionToUser(ctx context.Context, username string, subscriptionID int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if subscriptionID <= 0 {
		return errors.New("invalid subscription ID")
	}

	_, err := r.db.ExecContext(ctx, `INSERT INTO user_subscriptions (username, subscription_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, username, subscriptionID)
	if err != nil {
		return fmt.Errorf("assign subscription to user: %w", err)
	}

	return nil
}

// 删除用户的订阅分配。
func (r *TrafficRepository) RemoveSubscriptionFromUser(ctx context.Context, username string, subscriptionID int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if subscriptionID <= 0 {
		return errors.New("invalid subscription ID")
	}

	_, err := r.db.ExecContext(ctx, `DELETE FROM user_subscriptions WHERE username = ? AND subscription_id = ?`, username, subscriptionID)
	if err != nil {
		return fmt.Errorf("remove subscription from user: %w", err)
	}

	return nil
}

// GetUserSubscriptionIDs 返回分配给用户的所有订阅 ID。
// 仅返回 subscribe_files 表中存在的 ID（过滤掉孤立记录）。
func (r *TrafficRepository) GetUserSubscriptionIDs(ctx context.Context, username string) ([]int64, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}

	// 使用 subscribe_files 加入仅返回有效的订阅 ID
	const stmt = `
		SELECT us.subscription_id
		FROM user_subscriptions us
		INNER JOIN subscribe_files sf ON us.subscription_id = sf.id
		WHERE us.username = ?
		ORDER BY us.created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, stmt, username)
	if err != nil {
		return nil, fmt.Errorf("get user subscription IDs: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan subscription ID: %w", err)
		}
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscription IDs: %w", err)
	}

	return ids, nil
}

// 使用提供的列表替换用户的所有订阅。
// UserShortCodeInfo 用户短码信息。
type UserShortCodeInfo struct {
	Username            string `json:"username"`
	UserShortCode       string `json:"user_short_code"`
	CustomUserShortCode string `json:"custom_user_short_code"`
}

// GetUsersBySubscriptionID 返回某订阅文件分配给哪些用户 + 每个用户的短码,
// 用于管理 UI 集中编辑用户短码。
func (r *TrafficRepository) GetUsersBySubscriptionID(ctx context.Context, subscriptionID int64) ([]UserShortCodeInfo, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const stmt = `
		SELECT ut.username, COALESCE(ut.user_short_code, ''), COALESCE(ut.custom_user_short_code, '')
		FROM user_subscriptions us
		INNER JOIN user_tokens ut ON us.username = ut.username
		WHERE us.subscription_id = ?
		ORDER BY ut.username ASC
	`
	rows, err := r.db.QueryContext(ctx, stmt, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("get users by subscription ID: %w", err)
	}
	defer rows.Close()

	var users []UserShortCodeInfo
	for rows.Next() {
		var u UserShortCodeInfo
		if err := rows.Scan(&u.Username, &u.UserShortCode, &u.CustomUserShortCode); err != nil {
			return nil, fmt.Errorf("scan user short code: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *TrafficRepository) SetUserSubscriptions(ctx context.Context, username string, subscriptionIDs []int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	// 使用事务确保原子性
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 删除用户的所有现有订阅
	_, err = tx.ExecContext(ctx, `DELETE FROM user_subscriptions WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("delete existing subscriptions: %w", err)
	}

	// 插入新的订阅
	if len(subscriptionIDs) > 0 {
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO user_subscriptions (username, subscription_id) VALUES (?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare insert statement: %w", err)
		}
		defer stmt.Close()

		for _, id := range subscriptionIDs {
			if id <= 0 {
				continue
			}
			_, err = stmt.ExecContext(ctx, username, id)
			if err != nil {
				return fmt.Errorf("insert subscription %d: %w", id, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// 返回分配给用户的所有订阅。
func (r *TrafficRepository) GetUserSubscriptions(ctx context.Context, username string) ([]SubscribeFile, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}

	// 用 subscribeFileSelectClause 统一列定义,避免手抄列表跟 scanSubscribeFile 的 20 列对不上
	rows, err := r.db.QueryContext(ctx, `SELECT `+subscribeFileSelectClause("s")+`
		FROM subscribe_files s
		INNER JOIN user_subscriptions us ON s.id = us.subscription_id
		WHERE us.username = ?
		ORDER BY s.sort_order ASC, s.created_at DESC`, username)
	if err != nil {
		return nil, fmt.Errorf("get user subscriptions: %w", err)
	}
	defer rows.Close()

	var subscriptions []SubscribeFile
	for rows.Next() {
		sub, err := scanSubscribeFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}
		subscriptions = append(subscriptions, sub)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscriptions: %w", err)
	}

	return subscriptions, nil
}

// 检索给定用户名的用户设置。
func (r *TrafficRepository) GetUserSettings(ctx context.Context, username string) (UserSettings, error) {
	var settings UserSettings
	if r == nil || r.db == nil {
		return settings, errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return settings, errors.New("username is required")
	}

	const stmt = `SELECT username, force_sync_external, COALESCE(match_rule, 'node_name'), COALESCE(sync_scope, 'saved_only'), COALESCE(keep_node_name, 1), COALESCE(cache_expire_minutes, 0), COALESCE(sync_traffic, 0), COALESCE(node_name_filter, '剩余|流量|到期|订阅|时间|重置'), COALESCE(append_sub_info, 0), COALESCE(custom_rules_enabled, 0), COALESCE(enable_short_link, 0), COALESCE(use_new_template_system, 1), COALESCE(enable_proxy_provider, 0), COALESCE(node_order, '[]'), COALESCE(debug_enabled, 0), COALESCE(debug_log_path, ''), debug_started_at, created_at, updated_at FROM user_settings WHERE username = ? LIMIT 1`
	var forceSyncInt, keepNodeNameInt, syncTrafficInt, appendSubInfoInt, customRulesEnabledInt, enableShortLinkInt, useNewTemplateSystemInt, enableProxyProviderInt, debugEnabledInt int
	var nodeOrderJSON string
	var debugStartedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, stmt, username).Scan(&settings.Username, &forceSyncInt, &settings.MatchRule, &settings.SyncScope, &keepNodeNameInt, &settings.CacheExpireMinutes, &syncTrafficInt, &settings.NodeNameFilter, &appendSubInfoInt, &customRulesEnabledInt, &enableShortLinkInt, &useNewTemplateSystemInt, &enableProxyProviderInt, &nodeOrderJSON, &debugEnabledInt, &settings.DebugLogPath, &debugStartedAt, &settings.CreatedAt, &settings.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return settings, ErrUserSettingsNotFound
		}
		return settings, fmt.Errorf("get user settings: %w", err)
	}

	settings.ForceSyncExternal = forceSyncInt == 1
	settings.KeepNodeName = keepNodeNameInt == 1
	settings.SyncTraffic = syncTrafficInt == 1
	settings.AppendSubInfo = appendSubInfoInt == 1
	settings.CustomRulesEnabled = customRulesEnabledInt == 1
	settings.EnableShortLink = enableShortLinkInt == 1
	settings.UseNewTemplateSystem = useNewTemplateSystemInt == 1
	settings.EnableProxyProvider = enableProxyProviderInt == 1
	settings.DebugEnabled = debugEnabledInt == 1

	// 解析node_order JSON
	if nodeOrderJSON != "" && nodeOrderJSON != "[]" {
		if err := json.Unmarshal([]byte(nodeOrderJSON), &settings.NodeOrder); err != nil {
			// 如果 JSON 解析失败，则使用空数组
			settings.NodeOrder = []int64{}
		}
	} else {
		settings.NodeOrder = []int64{}
	}

	// 处理可为空的 debug_started_at
	if debugStartedAt.Valid {
		settings.DebugStartedAt = &debugStartedAt.Time
	}

	return settings, nil
}

// 创建或更新用户设置。
func (r *TrafficRepository) UpsertUserSettings(ctx context.Context, settings UserSettings) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username := strings.TrimSpace(settings.Username)
	if username == "" {
		return errors.New("username is required")
	}

	forceSyncInt := 0
	if settings.ForceSyncExternal {
		forceSyncInt = 1
	}

	keepNodeNameInt := 1 // 默认为 true
	if !settings.KeepNodeName {
		keepNodeNameInt = 0
	}

	syncTrafficInt := 0
	if settings.SyncTraffic {
		syncTrafficInt = 1
	}

	customRulesEnabledInt := 0
	if settings.CustomRulesEnabled {
		customRulesEnabledInt = 1
	}

	enableShortLinkInt := 0
	if settings.EnableShortLink {
		enableShortLinkInt = 1
	}

	useNewTemplateSystemInt := 1 // 默认为 true
	if !settings.UseNewTemplateSystem {
		useNewTemplateSystemInt = 0
	}

	enableProxyProviderInt := 0
	if settings.EnableProxyProvider {
		enableProxyProviderInt = 1
	}

	debugEnabledInt := 0
	if settings.DebugEnabled {
		debugEnabledInt = 1
	}

	appendSubInfoInt := 0
	if settings.AppendSubInfo {
		appendSubInfoInt = 1
	}

	matchRule := strings.TrimSpace(settings.MatchRule)
	if matchRule == "" {
		matchRule = "node_name"
	}

	syncScope := strings.TrimSpace(settings.SyncScope)
	if syncScope == "" {
		syncScope = "saved_only"
	}

	cacheExpireMinutes := settings.CacheExpireMinutes
	if cacheExpireMinutes < 0 {
		cacheExpireMinutes = 0
	}

	// 将node_order序列化为JSON
	nodeOrderJSON := "[]"
	if len(settings.NodeOrder) > 0 {
		nodeOrderBytes, err := json.Marshal(settings.NodeOrder)
		if err == nil {
			nodeOrderJSON = string(nodeOrderBytes)
		}
	}

	nodeNameFilter := settings.NodeNameFilter

	const stmt = `
		INSERT INTO user_settings (username, force_sync_external, match_rule, sync_scope, keep_node_name, cache_expire_minutes, sync_traffic, node_name_filter, append_sub_info, custom_rules_enabled, enable_short_link, use_new_template_system, enable_proxy_provider, node_order, debug_enabled, debug_log_path, debug_started_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(username) DO UPDATE SET
			force_sync_external = excluded.force_sync_external,
			match_rule = excluded.match_rule,
			sync_scope = excluded.sync_scope,
			keep_node_name = excluded.keep_node_name,
			cache_expire_minutes = excluded.cache_expire_minutes,
			sync_traffic = excluded.sync_traffic,
			node_name_filter = excluded.node_name_filter,
			append_sub_info = excluded.append_sub_info,
			custom_rules_enabled = excluded.custom_rules_enabled,
			enable_short_link = excluded.enable_short_link,
			use_new_template_system = excluded.use_new_template_system,
			enable_proxy_provider = excluded.enable_proxy_provider,
			node_order = excluded.node_order,
			debug_enabled = excluded.debug_enabled,
			debug_log_path = excluded.debug_log_path,
			debug_started_at = excluded.debug_started_at,
			updated_at = CURRENT_TIMESTAMP
	`

	if _, err := r.db.ExecContext(ctx, stmt, username, forceSyncInt, matchRule, syncScope, keepNodeNameInt, cacheExpireMinutes, syncTrafficInt, nodeNameFilter, appendSubInfoInt, customRulesEnabledInt, enableShortLinkInt, useNewTemplateSystemInt, enableProxyProviderInt, nodeOrderJSON, debugEnabledInt, settings.DebugLogPath, settings.DebugStartedAt); err != nil {
		return fmt.Errorf("upsert user settings: %w", err)
	}

	return nil
}

// 返回用户的所有外部订阅。
func (r *TrafficRepository) ListExternalSubscriptions(ctx context.Context, username string) ([]ExternalSubscription, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}

	const stmt = `SELECT id, username, name, url, COALESCE(user_agent, 'clash-meta/2.4.0'), node_count, last_sync_at, COALESCE(upload, 0), COALESCE(download, 0), COALESCE(total, 0), expire, COALESCE(traffic_mode, 'both'), created_at, updated_at FROM external_subscriptions WHERE username = ? ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, stmt, username)
	if err != nil {
		return nil, fmt.Errorf("list external subscriptions: %w", err)
	}
	defer rows.Close()

	var subs []ExternalSubscription
	for rows.Next() {
		var sub ExternalSubscription
		var lastSyncAt, expire sql.NullTime
		if err := rows.Scan(&sub.ID, &sub.Username, &sub.Name, &sub.URL, &sub.UserAgent, &sub.NodeCount, &lastSyncAt, &sub.Upload, &sub.Download, &sub.Total, &expire, &sub.TrafficMode, &sub.CreatedAt, &sub.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan external subscription: %w", err)
		}
		if lastSyncAt.Valid {
			sub.LastSyncAt = &lastSyncAt.Time
		}
		if expire.Valid {
			sub.Expire = &expire.Time
		}
		subs = append(subs, sub)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate external subscriptions: %w", err)
	}

	return subs, nil
}

// 按 ID 检索外部订阅。
func (r *TrafficRepository) GetExternalSubscription(ctx context.Context, id int64, username string) (ExternalSubscription, error) {
	var sub ExternalSubscription
	if r == nil || r.db == nil {
		return sub, errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return sub, errors.New("subscription id is required")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return sub, errors.New("username is required")
	}

	const stmt = `SELECT id, username, name, url, COALESCE(user_agent, 'clash-meta/2.4.0'), node_count, last_sync_at, COALESCE(upload, 0), COALESCE(download, 0), COALESCE(total, 0), expire, COALESCE(traffic_mode, 'both'), created_at, updated_at FROM external_subscriptions WHERE id = ? AND username = ? LIMIT 1`
	var lastSyncAt, expire sql.NullTime
	err := r.db.QueryRowContext(ctx, stmt, id, username).Scan(&sub.ID, &sub.Username, &sub.Name, &sub.URL, &sub.UserAgent, &sub.NodeCount, &lastSyncAt, &sub.Upload, &sub.Download, &sub.Total, &expire, &sub.TrafficMode, &sub.CreatedAt, &sub.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sub, ErrExternalSubscriptionNotFound
		}
		return sub, fmt.Errorf("get external subscription: %w", err)
	}

	if lastSyncAt.Valid {
		sub.LastSyncAt = &lastSyncAt.Time
	}
	if expire.Valid {
		sub.Expire = &expire.Time
	}

	return sub, nil
}

// 创建一个新的外部订阅。
func (r *TrafficRepository) CreateExternalSubscription(ctx context.Context, sub ExternalSubscription) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}

	username := strings.TrimSpace(sub.Username)
	if username == "" {
		return 0, errors.New("username is required")
	}

	name := strings.TrimSpace(sub.Name)
	if name == "" {
		return 0, errors.New("subscription name is required")
	}

	url := strings.TrimSpace(sub.URL)
	if url == "" {
		return 0, errors.New("subscription url is required")
	}

	userAgent := strings.TrimSpace(sub.UserAgent)
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}

	trafficMode := strings.TrimSpace(sub.TrafficMode)
	if trafficMode == "" {
		trafficMode = "both"
	}

	const stmt = `INSERT INTO external_subscriptions (username, name, url, user_agent, node_count, last_sync_at, upload, download, total, expire, traffic_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	result, err := r.db.ExecContext(ctx, stmt, username, name, url, userAgent, sub.NodeCount, sub.LastSyncAt, sub.Upload, sub.Download, sub.Total, sub.Expire, trafficMode)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrExternalSubscriptionExists
		}
		return 0, fmt.Errorf("create external subscription: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}

	return id, nil
}

// 更新现有的外部订阅。
func (r *TrafficRepository) UpdateExternalSubscription(ctx context.Context, sub ExternalSubscription) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if sub.ID <= 0 {
		return errors.New("subscription id is required")
	}

	username := strings.TrimSpace(sub.Username)
	if username == "" {
		return errors.New("username is required")
	}

	name := strings.TrimSpace(sub.Name)
	if name == "" {
		return errors.New("subscription name is required")
	}

	url := strings.TrimSpace(sub.URL)
	if url == "" {
		return errors.New("subscription url is required")
	}

	userAgent := strings.TrimSpace(sub.UserAgent)
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}

	trafficMode := strings.TrimSpace(sub.TrafficMode)
	if trafficMode == "" {
		trafficMode = "both"
	}

	const stmt = `UPDATE external_subscriptions SET name = ?, url = ?, user_agent = ?, node_count = ?, last_sync_at = ?, upload = ?, download = ?, total = ?, expire = ?, traffic_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND username = ?`
	result, err := r.db.ExecContext(ctx, stmt, name, url, userAgent, sub.NodeCount, sub.LastSyncAt, sub.Upload, sub.Download, sub.Total, sub.Expire, trafficMode, sub.ID, username)
	if err != nil {
		return fmt.Errorf("update external subscription: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrExternalSubscriptionNotFound
	}

	return nil
}

// 删除外部订阅。
func (r *TrafficRepository) DeleteExternalSubscription(ctx context.Context, id int64, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("subscription id is required")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete external subscription: %w", err)
	}
	defer tx.Rollback()

	// The parent delete remains owner-scoped. Keeping both deletes in one
	// transaction ensures a foreign or missing ID cannot orphan another user's
	// provider configs before the ownership check fails.
	const deleteProvidersStmt = `DELETE FROM proxy_provider_configs WHERE external_subscription_id = ?`
	if _, err := tx.ExecContext(ctx, deleteProvidersStmt, id); err != nil {
		return fmt.Errorf("delete related proxy provider configs: %w", err)
	}

	const stmt = `DELETE FROM external_subscriptions WHERE id = ? AND username = ?`
	result, err := tx.ExecContext(ctx, stmt, id, username)
	if err != nil {
		return fmt.Errorf("delete external subscription: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrExternalSubscriptionNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete external subscription: %w", err)
	}
	return nil
}

// GetExternalSubscriptionByID 不限 owner 按 ID 取(仅管理员路径使用)。返回的 sub.Username 即 owner。
func (r *TrafficRepository) GetExternalSubscriptionByID(ctx context.Context, id int64) (ExternalSubscription, error) {
	var sub ExternalSubscription
	if r == nil || r.db == nil {
		return sub, errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return sub, errors.New("subscription id is required")
	}
	const stmt = `SELECT id, username, name, url, COALESCE(user_agent, 'clash-meta/2.4.0'), node_count, last_sync_at, COALESCE(upload, 0), COALESCE(download, 0), COALESCE(total, 0), expire, COALESCE(traffic_mode, 'both'), created_at, updated_at FROM external_subscriptions WHERE id = ? LIMIT 1`
	var lastSyncAt, expire sql.NullTime
	err := r.db.QueryRowContext(ctx, stmt, id).Scan(&sub.ID, &sub.Username, &sub.Name, &sub.URL, &sub.UserAgent, &sub.NodeCount, &lastSyncAt, &sub.Upload, &sub.Download, &sub.Total, &expire, &sub.TrafficMode, &sub.CreatedAt, &sub.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sub, ErrExternalSubscriptionNotFound
		}
		return sub, fmt.Errorf("get external subscription by id: %w", err)
	}
	if lastSyncAt.Valid {
		sub.LastSyncAt = &lastSyncAt.Time
	}
	if expire.Valid {
		sub.Expire = &expire.Time
	}
	return sub, nil
}

// UpdateExternalSubscriptionByID 不限 owner 按 ID 更新(仅管理员路径使用)。owner(username)不变。
func (r *TrafficRepository) UpdateExternalSubscriptionByID(ctx context.Context, sub ExternalSubscription) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if sub.ID <= 0 {
		return errors.New("subscription id is required")
	}
	name := strings.TrimSpace(sub.Name)
	if name == "" {
		return errors.New("subscription name is required")
	}
	url := strings.TrimSpace(sub.URL)
	if url == "" {
		return errors.New("subscription url is required")
	}
	userAgent := strings.TrimSpace(sub.UserAgent)
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}
	trafficMode := strings.TrimSpace(sub.TrafficMode)
	if trafficMode == "" {
		trafficMode = "both"
	}
	const stmt = `UPDATE external_subscriptions SET name = ?, url = ?, user_agent = ?, node_count = ?, last_sync_at = ?, upload = ?, download = ?, total = ?, expire = ?, traffic_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	result, err := r.db.ExecContext(ctx, stmt, name, url, userAgent, sub.NodeCount, sub.LastSyncAt, sub.Upload, sub.Download, sub.Total, sub.Expire, trafficMode, sub.ID)
	if err != nil {
		return fmt.Errorf("update external subscription by id: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrExternalSubscriptionNotFound
	}
	return nil
}

// DeleteExternalSubscriptionByID 不限 owner 按 ID 删除(仅管理员路径使用)。级联清 proxy_provider_configs。
func (r *TrafficRepository) DeleteExternalSubscriptionByID(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("subscription id is required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete external subscription by id: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM proxy_provider_configs WHERE external_subscription_id = ?`, id); err != nil {
		return fmt.Errorf("delete related proxy provider configs: %w", err)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM external_subscriptions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete external subscription by id: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrExternalSubscriptionNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete external subscription by id: %w", err)
	}
	return nil
}

// 自定义规则CRUD操作

var (
	ErrCustomRuleNotFound = errors.New("custom rule not found")
)

// 返回所有自定义规则，可以选择按类型过滤。
func (r *TrafficRepository) ListCustomRules(ctx context.Context, ruleType string) ([]CustomRule, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	var query string
	var args []interface{}

	if ruleType != "" {
		query = `SELECT id, name, type, mode, content, enabled, COALESCE(created_by,''), created_at, updated_at FROM custom_rules WHERE type = ? ORDER BY created_at DESC`
		args = append(args, ruleType)
	} else {
		query = `SELECT id, name, type, mode, content, enabled, COALESCE(created_by,''), created_at, updated_at FROM custom_rules ORDER BY created_at DESC`
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list custom rules: %w", err)
	}
	defer rows.Close()

	var rules []CustomRule
	for rows.Next() {
		var rule CustomRule
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Type, &rule.Mode, &rule.Content, &enabled, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan custom rule: %w", err)
		}
		rule.Enabled = enabled != 0
		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate custom rules: %w", err)
	}

	return rules, nil
}

// 按 ID 返回自定义规则。
func (r *TrafficRepository) GetCustomRule(ctx context.Context, id int64) (*CustomRule, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return nil, errors.New("custom rule id is required")
	}

	const query = `SELECT id, name, type, mode, content, enabled, COALESCE(created_by,''), created_at, updated_at FROM custom_rules WHERE id = ?`

	var rule CustomRule
	var enabled int
	err := r.db.QueryRowContext(ctx, query, id).Scan(&rule.ID, &rule.Name, &rule.Type, &rule.Mode, &rule.Content, &enabled, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCustomRuleNotFound
		}
		return nil, fmt.Errorf("get custom rule: %w", err)
	}

	rule.Enabled = enabled != 0
	return &rule, nil
}

// 创建新的自定义规则。
func (r *TrafficRepository) CreateCustomRule(ctx context.Context, rule *CustomRule) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if rule == nil {
		return errors.New("custom rule is required")
	}

	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		return errors.New("custom rule name is required")
	}

	rule.Type = strings.TrimSpace(rule.Type)
	if rule.Type != "dns" && rule.Type != "rules" && rule.Type != "rule-providers" {
		return errors.New("custom rule type must be 'dns', 'rules', or 'rule-providers'")
	}

	rule.Mode = strings.TrimSpace(rule.Mode)
	if rule.Type == "dns" {
		rule.Mode = "replace"
	} else if rule.Type == "rules" {
		// 规则类型支持替换、前置和附加
		if rule.Mode != "replace" && rule.Mode != "prepend" && rule.Mode != "append" {
			return errors.New("custom rule mode must be 'replace', 'prepend', or 'append' for rules type")
		}
	} else if rule.Mode != "replace" && rule.Mode != "prepend" {
		return errors.New("custom rule mode must be 'replace' or 'prepend'")
	}

	rule.Content = strings.TrimSpace(rule.Content)
	if rule.Content == "" {
		return errors.New("custom rule content is required")
	}

	const stmt = `INSERT INTO custom_rules (name, type, mode, content, enabled, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`

	enabled := 0
	if rule.Enabled {
		enabled = 1
	}

	result, err := r.db.ExecContext(ctx, stmt, rule.Name, rule.Type, rule.Mode, rule.Content, enabled, rule.CreatedBy)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("custom rule with this name and type already exists")
		}
		return fmt.Errorf("create custom rule: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	rule.ID = id
	return nil
}

// 更新现有的自定义规则。
func (r *TrafficRepository) UpdateCustomRule(ctx context.Context, rule *CustomRule) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if rule == nil {
		return errors.New("custom rule is required")
	}

	if rule.ID <= 0 {
		return errors.New("custom rule id is required")
	}

	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		return errors.New("custom rule name is required")
	}

	rule.Type = strings.TrimSpace(rule.Type)
	if rule.Type != "dns" && rule.Type != "rules" && rule.Type != "rule-providers" {
		return errors.New("custom rule type must be 'dns', 'rules', or 'rule-providers'")
	}

	rule.Mode = strings.TrimSpace(rule.Mode)
	if rule.Type == "dns" {
		rule.Mode = "replace"
	} else if rule.Type == "rules" {
		// 规则类型支持替换、前置和附加
		if rule.Mode != "replace" && rule.Mode != "prepend" && rule.Mode != "append" {
			return errors.New("custom rule mode must be 'replace', 'prepend', or 'append' for rules type")
		}
	} else if rule.Mode != "replace" && rule.Mode != "prepend" {
		return errors.New("custom rule mode must be 'replace' or 'prepend'")
	}

	rule.Content = strings.TrimSpace(rule.Content)
	if rule.Content == "" {
		return errors.New("custom rule content is required")
	}

	const stmt = `UPDATE custom_rules SET name = ?, type = ?, mode = ?, content = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`

	enabled := 0
	if rule.Enabled {
		enabled = 1
	}

	result, err := r.db.ExecContext(ctx, stmt, rule.Name, rule.Type, rule.Mode, rule.Content, enabled, rule.ID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errors.New("custom rule with this name and type already exists")
		}
		return fmt.Errorf("update custom rule: %w", err)
	}

	rows2, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rows2 == 0 {
		return ErrCustomRuleNotFound
	}

	return nil
}

// 按 ID 删除自定义规则。
func (r *TrafficRepository) DeleteCustomRule(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("custom rule id is required")
	}

	const stmt = `DELETE FROM custom_rules WHERE id = ?`
	result, err := r.db.ExecContext(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("delete custom rule: %w", err)
	}

	rows3, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rows3 == 0 {
		return ErrCustomRuleNotFound
	}

	return nil
}

// 返回所有启用的自定义规则，可以选择按类型过滤。
func (r *TrafficRepository) ListEnabledCustomRules(ctx context.Context, ruleType string) ([]CustomRule, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	var query string
	var args []interface{}

	if ruleType != "" {
		query = `SELECT id, name, type, mode, content, enabled, COALESCE(created_by, ''), created_at, updated_at FROM custom_rules WHERE type = ? AND enabled = 1 ORDER BY created_at DESC`
		args = append(args, ruleType)
	} else {
		query = `SELECT id, name, type, mode, content, enabled, COALESCE(created_by, ''), created_at, updated_at FROM custom_rules WHERE enabled = 1 ORDER BY created_at DESC`
	}

	rows4, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list enabled custom rules: %w", err)
	}
	defer rows4.Close()

	var rules []CustomRule
	for rows4.Next() {
		var rule CustomRule
		var enabled int
		if err := rows4.Scan(&rule.ID, &rule.Name, &rule.Type, &rule.Mode, &rule.Content, &enabled, &rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan custom rule: %w", err)
		}
		rule.Enabled = enabled != 0
		rules = append(rules, rule)
	}

	if err := rows4.Err(); err != nil {
		return nil, fmt.Errorf("iterate custom rules: %w", err)
	}

	return rules, nil
}

// 检索订阅文件的所有自定义规则应用程序。
func (r *TrafficRepository) GetCustomRuleApplications(ctx context.Context, fileID int64) ([]CustomRuleApplication, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if fileID <= 0 {
		return nil, errors.New("subscribe file id is required")
	}

	const query = `SELECT id, subscribe_file_id, custom_rule_id, rule_type, rule_mode, applied_content, content_hash, applied_at
		FROM custom_rule_applications
		WHERE subscribe_file_id = ?
		ORDER BY applied_at DESC`

	rows, err := r.db.QueryContext(ctx, query, fileID)
	if err != nil {
		return nil, fmt.Errorf("get custom rule applications: %w", err)
	}
	defer rows.Close()

	var applications []CustomRuleApplication
	for rows.Next() {
		var app CustomRuleApplication
		if err := rows.Scan(&app.ID, &app.SubscribeFileID, &app.CustomRuleID, &app.RuleType, &app.RuleMode, &app.AppliedContent, &app.ContentHash, &app.AppliedAt); err != nil {
			return nil, fmt.Errorf("scan custom rule application: %w", err)
		}
		applications = append(applications, app)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate custom rule applications: %w", err)
	}

	return applications, nil
}

// 插入或更新自定义规则应用程序记录。
func (r *TrafficRepository) UpsertCustomRuleApplication(ctx context.Context, app *CustomRuleApplication) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if app.SubscribeFileID <= 0 {
		return errors.New("subscribe file id is required")
	}
	if app.CustomRuleID <= 0 {
		return errors.New("custom rule id is required")
	}
	if app.RuleType == "" {
		return errors.New("rule type is required")
	}

	const stmt = `INSERT INTO custom_rule_applications (subscribe_file_id, custom_rule_id, rule_type, rule_mode, applied_content, content_hash, applied_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(subscribe_file_id, custom_rule_id, rule_type)
		DO UPDATE SET
			rule_mode = excluded.rule_mode,
			applied_content = excluded.applied_content,
			content_hash = excluded.content_hash,
			applied_at = CURRENT_TIMESTAMP`

	_, err := r.db.ExecContext(ctx, stmt, app.SubscribeFileID, app.CustomRuleID, app.RuleType, app.RuleMode, app.AppliedContent, app.ContentHash)
	if err != nil {
		return fmt.Errorf("upsert custom rule application: %w", err)
	}

	return nil
}

// 删除自定义规则应用程序记录。
func (r *TrafficRepository) DeleteCustomRuleApplication(ctx context.Context, fileID, ruleID int64, ruleType string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if fileID <= 0 {
		return errors.New("subscribe file id is required")
	}
	if ruleID <= 0 {
		return errors.New("custom rule id is required")
	}
	if ruleType == "" {
		return errors.New("rule type is required")
	}

	const stmt = `DELETE FROM custom_rule_applications WHERE subscribe_file_id = ? AND custom_rule_id = ? AND rule_type = ?`
	_, err := r.db.ExecContext(ctx, stmt, fileID, ruleID, ruleType)
	if err != nil {
		return fmt.Errorf("delete custom rule application: %w", err)
	}

	return nil
}

// 检查是否在任何 user_settings（系统级设置）中启用了sync_traffic。
func (r *TrafficRepository) IsSyncTrafficEnabled(ctx context.Context) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}

	const query = `SELECT COUNT(*) FROM user_settings WHERE sync_traffic = 1 LIMIT 1`
	var count int
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check sync traffic setting: %w", err)
	}

	return count > 0, nil
}

// 返回所有用户的所有外部订阅。
func (r *TrafficRepository) ListAllExternalSubscriptions(ctx context.Context) ([]ExternalSubscription, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const stmt = `SELECT id, username, name, url, COALESCE(user_agent, 'clash-meta/2.4.0'), node_count, last_sync_at, COALESCE(upload, 0), COALESCE(download, 0), COALESCE(total, 0), expire, COALESCE(traffic_mode, 'both'), created_at, updated_at FROM external_subscriptions ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("list all external subscriptions: %w", err)
	}
	defer rows.Close()

	var subs []ExternalSubscription
	for rows.Next() {
		var sub ExternalSubscription
		var lastSyncAt sql.NullTime
		var expire sql.NullTime
		if err := rows.Scan(&sub.ID, &sub.Username, &sub.Name, &sub.URL, &sub.UserAgent, &sub.NodeCount, &lastSyncAt, &sub.Upload, &sub.Download, &sub.Total, &expire, &sub.TrafficMode, &sub.CreatedAt, &sub.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan external subscription: %w", err)
		}
		if lastSyncAt.Valid {
			sub.LastSyncAt = &lastSyncAt.Time
		}
		if expire.Valid {
			sub.Expire = &expire.Time
		}
		subs = append(subs, sub)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate external subscriptions: %w", err)
	}

	return subs, nil
}

// 返回所有启用了自动同步的订阅文件。
func (r *TrafficRepository) GetSubscribeFilesWithAutoSync(ctx context.Context) ([]SubscribeFile, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT `+subscribeFileSelectCols+`
		FROM subscribe_files
		WHERE auto_sync_custom_rules = 1
		ORDER BY sort_order ASC, created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("get subscribe files with auto sync: %w", err)
	}
	defer rows.Close()

	var files []SubscribeFile
	for rows.Next() {
		file, err := scanSubscribeFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan subscribe file: %w", err)
		}
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscribe files: %w", err)
	}

	return files, nil
}

// 创建一个新的代理提供程序配置
func (r *TrafficRepository) CreateProxyProviderConfig(ctx context.Context, config *ProxyProviderConfig) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}

	healthCheckEnabled := 0
	if config.HealthCheckEnabled {
		healthCheckEnabled = 1
	}
	healthCheckLazy := 0
	if config.HealthCheckLazy {
		healthCheckLazy = 1
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO proxy_provider_configs (
			username, external_subscription_id, name, type, interval, proxy, size_limit, header,
			health_check_enabled, health_check_url, health_check_interval, health_check_timeout,
			health_check_lazy, health_check_expected_status,
			filter, exclude_filter, exclude_type, geo_ip_filter, override, process_mode
		)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		FROM external_subscriptions
		WHERE id = ? AND username = ?
	`,
		config.Username, config.ExternalSubscriptionID, config.Name, config.Type,
		config.Interval, config.Proxy, config.SizeLimit, config.Header,
		healthCheckEnabled, config.HealthCheckURL, config.HealthCheckInterval, config.HealthCheckTimeout,
		healthCheckLazy, config.HealthCheckExpectedStatus,
		config.Filter, config.ExcludeFilter, config.ExcludeType, config.GeoIPFilter, config.Override, config.ProcessMode,
		config.ExternalSubscriptionID, config.Username,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return 0, ErrProxyProviderConfigExists
		}
		return 0, fmt.Errorf("create proxy provider config: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return 0, ErrExternalSubscriptionNotFound
	}

	return result.LastInsertId()
}

// 通过 ID 检索代理提供程序配置
func (r *TrafficRepository) GetProxyProviderConfig(ctx context.Context, id int64) (*ProxyProviderConfig, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	row := r.db.QueryRowContext(ctx, `
		SELECT id, username, external_subscription_id, name, type, interval, proxy, size_limit,
			COALESCE(header, ''), health_check_enabled, health_check_url, health_check_interval,
			health_check_timeout, health_check_lazy, health_check_expected_status,
			COALESCE(filter, ''), COALESCE(exclude_filter, ''), COALESCE(exclude_type, ''),
			COALESCE(geo_ip_filter, ''), COALESCE(override, ''), process_mode, created_at, updated_at
		FROM proxy_provider_configs WHERE id = ?
	`, id)

	var config ProxyProviderConfig
	var healthCheckEnabled, healthCheckLazy int
	err := row.Scan(
		&config.ID, &config.Username, &config.ExternalSubscriptionID, &config.Name, &config.Type,
		&config.Interval, &config.Proxy, &config.SizeLimit, &config.Header,
		&healthCheckEnabled, &config.HealthCheckURL, &config.HealthCheckInterval,
		&config.HealthCheckTimeout, &healthCheckLazy, &config.HealthCheckExpectedStatus,
		&config.Filter, &config.ExcludeFilter, &config.ExcludeType,
		&config.GeoIPFilter, &config.Override, &config.ProcessMode, &config.CreatedAt, &config.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get proxy provider config: %w", err)
	}

	config.HealthCheckEnabled = healthCheckEnabled != 0
	config.HealthCheckLazy = healthCheckLazy != 0

	return &config, nil
}

// 按名称检索代理提供程序配置
func (r *TrafficRepository) GetProxyProviderConfigByName(ctx context.Context, name string) (*ProxyProviderConfig, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	row := r.db.QueryRowContext(ctx, `
		SELECT id, username, external_subscription_id, name, type, interval, proxy, size_limit,
			COALESCE(header, ''), health_check_enabled, health_check_url, health_check_interval,
			health_check_timeout, health_check_lazy, health_check_expected_status,
			COALESCE(filter, ''), COALESCE(exclude_filter, ''), COALESCE(exclude_type, ''),
			COALESCE(geo_ip_filter, ''), COALESCE(override, ''), process_mode, created_at, updated_at
		FROM proxy_provider_configs WHERE name = ?
	`, name)

	var config ProxyProviderConfig
	var healthCheckEnabled, healthCheckLazy int
	err := row.Scan(
		&config.ID, &config.Username, &config.ExternalSubscriptionID, &config.Name, &config.Type,
		&config.Interval, &config.Proxy, &config.SizeLimit, &config.Header,
		&healthCheckEnabled, &config.HealthCheckURL, &config.HealthCheckInterval,
		&config.HealthCheckTimeout, &healthCheckLazy, &config.HealthCheckExpectedStatus,
		&config.Filter, &config.ExcludeFilter, &config.ExcludeType,
		&config.GeoIPFilter, &config.Override, &config.ProcessMode, &config.CreatedAt, &config.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get proxy provider config by name: %w", err)
	}

	config.HealthCheckEnabled = healthCheckEnabled != 0
	config.HealthCheckLazy = healthCheckLazy != 0

	return &config, nil
}

// 返回用户的所有代理提供程序配置
func (r *TrafficRepository) ListProxyProviderConfigs(ctx context.Context, username string) ([]ProxyProviderConfig, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, external_subscription_id, name, type, interval, proxy, size_limit,
			COALESCE(header, ''), health_check_enabled, health_check_url, health_check_interval,
			health_check_timeout, health_check_lazy, health_check_expected_status,
			COALESCE(filter, ''), COALESCE(exclude_filter, ''), COALESCE(exclude_type, ''),
			COALESCE(geo_ip_filter, ''), COALESCE(override, ''), process_mode, created_at, updated_at
		FROM proxy_provider_configs WHERE username = ? ORDER BY id ASC
	`, username)
	if err != nil {
		return nil, fmt.Errorf("list proxy provider configs: %w", err)
	}
	defer rows.Close()

	var configs []ProxyProviderConfig
	for rows.Next() {
		var config ProxyProviderConfig
		var healthCheckEnabled, healthCheckLazy int
		err := rows.Scan(
			&config.ID, &config.Username, &config.ExternalSubscriptionID, &config.Name, &config.Type,
			&config.Interval, &config.Proxy, &config.SizeLimit, &config.Header,
			&healthCheckEnabled, &config.HealthCheckURL, &config.HealthCheckInterval,
			&config.HealthCheckTimeout, &healthCheckLazy, &config.HealthCheckExpectedStatus,
			&config.Filter, &config.ExcludeFilter, &config.ExcludeType,
			&config.GeoIPFilter, &config.Override, &config.ProcessMode, &config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan proxy provider config: %w", err)
		}
		config.HealthCheckEnabled = healthCheckEnabled != 0
		config.HealthCheckLazy = healthCheckLazy != 0
		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate proxy provider configs: %w", err)
	}

	return configs, nil
}

// 返回外部订阅的所有代理提供程序配置
func (r *TrafficRepository) ListProxyProviderConfigsBySubscription(ctx context.Context, externalSubscriptionID int64) ([]ProxyProviderConfig, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, external_subscription_id, name, type, interval, proxy, size_limit,
			COALESCE(header, ''), health_check_enabled, health_check_url, health_check_interval,
			health_check_timeout, health_check_lazy, health_check_expected_status,
			COALESCE(filter, ''), COALESCE(exclude_filter, ''), COALESCE(exclude_type, ''),
			COALESCE(geo_ip_filter, ''), COALESCE(override, ''), process_mode, created_at, updated_at
		FROM proxy_provider_configs WHERE external_subscription_id = ? ORDER BY id ASC
	`, externalSubscriptionID)
	if err != nil {
		return nil, fmt.Errorf("list proxy provider configs by subscription: %w", err)
	}
	defer rows.Close()

	var configs []ProxyProviderConfig
	for rows.Next() {
		var config ProxyProviderConfig
		var healthCheckEnabled, healthCheckLazy int
		err := rows.Scan(
			&config.ID, &config.Username, &config.ExternalSubscriptionID, &config.Name, &config.Type,
			&config.Interval, &config.Proxy, &config.SizeLimit, &config.Header,
			&healthCheckEnabled, &config.HealthCheckURL, &config.HealthCheckInterval,
			&config.HealthCheckTimeout, &healthCheckLazy, &config.HealthCheckExpectedStatus,
			&config.Filter, &config.ExcludeFilter, &config.ExcludeType,
			&config.GeoIPFilter, &config.Override, &config.ProcessMode, &config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan proxy provider config: %w", err)
		}
		config.HealthCheckEnabled = healthCheckEnabled != 0
		config.HealthCheckLazy = healthCheckLazy != 0
		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate proxy provider configs: %w", err)
	}

	return configs, nil
}

// ListServerProxyProviderConfigs 返回所有服务端处理模式的代理集合配置
// 该方法用于定时同步器获取需要自动刷新的代理集合列表
func (r *TrafficRepository) ListServerProxyProviderConfigs(ctx context.Context) ([]ProxyProviderConfig, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, external_subscription_id, name, type, interval, proxy, size_limit,
			COALESCE(header, ''), health_check_enabled, health_check_url, health_check_interval,
			health_check_timeout, health_check_lazy, health_check_expected_status,
			COALESCE(filter, ''), COALESCE(exclude_filter, ''), COALESCE(exclude_type, ''),
			COALESCE(geo_ip_filter, ''), COALESCE(override, ''), process_mode, created_at, updated_at
		FROM proxy_provider_configs
		WHERE process_mode = 'server'
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list server proxy provider configs: %w", err)
	}
	defer rows.Close()

	var configs []ProxyProviderConfig
	for rows.Next() {
		var config ProxyProviderConfig
		var healthCheckEnabled, healthCheckLazy int
		err := rows.Scan(
			&config.ID, &config.Username, &config.ExternalSubscriptionID, &config.Name, &config.Type,
			&config.Interval, &config.Proxy, &config.SizeLimit, &config.Header,
			&healthCheckEnabled, &config.HealthCheckURL, &config.HealthCheckInterval,
			&config.HealthCheckTimeout, &healthCheckLazy, &config.HealthCheckExpectedStatus,
			&config.Filter, &config.ExcludeFilter, &config.ExcludeType,
			&config.GeoIPFilter, &config.Override, &config.ProcessMode, &config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan server proxy provider config: %w", err)
		}
		config.HealthCheckEnabled = healthCheckEnabled != 0
		config.HealthCheckLazy = healthCheckLazy != 0
		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate server proxy provider configs: %w", err)
	}

	return configs, nil
}

// 更新现有的代理提供程序配置
func (r *TrafficRepository) UpdateProxyProviderConfig(ctx context.Context, config *ProxyProviderConfig) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	healthCheckEnabled := 0
	if config.HealthCheckEnabled {
		healthCheckEnabled = 1
	}
	healthCheckLazy := 0
	if config.HealthCheckLazy {
		healthCheckLazy = 1
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE proxy_provider_configs SET
			external_subscription_id = ?, name = ?, type = ?, interval = ?, proxy = ?, size_limit = ?, header = ?,
			health_check_enabled = ?, health_check_url = ?, health_check_interval = ?,
			health_check_timeout = ?, health_check_lazy = ?, health_check_expected_status = ?,
			filter = ?, exclude_filter = ?, exclude_type = ?, geo_ip_filter = ?, override = ?, process_mode = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND username = ?
		  AND EXISTS (
			SELECT 1 FROM external_subscriptions
			WHERE external_subscriptions.id = ? AND external_subscriptions.username = ?
		  )
	`,
		config.ExternalSubscriptionID, config.Name, config.Type, config.Interval, config.Proxy, config.SizeLimit, config.Header,
		healthCheckEnabled, config.HealthCheckURL, config.HealthCheckInterval,
		config.HealthCheckTimeout, healthCheckLazy, config.HealthCheckExpectedStatus,
		config.Filter, config.ExcludeFilter, config.ExcludeType, config.GeoIPFilter, config.Override, config.ProcessMode,
		config.ID, config.Username, config.ExternalSubscriptionID, config.Username,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrProxyProviderConfigExists
		}
		return fmt.Errorf("update proxy provider config: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrExternalSubscriptionNotFound
	}

	return nil
}

// 删除代理提供程序配置
func (r *TrafficRepository) DeleteProxyProviderConfig(ctx context.Context, id int64, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM proxy_provider_configs WHERE id = ? AND username = ?`, id, username)
	if err != nil {
		return fmt.Errorf("delete proxy provider config: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return errors.New("proxy provider config not found or not owned by user")
	}

	return nil
}

// GetSystemConfig 检索全局系统配置。
// 如果该行不存在，则返回空的 SystemConfig（迁移后不应发生）。
func (r *TrafficRepository) GetSystemConfig(ctx context.Context) (SystemConfig, error) {
	const query = `
SELECT proxy_groups_source_url, client_compatibility_mode, COALESCE(enable_short_link, 1),
       COALESCE(speed_collect_interval, 3), COALESCE(traffic_collect_interval, 60),
       COALESCE(traffic_check_interval, 120), COALESCE(heartbeat_interval, 30),
       COALESCE(agent_log_enabled, 0),
       COALESCE(notify_enabled, 0), COALESCE(telegram_bot_token, ''), COALESCE(telegram_chat_id, ''),
       COALESCE(notify_login, 0), COALESCE(notify_subscribe_fetch, 0), COALESCE(notify_daily_traffic, 0),
       COALESCE(notify_server_offline, 0), COALESCE(notify_server_online, 0), COALESCE(notify_traffic_threshold, 0),
       COALESCE(notify_daily_traffic_time, '08:00'), COALESCE(notify_traffic_threshold_percent, 80),
       COALESCE(enable_override_scripts, 0),
       COALESCE(subscription_output_format, 'yaml'),
       COALESCE(silent_mode, 0), COALESCE(silent_mode_timeout, 15),
       COALESCE(enable_management_features, 1), COALESCE(default_template_filename, ''),
		COALESCE(enable_root_short_links, 0),
       COALESCE(node_name_multiplier_prefix_enabled, 0),
       COALESCE(node_name_multiplier_left, '「'),
       COALESCE(node_name_multiplier_right, '」'),
       COALESCE(notify_traffic_threshold_80, 0),
       COALESCE(notify_over_limit, 0),
       COALESCE(notify_package_expiring, 0),
       COALESCE(notify_package_expiring_days, 3),
       COALESCE(notify_package_expired, 0),
       COALESCE(notify_user_registered, 0),
       COALESCE(notify_telegram_bound, 0),
       COALESCE(notify_cert_result, 0),
       COALESCE(notify_agent_long_offline, 0),
       COALESCE(notify_agent_long_offline_minutes, 30),
       COALESCE(notify_device_limit_exceeded, 0)
FROM system_config
WHERE id = 1
`

	var cfg SystemConfig
	var compatibilityMode, enableShortLink, agentLogEnabled int
	var notifyEnabled, notifyLogin, notifySubFetch, notifyDailyTraffic int
	var notifyServerOffline, notifyServerOnline, notifyTrafficThreshold int
	var enableOverrideScripts, silentMode, silentModeTimeout int
	var enableManagementFeatures, enableRootShortLinks int
	var nodeNameMultPrefixEnabled int
	var notifyTH80, notifyOverLimit, notifyPkgExpiring, notifyPkgExpired int
	var notifyUserReg, notifyTGBound, notifyCert, notifyAgentLO, notifyDeviceLimit int
	err := r.db.QueryRowContext(ctx, query).Scan(
		&cfg.ProxyGroupsSourceURL, &compatibilityMode, &enableShortLink,
		&cfg.SpeedCollectInterval, &cfg.TrafficCollectInterval,
		&cfg.TrafficCheckInterval, &cfg.HeartbeatInterval,
		&agentLogEnabled,
		&notifyEnabled, &cfg.TelegramBotToken, &cfg.TelegramChatID,
		&notifyLogin, &notifySubFetch, &notifyDailyTraffic,
		&notifyServerOffline, &notifyServerOnline, &notifyTrafficThreshold,
		&cfg.NotifyDailyTrafficTime, &cfg.NotifyTrafficThresholdPercent,
		&enableOverrideScripts,
		&cfg.SubscriptionOutputFormat,
		&silentMode, &silentModeTimeout,
		&enableManagementFeatures, &cfg.DefaultTemplateFilename,
		&enableRootShortLinks,
		&nodeNameMultPrefixEnabled, &cfg.NodeNameMultiplierLeft, &cfg.NodeNameMultiplierRight,
		&notifyTH80, &notifyOverLimit, &notifyPkgExpiring, &cfg.NotifyPackageExpiringDays,
		&notifyPkgExpired, &notifyUserReg, &notifyTGBound, &notifyCert, &notifyAgentLO,
		&cfg.NotifyAgentLongOfflineMinutes, &notifyDeviceLimit,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SystemConfig{EnableShortLink: true, SpeedCollectInterval: 3, TrafficCollectInterval: 60, TrafficCheckInterval: 120, HeartbeatInterval: 30, NotifyDailyTrafficTime: "08:00", NotifyTrafficThresholdPercent: 80, SubscriptionOutputFormat: "yaml", SilentModeTimeout: 15, EnableManagementFeatures: true}, nil
		}
		return SystemConfig{}, fmt.Errorf("query system config: %w", err)
	}

	cfg.ClientCompatibilityMode = compatibilityMode != 0
	cfg.EnableShortLink = enableShortLink != 0
	cfg.AgentLogEnabled = agentLogEnabled != 0
	cfg.NotifyEnabled = notifyEnabled != 0
	cfg.NotifyLogin = notifyLogin != 0
	cfg.NotifySubscribeFetch = notifySubFetch != 0
	cfg.NotifyDailyTraffic = notifyDailyTraffic != 0
	cfg.NotifyServerOffline = notifyServerOffline != 0
	cfg.NotifyServerOnline = notifyServerOnline != 0
	cfg.NotifyTrafficThreshold = notifyTrafficThreshold != 0
	cfg.EnableOverrideScripts = enableOverrideScripts != 0
	if cfg.SubscriptionOutputFormat == "" {
		cfg.SubscriptionOutputFormat = "yaml"
	}
	cfg.SilentMode = silentMode != 0
	cfg.SilentModeTimeout = silentModeTimeout
	if cfg.SilentModeTimeout <= 0 {
		cfg.SilentModeTimeout = 15
	}
	cfg.EnableManagementFeatures = enableManagementFeatures != 0
	cfg.EnableRootShortLinks = enableRootShortLinks != 0
	cfg.NodeNameMultiplierPrefixEnabled = nodeNameMultPrefixEnabled != 0
	cfg.NotifyTrafficThreshold80 = notifyTH80 != 0
	cfg.NotifyOverLimit = notifyOverLimit != 0
	cfg.NotifyPackageExpiring = notifyPkgExpiring != 0
	cfg.NotifyPackageExpired = notifyPkgExpired != 0
	cfg.NotifyUserRegistered = notifyUserReg != 0
	cfg.NotifyTelegramBound = notifyTGBound != 0
	cfg.NotifyCertResult = notifyCert != 0
	cfg.NotifyAgentLongOffline = notifyAgentLO != 0
	cfg.NotifyDeviceLimitExceeded = notifyDeviceLimit != 0
	if cfg.NotifyPackageExpiringDays <= 0 {
		cfg.NotifyPackageExpiringDays = 3
	}
	if cfg.NotifyAgentLongOfflineMinutes <= 0 {
		cfg.NotifyAgentLongOfflineMinutes = 30
	}
	return cfg, nil
}

// UpdateSystemConfig 更新全局系统配置。
// 如果单例行不存在则创建它（防御性）。
func (r *TrafficRepository) UpdateSystemConfig(ctx context.Context, cfg SystemConfig) error {
	const updateStmt = `
UPDATE system_config
SET proxy_groups_source_url = ?,
    client_compatibility_mode = ?,
    enable_short_link = ?,
    speed_collect_interval = ?,
    traffic_collect_interval = ?,
    traffic_check_interval = ?,
    heartbeat_interval = ?,
    agent_log_enabled = ?,
    notify_enabled = ?,
    telegram_bot_token = ?,
    telegram_chat_id = ?,
    notify_login = ?,
    notify_subscribe_fetch = ?,
    notify_daily_traffic = ?,
    notify_server_offline = ?,
    notify_server_online = ?,
    notify_traffic_threshold = ?,
    notify_daily_traffic_time = ?,
    notify_traffic_threshold_percent = ?,
    enable_override_scripts = ?,
    subscription_output_format = ?,
    silent_mode = ?,
    silent_mode_timeout = ?,
    enable_management_features = ?,
    default_template_filename = ?,
    enable_root_short_links = ?,
    node_name_multiplier_prefix_enabled = ?,
    node_name_multiplier_left = ?,
    node_name_multiplier_right = ?,
    notify_traffic_threshold_80 = ?,
    notify_over_limit = ?,
    notify_package_expiring = ?,
    notify_package_expiring_days = ?,
    notify_package_expired = ?,
    notify_user_registered = ?,
    notify_telegram_bound = ?,
    notify_cert_result = ?,
    notify_agent_long_offline = ?,
    notify_agent_long_offline_minutes = ?,
    notify_device_limit_exceeded = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = 1
`

	compatibilityMode := 0
	if cfg.ClientCompatibilityMode {
		compatibilityMode = 1
	}
	enableShortLink := 0
	if cfg.EnableShortLink {
		enableShortLink = 1
	}
	agentLogEnabled := 0
	if cfg.AgentLogEnabled {
		agentLogEnabled = 1
	}

	boolToInt := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	silentModeTimeout := cfg.SilentModeTimeout
	if silentModeTimeout <= 0 {
		silentModeTimeout = 15
	}

	// 仅接受 yaml / json 二值,其他兜底 yaml(避免老配置 / 入参错乱触发 CHECK 或后端误判)
	subOutFmt := cfg.SubscriptionOutputFormat
	if subOutFmt != "json" {
		subOutFmt = "yaml"
	}

	// 默认分隔符兜底(老配置可能 nil/空)
	nnmLeft := cfg.NodeNameMultiplierLeft
	if nnmLeft == "" {
		nnmLeft = "「"
	}
	nnmRight := cfg.NodeNameMultiplierRight
	if nnmRight == "" {
		nnmRight = "」"
	}

	// Phase 2 默认值兜底:0 表示用户从未设过,落库时给个合理初值
	pkgExpiringDays := cfg.NotifyPackageExpiringDays
	if pkgExpiringDays <= 0 {
		pkgExpiringDays = 3
	}
	agentLOMinutes := cfg.NotifyAgentLongOfflineMinutes
	if agentLOMinutes <= 0 {
		agentLOMinutes = 30
	}

	result, err := r.db.ExecContext(ctx, updateStmt, cfg.ProxyGroupsSourceURL, compatibilityMode, enableShortLink,
		cfg.SpeedCollectInterval, cfg.TrafficCollectInterval, cfg.TrafficCheckInterval, cfg.HeartbeatInterval,
		agentLogEnabled,
		boolToInt(cfg.NotifyEnabled), cfg.TelegramBotToken, cfg.TelegramChatID,
		boolToInt(cfg.NotifyLogin), boolToInt(cfg.NotifySubscribeFetch), boolToInt(cfg.NotifyDailyTraffic),
		boolToInt(cfg.NotifyServerOffline), boolToInt(cfg.NotifyServerOnline), boolToInt(cfg.NotifyTrafficThreshold),
		cfg.NotifyDailyTrafficTime, cfg.NotifyTrafficThresholdPercent,
		boolToInt(cfg.EnableOverrideScripts),
		subOutFmt,
		boolToInt(cfg.SilentMode), silentModeTimeout,
		boolToInt(cfg.EnableManagementFeatures), cfg.DefaultTemplateFilename,
		boolToInt(cfg.EnableRootShortLinks),
		boolToInt(cfg.NodeNameMultiplierPrefixEnabled), nnmLeft, nnmRight,
		boolToInt(cfg.NotifyTrafficThreshold80), boolToInt(cfg.NotifyOverLimit),
		boolToInt(cfg.NotifyPackageExpiring), pkgExpiringDays,
		boolToInt(cfg.NotifyPackageExpired), boolToInt(cfg.NotifyUserRegistered),
		boolToInt(cfg.NotifyTelegramBound), boolToInt(cfg.NotifyCertResult),
		boolToInt(cfg.NotifyAgentLongOffline), agentLOMinutes,
		boolToInt(cfg.NotifyDeviceLimitExceeded))
	if err != nil {
		return fmt.Errorf("update system config: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		const insertStmt = `
INSERT INTO system_config (id, proxy_groups_source_url, client_compatibility_mode, enable_short_link,
    speed_collect_interval, traffic_collect_interval, traffic_check_interval, heartbeat_interval, agent_log_enabled,
    notify_enabled, telegram_bot_token, telegram_chat_id, notify_login, notify_subscribe_fetch,
    notify_daily_traffic, notify_server_offline, notify_server_online, notify_traffic_threshold,
    notify_daily_traffic_time, notify_traffic_threshold_percent, enable_override_scripts,
    subscription_output_format,
    silent_mode, silent_mode_timeout, enable_management_features, default_template_filename, enable_root_short_links,
    node_name_multiplier_prefix_enabled, node_name_multiplier_left, node_name_multiplier_right,
    notify_traffic_threshold_80, notify_over_limit, notify_package_expiring, notify_package_expiring_days,
    notify_package_expired, notify_user_registered, notify_telegram_bound, notify_cert_result,
    notify_agent_long_offline, notify_agent_long_offline_minutes, notify_device_limit_exceeded)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`
		if _, err := r.db.ExecContext(ctx, insertStmt, cfg.ProxyGroupsSourceURL, compatibilityMode, enableShortLink,
			cfg.SpeedCollectInterval, cfg.TrafficCollectInterval, cfg.TrafficCheckInterval, cfg.HeartbeatInterval, agentLogEnabled,
			boolToInt(cfg.NotifyEnabled), cfg.TelegramBotToken, cfg.TelegramChatID,
			boolToInt(cfg.NotifyLogin), boolToInt(cfg.NotifySubscribeFetch), boolToInt(cfg.NotifyDailyTraffic),
			boolToInt(cfg.NotifyServerOffline), boolToInt(cfg.NotifyServerOnline), boolToInt(cfg.NotifyTrafficThreshold),
			cfg.NotifyDailyTrafficTime, cfg.NotifyTrafficThresholdPercent,
			boolToInt(cfg.EnableOverrideScripts),
			subOutFmt,
			boolToInt(cfg.SilentMode), silentModeTimeout,
			boolToInt(cfg.EnableManagementFeatures), cfg.DefaultTemplateFilename,
			boolToInt(cfg.EnableRootShortLinks),
			boolToInt(cfg.NodeNameMultiplierPrefixEnabled), nnmLeft, nnmRight,
			boolToInt(cfg.NotifyTrafficThreshold80), boolToInt(cfg.NotifyOverLimit),
			boolToInt(cfg.NotifyPackageExpiring), pkgExpiringDays,
			boolToInt(cfg.NotifyPackageExpired), boolToInt(cfg.NotifyUserRegistered),
			boolToInt(cfg.NotifyTelegramBound), boolToInt(cfg.NotifyCertResult),
			boolToInt(cfg.NotifyAgentLongOffline), agentLOMinutes,
			boolToInt(cfg.NotifyDeviceLimitExceeded)); err != nil {
			return fmt.Errorf("insert system config: %w", err)
		}
	}

	return nil
}

// Xray 服务器 CRUD 操作

// 返回所有 Xray 服务器。
func (r *TrafficRepository) ListXrayServers(ctx context.Context) ([]XrayServer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const query = `SELECT id, name, host, port, COALESCE(description, ''), COALESCE(is_primary, 0), process_id, COALESCE(config_path, ''), COALESCE(traffic_limit, 0), COALESCE(traffic_reset_day, 0), COALESCE(traffic_used_offset, 0), created_at, updated_at FROM xray_servers ORDER BY is_primary DESC, created_at DESC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list xray servers: %w", err)
	}
	defer rows.Close()

	var servers []XrayServer
	for rows.Next() {
		var server XrayServer
		var isPrimary int
		if err := rows.Scan(&server.ID, &server.Name, &server.Host, &server.Port, &server.Description, &isPrimary, &server.ProcessID, &server.ConfigPath, &server.TrafficLimit, &server.TrafficResetDay, &server.TrafficUsedOffset, &server.CreatedAt, &server.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan xray server: %w", err)
		}
		server.IsPrimary = isPrimary != 0
		servers = append(servers, server)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate xray servers: %w", err)
	}

	// 从node_traffic表+偏移量计算每个服务器使用的流量
	for i := range servers {
		aggregated, err := r.GetServerTrafficUsed(ctx, servers[i].ID)
		if err == nil {
			servers[i].TrafficUsed = aggregated + servers[i].TrafficUsedOffset
		}
	}

	return servers, nil
}

// GetServerTrafficUsed 计算服务器的"已用流量",按 traffic_source 分支:
//   - source='xray'(默认)→ SUM(node_traffic.uplink+downlink),跟节点视图口径一致
//   - source='system'    → 累加 system_rx_cycle + system_tx_cycle(agent /proc/net/dev 上报)
//
// traffic_stats_mode (both/upload/download) 对两种数据源同样适用:
//   - upload = 出方向 = node_traffic.uplink 或 system_tx_cycle
//   - download = 入方向 = node_traffic.downlink 或 system_rx_cycle
//
// 用户流量按套餐 traffic_mode 走,不在此处处理。
type trafficQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getServerTrafficUsed(ctx context.Context, q trafficQueryRower, serverID int64) (int64, error) {
	if serverID <= 0 {
		return 0, errors.New("server id is required")
	}

	var (
		mode   = "both"
		source = "xray"
		sysRx  int64
		sysTx  int64
	)
	if err := q.QueryRowContext(ctx, `
		SELECT COALESCE(traffic_stats_mode, 'both'), COALESCE(traffic_source, 'xray'),
		       COALESCE(system_rx_cycle, 0), COALESCE(system_tx_cycle, 0)
		FROM remote_servers WHERE id = ?`, serverID).Scan(&mode, &source, &sysRx, &sysTx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrRemoteServerNotFound
		}
		return 0, fmt.Errorf("get server traffic settings: %w", err)
	}

	if source == "system" {
		switch mode {
		case "upload":
			return sysTx, nil
		case "download":
			return sysRx, nil
		case "max":
			if sysRx > sysTx {
				return sysRx, nil
			}
			return sysTx, nil
		default:
			return sysRx + sysTx, nil
		}
	}

	var query string
	switch mode {
	case "upload":
		query = `SELECT COALESCE(SUM(uplink), 0) FROM node_traffic WHERE server_id = ?`
	case "download":
		query = `SELECT COALESCE(SUM(downlink), 0) FROM node_traffic WHERE server_id = ?`
	case "max":
		query = `SELECT CASE WHEN COALESCE(SUM(uplink),0) > COALESCE(SUM(downlink),0)
		                     THEN COALESCE(SUM(uplink),0) ELSE COALESCE(SUM(downlink),0) END
		         FROM node_traffic WHERE server_id = ?`
	default:
		query = `SELECT COALESCE(SUM(uplink + downlink), 0) FROM node_traffic WHERE server_id = ?`
	}

	var total int64
	if err := q.QueryRowContext(ctx, query, serverID).Scan(&total); err != nil {
		return 0, fmt.Errorf("get server traffic used: %w", err)
	}
	return total, nil
}

func (r *TrafficRepository) GetServerTrafficUsed(ctx context.Context, serverID int64) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	return getServerTrafficUsed(ctx, r.db, serverID)
}

// UpsertRemoteServerSystemTraffic 处理 agent 每次 traffic 上报里带的系统级累计 RX/TX:
//   - boot_time_unix 与 server.system_boot_time_unix 不一致 → 系统重启,基线重建,本次不计 delta
//   - 同 boot 周期下 rxTotal 倒退(/proc 抖动)→ 跳一次不计 delta,避免一个错值毁掉 cycle 累计
//   - 正常:rxDelta = rxTotal - last_seen_rx,累加到 system_rx_cycle;tx 同理
//   - last_seen_rx/tx 和 system_boot_time_unix 永远更新为本次上报值
//
// 在 RemoteTrafficHandler 解析到 payload.system 时调用。
func (r *TrafficRepository) UpsertRemoteServerSystemTraffic(ctx context.Context, serverID, rxTotal, txTotal, bootTimeUnix int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	var (
		lastRx   int64
		lastTx   int64
		lastBoot int64
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(system_last_seen_rx, 0), COALESCE(system_last_seen_tx, 0),
		       COALESCE(system_boot_time_unix, 0)
		FROM remote_servers WHERE id = ?`, serverID).Scan(&lastRx, &lastTx, &lastBoot)
	if err != nil {
		return fmt.Errorf("read server system traffic state: %w", err)
	}

	rxDelta, txDelta := int64(0), int64(0)
	// lastBoot=0 是首次上报;lastBoot != bootTimeUnix 是系统/agent 重启 — 两种情况都不计 delta
	if lastBoot != 0 && lastBoot == bootTimeUnix {
		if rxTotal >= lastRx {
			rxDelta = rxTotal - lastRx
		}
		if txTotal >= lastTx {
			txDelta = txTotal - lastTx
		}
	}

	_, err = r.db.ExecContext(ctx, `
		UPDATE remote_servers SET
			system_rx_cycle = COALESCE(system_rx_cycle, 0) + ?,
			system_tx_cycle = COALESCE(system_tx_cycle, 0) + ?,
			system_last_seen_rx = ?,
			system_last_seen_tx = ?,
			system_boot_time_unix = ?,
			system_traffic_updated_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		rxDelta, txDelta, rxTotal, txTotal, bootTimeUnix, serverID)
	if err != nil {
		return fmt.Errorf("update server system traffic: %w", err)
	}
	return nil
}

// ResetRemoteServerSystemCycle 清零 cycle 累计,保留 last_seen / boot_time_unix(物理网卡累计不变)。
// 在套餐周期 reset 触发时调用,跟 node_traffic 的归零同步。
func (r *TrafficRepository) ResetRemoteServerSystemCycle(ctx context.Context, serverID int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE remote_servers SET
			system_rx_cycle = 0,
			system_tx_cycle = 0,
			system_traffic_updated_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, serverID)
	if err != nil {
		return fmt.Errorf("reset server system cycle: %w", err)
	}
	return nil
}

func (r *TrafficRepository) GetRemoteServerTrafficTotals(ctx context.Context, serverIDs []int64) (limit int64, used int64, err error) {
	if r == nil || r.db == nil {
		return 0, 0, errors.New("traffic repository not initialized")
	}
	for _, id := range serverIDs {
		server, sErr := r.GetRemoteServer(ctx, id)
		if sErr != nil {
			continue
		}
		aggregated, _ := r.GetServerTrafficUsed(ctx, id)
		used += aggregated + server.TrafficUsedOffset
		limit += server.TrafficLimit
	}
	return limit, used, nil
}

func (r *TrafficRepository) GetAllRemoteServersTrafficTotals(ctx context.Context) (limit int64, used int64, err error) {
	if r == nil || r.db == nil {
		return 0, 0, errors.New("traffic repository not initialized")
	}
	servers, err := r.ListRemoteServers(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, s := range servers {
		aggregated, _ := r.GetServerTrafficUsed(ctx, s.ID)
		used += aggregated + s.TrafficUsedOffset
		limit += s.TrafficLimit
	}
	return limit, used, nil
}

// GetInboundTagServerMap 批量获取所有 inbound tag → server_id 映射
func (r *TrafficRepository) GetInboundTagServerMap(ctx context.Context) (map[string]int64, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	const query = `SELECT tag, server_id FROM batch_inbounds`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get inbound tag server map: %w", err)
	}
	defer rows.Close()
	result := make(map[string]int64)
	for rows.Next() {
		var tag string
		var serverID int64
		if err := rows.Scan(&tag, &serverID); err != nil {
			return nil, err
		}
		result[tag] = serverID
	}
	return result, nil
}

// 批量入站 CRUD 操作

// 创建新的批次入站记录。
func (r *TrafficRepository) CreateBatchInbound(ctx context.Context, batch *BatchInbound) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if batch == nil {
		return errors.New("batch inbound is required")
	}

	batch.BatchID = strings.TrimSpace(batch.BatchID)
	if batch.BatchID == "" {
		return errors.New("batch id is required")
	}

	batch.Tag = strings.TrimSpace(batch.Tag)
	if batch.Tag == "" {
		return errors.New("tag is required")
	}

	if batch.ServerID <= 0 {
		return errors.New("server id is required")
	}

	const stmt = `INSERT INTO batch_inbounds (batch_id, tag, server_id, protocol, port, created_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	result, err := r.db.ExecContext(ctx, stmt, batch.BatchID, batch.Tag, batch.ServerID, batch.Protocol, batch.Port)
	if err != nil {
		return fmt.Errorf("create batch inbound: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	batch.ID = id
	return nil
}

// 返回具有给定批次 ID 的所有批次入站。
func (r *TrafficRepository) GetBatchInboundsByBatchID(ctx context.Context, batchID string) ([]BatchInbound, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	batchID = strings.TrimSpace(batchID)
	if batchID == "" {
		return nil, errors.New("batch id is required")
	}

	const query = `SELECT id, batch_id, tag, server_id, protocol, port, created_at FROM batch_inbounds WHERE batch_id = ?`
	rows, err := r.db.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("get batch inbounds by batch id: %w", err)
	}
	defer rows.Close()

	var batches []BatchInbound
	for rows.Next() {
		var batch BatchInbound
		if err := rows.Scan(&batch.ID, &batch.BatchID, &batch.Tag, &batch.ServerID, &batch.Protocol, &batch.Port, &batch.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan batch inbound: %w", err)
		}
		batches = append(batches, batch)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate batch inbounds: %w", err)
	}

	return batches, nil
}

// 返回具有给定标签的所有批次入站。
func (r *TrafficRepository) GetBatchInboundsByTag(ctx context.Context, tag string) ([]BatchInbound, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, errors.New("tag is required")
	}

	const query = `SELECT id, batch_id, tag, server_id, protocol, port, created_at FROM batch_inbounds WHERE tag = ?`
	rows, err := r.db.QueryContext(ctx, query, tag)
	if err != nil {
		return nil, fmt.Errorf("get batch inbounds by tag: %w", err)
	}
	defer rows.Close()

	var batches []BatchInbound
	for rows.Next() {
		var batch BatchInbound
		if err := rows.Scan(&batch.ID, &batch.BatchID, &batch.Tag, &batch.ServerID, &batch.Protocol, &batch.Port, &batch.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan batch inbound: %w", err)
		}
		batches = append(batches, batch)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate batch inbounds: %w", err)
	}

	return batches, nil
}

// 删除具有给定批次 ID 的所有批次入站。
func (r *TrafficRepository) DeleteBatchInboundsByBatchID(ctx context.Context, batchID string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	batchID = strings.TrimSpace(batchID)
	if batchID == "" {
		return errors.New("batch id is required")
	}

	const stmt = `DELETE FROM batch_inbounds WHERE batch_id = ?`
	_, err := r.db.ExecContext(ctx, stmt, batchID)
	if err != nil {
		return fmt.Errorf("delete batch inbounds by batch id: %w", err)
	}

	return nil
}

// 删除具有给定标签的所有批次入站。
func (r *TrafficRepository) DeleteBatchInboundsByTag(ctx context.Context, tag string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	tag = strings.TrimSpace(tag)
	if tag == "" {
		return errors.New("tag is required")
	}

	const stmt = `DELETE FROM batch_inbounds WHERE tag = ?`
	_, err := r.db.ExecContext(ctx, stmt, tag)
	if err != nil {
		return fmt.Errorf("delete batch inbounds by tag: %w", err)
	}

	return nil
}

// 批量出站 CRUD 操作

// CreateBatchOutb​​ound 创建新的批量出站记录。
func (r *TrafficRepository) CreateBatchOutbound(ctx context.Context, batch *BatchOutbound) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if batch == nil {
		return errors.New("batch outbound is required")
	}

	batch.BatchID = strings.TrimSpace(batch.BatchID)
	if batch.BatchID == "" {
		return errors.New("batch id is required")
	}

	batch.Tag = strings.TrimSpace(batch.Tag)
	if batch.Tag == "" {
		return errors.New("tag is required")
	}

	if batch.ServerID <= 0 {
		return errors.New("server id is required")
	}

	const stmt = `INSERT INTO batch_outbounds (batch_id, tag, server_id, protocol, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`

	result, err := r.db.ExecContext(ctx, stmt, batch.BatchID, batch.Tag, batch.ServerID, batch.Protocol)
	if err != nil {
		return fmt.Errorf("create batch outbound: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	batch.ID = id
	return nil
}

// GetBatchOutb​​oundsByBatchID 返回具有给定批次 ID 的所有批次出站。
func (r *TrafficRepository) GetBatchOutboundsByBatchID(ctx context.Context, batchID string) ([]BatchOutbound, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	batchID = strings.TrimSpace(batchID)
	if batchID == "" {
		return nil, errors.New("batch id is required")
	}

	const query = `SELECT id, batch_id, tag, server_id, protocol, created_at FROM batch_outbounds WHERE batch_id = ?`
	rows, err := r.db.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("get batch outbounds by batch id: %w", err)
	}
	defer rows.Close()

	var batches []BatchOutbound
	for rows.Next() {
		var batch BatchOutbound
		if err := rows.Scan(&batch.ID, &batch.BatchID, &batch.Tag, &batch.ServerID, &batch.Protocol, &batch.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan batch outbound: %w", err)
		}
		batches = append(batches, batch)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate batch outbounds: %w", err)
	}

	return batches, nil
}

// GetBatchOutb​​oundsByTag 返回具有给定标签的所有批次出站。
func (r *TrafficRepository) GetBatchOutboundsByTag(ctx context.Context, tag string) ([]BatchOutbound, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, errors.New("tag is required")
	}

	const query = `SELECT id, batch_id, tag, server_id, protocol, created_at FROM batch_outbounds WHERE tag = ?`
	rows, err := r.db.QueryContext(ctx, query, tag)
	if err != nil {
		return nil, fmt.Errorf("get batch outbounds by tag: %w", err)
	}
	defer rows.Close()

	var batches []BatchOutbound
	for rows.Next() {
		var batch BatchOutbound
		if err := rows.Scan(&batch.ID, &batch.BatchID, &batch.Tag, &batch.ServerID, &batch.Protocol, &batch.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan batch outbound: %w", err)
		}
		batches = append(batches, batch)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate batch outbounds: %w", err)
	}

	return batches, nil
}

// DeleteBatchOutb​​oundsByBatchID 删除具有给定批次 ID 的所有批次出站。
func (r *TrafficRepository) DeleteBatchOutboundsByBatchID(ctx context.Context, batchID string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	batchID = strings.TrimSpace(batchID)
	if batchID == "" {
		return errors.New("batch id is required")
	}

	const stmt = `DELETE FROM batch_outbounds WHERE batch_id = ?`
	_, err := r.db.ExecContext(ctx, stmt, batchID)
	if err != nil {
		return fmt.Errorf("delete batch outbounds by batch id: %w", err)
	}

	return nil
}

// DeleteBatchOutb​​oundsByTag 删除具有给定标签的所有批次出站。
func (r *TrafficRepository) DeleteBatchOutboundsByTag(ctx context.Context, tag string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	tag = strings.TrimSpace(tag)
	if tag == "" {
		return errors.New("tag is required")
	}

	const stmt = `DELETE FROM batch_outbounds WHERE tag = ?`
	_, err := r.db.ExecContext(ctx, stmt, tag)
	if err != nil {
		return fmt.Errorf("delete batch outbounds by tag: %w", err)
	}

	return nil
}

// 封装CRUD操作

// 返回所有包模板
// aliveNodeIDs 把传入 id 列表查 nodes 表,返回"实际存在"的 id 集合。
// 出错返回 nil + err,调用方应回退到不过滤,避免单次 SQL 故障让套餐 API 整体崩。
// 用途:套餐 nodes JSON 数组里可能有指向已删节点的孤儿 id(历史 BUG / 节点删除时套餐没联动清理),
// 加载套餐时静默过滤,防止前端 tooltip / 关联节点 dialog 拿不到 name 显示成 "node-272" fallback。
func (r *TrafficRepository) aliveNodeIDs(ctx context.Context, ids []int64) (map[int64]bool, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if len(ids) == 0 {
		return map[int64]bool{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	query := fmt.Sprintf("SELECT id FROM nodes WHERE id IN (%s)", strings.Join(placeholders, ","))
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query alive node ids: %w", err)
	}
	defer rows.Close()
	alive := make(map[int64]bool, len(ids))
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan alive node id: %w", err)
		}
		alive[id] = true
	}
	return alive, nil
}

// filterAliveNodeIDs 保序过滤孤儿。query 失败时返回原 ids(不过滤,保活)。
func (r *TrafficRepository) filterAliveNodeIDs(ctx context.Context, ids []int64) []int64 {
	if len(ids) == 0 {
		return ids
	}
	alive, err := r.aliveNodeIDs(ctx, ids)
	if err != nil {
		return ids
	}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if alive[id] {
			out = append(out, id)
		}
	}
	return out
}

func (r *TrafficRepository) ListPackages(ctx context.Context) ([]Package, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const query = `
		SELECT id, name, COALESCE(description, ''), traffic_limit_bytes, cycle_days,
		       is_reset, reset_day, COALESCE(nodes, '[]'), COALESCE(speed_limit_mbps, 0), COALESCE(device_limit, 0),
		       COALESCE(auto_speed_limit_json, ''), COALESCE(short_code, ''), COALESCE(traffic_mode, 'oneway'), COALESCE(template_filename, ''), COALESCE(node_multipliers, '{}'), COALESCE(node_speed_limits, '{}'), COALESCE(node_device_limits, '{}'), created_at, updated_at
		FROM packages
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list packages: %w", err)
	}
	defer rows.Close()

	var packages []Package
	for rows.Next() {
		var pkg Package
		var isReset int
		var nodesJSON, autoSpeedJSON, nodeMultJSON, nodeSpeedJSON, nodeDeviceJSON string
		err := rows.Scan(&pkg.ID, &pkg.Name, &pkg.Description, &pkg.TrafficLimitBytes,
			&pkg.CycleDays, &isReset, &pkg.ResetDay, &nodesJSON, &pkg.SpeedLimitMbps, &pkg.DeviceLimit,
			&autoSpeedJSON, &pkg.ShortCode, &pkg.TrafficMode, &pkg.TemplateFilename, &nodeMultJSON, &nodeSpeedJSON, &nodeDeviceJSON, &pkg.CreatedAt, &pkg.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan package: %w", err)
		}
		pkg.IsReset = isReset != 0
		pkg.TrafficLimitGB = float64(pkg.TrafficLimitBytes) / (1024 * 1024 * 1024)

		pkg.Nodes = []int64{}
		if nodesJSON != "" && nodesJSON != "[]" {
			if err := json.Unmarshal([]byte(nodesJSON), &pkg.Nodes); err != nil {
				pkg.Nodes = []int64{}
			}
		}
		if autoSpeedJSON != "" {
			json.Unmarshal([]byte(autoSpeedJSON), &pkg.AutoSpeedRules)
		}
		if nodeMultJSON != "" && nodeMultJSON != "{}" {
			json.Unmarshal([]byte(nodeMultJSON), &pkg.NodeMultipliers)
		}
		if nodeSpeedJSON != "" && nodeSpeedJSON != "{}" {
			unmarshalStringKeyedMap(nodeSpeedJSON, &pkg.NodeSpeedLimits)
		}
		if nodeDeviceJSON != "" && nodeDeviceJSON != "{}" {
			unmarshalStringKeyedIntMap(nodeDeviceJSON, &pkg.NodeDeviceLimits)
		}

		packages = append(packages, pkg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate packages: %w", err)
	}

	// 静默过滤孤儿 node id — union 一次 SQL 查所有 pkg.Nodes 涉及的 id 是否在 nodes 表存在,
	// 然后保序剔除已删 id。query 失败时不过滤(返回原 pkg.Nodes)避免单次故障让 API 崩。
	idUnion := make([]int64, 0)
	seen := make(map[int64]bool)
	for _, pkg := range packages {
		for _, id := range pkg.Nodes {
			if !seen[id] {
				idUnion = append(idUnion, id)
				seen[id] = true
			}
		}
	}
	if len(idUnion) > 0 {
		if alive, err := r.aliveNodeIDs(ctx, idUnion); err == nil {
			for i := range packages {
				if len(packages[i].Nodes) == 0 {
					continue
				}
				out := make([]int64, 0, len(packages[i].Nodes))
				for _, id := range packages[i].Nodes {
					if alive[id] {
						out = append(out, id)
					}
				}
				packages[i].Nodes = out
			}
		}
	}

	return packages, nil
}

// 按 ID 返回包
func (r *TrafficRepository) GetPackage(ctx context.Context, id int64) (*Package, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const query = `
		SELECT id, name, COALESCE(description, ''), traffic_limit_bytes, cycle_days,
		       is_reset, reset_day, COALESCE(nodes, '[]'), COALESCE(speed_limit_mbps, 0), COALESCE(device_limit, 0),
		       COALESCE(auto_speed_limit_json, ''), COALESCE(short_code, ''), COALESCE(traffic_mode, 'oneway'), COALESCE(template_filename, ''), COALESCE(node_multipliers, '{}'), COALESCE(node_speed_limits, '{}'), COALESCE(node_device_limits, '{}'), created_at, updated_at
		FROM packages
		WHERE id = ?
	`

	var pkg Package
	var isReset int
	var nodesJSON, autoSpeedJSON, nodeMultJSON, nodeSpeedJSON, nodeDeviceJSON string
	err := r.db.QueryRowContext(ctx, query, id).Scan(&pkg.ID, &pkg.Name, &pkg.Description,
		&pkg.TrafficLimitBytes, &pkg.CycleDays, &isReset, &pkg.ResetDay, &nodesJSON,
		&pkg.SpeedLimitMbps, &pkg.DeviceLimit, &autoSpeedJSON, &pkg.ShortCode, &pkg.TrafficMode,
		&pkg.TemplateFilename, &nodeMultJSON, &nodeSpeedJSON, &nodeDeviceJSON, &pkg.CreatedAt, &pkg.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPackageNotFound
		}
		return nil, fmt.Errorf("get package: %w", err)
	}

	pkg.IsReset = isReset != 0
	pkg.TrafficLimitGB = float64(pkg.TrafficLimitBytes) / (1024 * 1024 * 1024)

	pkg.Nodes = []int64{}
	if nodesJSON != "" && nodesJSON != "[]" {
		if err := json.Unmarshal([]byte(nodesJSON), &pkg.Nodes); err != nil {
			pkg.Nodes = []int64{}
		}
	}
	if autoSpeedJSON != "" {
		json.Unmarshal([]byte(autoSpeedJSON), &pkg.AutoSpeedRules)
	}
	if nodeMultJSON != "" && nodeMultJSON != "{}" {
		json.Unmarshal([]byte(nodeMultJSON), &pkg.NodeMultipliers)
	}
	if nodeSpeedJSON != "" && nodeSpeedJSON != "{}" {
		unmarshalStringKeyedMap(nodeSpeedJSON, &pkg.NodeSpeedLimits)
	}
	if nodeDeviceJSON != "" && nodeDeviceJSON != "{}" {
		unmarshalStringKeyedIntMap(nodeDeviceJSON, &pkg.NodeDeviceLimits)
	}

	// 静默过滤孤儿 node id(同 ListPackages,query 失败时不过滤保活)
	pkg.Nodes = r.filterAliveNodeIDs(ctx, pkg.Nodes)

	return &pkg, nil
}

// 按名称返回包
func (r *TrafficRepository) GetPackageByName(ctx context.Context, name string) (*Package, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("package name is required")
	}

	const query = `
		SELECT id, name, COALESCE(description, ''), traffic_limit_bytes, cycle_days,
		       is_reset, reset_day, COALESCE(nodes, '[]'), COALESCE(speed_limit_mbps, 0), COALESCE(device_limit, 0),
		       COALESCE(auto_speed_limit_json, ''), COALESCE(short_code, ''), COALESCE(traffic_mode, 'oneway'), COALESCE(template_filename, ''), COALESCE(node_multipliers, '{}'), COALESCE(node_speed_limits, '{}'), COALESCE(node_device_limits, '{}'), created_at, updated_at
		FROM packages
		WHERE name = ?
	`

	var pkg Package
	var isReset int
	var nodesJSON, autoSpeedJSON, nodeMultJSON, nodeSpeedJSON, nodeDeviceJSON string
	err := r.db.QueryRowContext(ctx, query, name).Scan(&pkg.ID, &pkg.Name, &pkg.Description,
		&pkg.TrafficLimitBytes, &pkg.CycleDays, &isReset, &pkg.ResetDay, &nodesJSON,
		&pkg.SpeedLimitMbps, &pkg.DeviceLimit, &autoSpeedJSON, &pkg.ShortCode, &pkg.TrafficMode,
		&pkg.TemplateFilename, &nodeMultJSON, &nodeSpeedJSON, &nodeDeviceJSON, &pkg.CreatedAt, &pkg.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPackageNotFound
		}
		return nil, fmt.Errorf("get package by name: %w", err)
	}

	pkg.IsReset = isReset != 0
	pkg.TrafficLimitGB = float64(pkg.TrafficLimitBytes) / (1024 * 1024 * 1024)

	pkg.Nodes = []int64{}
	if nodesJSON != "" && nodesJSON != "[]" {
		if err := json.Unmarshal([]byte(nodesJSON), &pkg.Nodes); err != nil {
			pkg.Nodes = []int64{}
		}
	}
	if autoSpeedJSON != "" {
		json.Unmarshal([]byte(autoSpeedJSON), &pkg.AutoSpeedRules)
	}
	if nodeMultJSON != "" && nodeMultJSON != "{}" {
		json.Unmarshal([]byte(nodeMultJSON), &pkg.NodeMultipliers)
	}
	if nodeSpeedJSON != "" && nodeSpeedJSON != "{}" {
		unmarshalStringKeyedMap(nodeSpeedJSON, &pkg.NodeSpeedLimits)
	}
	if nodeDeviceJSON != "" && nodeDeviceJSON != "{}" {
		unmarshalStringKeyedIntMap(nodeDeviceJSON, &pkg.NodeDeviceLimits)
	}
	return &pkg, nil
}

// 创建一个新的包模板
func (r *TrafficRepository) CreatePackage(ctx context.Context, pkg Package) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}

	name := strings.TrimSpace(pkg.Name)
	if name == "" {
		return 0, errors.New("package name is required")
	}

	// 检查同名的包是否已经存在
	if existing, err := r.GetPackageByName(ctx, name); err == nil && existing != nil {
		return 0, ErrPackageExists
	}

	// 将节点序列化为 JSON
	nodesJSON, err := json.Marshal(pkg.Nodes)
	if err != nil {
		return 0, fmt.Errorf("serialize nodes: %w", err)
	}

	var autoSpeedJSON string
	if len(pkg.AutoSpeedRules) > 0 {
		b, _ := json.Marshal(pkg.AutoSpeedRules)
		autoSpeedJSON = string(b)
	}

	// node_multipliers 序列化:仅保留 nodes 列表里的 key,nil/空 map → "{}"
	nodeMultJSON := serializeNodeMultipliers(pkg.NodeMultipliers, pkg.Nodes)
	// per-node 限速 / 客户端数:跟 nodes 白名单过滤,0 值保留(显式不限速)
	nodeSpeedJSON := serializeNodeFloatMap(pkg.NodeSpeedLimits, pkg.Nodes)
	nodeDeviceJSON := serializeNodeIntMap(pkg.NodeDeviceLimits, pkg.Nodes)

	// 生成短码
	shortCode, err := generatePackageShortCode()
	if err != nil {
		return 0, err
	}

	const query = `
		INSERT INTO packages (name, description, traffic_limit_bytes, cycle_days, is_reset, reset_day, nodes, speed_limit_mbps, device_limit, auto_speed_limit_json, short_code, traffic_mode, template_filename, node_multipliers, node_speed_limits, node_device_limits)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	isReset := 0
	if pkg.IsReset {
		isReset = 1
	}

	trafficMode := pkg.TrafficMode
	if trafficMode == "" {
		trafficMode = "oneway"
	}

	result, err := r.db.ExecContext(ctx, query, name, pkg.Description, pkg.TrafficLimitBytes,
		pkg.CycleDays, isReset, pkg.ResetDay, string(nodesJSON), pkg.SpeedLimitMbps, pkg.DeviceLimit, autoSpeedJSON, shortCode, trafficMode, pkg.TemplateFilename, nodeMultJSON, nodeSpeedJSON, nodeDeviceJSON)
	if err != nil {
		return 0, fmt.Errorf("create package: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}

	r.invalidateTrafficBillingCache()
	return id, nil
}

// 更新现有包模板
func (r *TrafficRepository) UpdatePackage(ctx context.Context, pkg Package) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if pkg.ID <= 0 {
		return errors.New("package ID is required")
	}

	name := strings.TrimSpace(pkg.Name)
	if name == "" {
		return errors.New("package name is required")
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	if err := r.packageUpdateConflictsWithManagedSelections(ctx, pkg.ID, pkg.Nodes); err != nil {
		return err
	}

	// 将节点序列化为 JSON
	nodesJSON, err := json.Marshal(pkg.Nodes)
	if err != nil {
		return fmt.Errorf("serialize nodes: %w", err)
	}

	var autoSpeedJSON string
	if len(pkg.AutoSpeedRules) > 0 {
		b, _ := json.Marshal(pkg.AutoSpeedRules)
		autoSpeedJSON = string(b)
	}

	nodeMultJSON := serializeNodeMultipliers(pkg.NodeMultipliers, pkg.Nodes)
	nodeSpeedJSON := serializeNodeFloatMap(pkg.NodeSpeedLimits, pkg.Nodes)
	nodeDeviceJSON := serializeNodeIntMap(pkg.NodeDeviceLimits, pkg.Nodes)

	const query = `
		UPDATE packages
		SET name = ?, description = ?, traffic_limit_bytes = ?, cycle_days = ?,
		    is_reset = ?, reset_day = ?, nodes = ?, speed_limit_mbps = ?, device_limit = ?,
		    auto_speed_limit_json = ?, traffic_mode = ?, template_filename = ?, node_multipliers = ?,
		    node_speed_limits = ?, node_device_limits = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`

	isReset := 0
	if pkg.IsReset {
		isReset = 1
	}

	trafficMode := pkg.TrafficMode
	if trafficMode == "" {
		trafficMode = "oneway"
	}

	result, err := r.db.ExecContext(ctx, query, name, pkg.Description, pkg.TrafficLimitBytes,
		pkg.CycleDays, isReset, pkg.ResetDay, string(nodesJSON), pkg.SpeedLimitMbps, pkg.DeviceLimit, autoSpeedJSON, trafficMode, pkg.TemplateFilename, nodeMultJSON, nodeSpeedJSON, nodeDeviceJSON, pkg.ID)
	if err != nil {
		return fmt.Errorf("update package: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}

	if affected == 0 {
		return ErrPackageNotFound
	}

	r.invalidateTrafficBillingCache()
	return nil
}

// 根据 ID 删除包模板
func (r *TrafficRepository) DeletePackage(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("package ID is required")
	}

	const query = `DELETE FROM packages WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete package: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}

	if affected == 0 {
		return ErrPackageNotFound
	}

	r.invalidateTrafficBillingCache()
	return nil
}

// 将包分配给用户
func (r *TrafficRepository) AssignPackageToUser(ctx context.Context, username string, packageID int64, startDate time.Time, endDate time.Time, isReset bool, resetDay int) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	if pending, err := r.IsUserDeletionPending(ctx, username); err != nil {
		return err
	} else if pending {
		return ErrUserDeletionPending
	}

	// 验证套餐存在，并拒绝与用户自选节点重复授权同一物理入站。
	pkg, err := r.GetPackage(ctx, packageID)
	if err != nil {
		return err
	}
	if err := packageNodesConflictWithManagedSelections(ctx, r.db, username, pkg.Nodes, 0); err != nil {
		return err
	}

	var isResetInt int
	if isReset {
		isResetInt = 1
	}

	// 覆写属于当前套餐周期:续期同一套餐时保留,换套餐时清除。
	// `IS NOT` 是 SQLite 的 null-safe 比较,旧 package_id 为 NULL 时也会正确清除。
	const query = `
		UPDATE users
		SET traffic_limit_override = CASE WHEN package_id IS NOT ? THEN NULL ELSE traffic_limit_override END,
		    package_id = ?, package_start_date = ?, package_end_date = ?, is_reset = ?, reset_day = ?, updated_at = CURRENT_TIMESTAMP
		WHERE username = ?
	`

	result, err := r.db.ExecContext(ctx, query, packageID, packageID, startDate, endDate, isResetInt, resetDay, username)
	if err != nil {
		return fmt.Errorf("assign package to user: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}

	if affected == 0 {
		return ErrUserNotFound
	}

	r.invalidateTrafficBillingCache()
	return nil
}

// 删除用户的包分配
func (r *TrafficRepository) RemovePackageFromUser(ctx context.Context, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}

	const query = `
		UPDATE users
		SET package_id = NULL, package_start_date = NULL, package_end_date = NULL, is_reset = 0, reset_day = 1,
		    traffic_limit_override = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE username = ?
	`

	result, err := r.db.ExecContext(ctx, query, username)
	if err != nil {
		return fmt.Errorf("remove package from user: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}

	if affected == 0 {
		return ErrUserNotFound
	}

	r.invalidateTrafficBillingCache()
	return nil
}

// UserInboundConfig 记录用户绑定套餐时添加到入站的凭据，用于解绑时清理
type UserInboundConfig struct {
	ID             int64
	Username       string
	ServerID       int64
	InboundTag     string
	Protocol       string
	CredentialJSON string
	CreatedAt      time.Time
}

func (r *TrafficRepository) SaveUserInboundConfig(ctx context.Context, cfg UserInboundConfig) error {
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	if pending, err := r.IsUserDeletionPending(ctx, cfg.Username); err != nil {
		return err
	} else if pending {
		return ErrUserDeletionPending
	}
	// ON CONFLICT DO NOTHING:配合 UNIQUE(username,server_id,inbound_tag) 索引,并发写只保留第一条、
	// 后写静默忽略。凭据以「先写入的那条」为准,与全局锁 + 生成时立即写 DB 配合,彻底防同用户同入站重复凭据。
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_inbound_configs (username, server_id, inbound_tag, protocol, credential_json) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(username, server_id, inbound_tag) DO NOTHING`,
		cfg.Username, cfg.ServerID, cfg.InboundTag, cfg.Protocol, cfg.CredentialJSON)
	return err
}

func (r *TrafficRepository) GetUserInboundConfigs(ctx context.Context, username string) ([]UserInboundConfig, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, server_id, inbound_tag, protocol, credential_json, created_at FROM user_inbound_configs WHERE username = ?`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var configs []UserInboundConfig
	for rows.Next() {
		var c UserInboundConfig
		if err := rows.Scan(&c.ID, &c.Username, &c.ServerID, &c.InboundTag, &c.Protocol, &c.CredentialJSON, &c.CreatedAt); err != nil {
			return nil, err
		}
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

func (r *TrafficRepository) GetUserInboundConfigsByServer(ctx context.Context, serverID int64) ([]UserInboundConfig, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, server_id, inbound_tag, protocol, credential_json, created_at FROM user_inbound_configs WHERE server_id = ?`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var configs []UserInboundConfig
	for rows.Next() {
		var c UserInboundConfig
		if err := rows.Scan(&c.ID, &c.Username, &c.ServerID, &c.InboundTag, &c.Protocol, &c.CredentialJSON, &c.CreatedAt); err != nil {
			return nil, err
		}
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

func (r *TrafficRepository) DeleteUserInboundConfigs(ctx context.Context, username string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_inbound_configs WHERE username = ?`, username)
	return err
}

// ListAllUserInboundConfigs 全量返回所有用户的 inbound 凭据。
// 用于 credential_email_migrator 一次性扫描老格式 email 凭据。规模 = 用户数 × 套餐 inbound 数,
// 个人项目级别预计 < 千行,无需分页。
func (r *TrafficRepository) ListAllUserInboundConfigs(ctx context.Context) ([]UserInboundConfig, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, server_id, inbound_tag, protocol, credential_json, created_at FROM user_inbound_configs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var configs []UserInboundConfig
	for rows.Next() {
		var c UserInboundConfig
		if err := rows.Scan(&c.ID, &c.Username, &c.ServerID, &c.InboundTag, &c.Protocol, &c.CredentialJSON, &c.CreatedAt); err != nil {
			return nil, err
		}
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

// UpdateUserInboundCredentialJSONByID 按 user_inbound_configs.id 原地更新 credential_json。
// 用 id 而非 (username, server_id, inbound_tag) 三元组 — 该三元组不是 UNIQUE,
// 同 user 在同一 inbound 上可以有多条 client(EnsureAdminInboundClient 引入的导入 client、
// 历史多 client 测试等),按三元组更新会一次性把多行变成同一 credential_json。
func (r *TrafficRepository) UpdateUserInboundCredentialJSONByID(ctx context.Context, id int64, credJSON string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE user_inbound_configs SET credential_json = ? WHERE id = ?`,
		credJSON, id)
	return err
}

func (r *TrafficRepository) DeleteUserInboundConfig(ctx context.Context, username string, serverID int64, inboundTag string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_inbound_configs WHERE username = ? AND server_id = ? AND inbound_tag = ?`, username, serverID, inboundTag)
	return err
}

// EnsureAdminInboundClient 把一个 xray inbound client 凭据登记给 admin。
// 按 (username, server_id, inbound_tag, credential_json) 四元组去重 — 已存在则跳过,
// 不存在才插入。返回 wasNew=true 表示本次新插入。
//
// 用途:导入时把 server 上已存在 email 的 Xray client 绑定到系统 admin,
// 让 RelayDock 主控能识别这些 client 的归属、做流量统计 / routing 限定。
//
// 一个 inbound 上多个 client 各算一行(不强 UNIQUE);credential_json 是去重 key,
// 同 client 反复扫描不会重复入库。
func (r *TrafficRepository) EnsureAdminInboundClient(ctx context.Context, username string, serverID int64, inboundTag, protocol, credentialJSON string) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	var existsID int64
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM user_inbound_configs
		 WHERE username = ? AND server_id = ? AND inbound_tag = ? AND credential_json = ?
		 LIMIT 1`,
		username, serverID, inboundTag, credentialJSON,
	).Scan(&existsID)
	if err == nil && existsID > 0 {
		return false, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO user_inbound_configs (username, server_id, inbound_tag, protocol, credential_json) VALUES (?, ?, ?, ?, ?)`,
		username, serverID, inboundTag, protocol, credentialJSON,
	); err != nil {
		return false, err
	}
	return true, nil
}

func (r *TrafficRepository) GetUserInboundConfig(ctx context.Context, username string, serverID int64, inboundTag string) (*UserInboundConfig, error) {
	var c UserInboundConfig
	err := r.db.QueryRowContext(ctx,
		`SELECT id, username, server_id, inbound_tag, protocol, credential_json, created_at FROM user_inbound_configs WHERE username = ? AND server_id = ? AND inbound_tag = ? LIMIT 1`,
		username, serverID, inboundTag).Scan(&c.ID, &c.Username, &c.ServerID, &c.InboundTag, &c.Protocol, &c.CredentialJSON, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UserOutbound 记录用户添加的出站配置
type UserOutbound struct {
	ID           int64
	Username     string
	ServerID     int64
	InboundTag   string
	OutboundTag  string
	OutboundJSON string
	CreatedAt    time.Time
}

func (r *TrafficRepository) SaveUserOutbound(ctx context.Context, uo UserOutbound) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_outbounds (username, server_id, inbound_tag, outbound_tag, outbound_json) VALUES (?, ?, ?, ?, ?)`,
		uo.Username, uo.ServerID, uo.InboundTag, uo.OutboundTag, uo.OutboundJSON)
	return err
}

func (r *TrafficRepository) GetUserOutbounds(ctx context.Context, username string) ([]UserOutbound, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, server_id, inbound_tag, outbound_tag, outbound_json, created_at FROM user_outbounds WHERE username = ?`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var outbounds []UserOutbound
	for rows.Next() {
		var o UserOutbound
		if err := rows.Scan(&o.ID, &o.Username, &o.ServerID, &o.InboundTag, &o.OutboundTag, &o.OutboundJSON, &o.CreatedAt); err != nil {
			return nil, err
		}
		outbounds = append(outbounds, o)
	}
	return outbounds, rows.Err()
}

func (r *TrafficRepository) GetUserOutbound(ctx context.Context, username string, serverID int64, outboundTag string) (*UserOutbound, error) {
	var o UserOutbound
	err := r.db.QueryRowContext(ctx,
		`SELECT id, username, server_id, inbound_tag, outbound_tag, outbound_json, created_at FROM user_outbounds WHERE username = ? AND server_id = ? AND outbound_tag = ?`,
		username, serverID, outboundTag).Scan(&o.ID, &o.Username, &o.ServerID, &o.InboundTag, &o.OutboundTag, &o.OutboundJSON, &o.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func (r *TrafficRepository) DeleteUserOutbound(ctx context.Context, username string, serverID int64, outboundTag string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_outbounds WHERE username = ? AND server_id = ? AND outbound_tag = ?`,
		username, serverID, outboundTag)
	return err
}

func (r *TrafficRepository) DeleteUserOutboundsByUsername(ctx context.Context, username string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_outbounds WHERE username = ?`, username)
	return err
}

// DeleteUserOutboundByServerTag 按 (server_id, outbound_tag) 删 user_outbounds 行(不限 username)。
// 删节点时级联清理「以该节点为出口的出站」用 —— landing/routed 出站不在此表,删不到也无妨(best-effort)。
func (r *TrafficRepository) DeleteUserOutboundByServerTag(ctx context.Context, serverID int64, outboundTag string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_outbounds WHERE server_id = ? AND outbound_tag = ?`, serverID, outboundTag)
	return err
}

// UserSubaccount 记录一个 RelayDock 用户在某 routed 节点上的 Xray client 凭据。
// is_active=0 表示已下线(凭据保留供续费恢复),=1 表示已下发到 inbound + routing rule.user。
type UserSubaccount struct {
	ID             int64
	Username       string
	RoutedNodeID   int64
	Email          string
	CredentialJSON string
	IsActive       bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ClearNegativeTrafficUsedOffsetsAfterReset 紧急修复 — 配套 ResetTrafficTotalsForXrayBootTimeMigration。
//
// traffic_used_offset 字段记录用户手动校准的累计偏移。**负 offset** 通常是用户点了 admin UI 上的
// "重置流量"按钮 → 把当时累计的负数填进去,显示 used = 0,从那一刻起算。
// 但 reset migration 已经把 uplink/downlink 改成 last_*(等效又做了一次 reset),负 offset 叠加
// → used = (小值 + 大负数) - snap → 大负数 → clamp 0 → 服务器视图"已用 0"假象。
//
// 修复:把所有 server 的负 offset 清零,正 offset 保留(那是用户记账的累计基线,有保留价值)。
// 用 flag 防重复跑。
func (r *TrafficRepository) ClearNegativeTrafficUsedOffsetsAfterReset(ctx context.Context) (n int64, alreadyDone bool, err error) {
	const flagKey = "traffic_offset_clear_negative_v1_done"
	if v, gerr := r.GetSystemSetting(ctx, flagKey); gerr == nil && v == "1" {
		return 0, true, nil
	}
	res, eerr := r.db.ExecContext(ctx, `UPDATE remote_servers SET traffic_used_offset = 0 WHERE traffic_used_offset < 0`)
	if eerr != nil {
		return 0, false, fmt.Errorf("clear negative offsets: %w", eerr)
	}
	n, _ = res.RowsAffected()
	if serr := r.SetSystemSetting(ctx, flagKey, "1"); serr != nil {
		return n, false, fmt.Errorf("set flag: %w", serr)
	}
	return n, false, nil
}

// ResyncSnapshotsAfterReset 已废弃 — 改用 RestoreNodeTrafficFromSnapshots 真正反推恢复。
// 保留接口供 main.go 调用兼容,直接返回 alreadyDone=true 跳过。
func (r *TrafficRepository) ResyncSnapshotsAfterReset(ctx context.Context) (n int64, alreadyDone bool, err error) {
	return 0, true, nil
}

// RestoreNodeTrafficFromSnapshots 从 node_traffic_snapshots 表反推恢复 reset 前的 node_traffic.uplink/downlink。
//
// 原理:CreateDailySnapshots 每天把 node_traffic 表的 uplink/downlink(cycle delta 累加)快照到
// node_traffic_snapshots,所以历史 snapshot 完整保留了 reset 前的累计值。reset migration 把
// node_traffic.uplink/downlink 改成 last_*(当前 xray cumulative,很小),snapshot 没动。
// 取每个 (server, tag) 历史 snapshot 中 (uplink + downlink) 最大值,反写到 node_traffic —
// 等同于"恢复到 reset 前最近一次完整快照的累计"。
//
// 注意只动 uplink/downlink,不动 last_*:
//   - last_* 是 xray 当前 cumulative,collector 算 delta 用,改了会让下次 tick 算错
//   - 恢复后 collector 下次 tick:delta = current_xray - last (保持 = 当前 xray cumulative) = 真实增量
//   - 用户视角:node_traffic.uplink/downlink 恢复成 reset 前的累计 + 后续真实增量
//
// 选 max(uplink+downlink) 而非 max(date):
//   - reset 后 today snapshot 会被 reset 后的小值污染(CreateDailySnapshots 直接读 node_traffic
//     当前小值写 snapshot)
//   - cumulative 单调递增,reset 前的 snapshot 值远大于 reset 后 → max 自动选 reset 前最大值,绕开污染
//
// 用 flag `traffic_restore_v1_done` 防重复跑。
func (r *TrafficRepository) RestoreNodeTrafficFromSnapshots(ctx context.Context) (n int64, alreadyDone bool, err error) {
	const flagKey = "traffic_restore_node_v1_done"
	if v, gerr := r.GetSystemSetting(ctx, flagKey); gerr == nil && v == "1" {
		return 0, true, nil
	}
	const stmt = `
UPDATE node_traffic
SET uplink = COALESCE((SELECT s.uplink FROM node_traffic_snapshots s
                       WHERE s.server_id = node_traffic.server_id
                         AND s.tag = node_traffic.tag
                       ORDER BY (s.uplink + s.downlink) DESC LIMIT 1), uplink),
    downlink = COALESCE((SELECT s.downlink FROM node_traffic_snapshots s
                         WHERE s.server_id = node_traffic.server_id
                           AND s.tag = node_traffic.tag
                         ORDER BY (s.uplink + s.downlink) DESC LIMIT 1), downlink)
WHERE EXISTS (SELECT 1 FROM node_traffic_snapshots s
              WHERE s.server_id = node_traffic.server_id
                AND s.tag = node_traffic.tag);`
	res, eerr := r.db.ExecContext(ctx, stmt)
	if eerr != nil {
		return 0, false, fmt.Errorf("restore node_traffic from snapshots: %w", eerr)
	}
	n, _ = res.RowsAffected()
	if serr := r.SetSystemSetting(ctx, flagKey, "1"); serr != nil {
		return n, false, fmt.Errorf("set restore flag: %w", serr)
	}
	return n, false, nil
}

// RestoreUserTrafficFromSnapshots 跟 RestoreNodeTrafficFromSnapshots 同款,对 user_traffic 表
// 从 user_traffic_snapshots 反推恢复。key 维度换 (server_id, username)。
func (r *TrafficRepository) RestoreUserTrafficFromSnapshots(ctx context.Context) (n int64, alreadyDone bool, err error) {
	const flagKey = "traffic_restore_user_v1_done"
	if v, gerr := r.GetSystemSetting(ctx, flagKey); gerr == nil && v == "1" {
		return 0, true, nil
	}
	const stmt = `
UPDATE user_traffic
SET uplink = COALESCE((SELECT s.uplink FROM user_traffic_snapshots s
                       WHERE s.server_id = user_traffic.server_id
                         AND s.username = user_traffic.username
                       ORDER BY (s.uplink + s.downlink) DESC LIMIT 1), uplink),
    downlink = COALESCE((SELECT s.downlink FROM user_traffic_snapshots s
                         WHERE s.server_id = user_traffic.server_id
                           AND s.username = user_traffic.username
                         ORDER BY (s.uplink + s.downlink) DESC LIMIT 1), downlink)
WHERE EXISTS (SELECT 1 FROM user_traffic_snapshots s
              WHERE s.server_id = user_traffic.server_id
                AND s.username = user_traffic.username);`
	res, eerr := r.db.ExecContext(ctx, stmt)
	if eerr != nil {
		return 0, false, fmt.Errorf("restore user_traffic from snapshots: %w", eerr)
	}
	n, _ = res.RowsAffected()
	if serr := r.SetSystemSetting(ctx, flagKey, "1"); serr != nil {
		return n, false, fmt.Errorf("set restore flag: %w", serr)
	}
	return n, false, nil
}

// ResetTrafficTotalsForXrayBootTimeMigration 一次性数据修复 — 配套 collector 切到 xray_boot_time
// 重启检测的新算法。3 张流量表的 `total_*` 是历史"启发式重启检测"误判累加的脏数据,
// 切到新算法后这部分总要清,否则前端展示一直带历史误差。
//
// 把每行的 total_* 清零、uplink/downlink 对齐 last_*,保留 last_* 作为下一轮 delta 的 baseline。
// 用 system_settings 的 flag 防重复跑,首次启动时调用一次即可。
//
// 返回三表受影响行数 + flag 是否已经存在(已存在 → 跳过)。
func (r *TrafficRepository) ResetTrafficTotalsForXrayBootTimeMigration(ctx context.Context) (n int64, alreadyDone bool, err error) {
	const flagKey = "traffic_total_reset_v2_done"
	if v, gerr := r.GetSystemSetting(ctx, flagKey); gerr == nil && v == "1" {
		return 0, true, nil
	}
	const stmt = `
UPDATE user_email_traffic SET total_uplink = 0, total_downlink = 0, uplink = last_uplink, downlink = last_downlink;
UPDATE user_traffic       SET total_uplink = 0, total_downlink = 0, uplink = last_uplink, downlink = last_downlink;
UPDATE node_traffic       SET total_uplink = 0, total_downlink = 0, uplink = last_uplink, downlink = last_downlink;`
	// SQLite Exec 支持多语句执行(modernc.org/sqlite),三表一次写完
	res, eerr := r.db.ExecContext(ctx, stmt)
	if eerr != nil {
		return 0, false, fmt.Errorf("reset traffic totals: %w", eerr)
	}
	n, _ = res.RowsAffected()
	if serr := r.SetSystemSetting(ctx, flagKey, "1"); serr != nil {
		// 标志写失败不致命 — 下次启动会重跑,SQL 幂等,损失只是再 reset 一次最新 last(可能丢几秒 delta)。
		return n, false, fmt.Errorf("set migration flag: %w", serr)
	}
	return n, false, nil
}

// BackfillRoutedCreatorSubaccounts 给所有 routed 节点补 creator 自己的 user_subaccounts 行。
// 老代码 routed_outbound.create 时只写"占位 admin client",没给 creator 自己写子账号,
// 导致 ResolveUsernameByEmail 走 _admin__ 兜底 fallback,多 admin 系统下归属错乱。
//
// 这里幂等地一次性补:用 nodes 表里已存的 routed_admin_email + routed_admin_credential
// 直接写到 user_subaccounts(username=nodes.username,即父节点 owner = creator)。
// 老的 _admin__ 占位 email 不动 — agent inbound + routing rule 继续工作,本步只让流量归属走子账号查询命中。
//
// 返回新写入的行数。NOT EXISTS 保护:已有的不重复写。
// BackfillUserResetFromPackage 一次性把「套餐开了按月重置、但用户行 is_reset=0」的存量用户按套餐刷回。
// 历史 bug:web 绑定套餐只用请求体的 is_reset(前端恒发 false),导致套餐的按月重置对存量用户从未生效。
// 新版允许管理员显式关闭用户级重置,因此必须用持久化 flag 保证 UPDATE 终身只执行一次。
func (r *TrafficRepository) BackfillUserResetFromPackage(ctx context.Context) (n int64, alreadyDone bool, err error) {
	if r == nil || r.db == nil {
		return 0, false, errors.New("traffic repository not initialized")
	}
	const flagKey = "user_reset_from_package_v1_done"
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("begin user reset backfill: %w", err)
	}
	defer tx.Rollback()

	var flag string
	if qerr := tx.QueryRowContext(ctx, "SELECT value FROM system_settings WHERE key = ?", flagKey).Scan(&flag); qerr != nil && qerr != sql.ErrNoRows {
		return 0, false, fmt.Errorf("read user reset backfill flag: %w", qerr)
	}
	if flag == "1" {
		return 0, true, nil
	}

	res, err := tx.ExecContext(ctx, `
UPDATE users
SET is_reset = 1,
    reset_day = (SELECT p.reset_day FROM packages p WHERE p.id = users.package_id)
WHERE package_id IS NOT NULL AND package_id > 0
  AND COALESCE(is_reset, 0) = 0
  AND EXISTS (
      SELECT 1 FROM packages p
      WHERE p.id = users.package_id AND p.is_reset = 1 AND p.reset_day BETWEEN 1 AND 31
  )`)
	if err != nil {
		return 0, false, fmt.Errorf("backfill user reset from package: %w", err)
	}
	n, _ = res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO system_settings (key, value, updated_at)
VALUES (?, '1', CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`, flagKey); err != nil {
		return 0, false, fmt.Errorf("set user reset backfill flag: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit user reset backfill: %w", err)
	}
	return n, false, nil
}

func (r *TrafficRepository) BackfillRoutedCreatorSubaccounts(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	const stmt = `
INSERT INTO user_subaccounts (username, routed_node_id, email, credential_json, is_active, created_at, updated_at)
SELECT n.username, n.id, n.routed_admin_email, n.routed_admin_credential, 1,
       CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM nodes n
WHERE n.node_type = 'routed'
  AND n.username IS NOT NULL AND n.username != ''
  AND n.routed_admin_email IS NOT NULL AND n.routed_admin_email != ''
  AND n.routed_admin_credential IS NOT NULL AND n.routed_admin_credential != ''
  AND NOT EXISTS (
    SELECT 1 FROM user_subaccounts s
    WHERE s.username = n.username AND s.routed_node_id = n.id
  )`
	res, err := r.db.ExecContext(ctx, stmt)
	if err != nil {
		return 0, fmt.Errorf("backfill routed creator subaccounts: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// UpsertUserSubaccount 新建或更新一个子账号。续费时若已存在,credential 不变(由调用方决定);
// 这里只负责持久化传入字段。
func (r *TrafficRepository) UpsertUserSubaccount(ctx context.Context, sa UserSubaccount) (int64, error) {
	active := 0
	if sa.IsActive {
		active = 1
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO user_subaccounts (username, routed_node_id, email, credential_json, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(routed_node_id, username) DO UPDATE SET
			email = excluded.email,
			credential_json = excluded.credential_json,
			is_active = excluded.is_active,
			updated_at = CURRENT_TIMESTAMP
	`, sa.Username, sa.RoutedNodeID, sa.Email, sa.CredentialJSON, active)
	if err != nil {
		return 0, err
	}
	if sa.ID > 0 {
		r.invalidateTrafficBillingCache()
		return sa.ID, nil
	}
	id, _ := res.LastInsertId()
	r.invalidateTrafficBillingCache()
	return id, nil
}

// ReserveUserSubaccount durably records cleanup material before a routed
// client becomes usable. Existing active bindings are left unchanged.
func (r *TrafficRepository) ReserveUserSubaccount(ctx context.Context, sa UserSubaccount) error {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO user_subaccounts (username, routed_node_id, email, credential_json, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(routed_node_id, username) DO NOTHING
	`, sa.Username, sa.RoutedNodeID, sa.Email, sa.CredentialJSON)
	if err == nil {
		if affected, _ := res.RowsAffected(); affected > 0 {
			r.invalidateTrafficBillingCache()
		}
	}
	return err
}

func (r *TrafficRepository) GetUserSubaccount(ctx context.Context, routedNodeID int64, username string) (*UserSubaccount, error) {
	var sa UserSubaccount
	var active int
	err := r.db.QueryRowContext(ctx, `
		SELECT id, username, routed_node_id, email, credential_json, is_active, created_at, updated_at
		FROM user_subaccounts WHERE routed_node_id = ? AND username = ?
	`, routedNodeID, username).Scan(&sa.ID, &sa.Username, &sa.RoutedNodeID, &sa.Email, &sa.CredentialJSON, &active, &sa.CreatedAt, &sa.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	sa.IsActive = active == 1
	return &sa, nil
}

func (r *TrafficRepository) ListUserSubaccounts(ctx context.Context, username string) ([]UserSubaccount, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, routed_node_id, email, credential_json, is_active, created_at, updated_at
		FROM user_subaccounts WHERE username = ? ORDER BY routed_node_id
	`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserSubaccount
	for rows.Next() {
		var sa UserSubaccount
		var active int
		if err := rows.Scan(&sa.ID, &sa.Username, &sa.RoutedNodeID, &sa.Email, &sa.CredentialJSON, &active, &sa.CreatedAt, &sa.UpdatedAt); err != nil {
			return nil, err
		}
		sa.IsActive = active == 1
		out = append(out, sa)
	}
	return out, rows.Err()
}

// SubaccountRef 是流量归因用的精简子账号行(email → routed 节点 + 归属 user)。
type SubaccountRef struct {
	Email        string
	Username     string
	RoutedNodeID int64
	IsActive     bool
}

// ListAllSubaccounts 返回全部 user_subaccounts(**忽略 is_active**),供流量归因用。
// 归因必须涵盖被停用的子账号 email——历史流量仍属该 routed 节点,绝不能落到父入站(否则双算)。
func (r *TrafficRepository) ListAllSubaccounts(ctx context.Context) ([]SubaccountRef, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT email, username, routed_node_id, is_active FROM user_subaccounts`)
	if err != nil {
		return nil, fmt.Errorf("list all subaccounts: %w", err)
	}
	defer rows.Close()
	var out []SubaccountRef
	for rows.Next() {
		var s SubaccountRef
		var active int
		if err := rows.Scan(&s.Email, &s.Username, &s.RoutedNodeID, &active); err != nil {
			return nil, err
		}
		s.IsActive = active == 1
		if s.Email != "" {
			out = append(out, s)
		}
	}
	return out, rows.Err()
}

// RoutedAdminRef 是 routed 节点的 admin 占位 email → 节点 + 创建者。
type RoutedAdminRef struct {
	Email    string
	NodeID   int64
	Username string
}

// ListRoutedAdminEmailNodes 返回所有 routed 节点的 (routed_admin_email, id, username)。
// admin 占位 client 直连 routed 出站的流量(email 前缀 _admin__)应归该 routed 节点,而非父入站。
func (r *TrafficRepository) ListRoutedAdminEmailNodes(ctx context.Context) ([]RoutedAdminRef, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT COALESCE(routed_admin_email,''), id, username FROM nodes WHERE node_type='routed' AND COALESCE(routed_admin_email,'') != ''`)
	if err != nil {
		return nil, fmt.Errorf("list routed admin emails: %w", err)
	}
	defer rows.Close()
	var out []RoutedAdminRef
	for rows.Next() {
		var a RoutedAdminRef
		if err := rows.Scan(&a.Email, &a.NodeID, &a.Username); err != nil {
			return nil, err
		}
		if a.Email != "" {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

func (r *TrafficRepository) ListSubaccountsByRoutedNode(ctx context.Context, routedNodeID int64) ([]UserSubaccount, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, routed_node_id, email, credential_json, is_active, created_at, updated_at
		FROM user_subaccounts WHERE routed_node_id = ? ORDER BY username
	`, routedNodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserSubaccount
	for rows.Next() {
		var sa UserSubaccount
		var active int
		if err := rows.Scan(&sa.ID, &sa.Username, &sa.RoutedNodeID, &sa.Email, &sa.CredentialJSON, &active, &sa.CreatedAt, &sa.UpdatedAt); err != nil {
			return nil, err
		}
		sa.IsActive = active == 1
		out = append(out, sa)
	}
	return out, rows.Err()
}

// ListActiveSubaccountsByServerName 用于 limiter 下发:列出某 server 上所有 active 子账号
// 以及其挂的 inbound_tag(继承自父物理节点)。需要 JOIN nodes 表拿 inbound 信息。
type ActiveSubaccountForLimiter struct {
	Username   string
	Email      string
	InboundTag string
}

func (r *TrafficRepository) ListActiveSubaccountsByServerName(ctx context.Context, serverName string) ([]ActiveSubaccountForLimiter, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT sa.username, sa.email, COALESCE(n.inbound_tag, '')
		FROM user_subaccounts sa
		INNER JOIN nodes n ON sa.routed_node_id = n.id
		WHERE sa.is_active = 1 AND n.original_server = ? AND n.node_type = 'routed'
	`, serverName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActiveSubaccountForLimiter
	for rows.Next() {
		var a ActiveSubaccountForLimiter
		if err := rows.Scan(&a.Username, &a.Email, &a.InboundTag); err != nil {
			return nil, err
		}
		if a.InboundTag == "" {
			continue
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListServerIDsForUserSubaccounts 返回该用户所有 active routed 子账号所在的 remote_server id。
// 限速下发收集服务器时,主账号走 user_inbound_configs(物理),子账号在 user_subaccounts ——
// 只有 routed 子账号、没有物理 inbound 的用户,光查 inbound_configs 会漏掉这些 server。
func (r *TrafficRepository) ListServerIDsForUserSubaccounts(ctx context.Context, username string) ([]int64, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT rs.id
		FROM user_subaccounts sa
		INNER JOIN nodes n ON sa.routed_node_id = n.id
		INNER JOIN remote_servers rs ON rs.name = n.original_server
		WHERE sa.is_active = 1 AND sa.username = ? AND n.node_type = 'routed'
	`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// InboundNodeRef:一个 (inbound_tag → node) 映射条目,供限速下发反查 per-node 覆盖用。
// ParentID = 0 表示物理节点;> 0 表示 routed 子节点,继承父物理节点的 per-node 覆盖。
type InboundNodeRef struct {
	InboundTag string
	NodeID     int64
	ParentID   int64
	NodeType   string // "physical" 或 "routed"
}

// ListInboundNodeRefsForServer 查该 server 上所有有 inbound_tag 的节点,供 limiter 下发反查用。
// 同一 inbound_tag 上可能有多条(physical + routed),调用方按 NodeType 区分:
// 主账号(走原 inbound)用 physical 行;routed 子账号(走 routed inbound)用 routed 行。
func (r *TrafficRepository) ListInboundNodeRefsForServer(ctx context.Context, serverName string) ([]InboundNodeRef, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT COALESCE(inbound_tag, ''), id, COALESCE(parent_node_id, 0), COALESCE(node_type, 'physical')
		 FROM nodes
		 WHERE original_server = ? AND inbound_tag IS NOT NULL AND inbound_tag != ''`,
		serverName)
	if err != nil {
		return nil, fmt.Errorf("list inbound node refs: %w", err)
	}
	defer rows.Close()
	var out []InboundNodeRef
	for rows.Next() {
		var ref InboundNodeRef
		if err := rows.Scan(&ref.InboundTag, &ref.NodeID, &ref.ParentID, &ref.NodeType); err != nil {
			continue
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// SetSubaccountActive 切换 is_active(下线/恢复),不动 credential。
func (r *TrafficRepository) SetSubaccountActive(ctx context.Context, id int64, active bool) error {
	v := 0
	if active {
		v = 1
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE user_subaccounts SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, v, id)
	return err
}

func (r *TrafficRepository) DeleteUserSubaccount(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM user_subaccounts WHERE id = ?`, id)
	if err == nil {
		if affected, _ := res.RowsAffected(); affected > 0 {
			r.invalidateTrafficBillingCache()
		}
	}
	return err
}

// ListSubaccountEmailToUsername 一次性拉所有子账号 email → 父用户名的映射。
// 适合每日通知 / 报表这种"一次跑、需要把流量按主账号聚合"的场景,避免对每条流量逐行查 DB。
func (r *TrafficRepository) ListSubaccountEmailToUsername(ctx context.Context) (map[string]string, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT email, username FROM user_subaccounts`)
	if err != nil {
		return nil, fmt.Errorf("list subaccount mappings: %w", err)
	}
	defer rows.Close()
	m := make(map[string]string)
	for rows.Next() {
		var email, username string
		if err := rows.Scan(&email, &username); err != nil {
			return nil, fmt.Errorf("scan subaccount mapping: %w", err)
		}
		if email != "" && username != "" {
			m[email] = username
		}
	}
	return m, nil
}

// ResolveUsernameByEmail 把 Xray 上报的 stats.User key (email) 反查到 RelayDock 用户名。
// 优先级:
//  1. user_subaccounts.email → username (子账号路径,包括 admin 把自己作为 routed 子账号的情况)
//  2. _admin__ 占位 email 没命中 user_subaccounts → 反查 nodes.routed_admin_email 找到对应 routed 节点,
//     归属给系统 admin owner(GetSystemNodeOwner)— admin 自己用占位 client 直连的流量归 admin
//  3. users.email 反查(主账号 inbound 凭据有时把 client.email 设成主账号 email)
//  4. 否则按 "<username>__<tag>" 取首段 / 原值兜底
//
// 历史 BUG:之前 _admin__ 前缀直接 return "",所有 admin 自己用 routed 节点 admin 占位 uuid
// 连上线的流量全部丢失 — admin 在节点视图看不到自己用 routed 节点的流量。
// 修复:先查 user_subaccounts(覆盖被 scan_result auto-claim 写过的情况),没命中再用
// routed_admin_email 反查 + admin owner fallback。
//
// 该函数应在流量采集热路径上调用,后续可加内存 cache 优化。
func (r *TrafficRepository) ResolveUsernameByEmail(ctx context.Context, email string) string {
	if email == "" {
		return ""
	}
	var username string
	err := r.db.QueryRowContext(ctx,
		`SELECT username FROM user_subaccounts WHERE email = ? LIMIT 1`, email).Scan(&username)
	if err == nil && username != "" {
		return username
	}
	// _admin__ 占位:架构上多个 admin 共享同一个 client(用 routed_admin_email 标识),
	// 流量在 xray 上报时合并为一行,master 端无法区分是 admin A 还是 admin B 产生的。
	// 这里反查 nodes.username 取**创建者** username 作为归属 — 单 admin 系统准确,
	// 多 admin 系统会偏向 creator(承认不完美,彻底解决见占位架构改造路线)。
	if strings.HasPrefix(email, "_admin__") {
		var creator string
		eerr := r.db.QueryRowContext(ctx,
			`SELECT username FROM nodes WHERE routed_admin_email = ? LIMIT 1`, email).Scan(&creator)
		if eerr == nil && creator != "" {
			return creator
		}
		// 没有任何 routed node 持有这个占位 email → 真孤儿,丢弃避免归属混乱
		return ""
	}
	// 用户直接 inbound 凭据有时把 client.email 设成主账号 email(如 share@2ha.me) —
	// 既不符合 `<username>__<tag>` 新格式,也不在 user_subaccounts,
	// fallback `return email` 会把流量记到 username=email 的孤行,管理员页按 username 查不到。
	// 这里反查 users.email → username,把这类流量归回主账号。
	err = r.db.QueryRowContext(ctx,
		`SELECT username FROM users WHERE email = ? LIMIT 1`, email).Scan(&username)
	if err == nil && username != "" {
		return username
	}
	// 新格式 inbound 凭据 email = `<username>__<inbound_tag>`(generateCredential 生成);
	// routed 子账户老格式 `<username>__<id>__<label>` 没命中 user_subaccounts 时也走这里。
	// 用 instr(精确子串,无 SQL LIKE 的 `_` 通配符坑)按最长真实用户名匹配 —— 避免用户名含 `__` 或以 `_` 结尾时
	// 首个 `__` 拆错(如 `foo__bar__tag` 应归 `foo__bar` 而非 `foo`)。
	var matched string
	if e := r.db.QueryRowContext(ctx,
		`SELECT username FROM users WHERE instr(?, username || '__') = 1 ORDER BY length(username) DESC LIMIT 1`,
		email).Scan(&matched); e == nil && matched != "" {
		return matched
	}
	if i := strings.Index(email, "__"); i > 0 {
		return email[:i]
	}
	return email
}

const trafficBillingCacheTTL = 5 * time.Second

// UserTrafficBilling is the collection-time attribution for one Xray client
// counter. Multiplier already includes both the package traffic mode and the
// selected node multiplier, so callers must not multiply it again later.
type UserTrafficBilling struct {
	Username   string
	Multiplier float64
}

type trafficBillingUser struct {
	packageID int64
}

type trafficBillingNode struct {
	username string
	nodeID   int64
}

type trafficBillingPackage struct {
	trafficMode     string
	nodeMultipliers map[int64]float64
}

type trafficBillingSnapshot struct {
	serverName    string
	subaccounts   map[string]trafficBillingNode
	adminClients  map[string]trafficBillingNode
	users         map[string]trafficBillingUser
	usersByEmail  map[string]string
	usernames     []string
	packages      map[int64]trafficBillingPackage
	physicalByTag map[string]int64
}

type trafficBillingCacheEntry struct {
	expiresAt time.Time
	snapshot  *trafficBillingSnapshot
}

func (r *TrafficRepository) invalidateTrafficBillingCache() {
	if r == nil {
		return
	}
	r.billingCacheMu.Lock()
	r.billingCache = nil
	r.billingCacheMu.Unlock()
}

func normalizeTrafficBillingMultiplier(multiplier float64) float64 {
	if multiplier <= 0 || math.IsNaN(multiplier) || math.IsInf(multiplier, 0) {
		return 1
	}
	return multiplier
}

func billTrafficBytes(rawBytes int64, multiplier float64) int64 {
	billed, _ := accrueBillableTraffic(rawBytes, multiplier, 0)
	return billed
}

// accrueBillableTraffic keeps the fractional part between collector ticks.
// Rounding every small delta independently can materially overcharge packages
// with multipliers below 1 (for example, 100 one-byte deltas at 0.5x used to
// become 100 bytes instead of 50).
func accrueBillableTraffic(rawBytes int64, multiplier, carry float64) (int64, float64) {
	if math.IsNaN(carry) || math.IsInf(carry, 0) || carry < 0 || carry >= 1 {
		carry = 0
	}
	if rawBytes <= 0 {
		return 0, carry
	}
	weighted := float64(rawBytes)*normalizeTrafficBillingMultiplier(multiplier) + carry
	if math.IsInf(weighted, 1) || weighted >= float64(math.MaxInt64) {
		return math.MaxInt64, 0
	}
	whole := math.Floor(weighted)
	return int64(whole), weighted - whole
}

func saturatingTrafficAdd(left, right int64) int64 {
	left = max(left, 0)
	right = max(right, 0)
	if math.MaxInt64-left < right {
		return math.MaxInt64
	}
	return left + right
}

func (s *trafficBillingSnapshot) resolve(email string) UserTrafficBilling {
	if email == "" {
		return UserTrafficBilling{}
	}

	var (
		username string
		nodeID   int64
	)
	if match, ok := s.subaccounts[email]; ok {
		username, nodeID = match.username, match.nodeID
	} else if match, ok := s.adminClients[email]; ok {
		username, nodeID = match.username, match.nodeID
	} else if strings.HasPrefix(email, "_admin__") {
		return UserTrafficBilling{}
	} else if matched, ok := s.usersByEmail[email]; ok {
		username = matched
	} else {
		for _, candidate := range s.usernames {
			if strings.HasPrefix(email, candidate+"__") {
				username = candidate
				if tag := strings.TrimPrefix(email, candidate+"__"); tag != "" {
					nodeID = s.physicalByTag[tag]
				}
				break
			}
		}
		if username == "" {
			if _, ok := s.users[email]; ok {
				username = email
			} else if i := strings.Index(email, "__"); i > 0 {
				username = email[:i]
			}
		}
	}
	if username == "" {
		return UserTrafficBilling{}
	}

	multiplier := 1.0
	if user, ok := s.users[username]; ok && user.packageID > 0 {
		if pkg, ok := s.packages[user.packageID]; ok {
			if pkg.trafficMode == "twoway" {
				multiplier *= 2
			}
			if configured, ok := pkg.nodeMultipliers[nodeID]; nodeID > 0 && ok && configured > 0 {
				multiplier *= configured
			}
		}
	}
	return UserTrafficBilling{Username: username, Multiplier: normalizeTrafficBillingMultiplier(multiplier)}
}

func (r *TrafficRepository) buildTrafficBillingSnapshot(ctx context.Context, serverID int64) (*trafficBillingSnapshot, error) {
	snapshot := &trafficBillingSnapshot{
		subaccounts:   make(map[string]trafficBillingNode),
		adminClients:  make(map[string]trafficBillingNode),
		users:         make(map[string]trafficBillingUser),
		usersByEmail:  make(map[string]string),
		packages:      make(map[int64]trafficBillingPackage),
		physicalByTag: make(map[string]int64),
	}

	if err := r.db.QueryRowContext(ctx, `SELECT name FROM remote_servers WHERE id = ?`, serverID).Scan(&snapshot.serverName); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("resolve billing server: %w", err)
		}
		// Local Xray collection uses xray_servers IDs. Keep that path working.
		if err := r.db.QueryRowContext(ctx, `SELECT name FROM xray_servers WHERE id = ?`, serverID).Scan(&snapshot.serverName); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("resolve local billing server: %w", err)
		}
	}

	rows, err := r.db.QueryContext(ctx, `SELECT username, COALESCE(email, ''), COALESCE(package_id, 0) FROM users`)
	if err != nil {
		return nil, fmt.Errorf("list billing users: %w", err)
	}
	for rows.Next() {
		var username, email string
		var packageID int64
		if err := rows.Scan(&username, &email, &packageID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan billing user: %w", err)
		}
		snapshot.users[username] = trafficBillingUser{packageID: packageID}
		snapshot.usernames = append(snapshot.usernames, username)
		if email != "" {
			snapshot.usersByEmail[email] = username
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate billing users: %w", err)
	}
	rows.Close()
	sort.Slice(snapshot.usernames, func(i, j int) bool { return len(snapshot.usernames[i]) > len(snapshot.usernames[j]) })

	rows, err = r.db.QueryContext(ctx, `SELECT id, COALESCE(traffic_mode, 'oneway'), COALESCE(node_multipliers, '{}') FROM packages`)
	if err != nil {
		return nil, fmt.Errorf("list billing packages: %w", err)
	}
	for rows.Next() {
		var id int64
		var mode, multipliersJSON string
		if err := rows.Scan(&id, &mode, &multipliersJSON); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan billing package: %w", err)
		}
		pkg := trafficBillingPackage{trafficMode: mode, nodeMultipliers: map[int64]float64{}}
		_ = json.Unmarshal([]byte(multipliersJSON), &pkg.nodeMultipliers)
		snapshot.packages[id] = pkg
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate billing packages: %w", err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, `SELECT email, username, routed_node_id FROM user_subaccounts`)
	if err != nil {
		return nil, fmt.Errorf("list billing subaccounts: %w", err)
	}
	for rows.Next() {
		var email, username string
		var nodeID int64
		if err := rows.Scan(&email, &username, &nodeID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan billing subaccount: %w", err)
		}
		snapshot.subaccounts[email] = trafficBillingNode{username: username, nodeID: nodeID}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate billing subaccounts: %w", err)
	}
	rows.Close()

	rows, err = r.db.QueryContext(ctx, `
		SELECT id, username, COALESCE(node_type, 'physical'), COALESCE(parent_node_id, 0),
		       COALESCE(original_server, ''), COALESCE(inbound_tag, ''), COALESCE(routed_admin_email, '')
		FROM nodes`)
	if err != nil {
		return nil, fmt.Errorf("list billing nodes: %w", err)
	}
	for rows.Next() {
		var id, parentID int64
		var username, nodeType, serverName, inboundTag, adminEmail string
		if err := rows.Scan(&id, &username, &nodeType, &parentID, &serverName, &inboundTag, &adminEmail); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan billing node: %w", err)
		}
		if adminEmail != "" {
			if _, claimed := snapshot.subaccounts[adminEmail]; !claimed {
				snapshot.adminClients[adminEmail] = trafficBillingNode{username: username, nodeID: id}
			}
		}
		if nodeType != "routed" && parentID == 0 && serverName == snapshot.serverName && inboundTag != "" {
			snapshot.physicalByTag[inboundTag] = id
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate billing nodes: %w", err)
	}
	rows.Close()
	return snapshot, nil
}

// ResolveUserTrafficBilling resolves a whole collector batch from one cached
// snapshot, eliminating the previous per-email SQL queries. Cache entries are
// deliberately short lived so package/node changes affect new traffic quickly.
func (r *TrafficRepository) ResolveUserTrafficBilling(ctx context.Context, serverID int64, emails []string) (map[string]UserTrafficBilling, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return nil, errors.New("server id is required")
	}

	now := time.Now()
	r.billingCacheMu.Lock()
	if r.billingCache == nil {
		r.billingCache = make(map[int64]trafficBillingCacheEntry)
	}
	entry, ok := r.billingCache[serverID]
	if !ok || entry.snapshot == nil || !now.Before(entry.expiresAt) {
		snapshot, err := r.buildTrafficBillingSnapshot(ctx, serverID)
		if err != nil {
			r.billingCacheMu.Unlock()
			return nil, err
		}
		entry = trafficBillingCacheEntry{snapshot: snapshot, expiresAt: now.Add(trafficBillingCacheTTL)}
		r.billingCache[serverID] = entry
	}
	r.billingCacheMu.Unlock()

	resolved := make(map[string]UserTrafficBilling, len(emails))
	for _, email := range emails {
		resolved[email] = entry.snapshot.resolve(email)
	}
	return resolved, nil
}

// initializeLegacyBillableTraffic freezes pre-migration cycle usage once using
// the rules active during the upgrade. It is idempotent per row and does not
// alter raw counters, snapshots, or cycle baselines.
func (r *TrafficRepository) initializeLegacyBillableTraffic(ctx context.Context) error {
	type legacyRow struct {
		id       int64
		serverID int64
		email    string
		rawBytes int64
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, server_id, email,
		       MAX(uplink - cycle_base_uplink, 0) + MAX(downlink - cycle_base_downlink, 0)
		FROM user_email_traffic WHERE billable_initialized = 0`)
	if err != nil {
		return fmt.Errorf("list legacy billable traffic: %w", err)
	}
	var legacy []legacyRow
	byServer := make(map[int64][]string)
	for rows.Next() {
		var row legacyRow
		if err := rows.Scan(&row.id, &row.serverID, &row.email, &row.rawBytes); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy billable traffic: %w", err)
		}
		legacy = append(legacy, row)
		byServer[row.serverID] = append(byServer[row.serverID], row.email)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate legacy billable traffic: %w", err)
	}
	rows.Close()
	if len(legacy) == 0 {
		return nil
	}

	resolvedByServer := make(map[int64]map[string]UserTrafficBilling, len(byServer))
	for serverID, emails := range byServer {
		resolved, err := r.ResolveUserTrafficBilling(ctx, serverID, emails)
		if err != nil {
			return err
		}
		resolvedByServer[serverID] = resolved
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin legacy billable migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, row := range legacy {
		billing := resolvedByServer[row.serverID][row.email]
		billedBytes, billedFraction := accrueBillableTraffic(row.rawBytes, billing.Multiplier, 0)
		if _, err := tx.ExecContext(ctx, `UPDATE user_email_traffic
			SET billable_bytes = ?, billable_fraction = ?, billable_initialized = 1,
			    billable_username = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ? AND billable_initialized = 0`,
			billedBytes, billedFraction, billing.Username, row.id); err != nil {
			return fmt.Errorf("initialize legacy billable row %d: %w", row.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy billable migration: %w", err)
	}
	return nil
}

// ResolveNodeNameByEmail 按 xray client email 反查节点名(连接数超限通知"哪个节点"用)。
// 子账号 email → 其 routed 节点;物理 email(<user>__<inbound_tag>)→ 该 server 上匹配 inbound_tag 的物理节点。
// 返回 "" = 未解析到(通知里省略节点)。
func (r *TrafficRepository) ResolveNodeNameByEmail(ctx context.Context, serverName, email string) string {
	if r == nil || r.db == nil || email == "" {
		return ""
	}
	var name string
	// 1. 子账号(routed 节点)
	if err := r.db.QueryRowContext(ctx,
		`SELECT n.node_name FROM user_subaccounts sa JOIN nodes n ON sa.routed_node_id = n.id WHERE sa.email = ? LIMIT 1`,
		email).Scan(&name); err == nil && name != "" {
		return name
	}
	// 2. 物理:email = <user>__<inbound_tag>。用 instr 按最长真实用户名定位分隔点,避免用户名含 `__` 时拆错 tag。
	if serverName != "" {
		var uname string
		_ = r.db.QueryRowContext(ctx,
			`SELECT username FROM users WHERE instr(?, username || '__') = 1 ORDER BY length(username) DESC LIMIT 1`,
			email).Scan(&uname)
		tag := ""
		if uname != "" && len(email) > len(uname)+2 {
			tag = email[len(uname)+2:]
		} else if i := strings.Index(email, "__"); i > 0 {
			tag = email[i+2:]
		}
		if tag != "" {
			if err := r.db.QueryRowContext(ctx,
				`SELECT node_name FROM nodes WHERE original_server = ? AND inbound_tag = ? AND COALESCE(node_type,'physical') != 'routed' LIMIT 1`,
				serverName, tag).Scan(&name); err == nil && name != "" {
				return name
			}
		}
	}
	return ""
}

func (r *TrafficRepository) ListUsersWithPackage(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT username, password_hash, COALESCE(email, ''), COALESCE(nickname, ''), COALESCE(avatar_url, ''), COALESCE(role, ''), is_active, COALESCE(remark, ''), COALESCE(package_id, 0), COALESCE(is_reset, 0), COALESCE(reset_day, 1), last_reset_at, package_end_date, speed_limit_override, device_limit_override, traffic_limit_override, COALESCE(node_speed_limit_overrides, '{}'), COALESCE(node_device_limit_overrides, '{}'), created_at, updated_at FROM users WHERE package_id IS NOT NULL AND package_id > 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var active, isReset int
		var lastResetAt, endDate sql.NullTime
		var speedOverride sql.NullFloat64
		var deviceOverride sql.NullInt64
		var trafficOverride sql.NullInt64
		var nodeSpeedJSON, nodeDeviceJSON string
		if err := rows.Scan(&u.Username, &u.PasswordHash, &u.Email, &u.Nickname, &u.AvatarURL, &u.Role, &active, &u.Remark, &u.PackageID, &isReset, &u.ResetDay, &lastResetAt, &endDate, &speedOverride, &deviceOverride, &trafficOverride, &nodeSpeedJSON, &nodeDeviceJSON, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.IsActive = active != 0
		u.IsReset = isReset != 0
		if lastResetAt.Valid {
			u.LastResetAt = &lastResetAt.Time
		}
		if endDate.Valid {
			u.PackageEndDate = &endDate.Time
		}
		if speedOverride.Valid {
			v := speedOverride.Float64
			u.SpeedLimitOverride = &v
		}
		if deviceOverride.Valid {
			v := int(deviceOverride.Int64)
			u.DeviceLimitOverride = &v
		}
		if trafficOverride.Valid {
			v := trafficOverride.Int64
			u.TrafficLimitOverride = &v
		}
		if nodeSpeedJSON != "" && nodeSpeedJSON != "{}" {
			unmarshalStringKeyedMap(nodeSpeedJSON, &u.NodeSpeedLimitOverrides)
		}
		if nodeDeviceJSON != "" && nodeDeviceJSON != "{}" {
			unmarshalStringKeyedIntMap(nodeDeviceJSON, &u.NodeDeviceLimitOverrides)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *TrafficRepository) GetUserTotalTraffic(ctx context.Context, username string) (int64, error) {
	var total int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(uplink + downlink), 0) FROM user_traffic WHERE username = ?`, username).Scan(&total)
	return total, err
}

// GetUserWeightedTraffic 按 pkg.NodeMultipliers 加权汇总该用户的流量。
// 数据源:user_email_traffic(每行 email 维度),email 形态:
//   - <username>__<inbound_tag>:主账号在某 inbound 的流量,反查 nodes(server_name+inbound_tag)→ 节点 → 倍率
//   - 子账号:命中 user_subaccounts → routed_node_id → routed 节点 → 父节点 → 父倍率
//   - 其它(主账号无 __ 分隔等)→ 兜底按 1.0 计算
//
// 套餐 nil 或 NodeMultipliers 空 → 等价于 GetUserTotalTraffic 在 email 维度的求和(全部按 1)。
// escapeLikePattern 转义 SQL LIKE 元字符(`\` `_` `%`),配合 `ESCAPE '\'` 做「字面」匹配,
// 避免用户名里的 `_` 被当成 SQL 单字符通配符导致跨用户误匹配。
func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	return s
}

func (r *TrafficRepository) GetUserWeightedTraffic(ctx context.Context, username string, pkg *Package) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return 0, errors.New("username is required")
	}

	// 套餐空 / 无倍率配置 → 直接用 user_traffic(按 username 聚合,等价于全 1)
	if pkg == nil || len(pkg.NodeMultipliers) == 0 {
		return r.GetUserTotalTraffic(ctx, username)
	}

	// 预加载:server_id → server.name(反查主账号节点用)
	serverNames := make(map[int64]string)
	srvRows, err := r.db.QueryContext(ctx, `SELECT id, name FROM remote_servers`)
	if err != nil {
		return 0, fmt.Errorf("list servers: %w", err)
	}
	for srvRows.Next() {
		var id int64
		var name string
		if err := srvRows.Scan(&id, &name); err == nil {
			serverNames[id] = name
		}
	}
	srvRows.Close()

	// 预加载:user_subaccounts(email → routed_node_id);仅本用户的
	subaccNodeID := make(map[string]int64)
	saRows, err := r.db.QueryContext(ctx,
		`SELECT email, routed_node_id FROM user_subaccounts WHERE username = ?`, username)
	if err != nil {
		return 0, fmt.Errorf("list subaccounts: %w", err)
	}
	for saRows.Next() {
		var email string
		var nid int64
		if err := saRows.Scan(&email, &nid); err == nil {
			subaccNodeID[email] = nid
		}
	}
	saRows.Close()

	// 预加载:主账号 <username>__<inbound_tag> 流量反查节点用。key=server_name+"\x00"+inbound_tag。
	// **只映射物理节点(parent_node_id IS NULL)**:routed 子节点继承了父节点的 original_server+inbound_tag,
	// 若一并映射,同一 (server,inbound) 会被 routed 子节点覆盖(后写覆盖前写)→ 主账号(连的是物理入站)
	// 的流量会误用某个 routed 子节点的倍率。主账号流量本就属于物理节点,故只认物理节点。
	nodeByServerTag := make(map[string]int64)
	nRows, err := r.db.QueryContext(ctx,
		`SELECT id, parent_node_id, COALESCE(original_server,''), COALESCE(inbound_tag,'') FROM nodes`)
	if err != nil {
		return 0, fmt.Errorf("list nodes: %w", err)
	}
	for nRows.Next() {
		var id int64
		var parentID *int64
		var srv, tag string
		if err := nRows.Scan(&id, &parentID, &srv, &tag); err != nil {
			continue
		}
		if parentID == nil && srv != "" && tag != "" {
			nodeByServerTag[srv+"\x00"+tag] = id
		}
	}
	nRows.Close()

	// 扫该用户所有 email 流量行。只取本周期增量:月度重置把当时的累计值抬进了 cycle_base_*,
	// 不减掉基线的话,重置后仍会拿历史累计去判超限(见 ResetUserTrafficCycle)。
	prefix := username + "__"
	// 转义 `_`(SQL 单字符通配符),用「字面」前缀匹配,防止用户名含 `_` 时跨用户串味(如 alice__% 误吞 alice_2 的行)。
	// 两种子账号 email 形态都显式覆盖:`<user>__...`(物理 + routed)与 `<user>-<tag>`(dash 老格式);
	// 再并上 user_subaccounts 精确集兜底。三者都对 `_` 转义,故不会像旧 `_` 通配符那样误吞别的用户。
	esc := escapeLikePattern(username)
	rows, err := r.db.QueryContext(ctx,
		`SELECT server_id, email, uplink - cycle_base_uplink, downlink - cycle_base_downlink
		 FROM user_email_traffic
		 WHERE email = ?
		    OR email LIKE ? ESCAPE '\'
		    OR email LIKE ? ESCAPE '\'
		    OR email IN (SELECT email FROM user_subaccounts WHERE username = ?)`,
		username, esc+`\_\_%`, esc+`-%`, username)
	if err != nil {
		return 0, fmt.Errorf("query user_email_traffic: %w", err)
	}
	defer rows.Close()

	var weighted float64
	for rows.Next() {
		var serverID, uplink, downlink int64
		var email string
		if err := rows.Scan(&serverID, &email, &uplink, &downlink); err != nil {
			continue
		}
		bytes := max(uplink, 0) + max(downlink, 0)

		// 子账号路径(routed):每个 routed 节点用它自己的倍率(独立,不再回退父/根节点)。
		if nid, ok := subaccNodeID[email]; ok {
			weighted += float64(bytes) * pkg.MultiplierForNode(nid)
			continue
		}

		// 主账号 inbound 路径:<username>__<inbound_tag> → 物理节点(nodeByServerTag 只含物理节点)。
		if strings.HasPrefix(email, prefix) {
			tag := email[len(prefix):]
			srvName := serverNames[serverID]
			if srvName != "" {
				if nid, ok := nodeByServerTag[srvName+"\x00"+tag]; ok {
					weighted += float64(bytes) * pkg.MultiplierForNode(nid)
					continue
				}
			}
		}

		// 兜底:无法识别节点 → 按 1 算(包括 email == username 的历史孤行)
		weighted += float64(bytes)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("scan user_email_traffic: %w", err)
	}
	return int64(weighted), nil
}

// ListUserBillableTraffic returns the current-cycle counters already weighted
// at collection time. It resolves all rows per server in batches and only uses
// the legacy user_traffic table when no email-level rows exist for a user.
func (r *TrafficRepository) ListUserBillableTraffic(ctx context.Context) (map[string]int64, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	type billedRow struct {
		serverID int64
		email    string
		username string
		bytes    int64
	}
	rows, err := r.db.QueryContext(ctx, `SELECT server_id, email, billable_username, billable_bytes
		FROM user_email_traffic WHERE billable_initialized = 1`)
	if err != nil {
		return nil, fmt.Errorf("list billable traffic: %w", err)
	}
	var billedRows []billedRow
	byServer := make(map[int64][]string)
	for rows.Next() {
		var row billedRow
		if err := rows.Scan(&row.serverID, &row.email, &row.username, &row.bytes); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan billable traffic: %w", err)
		}
		billedRows = append(billedRows, row)
		if row.username == "" {
			byServer[row.serverID] = append(byServer[row.serverID], row.email)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate billable traffic: %w", err)
	}
	rows.Close()

	resolvedByServer := make(map[int64]map[string]UserTrafficBilling, len(byServer))
	for serverID, emails := range byServer {
		resolved, err := r.ResolveUserTrafficBilling(ctx, serverID, emails)
		if err != nil {
			return nil, err
		}
		resolvedByServer[serverID] = resolved
	}
	totals := make(map[string]int64)
	for _, row := range billedRows {
		username := row.username
		if username == "" {
			username = resolvedByServer[row.serverID][row.email].Username
		}
		if username == "" {
			continue
		}
		if row.bytes > 0 && math.MaxInt64-totals[username] < row.bytes {
			totals[username] = math.MaxInt64
		} else {
			totals[username] += max(row.bytes, 0)
		}
	}

	// Very old installations may have user_traffic rows but no corresponding
	// email rows. Preserve their previous traffic-mode semantics as a fallback.
	rows, err = r.db.QueryContext(ctx, `
		SELECT ut.username, COALESCE(SUM(ut.uplink + ut.downlink), 0), COALESCE(p.traffic_mode, 'oneway')
		FROM user_traffic ut
		LEFT JOIN users u ON u.username = ut.username
		LEFT JOIN packages p ON p.id = u.package_id
		GROUP BY ut.username, p.traffic_mode`)
	if err != nil {
		return nil, fmt.Errorf("list legacy user traffic fallback: %w", err)
	}
	for rows.Next() {
		var username, mode string
		var raw int64
		if err := rows.Scan(&username, &raw, &mode); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan legacy user traffic fallback: %w", err)
		}
		if _, hasEmailCounters := totals[username]; hasEmailCounters {
			continue
		}
		multiplier := 1.0
		if mode == "twoway" {
			multiplier = 2
		}
		totals[username] = billTrafficBytes(raw, multiplier)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate legacy user traffic fallback: %w", err)
	}
	rows.Close()
	return totals, nil
}

func (r *TrafficRepository) GetUserBillableTraffic(ctx context.Context, username string) (int64, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0, errors.New("username is required")
	}
	totals, err := r.ListUserBillableTraffic(ctx)
	if err != nil {
		return 0, err
	}
	return totals[username], nil
}

func (r *TrafficRepository) UpdateUserLimitOverrides(ctx context.Context, username string, speedOverride *float64, deviceOverride *int) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET speed_limit_override = ?, device_limit_override = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		speedOverride, deviceOverride, username)
	return err
}

// UpdateUserTrafficLimitOverride writes the optional package-level total traffic cap.
// nil inherits the package, 0 explicitly disables the total cap, and >0 overrides it.
func (r *TrafficRepository) UpdateUserTrafficLimitOverride(ctx context.Context, username string, limitBytes *int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if limitBytes != nil && *limitBytes < 0 {
		return errors.New("traffic limit override cannot be negative")
	}
	result, err := r.db.ExecContext(ctx,
		`UPDATE users SET traffic_limit_override = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		limitBytes, username)
	if err != nil {
		return fmt.Errorf("update user traffic limit override: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UpdateUserNodeLimits 写用户级 per-node 限速 / 客户端数覆盖。
// 序列化用 serializeNodeFloatMap/IntMap(nodes 传 nil 不过滤,用户可能切换套餐)。
// nil map / 空 map → 存 "{}"。
func (r *TrafficRepository) UpdateUserNodeLimits(ctx context.Context, username string, speedOverrides map[int64]float64, deviceOverrides map[int64]int) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	speedJSON := serializeNodeFloatMap(speedOverrides, nil)
	deviceJSON := serializeNodeIntMap(deviceOverrides, nil)
	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET node_speed_limit_overrides = ?, node_device_limit_overrides = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		speedJSON, deviceJSON, username)
	if err != nil {
		return fmt.Errorf("update user node limits: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *TrafficRepository) UpdateUserOverLimit(ctx context.Context, username string, isOverLimit bool) error {
	val := 0
	if isOverLimit {
		val = 1
	}
	_, err := r.db.ExecContext(ctx, `UPDATE users SET is_over_limit = ? WHERE username = ?`, val, username)
	return err
}

func (r *TrafficRepository) IsUserOverLimit(ctx context.Context, username string) (bool, error) {
	var val int
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(is_over_limit, 0) FROM users WHERE username = ?`, username).Scan(&val)
	return val == 1, err
}

// 初始化 API token（如果不存在）
func (r *TrafficRepository) initializeAPIToken() error {
	// 检查 API token 是否已存在
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM system_settings WHERE key = 'api_token')").Scan(&exists)
	if err != nil {
		return fmt.Errorf("检查 api token 是否存在: %w", err)
	}

	if !exists {
		// 生成新的 API token
		token := uuid.New().String()
		_, err = r.db.Exec("INSERT INTO system_settings (key, value) VALUES ('api_token', ?)", token)
		if err != nil {
			return fmt.Errorf("插入 api token: %w", err)
		}
	}

	return nil
}

// 返回当前的 API token
func (r *TrafficRepository) GetAPIToken(ctx context.Context) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("流量仓库未初始化")
	}

	var token string
	err := r.db.QueryRowContext(ctx, "SELECT value FROM system_settings WHERE key = 'api_token'").Scan(&token)
	if err == sql.ErrNoRows {
		// 如果 token 不存在，初始化它
		if err := r.initializeAPIToken(); err != nil {
			return "", err
		}
		// 重新获取
		err = r.db.QueryRowContext(ctx, "SELECT value FROM system_settings WHERE key = 'api_token'").Scan(&token)
	}
	if err != nil {
		return "", fmt.Errorf("获取 api token: %w", err)
	}

	return token, nil
}

// 重新生成 API token
func (r *TrafficRepository) RegenerateAPIToken(ctx context.Context) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("流量仓库未初始化")
	}

	token := uuid.New().String()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ('api_token', ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, token)
	if err != nil {
		return "", fmt.Errorf("重新生成 api token: %w", err)
	}

	return token, nil
}

// 获取是否使用 gRPC 的设置
func (r *TrafficRepository) GetUseGRPC(ctx context.Context) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("流量仓库未初始化")
	}

	var value string
	err := r.db.QueryRowContext(ctx, "SELECT value FROM system_settings WHERE key = 'use_grpc'").Scan(&value)
	if err == sql.ErrNoRows {
		return false, nil // 默认不使用 gRPC
	}
	if err != nil {
		return false, fmt.Errorf("获取 use_grpc 设置: %w", err)
	}

	return value == "true", nil
}

// 设置是否使用 gRPC
func (r *TrafficRepository) SetUseGRPC(ctx context.Context, useGRPC bool) error {
	if r == nil || r.db == nil {
		return errors.New("流量仓库未初始化")
	}

	value := "false"
	if useGRPC {
		value = "true"
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ('use_grpc', ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, value)
	if err != nil {
		return fmt.Errorf("设置 use_grpc: %w", err)
	}

	return nil
}

// 获取系统设置
func (r *TrafficRepository) GetSystemSetting(ctx context.Context, key string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	var value string
	err := r.db.QueryRowContext(ctx, "SELECT value FROM system_settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("获取系统设置 %s: %w", key, err)
	}
	return value, nil
}

// 设置系统设置
func (r *TrafficRepository) SetSystemSetting(ctx context.Context, key, value string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, key, value)
	if err != nil {
		return fmt.Errorf("设置系统设置 %s: %w", key, err)
	}
	return nil
}

// serverNotifyToleranceKey 上下线通知容忍阈值(秒)在 system_settings 里的 key。
const serverNotifyToleranceKey = "notify_server_tolerance_seconds"

// GetServerNotifyToleranceSeconds 读服务器上下线通知的容忍阈值(秒):离线满该秒数才发下线通知,
// 阈值内又上线则一条都不发(压抖动 + 主控升级重启误报)。未设置→默认 120(开);显式 "0"→0(关闭,即时通知)。
func (r *TrafficRepository) GetServerNotifyToleranceSeconds(ctx context.Context) int {
	const def = 120
	if r == nil || r.db == nil {
		return def
	}
	v, err := r.GetSystemSetting(ctx, serverNotifyToleranceKey)
	if err != nil || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return def
	}
	return n
}

// SetServerNotifyToleranceSeconds 写容忍阈值(秒),<0 归 0。
func (r *TrafficRepository) SetServerNotifyToleranceSeconds(ctx context.Context, seconds int) error {
	if seconds < 0 {
		seconds = 0
	}
	return r.SetSystemSetting(ctx, serverNotifyToleranceKey, strconv.Itoa(seconds))
}

func (r *TrafficRepository) CountRemoteServers(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	var count int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM remote_servers`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count remote servers: %w", err)
	}
	return count, nil
}

func (r *TrafficRepository) CountUsers(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	var count int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

// CountUserTemplates / CountUserOverrideScripts / CountUserSubscribeFiles
// 统计某用户创建的资源数量,用于"普通用户配额"校验。created_by/username 空串视为 admin 创建。
func (r *TrafficRepository) CountUserTemplates(ctx context.Context, username string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM templates WHERE created_by = ?`, username).Scan(&n)
	return n, err
}

func (r *TrafficRepository) CountUserOverrideScripts(ctx context.Context, username string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM override_scripts WHERE username = ?`, username).Scan(&n)
	return n, err
}

func (r *TrafficRepository) CountUserSubscribeFiles(ctx context.Context, username string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM subscribe_files WHERE created_by = ?`, username).Scan(&n)
	return n, err
}

func (r *TrafficRepository) CountUserCustomRules(ctx context.Context, username string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM custom_rules WHERE created_by = ?`, username).Scan(&n)
	return n, err
}

func remoteInstallationNonceHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}

// CreateRemoteServerInstallTicket stores only a digest of a short-lived ticket
// used to download one installer. A ticket may be consumed exactly once.
func (r *TrafficRepository) CreateRemoteServerInstallTicket(ctx context.Context, serverID int64, ticket string, expiresAt time.Time) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if serverID <= 0 || strings.TrimSpace(ticket) == "" {
		return errors.New("remote server and install ticket are required")
	}
	now := time.Now()
	if !expiresAt.After(now) {
		return errors.New("install ticket expiry must be in the future")
	}
	if _, err := r.db.ExecContext(ctx, `
		DELETE FROM remote_server_install_tickets
		WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND consumed_at <= ?)`,
		now.UnixNano(), now.Add(-time.Hour).UnixNano()); err != nil {
		return fmt.Errorf("prune remote server install tickets: %w", err)
	}
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO remote_server_install_tickets (ticket_hash, server_id, created_at, expires_at, consumed_at)
		SELECT ?, id, ?, ?, NULL FROM remote_servers WHERE id = ?
		ON CONFLICT(ticket_hash) DO NOTHING`,
		remoteInstallationNonceHash(ticket), now.UnixNano(), expiresAt.UnixNano(), serverID)
	if err != nil {
		return fmt.Errorf("create remote server install ticket: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("create remote server install ticket rows affected: %w", err)
	} else if affected == 0 {
		var exists int
		if err := r.db.QueryRowContext(ctx, `SELECT 1 FROM remote_servers WHERE id = ?`, serverID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return ErrRemoteServerNotFound
		} else if err != nil {
			return fmt.Errorf("check remote server for install ticket: %w", err)
		}
		return errors.New("install ticket collision")
	}
	return nil
}

// ConsumeRemoteServerInstallTicket atomically marks a live ticket consumed and
// returns the server it authorizes. Response loss deliberately burns the ticket;
// an administrator can issue a fresh command without exposing the node token.
func (r *TrafficRepository) ConsumeRemoteServerInstallTicket(ctx context.Context, ticket string, now time.Time) (*RemoteServer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if strings.TrimSpace(ticket) == "" {
		return nil, ErrRemoteInstallTicketInvalid
	}
	ticketHash := remoteInstallationNonceHash(ticket)
	result, err := r.db.ExecContext(ctx, `
		UPDATE remote_server_install_tickets
		SET consumed_at = ?
		WHERE ticket_hash = ? AND consumed_at IS NULL AND expires_at > ?`,
		now.UnixNano(), ticketHash, now.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("consume remote server install ticket: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return nil, fmt.Errorf("consume remote server install ticket rows affected: %w", err)
	} else if affected != 1 {
		return nil, ErrRemoteInstallTicketInvalid
	}
	var serverID int64
	if err := r.db.QueryRowContext(ctx,
		`SELECT server_id FROM remote_server_install_tickets WHERE ticket_hash = ? AND consumed_at = ?`,
		ticketHash, now.UnixNano(),
	).Scan(&serverID); err != nil {
		return nil, fmt.Errorf("read consumed remote server install ticket: %w", err)
	}
	server, err := r.GetRemoteServer(ctx, serverID)
	if err != nil {
		if errors.Is(err, ErrRemoteServerNotFound) {
			return nil, ErrRemoteInstallTicketInvalid
		}
		return nil, err
	}
	return server, nil
}

const (
	remoteInstallationDefaultListenPort = 23889
	remoteInstallationGuardPortOffset   = 1
	remoteInstallationAbortedTTL        = 5 * time.Minute
)

// RemoteServerInstallationPolicyFingerprint binds a downloaded installer to
// the normalized server policy that determines what it may replace, snapshot,
// expose, and start. Tokens and other credentials are deliberately excluded.
func RemoteServerInstallationPolicyFingerprint(server *RemoteServer) (string, error) {
	if server == nil {
		return "", errors.New("remote server is required")
	}
	stealSelf := server.StealSelf
	stealMode := "default"
	if stealSelf {
		switch server.StealMode {
		case "tunnel", "fallback":
			stealMode = server.StealMode
		default:
			return "", errors.New("invalid remote server takeover mode")
		}
	}
	xrayMode := "external"
	if server.XrayMode == "embedded" {
		xrayMode = "embedded"
	}
	nginxMode := strings.TrimSpace(server.NginxMode)
	if nginxMode == "" {
		nginxMode = "managed"
	}
	if nginxMode != "managed" && nginxMode != "reuse_existing" {
		return "", errors.New("invalid remote server nginx mode")
	}
	connectionMode := ""
	switch server.ConnectionMode {
	case ConnectionModePush:
		connectionMode = "http"
	case ConnectionModeWebSocket:
		connectionMode = "websocket"
	default:
		return "", errors.New("remote installer requires push or websocket connection mode")
	}
	listenPort := server.ListenPort
	if listenPort == 0 {
		listenPort = remoteInstallationDefaultListenPort
	}
	if !IsValidRemoteManagementListenPort(listenPort) || listenPort == 0 {
		return "", errors.New("invalid remote server management port")
	}
	guardPort := listenPort + remoteInstallationGuardPortOffset
	canonical := fmt.Sprintf(
		"arcway-install-policy-v1\nsteal_self=%t\nsteal_mode=%s\nnginx_mode=%s\nxray_mode=%s\nconnection_mode=%s\nfront_service=xray\nlisten_port=%d\nguard_port=%d\n",
		stealSelf, stealMode, nginxMode, xrayMode, connectionMode, listenPort, guardPort,
	)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

// RemoteInstallationPolicyContext contains panel-wide inputs that change what
// an installer trusts or where it connects. Callers must pass normalized,
// deterministic values (panel IPs sorted, master URL normalized).
type RemoteInstallationPolicyContext struct {
	PanelSourceIPs  []string
	MasterURL       string
	MasterPublicKey string
}

// RemoteServerInstallationPolicyFingerprintWithContext binds the server policy
// and all panel-wide trust inputs into one digest. The server portion is
// recomputed while the exclusive installation lease is held by Begin.
func RemoteServerInstallationPolicyFingerprintWithContext(server *RemoteServer, policy RemoteInstallationPolicyContext) (string, error) {
	serverFingerprint, err := RemoteServerInstallationPolicyFingerprint(server)
	if err != nil {
		return "", err
	}
	if len(policy.PanelSourceIPs) == 0 {
		return "", errors.New("panel source IPs are required")
	}
	panelSourceIPs := append([]string(nil), policy.PanelSourceIPs...)
	for index := range panelSourceIPs {
		panelSourceIPs[index] = strings.TrimSpace(panelSourceIPs[index])
		if panelSourceIPs[index] == "" || strings.ContainsAny(panelSourceIPs[index], "\r\n") {
			return "", errors.New("invalid panel source IP")
		}
	}
	sort.Strings(panelSourceIPs)
	masterURL := strings.TrimSpace(policy.MasterURL)
	if masterURL == "" || strings.ContainsAny(masterURL, "\r\n") {
		return "", errors.New("effective master URL is required")
	}
	masterPublicKey := strings.TrimSpace(policy.MasterPublicKey)
	if strings.ContainsAny(masterPublicKey, "\r\n") {
		return "", errors.New("invalid master public key")
	}
	canonical := fmt.Sprintf(
		"arcway-install-policy-v2\nserver=%s\npanel_source_ips=%s\nmaster_url=%s\nmaster_public_key=%s\n",
		serverFingerprint, strings.Join(panelSourceIPs, ","), masterURL, masterPublicKey,
	)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

func remoteInstallationPolicyMatches(supplied, expected string) bool {
	if len(supplied) != sha256.Size*2 || len(expected) != sha256.Size*2 {
		return false
	}
	if _, err := hex.DecodeString(supplied); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(supplied)), []byte(expected)) == 1
}

type remoteServerInstallation struct {
	nonceHash     string
	startedAt     int64
	expiresAt     int64
	readyAt       sql.NullInt64
	preparedAt    sql.NullInt64
	completedAt   sql.NullInt64
	rollingBackAt sql.NullInt64
	abortedAt     sql.NullInt64
}

func (r *TrafficRepository) getRemoteServerInstallation(ctx context.Context, serverID int64) (*remoteServerInstallation, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return nil, errors.New("remote server id is required")
	}

	var installation remoteServerInstallation
	err := r.db.QueryRowContext(ctx, `
		SELECT nonce_hash, started_at, expires_at, ready_at, prepared_at, completed_at, rolling_back_at, aborted_at
		FROM remote_server_installations
		WHERE server_id = ?`, serverID).Scan(
		&installation.nonceHash,
		&installation.startedAt,
		&installation.expiresAt,
		&installation.readyAt,
		&installation.preparedAt,
		&installation.completedAt,
		&installation.rollingBackAt,
		&installation.abortedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get remote server installation: %w", err)
	}
	return &installation, nil
}

func remoteInstallationNonceMatches(installation *remoteServerInstallation, nonce string) bool {
	if installation == nil || nonce == "" {
		return false
	}
	want := remoteInstallationNonceHash(nonce)
	return subtle.ConstantTimeCompare([]byte(installation.nonceHash), []byte(want)) == 1
}

func remoteInstallationMatches(installation *remoteServerInstallation, nonce string, now time.Time) bool {
	return remoteInstallationNonceMatches(installation, nonce) &&
		!installation.completedAt.Valid && !installation.abortedAt.Valid &&
		installation.expiresAt > now.UnixNano()
}

func remoteInstallationUsable(installation *remoteServerInstallation, nonce string, now time.Time) bool {
	return remoteInstallationMatches(installation, nonce, now) && !installation.rollingBackAt.Valid
}

func (r *TrafficRepository) remoteServerInstallationLease(serverID int64) *sync.RWMutex {
	lease, _ := r.remoteInstallationLeases.LoadOrStore(serverID, &sync.RWMutex{})
	return lease.(*sync.RWMutex)
}

type remoteServerMutationLeaseContextKey struct{}

type remoteServerMutationLeaseContext struct {
	repo               *TrafficRepository
	heldServerIDs      map[int64]struct{}
	exclusiveServerIDs map[int64]struct{}
	bypassServerIDs    map[int64]struct{}
}

// RemoteServerMutationLeaseState reports whether ctx already carries this
// repository's lease for serverID. Callers use it to avoid trying to upgrade a
// shared lease in the same call stack, which RWMutex cannot do safely.
func (r *TrafficRepository) RemoteServerMutationLeaseState(ctx context.Context, serverID int64) (held, exclusive bool) {
	if r == nil || ctx == nil || serverID <= 0 {
		return false, false
	}
	state, _ := ctx.Value(remoteServerMutationLeaseContextKey{}).(remoteServerMutationLeaseContext)
	if state.repo != r {
		return false, false
	}
	_, held = state.heldServerIDs[serverID]
	_, exclusive = state.exclusiveServerIDs[serverID]
	return held, exclusive
}

// RemoteServerMutationLeaseBypassContext marks an explicit installation
// mutation for one server (the authenticated Prepare phase). The first
// WithRemoteServerMutationLease call takes the exclusive lease but bypasses the
// durable-active rejection; nested calls reuse it. Keep this context scoped to
// that request.
func (r *TrafficRepository) RemoteServerMutationLeaseBypassContext(ctx context.Context, serverID int64) context.Context {
	previous, _ := ctx.Value(remoteServerMutationLeaseContextKey{}).(remoteServerMutationLeaseContext)
	held := make(map[int64]struct{})
	exclusive := make(map[int64]struct{})
	bypassed := make(map[int64]struct{})
	if previous.repo == r {
		for id := range previous.heldServerIDs {
			held[id] = struct{}{}
		}
		for id := range previous.bypassServerIDs {
			bypassed[id] = struct{}{}
		}
		for id := range previous.exclusiveServerIDs {
			exclusive[id] = struct{}{}
		}
	}
	bypassed[serverID] = struct{}{}
	return context.WithValue(ctx, remoteServerMutationLeaseContextKey{}, remoteServerMutationLeaseContext{
		repo:               r,
		heldServerIDs:      held,
		exclusiveServerIDs: exclusive,
		bypassServerIDs:    bypassed,
	})
}

// AcquireRemoteServerMutationLease holds the server's installation lease from
// the final durable-lock check until release. The returned context must be used
// for all nested repository calls so same-server acquisition is reentrant even
// when an installation Begin is waiting for the exclusive side of the lock.
//
// A context produced by RemoteServerMutationLeaseBypassContext takes the
// exclusive side and skips only the durable-active rejection. This is reserved
// for the authenticated Prepare transaction itself.
func (r *TrafficRepository) AcquireRemoteServerMutationLease(ctx context.Context, serverID int64) (context.Context, func(), error) {
	if r == nil || r.db == nil {
		return nil, nil, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return nil, nil, errors.New("remote server id is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	state, _ := ctx.Value(remoteServerMutationLeaseContextKey{}).(remoteServerMutationLeaseContext)
	if state.repo == r {
		if _, held := state.heldServerIDs[serverID]; held {
			return ctx, func() {}, nil
		}
	}

	lease := r.remoteServerInstallationLease(serverID)
	_, bypassed := state.bypassServerIDs[serverID]
	exclusive := state.repo == r && bypassed
	if exclusive {
		lease.Lock()
	} else {
		lease.RLock()
	}
	unlock := func() {
		if exclusive {
			lease.Unlock()
		} else {
			lease.RUnlock()
		}
	}
	if err := ctx.Err(); err != nil {
		unlock()
		return nil, nil, err
	}
	if !exclusive {
		active, err := r.IsRemoteServerInstallationActive(ctx, serverID)
		if err != nil {
			unlock()
			return nil, nil, err
		}
		if active {
			unlock()
			return nil, nil, ErrRemoteInstallationActive
		}
	}
	heldServerIDs := make(map[int64]struct{}, len(state.heldServerIDs)+1)
	exclusiveServerIDs := make(map[int64]struct{}, len(state.exclusiveServerIDs))
	bypassServerIDs := make(map[int64]struct{}, len(state.bypassServerIDs))
	if state.repo == r {
		for heldID := range state.heldServerIDs {
			heldServerIDs[heldID] = struct{}{}
		}
		for bypassedID := range state.bypassServerIDs {
			bypassServerIDs[bypassedID] = struct{}{}
		}
		for exclusiveID := range state.exclusiveServerIDs {
			exclusiveServerIDs[exclusiveID] = struct{}{}
		}
	}
	heldServerIDs[serverID] = struct{}{}
	if exclusive {
		exclusiveServerIDs[serverID] = struct{}{}
	}
	leasedCtx := context.WithValue(ctx, remoteServerMutationLeaseContextKey{}, remoteServerMutationLeaseContext{
		repo:               r,
		heldServerIDs:      heldServerIDs,
		exclusiveServerIDs: exclusiveServerIDs,
		bypassServerIDs:    bypassServerIDs,
	})
	var releaseOnce sync.Once
	return leasedCtx, func() { releaseOnce.Do(unlock) }, nil
}

// AcquireRemoteServerExclusiveMutationLease serializes a multi-step operation
// with every existing server mutation that uses AcquireRemoteServerMutationLease.
// It is intended for operations such as forwarding-port reservation plus
// remote inbound application, where two ordinary read-side leases would still
// be able to race. A shared lease cannot be upgraded in place because doing so
// would deadlock when another reader is present; callers must acquire the
// exclusive lease before any nested server mutation.
func (r *TrafficRepository) AcquireRemoteServerExclusiveMutationLease(ctx context.Context, serverID int64) (context.Context, func(), error) {
	if r == nil || r.db == nil {
		return nil, nil, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return nil, nil, errors.New("remote server id is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	state, _ := ctx.Value(remoteServerMutationLeaseContextKey{}).(remoteServerMutationLeaseContext)
	if state.repo == r {
		if _, exclusive := state.exclusiveServerIDs[serverID]; exclusive {
			return ctx, func() {}, nil
		}
		if _, held := state.heldServerIDs[serverID]; held {
			return nil, nil, errors.New("remote server mutation lease cannot be upgraded")
		}
	}

	lease := r.remoteServerInstallationLease(serverID)
	lease.Lock()
	if err := ctx.Err(); err != nil {
		lease.Unlock()
		return nil, nil, err
	}
	active, err := r.IsRemoteServerInstallationActive(ctx, serverID)
	if err != nil {
		lease.Unlock()
		return nil, nil, err
	}
	if active {
		lease.Unlock()
		return nil, nil, ErrRemoteInstallationActive
	}

	heldServerIDs := make(map[int64]struct{}, len(state.heldServerIDs)+1)
	exclusiveServerIDs := make(map[int64]struct{}, len(state.exclusiveServerIDs)+1)
	bypassServerIDs := make(map[int64]struct{}, len(state.bypassServerIDs))
	if state.repo == r {
		for heldID := range state.heldServerIDs {
			heldServerIDs[heldID] = struct{}{}
		}
		for exclusiveID := range state.exclusiveServerIDs {
			exclusiveServerIDs[exclusiveID] = struct{}{}
		}
		for bypassedID := range state.bypassServerIDs {
			bypassServerIDs[bypassedID] = struct{}{}
		}
	}
	heldServerIDs[serverID] = struct{}{}
	exclusiveServerIDs[serverID] = struct{}{}
	leasedCtx := context.WithValue(ctx, remoteServerMutationLeaseContextKey{}, remoteServerMutationLeaseContext{
		repo:               r,
		heldServerIDs:      heldServerIDs,
		exclusiveServerIDs: exclusiveServerIDs,
		bypassServerIDs:    bypassServerIDs,
	})
	var releaseOnce sync.Once
	return leasedCtx, func() { releaseOnce.Do(lease.Unlock) }, nil
}

// WithRemoteServerMutationLease is the single-return convenience wrapper for
// AcquireRemoteServerMutationLease. Multi-step handlers should acquire once and
// defer release so reads, database writes, and cache updates share one lease.
func (r *TrafficRepository) WithRemoteServerMutationLease(ctx context.Context, serverID int64, action func(context.Context) error) error {
	if action == nil {
		return errors.New("remote server mutation action is required")
	}
	leasedCtx, release, err := r.AcquireRemoteServerMutationLease(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	return action(leasedCtx)
}

func (r *TrafficRepository) acquireRemoteServerInstallationExclusive(ctx context.Context, serverID int64) (func(), error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return nil, errors.New("remote server id is required")
	}
	state, _ := ctx.Value(remoteServerMutationLeaseContextKey{}).(remoteServerMutationLeaseContext)
	if state.repo == r {
		if _, exclusive := state.exclusiveServerIDs[serverID]; exclusive {
			return func() {}, nil
		}
		if _, held := state.heldServerIDs[serverID]; held {
			return nil, errors.New("cannot acquire installation exclusive lease while shared mutation lease is held")
		}
	}
	lease := r.remoteServerInstallationLease(serverID)
	lease.Lock()
	if err := ctx.Err(); err != nil {
		lease.Unlock()
		return nil, err
	}
	return lease.Unlock, nil
}

func (r *TrafficRepository) validateRemoteServerInstallationPolicyLocked(ctx context.Context, serverID int64, suppliedFingerprint string) error {
	server, err := r.GetRemoteServer(ctx, serverID)
	if err != nil {
		return err
	}
	expectedFingerprint, err := RemoteServerInstallationPolicyFingerprint(server)
	if err != nil {
		return fmt.Errorf("calculate remote installation policy: %w", err)
	}
	if !remoteInstallationPolicyMatches(suppliedFingerprint, expectedFingerprint) {
		return ErrRemoteInstallationPolicy
	}
	return nil
}

func (r *TrafficRepository) validateRemoteServerInstallationPolicyContextLocked(ctx context.Context, serverID int64, suppliedFingerprint string, policy RemoteInstallationPolicyContext) error {
	server, err := r.GetRemoteServer(ctx, serverID)
	if err != nil {
		return err
	}
	expectedFingerprint, err := RemoteServerInstallationPolicyFingerprintWithContext(server, policy)
	if err != nil {
		return fmt.Errorf("calculate remote installation policy context: %w", err)
	}
	if !remoteInstallationPolicyMatches(suppliedFingerprint, expectedFingerprint) {
		return ErrRemoteInstallationPolicy
	}
	return nil
}

func (r *TrafficRepository) beginRemoteServerInstallationLocked(ctx context.Context, serverID int64, nonce string, expiresAt, now time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO remote_server_installations (
			server_id, nonce_hash, started_at, expires_at, ready_at, prepared_at, completed_at, rolling_back_at, aborted_at
		)
		SELECT id, ?, ?, ?, NULL, NULL, NULL, NULL, NULL FROM remote_servers WHERE id = ?
		ON CONFLICT(server_id) DO UPDATE SET
			nonce_hash = excluded.nonce_hash,
			started_at = excluded.started_at,
			expires_at = excluded.expires_at,
			ready_at = NULL,
			prepared_at = NULL,
			completed_at = NULL,
			rolling_back_at = NULL,
			aborted_at = NULL
		WHERE remote_server_installations.nonce_hash <> excluded.nonce_hash
			AND (remote_server_installations.completed_at IS NOT NULL
				OR remote_server_installations.aborted_at IS NOT NULL
				OR remote_server_installations.expires_at <= ?)`,
		remoteInstallationNonceHash(nonce), now.UnixNano(), expiresAt.UnixNano(), serverID, now.UnixNano())
	if err != nil {
		return fmt.Errorf("begin remote server installation: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("begin remote server installation rows affected: %w", err)
	} else if affected == 0 {
		installation, installErr := r.getRemoteServerInstallation(ctx, serverID)
		if installErr != nil {
			return installErr
		}
		if remoteInstallationNonceMatches(installation, nonce) {
			switch {
			case installation.abortedAt.Valid:
				return ErrRemoteInstallationAborted
			case installation.completedAt.Valid, installation.rollingBackAt.Valid, installation.expiresAt <= now.UnixNano():
				return ErrRemoteInstallationInvalid
			default:
				// A response-loss retry for the same live transaction keeps the
				// original expiry and readiness state.
				return nil
			}
		}
		var exists int
		if err := r.db.QueryRowContext(ctx, `SELECT 1 FROM remote_servers WHERE id = ?`, serverID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return ErrRemoteServerNotFound
		} else if err != nil {
			return fmt.Errorf("check remote server after installation conflict: %w", err)
		}
		return ErrRemoteInstallationActive
	}
	return nil
}

// BeginRemoteServerInstallation creates a durable transaction for trusted
// internal callers. The authenticated HTTP installer must use the policy-bound
// variant below so a downloaded script cannot outlive a policy edit.
func (r *TrafficRepository) BeginRemoteServerInstallation(ctx context.Context, serverID int64, nonce string, expiresAt time.Time) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return errors.New("remote server id is required")
	}
	if nonce == "" {
		return errors.New("installation nonce is required")
	}
	now := time.Now()
	if !expiresAt.After(now) {
		return errors.New("installation expiry must be in the future")
	}
	release, err := r.acquireRemoteServerInstallationExclusive(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	return r.beginRemoteServerInstallationLocked(ctx, serverID, nonce, expiresAt, now)
}

// BeginRemoteServerInstallationWithPolicy compares the downloaded script's
// fingerprint against a fresh database read while holding the same exclusive
// lease that creates the durable transaction.
func (r *TrafficRepository) BeginRemoteServerInstallationWithPolicy(ctx context.Context, serverID int64, nonce string, expiresAt time.Time, policyFingerprint string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return errors.New("remote server id is required")
	}
	if nonce == "" {
		return errors.New("installation nonce is required")
	}
	now := time.Now()
	if !expiresAt.After(now) {
		return errors.New("installation expiry must be in the future")
	}
	release, err := r.acquireRemoteServerInstallationExclusive(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	if err := r.validateRemoteServerInstallationPolicyLocked(ctx, serverID, policyFingerprint); err != nil {
		return err
	}
	return r.beginRemoteServerInstallationLocked(ctx, serverID, nonce, expiresAt, now)
}

// BeginRemoteServerInstallationWithPolicyContext validates server-specific and
// panel-wide trust inputs while holding the same exclusive lease that creates
// the durable installation row.
func (r *TrafficRepository) BeginRemoteServerInstallationWithPolicyContext(ctx context.Context, serverID int64, nonce string, expiresAt time.Time, policyFingerprint string, policy RemoteInstallationPolicyContext) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return errors.New("remote server id is required")
	}
	if nonce == "" {
		return errors.New("installation nonce is required")
	}
	now := time.Now()
	if !expiresAt.After(now) {
		return errors.New("installation expiry must be in the future")
	}
	release, err := r.acquireRemoteServerInstallationExclusive(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	if err := r.validateRemoteServerInstallationPolicyContextLocked(ctx, serverID, policyFingerprint, policy); err != nil {
		return err
	}
	return r.beginRemoteServerInstallationLocked(ctx, serverID, nonce, expiresAt, now)
}

// RenewRemoteServerInstallation extends a live nonce-bound lease without ever
// moving it past started_at+maxLifetime. Expired, rolling-back, aborted, and
// completed transactions cannot be resurrected.
func (r *TrafficRepository) RenewRemoteServerInstallation(ctx context.Context, serverID int64, nonce string, now time.Time, ttl, maxLifetime time.Duration) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if serverID <= 0 || nonce == "" {
		return ErrRemoteInstallationInvalid
	}
	if ttl <= 0 || maxLifetime <= 0 || ttl > maxLifetime {
		return errors.New("invalid installation renewal policy")
	}
	release, err := r.acquireRemoteServerInstallationExclusive(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return err
	}
	if !remoteInstallationUsable(installation, nonce, now) || installation.startedAt <= 0 {
		if remoteInstallationMatches(installation, nonce, now) && installation.rollingBackAt.Valid {
			return ErrRemoteInstallationRollingBack
		}
		if remoteInstallationNonceMatches(installation, nonce) && installation != nil && installation.abortedAt.Valid {
			return ErrRemoteInstallationAborted
		}
		return ErrRemoteInstallationInvalid
	}
	hardDeadline := time.Unix(0, installation.startedAt).Add(maxLifetime)
	if !hardDeadline.After(now) {
		return ErrRemoteInstallationInvalid
	}
	newExpiry := now.Add(ttl)
	if newExpiry.After(hardDeadline) {
		newExpiry = hardDeadline
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE remote_server_installations
		SET expires_at = ?
		WHERE server_id = ? AND nonce_hash = ? AND started_at = ? AND expires_at = ?
			AND completed_at IS NULL AND aborted_at IS NULL
			AND rolling_back_at IS NULL AND expires_at > ?`,
		newExpiry.UnixNano(), serverID, installation.nonceHash, installation.startedAt,
		installation.expiresAt, now.UnixNano())
	if err != nil {
		return fmt.Errorf("renew remote server installation: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("renew remote server installation rows affected: %w", err)
	} else if affected == 0 {
		return ErrRemoteInstallationInvalid
	}
	return nil
}

// ValidateRemoteServerInstallation verifies the nonce without exposing its
// stored digest. Expired installations are invalid even if the nonce matches.
func (r *TrafficRepository) ValidateRemoteServerInstallation(ctx context.Context, serverID int64, nonce string) (bool, error) {
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return false, err
	}
	return remoteInstallationUsable(installation, nonce, time.Now()), nil
}

// ValidateRemoteServerInstallationReady authorizes the explicit prepare phase:
// the transaction must be live, nonce-bound, and already management-ready.
func (r *TrafficRepository) ValidateRemoteServerInstallationReady(ctx context.Context, serverID int64, nonce string) (bool, error) {
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return false, err
	}
	return remoteInstallationUsable(installation, nonce, time.Now()) && installation.readyAt.Valid, nil
}

// MarkRemoteServerInstallationReady records that the management readiness
// checks passed. It is idempotent for the same live installation.
func (r *TrafficRepository) MarkRemoteServerInstallationReady(ctx context.Context, serverID int64, nonce string) error {
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return err
	}
	if !remoteInstallationUsable(installation, nonce, time.Now()) {
		return ErrRemoteInstallationInvalid
	}

	readyAt := time.Now().UnixNano()
	result, err := r.db.ExecContext(ctx, `
		UPDATE remote_server_installations
		SET ready_at = COALESCE(ready_at, ?)
		WHERE server_id = ? AND nonce_hash = ? AND expires_at = ?
			AND completed_at IS NULL AND aborted_at IS NULL
			AND rolling_back_at IS NULL AND expires_at > ?`,
		readyAt, serverID, installation.nonceHash, installation.expiresAt, readyAt)
	if err != nil {
		return fmt.Errorf("mark remote server installation ready: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("mark remote server installation ready rows affected: %w", err)
	} else if affected == 0 {
		return ErrRemoteInstallationInvalid
	}
	return nil
}

// MarkRemoteServerInstallationRollingBack quiesces panel-side writes before a
// failed installer restores local files. The exclusive lease waits for an
// in-flight Prepare to finish; the durable state then blocks later Prepare
// requests and all ordinary mutations until Abort records its tombstone.
func (r *TrafficRepository) MarkRemoteServerInstallationRollingBack(ctx context.Context, serverID int64, nonce string) error {
	release, err := r.acquireRemoteServerInstallationExclusive(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return err
	}
	if !remoteInstallationMatches(installation, nonce, time.Now()) {
		return ErrRemoteInstallationInvalid
	}
	if installation.rollingBackAt.Valid {
		return nil
	}

	now := time.Now().UnixNano()
	result, err := r.db.ExecContext(ctx, `
		UPDATE remote_server_installations
		SET rolling_back_at = COALESCE(rolling_back_at, ?)
		WHERE server_id = ? AND nonce_hash = ? AND expires_at = ?
			AND completed_at IS NULL AND aborted_at IS NULL AND expires_at > ?`,
		now, serverID, installation.nonceHash, installation.expiresAt, now)
	if err != nil {
		return fmt.Errorf("mark remote server installation rolling back: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("mark remote server installation rolling back rows affected: %w", err)
	} else if affected == 0 {
		return ErrRemoteInstallationInvalid
	}
	return nil
}

// MarkRemoteServerInstallationPrepared records that the panel deployed the
// desired Xray/Nginx state successfully. Preparation is valid only after the
// management readiness phase and is idempotent for the same live transaction.
func (r *TrafficRepository) MarkRemoteServerInstallationPrepared(ctx context.Context, serverID int64, nonce string) error {
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return err
	}
	if !remoteInstallationUsable(installation, nonce, time.Now()) {
		if remoteInstallationMatches(installation, nonce, time.Now()) && installation.rollingBackAt.Valid {
			return ErrRemoteInstallationRollingBack
		}
		return ErrRemoteInstallationInvalid
	}
	if !installation.readyAt.Valid {
		return ErrRemoteInstallationNotReady
	}

	preparedAt := time.Now().UnixNano()
	result, err := r.db.ExecContext(ctx, `
		UPDATE remote_server_installations
		SET prepared_at = COALESCE(prepared_at, ?)
		WHERE server_id = ? AND nonce_hash = ? AND expires_at = ?
			AND ready_at IS NOT NULL AND completed_at IS NULL
			AND aborted_at IS NULL AND rolling_back_at IS NULL AND expires_at > ?`,
		preparedAt, serverID, installation.nonceHash, installation.expiresAt, preparedAt)
	if err != nil {
		return fmt.Errorf("mark remote server installation prepared: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("mark remote server installation prepared rows affected: %w", err)
	} else if affected == 0 {
		return ErrRemoteInstallationInvalid
	}
	return nil
}

// FinalizeRemoteServerInstallation marks a prepared installation completed.
// The nonce-bound tombstone makes response-loss retries idempotent while
// IsActive immediately stops blocking automatic mutations.
func (r *TrafficRepository) FinalizeRemoteServerInstallation(ctx context.Context, serverID int64, nonce string) error {
	release, err := r.acquireRemoteServerInstallationExclusive(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return err
	}
	if !remoteInstallationNonceMatches(installation, nonce) {
		return ErrRemoteInstallationInvalid
	}
	if installation.completedAt.Valid {
		return nil
	}
	if installation.abortedAt.Valid {
		return ErrRemoteInstallationAborted
	}
	if installation.rollingBackAt.Valid {
		return ErrRemoteInstallationRollingBack
	}
	if installation.expiresAt <= time.Now().UnixNano() {
		return ErrRemoteInstallationInvalid
	}
	if !installation.readyAt.Valid {
		return ErrRemoteInstallationNotReady
	}
	if !installation.preparedAt.Valid {
		return ErrRemoteInstallationNotPrepared
	}

	now := time.Now().UnixNano()
	result, err := r.db.ExecContext(ctx, `
		UPDATE remote_server_installations
		SET completed_at = COALESCE(completed_at, ?)
		WHERE server_id = ? AND nonce_hash = ? AND expires_at = ?
			AND ready_at = ? AND prepared_at = ? AND completed_at IS NULL
			AND aborted_at IS NULL AND rolling_back_at IS NULL AND expires_at > ?`,
		now, serverID, installation.nonceHash, installation.expiresAt,
		installation.readyAt.Int64, installation.preparedAt.Int64, now)
	if err != nil {
		return fmt.Errorf("finalize remote server installation: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("finalize remote server installation rows affected: %w", err)
	} else if affected == 0 {
		latest, latestErr := r.getRemoteServerInstallation(ctx, serverID)
		if latestErr != nil {
			return latestErr
		}
		if remoteInstallationNonceMatches(latest, nonce) && latest.completedAt.Valid {
			return nil
		}
		return ErrRemoteInstallationInvalid
	}
	return nil
}

// AbortRemoteServerInstallation records a nonce-bound tombstone. It may arrive
// before a timed-out Begin request; the later same-nonce Begin then fails closed
// instead of recreating an active lock. A different nonce may replace an
// aborted, completed, or expired row.
func (r *TrafficRepository) AbortRemoteServerInstallation(ctx context.Context, serverID int64, nonce string) error {
	if nonce == "" {
		return errors.New("installation nonce is required")
	}
	release, err := r.acquireRemoteServerInstallationExclusive(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return err
	}
	now := time.Now()
	nowUnix := now.UnixNano()
	tombstoneExpiry := now.Add(remoteInstallationAbortedTTL).UnixNano()
	if remoteInstallationNonceMatches(installation, nonce) {
		if installation.completedAt.Valid {
			return ErrRemoteInstallationInvalid
		}
		if installation.abortedAt.Valid {
			return nil
		}
		result, err := r.db.ExecContext(ctx, `
			UPDATE remote_server_installations
			SET aborted_at = ?, expires_at = CASE WHEN expires_at > ? THEN expires_at ELSE ? END
			WHERE server_id = ? AND nonce_hash = ? AND completed_at IS NULL AND aborted_at IS NULL`,
			nowUnix, tombstoneExpiry, tombstoneExpiry, serverID, installation.nonceHash)
		if err != nil {
			return fmt.Errorf("abort remote server installation: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("abort remote server installation rows affected: %w", err)
		} else if affected == 0 {
			return ErrRemoteInstallationInvalid
		}
		return nil
	}
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO remote_server_installations (
			server_id, nonce_hash, started_at, expires_at, ready_at, prepared_at, completed_at, rolling_back_at, aborted_at
		)
		SELECT id, ?, ?, ?, NULL, NULL, NULL, NULL, ? FROM remote_servers WHERE id = ?
		ON CONFLICT(server_id) DO UPDATE SET
			nonce_hash = excluded.nonce_hash,
			started_at = excluded.started_at,
			expires_at = excluded.expires_at,
			ready_at = NULL,
			prepared_at = NULL,
			completed_at = NULL,
			rolling_back_at = NULL,
			aborted_at = excluded.aborted_at
		WHERE remote_server_installations.completed_at IS NOT NULL
			OR remote_server_installations.aborted_at IS NOT NULL
			OR remote_server_installations.expires_at <= ?`,
		remoteInstallationNonceHash(nonce), nowUnix, tombstoneExpiry, nowUnix, serverID, nowUnix)
	if err != nil {
		return fmt.Errorf("abort remote server installation: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("abort remote server installation rows affected: %w", err)
	} else if affected == 0 {
		if installation == nil {
			var exists int
			if err := r.db.QueryRowContext(ctx, `SELECT 1 FROM remote_servers WHERE id = ?`, serverID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
				return ErrRemoteServerNotFound
			} else if err != nil {
				return fmt.Errorf("check remote server after abort conflict: %w", err)
			}
		}
		return ErrRemoteInstallationInvalid
	}
	return nil
}

// IsRemoteServerInstallationActive reports whether a non-expired installation
// transaction exists. Expired rows deliberately remain available for audit but
// never block automatic deployment.
func (r *TrafficRepository) IsRemoteServerInstallationActive(ctx context.Context, serverID int64) (bool, error) {
	installation, err := r.getRemoteServerInstallation(ctx, serverID)
	if err != nil {
		return false, err
	}
	return installation != nil && !installation.completedAt.Valid && !installation.abortedAt.Valid && installation.expiresAt > time.Now().UnixNano(), nil
}

// 远程服务器CRUD操作

// 返回所有远程服务器。
func (r *TrafficRepository) ListRemoteServers(ctx context.Context) ([]RemoteServer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const query = `SELECT id, name, token, status, last_heartbeat, COALESCE(ip_address, ''), COALESCE(ip_address_v6, ''), COALESCE(ipv6_enabled, 1), COALESCE(offline_notified, 0), COALESCE(domain, ''),
		boot_time, xray_boot_time, COALESCE(boot_count, 0), COALESCE(xray_boot_count, 0),
		token_expires_at, last_token_refresh,
		COALESCE(connection_mode, 'push'), COALESCE(pull_address, ''), COALESCE(pull_port, 0), COALESCE(pull_token, ''), last_pull_at,
		COALESCE(push_fail_count, 0), last_push_fail, COALESCE(fallback_to_pull, 0), fallback_at,
		COALESCE(current_upload_speed, 0), COALESCE(current_download_speed, 0), speed_updated_at,
		COALESCE(xray_running, 0), COALESCE(xray_version, ''), xray_scanned_at,
		COALESCE(listen_port, 0), COALESCE(traffic_limit, 0), COALESCE(traffic_reset_day, 0),
		COALESCE(agent_token, ''), agent_token_expires_at, last_agent_token_refresh,
		COALESCE(use_443, 0), COALESCE(steal_self, 0), COALESCE(steal_mode, 'tunnel'), COALESCE(nginx_mode, 'managed'),
		COALESCE(site_type, ''), COALESCE(site_value, ''),
		COALESCE(xray_mode, 'external'),
		COALESCE(time_offset_seconds, 0),
		COALESCE(traffic_used_offset, 0),
		COALESCE(traffic_stats_mode, 'both'),
		COALESCE(traffic_source, 'xray'),
		COALESCE(warp_installed, 0),
		COALESCE(ddns_enabled, 0), COALESCE(ddns_provider_id, 0), ddns_last_synced_at, COALESCE(ddns_last_error, ''), COALESCE(ddns_pending, 0),
		last_traffic_reset_at,
		EXISTS(SELECT 1 FROM federated_servers fs WHERE fs.server_id = remote_servers.id),
		COALESCE((SELECT prefix FROM federated_servers fs WHERE fs.server_id = remote_servers.id), ''),
		created_at, updated_at
		FROM remote_servers ORDER BY sort_order ASC, id ASC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list remote servers: %w", err)
	}
	defer rows.Close()

	var servers []RemoteServer
	for rows.Next() {
		var server RemoteServer
		var lastHeartbeat, tokenExpiresAt, lastTokenRefresh, lastPullAt, lastPushFail, fallbackAt, speedUpdatedAt, xrayScannedAt sql.NullTime
		var bootTime, xrayBootTime sql.NullString
		var agentTokenExpiresAt, lastAgentTokenRefresh sql.NullTime
		var fallbackToPull, xrayRunning, warpInstalledInt int
		var timeOffsetSeconds int64
		var ddnsEnabledInt, ddnsPendingInt int
		var ddnsLastSyncedAt sql.NullTime
		var lastTrafficResetAt sql.NullTime
		if err := rows.Scan(&server.ID, &server.Name, &server.Token, &server.Status, &lastHeartbeat, &server.IPAddress, &server.IPAddressV6, &server.IPv6Enabled, &server.OfflineNotified, &server.Domain,
			&bootTime, &xrayBootTime, &server.BootCount, &server.XrayBootCount,
			&tokenExpiresAt, &lastTokenRefresh,
			&server.ConnectionMode, &server.PullAddress, &server.PullPort, &server.PullToken, &lastPullAt,
			&server.PushFailCount, &lastPushFail, &fallbackToPull, &fallbackAt,
			&server.CurrentUploadSpeed, &server.CurrentDownloadSpeed, &speedUpdatedAt,
			&xrayRunning, &server.XrayVersion, &xrayScannedAt,
			&server.ListenPort, &server.TrafficLimit, &server.TrafficResetDay,
			&server.AgentToken, &agentTokenExpiresAt, &lastAgentTokenRefresh,
			&server.Use443, &server.StealSelf, &server.StealMode, &server.NginxMode,
			&server.SiteType, &server.SiteValue,
			&server.XrayMode,
			&timeOffsetSeconds,
			&server.TrafficUsedOffset,
			&server.TrafficStatsMode,
			&server.TrafficSource,
			&warpInstalledInt,
			&ddnsEnabledInt, &server.DDNSProviderID, &ddnsLastSyncedAt, &server.DDNSLastError, &ddnsPendingInt,
			&lastTrafficResetAt,
			&server.IsFederated,
			&server.FederationPrefix,
			&server.CreatedAt, &server.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan remote server: %w", err)
		}
		server.DDNSEnabled = ddnsEnabledInt != 0
		server.DDNSPending = ddnsPendingInt != 0
		if ddnsLastSyncedAt.Valid {
			server.DDNSLastSyncedAt = &ddnsLastSyncedAt.Time
		}
		if lastTrafficResetAt.Valid {
			server.LastTrafficResetAt = &lastTrafficResetAt.Time
		}
		if lastHeartbeat.Valid {
			server.LastHeartbeat = &lastHeartbeat.Time
		}
		server.BootTime = parseNullTimeString(bootTime)
		server.XrayBootTime = parseNullTimeString(xrayBootTime)
		if tokenExpiresAt.Valid {
			server.TokenExpiresAt = &tokenExpiresAt.Time
		}
		if lastTokenRefresh.Valid {
			server.LastTokenRefresh = &lastTokenRefresh.Time
		}
		if lastPullAt.Valid {
			server.LastPullAt = &lastPullAt.Time
		}
		if lastPushFail.Valid {
			server.LastPushFail = &lastPushFail.Time
		}
		if fallbackAt.Valid {
			server.FallbackAt = &fallbackAt.Time
		}
		if speedUpdatedAt.Valid {
			server.SpeedUpdatedAt = &speedUpdatedAt.Time
		}
		if xrayScannedAt.Valid {
			server.XrayScannedAt = &xrayScannedAt.Time
		}
		if agentTokenExpiresAt.Valid {
			server.AgentTokenExpiresAt = &agentTokenExpiresAt.Time
		}
		if lastAgentTokenRefresh.Valid {
			server.LastAgentTokenRefresh = &lastAgentTokenRefresh.Time
		}
		server.FallbackToPull = fallbackToPull != 0
		server.XrayRunning = xrayRunning != 0
		server.WarpInstalled = warpInstalledInt != 0
		if timeOffsetSeconds != 0 {
			server.TimeOffsetSeconds = &timeOffsetSeconds
		}
		servers = append(servers, server)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remote servers: %w", err)
	}

	return servers, nil
}

// 按 ID 返回远程服务器。
func (r *TrafficRepository) GetRemoteServer(ctx context.Context, id int64) (*RemoteServer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return nil, errors.New("remote server id is required")
	}

	const query = `SELECT id, name, token, status, last_heartbeat, COALESCE(ip_address, ''), COALESCE(ip_address_v6, ''), COALESCE(ipv6_enabled, 1), COALESCE(offline_notified, 0), COALESCE(domain, ''),
		boot_time, xray_boot_time, COALESCE(boot_count, 0), COALESCE(xray_boot_count, 0),
		token_expires_at, last_token_refresh,
		COALESCE(connection_mode, 'push'), COALESCE(pull_address, ''), COALESCE(pull_port, 0), COALESCE(pull_token, ''), last_pull_at,
		COALESCE(listen_port, 0),
		COALESCE(agent_token, ''), agent_token_expires_at, last_agent_token_refresh,
		COALESCE(use_443, 0), COALESCE(steal_self, 0), COALESCE(steal_mode, 'tunnel'), COALESCE(nginx_mode, 'managed'),
		COALESCE(site_type, ''), COALESCE(site_value, ''),
		COALESCE(xray_mode, 'external'),
		COALESCE(traffic_limit, 0), COALESCE(traffic_reset_day, 0),
		COALESCE(current_upload_speed, 0), COALESCE(current_download_speed, 0),
		COALESCE(xray_running, 0), COALESCE(xray_version, ''),
		COALESCE(traffic_used_offset, 0),
		COALESCE(traffic_stats_mode, 'both'),
		COALESCE(traffic_source, 'xray'),
		COALESCE(warp_installed, 0),
		COALESCE(ddns_enabled, 0), COALESCE(ddns_provider_id, 0), ddns_last_synced_at, COALESCE(ddns_last_error, ''), COALESCE(ddns_pending, 0),
		last_traffic_reset_at,
		created_at, updated_at
		FROM remote_servers WHERE id = ?`

	var server RemoteServer
	var lastHeartbeat, tokenExpiresAt, lastTokenRefresh, lastPullAt sql.NullTime
	var bootTime, xrayBootTime sql.NullString
	var agentTokenExpiresAt, lastAgentTokenRefresh sql.NullTime
	var xrayRunningInt, warpInstalledInt int
	var ddnsEnabledInt, ddnsPendingInt int
	var ddnsLastSyncedAt sql.NullTime
	var lastTrafficResetAt sql.NullTime
	err := r.db.QueryRowContext(ctx, query, id).Scan(&server.ID, &server.Name, &server.Token, &server.Status, &lastHeartbeat, &server.IPAddress, &server.IPAddressV6, &server.IPv6Enabled, &server.OfflineNotified, &server.Domain,
		&bootTime, &xrayBootTime, &server.BootCount, &server.XrayBootCount,
		&tokenExpiresAt, &lastTokenRefresh,
		&server.ConnectionMode, &server.PullAddress, &server.PullPort, &server.PullToken, &lastPullAt,
		&server.ListenPort,
		&server.AgentToken, &agentTokenExpiresAt, &lastAgentTokenRefresh,
		&server.Use443, &server.StealSelf, &server.StealMode, &server.NginxMode,
		&server.SiteType, &server.SiteValue,
		&server.XrayMode,
		&server.TrafficLimit, &server.TrafficResetDay,
		&server.CurrentUploadSpeed, &server.CurrentDownloadSpeed,
		&xrayRunningInt, &server.XrayVersion,
		&server.TrafficUsedOffset,
		&server.TrafficStatsMode,
		&server.TrafficSource,
		&warpInstalledInt,
		&ddnsEnabledInt, &server.DDNSProviderID, &ddnsLastSyncedAt, &server.DDNSLastError, &ddnsPendingInt,
		&lastTrafficResetAt,
		&server.CreatedAt, &server.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRemoteServerNotFound
		}
		return nil, fmt.Errorf("get remote server: %w", err)
	}

	server.XrayRunning = xrayRunningInt != 0
	server.WarpInstalled = warpInstalledInt != 0
	server.DDNSEnabled = ddnsEnabledInt != 0
	server.DDNSPending = ddnsPendingInt != 0
	if ddnsLastSyncedAt.Valid {
		server.DDNSLastSyncedAt = &ddnsLastSyncedAt.Time
	}
	if lastTrafficResetAt.Valid {
		server.LastTrafficResetAt = &lastTrafficResetAt.Time
	}
	if lastHeartbeat.Valid {
		server.LastHeartbeat = &lastHeartbeat.Time
	}
	server.BootTime = parseNullTimeString(bootTime)
	server.XrayBootTime = parseNullTimeString(xrayBootTime)
	if tokenExpiresAt.Valid {
		server.TokenExpiresAt = &tokenExpiresAt.Time
	}
	if lastTokenRefresh.Valid {
		server.LastTokenRefresh = &lastTokenRefresh.Time
	}
	if lastPullAt.Valid {
		server.LastPullAt = &lastPullAt.Time
	}
	if agentTokenExpiresAt.Valid {
		server.AgentTokenExpiresAt = &agentTokenExpiresAt.Time
	}
	if lastAgentTokenRefresh.Valid {
		server.LastAgentTokenRefresh = &lastAgentTokenRefresh.Time
	}
	return &server, nil
}

// 通过其令牌返回远程服务器。
func (r *TrafficRepository) GetRemoteServerByToken(ctx context.Context, token string) (*RemoteServer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("remote server token is required")
	}

	const query = `SELECT id, name, token, status, last_heartbeat, COALESCE(ip_address, ''), COALESCE(ip_address_v6, ''), COALESCE(ipv6_enabled, 1), COALESCE(offline_notified, 0), COALESCE(domain, ''),
		boot_time, xray_boot_time, COALESCE(boot_count, 0), COALESCE(xray_boot_count, 0),
		token_expires_at, last_token_refresh,
		COALESCE(connection_mode, 'push'), COALESCE(pull_address, ''), COALESCE(pull_port, 0), COALESCE(pull_token, ''), last_pull_at,
		COALESCE(listen_port, 0),
		COALESCE(agent_token, ''), agent_token_expires_at, last_agent_token_refresh,
		COALESCE(use_443, 0), COALESCE(steal_self, 0), COALESCE(steal_mode, 'tunnel'), COALESCE(nginx_mode, 'managed'),
		COALESCE(site_type, ''), COALESCE(site_value, ''),
		COALESCE(xray_mode, 'external'),
		COALESCE(ddns_enabled, 0), COALESCE(ddns_provider_id, 0), ddns_last_synced_at, COALESCE(ddns_last_error, ''), COALESCE(ddns_pending, 0),
		created_at, updated_at
		FROM remote_servers WHERE token = ?`

	var server RemoteServer
	var lastHeartbeat, tokenExpiresAt, lastTokenRefresh, lastPullAt sql.NullTime
	var bootTime, xrayBootTime sql.NullString
	var agentTokenExpiresAt, lastAgentTokenRefresh sql.NullTime
	var ddnsEnabledInt, ddnsPendingInt int
	var ddnsLastSyncedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, query, token).Scan(&server.ID, &server.Name, &server.Token, &server.Status, &lastHeartbeat, &server.IPAddress, &server.IPAddressV6, &server.IPv6Enabled, &server.OfflineNotified, &server.Domain,
		&bootTime, &xrayBootTime, &server.BootCount, &server.XrayBootCount,
		&tokenExpiresAt, &lastTokenRefresh,
		&server.ConnectionMode, &server.PullAddress, &server.PullPort, &server.PullToken, &lastPullAt,
		&server.ListenPort,
		&server.AgentToken, &agentTokenExpiresAt, &lastAgentTokenRefresh,
		&server.Use443, &server.StealSelf, &server.StealMode, &server.NginxMode,
		&server.SiteType, &server.SiteValue,
		&server.XrayMode,
		&ddnsEnabledInt, &server.DDNSProviderID, &ddnsLastSyncedAt, &server.DDNSLastError, &ddnsPendingInt,
		&server.CreatedAt, &server.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRemoteServerNotFound
		}
		return nil, fmt.Errorf("get remote server by token: %w", err)
	}

	if lastHeartbeat.Valid {
		server.LastHeartbeat = &lastHeartbeat.Time
	}
	server.BootTime = parseNullTimeString(bootTime)
	server.XrayBootTime = parseNullTimeString(xrayBootTime)
	if tokenExpiresAt.Valid {
		server.TokenExpiresAt = &tokenExpiresAt.Time
	}
	if lastTokenRefresh.Valid {
		server.LastTokenRefresh = &lastTokenRefresh.Time
	}
	if lastPullAt.Valid {
		server.LastPullAt = &lastPullAt.Time
	}
	if agentTokenExpiresAt.Valid {
		server.AgentTokenExpiresAt = &agentTokenExpiresAt.Time
	}
	if lastAgentTokenRefresh.Valid {
		server.LastAgentTokenRefresh = &lastAgentTokenRefresh.Time
	}
	server.DDNSEnabled = ddnsEnabledInt != 0
	server.DDNSPending = ddnsPendingInt != 0
	if ddnsLastSyncedAt.Valid {
		server.DDNSLastSyncedAt = &ddnsLastSyncedAt.Time
	}
	return &server, nil
}

// 按名称返回远程服务器。
func (r *TrafficRepository) GetRemoteServerByName(ctx context.Context, name string) (*RemoteServer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("remote server name is required")
	}

	const query = `SELECT id, name, token, status, last_heartbeat, COALESCE(ip_address, ''), COALESCE(ip_address_v6, ''), COALESCE(ipv6_enabled, 1), COALESCE(offline_notified, 0), COALESCE(domain, ''),
		boot_time, xray_boot_time, COALESCE(boot_count, 0), COALESCE(xray_boot_count, 0),
		token_expires_at, last_token_refresh,
		COALESCE(connection_mode, 'push'), COALESCE(pull_address, ''), COALESCE(pull_port, 0), COALESCE(pull_token, ''), last_pull_at,
		COALESCE(listen_port, 0),
		COALESCE(agent_token, ''), agent_token_expires_at, last_agent_token_refresh,
		COALESCE(use_443, 0), COALESCE(steal_self, 0), COALESCE(steal_mode, 'tunnel'), COALESCE(nginx_mode, 'managed'),
		COALESCE(site_type, ''), COALESCE(site_value, ''),
		COALESCE(xray_mode, 'external'),
		COALESCE(ddns_enabled, 0), COALESCE(ddns_provider_id, 0), ddns_last_synced_at, COALESCE(ddns_last_error, ''), COALESCE(ddns_pending, 0),
		created_at, updated_at
		FROM remote_servers WHERE name = ?`

	var server RemoteServer
	var lastHeartbeat, tokenExpiresAt, lastTokenRefresh, lastPullAt sql.NullTime
	var bootTime, xrayBootTime sql.NullString
	var agentTokenExpiresAt, lastAgentTokenRefresh sql.NullTime
	var ddnsEnabledInt, ddnsPendingInt int
	var ddnsLastSyncedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, query, name).Scan(&server.ID, &server.Name, &server.Token, &server.Status, &lastHeartbeat, &server.IPAddress, &server.IPAddressV6, &server.IPv6Enabled, &server.OfflineNotified, &server.Domain,
		&bootTime, &xrayBootTime, &server.BootCount, &server.XrayBootCount,
		&tokenExpiresAt, &lastTokenRefresh,
		&server.ConnectionMode, &server.PullAddress, &server.PullPort, &server.PullToken, &lastPullAt,
		&server.ListenPort,
		&server.AgentToken, &agentTokenExpiresAt, &lastAgentTokenRefresh,
		&server.Use443, &server.StealSelf, &server.StealMode, &server.NginxMode,
		&server.SiteType, &server.SiteValue,
		&server.XrayMode,
		&ddnsEnabledInt, &server.DDNSProviderID, &ddnsLastSyncedAt, &server.DDNSLastError, &ddnsPendingInt,
		&server.CreatedAt, &server.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRemoteServerNotFound
		}
		return nil, fmt.Errorf("get remote server by name: %w", err)
	}
	server.DDNSEnabled = ddnsEnabledInt != 0
	server.DDNSPending = ddnsPendingInt != 0
	if ddnsLastSyncedAt.Valid {
		server.DDNSLastSyncedAt = &ddnsLastSyncedAt.Time
	}

	if lastHeartbeat.Valid {
		server.LastHeartbeat = &lastHeartbeat.Time
	}
	server.BootTime = parseNullTimeString(bootTime)
	server.XrayBootTime = parseNullTimeString(xrayBootTime)
	if tokenExpiresAt.Valid {
		server.TokenExpiresAt = &tokenExpiresAt.Time
	}
	if lastTokenRefresh.Valid {
		server.LastTokenRefresh = &lastTokenRefresh.Time
	}
	if lastPullAt.Valid {
		server.LastPullAt = &lastPullAt.Time
	}
	if agentTokenExpiresAt.Valid {
		server.AgentTokenExpiresAt = &agentTokenExpiresAt.Time
	}
	if lastAgentTokenRefresh.Valid {
		server.LastAgentTokenRefresh = &lastAgentTokenRefresh.Time
	}
	return &server, nil
}

// 创建一个新的远程服务器。
func (r *TrafficRepository) CreateRemoteServer(ctx context.Context, server *RemoteServer) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if server == nil {
		return errors.New("remote server is required")
	}

	server.Name = strings.TrimSpace(server.Name)
	if server.Name == "" {
		return errors.New("remote server name is required")
	}
	var existingID int64
	if err := r.db.QueryRowContext(ctx, `SELECT id FROM remote_servers WHERE name = ? LIMIT 1`, server.Name).Scan(&existingID); err == nil {
		return ErrRemoteServerExists
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check remote server name: %w", err)
	}

	server.Token = strings.TrimSpace(server.Token)
	if server.Token == "" {
		return errors.New("remote server token is required")
	}

	if server.Status == "" {
		server.Status = RemoteServerStatusPending
	}

	// 设置默认连接模式
	if server.ConnectionMode == "" {
		server.ConnectionMode = ConnectionModePush
	}

	// 将令牌有效期设置为从现在起 7 天
	tokenExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	const stmt = `INSERT INTO remote_servers (name, token, status, ip_address, ip_address_v6, ipv6_enabled, domain, token_expires_at, last_token_refresh, connection_mode, listen_port, pull_address, pull_port, pull_token, use_443, steal_self, steal_mode, nginx_mode, site_type, site_value, xray_mode, traffic_limit, traffic_used_offset, traffic_reset_day, traffic_stats_mode, traffic_source, ddns_enabled, ddns_provider_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`

	stealMode := server.StealMode
	if stealMode == "" {
		// 历史默认 "tunnel" 改为 "default" — 没显式选 tunnel/fallback 的就是"默认部署模式",
		// 跟 handler 那里的默认保持一致
		stealMode = "default"
	}
	nginxMode := strings.TrimSpace(server.NginxMode)
	if nginxMode != "reuse_existing" {
		nginxMode = "managed"
	}
	xrayMode := server.XrayMode
	if xrayMode == "" {
		xrayMode = "external"
	}
	statsMode := strings.TrimSpace(server.TrafficStatsMode)
	if statsMode != "upload" && statsMode != "download" {
		statsMode = "both"
	}
	trafficSource := strings.TrimSpace(server.TrafficSource)
	if trafficSource != "system" {
		trafficSource = "xray"
	}
	ddnsEnabledInt := 0
	if server.DDNSEnabled {
		ddnsEnabledInt = 1
	}
	result, err := r.db.ExecContext(ctx, stmt, server.Name, server.Token, server.Status, server.IPAddress, server.IPAddressV6, server.IPv6Enabled, server.Domain, tokenExpiresAt, server.ConnectionMode, server.ListenPort, server.PullAddress, server.PullPort, server.PullToken, server.Use443, server.StealSelf, stealMode, nginxMode, server.SiteType, server.SiteValue, xrayMode, server.TrafficLimit, server.TrafficUsedOffset, server.TrafficResetDay, statsMode, trafficSource, ddnsEnabledInt, server.DDNSProviderID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrRemoteServerExists
		}
		return fmt.Errorf("create remote server: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	server.ID = id
	server.TokenExpiresAt = &tokenExpiresAt
	return nil
}

// HeartbeatUpdate 包含用于更新远程服务器心跳的数据。
type HeartbeatUpdate struct {
	Token             string
	IPAddress         string
	IPAddressV6       string // dual-stack v6,可空(老 agent 不发)
	BootTime          *time.Time
	XrayBootTime      *time.Time
	ListenPort        int
	TimeOffsetSeconds *int64
}

// HeartbeatResult 包含心跳更新的结果，包括重新启动检测。
type HeartbeatResult struct {
	ServerID           int64
	ServerName         string
	PreviousStatus     string
	RelayDockRestarted bool
	XrayRestarted      bool
	BootCount          int
	XrayBootCount      int
	TokenExpiresSoon   bool
	TokenExpiresAt     *time.Time
	// IPChanged:本次心跳让 ip_address 或 ip_address_v6 字段发生变化。调用方据此触发 RefreshNodesServerAddress
	// 同步已存在节点的 clash_config.server,避免小鸡换 IP 后旧节点配置还是旧 IP。
	IPChanged bool
	// Server:UPDATE 后的最新 RemoteServer(IP/PullAddress 已应用 update)。
	// IPChanged=true 时非 nil;调用方拿它喂给 chooseClashServerHost 算最新的 effective host。
	Server *RemoteServer
}

// UpdateRemoteServerWarpInstalled 单独同步 warp_installed 字段(auth/heartbeat 上报后调)。
// 跟主 heartbeat UPDATE 分开是为了不破坏 UpdateRemoteServerHeartbeat 签名,所有老调用方继续工作。
// 老 agent 不上报 warp_installed → handler 不调本方法 → db 保留旧值(默认 0 / 上次值)。
func (r *TrafficRepository) UpdateRemoteServerWarpInstalled(ctx context.Context, token string, installed bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("remote server token is required")
	}
	installedInt := 0
	if installed {
		installedInt = 1
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE remote_servers SET warp_installed = ?, updated_at = CURRENT_TIMESTAMP WHERE token = ?`,
		installedInt, token)
	return err
}

// 更新远程服务器的检测信号和状态。
// ipAddressV6 为空时保留 db 现有值(老 agent 兼容)。
// 返回 (ipChanged, latestServer, err):IP 漂移时 ipChanged=true + latestServer 是 UPDATE 后状态,
// 调用方据此触发 RefreshNodesServerAddress 同步节点 clash_config.server。
func (r *TrafficRepository) UpdateRemoteServerHeartbeat(ctx context.Context, token string, ipAddress string, ipAddressV6 string) (bool, *RemoteServer, error) {
	if r == nil || r.db == nil {
		return false, nil, errors.New("traffic repository not initialized")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return false, nil, errors.New("remote server token is required")
	}

	// 拿 UPDATE 前的 server 状态,用于 IP 漂移检测
	server, err := r.GetRemoteServerByToken(ctx, token)
	if err != nil {
		return false, nil, err
	}

	// 空 ipAddress / ipAddressV6 都不覆盖 db 旧值 — 老 agent + v4-only / v6-only 网络抖动场景下,
	// agent 端 detectPublicIPv4 偶发失败上报空字段时,保留上次正确的 v4/v6 值,避免 master 反向连接断链。
	const stmt = `UPDATE remote_servers SET
		status = ?,
		last_heartbeat = CURRENT_TIMESTAMP,
		ip_address = COALESCE(NULLIF(?, ''), ip_address),
		ip_address_v6 = COALESCE(NULLIF(?, ''), ip_address_v6),
		offline_since = NULL,
		offline_notified = 0,
		updated_at = CURRENT_TIMESTAMP
		WHERE token = ?`

	res, err := r.db.ExecContext(ctx, stmt, RemoteServerStatusConnected, ipAddress, ipAddressV6, token)
	if err != nil {
		return false, nil, fmt.Errorf("update remote server heartbeat: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, nil, fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return false, nil, ErrRemoteServerNotFound
	}

	v4Changed := ipAddress != "" && ipAddress != server.IPAddress
	v6Changed := ipAddressV6 != "" && ipAddressV6 != server.IPAddressV6
	if v4Changed || v6Changed {
		latest := *server
		if v4Changed {
			latest.IPAddress = ipAddress
		}
		if v6Changed {
			latest.IPAddressV6 = ipAddressV6
		}
		return true, &latest, nil
	}
	return false, nil, nil
}

// MarkRemoteServerOfflineByID 立即把指定服务器标记为离线(不等 60s 心跳超时)。
// 返回 (prevStatus, name, ip, err);如果 prev == connected 才算"真的下线",调用方据此决定要不要发通知。
// 用途:WS 断开时立刻下推下线状态(不然要等 traffic collector 下一轮才检测,可能 60s+)。
func (r *TrafficRepository) MarkRemoteServerOfflineByID(ctx context.Context, serverID int64) (string, string, string, error) {
	if r == nil || r.db == nil {
		return "", "", "", errors.New("traffic repository not initialized")
	}
	var prevStatus, name, ip string
	checkStmt := `SELECT name, status, COALESCE(ip_address, '') FROM remote_servers WHERE id = ?`
	if err := r.db.QueryRowContext(ctx, checkStmt, serverID).Scan(&name, &prevStatus, &ip); err != nil {
		return "", "", "", fmt.Errorf("check server status: %w", err)
	}
	if prevStatus != RemoteServerStatusConnected {
		// 已经不是 connected 就不动 — 避免重复发下线通知(比如已经被 collector 标过了)
		return prevStatus, name, ip, nil
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE remote_servers SET status = ?, offline_since = CURRENT_TIMESTAMP, offline_notified = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = ?`,
		RemoteServerStatusOffline, serverID, RemoteServerStatusConnected,
	)
	if err != nil {
		return prevStatus, name, ip, fmt.Errorf("mark server offline: %w", err)
	}
	return prevStatus, name, ip, nil
}

// UpdateRemoteServerLastActivity 通过服务器 ID 更新 last_heartbeat。
// 当收到流量数据时会调用此方法，从而无需单独的心跳。
// 返回 (prevStatus, serverName, ipAddress, prevOfflineNotified, err);调用方比对 prev 决定要不要发上线通知
// (容忍阈值下:只有 prevOfflineNotified=1,即下线通知已发过,恢复时才补发上线通知)。
func (r *TrafficRepository) UpdateRemoteServerLastActivity(ctx context.Context, serverID int64) (string, string, string, bool, error) {
	if r == nil || r.db == nil {
		return "", "", "", false, errors.New("traffic repository not initialized")
	}

	// 首先检查当前状态以记录状态更改
	var currentStatus, serverName, ipAddress string
	var prevOfflineNotified bool
	checkStmt := `SELECT name, status, COALESCE(ip_address, ''), COALESCE(offline_notified, 0) FROM remote_servers WHERE id = ?`
	if err := r.db.QueryRowContext(ctx, checkStmt, serverID).Scan(&serverName, &currentStatus, &ipAddress, &prevOfflineNotified); err == nil {
		if currentStatus == RemoteServerStatusOffline {
			log.Printf("[Online Detection] Server %s (ID=%d) status changing: OFFLINE -> CONNECTED (received traffic data)",
				serverName, serverID)
		}
	}

	const stmt = `UPDATE remote_servers SET status = ?, last_heartbeat = CURRENT_TIMESTAMP, offline_since = NULL, offline_notified = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?`

	_, err := r.db.ExecContext(ctx, stmt, RemoteServerStatusConnected, serverID)
	if err != nil {
		return currentStatus, serverName, ipAddress, prevOfflineNotified, fmt.Errorf("update remote server last activity: %w", err)
	}

	return currentStatus, serverName, ipAddress, prevOfflineNotified, nil
}

// UpdateRemoteServerHeartbeatWithRestart 通过重新启动检测来更新心跳。
// 返回 HeartbeatResult 指示 RelayDock Agent 或 Xray 是否已重新启动。
func (r *TrafficRepository) UpdateRemoteServerHeartbeatWithRestart(ctx context.Context, update HeartbeatUpdate) (*HeartbeatResult, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	token := strings.TrimSpace(update.Token)
	if token == "" {
		return nil, errors.New("remote server token is required")
	}

	// 获取当前服务器状态
	server, err := r.GetRemoteServerByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	reportedListenPort := update.ListenPort
	if !IsValidRemoteManagementListenPort(reportedListenPort) {
		return nil, fmt.Errorf("invalid Agent listen port %d", reportedListenPort)
	}
	effectiveListenPort := server.ListenPort
	if effectiveListenPort <= 0 {
		effectiveListenPort = reportedListenPort
	} else if reportedListenPort > 0 && reportedListenPort != effectiveListenPort {
		return nil, fmt.Errorf("%w: reported %d, provisioned %d", ErrRemoteListenPortMismatch, reportedListenPort, effectiveListenPort)
	}

	result := &HeartbeatResult{
		ServerID:       server.ID,
		ServerName:     server.Name,
		PreviousStatus: server.Status,
		BootCount:      server.BootCount,
		XrayBootCount:  server.XrayBootCount,
	}

	// 检测 RelayDock Agent 重启。
	if update.BootTime != nil {
		if server.BootTime != nil && !update.BootTime.Equal(*server.BootTime) {
			result.RelayDockRestarted = true
			result.BootCount++
		}
	}

	// 检测 X 射线重启
	if update.XrayBootTime != nil {
		if server.XrayBootTime != nil && !update.XrayBootTime.Equal(*server.XrayBootTime) {
			result.XrayRestarted = true
			result.XrayBootCount++
		}
	}

	// 检查令牌过期（如果在 24 小时内过期则发出警告）
	if server.TokenExpiresAt != nil {
		result.TokenExpiresAt = server.TokenExpiresAt
		if time.Until(*server.TokenExpiresAt) < 24*time.Hour {
			result.TokenExpiresSoon = true
		}
	}

	// 确定 pull_address：如果为空或与旧 ip_​​address 相同，则与 ip_address 同步
	pullAddress := server.PullAddress
	if pullAddress == "" || pullAddress == server.IPAddress {
		pullAddress = update.IPAddress
	}

	// 更新服务器记录。ip_address / ip_address_v6 都用 COALESCE(NULLIF(?, ''), 旧值):
	// agent 字段为空(detect 失败 / 老 agent 不发) → 保留 db 旧值,不覆盖。
	// 防止 agent 端 detectPublicIPv4 偶发失败(空字段)导致 db 里上一次正确的 v4 被清空。
	const stmt = `UPDATE remote_servers SET
		status = ?,
		last_heartbeat = CURRENT_TIMESTAMP,
		ip_address = COALESCE(NULLIF(?, ''), ip_address),
		ip_address_v6 = COALESCE(NULLIF(?, ''), ip_address_v6),
		boot_time = ?,
		xray_boot_time = ?,
		boot_count = ?,
		xray_boot_count = ?,
		listen_port = ?,
		pull_address = ?,
		time_offset_seconds = ?,
		offline_since = NULL,
		offline_notified = 0,
		updated_at = CURRENT_TIMESTAMP
		WHERE token = ?`

	_, err = r.db.ExecContext(ctx, stmt,
		RemoteServerStatusConnected,
		update.IPAddress,
		update.IPAddressV6,
		update.BootTime,
		update.XrayBootTime,
		result.BootCount,
		result.XrayBootCount,
		effectiveListenPort,
		pullAddress,
		update.TimeOffsetSeconds,
		token)
	if err != nil {
		return nil, fmt.Errorf("update remote server heartbeat: %w", err)
	}

	// 检测 IP 漂移并把 UPDATE 后的最新 server 塞进 result,
	// 由 handler 层据此触发 RefreshNodesServerAddress 同步已存在节点的 clash_config.server。
	// COALESCE(NULLIF) 模式下:update.IP 为空时 DB 不动 → 视为「未变化」;非空且跟旧值不同才算「漂移」
	v4Changed := update.IPAddress != "" && update.IPAddress != server.IPAddress
	v6Changed := update.IPAddressV6 != "" && update.IPAddressV6 != server.IPAddressV6
	if v4Changed || v6Changed {
		latest := *server
		if v4Changed {
			latest.IPAddress = update.IPAddress
		}
		if v6Changed {
			latest.IPAddressV6 = update.IPAddressV6
		}
		latest.ListenPort = effectiveListenPort
		latest.PullAddress = pullAddress
		result.IPChanged = true
		result.Server = &latest
	}

	return result, nil
}

// RefreshRemoteServerToken 为远程服务器生成新令牌。
// 如果成功则返回新令牌。
func (r *TrafficRepository) RefreshRemoteServerToken(ctx context.Context, oldToken string) (string, *time.Time, error) {
	if r == nil || r.db == nil {
		return "", nil, errors.New("traffic repository not initialized")
	}

	oldToken = strings.TrimSpace(oldToken)
	if oldToken == "" {
		return "", nil, errors.New("remote server token is required")
	}

	// 验证旧令牌是否存在并检查是否允许刷新
	server, err := r.GetRemoteServerByToken(ctx, oldToken)
	if err != nil {
		return "", nil, err
	}

	// 检查token是否可以刷新（必须是过期24小时内或者已经过期）
	if server.TokenExpiresAt != nil {
		timeUntilExpiry := time.Until(*server.TokenExpiresAt)
		if timeUntilExpiry > 24*time.Hour {
			return "", nil, errors.New("token can only be refreshed within 24 hours of expiration")
		}
	}

	// 生成新令牌
	newToken := uuid.New().String()
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	const stmt = `UPDATE remote_servers SET
		token = ?,
		token_expires_at = ?,
		last_token_refresh = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	result, err := r.db.ExecContext(ctx, stmt, newToken, newExpiresAt, server.ID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return "", nil, errors.New("failed to generate unique token, please try again")
		}
		return "", nil, fmt.Errorf("refresh remote server token: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return "", nil, fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return "", nil, ErrRemoteServerNotFound
	}

	return newToken, &newExpiresAt, nil
}

// ResetServerToken 强制重置服务器令牌（代理用于推送到服务器）。
// 无论令牌是否过期，管理员都可以随时调用它。
func (r *TrafficRepository) ResetServerToken(ctx context.Context, serverID int64) (string, *time.Time, error) {
	if r == nil || r.db == nil {
		return "", nil, errors.New("traffic repository not initialized")
	}

	if serverID <= 0 {
		return "", nil, errors.New("remote server id is required")
	}

	// 生成新令牌
	newToken := uuid.New().String()
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	const stmt = `UPDATE remote_servers SET
		token = ?,
		token_expires_at = ?,
		last_token_refresh = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	result, err := r.db.ExecContext(ctx, stmt, newToken, newExpiresAt, serverID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return "", nil, errors.New("failed to generate unique token, please try again")
		}
		return "", nil, fmt.Errorf("reset server token: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return "", nil, fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return "", nil, ErrRemoteServerNotFound
	}

	return newToken, &newExpiresAt, nil
}

// ResetAgentToken 强制重置代理令牌（服务器使用该令牌从代理中提取）。
// 管理员可以随时调用此功能。
func (r *TrafficRepository) ResetAgentToken(ctx context.Context, serverID int64) (string, *time.Time, error) {
	if r == nil || r.db == nil {
		return "", nil, errors.New("traffic repository not initialized")
	}

	if serverID <= 0 {
		return "", nil, errors.New("remote server id is required")
	}

	// 生成新令牌
	newToken := uuid.New().String()
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	const stmt = `UPDATE remote_servers SET
		agent_token = ?,
		agent_token_expires_at = ?,
		last_agent_token_refresh = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	result, err := r.db.ExecContext(ctx, stmt, newToken, newExpiresAt, serverID)
	if err != nil {
		return "", nil, fmt.Errorf("reset agent token: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return "", nil, fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return "", nil, ErrRemoteServerNotFound
	}

	return newToken, &newExpiresAt, nil
}

// 强制重置服务器令牌和代理令牌。
func (r *TrafficRepository) ResetAllTokens(ctx context.Context, serverID int64) (serverToken string, serverTokenExpiresAt *time.Time, agentToken string, agentTokenExpiresAt *time.Time, err error) {
	if r == nil || r.db == nil {
		return "", nil, "", nil, errors.New("traffic repository not initialized")
	}

	if serverID <= 0 {
		return "", nil, "", nil, errors.New("remote server id is required")
	}

	// 生成新的代币
	newServerToken := uuid.New().String()
	newAgentToken := uuid.New().String()
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	const stmt = `UPDATE remote_servers SET
		token = ?,
		token_expires_at = ?,
		last_token_refresh = CURRENT_TIMESTAMP,
		agent_token = ?,
		agent_token_expires_at = ?,
		last_agent_token_refresh = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	result, err := r.db.ExecContext(ctx, stmt, newServerToken, newExpiresAt, newAgentToken, newExpiresAt, serverID)
	if err != nil {
		return "", nil, "", nil, fmt.Errorf("reset all tokens: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return "", nil, "", nil, fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return "", nil, "", nil, ErrRemoteServerNotFound
	}

	return newServerToken, &newExpiresAt, newAgentToken, &newExpiresAt, nil
}

// 更新远程服务器的配置（连接模式、拉取设置等）。
func (r *TrafficRepository) UpdateRemoteServerConfig(ctx context.Context, id int64, connectionMode, pullAddress string, pullPort int, pullToken string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("remote server id is required")
	}

	// 验证连接模式 — push/pull/websocket/auto 都合法。
	// 漏 "auto" 历史 bug:add server 路径写入 connection_mode='auto',update 时这里
	// 报"invalid connection mode",handler 吞错只 log → 前端看到 success 实际 pull_address 没更新。
	if connectionMode != "" && connectionMode != ConnectionModePush && connectionMode != ConnectionModePull && connectionMode != ConnectionModeWebSocket && connectionMode != ConnectionModeAuto {
		return errors.New("invalid connection mode")
	}

	const stmt = `UPDATE remote_servers SET connection_mode = ?, pull_address = ?, pull_port = ?, pull_token = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`

	result, err := r.db.ExecContext(ctx, stmt, connectionMode, pullAddress, pullPort, pullToken, id)
	if err != nil {
		return fmt.Errorf("update remote server config: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return ErrRemoteServerNotFound
	}

	return nil
}

// 更新远程服务器的上次拉取时间戳。
func (r *TrafficRepository) UpdateRemoteServerLastPull(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("remote server id is required")
	}

	const stmt = `UPDATE remote_servers SET last_pull_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`

	result, err := r.db.ExecContext(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("update remote server last pull: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return ErrRemoteServerNotFound
	}

	return nil
}

// 更新远程服务器的实时速度。
func (r *TrafficRepository) UpdateRemoteServerSpeed(ctx context.Context, id int64, uploadSpeed, downloadSpeed int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("remote server id is required")
	}

	const stmt = `UPDATE remote_servers SET current_upload_speed = ?, current_download_speed = ?, speed_updated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`

	result, err := r.db.ExecContext(ctx, stmt, uploadSpeed, downloadSpeed, id)
	if err != nil {
		return fmt.Errorf("update remote server speed: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return ErrRemoteServerNotFound
	}

	return nil
}

// 通过令牌更新远程服务器的实时速度。
func (r *TrafficRepository) UpdateRemoteServerSpeedByToken(ctx context.Context, token string, uploadSpeed, downloadSpeed int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if token == "" {
		return errors.New("token is required")
	}

	const stmt = `UPDATE remote_servers SET current_upload_speed = ?, current_download_speed = ?, speed_updated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE token = ?`

	result, err := r.db.ExecContext(ctx, stmt, uploadSpeed, downloadSpeed, token)
	if err != nil {
		return fmt.Errorf("update remote server speed by token: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return ErrRemoteServerNotFound
	}

	return nil
}

// 在扫描后更新 X 射线状态。
// UpdateRemoteServerXrayStatus 更新 xray 运行状态,并返回更新前的 xray_running 值,
// 供调用方比对变化(主控会在状态翻转时发 TG 通知)。
func (r *TrafficRepository) UpdateRemoteServerXrayStatus(ctx context.Context, id int64, running bool, version string) (prevRunning bool, err error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return false, errors.New("remote server id is required")
	}

	// 先读旧值用于判断状态翻转
	var prev int
	if scanErr := r.db.QueryRowContext(ctx, `SELECT COALESCE(xray_running, 0) FROM remote_servers WHERE id = ?`, id).Scan(&prev); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return false, ErrRemoteServerNotFound
		}
		return false, fmt.Errorf("read prev xray status: %w", scanErr)
	}

	runningVal := 0
	if running {
		runningVal = 1
	}

	const stmt = `UPDATE remote_servers SET xray_running = ?, xray_version = ?, xray_scanned_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`

	result, execErr := r.db.ExecContext(ctx, stmt, runningVal, version, id)
	if execErr != nil {
		return false, fmt.Errorf("update remote server xray status: %w", execErr)
	}

	affected, rErr := result.RowsAffected()
	if rErr != nil {
		return false, fmt.Errorf("get rows affected: %w", rErr)
	}

	if affected == 0 {
		return false, ErrRemoteServerNotFound
	}
	log.Printf("[Remote Server] Updated Xray status for server ID=%d: running=%v, version=%s", id, running, version)
	return prev != 0, nil
}

// UpdateRemoteServerListenPort updates the provisioned Agent port for initial
// migration/setup helpers. Runtime edits must reinstall the remote server.
func (r *TrafficRepository) UpdateRemoteServerListenPort(ctx context.Context, id int64, port int) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("remote server id is required")
	}
	if !IsValidRemoteManagementListenPort(port) {
		return errors.New("listen_port out of range")
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE remote_servers SET listen_port = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, port, id)
	if err != nil {
		return fmt.Errorf("update remote server listen_port: %w", err)
	}
	return nil
}

// UpdateRemoteServerXrayMode 仅更新 xray_mode 字段(联邦同步用,不动 name/domain 等)。mode 非 embedded/external 视为空,跳过。
func (r *TrafficRepository) UpdateRemoteServerXrayMode(ctx context.Context, id int64, mode string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("remote server id is required")
	}
	if mode != "embedded" && mode != "external" {
		return nil
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE remote_servers SET xray_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, mode, id)
	if err != nil {
		return fmt.Errorf("update remote server xray_mode: %w", err)
	}
	return nil
}

func (r *TrafficRepository) RemoteServerXrayBootstrapPending(ctx context.Context, id int64) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return false, errors.New("remote server id is required")
	}
	var pending int
	if err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(xray_bootstrap_pending, 0) FROM remote_servers WHERE id = ?`, id,
	).Scan(&pending); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrRemoteServerNotFound
		}
		return false, fmt.Errorf("read remote server Xray bootstrap state: %w", err)
	}
	return pending != 0, nil
}

func (r *TrafficRepository) SetRemoteServerXrayBootstrapPending(ctx context.Context, id int64, pending bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("remote server id is required")
	}
	value := 0
	if pending {
		value = 1
	}
	result, err := r.db.ExecContext(ctx,
		`UPDATE remote_servers SET xray_bootstrap_pending = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, value, id)
	if err != nil {
		return fmt.Errorf("update remote server Xray bootstrap state: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read remote server Xray bootstrap update result: %w", err)
	}
	if affected != 1 {
		return ErrRemoteServerNotFound
	}
	return nil
}

// IncrementRemoteServerPushFailCount 增加推送失败计数并记录时间。
// 如果失败计数超过阈值，它将触发回退到拉模式。
func (r *TrafficRepository) IncrementRemoteServerPushFailCount(ctx context.Context, id int64, failThreshold int) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return false, errors.New("remote server id is required")
	}

	// 首先，增加失败计数
	const updateStmt = `UPDATE remote_servers SET
		push_fail_count = push_fail_count + 1,
		last_push_fail = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	if _, err := r.db.ExecContext(ctx, updateStmt, id); err != nil {
		return false, fmt.Errorf("increment push fail count: %w", err)
	}

	// 检查我们是否应该后退
	var failCount int
	var fallbackToPull bool
	const selectStmt = `SELECT push_fail_count, fallback_to_pull FROM remote_servers WHERE id = ?`
	if err := r.db.QueryRowContext(ctx, selectStmt, id).Scan(&failCount, &fallbackToPull); err != nil {
		return false, fmt.Errorf("get push fail count: %w", err)
	}

	// 如果已经处于后备模式，则返回 true
	if fallbackToPull {
		return true, nil
	}

	// 检查阈值并在超出时触发回退
	if failCount >= failThreshold {
		const fallbackStmt = `UPDATE remote_servers SET
			fallback_to_pull = 1,
			fallback_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
			WHERE id = ?`
		if _, err := r.db.ExecContext(ctx, fallbackStmt, id); err != nil {
			return false, fmt.Errorf("set fallback to pull: %w", err)
		}
		return true, nil
	}

	return false, nil
}

// 在推送成功时重置推送失败计数。
func (r *TrafficRepository) ResetRemoteServerPushFailCount(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("remote server id is required")
	}

	const stmt = `UPDATE remote_servers SET
		push_fail_count = 0,
		fallback_to_pull = 0,
		fallback_at = NULL,
		updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	_, err := r.db.ExecContext(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("reset push fail count: %w", err)
	}

	return nil
}

// 根据连接模式和回退状态确定远程服务器是否应使用拉模式。
func (r *TrafficRepository) ShouldUsePullMode(server RemoteServer) bool {
	// 显式拉模式
	if server.ConnectionMode == ConnectionModePull {
		return true
	}
	// 触发回退的自动模式
	if server.ConnectionMode == ConnectionModeAuto && server.FallbackToPull {
		return true
	}
	// 默认推送/Websocket 模式，触发回退
	if server.FallbackToPull && server.PullAddress != "" && server.PullPort > 0 {
		return true
	}
	return false
}

// 更新远程服务器的基本信息（名称、域、流量设置、连接模式、Xray模式）。
func (r *TrafficRepository) UpdateRemoteServer(ctx context.Context, id int64, name, domain string, trafficLimit int64, trafficResetDay int, connectionMode, xrayMode, trafficStatsMode, trafficSource string, ipv6Enabled *bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("remote server id is required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("remote server name is required")
	}
	leasedCtx, release, err := r.AcquireRemoteServerMutationLease(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	ctx = leasedCtx

	var existingID int64
	if err := r.db.QueryRowContext(ctx, `SELECT id FROM remote_servers WHERE name = ? AND id != ? LIMIT 1`, name, id).Scan(&existingID); err == nil {
		return ErrRemoteServerExists
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check remote server name: %w", err)
	}

	// 动态构建 SET 子句
	setClauses := []string{"name = ?", "domain = ?", "traffic_limit = ?", "traffic_reset_day = ?"}
	args := []any{name, domain, trafficLimit, trafficResetDay}

	if connectionMode != "" {
		setClauses = append(setClauses, "connection_mode = ?")
		args = append(args, connectionMode)
	}
	if xrayMode != "" {
		setClauses = append(setClauses, "xray_mode = ?")
		args = append(args, xrayMode)
	}
	if mode := strings.TrimSpace(trafficStatsMode); mode == "both" || mode == "upload" || mode == "download" || mode == "max" {
		setClauses = append(setClauses, "traffic_stats_mode = ?")
		args = append(args, mode)
	}
	// 服务器流量统计源切换 — 默认 'xray' 保留向后兼容,切到 'system' 后 GetServerTrafficUsed 改读 system_*_cycle
	if src := strings.TrimSpace(trafficSource); src == "xray" || src == "system" {
		setClauses = append(setClauses, "traffic_source = ?")
		args = append(args, src)
	}
	// IPv6 启用开关:指针非 nil 才更新(前端编辑对话框切换时下发)
	if ipv6Enabled != nil {
		setClauses = append(setClauses, "ipv6_enabled = ?")
		args = append(args, *ipv6Enabled)
	}
	setClauses = append(setClauses, "updated_at = CURRENT_TIMESTAMP")
	args = append(args, id)

	stmt := `UPDATE remote_servers SET ` + strings.Join(setClauses, ", ") + ` WHERE id = ?`

	result, err := r.db.ExecContext(ctx, stmt, args...)
	if err != nil {
		return fmt.Errorf("update remote server: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if affected == 0 {
		return ErrRemoteServerNotFound
	}

	return nil
}

func (r *TrafficRepository) UpdateRemoteServerTrafficOffset(ctx context.Context, id int64, offset int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET traffic_used_offset = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, offset, id)
	if err != nil {
		return fmt.Errorf("update traffic_used_offset: %w", err)
	}
	return nil
}

// UpdateRemoteServerTrafficMeta 仅更新流量限额与重置日(联邦轮询透传拥有方的限额信息用)。
func (r *TrafficRepository) UpdateRemoteServerTrafficMeta(ctx context.Context, id int64, trafficLimit int64, trafficResetDay int) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET traffic_limit = ?, traffic_reset_day = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, trafficLimit, trafficResetDay, id)
	if err != nil {
		return fmt.Errorf("update traffic meta: %w", err)
	}
	return nil
}

func (r *TrafficRepository) UpdateRemoteServerStealMode(ctx context.Context, id int64, stealMode string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	stealSelf := stealMode == "tunnel" || stealMode == "fallback"
	result, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET steal_mode = ?, steal_self = ?, use_443 = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, stealMode, stealSelf, stealSelf, id)
	if err != nil {
		return fmt.Errorf("update steal_mode: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrRemoteServerNotFound
	}
	return nil
}

func (r *TrafficRepository) UpdateRemoteServerNginxMode(ctx context.Context, id int64, nginxMode string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	nginxMode = strings.TrimSpace(nginxMode)
	if nginxMode != "managed" && nginxMode != "reuse_existing" {
		return errors.New("invalid nginx mode")
	}
	result, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET nginx_mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, nginxMode, id)
	if err != nil {
		return fmt.Errorf("update nginx_mode: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrRemoteServerNotFound
	}
	return nil
}

func (r *TrafficRepository) DeleteNodesByOriginalServer(ctx context.Context, serverName string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM nodes WHERE original_server = ?`, serverName)
	if err != nil {
		return 0, fmt.Errorf("delete nodes by original_server: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}

// 通过 ID 删除远程服务器。
// ReorderRemoteServers 按给定顺序写 sort_order(单调递增,从 10、20、30… 起步,留间隙便于以后单点插入)。
// ids 里没有给到的服务器维持当前 sort_order,会自然排到列表后面。
func (r *TrafficRepository) ReorderRemoteServers(ctx context.Context, ids []int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if len(ids) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `UPDATE remote_servers SET sort_order = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("prepare reorder: %w", err)
	}
	defer stmt.Close()
	for i, id := range ids {
		if _, err := stmt.ExecContext(ctx, (i+1)*10, id); err != nil {
			return fmt.Errorf("reorder id=%d: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reorder: %w", err)
	}
	return nil
}

type remoteServerDeletionQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validateRemoteServerDeletion(ctx context.Context, querier remoteServerDeletionQuerier, id int64) (string, error) {
	var name string
	switch err := querier.QueryRowContext(ctx, `SELECT name FROM remote_servers WHERE id = ?`, id).Scan(&name); err {
	case nil:
		// ok
	case sql.ErrNoRows:
		return "", ErrRemoteServerNotFound
	default:
		return "", fmt.Errorf("lookup remote server: %w", err)
	}

	var sameNameCount int
	if err := querier.QueryRowContext(ctx, `SELECT COUNT(*) FROM remote_servers WHERE name = ?`, name).Scan(&sameNameCount); err != nil {
		return "", fmt.Errorf("count same-name remote servers: %w", err)
	}
	if sameNameCount > 1 {
		return "", errors.New("duplicate remote server name; rename servers before deletion")
	}

	// Forwarding routes own durable resources on the server. Removing the
	// server record while any reference remains would orphan those resources.
	var forwardingReferenced int
	if err := querier.QueryRowContext(ctx, `SELECT EXISTS(
	    SELECT 1 FROM tunnel_template_hops WHERE server_id = ?
	    UNION ALL
	    SELECT 1 FROM user_forward_hops WHERE server_id = ?
	    UNION ALL
	    SELECT 1 FROM server_port_allocations WHERE server_id = ?
	)`, id, id, id).Scan(&forwardingReferenced); err != nil {
		return "", fmt.Errorf("check forwarding server references: %w", err)
	}
	if forwardingReferenced != 0 {
		return "", ErrForwardingConflict
	}
	return name, nil
}

// ValidateRemoteServerDeletion checks every durable constraint used by
// DeleteRemoteServer without changing data. Callers that perform remote side
// effects must hold an exclusive server mutation lease across this preflight,
// the remote operation, and the final DeleteRemoteServer call.
func (r *TrafficRepository) ValidateRemoteServerDeletion(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("remote server id is required")
	}

	leasedCtx, release, err := r.AcquireRemoteServerMutationLease(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	_, err = validateRemoteServerDeletion(leasedCtx, r.db, id)
	return err
}

func (r *TrafficRepository) DeleteRemoteServer(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if id <= 0 {
		return errors.New("remote server id is required")
	}
	leasedCtx, release, err := r.AcquireRemoteServerMutationLease(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	ctx = leasedCtx

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete-server tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit 成功后 rollback 为 no-op

	// Re-check inside the delete transaction. A compound remote-uninstall flow
	// runs the same validation before touching the Agent, but the final database
	// mutation must remain independently safe for every caller.
	name, err := validateRemoteServerDeletion(ctx, tx, id)
	if err != nil {
		return err
	}

	// 1) 用户子账户:按 routed_node_id 关联,经 nodes.original_server 反查该服务器的(routed)节点。必须在删 nodes 之前。
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM user_subaccounts WHERE routed_node_id IN (SELECT id FROM nodes WHERE original_server = ?)`, name); err != nil {
		return fmt.Errorf("delete user_subaccounts: %w", err)
	}
	// 节点测速与自助节点授权同样引用即将删除的 node/offer/grant。SQLite
	// 历史库不一定启用了外键，按依赖顺序显式清理，避免留下不可见的授权和统计。
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM speed_test_results WHERE node_id IN (SELECT id FROM nodes WHERE original_server = ?)`, name); err != nil {
		return fmt.Errorf("delete speed_test_results: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_node_selection_usage WHERE selection_id IN (
		SELECT id FROM user_node_selections WHERE
		grant_id IN (SELECT id FROM user_server_grants WHERE server_id = ?)
		OR offer_id IN (SELECT id FROM self_service_node_offers WHERE server_id = ?)
	)`, id, id); err != nil {
		return fmt.Errorf("delete user_node_selection_usage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_node_selections WHERE
		grant_id IN (SELECT id FROM user_server_grants WHERE server_id = ?)
		OR offer_id IN (SELECT id FROM self_service_node_offers WHERE server_id = ?)`, id, id); err != nil {
		return fmt.Errorf("delete user_node_selections: %w", err)
	}
	// 2) 该服务器入站同步出来的所有节点(普通 + routed),按 original_server 名字。
	if _, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE original_server = ?`, name); err != nil {
		return fmt.Errorf("delete nodes: %w", err)
	}
	// 3) server_id 关联的数据:活跃运营(凭据/出站/xray 快照/批量记录/到期通知 flag)+ 历史流量统计。
	//    服务器删除后这些全是孤儿,一并清掉。表名为内部常量,非用户输入,无注入风险。
	//    注:证书(certificates.remote_server_id)按用户要求保留不动;dns_providers / custom_rules 为全局可复用资源,不在此列。
	for _, table := range []string{
		// 活跃运营配置
		"remote_server_installations",
		"remote_server_install_tickets",
		"user_inbound_configs",
		"user_outbounds",
		"server_xray_config_snapshots",
		"batch_inbounds",
		"batch_outbounds",
		"traffic_threshold_notified",
		// 历史流量统计
		"node_traffic",
		"user_traffic",
		"user_email_traffic",
		"traffic_snapshots",
		"node_traffic_snapshots",
		"user_traffic_snapshots",
		"user_email_traffic_snapshots",
		"server_system_traffic_snapshots",
		"line_speedtest_results",
		// 自助节点与管理侧资源
		"self_service_node_offers",
		"user_server_grants",
		"user_inbound_access_sources",
		"managed_inbound_resources",
		"managed_access_audit",
		"remote_server_guard_secrets",
		"shared_servers",
		"federated_servers",
		// 删除任务最后清理；若事务失败，已确认的 Agent 状态仍可重试。
		"remote_server_deletion_tasks",
	} {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE server_id = ?`, table), id); err != nil {
			return fmt.Errorf("delete %s: %w", table, err)
		}
	}
	// 4) 服务器行本身。
	res, err := tx.ExecContext(ctx, `DELETE FROM remote_servers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete remote server: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete-server tx: %w", err)
	}

	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrRemoteServerNotFound
	}
	return nil
}

type OfflineServerInfo struct {
	ID   int64
	Name string
	IP   string
}

// 如果服务器在给定时间内未发送心跳，MarkOfflineRemoteServers 会将服务器标记为离线。
func (r *TrafficRepository) MarkOfflineRemoteServers(ctx context.Context, timeout time.Duration) ([]OfflineServerInfo, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	// 使用 UTC 时间进行比较，因为 SQLite CURRENT_TIMESTAMP 存储的是 UTC 时间
	cutoff := time.Now().UTC().Add(-timeout)

	// 首先，查询哪些服务器将被标记为离线以进行日志记录
	queryStmt := `SELECT id, name, COALESCE(ip_address, ''), last_heartbeat FROM remote_servers WHERE status = ? AND last_heartbeat < ?`
	rows, err := r.db.QueryContext(ctx, queryStmt, RemoteServerStatusConnected, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query servers to mark offline: %w", err)
	}
	defer rows.Close()

	var serversToMarkOffline []struct {
		ID            int64
		Name          string
		IP            string
		LastHeartbeat time.Time
	}
	for rows.Next() {
		var s struct {
			ID            int64
			Name          string
			IP            string
			LastHeartbeat time.Time
		}
		if err := rows.Scan(&s.ID, &s.Name, &s.IP, &s.LastHeartbeat); err != nil {
			continue
		}
		serversToMarkOffline = append(serversToMarkOffline, s)
	}

	// 记录哪些服务器将被标记为离线
	for _, s := range serversToMarkOffline {
		// 使用 UTC 时间计算时间差，因为 LastHeartbeat 是 UTC 时间
		sinceLast := time.Now().UTC().Sub(s.LastHeartbeat)
		log.Printf("[Offline Detection] Marking server %s (ID=%d) as OFFLINE: last_heartbeat was %v ago (threshold: %v)",
			s.Name, s.ID, sinceLast.Round(time.Second), timeout)
	}

	// 现在执行更新
	const stmt = `UPDATE remote_servers SET status = ?, offline_since = CURRENT_TIMESTAMP, offline_notified = 0, updated_at = CURRENT_TIMESTAMP WHERE status = ? AND last_heartbeat < ?`

	result, err := r.db.ExecContext(ctx, stmt, RemoteServerStatusOffline, RemoteServerStatusConnected, cutoff)
	if err != nil {
		return nil, fmt.Errorf("mark offline remote servers: %w", err)
	}

	var offlineServers []OfflineServerInfo
	if affected, _ := result.RowsAffected(); affected > 0 {
		log.Printf("[Offline Detection] Marked %d server(s) as offline", affected)
		for _, s := range serversToMarkOffline {
			offlineServers = append(offlineServers, OfflineServerInfo{ID: s.ID, Name: s.Name, IP: s.IP})
		}
	}

	return offlineServers, nil
}

// TakeOfflineServersToNotify 取出"离线已满容忍阈值 tolerance、且本次离线周期尚未发过下线通知"的服务器,
// 原子地把它们标记为 offline_notified=1 并返回(供 collector 发下线通知)。
// 这是"容忍阈值"防抖的核心:离线后要持续离线满 tolerance 才通知 —— 阈值内又上线的(抖动/主控重启后 agent
// 快速重连)其 offline_since 已被清空,永远走不到这里,故一条通知都不发。tolerance<=0 时 cutoff=now,
// 相当于"下一轮 collector tick 即发"(接近即时)。
func (r *TrafficRepository) TakeOfflineServersToNotify(ctx context.Context, tolerance time.Duration) ([]OfflineServerInfo, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if tolerance < 0 {
		tolerance = 0
	}
	cutoff := time.Now().UTC().Add(-tolerance)

	const q = `SELECT id, name, COALESCE(ip_address, '') FROM remote_servers
		WHERE status = ? AND offline_notified = 0 AND offline_since IS NOT NULL AND offline_since <= ?`
	rows, err := r.db.QueryContext(ctx, q, RemoteServerStatusOffline, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query offline servers to notify: %w", err)
	}
	var list []OfflineServerInfo
	for rows.Next() {
		var s OfflineServerInfo
		if err := rows.Scan(&s.ID, &s.Name, &s.IP); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan offline server to notify: %w", err)
		}
		list = append(list, s)
	}
	rows.Close()
	if len(list) == 0 {
		return nil, nil
	}

	// 标记为已通知,避免下轮重复发。用同一 cutoff + 同一 WHERE,只会命中上面选出的那批。
	const upd = `UPDATE remote_servers SET offline_notified = 1, updated_at = CURRENT_TIMESTAMP
		WHERE status = ? AND offline_notified = 0 AND offline_since IS NOT NULL AND offline_since <= ?`
	if _, err := r.db.ExecContext(ctx, upd, RemoteServerStatusOffline, cutoff); err != nil {
		return nil, fmt.Errorf("mark offline_notified: %w", err)
	}
	return list, nil
}

// ==================== 节点流量 CRUD ====================

// UpsertNodeTraffic 通过重新启动检测来更新或插入节点流量。
// 如果当前值小于上次值，则意味着 Xray 已重新启动，
// 所以我们在更新之前将最后的值累加到总计。
func (r *TrafficRepository) UpsertNodeTraffic(ctx context.Context, serverID int64, tag, trafficType string, uplink, downlink int64, isXrayRestarted bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if serverID <= 0 {
		return errors.New("server id is required")
	}
	if tag == "" {
		return errors.New("tag is required")
	}
	if trafficType != "inbound" && trafficType != "outbound" {
		return errors.New("type must be 'inbound' or 'outbound'")
	}

	// 首先，尝试获取现有记录
	var existing NodeTraffic
	var exists bool
	row := r.db.QueryRowContext(ctx, `SELECT id, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink FROM node_traffic WHERE server_id = ? AND tag = ? AND type = ?`, serverID, tag, trafficType)
	err := row.Scan(&existing.ID, &existing.Uplink, &existing.Downlink, &existing.TotalUplink, &existing.TotalDownlink, &existing.LastUplink, &existing.LastDownlink)
	if err == nil {
		exists = true
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("query existing node traffic: %w", err)
	}

	if !exists {
		// 首次见到 (server, tag, type):把当前 raw 仅作为 baseline(写入 last_*),
		// uplink/downlink/total_* 都从 0 起步。**不能**把 raw 写入累计字段 —— xray 已有的历史累计
		// 会被当成"本次见到的新增 delta"一次性灌进当天的 traffic_records.total_used,
		// 前端每日流量图就在那一天爆出来一条尖刺(用户报的"重启后某天数据错误")。
		// 触发场景:新增远程服务器、新加 inbound tag、node_traffic 表被清/迁移后等。
		const insertStmt = `INSERT INTO node_traffic (server_id, tag, type, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, updated_at) VALUES (?, ?, ?, 0, 0, 0, 0, ?, ?, CURRENT_TIMESTAMP)`
		_, err := r.db.ExecContext(ctx, insertStmt, serverID, tag, trafficType, uplink, downlink)
		if err != nil {
			return fmt.Errorf("insert node traffic: %w", err)
		}
		return nil
	}

	// 重启判定权威来自 isXrayRestarted(由 collector 用 xray_boot_time 判断),不再用 new<last 启发式。
	// 历史 BUG:启发式把 inbound client 增删导致的 user counter reset 误判为 xray 重启 →
	// total_* 渐进累积(user_email_traffic 591MB vs node_traffic 209MB 的 382MB 差额)。
	var deltaUplink, deltaDownlink int64
	var newTotalUplink, newTotalDownlink int64

	if isXrayRestarted {
		// Xray 真重启 — 把上次 cumulative 归档到 total,delta 用新 cumulative 起算。
		log.Printf("[Traffic] Xray restart for server %d, %s tag %s: uplink %d -> %d, downlink %d -> %d (accumulating to total)",
			serverID, trafficType, tag, existing.LastUplink, uplink, existing.LastDownlink, downlink)
		newTotalUplink = existing.TotalUplink + existing.LastUplink
		newTotalDownlink = existing.TotalDownlink + existing.LastDownlink
		deltaUplink = uplink
		deltaDownlink = downlink
	} else {
		// 非 xray 重启 — counter 任何下降都视为 client 被删/重加(非真重启),不污染 total。
		// delta 用 max(0, new - last),避免负数 / cumulative 倒退被错误累加。
		if uplink >= existing.LastUplink {
			deltaUplink = uplink - existing.LastUplink
		} else {
			deltaUplink = 0
		}
		if downlink >= existing.LastDownlink {
			deltaDownlink = downlink - existing.LastDownlink
		} else {
			deltaDownlink = 0
		}
		newTotalUplink = existing.TotalUplink
		newTotalDownlink = existing.TotalDownlink
	}

	// 更新记录
	const updateStmt = `UPDATE node_traffic SET uplink = uplink + ?, downlink = downlink + ?, total_uplink = ?, total_downlink = ?, last_uplink = ?, last_downlink = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err = r.db.ExecContext(ctx, updateStmt, deltaUplink, deltaDownlink, newTotalUplink, newTotalDownlink, uplink, downlink, existing.ID)
	if err != nil {
		return fmt.Errorf("update node traffic: %w", err)
	}

	return nil
}

// 返回服务器的所有节点流量记录。
func (r *TrafficRepository) GetNodeTrafficByServer(ctx context.Context, serverID int64) ([]NodeTraffic, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const query = `SELECT id, server_id, tag, type, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, updated_at FROM node_traffic WHERE server_id = ? ORDER BY type, tag`
	rows, err := r.db.QueryContext(ctx, query, serverID)
	if err != nil {
		return nil, fmt.Errorf("query node traffic: %w", err)
	}
	defer rows.Close()

	var results []NodeTraffic
	for rows.Next() {
		var t NodeTraffic
		if err := rows.Scan(&t.ID, &t.ServerID, &t.Tag, &t.Type, &t.Uplink, &t.Downlink, &t.TotalUplink, &t.TotalDownlink, &t.LastUplink, &t.LastDownlink, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan node traffic: %w", err)
		}
		results = append(results, t)
	}

	return results, nil
}

// 返回所有节点流量记录。
func (r *TrafficRepository) GetAllNodeTraffic(ctx context.Context) ([]NodeTraffic, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const query = `SELECT id, server_id, tag, type, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, updated_at FROM node_traffic ORDER BY server_id, type, tag`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query all node traffic: %w", err)
	}
	defer rows.Close()

	var results []NodeTraffic
	for rows.Next() {
		var t NodeTraffic
		if err := rows.Scan(&t.ID, &t.ServerID, &t.Tag, &t.Type, &t.Uplink, &t.Downlink, &t.TotalUplink, &t.TotalDownlink, &t.LastUplink, &t.LastDownlink, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan node traffic: %w", err)
		}
		results = append(results, t)
	}

	return results, nil
}

// ==================== 用户流量CRUD ====================

type trafficReadWriter interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// 通过重新启动检测来更新或插入用户流量。
func (r *TrafficRepository) UpsertUserTraffic(ctx context.Context, serverID int64, username string, uplink, downlink int64, isXrayRestarted bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if serverID <= 0 {
		return errors.New("server id is required")
	}
	if username == "" {
		return errors.New("username is required")
	}
	return upsertUserTraffic(ctx, r.db, serverID, username, uplink, downlink, isXrayRestarted)
}

func upsertUserTraffic(ctx context.Context, q trafficReadWriter, serverID int64, username string, uplink, downlink int64, isXrayRestarted bool) error {
	// 首先，尝试获取现有记录
	var existing UserTraffic
	var exists bool
	row := q.QueryRowContext(ctx, `SELECT id, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink FROM user_traffic WHERE server_id = ? AND username = ?`, serverID, username)
	err := row.Scan(&existing.ID, &existing.Uplink, &existing.Downlink, &existing.TotalUplink, &existing.TotalDownlink, &existing.LastUplink, &existing.LastDownlink)
	if err == nil {
		exists = true
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("query existing user traffic: %w", err)
	}

	if !exists {
		// 首次见到 (server, username):见 UpsertNodeTraffic 同款注释 —
		// 累计字段(uplink/downlink/total_*)从 0 起步,raw 仅作 last baseline,
		// 否则套餐已用流量在首次见到一个用户时会被 xray 已有累计灌满。
		const insertStmt = `INSERT INTO user_traffic (server_id, username, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, cycle_start, updated_at) VALUES (?, ?, 0, 0, 0, 0, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
		_, err := q.ExecContext(ctx, insertStmt, serverID, username, uplink, downlink)
		if err != nil {
			return fmt.Errorf("insert user traffic: %w", err)
		}
		return nil
	}

	// 重启判定来自 isXrayRestarted(详见 UpsertNodeTraffic 同款注释)。
	var deltaUplink, deltaDownlink int64
	var newTotalUplink, newTotalDownlink int64

	if isXrayRestarted {
		log.Printf("[Traffic] Xray restart for server %d, user %s: uplink %d -> %d, downlink %d -> %d (accumulating to total)",
			serverID, username, existing.LastUplink, uplink, existing.LastDownlink, downlink)
		newTotalUplink = existing.TotalUplink + existing.LastUplink
		newTotalDownlink = existing.TotalDownlink + existing.LastDownlink
		deltaUplink = uplink
		deltaDownlink = downlink
	} else {
		if uplink >= existing.LastUplink {
			deltaUplink = uplink - existing.LastUplink
		} else {
			deltaUplink = 0
		}
		if downlink >= existing.LastDownlink {
			deltaDownlink = downlink - existing.LastDownlink
		} else {
			deltaDownlink = 0
		}
		newTotalUplink = existing.TotalUplink
		newTotalDownlink = existing.TotalDownlink
	}

	// 更新记录
	const updateStmt = `UPDATE user_traffic SET uplink = uplink + ?, downlink = downlink + ?, total_uplink = ?, total_downlink = ?, last_uplink = ?, last_downlink = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err = q.ExecContext(ctx, updateStmt, deltaUplink, deltaDownlink, newTotalUplink, newTotalDownlink, uplink, downlink, existing.ID)
	if err != nil {
		return fmt.Errorf("update user traffic: %w", err)
	}

	return nil
}

// UserEmailTraffic 跟 UserTraffic 字段对齐,只是 key 换 email。
type UserEmailTraffic struct {
	ID               int64
	ServerID         int64
	Email            string
	Uplink           int64
	Downlink         int64
	TotalUplink      int64
	TotalDownlink    int64
	LastUplink       int64
	LastDownlink     int64
	BillableBytes    int64
	BillableFraction float64
	BillableUsername string
	CycleStart       time.Time
	UpdatedAt        time.Time
}

// UpsertUserEmailTraffic 跟 UpsertUserTraffic 完全一样的 delta/restart 检测逻辑,key 换成 email。
// collector 同一次循环里跟 UpsertUserTraffic 并行调用,**双写两张表**:user_traffic 按 username
// 聚合(老路径不变),user_email_traffic 保留 email 细分(新功能用)。
func (r *TrafficRepository) UpsertUserEmailTraffic(ctx context.Context, serverID int64, email string, uplink, downlink int64, isXrayRestarted bool) error {
	return r.UpsertUserEmailTrafficWithBilling(ctx, serverID, email, uplink, downlink, isXrayRestarted, 1)
}

// UpsertUserEmailTrafficWithBilling stores the collection-time billable delta.
// Existing raw counters remain intact for drilldown and historical snapshots.
func (r *TrafficRepository) UpsertUserEmailTrafficWithBilling(ctx context.Context, serverID int64, email string, uplink, downlink int64, isXrayRestarted bool, billingMultiplier float64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return errors.New("server id is required")
	}
	if email == "" {
		return errors.New("email is required")
	}
	return upsertUserEmailTraffic(ctx, r.db, serverID, email, "", uplink, downlink, isXrayRestarted, billingMultiplier)
}

func upsertUserEmailTraffic(ctx context.Context, q trafficReadWriter, serverID int64, email, billingUsername string, uplink, downlink int64, isXrayRestarted bool, billingMultiplier float64) error {
	var existing UserEmailTraffic
	var cycleBaseUplink, cycleBaseDownlink int64
	var billableInitialized int
	var exists bool
	row := q.QueryRowContext(ctx, `SELECT id, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink,
		cycle_base_uplink, cycle_base_downlink, billable_bytes, billable_fraction, billable_initialized, billable_username
		FROM user_email_traffic WHERE server_id = ? AND email = ?`, serverID, email)
	err := row.Scan(&existing.ID, &existing.Uplink, &existing.Downlink, &existing.TotalUplink, &existing.TotalDownlink,
		&existing.LastUplink, &existing.LastDownlink, &cycleBaseUplink, &cycleBaseDownlink,
		&existing.BillableBytes, &existing.BillableFraction, &billableInitialized, &existing.BillableUsername)
	if err == nil {
		exists = true
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("query existing user email traffic: %w", err)
	}

	if !exists {
		// 首次见到 (server, email):见 UpsertNodeTraffic 同款注释 —— raw 仅作 baseline,
		// 累计字段从 0 起步,避免历史累计灌入当期。
		const insertStmt = `INSERT INTO user_email_traffic (server_id, email, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, billable_bytes, billable_fraction, billable_initialized, billable_username, cycle_start, updated_at) VALUES (?, ?, 0, 0, 0, 0, ?, ?, 0, 0, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
		if _, err := q.ExecContext(ctx, insertStmt, serverID, email, uplink, downlink, billingUsername); err != nil {
			return fmt.Errorf("insert user email traffic: %w", err)
		}
		return nil
	}

	// 重启判定来自 isXrayRestarted(详见 UpsertNodeTraffic 同款注释 — 历史 BUG 的核心来源就在这里)。
	var deltaUplink, deltaDownlink int64
	var newTotalUplink, newTotalDownlink int64
	if isXrayRestarted {
		newTotalUplink = existing.TotalUplink + existing.LastUplink
		newTotalDownlink = existing.TotalDownlink + existing.LastDownlink
		deltaUplink = uplink
		deltaDownlink = downlink
	} else {
		if uplink >= existing.LastUplink {
			deltaUplink = uplink - existing.LastUplink
		} else {
			deltaUplink = 0
		}
		if downlink >= existing.LastDownlink {
			deltaDownlink = downlink - existing.LastDownlink
		} else {
			deltaDownlink = 0
		}
		newTotalUplink = existing.TotalUplink
		newTotalDownlink = existing.TotalDownlink
	}

	// Old rows are initialized once from their current cycle usage. From this
	// point onward only each new delta is multiplied, preserving history across
	// future package or node multiplier changes.
	newBillable := existing.BillableBytes
	newBillableFraction := existing.BillableFraction
	if billableInitialized == 0 {
		currentRaw := saturatingTrafficAdd(existing.Uplink-cycleBaseUplink, existing.Downlink-cycleBaseDownlink)
		newBillable, newBillableFraction = accrueBillableTraffic(currentRaw, billingMultiplier, 0)
	}
	billedDelta, newBillableFraction := accrueBillableTraffic(
		saturatingTrafficAdd(deltaUplink, deltaDownlink), billingMultiplier, newBillableFraction)
	if math.MaxInt64-newBillable < billedDelta {
		newBillable = math.MaxInt64
		newBillableFraction = 0
	} else {
		newBillable += billedDelta
	}

	if billingUsername == "" {
		billingUsername = existing.BillableUsername
	}
	const updateStmt = `UPDATE user_email_traffic SET uplink = uplink + ?, downlink = downlink + ?, total_uplink = ?, total_downlink = ?, last_uplink = ?, last_downlink = ?, billable_bytes = ?, billable_fraction = ?, billable_initialized = 1, billable_username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	if _, err := q.ExecContext(ctx, updateStmt, deltaUplink, deltaDownlink, newTotalUplink, newTotalDownlink, uplink, downlink, newBillable, newBillableFraction, billingUsername, existing.ID); err != nil {
		return fmt.Errorf("update user email traffic: %w", err)
	}
	return nil
}

// UserTrafficSample is one email counter and its in-batch attribution.
type UserTrafficSample struct {
	Email             string
	Username          string
	Uplink            int64
	Downlink          int64
	BillingMultiplier float64
}

// UpsertUserTrafficBatch writes every per-email counter and its per-user
// aggregate in one transaction. A partial collector tick is never exposed.
func (r *TrafficRepository) UpsertUserTrafficBatch(ctx context.Context, serverID int64, samples []UserTrafficSample, isXrayRestarted bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return errors.New("server id is required")
	}
	conn, err := r.beginImmediateTransaction(ctx)
	if err != nil {
		return fmt.Errorf("begin user traffic batch: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = finishImmediateTransaction(context.Background(), conn, false)
		}
	}()

	type aggregate struct{ uplink, downlink int64 }
	byUsername := make(map[string]*aggregate)
	for _, sample := range samples {
		if sample.Email == "" {
			continue
		}
		if err := upsertUserEmailTraffic(ctx, conn, serverID, sample.Email, sample.Username, sample.Uplink, sample.Downlink, isXrayRestarted, sample.BillingMultiplier); err != nil {
			return fmt.Errorf("upsert email %q: %w", sample.Email, err)
		}
		if sample.Username == "" {
			continue
		}
		if total := byUsername[sample.Username]; total != nil {
			total.uplink = saturatingTrafficAdd(total.uplink, sample.Uplink)
			total.downlink = saturatingTrafficAdd(total.downlink, sample.Downlink)
		} else {
			byUsername[sample.Username] = &aggregate{uplink: max(sample.Uplink, 0), downlink: max(sample.Downlink, 0)}
		}
	}
	for username, total := range byUsername {
		if err := upsertUserTraffic(ctx, conn, serverID, username, total.uplink, total.downlink, isXrayRestarted); err != nil {
			return fmt.Errorf("upsert user %q: %w", username, err)
		}
	}
	if err := finishImmediateTransaction(ctx, conn, true); err != nil {
		return fmt.Errorf("commit user traffic batch: %w", err)
	}
	committed = true
	return nil
}

// ListUserEmailTraffic 返回所有 (server_id, email) 流量行 — 给 /api/admin/traffic/user-nodes 用。
func (r *TrafficRepository) ListUserEmailTraffic(ctx context.Context) ([]UserEmailTraffic, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	// Uplink/Downlink 返回本周期增量(减去月度重置抬起的基线),与 user_traffic 的口径一致;
	// TotalUplink/TotalDownlink 仍是不受重置影响的历史累计。
	rows, err := r.db.QueryContext(ctx, `SELECT id, server_id, email, uplink - cycle_base_uplink, downlink - cycle_base_downlink, total_uplink, total_downlink, last_uplink, last_downlink, cycle_start, updated_at FROM user_email_traffic`)
	if err != nil {
		return nil, fmt.Errorf("query user email traffic: %w", err)
	}
	defer rows.Close()
	var out []UserEmailTraffic
	for rows.Next() {
		var t UserEmailTraffic
		if err := rows.Scan(&t.ID, &t.ServerID, &t.Email, &t.Uplink, &t.Downlink, &t.TotalUplink, &t.TotalDownlink, &t.LastUplink, &t.LastDownlink, &t.CycleStart, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user email traffic: %w", err)
		}
		t.Uplink = max(t.Uplink, 0)
		t.Downlink = max(t.Downlink, 0)
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetUserEmailTraffic returns one exact (server, client email) counter row.
// A missing row is not an error because a newly provisioned client may not have
// produced traffic before the reconciler's first pass.
func (r *TrafficRepository) GetUserEmailTraffic(ctx context.Context, serverID int64, email string) (*UserEmailTraffic, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	email = strings.TrimSpace(email)
	if serverID <= 0 || email == "" {
		return nil, ErrManagedInvalidArgument
	}
	var traffic UserEmailTraffic
	err := r.db.QueryRowContext(ctx, `SELECT id, server_id, email,
       uplink - cycle_base_uplink, downlink - cycle_base_downlink,
       total_uplink, total_downlink, last_uplink, last_downlink,
       cycle_start, updated_at
FROM user_email_traffic WHERE server_id = ? AND email = ?`, serverID, email).Scan(
		&traffic.ID, &traffic.ServerID, &traffic.Email, &traffic.Uplink,
		&traffic.Downlink, &traffic.TotalUplink, &traffic.TotalDownlink,
		&traffic.LastUplink, &traffic.LastDownlink, &traffic.CycleStart,
		&traffic.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user email traffic: %w", err)
	}
	traffic.Uplink = max(traffic.Uplink, 0)
	traffic.Downlink = max(traffic.Downlink, 0)
	return &traffic, nil
}

// 返回服务器的所有用户流量记录。
func (r *TrafficRepository) GetUserTrafficByServer(ctx context.Context, serverID int64) ([]UserTraffic, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const query = `SELECT id, server_id, username, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, cycle_start, updated_at
		FROM user_traffic WHERE server_id = ? ORDER BY username`
	rows, err := r.db.QueryContext(ctx, query, serverID)
	if err != nil {
		return nil, fmt.Errorf("query user traffic: %w", err)
	}
	defer rows.Close()

	var results []UserTraffic
	for rows.Next() {
		var t UserTraffic
		if err := rows.Scan(&t.ID, &t.ServerID, &t.Username, &t.Uplink, &t.Downlink, &t.TotalUplink, &t.TotalDownlink, &t.LastUplink, &t.LastDownlink, &t.CycleStart, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user traffic: %w", err)
		}
		results = append(results, t)
	}

	return results, nil
}

// 返回所有用户流量记录。
func (r *TrafficRepository) GetAllUserTraffic(ctx context.Context) ([]UserTraffic, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	const query = `SELECT id, server_id, username, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, cycle_start, updated_at
		FROM user_traffic ORDER BY username, server_id`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query all user traffic: %w", err)
	}
	defer rows.Close()

	var results []UserTraffic
	for rows.Next() {
		var t UserTraffic
		if err := rows.Scan(&t.ID, &t.ServerID, &t.Username, &t.Uplink, &t.Downlink, &t.TotalUplink, &t.TotalDownlink, &t.LastUplink, &t.LastDownlink, &t.CycleStart, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user traffic: %w", err)
		}
		results = append(results, t)
	}

	return results, nil
}

// 返回所有服务器上特定用户的所有流量记录。
func (r *TrafficRepository) GetUserTrafficByUsername(ctx context.Context, username string) ([]UserTraffic, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if username == "" {
		return nil, errors.New("username is required")
	}

	const query = `SELECT id, server_id, username, uplink, downlink, total_uplink, total_downlink, last_uplink, last_downlink, cycle_start, updated_at
		FROM user_traffic WHERE username = ? ORDER BY server_id`
	rows, err := r.db.QueryContext(ctx, query, username)
	if err != nil {
		return nil, fmt.Errorf("query user traffic by username: %w", err)
	}
	defer rows.Close()

	var results []UserTraffic
	for rows.Next() {
		var t UserTraffic
		if err := rows.Scan(&t.ID, &t.ServerID, &t.Username, &t.Uplink, &t.Downlink, &t.TotalUplink, &t.TotalDownlink, &t.LastUplink, &t.LastDownlink, &t.CycleStart, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user traffic: %w", err)
		}
		results = append(results, t)
	}

	return results, nil
}

// 重置用户在所有服务器上的当前周期流量。
//
// 两张表口径必须一起归零,否则会撕裂:面板/订阅头读 user_traffic(已归零),而套餐配了 node_multipliers 时
// 超限判定读 user_email_traffic —— 后者不归零的话,重置当轮就会"恢复入站→按累计值重新判超限→再踢出"。
//
// user_email_traffic 走基线而非清零:把 uplink/downlink 的当前值抬进 cycle_base_*,判定只看差值。
// 这样 total_* 的历史累计得以保留,collector 的 `uplink = uplink + delta` 累加逻辑也无需改动。
func (r *TrafficRepository) resetUserTrafficCycle(ctx context.Context, username string, automaticResetAt *time.Time) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if username == "" {
		return errors.New("username is required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin reset user traffic cycle: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const userStmt = `UPDATE user_traffic SET uplink = 0, downlink = 0, cycle_start = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE username = ?`
	if _, err := tx.ExecContext(ctx, userStmt, username); err != nil {
		return fmt.Errorf("reset user traffic cycle: %w", err)
	}

	// WHERE 必须与 GetUserWeightedTraffic 的扫描条件严格一致,确保"判定看得见的行"都被抬了基线。
	// 转义 `_`(防跨用户串味)+ 显式覆盖 `<user>__...` 和 `<user>-<tag>` 两种子账号形态 + user_subaccounts 精确集。
	esc := escapeLikePattern(username)
	const emailStmt = `UPDATE user_email_traffic
		SET cycle_base_uplink = uplink, cycle_base_downlink = downlink,
		    billable_bytes = 0, billable_fraction = 0, billable_initialized = 1,
		    cycle_start = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE email = ?
		   OR email LIKE ? ESCAPE '\'
		   OR email LIKE ? ESCAPE '\'
		   OR email IN (SELECT email FROM user_subaccounts WHERE username = ?)
		   OR billable_username = ?`
	if _, err := tx.ExecContext(ctx, emailStmt, username, esc+`\_\_%`, esc+`-%`, username, username); err != nil {
		return fmt.Errorf("reset user email traffic cycle: %w", err)
	}

	if automaticResetAt != nil {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET last_reset_at = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
			*automaticResetAt, username); err != nil {
			return fmt.Errorf("update user last_reset_at: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_traffic_threshold_notified WHERE username = ?`, username); err != nil {
		return fmt.Errorf("clear user traffic threshold notification: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reset user traffic cycle: %w", err)
	}
	return nil
}

// ResetUserTrafficCycle clears a cycle manually. It also clears the 80% marker,
// but deliberately leaves last_reset_at unchanged so a manual reset cannot
// suppress the next configured calendar reset.
func (r *TrafficRepository) ResetUserTrafficCycle(ctx context.Context, username string) error {
	return r.resetUserTrafficCycle(ctx, username, nil)
}

// ResetUserTrafficCycleAt performs the automatic cycle reset and records its
// timestamp in the same transaction as both traffic tables and the warning marker.
func (r *TrafficRepository) ResetUserTrafficCycleAt(ctx context.Context, username string, resetAt time.Time) error {
	if resetAt.IsZero() {
		return errors.New("reset time is required")
	}
	return r.resetUserTrafficCycle(ctx, username, &resetAt)
}

// UpdateUserLastResetAt 记录用户最近一次按 reset_day 触发的流量周期重置时间。
// CheckAll 用这个时间戳判定"本月是否已重置过",确保 enforcer 每 5 分钟跑一次时同一天不反复 reset。
func (r *TrafficRepository) UpdateUserLastResetAt(ctx context.Context, username string, t time.Time) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if username == "" {
		return errors.New("username is required")
	}
	const stmt = `UPDATE users SET last_reset_at = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`
	_, err := r.db.ExecContext(ctx, stmt, t, username)
	if err != nil {
		return fmt.Errorf("update user last_reset_at: %w", err)
	}
	return nil
}

// UpdateUserResetDay 修正用户的每月重置日(1-31)。
// 用于自愈历史脏数据:is_reset=1 但 reset_day=0 的用户永远不会触发重置。
func (r *TrafficRepository) UpdateUserResetDay(ctx context.Context, username string, day int) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if username == "" {
		return errors.New("username is required")
	}
	if day < 1 || day > 31 {
		return fmt.Errorf("invalid reset day: %d", day)
	}
	const stmt = `UPDATE users SET reset_day = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`
	_, err := r.db.ExecContext(ctx, stmt, day, username)
	if err != nil {
		return fmt.Errorf("update user reset_day: %w", err)
	}
	return nil
}

// UpdateRemoteServerLastTrafficResetAt 记录服务器最近一次按 traffic_reset_day 自动重置流量的时间。
// enforcer 用它判定"本月是否已重置过",避免每轮 CheckAll(默认 2 分钟)反复 reset。
func (r *TrafficRepository) UpdateRemoteServerLastTrafficResetAt(ctx context.Context, id int64, t time.Time) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("remote server id is required")
	}
	const stmt = `UPDATE remote_servers SET last_traffic_reset_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := r.db.ExecContext(ctx, stmt, t, id)
	if err != nil {
		return fmt.Errorf("update remote server last_traffic_reset_at: %w", err)
	}
	return nil
}

// ResetRemoteServerTrafficCycle 把服务器"已用流量"逻辑归零 —— 与手动"重置流量"按钮同一套算法:
// offset = 0 - 当前聚合用量。对 system / xray 两种 source 统一(GetServerTrafficUsed 内部按 source 分流),
// 只改 traffic_used_offset,不清 system_cycle / node_traffic(物理累计保留,后续增量继续从 0 涨)。
func (r *TrafficRepository) ResetRemoteServerTrafficCycle(ctx context.Context, serverID int64) error {
	return r.resetRemoteServerTrafficCycle(ctx, serverID, nil)
}

// ResetRemoteServerTrafficCycleAt updates the logical traffic offset, the
// calendar reset timestamp and the server warning marker atomically.
func (r *TrafficRepository) ResetRemoteServerTrafficCycleAt(ctx context.Context, serverID int64, resetAt time.Time) error {
	if resetAt.IsZero() {
		return errors.New("reset time is required")
	}
	return r.resetRemoteServerTrafficCycle(ctx, serverID, &resetAt)
}

func (r *TrafficRepository) resetRemoteServerTrafficCycle(ctx context.Context, serverID int64, resetAt *time.Time) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return errors.New("server id is required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin reset remote server traffic cycle: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	aggregated, err := getServerTrafficUsed(ctx, tx, serverID)
	if err != nil {
		return fmt.Errorf("get server traffic used: %w", err)
	}
	if resetAt == nil {
		if _, err := tx.ExecContext(ctx,
			`UPDATE remote_servers SET traffic_used_offset = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			-aggregated, serverID); err != nil {
			return fmt.Errorf("reset remote server traffic offset: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx,
			`UPDATE remote_servers SET traffic_used_offset = ?, last_traffic_reset_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			-aggregated, *resetAt, serverID); err != nil {
			return fmt.Errorf("reset remote server traffic offset and timestamp: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_threshold_notified WHERE server_id = ?`, serverID); err != nil {
		return fmt.Errorf("clear remote server traffic threshold notification: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reset remote server traffic cycle: %w", err)
	}
	return nil
}

// ==================== 流量快照 CRUD ====================

// 为服务器创建每日快照。
func (r *TrafficRepository) CreateTrafficSnapshot(ctx context.Context, serverID int64, date string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if serverID <= 0 {
		return errors.New("server id is required")
	}
	if date == "" {
		date = time.Now().Format("2006-01-02")
	}

	// 根据node_traffic和user_traffic计算总计
	var inboundUplink, inboundDownlink, outboundUplink, outboundDownlink int64
	row := r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN type='inbound' THEN uplink ELSE 0 END), 0), COALESCE(SUM(CASE WHEN type='inbound' THEN downlink ELSE 0 END), 0), COALESCE(SUM(CASE WHEN type='outbound' THEN uplink ELSE 0 END), 0), COALESCE(SUM(CASE WHEN type='outbound' THEN downlink ELSE 0 END), 0) FROM node_traffic WHERE server_id = ?`, serverID)
	if err := row.Scan(&inboundUplink, &inboundDownlink, &outboundUplink, &outboundDownlink); err != nil {
		return fmt.Errorf("calculate node traffic totals: %w", err)
	}

	var userUplink, userDownlink int64
	row = r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(uplink), 0), COALESCE(SUM(downlink), 0) FROM user_traffic WHERE server_id = ?`, serverID)
	if err := row.Scan(&userUplink, &userDownlink); err != nil {
		return fmt.Errorf("calculate user traffic totals: %w", err)
	}

	// 更新插入快照
	const stmt = `INSERT INTO traffic_snapshots (server_id, date, inbound_uplink, inbound_downlink, outbound_uplink, outbound_downlink, user_uplink, user_downlink, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(server_id, date) DO UPDATE SET inbound_uplink = excluded.inbound_uplink, inbound_downlink = excluded.inbound_downlink, outbound_uplink = excluded.outbound_uplink, outbound_downlink = excluded.outbound_downlink, user_uplink = excluded.user_uplink, user_downlink = excluded.user_downlink`
	_, err := r.db.ExecContext(ctx, stmt, serverID, date, inboundUplink, inboundDownlink, outboundUplink, outboundDownlink, userUplink, userDownlink)
	if err != nil {
		return fmt.Errorf("upsert traffic snapshot: %w", err)
	}

	return nil
}

// 返回某个日期范围内服务器的流量快照。
func (r *TrafficRepository) GetTrafficSnapshots(ctx context.Context, serverID int64, days int) ([]TrafficSnapshot, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if days <= 0 {
		days = 30
	}

	startDate := time.Now().AddDate(0, 0, -days).Format("2006-01-02")

	var query string
	var args []interface{}
	if serverID > 0 {
		query = `SELECT id, server_id, date, inbound_uplink, inbound_downlink, outbound_uplink, outbound_downlink, user_uplink, user_downlink, created_at FROM traffic_snapshots WHERE server_id = ? AND date >= ? ORDER BY date ASC`
		args = []interface{}{serverID, startDate}
	} else {
		query = `SELECT id, server_id, date, inbound_uplink, inbound_downlink, outbound_uplink, outbound_downlink, user_uplink, user_downlink, created_at FROM traffic_snapshots WHERE date >= ? ORDER BY date ASC, server_id ASC`
		args = []interface{}{startDate}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query traffic snapshots: %w", err)
	}
	defer rows.Close()

	var results []TrafficSnapshot
	for rows.Next() {
		var s TrafficSnapshot
		if err := rows.Scan(&s.ID, &s.ServerID, &s.Date, &s.InboundUplink, &s.InboundDownlink, &s.OutboundUplink, &s.OutboundDownlink, &s.UserUplink, &s.UserDownlink, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan traffic snapshot: %w", err)
		}
		results = append(results, s)
	}

	return results, nil
}

// 删除早于指定天数的快照。
func (r *TrafficRepository) CleanOldSnapshots(ctx context.Context, days int) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if days <= 0 {
		days = 30
	}

	cutoffDate := time.Now().AddDate(0, 0, -days).Format("2006-01-02")
	const stmt = `DELETE FROM traffic_snapshots WHERE date < ?`
	_, err := r.db.ExecContext(ctx, stmt, cutoffDate)
	if err != nil {
		return fmt.Errorf("clean old snapshots: %w", err)
	}

	return nil
}

// 证书状态常量
const (
	CertStatusPending = "pending"
	CertStatusValid   = "valid"
	CertStatusExpired = "expired"
	CertStatusFailed  = "failed"
)

// 证书质询模式常量
const (
	CertChallengeStandalone = "standalone"
	CertChallengeWebroot    = "webroot"
	CertChallengeDNS        = "dns"
)

// 证书表示由 ACME 管理的 SSL/TLS 证书
type Certificate struct {
	ID             int64
	Domain         string
	Email          string
	Provider       string
	CertPath       string
	KeyPath        string
	CertPEM        string
	KeyPEM         string
	Status         string
	ExpiryDate     *time.Time
	IssueDate      *time.Time
	AutoRenew      bool
	ChallengeMode  string
	WebrootPath    string
	RemoteServerID int64
	Message        string
	DNSProviderID  int64
	DeployTarget   string
	DeployCertPath string
	DeployKeyPath  string
	AutoDeploy     bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// DNSProvider 代表可重用的 DNS API 凭证集
type DNSProvider struct {
	ID           int64
	Name         string
	ProviderType string
	Credentials  string // 详见上下文
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func scanCertificate(scanner rowScanner) (Certificate, error) {
	var cert Certificate
	var certPath, keyPath, certPEM, keyPEM, webrootPath, message sql.NullString
	var deployTarget, deployCertPath, deployKeyPath sql.NullString
	var expiryDate, issueDate sql.NullTime
	var autoRenew int
	var autoDeploy int

	if err := scanner.Scan(
		&cert.ID,
		&cert.Domain,
		&cert.Email,
		&cert.Provider,
		&certPath,
		&keyPath,
		&certPEM,
		&keyPEM,
		&cert.Status,
		&expiryDate,
		&issueDate,
		&autoRenew,
		&cert.ChallengeMode,
		&webrootPath,
		&cert.RemoteServerID,
		&message,
		&cert.DNSProviderID,
		&deployTarget,
		&deployCertPath,
		&deployKeyPath,
		&autoDeploy,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	); err != nil {
		return Certificate{}, err
	}

	cert.CertPath = certPath.String
	cert.KeyPath = keyPath.String
	cert.CertPEM = certPEM.String
	cert.KeyPEM = keyPEM.String
	cert.WebrootPath = webrootPath.String
	cert.Message = message.String
	cert.DeployTarget = deployTarget.String
	cert.DeployCertPath = deployCertPath.String
	cert.DeployKeyPath = deployKeyPath.String
	cert.AutoRenew = autoRenew == 1
	cert.AutoDeploy = autoDeploy == 1
	if expiryDate.Valid {
		cert.ExpiryDate = &expiryDate.Time
	}
	if issueDate.Valid {
		cert.IssueDate = &issueDate.Time
	}

	return cert, nil
}

// 返回按创建时间排序的所有证书。
func (r *TrafficRepository) ListCertificates(ctx context.Context) ([]Certificate, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		       status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		       remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy,
		       created_at, updated_at
		FROM certificates ORDER BY id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certificates: %w", err)
	}

	return certs, nil
}

// 返回特定服务器的证书。
func (r *TrafficRepository) ListCertificatesByServer(ctx context.Context, serverID int64) ([]Certificate, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		       status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		       remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy,
		       created_at, updated_at
		FROM certificates WHERE remote_server_id = ? ORDER BY id DESC
	`, serverID)
	if err != nil {
		return nil, fmt.Errorf("list certificates by server: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certificates: %w", err)
	}

	return certs, nil
}

// 按 ID 返回证书。
func (r *TrafficRepository) GetCertificate(ctx context.Context, id int64) (*Certificate, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	row := r.db.QueryRowContext(ctx, `
		SELECT id, domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		       status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		       remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy,
		       created_at, updated_at
		FROM certificates WHERE id = ?
	`, id)

	cert, err := scanCertificate(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCertificateNotFound
		}
		return nil, fmt.Errorf("get certificate: %w", err)
	}

	return &cert, nil
}

// 按域和服务器 ID 返回证书。
func (r *TrafficRepository) GetCertificateByDomain(ctx context.Context, domain string, serverID int64) (*Certificate, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	row := r.db.QueryRowContext(ctx, `
		SELECT id, domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		       status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		       remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy,
		       created_at, updated_at
		FROM certificates WHERE domain = ? AND remote_server_id = ?
	`, domain, serverID)

	cert, err := scanCertificate(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCertificateNotFound
		}
		return nil, fmt.Errorf("get certificate by domain: %w", err)
	}

	return &cert, nil
}

// FindCertificateForDomain 找一张能覆盖该 FQDN 的 valid 证书,用于 DDNS 推断 DNS provider:
//   - 精确匹配 domain == fqdn
//   - 通配符匹配 *.parent,其中 parent 是 fqdn 去掉最左 label 的部分(host.example.com → example.com)
//
// 返回找到的第一张(优先精确,其次通配符),没有则 ErrCertificateNotFound。
// 证书签发时已经选好 dns_provider_id,这里只需把它读出来给 DDNS 用。
func (r *TrafficRepository) FindCertificateForDomain(ctx context.Context, fqdn string) (*Certificate, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	fqdn = strings.TrimSpace(strings.ToLower(fqdn))
	if fqdn == "" {
		return nil, ErrCertificateNotFound
	}

	// 候选 domain:精确 + 各层级通配符(host.a.b.com → *.a.b.com / *.b.com)
	parts := strings.Split(fqdn, ".")
	candidates := []string{fqdn}
	for i := 1; i < len(parts)-1; i++ {
		candidates = append(candidates, "*."+strings.Join(parts[i:], "."))
	}

	placeholders := strings.Repeat("?,", len(candidates))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]interface{}, len(candidates))
	for i, c := range candidates {
		args[i] = c
	}

	query := `SELECT id, domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		       status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		       remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy,
		       created_at, updated_at
		FROM certificates
		WHERE status = 'valid' AND domain IN (` + placeholders + `)
		ORDER BY CASE WHEN domain = ? THEN 0 ELSE 1 END, id DESC
		LIMIT 1`
	args = append(args, fqdn) // 第一个 ORDER BY 的精确匹配参数

	row := r.db.QueryRowContext(ctx, query, args...)
	cert, err := scanCertificate(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCertificateNotFound
		}
		return nil, fmt.Errorf("find certificate for domain: %w", err)
	}
	return &cert, nil
}

// MarkDDNSPending 在 DDNS goroutine 启动时标记,UI 可显示"正在同步"
func (r *TrafficRepository) MarkDDNSPending(ctx context.Context, serverID int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET ddns_pending = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, serverID)
	return err
}

// UpdateRemoteServerDDNSStatus 记录 DDNS 同步结果:
// 成功(errMsg=""):清 pending,更新 last_synced_at,清 last_error
// 失败(errMsg 非空):清 pending,写 last_error,last_synced_at 不动(保留上次成功时间)
func (r *TrafficRepository) UpdateRemoteServerDDNSStatus(ctx context.Context, serverID int64, errMsg string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if errMsg == "" {
		_, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET ddns_pending = 0, ddns_last_synced_at = CURRENT_TIMESTAMP, ddns_last_error = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, serverID)
		return err
	}
	_, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET ddns_pending = 0, ddns_last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, errMsg, serverID)
	return err
}

// UpdateRemoteServerDDNSConfig 更新 DDNS 配置(enabled + provider_id),由 server 创建/编辑路径调用。
// 关闭(enabled=false)时同时清掉 last_error,避免下次开启时仍带旧错误。
func (r *TrafficRepository) UpdateRemoteServerDDNSConfig(ctx context.Context, serverID int64, enabled bool, providerID int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	if !enabled {
		_, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET ddns_enabled = ?, ddns_provider_id = ?, ddns_last_error = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, enabledInt, providerID, serverID)
		return err
	}
	_, err := r.db.ExecContext(ctx, `UPDATE remote_servers SET ddns_enabled = ?, ddns_provider_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, enabledInt, providerID, serverID)
	return err
}

// ListDDNSRetryCandidates reconciler 用:扫所有 enabled + 上次失败 + 在线 的 server。
// 离线 server 没新 IP 上来,重试也没意义。
func (r *TrafficRepository) ListDDNSRetryCandidates(ctx context.Context) ([]RemoteServer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM remote_servers WHERE ddns_enabled = 1 AND ddns_last_error <> '' AND status = 'connected'`)
	if err != nil {
		return nil, fmt.Errorf("list ddns retry candidates: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	servers := make([]RemoteServer, 0, len(ids))
	for _, id := range ids {
		s, err := r.GetRemoteServer(ctx, id)
		if err != nil {
			continue
		}
		servers = append(servers, *s)
	}
	return servers, nil
}

// 创建新的证书记录。
func (r *TrafficRepository) CreateCertificate(ctx context.Context, cert *Certificate) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	cert.Domain = strings.TrimSpace(cert.Domain)
	if cert.Domain == "" {
		return errors.New("domain is required")
	}
	cert.Email = strings.TrimSpace(cert.Email)
	if cert.Email == "" {
		return errors.New("email is required")
	}
	if cert.Provider == "" {
		cert.Provider = "letsencrypt"
	}
	if cert.Status == "" {
		cert.Status = CertStatusPending
	}
	if cert.ChallengeMode == "" {
		cert.ChallengeMode = CertChallengeStandalone
	}

	autoRenew := 0
	if cert.AutoRenew {
		autoRenew = 1
	}

	if cert.DeployTarget == "" {
		cert.DeployTarget = "none"
	}

	autoDeploy := 0
	if cert.AutoDeploy {
		autoDeploy = 1
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO certificates (domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		                          status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		                          remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		cert.Domain,
		cert.Email,
		cert.Provider,
		sql.NullString{String: cert.CertPath, Valid: cert.CertPath != ""},
		sql.NullString{String: cert.KeyPath, Valid: cert.KeyPath != ""},
		sql.NullString{String: cert.CertPEM, Valid: cert.CertPEM != ""},
		sql.NullString{String: cert.KeyPEM, Valid: cert.KeyPEM != ""},
		cert.Status,
		cert.ExpiryDate,
		cert.IssueDate,
		autoRenew,
		cert.ChallengeMode,
		sql.NullString{String: cert.WebrootPath, Valid: cert.WebrootPath != ""},
		cert.RemoteServerID,
		sql.NullString{String: cert.Message, Valid: cert.Message != ""},
		cert.DNSProviderID,
		cert.DeployTarget,
		sql.NullString{String: cert.DeployCertPath, Valid: cert.DeployCertPath != ""},
		sql.NullString{String: cert.DeployKeyPath, Valid: cert.DeployKeyPath != ""},
		autoDeploy,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return ErrCertificateExists
		}
		return fmt.Errorf("create certificate: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}
	cert.ID = id

	return nil
}

// 更新现有证书记录。
func (r *TrafficRepository) UpdateCertificate(ctx context.Context, cert *Certificate) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	if cert.ID <= 0 {
		return errors.New("certificate id is required")
	}

	autoRenew := 0
	if cert.AutoRenew {
		autoRenew = 1
	}
	autoDeploy := 0
	if cert.AutoDeploy {
		autoDeploy = 1
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET
		    domain = ?,
		    email = ?,
		    provider = ?,
		    cert_path = ?,
		    key_path = ?,
		    cert_pem = ?,
		    key_pem = ?,
		    status = ?,
		    expiry_date = ?,
		    issue_date = ?,
		    auto_renew = ?,
		    challenge_mode = ?,
		    webroot_path = ?,
		    remote_server_id = ?,
		    message = ?,
		    dns_provider_id = ?,
		    deploy_target = ?,
		    deploy_cert_path = ?,
		    deploy_key_path = ?,
		    auto_deploy = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`,
		cert.Domain,
		cert.Email,
		cert.Provider,
		sql.NullString{String: cert.CertPath, Valid: cert.CertPath != ""},
		sql.NullString{String: cert.KeyPath, Valid: cert.KeyPath != ""},
		sql.NullString{String: cert.CertPEM, Valid: cert.CertPEM != ""},
		sql.NullString{String: cert.KeyPEM, Valid: cert.KeyPEM != ""},
		cert.Status,
		cert.ExpiryDate,
		cert.IssueDate,
		autoRenew,
		cert.ChallengeMode,
		sql.NullString{String: cert.WebrootPath, Valid: cert.WebrootPath != ""},
		cert.RemoteServerID,
		sql.NullString{String: cert.Message, Valid: cert.Message != ""},
		cert.DNSProviderID,
		cert.DeployTarget,
		sql.NullString{String: cert.DeployCertPath, Valid: cert.DeployCertPath != ""},
		sql.NullString{String: cert.DeployKeyPath, Valid: cert.DeployKeyPath != ""},
		autoDeploy,
		cert.ID,
	)
	if err != nil {
		return fmt.Errorf("update certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

// UpdateCertificateSettings updates administrator-controlled certificate
// metadata without writing issued material, status, dates, or messages. Those
// fields may change concurrently while an ACME operation is in flight.
func (r *TrafficRepository) UpdateCertificateSettings(ctx context.Context, cert *Certificate) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if cert == nil || cert.ID <= 0 {
		return errors.New("certificate id is required")
	}
	autoRenew := 0
	if cert.AutoRenew {
		autoRenew = 1
	}
	autoDeploy := 0
	if cert.AutoDeploy {
		autoDeploy = 1
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET
		    domain = ?, email = ?, provider = ?, auto_renew = ?,
		    challenge_mode = ?, webroot_path = ?, dns_provider_id = ?,
		    deploy_target = ?, deploy_cert_path = ?, deploy_key_path = ?,
		    auto_deploy = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`,
		cert.Domain, cert.Email, cert.Provider, autoRenew, cert.ChallengeMode,
		sql.NullString{String: cert.WebrootPath, Valid: cert.WebrootPath != ""}, cert.DNSProviderID,
		cert.DeployTarget,
		sql.NullString{String: cert.DeployCertPath, Valid: cert.DeployCertPath != ""},
		sql.NullString{String: cert.DeployKeyPath, Valid: cert.DeployKeyPath != ""},
		autoDeploy, cert.ID,
	)
	if err != nil {
		return fmt.Errorf("update certificate settings: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}
	return nil
}

// UpdateCertificateDeploymentSettings persists a successful manual deployment
// without replaying a stale certificate snapshot over concurrently renewed
// material or automation settings.
func (r *TrafficRepository) UpdateCertificateDeploymentSettings(ctx context.Context, id int64, target, certPath, keyPath string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("certificate id is required")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET deploy_target = ?, deploy_cert_path = ?, deploy_key_path = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, target, sql.NullString{String: certPath, Valid: certPath != ""}, sql.NullString{String: keyPath, Valid: keyPath != ""}, id)
	if err != nil {
		return fmt.Errorf("update certificate deployment settings: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}
	return nil
}

// 仅更新证书的状态和消息。
func (r *TrafficRepository) UpdateCertificateStatus(ctx context.Context, id int64, status, message string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET status = ?, message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, status, sql.NullString{String: message, Valid: message != ""}, id)
	if err != nil {
		return fmt.Errorf("update certificate status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

func (r *TrafficRepository) AppendCertificateLog(ctx context.Context, id int64, line string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	ts := time.Now().Format("15:04:05")
	entry := "[" + ts + "] " + line + "\n"
	_, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET message = COALESCE(message, '') || ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, entry, id)
	return err
}

// 成功颁发后更新证书。
func (r *TrafficRepository) UpdateCertificateIssued(ctx context.Context, id int64, certPath, keyPath, certPEM, keyPEM string, issueDate, expiryDate time.Time) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET
		    cert_path = ?,
		    key_path = ?,
		    cert_pem = ?,
		    key_pem = ?,
		    status = ?,
		    issue_date = ?,
		    expiry_date = ?,
		    message = NULL,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, certPath, keyPath, certPEM, keyPEM, CertStatusValid, issueDate, expiryDate, id)
	if err != nil {
		return fmt.Errorf("update certificate issued: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

// UpdateCertificateIssuedWithDefaultDeployPaths is used by manual uploads of
// an existing certificate. It replaces issued material and initializes missing
// deployment paths in one statement, so no stale full-record update can restore
// the old PEM after a successful upload.
func (r *TrafficRepository) UpdateCertificateIssuedWithDefaultDeployPaths(ctx context.Context, id int64, certPath, keyPath, certPEM, keyPEM string, issueDate, expiryDate time.Time, deployCertPath, deployKeyPath string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET
		    cert_path = ?, key_path = ?, cert_pem = ?, key_pem = ?, status = ?,
		    issue_date = ?, expiry_date = ?, message = NULL,
		    deploy_cert_path = CASE WHEN COALESCE(TRIM(deploy_cert_path), '') = '' THEN ? ELSE deploy_cert_path END,
		    deploy_key_path = CASE WHEN COALESCE(TRIM(deploy_key_path), '') = '' THEN ? ELSE deploy_key_path END,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, certPath, keyPath, certPEM, keyPEM, CertStatusValid, issueDate, expiryDate, deployCertPath, deployKeyPath, id)
	if err != nil {
		return fmt.Errorf("update uploaded certificate issued material: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}
	return nil
}

// 设置证书的 auto_renew 标志。
func (r *TrafficRepository) SetCertificateAutoRenew(ctx context.Context, id int64, autoRenew bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	val := 0
	if autoRenew {
		val = 1
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET auto_renew = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, val, id)
	if err != nil {
		return fmt.Errorf("set certificate auto_renew: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

// 更新证书的 auto_deploy 标志。
func (r *TrafficRepository) SetCertificateAutoDeploy(ctx context.Context, id int64, autoDeploy bool) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	val := 0
	if autoDeploy {
		val = 1
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET auto_deploy = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, val, id)
	if err != nil {
		return fmt.Errorf("set certificate auto_deploy: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

// 返回启用了 auto_deploy 的所有有效证书。
func (r *TrafficRepository) ListAutoDeployCertificates(ctx context.Context) ([]Certificate, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		       status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		       remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy,
		       created_at, updated_at
		FROM certificates
		WHERE auto_deploy = 1 AND status = 'valid' AND cert_pem != '' AND key_pem != ''
		      AND deploy_cert_path != '' AND deploy_key_path != ''
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list auto_deploy certificates: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}

// 按 ID 删除证书。
func (r *TrafficRepository) DeleteCertificate(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

// 返回在指定天内过期并启用 auto_renew 的证书。
func (r *TrafficRepository) ListExpiringCertificates(ctx context.Context, days int) ([]Certificate, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	if days <= 0 {
		days = 30
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		       status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		       remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy,
		       created_at, updated_at
		FROM certificates
		WHERE auto_renew = 1
		  AND status = 'valid'
		  AND expiry_date IS NOT NULL
		  AND expiry_date <= datetime('now', '+' || ? || ' days')
		ORDER BY expiry_date ASC
	`, days)
	if err != nil {
		return nil, fmt.Errorf("list expiring certificates: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certificates: %w", err)
	}

	return certs, nil
}

// 返回所有有效证书（用于入站向导选择）。
func (r *TrafficRepository) ListValidCertificates(ctx context.Context) ([]Certificate, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain, email, provider, cert_path, key_path, cert_pem, key_pem,
		       status, expiry_date, issue_date, auto_renew, challenge_mode, webroot_path,
		       remote_server_id, message, dns_provider_id, deploy_target, deploy_cert_path, deploy_key_path, auto_deploy,
		       created_at, updated_at
		FROM certificates
		WHERE status = 'valid'
		ORDER BY domain ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list valid certificates: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certificates: %w", err)
	}

	return certs, nil
}

// --- DNS 提供商 CRUD ---

// 返回所有 DNS 提供商。
func (r *TrafficRepository) ListDNSProviders(ctx context.Context) ([]DNSProvider, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, provider_type, credentials, created_at, updated_at FROM dns_providers ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list dns_providers: %w", err)
	}
	defer rows.Close()

	var providers []DNSProvider
	for rows.Next() {
		var p DNSProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.ProviderType, &p.Credentials, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan dns_provider: %w", err)
		}
		providers = append(providers, p)
	}
	return providers, rows.Err()
}

// 按 ID 返回 DNS 提供商。
func (r *TrafficRepository) GetDNSProvider(ctx context.Context, id int64) (*DNSProvider, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	var p DNSProvider
	err := r.db.QueryRowContext(ctx, `SELECT id, name, provider_type, credentials, created_at, updated_at FROM dns_providers WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.ProviderType, &p.Credentials, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get dns_provider: %w", err)
	}
	return &p, nil
}

// 创建一个新的 DNS 提供商。
func (r *TrafficRepository) CreateDNSProvider(ctx context.Context, p *DNSProvider) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx, `INSERT INTO dns_providers (name, provider_type, credentials) VALUES (?, ?, ?)`,
		p.Name, p.ProviderType, p.Credentials)
	if err != nil {
		return fmt.Errorf("create dns_provider: %w", err)
	}
	id, _ := result.LastInsertId()
	p.ID = id
	return nil
}

// 更新 DNS 提供商。
func (r *TrafficRepository) UpdateDNSProvider(ctx context.Context, p *DNSProvider) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx, `UPDATE dns_providers SET name = ?, provider_type = ?, credentials = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		p.Name, p.ProviderType, p.Credentials, p.ID)
	if err != nil {
		return fmt.Errorf("update dns_provider: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return errors.New("dns provider not found")
	}
	return nil
}

// 按 ID 删除 DNS 提供商。
func (r *TrafficRepository) DeleteDNSProvider(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM dns_providers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete dns_provider: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return errors.New("dns provider not found")
	}
	return nil
}

func (r *TrafficRepository) CreateNodeTrafficSnapshots(ctx context.Context, serverID int64, date string) error {
	// UNIQUE 已包含 type 列(rebuild 后),同 (server, tag, date) 不同 type 各自独立行,
	// 不再互相覆盖。ON CONFLICT 也带 type,行存在时按 type 维度独立更新。
	const stmt = `
INSERT INTO node_traffic_snapshots (server_id, tag, type, date, uplink, downlink)
SELECT server_id, tag, type, ?, uplink, downlink FROM node_traffic WHERE server_id = ?
ON CONFLICT(server_id, tag, type, date) DO UPDATE SET uplink=excluded.uplink, downlink=excluded.downlink`
	_, err := r.db.ExecContext(ctx, stmt, date, serverID)
	return err
}

func (r *TrafficRepository) CreateUserTrafficSnapshots(ctx context.Context, serverID int64, date string) error {
	const stmt = `
INSERT INTO user_traffic_snapshots (server_id, username, date, uplink, downlink)
SELECT server_id, username, ?, uplink, downlink FROM user_traffic WHERE server_id = ?
ON CONFLICT(server_id, username, date) DO UPDATE SET uplink=excluded.uplink, downlink=excluded.downlink`
	_, err := r.db.ExecContext(ctx, stmt, date, serverID)
	return err
}

// CreateUserEmailTrafficSnapshots 把当前 user_email_traffic 的 cycle-delta(uplink/downlink)拍进 email 级快照表。
// 与 CreateUserTrafficSnapshots 同模式,只是粒度到 (server_id, email)。同日多次跑按 ON CONFLICT 覆盖。
func (r *TrafficRepository) CreateUserEmailTrafficSnapshots(ctx context.Context, serverID int64, date string) error {
	const stmt = `
INSERT INTO user_email_traffic_snapshots (server_id, email, date, uplink, downlink)
SELECT server_id, email, ?, uplink, downlink FROM user_email_traffic WHERE server_id = ?
ON CONFLICT(server_id, email, date) DO UPDATE SET uplink=excluded.uplink, downlink=excluded.downlink`
	_, err := r.db.ExecContext(ctx, stmt, date, serverID)
	return err
}

// GetNodeTrafficSnapshots 返回每个 (server_id, tag) **小于等于** date 的最新一份快照。
// 改 = 为 <=:cron 漏跑某一天 / 用户切换 timeRange 落到没快照的日期时,自动 fallback 到上一份
// 有数据的快照,前端"当前累计 - baseline"就能正确算出"自该日期以来的增量"。
// 实现:每组(server_id, tag)按 date DESC 取最大值;旧逻辑 = 时严格 0 行匹配的事故消失。
func (r *TrafficRepository) GetNodeTrafficSnapshots(ctx context.Context, date string) ([]NodeTrafficSnapshot, error) {
	const query = `
SELECT s.id, s.server_id, s.tag, s.type, s.date, s.uplink, s.downlink
FROM node_traffic_snapshots s
JOIN (
    SELECT server_id, tag, MAX(date) AS max_date
    FROM node_traffic_snapshots
    WHERE date <= ?
    GROUP BY server_id, tag
) latest ON s.server_id = latest.server_id AND s.tag = latest.tag AND s.date = latest.max_date`
	rows, err := r.db.QueryContext(ctx, query, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []NodeTrafficSnapshot
	for rows.Next() {
		var s NodeTrafficSnapshot
		if err := rows.Scan(&s.ID, &s.ServerID, &s.Tag, &s.Type, &s.Date, &s.Uplink, &s.Downlink); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// GetUserTrafficSnapshots 同 GetNodeTrafficSnapshots 的语义,但按 (server_id, username) 维度。
func (r *TrafficRepository) GetUserTrafficSnapshots(ctx context.Context, date string) ([]UserTrafficSnapshot, error) {
	const query = `
SELECT s.id, s.server_id, s.username, s.date, s.uplink, s.downlink
FROM user_traffic_snapshots s
JOIN (
    SELECT server_id, username, MAX(date) AS max_date
    FROM user_traffic_snapshots
    WHERE date <= ?
    GROUP BY server_id, username
) latest ON s.server_id = latest.server_id AND s.username = latest.username AND s.date = latest.max_date`
	rows, err := r.db.QueryContext(ctx, query, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []UserTrafficSnapshot
	for rows.Next() {
		var s UserTrafficSnapshot
		if err := rows.Scan(&s.ID, &s.ServerID, &s.Username, &s.Date, &s.Uplink, &s.Downlink); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// UserEmailTrafficSnapshot 是 user_email_traffic_snapshots 的一行(email 级 cycle-delta baseline)。
type UserEmailTrafficSnapshot struct {
	ServerID int64  `json:"server_id"`
	Email    string `json:"email"`
	Date     string `json:"date"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

// GetUserEmailTrafficSnapshots 同 GetUserTrafficSnapshots 语义,但按 (server_id, email) 维度。
// date <= ? + GROUP BY MAX(date) fallback:某天没拍到自动回退上一份,详情减法不会因找不到 baseline 而崩。
func (r *TrafficRepository) GetUserEmailTrafficSnapshots(ctx context.Context, date string) ([]UserEmailTrafficSnapshot, error) {
	const query = `
SELECT s.server_id, s.email, s.date, s.uplink, s.downlink
FROM user_email_traffic_snapshots s
JOIN (
    SELECT server_id, email, MAX(date) AS max_date
    FROM user_email_traffic_snapshots
    WHERE date <= ?
    GROUP BY server_id, email
) latest ON s.server_id = latest.server_id AND s.email = latest.email AND s.date = latest.max_date`
	rows, err := r.db.QueryContext(ctx, query, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []UserEmailTrafficSnapshot
	for rows.Next() {
		var s UserEmailTrafficSnapshot
		if err := rows.Scan(&s.ServerID, &s.Email, &s.Date, &s.Uplink, &s.Downlink); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// CreateServerSystemTrafficSnapshot 拍下"当前 server 的 system_rx_cycle / system_tx_cycle"作为该日 baseline。
// 由 collector.CreateDailySnapshots 在每日 00:00 调用。
// ON CONFLICT 是为了"同一天多次跑"的边角情况(主控重启 + 调度补偿)— 后写覆盖前写。
func (r *TrafficRepository) CreateServerSystemTrafficSnapshot(ctx context.Context, serverID int64, date string) error {
	const stmt = `
INSERT INTO server_system_traffic_snapshots (server_id, date, rx_cycle, tx_cycle)
SELECT id, ?, COALESCE(system_rx_cycle, 0), COALESCE(system_tx_cycle, 0) FROM remote_servers WHERE id = ?
ON CONFLICT(server_id, date) DO UPDATE SET rx_cycle = excluded.rx_cycle, tx_cycle = excluded.tx_cycle`
	_, err := r.db.ExecContext(ctx, stmt, date, serverID)
	return err
}

// GetServerSystemTrafficSnapshots 返回每个 server 在 <= date 的最新一份 baseline。
// 跟 GetNodeTrafficSnapshots 同样的 <= ? + GROUP BY MAX(date) fallback 模式 —
// 某天 snapshot 没跑(主控当时离线 / 服务器没数据)时自动回退到上一份有数据的快照,
// 减法不会因为找不到 baseline 而崩。
func (r *TrafficRepository) GetServerSystemTrafficSnapshots(ctx context.Context, date string) ([]ServerSystemTrafficSnapshot, error) {
	const query = `
SELECT s.server_id, s.date, s.rx_cycle, s.tx_cycle
FROM server_system_traffic_snapshots s
JOIN (
    SELECT server_id, MAX(date) AS max_date
    FROM server_system_traffic_snapshots
    WHERE date <= ?
    GROUP BY server_id
) latest ON s.server_id = latest.server_id AND s.date = latest.max_date`
	rows, err := r.db.QueryContext(ctx, query, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ServerSystemTrafficSnapshot
	for rows.Next() {
		var s ServerSystemTrafficSnapshot
		if err := rows.Scan(&s.ServerID, &s.Date, &s.RxCycle, &s.TxCycle); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// MigrateXraySnapshotsToSystem 在 server.traffic_source 从 xray 切到 system 时调用,
// 把 xray 流量的"当前累计 + daily snapshot 历史"完整搬到 system 维度,让切换后:
//   - server.traffic_used 显示 = xray 总累计(等同切换前 xray 视角)
//   - 服务器视图 today / week / month 三个时间按钮立即可用(每个日期都有 baseline)
//
// 三步事务:
//  1. system_rx_cycle / system_tx_cycle = SUM(downlink) / SUM(uplink) FROM node_traffic
//     → mode=both 时 cycle 和 = SUM(uplink+downlink) = xray total
//  2. **traffic_used_offset = 0**(关键!): 历史 bug 防御 + 语义复位
//     之前版本只 SET cycle 没动 offset → 切换瞬间 handler 算的 offset(基于"system 真实小累加")
//     跟 migrate 后 cycle(= xray total)脱节 → traffic_used = cycle + offset 翻倍。
//     reset offset = 0 意味着 server.traffic_used = cycle 单独,跟 xray 视角自然对齐。
//     用户后续若要校准已用流量,通过 dialog 显式填入(handler 的 if req.TrafficUsed != nil 路径)。
//  3. server_system_traffic_snapshots 按 node_traffic_snapshots 每日聚合填充
//     → 之后 daily snapshot job 继续每天 00:00 拍新行
//
// 上一轮切换的 server 缺少这步迁移 → daily snapshot baseline 全 0 + offset 错锁 → 翻倍 bug,
// 启动 backfill goroutine 用本函数补齐。
func (r *TrafficRepository) MigrateXraySnapshotsToSystem(ctx context.Context, serverID int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}

	// Step A+B 合一: cycle SET = xray 累计;offset 复位为 0(避免历史 bug 锁定的脱节 offset)
	const updateCycleStmt = `
UPDATE remote_servers SET
  system_rx_cycle = COALESCE((SELECT SUM(downlink) FROM node_traffic WHERE server_id = ?), 0),
  system_tx_cycle = COALESCE((SELECT SUM(uplink)   FROM node_traffic WHERE server_id = ?), 0),
  traffic_used_offset = 0,
  system_traffic_updated_at = CURRENT_TIMESTAMP,
  updated_at = CURRENT_TIMESTAMP
WHERE id = ?`
	if _, err := r.db.ExecContext(ctx, updateCycleStmt, serverID, serverID, serverID); err != nil {
		return fmt.Errorf("migrate cycle to xray baseline: %w", err)
	}

	// Step C: 复制 daily snapshot 历史(per server per date 聚合 node 流量)
	const copySnapshotsStmt = `
INSERT INTO server_system_traffic_snapshots (server_id, date, rx_cycle, tx_cycle)
SELECT server_id, date, COALESCE(SUM(downlink), 0), COALESCE(SUM(uplink), 0)
FROM node_traffic_snapshots
WHERE server_id = ?
GROUP BY date
ON CONFLICT(server_id, date) DO UPDATE SET
  rx_cycle = excluded.rx_cycle,
  tx_cycle = excluded.tx_cycle`
	if _, err := r.db.ExecContext(ctx, copySnapshotsStmt, serverID); err != nil {
		return fmt.Errorf("migrate daily snapshots to system: %w", err)
	}

	return nil
}

// CountServerSystemTrafficSnapshots 返回某 server 已有的 system snapshot 行数,
// 启动 backfill 用此判断"上一轮切换时是否漏迁移"(< 7 视为需要补)。
func (r *TrafficRepository) CountServerSystemTrafficSnapshots(ctx context.Context, serverID int64) (int, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_system_traffic_snapshots WHERE server_id = ?`, serverID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count server system snapshots: %w", err)
	}
	return n, nil
}

func (r *TrafficRepository) IsTrafficThresholdNotified(ctx context.Context, serverID int64) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_threshold_notified WHERE server_id = ?`, serverID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *TrafficRepository) MarkTrafficThresholdNotified(ctx context.Context, serverID int64) error {
	_, err := r.db.ExecContext(ctx, `INSERT OR REPLACE INTO traffic_threshold_notified (server_id, notified_at) VALUES (?, CURRENT_TIMESTAMP)`, serverID)
	return err
}

func (r *TrafficRepository) ClearTrafficThresholdNotified(ctx context.Context, serverID int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM traffic_threshold_notified WHERE server_id = ?`, serverID)
	return err
}

// ClaimUserTrafficThresholdNotification atomically claims the 80% notification
// for one user's current limit. Repeated checks for the same limit return false;
// changing the limit creates a fresh claim without waiting for a cycle reset.
func (r *TrafficRepository) ClaimUserTrafficThresholdNotification(ctx context.Context, username string, limitBytes int64) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" || limitBytes <= 0 {
		return false, errors.New("username and positive limit are required")
	}
	result, err := r.db.ExecContext(ctx, `
INSERT INTO user_traffic_threshold_notified (username, limit_bytes, notified_at)
VALUES (?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(username) DO UPDATE SET
    limit_bytes = excluded.limit_bytes,
    notified_at = CURRENT_TIMESTAMP
WHERE user_traffic_threshold_notified.limit_bytes != excluded.limit_bytes`, username, limitBytes)
	if err != nil {
		return false, fmt.Errorf("claim user traffic threshold notification: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("claim user traffic threshold rows affected: %w", err)
	}
	return rows > 0, nil
}

func (r *TrafficRepository) ClearUserTrafficThresholdNotification(ctx context.Context, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_traffic_threshold_notified WHERE username = ?`, strings.TrimSpace(username))
	return err
}

func (r *TrafficRepository) SetUserTOTPSecret(ctx context.Context, username, secret string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET totp_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, secret, username)
	return err
}

func (r *TrafficRepository) EnableUserTOTP(ctx context.Context, username, recoveryCodes string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET totp_enabled = 1, recovery_codes = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`, recoveryCodes, username)
	return err
}

func (r *TrafficRepository) DisableUserTOTP(ctx context.Context, username string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET totp_enabled = 0, totp_secret = '', recovery_codes = '[]', updated_at = CURRENT_TIMESTAMP WHERE username = ?`, username)
	return err
}

// OverrideScript CRUD

func (r *TrafficRepository) ListOverrideScripts(ctx context.Context, username string, hook string) ([]OverrideScript, error) {
	query := `SELECT id, username, name, hook, content, enabled, sort_order, created_at, updated_at
		FROM override_scripts WHERE username = ?`
	args := []interface{}{username}

	if hook != "" {
		query += " AND hook = ?"
		args = append(args, hook)
	}
	query += " ORDER BY sort_order ASC, id ASC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scripts []OverrideScript
	for rows.Next() {
		var s OverrideScript
		if err := rows.Scan(&s.ID, &s.Username, &s.Name, &s.Hook, &s.Content, &s.Enabled, &s.SortOrder, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		scripts = append(scripts, s)
	}
	return scripts, rows.Err()
}

func (r *TrafficRepository) GetOverrideScript(ctx context.Context, id int64, username string) (*OverrideScript, error) {
	var s OverrideScript
	err := r.db.QueryRowContext(ctx,
		`SELECT id, username, name, hook, content, enabled, sort_order, created_at, updated_at
		FROM override_scripts WHERE id = ? AND username = ?`, id, username).Scan(
		&s.ID, &s.Username, &s.Name, &s.Hook, &s.Content, &s.Enabled, &s.SortOrder, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *TrafficRepository) CreateOverrideScript(ctx context.Context, s *OverrideScript) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		`INSERT INTO override_scripts (username, name, hook, content, enabled, sort_order) VALUES (?, ?, ?, ?, ?, ?)`,
		s.Username, s.Name, s.Hook, s.Content, s.Enabled, s.SortOrder)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (r *TrafficRepository) UpdateOverrideScript(ctx context.Context, s *OverrideScript) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE override_scripts SET name = ?, hook = ?, content = ?, enabled = ?, sort_order = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND username = ?`,
		s.Name, s.Hook, s.Content, s.Enabled, s.SortOrder, s.ID, s.Username)
	return err
}

func (r *TrafficRepository) DeleteOverrideScript(ctx context.Context, id int64, username string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM override_scripts WHERE id = ? AND username = ?`, id, username)
	return err
}
