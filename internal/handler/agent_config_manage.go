package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/ddns"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/traffic"
)

// randReader 是用于生成安全令牌的加密读取器
var randReader io.Reader = rand.Reader

// base64URLEncoding 用于 URL 安全的 base64 编码
var base64URLEncoding = base64.URLEncoding

// The Agent hard-stops its detached cleanup runner no later than 360 seconds
// after dispatch. Keep one additional minute for dispatch, scheduling and the
// final callback request so a completed uninstall cannot become an orphaned
// panel record merely because the panel stopped waiting too early.
const agentUninstallCallbackWaitTimeout = 7 * time.Minute
const remoteServerDeleteLeaseAcquireTimeout = 60 * time.Second
const agentUninstallPreDispatchTimeout = 2 * time.Minute
const remoteServerDeleteCommitTimeout = 15 * time.Second

const AgentUninstallCompletePath = "/api/remote/agent/uninstall-complete"

type XrayServerHandler struct {
	repo                     *storage.TrafficRepository
	collector                *traffic.Collector
	limiterPusher            *LimiterConfigPusher
	remoteManager            *RemoteManageHandler
	wsHandler                *RemoteWSHandler
	probeStore               *ProbeMetricsStore
	crypto                   *CryptoConfig
	capabilityManager        *capabilities.Manager
	ddnsManager              *ddns.Manager
	managementProbeMu        sync.Mutex
	managementProbes         map[int64]time.Time
	agentUninstallMu         sync.Mutex
	agentUninstallPending    map[string]*agentUninstallPending
	agentUninstallTimeout    time.Duration
	serverDeleteLeaseTimeout time.Duration
}

func (h *XrayServerHandler) SetWSHandler(ws *RemoteWSHandler) {
	h.wsHandler = ws
}

// SetProbeMetricsStore injects the volatile live host-health cache shared by
// authenticated Agent reports. It is optional for compatibility with focused
// handler tests and older startup wiring.
func (h *XrayServerHandler) SetProbeMetricsStore(store *ProbeMetricsStore) {
	h.probeStore = store
}

func (h *XrayServerHandler) SetDDNSManager(m *ddns.Manager) {
	h.ddnsManager = m
}

func NewXrayServerHandler(repo *storage.TrafficRepository, collector *traffic.Collector, crypto *CryptoConfig) *XrayServerHandler {
	return &XrayServerHandler{
		repo:                     repo,
		collector:                collector,
		crypto:                   crypto,
		managementProbes:         make(map[int64]time.Time),
		agentUninstallPending:    make(map[string]*agentUninstallPending),
		agentUninstallTimeout:    agentUninstallCallbackWaitTimeout,
		serverDeleteLeaseTimeout: remoteServerDeleteLeaseAcquireTimeout,
	}
}

func (h *XrayServerHandler) SetLimiterPusher(p *LimiterConfigPusher) {
	h.limiterPusher = p
}

func (h *XrayServerHandler) SetRemoteManager(rm *RemoteManageHandler) {
	h.remoteManager = rm
}

func (h *XrayServerHandler) SetCapabilityManager(manager *capabilities.Manager) {
	h.capabilityManager = manager
}

// 远程服务器管理API

// RemoteServerCreateRequest代表创建远程服务器的请求
type RemoteServerCreateRequest struct {
	Name              string `json:"name"`
	TrafficLimit      int64  `json:"traffic_limit"`       // 流量限制（以字节为单位）
	TrafficUsedOffset int64  `json:"traffic_used_offset"` // 手动偏移校准
	TrafficResetDay   int    `json:"traffic_reset_day"`   // 要重置的月份日期 (1-31)
	IPAddress         string `json:"ip_address"`          // 子服务器 IP 地址
	ConnectionMode    string `json:"connection_mode"`     // push | pull | websocket
	ListenPort        int    `json:"listen_port"`         // Agent HTTP 监听端口(0 = 用默认 23889);通过 install 脚本注入 RELAYDOCK_LISTEN_PORT
	PullAddress       string `json:"pull_address"`        // 对于pull模式
	PullPort          int    `json:"pull_port"`           // 对于pull模式
	PullToken         string `json:"pull_token"`          // 对于pull模式
	StealSelf         bool   `json:"steal_self"`          // 代理安装后自动安装xray+nginx
	FrontService      string `json:"front_service"`       // xray | nginx 使用nginx还是xray做443前置（nginx 保留，尚未启用）
	Domain            string `json:"domain"`              // 服务器域（443模式）
	Use443            bool   `json:"use_443"`             // 使用 443 端口与 nginx 隧道
	StealMode         string `json:"steal_mode"`          // "tunnel" | "fallback"，默认 tunnel
	NginxMode         string `json:"nginx_mode"`          // "managed" | "reuse_existing"
	SiteType          string `json:"site_type"`           // "static" | "proxy"
	SiteValue         string `json:"site_value"`          // 静态路径或反向代理地址
	XrayMode          string `json:"xray_mode"`           // "external" 或 "embedded"，默认 "external"
	TrafficStatsMode  string `json:"traffic_stats_mode"`  // "both"(默认) | "upload" | "download" — 节点流量统计方向
	TrafficSource     string `json:"traffic_source"`      // "xray"(默认,聚合 node_traffic) | "system"(用 agent 上报系统级网卡累计)
	IPv6Enabled       *bool  `json:"ipv6_enabled"`        // 指针:nil=默认启用;false=创建时即关闭 v6
	// DDNS 自动同步:开启时 PullAddress 必须是域名,agent 上报新 IP 时自动更新 A/AAAA 记录。
	// DDNSProviderID=0 → 自动模式(按 PullAddress 找匹配的通配符证书,取证书的 dns_provider_id);>0 → 显式指定
	DDNSEnabled    bool  `json:"ddns_enabled"`
	DDNSProviderID int64 `json:"ddns_provider_id"`
}

// RemoteServerResponse 表示带有远程服务器数据的响应
type RemoteServerResponse struct {
	Success        bool                  `json:"success"`
	Message        string                `json:"message"`
	DeletionStatus string                `json:"deletion_status,omitempty"`
	Server         *storage.RemoteServer `json:"server,omitempty"`
	InstallCommand string                `json:"install_command,omitempty"`
	IsLocal        bool                  `json:"is_local,omitempty"`
}

// RemoteServerInboundInfo 表示远程服务器的入站信息
type RemoteServerInboundInfo struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

// RemoteServerExtended 表示具有附加流量和入站信息的远程服务器
type RemoteServerExtended struct {
	storage.RemoteServer
	TrafficUsed      int64                     `json:"traffic_used"`
	CountryCode      string                    `json:"country_code,omitempty"`
	CPUPct           *float64                  `json:"cpu_pct,omitempty"`
	LoadAvg          string                    `json:"loadavg,omitempty"`
	MemUsed          *int64                    `json:"mem_used,omitempty"`
	MemTotal         *int64                    `json:"mem_total,omitempty"`
	DiskUsed         *int64                    `json:"disk_used,omitempty"`
	DiskTotal        *int64                    `json:"disk_total,omitempty"`
	Inbounds         []RemoteServerInboundInfo `json:"inbounds"`
	Encrypted        bool                      `json:"encrypted"`
	WsConnected      bool                      `json:"ws_connected"`
	AgentUninstallV2 *bool                     `json:"agent_uninstall_v2,omitempty"`
}

// RemoteServersListResponse 表示所有远程服务器的响应
type RemoteServersListResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Servers []RemoteServerExtended `json:"servers,omitempty"`
}

// RemoteServerDeleteRequest 表示删除远程服务器的请求
type RemoteServerDeleteRequest struct {
	ID             int64 `json:"id"`
	UninstallAgent bool  `json:"uninstall_agent,omitempty"`
}

type RemoteServerDeleteImpactServer struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Ownership        string `json:"ownership"`
	Online           bool   `json:"online"`
	AgentUninstallV2 *bool  `json:"agent_uninstall_v2"`
	XrayMode         string `json:"xray_mode"`
	WarpInstalled    bool   `json:"warp_installed"`
}

type RemoteServerDeleteImpactResponse struct {
	Success      bool                              `json:"success"`
	Message      string                            `json:"message,omitempty"`
	Server       RemoteServerDeleteImpactServer    `json:"server"`
	Counts       storage.RemoteServerDeleteCounts  `json:"counts"`
	Blocker      *string                           `json:"blocker"`
	DeletionTask *storage.RemoteServerDeletionTask `json:"deletion_task,omitempty"`
}

// RemoteServerUpdateRequest 表示更新远程服务器的请求
type RemoteServerUpdateRequest struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Domain           string `json:"domain"`
	TrafficLimit     int64  `json:"traffic_limit"`
	TrafficResetDay  int    `json:"traffic_reset_day"`
	TrafficUsed      *int64 `json:"traffic_used"`
	ConnectionMode   string `json:"connection_mode"`
	ListenPort       int    `json:"listen_port"` // Agent HTTP 监听端口;安装后不可单独修改
	PullAddress      string `json:"pull_address"`
	PullPort         int    `json:"pull_port"`
	PullToken        string `json:"pull_token"`
	XrayMode         string `json:"xray_mode"`
	NginxMode        string `json:"nginx_mode"`
	TrafficStatsMode string `json:"traffic_stats_mode"` // both | upload | download
	TrafficSource    string `json:"traffic_source"`     // xray | system
	IPv6Enabled      *bool  `json:"ipv6_enabled"`       // 指针:nil=不改;false=关闭(服务管理不显示 v6、加节点不可选 v6)
	// DDNS 同 Create
	DDNSEnabled    bool  `json:"ddns_enabled"`
	DDNSProviderID int64 `json:"ddns_provider_id"`
}

// 生成加密安全令牌
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64Encode(b), nil
}

// randRead 是一个允许在测试中进行模拟的变量
var randRead = func(b []byte) (int, error) {
	return randReader.Read(b)
}

// base64Encode 将字节编码为 Base64 URL 安全字符串
var base64Encode = func(b []byte) string {
	return base64URLEncoding.EncodeToString(b)
}

// 返回所有远程服务器
func (h *XrayServerHandler) ListRemoteServers(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "GET" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	resp := h.BuildRemoteServersList(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// BuildRemoteServersList 组装服务器列表响应(状态/网速/流量/入站),供 HTTP handler 与浏览器 WS 推送共用。
func (h *XrayServerHandler) BuildRemoteServersList(ctx context.Context) RemoteServersListResponse {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return RemoteServersListResponse{
			Success: false,
			Message: fmt.Sprintf("获取服务器列表失败: %s", err.Error()),
		}
	}

	// 使用流量和入站信息构建扩展服务器列表
	extendedServers := make([]RemoteServerExtended, 0, len(servers))
	for _, server := range servers {
		extended := RemoteServerExtended{
			RemoteServer: server,
			Inbounds:     []RemoteServerInboundInfo{},
		}
		if h.wsHandler != nil {
			extended.Encrypted = h.wsHandler.IsConnectionEncrypted(server.Token)
			extended.WsConnected = h.wsHandler.IsConnected(server.Token)
			if connection, connected := h.wsHandler.GetConnectionByServerID(server.ID); connected &&
				server.Status == storage.RemoteServerStatusConnected && !server.IsFederated {
				capable := connection.Capabilities.AgentUninstallV2
				extended.AgentUninstallV2 = &capable
			}
		}
		extended.CountryCode = cachedOrQueueGeoIPCountryCode(server.IPAddress)
		if extended.CountryCode == "" && server.IPv6Enabled {
			extended.CountryCode = cachedOrQueueGeoIPCountryCode(server.IPAddressV6)
		}
		if ((h.wsHandler != nil && h.wsHandler.IsConnected(server.Token)) || server.Status == storage.RemoteServerStatusConnected) && h.probeStore != nil {
			if snapshot, ok := h.probeStore.Snapshot(server.ID); ok {
				fillRemoteServerSystemMetrics(&extended, snapshot)
			}
		}

		trafficUsed, _ := h.repo.GetServerTrafficUsed(ctx, server.ID)
		extended.TrafficUsed = trafficUsed + server.TrafficUsedOffset

		nodeTraffic, err := h.repo.GetNodeTrafficByServer(ctx, server.ID)
		if err == nil {
			for _, nt := range nodeTraffic {
				if nt.Type == "inbound" && nt.Tag != "api" {
					extended.Inbounds = append(extended.Inbounds, RemoteServerInboundInfo{
						Tag:      nt.Tag,
						Protocol: "",
						Port:     0,
						Uplink:   nt.TotalUplink,
						Downlink: nt.TotalDownlink,
					})
				}
			}
		}

		// 列表不再明文回传令牌(Encrypted/WsConnected 已在上面用原始 server.Token 算好)。
		// 前端需要时走 reveal-token 按单台显式获取。
		maskServerSecrets(&extended.RemoteServer)
		extendedServers = append(extendedServers, extended)
	}

	return RemoteServersListResponse{
		Success: true,
		Servers: extendedServers,
	}
}

func fillRemoteServerSystemMetrics(dst *RemoteServerExtended, snapshot ProbeSysSnapshot) {
	if dst == nil {
		return
	}
	if snapshot.HasCPU {
		value := snapshot.CPUPct
		dst.CPUPct = &value
		dst.LoadAvg = snapshot.LoadAvg
	}
	if snapshot.HasMem {
		used, total := snapshot.MemUsed, snapshot.MemTotal
		dst.MemUsed, dst.MemTotal = &used, &total
	}
	if snapshot.HasDisk {
		used, total := snapshot.DiskUsed, snapshot.DiskTotal
		dst.DiskUsed, dst.DiskTotal = &used, &total
	}
}

// maskServerSecrets 清空响应里的令牌字段。列表/详情接口不再明文回传 token,
// 需要时由前端走 /api/admin/remote-servers/reveal-token 按单台显式获取(T2#6 token 脱敏)。
func maskServerSecrets(s *storage.RemoteServer) {
	if s == nil {
		return
	}
	s.Token = ""
	s.PullToken = ""
	s.AgentToken = ""
}

// RevealServerToken 按需返回单台服务器的令牌(管理员鉴权)。前端仅在用户点击
// "复制安装命令 / 复制 Token" 时调用,避免 token 随列表轮询批量外泄到浏览器历史/日志/屏幕。
func (h *XrayServerHandler) RevealServerToken(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "GET" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "invalid server_id"})
		return
	}
	ctx := r.Context()
	server, err := h.repo.GetRemoteServer(ctx, id)
	if err != nil || server == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "server not found"})
		return
	}
	// The one-time download ticket is only an envelope around the server's
	// long-lived credential. GetRemoteInstallScript intentionally rejects that
	// ticket when the underlying credential has expired, so renew it before
	// issuing a ticket that could otherwise be unusable. Use the ticket TTL as
	// the renewal window to guarantee the credential remains valid for the
	// entire lifetime of the command we return.
	if remoteServerTokenNeedsInstallRenewal(server, time.Now()) {
		leasedCtx, release, leaseErr := h.repo.AcquireRemoteServerExclusiveMutationLease(ctx, id)
		if leaseErr != nil {
			w.Header().Set("Content-Type", "application/json")
			if errors.Is(leaseErr, storage.ErrRemoteInstallationActive) {
				w.WriteHeader(stdhttp.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "server installation is active; retry after it completes"})
				return
			}
			w.WriteHeader(stdhttp.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "unable to acquire server mutation lease"})
			return
		}
		defer release()
		ctx = leasedCtx

		// Another reveal request may have renewed the token while this request
		// waited for the exclusive lease.
		server, err = h.repo.GetRemoteServer(ctx, id)
		if err != nil || server == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "server not found"})
			return
		}
		if remoteServerTokenNeedsInstallRenewal(server, time.Now()) {
			oldToken := server.Token
			newToken, expiresAt, resetErr := h.repo.ResetServerToken(ctx, id)
			if resetErr != nil || expiresAt == nil {
				log.Printf("[Reveal Token] Failed to renew install credential for server %d: %v", id, resetErr)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(stdhttp.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "failed to renew server token"})
				return
			}
			server.Token = newToken
			server.TokenExpiresAt = expiresAt

			if guardErr := syncRemoteExpiryGuardAgentToken(ctx, h.repo, id, newToken); guardErr != nil {
				log.Printf("[Reveal Token] Failed to synchronize expiry guard token for server %d: %v", id, guardErr)
			}
			if h.wsHandler != nil && h.wsHandler.IsConnected(oldToken) {
				if pushErr := h.wsHandler.SendTokenUpdate(oldToken, newToken, *expiresAt); pushErr != nil {
					log.Printf("[Reveal Token] Failed to push renewed token to server %d: %v", id, pushErr)
				}
			}
		}
	}
	var panelSourceIPs []string
	if server.ConnectionMode != storage.ConnectionModePull {
		panelSourceIPs, err = configuredPanelSourceIPs()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "trusted panel source IPs are not configured"})
			return
		}
	}
	installRequest := r.Clone(ctx)
	installCommand, err := h.buildRemoteInstallCommand(installRequest, server, panelSourceIPs, server.StealSelf, "xray")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "failed to build install command"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":         true,
		"token":           server.Token,
		"pull_token":      server.PullToken,
		"agent_token":     server.AgentToken,
		"install_command": installCommand,
	})
}

func remoteServerTokenNeedsInstallRenewal(server *storage.RemoteServer, now time.Time) bool {
	return server != nil && server.TokenExpiresAt != nil && !server.TokenExpiresAt.After(now.Add(remoteInstallTicketTTL))
}

// 使用生成的令牌创建一个新的远程服务器
// validateSiteValue 校验偷自己/fallback 站点的反代地址。site_type=proxy 时,site_value 必须是
// 合法的反代目标(host:port 或带 scheme 的 URL);host 形如"纯数字+点"却不是合法 IPv4 时判为 typo
// (如 127.0.01 少一个 0)。static(本地静态路径)与空值跳过校验。
func validateSiteValue(siteType, siteValue string) error {
	v := strings.TrimSpace(siteValue)
	if v == "" || siteType != "proxy" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		if u, err = url.Parse("http://" + v); err != nil || u.Host == "" {
			return fmt.Errorf("反代地址格式无效: %s", v)
		}
	}
	host := u.Hostname()
	if isDottedNumeric(host) && net.ParseIP(host) == nil {
		return fmt.Errorf("反代地址 IP 无效: %s(如 127.0.01 应为 127.0.0.1)", host)
	}
	return nil
}

// isDottedNumeric 判断 s 是否仅由数字和点组成,用于识别"看起来是 IPv4 但写错"的 host。
func isDottedNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// shellSingleQuote returns one POSIX-shell argument without allowing the value
// to terminate the surrounding command. Install commands are copied verbatim
// into a root shell, so every dynamic value must pass through this helper.
func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func shellCommentText(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// effectiveRemoteInstallMasterURL returns the exact normalized panel URL that
// is embedded in an installer. The bool reports whether it came from the
// authoritative master_url setting rather than the current admin request.
func (h *XrayServerHandler) effectiveRemoteInstallMasterURL(ctx context.Context, r *stdhttp.Request) (string, bool, error) {
	if h == nil || h.repo == nil {
		return "", false, errors.New("remote server repository is unavailable")
	}
	if masterURL, err := h.repo.GetSystemSetting(ctx, "master_url"); err == nil && strings.TrimSpace(masterURL) != "" {
		normalized, normalizeErr := normalizeMasterURL(masterURL)
		if normalizeErr != nil {
			return "", false, fmt.Errorf("configured master URL is invalid: %w", normalizeErr)
		}
		if !masterURLAllowsNodeInstall(normalized) {
			return "", false, errors.New("remote node installation requires an HTTPS master URL")
		}
		return normalized, true, nil
	}
	host := strings.TrimSpace(r.Host)
	scheme := defaultMasterScheme(host, r.TLS != nil)
	normalized, err := normalizeMasterURL(scheme + "://" + host)
	if err != nil {
		return "", false, fmt.Errorf("request host is invalid: %w", err)
	}
	return normalized, false, nil
}

func (h *XrayServerHandler) remoteInstallationPolicyContext(ctx context.Context, r *stdhttp.Request, panelSourceIPs []string) (storage.RemoteInstallationPolicyContext, error) {
	masterURL, _, err := h.effectiveRemoteInstallMasterURL(ctx, r)
	if err != nil {
		return storage.RemoteInstallationPolicyContext{}, err
	}
	return storage.RemoteInstallationPolicyContext{
		PanelSourceIPs:  append([]string(nil), panelSourceIPs...),
		MasterURL:       masterURL,
		MasterPublicKey: h.masterPublicKeyBase64(),
	}, nil
}

func (h *XrayServerHandler) buildRemoteInstallCommand(r *stdhttp.Request, server *storage.RemoteServer, panelSourceIPs []string, stealSelf bool, frontService string) (string, error) {
	if server == nil {
		return "", errors.New("remote server is required")
	}
	if server.ConnectionMode == storage.ConnectionModePull {
		agentToken := server.AgentToken
		if agentToken == "" {
			agentToken = server.PullToken
		}
		return fmt.Sprintf("# pull模式：主服务器将从 %s:%d 拉取流量数据\n# 请确保子服务器已配置 RELAYDOCK_MODE=child RELAYDOCK_CHILD_API_TOKEN=%s", shellCommentText(server.PullAddress), server.PullPort, shellCommentText(agentToken)), nil
	}
	if len(panelSourceIPs) == 0 {
		return "", errors.New("trusted panel source IPs are required")
	}

	serverURL, _, err := h.effectiveRemoteInstallMasterURL(r.Context(), r)
	if err != nil {
		return "", err
	}

	frontService = strings.ToLower(strings.TrimSpace(frontService))
	if frontService != "xray" {
		frontService = "xray"
	}
	installQuery := url.Values{}
	agentConnectionMode := "websocket"
	if server.ConnectionMode == storage.ConnectionModePush {
		agentConnectionMode = "http"
	}
	installQuery.Set("connection_mode", agentConnectionMode)
	if stealSelf {
		installQuery.Set("steal_self", "1")
		installQuery.Set("front_service", frontService)
	}
	if server.NginxMode == "reuse_existing" {
		installQuery.Set("nginx_mode", "reuse_existing")
	}
	if server.XrayMode == "embedded" {
		installQuery.Set("xray_mode", "embedded")
	}
	if server.ListenPort > 0 {
		installQuery.Set("listen_port", strconv.Itoa(server.ListenPort))
	}
	installScriptURL := serverURL + "/api/remote/install.sh"
	if encodedQuery := installQuery.Encode(); encodedQuery != "" {
		installScriptURL += "?" + encodedQuery
	}

	installTicket, err := generateSecureToken()
	if err != nil {
		return "", fmt.Errorf("generate install ticket: %w", err)
	}
	installTicket = remoteInstallTicketPrefix + installTicket
	if err := h.repo.CreateRemoteServerInstallTicket(r.Context(), server.ID, installTicket, time.Now().Add(remoteInstallTicketTTL)); err != nil {
		return "", fmt.Errorf("create install ticket: %w", err)
	}
	panelEnvironment := "ARCWAY_PANEL_IPS=" + shellSingleQuote(strings.Join(panelSourceIPs, " "))
	authorizationHeader := shellSingleQuote("Authorization: Bearer " + installTicket)
	installURLArgument := shellSingleQuote(installScriptURL)
	downloadCommand := fmt.Sprintf(`set -eu; installer="$(mktemp /tmp/arcway-node-install.XXXXXX)"; trap 'rm -f "$installer"' EXIT; trap 'exit 130' HUP INT TERM; curl -fsSL -H %s -o "$installer" %s;`, authorizationHeader, installURLArgument)
	return fmt.Sprintf("(%s env %s bash \"$installer\")", downloadCommand, panelEnvironment), nil
}

func (h *XrayServerHandler) CreateRemoteServer(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "POST" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	var req RemoteServerCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "无效的请求参数",
		})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "服务器名称不能为空",
		})
		return
	}

	if err := validateSiteValue(req.SiteType, req.SiteValue); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}
	if !storage.IsValidRemoteManagementListenPort(req.ListenPort) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "Agent 监听端口必须为 1024-65534，0 表示使用默认端口",
		})
		return
	}

	ctx := r.Context()
	reqDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Domain)), ".")
	if reqDomain != "" && (net.ParseIP(reqDomain) != nil || !validMasterHostname(reqDomain)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "节点域名格式无效"})
		return
	}

	stealMode := strings.TrimSpace(req.StealMode)
	if stealMode == "" {
		stealMode = "default"
	}
	if stealMode != "default" && stealMode != "tunnel" && stealMode != "fallback" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "接管模式必须为 default、tunnel 或 fallback"})
		return
	}
	stealSelf := stealMode == "tunnel" || stealMode == "fallback"
	if req.StealSelf != stealSelf || req.Use443 != stealSelf {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "接管模式、443 部署和安装授权必须保持一致"})
		return
	}
	if stealSelf && reqDomain == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "Tunnel/Fallback 接管模式必须填写节点域名"})
		return
	}
	nginxMode := strings.TrimSpace(req.NginxMode)
	if nginxMode == "" {
		nginxMode = "managed"
	}
	if nginxMode != "managed" && nginxMode != "reuse_existing" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "Nginx 模式必须为 managed 或 reuse_existing"})
		return
	}
	relaydockDomain := getDomainFromMasterURL(h.repo, ctx)

	isLocalByAddr := false
	relaydockIPs := resolveIPs(relaydockDomain)
	relaydockIPSet := make(map[string]struct{})
	for _, ip := range relaydockIPs {
		relaydockIPSet[ip] = struct{}{}
	}
	checkAddrLocal := func(addr string) bool {
		for _, ip := range resolveIPs(addr) {
			if _, ok := relaydockIPSet[ip]; ok {
				return true
			}
		}
		return false
	}
	if relaydockDomain != "" {
		if req.IPAddress != "" {
			isLocalByAddr = checkAddrLocal(req.IPAddress)
		}
		if !isLocalByAddr && req.PullAddress != "" {
			isLocalByAddr = checkAddrLocal(req.PullAddress)
		}
	}

	if reqDomain != "" && relaydockDomain != "" && reqDomain == relaydockDomain && !isLocalByAddr {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "域名不能与 RelayDock 安装域名相同",
		})
		return
	}

	// 生成安全令牌
	token, err := generateSecureToken()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: fmt.Sprintf("生成Token失败: %s", err.Error()),
		})
		return
	}

	// 生成用于拉取/API 身份验证的代理令牌
	agentToken := req.PullToken
	if agentToken == "" {
		agentToken, err = generateSecureToken()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: fmt.Sprintf("生成Agent Token失败: %s", err.Error()),
			})
			return
		}
	}

	// 如果没有指定则设置默认连接模式
	connectionMode := req.ConnectionMode
	if connectionMode == "" {
		connectionMode = storage.ConnectionModePush
	}
	var panelSourceIPs []string
	if connectionMode != storage.ConnectionModePull {
		panelSourceIPs, err = configuredPanelSourceIPs()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: fmt.Sprintf("主控出口 IP 未配置: %v", err),
			})
			return
		}
	}

	xrayMode := req.XrayMode
	if xrayMode != "embedded" {
		xrayMode = "external"
	}
	if xrayMode == "embedded" && h.capabilityManager != nil && !h.capabilityManager.HasFeature(capabilities.FeatureEmbeddedXray) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusForbidden)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "当前构建未启用内嵌 Xray"})
		return
	}

	// Agent 与 expiry guard 使用连续端口，因此只接受 0 或 1024-65534。
	listenPort := req.ListenPort

	resetDay := req.TrafficResetDay
	if resetDay < 0 || resetDay > 31 {
		resetDay = 0
	}
	trafficUsedOffset := req.TrafficUsedOffset
	if trafficUsedOffset < 0 {
		trafficUsedOffset = 0
	}
	trafficLimit := req.TrafficLimit
	if trafficLimit < 0 {
		trafficLimit = 0
	}
	trafficStatsMode := strings.TrimSpace(req.TrafficStatsMode)
	if trafficStatsMode != "upload" && trafficStatsMode != "download" && trafficStatsMode != "max" {
		trafficStatsMode = "both"
	}
	// 新建 server 默认 system — VPS 计费口径,跟 UI 默认保持一致。
	// 前端 dialog 默认勾选「系统网卡流量」;API 直调时 req 没传 traffic_source 也走 system。
	// 仅 req 显式传 "xray" 才走 xray 路径(中转机 / 需要协议级口径的特殊场景)。
	trafficSource := strings.TrimSpace(req.TrafficSource)
	if trafficSource != "xray" {
		trafficSource = "system"
	}

	// DDNS 开启时必须用域名 — agent 上报 IP 漂移后,DDNS 把这个域名的 A/AAAA 指到新 IP
	if req.DDNSEnabled {
		pa := strings.TrimSpace(req.PullAddress)
		if pa == "" || net.ParseIP(pa) != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusBadRequest)
			json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "DDNS 开启时,服务器地址必须填域名"})
			return
		}
		// 显式 provider_id 必须存在
		if req.DDNSProviderID > 0 {
			if _, perr := h.repo.GetDNSProvider(ctx, req.DDNSProviderID); perr != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(stdhttp.StatusBadRequest)
				json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: fmt.Sprintf("DDNS 服务商不存在: %v", perr)})
				return
			}
		}
		// provider_id=0 自动模式:必须能找到匹配证书,否则没办法推断 provider
		if req.DDNSProviderID == 0 {
			if _, cerr := h.repo.FindCertificateForDomain(ctx, pa); cerr != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(stdhttp.StatusBadRequest)
				json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: fmt.Sprintf("DDNS 自动模式:找不到匹配 %s 的通配符证书,请先签发证书或显式选择 DNS 服务商", pa)})
				return
			}
		}
	}

	server := &storage.RemoteServer{
		Name:              req.Name,
		Token:             token,
		Status:            storage.RemoteServerStatusPending,
		IPAddress:         req.IPAddress,
		ConnectionMode:    connectionMode,
		ListenPort:        listenPort,
		PullAddress:       req.PullAddress,
		PullPort:          req.PullPort,
		PullToken:         agentToken,
		Domain:            reqDomain,
		Use443:            stealSelf,
		StealSelf:         stealSelf,
		StealMode:         stealMode,
		NginxMode:         nginxMode,
		SiteType:          req.SiteType,
		SiteValue:         req.SiteValue,
		XrayMode:          xrayMode,
		TrafficLimit:      trafficLimit,
		TrafficUsedOffset: trafficUsedOffset,
		TrafficResetDay:   resetDay,
		TrafficStatsMode:  trafficStatsMode,
		TrafficSource:     trafficSource,
		IPv6Enabled:       req.IPv6Enabled == nil || *req.IPv6Enabled, // 默认启用;仅显式 false 才关闭
		DDNSEnabled:       req.DDNSEnabled,
		DDNSProviderID:    req.DDNSProviderID,
	}
	if err := h.repo.CreateRemoteServer(ctx, server); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: fmt.Sprintf("创建服务器失败: %s", err.Error()),
		})
		return
	}
	installCommand, err := h.buildRemoteInstallCommand(r, server, panelSourceIPs, server.StealSelf, req.FrontService)
	if err != nil {
		// Ticket issuance requires the persisted server ID. If it fails, remove the
		// still-pending record so a failed create response cannot leave an orphan.
		if cleanupErr := h.repo.DeleteRemoteServer(context.WithoutCancel(ctx), server.ID); cleanupErr != nil {
			log.Printf("[CreateRemoteServer] remove server after install command failure: %v", cleanupErr)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: fmt.Sprintf("生成安装命令失败: %v", err)})
		return
	}

	// 本机检测：域名解析 IP 与 relaydock_domain 解析 IP 一致则为本机
	isLocal := isLocalByAddr
	if !isLocal && reqDomain != "" && relaydockDomain != "" {
		reqIPs, err1 := net.LookupHost(reqDomain)
		relaydockIPs, err2 := net.LookupHost(relaydockDomain)
		if err1 == nil && err2 == nil {
			relaydockIPSet := make(map[string]struct{})
			for _, ip := range relaydockIPs {
				relaydockIPSet[ip] = struct{}{}
			}
			for _, ip := range reqIPs {
				if _, ok := relaydockIPSet[ip]; ok {
					isLocal = true
					break
				}
			}
		}
	}

	if isLocal {
		if err := deployLocalNginx(reqDomain, h.repo); err != nil {
			log.Printf("[CreateRemoteServer] 本机 Nginx 部署失败: %v", err)
		} else {
			log.Printf("[CreateRemoteServer] 本机 Nginx 部署成功, domain=%s", reqDomain)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RemoteServerResponse{
		Success:        true,
		Message:        "服务器创建成功",
		Server:         server,
		InstallCommand: installCommand,
		IsLocal:        isLocal,
	})
}

type remoteServerExclusiveLeaseResult struct {
	ctx     context.Context
	release func()
	err     error
}

func (h *XrayServerHandler) acquireRemoteServerExclusiveLease(parent context.Context, serverID int64) (context.Context, func(), error) {
	timeout := h.serverDeleteLeaseTimeout
	if timeout <= 0 {
		timeout = remoteServerDeleteLeaseAcquireTimeout
	}
	acquireCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), timeout)
	resultCh := make(chan remoteServerExclusiveLeaseResult, 1)
	keepLease := make(chan bool, 1)
	go func() {
		ctx, release, err := h.repo.AcquireRemoteServerExclusiveMutationLease(acquireCtx, serverID)
		resultCh <- remoteServerExclusiveLeaseResult{ctx: ctx, release: release, err: err}
		if err == nil && release != nil && !<-keepLease {
			release()
		}
	}()

	select {
	case result := <-resultCh:
		keepLease <- result.err == nil
		cancel()
		if result.err != nil {
			return nil, nil, result.err
		}
		// Strip only the acquisition deadline while retaining the repository's
		// lease marker in Context values for reentrant nested mutations.
		return context.WithoutCancel(result.ctx), result.release, nil
	case <-acquireCtx.Done():
		keepLease <- false
		err := acquireCtx.Err()
		cancel()
		return nil, nil, err
	}
}

// 通过 ID 删除远程服务器
func (h *XrayServerHandler) DeleteRemoteServer(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "POST" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	var req RemoteServerDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadRequest, "无效的请求参数")
		return
	}

	if req.ID <= 0 {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadRequest, "无效的服务器ID")
		return
	}
	server, err := h.repo.GetRemoteServer(r.Context(), req.ID)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusNotFound, "服务器不存在")
			return
		}
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "读取服务器失败")
		return
	}
	_, federatedErr := h.repo.GetFederatedServer(r.Context(), server.ID)
	if federatedErr == nil {
		// A shared server is only a local subscription to another panel's
		// resource. Its owner remains solely responsible for the remote Agent.
		h.deleteRemoteServerRecord(w, r.Context(), req.ID, "共享服务器接入关系及本地关联数据已删除")
		return
	}
	if !errors.Is(federatedErr, storage.ErrFederatedServerNotFound) {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "无法确认服务器所有权")
		return
	}
	if !req.UninstallAgent {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadRequest, "删除自有服务器必须同时卸载远端 Agent")
		return
	}
	h.uninstallAgentAndDeleteRemoteServer(w, r, req.ID)
}

func (h *XrayServerHandler) deleteRemoteServerRecord(w stdhttp.ResponseWriter, parent context.Context, serverID int64, successMessage string) {
	leasedCtx, release, err := h.acquireRemoteServerExclusiveLease(parent, serverID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, storage.ErrRemoteInstallationActive) {
			w.WriteHeader(stdhttp.StatusConflict)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: "服务器正在安装，暂不能删除",
			})
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			w.WriteHeader(stdhttp.StatusGatewayTimeout)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "服务器仍有管理操作进行中，删除等待超时"})
			return
		}
		_ = json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "删除服务器失败",
		})
		return
	}
	defer release()
	commitCtx, cancelCommit := context.WithTimeout(leasedCtx, remoteServerDeleteCommitTimeout)
	defer cancelCommit()
	if err := h.repo.DeleteRemoteServer(commitCtx, serverID); err != nil {
		msg := "删除服务器失败"
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			msg = "服务器不存在"
		} else if errors.Is(err, storage.ErrRemoteInstallationActive) {
			msg = "服务器正在安装，暂不能删除"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusConflict)
		} else if errors.Is(err, storage.ErrForwardingConflict) {
			msg = "服务器仍被转发模板或转发规则使用，请先移除相关配置"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusConflict)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: msg,
		})
		return
	}
	h.invalidateDeletedRemoteServer(serverID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RemoteServerResponse{
		Success: true,
		Message: successMessage,
	})
}

// GetRemoteServerDeleteImpact returns the exact local records affected by the
// delete transaction and the current remote-uninstall preconditions. It never
// mutates the Agent or panel data.
func (h *XrayServerHandler) GetRemoteServerDeleteImpact(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != stdhttp.MethodGet {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}
	serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadRequest, "无效的服务器ID")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusNotFound, "服务器不存在")
			return
		}
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "读取服务器失败")
		return
	}
	counts, err := h.repo.GetRemoteServerDeleteCounts(ctx, serverID)
	if err != nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "统计删除影响失败")
		return
	}
	response := RemoteServerDeleteImpactResponse{
		Success: true,
		Server: RemoteServerDeleteImpactServer{
			ID: server.ID, Name: server.Name, Ownership: "owned",
			Online:   server.Status == storage.RemoteServerStatusConnected,
			XrayMode: server.XrayMode, WarpInstalled: server.WarpInstalled,
		},
		Counts: counts,
	}
	if task, taskErr := h.repo.GetRemoteServerDeletionTask(ctx, serverID); taskErr == nil {
		response.DeletionTask = task
	} else if !errors.Is(taskErr, storage.ErrRemoteServerDeletionTaskNotFound) {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "读取删除任务失败")
		return
	}
	if _, fedErr := h.repo.GetFederatedServer(ctx, serverID); fedErr == nil {
		response.Server.Ownership = "shared"
	} else if !errors.Is(fedErr, storage.ErrFederatedServerNotFound) {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "无法确认服务器所有权")
		return
	}
	if err := h.repo.ValidateRemoteServerDeletion(ctx, serverID); err != nil {
		message := "服务器暂不能安全删除: " + err.Error()
		switch {
		case errors.Is(err, storage.ErrForwardingConflict):
			message = "服务器仍被转发模板、转发规则或端口分配使用，请先移除相关配置"
		case errors.Is(err, storage.ErrRemoteInstallationActive):
			message = "服务器正在安装，暂不能删除"
		}
		response.Blocker = &message
	}
	confirmed := response.DeletionTask != nil && response.DeletionTask.Status == storage.RemoteServerDeletionAgentUninstalled
	inProgress := response.DeletionTask != nil && response.DeletionTask.ExpiresAt.After(time.Now().UTC()) &&
		(response.DeletionTask.Status == storage.RemoteServerDeletionDispatched ||
			(response.DeletionTask.Status == storage.RemoteServerDeletionPending && response.DeletionTask.CleanupID != ""))
	if response.Server.Ownership == "owned" && response.Blocker == nil && !confirmed && !inProgress {
		if !response.Server.Online {
			message := "Agent 当前不在线，无法确认并执行完整卸载"
			response.Blocker = &message
		} else {
			capable, capabilityErr := h.agentSupportsSafeUninstall(ctx, serverID)
			if capabilityErr != nil {
				message := "无法确认 Agent 的安全卸载能力: " + capabilityErr.Error()
				response.Blocker = &message
			} else {
				response.Server.AgentUninstallV2 = &capable
				if !capable {
					message := "Agent 版本或运行环境不支持安全卸载，请先升级 Agent"
					response.Blocker = &message
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

type remoteRemovalAcknowledgement struct {
	Success          bool   `json:"success"`
	Installed        *bool  `json:"installed"`
	Uninstalled      bool   `json:"uninstalled"`
	DispatchVerified bool   `json:"dispatch_verified"`
	CleanupID        string `json:"cleanup_id"`
	Message          string `json:"message"`
	Error            string `json:"error"`
}

type agentUninstallDispatchRequest struct {
	CallbackURL   string `json:"callback_url"`
	CallbackToken string `json:"callback_token"`
}

type agentUninstallCallback struct {
	Success   bool   `json:"success"`
	CleanupID string `json:"cleanup_id"`
	Error     string `json:"error,omitempty"`
}

type agentUninstallPending struct {
	serverID int64
	done     chan agentUninstallCallback

	mu                sync.Mutex
	expectedCleanupID string
	active            bool
	completed         bool
}

func (p *agentUninstallPending) setExpectedCleanupID(cleanupID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active {
		return errors.New("uninstall callback has expired")
	}
	cleanupID = strings.TrimSpace(cleanupID)
	if cleanupID == "" {
		return errors.New("cleanup id is required")
	}
	if p.expectedCleanupID != "" && p.expectedCleanupID != cleanupID {
		return errors.New("cleanup id changed after dispatch")
	}
	p.expectedCleanupID = cleanupID
	return nil
}

func (p *agentUninstallPending) accept(callback agentUninstallCallback) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active {
		return errors.New("uninstall callback has expired")
	}
	if p.completed {
		return errors.New("uninstall callback was already consumed")
	}
	callback.CleanupID = strings.TrimSpace(callback.CleanupID)
	if callback.CleanupID == "" {
		return errors.New("cleanup id is required")
	}
	if p.expectedCleanupID != "" && callback.CleanupID != p.expectedCleanupID {
		return errors.New("cleanup id does not match the pending uninstall")
	}
	p.completed = true
	p.done <- callback
	return nil
}

func (h *XrayServerHandler) registerAgentUninstall(serverID int64) (string, *agentUninstallPending, error) {
	if serverID <= 0 || h.repo == nil {
		return "", nil, errors.New("server id is required")
	}
	for attempt := 0; attempt < 4; attempt++ {
		var raw [32]byte
		if _, err := randRead(raw[:]); err != nil {
			return "", nil, fmt.Errorf("generate uninstall callback token: %w", err)
		}
		// The Agent contract accepts URL-safe unpadded bearer tokens. Keep this
		// separate from generateSecureToken so existing padded tokens remain
		// byte-for-byte compatible with already installed nodes.
		token := base64.RawURLEncoding.EncodeToString(raw[:])
		tokenHash := agentUninstallTokenHash(token)
		pending := &agentUninstallPending{serverID: serverID, done: make(chan agentUninstallCallback, 1), active: true}
		h.agentUninstallMu.Lock()
		if h.agentUninstallPending == nil {
			h.agentUninstallPending = make(map[string]*agentUninstallPending)
		}
		_, exists := h.agentUninstallPending[token]
		h.agentUninstallMu.Unlock()
		if exists {
			continue
		}
		expiresAt := time.Now().UTC().Add(agentUninstallCallbackWaitTimeout + 3*time.Minute)
		if _, err := h.repo.CreateRemoteServerDeletionTask(context.Background(), serverID, tokenHash, expiresAt); err != nil {
			return "", nil, err
		}
		h.agentUninstallMu.Lock()
		h.agentUninstallPending[token] = pending
		h.agentUninstallMu.Unlock()
		return token, pending, nil
	}
	return "", nil, errors.New("could not allocate a unique uninstall callback token")
}

func agentUninstallTokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func (h *XrayServerHandler) unregisterAgentUninstall(token string, pending *agentUninstallPending) {
	h.agentUninstallMu.Lock()
	if current := h.agentUninstallPending[token]; current == pending {
		pending.mu.Lock()
		pending.active = false
		pending.mu.Unlock()
		delete(h.agentUninstallPending, token)
	}
	h.agentUninstallMu.Unlock()
}

// HandleAgentUninstallComplete accepts the Agent's one-time completion proof.
// It deliberately sits outside admin authentication: possession of the
// high-entropy, operation-scoped bearer token is the only callback credential.
func (h *XrayServerHandler) HandleAgentUninstallComplete(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != stdhttp.MethodPost {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}
	const bearerPrefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, bearerPrefix) {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusUnauthorized, "invalid uninstall callback credential")
		return
	}
	token := strings.TrimPrefix(authorization, bearerPrefix)
	decodedToken, decodeErr := base64.RawURLEncoding.DecodeString(token)
	if strings.TrimSpace(token) != token || decodeErr != nil || len(decodedToken) != 32 {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusUnauthorized, "invalid uninstall callback credential")
		return
	}

	decoder := json.NewDecoder(stdhttp.MaxBytesReader(w, r.Body, 4<<10))
	decoder.DisallowUnknownFields()
	var callback agentUninstallCallback
	if err := decoder.Decode(&callback); err != nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadRequest, "invalid uninstall callback")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadRequest, "invalid uninstall callback")
		return
	}
	if !validAgentUninstallCleanupID(strings.TrimSpace(callback.CleanupID)) {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadRequest, "invalid cleanup id")
		return
	}
	callbackCtx, cancel := context.WithTimeout(context.Background(), remoteServerDeleteCommitTimeout)
	defer cancel()
	task, err := h.repo.ConsumeRemoteServerDeletionCallback(
		callbackCtx, agentUninstallTokenHash(token), strings.TrimSpace(callback.CleanupID), callback.Success, callback.Error,
	)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrRemoteServerDeletionTokenInvalid), errors.Is(err, storage.ErrRemoteServerDeletionTokenExpired):
			writeRemoteServerDeleteFailure(w, stdhttp.StatusUnauthorized, "invalid or expired uninstall callback credential")
		case errors.Is(err, storage.ErrRemoteServerDeletionCallbackUsed), errors.Is(err, storage.ErrRemoteServerDeletionCleanupID):
			writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, err.Error())
		default:
			writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "could not persist uninstall callback")
		}
		return
	}
	h.agentUninstallMu.Lock()
	pending := h.agentUninstallPending[token]
	h.agentUninstallMu.Unlock()
	if pending != nil {
		if notifyErr := pending.accept(callback); notifyErr != nil {
			// The durable task is authoritative. A failed in-memory notification
			// must not ask the Agent to replay its one-time callback.
			log.Printf("[Agent Uninstall] persisted callback for server %d but could not notify waiter: %v", task.ServerID, notifyErr)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "received": true})
	if pending == nil && callback.Success {
		go h.finalizeConfirmedRemoteServerDeletion(task.ServerID)
	}
}

func validAgentUninstallCleanupID(cleanupID string) bool {
	if len(cleanupID) != 32 {
		return false
	}
	for _, c := range cleanupID {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func remoteRemovalMessage(ack remoteRemovalAcknowledgement, fallback string) string {
	if message := strings.TrimSpace(ack.Error); message != "" {
		return message
	}
	if message := strings.TrimSpace(ack.Message); message != "" {
		return message
	}
	return fallback
}

func writeRemoteServerDeleteFailure(w stdhttp.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: message})
}

func (h *XrayServerHandler) invalidateDeletedRemoteServer(serverID int64) {
	if h.remoteManager != nil && h.remoteManager.inboundCache != nil {
		h.remoteManager.inboundCache.Invalidate(serverID)
	}
}

func (h *XrayServerHandler) finalizeConfirmedRemoteServerDeletion(serverID int64) {
	if h == nil || h.repo == nil || serverID <= 0 {
		return
	}
	ctx, release, err := h.acquireRemoteServerExclusiveLease(context.Background(), serverID)
	if err != nil {
		_ = h.repo.SetRemoteServerDeletionTaskError(context.Background(), serverID, "Agent 已卸载，等待删除面板记录: "+err.Error())
		return
	}
	defer release()
	task, err := h.repo.GetRemoteServerDeletionTask(ctx, serverID)
	if err != nil || task.Status != storage.RemoteServerDeletionAgentUninstalled {
		return
	}
	deleteCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), remoteServerDeleteCommitTimeout)
	defer cancel()
	if err := h.repo.DeleteRemoteServer(deleteCtx, serverID); err != nil {
		if !errors.Is(err, storage.ErrRemoteServerNotFound) {
			_ = h.repo.SetRemoteServerDeletionTaskError(context.Background(), serverID, "Agent 已卸载，等待删除面板记录: "+err.Error())
			log.Printf("[Agent Uninstall] server %d cleanup confirmed but panel deletion failed: %v", serverID, err)
		}
		return
	}
	h.invalidateDeletedRemoteServer(serverID)
}

func (h *XrayServerHandler) deleteConfirmedRemoteServer(w stdhttp.ResponseWriter, ctx context.Context, serverID int64) {
	deleteCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), remoteServerDeleteCommitTimeout)
	defer cancel()
	if err := h.repo.DeleteRemoteServer(deleteCtx, serverID); err != nil {
		writeRemoteServerDeleteFailureWithStatus(w, stdhttp.StatusInternalServerError,
			"远端 Agent 已完成清理，但删除面板记录失败，记录已保留: "+err.Error(),
			storage.RemoteServerDeletionAgentUninstalled)
		return
	}
	h.invalidateDeletedRemoteServer(serverID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: true, Message: "远端 Agent 已完成清理，服务器记录已删除"})
}

func writeRemoteServerDeleteFailureWithStatus(w stdhttp.ResponseWriter, status int, message, deletionStatus string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: message, DeletionStatus: deletionStatus})
}

func (h *XrayServerHandler) waitForPersistedRemoteServerDeletion(w stdhttp.ResponseWriter, ctx context.Context, serverID int64, expiresAt time.Time) {
	timeout := h.agentUninstallTimeout
	if timeout <= 0 {
		timeout = agentUninstallCallbackWaitTimeout
	}
	if remaining := time.Until(expiresAt); remaining > 0 && remaining < timeout {
		timeout = remaining
	}
	waitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			writeRemoteServerDeleteFailureWithStatus(w, stdhttp.StatusGatewayTimeout, "等待 Agent 完成卸载超时，服务器记录已保留", storage.RemoteServerDeletionDispatched)
			return
		default:
		}
		task, err := h.repo.GetRemoteServerDeletionTask(waitCtx, serverID)
		if errors.Is(err, storage.ErrRemoteServerDeletionTaskNotFound) {
			if _, serverErr := h.repo.GetRemoteServer(waitCtx, serverID); errors.Is(serverErr, storage.ErrRemoteServerNotFound) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: true, Message: "服务器已删除"})
				return
			}
			writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, "卸载任务状态丢失，服务器记录已保留")
			return
		}
		if err != nil {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "读取 Agent 卸载任务失败")
			return
		}
		switch task.Status {
		case storage.RemoteServerDeletionAgentUninstalled:
			h.deleteConfirmedRemoteServer(w, ctx, serverID)
			return
		case storage.RemoteServerDeletionFailed:
			message := strings.TrimSpace(task.LastError)
			if message == "" {
				message = "远端清理未完成"
			}
			writeRemoteServerDeleteFailureWithStatus(w, stdhttp.StatusBadGateway, "Agent 卸载清理失败，服务器记录已保留: "+message, task.Status)
			return
		}
		select {
		case <-waitCtx.Done():
			writeRemoteServerDeleteFailureWithStatus(w, stdhttp.StatusGatewayTimeout, "等待 Agent 完成卸载超时，服务器记录已保留", task.Status)
			return
		case <-ticker.C:
		}
	}
}

func (h *XrayServerHandler) uninstallAgentAndDeleteRemoteServer(w stdhttp.ResponseWriter, r *stdhttp.Request, serverID int64) {
	timeout := h.agentUninstallTimeout
	if timeout <= 0 {
		timeout = agentUninstallCallbackWaitTimeout
	}
	// Once the Agent accepts this destructive operation, a closed browser must
	// not cancel the callback wait and release the exclusive server lease early.
	// Lease acquisition has its own deadline. The full seven-minute callback
	// window starts only after dispatch acknowledgement below, so neither lock
	// queuing nor capability/WARP preflight consumes the Agent's 360-second bound.
	ctx, release, err := h.acquireRemoteServerExclusiveLease(r.Context(), serverID)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteInstallationActive) {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, "服务器正在安装，暂不能卸载 Agent")
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusGatewayTimeout, "服务器仍有管理操作进行中，卸载等待超时")
			return
		}
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "无法锁定服务器卸载操作")
		return
	}
	defer release()
	preDispatchCtx, cancelPreDispatch := context.WithTimeout(ctx, agentUninstallPreDispatchTimeout)
	defer cancelPreDispatch()
	ctx = preDispatchCtx

	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusNotFound, "服务器不存在")
			return
		}
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "读取服务器失败")
		return
	}
	if _, fedErr := h.repo.GetFederatedServer(ctx, serverID); fedErr == nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, "接入的共享服务器不能卸载拥有方 Agent，只能删除本地记录")
		return
	} else if !errors.Is(fedErr, storage.ErrFederatedServerNotFound) {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "无法确认服务器所有权")
		return
	}
	if err := h.repo.ValidateRemoteServerDeletion(ctx, serverID); err != nil {
		switch {
		case errors.Is(err, storage.ErrForwardingConflict):
			writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, "服务器仍被转发模板、转发规则或端口分配使用，请先移除相关配置")
		case errors.Is(err, storage.ErrRemoteInstallationActive):
			writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, "服务器正在安装，暂不能卸载 Agent")
		case errors.Is(err, storage.ErrRemoteServerNotFound):
			writeRemoteServerDeleteFailure(w, stdhttp.StatusNotFound, "服务器不存在")
		default:
			writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, "服务器暂不能安全删除: "+err.Error())
		}
		return
	}
	if task, taskErr := h.repo.GetRemoteServerDeletionTask(ctx, serverID); taskErr == nil {
		switch task.Status {
		case storage.RemoteServerDeletionAgentUninstalled:
			// The callback is durable. Retrying after a browser disconnect or
			// panel restart must never contact the already removed Agent again.
			h.deleteConfirmedRemoteServer(w, ctx, serverID)
			return
		case storage.RemoteServerDeletionPending:
			if task.CleanupID == "" {
				// The task was persisted but never crossed the durable dispatch
				// boundary, so no Agent callback can belong to it.
				if err := h.repo.FailRemoteServerDeletionTask(ctx, serverID, "面板在下发 Agent 卸载前中断，正在重新创建任务"); err != nil {
					writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "无法恢复 Agent 卸载任务")
					return
				}
			} else if task.ExpiresAt.After(time.Now().UTC()) {
				h.waitForPersistedRemoteServerDeletion(w, ctx, serverID, task.ExpiresAt)
				return
			}
		case storage.RemoteServerDeletionDispatched:
			if task.ExpiresAt.After(time.Now().UTC()) {
				h.waitForPersistedRemoteServerDeletion(w, ctx, serverID, task.ExpiresAt)
				return
			}
		}
	} else if !errors.Is(taskErr, storage.ErrRemoteServerDeletionTaskNotFound) {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "读取 Agent 卸载任务失败")
		return
	}
	if server.Status != storage.RemoteServerStatusConnected {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, "Agent 当前不在线，未执行卸载，服务器记录已保留")
		return
	}
	if h.remoteManager == nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusServiceUnavailable, "远程 Agent 管理通道不可用")
		return
	}
	capable, capabilityErr := h.agentSupportsSafeUninstall(ctx, serverID)
	if capabilityErr != nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "无法确认 Agent 的安全卸载能力，服务器记录已保留: "+capabilityErr.Error())
		return
	}
	if !capable {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusConflict, "Agent 版本或运行环境不支持安全卸载，请升级 Agent 或手动卸载")
		return
	}

	statusResult, statusErr := h.remoteManager.forwardToRemoteServer(ctx, serverID, stdhttp.MethodGet, "/api/child/warp/status", nil)
	if statusErr != nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "无法确认 WARP 实际状态，未卸载 Agent，服务器记录已保留: "+statusErr.Error())
		return
	}
	var warpStatus remoteRemovalAcknowledgement
	if err := json.Unmarshal(statusResult, &warpStatus); err != nil || !warpStatus.Success || warpStatus.Installed == nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "无法确认 WARP 实际状态，未卸载 Agent，服务器记录已保留: "+remoteRemovalMessage(warpStatus, "远程响应无效"))
		return
	}
	if *warpStatus.Installed {
		result, removeErr := h.remoteManager.forwardToRemoteServer(ctx, serverID, stdhttp.MethodPost, "/api/child/warp/remove", nil)
		if removeErr != nil {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "WARP 清理失败，未卸载 Agent，服务器记录已保留: "+removeErr.Error())
			return
		}
		var ack remoteRemovalAcknowledgement
		if err := json.Unmarshal(result, &ack); err != nil || !ack.Success || !ack.Uninstalled {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "WARP 未确认完成清理，未卸载 Agent，服务器记录已保留: "+remoteRemovalMessage(ack, "远程响应无效"))
			return
		}
		if err := h.repo.UpdateRemoteServerWarpInstalled(ctx, server.Token, false); err != nil {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "WARP 已清理，但面板状态更新失败，未卸载 Agent，服务器记录已保留")
			return
		}
	}

	masterURL, _, masterURLErr := h.effectiveRemoteInstallMasterURL(ctx, r)
	if masterURLErr != nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusServiceUnavailable, "无法生成 Agent 卸载回调地址，服务器记录已保留: "+masterURLErr.Error())
		return
	}
	callbackToken, pending, registerErr := h.registerAgentUninstall(serverID)
	if registerErr != nil {
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "无法创建 Agent 卸载回调，服务器记录已保留")
		return
	}
	defer h.unregisterAgentUninstall(callbackToken, pending)
	callbackTokenHash := agentUninstallTokenHash(callbackToken)
	dispatchBody, marshalErr := json.Marshal(agentUninstallDispatchRequest{
		CallbackURL:   strings.TrimRight(masterURL, "/") + AgentUninstallCompletePath,
		CallbackToken: callbackToken,
	})
	if marshalErr != nil {
		_ = h.repo.FailRemoteServerDeletionTask(context.Background(), serverID, "无法创建 Agent 卸载请求")
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "无法创建 Agent 卸载请求，服务器记录已保留")
		return
	}
	// Persist the dispatch boundary before sending anything destructive. Thus
	// pending+empty is provably pre-dispatch and can be replaced after restart;
	// dispatched+empty is ambiguous and must keep waiting for its old callback.
	if err := h.repo.MarkRemoteServerDeletionDispatched(context.Background(), serverID, callbackTokenHash, ""); err != nil {
		_ = h.repo.FailRemoteServerDeletionTask(context.Background(), serverID, "无法持久化 Agent 卸载下发状态")
		writeRemoteServerDeleteFailure(w, stdhttp.StatusInternalServerError, "无法持久化 Agent 卸载任务，服务器记录已保留")
		return
	}

	result, uninstallErr := h.remoteManager.forwardToRemoteServer(ctx, serverID, stdhttp.MethodPost, "/api/child/agent/uninstall-v2", dispatchBody)
	if uninstallErr != nil {
		_ = h.repo.SetRemoteServerDeletionTaskError(context.Background(), serverID, "Agent 卸载请求结果未知: "+uninstallErr.Error())
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "Agent 未接受安全卸载任务，服务器记录已保留: "+uninstallErr.Error())
		return
	}
	var ack remoteRemovalAcknowledgement
	if err := json.Unmarshal(result, &ack); err != nil || !ack.Success || !ack.DispatchVerified || !validAgentUninstallCleanupID(strings.TrimSpace(ack.CleanupID)) {
		_ = h.repo.SetRemoteServerDeletionTaskError(context.Background(), serverID, "Agent 未返回可验证的任务接收结果")
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "Agent 未返回可验证的任务接收结果，服务器记录已保留: "+remoteRemovalMessage(ack, "远程响应无效"))
		return
	}
	if err := h.repo.MarkRemoteServerDeletionDispatched(context.Background(), serverID, callbackTokenHash, strings.TrimSpace(ack.CleanupID)); err != nil {
		_ = h.repo.KeepRemoteServerDeletionDispatched(context.Background(), serverID, "Agent 卸载任务标识与回调不一致")
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "Agent 卸载任务标识无效，服务器记录已保留")
		return
	}
	if err := pending.setExpectedCleanupID(ack.CleanupID); err != nil {
		_ = h.repo.KeepRemoteServerDeletionDispatched(context.Background(), serverID, "Agent 卸载任务标识无效")
		writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "Agent 卸载任务标识无效，服务器记录已保留")
		return
	}
	// Start the full callback budget after dispatch is acknowledged. Capability
	// probing and WARP removal cannot consume any of the Agent's 360-second hard
	// cleanup bound or the panel's additional 60-second delivery margin.
	callbackCtx, cancelCallback := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancelCallback()

	var completion agentUninstallCallback
	select {
	case completion = <-pending.done:
		if completion.CleanupID != strings.TrimSpace(ack.CleanupID) {
			writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "Agent 卸载完成回执与任务不匹配，服务器记录已保留")
			return
		}
		if !completion.Success {
			message := strings.TrimSpace(completion.Error)
			if message == "" {
				message = "远端清理未完成"
			}
			writeRemoteServerDeleteFailure(w, stdhttp.StatusBadGateway, "Agent 卸载清理失败，服务器记录已保留: "+message)
			return
		}
	case <-callbackCtx.Done():
		writeRemoteServerDeleteFailure(w, stdhttp.StatusGatewayTimeout, "等待 Agent 完成卸载超时，服务器记录已保留")
		return
	}

	// DeleteRemoteServer re-enters this exclusive lease and repeats the durable
	// deletion checks inside its own transaction before committing.
	h.deleteConfirmedRemoteServer(w, ctx, serverID)
}

func (h *XrayServerHandler) agentSupportsSafeUninstall(ctx context.Context, serverID int64) (bool, error) {
	if h.wsHandler != nil {
		if connection, connected := h.wsHandler.GetConnectionByServerID(serverID); connected {
			return connection.Capabilities.AgentUninstallV2, nil
		}
	}
	if h.remoteManager == nil {
		return false, errors.New("remote Agent manager is unavailable")
	}
	result, err := h.remoteManager.forwardToRemoteServer(ctx, serverID, stdhttp.MethodGet, "/api/child/system/info", nil)
	if err != nil {
		return false, err
	}
	var info struct {
		Success      bool            `json:"success"`
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal(result, &info); err != nil {
		return false, fmt.Errorf("decode system info: %w", err)
	}
	if !info.Success {
		return false, errors.New("Agent system info reported failure")
	}
	return info.Capabilities["agent_uninstall_v2"], nil
}

// 更新远程服务器的基本信息
// ReorderRemoteServers 接受按目标顺序排列的 server ID 数组,把数据库里 sort_order 字段按这个顺序写一遍。
// 前端拖动结束就调一下,ListRemoteServers 已经按 sort_order ASC 排了,刷新自然看到新顺序。
func (h *XrayServerHandler) ReorderRemoteServers(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != stdhttp.MethodPost {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "无效的请求参数"})
		return
	}
	if len(req.IDs) == 0 {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "ids 不能为空"})
		return
	}
	if err := h.repo.ReorderRemoteServers(r.Context(), req.IDs); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (h *XrayServerHandler) UpdateRemoteServer(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "PUT" && r.Method != "POST" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	var req RemoteServerUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "无效的请求参数",
		})
		return
	}

	if req.ID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "无效的服务器ID",
		})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "服务器名称不能为空",
		})
		return
	}

	ctx := r.Context()
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, req.ID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, storage.ErrRemoteInstallationActive) {
			w.WriteHeader(stdhttp.StatusConflict)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: "服务器正在安装，暂不能修改",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "获取服务器信息失败",
		})
		return
	}
	defer release()
	ctx = leasedCtx

	// 获取旧的服务器信息，用于检查名称是否变更
	oldServer, err := h.repo.GetRemoteServer(ctx, req.ID)
	if err != nil {
		msg := "获取服务器信息失败"
		if err == storage.ErrRemoteServerNotFound {
			msg = "服务器不存在"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: msg,
		})
		return
	}
	oldListenPort := oldServer.ListenPort
	if oldListenPort <= 0 {
		oldListenPort = 23889
	}
	if req.ListenPort > 0 && req.ListenPort != oldListenPort {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusConflict)
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "安装后不能单独修改 Agent 端口；请删除并按新端口重新添加服务器",
		})
		return
	}
	requestedConnectionMode := strings.TrimSpace(req.ConnectionMode)
	if requestedConnectionMode != "" && requestedConnectionMode != oldServer.ConnectionMode {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusConflict)
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "安装后不能单独修改连接模式；请删除并按新模式重新添加服务器",
		})
		return
	}
	oldNginxMode := strings.TrimSpace(oldServer.NginxMode)
	if oldNginxMode == "" {
		oldNginxMode = "managed"
	}
	newNginxMode := strings.TrimSpace(req.NginxMode)
	if newNginxMode == "" {
		newNginxMode = oldNginxMode
	}
	if newNginxMode != "managed" && newNginxMode != "reuse_existing" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusBadRequest)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "Nginx 模式必须为 managed 或 reuse_existing"})
		return
	}
	oldEffectiveNodeHost, newEffectiveNodeHost := normalizeRemoteServerAddressUpdate(oldServer, &req)
	identityOrEndpointChanged := strings.TrimSpace(req.Name) != oldServer.Name ||
		(newEffectiveNodeHost != "" && newEffectiveNodeHost != oldEffectiveNodeHost)
	if identityOrEndpointChanged {
		hasDirectGrants, grantErr := h.repo.HasActiveDirectNodeGrantsForServer(ctx, req.ID)
		if grantErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "检查固定节点授权失败"})
			return
		}
		if hasDirectGrants {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusConflict)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: "服务器存在生效中的个性化固定节点授权；请先撤销授权，再修改名称或节点地址",
			})
			return
		}
	}

	if req.XrayMode == "embedded" && oldServer.XrayMode != "embedded" && h.capabilityManager != nil && !h.capabilityManager.HasFeature(capabilities.FeatureEmbeddedXray) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusForbidden)
		json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "当前构建未启用内嵌 Xray"})
		return
	}

	// Validate DDNS before changing any other server fields. A failed provider or
	// domain check must not leave the main server update half-applied.
	if req.DDNSEnabled {
		effectivePull := strings.TrimSpace(req.PullAddress)
		if effectivePull == "" {
			effectivePull = strings.TrimSpace(oldServer.PullAddress)
		}
		if effectivePull == "" || net.ParseIP(effectivePull) != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: "DDNS 开启时,服务器地址必须填域名"})
			return
		}
		if req.DDNSProviderID > 0 {
			if _, perr := h.repo.GetDNSProvider(ctx, req.DDNSProviderID); perr != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(stdhttp.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: fmt.Sprintf("DDNS 服务商不存在: %v", perr)})
				return
			}
		} else if _, cerr := h.repo.FindCertificateForDomain(ctx, effectivePull); cerr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: fmt.Sprintf("DDNS 自动模式:找不到匹配 %s 的通配符证书,请先签发证书或显式选择 DNS 服务商", effectivePull)})
			return
		}
	}

	// 检测 traffic_source 是否变更 — 用于切换时自动迁移 offset,让 server.traffic_used 显示值连续,
	// 避免用户从 xray 切到 system 时数字突然变小(只剩主控升级以来累积的几小时 system 流量),
	// 反向切回也同样平滑。必须在 UpdateRemoteServer **之前**算 oldDisplay,否则 GetServerTrafficUsed
	// 走的就是新 source 分支了,oldDisplay 取不到旧值。
	newSource := strings.TrimSpace(req.TrafficSource)
	if newSource == "" {
		newSource = oldServer.TrafficSource
	}
	sourceChanged := newSource != "" && newSource != oldServer.TrafficSource
	var oldDisplayForMigration int64
	if sourceChanged {
		oldRaw, _ := h.repo.GetServerTrafficUsed(ctx, req.ID)
		oldDisplayForMigration = oldRaw + oldServer.TrafficUsedOffset
	}
	nginxModeChanged := newNginxMode != oldNginxMode
	if nginxModeChanged {
		if err := h.switchRemoteNginxMode(ctx, req.ID, newNginxMode); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: fmt.Sprintf("Agent 未确认 Nginx 模式切换，面板信息未修改: %v", err),
			})
			return
		}
	}

	if err := h.repo.UpdateRemoteServer(ctx, req.ID, req.Name, req.Domain, req.TrafficLimit, req.TrafficResetDay, req.ConnectionMode, req.XrayMode, req.TrafficStatsMode, req.TrafficSource, req.IPv6Enabled); err != nil {
		msg := "更新服务器失败"
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			msg = "服务器不存在"
		} else if errors.Is(err, storage.ErrRemoteServerExists) {
			msg = "服务器名称已存在"
		} else if errors.Is(err, storage.ErrRemoteInstallationActive) {
			msg = "服务器正在安装，暂不能修改"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusConflict)
		}
		if nginxModeChanged {
			if rollbackErr := h.rollbackRemoteNginxMode(ctx, req.ID, oldNginxMode); rollbackErr != nil {
				log.Printf("[Remote Server] CRITICAL: failed to roll Agent nginx_mode back to %s for server %d after database update failure: %v", oldNginxMode, req.ID, rollbackErr)
				msg += fmt.Sprintf("；Agent Nginx 模式回滚失败，当前状态可能不一致: %v", rollbackErr)
			} else {
				msg += "；Agent Nginx 模式已回滚"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: msg,
		})
		return
	}
	if nginxModeChanged {
		if err := h.repo.UpdateRemoteServerNginxMode(ctx, req.ID, newNginxMode); err != nil {
			rollbackErr := h.rollbackRemoteNginxMode(ctx, req.ID, oldNginxMode)
			message := fmt.Sprintf("其他服务器信息已保存，但面板 Nginx 模式更新失败: %v", err)
			if rollbackErr != nil {
				log.Printf("[Remote Server] CRITICAL: failed to roll Agent nginx_mode back to %s for server %d after nginx_mode database failure: %v", oldNginxMode, req.ID, rollbackErr)
				message += fmt.Sprintf("；Agent 回滚失败，当前状态可能不一致: %v", rollbackErr)
			} else {
				message += "；Agent 已回滚到原 Nginx 模式"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusInternalServerError)
			json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: message})
			return
		}
	}

	// 切换 xray→system 时,把 xray 流量的当前累计 + daily snapshot 历史完整搬到 system 维度:
	//   - cycle 起点 = xray inbound 累计 → 切换瞬间 GetServerTrafficUsed(system) == 切换前 xray raw → 显示数值无变化
	//   - daily snapshot 按 node_traffic_snapshots 每日聚合 → 服务器视图 today/week/month 立即可用
	// 反向(system→xray)不需要迁移 — node_traffic_snapshots 一直在被 daily snapshot job 拍,xray baseline 现成可用。
	if sourceChanged && oldServer.TrafficSource == "xray" && newSource == "system" {
		if err := h.repo.MigrateXraySnapshotsToSystem(ctx, req.ID); err != nil {
			log.Printf("[Remote Server] Migrate xray snapshots to system failed for server %d: %v", req.ID, err)
			// 不阻断 update — 切换基本功能仍然可用,只是 today/week/month baseline 缺失;
			// 主控启动 backfill goroutine 之后会自动补
		} else {
			log.Printf("[Remote Server] Migrated xray snapshots to system for server %d on source switch", req.ID)
		}
	}

	// 更新拉取配置（如果提供）
	if req.PullAddress != "" || req.PullPort > 0 || req.PullToken != "" {
		connMode := req.ConnectionMode
		if connMode == "" {
			connMode = oldServer.ConnectionMode
		}
		if err := h.repo.UpdateRemoteServerConfig(ctx, req.ID, connMode, req.PullAddress, req.PullPort, req.PullToken); err != nil {
			log.Printf("[Remote Server] Failed to update pull config for server %d: %v", req.ID, err)
			// 之前这里只 log 不返 error,导致用户看到 success 但 pull_address 没真更新;
			// 现在向前端透出错误,起码用户能感知失败并 retry。
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: fmt.Sprintf("更新拉取配置失败: %s", err.Error()),
			})
			return
		}
	}

	// 如果服务器名称变更，同步更新关联的节点
	if oldServer.Name != req.Name {
		if updated, err := h.repo.UpdateNodesByServerName(ctx, oldServer.Name, req.Name); err != nil {
			log.Printf("[Remote Server] Failed to update nodes for server name change: %v", err)
		} else if updated > 0 {
			log.Printf("[Remote Server] Updated %d nodes for server name change: %s -> %s", updated, oldServer.Name, req.Name)
		}
	}

	// Compare the effective endpoint, not just Domain. PullAddress changes and
	// IPv4-to-IPv6 fallback changes must refresh existing subscription nodes too.
	if newEffectiveNodeHost != "" && newEffectiveNodeHost != oldEffectiveNodeHost {
		finalName := strings.TrimSpace(req.Name)
		if finalName == "" {
			finalName = oldServer.Name
		}
		if n, err := h.repo.RefreshNodesServerAddress(ctx, finalName, newEffectiveNodeHost); err != nil {
			log.Printf("[Remote Server] Refresh nodes server address failed for %s: %v", finalName, err)
		} else if n > 0 {
			log.Printf("[Remote Server] Refreshed %d node(s) server address %s → %s on %s", n, oldEffectiveNodeHost, newEffectiveNodeHost, finalName)
		}
	}

	if err := h.repo.UpdateRemoteServerDDNSConfig(ctx, req.ID, req.DDNSEnabled, req.DDNSProviderID); err != nil {
		log.Printf("[Remote Server] Failed to update DDNS config for server %d: %v", req.ID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(RemoteServerResponse{Success: false, Message: fmt.Sprintf("更新 DDNS 配置失败: %s", err.Error())})
		return
	}

	// 更新已用流量偏移量。优先级:
	//   1. 用户在 dialog 显式填了"已用流量" → 按用户输入算 offset
	//   2. 没填但 traffic_source 变了 → 自动迁移,把旧 source 显示值"搬"到新 source 起点
	//      (oldDisplay 在 UpdateRemoteServer 之前抓的,此时 source 已切到新值,GetServerTrafficUsed 走新分支)
	//   3. 都不满足 → 不动 offset
	if req.TrafficUsed != nil {
		aggregated, _ := h.repo.GetServerTrafficUsed(ctx, req.ID)
		offset := *req.TrafficUsed - aggregated
		if err := h.repo.UpdateRemoteServerTrafficOffset(ctx, req.ID, offset); err != nil {
			log.Printf("[Remote Server] Failed to update traffic offset for server %d: %v", req.ID, err)
		}
	} else if sourceChanged {
		newRaw, _ := h.repo.GetServerTrafficUsed(ctx, req.ID)
		offset := oldDisplayForMigration - newRaw
		if err := h.repo.UpdateRemoteServerTrafficOffset(ctx, req.ID, offset); err != nil {
			log.Printf("[Remote Server] Auto-migrate traffic offset on source switch failed for server %d: %v", req.ID, err)
		} else {
			log.Printf("[Remote Server] Auto-migrated traffic offset for server %d on source switch %s→%s: oldDisplay=%d, newRaw=%d, newOffset=%d",
				req.ID, oldServer.TrafficSource, newSource, oldDisplayForMigration, newRaw, offset)
		}
	}

	// Keep the database and Agent mode in one installation-safe transaction.
	// The request already holds the server mutation lease, so a new installer
	// cannot begin between the database write and the remote restart.
	newXrayMode := req.XrayMode
	if newXrayMode == "" {
		newXrayMode = oldServer.XrayMode
	}
	if newXrayMode != oldServer.XrayMode {
		var switchErr error
		if h.remoteManager == nil {
			switchErr = errors.New("remote deployment manager is unavailable")
		} else {
			switchErr = h.switchRemoteXrayMode(ctx, req.ID, newXrayMode)
		}
		if switchErr != nil {
			if rollbackErr := h.repo.UpdateRemoteServerXrayMode(ctx, req.ID, oldServer.XrayMode); rollbackErr != nil {
				log.Printf("[Remote Server] CRITICAL: failed to restore xray_mode for server %d after Agent rejection: %v", req.ID, rollbackErr)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusConflict)
			_ = json.NewEncoder(w).Encode(RemoteServerResponse{
				Success: false,
				Message: fmt.Sprintf("其他服务器信息已保存，但 Xray 模式切换失败并已回滚: %v", switchErr),
			})
			return
		}
	}

	respMsg := "服务器信息已更新"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RemoteServerResponse{
		Success: true,
		Message: respMsg,
	})
}

// normalizeRemoteServerAddressUpdate applies the linked-domain rule and returns
// the old/new client endpoints. A Domain follows PullAddress only when it was
// previously equal to PullAddress and the request did not explicitly replace it
// with a different value.
func normalizeRemoteServerAddressUpdate(oldServer *storage.RemoteServer, req *RemoteServerUpdateRequest) (string, string) {
	if oldServer == nil || req == nil {
		return "", ""
	}
	oldHost := chooseClashServerHost(oldServer)
	oldPull := strings.TrimSpace(oldServer.PullAddress)
	newPull := oldPull
	pullConfigProvided := strings.TrimSpace(req.PullAddress) != "" || req.PullPort > 0 || strings.TrimSpace(req.PullToken) != ""
	if pullConfigProvided {
		newPull = strings.TrimSpace(req.PullAddress)
	}
	oldDomain := strings.TrimSpace(oldServer.Domain)
	newDomain := strings.TrimSpace(req.Domain)
	if newPull != oldPull && oldDomain != "" && oldDomain == oldPull && (newDomain == "" || newDomain == oldDomain) {
		newDomain = newPull
		req.Domain = newDomain
	}

	next := *oldServer
	next.Domain = newDomain
	next.PullAddress = newPull
	return oldHost, chooseClashServerHost(&next)
}

// switchRemoteXrayMode 通知远程 Agent 切换 xray_mode 并重启。
func (h *XrayServerHandler) switchRemoteXrayMode(ctx context.Context, serverID int64, newMode string) error {
	body, _ := json.Marshal(map[string]string{"xray_mode": newMode})
	result, err := h.remoteManager.ForwardToServer(ctx, serverID, "POST", "/api/child/agent/switch-xray-mode", body)
	if err != nil {
		log.Printf("[Remote Server] Failed to switch xray_mode to %s for server %d: %v", newMode, serverID, err)
		return err
	}
	log.Printf("[Remote Server] Xray mode switch to %s for server %d: %s", newMode, serverID, string(result))
	return nil
}

func resolveIPs(address string) []string {
	if ip := net.ParseIP(address); ip != nil {
		return []string{ip.String()}
	}
	ips, err := net.LookupHost(address)
	if err != nil {
		return nil
	}
	return ips
}

func (h *XrayServerHandler) CheckSameIP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != stdhttp.MethodGet {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	address := strings.TrimSpace(r.URL.Query().Get("address"))
	if address == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "address 参数不能为空"})
		return
	}

	ctx := r.Context()
	relaydockDomain := getDomainFromMasterURL(h.repo, ctx)
	masterURL, _ := h.repo.GetSystemSetting(ctx, "master_url")
	httpsEnabled := strings.HasPrefix(masterURL, "https://")

	sameIP := false
	if relaydockDomain != "" {
		addrIPs := resolveIPs(address)
		relaydockIPs := resolveIPs(relaydockDomain)
		relaydockIPSet := make(map[string]struct{})
		for _, ip := range relaydockIPs {
			relaydockIPSet[ip] = struct{}{}
		}
		for _, ip := range addrIPs {
			if _, ok := relaydockIPSet[ip]; ok {
				sameIP = true
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"same_ip":       sameIP,
		"master_domain": relaydockDomain,
		"https_enabled": httpsEnabled,
	})
}
