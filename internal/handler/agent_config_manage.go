package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

	"miaomiaowux/internal/capabilities"
	"miaomiaowux/internal/ddns"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/traffic"
)

// randReader 是用于生成安全令牌的加密读取器
var randReader io.Reader = rand.Reader

// base64URLEncoding 用于 URL 安全的 base64 编码
var base64URLEncoding = base64.URLEncoding

type XrayServerHandler struct {
	repo              *storage.TrafficRepository
	collector         *traffic.Collector
	limiterPusher     *LimiterConfigPusher
	remoteManager     *RemoteManageHandler
	wsHandler         *RemoteWSHandler
	crypto            *CryptoConfig
	capabilityManager *capabilities.Manager
	ddnsManager       *ddns.Manager
	managementProbeMu sync.Mutex
	managementProbes  map[int64]time.Time
}

func (h *XrayServerHandler) SetWSHandler(ws *RemoteWSHandler) {
	h.wsHandler = ws
}

func (h *XrayServerHandler) SetDDNSManager(m *ddns.Manager) {
	h.ddnsManager = m
}

func NewXrayServerHandler(repo *storage.TrafficRepository, collector *traffic.Collector, crypto *CryptoConfig) *XrayServerHandler {
	return &XrayServerHandler{
		repo:             repo,
		collector:        collector,
		crypto:           crypto,
		managementProbes: make(map[int64]time.Time),
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
	ListenPort        int    `json:"listen_port"`         // Agent HTTP 监听端口(0 = 用默认 23889);通过 install 脚本注入 MMWX_LISTEN_PORT
	PullAddress       string `json:"pull_address"`        // 对于pull模式
	PullPort          int    `json:"pull_port"`           // 对于pull模式
	PullToken         string `json:"pull_token"`          // 对于pull模式
	StealSelf         bool   `json:"steal_self"`          // 代理安装后自动安装xray+nginx
	FrontService      string `json:"front_service"`       // xray | nginx 使用nginx还是xray做443前置（nginx 保留，尚未启用）
	Domain            string `json:"domain"`              // 服务器域（443模式）
	Use443            bool   `json:"use_443"`             // 使用 443 端口与 nginx 隧道
	StealMode         string `json:"steal_mode"`          // "tunnel" | "fallback"，默认 tunnel
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
	TrafficUsed int64                     `json:"traffic_used"`
	Inbounds    []RemoteServerInboundInfo `json:"inbounds"`
	Encrypted   bool                      `json:"encrypted"`
	WsConnected bool                      `json:"ws_connected"`
}

// RemoteServersListResponse 表示所有远程服务器的响应
type RemoteServersListResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Servers []RemoteServerExtended `json:"servers,omitempty"`
}

// RemoteServerDeleteRequest 表示删除远程服务器的请求
type RemoteServerDeleteRequest struct {
	ID int64 `json:"id"`
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
		return fmt.Sprintf("# pull模式：主服务器将从 %s:%d 拉取流量数据\n# 请确保子服务器已配置 MMWX_MODE=child MMWX_CHILD_API_TOKEN=%s", shellCommentText(server.PullAddress), server.PullPort, shellCommentText(agentToken)), nil
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
	mmwxDomain := getDomainFromMasterURL(h.repo, ctx)

	isLocalByAddr := false
	mmwxIPs := resolveIPs(mmwxDomain)
	mmwxIPSet := make(map[string]struct{})
	for _, ip := range mmwxIPs {
		mmwxIPSet[ip] = struct{}{}
	}
	checkAddrLocal := func(addr string) bool {
		for _, ip := range resolveIPs(addr) {
			if _, ok := mmwxIPSet[ip]; ok {
				return true
			}
		}
		return false
	}
	if mmwxDomain != "" {
		if req.IPAddress != "" {
			isLocalByAddr = checkAddrLocal(req.IPAddress)
		}
		if !isLocalByAddr && req.PullAddress != "" {
			isLocalByAddr = checkAddrLocal(req.PullAddress)
		}
	}

	if reqDomain != "" && mmwxDomain != "" && reqDomain == mmwxDomain && !isLocalByAddr {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "域名不能与 MMWX 安装域名相同",
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

	// 本机检测：域名解析 IP 与 mmwx_domain 解析 IP 一致则为本机
	isLocal := isLocalByAddr
	if !isLocal && reqDomain != "" && mmwxDomain != "" {
		reqIPs, err1 := net.LookupHost(reqDomain)
		mmwxIPs, err2 := net.LookupHost(mmwxDomain)
		if err1 == nil && err2 == nil {
			mmwxIPSet := make(map[string]struct{})
			for _, ip := range mmwxIPs {
				mmwxIPSet[ip] = struct{}{}
			}
			for _, ip := range reqIPs {
				if _, ok := mmwxIPSet[ip]; ok {
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

// 通过 ID 删除远程服务器
func (h *XrayServerHandler) DeleteRemoteServer(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	if r.Method != "POST" {
		stdhttp.Error(w, "Method not allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	var req RemoteServerDeleteRequest
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

	ctx := r.Context()
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, req.ID)
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
		_ = json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: "删除服务器失败",
		})
		return
	}
	defer release()
	ctx = leasedCtx
	if err := h.repo.DeleteRemoteServer(ctx, req.ID); err != nil {
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

	// 删后清掉该 server 的 inbound 内存缓存,避免残留(否则同 id 复用时会读到旧 inbound 数据)。
	if h.remoteManager != nil && h.remoteManager.inboundCache != nil {
		h.remoteManager.inboundCache.Invalidate(req.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RemoteServerResponse{
		Success: true,
		Message: "服务器已删除",
	})
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RemoteServerResponse{
			Success: false,
			Message: msg,
		})
		return
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

	// 域名变更同步刷新该服务器下所有节点 clash_config.server。
	// Domain 优先于 IP(动态 IP 场景下域名稳定),空 Domain 时回退到 IPAddress。
	newDomain := strings.TrimSpace(req.Domain)
	oldDomain := strings.TrimSpace(oldServer.Domain)
	if newDomain != oldDomain {
		addr := newDomain
		if addr == "" {
			addr = oldServer.IPAddress
		}
		if addr != "" {
			finalName := req.Name
			if finalName == "" {
				finalName = oldServer.Name
			}
			if n, err := h.repo.RefreshNodesServerAddress(ctx, finalName, addr); err != nil {
				log.Printf("[Remote Server] Refresh nodes server address failed for %s: %v", finalName, err)
			} else if n > 0 {
				log.Printf("[Remote Server] Refreshed %d node(s) server address → %s after domain change on %s", n, addr, finalName)
			}
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
	mmwxDomain := getDomainFromMasterURL(h.repo, ctx)
	masterURL, _ := h.repo.GetSystemSetting(ctx, "master_url")
	httpsEnabled := strings.HasPrefix(masterURL, "https://")

	sameIP := false
	if mmwxDomain != "" {
		addrIPs := resolveIPs(address)
		mmwxIPs := resolveIPs(mmwxDomain)
		mmwxIPSet := make(map[string]struct{})
		for _, ip := range mmwxIPs {
			mmwxIPSet[ip] = struct{}{}
		}
		for _, ip := range addrIPs {
			if _, ok := mmwxIPSet[ip]; ok {
				sameIP = true
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"same_ip":       sameIP,
		"master_domain": mmwxDomain,
		"https_enabled": httpsEnabled,
	})
}
