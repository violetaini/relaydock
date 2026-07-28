package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"miaomiaowux/internal/child"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/version"
)

// ChildAPIHandler 处理来自主服务器的 API 请求（对于pull模式）
type ChildAPIHandler struct {
	client      *child.Client
	configToken string // 用于身份验证的令牌
}

// 创建一个新的子 API 处理程序
func NewChildAPIHandler(client *child.Client, configToken string) *ChildAPIHandler {
	return &ChildAPIHandler{
		client:      client,
		configToken: configToken,
	}
}

// 处理流量数据的 HTTP 请求
func (h *ChildAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 只允许 GET 方法
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 验证请求
	if !h.authenticate(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Unauthorized",
		})
		return
	}

	// 获取流量统计
	stats, err := h.client.GetStats()
	if err != nil {
		log.Printf("[Child API] Failed to get stats: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Failed to collect stats",
		})
		return
	}

	// 返回统计数据
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"stats":   stats,
	})
}

// 处理速度数据的 HTTP 请求
func (h *ChildAPIHandler) ServeSpeedHTTP(w http.ResponseWriter, r *http.Request) {
	// 只允许 GET 方法
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 验证请求
	if !h.authenticate(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Unauthorized",
		})
		return
	}

	// 获取速度数据
	uploadSpeed, downloadSpeed := h.client.GetSpeed()

	// 返回速度数据
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"upload_speed":   uploadSpeed,
		"download_speed": downloadSpeed,
	})
}

// 验证检查请求是否被授权
func (h *ChildAPIHandler) authenticate(r *http.Request) bool {
	if h.configToken == "" {
		// 如果未配置令牌，则允许所有请求（不建议用于生产）
		return true
	}

	// 检查授权标头
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}

	// 支持“Bearer <token>”格式
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		return token == h.configToken
	}

	// 还支持普通令牌
	return auth == h.configToken
}

// RemoteHeartbeatRequest代表来自远程服务器的心跳请求
type RemoteHeartbeatRequest struct {
	BootTime     int64 `json:"boot_time"`      // MMWX进程启动时间（Unix时间戳）
	XrayBootTime int64 `json:"xray_boot_time"` // Xray 进程开始时间（Unix 时间戳）
	XrayPID      int   `json:"xray_pid"`       // 当前 X 射线进程 ID
	ListenPort   int   `json:"listen_port"`    // 代理HTTP监听端口
	LocalTime    int64 `json:"local_time"`     // agent 本地 Unix 时间戳，用于时钟偏差检测
	// PublicIPv4/v6 由 agent 端 ipProbeLoop 缓存后随心跳上报(WS auth/heartbeat 同款字段)。
	// master 优先用上报值写 db,fallback 才用 r.RemoteAddr 并强校验类型(避免 v6 写 v4 字段)。
	// 老 agent 不发 → 字段为空 → 走 fallback 路径,行为退化为现状。
	PublicIPv4 string `json:"public_ipv4,omitempty"`
	PublicIPv6 string `json:"public_ipv6,omitempty"`
}

// RemoteHeartbeatResponse 表示心跳响应
type RemoteHeartbeatResponse struct {
	Success          bool   `json:"success"`
	Message          string `json:"message"`
	MmwxRestarted    bool   `json:"mmwx_restarted,omitempty"`     // 检测到 MMWX 重启
	XrayRestarted    bool   `json:"xray_restarted,omitempty"`     // 检测到 X 射线重新启动
	TokenExpiresSoon bool   `json:"token_expires_soon,omitempty"` // 令牌将在 24 小时内过期
	TokenExpiresAt   int64  `json:"token_expires_at,omitempty"`   // 令牌过期时间戳
	ServerTime       int64  `json:"server_time"`                  // 当前服务器时间
}

// RemoteHeartbeat 处理来自远程服务器的心跳请求
// 该端点不需要管理员身份验证，只需要远程令牌验证
func (h *XrayServerHandler) RemoteHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("User-Agent") != version.AgentUserAgent {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(RemoteHeartbeatResponse{
			Success:    false,
			Message:    "Forbidden",
			ServerTime: time.Now().Unix(),
		})
		return
	}

	// 加密中间件处理
	crypto, cryptoErr := handleHTTPCrypto(r, w, h.crypto)
	if crypto == nil {
		return
	}
	_ = cryptoErr

	token := crypto.Token
	if token == "" {
		token = r.Header.Get("MM-Remote-Token")
	}
	if token == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(RemoteHeartbeatResponse{
			Success:    false,
			Message:    "缺少认证Token",
			ServerTime: time.Now().Unix(),
		})
		return
	}

	// 解析请求体
	var req RemoteHeartbeatRequest
	json.Unmarshal(crypto.Body, &req)

	// 获取客户端IP — X-Forwarded-For > X-Real-IP > r.RemoteAddr
	rawIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// 从逗号分隔列表中获取第一个 IP
		rawIP = strings.Split(forwarded, ",")[0]
		rawIP = strings.TrimSpace(rawIP)
	} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		rawIP = realIP
	}
	// 用 stripPort 正确处理 v4 / [v6]:port / 裸 v6 三种形式。
	// 老代码用 strings.LastIndex(":") 截断,对裸 v6 会把最后一段误删,留下半截 v6 字符串塞进 db.ip_address。
	clientIP := stripPort(rawIP)
	clientParsed := net.ParseIP(clientIP)
	clientIsV4 := clientParsed != nil && clientParsed.To4() != nil

	// 严格选 v4 / v6 字段(同 WS handleHeartbeat 模式):
	//   1) 优先用 agent 上报的 public_ipv4/public_ipv6(经 ipProbeLoop 校验过的本机出口 IP)
	//   2) fallback 用 clientIP,但**只在类型匹配时**才写对应字段 — 避免 agent v6 拨号 master →
	//      master 把 clientIP(v6) 当 v4 塞进 ip_address → IPv4-only master 反向请求全部失败
	v4 := ""
	if reported := strings.TrimSpace(req.PublicIPv4); reported != "" {
		if p := net.ParseIP(reported); p != nil && p.To4() != nil {
			v4 = reported
		}
	}
	if v4 == "" && clientIsV4 {
		v4 = clientIP
	}

	v6 := ""
	if reported := strings.TrimSpace(req.PublicIPv6); reported != "" {
		if p := net.ParseIP(reported); p != nil && p.To4() == nil {
			v6 = reported
		}
	}
	if v6 == "" && clientParsed != nil && !clientIsV4 {
		v6 = clientIP
	}

	ctx := r.Context()

	// 构建心跳更新 — v4/v6 字段空字符串走 storage 层 COALESCE/NULLIF 保留 db 旧值
	update := storage.HeartbeatUpdate{
		Token:       token,
		IPAddress:   v4,
		IPAddressV6: v6,
		ListenPort:  req.ListenPort,
	}

	// 从 Unix 时间戳转换启动时间
	if req.BootTime > 0 {
		bootTime := time.Unix(req.BootTime, 0)
		update.BootTime = &bootTime
	}
	if req.XrayBootTime > 0 {
		xrayBootTime := time.Unix(req.XrayBootTime, 0)
		update.XrayBootTime = &xrayBootTime
	}
	if req.LocalTime > 0 {
		offset := req.LocalTime - time.Now().Unix()
		update.TimeOffsetSeconds = &offset
	}

	// 通过重启检测更新心跳
	result, err := h.repo.UpdateRemoteServerHeartbeatWithRestart(ctx, update)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(RemoteHeartbeatResponse{
				Success:    false,
				Message:    "无效的Token",
				ServerTime: time.Now().Unix(),
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, storage.ErrRemoteListenPortMismatch) {
			w.WriteHeader(http.StatusConflict)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		json.NewEncoder(w).Encode(RemoteHeartbeatResponse{
			Success:    false,
			Message:    fmt.Sprintf("更新心跳失败: %s", err.Error()),
			ServerTime: time.Now().Unix(),
		})
		return
	}

	// 记录重启事件
	if result.MmwxRestarted {
		log.Printf("[RemoteHeartbeat] Detected MMWX restart for token %s... (boot count: %d)", token[:8], result.BootCount)
	}
	if result.XrayRestarted {
		log.Printf("[RemoteHeartbeat] Detected Xray restart for token %s... (xray boot count: %d)", token[:8], result.XrayBootCount)
	}

	if result.PreviousStatus != "connected" {
		SendServerOnlineNotification(ctx, result.ServerName, clientIP)
	}

	// agent IP 漂移 → 同步刷新已存在节点的 clash_config.server,避免节点继续指向旧 IP
	if result.IPChanged && result.Server != nil {
		if newHost := chooseClashServerHost(result.Server); newHost != "" {
			if n, e := h.repo.RefreshNodesServerAddress(ctx, result.Server.Name, newHost); e != nil {
				log.Printf("[RemoteHeartbeat] refresh nodes server address for %s failed: %v", result.Server.Name, e)
			} else if n > 0 {
				log.Printf("[RemoteHeartbeat] refreshed %d node(s) clash.server → %s for %s", n, newHost, result.Server.Name)
			}
		}
		// v6 节点单独刷成新的 IPv6 地址(RefreshNodesServerAddress 只动 v4/域名节点)
		if v6 := strings.TrimSpace(result.Server.IPAddressV6); v6 != "" {
			if n, e := h.repo.RefreshNodesServerAddressV6(ctx, result.Server.Name, v6); e != nil {
				log.Printf("[RemoteHeartbeat] refresh v6 nodes for %s failed: %v", result.Server.Name, e)
			} else if n > 0 {
				log.Printf("[RemoteHeartbeat] refreshed %d v6 node(s) clash.server → %s for %s", n, v6, result.Server.Name)
			}
		}
		// DDNS:把新 IP 同步到 pull_address 域名的 A/AAAA 记录
		if h.ddnsManager != nil && result.Server.DDNSEnabled {
			go h.ddnsManager.Trigger(context.Background(), result.Server)
		}
	}

	// 首次连接或 Xray 重启时推送限速配置（非 WebSocket 模式的补偿）
	if result.ServerID > 0 && h.limiterPusher != nil {
		if result.PreviousStatus != "connected" || result.XrayRestarted {
			go h.limiterPusher.PushToServer(context.Background(), result.ServerID)
		}
	}

	// 重置成功心跳时的推送失败计数（连接正常）
	if result.ServerID > 0 {
		if err := h.repo.ResetRemoteServerPushFailCount(ctx, result.ServerID); err != nil {
			log.Printf("[RemoteHeartbeat] Failed to reset push fail count for server %d: %v", result.ServerID, err)
		}
	}

	resp := RemoteHeartbeatResponse{
		Success:          true,
		Message:          "心跳成功",
		MmwxRestarted:    result.MmwxRestarted,
		XrayRestarted:    result.XrayRestarted,
		TokenExpiresSoon: result.TokenExpiresSoon,
		ServerTime:       time.Now().Unix(),
	}

	if result.TokenExpiresAt != nil {
		resp.TokenExpiresAt = result.TokenExpiresAt.Unix()
	}

	respData, _ := json.Marshal(resp)
	writeHTTPCryptoResponse(w, crypto.Session, respData)
}

// RefreshRemoteTokenResponse 是令牌刷新端点的响应
type RefreshRemoteTokenResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	NewToken  string `json:"new_token,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"` // Unix时间戳
}

// 处理远程服务器的令牌刷新
func (h *XrayServerHandler) RefreshRemoteToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("User-Agent") != version.AgentUserAgent {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{
			Success: false,
			Message: "Forbidden",
		})
		return
	}

	// 从标头获取令牌
	token := r.Header.Get("MM-Remote-Token")
	if token == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{
			Success: false,
			Message: "Missing MM-Remote-Token header",
		})
		return
	}

	// 尝试刷新令牌
	ctx := r.Context()
	server, lookupErr := h.repo.GetRemoteServerByToken(ctx, token)
	if lookupErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{Success: false, Message: "Invalid token"})
		return
	}
	leasedCtx, release, leaseErr := h.repo.AcquireRemoteServerMutationLease(ctx, server.ID)
	if leaseErr != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(leaseErr, storage.ErrRemoteInstallationActive) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{
				Success: false,
				Message: "Server installation is active; retry after it completes",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{Success: false, Message: "Failed to acquire server mutation lease"})
		return
	}
	defer release()
	ctx = leasedCtx
	// The token may have changed while this request waited for an installation.
	server, lookupErr = h.repo.GetRemoteServerByToken(ctx, token)
	if lookupErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{Success: false, Message: "Invalid token"})
		return
	}
	newToken, expiresAt, err := h.repo.RefreshRemoteServerToken(ctx, token)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")

		// 检查具体错误
		if err.Error() == "token can only be refreshed within 24 hours of expiration" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{
				Success: false,
				Message: err.Error(),
			})
			return
		}

		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{
				Success: false,
				Message: "Invalid token",
			})
			return
		}

		log.Printf("[Remote] Failed to refresh token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{
			Success: false,
			Message: "Failed to refresh token",
		})
		return
	}
	if err := syncRemoteExpiryGuardAgentToken(ctx, h.repo, server.ID, newToken); err != nil {
		log.Printf("[Remote] Failed to synchronize refreshed token to expiry guard for server %d: %v", server.ID, err)
	}

	log.Printf("[Remote] Token refreshed successfully, new expiration: %s", expiresAt.Format(time.RFC3339))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RefreshRemoteTokenResponse{
		Success:   true,
		Message:   "Token refreshed successfully",
		NewToken:  newToken,
		ExpiresAt: expiresAt.Unix(),
	})
}

func (h *XrayServerHandler) getMasterPort() string {
	if port := os.Getenv("PORT"); port != "" {
		return port
	}
	return "12889"
}

func (h *XrayServerHandler) masterPublicKeyBase64() string {
	if h.crypto != nil && h.crypto.Identity != nil {
		return h.crypto.Identity.PublicKeyBase64()
	}
	return ""
}

const panelSourceIPsEnv = "ARCWAY_PANEL_IPS"

func normalizePanelSourceIPs(raw string) ([]string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	seen := make(map[string]struct{}, len(fields))
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		ip := net.ParseIP(strings.TrimSpace(field))
		if ip == nil {
			return nil, fmt.Errorf("invalid panel source IP %q", field)
		}
		normalized := ip.String()
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Slice(result, func(i, j int) bool {
		leftV4 := net.ParseIP(result[i]).To4() != nil
		rightV4 := net.ParseIP(result[j]).To4() != nil
		if leftV4 != rightV4 {
			return leftV4
		}
		return result[i] < result[j]
	})
	return result, nil
}

// configuredPanelSourceIPs returns the addresses remote servers will see when
// the panel connects to their management ports. NAT deployments must set the
// environment variable explicitly; direct public hosts can be detected safely.
func configuredPanelSourceIPs() ([]string, error) {
	if configured := strings.TrimSpace(os.Getenv(panelSourceIPsEnv)); configured != "" {
		addresses, err := normalizePanelSourceIPs(configured)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, errors.New("panel source IP list is empty")
		}
		return addresses, nil
	}

	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("list panel interfaces: %w", err)
	}
	detected := make([]string, 0, len(interfaceAddresses))
	for _, address := range interfaceAddresses {
		ipText := address.String()
		if host, _, splitErr := net.SplitHostPort(ipText); splitErr == nil {
			ipText = host
		} else if ip, _, cidrErr := net.ParseCIDR(ipText); cidrErr == nil {
			ipText = ip.String()
		}
		ip := net.ParseIP(strings.TrimSpace(ipText))
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
			continue
		}
		detected = append(detected, ip.String())
	}
	detected, err = normalizePanelSourceIPs(strings.Join(detected, " "))
	if err != nil {
		return nil, err
	}
	if len(detected) == 0 {
		return nil, fmt.Errorf("no public panel address detected; set %s to the panel egress IPs", panelSourceIPsEnv)
	}
	return detected, nil
}

// 返回远程服务器的安装脚本
func (h *XrayServerHandler) GetRemoteInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	presentedCredential := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	var server *storage.RemoteServer
	var err error
	if strings.HasPrefix(presentedCredential, remoteInstallTicketPrefix) {
		server, err = h.repo.ConsumeRemoteServerInstallTicket(r.Context(), presentedCredential, time.Now())
	} else {
		// Backward compatibility for already-issued commands. Newly generated
		// commands always use a five-minute, single-consumption ticket.
		server, err = h.repo.GetRemoteServerByToken(r.Context(), presentedCredential)
	}
	if err != nil || server == nil || (server.TokenExpiresAt != nil && !server.TokenExpiresAt.After(time.Now())) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := server.Token
	guardSecret, err := h.repo.GetOrCreateRemoteServerGuardSecret(r.Context(), server.ID)
	if err != nil {
		http.Error(w, "Unable to initialize expiry guard", http.StatusInternalServerError)
		return
	}
	guardSHA256AMD64, err := expiryGuardAssetSHA256("arcway-expiry-guard-linux-amd64")
	if err != nil {
		http.Error(w, "Expiry guard release asset is unavailable", http.StatusServiceUnavailable)
		return
	}
	guardSHA256ARM64, err := expiryGuardAssetSHA256("arcway-expiry-guard-linux-arm64")
	if err != nil {
		http.Error(w, "Expiry guard release asset is unavailable", http.StatusServiceUnavailable)
		return
	}
	agentSHA256AMD64, err := agentAssetSHA256("mmw-agent-linux-amd64")
	if err != nil {
		http.Error(w, "Agent release asset is unavailable", http.StatusServiceUnavailable)
		return
	}
	agentSHA256ARM64, err := agentAssetSHA256("mmw-agent-linux-arm64")
	if err != nil {
		http.Error(w, "Agent release asset is unavailable", http.StatusServiceUnavailable)
		return
	}
	panelSourceIPs, err := configuredPanelSourceIPs()
	if err != nil {
		http.Error(w, "Panel source IPs are not configured", http.StatusServiceUnavailable)
		return
	}
	stealSelf := server.StealSelf
	stealMode := "default"
	if stealSelf && (server.StealMode == "tunnel" || server.StealMode == "fallback") {
		stealMode = server.StealMode
	}
	xrayMode := server.XrayMode
	if xrayMode != "embedded" {
		xrayMode = "external"
	}
	nginxMode := strings.TrimSpace(server.NginxMode)
	if nginxMode != "reuse_existing" {
		nginxMode = "managed"
	}
	agentConnectionMode := server.ConnectionMode
	switch agentConnectionMode {
	case storage.ConnectionModePush:
		agentConnectionMode = "http"
	case storage.ConnectionModeWebSocket:
		agentConnectionMode = "websocket"
	default:
		http.Error(w, "Pull-mode servers do not use the remote installer", http.StatusConflict)
		return
	}
	// The authenticated server record is the sole source of installation policy.
	// Query parameters are deliberately ignored so a leaked node token cannot
	// authorize port takeover or drift the protected management port.
	listenPort := server.ListenPort
	if listenPort == 0 {
		listenPort = 23889
	}
	if !storage.IsValidRemoteManagementListenPort(listenPort) || listenPort == 0 {
		http.Error(w, "Remote management port is invalid", http.StatusConflict)
		return
	}
	listenPortParam := strconv.Itoa(listenPort)
	// 计算 install 脚本里写入的 SERVER:
	// 优先用系统设置 master_url 里的 host(用户配置的对外可达域名),
	// 这是 agent 真正访问主控的地址。仅在 master_url 未配置时回退到 r.Host(可能是 nginx upstream 名,如 miaomiaowu_web,不可对外访问)。
	// 若 master_url 已显式配置,EXPLICIT_MASTER=1 在脚本里禁用"同机部署"自动覆盖
	// (避免在主控本机上安装 agent 时把 master_url 改写成 127.0.0.1)。
	normalizedIngress, hasExplicitMaster, normalizeErr := h.effectiveRemoteInstallMasterURL(r.Context(), r)
	if normalizeErr != nil {
		http.Error(w, "Configured master URL is invalid", http.StatusServiceUnavailable)
		return
	}
	parsedIngress, parseErr := url.Parse(normalizedIngress)
	if parseErr != nil || parsedIngress.Host == "" {
		http.Error(w, "Request host is invalid", http.StatusBadRequest)
		return
	}
	scriptServer := parsedIngress.Host
	scriptProtocol := parsedIngress.Scheme
	explicitMaster := "0"
	if hasExplicitMaster {
		explicitMaster = "1"
	}
	policyContext := storage.RemoteInstallationPolicyContext{
		PanelSourceIPs:  panelSourceIPs,
		MasterURL:       normalizedIngress,
		MasterPublicKey: h.masterPublicKeyBase64(),
	}
	policyFingerprint, err := storage.RemoteServerInstallationPolicyFingerprintWithContext(server, policyContext)
	if err != nil {
		http.Error(w, "Remote installation policy is invalid", http.StatusConflict)
		return
	}
	installationNonce, err := generateSecureToken()
	if err != nil {
		http.Error(w, "Unable to initialize installation transaction", http.StatusInternalServerError)
		return
	}
	releaseAssetBaseURL := fmt.Sprintf("https://github.com/%s/releases/download/v%s", githubRepo, version.Version)

	// 返回安装脚本内容
	script := `#!/bin/bash
# MMWX Remote Server Installation Script
# This script installs panel-provided MMWX assets and configures a remote server

set -e
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this installer as root" >&2
    exit 1
fi

if ! command -v flock >/dev/null 2>&1; then
    echo "ERROR: install util-linux/flock before retrying; no system files were changed" >&2
    exit 1
fi
exec 9>/run/arcway-node-install.lock
if ! flock -n 9; then
    echo "ERROR: another Arcway node installation is already running" >&2
    exit 1
fi

select_download_root() {
    local candidate="" available="" best_root="" best_available=0
    for candidate in /var/tmp /tmp; do
        [ -d "$candidate" ] && [ -w "$candidate" ] || continue
        available=$(df -Pk "$candidate" 2>/dev/null | awk 'NR == 2 { print $4 }')
        case "$available" in ''|*[!0-9]*) continue ;; esac
        if [ "$available" -gt "$best_available" ]; then
            best_root="$candidate"
            best_available="$available"
        fi
    done
    if [ -z "$best_root" ]; then
        echo "ERROR: no writable temporary directory is available" >&2
        return 1
    fi
    if [ "$best_available" -lt 131072 ]; then
        echo "ERROR: temporary storage has less than 128 MiB free; clean /tmp or /var/tmp and retry" >&2
        df -h /tmp /var/tmp 2>/dev/null >&2 || true
        return 1
    fi
    printf '%s\n' "$best_root"
}
DOWNLOAD_ROOT=$(select_download_root) || exit 1
DOWNLOAD_DIR=$(mktemp -d "${DOWNLOAD_ROOT%/}/arcway-install.XXXXXX")
chmod 0700 "$DOWNLOAD_DIR"
trap 'rm -rf "$DOWNLOAD_DIR"' EXIT
trap 'exit 130' HUP INT TERM
AGENT_DOWNLOAD="$DOWNLOAD_DIR/mmw-agent"
GUARD_DOWNLOAD="$DOWNLOAD_DIR/arcway-expiry-guard"
CURL_AUTH_HEADER_FILE="$DOWNLOAD_DIR/curl-auth.header"
CURL_INSTALL_NONCE_HEADER_FILE="$DOWNLOAD_DIR/curl-install-nonce.header"
CURL_INSTALL_POLICY_HEADER_FILE="$DOWNLOAD_DIR/curl-install-policy.header"

TOKEN=` + shellSingleQuote(token) + `
INSTALL_NONCE=` + shellSingleQuote(installationNonce) + `
INSTALL_POLICY_SHA256=` + shellSingleQuote(policyFingerprint) + `
GUARD_SECRET=` + shellSingleQuote(guardSecret) + `
SERVER=` + shellSingleQuote(scriptServer) + `
SCRIPT_PROTOCOL=` + shellSingleQuote(scriptProtocol) + `
EXPLICIT_MASTER=` + shellSingleQuote(explicitMaster) + `
AUTO_STEAL_SELF=` + shellSingleQuote(map[bool]string{true: "1", false: "0"}[stealSelf]) + `
STEAL_MODE=` + shellSingleQuote(stealMode) + `
NGINX_MODE=` + shellSingleQuote(nginxMode) + `
XRAY_MODE=` + shellSingleQuote(xrayMode) + `
CONNECTION_MODE=` + shellSingleQuote(agentConnectionMode) + `
MASTER_PUBLIC_KEY=` + shellSingleQuote(h.masterPublicKeyBase64()) + `
MASTER_PORT=` + shellSingleQuote(h.getMasterPort()) + `
LISTEN_PORT=` + shellSingleQuote(listenPortParam) + `
PANEL_SOURCE_IPS=` + shellSingleQuote(strings.Join(panelSourceIPs, " ")) + `
ASSET_RELEASE_BASE_URL=` + shellSingleQuote(releaseAssetBaseURL) + `

# Keep the long-lived node token out of curl argv (/proc/*/cmdline). curl reads
# these root-only files directly; the enclosing 0700 directory is deleted on exit.
printf 'Authorization: Bearer %s\n' "$TOKEN" > "$CURL_AUTH_HEADER_FILE"
printf 'User-Agent: %s\n' ` + shellSingleQuote(version.AgentUserAgent) + ` >> "$CURL_AUTH_HEADER_FILE"
printf 'X-Arcway-Install-Nonce: %s\n' "$INSTALL_NONCE" > "$CURL_INSTALL_NONCE_HEADER_FILE"
printf 'X-Arcway-Install-Policy-SHA256: %s\n' "$INSTALL_POLICY_SHA256" > "$CURL_INSTALL_POLICY_HEADER_FILE"
chmod 0600 "$CURL_AUTH_HEADER_FILE" "$CURL_INSTALL_NONCE_HEADER_FILE" "$CURL_INSTALL_POLICY_HEADER_FILE"

# 协议:优先用主控注入的 SCRIPT_PROTOCOL(来自系统设置 master_url 的 scheme),
# 否则按 SERVER 是否带端口启发判断(开发场景常见 http)。
if [ -n "$SCRIPT_PROTOCOL" ]; then
    PROTOCOL="$SCRIPT_PROTOCOL"
elif [[ "$SERVER" == *":"* ]]; then
    PROTOCOL="http"
else
    PROTOCOL="https"
fi

if [ "$PROTOCOL" = "http" ]; then
    case "$SERVER" in
        localhost|localhost:*|127.0.0.1|127.0.0.1:*|\[::1\]|\[::1\]:*) ;;
        *)
            echo "ERROR: plaintext master transport is allowed only on loopback; configure an HTTPS master_url" >&2
            exit 1
            ;;
    esac
fi

MASTER_URL="${PROTOCOL}://${SERVER}"

echo "=========================================="
echo "  MMWX Remote Server Installation"
echo "=========================================="
echo ""
echo "Master Server: $MASTER_URL"
echo ""

# 检测 init 系统:OpenRC(Alpine 首选)/ systemd(主流)/ 兜底用 nohup + rc.local。
# 安装器不会在事务外安装 init 包；极简系统直接使用兜底 supervisor。
HAS_SYSTEMD=0
HAS_OPENRC=0
IS_ALPINE=0
if [ -f /etc/alpine-release ]; then
    IS_ALPINE=1
elif [ -f /etc/os-release ] && grep -qE '^ID=alpine' /etc/os-release 2>/dev/null; then
    IS_ALPINE=1
fi
# Alpine 优先 OpenRC;非 Alpine 仍然先看 systemd(主流发行版默认)
if [ "$IS_ALPINE" = "1" ]; then
    if command -v rc-service >/dev/null 2>&1; then HAS_OPENRC=1; fi
fi
if [ "$HAS_OPENRC" = "0" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=1
fi
if [ "$HAS_SYSTEMD" = "0" ] && [ "$HAS_OPENRC" = "0" ] && command -v rc-service >/dev/null 2>&1; then
    HAS_OPENRC=1
fi
INIT_NAME="none"
if [ "$HAS_OPENRC" = "1" ]; then
    INIT_NAME="openrc"
elif [ "$HAS_SYSTEMD" = "1" ]; then
    INIT_NAME="systemd"
fi
if [ "$IS_ALPINE" = "1" ]; then
    INIT_NAME="${INIT_NAME} (Alpine)"
fi
echo "Init system: $INIT_NAME"
echo "Temporary workspace: $DOWNLOAD_DIR"

# All network downloads and integrity checks complete before the running node is touched.
echo "[1/7] Downloading and verifying release assets..."
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH_NAME="amd64"
        AGENT_SHA256=` + shellSingleQuote(agentSHA256AMD64) + `
        GUARD_SHA256=` + shellSingleQuote(guardSHA256AMD64) + `
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        AGENT_SHA256=` + shellSingleQuote(agentSHA256ARM64) + `
        GUARD_SHA256=` + shellSingleQuote(guardSHA256ARM64) + `
        ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: install curl before retrying; no system packages were changed" >&2
    exit 1
fi

download_verified_asset() {
    local label="$1" destination="$2" expected_sha256="$3" github_url="$4" master_url="$5"
    local candidate="${destination}.download" actual_sha256=""
    rm -f "$candidate"

    echo "Downloading $label from GitHub Release..."
    if curl -fsSL --retry 2 --retry-delay 1 --connect-timeout 10 --max-time 180 \
        -o "$candidate" "$github_url"; then
        actual_sha256=$(sha256sum "$candidate" | awk '{ print $1 }')
        if [ "$actual_sha256" = "$expected_sha256" ]; then
            mv -f "$candidate" "$destination"
            return 0
        fi
        echo "WARNING: GitHub $label SHA-256 mismatch; retrying from the authenticated master" >&2
    else
        echo "WARNING: GitHub $label download failed; retrying from the authenticated master" >&2
    fi
    rm -f "$candidate"

    echo "Downloading $label from master fallback..."
    if ! curl -fsSL --connect-timeout 10 --max-time 180 \
        -H @"$CURL_AUTH_HEADER_FILE" \
        -o "$candidate" "$master_url"; then
        echo "ERROR: unable to download $label from GitHub or master; check network and temporary storage" >&2
        rm -f "$candidate"
        return 1
    fi
    actual_sha256=$(sha256sum "$candidate" | awk '{ print $1 }')
    if [ "$actual_sha256" != "$expected_sha256" ]; then
        echo "ERROR: $label SHA-256 verification failed; installation aborted" >&2
        rm -f "$candidate"
        return 1
    fi
    mv -f "$candidate" "$destination"
}

AGENT_GITHUB_URL="${ASSET_RELEASE_BASE_URL}/mmw-agent-linux-${ARCH_NAME}"
AGENT_MASTER_URL="${MASTER_URL}/api/remote/mmw-agent?arch=${ARCH_NAME}"
download_verified_asset "mmw-agent" "$AGENT_DOWNLOAD" "$AGENT_SHA256" "$AGENT_GITHUB_URL" "$AGENT_MASTER_URL" || exit 1

GUARD_GITHUB_URL="${ASSET_RELEASE_BASE_URL}/arcway-expiry-guard-linux-${ARCH_NAME}"
GUARD_MASTER_URL="${MASTER_URL}/api/remote/expiry-guard?arch=${ARCH_NAME}"
download_verified_asset "Arcway expiry guard" "$GUARD_DOWNLOAD" "$GUARD_SHA256" "$GUARD_GITHUB_URL" "$GUARD_MASTER_URL" || exit 1

validate_elf() {
    [ -s "$1" ] || return 1
    [ "$(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n')" = "7f454c46" ]
}
if ! validate_elf "$AGENT_DOWNLOAD" || ! validate_elf "$GUARD_DOWNLOAD"; then
    echo "ERROR: 下载结果不是有效 ELF 可执行文件,安装中止" >&2
    exit 1
fi
if [ "$(sha256sum "$AGENT_DOWNLOAD" | awk '{ print $1 }')" != "$AGENT_SHA256" ]; then
    echo "ERROR: mmw-agent SHA-256 verification failed; installation aborted" >&2
    exit 1
fi
if [ "$(sha256sum "$GUARD_DOWNLOAD" | awk '{ print $1 }')" != "$GUARD_SHA256" ]; then
    echo "ERROR: expiry guard SHA-256 verification failed; installation aborted" >&2
    exit 1
fi
chmod 0700 "$AGENT_DOWNLOAD" "$GUARD_DOWNLOAD"

# System prerequisites are verified before the rollback transaction. The node
# installer never mutates the package database, so a failed install cannot leave
# unrelated dependency packages behind.
firewall_stack_ready() {
    command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1
}
if ! firewall_stack_ready; then
    echo "ERROR: install and enable nftables before retrying; no system packages were changed" >&2
    exit 1
fi
if [ -z "$PANEL_SOURCE_IPS" ]; then
    echo "ERROR: trusted panel source IPs are empty; configure ARCWAY_PANEL_IPS on the panel" >&2
    exit 1
fi
for PANEL_SOURCE_IP in $PANEL_SOURCE_IPS; do
    case "$PANEL_SOURCE_IP" in
        ''|*[!0-9A-Fa-f:.]*)
            echo "ERROR: invalid trusted panel source IP: $PANEL_SOURCE_IP" >&2
            exit 1
            ;;
    esac
done
for HOST_FILTER_SPEC in iptables:ip ip6tables:ip6; do
    HOST_FILTER_TOOL=${HOST_FILTER_SPEC%%:*}
    HOST_FILTER_NFT_FAMILY=${HOST_FILTER_SPEC#*:}
    if command -v "$HOST_FILTER_TOOL" >/dev/null 2>&1; then
        if ! command -v "${HOST_FILTER_TOOL}-restore" >/dev/null 2>&1; then
            echo "ERROR: ${HOST_FILTER_TOOL}-restore is required for atomic Arcway firewall updates" >&2
            exit 1
        fi
        if ! "$HOST_FILTER_TOOL" -w 5 -t filter -S INPUT >/dev/null 2>&1; then
            echo "ERROR: $HOST_FILTER_TOOL is installed but cannot inspect the host INPUT filter" >&2
            exit 1
        fi
        if "$HOST_FILTER_TOOL" -w 5 -t filter -S ARCWAY_PANEL_IN >/dev/null 2>&1; then
            if [ ! -x /usr/local/sbin/arcway-agent-firewall ] || \
                ! grep -q 'HOST_FILTER_CHAIN=ARCWAY_PANEL_IN' /usr/local/sbin/arcway-agent-firewall 2>/dev/null || \
                ! "$HOST_FILTER_TOOL" -w 5 -t filter -S ARCWAY_PANEL_IN | grep -F -- '--comment arcway-managed' >/dev/null 2>&1; then
                echo "ERROR: reserved $HOST_FILTER_NFT_FAMILY host firewall chain ARCWAY_PANEL_IN is not owned by the installed Arcway helper" >&2
                exit 1
            fi
        fi
    elif nft list chain "$HOST_FILTER_NFT_FAMILY" filter ARCWAY_PANEL_IN >/dev/null 2>&1; then
        echo "ERROR: $HOST_FILTER_TOOL cannot manage the existing Arcway host INPUT chain" >&2
        exit 1
    fi
done

retry_remote_install_post() {
    local callback_path="$1" max_time="$2" include_policy="$3"
    local attempt=1 delay=1 max_attempts=5
    while [ "$attempt" -le "$max_attempts" ]; do
		if [ "$include_policy" = "1" ]; then
			if curl -fsS --connect-timeout 5 --max-time "$max_time" -X POST \
				-H @"$CURL_AUTH_HEADER_FILE" \
				-H @"$CURL_INSTALL_NONCE_HEADER_FILE" \
				-H @"$CURL_INSTALL_POLICY_HEADER_FILE" \
				"${MASTER_URL}${callback_path}" >/dev/null; then
				return 0
			fi
		elif curl -fsS --connect-timeout 5 --max-time "$max_time" -X POST \
			-H @"$CURL_AUTH_HEADER_FILE" \
			-H @"$CURL_INSTALL_NONCE_HEADER_FILE" \
			"${MASTER_URL}${callback_path}" >/dev/null; then
            return 0
        fi
        if [ "$attempt" -lt "$max_attempts" ]; then
            sleep "$delay"
            if [ "$delay" -lt 8 ]; then delay=$((delay * 2)); fi
        fi
        attempt=$((attempt + 1))
    done
	return 1
}

INSTALL_RENEW_PID=""
INSTALL_HARD_STOP_PID=""
INSTALL_MAIN_PID=$$
INSTALL_RENEW_FAILED_FILE="$DOWNLOAD_DIR/install-renew-failed"
stop_install_renewal() {
	local renew_pid="$INSTALL_RENEW_PID" hard_stop_pid="$INSTALL_HARD_STOP_PID"
	[ -z "$renew_pid" ] || kill "$renew_pid" >/dev/null 2>&1 || true
	[ -z "$hard_stop_pid" ] || kill "$hard_stop_pid" >/dev/null 2>&1 || true
	[ -z "$renew_pid" ] || wait "$renew_pid" 2>/dev/null || true
	[ -z "$hard_stop_pid" ] || wait "$hard_stop_pid" 2>/dev/null || true
	INSTALL_RENEW_PID=""
	INSTALL_HARD_STOP_PID=""
}
start_install_renewal() {
	rm -f "$INSTALL_RENEW_FAILED_FILE"
	(
		exec 9>&-
		RENEW_SLEEP_PID=""
		stop_renew_worker() {
			trap - TERM INT HUP
			if [ -n "$RENEW_SLEEP_PID" ]; then
				kill "$RENEW_SLEEP_PID" >/dev/null 2>&1 || true
				wait "$RENEW_SLEEP_PID" 2>/dev/null || true
				RENEW_SLEEP_PID=""
			fi
			exit 0
		}
		trap stop_renew_worker TERM INT HUP
		consecutive_failures=0
		while :; do
			sleep 60 &
			RENEW_SLEEP_PID=$!
			if ! wait "$RENEW_SLEEP_PID"; then
				RENEW_SLEEP_PID=""
				exit 0
			fi
			RENEW_SLEEP_PID=""
			if retry_remote_install_post "/api/remote/install-renew" 10 0 >/dev/null 2>&1; then
				consecutive_failures=0
			else
				consecutive_failures=$((consecutive_failures + 1))
				if [ "$consecutive_failures" -ge 3 ]; then
					: > "$INSTALL_RENEW_FAILED_FILE"
					kill -TERM "$INSTALL_MAIN_PID" >/dev/null 2>&1 || true
					exit 1
				fi
			fi
		done
	) &
	INSTALL_RENEW_PID=$!
	# Stop with one full lease window left before the server's absolute two-hour
	# cap, so the EXIT trap can still quiesce and roll back under a live lock.
	(
		exec 9>&-
		HARD_STOP_SLEEP_PID=""
		stop_hard_stop_worker() {
			trap - TERM INT HUP
			if [ -n "$HARD_STOP_SLEEP_PID" ]; then
				kill "$HARD_STOP_SLEEP_PID" >/dev/null 2>&1 || true
				wait "$HARD_STOP_SLEEP_PID" 2>/dev/null || true
				HARD_STOP_SLEEP_PID=""
			fi
			exit 0
		}
		trap stop_hard_stop_worker TERM INT HUP
		sleep 5400 &
		HARD_STOP_SLEEP_PID=$!
		if ! wait "$HARD_STOP_SLEEP_PID"; then
			HARD_STOP_SLEEP_PID=""
			exit 0
		fi
		HARD_STOP_SLEEP_PID=""
		: > "$INSTALL_RENEW_FAILED_FILE"
		kill -TERM "$INSTALL_MAIN_PID" >/dev/null 2>&1 || true
	) &
	INSTALL_HARD_STOP_PID=$!
}
assert_install_lease() {
	if [ -z "$INSTALL_RENEW_PID" ] || [ -e "$INSTALL_RENEW_FAILED_FILE" ] || ! kill -0 "$INSTALL_RENEW_PID" >/dev/null 2>&1; then
		echo "ERROR: installation lease renewal stopped; refusing further changes" >&2
		return 1
	fi
	if ! retry_remote_install_post "/api/remote/install-renew" 10 0 >/dev/null 2>&1; then
		: > "$INSTALL_RENEW_FAILED_FILE"
		echo "ERROR: installation lease could not be renewed; refusing further changes" >&2
		return 1
	fi
}

# Start the durable panel-side transaction only after all downloads and basic
# host prerequisites pass. From this point, automatic panel writes are blocked
# until this exact one-time nonce commits or aborts the installation.
SERVER_LOCK_ATTEMPTED=0
SERVER_LOCK_STARTED=0
abort_remote_installation() {
	[ "$SERVER_LOCK_ATTEMPTED" = "1" ] || return 0
	stop_install_renewal
	if ! retry_remote_install_post "/api/remote/install-abort" 10 0 >/dev/null 2>&1; then
        echo "WARNING: panel installation lock could not be aborted; it will expire automatically" >&2
		return 1
    fi
    SERVER_LOCK_ATTEMPTED=0
	SERVER_LOCK_STARTED=0
}
quiesce_remote_installation() {
	[ "$SERVER_LOCK_STARTED" = "1" ] || return 1
	retry_remote_install_post "/api/remote/install-quiesce" 120 0
}
early_install_finish() {
    local install_status=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [ "$install_status" -ne 0 ]; then
		if ! abort_remote_installation; then
			echo "WARNING: the panel lock remains active and will expire automatically" >&2
		fi
    fi
    rm -rf "$DOWNLOAD_DIR"
    exit "$install_status"
}
SERVER_LOCK_ATTEMPTED=1
trap early_install_finish EXIT
trap 'exit 130' HUP INT TERM
if ! retry_remote_install_post "/api/remote/install-begin" 10 1; then
    echo "ERROR: the panel refused the installation transaction; another install may be active" >&2
    exit 1
fi
SERVER_LOCK_STARTED=1
start_install_renewal

XRAY_BIN=""
if [ "$XRAY_MODE" != "embedded" ]; then
    for CANDIDATE in "$(command -v xray 2>/dev/null || true)" /usr/local/bin/xray /usr/bin/xray /opt/xray/xray; do
        if [ -n "$CANDIDATE" ] && [ -x "$CANDIDATE" ]; then XRAY_BIN="$CANDIDATE"; break; fi
    done
    if [ -z "$XRAY_BIN" ] || ! "$XRAY_BIN" version >/dev/null 2>&1; then
        echo "ERROR: external Xray mode requires a working Xray installation; install Xray before retrying" >&2
        exit 1
    fi
fi

NGINX_BIN=""
if [ "$AUTO_STEAL_SELF" = "1" ]; then
    for CANDIDATE in "$(command -v nginx 2>/dev/null || true)" /usr/local/nginx/sbin/nginx /usr/sbin/nginx; do
        if [ -n "$CANDIDATE" ] && [ -x "$CANDIDATE" ]; then NGINX_BIN="$CANDIDATE"; break; fi
    done
    if [ -z "$NGINX_BIN" ] || ! "$NGINX_BIN" -t >/dev/null 2>&1; then
        echo "ERROR: takeover mode requires a working Nginx installation and valid configuration" >&2
        exit 1
    fi
fi

# The Agent can migrate Xray configuration and change Xray/Nginx service state
# during startup. Capture the complete data-plane surface before installing it.
XRAY_UNIT_PRESENT=0
NGINX_UNIT_PRESENT=0
OLD_XRAY_ACTIVE=0
OLD_NGINX_ACTIVE=0
OLD_XRAY_ENABLE_STATE=""
OLD_NGINX_ENABLE_STATE=""
if [ "$HAS_SYSTEMD" = "1" ]; then
    if systemctl cat xray >/dev/null 2>&1; then
        XRAY_UNIT_PRESENT=1
        OLD_XRAY_ENABLE_STATE=$(systemctl is-enabled xray 2>/dev/null || true)
        systemctl is-active --quiet xray && OLD_XRAY_ACTIVE=1 || true
    fi
    if systemctl cat nginx >/dev/null 2>&1; then
        NGINX_UNIT_PRESENT=1
        OLD_NGINX_ENABLE_STATE=$(systemctl is-enabled nginx 2>/dev/null || true)
        systemctl is-active --quiet nginx && OLD_NGINX_ACTIVE=1 || true
    fi
fi
reversible_systemd_enable_state() {
    case "$1" in
        enabled|enabled-runtime|disabled|static) return 0 ;;
        *) return 1 ;;
    esac
}
if [ "$XRAY_UNIT_PRESENT" = "1" ] && ! reversible_systemd_enable_state "$OLD_XRAY_ENABLE_STATE"; then
    echo "ERROR: xray.service has unsupported enable state '$OLD_XRAY_ENABLE_STATE'; normalize it before installing" >&2
    exit 1
fi
if [ "$NGINX_MODE" = "managed" ] && [ "$NGINX_UNIT_PRESENT" = "1" ] && ! reversible_systemd_enable_state "$OLD_NGINX_ENABLE_STATE"; then
    echo "ERROR: nginx.service has unsupported enable state '$OLD_NGINX_ENABLE_STATE'; normalize it before installing" >&2
    exit 1
fi
if [ "$XRAY_MODE" != "embedded" ] && { [ "$XRAY_UNIT_PRESENT" != "1" ] || [ "$OLD_XRAY_ACTIVE" != "1" ]; }; then
    echo "ERROR: external Xray mode requires an active systemd xray service so installation can be rolled back safely" >&2
    exit 1
fi
if [ "$AUTO_STEAL_SELF" = "1" ] && [ "$NGINX_MODE" = "managed" ] && { [ "$NGINX_UNIT_PRESENT" != "1" ] || [ "$OLD_NGINX_ACTIVE" != "1" ]; }; then
    echo "ERROR: takeover mode requires an active systemd nginx service so installation can be rolled back safely" >&2
    exit 1
fi
if pgrep -x xray >/dev/null 2>&1 && [ "$XRAY_UNIT_PRESENT" != "1" ]; then
    echo "ERROR: an unmanaged Xray process is running; register it as xray.service before installing Arcway" >&2
    exit 1
fi

XRAY_DISCOVERED_PATHS=()
record_xray_directory() {
    local candidate="$1"
    [ -n "$candidate" ] || return 0
    case "$candidate" in
        /*) ;;
        *) echo "ERROR: Xray uses a non-absolute configuration path: $candidate" >&2; return 1 ;;
    esac
    candidate=$(readlink -m -- "$candidate") || return 1
    case "$candidate" in
        /|/etc|/usr|/usr/local|/usr/local/etc|/var|/opt|/root|/home)
            echo "ERROR: Xray configuration path is too broad to snapshot safely: $candidate" >&2
            return 1
            ;;
    esac
    for existing in "${XRAY_DISCOVERED_PATHS[@]}"; do
        [ "$existing" = "$candidate" ] && return 0
    done
    XRAY_DISCOVERED_PATHS+=("$candidate")
}
record_xray_config() {
    local config_path="$1"
    local resolved_config=""
    [ -n "$config_path" ] || return 0
    record_xray_directory "$(dirname -- "$config_path")"
    if [ -L "$config_path" ]; then
        resolved_config=$(readlink -m -- "$config_path") || return 1
        record_xray_directory "$(dirname -- "$resolved_config")"
    fi
}
parse_xray_arguments() {
    local expect="" argument=""
    for argument in "$@"; do
        if [ -n "$expect" ]; then
            if [ "$expect" = "config" ]; then record_xray_config "$argument" || return 1; else record_xray_directory "$argument" || return 1; fi
            expect=""
            continue
        fi
        case "$argument" in
            -config|-c|--config) expect="config" ;;
            -confdir|-d|--confdir) expect="confdir" ;;
            -config=*|-c=*|--config=*) record_xray_config "${argument#*=}" || return 1 ;;
            -confdir=*|-d=*|--confdir=*) record_xray_directory "${argument#*=}" || return 1 ;;
        esac
    done
}
for XRAY_PID in $(pgrep -x xray 2>/dev/null || true); do
    XRAY_ARGUMENTS=()
    if mapfile -d '' -t XRAY_ARGUMENTS < "/proc/$XRAY_PID/cmdline" 2>/dev/null; then
        parse_xray_arguments "${XRAY_ARGUMENTS[@]}" || exit 1
    fi
done
XRAY_UNIT_FILES=(
    /etc/systemd/system/xray.service /etc/systemd/system/xray@.service
    /lib/systemd/system/xray.service /lib/systemd/system/xray@.service
    /usr/lib/systemd/system/xray.service /usr/lib/systemd/system/xray@.service
)
if [ "$XRAY_UNIT_PRESENT" = "1" ]; then
    XRAY_FRAGMENT=$(systemctl show xray -p FragmentPath --value 2>/dev/null || true)
    [ -n "$XRAY_FRAGMENT" ] && XRAY_UNIT_FILES+=("$XRAY_FRAGMENT")
fi
for XRAY_UNIT_FILE in "${XRAY_UNIT_FILES[@]}"; do
    [ -r "$XRAY_UNIT_FILE" ] || continue
    while IFS= read -r XRAY_EXEC_LINE; do
        case "$XRAY_EXEC_LINE" in ExecStart=*) ;; *) continue ;; esac
        read -r -a XRAY_ARGUMENTS <<< "${XRAY_EXEC_LINE#ExecStart=}"
        parse_xray_arguments "${XRAY_ARGUMENTS[@]}" || exit 1
    done < "$XRAY_UNIT_FILE"
done

if [ "$AUTO_STEAL_SELF" = "1" ] && [ "$NGINX_MODE" = "managed" ]; then
    NGINX_BUILD_INFO=$("$NGINX_BIN" -V 2>&1) || {
        echo "ERROR: cannot inspect the active Nginx build configuration" >&2
        exit 1
    }
    NGINX_CONF_PATH=$(printf '%s\n' "$NGINX_BUILD_INFO" | sed -n 's/.*--conf-path=\([^[:space:]]*\).*/\1/p' | tail -n 1)
    NGINX_PREFIX=$(printf '%s\n' "$NGINX_BUILD_INFO" | sed -n 's/.*--prefix=\([^[:space:]]*\).*/\1/p' | tail -n 1)
    NGINX_CONF_PATH=${NGINX_CONF_PATH#\"}
    NGINX_CONF_PATH=${NGINX_CONF_PATH%\"}
    NGINX_CONF_PATH=${NGINX_CONF_PATH#\'}
    NGINX_CONF_PATH=${NGINX_CONF_PATH%\'}
    NGINX_PREFIX=${NGINX_PREFIX#\"}
    NGINX_PREFIX=${NGINX_PREFIX%\"}
    NGINX_PREFIX=${NGINX_PREFIX#\'}
    NGINX_PREFIX=${NGINX_PREFIX%\'}
    if [ -z "$NGINX_CONF_PATH" ]; then
        if [ -z "$NGINX_PREFIX" ]; then
            echo "ERROR: Nginx reports neither --conf-path nor --prefix" >&2
            exit 1
        fi
        NGINX_CONF_PATH="${NGINX_PREFIX%/}/conf/nginx.conf"
    elif [ "${NGINX_CONF_PATH#/}" = "$NGINX_CONF_PATH" ]; then
        if [ -z "$NGINX_PREFIX" ]; then
            echo "ERROR: relative Nginx --conf-path has no --prefix" >&2
            exit 1
        fi
        NGINX_CONF_PATH="${NGINX_PREFIX%/}/${NGINX_CONF_PATH}"
    fi
    if [ ! -r "$NGINX_CONF_PATH" ]; then
        echo "ERROR: resolved Nginx configuration is unreadable: $NGINX_CONF_PATH" >&2
        exit 1
    fi
    record_xray_config "$NGINX_CONF_PATH" || exit 1
    for NGINX_MANAGED_PATH in \
        /etc/nginx \
        /usr/local/nginx/nginx.conf \
        /usr/local/nginx/conf \
        /usr/local/nginx/servers \
        /usr/local/nginx/stream_servers \
        /usr/local/nginx/cert \
        /usr/local/nginx/html; do
        record_xray_directory "$NGINX_MANAGED_PATH" || exit 1
    done
fi

OLD_AGENT_ACTIVE=0
OLD_GUARD_ACTIVE=0
OLD_AGENT_ENABLED=0
OLD_GUARD_ENABLED=0
OLD_AGENT_UNIT_PRESENT=0
OLD_GUARD_UNIT_PRESENT=0
OLD_AGENT_ENABLE_STATE=""
OLD_GUARD_ENABLE_STATE=""
if [ "$HAS_SYSTEMD" = "1" ]; then
    systemctl is-active --quiet mmw-agent && OLD_AGENT_ACTIVE=1 || true
    systemctl is-active --quiet arcway-expiry-guard && OLD_GUARD_ACTIVE=1 || true
    if systemctl cat mmw-agent >/dev/null 2>&1; then
        OLD_AGENT_UNIT_PRESENT=1
        OLD_AGENT_ENABLE_STATE=$(systemctl is-enabled mmw-agent 2>/dev/null || true)
        reversible_systemd_enable_state "$OLD_AGENT_ENABLE_STATE" || {
            echo "ERROR: mmw-agent.service has unsupported enable state '$OLD_AGENT_ENABLE_STATE'" >&2
            exit 1
        }
        case "$OLD_AGENT_ENABLE_STATE" in enabled|enabled-runtime) OLD_AGENT_ENABLED=1 ;; esac
    fi
    if systemctl cat arcway-expiry-guard >/dev/null 2>&1; then
        OLD_GUARD_UNIT_PRESENT=1
        OLD_GUARD_ENABLE_STATE=$(systemctl is-enabled arcway-expiry-guard 2>/dev/null || true)
        reversible_systemd_enable_state "$OLD_GUARD_ENABLE_STATE" || {
            echo "ERROR: arcway-expiry-guard.service has unsupported enable state '$OLD_GUARD_ENABLE_STATE'" >&2
            exit 1
        }
        case "$OLD_GUARD_ENABLE_STATE" in enabled|enabled-runtime) OLD_GUARD_ENABLED=1 ;; esac
    fi
elif [ "$HAS_OPENRC" = "1" ]; then
    rc-service mmw-agent status >/dev/null 2>&1 && OLD_AGENT_ACTIVE=1 || true
    rc-service arcway-expiry-guard status >/dev/null 2>&1 && OLD_GUARD_ACTIVE=1 || true
    rc-update show default 2>/dev/null | awk '$1 == "mmw-agent" { found=1 } END { exit !found }' && OLD_AGENT_ENABLED=1 || true
    rc-update show default 2>/dev/null | awk '$1 == "arcway-expiry-guard" { found=1 } END { exit !found }' && OLD_GUARD_ENABLED=1 || true
else
    pgrep -f '/usr/local/bin/mmw-agent' >/dev/null 2>&1 && OLD_AGENT_ACTIVE=1 || true
    pgrep -f '/usr/local/bin/arcway-expiry-guard' >/dev/null 2>&1 && OLD_GUARD_ACTIVE=1 || true
fi

EXISTING_LISTEN_PORT=$(awk -F: '/^[[:space:]]*listen_port[[:space:]]*:/ { value=$2; gsub(/["[:space:]]/, "", value); print value; exit }' /etc/mmw-agent/config.yaml 2>/dev/null || true)
case "$EXISTING_LISTEN_PORT" in
    ''|*[!0-9]*) EXISTING_LISTEN_PORT="" ;;
    *)
        if [ "$EXISTING_LISTEN_PORT" -lt 1024 ] || [ "$EXISTING_LISTEN_PORT" -gt 65534 ]; then
            EXISTING_LISTEN_PORT=""
        fi
        ;;
esac

BACKUP_DIR="$DOWNLOAD_DIR/backup"
LEGACY_COMPAT_RULES_FILE="$BACKUP_DIR/legacy-compat.rules"
TRACKED_PATHS=(
    /usr/local/bin/mmw-agent
    /usr/local/bin/arcway-expiry-guard
    /usr/local/bin/geoip.dat
    /usr/local/bin/geosite.dat
    /usr/local/bin/geoip.dat.tmp
    /usr/local/bin/geosite.dat.tmp
    /etc/mmw-agent/config.yaml
    /etc/arcway-expiry-guard.env
    /var/lib/mmw-agent
    /var/lib/arcway-expiry-guard
    /var/log/mmw-agent
    /usr/local/etc/xray
    /etc/xray
    /opt/xray
    /etc/arcway-port-firewall.env
    /usr/local/sbin/arcway-agent-firewall
    /usr/local/sbin/arcway-nginx-bridge
    /etc/systemd/system/mmw-agent.service
    /etc/systemd/system/arcway-expiry-guard.service
    /etc/init.d/mmw-agent
    /etc/init.d/arcway-expiry-guard
    /usr/local/bin/mmw-agent-supervisor.sh
    /usr/local/bin/arcway-expiry-guard-supervisor.sh
    /etc/ufw/user.rules
    /etc/ufw/user6.rules
    /etc/rc.local
)
track_path() {
    local candidate="$1" existing=""
    for existing in "${TRACKED_PATHS[@]}"; do
        [ "$existing" = "$candidate" ] && return 0
        case "$candidate" in "$existing"/*) return 0 ;; esac
        case "$existing" in
            "$candidate"/*)
                echo "ERROR: managed path $candidate is a parent of already tracked path $existing" >&2
                return 1
                ;;
        esac
    done
    TRACKED_PATHS+=("$candidate")
}
for XRAY_DISCOVERED_PATH in "${XRAY_DISCOVERED_PATHS[@]}"; do
    track_path "$XRAY_DISCOVERED_PATH"
done
if [ "$NGINX_MODE" = "managed" ]; then
    for NGINX_BRIDGE_PATH in \
        /usr/local/nginx/servers \
        /usr/local/nginx/stream_servers \
        /usr/local/nginx/cert \
        /www/server/panel/vhost/nginx/zz_arcway_loader.conf \
        /www/server/panel/vhost/nginx/tcp/zz_arcway_loader.conf; do
        track_path "$NGINX_BRIDGE_PATH"
    done
fi
track_symlink_target() {
    local link_path="$1" resolved=""
    [ -L "$link_path" ] || return 0
    resolved=$(readlink -m -- "$link_path") || return 1
    case "$resolved" in
        /dev/null) return 0 ;;
        /|/etc|/usr|/usr/local|/usr/local/etc|/var|/var/lib|/var/log|/opt|/root|/home|/srv|/mnt)
            echo "ERROR: managed path $link_path targets an unsafe broad path: $resolved" >&2
            return 1
            ;;
    esac
    if [ -e "$resolved" ] && [ ! -f "$resolved" ] && [ ! -d "$resolved" ]; then
        echo "ERROR: managed path $link_path targets a special file: $resolved" >&2
        return 1
    fi
    track_path "$resolved"
}
# Back up targets as well as links. Otherwise writing a managed config through
# a symlink could mutate data outside the snapshotted directory.
discover_tracked_symlink_targets() {
    local scan_index=0 scan_root="" managed_symlink=""
    while [ "$scan_index" -lt "${#TRACKED_PATHS[@]}" ]; do
        scan_root="${TRACKED_PATHS[$scan_index]}"
        scan_index=$((scan_index + 1))
        if [ -L "$scan_root" ]; then
            track_symlink_target "$scan_root" || return 1
        elif [ -d "$scan_root" ]; then
            while IFS= read -r -d '' managed_symlink; do
                track_symlink_target "$managed_symlink" || return 1
            done < <(find "$scan_root" -xdev -type l -print0 2>/dev/null)
        fi
    done
}
discover_tracked_symlink_targets
OLD_FIREWALL_PRESENT=0
OLD_FIREWALL_USES_NFT=0
OLD_FIREWALL_USES_HOST_CHAIN=0
OLD_UFW_ACTIVE=0
if [ -x /usr/local/sbin/arcway-agent-firewall ]; then
    OLD_FIREWALL_PRESENT=1
    grep -q 'table inet arcway' /usr/local/sbin/arcway-agent-firewall 2>/dev/null && OLD_FIREWALL_USES_NFT=1 || true
    grep -q 'HOST_FILTER_CHAIN=ARCWAY_PANEL_IN' /usr/local/sbin/arcway-agent-firewall 2>/dev/null && OLD_FIREWALL_USES_HOST_CHAIN=1 || true
fi
if command -v ufw >/dev/null 2>&1; then
    if LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active' || grep -q '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null; then
        OLD_UFW_ACTIVE=1
    fi
fi
mkdir -p "$BACKUP_DIR"
: > "$LEGACY_COMPAT_RULES_FILE"
snapshot_tracked_path() {
    local tracked_path="$1"
    local backup_path="$BACKUP_DIR$tracked_path"
    local missing_path="$backup_path.arcway-missing"
    local stage_path="$backup_path.arcway-stage.$$.$RANDOM"
    local previous_path="$backup_path.arcway-previous.$$.$RANDOM"
    local previous_missing="$previous_path.arcway-missing"
    rm -rf "$stage_path" "$stage_path.arcway-missing" "$previous_path" "$previous_missing"
    mkdir -p "$(dirname "$backup_path")"
    if [ -e "$tracked_path" ] || [ -L "$tracked_path" ]; then
        cp -a "$tracked_path" "$stage_path" || { rm -rf "$stage_path"; return 1; }
    else
        : > "$stage_path.arcway-missing" || return 1
    fi
    if [ -e "$backup_path" ] || [ -L "$backup_path" ]; then
        mv "$backup_path" "$previous_path" || return 1
    fi
    if [ -e "$missing_path" ]; then
        mv "$missing_path" "$previous_missing" || {
            [ ! -e "$previous_path" ] || mv "$previous_path" "$backup_path"
            return 1
        }
    fi
    if [ -e "$stage_path" ] || [ -L "$stage_path" ]; then
        if ! mv "$stage_path" "$backup_path"; then
            [ ! -e "$previous_path" ] || mv "$previous_path" "$backup_path"
            [ ! -e "$previous_missing" ] || mv "$previous_missing" "$missing_path"
            return 1
        fi
    elif ! mv "$stage_path.arcway-missing" "$missing_path"; then
        [ ! -e "$previous_path" ] || mv "$previous_path" "$backup_path"
        [ ! -e "$previous_missing" ] || mv "$previous_missing" "$missing_path"
        return 1
    fi
    rm -rf "$previous_path" "$previous_missing"
}

# Refresh shutdown-flushed state as one complete generation. TRACKED_PATHS also
# contains recursively resolved symlink targets, which may live outside /var;
# rebuilding and swapping the whole backup root keeps those targets in the same
# quiesced generation as the three mutable Arcway trees.
snapshot_quiesced_mutable_state() {
    local stage_root="$DOWNLOAD_DIR/quiesced-backup.$$.$RANDOM"
    local previous_root="$DOWNLOAD_DIR/backup.arcway-previous.$$.$RANDOM"
    local tracked_path="" stage_path=""
    rm -rf "$stage_root" "$previous_root"
    mkdir -p "$stage_root" || return 1
    : > "$stage_root/legacy-compat.rules" || { rm -rf "$stage_root"; return 1; }
    for tracked_path in "${TRACKED_PATHS[@]}"; do
        stage_path="$stage_root$tracked_path"
        mkdir -p "$(dirname "$stage_path")" || { rm -rf "$stage_root"; return 1; }
        if [ -e "$tracked_path" ] || [ -L "$tracked_path" ]; then
            cp -a "$tracked_path" "$stage_path" || { rm -rf "$stage_root"; return 1; }
        else
            : > "$stage_path.arcway-missing" || { rm -rf "$stage_root"; return 1; }
        fi
    done
    mv "$BACKUP_DIR" "$previous_root" || { rm -rf "$stage_root"; return 1; }
    if ! mv "$stage_root" "$BACKUP_DIR"; then
        mv "$previous_root" "$BACKUP_DIR" || true
        rm -rf "$stage_root"
        return 1
    fi
    rm -rf "$previous_root"
}
for TRACKED_PATH in "${TRACKED_PATHS[@]}"; do
    snapshot_tracked_path "$TRACKED_PATH"
done

MUTATION_STARTED=0
PREPARE_ATTEMPTED=0
PRESERVE_DOWNLOAD_DIR=0
systemd_service_registered() {
    local service_name="$1"
    systemctl cat "$service_name" >/dev/null 2>&1 && return 0
    find /etc/systemd/system -type l -name "${service_name}.service" -print -quit 2>/dev/null | grep -q .
}
openrc_default_enabled() {
    local service_name="$1"
    [ -e "/etc/runlevels/default/$service_name" ] || [ -L "/etc/runlevels/default/$service_name" ]
}
restart_quiesced_arcway_services() {
    if [ "$HAS_SYSTEMD" = "1" ]; then
        if [ "$OLD_AGENT_ACTIVE" = "1" ]; then
            systemctl start mmw-agent >/dev/null 2>&1 && systemctl is-active --quiet mmw-agent || return 1
        fi
        if [ "$OLD_GUARD_ACTIVE" = "1" ]; then
            systemctl start arcway-expiry-guard >/dev/null 2>&1 && systemctl is-active --quiet arcway-expiry-guard || return 1
        fi
    elif [ "$HAS_OPENRC" = "1" ]; then
        if [ "$OLD_AGENT_ACTIVE" = "1" ]; then
            rc-service mmw-agent start 9>&- >/dev/null 2>&1 && rc-service mmw-agent status >/dev/null 2>&1 || return 1
        fi
        if [ "$OLD_GUARD_ACTIVE" = "1" ]; then
            rc-service arcway-expiry-guard start 9>&- >/dev/null 2>&1 && rc-service arcway-expiry-guard status >/dev/null 2>&1 || return 1
        fi
    else
        if [ "$OLD_AGENT_ACTIVE" = "1" ] && [ -x /usr/local/bin/mmw-agent-supervisor.sh ]; then
            nohup /usr/local/bin/mmw-agent-supervisor.sh 9>&- >/dev/null 2>&1 &
        fi
        if [ "$OLD_GUARD_ACTIVE" = "1" ] && [ -x /usr/local/bin/arcway-expiry-guard-supervisor.sh ]; then
            nohup /usr/local/bin/arcway-expiry-guard-supervisor.sh 9>&- >/dev/null 2>&1 &
        fi
        sleep 1
        if [ "$OLD_AGENT_ACTIVE" = "1" ] && ! pgrep -f '/usr/local/bin/mmw-agent' >/dev/null 2>&1; then return 1; fi
        if [ "$OLD_GUARD_ACTIVE" = "1" ] && ! pgrep -f '/usr/local/bin/arcway-expiry-guard' >/dev/null 2>&1; then return 1; fi
    fi
}
restore_systemd_service_state() {
    local service_name="$1" enable_state="$2" was_active="$3" current_state=""
    systemctl disable "$service_name" >/dev/null 2>&1 || true
    systemctl disable --runtime "$service_name" >/dev/null 2>&1 || true
    systemctl unmask "$service_name" >/dev/null 2>&1 || true
    systemctl unmask --runtime "$service_name" >/dev/null 2>&1 || true
    case "$enable_state" in
        enabled) systemctl enable "$service_name" >/dev/null 2>&1 || return 1 ;;
        enabled-runtime) systemctl enable --runtime "$service_name" >/dev/null 2>&1 || return 1 ;;
        disabled) ;;
        masked) systemctl mask "$service_name" >/dev/null 2>&1 || return 1 ;;
        masked-runtime) systemctl mask --runtime "$service_name" >/dev/null 2>&1 || return 1 ;;
        static|indirect|generated|transient|alias|"") ;;
        *) echo "ERROR: unsupported previous $service_name enable state: $enable_state" >&2; return 1 ;;
    esac
    if [ -n "$enable_state" ]; then
        current_state=$(systemctl is-enabled "$service_name" 2>/dev/null || true)
        [ "$current_state" = "$enable_state" ] || return 1
    fi
    if [ "$was_active" = "1" ]; then
        systemctl start "$service_name" >/dev/null 2>&1 && systemctl is-active --quiet "$service_name" || return 1
    else
        systemctl stop "$service_name" >/dev/null 2>&1 || true
		if systemctl is-active --quiet "$service_name"; then
			return 1
		fi
    fi
	return 0
}
rollback_install() {
    echo "ERROR: installation failed; restoring the previous Arcway node installation" >&2
    set +e
    ROLLBACK_FAILED=0
	if [ "$HAS_SYSTEMD" = "1" ]; then
		systemctl stop arcway-expiry-guard mmw-agent >/dev/null 2>&1
			if systemctl is-active --quiet arcway-expiry-guard || systemctl is-active --quiet mmw-agent; then
				ROLLBACK_FAILED=1
			fi
			if [ "$XRAY_UNIT_PRESENT" = "1" ]; then
				systemctl stop xray >/dev/null 2>&1 || true
				systemctl is-active --quiet xray && ROLLBACK_FAILED=1
			fi
			if [ "$NGINX_MODE" = "managed" ] && [ "$NGINX_UNIT_PRESENT" = "1" ]; then
				systemctl stop nginx >/dev/null 2>&1 || true
				systemctl is-active --quiet nginx && ROLLBACK_FAILED=1
			fi
		# Disable services that were not enabled before this transaction while the
		# newly written units still exist. This removes wants symlinks before a
		# fresh-install rollback deletes the unit files.
			if [ "$OLD_AGENT_ENABLED" != "1" ] && systemd_service_registered mmw-agent; then
				systemctl disable mmw-agent >/dev/null 2>&1 || ROLLBACK_FAILED=1
				systemctl is-enabled --quiet mmw-agent && ROLLBACK_FAILED=1
			fi
			if [ "$OLD_GUARD_ENABLED" != "1" ] && systemd_service_registered arcway-expiry-guard; then
				systemctl disable arcway-expiry-guard >/dev/null 2>&1 || ROLLBACK_FAILED=1
				systemctl is-enabled --quiet arcway-expiry-guard && ROLLBACK_FAILED=1
		fi
	elif [ "$HAS_OPENRC" = "1" ]; then
		rc-service arcway-expiry-guard stop >/dev/null 2>&1
		rc-service mmw-agent stop >/dev/null 2>&1
		if rc-service arcway-expiry-guard status >/dev/null 2>&1 || rc-service mmw-agent status >/dev/null 2>&1; then
			ROLLBACK_FAILED=1
		fi
		# Remove runlevel links created by this transaction before missing init
		# scripts are restored as absent.
				if [ "$OLD_AGENT_ENABLED" != "1" ]; then
					if openrc_default_enabled mmw-agent; then rc-update del mmw-agent default >/dev/null 2>&1 || ROLLBACK_FAILED=1; fi
					openrc_default_enabled mmw-agent && ROLLBACK_FAILED=1
				fi
				if [ "$OLD_GUARD_ENABLED" != "1" ]; then
					if openrc_default_enabled arcway-expiry-guard; then rc-update del arcway-expiry-guard default >/dev/null 2>&1 || ROLLBACK_FAILED=1; fi
					openrc_default_enabled arcway-expiry-guard && ROLLBACK_FAILED=1
				fi
	else
		pkill -f '/usr/local/bin/arcway-expiry-guard' >/dev/null 2>&1
        pkill -f '/usr/local/bin/mmw-agent' >/dev/null 2>&1
        sleep 1
        if pgrep -f '/usr/local/bin/arcway-expiry-guard' >/dev/null 2>&1 || pgrep -f '/usr/local/bin/mmw-agent' >/dev/null 2>&1; then
            ROLLBACK_FAILED=1
		fi
	fi
		rm -f /usr/local/bin/.mmw-agent.new /usr/local/bin/.arcway-expiry-guard.new || ROLLBACK_FAILED=1
    for TRACKED_PATH in "${TRACKED_PATHS[@]}"; do
        if [ -e "$BACKUP_DIR$TRACKED_PATH.arcway-missing" ]; then
            rm -rf "$TRACKED_PATH" || ROLLBACK_FAILED=1
        elif [ -e "$BACKUP_DIR$TRACKED_PATH" ] || [ -L "$BACKUP_DIR$TRACKED_PATH" ]; then
            if ! mkdir -p "$(dirname "$TRACKED_PATH")" || ! rm -rf "$TRACKED_PATH" || ! cp -a "$BACKUP_DIR$TRACKED_PATH" "$TRACKED_PATH"; then
                ROLLBACK_FAILED=1
            fi
        else
            ROLLBACK_FAILED=1
        fi
    done

    if [ -s "$LEGACY_COMPAT_RULES_FILE" ]; then
        while IFS='|' read -r LEGACY_TOOL LEGACY_IP LEGACY_PORT; do
            if command -v "$LEGACY_TOOL" >/dev/null 2>&1; then
                "$LEGACY_TOOL" -w 5 -D ARCWAY_PORTS -s "$LEGACY_IP" -p tcp --dport "$LEGACY_PORT" -j ACCEPT >/dev/null 2>&1 || true
            fi
        done < "$LEGACY_COMPAT_RULES_FILE"
    fi

    # The new helper inserts an exact-source accept chain into the host's own
    # INPUT filter. Remove that chain when rolling back to a helper version
    # that did not own it; otherwise a failed first upgrade would leave live
    # firewall state that the restored installation cannot maintain.
    if [ "$OLD_FIREWALL_USES_HOST_CHAIN" != "1" ]; then
        for HOST_FILTER_SPEC in iptables:ip ip6tables:ip6; do
            HOST_FILTER_TOOL=${HOST_FILTER_SPEC%%:*}
            HOST_FILTER_NFT_FAMILY=${HOST_FILTER_SPEC#*:}
            if ! command -v "$HOST_FILTER_TOOL" >/dev/null 2>&1; then
                if nft list chain "$HOST_FILTER_NFT_FAMILY" filter ARCWAY_PANEL_IN >/dev/null 2>&1; then
                    ROLLBACK_FAILED=1
                fi
                continue
            fi
            if ! "$HOST_FILTER_TOOL" -w 5 -t filter -S INPUT >/dev/null 2>&1; then
                ROLLBACK_FAILED=1
                continue
            fi
            if "$HOST_FILTER_TOOL" -w 5 -t filter -S ARCWAY_PANEL_IN >/dev/null 2>&1; then
                if ! "$HOST_FILTER_TOOL" -w 5 -t filter -S ARCWAY_PANEL_IN | grep -F -- '--comment arcway-managed' >/dev/null 2>&1; then
                    ROLLBACK_FAILED=1
                    continue
                fi
                while "$HOST_FILTER_TOOL" -w 5 -t filter -C INPUT -m comment --comment arcway-managed -j ARCWAY_PANEL_IN >/dev/null 2>&1; do
                    "$HOST_FILTER_TOOL" -w 5 -t filter -D INPUT -m comment --comment arcway-managed -j ARCWAY_PANEL_IN >/dev/null 2>&1 || { ROLLBACK_FAILED=1; break; }
                done
                "$HOST_FILTER_TOOL" -w 5 -t filter -F ARCWAY_PANEL_IN >/dev/null 2>&1 || ROLLBACK_FAILED=1
                "$HOST_FILTER_TOOL" -w 5 -t filter -X ARCWAY_PANEL_IN >/dev/null 2>&1 || ROLLBACK_FAILED=1
            fi
        done
    fi

    FIREWALL_SAFE=1
    if [ "$OLD_UFW_ACTIVE" = "1" ]; then
        if ! command -v ufw >/dev/null 2>&1 || ! ufw reload >/dev/null 2>&1; then
            FIREWALL_SAFE=0
            ROLLBACK_FAILED=1
        fi
    fi
    FIREWALL_RESTORED=0
    if [ "$OLD_FIREWALL_PRESENT" = "1" ] && [ -r /etc/arcway-port-firewall.env ] && [ -x /usr/local/sbin/arcway-agent-firewall ]; then
        set -a
        if ! . /etc/arcway-port-firewall.env; then
            FIREWALL_SAFE=0
            ROLLBACK_FAILED=1
        fi
        set +a
        if [ "$FIREWALL_SAFE" = "1" ] && /usr/local/sbin/arcway-agent-firewall >/dev/null 2>&1; then
            FIREWALL_RESTORED=1
        else
            FIREWALL_SAFE=0
            ROLLBACK_FAILED=1
        fi
    elif [ "$OLD_FIREWALL_PRESENT" = "1" ]; then
        FIREWALL_SAFE=0
        ROLLBACK_FAILED=1
    fi
    # A pre-nft helper cannot own the new table. If the old nft helper cannot be
    # restored either, remove the new table instead of leaving stale policy behind.
    if [ "$OLD_FIREWALL_USES_NFT" != "1" ] || [ "$FIREWALL_RESTORED" != "1" ]; then
        if nft list table inet arcway >/dev/null 2>&1 && ! nft delete table inet arcway >/dev/null 2>&1; then
            FIREWALL_SAFE=0
            ROLLBACK_FAILED=1
        fi
    fi

	if [ "$HAS_SYSTEMD" = "1" ]; then
		systemctl daemon-reload >/dev/null 2>&1 || ROLLBACK_FAILED=1
		if [ "$XRAY_UNIT_PRESENT" = "1" ]; then
			restore_systemd_service_state xray "$OLD_XRAY_ENABLE_STATE" "$OLD_XRAY_ACTIVE" || ROLLBACK_FAILED=1
		fi
		if [ "$NGINX_MODE" = "managed" ] && [ "$NGINX_UNIT_PRESENT" = "1" ]; then
			restore_systemd_service_state nginx "$OLD_NGINX_ENABLE_STATE" "$OLD_NGINX_ACTIVE" || ROLLBACK_FAILED=1
		fi
        if [ "$OLD_AGENT_UNIT_PRESENT" = "1" ]; then
            restore_systemd_service_state mmw-agent "$OLD_AGENT_ENABLE_STATE" 0 || ROLLBACK_FAILED=1
        fi
        if [ "$OLD_GUARD_UNIT_PRESENT" = "1" ]; then
            restore_systemd_service_state arcway-expiry-guard "$OLD_GUARD_ENABLE_STATE" 0 || ROLLBACK_FAILED=1
        fi
        if [ "$FIREWALL_SAFE" = "1" ]; then
            if [ "$OLD_AGENT_ACTIVE" = "1" ]; then
                systemctl start mmw-agent >/dev/null 2>&1 && systemctl is-active --quiet mmw-agent || ROLLBACK_FAILED=1
            fi
            if [ "$OLD_GUARD_ACTIVE" = "1" ]; then
                systemctl start arcway-expiry-guard >/dev/null 2>&1 && systemctl is-active --quiet arcway-expiry-guard || ROLLBACK_FAILED=1
            fi
        else
            ROLLBACK_FAILED=1
        fi
	elif [ "$HAS_OPENRC" = "1" ]; then
		if [ -e /etc/init.d/mmw-agent ]; then
			if [ "$OLD_AGENT_ENABLED" = "1" ]; then
				rc-update add mmw-agent default >/dev/null 2>&1 || ROLLBACK_FAILED=1
				openrc_default_enabled mmw-agent || ROLLBACK_FAILED=1
			elif openrc_default_enabled mmw-agent; then
				rc-update del mmw-agent default >/dev/null 2>&1 || ROLLBACK_FAILED=1
				openrc_default_enabled mmw-agent && ROLLBACK_FAILED=1
			fi
		fi
		if [ -e /etc/init.d/arcway-expiry-guard ]; then
			if [ "$OLD_GUARD_ENABLED" = "1" ]; then
				rc-update add arcway-expiry-guard default >/dev/null 2>&1 || ROLLBACK_FAILED=1
				openrc_default_enabled arcway-expiry-guard || ROLLBACK_FAILED=1
			elif openrc_default_enabled arcway-expiry-guard; then
				rc-update del arcway-expiry-guard default >/dev/null 2>&1 || ROLLBACK_FAILED=1
				openrc_default_enabled arcway-expiry-guard && ROLLBACK_FAILED=1
			fi
		fi
        if [ "$FIREWALL_SAFE" = "1" ]; then
            if [ "$OLD_AGENT_ACTIVE" = "1" ]; then rc-service mmw-agent start 9>&- >/dev/null 2>&1 && rc-service mmw-agent status >/dev/null 2>&1 || ROLLBACK_FAILED=1; fi
            if [ "$OLD_GUARD_ACTIVE" = "1" ]; then rc-service arcway-expiry-guard start 9>&- >/dev/null 2>&1 && rc-service arcway-expiry-guard status >/dev/null 2>&1 || ROLLBACK_FAILED=1; fi
        else
            ROLLBACK_FAILED=1
        fi
    else
        if [ "$FIREWALL_SAFE" = "1" ]; then
            if [ "$OLD_AGENT_ACTIVE" = "1" ] && [ -x /usr/local/bin/mmw-agent-supervisor.sh ]; then
                nohup /usr/local/bin/mmw-agent-supervisor.sh 9>&- >/dev/null 2>&1 &
            fi
            if [ "$OLD_GUARD_ACTIVE" = "1" ] && [ -x /usr/local/bin/arcway-expiry-guard-supervisor.sh ]; then
                nohup /usr/local/bin/arcway-expiry-guard-supervisor.sh 9>&- >/dev/null 2>&1 &
            fi
            sleep 1
            if [ "$OLD_AGENT_ACTIVE" = "1" ] && ! pgrep -f '/usr/local/bin/mmw-agent' >/dev/null 2>&1; then ROLLBACK_FAILED=1; fi
            if [ "$OLD_GUARD_ACTIVE" = "1" ] && ! pgrep -f '/usr/local/bin/arcway-expiry-guard' >/dev/null 2>&1; then ROLLBACK_FAILED=1; fi
        else
            ROLLBACK_FAILED=1
        fi
    fi
    MUTATION_STARTED=0
    if [ "$ROLLBACK_FAILED" != "0" ]; then
        echo "ERROR: automatic rollback was incomplete" >&2
        return 1
    fi
    echo "Previous Arcway node installation restored." >&2
    return 0
}

finish_install() {
    INSTALL_STATUS=$?
    trap - EXIT
    trap '' HUP INT TERM
    ROLLBACK_COMPLETE=1
    if [ "$INSTALL_STATUS" -ne 0 ] && [ "$MUTATION_STARTED" = "1" ]; then
        if [ "$PREPARE_ATTEMPTED" = "1" ] && ! quiesce_remote_installation; then
            ROLLBACK_COMPLETE=0
            PRESERVE_DOWNLOAD_DIR=1
            echo "ERROR: panel-side Prepare could not be quiesced; local rollback was not started" >&2
            echo "ERROR: retry recovery before changing files in $DOWNLOAD_DIR" >&2
        elif ! rollback_install; then
            ROLLBACK_COMPLETE=0
            PRESERVE_DOWNLOAD_DIR=1
            echo "ERROR: rollback backup retained at $BACKUP_DIR" >&2
        fi
    fi
    if [ "$INSTALL_STATUS" -ne 0 ] && [ "$ROLLBACK_COMPLETE" = "1" ]; then
        abort_remote_installation
	elif [ "$INSTALL_STATUS" -ne 0 ] && [ "$SERVER_LOCK_STARTED" = "1" ]; then
		echo "ERROR: panel installation lock retained until expiry because rollback was incomplete" >&2
	fi
	stop_install_renewal
	if [ "$PRESERVE_DOWNLOAD_DIR" != "1" ]; then
        rm -rf "$DOWNLOAD_DIR"
    else
        echo "ERROR: do not delete $DOWNLOAD_DIR until recovery is complete" >&2
    fi
    exit "$INSTALL_STATUS"
}
trap finish_install EXIT
trap 'exit 130' HUP INT TERM

assert_install_lease
MUTATION_STARTED=1
# Step 2: Stop existing service if running
echo "[2/7] Stopping existing service (if any)..."
if [ "$HAS_SYSTEMD" = "1" ]; then
    systemctl stop arcway-expiry-guard 2>/dev/null || true
    systemctl stop mmw-agent 2>/dev/null || true
    if systemctl is-active --quiet arcway-expiry-guard || systemctl is-active --quiet mmw-agent; then
        echo "ERROR: existing Arcway services did not stop" >&2
        exit 1
    fi
elif [ "$HAS_OPENRC" = "1" ]; then
    rc-service arcway-expiry-guard stop 2>/dev/null || true
    rc-service mmw-agent stop 2>/dev/null || true
    if rc-service arcway-expiry-guard status >/dev/null 2>&1 || rc-service mmw-agent status >/dev/null 2>&1; then
        echo "ERROR: existing Arcway services did not stop" >&2
        exit 1
    fi
else
    # nohup 兜底:杀掉现有 agent / guard 进程及 supervisor
    pkill -f /usr/local/bin/arcway-expiry-guard 2>/dev/null || true
    pkill -f /usr/local/bin/mmw-agent 2>/dev/null || true
    sleep 1
    if pgrep -f '/usr/local/bin/arcway-expiry-guard' >/dev/null 2>&1 || pgrep -f '/usr/local/bin/mmw-agent' >/dev/null 2>&1; then
        echo "ERROR: existing Arcway processes did not stop" >&2
        exit 1
    fi
fi

# Shutdown hooks may create or retarget state symlinks. Re-discover them while
# services are quiescent, before constructing the authoritative generation.
if ! discover_tracked_symlink_targets; then
    echo "ERROR: managed symlink topology became unsafe while stopping services" >&2
    if restart_quiesced_arcway_services; then
        MUTATION_STARTED=0
    else
        echo "ERROR: old Arcway services could not be restarted; full rollback will be attempted" >&2
    fi
    exit 1
fi

# The first snapshot protects failures while stopping old services. Refresh
# all tracked state after they are quiescent so rollback cannot lose late writes.
if ! snapshot_quiesced_mutable_state; then
    echo "ERROR: failed to capture a complete quiesced mutable-state snapshot" >&2
    if restart_quiesced_arcway_services; then
        # No files were changed yet. Preserve shutdown-flushed state and let the
        # EXIT handler abort only the panel transaction.
        MUTATION_STARTED=0
    else
        echo "ERROR: old Arcway services could not be restarted; full rollback will be attempted" >&2
    fi
    exit 1
fi

# Step 3: Create config directory first
echo ""
echo "[3/7] Creating configuration..."
mkdir -p /etc/mmw-agent
mkdir -p /var/lib/mmw-agent
mkdir -p /var/lib/arcway-expiry-guard
chmod 0700 /var/lib/arcway-expiry-guard

# 端口探测:Agent 与 expiry guard 必须占用连续两个端口。每次同时检查 P 和 P+1,
# 避免只挑到一个空闲端口后 guard 启动失败,导致过期客户端无法按时撤销。
port_is_listening() {
    CHECK_PORT="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${CHECK_PORT}\$"
        return $?
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | awk 'NR > 2 {print $4}' | grep -qE "[:.]${CHECK_PORT}\$"
        return $?
    fi
    CHECK_PORT_HEX=$(printf '%04X' "$CHECK_PORT")
    awk -v suffix=":${CHECK_PORT_HEX}" '$2 ~ suffix "$" && $4 == "0A" { found=1 } END { exit !found }' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

REQUESTED_PORT="${LISTEN_PORT:-${EXISTING_LISTEN_PORT:-23889}}"
PORT_SEARCH_LIMIT=19
if [ -n "$LISTEN_PORT" ] || [ -n "$EXISTING_LISTEN_PORT" ]; then
    PORT_SEARCH_LIMIT=0
fi
ACTUAL_PORT=""
GUARD_PORT=""
for i in $(seq 0 "$PORT_SEARCH_LIMIT"); do
    TRY_PORT=$((REQUESTED_PORT + i))
    TRY_GUARD_PORT=$((TRY_PORT + 1))
    if [ "$TRY_GUARD_PORT" -gt 65535 ]; then
        break
    fi
    if port_is_listening "$TRY_PORT" || port_is_listening "$TRY_GUARD_PORT"; then
        echo "  端口对 ${TRY_PORT}/${TRY_GUARD_PORT} 不可用,尝试下一个..."
        continue
    fi
    ACTUAL_PORT="$TRY_PORT"
    GUARD_PORT="$TRY_GUARD_PORT"
    break
done
if [ -z "$ACTUAL_PORT" ]; then
    echo "ERROR: 从 ${REQUESTED_PORT} 起找不到连续两个可用端口,安装中止" >&2
    exit 1
fi
if [ "$ACTUAL_PORT" != "$REQUESTED_PORT" ]; then
    echo "⚠ 请求端口对不可用,Agent 自动改用 ${ACTUAL_PORT},guard 使用 ${GUARD_PORT}"
fi
LISTEN_PORT="$ACTUAL_PORT"

cat > /etc/mmw-agent/config.yaml << EOF
# MMWX Remote Server Configuration
# Generated by install script

mode: remote
master_url: ${MASTER_URL}
token: ${TOKEN}
connection_mode: ${CONNECTION_MODE}
xray_mode: ${XRAY_MODE}
steal_mode: ${STEAL_MODE}
nginx_mode: ${NGINX_MODE}
master_public_key: ${MASTER_PUBLIC_KEY}
listen_port: "${LISTEN_PORT}"
hide_port_on_ws: false
EOF

echo "Configuration saved to /etc/mmw-agent/config.yaml"

cat > /etc/arcway-expiry-guard.env << EOF
ARCWAY_GUARD_LISTEN=:${GUARD_PORT}
ARCWAY_AGENT_URL=http://127.0.0.1:${LISTEN_PORT}
ARCWAY_GUARD_STATE=/var/lib/arcway-expiry-guard/state.json
ARCWAY_GUARD_SECRET=${GUARD_SECRET}
ARCWAY_AGENT_TOKEN=${TOKEN}
EOF
chmod 0600 /etc/arcway-expiry-guard.env
if [ ! -e /var/lib/arcway-expiry-guard/state.json ]; then
    printf '%s\n' '{"version":1,"entries":[]}' > /var/lib/arcway-expiry-guard/state.json
fi
chmod 0600 /var/lib/arcway-expiry-guard/state.json

# 保留上一版信息，用于删除 UFW 中旧出口地址的持久化规则。
OLD_ARCWAY_AGENT_PORT=""
OLD_ARCWAY_GUARD_PORT=""
OLD_ARCWAY_PANEL_IPS=""
if [ -r /etc/arcway-port-firewall.env ]; then
    OLD_ARCWAY_AGENT_PORT=$(sed -n 's/^ARCWAY_AGENT_PORT=//p' /etc/arcway-port-firewall.env | head -n 1)
    OLD_ARCWAY_GUARD_PORT=$(sed -n 's/^ARCWAY_GUARD_PORT=//p' /etc/arcway-port-firewall.env | head -n 1)
    OLD_ARCWAY_PANEL_IPS=$(sed -n "s/^ARCWAY_PANEL_IPS='\(.*\)'$/\1/p" /etc/arcway-port-firewall.env | head -n 1)
fi
if [ -z "$OLD_ARCWAY_AGENT_PORT" ] && [ -n "$EXISTING_LISTEN_PORT" ]; then
    OLD_ARCWAY_AGENT_PORT="$EXISTING_LISTEN_PORT"
fi
if [ -z "$OLD_ARCWAY_GUARD_PORT" ] && [ -n "$OLD_ARCWAY_AGENT_PORT" ]; then
    OLD_ARCWAY_GUARD_PORT=$((OLD_ARCWAY_AGENT_PORT + 1))
fi

# 用独立 inet table 同时保护 IPv4/IPv6。helper 由各 init 系统在每次启动前调用，
# nft -f 会将整份规则作为单个事务提交，校验或应用失败时旧 table 保持不变。
mkdir -p /usr/local/sbin
cat > /etc/arcway-port-firewall.env << EOF
ARCWAY_AGENT_PORT=${LISTEN_PORT}
ARCWAY_GUARD_PORT=${GUARD_PORT}
ARCWAY_PANEL_IPS='$PANEL_SOURCE_IPS'
EOF
chmod 0600 /etc/arcway-port-firewall.env
cat > /usr/local/sbin/arcway-agent-firewall << 'EOF'
#!/bin/sh
set -eu
if { [ -z "${ARCWAY_AGENT_PORT:-}" ] || [ -z "${ARCWAY_GUARD_PORT:-}" ] || [ -z "${ARCWAY_PANEL_IPS:-}" ]; } && [ -r /etc/arcway-port-firewall.env ]; then
    set -a
    . /etc/arcway-port-firewall.env
    set +a
fi
FIREWALL_MODE=${1:-full}
case "$FIREWALL_MODE" in
    full|--nft-only) ;;
    *) echo "ERROR: unsupported Arcway firewall mode: $FIREWALL_MODE" >&2; exit 2 ;;
esac
: "${ARCWAY_AGENT_PORT:?missing ARCWAY_AGENT_PORT}"
: "${ARCWAY_GUARD_PORT:?missing ARCWAY_GUARD_PORT}"
: "${ARCWAY_PANEL_IPS:?missing ARCWAY_PANEL_IPS}"

CONFIGURED_AGENT_PORT=$(awk -F: '/^[[:space:]]*listen_port[[:space:]]*:/ { value=$2; gsub(/["[:space:]]/, "", value); print value; exit }' /etc/mmw-agent/config.yaml 2>/dev/null || true)
case "$CONFIGURED_AGENT_PORT" in
    ''|*[!0-9]*)
        echo "ERROR: mmw-agent config has no valid listen_port" >&2
        exit 1
        ;;
esac
if [ "$CONFIGURED_AGENT_PORT" != "$ARCWAY_AGENT_PORT" ]; then
    echo "ERROR: mmw-agent listen_port drifted from the protected Arcway port" >&2
    exit 1
fi

if [ ! -r /etc/arcway-expiry-guard.env ]; then
    echo "ERROR: expiry guard configuration is missing" >&2
    exit 1
fi
CONFIGURED_GUARD_LISTEN=$(sed -n 's/^ARCWAY_GUARD_LISTEN=//p' /etc/arcway-expiry-guard.env | head -n 1)
CONFIGURED_GUARD_AGENT_URL=$(sed -n 's/^ARCWAY_AGENT_URL=//p' /etc/arcway-expiry-guard.env | head -n 1)
if [ "$CONFIGURED_GUARD_LISTEN" != ":${ARCWAY_GUARD_PORT}" ]; then
    echo "ERROR: expiry guard listen port drifted from the protected Arcway port" >&2
    exit 1
fi
if [ "$CONFIGURED_GUARD_AGENT_URL" != "http://127.0.0.1:${ARCWAY_AGENT_PORT}" ]; then
    echo "ERROR: expiry guard Agent URL drifted from the protected Arcway port" >&2
    exit 1
fi

umask 077
FIREWALL_RUNTIME_DIR=/var/lib/arcway-expiry-guard
if [ ! -d "$FIREWALL_RUNTIME_DIR" ]; then
    echo "ERROR: Arcway firewall runtime directory is unavailable" >&2
    exit 1
fi
chmod 0700 "$FIREWALL_RUNTIME_DIR"
FIREWALL_LOCK_FILE="$FIREWALL_RUNTIME_DIR/firewall.flock"
exec 8>"$FIREWALL_LOCK_FILE"
chmod 0600 "$FIREWALL_LOCK_FILE"
if ! flock -w 30 8; then
    echo "ERROR: timed out waiting for the Arcway firewall lock" >&2
    exit 1
fi
RULESET=$(mktemp "$FIREWALL_RUNTIME_DIR/arcway-agent-firewall.nft.XXXXXX")
PUBLIC_RULES_RAW=$(mktemp "$FIREWALL_RUNTIME_DIR/arcway-agent-firewall.rules.raw.XXXXXX")
PUBLIC_RULES=$(mktemp "$FIREWALL_RUNTIME_DIR/arcway-agent-firewall.rules.XXXXXX")
cleanup() {
    rm -f "$RULESET" "$PUBLIC_RULES_RAW" "$PUBLIC_RULES"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

XRAY_CONFIG_PATH=${ARCWAY_XRAY_CONFIG_PATH:-}
if [ -z "$XRAY_CONFIG_PATH" ]; then
    for candidate in /usr/local/etc/xray/config.json /etc/xray/config.json /opt/xray/config.json; do
        if [ -r "$candidate" ]; then
            XRAY_CONFIG_PATH="$candidate"
            break
        fi
    done
fi
if [ -n "$XRAY_CONFIG_PATH" ]; then
    ARCWAY_AGENT_BINARY=${ARCWAY_AGENT_BINARY:-/usr/local/bin/mmw-agent}
    if [ ! -x "$ARCWAY_AGENT_BINARY" ]; then
        echo "ERROR: Arcway Agent binary cannot derive Xray firewall rules" >&2
        exit 1
    fi
    if ! "$ARCWAY_AGENT_BINARY" -arcway-firewall-rules="$XRAY_CONFIG_PATH" > "$PUBLIC_RULES_RAW"; then
        echo "ERROR: failed to derive public ports from Xray config" >&2
        exit 1
    fi
fi
while read -r public_protocol public_port extra; do
    [ -n "$public_protocol" ] || continue
    if [ -n "${extra:-}" ]; then
        echo "ERROR: malformed Arcway public firewall rule" >&2
        exit 1
    fi
    case "$public_protocol" in tcp|udp) ;; *) echo "ERROR: invalid Arcway public firewall protocol" >&2; exit 1 ;; esac
    case "$public_port" in ''|*[!0-9]*) echo "ERROR: invalid Arcway public firewall port" >&2; exit 1 ;; esac
    if [ "$public_port" -lt 1 ] || [ "$public_port" -gt 65535 ]; then
        echo "ERROR: invalid Arcway public firewall port" >&2
        exit 1
    fi
    if [ "$public_port" = "$ARCWAY_AGENT_PORT" ] || [ "$public_port" = "$ARCWAY_GUARD_PORT" ]; then
        echo "ERROR: Xray inbound conflicts with protected Arcway management port $public_port" >&2
        exit 1
    fi
    printf '%s %s\n' "$public_protocol" "$public_port" >> "$PUBLIC_RULES"
done < "$PUBLIC_RULES_RAW"
sort -u -o "$PUBLIC_RULES" "$PUBLIC_RULES"

{
    if nft list table inet arcway >/dev/null 2>&1; then
        echo 'delete table inet arcway'
    fi
    echo 'table inet arcway {'
    echo '  chain input {'
    echo '    type filter hook input priority -10; policy accept;'
    echo '    iifname "lo" return'
    for panel_ip in $ARCWAY_PANEL_IPS; do
        case "$panel_ip" in
            *:*) printf '    ip6 saddr %s tcp dport { %s, %s } accept\n' "$panel_ip" "$ARCWAY_AGENT_PORT" "$ARCWAY_GUARD_PORT" ;;
            *)   printf '    ip saddr %s tcp dport { %s, %s } accept\n' "$panel_ip" "$ARCWAY_AGENT_PORT" "$ARCWAY_GUARD_PORT" ;;
        esac
    done
    while read -r public_protocol public_port; do
        [ -n "$public_protocol" ] || continue
        printf '    %s dport %s accept\n' "$public_protocol" "$public_port"
    done < "$PUBLIC_RULES"
    printf '    tcp dport { %s, %s } drop\n' "$ARCWAY_AGENT_PORT" "$ARCWAY_GUARD_PORT"
    echo '  }'
    echo '}'
} > "$RULESET"

nft -c -f "$RULESET"
nft -f "$RULESET"
nft list chain inet arcway input >/dev/null

# The Guard service runs with ProtectSystem=strict. Its pre-start may safely
# refresh the nft table, but the full host-chain update needs the global
# /run/xtables.lock and is therefore performed by the required Agent service.
if [ "$FIREWALL_MODE" = "--nft-only" ]; then
    exit 0
fi

# An accept verdict in an early nft base chain is not final: a later host INPUT
# chain (UFW, firewalld, or a panel firewall) can still drop the packet. Keep
# the independent nft table as the authoritative deny boundary, and also put
# the same exact-source accepts at the front of the host's IPv4/IPv6 INPUT
# filter so trusted panel traffic survives a later default-drop policy.
HOST_FILTER_CHAIN=ARCWAY_PANEL_IN
HOST_FILTER_COMMENT=arcway-managed
host_filter_tool_ready() {
    command -v "$1" >/dev/null 2>&1 && command -v "${1}-restore" >/dev/null 2>&1 && "$1" -w 5 -t filter -S INPUT >/dev/null 2>&1
}
ensure_host_filter_chain() {
    HOST_FILTER_TOOL="$1"
    HOST_FILTER_FAMILY="$2"
    HOST_FILTER_RESTORE="${HOST_FILTER_TOOL}-restore"
    if ! host_filter_tool_ready "$HOST_FILTER_TOOL"; then
        echo "ERROR: $HOST_FILTER_TOOL cannot manage the host INPUT filter" >&2
        return 1
    fi
    if "$HOST_FILTER_TOOL" -w 5 -t filter -S "$HOST_FILTER_CHAIN" >/dev/null 2>&1; then
        if ! "$HOST_FILTER_TOOL" -w 5 -t filter -S "$HOST_FILTER_CHAIN" | grep -F -- "--comment $HOST_FILTER_COMMENT" >/dev/null 2>&1; then
            echo "ERROR: host firewall chain $HOST_FILTER_CHAIN exists but is not owned by Arcway" >&2
            return 1
        fi
    else
        if ! "$HOST_FILTER_TOOL" -w 5 -t filter -N "$HOST_FILTER_CHAIN"; then
            return 1
        fi
        if ! "$HOST_FILTER_TOOL" -w 5 -t filter -A "$HOST_FILTER_CHAIN" -m comment --comment "$HOST_FILTER_COMMENT" -j RETURN; then
            "$HOST_FILTER_TOOL" -w 5 -t filter -X "$HOST_FILTER_CHAIN" >/dev/null 2>&1 || true
            return 1
        fi
    fi
    HOST_RULESET=$(mktemp "$FIREWALL_RUNTIME_DIR/arcway-agent-host-filter.XXXXXX") || return 1
    {
        echo '*filter'
        printf -- '-F %s\n' "$HOST_FILTER_CHAIN"
        for HOST_PANEL_IP in $ARCWAY_PANEL_IPS; do
            case "$HOST_PANEL_IP" in
                *:*) [ "$HOST_FILTER_FAMILY" = "ipv6" ] || continue ;;
                *) [ "$HOST_FILTER_FAMILY" = "ipv4" ] || continue ;;
            esac
            for HOST_MANAGEMENT_PORT in "$ARCWAY_AGENT_PORT" "$ARCWAY_GUARD_PORT"; do
                printf -- '-A %s -s %s -p tcp --dport %s -m comment --comment %s -j ACCEPT\n' \
                    "$HOST_FILTER_CHAIN" "$HOST_PANEL_IP" "$HOST_MANAGEMENT_PORT" "$HOST_FILTER_COMMENT"
            done
        done
        while read -r HOST_PUBLIC_PROTOCOL HOST_PUBLIC_PORT; do
            [ -n "$HOST_PUBLIC_PROTOCOL" ] || continue
            printf -- '-A %s -p %s --dport %s -m comment --comment %s -j ACCEPT\n' \
                "$HOST_FILTER_CHAIN" "$HOST_PUBLIC_PROTOCOL" "$HOST_PUBLIC_PORT" "$HOST_FILTER_COMMENT"
        done < "$PUBLIC_RULES"
        printf -- '-A %s -m comment --comment %s -j RETURN\n' "$HOST_FILTER_CHAIN" "$HOST_FILTER_COMMENT"
        echo 'COMMIT'
    } > "$HOST_RULESET"
    if ! "$HOST_FILTER_RESTORE" -w 5 --test --noflush < "$HOST_RULESET" || \
        ! "$HOST_FILTER_RESTORE" -w 5 --noflush < "$HOST_RULESET"; then
        rm -f "$HOST_RULESET"
        return 1
    fi
    rm -f "$HOST_RULESET"

    HOST_JUMP_COUNT=$("$HOST_FILTER_TOOL" -w 5 -t filter -S INPUT | awk -v chain="$HOST_FILTER_CHAIN" -v comment="$HOST_FILTER_COMMENT" '
        $0 ~ ("--comment " comment) && $0 ~ ("-j " chain "([[:space:]]|$)") { count++ }
        END { print count+0 }
    ')
    while [ "$HOST_JUMP_COUNT" -gt 1 ]; do
        "$HOST_FILTER_TOOL" -w 5 -t filter -D INPUT -m comment --comment "$HOST_FILTER_COMMENT" -j "$HOST_FILTER_CHAIN" || return 1
        HOST_JUMP_COUNT=$((HOST_JUMP_COUNT - 1))
    done
    if [ "$HOST_JUMP_COUNT" -eq 0 ]; then
        "$HOST_FILTER_TOOL" -w 5 -t filter -I INPUT 1 -m comment --comment "$HOST_FILTER_COMMENT" -j "$HOST_FILTER_CHAIN" || return 1
    fi
    "$HOST_FILTER_TOOL" -w 5 -t filter -C INPUT -m comment --comment "$HOST_FILTER_COMMENT" -j "$HOST_FILTER_CHAIN" || return 1
}

remove_host_filter_chain() {
    HOST_FILTER_TOOL="$1"
    HOST_FILTER_NFT_FAMILY="$2"
    if command -v "$HOST_FILTER_TOOL" >/dev/null 2>&1; then
        if ! host_filter_tool_ready "$HOST_FILTER_TOOL"; then
            echo "ERROR: $HOST_FILTER_TOOL is installed but cannot inspect the host INPUT filter" >&2
            return 1
        fi
    else
        if nft list chain "$HOST_FILTER_NFT_FAMILY" filter "$HOST_FILTER_CHAIN" >/dev/null 2>&1; then
            echo "ERROR: $HOST_FILTER_TOOL cannot remove the obsolete Arcway host INPUT chain" >&2
            return 1
        fi
        return 0
    fi
    if ! "$HOST_FILTER_TOOL" -w 5 -t filter -S "$HOST_FILTER_CHAIN" >/dev/null 2>&1; then
        return 0
    fi
    if ! "$HOST_FILTER_TOOL" -w 5 -t filter -S "$HOST_FILTER_CHAIN" | grep -F -- "--comment $HOST_FILTER_COMMENT" >/dev/null 2>&1; then
        echo "ERROR: host firewall chain $HOST_FILTER_CHAIN exists but is not owned by Arcway" >&2
        return 1
    fi
    while "$HOST_FILTER_TOOL" -w 5 -t filter -C INPUT -m comment --comment "$HOST_FILTER_COMMENT" -j "$HOST_FILTER_CHAIN" >/dev/null 2>&1; do
        "$HOST_FILTER_TOOL" -w 5 -t filter -D INPUT -m comment --comment "$HOST_FILTER_COMMENT" -j "$HOST_FILTER_CHAIN" || return 1
    done
    "$HOST_FILTER_TOOL" -w 5 -t filter -F "$HOST_FILTER_CHAIN" || return 1
    "$HOST_FILTER_TOOL" -w 5 -t filter -X "$HOST_FILTER_CHAIN" || return 1
}

HOST_FILTER_NEEDS_V4=0
HOST_FILTER_NEEDS_V6=0
for HOST_PANEL_IP in $ARCWAY_PANEL_IPS; do
    case "$HOST_PANEL_IP" in
        *:*) HOST_FILTER_NEEDS_V6=1 ;;
        *) HOST_FILTER_NEEDS_V4=1 ;;
    esac
done
if [ -s "$PUBLIC_RULES" ]; then
    HOST_FILTER_NEEDS_V4=1
    HOST_FILTER_NEEDS_V6=1
fi
if [ "$HOST_FILTER_NEEDS_V4" = "1" ]; then
    if command -v iptables >/dev/null 2>&1; then
        if ! host_filter_tool_ready iptables; then
            echo "ERROR: iptables is installed but cannot inspect the host INPUT filter" >&2
            exit 1
        fi
        ensure_host_filter_chain iptables ipv4 || exit 1
    elif nft list chain ip filter "$HOST_FILTER_CHAIN" >/dev/null 2>&1; then
        echo "ERROR: iptables cannot manage the existing Arcway IPv4 host INPUT chain" >&2
        exit 1
    else
        echo "WARNING: iptables is unavailable; relying on nft policy and panel readiness for IPv4" >&2
    fi
else
    remove_host_filter_chain iptables ip || exit 1
fi
if [ "$HOST_FILTER_NEEDS_V6" = "1" ]; then
    if command -v ip6tables >/dev/null 2>&1; then
        if ! host_filter_tool_ready ip6tables; then
            echo "ERROR: ip6tables is installed but cannot inspect the host INPUT filter" >&2
            exit 1
        fi
        ensure_host_filter_chain ip6tables ipv6 || exit 1
    elif nft list chain ip6 filter "$HOST_FILTER_CHAIN" >/dev/null 2>&1; then
        echo "ERROR: ip6tables cannot manage the existing Arcway IPv6 host INPUT chain" >&2
        exit 1
    else
        echo "WARNING: ip6tables is unavailable; relying on nft policy and panel readiness for IPv6" >&2
    fi
else
    remove_host_filter_chain ip6tables ip6 || exit 1
fi
EOF
chmod 0755 /usr/local/sbin/arcway-agent-firewall
set -a
. /etc/arcway-port-firewall.env
set +a
if ! ARCWAY_AGENT_BINARY="$AGENT_DOWNLOAD" /usr/local/sbin/arcway-agent-firewall; then
    echo "ERROR: failed to protect the Arcway management ports" >&2
    exit 1
fi

# Pre-nft Arcway installations may still jump through ARCWAY_PORTS at a later
# netfilter priority. Temporarily admit only the new panel/port pairs so the
# panel can verify the migration. Rollback removes just these recorded rules;
# successful readiness removes the obsolete chain in full.
for PANEL_IP in $PANEL_SOURCE_IPS; do
    case "$PANEL_IP" in
        *:*) LEGACY_TOOL=ip6tables ;;
        *) LEGACY_TOOL=iptables ;;
    esac
    if ! command -v "$LEGACY_TOOL" >/dev/null 2>&1 || ! "$LEGACY_TOOL" -w 5 -n -L ARCWAY_PORTS >/dev/null 2>&1; then
        continue
    fi
    for MANAGEMENT_PORT in "$LISTEN_PORT" "$GUARD_PORT"; do
        if "$LEGACY_TOOL" -w 5 -C ARCWAY_PORTS -s "$PANEL_IP" -p tcp --dport "$MANAGEMENT_PORT" -j ACCEPT >/dev/null 2>&1; then
            continue
        fi
        printf '%s|%s|%s\n' "$LEGACY_TOOL" "$PANEL_IP" "$MANAGEMENT_PORT" >> "$LEGACY_COMPAT_RULES_FILE"
        if ! "$LEGACY_TOOL" -w 5 -I ARCWAY_PORTS 1 -s "$PANEL_IP" -p tcp --dport "$MANAGEMENT_PORT" -j ACCEPT; then
            echo "ERROR: failed to add a temporary legacy firewall migration rule" >&2
            exit 1
        fi
    done
done

# 若 UFW 已启用，同步写入可见、可持久化的精确来源规则。Arcway owns
# both management ports, so all prior UFW rules for those ports are replaced.
UFW_ACTIVE=0
if command -v ufw >/dev/null 2>&1; then
    if ! UFW_STATUS=$(LC_ALL=C ufw status 2>/dev/null); then
		if grep -q '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null; then
			echo "ERROR: active UFW policy cannot be inspected" >&2
			exit 1
		fi
		# A disabled UFW can still have inconsistent stale live chains (for
		# example IPv4 loaded while IPv6 is absent). The inactive branch below
		# removes exact persisted Arcway rules and then audits the files, while
		# the independent nft table remains the authoritative live policy.
		echo "WARNING: disabled UFW status is unavailable; auditing its persisted rules directly" >&2
		UFW_STATUS='Status: inactive'
    fi
    if printf '%s\n' "$UFW_STATUS" | grep -q '^Status: active' || grep -q '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null; then
        UFW_ACTIVE=1
    fi
fi
if command -v ufw >/dev/null 2>&1; then
    UFW_PORT_PATTERN=""
    UFW_MANAGED_PORTS=""
    for UFW_PORT in $OLD_ARCWAY_AGENT_PORT $OLD_ARCWAY_GUARD_PORT "$LISTEN_PORT" "$GUARD_PORT"; do
        case "$UFW_PORT" in ''|*[!0-9]*) continue ;; esac
        if [ -z "$UFW_PORT_PATTERN" ]; then UFW_PORT_PATTERN="$UFW_PORT"; else UFW_PORT_PATTERN="$UFW_PORT_PATTERN|$UFW_PORT"; fi
        case " $UFW_MANAGED_PORTS " in *" $UFW_PORT "*) ;; *) UFW_MANAGED_PORTS="$UFW_MANAGED_PORTS $UFW_PORT" ;; esac
    done
    if [ "$UFW_ACTIVE" = "1" ]; then
        if ! UFW_NUMBERED=$(LC_ALL=C ufw status numbered 2>/dev/null); then
            echo "ERROR: failed to enumerate active UFW rules" >&2
            exit 1
        fi
        if printf '%s\n' "$UFW_NUMBERED" | awk -v managed_ports="$UFW_MANAGED_PORTS" '
            function covers_managed(spec, parts, limits, ports, count, i) {
                split(spec, parts, "/")
                spec=parts[1]
                if (spec !~ /^[0-9]+:[0-9]+$/) return 0
                split(spec, limits, ":")
                count=split(managed_ports, ports, " ")
                for (i=1; i<=count; i++) if (ports[i] >= limits[1] && ports[i] <= limits[2]) return 1
                return 0
            }
            /ALLOW/ {
                line=$0
                sub(/^\[[^]]*\][[:space:]]*/, "", line)
                split(line, fields, /[[:space:]]+/)
                if (covers_managed(fields[1])) found=1
            }
            END { exit(found ? 0 : 1) }
        '; then
            echo "ERROR: UFW has a port-range rule covering an Arcway management port; narrow or remove it before retrying" >&2
            exit 1
        fi
        UFW_RULE_NUMBERS=$(printf '%s\n' "$UFW_NUMBERED" | awk -v managed_ports="$UFW_MANAGED_PORTS" '
            function is_managed(spec, parts, ports, count, i) {
                split(spec, parts, "/")
                spec=parts[1]
                if (spec !~ /^[0-9]+$/) return 0
                count=split(managed_ports, ports, " ")
                for (i=1; i<=count; i++) if (ports[i] == spec) return 1
                return 0
            }
            match($0, /^\[[[:space:]]*[0-9]+\]/) {
                number=substr($0, RSTART, RLENGTH)
                gsub(/[^0-9]/, "", number)
                line=substr($0, RSTART+RLENGTH)
                sub(/^[[:space:]]*/, "", line)
                split(line, fields, /[[:space:]]+/)
                if (is_managed(fields[1])) print number
            }
        ' | sort -rn -u)
        for RULE_NUMBER in $UFW_RULE_NUMBERS; do
            if ! ufw --force delete "$RULE_NUMBER" >/dev/null 2>&1; then
                echo "ERROR: failed to remove obsolete UFW rule $RULE_NUMBER" >&2
                exit 1
            fi
        done
        for PANEL_IP in $PANEL_SOURCE_IPS; do
            for MANAGEMENT_PORT in "$LISTEN_PORT" "$GUARD_PORT"; do
                echo "Persisting UFW rule for panel $PANEL_IP to management port $MANAGEMENT_PORT..."
                if ! ufw allow proto tcp from "$PANEL_IP" to any port "$MANAGEMENT_PORT" comment 'arcway-managed'; then
                    echo "ERROR: UFW could not persist the trusted source rule" >&2
                    exit 1
                fi
            done
        done
        if ! UFW_FINAL_STATUS=$(LC_ALL=C ufw status numbered 2>/dev/null); then
            echo "ERROR: failed to verify UFW persistent rules" >&2
            exit 1
        fi
        for MANAGEMENT_PORT in "$LISTEN_PORT" "$GUARD_PORT"; do
            UFW_PORT_LINES=$(printf '%s\n' "$UFW_FINAL_STATUS" | grep -E "(^|[[:space:]])${MANAGEMENT_PORT}(/tcp)?([[:space:]]|$)" || true)
            if [ -z "$UFW_PORT_LINES" ] || printf '%s\n' "$UFW_PORT_LINES" | grep -q 'Anywhere'; then
                echo "ERROR: UFW has a missing or broad rule for Arcway port $MANAGEMENT_PORT" >&2
                exit 1
            fi
            for PANEL_IP in $PANEL_SOURCE_IPS; do
                if ! printf '%s\n' "$UFW_PORT_LINES" | grep -F -- "$PANEL_IP" >/dev/null; then
                    echo "ERROR: UFW is missing panel $PANEL_IP on Arcway port $MANAGEMENT_PORT" >&2
                    exit 1
                fi
            done
        done
    else
        # Inactive UFW does not expose numbered rules. Remove known Arcway rules,
        # then inspect the persisted files; command failures are harmless only
        # because the final file-state check is authoritative.
        for UFW_PANEL_IP in $OLD_ARCWAY_PANEL_IPS $PANEL_SOURCE_IPS; do
            for UFW_PORT in $OLD_ARCWAY_AGENT_PORT $OLD_ARCWAY_GUARD_PORT "$LISTEN_PORT" "$GUARD_PORT"; do
                case "$UFW_PORT" in ''|*[!0-9]*) continue ;; esac
                ufw --force delete allow proto tcp from "$UFW_PANEL_IP" to any port "$UFW_PORT" >/dev/null 2>&1 || true
            done
        done
        for UFW_PORT in $OLD_ARCWAY_AGENT_PORT $OLD_ARCWAY_GUARD_PORT "$LISTEN_PORT" "$GUARD_PORT"; do
            case "$UFW_PORT" in ''|*[!0-9]*) continue ;; esac
            ufw --force delete allow "${UFW_PORT}/tcp" >/dev/null 2>&1 || true
        done
        if awk -v managed_ports="$UFW_MANAGED_PORTS" '
            function covers_managed(spec, parts, limits, ports, count, i) {
                split(spec, parts, "/")
                spec=parts[1]
                count=split(managed_ports, ports, " ")
                if (spec ~ /^[0-9]+$/) {
                    for (i=1; i<=count; i++) if (ports[i] == spec) return 1
                    return 0
                }
                if (spec ~ /^[0-9]+:[0-9]+$/) {
                    split(spec, limits, ":")
                    for (i=1; i<=count; i++) if (ports[i] >= limits[1] && ports[i] <= limits[2]) return 1
                }
                return 0
            }
            {
                dport=""; accept=0
                for (i=1; i<=NF; i++) {
                    if ($i == "--dport" && i < NF) dport=$(i+1)
                    if (($i == "-j" || $i == "--jump") && i < NF && $(i+1) == "ACCEPT") accept=1
                }
                if (accept && covers_managed(dport)) found=1
            }
            END { exit(found ? 0 : 1) }
        ' /etc/ufw/user.rules /etc/ufw/user6.rules 2>/dev/null; then
            echo "ERROR: inactive UFW retains an Arcway management-port rule; remove it explicitly and retry" >&2
            exit 1
        fi
    fi
    if [ "$UFW_ACTIVE" = "1" ]; then
        ARCWAY_AGENT_BINARY="$AGENT_DOWNLOAD" /usr/local/sbin/arcway-agent-firewall
    fi
fi

cat > /usr/local/sbin/arcway-nginx-bridge << 'EOF'
#!/bin/sh
set -eu
umask 077

BT_PREFIX=/www/server/nginx
BT_BIN="$BT_PREFIX/sbin/nginx"
BT_CONF="$BT_PREFIX/conf/nginx.conf"
BT_HTTP_DIR=/www/server/panel/vhost/nginx
BT_STREAM_DIR="$BT_HTTP_DIR/tcp"
HTTP_LOADER="$BT_HTTP_DIR/zz_arcway_loader.conf"
STREAM_LOADER="$BT_STREAM_DIR/zz_arcway_loader.conf"
MANAGED_ROOT=/usr/local/nginx
HTTP_INCLUDE='/www/server/panel/vhost/nginx/*.conf'
STREAM_INCLUDE='/www/server/panel/vhost/nginx/tcp/*.conf'
AGENT_CONFIG=${ARCWAY_AGENT_CONFIG:-/etc/mmw-agent/config.yaml}

# The helper remains in service pre-start hooks for installation compatibility,
# but reuse_existing must never create loaders or reload the externally-owned
# Nginx. Reading the Agent config here also makes later mode changes fail safe.
CONFIGURED_MODE=$(awk -F: '
    /^[[:space:]]*nginx_mode[[:space:]]*:/ {
        value=$2
        sub(/[[:space:]]*#.*/, "", value)
        gsub(/[[:space:]\"]/, "", value)
        mode=value
    }
    END { print mode }
' "$AGENT_CONFIG" 2>/dev/null || true)
if [ "$CONFIGURED_MODE" = "reuse_existing" ]; then
    exit 0
fi

# A host without the BaoTa layout is not an error. A partial BaoTa layout is:
# silently guessing there would recreate the Agent's false-success path bug.
if [ ! -e "$BT_CONF" ] && [ ! -x "$BT_BIN" ] && [ ! -d "$BT_HTTP_DIR" ]; then
    exit 0
fi
for REQUIRED_PATH in "$BT_BIN" "$BT_CONF" "$BT_HTTP_DIR" "$BT_STREAM_DIR"; do
    if [ ! -e "$REQUIRED_PATH" ]; then
        echo "ERROR: partial BaoTa Nginx layout; missing $REQUIRED_PATH" >&2
        exit 1
    fi
done
if [ ! -x "$BT_BIN" ] || [ ! -r "$BT_CONF" ] || [ ! -d "$BT_HTTP_DIR" ] || [ ! -d "$BT_STREAM_DIR" ]; then
    echo "ERROR: BaoTa Nginx layout has unusable permissions or file types" >&2
    exit 1
fi

include_is_present() {
    awk -v wanted="$1" '
        {
            line=$0
            sub(/#.*/, "", line)
            gsub(/[[:space:]]/, "", line)
            if (line == "include" wanted ";") found=1
        }
        END { exit(found ? 0 : 1) }
    ' "$BT_CONF"
}
if ! include_is_present "$HTTP_INCLUDE" || ! include_is_present "$STREAM_INCLUDE"; then
    echo "ERROR: BaoTa nginx.conf does not include both supported HTTP and stream vhost globs" >&2
    exit 1
fi

for MANAGED_DIR in "$MANAGED_ROOT/servers" "$MANAGED_ROOT/stream_servers" "$MANAGED_ROOT/cert"; do
    if [ -L "$MANAGED_DIR" ] || { [ -e "$MANAGED_DIR" ] && [ ! -d "$MANAGED_DIR" ]; }; then
        echo "ERROR: Arcway Nginx managed path is not a real directory: $MANAGED_DIR" >&2
        exit 1
    fi
    if [ ! -d "$MANAGED_DIR" ]; then
        mkdir -m 0755 -p "$MANAGED_DIR"
    fi
done

LOCK_FILE=/run/arcway-nginx-bridge.lock
exec 7>"$LOCK_FILE"
chmod 0600 "$LOCK_FILE"
if ! flock -w 30 7; then
    echo "ERROR: timed out waiting for the Arcway Nginx bridge lock" >&2
    exit 1
fi

STATE_DIR=$(mktemp -d /run/arcway-nginx-bridge.XXXXXX)
TEMP_LOADER=""
cleanup_bridge() {
    [ -z "$TEMP_LOADER" ] || rm -f "$TEMP_LOADER"
    rm -rf "$STATE_DIR"
}
trap cleanup_bridge EXIT
trap 'exit 130' HUP INT TERM

backup_loader() {
    target="$1"
    name="$2"
    if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
        echo "ERROR: reserved Arcway loader path is not a regular file: $target" >&2
        return 1
    fi
    if [ -f "$target" ]; then
        cp -a "$target" "$STATE_DIR/$name" || return 1
        : > "$STATE_DIR/$name.present" || return 1
    fi
}
backup_loader "$HTTP_LOADER" http || exit 1
backup_loader "$STREAM_LOADER" stream || exit 1

CHANGED=0
write_loader() {
    target="$1"
    include_path="$2"
    loader_context="$3"
    temp=$(mktemp "$(dirname "$target")/.arcway-loader.XXXXXX") || return 1
    TEMP_LOADER="$temp"
    {
        echo '# Managed by Arcway. BaoTa loads this file inside the matching Nginx context.'
        if [ "$loader_context" = "http" ]; then
            echo 'map $http_upgrade $arcway_connection_upgrade {'
            echo '    default upgrade;'
            echo "    '' close;"
            echo '}'
        fi
        printf 'include %s;\n' "$include_path"
    } > "$temp" || { rm -f "$temp"; return 1; }
    chmod 0600 "$temp" || { rm -f "$temp"; return 1; }
    chown root:root "$temp" || { rm -f "$temp"; return 1; }
    if [ -f "$target" ] && cmp -s "$temp" "$target"; then
        rm -f "$temp" || return 1
        TEMP_LOADER=""
        return 0
    fi
    mv -f "$temp" "$target" || { rm -f "$temp"; return 1; }
    TEMP_LOADER=""
    CHANGED=1
}

restore_loader() {
    target="$1"
    name="$2"
    rm -f "$target" || return 1
    if [ -f "$STATE_DIR/$name.present" ]; then
        cp -a "$STATE_DIR/$name" "$target" || return 1
    fi
}
rollback_bridge() {
    rollback_ok=1
    restore_loader "$HTTP_LOADER" http || rollback_ok=0
    restore_loader "$STREAM_LOADER" stream || rollback_ok=0
    if [ "$rollback_ok" = "1" ]; then
        if ! "$BT_BIN" -p "$BT_PREFIX/" -c "$BT_CONF" -t >/dev/null 2>&1; then
            rollback_ok=0
        elif [ "$CHANGED" = "1" ] && ! "$BT_BIN" -p "$BT_PREFIX/" -c "$BT_CONF" -s reload >/dev/null 2>&1; then
            rollback_ok=0
        fi
    fi
    [ "$rollback_ok" = "1" ]
}
fail_bridge() {
    message="$1"
    echo "ERROR: $message" >&2
    if [ "$CHANGED" = "1" ] && ! rollback_bridge; then
        echo "ERROR: failed to restore the previous BaoTa Nginx bridge" >&2
    fi
    exit 1
}

write_loader "$HTTP_LOADER" "$MANAGED_ROOT/servers/*.conf" http || fail_bridge "cannot write the HTTP loader"
write_loader "$STREAM_LOADER" "$MANAGED_ROOT/stream_servers/*.conf" stream || fail_bridge "cannot write the stream loader"

if ! TEST_OUTPUT=$("$BT_BIN" -p "$BT_PREFIX/" -c "$BT_CONF" -t 2>&1); then
    printf '%s\n' "$TEST_OUTPUT" >&2
    fail_bridge "BaoTa Nginx rejected the Arcway bridge"
fi
if ! CONFIG_DUMP=$("$BT_BIN" -p "$BT_PREFIX/" -c "$BT_CONF" -T 2>&1); then
    printf '%s\n' "$CONFIG_DUMP" >&2
    fail_bridge "BaoTa Nginx could not dump the effective configuration"
fi
if ! printf '%s\n' "$CONFIG_DUMP" | grep -F -- "# configuration file $HTTP_LOADER:" >/dev/null; then
    fail_bridge "HTTP loader was written but is not loaded by nginx -T"
fi
if ! printf '%s\n' "$CONFIG_DUMP" | grep -F -- "# configuration file $STREAM_LOADER:" >/dev/null; then
    fail_bridge "stream loader was written but is not loaded by nginx -T"
fi
if [ "$CHANGED" = "1" ] && ! "$BT_BIN" -p "$BT_PREFIX/" -c "$BT_CONF" -s reload >/dev/null 2>&1; then
    fail_bridge "BaoTa Nginx reload failed after validating the bridge"
fi
EOF
chmod 0755 /usr/local/sbin/arcway-nginx-bridge
if ! /usr/local/sbin/arcway-nginx-bridge; then
    echo "ERROR: failed to install the BaoTa Nginx compatibility bridge" >&2
    exit 1
fi

# Step 4: 创建 service 文件 — 按检测到的 init 系统选不同写法
echo ""
echo "[4/7] Creating service..."

if [ "$HAS_SYSTEMD" = "1" ]; then
    cat > /etc/systemd/system/mmw-agent.service << EOF
[Unit]
Description=MMW Agent Remote Server
After=network-online.target ufw.service firewalld.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/arcway-port-firewall.env
ExecStartPre=/usr/local/sbin/arcway-agent-firewall
ExecStartPre=/usr/local/sbin/arcway-nginx-bridge
ExecStart=/usr/local/bin/mmw-agent -c /etc/mmw-agent/config.yaml
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/mmw-agent

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/arcway-expiry-guard.service << EOF
[Unit]
Description=Arcway Managed Client Expiry Guard
After=network-online.target mmw-agent.service
Wants=network-online.target
Requires=mmw-agent.service

[Service]
Type=simple
EnvironmentFile=/etc/arcway-port-firewall.env
EnvironmentFile=/etc/arcway-expiry-guard.env
ExecStartPre=/usr/local/sbin/arcway-agent-firewall --nft-only
ExecStart=/usr/local/bin/arcway-expiry-guard
Restart=always
RestartSec=5
WorkingDirectory=/var/lib/arcway-expiry-guard
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/arcway-expiry-guard

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 /etc/systemd/system/mmw-agent.service /etc/systemd/system/arcway-expiry-guard.service
    systemctl daemon-reload
elif [ "$HAS_OPENRC" = "1" ]; then
    cat > /etc/init.d/mmw-agent << 'EOF'
#!/sbin/openrc-run
name="mmw-agent"
description="MMW Agent Remote Server"
command="/usr/local/bin/mmw-agent"
command_args="-c /etc/mmw-agent/config.yaml"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
# 日志由 agent 自身写文件并轮转(/var/log/mmw-agent/mmw-agent.log),不再用 output_log 重复落地(避免无轮转爆盘)
start_pre() {
    set -a
    . /etc/arcway-port-firewall.env
    set +a
    /usr/local/sbin/arcway-agent-firewall || return 1
    /usr/local/sbin/arcway-nginx-bridge || return 1
}
depend() { need net; }
EOF
    chmod +x /etc/init.d/mmw-agent
    cat > /etc/init.d/arcway-expiry-guard << 'EOF'
#!/sbin/openrc-run
name="arcway-expiry-guard"
description="Arcway Managed Client Expiry Guard"
command="/usr/local/bin/arcway-expiry-guard"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
start_pre() {
    set -a
    . /etc/arcway-port-firewall.env
    set +a
    /usr/local/sbin/arcway-agent-firewall || return 1
    set -a
    . /etc/arcway-expiry-guard.env || return 1
    set +a
}
depend() { need net mmw-agent; }
EOF
    chmod +x /etc/init.d/arcway-expiry-guard
else
    # 无 init 系统(典型 LXC 容器):写一个 supervisor 脚本,失败自动重启,放后台跑;同时塞进 rc.local 以便重启
    cat > /usr/local/bin/mmw-agent-supervisor.sh << 'EOF'
#!/bin/sh
if ! /usr/local/sbin/arcway-nginx-bridge; then
    echo "[supervisor] Arcway Nginx bridge validation failed" >&2
    exit 1
fi
while true; do
    # 日志由 agent 自身写文件并轮转(/var/log/mmw-agent/mmw-agent.log);这里输出走 stdout(由 rc.local 的 nohup 接管)
    /usr/local/bin/mmw-agent -c /etc/mmw-agent/config.yaml
    echo "[supervisor] mmw-agent exited, restarting in 5s..."
    sleep 5
done
EOF
    chmod +x /usr/local/bin/mmw-agent-supervisor.sh

    cat > /usr/local/bin/arcway-expiry-guard-supervisor.sh << 'EOF'
#!/bin/sh
set -a
. /etc/arcway-expiry-guard.env
set +a
while true; do
    /usr/local/bin/arcway-expiry-guard
    echo "[supervisor] arcway-expiry-guard exited, restarting in 5s..."
    sleep 5
done
EOF
    chmod +x /usr/local/bin/arcway-expiry-guard-supervisor.sh

    # 写入 rc.local 实现重启自启动(若文件不存在就建一个)
    if [ ! -f /etc/rc.local ]; then
        echo "#!/bin/sh" > /etc/rc.local
        echo "exit 0" >> /etc/rc.local
        chmod +x /etc/rc.local
    fi
    # Rebuild all managed lines as one ordered block. This also repairs an old
    # installation where the firewall line had been appended after supervisors.
    RC_LOCAL_NEW="$DOWNLOAD_DIR/rc.local"
    awk '
        /arcway-agent-firewall|arcway-nginx-bridge|mmw-agent-supervisor[.]sh|arcway-expiry-guard-supervisor[.]sh/ { next }
        /^exit 0[[:space:]]*$/ && !inserted {
            print "set -a; . /etc/arcway-port-firewall.env; set +a; /usr/local/sbin/arcway-agent-firewall || exit 1"
            print "/usr/local/sbin/arcway-nginx-bridge || exit 1"
            print "nohup /usr/local/bin/mmw-agent-supervisor.sh >/dev/null 2>&1 &"
            print "nohup /usr/local/bin/arcway-expiry-guard-supervisor.sh >/dev/null 2>&1 &"
            inserted=1
        }
        { print }
        END {
            if (!inserted) {
                print "set -a; . /etc/arcway-port-firewall.env; set +a; /usr/local/sbin/arcway-agent-firewall || exit 1"
                print "/usr/local/sbin/arcway-nginx-bridge || exit 1"
                print "nohup /usr/local/bin/mmw-agent-supervisor.sh >/dev/null 2>&1 &"
                print "nohup /usr/local/bin/arcway-expiry-guard-supervisor.sh >/dev/null 2>&1 &"
            }
        }
    ' /etc/rc.local > "$RC_LOCAL_NEW"
    install -m 0755 "$RC_LOCAL_NEW" /etc/rc.local
fi

# Step 5: atomically install the already verified binaries.
echo ""
echo "[5/7] Installing verified binaries..."
install -m 0755 "$AGENT_DOWNLOAD" /usr/local/bin/.mmw-agent.new
mv -f /usr/local/bin/.mmw-agent.new /usr/local/bin/mmw-agent
install -m 0755 "$GUARD_DOWNLOAD" /usr/local/bin/.arcway-expiry-guard.new
mv -f /usr/local/bin/.arcway-expiry-guard.new /usr/local/bin/arcway-expiry-guard

echo "Binaries installed to /usr/local/bin/mmw-agent and /usr/local/bin/arcway-expiry-guard"

# Step 6: 启用并启动 service
echo ""
echo "[6/7] Starting service..."
if [ "$HAS_SYSTEMD" = "1" ]; then
    systemctl enable mmw-agent
    systemctl start mmw-agent
    systemctl enable arcway-expiry-guard
    systemctl start arcway-expiry-guard
elif [ "$HAS_OPENRC" = "1" ]; then
	rc-update add mmw-agent default
	rc-update show default 2>/dev/null | awk '$1 == "mmw-agent" { found=1 } END { exit !found }' || {
		echo "ERROR: mmw-agent was not registered in the OpenRC default runlevel" >&2
		exit 1
	}
	rc-service mmw-agent start 9>&-
	rc-update add arcway-expiry-guard default
	rc-update show default 2>/dev/null | awk '$1 == "arcway-expiry-guard" { found=1 } END { exit !found }' || {
		echo "ERROR: arcway-expiry-guard was not registered in the OpenRC default runlevel" >&2
		exit 1
	}
	rc-service arcway-expiry-guard start 9>&-
else
    nohup /usr/local/bin/mmw-agent-supervisor.sh 9>&- >/dev/null 2>&1 &
    nohup /usr/local/bin/arcway-expiry-guard-supervisor.sh 9>&- >/dev/null 2>&1 &
    echo "Started via nohup (PID=$!); 安装重启后通过 /etc/rc.local 自启动"
fi

# Wait a moment for service to start
sleep 3

# Step 7: Verify installation
echo ""
echo "[7/7] Verifying installation..."

echo "Service status:"
if [ "$HAS_SYSTEMD" = "1" ]; then
    systemctl status mmw-agent --no-pager -l 2>/dev/null | head -15 || echo "Service started"
    systemctl status arcway-expiry-guard --no-pager -l 2>/dev/null | head -15 || echo "Guard service started"
elif [ "$HAS_OPENRC" = "1" ]; then
    rc-service mmw-agent status 2>/dev/null || echo "Service started"
    rc-service arcway-expiry-guard status 2>/dev/null || echo "Guard service started"
else
    pgrep -af /usr/local/bin/mmw-agent | head -5 || echo "Process not found in pgrep, check /var/log/mmw-agent.log"
    pgrep -af /usr/local/bin/arcway-expiry-guard | head -5 || echo "Guard process not found"
fi
guard_healthy=0
for health_attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --connect-timeout 1 --max-time 2 "http://127.0.0.1:${GUARD_PORT}/healthz" >/dev/null 2>&1; then
        guard_healthy=1
        break
    fi
    sleep 1
done
if [ "$guard_healthy" != "1" ]; then
    echo "ERROR: expiry guard health check failed on port ${GUARD_PORT}" >&2
    exit 1
fi

verify_local_services() {
	local services_status=""
	services_status=$(curl -fsS --connect-timeout 2 --max-time 5 \
		-H @"$CURL_AUTH_HEADER_FILE" \
		"http://127.0.0.1:${LISTEN_PORT}/api/child/services/status") || {
        echo "ERROR: local Agent service-status check failed" >&2
        return 1
    }
    if ! printf '%s\n' "$services_status" | grep -Eq '"xray"[[:space:]]*:[[:space:]]*\{[^}]*"running"[[:space:]]*:[[:space:]]*true'; then
        echo "ERROR: Agent reports that Xray is not running" >&2
        return 1
    fi
    if [ "$AUTO_STEAL_SELF" = "1" ] && ! printf '%s\n' "$services_status" | grep -Eq '"nginx"[[:space:]]*:[[:space:]]*\{[^}]*"running"[[:space:]]*:[[:space:]]*true'; then
        echo "ERROR: Agent reports that Nginx is not running" >&2
        return 1
    fi
}
agent_healthy=0
for health_attempt in 1 2 3 4 5 6 7 8 9 10; do
    if verify_local_services; then
        agent_healthy=1
        break
    fi
    sleep 1
done
if [ "$agent_healthy" != "1" ]; then
    echo "ERROR: Agent did not become ready within the verification window" >&2
    exit 1
fi

# Management readiness covers the control plane. Validate selected data-plane
# prerequisites separately so a healthy Agent cannot mask a stopped Xray/Nginx.
if [ "$XRAY_MODE" != "embedded" ]; then
    if ! "$XRAY_BIN" version >/dev/null 2>&1; then
        echo "ERROR: external Xray became unavailable during installation" >&2
        exit 1
    fi
    if [ "$HAS_SYSTEMD" = "1" ] && systemctl cat xray >/dev/null 2>&1; then
        if ! systemctl is-active --quiet xray; then
            echo "ERROR: external Xray systemd service is not active" >&2
            exit 1
        fi
    elif ! pgrep -x xray >/dev/null 2>&1; then
        echo "ERROR: external Xray process is not running" >&2
        exit 1
    fi
fi
if [ "$AUTO_STEAL_SELF" = "1" ]; then
    if ! "$NGINX_BIN" -t >/dev/null 2>&1; then
        echo "ERROR: Nginx configuration is invalid after enabling takeover mode" >&2
        exit 1
    fi
    if [ "$HAS_SYSTEMD" = "1" ] && systemctl cat nginx >/dev/null 2>&1; then
        if ! systemctl is-active --quiet nginx; then
            echo "ERROR: Nginx systemd service is not active" >&2
            exit 1
        fi
    elif ! pgrep -x nginx >/dev/null 2>&1; then
        echo "ERROR: Nginx process is not running" >&2
        exit 1
    fi
fi

# 由主控反向验证 Agent HTTP fallback 和 guard 端口。这一步能检出云防火墙、native nft
# default-drop 或 NAT 出口配置错误，避免只做本机 healthz 后误报安装成功。
management_ready=0
for attempt in $(seq 1 20); do
	if curl -fsS --connect-timeout 5 --max-time 10 -X POST \
		-H @"$CURL_AUTH_HEADER_FILE" \
		-H @"$CURL_INSTALL_NONCE_HEADER_FILE" \
		"${MASTER_URL}/api/remote/management-ready" >/dev/null; then
        management_ready=1
        break
    fi
    if [ "$attempt" -eq 1 ]; then
        echo "Waiting for the panel to verify both management services..."
    fi
    sleep 2
done
if [ "$management_ready" != "1" ]; then
    echo "ERROR: panel cannot reach Agent ${LISTEN_PORT} and guard ${GUARD_PORT}." >&2
    echo "ERROR: allow the configured ARCWAY_PANEL_IPS in the host/cloud firewall and retry." >&2
    exit 1
fi

# Apply the final panel-owned data-plane state while both the durable install
# lock and local rollback snapshot are still active.
assert_install_lease
PREPARE_ATTEMPTED=1
if ! curl -fsS --connect-timeout 10 --max-time 120 -X POST \
	-H @"$CURL_AUTH_HEADER_FILE" \
	-H @"$CURL_INSTALL_NONCE_HEADER_FILE" \
	"${MASTER_URL}/api/remote/install-prepare" >/dev/null; then
    echo "ERROR: panel could not prepare the final desired state" >&2
    exit 1
fi
verify_local_services

# Desired state is proven, so commit the local rollback transaction before
# removing legacy iptables state. Legacy cleanup is deliberately outside rollback: partial chain
# deletion cannot be reconstructed reliably without restoring the entire host
# firewall. Any cleanup failure is reported as a failed install, never hidden.
assert_install_lease
MUTATION_STARTED=0
cleanup_legacy_firewall() {
    local LEGACY_TOOL="$1"
    if ! "$LEGACY_TOOL" -w 5 -S INPUT >/dev/null 2>&1; then
        echo "ERROR: cannot inspect legacy $LEGACY_TOOL INPUT rules" >&2
        return 1
    fi

    if "$LEGACY_TOOL" -w 5 -S ARCWAY_PORTS >/dev/null 2>&1; then
        while "$LEGACY_TOOL" -w 5 -C INPUT -j ARCWAY_PORTS >/dev/null 2>&1; do
            "$LEGACY_TOOL" -w 5 -D INPUT -j ARCWAY_PORTS >/dev/null 2>&1 || return 1
        done
        if ! "$LEGACY_TOOL" -w 5 -S INPUT >/dev/null 2>&1; then return 1; fi
        if "$LEGACY_TOOL" -w 5 -S INPUT 2>/dev/null | grep -q -- '-A INPUT -j ARCWAY_PORTS'; then
            echo "ERROR: a legacy $LEGACY_TOOL ARCWAY_PORTS jump remains" >&2
            return 1
        fi
        "$LEGACY_TOOL" -w 5 -F ARCWAY_PORTS >/dev/null 2>&1 || return 1
        "$LEGACY_TOOL" -w 5 -X ARCWAY_PORTS >/dev/null 2>&1 || return 1
    fi

    if "$LEGACY_TOOL" -w 5 -S ufw-user-input >/dev/null 2>&1; then
        for LEGACY_PORT in $OLD_ARCWAY_AGENT_PORT $OLD_ARCWAY_GUARD_PORT "$LISTEN_PORT" "$GUARD_PORT"; do
            case "$LEGACY_PORT" in
                ''|*[!0-9]*) continue ;;
            esac
            while "$LEGACY_TOOL" -w 5 -C ufw-user-input -p tcp --dport "$LEGACY_PORT" -j ACCEPT >/dev/null 2>&1; do
                "$LEGACY_TOOL" -w 5 -D ufw-user-input -p tcp --dport "$LEGACY_PORT" -j ACCEPT >/dev/null 2>&1 || return 1
            done
        done
        "$LEGACY_TOOL" -w 5 -S ufw-user-input >/dev/null 2>&1 || return 1
    fi
}
for LEGACY_TOOL in iptables ip6tables; do
    if ! command -v "$LEGACY_TOOL" >/dev/null 2>&1; then
        continue
    fi
    if ! cleanup_legacy_firewall "$LEGACY_TOOL"; then
        echo "ERROR: Arcway services are healthy, but obsolete $LEGACY_TOOL rules require manual cleanup" >&2
        exit 1
    fi
done

# The panel releases its durable lock only after legacy cleanup succeeds.
if ! retry_remote_install_post "/api/remote/install-finalize" 120 0; then
    echo "ERROR: panel could not finalize the installation transaction" >&2
    exit 1
fi
SERVER_LOCK_ATTEMPTED=0
SERVER_LOCK_STARTED=0
stop_install_renewal

echo ""
echo "To check status:"
if [ "$HAS_SYSTEMD" = "1" ]; then
    echo "  systemctl status mmw-agent"
    echo "  systemctl status arcway-expiry-guard"
elif [ "$HAS_OPENRC" = "1" ]; then
    echo "  rc-service mmw-agent status"
    echo "  rc-service arcway-expiry-guard status"
else
    echo "  tail -f /var/log/mmw-agent.log  # 或: pgrep -af mmw-agent"
fi
echo ""
echo "To view logs:"
echo "  journalctl -u mmw-agent -f"
echo ""

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
`

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=install.sh")
	w.Write([]byte(script))
}
