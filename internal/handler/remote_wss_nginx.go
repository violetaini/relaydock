package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	texttemplate "text/template"

	"miaomiaowux/internal/storage"
	"miaomiaowux/templates"
)

// WSS 入站 nginx 联动:
//   - 入站创建时:自动分配本地端口 + 随机 path,强制 listen 127.0.0.1 + security=none
//     (TLS 由 nginx 在 443 端口处理,xray 只负责 127.0.0.1:<port> 的 ws upgrade)
//   - 入站创建/删除后:聚合渲染该 server 全部 VLESS/VMess/Trojan+WS 入站到一份 nginx domain.conf,
//     调 agent /api/child/nginx/setup-ssl 下发 + reload
//
// 与 reality 流程互斥(都覆盖 servers/{domain}.conf),设计上同一 server.domain 不应同时用两种。

const (
	wssPortRangeStart = 11000
	wssPortRangeEnd   = 19999
)

// wssServerLocks per-server mutex,防止并发添加 WSS 入站抢到同一端口。
var wssServerLocks sync.Map // serverID(int64) → *sync.Mutex

func wssServerLock(serverID int64) *sync.Mutex {
	v, _ := wssServerLocks.LoadOrStore(serverID, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// 8 字符 a-z0-9 随机串,用于 ws path。
func randomWSPath() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "fallback1" // 极端罕见,撑住 nginx location 匹配即可
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return "/ws/" + string(b)
}

func isWSSProtocol(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vless", "vmess", "trojan":
		return true
	default:
		return false
	}
}

// isNginxManagedWSSInbound distinguishes the internal WebSocket backend used by
// Arcway's nginx TLS terminator from a regular, directly exposed WS inbound.
// A public WS inbound may intentionally have no domain or TLS certificate, so
// network=ws alone must never opt it into the nginx/domain/443 workflow.
func isNginxManagedWSSInbound(inbound map[string]interface{}) bool {
	if inbound == nil {
		return false
	}
	if protocol, _ := inbound["protocol"].(string); !isWSSProtocol(protocol) {
		return false
	}

	listen, _ := inbound["listen"].(string)
	switch strings.ToLower(strings.TrimSpace(listen)) {
	case "127.0.0.1", "localhost":
	default:
		return false
	}

	ss, _ := inbound["streamSettings"].(map[string]interface{})
	if ss == nil {
		return false
	}
	network, _ := ss["network"].(string)
	security, _ := ss["security"].(string)
	return strings.EqualFold(strings.TrimSpace(network), "ws") &&
		strings.EqualFold(strings.TrimSpace(security), "none")
}

// isWSSInboundReq 从 HandleInbounds 收到的 inboundReq 里判断是否需要 nginx TLS 终止的 WS 入站。
func isWSSInboundReq(inboundReq map[string]interface{}) bool {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	return isNginxManagedWSSInbound(inbound)
}

// isVlessWSInboundReq 保留给旧调用方和测试，语义仍严格限定为 VLESS+WS。
func isVlessWSInboundReq(inboundReq map[string]interface{}) bool {
	if !isWSSInboundReq(inboundReq) {
		return false
	}
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	protocol, _ := inbound["protocol"].(string)
	return strings.EqualFold(strings.TrimSpace(protocol), "vless")
}

// preprocessWSSInbound 在 forward 之前对受管 WS 入站强制注入安全默认值。
// 返回新的 body(已 marshal 好,可直接 forward)。
//
// 调用方持有 server-level 锁,内部扫端口安全。
func (h *RemoteManageHandler) preprocessWSSInbound(ctx context.Context, serverID int64, body []byte, inboundReq map[string]interface{}) ([]byte, error) {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	if inbound == nil {
		return body, nil
	}

	// 强制 listen 127.0.0.1(xray 只接收 nginx 反代,不直接对外)
	inbound["listen"] = "127.0.0.1"

	// 自动分配未占用本地端口
	port, err := h.allocateWSSPort(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("分配 WSS 本地端口失败: %v", err)
	}
	inbound["port"] = port

	// 强制 streamSettings.security="none"(TLS 给 nginx)
	ss, _ := inbound["streamSettings"].(map[string]interface{})
	if ss == nil {
		ss = map[string]interface{}{}
		inbound["streamSettings"] = ss
	}
	ss["network"] = "ws"
	ss["security"] = "none"

	// wsSettings.path 后端强制随机化(隐蔽性 + 避免前端默认 "/wss" 等可猜路径泄漏)。
	// 用户想要的可见 path 在节点详情可查。
	ws, _ := ss["wsSettings"].(map[string]interface{})
	if ws == nil {
		ws = map[string]interface{}{}
		ss["wsSettings"] = ws
	}
	ws["path"] = randomWSPath()

	newBody, err := json.Marshal(inboundReq)
	if err != nil {
		return nil, fmt.Errorf("重新序列化 inbound 失败: %v", err)
	}
	return newBody, nil
}

// allocateWSSPort 在 wssPortRangeStart-End 段挑一个未被该 server 现有 inbounds 占用的端口。
// 走 forward GET /api/child/inbounds 拿当前真实端口集(权威,不依赖 cache 的 snapshot)。
func (h *RemoteManageHandler) allocateWSSPort(ctx context.Context, serverID int64) (int, error) {
	used := make(map[int]struct{})
	result, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Success  *bool                    `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
		Error    string                   `json:"error"`
		Message  string                   `json:"message"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return 0, fmt.Errorf("解析 inbounds 失败: %w", err)
	}
	if resp.Success != nil && !*resp.Success {
		message := strings.TrimSpace(resp.Error)
		if message == "" {
			message = strings.TrimSpace(resp.Message)
		}
		if message == "" {
			message = "Agent rejected inbounds query"
		}
		return 0, errors.New(message)
	}
	for _, ib := range resp.Inbounds {
		if p, ok := ib["port"].(float64); ok {
			used[int(p)] = struct{}{}
		} else if text, ok := ib["port"].(string); ok {
			if p, parseErr := strconv.Atoi(text); parseErr == nil {
				used[p] = struct{}{}
			}
		}
	}

	// 从 start 顺序找第一个空闲;扫整段都满了直接报错(WSS 入站不应该有这么多)
	for p := wssPortRangeStart; p <= wssPortRangeEnd; p++ {
		if _, taken := used[p]; !taken {
			return p, nil
		}
	}
	return 0, fmt.Errorf("端口段 %d-%d 全被占用", wssPortRangeStart, wssPortRangeEnd)
}

// wssInboundInfo 渲染到 nginx 模板的单条 location 信息。
type wssInboundInfo struct {
	WSPath string
	Port   string
}

type wssCertificateContext struct {
	server      *storage.RemoteServer
	domain      string
	rootDomain  string
	certificate *storage.Certificate
	certName    string
}

func (h *RemoteManageHandler) resolveWSSCertificateContext(ctx context.Context, serverID int64) (*wssCertificateContext, error) {
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("server not found: %v", err)
	}
	domain := strings.ToLower(strings.TrimSpace(server.Domain))
	if domain == "" {
		return nil, fmt.Errorf("server %d 未配置域名，无法同步 WSS nginx", serverID)
	}
	if h.certHandler == nil {
		return nil, fmt.Errorf("证书功能未初始化，无法同步 WSS nginx")
	}
	rootDomain := extractRootDomain(domain)
	certificate, err := h.findCertificateForRemoteDomain(ctx, domain, serverID)
	if err != nil {
		return nil, fmt.Errorf("server %d domain=%s 根域=%s 无可部署证书，无法同步 WSS nginx: %v", serverID, domain, rootDomain, err)
	}
	return &wssCertificateContext{
		server: server, domain: domain, rootDomain: rootDomain,
		certificate: certificate, certName: certDeployFilename(certificate.Domain),
	}, nil
}

// SyncWSSNginx 查该 server 所有受支持的 WS 入站,聚合渲染 nginx domain.conf 并下发 agent。
// 关键约束:
//   - server.domain 必须有
//   - 根域必须有状态有效、PEM 完整且未过期的可部署证书
//   - 必须先收到 Agent 证书落盘 ACK，才能下发引用该证书的 nginx 配置
//   - 不下发主 nginx.conf(留空),只覆盖 servers/{domain}.conf
//   - infos 为空(用户删完所有 WSS 入站)时也走渲染流程下发空 location 的 server 块,
//     借模板的 default `location / { return 404; }` 兜底,把旧 location 全部覆盖,避免死 backend 残留。
//
// 大写导出:nodes.go 的 deleteRemoteInbound 也要调,删节点路径不走 HandleInbounds remove。
func (h *RemoteManageHandler) SyncWSSNginx(ctx context.Context, serverID int64) error {
	certificateContext, err := h.resolveWSSCertificateContext(ctx, serverID)
	if err != nil {
		return err
	}
	server := certificateContext.server
	domain := certificateContext.domain
	rootDomain := certificateContext.rootDomain
	cert := certificateContext.certificate
	certName := certificateContext.certName

	// 拉全部 inbounds,过滤 VLESS/VMess/Trojan+WS。
	result, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return fmt.Errorf("拉取 inbounds 失败: %v", err)
	}
	var resp struct {
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return fmt.Errorf("解析 inbounds 失败: %v", err)
	}

	infos := extractWSSInbounds(resp.Inbounds)

	var domainConf string
	stealSelf := server.StealMode == "tunnel" || server.StealMode == "fallback"

	// 偷自己 server(steal_mode=tunnel/fallback):ws location 合并进伪装站 conf(listen 127.0.0.1:8001,
	// 流量走 tunnel 域名分流 / reality fallback 到 nginx),不用 wss_domain.conf.tpl(listen 443 会和
	// xray 的 443 抢端口 + 冲掉伪装站)。renderStealSelfDomainConf 把伪装站 location / 和 ws location 一并渲染,
	// 无 ws 入站时就是纯伪装站 conf(不再空 404 兜底冲掉伪装站)。
	if stealSelf {
		conf, rerr := renderStealSelfDomainConf(server.StealMode, server.SiteType, server.SiteValue, domain, certName, infos)
		if rerr != nil {
			return rerr
		}
		domainConf = conf
	} else {
		// 纯 WSS server(非偷自己, listen 443 独占):
		// 空 infos 也继续走模板渲染:渲染后是「只有 ssl 配置 + 默认 404 location」的 server 块,
		// 覆盖 servers/{domain}.conf 后,旧的 WSS location 全部被冲掉,不再残留死 backend。
		// 当前架构假设 WSS 与 reality 在同 domain 互斥(同 conf 文件覆盖),没有共存场景下的副作用。
		if len(infos) == 0 {
			log.Printf("[WSS-Nginx] server %d domain=%s 已无受管 WS 入站,下发空 location 兜底(覆盖残留)", serverID, domain)
		}

		tplBytes, err := templates.ReadFile("wss_domain.conf.tpl")
		if err != nil {
			return fmt.Errorf("读取 wss 模板失败: %v", err)
		}
		tpl, err := texttemplate.New("wss").Parse(string(tplBytes))
		if err != nil {
			return fmt.Errorf("解析 wss 模板失败: %v", err)
		}
		data := struct {
			Domain   string
			CertName string
			Inbounds []wssInboundInfo
		}{Domain: domain, CertName: certName, Inbounds: infos}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, data); err != nil {
			return fmt.Errorf("渲染 wss 模板失败: %v", err)
		}
		domainConf = buf.String()
	}

	payload, err := json.Marshal(map[string]interface{}{
		"domain":        domain,
		"nginx_config":  "", // 留空 → agent 跳过主 nginx.conf 写入(reality 已下过的不动)
		"domain_config": domainConf,
		"nginx_mode":    normalizedRemoteNginxMode(server),
	})
	if err != nil {
		return fmt.Errorf("序列化 WSS nginx 配置失败: %v", err)
	}

	certPayload := WSCertDeployPayload{
		Domain:   rootDomain,
		CertPEM:  cert.CertPEM,
		KeyPEM:   cert.KeyPEM,
		CertPath: fmt.Sprintf("/usr/local/nginx/cert/%s.pem", certName),
		KeyPath:  fmt.Sprintf("/usr/local/nginx/cert/%s.key", certName),
		Reload:   "none",
	}
	if err := h.certHandler.deployToRemoteServerSync(ctx, server, certPayload); err != nil {
		return fmt.Errorf("WSS 证书部署未获得 Agent ACK: %v", err)
	}

	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/nginx/setup-ssl", payload); err != nil {
		if stealSelf {
			return fmt.Errorf("下发偷自己 nginx 配置失败: %v", err)
		}
		return fmt.Errorf("下发 nginx 配置失败: %v", err)
	}
	if stealSelf {
		log.Printf("[WSS-Nginx] server %d domain=%s 偷自己模式:伪装站 + %d 条 ws location(listen 8001)已下发", serverID, domain, len(infos))
		return nil
	}
	log.Printf("[WSS-Nginx] server %d domain=%s 已下发 %d 条 WSS location", serverID, domain, len(infos))
	return nil
}

// extractWSSInbounds 从 agent inbounds 列表过滤出 VLESS/VMess/Trojan+WS 入站的 {path, port}。
func extractWSSInbounds(inbounds []map[string]interface{}) []wssInboundInfo {
	var infos []wssInboundInfo
	for _, ib := range inbounds {
		if !isNginxManagedWSSInbound(ib) {
			continue
		}
		ss, _ := ib["streamSettings"].(map[string]interface{})
		ws, _ := ss["wsSettings"].(map[string]interface{})
		if ws == nil {
			continue
		}
		path, _ := ws["path"].(string)
		if path == "" {
			continue
		}
		var portStr string
		if p, ok := ib["port"].(float64); ok {
			portStr = strconv.Itoa(int(p))
		} else if ps, ok := ib["port"].(string); ok {
			portStr = ps
		}
		if portStr == "" {
			continue
		}
		infos = append(infos, wssInboundInfo{WSPath: path, Port: portStr})
	}
	return infos
}

// fetchWSSInboundsStrict 拉 server 当前所有受管 WS 入站。多步写操作必须使用
// strict 版本：读取失败时若当作“没有 WSS”，会用空 location 覆盖掉现网配置。
func (h *RemoteManageHandler) fetchWSSInboundsStrict(ctx context.Context, serverID int64) ([]wssInboundInfo, error) {
	result, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Success  *bool                    `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
		Error    string                   `json:"error"`
		Message  string                   `json:"message"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("解析 inbounds 失败: %w", err)
	}
	if resp.Success != nil && !*resp.Success {
		message := strings.TrimSpace(resp.Error)
		if message == "" {
			message = strings.TrimSpace(resp.Message)
		}
		if message == "" {
			message = "Agent rejected inbounds query"
		}
		return nil, fmt.Errorf("Agent 返回 inbounds 失败: %s", message)
	}
	return extractWSSInbounds(resp.Inbounds), nil
}

// fetchWSSInbounds 保留给只读/最佳努力调用方；写操作不应使用它。
func (h *RemoteManageHandler) fetchWSSInbounds(ctx context.Context, serverID int64) []wssInboundInfo {
	infos, err := h.fetchWSSInboundsStrict(ctx, serverID)
	if err != nil {
		log.Printf("[WSS-Nginx] fetch inbounds for server %d failed: %v", serverID, err)
		return nil
	}
	return infos
}

// stealSelfDomainTplPath 按 steal_mode(tunnel/fallback)+ site_type(static/proxy)选伪装站 domain 模板。
func stealSelfDomainTplPath(stealMode, siteType string) string {
	dir := "tunnel"
	if stealMode == "fallback" {
		dir = "fallback"
	}
	if siteType == "proxy" {
		return dir + "/domain_proxy.conf"
	}
	return dir + "/domain_static.conf"
}

// renderStealSelfWSLocations 渲染偷自己 server 的 ws 入站 nginx location(合并进伪装站 conf@8001)。
// 偷自己 nginx listen proxy_protocol,真实客户端 IP 在 $proxy_protocol_addr(不是 $remote_addr)。
func renderStealSelfWSLocations(wssInbounds []wssInboundInfo) string {
	var b strings.Builder
	for _, w := range wssInbounds {
		fmt.Fprintf(&b, `
        location = %s {
            if ($http_upgrade != "websocket") { return 404; }
            proxy_pass         http://127.0.0.1:%s;
            proxy_redirect     off;
            proxy_http_version 1.1;
            proxy_set_header   Upgrade            $http_upgrade;
            proxy_set_header   Connection         "upgrade";
            proxy_set_header   Host               $host;
            proxy_set_header   X-Real-IP          $proxy_protocol_addr;
            proxy_set_header   X-Forwarded-For    $proxy_add_x_forwarded_for;
            proxy_read_timeout 5d;
        }
`, w.WSPath, w.Port)
	}
	return b.String()
}

// injectWSLocations 把 ws location 注入伪装站 conf 的 server 块内(最后一个 } 前)。
// 伪装站模板只有一个 server 块,最后一个 } 即 server 结束。无 ws 入站时原样返回。
func injectWSLocations(conf string, wssInbounds []wssInboundInfo) string {
	if len(wssInbounds) == 0 {
		return conf
	}
	wsLoc := renderStealSelfWSLocations(wssInbounds)
	idx := strings.LastIndex(conf, "}")
	if idx < 0 {
		return conf + wsLoc
	}
	return conf[:idx] + wsLoc + conf[idx:]
}

// renderStealSelfDomainConf 渲染偷自己 server 的 servers/{domain}.conf:
// 伪装站 location /(按 site_type static/proxy, listen 127.0.0.1:8001)+ 该域名所有 ws location。
// 统一入口 —— 供 SyncWSSNginx / deployTunnelConfig / deployFallbackConfig / HandleSetupSSL / HandleAddWebsite 复用,
// 消除各自渲染导致伪装站与 ws location 互相覆盖的问题(reality偷自己 + WSS 共存的核心)。
func renderStealSelfDomainConf(stealMode, siteType, siteValue, domain, certName string, wssInbounds []wssInboundInfo) (string, error) {
	tplPath := stealSelfDomainTplPath(stealMode, siteType)
	tpl, err := templates.ReadFile(tplPath)
	if err != nil {
		return "", fmt.Errorf("读取 %s 模板失败: %w", tplPath, err)
	}
	conf := strings.ReplaceAll(string(tpl), "{domain}", domain)
	conf = strings.ReplaceAll(conf, "{root_domain}", extractRootDomain(domain))
	conf = strings.ReplaceAll(conf, "{cert_name}", certName)
	staticRoot := siteValue
	if staticRoot == "" {
		staticRoot = "/usr/local/nginx/html"
	}
	conf = strings.ReplaceAll(conf, "{static_root_path}", staticRoot)
	conf = strings.ReplaceAll(conf, "{proxy_pass_server}", siteValue)
	return injectWSLocations(conf, wssInbounds), nil
}
