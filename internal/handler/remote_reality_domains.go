package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/templates"
)

type realityDomainLatencyProbeRequest struct {
	Domains   []string `json:"domains"`
	TimeoutMs int      `json:"timeout_ms,omitempty"`
}

type realityDomainLatencyProbeResult struct {
	Domain       string `json:"domain"`
	Target       string `json:"target"`
	Success      bool   `json:"success"`
	LatencyMs    int64  `json:"latency_ms,omitempty"`
	Error        string `json:"error,omitempty"`
	NginxSSLPort int    `json:"nginx_ssl_port,omitempty"`
}

type realityDomainLatencyProbeResponse struct {
	Success bool                              `json:"success"`
	Results []realityDomainLatencyProbeResult `json:"results"`
	Message string                            `json:"message,omitempty"`
	Error   string                            `json:"error,omitempty"`
}

type domainServerInfo struct {
	ServerID   int64  `json:"server_id"`
	ServerName string `json:"server_name"`
	Domain     string `json:"domain"`
}

// 返回由所选远程服务器探测的域延迟结果（低 -> 高）。
func (h *RemoteManageHandler) HandleRealityDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverIDStr := r.URL.Query().Get("server_id")
	if serverIDStr == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}
	serverID, err := strconv.ParseInt(serverIDStr, 10, 64)
	if err != nil || serverID <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	timeoutMs := 2000
	if timeoutStr := r.URL.Query().Get("timeout_ms"); timeoutStr != "" {
		if parsed, parseErr := strconv.Atoi(timeoutStr); parseErr == nil {
			if parsed < 200 {
				parsed = 200
			}
			if parsed > 10000 {
				parsed = 10000
			}
			timeoutMs = parsed
		}
	}

	candidates, domainServerMap, err := h.collectRealityDomainCandidates(r.Context())
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to collect domain candidates: %v", err))
		return
	}

	if len(candidates) == 0 {
		remoteWriteJSON(w, http.StatusOK, map[string]any{
			"success":          true,
			"message":          "未在服务器配置中找到可用域名",
			"probe_server_id":  serverID,
			"total_candidates": 0,
			"domains":          []realityDomainLatencyProbeResult{},
		})
		return
	}

	// 通过 WebSocket 进行探测（代理在远程服务器上本地运行探测）
	var probeResults []realityDomainLatencyProbeResult

	if h.wsHandler != nil {
		wsResult, err := h.wsHandler.SendDomainLatencyProbe(serverID, candidates, timeoutMs)
		if err != nil {
			log.Printf("[Remote Manage] WebSocket probe failed for server %d, falling back to HTTP: %v", serverID, err)
		} else if wsResult != nil && wsResult.Success {
			for _, r := range wsResult.Results {
				probeResults = append(probeResults, realityDomainLatencyProbeResult{
					Domain:       r.Domain,
					Target:       r.Target,
					Success:      r.Success,
					LatencyMs:    r.LatencyMs,
					Error:        r.Error,
					NginxSSLPort: int(r.NginxSSLPort),
				})
			}
		}
	}

	// 如果 WebSocket 探测未产生结果，则回退到 HTTP 转发
	if len(probeResults) == 0 {
		reqPayload := realityDomainLatencyProbeRequest{
			Domains:   candidates,
			TimeoutMs: timeoutMs,
		}
		body, err := json.Marshal(reqPayload)
		if err != nil {
			remoteWriteError(w, http.StatusInternalServerError, "failed to build probe request")
			return
		}

		result, err := h.forwardToRemoteServer(r.Context(), serverID, http.MethodPost, "/api/child/domains/latency", body)
		if err != nil {
			failedResults := make([]realityDomainLatencyProbeResult, 0, len(candidates))
			for _, d := range candidates {
				failedResults = append(failedResults, realityDomainLatencyProbeResult{
					Domain:  d,
					Target:  d + ":443",
					Success: false,
					Error:   err.Error(),
				})
			}
			remoteWriteJSON(w, http.StatusOK, map[string]any{
				"success":          true,
				"probe_server_id":  serverID,
				"total_candidates": len(candidates),
				"domains":          failedResults,
				"domain_servers":   domainServerMap,
				"warning":          fmt.Sprintf("探测失败: %v", err),
			})
			return
		}

		var probeResp realityDomainLatencyProbeResponse
		if err := json.Unmarshal(result, &probeResp); err != nil {
			remoteWriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to parse probe response: %v", err))
			return
		}

		if !probeResp.Success {
			if probeResp.Error != "" {
				remoteWriteError(w, http.StatusBadGateway, probeResp.Error)
				return
			}
			remoteWriteError(w, http.StatusBadGateway, "domain probe failed")
			return
		}

		probeResults = probeResp.Results
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":          true,
		"probe_server_id":  serverID,
		"total_candidates": len(candidates),
		"domains":          probeResults,
		"domain_servers":   domainServerMap,
	})
}

func (h *RemoteManageHandler) collectRealityDomainCandidates(ctx context.Context) ([]string, map[string]domainServerInfo, error) {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, nil, err
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, 64)
	domainServerMap := make(map[string]domainServerInfo)

	if masterDomain := getDomainFromMasterURL(h.repo, ctx); masterDomain != "" {
		if d := normalizeDomainCandidate(masterDomain); d != "" {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}

	customJSON, _ := h.repo.GetSystemSetting(ctx, "reality_domains")
	if customJSON != "" {
		var customDomains []string
		if json.Unmarshal([]byte(customJSON), &customDomains) == nil {
			for _, raw := range customDomains {
				if d := normalizeDomainCandidate(raw); d != "" {
					if _, exists := seen[d]; !exists {
						seen[d] = struct{}{}
						out = append(out, d)
					}
				}
			}
		}
	}

	for _, server := range servers {
		serverDomainSources := []string{server.Domain, server.PullAddress}
		for _, source := range serverDomainSources {
			if source == "" {
				continue
			}
			for _, raw := range strings.Split(source, ",") {
				d := normalizeDomainCandidate(raw)
				if d == "" {
					continue
				}
				if _, exists := seen[d]; !exists {
					seen[d] = struct{}{}
					out = append(out, d)
				}
				domainServerMap[d] = domainServerInfo{
					ServerID:   server.ID,
					ServerName: server.Name,
					Domain:     d,
				}
			}
		}

		if server.Status != "connected" {
			continue
		}

		result, err := h.forwardToRemoteServer(ctx, server.ID, http.MethodGet, "/api/child/inbounds", nil)
		if err != nil {
			log.Printf("[Remote Manage] Skip domain collection for server %d (%s): %v", server.ID, server.Name, err)
			continue
		}

		var inboundsResp struct {
			Success  bool                     `json:"success"`
			Inbounds []map[string]interface{} `json:"inbounds"`
		}
		if err := json.Unmarshal(result, &inboundsResp); err != nil {
			log.Printf("[Remote Manage] Invalid inbounds response from server %d (%s): %v", server.ID, server.Name, err)
			continue
		}
		if !inboundsResp.Success {
			continue
		}

		for _, inbound := range inboundsResp.Inbounds {
			extractDomainsFromInbound(inbound, seen, &out)
		}
	}

	sort.Strings(out)
	return out, domainServerMap, nil
}

// 配置 nginx SSL (443) + 在远程服务器上部署证书。
func (h *RemoteManageHandler) HandleSetupSSL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil || id <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	ctx, release, err := h.repo.AcquireRemoteServerMutationLease(r.Context(), id)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}
	defer release()

	server, err := h.repo.GetRemoteServer(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}
	if server.Domain == "" {
		remoteWriteError(w, http.StatusBadRequest, "服务器未配置域名")
		return
	}

	domain := strings.ToLower(strings.TrimSpace(server.Domain))

	// 提取通配符证书的根域（例如 us1.example.com -> example.com）
	rootDomain := extractRootDomain(domain)

	// 步骤1：读取nginx.conf基本模板（无需域替换）
	nginxTplPath := "tunnel/nginx.conf"
	if server.StealMode == "fallback" {
		nginxTplPath = "fallback/nginx.conf"
	}
	nginxConf, readErr := templates.ReadFile(nginxTplPath)
	if readErr != nil {
		remoteWriteError(w, http.StatusInternalServerError, fmt.Sprintf("读取 nginx.conf 模板失败: %v", readErr))
		return
	}

	if h.certHandler == nil {
		remoteWriteJSON(w, http.StatusConflict, map[string]any{
			"success":       false,
			"partial":       false,
			"cert_deployed": false,
			"error":         "证书功能未初始化",
			"message":       "证书功能未初始化",
		})
		return
	}
	cert, certErr := h.findCertificateForRemoteDomain(ctx, domain, id)
	if certErr != nil {
		message := fmt.Sprintf("未找到可部署的 %s 证书: %v", rootDomain, certErr)
		remoteWriteJSON(w, http.StatusConflict, map[string]any{
			"success":       false,
			"partial":       false,
			"cert_deployed": false,
			"error":         message,
			"message":       message,
		})
		return
	}
	certName := certDeployFilename(cert.Domain)
	// 第2步：统一渲染 domain conf(伪装站 location / + 该 server 现有 ws location,reality偷自己+WSS 共存)
	wssInbounds, wssErr := h.fetchWSSInboundsStrict(ctx, id)
	if wssErr != nil {
		remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("读取 WSS 入站失败: %v", wssErr))
		return
	}
	domainConf, derr := renderStealSelfDomainConf(server.StealMode, server.SiteType, server.SiteValue, domain, certName, wssInbounds)
	if derr != nil {
		remoteWriteError(w, http.StatusInternalServerError, fmt.Sprintf("渲染 domain.conf 失败: %v", derr))
		return
	}

	// 先同步落盘证书，再让 setup-ssl 写入引用它的 nginx 配置并重载。
	// 这样首次配置时不会因证书文件尚不存在而 reload 失败。
	certPayload := WSCertDeployPayload{
		Domain:   rootDomain,
		CertPEM:  cert.CertPEM,
		KeyPEM:   cert.KeyPEM,
		CertPath: fmt.Sprintf("/usr/local/nginx/cert/%s.pem", certName),
		KeyPath:  fmt.Sprintf("/usr/local/nginx/cert/%s.key", certName),
		Reload:   "none",
	}
	if err := h.certHandler.deployToRemoteServerSync(ctx, server, certPayload); err != nil {
		message := fmt.Sprintf("证书部署未获得 Agent ACK: %v", err)
		remoteWriteJSON(w, http.StatusConflict, map[string]any{
			"success":       false,
			"partial":       true,
			"cert_deployed": false,
			"error":         message,
			"message":       message,
		})
		return
	}

	sslPayload, marshalErr := json.Marshal(map[string]any{
		"domain":        domain,
		"nginx_config":  string(nginxConf),
		"domain_config": domainConf,
		"nginx_mode":    normalizedRemoteNginxMode(server),
	})
	if marshalErr != nil {
		remoteWriteError(w, http.StatusInternalServerError, fmt.Sprintf("序列化 nginx 配置失败: %v", marshalErr))
		return
	}
	_, err = h.forwardToRemoteServer(ctx, id, http.MethodPost, "/api/child/nginx/setup-ssl", sslPayload)
	if err != nil {
		message := fmt.Sprintf("证书已部署，但配置 Nginx SSL 失败: %v", err)
		remoteWriteJSON(w, http.StatusConflict, map[string]any{
			"success":       false,
			"partial":       true,
			"cert_deployed": true,
			"error":         message,
			"message":       message,
		})
		return
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":       true,
		"message":       fmt.Sprintf("已为 %s 配置 SSL", domain),
		"cert_deployed": true,
	})
}

// findCertificateForRemoteDomain verifies the actual certificate SANs against
// the complete server hostname. The database domain is only an index/label and
// must not be treated as proof that a certificate covers a child hostname.
func (h *RemoteManageHandler) findCertificateForRemoteDomain(ctx context.Context, hostname string, serverID int64) (*storage.Certificate, error) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	certificates, err := h.repo.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	owners := []int64{serverID}
	if serverID != 0 {
		owners = append(owners, 0)
	}
	now := time.Now()
	for _, owner := range owners {
		// Prefer an exact record, then a syntactically matching wildcard record,
		// then any multi-SAN certificate that x509 confirms covers the hostname.
		for matchKind := 0; matchKind < 3; matchKind++ {
			for index := range certificates {
				cert := &certificates[index]
				if cert.RemoteServerID != owner || cert.Status != storage.CertStatusValid {
					continue
				}
				if cert.ExpiryDate != nil && !cert.ExpiryDate.After(now) {
					continue
				}
				recordDomain := strings.ToLower(strings.TrimSpace(cert.Domain))
				recordKind := 2
				if recordDomain == hostname {
					recordKind = 0
				} else if strings.HasPrefix(recordDomain, "*.") && certificateNameCoversHostname(recordDomain, hostname) {
					recordKind = 1
				}
				if recordKind != matchKind || !certificateCoversHostname(cert.CertPEM, cert.KeyPEM, hostname, now) {
					continue
				}
				return cert, nil
			}
		}
	}
	return nil, storage.ErrCertificateNotFound
}

// 将 nginx.conf + domain.conf + config.json 部署到远程服务器。
func (h *RemoteManageHandler) HandleDeployStealSelfConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil || id <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	// 使用独立 context：steal-self 部署会清理 nginx 443 端口，可能导致反代连接中断、请求 context 被取消
	deployCtx, deployCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 60*time.Second)
	defer deployCancel()
	if err := h.DeployStealSelfConfig(deployCtx, id); err != nil {
		remoteWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "配置下发成功",
	})
}

// DeployStealSelfConfig 将配置部署到远程服务器，根据 steal_mode 选择对应配置:
//   - "fallback":需要 domain,下发 fallback 模板
//   - "tunnel":需要 domain,下发 tunnel 模板
//   - "default" / 空值:下发主控内嵌的 default/config.json 模板,无需 domain
//
// 历史 BUG:之前 if/else 只识别 fallback,其它(含 default、空)统统走 tunnel,
// 用户选了"默认"部署模式但 deployStealSelf 实际下发的是 tunnel 配置。
func (h *RemoteManageHandler) DeployStealSelfConfig(ctx context.Context, serverID int64) error {
	return h.repo.WithRemoteServerMutationLease(ctx, serverID, func(leasedCtx context.Context) error {
		return h.deployStealSelfConfigLeased(leasedCtx, serverID)
	})
}

func (h *RemoteManageHandler) deployStealSelfConfigLeased(ctx context.Context, serverID int64) error {
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("获取服务器信息失败: %w", err)
	}

	switch server.StealMode {
	case "fallback":
		if server.Domain == "" {
			return fmt.Errorf("fallback 模式需要先配置域名")
		}
		return h.deployFallbackConfig(ctx, server)
	case "tunnel":
		if server.Domain == "" {
			return fmt.Errorf("tunnel 模式需要先配置域名")
		}
		return h.deployTunnelConfig(ctx, server)
	default:
		// default / 空值都走主控内嵌默认模板。用户主动触发不跳过 has-config 检查
		// (跳过是为"全新装机自动下发"防覆盖业务,用户手动点这里说明就是要覆盖)。
		return h.deployDefaultConfigManual(ctx, serverID)
	}
}

// deployDefaultConfigManual 是 deployDefaultConfig 的"用户主动模式":不做 has-config 检查,
// 直接覆盖 agent 当前 xray 配置为内嵌默认模板,然后重启 xray。
func (h *RemoteManageHandler) deployDefaultConfigManual(ctx context.Context, serverID int64) error {
	configTpl, err := templates.ReadFile("default/config.json")
	if err != nil {
		return fmt.Errorf("读取默认配置模板: %w", err)
	}
	configPayload, _ := json.Marshal(map[string]string{"config": string(configTpl)})
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		return fmt.Errorf("下发默认配置: %w", err)
	}
	if err := h.restartXrayWithRecovery(ctx, serverID, "ManualDeployDefault"); err != nil {
		return fmt.Errorf("重启 xray: %w", err)
	}
	return nil
}

func extractDomainsFromInbound(inbound map[string]interface{}, seen map[string]struct{}, out *[]string) {
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})
	if streamSettings == nil {
		return
	}

	if realitySettings, _ := streamSettings["realitySettings"].(map[string]interface{}); realitySettings != nil {
		if target, ok := realitySettings["target"].(string); ok {
			addDomainCandidate(target, seen, out)
		}
		// Xray used dest as the legacy alias for target. Keep reading it so
		// existing inbounds remain discoverable after the field migration.
		if dest, ok := realitySettings["dest"].(string); ok {
			addDomainCandidate(dest, seen, out)
		}

		switch v := realitySettings["serverNames"].(type) {
		case []interface{}:
			for _, item := range v {
				if name, ok := item.(string); ok {
					addDomainCandidate(name, seen, out)
				}
			}
		case string:
			for _, item := range strings.Split(v, ",") {
				addDomainCandidate(item, seen, out)
			}
		}
	}

	if tlsSettings, _ := streamSettings["tlsSettings"].(map[string]interface{}); tlsSettings != nil {
		if serverName, ok := tlsSettings["serverName"].(string); ok {
			addDomainCandidate(serverName, seen, out)
		}
	}
}

func addDomainCandidate(raw string, seen map[string]struct{}, out *[]string) {
	domain := normalizeDomainCandidate(raw)
	if domain == "" {
		return
	}
	if _, exists := seen[domain]; exists {
		return
	}
	seen[domain] = struct{}{}
	*out = append(*out, domain)
}

func normalizeDomainCandidate(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	if strings.Contains(s, "://") {
		if idx := strings.Index(s, "://"); idx >= 0 && idx+3 < len(s) {
			s = s[idx+3:]
		}
	}
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}

	s = strings.TrimSpace(strings.Trim(s, "[]"))
	if s == "" {
		return ""
	}

	if host, port, err := net.SplitHostPort(s); err == nil {
		if host != "" && port != "" {
			s = host
		}
	} else {
		if idx := strings.LastIndex(s, ":"); idx > 0 && idx < len(s)-1 {
			if _, err := strconv.Atoi(s[idx+1:]); err == nil {
				s = s[:idx]
			}
		}
	}

	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "*."))
	if s == "" {
		return ""
	}

	// 仅保留域名；跳过纯 IP 候选者。
	if net.ParseIP(s) != nil {
		return ""
	}
	return s
}

// extractRootDomain 从子域返回根域。
// 例如“us1.example.com”->“example.com”，“example.com”->“example.com”
func extractRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (h *RemoteManageHandler) HandleAddCustomRealityDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Domain   string `json:"domain"`
		ServerID int64  `json:"server_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid request")
		return
	}

	domain := normalizeDomainCandidate(req.Domain)
	if domain == "" {
		remoteWriteError(w, http.StatusBadRequest, "域名不能为空")
		return
	}

	ctx := r.Context()

	var existing []string
	if raw, _ := h.repo.GetSystemSetting(ctx, "reality_domains"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &existing)
	}
	found := false
	for _, d := range existing {
		if d == domain {
			found = true
			break
		}
	}
	if !found {
		existing = append(existing, domain)
		if data, err := json.Marshal(existing); err == nil {
			_ = h.repo.SetSystemSetting(ctx, "reality_domains", string(data))
		}
	}

	result := map[string]any{
		"success":    true,
		"domain":     domain,
		"latency_ms": nil,
		"saved":      !found,
	}

	if req.ServerID > 0 && h.wsHandler != nil {
		wsResult, err := h.wsHandler.SendDomainLatencyProbe(req.ServerID, []string{domain}, 2000)
		if err == nil && wsResult != nil && wsResult.Success && len(wsResult.Results) > 0 {
			r := wsResult.Results[0]
			result["success"] = r.Success
			result["latency_ms"] = r.LatencyMs
			result["target"] = r.Target
			result["error"] = r.Error
			result["nginx_ssl_port"] = r.NginxSSLPort
		} else if err != nil {
			result["error"] = err.Error()
		}
	}

	remoteWriteJSON(w, http.StatusOK, result)
}

func (h *RemoteManageHandler) HandleDeleteCustomRealityDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid request")
		return
	}

	domain := normalizeDomainCandidate(req.Domain)
	if domain == "" {
		remoteWriteError(w, http.StatusBadRequest, "域名不能为空")
		return
	}

	ctx := r.Context()
	var existing []string
	if raw, _ := h.repo.GetSystemSetting(ctx, "reality_domains"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &existing)
	}

	filtered := make([]string, 0, len(existing))
	for _, d := range existing {
		if d != domain {
			filtered = append(filtered, d)
		}
	}

	if data, err := json.Marshal(filtered); err == nil {
		_ = h.repo.SetSystemSetting(ctx, "reality_domains", string(data))
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{"success": true, "message": "已删除"})
}
