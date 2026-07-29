package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/templates"
)

func (h *RemoteManageHandler) deployTunnelConfig(ctx context.Context, server *storage.RemoteServer) error {
	domain := strings.ToLower(strings.TrimSpace(server.Domain))
	rootDomain := extractRootDomain(domain)
	proxyDomain := strings.ToLower(strings.TrimSpace(server.PullAddress))

	nginxConf, err := templates.ReadFile("tunnel/nginx.conf")
	if err != nil {
		return fmt.Errorf("读取 tunnel/nginx.conf 模板失败: %w", err)
	}

	certName := "_." + rootDomain
	var selectedCert *storage.Certificate
	if cert, certErr := h.repo.GetCertificateByDomain(ctx, rootDomain, server.ID); certErr == nil && cert != nil {
		certName = certDeployFilename(cert.Domain)
		selectedCert = cert
	}
	// 统一渲染:伪装站 location / + 该 server 现有 ws 入站的 location
	// (reality偷自己 + WSS 共存 —— 下发伪装站时把已有 ws location 一并渲染,避免冲掉)
	domainConf, err := renderStealSelfDomainConf(server.StealMode, server.SiteType, server.SiteValue, domain, certName, h.fetchWSSInbounds(ctx, server.ID))
	if err != nil {
		return err
	}
	if selectedCert != nil && selectedCert.CertPEM != "" && selectedCert.KeyPEM != "" {
		if err := h.deployStealCertificateSync(ctx, server, rootDomain, selectedCert); err != nil {
			return err
		}
		log.Printf("[DeployTunnel] Deployed certificate for %s to server %d", rootDomain, server.ID)
	}

	clearPayload, _ := json.Marshal(map[string]any{"port": 443, "nginx_mode": normalizedRemoteNginxMode(server)})
	if _, err := h.forwardToRemoteServer(ctx, server.ID, http.MethodPost, "/api/child/nginx/clear-stream-port", clearPayload); err != nil {
		return fmt.Errorf("清理 Nginx 443 stream 失败: %w", err)
	}

	sslPayload, _ := json.Marshal(map[string]any{
		"domain":        domain,
		"nginx_config":  string(nginxConf),
		"domain_config": domainConf,
		"nginx_mode":    normalizedRemoteNginxMode(server),
	})
	if _, err := h.forwardToRemoteServer(ctx, server.ID, http.MethodPost, "/api/child/nginx/setup-ssl", sslPayload); err != nil {
		return fmt.Errorf("配置 Nginx SSL 失败: %w", err)
	}
	log.Printf("[DeployTunnel] Deployed nginx config to server %d (%s)", server.ID, server.Name)

	configFile := "tunnel/config.json"
	if proxyDomain == "" || proxyDomain == domain {
		configFile = "tunnel/config_ip.json"
	}
	configTpl, err := templates.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("读取 %s 模板失败: %w", configFile, err)
	}
	configJSON := strings.ReplaceAll(string(configTpl), "{proxy_domain}", proxyDomain)

	var xrayConfig map[string]any
	if err := json.Unmarshal([]byte(configJSON), &xrayConfig); err != nil {
		return fmt.Errorf("解析 Xray 模板配置失败: %w", err)
	}

	// 同机部署时，主控域名路由到 nginx，否则主控 HTTPS 不可达
	if server.IPAddress == "127.0.0.1" {
		if masterDomain := getDomainFromMasterURL(h.repo, ctx); masterDomain != "" && masterDomain != domain {
			h.addWebsiteTunnelConfig(xrayConfig, masterDomain)
		}
	} else {
		// 非主控部署直接使用服务器添加时的domain
		h.addWebsiteTunnelConfig(xrayConfig, domain)
	}

	updatedConfig, _ := json.MarshalIndent(xrayConfig, "", "    ")

	configPayload, _ := json.Marshal(map[string]string{
		"config": string(updatedConfig),
	})
	if _, err := h.forwardToRemoteServer(ctx, server.ID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		return fmt.Errorf("下发 Xray 配置失败: %w", err)
	}
	log.Printf("[DeployTunnel] Deployed xray config to server %d (%s)", server.ID, server.Name)

	if err := h.restartXrayWithRecovery(ctx, server.ID, "DeployTunnel"); err != nil {
		return err
	}

	log.Printf("[DeployTunnel] Completed tunnel config deployment for server %d (%s), domain=%s", server.ID, server.Name, domain)

	// 通知 agent 更新本地 steal_mode
	if h.wsHandler != nil {
		_ = h.wsHandler.SendConfigUpdate(server.ID, map[string]string{"steal_mode": "tunnel"})
	}

	return nil
}

func (h *RemoteManageHandler) deployStealCertificateSync(ctx context.Context, server *storage.RemoteServer, rootDomain string, cert *storage.Certificate) error {
	payload, err := json.Marshal(WSCertDeployPayload{
		Domain:   rootDomain,
		CertPEM:  cert.CertPEM,
		KeyPEM:   cert.KeyPEM,
		CertPath: fmt.Sprintf("/usr/local/nginx/cert/%s.pem", certDeployFilename(cert.Domain)),
		KeyPath:  fmt.Sprintf("/usr/local/nginx/cert/%s.key", certDeployFilename(cert.Domain)),
		Reload:   "none",
	})
	if err != nil {
		return fmt.Errorf("编码证书部署请求失败: %w", err)
	}
	if _, err := h.forwardToRemoteServer(ctx, server.ID, http.MethodPost, "/api/child/cert/deploy", payload); err != nil {
		return fmt.Errorf("同步部署证书失败: %w", err)
	}
	return nil
}
