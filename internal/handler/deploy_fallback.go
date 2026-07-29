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

func (h *RemoteManageHandler) deployFallbackConfig(ctx context.Context, server *storage.RemoteServer) error {
	domain := strings.ToLower(strings.TrimSpace(server.Domain))
	rootDomain := extractRootDomain(domain)

	nginxConf, err := templates.ReadFile("fallback/nginx.conf")
	if err != nil {
		return fmt.Errorf("读取 fallback/nginx.conf 模板失败: %w", err)
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
		log.Printf("[DeployFallback] Deployed certificate for %s to server %d", rootDomain, server.ID)
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
	log.Printf("[DeployFallback] Deployed nginx config to server %d (%s)", server.ID, server.Name)

	configTpl, err := templates.ReadFile("default/config.json")
	if err != nil {
		return fmt.Errorf("读取 default/config.json 模板失败: %w", err)
	}

	configPayload, _ := json.Marshal(map[string]string{
		"config": string(configTpl),
	})
	if _, err := h.forwardToRemoteServer(ctx, server.ID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		return fmt.Errorf("下发 Xray 配置失败: %w", err)
	}
	log.Printf("[DeployFallback] Deployed xray config to server %d (%s)", server.ID, server.Name)

	if err := h.restartXrayWithRecovery(ctx, server.ID, "DeployFallback"); err != nil {
		return err
	}

	log.Printf("[DeployFallback] Completed fallback config deployment for server %d (%s), domain=%s", server.ID, server.Name, domain)

	// 通知 agent 更新本地 steal_mode
	if h.wsHandler != nil {
		_ = h.wsHandler.SendConfigUpdate(server.ID, map[string]string{"steal_mode": "fallback"})
	}

	return nil
}
