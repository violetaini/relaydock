package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/acme"
	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/dnscredentials"
	"github.com/violetaini/relaydock/internal/storage"
)

// CertificateHandler 处理证书管理 API 端点。

// certDeployFilename 根据证书域名生成部署文件名。
// 泛域名 *.example.com → _.example.com，单域名保持原样。
func certDeployFilename(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return "_." + domain[2:]
	}
	return domain
}

// certDeployPaths 根据证书域名和基础目录生成部署路径。
func certDeployPaths(domain, dir string) (certPath, keyPath string) {
	name := certDeployFilename(domain)
	return filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
}

type CertificateHandler struct {
	repo               *storage.TrafficRepository
	wsHandler          *RemoteWSHandler
	acmeClient         certificateACMEClient
	onMasterURLChanged func(ctx context.Context, newURL string)
	remoteManage       *RemoteManageHandler // 联邦(分享)服务器证书下发时,复用其 ForwardToAgent 走拥有方主控
	localDeployer      func(certPEM, keyPEM, certPath, keyPath, reloadTarget string) error
	managedXrayRestart func(ctx context.Context, serverID int64, logPrefix string) error
	renewals           sync.Map // certificate ID -> in-flight marker
	xrayCertSyncMu     sync.Mutex
	xrayCertSynced     sync.Map // "serverID:certID" -> certificate material fingerprint
}

type certificateACMEClient interface {
	ObtainCertificateV2(context.Context, acme.CertRequest) (*acme.CertResult, error)
	RenewCertificateV2(context.Context, acme.CertRequest, string, string) (*acme.CertResult, error)
	ProcessCertResult(string, []byte, []byte) (*acme.CertResult, error)
}

func (h *CertificateHandler) SetOnMasterURLChanged(fn func(ctx context.Context, newURL string)) {
	h.onMasterURLChanged = fn
}

// SetRemoteManage 注入 RemoteManageHandler,用于把证书下发转发到联邦(分享)服务器的拥有方主控。
func (h *CertificateHandler) SetRemoteManage(rm *RemoteManageHandler) {
	h.remoteManage = rm
}

// SetLocalDeployer injects child-mode service serialization for certificates
// deployed on this host. Remote certificate delivery continues through Agent.
func (h *CertificateHandler) SetLocalDeployer(deployer func(certPEM, keyPEM, certPath, keyPath, reloadTarget string) error) {
	h.localDeployer = deployer
}

func (h *CertificateHandler) deployLocal(certPEM, keyPEM, certPath, keyPath, reloadTarget string) error {
	if h.localDeployer != nil {
		return h.localDeployer(certPEM, keyPEM, certPath, keyPath, reloadTarget)
	}
	return acme.Deploy(certPEM, keyPEM, certPath, keyPath, reloadTarget)
}

func (h *CertificateHandler) beginRenewal(certID int64) bool {
	if certID <= 0 {
		return false
	}
	_, loaded := h.renewals.LoadOrStore(certID, struct{}{})
	return !loaded
}

func (h *CertificateHandler) finishRenewal(certID int64) {
	h.renewals.Delete(certID)
}

func (h *CertificateHandler) appendCertificateLogDurable(certID int64, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.repo.AppendCertificateLog(ctx, certID, message); err != nil {
		log.Printf("[Certificate] append log for certificate %d: %v", certID, err)
	}
}

func (h *CertificateHandler) updateCertificateStatusDurable(certID int64, status, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return h.repo.UpdateCertificateStatus(ctx, certID, status, message)
}

// 创建一个新的CertificateHandler。
func NewCertificateHandler(repo *storage.TrafficRepository, wsHandler *RemoteWSHandler) *CertificateHandler {
	h := &CertificateHandler{
		repo:       repo,
		wsHandler:  wsHandler,
		acmeClient: acme.NewClient(),
	}
	// 注册来自远程服务器的证书更新回调
	if wsHandler != nil {
		wsHandler.SetCertUpdateHandler(h.HandleCertUpdate)
	}
	return h
}

// CertificateRequest 表示创建或更新证书的请求。
type CertificateRequest struct {
	Domain         string `json:"domain"`
	Email          string `json:"email"`
	RemoteServerID int64  `json:"remote_server_id"` // 0 = 主控
	Provider       string `json:"provider"`         // 详见上下文
	ChallengeMode  string `json:"challenge_mode"`   // 独立 |网站根目录 |域名系统
	WebrootPath    string `json:"webroot_path"`     // 仅适用于 webroot 模式
	AutoRenew      bool   `json:"auto_renew"`
	DNSProviderID  int64  `json:"dns_provider_id"` // 参考 dns_providers 表
	DeployTarget   string `json:"deploy_target"`   // 无、nginx、xray、两者
	DeployCertPath string `json:"deploy_cert_path"`
	DeployKeyPath  string `json:"deploy_key_path"`
	AutoDeploy     bool   `json:"auto_deploy"`
}

// CertificateResponse 表示 API 响应中的证书。
type CertificateResponse struct {
	ID               int64    `json:"id"`
	Domain           string   `json:"domain"`
	Email            string   `json:"email"`
	Provider         string   `json:"provider"`
	CertPath         string   `json:"cert_path"`
	KeyPath          string   `json:"key_path"`
	Status           string   `json:"status"`
	DNSNames         []string `json:"dns_names,omitempty"`
	ExpiryDate       *string  `json:"expiry_date"`
	IssueDate        *string  `json:"issue_date"`
	AutoRenew        bool     `json:"auto_renew"`
	ChallengeMode    string   `json:"challenge_mode"`
	WebrootPath      string   `json:"webroot_path,omitempty"`
	RemoteServerID   int64    `json:"remote_server_id"`
	RemoteServerName string   `json:"remote_server_name,omitempty"`
	Message          string   `json:"message,omitempty"`
	DNSProviderID    int64    `json:"dns_provider_id"`
	DeployTarget     string   `json:"deploy_target"`
	DeployCertPath   string   `json:"deploy_cert_path,omitempty"`
	DeployKeyPath    string   `json:"deploy_key_path,omitempty"`
	AutoDeploy       bool     `json:"auto_deploy"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
}

// ListCertificatesResponse 表示列出证书的响应。
type ListCertificatesResponse struct {
	Success      bool                  `json:"success"`
	Message      string                `json:"message,omitempty"`
	Certificates []CertificateResponse `json:"certificates"`
}

// SingleCertificateResponse 表示具有单个证书的响应。
type SingleCertificateResponse struct {
	Success     bool                 `json:"success"`
	Message     string               `json:"message,omitempty"`
	Certificate *CertificateResponse `json:"certificate,omitempty"`
}

func certificateToResponse(cert *storage.Certificate) CertificateResponse {
	resp := CertificateResponse{
		ID:             cert.ID,
		Domain:         cert.Domain,
		Email:          cert.Email,
		Provider:       cert.Provider,
		CertPath:       cert.CertPath,
		KeyPath:        cert.KeyPath,
		Status:         cert.Status,
		DNSNames:       certificateDNSNames(cert.CertPEM),
		AutoRenew:      cert.AutoRenew,
		ChallengeMode:  cert.ChallengeMode,
		WebrootPath:    cert.WebrootPath,
		RemoteServerID: cert.RemoteServerID,
		Message:        cert.Message,
		DNSProviderID:  cert.DNSProviderID,
		DeployTarget:   cert.DeployTarget,
		DeployCertPath: cert.DeployCertPath,
		DeployKeyPath:  cert.DeployKeyPath,
		AutoDeploy:     cert.AutoDeploy,
		CreatedAt:      cert.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      cert.UpdatedAt.Format(time.RFC3339),
	}
	if cert.ExpiryDate != nil {
		t := cert.ExpiryDate.Format(time.RFC3339)
		resp.ExpiryDate = &t
	}
	if cert.IssueDate != nil {
		t := cert.IssueDate.Format(time.RFC3339)
		resp.IssueDate = &t
	}
	return resp
}

// 检查当前用户是否是管理员
func (h *CertificateHandler) requireAdmin(r *http.Request) bool {
	username := auth.UsernameFromContext(r.Context())
	if username == "" {
		return false
	}
	// 全局 API token 走 auth.RequireToken 之后会得到 "api-token-admin" 虚拟用户名,
	// 该虚拟用户不在 db 里,GetUser 会失败 → 必须短路放行,跟 auth.RequireAdmin 同款行为。
	if username == "api-token-admin" {
		return true
	}
	user, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		return false
	}
	return user.Role == storage.RoleAdmin
}

// 处理 GET /api/admin/certificates
func (h *CertificateHandler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// 检查 server_id 过滤器
	serverIDStr := r.URL.Query().Get("server_id")
	var certs []storage.Certificate
	var err error

	if serverIDStr != "" {
		serverID, parseErr := strconv.ParseInt(serverIDStr, 10, 64)
		if parseErr != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的服务器ID"})
			return
		}
		certs, err = h.repo.ListCertificatesByServer(ctx, serverID)
	} else {
		certs, err = h.repo.ListCertificates(ctx)
	}

	if err != nil {
		log.Printf("[Certificate] ListCertificates error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "获取证书列表失败"})
		return
	}

	// 获取远程服务器名称以进行显示
	serverNames := make(map[int64]string)
	servers, _ := h.repo.ListRemoteServers(ctx)
	for _, s := range servers {
		serverNames[s.ID] = s.Name
	}

	responses := make([]CertificateResponse, len(certs))
	for i, cert := range certs {
		responses[i] = certificateToResponse(&cert)
		if cert.RemoteServerID > 0 {
			responses[i].RemoteServerName = serverNames[cert.RemoteServerID]
		} else {
			responses[i].RemoteServerName = "本地服务器"
		}
	}

	respondJSON(w, http.StatusOK, ListCertificatesResponse{
		Success:      true,
		Certificates: responses,
	})
}

// 处理 GET /api/admin/certificates/{id}
func (h *CertificateHandler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		h.UpdateCertificate(w, r)
		return
	}
	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "message": "不支持的请求方法"})
		return
	}
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/certificates/")
	idStr = strings.Split(idStr, "/")[0]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的证书ID"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	cert, err := h.repo.GetCertificate(ctx, id)
	if err != nil {
		if err == storage.ErrCertificateNotFound {
			respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "证书不存在"})
			return
		}
		log.Printf("[Certificate] GetCertificate error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "获取证书失败"})
		return
	}

	resp := certificateToResponse(cert)
	if cert.RemoteServerID > 0 {
		server, _ := h.repo.GetRemoteServer(ctx, cert.RemoteServerID)
		if server != nil {
			resp.RemoteServerName = server.Name
		}
	} else {
		resp.RemoteServerName = "本地服务器"
	}

	respondJSON(w, http.StatusOK, SingleCertificateResponse{
		Success:     true,
		Certificate: &resp,
	})
}

// UpdateCertificate edits certificate automation metadata. It does not issue a
// certificate; the new provider and challenge settings apply on the next renewal.
func (h *CertificateHandler) UpdateCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/certificates/")
	idStr = strings.Split(idStr, "/")[0]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的证书ID"})
		return
	}

	var req CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的请求数据"})
		return
	}
	req.Domain = strings.TrimSpace(req.Domain)
	req.Email = strings.TrimSpace(req.Email)
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.ChallengeMode = strings.ToLower(strings.TrimSpace(req.ChallengeMode))
	req.WebrootPath = strings.TrimSpace(req.WebrootPath)
	req.DeployTarget = strings.ToLower(strings.TrimSpace(req.DeployTarget))
	req.DeployCertPath = strings.TrimSpace(req.DeployCertPath)
	req.DeployKeyPath = strings.TrimSpace(req.DeployKeyPath)

	if req.Domain == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "域名不能为空"})
		return
	}
	if req.Provider != acme.CALetsEncrypt && req.Provider != acme.CALetsEncryptStaging && req.Provider != "manual" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "不支持的证书颁发机构"})
		return
	}
	if req.Provider != "manual" && req.Email == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "ACME 证书的联系邮箱不能为空"})
		return
	}
	switch req.ChallengeMode {
	case storage.CertChallengeDNS:
		if req.DNSProviderID <= 0 {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "DNS-01 验证必须选择 DNS 提供商"})
			return
		}
	case storage.CertChallengeWebroot:
		if req.WebrootPath == "" {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "网站根目录不能为空"})
			return
		}
		req.DNSProviderID = 0
	case storage.CertChallengeStandalone:
		req.DNSProviderID = 0
	case "manual":
		if req.Provider != "manual" {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "ACME 证书不能使用手动验证方式"})
			return
		}
		req.DNSProviderID = 0
		req.WebrootPath = ""
		req.AutoRenew = false
	default:
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "不支持的验证方式"})
		return
	}
	if req.Provider == "manual" && req.ChallengeMode != "manual" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "手动上传证书不能配置 ACME 验证方式"})
		return
	}
	if req.Provider != "manual" && strings.Contains(req.Domain, "*") && req.ChallengeMode != storage.CertChallengeDNS {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "泛域名证书必须使用 DNS-01 验证"})
		return
	}
	switch req.DeployTarget {
	case "", "none":
		req.DeployTarget = "none"
		req.DeployCertPath = ""
		req.DeployKeyPath = ""
		req.AutoDeploy = false
	case "nginx", "xray", "both":
		if req.DeployCertPath == "" || req.DeployKeyPath == "" {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "自动部署必须填写证书和私钥路径"})
			return
		}
	default:
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "不支持的部署目标"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	cert, err := h.repo.GetCertificate(ctx, id)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "证书不存在"})
		return
	}
	if cert.CertPEM != "" {
		if req.Domain != cert.Domain {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "已签发证书不能修改域名，请为新域名单独申请证书"})
			return
		}
		if req.Provider != cert.Provider {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "已签发证书不能直接修改颁发机构；可在重新申请时选择其他机构"})
			return
		}
	}
	if req.ChallengeMode == storage.CertChallengeDNS {
		if _, err := h.repo.GetDNSProvider(ctx, req.DNSProviderID); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "所选 DNS 提供商不存在，请重新选择"})
			return
		}
	}

	cert.Domain = req.Domain
	cert.Email = req.Email
	cert.Provider = req.Provider
	cert.AutoRenew = req.AutoRenew
	cert.ChallengeMode = req.ChallengeMode
	cert.WebrootPath = req.WebrootPath
	cert.DNSProviderID = req.DNSProviderID
	cert.DeployTarget = req.DeployTarget
	cert.DeployCertPath = req.DeployCertPath
	cert.DeployKeyPath = req.DeployKeyPath
	cert.AutoDeploy = req.AutoDeploy
	if err := h.repo.UpdateCertificate(ctx, cert); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			respondJSON(w, http.StatusConflict, map[string]any{"success": false, "message": "该域名的证书记录已存在"})
			return
		}
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "更新证书记录失败"})
		return
	}
	resp := certificateToResponse(cert)
	respondJSON(w, http.StatusOK, SingleCertificateResponse{
		Success:     true,
		Message:     "证书设置已更新，将在下次续期或部署时生效",
		Certificate: &resp,
	})
}

// 处理 POST /api/admin/certificates
func (h *CertificateHandler) CreateCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	var req CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的请求数据"})
		return
	}

	req.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	req.Email = strings.TrimSpace(req.Email)
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.ChallengeMode = strings.ToLower(strings.TrimSpace(req.ChallengeMode))
	req.WebrootPath = strings.TrimSpace(req.WebrootPath)
	req.DeployTarget = strings.ToLower(strings.TrimSpace(req.DeployTarget))
	req.DeployCertPath = strings.TrimSpace(req.DeployCertPath)
	req.DeployKeyPath = strings.TrimSpace(req.DeployKeyPath)

	if req.Domain == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "域名不能为空"})
		return
	}
	if req.Email == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "邮箱不能为空"})
		return
	}

	if req.Provider == "" {
		req.Provider = acme.CALetsEncrypt
	}
	if req.ChallengeMode == "" {
		req.ChallengeMode = storage.CertChallengeStandalone
	}
	if req.Provider != acme.CALetsEncrypt && req.Provider != acme.CALetsEncryptStaging {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "不支持的证书颁发机构"})
		return
	}
	baseDomain := strings.TrimPrefix(strings.ToLower(req.Domain), "*.")
	if !validManagedDNSName(baseDomain) || (strings.Contains(req.Domain, "*") && !strings.HasPrefix(req.Domain, "*.")) {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "域名格式无效"})
		return
	}
	switch req.ChallengeMode {
	case storage.CertChallengeDNS:
		if req.DNSProviderID <= 0 {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "DNS-01 验证必须选择 DNS 提供商"})
			return
		}
	case storage.CertChallengeWebroot:
		if req.WebrootPath == "" {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "网站根目录不能为空"})
			return
		}
		req.DNSProviderID = 0
	case storage.CertChallengeStandalone:
		req.DNSProviderID = 0
	default:
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "不支持的验证方式"})
		return
	}
	if strings.HasPrefix(req.Domain, "*.") && req.ChallengeMode != storage.CertChallengeDNS {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "泛域名证书必须使用 DNS-01 验证"})
		return
	}
	switch req.DeployTarget {
	case "", "none":
		req.DeployTarget = "none"
		req.DeployCertPath = ""
		req.DeployKeyPath = ""
		req.AutoDeploy = false
	case "nginx", "xray", "both":
		if req.DeployCertPath == "" || req.DeployKeyPath == "" {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "自动部署必须填写证书和私钥路径"})
			return
		}
	default:
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "不支持的部署目标"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if req.ChallengeMode == storage.CertChallengeDNS {
		if _, err := h.repo.GetDNSProvider(ctx, req.DNSProviderID); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "所选 DNS 提供商不存在"})
			return
		}
	}
	if req.RemoteServerID > 0 {
		if _, err := h.repo.GetRemoteServer(ctx, req.RemoteServerID); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "目标服务器不存在"})
			return
		}
	}

	// 检查现有证书
	existing, err := h.repo.GetCertificateByDomain(ctx, req.Domain, req.RemoteServerID)
	if err == nil && existing != nil {
		respondJSON(w, http.StatusConflict, map[string]any{"success": false, "message": "该域名的证书已存在"})
		return
	}

	// 先创建证书记录
	cert := &storage.Certificate{
		Domain:         req.Domain,
		Email:          req.Email,
		Provider:       req.Provider,
		Status:         storage.CertStatusPending,
		AutoRenew:      req.AutoRenew,
		ChallengeMode:  req.ChallengeMode,
		WebrootPath:    req.WebrootPath,
		RemoteServerID: req.RemoteServerID,
		DNSProviderID:  req.DNSProviderID,
		DeployTarget:   req.DeployTarget,
		DeployCertPath: req.DeployCertPath,
		DeployKeyPath:  req.DeployKeyPath,
		AutoDeploy:     req.AutoDeploy,
	}

	if err := h.repo.CreateCertificate(ctx, cert); err != nil {
		if err == storage.ErrCertificateExists {
			respondJSON(w, http.StatusConflict, map[string]any{"success": false, "message": "该域名的证书已存在"})
			return
		}
		log.Printf("[Certificate] CreateCertificate error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "创建证书记录失败"})
		return
	}

	if !h.beginRenewal(cert.ID) {
		_ = h.repo.UpdateCertificateStatus(ctx, cert.ID, storage.CertStatusFailed, "证书申请状态冲突，请重试")
		respondJSON(w, http.StatusConflict, map[string]any{"success": false, "message": "证书申请正在处理中，请勿重复提交"})
		return
	}

	if req.RemoteServerID == 0 {
		// 本地证书请求
		go func() {
			defer h.finishRenewal(cert.ID)
			h.requestLocalCertificate(cert)
		}()
		respondJSON(w, http.StatusAccepted, SingleCertificateResponse{
			Success:     true,
			Message:     "证书申请已提交，正在处理中...",
			Certificate: &CertificateResponse{ID: cert.ID, Domain: cert.Domain, Status: storage.CertStatusPending},
		})
	} else {
		// 通过WebSocket远程证书请求
		go func() {
			defer h.finishRenewal(cert.ID)
			h.requestRemoteCertificate(cert)
		}()
		respondJSON(w, http.StatusAccepted, SingleCertificateResponse{
			Success:     true,
			Message:     "证书申请已发送到远程服务器...",
			Certificate: &CertificateResponse{ID: cert.ID, Domain: cert.Domain, Status: storage.CertStatusPending},
		})
	}
}

// 使用 ACME 在本地请求证书。
func (h *CertificateHandler) requestLocalCertificate(cert *storage.Certificate) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	appendLog := func(msg string) { h.appendCertificateLogDurable(cert.ID, msg) }

	appendLog("开始申请证书: " + cert.Domain)

	certReq, err := h.buildCertRequest(ctx, cert)
	if err != nil {
		log.Printf("[Certificate] buildCertRequest failed for %s: %v", cert.Domain, err)
		appendLog("构建请求失败: " + err.Error())
		_ = h.updateCertificateStatusDurable(cert.ID, storage.CertStatusFailed, err.Error())
		return
	}

	appendLog(fmt.Sprintf("验证方式: %s, CA: %s", certReq.ChallengeMode, certReq.Provider))
	if certReq.ChallengeMode == "dns" {
		appendLog("DNS 提供商: " + certReq.DNSProvider)
	}
	appendLog("正在向 CA 请求证书...")

	result, err := h.acmeClient.ObtainCertificateV2(ctx, certReq)
	if err != nil {
		log.Printf("[Certificate] ObtainCertificate failed for %s: %v", cert.Domain, err)
		appendLog("证书申请失败: " + err.Error())
		_ = h.updateCertificateStatusDurable(cert.ID, storage.CertStatusFailed, err.Error())
		SendCertResultNotification(ctx, cert.Domain, false, err.Error())
		return
	}

	appendLog(fmt.Sprintf("证书颁发成功, 有效期至 %s", result.ExpiryDate.Format("2006-01-02")))

	persistCtx, persistCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = h.repo.UpdateCertificateIssued(persistCtx, cert.ID, result.CertPath, result.KeyPath, result.CertPEM, result.KeyPEM, result.IssueDate, result.ExpiryDate)
	persistCancel()
	if err != nil {
		log.Printf("[Certificate] UpdateCertificateIssued failed for %s: %v", cert.Domain, err)
		_ = h.updateCertificateStatusDurable(cert.ID, storage.CertStatusFailed, "证书已签发，但保存证书记录失败: "+err.Error())
		return
	}

	log.Printf("[Certificate] Successfully issued certificate for %s, expires %s", cert.Domain, result.ExpiryDate.Format("2006-01-02"))
	SendCertResultNotification(ctx, cert.Domain, true, fmt.Sprintf("有效期至 %s", result.ExpiryDate.Format("2006-01-02")))

	h.syncManagedXrayAfterMaterialUpdate(cert, result.CertPEM, result.KeyPEM)
	// 如果配置则本地部署
	h.deployAfterIssue(cert, result)
	h.checkMasterCertReady(cert)
}

// DEAD CODE — 通过 WebSocket 向远程代理发送证书请求。
//
// **当前 agent 端没有实现 cert_request 消息处理,也没有 ACME 能力**(无 lego/acme.sh 依赖)。
// SendCertRequest 发出后 agent 收到 cert_request 走 default case 忽略,master 永远收不到
// cert_update 回响 → 证书状态卡在 Pending 直至 30s ctx 超时。
//
// 入口:前端「申请证书」dialog 里「目标服务器」下拉选了具体 agent 时触发(remote_server_id > 0)。
// 选「主控本地」(=0)走 requestLocalCertificate,master 端用 lego + DNS provider token 操作
// DNS API 申请,这条是 working 的。
//
// 若要修复:推荐改造为 master 本地申请(复用 acmeClient.ObtainCertificateV2)+ 申请成功后
// 调 deployToRemoteServer(server, ...) 推送(已有 WS-first + HTTP v4/v6 fallback),
// 不依赖 agent ACME 能力。HTTP-01 仍需 agent 配合(此场景下需另起方案)。
func (h *CertificateHandler) requestRemoteCertificate(cert *storage.Certificate) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	appendLog := func(msg string) { h.appendCertificateLogDurable(cert.ID, msg) }

	appendLog("开始远程证书申请: " + cert.Domain)

	// 获取远程服务器令牌
	server, err := h.repo.GetRemoteServer(ctx, cert.RemoteServerID)
	if err != nil {
		log.Printf("[Certificate] GetRemoteServer failed: %v", err)
		appendLog("获取远程服务器信息失败: " + err.Error())
		h.markCertificateOperationFailed(cert, errors.New("获取远程服务器信息失败"))
		return
	}

	appendLog("目标服务器: " + server.Name)

	if !h.wsHandler.IsConnected(server.Token) {
		log.Printf("[Certificate] Remote server %s is not connected", server.Name)
		appendLog("远程服务器未连接")
		h.markCertificateOperationFailed(cert, errors.New("远程服务器未连接"))
		return
	}

	// 如果需要，解析 DNS 凭据
	var dnsProviderType string
	var dnsCredentials string
	if cert.ChallengeMode == storage.CertChallengeDNS && cert.DNSProviderID > 0 {
		dnsProvider, dnsErr := h.repo.GetDNSProvider(ctx, cert.DNSProviderID)
		if dnsErr != nil {
			log.Printf("[Certificate] GetDNSProvider failed: %v", dnsErr)
			appendLog("获取 DNS 凭证失败")
			h.markCertificateOperationFailed(cert, errors.New("获取DNS凭证失败"))
			return
		}
		dnsProviderType = dnsProvider.ProviderType
		dnsCredentials = dnsProvider.Credentials
		appendLog("DNS 提供商: " + dnsProviderType)
	}

	appendLog("正在通过 WebSocket 发送证书请求...")

	// 通过 WebSocket 发送证书请求
	payload := WSCertRequestPayload{
		CertID:         cert.ID,
		Domain:         cert.Domain,
		Email:          cert.Email,
		Provider:       cert.Provider,
		ChallengeMode:  cert.ChallengeMode,
		WebrootPath:    cert.WebrootPath,
		DNSProvider:    dnsProviderType,
		DNSCredentials: dnsCredentials,
	}

	if err := h.wsHandler.SendCertRequest(server.Token, payload); err != nil {
		log.Printf("[Certificate] SendCertRequest failed: %v", err)
		h.markCertificateOperationFailed(cert, errors.New("发送证书请求失败"))
		return
	}

	log.Printf("[Certificate] Sent certificate request to remote server %s for domain %s", server.Name, cert.Domain)
}

// 处理 POST /api/admin/certificates/renew
func (h *CertificateHandler) RenewCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的证书ID"})
		return
	}
	id := req.ID

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	cert, err := h.repo.GetCertificate(ctx, id)
	if err != nil {
		if err == storage.ErrCertificateNotFound {
			respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "证书不存在"})
			return
		}
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "获取证书失败"})
		return
	}
	if cert.Provider == "manual" || cert.ChallengeMode == "manual" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "手动上传证书不能通过 ACME 续期"})
		return
	}
	if !h.beginRenewal(cert.ID) {
		respondJSON(w, http.StatusConflict, map[string]any{"success": false, "message": "该证书正在申请或续期，请勿重复提交"})
		return
	}

	// 将状态更新为待处理
	if err := h.repo.UpdateCertificateStatus(ctx, cert.ID, storage.CertStatusPending, "正在续期..."); err != nil {
		h.finishRenewal(cert.ID)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "更新证书续期状态失败"})
		return
	}

	if cert.RemoteServerID == 0 {
		go func() {
			defer h.finishRenewal(cert.ID)
			h.renewLocalCertificate(cert)
		}()
	} else {
		go func() {
			defer h.finishRenewal(cert.ID)
			h.requestRemoteCertificate(cert)
		}()
	}

	respondJSON(w, http.StatusAccepted, map[string]any{"success": true, "message": "证书续期已提交"})
}

// 在本地更新证书。
func (h *CertificateHandler) renewLocalCertificate(cert *storage.Certificate) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	h.appendCertificateLogDurable(cert.ID, "开始续期证书: "+cert.Domain)

	certReq, err := h.buildCertRequest(ctx, cert)
	if err != nil {
		log.Printf("[Certificate] buildCertRequest failed for %s: %v", cert.Domain, err)
		h.markRenewalFailed(cert, err)
		return
	}

	result, err := h.acmeClient.RenewCertificateV2(ctx, certReq, cert.CertPEM, cert.KeyPEM)
	if err != nil {
		log.Printf("[Certificate] RenewCertificate failed for %s: %v", cert.Domain, err)
		h.markRenewalFailed(cert, err)
		SendCertResultNotification(ctx, cert.Domain, false, "续期失败，旧证书保持不变: "+err.Error())
		return
	}

	persistCtx, persistCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = h.repo.UpdateCertificateIssued(persistCtx, cert.ID, result.CertPath, result.KeyPath, result.CertPEM, result.KeyPEM, result.IssueDate, result.ExpiryDate)
	persistCancel()
	if err != nil {
		log.Printf("[Certificate] UpdateCertificateIssued failed for %s: %v", cert.Domain, err)
		h.markRenewalFailed(cert, fmt.Errorf("保存续签证书失败: %w", err))
		return
	}

	log.Printf("[Certificate] Successfully renewed certificate for %s, expires %s", cert.Domain, result.ExpiryDate.Format("2006-01-02"))
	h.appendCertificateLogDurable(cert.ID, fmt.Sprintf("证书续期成功，有效期至 %s", result.ExpiryDate.Format("2006-01-02")))
	SendCertResultNotification(ctx, cert.Domain, true, fmt.Sprintf("续期成功，有效期至 %s", result.ExpiryDate.Format("2006-01-02")))

	h.syncManagedXrayAfterMaterialUpdate(cert, result.CertPEM, result.KeyPEM)
	// 如果配置则本地部署
	h.deployAfterIssue(cert, result)
	h.checkMasterCertReady(cert)
}

func (h *CertificateHandler) markRenewalFailed(cert *storage.Certificate, renewalErr error) {
	status := storage.CertStatusFailed
	message := "续期失败: " + renewalErr.Error()
	if cert != nil && cert.CertPEM != "" && cert.KeyPEM != "" && cert.ExpiryDate != nil && cert.ExpiryDate.After(time.Now()) {
		status = storage.CertStatusValid
		message = "续期失败，已保留当前有效证书: " + renewalErr.Error()
	}
	if cert == nil {
		return
	}
	if err := h.updateCertificateStatusDurable(cert.ID, status, message); err != nil {
		log.Printf("[Certificate] preserve certificate after renewal failure for %s: %v", cert.Domain, err)
	}
	h.appendCertificateLogDurable(cert.ID, message)
}

func (h *CertificateHandler) markCertificateOperationFailed(cert *storage.Certificate, operationErr error) {
	if cert != nil && cert.CertPEM != "" && cert.KeyPEM != "" {
		h.markRenewalFailed(cert, operationErr)
		return
	}
	if cert != nil {
		_ = h.updateCertificateStatusDurable(cert.ID, storage.CertStatusFailed, operationErr.Error())
		h.appendCertificateLogDurable(cert.ID, operationErr.Error())
	}
}

// 处理 PATCH /api/admin/certificates/auto-renew
func (h *CertificateHandler) SetAutoRenew(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	var req struct {
		ID        int64 `json:"id"`
		AutoRenew bool  `json:"auto_renew"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的请求数据"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.repo.SetCertificateAutoRenew(ctx, req.ID, req.AutoRenew); err != nil {
		if err == storage.ErrCertificateNotFound {
			respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "证书不存在"})
			return
		}
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "更新失败"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "已更新"})
}

// 处理 PATCH /api/admin/certificates/auto-deploy
func (h *CertificateHandler) SetAutoDeploy(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	var req struct {
		ID         int64 `json:"id"`
		AutoDeploy bool  `json:"auto_deploy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的请求数据"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.repo.SetCertificateAutoDeploy(ctx, req.ID, req.AutoDeploy); err != nil {
		if err == storage.ErrCertificateNotFound {
			respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "证书不存在"})
			return
		}
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "更新失败"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "已更新"})
}

// 处理 DELETE /api/admin/certificates/delete
func (h *CertificateHandler) DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的证书ID"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.repo.DeleteCertificate(ctx, req.ID); err != nil {
		if err == storage.ErrCertificateNotFound {
			respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "证书不存在"})
			return
		}
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "删除失败"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "证书已删除"})
}

// 处理 GET /api/admin/certificates/valid
func (h *CertificateHandler) ListValidCertificates(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	certs, err := h.repo.ListValidCertificates(ctx)
	if err != nil {
		log.Printf("[Certificate] ListValidCertificates error: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "获取证书列表失败"})
		return
	}

	// 获取远程服务器名称
	serverNames := make(map[int64]string)
	servers, _ := h.repo.ListRemoteServers(ctx)
	for _, s := range servers {
		serverNames[s.ID] = s.Name
	}

	responses := make([]CertificateResponse, len(certs))
	for i, cert := range certs {
		responses[i] = certificateToResponse(&cert)
		if cert.RemoteServerID > 0 {
			responses[i].RemoteServerName = serverNames[cert.RemoteServerID]
		} else {
			responses[i].RemoteServerName = "本地服务器"
		}
	}

	respondJSON(w, http.StatusOK, ListCertificatesResponse{
		Success:      true,
		Certificates: responses,
	})
}

// 启动一个 goroutine 来检查过期的证书。
func (h *CertificateHandler) StartRenewalChecker(ctx context.Context) {
	go func() {
		// 启动后初步检查
		time.Sleep(1 * time.Minute)
		h.checkAndRenewCertificates()

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.checkAndRenewCertificates()
			}
		}
	}()
}

// 检查过期证书并更新它们。
func (h *CertificateHandler) checkAndRenewCertificates() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 启用 auto_renew 后获取 30 天后到期的证书
	certs, err := h.repo.ListExpiringCertificates(ctx, 30)
	if err != nil {
		log.Printf("[Certificate] ListExpiringCertificates error: %v", err)
		return
	}

	for _, cert := range certs {
		log.Printf("[Certificate] Auto-renewing certificate for %s (expires %s)", cert.Domain, cert.ExpiryDate.Format("2006-01-02"))

		if !h.beginRenewal(cert.ID) {
			continue
		}
		if err := h.repo.UpdateCertificateStatus(ctx, cert.ID, storage.CertStatusPending, "自动续期中..."); err != nil {
			h.finishRenewal(cert.ID)
			log.Printf("[Certificate] mark auto-renew pending for %s: %v", cert.Domain, err)
			continue
		}

		if cert.RemoteServerID == 0 {
			go func(cert storage.Certificate) {
				defer h.finishRenewal(cert.ID)
				h.renewLocalCertificate(&cert)
			}(cert)
		} else {
			go func(cert storage.Certificate) {
				defer h.finishRenewal(cert.ID)
				h.requestRemoteCertificate(&cert)
			}(cert)
		}
	}

	if len(certs) > 0 {
		log.Printf("[Certificate] Initiated renewal for %d certificates", len(certs))
	}
}

// 处理来自远程代理的证书更新通知。
func (h *CertificateHandler) HandleCertUpdate(serverID int64, payload WSCertUpdatePayload) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if payload.Success {
		if err := h.repo.UpdateCertificateIssued(ctx, payload.CertID, payload.CertPath, payload.KeyPath, payload.CertPEM, payload.KeyPEM, payload.IssueDate, payload.ExpiryDate); err != nil {
			log.Printf("[Certificate] HandleCertUpdate UpdateCertificateIssued failed: %v", err)
			return
		}
		log.Printf("[Certificate] Remote certificate issued for domain from cert_update, cert_id=%d, server_id=%d", payload.CertID, serverID)

		// 部署到主服务器和所有远程服务器（如果配置）
		cert, err := h.repo.GetCertificate(ctx, payload.CertID)
		if err == nil && cert.DeployCertPath != "" && cert.DeployKeyPath != "" {
			deployTarget := cert.DeployTarget
			if cert.AutoDeploy {
				deployTarget = "both"
			}
			if deployTarget != "" && deployTarget != "none" {
				if deployErr := h.deployLocal(payload.CertPEM, payload.KeyPEM, cert.DeployCertPath, cert.DeployKeyPath, deployTarget); deployErr != nil {
					log.Printf("[Certificate] Local deploy from cert_update failed: %v", deployErr)
				}
				h.deployToAllRemotes(cert.Domain, payload.CertPEM, payload.KeyPEM, cert.DeployCertPath, cert.DeployKeyPath, deployTarget)
			}
		}
	} else {
		if err := h.repo.UpdateCertificateStatus(ctx, payload.CertID, storage.CertStatusFailed, payload.Error); err != nil {
			log.Printf("[Certificate] HandleCertUpdate UpdateCertificateStatus failed: %v", err)
			return
		}
		log.Printf("[Certificate] Remote certificate failed for cert_id=%d, server_id=%d: %s", payload.CertID, serverID, payload.Error)
	}
}

// buildCertRequest 从 storage.Certificate 构造 acme.CertRequest，
// 从数据库解析 DNS 提供商凭据。
func (h *CertificateHandler) buildCertRequest(ctx context.Context, cert *storage.Certificate) (acme.CertRequest, error) {
	req := acme.CertRequest{
		Email:         cert.Email,
		Domain:        cert.Domain,
		Provider:      cert.Provider,
		ChallengeMode: cert.ChallengeMode,
		WebrootPath:   cert.WebrootPath,
	}

	// 如果使用 DNS-01，则解析 DNS 提供商凭据
	if cert.ChallengeMode == storage.CertChallengeDNS && cert.DNSProviderID > 0 {
		dnsProvider, err := h.repo.GetDNSProvider(ctx, cert.DNSProviderID)
		if err != nil {
			return req, fmt.Errorf("get DNS provider: %w", err)
		}
		req.DNSProvider = dnsProvider.ProviderType

		// 解析凭证 JSON
		var creds map[string]string
		if err := json.Unmarshal([]byte(dnsProvider.Credentials), &creds); err != nil {
			return req, fmt.Errorf("parse DNS credentials: %w", err)
		}
		req.DNSCredentials = creds
	}

	return req, nil
}

// 处理颁发后的证书部署 - 部署到主服务器和所有远程服务器。
func (h *CertificateHandler) deployAfterIssue(cert *storage.Certificate, result *acme.CertResult) {
	deployTarget := cert.DeployTarget
	if cert.AutoDeploy && cert.DeployCertPath != "" && cert.DeployKeyPath != "" {
		deployTarget = "both"
	}
	if deployTarget == "" || deployTarget == "none" {
		return
	}
	if cert.DeployCertPath == "" || cert.DeployKeyPath == "" {
		return
	}

	// 本地部署（主）
	if err := h.deployLocal(result.CertPEM, result.KeyPEM, cert.DeployCertPath, cert.DeployKeyPath, deployTarget); err != nil {
		log.Printf("[Certificate] Local deploy failed for %s: %v", cert.Domain, err)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.repo.AppendCertificateLog(ctx, cert.ID, "自动部署失败，旧证书已恢复: "+err.Error())
	} else {
		log.Printf("[Certificate] Local deploy succeeded for %s to %s", cert.Domain, cert.DeployCertPath)
	}

	// 部署到所有远程服务器
	h.deployToAllRemotes(cert.Domain, result.CertPEM, result.KeyPEM, cert.DeployCertPath, cert.DeployKeyPath, deployTarget)
}

func (h *CertificateHandler) checkMasterCertReady(cert *storage.Certificate) {
	if cert.RemoteServerID != 0 {
		return
	}
	ctx := context.Background()
	domain := getDomainFromMasterURL(h.repo, ctx)
	if domain == "" {
		return
	}
	rootDomain := extractRootDomain(domain)
	certDomain := strings.ToLower(cert.Domain)
	if !strings.EqualFold(certDomain, domain) && certDomain != "*."+rootDomain && certDomain != rootDomain {
		return
	}
	masterURL, _ := h.repo.GetSystemSetting(ctx, "master_url")
	if strings.HasPrefix(masterURL, "https://") {
		return
	}
	_ = h.repo.SetSystemSetting(ctx, "master_cert_pending", "true")
	log.Printf("[Certificate] 主控域名证书已签发，等待用户确认部署: %s", cert.Domain)
}

// 将 cert_deploy 消息发送到特定的远程代理。
func (h *CertificateHandler) deployRemoteCertificate(cert *storage.Certificate, certPEM, keyPEM string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server, err := h.repo.GetRemoteServer(ctx, cert.RemoteServerID)
	if err != nil {
		log.Printf("[Certificate] GetRemoteServer for deploy failed: %v", err)
		return
	}

	payload := WSCertDeployPayload{
		Domain:   cert.Domain,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		CertPath: filepath.Join(filepath.Dir(cert.DeployCertPath), certDeployFilename(cert.Domain)+filepath.Ext(cert.DeployCertPath)),
		KeyPath:  filepath.Join(filepath.Dir(cert.DeployKeyPath), certDeployFilename(cert.Domain)+filepath.Ext(cert.DeployKeyPath)),
		Reload:   cert.DeployTarget,
	}

	h.deployToRemoteServer(server, payload)
}

// deployToRemoteServerSync 在调用方的上下文中持有 server mutation lease，
// 并等到 Agent 对证书落盘/重载给出明确 ACK 后才返回。多步处理器应该把已持租约的
// context 传进来；底层租约可重入，不会在同一 server 上再次锁住自己。
func (h *CertificateHandler) deployToRemoteServerSync(ctx context.Context, server *storage.RemoteServer, payload WSCertDeployPayload) error {
	return h.repo.WithRemoteServerMutationLease(ctx, server.ID, func(leasedCtx context.Context) error {
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if h.remoteManage != nil {
			ack, err := h.remoteManage.ForwardToAgent(leasedCtx, server.ID, http.MethodPost, "/api/child/cert/deploy", body)
			if err != nil {
				return err
			}
			return validateCertificateDeployACK(ack)
		}
		return h.deployRemoteCertificateHTTP(leasedCtx, server, payload)
	})
}

// 通过 WS 或 HTTP 将证书发送到特定的远程服务器。保留该包装供后台任务使用；
// HTTP 请求链路应直接调 deployToRemoteServerSync 以获取错误。
func (h *CertificateHandler) deployToRemoteServer(server *storage.RemoteServer, payload WSCertDeployPayload) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := h.deployToRemoteServerSync(ctx, server, payload)
	if err != nil {
		log.Printf("[Certificate] cert_deploy failed for %s: %v", server.Name, err)
		return
	}
	log.Printf("[Certificate] Synchronously deployed certificate to %s for %s", server.Name, payload.Domain)
}

// DeployCertToServerSync 同步把证书下发到指定 agent 的 xray 证书目录,返回 agent 上的 cert/key 路径。
// 用于「添加 tls 入站时自动确保证书已在 agent 上」,避免证书缺失导致 xray 加载失败(502)。
// Reload 用 "none":证书只写文件,真正生效由随后的 add inbound(gRPC) 触发,避免无谓重启。
//
// 优先走 WS(跟 deployToRemoteServer 一致 — agent 通过 WS 长连接收 cert_deploy 即可写文件),
// WS 不可用 / 写失败时 fallback HTTP。WS 写完即返回路径,不等 agent ack — agent 处理是 ms 级,
// 后续 add inbound 之间的时间差足够 agent 完成 cert 落盘。
func (h *CertificateHandler) DeployCertToServerSync(ctx context.Context, server *storage.RemoteServer, cert *storage.Certificate) (string, string, error) {
	var certPath, keyPath string
	err := h.repo.WithRemoteServerMutationLease(ctx, server.ID, func(leasedCtx context.Context) error {
		var deployErr error
		certPath, keyPath, deployErr = h.deployCertToServerSyncLeased(leasedCtx, server, cert)
		return deployErr
	})
	return certPath, keyPath, err
}

func (h *CertificateHandler) deployCertToServerSyncLeased(ctx context.Context, server *storage.RemoteServer, cert *storage.Certificate) (string, string, error) {
	name := certDeployFilename(cert.Domain)
	certPath := "/usr/local/etc/xray/certs/" + name + ".pem"
	keyPath := "/usr/local/etc/xray/certs/" + name + ".key"
	payload := WSCertDeployPayload{
		Domain:   cert.Domain,
		CertPEM:  cert.CertPEM,
		KeyPEM:   cert.KeyPEM,
		CertPath: certPath,
		KeyPath:  keyPath,
		Reload:   "none",
	}

	// Use the request/response management path whenever available. It selects WS
	// first (including federation) and keeps the mutation lease until Agent ACK.
	if h.remoteManage != nil {
		body, _ := json.Marshal(payload)
		fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		ack, err := h.remoteManage.ForwardToAgent(fctx, server.ID, http.MethodPost, "/api/child/cert/deploy", body)
		if err != nil {
			return "", "", err
		}
		if err := validateCertificateDeployACK(ack); err != nil {
			return "", "", err
		}
		h.rememberXrayCertSync(server.ID, cert)
		log.Printf("[Certificate] Sync cert_deploy to %s for %s", server.Name, payload.Domain)
		return certPath, keyPath, nil
	}

	// Fallback HTTP is still synchronous; no fire-and-forget WS mutation escapes
	// the installation lease.
	if err := h.deployRemoteCertificateHTTP(ctx, server, payload); err != nil {
		return "", "", err
	}
	h.rememberXrayCertSync(server.ID, cert)
	log.Printf("[Certificate] Sync cert_deploy via HTTP to %s for %s", server.Name, payload.Domain)
	return certPath, keyPath, nil
}

// 将证书部署到所有连接的远程服务器。
func (h *CertificateHandler) deployToAllRemotes(domain, certPEM, keyPEM, certPath, keyPath, reloadTarget string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil || len(servers) == 0 {
		return
	}

	payload := WSCertDeployPayload{
		Domain:   domain,
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		CertPath: filepath.Join(filepath.Dir(certPath), certDeployFilename(domain)+filepath.Ext(certPath)),
		KeyPath:  filepath.Join(filepath.Dir(keyPath), certDeployFilename(domain)+filepath.Ext(keyPath)),
		Reload:   reloadTarget,
	}

	for i := range servers {
		go h.deployToRemoteServer(&servers[i], payload)
	}
	log.Printf("[Certificate] Initiated deploy to %d remote server(s) for %s", len(servers), domain)
}

// 通过 HTTP POST 将证书推送到代理。
// 走 buildAgentURLCandidates 的 v4-first → v6-fallback 候选清单,消灭旧的 strings.LastIndex 截断 bug。
func (h *CertificateHandler) deployRemoteCertificateHTTP(ctx context.Context, server *storage.RemoteServer, payload WSCertDeployPayload) error {
	body, _ := json.Marshal(payload)

	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Authorization", "Bearer "+server.Token)
	hdr.Set("User-Agent", "relaydock/0.1")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := tryHTTPWithFallback(ctx, client, server, http.MethodPost, "/api/child/cert/deploy", body, hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("read certificate deploy ACK: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return validateCertificateDeployACK(respBody)
}

// 旧 Agent 在 2xx 时可能返回空 body 或不带 success 字段，两者都视为 HTTP ACK。
// 新 Agent 若明确返回 success=false，则必须将远程失败透传给上层。
func validateCertificateDeployACK(body []byte) error {
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	var ack struct {
		Success *bool  `json:"success"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &ack); err != nil || ack.Success == nil {
		return nil
	}
	if *ack.Success {
		return nil
	}
	message := strings.TrimSpace(ack.Error)
	if message == "" {
		message = strings.TrimSpace(ack.Message)
	}
	if message == "" {
		message = "Agent rejected certificate deployment"
	}
	return errors.New(message)
}

// 处理 POST /api/admin/certificates/deploy — 手动部署证书。
func (h *CertificateHandler) DeployCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "message": "Method not allowed"})
		return
	}

	var req struct {
		ID             int64  `json:"id"`
		DeployTarget   string `json:"deploy_target"`
		DeployCertPath string `json:"deploy_cert_path"`
		DeployKeyPath  string `json:"deploy_key_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "请求格式错误"})
		return
	}
	if req.ID == 0 || req.DeployTarget == "" || req.DeployCertPath == "" || req.DeployKeyPath == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "缺少必要参数"})
		return
	}

	cert, err := h.repo.GetCertificate(r.Context(), req.ID)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "证书不存在"})
		return
	}
	if cert.Status != "valid" || cert.CertPEM == "" || cert.KeyPEM == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "证书状态无效或缺少证书数据"})
		return
	}

	// 本地部署（主）
	if err := h.deployLocal(cert.CertPEM, cert.KeyPEM, req.DeployCertPath, req.DeployKeyPath, req.DeployTarget); err != nil {
		log.Printf("[Certificate] Local deploy failed for %s: %v", cert.Domain, err)
		_ = h.repo.AppendCertificateLog(r.Context(), cert.ID, "部署失败，已恢复旧证书: "+err.Error())
		respondJSON(w, http.StatusBadGateway, map[string]any{"success": false, "message": "证书部署或服务重载失败，已恢复旧证书: " + err.Error()})
		return
	}

	// 仅在文件和服务均成功切换后保存部署设置。
	cert.DeployTarget = req.DeployTarget
	cert.DeployCertPath = req.DeployCertPath
	cert.DeployKeyPath = req.DeployKeyPath
	if err := h.repo.UpdateCertificate(r.Context(), cert); err != nil {
		log.Printf("[Certificate] UpdateCertificate deploy settings failed: %v", err)
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "证书已部署，但保存部署设置失败"})
		return
	}

	// 部署到所有远程服务器
	h.deployToAllRemotes(cert.Domain, cert.CertPEM, cert.KeyPEM, req.DeployCertPath, req.DeployKeyPath, req.DeployTarget)

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "证书已部署到主服务器，远程服务器部署已提交"})
}

// DeployAutoDeployCertificates 将所有 auto_deploy 证书部署到特定的远程服务器。
// 在远程服务器安装 nginx/xray 后调用。
func (h *CertificateHandler) DeployAutoDeployCertificates(serverID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	certs, err := h.repo.ListAutoDeployCertificates(ctx)
	if err != nil || len(certs) == 0 {
		return
	}

	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		log.Printf("[Certificate] DeployAutoDeployCertificates: GetRemoteServer(%d) failed: %v", serverID, err)
		return
	}

	for _, cert := range certs {
		payload := WSCertDeployPayload{
			Domain:   cert.Domain,
			CertPEM:  cert.CertPEM,
			KeyPEM:   cert.KeyPEM,
			CertPath: filepath.Join(filepath.Dir(cert.DeployCertPath), certDeployFilename(cert.Domain)+filepath.Ext(cert.DeployCertPath)),
			KeyPath:  filepath.Join(filepath.Dir(cert.DeployKeyPath), certDeployFilename(cert.Domain)+filepath.Ext(cert.DeployKeyPath)),
			Reload:   "both",
		}
		if err := h.deployToRemoteServerSync(ctx, server, payload); err != nil {
			log.Printf("[Certificate] Auto-deploy %s to server %s failed: %v", cert.Domain, server.Name, err)
		}
	}
	log.Printf("[Certificate] Completed auto-deploy of %d cert(s) to server %s", len(certs), server.Name)
}

// --- DNS 提供商 API 处理程序 ---

// DNSProviderRequest 表示 DNS 提供商创建/更新请求。
type DNSProviderRequest struct {
	Name         string `json:"name"`
	ProviderType string `json:"provider_type"`
	Credentials  string `json:"credentials"` // JSON 字符串
}

// dnsProviderResponse deliberately excludes Credentials. Routine list/create
// responses must never expose DNS API secrets; admins can explicitly retrieve
// one provider's credentials through RevealDNSProviderCredentials.
type dnsProviderResponse struct {
	ID                    int64     `json:"id"`
	Name                  string    `json:"name"`
	ProviderType          string    `json:"provider_type"`
	CredentialsConfigured bool      `json:"credentials_configured"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func publicDNSProvider(provider storage.DNSProvider) dnsProviderResponse {
	return dnsProviderResponse{
		ID:                    provider.ID,
		Name:                  provider.Name,
		ProviderType:          provider.ProviderType,
		CredentialsConfigured: strings.TrimSpace(provider.Credentials) != "",
		CreatedAt:             provider.CreatedAt,
		UpdatedAt:             provider.UpdatedAt,
	}
}

// 处理 GET /api/admin/dns-providers
func (h *CertificateHandler) ListDNSProviders(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	providers, err := h.repo.ListDNSProviders(ctx)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "获取DNS提供商列表失败"})
		return
	}

	publicProviders := make([]dnsProviderResponse, 0, len(providers))
	for _, provider := range providers {
		publicProviders = append(publicProviders, publicDNSProvider(provider))
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "providers": publicProviders})
}

// RevealDNSProviderCredentials handles
// GET /api/admin/dns-providers/{id}/credentials. The endpoint is intentionally
// separate from routine provider reads so secret material is only returned
// after an explicit admin action.
func (h *CertificateHandler) RevealDNSProviderCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "message": "不支持的请求方法"})
		return
	}
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	const prefix = "/api/admin/dns-providers/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	idText, found := strings.CutSuffix(path, "/credentials")
	if !found || idText == "" || strings.Contains(idText, "/") {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的ID"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	provider, err := h.repo.GetDNSProvider(ctx, id)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "DNS 提供商不存在"})
		return
	}

	credentials := make(map[string]string)
	if strings.TrimSpace(provider.Credentials) != "" {
		if err := json.Unmarshal([]byte(provider.Credentials), &credentials); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "DNS 提供商凭据格式无效"})
			return
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "credentials": credentials})
}

// 处理 POST /api/admin/dns-providers
func (h *CertificateHandler) CreateDNSProvider(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	var req DNSProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的请求数据"})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.ProviderType = strings.ToLower(strings.TrimSpace(req.ProviderType))
	if req.Name == "" || req.ProviderType == "" || strings.TrimSpace(req.Credentials) == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "名称、类型和凭证不能为空"})
		return
	}
	normalized, err := normalizeDNSProviderCredentials(req.ProviderType, req.Credentials)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	req.Credentials = normalized

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	p := &storage.DNSProvider{
		Name:         req.Name,
		ProviderType: req.ProviderType,
		Credentials:  req.Credentials,
	}

	if err := h.repo.CreateDNSProvider(ctx, p); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": fmt.Sprintf("创建DNS提供商失败: %v", err)})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "provider": publicDNSProvider(*p)})
}

// 处理 PUT /api/admin/dns-providers/{id}
func (h *CertificateHandler) UpdateDNSProvider(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/dns-providers/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的ID"})
		return
	}

	var req DNSProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的请求数据"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	existing, err := h.repo.GetDNSProvider(ctx, id)
	if err != nil {
		respondJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "DNS 提供商不存在"})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.ProviderType = strings.ToLower(strings.TrimSpace(req.ProviderType))
	if req.Name == "" || req.ProviderType == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "名称和提供商类型不能为空"})
		return
	}
	credentials, err := dnsProviderCredentialsForUpdate(*existing, req.ProviderType, req.Credentials)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}

	p := &storage.DNSProvider{
		ID:           id,
		Name:         req.Name,
		ProviderType: req.ProviderType,
		Credentials:  credentials,
	}

	if err := h.repo.UpdateDNSProvider(ctx, p); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": fmt.Sprintf("更新DNS提供商失败: %v", err)})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "更新成功"})
}

func dnsProviderCredentialsForUpdate(existing storage.DNSProvider, providerType, raw string) (string, error) {
	provided, err := dnsProviderCredentialsProvided(raw)
	if err != nil {
		return "", err
	}
	if !provided {
		if !strings.EqualFold(providerType, strings.TrimSpace(existing.ProviderType)) {
			return "", errors.New("切换 DNS 提供商时必须输入新提供商的 API 凭据")
		}
		return existing.Credentials, nil
	}
	return normalizeDNSProviderCredentials(providerType, raw)
}

func dnsProviderCredentialsProvided(raw string) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return false, nil
	}
	var input map[string]string
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		return false, errors.New("DNS 凭据格式无效")
	}
	for _, value := range input {
		if strings.TrimSpace(value) != "" {
			return true, nil
		}
	}
	return false, nil
}

func normalizeDNSProviderCredentials(providerType, raw string) (string, error) {
	keys, ok := acme.DNSProviderEnvKeys[providerType]
	if !ok {
		return "", fmt.Errorf("不支持的 DNS 提供商：%s", providerType)
	}
	var input map[string]string
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		return "", errors.New("DNS 凭据格式无效")
	}

	var normalized map[string]string
	if providerType == "cloudflare" {
		var err error
		normalized, err = dnscredentials.NormalizeCloudflare(input)
		if err != nil {
			return "", err
		}
	} else {
		normalized = make(map[string]string, len(keys))
		for _, key := range keys {
			value := strings.TrimSpace(input[key])
			if value == "" {
				return "", fmt.Errorf("DNS 凭据缺少 %s", key)
			}
			normalized[key] = value
		}
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", errors.New("DNS 凭据保存失败")
	}
	return string(payload), nil
}

// 处理 DELETE /api/admin/dns-providers/{id}
func (h *CertificateHandler) DeleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "管理员权限不足"})
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/dns-providers/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "无效的ID"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.repo.DeleteDNSProvider(ctx, id); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": fmt.Sprintf("删除DNS提供商失败: %v", err)})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "删除成功"})
}

// UploadCertificate 处理手动上传证书（UI 和 API Token 均可调用）。
// POST /api/admin/certificates/upload
// 参数: domain, cert_pem, key_pem
//   - cert_pem / key_pem 兼容两种格式:
//     1. 裸 PEM 文本(以 "-----BEGIN" 开头,Certimate 等 webhook 直接发的格式)
//     2. base64 编码后的 PEM(原 UI 上传路径)
//     仅按首字符判别,base64 编码后的 PEM 不会以 "-----BEGIN" 开头(对应 base64 是 "LS0tLS1CRUdJTi"),不会冲突。
func (h *CertificateHandler) UploadCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "message": "Method not allowed"})
		return
	}
	if !h.requireAdmin(r) {
		respondJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "权限不足"})
		return
	}

	var req struct {
		Domain  string `json:"domain"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "请求格式错误"})
		return
	}

	req.Domain = strings.TrimSpace(req.Domain)
	if req.Domain == "" || req.CertPEM == "" || req.KeyPEM == "" {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "domain、cert_pem、key_pem 不能为空"})
		return
	}

	decodePEMOrBase64 := func(input, label string) ([]byte, error) {
		s := strings.TrimSpace(input)
		if strings.HasPrefix(s, "-----BEGIN") {
			return []byte(s), nil
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%s 不是合法的 PEM 文本或 base64 编码: %v", label, err)
		}
		return decoded, nil
	}

	certBytes, err := decodePEMOrBase64(req.CertPEM, "cert_pem")
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	keyBytes, err := decodePEMOrBase64(req.KeyPEM, "key_pem")
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}

	result, err := h.acmeClient.ProcessCertResult(req.Domain, certBytes, keyBytes)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": fmt.Sprintf("证书处理失败: %v", err)})
		return
	}

	deployCertPath, deployKeyPath := certDeployPaths(req.Domain, "/usr/local/nginx/cert")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	existing, err := h.repo.GetCertificateByDomain(ctx, req.Domain, 0)
	if err == nil && existing != nil {
		if err := h.repo.UpdateCertificateIssued(ctx, existing.ID, result.CertPath, result.KeyPath, result.CertPEM, result.KeyPEM, result.IssueDate, result.ExpiryDate); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": fmt.Sprintf("更新证书失败: %v", err)})
			return
		}
		if existing.DeployCertPath == "" {
			existing.DeployCertPath = deployCertPath
			existing.DeployKeyPath = deployKeyPath
			_ = h.repo.UpdateCertificate(ctx, existing)
		}
		h.syncManagedXrayAfterMaterialUpdate(existing, result.CertPEM, result.KeyPEM)
		h.checkMasterCertReady(existing)
		respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "证书已更新", "certificate_id": existing.ID})
		return
	}

	cert := &storage.Certificate{
		Domain:         req.Domain,
		Email:          auth.UsernameFromContext(r.Context()) + "@upload",
		Provider:       "manual",
		Status:         storage.CertStatusPending,
		AutoRenew:      false,
		ChallengeMode:  "manual",
		DeployTarget:   "none",
		DeployCertPath: deployCertPath,
		DeployKeyPath:  deployKeyPath,
	}

	if err := h.repo.CreateCertificate(ctx, cert); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": fmt.Sprintf("创建证书记录失败: %v", err)})
		return
	}

	if err := h.repo.UpdateCertificateIssued(ctx, cert.ID, result.CertPath, result.KeyPath, result.CertPEM, result.KeyPEM, result.IssueDate, result.ExpiryDate); err != nil {
		log.Printf("[Certificate] UpdateCertificateIssued after upload failed: %v", err)
	}

	h.syncManagedXrayAfterMaterialUpdate(cert, result.CertPEM, result.KeyPEM)
	h.checkMasterCertReady(cert)

	respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "证书上传成功", "certificate_id": cert.ID})
}
