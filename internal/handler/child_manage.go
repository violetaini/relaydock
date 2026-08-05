package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/acme"
	"github.com/violetaini/relaydock/internal/xrpc/client"

	"github.com/xtls/xray-core/app/proxyman/command"
	routercommand "github.com/xtls/xray-core/app/router/command"
	xserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ChildManageHandler 处理子服务器的管理 API 请求
type ChildManageHandler struct {
	configToken                 string // 用于身份验证的令牌
	inboundsMu                  sync.Mutex
	inboundMutationFencePath    string
	inboundMutationLegacyPaths  []string
	inboundMutationActiveConfig func() string
	inboundMutationFencesLoaded bool
	inboundMutationFences       map[string]inboundMutationFenceState
	inboundMutationFenceWriter  func(string, interface{}) error
	serviceControlCommand       func(service, action string) ([]byte, error)
	clientExpiryMu              sync.Mutex
	clientExpirations           map[string]managedClientExpiration
	clientExpiryConfigPath      string
	clientExpiryWake            chan struct{}
	inboundFirewallSync         func(context.Context) error
}

const (
	managedClientExpiryVersion     = 1
	managedClientExpirySidecarName = ".relaydock-managed-client-expirations.json"
	arcwayFirewallHelperPath       = "/usr/local/sbin/arcway-agent-firewall"
	arcwayFirewallEnvironmentPath  = "/etc/arcway-port-firewall.env"
)

var childXrayConfigPaths = []string{
	"/usr/local/etc/xray/config.json",
	"/etc/xray/config.json",
	"/opt/xray/config.json",
}

type managedClientExpiration struct {
	Tag           string    `json:"tag"`
	Protocol      string    `json:"protocol"`
	IdentityKey   string    `json:"identity_key"`
	IdentityValue string    `json:"identity_value"`
	NotAfter      time.Time `json:"not_after"`
}

type managedClientExpirationFile struct {
	Version int                       `json:"version"`
	Entries []managedClientExpiration `json:"entries"`
}

// 创建一个新的子管理处理程序
func NewChildManageHandler(configToken string) *ChildManageHandler {
	h := &ChildManageHandler{
		configToken:                 configToken,
		inboundMutationFencePath:    defaultChildInboundMutationFencePath(),
		inboundMutationLegacyPaths:  childInboundMutationLegacySidecars(),
		inboundMutationActiveConfig: findChildXrayConfigPath,
		inboundMutationFences:       make(map[string]inboundMutationFenceState),
		clientExpirations:           make(map[string]managedClientExpiration),
		clientExpiryWake:            make(chan struct{}, 1),
		inboundFirewallSync:         syncArcwayInboundFirewall,
	}
	if configPath := h.findXrayConfigPath(); configPath != "" {
		h.clientExpiryMu.Lock()
		if err := h.ensureClientExpirationsLoadedLocked(configPath); err != nil {
			log.Printf("[Child Manage] Failed to restore managed client expirations: %v", err)
		}
		h.clientExpiryMu.Unlock()
		h.inboundsMu.Lock()
		if err := h.recoverPendingInboundMutationsWithRuntimeLocked(); err != nil {
			log.Printf("[Child Manage] Failed to recover inbound mutation ownership at startup: %v", err)
		}
		h.inboundsMu.Unlock()
	}
	go h.runManagedClientExpiryScheduler()
	return h
}

func syncArcwayInboundFirewall(ctx context.Context) error {
	return syncArcwayInboundFirewallPaths(ctx, arcwayFirewallHelperPath, arcwayFirewallEnvironmentPath)
}

func syncArcwayInboundFirewallPaths(ctx context.Context, helperPath, environmentPath string) error {
	info, err := os.Stat(helperPath)
	if errors.Is(err, os.ErrNotExist) {
		if _, envErr := os.Stat(environmentPath); envErr == nil {
			return fmt.Errorf("Arcway firewall helper is missing; rerun the node installation")
		}
		// Local development and legacy unmanaged child-mode installations do not
		// have an Arcway-owned host firewall to reconcile.
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Arcway firewall helper: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("Arcway firewall helper is not executable")
	}
	helper, err := os.ReadFile(helperPath)
	if err != nil {
		return fmt.Errorf("read Arcway firewall helper: %w", err)
	}
	if !bytes.Contains(helper, []byte("PUBLIC_RULES_RAW=")) || !bytes.Contains(helper, []byte("-arcway-firewall-rules=")) {
		return fmt.Errorf("Arcway firewall helper is outdated; rerun the node installation before changing inbounds")
	}
	command := exec.CommandContext(ctx, helperPath)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("reconcile Arcway inbound firewall: %s", message)
	}
	return nil
}

func (h *ChildManageHandler) reconcileInboundFirewall() error {
	if h.inboundFirewallSync == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return h.inboundFirewallSync(ctx)
}

func (h *ChildManageHandler) lockXrayConfigMutation() error {
	h.inboundsMu.Lock()
	if err := h.ensureInboundMutationFencesLocked(); err != nil {
		h.inboundsMu.Unlock()
		return err
	}
	return nil
}

func (h *ChildManageHandler) unlockXrayConfigMutation() {
	h.inboundsMu.Unlock()
}

func (h *ChildManageHandler) runServiceControl(service, action string) ([]byte, error) {
	if h.serviceControlCommand != nil {
		return h.serviceControlCommand(service, action)
	}
	return exec.Command("systemctl", action, service).CombinedOutput()
}

// controlXrayServiceLocked must be called while inboundsMu is held. Starting
// Xray can make durable config live before a crashed inbound transaction has
// finalized its owner, so recovery is completed in the same exclusion domain.
func (h *ChildManageHandler) controlXrayServiceLocked(action string) ([]byte, error) {
	output, err := h.runServiceControl("xray", action)
	if err != nil {
		return output, err
	}
	if action == "start" || action == "restart" {
		if err := h.recoverPendingInboundMutationsWithRuntimeLocked(); err != nil {
			return output, fmt.Errorf("recover pending inbound mutations after Xray %s: %w", action, err)
		}
	}
	return output, nil
}

// DeployCertificateFiles serializes the entire certificate write/restart
// sequence with inbound mutations when Xray consumes the certificate. Keeping
// both PEM writes inside the mutex also prevents another restart from loading a
// temporarily mismatched certificate/key pair.
func (h *ChildManageHandler) DeployCertificateFiles(certPEM, keyPEM, certPath, keyPath, reloadTarget string) error {
	if reloadTarget != "xray" && reloadTarget != "both" {
		return acme.Deploy(certPEM, keyPEM, certPath, keyPath, reloadTarget)
	}
	if err := h.lockXrayConfigMutation(); err != nil {
		return fmt.Errorf("inbound mutation recovery must complete before deploying an Xray certificate: %w", err)
	}
	defer h.unlockXrayConfigMutation()

	return acme.DeployWithXrayRestarter(certPEM, keyPEM, certPath, keyPath, reloadTarget, func() error {
		output, err := h.controlXrayServiceLocked("restart")
		if err != nil {
			return fmt.Errorf("restart Xray after certificate deployment: %w - %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	})
}

// 验证检查请求是否被授权
func (h *ChildManageHandler) authenticate(r *http.Request) bool {
	if h.configToken == "" {
		// 如果未配置令牌，则允许所有请求（不建议用于生产）
		return true
	}

	// 只接受标准 Bearer 标头。
	token, ok := remoteBearerToken(r.Header.Get("Authorization"))
	if !ok {
		return false
	}
	return token == h.configToken
}

// 写入 JSON 响应
func childWriteJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// 写入错误响应
func childWriteError(w http.ResponseWriter, statusCode int, message string) {
	childWriteJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// ================== 系统服务状态==================

// ChildServicesStatusResponse 表示服务状态的响应
type ChildServicesStatusResponse struct {
	Success bool                `json:"success"`
	Xray    *ChildServiceStatus `json:"xray,omitempty"`
	Nginx   *ChildServiceStatus `json:"nginx,omitempty"`
}

// ChildServiceStatus 代表服务状态
type ChildServiceStatus struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Version   string `json:"version,omitempty"`
}

// 处理 GET /api/child/services/status
func (h *ChildManageHandler) HandleServicesStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	response := ChildServicesStatusResponse{
		Success: true,
		Xray:    h.getXrayStatus(),
		Nginx:   h.getNginxStatus(),
	}

	childWriteJSON(w, http.StatusOK, response)
}

func (h *ChildManageHandler) getXrayStatus() *ChildServiceStatus {
	status := &ChildServiceStatus{}

	// 检查是否安装了xray
	xrayPath, err := exec.LookPath("xray")
	if err != nil {
		// 尝试常见地点
		commonPaths := []string{"/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray"}
		for _, p := range commonPaths {
			if _, err := os.Stat(p); err == nil {
				xrayPath = p
				break
			}
		}
	}

	if xrayPath != "" {
		status.Installed = true
		// 获取版本
		cmd := exec.Command(xrayPath, "version")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// 检查是否正在运行
	cmd := exec.Command("systemctl", "is-active", "xray")
	output, _ := cmd.Output()
	status.Running = strings.TrimSpace(string(output)) == "active"

	return status
}

func (h *ChildManageHandler) getNginxStatus() *ChildServiceStatus {
	status := &ChildServiceStatus{}

	// 检查nginx是否安装
	nginxPath, err := exec.LookPath("nginx")
	if err == nil {
		status.Installed = true
		// 获取版本
		cmd := exec.Command(nginxPath, "-v")
		output, err := cmd.CombinedOutput()
		if err == nil {
			status.Version = strings.TrimSpace(string(output))
		}
	}

	// 检查是否正在运行
	cmd := exec.Command("systemctl", "is-active", "nginx")
	output, _ := cmd.Output()
	status.Running = strings.TrimSpace(string(output)) == "active"

	return status
}

// ================== 服务控制 ==================

// ChildServiceControlRequest 表示服务控制请求
type ChildServiceControlRequest struct {
	Service string `json:"service"` // “xray”或“nginx”
	Action  string `json:"action"`  // “开始”、“停止”、“重新启动”
}

// 处理 POST /api/child/services/control
func (h *ChildManageHandler) HandleServiceControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req ChildServiceControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// 验证服务
	if req.Service != "xray" && req.Service != "nginx" {
		childWriteError(w, http.StatusBadRequest, "Invalid service. Must be 'xray' or 'nginx'")
		return
	}

	// 验证行动
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		childWriteError(w, http.StatusBadRequest, "Invalid action. Must be 'start', 'stop', or 'restart'")
		return
	}

	var output []byte
	var err error
	if req.Service == "xray" {
		// Xray lifecycle changes and inbound runtime/config mutations must never
		// cross: a restart between runtime apply and durable config commit would
		// otherwise resurrect the wrong generation.
		h.inboundsMu.Lock()
		output, err = h.controlXrayServiceLocked(req.Action)
		h.inboundsMu.Unlock()
	} else {
		output, err = h.runServiceControl(req.Service, req.Action)
	}
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to %s %s: %v - %s", req.Action, req.Service, err, string(output)))
		return
	}

	log.Printf("[Child Manage] Service %s: %s", req.Service, req.Action)

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Service %s %sed successfully", req.Service, req.Action),
	})
}

// ================== X 射线安装 ==================

// 处理 POST /api/child/xray/install
func (h *ChildManageHandler) HandleXrayInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if err := h.lockXrayConfigMutation(); err != nil {
		childWriteError(w, http.StatusConflict, fmt.Sprintf("Inbound mutation recovery must complete before installing Xray: %v", err))
		return
	}
	defer h.unlockXrayConfigMutation()

	log.Printf("[Child Manage] Installing Xray...")

	// 运行 xray 安装脚本
	cmd := exec.Command("bash", "-c", "bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install")
	cmd.Env = os.Environ()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("[Child Manage] Xray installation failed: %v, stderr: %s", err, stderr.String())
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Installation failed: %v", err))
		return
	}

	log.Printf("[Child Manage] Xray installed successfully")

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Xray installed successfully",
		"output":  stdout.String(),
	})
}

// 处理 POST /api/child/xray/remove
func (h *ChildManageHandler) HandleXrayRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if err := h.lockXrayConfigMutation(); err != nil {
		childWriteError(w, http.StatusConflict, fmt.Sprintf("Inbound mutation recovery must complete before removing Xray: %v", err))
		return
	}
	defer h.unlockXrayConfigMutation()

	log.Printf("[Child Manage] Removing Xray...")

	// 运行 X 射线删除脚本
	cmd := exec.Command("bash", "-c", "bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ remove")
	cmd.Env = os.Environ()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("[Child Manage] Xray removal failed: %v, stderr: %s", err, stderr.String())
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Removal failed: %v", err))
		return
	}

	log.Printf("[Child Manage] Xray removed successfully")

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Xray removed successfully",
		"output":  stdout.String(),
	})
}

// ================== X 射线配置 ==================

// 处理 GET/POST /api/child/xray/config
func (h *ChildManageHandler) HandleXrayConfig(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getXrayConfig(w, r)
	case http.MethodPost:
		h.setXrayConfig(w, r)
	default:
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ChildManageHandler) getXrayConfig(w http.ResponseWriter, r *http.Request) {
	// 常见的 X 射线配置路径
	configPaths := []string{
		"/usr/local/etc/xray/config.json",
		"/etc/xray/config.json",
		"/opt/xray/config.json",
	}

	var configPath string
	var content []byte
	var err error

	for _, p := range configPaths {
		content, err = os.ReadFile(p)
		if err == nil {
			configPath = p
			break
		}
	}

	if configPath == "" {
		childWriteError(w, http.StatusNotFound, "Xray config not found")
		return
	}

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"path":    configPath,
		"config":  string(content),
	})
}

func (h *ChildManageHandler) setXrayConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config string `json:"config"`
		Path   string `json:"path,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// 验证 JSON
	var js json.RawMessage
	if err := json.Unmarshal([]byte(req.Config), &js); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid JSON config")
		return
	}
	if err := h.lockXrayConfigMutation(); err != nil {
		childWriteError(w, http.StatusConflict, fmt.Sprintf("Inbound mutation recovery must complete before replacing Xray config: %v", err))
		return
	}
	defer h.unlockXrayConfigMutation()

	// 确定配置路径
	configPath := req.Path
	if configPath == "" {
		configPath = "/usr/local/etc/xray/config.json"
	}

	// 确保目录存在
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create directory: %v", err))
		return
	}

	// 写入配置
	if err := os.WriteFile(configPath, []byte(req.Config), 0644); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write config: %v", err))
		return
	}

	log.Printf("[Child Manage] Xray config saved to %s", configPath)

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Config saved successfully",
		"path":    configPath,
	})
}

// ================== X射线系统配置==================

// ChildXraySystemConfig 子服务器的系统配置状态
type ChildXraySystemConfig struct {
	MetricsEnabled bool   `json:"metrics_enabled"`
	MetricsListen  string `json:"metrics_listen"` // 例如 127.0.0.1:38889
	StatsEnabled   bool   `json:"stats_enabled"`
	GrpcEnabled    bool   `json:"grpc_enabled"`
	GrpcPort       int    `json:"grpc_port"` // 例如 46736
}

// 处理 GET/POST /api/child/xray/system-config
func (h *ChildManageHandler) HandleXraySystemConfig(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getXraySystemConfig(w, r)
	case http.MethodPost:
		h.updateXraySystemConfig(w, r)
	default:
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// 获取 Xray 系统配置状态
func (h *ChildManageHandler) getXraySystemConfig(w http.ResponseWriter, r *http.Request) {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		childWriteError(w, http.StatusNotFound, "Xray config not found")
		return
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to read config: %v", err))
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	sysConfig := &ChildXraySystemConfig{
		MetricsListen: "127.0.0.1:38889",
		GrpcPort:      46736,
	}

	// 检查 metrics 配置
	if metrics, ok := config["metrics"].(map[string]interface{}); ok {
		sysConfig.MetricsEnabled = true
		if listen, ok := metrics["listen"].(string); ok {
			sysConfig.MetricsListen = listen
		}
	}

	// 检查 stats 配置
	if _, ok := config["stats"]; ok {
		sysConfig.StatsEnabled = true
	}

	// 检查 api/grpc 配置
	if api, ok := config["api"].(map[string]interface{}); ok {
		if _, hasTag := api["tag"]; hasTag {
			sysConfig.GrpcEnabled = true
		}
	}

	// 查找 api inbound 端口
	if inbounds, ok := config["inbounds"].([]interface{}); ok {
		for _, ib := range inbounds {
			if inbound, ok := ib.(map[string]interface{}); ok {
				if tag, _ := inbound["tag"].(string); tag == "api" {
					if port, ok := inbound["port"].(float64); ok {
						sysConfig.GrpcPort = int(port)
					}
					break
				}
			}
		}
	}

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"config":  sysConfig,
	})
}

// 更新 Xray 系统配置
func (h *ChildManageHandler) updateXraySystemConfig(w http.ResponseWriter, r *http.Request) {
	var req ChildXraySystemConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := h.lockXrayConfigMutation(); err != nil {
		childWriteError(w, http.StatusConflict, fmt.Sprintf("Inbound mutation recovery must complete before updating Xray system config: %v", err))
		return
	}
	defer h.unlockXrayConfigMutation()

	configPath := h.findXrayConfigPath()
	if configPath == "" {
		childWriteError(w, http.StatusNotFound, "Xray config not found")
		return
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to read config: %v", err))
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	// 更新 metrics 配置
	if req.MetricsEnabled {
		config["metrics"] = map[string]interface{}{
			"tag":    "Metrics",
			"listen": req.MetricsListen,
		}
	} else {
		delete(config, "metrics")
	}

	// 更新 stats 配置
	if req.StatsEnabled {
		config["stats"] = map[string]interface{}{}
		// 同时更新 policy
		config["policy"] = map[string]interface{}{
			"levels": map[string]interface{}{
				"0": map[string]interface{}{
					"handshake":         float64(5),
					"connIdle":          float64(300),
					"uplinkOnly":        float64(2),
					"downlinkOnly":      float64(2),
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
			"system": map[string]interface{}{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		}
	} else {
		delete(config, "stats")
		delete(config, "policy")
	}

	// 更新 api/grpc 配置
	if req.GrpcEnabled {
		config["api"] = map[string]interface{}{
			"tag":      "api",
			"services": []interface{}{"HandlerService", "LoggerService", "StatsService", "RoutingService"},
		}

		// 确保有 api inbound
		hasAPIInbound := false
		if inbounds, ok := config["inbounds"].([]interface{}); ok {
			for i, ib := range inbounds {
				if inbound, ok := ib.(map[string]interface{}); ok {
					if tag, _ := inbound["tag"].(string); tag == "api" {
						// 更新端口
						inbound["port"] = float64(req.GrpcPort)
						inbounds[i] = inbound
						hasAPIInbound = true
						break
					}
				}
			}
			if !hasAPIInbound {
				// 添加 api inbound
				apiInbound := map[string]interface{}{
					"tag":      "api",
					"port":     float64(req.GrpcPort),
					"listen":   "127.0.0.1",
					"protocol": "tunnel",
					"settings": map[string]interface{}{
						"address": "127.0.0.1",
					},
				}
				config["inbounds"] = append([]interface{}{apiInbound}, inbounds...)
			}
		} else {
			// 创建 inbounds
			config["inbounds"] = []interface{}{
				map[string]interface{}{
					"tag":      "api",
					"port":     float64(req.GrpcPort),
					"listen":   "127.0.0.1",
					"protocol": "tunnel",
					"settings": map[string]interface{}{
						"address": "127.0.0.1",
					},
				},
			}
		}

		// 确保有 api routing rule
		h.ensureAPIRoutingRule(config)
	} else {
		delete(config, "api")
		// 移除 api inbound
		if inbounds, ok := config["inbounds"].([]interface{}); ok {
			newInbounds := make([]interface{}, 0)
			for _, ib := range inbounds {
				if inbound, ok := ib.(map[string]interface{}); ok {
					if tag, _ := inbound["tag"].(string); tag != "api" {
						newInbounds = append(newInbounds, inbound)
					}
				}
			}
			config["inbounds"] = newInbounds
		}
		// 移除 api routing rule
		h.removeAPIRoutingRule(config)
	}

	// 备份并保存
	backupPath := configPath + ".backup"
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		log.Printf("[Child Manage] Warning: failed to backup config: %v", err)
	}

	newContent, _ := json.MarshalIndent(config, "", "    ")
	if err := os.WriteFile(configPath, newContent, 0644); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write config: %v", err))
		return
	}

	// Keep config persistence and the restart in one exclusion domain.
	output, err := h.controlXrayServiceLocked("restart")
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to restart Xray after system config update: %v - %s", err, strings.TrimSpace(string(output))))
		return
	}

	log.Printf("[Child Manage] Xray system config updated: metrics=%v, stats=%v, grpc=%v",
		req.MetricsEnabled, req.StatsEnabled, req.GrpcEnabled)

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "System config updated, Xray restarted",
	})
}

// 确保存在 api 路由规则
func (h *ChildManageHandler) ensureAPIRoutingRule(config map[string]interface{}) {
	routing, ok := config["routing"].(map[string]interface{})
	if !ok {
		routing = map[string]interface{}{
			"domainStrategy": "IPIfNonMatch",
			"rules":          []interface{}{},
		}
		config["routing"] = routing
	}

	rules, ok := routing["rules"].([]interface{})
	if !ok {
		rules = []interface{}{}
	}

	// 检查是否已存在 api 规则
	for _, r := range rules {
		if rule, ok := r.(map[string]interface{}); ok {
			if outboundTag, _ := rule["outboundTag"].(string); outboundTag == "api" {
				return // 已存在
			}
		}
	}

	// 添加 api 规则到开头
	apiRule := map[string]interface{}{
		"type":        "field",
		"inboundTag":  []interface{}{"api"},
		"outboundTag": "api",
	}
	routing["rules"] = append([]interface{}{apiRule}, rules...)
}

// 移除 api 路由规则
func (h *ChildManageHandler) removeAPIRoutingRule(config map[string]interface{}) {
	routing, ok := config["routing"].(map[string]interface{})
	if !ok {
		return
	}

	rules, ok := routing["rules"].([]interface{})
	if !ok {
		return
	}

	newRules := make([]interface{}, 0)
	for _, r := range rules {
		if rule, ok := r.(map[string]interface{}); ok {
			if outboundTag, _ := rule["outboundTag"].(string); outboundTag != "api" {
				newRules = append(newRules, rule)
			}
		}
	}
	routing["rules"] = newRules
}

// ================== Nginx 安装 ==================

// 处理 POST /api/child/nginx/install
func (h *ChildManageHandler) HandleNginxInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	log.Printf("[Child Manage] Installing Nginx...")

	// 检测包管理器并安装
	var cmd *exec.Cmd
	if _, err := exec.LookPath("apt-get"); err == nil {
		cmd = exec.Command("bash", "-c", "apt-get update && apt-get install -y nginx")
	} else if _, err := exec.LookPath("yum"); err == nil {
		cmd = exec.Command("bash", "-c", "yum install -y nginx")
	} else if _, err := exec.LookPath("dnf"); err == nil {
		cmd = exec.Command("bash", "-c", "dnf install -y nginx")
	} else {
		childWriteError(w, http.StatusInternalServerError, "No supported package manager found")
		return
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("[Child Manage] Nginx installation failed: %v, stderr: %s", err, stderr.String())
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Installation failed: %v", err))
		return
	}

	log.Printf("[Child Manage] Nginx installed successfully")

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Nginx installed successfully",
		"output":  stdout.String(),
	})
}

// 处理 POST /api/child/nginx/remove
func (h *ChildManageHandler) HandleNginxRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	log.Printf("[Child Manage] Removing Nginx...")

	// 首先停止nginx
	exec.Command("systemctl", "stop", "nginx").Run()

	// 检测包管理器并删除
	var cmd *exec.Cmd
	if _, err := exec.LookPath("apt-get"); err == nil {
		cmd = exec.Command("bash", "-c", "apt-get remove -y nginx nginx-common")
	} else if _, err := exec.LookPath("yum"); err == nil {
		cmd = exec.Command("bash", "-c", "yum remove -y nginx")
	} else if _, err := exec.LookPath("dnf"); err == nil {
		cmd = exec.Command("bash", "-c", "dnf remove -y nginx")
	} else {
		childWriteError(w, http.StatusInternalServerError, "No supported package manager found")
		return
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("[Child Manage] Nginx removal failed: %v, stderr: %s", err, stderr.String())
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Removal failed: %v", err))
		return
	}

	log.Printf("[Child Manage] Nginx removed successfully")

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Nginx removed successfully",
		"output":  stdout.String(),
	})
}

// ================== Nginx 配置 ==================

// 处理 GET/POST /api/child/nginx/config
func (h *ChildManageHandler) HandleNginxConfig(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getNginxConfig(w, r)
	case http.MethodPost:
		h.setNginxConfig(w, r)
	default:
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ChildManageHandler) getNginxConfig(w http.ResponseWriter, r *http.Request) {
	// 常见的 nginx 配置路径
	configPaths := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/nginx.conf",
	}

	var configPath string
	var content []byte
	var err error

	for _, p := range configPaths {
		content, err = os.ReadFile(p)
		if err == nil {
			configPath = p
			break
		}
	}

	if configPath == "" {
		childWriteError(w, http.StatusNotFound, "Nginx config not found")
		return
	}

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"path":    configPath,
		"config":  string(content),
	})
}

func (h *ChildManageHandler) setNginxConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config string `json:"config"`
		Path   string `json:"path,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// 确定配置路径
	configPath := req.Path
	if configPath == "" {
		configPath = "/etc/nginx/nginx.conf"
	}

	// 备份现有配置
	backupPath := configPath + ".bak." + time.Now().Format("20060102150405")
	if content, err := os.ReadFile(configPath); err == nil {
		os.WriteFile(backupPath, content, 0644)
	}

	// 写入配置
	if err := os.WriteFile(configPath, []byte(req.Config), 0644); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write config: %v", err))
		return
	}

	// 测试 nginx 配置
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 恢复备份
		if backup, err := os.ReadFile(backupPath); err == nil {
			os.WriteFile(configPath, backup, 0644)
		}
		childWriteError(w, http.StatusBadRequest, fmt.Sprintf("Invalid nginx config: %s", string(output)))
		return
	}

	log.Printf("[Child Manage] Nginx config saved to %s", configPath)

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Config saved successfully",
		"path":    configPath,
	})
}

// ==================系统信息==================

// 处理 GET /api/child/system/info
func (h *ChildManageHandler) HandleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	info := map[string]interface{}{
		"success": true,
	}

	// 获取主机名
	if hostname, err := os.Hostname(); err == nil {
		info["hostname"] = hostname
	}

	// 获得正常运行时间
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			info["uptime"] = parts[0]
		}
	}

	// 获取内存信息
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		memInfo := make(map[string]string)
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if key == "MemTotal" || key == "MemFree" || key == "MemAvailable" {
					memInfo[key] = value
				}
			}
		}
		info["memory"] = memInfo
	}

	// 获取平均负载
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		info["loadavg"] = strings.TrimSpace(string(data))
	}

	childWriteJSON(w, http.StatusOK, info)
}

// ================== 配置文件管理 ==================

// ConfigFileInfo 表示配置文件条目
type ConfigFileInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

// 处理列出和管理 xray 配置文件
func (h *ChildManageHandler) HandleXrayConfigFiles(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		file := r.URL.Query().Get("file")
		if file != "" {
			h.getXrayConfigFile(w, r, file)
		} else {
			h.listXrayConfigFiles(w, r)
		}
	case http.MethodPut, http.MethodPost:
		h.saveXrayConfigFile(w, r)
	default:
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ChildManageHandler) listXrayConfigFiles(w http.ResponseWriter, r *http.Request) {
	// 常见的 xray 配置目录
	configDirs := []string{
		"/usr/local/etc/xray",
		"/etc/xray",
		"/opt/xray",
	}

	var files []ConfigFileInfo
	var baseDir string

	for _, dir := range configDirs {
		if _, err := os.Stat(dir); err == nil {
			baseDir = dir
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				// 只显示json文件
				if !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				info, err := entry.Info()
				if err != nil {
					continue
				}
				files = append(files, ConfigFileInfo{
					Name:    entry.Name(),
					Path:    filepath.Join(dir, entry.Name()),
					Size:    info.Size(),
					ModTime: info.ModTime().Format(time.RFC3339),
				})
			}
			break
		}
	}

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"base_dir": baseDir,
		"files":    files,
	})
}

func (h *ChildManageHandler) getXrayConfigFile(w http.ResponseWriter, r *http.Request, file string) {
	// 清理文件路径
	file = filepath.Clean(file)

	// 常见的 xray 配置目录
	configDirs := []string{
		"/usr/local/etc/xray",
		"/etc/xray",
		"/opt/xray",
	}

	var filePath string
	for _, dir := range configDirs {
		candidate := filepath.Join(dir, file)
		// 确保该文件位于 config 目录中
		if !strings.HasPrefix(candidate, dir) {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			filePath = candidate
			break
		}
	}

	if filePath == "" {
		childWriteError(w, http.StatusNotFound, "File not found")
		return
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to read file: %v", err))
		return
	}

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"path":    filePath,
		"content": string(content),
	})
}

func (h *ChildManageHandler) saveXrayConfigFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File    string `json:"file"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.File == "" {
		childWriteError(w, http.StatusBadRequest, "File name required")
		return
	}
	if err := h.lockXrayConfigMutation(); err != nil {
		childWriteError(w, http.StatusConflict, fmt.Sprintf("Inbound mutation recovery must complete before saving Xray config files: %v", err))
		return
	}
	defer h.unlockXrayConfigMutation()

	// 清理文件名
	req.File = filepath.Base(req.File)
	if !strings.HasSuffix(req.File, ".json") {
		req.File += ".json"
	}

	// 找到配置目录
	configDirs := []string{
		"/usr/local/etc/xray",
		"/etc/xray",
		"/opt/xray",
	}

	var configDir string
	for _, dir := range configDirs {
		if _, err := os.Stat(dir); err == nil {
			configDir = dir
			break
		}
	}

	if configDir == "" {
		// 创建默认目录
		configDir = "/usr/local/etc/xray"
		if err := os.MkdirAll(configDir, 0755); err != nil {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create config directory: %v", err))
			return
		}
	}

	filePath := filepath.Join(configDir, req.File)

	// 验证 JSON 如果它是 json 文件
	if strings.HasSuffix(req.File, ".json") {
		var js json.RawMessage
		if err := json.Unmarshal([]byte(req.Content), &js); err != nil {
			childWriteError(w, http.StatusBadRequest, "Invalid JSON content")
			return
		}
	}

	if err := os.WriteFile(filePath, []byte(req.Content), 0644); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write file: %v", err))
		return
	}

	log.Printf("[Child Manage] Xray config file saved: %s", filePath)

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "File saved successfully",
		"path":    filePath,
	})
}

// 处理列出和管理 nginx 配置文件
func (h *ChildManageHandler) HandleNginxConfigFiles(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		file := r.URL.Query().Get("file")
		if file != "" {
			h.getNginxConfigFile(w, r, file)
		} else {
			h.listNginxConfigFiles(w, r)
		}
	case http.MethodPut, http.MethodPost:
		h.saveNginxConfigFile(w, r)
	default:
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ChildManageHandler) listNginxConfigFiles(w http.ResponseWriter, r *http.Request) {
	// 常见的 nginx 配置目录
	configDirs := []struct {
		dir         string
		description string
	}{
		{"/etc/nginx", "main"},
		{"/etc/nginx/sites-available", "sites-available"},
		{"/etc/nginx/sites-enabled", "sites-enabled"},
		{"/etc/nginx/conf.d", "conf.d"},
	}

	result := make(map[string][]ConfigFileInfo)

	for _, cd := range configDirs {
		if _, err := os.Stat(cd.dir); err != nil {
			continue
		}
		entries, err := os.ReadDir(cd.dir)
		if err != nil {
			continue
		}

		var files []ConfigFileInfo
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			files = append(files, ConfigFileInfo{
				Name:    entry.Name(),
				Path:    filepath.Join(cd.dir, entry.Name()),
				Size:    info.Size(),
				ModTime: info.ModTime().Format(time.RFC3339),
			})
		}
		result[cd.description] = files
	}

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"files":   result,
	})
}

func (h *ChildManageHandler) getNginxConfigFile(w http.ResponseWriter, r *http.Request, file string) {
	// 清理文件路径
	file = filepath.Clean(file)

	// 常见的 nginx 配置目录
	allowedDirs := []string{
		"/etc/nginx",
		"/etc/nginx/sites-available",
		"/etc/nginx/sites-enabled",
		"/etc/nginx/conf.d",
		"/usr/local/nginx/conf",
	}

	var filePath string

	// 如果文件是绝对路径，请检查它是否位于允许的目录中
	if filepath.IsAbs(file) {
		for _, dir := range allowedDirs {
			if strings.HasPrefix(file, dir) {
				if _, err := os.Stat(file); err == nil {
					filePath = file
					break
				}
			}
		}
	} else {
		// 尝试在允许的目录中查找该文件
		for _, dir := range allowedDirs {
			candidate := filepath.Join(dir, file)
			if _, err := os.Stat(candidate); err == nil {
				filePath = candidate
				break
			}
		}
	}

	if filePath == "" {
		childWriteError(w, http.StatusNotFound, "File not found")
		return
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to read file: %v", err))
		return
	}

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"path":    filePath,
		"content": string(content),
	})
}

func (h *ChildManageHandler) saveNginxConfigFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		childWriteError(w, http.StatusBadRequest, "File path required")
		return
	}

	// 清理路径
	req.Path = filepath.Clean(req.Path)

	// 检查路径是否在允许的目录中
	allowedDirs := []string{
		"/etc/nginx",
		"/usr/local/nginx/conf",
	}

	allowed := false
	for _, dir := range allowedDirs {
		if strings.HasPrefix(req.Path, dir) {
			allowed = true
			break
		}
	}

	if !allowed {
		childWriteError(w, http.StatusForbidden, "Path not allowed")
		return
	}

	// 备份现有文件
	if _, err := os.Stat(req.Path); err == nil {
		backupPath := req.Path + ".bak." + time.Now().Format("20060102150405")
		if content, err := os.ReadFile(req.Path); err == nil {
			os.WriteFile(backupPath, content, 0644)
		}
	}

	// 确保目录存在
	dir := filepath.Dir(req.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create directory: %v", err))
		return
	}

	if err := os.WriteFile(req.Path, []byte(req.Content), 0644); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write file: %v", err))
		return
	}

	// 测试 nginx 配置
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 恢复备份
		backupPath := req.Path + ".bak." + time.Now().Format("20060102150405")[:14]
		if backup, err := os.ReadFile(backupPath); err == nil {
			os.WriteFile(req.Path, backup, 0644)
		}
		childWriteError(w, http.StatusBadRequest, fmt.Sprintf("Invalid nginx config: %s", string(output)))
		return
	}

	log.Printf("[Child Manage] Nginx config file saved: %s", req.Path)

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "File saved successfully",
		"path":    req.Path,
	})
}

// ================== X 射线入库管理 ==================

// ChildInboundRequest 表示入站管理请求
type ChildInboundRequest struct {
	Action                string                 `json:"action"` // “添加”、“删除”、“列表”
	Inbound               map[string]interface{} `json:"inbound,omitempty"`
	Tag                   string                 `json:"tag,omitempty"`
	MutationID            string                 `json:"mutation_id,omitempty"`
	ExpectedMutationOwner *string                `json:"expected_mutation_owner,omitempty"`
	ExpectedInboundDigest string                 `json:"expected_inbound_digest,omitempty"`
	Client                map[string]interface{} `json:"client,omitempty"`
	NotAfter              *time.Time             `json:"not_after,omitempty"`
}

// HandleInbounds 处理子服务器的入站管理
// GET：列出所有入站
// POST：添加/删除入站
func (h *ChildManageHandler) HandleInbounds(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listInbounds(w, r)
	case http.MethodPost:
		h.manageInbound(w, r)
	default:
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ChildManageHandler) listInbounds(w http.ResponseWriter, r *http.Request) {
	h.inboundsMu.Lock()
	defer h.inboundsMu.Unlock()
	if err := h.recoverPendingInboundMutationsWithRuntimeLocked(); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to recover inbound mutation ownership: %v", err))
		return
	}
	// 1. 从配置文件读取入站
	configInbounds := h.getInboundsFromConfig()

	// 2. 从 gRPC 运行时读取入站 tags
	runtimeTags := h.getInboundTagsFromGRPC()

	// 3. 合并：以配置文件为基础，标记运行时状态
	mergedInbounds := h.mergeInbounds(configInbounds, runtimeTags)
	for _, inbound := range mergedInbounds {
		tag, _ := inbound["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		// This authenticated inventory evidence lets the control plane recover
		// ownership after upgrading or restoring its database. The explicit known
		// bit distinguishes a new Agent with no owner from an old Agent that never
		// implemented mutation fencing.
		inbound["_mutation_fence_known"] = true
		if owner := strings.TrimSpace(h.inboundMutationFences[tag].Owner); owner != "" {
			inbound["_mutation_id"] = owner
		}
	}
	mutationOwners := make(map[string]string)
	for tag, state := range h.inboundMutationFences {
		if owner := strings.TrimSpace(state.Owner); owner != "" {
			mutationOwners[tag] = owner
		}
	}

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":              true,
		"inbounds":             mergedInbounds,
		"mutation_fence_known": true,
		"mutation_owners":      mutationOwners,
	})
}

// recoverPendingInboundMutationsWithRuntimeLocked first forces the Xray
// runtime to match its durable config, then commits or restores the owner in
// the WAL. Clearing pending before this convergence would expose an owner for
// a different runtime generation after a runtime-first crash.
func (h *ChildManageHandler) recoverPendingInboundMutationsWithRuntimeLocked() error {
	if err := h.loadInboundMutationFencesLocked(); err != nil {
		return err
	}
	hasPending := false
	for _, state := range h.inboundMutationFences {
		if state.Pending != nil {
			hasPending = true
			break
		}
	}
	if !hasPending {
		return nil
	}

	apiPort := h.findXrayAPIPort()
	if apiPort == 0 {
		return fmt.Errorf("Xray API not available for inbound mutation recovery")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clients, err := client.New(ctx, "127.0.0.1", uint16(apiPort))
	if err != nil {
		return fmt.Errorf("connect to Xray for inbound mutation recovery: %w", err)
	}
	defer clients.Connection.Close()

	return h.resolvePendingInboundMutationsLocked(func(_ string, tag string, inbound map[string]interface{}, present bool) error {
		if present {
			if err := h.addInbound(ctx, clients.Handler, inbound); err != nil {
				return fmt.Errorf("restore durable inbound %s: %w", tag, err)
			}
		} else if err := h.removeInbound(ctx, clients.Handler, tag); err != nil && !isInboundRuntimeAbsentError(err) {
			return fmt.Errorf("remove non-durable inbound %s: %w", tag, err)
		}
		if err := h.reconcileInboundFirewall(); err != nil {
			return fmt.Errorf("synchronize firewall with durable inbound config: %w", err)
		}
		return nil
	})
}

// 从配置文件读取入站列表
func (h *ChildManageHandler) getInboundsFromConfig() []map[string]interface{} {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return nil
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("[Child Manage] Failed to read config file: %v", err)
		return nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		log.Printf("[Child Manage] Failed to parse config: %v", err)
		return nil
	}

	rawInbounds, _ := config["inbounds"].([]interface{})
	inbounds := make([]map[string]interface{}, 0, len(rawInbounds))
	for _, ib := range rawInbounds {
		if ibMap, ok := ib.(map[string]interface{}); ok {
			inbounds = append(inbounds, ibMap)
		}
	}
	return inbounds
}

func (h *ChildManageHandler) getInboundFromConfig(tag string) (map[string]interface{}, error) {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return nil, fmt.Errorf("Xray config file not found")
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Xray config: %w", err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("failed to parse Xray config: %w", err)
	}
	rawInbounds, ok := config["inbounds"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("Xray config has no inbounds array")
	}
	for _, raw := range rawInbounds {
		inbound, _ := raw.(map[string]interface{})
		if inboundTag, _ := inbound["tag"].(string); inboundTag == tag {
			return inbound, nil
		}
	}
	return nil, nil
}

func cloneInboundConfig(inbound map[string]interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(inbound)
	if err != nil {
		return nil, err
	}
	var cloned map[string]interface{}
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, err
	}
	return cloned, nil
}

func inboundClientListKey(protocol string, settings map[string]interface{}) (string, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	preferred := ""
	switch protocol {
	case "vless", "vmess", "trojan", "shadowsocks", "ss", "hysteria", "hysteria2", "hy2":
		preferred = "clients"
	case "anytls", "snell":
		preferred = "users"
	case "socks", "http":
		preferred = "accounts"
	}
	if preferred != "" {
		if _, exists := settings[preferred]; exists {
			return preferred, nil
		}
	}
	for _, key := range []string{"clients", "users", "accounts"} {
		if _, exists := settings[key]; exists {
			return key, nil
		}
	}
	if preferred == "" {
		return "", fmt.Errorf("protocol %s does not support managed clients", protocol)
	}
	return preferred, nil
}

func inboundCredentialPrimaryKey(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vless", "vmess":
		return "id"
	case "trojan", "anytls", "shadowsocks", "ss":
		return "password"
	case "snell":
		return "psk"
	case "hysteria", "hysteria2", "hy2":
		return "auth"
	case "socks", "http":
		return "user"
	default:
		return ""
	}
}

func nonEmptyCredentialValue(client map[string]interface{}, key string) string {
	if key == "" {
		return ""
	}
	value, exists := client[key]
	if !exists || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func managedClientExpirationIdentity(protocol string, client map[string]interface{}) (string, string, error) {
	if email := nonEmptyCredentialValue(client, "email"); email != "" {
		return "email", email, nil
	}
	primaryKey := inboundCredentialPrimaryKey(protocol)
	if primaryKey == "" {
		return "", "", fmt.Errorf("protocol %s does not support managed clients", strings.TrimSpace(protocol))
	}
	value := nonEmptyCredentialValue(client, primaryKey)
	if value == "" {
		return "", "", fmt.Errorf("client has no usable identity")
	}
	return primaryKey, value, nil
}

func managedClientExpirationKey(tag, identityKey, identityValue string) string {
	return strings.TrimSpace(tag) + "\x00" + identityKey + "\x00" + identityValue
}

func (entry managedClientExpiration) key() string {
	return managedClientExpirationKey(entry.Tag, entry.IdentityKey, entry.IdentityValue)
}

func (entry managedClientExpiration) clientIdentity() map[string]interface{} {
	return map[string]interface{}{entry.IdentityKey: entry.IdentityValue}
}

func newManagedClientExpiration(tag, protocol string, client map[string]interface{}, notAfter time.Time) (managedClientExpiration, error) {
	tag = strings.TrimSpace(tag)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if tag == "" {
		return managedClientExpiration{}, fmt.Errorf("inbound tag is required")
	}
	if notAfter.IsZero() {
		return managedClientExpiration{}, fmt.Errorf("not_after is required")
	}
	identityKey, identityValue, err := managedClientExpirationIdentity(protocol, client)
	if err != nil {
		return managedClientExpiration{}, err
	}
	return managedClientExpiration{
		Tag:           tag,
		Protocol:      protocol,
		IdentityKey:   identityKey,
		IdentityValue: identityValue,
		NotAfter:      notAfter.UTC(),
	}, nil
}

func cloneManagedClientExpirations(entries map[string]managedClientExpiration) map[string]managedClientExpiration {
	cloned := make(map[string]managedClientExpiration, len(entries))
	for key, entry := range entries {
		cloned[key] = entry
	}
	return cloned
}

func setManagedClientExpiration(entries map[string]managedClientExpiration, tag, protocol string, client map[string]interface{}, notAfter *time.Time) (bool, error) {
	identityKey, identityValue, err := managedClientExpirationIdentity(protocol, client)
	if err != nil {
		return false, err
	}
	key := managedClientExpirationKey(tag, identityKey, identityValue)
	if notAfter == nil {
		if _, exists := entries[key]; !exists {
			return false, nil
		}
		delete(entries, key)
		return true, nil
	}
	entry, err := newManagedClientExpiration(tag, protocol, client, *notAfter)
	if err != nil {
		return false, err
	}
	if existing, exists := entries[key]; exists && existing == entry {
		return false, nil
	}
	entries[key] = entry
	return true, nil
}

func managedClientExpirationSidecarPath(configPath string) string {
	if strings.TrimSpace(configPath) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), managedClientExpirySidecarName)
}

func validateManagedClientExpiration(entry managedClientExpiration) error {
	if strings.TrimSpace(entry.Tag) == "" || entry.NotAfter.IsZero() || strings.TrimSpace(entry.IdentityValue) == "" {
		return fmt.Errorf("invalid managed client expiration entry")
	}
	protocol := strings.ToLower(strings.TrimSpace(entry.Protocol))
	if inboundCredentialPrimaryKey(protocol) == "" {
		return fmt.Errorf("unsupported managed client expiration protocol")
	}
	if entry.IdentityKey != "email" && entry.IdentityKey != inboundCredentialPrimaryKey(protocol) {
		return fmt.Errorf("invalid managed client expiration identity")
	}
	return nil
}

func loadManagedClientExpirations(path string) (map[string]managedClientExpiration, error) {
	entries := make(map[string]managedClientExpiration)
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}
	var state managedClientExpirationFile
	if err := json.Unmarshal(content, &state); err != nil {
		return nil, fmt.Errorf("parse managed client expirations: %w", err)
	}
	if state.Version != managedClientExpiryVersion {
		return nil, fmt.Errorf("unsupported managed client expiration version %d", state.Version)
	}
	for _, entry := range state.Entries {
		entry.Tag = strings.TrimSpace(entry.Tag)
		entry.Protocol = strings.ToLower(strings.TrimSpace(entry.Protocol))
		entry.IdentityKey = strings.TrimSpace(entry.IdentityKey)
		entry.IdentityValue = strings.TrimSpace(entry.IdentityValue)
		entry.NotAfter = entry.NotAfter.UTC()
		if err := validateManagedClientExpiration(entry); err != nil {
			return nil, err
		}
		entries[entry.key()] = entry
	}
	return entries, nil
}

func managedClientExpirationState(entries map[string]managedClientExpiration) managedClientExpirationFile {
	items := make([]managedClientExpiration, 0, len(entries))
	for _, entry := range entries {
		items = append(items, entry)
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].NotAfter.Equal(items[j].NotAfter) {
			return items[i].NotAfter.Before(items[j].NotAfter)
		}
		return items[i].key() < items[j].key()
	})
	return managedClientExpirationFile{Version: managedClientExpiryVersion, Entries: items}
}

func writeManagedClientExpirations(path string, entries map[string]managedClientExpiration) (returnErr error) {
	content, err := json.MarshalIndent(managedClientExpirationState(entries), "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".managed-client-expirations-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() { _ = os.Remove(tmpPath) }()
	defer func() {
		if !closed {
			if closeErr := tmp.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	if directory, openErr := os.Open(filepath.Dir(path)); openErr == nil {
		if syncErr := directory.Sync(); syncErr != nil {
			_ = directory.Close()
			return syncErr
		}
		if closeErr := directory.Close(); closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func dueManagedClientExpirations(entries map[string]managedClientExpiration, now time.Time) ([]managedClientExpiration, *time.Time) {
	due := make([]managedClientExpiration, 0)
	var next *time.Time
	for _, entry := range entries {
		if !entry.NotAfter.After(now) {
			due = append(due, entry)
			continue
		}
		if next == nil || entry.NotAfter.Before(*next) {
			value := entry.NotAfter
			next = &value
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].NotAfter.Equal(due[j].NotAfter) {
			return due[i].NotAfter.Before(due[j].NotAfter)
		}
		return due[i].key() < due[j].key()
	})
	return due, next
}

func (h *ChildManageHandler) ensureClientExpirationsLoadedLocked(configPath string) error {
	if h.clientExpiryConfigPath == configPath {
		return nil
	}
	sidecarPath := managedClientExpirationSidecarPath(configPath)
	entries, err := loadManagedClientExpirations(sidecarPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(sidecarPath); err == nil {
		if err := os.Chmod(sidecarPath, 0600); err != nil {
			return fmt.Errorf("secure managed client expiration sidecar: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	h.clientExpirations = entries
	h.clientExpiryConfigPath = configPath
	return nil
}

func (h *ChildManageHandler) signalClientExpiryScheduler() {
	select {
	case h.clientExpiryWake <- struct{}{}:
	default:
	}
}

func (h *ChildManageHandler) updateClientExpiration(configPath, tag, protocol string, client map[string]interface{}, notAfter *time.Time) (bool, error) {
	h.clientExpiryMu.Lock()
	defer h.clientExpiryMu.Unlock()
	if err := h.ensureClientExpirationsLoadedLocked(configPath); err != nil {
		return false, err
	}
	next := cloneManagedClientExpirations(h.clientExpirations)
	changed, err := setManagedClientExpiration(next, tag, protocol, client, notAfter)
	if err != nil || !changed {
		return changed, err
	}
	if err := writeManagedClientExpirations(managedClientExpirationSidecarPath(configPath), next); err != nil {
		return false, fmt.Errorf("persist managed client expiration: %w", err)
	}
	h.clientExpirations = next
	h.signalClientExpiryScheduler()
	return true, nil
}

func (h *ChildManageHandler) removeClientExpirationsForTag(configPath, tag string) error {
	h.clientExpiryMu.Lock()
	defer h.clientExpiryMu.Unlock()
	if err := h.ensureClientExpirationsLoadedLocked(configPath); err != nil {
		return err
	}
	next := cloneManagedClientExpirations(h.clientExpirations)
	changed := false
	for key, entry := range next {
		if entry.Tag == tag {
			delete(next, key)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := writeManagedClientExpirations(managedClientExpirationSidecarPath(configPath), next); err != nil {
		return err
	}
	h.clientExpirations = next
	h.signalClientExpiryScheduler()
	return nil
}

func (h *ChildManageHandler) clientExpirationIsCurrent(configPath string, expected managedClientExpiration) (bool, error) {
	h.clientExpiryMu.Lock()
	defer h.clientExpiryMu.Unlock()
	if err := h.ensureClientExpirationsLoadedLocked(configPath); err != nil {
		return false, err
	}
	current, exists := h.clientExpirations[expected.key()]
	return exists && current == expected, nil
}

func (h *ChildManageHandler) removeClientExpirationIfCurrent(configPath string, expected managedClientExpiration) error {
	h.clientExpiryMu.Lock()
	defer h.clientExpiryMu.Unlock()
	if err := h.ensureClientExpirationsLoadedLocked(configPath); err != nil {
		return err
	}
	current, exists := h.clientExpirations[expected.key()]
	if !exists || current != expected {
		return nil
	}
	next := cloneManagedClientExpirations(h.clientExpirations)
	delete(next, expected.key())
	if err := writeManagedClientExpirations(managedClientExpirationSidecarPath(configPath), next); err != nil {
		return err
	}
	h.clientExpirations = next
	h.signalClientExpiryScheduler()
	return nil
}

func (h *ChildManageHandler) clientExpirationSnapshot(configPath string, now time.Time) ([]managedClientExpiration, *time.Time, error) {
	h.clientExpiryMu.Lock()
	defer h.clientExpiryMu.Unlock()
	if err := h.ensureClientExpirationsLoadedLocked(configPath); err != nil {
		return nil, nil, err
	}
	due, next := dueManagedClientExpirations(h.clientExpirations, now)
	return due, next, nil
}

func (h *ChildManageHandler) runManagedClientExpiryScheduler() {
	for {
		wait := 30 * time.Second
		configPath := h.findXrayConfigPath()
		if configPath != "" {
			now := time.Now().UTC()
			due, next, err := h.clientExpirationSnapshot(configPath, now)
			if err != nil {
				log.Printf("[Child Manage] Failed to load managed client expirations: %v", err)
			} else {
				retry := false
				for _, entry := range due {
					if err := h.expireManagedClient(entry); err != nil {
						log.Printf("[Child Manage] Failed to expire managed client for inbound %s: %v", entry.Tag, err)
						retry = true
					}
				}
				if retry {
					wait = 5 * time.Second
				} else if next != nil {
					wait = time.Until(*next)
					if wait < 0 {
						wait = 0
					}
				}
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-h.clientExpiryWake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
}

func (h *ChildManageHandler) expireManagedClient(entry managedClientExpiration) error {
	// Keep the same lock order as HTTP mutations: inbound first, expiry state second.
	h.inboundsMu.Lock()
	defer h.inboundsMu.Unlock()
	if err := h.ensureInboundMutationFencesLocked(); err != nil {
		return fmt.Errorf("inbound mutation recovery must complete before expiring clients: %w", err)
	}

	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return fmt.Errorf("Xray config file not found")
	}
	current, err := h.clientExpirationIsCurrent(configPath, entry)
	if err != nil || !current {
		return err
	}
	inbound, err := h.getInboundFromConfig(entry.Tag)
	if err != nil {
		return err
	}
	if inbound == nil {
		return h.removeClientExpirationIfCurrent(configPath, entry)
	}
	original, err := cloneInboundConfig(inbound)
	if err != nil {
		return err
	}
	changed, err := mutateInboundClient(inbound, entry.clientIdentity(), false)
	if err != nil {
		return err
	}
	if changed {
		apiPort := h.findXrayAPIPort()
		if apiPort == 0 {
			return fmt.Errorf("Xray API not available")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		xrayClients, err := client.New(ctx, "127.0.0.1", uint16(apiPort))
		if err != nil {
			return fmt.Errorf("connect to Xray: %w", err)
		}
		defer xrayClients.Connection.Close()
		if err := h.addInbound(ctx, xrayClients.Handler, inbound); err != nil {
			if rollbackErr := h.addInbound(ctx, xrayClients.Handler, original); rollbackErr != nil {
				log.Printf("[Child Manage] CRITICAL: failed to restore inbound %s after expiry apply failure: %v", entry.Tag, rollbackErr)
			}
			return fmt.Errorf("apply expired client removal: %w", err)
		}
		if err := h.replaceInboundInConfig(inbound); err != nil {
			if rollbackErr := h.addInbound(ctx, xrayClients.Handler, original); rollbackErr != nil {
				log.Printf("[Child Manage] CRITICAL: failed to restore inbound %s after expiry persistence failure: %v", entry.Tag, rollbackErr)
			}
			return fmt.Errorf("persist expired client removal: %w", err)
		}
	}
	if err := h.removeClientExpirationIfCurrent(configPath, entry); err != nil {
		return fmt.Errorf("clear expired client schedule: %w", err)
	}
	return nil
}

func sameInboundClientForAdd(existing, requested map[string]interface{}, protocol string) bool {
	primaryKey := inboundCredentialPrimaryKey(protocol)
	primary := nonEmptyCredentialValue(requested, primaryKey)
	if primary != "" && primary == nonEmptyCredentialValue(existing, primaryKey) {
		return true
	}
	requestedEmail := nonEmptyCredentialValue(requested, "email")
	return requestedEmail != "" && requestedEmail == nonEmptyCredentialValue(existing, "email")
}

func sameInboundClientForRemove(existing, requested map[string]interface{}, protocol string) bool {
	primaryKey := inboundCredentialPrimaryKey(protocol)
	if primary := nonEmptyCredentialValue(requested, primaryKey); primary != "" {
		return primary == nonEmptyCredentialValue(existing, primaryKey)
	}
	requestedEmail := nonEmptyCredentialValue(requested, "email")
	return requestedEmail != "" && requestedEmail == nonEmptyCredentialValue(existing, "email")
}

// mutateInboundClient updates one protocol-specific credential list. It is pure
// apart from mutating inbound and is kept separate so idempotency is testable.
func mutateInboundClient(inbound, requested map[string]interface{}, add bool) (bool, error) {
	protocol, _ := inbound["protocol"].(string)
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		return false, fmt.Errorf("inbound has no settings")
	}
	primaryKey := inboundCredentialPrimaryKey(protocol)
	if nonEmptyCredentialValue(requested, primaryKey) == "" && nonEmptyCredentialValue(requested, "email") == "" {
		return false, fmt.Errorf("client has no usable identity")
	}

	listKey, err := inboundClientListKey(protocol, settings)
	if err != nil {
		return false, err
	}
	var clients []interface{}
	if raw, exists := settings[listKey]; exists && raw != nil {
		var ok bool
		clients, ok = raw.([]interface{})
		if !ok {
			return false, fmt.Errorf("inbound settings.%s is not an array", listKey)
		}
	}

	if add {
		for _, raw := range clients {
			existing, _ := raw.(map[string]interface{})
			if existing != nil && sameInboundClientForAdd(existing, requested, protocol) {
				return false, nil
			}
		}
		settings[listKey] = append(clients, requested)
		inbound["settings"] = settings
		return true, nil
	}

	filtered := make([]interface{}, 0, len(clients))
	changed := false
	for _, raw := range clients {
		existing, _ := raw.(map[string]interface{})
		if existing != nil && sameInboundClientForRemove(existing, requested, protocol) {
			changed = true
			continue
		}
		filtered = append(filtered, raw)
	}
	if changed {
		settings[listKey] = filtered
		inbound["settings"] = settings
	}
	return changed, nil
}

// 从 gRPC 运行时获取入站 tags
func (h *ChildManageHandler) getInboundTagsFromGRPC() []string {
	apiPort := h.findXrayAPIPort()
	if apiPort == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clients, err := client.New(ctx, "127.0.0.1", uint16(apiPort))
	if err != nil {
		log.Printf("[Child Manage] Failed to connect to Xray gRPC: %v", err)
		return nil
	}
	defer clients.Connection.Close()

	resp, err := clients.Handler.ListInbounds(ctx, &command.ListInboundsRequest{IsOnlyTags: true})
	if err != nil {
		log.Printf("[Child Manage] Failed to list inbounds via gRPC: %v", err)
		return nil
	}

	tags := make([]string, 0, len(resp.Inbounds))
	for _, ib := range resp.Inbounds {
		// 过滤掉 tag="api" 和空 tag（Xray 内部入站）
		if ib.Tag != "" && ib.Tag != "api" {
			tags = append(tags, ib.Tag)
		}
	}
	return tags
}

// mergeInbounds 合并配置文件入站和 gRPC 运行时入站
// 以配置文件为基础，gRPC 中存在但配置文件中不存在的入站标记为 runtime_only
func (h *ChildManageHandler) mergeInbounds(configInbounds []map[string]interface{}, runtimeTags []string) []map[string]interface{} {
	// 创建运行时 tags 集合
	runtimeTagSet := make(map[string]bool)
	for _, tag := range runtimeTags {
		runtimeTagSet[tag] = true
	}

	// 创建配置文件 tags 集合
	configTagSet := make(map[string]bool)
	for _, ib := range configInbounds {
		if tag, ok := ib["tag"].(string); ok {
			configTagSet[tag] = true
		}
	}

	// 为配置文件中的入站添加运行时状态
	result := make([]map[string]interface{}, 0, len(configInbounds)+len(runtimeTags))
	for _, ib := range configInbounds {
		tag, _ := ib["tag"].(string)
		// 跳过 tag="api" 的入站（Xray 内部 API 入站）
		if tag == "api" {
			continue
		}
		// 复制 map 避免修改原始数据
		ibCopy := make(map[string]interface{})
		for k, v := range ib {
			ibCopy[k] = v
		}
		// 如果 tag 为空，根据协议和端口生成名称
		if tag == "" {
			protocol, _ := ib["protocol"].(string)
			port := 0
			if p, ok := ib["port"].(float64); ok {
				port = int(p)
			} else if p, ok := ib["port"].(int); ok {
				port = p
			}
			if protocol != "" && port > 0 {
				ibCopy["tag"] = fmt.Sprintf("%s-%d", protocol, port)
				ibCopy["_generated_tag"] = true
			}
		}
		// 标记是否在运行时存在
		if runtimeTagSet[tag] {
			ibCopy["_runtime_status"] = "running"
		} else {
			ibCopy["_runtime_status"] = "not_running"
		}
		ibCopy["_source"] = "config"
		result = append(result, ibCopy)
	}

	// 添加只在运行时存在的入站（配置文件中不存在）
	for _, tag := range runtimeTags {
		if !configTagSet[tag] {
			// 这个入站只存在于运行时，没有持久化到配置文件
			result = append(result, map[string]interface{}{
				"tag":             tag,
				"_runtime_status": "running",
				"_source":         "runtime_only",
				"_warning":        "此入站未持久化到配置文件，重启后将丢失",
			})
		}
	}

	return result
}

func (h *ChildManageHandler) manageInbound(w http.ResponseWriter, r *http.Request) {
	var req ChildInboundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "add"
	}

	// Every inbound mutation is a read-modify-write operation. Serializing them
	// prevents concurrent package or self-service requests from losing clients.
	h.inboundsMu.Lock()
	defer h.inboundsMu.Unlock()
	if action == "add-client" || action == "remove-client" {
		if err := h.ensureInboundMutationFencesLocked(); err != nil {
			childWriteError(w, http.StatusConflict, fmt.Sprintf("Inbound mutation recovery must complete before changing clients: %v", err))
			return
		}
	}
	if action == "remove" {
		if skipRemove, _, err := h.beginInboundMutationLocked(action, &req); err != nil {
			childWriteError(w, http.StatusConflict, err.Error())
			return
		} else if skipRemove {
			response := map[string]interface{}{
				"success":    true,
				"message":    "Inbound removal superseded by a newer mutation",
				"superseded": true,
				"changed":    false,
			}
			if req.MutationID != "" {
				response["mutation_id"] = req.MutationID
			}
			childWriteJSON(w, http.StatusOK, response)
			return
		}
	}

	// 连接到本地 Xray gRPC API
	apiPort := h.findXrayAPIPort()
	if apiPort == 0 {
		childWriteError(w, http.StatusInternalServerError, "Xray API not available")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, err := client.New(ctx, "127.0.0.1", uint16(apiPort))
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to connect to Xray: %v", err))
		return
	}
	defer clients.Connection.Close()

	switch action {
	case "add-client", "remove-client":
		if strings.TrimSpace(req.Tag) == "" {
			childWriteError(w, http.StatusBadRequest, "Tag is required for client actions")
			return
		}
		if req.Client == nil {
			childWriteError(w, http.StatusBadRequest, "Client payload is required")
			return
		}

		inbound, err := h.getInboundFromConfig(req.Tag)
		if err != nil {
			childWriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if inbound == nil {
			childWriteError(w, http.StatusNotFound, fmt.Sprintf("Inbound %s not found", req.Tag))
			return
		}
		configPath := h.findXrayConfigPath()
		if configPath == "" {
			childWriteError(w, http.StatusInternalServerError, "Xray config file not found")
			return
		}

		original, err := cloneInboundConfig(inbound)
		if err != nil {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to clone inbound: %v", err))
			return
		}
		protocol, _ := inbound["protocol"].(string)
		shouldAdd := action == "add-client"
		expiration := req.NotAfter
		if expiration != nil {
			value := expiration.UTC()
			expiration = &value
		}
		if shouldAdd && expiration != nil && !expiration.After(time.Now().UTC()) {
			// A past deadline must never briefly restore access. Treat it as an
			// idempotent removal and clear any obsolete timer.
			shouldAdd = false
			expiration = nil
		}
		if action == "remove-client" {
			expiration = nil
		}
		changed, err := mutateInboundClient(inbound, req.Client, shouldAdd)
		if err != nil {
			childWriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if changed {
			// Validate and replace the runtime inbound first. If persistence fails,
			// restore the prior runtime definition so disk and runtime do not drift.
			if err := h.addInbound(ctx, clients.Handler, inbound); err != nil {
				if rollbackErr := h.addInbound(ctx, clients.Handler, original); rollbackErr != nil {
					log.Printf("[Child Manage] CRITICAL: failed to roll back inbound %s: %v", req.Tag, rollbackErr)
				}
				childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to apply client: %v", err))
				return
			}
			if err := h.replaceInboundInConfig(inbound); err != nil {
				rollbackErr := h.addInbound(ctx, clients.Handler, original)
				if rollbackErr != nil {
					log.Printf("[Child Manage] CRITICAL: failed to roll back inbound %s: %v", req.Tag, rollbackErr)
				}
				childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to persist client: %v", err))
				return
			}
		}

		expiryChanged, expiryErr := h.updateClientExpiration(configPath, req.Tag, protocol, req.Client, expiration)
		if expiryErr != nil {
			// An added client without a durable deadline would violate strict
			// expiry. Restore both runtime and config before reporting failure.
			if changed && shouldAdd {
				if rollbackErr := h.addInbound(ctx, clients.Handler, original); rollbackErr != nil {
					log.Printf("[Child Manage] CRITICAL: failed to roll back inbound %s after expiry persistence failure: %v", req.Tag, rollbackErr)
				}
				if rollbackErr := h.replaceInboundInConfig(original); rollbackErr != nil {
					log.Printf("[Child Manage] CRITICAL: failed to restore config for inbound %s after expiry persistence failure: %v", req.Tag, rollbackErr)
				}
			}
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to persist client expiry: %v", expiryErr))
			return
		}

		response := map[string]interface{}{
			"success":        true,
			"message":        "Client state applied successfully",
			"changed":        changed || expiryChanged,
			"client_changed": changed,
		}
		if expiration != nil {
			response["not_after"] = expiration.Format(time.RFC3339Nano)
		}
		childWriteJSON(w, http.StatusOK, response)

	case "add":
		if req.Inbound == nil {
			childWriteError(w, http.StatusBadRequest, "Inbound payload is required")
			return
		}
		tag, _ := req.Inbound["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			childWriteError(w, http.StatusBadRequest, "Inbound tag is required")
			return
		}
		configPath := h.findXrayConfigPath()
		if configPath == "" {
			childWriteError(w, http.StatusInternalServerError, "Xray config file not found")
			return
		}
		original, err := h.getInboundFromConfig(tag)
		if err != nil {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to inspect existing inbound: %v", err))
			return
		}
		if original != nil {
			original, err = cloneInboundConfig(original)
			if err != nil {
				childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to clone existing inbound: %v", err))
				return
			}
		}

		if err := h.applyInboundAddLocked(ctx, clients.Handler, configPath, &req, original); err != nil {
			status := http.StatusInternalServerError
			var reservationErr *inboundMutationReservationError
			if errors.As(err, &reservationErr) {
				status = http.StatusConflict
			}
			childWriteError(w, status, err.Error())
			return
		}

		response := map[string]interface{}{
			"success": true,
			"message": "Inbound added successfully",
		}
		if req.MutationID != "" {
			response["mutation_id"] = req.MutationID
		}
		childWriteJSON(w, http.StatusOK, response)

	case "remove":
		if req.Tag == "" {
			childWriteError(w, http.StatusBadRequest, "Tag is required for remove action")
			return
		}
		configPath := h.findXrayConfigPath()
		if configPath == "" {
			childWriteError(w, http.StatusInternalServerError, "Xray config file not found")
			return
		}
		original, err := h.getInboundFromConfig(req.Tag)
		if err != nil {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to inspect inbound before removal: %v", err))
			return
		}
		if original != nil {
			original, err = cloneInboundConfig(original)
			if err != nil {
				childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to clone inbound before removal: %v", err))
				return
			}
		}

		// Runtime removal is idempotent. A staged control-plane record may exist
		// even when the remote add never reached Xray; retrying its cleanup must
		// still advance through durable config and mutation-fence cleanup.
		if err := h.removeInbound(ctx, clients.Handler, req.Tag); err != nil && !isInboundRuntimeAbsentError(err) {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to remove inbound: %v", err))
			return
		}

		// 从配置文件中删除
		if err := h.removeInboundFromConfig(req.Tag); err != nil {
			var rollbackErr error
			if original != nil {
				rollbackErr = h.addInbound(ctx, clients.Handler, original)
			}
			if rollbackErr != nil {
				childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to persist inbound removal: %v; failed to restore runtime inbound: %v", err, rollbackErr))
				return
			}
			if original == nil {
				childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to persist inbound removal: %v; runtime inbound was removed but no persisted definition was available to restore", err))
				return
			}
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to persist inbound removal: %v; runtime state restored", err))
			return
		}
		if firewallErr := h.reconcileInboundFirewall(); firewallErr != nil {
			rollbackFailures := make([]string, 0, 3)
			var configRollbackErr error
			if original != nil {
				configRollbackErr = upsertInboundConfigFile(configPath, original)
			}
			if configRollbackErr != nil {
				rollbackFailures = append(rollbackFailures, "config: "+configRollbackErr.Error())
			}

			var runtimeRollbackErr error
			if original != nil {
				rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 10*time.Second)
				runtimeRollbackErr = h.addInbound(rollbackCtx, clients.Handler, original)
				rollbackCancel()
			}
			if runtimeRollbackErr != nil {
				rollbackFailures = append(rollbackFailures, "runtime: "+runtimeRollbackErr.Error())
			}
			if configRollbackErr == nil {
				if rollbackFirewallErr := h.reconcileInboundFirewall(); rollbackFirewallErr != nil {
					rollbackFailures = append(rollbackFailures, "firewall: "+rollbackFirewallErr.Error())
				}
			}
			message := fmt.Sprintf("Failed to synchronize inbound firewall removal: %v", firewallErr)
			if len(rollbackFailures) == 0 {
				message += "; runtime, config, and firewall state restored"
			} else {
				message += "; rollback failures: " + strings.Join(rollbackFailures, "; ")
			}
			childWriteError(w, http.StatusInternalServerError, message)
			return
		}
		if err := h.removeClientExpirationsForTag(configPath, req.Tag); err != nil {
			log.Printf("[Child Manage] Warning: Failed to clear expirations for removed inbound %s: %v", req.Tag, err)
		}
		if err := h.completeInboundMutationRemovalLocked(req.Tag, req.MutationID); err != nil {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to persist inbound mutation fence: %v", err))
			return
		}

		response := map[string]interface{}{
			"success": true,
			"message": "Inbound removed successfully",
		}
		if req.MutationID != "" {
			response["mutation_id"] = req.MutationID
		}
		childWriteJSON(w, http.StatusOK, response)

	default:
		childWriteError(w, http.StatusBadRequest, "Invalid action. Must be 'add', 'remove', 'add-client', or 'remove-client'")
	}
}

type inboundMutationReservationError struct {
	err error
}

func (err *inboundMutationReservationError) Error() string {
	return fmt.Sprintf("Failed to reserve inbound mutation: %v", err.err)
}

func (err *inboundMutationReservationError) Unwrap() error {
	return err.err
}

func (h *ChildManageHandler) applyInboundAddLocked(
	ctx context.Context,
	handlerClient command.HandlerServiceClient,
	configPath string,
	req *ChildInboundRequest,
	original map[string]interface{},
) (returnErr error) {
	fenceTransaction, err := h.beginInboundAddMutationLocked(req, configPath, original)
	if err != nil {
		return &inboundMutationReservationError{err: err}
	}
	defer func() {
		if fenceTransaction == nil || !fenceTransaction.active {
			return
		}
		if rollbackErr := h.rollbackInboundMutationLocked(fenceTransaction); rollbackErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("failed to restore inbound mutation ownership: %w", rollbackErr))
		}
	}()

	tag, _ := req.Inbound["tag"].(string)
	tag = strings.TrimSpace(tag)
	if err := h.addInbound(ctx, handlerClient, req.Inbound); err != nil {
		var rollbackErr error
		if original != nil {
			rollbackErr = h.addInbound(ctx, handlerClient, original)
		} else {
			rollbackErr = h.removeInbound(ctx, handlerClient, tag)
			if isInboundRuntimeAbsentError(rollbackErr) {
				rollbackErr = nil
			}
		}
		if rollbackErr != nil {
			// Runtime ownership is unresolved. Keep pending and let the durable
			// config digest choose the generation after a restart or inventory read.
			fenceTransaction.abandonForRecovery()
			return fmt.Errorf("Failed to add inbound: %v; failed to restore previous runtime inbound: %v", err, rollbackErr)
		}
		return fmt.Errorf("Failed to add inbound: %w", err)
	}

	// Only acknowledge the mutation after the on-disk config is durable. If
	// persistence fails, restore the prior runtime state before returning an
	// error so callers never mistake a restart-unsafe mutation for success.
	if err := upsertInboundConfigFile(configPath, req.Inbound); err != nil {
		if atomicRenameWasApplied(err) {
			// The intended complete config is visible, but directory durability is
			// uncertain. Leave pending so the actual post-crash file decides owner.
			fenceTransaction.abandonForRecovery()
			return fmt.Errorf("Failed to durably persist inbound after config rename: %w", err)
		}
		var rollbackErr error
		if original != nil {
			rollbackErr = h.addInbound(ctx, handlerClient, original)
		} else {
			rollbackErr = h.removeInbound(ctx, handlerClient, tag)
			if isInboundRuntimeAbsentError(rollbackErr) {
				rollbackErr = nil
			}
		}
		if rollbackErr != nil {
			fenceTransaction.abandonForRecovery()
			return fmt.Errorf("Failed to persist inbound: %v; failed to restore runtime state: %v", err, rollbackErr)
		}
		return fmt.Errorf("Failed to persist inbound: %v; runtime state restored", err)
	}
	if firewallErr := h.reconcileInboundFirewall(); firewallErr != nil {
		rollbackFailures := make([]string, 0, 3)
		var configRollbackErr error
		if original != nil {
			configRollbackErr = upsertInboundConfigFile(configPath, original)
		} else {
			configRollbackErr = removeInboundConfigFile(configPath, tag)
		}
		if configRollbackErr != nil {
			rollbackFailures = append(rollbackFailures, "config: "+configRollbackErr.Error())
		}

		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 10*time.Second)
		var runtimeRollbackErr error
		if original != nil {
			runtimeRollbackErr = h.addInbound(rollbackCtx, handlerClient, original)
		} else {
			runtimeRollbackErr = h.removeInbound(rollbackCtx, handlerClient, tag)
			if isInboundRuntimeAbsentError(runtimeRollbackErr) {
				runtimeRollbackErr = nil
			}
		}
		rollbackCancel()
		if runtimeRollbackErr != nil {
			rollbackFailures = append(rollbackFailures, "runtime: "+runtimeRollbackErr.Error())
		}
		if configRollbackErr == nil {
			if rollbackFirewallErr := h.reconcileInboundFirewall(); rollbackFirewallErr != nil {
				rollbackFailures = append(rollbackFailures, "firewall: "+rollbackFirewallErr.Error())
			}
		}
		message := fmt.Sprintf("Failed to synchronize inbound firewall: %v", firewallErr)
		if len(rollbackFailures) == 0 {
			message += "; runtime, config, and firewall state restored"
		} else {
			// At least one side effect is unresolved. The WAL must remain pending;
			// publishing either owner here could authorize a stale deletion.
			fenceTransaction.abandonForRecovery()
			message += "; rollback failures: " + strings.Join(rollbackFailures, "; ")
		}
		return errors.New(message)
	}

	if err := h.commitInboundMutationLocked(fenceTransaction); err != nil {
		return fmt.Errorf("Failed to commit inbound mutation ownership: %w", err)
	}
	return nil
}

// ================== X 射线出库管理 ==================

// ChildOutboundRequest 表示出站管理请求
type ChildOutboundRequest struct {
	Action   string                 `json:"action"` // “添加”、“删除”、“列表”
	Outbound map[string]interface{} `json:"outbound,omitempty"`
	Tag      string                 `json:"tag,omitempty"`
	Tags     []string               `json:"tags,omitempty"` // 重新订购
}

// 处理子服务器的出站管理
func (h *ChildManageHandler) HandleOutbounds(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listOutbounds(w, r)
	case http.MethodPost:
		h.manageOutbound(w, r)
	default:
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ChildManageHandler) listOutbounds(w http.ResponseWriter, r *http.Request) {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		childWriteError(w, http.StatusNotFound, "Xray config not found")
		return
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to read config: %v", err))
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to parse config: %v", err))
		return
	}

	outbounds, _ := config["outbounds"].([]interface{})

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"outbounds": outbounds,
	})
}

func (h *ChildManageHandler) manageOutbound(w http.ResponseWriter, r *http.Request) {
	var req ChildOutboundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "add"
	}
	if err := h.lockXrayConfigMutation(); err != nil {
		childWriteError(w, http.StatusConflict, fmt.Sprintf("Inbound mutation recovery must complete before changing outbounds: %v", err))
		return
	}
	defer h.unlockXrayConfigMutation()

	apiPort := h.findXrayAPIPort()
	if apiPort == 0 {
		childWriteError(w, http.StatusInternalServerError, "Xray API not available")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, err := client.New(ctx, "127.0.0.1", uint16(apiPort))
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to connect to Xray: %v", err))
		return
	}
	defer clients.Connection.Close()

	switch action {
	case "add":
		if req.Outbound == nil {
			childWriteError(w, http.StatusBadRequest, "Outbound payload is required")
			return
		}

		if err := h.addOutbound(ctx, clients.Handler, req.Outbound); err != nil {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to add outbound: %v", err))
			return
		}

		if err := h.persistOutbound(req.Outbound); err != nil {
			log.Printf("[Child Manage] Warning: Failed to persist outbound to config: %v", err)
		}

		childWriteJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Outbound added successfully",
		})

	case "remove":
		if req.Tag == "" {
			childWriteError(w, http.StatusBadRequest, "Tag is required for remove action")
			return
		}

		if err := h.removeOutbound(ctx, clients.Handler, req.Tag); err != nil {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to remove outbound: %v", err))
			return
		}

		if err := h.removeOutboundFromConfig(req.Tag); err != nil {
			log.Printf("[Child Manage] Warning: Failed to remove outbound from config: %v", err)
		}

		childWriteJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Outbound removed successfully",
		})

	default:
		childWriteError(w, http.StatusBadRequest, "Invalid action. Must be 'add' or 'remove'")
	}
}

// ================== X 射线路由管理 ==================

// ChildRoutingRequest代表路由管理请求
type ChildRoutingRequest struct {
	Action  string                 `json:"action"` // “获取”、“设置”、“添加规则”、“删除规则”
	Routing map[string]interface{} `json:"routing,omitempty"`
	Rule    map[string]interface{} `json:"rule,omitempty"`
	Index   int                    `json:"index,omitempty"`
	// 负载均衡 leastPing/leastLoad 的 xray 顶层观测站(balancers 随 Routing 透传)。
	// RawMessage 三态:缺失=不变;JSON null=清除;对象=写入。
	Observatory      json.RawMessage `json:"observatory,omitempty"`
	BurstObservatory json.RawMessage `json:"burstObservatory,omitempty"`
}

// applyObservatory 按 RawMessage 三态把顶层 observatory/burstObservatory 写入/删除/保持。
func applyObservatory(config map[string]interface{}, key string, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	if string(raw) == "null" {
		delete(config, key)
		return
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err == nil {
		config[key] = obj
	}
}

func applyRoutingRulesHot(ctx context.Context, routingClient routercommand.RoutingServiceClient, routing map[string]interface{}) error {
	raw, err := json.Marshal(routing)
	if err != nil {
		return fmt.Errorf("marshal routing config: %w", err)
	}
	var routingConfig conf.RouterConfig
	if err := json.Unmarshal(raw, &routingConfig); err != nil {
		return fmt.Errorf("decode routing config: %w", err)
	}
	built, err := routingConfig.Build()
	if err != nil {
		return fmt.Errorf("build routing config: %w", err)
	}
	message := xserial.ToTypedMessage(built)
	if message == nil {
		return errors.New("build routing typed message")
	}
	if _, err := routingClient.AddRule(ctx, &routercommand.AddRuleRequest{
		Config:       message,
		ShouldAppend: false,
	}); err != nil {
		return fmt.Errorf("replace runtime routing rules: %w", err)
	}
	return nil
}

// 处理子服务器的路由管理
func (h *ChildManageHandler) HandleRouting(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getRouting(w, r)
	case http.MethodPost:
		h.manageRouting(w, r)
	default:
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ChildManageHandler) getRouting(w http.ResponseWriter, r *http.Request) {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		childWriteError(w, http.StatusNotFound, "Xray config not found")
		return
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to read config: %v", err))
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to parse config: %v", err))
		return
	}

	routing, _ := config["routing"].(map[string]interface{})

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"routing": routing,
	})
}

func (h *ChildManageHandler) manageRouting(w http.ResponseWriter, r *http.Request) {
	var req ChildRoutingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		childWriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "set"
	}
	if err := h.lockXrayConfigMutation(); err != nil {
		childWriteError(w, http.StatusConflict, fmt.Sprintf("Inbound mutation recovery must complete before changing routing: %v", err))
		return
	}
	defer h.unlockXrayConfigMutation()

	configPath := h.findXrayConfigPath()
	if configPath == "" {
		childWriteError(w, http.StatusNotFound, "Xray config not found")
		return
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to read config: %v", err))
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to parse config: %v", err))
		return
	}
	originalRouting, _ := config["routing"].(map[string]interface{})
	if originalRouting == nil {
		originalRouting = map[string]interface{}{}
	}
	hotReplace := action == "set_hot"

	switch action {
	case "set", "set_hot":
		if req.Routing == nil {
			childWriteError(w, http.StatusBadRequest, "Routing config is required")
			return
		}
		if hotReplace && (len(req.Observatory) != 0 || len(req.BurstObservatory) != 0) {
			childWriteError(w, http.StatusBadRequest, "set_hot only replaces routing rules")
			return
		}
		config["routing"] = req.Routing
		if !hotReplace {
			applyObservatory(config, "observatory", req.Observatory)
			applyObservatory(config, "burstObservatory", req.BurstObservatory)
		}

	case "add_rule":
		if req.Rule == nil {
			childWriteError(w, http.StatusBadRequest, "Rule is required")
			return
		}
		routing, _ := config["routing"].(map[string]interface{})
		if routing == nil {
			routing = map[string]interface{}{}
		}
		rules, _ := routing["rules"].([]interface{})
		rules = append(rules, req.Rule)
		routing["rules"] = rules
		config["routing"] = routing

	case "remove_rule":
		routing, _ := config["routing"].(map[string]interface{})
		if routing == nil {
			childWriteError(w, http.StatusBadRequest, "No routing config found")
			return
		}
		rules, _ := routing["rules"].([]interface{})
		if req.Index < 0 || req.Index >= len(rules) {
			childWriteError(w, http.StatusBadRequest, "Invalid rule index")
			return
		}
		rules = append(rules[:req.Index], rules[req.Index+1:]...)
		routing["rules"] = rules
		config["routing"] = routing

	default:
		childWriteError(w, http.StatusBadRequest, "Invalid action")
		return
	}

	if hotReplace {
		apiPort := h.findXrayAPIPort()
		if apiPort == 0 {
			childWriteError(w, http.StatusInternalServerError, "Xray API not available")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		clients, err := client.New(ctx, "127.0.0.1", uint16(apiPort))
		if err != nil {
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to connect to Xray routing API: %v", err))
			return
		}
		defer clients.Connection.Close()
		if err := applyRoutingRulesHot(ctx, clients.Routing, req.Routing); err != nil {
			childWriteError(w, http.StatusConflict, fmt.Sprintf("Failed to hot-apply routing rules (upgrade the Xray core if AddRule is unavailable): %v", err))
			return
		}
		if err := writeJSONFileAtomic(configPath, config); err != nil {
			rollbackErr := applyRoutingRulesHot(ctx, clients.Routing, originalRouting)
			if rollbackErr != nil {
				childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to persist routing config: %v; runtime rollback failed: %v", err, rollbackErr))
				return
			}
			childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to persist routing config: %v; runtime rules restored", err))
			return
		}
		childWriteJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Routing updated in runtime and persisted without restarting Xray.",
		})
		return
	}

	// 保存配置
	newContent, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal config: %v", err))
		return
	}

	if err := os.WriteFile(configPath, newContent, 0644); err != nil {
		childWriteError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to write config: %v", err))
		return
	}

	log.Printf("[Child Manage] Routing config updated")

	childWriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Routing updated successfully. Restart Xray to apply changes.",
	})
}

// ================== 辅助函数 ==================

func (h *ChildManageHandler) findXrayConfigPath() string {
	return findChildXrayConfigPath()
}

func findChildXrayConfigPath() string {
	for _, p := range childXrayConfigPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (h *ChildManageHandler) findXrayAPIPort() int {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return 0
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return 0
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return 0
	}

	// 检查 API 入站
	inbounds, ok := config["inbounds"].([]interface{})
	if !ok {
		return 0
	}

	for _, ib := range inbounds {
		inbound, ok := ib.(map[string]interface{})
		if !ok {
			continue
		}
		tag, _ := inbound["tag"].(string)
		if tag == "api" {
			port, ok := inbound["port"].(float64)
			if ok {
				return int(port)
			}
		}
	}

	// 默认API端口
	return 10085
}

func (h *ChildManageHandler) addInbound(ctx context.Context, handlerClient command.HandlerServiceClient, inbound map[string]interface{}) error {
	inboundJSON, err := json.Marshal(inbound)
	if err != nil {
		return fmt.Errorf("failed to marshal inbound: %w", err)
	}

	inboundConfig := &conf.InboundDetourConfig{}
	if err := json.Unmarshal(inboundJSON, inboundConfig); err != nil {
		return fmt.Errorf("failed to unmarshal inbound config: %w", err)
	}

	rawConfig, err := inboundConfig.Build()
	if err != nil {
		return fmt.Errorf("failed to build inbound config: %w", err)
	}

	// 先尝试删除同名的 tag，避免 "existing tag found" 错误
	// 这种情况可能发生在：Xray 运行时存在该 tag，但配置文件中没有
	if tag, ok := inbound["tag"].(string); ok && tag != "" {
		_, _ = handlerClient.RemoveInbound(ctx, &command.RemoveInboundRequest{
			Tag: tag,
		})
		// 忽略删除错误，因为 tag 可能不存在
	}

	_, err = handlerClient.AddInbound(ctx, &command.AddInboundRequest{
		Inbound: rawConfig,
	})
	return err
}

func (h *ChildManageHandler) removeInbound(ctx context.Context, handlerClient command.HandlerServiceClient, tag string) error {
	_, err := handlerClient.RemoveInbound(ctx, &command.RemoveInboundRequest{
		Tag: tag,
	})
	return err
}

func isInboundRuntimeAbsentError(err error) bool {
	if err == nil {
		return false
	}
	if status.Code(err) == codes.NotFound {
		return true
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(message, "not found") ||
		strings.Contains(message, "does not exist") ||
		strings.Contains(message, "not exist")
}

func (h *ChildManageHandler) addOutbound(ctx context.Context, handlerClient command.HandlerServiceClient, outbound map[string]interface{}) error {
	outboundJSON, err := json.Marshal(outbound)
	if err != nil {
		return fmt.Errorf("failed to marshal outbound: %w", err)
	}

	outboundConfig := &conf.OutboundDetourConfig{}
	if err := json.Unmarshal(outboundJSON, outboundConfig); err != nil {
		return fmt.Errorf("failed to unmarshal outbound config: %w", err)
	}

	rawConfig, err := outboundConfig.Build()
	if err != nil {
		return fmt.Errorf("failed to build outbound config: %w", err)
	}

	_, err = handlerClient.AddOutbound(ctx, &command.AddOutboundRequest{
		Outbound: rawConfig,
	})
	return err
}

func (h *ChildManageHandler) removeOutbound(ctx context.Context, handlerClient command.HandlerServiceClient, tag string) error {
	_, err := handlerClient.RemoveOutbound(ctx, &command.RemoveOutboundRequest{
		Tag: tag,
	})
	return err
}

func (h *ChildManageHandler) persistInbound(inbound map[string]interface{}) error {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return fmt.Errorf("config file not found")
	}
	return upsertInboundConfigFile(configPath, inbound)
}

func upsertInboundConfigFile(configPath string, inbound map[string]interface{}) error {
	tag, _ := inbound["tag"].(string)
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return fmt.Errorf("inbound tag is required")
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	inbounds, _ := config["inbounds"].([]interface{})
	updated := make([]interface{}, 0, len(inbounds)+1)
	replaced := false
	for _, raw := range inbounds {
		current, _ := raw.(map[string]interface{})
		currentTag, _ := current["tag"].(string)
		if currentTag != tag {
			updated = append(updated, raw)
			continue
		}
		if !replaced {
			updated = append(updated, inbound)
			replaced = true
		}
		// Drop any additional definitions for the same tag while repairing
		// configurations written by the historical append-only implementation.
	}
	if !replaced {
		updated = append(updated, inbound)
	}
	config["inbounds"] = updated
	if err := writeJSONFileAtomic(configPath, config); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

func (h *ChildManageHandler) replaceInboundInConfig(inbound map[string]interface{}) error {
	tag, _ := inbound["tag"].(string)
	if strings.TrimSpace(tag) == "" {
		return fmt.Errorf("inbound tag is required")
	}
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return fmt.Errorf("config file not found")
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	rawInbounds, ok := config["inbounds"].([]interface{})
	if !ok {
		return fmt.Errorf("config has no inbounds array")
	}
	replaced := false
	updated := make([]interface{}, 0, len(rawInbounds))
	for _, raw := range rawInbounds {
		current, _ := raw.(map[string]interface{})
		currentTag, _ := current["tag"].(string)
		if currentTag != tag {
			updated = append(updated, raw)
			continue
		}
		if !replaced {
			updated = append(updated, inbound)
			replaced = true
		}
		// Drop duplicate definitions for the same tag while repairing the file.
	}
	if !replaced {
		return fmt.Errorf("inbound %s not found", tag)
	}
	config["inbounds"] = updated
	if err := writeJSONFileAtomic(configPath, config); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

func writeJSONFileAtomic(path string, value interface{}) (returnErr error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')

	mode := os.FileMode(0644)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xray-config-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	defer func() {
		if !closed {
			if closeErr := tmp.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := syncRenamedFileDirectory(path); err != nil {
		return &atomicRenameAppliedError{err: err}
	}
	return nil
}

// atomicRenameAppliedError means the target already contains the new complete
// file, but syncing its parent directory failed. Callers must keep memory on
// the new state while withholding success from the remote caller.
type atomicRenameAppliedError struct {
	err error
}

func (err *atomicRenameAppliedError) Error() string { return err.err.Error() }
func (err *atomicRenameAppliedError) Unwrap() error { return err.err }

func atomicRenameWasApplied(err error) bool {
	var applied *atomicRenameAppliedError
	return errors.As(err, &applied)
}

func (h *ChildManageHandler) removeInboundFromConfig(tag string) error {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return fmt.Errorf("config file not found")
	}
	return removeInboundConfigFile(configPath, tag)
}

func removeInboundConfigFile(configPath, tag string) error {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return fmt.Errorf("inbound tag is required")
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	inbounds, _ := config["inbounds"].([]interface{})
	var newInbounds []interface{}
	for _, ib := range inbounds {
		inbound, ok := ib.(map[string]interface{})
		if !ok {
			newInbounds = append(newInbounds, ib)
			continue
		}
		ibTag, _ := inbound["tag"].(string)
		if ibTag != tag {
			newInbounds = append(newInbounds, ib)
		}
	}
	config["inbounds"] = newInbounds
	if err := writeJSONFileAtomic(configPath, config); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

func (h *ChildManageHandler) persistOutbound(outbound map[string]interface{}) error {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return fmt.Errorf("config file not found")
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	outbounds, _ := config["outbounds"].([]interface{})
	outbounds = append(outbounds, outbound)
	config["outbounds"] = outbounds

	newContent, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(configPath, newContent, 0644)
}

func (h *ChildManageHandler) removeOutboundFromConfig(tag string) error {
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		return fmt.Errorf("config file not found")
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	outbounds, _ := config["outbounds"].([]interface{})
	var newOutbounds []interface{}
	for _, ob := range outbounds {
		outbound, ok := ob.(map[string]interface{})
		if !ok {
			newOutbounds = append(newOutbounds, ob)
			continue
		}
		obTag, _ := outbound["tag"].(string)
		if obTag != tag {
			newOutbounds = append(newOutbounds, ob)
		}
	}
	config["outbounds"] = newOutbounds

	newContent, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(configPath, newContent, 0644)
}

// ==================扫描==================

// ChildScanResponse 表示扫描操作的响应
type ChildScanResponse struct {
	Success             bool                     `json:"success"`
	Message             string                   `json:"message"`
	XrayRunning         bool                     `json:"xray_running"`
	XrayVersion         string                   `json:"xray_version,omitempty"`
	APIPort             int                      `json:"api_port,omitempty"`
	ConfigPath          string                   `json:"config_path,omitempty"`
	Inbounds            []map[string]interface{} `json:"inbounds,omitempty"`
	ConfigModified      bool                     `json:"config_modified,omitempty"`
	ConfigAddedSections []string                 `json:"config_added_sections,omitempty"`
}

// 处理 POST /api/child/scan - 扫描 Xray 进程并返回信息
func (h *ChildManageHandler) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		childWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		childWriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	log.Printf("[Child Manage] Scanning for Xray process...")

	// 首先执行配置检查和补全
	configResult := h.EnsureXrayConfig()

	response := ChildScanResponse{
		Success: true,
		Message: "Scan completed",
	}

	// 添加配置检查结果到响应
	if configResult.Modified {
		response.ConfigModified = true
		response.ConfigAddedSections = configResult.AddedSections
		log.Printf("[Child Manage] Xray config auto-completed, added sections: %v", configResult.AddedSections)
		if configResult.Error == "" {
			log.Printf("[Child Manage] Xray restarted after config update")
			time.Sleep(1 * time.Second) // 等待状态探测稳定
		}
	}
	if configResult.Error != "" {
		log.Printf("[Child Manage] Xray config check warning: %s", configResult.Error)
	}

	// 获取 X 射线状态
	xrayStatus := h.getXrayStatus()
	if xrayStatus != nil {
		response.XrayRunning = xrayStatus.Running
		response.XrayVersion = xrayStatus.Version
	}

	// 查找配置和API端口
	configPath := h.findXrayConfigPath()
	if configPath != "" {
		response.ConfigPath = configPath
		response.APIPort = h.findXrayAPIPort()

		// 从配置中读取入站
		content, err := os.ReadFile(configPath)
		if err == nil {
			var config map[string]interface{}
			if json.Unmarshal(content, &config) == nil {
				if inbounds, ok := config["inbounds"].([]interface{}); ok {
					for _, ib := range inbounds {
						if inbound, ok := ib.(map[string]interface{}); ok {
							// 跳过 API 入站
							if tag, _ := inbound["tag"].(string); tag == "api" {
								continue
							}
							response.Inbounds = append(response.Inbounds, inbound)
						}
					}
				}
			}
		}
	}

	if response.XrayRunning {
		response.Message = fmt.Sprintf("Xray is running, found %d inbound(s)", len(response.Inbounds))
		if response.ConfigModified {
			response.Message += fmt.Sprintf(", config updated: added %v", response.ConfigAddedSections)
		}
	} else if xrayStatus != nil && xrayStatus.Installed {
		response.Message = "Xray is installed but not running"
	} else {
		response.Message = "Xray is not installed"
	}

	log.Printf("[Child Manage] Scan result: %s", response.Message)

	childWriteJSON(w, http.StatusOK, response)
}

// ================== Xray 配置自动完成 ==================

// EnsureXrayConfigResult 配置检查结果
type EnsureXrayConfigResult struct {
	ConfigPath    string   `json:"config_path"`
	Modified      bool     `json:"modified"`
	AddedSections []string `json:"added_sections,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// EnsureXrayConfig 检查并补全 Xray 配置
// 确保配置文件包含必要的 api、stats、policy、metrics 配置
// 这是一个公开方法，可以在 main.go 中调用
func (h *ChildManageHandler) EnsureXrayConfig() *EnsureXrayConfigResult {
	result := &EnsureXrayConfigResult{}
	if err := h.lockXrayConfigMutation(); err != nil {
		result.Error = fmt.Sprintf("Inbound mutation recovery must complete before normalizing Xray config: %v", err)
		return result
	}
	defer h.unlockXrayConfigMutation()

	// 1. 查找配置文件路径
	configPath := h.findXrayConfigPath()
	if configPath == "" {
		result.Error = "Xray config not found"
		return result
	}
	result.ConfigPath = configPath

	// 2. 读取现有配置
	content, err := os.ReadFile(configPath)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read config: %v", err)
		return result
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		result.Error = fmt.Sprintf("Invalid JSON: %v", err)
		return result
	}

	// 3. 检查并补全各个配置项
	modified := false

	// 3.1 检查 api 配置
	if _, ok := config["api"]; !ok {
		config["api"] = map[string]interface{}{
			"tag":      "api",
			"services": []interface{}{"HandlerService", "LoggerService", "StatsService", "RoutingService"},
		}
		result.AddedSections = append(result.AddedSections, "api")
		modified = true
	}

	// 3.2 检查 stats 配置
	if _, ok := config["stats"]; !ok {
		config["stats"] = map[string]interface{}{}
		result.AddedSections = append(result.AddedSections, "stats")
		modified = true
	}

	// 3.3 检查 policy 配置
	if !h.hasValidPolicy(config) {
		config["policy"] = h.getTemplatePolicy()
		result.AddedSections = append(result.AddedSections, "policy")
		modified = true
	}

	// 3.4 检查 metrics 配置
	if _, ok := config["metrics"]; !ok {
		config["metrics"] = map[string]interface{}{
			"tag":    "Metrics",
			"listen": "127.0.0.1:38889",
		}
		result.AddedSections = append(result.AddedSections, "metrics")
		modified = true
	}

	// 3.5 检查 api 入站
	if !h.hasAPIInbound(config) {
		h.addAPIInbound(config)
		result.AddedSections = append(result.AddedSections, "api_inbound")
		modified = true
	}

	// 3.6 检查 routing rules 中的 api 规则
	if !h.hasAPIRoutingRule(config) {
		h.addAPIRoutingRule(config)
		result.AddedSections = append(result.AddedSections, "api_routing_rule")
		modified = true
	}

	// 4. 如果有修改，写回配置文件
	if modified {
		// 备份原配置
		backupPath := configPath + ".backup"
		if err := os.WriteFile(backupPath, content, 0644); err != nil {
			log.Printf("[Child Manage] Warning: failed to backup config: %v", err)
		}

		// 写入新配置
		newContent, _ := json.MarshalIndent(config, "", "    ")
		if err := os.WriteFile(configPath, newContent, 0644); err != nil {
			result.Error = fmt.Sprintf("Failed to write config: %v", err)
			return result
		}
		result.Modified = true
		log.Printf("[Child Manage] Xray config updated, added: %v", result.AddedSections)

		// The caller previously restarted after this method released inboundsMu,
		// leaving a window where an inbound mutation could interleave. Restart
		// here while the config write is still protected by the same mutex.
		output, err := h.controlXrayServiceLocked("restart")
		if err != nil {
			result.Error = fmt.Sprintf("Failed to restart Xray after config update: %v - %s", err, strings.TrimSpace(string(output)))
			return result
		}
	}

	return result
}

// 检查 policy 配置是否包含必要的统计配置
func (h *ChildManageHandler) hasValidPolicy(config map[string]interface{}) bool {
	policy, ok := config["policy"].(map[string]interface{})
	if !ok {
		return false
	}

	// 检查 levels.0.statsUserUplink 和 statsUserDownlink
	levels, ok := policy["levels"].(map[string]interface{})
	if !ok {
		return false
	}
	level0, ok := levels["0"].(map[string]interface{})
	if !ok {
		return false
	}

	statsUplink, _ := level0["statsUserUplink"].(bool)
	statsDownlink, _ := level0["statsUserDownlink"].(bool)

	return statsUplink && statsDownlink
}

// 返回模板中的 policy 配置
func (h *ChildManageHandler) getTemplatePolicy() map[string]interface{} {
	return map[string]interface{}{
		"levels": map[string]interface{}{
			"0": map[string]interface{}{
				"handshake":         float64(5),
				"connIdle":          float64(300),
				"uplinkOnly":        float64(2),
				"downlinkOnly":      float64(2),
				"statsUserUplink":   true,
				"statsUserDownlink": true,
			},
		},
		"system": map[string]interface{}{
			"statsInboundUplink":    true,
			"statsInboundDownlink":  true,
			"statsOutboundUplink":   true,
			"statsOutboundDownlink": true,
		},
	}
}

// 检查是否存在 api 入站
func (h *ChildManageHandler) hasAPIInbound(config map[string]interface{}) bool {
	inbounds, ok := config["inbounds"].([]interface{})
	if !ok {
		return false
	}
	for _, ib := range inbounds {
		if inbound, ok := ib.(map[string]interface{}); ok {
			if tag, _ := inbound["tag"].(string); tag == "api" {
				return true
			}
		}
	}
	return false
}

// 添加 api 入站配置
func (h *ChildManageHandler) addAPIInbound(config map[string]interface{}) {
	apiInbound := map[string]interface{}{
		"tag":      "api",
		"port":     float64(46736),
		"listen":   "127.0.0.1",
		"protocol": "tunnel",
		"settings": map[string]interface{}{
			"address": "127.0.0.1",
		},
	}

	inbounds, ok := config["inbounds"].([]interface{})
	if !ok {
		inbounds = []interface{}{}
	}
	config["inbounds"] = append([]interface{}{apiInbound}, inbounds...)
}

// 检查是否存在 api 路由规则
func (h *ChildManageHandler) hasAPIRoutingRule(config map[string]interface{}) bool {
	routing, ok := config["routing"].(map[string]interface{})
	if !ok {
		return false
	}
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		return false
	}
	for _, r := range rules {
		if rule, ok := r.(map[string]interface{}); ok {
			if outboundTag, _ := rule["outboundTag"].(string); outboundTag == "api" {
				return true
			}
		}
	}
	return false
}

// 添加 api 路由规则
func (h *ChildManageHandler) addAPIRoutingRule(config map[string]interface{}) {
	apiRule := map[string]interface{}{
		"type":        "field",
		"inboundTag":  []interface{}{"api"},
		"outboundTag": "api",
	}

	routing, ok := config["routing"].(map[string]interface{})
	if !ok {
		routing = map[string]interface{}{
			"domainStrategy": "IPIfNonMatch",
			"rules":          []interface{}{},
		}
		config["routing"] = routing
	}

	rules, ok := routing["rules"].([]interface{})
	if !ok {
		rules = []interface{}{}
	}
	// 将 api 规则放在最前面
	routing["rules"] = append([]interface{}{apiRule}, rules...)
}
