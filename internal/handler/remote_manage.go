package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/event"
	"miaomiaowux/internal/securechan"
	"miaomiaowux/internal/storage"
	"miaomiaowux/internal/version"
	"miaomiaowux/templates"
)

// RemoteManageHandler 处理需要转发到子服务器的管理请求
type RemoteManageHandler struct {
	repo              *storage.TrafficRepository
	wsHandler         *RemoteWSHandler
	httpClient        *http.Client
	certHandler       *CertificateHandler
	crypto            *CryptoConfig
	pullSessions      sync.Map // serverID (int64) → *securechan.Session
	fedSessions       sync.Map // serverID (int64) → *securechan.Session (联邦:消费方↔拥有方)
	stealSelfDeployer func(ctx context.Context, serverID int64) error
	inboundCache      *InboundCache // 从 xray config snapshot 派生,套餐绑/换绑 cred 计算用,setter 注入
}

const (
	defaultRemoteOperationTimeout = 30 * time.Second
	warpRemoteOperationTimeout    = 75 * time.Second
	lineSpeedOperationTimeout     = 5 * time.Minute
)

func remoteOperationTimeout(path string) time.Duration {
	if strings.HasPrefix(path, "/api/child/line-speedtest/") {
		return lineSpeedOperationTimeout
	}
	if strings.HasPrefix(path, "/api/child/warp/") {
		return warpRemoteOperationTimeout
	}
	return defaultRemoteOperationTimeout
}

func remoteTransportContext(parent context.Context, path string) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, remoteOperationTimeout(path))
}

// SetInboundCache 注入 inbound cache。nil = 不启用 cache(套餐绑回退到逐节点 GET inbounds 老路径)。
func (h *RemoteManageHandler) SetInboundCache(c *InboundCache) {
	h.inboundCache = c
}

// 创建一个新的远程管理处理程序
func NewRemoteManageHandler(repo *storage.TrafficRepository, wsHandler *RemoteWSHandler) *RemoteManageHandler {
	return &RemoteManageHandler{
		repo:      repo,
		wsHandler: wsHandler,
		httpClient: &http.Client{
			// Per-operation contexts still enforce the shorter default/WARP
			// deadlines; the client ceiling must allow a full line speed test.
			Timeout: lineSpeedOperationTimeout,
		},
	}
}

// 设置安装后自动部署的证书处理程序。
func (h *RemoteManageHandler) SetCertificateHandler(ch *CertificateHandler) {
	h.certHandler = ch
}

func (h *RemoteManageHandler) SetCrypto(cc *CryptoConfig) {
	h.crypto = cc
}

func (h *RemoteManageHandler) SetStealSelfDeployer(deployer func(ctx context.Context, serverID int64) error) {
	h.stealSelfDeployer = deployer
}

// remoteInstallationAllowsAutoDeploy is deliberately fail-closed: an active
// install may still roll back Xray/Nginx, and an unreadable lock state must not
// be treated as permission to race that rollback.
func remoteInstallationAllowsAutoDeploy(ctx context.Context, repo *storage.TrafficRepository, serverID int64, source string) bool {
	if repo == nil {
		log.Printf("[%s] Skip automatic deployment for server %d: installation lock repository unavailable", source, serverID)
		return false
	}
	active, err := repo.IsRemoteServerInstallationActive(ctx, serverID)
	if err != nil {
		log.Printf("[%s] Skip automatic deployment for server %d: cannot read installation lock: %v", source, serverID, err)
		return false
	}
	if active {
		log.Printf("[%s] Skip automatic deployment for server %d: installation transaction is active", source, serverID)
		return false
	}
	return true
}

func withRemoteInstallationSafeMutation(ctx context.Context, repo *storage.TrafficRepository, serverID int64, source string, action func(context.Context) error) error {
	if repo == nil {
		err := errors.New("installation lock repository unavailable")
		log.Printf("[%s] Skip mutation for server %d: %v", source, serverID, err)
		return err
	}
	err := repo.WithRemoteServerMutationLease(ctx, serverID, action)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteInstallationActive) {
			log.Printf("[%s] Skip mutation for server %d: installation transaction is active", source, serverID)
		} else {
			log.Printf("[%s] Mutation for server %d failed closed: %v", source, serverID, err)
		}
	}
	return err
}

func (h *RemoteManageHandler) deployDefaultConfig(parentCtx context.Context, serverID int64) {
	ctx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
	defer cancel()

	// 已存在配置则不下发 — 保护现网 inbound/outbound/routing,只在全新装机时初始化默认模板。
	// 历史 BUG:scan_result xray_running=false 一旦上报(xray 启动失败 / 短暂故障 / 配置冲突),
	// 这里就会无脑下发默认模板覆盖现有配置,导致服务器再次上线时业务入站全部丢失。
	if cur, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil); err == nil {
		// 解析返回:{ "success": true, "config": "<json string>" }
		var resp struct {
			Success bool   `json:"success"`
			Config  string `json:"config"`
		}
		if json.Unmarshal(cur, &resp) == nil && resp.Success {
			cfg := strings.TrimSpace(resp.Config)
			// 判 "有效配置" 标准:能 parse + 至少包含 1 个非 api 的 inbound 或 1 个非默认 outbound
			if cfg != "" && hasNonTemplateContent(cfg) {
				log.Printf("[Remote Manage] Server %d already has non-empty xray config, skip auto-deploy default template", serverID)
				return
			}
		}
	}

	configTpl, err := templates.ReadFile("default/config.json")
	if err != nil {
		log.Printf("[Remote Manage] Failed to read default/config.json template: %v", err)
		return
	}

	configPayload, _ := json.Marshal(map[string]string{
		"config": string(configTpl),
	})
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		log.Printf("[Remote Manage] Failed to deploy default config to server %d: %v", serverID, err)
		return
	}

	if err := h.restartXrayWithRecovery(ctx, serverID, "AutoDeployDefault"); err != nil {
		log.Printf("[Remote Manage] %v", err)
		return
	}
	log.Printf("[Remote Manage] Auto-deployed default config to server %d (was empty)", serverID)
}

// serverHasXrayContent 查 server 当前 xray config 是否已有用户内容(非空模板),复用 hasNonTemplateContent。
// GET /api/child/xray/config 读的是 agent 上的 config.json 文件、不依赖 xray 进程,xray 挂时也能返回。
// GET / 解析失败保守返回 true(视为有内容、不覆盖),优先保护存量配置(宁可漏一次自动部署,也不误覆盖用户配置)。
func (h *RemoteManageHandler) serverHasXrayContent(ctx context.Context, serverID int64) bool {
	cur, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return true
	}
	var resp struct {
		Success bool   `json:"success"`
		Config  string `json:"config"`
	}
	if json.Unmarshal(cur, &resp) != nil || !resp.Success {
		return true
	}
	cfg := strings.TrimSpace(resp.Config)
	return cfg != "" && hasNonTemplateContent(cfg)
}

// hasNonTemplateContent 判断一份 xray config 是不是"用户有内容"的(而非空模板)。
// 标准:
//   - 至少 1 个 tag != "api" 的 inbound,或
//   - 至少 1 个 tag != "direct" && tag != "block" 的 outbound,或
//   - 任何 routing.rules
//
// 任一满足即认为有内容,不应被默认模板覆盖。
func hasNonTemplateContent(cfgJSON string) bool {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		// parse 失败也别覆盖 — 让用户介入修复
		return true
	}
	if ibs, ok := cfg["inbounds"].([]any); ok {
		for _, raw := range ibs {
			if m, ok := raw.(map[string]any); ok {
				if tag, _ := m["tag"].(string); tag != "" && tag != "api" {
					return true
				}
			}
		}
	}
	if obs, ok := cfg["outbounds"].([]any); ok {
		for _, raw := range obs {
			if m, ok := raw.(map[string]any); ok {
				if tag, _ := m["tag"].(string); tag != "" && tag != "direct" && tag != "block" {
					return true
				}
			}
		}
	}
	if r, ok := cfg["routing"].(map[string]any); ok {
		if rules, ok := r["rules"].([]any); ok && len(rules) > 0 {
			return true
		}
	}
	return false
}

// deviceKickPrev 主控内存:per (serverID, email) → 上次见到的累计 kick 值。
// agent 每次 scan_result 上报累计值,主控算 delta = current - prev_seen;delta > 0 → tg 通知。
// agent 重启会让累计值回到 0,主控这里检测到 current < prev → 重置 prev = current(避免负 delta 误触发)。
var deviceKickPrevMu sync.Mutex
var deviceKickPrev = make(map[string]int64) // key = fmt.Sprintf("%d|%s", serverID, email)

// handleConnLimitKickDelta:agent 上报的累计"连接数超限被拒次数"(payload.DeviceKicks,现语义=连接超限),
// 主控算 delta>0 → 解析 用户名 + 节点名 → 连接数超限通知(5min 节流兜底)。
func (h *RemoteManageHandler) handleConnLimitKickDelta(ctx context.Context, serverID int64, kicks map[string]int64) {
	deviceKickPrevMu.Lock()
	defer deviceKickPrevMu.Unlock()
	var serverName string
	if srv, err := h.repo.GetRemoteServer(ctx, serverID); err == nil && srv != nil {
		serverName = srv.Name
	}
	for email, current := range kicks {
		key := fmt.Sprintf("%d|%s", serverID, email)
		prev, seen := deviceKickPrev[key]
		if !seen || current < prev {
			// 第一次见或 agent 重启了累计值,记当前值即可,不产生 delta(避免误触发)
			deviceKickPrev[key] = current
			continue
		}
		delta := int(current - prev)
		if delta > 0 {
			deviceKickPrev[key] = current
			username := h.repo.ResolveUsernameByEmail(ctx, email)
			if username == "" {
				username = email
			}
			nodeName := h.repo.ResolveNodeNameByEmail(ctx, serverName, email)
			SendConnLimitExceededNotification(ctx, username, nodeName, delta)
		}
	}
}

// 处理通过 WebSocket 从代理收到的扫描结果。
func (h *RemoteManageHandler) HandleScanResult(serverID int64, payload WSScanResultPayload) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, serverID)
	if err != nil {
		if !errors.Is(err, storage.ErrRemoteInstallationActive) {
			log.Printf("[Remote Manage] Failed to acquire scan-result lease for server %d: %v", serverID, err)
		}
		return
	}
	defer release()
	ctx = leasedCtx

	// 更新数据库中的 X 射线状态;若状态翻转则发 TG 通知(复用服务器上下线开关)
	prevRunning, err := h.repo.UpdateRemoteServerXrayStatus(ctx, serverID, payload.XrayRunning, payload.XrayVersion)
	if err != nil {
		log.Printf("[Remote Manage] Failed to update Xray status for server %d: %v", serverID, err)
	} else if prevRunning != payload.XrayRunning {
		if server, gErr := h.repo.GetRemoteServer(ctx, serverID); gErr == nil && server != nil {
			SendXrayStatusChangeNotification(ctx, server.Name, server.IPAddress, payload.XrayRunning)
		}
	}

	// Phase 3B: device kicks delta 触发设备超限通知。
	// payload.DeviceKicks 是累计量(自 agent 启动起单调递增),主控内存记录上次见到的值,算 delta。
	// 设备超限通知给 admin,文案带 email + delta。同一 email 5min 节流由 notifyAsync 兜底。
	if len(payload.DeviceKicks) > 0 {
		h.handleConnLimitKickDelta(ctx, serverID, payload.DeviceKicks)
	}

	if payload.XrayRunning {
		// Installation may be observing a temporary Xray config that will be
		// rolled back. Do not create/claim database nodes from that transient
		// state. The shared lease covers every remote/DB mutation in auto-sync.
		var result SyncInboundsToNodesResponse
		if err := withRemoteInstallationSafeMutation(ctx, h.repo, serverID, "Remote Manage inbound sync", func(actionCtx context.Context) error {
			result = h.syncInboundsToNodesInternal(actionCtx, serverID)
			return nil
		}); err != nil {
			return
		}
		log.Printf("[Remote Manage] Auto-sync from scan_result for server %d: synced=%d (claimed=%d, created=%d), skipped=%d",
			serverID, result.SyncedCount, result.ClaimedCount, result.CreatedCount, result.SkippedCount)
	} else {
		// xray 未运行，自动下发配置
		server, err := h.repo.GetRemoteServer(ctx, serverID)
		if err == nil && server != nil {
			if !remoteInstallationAllowsAutoDeploy(ctx, h.repo, serverID, "Remote Manage") {
				return
			}
			useStealSelf := server.Use443 && server.Domain != "" && h.stealSelfDeployer != nil
			go func() {
				deployCtx, deployCancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer deployCancel()
				// 已有用户内容就不覆盖:偷自己 server 重启瞬间 xray 未就绪也会上报 XrayRunning=false,
				// 之前只有 deployDefaultConfig 内部有 hasNonTemplateContent 保护、stealSelfDeployer 分支没有,
				// 导致已部署的偷自己 server 每次重启都被模板覆盖 nginx/config。这里统一拦一道,两分支都保护。
				if h.serverHasXrayContent(deployCtx, serverID) {
					log.Printf("[Remote Manage] server %d xray 未运行但配置已有用户内容,跳过自动下发(避免覆盖 nginx/config)", serverID)
					return
				}
				mutationErr := withRemoteInstallationSafeMutation(deployCtx, h.repo, serverID, "Remote Manage", func(actionCtx context.Context) error {
					if useStealSelf {
						return h.stealSelfDeployer(actionCtx, serverID)
					}
					h.deployDefaultConfig(actionCtx, serverID)
					return nil
				})
				if mutationErr != nil {
					if !errors.Is(mutationErr, storage.ErrRemoteInstallationActive) {
						log.Printf("[Remote Manage] Auto-deploy config failed for server %d: %v", serverID, mutationErr)
					}
					return
				}
				if useStealSelf {
					log.Printf("[Remote Manage] Auto-deployed steal-self config for server %d", serverID)
				}
			}()
		}
	}
}

// RemoteWriteJSON 写入 JSON 响应
func remoteWriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// RemoteWriteError 写入错误响应
func remoteWriteError(w http.ResponseWriter, status int, message string) {
	// Cloudflare 等 CDN 会把源站 5xx 响应替换成自己的错误页(Error 502 Bad Gateway),
	// 导致真实错误信息(agent 转发失败 / xray·nginx 启动失败原因)丢失。
	// CF 默认透传 4xx,所以把 5xx 统一降为 4xx(语义上是"无法完成该远程操作"),
	// body 仍带真实 error/message,前端 onError 逻辑不变即可拿到真实原因。
	httpStatus := status
	if status >= 500 {
		httpStatus = http.StatusBadRequest
	}
	remoteWriteJSON(w, httpStatus, map[string]any{
		"success": false,
		"error":   message,
		"message": message,
		"status":  status,
	})
}

func remoteWriteForwardError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if errors.Is(err, storage.ErrRemoteInstallationActive) {
		status = http.StatusConflict
	}
	remoteWriteError(w, status, err.Error())
}

// remoteWritePartialError 表示远程多步操作的主动作已经生效，但后置同步未完成。
// 用 409 保证 CDN 不替换 body，并让客户端明确知道不应把该请求当成全部成功。
func remoteWritePartialError(w http.ResponseWriter, message string) {
	remoteWriteJSON(w, http.StatusConflict, map[string]any{
		"success": false,
		"partial": true,
		"error":   message,
		"message": message,
		"status":  http.StatusBadGateway,
	})
}

// 代理对远程服务器的服务状态请求
func (h *RemoteManageHandler) HandleServicesStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "GET", "/api/child/services/status", nil)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 将服务控制请求代理到远程服务器
func (h *RemoteManageHandler) HandleServiceControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	// xray 启动/重启时使用带恢复的逻辑
	var req struct {
		Service string `json:"service"`
		Action  string `json:"action"`
	}
	if json.Unmarshal(body, &req) == nil && req.Service == "xray" && (req.Action == "start" || req.Action == "restart") {
		// 使用独立 context，避免同机 tunnel 模式下请求断开导致 context canceled
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := h.restartXrayWithRecovery(ctx, id, "ServiceControl"); err != nil {
			remoteWriteForwardError(w, err)
			return
		}
		remoteWriteJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"message": fmt.Sprintf("Service xray %sed successfully", req.Action),
		})
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/services/control", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 代理 xray 安装请求到远程服务器
func (h *RemoteManageHandler) HandleXrayInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/xray/install", nil)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	// install 完成后异步自动触发"下发配置"动作 — 等价于用户手动点 UI 上的下发配置按钮。
	// 走同一份 DeployStealSelfConfig:按 server.StealMode dispatch 到 fallback / tunnel / default
	// 模板,与内置 xray 完全一致。否则装完 agent 跑的是"只有 api 入站"的默认配置,业务不通,
	// 用户必须手动再点一次"下发配置"才能用 — 这一步是冗余的。
	//
	// install 后 agent xray 启动 + RPC 就绪有几秒延迟,先等再 deploy。
	// 失败只 log,不影响 install 响应 — 用户仍可手动点"下发配置"重试。
	go func() {
		deployCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		select {
		case <-time.After(3 * time.Second):
		case <-deployCtx.Done():
			return
		}
		if err := withRemoteInstallationSafeMutation(deployCtx, h.repo, id, "Post-Xray-install deploy", func(actionCtx context.Context) error {
			return h.DeployStealSelfConfig(actionCtx, id)
		}); err != nil {
			log.Printf("[Remote Manage] Post-install auto-deploy failed for server %d: %v (user can retry via UI 下发配置)", id, err)
			return
		}
		log.Printf("[Remote Manage] Post-install auto-deploy succeeded for server %d", id)
	}()

	// 成功安装 xray 后触发自动部署证书
	if h.certHandler != nil {
		go h.certHandler.DeployAutoDeployCertificates(id)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 代理对远程服务器的 xray 删除请求
func (h *RemoteManageHandler) HandleXrayRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/xray/remove", nil)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 将 xray 配置请求代理到远程服务器
func (h *RemoteManageHandler) HandleXrayConfig(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/xray/config", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// HandleXrayTestConfig 把前端的 xray 配置预检请求转发到 agent。
// 前端在 dialog 点"保存"前先调一次本接口,失败则不下发,直接 toast 错误内容。
// agent 端不论 embedded/external 都会用 xray-core 库或 xray cli 验证 (见 ManageHandler.HandleXrayTestConfig)。
func (h *RemoteManageHandler) HandleXrayTestConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}
	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	result, err := h.forwardToRemoteServer(r.Context(), id, http.MethodPost, "/api/child/xray/test-config", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 代理 nginx 安装请求到远程服务器
func (h *RemoteManageHandler) HandleNginxInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}

	var body []byte
	if server.Domain != "" {
		body, _ = json.Marshal(map[string]string{"domain": server.Domain})
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/nginx/install", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	// nginx 安装成功后触发自动部署证书
	if h.certHandler != nil {
		go h.certHandler.DeployAutoDeployCertificates(id)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 代理 nginx 删除对远程服务器的请求
func (h *RemoteManageHandler) HandleNginxRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/nginx/remove", nil)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// ================== SSE 流安装/删除 ==================

func remoteSSEError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	b, _ := json.Marshal(map[string]string{"type": "error", "message": msg})
	fmt.Fprintf(w, "data: %s\n\n", b)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *RemoteManageHandler) forwardStreamToRemote(w http.ResponseWriter, r *http.Request, serverID int64, agentPath string) {
	h.forwardStreamToRemoteWithin(w, r, serverID, agentPath, 5*time.Minute)
}

func (h *RemoteManageHandler) forwardStreamToRemoteWithin(w http.ResponseWriter, r *http.Request, serverID int64, agentPath string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	err := h.repo.WithRemoteServerMutationLease(ctx, serverID, func(leasedCtx context.Context) error {
		h.forwardStreamToRemoteLeased(w, r.WithContext(leasedCtx), serverID, agentPath)
		return nil
	})
	if errors.Is(err, storage.ErrRemoteInstallationActive) {
		remoteWriteError(w, http.StatusConflict, "server installation is active; retry after it completes")
	} else if err != nil {
		remoteSSEError(w, "unable to acquire server mutation lease: "+err.Error())
	}
}

func (h *RemoteManageHandler) forwardStreamToRemoteLeased(w http.ResponseWriter, r *http.Request, serverID int64, agentPath string) {
	server, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil {
		remoteSSEError(w, "server not found: "+err.Error())
		return
	}
	if server.Status != "connected" {
		remoteSSEError(w, "server not connected")
		return
	}

	// WS-first 流式 RPC:agent capabilities.stream=true 时直接走 WS,绕开反向 HTTP 的 IP 漂移痛点。
	// 写 SSE headers 必须在 try 之前 — 数据帧会立刻通过 out 写出,前端 EventSource 看到 headers
	// 才会开始解析事件。
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	// forwardStreamToRemote 给整个操作设置了 5 分钟上限，包括租约等待、
	// WS 尝试、HTTP 回退和响应读取；这里继续把同一 context 传给传输层。
	if ok, err := h.tryWSRPCStream(r.Context(), serverID, http.MethodPost, agentPath, nil, w, flusher, 5*time.Minute); ok {
		if err != nil {
			log.Printf("[Remote Manage] WS stream %s for server %s ended with error (no fallback): %v", agentPath, server.Name, err)
		}
		return
	}

	// IP 候选清单:v4 优先,v6 兜底。dial 失败才 fallback;一旦 200 OK 且开始读流就不再 fallback
	// (避免双重执行 install / upgrade 这类幂等性差的操作)。
	candidates := buildAgentURLCandidates(server, agentPath)
	if len(candidates) == 0 {
		remoteSSEError(w, "server IP address unknown")
		return
	}

	var resp *http.Response
	for i, childURL := range candidates {
		log.Printf("[Remote Manage] Forwarding stream %s to server %s (%s)", agentPath, server.Name, childURL)

		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, childURL, nil)
		if err != nil {
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] stream candidate %s req-build failed (%v), trying next", childURL, err)
				continue
			}
			remoteSSEError(w, "failed to create request: "+err.Error())
			return
		}
		req.Header.Set("Authorization", "Bearer "+server.Token)
		req.Header.Set("User-Agent", version.AgentUserAgent)

		client := &http.Client{} // SSE 生命周期由请求 context 的硬上限控制。
		r2, err := client.Do(req)
		if err != nil {
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] stream candidate %s dial failed (%v), trying next", childURL, err)
				continue
			}
			remoteSSEError(w, "agent unreachable: "+err.Error())
			return
		}
		// 4xx/5xx 也算"这个 candidate 失败",尝试下一个 — agent install/upgrade 类幂等性差,
		// 但 4xx 通常是 token/auth/path 错,fallback 也是同样 4xx,代价 = 1 次多发,可接受
		if r2.StatusCode >= 400 {
			body, _ := io.ReadAll(r2.Body)
			r2.Body.Close()
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] stream candidate %s returned %d, trying next", childURL, r2.StatusCode)
				continue
			}
			remoteSSEError(w, fmt.Sprintf("agent error %d: %s", r2.StatusCode, string(body)))
			return
		}
		resp = r2
		break
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		remoteSSEError(w, "streaming not supported")
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		default:
		}
	}
}

func (h *RemoteManageHandler) HandleXrayInstallStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardStreamToRemote(w, r, id, "/api/child/xray/install-stream")

	// 安装完成后自动扫描更新 xray 状态
	go h.refreshXrayStatus(id)
}

func (h *RemoteManageHandler) HandleXrayRemoveStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardStreamToRemote(w, r, id, "/api/child/xray/remove-stream")

	// 卸载完成后更新 xray 状态
	go h.refreshXrayStatus(id)
}

func (h *RemoteManageHandler) refreshXrayStatus(serverID int64) {
	time.Sleep(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, serverID)
	if err != nil {
		if !errors.Is(err, storage.ErrRemoteInstallationActive) {
			log.Printf("[Remote Manage] refreshXrayStatus lease failed for server %d: %v", serverID, err)
		}
		return
	}
	defer release()
	ctx = leasedCtx

	result, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/services/status", nil)
	if err != nil {
		log.Printf("[Remote Manage] refreshXrayStatus failed for server %d: %v", serverID, err)
		return
	}

	var status struct {
		Xray *struct {
			Running bool   `json:"running"`
			Version string `json:"version"`
		} `json:"xray"`
	}
	if err := json.Unmarshal(result, &status); err != nil || status.Xray == nil {
		return
	}

	version := ""
	if status.Xray.Version != "" {
		version = status.Xray.Version
	}
	prev, err := h.repo.UpdateRemoteServerXrayStatus(ctx, serverID, status.Xray.Running, version)
	if err != nil {
		log.Printf("[Remote Manage] refreshXrayStatus: failed to update DB for server %d: %v", serverID, err)
	} else {
		log.Printf("[Remote Manage] refreshXrayStatus: server %d xray_running=%v", serverID, status.Xray.Running)
		if prev != status.Xray.Running {
			if server, gErr := h.repo.GetRemoteServer(ctx, serverID); gErr == nil && server != nil {
				SendXrayStatusChangeNotification(ctx, server.Name, server.IPAddress, status.Xray.Running)
			}
		}
	}
}

func (h *RemoteManageHandler) HandleNginxInstallStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}

	server, err := h.repo.GetRemoteServer(r.Context(), id)
	if err != nil {
		remoteSSEError(w, "server not found")
		return
	}

	agentPath := "/api/child/nginx/install-stream"
	if server.Domain != "" {
		agentPath += "?domain=" + server.Domain
	}
	h.forwardStreamToRemote(w, r, id, agentPath)

	// 流完成后触发自动部署证书
	if h.certHandler != nil {
		go h.certHandler.DeployAutoDeployCertificates(id)
	}
}

func (h *RemoteManageHandler) HandleNginxRemoveStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardStreamToRemote(w, r, id, "/api/child/nginx/remove-stream")
}

func (h *RemoteManageHandler) HandleAgentUpgradeStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardUpgradeStream(w, r, id)
}

// forwardUpgradeStream 是升级专用版本的 SSE 转发,在 forwardStreamToRemote 基础上加了:
//  1. 主控侧 5min 硬超时 — 老 agent 的 sseStreamCmd 会卡死,通用 forward 无 timeout 浏览器会一直转
//  2. 升级成功检测 — 用 system-info.agent_version 前后对比;无 agent_version 字段的老 agent 退化为
//     "ping 是否变化"(老 binary 没重启 → 旧 PID 还在响应原 conn;若新 binary 起来 → 短暂 502 然后恢复)
//  3. 失败时往 SSE 末尾追一条 {type:"result", success:false, hint:"..."} — 前端可据此提示
//     用户哪几台需要手工 ssh 上去跑 upgrade-agent.sh
func (h *RemoteManageHandler) forwardUpgradeStream(w http.ResponseWriter, r *http.Request, serverID int64) {
	err := h.repo.WithRemoteServerMutationLease(r.Context(), serverID, func(leasedCtx context.Context) error {
		h.forwardUpgradeStreamLeased(w, r.WithContext(leasedCtx), serverID)
		return nil
	})
	if errors.Is(err, storage.ErrRemoteInstallationActive) {
		remoteSSEError(w, "server installation is active; retry after it completes")
	} else if err != nil {
		remoteSSEError(w, "unable to acquire server mutation lease: "+err.Error())
	}
}

func (h *RemoteManageHandler) forwardUpgradeStreamLeased(w http.ResponseWriter, r *http.Request, serverID int64) {
	const upgradeTimeout = 5 * time.Minute

	server, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil {
		remoteSSEError(w, "server not found: "+err.Error())
		return
	}
	if server.Status != "connected" {
		remoteSSEError(w, "server not connected")
		return
	}

	// 进入升级流程前先 mark — 升级期间 agent 必然要退出 + 重连一次,WS cleanup 和 handleAuth
	// 会跳过上下线通知,防止批量升级一台一对 → Telegram 风控爆。
	// 窗口 2min 兜底:GitHub CDN 慢 + agent 重启 + WS 重连,正常 <30s,留够冗余。
	MarkServerUpgrading(serverID, 2*time.Minute)

	// 拿升级前的 agent_version 做对比基线(老 agent 没这个字段就空,后面用其它信号)
	preVersion := h.probeAgentVersion(r.Context(), serverID)

	// WS-first:capabilities.stream=true 时走 WS,数据帧用 io.MultiWriter fork 一份给
	// markerWriter,继续扫 "Binary replaced" 关键字,verify 路径完全跟 HTTP 一致。
	// 升级末期 agent 必然重启 → WS 断 → CallAgentStream 返回 stream interrupted 错误,
	// 但 markerWriter 已经看到 Binary replaced(那是脚本最后一步,先于重启输出),正常进 verify。
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if flusher, ok := w.(http.Flusher); ok {
		mw := &markerWriter{marker: []byte("Binary replaced")}
		out := io.MultiWriter(w, mw)
		ctx, cancel := context.WithTimeout(r.Context(), upgradeTimeout)
		wsOk, wsErr := h.tryWSRPCStream(ctx, serverID, http.MethodPost, "/api/child/agent/upgrade-stream", nil, out, flusher, upgradeTimeout)
		cancel()
		if wsOk {
			// 已走 WS 路径,直接 verify(agent 重启导致 wsErr 非 nil 是预期内的,不阻塞 verify)
			sawBinaryReplaced := mw.matched
			timeoutHit := wsErr != nil && (errors.Is(wsErr, context.DeadlineExceeded) ||
				strings.Contains(wsErr.Error(), "timed out"))
			h.upgradeVerify(w, flusher, server.Name, serverID, preVersion, sawBinaryReplaced, timeoutHit)
			return
		}
		// WS 不可用,继续走下面老 HTTP 路径(headers 已经写过,无副作用)
	}

	// v4-first → v6-fallback 候选清单
	candidates := buildAgentURLCandidates(server, "/api/child/agent/upgrade-stream")
	if len(candidates) == 0 {
		remoteSSEError(w, "server IP address unknown")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), upgradeTimeout)
	defer cancel()

	var resp *http.Response
	for i, childURL := range candidates {
		log.Printf("[Remote Manage] Forwarding upgrade stream to server %s (%s) preVersion=%q", server.Name, childURL, preVersion)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, childURL, nil)
		if err != nil {
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] upgrade-stream %s req-build failed (%v), trying next", childURL, err)
				continue
			}
			remoteSSEError(w, "failed to create request: "+err.Error())
			return
		}
		req.Header.Set("Authorization", "Bearer "+server.Token)
		req.Header.Set("User-Agent", version.AgentUserAgent)

		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] upgrade-stream %s dial failed (%v), trying next", childURL, err)
				continue
			}
			remoteSSEError(w, "agent unreachable: "+err.Error())
			return
		}
		if r2.StatusCode >= 400 {
			body, _ := io.ReadAll(r2.Body)
			r2.Body.Close()
			if i+1 < len(candidates) {
				log.Printf("[Remote Manage] upgrade-stream %s returned %d, trying next", childURL, r2.StatusCode)
				continue
			}
			remoteSSEError(w, fmt.Sprintf("agent error %d: %s", r2.StatusCode, string(body)))
			return
		}
		resp = r2
		break
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		remoteSSEError(w, "streaming not supported")
		return
	}

	// 透传 SSE,同时记录是否看到 "Binary replaced" 标记 — 那是 agent 脚本里最后一条 echo,
	// 看到代表脚本跑到了最后一步;没看到代表脚本中途卡死或失败。
	sawBinaryReplaced := false
	timeoutHit := false
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Binary replaced") {
			sawBinaryReplaced = true
		}
		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				timeoutHit = true
			}
			goto verify
		default:
		}
	}
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		timeoutHit = true
	}

verify:
	h.upgradeVerify(w, flusher, server.Name, serverID, preVersion, sawBinaryReplaced, timeoutHit)
}

// upgradeVerify 抽出来供 WS 路径和 HTTP 路径共用 — 等 8 秒 agent 重启窗口,再 probe 一次
// 新版本号,把结果追到 SSE 末尾。
func (h *RemoteManageHandler) upgradeVerify(w io.Writer, flusher http.Flusher, serverName string, serverID int64, preVersion string, sawBinaryReplaced, timeoutHit bool) {
	time.Sleep(8 * time.Second)
	postVersion := h.probeAgentVersion(context.Background(), serverID)

	result := upgradeResult(preVersion, postVersion, sawBinaryReplaced, timeoutHit)
	resultJSON, _ := json.Marshal(result)
	fmt.Fprintf(w, "data: %s\n\n", resultJSON)
	if flusher != nil {
		flusher.Flush()
	}
	log.Printf("[Remote Manage] Upgrade verification for %s: pre=%q post=%q sawReplaced=%v timeout=%v → %+v",
		serverName, preVersion, postVersion, sawBinaryReplaced, timeoutHit, result)
}

// markerWriter 实现 io.Writer 但**不保存原文**,只跟踪给定 marker 字串是否出现过。
// 配合 io.MultiWriter 给 WS 路径用 — 让 master 既能透传字节给前端,又能扫到升级脚本的
// 最后一条 echo "Binary replaced",维持跟 HTTP 路径一致的 verify 判断口径。
//
// 跨写入边界的处理:保留上一次写入的最后 len(marker)-1 字节,与本次拼接后再扫,
// 避免单次 buf 切到 "Binary replac" + "ed" 时漏报。
type markerWriter struct {
	marker  []byte
	matched bool
	tail    []byte // 上次留下来的尾巴(长度 ≤ len(marker)-1)
}

func (m *markerWriter) Write(p []byte) (int, error) {
	if m.matched {
		return len(p), nil
	}
	combined := append(m.tail, p...)
	if bytes.Contains(combined, m.marker) {
		m.matched = true
		m.tail = nil
		return len(p), nil
	}
	overlap := len(m.marker) - 1
	if len(combined) > overlap {
		m.tail = append(m.tail[:0], combined[len(combined)-overlap:]...)
	} else {
		m.tail = combined
	}
	return len(p), nil
}

// probeAgentVersion GET 一次 system-info 取 agent_version,失败返回空字符串。
// 5s 超时 — 我们只想瞄一眼,不希望卡这条主流程。
func (h *RemoteManageHandler) probeAgentVersion(parent context.Context, serverID int64) string {
	// WS-first:auth 上报的版本优先(端口隐身后反向 HTTP 不可达)。
	// 升级后 agent 重连会带新版本覆盖 wsConn.AgentVersion,所以升级后再 probe 仍准。
	if h.wsHandler != nil {
		if conn, ok := h.wsHandler.GetConnectionByServerID(serverID); ok && conn.AgentVersion != "" {
			return conn.AgentVersion
		}
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	body, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/system/info", nil)
	if err != nil {
		return ""
	}
	var info struct {
		AgentVersion string `json:"agent_version"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return ""
	}
	return strings.TrimSpace(info.AgentVersion)
}

// upgradeResult 推导升级最终结果,根据前后版本号 + 脚本输出标记综合判断。
// 用于追加到 SSE 末尾告诉前端是否真的升级成功了 — 这是因为 agent 自身 SSE 在卡死/部分失败场景
// 不能保证有 type=complete/error 事件,主控这边再兜一道。
func upgradeResult(preVersion, postVersion string, sawBinaryReplaced, timeoutHit bool) map[string]any {
	r := map[string]any{
		"type":         "result",
		"pre_version":  preVersion,
		"post_version": postVersion,
	}

	switch {
	case postVersion != "" && preVersion != "" && postVersion != preVersion:
		// 新版本号 ≠ 旧版本号 → agent 重启 + 新 binary 装上了 → 真升上去了
		r["success"] = true
		r["message"] = fmt.Sprintf("升级成功:v%s → v%s", preVersion, postVersion)
	case postVersion != "" && preVersion == "" && sawBinaryReplaced:
		// 旧 agent 没上报版本,但脚本完整跑完且现在能查到版本号 → 大概率成功
		r["success"] = true
		r["message"] = fmt.Sprintf("升级成功:agent v%s(旧版本无法识别,以脚本完成 + 当前可查为准)", postVersion)
	case timeoutHit:
		r["success"] = false
		r["message"] = "升级超时(5min):agent 脚本可能卡死。请在服务器上手工跑 scripts/upgrade-agent.sh 救场"
		r["hint"] = "old_agent_stuck"
	case !sawBinaryReplaced:
		r["success"] = false
		r["message"] = "升级失败:agent 未跑到 'Binary replaced'(脚本中途出错)。请检查日志 journalctl -u mmw-agent / /var/log/mmw-agent.log,或手工 ssh 跑 upgrade-agent.sh"
		r["hint"] = "script_aborted"
	case preVersion != "" && postVersion == preVersion:
		r["success"] = false
		r["message"] = fmt.Sprintf("升级失败:版本号未变(v%s)。可能 agent 进程没真正重启,或 sseStreamCmd 卡死。请手工 ssh 跑 upgrade-agent.sh", preVersion)
		r["hint"] = "no_restart"
	case preVersion == "" && postVersion == "":
		r["success"] = false
		r["message"] = "升级状态未知:agent 老版本不上报 version,无法自动确认。建议手工 ssh 检查 /usr/local/bin/mmw-agent 时间戳"
		r["hint"] = "unknown_old_agent"
	default:
		// 兜底:脚本说看到 "Binary replaced" 但版本号没变 / 没拿到,认为"大概率成功",前端可正常 toast
		r["success"] = true
		r["message"] = "升级看似完成(脚本跑完最后一步)"
	}
	return r
}

func (h *RemoteManageHandler) HandleAgentUninstallStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil {
		remoteSSEError(w, "invalid server_id")
		return
	}
	h.forwardStreamToRemote(w, r, id, "/api/child/agent/uninstall-stream")
}

// 将 nginx 配置请求代理到远程服务器
func (h *RemoteManageHandler) HandleNginxConfig(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/nginx/config", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 将系统信息请求代理到远程服务器
func (h *RemoteManageHandler) HandleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, "GET", "/api/child/system/info", nil)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 通过 HTTP 将请求转发到远程服务器
func (h *RemoteManageHandler) ForwardToServer(ctx context.Context, serverID int64, method, path string, body []byte) ([]byte, error) {
	return h.forwardToRemoteServer(ctx, serverID, method, path, body)
}

// BroadcastMasterURLUpdate 向所有已连接的非本机 agent 推送新的 master_url。
func (h *RemoteManageHandler) BroadcastMasterURLUpdate(ctx context.Context, newMasterURL string) {
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[BroadcastMasterURL] Failed to list servers: %v", err)
		return
	}

	payload, _ := json.Marshal(map[string]string{"master_url": newMasterURL})

	for _, s := range servers {
		if s.Status != "connected" {
			continue
		}
		// 跳过本机 agent（偷自己场景，master_url 为 127.0.0.1）
		if s.IPAddress == "127.0.0.1" || s.IPAddress == "::1" {
			continue
		}
		resp, err := h.forwardToRemoteServer(ctx, s.ID, http.MethodPost, "/api/child/agent/update-master-url", payload)
		if err != nil {
			log.Printf("[BroadcastMasterURL] Server %d (%s): failed: %v", s.ID, s.Name, err)
			continue
		}
		log.Printf("[BroadcastMasterURL] Server %d (%s): %s", s.ID, s.Name, string(resp))
	}
}

// ForwardToAgent 导出包装,供联邦(分享服务器)转发使用。
func (h *RemoteManageHandler) ForwardToAgent(ctx context.Context, serverID int64, method, path string, body []byte) ([]byte, error) {
	return h.forwardToRemoteServer(ctx, serverID, method, path, body)
}

// isSessionInvalidErr 判断错误是否意味着 securechan 会话失效,需要重新协商密钥后重试。
// 覆盖三种信号:
//   - agent/拥有方"无会话"返回 412 "no session, re-negotiate"
//   - agent 解密我方请求失败返回 400 "decrypt failed"(我方持有的会话已过期/被新 KX 覆盖,与对端错位)
//   - 我方解密对端响应失败 "decrypt response/federation response"(同上,会话错位)
//
// 密钥轮换窗口(agent 会话 1h TTL 过期 / 同 token 并发请求触发重新 KX 覆盖旧会话)会出现后两种,
// 仅靠重协商一次即可自愈(doPullKeyExchange 是 KX+请求+明文响应一次往返,不涉及解密,必定成功)。
func isSessionInvalidErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "412") ||
		strings.Contains(s, "re-negotiate") ||
		strings.Contains(s, "decrypt")
}

func (h *RemoteManageHandler) forwardToRemoteServer(ctx context.Context, serverID int64, method, path string, body []byte) ([]byte, error) {
	// A line speed test is a long-lived measurement, not an Agent/Xray mutation.
	// Keep this exact POST out of the installation lease. This method is also
	// used by FederationHandler on the owning control plane, so the exception
	// must live here rather than only in the consumer-side caller.
	if method == http.MethodGet || method == http.MethodHead || isLineSpeedtestRun(method, path) {
		return h.forwardToRemoteServerLeased(ctx, serverID, method, path, body)
	}
	var response []byte
	err := h.repo.WithRemoteServerMutationLease(ctx, serverID, func(leasedCtx context.Context) error {
		var forwardErr error
		response, forwardErr = h.forwardToRemoteServerLeased(leasedCtx, serverID, method, path, body)
		return forwardErr
	})
	return response, err
}

func isLineSpeedtestRun(method, path string) bool {
	return method == http.MethodPost && path == "/api/child/line-speedtest/run"
}

func (h *RemoteManageHandler) forwardToRemoteServerLeased(ctx context.Context, serverID int64, method, path string, body []byte) (respBody []byte, err error) {
	// 写操作成功 + path 命中 xray 配置修改清单 → 异步 refresh snapshot
	// (用 defer + named return 统一处理所有 return 分支,无需在每个 return 点重复)
	defer func() {
		if err == nil && shouldRefreshXraySnapshotAfter(method, path) {
			go h.refreshXraySnapshot(serverID)
		}
	}()

	// 联邦(分享)服务器:不直连 agent,改走拥有方主控的 /api/federation/manage。
	// Only the explicit not-found sentinel may fall back to a direct Agent call;
	// treating a database read failure as a local server can bypass the owner
	// relay during a transient storage fault.
	if fed, ferr := h.repo.GetFederatedServer(ctx, serverID); ferr == nil {
		transportCtx, cancel := remoteTransportContext(ctx, path)
		defer cancel()
		return h.doFederationRequest(transportCtx, fed, method, path, body)
	} else if !errors.Is(ferr, storage.ErrFederatedServerNotFound) {
		return nil, fmt.Errorf("resolve federated server: %w", ferr)
	}

	// WS-first:agent 上报 capabilities.rpc=true 且 WS 当前已连接 → 走反向 RPC,
	// 绕开 db.IPAddress 漂移 / agent 公网端口不可达 / 中间代理瞬时撕连 等 HTTP 反向请求痛点。
	// 只在以下情况 fallback 到 HTTP:
	//   - agent 老二进制不支持 RPC(Capabilities.RPC=false)→ tryWSRPC 直接 return nil,false
	//   - WS 临时断开 / RPC 调用超时 → tryWSRPC 返回 ErrWSRPCUnavailable
	//   - 业务级错误(handler 返回非 2xx)直接透传,**不** fallback(语义错就是错)
	wsCtx, cancelWS := remoteTransportContext(ctx, path)
	wsResp, ok, wsErr := h.tryWSRPC(wsCtx, serverID, method, path, body)
	cancelWS()
	if ok {
		respBody, err = wsResp, wsErr
		return respBody, err
	}

	// A stalled reverse-RPC attempt must not consume the HTTP fallback budget.
	// Give the fallback its own transport deadline while still honoring caller
	// cancellation through the shared parent context.
	fallbackCtx, cancelFallback := remoteTransportContext(ctx, path)
	defer cancelFallback()

	server, err := h.repo.GetRemoteServer(fallbackCtx, serverID)
	if err != nil {
		return nil, fmt.Errorf("server not found: %v", err)
	}

	if server.Status != "connected" {
		return nil, fmt.Errorf("server not connected (status: %s)", server.Status)
	}

	// IP 候选清单:v4 优先,v6 兜底(空字段自动跳过)。用统一 helper 消灭旧 strings.LastIndex IPv6 截断 bug。
	candidates := buildAgentURLCandidates(server, path)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("server IP address unknown")
	}

	// 逐个 candidate 尝试:成功即返回;任何错误都 fallback 到下一个候选(代价 = 业务 4xx 多发一次,可接受)。
	// 单候选场景下退化为现状(只走一次,不重试)。
	for i, childURL := range candidates {
		log.Printf("[Remote Manage] Forwarding %s %s to server %s (%s)", method, path, server.Name, childURL)

		var attemptResp []byte
		var attemptErr error

		if h.crypto == nil || h.crypto.Identity == nil {
			attemptResp, attemptErr = h.doPlainPullRequest(fallbackCtx, method, childURL, server.Token, body)
		} else {
			sessionVal, ok := h.pullSessions.Load(serverID)
			if !ok {
				attemptResp, attemptErr = h.doPullKeyExchange(fallbackCtx, serverID, method, childURL, server.Token, body)
			} else {
				session := sessionVal.(*securechan.Session)
				attemptResp, attemptErr = h.doEncryptedPullRequest(fallbackCtx, method, childURL, server.Token, body, session)
				if isSessionInvalidErr(attemptErr) {
					h.pullSessions.Delete(serverID)
					log.Printf("[Remote Manage] Pull session invalid for server %d (%v), re-negotiating", serverID, attemptErr)
					attemptResp, attemptErr = h.doPullKeyExchange(fallbackCtx, serverID, method, childURL, server.Token, body)
				}
			}
		}

		if attemptErr == nil {
			return attemptResp, nil
		}
		if i+1 < len(candidates) {
			log.Printf("[Remote Manage] candidate %s failed (%v), trying next", childURL, attemptErr)
			continue
		}
		// 最后一个候选,直接把 err 透传给上层(同原行为)
		return attemptResp, attemptErr
	}
	return nil, fmt.Errorf("server %d: all IP candidates exhausted", serverID)
}

// doFederationRequest 把一条远程管理命令通过拥有方主控的 /api/federation/manage 转发(分享服务器)。
// 在 HTTPS 之上叠加"令牌揭示的 ECDH"端到端加密:已有会话则加密发送,无会话则先做密钥交换,
// 会话失效(412/re-negotiate)自动重新协商。
func (h *RemoteManageHandler) doFederationRequest(ctx context.Context, fed storage.FederatedServer, method, path string, body []byte) ([]byte, error) {
	payload, _ := json.Marshal(map[string]string{
		"method": method,
		"path":   path,
		"body":   base64.StdEncoding.EncodeToString(body),
	})

	if sessionVal, ok := h.fedSessions.Load(fed.ServerID); ok {
		session := sessionVal.(*securechan.Session)
		respBody, err := h.doEncryptedFederationRequest(ctx, fed, payload, session)
		if isSessionInvalidErr(err) {
			h.fedSessions.Delete(fed.ServerID)
			log.Printf("[Federation] session invalid for server %d (%v), re-negotiating", fed.ServerID, err)
			return h.doFederationKeyExchange(ctx, fed, payload)
		}
		return respBody, err
	}
	return h.doFederationKeyExchange(ctx, fed, payload)
}

// doFederationKeyExchange 发起密钥交换:明文发送 payload + 临时公钥,从响应头取拥有方临时公钥建会话。
func (h *RemoteManageHandler) doFederationKeyExchange(ctx context.Context, fed storage.FederatedServer, payload []byte) ([]byte, error) {
	consPriv, consPub, err := securechan.GenerateEphemeral()
	if err != nil {
		return h.doPlainFederationRequest(ctx, fed, payload)
	}
	url := strings.TrimRight(fed.OwnerURL, "/") + "/api/federation/manage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create federation request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Share-Token", fed.ShareToken)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	req.Header.Set(fedKeyExchangeHeader, encodeKey(consPub))

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("read federation response: %v", rerr)
	}
	if resp.StatusCode >= 400 {
		return nil, federationErrorFromBody(resp.StatusCode, respBody)
	}

	// 拥有方支持加密时回带临时公钥,建会话供后续请求复用;不支持则保持明文(自动降级)。
	if kx := resp.Header.Get(fedKeyExchangeHeader); kx != "" {
		if ownerPub, ok := decodeKey(kx); ok {
			if session, derr := deriveFederationSession(consPriv, ownerPub, consPub, fed.ShareToken, true); derr == nil {
				h.fedSessions.Store(fed.ServerID, session)
				log.Printf("[Federation] key exchange completed for server %d", fed.ServerID)
			}
		}
	}
	return respBody, nil
}

// doEncryptedFederationRequest 用已建立的会话加密 payload 发送,并解密响应。
func (h *RemoteManageHandler) doEncryptedFederationRequest(ctx context.Context, fed storage.FederatedServer, payload []byte, session *securechan.Session) ([]byte, error) {
	encrypted, err := session.Encrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt federation payload: %w", err)
	}
	url := strings.TrimRight(fed.OwnerURL, "/") + "/api/federation/manage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encrypted))
	if err != nil {
		return nil, fmt.Errorf("create federation request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Share-Token", fed.ShareToken)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	req.Header.Set("X-Encrypted", "1")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("read federation response: %v", rerr)
	}
	// 拥有方对响应(含错误)加密,先解密再判状态码。
	if resp.Header.Get("X-Encrypted") == "1" {
		decrypted, derr := session.Decrypt(respBody)
		if derr != nil {
			return nil, fmt.Errorf("decrypt federation response: %w", derr)
		}
		respBody = decrypted
	}
	if resp.StatusCode >= 400 {
		return nil, federationErrorFromBody(resp.StatusCode, respBody)
	}
	return respBody, nil
}

func (h *RemoteManageHandler) doPlainFederationRequest(ctx context.Context, fed storage.FederatedServer, payload []byte) ([]byte, error) {
	url := strings.TrimRight(fed.OwnerURL, "/") + "/api/federation/manage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create federation request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Share-Token", fed.ShareToken)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("read federation response: %v", rerr)
	}
	if resp.StatusCode >= 400 {
		return nil, federationErrorFromBody(resp.StatusCode, respBody)
	}
	return respBody, nil
}

func federationErrorFromBody(status int, body []byte) error {
	var er map[string]any
	if json.Unmarshal(body, &er) == nil {
		if msg, ok := er["error"].(string); ok {
			return fmt.Errorf("%s", msg)
		}
	}
	return fmt.Errorf("federation returned status %d: %s", status, string(body))
}

func (h *RemoteManageHandler) doPlainPullRequest(ctx context.Context, method, childURL, token string, body []byte) ([]byte, error) {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, childURL, bytes.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, childURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", version.AgentUserAgent)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, fmt.Errorf("remote server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (h *RemoteManageHandler) doPullKeyExchange(ctx context.Context, serverID int64, method, childURL, token string, body []byte) ([]byte, error) {
	masterPriv, masterPub, err := securechan.GenerateEphemeral()
	if err != nil {
		return h.doPlainPullRequest(ctx, method, childURL, token, body)
	}

	sig := securechan.Sign(h.crypto.Identity.PrivateKey, masterPub)
	kxHeader := base64.StdEncoding.EncodeToString(masterPub) + "|" + base64.StdEncoding.EncodeToString(sig)

	var req *http.Request
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, childURL, bytes.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, childURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	req.Header.Set("X-Key-Exchange", kxHeader)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, fmt.Errorf("remote server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	if kxResp := resp.Header.Get("X-Key-Exchange"); kxResp != "" {
		agentEphPub, err := base64.StdEncoding.DecodeString(kxResp)
		if err == nil && len(agentEphPub) == 32 {
			sharedSecret, err := securechan.ComputeSharedSecret(masterPriv, agentEphPub)
			if err == nil {
				session, err := securechan.DeriveSession(sharedSecret, agentEphPub, masterPub, true)
				if err == nil {
					h.pullSessions.Store(serverID, session)
					log.Printf("[Remote Manage] Pull key exchange completed for server %d", serverID)
				}
			}
		}
	}

	return respBody, nil
}

func (h *RemoteManageHandler) doEncryptedPullRequest(ctx context.Context, method, childURL, token string, body []byte, session *securechan.Session) ([]byte, error) {
	var reqBody []byte
	if body != nil {
		encrypted, err := session.Encrypt(body)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		reqBody = encrypted
	}

	var req *http.Request
	var err error
	if reqBody != nil {
		req, err = http.NewRequestWithContext(ctx, method, childURL, bytes.NewReader(reqBody))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, childURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	req.Header.Set("X-Encrypted", "1")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// agent 对所有响应都加密(含错误响应),必须先解密再判断状态码,
	// 否则错误响应体仍是密文,前端 toast 会显示乱码。
	if resp.Header.Get("X-Encrypted") == "1" {
		decrypted, derr := session.Decrypt(respBody)
		if derr != nil {
			return nil, fmt.Errorf("decrypt response: %w", derr)
		}
		respBody = decrypted
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, fmt.Errorf("remote server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// 处理远程服务器上的 xray 配置文件的列表和管理
func (h *RemoteManageHandler) HandleXrayConfigFiles(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	// 转发查询参数
	query := ""
	if file := r.URL.Query().Get("file"); file != "" {
		query = "?file=" + file
	}

	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/xray/config/files"+query, body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 处理远程服务器上的 nginx 配置文件的列表和管理
func (h *RemoteManageHandler) HandleNginxConfigFiles(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	// 转发查询参数
	query := ""
	if file := r.URL.Query().Get("file"); file != "" {
		query = "?file=" + file
	}

	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/nginx/config/files"+query, body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// HandleNginxServersList 转发到 agent 的 /api/child/nginx/servers-list,
// 让前端在新建 vless+wss 入站前能拿到目标服务器 nginx servers/ 目录里现有域名,
// 用于检测同域名旧 conf 被静默覆盖的风险(reality 或老 wss 配置)。
// 老 agent 没这个 endpoint 时返回 502 透传 — 前端兜底为"暂无冲突",保持向后兼容。
func (h *RemoteManageHandler) HandleNginxServersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}
	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/nginx/servers-list", nil)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// getRemoteServerPort 提取或确定远程服务器的端口
// 现在，我们假设子服务器在配置中指定的同一端口上运行
func (h *RemoteManageHandler) getRemoteServerPort(server *storage.RemoteServer) string {
	// 默认端口
	port := "23889"

	// 如果服务器的名称或元数据中有特定端口，请将其提取
	// 目前，使用默认值
	if server.IPAddress != "" && strings.Contains(server.IPAddress, ":") {
		parts := strings.Split(server.IPAddress, ":")
		if len(parts) == 2 {
			port = parts[1]
		}
	}

	return port
}

// ================== X 射线入库管理 ==================

// 将入站管理请求代理到远程服务器
// validateInboundClientsSelfOnly 校验 add inbound 请求里的 clients/users/accounts 只包含当前登录账号自己。
// 返回空字符串表示通过,否则返回错误信息。
//
// 身份口径:xray 的 vless/vmess/trojan/shadowsocks 用 client.email 标识用户;socks/http 用 account.user。
// mmwx 约定 email/user == 用户名。校验要求每一条 client 的身份都等于当前登录用户名。
// 允许 0 条(空 clients,纯创建 inbound 不挂用户的场景)。
func validateInboundClientsSelfOnly(ctx context.Context, inboundReq map[string]interface{}) string {
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		return "无法识别当前登录用户"
	}
	inbound, ok := inboundReq["inbound"].(map[string]interface{})
	if !ok {
		return "" // 没有 inbound 体(可能是别的 action),不拦
	}
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		return ""
	}
	check := func(entries []interface{}, idField string) string {
		for _, e := range entries {
			m, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			// 优先 email,其次 idField(user)。两者都为空视为非法(无法归属)。
			identity, _ := m["email"].(string)
			if identity == "" {
				identity, _ = m[idField].(string)
			}
			if identity != username {
				return fmt.Sprintf("节点只能添加你自己(%s)的用户配置,检测到非法用户 %q", username, identity)
			}
		}
		return ""
	}
	if clients, ok := settings["clients"].([]interface{}); ok {
		if msg := check(clients, "id"); msg != "" {
			return msg
		}
	}
	if users, ok := settings["users"].([]interface{}); ok {
		if msg := check(users, "auth"); msg != "" {
			return msg
		}
	}
	if accounts, ok := settings["accounts"].([]interface{}); ok {
		if msg := check(accounts, "user"); msg != "" {
			return msg
		}
	}
	return ""
}

// validateInboundTLS 兜底校验入站 TLS 证书完整性。Hysteria2 / VLESS+TLS / Trojan+TLS 等
// 协议必 TLS,前端漏填证书时 xray-core 报 "both file and bytes are empty" 对用户不友好,
// 还容易让人误以为是后端 bug。这里在 forward 前明确拒绝并给出用户能看懂的提示。
//
// 调用时机:在 resolveInboundCert 之后,inboundReq 已经反映了"托管证书路径已注入"的最新形态。
// 兼容 action: "add" / "" 两种入站添加场景;remove/update 不校验。
func validateInboundTLS(inboundReq map[string]interface{}) string {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	if inbound == nil {
		return ""
	}
	ss, _ := inbound["streamSettings"].(map[string]interface{})
	if ss == nil {
		return ""
	}
	sec, _ := ss["security"].(string)
	if sec != "tls" {
		return ""
	}
	protocol, _ := inbound["protocol"].(string)
	protocol = canonicalManagedProtocol(protocol)
	tls, _ := ss["tlsSettings"].(map[string]interface{})
	certs, _ := tls["certificates"].([]interface{})
	if len(certs) == 0 {
		return fmt.Sprintf("入站 %s 启用了 TLS,但未配置证书。请在「证书来源」选择主控托管证书,或手动填写 certificateFile + keyFile 路径", strings.ToLower(protocol))
	}
	for i, c := range certs {
		cm, ok := c.(map[string]interface{})
		if !ok {
			return fmt.Sprintf("入站 %s 的 tlsSettings.certificates[%d] 不是对象", strings.ToLower(protocol), i)
		}
		certFile, _ := cm["certificateFile"].(string)
		keyFile, _ := cm["keyFile"].(string)
		certBytes, _ := cm["certificate"].([]interface{})
		keyBytes, _ := cm["key"].([]interface{})
		if strings.TrimSpace(certFile) == "" && len(certBytes) == 0 {
			return fmt.Sprintf("入站 %s 的证书 #%d 没填证书文件路径(certificateFile),也没填证书内联内容(certificate)。请补全后重试", strings.ToLower(protocol), i)
		}
		if strings.TrimSpace(keyFile) == "" && len(keyBytes) == 0 {
			return fmt.Sprintf("入站 %s 的证书 #%d 没填私钥文件路径(keyFile),也没填私钥内联内容(key)。请补全后重试", strings.ToLower(protocol), i)
		}
	}
	return ""
}

const managedClientSkipCertVerifyMarker = "_arcway_client_skip_cert_verify"

// extractManagedClientOptions removes panel-only client preferences before the
// request is sent to the Agent. Xray inbound TLS settings describe the server;
// client certificate verification belongs only in the generated Clash proxy.
func extractManagedClientOptions(inboundReq map[string]interface{}) (bool, error) {
	raw, exists := inboundReq["client_options"]
	if !exists {
		return false, nil
	}
	delete(inboundReq, "client_options")
	options, ok := raw.(map[string]interface{})
	if !ok {
		return false, errors.New("client_options must be an object")
	}
	for key := range options {
		if key != "skip_cert_verify" {
			return false, fmt.Errorf("unsupported client option %q", key)
		}
	}
	rawSkip, exists := options["skip_cert_verify"]
	if !exists {
		return false, nil
	}
	skip, ok := rawSkip.(bool)
	if !ok {
		return false, errors.New("client_options.skip_cert_verify must be a boolean")
	}
	if !skip {
		return false, nil
	}
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})
	security, _ := streamSettings["security"].(string)
	if !strings.EqualFold(strings.TrimSpace(security), "tls") {
		return false, errors.New("client_options.skip_cert_verify is only valid for TLS inbounds")
	}
	return true, nil
}

// validateInboundRealityTarget keeps the server-side REALITY contract strict.
// target is a camouflage TLS peer, not the address clients use to reach this
// node. The current managed presets intentionally require a DNS name and keep
// target aligned with one accepted SNI.
func validateInboundRealityTarget(inboundReq map[string]interface{}, serverDomain string) string {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})
	security, _ := streamSettings["security"].(string)
	if !strings.EqualFold(strings.TrimSpace(security), "reality") {
		return ""
	}
	realitySettings, _ := streamSettings["realitySettings"].(map[string]interface{})
	target, _ := realitySettings["target"].(string)
	if strings.TrimSpace(target) == "" {
		// Xray still accepts the historical alias, but newly managed configs use target.
		target, _ = realitySettings["dest"].(string)
	}
	if strings.Contains(target, "://") || strings.ContainsAny(target, "/?#") {
		return "Reality 伪装目标必须是域名或域名:端口，不能包含协议、路径或参数"
	}
	targetDomain, targetErr := parseManagedRealityTarget(target)
	if targetErr != nil {
		return "Reality 必须配置有效的伪装目标域名，不能使用 IP 地址"
	}
	serverNames, _ := realitySettings["serverNames"].([]interface{})
	if len(serverNames) == 0 {
		return "Reality serverNames 至少需要一个目标证书覆盖的 SNI"
	}
	targetAccepted := false
	for _, value := range serverNames {
		serverName, _ := value.(string)
		serverName = strings.ToLower(strings.TrimSpace(serverName))
		if validManagedDNSName(serverName) && serverName == targetDomain {
			targetAccepted = true
			break
		}
	}
	if !targetAccepted {
		return "Reality 伪装目标域名必须同时出现在 serverNames 中"
	}
	if ownDomain := normalizeDomainCandidate(serverDomain); ownDomain != "" && ownDomain == targetDomain {
		return "Reality 伪装目标不能使用当前节点自己的域名，否则接管端口后可能形成回环"
	}
	return ""
}

func parseManagedRealityTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty target")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port")
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if net.ParseIP(host) != nil || !validManagedDNSName(host) {
		return "", fmt.Errorf("invalid DNS name")
	}
	return host, nil
}

func validManagedDNSName(domain string) bool {
	if len(domain) < 3 || len(domain) > 253 || !strings.Contains(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

// resolveInboundCert 处理「添加 tls 入站时选了主控托管证书」(前端通过带外字段 cert_id 指定):
// 同步把证书下发到该 agent 的 xray 证书目录,再把 tlsSettings.certificates 改写成 agent 上的真实路径,
// 并在 serverName 为空时补成证书域名。返回改写后的 body(未触发则返回 nil);失败返回错误,由调用方透传给前端。
func (h *RemoteManageHandler) resolveInboundCert(ctx context.Context, serverID int64, inboundReq map[string]interface{}) ([]byte, error) {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	if inbound == nil {
		return nil, nil
	}
	// cert_id 是前端塞进 inbound 的带外字段(选了主控托管证书时);处理后剥离,不传给 agent。
	certIDf, _ := inbound["cert_id"].(float64)
	certID := int64(certIDf)
	if certID <= 0 {
		return nil, nil // 未选托管证书:用户手填路径或非 tls,不处理
	}
	ss, _ := inbound["streamSettings"].(map[string]interface{})
	if ss == nil {
		return nil, fmt.Errorf("入站缺少 streamSettings,无法应用证书")
	}
	if sec, _ := ss["security"].(string); sec != "tls" {
		return nil, nil // 非 tls 不处理
	}
	if h.certHandler == nil {
		return nil, fmt.Errorf("证书功能未初始化")
	}
	cert, err := h.repo.GetCertificate(ctx, certID)
	if err != nil || cert == nil {
		return nil, fmt.Errorf("所选证书不存在(id=%d)", certID)
	}
	if cert.Status != storage.CertStatusValid {
		return nil, fmt.Errorf("所选证书状态不是 valid")
	}
	if cert.RemoteServerID != 0 && cert.RemoteServerID != serverID {
		return nil, fmt.Errorf("所选证书属于另一台服务器，不能跨节点下发")
	}
	now := time.Now()
	if cert.ExpiryDate != nil && !cert.ExpiryDate.After(now) {
		return nil, fmt.Errorf("所选证书已过期")
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	tlsSettings, _ := ss["tlsSettings"].(map[string]interface{})
	if tlsSettings == nil {
		tlsSettings = map[string]interface{}{}
		ss["tlsSettings"] = tlsSettings
	}
	serverName, _ := tlsSettings["serverName"].(string)
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	if serverName == "" {
		candidates := append([]string{server.Domain, cert.Domain}, certificateDNSNames(cert.CertPEM)...)
		for _, candidate := range candidates {
			candidate = strings.ToLower(strings.TrimSpace(candidate))
			if strings.HasPrefix(candidate, "*.") || !certificateCoversHostname(cert.CertPEM, cert.KeyPEM, candidate, now) {
				continue
			}
			serverName = candidate
			break
		}
	}
	if serverName == "" || !certificateCoversHostname(cert.CertPEM, cert.KeyPEM, serverName, now) {
		return nil, fmt.Errorf("所选证书不覆盖 TLS SNI %q，或证书与私钥不匹配", serverName)
	}
	certPath, keyPath, derr := h.certHandler.DeployCertToServerSync(ctx, server, cert)
	if derr != nil {
		return nil, fmt.Errorf("下发证书到服务器失败: %v", derr)
	}
	tlsSettings["certificates"] = []interface{}{
		map[string]interface{}{"certificateFile": certPath, "keyFile": keyPath},
	}
	tlsSettings["serverName"] = serverName
	delete(inbound, "cert_id") // 剥离带外字段,xray 不认识它
	return json.Marshal(inboundReq)
}

func (h *RemoteManageHandler) HandleInbounds(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	var inboundReq map[string]interface{}
	var clientSkipCertVerify bool
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		// 解析请求体以获取入站配置
		if err := json.Unmarshal(body, &inboundReq); err != nil {
			remoteWriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		clientSkipCertVerify, err = extractManagedClientOptions(inboundReq)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		body, err = json.Marshal(inboundReq)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to normalize client options")
			return
		}
	}

	// 添加节点(add inbound)时校验:inbound.settings.clients/accounts 只能包含"当前登录账号自己"。
	// 用户卡片在前端已锁死,但后端必须独立校验,防止普通用户绕过前端直接构造请求把别人的 uuid/email 塞进节点。
	// 管理员是节点管理者,可添加任意 client(任意 uuid/email),不受此限制。
	// 注:套餐分配用户走的是 addUserToInbound → forwardToRemoteServer,不经过本 HTTP handler,不受影响。
	if r.Method == http.MethodPost && inboundReq != nil {
		action, _ := inboundReq["action"].(string)
		if al := strings.ToLower(action); al == "" || al == "add" {
			uname := auth.UsernameFromContext(r.Context())
			if !userIsAdmin(r.Context(), h.repo, uname) {
				if msg := validateInboundClientsSelfOnly(r.Context(), inboundReq); msg != "" {
					remoteWriteError(w, http.StatusForbidden, msg)
					return
				}
			}
		}
	}

	// POST 是一条多步远程写链：证书落盘、inbound 变更、Reality 路由以及
	// WSS nginx 聚合都必须在同一 server mutation lease 内完成。GET 保持原来的无写租约路径。
	operationCtx := r.Context()
	if r.Method == http.MethodPost {
		leasedCtx, release, leaseErr := h.repo.AcquireRemoteServerMutationLease(operationCtx, id)
		if leaseErr != nil {
			remoteWriteForwardError(w, leaseErr)
			return
		}
		defer release()
		operationCtx = leasedCtx
	}

	// 删除 reality 入站前，先保存其 serverNames 以便后续恢复路由
	var preDeleteRealityDomains []string
	var removedInboundWasWSS bool
	if r.Method == http.MethodPost && inboundReq != nil {
		action, _ := inboundReq["action"].(string)
		if strings.ToLower(action) == "remove" {
			if tag, _ := inboundReq["tag"].(string); tag != "" {
				preDeleteRealityDomains, removedInboundWasWSS, err = h.getInboundRemovalSyncState(operationCtx, id, tag)
				if err != nil {
					remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("删除前读取入站后置同步信息失败: %v", err))
					return
				}
			}
		}
	}

	// 添加 tls 入站若选了主控托管证书(cert_id),先同步下发证书到 agent 并把路径注入到入站配置,
	// 避免「agent 上没有该证书 → xray 加载失败 → 502」。失败明确报错(已透传,不被 CF 吞)。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); action == "" || strings.ToLower(action) == "add" {
			if newBody, certErr := h.resolveInboundCert(operationCtx, id, inboundReq); certErr != nil {
				remoteWriteError(w, http.StatusBadGateway, "证书处理失败: "+certErr.Error())
				return
			} else if newBody != nil {
				body = newBody
				// 重新 unmarshal 一下,后续 TLS 兜底校验要看到最新的 certificates 值
				_ = json.Unmarshal(body, &inboundReq)
			}
		}
	}

	// VLESS/VMess/Trojan + WSS 入站添加:强制 listen=127.0.0.1、自动分配本地端口、自动随机 path、security=none
	// (TLS 由 nginx 在 443 处理,xray 只接 ws upgrade)。后续 forward 成功再调 syncWSSNginx 聚合渲染。
	// per-server 锁:防止并发添加抢到同一端口。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); (action == "" || strings.ToLower(action) == "add") && isWSSInboundReq(inboundReq) {
			if _, prerequisiteErr := h.resolveWSSCertificateContext(operationCtx, id); prerequisiteErr != nil {
				remoteWriteError(w, http.StatusConflict, "WSS 前置检查失败: "+prerequisiteErr.Error())
				return
			}
			lock := wssServerLock(id)
			lock.Lock()
			defer lock.Unlock()
			newBody, perr := h.preprocessWSSInbound(operationCtx, id, body, inboundReq)
			if perr != nil {
				remoteWriteError(w, http.StatusBadGateway, perr.Error())
				return
			}
			body = newBody
			_ = json.Unmarshal(body, &inboundReq)
		}
	}

	// TLS 入站兜底校验:hysteria2 / vless+tls / trojan 等必须 TLS 的协议,前端漏填证书时
	// xray-core 的错是 "both file and bytes are empty",对用户不友好且让人怀疑后端 bug。
	// 这里在 forward 前明确拒绝并给出用户能看懂的提示。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); action == "" || strings.ToLower(action) == "add" {
			serverDomain := ""
			if server, serverErr := h.repo.GetRemoteServer(operationCtx, id); serverErr == nil && server != nil {
				serverDomain = server.Domain
			}
			if msg := validateInboundRealityTarget(inboundReq, serverDomain); msg != "" {
				remoteWriteError(w, http.StatusBadRequest, msg)
				return
			}
			if msg := validateInboundWireGuard(inboundReq); msg != "" {
				remoteWriteError(w, http.StatusBadRequest, msg)
				return
			}
			if msg := validateInboundTLS(inboundReq); msg != "" {
				remoteWriteError(w, http.StatusBadRequest, msg)
				return
			}
		}
	}

	// anytls 入站只有内嵌 xray(fork)支持,官方外置 xray 无此协议 → 会以 "unknown config id: anytls" 启动失败。
	// 外置模式直接拒绝(前端也会禁用该选项,这里是绕过前端直连 API 的兜底)。
	if r.Method == http.MethodPost && inboundReq != nil {
		if action, _ := inboundReq["action"].(string); action == "" || strings.ToLower(action) == "add" {
			if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok {
				if proto, _ := inbound["protocol"].(string); strings.ToLower(proto) == "anytls" || strings.ToLower(proto) == "snell" {
					if server, err := h.repo.GetRemoteServer(operationCtx, id); err == nil && server != nil && server.XrayMode == "external" {
						remoteWriteError(w, http.StatusBadRequest, strings.ToLower(proto)+" 协议需要内嵌 xray,请先将该服务器切换为内嵌模式")
						return
					}
				}
			}
		}
	}

	// 中转(relay):relay_server/relay_port 是前端 wizard 挂在 inbound 上的带外字段,agent/xray 不需要 ——
	// 转发前从 body 里剥掉,仅用于建节点时把 clash server/port 换成中转地址(经 InboundEvent 传给 NodeSyncListener)。
	var relayServer string
	var relayPort int
	if r.Method == http.MethodPost && inboundReq != nil {
		if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok {
			if rs, _ := inbound["relay_server"].(string); strings.TrimSpace(rs) != "" {
				relayServer = strings.TrimSpace(rs)
				if rp, ok := inbound["relay_port"].(float64); ok {
					relayPort = int(rp)
				}
				delete(inbound, "relay_server")
				delete(inbound, "relay_port")
				if nb, mErr := json.Marshal(inboundReq); mErr == nil {
					body = nb
				}
			}
		}
	}

	result, err := h.forwardToRemoteServer(operationCtx, id, r.Method, "/api/child/inbounds", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	// 对于 GET 请求，过滤掉空 tag 和 tag="api" 的入站
	if r.Method == http.MethodGet {
		result = h.filterInboundsResponse(result)
	}

	// 对于 POST 请求，处理添加和删除操作
	if r.Method == http.MethodPost {
		action, _ := inboundReq["action"].(string)
		actionLower := strings.ToLower(action)

		// 检查远程服务器响应是否成功
		var resp map[string]interface{}
		if err := json.Unmarshal(result, &resp); err == nil {
			if success, ok := resp["success"].(bool); ok && success {
				var postSyncErrors []string
				if actionLower == "" || actionLower == "add" {
					var pendingWSSEvent *event.InboundEvent
					// 添加入站：先处理 reality 相关配置（更新 tunnel-in port + 清理域名路由）
					if inbound, ok := inboundReq["inbound"].(map[string]interface{}); ok {
						tag, _ := inbound["tag"].(string)
						protocol, _ := inbound["protocol"].(string)
						port, _ := inbound["port"].(float64)
						customNodeName, _ := inboundReq["node_name"].(string)
						forwardNodeID, _ := inboundReq["forward_node_id"].(float64) // tunnel「转发已有节点」时携带源节点 ID
						// ip_version: ""/v4(默认) | v6 | both —— 决定生成节点 clash server 用 v4/v6/双节点
						ipVersion, _ := inboundReq["ip_version"].(string)
						switch ipVersion {
						case "v4", "v6", "both":
						default:
							ipVersion = "" // 非法值降级为默认 v4
						}

						if err := h.cleanupTunnelRouteForReality(operationCtx, id, inbound); err != nil {
							postSyncErrors = append(postSyncErrors, "Reality 路由同步失败: "+err.Error())
						}

						// 转换为 map[string]any
						inboundAny := make(map[string]any)
						for k, v := range inbound {
							inboundAny[k] = v
						}
						if clientSkipCertVerify {
							inboundAny[managedClientSkipCertVerifyMarker] = true
						}
						inboundEvent := event.InboundEvent{
							Type:          event.EventInboundAdded,
							ServerID:      id,
							Tag:           tag,
							Protocol:      protocol,
							Port:          int(port),
							Inbound:       inboundAny,
							NodeName:      customNodeName,
							ForwardNodeID: int64(forwardNodeID),
							IPVersion:     ipVersion,
							RelayServer:   relayServer,
							RelayPort:     relayPort,
						}
						if canonicalManagedProtocol(protocol) == "wireguard" {
							if _, resourceErr := h.upsertWireGuardManagedResource(
								operationCtx,
								id,
								customNodeName,
								managedInboundCreatedBy(r.Context()),
								inbound,
							); resourceErr != nil {
								postSyncErrors = append(postSyncErrors, "WireGuard 管理记录同步失败: "+resourceErr.Error())
							}
						}
						if isWSSInboundReq(inboundReq) {
							pendingWSSEvent = &inboundEvent
						} else {
							event.GetBus().Publish(inboundEvent)
						}
					}
					// 受管 WS 入站添加成功 → 在同一租约内聚合渲染并等待 Agent ACK。
					if isWSSInboundReq(inboundReq) {
						if err := h.SyncWSSNginx(operationCtx, id); err != nil {
							inbound, _ := inboundReq["inbound"].(map[string]interface{})
							tag, _ := inbound["tag"].(string)
							rollbackErr := h.rollbackWSSInboundAdd(operationCtx, id, tag)
							if rollbackErr == nil {
								remoteWriteError(w, http.StatusBadGateway, "WSS nginx 同步失败，刚创建的入站已自动回滚: "+err.Error())
								return
							}
							postSyncErrors = append(postSyncErrors, "WSS nginx 同步失败: "+err.Error()+"；自动回滚失败: "+rollbackErr.Error())
						} else if pendingWSSEvent != nil {
							event.GetBus().Publish(*pendingWSSEvent)
						}
					}
				} else if actionLower == "remove" {
					// 删除入站：发布事件
					if tag, ok := inboundReq["tag"].(string); ok && tag != "" {
						event.GetBus().Publish(event.InboundEvent{
							Type:     event.EventInboundRemoved,
							ServerID: id,
							Tag:      tag,
						})
					}
					// 恢复被 reality 接管的域名到 tunnel-in→nginx 路由
					if len(preDeleteRealityDomains) > 0 {
						if err := h.restoreTunnelRouteForReality(operationCtx, id, preDeleteRealityDomains); err != nil {
							postSyncErrors = append(postSyncErrors, "Reality 路由恢复失败: "+err.Error())
						}
					}
					if removedInboundWasWSS {
						if err := h.SyncWSSNginx(operationCtx, id); err != nil {
							postSyncErrors = append(postSyncErrors, "WSS nginx 清理失败: "+err.Error())
						}
					}
				}
				if len(postSyncErrors) > 0 {
					remoteWritePartialError(w, "入站主动作已生效，但后置同步未完成: "+strings.Join(postSyncErrors, "; "))
					return
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

func (h *RemoteManageHandler) rollbackWSSInboundAdd(ctx context.Context, serverID int64, tag string) error {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return errors.New("入站 Tag 为空")
	}
	body, err := json.Marshal(map[string]interface{}{"action": "remove", "tag": tag})
	if err != nil {
		return err
	}
	result, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/inbounds", body)
	if err != nil {
		return err
	}
	var response struct {
		Success *bool  `json:"success"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("解析 Agent 回滚响应失败: %w", err)
	}
	if response.Success != nil && *response.Success {
		return nil
	}
	message := strings.TrimSpace(response.Error)
	if message == "" {
		message = strings.TrimSpace(response.Message)
	}
	if message == "" {
		message = "Agent 未确认入站删除"
	}
	return errors.New(message)
}

// HandleCreateManagedNode creates a remote inbound and only reports success when
// the corresponding database node exists. The legacy raw inbound endpoint keeps
// its low-level semantics; this endpoint is the transactional UI workflow.
func (h *RemoteManageHandler) HandleCreateManagedNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	var request map[string]interface{}
	if err := json.Unmarshal(body, &request); err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	action, _ := request["action"].(string)
	if action != "" && !strings.EqualFold(strings.TrimSpace(action), "add") {
		remoteWriteError(w, http.StatusBadRequest, "managed node creation only supports action=add")
		return
	}
	request["action"] = "add"
	nodeName, _ := request["node_name"].(string)
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		remoteWriteError(w, http.StatusBadRequest, "node_name is required")
		return
	}
	request["node_name"] = nodeName
	inbound, _ := request["inbound"].(map[string]interface{})
	tag, _ := inbound["tag"].(string)
	protocol, _ := inbound["protocol"].(string)
	tag = strings.TrimSpace(tag)
	if inbound == nil || tag == "" || strings.TrimSpace(protocol) == "" {
		remoteWriteError(w, http.StatusBadRequest, "inbound.tag and inbound.protocol are required")
		return
	}
	if canonicalManagedProtocol(protocol) == "wireguard" {
		remoteWriteError(w, http.StatusUnprocessableEntity, "WireGuard 客户端私钥不能写入受管订阅节点；请使用专用一次性 WireGuard 入站创建流程")
		return
	}
	inbound["tag"] = tag
	body, err = json.Marshal(request)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "failed to normalize request")
		return
	}
	server, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil || server == nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}
	if !server.XrayRunning || (server.Status != "online" && server.Status != "connected") {
		remoteWriteError(w, http.StatusConflict, "目标服务器或 Xray 当前不在线")
		return
	}
	if _, found, lookupErr := h.findManagedNode(r.Context(), server.Name, tag); lookupErr != nil {
		remoteWriteError(w, http.StatusInternalServerError, "failed to validate inbound tag")
		return
	} else if found {
		remoteWriteError(w, http.StatusConflict, "该服务器已存在相同入站 Tag 的节点")
		return
	}

	forwardRequest := r.Clone(r.Context())
	forwardRequest.Body = io.NopCloser(bytes.NewReader(body))
	forwardRequest.ContentLength = int64(len(body))
	recorder := &managedNodeResponseRecorder{header: make(http.Header)}
	h.HandleInbounds(recorder, forwardRequest)
	if recorder.status >= http.StatusBadRequest {
		if !managedNodeResponseIsPartial(recorder) {
			copyHTTPResponse(w, recorder)
			return
		}
		rollbackErr := h.rollbackManagedNode(r, serverID, server.Name, tag)
		message := managedNodeResponseMessage(recorder, "入站后置同步失败")
		if rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, message+"；自动回滚也失败: "+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, message+"；已回滚远程入站和节点记录")
		return
	}
	if success, message := managedNodeResponseSuccess(recorder); !success {
		rollbackErr := h.rollbackManagedNode(r, serverID, server.Name, tag)
		if rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, message+"；自动回滚也失败: "+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, message+"；已回滚远程入站和节点记录")
		return
	}

	node, found, lookupErr := h.findManagedNode(r.Context(), server.Name, tag)
	if lookupErr == nil && !found {
		syncResult := h.syncInboundsToNodes(r.Context(), serverID, "", false)
		node, found, err = h.findManagedNode(r.Context(), server.Name, tag)
		lookupErr = err
		if lookupErr == nil && !found && len(syncResult.Errors) > 0 {
			lookupErr = fmt.Errorf("%s", strings.Join(syncResult.Errors, "; "))
		}
	}
	if lookupErr == nil && !found {
		lookupErr = errors.New("入站已创建，但节点同步未生成记录")
	}
	if lookupErr != nil {
		if rollbackErr := h.rollbackManagedNode(r, serverID, server.Name, tag); rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, "节点同步失败，自动回滚也失败: "+lookupErr.Error()+"；"+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, "节点同步失败，已回滚远程入站和节点记录: "+lookupErr.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "受管节点已创建",
		"node_id": node.ID,
		"node":    node,
	})
}

func managedNodeResponseIsPartial(recorder *managedNodeResponseRecorder) bool {
	var response struct {
		Partial bool `json:"partial"`
	}
	return json.Unmarshal(recorder.body.Bytes(), &response) == nil && response.Partial
}

func managedNodeResponseMessage(recorder *managedNodeResponseRecorder, fallback string) string {
	var response struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(recorder.body.Bytes(), &response) == nil {
		if message := strings.TrimSpace(response.Message); message != "" {
			return message
		}
		if message := strings.TrimSpace(response.Error); message != "" {
			return message
		}
	}
	return fallback
}

func managedNodeResponseSuccess(recorder *managedNodeResponseRecorder) (bool, string) {
	var response struct {
		Success        *bool  `json:"success"`
		Message        string `json:"message"`
		Error          string `json:"error"`
		Warning        string `json:"warning"`
		RuntimeWarning string `json:"runtime_warning"`
	}
	if json.Unmarshal(recorder.body.Bytes(), &response) != nil || response.Success == nil {
		return false, "Agent 返回了无法确认的创建结果"
	}
	if !*response.Success {
		message := strings.TrimSpace(response.Message)
		if message == "" {
			message = strings.TrimSpace(response.Error)
		}
		if message == "" {
			message = "Agent 拒绝创建入站"
		}
		return false, message
	}
	if warning := strings.TrimSpace(response.Warning); warning != "" {
		message := strings.TrimSpace(response.Message)
		if message == "" {
			message = "Agent 创建结果包含警告: " + warning
		} else {
			message += " (" + warning + ")"
		}
		return false, message
	}
	if warning := strings.TrimSpace(response.RuntimeWarning); warning != "" {
		return false, "Agent 运行态结果不可信: " + warning
	}
	return true, ""
}

func (h *RemoteManageHandler) rollbackManagedNode(r *http.Request, serverID int64, serverName, tag string) error {
	rollbackBody, _ := json.Marshal(map[string]interface{}{"action": "remove", "tag": tag})
	rollbackRequest := r.Clone(context.Background())
	rollbackRequest.Body = io.NopCloser(bytes.NewReader(rollbackBody))
	rollbackRequest.ContentLength = int64(len(rollbackBody))
	rollbackRequest.URL = cloneURLWithQuery(r, serverID)
	rollbackRecorder := &managedNodeResponseRecorder{header: make(http.Header)}
	h.HandleInbounds(rollbackRecorder, rollbackRequest)
	if rollbackRecorder.status >= http.StatusBadRequest {
		return errors.New(managedNodeResponseMessage(rollbackRecorder, fmt.Sprintf("回滚 HTTP %d", rollbackRecorder.status)))
	}
	if success, message := managedNodeResponseSuccess(rollbackRecorder); !success {
		return errors.New(message)
	}
	if _, err := h.repo.DeleteNodesByInboundTag(context.Background(), serverName, tag); err != nil {
		return fmt.Errorf("清理节点记录失败: %w", err)
	}
	return nil
}

type managedNodeResponseRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (r *managedNodeResponseRecorder) Header() http.Header    { return r.header }
func (r *managedNodeResponseRecorder) WriteHeader(status int) { r.status = status }
func (r *managedNodeResponseRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(body)
}

func copyHTTPResponse(w http.ResponseWriter, source *managedNodeResponseRecorder) {
	for key, values := range source.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := source.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(source.body.Bytes())
}

func cloneURLWithQuery(r *http.Request, serverID int64) *url.URL {
	next := *r.URL
	query := next.Query()
	query.Set("server_id", strconv.FormatInt(serverID, 10))
	next.RawQuery = query.Encode()
	return &next
}

func (h *RemoteManageHandler) findManagedNode(ctx context.Context, serverName, inboundTag string) (storage.Node, bool, error) {
	nodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		return storage.Node{}, false, err
	}
	for _, node := range nodes {
		if node.OriginalServer == serverName && node.InboundTag == inboundTag {
			return node, true, nil
		}
	}
	return storage.Node{}, false, nil
}

// 过滤入站响应，移除空 tag 和 tag="api" 的入站
func (h *RemoteManageHandler) filterInboundsResponse(result []byte) []byte {
	var resp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
		Message  string                   `json:"message,omitempty"`
	}

	if err := json.Unmarshal(result, &resp); err != nil {
		return result
	}

	// 过滤入站列表
	filtered := make([]map[string]interface{}, 0, len(resp.Inbounds))
	for _, ib := range resp.Inbounds {
		tag, _ := ib["tag"].(string)
		source, _ := ib["_source"].(string)

		// 跳过 tag="api" 的入站
		if tag == "api" {
			continue
		}
		// 跳过空 tag 的 runtime_only 入站
		if tag == "" && source == "runtime_only" {
			continue
		}
		// 对于空 tag 的配置入站，生成名称
		if tag == "" && source == "config" {
			protocol, _ := ib["protocol"].(string)
			port := 0
			if p, ok := ib["port"].(float64); ok {
				port = int(p)
			}
			if protocol != "" && port > 0 {
				ib["tag"] = fmt.Sprintf("%s-%d", protocol, port)
				ib["_generated_tag"] = true
			}
		}
		filtered = append(filtered, ib)
	}

	resp.Inbounds = filtered
	newResult, err := json.Marshal(resp)
	if err != nil {
		return result
	}
	return newResult
}

// 自动将入站同步到节点表
func (h *RemoteManageHandler) autoSyncInboundToNodes(ctx context.Context, serverID int64, inbound map[string]interface{}) {
	protocol, _ := inbound["protocol"].(string)
	if canonicalManagedProtocol(protocol) == "wireguard" {
		// A usable WireGuard client profile includes a private key that intentionally
		// never enters the panel, so this inbound has no subscription node to sync.
		return
	}

	// 获取远程服务器信息
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		log.Printf("[Remote Manage] Failed to get remote server %d: %v", serverID, err)
		return
	}

	// Domain → 非私有的 PullAddress → IPAddress 优先序
	serverHost := chooseClashServerHost(server)
	if serverHost == "" {
		log.Printf("[Remote Manage] No server address available for server %d", serverID)
		return
	}

	// tunnel 模式：仅当入站端口 == tunnel-in 的 settings.port 时，使用 443 端口（但 server 保持用 IP，域名可能走 CDN）
	tunnelPort := 0
	if server.Domain != "" && (server.StealMode == "tunnel" || server.StealMode == "") {
		inboundPort := 0
		if p, ok := inbound["port"].(float64); ok {
			inboundPort = int(p)
		} else if p, ok := inbound["port"].(int); ok {
			inboundPort = p
		}
		if inboundPort > 0 {
			tunnelInSettingsPort := h.getTunnelInSettingsPort(ctx, serverID)
			if tunnelInSettingsPort > 0 && inboundPort == tunnelInSettingsPort {
				tunnelPort = 443
			}
		}
	}
	// WSS 入站 → 客户端视角 (port 443, sni, Host header)。覆盖上面 tunnel 端口判断,因为
	// listen=127.0.0.1 的 WSS 入站本来就跟 tunnel 互斥。
	if effPort, effHost := applyWSSClientRewrite(inbound, server); effPort > 0 {
		tunnelPort = effPort
		serverHost = effHost
	}
	clashProxy, err := h.inboundToClashProxy(inbound, serverHost, server.Name, tunnelPort)
	if err != nil {
		log.Printf("[Remote Manage] Failed to convert inbound to Clash proxy: %v", err)
		return
	}

	// 序列化为 JSON（与 HandleSyncInboundsToNodes 保持一致）
	clashJSON, err := json.Marshal(clashProxy)
	if err != nil {
		log.Printf("[Remote Manage] Failed to marshal Clash proxy to JSON: %v", err)
		return
	}

	// 获取入站标签
	inboundTag, _ := inbound["tag"].(string)
	nodeName, _ := clashProxy["name"].(string)

	// 创建节点
	node := storage.Node{
		Username:       "admin", // 默认为管理员
		NodeName:       nodeName,
		Protocol:       protocol,
		ClashConfig:    string(clashJSON),
		ParsedConfig:   string(clashJSON),
		Enabled:        true,
		Tag:            fmt.Sprintf("远程:%s", server.Name),
		OriginalServer: server.Name,
		InboundTag:     inboundTag,
	}

	_, err = h.repo.CreateNode(ctx, node)
	if err != nil {
		log.Printf("[Remote Manage] Failed to create node for inbound %s: %v", inboundTag, err)
		return
	}

	log.Printf("[Remote Manage] Auto-synced inbound %s to nodes table for server %s", inboundTag, server.Name)
}

// 自动删除入站对应的节点
func (h *RemoteManageHandler) autoDeleteInboundNodes(ctx context.Context, serverID int64, inboundTag string) {
	// 获取远程服务器信息
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		log.Printf("[Remote Manage] Failed to get remote server %d for node deletion: %v", serverID, err)
		return
	}

	// 删除对应的节点
	deleted, err := h.repo.DeleteNodesByInboundTag(ctx, server.Name, inboundTag)
	if err != nil {
		log.Printf("[Remote Manage] Failed to delete nodes for inbound %s: %v", inboundTag, err)
		return
	}

	if deleted > 0 {
		log.Printf("[Remote Manage] Auto-deleted %d node(s) for inbound %s on server %s", deleted, inboundTag, server.Name)
	}
}

// ================== X 射线出库管理 ==================

// 将出站管理请求代理到远程服务器
func (h *RemoteManageHandler) HandleOutbounds(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		// Hook: action=add 且 outbound 是 TLS 且 pinnedPeerCertSha256 缺失 → TLS dial 拿对端证书 sha256 自动注入
		// 失败直接 400 返给前端,提示用户手动填(替代已废弃的 allowInsecure)
		if newBody, hookErr := autoInjectPinnedCertSha256(r.Context(), body); hookErr != nil {
			remoteWriteError(w, http.StatusBadRequest, hookErr.Error())
			return
		} else if newBody != nil {
			body = newBody
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/outbounds", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// autoInjectPinnedCertSha256 解析 outbound add 请求体,若 TLS outbound 缺 pinnedPeerCertSha256
// 则 TLS dial 抓 peer cert sha256 注入。非 add 动作 / 非 TLS / 已填 sha256 → 返回 (nil, nil) 不动 body。
// 失败返回错误(前端会展开 sha256 输入框让用户手动填)。
func autoInjectPinnedCertSha256(ctx context.Context, body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, nil // 不是 JSON 就不动,让 forward 把原 body 透传
	}
	action, _ := req["action"].(string)
	if strings.ToLower(strings.TrimSpace(action)) != "add" {
		return nil, nil
	}
	ob, _ := req["outbound"].(map[string]any)
	if ob == nil {
		return nil, nil
	}
	ss, _ := ob["streamSettings"].(map[string]any)
	if ss == nil {
		return nil, nil
	}
	if sec, _ := ss["security"].(string); strings.ToLower(strings.TrimSpace(sec)) != "tls" {
		return nil, nil
	}
	tlsObj, _ := ss["tlsSettings"].(map[string]any)
	if tlsObj == nil {
		tlsObj = map[string]any{}
		ss["tlsSettings"] = tlsObj
	}
	// 已填 sha256 → 跳过
	if existing, _ := tlsObj["pinnedPeerCertSha256"].(string); strings.TrimSpace(existing) != "" {
		return nil, nil
	}

	// 提取 address/port:支持 vnext[0] (VLESS/VMess) 或 servers[0] (Trojan/Shadowsocks)
	addr, port := extractOutboundTarget(ob)
	if addr == "" || port == 0 {
		return nil, fmt.Errorf("无法识别 outbound 目标地址,请在 tlsSettings.pinnedPeerCertSha256 手动填写证书 SHA256")
	}

	sni, _ := tlsObj["serverName"].(string)
	alpn := ""
	if alpnArr, ok := tlsObj["alpn"].([]any); ok && len(alpnArr) > 0 {
		parts := make([]string, 0, len(alpnArr))
		for _, a := range alpnArr {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		alpn = strings.Join(parts, ",")
	}

	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	sha, err := fetchPeerCertSha256(dialCtx, addr, port, sni, alpn)
	if err != nil {
		return nil, fmt.Errorf("自动获取对端证书 SHA256 失败 (%s:%d): %v;请在 tlsSettings.pinnedPeerCertSha256 手动填写", addr, port, err)
	}
	tlsObj["pinnedPeerCertSha256"] = sha
	// 顺手清掉 allowInsecure(xray 已废弃,留着没意义)
	delete(tlsObj, "allowInsecure")
	return json.Marshal(req)
}

// extractOutboundTarget 从 xray outbound JSON 中提取目标 address/port。
// 支持 settings.vnext[0] (VLESS/VMess) 和 settings.servers[0] (Trojan/Shadowsocks/Socks/HTTP)。
func extractOutboundTarget(ob map[string]any) (string, int) {
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return "", 0
	}
	pickAddrPort := func(m map[string]any) (string, int) {
		addr, _ := m["address"].(string)
		var port int
		switch v := m["port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		case int64:
			port = int(v)
		case string:
			if p, err := strconv.Atoi(v); err == nil {
				port = p
			}
		}
		return strings.TrimSpace(addr), port
	}
	if vnext, ok := settings["vnext"].([]any); ok && len(vnext) > 0 {
		if first, ok := vnext[0].(map[string]any); ok {
			if a, p := pickAddrPort(first); a != "" && p > 0 {
				return a, p
			}
		}
	}
	if servers, ok := settings["servers"].([]any); ok && len(servers) > 0 {
		if first, ok := servers[0].(map[string]any); ok {
			if a, p := pickAddrPort(first); a != "" && p > 0 {
				return a, p
			}
		}
	}
	return "", 0
}

// ================== X 射线路由管理 ==================

// 代理将管理请求路由到远程服务器
func (h *RemoteManageHandler) HandleRouting(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/routing", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// ==================扫描==================

// 将扫描请求代理到远程服务器并将入站同步到节点
func (h *RemoteManageHandler) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(r.Context(), id)
	if errors.Is(err, storage.ErrRemoteInstallationActive) {
		remoteWriteError(w, http.StatusConflict, "server installation is active; retry after it completes")
		return
	}
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, "unable to acquire server mutation lease")
		return
	}
	defer release()
	r = r.WithContext(leasedCtx)

	result, err := h.forwardToRemoteServer(r.Context(), id, "POST", "/api/child/scan", nil)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	// 解析扫描结果以更新数据库中的 X 射线状态
	var scanResult struct {
		Success     bool   `json:"success"`
		XrayRunning bool   `json:"xray_running"`
		XrayVersion string `json:"xray_version"`
	}
	if err := json.Unmarshal(result, &scanResult); err == nil && scanResult.Success {
		// 更新数据库中的 X 射线状态;状态翻转时发 TG 通知
		prev, updateErr := h.repo.UpdateRemoteServerXrayStatus(r.Context(), id, scanResult.XrayRunning, scanResult.XrayVersion)
		if updateErr != nil {
			log.Printf("[Remote Manage] Failed to update Xray status for server %d: %v", id, updateErr)
		} else if prev != scanResult.XrayRunning {
			if server, gErr := h.repo.GetRemoteServer(r.Context(), id); gErr == nil && server != nil {
				SendXrayStatusChangeNotification(r.Context(), server.Name, server.IPAddress, scanResult.XrayRunning)
			}
		}

		// 如果 Xray 正在运行，则将入站同步到节点表
		if scanResult.XrayRunning {
			syncResult := h.syncInboundsToNodesInternal(r.Context(), id)
			log.Printf("[Remote Manage] Sync inbounds result for server %d: synced=%d (claimed=%d, created=%d), skipped=%d, tags=%v",
				id, syncResult.SyncedCount, syncResult.ClaimedCount, syncResult.CreatedCount, syncResult.SkippedCount, syncResult.SyncedTags)

			// 将同步结果合并到响应中
			var response map[string]interface{}
			if err := json.Unmarshal(result, &response); err == nil {
				response["synced_count"] = syncResult.SyncedCount
				response["claimed_count"] = syncResult.ClaimedCount
				response["created_count"] = syncResult.CreatedCount
				response["skipped_count"] = syncResult.SkippedCount
				response["synced_tags"] = syncResult.SyncedTags
				if len(syncResult.Errors) > 0 {
					response["sync_errors"] = syncResult.Errors
				}
				result, _ = json.Marshal(response)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// 将远程服务器的入站同步到节点表（内部使用）
func (h *RemoteManageHandler) syncInboundsToNodesInternal(ctx context.Context, serverID int64) SyncInboundsToNodesResponse {
	return h.syncInboundsToNodes(ctx, serverID, "", false)
}

// syncInboundsToNodes 是真正的实现:auto-sync(WS scan_result)与手动同步(HandleSyncInboundsToNodes)
// 共用一份逻辑,避免两边漂移(历史上手动同步分支没有 claim 逻辑,导致"回落+路由出站"场景下同一 inbound
// 对应的多个外部节点无法被认领,见 issue: hk-n.2ha.me 节点只有 1 个被匹配的反馈)。
//
// serverHostOverride: 写入 clash proxy 配置的 server 字段;空时回退到 server.IPAddress。
// forceOverride: true 时,遇到同名节点先删除再新建(手动同步对话框的"强制覆盖"开关)。
func (h *RemoteManageHandler) syncInboundsToNodes(ctx context.Context, serverID int64, serverHostOverride string, forceOverride bool) SyncInboundsToNodesResponse {
	var response SyncInboundsToNodesResponse
	err := withRemoteInstallationSafeMutation(ctx, h.repo, serverID, "Inbound-to-node sync", func(leasedCtx context.Context) error {
		response = h.syncInboundsToNodesLeased(leasedCtx, serverID, serverHostOverride, forceOverride)
		return nil
	})
	if err != nil {
		return SyncInboundsToNodesResponse{
			Success: false,
			Errors:  []string{err.Error()},
		}
	}
	return response
}

func (h *RemoteManageHandler) syncInboundsToNodesLeased(ctx context.Context, serverID int64, serverHostOverride string, forceOverride bool) SyncInboundsToNodesResponse {
	response := SyncInboundsToNodesResponse{
		Success:    true,
		SyncedTags: []string{},
		Errors:     []string{},
	}

	// 获取远程服务器信息
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		response.Success = false
		response.Errors = append(response.Errors, fmt.Sprintf("获取服务器信息失败: %v", err))
		return response
	}

	// 调用方显式 override > Domain > 非私有 PullAddress > IPAddress
	serverHost := strings.TrimSpace(serverHostOverride)
	if serverHost == "" {
		serverHost = chooseClashServerHost(server)
	}
	if serverHost == "" {
		response.Success = false
		response.Errors = append(response.Errors, "服务器 IP/域名 均为空")
		return response
	}

	// 从远程服务器获取入站
	result, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		response.Success = false
		response.Errors = append(response.Errors, fmt.Sprintf("获取入站失败: %v", err))
		return response
	}

	var inboundsResp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(result, &inboundsResp); err != nil {
		response.Success = false
		response.Errors = append(response.Errors, fmt.Sprintf("解析入站失败: %v", err))
		return response
	}

	if !inboundsResp.Success {
		response.Success = false
		response.Errors = append(response.Errors, "远程服务器返回错误")
		return response
	}

	// 拉一次全量 xray config,提取 routing.rules 用于构造 email → outboundTag 映射。
	// 这是判定"路由出站节点"的依据 —— 客户端 email 命中 user[] 且规则有具体 outboundTag,即视为该客户端绑定到那条出站。
	// 注意:agent 返回的 config 字段是 JSON 字符串(原文),需要二次 unmarshal,不能直接当 map 读。
	// 拉取失败不算 sync 失败,仅放弃路由识别。
	emailToOutbound := map[string]string{}
	if rawCfg, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/xray/config", nil); err == nil {
		var cfgResp struct {
			Success bool   `json:"success"`
			Config  string `json:"config"`
		}
		if err := json.Unmarshal(rawCfg, &cfgResp); err == nil && cfgResp.Success && cfgResp.Config != "" {
			var xrayCfg map[string]interface{}
			if err := json.Unmarshal([]byte(cfgResp.Config), &xrayCfg); err == nil {
				if routing, _ := xrayCfg["routing"].(map[string]interface{}); routing != nil {
					if rules, _ := routing["rules"].([]interface{}); rules != nil {
						for _, r := range rules {
							rm, _ := r.(map[string]interface{})
							if rm == nil {
								continue
							}
							outTag, _ := rm["outboundTag"].(string)
							if outTag == "" || outTag == "block" || outTag == "direct" || outTag == "api" {
								continue
							}
							users, _ := rm["user"].([]interface{})
							for _, u := range users {
								if s, ok := u.(string); ok && s != "" {
									emailToOutbound[s] = outTag
								}
							}
						}
					}
				}
			}
		}
	}
	log.Printf("[Remote Manage] Sync server=%q: parsed %d routing user→outbound mappings", server.Name, len(emailToOutbound))

	// 提取 tunnel-in 的 settings.port
	tunnelInSettingsPort := 0
	if server.Domain != "" && (server.StealMode == "tunnel" || server.StealMode == "") {
		for _, ib := range inboundsResp.Inbounds {
			if tag, _ := ib["tag"].(string); tag == "tunnel-in" {
				if s, _ := ib["settings"].(map[string]interface{}); s != nil {
					if p, ok := s["port"].(float64); ok && p > 0 {
						tunnelInSettingsPort = int(p)
					}
				}
				break
			}
		}
	}

	username := h.repo.GetSystemNodeOwner(ctx)

	// 先确保 admin email 已经在 vless/vmess/trojan inbound 的 clients[] 里。
	// 历史 inbound(从 mmw 迁过来 / 老 agent 手动加的)往往只有用户原始 client,没有 admin 的 — 流量统计会算到别人头上、
	// admin 也无法以"自己的身份"连。这里给缺失的 inbound 自动补一个 admin client,凭据现场生成,后续同步幂等不重复。
	for _, inbound := range inboundsResp.Inbounds {
		protocol, _ := inbound["protocol"].(string)
		// 只对带 clients[] 的协议补 admin client;ss 类协议是入站全局密码,没有 per-client 身份
		if protocol != "vless" && protocol != "vmess" && protocol != "trojan" {
			continue
		}
		tag, _ := inbound["tag"].(string)
		if tag == "" || tag == "api" {
			continue
		}
		settings, _ := inbound["settings"].(map[string]interface{})
		if settings == nil {
			continue
		}
		clients, _ := settings["clients"].([]interface{})
		var refClient map[string]interface{}
		hasAdmin := false
		for _, c := range clients {
			cm, _ := c.(map[string]interface{})
			if cm == nil {
				continue
			}
			if e, _ := cm["email"].(string); e == username {
				hasAdmin = true
				break
			}
			if refClient == nil {
				refClient = cm
			}
		}
		if hasAdmin {
			continue
		}
		// 生成新 client。flow 复用现有 client 的(reality/vision 必须一致);其它字段 agent 端自行补默认
		newClient := map[string]interface{}{"email": username}
		switch protocol {
		case "vless", "vmess":
			newClient["id"] = uuid.New().String()
			if refClient != nil {
				if flow, ok := refClient["flow"].(string); ok && flow != "" {
					newClient["flow"] = flow
				}
			}
		case "trojan":
			newClient["password"] = uuid.New().String()
		}
		if err := addClientToInbound(ctx, h, server.ID, tag, newClient); err != nil {
			log.Printf("[Remote Manage] inject admin client failed (server=%s tag=%s): %v", server.Name, tag, err)
			continue
		}
		log.Printf("[Remote Manage] Injected admin client into inbound (server=%s tag=%s email=%s protocol=%s)", server.Name, tag, username, protocol)
		// 更新本次循环的 in-memory inbound 视图,后续 routed 检测 / 节点 dedup 才能正确看到 admin client
		settings["clients"] = append(clients, newClient)
		inbound["settings"] = settings
	}

	// 在循环之前获取现有节点一次。dedup 两步走:
	//   1. inbound_tag 精确匹配 → 直接 skip(命中后续 tag 维护逻辑无需触发)
	//   2. clash 配置指纹(server + 归一化 protocol + port)→ skip,并把库里该节点的 inbound_tag 校正成本次同步扫到的 tag,
	//      下次再同步就能走第 1 步快速通道(tag 用户改名 / 老 agent 改命名规则,都是通过这一步收敛)。
	// 端口与协议用 clash_config 字段(已应用过 tunnel 端口映射等规则,与本次同步生成的 clashProxy 同坐标系)。
	existingNodes, _ := h.repo.ListNodes(ctx, username)
	existingNodeNames := make(map[string]bool)
	existingByTag := make(map[string]bool)                  // 键: server.Name + ":" + inbound_tag
	existingByFingerprint := make(map[string]*storage.Node) // 键: server.Name + ":" + 归一化协议 + ":" + 端口

	serverAddrSet := map[string]bool{}
	for _, a := range []string{server.IPAddress, server.Domain, server.PullAddress, serverHost} {
		a = strings.TrimSpace(a)
		if a != "" {
			serverAddrSet[a] = true
		}
	}

	for i := range existingNodes {
		n := &existingNodes[i]
		existingNodeNames[n.NodeName] = true
		var config map[string]interface{}
		if err := json.Unmarshal([]byte(n.ClashConfig), &config); err != nil {
			continue
		}
		proto, _ := config["type"].(string)
		port, _ := config["port"].(float64)
		if proto == "" || port == 0 {
			continue
		}
		cfgServer, _ := config["server"].(string)
		// 节点归属本服务器的判定:已绑 original_server,或老的未绑节点但 clash_config.server 落在本服务器地址集内
		belongs := n.OriginalServer == server.Name || (n.OriginalServer == "" && serverAddrSet[cfgServer])
		if !belongs {
			continue
		}
		if n.InboundTag != "" {
			existingByTag[server.Name+":"+n.InboundTag] = true
		}
		fp := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(proto), int(port))
		// 多个节点共享同一 fingerprint(回落+路由出站)时,这里只挂第一个 —— 它代表「这条 inbound 连接坐标已被消耗」,
		// 真正需要按 credential 区分的多节点 claim 走 tryClaimExternalNodeForSync 那条独立路径。
		if _, ok := existingByFingerprint[fp]; !ok {
			existingByFingerprint[fp] = n
		}
	}

	// 处理每个入站并创建节点
	for _, inbound := range inboundsResp.Inbounds {
		tag, _ := inbound["tag"].(string)
		protocol, _ := inbound["protocol"].(string)
		port, _ := inbound["port"].(float64)

		if canonicalManagedProtocol(protocol) == "wireguard" {
			// WireGuard is management-only: reconcile its public inventory without
			// ever creating a subscription node or retaining a client private key.
			if _, resourceErr := h.upsertWireGuardManagedResource(ctx, serverID, "", "system-sync", inbound); resourceErr != nil {
				response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: WireGuard 管理记录同步失败: %v", tag, resourceErr))
			}
			response.SkippedCount++
			continue
		}
		if tag == "api" || isTunnelProtocol(protocol) {
			response.SkippedCount++
			continue
		}

		// 将入站转换为 Clash 代理配置(server 保持用 IP,域名可能走 CDN)
		// 即便该 inbound 会被 dedupe skip,我们仍需 clash_config 来 claim 同 server:port:proto 的其它外部节点
		tunnelPort := 0
		if tunnelInSettingsPort > 0 && int(port) == tunnelInSettingsPort {
			tunnelPort = 443
		}
		effectiveServerHost := serverHost
		if effPort, effHost := applyWSSClientRewrite(inbound, server); effPort > 0 {
			tunnelPort = effPort
			effectiveServerHost = effHost
		}
		clashProxy, err := h.inboundToClashProxy(inbound, effectiveServerHost, server.Name, tunnelPort)
		if err != nil {
			// "no settings found" — agent listInbounds 返回的"孤儿入站"(只有 tag/protocol/port,缺 settings),
			// 既无法生成节点配置也对用户毫无价值。后台静默调 agent remove RPC 清理掉,
			// 不污染前端 SkippedCount/Errors,用户感知不到。
			if err.Error() == "no settings found" {
				go h.silentlyRemoveOrphanInbound(serverID, tag)
				continue
			}
			response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: %v", tag, err))
			response.SkippedCount++
			continue
		}
		if clashProxy == nil {
			response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: 无法生成节点配置", tag))
			response.SkippedCount++
			continue
		}
		clashConfigJSON, err := json.Marshal(clashProxy)
		if err != nil {
			response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: 序列化配置失败", tag))
			response.SkippedCount++
			continue
		}

		// dedup key 取 clashProxy 内的 type/port —— 与存量节点 clash_config 字段同源,确保 tunnel 端口映射等规则两边一致
		proxyType, _ := clashProxy["type"].(string)
		proxyPort := 0
		switch p := clashProxy["port"].(type) {
		case float64:
			proxyPort = int(p)
		case int:
			proxyPort = p
		}
		dedupeKey := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(proxyType), proxyPort)

		// 先尝试 claim 所有匹配的未认领外部节点 — 这一步必须在 dedupe 之前,
		// 因为「回落+路由出站」场景下 1 个 inbound 可能对应 N 个客户端节点(uuid/email 不同),
		// 即使其中 1 个节点已经认领了这个 inbound(导致 dedupe 命中),其余的也仍需要 claim。
		claimedThis := h.tryClaimExternalNodeForSync(ctx, server, protocol, int(port), string(clashConfigJSON), tag)
		if claimedThis {
			response.ClaimedCount++
			if tag != "" {
				response.SyncedTags = append(response.SyncedTags, fmt.Sprintf("%s (port:%d) [claimed]", tag, int(port)))
			}
		}

		// Step 1: inbound_tag 精确匹配 → 直接 skip。最便宜的快速通道
		if tag != "" && existingByTag[server.Name+":"+tag] {
			response.SkippedCount++
			continue
		}

		// Step 2: clash 配置指纹(server+协议+端口)匹配 → skip 创建,但若 agent 这次扫到的 tag 与库里不一致,
		//          把库里 tag 校正成最新值;这样下次同步就能走 Step 1 快速通道。
		if existingNode, ok := existingByFingerprint[dedupeKey]; ok {
			if tag != "" && existingNode.InboundTag != tag {
				if err := h.repo.UpdateNodeInboundTag(ctx, existingNode.ID, tag); err != nil {
					log.Printf("[Remote Manage] UpdateNodeInboundTag id=%d %q → %q failed: %v", existingNode.ID, existingNode.InboundTag, tag, err)
				} else {
					log.Printf("[Remote Manage] Reconciled inbound_tag id=%d: %q → %q (matched by config fingerprint)", existingNode.ID, existingNode.InboundTag, tag)
					existingNode.InboundTag = tag
					existingByTag[server.Name+":"+tag] = true
				}
			}
			response.SkippedCount++
			continue
		}

		// 创建节点名称:如果没有标签,则使用协议:端口
		var nodeName string
		if tag != "" {
			nodeName = fmt.Sprintf("[%s] %s", server.Name, tag)
		} else {
			nodeName = fmt.Sprintf("[%s] %s:%d", server.Name, protocol, int(port))
		}

		// 走到这里已过 Step 1(tag)+ Step 2(fingerprint)两道真重复闸门,撞名一定是"不同物理节点碰巧同名"。
		if existingNodeNames[nodeName] {
			if forceOverride {
				// 强制覆盖:删除同名节点,后面走"创建"路径覆盖
				for _, n := range existingNodes {
					if n.NodeName == nodeName {
						if err := h.repo.DeleteNode(ctx, n.ID, username); err != nil {
							response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: 删除旧节点失败: %v", tag, err))
							response.SkippedCount++
							continue
						}
						break
					}
				}
				delete(existingNodeNames, nodeName)
			} else {
				// 撞名 → 加协议后缀保证唯一(否则订阅侧会出现重复 proxy name),而不是 skip 丢节点
				nodeName = storage.UniqueNodeName(nodeName, protocol, existingNodeNames)
			}
		}

		// 如果上一步 claim 命中,本次循环已经处理完,不再走"创建新节点"分支
		if claimedThis {
			response.SyncedCount++
			// claim 后该节点已落库,占用当前 fingerprint/tag,后续同步循环里别再生成重复
			existingByFingerprint[dedupeKey] = &storage.Node{InboundTag: tag}
			if tag != "" {
				existingByTag[server.Name+":"+tag] = true
			}
			continue
		}

		// 把 clash 配置的 name 同步成最终 nodeName(撞名改名后必须一致,订阅用的是 clash 配置里的 name)
		clashProxy["name"] = nodeName
		if b, mErr := json.Marshal(clashProxy); mErr == nil {
			clashConfigJSON = b
		}

		// 创建节点
		node := storage.Node{
			Username:       username,
			NodeName:       nodeName,
			Protocol:       protocol,
			ClashConfig:    string(clashConfigJSON),
			ParsedConfig:   string(clashConfigJSON),
			Enabled:        true,
			Tag:            fmt.Sprintf("远程:%s", server.Name),
			OriginalServer: server.Name,
			InboundTag:     tag,
		}

		if _, err := h.repo.CreateNode(ctx, node); err != nil {
			response.Errors = append(response.Errors, fmt.Sprintf("tag=%s: 创建节点失败: %v", tag, err))
			continue
		}

		response.SyncedCount++
		response.CreatedCount++
		if tag != "" {
			response.SyncedTags = append(response.SyncedTags, fmt.Sprintf("%s (port:%d)", tag, int(port)))
		} else {
			response.SyncedTags = append(response.SyncedTags, fmt.Sprintf("%s:%d", protocol, int(port)))
		}

		// 更新 dedup 索引,防止同一批次同 fingerprint 的入站再次落到这里(理论上 inbound 列表不会重复,纯防御)
		existingByFingerprint[dedupeKey] = &storage.Node{InboundTag: tag}
		if tag != "" {
			existingByTag[server.Name+":"+tag] = true
		}
		existingNodeNames[nodeName] = true
	}

	// 同步末尾顺手把该服务器下已存在节点的 clash_config.server 字段刷成当前 serverHost。
	// 主要处理"服务器配过域名后 / IP 漂移后,老节点的 server 字段还停在旧 IP"的场景 — 用户每次同步就自动校正。
	if refreshed, err := h.repo.RefreshNodesServerAddress(ctx, server.Name, serverHost); err != nil {
		log.Printf("[Remote Manage] Refresh node server address failed for %s: %v", server.Name, err)
	} else if refreshed > 0 {
		log.Printf("[Remote Manage] Refreshed %d node(s) server address → %s for %s", refreshed, serverHost, server.Name)
	}
	// v6 节点单独校正到当前 IPv6 地址(RefreshNodesServerAddress 只动 v4/域名节点)
	if v6 := strings.TrimSpace(server.IPAddressV6); v6 != "" {
		if refreshed, err := h.repo.RefreshNodesServerAddressV6(ctx, server.Name, v6); err != nil {
			log.Printf("[Remote Manage] Refresh v6 node server address failed for %s: %v", server.Name, err)
		} else if refreshed > 0 {
			log.Printf("[Remote Manage] Refreshed %d v6 node(s) server address → %s for %s", refreshed, v6, server.Name)
		}
	}

	// 路由出站节点识别:扫所有 inbound 的 clients[],建立 凭据值 → email 映射;
	// 已存在节点的 clash_config 凭据(uuid / password)能在这里反查到 email,且 email 命中 emailToOutbound 时,
	// 把节点升级为 routed_outbound 类型,parent 指向同 inbound 下"非路由"节点(master)。识别失败不阻断 sync。
	if len(emailToOutbound) > 0 {
		// per-inbound 视角:protocol:port → (credToEmail / clients)
		type inboundClientMap struct {
			credToEmail map[string]string                 // uuid|password → email
			emailToCred map[string]map[string]interface{} // email → 完整 client(用来自动建节点)
			rawInbound  map[string]interface{}            // 原始 inbound 引用,后续可调 inboundToClashProxy
		}
		perInbound := map[string]*inboundClientMap{}
		for _, inbound := range inboundsResp.Inbounds {
			protocol, _ := inbound["protocol"].(string)
			port, _ := inbound["port"].(float64)
			if protocol == "" || port == 0 || isTunnelProtocol(protocol) {
				continue
			}
			settings, _ := inbound["settings"].(map[string]interface{})
			if settings == nil {
				continue
			}
			clients, _ := settings["clients"].([]interface{})
			if len(clients) == 0 {
				continue
			}
			tunnelPortForKey := 0
			if tunnelInSettingsPort > 0 && int(port) == tunnelInSettingsPort {
				tunnelPortForKey = 443
			}
			effectivePort := int(port)
			if tunnelPortForKey > 0 {
				effectivePort = tunnelPortForKey
			}
			key := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(protocol), effectivePort)
			m := &inboundClientMap{
				credToEmail: map[string]string{},
				emailToCred: map[string]map[string]interface{}{},
				rawInbound:  inbound,
			}
			for _, c := range clients {
				cm, _ := c.(map[string]interface{})
				if cm == nil {
					continue
				}
				email, _ := cm["email"].(string)
				if email == "" {
					continue
				}
				m.emailToCred[email] = cm
				if id, ok := cm["id"].(string); ok && id != "" {
					m.credToEmail[id] = email
				}
				if pw, ok := cm["password"].(string); ok && pw != "" {
					m.credToEmail[pw] = email
				}
			}
			perInbound[key] = m
		}

		// 第一遍:按 fingerprint 找该 inbound 下的「master」物理节点 —— 凭据 email 不在 emailToOutbound 里的那个(默认/未路由用户)。
		// 找不到 master 也允许其它路由节点处理,只是 parent 留空。
		masterByFingerprint := map[string]int64{}
		for i := range existingNodes {
			n := &existingNodes[i]
			if n.OriginalServer != server.Name || n.NodeType == "routed" {
				continue
			}
			var cfg map[string]interface{}
			if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
				continue
			}
			proto, _ := cfg["type"].(string)
			port, _ := cfg["port"].(float64)
			if proto == "" || port == 0 {
				continue
			}
			fp := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(proto), int(port))
			ib := perInbound[fp]
			if ib == nil {
				continue
			}
			var cred string
			for _, k := range []string{"uuid", "password"} {
				if v, _ := cfg[k].(string); v != "" {
					cred = v
					break
				}
			}
			if cred == "" {
				continue
			}
			email := ib.credToEmail[cred]
			if _, isRouted := emailToOutbound[email]; !isRouted {
				// 该节点凭据对应的 email 不在路由规则里 → 视为 master(默认用户)
				if _, exists := masterByFingerprint[fp]; !exists {
					masterByFingerprint[fp] = n.ID
				}
			}
		}

		// 第二遍:已存在的节点凭据对应 email 命中路由规则 → 升级为 routed,parent 指 master
		matchedEmails := map[string]bool{} // 用于第三遍判断"哪些 email 还没节点"
		for i := range existingNodes {
			n := &existingNodes[i]
			if n.OriginalServer != server.Name {
				continue
			}
			var cfg map[string]interface{}
			if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
				continue
			}
			proto, _ := cfg["type"].(string)
			port, _ := cfg["port"].(float64)
			if proto == "" || port == 0 {
				continue
			}
			fp := fmt.Sprintf("%s:%s:%d", server.Name, normalizeProtocol(proto), int(port))
			ib := perInbound[fp]
			if ib == nil {
				continue
			}
			var cred string
			for _, k := range []string{"uuid", "password"} {
				if v, _ := cfg[k].(string); v != "" {
					cred = v
					break
				}
			}
			if cred == "" {
				continue
			}
			email := ib.credToEmail[cred]
			outTag, ok := emailToOutbound[email]
			if !ok {
				continue
			}
			matchedEmails[fp+":"+email] = true
			parentID := masterByFingerprint[fp]
			if err := h.repo.MarkNodeAsRouted(ctx, n.ID, outTag, parentID); err != nil {
				log.Printf("[Remote Manage] MarkNodeAsRouted id=%d email=%q → %s failed: %v", n.ID, email, outTag, err)
				continue
			}
			log.Printf("[Remote Manage] Detected routed node id=%d %q: email=%q → outboundTag=%q parent=%d", n.ID, n.NodeName, email, outTag, parentID)
			// 把这个 routed client 写进 admin 的 user_subaccounts(已存在则刷新凭据/激活状态)。
			// 不写的话:每日流量通知合并子账号失败、套餐分配也找不到这个 routed 节点对应的 admin 子账号。
			if client := ib.emailToCred[email]; client != nil {
				if credJSON, err := json.Marshal(client); err == nil {
					if _, err := h.repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
						Username: username, RoutedNodeID: n.ID, Email: email, CredentialJSON: string(credJSON), IsActive: true,
					}); err != nil {
						log.Printf("[Remote Manage] UpsertUserSubaccount routed_node=%d email=%q failed: %v", n.ID, email, err)
					}
				}
			}
		}

		// 次级 dedup:扫已有节点,记录已经存在的 (server, inbound_tag, outbound_tag) 三元组,
		// 防止上一次因为凭据映射错(uuid 取了 master 的)留下来的脏数据继续被当成"还没节点"再造一份。
		existingRoutedTriple := map[string]bool{}
		for _, n := range existingNodes {
			if n.OriginalServer != server.Name {
				continue
			}
			if n.NodeType != "routed" || n.RoutedOutboundTag == "" {
				continue
			}
			existingRoutedTriple[n.InboundTag+":"+n.RoutedOutboundTag] = true
		}

		// 第三遍:为没有节点的 routed email 自动建一个 routed 节点
		for fp, ib := range perInbound {
			master, hasMaster := masterByFingerprint[fp]
			if !hasMaster {
				continue // 没找到 master,无法挂 parent,这一轮跳过(等用户先 sync 出 master 物理节点)
			}
			inboundTagStr, _ := ib.rawInbound["tag"].(string)
			for email, client := range ib.emailToCred {
				outTag, isRouted := emailToOutbound[email]
				if !isRouted {
					continue
				}
				if matchedEmails[fp+":"+email] {
					continue // 已有节点的凭据对应该 email
				}
				if existingRoutedTriple[inboundTagStr+":"+outTag] {
					continue // 已经有一个 routed 节点占据这条 outbound,即便凭据值错了也不再追加
				}
				// 用 inboundToClashProxy 构造 clash 配置,然后把凭据字段替换为本 client 的
				tunnelPortForKey := 0
				port, _ := ib.rawInbound["port"].(float64)
				if tunnelInSettingsPort > 0 && int(port) == tunnelInSettingsPort {
					tunnelPortForKey = 443
				}
				effectiveServerHostForKey := serverHost
				if effPort, effHost := applyWSSClientRewrite(ib.rawInbound, server); effPort > 0 {
					tunnelPortForKey = effPort
					effectiveServerHostForKey = effHost
				}
				proxy, err := h.inboundToClashProxy(ib.rawInbound, effectiveServerHostForKey, server.Name, tunnelPortForKey)
				if err != nil || proxy == nil {
					log.Printf("[Remote Manage] auto-create routed node for email=%q skip: build clash failed: %v", email, err)
					continue
				}
				// xray 客户端的字段 ↔ clash 字段映射(vless/vmess/trojan):
				//   client.id ↔ proxy.uuid (vless/vmess)
				//   client.password ↔ proxy.password (trojan/ss)
				//   client.email 透传方便后续反查
				if id, ok := client["id"].(string); ok && id != "" {
					proxy["uuid"] = id
				}
				if pw, ok := client["password"].(string); ok && pw != "" {
					proxy["password"] = pw
				}
				if flow, ok := client["flow"].(string); ok && flow != "" {
					proxy["flow"] = flow
				}
				if aid, ok := client["alterId"]; ok {
					proxy["alterId"] = aid
				}
				if cipher, ok := client["cipher"].(string); ok && cipher != "" {
					proxy["cipher"] = cipher
				}
				nodeName := fmt.Sprintf("[%s] %s · %s", server.Name, inboundTagStr, email)
				proxy["name"] = nodeName
				cfgJSON, err := json.Marshal(proxy)
				if err != nil {
					continue
				}
				protocolStr, _ := ib.rawInbound["protocol"].(string)
				node := storage.Node{
					Username:       username,
					NodeName:       nodeName,
					Protocol:       protocolStr,
					ClashConfig:    string(cfgJSON),
					ParsedConfig:   string(cfgJSON),
					Enabled:        true,
					Tag:            fmt.Sprintf("远程:%s", server.Name),
					OriginalServer: server.Name,
					InboundTag:     inboundTagStr,
				}
				created, err := h.repo.CreateNode(ctx, node)
				if err != nil {
					log.Printf("[Remote Manage] auto-create routed node for email=%q failed: %v", email, err)
					continue
				}
				// 同步给 admin 注册子账号 — 同 Pass 2 的理由
				if credJSON, err := json.Marshal(client); err == nil {
					if _, err := h.repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
						Username: username, RoutedNodeID: created.ID, Email: email, CredentialJSON: string(credJSON), IsActive: true,
					}); err != nil {
						log.Printf("[Remote Manage] UpsertUserSubaccount routed_node=%d email=%q failed: %v", created.ID, email, err)
					}
				}
				// CreateNode 没有写 node_type/parent/routed_outbound_tag,补一刀
				if err := h.repo.MarkNodeAsRouted(ctx, created.ID, outTag, master); err != nil {
					log.Printf("[Remote Manage] auto-create: MarkNodeAsRouted id=%d failed: %v", created.ID, err)
				}
				existingRoutedTriple[inboundTagStr+":"+outTag] = true
				response.SyncedCount++
				response.CreatedCount++
				log.Printf("[Remote Manage] Auto-created routed node id=%d email=%q → outboundTag=%q parent=%d", created.ID, email, outTag, master)
			}
		}
	}

	response.Message = fmt.Sprintf("已同步 %d 个节点(绑定 %d 个，新增 %d 个)，跳过 %d 个",
		response.SyncedCount, response.ClaimedCount, response.CreatedCount, response.SkippedCount)
	return response
}

// protocolEquivalent 判断 clash type 和 xray protocol 是否等价。
// clash 用 `type: ss/vless/vmess/trojan`,xray 用 `protocol: shadowsocks/vless/vmess/trojan`,
// 这里把 ss <-> shadowsocks 同等化(其他名字一致)。
func protocolEquivalent(clashType, xrayProtocol string) bool {
	return normalizeProtocol(clashType) == normalizeProtocol(xrayProtocol)
}

// normalizeProtocol 把 clash type 和 xray protocol 统一成同一个规范形式,
// 便于参与 dedup key 拼装(参与字符串匹配 而不只是相等判断)。
func normalizeProtocol(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "ss" {
		return "shadowsocks"
	}
	return s
}

// 同样的等价判断,也给 NodeSyncListener / 别处用。在 event 包里也有 tryClaim,
// 那边自己也保留一份语义一致的判断;此处不导出避免跨包耦合。

// MatchRemoteServerByNodeHost 给定一个 clash 配置(JSON),如果它的 server 字段命中
// 任一已注册 remote_server 的 IPAddress/Domain/PullAddress,返回那台 server。
// 用于"导入节点时识别它是否指向 mmwx 已管理的 server",从而自动 claim。
// overrideHost 非空时用它替代 clash.server 匹配 —— 中转节点 clash.server 是中转地址,必须用
// 原始源站地址(relay_orig_server)才能匹配到真实 server。找不到返回 (nil, nil)。
func (h *RemoteManageHandler) MatchRemoteServerByNodeHost(ctx context.Context, clashConfigJSON string, overrideHost string) (*storage.RemoteServer, error) {
	srv := strings.TrimSpace(overrideHost)
	if srv == "" {
		if strings.TrimSpace(clashConfigJSON) == "" {
			return nil, nil
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(clashConfigJSON), &cfg); err != nil {
			return nil, nil
		}
		s, _ := cfg["server"].(string)
		srv = strings.TrimSpace(s)
	}
	if srv == "" {
		return nil, nil
	}
	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range servers {
		s := &servers[i]
		for _, host := range []string{s.IPAddress, s.Domain, s.PullAddress} {
			if strings.TrimSpace(host) == "" {
				continue
			}
			if strings.EqualFold(host, srv) {
				return s, nil
			}
		}
	}
	return nil, nil
}

// tryClaimExternalNodeForSync 在 sync inbounds → nodes 流程里,扫"外部节点"
// (original_server=” AND inbound_tag=”),按 server 地址(IP/Domain/PullAddress 任一)+ port + protocol
// 匹配,把命中的节点全部升级为受管节点(填上 original_server + inbound_tag),返回是否至少 claim 了一个。
//
// 全部 claim 而非 claim 第一个:同一台服务器使用「回落+路由出站」时,订阅里会出现多条
// server+port+protocol 完全相同、只是用户凭据 / email 不同的客户端节点(各自走不同上游路径),
// 都应该匹配到这台服务器,见 Issue: hk-n.2ha.me 多个节点只匹配到 1 个的反馈。
func (h *RemoteManageHandler) tryClaimExternalNodeForSync(ctx context.Context, server *storage.RemoteServer, protocol string, port int, clashConfigJSON, inboundTag string) bool {
	candidates := map[string]bool{}
	for _, a := range []string{server.IPAddress, server.Domain, server.PullAddress} {
		a = strings.TrimSpace(a)
		if a != "" {
			candidates[a] = true
		}
	}
	if len(candidates) == 0 {
		return false
	}
	allNodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		return false
	}
	claimedAny := false
	for _, n := range allNodes {
		owner, ownerErr := h.repo.GetUser(ctx, n.Username)
		if ownerErr != nil || owner.Role != storage.RoleAdmin {
			continue
		}
		if strings.TrimSpace(n.OriginalServer) != "" || strings.TrimSpace(n.InboundTag) != "" {
			continue
		}
		if n.NodeType == "routed" {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
			continue
		}
		srv, _ := cfg["server"].(string)
		if !candidates[srv] {
			continue
		}
		var cfgPort int
		switch p := cfg["port"].(type) {
		case float64:
			cfgPort = int(p)
		case int:
			cfgPort = p
		}
		if cfgPort != port {
			continue
		}
		proto, _ := cfg["type"].(string)
		if !protocolEquivalent(proto, protocol) {
			continue
		}
		// 命中:用 agent 转出来的 clash_config 作为「连接配置」基础,但保留原节点名(用户改过的中文名)
		// 以及原 clash_config 里区分各节点的凭据字段(uuid/password/email,因为这是回落+路由出站下区分 route 的关键)
		mergedConfig := clashConfigJSON
		var newCfg map[string]any
		if err := json.Unmarshal([]byte(clashConfigJSON), &newCfg); err == nil {
			if name, _ := cfg["name"].(string); name != "" {
				newCfg["name"] = name
			}
			// 凭据字段 — 多节点共用同一 inbound 时,这些字段是区分路由的关键,必须保留原值
			for _, k := range []string{"uuid", "password", "email", "alterId", "cipher"} {
				if v, ok := cfg[k]; ok {
					newCfg[k] = v
				}
			}
			if updated, err := json.Marshal(newCfg); err == nil {
				mergedConfig = string(updated)
			}
		}
		if err := h.repo.ClaimExternalNode(ctx, n.ID, server.Name, inboundTag, fmt.Sprintf("远程:%s", server.Name), mergedConfig); err != nil {
			log.Printf("[Remote Manage] tryClaim node %d failed: %v", n.ID, err)
			continue
		}
		log.Printf("[Remote Manage] Claimed external node id=%d name=%q for %s/%s:%d", n.ID, n.NodeName, server.Name, protocol, port)
		claimedAny = true
	}
	return claimedAny
}

// ================== X射线系统配置==================

// 将 xray 系统配置请求代理到远程服务器
func (h *RemoteManageHandler) HandleXraySystemConfig(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	var body []byte
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			remoteWriteError(w, http.StatusBadRequest, "failed to read body")
			return
		}
	}

	result, err := h.forwardToRemoteServer(r.Context(), id, r.Method, "/api/child/xray/system-config", body)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

// ================== 将入站同步到节点 ==================

// SyncInboundsToNodesRequest 表示将入站同步到节点的请求
type SyncInboundsToNodesRequest struct {
	ServerHost    string `json:"server_host"`    // 远程服务器的对外访问地址
	ForceOverride bool   `json:"force_override"` // 是否强制覆盖已存在的节点
}

// SyncInboundsToNodesResponse 表示同步入站的响应
type SyncInboundsToNodesResponse struct {
	Success      bool     `json:"success"`
	Message      string   `json:"message"`
	SyncedCount  int      `json:"synced_count"`
	ClaimedCount int      `json:"claimed_count"` // 自动绑定已有外部节点的数量
	CreatedCount int      `json:"created_count"` // 新建节点的数量
	SkippedCount int      `json:"skipped_count"`
	SyncedTags   []string `json:"synced_tags,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

// 将远程服务器的入站同步到节点表(手动触发)。
// 与 WS scan_result 自动同步共用 syncInboundsToNodes 实现 — 不再单独写一份循环逻辑,
// 防止 claim/dedupe/规则跨入口漂移。
func (h *RemoteManageHandler) HandleSyncInboundsToNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	// 解析请求体(server_host + force_override 都是可选)
	var req SyncInboundsToNodesRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			remoteWriteError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}

	response := h.syncInboundsToNodes(r.Context(), id, req.ServerHost, req.ForceOverride)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// chooseClashServerHost 给一台 remote server 选合适的 clash_config.server 值。
// 优先级:Domain → PullAddress (仅当不是 IP) → IPAddress。
//
// 关键规则:PullAddress 是 IP 字符串(v4/v6)→ 跳过,fall to IPAddress。
// 因为 IPAddress 由 agent 心跳实时上报,IP 漂移自动跟随;而 PullAddress 是用户表单写入的静态字符串,
// 漂了不会自己更新,如果用作 clash.server 会让节点指向旧 IP。
// 反过来 PullAddress 是域名/反代地址时保留 — 域名是稳定的,用户特意填的就是要走它。
func chooseClashServerHost(server *storage.RemoteServer) string {
	if server == nil {
		return ""
	}
	if d := strings.TrimSpace(server.Domain); d != "" {
		return d
	}
	if p := strings.TrimSpace(server.PullAddress); p != "" && net.ParseIP(p) == nil {
		return p
	}
	return strings.TrimSpace(server.IPAddress)
}

// silentlyRemoveOrphanInbound 在后台静默删除 agent 上的"孤儿入站"(listInbounds 返回但 settings 缺失)。
// 触发场景:agent 的 xray runtime 里残留只有 tag/protocol/port 没 settings 的入站,通常来自:
//   - 手动 SSH 操作时半截写入的入站
//   - 历史 bug 留下的损坏入站
//   - confdir 下 *.json 文件丢失但 runtime 还在跑
//
// 这类入站既无法生成节点配置,留着只会每次扫描污染 SkippedCount/Errors,用户也看不懂。
// 直接调 agent 的 inbounds remove RPC 清掉,跟 deleteRemoteInbound 同款路径。
// 失败只 log,不阻塞 sync 流程;成功也只 log,前端无感。
func (h *RemoteManageHandler) silentlyRemoveOrphanInbound(serverID int64, tag string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"action": "remove", "tag": tag})
	if _, err := h.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/inbounds", body); err != nil {
		log.Printf("[SyncInbounds] silent cleanup of orphan inbound %s on server=%d failed: %v", tag, serverID, err)
		return
	}
	log.Printf("[SyncInbounds] silently removed orphan inbound %s on server=%d (no settings found)", tag, serverID)
}

// inboundToClashProxy 将 Xray 入站配置转换为 Clash 代理配置。
// tunnelPort > 0 表示服务器使用隧道模式；将其用作节点的外部端口。
func (h *RemoteManageHandler) inboundToClashProxy(inbound map[string]interface{}, serverHost, serverName string, tunnelPort int) (map[string]interface{}, error) {
	protocol, _ := inbound["protocol"].(string)
	protocol = canonicalManagedProtocol(protocol)
	tag, _ := inbound["tag"].(string)
	port, _ := inbound["port"].(float64)
	settings, _ := inbound["settings"].(map[string]interface{})
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})

	if settings == nil {
		return nil, fmt.Errorf("no settings found")
	}

	// 获取第一个客户/帐户(anytls 用 users[],其他主流协议用 clients[],socks/http 用 accounts[])
	var client map[string]interface{}
	if clients, ok := settings["clients"].([]interface{}); ok && len(clients) > 0 {
		client, _ = clients[0].(map[string]interface{})
	} else if users, ok := settings["users"].([]interface{}); ok && len(users) > 0 {
		client, _ = users[0].(map[string]interface{})
	} else if accounts, ok := settings["accounts"].([]interface{}); ok && len(accounts) > 0 {
		client, _ = accounts[0].(map[string]interface{})
	}

	// shadowsocks server 端 password 在 settings 顶层不在 clients[];socks / http 无认证模式 accounts 可空;
	// dokodemo-door 是端口转发,本来就没 clients/users/accounts。这几个协议允许 client == nil 继续走下游 case 分支。
	// 历史 bug:只放过 shadowsocks → 无认证 SOCKS5 入站扫描时这里报 "no client/account found",
	// syncInboundsToNodes SkippedCount++ → 节点不进 DB → UI 节点列表看不到 + 无法删除。
	noClientProtocols := map[string]bool{"shadowsocks": true, "socks": true, "http": true, "dokodemo-door": true}
	if client == nil && !noClientProtocols[protocol] {
		return nil, fmt.Errorf("no client/account found")
	}

	// 节点名称
	nodeName := fmt.Sprintf("[%s] %s", serverName, tag)

	nodePort := int(port)
	if tunnelPort > 0 {
		nodePort = tunnelPort
	}

	proxy := map[string]interface{}{
		"name":   nodeName,
		"server": serverHost,
		"port":   nodePort,
	}

	switch protocol {
	case "vless":
		proxy["type"] = "vless"
		if id, ok := client["id"].(string); ok {
			proxy["uuid"] = id
		}
		// 检查流量
		if flow, ok := client["flow"].(string); ok && flow != "" {
			proxy["flow"] = flow
		}
		// VLESS Reality V2 encryption(mihomo 已支持):服务端的 settings.encryption 客户端配置必须带,
		// 否则握手失败。注意是 settings.encryption(对外下发的密钥),不是 decryption(服务端自己解密)。
		if enc, ok := settings["encryption"].(string); ok && enc != "" && enc != "none" {
			proxy["encryption"] = enc
		}
		// 添加流设置
		if err := h.addStreamSettings(proxy, streamSettings); err != nil {
			return nil, err
		}

	case "vmess":
		proxy["type"] = "vmess"
		if id, ok := client["id"].(string); ok {
			proxy["uuid"] = id
		}
		proxy["alterId"] = 0
		if aid, ok := client["alterId"].(float64); ok {
			proxy["alterId"] = int(aid)
		}
		proxy["cipher"] = "auto"
		if cipher, ok := client["security"].(string); ok && strings.TrimSpace(cipher) != "" {
			proxy["cipher"] = strings.ToLower(strings.TrimSpace(cipher))
		}
		// 添加流设置
		if err := h.addStreamSettings(proxy, streamSettings); err != nil {
			return nil, err
		}

	case "trojan":
		proxy["type"] = "trojan"
		if password, ok := client["password"].(string); ok {
			proxy["password"] = password
		}
		// 检查流量
		if flow, ok := client["flow"].(string); ok && flow != "" {
			proxy["flow"] = flow
		}
		// 添加流设置
		if err := h.addStreamSettings(proxy, streamSettings); err != nil {
			return nil, err
		}
		// mihomo trojan 使用 sni 而非 servername
		if sn, ok := proxy["servername"]; ok {
			proxy["sni"] = sn
			delete(proxy, "servername")
		}

	case "shadowsocks":
		proxy["type"] = "ss"
		method, _ := settings["method"].(string)
		if method != "" {
			proxy["cipher"] = method
		}
		// SS2022(method 以 "2022-" 开头)需要 `master:userPass` 双段密码。
		// 节点 clash_config 是 admin 视角(也用作直接订阅 / routed 出站模板):
		//   - 有 client → 拼 `master:firstClient.password`(jimlee 等 admin 自用此节点能直接订阅)
		//   - 无 client → 只放 master(空 inbound,后续 user override 时再拼)
		// 订阅生成时 appendUserCredentialOverride 会兜底剥掉冒号后段重拼当前用户密码,所以多用户场景不会三段叠加。
		// 老 SS(非 2022)单段密码,直接 master 就够,client password 跟 master 必须相同 → 不拼。
		nodePass, _ := settings["password"].(string)
		if strings.HasPrefix(method, "2022-") {
			if clients, ok := settings["clients"].([]interface{}); ok && len(clients) > 0 {
				if first, ok := clients[0].(map[string]interface{}); ok {
					if clientPass, ok := first["password"].(string); ok && clientPass != "" {
						nodePass = nodePass + ":" + clientPass
					}
				}
			}
		}
		if nodePass != "" {
			proxy["password"] = nodePass
		}

	case "hysteria":
		proxy["type"] = "hysteria2"
		if auth, ok := client["auth"].(string); ok {
			proxy["password"] = auth
		}
		if streamSettings != nil {
			if tlsSettings, ok := streamSettings["tlsSettings"].(map[string]interface{}); ok {
				if sni, ok := tlsSettings["serverName"].(string); ok && sni != "" {
					proxy["sni"] = sni
				}
			}
			if hySettings, ok := streamSettings["hysteriaSettings"].(map[string]interface{}); ok {
				if obfsPwd, ok := hySettings["password"].(string); ok && obfsPwd != "" {
					proxy["obfs"] = "salamander"
					proxy["obfs-password"] = obfsPwd
				}
			}
		}

	case "anytls":
		// mihomo anytls(https://wiki.metacubex.one/en/config/proxies/anytls/):password + sni,跟 trojan 几乎一致。
		proxy["type"] = "anytls"
		// anytls 天然支持 UDP(UDP-over-TCP,服务端自动无需配置),默认开启;不依赖 streamSettings
		// 是否为 nil(addStreamSettings 在 streamSettings==nil 时会提前返回、漏设 udp)。
		proxy["udp"] = true
		if password, ok := client["password"].(string); ok {
			proxy["password"] = password
		}
		if err := h.addStreamSettings(proxy, streamSettings); err != nil {
			return nil, err
		}
		if sn, ok := proxy["servername"]; ok {
			proxy["sni"] = sn
			delete(proxy, "servername")
		}

	case "socks", "http":
		proxy["type"] = protocol
		// client 为 nil 时(无认证模式),clash 配置不带 username/password,客户端按无认证直连。
		if client != nil {
			if user, ok := client["user"].(string); ok {
				proxy["username"] = user
			}
			if pass, ok := client["pass"].(string); ok {
				proxy["password"] = pass
			}
		}

	case "snell":
		// mihomo/clash snell:type:snell, server, port, psk, version, obfs-opts:{mode,host}(v4/v5);
		// v6:mode(default/unshaped/unsafe-raw)。字段来自 settings.users[] 条目(generateInboundConfig 下发)。
		proxy["type"] = "snell"
		if psk, ok := client["psk"].(string); ok {
			proxy["psk"] = psk
		}
		version := 4
		if v, ok := client["version"].(float64); ok {
			version = int(v)
		} else if v, ok := client["version"].(int); ok {
			version = v
		}
		proxy["version"] = version
		if version == 6 {
			if mode, ok := client["v6Mode"].(string); ok && mode != "" {
				proxy["mode"] = mode
			}
		} else if obfsMode, ok := client["obfsMode"].(string); ok && obfsMode != "" && obfsMode != "none" {
			obfsOpts := map[string]interface{}{"mode": obfsMode}
			if obfsHost, ok := client["obfsHost"].(string); ok && obfsHost != "" {
				obfsOpts["host"] = obfsHost
			}
			proxy["obfs-opts"] = obfsOpts
		}

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	if skip, _ := inbound[managedClientSkipCertVerifyMarker].(bool); skip {
		security, _ := streamSettings["security"].(string)
		if strings.EqualFold(strings.TrimSpace(security), "tls") {
			proxy["skip-cert-verify"] = true
		}
	}

	return proxy, nil
}

func canonicalManagedProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ss":
		return "shadowsocks"
	case "hysteria2", "hy2":
		return "hysteria"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

// 将流设置添加到 Clash 代理配置
func (h *RemoteManageHandler) addStreamSettings(proxy map[string]interface{}, streamSettings map[string]interface{}) error {
	if streamSettings == nil {
		return nil
	}

	network, _ := streamSettings["network"].(string)
	security, _ := streamSettings["security"].(string)

	// 设置网络类型（始终包含，即使对于 tcp）
	if network != "" {
		proxy["network"] = network
	}

	// UDP支持
	proxy["udp"] = true

	// 处理 TLS
	if security == "tls" {
		proxy["tls"] = true
		if tlsSettings, ok := streamSettings["tlsSettings"].(map[string]interface{}); ok {
			if sni, ok := tlsSettings["serverName"].(string); ok && sni != "" {
				proxy["servername"] = sni
			}
			if alpn, ok := tlsSettings["alpn"].([]interface{}); ok && len(alpn) > 0 {
				alpnStrs := make([]string, 0, len(alpn))
				for _, a := range alpn {
					if s, ok := a.(string); ok {
						alpnStrs = append(alpnStrs, s)
					}
				}
				proxy["alpn"] = alpnStrs
			}
			if fp, ok := tlsSettings["fingerprint"].(string); ok && fp != "" {
				proxy["client-fingerprint"] = fp
			}
			// 反查 xray → clash:客户端不支持 pinnedPeerCertSha256,只能退化到 skip-cert-verify。
			// - pinnedPeerCertSha256 非空 → skip-cert-verify=true(客户端宽松,但服务端仍精确锁证书)
			// - allowInsecure(老数据兼容)→ 同上
			pinned, _ := tlsSettings["pinnedPeerCertSha256"].(string)
			allowInsecure, _ := tlsSettings["allowInsecure"].(bool)
			if strings.TrimSpace(pinned) != "" || allowInsecure {
				proxy["skip-cert-verify"] = true
			} else {
				proxy["skip-cert-verify"] = false
			}
		}
	}

	// 处理现实
	if security == "reality" {
		proxy["tls"] = true
		proxy["skip-cert-verify"] = true
		realitySettings, ok := streamSettings["realitySettings"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("Reality 入站缺少 realitySettings")
		}
		realityOpts := map[string]interface{}{}
		publicKey, err := managedRealityPublicKey(realitySettings)
		if err != nil {
			return err
		}
		realityOpts["public-key"] = publicKey
		// ShortIds 是 Xray 配置中的一个数组
		if shortIds, ok := realitySettings["shortIds"].([]interface{}); ok && len(shortIds) > 0 {
			if sid, ok := shortIds[0].(string); ok {
				realityOpts["short-id"] = sid
			}
		}
		// 后备：单个 ShortId 字段
		if _, exists := realityOpts["short-id"]; !exists {
			if shortId, ok := realitySettings["shortId"].(string); ok {
				realityOpts["short-id"] = shortId
			}
		}
		if spiderX, ok := realitySettings["spiderX"].(string); ok {
			realityOpts["spider-x"] = spiderX
		}
		if len(realityOpts) > 0 {
			proxy["reality-opts"] = realityOpts
		}
		// serverNames 是 Xray 配置中的一个数组
		if serverNames, ok := realitySettings["serverNames"].([]interface{}); ok && len(serverNames) > 0 {
			if sn, ok := serverNames[0].(string); ok && sn != "" {
				proxy["servername"] = strings.ToLower(strings.TrimSpace(sn))
			}
		}
		// 后备：单个 serverName 字段
		if _, exists := proxy["servername"]; !exists {
			if sni, ok := realitySettings["serverName"].(string); ok && sni != "" {
				proxy["servername"] = strings.ToLower(strings.TrimSpace(sni))
			}
		}
		sni, _ := proxy["servername"].(string)
		if net.ParseIP(sni) != nil || !validManagedDNSName(sni) {
			return fmt.Errorf("Reality 入站缺少有效的 serverNames / SNI 域名")
		}
		if fp, ok := realitySettings["fingerprint"].(string); ok && fp != "" {
			proxy["client-fingerprint"] = fp
		}
		// 如果未设置，则为 REALITY 默认客户端指纹
		if _, exists := proxy["client-fingerprint"]; !exists {
			proxy["client-fingerprint"] = "chrome"
		}
	}

	// 处理WebSocket
	if network == "ws" {
		if wsSettings, ok := streamSettings["wsSettings"].(map[string]interface{}); ok {
			wsOpts := map[string]interface{}{}
			if path, ok := wsSettings["path"].(string); ok {
				wsOpts["path"] = path
			}
			var wsHeaders map[string]interface{}
			if headers, ok := wsSettings["headers"].(map[string]interface{}); ok {
				wsHeaders = make(map[string]interface{}, len(headers)+1)
				for key, value := range headers {
					wsHeaders[key] = value
				}
			}
			// Xray's current WebSocket schema uses wsSettings.host. Mihomo still
			// represents the HTTP Host header under ws-opts.headers.Host.
			if host, ok := wsSettings["host"].(string); ok && strings.TrimSpace(host) != "" {
				if wsHeaders == nil {
					wsHeaders = map[string]interface{}{}
				}
				wsHeaders["Host"] = strings.TrimSpace(host)
			}
			if len(wsHeaders) > 0 {
				wsOpts["headers"] = wsHeaders
			}
			if len(wsOpts) > 0 {
				proxy["ws-opts"] = wsOpts
			}
		}
	}

	// 处理 gRPC
	if network == "grpc" {
		if grpcSettings, ok := streamSettings["grpcSettings"].(map[string]interface{}); ok {
			grpcOpts := map[string]interface{}{}
			if serviceName, ok := grpcSettings["serviceName"].(string); ok {
				grpcOpts["grpc-service-name"] = serviceName
			}
			if len(grpcOpts) > 0 {
				proxy["grpc-opts"] = grpcOpts
			}
		}
	}

	// 处理 HTTP/2
	if network == "h2" || network == "http" {
		if httpSettings, ok := streamSettings["httpSettings"].(map[string]interface{}); ok {
			h2Opts := map[string]interface{}{}
			if path, ok := httpSettings["path"].(string); ok {
				h2Opts["path"] = path
			}
			if host, ok := httpSettings["host"].([]interface{}); ok && len(host) > 0 {
				h2Opts["host"] = host
			}
			if len(h2Opts) > 0 {
				proxy["h2-opts"] = h2Opts
			}
		}
	}

	// 处理 XHTTP
	if network == "xhttp" {
		if xhttpSettings, ok := streamSettings["xhttpSettings"].(map[string]interface{}); ok {
			xhttpOpts := map[string]interface{}{
				"headers": map[string]interface{}{},
			}
			if path, ok := xhttpSettings["path"].(string); ok {
				xhttpOpts["path"] = path
			}
			proxy["xhttp-opts"] = xhttpOpts
			if mode, ok := xhttpSettings["mode"].(string); ok && mode != "" {
				proxy["mode"] = mode
			}
		}
	}
	return nil
}

func decodeManagedRealityKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	encodings := []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("Reality X25519 密钥必须是 32 字节 Base64")
}

func managedRealityPublicKey(settings map[string]interface{}) (string, error) {
	if publicKey, _ := settings["publicKey"].(string); strings.TrimSpace(publicKey) != "" {
		decoded, err := decodeManagedRealityKey(publicKey)
		if err != nil {
			return "", fmt.Errorf("Reality publicKey 无效: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(decoded), nil
	}
	privateKey, _ := settings["privateKey"].(string)
	decoded, err := decodeManagedRealityKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("Reality 入站缺少可用于派生公钥的有效 privateKey: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", fmt.Errorf("Reality privateKey 无法派生公钥: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func (h *RemoteManageHandler) getTunnelInSettingsPort(ctx context.Context, serverID int64) int {
	result, err := h.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		return 0
	}
	var resp struct {
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if json.Unmarshal(result, &resp) != nil {
		return 0
	}
	for _, ib := range resp.Inbounds {
		tag, _ := ib["tag"].(string)
		if tag != "tunnel-in" {
			continue
		}
		settings, _ := ib["settings"].(map[string]interface{})
		if settings == nil {
			return 0
		}
		if p, ok := settings["port"].(float64); ok && p > 0 {
			return int(p)
		}
		return 0
	}
	return 0
}

// InboundToClashProxyByServerID 将 Xray 入站配置转换为 Clash 代理 JSON 字符串。
// 这是供事件侦听器使用的导出方法。
func (h *RemoteManageHandler) InboundToClashProxyByServerID(serverID int64, inbound map[string]any) (string, error) {
	ctx := context.Background()
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return "", fmt.Errorf("get server: %w", err)
	}

	serverHost := chooseClashServerHost(server)
	tunnelPort := 0

	// tunnel 模式:新入站端口正好等于 tunnel-in 的 settings.port,意味着这条入站会被 tunnel 暴露在 443
	if server.Domain != "" && (server.StealMode == "tunnel" || server.StealMode == "") {
		inboundPort := 0
		if p, ok := inbound["port"].(float64); ok {
			inboundPort = int(p)
		} else if p, ok := inbound["port"].(int); ok {
			inboundPort = p
		}

		if inboundPort > 0 {
			tunnelInSettingsPort := h.getTunnelInSettingsPort(ctx, serverID)
			if tunnelInSettingsPort > 0 && inboundPort == tunnelInSettingsPort {
				tunnelPort = 443
			}
		}
	}

	if serverHost == "" {
		return "", fmt.Errorf("server has no IP or domain")
	}

	inboundMap := make(map[string]interface{})
	for k, v := range inbound {
		inboundMap[k] = v
	}

	if effPort, effHost := applyWSSClientRewrite(inboundMap, server); effPort > 0 {
		tunnelPort = effPort
		serverHost = effHost
	}

	proxy, err := h.inboundToClashProxy(inboundMap, serverHost, server.Name, tunnelPort)
	if err != nil {
		return "", err
	}

	clashJSON, err := json.Marshal(proxy)
	if err != nil {
		return "", fmt.Errorf("marshal clash config: %w", err)
	}

	return string(clashJSON), nil
}

// applyWSSClientRewrite 若 inbound 是受支持的 WSS 入站(network=ws + security=none + listen 127.0.0.1),
// 把 inboundMap 原地改写为"客户端视角"(security=tls, tlsSettings.serverName=domain, wsSettings.host=domain),
// 并返回客户端连接用的端口(443) + serverHost(域名)。
//
// 否则不修改 inboundMap,返回 (0, "")。调用方据此判断是否覆盖默认 tunnelPort/serverHost。
//
// 设计上 server.Domain 必须有 — 没域名 nginx + TLS 链路根本起不来,所以 WSS 入站本来就要求 domain 存在。
func applyWSSClientRewrite(inboundMap map[string]interface{}, server *storage.RemoteServer) (port int, host string) {
	if server == nil || server.Domain == "" {
		return 0, ""
	}
	if !isNginxManagedWSSInbound(inboundMap) {
		return 0, ""
	}
	ss, _ := inboundMap["streamSettings"].(map[string]interface{})

	// 不污染外面持有的 streamSettings,做浅拷贝
	ssCopy := make(map[string]interface{}, len(ss)+1)
	for k, v := range ss {
		ssCopy[k] = v
	}
	ssCopy["security"] = "tls"
	ssCopy["tlsSettings"] = map[string]interface{}{"serverName": server.Domain}

	ws, _ := ssCopy["wsSettings"].(map[string]interface{})
	wsCopy := make(map[string]interface{}, len(ws)+1)
	for k, v := range ws {
		wsCopy[k] = v
	}
	wsCopy["host"] = server.Domain
	ssCopy["wsSettings"] = wsCopy
	inboundMap["streamSettings"] = ssCopy
	return 443, server.Domain
}

// 重置服务器令牌（代理用于推送到服务器）
func (h *RemoteManageHandler) HandleResetServerToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	ctx := r.Context()
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, id)
	if errors.Is(err, storage.ErrRemoteInstallationActive) {
		remoteWriteError(w, http.StatusConflict, "server installation is active; retry after it completes")
		return
	}
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, "unable to acquire server mutation lease")
		return
	}
	defer release()
	ctx = leasedCtx

	// 获取当前服务器信息以查找旧令牌
	server, err := h.repo.GetRemoteServer(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}
	oldToken := server.Token

	// 重置令牌
	newToken, expiresAt, err := h.repo.ResetServerToken(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	guardSynced := syncRemoteExpiryGuardAgentToken(ctx, h.repo, id, newToken) == nil
	if !guardSynced {
		log.Printf("[Token Reset] Failed to synchronize expiry guard token for server %d", id)
	}

	// 尝试通过 WebSocket 将新令牌推送到连接的代理
	pushSuccess := false
	if h.wsHandler != nil && h.wsHandler.IsConnected(oldToken) {
		if err := h.wsHandler.SendTokenUpdate(oldToken, newToken, *expiresAt); err != nil {
			log.Printf("[Token Reset] Failed to push token update to agent: %v", err)
		} else {
			pushSuccess = true
			log.Printf("[Token Reset] Successfully pushed new token to server %s", server.Name)
		}
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"server_token": newToken,
		"expires_at":   expiresAt.Format(time.RFC3339),
		"pushed":       pushSuccess,
		"guard_synced": guardSynced,
		"message":      "Server token reset successfully",
	})
}

// 重置代理令牌（服务器使用它从代理中拉取）
func (h *RemoteManageHandler) HandleResetAgentToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	ctx := r.Context()
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, id)
	if errors.Is(err, storage.ErrRemoteInstallationActive) {
		remoteWriteError(w, http.StatusConflict, "server installation is active; retry after it completes")
		return
	}
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, "unable to acquire server mutation lease")
		return
	}
	defer release()
	ctx = leasedCtx

	// 重置代理令牌
	newToken, expiresAt, err := h.repo.ResetAgentToken(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":     true,
		"agent_token": newToken,
		"expires_at":  expiresAt.Format(time.RFC3339),
		"message":     "Agent token reset successfully",
	})
}

// 重置服务器令牌和代理令牌
func (h *RemoteManageHandler) HandleResetAllTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	serverID := r.URL.Query().Get("server_id")
	if serverID == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id required")
		return
	}

	id, err := strconv.ParseInt(serverID, 10, 64)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}

	ctx := r.Context()
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, id)
	if errors.Is(err, storage.ErrRemoteInstallationActive) {
		remoteWriteError(w, http.StatusConflict, "server installation is active; retry after it completes")
		return
	}
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, "unable to acquire server mutation lease")
		return
	}
	defer release()
	ctx = leasedCtx

	// 获取当前服务器信息以查找旧令牌
	server, err := h.repo.GetRemoteServer(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}
	oldToken := server.Token

	// 重置所有令牌
	serverToken, serverExpiresAt, agentToken, agentExpiresAt, err := h.repo.ResetAllTokens(ctx, id)
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	guardSynced := syncRemoteExpiryGuardAgentToken(ctx, h.repo, id, serverToken) == nil
	if !guardSynced {
		log.Printf("[Token Reset] Failed to synchronize expiry guard token for server %d", id)
	}

	// 尝试通过 WebSocket 将新的服务器令牌推送到连接的代理
	pushSuccess := false
	if h.wsHandler != nil && h.wsHandler.IsConnected(oldToken) {
		if err := h.wsHandler.SendTokenUpdate(oldToken, serverToken, *serverExpiresAt); err != nil {
			log.Printf("[Token Reset] Failed to push token update to agent: %v", err)
		} else {
			pushSuccess = true
			log.Printf("[Token Reset] Successfully pushed new token to server %s", server.Name)
		}
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success":                 true,
		"server_token":            serverToken,
		"server_token_expires_at": serverExpiresAt.Format(time.RFC3339),
		"agent_token":             agentToken,
		"agent_token_expires_at":  agentExpiresAt.Format(time.RFC3339),
		"pushed":                  pushSuccess,
		"guard_synced":            guardSynced,
		"message":                 "All tokens reset successfully",
	})
}

// isXrayConfigError 判断 xray 重启失败是否源于「配置本身」(JSON 解析 / config 构建失败)。
// 这类错误重启多少次、清 nginx stream、停 nginx 都救不了 —— config 不改就永远起不来。
// 内嵌模式下,主控对坏配置反复升级重启会挤占 / 阻塞 agent 的 WS 心跳,把它误判成「断联」
// (见:负载均衡 burstObservatory 缺 pingConfig 导致整机假性掉线的事故)。命中则跳过后续升级重试。
func isXrayConfigError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, kw := range []string{
		"failed to parse json config",
		"infra/conf",
		"requires a valid",
		"failed to build",
		"unknown config id",
		"failed to load",
	} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

func (h *RemoteManageHandler) restartXrayWithRecovery(ctx context.Context, serverID int64, logPrefix string) error {
	leasedCtx, release, err := h.repo.AcquireRemoteServerMutationLease(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()
	ctx = leasedCtx

	// restartAndVerify 改成 polling — 之前固定 sleep N 秒固然简单但显著拖慢套餐绑定/批量操作:
	// 主控对每条 server restart 都等满 sleep 时长,套餐里多 routed 节点跨多台 server 时
	// total wait ≈ 最慢 server 的 sleep 时长。xray 实际重启通常 < 500ms,polling 能把
	// 多数情况从 sleep 2s 砍到 ~200ms,batch 绑定/解绑直接感知"立刻完成"。
	restartAndVerify := func(maxWait time.Duration) error {
		controlResult, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/services/control", []byte(`{"service":"xray","action":"restart"}`))
		if err != nil {
			return err
		}
		var controlAck struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(controlResult, &controlAck); err != nil || !controlAck.Success {
			return fmt.Errorf("Agent did not acknowledge Xray restart: %s", strings.TrimSpace(controlAck.Message))
		}
		// 先给 100ms 让 service 退出再 polling,避免恰好 catch 到老进程残留 running 状态。
		time.Sleep(100 * time.Millisecond)
		deadline := time.Now().Add(maxWait)
		var lastErr error
		for {
			statusResult, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/services/status", nil)
			if err == nil {
				var statusResp struct {
					Xray *struct {
						Running bool `json:"running"`
					} `json:"xray"`
				}
				if jerr := json.Unmarshal(statusResult, &statusResp); jerr == nil && statusResp.Xray != nil && statusResp.Xray.Running {
					return nil
				}
				lastErr = fmt.Errorf("xray not yet running")
			} else {
				lastErr = fmt.Errorf("failed to check xray status: %v", err)
			}
			if time.Now().After(deadline) {
				if lastErr == nil {
					return fmt.Errorf("xray process exited after restart (likely port conflict)")
				}
				return lastErr
			}
			time.Sleep(150 * time.Millisecond)
		}
	}

	// 第一轮:polling 最多 2 秒 — 正常 xray 启动通常 < 500ms
	if err := restartAndVerify(2 * time.Second); err == nil {
		return nil
	} else {
		log.Printf("[%s] Xray restart attempt 1 failed on server %d: %v", logPrefix, serverID, err)
		// config 本身错误(如 burstObservatory 缺 pingConfig / anytls 未知协议 / JSON 解析失败):
		// 后面的升级重试(等更久、清 nginx stream、停 nginx 重启)全都无济于事,只会反复折腾、
		// 拖垮 agent。直接返回,让用户去修配置 —— 不进入升级重启风暴。
		if isXrayConfigError(err) {
			log.Printf("[%s] server %d: xray 配置错误,跳过升级重启(需改配置才能恢复): %v", logPrefix, serverID, err)
			return err
		}
	}

	// 第二轮:可能只是启动慢,polling 久一点
	if err := restartAndVerify(5 * time.Second); err == nil {
		log.Printf("[%s] Xray restarted on server %d after longer wait", logPrefix, serverID)
		return nil
	} else {
		log.Printf("[%s] Xray restart attempt 2 failed on server %d: %v, trying stream cleanup", logPrefix, serverID, err)
	}

	// 第三轮：清理 nginx stream 端口冲突后重试
	clearPayload, _ := json.Marshal(map[string]int{"port": 443})
	clearResult, clearErr := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/nginx/clear-stream-port", clearPayload)
	if clearErr == nil {
		var clearResp struct {
			Removed int `json:"removed"`
		}
		json.Unmarshal(clearResult, &clearResp)
		if clearResp.Removed > 0 {
			log.Printf("[%s] Removed %d stream config(s) on server %d, retrying", logPrefix, clearResp.Removed, serverID)
			if err := restartAndVerify(3 * time.Second); err == nil {
				log.Printf("[%s] Xray restarted after stream cleanup on server %d", logPrefix, serverID)
				return nil
			}
		}
	} else {
		log.Printf("[%s] Stream cleanup failed on server %d: %v", logPrefix, serverID, clearErr)
	}

	// 第四轮兜底：先停 nginx 释放端口 → 重启 xray → 再启 nginx
	log.Printf("[%s] All normal attempts failed on server %d, trying nginx stop → xray restart → nginx start", logPrefix, serverID)
	h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/services/control", []byte(`{"service":"nginx","action":"stop"}`))
	time.Sleep(1 * time.Second)

	if err := restartAndVerify(3 * time.Second); err != nil {
		// xray 还是起不来，把 nginx 恢复
		h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/services/control", []byte(`{"service":"nginx","action":"start"}`))
		log.Printf("[%s] Xray restart failed even after stopping nginx on server %d: %v", logPrefix, serverID, err)
		return fmt.Errorf("xray restart failed after all recovery attempts: %v", err)
	}

	// xray 起来了，恢复 nginx
	h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/services/control", []byte(`{"service":"nginx","action":"start"}`))
	log.Printf("[%s] Xray restarted via nginx stop/start fallback on server %d", logPrefix, serverID)
	return nil
}

func (h *RemoteManageHandler) HandleValidateSite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServerID  int64  `json:"server_id"`
		SiteType  string `json:"site_type"`
		SiteValue string `json:"site_value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServerID == 0 || req.SiteValue == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id and site_value are required")
		return
	}

	if err := validateSiteValue(req.SiteType, req.SiteValue); err != nil {
		remoteWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload, _ := json.Marshal(map[string]string{
		"site_type":  req.SiteType,
		"site_value": req.SiteValue,
	})
	resp, err := h.forwardToRemoteServer(r.Context(), req.ServerID, http.MethodPost, "/api/child/validate-site", payload)
	if err != nil {
		remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("验证失败: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (h *RemoteManageHandler) HandleAddWebsite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServerID  int64  `json:"server_id"`
		Domain    string `json:"domain"`
		SiteType  string `json:"site_type"`
		SiteValue string `json:"site_value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServerID == 0 || req.Domain == "" {
		remoteWriteError(w, http.StatusBadRequest, "server_id and domain are required")
		return
	}

	if err := validateSiteValue(req.SiteType, req.SiteValue); err != nil {
		remoteWriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		remoteWriteError(w, http.StatusBadRequest, "domain is required")
		return
	}

	ctx, release, err := h.repo.AcquireRemoteServerMutationLease(r.Context(), req.ServerID)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}
	defer release()

	server, err := h.repo.GetRemoteServer(ctx, req.ServerID)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}

	rootDomain := extractRootDomain(domain)

	if h.certHandler == nil {
		remoteWriteError(w, http.StatusConflict, "证书功能未初始化，无法添加 HTTPS 网站")
		return
	}
	cert, certErr := h.findCertificateForRemoteDomain(ctx, domain, req.ServerID)
	if certErr != nil {
		remoteWriteError(w, http.StatusConflict, fmt.Sprintf("未找到可部署的 %s 证书: %v", rootDomain, certErr))
		return
	}
	certName := certDeployFilename(cert.Domain)
	// 1. 生成 nginx domain config(统一渲染:伪装站 location / + ws location)。
	// ws 入站走主域名 fallback,故仅当添加的正是 server 主域名时才聚合 ws location;额外网站域名不带 ws。
	var wssForDomain []wssInboundInfo
	if strings.EqualFold(domain, strings.ToLower(strings.TrimSpace(server.Domain))) {
		wssForDomain, err = h.fetchWSSInboundsStrict(ctx, req.ServerID)
		if err != nil {
			remoteWriteError(w, http.StatusBadGateway, fmt.Sprintf("读取 WSS 入站失败: %v", err))
			return
		}
	}
	domainConf, err := renderStealSelfDomainConf(server.StealMode, req.SiteType, req.SiteValue, domain, certName, wssForDomain)
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, fmt.Sprintf("渲染 domain.conf 失败: %v", err))
		return
	}

	// 2. 先同步部署证书并确认 Agent 完成落盘；随后 setup-ssl 负责重载 nginx。
	// 证书和 nginx 配置都是覆盖写入，因此该流程可幂等重试。
	certPayload := WSCertDeployPayload{
		Domain:   rootDomain,
		CertPEM:  cert.CertPEM,
		KeyPEM:   cert.KeyPEM,
		CertPath: fmt.Sprintf("/usr/local/nginx/cert/%s.pem", certName),
		KeyPath:  fmt.Sprintf("/usr/local/nginx/cert/%s.key", certName),
		Reload:   "none",
	}
	if err := h.certHandler.deployToRemoteServerSync(ctx, server, certPayload); err != nil {
		remoteWritePartialError(w, fmt.Sprintf("证书部署未获得 Agent ACK: %v", err))
		return
	}

	// 3. 部署 nginx domain config（不覆盖 nginx.conf）。覆盖写入使重试幂等。
	sslPayload, marshalErr := json.Marshal(map[string]any{
		"domain":        domain,
		"domain_config": domainConf,
	})
	if marshalErr != nil {
		remoteWritePartialError(w, fmt.Sprintf("序列化 nginx 配置失败: %v", marshalErr))
		return
	}
	if _, err := h.forwardToRemoteServer(ctx, req.ServerID, http.MethodPost, "/api/child/nginx/setup-ssl", sslPayload); err != nil {
		remoteWritePartialError(w, fmt.Sprintf("证书已部署，但 nginx 配置失败: %v", err))
		return
	}

	// 4. 读取当前 xray 配置
	xrayResp, err := h.forwardToRemoteServer(ctx, req.ServerID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		remoteWritePartialError(w, fmt.Sprintf("证书和 nginx 已部署，但读取 xray 配置失败: %v", err))
		return
	}
	var xrayConfigResp struct {
		Success *bool  `json:"success"`
		Config  string `json:"config"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(xrayResp, &xrayConfigResp); err != nil {
		remoteWritePartialError(w, fmt.Sprintf("解析 xray 配置响应失败: %v", err))
		return
	}
	if xrayConfigResp.Success != nil && !*xrayConfigResp.Success {
		message := strings.TrimSpace(xrayConfigResp.Error)
		if message == "" {
			message = strings.TrimSpace(xrayConfigResp.Message)
		}
		remoteWritePartialError(w, "Agent 拒绝读取 xray 配置: "+message)
		return
	}

	var xrayConfig map[string]any
	if err := json.Unmarshal([]byte(xrayConfigResp.Config), &xrayConfig); err != nil {
		remoteWritePartialError(w, fmt.Sprintf("解析 xray 配置失败: %v", err))
		return
	}

	// 5. 修改 xray 配置；添加域名的 helper 会去重，因此重试不会产生重复路由。
	if server.StealMode == "fallback" {
		h.addWebsiteFallbackConfig(xrayConfig, domain)
	} else {
		h.addWebsiteTunnelConfig(xrayConfig, domain)
	}

	updatedConfig, marshalErr := json.MarshalIndent(xrayConfig, "", "    ")
	if marshalErr != nil {
		remoteWritePartialError(w, fmt.Sprintf("序列化 xray 配置失败: %v", marshalErr))
		return
	}
	configPayload, marshalErr := json.Marshal(map[string]string{
		"config": string(updatedConfig),
	})
	if marshalErr != nil {
		remoteWritePartialError(w, fmt.Sprintf("序列化 xray 请求失败: %v", marshalErr))
		return
	}
	if _, err := h.forwardToRemoteServer(ctx, req.ServerID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		remoteWritePartialError(w, fmt.Sprintf("nginx 已部署，但写入 xray 配置失败: %v", err))
		return
	}

	// 6. 重启 xray，必须同步确认恢复流程最终成功。
	if err := h.restartXrayWithRecovery(ctx, req.ServerID, "AddWebsite"); err != nil {
		remoteWritePartialError(w, fmt.Sprintf("配置已写入，但 xray 重启/健康检查失败: %v", err))
		return
	}

	remoteWriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": fmt.Sprintf("网站 %s 添加成功", domain),
	})
}

func (h *RemoteManageHandler) addWebsiteTunnelConfig(config map[string]any, domain string) {
	routing, _ := config["routing"].(map[string]any)
	if routing == nil {
		return
	}
	rules, _ := routing["rules"].([]any)

	for _, rule := range rules {
		r, _ := rule.(map[string]any)
		if r == nil {
			continue
		}
		outTag, _ := r["outboundTag"].(string)
		if outTag != "nginx" {
			continue
		}
		inTags, _ := r["inboundTag"].([]any)
		hasTunnelIn := false
		for _, t := range inTags {
			if s, _ := t.(string); s == "tunnel-in" {
				hasTunnelIn = true
				break
			}
		}
		if !hasTunnelIn {
			continue
		}
		domains, _ := r["domain"].([]any)
		for _, d := range domains {
			if s, _ := d.(string); s == domain {
				return
			}
		}
		r["domain"] = append(domains, domain)
		return
	}

	newRule := map[string]any{
		"inboundTag":  []any{"tunnel-in"},
		"domain":      []any{domain},
		"outboundTag": "nginx",
	}
	rules = append([]any{newRule}, rules...)
	routing["rules"] = rules
}

func (h *RemoteManageHandler) removeDomainsFromTunnelNginxRoute(config map[string]any, domainsToRemove []string) bool {
	routing, _ := config["routing"].(map[string]any)
	if routing == nil {
		return false
	}
	rules, _ := routing["rules"].([]any)

	removeSet := make(map[string]struct{})
	for _, d := range domainsToRemove {
		removeSet[strings.ToLower(d)] = struct{}{}
	}

	for i, rule := range rules {
		r, _ := rule.(map[string]any)
		if r == nil {
			continue
		}
		outTag, _ := r["outboundTag"].(string)
		if outTag != "nginx" {
			continue
		}
		inTags, _ := r["inboundTag"].([]any)
		hasTunnelIn := false
		for _, t := range inTags {
			if s, _ := t.(string); s == "tunnel-in" {
				hasTunnelIn = true
				break
			}
		}
		if !hasTunnelIn {
			continue
		}

		domains, _ := r["domain"].([]any)
		var remaining []any
		for _, d := range domains {
			if s, _ := d.(string); s != "" {
				if _, found := removeSet[strings.ToLower(s)]; !found {
					remaining = append(remaining, d)
				}
			}
		}

		if len(remaining) == 0 {
			routing["rules"] = append(rules[:i], rules[i+1:]...)
		} else {
			r["domain"] = remaining
		}
		return true
	}
	return false
}

func (h *RemoteManageHandler) cleanupTunnelRouteForReality(ctx context.Context, serverID int64, inbound map[string]interface{}) error {
	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})
	if streamSettings == nil {
		return nil
	}
	security, _ := streamSettings["security"].(string)
	if security != "reality" {
		return nil
	}
	realitySettings, _ := streamSettings["realitySettings"].(map[string]interface{})
	if realitySettings == nil {
		return nil
	}
	serverNames, _ := realitySettings["serverNames"].([]interface{})
	if len(serverNames) == 0 {
		return nil
	}

	var domains []string
	for _, sn := range serverNames {
		if s, _ := sn.(string); s != "" {
			domains = append(domains, s)
		}
	}
	if len(domains) == 0 {
		return nil
	}

	inboundPort := 0
	if p, ok := inbound["port"].(float64); ok {
		inboundPort = int(p)
	}
	inboundTag, _ := inbound["tag"].(string)

	xrayResp, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return fmt.Errorf("读取 xray 配置: %w", err)
	}
	var configResp struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(xrayResp, &configResp); err != nil {
		return fmt.Errorf("解析 xray 响应: %w", err)
	}
	var xrayConfig map[string]any
	if err := json.Unmarshal([]byte(configResp.Config), &xrayConfig); err != nil {
		return fmt.Errorf("解析 xray 配置: %w", err)
	}

	configChanged := false

	// 如果是第一个 reality 入站，更新 tunnel-in 的 settings.port
	if inboundPort > 0 && h.isFirstRealityInbound(xrayConfig, inboundTag) {
		if h.updateTunnelInPortInConfig(xrayConfig, inboundPort) {
			configChanged = true
			log.Printf("[HandleInbounds] Updated tunnel-in settings.port to %d for first reality inbound on server %d", inboundPort, serverID)
		}
	}

	// 从 tunnel-in→nginx 路由中移除 reality serverNames
	if h.removeDomainsFromTunnelNginxRoute(xrayConfig, domains) {
		configChanged = true
	}

	if !configChanged {
		return nil
	}

	updatedConfig, err := json.MarshalIndent(xrayConfig, "", "    ")
	if err != nil {
		return fmt.Errorf("序列化 xray 配置: %w", err)
	}
	configPayload, err := json.Marshal(map[string]string{"config": string(updatedConfig)})
	if err != nil {
		return fmt.Errorf("序列化 xray 请求: %w", err)
	}
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		return fmt.Errorf("写入 Reality 路由配置: %w", err)
	}
	if err := h.restartXrayWithRecovery(ctx, serverID, "RealityRouteUpdate"); err != nil {
		return err
	}
	log.Printf("[HandleInbounds] Reality cleanup done on server %d: domains=%v", serverID, domains)
	return nil
}

// isFirstRealityInbound 检查当前配置中是否已有其他 reality 入站（排除 currentTag）
func (h *RemoteManageHandler) isFirstRealityInbound(xrayConfig map[string]any, currentTag string) bool {
	inbounds, _ := xrayConfig["inbounds"].([]any)
	for _, ib := range inbounds {
		ibMap, _ := ib.(map[string]any)
		if ibMap == nil {
			continue
		}
		tag, _ := ibMap["tag"].(string)
		if tag == currentTag || tag == "" {
			continue
		}
		ss, _ := ibMap["streamSettings"].(map[string]any)
		if ss == nil {
			continue
		}
		if sec, _ := ss["security"].(string); sec == "reality" {
			return false
		}
	}
	return true
}

// updateTunnelInPortInConfig 修改 xray 配置中 tunnel-in 的 settings.port
func (h *RemoteManageHandler) updateTunnelInPortInConfig(xrayConfig map[string]any, port int) bool {
	inbounds, _ := xrayConfig["inbounds"].([]any)
	for _, ib := range inbounds {
		ibMap, _ := ib.(map[string]any)
		if ibMap == nil {
			continue
		}
		tag, _ := ibMap["tag"].(string)
		if tag != "tunnel-in" {
			continue
		}
		settings, _ := ibMap["settings"].(map[string]any)
		if settings == nil {
			settings = map[string]any{}
			ibMap["settings"] = settings
		}
		settings["port"] = port
		return true
	}
	return false
}

// getInboundRemovalSyncState 在删除前一次读取目标 inbound，同时保存 Reality 路由恢复
// 所需的 serverNames 以及 WSS nginx 清理标志。该读取失败时必须在主删除前终止，
// 否则删除成功后已无法可靠重建后置状态。
func (h *RemoteManageHandler) getInboundRemovalSyncState(ctx context.Context, serverID int64, tag string) ([]string, bool, error) {
	resp, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return nil, false, err
	}
	var inboundsResp struct {
		Success  *bool                    `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
		Error    string                   `json:"error"`
		Message  string                   `json:"message"`
	}
	if err := json.Unmarshal(resp, &inboundsResp); err != nil {
		return nil, false, err
	}
	if inboundsResp.Success != nil && !*inboundsResp.Success {
		message := strings.TrimSpace(inboundsResp.Error)
		if message == "" {
			message = strings.TrimSpace(inboundsResp.Message)
		}
		if message == "" {
			message = "Agent rejected inbounds query"
		}
		return nil, false, errors.New(message)
	}
	for _, inb := range inboundsResp.Inbounds {
		inbTag, _ := inb["tag"].(string)
		if inbTag != tag {
			continue
		}
		wasWSS := isNginxManagedWSSInbound(inb)
		ss, _ := inb["streamSettings"].(map[string]interface{})
		if ss == nil {
			return nil, wasWSS, nil
		}
		if sec, _ := ss["security"].(string); sec != "reality" {
			return nil, wasWSS, nil
		}
		rs, _ := ss["realitySettings"].(map[string]interface{})
		if rs == nil {
			return nil, wasWSS, nil
		}
		sns, _ := rs["serverNames"].([]interface{})
		var domains []string
		for _, sn := range sns {
			if s, _ := sn.(string); s != "" {
				domains = append(domains, s)
			}
		}
		return domains, wasWSS, nil
	}
	return nil, false, nil
}

// restoreTunnelRouteForReality 删除 reality 入站后，将其 serverNames 恢复到 tunnel-in→nginx 路由。
func (h *RemoteManageHandler) restoreTunnelRouteForReality(ctx context.Context, serverID int64, domains []string) error {
	xrayResp, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return fmt.Errorf("读取 xray 配置: %w", err)
	}
	var configResp struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(xrayResp, &configResp); err != nil {
		return fmt.Errorf("解析 xray 响应: %w", err)
	}
	var xrayConfig map[string]any
	if err := json.Unmarshal([]byte(configResp.Config), &xrayConfig); err != nil {
		return fmt.Errorf("解析 xray 配置: %w", err)
	}

	for _, domain := range domains {
		h.addWebsiteTunnelConfig(xrayConfig, domain)
	}

	updatedConfig, err := json.MarshalIndent(xrayConfig, "", "    ")
	if err != nil {
		return fmt.Errorf("序列化 xray 配置: %w", err)
	}
	configPayload, err := json.Marshal(map[string]string{"config": string(updatedConfig)})
	if err != nil {
		return fmt.Errorf("序列化 xray 请求: %w", err)
	}
	if _, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/xray/config", configPayload); err != nil {
		return fmt.Errorf("恢复域名 %v 到 tunnel 路由: %w", domains, err)
	}
	if err := h.restartXrayWithRecovery(ctx, serverID, "RealityRouteRestore"); err != nil {
		return err
	}
	log.Printf("[HandleInbounds] Restored reality serverNames %v to tunnel-in→nginx route on server %d", domains, serverID)
	return nil
}

func (h *RemoteManageHandler) addWebsiteFallbackConfig(config map[string]any, domain string) {
	inbounds, _ := config["inbounds"].([]any)
	for _, inb := range inbounds {
		ib, _ := inb.(map[string]any)
		if ib == nil {
			continue
		}
		settings, _ := ib["settings"].(map[string]any)
		if settings == nil {
			continue
		}
		realitySettings, _ := settings["realitySettings"].(map[string]any)
		if realitySettings == nil {
			continue
		}
		serverNames, _ := realitySettings["serverNames"].([]any)
		for _, sn := range serverNames {
			if s, _ := sn.(string); s == domain {
				return
			}
		}
		realitySettings["serverNames"] = append(serverNames, domain)
		return
	}
}

func (h *RemoteManageHandler) HandleUserSpeeds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil || serverID <= 0 {
		respondJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid server_id"})
		return
	}

	speeds := h.wsHandler.GetUserSpeeds(serverID)
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "user_speeds": speeds})
}

func toURLSafeBase64(s string) string {
	replacer := strings.NewReplacer("+", "-", "/", "_")
	return strings.TrimRight(replacer.Replace(s), "=")
}
