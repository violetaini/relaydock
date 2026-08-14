package handler

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/storage"

	"github.com/google/uuid"
)

// PackageListHandler 处理列出所有包模板
type PackageListHandler struct {
	repo *storage.TrafficRepository
}

func NewPackageListHandler(repo *storage.TrafficRepository) *PackageListHandler {
	return &PackageListHandler{repo: repo}
}

func (h *PackageListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	packages, err := h.repo.ListPackages(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"packages": packages,
	})
}

// PackageCreateHandler 处理创建新的包模板
type PackageCreateHandler struct {
	repo              *storage.TrafficRepository
	capabilityManager *capabilities.Manager
}

func NewPackageCreateHandler(repo *storage.TrafficRepository) *PackageCreateHandler {
	return &PackageCreateHandler{repo: repo}
}

func (h *PackageCreateHandler) SetCapabilityManager(manager *capabilities.Manager) {
	h.capabilityManager = manager
}

// hasNonZeroLimit 任何一项 > 0 都算"启用限速"。0 表示显式不限速,不算"启用"。
func hasNonZeroLimit(m map[int64]float64) bool {
	for _, v := range m {
		if v > 0 {
			return true
		}
	}
	return false
}

func hasNonZeroIntLimit(m map[int64]int) bool {
	for _, v := range m {
		if v > 0 {
			return true
		}
	}
	return false
}

type createPackageRequest struct {
	Name             string                           `json:"name"`
	Description      string                           `json:"description"`
	TrafficLimitGB   float64                          `json:"traffic_limit_gb"`
	CycleDays        int                              `json:"cycle_days"`
	IsReset          bool                             `json:"is_reset"`
	ResetDay         int                              `json:"reset_day"`
	Nodes            []int64                          `json:"nodes"`
	NodeMultipliers  map[int64]float64                `json:"node_multipliers"`   // node_id → 倍率
	NodeSpeedLimits  map[int64]float64                `json:"node_speed_limits"`  // 套餐 per-node 限速覆盖 (Mbps);0=显式不限速,缺省=继承 SpeedLimitMbps
	NodeDeviceLimits map[int64]int                    `json:"node_device_limits"` // 套餐 per-node 客户端数覆盖;0=显式不限,缺省=继承 DeviceLimit
	SpeedLimitMbps   float64                          `json:"speed_limit_mbps"`
	DeviceLimit      int                              `json:"device_limit"`
	AutoSpeedRules   []storage.AutoSpeedLimitRule     `json:"auto_speed_rules"`
	ServerGrants     []storage.PackageServerGrant     `json:"server_grants"`
	ForwardingGrants []storage.PackageForwardingGrant `json:"forwarding_grants"`
	TrafficMode      string                           `json:"traffic_mode"`
	TemplateFilename string                           `json:"template_filename"` // 空 = 走系统默认
}

// validatePackageTemplateFilename 非空时校验 rule_templates 下文件存在。空字符串直接通过(表示用系统默认)。
func validatePackageTemplateFilename(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	// 防目录穿越
	if strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("invalid template filename")
	}
	if _, err := os.Stat(filepath.Join("rule_templates", name)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("template file not found: %s", name)
		}
		return fmt.Errorf("stat template: %w", err)
	}
	return nil
}

func (h *PackageCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req createPackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.Name == "" {
		http.Error(w, "Package name is required", http.StatusBadRequest)
		return
	}

	if req.TrafficLimitGB < 0 {
		http.Error(w, "Traffic limit cannot be negative", http.StatusBadRequest)
		return
	}

	if (req.SpeedLimitMbps > 0 || len(req.AutoSpeedRules) > 0 || hasNonZeroLimit(req.NodeSpeedLimits) || hasNonZeroIntLimit(req.NodeDeviceLimits)) && h.capabilityManager != nil && !h.capabilityManager.HasFeature(capabilities.FeatureLimiter) {
		http.Error(w, "当前构建未启用限速器", http.StatusForbidden)
		return
	}

	if req.CycleDays <= 0 {
		http.Error(w, "Duration days must be greater than 0", http.StatusBadRequest)
		return
	}

	if req.IsReset && (req.ResetDay < 1 || req.ResetDay > 31) {
		http.Error(w, "Reset day must be between 1 and 31", http.StatusBadRequest)
		return
	}

	if err := validatePackageTemplateFilename(req.TemplateFilename); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 如果 nil 则初始化空节点数组
	nodes := req.Nodes
	if nodes == nil {
		nodes = []int64{}
	}

	trafficMode := req.TrafficMode
	if trafficMode == "" {
		trafficMode = "oneway"
	}

	pkg := storage.Package{
		Name:              req.Name,
		Description:       req.Description,
		TrafficLimitGB:    req.TrafficLimitGB,
		TrafficLimitBytes: int64(req.TrafficLimitGB * 1024 * 1024 * 1024),
		CycleDays:         req.CycleDays,
		IsReset:           req.IsReset,
		ResetDay:          req.ResetDay,
		Nodes:             nodes,
		NodeMultipliers:   req.NodeMultipliers,
		NodeSpeedLimits:   req.NodeSpeedLimits,
		NodeDeviceLimits:  req.NodeDeviceLimits,
		SpeedLimitMbps:    req.SpeedLimitMbps,
		DeviceLimit:       req.DeviceLimit,
		AutoSpeedRules:    req.AutoSpeedRules,
		ServerGrants:      req.ServerGrants,
		ForwardingGrants:  req.ForwardingGrants,
		TrafficMode:       trafficMode,
		TemplateFilename:  strings.TrimSpace(req.TemplateFilename),
	}

	id, err := h.repo.CreatePackage(r.Context(), pkg)
	if err != nil {
		if err == storage.ErrPackageExists {
			http.Error(w, "Package with this name already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "Package created successfully",
	})
}

// PackageUpdateHandler 处理更新现有包模板
type PackageUpdateHandler struct {
	repo                     *storage.TrafficRepository
	remoteManage             *RemoteManageHandler
	pusher                   *LimiterConfigPusher
	managed                  *ManagedNodesHandler
	forwarding               *ForwardingHandler
	capabilityManager        *capabilities.Manager
	afterUserSnapshotForTest func()
}

func (h *PackageUpdateHandler) SetCapabilityManager(manager *capabilities.Manager) {
	h.capabilityManager = manager
}

func NewPackageUpdateHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *PackageUpdateHandler {
	managed := NewManagedNodesHandler(repo, remoteManage, pusher)
	return &PackageUpdateHandler{
		repo: repo, remoteManage: remoteManage, pusher: pusher, managed: managed,
		forwarding: NewForwardingHandler(repo, NewForwardingGuardDeployer(managed)),
	}
}

type updatePackageRequest struct {
	ID               int64                            `json:"id"`
	Name             string                           `json:"name"`
	Description      string                           `json:"description"`
	TrafficLimitGB   float64                          `json:"traffic_limit_gb"`
	CycleDays        int                              `json:"cycle_days"`
	IsReset          *bool                            `json:"is_reset"`  // 指针:请求未携带时保留库中旧值,不按零值覆盖
	ResetDay         *int                             `json:"reset_day"` // 同上
	Nodes            []int64                          `json:"nodes"`
	NodeMultipliers  map[int64]float64                `json:"node_multipliers"`   // node_id → 倍率
	NodeSpeedLimits  map[int64]float64                `json:"node_speed_limits"`  // 套餐 per-node 限速覆盖 (Mbps);0=显式不限速,缺省=继承 SpeedLimitMbps
	NodeDeviceLimits map[int64]int                    `json:"node_device_limits"` // 套餐 per-node 客户端数覆盖;0=显式不限,缺省=继承 DeviceLimit
	SpeedLimitMbps   float64                          `json:"speed_limit_mbps"`
	DeviceLimit      int                              `json:"device_limit"`
	AutoSpeedRules   []storage.AutoSpeedLimitRule     `json:"auto_speed_rules"`
	ServerGrants     []storage.PackageServerGrant     `json:"server_grants"`
	ForwardingGrants []storage.PackageForwardingGrant `json:"forwarding_grants"`
	TrafficMode      string                           `json:"traffic_mode"`
	TemplateFilename string                           `json:"template_filename"` // 空 = 走系统默认
}

func (h *PackageUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req updatePackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.ID <= 0 {
		http.Error(w, "Invalid package ID", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Package name is required", http.StatusBadRequest)
		return
	}

	if req.TrafficLimitGB < 0 {
		http.Error(w, "Traffic limit cannot be negative", http.StatusBadRequest)
		return
	}

	if (req.SpeedLimitMbps > 0 || len(req.AutoSpeedRules) > 0 || hasNonZeroLimit(req.NodeSpeedLimits) || hasNonZeroIntLimit(req.NodeDeviceLimits)) && h.capabilityManager != nil && !h.capabilityManager.HasFeature(capabilities.FeatureLimiter) {
		http.Error(w, "当前构建未启用限速器", http.StatusForbidden)
		return
	}

	if req.CycleDays <= 0 {
		http.Error(w, "Duration days must be greater than 0", http.StatusBadRequest)
		return
	}

	if err := validatePackageTemplateFilename(req.TemplateFilename); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 如果 nil 则初始化空节点数组
	nodes := req.Nodes
	if nodes == nil {
		nodes = []int64{}
	}
	packageCtx, releasePackage, err := h.repo.AcquirePackageAuthorizationLease(r.Context(), req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer releasePackage()

	// 获取旧套餐的节点列表，用于后续计算差异
	var oldNodes []int64
	var oldPkg *storage.Package
	if p, err := h.repo.GetPackage(packageCtx, req.ID); err == nil {
		oldPkg = p
		oldNodes = p.Nodes
	}

	// 套餐表单没有按月重置的控件,请求里不带这两个字段。缺省时必须沿用旧值,
	// 否则每保存一次套餐就把 is_reset/reset_day 清成 false/0,已开启的按月重置被静默关闭。
	isReset, resetDay := false, 0
	if oldPkg != nil {
		isReset, resetDay = oldPkg.IsReset, oldPkg.ResetDay
	}
	if req.IsReset != nil {
		isReset = *req.IsReset
	}
	if req.ResetDay != nil {
		resetDay = *req.ResetDay
	}
	if isReset && (resetDay < 1 || resetDay > 31) {
		http.Error(w, "Reset day must be between 1 and 31", http.StatusBadRequest)
		return
	}

	trafficMode := req.TrafficMode
	if trafficMode == "" {
		trafficMode = "oneway"
	}

	pkg := storage.Package{
		ID:                req.ID,
		Name:              req.Name,
		Description:       req.Description,
		TrafficLimitGB:    req.TrafficLimitGB,
		TrafficLimitBytes: int64(req.TrafficLimitGB * 1024 * 1024 * 1024),
		CycleDays:         req.CycleDays,
		IsReset:           isReset,
		ResetDay:          resetDay,
		Nodes:             nodes,
		NodeMultipliers:   req.NodeMultipliers,
		NodeSpeedLimits:   req.NodeSpeedLimits,
		NodeDeviceLimits:  req.NodeDeviceLimits,
		SpeedLimitMbps:    req.SpeedLimitMbps,
		DeviceLimit:       req.DeviceLimit,
		AutoSpeedRules:    req.AutoSpeedRules,
		ServerGrants:      req.ServerGrants,
		ForwardingGrants:  req.ForwardingGrants,
		TrafficMode:       trafficMode,
		TemplateFilename:  strings.TrimSpace(req.TemplateFilename),
	}

	boundUsers, err := h.repo.ListUsersWithPackage(packageCtx)
	if err != nil {
		http.Error(w, fmt.Sprintf("list package users: %v", err), http.StatusInternalServerError)
		return
	}
	boundUsernames := make([]string, 0)
	for _, user := range boundUsers {
		if user.PackageID == req.ID {
			boundUsernames = append(boundUsernames, user.Username)
		}
	}
	if h.afterUserSnapshotForTest != nil {
		h.afterUserSnapshotForTest()
	}
	updateCtx := packageCtx
	releaseAuthorization := func() {}
	if len(boundUsernames) > 0 {
		updateCtx, releaseAuthorization, err = h.repo.AcquireUserAuthorizationLease(packageCtx, boundUsernames...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		defer releaseAuthorization()
	}

	bundleWarnings, err := h.repo.UpdatePackageBundle(updateCtx, pkg)
	if err != nil {
		if errors.Is(err, storage.ErrPackageNotFound) {
			http.Error(w, "Package not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, storage.ErrManagedAccessConflict) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if bundleWarnings == nil {
		bundleWarnings = make(map[string][]string)
	}
	if h.pusher != nil {
		go h.pusher.PushToAllServersForPackage(context.Background(), req.ID)
	}
	helper := &ServiceAuthorizationHandler{repo: h.repo, managed: h.managed, forwarding: h.forwarding}
	for _, user := range boundUsers {
		if user.PackageID != req.ID {
			continue
		}
		latest, latestErr := h.repo.GetUser(updateCtx, user.Username)
		if latestErr != nil {
			bundleWarnings[user.Username] = append(bundleWarnings[user.Username], latestErr.Error())
			continue
		}
		if latest.AuthorizationMode != storage.AuthorizationModePackage || latest.PackageID != req.ID {
			continue
		}
		if cleanupWarnings := helper.reconcileAuthorizationTombstones(
			updateCtx, user.Username, storage.GrantSourcePackage, "package-template",
		); len(cleanupWarnings) > 0 {
			bundleWarnings[user.Username] = append(bundleWarnings[user.Username], cleanupWarnings...)
		}
	}

	// 异步同步 xray 用户凭据：对比新旧节点差异，为绑定此套餐的用户添加/移除入站配置
	go h.syncInboundUsersAfterNodeChange(context.Background(), req.ID, oldNodes, nodes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Package updated successfully",
		"warnings": bundleWarnings,
	})
}

func (h *PackageUpdateHandler) syncInboundUsersAfterNodeChange(ctx context.Context, packageID int64, oldNodes, newNodes []int64) {
	oldSet := make(map[int64]bool, len(oldNodes))
	for _, id := range oldNodes {
		oldSet[id] = true
	}
	newSet := make(map[int64]bool, len(newNodes))
	for _, id := range newNodes {
		newSet[id] = true
	}

	var addedNodes, removedNodes []int64
	for _, id := range newNodes {
		if !oldSet[id] {
			addedNodes = append(addedNodes, id)
		}
	}
	for _, id := range oldNodes {
		if !newSet[id] {
			removedNodes = append(removedNodes, id)
		}
	}

	if len(addedNodes) == 0 && len(removedNodes) == 0 {
		return
	}
	leasedCtx, releasePackage, err := h.repo.AcquirePackageAuthorizationLease(ctx, packageID)
	if err != nil {
		log.Printf("[PackageUpdate] Failed to acquire package %d lease: %v", packageID, err)
		return
	}
	defer releasePackage()
	ctx = leasedCtx

	// An earlier update worker may run after a newer template commit. Only add
	// nodes that are still present in the current template; stale removals are
	// independently revalidated under the same package lease and each user lease.
	currentPackage, err := h.repo.GetPackage(ctx, packageID)
	if err != nil {
		log.Printf("[PackageUpdate] Failed to reload package %d before Agent sync: %v", packageID, err)
		return
	}
	currentNodes := make(map[int64]struct{}, len(currentPackage.Nodes))
	for _, nodeID := range currentPackage.Nodes {
		currentNodes[nodeID] = struct{}{}
	}
	stillAdded := addedNodes[:0]
	for _, nodeID := range addedNodes {
		if _, ok := currentNodes[nodeID]; ok {
			stillAdded = append(stillAdded, nodeID)
		}
	}
	addedNodes = stillAdded

	users, err := h.repo.ListUsersWithPackage(ctx)
	if err != nil {
		log.Printf("[PackageUpdate] Failed to list users with package: %v", err)
		return
	}

	var targetUsers []storage.User
	for _, u := range users {
		if u.PackageID == packageID {
			targetUsers = append(targetUsers, u)
		}
	}
	if len(targetUsers) == 0 {
		return
	}

	log.Printf("[PackageUpdate] Syncing inbound users for package %d: %d added nodes, %d removed nodes, %d users",
		packageID, len(addedNodes), len(removedNodes), len(targetUsers))

	// routed rules and inbound clients are both activated through Agent runtime APIs.
	var mu sync.Mutex
	// per-server 收集 routed batch items + inbound add-client items,阶段二 per-server 一次 batch-apply 提交。
	routedBatch := map[int64][]routedBatchItem{}
	inboundBatch := map[int64][]InboundClientAddItem{}
	type inboundFallbackItem struct {
		Username   string
		ServerID   int64
		InboundTag string
		NodeName   string
	}
	var inboundFallbacks []inboundFallbackItem
	// both(v4/v6)会为同一 inbound 建两个节点(同 server + 同 InboundTag)。按节点遍历会让同一
	// (user, server, inbound) 被收集两次 → agent 加两个同 email client → xray "User already exists" 启动失败。
	// 凭据是绑到 inbound(server+tag)而非节点的,按 (user, server, inboundTag) 去重:每个入站每个用户只加一次。
	// routed 节点走 collectRoutedBatchItem(按 node.ID)独立路径,不参与此去重。
	inboundSeen := map[string]bool{}
	// 用户间互不影响 + 节点间互不影响 → 全部并发跑。
	// agent 端 inboundsMu 自动同服务器顺序化,master 这边不需要 per-server 锁。
	var bindWg sync.WaitGroup
	for _, user := range targetUsers {
		for _, nodeID := range addedNodes {
			bindWg.Add(1)
			go func(user storage.User, nodeID int64) {
				defer bindWg.Done()
				node, err := h.repo.GetNodeByID(ctx, nodeID)
				if err != nil {
					log.Printf("[PackageUpdate] Failed to get node %d: %v", nodeID, err)
					return
				}
				if node.NodeType == "routed" {
					item, err := collectRoutedBatchItem(ctx, h.remoteManage, h.repo, user, node.ID)
					if err != nil {
						log.Printf("[PackageUpdate] collect routed item user=%s node=%d failed: %v", user.Username, node.ID, err)
						return
					}
					if item != nil {
						mu.Lock()
						routedBatch[item.ServerID] = append(routedBatch[item.ServerID], *item)
						mu.Unlock()
					}
					return
				}
				if node.InboundTag == "" || node.OriginalServer == "" ||
					!supportsPerUserInboundCredential(node.Protocol) {
					return
				}
				// 同一 (user, server, inbound) 只收集一次 —— both 的 v4/v6 双节点共享同一入站,避免重复加 client。
				seenKey := user.Username + "|" + node.OriginalServer + "|" + node.InboundTag
				mu.Lock()
				if inboundSeen[seenKey] {
					mu.Unlock()
					return
				}
				inboundSeen[seenKey] = true
				mu.Unlock()
				server, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
				if err != nil {
					log.Printf("[PackageUpdate] Failed to find server %s: %v", node.OriginalServer, err)
					return
				}
				// 阶段一:从 InboundCache 算 cred,收集成 batch item;cache miss / 续费 → fallback 逐项。
				item, collected, cerr := collectInboundClientAddItem(ctx, h.remoteManage.inboundCache, h.repo, user, server.ID, node.InboundTag)
				if cerr != nil {
					mu.Lock()
					inboundFallbacks = append(inboundFallbacks, inboundFallbackItem{Username: user.Username, ServerID: server.ID, InboundTag: node.InboundTag, NodeName: node.NodeName})
					mu.Unlock()
					return
				}
				if collected && item != nil {
					mu.Lock()
					inboundBatch[item.ServerID] = append(inboundBatch[item.ServerID], *item)
					mu.Unlock()
				}
			}(user, nodeID)
		}

		for _, nodeID := range removedNodes {
			bindWg.Add(1)
			go func(user storage.User, nodeID int64) {
				defer bindWg.Done()
				node, err := h.repo.GetNodeByID(ctx, nodeID)
				if err != nil {
					return
				}
				if node.NodeType == "routed" {
					_, err := removeStalePackageUserFromRoutedNode(ctx, h.remoteManage, h.repo, user.Username, node.ID)
					if err != nil {
						log.Printf("[PackageUpdate] remove user %s from routed node %d failed: %v", user.Username, node.ID, err)
					}
					return
				}
				if node.InboundTag == "" || node.OriginalServer == "" ||
					!supportsPerUserInboundCredential(node.Protocol) {
					return
				}
				server, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
				if err != nil {
					return
				}
				cfg, err := h.repo.GetUserInboundConfig(ctx, user.Username, server.ID, node.InboundTag)
				if err != nil {
					return
				}
				_, removeErr := removeStalePackageUserInboundConfig(ctx, h.remoteManage, h.repo, *cfg)
				if removeErr != nil && !isInboundNotFoundErr(removeErr) {
					log.Printf("[PackageUpdate] Failed to remove user %s from inbound %s on server %d: %v",
						user.Username, cfg.InboundTag, cfg.ServerID, removeErr)
					return
				}
			}(user, nodeID)
		}
	}
	bindWg.Wait()

	// 阶段二 — per-server 并行调 batch-apply。routed + inbound 各自一批,跨 server 并行。
	var routeWg sync.WaitGroup
	for serverID, items := range routedBatch {
		routeWg.Add(1)
		go func(sid int64, list []routedBatchItem) {
			defer routeWg.Done()
			_, _ = applyRoutedBatchOrFallback(ctx, h.remoteManage, h.repo, sid, list, "PackageUpdate")
		}(serverID, items)
	}
	for serverID, items := range inboundBatch {
		routeWg.Add(1)
		go func(sid int64, list []InboundClientAddItem) {
			defer routeWg.Done()
			_ = applyInboundBatchOrFallback(ctx, h.remoteManage, h.repo, sid, list, "PackageUpdate")
		}(serverID, items)
	}
	routeWg.Wait()

	// 阶段三 — cache miss 类 fallback:并发跑逐项 addUserToInbound(老路径)。
	if len(inboundFallbacks) > 0 {
		log.Printf("[PackageUpdate] %d inbound items fell back to per-item add (cache miss / no batch)", len(inboundFallbacks))
		var fbWg sync.WaitGroup
		for _, fb := range inboundFallbacks {
			fbWg.Add(1)
			go func(fb inboundFallbackItem) {
				defer fbWg.Done()
				user := storage.User{Username: fb.Username}
				if err := addUserToInbound(ctx, h.remoteManage, h.repo, user, fb.ServerID, fb.InboundTag); err != nil {
					log.Printf("[PackageUpdate] fallback addUserToInbound user=%s server=%d tag=%s: %v",
						fb.Username, fb.ServerID, fb.InboundTag, err)
				}
			}(fb)
		}
		fbWg.Wait()
	}

	// limiter push 后台异步,不阻塞响应
	if h.pusher != nil {
		for _, user := range targetUsers {
			go h.pusher.PushToAllServersForUser(context.Background(), user.Username)
		}
	}
}

// PackageDeleteHandler 处理删除包模板
type PackageDeleteHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
	pusher       *LimiterConfigPusher
}

func NewPackageDeleteHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *PackageDeleteHandler {
	return &PackageDeleteHandler{repo: repo, remoteManage: remoteManage, pusher: pusher}
}

// unbindUserPackage 解除单个用户的套餐绑定:从入站移除凭据、删本地入站配置、推送 limiter、
// 清空 package_id,并删除该用户残留的套餐订阅(历史 auto-gen)。远端失败时保留 package_id
// 供重试，并把部分失败明确返回给调用方。
func unbindUserPackage(ctx context.Context, repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher, username string) error {
	return unbindUserPackageWithOptions(ctx, repo, remoteManage, pusher, username, true)
}

func unbindUserPackageWithOptions(ctx context.Context, repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher, username string, deleteSubscription bool) error {
	return withStableUserPackageAuthorizationLease(ctx, repo, username, nil, func(leasedCtx context.Context, _ storage.User) error {
		return unbindUserPackageLocked(leasedCtx, repo, remoteManage, pusher, username, deleteSubscription)
	})
}

func withStableUserPackageAuthorizationLease(
	ctx context.Context,
	repo *storage.TrafficRepository,
	username string,
	additionalPackageIDs []int64,
	mutate func(context.Context, storage.User) error,
) error {
	if repo == nil || mutate == nil {
		return storage.ErrManagedInvalidArgument
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		observed, err := repo.GetUser(ctx, username)
		if err != nil {
			return err
		}
		packageSet := make(map[int64]struct{}, len(additionalPackageIDs)+1)
		for _, packageID := range additionalPackageIDs {
			if packageID > 0 {
				packageSet[packageID] = struct{}{}
			}
		}
		if observed.PackageID > 0 {
			packageSet[observed.PackageID] = struct{}{}
		}
		packageIDs := make([]int64, 0, len(packageSet))
		for packageID := range packageSet {
			packageIDs = append(packageIDs, packageID)
		}

		packageCtx := ctx
		releasePackage := func() {}
		if len(packageIDs) > 0 {
			packageCtx, releasePackage, err = repo.AcquirePackageAuthorizationLease(ctx, packageIDs...)
			if err != nil {
				return err
			}
		}
		leasedCtx, releaseUser, err := repo.AcquireUserAuthorizationLease(packageCtx, username)
		if err != nil {
			releasePackage()
			return err
		}
		latest, err := repo.GetUser(leasedCtx, username)
		if err != nil {
			releaseUser()
			releasePackage()
			return err
		}
		if latest.PackageID > 0 {
			if _, held := packageSet[latest.PackageID]; !held {
				releaseUser()
				releasePackage()
				continue
			}
		}
		err = mutate(leasedCtx, latest)
		releaseUser()
		releasePackage()
		return err
	}
}

func unbindUserPackageLocked(ctx context.Context, repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher, username string, deleteSubscription bool) error {
	var mu sync.Mutex
	var mutationErrs []error
	previous, err := repo.GetUser(ctx, username)
	if err != nil {
		return err
	}
	if previous.AuthorizationMode != storage.AuthorizationModePackage || previous.PackageID <= 0 {
		return storage.ErrAuthorizationModeConflict
	}
	packages := NewPackageAssignHandler(repo, remoteManage, pusher)
	helper := &ServiceAuthorizationHandler{
		repo: repo, packages: packages, managed: packages.managed, forwarding: packages.forwarding,
	}
	packageChildren, err := helper.captureAuthorizationChildState(ctx, username, storage.GrantSourcePackage)
	if err != nil {
		return fmt.Errorf("capture package child access: %w", err)
	}
	restoreOnFailure := func(cause error) error {
		if previous.PackageStartDate == nil || previous.PackageEndDate == nil {
			return cause
		}
		if !previous.PackageEndDate.After(time.Now()) {
			_, restoreErr := repo.AssignPackageBundleToUser(ctx, previous.Username, previous.PackageID,
				*previous.PackageStartDate, *previous.PackageEndDate, previous.IsReset, previous.ResetDay)
			return errors.Join(cause, restoreErr)
		}
		warnings, restoreErr := helper.restorePackageAuthorization(ctx, previous, packageChildren, "package-unbind-rollback")
		if len(warnings) > 0 {
			restoreErr = errors.Join(restoreErr, warningsError("package restore warnings", warnings))
		}
		return errors.Join(cause, restoreErr)
	}

	// inbound 移除 + routed 下线并发执行 — 每条目独立,失败只 log。
	var wg sync.WaitGroup

	configs, err := repo.GetUserInboundConfigs(ctx, username)
	if err != nil {
		return fmt.Errorf("获取用户 %s 入站配置失败: %w", username, err)
	}
	for _, cfg := range configs {
		wg.Add(1)
		go func(cfg storage.UserInboundConfig) {
			defer wg.Done()
			_, removeErr := removePackageUserInboundConfig(ctx, remoteManage, repo, cfg)
			if removeErr != nil && !isInboundNotFoundErr(removeErr) {
				log.Printf("[PackageUnbind] 从入站 %s(server %d)移除用户 %s 失败: %v", cfg.InboundTag, cfg.ServerID, username, removeErr)
				mu.Lock()
				mutationErrs = append(mutationErrs, fmt.Errorf("server %d inbound %s: %w", cfg.ServerID, cfg.InboundTag, removeErr))
				mu.Unlock()
				return
			}
		}(cfg)
	}

	packageRoutedNodes, packageErr := packageRoutedNodeIDsForUser(ctx, repo, username)
	if packageErr != nil {
		mutationErrs = append(mutationErrs, packageErr)
	}
	// 只下线当前套餐直接授权的 shared routed 节点。用户基于手工固定节点或
	// 服务器授权创建的私有转发不属于套餐生命周期，解绑不能误停它们。
	subaccs, subaccountErr := repo.ListUserSubaccounts(ctx, username)
	if subaccountErr != nil {
		mutationErrs = append(mutationErrs, fmt.Errorf("获取用户 %s 路由子账号失败: %w", username, subaccountErr))
	}
	for _, sa := range subaccs {
		if !sa.IsActive || !packageRoutedNodes[sa.RoutedNodeID] {
			continue
		}
		wg.Add(1)
		go func(routedNodeID int64) {
			defer wg.Done()
			_, err := removeUserFromRoutedNode(ctx, remoteManage, repo, username, routedNodeID)
			if err != nil {
				log.Printf("[PackageUnbind] routed node %d 下线用户 %s 失败: %v", routedNodeID, username, err)
				mu.Lock()
				mutationErrs = append(mutationErrs, fmt.Errorf("routed node %d: %w", routedNodeID, err))
				mu.Unlock()
			}
		}(sa.RoutedNodeID)
	}
	wg.Wait()

	if joined := errors.Join(mutationErrs...); joined != nil {
		return restoreOnFailure(joined)
	}
	if pusher != nil {
		go pusher.PushToAllServersForUser(context.Background(), username)
	}
	if err := repo.RemovePackageFromUser(ctx, username); err != nil && err != storage.ErrUserNotFound {
		return restoreOnFailure(fmt.Errorf("remove package assignment for %s: %w", username, err))
	}
	if cleanupWarnings := helper.reconcileAuthorizationTombstones(ctx, username, storage.GrantSourcePackage, "package-unbind"); len(cleanupWarnings) > 0 {
		return restoreOnFailure(fmt.Errorf("package child cleanup is incomplete: %s", strings.Join(cleanupWarnings, "; ")))
	}
	// 删除该用户残留的套餐订阅(历史 auto-gen 文件)
	if deleteSubscription {
		if sf, err := repo.GetUserPackageSubscription(ctx, username); err == nil && sf.ID > 0 {
			if derr := deleteSubscribeFileAndPhysical(ctx, repo, "subscribes", sf); derr != nil {
				log.Printf("[PackageUnbind] 删除用户 %s 套餐订阅记录失败: %v", username, derr)
			}
		}
	}
	return nil
}

func packageRoutedNodeIDsForUser(ctx context.Context, repo *storage.TrafficRepository, username string) (map[int64]bool, error) {
	result := make(map[int64]bool)
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return result, fmt.Errorf("获取用户 %s 套餐失败: %w", username, err)
	}
	if user.PackageID <= 0 {
		return result, nil
	}
	pkg, err := repo.GetPackage(ctx, user.PackageID)
	if err != nil {
		return result, fmt.Errorf("获取用户 %s 套餐模板失败: %w", username, err)
	}
	for _, nodeID := range pkg.Nodes {
		node, nodeErr := repo.GetNodeByID(ctx, nodeID)
		if nodeErr != nil {
			if errors.Is(nodeErr, storage.ErrNodeNotFound) {
				continue
			}
			return result, nodeErr
		}
		if strings.EqualFold(strings.TrimSpace(node.NodeType), "routed") &&
			!strings.EqualFold(strings.TrimSpace(node.RoutedOwner), "user") {
			result[node.ID] = true
		}
	}
	return result, nil
}

// removeStalePackageUserFromRoutedNode revalidates the current package while
// holding the account authorization lease. A delayed template reconciler can
// therefore never remove a routed subaccount newly authorized by a package
// switch that completed after the reconciler took its initial snapshot.
func removeStalePackageUserFromRoutedNode(ctx context.Context, remoteManage *RemoteManageHandler, repo *storage.TrafficRepository, username string, routedNodeID int64) (bool, error) {
	changed := false
	err := repo.WithUserAuthorizationLease(ctx, username, func(leasedCtx context.Context) error {
		packageNodes, err := packageRoutedNodeIDsForUser(leasedCtx, repo, username)
		if err != nil {
			return err
		}
		if packageNodes[routedNodeID] {
			return nil
		}
		changed, err = removeUserFromRoutedNode(leasedCtx, remoteManage, repo, username, routedNodeID)
		return err
	})
	return changed, err
}

func (h *PackageDeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从 URL 路径或请求正文中提取 ID
	var id int64
	var err error

	if r.Method == http.MethodDelete {
		// 从 URL 路径提取：/api/admin/packages/123
		pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/admin/packages/"), "/")
		if len(pathParts) > 0 && pathParts[0] != "" {
			id, err = strconv.ParseInt(pathParts[0], 10, 64)
			if err != nil {
				http.Error(w, "Invalid package ID", http.StatusBadRequest)
				return
			}
		}
	} else {
		// 从 JSON 正文中提取
		var req struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		id = req.ID
	}

	if id <= 0 {
		http.Error(w, "Invalid package ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	packageCtx, releasePackage, err := h.repo.AcquirePackageAuthorizationLease(ctx, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer releasePackage()

	// Package deletion is a coordinated authorization transition. Hold every
	// currently bound account lease until either the template is deleted or all
	// successful unbinds have been compensated.
	users, err := h.repo.ListUsersWithPackage(packageCtx)
	if err != nil {
		http.Error(w, fmt.Sprintf("list package users: %v", err), http.StatusInternalServerError)
		return
	}
	usernames := make([]string, 0)
	for _, user := range users {
		if user.PackageID == id {
			usernames = append(usernames, user.Username)
		}
	}
	leasedCtx := packageCtx
	releaseAuthorization := func() {}
	if len(usernames) > 0 {
		leasedCtx, releaseAuthorization, err = h.repo.AcquireUserAuthorizationLease(packageCtx, usernames...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		defer releaseAuthorization()
	}

	type packageDeleteRollback struct {
		user     storage.User
		children authorizationChildState
	}
	assigner := NewPackageAssignHandler(h.repo, h.remoteManage, h.pusher)
	helper := &ServiceAuthorizationHandler{
		repo: h.repo, packages: assigner, managed: assigner.managed, forwarding: assigner.forwarding,
	}
	snapshots := make([]packageDeleteRollback, 0, len(usernames))
	for _, username := range usernames {
		latest, loadErr := h.repo.GetUser(leasedCtx, username)
		if loadErr != nil {
			http.Error(w, loadErr.Error(), http.StatusInternalServerError)
			return
		}
		if latest.AuthorizationMode != storage.AuthorizationModePackage || latest.PackageID != id {
			continue
		}
		if latest.PackageStartDate == nil || latest.PackageEndDate == nil {
			http.Error(w, fmt.Sprintf("user %s has an incomplete package validity window", username), http.StatusConflict)
			return
		}
		children, captureErr := helper.captureAuthorizationChildState(leasedCtx, username, storage.GrantSourcePackage)
		if captureErr != nil {
			http.Error(w, captureErr.Error(), http.StatusInternalServerError)
			return
		}
		snapshots = append(snapshots, packageDeleteRollback{user: latest, children: children})
	}

	rollback := func(applied []packageDeleteRollback) error {
		var rollbackErrs []error
		for i := len(applied) - 1; i >= 0; i-- {
			warnings, restoreErr := helper.restorePackageAuthorization(
				leasedCtx, applied[i].user, applied[i].children, "package-delete-rollback",
			)
			if len(warnings) > 0 {
				restoreErr = errors.Join(restoreErr, warningsError("package restore warnings", warnings))
			}
			if restoreErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restore user %s: %w", applied[i].user.Username, restoreErr))
			}
		}
		return errors.Join(rollbackErrs...)
	}

	applied := make([]packageDeleteRollback, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if unbindErr := unbindUserPackageLocked(leasedCtx, h.repo, h.remoteManage, h.pusher, snapshot.user.Username, false); unbindErr != nil {
			rollbackErr := rollback(applied)
			status := http.StatusBadGateway
			if errors.Is(unbindErr, storage.ErrRemoteInstallationActive) {
				status = http.StatusConflict
			}
			http.Error(w, fmt.Sprintf("Package deletion failed while unbinding %s; package was retained: %v",
				snapshot.user.Username, errors.Join(unbindErr, rollbackErr)), status)
			return
		}
		applied = append(applied, snapshot)
	}

	if err := h.repo.DeletePackage(leasedCtx, id); err != nil {
		rollbackErr := rollback(applied)
		if err == storage.ErrPackageNotFound {
			http.Error(w, "Package not found", http.StatusNotFound)
			return
		}
		http.Error(w, errors.Join(err, rollbackErr).Error(), http.StatusInternalServerError)
		return
	}
	for _, snapshot := range snapshots {
		if file, fileErr := h.repo.GetUserPackageSubscription(leasedCtx, snapshot.user.Username); fileErr == nil && file.ID > 0 {
			if deleteErr := deleteSubscribeFileAndPhysical(leasedCtx, h.repo, "subscribes", file); deleteErr != nil {
				log.Printf("[PackageDelete] 删除用户 %s 套餐订阅记录失败: %v", snapshot.user.Username, deleteErr)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "Package deleted successfully",
		"unbound_users": len(applied),
	})
}

// PackageUnassignHandler 处理从用户删除包分配
type PackageUnassignHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
	pusher       *LimiterConfigPusher
}

func NewPackageUnassignHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *PackageUnassignHandler {
	return &PackageUnassignHandler{repo: repo, remoteManage: remoteManage, pusher: pusher}
}

func (h *PackageUnassignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := unbindUserPackage(ctx, h.repo, h.remoteManage, h.pusher, req.Username); err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, storage.ErrRemoteInstallationActive) || errors.Is(err, storage.ErrAuthorizationModeConflict) {
			status = http.StatusConflict
		}
		if errors.Is(err, storage.ErrUserNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Package removal failed and was rolled back when possible: %v", err), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Package removed successfully",
	})
}

// PackageAssignHandler 处理将包分配给用户的操作
type PackageAssignHandler struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
	pusher       *LimiterConfigPusher
	managed      *ManagedNodesHandler
	forwarding   *ForwardingHandler
	reconcileMu  sync.Mutex
	reconcileWG  sync.WaitGroup
}

func NewPackageAssignHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *PackageAssignHandler {
	managed := NewManagedNodesHandler(repo, remoteManage, pusher)
	return &PackageAssignHandler{
		repo: repo, remoteManage: remoteManage, pusher: pusher, managed: managed,
		forwarding: NewForwardingHandler(repo, NewForwardingGuardDeployer(managed)),
	}
}

// StartReconciler continuously derives package credentials from the current
// assignment state. This closes the failure window left by an Agent being
// offline during assignment/template update and also repairs it after restart.
func (h *PackageAssignHandler) StartReconciler(ctx context.Context) {
	if h == nil || h.repo == nil {
		return
	}
	h.reconcileWG.Add(1)
	go func() {
		defer h.reconcileWG.Done()
		startup := time.NewTimer(20 * time.Second)
		defer startup.Stop()
		select {
		case <-ctx.Done():
			return
		case <-startup.C:
		}
		h.reconcileAssignments(ctx)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.reconcileAssignments(ctx)
			}
		}
	}()
}

func (h *PackageAssignHandler) WaitForReconciler() {
	if h != nil {
		h.reconcileWG.Wait()
	}
}

func (h *PackageAssignHandler) reconcileAssignments(ctx context.Context) {
	if !h.reconcileMu.TryLock() {
		return
	}
	defer h.reconcileMu.Unlock()
	users, err := h.repo.ListUsersWithPackage(ctx)
	if err != nil {
		log.Printf("[PackageReconcile] list users failed: %v", err)
		return
	}
	now := time.Now()
	for _, user := range users {
		if ctx.Err() != nil {
			return
		}
		if !user.IsActive || user.PackageID <= 0 || user.PackageStartDate == nil || user.PackageEndDate == nil ||
			now.Before(*user.PackageStartDate) || !now.Before(*user.PackageEndDate) {
			continue
		}
		var warnings []string
		var reconcileErr error
		var cleanupErr error
		leaseErr := withStableUserPackageAuthorizationLease(ctx, h.repo, user.Username, []int64{user.PackageID}, func(leasedCtx context.Context, latest storage.User) error {
			if latest.AuthorizationMode != storage.AuthorizationModePackage || latest.PackageID != user.PackageID ||
				latest.PackageStartDate == nil || latest.PackageEndDate == nil {
				return nil
			}
			warnings, reconcileErr = h.assignAndProvisionLocked(leasedCtx, user.Username, latest.PackageID,
				*latest.PackageStartDate, *latest.PackageEndDate, latest.IsReset, latest.ResetDay)
			if reconcileErr == nil {
				cleanupErr = h.reconcileStalePackageNodeAccess(leasedCtx, user.Username)
			}
			return nil
		})
		if leaseErr != nil {
			reconcileErr = leaseErr
		}
		if reconcileErr != nil || cleanupErr != nil || len(warnings) > 0 {
			log.Printf("[PackageReconcile] user=%s package=%d warnings=%v provision_err=%v cleanup_err=%v",
				user.Username, user.PackageID, warnings, reconcileErr, cleanupErr)
		}
	}
}

// reconcileStalePackageNodeAccess makes template removal durable. The update
// request performs the same cleanup eagerly, while this pass repairs a crash or
// transient Agent failure between the package commit and that remote cleanup.
func (h *PackageAssignHandler) reconcileStalePackageNodeAccess(ctx context.Context, username string) error {
	var cleanupErr error
	err := h.repo.WithUserAuthorizationLease(ctx, username, func(leasedCtx context.Context) error {
		cleanupErr = h.reconcileStalePackageNodeAccessLocked(leasedCtx, username)
		return nil
	})
	return errors.Join(err, cleanupErr)
}

func (h *PackageAssignHandler) reconcileStalePackageNodeAccessLocked(ctx context.Context, username string) error {
	configs, err := h.repo.GetUserInboundConfigs(ctx, username)
	if err != nil {
		return fmt.Errorf("list package inbound credentials: %w", err)
	}
	var cleanupErrs []error
	for _, cfg := range configs {
		if _, removeErr := removeStalePackageUserInboundConfig(ctx, h.remoteManage, h.repo, cfg); removeErr != nil && !isInboundNotFoundErr(removeErr) {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("remove stale inbound %d/%s: %w",
				cfg.ServerID, cfg.InboundTag, removeErr))
		}
	}

	packageRoutedNodes, err := packageRoutedNodeIDsForUser(ctx, h.repo, username)
	if err != nil {
		cleanupErrs = append(cleanupErrs, err)
		return errors.Join(cleanupErrs...)
	}
	subaccounts, err := h.repo.ListUserSubaccounts(ctx, username)
	if err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("list routed subaccounts: %w", err))
		return errors.Join(cleanupErrs...)
	}
	for _, subaccount := range subaccounts {
		if !subaccount.IsActive || packageRoutedNodes[subaccount.RoutedNodeID] {
			continue
		}
		node, nodeErr := h.repo.GetNodeByID(ctx, subaccount.RoutedNodeID)
		if nodeErr != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("load routed node %d: %w", subaccount.RoutedNodeID, nodeErr))
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(node.NodeType), "routed") ||
			strings.EqualFold(strings.TrimSpace(node.RoutedOwner), "user") {
			continue
		}
		if _, removeErr := removeStalePackageUserFromRoutedNode(ctx, h.remoteManage, h.repo, username, node.ID); removeErr != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("remove stale routed node %d: %w", node.ID, removeErr))
		}
	}
	return errors.Join(cleanupErrs...)
}

// hasPackageTemplateInboundAccess answers only the durable template question.
// It intentionally does not apply traffic-limit or Agent-observed state: an
// over-limit user still owns the package credential and the normal enforcer
// must be able to retry it later.
func hasPackageTemplateInboundAccess(ctx context.Context, repo *storage.TrafficRepository, username string, serverID int64, inboundTag string, now time.Time) (bool, error) {
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return false, err
	}
	if !packageAssignmentActive(user, now) {
		return false, nil
	}
	pkg, err := repo.GetPackage(ctx, user.PackageID)
	if err != nil {
		return false, err
	}
	server, err := repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return false, err
	}
	for _, nodeID := range pkg.Nodes {
		node, nodeErr := repo.GetNodeByID(ctx, nodeID)
		if nodeErr != nil {
			if errors.Is(nodeErr, storage.ErrNodeNotFound) {
				continue
			}
			return false, nodeErr
		}
		if node.Enabled && !strings.EqualFold(strings.TrimSpace(node.NodeType), "routed") &&
			supportsPerUserInboundCredential(node.Protocol) &&
			node.OriginalServer == server.Name && node.InboundTag == inboundTag {
			return true, nil
		}
	}
	return false, nil
}

type assignPackageRequest struct {
	Username   string `json:"username"`
	PackageID  int64  `json:"package_id"`
	StartDate  string `json:"start_date"`
	ExpireDate string `json:"expire_date"`
	// IsReset/ResetDay 用指针:nil = 请求未提供 → 回退取套餐自身的 is_reset/reset_day(套餐才是真值源);
	// 非 nil = 调用方显式覆盖。历史 bug:前端恒发 is_reset=false 让套餐的按月重置永远不生效。
	IsReset  *bool `json:"is_reset"`
	ResetDay *int  `json:"reset_day"`
}

var errInvalidPackageWindow = errors.New("invalid package assignment window")

func (h *PackageAssignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req assignPackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	if req.PackageID <= 0 {
		http.Error(w, "Package ID is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	// 先取套餐:既用于 is_reset/reset_day 的回退真值源,也用于默认到期日(CycleDays)。
	pkg, pkgErr := h.repo.GetPackage(ctx, req.PackageID)

	// 解析重置设置:请求提供了就用请求值(管理员显式覆盖),否则回退套餐自身值。
	isReset := false
	resetDay := 0
	if pkg != nil {
		isReset = pkg.IsReset
		resetDay = pkg.ResetDay
	}
	if req.IsReset != nil {
		isReset = *req.IsReset
	}
	if req.ResetDay != nil {
		resetDay = *req.ResetDay
	}
	// 开启按月重置但没有有效重置日 → 取当天(封顶 28,避开月末不存在的日期),与 TG 续期路径一致。
	// 否则 reset_day=0 落库会让 shouldResetThisMonth 永远返回 false —— 开关形同虚设。
	if isReset && resetDay == 0 {
		resetDay = time.Now().Day()
		if resetDay > 28 {
			resetDay = 28
		}
	}
	if isReset && (resetDay < 1 || resetDay > 31) {
		http.Error(w, "Reset day must be between 1 and 31", http.StatusBadRequest)
		return
	}

	var startDate time.Time
	if req.StartDate != "" {
		parsed, err := time.ParseInLocation("2006-01-02", req.StartDate, time.Local)
		if err != nil {
			http.Error(w, "Invalid start_date format, expected YYYY-MM-DD", http.StatusBadRequest)
			return
		}
		startDate = parsed
	} else {
		startDate = time.Now()
	}
	if startDate.After(time.Now().Add(time.Minute)) {
		http.Error(w, "Future package start dates are not supported", http.StatusBadRequest)
		return
	}

	// 计算到期时间：优先使用前端传入的 expire_date，否则默认 start + CycleDays 天
	var endDate time.Time
	if req.ExpireDate != "" {
		parsed, err := time.ParseInLocation("2006-01-02", req.ExpireDate, time.Local)
		if err != nil {
			http.Error(w, "Invalid expire_date format, expected YYYY-MM-DD", http.StatusBadRequest)
			return
		}
		endDate = parsed
	} else if pkgErr == nil && pkg != nil && pkg.CycleDays > 0 {
		endDate = startDate.AddDate(0, 0, pkg.CycleDays)
	} else {
		endDate = startDate.AddDate(0, 1, 0)
	}
	if !endDate.After(startDate) || !endDate.After(time.Now()) {
		http.Error(w, "expire_date must be later than the package start time", http.StatusBadRequest)
		return
	}

	warnings, perr := h.AssignAndProvision(ctx, req.Username, req.PackageID, startDate, endDate, isReset, resetDay)
	if perr != nil {
		if errors.Is(perr, storage.ErrPackageNotFound) {
			http.Error(w, "Package not found", http.StatusNotFound)
			return
		}
		if errors.Is(perr, storage.ErrUserNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if errors.Is(perr, storage.ErrManagedAccessConflict) {
			http.Error(w, perr.Error(), http.StatusConflict)
			return
		}
		if errors.Is(perr, errInvalidPackageWindow) {
			http.Error(w, perr.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, perr.Error(), http.StatusInternalServerError)
		return
	}
	if len(warnings) > 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"message": "Package assigned with warnings", "warnings": warnings})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"message": "Package assigned successfully"})
}

// AssignAndProvision 绑定套餐并真正下发(给套餐节点 inbound 加用户凭据 + 批量推服务器 + 重启 xray + 推限速)。
// 抽自 ServeHTTP,供 web /api/admin/packages/assign 与 TGBOT 注册/兑换共用,确保两条路都生效。
func (h *PackageAssignHandler) AssignAndProvision(ctx context.Context, username string, packageID int64, startDate, endDate time.Time, isReset bool, resetDay int) ([]string, error) {
	var warnings []string
	err := withStableUserPackageAuthorizationLease(ctx, h.repo, username, []int64{packageID}, func(leasedCtx context.Context, _ storage.User) error {
		var assignErr error
		warnings, assignErr = h.assignAndProvisionLocked(leasedCtx, username, packageID, startDate, endDate, isReset, resetDay)
		return assignErr
	})
	return warnings, err
}

func (h *PackageAssignHandler) assignAndProvisionLocked(ctx context.Context, username string, packageID int64, startDate, endDate time.Time, isReset bool, resetDay int) ([]string, error) {
	var warnings []string
	var revokedPreviousAccess []packageNodeRevocation
	var previousPackageChildren authorizationChildState
	if startDate.After(time.Now().Add(time.Minute)) || !endDate.After(startDate) || !endDate.After(time.Now()) {
		return nil, errInvalidPackageWindow
	}
	currentUser, err := h.repo.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}
	targetPackage, err := h.repo.GetPackage(ctx, packageID)
	if err != nil {
		return nil, err
	}
	switchingPackages := currentUser.PackageID > 0 && currentUser.PackageID != packageID
	authorizationHelper := &ServiceAuthorizationHandler{
		repo: h.repo, managed: h.managed, forwarding: h.forwarding,
	}
	if switchingPackages {
		if currentUser.PackageStartDate == nil || currentUser.PackageEndDate == nil {
			return nil, errors.New("current package assignment has no restorable validity window")
		}
		previousPackageChildren, err = authorizationHelper.captureAuthorizationChildState(ctx, username, storage.GrantSourcePackage)
		if err != nil {
			return nil, fmt.Errorf("capture current package child access: %w", err)
		}
		currentPackage, currentErr := h.repo.GetPackage(ctx, currentUser.PackageID)
		if currentErr != nil {
			return nil, fmt.Errorf("load current package before switch: %w", currentErr)
		}
		revokedPreviousAccess, err = h.revokePackageNodeDifference(ctx, username, currentPackage, targetPackage)
		if err != nil {
			revokeErr := fmt.Errorf("revoke previous package access before switch: %w", err)
			if compensateErr := h.restorePackageNodeRevocations(ctx, currentUser, revokedPreviousAccess); compensateErr != nil {
				return nil, errors.Join(revokeErr, fmt.Errorf("restore previous package access: %w", compensateErr))
			}
			return nil, revokeErr
		}
	}

	bundleWarnings, err := h.repo.AssignPackageBundleToUser(ctx, username, packageID, startDate, endDate, isReset, resetDay)
	if err != nil {
		// Storage validation and transaction failures normally leave the old
		// assignment authoritative. Confirm that state before restoring the old
		// remote access: if commit status were ever uncertain, restoring without
		// this check could grant both packages at once.
		if len(revokedPreviousAccess) > 0 {
			persisted, readErr := h.repo.GetUser(ctx, username)
			if readErr == nil && persisted.PackageID == currentUser.PackageID {
				if compensateErr := h.restorePackageNodeRevocations(ctx, currentUser, revokedPreviousAccess); compensateErr != nil {
					return nil, errors.Join(err, fmt.Errorf("restore previous package access: %w", compensateErr))
				}
			} else if readErr != nil {
				return nil, errors.Join(err, fmt.Errorf("verify package state before compensation: %w", readErr))
			}
		}
		return nil, err
	}
	warnings = append(warnings, bundleWarnings...)

	if switchingPackages {
		cleanupWarnings := authorizationHelper.reconcileAuthorizationTombstones(
			ctx, username, storage.GrantSourcePackage, "package-switch",
		)
		if len(cleanupWarnings) > 0 {
			switchErr := fmt.Errorf("previous package cleanup is incomplete: %s", strings.Join(cleanupWarnings, "; "))
			_, restoreErr := h.repo.AssignPackageBundleToUser(ctx, username, currentUser.PackageID,
				*currentUser.PackageStartDate, *currentUser.PackageEndDate, currentUser.IsReset, currentUser.ResetDay)
			if restoreErr == nil {
				restoreErr = h.repo.UpdateUserTrafficLimitOverride(ctx, username, currentUser.TrafficLimitOverride)
			}
			if restoreErr == nil {
				newPackageCleanupWarnings := authorizationHelper.reconcileAuthorizationTombstones(
					ctx, username, storage.GrantSourcePackage, "package-switch-rollback",
				)
				restoreErr = errors.Join(
					warningsError("new package cleanup rollback warnings", newPackageCleanupWarnings),
					authorizationHelper.restoreAuthorizationChildState(ctx, username, previousPackageChildren, "package-switch-rollback"),
					h.restorePackageNodeRevocations(ctx, currentUser, revokedPreviousAccess),
				)
			}
			return nil, errors.Join(switchErr, restoreErr)
		}
	}

	// Always reconcile every package node, including same-package renewal. This
	// refreshes deadlines and repairs a partial previous assignment where a
	// credential or routed subaccount was never created. The lower-level Agent
	// mutations are idempotent and reuse the persisted credential identity.
	pkg, err := h.repo.GetPackage(ctx, packageID)
	if err != nil {
		log.Printf("[PackageAssign] Failed to get package: %v", err)
	} else {
		user, err := h.repo.GetUser(ctx, username)
		if err != nil {
			log.Printf("[PackageAssign] Failed to get user: %v", err)
		} else {
			var mu sync.Mutex
			// per-server 收集 routed 节点的 batch items + 普通 inbound 加 client items。
			// 新 agent 支持 /api/child/batch-apply → 同 server 所有 client + routing 改动一次 round-trip;
			// 老 agent 不支持 → applyRoutedBatchOrFallback / applyInboundBatchOrFallback 内部 fallback 逐项。
			routedBatch := map[int64][]routedBatchItem{}
			inboundBatch := map[int64][]InboundClientAddItem{}
			// 普通 inbound 节点 cache miss / 续费跳过时,fallback 直接走逐项 addUserToInbound。
			type inboundFallbackItem struct {
				ServerID   int64
				InboundTag string
				NodeName   string
			}
			var inboundFallbacks []inboundFallbackItem

			// both(v4/v6)会为同一 inbound 建两个节点(同 server + 同 InboundTag)。凭据绑到 inbound 而非节点,
			// 按 (server, inboundTag) 去重,避免同一用户同一入站被加两个同 email client → xray "User already exists"。
			// routed 节点走 node.ID 独立路径,不参与此去重。
			inboundSeen := map[string]bool{}
			// 节点绑定并发跑 — routed / inbound 都只在阶段一收集,阶段二 per-server batch 一次性提交。
			var bindWg sync.WaitGroup
			for _, nodeID := range pkg.Nodes {
				bindWg.Add(1)
				go func(nodeID int64) {
					defer bindWg.Done()
					node, err := h.repo.GetNodeByID(ctx, nodeID)
					if err != nil {
						log.Printf("[PackageAssign] Failed to get node %d: %v", nodeID, err)
						return
					}
					if node.NodeType == "routed" {
						item, err := collectRoutedBatchItem(ctx, h.remoteManage, h.repo, user, node.ID)
						if err != nil {
							log.Printf("[PackageAssign] routed node %d collect failed for user %s: %v", node.ID, username, err)
							mu.Lock()
							warnings = append(warnings, fmt.Sprintf("路由出站 %s 添加用户失败", node.NodeName))
							mu.Unlock()
							return
						}
						if item != nil {
							mu.Lock()
							routedBatch[item.ServerID] = append(routedBatch[item.ServerID], *item)
							mu.Unlock()
						}
						return
					}
					if node.InboundTag == "" || node.OriginalServer == "" ||
						!supportsPerUserInboundCredential(node.Protocol) {
						return
					}
					// 同一 (server, inbound) 只收集一次 —— both 的 v4/v6 双节点共享同一入站,避免重复加 client。
					seenKey := user.Username + "|" + node.OriginalServer + "|" + node.InboundTag
					mu.Lock()
					if inboundSeen[seenKey] {
						mu.Unlock()
						return
					}
					inboundSeen[seenKey] = true
					mu.Unlock()
					server, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
					if err != nil {
						log.Printf("[PackageAssign] Failed to find server %s: %v", node.OriginalServer, err)
						return
					}
					// 阶段一:从 InboundCache 算 cred,收集成 batch item;cache miss / 续费 → fallback 逐项。
					item, collected, cerr := collectInboundClientAddItem(ctx, h.remoteManage.inboundCache, h.repo, user, server.ID, node.InboundTag)
					if cerr != nil {
						mu.Lock()
						inboundFallbacks = append(inboundFallbacks, inboundFallbackItem{ServerID: server.ID, InboundTag: node.InboundTag, NodeName: node.NodeName})
						mu.Unlock()
						return
					}
					if collected && item != nil {
						mu.Lock()
						inboundBatch[item.ServerID] = append(inboundBatch[item.ServerID], *item)
						mu.Unlock()
					}
				}(nodeID)
			}
			bindWg.Wait()

			// 阶段二 — per-server 并行调 batch-apply。
			// routed + inbound 各自一批,跨 server 并行;同 server 内各自一次 round-trip。
			var routeWg sync.WaitGroup
			for serverID, items := range routedBatch {
				routeWg.Add(1)
				go func(sid int64, list []routedBatchItem) {
					defer routeWg.Done()
					_, ws := applyRoutedBatchOrFallback(ctx, h.remoteManage, h.repo, sid, list, "PackageAssign")
					if len(ws) > 0 {
						mu.Lock()
						warnings = append(warnings, ws...)
						mu.Unlock()
					}
				}(serverID, items)
			}
			for serverID, items := range inboundBatch {
				routeWg.Add(1)
				go func(sid int64, list []InboundClientAddItem) {
					defer routeWg.Done()
					ws := applyInboundBatchOrFallback(ctx, h.remoteManage, h.repo, sid, list, "PackageAssign")
					if len(ws) > 0 {
						mu.Lock()
						warnings = append(warnings, ws...)
						mu.Unlock()
					}
				}(serverID, items)
			}
			routeWg.Wait()

			// 阶段三 — cache miss 类 fallback:并发跑逐项 addUserToInbound(老路径)。
			if len(inboundFallbacks) > 0 {
				log.Printf("[PackageAssign] %d inbound items fell back to per-item add (cache miss / no batch)", len(inboundFallbacks))
				var fbWg sync.WaitGroup
				for _, fb := range inboundFallbacks {
					fbWg.Add(1)
					go func(fb inboundFallbackItem) {
						defer fbWg.Done()
						if err := addUserToInbound(ctx, h.remoteManage, h.repo, user, fb.ServerID, fb.InboundTag); err != nil {
							log.Printf("[PackageAssign] fallback addUserToInbound user=%s server=%d tag=%s: %v",
								username, fb.ServerID, fb.InboundTag, err)
							mu.Lock()
							warnings = append(warnings, fmt.Sprintf("节点 %s 添加用户失败", fb.NodeName))
							mu.Unlock()
						}
					}(fb)
				}
				fbWg.Wait()
			}
		}
	}

	if h.pusher != nil {
		go h.pusher.PushToAllServersForUser(context.Background(), username)
	}
	return warnings, nil
}

type packageNodeRevocation struct {
	routedNodeID int64
	inbound      *storage.UserInboundConfig
}

// revokePackageNodeDifference removes old-package-only credentials before the
// database assignment changes. A failed Agent mutation therefore leaves the
// old package authoritative and makes the switch retryable instead of granting
// the new package while stale old access remains live.
func (h *PackageAssignHandler) revokePackageNodeDifference(ctx context.Context, username string, current, target *storage.Package) ([]packageNodeRevocation, error) {
	if current == nil || target == nil {
		return nil, errors.New("package template is unavailable")
	}
	revoked := make([]packageNodeRevocation, 0)
	targetNodes := make(map[int64]struct{}, len(target.Nodes))
	targetInbounds := make(map[string]struct{}, len(target.Nodes))
	for _, nodeID := range target.Nodes {
		targetNodes[nodeID] = struct{}{}
		node, err := h.repo.GetNodeByID(ctx, nodeID)
		if err != nil || node.NodeType == "routed" || node.OriginalServer == "" || node.InboundTag == "" ||
			!supportsPerUserInboundCredential(node.Protocol) {
			continue
		}
		server, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
		if err == nil {
			targetInbounds[fmt.Sprintf("%d|%s", server.ID, node.InboundTag)] = struct{}{}
		}
	}
	seenInbound := make(map[string]struct{})
	for _, nodeID := range current.Nodes {
		if _, keep := targetNodes[nodeID]; keep {
			continue
		}
		node, err := h.repo.GetNodeByID(ctx, nodeID)
		if err != nil {
			continue
		}
		if node.NodeType == "routed" {
			subaccount, err := h.repo.GetUserSubaccount(ctx, node.ID, username)
			if err != nil {
				return revoked, err
			}
			wasActive := subaccount != nil && subaccount.IsActive
			if wasActive {
				revoked = append(revoked, packageNodeRevocation{routedNodeID: node.ID})
			}
			if _, err := removeUserFromRoutedNode(ctx, h.remoteManage, h.repo, username, node.ID); err != nil {
				return revoked, err
			}
			continue
		}
		if node.OriginalServer == "" || node.InboundTag == "" ||
			!supportsPerUserInboundCredential(node.Protocol) {
			continue
		}
		server, err := h.repo.GetRemoteServerByName(ctx, node.OriginalServer)
		if err != nil {
			return revoked, err
		}
		key := fmt.Sprintf("%d|%s", server.ID, node.InboundTag)
		if _, keep := targetInbounds[key]; keep {
			continue
		}
		if _, duplicate := seenInbound[key]; duplicate {
			continue
		}
		seenInbound[key] = struct{}{}
		cfg, err := h.repo.GetUserInboundConfig(ctx, username, server.ID, node.InboundTag)
		if errors.Is(err, sql.ErrNoRows) || cfg == nil {
			continue
		}
		if err != nil {
			return revoked, err
		}
		copy := *cfg
		revoked = append(revoked, packageNodeRevocation{inbound: &copy})
		retained, err := removePackageUserInboundConfig(ctx, h.remoteManage, h.repo, *cfg)
		if err != nil && !isInboundNotFoundErr(err) {
			return revoked, err
		}
		if retained {
			revoked = revoked[:len(revoked)-1]
		}
	}
	return revoked, nil
}

func (h *PackageAssignHandler) restorePackageNodeRevocations(ctx context.Context, user storage.User, revoked []packageNodeRevocation) error {
	var restoreErrors []error
	for i := len(revoked) - 1; i >= 0; i-- {
		action := revoked[i]
		if action.routedNodeID > 0 {
			if err := addUserToRoutedNode(ctx, h.remoteManage, h.repo, user, action.routedNodeID); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("routed node %d: %w", action.routedNodeID, err))
			}
			continue
		}
		if action.inbound == nil {
			continue
		}
		cfg := *action.inbound
		var credential map[string]interface{}
		if err := json.Unmarshal([]byte(cfg.CredentialJSON), &credential); err != nil || credential == nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("inbound %d/%s credential: %v", cfg.ServerID, cfg.InboundTag, err))
			continue
		}
		if err := h.repo.SaveUserInboundConfig(ctx, cfg); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("inbound %d/%s state: %w", cfg.ServerID, cfg.InboundTag, err))
			continue
		}
		if err := applyPreparedInboundCredentialForUser(ctx, h.remoteManage, h.repo, user.Username, cfg.ServerID, cfg.InboundTag, credential, user.PackageEndDate); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("inbound %d/%s remote: %w", cfg.ServerID, cfg.InboundTag, err))
		}
	}
	return errors.Join(restoreErrors...)
}

func (h *PackageAssignHandler) autoGenerateSubscription(ctx context.Context, username string, packageID int64) {
	pkg, err := h.repo.GetPackage(ctx, packageID)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 获取套餐错误: %v", err)
		return
	}

	var proxies []map[string]any
	for _, nodeID := range pkg.Nodes {
		node, err := h.repo.GetNodeByID(ctx, nodeID)
		if err != nil || !node.Enabled || node.ClashConfig == "" {
			continue
		}
		// Package subscriptions are rendered from the encrypted database by
		// PackageSubscribeHandler. Do not copy a hydrated WireGuard identity into
		// this legacy persistent snapshot.
		if !shouldPersistNodeInLegacyPackageSnapshot(node) {
			continue
		}
		var proxyConfig map[string]any
		if err := json.Unmarshal([]byte(node.ClashConfig), &proxyConfig); err != nil {
			continue
		}
		delete(proxyConfig, storage.ManagedShadowsocksMultiUserMarker)
		proxies = append(proxies, proxyConfig)
	}

	if len(proxies) == 0 {
		log.Printf("[PackageAssign] 自动生成订阅跳过: 套餐 %d 无可用节点", packageID)
		return
	}

	templateContent, err := h.loadDefaultTemplate(ctx)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: %v", err)
		return
	}

	// This legacy path persists a YAML snapshot. Native Provider credentials
	// must only be emitted by request-time rendering so token rotation can take
	// effect immediately; expand every Provider before writing the snapshot.
	result, err := renderTemplateWithProxyProviders(ctx, h.repo, templateContent, proxies, username, true)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 处理模板错误: %v", err)
		return
	}
	if strings.Contains(result, proxyProviderAccessTokenPrefix) {
		log.Printf("[PackageAssign] 自动生成订阅失败: 拒绝持久化 Provider 访问凭据")
		return
	}

	if err := os.MkdirAll("subscribes", 0700); err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 创建目录错误: %v", err)
		return
	}

	existing, err := h.repo.GetUserPackageSubscription(ctx, username)
	if err == nil {
		if err := storage.ValidateSubscribeFilename(existing.Filename); err != nil {
			log.Printf("[PackageAssign] 自动生成订阅失败: 无效文件名: %v", err)
			return
		}
		unlock, err := lockSubscriptionFilenames(existing.Filename)
		if err != nil {
			log.Printf("[PackageAssign] 自动生成订阅失败: 锁定文件错误: %v", err)
			return
		}
		defer unlock()
		fresh, err := h.repo.GetSubscribeFileByID(ctx, existing.ID)
		if err != nil {
			log.Printf("[PackageAssign] 自动生成订阅失败: 重新读取订阅错误: %v", err)
			return
		}
		existing = fresh
		if err := storage.ValidateSubscribeFilename(existing.Filename); err != nil {
			log.Printf("[PackageAssign] 自动生成订阅失败: 无效文件名: %v", err)
			return
		}
		filePath := filepath.Join("subscribes", existing.Filename)
		protected, protectErr := protectWireGuardSubscriptionContent(ctx, h.repo, existing.Filename, result, false)
		if protectErr != nil {
			log.Printf("[PackageAssign] 自动生成订阅失败: WireGuard 私钥保护错误: %v", protectErr)
			return
		}
		if err := writePrivateSubscriptionFileUnlocked(filePath, []byte(protected)); err != nil {
			log.Printf("[PackageAssign] 自动生成订阅失败: 写入文件错误: %v", err)
			return
		}
		existing.Name = fmt.Sprintf("%s - %s", username, pkg.Name)
		existing.Description = "套餐自动生成"
		if _, err := h.repo.UpdateSubscribeFile(ctx, existing); err != nil {
			log.Printf("[PackageAssign] 自动生成订阅失败: 更新记录错误: %v", err)
			return
		}
		log.Printf("[PackageAssign] 已更新用户 %s 的套餐订阅文件", username)
		return
	}

	filename := fmt.Sprintf("pkg_%s.yaml", username)
	if err := storage.ValidateSubscribeFilename(filename); err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 无效文件名: %v", err)
		return
	}
	unlock, err := lockSubscriptionFilenames(filename)
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 锁定文件错误: %v", err)
		return
	}
	defer unlock()
	filePath := filepath.Join("subscribes", filename)
	protected, protectErr := protectWireGuardSubscriptionContent(ctx, h.repo, filename, result, false)
	if protectErr != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: WireGuard 私钥保护错误: %v", protectErr)
		return
	}
	ownership, err := writeNewPrivateSubscriptionFile(filePath, []byte(protected))
	if err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 写入文件错误: %v", err)
		return
	}

	file := storage.SubscribeFile{
		Name:        fmt.Sprintf("%s - %s", username, pkg.Name),
		Description: "套餐自动生成",
		Type:        storage.SubscribeTypePackage,
		Filename:    filename,
		CreatedBy:   username, // 套餐自动生成的订阅归属到该用户，否则后续 GetSubscribeFileByShortCode 拿不到归属用户
	}
	created, err := h.repo.CreateSubscribeFile(ctx, file)
	if err != nil {
		_ = removeSubscriptionFileIfOwned(filePath, ownership)
		log.Printf("[PackageAssign] 自动生成订阅失败: 创建记录错误: %v", err)
		return
	}
	if err := h.repo.AssignSubscriptionToUser(ctx, username, created.ID); err != nil {
		log.Printf("[PackageAssign] 自动生成订阅失败: 关联用户错误: %v", err)
		return
	}
	log.Printf("[PackageAssign] 已为用户 %s 创建套餐订阅文件", username)
}

func shouldPersistNodeInLegacyPackageSnapshot(node storage.Node) bool {
	return !strings.EqualFold(strings.TrimSpace(node.Protocol), "wireguard")
}

func (h *PackageAssignHandler) loadDefaultTemplate(ctx context.Context) (string, error) {
	templatesDir := "rule_templates"
	var candidates []string

	cfg, err := h.repo.GetSystemConfig(ctx)
	if err == nil && cfg.DefaultTemplateFilename != "" {
		candidates = append(candidates, cfg.DefaultTemplateFilename)
	}
	candidates = append(candidates, "default.yaml", "redirhost__v3.yaml")

	for _, name := range candidates {
		content, err := os.ReadFile(filepath.Join(templatesDir, name))
		if err == nil {
			return string(content), nil
		}
	}
	return "", fmt.Errorf("未找到可用模板")
}

// inboundCredLocks 串行化同一 (user, server, inbound) 的凭据生成 + 写 DB。
// 根治跨操作并发(套餐绑定 + 限速 enforcer / node-sync 同时命中同一 user+inbound)时,两条路径各自
// 查到 DB 无记录 → 各生成不同随机 uuid → agent 按 uuid 去重失效 → 同 email 重复子账户。
var inboundCredLocks sync.Map // key "username|serverID|inboundTag" → *sync.Mutex

func inboundCredLock(username string, serverID int64, inboundTag string) *sync.Mutex {
	key := fmt.Sprintf("%s|%d|%s", username, serverID, inboundTag)
	v, _ := inboundCredLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// getOrCreateInboundCredential 在 (user, server, inbound) 全局锁内原子地拿到该用户在该入站的凭据:
//  1. DB user_inbound_configs 有记录 → 复用(续费 / 重复绑定 / 并发中的第二个请求)
//  2. agent 该入站已有同 email 的 client(settings 快照)→ 复用并回写 DB
//  3. 都没有 → 生成新凭据 + 立即写 DB
//
// 「全局锁 + 生成时立即写 DB」是根治并发重复的核心:串行后第二个并发请求在步骤 1 就命中第一个刚写入的
// 凭据、拿到同一 uuid,agent add-client 按 uuid 幂等 no-op,不再产生同 email 不同 uuid 的重复子账户。
// settings 为该入站 settings 快照(InboundCache 或 live GET 均可)。返回 (credential, credJSON, reused)。
func getOrCreateInboundCredential(ctx context.Context, repo *storage.TrafficRepository,
	user storage.User, serverID int64, inboundTag, protocol string, settings map[string]interface{},
) (map[string]interface{}, string, bool, error) {
	lock := inboundCredLock(user.Username, serverID, inboundTag)
	lock.Lock()
	defer lock.Unlock()

	// 1) DB 复用
	if existing, _ := repo.GetUserInboundConfig(ctx, user.Username, serverID, inboundTag); existing != nil && existing.Protocol == protocol {
		var cred map[string]interface{}
		if json.Unmarshal([]byte(existing.CredentialJSON), &cred) == nil && cred != nil {
			credJSON := existing.CredentialJSON
			credentialChanged := false
			if strings.EqualFold(protocol, "vless") && reconcileVLESSCredentialFlow(cred, settings) {
				credentialChanged = true
			}
			if canonicalManagedProtocol(protocol) == "shadowsocks" {
				methodChanged, err := reconcileClassicShadowsocksCredentialMethod(cred, settings)
				if err != nil {
					return nil, "", false, fmt.Errorf("reconcile classic Shadowsocks credential: %w", err)
				}
				credentialChanged = credentialChanged || methodChanged
			}
			if credentialChanged {
				updated, err := json.Marshal(cred)
				if err != nil {
					return nil, "", false, fmt.Errorf("marshal reconciled credential: %w", err)
				}
				credJSON = string(updated)
				if err := repo.UpdateUserInboundCredentialJSONByID(ctx, existing.ID, credJSON); err != nil {
					return nil, "", false, fmt.Errorf("persist reconciled credential: %w", err)
				}
			}
			return cred, credJSON, true, nil
		}
	}

	email := user.Username + "__" + inboundTag

	// 2) agent 已有同 email → 复用并回写 DB(主控与 agent 重新对齐,下次直接走步骤 1)
	if reuse := extractClientByEmail(settings, email); reuse != nil {
		if canonicalManagedProtocol(protocol) == "shadowsocks" {
			if _, err := reconcileClassicShadowsocksCredentialMethod(reuse, settings); err != nil {
				return nil, "", false, fmt.Errorf("validate live classic Shadowsocks credential: %w", err)
			}
		}
		b, _ := json.Marshal(reuse)
		credJSON := string(b)
		if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
			Username: user.Username, ServerID: serverID, InboundTag: inboundTag,
			Protocol: protocol, CredentialJSON: credJSON,
		}); err != nil {
			return nil, "", false, err
		}
		return reuse, credJSON, true, nil
	}

	// 3) 生成新 + 立即写 DB(锁内)。后续 add-client / batch-apply 即便失败也没关系:凭据已 reserve,
	// 下次复用同一份重发,agent 幂等 → 永不重复。
	method := shadowsocksInboundMethod(settings)
	cred, credJSON, err := generateCredential(protocol, user, method, inboundTag)
	if err != nil {
		return nil, "", false, err
	}
	// VLESS 新凭据尚未存在于 Agent，按入站参考 client 继承 flow。
	if strings.EqualFold(protocol, "vless") && reconcileVLESSCredentialFlow(cred, settings) {
		if b, err := json.Marshal(cred); err == nil {
			credJSON = string(b)
		}
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: user.Username, ServerID: serverID, InboundTag: inboundTag,
		Protocol: protocol, CredentialJSON: credJSON,
	}); err != nil {
		return nil, "", false, err
	}
	return cred, credJSON, false, nil
}

// shadowsocksInboundMethod supports both SS2022's top-level method and
// classic multi-user inbounds, where Xray keeps the cipher on each client.
func shadowsocksInboundMethod(settings map[string]interface{}) string {
	if settings == nil {
		return ""
	}
	if method, _ := settings["method"].(string); strings.TrimSpace(method) != "" {
		return strings.ToLower(strings.TrimSpace(method))
	}
	clients, _ := settings["clients"].([]interface{})
	for _, item := range clients {
		client, _ := item.(map[string]interface{})
		if method, _ := client["method"].(string); strings.TrimSpace(method) != "" {
			return strings.ToLower(strings.TrimSpace(method))
		}
	}
	return ""
}

// reconcileClassicShadowsocksCredentialMethod only backfills historical
// credentials after the live inbound proves that the same client identity uses
// the current cipher. A blind backfill can relabel an AES-128 password as
// AES-256 after an inbound edit while the Agent still has the old client.
func reconcileClassicShadowsocksCredentialMethod(credential, settings map[string]interface{}) (bool, error) {
	method := shadowsocksInboundMethod(settings)
	if method != "aes-128-gcm" && method != "aes-256-gcm" {
		return false, nil
	}
	if credential == nil {
		return false, errors.New("credential is missing")
	}

	if rawMethod, exists := credential["method"]; exists {
		storedMethod, ok := rawMethod.(string)
		storedMethod = strings.ToLower(strings.TrimSpace(storedMethod))
		if !ok || storedMethod == "" {
			return false, errors.New("stored credential method is invalid")
		}
		if storedMethod != method {
			return false, fmt.Errorf("stored credential method %q does not match inbound method %q", storedMethod, method)
		}
		return false, nil
	}

	password, _ := credential["password"].(string)
	email, _ := credential["email"].(string)
	password = strings.TrimSpace(password)
	email = strings.TrimSpace(email)
	if password == "" && email == "" {
		return false, errors.New("stored credential has no verifiable client identity")
	}

	clients, _ := settings["clients"].([]interface{})
	for _, item := range clients {
		client, _ := item.(map[string]interface{})
		if client == nil {
			continue
		}
		clientMethod, _ := client["method"].(string)
		if strings.ToLower(strings.TrimSpace(clientMethod)) != method {
			continue
		}
		clientPassword, _ := client["password"].(string)
		clientEmail, _ := client["email"].(string)
		if password != "" && strings.TrimSpace(clientPassword) != password {
			continue
		}
		if email != "" && strings.TrimSpace(clientEmail) != email {
			continue
		}
		credential["method"] = method
		return true, nil
	}

	return false, errors.New("stored credential method is missing and no matching live client was found")
}

func validateClassicShadowsocksManagedSettings(protocol string, settings map[string]interface{}) error {
	if canonicalManagedProtocol(protocol) != "shadowsocks" {
		return nil
	}
	method := shadowsocksInboundMethod(settings)
	if method != "aes-128-gcm" && method != "aes-256-gcm" {
		return nil
	}
	if _, topLevelMethod := settings["method"]; topLevelMethod {
		return errors.New("classic Shadowsocks managed access requires a per-user clients configuration")
	}
	clients, ok := settings["clients"].([]interface{})
	if !ok || len(clients) == 0 {
		return errors.New("classic Shadowsocks managed access requires a per-user clients configuration")
	}
	for _, item := range clients {
		client, _ := item.(map[string]interface{})
		clientMethod, _ := client["method"].(string)
		clientPassword, _ := client["password"].(string)
		if strings.EqualFold(strings.TrimSpace(clientMethod), method) && strings.TrimSpace(clientPassword) != "" {
			return nil
		}
	}
	return errors.New("classic Shadowsocks managed access requires AES-GCM method and password on each client")
}

// addUserToInbound 获取远程入站配置，添加用户凭据，然后重新提交
func addUserToInbound(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, user storage.User, serverID int64, inboundTag string) error {
	return repo.WithUserAuthorizationLease(ctx, user.Username, func(leasedCtx context.Context) error {
		latest, err := repo.GetUser(leasedCtx, user.Username)
		if err != nil {
			return err
		}
		hasAccess, notAfter, err := effectiveUserInboundAuthorization(leasedCtx, repo, user.Username, serverID, inboundTag, time.Now().UTC())
		if err != nil {
			return err
		}
		if !hasAccess {
			return errors.New("no active authorization for inbound")
		}
		return addUserToInboundWithExpiry(leasedCtx, rm, repo, latest, serverID, inboundTag, notAfter)
	})
}

func effectiveUserInboundAuthorization(ctx context.Context, repo *storage.TrafficRepository, username string, serverID int64, inboundTag string, now time.Time) (bool, *time.Time, error) {
	hasManaged, managedExpiry, err := repo.HasEffectiveUserInboundAccess(ctx, username, serverID, inboundTag, 0, now)
	if err != nil {
		return false, nil, fmt.Errorf("resolve managed inbound access: %w", err)
	}
	hasDirect, directExpiry, err := repo.HasEffectiveDirectUserInboundAccess(ctx, username, serverID, inboundTag, 0, now)
	if err != nil {
		return false, nil, fmt.Errorf("resolve direct inbound access: %w", err)
	}
	hasIndependent, independentExpiry := laterOptionalExpiry(hasManaged, managedExpiry, hasDirect, directExpiry)
	hasPackage, packageExpiry, err := hasLegacyPackageInboundAccess(ctx, repo, username, serverID, inboundTag, now)
	if err != nil {
		return false, nil, fmt.Errorf("resolve package inbound access: %w", err)
	}
	hasAccess, notAfter := laterOptionalExpiry(hasIndependent, independentExpiry, hasPackage, packageExpiry)
	return hasAccess, notAfter, nil
}

func packageAssignmentActive(user storage.User, now time.Time) bool {
	if !user.IsActive || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID <= 0 {
		return false
	}
	if user.PackageStartDate != nil && now.Before(*user.PackageStartDate) {
		return false
	}
	return user.PackageEndDate == nil || now.Before(*user.PackageEndDate)
}

func addUserToInboundWithExpiry(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, user storage.User, serverID int64, inboundTag string, notAfter *time.Time) error {
	// SaveUserInboundConfig takes the user provisioning mutex itself. Hold only
	// the server lease across snapshot, reservation, publish, and restart to
	// avoid reversing the user->server order used by deletion/routed flows.
	leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
	if err != nil {
		return err
	}
	defer release()

	credential, err := prepareUserInboundCredential(leasedCtx, rm, repo, user, serverID, inboundTag)
	if err != nil {
		return err
	}
	return applyPreparedInboundCredential(leasedCtx, rm, serverID, inboundTag, credential, notAfter)
}

func applyPreparedInboundCredentialForUser(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, username string, serverID int64, inboundTag string, credential map[string]interface{}, notAfter *time.Time) error {
	return repo.WithUserProvisioningLease(ctx, username, func() error {
		hasAccess, latestExpiry, err := effectiveUserInboundAuthorization(ctx, repo, username, serverID, inboundTag, time.Now().UTC())
		if err != nil {
			return err
		}
		if !hasAccess {
			return errors.New("authorization changed before inbound credential publication")
		}
		if latestExpiry != nil && (notAfter == nil || latestExpiry.Before(*notAfter)) {
			notAfter = latestExpiry
		}
		leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
		if err != nil {
			return err
		}
		defer release()
		return applyPreparedInboundCredential(leasedCtx, rm, serverID, inboundTag, credential, notAfter)
	})
}

// prepareUserInboundCredential reserves the canonical credential in storage
// before it becomes usable on the Agent. Managed provisioning uses this split
// to publish limiter policy between reservation and add-client.
func prepareUserInboundCredential(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, user storage.User, serverID int64, inboundTag string) (map[string]interface{}, error) {
	// 只读 inbound 列表,目的是拿到 protocol/method/flow 这些构造 credential 必需的字段。
	// 不再在主控这边修改 inbound:实际的"加 client"由 agent 在 inboundsMu 锁内原子完成,
	// 避免多用户并发绑套餐时主控基于同一份快照各自 append → 后写覆盖先写 → 丢 client。
	result, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		return nil, fmt.Errorf("get inbounds: %w", err)
	}

	var resp struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(result, &resp); err != nil || !resp.Success {
		return nil, fmt.Errorf("parse inbounds response: %v", err)
	}

	var targetInbound map[string]interface{}
	for _, ib := range resp.Inbounds {
		if tag, _ := ib["tag"].(string); tag == inboundTag {
			targetInbound = ib
			break
		}
	}
	if targetInbound == nil {
		return nil, fmt.Errorf("inbound %s not found", inboundTag)
	}

	protocol, _ := targetInbound["protocol"].(string)
	settings, _ := targetInbound["settings"].(map[string]interface{})
	if err := validateClassicShadowsocksManagedSettings(protocol, settings); err != nil {
		return nil, err
	}

	// 凭据统一走 getOrCreateInboundCredential:全局锁内查 DB 复用 / 按 email 复用 / 生成 + 立即写 DB。
	// 根治跨操作并发时两条路径各自生成不同 uuid 的重复子账户;flow 继承 + 写 DB 都在其内部完成。
	credential, _, _, err := getOrCreateInboundCredential(ctx, repo, user, serverID, inboundTag, protocol, settings)
	if err != nil {
		return nil, fmt.Errorf("get or create credential: %w", err)
	}
	return credential, nil
}

func applyPreparedInboundCredential(ctx context.Context, rm *RemoteManageHandler, serverID int64, inboundTag string, credential map[string]interface{}, notAfter *time.Time) error {
	// 原子 add-client:agent 端在 inboundsMu 内做 read-modify-write,自带幂等(已存在则 no-op)。
	request := map[string]interface{}{
		"action": "add-client",
		"tag":    inboundTag,
		"client": credential,
	}
	if notAfter != nil {
		request["not_after"] = notAfter.UTC()
	}
	body, _ := json.Marshal(request)
	response, err := rm.forwardToRemoteServer(suppressDatabaseInboundPostWrite(ctx), serverID, "POST", "/api/child/inbounds", body)
	if err != nil {
		return fmt.Errorf("add-client: %w", err)
	}
	runtimeDeferred, err := validateAgentClientMutation(response)
	if err != nil {
		return fmt.Errorf("add-client ACK: %w", err)
	}
	if runtimeDeferred {
		// The Agent persisted the client but could not hot-replace the inbound.
		// Do not revive an administrator-stopped core; the Agent retries on a
		// later matching mutation or the operator's explicit Xray start.
		log.Printf("[ManagedClientAdd] server=%d Agent deferred inbound runtime apply; Xray lifecycle left unchanged", serverID)
	}

	return nil
}

type agentClientMutationOutcome struct {
	RuntimeDeferred   bool
	NoOp              bool
	ExplicitUnchanged bool
}

// inspectAgentClientMutation separates a genuine runtime-apply failure from
// an idempotent no-op. Neither condition grants the control plane permission
// to start a stopped Xray process.
func inspectAgentClientMutation(body []byte) (agentClientMutationOutcome, error) {
	var response struct {
		Success        bool   `json:"success"`
		Message        string `json:"message"`
		RuntimeWarning string `json:"runtime_warning"`
		Changed        *bool  `json:"changed"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return agentClientMutationOutcome{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if !response.Success {
		return agentClientMutationOutcome{}, errors.New("Agent did not acknowledge the client mutation")
	}
	return agentClientMutationOutcome{
		RuntimeDeferred:   strings.TrimSpace(response.RuntimeWarning) != "",
		NoOp:              strings.Contains(strings.ToLower(response.Message), "no-op"),
		ExplicitUnchanged: response.Changed != nil && !*response.Changed,
	}, nil
}

// validateAgentClientMutation reports only whether the Agent deferred a live
// inbound replacement. Callers may surface or log that condition, but must not
// use it as a reason to start or restart Xray.
func validateAgentClientMutation(body []byte) (bool, error) {
	outcome, err := inspectAgentClientMutation(body)
	if err != nil {
		return false, err
	}
	return outcome.RuntimeDeferred, nil
}

// extractClientByEmail 在 inbound.settings 的 clients / users / accounts 数组里按 email 找现存 client,
// 命中返回其副本(浅拷贝),没有则 nil。用于"加 client 前先按 email 查、有就复用"的去重兜底。
func extractClientByEmail(settings map[string]interface{}, email string) map[string]interface{} {
	if settings == nil || email == "" {
		return nil
	}
	for _, key := range []string{"clients", "users", "accounts"} {
		arr, _ := settings[key].([]interface{})
		for _, c := range arr {
			cm, _ := c.(map[string]interface{})
			if cm == nil {
				continue
			}
			if e, _ := cm["email"].(string); e == email {
				cp := make(map[string]interface{}, len(cm))
				for k, v := range cm {
					cp[k] = v
				}
				return cp
			}
		}
	}
	return nil
}

// reconcileVLESSCredentialFlow 让主控凭据与 Agent 当前 VLESS client 的 flow 保持一致。
// 已存在的 client 优先按 id、其次按 email 匹配；尚未下发的凭据才继承第一个 client 的 flow。
// 这样存量凭据不会错误继承其他账户的 Vision flow，新账户仍能继承入站的协议组合。
func reconcileVLESSCredentialFlow(credential, settings map[string]interface{}) bool {
	if credential == nil || settings == nil {
		return false
	}
	clients, _ := settings["clients"].([]interface{})
	if len(clients) == 0 {
		return false
	}

	var matched map[string]interface{}
	id := strings.TrimSpace(fmt.Sprint(credential["id"]))
	if id != "" && id != "<nil>" {
		for _, item := range clients {
			client, _ := item.(map[string]interface{})
			if client != nil && strings.TrimSpace(fmt.Sprint(client["id"])) == id {
				matched = client
				break
			}
		}
	}
	if matched == nil {
		email := strings.TrimSpace(fmt.Sprint(credential["email"]))
		if email != "" && email != "<nil>" {
			for _, item := range clients {
				client, _ := item.(map[string]interface{})
				if client != nil && strings.TrimSpace(fmt.Sprint(client["email"])) == email {
					matched = client
					break
				}
			}
		}
	}
	if matched == nil {
		matched, _ = clients[0].(map[string]interface{})
	}
	if matched == nil {
		return false
	}

	desiredFlow, _ := matched["flow"].(string)
	desiredFlow = strings.TrimSpace(desiredFlow)
	currentFlow, hasFlow := credential["flow"]
	if desiredFlow == "" {
		if hasFlow {
			delete(credential, "flow")
			return true
		}
		return false
	}
	if current, ok := currentFlow.(string); ok && current == desiredFlow {
		return false
	}
	credential["flow"] = desiredFlow
	return true
}

// removeUserFromInbound 通过 agent 原子 remove-client 移除用户凭据。
// 主控不再持有 inbound 副本,所以也不存在并发解绑时彼此覆盖的可能。
func removeUserFromInbound(ctx context.Context, rm *RemoteManageHandler, cfg storage.UserInboundConfig) error {
	var savedCred map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.CredentialJSON), &savedCred); err != nil || savedCred == nil {
		return fmt.Errorf("parse saved credential: %v", err)
	}
	body, _ := json.Marshal(map[string]interface{}{
		"action": "remove-client",
		"tag":    cfg.InboundTag,
		"client": savedCred,
	})
	response, err := rm.forwardToRemoteServer(ctx, cfg.ServerID, "POST", "/api/child/inbounds", body)
	if err != nil {
		return fmt.Errorf("remove-client: %w", err)
	}
	runtimeDeferred, err := validateAgentClientMutation(response)
	if err != nil {
		return fmt.Errorf("remove-client ACK: %w", err)
	}
	if runtimeDeferred {
		log.Printf("[ManagedClientRemove] server=%d Agent deferred inbound runtime apply; Xray lifecycle left unchanged", cfg.ServerID)
	}
	return nil
}

// removePackageUserFromInbound removes the shared credential only when no
// independent managed-node grant still authorizes the same user and inbound.
// User deletion/status handlers intentionally keep using removeUserFromInbound
// directly because those operations revoke every access source.
func removePackageUserFromInbound(ctx context.Context, rm *RemoteManageHandler, cfg storage.UserInboundConfig) (bool, error) {
	if rm == nil || rm.repo == nil {
		return false, errors.New("remote manager is not available")
	}
	hasManagedAccess, notAfter, err := rm.repo.HasEffectiveUserInboundAccess(ctx, cfg.Username, cfg.ServerID, cfg.InboundTag, 0, time.Now().UTC())
	if err != nil {
		return false, fmt.Errorf("resolve managed access before package cleanup: %w", err)
	}
	hasDirectAccess, directExpiry, err := rm.repo.HasEffectiveDirectUserInboundAccess(ctx, cfg.Username, cfg.ServerID, cfg.InboundTag, 0, time.Now().UTC())
	if err != nil {
		return false, fmt.Errorf("resolve direct access before package cleanup: %w", err)
	}
	hasManagedAccess, notAfter = laterOptionalExpiry(hasManagedAccess, notAfter, hasDirectAccess, directExpiry)
	if hasManagedAccess {
		user, userErr := rm.repo.GetUser(ctx, cfg.Username)
		if userErr != nil {
			return true, userErr
		}
		if refreshErr := addUserToInboundWithExpiry(ctx, rm, rm.repo, user, cfg.ServerID, cfg.InboundTag, notAfter); refreshErr != nil {
			requeueManagedInboundAccess(ctx, rm.repo, cfg.Username, cfg.ServerID, cfg.InboundTag)
			return true, fmt.Errorf("refresh managed credential deadline: %w", refreshErr)
		}
		return true, nil
	}
	return false, removeUserFromInbound(ctx, rm, cfg)
}

// removePackageUserInboundConfig is the package unbind transaction for one
// physical server. The remote remove/managed-deadline refresh, its required
// restart, and the local credential-state deletion all happen under the same
// user-then-server lease order. A running installation therefore fails before
// the Agent or user_inbound_configs can be changed.
func removePackageUserInboundConfig(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, cfg storage.UserInboundConfig) (bool, error) {
	if rm == nil || repo == nil {
		return false, errors.New("remote manager is not available")
	}
	retained := false
	err := repo.WithUserProvisioningLease(ctx, cfg.Username, func() error {
		leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, cfg.ServerID)
		if err != nil {
			return err
		}
		defer release()

		hasManagedAccess, notAfter, err := repo.HasEffectiveUserInboundAccess(
			leasedCtx, cfg.Username, cfg.ServerID, cfg.InboundTag, 0, time.Now().UTC(),
		)
		if err != nil {
			return fmt.Errorf("resolve managed access before package cleanup: %w", err)
		}
		hasDirectAccess, directExpiry, err := repo.HasEffectiveDirectUserInboundAccess(
			leasedCtx, cfg.Username, cfg.ServerID, cfg.InboundTag, 0, time.Now().UTC(),
		)
		if err != nil {
			return fmt.Errorf("resolve direct access before package cleanup: %w", err)
		}
		hasManagedAccess, notAfter = laterOptionalExpiry(hasManagedAccess, notAfter, hasDirectAccess, directExpiry)
		if hasManagedAccess {
			var credential map[string]interface{}
			if err := json.Unmarshal([]byte(cfg.CredentialJSON), &credential); err != nil || credential == nil {
				return fmt.Errorf("parse retained package credential: %v", err)
			}
			err = applyPreparedInboundCredential(leasedCtx, rm, cfg.ServerID, cfg.InboundTag, credential, notAfter)
			if err != nil {
				requeueManagedInboundAccess(leasedCtx, repo, cfg.Username, cfg.ServerID, cfg.InboundTag)
				return fmt.Errorf("refresh managed credential deadline: %w", err)
			}
			retained = true
			return nil
		}

		if err := removeUserFromInbound(leasedCtx, rm, cfg); err != nil && !isInboundNotFoundErr(err) {
			return err
		}
		if err := repo.DeleteUserInboundConfig(leasedCtx, cfg.Username, cfg.ServerID, cfg.InboundTag); err != nil {
			return fmt.Errorf("delete package inbound credential state: %w", err)
		}
		return nil
	})
	return retained, err
}

// removeStalePackageUserInboundConfig is used by template cleanup. It repeats
// the durable package-template check while holding the same account lease as
// the remote removal, so a concurrent package switch cannot make a stale
// background task revoke a credential required by the new package.
func removeStalePackageUserInboundConfig(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, cfg storage.UserInboundConfig) (bool, error) {
	if rm == nil || repo == nil {
		return false, errors.New("remote manager is not available")
	}
	retained := false
	err := repo.WithUserAuthorizationLease(ctx, cfg.Username, func(leasedCtx context.Context) error {
		hasPackageAccess, err := hasPackageTemplateInboundAccess(
			leasedCtx, repo, cfg.Username, cfg.ServerID, cfg.InboundTag, time.Now().UTC(),
		)
		if err != nil {
			return err
		}
		if hasPackageAccess {
			retained = true
			return nil
		}
		var removeErr error
		retained, removeErr = removePackageUserInboundConfig(leasedCtx, rm, repo, cfg)
		return removeErr
	})
	return retained, err
}

func requeueManagedInboundAccess(ctx context.Context, repo *storage.TrafficRepository, username string, serverID int64, inboundTag string) {
	sources, err := repo.ListUserInboundAccessSources(ctx, username, serverID)
	if err != nil {
		return
	}
	for _, source := range sources {
		if source.InboundTag != inboundTag || source.DesiredState != storage.ManagedDesiredActive {
			continue
		}
		_, _ = repo.SetUserInboundAccessSourceState(ctx, source.ID, source.Generation,
			storage.ManagedDesiredActive, storage.ManagedSuspendNone, "package_cleanup", source.ExpiresAt)
	}
}

// hasLegacyPackageInboundAccess reports whether the current package still
// authorizes the physical inbound. Package cleanup callers intentionally skip
// this check because they are removing that source; managed cleanup uses it to
// avoid revoking a shared credential that the package still needs.
func hasLegacyPackageInboundAccess(ctx context.Context, repo *storage.TrafficRepository, username string, serverID int64, inboundTag string, now time.Time) (bool, *time.Time, error) {
	if repo == nil || strings.TrimSpace(username) == "" || serverID <= 0 || strings.TrimSpace(inboundTag) == "" {
		return false, nil, storage.ErrManagedInvalidArgument
	}
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return false, nil, err
	}
	if !packageAssignmentActive(user, now) {
		return false, nil, nil
	}
	overLimit, err := repo.IsUserOverLimit(ctx, username)
	if err != nil {
		return false, nil, err
	}
	if overLimit {
		return false, nil, nil
	}
	pkg, err := repo.GetPackage(ctx, user.PackageID)
	if err != nil {
		return false, nil, err
	}
	server, err := repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return false, nil, err
	}
	for _, nodeID := range pkg.Nodes {
		node, nodeErr := repo.GetNodeByID(ctx, nodeID)
		if nodeErr != nil {
			continue
		}
		if node.Enabled && node.NodeType != "routed" && supportsPerUserInboundCredential(node.Protocol) &&
			node.OriginalServer == server.Name && node.InboundTag == inboundTag {
			if user.PackageEndDate == nil {
				return true, nil, nil
			}
			expires := user.PackageEndDate.UTC()
			return true, &expires, nil
		}
	}
	return false, nil, nil
}

// shadowsocksKeyLength 根据 SS method 返回 password 应有的字节数（base64 解码后）。
func shadowsocksKeyLength(method string) int {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	// 老 SS 算法对 key 长度宽松,16 字节够大多数场景。
	return 16
}

// generateCredential 生成单用户在指定 inbound 上的认证凭据。
// shadowsocks 协议要求 password 与 method 的 key length 严格匹配,否则 xray reload 会失败。
// SS2022 :
//
//	2022-blake3-aes-128-gcm           → 16 bytes (base64 24 chars)
//	2022-blake3-aes-256-gcm           → 32 bytes
//	2022-blake3-chacha20-poly1305     → 32 bytes
//
// 老 SS / 非 2022 method → 任意长度都接受,默认给 16 bytes 即可。
//
// email 强制使用 `<username>__<inboundTag>` 格式,保证同一 user 在同一 server 多 inbound 时
// 每条 client 的 email 唯一 — Xray stats 才能按 inbound 拆开 per-user 流量,前端 drilldown
// 无需"多 inbound 平均分"近似。反查走 ResolveUsernameByEmail 的 `__` split 规则,
// 跟 routed 子账户 `<username>__<id>__<label>` 命名兼容(都取首段当 username)。
func generateCredential(protocol string, user storage.User, method, inboundTag string) (map[string]interface{}, string, error) {
	cred := make(map[string]interface{})
	email := user.Username + "__" + inboundTag
	protocol = canonicalManagedProtocol(protocol)

	switch strings.ToLower(protocol) {
	case "vless", "vmess":
		id := uuid.New().String()
		cred["id"] = id
		cred["email"] = email
		cred["level"] = 0
	case "trojan":
		cred["password"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "anytls":
		cred["password"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "snell":
		// Snell v4/v5 多用户 = 每用户独立 psk(逐 PSK 试解);version/obfs 由 inbound(users[0])决定。
		// v6(共享 psk + clientId)需 version 感知,由 inbound 创建时处理,此处按 v4/v5 生成 psk。
		cred["psk"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "hysteria":
		// HY2 客户端凭据:auth(密码) + email(用于 per-user 流量统计,接入套餐限额)。
		cred["auth"] = uuid.New().String()
		cred["email"] = email
		cred["level"] = 0
	case "shadowsocks":
		keyLen := shadowsocksKeyLength(method)
		key := make([]byte, keyLen)
		rand.Read(key)
		cred["password"] = base64.StdEncoding.EncodeToString(key)
		method = strings.ToLower(strings.TrimSpace(method))
		if method == "aes-128-gcm" || method == "aes-256-gcm" {
			cred["method"] = method
		}
		cred["email"] = email
		cred["level"] = 0
	case "socks", "http":
		cred["user"] = user.Username
		cred["pass"] = uuid.New().String()[:16]
	default:
		return nil, "", fmt.Errorf("unsupported protocol: %s", protocol)
	}

	credJSON, _ := json.Marshal(cred)
	return cred, string(credJSON), nil
}

// supportsPerUserInboundCredential identifies protocols whose inbound model
// can isolate one account with a dedicated client credential. Package nodes
// outside this allowlist (notably WireGuard) remain visible in subscriptions,
// but must never enter the managed add-client/revoke/reconcile lifecycle.
func supportsPerUserInboundCredential(protocol string) bool {
	switch canonicalManagedProtocol(protocol) {
	case "vless", "vmess", "trojan", "anytls", "snell", "hysteria", "shadowsocks", "socks", "http":
		return true
	default:
		return false
	}
}

// filterCredentials 从凭据列表中移除匹配的凭据
func filterCredentials(items []interface{}, savedCred map[string]interface{}, protocol string) []interface{} {
	var result []interface{}
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			result = append(result, item)
			continue
		}
		if matchCredential(m, savedCred, protocol) {
			continue
		}
		result = append(result, item)
	}
	return result
}

func matchCredential(a, b map[string]interface{}, protocol string) bool {
	switch canonicalManagedProtocol(protocol) {
	case "vless", "vmess":
		return fmt.Sprint(a["id"]) == fmt.Sprint(b["id"])
	case "trojan", "anytls":
		return fmt.Sprint(a["password"]) == fmt.Sprint(b["password"])
	case "snell":
		return fmt.Sprint(a["psk"]) == fmt.Sprint(b["psk"])
	case "hysteria":
		return fmt.Sprint(a["auth"]) == fmt.Sprint(b["auth"])
	case "shadowsocks":
		return fmt.Sprint(a["password"]) == fmt.Sprint(b["password"])
	case "socks", "http":
		return fmt.Sprint(a["user"]) == fmt.Sprint(b["user"])
	}
	return false
}
