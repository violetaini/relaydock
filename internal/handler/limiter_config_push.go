package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/version"
)

type LimiterConfigPusher struct {
	repo              *storage.TrafficRepository
	wsHandler         *RemoteWSHandler
	httpClient        *http.Client
	capabilityManager *capabilities.Manager
	serverPushLocks   sync.Map
}

func NewLimiterConfigPusher(repo *storage.TrafficRepository, wsHandler *RemoteWSHandler) *LimiterConfigPusher {
	return &LimiterConfigPusher{
		repo:      repo,
		wsHandler: wsHandler,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (p *LimiterConfigPusher) SetCapabilityManager(manager *capabilities.Manager) {
	p.capabilityManager = manager
}

// resolveLimit 按 4 段优先级算用户在指定节点上的限速 + 客户端数:
//
//	user.NodeSpeedLimitOverrides[node_id]  ← 用户级 per-node(map 含 key 即生效)
//	  ?? user.SpeedLimitOverride           ← 用户级全局
//	  ?? pkg.NodeSpeedLimits[node_id]      ← 套餐级 per-node(含 routed→父 一次跳)
//	  ?? pkg.SpeedLimitMbps                ← 套餐通用
//	  ?? 0 (unlimited)
//
// 每一层用 "map 是否含 key" / "指针是否非 nil" 判断;**不能用 value > 0 判断**,
// 因为 0 是显式不限速的有意义值。客户端数同结构。
// nodeID = 0 时跳过 per-node 层,只用全局/通用层(常见于反查未命中)。
// connGroupKey 连接数计数分组键 = "<username>|<物理节点ID>"。同一用户在同一物理节点(含其路由出站
// 子账户)的所有 email 共用此 key → agent 侧共享一份并发连接配额(问题1:20 而非 20×N)。
func connGroupKey(username string, physicalNodeID int64) string {
	return fmt.Sprintf("%s|%d", username, physicalNodeID)
}

func wireGuardProbeLimiterEmail(resourceID int64, inboundTag string) string {
	return fmt.Sprintf("_arcway_wireguard_probe_%d__%s", resourceID, strings.TrimSpace(inboundTag))
}

const (
	// Limiter zero values mean unlimited. A user deletion tombstone therefore
	// needs explicit non-zero minima while an unreachable Agent still retains
	// the peer; the same rule applies to an over-limit package peer awaiting
	// removal. Otherwise revocation residue silently becomes unlimited.
	revocationResidualDenySpeedBytes      uint64 = 1
	revocationResidualDenyConnectionLimit        = 1
)

type managedLimiterKey struct {
	username   string
	inboundTag string
}

type managedLimiterLimit struct {
	nodeID          int64
	speedMbps       float64
	connectionLimit int
}

func resolveManagedLimiterLimit(user *storage.User, grant storage.UserServerGrant, selection storage.UserNodeSelection) (float64, int) {
	speed := grant.SpeedLimitMbps
	if selection.SpeedLimitOverrideMbps != nil {
		speed = *selection.SpeedLimitOverrideMbps
	} else if speed <= 0 && user != nil && user.SpeedLimitOverride != nil {
		speed = *user.SpeedLimitOverride
	}
	connections := grant.ConnectionLimit
	if selection.ConnectionLimitOverride != nil {
		connections = *selection.ConnectionLimitOverride
	} else if connections <= 0 && user != nil && user.DeviceLimitOverride != nil {
		connections = *user.DeviceLimitOverride
	}
	return speed, connections
}

// mergeManagedLimiterLimit is defensive for duplicate offers that point at the
// same physical inbound. The Agent can only identify the shared client by
// email, so the most restrictive positive limit wins.
func mergeManagedLimiterLimit(current, next managedLimiterLimit) managedLimiterLimit {
	if current.nodeID == 0 || next.nodeID > 0 && next.nodeID < current.nodeID {
		current.nodeID = next.nodeID
	}
	if current.speedMbps <= 0 || next.speedMbps > 0 && next.speedMbps < current.speedMbps {
		current.speedMbps = next.speedMbps
	}
	if current.connectionLimit <= 0 || next.connectionLimit > 0 && next.connectionLimit < current.connectionLimit {
		current.connectionLimit = next.connectionLimit
	}
	return current
}

func strictestPositiveFloat(current, next float64) float64 {
	if current <= 0 {
		return next
	}
	if next <= 0 || current < next {
		return current
	}
	return next
}

func strictestPositiveInt(current, next int) int {
	if current <= 0 {
		return next
	}
	if next <= 0 || current < next {
		return current
	}
	return next
}

// buildManagedLimiterLimits returns desired-active selection limits whose
// grant is currently effective. Observed state is deliberately not required:
// the rule must be installable before the remote client is added.
func (p *LimiterConfigPusher) buildManagedLimiterLimits(ctx context.Context, serverID int64, now time.Time) (map[managedLimiterKey]managedLimiterLimit, error) {
	grants, err := p.repo.ListAllUserServerGrants(ctx)
	if err != nil {
		return nil, err
	}
	limits := make(map[managedLimiterKey]managedLimiterLimit)
	for _, grant := range grants {
		if grant.ServerID != serverID {
			continue
		}
		user, err := p.repo.GetUser(ctx, grant.Username)
		if err != nil {
			return nil, err
		}
		_, _, billed, err := p.repo.GetUserServerGrantUsage(ctx, grant.ID)
		if err != nil {
			return nil, err
		}
		if grant.StateAt(now, user.IsActive, billed) != storage.ManagedGrantActive {
			continue
		}
		selections, err := p.repo.ListUserNodeSelections(ctx, grant.Username, true)
		if err != nil {
			return nil, err
		}
		for _, selection := range selections {
			if selection.GrantID != grant.ID || selection.AccessSourceID == nil {
				continue
			}
			source, err := p.repo.GetUserInboundAccessSource(ctx, *selection.AccessSourceID)
			if err != nil {
				return nil, err
			}
			if source.SourceType != storage.ManagedSourceSelection || source.SourceID != selection.ID ||
				source.ServerID != serverID || source.DesiredState != storage.ManagedDesiredActive ||
				source.SuspendReason != storage.ManagedSuspendNone || now.Before(source.StartsAt) ||
				source.ExpiresAt != nil && !now.Before(*source.ExpiresAt) {
				continue
			}
			speed, connections := resolveManagedLimiterLimit(&user, grant, selection)
			key := managedLimiterKey{username: grant.Username, inboundTag: source.InboundTag}
			next := managedLimiterLimit{nodeID: source.NodeID, speedMbps: speed, connectionLimit: connections}
			if current, ok := limits[key]; ok {
				limits[key] = mergeManagedLimiterLimit(current, next)
			} else {
				limits[key] = next
			}
		}
	}
	return limits, nil
}

func resolveLimit(user *storage.User, pkg *storage.Package, nodeID, parentID int64) (speedMbps float64, deviceLimit int) {
	// 限速
	switch {
	case user != nil && nodeID > 0:
		if v, ok := user.NodeSpeedLimitOverrides[nodeID]; ok {
			speedMbps = v
			break
		}
		if parentID > 0 {
			if v, ok := user.NodeSpeedLimitOverrides[parentID]; ok {
				speedMbps = v
				break
			}
		}
		if user.SpeedLimitOverride != nil {
			speedMbps = *user.SpeedLimitOverride
			break
		}
		if pkg != nil {
			if v, ok := pkg.SpeedLimitMbpsForNode(nodeID, &parentID); ok {
				speedMbps = v
				break
			}
			speedMbps = pkg.SpeedLimitMbps
		}
	case user != nil:
		if user.SpeedLimitOverride != nil {
			speedMbps = *user.SpeedLimitOverride
		} else if pkg != nil {
			speedMbps = pkg.SpeedLimitMbps
		}
	}

	// 客户端数
	switch {
	case user != nil && nodeID > 0:
		if v, ok := user.NodeDeviceLimitOverrides[nodeID]; ok {
			deviceLimit = v
			break
		}
		if parentID > 0 {
			if v, ok := user.NodeDeviceLimitOverrides[parentID]; ok {
				deviceLimit = v
				break
			}
		}
		if user.DeviceLimitOverride != nil {
			deviceLimit = *user.DeviceLimitOverride
			break
		}
		if pkg != nil {
			if v, ok := pkg.DeviceLimitForNode(nodeID, &parentID); ok {
				deviceLimit = v
				break
			}
			deviceLimit = pkg.DeviceLimit
		}
	case user != nil:
		if user.DeviceLimitOverride != nil {
			deviceLimit = *user.DeviceLimitOverride
		} else if pkg != nil {
			deviceLimit = pkg.DeviceLimit
		}
	}

	return
}

func (p *LimiterConfigPusher) BuildLimiterConfigForServer(ctx context.Context, serverID int64) ([]WSLimiterConfigPayload, error) {
	now := time.Now().UTC()
	configs, err := p.repo.GetUserInboundConfigsByServer(ctx, serverID)
	if err != nil {
		return nil, err
	}

	// 查 server name,用于反查子账号(子账号通过 routed_node 的 original_server 关联)
	var serverName string
	if servers, err := p.repo.ListRemoteServers(ctx); err == nil {
		for _, s := range servers {
			if s.ID == serverID {
				serverName = s.Name
				break
			}
		}
	}

	// routed 节点的 active 子账号:也要为它们下发限速规则,key 是子账号 email
	var subaccs []storage.ActiveSubaccountForLimiter
	if serverName != "" {
		subaccs, _ = p.repo.ListActiveSubaccountsByServerName(ctx, serverName)
	}

	// 预加载 inbound_tag → node(主账号走 physical,routed 子账号走 routed)
	// 同 tag 上可能同时有 physical + routed,所以用两张 map 分流。
	physicalByTag := make(map[string]storage.InboundNodeRef)
	routedByTag := make(map[string]storage.InboundNodeRef)
	allInboundTags := make(map[string]struct{})
	nodeRefsLoaded := false
	if serverName != "" {
		if refs, err := p.repo.ListInboundNodeRefsForServer(ctx, serverName); err == nil {
			nodeRefsLoaded = true
			for _, r := range refs {
				tag := strings.TrimSpace(r.InboundTag)
				if tag == "" {
					continue
				}
				allInboundTags[tag] = struct{}{}
				if r.NodeType == "routed" {
					routedByTag[tag] = r
				} else {
					physicalByTag[tag] = r
				}
			}
		}
	}

	usernames := make(map[string]bool)
	for _, c := range configs {
		usernames[c.Username] = true
	}
	for _, sa := range subaccs {
		usernames[sa.Username] = true
	}

	// 缓存 user 对象(指针)和套餐(指针);**不预算限速值** — 现在同一用户在不同 inbound 上限速可能不同,
	// 推迟到内层按 (user, pkg, node_id) lookup。
	userMap := make(map[string]*storage.User)
	pendingDeletionUsers := make(map[string]bool)
	pendingDisableUsers := make(map[string]bool)
	overLimitUsers := make(map[string]bool)
	pkgCache := make(map[int64]*storage.Package)

	for username := range usernames {
		user, err := p.repo.GetUser(ctx, username)
		if err != nil {
			continue
		}
		deletionPending, pendingErr := p.repo.IsUserDeletionPending(ctx, username)
		if pendingErr != nil {
			return nil, pendingErr
		}
		disablePending, pendingErr := p.repo.IsUserDisablePending(ctx, username)
		if pendingErr != nil {
			return nil, pendingErr
		}
		overLimit, pendingErr := p.repo.IsUserOverLimit(ctx, username)
		if pendingErr != nil {
			return nil, pendingErr
		}
		u := user // 避免循环变量 alias
		userMap[username] = &u
		pendingDeletionUsers[username] = deletionPending
		pendingDisableUsers[username] = disablePending
		overLimitUsers[username] = overLimit
		if user.PackageID > 0 {
			if _, ok := pkgCache[user.PackageID]; !ok {
				if pkg, err := p.repo.GetPackage(ctx, user.PackageID); err == nil {
					pkgCache[user.PackageID] = pkg
				}
			}
		}
	}
	managedLimits, err := p.buildManagedLimiterLimits(ctx, serverID, now)
	if err != nil {
		return nil, fmt.Errorf("build managed limiter limits: %w", err)
	}
	pendingRevocationResiduals := make(map[managedLimiterKey]bool)
	type managedSourceState struct {
		present                bool
		peerRemovalUnconfirmed bool
	}
	managedSourceStates := make(map[managedLimiterKey]managedSourceState)
	for username := range userMap {
		sources, sourceErr := p.repo.ListUserInboundAccessSources(ctx, username, serverID)
		if sourceErr != nil {
			return nil, fmt.Errorf("list pending managed revocations for %s: %w", username, sourceErr)
		}
		for _, source := range sources {
			key := managedLimiterKey{username: username, inboundTag: source.InboundTag}
			state := managedSourceStates[key]
			state.present = true
			if source.DesiredState == storage.ManagedDesiredActive ||
				source.ObservedState != storage.ManagedObservedInactive {
				// Unknown includes the crash window after Agent peer creation but
				// before the source generation is acknowledged in storage.
				state.peerRemovalUnconfirmed = true
			}
			managedSourceStates[key] = state
			if source.DesiredState != storage.ManagedDesiredActive &&
				source.ObservedState != storage.ManagedObservedInactive {
				pendingRevocationResiduals[key] = true
			}
		}
	}

	tagUsers := make(map[string][]WSUserLimitInfo)
	tagWireGuardPeers := make(map[string]map[string]string)
	tagPkgIDs := make(map[string]map[int64]bool)
	// Empty snapshots are intentional. They clear stale per-user limits that may
	// remain on an Agent after the last user is removed from an inbound.
	for tag := range allInboundTags {
		tagUsers[tag] = []WSUserLimitInfo{}
		tagWireGuardPeers[tag] = make(map[string]string)
	}

	// Panel-managed WireGuard probes use a dedicated database identity rather
	// than an anonymous bootstrap peer. Publish that identity through the same
	// full-replace mapping as ordinary users so an Agent may reject every
	// otherwise unknown tunnel source without disabling Mihomo validation.
	resources, err := p.repo.ListManagedInboundResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("list panel-managed WireGuard resources: %w", err)
	}
	for index := range resources {
		resource := &resources[index]
		if resource.ServerID != serverID || canonicalManagedProtocol(resource.Protocol) != "wireguard" {
			continue
		}
		tag := strings.TrimSpace(resource.InboundTag)
		if tag == "" {
			return nil, fmt.Errorf("panel-managed WireGuard resource %d has no inbound tag", resource.ID)
		}
		desired, err := p.repo.GetDesiredInbound(ctx, resource.ServerID, tag)
		if err != nil {
			return nil, fmt.Errorf("load panel-managed WireGuard desired inbound %s: %w", tag, err)
		}
		_, hasNodeBinding := allInboundTags[tag]
		if nodeRefsLoaded && !hasNodeBinding &&
			(desired == nil || desired.DesiredState != storage.DesiredInboundStateActive) {
			// Inventory reconciliation can leave a historical resource row after
			// both of its actual authorities have disappeared. It must not block
			// unrelated limiter snapshots or manufacture a new probe identity.
			continue
		}
		probePeer, err := ensureAuthoritativeManagedWireGuardProbePeer(ctx, p.repo, resource, nil)
		if err != nil {
			return nil, fmt.Errorf("prepare panel-managed WireGuard probe peer %s: %w", tag, err)
		}
		email := wireGuardProbeLimiterEmail(resource.ID, tag)
		if tagWireGuardPeers[tag] == nil {
			tagWireGuardPeers[tag] = make(map[string]string)
		}
		tagUsers[tag] = append(tagUsers[tag], WSUserLimitInfo{
			Email: email, ConnGroup: fmt.Sprintf("wireguard-probe|%d", resource.ID),
		})
		for _, address := range probePeer.Addresses {
			address = strings.TrimSpace(address)
			if existing, ok := tagWireGuardPeers[tag][address]; ok && existing != email {
				return nil, fmt.Errorf("WireGuard probe address %s is assigned to both %s and %s on inbound %s", address, existing, email, tag)
			}
			tagWireGuardPeers[tag][address] = email
		}
	}

	// 主账号:走 c.InboundTag,反查 physical 节点的 (nodeID, parentID)
	for _, c := range configs {
		user, ok := userMap[c.Username]
		if !ok {
			continue
		}
		hasManagedAccess, _, err := p.repo.HasEffectiveUserInboundAccess(ctx, c.Username, serverID, c.InboundTag, 0, now)
		if err != nil {
			return nil, fmt.Errorf("resolve managed limiter access for %s/%s: %w", c.Username, c.InboundTag, err)
		}
		hasDirectAccess, _, err := p.repo.HasEffectiveDirectUserInboundAccess(ctx, c.Username, serverID, c.InboundTag, 0, now)
		if err != nil {
			return nil, fmt.Errorf("resolve direct limiter access for %s/%s: %w", c.Username, c.InboundTag, err)
		}
		hasPackageAccess, _, err := hasLegacyPackageInboundAccessProtocol(ctx, p.repo, c.Username, serverID, c.InboundTag, c.Protocol, now)
		if err != nil {
			return nil, fmt.Errorf("resolve package limiter access for %s/%s: %w", c.Username, c.InboundTag, err)
		}
		hasOverLimitPackageResidual := false
		if !hasManagedAccess && !hasDirectAccess && !hasPackageAccess && user.IsActive {
			overLimit, overLimitErr := p.repo.IsUserOverLimit(ctx, c.Username)
			if overLimitErr != nil {
				return nil, fmt.Errorf("resolve over-limit state for %s/%s: %w", c.Username, c.InboundTag, overLimitErr)
			}
			if overLimit {
				hasOverLimitPackageResidual, _, err = hasLegacyPackageInboundAccessIgnoringOverLimit(ctx, p.repo, c.Username, serverID, c.InboundTag, now)
				if err != nil {
					return nil, fmt.Errorf("resolve over-limit package limiter access for %s/%s: %w", c.Username, c.InboundTag, err)
				}
			}
		}
		hasDeletionResidual := pendingDeletionUsers[c.Username]
		hasDisableResidual := pendingDisableUsers[c.Username]
		managedKey := managedLimiterKey{username: c.Username, inboundTag: c.InboundTag}
		hasManagedRevocationResidual := pendingRevocationResiduals[managedKey]
		// A canonical WireGuard credential can outlive a legacy package template
		// update or provenance failure until remote peer removal is acknowledged.
		// Keeping its address mapped to a strict residual is not authorization; it
		// makes every such cleanup window fail closed and retryable.
		managedState := managedSourceStates[managedKey]
		// A legacy package can reuse the canonical credential after a managed
		// source has converged inactive. Its package assignment remains the
		// durable provenance until stale credential cleanup removes the peer.
		hasLegacyPackageCredentialProvenance := user.AuthorizationMode == storage.AuthorizationModePackage &&
			user.PackageID > 0
		hasWireGuardCredentialResidual := user.IsActive &&
			strings.EqualFold(strings.TrimSpace(c.Protocol), "wireguard") &&
			!hasManagedAccess && !hasDirectAccess && !hasPackageAccess &&
			(!managedState.present || managedState.peerRemovalUnconfirmed || hasLegacyPackageCredentialProvenance)
		if !hasManagedAccess && !hasDirectAccess && !hasPackageAccess &&
			!hasOverLimitPackageResidual && !hasDeletionResidual && !hasDisableResidual && !hasManagedRevocationResidual &&
			!hasWireGuardCredentialResidual {
			continue
		}
		var pkg *storage.Package
		if user.PackageID > 0 {
			pkg = pkgCache[user.PackageID]
		}
		ref := physicalByTag[c.InboundTag] // 不存在时 NodeID=0,resolveLimit 容错
		speedMbps, deviceLimit := float64(0), 0
		physicalNodeID := ref.NodeID
		managedLimit, hasManagedLimit := managedLimits[managedLimiterKey{username: c.Username, inboundTag: c.InboundTag}]
		if hasManagedAccess && hasManagedLimit {
			speedMbps, deviceLimit = managedLimit.speedMbps, managedLimit.connectionLimit
			physicalNodeID = managedLimit.nodeID
			if hasPackageAccess {
				packageSpeed, packageDevices := resolveLimit(user, pkg, ref.NodeID, ref.ParentID)
				speedMbps = strictestPositiveFloat(speedMbps, packageSpeed)
				deviceLimit = strictestPositiveInt(deviceLimit, packageDevices)
			}
		} else if hasPackageAccess || hasDirectAccess {
			speedMbps, deviceLimit = resolveLimit(user, pkg, ref.NodeID, ref.ParentID)
		} else if !hasDeletionResidual && !hasDisableResidual && !hasOverLimitPackageResidual && !hasManagedRevocationResidual &&
			!hasWireGuardCredentialResidual {
			// A desired source can briefly outlive its grant state until the
			// reconciler versions it inactive. It must not fall through to an
			// unlimited legacy rule during that window.
			continue
		}
		var speedBytes uint64
		if speedMbps > 0 {
			speedBytes = uint64(speedMbps * 1000000 / 8)
		}
		if hasDeletionResidual || hasDisableResidual || hasOverLimitPackageResidual || hasManagedRevocationResidual ||
			hasWireGuardCredentialResidual {
			speedBytes = revocationResidualDenySpeedBytes
			deviceLimit = revocationResidualDenyConnectionLimit
		}
		limitEmail := user.Username + "__" + c.InboundTag
		tagUsers[c.InboundTag] = append(tagUsers[c.InboundTag], WSUserLimitInfo{
			// email 必须与 generateCredential 写进 xray inbound 的 client email 一致 —— 强制 <username>__<inboundTag>
			// (自动子账户格式)。此前这里用纯 username,导致限速器按 username 记账、xray 流量走子账户 email,
			// agent GetUserBucket 用连接 email 查不到限速记录 → 套餐/固定限速对自动子账户全部失效。
			Email:      limitEmail,
			SpeedLimit: speedBytes,
			// 物理节点自身即 group 的物理节点(ref.NodeID);其路由出站子账户在下面用 ParentID 归到同一 group。
			DeviceLimit: deviceLimit,
			Denied:      hasDeletionResidual || hasDisableResidual || hasOverLimitPackageResidual || hasManagedRevocationResidual || hasWireGuardCredentialResidual,
			ConnGroup:   connGroupKey(user.Username, physicalNodeID),
		})
		if strings.EqualFold(strings.TrimSpace(c.Protocol), "wireguard") {
			addresses, err := wireGuardLimiterAddresses(c.CredentialJSON)
			if err != nil {
				return nil, fmt.Errorf("resolve WireGuard limiter identity for %s/%s: %w", c.Username, c.InboundTag, err)
			}
			if tagWireGuardPeers[c.InboundTag] == nil {
				tagWireGuardPeers[c.InboundTag] = make(map[string]string)
			}
			for _, address := range addresses {
				if existing, ok := tagWireGuardPeers[c.InboundTag][address]; ok && existing != limitEmail {
					return nil, fmt.Errorf("WireGuard tunnel address %s is assigned to both %s and %s on inbound %s", address, existing, limitEmail, c.InboundTag)
				}
				tagWireGuardPeers[c.InboundTag][address] = limitEmail
			}
		}
		if hasPackageAccess && !(hasManagedAccess && hasManagedLimit) && user.PackageID > 0 {
			if tagPkgIDs[c.InboundTag] == nil {
				tagPkgIDs[c.InboundTag] = make(map[int64]bool)
			}
			tagPkgIDs[c.InboundTag][user.PackageID] = true
		}
	}

	// 子账号:走 sa.InboundTag,反查 routed 节点的 (nodeID, parentID)。
	// routed 节点的 per-node 限速继承 parent 物理节点(在 resolveLimit 内自动处理)。
	for _, sa := range subaccs {
		user, ok := userMap[sa.Username]
		if !ok {
			continue
		}
		var pkg *storage.Package
		if user.PackageID > 0 {
			pkg = pkgCache[user.PackageID]
		}
		ref := routedByTag[sa.InboundTag]
		speedMbps, deviceLimit := resolveLimit(user, pkg, ref.NodeID, ref.ParentID)
		var speedBytes uint64
		if speedMbps > 0 {
			speedBytes = uint64(speedMbps * 1000000 / 8)
		}
		// A routed client that is being revoked (or belongs to a disabled/deleting
		// account) must remain explicitly denied until the remote rule and client
		// removal are acknowledged. The row is intentionally still returned by
		// the repository while revoke_pending=1 so a checked snapshot can replace
		// the prior normal bucket instead of silently dropping it.
		subaccountDenied := !user.IsActive || overLimitUsers[sa.Username] || sa.RevokePending ||
			pendingDisableUsers[sa.Username] || pendingDeletionUsers[sa.Username]
		if subaccountDenied {
			speedBytes = revocationResidualDenySpeedBytes
			deviceLimit = revocationResidualDenyConnectionLimit
		}
		// 路由出站的 group 归到**父物理节点**(ref.ParentID),从而与父节点及其它路由出站共享连接配额。
		physID := ref.ParentID
		if physID == 0 {
			physID = ref.NodeID // 兜底:父未知时按自身,避免 group="user|0" 把不同节点误并
		}
		tagUsers[sa.InboundTag] = append(tagUsers[sa.InboundTag], WSUserLimitInfo{
			Email:       sa.Email,
			SpeedLimit:  speedBytes,
			DeviceLimit: deviceLimit,
			Denied:      subaccountDenied,
			ConnGroup:   connGroupKey(user.Username, physID),
		})
		if user.PackageID > 0 {
			if tagPkgIDs[sa.InboundTag] == nil {
				tagPkgIDs[sa.InboundTag] = make(map[int64]bool)
			}
			tagPkgIDs[sa.InboundTag][user.PackageID] = true
		}
	}

	tags := make([]string, 0, len(tagUsers))
	for tag := range tagUsers {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	payloads := make([]WSLimiterConfigPayload, 0, len(tags))
	for _, tag := range tags {
		users := tagUsers[tag]
		if users == nil {
			users = []WSUserLimitInfo{}
		}
		var rules []storage.AutoSpeedLimitRule
		for pkgID := range tagPkgIDs[tag] {
			if pkg, ok := pkgCache[pkgID]; ok && len(pkg.AutoSpeedRules) > 0 {
				rules = append(rules, pkg.AutoSpeedRules...)
			}
		}
		peerAddresses := make([]string, 0, len(tagWireGuardPeers[tag]))
		for address := range tagWireGuardPeers[tag] {
			peerAddresses = append(peerAddresses, address)
		}
		sort.Strings(peerAddresses)
		peers := make([]WSWireGuardPeerIdentity, 0, len(peerAddresses))
		for _, address := range peerAddresses {
			peers = append(peers, WSWireGuardPeerIdentity{Address: address, Email: tagWireGuardPeers[tag][address]})
		}
		payloads = append(payloads, WSLimiterConfigPayload{
			InboundTag:     tag,
			Users:          users,
			WireGuardPeers: peers,
			AutoSpeedRules: rules,
		})
	}

	return payloads, nil
}

func hasLegacyPackageInboundAccessIgnoringOverLimit(ctx context.Context, repo *storage.TrafficRepository, username string, serverID int64, inboundTag string, now time.Time) (bool, *time.Time, error) {
	return hasLegacyPackageInboundAccessIgnoringOverLimitProtocol(ctx, repo, username, serverID, inboundTag, "", now)
}

func hasLegacyPackageInboundAccessIgnoringOverLimitProtocol(ctx context.Context, repo *storage.TrafficRepository, username string, serverID int64, inboundTag, protocol string, now time.Time) (bool, *time.Time, error) {
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
			node.OriginalServer == server.Name && node.InboundTag == inboundTag &&
			(strings.TrimSpace(protocol) == "" || canonicalManagedProtocol(node.Protocol) == canonicalManagedProtocol(protocol)) {
			if canonicalManagedProtocol(node.Protocol) == "wireguard" {
				provisionable, provenanceErr := repo.ManagedWireGuardNodeAuthorityProvisionable(ctx, node.ID)
				if provenanceErr != nil {
					return false, nil, provenanceErr
				}
				if !provisionable {
					continue
				}
			}
			if user.PackageEndDate == nil {
				return true, nil, nil
			}
			expires := user.PackageEndDate.UTC()
			return true, &expires, nil
		}
	}
	return false, nil, nil
}

func wireGuardLimiterAddresses(credentialJSON string) ([]string, error) {
	var credential struct {
		Address []string `json:"address"`
	}
	if err := json.Unmarshal([]byte(credentialJSON), &credential); err != nil {
		return nil, fmt.Errorf("parse credential: %w", err)
	}
	if len(credential.Address) == 0 {
		return nil, errors.New("credential has no tunnel address")
	}
	addresses := make([]string, 0, len(credential.Address))
	seen := make(map[string]struct{}, len(credential.Address))
	for _, raw := range credential.Address {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
			return nil, fmt.Errorf("credential contains invalid host address %q", raw)
		}
		address := prefix.Addr().String() + fmt.Sprintf("/%d", prefix.Bits())
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	return addresses, nil
}

// ensureEmptyLimiterSnapshots adds an explicit empty user list for every
// inbound reported by the Agent. Existing payloads win, so active limits are
// never overwritten while stale Agent-only entries are still cleared.
func ensureEmptyLimiterSnapshots(configs []WSLimiterConfigPayload, inboundTags []string) []WSLimiterConfigPayload {
	byTag := make(map[string]WSLimiterConfigPayload, len(configs)+len(inboundTags))
	for _, cfg := range configs {
		tag := strings.TrimSpace(cfg.InboundTag)
		if tag == "" {
			continue
		}
		cfg.InboundTag = tag
		if cfg.Users == nil {
			cfg.Users = []WSUserLimitInfo{}
		}
		if cfg.WireGuardPeers == nil {
			cfg.WireGuardPeers = []WSWireGuardPeerIdentity{}
		}
		byTag[tag] = cfg
	}
	for _, rawTag := range inboundTags {
		tag := strings.TrimSpace(rawTag)
		if tag == "" {
			continue
		}
		if _, ok := byTag[tag]; !ok {
			byTag[tag] = WSLimiterConfigPayload{InboundTag: tag, Users: []WSUserLimitInfo{}, WireGuardPeers: []WSWireGuardPeerIdentity{}}
		}
	}
	tags := make([]string, 0, len(byTag))
	for tag := range byTag {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	out := make([]WSLimiterConfigPayload, 0, len(tags))
	for _, tag := range tags {
		out = append(out, byTag[tag])
	}
	return out
}

func decodeInboundTags(body []byte) []string {
	var response struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(body, &response); err != nil || !response.Success {
		return nil
	}
	tags := make([]string, 0, len(response.Inbounds))
	for _, inbound := range response.Inbounds {
		if tag, _ := inbound["tag"].(string); strings.TrimSpace(tag) != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

// listServerInboundTags asks the Agent for its current inbound set. WS RPC is
// preferred for push-only servers; HTTP remains the compatibility fallback.
func (p *LimiterConfigPusher) listServerInboundTags(ctx context.Context, server *storage.RemoteServer) []string {
	if p.wsHandler != nil {
		if _, body, err := p.wsHandler.CallAgent(ctx, server.ID, http.MethodGet, "/api/child/inbounds", "", nil, 12*time.Second); err == nil {
			return decodeInboundTags(body)
		}
	}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+server.Token)
	hdr.Set("User-Agent", version.AgentUserAgent)
	resp, err := tryHTTPWithFallback(ctx, p.httpClient, server, http.MethodGet, "/api/child/inbounds", nil, hdr)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}
	return decodeInboundTags(body)
}

func (p *LimiterConfigPusher) PushToServer(ctx context.Context, serverID int64) {
	if p == nil || p.repo == nil {
		log.Printf("[LimiterPush] Failed to push config for server %d: limiter pusher is not available", serverID)
		return
	}
	err := p.repo.WithRemoteServerMutationLease(ctx, serverID, func(leasedCtx context.Context) error {
		p.pushToServerLeased(leasedCtx, serverID)
		return nil
	})
	if err != nil {
		log.Printf("[LimiterPush] Failed to push config for server %d: %v", serverID, err)
	}
}

func (p *LimiterConfigPusher) pushToServerLeased(ctx context.Context, serverID int64) {
	_ = p.withServerPushLock(serverID, func() error {
		p.pushToServerLeasedUnlocked(ctx, serverID)
		return nil
	})
}

func (p *LimiterConfigPusher) pushToServerLeasedUnlocked(ctx context.Context, serverID int64) {
	server, configs, err := p.buildServerLimiterSnapshots(ctx, serverID)
	if err != nil {
		log.Printf("[LimiterPush] Failed to push config for server %d: %v", serverID, err)
		return
	}

	// Legacy package refreshes remain best-effort and retain the published
	// one-way WS protocol. Managed provisioning uses PushToServerChecked below.
	if p.wsHandler != nil {
		if _, ok := p.wsHandler.GetConnectionByServerID(serverID); ok {
			if err := p.wsHandler.SendLimiterConfig(serverID, configs); err == nil {
				return
			} else {
				log.Printf("[LimiterPush] WebSocket send failed for server %d (%v), falling back to HTTP", serverID, err)
			}
		}
	}
	if err := p.pushViaHTTP(ctx, server, configs); err != nil {
		log.Printf("[LimiterPush] Failed to push config for server %d: %v", serverID, err)
	}
}

// withServerPushLock serializes the snapshot read with its complete delivery.
// Remote mutation leases are intentionally shared, so they cannot prevent an
// older limiter snapshot from being acknowledged after a newer one.
func (p *LimiterConfigPusher) withServerPushLock(serverID int64, fn func() error) error {
	lockValue, _ := p.serverPushLocks.LoadOrStore(serverID, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	return fn()
}

func (p *LimiterConfigPusher) buildServerLimiterSnapshots(ctx context.Context, serverID int64) (*storage.RemoteServer, []WSLimiterConfigPayload, error) {
	if p == nil || p.repo == nil {
		return nil, nil, fmt.Errorf("limiter pusher is not available")
	}
	server, err := p.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return nil, nil, err
	}
	if server.XrayMode != "embedded" {
		return nil, nil, fmt.Errorf("server %d is not using embedded Xray", serverID)
	}

	if p.capabilityManager != nil {
		if !p.capabilityManager.HasFeature(capabilities.FeatureLimiter) || !p.capabilityManager.HasFeature(capabilities.FeatureEmbeddedXray) {
			return nil, nil, fmt.Errorf("limiter capability is unavailable")
		}
	}

	configs, err := p.BuildLimiterConfigForServer(ctx, serverID)
	if err != nil {
		return nil, nil, err
	}
	configs = ensureEmptyLimiterSnapshots(configs, p.listServerInboundTags(ctx, server))
	if len(configs) == 0 {
		return nil, nil, fmt.Errorf("server %d has no limiter snapshot", serverID)
	}
	return server, configs, nil
}

// PushToServerChecked returns only after every full-replace limiter snapshot
// has received an application ACK. A successful WebSocket write is not an ACK.
// Managed provisioning uses this as the final gate before add-client.
func (p *LimiterConfigPusher) PushToServerChecked(ctx context.Context, serverID int64) error {
	if p == nil || p.repo == nil {
		return fmt.Errorf("limiter pusher is not available")
	}
	return p.repo.WithRemoteServerMutationLease(ctx, serverID, func(leasedCtx context.Context) error {
		return p.pushToServerCheckedLeased(leasedCtx, serverID)
	})
}

func (p *LimiterConfigPusher) pushToServerCheckedLeased(ctx context.Context, serverID int64) error {
	return p.withServerPushLock(serverID, func() error {
		return p.pushToServerCheckedLeasedUnlocked(ctx, serverID)
	})
}

func (p *LimiterConfigPusher) pushToServerCheckedLeasedUnlocked(ctx context.Context, serverID int64) error {
	server, configs, err := p.buildServerLimiterSnapshots(ctx, serverID)
	if err != nil {
		return err
	}

	// Prefer WS RPC because the reply is produced after the Agent's HTTP handler
	// returns. If the transport disappears, replay the full snapshots over HTTP.
	if p.wsHandler != nil {
		if connection, ok := p.wsHandler.GetConnectionByServerID(serverID); ok && connection.Capabilities.RPC {
			if limiterSnapshotsContainDenied(configs) && !connection.Capabilities.LimiterDeniedV1 {
				return errors.New("Agent lacks limiter_denied_v1 capability; upgrade and reconnect relaydock-agent")
			}
			for _, cfg := range configs {
				body, marshalErr := json.Marshal(cfg)
				if marshalErr != nil {
					return marshalErr
				}
				status, ackBody, callErr := p.wsHandler.CallAgent(ctx, serverID, http.MethodPost,
					"/api/child/limiter", "", body, 15*time.Second)
				if callErr != nil {
					if errors.Is(callErr, ErrWSRPCUnavailable) {
						log.Printf("[LimiterPush] ACK RPC unavailable for server %d (%v), replaying via HTTP", serverID, callErr)
						return p.pushViaHTTPChecked(ctx, server, configs)
					}
					return fmt.Errorf("limiter replace RPC failed: %w", callErr)
				}
				if status != http.StatusOK {
					return fmt.Errorf("limiter replace RPC returned status %d", status)
				}
				if err := validateLimiterReplaceACK(ackBody); err != nil {
					return err
				}
			}
			return nil
		}
	}

	return p.pushViaHTTPChecked(ctx, server, configs)
}

func validateLimiterReplaceACK(body []byte) error {
	var ack struct {
		Success        bool   `json:"success"`
		Warning        string `json:"warning"`
		RuntimeWarning string `json:"runtime_warning"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return fmt.Errorf("invalid limiter replace ACK: %w", err)
	}
	if !ack.Success {
		return fmt.Errorf("limiter replace was not acknowledged")
	}
	if warning := strings.TrimSpace(ack.Warning); warning != "" {
		return fmt.Errorf("limiter replace persistence warning: %s", warning)
	}
	if warning := strings.TrimSpace(ack.RuntimeWarning); warning != "" {
		return fmt.Errorf("limiter replace runtime warning: %s", warning)
	}
	return nil
}

func limiterSnapshotsContainDenied(configs []WSLimiterConfigPayload) bool {
	for _, config := range configs {
		for _, user := range config.Users {
			if user.Denied {
				return true
			}
		}
	}
	return false
}

// requireLimiterDeniedCapability prevents a legacy Agent from acknowledging a
// payload while silently ignoring denied=true. An active WS handshake is the
// authority for the running process; only an Agent without a WS connection is
// probed through system/info before an HTTP limiter delivery.
func (p *LimiterConfigPusher) requireLimiterDeniedCapability(ctx context.Context, server *storage.RemoteServer, configs []WSLimiterConfigPayload) error {
	if !limiterSnapshotsContainDenied(configs) {
		return nil
	}
	if p == nil {
		return errors.New("verify limiter_denied_v1 capability: limiter pusher is unavailable")
	}
	if server == nil {
		return errors.New("verify limiter_denied_v1 capability: remote server is unavailable")
	}
	if p.wsHandler != nil {
		if connection, connected := p.wsHandler.GetConnectionByServerID(server.ID); connected {
			if connection.Capabilities.LimiterDeniedV1 {
				return nil
			}
			return errors.New("Agent lacks limiter_denied_v1 capability; upgrade and reconnect relaydock-agent")
		}
	}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+server.Token)
	hdr.Set("User-Agent", version.AgentUserAgent)
	resp, err := tryHTTPWithFallback(ctx, p.httpClient, server, http.MethodGet, "/api/child/system/info", nil, hdr)
	if err != nil {
		return fmt.Errorf("verify limiter_denied_v1 capability: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read limiter_denied_v1 capability: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close limiter_denied_v1 capability response: %w", closeErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("verify limiter_denied_v1 capability returned HTTP %d", resp.StatusCode)
	}
	var info struct {
		Success      bool              `json:"success"`
		Capabilities AgentCapabilities `json:"capabilities"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return fmt.Errorf("decode Agent limiter_denied_v1 capability: %w", err)
	}
	if !info.Success || !info.Capabilities.LimiterDeniedV1 {
		return errors.New("Agent lacks limiter_denied_v1 capability; upgrade relaydock-agent")
	}
	return nil
}

func (p *LimiterConfigPusher) pushViaHTTP(ctx context.Context, server *storage.RemoteServer, configs []WSLimiterConfigPayload) error {
	if err := p.requireLimiterDeniedCapability(ctx, server, configs); err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Authorization", "Bearer "+server.Token)
	hdr.Set("User-Agent", version.AgentUserAgent)

	var firstErr error
	for _, cfg := range configs {
		body, err := json.Marshal(cfg)
		if err != nil {
			log.Printf("[LimiterPush] Failed to marshal config for server %s: %v", server.Name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// tryHTTPWithFallback 内部 v4-first → v6-fallback,消灭旧 strings.LastIndex IPv6 截断 bug
		resp, err := tryHTTPWithFallback(ctx, p.httpClient, server, http.MethodPost, "/api/child/limiter", body, hdr)
		if err != nil {
			log.Printf("[LimiterPush] HTTP push failed for server %s: %v", server.Name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[LimiterPush] HTTP push returned %d for server %s", resp.StatusCode, server.Name)
			if firstErr == nil {
				firstErr = fmt.Errorf("limiter push returned HTTP %d", resp.StatusCode)
			}
		}
	}
	return firstErr
}

func (p *LimiterConfigPusher) pushViaHTTPChecked(ctx context.Context, server *storage.RemoteServer, configs []WSLimiterConfigPayload) error {
	if err := p.requireLimiterDeniedCapability(ctx, server, configs); err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Authorization", "Bearer "+server.Token)
	hdr.Set("User-Agent", version.AgentUserAgent)

	for _, cfg := range configs {
		body, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		resp, err := tryHTTPWithFallback(ctx, p.httpClient, server, http.MethodPost, "/api/child/limiter", body, hdr)
		if err != nil {
			return fmt.Errorf("limiter replace HTTP request failed: %w", err)
		}
		ackBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read limiter replace ACK: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close limiter replace ACK: %w", closeErr)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("limiter replace returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(ackBody)))
		}
		if err := validateLimiterReplaceACK(ackBody); err != nil {
			return err
		}
	}
	return nil
}

func (p *LimiterConfigPusher) PushToAllServersForPackage(ctx context.Context, packageID int64) {
	if p.capabilityManager != nil && !p.capabilityManager.HasFeature(capabilities.FeatureLimiter) {
		return
	}
	users, err := p.repo.ListUsersWithPackage(ctx)
	if err != nil {
		return
	}

	serverIDs := make(map[int64]bool)
	for _, u := range users {
		if u.PackageID != packageID {
			continue
		}
		configs, err := p.repo.GetUserInboundConfigs(ctx, u.Username)
		if err != nil {
			continue
		}
		for _, c := range configs {
			serverIDs[c.ServerID] = true
		}
		// 同 PushToAllServersForUser:补上该用户 routed 子账号所在 server,避免 routed-only 用户漏推。
		if subIDs, err := p.repo.ListServerIDsForUserSubaccounts(ctx, u.Username); err == nil {
			for _, id := range subIDs {
				serverIDs[id] = true
			}
		}
	}

	for sid := range serverIDs {
		p.PushToServer(ctx, sid)
	}
}

func (p *LimiterConfigPusher) PushToAllServersForUser(ctx context.Context, username string) {
	if p.capabilityManager != nil && !p.capabilityManager.HasFeature(capabilities.FeatureLimiter) {
		return
	}
	configs, err := p.repo.GetUserInboundConfigs(ctx, username)
	if err != nil {
		return
	}

	serverIDs := make(map[int64]bool)
	for _, c := range configs {
		serverIDs[c.ServerID] = true
	}
	// 只有 routed 子账号、没有物理 inbound 的用户,上面查不到 server —— 补上子账号所在 server,
	// 否则这些用户在用户管理/套餐里设的限速对该 server 永不下发。
	if subIDs, err := p.repo.ListServerIDsForUserSubaccounts(ctx, username); err == nil {
		for _, id := range subIDs {
			serverIDs[id] = true
		}
	}

	for sid := range serverIDs {
		p.PushToServer(ctx, sid)
	}
}

// PushToAllEmbeddedServers 给所有 embedded 模式远程服务器重推限速配置。
func (p *LimiterConfigPusher) PushToAllEmbeddedServers(ctx context.Context) {
	if p.capabilityManager != nil && !p.capabilityManager.HasFeature(capabilities.FeatureLimiter) {
		return
	}
	servers, err := p.repo.ListRemoteServers(ctx)
	if err != nil {
		return
	}
	for _, s := range servers {
		if s.XrayMode == "embedded" {
			p.PushToServer(ctx, s.ID)
		}
	}
}
