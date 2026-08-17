package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type TrafficLimitEnforcer struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
	pusher       *LimiterConfigPusher
}

func NewTrafficLimitEnforcer(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, pusher *LimiterConfigPusher) *TrafficLimitEnforcer {
	return &TrafficLimitEnforcer{repo: repo, remoteManage: remoteManage, pusher: pusher}
}

func (e *TrafficLimitEnforcer) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	log.Printf("[TrafficLimitEnforcer] Starting with interval: %v", interval)
	e.CheckAll(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.CheckAll(ctx)
		}
	}
}

// shouldResetThisMonth 判断当前时刻是否应触发用户的本月流量重置。
//
// 规则:
//  1. 必须 user.IsReset=true,resetDay∈[1,31]
//  2. 当月的"有效重置日" = min(resetDay, 当月最后一天) — 处理 reset_day=31 但 2 月只有 28 天的边界
//  3. now.Day() >= 有效重置日 才进入触发窗口
//  4. lastResetAt 为 nil(从未重置过)或不在本月 → 应该重置;否则跳过(避免同月反复)
//
// 注:用 now 的本地时区(time.Now() 默认)。生产环境 server 时区需配为本地时区,否则用户感知的"7号"会偏移。
func shouldResetThisMonth(now time.Time, isReset bool, resetDay int, lastResetAt *time.Time) bool {
	if !isReset || resetDay <= 0 || resetDay > 31 {
		return false
	}
	// 当月最后一天 = 下月第 0 天
	lastDayOfMonth := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, now.Location()).Day()
	effectiveDay := resetDay
	if effectiveDay > lastDayOfMonth {
		effectiveDay = lastDayOfMonth
	}
	if now.Day() < effectiveDay {
		return false
	}
	if lastResetAt == nil {
		return true
	}
	// 同年同月 = 本月已经 reset 过,跳过
	return lastResetAt.Year() != now.Year() || lastResetAt.Month() != now.Month()
}

func (e *TrafficLimitEnforcer) CheckAll(ctx context.Context) {
	users, err := e.repo.ListUsersWithPackage(ctx)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to list users: %v", err)
		return
	}
	billableTraffic, err := e.repo.ListUserBillableTraffic(ctx)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to list billable traffic: %v", err)
		return
	}

	pkgCache := make(map[int64]*storage.Package)
	now := time.Now()

	for _, user := range users {
		// 套餐到期检查：到期后移除入站并清除套餐绑定
		if user.PackageEndDate != nil && now.After(*user.PackageEndDate) {
			expired := false
			expiredPackageID := int64(0)
			expiredAt := time.Time{}
			cleanupErr := withStableUserPackageAuthorizationLease(ctx, e.repo, user.Username, []int64{user.PackageID}, func(leasedCtx context.Context, latest storage.User) error {
				if latest.AuthorizationMode != storage.AuthorizationModePackage || latest.PackageID <= 0 ||
					latest.PackageEndDate == nil || now.Before(*latest.PackageEndDate) {
					return nil
				}
				expired = true
				expiredPackageID = latest.PackageID
				expiredAt = *latest.PackageEndDate
				// User-owned routed children are suspended before the package row is
				// cleared. A remote failure therefore leaves the expired assignment in
				// place as durable retry authority for the next enforcer pass.
				if err := suspendUserPrivateRouted(leasedCtx, e.remoteManage, e.repo, latest.Username); err != nil {
					return fmt.Errorf("suspend private routed access: %w", err)
				}
				if err := unbindUserPackageLocked(leasedCtx, e.repo, e.remoteManage, e.pusher, latest.Username, true); err != nil {
					return err
				}
				return nil
			})
			if cleanupErr != nil && !expired {
				log.Printf("[TrafficLimitEnforcer] User %s expiry state could not be revalidated: %v", user.Username, cleanupErr)
				continue
			}
			if !expired {
				continue
			}
			log.Printf("[TrafficLimitEnforcer] User %s package expired at %s, removing from inbounds and clearing package",
				user.Username, expiredAt.Format("2006-01-02"))
			if cleanupErr != nil {
				// Keep the expired package assignment as retry authority whenever a
				// remote revoke or child cleanup is incomplete.
				log.Printf("[TrafficLimitEnforcer] User %s expiry cleanup incomplete, retained for retry: %v", user.Username, cleanupErr)
				continue
			}
			// 套餐过期 tg 通知 — 用户的当前 package_id 在 RemovePackageFromUser 之前的快照里
			pkgName := ""
			if p, perr := e.repo.GetPackage(ctx, expiredPackageID); perr == nil && p != nil {
				pkgName = p.Name
			}
			SendPackageExpiredNotification(ctx, user.Username, pkgName)
			// 套餐过期跟 user delete 一样,需要通知所有 agent limiter 同步移除该用户
			// 否则 agent 内存里的 limiter UserInfo 还有这个用户,旧 IP 复用时仍能匹配 bucket。
			if e.pusher != nil {
				go e.pusher.PushToAllServersForUser(context.Background(), user.Username)
			}
			continue
		}

		pkg, ok := pkgCache[user.PackageID]
		if !ok {
			p, err := e.repo.GetPackage(ctx, user.PackageID)
			if err != nil {
				log.Printf("[TrafficLimitEnforcer] Failed to get package %d: %v", user.PackageID, err)
				continue
			}
			pkg = p
			pkgCache[user.PackageID] = pkg
		}

		// 自愈:is_reset=true 但 reset_day 非法(历史上 assign 接口不校验、套餐保存又会把它清成 0)。
		// 这类用户在 shouldResetThisMonth 第一道门就被静默挡掉,永远不会重置。补成当天(封顶 28,
		// 避开月末不存在的日期),与 TG 续期路径的兜底一致。写回 DB 后下一轮即合法,不会反复打日志。
		if user.IsReset && (user.ResetDay < 1 || user.ResetDay > 31) {
			day := now.Day()
			if day > 28 {
				day = 28
			}
			log.Printf("[TrafficLimitEnforcer] User %s has is_reset=true but invalid reset_day=%d, fixing to %d", user.Username, user.ResetDay, day)
			if err := e.repo.UpdateUserResetDay(ctx, user.Username, day); err != nil {
				log.Printf("[TrafficLimitEnforcer] Failed to fix reset_day for %s: %v", user.Username, err)
			} else {
				user.ResetDay = day
			}
		}

		// 每月流量周期自动重置 — 到 reset_day 当天 0 点之后(实际由 enforcer ticker 触发,粒度=interval)
		// 触发后立刻把当前周期 uplink/downlink 归 0 + cycle_start=now,并写 last_reset_at 防止同月反复。
		// 还原"超额"标志:重置后用户应该重新有流量配额,wasOverLimit → 立即恢复入站。
		if shouldResetThisMonth(now, user.IsReset, user.ResetDay, user.LastResetAt) {
			log.Printf("[TrafficLimitEnforcer] User %s monthly reset (day=%d, last=%v)", user.Username, user.ResetDay, user.LastResetAt)
			if err := e.repo.ResetUserTrafficCycleAt(ctx, user.Username, now); err != nil {
				log.Printf("[TrafficLimitEnforcer] Failed to reset user %s: %v", user.Username, err)
			} else {
				billableTraffic[user.Username] = 0
				// 复用现有"恢复入站"路径:如果用户之前因超额被踢,reset 后自动放回
				if wasOver, _ := e.repo.IsUserOverLimit(ctx, user.Username); wasOver {
					log.Printf("[TrafficLimitEnforcer] User %s back under limit after monthly reset, restoring inbounds", user.Username)
					if e.restoreOverLimitUserIfAllowed(ctx, user.Username, billableTraffic, pkgCache) {
						resumeUserPrivateRouted(ctx, e.remoteManage, e.repo, user.Username)
					}
				}
				// limiter 配置在 agent 端按 user_traffic 累计算,重置归零后下次 push 自然刷新
			}
		}

		// A present user override wins even when it is zero (explicit unlimited).
		// Keep this after the reset block so unlimited users still reset cycles.
		limitBytes := resolveTrafficLimitBytes(&user, pkg)
		if limitBytes <= 0 {
			// Switching an already-blocked user to explicit unlimited must restore
			// access; simply continuing would leave is_over_limit stuck forever.
			if wasOverLimit, _ := e.repo.IsUserOverLimit(ctx, user.Username); wasOverLimit {
				if e.restoreOverLimitUserIfAllowed(ctx, user.Username, billableTraffic, pkgCache) {
					resumeUserPrivateRouted(ctx, e.remoteManage, e.repo, user.Username)
				}
			}
			continue
		}

		wasOverLimit, _ := e.repo.IsUserOverLimit(ctx, user.Username)
		// Already weighted when each traffic delta was collected. Applying the
		// current package here would retroactively rewrite historical usage.
		usedWeighted := billableTraffic[user.Username]
		isOverLimit := trafficLimitExceeded(usedWeighted, limitBytes)

		// 流量 80% 预警按用户、当前限额原子去重。月度/手动重置会在同一事务清除此标记；
		// 限额变化也会产生新 claim，因此不会沿用旧套餐的预警状态。
		if !isOverLimit {
			pct := float64(usedWeighted) / float64(limitBytes) * 100
			if pct >= 80 {
				claimed, claimErr := e.repo.ClaimUserTrafficThresholdNotification(ctx, user.Username, limitBytes)
				if claimErr != nil {
					log.Printf("[TrafficLimitEnforcer] Failed to claim 80%% notification for %s: %v", user.Username, claimErr)
				} else if claimed {
					usedGB := float64(usedWeighted) / (1024 * 1024 * 1024)
					limitGB := float64(limitBytes) / (1024 * 1024 * 1024)
					SendTrafficThreshold80Notification(ctx, user.Username, usedGB, limitGB)
				}
			}
		}

		if isOverLimit && !wasOverLimit {
			log.Printf("[TrafficLimitEnforcer] User %s exceeded limit (%d/%d bytes), removing from inbounds",
				user.Username, usedWeighted, limitBytes)
			if usedForNotification, limitForNotification, ok := e.enforceUserOverLimit(ctx, user.Username, billableTraffic, pkgCache); ok {
				usedGB := float64(usedForNotification) / (1024 * 1024 * 1024)
				limitGB := float64(limitForNotification) / (1024 * 1024 * 1024)
				SendOverLimitNotification(ctx, user.Username, usedGB, limitGB)
			}
		} else if !isOverLimit && wasOverLimit {
			log.Printf("[TrafficLimitEnforcer] User %s back under limit (%d/%d bytes), restoring inbounds",
				user.Username, usedWeighted, limitBytes)
			if e.restoreOverLimitUserIfAllowed(ctx, user.Username, billableTraffic, pkgCache) {
				resumeUserPrivateRouted(ctx, e.remoteManage, e.repo, user.Username)
			}
		}
	}

	// 服务器按 traffic_reset_day 自动重置流量:逻辑同手动"重置流量"(offset = -当前用量)。
	// 触发时刻固定当天 08:05 之后,避开时区在 00:00 附近的跨天误判;只影响服务器,不动用户套餐重置。
	isAfter0805 := now.Hour() > 8 || (now.Hour() == 8 && now.Minute() >= 5)
	if isAfter0805 {
		if servers, sErr := e.repo.ListRemoteServers(ctx); sErr == nil {
			for _, s := range servers {
				if s.IsFederated {
					continue // 联邦分享的服务器流量归拥有方管,本机不重置
				}
				if !shouldResetThisMonth(now, true, s.TrafficResetDay, s.LastTrafficResetAt) {
					continue
				}
				if rErr := e.repo.ResetRemoteServerTrafficCycleAt(ctx, s.ID, now); rErr != nil {
					log.Printf("[TrafficLimitEnforcer] reset server %d(%s) traffic failed: %v", s.ID, s.Name, rErr)
					continue
				}
				log.Printf("[TrafficLimitEnforcer] server %d(%s) monthly traffic reset (day=%d)", s.ID, s.Name, s.TrafficResetDay)
			}
		} else {
			log.Printf("[TrafficLimitEnforcer] list servers for reset failed: %v", sErr)
		}
	}
}

func (e *TrafficLimitEnforcer) enforceUserOverLimit(ctx context.Context, username string, billableTraffic map[string]int64, pkgCache map[int64]*storage.Package) (int64, int64, bool) {
	leasedCtx, releaseAuthorization, err := e.repo.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit revoke deferred: acquire authorization lease: %v", username, err)
		return 0, 0, false
	}
	defer releaseAuthorization()

	latest, err := e.repo.GetUser(leasedCtx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit revoke deferred: reload user: %v", username, err)
		return 0, 0, false
	}
	if latest.AuthorizationMode != storage.AuthorizationModePackage || latest.PackageID <= 0 {
		return 0, 0, false
	}
	wasOverLimit, _ := e.repo.IsUserOverLimit(leasedCtx, username)
	if wasOverLimit {
		return 0, 0, false
	}
	pkg := pkgCache[latest.PackageID]
	if pkg == nil {
		pkg, err = e.repo.GetPackage(leasedCtx, latest.PackageID)
		if err != nil {
			log.Printf("[TrafficLimitEnforcer] User %s over-limit revoke deferred: package %d: %v", username, latest.PackageID, err)
			return 0, 0, false
		}
		pkgCache[latest.PackageID] = pkg
	}
	limitBytes := resolveTrafficLimitBytes(&latest, pkg)
	usedWeighted := billableTraffic[username]
	if limitBytes <= 0 || !trafficLimitExceeded(usedWeighted, limitBytes) {
		return 0, 0, false
	}
	configs, err := e.repo.GetUserInboundConfigs(leasedCtx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit revoke deferred: list inbound configs: %v", username, err)
		return 0, 0, false
	}
	serverLeasedCtx, releaseServers, err := acquireRemoteServerMutationLeases(
		leasedCtx, e.repo, inboundConfigServerIDs(configs),
	)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit revoke deferred: acquire server leases: %v", username, err)
		return 0, 0, false
	}
	defer releaseServers()
	leasedCtx = serverLeasedCtx
	removed := e.removeUserFromAllInbounds(leasedCtx, username, false)
	if err := suspendUserPrivateRouted(leasedCtx, e.remoteManage, e.repo, username); err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit private routed suspend failed: %v", username, err)
		removed = false
	}
	if !removed {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit revoke incomplete; retaining active limiter mapping for retry", username)
		return 0, 0, false
	}
	if err := e.repo.UpdateUserOverLimit(leasedCtx, username, true); err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit state update failed: %v", username, err)
		return 0, 0, false
	}
	return usedWeighted, limitBytes, true
}

func (e *TrafficLimitEnforcer) restoreOverLimitUserIfAllowed(ctx context.Context, username string, billableTraffic map[string]int64, pkgCache map[int64]*storage.Package) bool {
	leasedCtx, releaseAuthorization, err := e.repo.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit restore deferred: acquire authorization lease: %v", username, err)
		return false
	}
	defer releaseAuthorization()

	latest, err := e.repo.GetUser(leasedCtx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit restore deferred: reload user: %v", username, err)
		return false
	}
	if latest.AuthorizationMode != storage.AuthorizationModePackage || latest.PackageID <= 0 {
		return false
	}
	wasOverLimit, _ := e.repo.IsUserOverLimit(leasedCtx, username)
	if !wasOverLimit {
		return false
	}
	pkg := pkgCache[latest.PackageID]
	if pkg == nil {
		pkg, err = e.repo.GetPackage(leasedCtx, latest.PackageID)
		if err != nil {
			log.Printf("[TrafficLimitEnforcer] User %s over-limit restore deferred: package %d: %v", username, latest.PackageID, err)
			return false
		}
		pkgCache[latest.PackageID] = pkg
	}
	limitBytes := resolveTrafficLimitBytes(&latest, pkg)
	usedWeighted := billableTraffic[username]
	if limitBytes > 0 && trafficLimitExceeded(usedWeighted, limitBytes) {
		return false
	}
	configs, err := e.repo.GetUserInboundConfigs(leasedCtx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit restore deferred: list inbound configs: %v", username, err)
		return false
	}
	serverLeasedCtx, releaseServers, err := acquireRemoteServerMutationLeases(
		leasedCtx, e.repo, inboundConfigServerIDs(configs),
	)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit restore deferred: acquire server leases: %v", username, err)
		return false
	}
	defer releaseServers()
	leasedCtx = serverLeasedCtx
	limiterServerIDs, err := e.embeddedLimiterServerIDs(leasedCtx, configs)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit restore deferred: resolve limiter servers: %v", username, err)
		return false
	}
	if !e.restoreUserToInbounds(leasedCtx, latest, time.Now().UTC()) {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit restore incomplete; retaining over-limit state for retry", username)
		e.restoreOverLimitTombstone(leasedCtx, username, limiterServerIDs)
		return false
	}
	if err := e.repo.UpdateUserOverLimit(leasedCtx, username, false); err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s over-limit restore state update failed: %v", username, err)
		e.restoreOverLimitTombstone(leasedCtx, username, limiterServerIDs)
		return false
	}
	if err := e.pushLimiterPoliciesCheckedLeased(leasedCtx, limiterServerIDs); err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s normal limiter restore failed: %v", username, err)
		e.restoreOverLimitTombstone(leasedCtx, username, limiterServerIDs)
		return false
	}
	return true
}

func (e *TrafficLimitEnforcer) embeddedLimiterServerIDs(ctx context.Context, configs []storage.UserInboundConfig) ([]int64, error) {
	unique := make(map[int64]struct{}, len(configs))
	serverIDs := make([]int64, 0, len(configs))
	for _, cfg := range configs {
		if cfg.ServerID <= 0 {
			continue
		}
		if _, exists := unique[cfg.ServerID]; exists {
			continue
		}
		server, err := e.repo.GetRemoteServer(ctx, cfg.ServerID)
		if err != nil {
			return nil, err
		}
		if server.XrayMode != "embedded" {
			continue
		}
		unique[cfg.ServerID] = struct{}{}
		serverIDs = append(serverIDs, cfg.ServerID)
	}
	sort.Slice(serverIDs, func(i, j int) bool { return serverIDs[i] < serverIDs[j] })
	return serverIDs, nil
}

func (e *TrafficLimitEnforcer) pushLimiterPoliciesCheckedLeased(ctx context.Context, serverIDs []int64) error {
	if len(serverIDs) == 0 {
		return nil
	}
	if e.pusher == nil {
		return errors.New("limiter pusher is required to restore embedded inbound access")
	}
	for _, serverID := range serverIDs {
		if err := e.pusher.pushToServerCheckedLeased(ctx, serverID); err != nil {
			return fmt.Errorf("server %d: %w", serverID, err)
		}
	}
	return nil
}

func (e *TrafficLimitEnforcer) restoreOverLimitTombstone(ctx context.Context, username string, serverIDs []int64) {
	if err := e.repo.UpdateUserOverLimit(ctx, username, true); err != nil {
		log.Printf("[TrafficLimitEnforcer] User %s failed to restore over-limit retry state: %v", username, err)
		return
	}
	if err := e.pushLimiterPoliciesCheckedLeased(ctx, serverIDs); err != nil {
		// The durable over-limit flag keeps future snapshots fail-closed and lets
		// the next enforcer pass retry both the peer and tombstone publication.
		log.Printf("[TrafficLimitEnforcer] User %s tombstone limiter republish failed; retained over-limit retry state: %v", username, err)
	}
}

// removeUserFromAllInbounds 从该用户所有 inbound 摘除 client。
// 返回 true = 可安全清理 DB:所有 client 要么摘除成功,要么对应 inbound 本就不存在(不可能留孤儿)。
// 返回 false = 至少一个 inbound 摘除失败且 client 可能仍残留(典型:agent 离线)——调用方应保留
// user_inbound_configs 与套餐绑定,下个周期重试,避免「agent 有孤儿 client 但 DB 无行」的漂移
// (该漂移会让续费/再分配时生成同 email 新 uuid 的重复凭据,且过期用户因孤儿 client 仍能连)。
// 注:over-limit 摘除调用处忽略返回值即可(它不清 user_inbound_configs)。
func (e *TrafficLimitEnforcer) removeUserFromAllInbounds(ctx context.Context, username string, deleteRemovedConfigs bool) bool {
	configs, err := e.repo.GetUserInboundConfigs(ctx, username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to get inbound configs for %s: %v", username, err)
		return false
	}
	safe := true
	for _, cfg := range configs {
		retained, removeErr := removePackageUserFromInbound(ctx, e.remoteManage, cfg)
		if removeErr != nil && !isInboundNotFoundErr(removeErr) {
			log.Printf("[TrafficLimitEnforcer] Failed to remove %s from %s on server %d: %v",
				username, cfg.InboundTag, cfg.ServerID, removeErr)
			safe = false
			continue
		}
		if deleteRemovedConfigs && !retained {
			if err := e.repo.DeleteUserInboundConfig(ctx, username, cfg.ServerID, cfg.InboundTag); err != nil {
				log.Printf("[TrafficLimitEnforcer] Failed to delete inbound config for %s on %s/server %d: %v",
					username, cfg.InboundTag, cfg.ServerID, err)
				safe = false
			}
		}
	}
	return safe
}

func (e *TrafficLimitEnforcer) restoreUserToInbounds(ctx context.Context, user storage.User, now time.Time) bool {
	configs, err := e.repo.GetUserInboundConfigs(ctx, user.Username)
	if err != nil {
		log.Printf("[TrafficLimitEnforcer] Failed to get inbound configs for %s: %v", user.Username, err)
		return false
	}
	restored := true
	for _, cfg := range configs {
		hasManagedAccess, managedExpiry, err := e.repo.HasEffectiveUserInboundAccess(ctx, cfg.Username, cfg.ServerID, cfg.InboundTag, 0, now)
		if err != nil {
			log.Printf("[TrafficLimitEnforcer] Failed to resolve managed restore access for %s/%s on server %d: %v",
				cfg.Username, cfg.InboundTag, cfg.ServerID, err)
			restored = false
			continue
		}
		hasDirectAccess, directExpiry, err := e.repo.HasEffectiveDirectUserInboundAccess(ctx, cfg.Username, cfg.ServerID, cfg.InboundTag, 0, now)
		if err != nil {
			log.Printf("[TrafficLimitEnforcer] Failed to resolve direct restore access for %s/%s on server %d: %v",
				cfg.Username, cfg.InboundTag, cfg.ServerID, err)
			restored = false
			continue
		}
		hasPackageAccess, packageExpiry, err := hasLegacyPackageInboundAccessIgnoringOverLimit(ctx, e.repo, cfg.Username, cfg.ServerID, cfg.InboundTag, now)
		if err != nil {
			log.Printf("[TrafficLimitEnforcer] Failed to resolve package restore access for %s/%s on server %d: %v",
				cfg.Username, cfg.InboundTag, cfg.ServerID, err)
			restored = false
			continue
		}
		hasAccess, notAfter := laterOptionalExpiry(hasManagedAccess, managedExpiry, hasDirectAccess, directExpiry)
		hasAccess, notAfter = laterOptionalExpiry(hasAccess, notAfter, hasPackageAccess, packageExpiry)
		if !hasAccess {
			continue
		}
		if err := addUserToInboundWithExpiryAndLimiter(ctx, e.remoteManage, e.repo, e.pusher, user, cfg.ServerID, cfg.InboundTag, notAfter, true); err != nil {
			log.Printf("[TrafficLimitEnforcer] Failed to restore %s to %s on server %d: %v",
				user.Username, cfg.InboundTag, cfg.ServerID, err)
			restored = false
		}
	}
	return restored
}
