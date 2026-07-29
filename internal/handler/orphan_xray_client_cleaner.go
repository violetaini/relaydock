package handler

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// OrphanXrayClientCleaner 每天凌晨扫一次:清理 xray inbound 上已无主的 client(email)。
//
// 触发场景:
//   - 用户删除时某 server 离线 / push 失败 → db.users / db.user_subaccounts 已删,
//     但 agent 端 xray config 仍残留对应 client → 该 email 上的流量会被记到孤行,
//     更糟的是 vmess/trojan UUID 仍可被原客户端复用,绕过套餐过期 / 流量超额 / 黑名单。
//
// 白名单(以下任一命中则保留):
//   - 空 email 或 "_admin__" 前缀(系统占位)
//   - user_subaccounts.email 任意一行(无论 is_active) — 续费恢复期间凭据要保留
//   - nodes.routed_admin_email(routed 出站的 admin 占位)
//   - ResolveUsernameByEmail 命中 + 反查 users 表存在的 username
//   - 内置 tag "api" 上的全部 client(不扫这条 inbound)
//
// 时机:每天本地时间 03:30 — 跟 startDailySnapshotTask(0:00 跑)错峰,降低 sqlite 锁竞争,
// 且仍在业务低峰。
//
// 数据源:server_xray_config_snapshots.current — 即主控 push agent 配置时 snapshot 的 JSON,
// 不直接打 agent /api/child/inbounds GET(避免 agent 离线/弱网时阻塞清理)。
// 实际 remove 会调 remoteManage.forwardToRemoteServer → WS-first / HTTP fallback,agent 离线
// 时单台失败不阻塞其它 server 处理。
type OrphanXrayClientCleaner struct {
	repo         *storage.TrafficRepository
	remoteManage *RemoteManageHandler
}

func NewOrphanXrayClientCleaner(repo *storage.TrafficRepository, rm *RemoteManageHandler) *OrphanXrayClientCleaner {
	return &OrphanXrayClientCleaner{repo: repo, remoteManage: rm}
}

// Start 起一个 goroutine,等到下一个 03:30 跑首次,之后每 24h 一次。ctx 取消即退出。
func (c *OrphanXrayClientCleaner) Start(ctx context.Context) {
	go c.loop(ctx)
}

func (c *OrphanXrayClientCleaner) loop(ctx context.Context) {
	if c.repo == nil || c.remoteManage == nil {
		log.Printf("[OrphanXrayClientCleaner] repo or remoteManage nil, scheduler skipped")
		return
	}

	// 对齐到下一个本地时间 03:30
	now := time.Now()
	target := time.Date(now.Year(), now.Month(), now.Day(), 3, 30, 0, 0, now.Location())
	if !target.After(now) {
		target = target.Add(24 * time.Hour)
	}
	firstDelay := time.Until(target)
	log.Printf("[OrphanXrayClientCleaner] scheduler started, first run at %s (in %s)",
		target.Format("2006-01-02 15:04:05"), firstDelay.Round(time.Second))

	firstTimer := time.NewTimer(firstDelay)
	select {
	case <-ctx.Done():
		firstTimer.Stop()
		return
	case <-firstTimer.C:
		c.runOnce(ctx)
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.runOnce(ctx)
		}
	}
}

func (c *OrphanXrayClientCleaner) runOnce(ctx context.Context) {
	start := time.Now()
	log.Printf("[OrphanXrayClientCleaner] scan started")

	// 1) 白名单收集
	users, err := c.repo.ListUsers(ctx, 100000)
	if err != nil {
		log.Printf("[OrphanXrayClientCleaner] list users failed: %v", err)
		return
	}
	usernameSet := make(map[string]bool, len(users))
	for _, u := range users {
		usernameSet[u.Username] = true
	}

	subaccountEmails, err := c.repo.ListSubaccountEmailToUsername(ctx)
	if err != nil {
		log.Printf("[OrphanXrayClientCleaner] list subaccount emails failed: %v", err)
		return
	}

	servers, err := c.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[OrphanXrayClientCleaner] list servers failed: %v", err)
		return
	}

	// 2) 收集 routed_admin_email(占位 admin client,routed_owner='shared' 时存在)
	routedAdminEmails, err := c.repo.ListRoutedAdminEmails(ctx)
	if err != nil {
		log.Printf("[OrphanXrayClientCleaner] list routed admin emails failed (continue): %v", err)
		routedAdminEmails = make(map[string]bool)
	}

	shouldKeep := func(email string) bool {
		if email == "" || strings.HasPrefix(email, "_admin__") {
			return true
		}
		if _, ok := subaccountEmails[email]; ok {
			return true
		}
		if routedAdminEmails[email] {
			return true
		}
		username := c.repo.ResolveUsernameByEmail(ctx, email)
		if username == "" {
			return false
		}
		return usernameSet[username]
	}

	// 3) 遍历 server snapshot,识别孤儿,逐个 remove
	var totalScanned, totalOrphan, totalRemoved, totalFailed int
	for _, srv := range servers {
		snap, err := c.repo.GetCurrentXraySnapshot(ctx, srv.ID)
		if err != nil || snap == nil {
			continue
		}
		var cfg struct {
			Inbounds []struct {
				Tag      string `json:"tag"`
				Settings struct {
					Clients []map[string]interface{} `json:"clients"`
				} `json:"settings"`
			} `json:"inbounds"`
		}
		if jerr := json.Unmarshal([]byte(snap.ConfigJSON), &cfg); jerr != nil {
			log.Printf("[OrphanXrayClientCleaner] server=%d parse snapshot failed: %v", srv.ID, jerr)
			continue
		}
		for _, ib := range cfg.Inbounds {
			if ib.Tag == "" || ib.Tag == "api" {
				continue
			}
			for _, client := range ib.Settings.Clients {
				email, _ := client["email"].(string)
				totalScanned++
				if shouldKeep(email) {
					continue
				}
				totalOrphan++
				// remove 给 30s 超时(agent 离线 / 弱网时不卡死)
				rmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				err := removeClientFromInbound(rmCtx, c.remoteManage, srv.ID, ib.Tag, email)
				cancel()
				if err != nil {
					log.Printf("[OrphanXrayClientCleaner] remove FAILED server=%d tag=%s email=%s: %v",
						srv.ID, ib.Tag, email, err)
					totalFailed++
					continue
				}
				log.Printf("[OrphanXrayClientCleaner] removed orphan server=%d tag=%s email=%s",
					srv.ID, ib.Tag, email)
				totalRemoved++
			}
		}
	}

	log.Printf("[OrphanXrayClientCleaner] scan done in %s: scanned=%d orphan=%d removed=%d failed=%d",
		time.Since(start).Round(time.Millisecond), totalScanned, totalOrphan, totalRemoved, totalFailed)
}
