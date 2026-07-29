package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// OrphanInboundConfigBackfiller 启动时一次性补写"流量上存在但 user_inbound_configs 没登记"的 client。
//
// 背景:
//   - 普通付费用户走 SaveUserInboundConfig 自动登记(套餐绑定/续费 → inbound_batch_apply)。
//   - 但历史漏洞和手动添加 inbound client 的路径不写这张表 ⇒ collector 拿到 xray stats 的 user 维度
//     流量后,handleUserNodes / handleNodeUsers 这些反查接口看不到这个用户的节点归属。
//   - 没绑成功的用户 → 流量信息页"用户视图详情"和"节点视图详情"空白。
//
// 范围(严格限定,避免污染 user_inbound_configs 抽象):
//   - 只补 role != "admin" 的真实用户(admin 自用走 handler fallback,不进这张表)
//   - 只补 client.email 能精确反查到 users 表 username 的行
//   - 跳过 tag == "api" 的内置 inbound
//   - 跳过子账号 email(走 routed 路径,跟本表无关)
//   - 同 (username, server_id, inbound_tag) 已经有行 → 跳过(幂等)
//
// 数据源:server_xray_config_snapshots.current → 解析 inbounds[].settings.clients[].email。
// 不向 agent 发请求 — DB 里已经有完整 config,补丁纯本地操作。
//
// 启动延迟 90s — 比 CredentialEmailMigrator(60s)晚跑,让那个先把老格式 email 迁完,
// 我们再补剩下的;两次成功后写 system_settings._migrate_orphan_inbound_configs_done='1' 永久跳过。
type OrphanInboundConfigBackfiller struct {
	repo *storage.TrafficRepository
}

func NewOrphanInboundConfigBackfiller(repo *storage.TrafficRepository) *OrphanInboundConfigBackfiller {
	return &OrphanInboundConfigBackfiller{repo: repo}
}

const orphanInboundConfigBackfillDoneKey = "_migrate_orphan_inbound_configs_done"

func (m *OrphanInboundConfigBackfiller) Start(ctx context.Context, delay time.Duration) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		m.runOnce(ctx)
	}()
}

func (m *OrphanInboundConfigBackfiller) runOnce(ctx context.Context) {
	if m.repo == nil {
		return
	}
	if v, _ := m.repo.GetSystemSetting(ctx, orphanInboundConfigBackfillDoneKey); v == "1" {
		return
	}

	// 1. 真实非 admin 用户白名单 + email → username 反查(给 user.email 直绑场景用)
	users, err := m.repo.ListUsers(ctx, 100000)
	if err != nil {
		log.Printf("[OrphanInboundBackfill] list users failed: %v", err)
		return
	}
	usernameRole := make(map[string]string, len(users))
	emailToUsername := make(map[string]string, len(users))
	for _, u := range users {
		usernameRole[u.Username] = u.Role
		if u.Email != "" {
			emailToUsername[u.Email] = u.Username
		}
	}

	// 2. 已有 (username, server_id, inbound_tag) 索引(幂等检查 + 跳过)
	existingConfigs, err := m.repo.ListAllUserInboundConfigs(ctx)
	if err != nil {
		log.Printf("[OrphanInboundBackfill] list existing configs failed: %v", err)
		return
	}
	existingKey := make(map[string]bool, len(existingConfigs))
	for _, c := range existingConfigs {
		existingKey[fmt.Sprintf("%s|%d|%s", c.Username, c.ServerID, c.InboundTag)] = true
	}

	// 3. 服务器列表(给子账号 email 集合 + snapshot 遍历两步用)
	servers, err := m.repo.ListRemoteServers(ctx)
	if err != nil {
		log.Printf("[OrphanInboundBackfill] list servers failed: %v", err)
		return
	}

	// 4. 子账号 email 排除集 — 跨 server 合并所有 active 子账号 email。
	// ListActiveSubaccountsByServerName 是按 server name 拿,跨 server 逐个调一次合并。
	subaccountEmails := make(map[string]bool)
	for _, srv := range servers {
		if srv.Name == "" {
			continue
		}
		subs, _ := m.repo.ListActiveSubaccountsByServerName(ctx, srv.Name)
		for _, sa := range subs {
			subaccountEmails[sa.Email] = true
		}
	}

	type backfillRow struct {
		username, inboundTag, protocol, credJSON string
		serverID                                 int64
		email                                    string
	}
	var pending []backfillRow
	var skippedAdmin, skippedNoUser, skippedSubaccount, skippedAlready int

	for _, srv := range servers {
		snap, err := m.repo.GetCurrentXraySnapshot(ctx, srv.ID)
		if err != nil || snap == nil {
			continue
		}
		var cfg struct {
			Inbounds []struct {
				Tag      string `json:"tag"`
				Protocol string `json:"protocol"`
				Settings struct {
					Clients []map[string]interface{} `json:"clients"`
				} `json:"settings"`
			} `json:"inbounds"`
		}
		if jerr := json.Unmarshal([]byte(snap.ConfigJSON), &cfg); jerr != nil {
			log.Printf("[OrphanInboundBackfill] server=%d parse snapshot failed: %v", srv.ID, jerr)
			continue
		}
		for _, ib := range cfg.Inbounds {
			if ib.Tag == "" || ib.Tag == "api" {
				continue
			}
			for _, client := range ib.Settings.Clients {
				email, _ := client["email"].(string)
				if email == "" {
					continue
				}
				// 检查是不是子账号 email(优先级最高,跳过)
				if subaccountEmails[email] {
					skippedSubaccount++
					continue
				}
				// 反查 username
				username := m.repo.ResolveUsernameByEmail(ctx, email)
				if username == "" {
					skippedNoUser++
					continue
				}
				// users 表里必须存在
				role, ok := usernameRole[username]
				if !ok {
					skippedNoUser++
					continue
				}
				// admin 不补(走 handler fallback,不污染表)
				if role == storage.RoleAdmin {
					skippedAdmin++
					continue
				}
				// 幂等
				key := fmt.Sprintf("%s|%d|%s", username, srv.ID, ib.Tag)
				if existingKey[key] {
					skippedAlready++
					continue
				}
				existingKey[key] = true // 同 inbound 多 client 命中同 user 时只写一行

				credBytes, jerr := json.Marshal(client)
				if jerr != nil {
					continue
				}
				pending = append(pending, backfillRow{
					username:   username,
					serverID:   srv.ID,
					inboundTag: ib.Tag,
					protocol:   ib.Protocol,
					credJSON:   string(credBytes),
					email:      email,
				})
			}
		}
	}

	if len(pending) == 0 {
		log.Printf("[OrphanInboundBackfill] nothing to backfill (skipped: admin=%d no-user=%d subaccount=%d already=%d) — marking done",
			skippedAdmin, skippedNoUser, skippedSubaccount, skippedAlready)
		_ = m.repo.SetSystemSetting(ctx, orphanInboundConfigBackfillDoneKey, "1")
		return
	}

	log.Printf("[OrphanInboundBackfill] backfilling %d row(s) (skipped: admin=%d no-user=%d subaccount=%d already=%d)",
		len(pending), skippedAdmin, skippedNoUser, skippedSubaccount, skippedAlready)

	var ok, failed int
	for _, p := range pending {
		if err := m.repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
			Username:       p.username,
			ServerID:       p.serverID,
			InboundTag:     p.inboundTag,
			Protocol:       p.protocol,
			CredentialJSON: p.credJSON,
		}); err != nil {
			log.Printf("[OrphanInboundBackfill] save user=%s server=%d tag=%s FAILED: %v", p.username, p.serverID, p.inboundTag, err)
			failed++
			continue
		}
		log.Printf("[OrphanInboundBackfill] backfilled user=%s server=%d tag=%s email=%s", p.username, p.serverID, p.inboundTag, p.email)
		ok++
	}

	log.Printf("[OrphanInboundBackfill] done: ok=%d failed=%d", ok, failed)
	if failed == 0 {
		_ = m.repo.SetSystemSetting(ctx, orphanInboundConfigBackfillDoneKey, "1")
	}
}
