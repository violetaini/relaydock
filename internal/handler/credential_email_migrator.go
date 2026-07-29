package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// CredentialEmailMigrator 后台一次性迁移老格式 user_inbound_configs 凭据 email。
//
// 背景:commit ae60947 之前 generateCredential 用 user.Email(无 Email 则 user.Username)做 client.email,
// 该 commit 改成 `<username>__<inboundTag>` 但未回填存量。结果 collector 拿到老 client.email(如
// `share@2ha.me`),走 fallback `return email` 把流量记到 user_traffic.username=email 孤行,
// 管理员页面按 username 查不到。
//
// 流程:启动 60s 后跑一次(给 agent WS 重连时间)。扫所有 user_inbound_configs.credential_json.email,
// 不等于新格式 `<username>__<inbound_tag>` 即视为老格式,对该行:
//  1. 解析旧 cred(保留 uuid/password)
//  2. 构造新 cred:email 字段改成新格式,其他不动
//  3. agent remove-client(老)
//  4. agent add-client(新),失败时立即恢复老 client
//  5. UPDATE user_inbound_configs.credential_json
//
// 失败的行:记 log + 跳过(不阻断其他行)。不写 done 标记 — 下次启动重试。
// 成功 done(本轮全部成功)→ 写 system_settings._migrate_credential_email_done='1' 永久跳过。
type CredentialEmailMigrator struct {
	repo *storage.TrafficRepository
	rm   *RemoteManageHandler
}

func NewCredentialEmailMigrator(repo *storage.TrafficRepository, rm *RemoteManageHandler) *CredentialEmailMigrator {
	return &CredentialEmailMigrator{repo: repo, rm: rm}
}

// Start 启动后台 goroutine。delay 是首次执行前的等待(等 agent WS 重连)。
func (m *CredentialEmailMigrator) Start(ctx context.Context, delay time.Duration) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		m.runOnce(ctx)
	}()
}

const credentialEmailMigrationDoneKey = "_migrate_credential_email_done"

func (m *CredentialEmailMigrator) runOnce(ctx context.Context) {
	if m.repo == nil || m.rm == nil {
		return
	}
	if v, _ := m.repo.GetSystemSetting(ctx, credentialEmailMigrationDoneKey); v == "1" {
		return
	}

	configs, err := m.repo.ListAllUserInboundConfigs(ctx)
	if err != nil {
		log.Printf("[CredEmailMigrate] list configs failed: %v", err)
		return
	}

	// 兜底:只迁移**老 generateCredential 生成**的 email(== user.Email 或 user.Username)。
	// 任何其他由管理员手工添加的语义化 email 都保留不动 —
	// 它们往往跟 xray routing rule user[] 配套(改 email 会让 routed 出站规则全失效)。
	// 先一次性拉所有用户的 (username, email),省去每行查表的开销。
	userEmailByName := map[string]string{}
	if users, err := m.repo.ListUsers(ctx, 10000); err == nil {
		for _, u := range users {
			userEmailByName[u.Username] = u.Email
		}
	} else {
		log.Printf("[CredEmailMigrate] list users failed (will skip all rows for safety): %v", err)
		return
	}

	var legacy []storage.UserInboundConfig
	var skipped int
	for _, c := range configs {
		verdict := classifyCredentialEmail(c, userEmailByName)
		switch verdict {
		case credEmailLegacy:
			legacy = append(legacy, c)
		case credEmailCustom:
			skipped++
			log.Printf("[CredEmailMigrate] skip custom email row id=%d user=%s server=%d tag=%s (not generateCredential-generated)",
				c.ID, c.Username, c.ServerID, c.InboundTag)
		}
		// credEmailAlreadyNew / credEmailNoEmail: 静默跳过
	}
	if skipped > 0 {
		log.Printf("[CredEmailMigrate] skipped %d custom-email row(s) — they stay as-is", skipped)
	}
	if len(legacy) == 0 {
		log.Printf("[CredEmailMigrate] no legacy credentials, marking done")
		_ = m.repo.SetSystemSetting(ctx, credentialEmailMigrationDoneKey, "1")
		return
	}

	log.Printf("[CredEmailMigrate] found %d legacy credential(s) to migrate", len(legacy))

	var ok, failed int
	for _, c := range legacy {
		if err := m.migrateOne(ctx, c); err != nil {
			log.Printf("[CredEmailMigrate] user=%s server=%d tag=%s FAILED: %v", c.Username, c.ServerID, c.InboundTag, err)
			failed++
			continue
		}
		log.Printf("[CredEmailMigrate] user=%s server=%d tag=%s migrated", c.Username, c.ServerID, c.InboundTag)
		ok++
	}

	log.Printf("[CredEmailMigrate] done: ok=%d failed=%d", ok, failed)
	if failed == 0 {
		_ = m.repo.SetSystemSetting(ctx, credentialEmailMigrationDoneKey, "1")
	}
	// failed > 0 → 不标记 done,下次启动重试这批
}

// credEmailVerdict 对单行 user_inbound_configs 的 email 字段分类。
type credEmailVerdict int

const (
	credEmailNoEmail    credEmailVerdict = iota // 凭据没 email 字段(socks/http)或解析失败,静默跳过
	credEmailAlreadyNew                         // email 已经是 `<username>__<inbound_tag>` 新格式,静默跳过
	credEmailLegacy                             // 老 generateCredential 生成的(== user.Email 或 user.Username),需要迁移
	credEmailCustom                             // 自定义 email(admin 手工添加 / 跟 routing rule 配套),保留不动
)

// classifyCredentialEmail 判定该行是否需要迁移,并区分"自定义 email"(必须保留)
// 与"老 generateCredential 生成的 email"(可以安全迁移)。
//
// 老 generateCredential(ae60947 之前)规则:
//
//	email := user.Email; if email == "" { email = user.Username }
//
// 所以**只有** email 等于该用户的注册邮箱或用户名时,才认为是 generateCredential 老逻辑产物。
// 其他语义化 email —
// 是 admin 手工添加的 routed 入口 client,跟 xray routing rule `user[]` 数组精确对应。
// 改这种 email 会让 routed 出站规则全失效(实际事故:2026-06-01 jimlee 8 个 routed 入口被误迁)。
func classifyCredentialEmail(c storage.UserInboundConfig, userEmailByName map[string]string) credEmailVerdict {
	var cred map[string]interface{}
	if err := json.Unmarshal([]byte(c.CredentialJSON), &cred); err != nil {
		return credEmailNoEmail
	}
	email, _ := cred["email"].(string)
	if email == "" {
		return credEmailNoEmail
	}
	if email == c.Username+"__"+c.InboundTag {
		return credEmailAlreadyNew
	}
	if email == c.Username {
		return credEmailLegacy
	}
	if regEmail, ok := userEmailByName[c.Username]; ok && regEmail != "" && email == regEmail {
		return credEmailLegacy
	}
	return credEmailCustom
}

// migrateOne 切换单条凭据的 email。失败原子:任一步失败就 abort,不更新 DB。
func (m *CredentialEmailMigrator) migrateOne(ctx context.Context, c storage.UserInboundConfig) error {
	leasedCtx, release, err := m.repo.AcquireRemoteServerMutationLease(ctx, c.ServerID)
	if err != nil {
		return fmt.Errorf("acquire server mutation lease: %w", err)
	}
	defer release()
	ctx = leasedCtx

	var oldCred map[string]interface{}
	if err := json.Unmarshal([]byte(c.CredentialJSON), &oldCred); err != nil {
		return fmt.Errorf("parse old cred: %w", err)
	}

	// 构造新 cred:只换 email,其他字段(uuid/password/auth/level/flow ...)原样保留。
	newCred := make(map[string]interface{}, len(oldCred))
	for k, v := range oldCred {
		newCred[k] = v
	}
	newCred["email"] = c.Username + "__" + c.InboundTag

	newCredJSON, err := json.Marshal(newCred)
	if err != nil {
		return fmt.Errorf("marshal new cred: %w", err)
	}

	// 必须先 remove 老,再 add 新 — 不能反过来。
	// agent matchClientCredential 对 trojan/vless/vmess 只按 primary key(password/id)匹配,
	// 不看 email。新老 cred 共用同一 password/id,先 add-client(新)会被判定 "already present" 而 no-op,
	// 紧接着 remove-client(老)按 password 命中,把唯一一条 client 删掉 → 用户彻底失联。
	//
	// 顺序换成 remove → add:remove 把老的删掉,clients 里没了 → add 真正写入新 cred。
	// 中间空窗 ~毫秒级(同一 agent inboundsMu 串行,基本无缝),客户端短期重连即可。
	rmBody, _ := json.Marshal(map[string]interface{}{
		"action": "remove-client",
		"tag":    c.InboundTag,
		"client": oldCred,
	})
	rmResponse, err := m.rm.forwardToRemoteServer(ctx, c.ServerID, "POST", "/api/child/inbounds", rmBody)
	if err == nil {
		err = validateCredentialMigrationACK(rmResponse)
	}
	if err != nil {
		// 孤儿数据:user_inbound_configs 里有记录但 agent xray 已经没这个 inbound 了
		// (历史 inbound 删除时没级联清理 user_inbound_configs)。这条 client 在 agent 端不存在,
		// add/remove 都没意义 — 直接 UPDATE DB 把 credential_json 的 email 改成新格式,
		// 收尾 DB 一致性。后续即使 inbound 被恢复,client 也是按新 email 重新加入。
		if isInboundNotFoundErr(err) {
			if uerr := m.repo.UpdateUserInboundCredentialJSONByID(ctx, c.ID, string(newCredJSON)); uerr != nil {
				return fmt.Errorf("update db (orphan, agent missing inbound): %w", uerr)
			}
			log.Printf("[CredEmailMigrate] user=%s server=%d tag=%s db-only updated (agent has no such inbound)",
				c.Username, c.ServerID, c.InboundTag)
			return nil
		}
		return fmt.Errorf("remove-client (old): %w", err)
	}

	addBody, _ := json.Marshal(map[string]interface{}{
		"action": "add-client",
		"tag":    c.InboundTag,
		"client": newCred,
	})
	addResponse, err := m.rm.forwardToRemoteServer(ctx, c.ServerID, "POST", "/api/child/inbounds", addBody)
	if err == nil {
		err = validateCredentialMigrationACK(addResponse)
	}
	if err != nil {
		// add 失败:老 client 已 remove,新 client 没加 → 用户失联。
		// agent /api/child/inbounds 实现是写文件 + runtime apply,失败前通常已经写盘,
		// 但保险起见这里把老 cred 再 add 回去,恢复原状。
		rollback, _ := json.Marshal(map[string]interface{}{
			"action": "add-client",
			"tag":    c.InboundTag,
			"client": oldCred,
		})
		rollbackResponse, rbErr := m.rm.forwardToRemoteServer(ctx, c.ServerID, "POST", "/api/child/inbounds", rollback)
		if rbErr == nil {
			rbErr = validateCredentialMigrationACK(rollbackResponse)
		}
		if rbErr != nil {
			log.Printf("[CredEmailMigrate] CRITICAL: rollback add-client failed user=%s server=%d tag=%s: %v (manual fix needed)",
				c.Username, c.ServerID, c.InboundTag, rbErr)
		}
		return fmt.Errorf("add-client (new): %w", err)
	}

	if err := m.repo.UpdateUserInboundCredentialJSONByID(ctx, c.ID, string(newCredJSON)); err != nil {
		// The Agent already has the new email. Restore the old client before
		// releasing the server lease so an installation can never snapshot a
		// remote/DB split-brain state.
		removeNew, _ := json.Marshal(map[string]interface{}{
			"action": "remove-client",
			"tag":    c.InboundTag,
			"client": newCred,
		})
		removeResponse, removeErr := m.rm.forwardToRemoteServer(ctx, c.ServerID, "POST", "/api/child/inbounds", removeNew)
		if removeErr == nil {
			removeErr = validateCredentialMigrationACK(removeResponse)
		}
		if removeErr != nil {
			log.Printf("[CredEmailMigrate] CRITICAL: DB update and remove-new rollback failed user=%s server=%d tag=%s: %v",
				c.Username, c.ServerID, c.InboundTag, removeErr)
		} else {
			restoreOld, _ := json.Marshal(map[string]interface{}{
				"action": "add-client",
				"tag":    c.InboundTag,
				"client": oldCred,
			})
			restoreResponse, restoreErr := m.rm.forwardToRemoteServer(ctx, c.ServerID, "POST", "/api/child/inbounds", restoreOld)
			if restoreErr == nil {
				restoreErr = validateCredentialMigrationACK(restoreResponse)
			}
			if restoreErr != nil {
				log.Printf("[CredEmailMigrate] CRITICAL: DB update and restore-old rollback failed user=%s server=%d tag=%s: %v",
					c.Username, c.ServerID, c.InboundTag, restoreErr)
			}
		}
		return fmt.Errorf("update db: %w", err)
	}
	return nil
}

func validateCredentialMigrationACK(body []byte) error {
	var response struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("invalid Agent credential mutation ACK: %w", err)
	}
	if response.Success {
		return nil
	}
	detail := strings.TrimSpace(response.Error)
	if detail == "" {
		detail = strings.TrimSpace(response.Message)
	}
	if detail == "" {
		detail = "Agent did not acknowledge credential mutation"
	}
	return errors.New(detail)
}

// isInboundNotFoundErr 检测 forwardToRemoteServer 返回的"inbound 不存在"错误。
// 错误来源多个层,字面格式不固定:
//   - HTTP fallback 路径 → "remote server returned status 404: {\"error\":\"inbound XXX not found\"...}"
//   - WS-RPC HTTPLikeError → 同上
//   - WS-RPC reply.Error 透传 → "agent rpc error: inbound XXX not found"(无 status 前缀)
//   - 主控内部 helper(routed_outbound.go / packages.go)直接返 "inbound XXX not found"
//
// 统一只看子串 `inbound` + `not found` — 实际场景里这两个词共现都指向"agent 那边没这条 inbound",
// 误判风险接近零(没有其他业务流会用同样措辞)。
func isInboundNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "inbound") && strings.Contains(msg, "not found")
}
