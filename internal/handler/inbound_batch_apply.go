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

// collectInboundClientAddItem 从 master InboundCache 拿 protocol/settings，返回尚未
// 预留凭据的 batch item。**不调 agent / 不写 DB**；预留必须在 server lease 内完成。
//
// 返回 (nil, false, err):缓存 miss、已有凭据需刷新 deadline、入站不存在等 → fallback
// 返回 (nil, false, err):缓存 miss / 入站不存在等 → 调用方应 fallback 到逐个 addUserToInbound
// 返回 (item, true, nil):成功,加入 batch 列表
func collectInboundClientAddItem(ctx context.Context, cache *InboundCache, repo *storage.TrafficRepository, user storage.User, serverID int64, inboundTag string) (*InboundClientAddItem, bool, error) {
	if cache == nil {
		return nil, false, fmt.Errorf("inbound cache not available")
	}
	ib, ok := cache.GetInbound(serverID, inboundTag)
	if !ok {
		return nil, false, fmt.Errorf("inbound cache miss for server=%d tag=%s", serverID, inboundTag)
	}
	if err := validateClassicShadowsocksManagedSettings(ib.Protocol, ib.Settings); err != nil {
		return nil, false, err
	}

	// Existing credentials still need an idempotent Agent call: package renewal
	// or source coexistence may have changed their absolute deadline.
	existing, _ := repo.GetUserInboundConfig(ctx, user.Username, serverID, inboundTag)
	if existing != nil && existing.Protocol == ib.Protocol {
		return nil, false, fmt.Errorf("existing credential requires deadline refresh")
	}

	// The legacy batch endpoint has no acknowledged deadline contract. Any
	// expiring source must use add-client so an old Agent cannot silently accept
	// the credential while ignoring not_after.
	now := time.Now().UTC()
	hasManaged, managedExpiry, err := repo.HasEffectiveUserInboundAccess(ctx, user.Username, serverID, inboundTag, 0, now)
	if err != nil {
		return nil, false, err
	}
	hasDirect, directExpiry, err := repo.HasEffectiveDirectUserInboundAccess(ctx, user.Username, serverID, inboundTag, 0, now)
	if err != nil {
		return nil, false, err
	}
	hasIndependent, independentExpiry := laterOptionalExpiry(hasManaged, managedExpiry, hasDirect, directExpiry)
	hasPackage, packageExpiry, err := hasLegacyPackageInboundAccess(ctx, repo, user.Username, serverID, inboundTag, now)
	if err != nil {
		return nil, false, err
	}
	hasAccess, notAfter := laterOptionalExpiry(hasIndependent, independentExpiry, hasPackage, packageExpiry)
	if !hasAccess {
		return nil, false, errors.New("no active authorization for inbound")
	}
	if notAfter != nil {
		return nil, false, fmt.Errorf("expiring credential requires atomic add-client")
	}
	return &InboundClientAddItem{
		Username:   user.Username,
		ServerID:   serverID,
		InboundTag: inboundTag,
		Protocol:   ib.Protocol,
		Settings:   ib.Settings,
	}, true, nil
}

// applyInboundBatchOrFallback per-server 收集到的 inbound add-client items 一次 batch-apply 提交,
// 失败时降级到逐项 addUserToInbound(老 agent 不支持 batch-apply 也走这条)。
// 返回收集到的 warning(供前端 toast),空切片=全成功。
func applyInboundBatchOrFallback(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, serverID int64, items []InboundClientAddItem, label string) []string {
	if len(items) == 0 {
		return nil
	}
	var warnings []string
	err := withPreparedInboundBatchMutation(ctx, repo, serverID, items, func(leasedCtx context.Context, prepared []InboundClientAddItem) error {
		batchErr := applyInboundClientsBatchToAgentLocked(leasedCtx, rm, serverID, prepared)
		if batchErr == nil {
			return nil
		}
		if !errors.Is(batchErr, ErrAgentBatchNotSupported) {
			return batchErr
		}

		// The old-Agent fallback remains under the same user and server leases.
		// It is only used for an explicitly unsupported endpoint; a rejected or
		// malformed batch must surface as a failure instead of being retried as a
		// different mutation protocol.
		log.Printf("[%s] agent server=%d 不支持 batch-apply,fallback per-item", label, serverID)
		var fallbackErrs []error
		for _, it := range prepared {
			if ferr := applyPreparedInboundCredential(leasedCtx, rm, serverID, it.InboundTag, it.Credential, nil); ferr != nil {
				log.Printf("[%s] fallback add-client user=%s server=%d tag=%s: %v",
					label, it.Username, serverID, it.InboundTag, ferr)
				warnings = append(warnings, fmt.Sprintf("节点 %s 添加用户 %s 失败", it.InboundTag, it.Username))
				fallbackErrs = append(fallbackErrs, ferr)
			}
		}
		return errors.Join(fallbackErrs...)
	})
	if err != nil {
		log.Printf("[%s] inbound mutation server=%d failed: %v", label, serverID, err)
		if len(warnings) == 0 {
			if errors.Is(err, storage.ErrRemoteInstallationActive) {
				warnings = append(warnings, fmt.Sprintf("服务器 %d 正在安装，未执行套餐节点变更", serverID))
			} else {
				warnings = append(warnings, fmt.Sprintf("服务器 %d 套餐节点变更失败", serverID))
			}
		}
	}
	return warnings
}

// InboundClientAddItem 描述一次 per-server batch 中的单条"加 client"操作。
// 调用方按 ServerID 聚合后一次性传给 applyInboundClientsBatchToAgent。
//
// 字段使用规则:
//   - InboundTag / Credential 给 agent batch-apply 用,生成 add-client 操作
//   - Username / ServerID / Protocol / CredentialJSON 给 master DB 写 user_inbound_configs 用
//
// 调用方必须保证 (Username, ServerID, InboundTag) 三元组在 master DB 中**不存在**
// (即:已过滤 GetUserInboundConfig 返回非 nil 的情况),否则会写入重复行。
type InboundClientAddItem struct {
	Username       string
	ServerID       int64
	InboundTag     string
	Protocol       string
	Settings       map[string]interface{}
	Credential     map[string]interface{}
	CredentialJSON string
}

// withPreparedInboundBatchMutation holds the users' authorization leases and
// exactly one server mutation lease across entitlement revalidation,
// credential reservation, and Agent publication. The provisioning lease no
// longer owns the managed-node mutex, so SaveUserInboundConfig can safely take
// its narrower storage lock in this order.
func withPreparedInboundBatchMutation(ctx context.Context, repo *storage.TrafficRepository, serverID int64, items []InboundClientAddItem, action func(context.Context, []InboundClientAddItem) error) error {
	usernames := make([]string, 0, len(items))
	for _, item := range items {
		if item.ServerID != serverID {
			return fmt.Errorf("inbound batch item server=%d does not match transaction server=%d", item.ServerID, serverID)
		}
		usernames = append(usernames, item.Username)
	}
	return repo.WithUsersProvisioningLease(ctx, usernames, func() error {
		leasedCtx, release, err := repo.AcquireRemoteServerMutationLease(ctx, serverID)
		if err != nil {
			return err
		}
		defer release()

		prepared := make([]InboundClientAddItem, len(items))
		copy(prepared, items)
		for i := range prepared {
			user, err := repo.GetUser(leasedCtx, prepared[i].Username)
			if err != nil {
				return fmt.Errorf("load user %s: %w", prepared[i].Username, err)
			}
			hasAccess, notAfter, err := effectiveUserInboundAuthorization(
				leasedCtx, repo, prepared[i].Username, serverID, prepared[i].InboundTag, time.Now().UTC(),
			)
			if err != nil {
				return err
			}
			if !hasAccess || notAfter != nil {
				return fmt.Errorf("authorization changed before batch publication for user=%s inbound=%s", prepared[i].Username, prepared[i].InboundTag)
			}
			credential, credentialJSON, _, err := getOrCreateInboundCredential(
				leasedCtx, repo, user, serverID, prepared[i].InboundTag, prepared[i].Protocol, prepared[i].Settings,
			)
			if err != nil {
				return fmt.Errorf("reserve credential user=%s inbound=%s: %w", prepared[i].Username, prepared[i].InboundTag, err)
			}
			prepared[i].Credential = credential
			prepared[i].CredentialJSON = credentialJSON
		}
		return action(leasedCtx, prepared)
	})
}

// applyInboundClientsBatchToAgent 把同一 server 上多个用户加 client 的操作合并成 1 次
// POST /api/child/batch-apply,显著减少跨海外往返耗时:
//   - 现状:每个 (user, inbound) 一次 GET /api/child/inbounds + 一次 add-client → N 次 round-trip + agent inboundsMu 串行
//   - 改造:0 次 GET(cred 用 master InboundCache 算)+ 1 次 batch-apply → 整 server 1 次 round-trip
//
// 老 agent(无 batch-apply 端点)→ 返回 ErrAgentBatchNotSupported,caller 应 fallback 逐个 addUserToInbound。
// 凭据预留和 Agent ACK 都在同一台服务器的 mutation lease 内完成。入站
// client 变更由 Agent 走 HandlerService 热替换；无论幂等 no-op 还是运行时
// 延后，都不能为了补偿而启动或重启 Xray。
// Agent 任一 item 未确认即返回错误，不把部分失败伪装成成功。
func applyInboundClientsBatchToAgent(ctx context.Context, rm *RemoteManageHandler, repo *storage.TrafficRepository, serverID int64, items []InboundClientAddItem) error {
	if len(items) == 0 {
		return nil
	}
	return withPreparedInboundBatchMutation(ctx, repo, serverID, items, func(leasedCtx context.Context, prepared []InboundClientAddItem) error {
		return applyInboundClientsBatchToAgentLocked(leasedCtx, rm, serverID, prepared)
	})
}

func applyInboundClientsBatchToAgentLocked(ctx context.Context, rm *RemoteManageHandler, serverID int64, items []InboundClientAddItem) error {

	type batchInboundClient struct {
		Tag    string                 `json:"tag"`
		Client map[string]interface{} `json:"client"`
	}
	type batchReq struct {
		InboundClients []batchInboundClient `json:"inbound_clients"`
		// NoRestart=true:agent 端只 replaceRuntimeInbound 热更新,不重启 xray。
		// 加 client 是 HandlerService 热生效的场景,完全不需要 restart。
		NoRestart bool `json:"no_restart,omitempty"`
	}

	req := batchReq{NoRestart: true}
	for _, it := range items {
		if it.Credential == nil {
			return fmt.Errorf("inbound batch item user=%s tag=%s has no reserved credential", it.Username, it.InboundTag)
		}
		req.InboundClients = append(req.InboundClients, batchInboundClient{
			Tag:    it.InboundTag,
			Client: it.Credential,
		})
	}
	body, _ := json.Marshal(req)

	raw, err := rm.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/batch-apply", body)
	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "404") || strings.Contains(low, "not found") || strings.Contains(low, "method not allowed") {
			return ErrAgentBatchNotSupported
		}
		return fmt.Errorf("inbound batch-apply server=%d: %w", serverID, err)
	}

	var resp struct {
		Success         bool     `json:"success"`
		InboundResults  []string `json:"inbound_results"`
		RuntimeWarnings []string `json:"runtime_warnings"`
		Message         string   `json:"message"`
	}
	if jerr := json.Unmarshal(raw, &resp); jerr != nil {
		return fmt.Errorf("parse batch-apply response: %w", jerr)
	}
	if !resp.Success {
		return fmt.Errorf("batch-apply rejected: %s", resp.Message)
	}
	if len(resp.InboundResults) != len(items) {
		return fmt.Errorf("batch-apply returned incomplete item results")
	}
	for i, result := range resp.InboundResults {
		_, resultErr := validateAgentBatchItemResult(result)
		if resultErr != nil {
			return fmt.Errorf("batch-apply item %d failed: %w", i, resultErr)
		}
	}
	if len(resp.RuntimeWarnings) > 0 {
		// The durable config has already been updated. A stopped Xray can be an
		// intentional operator choice, so retain the Agent's deferred-recovery
		// path instead of turning a package mutation into an implicit start.
		log.Printf("[InboundBatchApply] server=%d Agent deferred inbound runtime apply; Xray lifecycle left unchanged: %s",
			serverID, strings.Join(resp.RuntimeWarnings, "; "))
	}

	return nil
}

func validateAgentBatchItemResult(result string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok":
		return false, nil
	case "ok (no-op)":
		return true, nil
	default:
		return false, fmt.Errorf("Agent returned unacknowledged result %q", result)
	}
}
