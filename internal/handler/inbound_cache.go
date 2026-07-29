package handler

import (
	"context"
	"encoding/json"
	"log"
	"sync"

	"github.com/violetaini/relaydock/internal/storage"
)

// CachedInbound 是 inbound 在内存中的最小描述,只保留 generateCredential 真正需要的字段:
//   - Protocol: vless/vmess/trojan/shadowsocks/hysteria/... 决定 cred 形式
//   - Settings.method: shadowsocks 的 method,决定 password 字节长度
//
// 不存 clients 列表(那是 mutable 状态,放 user_inbound_configs 里);也不存 listen/port(查询用不到)。
type CachedInbound struct {
	Tag      string
	Protocol string
	Settings map[string]interface{}
}

// InboundCache: 主控全局 in-memory cache,key = serverID,value = (tag → CachedInbound)。
//
// 数据源:server_xray_config_snapshots.current 行的 config_json。
// 刷新点:任何 UpsertCurrentXraySnapshot 成功后都同步 SyncFromConfig 重建当 server 的索引。
// 命中场景:套餐绑/换绑 — 阶段一 in-memory 算 cred,阶段二 per-server batch-apply,
//
//	彻底避开"每个节点都 GET /api/child/inbounds"的 N 次往返。
type InboundCache struct {
	mu   sync.RWMutex
	data map[int64]map[string]CachedInbound
}

func NewInboundCache() *InboundCache {
	return &InboundCache{data: make(map[int64]map[string]CachedInbound)}
}

// GetInbound 返回 (inbound, ok)。miss 时 ok=false,调用方应 fallback 到 GET /api/child/inbounds。
func (c *InboundCache) GetInbound(serverID int64, tag string) (CachedInbound, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.data[serverID]
	if !ok {
		return CachedInbound{}, false
	}
	ib, ok := s[tag]
	return ib, ok
}

// ListServerInbounds 返回某 server 全部 cached inbounds(只读拷贝)。
func (c *InboundCache) ListServerInbounds(serverID int64) []CachedInbound {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.data[serverID]
	if !ok {
		return nil
	}
	out := make([]CachedInbound, 0, len(s))
	for _, ib := range s {
		out = append(out, ib)
	}
	return out
}

// SyncFromConfig 用一份完整 xray config.json 重建 server 的 inbound 索引(原子替换)。
// 解析失败 → 不动现有 cache(继续提供旧数据,等下次 sync)。
func (c *InboundCache) SyncFromConfig(serverID int64, configJSON string) {
	var cfg struct {
		Inbounds []struct {
			Tag      string                 `json:"tag"`
			Protocol string                 `json:"protocol"`
			Settings map[string]interface{} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		log.Printf("[InboundCache] sync server=%d parse failed (keeping previous data): %v", serverID, err)
		return
	}
	m := make(map[string]CachedInbound, len(cfg.Inbounds))
	for _, ib := range cfg.Inbounds {
		if ib.Tag == "" {
			continue
		}
		m[ib.Tag] = CachedInbound{Tag: ib.Tag, Protocol: ib.Protocol, Settings: ib.Settings}
	}
	c.mu.Lock()
	c.data[serverID] = m
	c.mu.Unlock()
}

// Invalidate 清掉 server 的 inbound 索引。一般用不到 — 通常 SyncFromConfig 直接覆盖即可。
// server 被删除时由调用方主动调一次确保不残留。
func (c *InboundCache) Invalidate(serverID int64) {
	c.mu.Lock()
	delete(c.data, serverID)
	c.mu.Unlock()
}

// WarmupFromDB 启动 / connect 时调一次,从 DB current snapshot 派生 cache,免去等下一次主控写才填充。
// 缓存空时调一次足够;后续刷新都走 SyncFromConfig。
func (c *InboundCache) WarmupFromDB(ctx context.Context, repo *storage.TrafficRepository, serverID int64) {
	if repo == nil {
		return
	}
	snap, err := repo.GetCurrentXraySnapshot(ctx, serverID)
	if err != nil || snap == nil {
		return
	}
	c.SyncFromConfig(serverID, snap.ConfigJSON)
}
