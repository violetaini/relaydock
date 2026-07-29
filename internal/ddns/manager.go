package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// Manager 把 agent IP 漂移信号转成 DNS provider API 调用。
// 与 IP 漂移检测路径(HeartbeatResult.IPChanged)解耦:心跳处理完调一次 Trigger 即可,
// 内部 per-server mutex 串行化同一 server 的并发调用(防 WS+HTTP 双心跳 race / IP 短时间连漂)。
type Manager struct {
	repo *storage.TrafficRepository
	mu   sync.Map // map[int64]*sync.Mutex,key=server_id
}

// NewManager 创建管理器。reconciler 不在这里启动,由调用方 main.go 显式 go StartReconciler(ctx)。
func NewManager(repo *storage.TrafficRepository) *Manager {
	return &Manager{repo: repo}
}

// Trigger 同步指定 server 的 DDNS(A + AAAA)。同步过程:
//
//  1. lock per-server mutex
//  2. mark pending(UI 显示"正在同步")
//  3. doSync:校验域名 → 取 provider 凭据 → upsert A(若有 v4)+ upsert AAAA(若有 v6)
//  4. 写回结果(成功/失败)
//
// 不阻塞调用方 — 用法是 `go manager.Trigger(ctx, server)`。
// 失败只 log,不返 error;靠 DDNSLastError 字段 + reconciler 重试。
func (m *Manager) Trigger(ctx context.Context, server *storage.RemoteServer) {
	if server == nil || !server.DDNSEnabled || strings.TrimSpace(server.PullAddress) == "" {
		return
	}
	lock := m.lockFor(server.ID)
	lock.Lock()
	defer lock.Unlock()

	_ = m.repo.MarkDDNSPending(ctx, server.ID)
	err := m.doSync(ctx, server)
	if err != nil {
		_ = m.repo.UpdateRemoteServerDDNSStatus(ctx, server.ID, err.Error())
		log.Printf("[DDNS] sync failed for server %s (id=%d): %v", server.Name, server.ID, err)
		return
	}
	_ = m.repo.UpdateRemoteServerDDNSStatus(ctx, server.ID, "")
	log.Printf("[DDNS] sync ok for server %s (id=%d) → %s", server.Name, server.ID, server.PullAddress)
}

// TriggerByID 给 reconciler / 手动测试 API 用 — 自己加载 server。
func (m *Manager) TriggerByID(ctx context.Context, serverID int64) {
	server, err := m.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		log.Printf("[DDNS] TriggerByID load server %d failed: %v", serverID, err)
		return
	}
	m.Trigger(ctx, server)
}

func (m *Manager) lockFor(id int64) *sync.Mutex {
	v, _ := m.mu.LoadOrStore(id, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// doSync 真正执行同步,返回业务级 error。任何步骤失败都不写 record — 例如 v4 失败就放弃 v6,
// 因为通常用户是同一份凭据 → 一处失败两处都会失败,继续只是雪上加霜。
func (m *Manager) doSync(ctx context.Context, server *storage.RemoteServer) error {
	fqdn := strings.TrimSpace(server.PullAddress)
	if ip := net.ParseIP(fqdn); ip != nil {
		return fmt.Errorf("pull_address is an IP %q, DDNS requires a domain name", fqdn)
	}

	providerID, err := m.resolveProviderID(ctx, server, fqdn)
	if err != nil {
		return err
	}
	provider, providerType, err := m.loadProvider(ctx, providerID)
	if err != nil {
		return err
	}

	// 同步 A(v4)+ AAAA(v6),哪个 record type 当次没 IP 就跳过(不删除已有记录)
	var syncErrs []string
	if v4 := strings.TrimSpace(server.IPAddress); v4 != "" && net.ParseIP(v4) != nil && net.ParseIP(v4).To4() != nil {
		if e := provider.UpsertRecord(ctx, fqdn, "A", v4, 0); e != nil {
			syncErrs = append(syncErrs, fmt.Sprintf("A: %v", e))
		}
	}
	if v6 := strings.TrimSpace(server.IPAddressV6); v6 != "" {
		if p := net.ParseIP(v6); p != nil && p.To4() == nil {
			if e := provider.UpsertRecord(ctx, fqdn, "AAAA", v6, 0); e != nil {
				syncErrs = append(syncErrs, fmt.Sprintf("AAAA: %v", e))
			}
		}
	}
	if len(syncErrs) > 0 {
		return fmt.Errorf("provider=%s: %s", providerType, strings.Join(syncErrs, "; "))
	}
	return nil
}

// resolveProviderID 决定用哪个 dns_providers 行:
//   - server.DDNSProviderID > 0 → 显式指定
//   - server.DDNSProviderID == 0 → 自动模式,从 FindCertificateForDomain 取证书的 dns_provider_id
func (m *Manager) resolveProviderID(ctx context.Context, server *storage.RemoteServer, fqdn string) (int64, error) {
	if server.DDNSProviderID > 0 {
		return server.DDNSProviderID, nil
	}
	cert, err := m.repo.FindCertificateForDomain(ctx, fqdn)
	if err != nil {
		return 0, fmt.Errorf("auto-resolve provider: no matching wildcard cert for %q: %w", fqdn, err)
	}
	if cert.DNSProviderID == 0 {
		return 0, fmt.Errorf("auto-resolve provider: matching cert %q has no DNS provider", cert.Domain)
	}
	return cert.DNSProviderID, nil
}

// loadProvider 拿凭据 → 构造 provider 实例。
// providerType 返回出来供错误日志用。
func (m *Manager) loadProvider(ctx context.Context, providerID int64) (Provider, string, error) {
	dp, err := m.repo.GetDNSProvider(ctx, providerID)
	if err != nil {
		return nil, "", fmt.Errorf("load dns_provider id=%d: %w", providerID, err)
	}
	creds := map[string]string{}
	if dp.Credentials != "" {
		if err := json.Unmarshal([]byte(dp.Credentials), &creds); err != nil {
			return nil, dp.ProviderType, fmt.Errorf("parse credentials JSON: %w", err)
		}
	}
	provider, err := NewProvider(dp.ProviderType, creds)
	if err != nil {
		return nil, dp.ProviderType, err
	}
	return provider, dp.ProviderType, nil
}

// StartReconciler 5 分钟周期重试所有 last_error != "" 的 server。
// 防止「DDNS 失败后 IPChanged 已消费,下次心跳 IP 没变 → 不会重试」的死锁。
// ctx 取消时退出。
func (m *Manager) StartReconciler(ctx context.Context) {
	const interval = 5 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("[DDNS] reconciler started, interval=%s", interval)
	for {
		select {
		case <-ctx.Done():
			log.Printf("[DDNS] reconciler stopped")
			return
		case <-ticker.C:
			m.runReconcile(ctx)
		}
	}
}

func (m *Manager) runReconcile(ctx context.Context) {
	candidates, err := m.repo.ListDDNSRetryCandidates(ctx)
	if err != nil {
		log.Printf("[DDNS] reconciler list candidates failed: %v", err)
		return
	}
	if len(candidates) == 0 {
		return
	}
	log.Printf("[DDNS] reconciler: %d candidate(s) to retry", len(candidates))
	for i := range candidates {
		// 每个 server 单独 goroutine,避免一个慢 provider 阻塞其他
		s := candidates[i]
		go m.Trigger(ctx, &s)
	}
}

// 静态检查 — 让 import 不会被 lint 删掉
var _ = errors.New
