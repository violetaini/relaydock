package handler

import (
	"context"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/logger"
)

var globalSubscriptionRateLimiter *SubscriptionRateLimiter

func GetSubscriptionRateLimiter() *SubscriptionRateLimiter {
	return globalSubscriptionRateLimiter
}

// SubscriptionRateLimiter 对"获取订阅"类请求(短链接 /x/、临时订阅 /t/、/api/clash/subscribe 等)
// 做每 IP 频率限制,防止枚举/抓取滥用。固定窗口计数。
type subRateRecord struct {
	count       int
	windowStart time.Time
}

type SubscriptionRateLimiter struct {
	mu      sync.Mutex
	ips     map[string]*subRateRecord
	enabled bool
	limit   int
	window  time.Duration
	// skipLocalIP 命中本地/私有 IP 时直接 Allow,
	// 防反代未传 XFF 时全员共享一个内网 IP 一起被 429。默认 true。
	skipLocalIP bool
}

// NewSubscriptionRateLimiter limit=窗口内最大请求数,window=窗口时长。
func NewSubscriptionRateLimiter(limit int, window time.Duration) *SubscriptionRateLimiter {
	if limit <= 0 {
		limit = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	l := &SubscriptionRateLimiter{
		ips:         make(map[string]*subRateRecord),
		enabled:     true,
		limit:       limit,
		window:      window,
		skipLocalIP: true,
	}
	globalSubscriptionRateLimiter = l
	return l
}

// NewSubscriptionRateLimiterWithConfig 用 system_settings 自定义阈值构造。
func NewSubscriptionRateLimiterWithConfig(enabled bool, limit, windowMinutes int) *SubscriptionRateLimiter {
	if limit <= 0 {
		limit = 60
	}
	if windowMinutes <= 0 {
		windowMinutes = 1
	}
	l := &SubscriptionRateLimiter{
		ips:         make(map[string]*subRateRecord),
		enabled:     enabled,
		limit:       limit,
		window:      time.Duration(windowMinutes) * time.Minute,
		skipLocalIP: true,
	}
	globalSubscriptionRateLimiter = l
	return l
}

// SetSkipLocalIP 切换"是否跳过本地/私有 IP 的频率限制"。
func (l *SubscriptionRateLimiter) SetSkipLocalIP(skip bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.skipLocalIP = skip
}

// UpdateConfig 热更新参数 — security_settings handler PUT 后调用。
func (l *SubscriptionRateLimiter) UpdateConfig(enabled bool, limit, windowMinutes int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
	if limit > 0 {
		l.limit = limit
	}
	if windowMinutes > 0 {
		l.window = time.Duration(windowMinutes) * time.Minute
	}
}

// Allow 返回该 IP 此刻是否允许再发起一次订阅获取。
func (l *SubscriptionRateLimiter) Allow(ip string) bool {
	if ip == "" {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.enabled {
		return true
	}
	if l.skipLocalIP && IsLocalOrPrivateIP(ip) {
		return true
	}

	rec, ok := l.ips[ip]
	if !ok || now.Sub(rec.windowStart) > l.window {
		l.ips[ip] = &subRateRecord{count: 1, windowStart: now}
		return true
	}
	rec.count++
	if rec.count > l.limit {
		if rec.count == l.limit+1 {
			logger.Warn("🚦 [SUB_RATE] 订阅获取频率超限,已限流", "ip", ip, "limit", l.limit, "window", l.window.String())
		}
		return false
	}
	return true
}

// StartCleanup 定期清理过期 IP 记录,避免 map 无限增长。
func (l *SubscriptionRateLimiter) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			l.mu.Lock()
			for ip, rec := range l.ips {
				if now.Sub(rec.windowStart) > l.window {
					delete(l.ips, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}
