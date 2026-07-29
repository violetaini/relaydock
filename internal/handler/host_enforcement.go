package handler

// 应用层 host 拦截:HTTPS 启用后,只允许 Host header 匹配 master_url 域名的请求
// (或来自 loopback 的本机自调用),其它一律 308 重定向到正确的 https URL。
//
// 历史背景:
//   早期实现是 master 启动时绑 127.0.0.1,物理层禁止 IP+端口直连。但这套实现
//   在 Docker 部署下会让 -p 端口映射失效(容器内的 lo 跟 host 端口隔绝),所以
//   把"防 IP 直连"挪到应用层,跟 bind host 解耦:
//     - master 总是绑 0.0.0.0(网络层尽量通用)
//     - 应用层根据 master_url 配置决定拒不拒
//
// 设计要点:
//   - 仅当 master_url 以 https:// 开头时才生效(纯 HTTP 部署 / 初装阶段全放行)
//   - 缓存 5min(读 system_settings 不便每请求都查 db);改设置后短暂延迟生效
//   - loopback 来源永远放行 — 容器健康检查 / 同主机 nginx 反代 / master 自调用需要
//   - Host 不匹配时 308 重定向到正确 https URL — 用户即便误用 IP 也会被引到对的入口

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// hostEnforcer 中间件状态。
type hostEnforcer struct {
	repo *storage.TrafficRepository

	mu              sync.RWMutex
	cachedMasterURL string
	cachedHost      string // master_url 的 host(不含端口)
	cachedHTTPS     bool
	lastRefresh     time.Time
	// pendingRefresh 用于避免雷暴 — 多请求同时发现缓存过期时只有一个去查 db
	pendingRefresh atomic.Bool
}

const masterURLCacheTTL = 5 * time.Minute

// EnforceHTTPSHost 包一层中间件:HTTPS 启用时拒绝非合法 Host 的请求(loopback 除外)。
// 通常用法:srv.Handler = EnforceHTTPSHost(mux, repo)。
func EnforceHTTPSHost(next http.Handler, repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		// 没 repo 没法判定,直接透传
		return next
	}
	e := &hostEnforcer{repo: repo}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.shouldBlock(r) {
			// 308 把请求重定向到正确的 https URL,保留 path + query。
			// 用 308(Permanent)而不是 302 — 表达"这个域名是永久正确入口",
			// 浏览器/客户端可以缓存 redirect,减少后续无效命中。
			target := e.canonicalURL() + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// shouldBlock 返回 true 表示该请求被拦截 + 重定向。
func (e *hostEnforcer) shouldBlock(r *http.Request) bool {
	host, https := e.snapshot()
	if !https || host == "" {
		return false
	}
	// loopback 来源放行
	if remoteIPIsLoopback(r.RemoteAddr) {
		return false
	}
	// Host 比对(忽略端口、忽略大小写)
	got := stripPort(r.Host)
	if strings.EqualFold(got, host) {
		return false
	}
	return true
}

// snapshot 返回缓存的 (期望 host, 是否启用 https)。过期就异步刷新 + 同步用旧值
// (启动后第一次请求会同步拉一次以保证立刻可用)。
func (e *hostEnforcer) snapshot() (string, bool) {
	e.mu.RLock()
	expired := time.Since(e.lastRefresh) > masterURLCacheTTL
	host, https := e.cachedHost, e.cachedHTTPS
	firstTime := e.lastRefresh.IsZero()
	e.mu.RUnlock()

	if firstTime {
		// 同步刷一次,避免启动后短暂"全放行"
		e.refresh()
		e.mu.RLock()
		host, https = e.cachedHost, e.cachedHTTPS
		e.mu.RUnlock()
		return host, https
	}
	if expired && e.pendingRefresh.CompareAndSwap(false, true) {
		go func() {
			defer e.pendingRefresh.Store(false)
			e.refresh()
		}()
	}
	return host, https
}

func (e *hostEnforcer) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := e.repo.GetSystemSetting(ctx, "master_url")
	if err != nil {
		// 读不到先按"未启用"处理,5 分钟后下次再试
		e.mu.Lock()
		e.cachedMasterURL = ""
		e.cachedHost = ""
		e.cachedHTTPS = false
		e.lastRefresh = time.Now()
		e.mu.Unlock()
		return
	}
	masterURL := strings.TrimSpace(raw)
	https := strings.HasPrefix(masterURL, "https://")
	var host string
	if https {
		if u, perr := url.Parse(masterURL); perr == nil {
			host = stripPort(u.Host)
		}
	}
	e.mu.Lock()
	if e.cachedMasterURL != masterURL {
		log.Printf("[HostEnforcement] master_url=%q https=%v host=%q", masterURL, https, host)
	}
	e.cachedMasterURL = masterURL
	e.cachedHost = host
	e.cachedHTTPS = https
	e.lastRefresh = time.Now()
	e.mu.Unlock()
}

// canonicalURL 返回正确的 master_url 前缀(无尾斜杠),供 redirect 用。
func (e *hostEnforcer) canonicalURL() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return strings.TrimRight(e.cachedMasterURL, "/")
}

// stripPort 从 "host:port" 或 "[::1]:port" 中取 host 部分,失败时原样返回。
func stripPort(s string) string {
	if s == "" {
		return s
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// remoteIPIsLoopback 解析 r.RemoteAddr 的 IP 部分,判断是否 loopback (127.0.0.0/8 / ::1)。
// nginx 反代同主机时 RemoteAddr 是 127.0.0.1;Docker 容器内健康检查也是 loopback。
func remoteIPIsLoopback(remoteAddr string) bool {
	if remoteAddr == "" {
		return false
	}
	ipStr := stripPort(remoteAddr)
	ipStr = strings.Trim(ipStr, "[]")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
