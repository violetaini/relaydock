package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

// DashboardWSHub 是面向浏览器的实时数据推送 hub:主控每隔「刷新间隔」算一次快照(服务器状态/网速/流量、
// 用户连接数),广播给所有已连接的浏览器,替代前端对 /api/admin/remote-servers 等接口的高频轮询。
// 惰性 ticker:仅在有客户端连接时运行;数据按 admin/user 角色区分。
type DashboardWSHub struct {
	repo           *storage.TrafficRepository
	servers        *XrayServerHandler // 复用 BuildRemoteServersList
	trafficSummary http.Handler       // /api/traffic/summary(admin 全局)
	trafficApi     http.Handler       // /api/admin/traffic(明细)
	servicesStatus http.Handler       // /api/admin/remote/services/status(慢通道,per-server)
	recoveryStatus http.Handler       // /api/admin/xray-snapshots/recovery-status(慢通道,per-server)
	ws             *RemoteWSHandler   // 判断服务器是否在线(仅对在线服务器查状态)
	allowedOrigins []string
	upgrader       websocket.Upgrader

	clients     sync.Map // int64 -> *dashClient
	nextID      atomic.Int64
	clientCount atomic.Int32

	tickerMu   sync.Mutex
	tickerStop chan struct{}
}

type dashClient struct {
	conn     *websocket.Conn
	isAdmin  bool
	username string
	writeMu  sync.Mutex
}

func (c *dashClient) send(v any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteJSON(v)
}

func NewDashboardWSHub(repo *storage.TrafficRepository, servers *XrayServerHandler, allowedOrigins []string) *DashboardWSHub {
	h := &DashboardWSHub{
		repo:           repo,
		servers:        servers,
		allowedOrigins: allowedOrigins,
	}
	h.upgrader = websocket.Upgrader{CheckOrigin: h.checkOrigin}
	return h
}

// SetTrafficHandlers 注入 traffic 相关 handler(它们在 hub 之后构造),用于快照复用其 JSON 输出。
func (h *DashboardWSHub) SetTrafficHandlers(summary, api http.Handler) {
	h.trafficSummary = summary
	h.trafficApi = api
}

// SetStatusHandlers 注入慢通道 handler(services/status、recovery-status)+ WS handler(判在线)。
func (h *DashboardWSHub) SetStatusHandlers(services, recovery http.Handler, ws *RemoteWSHandler) {
	h.servicesStatus = services
	h.recoveryStatus = recovery
	h.ws = ws
}

// callJSON 用内存 recorder 以指定用户名身份调用现有 handler,拿到其 JSON(复用逻辑、不复制、不漂移)。
// 带 8s 超时,防某个慢 handler(如外部订阅拉取)拖住整个快照。
func (h *DashboardWSHub) callJSON(handler http.Handler, target, username string) json.RawMessage {
	if handler == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(auth.ContextWithUsername(context.Background(), username), 8*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return nil
	}
	return json.RawMessage(rec.Body.Bytes())
}

// checkOrigin:本 WS 用 URL query 里的 token 鉴权(非 ambient cookie),跨站页面拿不到 token,
// 天然不存在跨站 WS 劫持(CSWSH),故无需 Origin 校验 —— 与现有 agent/测速 WS 一致返回 true。
// (曾做「Origin host == 请求 Host」同源校验,但在 CDN/反代改写 Host 时会误拒合法连接。)
func (h *DashboardWSHub) checkOrigin(r *http.Request) bool {
	return true
}

func (h *DashboardWSHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 鉴权由 auth.RequireToken 中间件在 upgrade 前完成,username 已注入 ctx。
	username := auth.UsernameFromContext(r.Context())
	isAdmin := username == "api-token-admin" || userIsAdmin(r.Context(), h.repo, username)

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &dashClient{conn: conn, isAdmin: isAdmin, username: username}
	id := h.nextID.Add(1)
	h.clients.Store(id, c)
	if h.clientCount.Add(1) == 1 {
		h.startTicker()
	}
	// 连接后立刻推一帧,避免等一个 tick 才有数据
	h.pushTo(c)
	// admin 连接:异步触发一次慢通道,让新客户端尽快拿到 per-server 状态(否则要等最多 15s)。
	if isAdmin {
		go h.broadcastServerStatus()
	}

	defer func() {
		conn.Close()
		h.clients.Delete(id)
		if h.clientCount.Add(-1) == 0 {
			h.stopTicker()
		}
	}()

	conn.SetReadLimit(16 * 1024)
	_ = conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		return nil
	})
	// 读循环:只用于保活(客户端定期发 ping)与检测断连;任何消息刷新读超时。
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	}
}

func (h *DashboardWSHub) startTicker() {
	h.tickerMu.Lock()
	defer h.tickerMu.Unlock()
	if h.tickerStop != nil {
		return
	}
	stop := make(chan struct{})
	h.tickerStop = stop
	// 快通道:服务器状态/网速/流量 + 连接数 + 汇总/明细,跟随刷新间隔。
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(h.refreshInterval()):
				h.broadcastSnapshot()
			}
		}
	}()
	// 慢通道:per-server services/status + recovery-status,固定 15s(消 N+1)。
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(15 * time.Second):
				h.broadcastServerStatus()
			}
		}
	}()
}

func (h *DashboardWSHub) stopTicker() {
	h.tickerMu.Lock()
	defer h.tickerMu.Unlock()
	if h.tickerStop != nil {
		close(h.tickerStop)
		h.tickerStop = nil
	}
}

// refreshInterval 跟随系统设置 dashboard_refresh_interval_ms(与前端原轮询同频),clamp [1s,60s]。
func (h *DashboardWSHub) refreshInterval() time.Duration {
	ms := 1000
	if v, _ := h.repo.GetSystemSetting(context.Background(), "dashboard_refresh_interval_ms"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1000 && n <= 60000 {
			ms = n
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// buildAdminSnapshot 组装管理员实时快照(服务器状态/网速/流量 + 用户连接数 + 流量汇总 + 明细)。
// username 为代表性 admin 用户名(admin 视图均为全局,任一 admin 结果一致),用于 recorder 调用鉴权。
func (h *DashboardWSHub) buildAdminSnapshot(ctx context.Context, username string) map[string]any {
	snap := map[string]any{
		"type":            "realtime",
		"servers":         h.servers.BuildRemoteServersList(ctx).Servers,
		"userConnections": AggregateUserConnCounts(),
	}
	if s := h.callJSON(h.trafficSummary, "/api/traffic/summary", username); s != nil {
		snap["trafficSummary"] = s
	}
	if a := h.callJSON(h.trafficApi, "/api/admin/traffic", username); a != nil {
		snap["adminTraffic"] = a
	}
	// node-totals:推「今天」基线(前端默认 timeRange=today,snapshotDate 用 UTC 日期,这里必须同为 UTC 才能对上 query key)。
	// week/month 基线仍走前端轮询(值随实时累计变,但非默认视图,不为它三倍计算)。
	today := time.Now().UTC().Format("2006-01-02")
	if nt := h.callJSON(h.trafficApi, "/api/admin/traffic/node-totals?date="+today, username); nt != nil {
		snap["nodeTotals"] = nt
		snap["nodeTotalsDate"] = today
	}
	return snap
}

func (h *DashboardWSHub) broadcastSnapshot() {
	ctx := context.Background()
	var adminMsg map[string]any // 惰性构建:只有 admin 连接时才算一次
	h.clients.Range(func(_, v any) bool {
		c := v.(*dashClient)
		if c.isAdmin {
			if adminMsg == nil {
				adminMsg = h.buildAdminSnapshot(ctx, c.username)
			}
			_ = c.send(adminMsg)
		}
		return true
	})
}

// broadcastToAdmins 向所有 admin 连接发一帧。
func (h *DashboardWSHub) broadcastToAdmins(msg any) {
	h.clients.Range(func(_, v any) bool {
		c := v.(*dashClient)
		if c.isAdmin {
			_ = c.send(msg)
		}
		return true
	})
}

// representativeAdmin 返回任一在线 admin 用户名(admin 视图全局一致),没有则空串。
func (h *DashboardWSHub) representativeAdmin() string {
	username := ""
	h.clients.Range(func(_, v any) bool {
		c := v.(*dashClient)
		if c.isAdmin {
			username = c.username
			return false
		}
		return true
	})
	return username
}

// broadcastServerStatus 慢通道:主控每 15s 自己对每台在线服务器查一次 services/status + recovery-status,
// 广播给 admin,替代「每浏览器 × 每服务器」的 N+1 轮询。并发上限 5,单次查询走 callJSON 的 8s 超时。
func (h *DashboardWSHub) broadcastServerStatus() {
	if h.servicesStatus == nil && h.recoveryStatus == nil {
		return
	}
	admin := h.representativeAdmin()
	if admin == "" {
		return // 没有 admin 连接就不查(避免无谓打 agent)
	}
	servers, err := h.repo.ListRemoteServers(context.Background())
	if err != nil {
		return
	}
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for _, s := range servers {
		if h.ws == nil || !h.ws.IsConnected(s.Token) {
			continue // 仅对在线服务器查
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id int64) {
			defer wg.Done()
			defer func() { <-sem }()
			msg := map[string]any{"type": "server-status", "serverId": id}
			if v := h.callJSON(h.servicesStatus, fmt.Sprintf("/api/admin/remote/services/status?server_id=%d", id), admin); v != nil {
				msg["services"] = v
			}
			if v := h.callJSON(h.recoveryStatus, fmt.Sprintf("/api/admin/xray-snapshots/recovery-status?server_id=%d", id), admin); v != nil {
				msg["recovery"] = v
			}
			h.broadcastToAdmins(msg)
		}(s.ID)
	}
	wg.Wait()
}

func (h *DashboardWSHub) pushTo(c *dashClient) {
	if c.isAdmin {
		_ = c.send(h.buildAdminSnapshot(context.Background(), c.username))
	}
}
