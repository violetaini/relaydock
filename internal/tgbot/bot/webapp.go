package bot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

// Telegram Mini App 后端，直接挂载到主控 HTTP 路由：
//   GET /tg-app           → 返回单页前端
//   GET /api/tg-webapp/me → 校验 Telegram initData(用 bot 自己的 token)→ 反查账号 → 聚合返回
// 免登录:initData 由 Telegram 用 bot token 签名,校验通过即可信任其中的 telegram_id。

func (s *Service) newWebAppHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/tg-app", s.webAppPage)
	mux.HandleFunc("/api/tg-webapp/logo-light", s.webAppLogoLight)
	mux.HandleFunc("/api/tg-webapp/logo-dark", s.webAppLogoDark)
	// API 端点统一 per-IP 限流(60 次/分)。
	mux.HandleFunc("/api/tg-webapp/me", webRL(s.webAppMe))
	mux.HandleFunc("/api/tg-webapp/register", webRL(s.webAppRegister))
	mux.HandleFunc("/api/tg-webapp/redeem", webRL(s.webAppRedeem))
	mux.HandleFunc("/api/tg-webapp/admin/invites", webRL(s.webAppAdminInvites))
	mux.HandleFunc("/api/tg-webapp/admin/invite-create", webRL(s.webAppAdminInviteCreate))
	mux.HandleFunc("/api/tg-webapp/admin/invite-revoke", webRL(s.webAppAdminInviteRevoke))
	mux.HandleFunc("/api/tg-webapp/admin/invite-delete", webRL(s.webAppAdminInviteDelete))
	// 管理员用户管理:搜索(列全量前端过滤)/ 续期 / 改套餐
	mux.HandleFunc("/api/tg-webapp/admin/users", webRL(s.webAppAdminUsers))
	mux.HandleFunc("/api/tg-webapp/admin/user-extend", webRL(s.webAppAdminUserExtend))
	mux.HandleFunc("/api/tg-webapp/admin/user-assign", webRL(s.webAppAdminUserAssign))
	mux.HandleFunc("/api/tg-webapp/admin/announce", webRL(s.webAppAdminAnnounce))
	mux.HandleFunc("/api/tg-webapp/admin/announcements", webRL(s.webAppAdminAnnouncementsList))
	mux.HandleFunc("/api/tg-webapp/admin/announce-delete", webRL(s.webAppAdminAnnounceDelete))
	mux.HandleFunc("/api/tg-webapp/admin/xray-control", webRL(s.webAppAdminXrayControl))

	return mux
}

// validateInitData 按 Telegram 规范校验 initData,返回可信的 telegram_id 和 @handle。
// secret = HMAC_SHA256(key="WebAppData", msg=botToken);hash = HMAC_SHA256(key=secret, msg=data_check_string)。
func validateInitData(initData, botToken string) (int64, string, error) {
	if initData == "" || botToken == "" {
		return 0, "", errors.New("empty init data or token")
	}
	if len(initData) > 16*1024 {
		return 0, "", errors.New("init data too large")
	}
	parsed, err := url.ParseQuery(initData)
	if err != nil {
		return 0, "", err
	}
	hash := parsed.Get("hash")
	if hash == "" || len(parsed["hash"]) != 1 {
		return 0, "", errors.New("missing or duplicate hash")
	}

	pairs := make([]string, 0, len(parsed))
	for k, vs := range parsed {
		if k == "hash" {
			continue
		}
		if len(vs) != 1 {
			return 0, "", errors.New("duplicate init data field")
		}
		pairs = append(pairs, k+"="+vs[0])
	}
	sort.Strings(pairs)
	dcs := strings.Join(pairs, "\n")

	secret := hmacSum([]byte("WebAppData"), []byte(botToken))
	calc := hex.EncodeToString(hmacSum(secret, []byte(dcs)))
	if !hmac.Equal([]byte(calc), []byte(hash)) {
		return 0, "", errors.New("bad signature")
	}

	// 时效:拒绝缺失、无效、超过 24h 或明显来自未来的 initData,防重放。
	authDate := parsed.Get("auth_date")
	sec, err := strconv.ParseInt(authDate, 10, 64)
	if err != nil || authDate == "" {
		return 0, "", errors.New("invalid auth date")
	}
	age := time.Since(time.Unix(sec, 0))
	if age > 24*time.Hour {
		return 0, "", errors.New("init data expired")
	}
	if age < -5*time.Minute {
		return 0, "", errors.New("init data from future")
	}

	var u struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	if e := json.Unmarshal([]byte(parsed.Get("user")), &u); e != nil || u.ID == 0 {
		return 0, "", errors.New("no user id")
	}
	return u.ID, u.Username, nil
}

func hmacSum(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// devPreviewInitData 是本地浏览器预览时前端注入的哨兵值(见 webapp_page.go 的 __DEVPREVIEW__ 分支)。
const devPreviewInitData = "__devpreview__"

// validateRequestInitData 只对显式启用的本机预览开放哨兵值。
// 同时检查 TCP 对端与 Host，防止公网请求经本机反代后被误当作 loopback。
func (s *Service) validateRequestInitData(r *http.Request, initData string) (int64, string, error) {
	if s.cfg.WebAppDevPreview && initData == devPreviewInitData {
		if !isLoopbackRequest(r) {
			return 0, "", errors.New("dev preview requires loopback request")
		}
		if len(s.cfg.AdminTGIDs) == 0 {
			return 0, "", errors.New("dev preview 需在 admin_tg_ids 配置至少一个管理员")
		}
		return s.cfg.AdminTGIDs[0], "devpreview", nil
	}
	return validateInitData(initData, s.cfg.TGBotToken)
}

// isLoopbackRequest intentionally does not trust forwarded headers. A local
// reverse proxy may have a loopback peer while serving the public hostname, so
// both the peer address and the requested Host must identify the local machine.
func isLoopbackRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	peer := remoteIP(r.RemoteAddr)
	if peer == nil || !peer.IsLoopback() {
		return false
	}
	// A public request reaching a local reverse proxy has a loopback peer, but
	// the proxy records the real external address in these headers. Do not let
	// a caller combine that peer with a forged `Host: localhost`.
	if raw := strings.TrimSpace(r.Header.Get("X-Real-IP")); raw != "" {
		ip := parseForwardedIP(raw)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	if raw := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); raw != "" {
		parts := strings.Split(raw, ",")
		for _, part := range parts {
			ip := parseForwardedIP(part)
			if ip == nil || !ip.IsLoopback() {
				return false
			}
		}
	}
	return isLoopbackHost(r.Host)
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if parsed, err := url.Parse("//" + host); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.Trim(host, "[]")
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func remoteIP(remoteAddr string) net.IP {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = strings.Trim(remoteAddr, "[]")
	}
	return net.ParseIP(strings.TrimSpace(host))
}

// webAppMe 校验 initData → 反查账号 → 聚合账号/流量/节点/订阅。
func (s *Service) webAppMe(w http.ResponseWriter, r *http.Request) {
	initData := r.Header.Get("X-Telegram-Init-Data")
	if initData == "" {
		initData = r.URL.Query().Get("initData")
	}
	tgID, handle, err := s.validateRequestInitData(r, initData)
	if err != nil {
		writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	ctx := r.Context()
	info, err := s.client.UserByTG(ctx, tgID)
	if err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": "查询失败"})
		return
	}
	if !info.Bound {
		// 管理员未绑定时，自动绑定到主控管理员账号后再查询。
		if s.cfg.IsAdmin(tgID) {
			if _, berr := s.client.BindAdmin(ctx, tgID, handle); berr == nil {
				if re, rerr := s.client.UserByTG(ctx, tgID); rerr == nil {
					info = re
				}
			}
		}
		if !info.Bound {
			writeJSONResp(w, http.StatusOK, map[string]any{"bound": false})
			return
		}
	}
	username := info.Username

	resp := map[string]any{"bound": true, "is_admin": s.cfg.IsAdmin(tgID)}

	// 账号 + 流量 + 套餐
	if summary, err := s.client.UserSummary(ctx, username); err == nil {
		resp["account"] = map[string]any{
			"username":  summary.Username,
			"role":      summary.Role,
			"is_active": summary.IsActive,
			"email":     summary.Email,
		}
		pkgName, limitGB := "", 0.0
		if summary.Package != nil {
			if v, ok := summary.Package["name"].(string); ok {
				pkgName = v
			}
			if v, ok := summary.Package["traffic_limit_gb"].(float64); ok {
				limitGB = v
			}
		}
		traffic := map[string]any{
			"package_name": pkgName,
			"limit_gb":     limitGB,
			"cycle_used":   summary.Traffic.CycleUplink + summary.Traffic.CycleDownlink,
			"total_up":     summary.Traffic.TotalUplink,
			"total_down":   summary.Traffic.TotalDownlink,
		}
		if summary.PackageEndDate != "" {
			traffic["end_date"] = summary.PackageEndDate
			if d, ok := daysUntil(summary.PackageEndDate); ok {
				traffic["days_left"] = d
			}
		}
		resp["traffic"] = traffic
	}

	// 套餐周期内每日用量(首页曲线)
	history := []map[string]any{}
	if hist, err := s.client.UserDailyTraffic(ctx, username); err == nil {
		for _, d := range hist {
			history = append(history, map[string]any{"date": d.Date, "used_gb": d.UsedGB})
		}
	}
	resp["history"] = history

	// 各节点已用流量(主页用)
	nodes := []map[string]any{}
	if items, err := s.client.UserNodeTraffic(ctx, username); err == nil {
		for _, n := range items {
			nodes = append(nodes, map[string]any{
				"name": n.NodeName,
				"used": n.Uplink + n.Downlink,
			})
		}
	}
	resp["nodes"] = nodes

	// 各节点在线状态(状态页用)。server_status 为空 = 外部/未托管节点,无状态 → unknown。
	nodeStatus := []map[string]any{}
	if nr, err := s.client.UserNodes(ctx, username); err == nil {
		for _, n := range nr.Nodes {
			st := "offline"
			if n.ServerOnline {
				st = "online"
			} else if strings.TrimSpace(n.ServerStatus) == "" {
				st = "unknown"
			}
			nodeStatus = append(nodeStatus, map[string]any{
				"name": n.Name, "protocol": n.Protocol, "status": st,
			})
		}
	}
	resp["node_status"] = nodeStatus

	// 订阅(默认订阅在前)
	base := strings.TrimRight(s.cfg.PublicBaseURL, "/") + "/x"
	subs := []map[string]any{}
	if sr, err := s.client.UserSubscriptions(ctx, username); err == nil {
		if sr.DefaultSubscription != nil {
			subs = append(subs, map[string]any{
				"name": sr.DefaultSubscription.Name, "default": true,
				"url": base + "/" + sr.DefaultSubscription.CombinedCode,
			})
		}
		for _, sf := range sr.Subscriptions {
			subs = append(subs, map[string]any{
				"name": sf.Name, "default": false,
				"url": base + "/" + sf.CombinedCode,
			})
		}
	}
	resp["subscriptions"] = subs

	// 管理员主页始终使用全局视图：订阅管理第一条、所有非零流量节点、全部服务器状态。
	if s.cfg.IsAdmin(tgID) {
		resp["subscriptions"] = []map[string]any{}
		if sv, err := s.client.GetAdminSubview(ctx, username); err == nil && sv != nil {
			if sv.Subscription != nil {
				resp["subscriptions"] = []map[string]any{{
					"name": sv.Subscription.Name, "default": false,
					"url": base + "/" + sv.Subscription.CombinedCode,
				}}
			}
		}

		adminNodes := []map[string]any{}
		if items, err := s.client.AdminMonthlyNodeTraffic(ctx); err == nil {
			for _, n := range items {
				used := n.Uplink + n.Downlink
				if used <= 0 {
					continue
				}
				adminNodes = append(adminNodes, map[string]any{"name": n.NodeName, "used": used})
			}
		}
		resp["nodes"] = adminNodes
		resp["traffic_period"] = "month"

		serverStatuses := []map[string]any{}
		if servers, err := s.client.RemoteServers(ctx); err == nil {
			for _, server := range servers {
				status := "offline"
				if strings.EqualFold(strings.TrimSpace(server.Status), "connected") {
					status = "online"
				}
				serverStatuses = append(serverStatuses, map[string]any{
					"id": server.ID, "name": server.Name, "status": status,
					"xray_running": server.XrayRunning,
				})
			}
		}
		resp["node_status"] = serverStatuses
		resp["status_kind"] = "server"
	}

	// 生效公告(按套餐/节点归属定向)→ Mini App 首页横幅
	if anns, aerr := s.client.ActiveAnnouncements(ctx, username); aerr == nil && len(anns) > 0 {
		list := make([]map[string]any, 0, len(anns))
		for _, a := range anns {
			list = append(list, map[string]any{"type": a.Type, "title": a.Title, "body": a.Body})
		}
		resp["announcements"] = list
	}

	writeJSONResp(w, http.StatusOK, resp)
}

// webAppAdminXrayControl 为管理员状态页提供 Xray 启停。
// 身份只信任 Telegram 签名后的 tgID，不接受前端传入的管理员标记。
func (s *Service) webAppAdminXrayControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	var body struct {
		ServerID int64  `json:"server_id"`
		Action   string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ServerID <= 0 {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "无效的服务器"})
		return
	}
	body.Action = strings.ToLower(strings.TrimSpace(body.Action))
	if body.Action != "start" && body.Action != "stop" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "action 仅支持 start 或 stop"})
		return
	}
	if err := s.client.ControlXray(r.Context(), body.ServerID, body.Action); err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"success": true, "server_id": body.ServerID, "xray_running": body.Action == "start",
	})
}

// webAppRegister 未绑定用户在 Mini App 内用「邀请码+用户名+密码」注册并绑定 TG。
func (s *Service) webAppRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	initData := r.Header.Get("X-Telegram-Init-Data")
	tgID, handle, err := s.validateRequestInitData(r, initData)
	if err != nil {
		writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var body struct {
		Code     string `json:"code"`
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}

	resp, err := s.client.Bind(r.Context(), mmwxclient.BindRequest{
		Code:           strings.ToUpper(strings.TrimSpace(body.Code)),
		TelegramID:     tgID,
		TelegramHandle: handle,
		Username:       strings.TrimSpace(body.Username),
		Email:          strings.TrimSpace(body.Email),
		Password:       body.Password,
	})
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true, "username": resp.Username})
}

// webAppRedeem 已绑定用户用兑换码续期。
func (s *Service) webAppRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	tgID, _, err := s.validateRequestInitData(r, r.Header.Get("X-Telegram-Init-Data"))
	if err != nil {
		writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Code) == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "请输入兑换码"})
		return
	}
	res, err := s.client.Redeem(r.Context(), strings.ToUpper(strings.TrimSpace(body.Code)), tgID)
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"success": true, "username": res.Username, "end_date": res.EndDate, "package_name": res.PackageName,
	})
}

// adminTGID 校验 initData 且要求是管理员;失败时已写好响应并返回 ok=false。
// 授权严格服务端判定(从签名校验出的 tgID),不信任任何前端标志。
func (s *Service) adminTGID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	tgID, _, err := s.validateRequestInitData(r, r.Header.Get("X-Telegram-Init-Data"))
	if err != nil {
		writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return 0, false
	}
	if !s.cfg.IsAdmin(tgID) {
		writeJSONResp(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return 0, false
	}
	return tgID, true
}

// webAppAdminAnnounce 管理员在 Mini App 内发布公告(广播 + 横幅)。
func (s *Service) webAppAdminAnnounce(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	var body struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Body) == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "请输入公告内容"})
		return
	}
	title := strings.TrimSpace(body.Title)
	if title == "" {
		title = "公告"
	}
	if err := s.client.PostAnnouncement(r.Context(), title, strings.TrimSpace(body.Body)); err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true})
}

// webAppAdminAnnouncementsList 管理员在 Mini App 查看当前生效公告(列表)。
func (s *Service) webAppAdminAnnouncementsList(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	items, err := s.client.ListAnnouncements(r.Context())
	if err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	list := make([]map[string]any, 0, len(items))
	for _, a := range items {
		list = append(list, map[string]any{"id": a.ID, "type": a.Type, "title": a.Title, "body": a.Body})
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"announcements": list})
}

// webAppAdminAnnounceDelete 管理员在 Mini App 删除一条公告。
func (s *Service) webAppAdminAnnounceDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "无效的公告 id"})
		return
	}
	if err := s.client.DeleteAnnouncement(r.Context(), body.ID); err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true})
}

// webAppAdminInvites GET 列邀请码 + 套餐(供生成表单选套餐)。
func (s *Service) webAppAdminInvites(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	ctx := r.Context()
	invites, err := s.client.ListInvites(ctx, 50)
	if err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	pkgs, _ := s.client.ListPackages(ctx)
	// 兑换码「复制文案」用:主控可配的模板 + 占位符取值。模板取失败不阻塞列表(前端退化为只复制码)。
	tpl, _ := s.client.GetRedeemTemplate(ctx)
	writeJSONResp(w, http.StatusOK, map[string]any{
		"invites":         invites,
		"packages":        pkgs,
		"redeem_template": tpl,
		"master_url":      s.cfg.PublicBaseURL,
		"bot_url":         s.botURL(),
	})
}

// webAppAdminInviteCreate POST 创建邀请码。
func (s *Service) webAppAdminInviteCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	var body struct {
		PackageID      *int64 `json:"package_id"`
		DurationMonths int    `json:"duration_months"`
		MaxUses        int    `json:"max_uses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	maxUses := body.MaxUses
	if maxUses < 1 {
		maxUses = 1
	}
	// 兑换码统一 kind=new;使用次数可设(>1 = 多用户共用一个码注册)。
	req := mmwxclient.CreateInviteRequest{
		Kind:           "new",
		MaxUses:        maxUses,
		PackageID:      body.PackageID,
		DurationMonths: body.DurationMonths,
	}
	code, err := s.client.CreateInvite(r.Context(), req)
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true, "code": code})
}

// webAppAdminInviteRevoke POST 撤销邀请码。
func (s *Service) webAppAdminInviteRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Code) == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "code 必填"})
		return
	}
	if err := s.client.RevokeInvite(r.Context(), strings.TrimSpace(body.Code)); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true})
}

// webAppAdminInviteDelete POST 硬删除邀请码(仅限已不可用的)。
func (s *Service) webAppAdminInviteDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Code) == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "code 必填"})
		return
	}
	if err := s.client.DeleteInvite(r.Context(), strings.TrimSpace(body.Code)); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true})
}

// webAppAdminUsers GET 列用户 + 套餐(搜索在前端做,改套餐下拉用套餐列表)。
func (s *Service) webAppAdminUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	ctx := r.Context()
	users, err := s.client.ListUsers(ctx)
	if err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	pkgs, _ := s.client.ListPackages(ctx)
	writeJSONResp(w, http.StatusOK, map[string]any{
		"users":    users,
		"packages": pkgs,
	})
}

// webAppAdminUserExtend POST 给用户续期(+N 天)。
func (s *Service) webAppAdminUserExtend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	var body struct {
		Username string `json:"username"`
		Days     int    `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Username) == "" || body.Days <= 0 {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "username / days 必填"})
		return
	}
	if err := s.client.ExtendUser(r.Context(), strings.TrimSpace(body.Username), body.Days); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true})
}

// webAppAdminUserAssign POST 改用户套餐。
func (s *Service) webAppAdminUserAssign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]any{"error": "method"})
		return
	}
	if _, ok := s.adminTGID(w, r); !ok {
		return
	}
	var body struct {
		Username  string `json:"username"`
		PackageID int64  `json:"package_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Username) == "" || body.PackageID <= 0 {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "username / package_id 必填"})
		return
	}
	if err := s.client.AssignPackage(r.Context(), strings.TrimSpace(body.Username), body.PackageID); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"success": true})
}

// per-IP 固定窗口限流(60 次/分),给 Mini App API 端点用。
var (
	webRLMu  sync.Mutex
	webRLMap = map[string]*rlEntry{}
)

func webAllow(ip string) bool {
	webRLMu.Lock()
	defer webRLMu.Unlock()
	now := time.Now()
	e := webRLMap[ip]
	if e == nil {
		if !makeRateLimitRoom(webRLMap, now, time.Minute) {
			return false
		}
		webRLMap[ip] = &rlEntry{count: 1, windowStart: now}
		return true
	}
	if now.Sub(e.windowStart) >= time.Minute {
		webRLMap[ip] = &rlEntry{count: 1, windowStart: now}
		return true
	}
	e.count++
	return e.count <= 60
}

func clientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	peer := remoteIP(r.RemoteAddr)
	if peer == nil {
		return strings.TrimSpace(r.RemoteAddr)
	}

	// Only a local reverse proxy is allowed to supply the client address. A
	// direct public request cannot evade the limiter by inventing X-Real-IP/XFF.
	if peer.IsLoopback() {
		if candidate := parseForwardedIP(r.Header.Get("X-Real-IP")); candidate != nil {
			return candidate.String()
		}
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if candidate := parseForwardedIP(parts[i]); candidate != nil {
				return candidate.String()
			}
		}
	}
	return peer.String()
}

func parseForwardedIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else {
		value = strings.Trim(value, "[]")
	}
	return net.ParseIP(value)
}

func webRL(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !webAllow(clientIP(r)) {
			writeJSONResp(w, http.StatusTooManyRequests, map[string]any{"error": "请求过于频繁,请稍后再试"})
			return
		}
		h(w, r)
	}
}

func writeJSONResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
