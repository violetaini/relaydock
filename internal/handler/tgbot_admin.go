package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"

	"golang.org/x/crypto/bcrypt"
)

// TGBotAPIHandler 统一服务 /api/admin/tgbot/* 子路径。
//
// 邀请码 CRUD(admin web UI 用):
//
//	GET    /api/admin/tgbot/invites               列出
//	POST   /api/admin/tgbot/invites                创建
//	POST   /api/admin/tgbot/invites/revoke         撤销
//
// 独立 TG bot 调用(用 admin token):
//
//	POST   /api/admin/tgbot/bind                   一次性入口:kind=new 创建+绑+消费,kind=bind 绑已有+消费
//	POST   /api/admin/tgbot/unbind                 反查 username 后解绑
//	GET    /api/admin/tgbot/user-by-tg?tg_id=      TG ID → username 反查
//	GET    /api/admin/tgbot/user-summary?username= username/role/套餐/到期/本周期流量
//	GET    /api/admin/tgbot/user-subscriptions?username=  订阅列表 + short_code
//	GET    /api/admin/tgbot/user-nodes?username=   套餐节点 + 服务器在线状态
type TGBotAPIHandler struct {
	repo   *storage.TrafficRepository
	assign *PackageAssignHandler // 套餐绑定+下发(与 web /api/admin/packages/assign 共用),由 main.go 注入
}

func NewTGBotAPIHandler(repo *storage.TrafficRepository) *TGBotAPIHandler {
	return &TGBotAPIHandler{repo: repo}
}

// SetPackageAssign 注入套餐下发器,让 TGBOT 注册/兑换的套餐真正生效(下发节点凭据/推送)。
func (h *TGBotAPIHandler) SetPackageAssign(a *PackageAssignHandler) {
	h.assign = a
}

// assignPackage 绑定套餐:有下发器走完整下发(同 web),否则回退到仅写记录(兜底,不应发生)。
func (h *TGBotAPIHandler) assignPackage(ctx context.Context, username string, packageID int64, start, end time.Time, isReset bool, resetDay int) ([]string, error) {
	if h.assign != nil {
		return h.assign.AssignAndProvision(ctx, username, packageID, start, end, isReset, resetDay)
	}
	err := withStableUserPackageAuthorizationLease(ctx, h.repo, username, []int64{packageID}, func(leasedCtx context.Context, _ storage.User) error {
		return h.repo.AssignPackageToUser(leasedCtx, username, packageID, start, end, isReset, resetDay)
	})
	return nil, err
}

func resolveTGResetPolicy(pkg *storage.Package, current *storage.User, now time.Time) (bool, int) {
	isReset := pkg != nil && pkg.IsReset
	resetDay := 1
	if pkg != nil {
		resetDay = pkg.ResetDay
	}
	// Redeeming the same package is a renewal, so preserve an administrator's
	// user-level override. Switching packages starts from the target default.
	if pkg != nil && current != nil && current.PackageID == pkg.ID {
		isReset = current.IsReset
		resetDay = current.ResetDay
	}
	if resetDay < 1 || resetDay > 31 {
		resetDay = 1
		if isReset {
			resetDay = now.Day()
			if resetDay > 28 {
				resetDay = 28
			}
		}
	}
	return isReset, resetDay
}

// 向后兼容旧名字
func NewTGBotInviteHandler(repo *storage.TrafficRepository) *TGBotAPIHandler {
	return NewTGBotAPIHandler(repo)
}

func (h *TGBotAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/tgbot")
	path = strings.Trim(path, "/")

	switch {
	// 邀请码 CRUD
	case path == "invites" && r.Method == http.MethodGet:
		h.listInvites(w, r)
	case path == "invites/lookup" && r.Method == http.MethodGet:
		h.lookupInvite(w, r)
	case path == "invites" && r.Method == http.MethodPost:
		h.createInvite(w, r)
	case path == "invites/revoke" && r.Method == http.MethodPost:
		h.revokeInvite(w, r)
	case path == "invites/delete" && r.Method == http.MethodPost:
		h.deleteInvite(w, r)
	// 独立 bot 用
	case path == "bind" && r.Method == http.MethodPost:
		h.bind(w, r)
	case path == "bind-admin" && r.Method == http.MethodPost:
		h.bindAdmin(w, r)
	case path == "unbind" && r.Method == http.MethodPost:
		h.unbind(w, r)
	case path == "user-by-tg" && r.Method == http.MethodGet:
		h.userByTG(w, r)
	case path == "user-summary" && r.Method == http.MethodGet:
		h.userSummary(w, r)
	case path == "user-subscriptions" && r.Method == http.MethodGet:
		h.userSubscriptions(w, r)
	case path == "user-nodes" && r.Method == http.MethodGet:
		h.userNodes(w, r)
	case path == "notify" && r.Method == http.MethodPost:
		h.setNotify(w, r)
	case path == "notify-digest" && r.Method == http.MethodGet:
		h.notifyDigest(w, r)
	case path == "user-daily-traffic" && r.Method == http.MethodGet:
		h.userDailyTraffic(w, r)
	case path == "redeem" && r.Method == http.MethodPost:
		h.redeem(w, r)
	case path == "admin-subview" && r.Method == http.MethodGet:
		h.adminSubview(w, r)
	case path == "announcements/pending" && r.Method == http.MethodGet:
		h.announcementsPending(w, r)
	case path == "announcements/delivered" && r.Method == http.MethodPost:
		h.announcementDelivered(w, r)
	case path == "announcements/active" && r.Method == http.MethodGet:
		h.announcementsActive(w, r)
	case path == "announcements" && r.Method == http.MethodPost:
		h.postAnnouncement(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// ============ 邀请码 CRUD ============

type inviteOut struct {
	Code           string `json:"code"`
	Kind           string `json:"kind"`
	BindUsername   string `json:"bind_username,omitempty"`
	CreatedBy      string `json:"created_by"`
	PackageID      *int64 `json:"package_id,omitempty"`
	MaxUses        int    `json:"max_uses"`
	UsedCount      int    `json:"used_count"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	Revoked        bool   `json:"revoked"`
	Remark         string `json:"remark,omitempty"`
	CreatedAt      string `json:"created_at"`
	Usable         bool   `json:"usable"`
	DurationMonths int    `json:"duration_months,omitempty"`
}

func toInviteOut(ic storage.InviteCode) inviteOut {
	out := inviteOut{
		Code: ic.Code, Kind: ic.Kind, BindUsername: ic.BindUsername,
		CreatedBy: ic.CreatedBy, PackageID: ic.PackageID,
		MaxUses: ic.MaxUses, UsedCount: ic.UsedCount,
		Revoked: ic.Revoked, Remark: ic.Remark,
		CreatedAt:      ic.CreatedAt.Format(time.RFC3339),
		Usable:         ic.IsUsable(),
		DurationMonths: ic.DurationMonths,
	}
	if ic.ExpiresAt != nil {
		out.ExpiresAt = ic.ExpiresAt.Format(time.RFC3339)
	}
	return out
}

func (h *TGBotAPIHandler) listInvites(w http.ResponseWriter, r *http.Request) {
	createdBy := r.URL.Query().Get("created_by")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.repo.ListInviteCodes(r.Context(), createdBy, limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list failed: "+err.Error())
		return
	}
	out := make([]inviteOut, 0, len(items))
	for _, ic := range items {
		out = append(out, toInviteOut(ic))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": out})
}

// lookupInvite returns one exact code without the recency limit used by the
// administration list. This keeps old Telegram deep links usable while the
// endpoint remains behind the existing administrator authentication boundary.
func (h *TGBotAPIHandler) lookupInvite(w http.ResponseWriter, r *http.Request) {
	code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("code")))
	if code == "" || len(code) > 128 {
		writeJSONError(w, http.StatusBadRequest, "code 必填且不能超过 128 字节")
		return
	}
	ic, ok := h.repo.GetInviteCode(r.Context(), code)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "found": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"found":   true,
		"item":    toInviteOut(ic),
	})
}

func (h *TGBotAPIHandler) createInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind           string `json:"kind"`
		BindUsername   string `json:"bind_username"`
		PackageID      *int64 `json:"package_id"`
		MaxUses        int    `json:"max_uses"`
		ExpiresAt      string `json:"expires_at"`
		Remark         string `json:"remark"`
		DurationMonths int    `json:"duration_months"` // kind=new 账号有效期(月);0=按套餐周期
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Kind != "new" && body.Kind != "bind" {
		writeJSONError(w, http.StatusBadRequest, "kind 必须是 new 或 bind")
		return
	}
	if body.Kind == "bind" && strings.TrimSpace(body.BindUsername) == "" {
		writeJSONError(w, http.StatusBadRequest, "kind=bind 时 bind_username 必填")
		return
	}
	if body.MaxUses <= 0 {
		body.MaxUses = 1
	}

	ic := storage.InviteCode{
		Kind:           body.Kind,
		BindUsername:   strings.TrimSpace(body.BindUsername),
		CreatedBy:      auth.UsernameFromContext(r.Context()),
		PackageID:      body.PackageID,
		MaxUses:        body.MaxUses,
		Remark:         body.Remark,
		DurationMonths: body.DurationMonths,
	}
	if strings.TrimSpace(body.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "expires_at 必须是 RFC3339")
			return
		}
		ic.ExpiresAt = &t
	}

	code, err := h.repo.CreateInviteCode(r.Context(), ic)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "code": code})
}

func (h *TGBotAPIHandler) revokeInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if strings.TrimSpace(body.Code) == "" {
		writeJSONError(w, http.StatusBadRequest, "code 必填")
		return
	}
	if err := h.repo.RevokeInviteCode(r.Context(), body.Code); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// deleteInvite POST /invites/delete {code}:硬删除邀请码(仅限已不可用的:已撤销/已用尽/已过期)。
func (h *TGBotAPIHandler) deleteInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		writeJSONError(w, http.StatusBadRequest, "code 必填")
		return
	}
	if ic, ok := h.repo.GetInviteCode(r.Context(), code); ok && ic.IsUsable() {
		writeJSONError(w, http.StatusBadRequest, "邀请码仍可用,请先撤销再删除")
		return
	}
	if err := h.repo.DeleteInviteCode(r.Context(), code); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ============ /bind 一次性入口 ============

// 用户名字符集:字母/数字/短横线,3-20 位,**不含下划线**。
// 下划线会破坏流量归因(email 用 `<username>__<...>` 编码,下划线与分隔符 `__` 及 SQL LIKE 的 `_` 通配冲突)。
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9-]{3,20}$`)

// validateUsername 是所有创建/改名入口共用的用户名校验(setup / admin 创建 / 自助改名 / TG 注册)。
func validateUsername(s string) error {
	if !usernameRe.MatchString(s) {
		return errors.New("用户名只能包含字母、数字、短横线,长度 3-20,且不能包含下划线")
	}
	if storage.IsReservedUsername(s) {
		return errors.New("该用户名为系统保留名称")
	}
	return nil
}

func (h *TGBotAPIHandler) bind(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code           string `json:"code"`
		TelegramID     int64  `json:"telegram_id"`
		TelegramHandle string `json:"telegram_handle"`
		Username       string `json:"username"` // kind=new 时由 bot 收集
		Email          string `json:"email"`    // kind=new 可选
		Password       string `json:"password"` // kind=new 可选:用户自定义密码,空则随机生成
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Code == "" || body.TelegramID == 0 {
		writeJSONError(w, http.StatusBadRequest, "code 和 telegram_id 必填")
		return
	}
	ctx := r.Context()

	// 同 tg_id 已绑 → 拒(防多账号)
	if existing, ok := h.repo.GetUsernameByTelegramID(ctx, body.TelegramID); ok {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("该 TG 已绑定到 %s,请先解绑", existing))
		return
	}

	ic, ok := h.repo.GetInviteCode(ctx, body.Code)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "邀请码不存在")
		return
	}
	if !ic.IsUsable() {
		writeJSONError(w, http.StatusBadRequest, "邀请码不可用(已撤销/已用尽/已过期)")
		return
	}

	switch ic.Kind {
	case "bind":
		h.bindExisting(ctx, w, body.TelegramID, body.TelegramHandle, ic)
	case "new":
		h.bindNew(ctx, w, body.TelegramID, body.TelegramHandle, body.Username, body.Email, body.Password, ic)
	default:
		writeJSONError(w, http.StatusInternalServerError, "未知邀请码 kind: "+ic.Kind)
	}
}

func (h *TGBotAPIHandler) bindExisting(ctx context.Context, w http.ResponseWriter,
	tgID int64, tgHandle string, ic storage.InviteCode) {

	user, err := h.repo.GetUser(ctx, ic.BindUsername)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "目标账号不存在: "+ic.BindUsername)
		return
	}
	if !user.IsActive {
		writeJSONError(w, http.StatusForbidden, "目标账号已停用")
		return
	}
	if err := h.repo.ConsumeInviteCode(ctx, ic.Code, user.Username, tgID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "消耗邀请码失败: "+err.Error())
		return
	}
	// 绑前先查原 telegram_id 判断是否首次绑(=0 即未绑过)
	wasUnbound := h.repo.GetTelegramIDByUsername(ctx, user.Username) == 0
	if err := h.repo.BindTelegram(ctx, user.Username, tgID, tgHandle); err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"绑定失败: "+err.Error()+" (邀请码已消耗,请联系管理员)")
		return
	}
	_ = h.repo.WriteTGAudit(ctx, storage.TGAudit{
		TGID: tgID, Username: user.Username,
		Action: "bind", Detail: "invite_code=" + ic.Code,
	})
	if wasUnbound {
		SendTelegramBoundNotification(ctx, user.Username, tgID, tgHandle)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"username": user.Username,
		"kind":     "bind",
	})
}

func (h *TGBotAPIHandler) bindNew(ctx context.Context, w http.ResponseWriter,
	tgID int64, tgHandle, requestedUsername, email, password string, ic storage.InviteCode) {

	requestedUsername = strings.TrimSpace(requestedUsername)
	if err := validateUsername(requestedUsername); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.repo.GetUser(ctx, requestedUsername); err == nil {
		writeJSONError(w, http.StatusConflict, "用户名已被占用")
		return
	}

	// 密码:用户自定义优先(>=6 位),否则随机生成。
	plainPw := strings.TrimSpace(password)
	userSetPw := plainPw != ""
	if userSetPw {
		if len(plainPw) < 6 || len(plainPw) > 64 {
			writeJSONError(w, http.StatusBadRequest, "密码长度需 6-64 位")
			return
		}
	} else {
		pwBuf := make([]byte, 8)
		if _, err := rand.Read(pwBuf); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rand: "+err.Error())
			return
		}
		plainPw = hex.EncodeToString(pwBuf)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPw), bcrypt.DefaultCost)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "bcrypt: "+err.Error())
		return
	}

	if err := h.repo.ConsumeInviteCode(ctx, ic.Code, requestedUsername, tgID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "消耗邀请码失败: "+err.Error())
		return
	}
	if err := h.repo.CreateUser(ctx, requestedUsername, email, "", string(hash), "user", "TG 注册"); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "创建账号失败: "+err.Error())
		return
	}
	SendUserRegisteredNotification(ctx, requestedUsername, email, "TG 注册")
	// 确保生成 user_tokens 行 + 用户短码,否则订阅链接缺用户码(/x/<套餐码> 而非 /x/<套餐码><用户码>)。
	_, _ = h.repo.GetOrCreateUserToken(ctx, requestedUsername)

	pkgInfo := map[string]any{}
	var warnings []string
	if ic.PackageID != nil {
		if pkg, perr := h.repo.GetPackage(ctx, *ic.PackageID); perr == nil && pkg != nil {
			start := time.Now()
			// 邀请码指定了月数则按月数算到期,未指定(0)沿用套餐自身周期。
			end := start.AddDate(0, 0, pkg.CycleDays)
			if ic.DurationMonths > 0 {
				end = start.AddDate(0, ic.DurationMonths, 0)
			}
			// 新绑定遵循套餐默认策略,与 Web 分配入口保持一致。
			isReset, resetDay := resolveTGResetPolicy(pkg, nil, start)
			provisionWarnings, aerr := h.assignPackage(ctx, requestedUsername, pkg.ID, start, end,
				isReset, resetDay)
			if aerr == nil {
				warnings = append(warnings, provisionWarnings...)
				pkgInfo = map[string]any{
					"package_name":     pkg.Name,
					"traffic_limit_gb": pkg.TrafficLimitGB,
					"cycle_days":       pkg.CycleDays,
					"end_date":         end.Format("2006-01-02"),
				}
			} else {
				warnings = append(warnings, "套餐分配失败,请联系管理员: "+aerr.Error())
			}
		} else {
			warnings = append(warnings, "邀请码关联的套餐不存在,请联系管理员")
		}
	}

	if err := h.repo.BindTelegram(ctx, requestedUsername, tgID, tgHandle); err != nil {
		writeJSONError(w, http.StatusInternalServerError,
			"TG 绑定失败: "+err.Error()+" (账号已创建,请联系管理员手动绑)")
		return
	}
	SendTelegramBoundNotification(ctx, requestedUsername, tgID, tgHandle)
	_ = h.repo.WriteTGAudit(ctx, storage.TGAudit{
		TGID: tgID, Username: requestedUsername,
		Action: "register", Detail: "invite_code=" + ic.Code,
	})

	respPw := plainPw
	if userSetPw { // 用户自设密码,不回显
		respPw = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":          true,
		"username":         requestedUsername,
		"kind":             "new",
		"initial_password": respPw,
		"package":          pkgInfo,
		"warnings":         warnings,
	})
}

// bindAdmin POST /bind-admin {telegram_id, telegram_handle}:把 TG 自动绑到主控管理员账号。
// 用于 Mini App:管理员打开面板时若未绑定,自动绑到(默认单一的)管理员账号。
func (h *TGBotAPIHandler) bindAdmin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TelegramID     int64  `json:"telegram_id"`
		TelegramHandle string `json:"telegram_handle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.TelegramID == 0 {
		writeJSONError(w, http.StatusBadRequest, "telegram_id 必填")
		return
	}
	ctx := r.Context()

	// 已绑 → 幂等返回
	if existing, ok := h.repo.GetUsernameByTelegramID(ctx, body.TelegramID); ok {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "username": existing})
		return
	}

	adminUser := h.repo.GetSystemNodeOwner(ctx) // role=admin 最早一个(无则回退 "admin")
	u, err := h.repo.GetUser(ctx, adminUser)
	if err != nil || u.Role != "admin" {
		writeJSONError(w, http.StatusNotFound, "未找到管理员账号")
		return
	}
	if boundTG := h.repo.GetTelegramIDByUsername(ctx, adminUser); boundTG != 0 && boundTG != body.TelegramID {
		writeJSONError(w, http.StatusConflict, "管理员账号已绑定其它 Telegram,请先在网页端解绑")
		return
	}
	if err := h.repo.BindTelegram(ctx, adminUser, body.TelegramID, body.TelegramHandle); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "绑定失败: "+err.Error())
		return
	}
	_ = h.repo.WriteTGAudit(ctx, storage.TGAudit{
		TGID: body.TelegramID, Username: adminUser, Action: "bind", Detail: "auto-admin",
	})
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "username": adminUser})
}

// ============ /unbind ============

func (h *TGBotAPIHandler) unbind(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TelegramID int64 `json:"telegram_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.TelegramID == 0 {
		writeJSONError(w, http.StatusBadRequest, "telegram_id 必填")
		return
	}
	username, ok := h.repo.GetUsernameByTelegramID(r.Context(), body.TelegramID)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "TG 未绑定任何账号")
		return
	}
	if err := h.repo.UnbindTelegram(r.Context(), username); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.repo.WriteTGAudit(r.Context(), storage.TGAudit{
		TGID: body.TelegramID, Username: username,
		Action: "unbind", Detail: "via tgbot client",
	})
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "username": username})
}

// ============ /user-by-tg ============

func (h *TGBotAPIHandler) userByTG(w http.ResponseWriter, r *http.Request) {
	tgIDStr := r.URL.Query().Get("tg_id")
	tgID, err := strconv.ParseInt(tgIDStr, 10, 64)
	if err != nil || tgID == 0 {
		writeJSONError(w, http.StatusBadRequest, "tg_id 必填且为整数")
		return
	}
	username, ok := h.repo.GetUsernameByTelegramID(r.Context(), tgID)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "bound": false})
		return
	}
	user, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	notifyEnabled, _ := h.repo.GetTGNotify(r.Context(), tgID)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":        true,
		"bound":          true,
		"username":       username,
		"role":           user.Role,
		"is_active":      user.IsActive,
		"notify_enabled": notifyEnabled,
	})
}

// ============ /user-summary ============

func (h *TGBotAPIHandler) userSummary(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "username 必填")
		return
	}
	user, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	out := map[string]any{
		"success":           true,
		"username":          user.Username,
		"role":              user.Role,
		"is_active":         user.IsActive,
		"email":             user.Email,
		"telegram_id":       0,
		"telegram_username": "",
	}
	// 套餐
	if user.PackageID > 0 {
		pkg, perr := h.repo.GetPackage(r.Context(), user.PackageID)
		if perr == nil && pkg != nil {
			limit := pkg.TrafficLimitBytes
			if limit <= 0 {
				limit = int64(pkg.TrafficLimitGB * 1024 * 1024 * 1024)
			}
			out["package"] = map[string]any{
				"id":               pkg.ID,
				"name":             pkg.Name,
				"traffic_limit":    limit,
				"traffic_limit_gb": pkg.TrafficLimitGB,
				"cycle_days":       pkg.CycleDays,
				"traffic_mode":     pkg.TrafficMode,
				"speed_limit_mbps": pkg.SpeedLimitMbps,
				"device_limit":     pkg.DeviceLimit,
			}
		}
	}
	if user.PackageEndDate != nil {
		out["package_end_date"] = user.PackageEndDate.Format(time.RFC3339)
	}
	// 流量
	rows, _ := h.repo.GetUserTrafficByUsername(r.Context(), username)
	var sumUp, sumDown, totalUp, totalDown int64
	for _, t := range rows {
		sumUp += t.Uplink
		sumDown += t.Downlink
		totalUp += t.TotalUplink
		totalDown += t.TotalDownlink
	}
	out["traffic"] = map[string]any{
		"cycle_uplink":   sumUp,
		"cycle_downlink": sumDown,
		"total_uplink":   totalUp,
		"total_downlink": totalDown,
	}
	writeJSON(w, http.StatusOK, out)
}

// ============ /user-subscriptions ============

func (h *TGBotAPIHandler) userSubscriptions(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "username 必填")
		return
	}
	subs, err := h.repo.GetUserSubscriptions(r.Context(), username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = h.repo.GetOrCreateUserToken(r.Context(), username) // 确保有短码(修复老账号)
	userShortCode, _ := h.repo.GetEffectiveUserShortCode(r.Context(), username)

	type subOut struct {
		ID              int64  `json:"id"`
		Name            string `json:"name"`
		Description     string `json:"description"`
		FileShortCode   string `json:"file_short_code,omitempty"`
		CustomShortCode string `json:"custom_short_code,omitempty"`
		// CombinedCode 拼好的:有 custom 优先 custom,否则 file + user_short
		CombinedCode string `json:"combined_code"`
	}
	out := make([]subOut, 0, len(subs))
	for _, sf := range subs {
		combined := strings.TrimSpace(sf.CustomShortCode)
		if combined == "" {
			combined = sf.FileShortCode + userShortCode
		}
		out = append(out, subOut{
			ID: sf.ID, Name: sf.Name, Description: sf.Description,
			FileShortCode: sf.FileShortCode, CustomShortCode: sf.CustomShortCode,
			CombinedCode: combined,
		})
	}

	resp := map[string]any{
		"success":         true,
		"user_short_code": userShortCode,
		"subscriptions":   out,
	}
	// 默认订阅:用户套餐的动态订阅(/x/{套餐短码}{用户短码}),无需分配 subscribe_file,
	// 与网页端「登录即见」的默认订阅一致。
	if user, uerr := h.repo.GetUser(r.Context(), username); uerr == nil && user.PackageID > 0 {
		if pkg, perr := h.repo.GetPackage(r.Context(), user.PackageID); perr == nil && pkg != nil &&
			strings.TrimSpace(pkg.ShortCode) != "" {
			resp["default_subscription"] = subOut{
				Name:         pkg.Name,
				Description:  "套餐默认订阅",
				CombinedCode: pkg.ShortCode + userShortCode,
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ============ /user-nodes ============

func (h *TGBotAPIHandler) userNodes(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "username 必填")
		return
	}
	nodeIDs, err := ResolveEffectiveUserNodeIDs(r.Context(), h.repo, username, time.Now().UTC())
	if errors.Is(err, storage.ErrUserNotFound) {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "resolve user nodes failed")
		return
	}

	// 一次拉所有 server,做 name → status 查找表
	servers, err := h.repo.ListRemoteServers(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "resolve server status failed")
		return
	}
	serverStatus := make(map[string]string, len(servers))
	for _, s := range servers {
		serverStatus[s.Name] = s.Status
	}

	type nodeOut struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		Protocol     string `json:"protocol"`
		ServerName   string `json:"server_name"`
		ServerStatus string `json:"server_status"`
		ServerOnline bool   `json:"server_online"`
		InboundTag   string `json:"inbound_tag,omitempty"`
		NodeType     string `json:"node_type,omitempty"`
		Enabled      bool   `json:"enabled"`
	}
	out := make([]nodeOut, 0, len(nodeIDs))
	for _, nid := range nodeIDs {
		n, err := h.repo.GetNodeByID(r.Context(), nid)
		if err != nil {
			continue
		}
		status := serverStatus[n.OriginalServer]
		out = append(out, nodeOut{
			ID: n.ID, Name: n.NodeName, Protocol: n.Protocol,
			ServerName: n.OriginalServer, ServerStatus: status,
			ServerOnline: status == "connected",
			InboundTag:   n.InboundTag, NodeType: n.NodeType,
			Enabled: n.Enabled,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "nodes": out})
}

// ============ 用户自助通知 ============

// setNotify POST /notify {telegram_id, enabled} 开关用户的每日通知。
func (h *TGBotAPIHandler) setNotify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TelegramID int64 `json:"telegram_id"`
		Enabled    bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.TelegramID == 0 {
		writeJSONError(w, http.StatusBadRequest, "telegram_id 必填")
		return
	}
	if err := h.repo.SetTGNotify(r.Context(), body.TelegramID, body.Enabled); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "enabled": body.Enabled})
}

// notifyDigest GET /notify-digest 返回已开通知用户的流量 + 到期,供 bot 每日推送。
func (h *TGBotAPIHandler) notifyDigest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targets, err := h.repo.ListNotifyUsers(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type digestUser struct {
		Username       string  `json:"username"`
		TelegramID     int64   `json:"telegram_id"`
		PackageName    string  `json:"package_name,omitempty"`
		TrafficLimitGB float64 `json:"traffic_limit_gb"`
		CycleUplink    int64   `json:"cycle_uplink"`
		CycleDownlink  int64   `json:"cycle_downlink"`
		TotalUplink    int64   `json:"total_uplink"`
		TotalDownlink  int64   `json:"total_downlink"`
		PackageEndDate string  `json:"package_end_date,omitempty"`
	}

	users := make([]digestUser, 0, len(targets))
	for _, t := range targets {
		du := digestUser{Username: t.Username, TelegramID: t.TelegramID}
		if t.PackageID > 0 {
			if pkg, perr := h.repo.GetPackage(ctx, t.PackageID); perr == nil && pkg != nil {
				du.PackageName = pkg.Name
				du.TrafficLimitGB = pkg.TrafficLimitGB
			}
		}
		if t.PackageEndDate != nil {
			du.PackageEndDate = t.PackageEndDate.Format(time.RFC3339)
		}
		rows, _ := h.repo.GetUserTrafficByUsername(ctx, t.Username)
		for _, tr := range rows {
			du.CycleUplink += tr.Uplink
			du.CycleDownlink += tr.Downlink
			du.TotalUplink += tr.TotalUplink
			du.TotalDownlink += tr.TotalDownlink
		}
		users = append(users, du)
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "users": users})
}

// userDailyTraffic GET /user-daily-traffic?username= 返回用户套餐周期内每日用量(GB)。
// 复用 ListUserRecent(每日累计快照)+ 差分,口径同 /api/traffic/summary 的 history。
func (h *TGBotAPIHandler) userDailyTraffic(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "username 必填")
		return
	}
	ctx := r.Context()

	days := 31
	if user, err := h.repo.GetUser(ctx, username); err == nil && user.PackageID > 0 {
		if pkg, perr := h.repo.GetPackage(ctx, user.PackageID); perr == nil && pkg != nil && pkg.CycleDays > 0 {
			days = pkg.CycleDays + 1
			if days > 62 {
				days = 62
			}
		}
	}

	records, err := h.repo.ListUserRecent(ctx, username, days)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Date.Before(records[j].Date) })

	type dayUsage struct {
		Date   string  `json:"date"`
		UsedGB float64 `json:"used_gb"`
	}
	out := make([]dayUsage, 0, len(records))
	var prevUsed int64
	var hasPrev bool
	for _, rec := range records {
		delta := rec.TotalUsed
		if hasPrev {
			delta = rec.TotalUsed - prevUsed
			if delta < 0 {
				delta = 0
			}
		}
		prevUsed = rec.TotalUsed
		hasPrev = true
		out = append(out, dayUsage{Date: rec.Date.Format("2006-01-02"), UsedGB: roundUpTwoDecimals(bytesToGigabytes(delta))})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "history": out})
}

// redeem POST /redeem {code, telegram_id}:已绑定用户用兑换码续期(只延长到期时间,不重置流量)。
func (h *TGBotAPIHandler) redeem(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code       string `json:"code"`
		TelegramID int64  `json:"telegram_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	body.Code = strings.ToUpper(strings.TrimSpace(body.Code))
	if body.Code == "" || body.TelegramID == 0 {
		writeJSONError(w, http.StatusBadRequest, "code 和 telegram_id 必填")
		return
	}
	ctx := r.Context()

	existing, ok := h.repo.GetUsernameByTelegramID(ctx, body.TelegramID)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "该 TG 未绑定账号,请先注册")
		return
	}
	ic, ok := h.repo.GetInviteCode(ctx, body.Code)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "兑换码不存在")
		return
	}
	if !ic.IsUsable() {
		writeJSONError(w, http.StatusBadRequest, "兑换码不可用(已撤销/已用尽/已过期)")
		return
	}
	if ic.PackageID == nil {
		writeJSONError(w, http.StatusBadRequest, "该兑换码无套餐,无法续期")
		return
	}
	pkg, err := h.repo.GetPackage(ctx, *ic.PackageID)
	if err != nil || pkg == nil {
		writeJSONError(w, http.StatusInternalServerError, "套餐不存在")
		return
	}
	user, err := h.repo.GetUser(ctx, existing)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 从「当前到期日(若未过期)否则现在」往后延长,只延长不重置流量。
	now := time.Now()
	base := now
	if user.PackageEndDate != nil && user.PackageEndDate.After(now) {
		base = *user.PackageEndDate
	}
	var end time.Time
	if ic.DurationMonths > 0 {
		end = base.AddDate(0, ic.DurationMonths, 0)
	} else {
		end = base.AddDate(0, 0, pkg.CycleDays)
	}
	// 同套餐续期保留用户级策略;兑换不同套餐时采用目标套餐默认策略。
	isReset, resetDay := resolveTGResetPolicy(pkg, &user, now)

	if err := h.repo.ConsumeInviteCode(ctx, ic.Code, existing, body.TelegramID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "兑换失败: "+err.Error())
		return
	}
	warnings, err := h.assignPackage(ctx, existing, pkg.ID, now, end, isReset, resetDay)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "续期失败: "+err.Error())
		return
	}
	_ = h.repo.WriteTGAudit(ctx, storage.TGAudit{
		TGID: body.TelegramID, Username: existing, Action: "renew", Detail: "code=" + ic.Code,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "kind": "renew", "username": existing,
		"package_name": pkg.Name, "end_date": end.Format("2006-01-02"), "warnings": warnings,
	})
}

// adminSubview GET /admin-subview?username= 返回「系统订阅列表第一个订阅」及其节点(名/协议/在线状态)。
// 用于管理员账号(无套餐、无个人订阅)在 Mini App 里有可用的订阅与节点视图。
func (h *TGBotAPIHandler) adminSubview(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "username 必填")
		return
	}
	ctx := r.Context()
	files, err := h.repo.ListSubscribeFiles(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(files) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "subscription": nil, "nodes": []any{}})
		return
	}
	f := files[0]
	_, _ = h.repo.GetOrCreateUserToken(ctx, username) // 确保有短码(修复老账号)
	userShort, _ := h.repo.GetEffectiveUserShortCode(ctx, username)
	combined := strings.TrimSpace(f.CustomShortCode)
	if combined == "" {
		combined = f.FileShortCode + userShort
	}

	servers, _ := h.repo.ListRemoteServers(ctx)
	serverStatus := make(map[string]string, len(servers))
	for _, s := range servers {
		serverStatus[s.Name] = s.Status
	}

	type nodeOut struct {
		NodeID   int64  `json:"node_id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Status   string `json:"status"` // online | offline | unknown
	}
	nodes := make([]nodeOut, 0, len(f.SelectedNodeIDs))
	for _, id := range f.SelectedNodeIDs {
		n, err := h.repo.GetNodeByID(ctx, id)
		if err != nil {
			continue
		}
		st := "offline"
		if s := serverStatus[n.OriginalServer]; s == "connected" {
			st = "online"
		} else if strings.TrimSpace(n.OriginalServer) == "" || s == "" {
			st = "unknown"
		}
		nodes = append(nodes, nodeOut{NodeID: n.ID, Name: n.NodeName, Protocol: n.Protocol, Status: st})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"subscription": map[string]any{"name": f.Name, "combined_code": combined},
		"nodes":        nodes,
	})
}

// 占位:避免编译器报错(若未来 storage 没暴露某方法,可在这里 stub)
var _ = errors.New
