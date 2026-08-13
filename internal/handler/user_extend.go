package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// UserExtendHandler 处理 POST /api/admin/users/extend:给已绑套餐的用户快捷延长有效期(+N 天)。
// 只改 package_end_date,不触碰流量周期(续期与流量重置是完全独立的两套流程)。
// 复用 PackageAssignHandler.AssignAndProvision:同套餐续期也会幂等刷新并补齐缺失凭据。
type UserExtendHandler struct {
	assign *PackageAssignHandler
}

func NewUserExtendHandler(assign *PackageAssignHandler) *UserExtendHandler {
	return &UserExtendHandler{assign: assign}
}

type extendUserRequest struct {
	Username string `json:"username"`
	Days     int    `json:"days"`
}

func (h *UserExtendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req extendUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" {
		writeJSONError(w, http.StatusBadRequest, "username is required")
		return
	}
	if req.Days <= 0 || req.Days > 3650 {
		writeJSONError(w, http.StatusBadRequest, "days 必须在 1..3650 之间")
		return
	}

	ctx := r.Context()
	user, err := h.assign.repo.GetUser(ctx, req.Username)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}
	// 过期后 enforcer 会清空 package_id —— 这类用户没有套餐可续,引导走「改套餐」重新绑定,不在续期端点里隐式重绑。
	if user.PackageID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "用户未绑定套餐,无法续期")
		return
	}

	// 从「当前到期日(若未过期)否则现在」往后延长,只延长不重置流量。与 TG 兑换续期算法一致(tgbot_admin.go)。
	now := time.Now()
	base := now
	if user.PackageEndDate != nil && user.PackageEndDate.After(now) {
		base = *user.PackageEndDate
	}
	newEnd := base.AddDate(0, 0, req.Days)

	// 续费只延长有效期,不改动用户的流量重置策略。特别是管理员显式
	// 关闭按月重置后,快捷续期不能悄悄把它重新打开。
	isReset := user.IsReset
	resetDay := user.ResetDay
	if isReset && (resetDay < 1 || resetDay > 31) {
		resetDay = now.Day()
		if resetDay > 28 {
			resetDay = 28
		}
	}

	warnings, perr := h.assign.AssignAndProvision(ctx, req.Username, user.PackageID, now, newEnd, isReset, resetDay)
	if perr != nil {
		writeJSONError(w, http.StatusInternalServerError, perr.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"username": req.Username,
		"end_date": newEnd.Format("2006-01-02"),
		"warnings": warnings,
	})
}
