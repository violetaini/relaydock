package handler

import (
	"encoding/json"
	"math"
	"net/http"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type PortalSummaryHandler struct {
	repo *storage.TrafficRepository
}

func NewPortalSummaryHandler(repo *storage.TrafficRepository) *PortalSummaryHandler {
	return &PortalSummaryHandler{repo: repo}
}

type UserPortalSummaryResponse struct {
	Success bool `json:"success"`
	User    struct {
		Username  string `json:"username"`
		Nickname  string `json:"nickname"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
		Role      string `json:"role"`
		IsAdmin   bool   `json:"is_admin"`
	} `json:"user"`
	Package struct {
		ID             int64   `json:"id"`
		Name           string  `json:"name"`
		Description    string  `json:"description"`
		StartDate      *string `json:"start_date,omitempty"`
		EndDate        *string `json:"end_date,omitempty"`
		DaysRemaining  int     `json:"days_remaining"`
		IsExpired      bool    `json:"is_expired"`
		SpeedLimitMbps float64 `json:"speed_limit_mbps"`
		DeviceLimit    int     `json:"device_limit"`
	} `json:"package"`
	Traffic struct {
		TotalLimitBytes int64   `json:"total_limit_bytes"`
		TotalUsedBytes  int64   `json:"total_used_bytes"`
		RemainingBytes  int64   `json:"remaining_bytes"`
		UsagePercentage float64 `json:"usage_percentage"`
		ResetDay        int     `json:"reset_day"`
		DaysUntilReset  int     `json:"days_until_reset"`
	} `json:"traffic"`
	Nodes struct {
		TotalCount  int `json:"total_count"`
		OnlineCount int `json:"online_count"`
	} `json:"nodes"`
	Subscription struct {
		Token           string `json:"token,omitempty"`
		UserShortCode   string `json:"user_short_code,omitempty"`
		CustomShortCode string `json:"custom_short_code,omitempty"`
		ShortLinkPrefix string `json:"short_link_prefix,omitempty"`
	} `json:"subscription"`
}

func (h *PortalSummaryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errUnauthorized)
		return
	}

	ctx := r.Context()
	username := auth.UsernameFromContext(ctx)
	if username == "" {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}

	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := UserPortalSummaryResponse{Success: true}
	resp.User.Username = user.Username
	resp.User.Nickname = user.Nickname
	resp.User.Email = user.Email
	resp.User.AvatarURL = user.AvatarURL
	resp.User.Role = user.Role
	resp.User.IsAdmin = user.Role == storage.RoleAdmin

	now := time.Now().UTC()

	var totalLimitBytes int64
	var pkgName, pkgDesc string
	var pkgID int64
	var speedLimit float64
	var deviceLimit int
	var resetDay int = user.ResetDay

	if user.PackageID > 0 {
		if pkg, err := h.repo.GetPackage(ctx, user.PackageID); err == nil && pkg != nil {
			pkgID = pkg.ID
			pkgName = pkg.Name
			pkgDesc = pkg.Description
			speedLimit = pkg.SpeedLimitMbps
			deviceLimit = pkg.DeviceLimit
			if resetDay == 0 && pkg.ResetDay > 0 {
				resetDay = pkg.ResetDay
			}
			if pkg.TrafficLimitBytes > 0 {
				totalLimitBytes = pkg.TrafficLimitBytes
			} else if pkg.TrafficLimitGB > 0 {
				totalLimitBytes = int64(pkg.TrafficLimitGB * 1024 * 1024 * 1024)
			}
		}
	}

	if user.TrafficLimitOverride != nil && *user.TrafficLimitOverride > 0 {
		totalLimitBytes = *user.TrafficLimitOverride
	}
	if user.SpeedLimitOverride != nil {
		speedLimit = *user.SpeedLimitOverride
	}
	if user.DeviceLimitOverride != nil {
		deviceLimit = *user.DeviceLimitOverride
	}

	var totalUsedBytes int64
	if billed, err := h.repo.GetUserBillableTraffic(ctx, username); err == nil {
		totalUsedBytes = billed
	}

	remainingBytes := totalLimitBytes - totalUsedBytes
	if remainingBytes < 0 || totalLimitBytes == 0 {
		if totalLimitBytes == 0 {
			remainingBytes = -1 // unlimited
		} else {
			remainingBytes = 0
		}
	}

	var usagePercentage float64
	if totalLimitBytes > 0 {
		usagePercentage = math.Min(100.0, (float64(totalUsedBytes)/float64(totalLimitBytes))*100.0)
	}

	daysUntilReset := 0
	if resetDay > 0 {
		today := now.Day()
		if resetDay >= today {
			daysUntilReset = resetDay - today
		} else {
			daysInMonth := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
			daysUntilReset = (daysInMonth - today) + resetDay
		}
	}

	daysRemaining := -1
	isExpired := false
	if user.PackageEndDate != nil {
		endStr := user.PackageEndDate.Format("2006-01-02")
		resp.Package.EndDate = &endStr
		if now.After(*user.PackageEndDate) {
			isExpired = true
			daysRemaining = 0
		} else {
			daysRemaining = int(math.Ceil(user.PackageEndDate.Sub(now).Hours() / 24.0))
		}
	}
	if user.PackageStartDate != nil {
		startStr := user.PackageStartDate.Format("2006-01-02")
		resp.Package.StartDate = &startStr
	}

	resp.Package.ID = pkgID
	resp.Package.Name = pkgName
	resp.Package.Description = pkgDesc
	resp.Package.DaysRemaining = daysRemaining
	resp.Package.IsExpired = isExpired
	resp.Package.SpeedLimitMbps = speedLimit
	resp.Package.DeviceLimit = deviceLimit

	resp.Traffic.TotalLimitBytes = totalLimitBytes
	resp.Traffic.TotalUsedBytes = totalUsedBytes
	resp.Traffic.RemainingBytes = remainingBytes
	resp.Traffic.UsagePercentage = usagePercentage
	resp.Traffic.ResetDay = resetDay
	resp.Traffic.DaysUntilReset = daysUntilReset

	if nodeIDs, err := ResolveEffectiveUserNodeIDs(ctx, h.repo, username, now); err == nil {
		resp.Nodes.TotalCount = len(nodeIDs)
		onlineCount := 0
		for _, nid := range nodeIDs {
			if node, err := h.repo.GetNodeByID(ctx, nid); err == nil && node.Enabled {
				onlineCount++
			}
		}
		resp.Nodes.OnlineCount = onlineCount
	}

	if token, err := h.repo.GetOrCreateUserToken(ctx, username); err == nil {
		resp.Subscription.Token = token
	}
	if shortCode, err := h.repo.GetEffectiveUserShortCode(ctx, username); err == nil {
		resp.Subscription.UserShortCode = shortCode
	}
	if customCode, err := h.repo.GetUserCustomShortCode(ctx, username); err == nil {
		resp.Subscription.CustomShortCode = customCode
	}
	resp.Subscription.ShortLinkPrefix = "/x/"

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
