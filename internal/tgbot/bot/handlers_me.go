package bot

// 这里只是为了把 displayUserSummary 桥接给 formatUserSummary。
// 让 handlers_user.go 的 formatUserSummary 真正用上 mmwxclient.UserSummary 类型。
//
// 编译期注意:把 formatUserSummary 重写在这里,接受具体类型。

import (
	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

// formatSummaryFromClient 把 mmwxclient.UserSummary 渲染成可读卡片。
func formatSummaryFromClient(u *mmwxclient.UserSummary) string {
	return displayUserSummary(
		u.Role, u.Username, u.Email, u.IsActive,
		u.Package, u.PackageEndDate,
		u.Traffic.TotalUplink, u.Traffic.TotalDownlink,
		u.Traffic.CycleUplink, u.Traffic.CycleDownlink,
	)
}
