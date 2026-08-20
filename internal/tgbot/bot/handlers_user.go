package bot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

const helpText = `Arcway Telegram Bot

通用:
/help - 显示帮助
/start <code> - 用邀请码注册或绑定

已绑定用户:
/me - 我的账号信息
/sub - 订阅链接
/traffic - 流量统计
/nodes - 我的节点 + 在线状态
/notify - 通知开关(on|off|status):每日流量 + 临期提醒
/unbind - 解绑 TG(回复 /unbind UNBIND 确认)

管理员:
/admin_invite list | create | revoke <code>
/admin_user <username>`

func (s *Service) handleHelp(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil {
		return
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   helpText,
	})
}

func (s *Service) handleMe(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil || update.Message.From == nil {
		return
	}
	chatID := update.Message.Chat.ID
	tgID := update.Message.From.ID

	info, err := s.client.UserByTG(ctx, tgID)
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "查询失败:" + err.Error()})
		return
	}
	if !info.Bound {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "你还没绑定 Arcway 账号。向管理员要邀请码后用 /start <code>。",
		})
		return
	}
	summary, err := s.client.UserSummary(ctx, info.Username)
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "查账号信息失败:" + err.Error()})
		return
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   formatSummaryFromClient(summary),
	})
}

// displayUserSummary 渲染用户摘要卡片。
func displayUserSummary(role, username, email string, isActive bool,
	pkg map[string]any, pkgEndDate string,
	totalUp, totalDown, cycleUp, cycleDown int64) string {

	roleZh := "用户"
	if role == "admin" {
		roleZh = "管理员"
	}
	status := "启用"
	if !isActive {
		status = "停用"
	}
	pkgLine := "套餐: 未绑定"
	if pkg != nil && len(pkg) > 0 {
		name, _ := pkg["name"].(string)
		pkgLine = fmt.Sprintf("套餐: %s", name)
	}
	expireLine := ""
	if pkgEndDate != "" {
		if t, err := time.Parse(time.RFC3339, pkgEndDate); err == nil {
			days := int(time.Until(t).Hours() / 24)
			expireLine = fmt.Sprintf("\n到期: %s(剩 %d 天)", t.Format("2006-01-02"), days)
		}
	}
	return fmt.Sprintf(
		"账号: %s\n角色: %s\n状态: %s\n%s%s\nemail: %s\n\n本周期 ↑%s ↓%s · 累计 ↑%s ↓%s",
		username, roleZh, status, pkgLine, expireLine,
		emptyDash(email),
		humanBytes(cycleUp), humanBytes(cycleDown),
		humanBytes(totalUp), humanBytes(totalDown),
	)
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(未填)"
	}
	return s
}

// handleUnbind 二次确认 /unbind UNBIND
func (s *Service) handleUnbind(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil || update.Message.From == nil {
		return
	}
	chatID := update.Message.Chat.ID
	tgID := update.Message.From.ID

	info, err := s.client.UserByTG(ctx, tgID)
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "查询失败:" + err.Error()})
		return
	}
	if !info.Bound {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "你还没绑定 Arcway 账号,无需解绑。"})
		return
	}

	args := strings.TrimSpace(strings.TrimPrefix(update.Message.Text, "/unbind"))
	if args != "UNBIND" {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text: "⚠️ 解绑会让你失去 TG 通知 / /me /sub /traffic 命令。\n" +
				"确认请回复:/unbind UNBIND",
		})
		return
	}
	if _, err := s.client.Unbind(ctx, tgID); err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "解绑失败:" + err.Error()})
		return
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   "已解绑。可用新邀请码 /start <code> 重新绑定。",
	})
}

// humanBytes KB/MB/GB/TB 格式化。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
