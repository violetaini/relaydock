package bot

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// handleAdminInvite /admin_invite [list|revoke <code>|create→指 web]
func (s *Service) handleAdminInvite(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil || update.Message.From == nil {
		return
	}
	chatID := update.Message.Chat.ID
	tgID := update.Message.From.ID

	if !s.cfg.IsAdmin(tgID) {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "本命令仅管理员可用。"})
		return
	}

	args := strings.Fields(strings.TrimSpace(strings.TrimPrefix(update.Message.Text, "/admin_invite")))
	subcmd := "list"
	if len(args) > 0 {
		subcmd = strings.ToLower(args[0])
	}

	switch subcmd {
	case "list":
		items, err := s.client.ListInvites(ctx, 20)
		if err != nil {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "list 失败:" + err.Error()})
			return
		}
		if len(items) == 0 {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "暂无邀请码。"})
			return
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("邀请码(最近 %d 条):\n\n", len(items)))
		for _, ic := range items {
			status := "✓ 可用"
			if ic.Revoked {
				status = "✗ 已撤销"
			} else if !ic.Usable {
				status = "○ 已用尽/过期"
			}
			sb.WriteString(fmt.Sprintf("%s [%s] %s · %d/%d\n", ic.Code, ic.Kind, status, ic.UsedCount, ic.MaxUses))
		}
		sb.WriteString("\n完整管理请用 web UI:/tg-bot-invites")
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: sb.String()})

	case "revoke":
		if len(args) < 2 {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "用法: /admin_invite revoke <code>"})
			return
		}
		if err := s.client.RevokeInvite(ctx, args[1]); err != nil {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "撤销失败:" + err.Error()})
			return
		}
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "已撤销:" + args[1]})

	case "create":
		s.startInviteCreate(ctx, b, chatID)

	default:
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "用法: /admin_invite list | create | revoke <code>",
		})
	}
}

// handleAdminUser /admin_user <username>
func (s *Service) handleAdminUser(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil || update.Message.From == nil {
		return
	}
	chatID := update.Message.Chat.ID
	tgID := update.Message.From.ID

	if !s.cfg.IsAdmin(tgID) {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "本命令仅管理员可用。"})
		return
	}

	args := strings.Fields(strings.TrimSpace(strings.TrimPrefix(update.Message.Text, "/admin_user")))
	if len(args) < 1 {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "用法: /admin_user <username>"})
		return
	}
	summary, err := s.client.UserSummary(ctx, args[0])
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "查询失败:" + err.Error()})
		return
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   formatSummaryFromClient(summary),
	})
}

// handleAnnounce /announce <公告内容> — 管理员发布一条公告(广播给所有绑定 TG 的用户 + Mini App 横幅)。
func (s *Service) handleAnnounce(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil || update.Message.From == nil {
		return
	}
	chatID := update.Message.Chat.ID
	tgID := update.Message.From.ID
	if !s.cfg.IsAdmin(tgID) {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "本命令仅管理员可用。"})
		return
	}
	body := strings.TrimSpace(strings.TrimPrefix(update.Message.Text, "/announce"))
	if body == "" {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "用法: /announce <公告内容>\n将广播给所有绑定 TG 的用户,并显示在 Mini App。"})
		return
	}
	if err := s.client.PostAnnouncement(ctx, "公告", body); err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "发布失败:" + err.Error()})
		return
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "✅ 公告已发布,将在 1 分钟内广播给所有用户,并显示在 Mini App。"})
}
