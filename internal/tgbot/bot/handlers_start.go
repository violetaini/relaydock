package bot

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

// handleStart /start 入口。
//
//	A) 无 code:已绑 → 主菜单;未绑 → 提示要邀请码
//	B) /start <code>:校验 kind = bind → 调主控 /bind kind=bind
//	   /start <code>:校验 kind = new  → 开启多步注册对话(收集 username/email)
//
// 群聊更新由全局访问中间件静默拒绝，避免邀请码和账号信息回显。
func (s *Service) handleStart(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil || update.Message.From == nil {
		return
	}
	chatID := update.Message.Chat.ID
	tgID := update.Message.From.ID
	tgHandle := update.Message.From.Username

	if update.Message.Chat.Type != "private" {
		return
	}

	info, userErr := s.client.UserByTG(ctx, tgID)
	knownUser := s.cfg.IsAdmin(tgID) || (userErr == nil && info.Bound)

	command, args, validCommand := telegramCommand(update.Message.Text)
	if !validCommand || command != "start" {
		return
	}

	// A 无 code
	if len(args) == 0 {
		if !knownUser {
			return
		}
		if info != nil && info.Bound {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
				ChatID: chatID,
				Text: fmt.Sprintf("已绑定账号:%s\n\n常用:/me /sub /traffic /nodes /unbind /help",
					info.Username),
			})
			return
		}
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text: "欢迎使用 Arcway。\n" +
				"本系统仅接受邀请码注册/绑定。请联系管理员要邀请码后用 /start <code>。",
		})
		return
	}

	// B/C 有 code
	if len(args) != 1 {
		return
	}
	code := strings.ToUpper(args[0])

	// 注册邀请码需要先知道 kind,但不能从管理列表里找:列表有条数上限,
	// 会让较早创建、仍有效的深链被误判为不存在。
	ic, found, err := s.client.LookupInvite(ctx, code)
	if err != nil {
		if knownUser {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "查询邀请码失败:" + err.Error()})
		}
		return
	}
	if !found {
		if knownUser {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "邀请码不存在。"})
		}
		return
	}
	if !ic.Usable {
		if !knownUser {
			return
		}
		reason := "邀请码已不可用"
		if ic.Revoked {
			reason = "邀请码已被撤销"
		} else if ic.UsedCount >= ic.MaxUses {
			reason = "邀请码已用尽"
		}
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: reason})
		return
	}

	// 已绑 → 拒
	if info != nil && info.Bound {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   fmt.Sprintf("当前 TG 已绑定到 %s,请先 /unbind 解绑。", info.Username),
		})
		return
	}

	switch ic.Kind {
	case "bind":
		s.doBind(ctx, b, chatID, tgID, tgHandle, code)
	case "new":
		s.startRegistration(ctx, b, chatID, tgID, ic)
	}
}

// doBind 直接调主控 /bind(kind=bind 时无需多步对话)。
func (s *Service) doBind(ctx context.Context, b *bot.Bot, chatID, tgID int64, tgHandle, code string) {
	resp, err := s.client.Bind(ctx, mmwxclient.BindRequest{
		Code:           code,
		TelegramID:     tgID,
		TelegramHandle: tgHandle,
	})
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "绑定失败:" + err.Error()})
		return
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text: fmt.Sprintf("绑定成功:%s\n\n/me /sub /traffic /nodes /unbind /help",
			resp.Username),
	})
}
