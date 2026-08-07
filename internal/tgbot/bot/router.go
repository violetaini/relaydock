package bot

import (
	"context"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// registerCommands 注册所有命令。B2 阶段先 /help + 占位 /start,B4 补全。
func registerCommands(b *bot.Bot, s *Service) {
	// go-telegram/bot 的 MatchTypeCommand 比对的是去掉前导 "/" 后的命令名,
	// 所以注册 pattern 不能带 "/"(消息原文仍是 "/help",handler 内 TrimPrefix 不受影响)。
	b.RegisterHandler(bot.HandlerTypeMessageText, "help", bot.MatchTypeCommand, s.handleHelp)
	b.RegisterHandler(bot.HandlerTypeMessageText, "start", bot.MatchTypeCommand, s.handleStart)
	b.RegisterHandler(bot.HandlerTypeMessageText, "me", bot.MatchTypeCommand, s.handleMe)
	b.RegisterHandler(bot.HandlerTypeMessageText, "sub", bot.MatchTypeCommand, s.handleSub)
	b.RegisterHandler(bot.HandlerTypeMessageText, "traffic", bot.MatchTypeCommand, s.handleTraffic)
	b.RegisterHandler(bot.HandlerTypeMessageText, "nodes", bot.MatchTypeCommand, s.handleNodes)
	b.RegisterHandler(bot.HandlerTypeMessageText, "unbind", bot.MatchTypeCommand, s.handleUnbind)
	b.RegisterHandler(bot.HandlerTypeMessageText, "notify", bot.MatchTypeCommand, s.handleNotify)
	b.RegisterHandler(bot.HandlerTypeMessageText, "admin_invite", bot.MatchTypeCommand, s.withRateLimit(s.handleAdminInvite))
	b.RegisterHandler(bot.HandlerTypeMessageText, "admin_user", bot.MatchTypeCommand, s.withRateLimit(s.handleAdminUser))
	b.RegisterHandler(bot.HandlerTypeMessageText, "announce", bot.MatchTypeCommand, s.withRateLimit(s.handleAnnounce))
	// /admin_invite create 的按钮交互回调(类型/套餐/有效期)。
	b.RegisterHandler(bot.HandlerTypeCallbackQueryData, "iv:", bot.MatchTypePrefix, s.handleInviteCallback)
}

// setMyCommands 注册 Telegram 命令菜单(输入 / 时弹出提示)。
// 默认作用域给所有用户看普通命令;管理员的私聊额外追加 admin 命令。
func (s *Service) setMyCommands(ctx context.Context, b *bot.Bot) error {
	userCmds := []models.BotCommand{
		{Command: "start", Description: "用邀请码注册或绑定账号"},
		{Command: "me", Description: "我的账号信息"},
		{Command: "sub", Description: "订阅链接"},
		{Command: "traffic", Description: "流量统计"},
		{Command: "nodes", Description: "我的节点"},
		{Command: "notify", Description: "通知开关 on/off/status"},
		{Command: "unbind", Description: "解绑 TG"},
		{Command: "help", Description: "帮助"},
	}
	if _, err := b.SetMyCommands(ctx, &bot.SetMyCommandsParams{
		Commands: userCmds,
		Scope:    &models.BotCommandScopeDefault{},
	}); err != nil {
		return err
	}

	adminCmds := append(append([]models.BotCommand{}, userCmds...),
		models.BotCommand{Command: "admin_invite", Description: "邀请码 list/create/revoke"},
		models.BotCommand{Command: "admin_user", Description: "查指定用户"},
		models.BotCommand{Command: "announce", Description: "发布公告(广播给所有用户)"},
	)
	for _, id := range s.cfg.AdminTGIDs {
		if _, err := b.SetMyCommands(ctx, &bot.SetMyCommandsParams{
			Commands: adminCmds,
			Scope:    &models.BotCommandScopeChat{ChatID: id},
		}); err != nil {
			return err
		}
	}
	return nil
}

// defaultHandler 处理未注册的消息(多步对话状态机入口)。
func (s *Service) defaultHandler(ctx context.Context, b *bot.Bot, update *models.Update) {
	if s.continueInviteCreate(ctx, b, update) {
		return
	}
	if s.continueRegistration(ctx, b, update) {
		return
	}
}

// withRateLimit per-tg_id 5次/分钟。
func (s *Service) withRateLimit(h bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		if update.Message != nil && update.Message.From != nil {
			if !allowTGID(update.Message.From.ID) {
				_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
					ChatID: update.Message.Chat.ID,
					Text:   "操作太频繁,请稍后再试(每分钟限 5 次)。",
				})
				return
			}
		}
		h(ctx, b, update)
	}
}
