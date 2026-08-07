package bot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

// /admin_invite create 的按钮交互流程。
//
// 状态尽量编码进 callback_data,免服务端存储:
//
//	iv:k:new            选「新建账号」→ 列套餐
//	iv:k:bind           选「绑定已有」→ 进文字会话收用户名
//	iv:p:<pkgid>        选套餐(0=不绑)→ 列有效期(0 直接创建)
//	iv:d:<pkgid>:<mon>  选有效期 → 创建 kind=new(mon>1 主控自动开续期)
//	iv:x                取消
//
// 仅 kind=bind 需要文字输入(用户名),用下面这个带 TTL 的 session。
var adminInviteSessions = sync.Map{} // tgID(int64) → *inviteCreateSession

type inviteCreateSession struct {
	expiresAt time.Time
}

// durationChoices 有效期按钮(月)。>1 月主控会自动开按月续期,1 月不开。
var durationChoices = []int{1, 2, 3, 6, 12}

func durationLabel(months int) string {
	if months == 12 {
		return "1 年"
	}
	return fmt.Sprintf("%d 个月", months)
}

// startInviteCreate 入口:让管理员先选邀请码类型。
func (s *Service) startInviteCreate(ctx context.Context, b *bot.Bot, chatID int64) {
	kb := &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{{Text: "🆕 新建账号", CallbackData: "iv:k:new"}},
		{{Text: "🔗 绑定已有账号", CallbackData: "iv:k:bind"}},
		{{Text: "取消", CallbackData: "iv:x"}},
	}}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID:      chatID,
		Text:        "创建邀请码 — 请选择类型:",
		ReplyMarkup: kb,
	})
}

// handleInviteCallback 处理 iv:* 回调。注册于 router(HandlerTypeCallbackQueryData, 前缀 iv:)。
func (s *Service) handleInviteCallback(ctx context.Context, b *bot.Bot, update *models.Update) {
	cq := update.CallbackQuery
	if cq == nil {
		return
	}
	// 先应答,消掉按钮 loading 转圈
	defer b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: cq.ID})

	if !s.cfg.IsAdmin(cq.From.ID) {
		_, _ = b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{
			CallbackQueryID: cq.ID, Text: "仅管理员可用", ShowAlert: true,
		})
		return
	}
	if cq.Message.Message == nil { // 消息不可访问(太旧),忽略
		return
	}
	chatID := cq.Message.Message.Chat.ID
	msgID := cq.Message.Message.ID

	parts := strings.Split(cq.Data, ":")
	if len(parts) < 2 {
		return
	}

	switch parts[1] {
	case "x":
		s.editText(ctx, b, chatID, msgID, "已取消创建邀请码。")

	case "k":
		if len(parts) < 3 {
			return
		}
		switch parts[2] {
		case "new":
			s.showPackageButtons(ctx, b, chatID, msgID)
		case "bind":
			adminInviteSessions.Store(cq.From.ID, &inviteCreateSession{expiresAt: time.Now().Add(10 * time.Minute)})
			s.editText(ctx, b, chatID, msgID, "请发送要绑定的已有账号用户名(3-20 字符,字母数字 _ -),或发送 /cancel 取消:")
		}

	case "p":
		if len(parts) < 3 {
			return
		}
		pkgID, _ := strconv.ParseInt(parts[2], 10, 64)
		if pkgID == 0 { // 不绑套餐 → 没有有效期概念,直接创建
			s.finishCreateNew(ctx, b, chatID, msgID, 0, 0)
			return
		}
		s.showDurationButtons(ctx, b, chatID, msgID, pkgID)

	case "d":
		if len(parts) < 4 {
			return
		}
		pkgID, _ := strconv.ParseInt(parts[2], 10, 64)
		months, _ := strconv.Atoi(parts[3])
		s.finishCreateNew(ctx, b, chatID, msgID, pkgID, months)
	}
}

// showPackageButtons 列出套餐供选择。
func (s *Service) showPackageButtons(ctx context.Context, b *bot.Bot, chatID int64, msgID int) {
	pkgs, err := s.client.ListPackages(ctx)
	if err != nil {
		s.editText(ctx, b, chatID, msgID, "拉取套餐失败:"+err.Error())
		return
	}
	rows := make([][]models.InlineKeyboardButton, 0, len(pkgs)+2)
	for _, p := range pkgs {
		rows = append(rows, []models.InlineKeyboardButton{{
			Text:         fmt.Sprintf("%s(%.0f GB / %d 天)", p.Name, p.TrafficLimitGB, p.CycleDays),
			CallbackData: fmt.Sprintf("iv:p:%d", p.ID),
		}})
	}
	rows = append(rows,
		[]models.InlineKeyboardButton{{Text: "不绑套餐", CallbackData: "iv:p:0"}},
		[]models.InlineKeyboardButton{{Text: "取消", CallbackData: "iv:x"}},
	)
	s.editTextKB(ctx, b, chatID, msgID, "选择要绑定的套餐:", &models.InlineKeyboardMarkup{InlineKeyboard: rows})
}

// showDurationButtons 列出有效期供选择。
func (s *Service) showDurationButtons(ctx context.Context, b *bot.Bot, chatID int64, msgID int, pkgID int64) {
	row := make([]models.InlineKeyboardButton, 0, len(durationChoices))
	for _, m := range durationChoices {
		row = append(row, models.InlineKeyboardButton{
			Text:         durationLabel(m),
			CallbackData: fmt.Sprintf("iv:d:%d:%d", pkgID, m),
		})
	}
	kb := &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		row,
		{{Text: "取消", CallbackData: "iv:x"}},
	}}
	s.editTextKB(ctx, b, chatID, msgID,
		"选择账号有效期(超过 1 个月自动开启按月续期):", kb)
}

// finishCreateNew 创建 kind=new 邀请码并展示结果。
func (s *Service) finishCreateNew(ctx context.Context, b *bot.Bot, chatID int64, msgID int, pkgID int64, months int) {
	req := mmwxclient.CreateInviteRequest{Kind: "new", MaxUses: 1}
	if pkgID > 0 {
		req.PackageID = &pkgID
		req.DurationMonths = months
	}
	code, err := s.client.CreateInvite(ctx, req)
	if err != nil {
		s.editText(ctx, b, chatID, msgID, "创建失败:"+err.Error())
		return
	}

	detail := "不绑套餐"
	if pkgID > 0 {
		renew := "不续期"
		if months > 1 {
			renew = "自动按月续期"
		}
		detail = fmt.Sprintf("套餐 #%d · 有效期 %s · %s", pkgID, durationLabel(months), renew)
	}
	s.editText(ctx, b, chatID, msgID, fmt.Sprintf(
		"✅ 已创建新建账号邀请码\n\n码:%s\n%s\n使用次数:1\n\n发给用户:/start %s",
		code, detail, code))
}

// continueInviteCreate 消费 kind=bind 的用户名文字输入。返回 true 表示已处理。
func (s *Service) continueInviteCreate(ctx context.Context, b *bot.Bot, update *models.Update) bool {
	if update.Message == nil || update.Message.From == nil {
		return false
	}
	tgID := update.Message.From.ID
	chatID := update.Message.Chat.ID

	raw, ok := adminInviteSessions.Load(tgID)
	if !ok {
		return false
	}
	sess := raw.(*inviteCreateSession)
	if time.Now().After(sess.expiresAt) {
		adminInviteSessions.Delete(tgID)
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "创建对话已超时,请重新 /admin_invite create。"})
		return true
	}

	text := strings.TrimSpace(update.Message.Text)
	if strings.EqualFold(text, "/cancel") || strings.EqualFold(text, "取消") {
		adminInviteSessions.Delete(tgID)
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "已取消创建邀请码。"})
		return true
	}
	if !usernameRe.MatchString(text) {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "用户名格式不对(3-20 字符,字母数字 _ -)。请重发或 /cancel:",
		})
		return true
	}

	defer adminInviteSessions.Delete(tgID)
	code, err := s.client.CreateInvite(ctx, mmwxclient.CreateInviteRequest{
		Kind: "bind", BindUsername: text, MaxUses: 1,
	})
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "创建失败:" + err.Error()})
		return true
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text: fmt.Sprintf("✅ 已创建绑定邀请码\n\n码:%s\n绑定到账号:%s\n使用次数:1\n\n发给用户:/start %s",
			code, text, code),
	})
	return true
}

// editText 编辑消息文本并清掉键盘。
func (s *Service) editText(ctx context.Context, b *bot.Bot, chatID int64, msgID int, text string) {
	_, _ = b.EditMessageText(ctx, &bot.EditMessageTextParams{ChatID: chatID, MessageID: msgID, Text: text})
}

// editTextKB 编辑消息文本并替换键盘。
func (s *Service) editTextKB(ctx context.Context, b *bot.Bot, chatID int64, msgID int, text string, kb *models.InlineKeyboardMarkup) {
	_, _ = b.EditMessageText(ctx, &bot.EditMessageTextParams{ChatID: chatID, MessageID: msgID, Text: text, ReplyMarkup: kb})
}
