package bot

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

// 多步对话状态机:kind='new' 邀请码 → 问"用户名"→"邮箱"→ 调主控 /bind(kind=new)。
// 状态 in-memory(单实例;多副本部署不可用,plan 已说明)。

type regStep string

const (
	stepWaitingUsername regStep = "waiting_username"
	stepWaitingEmail    regStep = "waiting_email"

	regSessionTTL = 10 * time.Minute
)

type regSession struct {
	code      string
	step      regStep
	username  string
	expiresAt time.Time
}

var (
	regSessions = sync.Map{} // tg_id (int64) → *regSession
	usernameRe  = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,20}$`)
	emailRe     = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

// startRegistration 在 kind='new' 邀请码 + tg 未绑 + 可用 校验后调用。
func (s *Service) startRegistration(ctx context.Context, b *bot.Bot, chatID, tgID int64, ic *mmwxclient.Invite) {
	regSessions.Store(tgID, &regSession{
		code:      ic.Code,
		step:      stepWaitingUsername,
		expiresAt: time.Now().Add(regSessionTTL),
	})
	pkgLine := ""
	if ic.PackageID != nil {
		pkgLine = fmt.Sprintf("\n(注册后自动绑套餐 #%d)", *ic.PackageID)
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text:   fmt.Sprintf("邀请码有效,开始注册。%s\n\n请发送用户名(3-20 字符,字母数字 _ -):", pkgLine),
	})
}

// continueRegistration 状态机消费用户回复。返回 true 表示已处理。
func (s *Service) continueRegistration(ctx context.Context, b *bot.Bot, update *models.Update) bool {
	if update.Message == nil || update.Message.From == nil {
		return false
	}
	tgID := update.Message.From.ID
	chatID := update.Message.Chat.ID
	text := strings.TrimSpace(update.Message.Text)

	raw, ok := regSessions.Load(tgID)
	if !ok {
		return false
	}
	sess := raw.(*regSession)

	if time.Now().After(sess.expiresAt) {
		regSessions.Delete(tgID)
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "注册对话已超时,请重新 /start <code>。",
		})
		return true
	}
	if strings.EqualFold(text, "/cancel") || strings.EqualFold(text, "取消") {
		regSessions.Delete(tgID)
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "已取消注册。"})
		return true
	}

	switch sess.step {
	case stepWaitingUsername:
		if !usernameRe.MatchString(text) {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   "用户名格式不对(3-20 字符,字母数字 _ -)。请重发或 /cancel:",
			})
			return true
		}
		sess.username = text
		sess.step = stepWaitingEmail
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "邮箱(用于密码找回,回复 skip 跳过):",
		})
		return true

	case stepWaitingEmail:
		email := text
		if strings.EqualFold(email, "skip") {
			email = ""
		} else if !emailRe.MatchString(email) {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   "邮箱格式不对。重发或 skip:",
			})
			return true
		}
		s.finishRegistration(ctx, b, chatID, tgID, update.Message.From.Username, sess, email)
		return true
	}
	return false
}

func (s *Service) finishRegistration(ctx context.Context, b *bot.Bot,
	chatID, tgID int64, tgHandle string, sess *regSession, email string) {

	defer regSessions.Delete(tgID)

	resp, err := s.client.Bind(ctx, mmwxclient.BindRequest{
		Code:           sess.code,
		TelegramID:     tgID,
		TelegramHandle: tgHandle,
		Username:       sess.username,
		Email:          email,
	})
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "注册失败:" + err.Error()})
		return
	}

	pkgInfo := ""
	if resp.Package != nil && len(resp.Package) > 0 {
		name, _ := resp.Package["package_name"].(string)
		gb, _ := resp.Package["traffic_limit_gb"].(float64)
		days, _ := resp.Package["cycle_days"].(float64)
		end, _ := resp.Package["end_date"].(string)
		pkgInfo = fmt.Sprintf("\n套餐:%s (%.0f GB / %.0f 天),到期 %s", name, gb, days, end)
	}

	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: chatID,
		Text: fmt.Sprintf("✅ 注册成功\n\n账号:%s\n初始密码:%s%s\n\n建议尽快登录 web 改密码。\n/me /sub /traffic /nodes /unbind /help",
			resp.Username, resp.InitialPassword, pkgInfo),
	})
}
