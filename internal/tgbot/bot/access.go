package bot

import (
	"context"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// rateLimitUpdate applies one shared quota to messages and button callbacks
// before either can trigger an authorization lookup or a business handler.
func (s *Service) rateLimitUpdate(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		tgID, _, ok := updateIdentity(update)
		if !ok || !allowTGID(tgID) {
			return
		}
		next(ctx, b, update)
	}
}

// authorizeUpdate keeps the Bot private while preserving invite-based
// onboarding. Unknown Telegram accounts can reach only the authoritative
// /start invite check; subsequent registration replies are admitted through
// the in-memory registration session.
func (s *Service) authorizeUpdate(next bot.HandlerFunc) bot.HandlerFunc {
	return func(ctx context.Context, b *bot.Bot, update *models.Update) {
		tgID, private, ok := updateIdentity(update)
		if !ok || !private {
			return
		}

		if s.cfg.IsAdmin(tgID) {
			next(ctx, b, update)
			return
		}

		if update.Message != nil {
			if _, ok := startInviteCode(update.Message.Text); ok {
				next(ctx, b, update)
				return
			}
			if s.isRegistrationReply(tgID, update.Message.Text) {
				next(ctx, b, update)
				return
			}
		}

		info, err := s.client.UserByTG(ctx, tgID)
		if err != nil || !info.Bound {
			return
		}
		next(ctx, b, update)
	}
}

func updateIdentity(update *models.Update) (tgID int64, private bool, ok bool) {
	if update == nil {
		return 0, false, false
	}
	if update.Message != nil && update.Message.From != nil {
		return update.Message.From.ID, update.Message.Chat.Type == models.ChatTypePrivate, true
	}
	if update.CallbackQuery != nil {
		message := update.CallbackQuery.Message.Message
		if message == nil {
			return 0, false, false
		}
		return update.CallbackQuery.From.ID, message.Chat.Type == models.ChatTypePrivate, true
	}
	return 0, false, false
}

func startInviteCode(text string) (string, bool) {
	command, args, ok := telegramCommand(text)
	if !ok || command != "start" || len(args) != 1 {
		return "", false
	}
	return strings.ToUpper(args[0]), true
}

func telegramCommand(text string) (command string, args []string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return "", nil, false
	}
	command = strings.TrimPrefix(fields[0], "/")
	if at := strings.IndexByte(command, '@'); at >= 0 {
		command = command[:at]
	}
	if command == "" {
		return "", nil, false
	}
	return strings.ToLower(command), fields[1:], true
}

func commandAtStart(update *models.Update, expected string) bool {
	if update == nil || update.Message == nil {
		return false
	}
	command, _, ok := telegramCommand(update.Message.Text)
	return ok && command == expected
}

func (s *Service) isRegistrationReply(tgID int64, text string) bool {
	s.regSessionsMu.Lock()
	defer s.regSessionsMu.Unlock()
	raw, ok := s.regSessions.Load(tgID)
	if !ok {
		return false
	}
	session, ok := raw.(*regSession)
	if !ok || time.Now().After(session.expiresAt) {
		s.regSessions.Delete(tgID)
		return false
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	return !strings.HasPrefix(text, "/") || strings.EqualFold(text, "/cancel")
}
