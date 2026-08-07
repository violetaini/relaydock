package bot

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

// 用户自助通知:/notify on|off|status。开启后 bot 每天 notifyHour 点推流量,
// 套餐剩 7/3/1 天时单独推到期提醒。开关状态存主控(bot 无本地库)。

const notifyHour = 20 // 每日推送时间(服务器本地时区,20:00)

var expiryRemindDays = []int{7, 3, 1}

// handleNotify 处理 /notify on|off|status(无参=status)。
func (s *Service) handleNotify(ctx context.Context, b *bot.Bot, update *models.Update) {
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
			Text:   "你还没绑定 Arcway 账号。先 /start <code> 绑定后再开通知。",
		})
		return
	}

	arg := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(update.Message.Text, "/notify")))
	switch arg {
	case "on":
		if err := s.client.SetNotify(ctx, tgID, true); err != nil {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "开启失败:" + err.Error()})
			return
		}
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   fmt.Sprintf("✅ 已开启通知。每天 %02d:00 推送流量,套餐临近到期(7/3/1 天)会提醒。\n关闭:/notify off", notifyHour),
		})
	case "off":
		if err := s.client.SetNotify(ctx, tgID, false); err != nil {
			_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "关闭失败:" + err.Error()})
			return
		}
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "已关闭通知。重新开启:/notify on"})
	case "", "status":
		state := "未开启"
		if info.NotifyEnabled {
			state = "已开启"
		}
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   fmt.Sprintf("通知当前:%s\n\n/notify on 开启 · /notify off 关闭", state),
		})
	default:
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "用法: /notify on | off | status"})
	}
}

// runDailyNotifier 每日 notifyHour 点推送一次。随 ctx 取消退出。
func (s *Service) runDailyNotifier(ctx context.Context, b *bot.Bot) {
	for {
		next := nextNotifyTime(time.Now())
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			s.pushDailyNotifications(ctx, b)
		}
	}
}

// nextNotifyTime 返回下一个 notifyHour:00(今天若已过则明天)。
func nextNotifyTime(now time.Time) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), notifyHour, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

// pushDailyNotifications 拉名单 → 逐用户推流量 + 临期提醒。
func (s *Service) pushDailyNotifications(ctx context.Context, b *bot.Bot) {
	users, err := s.client.NotifyDigest(ctx)
	if err != nil {
		log.Printf("[notify] 拉取推送名单失败: %v", err)
		return
	}
	sent := 0
	for _, u := range users {
		if u.TelegramID == 0 {
			continue
		}
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: u.TelegramID, Text: formatDailyTraffic(u)})
		sent++

		if d, ok := daysUntil(u.PackageEndDate); ok {
			for _, thr := range expiryRemindDays {
				if d == thr {
					_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
						ChatID: u.TelegramID,
						Text:   fmt.Sprintf("⚠️ 套餐还剩 %d 天到期,请及时续费,以免服务中断。", d),
					})
				}
			}
		}
	}
	log.Printf("[notify] 每日推送完成,共 %d 个用户", sent)
}

// announcePollInterval 公告轮询间隔:每分钟拉一次主控待推送公告并广播。
const announcePollInterval = 60 * time.Second

// Telegram Bot API accepts at most 4096 Unicode characters in a text message.
const telegramMessageMaxRunes = 4096

// runAnnouncementBroadcaster 周期轮询主控的待推送公告,广播给所有绑定 TG 的用户。
func (s *Service) runAnnouncementBroadcaster(ctx context.Context, b *bot.Bot) {
	ticker := time.NewTicker(announcePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.broadcastPendingAnnouncements(ctx, b)
		}
	}
}

func (s *Service) broadcastPendingAnnouncements(ctx context.Context, b *bot.Bot) {
	items, err := s.client.PendingAnnouncements(ctx)
	if err != nil {
		log.Printf("[announce] 拉取待推送公告失败: %v", err)
		return
	}
	broadcastAnnouncements(ctx, items,
		func(ctx context.Context, telegramID int64, text string) error {
			_, err := b.SendMessage(ctx, &bot.SendMessageParams{ChatID: telegramID, Text: text})
			return err
		},
		s.client.MarkAnnouncementRecipientDelivered,
		s.client.MarkAnnouncementDelivered,
	)
}

type announcementSendFunc func(context.Context, int64, string) error
type announcementRecipientDeliveredFunc func(context.Context, int64, int64) error
type announcementDeliveredFunc func(context.Context, int64) error

func broadcastAnnouncements(
	ctx context.Context,
	items []mmwxclient.Announcement,
	send announcementSendFunc,
	markRecipientDelivered announcementRecipientDeliveredFunc,
	markDelivered announcementDeliveredFunc,
) {
	for _, a := range items {
		if ctx.Err() != nil {
			return
		}
		parts := splitTelegramMessage(formatAnnouncement(a.Title, a.Body), telegramMessageMaxRunes)
		sent := 0
		hadFailure := false
		for _, tgID := range a.Recipients { // 收件人已由主控按「有套餐 + 节点归属」定向筛好
			if ctx.Err() != nil {
				return
			}
			if tgID == 0 {
				continue
			}
			recipientSent := true
			for _, part := range parts {
				if ctx.Err() != nil {
					return
				}
				if err := send(ctx, tgID, part); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("[announce] 公告 #%d 向 TG %d 推送失败: %v", a.ID, tgID, err)
					recipientSent = false
					hadFailure = true
					break
				}
			}
			if !recipientSent {
				continue
			}
			if err := markRecipientDelivered(ctx, a.ID, tgID); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[announce] 回填公告 %d 收件人 TG %d 投递状态失败: %v", a.ID, tgID, err)
				hadFailure = true
				continue
			}
			sent++
			if !waitForContext(ctx, 50*time.Millisecond) { // 限速 ~20 msg/s,避免 Telegram 429
				return
			}
		}
		if hadFailure {
			// 每个成功收件人均已独立记账；失败收件人留在下一轮 pending
			// 中，但不能阻塞同批次后面的公告。
			continue
		}
		// 所有当前待投递收件人均完成后回填整条公告；若回填失败，
		// 下一轮 pending 会返回空收件人，不会重发已记账的用户。
		if err := markDelivered(ctx, a.ID); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[announce] 回填公告 %d 投递状态失败: %v", a.ID, err)
			continue
		}
		log.Printf("[announce] 公告 #%d 已推送 %d 个用户", a.ID, sent)
	}
}

func splitTelegramMessage(text string, maxRunes int) []string {
	if maxRunes <= 0 {
		return []string{text}
	}
	runes := []rune(text)
	if len(runes) == 0 {
		return []string{""}
	}
	parts := make([]string, 0, (len(runes)+maxRunes-1)/maxRunes)
	for len(runes) > 0 {
		n := maxRunes
		if len(runes) < n {
			n = len(runes)
		}
		parts = append(parts, string(runes[:n]))
		runes = runes[n:]
	}
	return parts
}

func waitForContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func formatAnnouncement(title, body string) string {
	if strings.TrimSpace(title) == "" {
		return body
	}
	return "📢 " + title + "\n\n" + body
}

// formatDailyTraffic 渲染每日流量播报(同 /traffic 口径)。
func formatDailyTraffic(u mmwxclient.NotifyUser) string {
	pkgName := u.PackageName
	if pkgName == "" {
		pkgName = "未绑定"
	}
	usedBytes := u.CycleUplink + u.CycleDownlink
	text := fmt.Sprintf("📊 每日流量播报 — %s\n套餐: %s\n本周期已用: %s",
		u.Username, pkgName, humanBytes(usedBytes))
	if u.TrafficLimitGB > 0 {
		pct := float64(usedBytes) / (u.TrafficLimitGB * 1024 * 1024 * 1024) * 100
		text += fmt.Sprintf(" / %.0f GB (%.1f%%)", u.TrafficLimitGB, pct)
	}
	text += fmt.Sprintf("\n累计 ↑%s ↓%s", humanBytes(u.TotalUplink), humanBytes(u.TotalDownlink))
	return text
}

// daysUntil 解析 RFC3339 到期时间,返回距今的「日历天数」。空/非法返回 ok=false。
func daysUntil(endRFC3339 string) (int, bool) {
	if strings.TrimSpace(endRFC3339) == "" {
		return 0, false
	}
	end, err := time.Parse(time.RFC3339, endRFC3339)
	if err != nil {
		return 0, false
	}
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endDay := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, now.Location())
	return int(endDay.Sub(today).Hours() / 24), true
}
