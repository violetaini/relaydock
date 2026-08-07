package bot

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// handleSub 列订阅文件 + 拼短链。
//
// URL 拼接:
//   - custom_short_code 非空:`/x/<custom>`
//   - 否则:`/x/<file_short><user_short>`
//
// 订阅链接基址使用主控已有的公网地址设置 + /x，无独立 Bot 主控地址配置。
func (s *Service) handleSub(ctx context.Context, b *bot.Bot, update *models.Update) {
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
			Text:   "你还没绑定 Arcway 账号。/start <code>。",
		})
		return
	}
	subs, err := s.client.UserSubscriptions(ctx, info.Username)
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "查订阅失败:" + err.Error()})
		return
	}

	// 默认订阅(套餐订阅)排在最前,再列管理员分配的订阅文件。
	type subItem struct{ name, desc, code string }
	var items []subItem
	if subs.DefaultSubscription != nil {
		d := subs.DefaultSubscription
		items = append(items, subItem{d.Name + "(默认)", d.Description, d.CombinedCode})
	}
	for _, sf := range subs.Subscriptions {
		items = append(items, subItem{sf.Name, sf.Description, sf.CombinedCode})
	}
	if len(items) == 0 {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "你当前没有订阅。请联系管理员分配套餐或订阅。",
		})
		return
	}

	// 订阅基址复用主控公网地址 + /x(短链路由)，不再单独配置。
	base := strings.TrimRight(s.cfg.PublicBaseURL, "/") + "/x"
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("你的订阅(%d 个):\n\n", len(items)))
	for i, it := range items {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, it.name))
		if it.desc != "" {
			sb.WriteString("   " + it.desc + "\n")
		}
		sb.WriteString(fmt.Sprintf("   %s/%s\n\n", base, it.code))
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: sb.String()})
}

// handleTraffic 显示流量统计(复用 user-summary)。
func (s *Service) handleTraffic(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil || update.Message.From == nil {
		return
	}
	chatID := update.Message.Chat.ID
	tgID := update.Message.From.ID

	info, err := s.client.UserByTG(ctx, tgID)
	if err != nil || !info.Bound {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "你还没绑定 Arcway 账号。/start <code>。"})
		return
	}
	summary, err := s.client.UserSummary(ctx, info.Username)
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "查询失败:" + err.Error()})
		return
	}

	pkgName := "未绑定"
	limitGB := 0.0
	if summary.Package != nil && len(summary.Package) > 0 {
		if v, ok := summary.Package["name"].(string); ok {
			pkgName = v
		}
		if v, ok := summary.Package["traffic_limit_gb"].(float64); ok {
			limitGB = v
		}
	}
	usedBytes := summary.Traffic.CycleUplink + summary.Traffic.CycleDownlink
	pct := 0.0
	if limitGB > 0 {
		pct = float64(usedBytes) / (limitGB * 1024 * 1024 * 1024) * 100
	}

	text := fmt.Sprintf(
		"流量统计 — %s\n套餐: %s\n本周期已用: %s",
		summary.Username, pkgName, humanBytes(usedBytes),
	)
	if limitGB > 0 {
		text += fmt.Sprintf(" / %.0f GB (%.1f%%)", limitGB, pct)
	}
	text += fmt.Sprintf("\n累计 ↑%s ↓%s",
		humanBytes(summary.Traffic.TotalUplink),
		humanBytes(summary.Traffic.TotalDownlink))

	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: text})
}

// handleNodes 列套餐节点 + 服务器在线状态。
func (s *Service) handleNodes(ctx context.Context, b *bot.Bot, update *models.Update) {
	if update.Message == nil || update.Message.From == nil {
		return
	}
	chatID := update.Message.Chat.ID
	tgID := update.Message.From.ID

	info, err := s.client.UserByTG(ctx, tgID)
	if err != nil || !info.Bound {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "你还没绑定 Arcway 账号。/start <code>。"})
		return
	}
	nodes, err := s.client.UserNodes(ctx, info.Username)
	if err != nil {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "查节点失败:" + err.Error()})
		return
	}
	if len(nodes.Nodes) == 0 {
		_, _ = b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: chatID,
			Text:   "套餐内暂无节点(或未绑套餐)。",
		})
		return
	}

	onlineCount := 0
	for _, n := range nodes.Nodes {
		if n.ServerOnline {
			onlineCount++
		}
	}

	// 普通用户只看节点,不暴露底层服务器名/状态/拓扑。
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("节点 %d 个(在线 %d):\n\n", len(nodes.Nodes), onlineCount))
	for i, n := range nodes.Nodes {
		mark := "✅"
		if !n.ServerOnline {
			mark = "❌"
		}
		sb.WriteString(fmt.Sprintf("%d. %s %s  [%s]\n", i+1, mark, n.Name, n.Protocol))
	}
	_, _ = b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: sb.String()})
}
