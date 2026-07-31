package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const telegramAPIBase = "https://api.telegram.org/bot"

var httpClient = &http.Client{Timeout: 10 * time.Second}

func sendTelegram(ctx context.Context, botToken, chatID, text string) error {
	if botToken == "" || chatID == "" {
		return fmt.Errorf("bot token or chat ID is empty")
	}

	endpoint := telegramAPIBase + botToken + "/sendMessage"
	params := url.Values{
		"chat_id":    {chatID},
		"text":       {text},
		"parse_mode": {"Markdown"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("create telegram request: %w", redactTelegramError(err, botToken, chatID))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram: %w", redactTelegramError(err, botToken, chatID))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var result struct {
			OK          bool   `json:"ok"`
			Description string `json:"description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&result)
		return fmt.Errorf("telegram API error (status %d): %s", resp.StatusCode,
			redactTelegramText(result.Description, botToken, chatID))
	}

	return nil
}

func redactTelegramError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(redactTelegramText(err.Error(), secrets...))
}

func redactTelegramText(value string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}

// markdownEscaper 转义 Telegram legacy Markdown 的特殊字符。
var markdownEscaper = strings.NewReplacer("_", "\\_", "*", "\\*", "`", "\\`", "[", "\\[")

// EscapeMarkdown 把用户名/服务器名等动态内容安全地嵌进带 *bold* / `code` 的消息模板。
// 未转义时,含下划线(或 * ` [)的用户名会让 TG 的 Markdown 解析失败 → 400 bad request。
func EscapeMarkdown(s string) string {
	return markdownEscaper.Replace(s)
}
