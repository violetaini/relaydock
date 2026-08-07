// Package bot 实现 Arcway 内嵌 Telegram Bot 的命令和 Mini App 路由。
package bot

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/violetaini/relaydock/internal/tgbot/config"
	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

type Service struct {
	mu          sync.Mutex
	cfg         config.Config
	client      *mmwxclient.Client
	b           *bot.Bot
	cancel      context.CancelFunc
	pollDone    chan struct{}
	webHandler  http.Handler
	botUsername string // 由 getMe 获取,用于兑换码文案的 {机器人地址} = https://t.me/<botUsername>

	// Mini App 主题跟随主控「默认主题」的 60s 缓存(见 cachedDefaultTheme)
	themeMu  sync.Mutex
	themeVal string
	themeExp time.Time

	// Mini App 左上角标题跟随主控自定义品牌标题，缓存策略同主题。
	brandMu  sync.Mutex
	brandVal string
	brandExp time.Time
}

// botURL 返回机器人的 t.me 链接;拿不到 username 时返回空串。
func (s *Service) botURL() string {
	if s.botUsername == "" {
		return ""
	}
	return "https://t.me/" + s.botUsername
}

// BotURL 返回 getMe 探测到的机器人公开地址。
func (s *Service) BotURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.botURL()
}

func New(cfg config.Config, client *mmwxclient.Client) *Service {
	s := &Service{cfg: cfg, client: client}
	s.webHandler = s.newWebAppHandler()
	return s
}

func (s *Service) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := bot.New(s.cfg.TGBotToken, bot.WithDefaultHandler(s.defaultHandler))
	if err != nil {
		return errors.New("Telegram Bot 配置无效")
	}
	registerCommands(b, s)

	// getMe 是启动探针。Token 无效或 Telegram 不可达时不能把状态标成运行中。
	probeCtx, probeCancel := context.WithTimeout(parent, 20*time.Second)
	me, err := b.GetMe(probeCtx)
	probeCancel()
	if err != nil {
		// Telegram errors may include the request URL, whose path contains the
		// Bot Token. Keep startup failures actionable without reflecting secrets
		// into the settings API or application logs.
		return errors.New("Telegram Bot 验证失败，请检查 Token 和网络连接")
	}
	if me == nil || me.Username == "" {
		return errors.New("Telegram Bot getMe 未返回用户名")
	}
	ctx, cancel := context.WithCancel(parent)
	s.b = b
	s.cancel = cancel
	s.botUsername = me.Username

	setupCtx, setupCancel := context.WithTimeout(ctx, 10*time.Second)
	s.setMyCommands(setupCtx, b)
	s.setMenuButton(setupCtx, b)
	setupCancel()

	pollDone := make(chan struct{})
	s.pollDone = pollDone
	go func() {
		defer close(pollDone)
		log.Printf("[arcway-tgbot] long-poll started")
		b.Start(ctx)
		log.Printf("[arcway-tgbot] long-poll stopped")
	}()
	go s.runDailyNotifier(ctx, b)
	go s.runAnnouncementBroadcaster(ctx, b)
	return nil
}

// setMenuButton 把主控内置的 Mini App 地址设为聊天菜单按钮。
func (s *Service) setMenuButton(ctx context.Context, b *bot.Bot) {
	if s.cfg.WebAppURL == "" {
		return
	}
	_, _ = b.SetChatMenuButton(ctx, &bot.SetChatMenuButtonParams{
		MenuButton: &models.MenuButtonWebApp{
			Type:   models.MenuButtonTypeWebApp,
			Text:   "📊 我的面板",
			WebApp: models.WebAppInfo{URL: s.cfg.WebAppURL},
		},
	})
}

func (s *Service) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	pollDone := s.pollDone
	s.cancel = nil
	s.pollDone = nil
	s.b = nil
	s.botUsername = ""
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if pollDone != nil {
		select {
		case <-pollDone:
		case <-time.After(5 * time.Second):
			log.Printf("[arcway-tgbot] long-poll stop timed out")
		}
	}
}

func (s *Service) ServeWebApp(w http.ResponseWriter, r *http.Request) {
	s.webHandler.ServeHTTP(w, r)
}
