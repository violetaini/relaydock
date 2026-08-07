package tgbot

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/tgbot/bot"
	"github.com/violetaini/relaydock/internal/tgbot/config"
	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

const (
	settingEnabled    = "tgbot_enabled"
	settingToken      = "tgbot_token"
	settingAdminIDs   = "tgbot_admin_ids"
	settingDevPreview = "tgbot_webapp_dev_preview"
	settingBotURL     = "tgbot_url"
)

type Settings struct {
	Enabled       bool    `json:"enabled"`
	BotToken      string  `json:"bot_token"`
	AdminTGIDs    []int64 `json:"admin_tg_ids"`
	WebDevPreview bool    `json:"webapp_dev_preview"`
	Running       bool    `json:"running"`
	BotURL        string  `json:"bot_url"`
}

type Manager struct {
	mu          sync.Mutex
	lifecycleMu sync.Mutex
	repo        *storage.TrafficRepository
	tokens      *auth.TokenStore
	handler     http.Handler
	service     *bot.Service
	cancel      context.CancelFunc
	running     bool
}

func NewManager(repo *storage.TrafficRepository, tokens *auth.TokenStore, handler http.Handler) *Manager {
	return &Manager{repo: repo, tokens: tokens, handler: handler}
}

// EnsurePublicBaseURL records the address observed by the settings request only
// when the administrator has not explicitly configured a master URL yet.
func (m *Manager) EnsurePublicBaseURL(ctx context.Context, observed string) error {
	current, _ := m.repo.GetSystemSetting(ctx, "master_url")
	if strings.TrimSpace(current) != "" || strings.TrimSpace(observed) == "" {
		return nil
	}
	return m.repo.SetSystemSetting(ctx, "master_url", strings.TrimRight(strings.TrimSpace(observed), "/"))
}

func (m *Manager) Load(ctx context.Context, revealToken bool) Settings {
	s := Settings{AdminTGIDs: []int64{}}
	s.Enabled = readBool(ctx, m.repo, settingEnabled)
	s.BotToken, _ = m.repo.GetSystemSetting(ctx, settingToken)
	if !revealToken && s.BotToken != "" {
		s.BotToken = mask(s.BotToken)
	}
	if raw, _ := m.repo.GetSystemSetting(ctx, settingAdminIDs); raw != "" {
		_ = json.Unmarshal([]byte(raw), &s.AdminTGIDs)
	}
	s.AdminTGIDs = normalizeAdminTGIDs(s.AdminTGIDs)
	s.WebDevPreview = readBool(ctx, m.repo, settingDevPreview)
	s.BotURL, _ = m.repo.GetSystemSetting(ctx, settingBotURL)
	m.mu.Lock()
	s.Running = m.running
	m.mu.Unlock()
	return s
}

func (m *Manager) SaveAndRestart(ctx context.Context, next Settings) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	current := m.Load(ctx, true)
	if next.BotToken == mask(current.BotToken) {
		next.BotToken = current.BotToken
	}
	next.BotToken = strings.TrimSpace(next.BotToken)
	if next.Enabled && next.BotToken == "" {
		return errors.New("启用 TGBot 前请填写 Bot Token")
	}
	next.AdminTGIDs = normalizeAdminTGIDs(next.AdminTGIDs)
	previousIDs, _ := json.Marshal(normalizeAdminTGIDs(current.AdminTGIDs))
	previous := map[string]string{
		settingEnabled:    strconv.FormatBool(current.Enabled),
		settingToken:      current.BotToken,
		settingAdminIDs:   string(previousIDs),
		settingDevPreview: strconv.FormatBool(current.WebDevPreview),
	}
	ids, _ := json.Marshal(next.AdminTGIDs)
	pairs := map[string]string{
		settingEnabled: strconv.FormatBool(next.Enabled), settingToken: next.BotToken,
		settingAdminIDs: string(ids), settingDevPreview: strconv.FormatBool(next.WebDevPreview),
	}
	for key, value := range pairs {
		if err := m.repo.SetSystemSetting(ctx, key, value); err != nil {
			m.restoreSettings(previous)
			return err
		}
	}
	if err := m.restartLocked(context.Background()); err != nil {
		m.restoreSettings(previous)
		return err
	}
	return nil
}

func (m *Manager) Restart(parent context.Context) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.restartLocked(parent)
}

func (m *Manager) restartLocked(parent context.Context) error {
	s := m.loadUnlocked(parent)
	if !s.Enabled {
		m.mu.Lock()
		oldCancel := m.cancel
		m.cancel, m.service, m.running = nil, nil, false
		m.mu.Unlock()
		if oldCancel != nil {
			oldCancel()
		}
		_ = m.repo.SetSystemSetting(parent, settingBotURL, "")
		return nil
	}
	service, stop, botURL, err := m.startService(parent, s)
	if err != nil {
		m.mu.Lock()
		hasRunningService := m.running && m.service != nil
		m.mu.Unlock()
		if !hasRunningService {
			_ = m.repo.SetSystemSetting(parent, settingBotURL, "")
		}
		return err
	}
	if botURL != "" {
		if err := m.repo.SetSystemSetting(parent, settingBotURL, botURL); err != nil {
			stop()
			return err
		}
	} else {
		_ = m.repo.SetSystemSetting(parent, settingBotURL, "")
	}
	m.mu.Lock()
	oldCancel := m.cancel
	m.cancel, m.service, m.running = stop, service, true
	m.mu.Unlock()
	if oldCancel != nil {
		oldCancel()
	}
	return nil
}

func (m *Manager) startService(parent context.Context, s Settings) (*bot.Service, context.CancelFunc, string, error) {
	adminUsername, err := m.repo.FindActiveAdminUsername(parent)
	if err != nil {
		return nil, nil, "", err
	}
	if adminUsername == "" {
		return nil, nil, "", errors.New("未找到已启用的管理员账号")
	}
	token, _, err := m.tokens.IssueWithTTL(adminUsername, 365*24*time.Hour)
	if err != nil {
		return nil, nil, "", err
	}
	masterURL, _ := m.repo.GetSystemSetting(parent, "master_url")
	masterURL = strings.TrimRight(strings.TrimSpace(masterURL), "/")
	if masterURL == "" {
		m.tokens.Revoke(token)
		return nil, nil, "", errors.New("请先配置主控公网地址，再启用 TGBot")
	}
	cfg := config.Config{
		Enabled: true, PublicBaseURL: masterURL, TGBotToken: s.BotToken,
		AdminTGIDs: s.AdminTGIDs, HTTPTimeoutSeconds: 30,
		WebAppURL: masterURL + "/tg-app", WebAppDevPreview: s.WebDevPreview,
	}
	client := mmwxclient.NewInProcess(m.handler, token, 30)
	service := bot.New(cfg, client)
	ctx, cancel := context.WithCancel(parent)
	if err := service.Start(ctx); err != nil {
		cancel()
		m.tokens.Revoke(token)
		return nil, nil, "", err
	}
	botURL := service.BotURL()
	stop := func() { cancel(); service.Stop(); m.tokens.Revoke(token) }
	return service, stop, botURL, nil
}

func (m *Manager) Stop() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	oldCancel := m.cancel
	m.cancel, m.service, m.running = nil, nil, false
	m.mu.Unlock()
	if oldCancel != nil {
		oldCancel()
	}
}

func (m *Manager) loadUnlocked(ctx context.Context) Settings {
	s := Settings{AdminTGIDs: []int64{}}
	s.Enabled = readBool(ctx, m.repo, settingEnabled)
	s.BotToken, _ = m.repo.GetSystemSetting(ctx, settingToken)
	if raw, _ := m.repo.GetSystemSetting(ctx, settingAdminIDs); raw != "" {
		_ = json.Unmarshal([]byte(raw), &s.AdminTGIDs)
	}
	s.AdminTGIDs = normalizeAdminTGIDs(s.AdminTGIDs)
	s.WebDevPreview = readBool(ctx, m.repo, settingDevPreview)
	return s
}

func (m *Manager) ServeWebApp(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	service := m.service
	m.mu.Unlock()
	if service == nil {
		http.Error(w, "TGBot is not enabled", http.StatusServiceUnavailable)
		return
	}
	service.ServeWebApp(w, r)
}

func readBool(ctx context.Context, repo *storage.TrafficRepository, key string) bool {
	v, _ := repo.GetSystemSetting(ctx, key)
	b, _ := strconv.ParseBool(v)
	return b
}

func normalizeAdminTGIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	result := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

func (m *Manager) restoreSettings(values map[string]string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for key, value := range values {
		_ = m.repo.SetSystemSetting(ctx, key, value)
	}
}

func mask(value string) string {
	if len(value) < 10 {
		return "****"
	}
	return value[:4] + "****" + value[len(value)-4:]
}
