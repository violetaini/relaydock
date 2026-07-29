package handler

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/storage"
)

var globalSilentModeManager *SilentModeManager

type SilentModeManager struct {
	repo                 *storage.TrafficRepository
	tokens               *auth.TokenStore
	lastActiveTime       sync.Map
	lastGlobalActiveTime time.Time
	globalActiveMu       sync.Mutex
	startTime            time.Time
	shortLinkSet         map[string]struct{}
	shortLinkSetMu       sync.RWMutex
	shortLinkSetTime     time.Time
}

func NewSilentModeManager(repo *storage.TrafficRepository, tokens *auth.TokenStore) *SilentModeManager {
	m := &SilentModeManager{
		repo:      repo,
		tokens:    tokens,
		startTime: time.Now(),
	}
	globalSilentModeManager = m
	logger.Info("🔓 [SILENT_MODE] 服务启动，静默模式临时恢复中",
		"start_time", m.startTime.Format("2006-01-02 15:04:05"),
	)
	return m
}

func GetSilentModeManager() *SilentModeManager {
	return globalSilentModeManager
}

func (m *SilentModeManager) InvalidateShortLinkCache() {
	m.shortLinkSetMu.Lock()
	m.shortLinkSetTime = time.Time{}
	m.shortLinkSetMu.Unlock()
}

func (m *SilentModeManager) refreshShortLinkSet() {
	ctx := context.Background()
	fileCodes, err := m.repo.GetAllFileShortCodes(ctx)
	if err != nil {
		return
	}
	userCodes, err := m.repo.GetAllUserShortCodes(ctx)
	if err != nil {
		return
	}

	set := make(map[string]struct{}, len(fileCodes)*len(userCodes))
	for fc := range fileCodes {
		for uc := range userCodes {
			set[fc+uc] = struct{}{}
		}
	}

	m.shortLinkSetMu.Lock()
	m.shortLinkSet = set
	m.shortLinkSetTime = time.Now()
	m.shortLinkSetMu.Unlock()
}

func (m *SilentModeManager) isKnownShortLink(path string) bool {
	if len(path) < 2 || !isAlphanumericPath(path) {
		return false
	}

	m.shortLinkSetMu.RLock()
	expired := time.Since(m.shortLinkSetTime) > 60*time.Second
	m.shortLinkSetMu.RUnlock()

	if expired {
		m.refreshShortLinkSet()
	}

	m.shortLinkSetMu.RLock()
	_, ok := m.shortLinkSet[path]
	m.shortLinkSetMu.RUnlock()
	return ok
}

func (m *SilentModeManager) RecordSubscriptionAccessWithIP(username, ip string) {
	if username == "" {
		return
	}
	now := time.Now()
	m.lastActiveTime.Store(username, now)

	m.globalActiveMu.Lock()
	m.lastGlobalActiveTime = now
	m.globalActiveMu.Unlock()

	logger.Info("🔓 [SILENT_MODE] 用户获取订阅，恢复所有IP访问权限",
		"username", username,
		"ip", ip,
		"time", now.Format("2006-01-02 15:04:05"),
	)
}

func (m *SilentModeManager) isUserActive(username string, timeout int) bool {
	if username == "" {
		return false
	}

	val, ok := m.lastActiveTime.Load(username)
	if !ok {
		return false
	}

	lastActive := val.(time.Time)
	activeUntil := lastActive.Add(time.Duration(timeout) * time.Minute)
	return time.Now().Before(activeUntil)
}

func (m *SilentModeManager) isGlobalActive(timeout int) bool {
	m.globalActiveMu.Lock()
	lastActive := m.lastGlobalActiveTime
	m.globalActiveMu.Unlock()

	if lastActive.IsZero() {
		return false
	}

	activeUntil := lastActive.Add(time.Duration(timeout) * time.Minute)
	return time.Now().Before(activeUntil)
}

func (m *SilentModeManager) extractUsername(r *http.Request) string {
	if m.tokens == nil {
		return ""
	}

	if token := strings.TrimSpace(r.Header.Get(auth.AuthHeader)); token != "" {
		if username, ok := m.tokens.Lookup(token); ok {
			return username
		}
	}

	if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
		if username, ok := m.tokens.Lookup(token); ok {
			return username
		}
	}

	return ""
}

func (m *SilentModeManager) isAllowedPath(path string) bool {
	// The Agent may finish cleanup after the user's silent-mode recovery window
	// closes. The exact callback remains reachable; its handler still requires
	// the operation-scoped, high-entropy Bearer token.
	if path == AgentUninstallCompletePath {
		return true
	}
	allowedPrefixes := []string{
		"/api/clash/subscribe",
		"/api/proxy-provider/",
		"/t/",
	}

	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	trimmedPath := strings.Trim(path, "/")
	if m.isKnownShortLink(trimmedPath) {
		return true
	}

	return false
}

func isAlphanumericPath(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func (m *SilentModeManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg, err := m.repo.GetSystemConfig(context.Background())
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		if !cfg.SilentMode {
			next.ServeHTTP(w, r)
			return
		}

		recoveryUntil := m.startTime.Add(time.Duration(cfg.SilentModeTimeout) * time.Minute)
		if time.Now().Before(recoveryUntil) {
			next.ServeHTTP(w, r)
			return
		}

		if m.isAllowedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		username := m.extractUsername(r)
		clientIP := GetClientIP(r)

		if username != "" && m.isUserActive(username, cfg.SilentModeTimeout) {
			next.ServeHTTP(w, r)
			return
		}

		if m.isGlobalActive(cfg.SilentModeTimeout) {
			next.ServeHTTP(w, r)
			return
		}

		logger.Info("🔒 [SILENT_MODE] 请求被拦截",
			"path", r.URL.Path,
			"username", username,
			"client_ip", clientIP,
		)
		w.Header().Set("X-Silent-Mode", "true")
		http.NotFound(w, r)
	})
}
