package handler

import (
	"errors"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/logger"
)

var ErrRateLimited = errors.New("rate limit exceeded")

var globalLoginRateLimiter *LoginRateLimiter

func GetLoginRateLimiter() *LoginRateLimiter {
	return globalLoginRateLimiter
}

type attemptInfo struct {
	count     int
	firstTime time.Time
	lockUntil time.Time
}

type LoginRateLimiter struct {
	mu              sync.RWMutex
	ipAttempts      sync.Map // IP -> *attemptInfo
	accountAttempts sync.Map // username -> *attemptInfo
	maxAttempts     int
	windowDuration  time.Duration
	lockDuration    time.Duration
	// skipLocalIP 命中本地/私有 IP 时,跳过 IP 维度限流;账户维度仍生效。
	// 防反代未传 XFF 时所有真实用户共享同一个内网 IP 一起被锁。
	skipLocalIP bool
}

// NewLoginRateLimiter 默认值构造:5 次失败 / 1 小时窗口 / 1 小时锁定。
// 登录限流没有 enabled 开关(登录路径必须有基本防护)。
func NewLoginRateLimiter() *LoginRateLimiter {
	l := &LoginRateLimiter{
		maxAttempts:    5,
		windowDuration: time.Hour,
		lockDuration:   time.Hour,
		skipLocalIP:    true,
	}
	globalLoginRateLimiter = l
	return l
}

// NewLoginRateLimiterWithConfig 用 system_settings 自定义阈值构造。
func NewLoginRateLimiterWithConfig(maxAttempts, windowMinutes, lockMinutes int) *LoginRateLimiter {
	l := &LoginRateLimiter{
		maxAttempts:    maxAttempts,
		windowDuration: time.Duration(windowMinutes) * time.Minute,
		lockDuration:   time.Duration(lockMinutes) * time.Minute,
		skipLocalIP:    true,
	}
	globalLoginRateLimiter = l
	return l
}

// SetSkipLocalIP 切换"是否跳过本地/私有 IP 的 IP 维度限流"。账户维度始终生效。
func (l *LoginRateLimiter) SetSkipLocalIP(skip bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.skipLocalIP = skip
}

func (l *LoginRateLimiter) shouldSkipIP(ip string) bool {
	l.mu.RLock()
	skip := l.skipLocalIP
	l.mu.RUnlock()
	return skip && IsLocalOrPrivateIP(ip)
}

// UpdateConfig 热更新参数 — security_settings handler PUT 后调用。
func (l *LoginRateLimiter) UpdateConfig(maxAttempts, windowMinutes, lockMinutes int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxAttempts = maxAttempts
	l.windowDuration = time.Duration(windowMinutes) * time.Minute
	l.lockDuration = time.Duration(lockMinutes) * time.Minute
}

func (l *LoginRateLimiter) getConfig() (int, time.Duration, time.Duration) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.maxAttempts, l.windowDuration, l.lockDuration
}

func (l *LoginRateLimiter) Check(ip, username string) error {
	now := time.Now()

	if !l.shouldSkipIP(ip) {
		if err := l.checkAttempts(&l.ipAttempts, ip, now); err != nil {
			logger.Warn("🚫🚫🚫 [RATE_LIMIT] 登录被限制（IP）",
				"ip", ip,
				"username", username,
			)
			return err
		}
	}

	if username != "" {
		if err := l.checkAttempts(&l.accountAttempts, username, now); err != nil {
			logger.Warn("🚫🚫🚫 [RATE_LIMIT] 登录被限制（账户）",
				"ip", ip,
				"username", username,
			)
			return err
		}
	}

	return nil
}

func (l *LoginRateLimiter) checkAttempts(store *sync.Map, key string, now time.Time) error {
	maxAttempts, windowDuration, lockDuration := l.getConfig()

	val, _ := store.Load(key)
	if val == nil {
		return nil
	}

	info := val.(*attemptInfo)

	if !info.lockUntil.IsZero() && now.Before(info.lockUntil) {
		return ErrRateLimited
	}

	if !info.lockUntil.IsZero() && now.After(info.lockUntil) {
		store.Delete(key)
		return nil
	}

	if now.Sub(info.firstTime) > windowDuration {
		store.Delete(key)
		return nil
	}

	if info.count >= maxAttempts {
		info.lockUntil = now.Add(lockDuration)
		return ErrRateLimited
	}

	return nil
}

func (l *LoginRateLimiter) RecordFailure(ip, username string) {
	now := time.Now()

	if !l.shouldSkipIP(ip) {
		l.recordAttempt(&l.ipAttempts, ip, now)
	}
	if username != "" {
		l.recordAttempt(&l.accountAttempts, username, now)
	}
}

func (l *LoginRateLimiter) recordAttempt(store *sync.Map, key string, now time.Time) {
	_, windowDuration, _ := l.getConfig()

	val, loaded := store.Load(key)
	if !loaded {
		store.Store(key, &attemptInfo{
			count:     1,
			firstTime: now,
		})
		return
	}

	info := val.(*attemptInfo)

	if now.Sub(info.firstTime) > windowDuration {
		store.Store(key, &attemptInfo{
			count:     1,
			firstTime: now,
		})
		return
	}

	info.count++
}

func (l *LoginRateLimiter) RecordSuccess(ip, username string) {
	l.ipAttempts.Delete(ip)
	if username != "" {
		l.accountAttempts.Delete(username)
	}
}
