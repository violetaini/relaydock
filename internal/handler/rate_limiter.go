package handler

import (
	"errors"
	"strings"
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
	pending   int
	firstTime time.Time
	lockUntil time.Time
}

type LoginRateLimiter struct {
	mu              sync.Mutex
	ipAttempts      map[string]*attemptInfo
	accountAttempts map[string]*attemptInfo
	maxAttempts     int
	windowDuration  time.Duration
	lockDuration    time.Duration
	// skipLocalIP 命中本地/私有 IP 时,跳过 IP 维度限流;账户维度仍生效。
	// 防反代未传 XFF 时所有真实用户共享同一个内网 IP 一起被锁。
	skipLocalIP bool
}

const maxTrackedLoginAttempts = 10_000

// NewLoginRateLimiter 默认值构造:5 次失败 / 1 小时窗口 / 1 小时锁定。
// 登录限流没有 enabled 开关(登录路径必须有基本防护)。
func NewLoginRateLimiter() *LoginRateLimiter {
	l := &LoginRateLimiter{
		ipAttempts:      make(map[string]*attemptInfo),
		accountAttempts: make(map[string]*attemptInfo),
		maxAttempts:     5,
		windowDuration:  time.Hour,
		lockDuration:    time.Hour,
		skipLocalIP:     true,
	}
	globalLoginRateLimiter = l
	return l
}

// NewLoginRateLimiterWithConfig 用 system_settings 自定义阈值构造。
func NewLoginRateLimiterWithConfig(maxAttempts, windowMinutes, lockMinutes int) *LoginRateLimiter {
	l := &LoginRateLimiter{
		ipAttempts:      make(map[string]*attemptInfo),
		accountAttempts: make(map[string]*attemptInfo),
		maxAttempts:     maxAttempts,
		windowDuration:  time.Duration(windowMinutes) * time.Minute,
		lockDuration:    time.Duration(lockMinutes) * time.Minute,
		skipLocalIP:     true,
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
	l.mu.Lock()
	skip := l.skipLocalIP
	l.mu.Unlock()
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
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxAttempts, l.windowDuration, l.lockDuration
}

func (l *LoginRateLimiter) Check(ip, username string) error {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if !(l.skipLocalIP && IsLocalOrPrivateIP(ip)) {
		if err := l.checkAttemptsLocked(l.ipAttempts, ip, now); err != nil {
			logger.Warn("🚫🚫🚫 [RATE_LIMIT] 登录被限制（IP）",
				"ip", ip,
				"username", username,
			)
			return err
		}
	}

	if username != "" {
		if err := l.checkAttemptsLocked(l.accountAttempts, username, now); err != nil {
			logger.Warn("🚫🚫🚫 [RATE_LIMIT] 登录被限制（账户）",
				"ip", ip,
				"username", username,
			)
			return err
		}
	}

	return nil
}

// Reserve atomically checks capacity and reserves one login attempt before
// expensive credential verification. Call RecordFailure, RecordSuccess, or
// Release after the request finishes.
func (l *LoginRateLimiter) Reserve(ip, username string) error {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !(l.skipLocalIP && IsLocalOrPrivateIP(ip)) {
		if err := l.reserveAttemptLocked(l.ipAttempts, ip, now); err != nil {
			return err
		}
	}
	if username != "" {
		if err := l.reserveAttemptLocked(l.accountAttempts, username, now); err != nil {
			if !(l.skipLocalIP && IsLocalOrPrivateIP(ip)) {
				l.releaseAttemptLocked(l.ipAttempts, ip)
			}
			return err
		}
	}
	return nil
}

// AttachAccount adds account-level protection to an existing IP reservation.
// It is used after a pending 2FA token reveals the account name.
func (l *LoginRateLimiter) AttachAccount(username string) error {
	if username == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reserveAttemptLocked(l.accountAttempts, username, time.Now())
}

// Release frees a successful pre-2FA reservation without resetting prior
// failures. Password authentication has completed, but the second factor has
// not yet succeeded.
func (l *LoginRateLimiter) Release(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !(l.skipLocalIP && IsLocalOrPrivateIP(ip)) {
		l.releaseAttemptLocked(l.ipAttempts, ip)
	}
	if username != "" {
		l.releaseAttemptLocked(l.accountAttempts, username)
	}
}

func (l *LoginRateLimiter) checkAttemptsLocked(store map[string]*attemptInfo, key string, now time.Time) error {
	info, ok := store[key]
	if !ok {
		return nil
	}

	if !info.lockUntil.IsZero() && now.Before(info.lockUntil) {
		return ErrRateLimited
	}

	if !info.lockUntil.IsZero() && now.After(info.lockUntil) {
		delete(store, key)
		return nil
	}

	if now.Sub(info.firstTime) > l.windowDuration {
		delete(store, key)
		return nil
	}

	if info.count+info.pending >= l.maxAttempts {
		info.lockUntil = now.Add(l.lockDuration)
		return ErrRateLimited
	}

	return nil
}

func (l *LoginRateLimiter) reserveAttemptLocked(store map[string]*attemptInfo, key string, now time.Time) error {
	if err := l.checkAttemptsLocked(store, key, now); err != nil {
		return err
	}
	info, ok := store[key]
	if !ok {
		if !l.ensureAttemptCapacityLocked(store, now) {
			return ErrRateLimited
		}
		info = &attemptInfo{firstTime: now}
		store[key] = info
	}
	info.pending++
	return nil
}

func (l *LoginRateLimiter) releaseAttemptLocked(store map[string]*attemptInfo, key string) {
	info, ok := store[key]
	if !ok {
		return
	}
	if info.pending > 0 {
		info.pending--
	}
	if info.count == 0 && info.pending == 0 && info.lockUntil.IsZero() {
		delete(store, key)
	}
}

func (l *LoginRateLimiter) RecordFailure(ip, username string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if !(l.skipLocalIP && IsLocalOrPrivateIP(ip)) {
		l.recordAttemptLocked(l.ipAttempts, ip, now)
	}
	if username != "" {
		l.recordAttemptLocked(l.accountAttempts, username, now)
	}
}

func (l *LoginRateLimiter) recordAttemptLocked(store map[string]*attemptInfo, key string, now time.Time) {
	info, loaded := store[key]
	if !loaded {
		if !l.ensureAttemptCapacityLocked(store, now) {
			return
		}
		store[key] = &attemptInfo{
			count:     1,
			firstTime: now,
		}
		return
	}

	if now.Sub(info.firstTime) > l.windowDuration {
		store[key] = &attemptInfo{
			count:     1,
			firstTime: now,
		}
		return
	}

	if info.pending > 0 {
		info.pending--
	}
	info.count++
}

func (l *LoginRateLimiter) RecordSuccess(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ipAttempts, ip)
	if username != "" {
		delete(l.accountAttempts, username)
	}
}

// RenameUsername moves account-scoped attempt state with an account rename.
// Merging is conservative so renaming cannot be used to shed an existing lock.
func (l *LoginRateLimiter) RenameUsername(oldUsername, newUsername string) {
	oldUsername = strings.TrimSpace(oldUsername)
	newUsername = strings.TrimSpace(newUsername)
	if oldUsername == "" || newUsername == "" || oldUsername == newUsername {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	oldInfo := l.accountAttempts[oldUsername]
	if oldInfo == nil {
		return
	}
	delete(l.accountAttempts, oldUsername)
	newInfo := l.accountAttempts[newUsername]
	if newInfo == nil {
		l.accountAttempts[newUsername] = oldInfo
		return
	}
	newInfo.count += oldInfo.count
	newInfo.pending += oldInfo.pending
	if newInfo.firstTime.IsZero() || !oldInfo.firstTime.IsZero() && oldInfo.firstTime.Before(newInfo.firstTime) {
		newInfo.firstTime = oldInfo.firstTime
	}
	if oldInfo.lockUntil.After(newInfo.lockUntil) {
		newInfo.lockUntil = oldInfo.lockUntil
	}
}

// ensureAttemptCapacityLocked only reclaims entries whose protection window is
// over. Evicting an active entry would let an attacker shed another client's
// failures or lock by flooding the limiter with new identifiers.
func (l *LoginRateLimiter) ensureAttemptCapacityLocked(store map[string]*attemptInfo, now time.Time) bool {
	if len(store) < maxTrackedLoginAttempts {
		return true
	}
	for key, info := range store {
		if info == nil || info.pending == 0 && ((!info.lockUntil.IsZero() && !now.Before(info.lockUntil)) || (info.lockUntil.IsZero() && now.Sub(info.firstTime) > l.windowDuration)) {
			delete(store, key)
		}
	}
	return len(store) < maxTrackedLoginAttempts
}
