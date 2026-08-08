package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func TestGetClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "203.0.113.8:4242"
	request.Header.Set("CF-Connecting-IP", "127.0.0.1")
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	request.Header.Set("X-Real-IP", "127.0.0.1")
	if got := GetClientIP(request); got != "203.0.113.8" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestTwoFactorLoginUsesGlobalAccountAttemptLimit(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "two-factor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "alice", "", "", string(passwordHash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetUserTOTPSecret(ctx, "alice", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}

	pending := auth.NewTwoFactorPendingStore(time.Minute)
	twoFactorToken, err := pending.Issue("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	limiter := NewLoginRateLimiterWithConfig(2, 60, 60)
	limiter.SetSkipLocalIP(false)
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	tokens := auth.NewTokenStore(time.Hour)
	twoFactorHandler := NewTwoFactorLoginHandler(manager, tokens, repo, pending, limiter)

	attempt := func(ip string) int {
		body := bytes.NewBufferString(`{"two_factor_token":"` + twoFactorToken + `","code":"not-a-code"}`)
		request := httptest.NewRequest(http.MethodPost, "/api/2fa/login", body)
		request.RemoteAddr = ip + ":4321"
		response := httptest.NewRecorder()
		twoFactorHandler.ServeHTTP(response, request)
		return response.Code
	}
	if got := attempt("198.51.100.24"); got != http.StatusUnauthorized {
		t.Fatalf("first invalid attempt status = %d", got)
	}
	if got := attempt("198.51.100.25"); got != http.StatusUnauthorized {
		t.Fatalf("second invalid attempt status = %d", got)
	}

	loginHandler := NewLoginHandler(manager, tokens, repo, limiter, pending, nil)
	request := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBufferString(
		`{"username":"alice","password":"correct-password"}`,
	))
	request.RemoteAddr = "198.51.100.26:4321"
	response := httptest.NewRecorder()
	loginHandler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("cross-IP password login after 2FA failures status = %d", response.Code)
	}
}

func TestGetClientIPAcceptsRealIPFromLoopbackProxy(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "127.0.0.1:4242"
	request.Header.Set("X-Real-IP", "198.51.100.9")
	if got := GetClientIP(request); got != "198.51.100.9" {
		t.Fatalf("client IP = %q", got)
	}
}

func TestLoginRateLimiterConcurrentFailures(t *testing.T) {
	limiter := NewLoginRateLimiterWithConfig(10_000, 60, 60)
	limiter.SetSkipLocalIP(false)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter.RecordFailure("198.51.100.10", "alice")
			_ = limiter.Check("198.51.100.10", "alice")
		}()
	}
	wg.Wait()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if got := limiter.accountAttempts["alice"].count; got != 100 {
		t.Fatalf("account failure count = %d", got)
	}
	if got := limiter.ipAttempts["198.51.100.10"].count; got != 100 {
		t.Fatalf("IP failure count = %d", got)
	}
}

func TestLoginRateLimiterMovesAccountStateOnRename(t *testing.T) {
	limiter := NewLoginRateLimiterWithConfig(5, 60, 60)
	limiter.SetSkipLocalIP(false)
	limiter.RecordFailure("198.51.100.10", "alice")
	limiter.RenameUsername("alice", "renamed")
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if _, ok := limiter.accountAttempts["alice"]; ok {
		t.Fatal("old username limiter state remained after rename")
	}
	if got := limiter.accountAttempts["renamed"]; got == nil || got.count != 1 {
		t.Fatalf("renamed limiter state=%#v", got)
	}
}

func TestLoginRateLimiterReservesConcurrentRequests(t *testing.T) {
	limiter := NewLoginRateLimiterWithConfig(5, 60, 60)
	limiter.SetSkipLocalIP(false)

	allowed := make(chan struct{}, 40)
	var wg sync.WaitGroup
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Reserve("198.51.100.11", "alice") == nil {
				// Keep the reservation in flight until every contender has checked.
				// This models concurrent bcrypt work in the login handler.
				allowed <- struct{}{}
			}
		}()
	}
	wg.Wait()
	if got := len(allowed); got != 5 {
		t.Fatalf("concurrent reservations allowed %d attempts, want 5", got)
	}
}

func TestLoginRateLimiterDoesNotEvictActiveStateAtCapacity(t *testing.T) {
	limiter := NewLoginRateLimiterWithConfig(20_000, 60, 60)
	limiter.SetSkipLocalIP(false)
	now := time.Now()
	for i := 0; i < maxTrackedLoginAttempts; i++ {
		key := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		limiter.ipAttempts[key] = &attemptInfo{count: 1, firstTime: now}
	}
	protected := "198.51.0.0"
	limiter.ipAttempts[protected].lockUntil = now.Add(time.Hour)
	pending := "198.51.0.1"
	limiter.ipAttempts[pending].firstTime = now.Add(-3 * time.Hour)
	limiter.ipAttempts[pending].pending = 1

	newKey := "203.0.113.250"
	if err := limiter.Reserve(newKey, ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Reserve() error = %v, want ErrRateLimited", err)
	}
	if _, ok := limiter.ipAttempts[protected]; !ok {
		t.Fatal("active locked entry was evicted")
	}
	if _, ok := limiter.ipAttempts[pending]; !ok {
		t.Fatal("in-flight pending entry was evicted")
	}
	if _, ok := limiter.ipAttempts[newKey]; ok {
		t.Fatal("new entry was inserted beyond capacity")
	}
	if got := len(limiter.ipAttempts); got != maxTrackedLoginAttempts {
		t.Fatalf("tracked IP count = %d, want %d", got, maxTrackedLoginAttempts)
	}

	limiter.RecordFailure(newKey, "")
	if _, ok := limiter.ipAttempts[newKey]; ok {
		t.Fatal("RecordFailure inserted a new entry by evicting active state")
	}
}

func TestLoginRateLimiterReclaimsExpiredStateAtCapacity(t *testing.T) {
	limiter := NewLoginRateLimiterWithConfig(20_000, 60, 60)
	limiter.SetSkipLocalIP(false)
	now := time.Now()
	for i := 0; i < maxTrackedLoginAttempts; i++ {
		key := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		limiter.ipAttempts[key] = &attemptInfo{count: 1, firstTime: now}
	}
	expired := "198.51.0.0"
	limiter.ipAttempts[expired].firstTime = now.Add(-3 * time.Hour)

	newKey := "203.0.113.251"
	if err := limiter.Reserve(newKey, ""); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if _, ok := limiter.ipAttempts[expired]; ok {
		t.Fatal("expired entry was not reclaimed")
	}
	if got := limiter.ipAttempts[newKey]; got == nil || got.pending != 1 {
		t.Fatalf("new reservation = %#v", got)
	}
}

func TestBruteForceProtectorDoesNotEvictActiveBanAtCapacity(t *testing.T) {
	protector := NewBruteForceProtectorWithConfig(true, 20_000, 60, 60)
	protector.SetSkipLocalIP(false)
	now := time.Now()
	for i := 0; i < maxTrackedBruteForceIPs; i++ {
		key := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		protector.attempts[key] = &bruteForceRecord{count: 1, firstTime: now}
	}
	protected := "198.51.0.0"
	protector.attempts[protected].firstTime = now.Add(-3 * time.Hour)
	protector.attempts[protected].blockUntil = now.Add(time.Hour)

	newKey := "203.0.113.252"
	if !protector.IsBlocked(newKey, "/subscription") {
		t.Fatal("untracked IP was allowed after protected tracking capacity was exhausted")
	}
	if _, ok := protector.attempts[protected]; !ok {
		t.Fatal("active ban was evicted")
	}
	protector.RecordFailure(newKey, "/subscription")
	if _, ok := protector.attempts[newKey]; ok {
		t.Fatal("new failure was inserted by evicting active state")
	}
	if got := len(protector.attempts); got != maxTrackedBruteForceIPs {
		t.Fatalf("tracked IP count = %d, want %d", got, maxTrackedBruteForceIPs)
	}
}

func TestBruteForceProtectorReclaimsExpiredStateAtCapacity(t *testing.T) {
	protector := NewBruteForceProtectorWithConfig(true, 20_000, 60, 60)
	protector.SetSkipLocalIP(false)
	now := time.Now()
	for i := 0; i < maxTrackedBruteForceIPs; i++ {
		key := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		protector.attempts[key] = &bruteForceRecord{count: 1, firstTime: now}
	}
	expired := "198.51.0.0"
	protector.attempts[expired].firstTime = now.Add(-2 * time.Hour)

	newKey := "203.0.113.253"
	if protector.IsBlocked(newKey, "/subscription") {
		t.Fatal("untracked IP was rejected after expired capacity was reclaimed")
	}
	protector.RecordFailure(newKey, "/subscription")
	if _, ok := protector.attempts[expired]; ok {
		t.Fatal("expired entry was not reclaimed")
	}
	if got := protector.attempts[newKey]; got == nil || got.count != 1 {
		t.Fatalf("new failure record = %#v", got)
	}
}
