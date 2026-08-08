package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func GenerateTOTPKey(username, issuer string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
}

func ValidateTOTPCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

func GenerateRecoveryCodes(count int) (plain, hashed []string, err error) {
	plain = make([]string, count)
	hashed = make([]string, count)
	for i := range count {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		code := strings.ToLower(hex.EncodeToString(buf))[:8]
		plain[i] = code
		h := sha256.Sum256([]byte(code))
		hashed[i] = hex.EncodeToString(h[:])
	}
	return plain, hashed, nil
}

func ValidateRecoveryCode(code string, hashedCodes []string) (bool, []string) {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(code))))
	target := hex.EncodeToString(h[:])
	for i, hc := range hashedCodes {
		if hc == target {
			remaining := make([]string, 0, len(hashedCodes)-1)
			remaining = append(remaining, hashedCodes[:i]...)
			remaining = append(remaining, hashedCodes[i+1:]...)
			return true, remaining
		}
	}
	return false, hashedCodes
}

type twoFactorPending struct {
	username   string
	rememberMe bool
	expiry     time.Time
	failures   int
	inUse      bool
}

type TwoFactorPendingStore struct {
	mu      sync.RWMutex
	pending map[string]twoFactorPending
	ttl     time.Duration
}

const maxTwoFactorAttempts = 5

func NewTwoFactorPendingStore(ttl time.Duration) *TwoFactorPendingStore {
	return &TwoFactorPendingStore{
		pending: make(map[string]twoFactorPending),
		ttl:     ttl,
	}
}

func (s *TwoFactorPendingStore) Issue(username string, rememberMe bool) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	now := time.Now()
	for existing, pending := range s.pending {
		if pending.username == username || now.After(pending.expiry) {
			delete(s.pending, existing)
		}
	}
	s.pending[token] = twoFactorPending{
		username:   username,
		rememberMe: rememberMe,
		expiry:     time.Now().Add(s.ttl),
	}
	s.mu.Unlock()
	return token, nil
}

func (s *TwoFactorPendingStore) Validate(token string) (username string, rememberMe bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.pending[token]
	if !exists {
		return "", false, false
	}
	if time.Now().After(p.expiry) || p.failures >= maxTwoFactorAttempts {
		delete(s.pending, token)
		return "", false, false
	}
	return p.username, p.rememberMe, true
}

// Acquire reserves a pending challenge for one verification attempt. The
// caller must later call Finish. This prevents concurrent requests from using
// the same pending token to create more than one login session.
func (s *TwoFactorPendingStore) Acquire(token string) (username string, rememberMe bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.pending[token]
	if !exists {
		return "", false, false
	}
	if time.Now().After(p.expiry) || p.failures >= maxTwoFactorAttempts {
		delete(s.pending, token)
		return "", false, false
	}
	if p.inUse {
		return "", false, false
	}
	p.inUse = true
	s.pending[token] = p
	return p.username, p.rememberMe, true
}

// IsAcquired reports whether a caller still owns a live pending token. It is
// used while holding the credential manager lock so a password change can
// revoke a challenge before it is allowed to issue a session.
func (s *TwoFactorPendingStore) IsAcquired(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pending[token]
	return ok && p.inUse && !time.Now().After(p.expiry)
}

// Finish releases an acquired challenge after a failed verification or
// consumes it after a successful session issuance.
func (s *TwoFactorPendingStore) Finish(token string, success bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[token]
	if !ok || !p.inUse || time.Now().After(p.expiry) {
		delete(s.pending, token)
		return false
	}
	if success {
		delete(s.pending, token)
		return true
	}
	p.inUse = false
	p.failures++
	if p.failures >= maxTwoFactorAttempts {
		delete(s.pending, token)
		return false
	}
	s.pending[token] = p
	return true
}

// RevokeUser removes pending factors after a password or credential update.
func (s *TwoFactorPendingStore) RevokeUser(username string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, pending := range s.pending {
		if pending.username == username {
			delete(s.pending, token)
		}
	}
}

// RecordFailure increments the atomic attempt counter and consumes the token
// once the maximum is reached. It returns true while another attempt remains.
func (s *TwoFactorPendingStore) RecordFailure(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[token]
	if !ok || time.Now().After(p.expiry) {
		delete(s.pending, token)
		return false
	}
	p.failures++
	if p.failures >= maxTwoFactorAttempts {
		delete(s.pending, token)
		return false
	}
	s.pending[token] = p
	return true
}

func (s *TwoFactorPendingStore) Consume(token string) {
	s.mu.Lock()
	delete(s.pending, token)
	s.mu.Unlock()
}
