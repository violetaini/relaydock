package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginEmailStatusAndCanonicalOwnership(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "login-status.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	hash, err := bcrypt.GenerateFromPassword([]byte("fixture-correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range [][2]string{{"alice", "alice@example.test"}, {"bob", "bob@example.test"}, {"duplicate-a", "duplicate@example.test"}, {"duplicate-b", "duplicate@example.test"}, {"alice@example.test", "other@example.test"}} {
		if err := repo.CreateUser(ctx, row[0], row[1], "", string(hash), storage.RoleUser, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.UpdateUserStatus(ctx, "bob", false); err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	login := NewLoginHandler(manager, auth.NewTokenStore(time.Hour), repo, nil, nil, nil)
	for _, tc := range []struct {
		identifier, password string
		status               int
		owner                string
	}{
		{"alice", "fixture-correct-password", 200, "alice"},
		{"ALICE@EXAMPLE.TEST", "fixture-correct-password", 200, "alice"},
		{"alice@example.test", "fixture-correct-password", 200, "alice@example.test"},
		{"bob", "fixture-correct-password", 403, ""},
		{"BOB@EXAMPLE.TEST", "fixture-correct-password", 403, ""},
		{"bob@example.test", "wrong-password", 401, ""},
		{"alice", "wrong-password", 401, ""},
		{"missing@example.test", "fixture-correct-password", 401, ""},
		{"duplicate@example.test", "fixture-correct-password", 401, ""},
	} {
		t.Run(tc.identifier+"/"+tc.password, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"username": tc.identifier, "password": tc.password})
			res := httptest.NewRecorder()
			login.ServeHTTP(res, httptest.NewRequest("POST", "/api/login", bytes.NewReader(body)))
			if res.Code != tc.status {
				t.Fatalf("status %d: %s", res.Code, res.Body.String())
			}
			if tc.status == 403 && !strings.Contains(res.Body.String(), "account is disabled") {
				t.Fatal(res.Body.String())
			}
			if tc.owner != "" {
				var result struct {
					Username string `json:"username"`
				}
				if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Username != tc.owner {
					t.Fatalf("owner %q, want %q", result.Username, tc.owner)
				}
			} else if strings.Contains(res.Body.String(), `"token"`) {
				t.Fatal("rejected login issued a token")
			}
		})
	}
}

func TestEmailAliasesShareLoginFailureLimit(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "alias-limits.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	hash, _ := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	if err := repo.CreateUser(context.Background(), "alice", "alice@example.test", "", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	limiter := NewLoginRateLimiterWithConfig(2, 60, 60)
	limiter.SetSkipLocalIP(false)
	login := NewLoginHandler(manager, auth.NewTokenStore(time.Hour), repo, limiter, nil, nil)
	for i, identifier := range []string{"alice", "ALICE@EXAMPLE.TEST", "alice@example.test"} {
		body, _ := json.Marshal(map[string]string{"username": identifier, "password": "incorrect"})
		req := httptest.NewRequest("POST", "/api/login", bytes.NewReader(body))
		req.RemoteAddr = []string{"198.51.100.1:1234", "198.51.100.2:1234", "198.51.100.3:1234"}[i]
		res := httptest.NewRecorder()
		login.ServeHTTP(res, req)
		want := 401
		if i == 2 {
			want = 429
		}
		if res.Code != want {
			t.Fatalf("attempt %d: %d, want %d", i, res.Code, want)
		}
	}
}

func TestDisabledAccountPendingFactorsReturnDisabled(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "disabled-factor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	if err := repo.CreateUser(ctx, "bob", "", "", string(hash), storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetUserTOTPSecret(ctx, "bob", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewManager(repo)
	if err != nil {
		t.Fatal(err)
	}
	pending := auth.NewTwoFactorPendingStore(time.Minute)
	token, err := pending.Issue("bob", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateUserStatus(ctx, "bob", false); err != nil {
		t.Fatal(err)
	}
	tokens := auth.NewTokenStore(time.Hour)
	for _, h := range []http.Handler{NewTwoFactorLoginHandler(manager, tokens, repo, pending, nil), NewRecoveryLoginHandler(manager, tokens, repo, pending, nil)} {
		body, _ := json.Marshal(map[string]string{"two_factor_token": token, "code": "123456", "recovery_code": "fixture-code"})
		res := httptest.NewRecorder()
		h.ServeHTTP(res, httptest.NewRequest("POST", "/api/2fa/login", bytes.NewReader(body)))
		if res.Code != 403 || !strings.Contains(res.Body.String(), "account is disabled") {
			t.Fatalf("status %d: %s", res.Code, res.Body.String())
		}
	}
}
