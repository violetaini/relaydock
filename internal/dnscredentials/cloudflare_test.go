package dnscredentials

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestNormalizeCloudflareToken(t *testing.T) {
	got, err := NormalizeCloudflare(map[string]string{
		CloudflareTokenKey: " token-value ",
		CloudflareEmailKey: " ",
	})
	if err != nil {
		t.Fatalf("NormalizeCloudflare: %v", err)
	}
	if got[CloudflareTokenKey] != "token-value" || len(got) != 1 {
		t.Fatalf("unexpected normalized credentials: %#v", got)
	}
}

func TestNormalizeCloudflareCompleteGlobalPairWinsOverLegacyToken(t *testing.T) {
	got, err := NormalizeCloudflare(map[string]string{
		CloudflareTokenKey:  "stale-token",
		CloudflareEmailKey:  "admin@example.com",
		CloudflareGlobalKey: "global-key",
	})
	if err != nil {
		t.Fatalf("NormalizeCloudflare: %v", err)
	}
	if got[CloudflareEmailKey] != "admin@example.com" || got[CloudflareGlobalKey] != "global-key" {
		t.Fatalf("unexpected normalized credentials: %#v", got)
	}
	if _, exists := got[CloudflareTokenKey]; exists {
		t.Fatalf("token must not remain beside a global key: %#v", got)
	}

	auth, err := ResolveCloudflare(got)
	if err != nil {
		t.Fatalf("ResolveCloudflare: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	auth.Apply(req)
	if req.Header.Get("Authorization") != "" || req.Header.Get("X-Auth-Key") != "global-key" {
		t.Fatalf("global key was mapped to the wrong headers: %#v", req.Header)
	}
}

func TestResolveCloudflareRejectsIncompleteGlobalCredentials(t *testing.T) {
	_, err := ResolveCloudflare(map[string]string{CloudflareGlobalKey: "global-key"})
	if err == nil || !strings.Contains(err.Error(), "账户邮箱") {
		t.Fatalf("expected actionable missing-email error, got %v", err)
	}
}

func TestFriendlyCloudflareError(t *testing.T) {
	err := FriendlyCloudflareError(errors.New("cloudflare API: [6003] Invalid request headers; [6103] Invalid format"))
	if err == nil || !strings.Contains(err.Error(), "API Token 时请留空账户邮箱") || !strings.Contains(err.Error(), "Global API Key") {
		t.Fatalf("unexpected friendly error: %v", err)
	}
}
