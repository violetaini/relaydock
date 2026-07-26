package ddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"miaomiaowux/internal/dnscredentials"
)

func TestNewCloudflareProviderUsesGlobalHeadersWhenLegacyRecordContainsBothModes(t *testing.T) {
	provider, err := newCloudflareProvider(map[string]string{
		dnscredentials.CloudflareTokenKey:  "stale-token",
		dnscredentials.CloudflareEmailKey:  "admin@example.com",
		dnscredentials.CloudflareGlobalKey: "global-key",
	})
	if err != nil {
		t.Fatalf("newCloudflareProvider: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	provider.authHeader(req)
	if req.Header.Get("Authorization") != "" {
		t.Fatalf("global key must not be sent as bearer: %#v", req.Header)
	}
	if req.Header.Get("X-Auth-Email") != "admin@example.com" || req.Header.Get("X-Auth-Key") != "global-key" {
		t.Fatalf("missing global authentication headers: %#v", req.Header)
	}
}

func TestCloudflareAPIAuthFailureIsActionableChinese(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":6003,"message":"Invalid request headers"},{"code":6103,"message":"Invalid format for X-Auth-Email header"}]}`))
	}))
	defer server.Close()

	provider, err := newCloudflareProvider(map[string]string{dnscredentials.CloudflareTokenKey: "token"})
	if err != nil {
		t.Fatalf("newCloudflareProvider: %v", err)
	}
	provider.baseURL = server.URL
	err = provider.doJSON(context.Background(), http.MethodGet, server.URL, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "Cloudflare 鉴权失败") || !strings.Contains(err.Error(), "请留空账户邮箱") {
		t.Fatalf("unexpected error: %v", err)
	}
}
