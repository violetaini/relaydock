package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/safefetch"
	"github.com/violetaini/relaydock/internal/storage"
	"gopkg.in/yaml.v3"
)

func TestGeoIPLookupLogsDoNotExposeAPIToken(t *testing.T) {
	const secret = "geoip-token-must-not-leak"
	t.Setenv("ARCWAY_IPINFO_TOKEN", secret)
	previousClient := geoIPHTTPClient
	geoIPHTTPClient = &http.Client{Transport: failingSubscriptionRoundTripper{}}
	t.Cleanup(func() { geoIPHTTPClient = previousClient })

	const ip = "203.0.113.250"
	geoIPCache.Delete(ip)
	t.Cleanup(func() { geoIPCache.Delete(ip) })
	logPath := filepath.Join(t.TempDir(), "geoip.log")
	if err := logger.EnableDebug(logPath); err != nil {
		t.Fatal(err)
	}
	debugEnabled := true
	t.Cleanup(func() {
		if debugEnabled {
			_ = logger.DisableDebug()
		}
	})

	if country := getGeoIPCountryCode(ip); country != "" {
		t.Fatalf("country=%q, want empty result after network failure", country)
	}
	_ = logger.DisableDebug()
	debugEnabled = false
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), secret) || strings.Contains(string(logged), "token=") {
		t.Fatalf("GeoIP log exposed API token: %s", logged)
	}
}

func newProxyProviderContentFixture(t *testing.T) (*storage.TrafficRepository, int64, string) {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "proxy-provider-content.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x53}, 32)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "test-hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	sourceID, err := repo.CreateExternalSubscription(ctx, storage.ExternalSubscription{
		Username: "alice",
		Name:     "secret source",
		URL:      "https://airport.example/sub?token=upstream-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := repo.CreateProxyProviderConfig(ctx, &storage.ProxyProviderConfig{
		Username:               "alice",
		ExternalSubscriptionID: sourceID,
		Name:                   "airport",
		Type:                   "http",
		Interval:               3600,
		SizeLimit:              1 << 20,
		ProcessMode:            "client",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := repo.EnsureProxyProviderAccessToken(ctx, providerID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	return repo, providerID, token
}

func newProxyProviderContentRequest(method string, providerID int64, token string) *http.Request {
	request := httptest.NewRequest(method, "/api/proxy-provider/"+strconv.FormatInt(providerID, 10), nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request
}

func TestProxyProviderContentGETAndHEADReturnNormalizedYAML(t *testing.T) {
	repo, providerID, token := newProxyProviderContentFixture(t)
	config, err := repo.GetProxyProviderConfig(context.Background(), providerID)
	if err != nil || config == nil {
		t.Fatalf("GetProxyProviderConfig: %v / %#v", err, config)
	}
	config.Filter = "^HK$"
	if err := repo.UpdateProxyProviderConfig(context.Background(), config); err != nil {
		t.Fatalf("UpdateProxyProviderConfig: %v", err)
	}
	handler := NewProxyProviderContentHandler(repo).(*ProxyProviderContentHandler)
	handler.fetch = func(_ *storage.ExternalSubscription) ([]byte, error) {
		return []byte("secret-metadata: upstream-secret\nproxies:\n  - {name: HK, type: ss, server: 8.8.8.8, port: 443, cipher: aes-128-gcm, password: node-password}\n  - {name: JP, type: ss, server: 1.1.1.1, port: 443, cipher: aes-128-gcm, password: node-password}\nrules:\n  - MATCH,DIRECT\n"), nil
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			request := newProxyProviderContentRequest(method, providerID, token)
			if strings.Contains(request.URL.Path, token) {
				t.Fatal("provider credential was placed in the request URL")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store, max-age=0" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("missing security headers: %#v", response.Header())
			}
			if !strings.HasPrefix(response.Header().Get("Content-Type"), "text/yaml") {
				t.Fatalf("Content-Type=%q", response.Header().Get("Content-Type"))
			}
			if method == http.MethodHead {
				if response.Body.Len() != 0 {
					t.Fatalf("HEAD returned body: %q", response.Body.String())
				}
				return
			}
			if strings.Contains(response.Body.String(), "upstream-secret") || strings.Contains(response.Body.String(), "secret-metadata") || strings.Contains(response.Body.String(), "rules:") {
				t.Fatalf("normalized output retained upstream metadata: %s", response.Body.String())
			}
			var payload struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.Proxies) != 1 || payload.Proxies[0]["name"] != "HK" {
				t.Fatalf("unexpected normalized proxies: %#v", payload.Proxies)
			}
		})
	}
}

func TestProxyProviderContentFailsClosed(t *testing.T) {
	repo, providerID, token := newProxyProviderContentFixture(t)
	handler := NewProxyProviderContentHandler(repo).(*ProxyProviderContentHandler)
	handler.fetch = func(_ *storage.ExternalSubscription) ([]byte, error) {
		return []byte("rules: []\n"), nil
	}

	for _, target := range []string{
		"/api/proxy-provider/not-an-id",
		"/api/proxy-provider/" + strconv.FormatInt(providerID, 10) + "/extra",
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "token") {
			t.Fatalf("target=%q status=%d body=%q", target, response.Code, response.Body.String())
		}
	}
	for _, request := range []*http.Request{
		newProxyProviderContentRequest(http.MethodGet, providerID, ""),
		newProxyProviderContentRequest(http.MethodGet, providerID, "wrong-token"),
		newProxyProviderContentRequest(http.MethodGet, providerID+1, token),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("unauthorized request %s returned %d", request.URL.Path, response.Code)
		}
	}

	badSource := httptest.NewRecorder()
	handler.ServeHTTP(badSource, newProxyProviderContentRequest(http.MethodGet, providerID, token))
	if badSource.Code != http.StatusBadGateway || strings.Contains(badSource.Body.String(), "upstream") {
		t.Fatalf("invalid source status=%d body=%q", badSource.Code, badSource.Body.String())
	}

	if _, err := repo.RotateProxyProviderAccessToken(context.Background(), providerID, "alice"); err != nil {
		t.Fatal(err)
	}
	oldToken := httptest.NewRecorder()
	handler.ServeHTTP(oldToken, newProxyProviderContentRequest(http.MethodGet, providerID, token))
	if oldToken.Code != http.StatusNotFound {
		t.Fatalf("rotated token status=%d, want 404", oldToken.Code)
	}

	method := httptest.NewRecorder()
	handler.ServeHTTP(method, newProxyProviderContentRequest(http.MethodPost, providerID, token))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST status=%d Allow=%q", method.Code, method.Header().Get("Allow"))
	}
}

func TestProxyProviderContentAcceptsLegacyEmptyHTTPType(t *testing.T) {
	repo, providerID, token := newProxyProviderContentFixture(t)
	config, err := repo.GetProxyProviderConfig(context.Background(), providerID)
	if err != nil || config == nil {
		t.Fatalf("GetProxyProviderConfig: %v / %#v", err, config)
	}
	config.Type = ""
	if err := repo.UpdateProxyProviderConfig(context.Background(), config); err != nil {
		t.Fatalf("store legacy empty provider type: %v", err)
	}
	handler := NewProxyProviderContentHandler(repo).(*ProxyProviderContentHandler)
	handler.fetch = func(_ *storage.ExternalSubscription) ([]byte, error) {
		return []byte("proxies:\n  - {name: Legacy, type: ss, server: 8.8.8.8, port: 443, cipher: aes-128-gcm, password: node-password}\n"), nil
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newProxyProviderContentRequest(http.MethodGet, providerID, token))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Legacy") {
		t.Fatalf("legacy empty type status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestProxyProviderFetchRejectsPrivateURLWithoutLeakingCredential(t *testing.T) {
	var reached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte("proxies: []"))
	}))
	defer server.Close()
	secretURL := server.URL + "/sub?token=do-not-log"
	_, err := fetchSubscriptionContent(&storage.ExternalSubscription{ID: 42, Name: "source", URL: secretURL})
	if !errors.Is(err, safefetch.ErrProhibitedAddress) {
		t.Fatalf("error=%v, want prohibited address", err)
	}
	if reached.Load() {
		t.Fatal("private upstream was reached")
	}
	if strings.Contains(err.Error(), secretURL) || strings.Contains(err.Error(), "do-not-log") {
		t.Fatalf("fetch error leaked source URL: %v", err)
	}
	if strings.Contains(subscriptionContentCacheKey(secretURL), secretURL) || strings.Contains(subscriptionContentCacheKey(secretURL), "do-not-log") {
		t.Fatal("cache key contains the upstream URL")
	}
}

func TestSubscriptionContentCacheSeparatesUserAgentsAndInvalidatesURL(t *testing.T) {
	rawURL := "https://subscription.example/source?token=secret"
	keyA := subscriptionContentCacheKey(rawURL, "client-a")
	keyB := subscriptionContentCacheKey(rawURL, "client-b")
	if keyA == keyB {
		t.Fatal("different upstream User-Agent values shared a cache key")
	}
	if strings.Contains(keyA, rawURL) || strings.Contains(keyB, rawURL) {
		t.Fatal("cache key contains the upstream URL")
	}

	subscriptionCache.put(keyA, []byte("a"), time.Now())
	subscriptionCache.put(keyB, []byte("b"), time.Now())
	InvalidateSubscriptionContentCache(rawURL)
	if _, ok := subscriptionCache.get(keyA, time.Now()); ok {
		t.Fatal("first User-Agent cache variant survived URL invalidation")
	}
	if _, ok := subscriptionCache.get(keyB, time.Now()); ok {
		t.Fatal("second User-Agent cache variant survived URL invalidation")
	}
}

func TestNormalizeProxyProviderContentEnforcesConfiguredLimit(t *testing.T) {
	content := []byte("proxies:\n  - {name: HK, type: ss, server: 8.8.8.8, port: 443}\n")
	if _, err := normalizeProxyProviderContent(content, len(content)-1); err == nil {
		t.Fatal("content exceeding configured size limit was accepted")
	}
	if _, err := normalizeProxyProviderContent([]byte("proxies:\n  - bad\n"), 0); err == nil {
		t.Fatal("non-mapping proxy was accepted")
	}
}
