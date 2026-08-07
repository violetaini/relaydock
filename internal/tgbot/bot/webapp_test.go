package bot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/tgbot/config"
	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

const testBotToken = "123456789:AAExampleTokenForInitDataTests"

func signedTestInitData(t *testing.T, authDate string) string {
	t.Helper()
	values := url.Values{
		"auth_date": {authDate},
		"query_id":  {"AAExampleQuery"},
		"user":      {`{"id":123456,"username":"preview_user"}`},
	}
	pairs := make([]string, 0, len(values))
	for key, values := range values {
		pairs = append(pairs, key+"="+values[0])
	}
	sort.Strings(pairs)
	secretMAC := hmac.New(sha256.New, []byte("WebAppData"))
	_, _ = secretMAC.Write([]byte(testBotToken))
	dataMAC := hmac.New(sha256.New, secretMAC.Sum(nil))
	_, _ = dataMAC.Write([]byte(strings.Join(pairs, "\n")))
	values.Set("hash", hex.EncodeToString(dataMAC.Sum(nil)))
	return values.Encode()
}

func TestValidateInitDataRequiresFreshAuthDate(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		authDate  string
		wantError string
	}{
		{name: "missing", wantError: "invalid auth date"},
		{name: "invalid", authDate: "not-a-timestamp", wantError: "invalid auth date"},
		{name: "expired", authDate: testUnixSeconds(now.Add(-25 * time.Hour)), wantError: "expired"},
		{name: "future", authDate: testUnixSeconds(now.Add(10 * time.Minute)), wantError: "future"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := signedTestInitData(t, tt.authDate)
			_, _, err := validateInitData(data, testBotToken)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateInitData() error = %v, want substring %q", err, tt.wantError)
			}
		})
	}
}

func TestValidateInitDataAcceptsSmallClockSkew(t *testing.T) {
	data := signedTestInitData(t, testUnixSeconds(time.Now().Add(1*time.Minute)))
	tgID, handle, err := validateInitData(data, testBotToken)
	if err != nil {
		t.Fatalf("validateInitData() unexpected error: %v", err)
	}
	if tgID != 123456 || handle != "preview_user" {
		t.Fatalf("identity = (%d, %q), want (123456, preview_user)", tgID, handle)
	}
}

func TestValidateInitDataRejectsDuplicateHash(t *testing.T) {
	data := signedTestInitData(t, testUnixSeconds(time.Now()))
	values, err := url.ParseQuery(data)
	if err != nil {
		t.Fatal(err)
	}
	values.Add("hash", values.Get("hash"))
	if _, _, err := validateInitData(values.Encode(), testBotToken); err == nil {
		t.Fatal("validateInitData() accepted duplicate hash fields")
	}
}

func TestWebAppMeRejectsInitDataInQueryString(t *testing.T) {
	data := signedTestInitData(t, testUnixSeconds(time.Now()))
	service := &Service{cfg: config.Config{TGBotToken: testBotToken}}
	r := httptest.NewRequest(http.MethodGet, "/api/tg-webapp/me?initData="+url.QueryEscape(data), nil)
	recorder := httptest.NewRecorder()

	service.webAppMe(recorder, r)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if strings.Contains(webAppHTML, "URLSearchParams(location.search)") {
		t.Fatal("Mini App still imports signed initData from the URL")
	}
}

func TestRegistrationUsernameRuleMatchesMaster(t *testing.T) {
	if usernameRe.MatchString("user_name") {
		t.Fatal("Bot accepted an underscore that the master rejects")
	}
	if !usernameRe.MatchString("user-name") {
		t.Fatal("Bot rejected a valid master username")
	}
	if strings.Contains(webAppHTML, "a-zA-Z0-9_-") {
		t.Fatal("Mini App still accepts underscores in usernames")
	}
}

func TestDevPreviewRequiresLoopbackPeerAndHost(t *testing.T) {
	service := &Service{cfg: config.Config{
		TGBotToken:       testBotToken,
		WebAppDevPreview: true,
		AdminTGIDs:       []int64{123456},
	}}

	tests := []struct {
		name       string
		remoteAddr string
		host       string
		wantOK     bool
	}{
		{name: "public peer", remoteAddr: "198.51.100.10:443", host: "localhost", wantOK: false},
		{name: "public host through local proxy", remoteAddr: "127.0.0.1:443", host: "arcway.example", wantOK: false},
		{name: "spoofed local host through proxy", remoteAddr: "127.0.0.1:443", host: "localhost", wantOK: false},
		{name: "local ipv4", remoteAddr: "127.0.0.1:3000", host: "localhost:3000", wantOK: true},
		{name: "local ipv6", remoteAddr: "[::1]:3000", host: "[::1]:3000", wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://"+tt.host+"/tg-app", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.name == "spoofed local host through proxy" {
				r.Header.Set("X-Real-IP", "198.51.100.10")
			}
			_, _, err := service.validateRequestInitData(r, devPreviewInitData)
			if (err == nil) != tt.wantOK {
				t.Fatalf("validateRequestInitData() error = %v, wantOK=%v", err, tt.wantOK)
			}
		})
	}
}

func TestClientIPUsesRemoteAddrForDirectClients(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/tg-app", nil)
	r.RemoteAddr = "198.51.100.10:443"
	r.Header.Set("X-Real-IP", "203.0.113.9")
	r.Header.Set("X-Forwarded-For", "203.0.113.8")
	if got := clientIP(r); got != "198.51.100.10" {
		t.Fatalf("clientIP() = %q, want RemoteAddr", got)
	}
}

func TestClientIPAcceptsStrictForwardedAddressFromLocalProxy(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/tg-app", nil)
	r.RemoteAddr = "127.0.0.1:443"
	r.Header.Set("X-Real-IP", "not-an-ip")
	r.Header.Set("X-Forwarded-For", "198.51.100.10, 203.0.113.9")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP() = %q, want last valid forwarded address", got)
	}
}

func TestWebAppPageOnlyInjectsPreviewFlagForLoopback(t *testing.T) {
	backend := http.NewServeMux()
	backend.HandleFunc("/api/admin/system-settings/default-theme", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"default_theme":""}`))
	})
	backend.HandleFunc("/api/public/branding", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"Arcway"}`))
	})
	service := New(config.Config{
		TGBotToken:       testBotToken,
		WebAppDevPreview: true,
		AdminTGIDs:       []int64{123456},
	}, mmwxclient.NewInProcess(backend, "test-admin-token", 1))

	remote := httptest.NewRequest(http.MethodGet, "http://arcway.example/tg-app", nil)
	remote.RemoteAddr = "198.51.100.10:443"
	remoteRecorder := httptest.NewRecorder()
	service.webAppPage(remoteRecorder, remote)
	if strings.Contains(remoteRecorder.Body.String(), "if(!initData&&true)") {
		t.Fatal("public Mini App page enabled the dev-preview sentinel")
	}

	local := httptest.NewRequest(http.MethodGet, "http://localhost:3000/tg-app", nil)
	local.RemoteAddr = "127.0.0.1:3000"
	localRecorder := httptest.NewRecorder()
	service.webAppPage(localRecorder, local)
	if !strings.Contains(localRecorder.Body.String(), "if(!initData&&true)") {
		t.Fatal("loopback Mini App page did not enable the intentional dev preview")
	}
}

func TestWebAppHTMLUsesContextSafeInlineArguments(t *testing.T) {
	for _, unsafe := range []string{
		`onclick="__subcopy('+i+',\''+esc(sf.url)`,
		`onclick="__copyInv(\''+esc(ic.code)`,
		`onclick="__extendUser(\''+esc(u.username)`,
		`onclick="__assignPkg(\''+esc(u.username)`,
	} {
		if strings.Contains(webAppHTML, unsafe) {
			t.Fatalf("web app still interpolates %s into an inline handler", unsafe)
		}
	}
	if !strings.Contains(webAppHTML, "function jsa(") {
		t.Fatal("web app is missing the JavaScript attribute string encoder")
	}
}

func TestRateLimitMapIsBounded(t *testing.T) {
	now := time.Now()
	active := make(map[int]*rlEntry, rateLimitMaxKeys)
	for i := 0; i < rateLimitMaxKeys; i++ {
		active[i] = &rlEntry{windowStart: now}
	}
	if makeRateLimitRoom(active, now, time.Minute) {
		t.Fatal("makeRateLimitRoom() allowed an unbounded active key")
	}
	active[0].windowStart = now.Add(-2 * time.Minute)
	if !makeRateLimitRoom(active, now, time.Minute) {
		t.Fatal("makeRateLimitRoom() did not reclaim an expired key")
	}
	if len(active) != rateLimitMaxKeys-1 {
		t.Fatalf("entry count = %d, want %d", len(active), rateLimitMaxKeys-1)
	}
}

func testUnixSeconds(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}
