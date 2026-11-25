package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestCustomSubscriptionRulesPersistAndProduceAllClientFormats(t *testing.T) {
	repo, source := generationFixture(t)
	if err := repo.SetSystemSetting(context.Background(), "master_url", "https://panel.example"); err != nil {
		t.Fatal(err)
	}
	g := generationRecipe(source.ID)
	g.Outputs = nil
	for _, client := range []string{"clashmeta", "clash-to-shadowrocket", "sing-box", "clash-to-surge", "clash-to-loon", "v2ray"} {
		mode := "full"
		if client == "v2ray" {
			mode = "nodes"
		}
		g.Outputs = append(g.Outputs, storage.SubscriptionOutput{Client: client, Mode: mode, RuleMode: "custom", RuleCategories: []string{"ads", "youtube", "private", "cn"}})
	}
	w := generationCall(repo, "/api/admin/subscribe-files/generation", generationRequest{Name: "Custom rules", Filename: "custom-rules.yaml", Generation: g})
	if w.Code != 201 {
		t.Fatalf("custom create=%d: %s", w.Code, w.Body.String())
	}
	var created struct {
		Preview generationPreview `json:"preview"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Preview.Outputs) != 6 {
		t.Fatalf("outputs=%d", len(created.Preview.Outputs))
	}
	for _, out := range created.Preview.Outputs {
		switch out.Client {
		case "clashmeta":
			if !strings.Contains(out.Content, "GEOSITE,youtube,PROXY") || !strings.Contains(out.Content, "MATCH,PROXY") || strings.Contains(out.Content, "GEOSITE,github") {
				t.Fatal("selected categories were changed")
			}
		case "clash-to-shadowrocket", "clash-to-surge", "clash-to-loon":
			if !strings.Contains(out.Content, "https://panel.example/api/public/subscription-rule-sets/geosite/youtube.list") || strings.Contains(out.Content, "GEOSITE,") {
				t.Fatalf("%s contains non-native or missing rule sets", out.Client)
			}
		case "sing-box":
			var native map[string]any
			if json.Unmarshal([]byte(out.Content), &native) != nil || native["route"] == nil || !strings.Contains(out.Content, "geosite/youtube.srs") {
				t.Fatal("sing-box lost custom routing")
			}
		}
	}
	f, err := repo.GetSubscribeFileByFilename(context.Background(), "custom-rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f.Generation.Outputs[0].RuleMode != "custom" || len(f.Generation.Outputs[0].RuleCategories) != 4 {
		t.Fatal("category selection was not persisted")
	}
	// The v2ray profile owns its independently selected routing categories.
	f.Generation.Outputs[5].RuleCategories = []string{"github"}
	if _, err = repo.UpdateSubscribeFile(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/admin/subscribe-files/"+strconv.FormatInt(f.ID, 10)+"/routes", nil).WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	w = httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "geosite:github") || strings.Contains(w.Body.String(), "geosite:youtube") {
		t.Fatalf("independent custom routing=%d %s", w.Code, w.Body.String())
	}
}

func TestCustomSubscriptionRulesValidateKeysAndKeepAnEmptySelection(t *testing.T) {
	repo, source := generationFixture(t)
	g := generationRecipe(source.ID)
	g.Outputs[0] = storage.SubscriptionOutput{Client: "clashmeta", Mode: "full", RuleMode: "custom", RuleCategories: []string{"../../private"}}
	w := generationCall(repo, "/api/admin/subscribe-files/generation/preview", generationRequest{Generation: g})
	if w.Code != 422 {
		t.Fatalf("unknown category=%d", w.Code)
	}
	g.Outputs[0].RuleCategories = []string{}
	w = generationCall(repo, "/api/admin/subscribe-files/generation/preview", generationRequest{Generation: g})
	if w.Code != 200 || strings.Contains(w.Body.String(), "GEOSITE,") || !strings.Contains(w.Body.String(), "MATCH,PROXY") {
		t.Fatalf("empty selection changed to default: %d %s", w.Code, w.Body.String())
	}
}

type ruleSetTransport func(*http.Request) (*http.Response, error)

func (f ruleSetTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPublicSubscriptionRuleSetsAreWhitelistedCachedAndCredentialFree(t *testing.T) {
	h := NewSubscriptionRuleSetsHandler().(*subscriptionRuleSetsHandler)
	calls := 0
	status := 200
	h.client = &http.Client{Transport: ruleSetTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.list" || r.Header.Get("Authorization") != "" {
			t.Fatal("untrusted URL or forwarded credentials")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("+.youtube.com\nyoutubei.googleapis.com\n")), Header: make(http.Header)}, nil
	})}
	request := func(path, etag string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "private-user-token")
		r.Header.Set("If-None-Match", etag)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	path := subscriptionRuleSetPrefix + "geosite/youtube.list"
	w := request(path, "")
	if w.Code != 200 || w.Body.String() != "DOMAIN-SUFFIX,youtube.com\nDOMAIN,youtubei.googleapis.com\n" {
		t.Fatalf("rule set=%d %s", w.Code, w.Body.String())
	}
	if cached := request(path, w.Header().Get("ETag")); cached.Code != 304 || calls != 1 {
		t.Fatal("conditional cache miss")
	}
	if invalid := request(subscriptionRuleSetPrefix+"geosite/not-whitelisted.list", ""); invalid.Code != 404 || calls != 1 {
		t.Fatal("non-catalog request reached upstream")
	}
	h.entries["geosite/youtube.list"].updated = time.Now().Add(-25 * time.Hour)
	status = 502
	if stale := request(path, ""); stale.Code != 200 || stale.Header().Get("Warning") == "" {
		t.Fatal("last good rules were not retained")
	}
	request(path, "")
	if calls != 2 {
		t.Fatal("upstream failures were not backed off")
	}
	ip, err := convertPublicSubscriptionRuleSet([]byte("10.0.0.0/8\nfc00::/7\n"), true)
	if err != nil || !strings.Contains(string(ip), "IP-CIDR6,fc00::/7,no-resolve") {
		t.Fatalf("CIDR conversion=%s %v", ip, err)
	}
	if _, err := convertPublicSubscriptionRuleSet([]byte("not a valid domain"), false); err == nil {
		t.Fatal(fmt.Errorf("malformed rule was accepted"))
	}
}
