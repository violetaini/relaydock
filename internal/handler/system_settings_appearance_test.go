package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrandingAppearancePersistsAcrossHandlerReplacement(t *testing.T) {
	repo, _ := newProbePublicRepository(t)
	h := NewSystemSettingsHandler(repo, nil)
	w := httptest.NewRecorder()
	h.SetBranding(w, httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"name":"Example","login_theme":"glass","login_title":"Welcome","login_kicker":"EXAMPLE","auto_sso":true,"font_preset":"classic-serif"}`)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	next := NewSystemSettingsHandler(repo, nil)
	w = httptest.NewRecorder()
	next.GetBrandingPublic(w, httptest.NewRequest(http.MethodGet, "/", nil))
	var v map[string]any
	json.Unmarshal(w.Body.Bytes(), &v)
	if v["auto_sso"] != true || v["login_theme"] != "glass" || v["font_preset"] != "classic-serif" {
		t.Fatal(v)
	}
	w = httptest.NewRecorder()
	next.SetBranding(w, httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"login_theme":"<script>"}`)))
	if w.Code != 400 {
		t.Fatal("invalid theme accepted")
	}
}
func TestBrandingRandomBackgroundValidation(t *testing.T) {
	repo, _ := newProbePublicRepository(t)
	h := NewSystemSettingsHandler(repo, nil)
	w := httptest.NewRecorder()
	h.SetBranding(w, httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"login_background_mode":"random","login_background_urls":["https://images.example/random","/wallpaper.jpg"]}`)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	h.GetBrandingPublic(w, httptest.NewRequest(http.MethodGet, "/", nil))
	var b map[string]any
	json.Unmarshal(w.Body.Bytes(), &b)
	if b["login_theme"] != "glass" || b["login_background_mode"] != "random" || len(b["login_background_urls"].([]any)) != 2 {
		t.Fatal(b)
	}
	for _, body := range []string{`{"login_background_mode":"bad"}`, `{"login_background_urls":["javascript:alert(1)"]}`, `{"login_background_urls":["//untrusted.example/image"]}`} {
		w = httptest.NewRecorder()
		h.SetBranding(w, httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("invalid background accepted", body)
		}
	}
}

func TestBrandingBackgroundDefaultDoesNotOverrideInstanceChoices(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stored *string
		want   []string
	}{
		{name: "unconfigured", want: []string{"https://api.timelessq.com/bing/random"}},
		{name: "custom", stored: stringPtrForBackgroundTest(`["https://images.example/custom"]`), want: []string{"https://images.example/custom"}},
		{name: "cleared", stored: stringPtrForBackgroundTest(`[]`), want: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, _ := newProbePublicRepository(t)
			if tc.stored != nil {
				if err := repo.SetSystemSetting(t.Context(), "branding_login_background_urls", *tc.stored); err != nil {
					t.Fatal(err)
				}
			}
			h := NewSystemSettingsHandler(repo, nil)
			w := httptest.NewRecorder()
			h.GetBrandingPublic(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
			var got brandingSettings
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.LoginBackgroundURLs) != len(tc.want) {
				t.Fatal(got.LoginBackgroundURLs)
			}
			for i := range tc.want {
				if got.LoginBackgroundURLs[i] != tc.want[i] {
					t.Fatal(got.LoginBackgroundURLs)
				}
			}
		})
	}
}

func stringPtrForBackgroundTest(value string) *string { return &value }
