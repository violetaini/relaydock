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
