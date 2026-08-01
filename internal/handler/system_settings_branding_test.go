package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decodeBrandingResponse(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode branding response: %v", err)
	}
	return body
}

func TestBrandingSettingsDefaultToRelayDockAndExposePublicContract(t *testing.T) {
	repo, _ := newProbePublicRepository(t)
	handler := NewSystemSettingsHandler(repo, nil)

	adminResponse := httptest.NewRecorder()
	handler.GetBranding(adminResponse, httptest.NewRequest(http.MethodGet, "/api/admin/system-settings/branding", nil))
	admin := decodeBrandingResponse(t, adminResponse)
	if admin["success"] != true || admin["name"] != defaultBrandingName || admin["logo"] != "" || admin["favicon"] != "" {
		t.Fatalf("default admin branding=%#v", admin)
	}

	publicResponse := httptest.NewRecorder()
	handler.GetBrandingPublic(publicResponse, httptest.NewRequest(http.MethodGet, "/api/public/branding", nil))
	public := decodeBrandingResponse(t, publicResponse)
	if public["name"] != defaultBrandingName || public["logo"] != "" || public["favicon"] != "" {
		t.Fatalf("default public branding=%#v", public)
	}
	if _, ok := public["success"]; ok {
		t.Fatalf("public branding exposed an admin-only success wrapper: %#v", public)
	}
}

func TestBrandingSettingsSaveResetAndRejectInvalidAssets(t *testing.T) {
	repo, _ := newProbePublicRepository(t)
	handler := NewSystemSettingsHandler(repo, nil)

	request := httptest.NewRequest(http.MethodPut, "/api/admin/system-settings/branding", strings.NewReader(`{
		"name":"Northstar",
		"logo":"/assets/northstar-logo.svg",
		"favicon":"data:image/png;base64,AA=="
	}`))
	response := httptest.NewRecorder()
	handler.SetBranding(response, request)
	saved := decodeBrandingResponse(t, response)
	if saved["name"] != "Northstar" || saved["logo"] != "/assets/northstar-logo.svg" || saved["favicon"] != "data:image/png;base64,AA==" {
		t.Fatalf("saved branding=%#v", saved)
	}

	for key, want := range map[string]string{
		brandingNameKey:    "Northstar",
		brandingLogoKey:    "/assets/northstar-logo.svg",
		brandingFaviconKey: "data:image/png;base64,AA==",
	} {
		if got, err := repo.GetSystemSetting(context.Background(), key); err != nil || got != want {
			t.Fatalf("stored %s=%q err=%v want=%q", key, got, err, want)
		}
	}

	invalid := httptest.NewRequest(http.MethodPut, "/api/admin/system-settings/branding", strings.NewReader(`{
		"name":"should not save",
		"logo":"javascript:alert(1)",
		"favicon":"/favicon.ico"
	}`))
	invalidResponse := httptest.NewRecorder()
	handler.SetBranding(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid branding status=%d body=%s", invalidResponse.Code, invalidResponse.Body.String())
	}
	if got, _ := repo.GetSystemSetting(context.Background(), brandingNameKey); got != "Northstar" {
		t.Fatalf("invalid branding partially saved name=%q", got)
	}

	reset := httptest.NewRequest(http.MethodPut, "/api/admin/system-settings/branding", strings.NewReader(`{"name":"","logo":"","favicon":""}`))
	resetResponse := httptest.NewRecorder()
	handler.SetBranding(resetResponse, reset)
	resetBody := decodeBrandingResponse(t, resetResponse)
	if resetBody["name"] != defaultBrandingName || resetBody["logo"] != "" || resetBody["favicon"] != "" {
		t.Fatalf("reset branding=%#v", resetBody)
	}
}
