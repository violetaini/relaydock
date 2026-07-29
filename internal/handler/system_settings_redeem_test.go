package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestGetRedeemTemplateReturnsConfiguredValue(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "redeem-template.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	want := "需要登录 RelayDock\n{主控域名}"
	if err := repo.SetSystemSetting(context.Background(), "redeem_copy_template", want); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/admin/system-settings/redeem-template", nil)
	response := httptest.NewRecorder()
	NewSystemSettingsHandler(repo, nil).GetRedeemTemplate(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}

	var body struct {
		RedeemTemplate string `json:"redeem_template"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.RedeemTemplate != want {
		t.Fatalf("redeem template = %q, want %q", body.RedeemTemplate, want)
	}
	persisted, err := repo.GetSystemSetting(context.Background(), "redeem_copy_template")
	if err != nil {
		t.Fatal(err)
	}
	if persisted != want {
		t.Fatalf("persisted template = %q, want %q", persisted, want)
	}
}
