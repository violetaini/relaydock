package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDashboardRefreshDefaultsToOneSecondAndHonorsSavedValue(t *testing.T) {
	repo, _ := newProbePublicRepository(t)
	settings := NewSystemSettingsHandler(repo, nil)
	hub := NewDashboardWSHub(repo, nil, nil)

	assertPublicDashboardRefresh(t, settings, dashboardRefreshDefault)
	if got := hub.refreshInterval(); got != time.Second {
		t.Fatalf("default dashboard WebSocket interval=%s, want %s", got, time.Second)
	}

	setProbePublicSetting(t, repo, dashboardRefreshKey, "2500")
	assertPublicDashboardRefresh(t, settings, 2500)
	if got := hub.refreshInterval(); got != 2500*time.Millisecond {
		t.Fatalf("saved dashboard WebSocket interval=%s, want %s", got, 2500*time.Millisecond)
	}
}

func assertPublicDashboardRefresh(t *testing.T, settings *SystemSettingsHandler, want int) {
	t.Helper()
	response := httptest.NewRecorder()
	settings.GetPublicIntervals(response, httptest.NewRequest(http.MethodGet, "/api/system-config/refetch-interval", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("public refresh interval status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		RefetchIntervalMs int `json:"refetch_interval_ms"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode public refresh interval: %v", err)
	}
	if body.RefetchIntervalMs != want {
		t.Fatalf("public refresh interval=%d, want %d", body.RefetchIntervalMs, want)
	}
}
