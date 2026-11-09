package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/speedtest"
)

func TestSpeedTestMihomoStatusUsesStructuredContract(t *testing.T) {
	want := speedtest.MihomoCoreStatus{
		Ready: true, Path: "data/bin/mihomo", Source: "managed",
		CurrentVersion: "1.19.28", TargetVersion: "1.19.29", LatestVersion: "1.19.29",
		LatestError: "github unavailable", Manageable: true, UpdateAvailable: true,
	}
	h := NewSpeedTestHandler(nil, capabilities.NewManager())
	h.mihomoStatus = func(context.Context) speedtest.MihomoCoreStatus { return want }

	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/admin/speedtest/mihomo-status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Success bool                       `json:"success"`
		Ready   bool                       `json:"ready"`
		Path    string                     `json:"path"`
		Status  speedtest.MihomoCoreStatus `json:"status"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || !response.Ready || response.Path != want.Path || response.Status != want {
		t.Fatalf("response = %#v, want status %#v", response, want)
	}
	if strings.Contains(recorder.Body.String(), "latest_check_error") {
		t.Fatalf("response contains obsolete latest error field: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"latest_error":"github unavailable"`) {
		t.Fatalf("response does not expose latest_error: %s", recorder.Body.String())
	}
}

func TestSpeedTestMihomoInstallAndExternalConflict(t *testing.T) {
	h := NewSpeedTestHandler(nil, capabilities.NewManager())
	installed := speedtest.MihomoCoreStatus{
		Ready: true, Path: "data/bin/mihomo", Source: "managed",
		CurrentVersion: "1.19.29", TargetVersion: "1.19.29", LatestVersion: "1.19.29", Manageable: true,
	}
	calls := 0
	h.mihomoInstall = func(context.Context) (speedtest.MihomoCoreStatus, error) {
		calls++
		return installed, nil
	}
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/admin/speedtest/mihomo/install", nil))
	if recorder.Code != http.StatusOK || calls != 1 {
		t.Fatalf("install status = %d, calls = %d, body = %s", recorder.Code, calls, recorder.Body.String())
	}

	h.mihomoInstall = func(context.Context) (speedtest.MihomoCoreStatus, error) {
		return speedtest.MihomoCoreStatus{Ready: true, Source: "env"}, speedtest.ErrMihomoExternallyManaged
	}
	recorder = httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/admin/speedtest/mihomo/install", nil))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("external conflict status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestSpeedTestMihomoVersionsAndCustomVersionInstall(t *testing.T) {
	h := NewSpeedTestHandler(nil, capabilities.NewManager())
	h.mihomoStatus = func(context.Context) speedtest.MihomoCoreStatus {
		return speedtest.MihomoCoreStatus{
			Ready: true, Path: "data/bin/mihomo", Source: "managed",
			CurrentVersion: "1.19.33", TargetVersion: "1.19.33", LatestVersion: "1.19.33", Manageable: true,
		}
	}
	h.mihomoVersions = func(context.Context) ([]string, error) {
		return []string{"v1.19.33", "v1.19.32", "v1.19.31"}, nil
	}

	// Test GET /api/admin/speedtest/mihomo/versions
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/admin/speedtest/mihomo/versions", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("versions code = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var versResp struct {
		Success        bool     `json:"success"`
		CurrentVersion string   `json:"current_version"`
		Versions       []string `json:"versions"`
		Manageable     bool     `json:"manageable"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &versResp); err != nil {
		t.Fatal(err)
	}
	if !versResp.Success || !versResp.Manageable || len(versResp.Versions) != 3 || versResp.Versions[0] != "v1.19.33" {
		t.Fatalf("unexpected versions response: %#v", versResp)
	}

	// Test POST /api/admin/speedtest/mihomo/install with specific version
	requestedVersion := ""
	h.mihomoInstallVer = func(ctx context.Context, v string) (speedtest.MihomoCoreStatus, error) {
		requestedVersion = v
		return speedtest.MihomoCoreStatus{
			Ready: true, Path: "data/bin/mihomo", Source: "managed",
			CurrentVersion: v, TargetVersion: v, LatestVersion: "1.19.33", Manageable: true,
		}, nil
	}

	recorder = httptest.NewRecorder()
	reqBody := strings.NewReader(`{"version":"v1.19.32"}`)
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/admin/speedtest/mihomo/install", reqBody))
	if recorder.Code != http.StatusOK {
		t.Fatalf("install with version code = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if requestedVersion != "v1.19.32" {
		t.Fatalf("requestedVersion = %q, want v1.19.32", requestedVersion)
	}
}
