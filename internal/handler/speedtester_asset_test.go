package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSpeedtesterAssetHandlerServesCurrentInstallers(t *testing.T) {
	handler := NewSpeedtesterAssetHandler()
	for _, test := range []struct {
		path string
		want string
	}{
		{"/api/public/relaydock-speedtester/install.sh", "RELAYDOCK_MASTER_URL"},
		{"/api/public/relaydock-speedtester/install.ps1", "RelayDock Speedtester"},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d", test.path, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), test.want) {
			t.Fatalf("%s missing %q", test.path, test.want)
		}
	}
}

func TestSpeedtesterAssetHandlerRejectsUnsupportedPlatform(t *testing.T) {
	recorder := httptest.NewRecorder()
	NewSpeedtesterAssetHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/api/public/relaydock-speedtester/binary?os=plan9&arch=amd64", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}
