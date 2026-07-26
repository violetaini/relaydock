package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func installAgentAssetFixtures(t *testing.T) {
	t.Helper()
	assetDirectory := t.TempDir()
	for _, name := range []string{"mmw-agent-linux-amd64", "mmw-agent-linux-arm64"} {
		if err := os.WriteFile(filepath.Join(assetDirectory, name), []byte("\x7fELF-test-"+name), 0755); err != nil {
			t.Fatalf("write Agent fixture: %v", err)
		}
	}
	t.Setenv(agentAssetDirEnv, assetDirectory)
}

func requestAgentAsset(handler *XrayServerHandler, method, arch, authorization string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/api/remote/mmw-agent?arch="+arch, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.GetAgentAsset(response, request)
	return response
}

func TestAgentAssetRequiresRemoteBearerToken(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)

	for _, authorization := range []string{"", "Bearer invalid-token", token, "Basic " + token} {
		response := requestAgentAsset(handler, http.MethodGet, "amd64", authorization)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q status=%d want=%d", authorization, response.Code, http.StatusUnauthorized)
		}
		if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("security headers missing: %#v", response.Header())
		}
	}
}

func TestAgentAssetRejectsUnsupportedMethod(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)
	response := requestAgentAsset(handler, http.MethodPost, "amd64", "Bearer "+token)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want=%d", response.Code, http.StatusMethodNotAllowed)
	}
	if got := response.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow=%q want=%q", got, http.MethodGet)
	}
}

func TestAgentAssetValidatesArchitectureAndMissingAsset(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)
	t.Setenv(agentAssetDirEnv, t.TempDir())

	invalid := requestAgentAsset(handler, http.MethodGet, "386", "Bearer "+token)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid architecture status=%d want=%d", invalid.Code, http.StatusBadRequest)
	}

	missing := requestAgentAsset(handler, http.MethodGet, "arm64", "Bearer "+token)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing asset status=%d want=%d body=%s", missing.Code, http.StatusNotFound, missing.Body.String())
	}
}

func TestAgentAssetServesConfiguredBinary(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)
	directory := t.TempDir()
	t.Setenv(agentAssetDirEnv, directory)
	const content = "agent-binary-content"
	name := "mmw-agent-linux-amd64"
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	response := requestAgentAsset(handler, http.MethodGet, "amd64", "bearer "+token)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if response.Body.String() != content {
		t.Fatalf("body=%q want=%q", response.Body.String(), content)
	}
	if got := response.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := response.Header().Get("Content-Disposition"); got != `attachment; filename="`+name+`"` {
		t.Fatalf("Content-Disposition=%q", got)
	}
}

func TestAgentAssetRejectsNonRegularAsset(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)
	directory := t.TempDir()
	t.Setenv(agentAssetDirEnv, directory)
	name := "mmw-agent-linux-amd64"
	if err := os.Symlink(filepath.Join(directory, "does-not-matter"), filepath.Join(directory, name)); err != nil {
		t.Fatal(err)
	}

	response := requestAgentAsset(handler, http.MethodGet, "amd64", "Bearer "+token)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("symlink status=%d want=%d", response.Code, http.StatusInternalServerError)
	}
}

func TestRemoteInstallScriptFailsClosedWithoutAgentAssets(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	t.Setenv(agentAssetDirEnv, t.TempDir())
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
	if got := response.Body.String(); got != "Agent release asset is unavailable\n" {
		t.Fatalf("body=%q", got)
	}
}
