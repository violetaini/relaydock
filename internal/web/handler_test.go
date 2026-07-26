package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExternalFrontendSwitchesWithoutRecreatingHandler(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("atomic symbolic-link replacement requires Unix semantics")
	}
	SetDefaultTheme("pixel")
	t.Cleanup(func() { SetDefaultTheme("flat") })

	root := t.TempDir()
	one := filepath.Join(root, "releases", "one")
	two := filepath.Join(root, "releases", "two")
	writeTestFrontend(t, one, "one", "one-AAAAAAAA.js")
	writeTestFrontend(t, two, "two", "two-BBBBBBBB.js")

	current := filepath.Join(root, "current")
	if err := os.Symlink(one, current); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(current)

	assertResponseContains(t, handler, "/", "release=one;theme=pixel")
	assertResponseContains(t, handler, "/assets/one-AAAAAAAA.js", "asset=one")

	next := filepath.Join(root, ".current-next")
	if err := os.Symlink(two, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, current); err != nil {
		t.Fatal(err)
	}

	assertResponseContains(t, handler, "/nodes", "release=two;theme=pixel")
	assertResponseContains(t, handler, "/assets/two-BBBBBBBB.js", "asset=two")
}

func TestInvalidExternalFrontendFallsBackAndRecovers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("atomic symbolic-link replacement requires Unix semantics")
	}
	root := t.TempDir()
	broken := filepath.Join(root, "releases", "broken")
	valid := filepath.Join(root, "releases", "valid")
	if err := os.MkdirAll(filepath.Join(broken, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	brokenIndex := `<html><body>broken;theme=` + themePlaceholder + `<script src="/assets/missing.js"></script></body></html>`
	if err := os.WriteFile(filepath.Join(broken, "index.html"), []byte(brokenIndex), 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestFrontend(t, valid, "valid", "valid-AAAAAAAA.js")

	current := filepath.Join(root, "current")
	if err := os.Symlink(broken, current); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(current)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("fallback status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "broken") || strings.Contains(recorder.Body.String(), themePlaceholder) {
		t.Fatalf("invalid external index was served: %q", recorder.Body.String())
	}

	next := filepath.Join(root, ".current-next")
	if err := os.Symlink(valid, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, current); err != nil {
		t.Fatal(err)
	}
	assertResponseContains(t, handler, "/", "release=valid;theme=flat")
}

func TestExternalFrontendHeadersAndRouteIsolation(t *testing.T) {
	root := t.TempDir()
	writeTestFrontend(t, root, "headers", "app-ABm_Q5qM.js")
	handler := newHandler(root)

	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/assets/app-ABm_Q5qM.js", nil))
	if got := asset.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("asset cache control = %q", got)
	}

	unhashedPath := filepath.Join(root, "assets", "runtime.js")
	if err := os.WriteFile(unhashedPath, []byte("runtime"), 0o644); err != nil {
		t.Fatal(err)
	}
	unhashed := httptest.NewRecorder()
	handler.ServeHTTP(unhashed, httptest.NewRequest(http.MethodGet, "/assets/runtime.js", nil))
	if got := unhashed.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("unhashed asset cache control = %q", got)
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/assets/missing-AAAAAAAA.js", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing asset status = %d, want 404", missing.Code)
	}
	if strings.Contains(missing.Body.String(), "release=headers") {
		t.Fatalf("missing asset returned the SPA index: %q", missing.Body.String())
	}

	index := httptest.NewRecorder()
	indexRequest := httptest.NewRequest(http.MethodGet, "/users", nil)
	indexRequest.Header.Set("If-Modified-Since", "Wed, 21 Oct 2099 07:28:00 GMT")
	handler.ServeHTTP(index, indexRequest)
	if index.Code != http.StatusOK {
		t.Fatalf("index status with a future If-Modified-Since = %d", index.Code)
	}
	if got := index.Header().Get("Cache-Control"); got != "no-cache, must-revalidate" {
		t.Fatalf("index cache control = %q", got)
	}

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/", nil))
	if head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD response body=%d content-length=%q", head.Body.Len(), head.Header().Get("Content-Length"))
	}

	for _, route := range []string{"/api/example", "/traffic/example"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d", route, recorder.Code)
		}
	}
}

func TestDefaultThemeUpdatesExistingHandler(t *testing.T) {
	root := t.TempDir()
	writeTestFrontend(t, root, "theme", "app-AAAAAAAA.js")
	handler := newHandler(root)
	t.Cleanup(func() { SetDefaultTheme("flat") })

	SetDefaultTheme("anime")
	assertResponseContains(t, handler, "/", "release=theme;theme=anime")
	SetDefaultTheme("not-a-theme")
	assertResponseContains(t, handler, "/", "release=theme;theme=flat")
}

func TestHashedAssetDetection(t *testing.T) {
	tests := map[string]bool{
		"assets/index-ABm-Q5qM.js":  true,
		"assets/index-PKbzXf2j.css": true,
		"assets/app-1234567.js":     false,
		"assets/app-123456789.js":   false,
		"assets/runtime.js":         false,
		"assets/app-1234!678.js":    false,
	}
	for name, expected := range tests {
		if got := isHashedAsset(name); got != expected {
			t.Errorf("isHashedAsset(%q) = %v, want %v", name, got, expected)
		}
	}
}

func writeTestFrontend(t *testing.T, root, release, asset string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	index := `<html><body>release=` + release + `;theme=` + themePlaceholder + `<script src="/assets/` + asset + `"></script></body></html>`
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", asset), []byte("asset="+release), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertResponseContains(t *testing.T, handler http.Handler, target, expected string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), expected) {
		t.Fatalf("GET %s status=%d body=%q; expected %q", target, response.StatusCode, body, expected)
	}
}
