package web

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

//go:embed dist/*
var embeddedFiles embed.FS

// themePlaceholder is replaced when index.html is served so the first paint
// uses the configured default theme before React starts.
const themePlaceholder = "__RELAYDOCK_DEFAULT_THEME__"

type webSource struct {
	files      fs.FS
	fileServer http.Handler
	index      []byte
}

type frontendHandler struct {
	embedded     *webSource
	externalRoot string

	sourceMu       sync.Mutex
	externalKey    string
	externalSource *webSource
}

var (
	embeddedOnce   sync.Once
	embeddedSource *webSource

	themeMu      sync.RWMutex
	currentTheme = "flat"
)

// SetDefaultTheme updates the theme injected into every subsequently served
// index. The index itself is intentionally not cached so disk releases become
// visible without restarting the control plane.
func SetDefaultTheme(theme string) {
	if theme != "flat" && theme != "pixel" && theme != "anime" {
		theme = "flat"
	}
	themeMu.Lock()
	currentTheme = theme
	themeMu.Unlock()
}

func initializeEmbedded() {
	sub, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		panic(err)
	}
	source, err := loadWebSource(sub)
	if err != nil {
		panic(fmt.Sprintf("invalid embedded frontend: %v", err))
	}
	embeddedSource = source
}

// Handler serves ARCWAY_WEB_ROOT when it points to a complete frontend
// release. Missing or invalid disk releases transparently fall back to the
// frontend embedded in the binary.
func Handler() http.Handler {
	return newHandler(os.Getenv("ARCWAY_WEB_ROOT"))
}

func newHandler(externalRoot string) http.Handler {
	embeddedOnce.Do(initializeEmbedded)
	return &frontendHandler{
		embedded:     embeddedSource,
		externalRoot: strings.TrimSpace(externalRoot),
	}
}

func (h *frontendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/traffic/") {
		http.NotFound(w, r)
		return
	}

	cleaned := path.Clean(r.URL.Path)
	if cleaned == "." {
		cleaned = "/"
	}

	source := h.activeSource()
	if cleaned == "/" {
		serveIndex(w, r, source.index)
		return
	}

	resource := strings.TrimPrefix(cleaned, "/")
	if resource == "" {
		serveIndex(w, r, source.index)
		return
	}

	if fileExists(source.files, resource) {
		if strings.HasPrefix(resource, "assets/") && isHashedAsset(resource) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		source.fileServer.ServeHTTP(w, r)
		return
	}
	if resource == "assets" || strings.HasPrefix(resource, "assets/") {
		http.NotFound(w, r)
		return
	}

	serveIndex(w, r, source.index)
}

func (h *frontendHandler) activeSource() *webSource {
	if h.externalRoot == "" {
		return h.embedded
	}

	resolved, err := filepath.EvalSymlinks(h.externalRoot)
	if err != nil {
		return h.embedded
	}
	info, err := os.Stat(filepath.Join(resolved, "index.html"))
	if err != nil || info.IsDir() {
		return h.embedded
	}
	key := fmt.Sprintf("%s:%d:%d", resolved, info.ModTime().UnixNano(), info.Size())

	h.sourceMu.Lock()
	defer h.sourceMu.Unlock()
	if key == h.externalKey {
		if h.externalSource != nil {
			return h.externalSource
		}
		return h.embedded
	}

	source, err := loadWebSource(os.DirFS(resolved))
	if err != nil {
		// Releases are immutable. Remember a rejected release so a malformed
		// index is not reparsed on every request; changing the current symlink
		// produces a new key and retries validation.
		h.externalKey = key
		h.externalSource = nil
		return h.embedded
	}
	h.externalKey = key
	h.externalSource = source
	return source
}

func loadWebSource(files fs.FS) (*webSource, error) {
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read index.html: %w", err)
	}
	if len(bytes.TrimSpace(index)) == 0 {
		return nil, fmt.Errorf("index.html is empty")
	}
	if !bytes.Contains(index, []byte(themePlaceholder)) {
		return nil, fmt.Errorf("index.html does not contain the theme placeholder")
	}

	assets, err := referencedAssets(index)
	if err != nil {
		return nil, fmt.Errorf("parse index.html: %w", err)
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("index.html does not reference local assets")
	}
	for _, asset := range assets {
		info, err := fs.Stat(files, asset)
		if err != nil {
			return nil, fmt.Errorf("referenced asset %q is unavailable: %w", asset, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("referenced asset %q is a directory", asset)
		}
	}

	return &webSource{
		files:      files,
		fileServer: http.FileServer(http.FS(files)),
		index:      index,
	}, nil
}

func referencedAssets(index []byte) ([]string, error) {
	document, err := html.Parse(bytes.NewReader(index))
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var assets []string
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode {
			for _, attr := range node.Attr {
				if attr.Key != "src" && attr.Key != "href" {
					continue
				}
				parsed, err := url.Parse(attr.Val)
				if err != nil || parsed.Host != "" || parsed.Path == "" {
					continue
				}
				asset := strings.TrimPrefix(path.Clean("/"+parsed.Path), "/")
				if !strings.HasPrefix(asset, "assets/") {
					continue
				}
				if _, exists := seen[asset]; exists {
					continue
				}
				seen[asset] = struct{}{}
				assets = append(assets, asset)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document)
	return assets, nil
}

func serveIndex(w http.ResponseWriter, r *http.Request, rawIndex []byte) {
	themeMu.RLock()
	theme := currentTheme
	themeMu.RUnlock()
	content := bytes.ReplaceAll(rawIndex, []byte(themePlaceholder), []byte(theme))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(content)
}

func fileExists(files fs.FS, name string) bool {
	info, err := fs.Stat(files, name)
	return err == nil && !info.IsDir()
}

func isHashedAsset(name string) bool {
	base := path.Base(name)
	extension := path.Ext(base)
	stem := strings.TrimSuffix(base, extension)
	if len(stem) < 9 || stem[len(stem)-9] != '-' {
		return false
	}
	for _, char := range stem[len(stem)-8:] {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}
