package handler

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const agentAssetDirEnv = "ARCWAY_AGENT_ASSET_DIR"

var errAgentAssetNotFound = errors.New("agent asset not found")

// GetAgentAsset serves a panel-built mmw-agent binary to an authenticated
// remote server. The architecture allow-list keeps the resulting filename
// independent from untrusted request input.
func (h *XrayServerHandler) GetAgentAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, ok := remoteBearerToken(r.Header.Get("Authorization"))
	if !ok || h == nil || h.repo == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="remote-server"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	server, err := h.repo.GetRemoteServerByToken(r.Context(), token)
	if err != nil || (server.TokenExpiresAt != nil && !server.TokenExpiresAt.After(time.Now())) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="remote-server"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	arch := strings.TrimSpace(r.URL.Query().Get("arch"))
	if arch != "amd64" && arch != "arm64" {
		http.Error(w, "Unsupported architecture", http.StatusBadRequest)
		return
	}
	name := "mmw-agent-linux-" + arch
	asset, err := openAgentAsset(name)
	if errors.Is(err, errAgentAssetNotFound) {
		http.Error(w, "Agent asset unavailable", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Agent asset unavailable", http.StatusInternalServerError)
		return
	}
	defer asset.Close()

	info, err := asset.Stat()
	if err != nil {
		http.Error(w, "Agent asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	http.ServeContent(w, r, name, info.ModTime(), asset)
}

func agentAssetDirectories() []string {
	directories := make([]string, 0, 4)
	if configured := strings.TrimSpace(os.Getenv(agentAssetDirEnv)); configured != "" {
		directories = append(directories, configured)
	}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		directories = append(directories, directory, filepath.Join(directory, "agent-assets"))
	}
	if workingDirectory, err := os.Getwd(); err == nil {
		directories = append(directories, filepath.Join(workingDirectory, "agent-assets"))
	}

	seen := make(map[string]struct{}, len(directories))
	unique := directories[:0]
	for _, directory := range directories {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			continue
		}
		absolute = filepath.Clean(absolute)
		if _, exists := seen[absolute]; exists {
			continue
		}
		seen[absolute] = struct{}{}
		unique = append(unique, absolute)
	}
	return unique
}

func openAgentAsset(name string) (*os.File, error) {
	if name != "mmw-agent-linux-amd64" && name != "mmw-agent-linux-arm64" {
		return nil, errAgentAssetNotFound
	}
	for _, directory := range agentAssetDirectories() {
		path := filepath.Join(directory, name)
		linkInfo, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect agent asset: %w", err)
		}
		if !linkInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("agent asset is not a regular file")
		}
		asset, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open agent asset: %w", err)
		}
		openedInfo, err := asset.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
			asset.Close()
			return nil, fmt.Errorf("agent asset changed while opening")
		}
		return asset, nil
	}
	return nil, errAgentAssetNotFound
}

func agentAssetSHA256(name string) (string, error) {
	asset, err := openAgentAsset(name)
	if err != nil {
		return "", err
	}
	defer asset.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, asset); err != nil {
		return "", fmt.Errorf("hash agent asset: %w", err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
