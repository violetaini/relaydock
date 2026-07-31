package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	xrayCoreReleasesURL       = "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=50"
	xrayCoreVersionsCacheTTL  = 15 * time.Minute
	xrayCoreVersionsTimeout   = 10 * time.Second
	xrayCoreVersionsMaxBody   = 2 << 20
	xrayCoreVersionsMaxItems  = 30
	xrayInstallRequestMaxBody = 1024
)

var xrayCoreVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// XrayCoreVersion is a selectable release published by the official
// XTLS/Xray-core repository.
type XrayCoreVersion struct {
	Version     string `json:"version"`
	Name        string `json:"name"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at,omitempty"`
}

type githubXrayCoreRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at"`
}

func cloneXrayCoreVersions(in []XrayCoreVersion) []XrayCoreVersion {
	if len(in) == 0 {
		return nil
	}
	out := make([]XrayCoreVersion, len(in))
	copy(out, in)
	return out
}

// fetchXrayCoreVersions coalesces concurrent cache misses. A failed refresh
// keeps serving the last successful list so a temporary GitHub outage does not
// remove already-reviewed choices from the panel.
func (h *RemoteManageHandler) fetchXrayCoreVersions(ctx context.Context) ([]XrayCoreVersion, string) {
	h.xrayVersionsMu.Lock()
	cached := cloneXrayCoreVersions(h.xrayVersions)
	if len(cached) > 0 && time.Since(h.xrayVersionsAt) <= xrayCoreVersionsCacheTTL {
		h.xrayVersionsMu.Unlock()
		return cached, ""
	}
	if h.xrayVersionsFetch != nil {
		done := h.xrayVersionsFetch
		h.xrayVersionsMu.Unlock()
		select {
		case <-done:
			h.xrayVersionsMu.Lock()
			versions := cloneXrayCoreVersions(h.xrayVersions)
			fetchErr := h.xrayVersionsErr
			h.xrayVersionsMu.Unlock()
			return versions, fetchErr
		case <-ctx.Done():
			return cached, ctx.Err().Error()
		}
	}
	h.xrayVersionsFetch = make(chan struct{})
	done := h.xrayVersionsFetch
	h.xrayVersionsMu.Unlock()

	versions, fetchErr := h.fetchOfficialXrayCoreVersions(ctx)

	h.xrayVersionsMu.Lock()
	if fetchErr == "" {
		h.xrayVersions = cloneXrayCoreVersions(versions)
		h.xrayVersionsAt = time.Now()
		h.xrayVersionsErr = ""
	} else {
		h.xrayVersionsErr = fetchErr
	}
	result := cloneXrayCoreVersions(h.xrayVersions)
	resultErr := h.xrayVersionsErr
	h.xrayVersionsFetch = nil
	close(done)
	h.xrayVersionsMu.Unlock()
	return result, resultErr
}

func (h *RemoteManageHandler) fetchOfficialXrayCoreVersions(parent context.Context) ([]XrayCoreVersion, string) {
	ctx, cancel := context.WithTimeout(parent, xrayCoreVersionsTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, xrayCoreReleasesURL, nil)
	if err != nil {
		return nil, err.Error()
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := h.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "github status " + strconv.Itoa(resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, xrayCoreVersionsMaxBody+1))
	if err != nil {
		return nil, err.Error()
	}
	if len(raw) > xrayCoreVersionsMaxBody {
		return nil, "github response exceeds size limit"
	}
	var releases []githubXrayCoreRelease
	if err := json.Unmarshal(raw, &releases); err != nil {
		return nil, "parse github releases: " + err.Error()
	}

	versions := make([]XrayCoreVersion, 0, xrayCoreVersionsMaxItems)
	seen := make(map[string]struct{}, xrayCoreVersionsMaxItems)
	for _, release := range releases {
		version := strings.TrimSpace(release.TagName)
		if release.Draft || !xrayCoreVersionPattern.MatchString(version) {
			continue
		}
		if _, duplicate := seen[version]; duplicate {
			continue
		}
		seen[version] = struct{}{}
		name := strings.TrimSpace(release.Name)
		if name == "" {
			name = version
		}
		versions = append(versions, XrayCoreVersion{
			Version:     version,
			Name:        name,
			Prerelease:  release.Prerelease,
			PublishedAt: strings.TrimSpace(release.PublishedAt),
		})
		if len(versions) == xrayCoreVersionsMaxItems {
			break
		}
	}
	if len(versions) == 0 {
		return nil, "github returned no valid Xray releases"
	}
	return versions, ""
}

func xrayCoreVersionSummary(versions []XrayCoreVersion) (latest, latestStable string) {
	if len(versions) > 0 {
		latest = versions[0].Version
	}
	for _, release := range versions {
		if !release.Prerelease {
			return latest, release.Version
		}
	}
	return latest, ""
}

// xrayVersionSelectionSupported uses the active WS handshake as the source of
// truth. Only when no WS connection exists does it fall back to system/info.
func (h *RemoteManageHandler) xrayVersionSelectionSupported(parent context.Context, serverID int64) (bool, string) {
	if h.wsHandler != nil {
		if conn, ok := h.wsHandler.GetConnectionByServerID(serverID); ok {
			return conn.Capabilities.XrayVersionSelectV1, ""
		}
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	body, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/system/info", nil)
	if err != nil {
		return false, err.Error()
	}
	var info struct {
		Capabilities AgentCapabilities `json:"capabilities"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return false, "parse Agent capabilities: " + err.Error()
	}
	return info.Capabilities.XrayVersionSelectV1, ""
}

func (h *RemoteManageHandler) HandleXrayVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("server_id"), 10, 64)
	if err != nil || id <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}
	if !h.requireExternalManagedXray(r.Context(), w, id) {
		return
	}
	supported, capabilityErr := h.xrayVersionSelectionSupported(r.Context(), id)
	if !supported {
		message := "当前 Agent 不支持指定 Xray 版本，请先升级 Agent"
		if capabilityErr != "" {
			message = "无法确认 Agent 的 Xray 版本选择能力: " + capabilityErr
		}
		remoteWriteJSON(w, http.StatusOK, map[string]any{
			"success":                     true,
			"versions":                    []XrayCoreVersion{},
			"version_selection_supported": false,
			"support_error":               message,
		})
		return
	}

	versions, versionsErr := h.fetchXrayCoreVersions(r.Context())
	if len(versions) == 0 {
		remoteWriteError(w, http.StatusBadGateway, "unable to load official Xray versions: "+versionsErr)
		return
	}
	latest, latestStable := xrayCoreVersionSummary(versions)
	response := map[string]any{
		"success":                     true,
		"versions":                    versions,
		"latest":                      latest,
		"latest_stable":               latestStable,
		"version_selection_supported": supported,
	}
	if versionsErr != "" {
		response["versions_error"] = versionsErr
		response["stale"] = true
		response["warning"] = "GitHub 暂时不可达，正在使用最近一次成功同步的官方版本列表。"
	}
	remoteWriteJSON(w, http.StatusOK, response)
}

func normalizeRequestedXrayVersion(raw string) (string, error) {
	version := strings.TrimSpace(raw)
	if strings.HasPrefix(version, "V") {
		version = "v" + strings.TrimPrefix(version, "V")
	} else if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !xrayCoreVersionPattern.MatchString(version) {
		return "", errors.New("version must match vN.N.N")
	}
	return version, nil
}

func decodeXrayInstallVersion(r *http.Request) (string, bool, error) {
	if r.Body == nil {
		return "", false, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, xrayInstallRequestMaxBody+1))
	if err != nil {
		return "", false, fmt.Errorf("read request body: %w", err)
	}
	if len(raw) > xrayInstallRequestMaxBody {
		return "", false, errors.New("request body too large")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", false, nil
	}
	var request struct {
		Version string `json:"version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return "", true, fmt.Errorf("invalid request body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", true, errors.New("invalid request body: multiple JSON values")
		}
		return "", true, fmt.Errorf("invalid request body: %w", err)
	}
	version, err := normalizeRequestedXrayVersion(request.Version)
	if err != nil {
		return "", true, err
	}
	return version, true, nil
}

func (h *RemoteManageHandler) prepareXrayInstallPayload(ctx context.Context, serverID int64, r *http.Request) ([]byte, string, int, error) {
	version, specified, err := decodeXrayInstallVersion(r)
	if err != nil {
		return nil, "", http.StatusBadRequest, err
	}
	if !specified {
		return nil, "", 0, nil
	}
	supported, capabilityErr := h.xrayVersionSelectionSupported(ctx, serverID)
	if !supported {
		message := "目标 Agent 不支持选择 Xray 版本，请先升级 Agent"
		if capabilityErr != "" {
			message += ": " + capabilityErr
		}
		return nil, "", http.StatusConflict, errors.New(message)
	}
	versions, versionsErr := h.fetchXrayCoreVersions(ctx)
	if len(versions) == 0 {
		return nil, "", http.StatusBadGateway, fmt.Errorf("unable to load official Xray versions: %s", versionsErr)
	}
	allowed := false
	for _, candidate := range versions {
		if candidate.Version == version {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, "", http.StatusBadRequest, fmt.Errorf("Xray version %s is not in the official release list", version)
	}
	payload, err := json.Marshal(map[string]string{"version": version})
	if err != nil {
		return nil, "", http.StatusInternalServerError, err
	}
	return payload, version, 0, nil
}

func reportedXrayVersionMatches(reported, target string) bool {
	target, err := normalizeRequestedXrayVersion(target)
	if err != nil {
		return false
	}
	// Agent status historically returns either "26.7.28", "v26.7.28", or
	// the first line of `xray version` (for example "Xray 26.7.28 ...").
	fields := strings.FieldsFunc(reported, func(r rune) bool {
		return !(r >= '0' && r <= '9') && r != '.' && r != 'v' && r != 'V'
	})
	for _, field := range fields {
		candidate, candidateErr := normalizeRequestedXrayVersion(field)
		if candidateErr == nil && candidate == target {
			return true
		}
	}
	return false
}
