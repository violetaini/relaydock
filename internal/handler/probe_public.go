package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// ProbePublicHandler provides a read-only public status feed which can be
// presented as a neutral monitoring page.  Public data is constructed from an
// explicit DTO below; remote-server structs must never be encoded directly.
type ProbePublicHandler struct {
	repo       *storage.TrafficRepository
	wsHandler  *RemoteWSHandler
	probeStore *ProbeMetricsStore
	cacheMu    sync.Mutex
	cache      map[string]any
	cacheUntil time.Time
}

// A public probe normally uses its shared WebSocket broadcast. This small
// server-side cache only protects the unauthenticated HTTP fallback from
// repeatedly scanning SQLite during a direct request burst; it is far shorter
// than the browser's five-second fallback interval.
const probePublicCacheTTL = 250 * time.Millisecond

// NewProbePublicHandler keeps the former two-argument call form working while
// allowing the server to inject the live metrics store.  The store is optional
// so existing deployments continue serving the first-generation payload until
// their Agent starts reporting system metrics.
func NewProbePublicHandler(repo *storage.TrafficRepository, ws *RemoteWSHandler, stores ...*ProbeMetricsStore) *ProbePublicHandler {
	h := &ProbePublicHandler{repo: repo, wsHandler: ws}
	if len(stores) > 0 {
		h.probeStore = stores[0]
	}
	return h
}

// probeServer is the complete public allowlist.  Keep IDs, addresses, tokens,
// domains, inbound configuration, timestamps and reset policy out of this
// type.  Optional fields disappear when their display setting is disabled or
// when the Agent has not reported a fresh value.
type probeServer struct {
	Name          string `json:"name,omitempty"`
	CountryCode   string `json:"country_code,omitempty"`
	UploadSpeed   *int64 `json:"upload_speed,omitempty"`
	DownloadSpeed *int64 `json:"download_speed,omitempty"`
	TrafficUsed   *int64 `json:"traffic_used,omitempty"`
	TrafficLimit  *int64 `json:"traffic_limit,omitempty"`
	Online        bool   `json:"online"`

	CPUPct    *float64 `json:"cpu_pct,omitempty"`
	LoadAvg   string   `json:"loadavg,omitempty"`
	MemUsed   *int64   `json:"mem_used,omitempty"`
	MemTotal  *int64   `json:"mem_total,omitempty"`
	DiskUsed  *int64   `json:"disk_used,omitempty"`
	DiskTotal *int64   `json:"disk_total,omitempty"`
}

// ServeHTTP handles GET /api/public/probe-servers.  It intentionally returns
// {enabled:false} instead of an authorization error when the disguise is off,
// preserving the original endpoint contract and not revealing configuration.
func (h *ProbePublicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	payload, err := h.buildPayload(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"enabled": false})
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// buildPayload is deliberately shared by the HTTP fallback and public WS
// broadcast path, so browser transport changes cannot change what is exposed.
func (h *ProbePublicHandler) buildPayload(ctx context.Context) (map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if h == nil || h.repo == nil {
		return map[string]any{"enabled": false}, nil
	}

	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	now := time.Now()
	if h.cache != nil && now.Before(h.cacheUntil) {
		return h.cache, nil
	}
	if h.probeStore != nil {
		h.probeStore.PruneExpired(now)
	}
	payload, err := h.buildPayloadUncached(ctx)
	if err != nil {
		return nil, err
	}
	h.cache = payload
	h.cacheUntil = now.Add(probePublicCacheTTL)
	return payload, nil
}

func (h *ProbePublicHandler) buildPayloadUncached(ctx context.Context) (map[string]any, error) {
	if v, _ := h.repo.GetSystemSetting(ctx, probeDisguiseEnabledKey); v != "1" {
		return map[string]any{"enabled": false}, nil
	}

	title, _ := h.repo.GetSystemSetting(ctx, probeDisguiseTitleKey)
	logo, _ := h.repo.GetSystemSetting(ctx, probeDisguiseLogoKey)
	blockLogin, _ := h.repo.GetSystemSetting(ctx, probeDisguiseBlockLoginKey)
	showName := h.setting(ctx, probeDisguiseShowNameKey)
	showCPU := h.settingEnabledByDefault(ctx, probeDisguiseMetricCPUKey)
	showMemory := h.settingEnabledByDefault(ctx, probeDisguiseMetricMemKey)
	showDisk := h.settingEnabledByDefault(ctx, probeDisguiseMetricDiskKey)
	// Speed/traffic were always displayed by the old probe endpoint.  Treat an
	// unset value as enabled, so upgrading does not make existing pages sparse.
	trafficRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricTrafficKey)
	speedRaw, _ := h.repo.GetSystemSetting(ctx, probeDisguiseMetricSpeedKey)
	showTraffic := trafficRaw != "0"
	showSpeed := speedRaw != "0"

	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, err
	}
	selected, selectionConfigured := probeDisguiseServerSelection(ctx, h.repo)
	if !selectionConfigured {
		for _, server := range servers {
			selected[server.ID] = struct{}{}
		}
	}
	out := make([]probeServer, 0, len(selected))
	for i := range servers {
		server := &servers[i]
		if _, ok := selected[server.ID]; !ok {
			continue
		}

		probe := probeServer{
			Online: (h.wsHandler != nil && h.wsHandler.IsConnected(server.Token)) || server.Status == storage.RemoteServerStatusConnected,
		}
		// Country code is safe to expose while addresses are not. The resolver
		// only returns a cached two-letter value and queues any slow lookup.
		probe.CountryCode = cachedOrQueueGeoIPCountryCode(server.IPAddress)
		if probe.CountryCode == "" && server.IPv6Enabled {
			probe.CountryCode = cachedOrQueueGeoIPCountryCode(server.IPAddressV6)
		}
		if showName {
			probe.Name = server.Name
		}
		if showSpeed {
			up, down := server.CurrentUploadSpeed, server.CurrentDownloadSpeed
			probe.UploadSpeed, probe.DownloadSpeed = &up, &down
		}
		if showTraffic {
			used, err := h.repo.GetServerTrafficUsed(ctx, server.ID)
			if err == nil {
				used += server.TrafficUsedOffset
				total := server.TrafficLimit
				probe.TrafficUsed, probe.TrafficLimit = &used, &total
			}
		}
		// System metrics are meaningful only while the server is currently
		// online. A short-lived local cache is useful across report intervals,
		// but must not make an offline card look healthy after its Agent drops.
		if probe.Online && h.probeStore != nil {
			if snapshot, ok := h.probeStore.Snapshot(server.ID); ok {
				fillProbeSystemMetrics(&probe, snapshot, showCPU, showMemory, showDisk)
			}
		}
		out = append(out, probe)
	}

	return map[string]any{
		"enabled":      true,
		"title":        title,
		"logo":         logo,
		"block_login":  blockLogin == "1",
		"show_name":    showName,
		"show_cpu":     showCPU,
		"show_memory":  showMemory,
		"show_disk":    showDisk,
		"show_traffic": showTraffic,
		"show_speed":   showSpeed,
		// Ping/series remain absent until the Agent has a bounded probe
		// collector. Explicit false lets the frontend avoid feature guessing.
		"show_ping": false,
		"servers":   out,
	}, nil
}

func (h *ProbePublicHandler) setting(ctx context.Context, key string) bool {
	v, _ := h.repo.GetSystemSetting(ctx, key)
	return v == "1"
}

func (h *ProbePublicHandler) settingEnabledByDefault(ctx context.Context, key string) bool {
	v, _ := h.repo.GetSystemSetting(ctx, key)
	return v != "0"
}

func fillProbeSystemMetrics(dst *probeServer, snapshot ProbeSysSnapshot, showCPU, showMemory, showDisk bool) {
	if showCPU && snapshot.HasCPU {
		value := snapshot.CPUPct
		dst.CPUPct = &value
		dst.LoadAvg = snapshot.LoadAvg
	}
	if showMemory && snapshot.HasMem {
		used, total := snapshot.MemUsed, snapshot.MemTotal
		dst.MemUsed, dst.MemTotal = &used, &total
	}
	if showDisk && snapshot.HasDisk {
		used, total := snapshot.DiskUsed, snapshot.DiskTotal
		dst.DiskUsed, dst.DiskTotal = &used, &total
	}
}
