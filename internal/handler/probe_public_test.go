package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/violetaini/relaydock/internal/storage"
)

func newProbePublicRepository(t *testing.T) (*storage.TrafficRepository, *storage.RemoteServer) {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "probe-public.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	server := &storage.RemoteServer{
		Name:              "public-edge",
		Token:             "probe-private-token",
		Status:            storage.RemoteServerStatusConnected,
		IPAddress:         "198.51.100.93",
		IPAddressV6:       "2001:db8:1234::93",
		Domain:            "private.example.test",
		PullAddress:       "private-pull.example.test",
		PullToken:         "probe-private-pull-token",
		AgentToken:        "probe-private-agent-token",
		TrafficLimit:      2 << 30,
		TrafficUsedOffset: 4096,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if err := repo.UpdateRemoteServerSpeed(context.Background(), server.ID, 1234, 5678); err != nil {
		t.Fatalf("UpdateRemoteServerSpeed: %v", err)
	}
	return repo, server
}

func setProbePublicSetting(t *testing.T, repo *storage.TrafficRepository, key, value string) {
	t.Helper()
	if err := repo.SetSystemSetting(context.Background(), key, value); err != nil {
		t.Fatalf("SetSystemSetting(%q): %v", key, err)
	}
}

func enableProbeForServer(t *testing.T, repo *storage.TrafficRepository, serverID int64) {
	t.Helper()
	setProbePublicSetting(t, repo, probeDisguiseEnabledKey, "1")
	setProbePublicSetting(t, repo, probeDisguiseTitleKey, "Status Monitor")
	setProbePublicSetting(t, repo, probeDisguiseServerIDsKey, "["+strconv.FormatInt(serverID, 10)+"]")
	setProbePublicSetting(t, repo, probeDisguiseShowNameKey, "1")
	setProbePublicSetting(t, repo, probeDisguiseMetricCPUKey, "1")
	setProbePublicSetting(t, repo, probeDisguiseMetricMemKey, "1")
	setProbePublicSetting(t, repo, probeDisguiseMetricDiskKey, "1")
	setProbePublicSetting(t, repo, probeDisguiseMetricTrafficKey, "1")
	setProbePublicSetting(t, repo, probeDisguiseMetricSpeedKey, "1")
}

func decodeProbePayload(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}

func TestProbePublicPayloadUsesAllowlistAndLiveMetrics(t *testing.T) {
	repo, server := newProbePublicRepository(t)
	enableProbeForServer(t, repo, server.ID)

	metrics := NewProbeMetricsStore()
	if ok := metrics.IngestSys(server.ID, ProbeSysWire{
		CPUPct:  17.5,
		LoadAvg: "0.12 0.08 0.03",
		HasCPU:  true,
		MemUsed: 3 << 30, MemTotal: 8 << 30, HasMem: true,
		DiskUsed: 40 << 30, DiskTotal: 100 << 30, HasDisk: true,
	}); !ok {
		t.Fatal("IngestSys returned false for a valid report")
	}

	handler := NewProbePublicHandler(repo, nil, metrics)
	request := httptest.NewRequest(http.MethodGet, "/api/public/probe-servers", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if cacheControl := response.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") {
		t.Fatalf("Cache-Control=%q, want no-store", cacheControl)
	}
	payload := decodeProbePayload(t, response)
	if payload["enabled"] != true {
		t.Fatalf("enabled=%#v, want true", payload["enabled"])
	}
	if payload["title"] != "Status Monitor" {
		t.Fatalf("title=%#v", payload["title"])
	}

	servers, ok := payload["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("servers=%#v, want one selected server", payload["servers"])
	}
	probe, ok := servers[0].(map[string]any)
	if !ok {
		t.Fatalf("server payload=%T, want object", servers[0])
	}
	wantKeys := map[string]bool{
		"name": true, "online": true, "upload_speed": true, "download_speed": true,
		"traffic_used": true, "traffic_limit": true,
		"cpu_pct": true, "loadavg": true,
		"mem_used": true, "mem_total": true, "disk_used": true, "disk_total": true,
	}
	for key := range probe {
		if !wantKeys[key] {
			t.Fatalf("public probe returned non-allowlisted key %q: %#v", key, probe)
		}
	}
	for _, key := range []string{"cpu_pct", "loadavg", "mem_used", "mem_total", "disk_used", "disk_total"} {
		if _, ok := probe[key]; !ok {
			t.Fatalf("public probe omitted live metric %q: %#v", key, probe)
		}
	}
	if probe["cpu_pct"] != 17.5 || probe["loadavg"] != "0.12 0.08 0.03" {
		t.Fatalf("cpu payload=%#v", probe)
	}
	if probe["online"] != true || probe["upload_speed"] != float64(1234) || probe["download_speed"] != float64(5678) {
		t.Fatalf("live status payload=%#v", probe)
	}

	body := response.Body.String()
	for _, sensitive := range []string{
		server.Token, server.IPAddress, server.IPAddressV6, server.Domain,
		server.PullAddress, server.PullToken, server.AgentToken,
	} {
		if strings.Contains(body, sensitive) {
			t.Fatalf("public payload leaked sensitive server value %q: %s", sensitive, body)
		}
	}
}

func TestProbePublicPayloadHidesDisabledMetricFamiliesAndWorksWithoutStore(t *testing.T) {
	repo, server := newProbePublicRepository(t)
	enableProbeForServer(t, repo, server.ID)
	setProbePublicSetting(t, repo, probeDisguiseShowNameKey, "")
	setProbePublicSetting(t, repo, probeDisguiseMetricCPUKey, "0")
	setProbePublicSetting(t, repo, probeDisguiseMetricMemKey, "0")
	setProbePublicSetting(t, repo, probeDisguiseMetricDiskKey, "0")
	setProbePublicSetting(t, repo, probeDisguiseMetricTrafficKey, "0")
	setProbePublicSetting(t, repo, probeDisguiseMetricSpeedKey, "0")

	// The constructor's two-argument form is used by older call sites and must
	// still serve a safe payload while system metrics have not been injected.
	handler := NewProbePublicHandler(repo, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/public/probe-servers", nil))
	payload := decodeProbePayload(t, response)
	servers := payload["servers"].([]any)
	probe := servers[0].(map[string]any)
	if len(probe) != 1 || probe["online"] != true {
		t.Fatalf("hidden metrics payload=%#v, want only online", probe)
	}
	for _, configKey := range []string{"show_cpu", "show_memory", "show_disk", "show_traffic", "show_speed"} {
		if payload[configKey] != false {
			t.Fatalf("%s=%#v, want false", configKey, payload[configKey])
		}
	}
}

func TestProbePublicPayloadHidesCachedSystemMetricsWhenServerIsOffline(t *testing.T) {
	repo, server := newProbePublicRepository(t)
	enableProbeForServer(t, repo, server.ID)
	metrics := NewProbeMetricsStore()
	if ok := metrics.IngestSys(server.ID, ProbeSysWire{
		CPUPct:  9.5,
		HasCPU:  true,
		MemUsed: 2 << 30, MemTotal: 8 << 30, HasMem: true,
		DiskUsed: 30 << 30, DiskTotal: 100 << 30, HasDisk: true,
	}); !ok {
		t.Fatal("IngestSys returned false for a valid report")
	}
	if _, _, _, err := repo.MarkRemoteServerOfflineByID(context.Background(), server.ID); err != nil {
		t.Fatalf("MarkRemoteServerOfflineByID: %v", err)
	}

	response := httptest.NewRecorder()
	NewProbePublicHandler(repo, nil, metrics).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/public/probe-servers", nil))
	probe := decodeProbePayload(t, response)["servers"].([]any)[0].(map[string]any)
	if probe["online"] != false {
		t.Fatalf("online=%#v, want false", probe["online"])
	}
	for _, key := range []string{"cpu_pct", "loadavg", "mem_used", "mem_total", "disk_used", "disk_total"} {
		if _, ok := probe[key]; ok {
			t.Fatalf("offline payload retained cached %s: %#v", key, probe)
		}
	}
}

func TestProbeMetricsStorePrunesExpiredSnapshots(t *testing.T) {
	metrics := NewProbeMetricsStore()
	metrics.data[11] = ProbeSysSnapshot{At: time.Now().Add(-probeMetricsMaxAge - time.Second), HasCPU: true}
	metrics.data[12] = ProbeSysSnapshot{At: time.Now(), HasCPU: true}
	metrics.PruneExpired(time.Now())
	if _, ok := metrics.data[11]; ok {
		t.Fatal("expired snapshot was retained")
	}
	if _, ok := metrics.data[12]; !ok {
		t.Fatal("fresh snapshot was removed")
	}
}

func TestProbeConfigUpdatesReflectSelectionAndMetricSwitches(t *testing.T) {
	repo, server := newProbePublicRepository(t)

	zeroes := map[string]string{
		"probe_collect_cpu": "0", "probe_collect_mem": "0", "probe_collect_disk": "0",
	}
	if got := ProbeConfigUpdates(context.Background(), repo, server.ID); !mapsEqual(got, zeroes) {
		t.Fatalf("disabled config=%#v want=%#v", got, zeroes)
	}

	enableProbeForServer(t, repo, server.ID)
	setProbePublicSetting(t, repo, probeDisguiseMetricCPUKey, "")
	setProbePublicSetting(t, repo, probeDisguiseMetricMemKey, "")
	setProbePublicSetting(t, repo, probeDisguiseMetricDiskKey, "")
	want := map[string]string{
		"probe_collect_cpu": "1", "probe_collect_mem": "1", "probe_collect_disk": "1",
	}
	if got := ProbeConfigUpdates(context.Background(), repo, server.ID); !mapsEqual(got, want) {
		t.Fatalf("default collection config=%#v want=%#v", got, want)
	}

	setProbePublicSetting(t, repo, probeDisguiseMetricMemKey, "0")
	want = map[string]string{
		"probe_collect_cpu": "1", "probe_collect_mem": "0", "probe_collect_disk": "1",
	}
	if got := ProbeConfigUpdates(context.Background(), repo, server.ID); !mapsEqual(got, want) {
		t.Fatalf("selected config=%#v want=%#v", got, want)
	}
	if got := ProbeConfigUpdates(context.Background(), repo, server.ID+999); !mapsEqual(got, zeroes) {
		t.Fatalf("unselected config=%#v want=%#v", got, zeroes)
	}
	if got := ProbeConfigUpdates(context.Background(), nil, server.ID); !mapsEqual(got, zeroes) {
		t.Fatalf("nil repo config=%#v want=%#v", got, zeroes)
	}
}

func TestProbeDisguiseRejectsInvalidLogoBeforeSavingOtherSettings(t *testing.T) {
	repo, server := newProbePublicRepository(t)
	handler := NewSystemSettingsHandler(repo, nil)
	request := httptest.NewRequest(http.MethodPut, "/api/admin/system-settings/probe-disguise", strings.NewReader(`{
		"enabled": true,
		"title": "should not persist",
		"server_ids": [`+strconv.FormatInt(server.ID, 10)+`],
		"show_name": true,
		"logo": "ftp://invalid.example/logo.svg"
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.SetProbeDisguise(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	for _, key := range []string{
		probeDisguiseEnabledKey,
		probeDisguiseTitleKey,
		probeDisguiseServerIDsKey,
		probeDisguiseShowNameKey,
		probeDisguiseLogoKey,
	} {
		if value, err := repo.GetSystemSetting(context.Background(), key); err != nil || value != "" {
			t.Fatalf("invalid logo partially saved %s=%q err=%v", key, value, err)
		}
	}
}

func mapsEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func TestProbePublicWebSocketDisabledAndEnabled(t *testing.T) {
	repo, server := newProbePublicRepository(t)
	public := NewProbePublicHandler(repo, nil, NewProbeMetricsStore())
	wsHandler := NewProbeWSHandler(public)

	disabled := httptest.NewRecorder()
	wsHandler.ServeHTTP(disabled, httptest.NewRequest(http.MethodGet, "/api/public/probe-ws", nil))
	if disabled.Code != http.StatusNotFound {
		t.Fatalf("disabled websocket status=%d want=%d", disabled.Code, http.StatusNotFound)
	}

	enableProbeForServer(t, repo, server.ID)
	serverHTTP := httptest.NewServer(wsHandler)
	defer serverHTTP.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(serverHTTP.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial public websocket: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	messageType, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read initial public websocket frame: %v", err)
	}
	if messageType != websocket.TextMessage {
		t.Fatalf("message type=%d want text", messageType)
	}
	var payload map[string]any
	if err := json.Unmarshal(message, &payload); err != nil {
		t.Fatalf("decode websocket payload: %v", err)
	}
	if payload["enabled"] != true {
		t.Fatalf("websocket enabled=%#v", payload["enabled"])
	}
	if strings.Contains(string(message), server.Token) || strings.Contains(string(message), server.IPAddress) {
		t.Fatalf("websocket payload leaked private server data: %s", message)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("client payload is not allowed")); err != nil {
		t.Fatalf("write prohibited client payload: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set close read deadline: %v", err)
	}
	if _, _, err := conn.ReadMessage(); !websocket.IsCloseError(err, websocket.ClosePolicyViolation) {
		t.Fatalf("public websocket accepted a client payload: %v", err)
	}
}

func TestProbeWebSocketReservesPendingClientLimits(t *testing.T) {
	handler := NewProbeWSHandler(nil)
	const address = "198.51.100.24"
	for range probeWSMaxPerIP {
		if !handler.reserveClientSlot(address) {
			t.Fatal("expected per-IP reservation to succeed below the limit")
		}
	}
	if handler.reserveClientSlot(address) {
		t.Fatal("per-IP reservation exceeded its limit")
	}
	for range probeWSMaxPerIP {
		handler.releaseClientSlot(address)
	}

	for i := 0; i < probeWSMaxClients; i++ {
		if !handler.reserveClientSlot("198.51.100." + strconv.Itoa(i)) {
			t.Fatalf("global reservation %d unexpectedly failed", i)
		}
	}
	if handler.reserveClientSlot("203.0.113.1") {
		t.Fatal("global reservation exceeded its limit")
	}
}

func TestProbeWSClientIPOnlyTrustsLocalProxyRealIP(t *testing.T) {
	proxied := httptest.NewRequest(http.MethodGet, "/api/public/probe-ws", nil)
	proxied.RemoteAddr = "127.0.0.1:43120"
	proxied.Header.Set("X-Real-IP", "198.51.100.44")
	proxied.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := probeWSClientIP(proxied); got != "198.51.100.44" {
		t.Fatalf("proxied client IP=%q, want X-Real-IP", got)
	}

	direct := httptest.NewRequest(http.MethodGet, "/api/public/probe-ws", nil)
	direct.RemoteAddr = "198.51.100.45:43120"
	direct.Header.Set("X-Real-IP", "203.0.113.10")
	direct.Header.Set("X-Forwarded-For", "203.0.113.11")
	if got := probeWSClientIP(direct); got != "198.51.100.45" {
		t.Fatalf("direct client IP=%q, must ignore spoofable headers", got)
	}
}
