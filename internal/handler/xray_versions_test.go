package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type xrayVersionRoundTripFunc func(*http.Request) (*http.Response, error)

func (f xrayVersionRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func xrayVersionHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestFetchOfficialXrayCoreVersionsFiltersDraftsMalformedAndDuplicates(t *testing.T) {
	handler := NewRemoteManageHandler(nil, nil)
	handler.httpClient = &http.Client{Transport: xrayVersionRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.URL.String(); got != xrayCoreReleasesURL {
			t.Fatalf("request URL=%q want=%q", got, xrayCoreReleasesURL)
		}
		return xrayVersionHTTPResponse(http.StatusOK, `[
			{"tag_name":"v26.7.28","name":"July candidate","prerelease":true,"published_at":"2026-07-28T00:00:00Z"},
			{"tag_name":"v26.7.11","name":"July stable","prerelease":false,"published_at":"2026-07-11T00:00:00Z"},
			{"tag_name":"v26.7.11","name":"duplicate","prerelease":false},
			{"tag_name":"26.7.1","name":"missing prefix","prerelease":false},
			{"tag_name":"v26.7.1-rc1","name":"suffix","prerelease":true},
			{"tag_name":"v26.6.27","name":"draft","draft":true}
		]`), nil
	})}

	versions, fetchErr := handler.fetchOfficialXrayCoreVersions(context.Background())
	if fetchErr != "" {
		t.Fatal(fetchErr)
	}
	if len(versions) != 2 {
		t.Fatalf("versions=%+v want two valid unique releases", versions)
	}
	if versions[0].Version != "v26.7.28" || !versions[0].Prerelease {
		t.Fatalf("first version=%+v", versions[0])
	}
	latest, latestStable := xrayCoreVersionSummary(versions)
	if latest != "v26.7.28" || latestStable != "v26.7.11" {
		t.Fatalf("summary=(%q,%q)", latest, latestStable)
	}
}

func TestFetchOfficialXrayCoreVersionsAcceptsReleaseMetadataLargerThanTwoMiB(t *testing.T) {
	largeBody := `[{"tag_name":"v26.7.28","name":"latest","prerelease":false,"body":"` +
		strings.Repeat("x", (2<<20)+1024) + `"}]`
	handler := NewRemoteManageHandler(nil, nil)
	handler.httpClient = &http.Client{Transport: xrayVersionRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return xrayVersionHTTPResponse(http.StatusOK, largeBody), nil
	})}

	versions, fetchErr := handler.fetchOfficialXrayCoreVersions(context.Background())
	if fetchErr != "" {
		t.Fatal(fetchErr)
	}
	if len(versions) != 1 || versions[0].Version != "v26.7.28" {
		t.Fatalf("versions=%+v", versions)
	}
}

func TestFetchXrayCoreVersionsCoalescesAndFallsBackToStaleCache(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var requests atomic.Int32
	var fail atomic.Bool
	handler := NewRemoteManageHandler(nil, nil)
	handler.httpClient = &http.Client{Transport: xrayVersionRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		count := requests.Add(1)
		if fail.Load() {
			return nil, errors.New("temporary github failure")
		}
		if count == 1 {
			close(requestStarted)
			<-releaseRequest
		}
		return xrayVersionHTTPResponse(http.StatusOK, `[{"tag_name":"v26.7.11","name":"stable"}]`), nil
	})}

	type result struct {
		versions []XrayCoreVersion
		err      string
	}
	leader := make(chan result, 1)
	go func() {
		versions, fetchErr := handler.fetchXrayCoreVersions(context.Background())
		leader <- result{versions: versions, err: fetchErr}
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("first release request did not start")
	}

	waiter := make(chan result, 1)
	go func() {
		versions, fetchErr := handler.fetchXrayCoreVersions(context.Background())
		waiter <- result{versions: versions, err: fetchErr}
	}()
	time.Sleep(10 * time.Millisecond)
	if got := requests.Load(); got != 1 {
		t.Fatalf("in-flight requests=%d want=1", got)
	}
	close(releaseRequest)
	for _, resultCh := range []<-chan result{leader, waiter} {
		got := <-resultCh
		if got.err != "" || len(got.versions) != 1 || got.versions[0].Version != "v26.7.11" {
			t.Fatalf("coalesced result=%+v", got)
		}
	}

	handler.xrayVersionsMu.Lock()
	handler.xrayVersionsAt = time.Now().Add(-xrayCoreVersionsCacheTTL - time.Second)
	handler.xrayVersionsMu.Unlock()
	fail.Store(true)
	stale, staleErr := handler.fetchXrayCoreVersions(context.Background())
	if len(stale) != 1 || stale[0].Version != "v26.7.11" {
		t.Fatalf("stale versions=%+v", stale)
	}
	if !strings.Contains(staleErr, "temporary github failure") {
		t.Fatalf("stale error=%q", staleErr)
	}
}

func TestDecodeXrayInstallVersionNormalizesAndRejectsInvalidBodies(t *testing.T) {
	for _, test := range []struct {
		name      string
		body      string
		version   string
		specified bool
		wantErr   bool
	}{
		{name: "empty", body: "", specified: false},
		{name: "canonical", body: `{"version":"v26.7.28"}`, version: "v26.7.28", specified: true},
		{name: "adds prefix", body: `{"version":"26.7.28"}`, version: "v26.7.28", specified: true},
		{name: "unknown field", body: `{"version":"v26.7.28","shell":"oops"}`, specified: true, wantErr: true},
		{name: "missing version", body: `{}`, specified: true, wantErr: true},
		{name: "suffix", body: `{"version":"v26.7.28-rc1"}`, specified: true, wantErr: true},
		{name: "shell input", body: `{"version":"v26.7.28; reboot"}`, specified: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			version, specified, err := decodeXrayInstallVersion(request)
			if (err != nil) != test.wantErr || specified != test.specified || version != test.version {
				t.Fatalf("got version=%q specified=%v err=%v", version, specified, err)
			}
		})
	}
}

func TestPrepareXrayInstallPayloadRejectsUnknownVersionAndOldAgent(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/child/system/info" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"capabilities": map[string]bool{}})
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewRemoteManageHandler(repo, nil)
	var githubRequests atomic.Int32
	handler.httpClient = &http.Client{Transport: xrayVersionRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "api.github.com" {
			githubRequests.Add(1)
			return nil, errors.New("GitHub must not be called before the Agent capability check")
		}
		return http.DefaultTransport.RoundTrip(request)
	})}
	oldAgentRequest := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":"v26.7.28"}`))
	_, _, status, err := handler.prepareXrayInstallPayload(context.Background(), server.ID, oldAgentRequest)
	if status != http.StatusConflict || err == nil || !strings.Contains(err.Error(), "升级 Agent") {
		t.Fatalf("old Agent status=%d err=%v", status, err)
	}
	if githubRequests.Load() != 0 {
		t.Fatalf("old Agent triggered %d GitHub request(s)", githubRequests.Load())
	}

	wsHandler := NewRemoteWSHandler(repo, nil)
	wsHandler.conns.Store("active", &RemoteWSConnection{
		ServerID:     server.ID,
		Capabilities: AgentCapabilities{XrayVersionSelectV1: true},
	})
	handler = NewRemoteManageHandler(repo, wsHandler)
	handler.xrayVersions = []XrayCoreVersion{{Version: "v26.7.28"}}
	handler.xrayVersionsAt = time.Now()
	unknownRequest := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":"v26.6.27"}`))
	_, _, status, err = handler.prepareXrayInstallPayload(context.Background(), server.ID, unknownRequest)
	if status != http.StatusBadRequest || err == nil || !strings.Contains(err.Error(), "not in the official release list") {
		t.Fatalf("unknown version status=%d err=%v", status, err)
	}
}

func TestXrayVersionSelectionCapabilityUsesWSBeforeHTTP(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 1)
	wsHandler := NewRemoteWSHandler(repo, nil)
	wsHandler.conns.Store("active", &RemoteWSConnection{
		ServerID:     server.ID,
		Capabilities: AgentCapabilities{XrayVersionSelectV1: true},
	})
	handler := NewRemoteManageHandler(repo, wsHandler)
	supported, capabilityErr := handler.xrayVersionSelectionSupported(context.Background(), server.ID)
	if !supported || capabilityErr != "" {
		t.Fatalf("supported=%v err=%q", supported, capabilityErr)
	}
}

func TestHandleXrayVersionsReturnsUpgradeRequirementWithoutCallingGitHub(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/child/system/info" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"capabilities": map[string]bool{}})
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.UpdateRemoteServerXrayMode(context.Background(), server.ID, "external"); err != nil {
		t.Fatal(err)
	}

	var githubRequests atomic.Int32
	handler := NewRemoteManageHandler(repo, nil)
	handler.httpClient = &http.Client{Transport: xrayVersionRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "api.github.com" {
			githubRequests.Add(1)
			return nil, errors.New("GitHub must not be called for an unsupported Agent")
		}
		return http.DefaultTransport.RoundTrip(request)
	})}
	request := httptest.NewRequest(http.MethodGet, "/api/admin/remote/xray/versions?server_id="+strconv.FormatInt(server.ID, 10), nil)
	response := httptest.NewRecorder()

	handler.HandleXrayVersions(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if githubRequests.Load() != 0 {
		t.Fatalf("unsupported Agent triggered %d GitHub request(s)", githubRequests.Load())
	}
	var payload struct {
		Supported    bool              `json:"version_selection_supported"`
		SupportError string            `json:"support_error"`
		Versions     []XrayCoreVersion `json:"versions"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Supported || !strings.Contains(payload.SupportError, "升级 Agent") || len(payload.Versions) != 0 {
		t.Fatalf("unexpected response: %+v", payload)
	}
}

func TestXrayInstallStreamForwardsSelectedVersionAndVerifiesStatus(t *testing.T) {
	var forwardedBody atomic.Value
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"capabilities": map[string]bool{"xray_version_select_v1": true},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/services/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"xray": map[string]any{
					"installed": true,
					"running":   true,
					"version":   "Xray 26.7.28 (linux/amd64)",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/xray/install-stream":
			raw, _ := io.ReadAll(r.Body)
			forwardedBody.Store(string(raw))
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"type\":\"complete\",\"success\":true}\n\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepoWithSteal(t, testServerPort(t, agent.URL), false)
	if err := repo.UpdateRemoteServerXrayMode(context.Background(), server.ID, "external"); err != nil {
		t.Fatal(err)
	}
	handler := NewRemoteManageHandler(repo, nil)
	handler.xrayVersions = []XrayCoreVersion{{Version: "v26.7.28"}}
	handler.xrayVersionsAt = time.Now()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/admin/remote/xray/install-stream?server_id="+strconv.FormatInt(server.ID, 10),
		bytes.NewBufferString(`{"version":"26.7.28"}`),
	)
	response := httptest.NewRecorder()
	handler.HandleXrayInstallStream(response, request)

	if strings.Contains(response.Body.String(), `"type":"error"`) {
		t.Fatalf("stream failed: %s", response.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(forwardedBody.Load().(string)), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["version"] != "v26.7.28" {
		t.Fatalf("forwarded payload=%v", payload)
	}
	if !reportedXrayVersionMatches("Xray 26.7.28 (linux/amd64)", "v26.7.28") {
		t.Fatal("expected status version to match selected version")
	}
	if reportedXrayVersionMatches("Xray 26.7.11 (linux/amd64)", "v26.7.28") {
		t.Fatal("different status version unexpectedly matched")
	}
}
