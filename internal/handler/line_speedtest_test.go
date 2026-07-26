package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"miaomiaowux/internal/capabilities"
	"miaomiaowux/internal/linespeed"
	"miaomiaowux/internal/storage"
)

type stubLineSpeedService struct {
	status          linespeed.Status
	runResult       linespeed.Result
	runErr          error
	installCalls    int
	installAccepted bool
}

func (s *stubLineSpeedService) Status(context.Context) linespeed.Status { return s.status }

func (s *stubLineSpeedService) Install(_ context.Context, accepted bool) (linespeed.Status, error) {
	s.installCalls++
	s.installAccepted = accepted
	s.status.Installed = true
	s.status.Owned = true
	s.status.LicenseAccepted = true
	return s.status, nil
}

func TestLineSpeedInstallRequiresExplicitLicenseConsent(t *testing.T) {
	repo, _ := newRemoteInstallationHandlerRepo(t, 23889)
	local := &stubLineSpeedService{status: linespeed.Status{Supported: true, Managed: true}}
	h := NewLineSpeedTestHandler(repo, NewRemoteManageHandler(repo, nil))
	h.local = local
	body := []byte(`{"kind":"master"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/line-speedtest/install", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("install status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if local.installCalls != 0 || local.installAccepted {
		t.Fatalf("local installer ran without explicit consent: %#v", local)
	}
}

func TestLineSpeedRunRequiresRecordedLicenseConsent(t *testing.T) {
	repo, _ := newRemoteInstallationHandlerRepo(t, 23889)
	h := NewLineSpeedTestHandler(repo, NewRemoteManageHandler(repo, nil))
	h.local = &stubLineSpeedService{status: linespeed.Status{
		Supported:       true,
		Managed:         true,
		Installed:       true,
		LicenseAccepted: false,
	}}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/line-speedtest/run", bytes.NewReader([]byte(`{"kind":"master"}`)))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("run status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	results, err := repo.ListLineSpeedTestResults(context.Background(), storage.LineSpeedTargetMaster, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("run without consent created an asynchronous job: %#v", results)
	}
}

func TestDecodeRemoteLineSpeedResponsesRequireCompleteContracts(t *testing.T) {
	validStatus := []byte(`{"success":true,"status":{"supported":true,"installed":true,"license_accepted":true}}`)
	if status, err := decodeRemoteLineSpeedStatus(validStatus); err != nil || !status.Supported || !status.Installed || !status.LicenseAccepted {
		t.Fatalf("nested status=%#v err=%v", status, err)
	}
	flatStatus := []byte(`{"success":true,"supported":false,"installed":false}`)
	if status, err := decodeRemoteLineSpeedStatus(flatStatus); err != nil || status.Supported || status.Installed {
		t.Fatalf("flat status=%#v err=%v", status, err)
	}
	if _, err := decodeRemoteLineSpeedStatus([]byte(`{"success":true}`)); err == nil {
		t.Fatal("empty successful status response was accepted")
	}

	validResult := []byte(`{"success":true,"result":{"ping_ms":12.5,"download_mbps":800,"upload_mbps":100,"jitter_ms":0.5}}`)
	if result, err := decodeRemoteLineSpeedResult(validResult); err != nil || result.PingMS != 12.5 || result.DownloadMbps != 800 || result.UploadMbps != 100 {
		t.Fatalf("nested result=%#v err=%v", result, err)
	}
	flatResult := []byte(`{"ping_ms":1,"download_mbps":2,"upload_mbps":3}`)
	if result, err := decodeRemoteLineSpeedResult(flatResult); err != nil || result.PingMS != 1 || result.DownloadMbps != 2 || result.UploadMbps != 3 {
		t.Fatalf("flat result=%#v err=%v", result, err)
	}
	for _, body := range [][]byte{
		[]byte(`{"success":true}`),
		[]byte(`{"success":true,"result":{"ping_ms":1,"download_mbps":2}}`),
		[]byte(`{"success":true,"result":{"ping_ms":-1,"download_mbps":2,"upload_mbps":3}}`),
	} {
		if _, err := decodeRemoteLineSpeedResult(body); err == nil {
			t.Fatalf("invalid successful result was accepted: %s", body)
		}
	}
}

func TestPersistLineSpeedRetriesTransientDatabaseFailure(t *testing.T) {
	calls := 0
	h := &LineSpeedTestHandler{completeJob: func(context.Context, int64, storage.LineSpeedTestResult) error {
		calls++
		if calls == 1 {
			return errors.New("database busy")
		}
		return nil
	}}
	if err := h.persistLineSpeedCompletion(17, storage.LineSpeedTestResult{}); err != nil {
		t.Fatalf("persistLineSpeedCompletion() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("completion attempts=%d, want 2", calls)
	}
}

func TestRunAsyncFailsClosedWhenCompletionCannotPersist(t *testing.T) {
	completionCalls := 0
	failureCalls := 0
	var failureMessage string
	h := &LineSpeedTestHandler{
		local: &stubLineSpeedService{runResult: linespeed.Result{
			PingMS: 1, DownloadMbps: 2, UploadMbps: 3,
		}},
		completeJob: func(context.Context, int64, storage.LineSpeedTestResult) error {
			completionCalls++
			return errors.New("database unavailable")
		},
		failJob: func(_ context.Context, _ int64, message string) error {
			failureCalls++
			failureMessage = message
			return nil
		},
	}
	h.runAsync(99, lineSpeedTargetRequest{Kind: storage.LineSpeedTargetMaster}, storage.LineSpeedTargetMaster)
	if completionCalls != lineSpeedPersistTries {
		t.Fatalf("completion attempts=%d, want %d", completionCalls, lineSpeedPersistTries)
	}
	if failureCalls != 1 || failureMessage == "" || !strings.Contains(failureMessage, "结果保存失败") {
		t.Fatalf("failure fallback calls=%d message=%q", failureCalls, failureMessage)
	}
}

func (s *stubLineSpeedService) Remove(context.Context) (linespeed.Status, error) {
	s.status.Installed = false
	s.status.Owned = false
	return s.status, nil
}

func (s *stubLineSpeedService) Run(context.Context) (linespeed.Result, error) {
	return s.runResult, s.runErr
}

func TestLineSpeedTargetsRestoreJobsAndDistinguishOfflineFromUpgrade(t *testing.T) {
	var agentRequests atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentRequests.Add(1)
		http.NotFound(w, r)
	}))
	defer agent.Close()

	repo, oldAgent := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	offline := &storage.RemoteServer{
		Name:       "offline-edge",
		Token:      "offline-token",
		Status:     storage.RemoteServerStatusOffline,
		IPAddress:  "127.0.0.1",
		ListenPort: testServerPort(t, agent.URL),
	}
	if err := repo.CreateRemoteServer(context.Background(), offline); err != nil {
		t.Fatal(err)
	}

	resultID, err := repo.InsertLineSpeedTestResult(context.Background(), storage.LineSpeedTestResult{
		TargetKind: storage.LineSpeedTargetMaster,
		ServerName: "主控本机",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteLineSpeedTestResult(context.Background(), resultID, storage.LineSpeedTestResult{
		PingMS:       8.5,
		DownloadMbps: 512.25,
	}); err != nil {
		t.Fatal(err)
	}
	failedID, err := repo.InsertLineSpeedTestResult(context.Background(), storage.LineSpeedTestResult{
		TargetKind: storage.LineSpeedTargetMaster,
		ServerName: "主控本机",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.FailLineSpeedTestResult(context.Background(), failedID, "测速服务器不可达"); err != nil {
		t.Fatal(err)
	}

	h := NewLineSpeedTestHandler(repo, NewRemoteManageHandler(repo, nil))
	h.local = &stubLineSpeedService{status: linespeed.Status{Supported: true, Managed: true}}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/line-speedtest/targets", nil)
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("targets status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Targets []lineSpeedTarget `json:"targets"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	targets := make(map[string]lineSpeedTarget, len(response.Targets))
	for _, target := range response.Targets {
		targets[target.Key] = target
	}
	master := targets["master"]
	if master.Name != "主控本机" || master.Supported == nil || !*master.Supported {
		t.Fatalf("unexpected master target: %#v", master)
	}
	if master.LastResult == nil || master.LastResult.DownloadMbps != 512.25 {
		t.Fatalf("master last_result=%#v", master.LastResult)
	}
	if master.LastJob == nil || master.LastJob.ID != failedID || master.Error != "测速服务器不可达" {
		t.Fatalf("failed job was not restored: %#v", master)
	}

	upgrade := targets[targetKey(storage.LineSpeedTargetRemote, oldAgent.ID)]
	if upgrade.Name != oldAgent.Name || upgrade.Supported == nil || *upgrade.Supported || !upgrade.UpgradeRequired {
		t.Fatalf("unexpected old Agent target: %#v", upgrade)
	}
	if upgrade.Managed || upgrade.Installed || upgrade.Error != "Agent 版本过低，请先升级 Agent" {
		t.Fatalf("unexpected old Agent semantics: %#v", upgrade)
	}
	offlineTarget := targets[targetKey(storage.LineSpeedTargetRemote, offline.ID)]
	if offlineTarget.Online || offlineTarget.UpgradeRequired || offlineTarget.Supported != nil {
		t.Fatalf("offline target implied unsupported/upgrade: %#v", offlineTarget)
	}
	if got := agentRequests.Load(); got != 1 {
		t.Fatalf("Agent request count=%d, offline target must not be probed", got)
	}
}

func TestLineSpeedRemoteRunBypassesInstallationMutationLease(t *testing.T) {
	runReached := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/line-speedtest/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"status": linespeed.Status{
					Supported:       true,
					Installed:       true,
					Managed:         true,
					Owned:           true,
					LicenseAccepted: true,
					Implementation:  linespeed.Implementation,
					Version:         linespeed.Version,
				},
			})
		case "/api/child/line-speedtest/run":
			runReached <- struct{}{}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result": linespeed.Result{
					PingMS:         11.25,
					DownloadMbps:   700.5,
					UploadMbps:     90.75,
					ISP:            "Example ISP",
					EgressIP:       "203.0.113.9",
					TestServer:     "Tokyo #7",
					ServerLocation: "Tokyo",
					Implementation: linespeed.ResultImplementation,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "active-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	h := NewLineSpeedTestHandler(repo, NewRemoteManageHandler(repo, nil))
	h.local = &stubLineSpeedService{}
	body, err := json.Marshal(lineSpeedTargetRequest{Kind: storage.LineSpeedTargetRemote, ServerID: server.ID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/line-speedtest/run", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("run status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var started struct {
		JobID int64                       `json:"job_id"`
		Job   storage.LineSpeedTestResult `json:"job"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if started.JobID <= 0 || started.Job.ID != started.JobID || started.Job.CreatedAt.IsZero() {
		t.Fatalf("invalid started job: %#v", started)
	}
	select {
	case <-runReached:
	case <-time.After(2 * time.Second):
		t.Fatal("remote run was blocked by the active installation mutation lease")
	}

	deadline := time.Now().Add(2 * time.Second)
	var completed storage.LineSpeedTestResult
	for {
		completed, err = repo.GetLineSpeedTestResult(context.Background(), started.JobID)
		if err == nil && completed.Status != storage.LineSpeedStatusRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not complete: job=%#v err=%v", completed, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if completed.Status != storage.LineSpeedStatusOK || completed.DownloadMbps != 700.5 || completed.CompletedAt == nil {
		t.Fatalf("unexpected completed job: %#v", completed)
	}

	jobReq := httptest.NewRequest(http.MethodGet, "/api/admin/line-speedtest/jobs/"+strconv.FormatInt(started.JobID, 10), nil)
	jobRecorder := httptest.NewRecorder()
	h.ServeHTTP(jobRecorder, jobReq)
	if jobRecorder.Code != http.StatusOK {
		t.Fatalf("job status=%d body=%s", jobRecorder.Code, jobRecorder.Body.String())
	}
	var jobResponse struct {
		Status string                       `json:"status"`
		Job    storage.LineSpeedTestResult  `json:"job"`
		Result *storage.LineSpeedTestResult `json:"result"`
	}
	if err := json.Unmarshal(jobRecorder.Body.Bytes(), &jobResponse); err != nil {
		t.Fatal(err)
	}
	if jobResponse.Status != storage.LineSpeedStatusOK || jobResponse.Result == nil || jobResponse.Result.DownloadMbps != 700.5 {
		t.Fatalf("completed response does not expose result: %#v", jobResponse)
	}
}

func TestLineSpeedInstallKeepsRemoteMutationLease(t *testing.T) {
	var agentRequests atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentRequests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "active-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	h := NewLineSpeedTestHandler(repo, NewRemoteManageHandler(repo, nil))
	accepted := true
	body, err := json.Marshal(lineSpeedTargetRequest{Kind: storage.LineSpeedTargetRemote, ServerID: server.ID, AcceptLicense: &accepted})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/line-speedtest/install", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("install status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := agentRequests.Load(); got != 0 {
		t.Fatalf("install reached Agent %d time(s) while mutation lease was blocked", got)
	}
}

func TestLineSpeedRemoteInstallForwardsExplicitLicenseConsent(t *testing.T) {
	var installRequests atomic.Int32
	var invalidConsent atomic.Bool
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/line-speedtest/install":
			var payload struct {
				AcceptLicense *bool `json:"accept_license"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				invalidConsent.Store(true)
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			if payload.AcceptLicense == nil || !*payload.AcceptLicense {
				invalidConsent.Store(true)
				http.Error(w, "missing consent", http.StatusBadRequest)
				return
			}
			installRequests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		case "/api/child/line-speedtest/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":          true,
				"supported":        true,
				"installed":        true,
				"managed":          true,
				"owned":            true,
				"license_accepted": true,
				"implementation":   linespeed.Implementation,
				"version":          linespeed.Version,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	h := NewLineSpeedTestHandler(repo, NewRemoteManageHandler(repo, nil))
	accepted := true
	body, err := json.Marshal(lineSpeedTargetRequest{Kind: storage.LineSpeedTargetRemote, ServerID: server.ID, AcceptLicense: &accepted})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/line-speedtest/install", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("remote install status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if installRequests.Load() != 1 {
		t.Fatalf("remote install request count=%d", installRequests.Load())
	}
	if invalidConsent.Load() {
		t.Fatal("remote install payload did not carry explicit consent")
	}
}

func TestFederatedLineSpeedRunBypassesOwnerMutationLease(t *testing.T) {
	runReached := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/child/line-speedtest/run" {
			http.NotFound(w, r)
			return
		}
		runReached <- struct{}{}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": linespeed.Result{PingMS: 1}})
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	const shareToken = "line-speedtest-share-token"
	if _, err := repo.CreateSharedServer(context.Background(), server.ID, hashShareToken(shareToken), "line speed test"); err != nil {
		t.Fatal(err)
	}
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "active-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	federation := NewFederationHandler(repo, NewRemoteManageHandler(repo, nil), capabilities.NewManager())
	payload := []byte(`{"method":"POST","path":"/api/child/line-speedtest/run","body":"e30="}`)
	req := httptest.NewRequest(http.MethodPost, "/api/federation/manage", bytes.NewReader(payload))
	req.Header.Set("X-Share-Token", shareToken)
	recorder := httptest.NewRecorder()
	federation.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("federated run status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	select {
	case <-runReached:
	case <-time.After(2 * time.Second):
		t.Fatal("federated owner path held the installation mutation lease")
	}
}
