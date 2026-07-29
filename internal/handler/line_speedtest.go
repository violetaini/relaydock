package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/linespeed"
	"github.com/violetaini/relaydock/internal/storage"
)

const (
	lineSpeedToolDir       = "data/tools/ookla-speedtest"
	lineSpeedBodyLimit     = int64(8 << 10)
	lineSpeedStatusTimeout = 12 * time.Second
	lineSpeedJobTimeout    = 5 * time.Minute
	lineSpeedProbeWorkers  = 8
	lineSpeedMaxErrorBytes = 2048
	lineSpeedPersistTries  = 3
)

type lineSpeedService interface {
	Status(context.Context) linespeed.Status
	Install(context.Context, bool) (linespeed.Status, error)
	Remove(context.Context) (linespeed.Status, error)
	Run(context.Context) (linespeed.Result, error)
}

type LineSpeedTestHandler struct {
	repo        *storage.TrafficRepository
	remote      *RemoteManageHandler
	local       lineSpeedService
	completeJob func(context.Context, int64, storage.LineSpeedTestResult) error
	failJob     func(context.Context, int64, string) error
	runMu       sync.Mutex
	running     map[string]struct{}
}

func NewLineSpeedTestHandler(repo *storage.TrafficRepository, remote *RemoteManageHandler) *LineSpeedTestHandler {
	return &LineSpeedTestHandler{
		repo:        repo,
		remote:      remote,
		local:       linespeed.NewService(lineSpeedToolDir),
		completeJob: repo.CompleteLineSpeedTestResult,
		failJob:     repo.FailLineSpeedTestResult,
		running:     make(map[string]struct{}),
	}
}

type lineSpeedTargetRequest struct {
	Kind          string `json:"kind"`
	ServerID      int64  `json:"server_id,omitempty"`
	AcceptLicense *bool  `json:"accept_license,omitempty"`
}

type lineSpeedTarget struct {
	Key             string                       `json:"key"`
	Kind            string                       `json:"kind"`
	ServerID        int64                        `json:"server_id"`
	Name            string                       `json:"name"`
	ServerName      string                       `json:"server_name"`
	Online          bool                         `json:"online"`
	Supported       *bool                        `json:"supported,omitempty"`
	UpgradeRequired bool                         `json:"upgrade_required"`
	Installed       bool                         `json:"installed"`
	Managed         bool                         `json:"managed"`
	Owned           bool                         `json:"owned"`
	Running         bool                         `json:"running"`
	PythonReady     bool                         `json:"python_ready"`
	LicenseAccepted bool                         `json:"license_accepted"`
	Implementation  string                       `json:"implementation"`
	Version         string                       `json:"version,omitempty"`
	Error           string                       `json:"error,omitempty"`
	LastResult      *storage.LineSpeedTestResult `json:"last_result,omitempty"`
	LastJob         *storage.LineSpeedTestResult `json:"last_job,omitempty"`
}

func (h *LineSpeedTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/admin/line-speedtest/targets":
		h.handleTargets(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/admin/line-speedtest/install":
		h.handleTargetMutation(w, r, "install")
	case r.Method == http.MethodPost && r.URL.Path == "/api/admin/line-speedtest/remove":
		h.handleTargetMutation(w, r, "remove")
	case r.Method == http.MethodPost && r.URL.Path == "/api/admin/line-speedtest/run":
		h.handleRun(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/admin/line-speedtest/jobs/"):
		h.handleJob(w, r)
	default:
		writeError(w, http.StatusNotFound, errors.New("not found"))
	}
}

func (h *LineSpeedTestHandler) handleTargets(w http.ResponseWriter, r *http.Request) {
	latestResults, err := h.repo.ListLatestSuccessfulLineSpeedTestResults(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	latestByTarget := make(map[string]*storage.LineSpeedTestResult, len(latestResults))
	for i := range latestResults {
		result := &latestResults[i]
		latestByTarget[targetKey(result.TargetKind, result.ServerID)] = result
	}
	latestJobs, err := h.repo.ListLatestLineSpeedTestJobs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	latestJobsByTarget := make(map[string]*storage.LineSpeedTestResult, len(latestJobs))
	for i := range latestJobs {
		job := &latestJobs[i]
		latestJobsByTarget[targetKey(job.TargetKind, job.ServerID)] = job
	}
	localStatus := h.local.Status(r.Context())
	localTarget := h.localTarget(localStatus)
	localTarget.LastResult = latestByTarget[localTarget.Key]
	applyLineSpeedLastJob(&localTarget, latestJobsByTarget[localTarget.Key])
	targets := []lineSpeedTarget{localTarget}
	servers, err := h.repo.ListRemoteServers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	remoteTargets := make([]lineSpeedTarget, len(servers))
	semaphore := make(chan struct{}, lineSpeedProbeWorkers)
	var wg sync.WaitGroup
	for i := range servers {
		i, server := i, servers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			base := lineSpeedTarget{
				Key:        targetKey(storage.LineSpeedTargetRemote, server.ID),
				Kind:       storage.LineSpeedTargetRemote,
				ServerID:   server.ID,
				Name:       server.Name,
				ServerName: server.Name,
				Online:     server.Status == storage.RemoteServerStatusConnected,
				LastResult: latestByTarget[targetKey(storage.LineSpeedTargetRemote, server.ID)],
			}
			applyLineSpeedLastJob(&base, latestJobsByTarget[base.Key])
			if !base.Online {
				if base.Error == "" {
					base.Error = "服务器离线"
				}
				remoteTargets[i] = base
				return
			}
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-r.Context().Done():
				base.Error = "测速能力探测已取消"
				remoteTargets[i] = base
				return
			}
			probeCtx, cancel := context.WithTimeout(r.Context(), lineSpeedStatusTimeout)
			defer cancel()
			status, statusErr := h.remoteStatus(probeCtx, server.ID)
			if statusErr != nil {
				if isLineSpeedUpgradeRequired(statusErr) {
					supported := false
					base.Supported = &supported
					base.UpgradeRequired = true
					base.Error = "Agent 版本过低，请先升级 Agent"
				} else {
					if base.Error == "" {
						base.Error = lineSpeedError(statusErr)
					}
				}
				remoteTargets[i] = base
				return
			}
			remoteTargets[i] = h.targetFromStatus(base, status)
		}()
	}
	wg.Wait()
	targets = append(targets, remoteTargets...)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "targets": targets})
}

func (h *LineSpeedTestHandler) handleTargetMutation(w http.ResponseWriter, r *http.Request, action string) {
	req, server, ok := h.decodeAndResolveTarget(w, r)
	if !ok {
		return
	}
	if action == "install" && (req.AcceptLicense == nil || !*req.AcceptLicense) {
		writeError(w, http.StatusBadRequest, linespeed.ErrLicenseNotAccepted)
		return
	}
	if h.isRunning(targetKey(req.Kind, req.ServerID)) {
		writeError(w, http.StatusConflict, linespeed.ErrBusy)
		return
	}

	var (
		status linespeed.Status
		err    error
	)
	if req.Kind == storage.LineSpeedTargetMaster {
		if action == "install" {
			status, err = h.local.Install(r.Context(), true)
		} else {
			status, err = h.local.Remove(r.Context())
		}
	} else {
		path := "/api/child/line-speedtest/" + action
		body := []byte(`{}`)
		if action == "install" {
			body = []byte(`{"accept_license":true}`)
		}
		_, err = h.remote.forwardToRemoteServer(r.Context(), req.ServerID, http.MethodPost, path, body)
		if err == nil {
			status, err = h.remoteStatus(r.Context(), req.ServerID)
		}
	}
	if err != nil {
		if isLineSpeedUpgradeRequired(err) {
			writeLineSpeedUpgradeError(w)
			return
		}
		statusCode := http.StatusBadRequest
		if errors.Is(err, linespeed.ErrBusy) || errors.Is(err, storage.ErrRemoteInstallationActive) {
			statusCode = http.StatusConflict
		}
		writeError(w, statusCode, errors.New(lineSpeedError(err)))
		return
	}

	base := lineSpeedTarget{
		Key:        targetKey(req.Kind, req.ServerID),
		Kind:       req.Kind,
		ServerID:   req.ServerID,
		Name:       "主控本机",
		ServerName: "主控本机",
		Online:     true,
	}
	if server != nil {
		base.Name = server.Name
		base.ServerName = server.Name
		base.Online = server.Status == storage.RemoteServerStatusConnected
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"target":  h.targetFromStatus(base, status),
	})
}

func (h *LineSpeedTestHandler) handleRun(w http.ResponseWriter, r *http.Request) {
	req, server, ok := h.decodeAndResolveTarget(w, r)
	if !ok {
		return
	}

	var (
		status linespeed.Status
		err    error
	)
	if req.Kind == storage.LineSpeedTargetMaster {
		status = h.local.Status(r.Context())
	} else {
		statusCtx, cancel := context.WithTimeout(r.Context(), lineSpeedStatusTimeout)
		status, err = h.remoteStatus(statusCtx, req.ServerID)
		cancel()
	}
	if err != nil {
		if isLineSpeedUpgradeRequired(err) {
			writeLineSpeedUpgradeError(w)
			return
		}
		writeError(w, http.StatusBadRequest, errors.New(lineSpeedError(err)))
		return
	}
	if !status.Supported {
		writeError(w, http.StatusConflict, errors.New("该目标不支持线路测速"))
		return
	}
	if !status.Installed {
		writeError(w, http.StatusConflict, linespeed.ErrNotInstalled)
		return
	}
	if !status.LicenseAccepted {
		writeError(w, http.StatusConflict, linespeed.ErrLicenseNotAccepted)
		return
	}
	key := targetKey(req.Kind, req.ServerID)
	if status.Running || !h.markRunning(key) {
		writeError(w, http.StatusConflict, linespeed.ErrBusy)
		return
	}

	serverName := "主控本机"
	if server != nil {
		serverName = server.Name
	}
	job := storage.LineSpeedTestResult{
		TargetKind:     req.Kind,
		ServerID:       req.ServerID,
		ServerName:     serverName,
		Status:         storage.LineSpeedStatusRunning,
		Implementation: status.Implementation,
	}
	id, err := h.repo.InsertLineSpeedTestResult(r.Context(), job)
	if err != nil {
		h.clearRunning(key)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	job.ID = id
	if persisted, getErr := h.repo.GetLineSpeedTestResult(r.Context(), id); getErr == nil {
		job = persisted
	} else {
		job.CreatedAt = time.Now()
	}
	go h.runAsync(id, req, key)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"success": true,
		"job_id":  id,
		"status":  storage.LineSpeedStatusRunning,
		"job":     job,
	})
}

func (h *LineSpeedTestHandler) handleJob(w http.ResponseWriter, r *http.Request) {
	idText := strings.TrimPrefix(r.URL.Path, "/api/admin/line-speedtest/jobs/")
	if idText == "" || strings.Contains(idText, "/") {
		writeError(w, http.StatusNotFound, storage.ErrLineSpeedTestNotFound)
		return
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, errors.New("无效的测速任务 ID"))
		return
	}
	job, err := h.repo.GetLineSpeedTestResult(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrLineSpeedTestNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}
	response := map[string]any{"success": true, "job": job, "status": job.Status}
	if job.Status == storage.LineSpeedStatusOK {
		response["result"] = job
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *LineSpeedTestHandler) runAsync(id int64, target lineSpeedTargetRequest, key string) {
	defer h.clearRunning(key)
	ctx, cancel := context.WithTimeout(context.Background(), lineSpeedJobTimeout)
	defer cancel()

	var (
		result linespeed.Result
		err    error
	)
	if target.Kind == storage.LineSpeedTargetMaster {
		result, err = h.local.Run(ctx)
	} else {
		// 纯测速不会修改 Agent/Xray 配置，不能持有 remote server mutation lease 数分钟。
		// 直接进入已解析 transport 的调用层，仍保留 WS-RPC/HTTP 回退和 5 分钟 transport timeout。
		var body []byte
		body, err = h.remote.forwardToRemoteServerLeased(ctx, target.ServerID, http.MethodPost, "/api/child/line-speedtest/run", []byte(`{}`))
		if err == nil {
			result, err = decodeRemoteLineSpeedResult(body)
		}
	}

	if err != nil {
		if updateErr := h.persistLineSpeedFailure(id, lineSpeedError(err)); updateErr != nil {
			log.Printf("[Line Speedtest] fail job %d persistence failed: %v", id, updateErr)
		}
		return
	}
	if result.Implementation == "" {
		result.Implementation = linespeed.ResultImplementation
	}
	metrics := storage.LineSpeedTestResult{
		PingMS:            result.PingMS,
		DownloadMbps:      result.DownloadMbps,
		UploadMbps:        result.UploadMbps,
		JitterMS:          result.JitterMS,
		PacketLossPercent: result.PacketLossPercent,
		ISP:               result.ISP,
		EgressIP:          result.EgressIP,
		TestServer:        result.TestServer,
		ServerLocation:    result.ServerLocation,
		Implementation:    result.Implementation,
	}
	if updateErr := h.persistLineSpeedCompletion(id, metrics); updateErr != nil {
		fallbackMessage := lineSpeedError(fmt.Errorf("测速已完成，但结果保存失败: %w", updateErr))
		if failErr := h.persistLineSpeedFailure(id, fallbackMessage); failErr != nil {
			log.Printf("[Line Speedtest] complete job %d persistence failed: %v; fail-close also failed: %v", id, updateErr, failErr)
		} else {
			log.Printf("[Line Speedtest] complete job %d persistence failed; marked failed: %v", id, updateErr)
		}
	}
}

// persistLineSpeed retries small, independent database writes. A speed test is
// already finished by this point, so a transient SQLite lock must not leave the
// UI showing a job as running forever.
func persistLineSpeed(operation func(context.Context) error) error {
	var lastErr error
	for attempt := 0; attempt < lineSpeedPersistTries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := operation(ctx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt+1 < lineSpeedPersistTries {
			time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
		}
	}
	return lastErr
}

func (h *LineSpeedTestHandler) persistLineSpeedCompletion(id int64, metrics storage.LineSpeedTestResult) error {
	if h == nil || h.completeJob == nil {
		return errors.New("线路测速结果存储未初始化")
	}
	return persistLineSpeed(func(ctx context.Context) error {
		return h.completeJob(ctx, id, metrics)
	})
}

func (h *LineSpeedTestHandler) persistLineSpeedFailure(id int64, message string) error {
	if h == nil || h.failJob == nil {
		return errors.New("线路测速结果存储未初始化")
	}
	return persistLineSpeed(func(ctx context.Context) error {
		return h.failJob(ctx, id, message)
	})
}

func (h *LineSpeedTestHandler) decodeAndResolveTarget(w http.ResponseWriter, r *http.Request) (lineSpeedTargetRequest, *storage.RemoteServer, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, lineSpeedBodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req lineSpeedTargetRequest
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("请求格式无效"))
		return lineSpeedTargetRequest{}, nil, false
	}
	switch req.Kind {
	case storage.LineSpeedTargetMaster:
		if req.ServerID != 0 {
			writeError(w, http.StatusBadRequest, errors.New("主控测速不能指定 server_id"))
			return lineSpeedTargetRequest{}, nil, false
		}
		return req, nil, true
	case storage.LineSpeedTargetRemote:
		if req.ServerID <= 0 {
			writeError(w, http.StatusBadRequest, errors.New("远端测速必须指定 server_id"))
			return lineSpeedTargetRequest{}, nil, false
		}
		server, err := h.repo.GetRemoteServer(r.Context(), req.ServerID)
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("远端服务器不存在"))
			return lineSpeedTargetRequest{}, nil, false
		}
		if server.Status != storage.RemoteServerStatusConnected {
			writeError(w, http.StatusConflict, errors.New("远端服务器当前离线"))
			return lineSpeedTargetRequest{}, nil, false
		}
		return req, server, true
	default:
		writeError(w, http.StatusBadRequest, errors.New("kind 必须是 master 或 remote"))
		return lineSpeedTargetRequest{}, nil, false
	}
}

func (h *LineSpeedTestHandler) localTarget(status linespeed.Status) lineSpeedTarget {
	base := lineSpeedTarget{
		Key:        targetKey(storage.LineSpeedTargetMaster, 0),
		Kind:       storage.LineSpeedTargetMaster,
		Name:       "主控本机",
		ServerName: "主控本机",
		Online:     true,
	}
	return h.targetFromStatus(base, status)
}

func (h *LineSpeedTestHandler) targetFromStatus(base lineSpeedTarget, status linespeed.Status) lineSpeedTarget {
	base.Supported = boolPtr(status.Supported)
	base.Installed = status.Installed
	base.Managed = status.Managed
	base.Owned = status.Owned
	base.Running = base.Running || status.Running || h.isRunning(targetKey(base.Kind, base.ServerID))
	base.PythonReady = status.PythonReady
	base.LicenseAccepted = status.LicenseAccepted
	base.Implementation = status.Implementation
	base.Version = status.Version
	return base
}

func (h *LineSpeedTestHandler) remoteStatus(ctx context.Context, serverID int64) (linespeed.Status, error) {
	if h.remote == nil {
		return linespeed.Status{}, errors.New("远端管理未初始化")
	}
	body, err := h.remote.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/line-speedtest/status", nil)
	if err != nil {
		return linespeed.Status{}, err
	}
	return decodeRemoteLineSpeedStatus(body)
}

func decodeRemoteLineSpeedStatus(body []byte) (linespeed.Status, error) {
	var envelope struct {
		Success *bool           `json:"success"`
		Error   string          `json:"error"`
		Status  json.RawMessage `json:"status"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return linespeed.Status{}, fmt.Errorf("Agent 返回了无效的测速状态: %w", err)
	}
	if envelope.Success != nil && !*envelope.Success {
		if envelope.Error == "" {
			envelope.Error = "Agent 查询测速状态失败"
		}
		return linespeed.Status{}, errors.New(envelope.Error)
	}
	payload := body
	if len(envelope.Status) > 0 && string(envelope.Status) != "null" {
		payload = envelope.Status
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return linespeed.Status{}, fmt.Errorf("Agent 返回了无效的测速状态: %w", err)
	}
	if _, ok := fields["supported"]; !ok {
		return linespeed.Status{}, errors.New("Agent 返回的测速状态缺少 supported 字段")
	}
	var status linespeed.Status
	if err := json.Unmarshal(payload, &status); err != nil {
		return linespeed.Status{}, err
	}
	return status, nil
}

func decodeRemoteLineSpeedResult(body []byte) (linespeed.Result, error) {
	var envelope struct {
		Success *bool           `json:"success"`
		Error   string          `json:"error"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return linespeed.Result{}, fmt.Errorf("Agent 返回了无效的测速结果: %w", err)
	}
	if envelope.Success != nil && !*envelope.Success {
		if envelope.Error == "" {
			envelope.Error = "Agent 线路测速失败"
		}
		return linespeed.Result{}, errors.New(envelope.Error)
	}
	// New Agents return {success,result}. Keep accepting a legacy flat result,
	// but require all three core metrics to be present: unmarshalling a success
	// envelope into float64 fields would otherwise manufacture a false 0 Mbps
	// success record.
	payload := body
	if len(envelope.Result) > 0 && string(envelope.Result) != "null" {
		payload = envelope.Result
	}
	var raw struct {
		PingMS            *float64 `json:"ping_ms"`
		DownloadMbps      *float64 `json:"download_mbps"`
		UploadMbps        *float64 `json:"upload_mbps"`
		JitterMS          *float64 `json:"jitter_ms"`
		PacketLossPercent *float64 `json:"packet_loss_percent"`
		ISP               string   `json:"isp"`
		EgressIP          string   `json:"egress_ip"`
		TestServer        string   `json:"test_server"`
		ServerLocation    string   `json:"server_location"`
		Implementation    string   `json:"implementation"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return linespeed.Result{}, err
	}
	if raw.PingMS == nil || raw.DownloadMbps == nil || raw.UploadMbps == nil {
		return linespeed.Result{}, errors.New("Agent 返回的测速结果缺少 ping、下载或上传数据")
	}
	for name, value := range map[string]*float64{
		"ping_ms": raw.PingMS, "download_mbps": raw.DownloadMbps, "upload_mbps": raw.UploadMbps,
		"jitter_ms": raw.JitterMS, "packet_loss_percent": raw.PacketLossPercent,
	} {
		if value != nil && (*value < 0 || math.IsNaN(*value) || math.IsInf(*value, 0)) {
			return linespeed.Result{}, fmt.Errorf("Agent 返回了非法的 %s", name)
		}
	}
	return linespeed.Result{
		PingMS:            *raw.PingMS,
		DownloadMbps:      *raw.DownloadMbps,
		UploadMbps:        *raw.UploadMbps,
		JitterMS:          raw.JitterMS,
		PacketLossPercent: raw.PacketLossPercent,
		ISP:               raw.ISP,
		EgressIP:          raw.EgressIP,
		TestServer:        raw.TestServer,
		ServerLocation:    raw.ServerLocation,
		Implementation:    raw.Implementation,
	}, nil
}

func isLineSpeedUpgradeRequired(err error) bool {
	var httpErr *HTTPLikeError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "status 404") || strings.Contains(message, "404 page not found")
}

func writeLineSpeedUpgradeError(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, map[string]any{
		"success":          false,
		"upgrade_required": true,
		"error":            "Agent 版本过低，请先升级 Agent",
	})
}

func lineSpeedError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > lineSpeedMaxErrorBytes {
		message = message[:lineSpeedMaxErrorBytes]
	}
	return message
}

func targetKey(kind string, serverID int64) string {
	if kind == storage.LineSpeedTargetMaster {
		return storage.LineSpeedTargetMaster
	}
	return storage.LineSpeedTargetRemote + ":" + strconv.FormatInt(serverID, 10)
}

func boolPtr(value bool) *bool {
	return &value
}

func applyLineSpeedLastJob(target *lineSpeedTarget, job *storage.LineSpeedTestResult) {
	if target == nil || job == nil {
		return
	}
	target.LastJob = job
	switch job.Status {
	case storage.LineSpeedStatusRunning:
		target.Running = true
	case storage.LineSpeedStatusFailed:
		target.Error = job.Error
	}
}

func (h *LineSpeedTestHandler) markRunning(key string) bool {
	h.runMu.Lock()
	defer h.runMu.Unlock()
	if _, exists := h.running[key]; exists {
		return false
	}
	h.running[key] = struct{}{}
	return true
}

func (h *LineSpeedTestHandler) clearRunning(key string) {
	h.runMu.Lock()
	delete(h.running, key)
	h.runMu.Unlock()
}

func (h *LineSpeedTestHandler) isRunning(key string) bool {
	h.runMu.Lock()
	_, exists := h.running[key]
	h.runMu.Unlock()
	return exists
}
