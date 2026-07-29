package handler

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/version"
)

const (
	githubRepo   = "violetaini/relaydock"
	githubAPIURL = "https://api.github.com/repos/%s/releases/latest"

	updateDeploymentDocker     = "docker"
	updateDeploymentStandalone = "standalone"
	updateScopeNone            = "none"
	updateScopeBackendOnly     = "backend_only"
	updateScopeControlPlane    = "control_plane_only"
	updateScopeFull            = "full"
	maxUpdateBinarySize        = 256 << 20
)

var (
	releaseTagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256Pattern     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	updateInProgress  atomic.Bool
	execProcess       = replaceCurrentProcess
	errUpdateBusy     = errors.New("另一个 RelayDock 安装或更新进程正在运行")
)

// UpdateInfo包含版本更新信息
type UpdateInfo struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	HasUpdate       bool   `json:"has_update"`
	ReleaseURL      string `json:"release_url"`
	DownloadURL     string `json:"download_url"`
	ReleaseNotes    string `json:"release_notes"`
	DeploymentMode  string `json:"deployment_mode"`
	UpdateScope     string `json:"update_scope"`
	ExternalWebRoot bool   `json:"external_web_root"`
	CanApply        bool   `json:"can_apply"`
	Warning         string `json:"warning,omitempty"`
	expectedSHA256  string
	guardAssetDir   string
	guardAssets     []updateReleaseAsset
	missingGuards   []string
	agentAssetDir   string
	agentAssets     []updateReleaseAsset
	missingAgents   []string
}

type updateEnvironment struct {
	DeploymentMode  string
	UpdateScope     string
	ExternalWebRoot bool
	CanApply        bool
	Warning         string
}

type updateReleaseAsset struct {
	Name        string
	DownloadURL string
	SHA256      string
	TargetPath  string
	GOOS        string
	GOARCH      string
}

type preparedUpdateFile struct {
	Name       string
	SourcePath string
	TargetPath string
	BackupPath string
	HadTarget  bool
}

// UpdateProgress 表示更新操作的进度
type UpdateProgress struct {
	Step     string `json:"step"`     // 检查、下载、备份、替换、重新启动、完成、错误
	Progress int    `json:"progress"` // 下载步数 0-100
	Message  string `json:"message"`
}

type UpdateStatus struct {
	CurrentVersion  string `json:"current_version"`
	DeploymentMode  string `json:"deployment_mode"`
	UpdateScope     string `json:"update_scope"`
	ExternalWebRoot bool   `json:"external_web_root"`
	CanApply        bool   `json:"can_apply"`
	UpdateRunning   bool   `json:"update_running"`
	Warning         string `json:"warning,omitempty"`
}

// GitHubRelease 表示版本的 GitHub API 响应
type GitHubRelease struct {
	TagName string               `json:"tag_name"`
	HTMLURL string               `json:"html_url"`
	Body    string               `json:"body"`
	Assets  []GitHubReleaseAsset `json:"assets"`
}

type GitHubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

func detectUpdateEnvironment(docker bool, externalWebRoot string) updateEnvironment {
	external := strings.TrimSpace(externalWebRoot) != ""
	if docker {
		return updateEnvironment{
			DeploymentMode:  updateDeploymentDocker,
			UpdateScope:     updateScopeNone,
			ExternalWebRoot: external,
			CanApply:        false,
			Warning:         "Docker 部署不能在容器内原地更新，请在宿主机执行 docker compose pull && docker compose up -d。",
		}
	}

	environment := updateEnvironment{
		DeploymentMode:  updateDeploymentStandalone,
		UpdateScope:     updateScopeFull,
		ExternalWebRoot: external,
		CanApply:        true,
	}
	if external {
		environment.UpdateScope = updateScopeBackendOnly
		environment.Warning = "当前使用外置前端目录，外置前端需单独发布。"
	}
	if runtime.GOOS == "windows" {
		environment.UpdateScope = updateScopeNone
		environment.CanApply = false
		environment.Warning = appendUpdateWarning(environment.Warning, "Windows 暂不支持网页内原地更新，请下载新版本后手动替换。")
	}
	return environment
}

func currentUpdateEnvironment() updateEnvironment {
	environment := detectUpdateEnvironment(isDocker(), os.Getenv("ARCWAY_WEB_ROOT"))
	environment = populateGuardEnvironment(environment, os.Getenv("ARCWAY_GUARD_ASSET_DIR"))
	return populateAgentEnvironment(environment, os.Getenv("ARCWAY_AGENT_ASSET_DIR"))
}

func populateGuardEnvironment(environment updateEnvironment, guardAssetDir string) updateEnvironment {
	if environment.DeploymentMode == updateDeploymentDocker {
		return environment
	}
	guardAssetDir = strings.TrimSpace(guardAssetDir)
	if guardAssetDir == "" {
		if environment.UpdateScope == updateScopeFull {
			environment.UpdateScope = updateScopeControlPlane
		}
		environment.Warning = appendUpdateWarning(environment.Warning, "未配置守卫资产目录，本次只能更新控制端程序和面板；守卫资产需通过安装脚本更新。")
		return environment
	}
	if !filepath.IsAbs(guardAssetDir) {
		environment.CanApply = false
		environment.UpdateScope = updateScopeNone
		environment.Warning = appendUpdateWarning(environment.Warning, "ARCWAY_GUARD_ASSET_DIR 必须是绝对路径，网页更新已禁用。")
		return environment
	}
	if environment.ExternalWebRoot && environment.CanApply {
		environment.Warning = "本次会更新控制端程序和守卫资产；外置前端需单独发布。"
	}
	var missing []string
	for _, arch := range []string{"amd64", "arm64"} {
		name := "arcway-expiry-guard-linux-" + arch
		if info, err := os.Stat(filepath.Join(guardAssetDir, name)); err != nil || !info.Mode().IsRegular() {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		environment.Warning = appendUpdateWarning(environment.Warning, "当前守卫资产不完整，将在本次更新中补齐："+strings.Join(missing, "、")+"。")
	}
	return environment
}

func populateAgentEnvironment(environment updateEnvironment, agentAssetDir string) updateEnvironment {
	if environment.DeploymentMode == updateDeploymentDocker {
		return environment
	}
	agentAssetDir = strings.TrimSpace(agentAssetDir)
	if agentAssetDir == "" {
		if environment.UpdateScope == updateScopeFull {
			environment.UpdateScope = updateScopeControlPlane
		}
		environment.Warning = appendUpdateWarning(environment.Warning, "未配置 Agent 资产目录，本次只能更新控制端程序和面板；Agent 安装资产需通过安装脚本更新。")
		return environment
	}
	if !filepath.IsAbs(agentAssetDir) {
		environment.CanApply = false
		environment.UpdateScope = updateScopeNone
		environment.Warning = appendUpdateWarning(environment.Warning, "ARCWAY_AGENT_ASSET_DIR 必须是绝对路径，网页更新已禁用。")
		return environment
	}
	if environment.ExternalWebRoot && environment.CanApply {
		environment.Warning = appendUpdateWarning(environment.Warning, "本次也会更新 Agent 安装资产。")
	}
	var missing []string
	for _, arch := range []string{"amd64", "arm64"} {
		name := "mmw-agent-linux-" + arch
		if info, err := os.Stat(filepath.Join(agentAssetDir, name)); err != nil || !info.Mode().IsRegular() {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		environment.Warning = appendUpdateWarning(environment.Warning, "当前 Agent 安装资产不完整，将在本次更新中补齐："+strings.Join(missing, "、")+"。")
	}
	return environment
}

func populateUpdateEnvironment(info *UpdateInfo, environment updateEnvironment) {
	info.DeploymentMode = environment.DeploymentMode
	info.UpdateScope = environment.UpdateScope
	info.ExternalWebRoot = environment.ExternalWebRoot
	info.CanApply = environment.CanApply
	info.Warning = environment.Warning
	if info.DownloadURL == "" {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, "当前发布没有适用于本机系统和架构的安装包。")
	}
	if info.guardAssetDir != "" && len(info.missingGuards) > 0 {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, "最新发布缺少守卫资产 "+strings.Join(info.missingGuards, "、")+"；为避免版本不一致，网页更新已禁用。")
	}
	if info.agentAssetDir != "" && len(info.missingAgents) > 0 {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, "最新发布缺少 Agent 安装资产 "+strings.Join(info.missingAgents, "、")+"；为避免版本不一致，网页更新已禁用。")
	}
}

func appendUpdateWarning(current, extra string) string {
	current = strings.TrimSpace(current)
	extra = strings.TrimSpace(extra)
	if current == "" {
		return extra
	}
	if extra == "" {
		return current
	}
	return current + " " + extra
}

func beginUpdate() bool {
	return updateInProgress.CompareAndSwap(false, true)
}

func finishUpdate() {
	updateInProgress.Store(false)
}

func beginUpdateSession() (*systemUpdateLock, error) {
	if !beginUpdate() {
		return nil, errUpdateBusy
	}
	lock, err := acquireSystemUpdateLock()
	if err != nil {
		finishUpdate()
		return nil, err
	}
	return lock, nil
}

func finishUpdateSession(lock *systemUpdateLock) {
	if lock != nil {
		if err := lock.Close(); err != nil {
			logger.Warn("[系统更新] 释放安装锁失败", "error", err)
		}
	}
	finishUpdate()
}

func validateRequestedVersion(r *http.Request, info *UpdateInfo) error {
	requested := strings.TrimSpace(strings.TrimPrefix(r.URL.Query().Get("version"), "v"))
	if requested == "" {
		return nil
	}
	if requested != info.LatestVersion {
		return fmt.Errorf("最新版本已从 %s 变为 %s，请重新检查并确认", requested, info.LatestVersion)
	}
	return nil
}

func validateUpdateForApply(info *UpdateInfo) error {
	if !info.CanApply {
		if info.Warning != "" {
			return errors.New(info.Warning)
		}
		return errors.New("当前部署方式不支持网页内更新")
	}
	if info.DownloadURL == "" {
		return errors.New("未找到适合当前系统的下载链接")
	}
	if len(info.expectedSHA256) != sha256.Size*2 {
		return errors.New("发布包缺少有效的 SHA-256 校验值")
	}
	return nil
}

func updateCompletionMessages(info *UpdateInfo) (string, string) {
	components := "控制端程序"
	if !info.ExternalWebRoot {
		components += "与内嵌面板"
	}
	if len(info.guardAssets) == 2 {
		components += "及守卫资产"
	}
	if len(info.agentAssets) == 2 {
		components += "、Agent 安装资产"
	}
	done := components + "更新完成"
	if info.ExternalWebRoot {
		done += "；外置前端未更新"
	}
	return done + "，正在重启服务...", done
}

// NewUpdateStatusHandler reports local updater state without contacting GitHub.
func NewUpdateStatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeUpdateError(w, http.StatusMethodNotAllowed, errors.New("only GET is supported"))
			return
		}
		environment := currentUpdateEnvironment()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(UpdateStatus{
			CurrentVersion:  version.Version,
			DeploymentMode:  environment.DeploymentMode,
			UpdateScope:     environment.UpdateScope,
			ExternalWebRoot: environment.ExternalWebRoot,
			CanApply:        environment.CanApply,
			UpdateRunning:   updateInProgress.Load(),
			Warning:         environment.Warning,
		})
	})
}

// 返回一个检查更新的处理程序
func NewUpdateCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeUpdateError(w, http.StatusMethodNotAllowed, errors.New("only GET is supported"))
			return
		}

		info, err := checkLatestVersion()
		if err != nil {
			writeUpdateError(w, http.StatusInternalServerError, fmt.Errorf("检查更新失败: %w", err))
			return
		}
		populateUpdateEnvironment(info, currentUpdateEnvironment())

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(info)
	})
}

// 返回应用更新的处理程序
func NewUpdateApplyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeUpdateError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}
		environment := currentUpdateEnvironment()
		if !environment.CanApply {
			writeUpdateError(w, http.StatusConflict, errors.New(environment.Warning))
			return
		}
		updateLock, err := beginUpdateSession()
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errUpdateBusy) {
				status = http.StatusConflict
			}
			writeUpdateError(w, status, err)
			return
		}
		restartScheduled := false
		defer func() {
			if !restartScheduled {
				finishUpdateSession(updateLock)
			}
		}()

		// 1.获取最新版本信息
		info, err := checkLatestVersion()
		if err != nil {
			writeUpdateError(w, http.StatusBadGateway, fmt.Errorf("检查更新失败: %w", err))
			return
		}
		populateUpdateEnvironment(info, environment)
		if err := validateRequestedVersion(r, info); err != nil {
			writeUpdateError(w, http.StatusConflict, err)
			return
		}

		if !info.HasUpdate {
			writeUpdateError(w, http.StatusBadRequest, errors.New("已是最新版本"))
			return
		}

		if err := validateUpdateForApply(info); err != nil {
			writeUpdateError(w, http.StatusConflict, err)
			return
		}

		// 2. 将新的二进制文件下载到临时文件
		logger.Info("[系统更新] 开始下载更新", "url", info.DownloadURL)
		tempFile, err := downloadBinary(info.DownloadURL)
		if err != nil {
			writeUpdateError(w, http.StatusInternalServerError, fmt.Errorf("下载失败: %w", err))
			return
		}
		defer os.Remove(tempFile)
		if err := verifyBinaryChecksum(tempFile, info.expectedSHA256); err != nil {
			writeUpdateError(w, http.StatusBadGateway, fmt.Errorf("更新包校验失败: %w", err))
			return
		}
		if err := verifyBinaryFormat(tempFile); err != nil {
			writeUpdateError(w, http.StatusBadGateway, fmt.Errorf("更新包格式校验失败: %w", err))
			return
		}
		guardFiles, cleanupGuards, err := prepareGuardUpdateFiles(info, nil)
		if err != nil {
			writeUpdateError(w, http.StatusBadGateway, fmt.Errorf("准备守卫资产失败，尚未替换任何文件: %w", err))
			return
		}
		defer cleanupGuards()
		agentFiles, cleanupAgents, err := prepareAgentUpdateFiles(info, nil)
		if err != nil {
			writeUpdateError(w, http.StatusBadGateway, fmt.Errorf("准备 Agent 安装资产失败，尚未替换任何文件: %w", err))
			return
		}
		defer cleanupAgents()

		// 3. 获取二进制文件的目标路径
		targetPath, err := getUpdateTargetPath()
		if err != nil {
			writeUpdateError(w, http.StatusInternalServerError, fmt.Errorf("获取程序路径失败: %w", err))
			return
		}

		// 4. 所有发布文件校验完成后，再统一备份和替换。
		files := append(guardFiles, agentFiles...)
		files = append(files, preparedUpdateFile{
			Name:       "arcway",
			SourcePath: tempFile,
			TargetPath: targetPath,
			BackupPath: targetPath + ".bak",
		})
		if err := backupUpdateFiles(files); err != nil {
			writeUpdateError(w, http.StatusInternalServerError, fmt.Errorf("备份当前版本失败，已取消更新: %w", err))
			return
		}

		// 5. 守卫资产先替换、主程序最后替换；任一失败会恢复此前文件。
		logger.Info("[系统更新] 正在替换更新文件", "file_count", len(files))
		if err := installUpdateFiles(files); err != nil {
			writeUpdateError(w, http.StatusInternalServerError, fmt.Errorf("替换失败: %w", err))
			return
		}

		logger.Info("[系统更新] 更新成功，准备重启服务器")

		// 7.返回成功响应
		message, _ := updateCompletionMessages(info)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":       "success",
			"message":      message,
			"update_scope": info.UpdateScope,
			"warning":      info.Warning,
		})

		// 8.异步重启（给客户端时间接收响应）
		restartScheduled = true
		go func() {
			defer finishUpdateSession(updateLock)
			time.Sleep(500 * time.Millisecond)
			restartWithRollback(targetPath, files)
		}()
	})
}

// 返回一个处理程序，该处理程序根据 SSE 进度应用更新
func NewUpdateApplySSEHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeUpdateError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}
		environment := currentUpdateEnvironment()
		if !environment.CanApply {
			writeUpdateError(w, http.StatusConflict, errors.New(environment.Warning))
			return
		}
		updateLock, err := beginUpdateSession()
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errUpdateBusy) {
				status = http.StatusConflict
			}
			writeUpdateError(w, status, err)
			return
		}
		restartScheduled := false
		defer func() {
			if !restartScheduled {
				finishUpdateSession(updateLock)
			}
		}()

		// 设置 SSE 标头
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // 禁用 nginx 缓冲

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "SSE not supported", http.StatusInternalServerError)
			return
		}

		// 发送进度的助手
		sendProgress := func(step string, progress int, message string) {
			p := UpdateProgress{Step: step, Progress: progress, Message: message}
			data, _ := json.Marshal(p)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}

		// 1.检查版本
		sendProgress("checking", 0, "正在检查版本信息...")

		force := r.URL.Query().Get("force") == "true"

		info, err := checkLatestVersion()
		if err != nil {
			sendProgress("error", 0, fmt.Sprintf("检查更新失败: %v", err))
			return
		}
		populateUpdateEnvironment(info, environment)
		if err := validateRequestedVersion(r, info); err != nil {
			sendProgress("error", 0, err.Error())
			return
		}

		if !info.HasUpdate && !force {
			sendProgress("error", 0, "已是最新版本")
			return
		}

		if err := validateUpdateForApply(info); err != nil {
			sendProgress("error", 0, err.Error())
			return
		}

		// 2.有进度下载
		sendProgress("downloading", 0, "正在下载更新...")
		logger.Info("[系统更新] 开始下载更新", "url", info.DownloadURL)

		lastProgress := 0
		tempFile, err := downloadBinaryWithProgressAndRetry(info.DownloadURL, func(downloaded, total int64) {
			progress := int(downloaded * 100 / total)
			// 仅每 5% 发送一次更新以减少流量
			if progress >= lastProgress+5 || progress == 100 {
				lastProgress = progress
				sendProgress("downloading", progress, fmt.Sprintf("正在下载... %d%%", progress))
			}
		}, func(_ string) {
			// 官方源重试时重置进度并提示用户
			lastProgress = 0
			sendProgress("downloading", 0, "下载中断，正在从 GitHub 官方源重试...")
		})
		if err != nil {
			sendProgress("error", 0, fmt.Sprintf("下载失败: %v", err))
			return
		}
		defer os.Remove(tempFile)
		if err := verifyBinaryChecksum(tempFile, info.expectedSHA256); err != nil {
			sendProgress("error", 0, fmt.Sprintf("更新包校验失败: %v", err))
			return
		}
		if err := verifyBinaryFormat(tempFile); err != nil {
			sendProgress("error", 0, fmt.Sprintf("更新包格式校验失败: %v", err))
			return
		}
		guardFiles, cleanupGuards, err := prepareGuardUpdateFiles(info, func(name string) {
			sendProgress("downloading", 100, "正在下载并校验守卫资产 "+name+"...")
		})
		if err != nil {
			sendProgress("error", 0, fmt.Sprintf("准备守卫资产失败，尚未替换任何文件: %v", err))
			return
		}
		defer cleanupGuards()
		agentFiles, cleanupAgents, err := prepareAgentUpdateFiles(info, func(name string) {
			sendProgress("downloading", 100, "正在下载并校验 Agent 安装资产 "+name+"...")
		})
		if err != nil {
			sendProgress("error", 0, fmt.Sprintf("准备 Agent 安装资产失败，尚未替换任何文件: %v", err))
			return
		}
		defer cleanupAgents()

		// 3. 获取目标路径
		targetPath, err := getUpdateTargetPath()
		if err != nil {
			sendProgress("error", 0, fmt.Sprintf("获取程序路径失败: %v", err))
			return
		}

		// 4. 所有发布文件校验完成后，再统一备份和替换。
		sendProgress("backing_up", 0, "正在备份控制端程序与配套资产...")
		files := append(guardFiles, agentFiles...)
		files = append(files, preparedUpdateFile{
			Name:       "arcway",
			SourcePath: tempFile,
			TargetPath: targetPath,
			BackupPath: targetPath + ".bak",
		})
		if err := backupUpdateFiles(files); err != nil {
			sendProgress("error", 0, fmt.Sprintf("备份当前版本失败，已取消更新: %v", err))
			return
		}

		// 5. 守卫资产先替换、主程序最后替换；任一失败会恢复此前文件。
		sendProgress("replacing", 0, "正在原子替换控制端程序与配套资产...")
		logger.Info("[系统更新] 正在替换更新文件", "file_count", len(files))
		if err := installUpdateFiles(files); err != nil {
			sendProgress("error", 0, fmt.Sprintf("替换失败: %v", err))
			return
		}

		// 7.发送重启状态
		restartMessage, doneMessage := updateCompletionMessages(info)
		sendProgress("restarting", 0, restartMessage)
		logger.Info("[系统更新] 更新成功，准备重启服务器")

		// 8. 发送完成状态
		sendProgress("done", 100, doneMessage)

		// 9.异步重启（给客户端时间接收响应）
		restartScheduled = true
		go func() {
			defer finishUpdateSession(updateLock)
			time.Sleep(500 * time.Millisecond)
			restartWithRollback(targetPath, files)
		}()
	})
}

// 从 GitHub 获取最新版本信息
func checkLatestVersion() (*UpdateInfo, error) {
	url := fmt.Sprintf(githubAPIURL, githubRepo)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "arcway-updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API 返回状态码: %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("解析 GitHub 响应失败: %w", err)
	}
	if !releaseTagPattern.MatchString(strings.TrimSpace(release.TagName)) {
		return nil, fmt.Errorf("GitHub 最新发布标签无效: %q", release.TagName)
	}
	release.TagName = strings.TrimSpace(release.TagName)
	if err := validateGitHubURL(release.HTMLURL, "/"+githubRepo+"/releases/tag/"+release.TagName); err != nil {
		return nil, fmt.Errorf("GitHub 发布页面地址无效: %w", err)
	}

	// 根据当前操作系统/架构选择下载 URL
	arch := runtime.GOARCH
	osName := runtime.GOOS
	binaryName := fmt.Sprintf("arcway-%s-%s", osName, arch)
	if osName == "windows" {
		binaryName += ".exe"
	}

	var downloadURL, expectedSHA256 string
	downloadURL, expectedSHA256, err = selectReleaseAsset(release, binaryName)
	if err != nil {
		return nil, err
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	hasUpdate := compareVersions(version.Version, latestVersion)

	info := &UpdateInfo{
		CurrentVersion: version.Version,
		LatestVersion:  latestVersion,
		HasUpdate:      hasUpdate,
		ReleaseURL:     release.HTMLURL,
		DownloadURL:    downloadURL,
		ReleaseNotes:   release.Body,
		expectedSHA256: expectedSHA256,
		guardAssetDir:  strings.TrimSpace(os.Getenv("ARCWAY_GUARD_ASSET_DIR")),
		agentAssetDir:  strings.TrimSpace(os.Getenv("ARCWAY_AGENT_ASSET_DIR")),
	}
	if info.guardAssetDir != "" {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "arcway-expiry-guard-linux-" + arch
			assetURL, digest, assetErr := selectReleaseAsset(release, name)
			if assetErr != nil {
				return nil, assetErr
			}
			if assetURL == "" {
				info.missingGuards = append(info.missingGuards, name)
				continue
			}
			info.guardAssets = append(info.guardAssets, updateReleaseAsset{
				Name:        name,
				DownloadURL: assetURL,
				SHA256:      digest,
				TargetPath:  filepath.Join(info.guardAssetDir, name),
				GOOS:        "linux",
				GOARCH:      arch,
			})
		}
	}
	if info.agentAssetDir != "" {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "mmw-agent-linux-" + arch
			assetURL, digest, assetErr := selectReleaseAsset(release, name)
			if assetErr != nil {
				return nil, assetErr
			}
			if assetURL == "" {
				info.missingAgents = append(info.missingAgents, name)
				continue
			}
			info.agentAssets = append(info.agentAssets, updateReleaseAsset{
				Name:        name,
				DownloadURL: assetURL,
				SHA256:      digest,
				TargetPath:  filepath.Join(info.agentAssetDir, name),
				GOOS:        "linux",
				GOARCH:      arch,
			})
		}
	}
	return info, nil
}

func selectReleaseAsset(release GitHubRelease, binaryName string) (string, string, error) {
	for _, asset := range release.Assets {
		if asset.Name != binaryName {
			continue
		}
		expectedPath := "/" + githubRepo + "/releases/download/" + release.TagName + "/" + binaryName
		if err := validateGitHubURL(asset.BrowserDownloadURL, expectedPath); err != nil {
			return "", "", fmt.Errorf("GitHub 发布包地址无效: %w", err)
		}
		digest := strings.TrimSpace(asset.Digest)
		if !strings.HasPrefix(digest, "sha256:") || !sha256Pattern.MatchString(strings.TrimPrefix(digest, "sha256:")) {
			return "", "", fmt.Errorf("GitHub 发布包 %s 缺少有效的 SHA-256 digest", binaryName)
		}
		return asset.BrowserDownloadURL, strings.ToLower(strings.TrimPrefix(digest, "sha256:")), nil
	}
	return "", "", nil
}

func validateGitHubURL(rawURL, expectedPath string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), "github.com") || parsed.Port() != "" || parsed.User != nil {
		return errors.New("必须是 github.com 的 HTTPS 地址")
	}
	if parsed.Path != expectedPath || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("路径与发布内容不匹配: %s", parsed.Path)
	}
	return nil
}

// 如果最新 > 当前，compareVersions 返回 true
func compareVersions(current, latest string) bool {
	currentParts := parseVersion(current)
	latestParts := parseVersion(latest)

	for i := 0; i < len(latestParts) || i < len(currentParts); i++ {
		var cp, lp int
		if i < len(currentParts) {
			cp = currentParts[i]
		}
		if i < len(latestParts) {
			lp = latestParts[i]
		}

		if lp > cp {
			return true
		}
		if lp < cp {
			return false
		}
	}
	return false
}

// 将版本字符串拆分为整数部分
func parseVersion(v string) []int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	result := make([]int, len(parts))
	for i, p := range parts {
		var num int
		fmt.Sscanf(p, "%d", &num)
		result[i] = num
	}
	return result
}

// downloadBinary 将二进制文件下载到临时文件。

func downloadBinary(url string) (string, error) {
	return downloadBinaryWithProgress(url, nil)
}

// downloadBinaryWithProgress 使用进度回调将二进制文件下载到临时文件
// 如果直接下载失败或超时，会从 GitHub 官方地址重试。
func downloadBinaryWithProgress(url string, onProgress func(downloaded, total int64)) (string, error) {
	return downloadBinaryWithProgressAndRetry(url, onProgress, nil)
}

// 下载二进制文件，支持进度回调和重试通知
func downloadBinaryWithProgressAndRetry(url string, onProgress func(downloaded, total int64), onRetry func(proxyURL string)) (string, error) {
	// 首先尝试直接下载，使用较短的超时时间
	tempFile, err := downloadBinaryDirect(url, onProgress, 60*time.Second)
	if err == nil {
		return tempFile, nil
	}

	logger.Warn("[系统更新] GitHub 下载中断，尝试官方源重试", "error", err)

	// 通知切换到代理
	if onRetry != nil {
		onRetry(url)
	}

	tempFile, err = downloadBinaryDirect(url, onProgress, 5*time.Minute)
	if err != nil {
		return "", fmt.Errorf("GitHub 官方源重试失败: %w", err)
	}

	return tempFile, nil
}

func prepareGuardUpdateFiles(info *UpdateInfo, onAsset func(name string)) ([]preparedUpdateFile, func(), error) {
	return prepareManagedUpdateFiles("守卫", info.guardAssetDir, info.guardAssets, onAsset)
}

func prepareAgentUpdateFiles(info *UpdateInfo, onAsset func(name string)) ([]preparedUpdateFile, func(), error) {
	return prepareManagedUpdateFiles("Agent", info.agentAssetDir, info.agentAssets, onAsset)
}

func prepareManagedUpdateFiles(label, assetDir string, assets []updateReleaseAsset, onAsset func(name string)) ([]preparedUpdateFile, func(), error) {
	cleanupPaths := make([]string, 0, len(assets))
	cleanup := func() {
		for _, path := range cleanupPaths {
			_ = os.Remove(path)
		}
	}
	if assetDir == "" {
		return nil, cleanup, nil
	}
	if len(assets) != 2 {
		return nil, cleanup, fmt.Errorf("%s 发布资产不完整", label)
	}
	if !filepath.IsAbs(assetDir) {
		return nil, cleanup, fmt.Errorf("%s 资产目录必须是绝对路径", label)
	}
	if err := os.MkdirAll(assetDir, 0755); err != nil {
		return nil, cleanup, fmt.Errorf("创建%s资产目录: %w", label, err)
	}

	files := make([]preparedUpdateFile, 0, len(assets))
	for _, asset := range assets {
		if onAsset != nil {
			onAsset(asset.Name)
		}
		tempPath, err := downloadBinary(asset.DownloadURL)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("下载 %s: %w", asset.Name, err)
		}
		cleanupPaths = append(cleanupPaths, tempPath)
		if err := verifyBinaryChecksum(tempPath, asset.SHA256); err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("校验 %s: %w", asset.Name, err)
		}
		if err := verifyBinaryFormatFor(tempPath, asset.GOOS, asset.GOARCH); err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("校验 %s 格式: %w", asset.Name, err)
		}
		files = append(files, preparedUpdateFile{
			Name:       asset.Name,
			SourcePath: tempPath,
			TargetPath: asset.TargetPath,
			BackupPath: asset.TargetPath + ".bak",
		})
	}
	return files, cleanup, nil
}

func verifyBinaryChecksum(path, expected string) error {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if len(expected) != sha256.Size*2 {
		return errors.New("GitHub release 未提供有效的 SHA-256 digest")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := fmt.Sprintf("%x", h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("SHA-256 不匹配: got %s", actual)
	}
	return nil
}

func verifyBinaryFormat(path string) error {
	return verifyBinaryFormatFor(path, runtime.GOOS, runtime.GOARCH)
}

func verifyBinaryFormatFor(path, goos, goarch string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch goos {
	case "linux":
		header := make([]byte, 20)
		if _, err := io.ReadFull(f, header); err != nil {
			return fmt.Errorf("读取 ELF 文件头: %w", err)
		}
		if string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 {
			return errors.New("不是 64 位 little-endian ELF 可执行文件")
		}
		machine := binary.LittleEndian.Uint16(header[18:20])
		expected := map[string]uint16{"amd64": 62, "arm64": 183}[goarch]
		if expected == 0 || machine != expected {
			return fmt.Errorf("ELF 架构不匹配: machine=%d, expected=%s", machine, goarch)
		}
	case "darwin":
		header := make([]byte, 12)
		if _, err := io.ReadFull(f, header); err != nil {
			return fmt.Errorf("读取 Mach-O 文件头: %w", err)
		}
		if binary.LittleEndian.Uint32(header[:4]) != 0xfeedfacf {
			return errors.New("不是 64 位 Mach-O 可执行文件")
		}
		cpu := binary.LittleEndian.Uint32(header[4:8])
		expected := map[string]uint32{"amd64": 0x01000007, "arm64": 0x0100000c}[goarch]
		if expected == 0 || cpu != expected {
			return fmt.Errorf("Mach-O 架构不匹配: cpu=%#x, expected=%s", cpu, goarch)
		}
	case "windows":
		header := make([]byte, 64)
		if _, err := io.ReadFull(f, header); err != nil {
			return fmt.Errorf("读取 PE 文件头: %w", err)
		}
		if string(header[:2]) != "MZ" {
			return errors.New("不是 PE 可执行文件")
		}
		peOffset := int64(binary.LittleEndian.Uint32(header[0x3c:0x40]))
		peHeader := make([]byte, 6)
		if _, err := f.ReadAt(peHeader, peOffset); err != nil {
			return fmt.Errorf("读取 PE 签名: %w", err)
		}
		if string(peHeader[:4]) != "PE\x00\x00" {
			return errors.New("PE 签名无效")
		}
		machine := binary.LittleEndian.Uint16(peHeader[4:6])
		expected := map[string]uint16{"amd64": 0x8664, "arm64": 0xaa64}[goarch]
		if expected == 0 || machine != expected {
			return fmt.Errorf("PE 架构不匹配: machine=%#x, expected=%s", machine, goarch)
		}
	default:
		return fmt.Errorf("不支持校验 %s 可执行文件", goos)
	}
	return nil
}

// 直接下载二进制文件（不含重试逻辑）
func downloadBinaryDirect(url string, onProgress func(downloaded, total int64), timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载返回状态码: %d", resp.StatusCode)
	}
	if resp.ContentLength > maxUpdateBinarySize {
		return "", fmt.Errorf("更新包过大: %d bytes", resp.ContentLength)
	}

	tempFile, err := os.CreateTemp("", "arcway-update-*")
	if err != nil {
		return "", err
	}

	totalSize := resp.ContentLength
	var downloaded int64

	limitedBody := io.LimitReader(resp.Body, maxUpdateBinarySize+1)

	// 如果没有进度回调或未知大小，请使用简单复制
	if onProgress == nil || totalSize <= 0 {
		written, err := io.Copy(tempFile, limitedBody)
		if err != nil {
			tempFile.Close()
			os.Remove(tempFile.Name())
			return "", err
		}
		if written > maxUpdateBinarySize {
			tempFile.Close()
			os.Remove(tempFile.Name())
			return "", errors.New("更新包超过 256 MiB 限制")
		}
	} else {
		// 复制并跟踪进度
		buf := make([]byte, 32*1024) // 32KB缓冲区
		for {
			n, readErr := limitedBody.Read(buf)
			if n > 0 {
				if _, writeErr := tempFile.Write(buf[:n]); writeErr != nil {
					tempFile.Close()
					os.Remove(tempFile.Name())
					return "", writeErr
				}
				downloaded += int64(n)
				onProgress(downloaded, totalSize)
			}
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				tempFile.Close()
				os.Remove(tempFile.Name())
				return "", readErr
			}
		}
		if downloaded > maxUpdateBinarySize {
			tempFile.Close()
			os.Remove(tempFile.Name())
			return "", errors.New("更新包超过 256 MiB 限制")
		}
	}

	tempFile.Close()
	return tempFile.Name(), nil
}

// 返回二进制文件应放置的路径
func getUpdateTargetPath() (string, error) {
	if isDocker() {
		return "", errors.New("Docker 部署不能在容器内原地更新")
	}

	// 非 Docker：获取当前可执行路径
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", err
	}
	return execPath, nil
}

// 检查是否在 Docker 容器内运行
func isDocker() bool {
	// 检查 /.dockerenv 文件
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// 检查 DOCKER 环境变量
	if os.Getenv("DOCKER") == "1" {
		return true
	}

	// 检查 docker 的 cgroup
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil && strings.Contains(string(data), "docker") {
		return true
	}

	return false
}

// replaceBinary 将新文件先写入目标目录，再用 rename 原子替换当前程序。
func replaceBinary(src, dst string) error {
	return copyFileAtomically(src, dst, 0755)
}

// copyFile 保留源文件权限，并通过同目录临时文件原子写入目标。
func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return copyFileAtomically(src, dst, info.Mode().Perm())
}

func copyFileAtomically(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destinationDir := filepath.Dir(dst)
	tempFile, err := os.CreateTemp(destinationDir, ".arcway-update-*")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	committed := false
	defer func() {
		_ = tempFile.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(mode); err != nil {
		return err
	}
	if _, err := io.Copy(tempFile, srcFile); err != nil {
		return err
	}
	if err := tempFile.Sync(); err != nil {
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, dst); err != nil {
		return err
	}
	committed = true
	if dir, err := os.Open(destinationDir); err == nil {
		if syncErr := dir.Sync(); syncErr != nil {
			logger.Warn("[系统更新] 同步程序目录失败", "path", destinationDir, "error", syncErr)
		}
		_ = dir.Close()
	}
	return nil
}

func backupUpdateFiles(files []preparedUpdateFile) error {
	for i := range files {
		info, err := os.Stat(files[i].TargetPath)
		if err != nil {
			if os.IsNotExist(err) {
				files[i].HadTarget = false
				continue
			}
			return fmt.Errorf("检查 %s 当前文件: %w", files[i].Name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s 当前路径不是普通文件: %s", files[i].Name, files[i].TargetPath)
		}
		files[i].HadTarget = true
		if err := copyFile(files[i].TargetPath, files[i].BackupPath); err != nil {
			return fmt.Errorf("备份 %s: %w", files[i].Name, err)
		}
	}
	return nil
}

func installUpdateFiles(files []preparedUpdateFile) error {
	for i := range files {
		if err := replaceBinary(files[i].SourcePath, files[i].TargetPath); err != nil {
			installErr := fmt.Errorf("替换 %s: %w", files[i].Name, err)
			if rollbackErr := rollbackUpdateFiles(files[:i]); rollbackErr != nil {
				return errors.Join(installErr, fmt.Errorf("恢复已替换文件: %w", rollbackErr))
			}
			return installErr
		}
	}
	return nil
}

func rollbackUpdateFiles(files []preparedUpdateFile) error {
	var rollbackErrors []error
	for i := len(files) - 1; i >= 0; i-- {
		file := files[i]
		if file.HadTarget {
			if err := replaceBinary(file.BackupPath, file.TargetPath); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("恢复 %s: %w", file.Name, err))
			}
			continue
		}
		if err := os.Remove(file.TargetPath); err != nil && !os.IsNotExist(err) {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("移除新增的 %s: %w", file.Name, err))
		}
	}
	return errors.Join(rollbackErrors...)
}

// 重新启动当前进程
func restartSelf(execPath string) error {
	logger.Info("[系统重启] 正在重启服务器", "exec_path", execPath)

	// 只使用 Exec 原位替换，保持 systemd 跟踪的主 PID 不变。失败时当前旧进程仍在
	// 内存中运行，由 restartWithRollback 恢复磁盘上的旧二进制；不能另起子进程，
	// 否则 systemd 可能同时重启主服务并留下子进程，造成端口冲突。
	if err := execProcess(execPath, os.Args, os.Environ()); err != nil {
		return fmt.Errorf("syscall.Exec 失败: %w", err)
	}
	return nil
}

func restartWithRollback(execPath string, files []preparedUpdateFile) {
	if err := restartSelf(execPath); err != nil {
		logger.Error("[系统重启] 新版本启动失败，正在恢复旧版本", "error", err)
		if rollbackErr := rollbackUpdateFiles(files); rollbackErr != nil {
			logger.Error("[系统重启] 更新文件恢复失败，需要手工处理", "error", rollbackErr)
			return
		}
		logger.Warn("[系统重启] 已恢复主程序与守卫资产，当前进程继续运行")
	}
}

func writeUpdateError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}
