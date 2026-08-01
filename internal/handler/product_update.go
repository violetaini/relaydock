package handler

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/productrelease"
	"github.com/violetaini/relaydock/internal/version"
)

const (
	productUpdateJobSchema       = 1
	productUpdateJobFilename     = "active-transaction.json"
	productUpdateHealthPath      = "/api/internal/update-health"
	productUpdateWebHealthPath   = "/relaydock-release.json"
	productUpdateLockTimeout     = 30 * time.Second
	productUpdateStateDirEnv     = "ARCWAY_UPDATE_STATE_DIR"
	productUpdateSystemdUnitEnv  = "ARCWAY_SYSTEMD_UNIT"
	productUpdateHealthURLEnv    = "ARCWAY_UPDATE_HEALTH_URL"
	productUpdateWebHealthURLEnv = "ARCWAY_UPDATE_WEB_HEALTH_URL"
	productUpdateHelperFlag      = "arcway-update-helper"
)

var (
	productUpdateIDPattern      = regexp.MustCompile(`^[a-f0-9]{24}$`)
	productUpdateUnitPattern    = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`)
	productUpdateHealthTimeout  = 45 * time.Second
	productUpdateHealthInterval = time.Second
)

// ProductComponentStatus is returned to the panel so it can describe an
// intentionally frontend-only release instead of treating it as a failed
// backend version comparison.
type ProductComponentStatus struct {
	Name           string `json:"name"`
	Label          string `json:"label"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	Action         string `json:"action"`
	Status         string `json:"status"`
	Required       bool   `json:"required"`
	Compatible     bool   `json:"compatible"`
}

type productWebPreparation struct {
	Root     string                     `json:"root"`
	Staging  string                     `json:"staging"`
	Metadata productrelease.WebMetadata `json:"metadata"`
}

type productDatabaseBackup struct {
	Path       string `json:"path"`
	BackupPath string `json:"backup_path"`
	HadFile    bool   `json:"had_file"`
}

// productUpdateJob is deliberately self-contained. It is passed to a separate
// transient systemd service, so a failed replacement cannot leave the updater
// in the same service cgroup as the process it must restart and roll back.
type productUpdateJob struct {
	Schema          int                            `json:"schema"`
	ID              string                         `json:"id"`
	ReleaseID       string                         `json:"release_id"`
	Manifest        productrelease.Manifest        `json:"manifest"`
	InstalledState  productrelease.InstalledState  `json:"installed_state"`
	PreviousState   *productrelease.InstalledState `json:"previous_state,omitempty"`
	Files           []preparedUpdateFile           `json:"files"`
	Web             *productWebPreparation         `json:"web,omitempty"`
	Activation      *productrelease.WebActivation  `json:"activation,omitempty"`
	DatabaseBackups []productDatabaseBackup        `json:"database_backups,omitempty"`
	StateDir        string                         `json:"state_dir"`
	DataDirectory   string                         `json:"data_directory"`
	DatabasePath    string                         `json:"database_path,omitempty"`
	ServiceUnit     string                         `json:"service_unit"`
	HealthURL       string                         `json:"health_url"`
	WebHealthURL    string                         `json:"web_health_url,omitempty"`
	HealthToken     string                         `json:"health_token"`
	TargetVersion   string                         `json:"target_version"`
	HelperUnit      string                         `json:"helper_unit,omitempty"`
	RollbackReady   bool                           `json:"rollback_ready,omitempty"`
	FilesActivated  bool                           `json:"files_activated,omitempty"`
	StateRecorded   bool                           `json:"state_recorded,omitempty"`
	Phase           string                         `json:"phase"`
	Message         string                         `json:"message"`
	Error           string                         `json:"error,omitempty"`
	StartedAt       time.Time                      `json:"started_at"`
	UpdatedAt       time.Time                      `json:"updated_at"`
}

func (job productUpdateJob) Validate() error {
	if job.Schema != productUpdateJobSchema || !productUpdateIDPattern.MatchString(job.ID) {
		return errors.New("invalid product update transaction")
	}
	if job.StateDir == "" || !filepath.IsAbs(job.StateDir) || job.DataDirectory == "" || !filepath.IsAbs(job.DataDirectory) || job.ServiceUnit == "" || job.HealthURL == "" || len(job.HealthToken) != 64 {
		return errors.New("invalid product update transaction settings")
	}
	if job.HelperUnit != "" && !productUpdateUnitPattern.MatchString(job.HelperUnit) {
		return errors.New("invalid product update helper unit")
	}
	if job.DatabasePath != "" && !filepath.IsAbs(job.DatabasePath) {
		return errors.New("invalid product update database path")
	}
	if err := validateProductWebHealthURL(job.WebHealthURL); err != nil {
		return err
	}
	if err := job.Manifest.Validate(); err != nil {
		return err
	}
	if job.Manifest.ReleaseID != job.ReleaseID {
		return errors.New("product update release does not match manifest")
	}
	if err := job.InstalledState.Validate(); err != nil {
		return fmt.Errorf("invalid committed product state: %w", err)
	}
	if job.InstalledState.ReleaseID != job.ReleaseID {
		return errors.New("committed product state does not match manifest")
	}
	if job.PreviousState != nil {
		if err := job.PreviousState.Validate(); err != nil {
			return fmt.Errorf("invalid previous product state: %w", err)
		}
	}
	return nil
}

func productUpdateStateDir() (string, error) {
	if configured := strings.TrimSpace(os.Getenv(productUpdateStateDirEnv)); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("%s must be an absolute path", productUpdateStateDirEnv)
		}
		return filepath.Clean(configured), nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(filepath.Dir(executable)), "update"), nil
}

func productUpdateJobPath(stateDir string) string {
	return filepath.Join(stateDir, productUpdateJobFilename)
}

func writeProductUpdateJob(job productUpdateJob) error {
	if err := job.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(job.StateDir, 0700); err != nil {
		return err
	}
	job.UpdatedAt = time.Now().UTC()
	encoded, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	path := productUpdateJobPath(job.StateDir)
	temporary, err := os.CreateTemp(job.StateDir, ".active-transaction-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	if err := syncProductUpdateStateDirectory(job.StateDir); err != nil {
		return err
	}
	return nil
}

func syncProductUpdateStateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open update state directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync update state directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close update state directory: %w", err)
	}
	return nil
}

func loadProductUpdateJob(stateDir string) (productUpdateJob, error) {
	raw, err := os.ReadFile(productUpdateJobPath(stateDir))
	if err != nil {
		return productUpdateJob{}, err
	}
	var job productUpdateJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return productUpdateJob{}, fmt.Errorf("parse update transaction: %w", err)
	}
	if err := job.Validate(); err != nil {
		return productUpdateJob{}, err
	}
	return job, nil
}

func newProductUpdateID() (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func defaultSystemdUnit() string {
	if unit := strings.TrimSpace(os.Getenv(productUpdateSystemdUnitEnv)); unit != "" {
		return unit
	}
	return "arcway"
}

func defaultUpdateHealthURL() string {
	if raw := strings.TrimSpace(os.Getenv(productUpdateHealthURLEnv)); raw != "" {
		return strings.TrimRight(raw, "/") + productUpdateHealthPath
	}
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "12889"
	}
	return "http://127.0.0.1:" + port + productUpdateHealthPath
}

func defaultUpdateWebHealthURL() (string, error) {
	return normalizeProductWebHealthURL(os.Getenv(productUpdateWebHealthURLEnv))
}

func normalizeProductWebHealthURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", productUpdateWebHealthURLEnv, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must be an absolute HTTP(S) URL without credentials or fragment", productUpdateWebHealthURLEnv)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = productUpdateWebHealthPath
	}
	if parsed.Path != productUpdateWebHealthPath || parsed.RawQuery != "" {
		return "", fmt.Errorf("%s must point to %s", productUpdateWebHealthURLEnv, productUpdateWebHealthPath)
	}
	return parsed.String(), nil
}

func validateProductWebHealthURL(raw string) error {
	_, err := normalizeProductWebHealthURL(raw)
	if err != nil {
		return fmt.Errorf("invalid product web health URL: %w", err)
	}
	return nil
}

func updateTransactionStatus() (*productUpdateJob, error) {
	stateDir, err := productUpdateStateDir()
	if err != nil {
		return nil, err
	}
	job, err := loadProductUpdateJob(stateDir)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func setProductUpdatePhase(job *productUpdateJob, phase, message string) error {
	job.Phase = phase
	job.Message = message
	job.Error = ""
	return writeProductUpdateJob(*job)
}

func failProductUpdateJob(job *productUpdateJob, err error) error {
	job.Phase = "failed"
	job.Error = err.Error()
	job.Message = "更新失败，已保留当前已知可用版本"
	return writeProductUpdateJob(*job)
}

// NewUpdateHealthHandler accepts only a loopback request bearing the ephemeral
// token stored in the root-only transaction record. It is intentionally not a
// general public health endpoint.
func NewUpdateHealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !isLoopbackRequest(r) {
			http.NotFound(w, r)
			return
		}
		job, err := updateTransactionStatus()
		if err != nil || job.Phase != "waiting_for_health" {
			http.NotFound(w, r)
			return
		}
		token := r.Header.Get("X-Arcway-Update-Token")
		if len(token) != len(job.HealthToken) || subtle.ConstantTimeCompare([]byte(token), []byte(job.HealthToken)) != 1 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":      version.Version,
			"release_id":   job.ReleaseID,
			"api_contract": version.APIContract,
		})
	})
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

var productUpdateCommand = exec.CommandContext

func scheduleProductUpdate(job productUpdateJob) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	unit := productUpdateHelperUnit(job)
	command := productUpdateCommand(context.Background(), "systemd-run",
		"--no-block",
		"--quiet",
		"--collect",
		"--service-type=exec",
		"--property=Restart=on-abnormal",
		"--property=RestartSec=2s",
		"--unit="+unit,
		executable,
		"--"+productUpdateHelperFlag,
		productUpdateJobPath(job.StateDir),
	)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("schedule system update helper: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// ResumeProductUpdateOnStartup prevents a reboot from leaving an interrupted
// control-plane transaction permanently blocked. A surviving helper is left
// alone; otherwise a fresh helper is scheduled to either continue a pristine
// scheduled job or roll back every journaled mutation. The returned wait value
// tells main to stay out of the database until that helper stops this service.
func ResumeProductUpdateOnStartup() (wait bool, resultErr error) {
	stateDir, err := productUpdateStateDir()
	if err != nil {
		return false, err
	}
	job, err := loadProductUpdateJob(stateDir)
	if productrelease.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Keep the update UI locked, but never turn a manual-recovery record into a
	// boot loop. The control plane must start so an operator can inspect it.
	if strings.EqualFold(strings.TrimSpace(job.Phase), "recovery_required") {
		return false, nil
	}
	if productTransactionTerminal(job.Phase) {
		return false, nil
	}
	if len(job.Files) == 0 {
		if job.Web == nil {
			return false, markProductRecoveryRequired(&job, errors.New("frontend-only transaction has no frontend preparation"))
		}
		lock, err := acquireProductWebLockWithRetry(job.Web.Root)
		if err != nil {
			return false, markProductRecoveryRequired(&job, fmt.Errorf("lock interrupted frontend release: %w", err))
		}
		defer lock.Close()
		_ = recoverInterruptedProductUpdate(&job)
		recovered, loadErr := loadProductUpdateJob(stateDir)
		if loadErr != nil {
			return false, loadErr
		}
		if strings.EqualFold(strings.TrimSpace(recovered.Phase), "recovery_required") {
			// A web-only recovery cannot make the control-plane process unsafe.
			// Preserve the durable lock and let the operator reach the panel.
			return false, nil
		}
		if !productTransactionTerminal(recovered.Phase) {
			return false, fmt.Errorf("frontend transaction recovery did not reach a terminal state: %s", recovered.Phase)
		}
		return false, nil
	}
	if job.HelperUnit == "" {
		job.HelperUnit = productUpdateHelperUnit(job)
		if err := writeProductUpdateJob(job); err != nil {
			return false, err
		}
	}
	active, err := productUpdateHelperActive(job)
	if err != nil {
		return false, err
	}
	if active {
		return false, nil
	}
	if err := scheduleProductUpdate(job); err != nil {
		if !job.RollbackReady && !job.FilesActivated && job.Activation == nil && !job.StateRecorded {
			if recordErr := failProductUpdateJob(&job, fmt.Errorf("schedule interrupted product update recovery: %w", err)); recordErr != nil {
				return false, errors.Join(err, recordErr)
			}
			// No live component was changed. Let the systemd invocation that is
			// currently starting this binary continue with the known old release.
			return false, nil
		}
		return false, markProductRecoveryRequired(&job, fmt.Errorf("schedule interrupted product update recovery: %w", err))
	}
	return true, nil
}

func productUpdateHelperActive(job productUpdateJob) (bool, error) {
	command := productUpdateCommand(context.Background(), "systemctl", "is-active", "--quiet", productUpdateHelperUnit(job))
	if err := command.Run(); err == nil {
		return true, nil
	} else {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && (exitError.ExitCode() == 3 || exitError.ExitCode() == 4) {
			return false, nil
		}
		return false, fmt.Errorf("inspect product update helper: %w", err)
	}
}

func productUpdateHelperUnit(job productUpdateJob) string {
	if productUpdateUnitPattern.MatchString(job.HelperUnit) {
		return job.HelperUnit
	}
	return "arcway-update-" + job.ID
}

// RunProductUpdateHelper is invoked by a systemd transient service, outside
// arcway.service's cgroup. It owns stop/start, health verification and rollback
// for the entire control-plane transaction.
func RunProductUpdateHelper(jobPath string) (resultErr error) {
	jobPath = filepath.Clean(strings.TrimSpace(jobPath))
	if !filepath.IsAbs(jobPath) || filepath.Base(jobPath) != productUpdateJobFilename {
		return errors.New("invalid product update job path")
	}
	job, err := loadProductUpdateJob(filepath.Dir(jobPath))
	if err != nil {
		return err
	}
	if jobPath != productUpdateJobPath(job.StateDir) {
		return errors.New("product update job path does not match its state directory")
	}
	if productTransactionTerminal(job.Phase) || strings.EqualFold(strings.TrimSpace(job.Phase), "recovery_required") {
		return nil
	}
	// The HTTP handler only owns the lock while it stages verified inputs. The
	// helper takes it again for the irreversible part so installer.sh and a
	// second panel request cannot interleave file or web-link changes.
	updateLock, err := acquireProductUpdateSystemLock()
	if err != nil {
		_ = failProductUpdateJob(&job, fmt.Errorf("等待安装锁: %w", err))
		return err
	}
	defer updateLock.Close()
	var webLock *productWebLock
	if job.Web != nil {
		webLock, err = acquireProductWebLockWithRetry(job.Web.Root)
		if err != nil {
			_ = failProductUpdateJob(&job, fmt.Errorf("等待前端发布锁: %w", err))
			return err
		}
		defer webLock.Close()
	}
	if job.Phase != "scheduled" {
		return recoverInterruptedProductUpdate(&job)
	}

	serviceStopped := false
	committed := false
	defer func() {
		if !serviceStopped || committed || job.Phase == "rolled_back" || job.Phase == "recovery_required" {
			return
		}
		if job.RollbackReady {
			resultErr = rollbackProductUpdate(&job, resultErr)
			return
		}
		resultErr = recoverUnjournaledProductUpdate(&job, resultErr)
	}()
	if err := setProductUpdatePhase(&job, "stopping", "正在停止控制端以切换已验证的发布组件..."); err != nil {
		return err
	}
	if err := runSystemctl(context.Background(), "stop", job.ServiceUnit); err != nil {
		// A stop command can time out after systemd has already terminated the
		// process. Reassert the original service before recording failure so an
		// interrupted first step never leaves the panel unavailable.
		return recoverUnjournaledProductUpdate(&job, fmt.Errorf("stop control plane: %w", err))
	}
	serviceStopped = true

	if err := setProductUpdatePhase(&job, "backing_up", "正在备份控制端、安装资产和数据库..."); err != nil {
		return err
	}
	backups, err := backupProductDatabase(job)
	if err == nil {
		job.DatabaseBackups = backups
		err = backupUpdateFiles(job.Files)
	}
	if err != nil {
		return err
	}
	job.RollbackReady = true
	if err := writeProductUpdateJob(job); err != nil {
		return err
	}

	if err := setProductUpdatePhase(&job, "activating", "正在原子切换控制端与前端发布..."); err != nil {
		return err
	}
	if job.Web != nil && job.Activation == nil {
		activation, err := productrelease.PrepareWebActivation(job.Web.Root, job.Web.Staging, job.ReleaseID)
		if err != nil {
			return rollbackProductUpdate(&job, fmt.Errorf("prepare frontend activation: %w", err))
		}
		// Persist the exact old links before publishing a new release directory
		// or swapping either symlink. Recovery can now safely undo a SIGKILL at
		// any subsequent frontend activation step.
		job.Activation = &activation
		if err := writeProductUpdateJob(job); err != nil {
			return rollbackProductUpdate(&job, err)
		}
	}
	if err := installUpdateFiles(job.Files); err != nil {
		return rollbackProductUpdate(&job, fmt.Errorf("install update files: %w", err))
	}
	job.FilesActivated = true
	if err := writeProductUpdateJob(job); err != nil {
		return err
	}
	if job.Web != nil {
		if job.Activation == nil {
			return rollbackProductUpdate(&job, errors.New("frontend activation journal is missing"))
		}
		if err := productrelease.ActivatePreparedWebRelease(job.Web.Root, *job.Activation); err != nil {
			return rollbackProductUpdate(&job, fmt.Errorf("activate frontend release: %w", err))
		}
	}

	if err := setProductUpdatePhase(&job, "starting", "正在启动新的控制端..."); err != nil {
		return err
	}
	if err := runSystemctl(context.Background(), "start", job.ServiceUnit); err != nil {
		return rollbackProductUpdate(&job, fmt.Errorf("start updated control plane: %w", err))
	}
	if err := setProductUpdatePhase(&job, "waiting_for_health", "正在验证新的控制端、前端和 API 兼容性..."); err != nil {
		return err
	}
	if err := waitForProductUpdateHealth(job); err != nil {
		return rollbackProductUpdate(&job, err)
	}
	if err := setProductUpdatePhase(&job, "recording_state", "正在提交已验证的产品发布状态..."); err != nil {
		return err
	}
	if err := productrelease.WriteInstalledState(job.StateDir, job.InstalledState); err != nil {
		return rollbackProductUpdate(&job, fmt.Errorf("record installed product release: %w", err))
	}
	job.StateRecorded = true
	job.Phase = "committed"
	job.Message = "控制端、前端和本地安装资产已更新并通过健康检查"
	job.Error = ""
	if err := writeProductUpdateJob(job); err != nil {
		return err
	}
	committed = true
	return nil
}

func recoverInterruptedProductUpdate(job *productUpdateJob) error {
	cause := fmt.Errorf("检测到阶段 %s 的中断产品更新事务", job.Phase)
	if len(job.Files) == 0 {
		return rollbackWebOnlyProductUpdate(job, cause)
	}
	if job.RollbackReady {
		return rollbackProductUpdate(job, cause)
	}
	return recoverUnjournaledProductUpdate(job, cause)
}

// recoverUnjournaledProductUpdate handles every failure before live files and
// the rollback journal are changed. It deliberately asks systemd to start the
// original unit even after a failed stop command, because systemd can report an
// error after the process has already exited.
func recoverUnjournaledProductUpdate(job *productUpdateJob, cause error) error {
	if err := restartOldControlPlane(job); err != nil {
		return markProductRecoveryRequired(job, errors.Join(cause, err))
	}
	if err := failProductUpdateJob(job, cause); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func acquireProductUpdateSystemLock() (*systemUpdateLock, error) {
	deadline := time.Now().Add(productUpdateLockTimeout)
	var lastError error
	for {
		lock, err := acquireSystemUpdateLock()
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, errUpdateBusy) {
			return nil, err
		}
		lastError = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("等待安装锁超时: %w", lastError)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func acquireProductWebLockWithRetry(root string) (*productWebLock, error) {
	deadline := time.Now().Add(productUpdateLockTimeout)
	var lastError error
	for {
		lock, err := acquireProductWebLock(root)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, errUpdateBusy) {
			return nil, err
		}
		lastError = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("等待前端发布锁超时: %w", lastError)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func runSystemctl(ctx context.Context, arguments ...string) error {
	command := productUpdateCommand(ctx, "systemctl", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitForProductUpdateHealth(job productUpdateJob) error {
	deadline := time.Now().Add(productUpdateHealthTimeout)
	client := &http.Client{Timeout: 3 * time.Second}
	var lastError error
	for time.Now().Before(deadline) {
		request, err := http.NewRequest(http.MethodGet, job.HealthURL, nil)
		if err != nil {
			return err
		}
		request.Header.Set("X-Arcway-Update-Token", job.HealthToken)
		response, err := client.Do(request)
		if err == nil {
			var report struct {
				Version     string `json:"version"`
				ReleaseID   string `json:"release_id"`
				APIContract int    `json:"api_contract"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&report)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && report.ReleaseID == job.ReleaseID && report.Version == job.TargetVersion && report.APIContract == job.Manifest.Components[productrelease.ComponentControlPlane].APIContract {
				if webErr := verifyProductWebRelease(job); webErr == nil {
					return nil
				} else {
					lastError = webErr
				}
			} else if decodeErr != nil {
				lastError = decodeErr
			} else {
				lastError = fmt.Errorf("unexpected update health report: HTTP %d release=%s version=%s", response.StatusCode, report.ReleaseID, report.Version)
			}
		} else {
			lastError = err
		}
		time.Sleep(productUpdateHealthInterval)
	}
	if lastError == nil {
		lastError = errors.New("health check timeout")
	}
	return fmt.Errorf("updated control plane did not become healthy: %w", lastError)
}

// waitForProductWebRelease confirms both the active symlink target and, when
// configured, the URL actually served by the static frontend. The URL is
// optional because many self-hosted deployments do not expose their public
// origin to the service process; the on-disk managed release check remains
// mandatory in every external-web transaction.
func waitForProductWebRelease(job productUpdateJob) error {
	deadline := time.Now().Add(productUpdateHealthTimeout)
	var lastError error
	for time.Now().Before(deadline) {
		if err := verifyProductWebRelease(job); err == nil {
			return nil
		} else {
			lastError = err
		}
		time.Sleep(productUpdateHealthInterval)
	}
	if lastError == nil {
		lastError = errors.New("frontend health check timeout")
	}
	return fmt.Errorf("updated frontend did not become healthy: %w", lastError)
}

func verifyProductWebRelease(job productUpdateJob) error {
	if job.Web == nil {
		return nil
	}
	currentPath := filepath.Join(job.Web.Root, "current")
	releaseID, err := productrelease.CurrentManagedWebRelease(currentPath)
	if err != nil {
		return fmt.Errorf("inspect active frontend release: %w", err)
	}
	if releaseID != job.ReleaseID {
		return fmt.Errorf("active frontend release is %s, expected %s", releaseID, job.ReleaseID)
	}
	metadata, err := productrelease.ValidateWebReleaseDirectory(filepath.Join(job.Web.Root, "releases", releaseID))
	if err != nil {
		return fmt.Errorf("validate active frontend release: %w", err)
	}
	if metadata != job.Web.Metadata {
		return errors.New("active frontend metadata does not match the transaction")
	}
	if job.WebHealthURL == "" {
		return nil
	}
	request, err := http.NewRequest(http.MethodGet, job.WebHealthURL, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("frontend health URL returned HTTP %d", response.StatusCode)
	}
	var served productrelease.WebMetadata
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&served); err != nil {
		return fmt.Errorf("parse served frontend metadata: %w", err)
	}
	if served != job.Web.Metadata {
		return errors.New("served frontend metadata does not match the transaction")
	}
	return nil
}

func backupProductDatabase(job productUpdateJob) ([]productDatabaseBackup, error) {
	workspace := filepath.Join(job.StateDir, "transactions", job.ID, "database")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		return nil, err
	}
	databasePath, err := productDatabasePathForJob(job)
	if err != nil {
		return nil, err
	}
	paths := []string{databasePath, databasePath + "-wal", databasePath + "-shm"}
	backups := make([]productDatabaseBackup, 0, len(paths))
	for _, path := range paths {
		backup := productDatabaseBackup{Path: path, BackupPath: filepath.Join(workspace, filepath.Base(path))}
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			backups = append(backups, backup)
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("database path is not a regular file: %s", path)
		}
		backup.HadFile = true
		if err := copyFile(path, backup.BackupPath); err != nil {
			return nil, err
		}
		backups = append(backups, backup)
	}
	return backups, nil
}

func productDatabasePath(dataDirectory string) (string, error) {
	if !filepath.IsAbs(dataDirectory) {
		return "", errors.New("产品更新数据目录必须是绝对路径")
	}
	return filepath.Join(filepath.Clean(dataDirectory), "arcway.db"), nil
}

func productDatabasePathForJob(job productUpdateJob) (string, error) {
	// DatabasePath was persisted by an early transaction format. Ignore it on
	// recovery: the main process always opens <data-directory>/arcway.db.
	return productDatabasePath(job.DataDirectory)
}

func restoreProductDatabase(backups []productDatabaseBackup) error {
	var restoreErrors []error
	for _, backup := range backups {
		if backup.HadFile {
			if err := copyFile(backup.BackupPath, backup.Path); err != nil {
				restoreErrors = append(restoreErrors, err)
			}
			continue
		}
		if err := os.Remove(backup.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			restoreErrors = append(restoreErrors, err)
		} else if err == nil {
			if syncErr := syncUpdateDirectory(filepath.Dir(backup.Path)); syncErr != nil {
				restoreErrors = append(restoreErrors, syncErr)
			}
		}
	}
	return errors.Join(restoreErrors...)
}

func restartOldControlPlane(job *productUpdateJob) error {
	if err := runSystemctl(context.Background(), "start", job.ServiceUnit); err != nil {
		return err
	}
	return runSystemctl(context.Background(), "is-active", "--quiet", job.ServiceUnit)
}

func rollbackProductUpdate(job *productUpdateJob, cause error) error {
	_ = setProductUpdatePhase(job, "rolling_back", "新版本未通过健康检查，正在恢复上一个发布...")
	if err := runSystemctl(context.Background(), "stop", job.ServiceUnit); err != nil {
		return markProductRecoveryRequired(job, errors.Join(cause, fmt.Errorf("无法确认控制端已停止: %w", err)))
	}
	var rollbackErrors []error
	if job.Activation != nil {
		if job.Web == nil {
			rollbackErrors = append(rollbackErrors, errors.New("frontend activation journal has no frontend preparation"))
		} else if err := productrelease.RollbackWebActivation(job.Web.Root, *job.Activation); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if err := rollbackUpdateFiles(job.Files); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if err := restoreProductDatabase(job.DatabaseBackups); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if err := restorePreviousProductState(job); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if len(rollbackErrors) > 0 {
		return markProductRecoveryRequired(job, errors.Join(append([]error{cause}, rollbackErrors...)...))
	}
	if err := restartOldControlPlane(job); err != nil {
		return markProductRecoveryRequired(job, errors.Join(cause, fmt.Errorf("旧控制端未恢复健康: %w", err)))
	}
	job.Phase = "rolled_back"
	job.Message = "新版本未通过健康检查，已恢复上一个控制端和前端发布"
	job.Error = cause.Error()
	if err := writeProductUpdateJob(*job); err != nil {
		return markProductRecoveryRequired(job, errors.Join(cause, err))
	}
	return cause
}

// rollbackWebOnlyProductUpdate is the recovery path for a compatible
// frontend-only transaction. It never stops the control plane because no
// executable or database was changed; the persisted activation record still
// lets it atomically return the static site to the prior managed release.
func rollbackWebOnlyProductUpdate(job *productUpdateJob, cause error) error {
	if job.Activation == nil {
		if err := failProductUpdateJob(job, cause); err != nil {
			return errors.Join(cause, err)
		}
		return cause
	}
	if job.Web == nil {
		return markProductRecoveryRequired(job, errors.Join(cause, errors.New("frontend activation journal has no frontend preparation")))
	}
	if err := setProductUpdatePhase(job, "rolling_back", "前端发布未完成，正在恢复上一个网页版本..."); err != nil {
		return markProductRecoveryRequired(job, errors.Join(cause, err))
	}
	if err := productrelease.RollbackWebActivation(job.Web.Root, *job.Activation); err != nil {
		return markProductRecoveryRequired(job, errors.Join(cause, err))
	}
	if err := restorePreviousProductState(job); err != nil {
		return markProductRecoveryRequired(job, errors.Join(cause, err))
	}
	job.Phase = "rolled_back"
	job.Message = "前端发布未完成，已恢复上一个网页版本"
	job.Error = cause.Error()
	if err := writeProductUpdateJob(*job); err != nil {
		return markProductRecoveryRequired(job, errors.Join(cause, err))
	}
	return cause
}

func markProductRecoveryRequired(job *productUpdateJob, cause error) error {
	job.Phase = "recovery_required"
	job.Message = "自动回滚未能完整恢复，已暂停后续更新，请先修复控制端服务"
	job.Error = cause.Error()
	if err := writeProductUpdateJob(*job); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func restorePreviousProductState(job *productUpdateJob) error {
	if job.PreviousState != nil {
		return productrelease.WriteInstalledState(job.StateDir, *job.PreviousState)
	}
	if err := os.Remove(productrelease.StatePath(job.StateDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
