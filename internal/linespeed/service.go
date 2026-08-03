package linespeed

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/violetaini/relaydock/internal/componentcatalog"
)

const (
	Implementation       = "Ookla Speedtest CLI"
	Version              = componentcatalog.OoklaVersion
	ResultImplementation = Implementation + " " + Version

	officialDownloadBase    = "https://install.speedtest.net/app/cli/"
	defaultOperationTimeout = 5 * time.Minute
	maxArchiveSize          = int64(16 << 20)
	maxExtractedArchiveSize = int64(32 << 20)
	maxBinarySize           = int64(16 << 20)
	maxStdoutSize           = int64(1 << 20)
	maxStderrSize           = int64(64 << 10)
	managedBinaryFDPath     = "/proc/self/fd/3"
	managedBinaryName       = "speedtest"
	licenseMarkerName       = ".license-accepted"
	// The consent record intentionally has its own schema version rather than
	// the Ookla binary version. A binary update must not discard a consent that
	// the user already explicitly gave.
	licenseMarkerContents       = "arcway-ookla-speedtest-license-accepted-schema-v1\n"
	legacyLicenseMarkerContents = "arcway-ookla-speedtest-license-accepted-v1.2.0\n"
	managedHomeDirectoryName    = "home"
	managedConfigDirectoryName  = "xdg-config"
)

var (
	ErrBusy               = errors.New("线路测速工具正忙")
	ErrNotInstalled       = errors.New("Ookla Speedtest CLI 尚未安装")
	ErrNotOwned           = errors.New("当前 Ookla Speedtest CLI 不是由面板安装，不能由面板删除")
	ErrUnsupported        = errors.New("当前系统或 CPU 架构不支持面板管理 Ookla Speedtest CLI")
	ErrLicenseNotAccepted = errors.New("安装和测速前必须明确接受 Ookla Speedtest CLI 的许可协议与隐私条款")
)

// Artifact contains both the downloaded tarball and extracted executable
// digests. The executable digest keeps future status/run checks independent of
// the downloaded archive after installation.
type artifact struct {
	version    string
	name       string
	url        string
	archiveSHA string
	binarySHA  string
}

var linuxArtifacts = map[string][]artifact{
	"amd64": {{
		version:    Version,
		name:       "x86_64",
		url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-x86_64.tgz",
		archiveSHA: "5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7",
		binarySHA:  "31f1124c5ab8acdae6b9fe1741e704df420f9f2e7d429679fabe62075453c051",
	}},
	"arm64": {{
		version:    Version,
		name:       "aarch64",
		url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-aarch64.tgz",
		archiveSHA: "3953d231da3783e2bf8904b6dd72767c5c6e533e163d3742fd0437affa431bd3",
		binarySHA:  "d99fa13293f658b53eaa79fe81f4b210db39fdfc1e9698f33da3f234a6008df7",
	}},
	"386": {{
		version:    Version,
		name:       "i386",
		url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-i386.tgz",
		archiveSHA: "9ff7e18dbae7ee0e03c66108445a2fb6ceea6c86f66482e1392f55881b772fe8",
		binarySHA:  "8c600519568eddf31849fbbe9c65b1987dd6f81d69d9b443d4e4afdb3f4864b0",
	}},
	// Go does not expose the target ARM ABI at runtime. Try armhf first (the
	// common armv7 deployment) and fall back to armel when its binary cannot run.
	"arm": {
		{
			version:    Version,
			name:       "armhf",
			url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-armhf.tgz",
			archiveSHA: "e45fcdebbd8a185553535533dd032d6b10bc8c64eee4139b1147b9c09835d08d",
			binarySHA:  "66ad57568664e6f8580e14ad67316a57038fd22b30548bef98531df4ebcc8956",
		},
		{
			version:    Version,
			name:       "armel",
			url:        officialDownloadBase + "ookla-speedtest-1.2.0-linux-armel.tgz",
			archiveSHA: "629a455a2879224bd0dbd4b36d8c721dda540717937e4660b4d2c966029466bf",
			binarySHA:  "d103b5372da7720413f5263e0b557b6d477669785da2b6d7393d00e9708daf2b",
		},
	},
}

// legacyLinuxArtifacts is deliberately kept when the target is advanced. It
// lets the next backend recognize the immediately previous verified install and
// replace it automatically instead of treating it as foreign software.
var legacyLinuxArtifacts = map[string][]artifact{}

type Status struct {
	Supported bool `json:"supported"`
	Installed bool `json:"installed"`
	Managed   bool `json:"managed"`
	Owned     bool `json:"owned"`
	Running   bool `json:"running"`
	// PythonReady remains for clients that consumed the original line-speed
	// contract. The official binary has no Python dependency, so it is false.
	PythonReady     bool   `json:"python_ready"`
	LicenseAccepted bool   `json:"license_accepted"`
	Implementation  string `json:"implementation"`
	Version         string `json:"version,omitempty"`
	TargetVersion   string `json:"target_version,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
}

type Result struct {
	PingMS            float64  `json:"ping_ms"`
	DownloadMbps      float64  `json:"download_mbps"`
	UploadMbps        float64  `json:"upload_mbps"`
	JitterMS          *float64 `json:"jitter_ms,omitempty"`
	PacketLossPercent *float64 `json:"packet_loss_percent,omitempty"`
	ISP               string   `json:"isp"`
	EgressIP          string   `json:"egress_ip"`
	TestServer        string   `json:"test_server"`
	ServerLocation    string   `json:"server_location"`
	Implementation    string   `json:"implementation"`
}

type commandRunner func(context.Context, string, []string, []*os.File, []string, int64, int64) ([]byte, []byte, error)

type Service struct {
	dir                     string
	client                  *http.Client
	runCommand              commandRunner
	goos                    string
	goarch                  string
	artifactsOverride       []artifact
	legacyArtifactsOverride []artifact
	operation               chan struct{}
	running                 atomic.Bool
}

func NewService(dir string) *Service {
	return &Service{
		dir:        dir,
		client:     &http.Client{Timeout: 90 * time.Second},
		runCommand: runCommand,
		goos:       runtime.GOOS,
		goarch:     runtime.GOARCH,
		operation:  make(chan struct{}, 1),
	}
}

func (s *Service) Status(ctx context.Context) Status {
	status := Status{Implementation: Implementation}
	if s == nil {
		return status
	}
	if ctx == nil {
		ctx = context.Background()
	}
	artifacts := s.supportedArtifacts()
	status.Supported = s.goos == "linux" && len(artifacts) > 0
	status.Managed = status.Supported
	status.Running = s.running.Load()
	status.TargetVersion = Version
	if !status.Supported {
		return status
	}
	if item, binary, ok := s.openInstalled(ctx, s.knownArtifacts()); ok {
		_ = binary.Close()
		status.Installed = true
		status.Owned = true
		status.Version = artifactVersion(item)
		status.UpdateAvailable = componentcatalog.VersionCompare(status.Version, Version) < 0
		status.LicenseAccepted = s.hasTrustedLicenseMarker()
	}
	return status
}

// Install only proceeds after the caller has explicitly captured consent for
// Ookla's license and privacy terms. The marker is panel-owned and is required
// again at every run; it is not inferred from an unrelated user profile file.
func (s *Service) Install(ctx context.Context, acceptLicense bool) (Status, error) {
	if s == nil || s.goos != "linux" || len(s.supportedArtifacts()) == 0 {
		return Status{Implementation: Implementation}, ErrUnsupported
	}
	if !acceptLicense {
		return s.Status(ctx), ErrLicenseNotAccepted
	}
	if !s.acquire() {
		return s.Status(ctx), ErrBusy
	}
	defer s.release()

	ctx, cancel := operationContext(ctx)
	defer cancel()
	if err := s.ensureManagedDirectories(); err != nil {
		return s.Status(ctx), err
	}
	if current := s.Status(ctx); current.Installed && !current.UpdateAvailable {
		if !current.LicenseAccepted {
			if err := s.writeLicenseMarker(); err != nil {
				return s.Status(ctx), err
			}
		}
		return s.Status(ctx), nil
	}

	return s.installTargetLocked(ctx, true)
}

// AutoUpdate keeps an already panel-managed, licensed CLI aligned with the
// version baked into this backend. It never installs a new CLI merely because
// the backend started, preserving the explicit Ookla license-consent flow.
func (s *Service) AutoUpdate(ctx context.Context) (Status, error) {
	if s == nil || s.goos != "linux" || len(s.supportedArtifacts()) == 0 {
		return Status{Implementation: Implementation}, ErrUnsupported
	}
	if !s.acquire() {
		return s.Status(ctx), ErrBusy
	}
	defer s.release()

	ctx, cancel := operationContext(ctx)
	defer cancel()
	current := s.Status(ctx)
	if !current.Installed || !current.Owned || !current.LicenseAccepted || !current.UpdateAvailable {
		return current, nil
	}
	if err := s.ensureManagedDirectories(); err != nil {
		return s.Status(ctx), err
	}
	return s.installTargetLocked(ctx, false)
}

func (s *Service) installTargetLocked(ctx context.Context, recordLicense bool) (Status, error) {
	var installErrors []string
	for _, item := range s.supportedArtifacts() {
		if err := s.installArtifact(ctx, item); err == nil {
			if recordLicense {
				if markerErr := s.writeLicenseMarker(); markerErr != nil {
					return s.Status(ctx), markerErr
				}
			}
			return s.Status(ctx), nil
		} else {
			installErrors = append(installErrors, item.name+": "+err.Error())
		}
	}
	return s.Status(ctx), fmt.Errorf("安装 Ookla Speedtest CLI 失败: %s", strings.Join(installErrors, "; "))
}

func (s *Service) Remove(ctx context.Context) (Status, error) {
	if s == nil || s.goos != "linux" || len(s.supportedArtifacts()) == 0 {
		return Status{Implementation: Implementation}, ErrUnsupported
	}
	if !s.acquire() {
		return s.Status(ctx), ErrBusy
	}
	defer s.release()

	status := s.Status(ctx)
	// Never remove a binary that is present but does not match the pinned
	// official artifact. Runtime state is removable only after its own private
	// directory has been revalidated, so a stale install cannot turn Remove into
	// an arbitrary recursive delete.
	binaryExists, _ := trustedPathState(s.binaryPath(), func(info os.FileInfo) bool {
		return validateManagedFileInfo(info) == nil
	})
	markerExists, markerTrusted := trustedPathState(s.licenseMarkerPath(), func(info os.FileInfo) bool {
		if validateManagedFileInfo(info) != nil {
			return false
		}
		return s.hasTrustedLicenseMarker()
	})
	homeExists, homeTrusted := trustedRuntimeDirectoryState(s.homeDir())
	configExists, configTrusted := trustedRuntimeDirectoryState(s.configDir())
	if binaryExists && !status.Owned {
		return status, ErrNotOwned
	}
	if (markerExists && !markerTrusted) || (homeExists && !homeTrusted) || (configExists && !configTrusted) {
		return status, ErrNotOwned
	}
	if binaryExists {
		if err := os.Remove(s.binaryPath()); err != nil && !os.IsNotExist(err) {
			return s.Status(ctx), fmt.Errorf("删除 Ookla Speedtest CLI: %w", err)
		}
	}
	if markerExists {
		if err := os.Remove(s.licenseMarkerPath()); err != nil && !os.IsNotExist(err) {
			return s.Status(ctx), fmt.Errorf("删除 Ookla 许可确认记录: %w", err)
		}
	}
	for _, dir := range []string{s.homeDir(), s.configDir()} {
		if _, err := os.Lstat(dir); err == nil {
			if err := os.RemoveAll(dir); err != nil {
				return s.Status(ctx), fmt.Errorf("删除 Ookla 运行目录: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return s.Status(ctx), fmt.Errorf("检查 Ookla 运行目录: %w", err)
		}
	}
	if err := removeManagedTempFiles(s.dir); err != nil {
		return s.Status(ctx), err
	}
	_ = syncDirectory(s.dir)
	return s.Status(ctx), nil
}

func (s *Service) Run(ctx context.Context) (Result, error) {
	if s == nil || s.goos != "linux" || len(s.supportedArtifacts()) == 0 {
		return Result{}, ErrUnsupported
	}
	if !s.acquire() {
		return Result{}, ErrBusy
	}
	s.running.Store(true)
	defer func() {
		s.running.Store(false)
		s.release()
	}()

	ctx, cancel := operationContext(ctx)
	defer cancel()
	if err := s.ensureManagedDirectories(); err != nil {
		return Result{}, err
	}
	_, binary, installed := s.openInstalled(ctx, s.knownArtifacts())
	if !installed {
		return Result{}, ErrNotInstalled
	}
	defer binary.Close()
	if !s.hasTrustedLicenseMarker() {
		return Result{}, ErrLicenseNotAccepted
	}

	stdout, stderr, err := s.runCommand(ctx, managedBinaryFDPath, []string{
		"--accept-license",
		"--accept-gdpr",
		"--progress=no",
		"--format=json",
	}, []*os.File{binary}, s.runtimeEnv(), maxStdoutSize, maxStderrSize)
	if err != nil {
		detail := strings.TrimSpace(string(stderr))
		if detail == "" {
			detail = err.Error()
		}
		return Result{}, fmt.Errorf("Ookla Speedtest CLI 运行失败: %s", detail)
	}
	return parseResult(stdout)
}

func (s *Service) supportedArtifacts() []artifact {
	if s == nil || s.goos != "linux" {
		return nil
	}
	if s.artifactsOverride != nil {
		return s.artifactsOverride
	}
	return linuxArtifacts[s.goarch]
}

// knownArtifacts includes the current target and any explicitly retained old
// targets. Keeping old trusted digests lets a newer backend identify a prior
// panel installation as an upgrade candidate instead of mislabelling it as an
// unmanaged binary.
func (s *Service) knownArtifacts() []artifact {
	current := s.supportedArtifacts()
	if s == nil {
		return current
	}
	legacy := legacyLinuxArtifacts[s.goarch]
	if s.legacyArtifactsOverride != nil {
		legacy = s.legacyArtifactsOverride
	}
	if len(legacy) == 0 {
		return current
	}
	known := make([]artifact, 0, len(current)+len(legacy))
	known = append(known, current...)
	known = append(known, legacy...)
	return known
}

func artifactVersion(item artifact) string {
	if item.version != "" {
		return item.version
	}
	return Version
}

func (s *Service) installArtifact(ctx context.Context, item artifact) error {
	archivePath, err := s.downloadVerifiedArchive(ctx, item)
	if err != nil {
		return err
	}
	defer os.Remove(archivePath)

	binaryTemp, err := s.extractVerifiedBinary(archivePath, item)
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(binaryTemp)
		}
	}()
	binary, err := openTrustedManagedFile(binaryTemp, item.binarySHA, maxBinarySize)
	if err != nil {
		return fmt.Errorf("校验解出的 Ookla Speedtest CLI: %w", err)
	}
	validVersion := s.checkVersion(ctx, binary, artifactVersion(item))
	closeErr := binary.Close()
	if !validVersion {
		return errors.New("下载的 Ookla Speedtest CLI 不能报告固定版本")
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(binaryTemp, s.binaryPath()); err != nil {
		return fmt.Errorf("安装 Ookla Speedtest CLI: %w", err)
	}
	installed = true
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("同步 Ookla Speedtest CLI 安装目录: %w", err)
	}
	return nil
}

func (s *Service) downloadVerifiedArchive(ctx context.Context, item artifact) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.url, nil)
	if err != nil {
		return "", fmt.Errorf("创建 Ookla Speedtest CLI 下载请求: %w", err)
	}
	req.Header.Set("User-Agent", "arcway-line-speedtest/1.0")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载 Ookla Speedtest CLI: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载 Ookla Speedtest CLI HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxArchiveSize {
		return "", fmt.Errorf("Ookla Speedtest CLI 安装包大小 %d 超过上限 %d", resp.ContentLength, maxArchiveSize)
	}

	archive, err := os.CreateTemp(s.dir, ".ookla-speedtest-archive-*")
	if err != nil {
		return "", fmt.Errorf("创建 Ookla Speedtest CLI 临时安装包: %w", err)
	}
	archivePath := archive.Name()
	keep := false
	defer func() {
		_ = archive.Close()
		if !keep {
			_ = os.Remove(archivePath)
		}
	}()
	if err := archive.Chmod(0o600); err != nil {
		return "", err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(resp.Body, maxArchiveSize+1))
	if copyErr != nil {
		return "", fmt.Errorf("保存 Ookla Speedtest CLI 安装包: %w", copyErr)
	}
	if written > maxArchiveSize {
		return "", fmt.Errorf("Ookla Speedtest CLI 安装包超过大小上限 %d", maxArchiveSize)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != item.archiveSHA {
		return "", fmt.Errorf("Ookla Speedtest CLI 安装包 SHA-256 校验失败: expected %s, got %s", item.archiveSHA, got)
	}
	if err := archive.Sync(); err != nil {
		return "", err
	}
	if err := archive.Close(); err != nil {
		return "", err
	}
	keep = true
	return archivePath, nil
}

// extractVerifiedBinary never writes names from the archive. It only accepts a
// regular root-level speedtest entry, rejects links and traversal, and copies it
// into a panel-created temporary file.
func (s *Service) extractVerifiedBinary(archivePath string, item artifact) (string, error) {
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return "", fmt.Errorf("打开 Ookla Speedtest CLI 安装包: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)

	output, err := os.CreateTemp(s.dir, ".ookla-speedtest-binary-*")
	if err != nil {
		return "", err
	}
	outputPath := output.Name()
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = os.Remove(outputPath)
		}
	}()
	if err := output.Chmod(0o700); err != nil {
		return "", err
	}

	var (
		found      bool
		extracted  int64
		binarySize int64
	)
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return "", fmt.Errorf("读取 Ookla Speedtest CLI 安装包: %w", nextErr)
		}
		if err := validateArchiveHeader(header); err != nil {
			return "", err
		}
		extracted += header.Size
		if extracted > maxExtractedArchiveSize {
			return "", fmt.Errorf("Ookla Speedtest CLI 安装包解压内容超过上限 %d", maxExtractedArchiveSize)
		}
		if header.Name != managedBinaryName {
			if _, err := io.CopyN(io.Discard, reader, header.Size); err != nil {
				return "", fmt.Errorf("跳过 Ookla Speedtest CLI 非执行文件: %w", err)
			}
			continue
		}
		if found {
			return "", errors.New("Ookla Speedtest CLI 安装包包含多个 speedtest 文件")
		}
		if header.Size > maxBinarySize {
			return "", fmt.Errorf("Ookla Speedtest CLI 可执行文件超过大小上限 %d", maxBinarySize)
		}
		copied, err := io.Copy(output, io.LimitReader(reader, maxBinarySize+1))
		if err != nil {
			return "", fmt.Errorf("解压 Ookla Speedtest CLI: %w", err)
		}
		if copied != header.Size || copied > maxBinarySize {
			return "", errors.New("Ookla Speedtest CLI 可执行文件长度异常")
		}
		found = true
		binarySize = copied
	}
	if !found || binarySize == 0 {
		return "", errors.New("Ookla Speedtest CLI 安装包未包含普通 speedtest 文件")
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	if err := output.Chmod(0o755); err != nil {
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	if got, err := fileSHA256(outputPath, maxBinarySize); err != nil || got != item.binarySHA {
		if err != nil {
			return "", fmt.Errorf("校验 Ookla Speedtest CLI 可执行文件: %w", err)
		}
		return "", fmt.Errorf("Ookla Speedtest CLI 可执行文件 SHA-256 校验失败: expected %s, got %s", item.binarySHA, got)
	}
	keep = true
	return outputPath, nil
}

func validateArchiveHeader(header *tar.Header) error {
	if header == nil || header.Size < 0 {
		return errors.New("Ookla Speedtest CLI 安装包条目无效")
	}
	cleanName := path.Clean(header.Name)
	if header.Name == "" || cleanName != header.Name || cleanName == "." || strings.HasPrefix(cleanName, "/") || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return fmt.Errorf("Ookla Speedtest CLI 安装包包含不安全路径 %q", header.Name)
	}
	if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
		return fmt.Errorf("Ookla Speedtest CLI 安装包包含不允许的条目类型 %q", header.Name)
	}
	if header.Linkname != "" {
		return fmt.Errorf("Ookla Speedtest CLI 安装包包含链接条目 %q", header.Name)
	}
	return nil
}

func (s *Service) openInstalled(ctx context.Context, artifacts []artifact) (artifact, *os.File, bool) {
	for _, item := range artifacts {
		binary, err := openTrustedManagedFile(s.binaryPath(), item.binarySHA, maxBinarySize)
		if err != nil {
			continue
		}
		if s.checkVersion(ctx, binary, artifactVersion(item)) {
			return item, binary, true
		}
		_ = binary.Close()
	}
	return artifact{}, nil, false
}

func (s *Service) checkVersion(ctx context.Context, binary *os.File, expectedVersion string) bool {
	if binary == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := binary.Seek(0, io.SeekStart); err != nil {
		return false
	}
	stdout, stderr, err := s.runCommand(ctx, managedBinaryFDPath, []string{"--version"}, []*os.File{binary}, s.runtimeEnv(), 4096, 4096)
	if err != nil {
		return false
	}
	output := strings.TrimSpace(string(append(stdout, stderr...)))
	return strings.Contains(output, "Speedtest by Ookla "+expectedVersion)
}

func (s *Service) ensureManagedDirectories() error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("创建 Ookla Speedtest CLI 安装目录: %w", err)
	}
	if err := validateManagedDirectory(s.dir); err != nil {
		return fmt.Errorf("Ookla Speedtest CLI 安装目录不安全: %w", err)
	}
	for _, dir := range []string{s.homeDir(), s.configDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("创建 Ookla Speedtest CLI 运行目录: %w", err)
		}
		if err := validateManagedDirectory(dir); err != nil {
			return fmt.Errorf("Ookla Speedtest CLI 运行目录不安全: %w", err)
		}
	}
	return nil
}

func (s *Service) hasTrustedLicenseMarker() bool {
	for _, contents := range []string{licenseMarkerContents, legacyLicenseMarkerContents} {
		marker, err := openTrustedManagedFile(s.licenseMarkerPath(), markerSHA256(contents), int64(len(contents)))
		if err != nil {
			continue
		}
		return marker.Close() == nil
	}
	return false
}

func (s *Service) writeLicenseMarker() error {
	if err := writeManagedFileAtomically(s.licenseMarkerPath(), []byte(licenseMarkerContents), 0o600); err != nil {
		return fmt.Errorf("保存 Ookla 许可确认记录: %w", err)
	}
	return nil
}

func (s *Service) binaryPath() string        { return filepath.Join(s.dir, managedBinaryName) }
func (s *Service) licenseMarkerPath() string { return filepath.Join(s.dir, licenseMarkerName) }
func (s *Service) homeDir() string           { return filepath.Join(s.dir, managedHomeDirectoryName) }
func (s *Service) configDir() string         { return filepath.Join(s.dir, managedConfigDirectoryName) }

func (s *Service) runtimeEnv() []string {
	return []string{
		"HOME=" + s.homeDir(),
		"XDG_CONFIG_HOME=" + s.configDir(),
		"XDG_DATA_HOME=" + s.homeDir(),
		"XDG_CACHE_HOME=" + s.homeDir(),
		"XDG_STATE_HOME=" + s.homeDir(),
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"TZ=UTC",
	}
}

func (s *Service) acquire() bool {
	select {
	case s.operation <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Service) release() { <-s.operation }

func operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, defaultOperationTimeout)
}

func openTrustedManagedFile(filePath, expectedSHA string, maxSize int64) (*os.File, error) {
	if err := validateManagedDirectory(filepath.Dir(filePath)); err != nil {
		return nil, err
	}
	before, err := os.Lstat(filePath)
	if err != nil {
		return nil, err
	}
	if err := validateManagedFileInfo(before); err != nil {
		return nil, err
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	trusted := false
	defer func() {
		if !trusted {
			_ = file.Close()
		}
	}()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, errors.New("Ookla Speedtest CLI 文件在校验期间被替换")
	}
	if err := validateManagedFileInfo(after); err != nil {
		return nil, err
	}
	if after.Size() < 0 || after.Size() > maxSize {
		return nil, errors.New("Ookla Speedtest CLI 文件大小不可信")
	}
	if expectedSHA != "" {
		got, hashErr := fileSHA256FromOpenFile(file, maxSize)
		if hashErr != nil {
			return nil, hashErr
		}
		if got != expectedSHA {
			return nil, errors.New("Ookla Speedtest CLI 文件 SHA-256 校验失败")
		}
	}
	trusted = true
	return file, nil
}

func validateManagedDirectory(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	leaf := absDir
	for current := absDir; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("目录路径不可信: %s", current)
		}
		if !trustedFileOwner(info) {
			return fmt.Errorf("目录所有者不可信: %s", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			stickyParent := current != leaf && info.Mode()&os.ModeSticky != 0
			if !stickyParent {
				return fmt.Errorf("目录允许组或其他用户写入: %s", current)
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

// trustedPathState reports existence separately from trust so uninstall can
// refuse to touch an unexpected binary while still cleaning an interrupted,
// panel-owned runtime setup with no binary left behind.
func trustedPathState(filePath string, valid func(os.FileInfo) bool) (exists, trusted bool) {
	info, err := os.Lstat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false
		}
		return true, false
	}
	if err := validateManagedDirectory(filepath.Dir(filePath)); err != nil {
		return true, false
	}
	return true, valid != nil && valid(info)
}

func trustedRuntimeDirectoryState(dir string) (exists, trusted bool) {
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false
		}
		return true, false
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return true, false
	}
	return true, validateManagedDirectory(dir) == nil
}

func removeManagedTempFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取 Ookla 临时文件目录: %w", err)
	}
	if err := validateManagedDirectory(dir); err != nil {
		return fmt.Errorf("Ookla 临时文件目录不安全: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".ookla-speedtest-archive-") &&
			!strings.HasPrefix(name, ".ookla-speedtest-binary-") &&
			!strings.HasPrefix(name, ".arcway-managed-") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("删除 Ookla 临时文件 %q: %w", name, err)
		}
	}
	return nil
}

func validateManagedFileInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() {
		return errors.New("Ookla Speedtest CLI 不是普通文件")
	}
	if !trustedFileOwner(info) {
		return errors.New("Ookla Speedtest CLI 文件所有者不可信")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("Ookla Speedtest CLI 文件允许组或其他用户写入")
	}
	return nil
}

func fileSHA256(filePath string, maxSize int64) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return fileSHA256FromOpenFile(file, maxSize)
}

func fileSHA256FromOpenFile(file *os.File, maxSize int64) (string, error) {
	if file == nil {
		return "", errors.New("文件未打开")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxSize+1))
	if err != nil {
		return "", err
	}
	if written > maxSize {
		return "", errors.New("文件超过大小上限")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func markerSHA256(contents string) string {
	sum := sha256.Sum256([]byte(contents))
	return hex.EncodeToString(sum[:])
}

func writeManagedFileAtomically(target string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	if err := validateManagedDirectory(dir); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".arcway-managed-*")
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
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	committed = true
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

type rawResult struct {
	Type string `json:"type"`
	Ping struct {
		Latency *float64 `json:"latency"`
		Jitter  *float64 `json:"jitter"`
	} `json:"ping"`
	Download struct {
		Bandwidth *float64 `json:"bandwidth"`
	} `json:"download"`
	Upload struct {
		Bandwidth *float64 `json:"bandwidth"`
	} `json:"upload"`
	PacketLoss *float64 `json:"packetLoss"`
	ISP        string   `json:"isp"`
	Interface  struct {
		ExternalIP string `json:"externalIp"`
	} `json:"interface"`
	Server struct {
		Name     string `json:"name"`
		Host     string `json:"host"`
		Location string `json:"location"`
		Country  string `json:"country"`
	} `json:"server"`
}

// parseResult accepts the official client's line-oriented JSON stream. The
// first run can print a license banner and type=log records before type=result.
func parseResult(data []byte) (Result, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4<<10), int(maxStdoutSize))
	var lastResult *rawResult
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var raw rawResult
		if err := json.Unmarshal(line, &raw); err != nil || raw.Type != "result" {
			continue
		}
		lastResult = &raw
	}
	if err := scanner.Err(); err != nil {
		return Result{}, fmt.Errorf("读取 Ookla Speedtest CLI 输出失败: %w", err)
	}
	if lastResult == nil {
		return Result{}, errors.New("Ookla Speedtest CLI 未返回测速结果")
	}
	return normalizeResult(*lastResult)
}

func normalizeResult(raw rawResult) (Result, error) {
	if raw.Ping.Latency == nil || raw.Download.Bandwidth == nil || raw.Upload.Bandwidth == nil {
		return Result{}, errors.New("Ookla Speedtest CLI 返回的测速结果不完整")
	}
	for name, value := range map[string]*float64{
		"ping latency":       raw.Ping.Latency,
		"download bandwidth": raw.Download.Bandwidth,
		"upload bandwidth":   raw.Upload.Bandwidth,
		"ping jitter":        raw.Ping.Jitter,
		"packet loss":        raw.PacketLoss,
	} {
		if value != nil && (*value < 0 || math.IsNaN(*value) || math.IsInf(*value, 0)) {
			return Result{}, fmt.Errorf("Ookla Speedtest CLI 返回非法 %s", name)
		}
	}
	testServer := strings.TrimSpace(raw.Server.Name)
	if testServer == "" {
		testServer = strings.TrimSpace(raw.Server.Host)
	}
	location := joinNonEmpty(", ", raw.Server.Location, raw.Server.Country)
	return Result{
		PingMS:            *raw.Ping.Latency,
		DownloadMbps:      *raw.Download.Bandwidth * 8 / 1e6,
		UploadMbps:        *raw.Upload.Bandwidth * 8 / 1e6,
		JitterMS:          raw.Ping.Jitter,
		PacketLossPercent: raw.PacketLoss,
		ISP:               strings.TrimSpace(raw.ISP),
		EgressIP:          strings.TrimSpace(raw.Interface.ExternalIP),
		TestServer:        testServer,
		ServerLocation:    location,
		Implementation:    ResultImplementation,
	}, nil
}

func joinNonEmpty(separator string, values ...string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, separator)
}

type cappedBuffer struct {
	buf      bytes.Buffer
	max      int64
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - int64(b.buf.Len())
	if remaining > 0 {
		keep := int64(len(p))
		if keep > remaining {
			keep = remaining
		}
		_, _ = b.buf.Write(p[:int(keep)])
	}
	if int64(n) > remaining {
		b.exceeded = true
	}
	return n, nil
}

func runCommand(ctx context.Context, name string, args []string, extraFiles []*os.File, extraEnv []string, stdoutLimit, stderrLimit int64) ([]byte, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = commandEnvironment(extraEnv)
	cmd.ExtraFiles = extraFiles
	stdout := &cappedBuffer{max: stdoutLimit}
	stderr := &cappedBuffer{max: stderrLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return stdout.buf.Bytes(), stderr.buf.Bytes(), errors.New("命令输出超过安全上限")
	}
	return stdout.buf.Bytes(), stderr.buf.Bytes(), err
}

// commandEnvironment removes previous values for supplied keys. In particular,
// HOME/XDG_CONFIG_HOME must not fall back to root's profile when running Ookla.
func commandEnvironment(overrides []string) []string {
	// The official CLI is a privileged panel child process. Do not inherit the
	// service's profile, proxy, XDG, or loader variables; callers provide the
	// complete allowlisted environment explicitly.
	return append([]string(nil), overrides...)
}
