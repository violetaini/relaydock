// Package speedtest 在主控本机用 mihomo 内核对节点测速。
package speedtest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/componentcatalog"
)

const mihomoCacheDir = "data/bin"

// minMihomoVersion:snell v4/v5 支持自 mihomo v1.19.26 起(v1.19.25 及更早会报 "snell version error: 4")。
// 定位到的 mihomo 若低于此版本则跳过、重新下载后端批准版本,确保能对 snell 节点测速。
const minMihomoVersion = "1.19.26"

const (
	mihomoLatestReleaseURL = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
	maxMihomoArchiveSize   = int64(64 << 20)
	maxMihomoBinarySize    = int64(256 << 20)
)

type mihomoAssetSpec struct {
	Tag     string
	Version string
	Name    string
	Digest  string
}

func managedMihomoAssetNames(goos, goarch, version string) ([]string, bool) {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return []string{
			"mihomo-linux-amd64-v1-v" + version + ".gz",
			"mihomo-linux-amd64-compatible-v" + version + ".gz",
		}, true
	case "linux/arm64":
		return []string{"mihomo-linux-arm64-v" + version + ".gz"}, true
	default:
		return nil, false
	}
}

func managedMihomoPlatform(goos, goarch string) bool {
	_, supported := managedMihomoAssetNames(goos, goarch, "0.0.0")
	return supported
}

var (
	mihomoVerRe        = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)
	mihomoReleaseTagRe = regexp.MustCompile(`^v(\d+\.\d+\.\d+)$`)
)

// mihomoVersion 运行 `<bin> -v` 解析出 "X.Y.Z";解析不到返回 ""。
func mihomoVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
	m := mihomoVerRe.FindStringSubmatch(string(out))
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3]
}

// versionGTE 比较点分版本 a >= b(仅比 X.Y.Z 前三段)。
func versionGTE(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return true
}

// mihomoSupportsSnell 检查 mihomo 版本 >= minMihomoVersion(确保支持 snell v4/v5)。
// 版本无法解析时拒绝使用，避免把 MIHOMO_BIN、PATH 或缓存目录中的未知程序
// 当作受信任的 Mihomo 核心执行。
func mihomoSupportsSnell(bin string) bool {
	v := mihomoVersion(bin)
	if v == "" {
		return false
	}
	return versionGTE(v, minMihomoVersion)
}

// mihomoBinName 平台相关的 mihomo 可执行文件名(Windows 带 .exe)。
func mihomoBinName() string {
	if runtime.GOOS == "windows" {
		return "mihomo.exe"
	}
	return "mihomo"
}

var (
	mihomoMu sync.Mutex // 串行化定位/下载,避免并发重复下载
)

// ErrMihomoExternallyManaged 表示当前生效核心来自 MIHOMO_BIN 或 PATH，
// Arcway 只展示状态，不会覆盖用户自行维护的可执行文件。
var ErrMihomoExternallyManaged = errors.New("当前 Mihomo 由外部管理，请在 MIHOMO_BIN 或系统 PATH 中更新")

// MihomoCoreStatus 是主控本机 Mihomo 的可管理状态。
type MihomoCoreStatus struct {
	Ready           bool   `json:"ready"`
	Path            string `json:"path"`
	Source          string `json:"source"`
	CurrentVersion  string `json:"current_version"`
	TargetVersion   string `json:"target_version"`
	LatestVersion   string `json:"latest_version"`
	LatestError     string `json:"latest_error,omitempty"`
	Manageable      bool   `json:"manageable"`
	UpdateAvailable bool   `json:"update_available"`
}

func mihomoStatusFor(path, source, version, target string, manageable bool) MihomoCoreStatus {
	ready := version != "" && versionGTE(version, minMihomoVersion)
	return MihomoCoreStatus{
		Ready:           ready,
		Path:            path,
		Source:          source,
		CurrentVersion:  version,
		TargetVersion:   target,
		LatestVersion:   target,
		Manageable:      manageable,
		UpdateAvailable: manageable && target != "" && (version == "" || !versionGTE(version, target)),
	}
}

func applyMihomoLatest(status MihomoCoreStatus, version string) MihomoCoreStatus {
	status.TargetVersion = version
	status.LatestVersion = version
	status.LatestError = ""
	status.UpdateAvailable = status.Manageable && version != "" &&
		(status.CurrentVersion == "" || !versionGTE(status.CurrentVersion, version))
	return status
}

// inspectMihomoLocked 按 EnsureMihomo 的优先级检查候选核心。调用方必须持有 mihomoMu。
func inspectMihomoLocked() MihomoCoreStatus {
	supported := managedMihomoPlatform(runtime.GOOS, runtime.GOARCH)

	if p := os.Getenv("MIHOMO_BIN"); p != "" && fileExists(p) {
		if version := mihomoVersion(p); version != "" && versionGTE(version, minMihomoVersion) {
			return mihomoStatusFor(p, "env", version, "", false)
		}
	}
	if !supported {
		return mihomoStatusFor("", "none", "", "", false)
	}

	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	localVersion := ""
	if fileExists(local) {
		localVersion = mihomoVersion(local)
		if localVersion != "" && versionGTE(localVersion, minMihomoVersion) {
			return mihomoStatusFor(local, "managed", localVersion, "", true)
		}
	}
	if p, err := exec.LookPath("mihomo"); err == nil {
		if version := mihomoVersion(p); version != "" && versionGTE(version, minMihomoVersion) {
			return mihomoStatusFor(p, "path", version, "", false)
		}
	}
	if fileExists(local) {
		return mihomoStatusFor(local, "managed", localVersion, "", true)
	}
	return mihomoStatusFor("", "none", "", "", true)
}

type mihomoLatestResolver func(context.Context) (mihomoAssetSpec, ghAsset, error)
type mihomoAssetInstaller func(context.Context, ghAsset, mihomoAssetSpec, string) error

// getMihomoCoreStatus 返回本地核心状态，并加载当前后端内置的目标版本。
// 目标版本不可用不会让已安装核心变为不可用。
func getMihomoCoreStatus(ctx context.Context, resolve mihomoLatestResolver) MihomoCoreStatus {
	mihomoMu.Lock()
	status := inspectMihomoLocked()
	mihomoMu.Unlock()

	if !managedMihomoPlatform(runtime.GOOS, runtime.GOARCH) {
		return status
	}
	spec, _, err := resolve(ctx)
	if err != nil {
		status.LatestError = err.Error()
		return status
	}
	return applyMihomoLatest(status, spec.Version)
}

// GetMihomoCoreStatus 返回主控本机当前生效的 Mihomo、可管理性和当前
// Arcway 后端批准的目标版本。运行中的后端不会隐式跟随上游 latest。
func GetMihomoCoreStatus(ctx context.Context) MihomoCoreStatus {
	return getMihomoCoreStatus(ctx, latestMihomoAsset)
}

// EnsureMihomo 返回可用的 mihomo 二进制路径;按序尝试:env MIHOMO_BIN → data/bin/mihomo →
// $PATH → 从当前后端批准的 GitHub release 自动下载到 data/bin/mihomo。
func EnsureMihomo(ctx context.Context) (string, error) {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()

	status := inspectMihomoLocked()
	if status.Ready {
		return status.Path, nil
	}
	if !managedMihomoPlatform(runtime.GOOS, runtime.GOARCH) {
		return "", fmt.Errorf("mihomo 不支持在 %s/%s 自动下载，请通过 MIHOMO_BIN 提供可信二进制", runtime.GOOS, runtime.GOARCH)
	}
	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	// 自动下载当前后端批准的版本(支持 snell)。若 data/bin 里是过旧版本会被更新。
	if err := downloadMihomo(ctx, local); err != nil {
		return "", fmt.Errorf("mihomo 不可用且自动下载失败: %w", err)
	}
	return local, nil
}

// InstallManagedMihomo 安装或更新 Arcway 管理的核心到当前后端批准的
// MetaCubeX/mihomo 版本。外部 MIHOMO_BIN/PATH 核心永远不会被覆盖；
// 高于目标版本的受管核心也不会降级。
func InstallManagedMihomo(ctx context.Context) (MihomoCoreStatus, error) {
	return installManagedMihomo(ctx, latestMihomoAsset, func(ctx context.Context, asset ghAsset, spec mihomoAssetSpec, dst string) error {
		return downloadMihomoAsset(ctx, &http.Client{Timeout: 5 * time.Minute}, asset, spec, dst)
	})
}

// AutoUpdateManagedMihomo only updates an already Arcway-managed copy. It does
// not install an unused core and never overwrites MIHOMO_BIN or PATH copies.
func AutoUpdateManagedMihomo(ctx context.Context) (MihomoCoreStatus, error) {
	return autoUpdateManagedMihomo(ctx, latestMihomoAsset, func(ctx context.Context, asset ghAsset, spec mihomoAssetSpec, dst string) error {
		return downloadMihomoAsset(ctx, &http.Client{Timeout: 5 * time.Minute}, asset, spec, dst)
	})
}

func autoUpdateManagedMihomo(ctx context.Context, resolve mihomoLatestResolver, install mihomoAssetInstaller) (MihomoCoreStatus, error) {
	mihomoMu.Lock()
	status := inspectMihomoLocked()
	mihomoMu.Unlock()
	if status.Source != "managed" {
		return status, nil
	}
	return installManagedMihomo(ctx, resolve, install)
}

func installManagedMihomo(ctx context.Context, resolve mihomoLatestResolver, install mihomoAssetInstaller) (MihomoCoreStatus, error) {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()

	status := inspectMihomoLocked()
	if status.Source == "env" || status.Source == "path" {
		return status, ErrMihomoExternallyManaged
	}
	if !status.Manageable {
		return status, fmt.Errorf("mihomo 不支持在 %s/%s 自动安装，请通过 MIHOMO_BIN 提供可信二进制", runtime.GOOS, runtime.GOARCH)
	}
	spec, asset, err := resolve(ctx)
	if err != nil {
		status.LatestError = err.Error()
		return status, fmt.Errorf("读取后端指定的 Mihomo 版本失败: %w", err)
	}
	status = applyMihomoLatest(status, spec.Version)
	if status.Ready && versionGTE(status.CurrentVersion, spec.Version) {
		return status, nil
	}

	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	if err := install(ctx, asset, spec, local); err != nil {
		return status, fmt.Errorf("安装 Mihomo 失败: %w", err)
	}
	installed := applyMihomoLatest(inspectMihomoLocked(), spec.Version)
	if !installed.Ready || installed.Source != "managed" {
		return installed, errors.New("Mihomo 已下载但未能通过版本校验")
	}
	return installed, nil
}

// MihomoStatus 报告 mihomo 是否就绪及来源(供 UI 展示)。
func MihomoStatus() (ready bool, path string) {
	mihomoMu.Lock()
	status := inspectMihomoLocked()
	mihomoMu.Unlock()
	return status.Ready, status.Path
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// downloadMihomo 从当前后端批准的 MetaCubeX/mihomo release 下载当前平台资源。
func downloadMihomo(ctx context.Context, dst string) error {
	spec, asset, err := latestMihomoAsset(ctx)
	if err != nil {
		return err
	}
	return downloadMihomoAsset(ctx, &http.Client{Timeout: 5 * time.Minute}, asset, spec, dst)
}

func latestMihomoAsset(ctx context.Context) (mihomoAssetSpec, ghAsset, error) {
	_ = ctx
	if !managedMihomoPlatform(runtime.GOOS, runtime.GOARCH) {
		return mihomoAssetSpec{}, ghAsset{}, fmt.Errorf(
			"mihomo 不支持在 %s/%s 自动下载，请通过 MIHOMO_BIN 提供可信二进制",
			runtime.GOOS, runtime.GOARCH,
		)
	}
	asset, ok := componentcatalog.Mihomo(runtime.GOOS, runtime.GOARCH)
	if !ok {
		return mihomoAssetSpec{}, ghAsset{}, fmt.Errorf("mihomo 不支持在 %s/%s 自动下载", runtime.GOOS, runtime.GOARCH)
	}
	spec := mihomoAssetSpec{
		Tag:     "v" + asset.Version,
		Version: asset.Version,
		Name:    asset.Name,
		Digest:  "sha256:" + asset.SHA256,
	}
	githubAsset := ghAsset{
		Name:               asset.Name,
		BrowserDownloadURL: asset.URL,
		Digest:             "sha256:" + asset.SHA256,
		State:              "uploaded",
		ContentType:        "application/gzip",
		Size:               mihomoCatalogAssetSize(runtime.GOOS, runtime.GOARCH),
	}
	if err := validateMihomoReleaseAsset(spec.Tag, githubAsset); err != nil {
		return mihomoAssetSpec{}, ghAsset{}, fmt.Errorf("后端 Mihomo 目录无效: %w", err)
	}
	return spec, githubAsset, nil
}

func mihomoCatalogAssetSize(goos, goarch string) int64 {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return 17881563
	case "linux/arm64":
		return 16051759
	default:
		return 0
	}
}

func resolveMihomoReleaseAsset(rel *ghRelease, goos, goarch string) (mihomoAssetSpec, ghAsset, error) {
	if rel == nil {
		return mihomoAssetSpec{}, ghAsset{}, errors.New("mihomo latest release 为空")
	}
	if rel.Draft || rel.Prerelease {
		return mihomoAssetSpec{}, ghAsset{}, fmt.Errorf("mihomo latest release %q 不是稳定发布", rel.TagName)
	}
	match := mihomoReleaseTagRe.FindStringSubmatch(rel.TagName)
	if match == nil {
		return mihomoAssetSpec{}, ghAsset{}, fmt.Errorf("mihomo latest release 标签无效: %q", rel.TagName)
	}
	version := match[1]
	names, supported := managedMihomoAssetNames(goos, goarch, version)
	if !supported {
		return mihomoAssetSpec{}, ghAsset{}, fmt.Errorf("mihomo 不支持在 %s/%s 自动下载", goos, goarch)
	}
	for _, name := range names {
		for _, asset := range rel.Assets {
			if asset.Name != name {
				continue
			}
			if err := validateMihomoReleaseAsset(rel.TagName, asset); err != nil {
				return mihomoAssetSpec{}, ghAsset{}, err
			}
			return mihomoAssetSpec{
				Tag:     rel.TagName,
				Version: version,
				Name:    name,
				Digest:  asset.Digest,
			}, asset, nil
		}
	}
	return mihomoAssetSpec{}, ghAsset{}, fmt.Errorf("mihomo release %s 未找到 %s 资源", rel.TagName, strings.Join(names, " 或 "))
}

func validateMihomoReleaseAsset(tag string, asset ghAsset) error {
	if asset.State != "uploaded" {
		return fmt.Errorf("GitHub 资源 %s 状态不是 uploaded", asset.Name)
	}
	if asset.Size <= 0 || asset.Size > maxMihomoArchiveSize {
		return fmt.Errorf("GitHub 资源 %s 大小 %d 不在允许范围内", asset.Name, asset.Size)
	}
	if asset.ContentType != "application/gzip" && asset.ContentType != "application/x-gzip" {
		return fmt.Errorf("GitHub 资源 %s 类型不是 gzip: %q", asset.Name, asset.ContentType)
	}
	if _, err := parseSHA256Digest(asset.Digest); err != nil {
		return fmt.Errorf("GitHub 资源 %s 的 digest 无效: %w", asset.Name, err)
	}
	downloadURL, err := url.Parse(asset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("GitHub 资源 %s 下载地址无效: %w", asset.Name, err)
	}
	wantPath := "/MetaCubeX/mihomo/releases/download/" + tag + "/" + asset.Name
	if downloadURL.Scheme != "https" || !strings.EqualFold(downloadURL.Hostname(), "github.com") || downloadURL.Path != wantPath {
		return fmt.Errorf("GitHub 资源 %s 下载地址不在官方 release: %q", asset.Name, asset.BrowserDownloadURL)
	}
	return nil
}

func parseSHA256Digest(digest string) ([]byte, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) {
		return nil, fmt.Errorf("缺少 sha256 摘要")
	}
	hexDigest := strings.TrimPrefix(digest, prefix)
	if len(hexDigest) != sha256.Size*2 {
		return nil, fmt.Errorf("sha256 摘要长度应为 %d 个十六进制字符", sha256.Size*2)
	}
	expected, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("sha256 摘要不是合法十六进制: %w", err)
	}
	return expected, nil
}

// downloadMihomoAsset 校验 latest release 元数据中的 SHA-256，再受限解压并原子替换 dst。
func downloadMihomoAsset(ctx context.Context, client *http.Client, asset ghAsset, spec mihomoAssetSpec, dst string) error {
	return downloadMihomoAssetWithLimits(ctx, client, asset, spec, dst, maxMihomoArchiveSize, maxMihomoBinarySize)
}

func downloadMihomoAssetWithLimits(
	ctx context.Context,
	client *http.Client,
	asset ghAsset,
	spec mihomoAssetSpec,
	dst string,
	archiveLimit int64,
	binaryLimit int64,
) error {
	if asset.Name != spec.Name {
		return fmt.Errorf("release 资源名称不匹配: expected %s, got %s", spec.Name, asset.Name)
	}
	expectedDigest, err := parseSHA256Digest(spec.Digest)
	if err != nil {
		return fmt.Errorf("上游资源 %s 的 digest 无效: %w", spec.Name, err)
	}
	releaseDigest, err := parseSHA256Digest(asset.Digest)
	if err != nil {
		return fmt.Errorf("GitHub 资源 %s 的 digest 无效: %w", asset.Name, err)
	}
	if !bytes.Equal(releaseDigest, expectedDigest) {
		return fmt.Errorf("GitHub 资源 %s 的 digest 与 latest release 解析结果不一致", asset.Name)
	}
	if archiveLimit <= 0 || binaryLimit <= 0 {
		return fmt.Errorf("mihomo 下载大小上限必须大于零")
	}
	if asset.State != "uploaded" {
		return fmt.Errorf("GitHub 资源 %s 状态不是 uploaded", asset.Name)
	}
	if asset.ContentType != "application/gzip" && asset.ContentType != "application/x-gzip" {
		return fmt.Errorf("GitHub 资源 %s 类型不是 gzip: %q", asset.Name, asset.ContentType)
	}
	if asset.Size <= 0 || asset.Size > archiveLimit {
		return fmt.Errorf("GitHub 资源 %s 声明的压缩大小 %d 不在允许范围内", asset.Name, asset.Size)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return fmt.Errorf("创建 %s 下载请求: %w", asset.Name, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载 %s: %w", asset.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 %s HTTP %d", asset.Name, resp.StatusCode)
	}
	if resp.ContentLength > archiveLimit {
		return fmt.Errorf("资源 %s 压缩大小 %d 超过上限 %d", asset.Name, resp.ContentLength, archiveLimit)
	}

	download, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".download-*")
	if err != nil {
		return err
	}
	downloadPath := download.Name()
	defer func() {
		download.Close()
		os.Remove(downloadPath)
	}()

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(download, hash), io.LimitReader(resp.Body, archiveLimit+1))
	if written > archiveLimit {
		return fmt.Errorf("资源 %s 压缩大小超过上限 %d", asset.Name, archiveLimit)
	}
	if err != nil {
		return fmt.Errorf("读取 %s: %w", asset.Name, err)
	}
	if written != asset.Size {
		return fmt.Errorf("资源 %s 实际压缩大小 %d 与 release 元数据 %d 不一致", asset.Name, written, asset.Size)
	}
	actualDigest := hash.Sum(nil)
	if !bytes.Equal(actualDigest, expectedDigest) {
		return fmt.Errorf("资源 %s SHA-256 校验失败: expected %x, got %x", asset.Name, expectedDigest, actualDigest)
	}
	if _, err := download.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("重置 %s 读取位置: %w", asset.Name, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	installed := false
	defer func() {
		tmp.Close()
		if !installed {
			os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0755); err != nil {
		return err
	}

	gz, err := gzip.NewReader(download)
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	extracted, copyErr := io.Copy(tmp, io.LimitReader(gz, binaryLimit+1))
	if extracted > binaryLimit {
		gz.Close()
		return fmt.Errorf("资源 %s 解压大小超过上限 %d", asset.Name, binaryLimit)
	}
	if copyErr != nil {
		gz.Close()
		return fmt.Errorf("写入二进制: %w", copyErr)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("关闭 gzip: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("同步二进制: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭二进制: %w", err)
	}
	if err := verifyDownloadedMihomo(tmpPath, spec.Version); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	installed = true
	return nil
}

func verifyDownloadedMihomo(bin, expectedVersion string) error {
	version := mihomoVersion(bin)
	if version == "" {
		return fmt.Errorf("下载的 mihomo 无法报告版本")
	}
	if version != expectedVersion {
		return fmt.Errorf("下载的 mihomo 版本不匹配: expected %s, got %s", expectedVersion, version)
	}
	return nil
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
	State              string `json:"state"`
	ContentType        string `json:"content_type"`
	Size               int64  `json:"size"`
}

type ghRelease struct {
	TagName    string    `json:"tag_name"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Assets     []ghAsset `json:"assets"`
}

func fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	return fetchMihomoRelease(ctx, &http.Client{Timeout: 30 * time.Second}, mihomoLatestReleaseURL)
}

func fetchMihomoRelease(ctx context.Context, client *http.Client, endpoint string) (*ghRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("创建 mihomo release 请求: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "relaydock-speedtest")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询 mihomo latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询 mihomo latest release HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析 mihomo latest release: %w", err)
	}
	return &rel, nil
}
