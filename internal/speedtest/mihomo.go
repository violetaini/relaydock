// Package speedtest 在主控本机用 mihomo 内核对节点测速。
package speedtest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const mihomoCacheDir = "data/bin"

// minMihomoVersion:snell v4/v5 支持自 mihomo v1.19.26 起(v1.19.25 及更早会报 "snell version error: 4")。
// 定位到的 mihomo 若低于此版本则跳过、重新下载固定版本,确保能对 snell 节点测速。
const minMihomoVersion = "1.19.26"

const (
	pinnedMihomoTag      = "v1.19.28"
	maxMihomoArchiveSize = int64(64 << 20)
	maxMihomoBinarySize  = int64(256 << 20)
)

type mihomoAssetSpec struct {
	Tag     string
	Version string
	Name    string
	Digest  string
}

// pinnedMihomoAsset 是自动下载的信任根。未列出的平台必须显式提供 MIHOMO_BIN。
func pinnedMihomoAsset(goos, goarch string) (mihomoAssetSpec, bool) {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return mihomoAssetSpec{
			Tag:     pinnedMihomoTag,
			Version: "1.19.28",
			Name:    "mihomo-linux-amd64-compatible-v1.19.28.gz",
			Digest:  "sha256:70d01cfb8cb7bf7a92fd1af16cb4b9553d90bb4eecde3b5c4849103e27c80ddb",
		}, true
	case "linux/arm64":
		return mihomoAssetSpec{
			Tag:     pinnedMihomoTag,
			Version: "1.19.28",
			Name:    "mihomo-linux-arm64-v1.19.28.gz",
			Digest:  "sha256:2474450cd1c41dfa53036a54a4e85579f493d3af524d86c3d4b8e2b240b56cd2",
		}, true
	default:
		return mihomoAssetSpec{}, false
	}
}

var mihomoVerRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

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
	mihomoMu   sync.Mutex // 串行化定位/下载,避免并发重复下载
	cachedPath string
)

// EnsureMihomo 返回可用的 mihomo 二进制路径;按序尝试:env MIHOMO_BIN → data/bin/mihomo →
// $PATH → 从 GitHub releases 自动下载到 data/bin/mihomo。
func EnsureMihomo(ctx context.Context) (string, error) {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()

	if _, supported := pinnedMihomoAsset(runtime.GOOS, runtime.GOARCH); !supported {
		if p := os.Getenv("MIHOMO_BIN"); p != "" && fileExists(p) && mihomoSupportsSnell(p) {
			cachedPath = p
			return p, nil
		}
		return "", fmt.Errorf("mihomo 不支持在 %s/%s 自动下载，请通过 MIHOMO_BIN 提供可信二进制", runtime.GOOS, runtime.GOARCH)
	}
	if cachedPath != "" && fileExists(cachedPath) {
		return cachedPath, nil
	}
	// 每个候选都要求版本支持 snell(>= minMihomoVersion),否则跳过、最终重新下载固定版本。
	if p := os.Getenv("MIHOMO_BIN"); p != "" && fileExists(p) && mihomoSupportsSnell(p) {
		cachedPath = p
		return p, nil
	}
	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	if fileExists(local) && mihomoSupportsSnell(local) {
		cachedPath = local
		return local, nil
	}
	if p, err := exec.LookPath("mihomo"); err == nil && mihomoSupportsSnell(p) {
		cachedPath = p
		return p, nil
	}
	// 自动下载固定版本(支持 snell)。若 data/bin 里是旧版会被覆盖。
	if err := downloadMihomo(ctx, local); err != nil {
		return "", fmt.Errorf("mihomo 不可用且自动下载失败: %w", err)
	}
	cachedPath = local
	return local, nil
}

// MihomoStatus 报告 mihomo 是否就绪及来源(供 UI 展示)。
func MihomoStatus() (ready bool, path string) {
	if _, supported := pinnedMihomoAsset(runtime.GOOS, runtime.GOARCH); !supported {
		if p := os.Getenv("MIHOMO_BIN"); p != "" && fileExists(p) && mihomoSupportsSnell(p) {
			return true, p
		}
		return false, ""
	}
	if cachedPath != "" && fileExists(cachedPath) {
		return true, cachedPath
	}
	// 仅当版本支持 snell 时才算就绪,否则报未就绪以触发下载固定版本。
	if p := os.Getenv("MIHOMO_BIN"); p != "" && fileExists(p) && mihomoSupportsSnell(p) {
		return true, p
	}
	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	if fileExists(local) && mihomoSupportsSnell(local) {
		return true, local
	}
	if p, err := exec.LookPath("mihomo"); err == nil && mihomoSupportsSnell(p) {
		return true, p
	}
	return false, ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// downloadMihomo 从固定的 MetaCubeX/mihomo release 下载清单内资源并安装到 dst。
func downloadMihomo(ctx context.Context, dst string) error {
	spec, supported := pinnedMihomoAsset(runtime.GOOS, runtime.GOARCH)
	if !supported {
		return fmt.Errorf("mihomo 不支持在 %s/%s 自动下载，请通过 MIHOMO_BIN 提供可信二进制", runtime.GOOS, runtime.GOARCH)
	}
	rel, err := fetchRelease(ctx, spec.Tag)
	if err != nil {
		return err
	}
	if rel.TagName != spec.Tag {
		return fmt.Errorf("mihomo release 标签不匹配: expected %s, got %s", spec.Tag, rel.TagName)
	}
	var asset *ghAsset
	for i := range rel.Assets {
		if rel.Assets[i].Name == spec.Name {
			asset = &rel.Assets[i]
			break
		}
	}
	if asset == nil {
		return fmt.Errorf("release %s 未找到固定资源 %s", spec.Tag, spec.Name)
	}
	return downloadMihomoAsset(ctx, &http.Client{Timeout: 5 * time.Minute}, *asset, spec, dst)
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

// downloadMihomoAsset 校验固定摘要和 GitHub 元数据，再受限解压并原子替换 dst。
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
	trustedDigest, err := parseSHA256Digest(spec.Digest)
	if err != nil {
		return fmt.Errorf("固定资源 %s 的 digest 无效: %w", spec.Name, err)
	}
	releaseDigest, err := parseSHA256Digest(asset.Digest)
	if err != nil {
		return fmt.Errorf("GitHub 资源 %s 的 digest 无效: %w", asset.Name, err)
	}
	if !bytes.Equal(releaseDigest, trustedDigest) {
		return fmt.Errorf("GitHub 资源 %s 的 digest 与固定清单不一致", asset.Name)
	}
	if archiveLimit <= 0 || binaryLimit <= 0 {
		return fmt.Errorf("mihomo 下载大小上限必须大于零")
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
	actualDigest := hash.Sum(nil)
	if !bytes.Equal(actualDigest, trustedDigest) {
		return fmt.Errorf("资源 %s SHA-256 校验失败: expected %x, got %x", asset.Name, trustedDigest, actualDigest)
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
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

func fetchRelease(ctx context.Context, tag string) (*ghRelease, error) {
	endpoint := "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/" + tag
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("创建 mihomo release 请求: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "relaydock-speedtest")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询 mihomo release %s: %w", tag, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询 mihomo release %s HTTP %d", tag, resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}
