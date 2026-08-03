package speedtest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/violetaini/relaydock/internal/componentcatalog"
)

func TestResolveMihomoReleaseAssetUsesStableLatestPlatformAssets(t *testing.T) {
	const tag = "v1.19.29"
	amd64V1 := releaseAsset(tag, "mihomo-linux-amd64-v1-v1.19.29.gz")
	amd64Compatible := releaseAsset(tag, "mihomo-linux-amd64-compatible-v1.19.29.gz")
	arm64 := releaseAsset(tag, "mihomo-linux-arm64-v1.19.29.gz")
	release := &ghRelease{
		TagName: tag,
		Assets:  []ghAsset{amd64Compatible, arm64, amd64V1},
	}

	spec, asset, err := resolveMihomoReleaseAsset(release, "linux", "amd64")
	if err != nil {
		t.Fatalf("resolve amd64: %v", err)
	}
	if spec.Tag != tag || spec.Version != "1.19.29" || spec.Name != amd64V1.Name || asset.Name != amd64V1.Name {
		t.Fatalf("amd64 selection = %#v / %#v", spec, asset)
	}

	spec, asset, err = resolveMihomoReleaseAsset(release, "linux", "arm64")
	if err != nil || spec.Name != arm64.Name || asset.Name != arm64.Name {
		t.Fatalf("arm64 selection = %#v / %#v, err = %v", spec, asset, err)
	}

	// The upstream project is removing the compatible alias. Keep it only as a
	// fallback for older releases where the baseline v1 asset is absent.
	spec, _, err = resolveMihomoReleaseAsset(&ghRelease{TagName: tag, Assets: []ghAsset{amd64Compatible}}, "linux", "amd64")
	if err != nil || spec.Name != amd64Compatible.Name {
		t.Fatalf("amd64 compatible fallback = %#v, err = %v", spec, err)
	}

	for _, platform := range [][2]string{{"darwin", "amd64"}, {"windows", "amd64"}, {"linux", "386"}} {
		if _, _, err := resolveMihomoReleaseAsset(release, platform[0], platform[1]); err == nil {
			t.Fatalf("resolveMihomoReleaseAsset(%q, %q) error = nil", platform[0], platform[1])
		}
	}
}

func TestResolveMihomoReleaseAssetRejectsUntrustedMetadata(t *testing.T) {
	const tag = "v1.19.29"
	valid := releaseAsset(tag, "mihomo-linux-amd64-v1-v1.19.29.gz")
	tests := []struct {
		name    string
		release *ghRelease
	}{
		{name: "invalid tag", release: &ghRelease{TagName: "latest", Assets: []ghAsset{valid}}},
		{name: "prerelease", release: &ghRelease{TagName: tag, Prerelease: true, Assets: []ghAsset{valid}}},
		{name: "missing digest", release: &ghRelease{TagName: tag, Assets: []ghAsset{func() ghAsset { a := valid; a.Digest = ""; return a }()}}},
		{name: "wrong host", release: &ghRelease{TagName: tag, Assets: []ghAsset{func() ghAsset { a := valid; a.BrowserDownloadURL = "https://example.com/" + a.Name; return a }()}}},
		{name: "not uploaded", release: &ghRelease{TagName: tag, Assets: []ghAsset{func() ghAsset { a := valid; a.State = "new"; return a }()}}},
		{name: "wrong content type", release: &ghRelease{TagName: tag, Assets: []ghAsset{func() ghAsset { a := valid; a.ContentType = "application/octet-stream"; return a }()}}},
		{name: "invalid size", release: &ghRelease{TagName: tag, Assets: []ghAsset{func() ghAsset { a := valid; a.Size = 0; return a }()}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := resolveMihomoReleaseAsset(tt.release, "linux", "amd64"); err == nil {
				t.Fatal("resolveMihomoReleaseAsset() error = nil")
			}
		})
	}
}

func TestMihomoSupportsSnellRejectsUnparseableExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "not-mihomo")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho unknown-program\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if mihomoSupportsSnell(path) {
		t.Fatal("unparseable executable was accepted as a trusted Mihomo core")
	}
}

func TestMihomoCoreStatusAndManagedUpdate(t *testing.T) {
	requireLinux(t)
	t.Chdir(t.TempDir())
	t.Setenv("MIHOMO_BIN", "")
	t.Setenv("PATH", "")

	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, fakeMihomo("1.19.26", 0), 0o755); err != nil {
		t.Fatal(err)
	}

	status := getMihomoCoreStatus(context.Background(), testLatestResolver("1.19.29"))
	if !status.Ready || status.Source != "managed" || !status.Manageable || !status.UpdateAvailable {
		t.Fatalf("old managed status = %#v", status)
	}
	if status.CurrentVersion != "1.19.26" || status.TargetVersion != "1.19.29" || status.LatestVersion != "1.19.29" {
		t.Fatalf("old managed versions = %#v", status)
	}

	downloadCalls := 0
	updated, err := installManagedMihomo(context.Background(), testLatestResolver("1.19.29"), func(_ context.Context, _ ghAsset, _ mihomoAssetSpec, dst string) error {
		downloadCalls++
		return os.WriteFile(dst, fakeMihomo("1.19.29", 0), 0o755)
	})
	if err != nil {
		t.Fatalf("installManagedMihomo() error = %v", err)
	}
	if downloadCalls != 1 || !updated.Ready || updated.Source != "managed" || updated.CurrentVersion != "1.19.29" || updated.UpdateAvailable {
		t.Fatalf("updated status = %#v, download calls = %d", updated, downloadCalls)
	}
}

func TestAutoUpdateManagedMihomoLeavesMissingCoreUninstalled(t *testing.T) {
	requireLinux(t)
	t.Chdir(t.TempDir())
	t.Setenv("MIHOMO_BIN", "")
	t.Setenv("PATH", "")
	resolveCalls, installCalls := 0, 0
	status, err := autoUpdateManagedMihomo(context.Background(), func(context.Context) (mihomoAssetSpec, ghAsset, error) {
		resolveCalls++
		return testLatestResolver("1.19.29")(context.Background())
	}, func(context.Context, ghAsset, mihomoAssetSpec, string) error {
		installCalls++
		return nil
	})
	if err != nil || status.Source != "none" || resolveCalls != 0 || installCalls != 0 {
		t.Fatalf("status = %#v, resolve calls = %d, install calls = %d, err = %v", status, resolveCalls, installCalls, err)
	}
}

func TestLatestMihomoAssetUsesBackendCatalog(t *testing.T) {
	want, supported := componentcatalog.Mihomo(runtime.GOOS, runtime.GOARCH)
	if !supported {
		t.Skipf("no managed Mihomo target for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	spec, asset, err := latestMihomoAsset(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Version != want.Version || spec.Name != want.Name || asset.BrowserDownloadURL != want.URL || asset.Digest != "sha256:"+want.SHA256 || asset.Size <= 0 {
		t.Fatalf("backend catalog resolver = %#v / %#v, want %#v", spec, asset, want)
	}
}

func TestInstallManagedMihomoOnNewMachineUsesLatest(t *testing.T) {
	requireLinux(t)
	t.Chdir(t.TempDir())
	t.Setenv("MIHOMO_BIN", "")
	t.Setenv("PATH", "")

	installCalls := 0
	installed, err := installManagedMihomo(context.Background(), testLatestResolver("1.19.29"), func(_ context.Context, _ ghAsset, spec mihomoAssetSpec, dst string) error {
		installCalls++
		if spec.Version != "1.19.29" {
			t.Fatalf("install version = %q", spec.Version)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, fakeMihomo("1.19.29", 0), 0o755)
	})
	if err != nil {
		t.Fatalf("installManagedMihomo() error = %v", err)
	}
	if installCalls != 1 || !installed.Ready || installed.Source != "managed" || installed.CurrentVersion != "1.19.29" || installed.TargetVersion != "1.19.29" {
		t.Fatalf("installed status = %#v, install calls = %d", installed, installCalls)
	}
}

func TestMihomoCoreStatusPreservesLocalReadinessWhenLatestCheckFails(t *testing.T) {
	requireLinux(t)
	t.Chdir(t.TempDir())
	t.Setenv("MIHOMO_BIN", "")
	t.Setenv("PATH", "")
	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, fakeMihomo("1.19.29", 0), 0o755); err != nil {
		t.Fatal(err)
	}

	status := getMihomoCoreStatus(context.Background(), func(context.Context) (mihomoAssetSpec, ghAsset, error) {
		return mihomoAssetSpec{}, ghAsset{}, errors.New("github unavailable")
	})
	if !status.Ready || status.CurrentVersion != "1.19.29" || !strings.Contains(status.LatestError, "github unavailable") {
		t.Fatalf("status = %#v", status)
	}
}

func TestInstallManagedMihomoDoesNotDowngradeOrOverwriteExternalCore(t *testing.T) {
	requireLinux(t)

	t.Run("newer managed core", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv("MIHOMO_BIN", "")
		t.Setenv("PATH", "")
		local := filepath.Join(mihomoCacheDir, mihomoBinName())
		if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(local, fakeMihomo("1.20.0", 0), 0o755); err != nil {
			t.Fatal(err)
		}
		resolveCalls, installCalls := 0, 0
		status, err := installManagedMihomo(context.Background(), func(context.Context) (mihomoAssetSpec, ghAsset, error) {
			resolveCalls++
			return testLatestResolver("1.19.29")(context.Background())
		}, func(context.Context, ghAsset, mihomoAssetSpec, string) error {
			installCalls++
			return nil
		})
		if err != nil || resolveCalls != 1 || installCalls != 0 || status.UpdateAvailable || status.CurrentVersion != "1.20.0" {
			t.Fatalf("newer managed status = %#v, resolve calls = %d, install calls = %d, err = %v", status, resolveCalls, installCalls, err)
		}
	})

	t.Run("MIHOMO_BIN", func(t *testing.T) {
		t.Chdir(t.TempDir())
		external := filepath.Join(t.TempDir(), "mihomo-external")
		if err := os.WriteFile(external, fakeMihomo("1.19.28", 0), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("MIHOMO_BIN", external)
		t.Setenv("PATH", "")
		resolveCalls, installCalls := 0, 0
		status, err := installManagedMihomo(context.Background(), func(context.Context) (mihomoAssetSpec, ghAsset, error) {
			resolveCalls++
			return testLatestResolver("1.19.29")(context.Background())
		}, func(context.Context, ghAsset, mihomoAssetSpec, string) error {
			installCalls++
			return nil
		})
		if !errors.Is(err, ErrMihomoExternallyManaged) || resolveCalls != 0 || installCalls != 0 || status.Source != "env" || status.Manageable {
			t.Fatalf("external status = %#v, resolve calls = %d, install calls = %d, err = %v", status, resolveCalls, installCalls, err)
		}
	})
}

func TestDownloadMihomoAssetVerifiesCompressedSHA256AndVersion(t *testing.T) {
	requireLinux(t)
	payload := fakeMihomo("1.19.28", 0)
	compressed := gzipBytes(t, payload)
	server := assetServer(compressed)
	defer server.Close()

	spec := testAssetSpec(compressed)
	dst := filepath.Join(t.TempDir(), "mihomo")
	err := downloadMihomoAsset(context.Background(), server.Client(), testGHAsset(server.URL, spec, int64(len(compressed))), spec, dst)
	if err != nil {
		t.Fatalf("downloadMihomoAsset() error = %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", dst, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("installed payload = %q, want %q", got, payload)
	}
	if info, err := os.Stat(dst); err != nil {
		t.Fatalf("Stat(%q): %v", dst, err)
	} else if info.Mode().Perm()&0111 == 0 {
		t.Fatalf("installed mode = %v, want executable", info.Mode())
	}
}

func TestDownloadMihomoAssetRejectsMissingOrInvalidReleaseDigestBeforeRequest(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	compressed := gzipBytes(t, fakeMihomo("1.19.28", 0))
	spec := testAssetSpec(compressed)
	tests := []struct {
		name   string
		digest string
	}{
		{name: "missing"},
		{name: "wrong algorithm", digest: "sha512:" + strings.Repeat("0", 128)},
		{name: "wrong length", digest: "sha256:abcd"},
		{name: "invalid hex", digest: "sha256:" + strings.Repeat("z", 64)},
		{name: "differs from pinned", digest: sha256Digest([]byte("other asset"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := testGHAsset(server.URL, spec, int64(len(compressed)))
			asset.Digest = tt.digest
			err := downloadMihomoAsset(context.Background(), server.Client(), asset, spec, filepath.Join(t.TempDir(), "mihomo"))
			if err == nil {
				t.Fatal("downloadMihomoAsset() error = nil, want digest error")
			}
			if !strings.Contains(err.Error(), "digest") && !strings.Contains(err.Error(), "sha256") {
				t.Fatalf("downloadMihomoAsset() error = %q, want digest context", err)
			}
		})
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("HTTP requests = %d, want 0 for invalid release metadata", got)
	}
}

func TestDownloadMihomoAssetDigestMismatchPreservesExistingBinary(t *testing.T) {
	requireLinux(t)
	payload := fakeMihomo("1.19.28", 0)
	compressed := gzipBytes(t, payload)
	server := assetServer(compressed)
	defer server.Close()

	dir, dst, original := existingBinary(t)
	// The trusted and API digests intentionally cover the decompressed payload.
	// Downloading must still hash the compressed release asset and reject it.
	spec := testAssetSpec(payload)
	err := downloadMihomoAsset(context.Background(), server.Client(), testGHAsset(server.URL, spec, int64(len(compressed))), spec, dst)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 校验失败") {
		t.Fatalf("downloadMihomoAsset() error = %v, want digest mismatch", err)
	}
	assertPreservedOnly(t, dir, dst, original)
}

func TestDownloadMihomoAssetRejectsUnexpectedVersionBeforeRename(t *testing.T) {
	requireLinux(t)
	payload := fakeMihomo("1.19.27", 0)
	compressed := gzipBytes(t, payload)
	server := assetServer(compressed)
	defer server.Close()

	dir, dst, original := existingBinary(t)
	spec := testAssetSpec(compressed)
	err := downloadMihomoAsset(context.Background(), server.Client(), testGHAsset(server.URL, spec, int64(len(compressed))), spec, dst)
	if err == nil || !strings.Contains(err.Error(), "版本不匹配") {
		t.Fatalf("downloadMihomoAsset() error = %v, want version mismatch", err)
	}
	assertPreservedOnly(t, dir, dst, original)
}

func TestDownloadMihomoAssetEnforcesSizeLimits(t *testing.T) {
	requireLinux(t)
	payload := fakeMihomo("1.19.28", 128)
	compressed := gzipBytes(t, payload)

	t.Run("compressed", func(t *testing.T) {
		server := assetServer(compressed)
		defer server.Close()
		dir, dst, original := existingBinary(t)
		spec := testAssetSpec(compressed)
		err := downloadMihomoAssetWithLimits(
			context.Background(), server.Client(), testGHAsset(server.URL, spec, int64(len(compressed))), spec, dst,
			int64(len(compressed)-1), int64(len(payload)+1),
		)
		if err == nil || !strings.Contains(err.Error(), "压缩大小") {
			t.Fatalf("downloadMihomoAssetWithLimits() error = %v, want compressed size error", err)
		}
		assertPreservedOnly(t, dir, dst, original)
	})

	t.Run("decompressed", func(t *testing.T) {
		server := assetServer(compressed)
		defer server.Close()
		dir, dst, original := existingBinary(t)
		spec := testAssetSpec(compressed)
		err := downloadMihomoAssetWithLimits(
			context.Background(), server.Client(), testGHAsset(server.URL, spec, int64(len(compressed))), spec, dst,
			int64(len(compressed)+1), int64(len(payload)-1),
		)
		if err == nil || !strings.Contains(err.Error(), "解压大小") {
			t.Fatalf("downloadMihomoAssetWithLimits() error = %v, want decompressed size error", err)
		}
		assertPreservedOnly(t, dir, dst, original)
	})
}

func TestFetchMihomoReleaseUsesGitHubAPIHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Errorf("GitHub API headers = %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"tag_name":"v1.19.29","draft":false,"prerelease":false,"assets":[]}`)
	}))
	defer server.Close()

	release, err := fetchMihomoRelease(context.Background(), server.Client(), server.URL)
	if err != nil || release.TagName != "v1.19.29" {
		t.Fatalf("fetchMihomoRelease() = %#v, %v", release, err)
	}
}

func testAssetSpec(compressed []byte) mihomoAssetSpec {
	return mihomoAssetSpec{
		Tag:     "v1.19.28",
		Version: "1.19.28",
		Name:    "mihomo-linux-amd64-v1-v1.19.28.gz",
		Digest:  sha256Digest(compressed),
	}
}

func testGHAsset(url string, spec mihomoAssetSpec, size int64) ghAsset {
	return ghAsset{
		Name: spec.Name, BrowserDownloadURL: url, Digest: spec.Digest,
		State: "uploaded", ContentType: "application/gzip", Size: size,
	}
}

func testLatestResolver(version string) mihomoLatestResolver {
	return func(context.Context) (mihomoAssetSpec, ghAsset, error) {
		name, _ := managedMihomoAssetNames("linux", runtime.GOARCH, version)
		assetName := "mihomo-linux-amd64-v1-v" + version + ".gz"
		if len(name) > 0 {
			assetName = name[0]
		}
		spec := mihomoAssetSpec{Tag: "v" + version, Version: version, Name: assetName, Digest: "sha256:" + strings.Repeat("0", 64)}
		return spec, ghAsset{Name: spec.Name, Digest: spec.Digest}, nil
	}
}

func releaseAsset(tag, name string) ghAsset {
	return ghAsset{
		Name:               name,
		BrowserDownloadURL: "https://github.com/MetaCubeX/mihomo/releases/download/" + tag + "/" + name,
		Digest:             "sha256:" + strings.Repeat("a", 64),
		State:              "uploaded",
		ContentType:        "application/gzip",
		Size:               1024,
	}
}

func fakeMihomo(version string, padding int) []byte {
	return []byte("#!/bin/sh\necho 'Mihomo Meta v" + version + " linux amd64'\n# " + strings.Repeat("x", padding) + "\n")
}

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

func assetServer(data []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
}

func existingBinary(t *testing.T) (dir, dst string, original []byte) {
	t.Helper()
	dir = t.TempDir()
	dst = filepath.Join(dir, "mihomo")
	original = []byte("current binary")
	if err := os.WriteFile(dst, original, 0755); err != nil {
		t.Fatalf("WriteFile(%q): %v", dst, err)
	}
	return dir, dst, original
}

func assertPreservedOnly(t *testing.T, dir, dst string, original []byte) {
	t.Helper()
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", dst, err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing binary = %q, want unchanged %q", got, original)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(dst) {
		t.Fatalf("directory entries = %v, want only existing binary", entryNames(entries))
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("automatic Mihomo downloads are pinned for Linux only")
	}
}
