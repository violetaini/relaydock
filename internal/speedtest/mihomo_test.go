package speedtest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
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
)

func TestPinnedMihomoAssets(t *testing.T) {
	tests := []struct {
		goarch string
		name   string
		digest string
	}{
		{
			goarch: "amd64",
			name:   "mihomo-linux-amd64-compatible-v1.19.28.gz",
			digest: "sha256:70d01cfb8cb7bf7a92fd1af16cb4b9553d90bb4eecde3b5c4849103e27c80ddb",
		},
		{
			goarch: "arm64",
			name:   "mihomo-linux-arm64-v1.19.28.gz",
			digest: "sha256:2474450cd1c41dfa53036a54a4e85579f493d3af524d86c3d4b8e2b240b56cd2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.goarch, func(t *testing.T) {
			spec, ok := pinnedMihomoAsset("linux", tt.goarch)
			if !ok {
				t.Fatal("pinnedMihomoAsset() supported = false, want true")
			}
			if spec.Tag != pinnedMihomoTag || spec.Version != "1.19.28" {
				t.Fatalf("pinned release = %s/%s, want %s/1.19.28", spec.Tag, spec.Version, pinnedMihomoTag)
			}
			if spec.Name != tt.name || spec.Digest != tt.digest {
				t.Fatalf("pinned asset = %q %q, want %q %q", spec.Name, spec.Digest, tt.name, tt.digest)
			}
			if _, err := parseSHA256Digest(spec.Digest); err != nil {
				t.Fatalf("parseSHA256Digest(%q): %v", spec.Digest, err)
			}
		})
	}

	for _, platform := range [][2]string{{"darwin", "amd64"}, {"windows", "amd64"}, {"linux", "386"}} {
		if _, ok := pinnedMihomoAsset(platform[0], platform[1]); ok {
			t.Fatalf("pinnedMihomoAsset(%q, %q) supported = true, want false", platform[0], platform[1])
		}
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

func TestDownloadMihomoAssetVerifiesCompressedSHA256AndVersion(t *testing.T) {
	requireLinux(t)
	payload := fakeMihomo("1.19.28", 0)
	compressed := gzipBytes(t, payload)
	server := assetServer(compressed)
	defer server.Close()

	spec := testAssetSpec(compressed)
	dst := filepath.Join(t.TempDir(), "mihomo")
	err := downloadMihomoAsset(context.Background(), server.Client(), testGHAsset(server.URL, spec), spec, dst)
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
			asset := testGHAsset(server.URL, spec)
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
	err := downloadMihomoAsset(context.Background(), server.Client(), testGHAsset(server.URL, spec), spec, dst)
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
	err := downloadMihomoAsset(context.Background(), server.Client(), testGHAsset(server.URL, spec), spec, dst)
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
			context.Background(), server.Client(), testGHAsset(server.URL, spec), spec, dst,
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
			context.Background(), server.Client(), testGHAsset(server.URL, spec), spec, dst,
			int64(len(compressed)+1), int64(len(payload)-1),
		)
		if err == nil || !strings.Contains(err.Error(), "解压大小") {
			t.Fatalf("downloadMihomoAssetWithLimits() error = %v, want decompressed size error", err)
		}
		assertPreservedOnly(t, dir, dst, original)
	})
}

func testAssetSpec(compressed []byte) mihomoAssetSpec {
	return mihomoAssetSpec{
		Tag:     pinnedMihomoTag,
		Version: "1.19.28",
		Name:    "mihomo-linux-amd64-compatible-v1.19.28.gz",
		Digest:  sha256Digest(compressed),
	}
}

func testGHAsset(url string, spec mihomoAssetSpec) ghAsset {
	return ghAsset{Name: spec.Name, BrowserDownloadURL: url, Digest: spec.Digest}
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
