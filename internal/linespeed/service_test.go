package linespeed

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type tarFixtureEntry struct {
	name     string
	typeflag byte
	linkname string
	body     []byte
}

func makeTarFixture(t *testing.T, entries ...tarFixtureEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	writer := tar.NewWriter(gz)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0o755,
			Typeflag: typeflag,
			Linkname: entry.linkname,
			Size:     int64(len(entry.body)),
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func newOfficialFixtureService(t *testing.T, archive []byte, binary []byte) *Service {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)
	service := NewService(t.TempDir())
	service.goos = "linux"
	service.goarch = "fixture"
	service.artifactsOverride = []artifact{{
		name:       "fixture",
		url:        server.URL,
		archiveSHA: testDigest(archive),
		binarySHA:  testDigest(binary),
	}}
	service.runCommand = func(_ context.Context, name string, args []string, files []*os.File, _ []string, _, _ int64) ([]byte, []byte, error) {
		if name != managedBinaryFDPath || len(files) != 1 || files[0] == nil {
			t.Fatalf("expected verified executable FD, name=%q files=%#v", name, files)
		}
		if reflect.DeepEqual(args, []string{"--version"}) {
			return []byte("Speedtest by Ookla 1.2.0.84 (fixture)\n"), nil, nil
		}
		return nil, nil, errors.New("unexpected command")
	}
	return service
}

func TestParseResultSkipsLicenseTextAndLogRecords(t *testing.T) {
	result, err := parseResult([]byte(`==============================================================================
License acceptance recorded. Continuing.
{"type":"log","message":"selecting server"}
{"type":"result","ping":{"latency":12.5,"jitter":0.75},"download":{"bandwidth":125000000},"upload":{"bandwidth":25000000},"packetLoss":1.5,"isp":"Transit Ltd","interface":{"externalIp":"203.0.113.7"},"server":{"name":"Example ISP","location":"Shanghai","country":"China"}}
`))
	if err != nil {
		t.Fatal(err)
	}
	if result.DownloadMbps != 1000 || result.UploadMbps != 200 || result.PingMS != 12.5 {
		t.Fatalf("unexpected converted metrics: %#v", result)
	}
	if result.JitterMS == nil || *result.JitterMS != 0.75 || result.PacketLossPercent == nil || *result.PacketLossPercent != 1.5 {
		t.Fatalf("missing optional official metrics: %#v", result)
	}
	if result.TestServer != "Example ISP" || result.ServerLocation != "Shanghai, China" || result.EgressIP != "203.0.113.7" {
		t.Fatalf("unexpected server identity: %#v", result)
	}
	if result.Implementation != ResultImplementation {
		t.Fatalf("implementation=%q", result.Implementation)
	}
}

func TestParseResultRequiresResultRecord(t *testing.T) {
	if _, err := parseResult([]byte("license\n{\"type\":\"log\"}\n")); err == nil {
		t.Fatal("log-only output unexpectedly parsed as a result")
	}
}

func TestInstallRequiresExplicitLicenseConsent(t *testing.T) {
	binary := []byte("official fixture")
	archive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: binary})
	service := newOfficialFixtureService(t, archive, binary)
	if _, err := service.Install(context.Background(), false); !errors.Is(err, ErrLicenseNotAccepted) {
		t.Fatalf("Install error=%v, want ErrLicenseNotAccepted", err)
	}
	if _, err := os.Stat(service.binaryPath()); !os.IsNotExist(err) {
		t.Fatalf("binary was written without explicit consent: %v", err)
	}
}

func TestInstallAndRemovePinnedOfficialBinary(t *testing.T) {
	binary := []byte("official fixture")
	archive := makeTarFixture(t,
		tarFixtureEntry{name: managedBinaryName, body: binary},
		tarFixtureEntry{name: "speedtest.md", body: []byte("documentation")},
	)
	service := newOfficialFixtureService(t, archive, binary)

	status, err := service.Install(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Supported || !status.Managed || !status.Installed || !status.Owned || !status.LicenseAccepted || status.Version != Version {
		t.Fatalf("unexpected installed status: %#v", status)
	}
	got, err := os.ReadFile(service.binaryPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(binary) {
		t.Fatalf("installed binary mismatch: %q", got)
	}
	if marker, err := os.ReadFile(service.licenseMarkerPath()); err != nil || string(marker) != licenseMarkerContents {
		t.Fatalf("license marker=%q err=%v", marker, err)
	}

	status, err = service.Remove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Installed || status.Owned || status.LicenseAccepted {
		t.Fatalf("unexpected removed status: %#v", status)
	}
	if _, err := os.Stat(service.licenseMarkerPath()); !os.IsNotExist(err) {
		t.Fatalf("license marker remains after removal: %v", err)
	}
	if _, err := os.Stat(service.homeDir()); !os.IsNotExist(err) {
		t.Fatalf("managed HOME remains after removal: %v", err)
	}
	if _, err := os.Stat(service.configDir()); !os.IsNotExist(err) {
		t.Fatalf("managed XDG config remains after removal: %v", err)
	}
}

func TestRemoveClearsTrustedRuntimeStateAndInterruptedTemps(t *testing.T) {
	binary := []byte("official fixture")
	archive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: binary})
	service := newOfficialFixtureService(t, archive, binary)
	if _, err := service.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(service.homeDir(), "speedtest-cli.json"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(service.configDir(), "config.json"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".ookla-speedtest-archive-crash", ".ookla-speedtest-binary-crash", ".arcway-managed-crash"} {
		if err := os.WriteFile(filepath.Join(service.dir, name), []byte("temp"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{service.homeDir(), service.configDir(), filepath.Join(service.dir, ".ookla-speedtest-archive-crash"), filepath.Join(service.dir, ".ookla-speedtest-binary-crash"), filepath.Join(service.dir, ".arcway-managed-crash")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("managed runtime state remains at %q: %v", path, err)
		}
	}
}

func TestInstallRejectsDigestMismatchWithoutReplacingExistingBinary(t *testing.T) {
	binary := []byte("official fixture")
	archive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: binary})
	service := newOfficialFixtureService(t, archive, binary)
	service.artifactsOverride[0].archiveSHA = strings.Repeat("0", 64)
	if _, err := service.Install(context.Background(), true); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("Install error=%v, want digest failure", err)
	}
	if _, err := os.Stat(service.binaryPath()); !os.IsNotExist(err) {
		t.Fatalf("untrusted binary was installed: %v", err)
	}
}

func TestInstallRejectsUnsafeArchiveEntries(t *testing.T) {
	for name, entries := range map[string][]tarFixtureEntry{
		"symlink":                {{name: "speedtest-link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}},
		"traversal":              {{name: "../speedtest", body: []byte("bad")}},
		"not regular executable": {{name: managedBinaryName, typeflag: tar.TypeSymlink, linkname: "/bin/sh"}},
	} {
		t.Run(name, func(t *testing.T) {
			binary := []byte("official fixture")
			archive := makeTarFixture(t, append(entries, tarFixtureEntry{name: managedBinaryName, body: binary})...)
			service := newOfficialFixtureService(t, archive, binary)
			if _, err := service.Install(context.Background(), true); err == nil {
				t.Fatal("unsafe archive unexpectedly installed")
			}
			if _, err := os.Stat(service.binaryPath()); !os.IsNotExist(err) {
				t.Fatalf("unsafe archive left a binary: %v", err)
			}
		})
	}
}

func TestInstallFallsBackToSecondARMArtifact(t *testing.T) {
	badBinary := []byte("first ABI")
	goodBinary := []byte("second ABI")
	badArchive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: badBinary})
	goodArchive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: goodBinary})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/armhf":
			_, _ = w.Write(badArchive)
		case "/armel":
			_, _ = w.Write(goodArchive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	service := NewService(t.TempDir())
	service.goos = "linux"
	service.goarch = "arm"
	service.artifactsOverride = []artifact{
		{name: "armhf", url: server.URL + "/armhf", archiveSHA: testDigest(badArchive), binarySHA: testDigest(badBinary)},
		{name: "armel", url: server.URL + "/armel", archiveSHA: testDigest(goodArchive), binarySHA: testDigest(goodBinary)},
	}
	service.runCommand = func(_ context.Context, _ string, args []string, files []*os.File, _ []string, _, _ int64) ([]byte, []byte, error) {
		if !reflect.DeepEqual(args, []string{"--version"}) || len(files) != 1 {
			t.Fatalf("unexpected version invocation %#v", args)
		}
		if _, err := files[0].Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(files[0])
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(contents, badBinary) {
			return nil, []byte("Exec format error"), errors.New("Exec format error")
		}
		return []byte("Speedtest by Ookla 1.2.0.84\n"), nil, nil
	}
	if _, err := service.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(service.binaryPath())
	if err != nil || !bytes.Equal(got, goodBinary) {
		t.Fatalf("armel fallback binary=%q err=%v", got, err)
	}
}

func TestRunUsesFixedArgumentsTrustedEnvironmentAndSingleFlight(t *testing.T) {
	binary := []byte("official fixture")
	archive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: binary})
	service := newOfficialFixtureService(t, archive, binary)
	if _, err := service.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	service.runCommand = func(_ context.Context, name string, args []string, files []*os.File, env []string, _, _ int64) ([]byte, []byte, error) {
		if name != managedBinaryFDPath || len(files) != 1 || files[0] == nil {
			t.Fatalf("run did not use verified executable descriptor: name=%q files=%#v", name, files)
		}
		if reflect.DeepEqual(args, []string{"--version"}) {
			return []byte("Speedtest by Ookla 1.2.0.84\n"), nil, nil
		}
		wantArgs := []string{"--accept-license", "--accept-gdpr", "--progress=no", "--format=json"}
		if !reflect.DeepEqual(args, wantArgs) {
			t.Fatalf("run args=%#v, want %#v", args, wantArgs)
		}
		if !containsEnv(env, "HOME="+service.homeDir()) || !containsEnv(env, "XDG_CONFIG_HOME="+service.configDir()) {
			t.Fatalf("run did not isolate Ookla state: %#v", env)
		}
		close(started)
		<-release
		return []byte(`{"type":"result","ping":{"latency":10},"download":{"bandwidth":1000000},"upload":{"bandwidth":500000},"server":{},"interface":{}}`), nil, nil
	}

	done := make(chan error, 1)
	go func() {
		_, err := service.Run(context.Background())
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first run did not start")
	}
	if !service.Status(context.Background()).Running {
		t.Fatal("status did not report active run")
	}
	if _, err := service.Run(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent Run error=%v, want ErrBusy", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunRequiresTrustedLicenseMarker(t *testing.T) {
	binary := []byte("official fixture")
	archive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: binary})
	service := newOfficialFixtureService(t, archive, binary)
	if _, err := service.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(service.licenseMarkerPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Run(context.Background()); !errors.Is(err, ErrLicenseNotAccepted) {
		t.Fatalf("Run error=%v, want ErrLicenseNotAccepted", err)
	}
}

func TestStatusRejectsWritableManagedFilesAndDirectories(t *testing.T) {
	binary := []byte("official fixture")
	archive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: binary})
	service := newOfficialFixtureService(t, archive, binary)
	if _, err := service.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(service.binaryPath(), 0o775); err != nil {
		t.Fatal(err)
	}
	if status := service.Status(context.Background()); status.Installed {
		t.Fatalf("group-writable binary was trusted: %#v", status)
	}
	if err := os.Chmod(service.binaryPath(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(service.dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if status := service.Status(context.Background()); status.Installed {
		t.Fatalf("group-writable managed directory was trusted: %#v", status)
	}
	if err := os.Chmod(service.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(service.binaryPath(), 65534, -1); err != nil {
			t.Fatal(err)
		}
		if status := service.Status(context.Background()); status.Installed {
			t.Fatalf("binary owned by an unrelated uid was trusted: %#v", status)
		}
		if err := os.Chown(service.binaryPath(), 0, -1); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStatusRejectsUnsupportedOperatingSystems(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			service := NewService(t.TempDir())
			service.goos = goos
			status := service.Status(context.Background())
			if status.Supported || status.Managed || status.Installed {
				t.Fatalf("%s status=%#v", goos, status)
			}
		})
	}
}

func containsEnv(env []string, want string) bool {
	for _, item := range env {
		if item == want {
			return true
		}
	}
	return false
}

func TestCommandEnvironmentReplacesExistingOverrides(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://untrusted.invalid")
	t.Setenv("XDG_DATA_HOME", "/outside")
	env := commandEnvironment([]string{"HOME=/arcway/home", "XDG_CONFIG_HOME=/arcway/config", "PATH=/usr/bin"})
	if !reflect.DeepEqual(env, []string{"HOME=/arcway/home", "XDG_CONFIG_HOME=/arcway/config", "PATH=/usr/bin"}) {
		t.Fatalf("command environment inherited service variables: %#v", env)
	}
}

func TestRuntimeEnvironmentIsCompleteAndPanelOwned(t *testing.T) {
	service := NewService(t.TempDir())
	t.Setenv("HTTP_PROXY", "http://untrusted.invalid")
	t.Setenv("XDG_CACHE_HOME", "/outside")
	env := service.runtimeEnv()
	for _, want := range []string{
		"HOME=" + service.homeDir(),
		"XDG_CONFIG_HOME=" + service.configDir(),
		"XDG_DATA_HOME=" + service.homeDir(),
		"XDG_CACHE_HOME=" + service.homeDir(),
		"XDG_STATE_HOME=" + service.homeDir(),
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"TZ=UTC",
	} {
		if !containsEnv(env, want) {
			t.Fatalf("runtime environment missing %q: %#v", want, env)
		}
	}
}

func TestMarkerIsPanelOwnedAndNotSystemProfile(t *testing.T) {
	binary := []byte("official fixture")
	archive := makeTarFixture(t, tarFixtureEntry{name: managedBinaryName, body: binary})
	service := newOfficialFixtureService(t, archive, binary)
	if _, err := service.Install(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(service.homeDir(), service.dir+string(filepath.Separator)) || !strings.HasPrefix(service.configDir(), service.dir+string(filepath.Separator)) {
		t.Fatalf("Ookla state escaped managed directory: home=%q config=%q dir=%q", service.homeDir(), service.configDir(), service.dir)
	}
}
