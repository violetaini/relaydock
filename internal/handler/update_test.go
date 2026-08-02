package handler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/version"
)

func TestVerifyBinaryChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arcway")
	content := []byte("verified release asset")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%x", sha256.Sum256(content))
	if err := verifyBinaryChecksum(path, expected); err != nil {
		t.Fatalf("valid checksum rejected: %v", err)
	}
	if err := verifyBinaryChecksum(path, ""); err == nil {
		t.Fatal("missing checksum accepted")
	}
	if err := verifyBinaryChecksum(path, fmt.Sprintf("%064x", 1)); err == nil {
		t.Fatal("mismatched checksum accepted")
	}
}

func TestDetectUpdateEnvironment(t *testing.T) {
	tests := []struct {
		name        string
		docker      bool
		webRoot     string
		deployment  string
		scope       string
		external    bool
		canApply    bool
		warningPart string
	}{
		{
			name:       "standalone embedded frontend",
			deployment: updateDeploymentStandalone,
			scope:      updateScopeFull,
			canApply:   true,
		},
		{
			name:        "standalone external frontend",
			webRoot:     "/opt/arcway/web/current",
			deployment:  updateDeploymentStandalone,
			scope:       updateScopeBackendOnly,
			external:    true,
			canApply:    true,
			warningPart: "外置前端",
		},
		{
			name:        "docker cannot apply in place",
			docker:      true,
			webRoot:     "/app/web",
			deployment:  updateDeploymentDocker,
			scope:       updateScopeNone,
			external:    true,
			canApply:    false,
			warningPart: "docker compose pull",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectUpdateEnvironment(tt.docker, tt.webRoot)
			if got.DeploymentMode != tt.deployment || got.UpdateScope != tt.scope || got.ExternalWebRoot != tt.external || got.CanApply != tt.canApply {
				t.Fatalf("environment = %+v", got)
			}
			if tt.warningPart != "" && !strings.Contains(got.Warning, tt.warningPart) {
				t.Fatalf("warning %q does not contain %q", got.Warning, tt.warningPart)
			}
		})
	}
}

func TestPopulateUpdateEnvironmentDisablesMissingAsset(t *testing.T) {
	info := &UpdateInfo{}
	populateUpdateEnvironment(info, updateEnvironment{
		DeploymentMode: updateDeploymentStandalone,
		UpdateScope:    updateScopeFull,
		CanApply:       true,
	})
	if info.CanApply {
		t.Fatal("missing platform asset remained applicable")
	}
	if !strings.Contains(info.Warning, "没有适用于本机") {
		t.Fatalf("unexpected warning: %q", info.Warning)
	}
}

func TestPopulateGuardEnvironment(t *testing.T) {
	base := detectUpdateEnvironment(false, "")
	withoutDir := populateGuardEnvironment(base, "")
	if withoutDir.UpdateScope != updateScopeControlPlane || !withoutDir.CanApply {
		t.Fatalf("unexpected environment without guard dir: %+v", withoutDir)
	}
	if !strings.Contains(withoutDir.Warning, "守卫资产目录") {
		t.Fatalf("missing guard warning: %q", withoutDir.Warning)
	}

	withEmptyDir := populateGuardEnvironment(base, t.TempDir())
	if withEmptyDir.UpdateScope != updateScopeFull || !withEmptyDir.CanApply {
		t.Fatalf("unexpected environment with guard dir: %+v", withEmptyDir)
	}
	if !strings.Contains(withEmptyDir.Warning, "将在本次更新中补齐") {
		t.Fatalf("missing repair warning: %q", withEmptyDir.Warning)
	}

	withRelativeDir := populateGuardEnvironment(base, "relative/guards")
	if withRelativeDir.CanApply || withRelativeDir.UpdateScope != updateScopeNone {
		t.Fatalf("relative guard path remained applicable: %+v", withRelativeDir)
	}

	disabledExternal := populateGuardEnvironment(updateEnvironment{
		DeploymentMode:  updateDeploymentStandalone,
		UpdateScope:     updateScopeNone,
		ExternalWebRoot: true,
		CanApply:        false,
		Warning:         "platform update disabled",
	}, t.TempDir())
	if !strings.Contains(disabledExternal.Warning, "platform update disabled") || strings.Contains(disabledExternal.Warning, "本次会更新") {
		t.Fatalf("disabled platform warning was replaced: %+v", disabledExternal)
	}
}

func TestPopulateUpdateEnvironmentDisablesIncompleteGuardRelease(t *testing.T) {
	info := &UpdateInfo{
		DownloadURL:   "https://github.com/violetaini/relaydock/releases/download/v1.2.3/arcway-linux-amd64",
		guardAssetDir: "/opt/arcway/guard-assets",
		missingGuards: []string{"arcway-expiry-guard-linux-arm64"},
	}
	populateUpdateEnvironment(info, updateEnvironment{
		DeploymentMode: updateDeploymentStandalone,
		UpdateScope:    updateScopeFull,
		CanApply:       true,
	})
	if info.CanApply {
		t.Fatal("incomplete guard release remained applicable")
	}
	if !strings.Contains(info.Warning, "版本不一致") {
		t.Fatalf("unexpected warning: %q", info.Warning)
	}
}

func TestUpdateHandlersRejectWrongMethodWithoutNetwork(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		method  string
		allow   string
	}{
		{"status", NewUpdateStatusHandler(), http.MethodPost, http.MethodGet},
		{"check", NewUpdateCheckHandler(), http.MethodPost, http.MethodGet},
		{"apply", NewUpdateApplyHandler(), http.MethodGet, http.MethodPost},
		{"apply sse", NewUpdateApplySSEHandler(), http.MethodGet, http.MethodPost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			tt.handler.ServeHTTP(response, httptest.NewRequest(tt.method, "/", nil))
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405; body=%s", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Allow"); got != tt.allow {
				t.Fatalf("Allow = %q, want %q", got, tt.allow)
			}
		})
	}
}

func TestUpdateStatusHandlerReportsLocalState(t *testing.T) {
	finishUpdate()
	t.Setenv("DOCKER", "1")
	t.Setenv("ARCWAY_WEB_ROOT", "/app/external-web")
	response := httptest.NewRecorder()
	NewUpdateStatusHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/admin/update/status", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	var status UpdateStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.CurrentVersion != version.Version || status.DeploymentMode != updateDeploymentDocker || status.UpdateScope != updateScopeNone {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.CanApply || !status.ExternalWebRoot || status.UpdateRunning {
		t.Fatalf("unexpected Docker capabilities: %+v", status)
	}
}

func TestDockerApplyHandlersRejectWithoutContactingGitHub(t *testing.T) {
	finishUpdate()
	t.Setenv("DOCKER", "1")
	for name, handler := range map[string]http.Handler{
		"json": NewUpdateApplyHandler(),
		"sse":  NewUpdateApplySSEHandler(),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", nil))
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body=%s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "docker compose pull") {
				t.Fatalf("missing actionable Docker instruction: %s", response.Body.String())
			}
		})
	}
}

func TestUpdateConcurrencyGuard(t *testing.T) {
	finishUpdate()
	if !beginUpdate() {
		t.Fatal("first update did not acquire guard")
	}
	if beginUpdate() {
		t.Fatal("concurrent update acquired guard")
	}
	finishUpdate()
	if !beginUpdate() {
		t.Fatal("guard was not released")
	}
	finishUpdate()
}

func TestSystemUpdateLockExcludesInstallerAndOtherProcesses(t *testing.T) {
	t.Setenv("ARCWAY_INSTALL_LOCK_FILE", filepath.Join(t.TempDir(), "arcway-install.lock"))
	first, err := acquireSystemUpdateLock()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	if _, err := acquireSystemUpdateLock(); !errors.Is(err, errUpdateBusy) {
		t.Fatalf("second lock error = %v, want errUpdateBusy", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireSystemUpdateLock()
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBeginUpdateSessionReleasesMemoryGuardWhenSystemLockIsBusy(t *testing.T) {
	finishUpdate()
	t.Setenv("ARCWAY_INSTALL_LOCK_FILE", filepath.Join(t.TempDir(), "arcway-install.lock"))
	installerLock, err := acquireSystemUpdateLock()
	if err != nil {
		t.Fatal(err)
	}
	defer installerLock.Close()

	if _, err := beginUpdateSession(); !errors.Is(err, errUpdateBusy) {
		t.Fatalf("begin session error = %v, want errUpdateBusy", err)
	}
	if updateInProgress.Load() {
		t.Fatal("in-memory update guard remained locked after system lock failure")
	}
}

func TestValidateRequestedVersionRejectsReleaseDrift(t *testing.T) {
	info := &UpdateInfo{LatestVersion: "0.6.1"}
	matching := httptest.NewRequest(http.MethodPost, "/?version=v0.6.1", nil)
	if err := validateRequestedVersion(matching, info); err != nil {
		t.Fatalf("matching version rejected: %v", err)
	}
	drifted := httptest.NewRequest(http.MethodPost, "/?version=0.6.0", nil)
	if err := validateRequestedVersion(drifted, info); err == nil || !strings.Contains(err.Error(), "重新检查") {
		t.Fatalf("release drift error = %v", err)
	}
}

func TestSelectReleaseAssetValidatesURLAndDigest(t *testing.T) {
	const binaryName = "arcway-linux-amd64"
	valid := GitHubRelease{
		TagName: "v1.2.3",
		Assets: []GitHubReleaseAsset{{
			Name:               binaryName,
			BrowserDownloadURL: "https://github.com/violetaini/relaydock/releases/download/v1.2.3/arcway-linux-amd64",
			Digest:             "sha256:" + strings.Repeat("a", 64),
		}},
	}
	downloadURL, digest, err := selectReleaseAsset(valid, binaryName)
	if err != nil {
		t.Fatalf("valid asset rejected: %v", err)
	}
	if downloadURL == "" || digest != strings.Repeat("a", 64) {
		t.Fatalf("unexpected asset result: url=%q digest=%q", downloadURL, digest)
	}

	badHost := valid
	badHost.Assets = append([]GitHubReleaseAsset(nil), valid.Assets...)
	badHost.Assets[0].BrowserDownloadURL = "https://example.com/v1.2.3/arcway-linux-amd64"
	if _, _, err := selectReleaseAsset(badHost, binaryName); err == nil {
		t.Fatal("non-GitHub asset URL accepted")
	}

	badDigest := valid
	badDigest.Assets = append([]GitHubReleaseAsset(nil), valid.Assets...)
	badDigest.Assets[0].Digest = "sha256:not-a-digest"
	if _, _, err := selectReleaseAsset(badDigest, binaryName); err == nil {
		t.Fatal("invalid asset digest accepted")
	}
}

func TestSelectBothGuardReleaseAssets(t *testing.T) {
	release := GitHubRelease{TagName: "v1.2.3"}
	for _, arch := range []string{"amd64", "arm64"} {
		name := "arcway-expiry-guard-linux-" + arch
		release.Assets = append(release.Assets, GitHubReleaseAsset{
			Name:               name,
			BrowserDownloadURL: "https://github.com/violetaini/relaydock/releases/download/v1.2.3/" + name,
			Digest:             "sha256:" + strings.Repeat(arch[:1], 64),
		})
	}
	for _, asset := range release.Assets {
		assetURL, digest, err := selectReleaseAsset(release, asset.Name)
		if err != nil || assetURL == "" || len(digest) != 64 {
			t.Fatalf("guard asset %s not selectable: url=%q digest=%q err=%v", asset.Name, assetURL, digest, err)
		}
	}
}

func TestReleaseTagPattern(t *testing.T) {
	for _, tag := range []string{"v0.5.1", "v10.20.300"} {
		if !releaseTagPattern.MatchString(tag) {
			t.Fatalf("valid release tag %q rejected", tag)
		}
	}
	for _, tag := range []string{"0.5.1", "v0x5x1", "v0.5.1/../../asset", "v0.5.1-rc1", "v0.5"} {
		if releaseTagPattern.MatchString(tag) {
			t.Fatalf("invalid release tag %q accepted", tag)
		}
	}
}

func TestVerifyBinaryFormat(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBinaryFormat(executable); err != nil {
		t.Fatalf("current test executable rejected: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "not-a-binary")
	if err := os.WriteFile(bad, []byte("not an executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBinaryFormat(bad); err == nil {
		t.Fatal("invalid binary format accepted")
	}
	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	if err := verifyBinaryFormatFor(executable, "linux", otherArch); err == nil {
		t.Fatal("wrong ELF architecture accepted")
	}
}

func TestReplaceBinaryIsAtomicAndExecutable(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "download")
	target := filepath.Join(dir, "arcway")
	if err := os.WriteFile(source, []byte("new version"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old version"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(source, target); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new version" {
		t.Fatalf("target content = %q", content)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("target mode = %o, want 755", info.Mode().Perm())
	}
}

func TestInstallUpdateFilesRollsBackEarlierFiles(t *testing.T) {
	dir := t.TempDir()
	firstSource := filepath.Join(dir, "first-new")
	firstTarget := filepath.Join(dir, "first")
	firstBackup := filepath.Join(dir, "first.bak")
	secondSource := filepath.Join(dir, "second-new")
	secondTarget := filepath.Join(dir, "second-target-directory")
	for path, content := range map[string]string{
		firstSource:  "first-new",
		firstTarget:  "first-old",
		firstBackup:  "first-old",
		secondSource: "second-new",
	} {
		if err := os.WriteFile(path, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(secondTarget, 0755); err != nil {
		t.Fatal(err)
	}
	files := []preparedUpdateFile{
		{Name: "first", SourcePath: firstSource, TargetPath: firstTarget, BackupPath: firstBackup, HadTarget: true},
		{Name: "second", SourcePath: secondSource, TargetPath: secondTarget},
	}
	if err := installUpdateFiles(files); err == nil {
		t.Fatal("transaction with invalid second target succeeded")
	}
	content, err := os.ReadFile(firstTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "first-old" {
		t.Fatalf("first file was not rolled back: %q", content)
	}
}

func TestInstallUpdateFilesRollsBackCurrentFileAfterPostRenameSyncFailure(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "new")
	target := filepath.Join(dir, "arcway")
	backup := filepath.Join(dir, "arcway.bak")
	for path, content := range map[string]string{
		source: "new version",
		target: "old version",
		backup: "old version",
	} {
		if err := os.WriteFile(path, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	previousSync := syncUpdateDirectory
	syncCalls := 0
	syncUpdateDirectory = func(string) error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("simulated directory fsync failure")
		}
		return nil
	}
	t.Cleanup(func() { syncUpdateDirectory = previousSync })

	files := []preparedUpdateFile{{
		Name:       "arcway",
		SourcePath: source,
		TargetPath: target,
		BackupPath: backup,
		HadTarget:  true,
	}}
	if err := installUpdateFiles(files); err == nil {
		t.Fatal("post-rename sync failure unexpectedly completed")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old version" {
		t.Fatalf("current file was not rolled back after post-rename failure: %q", content)
	}
}

func TestRestartSelfReturnsExecFailure(t *testing.T) {
	previous := execProcess
	execProcess = func(string, []string, []string) error {
		return fmt.Errorf("exec rejected")
	}
	defer func() { execProcess = previous }()
	if err := restartSelf("/missing/arcway"); err == nil || !strings.Contains(err.Error(), "exec rejected") {
		t.Fatalf("restart error = %v", err)
	}
}
