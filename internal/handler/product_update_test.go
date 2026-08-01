package handler

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/productrelease"
	"github.com/violetaini/relaydock/internal/version"
)

func productTestAsset(name string) productrelease.Asset {
	return productrelease.Asset{
		Name:   name,
		SHA256: strings.Repeat("a", 64),
		Size:   1,
	}
}

func productTestManifest(releaseID string, controlChanged, webChanged bool) productrelease.Manifest {
	control := productrelease.Component{
		Version:     version.Version,
		APIContract: version.APIContract,
		Changed:     controlChanged,
	}
	if controlChanged {
		control.Assets = []productrelease.Asset{productTestAsset("arcway-test")}
	}
	web := productrelease.Component{
		Version:     releaseID,
		APIContract: version.APIContract,
		Changed:     webChanged,
	}
	if webChanged {
		web.Assets = []productrelease.Asset{productTestAsset("relaydock-web.tar.gz")}
	}
	return productrelease.Manifest{
		Schema:    productrelease.SchemaVersion,
		ReleaseID: releaseID,
		Components: map[string]productrelease.Component{
			productrelease.ComponentControlPlane: control,
			productrelease.ComponentWeb:          web,
		},
	}
}

func productTestInstalledState(releaseID string, manifest productrelease.Manifest) productrelease.InstalledState {
	return productrelease.NewInstalledState(releaseID, manifest.Components)
}

func TestProductComponentStatusAllowsTargetControlPlaneAPI(t *testing.T) {
	manifest := productTestManifest("v1.2.3", true, true)
	manifest.Components[productrelease.ComponentControlPlane] = productrelease.Component{
		Version:     "1.2.3",
		APIContract: version.APIContract + 1,
		Changed:     true,
		Assets:      []productrelease.Asset{productTestAsset("arcway-test")},
	}
	manifest.Components[productrelease.ComponentWeb] = productrelease.Component{
		Version:     "v1.2.3",
		APIContract: version.APIContract + 1,
		Changed:     true,
		Assets:      []productrelease.Asset{productTestAsset("relaydock-web.tar.gz")},
	}
	if err := validateProductReleaseCompatibility(manifest); err != nil {
		t.Fatalf("target control-plane API was rejected: %v", err)
	}
	installed := productTestInstalledState("v1.2.2", productTestManifest("v1.2.2", false, false))
	statuses := productComponentStatuses(installed, manifest, &UpdateInfo{HasUpdate: true})
	for _, status := range statuses {
		if status.Required && !status.Compatible {
			t.Fatalf("required target component marked incompatible: %+v", status)
		}
	}
}

func TestProductReleaseRecognizesLaterOptionalAssetSetup(t *testing.T) {
	manifest := productTestManifest("v1.2.3", false, false)
	manifest.Components[productrelease.ComponentGuard] = productrelease.Component{
		Version:     version.Version,
		APIContract: version.APIContract,
		Changed:     true,
		Assets:      []productrelease.Asset{productTestAsset("arcway-expiry-guard-linux-amd64")},
	}
	installed := productTestInstalledState("v1.2.3", productTestManifest("v1.2.3", false, false))
	info := &UpdateInfo{guardAssetDir: t.TempDir()}
	if !productReleaseNeedsApply(installed, manifest, info) {
		t.Fatal("newly configured guard assets were not marked for installation")
	}
	statuses := productComponentStatuses(installed, manifest, info)
	for _, status := range statuses {
		if status.Name == productrelease.ComponentGuard && (status.Action != "update" || !status.Required) {
			t.Fatalf("guard status = %+v", status)
		}
	}
}

func TestLoadCurrentProductStateRequiresVerifiedLegacyExternalWebRelease(t *testing.T) {
	root := productTestManagedWebRoot(t)
	legacyRelease := filepath.Join(root, "releases", "frontend-e5e6f4e")
	if err := os.Rename(filepath.Join(root, "releases", "v1.0.0"), legacyRelease); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/frontend-e5e6f4e", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}

	installed, managedRoot, warning := loadCurrentProductState(t.TempDir(), filepath.Join(root, "current"))
	if managedRoot != root || warning != "" {
		t.Fatalf("legacy external web state = root=%q warning=%q", managedRoot, warning)
	}
	if _, recorded := installed.Components[productrelease.ComponentWeb]; recorded {
		t.Fatalf("legacy unverified web release was recorded as current: %+v", installed)
	}
	manifest := productTestManifest("v1.2.3", false, true)
	if !productReleaseNeedsApply(installed, manifest, &UpdateInfo{ExternalWebRoot: true, ManagedExternalWeb: true}) {
		t.Fatal("legacy external web release was not marked for migration")
	}
}

func TestLoadCurrentProductStateReconcilesInstalledWebLink(t *testing.T) {
	root := productTestManagedWebRoot(t)
	stateDir := t.TempDir()
	recorded := productTestInstalledState("v1.0.1", productTestManifest("v1.0.1", false, false))
	if err := productrelease.WriteInstalledState(stateDir, recorded); err != nil {
		t.Fatal(err)
	}

	installed, managedRoot, warning := loadCurrentProductState(stateDir, filepath.Join(root, "current"))
	if managedRoot != root || warning != "" {
		t.Fatalf("reconciled external web state = root=%q warning=%q", managedRoot, warning)
	}
	if _, recorded := installed.Components[productrelease.ComponentWeb]; recorded {
		t.Fatalf("mismatched web link remained recorded: %+v", installed)
	}
}

func TestTargetProductReleaseIgnoresTerminalTransaction(t *testing.T) {
	terminal := &productUpdateJob{ReleaseID: "v1.2.2", Phase: "committed"}
	if got := targetProductRelease("v1.2.3", terminal); got != "v1.2.3" {
		t.Fatalf("terminal transaction target = %q", got)
	}
	running := &productUpdateJob{ReleaseID: "v1.2.2", Phase: "waiting_for_health"}
	if got := targetProductRelease("v1.2.3", running); got != "v1.2.2" {
		t.Fatalf("running transaction target = %q", got)
	}
}

func TestResolveProductReleaseAssetsChecksGitHubSizeAndDigest(t *testing.T) {
	manifest := productTestManifest("v1.2.3", true, true)
	assets := []GitHubReleaseAsset{}
	for _, name := range manifest.AssetNames() {
		assets = append(assets, GitHubReleaseAsset{
			Name:               name,
			BrowserDownloadURL: "https://github.com/violetaini/relaydock/releases/download/v1.2.3/" + name,
			Digest:             "sha256:" + strings.Repeat("a", 64),
			Size:               1,
		})
	}
	release := GitHubRelease{TagName: "v1.2.3", Assets: assets}
	resolved, err := resolveProductReleaseAssets(release, manifest)
	if err != nil || len(resolved) != len(assets) {
		t.Fatalf("valid product assets failed: resolved=%v err=%v", resolved, err)
	}
	release.Assets[0].Size = 2
	if _, err := resolveProductReleaseAssets(release, manifest); err == nil {
		t.Fatal("mismatched GitHub asset size was accepted")
	}
}

func TestApplyProductWebOnlyRelease(t *testing.T) {
	root := productTestManagedWebRoot(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	t.Setenv(productUpdateStateDirEnv, stateDir)
	t.Setenv("ARCWAY_WEB_ROOT", filepath.Join(root, "current"))
	t.Setenv("ARCWAY_DATA_DIR", filepath.Join(t.TempDir(), "data"))
	t.Setenv("ARCWAY_INSTALL_LOCK_FILE", filepath.Join(t.TempDir(), "arcway-install.lock"))

	manifest := productTestManifest("v1.0.1", false, true)
	archive := filepath.Join(t.TempDir(), "relaydock-web.tar.gz")
	productTestWriteWebArchive(t, archive, productrelease.WebMetadata{
		Schema:      productrelease.SchemaVersion,
		ReleaseID:   manifest.ReleaseID,
		APIContract: version.APIContract,
	})
	content, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))

	oldDownloader := productReleaseAssetDownloader
	productReleaseAssetDownloader = func(asset updateReleaseAsset) (string, error) {
		return archive, nil
	}
	t.Cleanup(func() { productReleaseAssetDownloader = oldDownloader })

	info := &UpdateInfo{
		HasUpdate:          true,
		TargetRelease:      manifest.ReleaseID,
		ExternalWebRoot:    true,
		ManagedExternalWeb: true,
		productManifest:    &manifest,
		productAssets: map[string]updateReleaseAsset{
			"relaydock-web.tar.gz": {
				Name:   "relaydock-web.tar.gz",
				SHA256: digest,
				Size:   int64(len(content)),
			},
		},
		managedWebRoot: root,
	}
	job, scheduled, err := applyProductRelease(info, nil)
	if err != nil || scheduled {
		t.Fatalf("web-only apply scheduled=%v job=%+v err=%v", scheduled, job, err)
	}
	if release, err := productrelease.CurrentManagedWebRelease(filepath.Join(root, "current")); err != nil || release != manifest.ReleaseID {
		t.Fatalf("current frontend release = %q, %v", release, err)
	}
	installed, err := productrelease.LoadInstalledState(stateDir)
	if err != nil || installed.ReleaseID != manifest.ReleaseID {
		t.Fatalf("installed state = %+v, %v", installed, err)
	}
	if persisted, err := loadProductUpdateJob(stateDir); err != nil || persisted.Phase != "committed" {
		t.Fatalf("web transaction = %+v, %v", persisted, err)
	} else if persisted.Activation == nil || !persisted.RollbackReady {
		t.Fatalf("web transaction did not persist its write-ahead rollback record: %+v", persisted)
	}
}

func TestRunProductUpdateHelperCommitsAndRollsBack(t *testing.T) {
	t.Run("commit after health check", func(t *testing.T) {
		job, target := productTestHelperJob(t, http.StatusOK)
		if err := RunProductUpdateHelper(productUpdateJobPath(job.StateDir)); err != nil {
			t.Fatal(err)
		}
		if content, err := os.ReadFile(target); err != nil || string(content) != "new" {
			t.Fatalf("updated binary content = %q, %v", content, err)
		}
		installed, err := productrelease.LoadInstalledState(job.StateDir)
		if err != nil || installed.ReleaseID != job.ReleaseID {
			t.Fatalf("installed release = %+v, %v", installed, err)
		}
		persisted, err := loadProductUpdateJob(job.StateDir)
		if err != nil || persisted.Phase != "committed" {
			t.Fatalf("transaction = %+v, %v", persisted, err)
		}
	})

	t.Run("rollback after health failure", func(t *testing.T) {
		job, target := productTestHelperJob(t, http.StatusServiceUnavailable)
		previous := *job.PreviousState
		if err := RunProductUpdateHelper(productUpdateJobPath(job.StateDir)); err == nil {
			t.Fatal("health failure committed the update")
		}
		if content, err := os.ReadFile(target); err != nil || string(content) != "old" {
			t.Fatalf("rolled-back binary content = %q, %v", content, err)
		}
		installed, err := productrelease.LoadInstalledState(job.StateDir)
		if err != nil || installed.ReleaseID != previous.ReleaseID {
			t.Fatalf("restored installed release = %+v, %v", installed, err)
		}
		persisted, err := loadProductUpdateJob(job.StateDir)
		if err != nil || persisted.Phase != "rolled_back" {
			t.Fatalf("transaction = %+v, %v", persisted, err)
		}
	})
}

func TestProductUpdateRollbackStopFailureRequiresManualRecovery(t *testing.T) {
	job, target := productTestHelperJob(t, http.StatusServiceUnavailable)
	oldCommand := productUpdateCommand
	stopCalls := 0
	productUpdateCommand = func(ctx context.Context, _ string, arguments ...string) *exec.Cmd {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProductUpdateSystemctlCommand$")
		environment := append(os.Environ(), "ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_HELPER=1")
		if len(arguments) > 0 && arguments[0] == "stop" {
			stopCalls++
			if stopCalls == 2 {
				environment = append(environment, "ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_FAIL=1")
			}
		}
		command.Env = environment
		return command
	}
	t.Cleanup(func() { productUpdateCommand = oldCommand })

	if err := RunProductUpdateHelper(productUpdateJobPath(job.StateDir)); err == nil {
		t.Fatal("rollback stop failure unexpectedly completed")
	}
	// The second stop failed, so rollback must not touch a potentially live
	// binary or database. The operator gets a durable manual-recovery state.
	if content, err := os.ReadFile(target); err != nil || string(content) != "new" {
		t.Fatalf("binary changed after rollback stop failure: %q, %v", content, err)
	}
	persisted, err := loadProductUpdateJob(job.StateDir)
	if err != nil || persisted.Phase != "recovery_required" {
		t.Fatalf("transaction = %+v, %v", persisted, err)
	}
}

func TestProductUpdateInitialStopFailureRestartsOldControlPlane(t *testing.T) {
	job, target := productTestHelperJob(t, http.StatusOK)
	oldCommand := productUpdateCommand
	stopCalls := 0
	productUpdateCommand = func(ctx context.Context, _ string, arguments ...string) *exec.Cmd {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProductUpdateSystemctlCommand$")
		environment := append(os.Environ(), "ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_HELPER=1")
		if len(arguments) > 0 && arguments[0] == "stop" {
			stopCalls++
			if stopCalls == 1 {
				environment = append(environment, "ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_FAIL=1")
			}
		}
		command.Env = environment
		return command
	}
	t.Cleanup(func() { productUpdateCommand = oldCommand })

	if err := RunProductUpdateHelper(productUpdateJobPath(job.StateDir)); err == nil {
		t.Fatal("initial stop failure unexpectedly completed")
	}
	if content, err := os.ReadFile(target); err != nil || string(content) != "old" {
		t.Fatalf("binary changed after initial stop failure: %q, %v", content, err)
	}
	persisted, err := loadProductUpdateJob(job.StateDir)
	if err != nil || persisted.Phase != "failed" {
		t.Fatalf("transaction = %+v, %v", persisted, err)
	}
}

func TestResumeScheduledProductUpdateFailureAllowsOldControlPlaneToStart(t *testing.T) {
	job, _ := productTestHelperJob(t, http.StatusOK)
	t.Setenv(productUpdateStateDirEnv, job.StateDir)
	oldCommand := productUpdateCommand
	productUpdateCommand = func(ctx context.Context, name string, _ ...string) *exec.Cmd {
		if name == "systemctl" {
			return exec.CommandContext(ctx, "sh", "-c", "exit 3")
		}
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProductUpdateSystemctlCommand$")
		command.Env = append(os.Environ(), "ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_HELPER=1", "ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_FAIL=1")
		return command
	}
	t.Cleanup(func() { productUpdateCommand = oldCommand })

	if wait, err := ResumeProductUpdateOnStartup(); err != nil || wait {
		t.Fatalf("scheduled startup recovery wait=%v err=%v", wait, err)
	}
	persisted, err := loadProductUpdateJob(job.StateDir)
	if err != nil || persisted.Phase != "failed" {
		t.Fatalf("transaction = %+v, %v", persisted, err)
	}
}

func TestResumeProductUpdateAllowsManualRecoveryState(t *testing.T) {
	job, _ := productTestHelperJob(t, http.StatusOK)
	t.Setenv(productUpdateStateDirEnv, job.StateDir)
	job.Phase = "recovery_required"
	job.Error = "manual repair needed"
	if err := writeProductUpdateJob(job); err != nil {
		t.Fatal(err)
	}
	if wait, err := ResumeProductUpdateOnStartup(); err != nil || wait {
		t.Fatalf("manual recovery blocked control-plane startup: wait=%v err=%v", wait, err)
	}
	if err := RunProductUpdateHelper(productUpdateJobPath(job.StateDir)); err != nil {
		t.Fatalf("manual recovery helper retried the transaction: %v", err)
	}
	persisted, err := loadProductUpdateJob(job.StateDir)
	if err != nil || persisted.Phase != "recovery_required" {
		t.Fatalf("manual recovery transaction = %+v, %v", persisted, err)
	}
}

func TestRunProductUpdateHelperCommitsExternalFrontendWithControlPlane(t *testing.T) {
	job, _ := productTestHelperJob(t, http.StatusOK)
	root := productTestManagedWebRoot(t)
	manifest := productTestManifest(job.ReleaseID, true, true)
	metadata := productrelease.WebMetadata{Schema: productrelease.SchemaVersion, ReleaseID: job.ReleaseID, APIContract: version.APIContract}
	archive := filepath.Join(t.TempDir(), "relaydock-web.tar.gz")
	productTestWriteWebArchive(t, archive, metadata)
	staging, err := productrelease.StageWebArchive(archive, root, job.ReleaseID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	job.Manifest = manifest
	job.InstalledState = productTestInstalledState(job.ReleaseID, manifest)
	job.Web = &productWebPreparation{Root: root, Staging: staging, Metadata: metadata}
	if err := writeProductUpdateJob(job); err != nil {
		t.Fatal(err)
	}
	if err := RunProductUpdateHelper(productUpdateJobPath(job.StateDir)); err != nil {
		t.Fatal(err)
	}
	if release, err := productrelease.CurrentManagedWebRelease(filepath.Join(root, "current")); err != nil || release != job.ReleaseID {
		t.Fatalf("active external frontend = %q, %v", release, err)
	}
	persisted, err := loadProductUpdateJob(job.StateDir)
	if err != nil || persisted.Phase != "committed" || persisted.Activation == nil {
		t.Fatalf("full transaction = %+v, %v", persisted, err)
	}
}

func TestResumeProductUpdateOnStartupRollsBackInterruptedWebRelease(t *testing.T) {
	root := productTestManagedWebRoot(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	t.Setenv(productUpdateStateDirEnv, stateDir)
	t.Setenv("ARCWAY_INSTALL_LOCK_FILE", filepath.Join(t.TempDir(), "arcway-install.lock"))
	manifest := productTestManifest("v1.0.1", false, true)
	metadata := productrelease.WebMetadata{Schema: productrelease.SchemaVersion, ReleaseID: manifest.ReleaseID, APIContract: version.APIContract}
	archive := filepath.Join(t.TempDir(), "relaydock-web.tar.gz")
	productTestWriteWebArchive(t, archive, metadata)
	staging, err := productrelease.StageWebArchive(archive, root, manifest.ReleaseID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := productrelease.PrepareWebActivation(root, staging, manifest.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if err := productrelease.ActivatePreparedWebRelease(root, activation); err != nil {
		t.Fatal(err)
	}
	previousManifest := productTestManifest("v1.0.0", false, false)
	previous := productTestInstalledState("v1.0.0", previousManifest)
	job := productUpdateJob{
		Schema:         productUpdateJobSchema,
		ID:             strings.Repeat("e", 24),
		ReleaseID:      manifest.ReleaseID,
		Manifest:       manifest,
		InstalledState: productTestInstalledState(manifest.ReleaseID, manifest),
		PreviousState:  &previous,
		Web:            &productWebPreparation{Root: root, Staging: staging, Metadata: metadata},
		Activation:     &activation,
		StateDir:       stateDir,
		DataDirectory:  t.TempDir(),
		ServiceUnit:    "arcway-test",
		HealthURL:      "http://127.0.0.1:12889" + productUpdateHealthPath,
		HealthToken:    strings.Repeat("f", 64),
		TargetVersion:  version.Version,
		RollbackReady:  true,
		Phase:          "activating",
		StartedAt:      time.Now().UTC(),
	}
	if err := writeProductUpdateJob(job); err != nil {
		t.Fatal(err)
	}
	if wait, err := ResumeProductUpdateOnStartup(); err != nil || wait {
		t.Fatalf("startup recovery wait=%v err=%v", wait, err)
	}
	if release, err := productrelease.CurrentManagedWebRelease(filepath.Join(root, "current")); err != nil || release != "v1.0.0" {
		t.Fatalf("recovered frontend release = %q, %v", release, err)
	}
	persisted, err := loadProductUpdateJob(stateDir)
	if err != nil || persisted.Phase != "rolled_back" {
		t.Fatalf("recovered transaction = %+v, %v", persisted, err)
	}
}

func TestVerifyProductWebReleaseChecksServedMetadata(t *testing.T) {
	root := productTestManagedWebRoot(t)
	metadata := productrelease.WebMetadata{Schema: productrelease.SchemaVersion, ReleaseID: "v1.0.1", APIContract: version.APIContract}
	archive := filepath.Join(t.TempDir(), "relaydock-web.tar.gz")
	productTestWriteWebArchive(t, archive, metadata)
	staging, err := productrelease.StageWebArchive(archive, root, metadata.ReleaseID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := productrelease.PrepareWebActivation(root, staging, metadata.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if err := productrelease.ActivatePreparedWebRelease(root, activation); err != nil {
		t.Fatal(err)
	}
	served := metadata
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(served)
	}))
	defer server.Close()
	job := productUpdateJob{
		ReleaseID:    metadata.ReleaseID,
		Web:          &productWebPreparation{Root: root, Staging: staging, Metadata: metadata},
		WebHealthURL: server.URL + productUpdateWebHealthPath,
	}
	if err := verifyProductWebRelease(job); err != nil {
		t.Fatalf("valid served frontend metadata: %v", err)
	}
	served.ReleaseID = "v9.9.9"
	if err := verifyProductWebRelease(job); err == nil {
		t.Fatal("mismatched served frontend metadata was accepted")
	}
}

func TestUpdateStatusLocksPersistentProductTransaction(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv(productUpdateStateDirEnv, stateDir)
	manifest := productTestManifest("v1.2.3", false, false)
	job := productUpdateJob{
		Schema:         productUpdateJobSchema,
		ID:             strings.Repeat("b", 24),
		ReleaseID:      manifest.ReleaseID,
		Manifest:       manifest,
		InstalledState: productTestInstalledState(manifest.ReleaseID, manifest),
		StateDir:       stateDir,
		DataDirectory:  t.TempDir(),
		ServiceUnit:    "arcway-test",
		HealthURL:      "http://127.0.0.1:12889" + productUpdateHealthPath,
		HealthToken:    strings.Repeat("c", 64),
		TargetVersion:  version.Version,
		Phase:          "recovery_required",
		StartedAt:      time.Now().UTC(),
	}
	if err := writeProductUpdateJob(job); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/admin/update/status", nil)
	response := httptest.NewRecorder()
	NewUpdateStatusHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status response = %d", response.Code)
	}
	var status UpdateStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !status.UpdateRunning || status.CanApply || status.TransactionState != "recovery_required" {
		t.Fatalf("status did not lock persistent transaction: %+v", status)
	}
}

func TestUpdateHealthHandlerRequiresLoopbackToken(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv(productUpdateStateDirEnv, stateDir)
	manifest := productTestManifest("v1.2.3", false, false)
	job := productUpdateJob{
		Schema:         productUpdateJobSchema,
		ID:             strings.Repeat("a", 24),
		ReleaseID:      manifest.ReleaseID,
		Manifest:       manifest,
		InstalledState: productTestInstalledState(manifest.ReleaseID, manifest),
		StateDir:       stateDir,
		DataDirectory:  t.TempDir(),
		ServiceUnit:    "arcway-test",
		HealthURL:      "http://127.0.0.1:18080" + productUpdateHealthPath,
		HealthToken:    strings.Repeat("b", 64),
		TargetVersion:  version.Version,
		Phase:          "waiting_for_health",
		StartedAt:      time.Now().UTC(),
	}
	if err := writeProductUpdateJob(job); err != nil {
		t.Fatal(err)
	}
	handler := NewUpdateHealthHandler()
	request := httptest.NewRequest(http.MethodGet, productUpdateHealthPath, nil)
	request.RemoteAddr = "127.0.0.1:2345"
	request.Header.Set("X-Arcway-Update-Token", job.HealthToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid health request returned %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, productUpdateHealthPath, nil)
	request.RemoteAddr = "127.0.0.1:2345"
	request.Header.Set("X-Arcway-Update-Token", "wrong")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("invalid health token returned %d", response.Code)
	}
}

func productTestHelperJob(t *testing.T, healthStatus int) (productUpdateJob, string) {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "arcway.db"), []byte("old-db"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "bin", "arcway")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "download", "arcway")
	if err := os.MkdirAll(filepath.Dir(source), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest := productTestManifest("v1.2.3", true, false)
	previousManifest := productTestManifest("v1.2.2", false, false)
	previous := productTestInstalledState("v1.2.2", previousManifest)
	installed := productTestInstalledState(manifest.ReleaseID, manifest)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(healthStatus)
		if healthStatus == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":      version.Version,
				"release_id":   manifest.ReleaseID,
				"api_contract": version.APIContract,
			})
		}
	}))
	t.Cleanup(server.Close)
	job := productUpdateJob{
		Schema:         productUpdateJobSchema,
		ID:             strings.Repeat("c", 24),
		ReleaseID:      manifest.ReleaseID,
		Manifest:       manifest,
		InstalledState: installed,
		PreviousState:  &previous,
		Files: []preparedUpdateFile{{
			Name:       "arcway",
			SourcePath: source,
			TargetPath: target,
			BackupPath: target + ".bak",
		}},
		StateDir:      stateDir,
		DataDirectory: dataDir,
		ServiceUnit:   "arcway-test",
		HealthURL:     server.URL,
		HealthToken:   strings.Repeat("d", 64),
		TargetVersion: version.Version,
		Phase:         "scheduled",
		StartedAt:     time.Now().UTC(),
	}
	if err := writeProductUpdateJob(job); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCWAY_INSTALL_LOCK_FILE", filepath.Join(root, "arcway-install.lock"))
	oldCommand := productUpdateCommand
	productUpdateCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProductUpdateSystemctlCommand$")
		command.Env = append(os.Environ(), "ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_HELPER=1")
		return command
	}
	t.Cleanup(func() { productUpdateCommand = oldCommand })
	oldTimeout, oldInterval := productUpdateHealthTimeout, productUpdateHealthInterval
	productUpdateHealthTimeout = 30 * time.Millisecond
	productUpdateHealthInterval = time.Millisecond
	t.Cleanup(func() {
		productUpdateHealthTimeout = oldTimeout
		productUpdateHealthInterval = oldInterval
	})
	return job, target
}

func TestProductUpdateSystemctlCommand(t *testing.T) {
	if os.Getenv("ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_HELPER") != "1" {
		return
	}
	if os.Getenv("ARCWAY_PRODUCT_UPDATE_SYSTEMCTL_FAIL") == "1" {
		os.Exit(1)
	}
}

func productTestManagedWebRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	current := filepath.Join(root, "releases", "v1.0.0")
	if err := os.MkdirAll(filepath.Join(current, "assets"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "index.html"), []byte(`<html>__RELAYDOCK_DEFAULT_THEME__<script src="/assets/old.js"></script></html>`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "assets", "old.js"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(productrelease.WebMetadata{Schema: productrelease.SchemaVersion, ReleaseID: "v1.0.0", APIContract: version.APIContract})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, productrelease.WebMetadataFilename), metadata, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/v1.0.0", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	return root
}

func productTestWriteWebArchive(t *testing.T, path string, metadata productrelease.WebMetadata) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	writer := tar.NewWriter(gzipWriter)
	write := func(name, content string) {
		t.Helper()
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", `<html>__RELAYDOCK_DEFAULT_THEME__<script src="/assets/app.js"></script></html>`)
	write("assets/app.js", "console.log('new')")
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	write(productrelease.WebMetadataFilename, string(raw))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
