package handler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/productrelease"
	"github.com/violetaini/relaydock/internal/runtimepaths"
	"github.com/violetaini/relaydock/internal/version"
)

// populateProductReleaseInfo upgrades a legacy binary-only GitHub release into
// a product transaction when the release carries the verified manifest. Older
// releases deliberately retain the previous updater behaviour, which lets an
// installation migrate in one controlled bootstrap deployment.
func populateProductReleaseInfo(info *UpdateInfo, release GitHubRelease) error {
	manifestAsset, manifestDigest, err := selectGitHubReleaseAsset(release, releaseManifestAssetName)
	if err != nil {
		return err
	}
	if manifestAsset.Name == "" {
		return nil
	}
	if manifestAsset.Size <= 0 {
		return errors.New("GitHub 产品发布清单没有有效大小")
	}
	manifestPath, err := downloadVerifiedReleaseAsset(updateReleaseAsset{
		Name:        manifestAsset.Name,
		DownloadURL: manifestAsset.BrowserDownloadURL,
		SHA256:      manifestDigest,
		Size:        manifestAsset.Size,
	})
	if err != nil {
		return fmt.Errorf("下载产品发布清单: %w", err)
	}
	defer os.Remove(manifestPath)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("读取产品发布清单: %w", err)
	}
	manifest, err := productrelease.Parse(raw)
	if err != nil {
		return err
	}
	if manifest.ReleaseID != release.TagName {
		return fmt.Errorf("产品发布清单 release_id %s 与 GitHub 标签 %s 不一致", manifest.ReleaseID, release.TagName)
	}
	assets, err := resolveProductReleaseAssets(release, manifest)
	if err != nil {
		return err
	}
	if err := validateProductReleaseCompatibility(manifest); err != nil {
		return err
	}

	stateDir, err := productUpdateStateDir()
	if err != nil {
		return err
	}
	externalWebRoot := strings.TrimSpace(os.Getenv("ARCWAY_WEB_ROOT"))
	installed, managedRoot, stateWarning := loadCurrentProductState(stateDir, externalWebRoot)
	adoptionWarning := ""
	if stateWarning == "" {
		adopted, changed, adoptionErr := adoptLegacyEmbeddedProductState(stateDir, externalWebRoot, manifest, assets, info)
		if adoptionErr != nil {
			adoptionWarning = "无法记录旧版更新后的产品状态，仍可通过面板执行完整更新。"
		} else if changed {
			installed = adopted
		}
	}
	info.productManifest = &manifest
	info.productAssets = assets
	info.managedWebRoot = managedRoot
	info.ProductRelease = installed.ReleaseID
	info.TargetRelease = manifest.ReleaseID
	info.APIContract = manifest.Components[productrelease.ComponentWeb].APIContract
	info.ManagedExternalWeb = strings.TrimSpace(os.Getenv("ARCWAY_WEB_ROOT")) != "" && managedRoot != ""
	info.HasUpdate = productReleaseNeedsApply(installed, manifest, info)
	info.productInternalComponents = productInternalComponentStatuses(installed, manifest, info)
	info.Components = visibleProductComponentStatuses(info.productInternalComponents)
	if stateWarning != "" {
		info.Warning = appendUpdateWarning(info.Warning, stateWarning)
		info.productStateUnsafe = true
	}
	if adoptionWarning != "" {
		info.Warning = appendUpdateWarning(info.Warning, adoptionWarning)
	}
	if transaction, transactionErr := loadProductUpdateJob(stateDir); transactionErr == nil {
		info.TransactionState = transaction.Phase
		info.TargetRelease = targetProductRelease(manifest.ReleaseID, &transaction)
	} else if !productrelease.IsNotExist(transactionErr) {
		info.Warning = appendUpdateWarning(info.Warning, "无法读取上次产品更新事务状态，网页更新已暂停。")
	}
	return nil
}

// adoptLegacyEmbeddedProductState recognizes the last step of the legacy
// updater. Before product manifests existed, it replaced the control-plane
// binary and configured managed local assets in place, but could not record the
// product transaction state added later. A verified embedded deployment can
// safely seed that state, avoiding a redundant second update prompt.
func adoptLegacyEmbeddedProductState(stateDir, externalWebRoot string, manifest productrelease.Manifest, assets map[string]updateReleaseAsset, info *UpdateInfo) (productrelease.InstalledState, bool, error) {
	if strings.TrimSpace(externalWebRoot) != "" || manifest.ReleaseID != "v"+version.Version {
		return productrelease.InstalledState{}, false, nil
	}
	if _, err := productrelease.LoadInstalledState(stateDir); err == nil {
		return productrelease.InstalledState{}, false, nil
	} else if !productrelease.IsNotExist(err) {
		return productrelease.InstalledState{}, false, err
	}
	if _, err := loadProductUpdateJob(stateDir); err == nil {
		return productrelease.InstalledState{}, false, nil
	} else if !productrelease.IsNotExist(err) {
		return productrelease.InstalledState{}, false, err
	}

	control, hasControl := manifest.Components[productrelease.ComponentControlPlane]
	web, hasWeb := manifest.Components[productrelease.ComponentWeb]
	if !hasControl || !hasWeb || !control.Changed || !web.Changed || strings.TrimPrefix(control.Version, "v") != version.Version || control.APIContract != version.APIContract || web.APIContract != version.APIContract {
		return productrelease.InstalledState{}, false, nil
	}
	controlAsset, exists := assets[productBinaryAssetName()]
	if !exists {
		return productrelease.InstalledState{}, false, nil
	}
	executable, err := os.Executable()
	if err != nil || verifyReleaseAssetFile(executable, controlAsset) != nil {
		return productrelease.InstalledState{}, false, nil
	}

	components := map[string]productrelease.InstalledComponent{
		productrelease.ComponentControlPlane: {Version: control.Version, APIContract: control.APIContract},
		productrelease.ComponentWeb:          {Version: web.Version, APIContract: web.APIContract},
	}
	adoptLegacyManagedProductComponent(components, productrelease.ComponentGuard, info.guardAssetDir, manifest, assets)

	state := productrelease.InstalledState{
		Schema:     productrelease.SchemaVersion,
		ReleaseID:  manifest.ReleaseID,
		UpdatedAt:  time.Now().UTC(),
		Components: components,
	}
	if err := productrelease.WriteInstalledState(stateDir, state); err != nil {
		return productrelease.InstalledState{}, false, err
	}
	return state, true, nil
}

func adoptLegacyManagedProductComponent(components map[string]productrelease.InstalledComponent, componentName, assetDir string, manifest productrelease.Manifest, assets map[string]updateReleaseAsset) {
	component, exists := manifest.Components[componentName]
	assetDir = strings.TrimSpace(assetDir)
	if !exists || !component.Changed || assetDir == "" || !filepath.IsAbs(assetDir) {
		return
	}
	for _, declared := range component.Assets {
		asset, exists := assets[declared.Name]
		if !exists || verifyReleaseAssetFile(filepath.Join(assetDir, declared.Name), asset) != nil {
			return
		}
	}
	components[componentName] = productrelease.InstalledComponent{Version: component.Version, APIContract: component.APIContract}
}

func targetProductRelease(manifestRelease string, transaction *productUpdateJob) string {
	if transaction == nil || productTransactionTerminal(transaction.Phase) || strings.TrimSpace(transaction.ReleaseID) == "" {
		return manifestRelease
	}
	return transaction.ReleaseID
}

func resolveProductReleaseAssets(release GitHubRelease, manifest productrelease.Manifest) (map[string]updateReleaseAsset, error) {
	assets := make(map[string]updateReleaseAsset)
	for componentName, component := range manifest.Components {
		for _, declared := range component.Assets {
			if _, duplicate := assets[declared.Name]; duplicate {
				return nil, fmt.Errorf("产品发布清单将资产 %s 分配给多个组件", declared.Name)
			}
			githubAsset, digest, err := selectGitHubReleaseAsset(release, declared.Name)
			if err != nil {
				return nil, err
			}
			if githubAsset.Name == "" {
				return nil, fmt.Errorf("产品发布缺少 %s 组件资产 %s", componentName, declared.Name)
			}
			if githubAsset.Size <= 0 || githubAsset.Size != declared.Size {
				return nil, fmt.Errorf("产品发布资产 %s 的大小与清单不一致", declared.Name)
			}
			if !strings.EqualFold(digest, declared.SHA256) {
				return nil, fmt.Errorf("产品发布资产 %s 的 SHA-256 与清单不一致", declared.Name)
			}
			assets[declared.Name] = updateReleaseAsset{
				Name:        declared.Name,
				DownloadURL: githubAsset.BrowserDownloadURL,
				SHA256:      strings.ToLower(declared.SHA256),
				Size:        declared.Size,
			}
		}
	}
	return assets, nil
}

func validateProductReleaseCompatibility(manifest productrelease.Manifest) error {
	control := manifest.Components[productrelease.ComponentControlPlane]
	web := manifest.Components[productrelease.ComponentWeb]
	if control.APIContract != web.APIContract {
		return errors.New("产品发布中的控制端与前端 API 兼容协议不一致")
	}
	if !control.Changed && control.APIContract != version.APIContract {
		return fmt.Errorf("前端发布要求 API 兼容协议 %d，但当前控制端为 %d", control.APIContract, version.APIContract)
	}
	return nil
}

func loadCurrentProductState(stateDir, externalWebRoot string) (productrelease.InstalledState, string, string) {
	legacy := productrelease.InstalledState{
		Schema:    productrelease.SchemaVersion,
		ReleaseID: "v" + version.Version,
		Components: map[string]productrelease.InstalledComponent{
			productrelease.ComponentControlPlane: {Version: version.Version, APIContract: version.APIContract},
		},
	}
	installed, err := productrelease.LoadInstalledState(stateDir)
	if err == nil {
		root := managedExternalRoot(externalWebRoot)
		if strings.TrimSpace(externalWebRoot) != "" && root == "" {
			return installed, "", "当前前端不是受管发布目录，无法安全执行网页内完整更新。"
		}
		if root == "" {
			return installed, root, ""
		}
		return reconcileInstalledExternalWebState(installed, root)
	}
	if !productrelease.IsNotExist(err) {
		return legacy, "", "已安装发布状态无效，网页更新已暂停。"
	}
	root := managedExternalRoot(externalWebRoot)
	if strings.TrimSpace(externalWebRoot) != "" && root == "" {
		return legacy, "", "当前前端不是受管发布目录，无法安全执行网页内完整更新。"
	}
	if root != "" {
		metadata, metadataErr := currentManagedWebMetadata(root)
		if metadataErr != nil {
			// A legacy directory has no trusted product metadata. Leave the web
			// component unrecorded so the first verified product release can
			// migrate it instead of treating it as current.
			return legacy, root, ""
		}
		legacy.ReleaseID = metadata.ReleaseID
		legacy.Components[productrelease.ComponentWeb] = productrelease.InstalledComponent{Version: metadata.ReleaseID, APIContract: metadata.APIContract}
	}
	return legacy, root, ""
}

func reconcileInstalledExternalWebState(installed productrelease.InstalledState, root string) (productrelease.InstalledState, string, string) {
	metadata, err := currentManagedWebMetadata(root)
	if err != nil {
		delete(installed.Components, productrelease.ComponentWeb)
		return installed, root, ""
	}
	current, recorded := installed.Components[productrelease.ComponentWeb]
	if !recorded || current.Version != metadata.ReleaseID || current.APIContract != metadata.APIContract {
		delete(installed.Components, productrelease.ComponentWeb)
		return installed, root, ""
	}
	return installed, root, ""
}

func currentManagedWebMetadata(root string) (productrelease.WebMetadata, error) {
	currentPath := filepath.Join(root, "current")
	releaseID, err := productrelease.CurrentManagedWebRelease(currentPath)
	if err != nil {
		return productrelease.WebMetadata{}, err
	}
	metadata, err := productrelease.ValidateWebReleaseDirectory(filepath.Join(root, "releases", releaseID))
	if err != nil {
		return productrelease.WebMetadata{}, err
	}
	if metadata.ReleaseID != releaseID {
		return productrelease.WebMetadata{}, errors.New("前端元数据与当前发布目录不一致")
	}
	return metadata, nil
}

func managedExternalRoot(externalWebRoot string) string {
	if strings.TrimSpace(externalWebRoot) == "" {
		return ""
	}
	root, err := productrelease.ManagedWebRoot(externalWebRoot)
	if err != nil {
		return ""
	}
	return root
}

func productComponentStatuses(installed productrelease.InstalledState, manifest productrelease.Manifest, info *UpdateInfo) []ProductComponentStatus {
	return visibleProductComponentStatuses(productInternalComponentStatuses(installed, manifest, info))
}

// productInternalComponentStatuses retains release dependencies that are
// applied with the backend but are not separate products in the panel.
func productInternalComponentStatuses(installed productrelease.InstalledState, manifest productrelease.Manifest, info *UpdateInfo) []ProductComponentStatus {
	names := []string{
		productrelease.ComponentControlPlane,
		productrelease.ComponentWeb,
		productrelease.ComponentGuard,
	}
	statuses := make([]ProductComponentStatus, 0, len(names))
	for _, name := range names {
		component, exists := manifest.Components[name]
		if !exists {
			continue
		}
		current := installed.Components[name]
		currentVersion := strings.TrimSpace(current.Version)
		if currentVersion == "" {
			currentVersion = "未记录"
		}
		action := "keep"
		status := "current"
		if productComponentNeedsApply(installed, manifest, name, info) {
			action = "update"
			status = "pending"
		}
		compatible := component.APIContract == version.APIContract || manifest.Components[productrelease.ComponentControlPlane].Changed && component.APIContract == manifest.Components[productrelease.ComponentControlPlane].APIContract
		required := productComponentRequired(name, info)
		statuses = append(statuses, ProductComponentStatus{
			Name:           name,
			Label:          productComponentLabel(name),
			CurrentVersion: currentVersion,
			TargetVersion:  component.Version,
			Action:         action,
			Status:         status,
			Required:       required,
			Compatible:     compatible,
		})
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	return statuses
}

func visibleProductComponentStatuses(internal []ProductComponentStatus) []ProductComponentStatus {
	statuses := make([]ProductComponentStatus, 0, 2)
	var guard *ProductComponentStatus
	for _, component := range internal {
		switch component.Name {
		case productrelease.ComponentControlPlane, productrelease.ComponentWeb:
			statuses = append(statuses, component)
		case productrelease.ComponentGuard:
			componentCopy := component
			guard = &componentCopy
		}
	}
	if guard != nil {
		for index := range statuses {
			if statuses[index].Name != productrelease.ComponentControlPlane {
				continue
			}
			// Guard is part of the backend delivery. Reflect an internal Guard
			// update on the backend row so the release summary remains accurate.
			if guard.Action != "keep" {
				statuses[index].Action = "update"
				statuses[index].Status = "pending"
			}
			if guard.Required && !guard.Compatible {
				statuses[index].Compatible = false
			}
		}
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	return statuses
}

func productReleaseNeedsApply(installed productrelease.InstalledState, manifest productrelease.Manifest, info *UpdateInfo) bool {
	for name := range manifest.Components {
		if productComponentNeedsApply(installed, manifest, name, info) {
			return true
		}
	}
	return false
}

func productComponentNeedsApply(installed productrelease.InstalledState, manifest productrelease.Manifest, name string, info *UpdateInfo) bool {
	component, exists := manifest.Components[name]
	if !exists || !component.Changed || !productComponentRequired(name, info) {
		return false
	}
	current, recorded := installed.Components[name]
	return !recorded || current.Version != component.Version || current.APIContract != component.APIContract
}

func productComponentRequired(name string, info *UpdateInfo) bool {
	switch name {
	case productrelease.ComponentControlPlane, productrelease.ComponentWeb:
		return true
	case productrelease.ComponentGuard:
		return strings.TrimSpace(info.guardAssetDir) != ""
	default:
		return false
	}
}

func productComponentLabel(name string) string {
	switch name {
	case productrelease.ComponentControlPlane:
		return "后端"
	case productrelease.ComponentWeb:
		return "前端"
	case productrelease.ComponentGuard:
		return "后端配套资产"
	default:
		return name
	}
}

func productAssetNames(component productrelease.Component) []string {
	names := make([]string, 0, len(component.Assets))
	for _, asset := range component.Assets {
		names = append(names, asset.Name)
	}
	sort.Strings(names)
	return names
}

func productBinaryAssetName() string {
	name := fmt.Sprintf("arcway-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func productDataDirectory() (string, error) {
	return runtimepaths.DataDirectory()
}

func populateProductUpdateEnvironment(info *UpdateInfo, environment updateEnvironment) {
	info.DeploymentMode = environment.DeploymentMode
	info.UpdateScope = environment.UpdateScope
	info.ExternalWebRoot = environment.ExternalWebRoot
	info.CanApply = environment.CanApply
	if info.productManifest == nil {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, "产品发布清单不可用。")
		return
	}
	if environment.DeploymentMode == updateDeploymentDocker || runtime.GOOS == "windows" {
		info.Warning = appendUpdateWarning(info.Warning, environment.Warning)
		return
	}
	// A verified manifest turns an external frontend from the legacy
	// backend-only path into one transaction. Never apply to an arbitrary web
	// directory: the managed current -> releases/<id> layout is our rollback
	// boundary.
	info.UpdateScope = updateScopeFull
	if info.ExternalWebRoot {
		if !info.ManagedExternalWeb {
			info.CanApply = false
			info.Warning = appendUpdateWarning(info.Warning, "当前前端未使用受管发布目录，已禁用网页内完整更新。")
		} else {
			info.Warning = removeLegacyExternalWebWarning(info.Warning)
		}
	}
	if info.productStateUnsafe {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, "已安装发布状态不可用，请先修复或重新部署当前版本。")
	}
	if err := validateProductReleaseCompatibility(*info.productManifest); err != nil {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, err.Error())
	}
	if !info.ExternalWebRoot && info.productManifest.Components[productrelease.ComponentWeb].Changed && !info.productManifest.Components[productrelease.ComponentControlPlane].Changed {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, "内嵌前端无法单独切换，请使用包含后端的完整发布。")
	}
	if runtime.GOOS != "linux" && productReleaseRequiresHelper(info) {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, "当前操作系统不支持 systemd 事务更新，请使用对应平台的安装流程。")
	}
	for _, component := range info.Components {
		if component.Required && !component.Compatible {
			info.CanApply = false
			info.Warning = appendUpdateWarning(info.Warning, productComponentLabel(component.Name)+"与当前 API 兼容协议不匹配。")
		}
	}
	if stateDir, err := productUpdateStateDir(); err == nil {
		if job, err := loadProductUpdateJob(stateDir); err == nil && !productTransactionTerminal(job.Phase) {
			info.CanApply = false
			info.Warning = appendUpdateWarning(info.Warning, "已有产品更新事务正在运行，请等待其完成或回滚。")
		} else if err != nil && !productrelease.IsNotExist(err) {
			info.CanApply = false
			info.Warning = appendUpdateWarning(info.Warning, "无法读取产品更新事务状态，网页更新已暂停。")
		}
	} else {
		info.CanApply = false
		info.Warning = appendUpdateWarning(info.Warning, "无法确定产品更新状态目录。")
	}
}

func productReleaseRequiresHelper(info *UpdateInfo) bool {
	components := info.productInternalComponents
	if len(components) == 0 {
		components = info.Components
	}
	for _, component := range components {
		if component.Action != "update" {
			continue
		}
		switch component.Name {
		case productrelease.ComponentControlPlane,
			productrelease.ComponentGuard:
			return true
		}
	}
	return false
}

func productTransactionTerminal(phase string) bool {
	switch strings.TrimSpace(strings.ToLower(phase)) {
	case "", "committed", "completed", "failed", "rolled_back":
		return true
	default:
		return false
	}
}

func productTransactionActive(phase string) bool {
	phase = strings.TrimSpace(strings.ToLower(phase))
	return phase != "" && phase != "idle" && !productTransactionTerminal(phase)
}

func removeLegacyExternalWebWarning(warning string) string {
	parts := strings.Fields(strings.TrimSpace(warning))
	if len(parts) == 0 {
		return ""
	}
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.Contains(part, "前端需单独发布") {
			continue
		}
		filtered = append(filtered, part)
	}
	return strings.Join(filtered, " ")
}

func localProductUpdateStatus(environment updateEnvironment) (productRelease string, targetRelease string, managedExternalWeb bool, transactionState string, components []ProductComponentStatus, warning string) {
	stateDir, err := productUpdateStateDir()
	if err != nil {
		return "", "", false, "", nil, "无法确定产品更新状态目录。"
	}
	installed, managedRoot, stateWarning := loadCurrentProductState(stateDir, strings.TrimSpace(os.Getenv("ARCWAY_WEB_ROOT")))
	productRelease = installed.ReleaseID
	targetRelease = installed.ReleaseID
	managedExternalWeb = environment.ExternalWebRoot && managedRoot != ""
	warning = stateWarning
	transactionState = "idle"
	if job, err := loadProductUpdateJob(stateDir); err == nil {
		transactionState = job.Phase
		targetRelease = job.ReleaseID
		components = productComponentStatuses(installed, job.Manifest, &UpdateInfo{
			HasUpdate:     !productTransactionTerminal(job.Phase),
			guardAssetDir: strings.TrimSpace(os.Getenv("ARCWAY_GUARD_ASSET_DIR")),
		})
		for index := range components {
			components[index].Status = transactionComponentStatus(job.Phase, components[index])
		}
	} else if !productrelease.IsNotExist(err) {
		warning = appendUpdateWarning(warning, "无法读取上次产品更新事务状态。")
	}
	if len(components) == 0 {
		components = localProductComponentStatuses(installed)
	}
	return productRelease, targetRelease, managedExternalWeb, transactionState, components, warning
}

func localProductComponentStatuses(installed productrelease.InstalledState) []ProductComponentStatus {
	names := []string{
		productrelease.ComponentControlPlane,
		productrelease.ComponentWeb,
	}
	sort.Strings(names)
	statuses := make([]ProductComponentStatus, 0, len(names))
	for _, name := range names {
		component, exists := installed.Components[name]
		if !exists {
			continue
		}
		statuses = append(statuses, ProductComponentStatus{
			Name:           name,
			Label:          productComponentLabel(name),
			CurrentVersion: component.Version,
			TargetVersion:  component.Version,
			Action:         "keep",
			Status:         "current",
			Compatible:     component.APIContract == version.APIContract,
		})
	}
	return statuses
}

func transactionComponentStatus(phase string, component ProductComponentStatus) string {
	if component.Action == "keep" {
		return "current"
	}
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "scheduled", "staging_web", "downloading":
		return "staged"
	case "activating", "stopping", "backing_up", "starting", "waiting_for_health", "recording_state":
		return "activating"
	case "committed", "completed":
		return "committed"
	case "rolling_back":
		return "rolling_back"
	case "rolled_back":
		return "rolled_back"
	case "failed":
		return "failed"
	case "recovery_required":
		return "recovery_required"
	default:
		return "pending"
	}
}
