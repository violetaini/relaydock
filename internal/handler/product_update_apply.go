package handler

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/productrelease"
	"github.com/violetaini/relaydock/internal/version"
)

var productReleaseAssetDownloader = downloadVerifiedReleaseAsset

// applyProductRelease stages every selected component before changing any live
// path. A control-plane replacement is handed to the isolated helper; a
// compatible web-only release can commit its symlink in this process because
// it never stops or replaces the running control plane.
func applyProductRelease(info *UpdateInfo, onProgress func(step string, progress int, message string)) (productUpdateJob, bool, error) {
	if info.productManifest == nil {
		return productUpdateJob{}, false, errors.New("当前 GitHub 发布没有产品更新清单")
	}
	manifest := *info.productManifest
	if err := validateProductUpdateForApply(info); err != nil {
		return productUpdateJob{}, false, err
	}
	stateDir, err := productUpdateStateDir()
	if err != nil {
		return productUpdateJob{}, false, err
	}
	dataDir, err := productDataDirectory()
	if err != nil {
		return productUpdateJob{}, false, err
	}
	databasePath, err := productDatabasePath(dataDir)
	if err != nil {
		return productUpdateJob{}, false, err
	}
	webHealthURL, err := defaultUpdateWebHealthURL()
	if err != nil {
		return productUpdateJob{}, false, err
	}
	id, err := newProductUpdateID()
	if err != nil {
		return productUpdateJob{}, false, err
	}
	if onProgress != nil {
		onProgress("downloading", 0, "正在下载并校验产品发布资产...")
	}

	files, appliedComponents, err := prepareProductUpdateFiles(info, id, onProgress)
	if err != nil {
		return productUpdateJob{}, false, err
	}
	web, webApplied, err := prepareProductWebRelease(info, id, onProgress)
	if err != nil {
		return productUpdateJob{}, false, err
	}
	if webApplied {
		appliedComponents[productrelease.ComponentWeb] = true
	}
	if !info.ExternalWebRoot && manifest.Components[productrelease.ComponentWeb].Changed && manifest.Components[productrelease.ComponentControlPlane].Changed {
		// In embedded deployments the frontend is packaged into the verified
		// control-plane binary, so it commits with that binary replacement.
		appliedComponents[productrelease.ComponentWeb] = true
	}
	if len(files) == 0 && web == nil {
		return productUpdateJob{}, false, errors.New("该产品发布没有适用于此控制端的可更新组件")
	}

	installed, _, _ := loadCurrentProductState(stateDir, strings.TrimSpace(os.Getenv("ARCWAY_WEB_ROOT")))
	var previousState *productrelease.InstalledState
	if recorded, loadErr := productrelease.LoadInstalledState(stateDir); loadErr == nil {
		previousState = &recorded
	} else if !productrelease.IsNotExist(loadErr) {
		return productUpdateJob{}, false, fmt.Errorf("读取当前产品发布状态: %w", loadErr)
	}
	committed := mergedInstalledProductState(installed, manifest, appliedComponents)
	healthToken, err := newProductUpdateToken()
	if err != nil {
		return productUpdateJob{}, false, err
	}
	control := manifest.Components[productrelease.ComponentControlPlane]
	targetVersion := version.Version
	if control.Changed {
		targetVersion = strings.TrimPrefix(control.Version, "v")
	}
	job := productUpdateJob{
		Schema:         productUpdateJobSchema,
		ID:             id,
		ReleaseID:      manifest.ReleaseID,
		Manifest:       manifest,
		InstalledState: committed,
		PreviousState:  previousState,
		Files:          files,
		Web:            web,
		StateDir:       stateDir,
		DataDirectory:  dataDir,
		DatabasePath:   databasePath,
		ServiceUnit:    defaultSystemdUnit(),
		HealthURL:      defaultUpdateHealthURL(),
		WebHealthURL:   webHealthURL,
		HealthToken:    healthToken,
		TargetVersion:  targetVersion,
		Phase:          "staging_web",
		Message:        "发布资产已完成校验，正在准备原子切换",
		StartedAt:      time.Now().UTC(),
	}
	if err := writeProductUpdateJob(job); err != nil {
		return productUpdateJob{}, false, err
	}

	if len(files) > 0 {
		job.HelperUnit = productUpdateHelperUnit(job)
		if err := setProductUpdatePhase(&job, "scheduled", "已安排独立更新事务，服务将短暂重启并自动验证..."); err != nil {
			return productUpdateJob{}, false, err
		}
		if err := scheduleProductUpdate(job); err != nil {
			_ = failProductUpdateJob(&job, err)
			return productUpdateJob{}, false, err
		}
		return job, true, nil
	}

	if onProgress != nil {
		onProgress("activating", 0, "正在原子切换已验证的前端...")
	}
	webLock, err := acquireProductWebLock(web.Root)
	if err != nil {
		return productUpdateJob{}, false, fmt.Errorf("锁定前端发布目录: %w", err)
	}
	defer webLock.Close()
	activation, err := productrelease.PrepareWebActivation(web.Root, web.Staging, job.ReleaseID)
	if err != nil {
		_ = failProductUpdateJob(&job, err)
		return productUpdateJob{}, false, err
	}
	job.Activation = &activation
	job.RollbackReady = true
	if err := setProductUpdatePhase(&job, "activating", "已记录前端回滚点，正在原子切换已验证的前端..."); err != nil {
		_ = failProductUpdateJob(&job, err)
		return productUpdateJob{}, false, err
	}
	if err := productrelease.ActivatePreparedWebRelease(web.Root, activation); err != nil {
		return productUpdateJob{}, false, rollbackWebOnlyProductUpdate(&job, fmt.Errorf("activate frontend release: %w", err))
	}
	if err := waitForProductWebRelease(job); err != nil {
		return productUpdateJob{}, false, rollbackWebOnlyProductUpdate(&job, err)
	}
	if err := productrelease.WriteInstalledState(job.StateDir, job.InstalledState); err != nil {
		return productUpdateJob{}, false, rollbackWebOnlyProductUpdate(&job, fmt.Errorf("record installed product release: %w", err))
	}
	job.Phase = "committed"
	job.Message = "前端已更新并与当前后端 API 兼容"
	job.Error = ""
	if err := writeProductUpdateJob(job); err != nil {
		return productUpdateJob{}, false, rollbackWebOnlyProductUpdate(&job, fmt.Errorf("commit frontend product release: %w", err))
	}
	return job, false, nil
}

func validateProductUpdateForApply(info *UpdateInfo) error {
	if info.productManifest == nil {
		return errors.New("产品发布清单不可用")
	}
	if info.ExternalWebRoot && !info.ManagedExternalWeb {
		return errors.New("当前前端不是受管发布目录，不能由网页安全更新")
	}
	if !info.ExternalWebRoot && info.productManifest.Components[productrelease.ComponentWeb].Changed && !info.productManifest.Components[productrelease.ComponentControlPlane].Changed {
		return errors.New("内嵌前端无法单独切换，请使用包含后端的完整发布")
	}
	if runtime.GOOS != "linux" && productReleaseRequiresHelper(info) {
		return errors.New("当前操作系统不支持 systemd 事务更新")
	}
	if info.TargetRelease == "" || info.TargetRelease != info.productManifest.ReleaseID {
		return errors.New("产品发布目标已变化，请重新检查")
	}
	if err := validateProductReleaseCompatibility(*info.productManifest); err != nil {
		return err
	}
	return nil
}

func prepareProductUpdateFiles(info *UpdateInfo, transactionID string, onProgress func(step string, progress int, message string)) ([]preparedUpdateFile, map[string]bool, error) {
	manifest := *info.productManifest
	applied := make(map[string]bool)
	var files []preparedUpdateFile
	appendManaged := func(componentName, assetDir string, specifications []productAssetSpecification) error {
		component := manifest.Components[componentName]
		if !component.Changed || strings.TrimSpace(assetDir) == "" {
			return nil
		}
		if err := ensureManagedAssetDirectory(assetDir); err != nil {
			return err
		}
		for _, specification := range specifications {
			asset, exists := info.productAssets[specification.Name]
			if !exists {
				return fmt.Errorf("产品发布缺少 %s 资产 %s", productComponentLabel(componentName), specification.Name)
			}
			if onProgress != nil {
				onProgress("downloading", 0, "正在下载并校验"+productComponentLabel(componentName)+" "+asset.Name+"...")
			}
			source, err := stageProductReleaseAsset(info, transactionID, asset)
			if err != nil {
				return err
			}
			if err := verifyBinaryFormatFor(source, specification.GOOS, specification.GOARCH); err != nil {
				return fmt.Errorf("校验 %s: %w", asset.Name, err)
			}
			files = append(files, preparedUpdateFile{
				Name:       asset.Name,
				SourcePath: source,
				TargetPath: filepath.Join(assetDir, asset.Name),
				BackupPath: filepath.Join(assetDir, asset.Name) + ".bak",
			})
		}
		applied[componentName] = true
		return nil
	}

	if err := appendManaged(productrelease.ComponentGuard, info.guardAssetDir, []productAssetSpecification{
		{Name: "arcway-expiry-guard-linux-amd64", GOOS: "linux", GOARCH: "amd64"},
		{Name: "arcway-expiry-guard-linux-arm64", GOOS: "linux", GOARCH: "arm64"},
	}); err != nil {
		return nil, nil, err
	}

	control := manifest.Components[productrelease.ComponentControlPlane]
	if control.Changed {
		asset, exists := info.productAssets[productBinaryAssetName()]
		if !exists {
			return nil, nil, fmt.Errorf("产品发布缺少此平台控制端资产 %s", productBinaryAssetName())
		}
		if onProgress != nil {
			onProgress("downloading", 0, "正在下载并校验后端...")
		}
		source, err := stageProductReleaseAsset(info, transactionID, asset)
		if err != nil {
			return nil, nil, err
		}
		if err := verifyBinaryFormat(source); err != nil {
			return nil, nil, err
		}
		target, err := getUpdateTargetPath()
		if err != nil {
			return nil, nil, err
		}
		files = append(files, preparedUpdateFile{
			Name:       "arcway",
			SourcePath: source,
			TargetPath: target,
			BackupPath: target + ".bak",
		})
		applied[productrelease.ComponentControlPlane] = true
	}
	return files, applied, nil
}

type productAssetSpecification struct {
	Name   string
	GOOS   string
	GOARCH string
}

func ensureManagedAssetDirectory(directory string) error {
	directory = strings.TrimSpace(directory)
	if !filepath.IsAbs(directory) {
		return errors.New("产品资产目录必须是绝对路径")
	}
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("不安全的产品资产目录: %s", directory)
	}
	return nil
}

func prepareProductWebRelease(info *UpdateInfo, transactionID string, onProgress func(step string, progress int, message string)) (*productWebPreparation, bool, error) {
	manifest := *info.productManifest
	web := manifest.Components[productrelease.ComponentWeb]
	if !web.Changed || !info.ExternalWebRoot {
		return nil, false, nil
	}
	if !info.ManagedExternalWeb || info.managedWebRoot == "" {
		return nil, false, errors.New("当前前端不是受管发布目录")
	}
	if len(web.Assets) != 1 {
		return nil, false, errors.New("前端发布必须恰好包含一个归档")
	}
	asset, exists := info.productAssets[web.Assets[0].Name]
	if !exists {
		return nil, false, errors.New("前端发布归档不存在")
	}
	if onProgress != nil {
		onProgress("staging_web", 0, "正在下载、校验并暂存前端...")
	}
	archive, err := stageProductReleaseAsset(info, transactionID, asset)
	if err != nil {
		return nil, false, err
	}
	metadata := productrelease.WebMetadata{
		Schema:      productrelease.SchemaVersion,
		ReleaseID:   manifest.ReleaseID,
		APIContract: web.APIContract,
	}
	staging, err := productrelease.StageWebArchive(archive, info.managedWebRoot, manifest.ReleaseID, metadata)
	if err != nil {
		return nil, false, err
	}
	if onProgress != nil {
		onProgress("staging_web", 100, "前端已完成校验并暂存，尚未切换线上页面。")
	}
	return &productWebPreparation{Root: info.managedWebRoot, Staging: staging, Metadata: metadata}, true, nil
}

func stageProductReleaseAsset(info *UpdateInfo, transactionID string, asset updateReleaseAsset) (string, error) {
	if asset.Name == "" || asset.Size <= 0 || !filepath.IsAbs(info.managedWebRoot) && info.ExternalWebRoot && info.managedWebRoot == "" {
		return "", errors.New("产品发布资产参数无效")
	}
	stateDir, err := productUpdateStateDir()
	if err != nil {
		return "", err
	}
	downloadDir := filepath.Join(stateDir, "transactions", transactionID, "downloads")
	if err := os.MkdirAll(downloadDir, 0700); err != nil {
		return "", err
	}
	destination := filepath.Join(downloadDir, asset.Name)
	if existing, err := os.Stat(destination); err == nil {
		if existing.Mode().IsRegular() && existing.Size() == asset.Size && verifyBinaryChecksum(destination, asset.SHA256) == nil {
			return destination, nil
		}
		return "", fmt.Errorf("产品更新暂存路径已被占用: %s", asset.Name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	temporary, err := productReleaseAssetDownloader(asset)
	if err != nil {
		return "", fmt.Errorf("下载 %s: %w", asset.Name, err)
	}
	defer os.Remove(temporary)
	if err := copyFileAtomically(temporary, destination, 0600); err != nil {
		return "", err
	}
	if err := verifyReleaseAssetFile(destination, asset); err != nil {
		_ = os.Remove(destination)
		return "", err
	}
	return destination, nil
}

func downloadVerifiedReleaseAsset(asset updateReleaseAsset) (string, error) {
	if asset.DownloadURL == "" || asset.Size <= 0 || asset.Size > maxUpdateBinarySize {
		return "", errors.New("产品发布资产大小或下载地址无效")
	}
	path, err := downloadBinary(asset.DownloadURL)
	if err != nil {
		return "", err
	}
	if err := verifyReleaseAssetFile(path, asset); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func verifyReleaseAssetFile(path string, asset updateReleaseAsset) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != asset.Size {
		return fmt.Errorf("资产 %s 大小与发布清单不一致", asset.Name)
	}
	return verifyBinaryChecksum(path, asset.SHA256)
}

func mergedInstalledProductState(previous productrelease.InstalledState, manifest productrelease.Manifest, applied map[string]bool) productrelease.InstalledState {
	components := make(map[string]productrelease.InstalledComponent, len(previous.Components)+len(manifest.Components))
	for name, component := range previous.Components {
		components[name] = component
	}
	for name, component := range manifest.Components {
		if !component.Changed || applied[name] {
			components[name] = productrelease.InstalledComponent{Version: component.Version, APIContract: component.APIContract}
		}
	}
	return productrelease.InstalledState{
		Schema:     productrelease.SchemaVersion,
		ReleaseID:  manifest.ReleaseID,
		UpdatedAt:  time.Now().UTC(),
		Components: components,
	}
}

func newProductUpdateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
