package productrelease

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	WebMetadataFilename = "relaydock-release.json"
	maxWebArchiveSize   = 128 << 20
	maxWebFileCount     = 8192
)

var releaseDirectoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// WebMetadata is embedded in every external frontend archive. The metadata is
// checked after extraction and later exposed in the product update status.
type WebMetadata struct {
	Schema      int    `json:"schema"`
	ReleaseID   string `json:"release_id"`
	APIContract int    `json:"api_contract"`
}

// WebActivation captures the previous managed symlink targets so a helper can
// put the exact frontend state back if the new control plane fails its health
// check.
type WebActivation struct {
	ReleaseID       string      `json:"release_id"`
	StagingPath     string      `json:"staging_path"`
	Metadata        WebMetadata `json:"metadata"`
	CurrentTarget   string      `json:"current_target"`
	PreviousTarget  string      `json:"previous_target"`
	HadCurrent      bool        `json:"had_current"`
	HadPrevious     bool        `json:"had_previous"`
	ActivatedTarget string      `json:"activated_target"`
}

// Validate checks the durable activation record before it is resumed or
// rolled back. It intentionally accepts either a staged or an already
// published target: a process can stop between those two steps.
func (activation WebActivation) Validate(root string) error {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		return errors.New("frontend activation root must be absolute")
	}
	if !releaseDirectoryPattern.MatchString(activation.ReleaseID) {
		return errors.New("invalid frontend activation release id")
	}
	if err := activation.Metadata.Validate(); err != nil {
		return err
	}
	if activation.Metadata.ReleaseID != activation.ReleaseID {
		return errors.New("frontend activation metadata does not match its release id")
	}
	if !activation.HadCurrent {
		return errors.New("frontend activation has no previous current release")
	}
	if err := validateManagedReleaseTarget(root, activation.CurrentTarget); err != nil {
		return fmt.Errorf("invalid frontend activation current target: %w", err)
	}
	if activation.HadPrevious {
		if err := validateManagedReleaseTarget(root, activation.PreviousTarget); err != nil {
			return fmt.Errorf("invalid frontend activation previous target: %w", err)
		}
	} else if activation.PreviousTarget != "" {
		return errors.New("frontend activation has an unexpected previous target")
	}
	expectedTarget := filepath.ToSlash(filepath.Join("releases", activation.ReleaseID))
	if activation.ActivatedTarget != expectedTarget {
		return errors.New("frontend activation has an invalid activated target")
	}
	staging := filepath.Clean(activation.StagingPath)
	releases := filepath.Join(root, "releases")
	if filepath.Dir(staging) != releases || !strings.HasPrefix(filepath.Base(staging), ".staging-"+activation.ReleaseID+"-") {
		return errors.New("frontend activation staging directory is outside managed releases")
	}
	return nil
}

func (m WebMetadata) Validate() error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("unsupported web metadata schema: %d", m.Schema)
	}
	if !releaseIDPattern.MatchString(m.ReleaseID) {
		return fmt.Errorf("invalid web release id: %q", m.ReleaseID)
	}
	if m.APIContract < 1 {
		return errors.New("invalid web API contract")
	}
	return nil
}

// ManagedWebRoot validates the layout used by the production deploy script:
// <root>/current -> releases/<id>. It never follows an arbitrary external
// directory, preventing a panel update from overwriting an operator's custom
// static site.
func ManagedWebRoot(externalRoot string) (string, error) {
	externalRoot = filepath.Clean(strings.TrimSpace(externalRoot))
	if !filepath.IsAbs(externalRoot) || filepath.Base(externalRoot) != "current" {
		return "", errors.New("ARCWAY_WEB_ROOT must be an absolute managed current link")
	}
	root := filepath.Dir(externalRoot)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect external web root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("external web root is not a safe directory")
	}
	currentInfo, err := os.Lstat(externalRoot)
	if err != nil {
		return "", fmt.Errorf("inspect external web current link: %w", err)
	}
	if currentInfo.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("external web current path is not a managed symbolic link")
	}
	if _, _, err := managedCurrentTarget(root); err != nil {
		return "", err
	}
	return root, nil
}

// CurrentManagedWebRelease returns the release identifier behind a validated
// ARCWAY_WEB_ROOT link. It is intentionally read-only so status reporting can
// recover a legacy installation before its first product transaction writes
// installed-release.json.
func CurrentManagedWebRelease(externalRoot string) (string, error) {
	root, err := ManagedWebRoot(externalRoot)
	if err != nil {
		return "", err
	}
	_, releaseID, err := managedCurrentTarget(root)
	return releaseID, err
}

func managedCurrentTarget(root string) (string, string, error) {
	current := filepath.Join(root, "current")
	target, err := os.Readlink(current)
	if err != nil {
		return "", "", fmt.Errorf("read managed current link: %w", err)
	}
	target, releaseID, err := normalizeManagedReleaseTarget(root, target)
	if err != nil {
		return "", "", fmt.Errorf("current link points outside managed releases: %w", err)
	}
	resolved := filepath.Join(root, target)
	info, err := os.Lstat(resolved)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("current link target is not a safe frontend release")
	}
	return target, releaseID, nil
}

// normalizeManagedReleaseTarget accepts the legacy absolute form only when it
// resolves lexically to this managed root's releases/<id> directory. Returning
// the relative form keeps every new journal and symlink replacement portable.
func normalizeManagedReleaseTarget(root, target string) (string, string, error) {
	root = filepath.Clean(root)
	target = filepath.Clean(strings.TrimSpace(target))
	if filepath.IsAbs(target) {
		relative, err := filepath.Rel(root, target)
		if err != nil {
			return "", "", err
		}
		target = relative
	}
	target = filepath.ToSlash(target)
	if !strings.HasPrefix(target, "releases/") {
		return "", "", errors.New("target points outside managed releases")
	}
	releaseID := strings.TrimPrefix(target, "releases/")
	if !releaseDirectoryPattern.MatchString(releaseID) || target != filepath.ToSlash(filepath.Join("releases", releaseID)) {
		return "", "", errors.New("target has an invalid managed release id")
	}
	return target, releaseID, nil
}

func validateManagedReleaseTarget(root, target string) error {
	target, _, err := normalizeManagedReleaseTarget(root, target)
	if err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Join(root, target))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("target is not a safe frontend release directory")
	}
	return nil
}

func readManagedPrevious(root string) (string, bool, error) {
	previous := filepath.Join(root, "previous")
	info, err := os.Lstat(previous)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", false, errors.New("previous frontend path is not a managed symbolic link")
	}
	target, err := os.Readlink(previous)
	if err != nil {
		return "", false, err
	}
	target, _, err = normalizeManagedReleaseTarget(root, target)
	if err != nil {
		return "", false, fmt.Errorf("previous frontend link points outside managed releases: %w", err)
	}
	return target, true, nil
}

// StageWebArchive extracts and validates an archive without changing current.
// The archive can be safely prepared while the old control plane still serves
// traffic; activation is a separate atomic operation.
func StageWebArchive(archivePath, root, releaseID string, expected WebMetadata) (string, error) {
	if !releaseDirectoryPattern.MatchString(releaseID) {
		return "", fmt.Errorf("invalid frontend release id: %q", releaseID)
	}
	if err := expected.Validate(); err != nil {
		return "", err
	}
	if expected.ReleaseID != releaseID {
		return "", errors.New("web metadata release does not match target release")
	}
	if _, err := ManagedWebRoot(filepath.Join(root, "current")); err != nil {
		return "", err
	}
	releases := filepath.Join(root, "releases")
	if err := ensureSafeDirectory(releases); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(releases, ".staging-"+releaseID+"-")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := extractWebArchive(archivePath, stage); err != nil {
		return "", err
	}
	metadata, err := ValidateWebReleaseDirectory(stage)
	if err != nil {
		return "", err
	}
	if metadata != expected {
		return "", errors.New("web archive metadata does not match the product manifest")
	}
	currentTarget, _, err := managedCurrentTarget(root)
	if err != nil {
		return "", err
	}
	if err := carryForwardAssets(filepath.Join(root, currentTarget), stage); err != nil {
		return "", err
	}
	if _, err := ValidateWebReleaseDirectory(stage); err != nil {
		return "", err
	}
	if err := normalizeWebReleasePermissions(stage); err != nil {
		return "", err
	}
	if err := syncWebReleaseTree(stage); err != nil {
		return "", err
	}
	// Do not move a retained failed release out of the way until the new
	// archive has been fully extracted and validated. An invalid retry archive
	// must leave the diagnostic copy exactly where the rollback left it.
	if err := quarantineRetryableWebRelease(root, releases, releaseID, expected); err != nil {
		return "", err
	}
	keep = true
	return stage, nil
}

// quarantineRetryableWebRelease makes a retry of a previously rolled-back
// release safe. A failed activation deliberately leaves its release directory
// behind for diagnosis, but a retry must never serve that old directory: it is
// first checked for unsafe entries and matching metadata, atomically moved out
// of the canonical release namespace, then StageWebArchive extracts the
// verified archive again into a fresh staging directory.
func quarantineRetryableWebRelease(root, releases, releaseID string, expected WebMetadata) error {
	target := filepath.Join(releases, releaseID)
	info, err := os.Lstat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("existing frontend release is not a safe directory: %s", releaseID)
	}
	existingMetadata, err := ValidateWebReleaseDirectory(target)
	if err != nil {
		return fmt.Errorf("existing frontend release cannot be retried safely: %w", err)
	}
	if existingMetadata != expected {
		return fmt.Errorf("frontend release already exists with different metadata: %s", releaseID)
	}
	currentTarget, _, err := managedCurrentTarget(root)
	if err != nil {
		return err
	}
	managedTarget := filepath.ToSlash(filepath.Join("releases", releaseID))
	if currentTarget == managedTarget {
		return fmt.Errorf("frontend release is already active: %s", releaseID)
	}
	previousTarget, hasPrevious, err := readManagedPrevious(root)
	if err != nil {
		return err
	}
	if hasPrevious && previousTarget == managedTarget {
		return fmt.Errorf("frontend release is retained as the previous release: %s", releaseID)
	}

	quarantine, err := os.MkdirTemp(releases, ".rolled-back-"+releaseID+"-")
	if err != nil {
		return fmt.Errorf("create frontend retry quarantine: %w", err)
	}
	quarantinedRelease := filepath.Join(quarantine, releaseID)
	if err := os.Rename(target, quarantinedRelease); err != nil {
		_ = os.Remove(quarantine)
		return fmt.Errorf("quarantine rolled-back frontend release: %w", err)
	}
	if err := syncWebDirectory(quarantine); err != nil {
		return fmt.Errorf("sync frontend retry quarantine: %w", err)
	}
	if err := syncWebDirectory(releases); err != nil {
		return fmt.Errorf("sync frontend releases after quarantine: %w", err)
	}
	return nil
}

// PrepareWebActivation validates and records an activation before any release
// directory or symlink changes. Callers that persist update transactions must
// write this record before calling ActivatePreparedWebRelease, so a process
// kill or power loss can be resumed or rolled back without guessing which
// links were changed.
func PrepareWebActivation(root, stagingPath, releaseID string) (WebActivation, error) {
	if _, err := ManagedWebRoot(filepath.Join(root, "current")); err != nil {
		return WebActivation{}, err
	}
	if !releaseDirectoryPattern.MatchString(releaseID) {
		return WebActivation{}, errors.New("invalid frontend release id")
	}
	releases := filepath.Join(root, "releases")
	stagingPath = filepath.Clean(stagingPath)
	if filepath.Dir(stagingPath) != releases || !strings.HasPrefix(filepath.Base(stagingPath), ".staging-"+releaseID+"-") {
		return WebActivation{}, errors.New("frontend staging directory is outside managed releases")
	}
	metadata, err := ValidateWebReleaseDirectory(stagingPath)
	if err != nil {
		return WebActivation{}, err
	}
	if metadata.ReleaseID != releaseID {
		return WebActivation{}, errors.New("frontend staging metadata does not match the release id")
	}
	currentTarget, _, err := managedCurrentTarget(root)
	if err != nil {
		return WebActivation{}, err
	}
	previousTarget, hadPrevious, err := readManagedPrevious(root)
	if err != nil {
		return WebActivation{}, err
	}
	target := filepath.Join(releases, releaseID)
	if _, err := os.Lstat(target); err == nil {
		return WebActivation{}, fmt.Errorf("frontend release already exists: %s", releaseID)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return WebActivation{}, err
	}
	return WebActivation{
		ReleaseID:       releaseID,
		StagingPath:     stagingPath,
		Metadata:        metadata,
		CurrentTarget:   currentTarget,
		PreviousTarget:  previousTarget,
		HadCurrent:      true,
		HadPrevious:     hadPrevious,
		ActivatedTarget: filepath.ToSlash(filepath.Join("releases", releaseID)),
	}, nil
}

// ActivatePreparedWebRelease executes a previously prepared activation. It is
// deliberately resumable: if a process stopped after publishing the release
// or after replacing only the previous link, a later invocation finishes the
// same recorded activation. Any unexpected link state is rejected instead of
// overwriting an operator's deployment.
func ActivatePreparedWebRelease(root string, activation WebActivation) error {
	if _, err := ManagedWebRoot(filepath.Join(root, "current")); err != nil {
		return err
	}
	if err := activation.Validate(root); err != nil {
		return err
	}
	releases := filepath.Join(root, "releases")
	target := filepath.Join(releases, activation.ReleaseID)
	if info, err := os.Lstat(target); errors.Is(err, fs.ErrNotExist) {
		if info != nil {
			return errors.New("frontend release target has an invalid state")
		}
		metadata, validateErr := ValidateWebReleaseDirectory(activation.StagingPath)
		if validateErr != nil {
			return validateErr
		}
		if metadata != activation.Metadata {
			return errors.New("frontend staging metadata changed after activation was prepared")
		}
		if err := syncWebReleaseTree(activation.StagingPath); err != nil {
			return fmt.Errorf("sync staged frontend release: %w", err)
		}
		if err := os.Rename(activation.StagingPath, target); err != nil {
			return fmt.Errorf("publish frontend release: %w", err)
		}
		if err := syncWebDirectory(releases); err != nil {
			return fmt.Errorf("sync published frontend release: %w", err)
		}
	} else if err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("published frontend release is not a safe directory")
	} else {
		metadata, validateErr := ValidateWebReleaseDirectory(target)
		if validateErr != nil {
			return validateErr
		}
		if metadata != activation.Metadata {
			return errors.New("published frontend release metadata does not match the activation")
		}
		if _, err := os.Lstat(activation.StagingPath); err == nil {
			return errors.New("frontend activation has both staging and published directories")
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	currentTarget, _, err := managedCurrentTarget(root)
	if err != nil {
		return err
	}
	previousTarget, hadPrevious, err := readManagedPrevious(root)
	if err != nil {
		return err
	}
	switch currentTarget {
	case activation.ActivatedTarget:
		if !hadPrevious || previousTarget != activation.CurrentTarget {
			return errors.New("frontend activation completed with an unexpected previous link")
		}
		return syncWebDirectory(root)
	case activation.CurrentTarget:
		initialPrevious := hadPrevious == activation.HadPrevious && (!hadPrevious || previousTarget == activation.PreviousTarget)
		if initialPrevious {
			if err := replaceManagedLink(root, "previous", activation.CurrentTarget); err != nil {
				return err
			}
		} else if !hadPrevious || previousTarget != activation.CurrentTarget {
			return errors.New("frontend links changed after activation was prepared")
		}
		return replaceManagedLink(root, "current", activation.ActivatedTarget)
	default:
		return errors.New("frontend current link changed after activation was prepared")
	}
}

// ActivateStagedWebRelease makes a fully validated staging directory live with
// rename-based symlink swaps. New update transactions should prefer the
// prepare/activate pair above so the activation record can be written ahead of
// the filesystem changes.
func ActivateStagedWebRelease(root, stagingPath, releaseID string) (WebActivation, error) {
	activation, err := PrepareWebActivation(root, stagingPath, releaseID)
	if err != nil {
		return WebActivation{}, err
	}
	if err := ActivatePreparedWebRelease(root, activation); err != nil {
		return activation, err
	}
	return activation, nil
}

// RollbackWebActivation restores links only; the staged/activated release is
// retained for diagnosis and manual cleanup after a failed transaction.
func RollbackWebActivation(root string, activation WebActivation) error {
	if _, err := ManagedWebRoot(filepath.Join(root, "current")); err != nil {
		return err
	}
	if err := activation.Validate(root); err != nil {
		return fmt.Errorf("validate frontend rollback journal: %w", err)
	}
	if err := validateRollbackLinkState(root, activation); err != nil {
		return err
	}
	if err := replaceManagedLink(root, "current", activation.CurrentTarget); err != nil {
		return err
	}
	if activation.HadPrevious {
		return replaceManagedLink(root, "previous", activation.PreviousTarget)
	}
	previous := filepath.Join(root, "previous")
	if info, err := os.Lstat(previous); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(previous); err != nil {
			return err
		}
		return syncWebDirectory(root)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func validateRollbackLinkState(root string, activation WebActivation) error {
	current, _, err := managedCurrentTarget(root)
	if err != nil {
		return err
	}
	if current != activation.CurrentTarget && current != activation.ActivatedTarget {
		return errors.New("frontend current link changed after activation was prepared")
	}
	previous, hasPrevious, err := readManagedPrevious(root)
	if err != nil {
		return err
	}
	if activation.HadPrevious {
		if !hasPrevious || (previous != activation.PreviousTarget && previous != activation.CurrentTarget) {
			return errors.New("frontend previous link changed after activation was prepared")
		}
		return nil
	}
	if hasPrevious && previous != activation.CurrentTarget {
		return errors.New("frontend previous link changed after activation was prepared")
	}
	return nil
}

// ValidateWebReleaseDirectory checks the immutable on-disk release after both
// archive extraction and the old-asset carry-forward step.
func ValidateWebReleaseDirectory(root string) (WebMetadata, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return WebMetadata{}, errors.New("frontend release root is not a safe directory")
	}
	if err := rejectSymlinks(root); err != nil {
		return WebMetadata{}, err
	}
	index, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil || len(strings.TrimSpace(string(index))) == 0 {
		return WebMetadata{}, errors.New("frontend release is missing index.html")
	}
	if !strings.Contains(string(index), "__RELAYDOCK_DEFAULT_THEME__") {
		return WebMetadata{}, errors.New("frontend release index.html is missing the theme placeholder")
	}
	for _, asset := range referencedAssets(index) {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(asset)))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return WebMetadata{}, fmt.Errorf("frontend release is missing referenced asset %s", asset)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, WebMetadataFilename))
	if err != nil {
		return WebMetadata{}, fmt.Errorf("frontend release is missing %s", WebMetadataFilename)
	}
	var metadata WebMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return WebMetadata{}, fmt.Errorf("parse web metadata: %w", err)
	}
	if err := metadata.Validate(); err != nil {
		return WebMetadata{}, err
	}
	return metadata, nil
}

func extractWebArchive(archivePath, destination string) error {
	info, err := os.Stat(archivePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxWebArchiveSize {
		return errors.New("invalid frontend archive size")
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(io.LimitReader(file, maxWebArchiveSize+1))
	if err != nil {
		return fmt.Errorf("read frontend archive: %w", err)
	}
	defer gzipReader.Close()
	reader := tar.NewReader(io.LimitReader(gzipReader, maxWebArchiveSize+1))
	var count int
	var total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read frontend archive: %w", err)
		}
		count++
		if count > maxWebFileCount {
			return errors.New("frontend archive contains too many files")
		}
		// GNU tar commonly emits a root "./" directory entry when an
		// archive is made with `tar -C dir -cf - .`. It carries no file
		// content and is safe to ignore; every real entry is still validated
		// below before touching the staging directory.
		if header.Typeflag == tar.TypeDir && (header.Name == "." || header.Name == "./") {
			continue
		}
		name, err := safeArchiveName(header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(filepath.Join(destination, filepath.FromSlash(name)), 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxWebArchiveSize-total {
				return errors.New("frontend archive expands beyond the size limit")
			}
			total += header.Size
			outputPath := filepath.Join(destination, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
				return err
			}
			output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				return fmt.Errorf("write frontend archive entry %s: %w", name, err)
			}
			written, copyErr := io.CopyN(output, reader, header.Size)
			closeErr := output.Close()
			if copyErr != nil || written != header.Size || closeErr != nil {
				_ = os.Remove(outputPath)
				if copyErr != nil {
					return copyErr
				}
				if closeErr != nil {
					return closeErr
				}
				return errors.New("frontend archive entry is truncated")
			}
		default:
			return fmt.Errorf("frontend archive contains unsupported entry %q", header.Name)
		}
	}
	return nil
}

func safeArchiveName(name string) (string, error) {
	name = strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "./")
	if name == "" || strings.HasPrefix(name, "/") {
		return "", errors.New("frontend archive contains an unsafe path")
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || path.IsAbs(cleaned) {
		return "", errors.New("frontend archive contains an unsafe path")
	}
	return cleaned, nil
}

func referencedAssets(index []byte) []string {
	document, err := html.Parse(strings.NewReader(string(index)))
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var assets []string
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode {
			for _, attribute := range node.Attr {
				if attribute.Key != "src" && attribute.Key != "href" {
					continue
				}
				asset := strings.TrimPrefix(path.Clean("/"+attribute.Val), "/")
				if !strings.HasPrefix(asset, "assets/") || asset == "assets/" {
					continue
				}
				if _, exists := seen[asset]; !exists {
					seen[asset] = struct{}{}
					assets = append(assets, asset)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document)
	sort.Strings(assets)
	return assets
}

func carryForwardAssets(currentDir, stagingDir string) error {
	currentAssets := filepath.Join(currentDir, "assets")
	stagingAssets := filepath.Join(stagingDir, "assets")
	if err := ensureSafeDirectory(currentAssets); err != nil {
		return err
	}
	if err := ensureSafeDirectory(stagingAssets); err != nil {
		return err
	}
	return filepath.WalkDir(currentAssets, func(source string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(currentAssets, source)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() && !entry.IsDir() {
			return errors.New("current frontend assets contain an unsafe entry")
		}
		destination := filepath.Join(stagingAssets, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0755)
		}
		if _, err := os.Lstat(destination); err == nil {
			return nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			return err
		}
		if err := os.Link(source, destination); err == nil {
			return nil
		}
		return copyRegularFile(source, destination)
	})
}

func copyRegularFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		_ = os.Remove(destination)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(destination)
	}
	return closeErr
}

func normalizeWebReleasePermissions(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("frontend release contains a symbolic link")
		}
		if entry.IsDir() {
			return os.Chmod(path, 0755)
		}
		return os.Chmod(path, 0644)
	})
}

// syncWebReleaseTree persists every staged file and then its directories from
// leaves to root. A release rename is only a durable publication after this
// data and the parent releases directory have both reached stable storage.
func syncWebReleaseTree(root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("frontend release contains a symbolic link")
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("frontend release contains an unsafe entry: %s", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("sync frontend release file %s: %w", path, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close frontend release file %s: %w", path, err)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool {
		return len(directories[i]) > len(directories[j])
	})
	for _, directory := range directories {
		if err := syncWebDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func syncWebDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func rejectSymlinks(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("frontend release contains a symbolic link: %s", path)
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return fmt.Errorf("frontend release contains an unsafe entry: %s", path)
		}
		return nil
	})
}

func ensureSafeDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe directory: %s", path)
	}
	return nil
}

func replaceManagedLink(root, name, target string) error {
	if name != "current" && name != "previous" {
		return errors.New("invalid managed link name")
	}
	var err error
	target, releaseID, err := normalizeManagedReleaseTarget(root, target)
	if err != nil {
		return fmt.Errorf("invalid managed link target: %w", err)
	}
	if err := validateManagedReleaseTarget(root, target); err != nil {
		return fmt.Errorf("unsafe managed link target: %w", err)
	}
	linkPath := filepath.Join(root, name)
	if info, err := os.Lstat(linkPath); err == nil && info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("managed link path is not a symbolic link: %s", linkPath)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	temporary := filepath.Join(root, "."+name+"-"+releaseID+fmt.Sprintf("-%d", time.Now().UnixNano()))
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, linkPath); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := syncWebDirectory(root); err != nil {
		return fmt.Errorf("sync managed link directory: %w", err)
	}
	return nil
}
