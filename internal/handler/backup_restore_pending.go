package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	pendingRestorePreviousName = pendingRestoreDirName + ".previous"
	restoreRollbackDirName     = ".arcway-restore-rollback"
	restoreCommittedDirName    = ".arcway-restore-committed"
	restoreStagePrefix         = ".arcway-restore-stage-"
	restoreManifestName        = ".arcway-restore-manifest.json"
	restoreNoLivePrefix        = ".no-live-"
	restoreManifestVersion     = 1
)

var managedRestoreRoots = map[string]struct{}{
	"data":       {},
	"subscribes": {},
}

type pendingRestoreManifest struct {
	Version int      `json:"version"`
	Roots   []string `json:"roots"`
}

type backupSizeError struct {
	message string
}

func (e *backupSizeError) Error() string {
	return e.message
}

func newBackupSizeError(format string, args ...any) error {
	return &backupSizeError{message: fmt.Sprintf(format, args...)}
}

func backupHTTPStatus(err error) int {
	var sizeErr *backupSizeError
	if errors.As(err, &sizeErr) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// newSecureAnonymousTemp creates a mode-0600 file and immediately removes its
// directory entry. The open descriptor remains usable, while a crash cannot
// leave a named plaintext backup behind.
func newSecureAnonymousTemp(pattern string) (*os.File, func(), error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, nil, err
	}
	name := file.Name()
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return nil, nil, err
	}
	if err := os.Remove(name); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return nil, nil, fmt.Errorf("unlink secure temporary file: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}

func copyBackupWithLimit(destination io.Writer, source io.Reader, limit int64) (int64, error) {
	written, err := io.Copy(destination, io.LimitReader(source, limit+1))
	if err != nil {
		return written, err
	}
	if written > limit {
		return written, newBackupSizeError("备份压缩包超过 %dMB 限制", limit>>20)
	}
	return written, nil
}

func decryptBackupStreamTo(destination io.Writer, source io.Reader, passphrase string, maxPlaintext int64) error {
	header := make([]byte, len(backupStreamMagic)+backupSaltLen+backupNonceLen)
	if _, err := io.ReadFull(source, header); err != nil {
		return errors.New("备份文件已损坏或格式不正确")
	}
	if !bytes.Equal(header[:len(backupStreamMagic)], backupStreamMagic) {
		return errors.New("不是分块加密备份")
	}
	offset := len(backupStreamMagic)
	salt := header[offset : offset+backupSaltLen]
	offset += backupSaltLen
	baseNonce := header[offset : offset+backupNonceLen]
	aead, err := backupStreamAEAD(passphrase, salt)
	if err != nil {
		return err
	}

	var plaintextSize int64
	for counter := uint64(0); ; counter++ {
		var size uint32
		if err := binary.Read(source, binary.BigEndian, &size); err != nil {
			return errors.New("备份文件已截断")
		}
		if size == 0 {
			terminal := make([]byte, aead.Overhead())
			if _, err := io.ReadFull(source, terminal); err != nil {
				return errors.New("备份文件已截断")
			}
			if _, err := aead.Open(nil, backupStreamNonce(baseNonce, counter), terminal, backupStreamAAD(counter)); err != nil {
				return errors.New("解密失败:备份口令错误或文件已损坏")
			}
			var trailing [1]byte
			if read, _ := source.Read(trailing[:]); read != 0 {
				return errors.New("备份文件包含尾随数据")
			}
			return nil
		}
		if size > backupStreamChunkBytes || plaintextSize+int64(size) > maxPlaintext {
			return newBackupSizeError("解密后的备份超过 %dMB 限制", maxPlaintext>>20)
		}
		ciphertext := make([]byte, int(size)+aead.Overhead())
		if _, err := io.ReadFull(source, ciphertext); err != nil {
			return errors.New("备份文件已截断")
		}
		chunk, err := aead.Open(nil, backupStreamNonce(baseNonce, counter), ciphertext, backupStreamAAD(counter))
		if err != nil {
			return errors.New("解密失败:备份口令错误或文件已损坏")
		}
		written, err := destination.Write(chunk)
		if err != nil {
			return err
		}
		if written != len(chunk) {
			return io.ErrShortWrite
		}
		plaintextSize += int64(written)
	}
}

func stageBackupArchiveAt(archive io.ReaderAt, size int64, baseDir string) error {
	if size <= 0 {
		return errors.New("备份文件为空")
	}
	if size > maxBackupArchiveBytes {
		return newBackupSizeError("备份压缩包超过 %dMB 限制", maxBackupArchiveBytes>>20)
	}
	reader, err := zip.NewReader(archive, size)
	if err != nil {
		return fmt.Errorf("打开备份 ZIP: %w", err)
	}
	return stageBackupZipReaderAt(reader, baseDir)
}

func stageBackupZipReaderAt(reader *zip.Reader, baseDir string) error {
	entries, rootSet, err := validateBackupArchive(reader)
	if err != nil {
		return err
	}
	if err := recoverPendingPublication(baseDir, os.Rename); err != nil {
		return err
	}
	if err := cleanupOrphanRestoreStages(baseDir); err != nil {
		return err
	}

	staging, err := os.MkdirTemp(baseDir, restoreStagePrefix)
	if err != nil {
		return fmt.Errorf("create restore staging directory: %w", err)
	}
	if err := os.Chmod(staging, 0700); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("secure restore staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	roots := make([]string, 0, len(rootSet))
	for root := range rootSet {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		if err := os.Mkdir(filepath.Join(staging, root), 0700); err != nil {
			return fmt.Errorf("create staged %s: %w", root, err)
		}
	}

	var writtenTotal int64
	for _, entry := range entries {
		destination := filepath.Join(staging, filepath.FromSlash(entry.name))
		if entry.file.FileInfo().IsDir() {
			if err := os.MkdirAll(destination, 0700); err != nil {
				return fmt.Errorf("create staged directory %s: %w", entry.name, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return fmt.Errorf("create staged parent for %s: %w", entry.name, err)
		}
		source, err := entry.file.Open()
		if err != nil {
			return fmt.Errorf("open backup entry %s: %w", entry.name, err)
		}
		destinationFile, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			_ = source.Close()
			return fmt.Errorf("create staged file %s: %w", entry.name, err)
		}
		written, copyErr := io.Copy(destinationFile, io.LimitReader(source, maxBackupFileBytes+1))
		syncErr := destinationFile.Sync()
		closeDestinationErr := destinationFile.Close()
		closeSourceErr := source.Close()
		if copyErr != nil || syncErr != nil || closeDestinationErr != nil || closeSourceErr != nil {
			return fmt.Errorf("extract staged file %s: %w", entry.name, errors.Join(copyErr, syncErr, closeDestinationErr, closeSourceErr))
		}
		if written != int64(entry.file.UncompressedSize64) || written > maxBackupFileBytes {
			return fmt.Errorf("backup entry %s size mismatch", entry.name)
		}
		writtenTotal += written
		if writtenTotal > maxBackupExpandedBytes {
			return newBackupSizeError("备份实际解压总量超过 %dMB 限制", maxBackupExpandedBytes>>20)
		}
	}

	manifest := pendingRestoreManifest{Version: restoreManifestVersion, Roots: roots}
	if err := writeRestoreManifest(staging, manifest); err != nil {
		return err
	}
	if err := validatePendingRestoreTree(staging, manifest); err != nil {
		return err
	}
	return publishPendingRestore(baseDir, staging, os.Rename)
}

func writeRestoreManifest(directory string, manifest pendingRestoreManifest) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	filename := filepath.Join(directory, restoreManifestName)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create restore manifest: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write restore manifest: %w", err)
	}
	return errors.Join(file.Sync(), file.Close())
}

func readRestoreManifest(directory string) (pendingRestoreManifest, error) {
	data, err := os.ReadFile(filepath.Join(directory, restoreManifestName))
	if err != nil {
		return pendingRestoreManifest{}, fmt.Errorf("read restore manifest: %w", err)
	}
	var manifest pendingRestoreManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return pendingRestoreManifest{}, fmt.Errorf("decode restore manifest: %w", err)
	}
	if manifest.Version != restoreManifestVersion {
		return pendingRestoreManifest{}, fmt.Errorf("unsupported restore manifest version %d", manifest.Version)
	}
	seen := make(map[string]struct{}, len(manifest.Roots))
	for _, root := range manifest.Roots {
		if _, ok := managedRestoreRoots[root]; !ok {
			return pendingRestoreManifest{}, fmt.Errorf("unsupported restore root %q", root)
		}
		if _, duplicate := seen[root]; duplicate {
			return pendingRestoreManifest{}, fmt.Errorf("duplicate restore root %q", root)
		}
		seen[root] = struct{}{}
	}
	if _, ok := seen["data"]; !ok {
		return pendingRestoreManifest{}, errors.New("restore manifest is missing data root")
	}
	if _, ok := seen["subscribes"]; !ok {
		return pendingRestoreManifest{}, errors.New("restore manifest is missing subscribes root")
	}
	sort.Strings(manifest.Roots)
	return manifest, nil
}

func validatePendingRestoreTree(directory string, manifest pendingRestoreManifest) error {
	allowedTopLevel := map[string]struct{}{restoreManifestName: {}}
	for _, root := range manifest.Roots {
		allowedTopLevel[root] = struct{}{}
	}
	topLevel, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range topLevel {
		if _, ok := allowedTopLevel[entry.Name()]; !ok {
			return fmt.Errorf("pending restore contains unexpected path %q", entry.Name())
		}
	}

	files := 0
	var expanded int64
	for _, root := range manifest.Roots {
		rootPath := filepath.Join(directory, root)
		rootInfo, err := os.Lstat(rootPath)
		if err != nil {
			return fmt.Errorf("inspect pending root %s: %w", root, err)
		}
		if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("pending restore root %s is not a directory", root)
		}
		err = filepath.Walk(rootPath, func(current string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
				return fmt.Errorf("pending restore contains unsupported file %s", current)
			}
			if info.Mode().IsRegular() {
				files++
				expanded += info.Size()
				if info.Size() > maxBackupFileBytes || expanded > maxBackupExpandedBytes || files > maxBackupFiles {
					return newBackupSizeError("pending restore exceeds extraction limits")
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	databaseInfo, err := os.Lstat(filepath.Join(directory, "data", "arcway.db"))
	if err != nil || !databaseInfo.Mode().IsRegular() {
		return errors.New("pending restore is missing a regular data/arcway.db")
	}
	return validateRestoredSQLite(filepath.Join(directory, "data", "arcway.db"))
}

// validateRestoredSQLite opens the staged database read-only and verifies its
// page structure before the tree can be published or activated. A bounded
// quick_check catches malformed or truncated backups without running schema
// migrations against untrusted input.
func validateRestoredSQLite(databasePath string) error {
	absolutePath, err := filepath.Abs(databasePath)
	if err != nil {
		return fmt.Errorf("resolve restored database path: %w", err)
	}
	dsn := (&url.URL{
		Scheme:   "file",
		Path:     filepath.ToSlash(absolutePath),
		RawQuery: "mode=ro&immutable=1&_pragma=query_only(1)&_pragma=busy_timeout(5000)",
	}).String()
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open restored database read-only: %w", err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var result string
	if err := database.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&result); err != nil {
		return fmt.Errorf("check restored database integrity: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("restored database failed integrity check: %s", result)
	}
	return nil
}

type restoreRenameFunc func(string, string) error

func publishPendingRestore(baseDir, staging string, rename restoreRenameFunc) error {
	if err := recoverPendingPublication(baseDir, rename); err != nil {
		return err
	}
	pending := filepath.Join(baseDir, pendingRestoreDirName)
	previous := filepath.Join(baseDir, pendingRestorePreviousName)
	hadPending, err := pathExists(pending)
	if err != nil {
		return err
	}
	if hadPending {
		if err := rename(pending, previous); err != nil {
			return fmt.Errorf("preserve previous pending restore: %w", err)
		}
	}
	if err := rename(staging, pending); err != nil {
		if hadPending {
			return errors.Join(fmt.Errorf("publish pending restore: %w", err), rename(previous, pending))
		}
		return fmt.Errorf("publish pending restore: %w", err)
	}
	if hadPending {
		if err := os.RemoveAll(previous); err != nil {
			return fmt.Errorf("remove superseded pending restore: %w", err)
		}
	}
	return nil
}

func recoverPendingPublication(baseDir string, rename restoreRenameFunc) error {
	pending := filepath.Join(baseDir, pendingRestoreDirName)
	previous := filepath.Join(baseDir, pendingRestorePreviousName)
	previousExists, err := pathExists(previous)
	if err != nil || !previousExists {
		return err
	}
	pendingExists, err := pathExists(pending)
	if err != nil {
		return err
	}
	if pendingExists {
		return os.RemoveAll(previous)
	}
	if err := rename(previous, pending); err != nil {
		return fmt.Errorf("recover previous pending restore: %w", err)
	}
	return nil
}

// ApplyPendingBackupRestore applies a fully validated pending restore. It must
// be called during startup before opening the SQLite repository or loading any
// keys and caches backed by the data directory.
func ApplyPendingBackupRestore(baseDir string) (bool, error) {
	backupRestoreMu.Lock()
	defer backupRestoreMu.Unlock()
	return applyPendingBackupRestoreAt(baseDir, os.Rename)
}

func applyPendingBackupRestoreAt(baseDir string, rename restoreRenameFunc) (bool, error) {
	if err := recoverPendingPublication(baseDir, rename); err != nil {
		return false, err
	}
	committed, err := recoverInterruptedRestoreApply(baseDir, rename)
	if err != nil {
		return false, err
	}
	if committed {
		_ = cleanupOrphanRestoreStages(baseDir)
		return true, nil
	}

	pending := filepath.Join(baseDir, pendingRestoreDirName)
	pendingExists, err := pathExists(pending)
	if err != nil || !pendingExists {
		return false, err
	}
	manifest, err := readRestoreManifest(pending)
	if err != nil {
		return false, err
	}
	if err := validatePendingRestoreTree(pending, manifest); err != nil {
		return false, err
	}

	rollback := filepath.Join(baseDir, restoreRollbackDirName)
	if err := os.Mkdir(rollback, 0700); err != nil {
		return false, fmt.Errorf("create restore rollback directory: %w", err)
	}
	if err := writeRestoreManifest(rollback, manifest); err != nil {
		_ = os.RemoveAll(rollback)
		return false, err
	}

	for _, root := range manifest.Roots {
		liveRoot := filepath.Join(baseDir, root)
		pendingRoot := filepath.Join(pending, root)
		rollbackRoot := filepath.Join(rollback, root)
		liveExists, err := pathExists(liveRoot)
		if err != nil {
			return false, rollbackRestoreApply(baseDir, rename, err)
		}
		if liveExists {
			if err := rename(liveRoot, rollbackRoot); err != nil {
				return false, rollbackRestoreApply(baseDir, rename, fmt.Errorf("preserve live %s: %w", root, err))
			}
		} else if err := writeRestoreMarker(filepath.Join(rollback, restoreNoLivePrefix+root)); err != nil {
			return false, rollbackRestoreApply(baseDir, rename, err)
		}
		if err := rename(pendingRoot, liveRoot); err != nil {
			return false, rollbackRestoreApply(baseDir, rename, fmt.Errorf("activate restored %s: %w", root, err))
		}
	}

	committedState := filepath.Join(baseDir, restoreCommittedDirName)
	if err := rename(rollback, committedState); err != nil {
		return false, rollbackRestoreApply(baseDir, rename, fmt.Errorf("commit pending restore: %w", err))
	}
	if err := os.RemoveAll(pending); err != nil {
		return true, fmt.Errorf("restore applied but pending cleanup failed: %w", err)
	}
	if err := os.RemoveAll(committedState); err != nil {
		return true, fmt.Errorf("restore applied but previous-tree cleanup failed: %w", err)
	}
	if err := cleanupOrphanRestoreStages(baseDir); err != nil {
		return true, fmt.Errorf("restore applied but staging cleanup failed: %w", err)
	}
	return true, nil
}

func writeRestoreMarker(filename string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func rollbackRestoreApply(baseDir string, rename restoreRenameFunc, cause error) error {
	_, rollbackErr := recoverInterruptedRestoreApply(baseDir, rename)
	return errors.Join(cause, rollbackErr)
}

// recoverInterruptedRestoreApply rolls an uncommitted transaction back to the
// old live tree and reconstructs the pending tree. Once rollback state is
// atomically renamed to the committed path, recovery only finishes cleanup and
// never undoes the newly activated tree.
func recoverInterruptedRestoreApply(baseDir string, rename restoreRenameFunc) (bool, error) {
	committedState := filepath.Join(baseDir, restoreCommittedDirName)
	committedExists, err := pathExists(committedState)
	if err != nil {
		return false, err
	}
	if committedExists {
		pending := filepath.Join(baseDir, pendingRestoreDirName)
		if err := os.RemoveAll(pending); err != nil {
			return true, fmt.Errorf("finish committed pending cleanup: %w", err)
		}
		if err := os.RemoveAll(committedState); err != nil {
			return true, fmt.Errorf("finish committed previous-tree cleanup: %w", err)
		}
		return true, nil
	}

	rollback := filepath.Join(baseDir, restoreRollbackDirName)
	rollbackExists, err := pathExists(rollback)
	if err != nil || !rollbackExists {
		return false, err
	}
	manifest, err := readRestoreManifest(rollback)
	if err != nil {
		return false, fmt.Errorf("read interrupted restore state: %w", err)
	}
	pending := filepath.Join(baseDir, pendingRestoreDirName)
	if err := os.MkdirAll(pending, 0700); err != nil {
		return false, err
	}
	if manifestExists, _ := pathExists(filepath.Join(pending, restoreManifestName)); !manifestExists {
		if err := writeRestoreManifest(pending, manifest); err != nil {
			return false, err
		}
	}

	for index := len(manifest.Roots) - 1; index >= 0; index-- {
		root := manifest.Roots[index]
		liveRoot := filepath.Join(baseDir, root)
		pendingRoot := filepath.Join(pending, root)
		rollbackRoot := filepath.Join(rollback, root)
		oldLiveExists, err := pathExists(rollbackRoot)
		if err != nil {
			return false, err
		}
		noLiveMarker, err := pathExists(filepath.Join(rollback, restoreNoLivePrefix+root))
		if err != nil {
			return false, err
		}
		if !oldLiveExists && !noLiveMarker {
			continue
		}
		pendingRootExists, err := pathExists(pendingRoot)
		if err != nil {
			return false, err
		}
		if !pendingRootExists {
			liveExists, err := pathExists(liveRoot)
			if err != nil {
				return false, err
			}
			if !liveExists {
				return false, fmt.Errorf("cannot recover restored root %s", root)
			}
			if err := rename(liveRoot, pendingRoot); err != nil {
				return false, fmt.Errorf("return restored %s to pending tree: %w", root, err)
			}
		}
		if oldLiveExists {
			if err := rename(rollbackRoot, liveRoot); err != nil {
				return false, fmt.Errorf("restore previous live %s: %w", root, err)
			}
		}
	}
	if err := os.RemoveAll(rollback); err != nil {
		return false, fmt.Errorf("remove restore rollback state: %w", err)
	}
	return false, nil
}

func cleanupOrphanRestoreStages(baseDir string) error {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return err
	}
	var cleanupErr error
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), restoreStagePrefix) {
			cleanupErr = errors.Join(cleanupErr, os.RemoveAll(filepath.Join(baseDir, entry.Name())))
		}
	}
	return cleanupErr
}

func pathExists(filename string) (bool, error) {
	_, err := os.Lstat(filename)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
