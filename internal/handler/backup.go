package handler

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

const (
	maxBackupArchiveBytes = 256 << 20
	// Leave room for the authenticated stream framing and multipart metadata so
	// every archive produced at maxBackupArchiveBytes can be uploaded again.
	maxBackupUploadBytes   = maxBackupArchiveBytes + (1 << 20)
	maxBackupExpandedBytes = 512 << 20
	maxBackupFileBytes     = 256 << 20
	// RLDKBKP1 used one AES-GCM message and therefore cannot be decrypted
	// incrementally. Cap compatibility restores so ciphertext and plaintext do
	// not create an attacker-controlled 512MB memory peak. New backups use the
	// chunked RLDKBKP2 format and retain the full archive limit above.
	maxLegacyBackupBytes   = 64 << 20
	maxBackupFiles         = 10000
	backupStreamChunkBytes = 1 << 20
	pendingRestoreDirName  = ".arcway-pending-restore"
)

var backupRestoreMu sync.Mutex
var backupStreamMagic = []byte("RLDKBKP2")

// restorePassphraseFromRequest only reads multipart form data. Backup secrets
// must never be accepted from URL query parameters because access logs retain
// the complete request target.
func restorePassphraseFromRequest(r *http.Request) string {
	if r.MultipartForm == nil {
		return ""
	}
	values := r.MultipartForm.Value["passphrase"]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// NewBackupDownloadHandler 返回一个创建并下载【加密】备份的处理程序。
// 备份用管理员现场输入的口令(X-Backup-Passphrase 头)整包加密,口令不落盘。
// 该处理程序需要管理员身份验证。
func NewBackupDownloadHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("backup download handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeBackupError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		passphrase := r.Header.Get("X-Backup-Passphrase")
		if len(passphrase) < backupMinPassphraseLen {
			writeBackupError(w, http.StatusBadRequest, fmt.Errorf("需要备份口令(至少 %d 位);备份含敏感凭据,必须加密下载", backupMinPassphraseLen))
			return
		}

		snapshotPath, cleanupSnapshot, err := repo.CreateConsistentSnapshot(r.Context())
		if err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("create database snapshot: %w", err))
			return
		}
		defer cleanupSnapshot()

		// The plaintext ZIP is unlinked immediately after creation. It remains
		// addressable through the open descriptor but cannot survive a crash as a
		// named file containing credentials and private keys.
		zipFile, cleanupZip, err := newSecureAnonymousTemp("arcway-backup-*.zip")
		if err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("create backup staging file: %w", err))
			return
		}
		defer cleanupZip()
		zipWriter := zip.NewWriter(zipFile)
		if err := addDirToZipFiltered(zipWriter, "data", "data", shouldSkipLiveDatabaseFile); err != nil {
			_ = zipWriter.Close()
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("打包 data 失败: %w", err))
			return
		}
		if err := addFileToZip(zipWriter, snapshotPath, "data/arcway.db"); err != nil {
			_ = zipWriter.Close()
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("打包数据库快照失败: %w", err))
			return
		}
		if err := addDirToZip(zipWriter, "subscribes", "subscribes"); err != nil {
			_ = zipWriter.Close()
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("打包 subscribes 失败: %w", err))
			return
		}
		if err := zipWriter.Close(); err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("finalize zip: %w", err))
			return
		}
		zipInfo, err := zipFile.Stat()
		if err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("stat zip: %w", err))
			return
		}
		if zipInfo.Size() > maxBackupArchiveBytes {
			writeBackupError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("备份压缩包超过 %dMB 限制", maxBackupArchiveBytes>>20))
			return
		}
		if _, err := zipFile.Seek(0, io.SeekStart); err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("rewind zip: %w", err))
			return
		}
		encryptedFile, cleanupEncrypted, err := newSecureAnonymousTemp("arcway-backup-*.enc")
		if err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("create encrypted staging file: %w", err))
			return
		}
		defer cleanupEncrypted()
		if err := encryptBackupStream(encryptedFile, zipFile, passphrase); err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("encrypt backup: %w", err))
			return
		}
		info, err := encryptedFile.Stat()
		if err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("stat encrypted backup: %w", err))
			return
		}
		if _, err := encryptedFile.Seek(0, io.SeekStart); err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("rewind encrypted backup: %w", err))
			return
		}

		filename := fmt.Sprintf("relaydock-backup-%s.zip.enc", time.Now().Format("20060102-150405"))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
		w.Header().Set("Cache-Control", "no-store")

		if _, err := io.Copy(w, encryptedFile); err != nil {
			log.Printf("[Backup] 输出失败: %v", err)
			return
		}
	})
}

// NewBackupRestoreHandler 返回一个从备份恢复的处理程序。
// 加密备份需在 multipart 表单里带 passphrase 字段;旧的明文 zip 备份仍可直接恢复(向后兼容)。
// 该处理程序需要管理员身份验证。
func NewBackupRestoreHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("backup restore handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeBackupError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		backupRestoreMu.Lock()
		defer backupRestoreMu.Unlock()
		if err := restoreFromRequest(w, r); err != nil {
			return // restoreFromRequest 内部已写错误响应
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "备份已验证并暂存，重启 Arcway 服务后自动应用",
		})
	})
}

// NewSetupRestoreBackupHandler 返回用于在初始设置期间恢复备份的处理程序。
// 该处理程序不需要身份验证，但仅在系统未初始化(无用户)时可用。
func NewSetupRestoreBackupHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("setup restore backup handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeBackupError(w, http.StatusMethodNotAllowed, errors.New("only POST is supported"))
			return
		}

		setupMu.Lock()
		defer setupMu.Unlock()

		// 关键安全检查：仅在不存在用户时允许
		users, err := repo.ListUsers(r.Context(), 1)
		if err != nil {
			writeBackupError(w, http.StatusInternalServerError, err)
			return
		}
		if len(users) > 0 {
			writeBackupError(w, http.StatusForbidden, errors.New("系统已初始化，无法使用此接口恢复备份"))
			return
		}

		backupRestoreMu.Lock()
		defer backupRestoreMu.Unlock()
		if err := restoreFromRequest(w, r); err != nil {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "备份已验证并暂存，重启 Arcway 服务后自动应用",
		})
	})
}

// restoreFromRequest validates an uploaded backup into a persistent pending
// tree. It deliberately does not replace live files while the repository is
// open; ApplyPendingBackupRestore performs that transition during startup.
func restoreFromRequest(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUploadBytes)

	file, _, err := r.FormFile("backup")
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeBackupError(w, status, fmt.Errorf("failed to read backup file: %w", err))
		return err
	}
	defer func() {
		_ = file.Close()
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	archiveFile, cleanupArchive, err := newSecureAnonymousTemp("arcway-restore-*.zip")
	if err != nil {
		writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("create restore staging file: %w", err))
		return err
	}
	defer cleanupArchive()

	prefix := make([]byte, len(backupStreamMagic))
	prefixLen, readErr := io.ReadFull(file, prefix)
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		writeBackupError(w, http.StatusBadRequest, fmt.Errorf("read backup header: %w", readErr))
		return readErr
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeBackupError(w, http.StatusBadRequest, fmt.Errorf("rewind backup upload: %w", err))
		return err
	}

	passphrase := restorePassphraseFromRequest(r)
	switch {
	case prefixLen == len(backupStreamMagic) && bytes.Equal(prefix, backupStreamMagic):
		if passphrase == "" {
			err = errors.New("该备份已加密，需要提供备份口令")
			writeBackupError(w, http.StatusBadRequest, err)
			return err
		}
		err = decryptBackupStreamTo(archiveFile, file, passphrase, maxBackupArchiveBytes)
	case prefixLen >= len(backupMagic) && bytes.Equal(prefix[:len(backupMagic)], backupMagic):
		if passphrase == "" {
			err = errors.New("该备份已加密，需要提供备份口令")
			writeBackupError(w, http.StatusBadRequest, err)
			return err
		}
		var encrypted []byte
		encrypted, err = io.ReadAll(io.LimitReader(file, maxLegacyBackupBytes+1))
		if err == nil && int64(len(encrypted)) > maxLegacyBackupBytes {
			err = newBackupSizeError("旧版加密备份超过 %dMB 兼容限制，请使用新版分块备份", maxLegacyBackupBytes>>20)
		}
		if err == nil {
			var plaintext []byte
			plaintext, err = decryptBackup(encrypted, passphrase)
			if err == nil && int64(len(plaintext)) > maxBackupArchiveBytes {
				err = newBackupSizeError("解密后的备份超过 %dMB 限制", maxBackupArchiveBytes>>20)
			}
			if err == nil {
				_, err = archiveFile.Write(plaintext)
			}
		}
	default:
		_, err = copyBackupWithLimit(archiveFile, file, maxBackupArchiveBytes)
	}
	if err != nil {
		writeBackupError(w, backupHTTPStatus(err), err)
		return err
	}

	info, err := archiveFile.Stat()
	if err != nil {
		writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("stat restore archive: %w", err))
		return err
	}
	if _, err := archiveFile.Seek(0, io.SeekStart); err != nil {
		writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("rewind restore archive: %w", err))
		return err
	}
	cwd, err := os.Getwd()
	if err == nil {
		err = stageBackupArchiveAt(archiveFile, info.Size(), cwd)
	}
	if err != nil {
		writeBackupError(w, backupHTTPStatus(err), fmt.Errorf("failed to stage backup: %w", err))
		return err
	}
	return nil
}

// 递归地将目录添加到 zip writer
func addDirToZip(zipWriter *zip.Writer, srcDir, baseInZip string) error {
	return addDirToZipFiltered(zipWriter, srcDir, baseInZip, nil)
}

func addDirToZipFiltered(zipWriter *zip.Writer, srcDir, baseInZip string, skip func(string) bool) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录（它们是隐式创建的）
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to back up special file %s", path)
		}

		// 跳过隐藏文件和特殊文件
		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if skip != nil && skip(filepath.ToSlash(relPath)) {
			return nil
		}
		zipPath := filepath.Join(baseInZip, relPath)

		// 创建具有适当修改时间的文件头
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = zipPath
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func shouldSkipLiveDatabaseFile(relativePath string) bool {
	if strings.Contains(relativePath, "/") {
		return false
	}
	switch strings.ToLower(relativePath) {
	case "arcway.db", "arcway.db-wal", "arcway.db-shm", "arcway.db-journal",
		"traffic.db", "traffic.db-wal", "traffic.db-shm", "traffic.db-journal":
		return true
	default:
		return false
	}
}

func addFileToZip(zipWriter *zip.Writer, sourcePath, nameInZip string) error {
	file, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to back up special file %s", sourcePath)
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(nameInZip)
	header.Method = zip.Deflate
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, file)
	return err
}

// extractBackupFromBytes 从内存中的 zip 字节提取备份。
func extractBackupFromBytes(data []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	return extractZipReader(zr)
}

// extractZipReader validates and stages a pending restore in the current
// working directory. It is retained as a small compatibility wrapper for
// package-level callers and tests.
func extractZipReader(reader *zip.Reader) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}
	return extractZipReaderAt(reader, cwd)
}

func extractZipReaderAt(reader *zip.Reader, cwd string) error {
	return stageBackupZipReaderAt(reader, cwd)
}

type validatedBackupEntry struct {
	file *zip.File
	name string
}

func validateBackupArchive(reader *zip.Reader) ([]validatedBackupEntry, map[string]struct{}, error) {
	if len(reader.File) > maxBackupFiles {
		return nil, nil, fmt.Errorf("备份文件数量超过 %d 个限制", maxBackupFiles)
	}
	entries := make([]validatedBackupEntry, 0, len(reader.File))
	roots := make(map[string]struct{})
	seen := make(map[string]struct{})
	hasDatabase := false
	var expanded uint64
	for _, file := range reader.File {
		name := file.Name
		if name == "" || strings.TrimSpace(name) != name || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || path.Clean(name) != strings.TrimSuffix(name, "/") {
			return nil, nil, fmt.Errorf("备份包含非法路径 %q", file.Name)
		}
		parts := strings.Split(strings.TrimSuffix(name, "/"), "/")
		if len(parts) == 0 || (parts[0] != "data" && parts[0] != "subscribes") {
			return nil, nil, fmt.Errorf("备份包含不支持的路径 %q", file.Name)
		}
		if len(parts) == 1 {
			if !file.FileInfo().IsDir() {
				return nil, nil, fmt.Errorf("备份根路径 %q 必须是目录", file.Name)
			}
			roots[parts[0]] = struct{}{}
			continue
		}
		for _, component := range parts {
			if component == "" || component == "." || component == ".." {
				return nil, nil, fmt.Errorf("备份包含非法路径 %q", file.Name)
			}
		}
		cleanName := strings.Join(parts, "/")
		if _, duplicate := seen[cleanName]; duplicate {
			return nil, nil, fmt.Errorf("备份包含重复路径 %q", cleanName)
		}
		seen[cleanName] = struct{}{}
		mode := file.Mode()
		if !file.FileInfo().IsDir() && !mode.IsRegular() {
			return nil, nil, fmt.Errorf("备份包含不支持的特殊文件 %q", cleanName)
		}
		if file.UncompressedSize64 > maxBackupFileBytes {
			return nil, nil, fmt.Errorf("备份文件 %q 超过 %dMB 限制", cleanName, maxBackupFileBytes>>20)
		}
		if ^uint64(0)-expanded < file.UncompressedSize64 {
			return nil, nil, errors.New("备份解压大小溢出")
		}
		expanded += file.UncompressedSize64
		if expanded > maxBackupExpandedBytes {
			return nil, nil, fmt.Errorf("备份解压总量超过 %dMB 限制", maxBackupExpandedBytes>>20)
		}
		roots[parts[0]] = struct{}{}
		if cleanName == "data/arcway.db" && !file.FileInfo().IsDir() {
			hasDatabase = true
		}
		entries = append(entries, validatedBackupEntry{file: file, name: cleanName})
	}
	if !hasDatabase {
		return nil, nil, errors.New("备份文件格式无效：缺少 data/arcway.db")
	}
	// A system backup is a complete snapshot of both managed roots. Older
	// archives may omit an empty subscribes directory, which must still restore
	// as empty rather than retaining files from the current installation.
	roots["data"] = struct{}{}
	roots["subscribes"] = struct{}{}
	return entries, roots, nil
}

func encryptBackupStream(destination io.Writer, source io.Reader, passphrase string) error {
	salt := make([]byte, backupSaltLen)
	baseNonce := make([]byte, backupNonceLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	if _, err := rand.Read(baseNonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	aead, err := backupStreamAEAD(passphrase, salt)
	if err != nil {
		return err
	}
	for _, header := range [][]byte{backupStreamMagic, salt, baseNonce} {
		if _, err := destination.Write(header); err != nil {
			return err
		}
	}
	buffer := make([]byte, backupStreamChunkBytes)
	for counter := uint64(0); ; {
		read, readErr := io.ReadFull(source, buffer)
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return readErr
		}
		if read > 0 {
			if err := binary.Write(destination, binary.BigEndian, uint32(read)); err != nil {
				return err
			}
			ciphertext := aead.Seal(nil, backupStreamNonce(baseNonce, counter), buffer[:read], backupStreamAAD(counter))
			if _, err := destination.Write(ciphertext); err != nil {
				return err
			}
			counter++
		}
		if readErr != nil {
			if err := binary.Write(destination, binary.BigEndian, uint32(0)); err != nil {
				return err
			}
			terminal := aead.Seal(nil, backupStreamNonce(baseNonce, counter), nil, backupStreamAAD(counter))
			_, err := destination.Write(terminal)
			return err
		}
	}
}

func decryptBackupStream(source io.Reader, passphrase string, maxPlaintext int64) ([]byte, error) {
	var plaintext bytes.Buffer
	if err := decryptBackupStreamTo(&plaintext, source, passphrase, maxPlaintext); err != nil {
		return nil, err
	}
	return plaintext.Bytes(), nil
}

func backupStreamAEAD(passphrase string, salt []byte) (cipher.AEAD, error) {
	key, err := deriveBackupKey(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func backupStreamNonce(base []byte, counter uint64) []byte {
	nonce := append([]byte(nil), base...)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], counter)
	return nonce
}

func backupStreamAAD(counter uint64) []byte {
	aad := make([]byte, len(backupStreamMagic)+8)
	copy(aad, backupStreamMagic)
	binary.BigEndian.PutUint64(aad[len(backupStreamMagic):], counter)
	return aad
}

func isStreamEncryptedBackup(data []byte) bool {
	return len(data) >= len(backupStreamMagic) && bytes.Equal(data[:len(backupStreamMagic)], backupStreamMagic)
}

func writeBackupError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}
