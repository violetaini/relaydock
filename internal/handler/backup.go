package handler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// backupPassphraseFromRequest 从请求头或表单取备份口令。下载用 header(不进访问日志),
// 恢复用 multipart 表单字段(与上传文件同一请求)。
func backupPassphraseFromRequest(r *http.Request) string {
	if p := r.Header.Get("X-Backup-Passphrase"); p != "" {
		return p
	}
	return r.FormValue("passphrase")
}

// NewBackupDownloadHandler 返回一个创建并下载【加密】备份的处理程序。
// 备份用管理员现场输入的口令(X-Backup-Passphrase 头)整包加密,口令不落盘。
// 该处理程序需要管理员身份验证。
func NewBackupDownloadHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("backup download handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeBackupError(w, http.StatusMethodNotAllowed, errors.New("only GET or POST is supported"))
			return
		}

		passphrase := backupPassphraseFromRequest(r)
		if len(passphrase) < backupMinPassphraseLen {
			writeBackupError(w, http.StatusBadRequest, fmt.Errorf("需要备份口令(至少 %d 位);备份含敏感凭据,必须加密下载", backupMinPassphraseLen))
			return
		}

		// 检查点 WAL 确保所有数据都写入主数据库文件
		if err := repo.Checkpoint(); err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("failed to checkpoint database: %w", err))
			return
		}

		// 先把 zip 打进内存,再整包加密后输出。备份体积小(主要是 SQLite + 订阅文件),内存可控;
		// 好处是加密前的打包错误仍能正常回 4xx/5xx(旧实现边打包边写响应,出错无法回报)。
		var zipBuf bytes.Buffer
		zipWriter := zip.NewWriter(&zipBuf)
		if err := addDirToZip(zipWriter, "data", "data"); err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("打包 data 失败: %w", err))
			return
		}
		if err := addDirToZip(zipWriter, "subscribes", "subscribes"); err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("打包 subscribes 失败: %w", err))
			return
		}
		if err := zipWriter.Close(); err != nil {
			writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("finalize zip: %w", err))
			return
		}

		filename := fmt.Sprintf("relaydock-backup-%s.zip.enc", time.Now().Format("20060102-150405"))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

		if err := encryptBackup(w, zipBuf.Bytes(), passphrase); err != nil {
			// 此时响应头已发出,无法再回 JSON 错误,只能记录。
			log.Printf("[Backup] 加密输出失败: %v", err)
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

		if err := restoreFromRequest(w, r); err != nil {
			return // restoreFromRequest 内部已写错误响应
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "备份恢复成功，请重启服务或刷新页面",
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

		if err := restoreFromRequest(w, r); err != nil {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "备份恢复成功，请刷新页面后登录",
		})
	})
}

// restoreFromRequest 读取上传的备份(加密或旧明文),解密(如需要)后提取到 data/ 与 subscribes/。
// 出错时已写好响应并返回非 nil,调用方据此直接 return。
func restoreFromRequest(w http.ResponseWriter, r *http.Request) error {
	// 将上传大小限制为 100MB
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)

	file, _, err := r.FormFile("backup")
	if err != nil {
		writeBackupError(w, http.StatusBadRequest, fmt.Errorf("failed to read backup file: %w", err))
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("failed to read backup file: %w", err))
		return err
	}

	if isEncryptedBackup(data) {
		passphrase := backupPassphraseFromRequest(r)
		if passphrase == "" {
			writeBackupError(w, http.StatusBadRequest, errors.New("该备份已加密，需要提供备份口令"))
			return errors.New("passphrase required")
		}
		plain, derr := decryptBackup(data, passphrase)
		if derr != nil {
			writeBackupError(w, http.StatusBadRequest, derr)
			return derr
		}
		data = plain
	}

	if err := extractBackupFromBytes(data); err != nil {
		writeBackupError(w, http.StatusInternalServerError, fmt.Errorf("failed to extract backup: %w", err))
		return err
	}
	return nil
}

// 递归地将目录添加到 zip writer
func addDirToZip(zipWriter *zip.Writer, srcDir, baseInZip string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录（它们是隐式创建的）
		if info.IsDir() {
			return nil
		}

		// 跳过隐藏文件和特殊文件
		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
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
		defer f.Close()

		_, err = io.Copy(writer, f)
		return err
	})
}

// extractBackupFromBytes 从内存中的 zip 字节提取备份。
func extractBackupFromBytes(data []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	return extractZipReader(zr)
}

// extractZipReader 把 zip 内容提取到 data/ 与 subscribes/(其余路径忽略,并防路径穿越)。
func extractZipReader(reader *zip.Reader) error {
	// 首先验证 zip 内容
	hasData := false
	hasSubscribes := false
	for _, f := range reader.File {
		if strings.HasPrefix(f.Name, "data/") {
			hasData = true
		}
		if strings.HasPrefix(f.Name, "subscribes/") {
			hasSubscribes = true
		}
	}

	if !hasData && !hasSubscribes {
		return errors.New("备份文件格式无效：缺少 data 或 subscribes 目录")
	}

	for _, f := range reader.File {
		// 安全检查：防止路径穿越
		if strings.Contains(f.Name, "..") {
			continue
		}

		// 只提取 data/ 和 subscribes/ 目录
		if !strings.HasPrefix(f.Name, "data/") && !strings.HasPrefix(f.Name, "subscribes/") {
			continue
		}

		destPath := f.Name

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", destPath, err)
			}
			continue
		}

		// 确保父目录存在
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("failed to create parent directory for %s: %w", destPath, err)
		}

		srcFile, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open zip file %s: %w", f.Name, err)
		}

		destFile, err := os.Create(destPath)
		if err != nil {
			srcFile.Close()
			return fmt.Errorf("failed to create file %s: %w", destPath, err)
		}

		_, err = io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()

		if err != nil {
			return fmt.Errorf("failed to extract file %s: %w", f.Name, err)
		}
	}

	return nil
}

func writeBackupError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}
