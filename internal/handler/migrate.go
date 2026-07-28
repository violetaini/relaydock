package handler

// 妙妙屋(mmw)→ 妙妙屋X 迁移工具的后端实现。
// 当前只实现"自动拉取备份"接口,其余 (import-mmw / claim-*) 后续在引导页评审通过后逐步补。

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
)

const (
	migrateWorkDir      = "/tmp/mmwx-migrate"
	defaultFetchTimeout = 5 * time.Minute // mmw 备份可能几十 MB,跨网络下载留足时间
	maxBackupSizeBytes  = 500 << 20       // 500 MB,防止恶意 URL 让主控 OOM
	maxExtractedBytes   = 1 << 30         // 1 GiB, ZIP 解压后所有有效条目的总上限
	maxExtractedEntry   = 768 << 20       // 768 MiB, 单个 DB/订阅文件上限
	maxArchiveEntries   = 10_000          // 防止海量空条目消耗 CPU/内存
	migrateWorkPerm     = 0o700
	migrateTempFilePerm = 0o600
	migrationSessionTTL = 24 * time.Hour
)

var migrationIDPattern = regexp.MustCompile(`^[a-f0-9]{16,64}$`)

// MigrateHandler 处理 /api/admin/migrate/* 系列接口。
type MigrateHandler struct {
	repo          *storage.TrafficRepository
	rm            *RemoteManageHandler
	subscribesDir string
}

func NewMigrateHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler) *MigrateHandler {
	return &MigrateHandler{repo: repo, rm: rm, subscribesDir: mmwxSubscribesDir}
}

// ------- POST /api/admin/migrate/fetch-mmw-backup -------

type fetchMmwBackupReq struct {
	URL                   string `json:"url"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	TOTP                  string `json:"totp"`
	AllowInsecureLoopback bool   `json:"allow_insecure_loopback"`
}

type fetchMmwBackupResp struct {
	Success        bool   `json:"success"`
	MigrationID    string `json:"migration_id"`
	BackupPath     string `json:"backup_path,omitempty"`    // 旧前端兼容字段;新响应不再暴露服务端路径
	DBPath         string `json:"db_path,omitempty"`        // 旧前端兼容字段
	SubscribesDir  string `json:"subscribes_dir,omitempty"` // 旧前端兼容字段
	SubscribeCount int    `json:"subscribe_count"`
	SizeBytes      int64  `json:"size_bytes"`
	DBSizeBytes    int64  `json:"db_size_bytes"`
}

func (h *MigrateHandler) FetchMmwBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST")
		return
	}
	var req fetchMmwBackupReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.URL == "" || req.Username == "" || req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "url, username, password 必填")
		return
	}
	sourceURL, err := validateMmwSourceURL(req.URL, req.AllowInsecureLoopback)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.URL = strings.TrimRight(sourceURL.String(), "/")

	ctx, cancel := context.WithTimeout(r.Context(), defaultFetchTimeout)
	defer cancel()
	// Cleanup runs before authentication too: a failed prepare must not prevent
	// stale sessions from being reclaimed on the next attempt.
	if err := ensureMigrateWorkDir(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("创建工作目录失败: %v", err))
		return
	}
	cleanupExpiredMigrationSessions(time.Now())
	// 不在 client 上设 Timeout — 完全靠 ctx 控制,避免和 ctx 重复
	client := newMmwHTTPClient(sourceURL)

	// 1. 登录 mmw 拿 token
	token, err := mmwLogin(ctx, client, req.URL, req.Username, req.Password, req.TOTP)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("登录妙妙屋失败: %v", err))
		return
	}

	// 2. 准备暂存目录 + 随机文件名(防并发覆盖)
	id, err := randomHex(16)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("生成随机 id 失败: %v", err))
		return
	}
	keepSession := false
	defer func() {
		if !keepSession {
			_ = removeMigrationSession(id)
		}
	}()
	zipPath := filepath.Join(migrateWorkDir, id+".zip")

	// 3. 调 mmw 备份下载接口
	dlReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, req.URL+"/api/admin/backup/download", nil)
	dlReq.Header.Set("MM-Authorization", token)
	dlResp, err := client.Do(dlReq)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("下载备份失败: %v", err))
		return
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(dlResp.Body, 1024))
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("下载备份失败 status=%d body=%s", dlResp.StatusCode, string(b)))
		return
	}

	zf, err := os.OpenFile(zipPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, migrateTempFilePerm)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("打开本地暂存文件失败: %v", err))
		return
	}
	// 用 LimitReader 防"恶意巨大 zip"
	n, copyErr := io.Copy(zf, io.LimitReader(dlResp.Body, maxBackupSizeBytes+1))
	zf.Close()
	if copyErr != nil {
		os.Remove(zipPath)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("写入本地暂存失败: %v", copyErr))
		return
	}
	if n > maxBackupSizeBytes {
		os.Remove(zipPath)
		writeJSONError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("备份大小超过限制 (%d MB)", maxBackupSizeBytes>>20))
		return
	}

	// 4. 解压 zip 中的 *.db 文件 + subscribes/ 目录到独立路径(后续 import 直接用)
	dbPath := filepath.Join(migrateWorkDir, id+".db")
	subsDir := filepath.Join(migrateWorkDir, id+"-subs")
	dbSize, subCount, err := extractMmwBackup(zipPath, dbPath, subsDir)
	if err != nil {
		_ = removeMigrationSession(id)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("解压备份失败: %v", err))
		return
	}

	log.Printf("[Migrate] fetched mmw backup from %s: zip=%d bytes db=%d bytes subs=%d files", req.URL, n, dbSize, subCount)

	respondJSON(w, http.StatusOK, fetchMmwBackupResp{
		Success:        true,
		MigrationID:    id,
		SubscribeCount: subCount,
		SizeBytes:      n,
		DBSizeBytes:    dbSize,
	})
	keepSession = true
}

// ------- POST /api/admin/migrate/upload-mmw-backup -------
// 用户上传妙妙屋后台备份 zip(同 fetch 接口拿到的格式)。
type uploadMmwBackupResp = fetchMmwBackupResp

const maxUploadBytes = 500 << 20

func (h *MigrateHandler) UploadMmwBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, header, err := r.FormFile("backup")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("读取上传文件失败: %v", err))
		return
	}
	defer file.Close()
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		writeJSONError(w, http.StatusBadRequest, "请上传妙妙屋后台导出的 zip 备份")
		return
	}

	if err := ensureMigrateWorkDir(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("创建工作目录失败: %v", err))
		return
	}
	cleanupExpiredMigrationSessions(time.Now())
	id, err := randomHex(16)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("生成随机 id 失败: %v", err))
		return
	}
	keepSession := false
	defer func() {
		if !keepSession {
			_ = removeMigrationSession(id)
		}
	}()
	zipPath := filepath.Join(migrateWorkDir, id+".zip")
	out, err := os.OpenFile(zipPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, migrateTempFilePerm)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("写本地暂存失败: %v", err))
		return
	}
	n, copyErr := io.Copy(out, file)
	out.Close()
	if copyErr != nil {
		os.Remove(zipPath)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("流式写入失败: %v", copyErr))
		return
	}

	dbPath := filepath.Join(migrateWorkDir, id+".db")
	subsDir := filepath.Join(migrateWorkDir, id+"-subs")
	dbSize, subCount, err := extractMmwBackup(zipPath, dbPath, subsDir)
	if err != nil {
		_ = removeMigrationSession(id)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("解压备份失败: %v", err))
		return
	}

	log.Printf("[Migrate] uploaded mmw backup: zip=%d bytes db=%d bytes subs=%d files", n, dbSize, subCount)

	respondJSON(w, http.StatusOK, uploadMmwBackupResp{
		Success:        true,
		MigrationID:    id,
		SubscribeCount: subCount,
		SizeBytes:      n,
		DBSizeBytes:    dbSize,
	})
	keepSession = true
}

// mmwLogin 调 $baseURL/api/login,若需 2FA 再调 /api/login/2fa,最终返回 access token。
func mmwLogin(ctx context.Context, client *http.Client, baseURL, username, password, totp string) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var first map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&first); err != nil {
		return "", err
	}
	// 需要 2FA
	if needs, _ := first["requires_2fa"].(bool); needs {
		tfToken, _ := first["two_factor_token"].(string)
		if tfToken == "" {
			return "", errors.New("mmw 要求 2FA 但未返回 two_factor_token")
		}
		if strings.TrimSpace(totp) == "" {
			return "", errors.New("管理员账号开启了 2FA,请填写两步验证码后重试")
		}
		body2, _ := json.Marshal(map[string]string{
			"two_factor_token": tfToken,
			"code":             strings.TrimSpace(totp),
		})
		req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/login/2fa", bytes.NewReader(body2))
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := client.Do(req2)
		if err != nil {
			return "", err
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp2.Body, 512))
			return "", fmt.Errorf("2fa status=%d body=%s", resp2.StatusCode, strings.TrimSpace(string(b)))
		}
		var second map[string]any
		if err := json.NewDecoder(resp2.Body).Decode(&second); err != nil {
			return "", err
		}
		tok, _ := second["token"].(string)
		if tok == "" {
			return "", errors.New("2fa 响应中缺少 token")
		}
		return tok, nil
	}
	tok, _ := first["token"].(string)
	if tok == "" {
		return "", errors.New("登录响应中缺少 token (可能不是妙妙屋实例?)")
	}
	return tok, nil
}

// extractMmwBackup 从 zip 提取 mmw 备份的两部分:
//   - data/*.db → outDBPath(取第一个找到的 db 文件)
//   - subscribes/* → outSubsDir/ (每个文件展平,忽略原 zip 内子目录)
//
// 返回 (dbSize, subsFileCount, error)。
//
// 防御:跳过含 "..", 跳过目录条目,subscribe 文件总大小受 maxBackupSizeBytes 约束(zip 自身已被外层限速)。
func extractMmwBackup(zipPath, outDBPath, outSubsDir string) (int64, int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, 0, err
	}
	defer zr.Close()
	if len(zr.File) > maxArchiveEntries {
		return 0, 0, fmt.Errorf("zip 条目数超过限制 (%d)", maxArchiveEntries)
	}

	if err := os.MkdirAll(outSubsDir, migrateWorkPerm); err != nil {
		return 0, 0, fmt.Errorf("创建 subscribes 目录失败: %w", err)
	}
	if err := os.Chmod(outSubsDir, migrateWorkPerm); err != nil {
		return 0, 0, fmt.Errorf("设置 subscribes 目录权限失败: %w", err)
	}

	var dbSize int64
	var dbFound bool
	subCount := 0
	var extractedTotal int64

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if strings.Contains(f.Name, "..") {
			continue
		}
		// 把 zip 路径分隔符(始终是 '/')统一处理
		clean := strings.TrimLeft(f.Name, "/")

		// data/*.db → outDBPath(取第一个)
		if !dbFound && strings.HasPrefix(strings.ToLower(clean), "data/") && strings.HasSuffix(strings.ToLower(clean), ".db") {
			if f.UncompressedSize64 > maxExtractedEntry || f.UncompressedSize64 > uint64(maxExtractedBytes)-uint64(extractedTotal) {
				return 0, 0, errors.New("zip 解压数据超过 DB 大小或总大小限制")
			}
			n, err := copyZipEntry(f, outDBPath, maxExtractedEntry, maxExtractedBytes-extractedTotal)
			if err != nil {
				return 0, 0, fmt.Errorf("copy db: %w", err)
			}
			dbSize = n
			extractedTotal += n
			dbFound = true
			continue
		}

		// subscribes/<filename> → outSubsDir/<filename>(扁平化)
		if strings.HasPrefix(strings.ToLower(clean), "subscribes/") {
			base := filepath.Base(clean)
			if base == "" || base == "." {
				continue
			}
			target := filepath.Join(outSubsDir, base)
			if f.UncompressedSize64 > maxExtractedEntry || f.UncompressedSize64 > uint64(maxExtractedBytes)-uint64(extractedTotal) {
				return 0, 0, errors.New("zip 解压订阅数据超过大小限制")
			}
			n, err := copyZipEntry(f, target, maxExtractedEntry, maxExtractedBytes-extractedTotal)
			if err != nil {
				return 0, 0, fmt.Errorf("copy subscribe %s: %w", clean, err)
			}
			extractedTotal += n
			subCount++
		}
	}

	if !dbFound {
		return 0, 0, errors.New("zip 中没有 data/*.db,该归档可能不是有效的妙妙屋备份")
	}
	return dbSize, subCount, nil
}

func copyZipEntry(f *zip.File, outPath string, entryLimit, totalRemaining int64) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	if entryLimit <= 0 || totalRemaining <= 0 {
		return 0, errors.New("zip 解压总大小超过限制")
	}
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, migrateTempFilePerm)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	limit := entryLimit
	if totalRemaining < limit {
		limit = totalRemaining
	}
	n, err := io.Copy(out, io.LimitReader(rc, limit+1))
	if err != nil {
		_ = os.Remove(outPath)
		return n, err
	}
	if n > limit {
		_ = os.Remove(outPath)
		return n, errors.New("zip 解压单条目超过大小限制")
	}
	return n, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type migrationSessionPaths struct {
	Zip  string
	DB   string
	Subs string
}

func migrationSession(id string) (migrationSessionPaths, error) {
	id = strings.TrimSpace(id)
	if !migrationIDPattern.MatchString(id) {
		return migrationSessionPaths{}, errors.New("migration_id 无效")
	}
	return migrationSessionPaths{
		Zip:  filepath.Join(migrateWorkDir, id+".zip"),
		DB:   filepath.Join(migrateWorkDir, id+".db"),
		Subs: filepath.Join(migrateWorkDir, id+"-subs"),
	}, nil
}

func ensureMigrateWorkDir() error {
	if err := os.MkdirAll(migrateWorkDir, migrateWorkPerm); err != nil {
		return err
	}
	info, err := os.Lstat(migrateWorkDir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("migration work directory must be a real directory")
	}
	// MkdirAll does not tighten an existing directory. Migration artifacts contain
	// databases and are therefore never allowed to inherit a world-readable mode.
	return os.Chmod(migrateWorkDir, migrateWorkPerm)
}

func removeMigrationSession(id string) error {
	paths, err := migrationSession(id)
	if err != nil {
		return err
	}
	var errs []string
	for _, path := range []string{paths.Zip, paths.DB} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err.Error())
		}
	}
	if err := os.RemoveAll(paths.Subs); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func cleanupExpiredMigrationSessions(now time.Time) {
	entries, err := os.ReadDir(migrateWorkDir)
	if err != nil {
		return
	}
	cutoff := now.Add(-migrationSessionTTL)
	ids := map[string]struct{}{}
	for _, entry := range entries {
		name := entry.Name()
		id := ""
		switch {
		case strings.HasSuffix(name, ".zip"):
			id = strings.TrimSuffix(name, ".zip")
		case strings.HasSuffix(name, ".db"):
			id = strings.TrimSuffix(name, ".db")
		case strings.HasSuffix(name, "-subs"):
			id = strings.TrimSuffix(name, "-subs")
		}
		if migrationIDPattern.MatchString(id) {
			ids[id] = struct{}{}
		}
	}
	for id := range ids {
		paths, err := migrationSession(id)
		if err != nil {
			continue
		}
		latest := time.Time{}
		for _, path := range []string{paths.Zip, paths.DB, paths.Subs} {
			info, statErr := os.Stat(path)
			if statErr != nil {
				continue
			}
			if info.ModTime().After(latest) {
				latest = info.ModTime()
			}
		}
		if !latest.IsZero() && latest.Before(cutoff) {
			if err := removeMigrationSession(id); err != nil {
				log.Printf("[Migrate] cleanup expired session %s failed: %v", id, err)
			}
		}
	}
}

func validateMigrationArtifact(path, id, suffix string, wantDir bool) (string, error) {
	paths, err := migrationSession(id)
	if err != nil {
		return "", err
	}
	expected := paths.DB
	if suffix == ".zip" {
		expected = paths.Zip
	} else if suffix == "-subs" {
		expected = paths.Subs
	}
	clean, err := filepath.Abs(filepath.Clean(strings.TrimSpace(path)))
	if err != nil || clean != expected {
		return "", errors.New("migration artifact path 不在当前会话工作目录中")
	}
	info, err := os.Lstat(expected)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || (wantDir != info.IsDir()) || (!wantDir && !info.Mode().IsRegular()) {
		return "", errors.New("migration artifact 类型无效")
	}
	return expected, nil
}

func resolveLegacyMigrationPaths(dbPath, subsDir string) (string, string, error) {
	dbPath = strings.TrimSpace(dbPath)
	clean, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return "", "", errors.New("db_path 无效")
	}
	rel, err := filepath.Rel(migrateWorkDir, clean)
	if err != nil || strings.Contains(rel, string(filepath.Separator)) || filepath.Dir(rel) != "." || !strings.HasSuffix(rel, ".db") {
		return "", "", errors.New("db_path 只能指向迁移工作目录内的会话数据库")
	}
	id := strings.TrimSuffix(filepath.Base(rel), ".db")
	if !migrationIDPattern.MatchString(id) {
		return "", "", errors.New("db_path 的会话 ID 无效")
	}
	resolvedDB, err := validateMigrationArtifact(clean, id, ".db", false)
	if err != nil {
		return "", "", fmt.Errorf("db_path 不可用: %w", err)
	}
	if strings.TrimSpace(subsDir) == "" {
		return resolvedDB, "", nil
	}
	resolvedSubs, err := validateMigrationArtifact(subsDir, id, "-subs", true)
	if err != nil {
		return "", "", fmt.Errorf("subscribes_dir 不可用: %w", err)
	}
	return resolvedDB, resolvedSubs, nil
}

func resolveMigrationImportPaths(req importMmwReq) (string, string, error) {
	if id := strings.TrimSpace(req.MigrationID); id != "" {
		paths, err := migrationSession(id)
		if err != nil {
			return "", "", err
		}
		dbPath, err := validateMigrationArtifact(paths.DB, id, ".db", false)
		if err != nil {
			return "", "", fmt.Errorf("migration_id 不可用: %w", err)
		}
		if _, err := os.Lstat(paths.Subs); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return dbPath, "", nil
			}
			return "", "", fmt.Errorf("migration subscribes 不可用: %w", err)
		}
		if _, err := validateMigrationArtifact(paths.Subs, id, "-subs", true); err != nil {
			return "", "", fmt.Errorf("migration subscribes 不可用: %w", err)
		}
		return dbPath, paths.Subs, nil
	}
	if strings.TrimSpace(req.DBPath) == "" {
		return "", "", errors.New("migration_id 或 db_path 必填")
	}
	return resolveLegacyMigrationPaths(req.DBPath, req.SubscribesDir)
}

// CleanupMmwSession 删除一个迁移会话创建的 zip、db 和 subscribes 目录。
// 只接受不透明 migration_id，绝不接受任意文件路径。
func (h *MigrateHandler) CleanupMmwSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only DELETE or POST")
		return
	}
	var req struct {
		MigrationID string `json:"migration_id"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	id := strings.TrimSpace(req.MigrationID)
	if id == "" {
		// DELETE /.../cleanup?id=... is intentionally not supported: accepting
		// only JSON keeps the endpoint explicit and avoids ambiguous path parsing.
		writeJSONError(w, http.StatusBadRequest, "migration_id 必填")
		return
	}
	if err := removeMigrationSession(id); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			respondJSON(w, http.StatusOK, map[string]any{"success": true, "migration_id": id, "removed": false})
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "migration_id": id, "removed": true})
}

func validateMmwSourceURL(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return nil, errors.New("url 必须是不含账号密码的 http(s) 地址")
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("url 只能包含源面板的协议、主机和可选端口")
	}
	u.Path = ""
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u, nil
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
		if loopback && allowInsecureLoopback {
			return u, nil
		}
		return nil, errors.New("远程源地址必须使用 HTTPS；HTTP 仅允许显式开启的 loopback 地址")
	default:
		return nil, errors.New("url 必须使用 https://（loopback 可显式使用 http://）")
	}
}

func sameURLOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return port(a) == port(b)
}

func newMmwHTTPClient(source *url.URL) *http.Client {
	return &http.Client{
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) > 0 && !sameURLOrigin(source, next.URL) {
				return errors.New("拒绝跳转到非同源地址")
			}
			return nil
		},
	}
}

// ------- POST /api/admin/migrate/import-mmw -------

type importMmwReq struct {
	MigrationID   string `json:"migration_id"`
	DBPath        string `json:"db_path"`        // mmw.db 路径
	SubscribesDir string `json:"subscribes_dir"` // 可选:解压后的 subscribes/ 目录,内部文件会被拷到 mmwx subscribes/
}

type importMmwResp struct {
	Success           bool                     `json:"success"`
	Report            *storage.MmwImportReport `json:"report"`
	OwnedByAdmin      string                   `json:"owned_by_admin"`     // 订阅 / 模板等被分配给哪个 admin 用户
	SubscribesCopied  int                      `json:"subscribes_copied"`  // 拷到 mmwx subscribes/ 的文件数
	SubscribesSkipped []string                 `json:"subscribes_skipped"` // 跳过的文件(同名已存在)
}

const mmwxSubscribesDir = "subscribes" // mmwx 默认订阅文件目录(相对工作目录)

// ImportMmw 把 mmw 备份完整导入当前 mmwx 实例:
//   - subscribes_dir(可选):先原子、幂等复制订阅文件，全部成功后才提交数据库
//   - db_path:mmw.db,核心 9 张表合并到 mmwx db(INSERT OR IGNORE)
//   - 把 subscribe_files / templates 的 created_by 字段填成当前认证 admin 用户名
//     (mmw 没有 created_by 概念，不能按源库时间或 rowid 选择管理员)
func (h *MigrateHandler) ImportMmw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST")
		return
	}
	var req importMmwReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	admin := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
	adminUser, err := h.repo.GetUser(r.Context(), admin)
	if err != nil || admin == "" || adminUser.Role != storage.RoleAdmin || !adminUser.IsActive {
		writeJSONError(w, http.StatusForbidden, "当前认证管理员无效，已拒绝迁移")
		return
	}
	dbPath, subsDir, err := resolveMigrationImportPaths(req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	blocking, err := h.repo.MmwImportBlockingCounts(r.Context(), admin)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("迁移预检失败: %v", err))
		return
	}
	if len(blocking) > 0 {
		keys := make([]string, 0, len(blocking))
		for key := range blocking {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", key, blocking[key]))
		}
		respondJSON(w, http.StatusConflict, map[string]any{
			"success":         false,
			"error":           "迁移只允许导入空白 Arcway 实例；为避免 ID 冲突和关联错位已阻止导入。检测到：" + strings.Join(parts, ", "),
			"blocking_counts": blocking,
		})
		return
	}

	// 1. 先复制订阅文件。每个文件通过同目录临时文件 + hard link 原子落盘，
	// 失败时数据库仍为空，管理员可直接重试；已成功的文件会被幂等跳过。
	copied, skipped := 0, []string{}
	if subsDir != "" {
		if _, err := os.Stat(subsDir); err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("读取 subscribes 失败: %v", err))
			return
		}
		destination := h.subscribesDir
		if strings.TrimSpace(destination) == "" {
			destination = mmwxSubscribesDir
		}
		copied, skipped, err = copySubscribesDir(r.Context(), h.repo, subsDir, destination)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("拷贝 subscribes 失败，未导入数据库，可直接重试: %v", err))
			return
		}
	}

	// 2. 文件已完整就位后，再以单事务导入数据库。
	report, err := h.repo.ImportFromMmw(r.Context(), dbPath, admin)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("导入失败: %v", err))
		return
	}

	log.Printf("[Migrate] imported mmw: db=%s users=%d user_tokens=%d nodes=%d sub_files=%d subs_copied=%d",
		dbPath, report.Users, report.UserTokens, report.Nodes, report.SubscribeFiles, copied)
	respondJSON(w, http.StatusOK, importMmwResp{
		Success:           true,
		Report:            report,
		OwnedByAdmin:      admin,
		SubscribesCopied:  copied,
		SubscribesSkipped: skipped,
	})
}

// copySubscribesDir 把 src 目录里所有非隐藏常规文件拷贝到 dst。
// 同名文件已存在 → 跳过(保留 mmwx 现有的,不覆盖),并把文件名加入 skipped 列表。
// dst 目录不存在会自动建。
func copySubscribesDir(ctx context.Context, repo *storage.TrafficRepository, src, dst string) (int, []string, error) {
	if repo == nil {
		return 0, nil, errors.New("订阅私钥存储不可用")
	}
	if err := os.MkdirAll(dst, migrateWorkPerm); err != nil {
		return 0, nil, err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return 0, nil, err
	}
	copied := 0
	var skipped []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		srcPath := filepath.Join(src, name)
		dstPath := filepath.Join(dst, name)
		if _, err := os.Lstat(dstPath); err == nil {
			skipped = append(skipped, name)
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return copied, skipped, err
		}
		content, err := os.ReadFile(srcPath)
		if err != nil {
			return copied, skipped, err
		}
		protected, err := protectWireGuardSubscriptionContent(ctx, repo, name, string(content), true)
		if err != nil {
			return copied, skipped, fmt.Errorf("保护订阅 %s 的 WireGuard 私钥失败: %w", name, err)
		}
		created, err := copyMigrationFile([]byte(protected), dstPath)
		if err != nil {
			return copied, skipped, err
		}
		if created {
			copied++
		} else {
			skipped = append(skipped, name)
		}
	}
	return copied, skipped, nil
}

func copyMigrationFile(content []byte, dst string) (created bool, err error) {
	temporary, err := os.CreateTemp(filepath.Dir(dst), ".arcway-migrate-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(migrateTempFilePerm); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}

	// Link is an atomic no-replace operation on the destination filesystem.
	// A concurrent retry that wins the race is treated as an idempotent skip.
	if err := os.Link(temporaryPath, dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ------- POST /api/admin/migrate/takeover-external-xray -------

type takeoverResultPerServer struct {
	ServerID    int64  `json:"server_id"`
	ServerName  string `json:"server_name"`
	Success     bool   `json:"success"`
	Detected    bool   `json:"detected"`
	ConfigPath  string `json:"config_path,omitempty"`
	ConfDir     string `json:"conf_dir,omitempty"`
	MergedFiles int    `json:"merged_files"`
	BackupDir   string `json:"backup_dir,omitempty"`
	Restarted   bool   `json:"restarted"`
	Message     string `json:"message"`
	Error       string `json:"error,omitempty"`
}

type takeoverExternalXrayResp struct {
	Success        bool                      `json:"success"`
	ServersScanned int                       `json:"servers_scanned"`
	Results        []takeoverResultPerServer `json:"results"`
}

// TakeoverExternalXray 对所有已添加的远程服务器,触发 agent 的
// /api/child/external-xray/takeover 接口:
//   - 让 agent 探测正在跑的外置 xray + 合并 -confdir 进单个 config.json + 重启 xray
//
// 用途:从妙妙屋迁移过来,被妙妙屋用 multi-conf 方式管理的 xray 服务器,
// 装上 mmw-agent 后需要先把多片配置合并成单文件,mmwx 主控的 /api/child/inbounds
// 等接口才能正确读写(后续 PatchClientEmails 也才能找到 client)。
func (h *MigrateHandler) TakeoverExternalXray(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST")
		return
	}
	var req struct {
		ServerIDs []int64 `json:"server_ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	servers, err := h.repo.ListRemoteServers(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("list servers: %v", err))
		return
	}
	if len(req.ServerIDs) > 0 {
		want := make(map[int64]bool, len(req.ServerIDs))
		for _, id := range req.ServerIDs {
			want[id] = true
		}
		filtered := servers[:0]
		for _, s := range servers {
			if want[s.ID] {
				filtered = append(filtered, s)
			}
		}
		servers = filtered
	}

	resp := takeoverExternalXrayResp{
		Success:        true,
		ServersScanned: len(servers),
		Results:        []takeoverResultPerServer{},
	}
	for _, s := range servers {
		row := takeoverResultPerServer{ServerID: s.ID, ServerName: s.Name}
		raw, err := h.rm.forwardToRemoteServer(r.Context(), s.ID, "POST", "/api/child/external-xray/takeover", []byte("{}"))
		if err != nil {
			row.Error = err.Error()
			resp.Results = append(resp.Results, row)
			continue
		}
		var ar struct {
			Success     bool   `json:"success"`
			Detected    bool   `json:"detected"`
			ConfigPath  string `json:"config_path"`
			ConfDir     string `json:"conf_dir"`
			MergedFiles int    `json:"merged_files"`
			BackupDir   string `json:"backup_dir"`
			Restarted   bool   `json:"restarted"`
			Message     string `json:"message"`
			Error       string `json:"error"`
		}
		if err := json.Unmarshal(raw, &ar); err != nil {
			row.Error = fmt.Sprintf("parse agent resp: %v", err)
			resp.Results = append(resp.Results, row)
			continue
		}
		row.Success = ar.Success
		row.Detected = ar.Detected
		row.ConfigPath = ar.ConfigPath
		row.ConfDir = ar.ConfDir
		row.MergedFiles = ar.MergedFiles
		row.BackupDir = ar.BackupDir
		row.Restarted = ar.Restarted
		row.Message = ar.Message
		row.Error = ar.Error
		if !ar.Success && row.Error == "" {
			row.Error = strings.TrimSpace(ar.Message)
			if row.Error == "" {
				row.Error = "agent returned success=false"
			}
		}
		resp.Results = append(resp.Results, row)
	}

	log.Printf("[Migrate] takeover-external-xray: scanned %d servers", resp.ServersScanned)
	respondJSON(w, http.StatusOK, resp)
}

// ------- POST /api/admin/migrate/patch-client-emails -------

type patchClientEmailsReq struct {
	ServerIDs []int64 `json:"server_ids"` // 可选,留空 = 处理全部已添加的远程服务器
}

type patchedClient struct {
	ServerID   int64  `json:"server_id"`
	ServerName string `json:"server_name"`
	InboundTag string `json:"inbound_tag"`
	OldEmail   string `json:"old_email"` // 通常为空字符串
	NewEmail   string `json:"new_email"`
}

type adminSubaccount struct {
	ServerID   int64  `json:"server_id"`
	ServerName string `json:"server_name"`
	InboundTag string `json:"inbound_tag"`
	Email      string `json:"email"`
	WasNew     bool   `json:"was_new"` // 本次操作是否首次绑定到 user_inbound_configs
}

type ss2022InboundInfo struct {
	ServerID   int64  `json:"server_id"`
	ServerName string `json:"server_name"`
	InboundTag string `json:"inbound_tag"`
	Method     string `json:"method"`
}

type patchClientEmailsResp struct {
	Success                bool                `json:"success"`
	OwnedByAdmin           string              `json:"owned_by_admin"`
	ServersScanned         int                 `json:"servers_scanned"`
	InboundsTotal          int                 `json:"inbounds_total"`
	ClientsPatched         []patchedClient     `json:"clients_patched"`
	AdminSubaccountsLinked []adminSubaccount   `json:"admin_subaccounts_linked"` // 所有 admin 持有的 client(含已有 email 的) → user_inbound_configs
	SS2022Inbounds         []ss2022InboundInfo `json:"ss2022_inbounds"`
	ServerErrors           []string            `json:"server_errors,omitempty"`
}

// PatchClientEmails 扫描所有已添加的远程服务器,给 xray inbound.clients[] 里无 email 的 client
// 补 email = 系统第一个 admin 的 username。
//
// 为什么需要:
//   - 妙妙屋时代 xray inbound 一般只配一个 client,没设 email
//   - mmwx 这边按 email 做流量统计 / routing 限定,缺 email 导致无法归属用户
//
// 处理逻辑(对每个 server):
//  1. forwardToRemoteServer GET /api/child/inbounds → 拿所有 inbound 定义
//  2. 对每个 inbound,遍历 settings.clients[](VLESS/VMess/Trojan)或 settings.users(SS multi-user)
//  3. 无 email 的 client → 设 email = admin (多个无 email 时第二个开始拼后缀:admin__2)
//  4. 整个 inbound 用 action="add" 提交回 agent(agent 内部"remove + add"实现原地替换)
//  5. 同时检测该 inbound 是不是 SS2022(method 以 "2022-" 开头)→ 加入 ss2022 列表
func (h *MigrateHandler) PatchClientEmails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST")
		return
	}
	var req patchClientEmailsReq
	_ = json.NewDecoder(r.Body).Decode(&req) // body 可空

	admin := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
	if admin == "" {
		writeJSONError(w, http.StatusForbidden, "无法确定当前管理员")
		return
	}
	if user, err := h.repo.GetUser(r.Context(), admin); err != nil || user.Role != storage.RoleAdmin || !user.IsActive {
		writeJSONError(w, http.StatusForbidden, "当前认证管理员无效")
		return
	}

	servers, err := h.repo.ListRemoteServers(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("list servers: %v", err))
		return
	}

	// 过滤 server_ids(如果给了)
	if len(req.ServerIDs) > 0 {
		want := make(map[int64]bool, len(req.ServerIDs))
		for _, id := range req.ServerIDs {
			want[id] = true
		}
		filtered := servers[:0]
		for _, s := range servers {
			if want[s.ID] {
				filtered = append(filtered, s)
			}
		}
		servers = filtered
	}

	resp := patchClientEmailsResp{
		Success:        true,
		OwnedByAdmin:   admin,
		ServersScanned: len(servers),
		// 显式初始化为空切片,防止 Go nil slice 序列化为 JSON null 导致前端 .length 炸
		ClientsPatched: []patchedClient{},
		SS2022Inbounds: []ss2022InboundInfo{},
		ServerErrors:   []string{},
	}

	for _, s := range servers {
		leasedCtx, release, leaseErr := h.repo.AcquireRemoteServerExclusiveMutationLease(r.Context(), s.ID)
		if leaseErr != nil {
			resp.ServerErrors = append(resp.ServerErrors, fmt.Sprintf("server %s(%d): acquire mutation lease: %v", s.Name, s.ID, leaseErr))
			continue
		}
		func() {
			defer release()
			inbounds, fetchErr := fetchAgentInbounds(leasedCtx, h.rm, s.ID)
			if fetchErr != nil {
				resp.ServerErrors = append(resp.ServerErrors, fmt.Sprintf("server %s(%d): %v", s.Name, s.ID, fetchErr))
				return
			}
			resp.InboundsTotal += len(inbounds)
			for _, ib := range inbounds {
				tag, _ := ib["tag"].(string)
				protocol, _ := ib["protocol"].(string)
				fenceKnown, _ := ib["_mutation_fence_known"].(bool)
				mutationID := strings.TrimSpace(wireGuardStringValue(ib["_mutation_id"]))
				patched, allClients, isSS2022, method, patchErr := patchInboundClientEmails(ib, admin)
				if isSS2022 {
					resp.SS2022Inbounds = append(resp.SS2022Inbounds, ss2022InboundInfo{
						ServerID: s.ID, ServerName: s.Name, InboundTag: tag, Method: method,
					})
				}
				if patchErr != nil {
					resp.ServerErrors = append(resp.ServerErrors, fmt.Sprintf("server %s inbound %s: patch err: %v", s.Name, tag, patchErr))
					continue
				}
				// Inventory-only ownership annotations are never part of an Xray inbound.
				delete(ib, "_mutation_fence_known")
				delete(ib, "_mutation_id")
				// 只有真的 patch 了 email 才需要 write back 到 agent;否则只做 DB 侧 user_inbound_configs 绑定。
				// A whole-inbound replacement is accepted only for the exact authenticated generation.
				if len(patched) > 0 {
					if !fenceKnown || mutationID == "" {
						resp.ServerErrors = append(resp.ServerErrors, fmt.Sprintf("server %s inbound %s: Agent 未提供可信的当前代次，拒绝整份覆盖", s.Name, tag))
						continue
					}
					body, marshalErr := json.Marshal(map[string]any{"action": "add", "inbound": ib, "mutation_id": mutationID})
					if marshalErr != nil {
						resp.ServerErrors = append(resp.ServerErrors, fmt.Sprintf("server %s inbound %s: encode write back: %v", s.Name, tag, marshalErr))
						continue
					}
					result, forwardErr := h.rm.forwardToRemoteServer(leasedCtx, s.ID, "POST", "/api/child/inbounds", body)
					if forwardErr != nil {
						resp.ServerErrors = append(resp.ServerErrors, fmt.Sprintf("server %s inbound %s: write back err: %v", s.Name, tag, forwardErr))
						continue
					}
					if ackErr := validateManagedWireGuardMutationACK(result, mutationID); ackErr != nil {
						resp.ServerErrors = append(resp.ServerErrors, fmt.Sprintf("server %s inbound %s: write back not confirmed: %v", s.Name, tag, ackErr))
						continue
					}
				}
				for _, p := range patched {
					resp.ClientsPatched = append(resp.ClientsPatched, patchedClient{
						ServerID:   s.ID,
						ServerName: s.Name,
						InboundTag: tag,
						OldEmail:   p.oldEmail,
						NewEmail:   p.newEmail,
					})
				}
				// 把所有 client 登记到 user_inbound_configs(归属 admin),用于流量统计/管理
				for _, cli := range allClients {
					if strings.TrimSpace(cli.email) == "" {
						continue
					}
					credJSON, marshalErr := json.Marshal(cli.credential)
					if marshalErr != nil {
						continue
					}
					wasNew, bindErr := h.repo.EnsureAdminInboundClient(leasedCtx, admin, s.ID, tag, protocol, string(credJSON))
					if bindErr != nil {
						resp.ServerErrors = append(resp.ServerErrors, fmt.Sprintf("server %s inbound %s email %s: bind admin err: %v", s.Name, tag, cli.email, bindErr))
						continue
					}
					resp.AdminSubaccountsLinked = append(resp.AdminSubaccountsLinked, adminSubaccount{
						ServerID: s.ID, ServerName: s.Name, InboundTag: tag, Email: cli.email, WasNew: wasNew,
					})
				}
			}
		}()
	}

	log.Printf("[Migrate] patch-client-emails: scanned %d servers, patched %d clients, %d ss2022 inbounds, %d errors",
		resp.ServersScanned, len(resp.ClientsPatched), len(resp.SS2022Inbounds), len(resp.ServerErrors))
	respondJSON(w, http.StatusOK, resp)
}

// fetchAgentInbounds 从某 remote server 拿 inbounds 完整列表。
func fetchAgentInbounds(ctx context.Context, rm *RemoteManageHandler, serverID int64) ([]map[string]any, error) {
	if rm == nil {
		return nil, errors.New("remote manage handler 未初始化")
	}
	raw, err := rm.forwardToRemoteServer(ctx, serverID, "GET", "/api/child/inbounds", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Success  bool             `json:"success"`
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse inbounds: %w", err)
	}
	if !resp.Success {
		return nil, errors.New("agent returned success=false")
	}
	return resp.Inbounds, nil
}

type clientPatchResult struct {
	oldEmail string
	newEmail string
}

type inboundClient struct {
	email      string
	credential map[string]any // 完整 client JSON,用于落 user_inbound_configs.credential_json
	wasPatched bool           // 本次 patchEmail 流程刚补的
	oldEmail   string         // 原始 email(空字符串表示原来无 email)
}

// patchInboundClientEmails 修改 inbound 里 client 数组的 email(原地修改 ib map)。
// 支持 VLESS/VMess/Trojan(settings.clients)和 SS(settings.users)的 multi-user 模式。
// 返回:
//   - patched 这次操作真的补了 email 的 client 列表
//   - allClients 这个 inbound 里**所有**(含原本已有 email)的 client 完整快照,
//     供 handler 把它们都登记到 user_inbound_configs 作为 admin 的子账户绑定
//   - isSS2022, method
func patchInboundClientEmails(ib map[string]any, admin string) ([]clientPatchResult, []inboundClient, bool, string, error) {
	settings, _ := ib["settings"].(map[string]any)
	if settings == nil {
		return nil, nil, false, "", nil
	}
	// 检测 ss2022
	method, _ := settings["method"].(string)
	isSS2022 := strings.HasPrefix(strings.ToLower(method), "2022-")

	// VLESS/VMess/Trojan/Shadowsocks-2022:settings.clients[]; SS multi-user 也可能用 settings.users
	var patched []clientPatchResult
	var allClients []inboundClient
	for _, key := range []string{"clients", "users"} {
		arr, ok := settings[key].([]any)
		if !ok || len(arr) == 0 {
			continue
		}
		usedEmails := map[string]bool{}
		// 第一遍:记下已用 email
		for _, e := range arr {
			m, _ := e.(map[string]any)
			if m == nil {
				continue
			}
			if s, _ := m["email"].(string); s != "" {
				usedEmails[s] = true
			}
		}
		// 第二遍:无 email 的逐个补 + 收集所有 client
		seq := 1
		for _, e := range arr {
			m, _ := e.(map[string]any)
			if m == nil {
				continue
			}
			oldEmail, _ := m["email"].(string)
			oldEmail = strings.TrimSpace(oldEmail)
			wasPatched := false
			if oldEmail == "" {
				candidate := admin
				for usedEmails[candidate] {
					seq++
					candidate = fmt.Sprintf("%s__%d", admin, seq)
				}
				usedEmails[candidate] = true
				m["email"] = candidate
				patched = append(patched, clientPatchResult{oldEmail: oldEmail, newEmail: candidate})
				wasPatched = true
			}
			currentEmail, _ := m["email"].(string)
			allClients = append(allClients, inboundClient{
				email:      currentEmail,
				credential: m, // 引用同 map,后续 marshal 即可
				wasPatched: wasPatched,
				oldEmail:   oldEmail,
			})
		}
		settings[key] = arr
	}
	ib["settings"] = settings
	return patched, allClients, isSS2022, method, nil
}

// ------- GET /api/admin/migrate/distinct-node-servers -------

type distinctServer struct {
	Address          string   `json:"address"`         // clash_config.server(域名或 IP)
	NodeCount        int      `json:"node_count"`      // 指向该 server 的节点数
	Ports            []int    `json:"ports"`           // 涉及到的端口集合
	Protocols        []string `json:"protocols"`       // 涉及到的协议集合
	ExistingServer   bool     `json:"existing_server"` // mmwx 已有同名 remote_server
	ExistingServerID int64    `json:"existing_server_id,omitempty"`
	SampleNodeName   string   `json:"sample_node_name"` // 任选一个节点名给用户做参考
}

type distinctServersResp struct {
	Success bool             `json:"success"`
	Servers []distinctServer `json:"servers"`
	Note    string           `json:"note"`
}

// DistinctNodeServers 列出当前 mmwx 数据库里所有外部节点(没有 original_server / inbound_tag 关联的)
// 的去重 server 地址,用于"待添加为远程服务器"清单。
//
// mmw 没有"远程服务器 / xray inbound"概念,节点只是 clash 配置;迁移到 mmwx 后这些节点是
// "外部节点",必须先把每个去重 server 加为 mmwx 远程服务器并装 agent,扫描其 inbound 与节点
// 凭据匹配后才能升级为"受管节点"。
func (h *MigrateHandler) DistinctNodeServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "only GET")
		return
	}
	servers, err := h.repo.ListDistinctNodeServers(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("查询失败: %v", err))
		return
	}
	out := make([]distinctServer, 0, len(servers))
	for _, s := range servers {
		out = append(out, distinctServer{
			Address:          s.Address,
			NodeCount:        s.NodeCount,
			Ports:            s.Ports,
			Protocols:        s.Protocols,
			ExistingServer:   s.ExistingServer,
			ExistingServerID: s.ExistingServerID,
			SampleNodeName:   s.SampleNodeName,
		})
	}
	respondJSON(w, http.StatusOK, distinctServersResp{
		Success: true,
		Servers: out,
		Note:    "对每个未关联的 server 地址,需要在「服务管理」创建对应的远程服务器并安装 mmw-agent;agent 接入后会自动扫描 inbound,主控按凭据匹配把节点从'外部'升级为'受管'。",
	})
}
