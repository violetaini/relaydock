package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	SubscribeTypeCreate  = "create"
	SubscribeTypeImport  = "import"
	SubscribeTypeUpload  = "upload"
	SubscribeTypePackage = "package"
)

// ValidateSubscribeFilename accepts only a single YAML basename. Keeping this
// check in storage makes every caller, including imports and background jobs,
// fail closed before a filename can become a path or encryption scope.
func ValidateSubscribeFilename(filename string) error {
	filename = strings.TrimSpace(filename)
	if filename == "" || filename == "." || filename == ".." || filepath.Base(filename) != filename || strings.ContainsAny(filename, `/\\`) {
		return errors.New("subscribe filename must be a YAML basename")
	}
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".yaml" && ext != ".yml" {
		return errors.New("subscribe filename must end with .yaml or .yml")
	}
	return nil
}

// ensureUniqueSubscribeFilenames diagnoses legacy duplicates before adding the
// unique index. It deliberately refuses migration instead of choosing a row
// and silently disconnecting the other subscription from its file/history.
func (r *TrafficRepository) ensureUniqueSubscribeFilenames() error {
	for _, table := range []string{"subscribe_files", "rule_versions"} {
		rows, err := r.db.Query(`SELECT id, filename FROM ` + table + ` ORDER BY id`)
		if err != nil {
			return fmt.Errorf("validate existing %s filenames: %w", table, err)
		}
		var invalid []string
		for rows.Next() {
			var id int64
			var filename string
			if err := rows.Scan(&id, &filename); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan existing %s filename: %w", table, err)
			}
			if err := ValidateSubscribeFilename(filename); err != nil {
				invalid = append(invalid, fmt.Sprintf("id=%d filename=%q", id, filename))
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("iterate existing %s filenames: %w", table, err)
		}
		_ = rows.Close()
		if len(invalid) > 0 {
			return fmt.Errorf("invalid existing %s filenames block migration: %s", table, strings.Join(invalid, ", "))
		}
	}

	rows, err := r.db.Query(`SELECT filename, GROUP_CONCAT(id), COUNT(*) FROM subscribe_files GROUP BY filename HAVING COUNT(*) > 1 ORDER BY filename`)
	if err != nil {
		return fmt.Errorf("diagnose duplicate subscribe filenames: %w", err)
	}
	defer rows.Close()
	var duplicates []string
	for rows.Next() {
		var filename, ids string
		var count int
		if err := rows.Scan(&filename, &ids, &count); err != nil {
			return fmt.Errorf("scan duplicate subscribe filename: %w", err)
		}
		duplicates = append(duplicates, fmt.Sprintf("%q(ids=%s,count=%d)", filename, ids, count))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate duplicate subscribe filenames: %w", err)
	}
	if len(duplicates) > 0 {
		return fmt.Errorf("duplicate subscribe filenames block migration: %s", strings.Join(duplicates, ", "))
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_subscribe_files_filename_unique ON subscribe_files(filename)`); err != nil {
		return fmt.Errorf("create unique subscribe filename index: %w", err)
	}
	return nil
}

// subscribeFileSelectClause 返回 subscribe_files 的 SELECT 列表,可选用表别名前缀。
// 之前用 const + JOIN 手抄列表的写法存在不一致(GetUserSubscriptions 漏了 selected_custom_rule_ids /
// selected_override_script_ids 两列,scanSubscribeFile 扫描时 destination 数量对不上,直接 500)。
// 单源定义,所有调用方一律走这里 — 列数永远跟 scanSubscribeFile 同步。
func subscribeFileSelectClause(alias string) string {
	pfx := ""
	if alias != "" {
		pfx = alias + "."
	}
	cols := []string{
		pfx + "id", pfx + "name", "COALESCE(" + pfx + "description, '')",
		pfx + "url", pfx + "type", pfx + "filename",
		"COALESCE(" + pfx + "file_short_code, '')",
		"COALESCE(" + pfx + "custom_short_code, '')",
		"COALESCE(" + pfx + "auto_sync_custom_rules, 0)",
		"COALESCE(" + pfx + "template_filename, '')",
		"COALESCE(" + pfx + "selected_tags, '[]')",
		"COALESCE(" + pfx + "selected_node_ids, '[]')",
		"COALESCE(" + pfx + "selected_custom_rule_ids, '[]')",
		"COALESCE(" + pfx + "selected_override_script_ids, '[]')",
		"COALESCE(" + pfx + "stats_server_ids, '')",
		pfx + "traffic_limit",
		"COALESCE(" + pfx + "sort_order, 0)",
		"COALESCE(" + pfx + "raw_output, 0)",
		"COALESCE(" + pfx + "created_by, '')",
		pfx + "created_at", pfx + "updated_at",
	}
	return strings.Join(cols, ", ")
}

// subscribeFileSelectCols 历史 const,所有原本拼字符串的地方继续走它,保持调用点不变。
var subscribeFileSelectCols = subscribeFileSelectClause("")

// marshalIDArray 把 ID 切片序列化为 JSON 数组字符串(nil/空 → "[]")。
func marshalIDArray(ids []int64) string {
	if len(ids) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func scanSubscribeFile(scanner interface{ Scan(dest ...any) error }) (SubscribeFile, error) {
	var file SubscribeFile
	var autoSync, rawOutput int
	var tagsJSON, nodeIDsJSON, customRuleIDsJSON, overrideScriptIDsJSON string
	var trafficLimit sql.NullFloat64
	if err := scanner.Scan(
		&file.ID, &file.Name, &file.Description, &file.URL, &file.Type, &file.Filename,
		&file.FileShortCode, &file.CustomShortCode,
		&autoSync,
		&file.TemplateFilename, &tagsJSON, &nodeIDsJSON,
		&customRuleIDsJSON, &overrideScriptIDsJSON,
		&file.StatsServerIDs, &trafficLimit,
		&file.SortOrder, &rawOutput, &file.CreatedBy,
		&file.CreatedAt, &file.UpdatedAt,
	); err != nil {
		return file, err
	}
	if err := ValidateSubscribeFilename(file.Filename); err != nil {
		return file, fmt.Errorf("invalid stored subscribe filename for id %d: %w", file.ID, err)
	}
	file.AutoSyncCustomRules = autoSync != 0
	file.RawOutput = rawOutput != 0
	if trafficLimit.Valid {
		file.TrafficLimit = &trafficLimit.Float64
	}
	if tagsJSON != "" && tagsJSON != "[]" {
		_ = json.Unmarshal([]byte(tagsJSON), &file.SelectedTags)
	}
	if file.SelectedTags == nil {
		file.SelectedTags = []string{}
	}
	if nodeIDsJSON != "" && nodeIDsJSON != "[]" {
		_ = json.Unmarshal([]byte(nodeIDsJSON), &file.SelectedNodeIDs)
	}
	if file.SelectedNodeIDs == nil {
		file.SelectedNodeIDs = []int64{}
	}
	if customRuleIDsJSON != "" && customRuleIDsJSON != "[]" {
		_ = json.Unmarshal([]byte(customRuleIDsJSON), &file.SelectedCustomRuleIDs)
	}
	if file.SelectedCustomRuleIDs == nil {
		file.SelectedCustomRuleIDs = []int64{}
	}
	if overrideScriptIDsJSON != "" && overrideScriptIDsJSON != "[]" {
		_ = json.Unmarshal([]byte(overrideScriptIDsJSON), &file.SelectedOverrideScriptIDs)
	}
	if file.SelectedOverrideScriptIDs == nil {
		file.SelectedOverrideScriptIDs = []int64{}
	}
	return file, nil
}

func (r *TrafficRepository) ListSubscribeFiles(ctx context.Context) ([]SubscribeFile, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}

	rows, err := r.db.QueryContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files ORDER BY sort_order ASC, created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list subscribe files: %w", err)
	}
	defer rows.Close()

	var files []SubscribeFile
	for rows.Next() {
		file, err := scanSubscribeFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan subscribe file: %w", err)
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscribe files: %w", err)
	}
	return files, nil
}

func (r *TrafficRepository) GetSubscribeFileByID(ctx context.Context, id int64) (SubscribeFile, error) {
	var file SubscribeFile
	if r == nil || r.db == nil {
		return file, errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return file, errors.New("subscribe file id is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE id = ? LIMIT 1`, id)
	file, err := scanSubscribeFile(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return file, ErrSubscribeFileNotFound
		}
		return file, fmt.Errorf("get subscribe file: %w", err)
	}
	return file, nil
}

func (r *TrafficRepository) GetSubscribeFileByName(ctx context.Context, name string) (SubscribeFile, error) {
	var file SubscribeFile
	if r == nil || r.db == nil {
		return file, errors.New("traffic repository not initialized")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return file, errors.New("subscribe file name is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE name = ? LIMIT 1`, name)
	file, err := scanSubscribeFile(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return file, ErrSubscribeFileNotFound
		}
		return file, fmt.Errorf("get subscribe file by name: %w", err)
	}
	return file, nil
}

func (r *TrafficRepository) GetSubscribeFileByFilename(ctx context.Context, filename string) (SubscribeFile, error) {
	var file SubscribeFile
	if r == nil || r.db == nil {
		return file, errors.New("traffic repository not initialized")
	}
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return file, errors.New("subscribe file filename is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE filename = ? LIMIT 1`, filename)
	file, err := scanSubscribeFile(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return file, ErrSubscribeFileNotFound
		}
		return file, fmt.Errorf("get subscribe file by filename: %w", err)
	}
	return file, nil
}

func (r *TrafficRepository) GetSubscribeFileByShortCode(ctx context.Context, code string) (SubscribeFile, error) {
	var file SubscribeFile
	if r == nil || r.db == nil {
		return file, errors.New("traffic repository not initialized")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return file, errors.New("short code is required")
	}

	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE custom_short_code = ? OR file_short_code = ? LIMIT 1`, code, code)
	file, err := scanSubscribeFile(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return file, ErrSubscribeFileNotFound
		}
		return file, fmt.Errorf("get subscribe file by short code: %w", err)
	}
	return file, nil
}

func (r *TrafficRepository) CreateSubscribeFile(ctx context.Context, file SubscribeFile) (SubscribeFile, error) {
	if r == nil || r.db == nil {
		return SubscribeFile{}, errors.New("traffic repository not initialized")
	}

	file.Name = strings.TrimSpace(file.Name)
	file.Description = strings.TrimSpace(file.Description)
	file.URL = strings.TrimSpace(file.URL)
	file.Type = strings.ToLower(strings.TrimSpace(file.Type))
	file.Filename = strings.TrimSpace(file.Filename)

	if file.Name == "" {
		return SubscribeFile{}, errors.New("subscribe file name is required")
	}
	if file.Type != SubscribeTypeCreate && file.Type != SubscribeTypeImport && file.Type != SubscribeTypeUpload && file.Type != SubscribeTypePackage {
		return SubscribeFile{}, errors.New("invalid subscribe file type")
	}
	if file.Type == SubscribeTypeImport && file.URL == "" {
		return SubscribeFile{}, errors.New("subscribe file url is required")
	}
	if file.Filename == "" {
		return SubscribeFile{}, errors.New("subscribe file filename is required")
	}
	if err := ValidateSubscribeFilename(file.Filename); err != nil {
		return SubscribeFile{}, err
	}

	tagsJSON, _ := json.Marshal(file.SelectedTags)
	if file.SelectedTags == nil {
		tagsJSON = []byte("[]")
	}
	nodeIDsJSON := marshalIDArray(file.SelectedNodeIDs)
	customRuleIDsJSON := marshalIDArray(file.SelectedCustomRuleIDs)
	overrideScriptIDsJSON := marshalIDArray(file.SelectedOverrideScriptIDs)

	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		newFileShortCode, err := generateFileShortCode()
		if err != nil {
			return SubscribeFile{}, fmt.Errorf("generate file short code: %w", err)
		}

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return SubscribeFile{}, fmt.Errorf("begin create subscribe file: %w", err)
		}
		var archived int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM rule_versions WHERE filename = ?`, file.Filename).Scan(&archived); err != nil {
			_ = tx.Rollback()
			return SubscribeFile{}, fmt.Errorf("check subscribe filename history: %w", err)
		}
		if archived != 0 {
			_ = tx.Rollback()
			return SubscribeFile{}, ErrSubscribeFilenameHistory
		}

		res, err := tx.ExecContext(ctx, `INSERT INTO subscribe_files
			(name, description, url, type, filename, file_short_code, custom_short_code,
			auto_sync_custom_rules, template_filename, selected_tags, selected_node_ids,
			selected_custom_rule_ids, selected_override_script_ids, stats_server_ids,
			traffic_limit, sort_order, raw_output, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			file.Name, file.Description, file.URL, file.Type, file.Filename, newFileShortCode, file.CustomShortCode,
			file.TemplateFilename, string(tagsJSON), nodeIDsJSON,
			customRuleIDsJSON, overrideScriptIDsJSON, file.StatsServerIDs,
			file.TrafficLimit, file.SortOrder, boolToInt(file.RawOutput), file.CreatedBy)
		if err != nil {
			_ = tx.Rollback()
			if strings.Contains(strings.ToLower(err.Error()), "unique") && strings.Contains(strings.ToLower(err.Error()), "file_short_code") {
				continue
			}
			if strings.Contains(strings.ToLower(err.Error()), "unique") && strings.Contains(strings.ToLower(err.Error()), "custom_short_code") {
				return SubscribeFile{}, ErrCustomShortCodeExists
			}
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return SubscribeFile{}, ErrSubscribeFileExists
			}
			return SubscribeFile{}, fmt.Errorf("create subscribe file: %w", err)
		}

		id, err := res.LastInsertId()
		if err != nil {
			_ = tx.Rollback()
			return SubscribeFile{}, fmt.Errorf("fetch subscribe file id: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return SubscribeFile{}, fmt.Errorf("commit create subscribe file: %w", err)
		}
		return r.GetSubscribeFileByID(ctx, id)
	}
	return SubscribeFile{}, errors.New("failed to generate unique file short code after retries")
}

func (r *TrafficRepository) UpdateSubscribeFile(ctx context.Context, file SubscribeFile) (SubscribeFile, error) {
	if r == nil || r.db == nil {
		return SubscribeFile{}, errors.New("traffic repository not initialized")
	}
	if file.ID <= 0 {
		return SubscribeFile{}, errors.New("subscribe file id is required")
	}

	file.Name = strings.TrimSpace(file.Name)
	file.Description = strings.TrimSpace(file.Description)
	file.URL = strings.TrimSpace(file.URL)
	file.Type = strings.ToLower(strings.TrimSpace(file.Type))
	file.Filename = strings.TrimSpace(file.Filename)

	if file.Name == "" {
		return SubscribeFile{}, errors.New("subscribe file name is required")
	}
	if file.Type != SubscribeTypeCreate && file.Type != SubscribeTypeImport && file.Type != SubscribeTypeUpload && file.Type != SubscribeTypePackage {
		return SubscribeFile{}, errors.New("invalid subscribe file type")
	}
	if file.Type == SubscribeTypeImport && file.URL == "" {
		return SubscribeFile{}, errors.New("subscribe file url is required")
	}
	if file.Filename == "" {
		return SubscribeFile{}, errors.New("subscribe file filename is required")
	}
	if err := ValidateSubscribeFilename(file.Filename); err != nil {
		return SubscribeFile{}, err
	}

	tagsJSON, _ := json.Marshal(file.SelectedTags)
	if file.SelectedTags == nil {
		tagsJSON = []byte("[]")
	}
	nodeIDsJSON := marshalIDArray(file.SelectedNodeIDs)
	customRuleIDsJSON := marshalIDArray(file.SelectedCustomRuleIDs)
	overrideScriptIDsJSON := marshalIDArray(file.SelectedOverrideScriptIDs)

	res, err := r.db.ExecContext(ctx, `UPDATE subscribe_files SET
		name = ?, description = ?, url = ?, type = ?, filename = ?,
		custom_short_code = ?, auto_sync_custom_rules = ?,
		template_filename = ?, selected_tags = ?, selected_node_ids = ?,
		selected_custom_rule_ids = ?, selected_override_script_ids = ?, stats_server_ids = ?,
		traffic_limit = ?, sort_order = ?, raw_output = ?,
		updated_at = CURRENT_TIMESTAMP WHERE id = ? AND filename = ?`,
		file.Name, file.Description, file.URL, file.Type, file.Filename,
		file.CustomShortCode, boolToInt(file.AutoSyncCustomRules),
		file.TemplateFilename, string(tagsJSON), nodeIDsJSON,
		customRuleIDsJSON, overrideScriptIDsJSON, file.StatsServerIDs,
		file.TrafficLimit, file.SortOrder, boolToInt(file.RawOutput),
		file.ID, file.Filename)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") && strings.Contains(strings.ToLower(err.Error()), "custom_short_code") {
			return SubscribeFile{}, ErrCustomShortCodeExists
		}
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return SubscribeFile{}, ErrSubscribeFileExists
		}
		return SubscribeFile{}, fmt.Errorf("update subscribe file: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return SubscribeFile{}, fmt.Errorf("subscribe file update rows affected: %w", err)
	}
	if affected == 0 {
		var exists int
		if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscribe_files WHERE id = ?`, file.ID).Scan(&exists); err != nil {
			return SubscribeFile{}, fmt.Errorf("check subscribe file after fenced update: %w", err)
		}
		if exists == 0 {
			return SubscribeFile{}, ErrSubscribeFileNotFound
		}
		return SubscribeFile{}, ErrSubscribeFileChanged
	}
	return r.GetSubscribeFileByID(ctx, file.ID)
}

// RenameSubscribeFileAndRuleVersions updates the subscription filename and
// every archived rule payload in one transaction. Callers must re-encrypt any
// filename-scoped secret in versions before invoking this method. The exact
// version set is verified inside the transaction so a concurrent history write
// cannot be left under the old filename or old encryption scope.
func (r *TrafficRepository) RenameSubscribeFileAndRuleVersions(ctx context.Context, file SubscribeFile, oldFilename string, versions []RuleVersionContent) (SubscribeFile, error) {
	if r == nil || r.db == nil {
		return SubscribeFile{}, errors.New("traffic repository not initialized")
	}
	if file.ID <= 0 {
		return SubscribeFile{}, errors.New("subscribe file id is required")
	}

	file.Name = strings.TrimSpace(file.Name)
	file.Description = strings.TrimSpace(file.Description)
	file.URL = strings.TrimSpace(file.URL)
	file.Type = strings.ToLower(strings.TrimSpace(file.Type))
	file.Filename = strings.TrimSpace(file.Filename)
	oldFilename = strings.TrimSpace(oldFilename)

	if file.Name == "" {
		return SubscribeFile{}, errors.New("subscribe file name is required")
	}
	if file.Type != SubscribeTypeCreate && file.Type != SubscribeTypeImport && file.Type != SubscribeTypeUpload && file.Type != SubscribeTypePackage {
		return SubscribeFile{}, errors.New("invalid subscribe file type")
	}
	if file.Type == SubscribeTypeImport && file.URL == "" {
		return SubscribeFile{}, errors.New("subscribe file url is required")
	}
	if oldFilename == "" || file.Filename == "" || oldFilename == file.Filename {
		return SubscribeFile{}, errors.New("distinct old and new subscribe filenames are required")
	}
	if err := ValidateSubscribeFilename(oldFilename); err != nil {
		return SubscribeFile{}, fmt.Errorf("invalid old subscribe filename: %w", err)
	}
	if err := ValidateSubscribeFilename(file.Filename); err != nil {
		return SubscribeFile{}, fmt.Errorf("invalid new subscribe filename: %w", err)
	}

	tagsJSON, _ := json.Marshal(file.SelectedTags)
	if file.SelectedTags == nil {
		tagsJSON = []byte("[]")
	}
	nodeIDsJSON := marshalIDArray(file.SelectedNodeIDs)
	customRuleIDsJSON := marshalIDArray(file.SelectedCustomRuleIDs)
	overrideScriptIDsJSON := marshalIDArray(file.SelectedOverrideScriptIDs)

	versionByID := make(map[int64]RuleVersionContent, len(versions))
	for _, version := range versions {
		if version.ID <= 0 || strings.TrimSpace(version.Filename) != oldFilename {
			return SubscribeFile{}, errors.New("invalid rule version rename plan")
		}
		if _, exists := versionByID[version.ID]; exists {
			return SubscribeFile{}, errors.New("duplicate rule version rename plan")
		}
		versionByID[version.ID] = version
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return SubscribeFile{}, fmt.Errorf("begin subscribe file rename: %w", err)
	}
	defer tx.Rollback()

	var storedFilename string
	if err := tx.QueryRowContext(ctx, `SELECT filename FROM subscribe_files WHERE id = ?`, file.ID).Scan(&storedFilename); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SubscribeFile{}, ErrSubscribeFileNotFound
		}
		return SubscribeFile{}, fmt.Errorf("verify subscribe file rename source: %w", err)
	}
	if storedFilename != oldFilename {
		return SubscribeFile{}, ErrSubscribeFileChanged
	}

	var storedVersionCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM rule_versions WHERE filename = ?`, oldFilename).Scan(&storedVersionCount); err != nil {
		return SubscribeFile{}, fmt.Errorf("count subscribe rule versions before rename: %w", err)
	}
	if storedVersionCount != len(versionByID) {
		return SubscribeFile{}, errors.New("subscribe rule versions changed during rename")
	}
	var targetVersionCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM rule_versions WHERE filename = ?`, file.Filename).Scan(&targetVersionCount); err != nil {
		return SubscribeFile{}, fmt.Errorf("count target subscribe rule versions before rename: %w", err)
	}
	if targetVersionCount != 0 {
		return SubscribeFile{}, ErrSubscribeFilenameHistory
	}
	var targetLinkCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscription_links WHERE rule_filename = ?`, file.Filename).Scan(&targetLinkCount); err != nil {
		return SubscribeFile{}, fmt.Errorf("count target subscription links before rename: %w", err)
	}
	if targetLinkCount != 0 {
		return SubscribeFile{}, ErrSubscribeFileExists
	}

	res, err := tx.ExecContext(ctx, `UPDATE subscribe_files SET
		name = ?, description = ?, url = ?, type = ?, filename = ?,
		custom_short_code = ?, auto_sync_custom_rules = ?,
		template_filename = ?, selected_tags = ?, selected_node_ids = ?,
		selected_custom_rule_ids = ?, selected_override_script_ids = ?, stats_server_ids = ?,
		traffic_limit = ?, sort_order = ?, raw_output = ?,
		updated_at = CURRENT_TIMESTAMP WHERE id = ? AND filename = ?`,
		file.Name, file.Description, file.URL, file.Type, file.Filename,
		file.CustomShortCode, boolToInt(file.AutoSyncCustomRules),
		file.TemplateFilename, string(tagsJSON), nodeIDsJSON,
		customRuleIDsJSON, overrideScriptIDsJSON, file.StatsServerIDs,
		file.TrafficLimit, file.SortOrder, boolToInt(file.RawOutput),
		file.ID, oldFilename)
	if err != nil {
		lowerMessage := strings.ToLower(err.Error())
		if strings.Contains(lowerMessage, "unique") && strings.Contains(lowerMessage, "custom_short_code") {
			return SubscribeFile{}, ErrCustomShortCodeExists
		}
		if strings.Contains(lowerMessage, "unique") {
			return SubscribeFile{}, ErrSubscribeFileExists
		}
		return SubscribeFile{}, fmt.Errorf("rename subscribe file: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return SubscribeFile{}, fmt.Errorf("subscribe file rename rows affected: %w", err)
	}
	if affected != 1 {
		return SubscribeFile{}, ErrSubscribeFileNotFound
	}

	for _, version := range versions {
		res, err := tx.ExecContext(ctx, `UPDATE rule_versions SET filename = ?, content = ? WHERE id = ? AND filename = ?`,
			file.Filename, version.Content, version.ID, oldFilename)
		if err != nil {
			return SubscribeFile{}, fmt.Errorf("rename rule version %d: %w", version.ID, err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return SubscribeFile{}, fmt.Errorf("verify renamed rule version %d: %w", version.ID, err)
		}
		if affected != 1 {
			return SubscribeFile{}, errors.New("subscribe rule versions changed during rename")
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE subscription_links SET rule_filename = ?, updated_at = CURRENT_TIMESTAMP WHERE rule_filename = ?`, file.Filename, oldFilename); err != nil {
		return SubscribeFile{}, fmt.Errorf("rename linked subscription rules: %w", err)
	}

	updated, err := scanSubscribeFile(tx.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+` FROM subscribe_files WHERE id = ? LIMIT 1`, file.ID))
	if err != nil {
		return SubscribeFile{}, fmt.Errorf("read renamed subscribe file: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SubscribeFile{}, fmt.Errorf("commit subscribe file rename: %w", err)
	}
	return updated, nil
}

func (r *TrafficRepository) DeleteSubscribeFile(ctx context.Context, id int64, expectedFilename string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return errors.New("subscribe file id is required")
	}
	expectedFilename = strings.TrimSpace(expectedFilename)
	if err := ValidateSubscribeFilename(expectedFilename); err != nil {
		return err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	var filename string
	if err := tx.QueryRowContext(ctx, `SELECT filename FROM subscribe_files WHERE id = ?`, id).Scan(&filename); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSubscribeFileNotFound
		}
		return fmt.Errorf("read subscribe filename before delete: %w", err)
	}
	if filename != expectedFilename {
		return ErrSubscribeFileChanged
	}
	var activeLinks int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscription_links WHERE rule_filename = ?`, expectedFilename).Scan(&activeLinks); err != nil {
		return fmt.Errorf("count active subscription links before delete: %w", err)
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM user_subscriptions WHERE subscription_id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user subscriptions: %w", err)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM subscribe_files WHERE id = ? AND filename = ?`, id, expectedFilename)
	if err != nil {
		return fmt.Errorf("delete subscribe file: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("subscribe file delete rows affected: %w", err)
	}
	if affected == 0 {
		return ErrSubscribeFileChanged
	}
	if activeLinks == 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM rule_versions WHERE filename = ?`, expectedFilename); err != nil {
			return fmt.Errorf("delete subscribe rule versions: %w", err)
		}
	}
	return tx.Commit()
}

func (r *TrafficRepository) ReorderSubscribeFiles(ctx context.Context, ids []int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	for i, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE subscribe_files SET sort_order = ? WHERE id = ?`, i, id); err != nil {
			return fmt.Errorf("update sort order: %w", err)
		}
	}
	return tx.Commit()
}

func (r *TrafficRepository) GetUserPackageSubscription(ctx context.Context, username string) (SubscribeFile, error) {
	var file SubscribeFile
	row := r.db.QueryRowContext(ctx, `SELECT `+subscribeFileSelectCols+`
		FROM subscribe_files sf
		INNER JOIN user_subscriptions us ON sf.id = us.subscription_id
		WHERE us.username = ? AND sf.type = ?
		LIMIT 1`, username, SubscribeTypePackage)
	file, err := scanSubscribeFile(row)
	if err != nil {
		return file, err
	}
	return file, nil
}
