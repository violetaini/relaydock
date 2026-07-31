package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// snapshot status
const (
	XraySnapshotStatusCurrent         = "current"
	XraySnapshotStatusOld             = "old"
	XraySnapshotStatusPendingRecovery = "pending_recovery"
)

// snapshot source
const (
	XraySnapshotSourceAgentReport  = "agent_report"
	XraySnapshotSourceMasterWrite  = "master_write"
	XraySnapshotSourceManualAccept = "manual_accept"
)

type ServerXrayConfigSnapshot struct {
	ID         int64     `json:"id"`
	ServerID   int64     `json:"server_id"`
	ConfigJSON string    `json:"config_json"`
	ConfigHash string    `json:"config_hash"`
	Source     string    `json:"source"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

// beginImmediateTransaction reserves SQLite's single writer before a read/write
// sequence. A deferred transaction can let two writers read the same state and
// then race while upgrading their read locks.
func (r *TrafficRepository) beginImmediateTransaction(ctx context.Context) (*sql.Conn, error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire immediate transaction connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("begin immediate transaction: %w", err)
	}
	return conn, nil
}

func finishImmediateTransaction(ctx context.Context, conn *sql.Conn, commit bool) error {
	if conn == nil {
		return nil
	}
	statement := `ROLLBACK`
	if commit {
		statement = `COMMIT`
	}
	_, err := conn.ExecContext(ctx, statement)
	if err != nil && commit {
		// A canceled request can make COMMIT fail after the writes have run. Roll
		// back before returning this manually managed connection to database/sql;
		// otherwise the next borrower could inherit an open transaction and its
		// writer lock.
		_, rollbackErr := conn.ExecContext(context.Background(), `ROLLBACK`)
		err = errors.Join(err, rollbackErr)
	}
	closeErr := conn.Close()
	return errors.Join(err, closeErr)
}

// HashXrayConfig 对 config 文本做 sha256,大小写敏感、不规范化。
// 调用方如果想跨格式差异(如 indent / trailing newline)对比,自己规范化后再 hash。
func HashXrayConfig(config string) string {
	sum := sha256.Sum256([]byte(config))
	return hex.EncodeToString(sum[:])
}

// GetCurrentXraySnapshot 返回 server 当前 current snapshot,无则 nil。
func (r *TrafficRepository) GetCurrentXraySnapshot(ctx context.Context, serverID int64) (*ServerXrayConfigSnapshot, error) {
	return r.getXraySnapshotByStatus(ctx, serverID, XraySnapshotStatusCurrent)
}

// GetPendingXrayRecovery 返回 server pending_recovery snapshot,无则 nil。
func (r *TrafficRepository) GetPendingXrayRecovery(ctx context.Context, serverID int64) (*ServerXrayConfigSnapshot, error) {
	return r.getXraySnapshotByStatus(ctx, serverID, XraySnapshotStatusPendingRecovery)
}

func (r *TrafficRepository) getXraySnapshotByStatus(ctx context.Context, serverID int64, status string) (*ServerXrayConfigSnapshot, error) {
	var s ServerXrayConfigSnapshot
	err := r.db.QueryRowContext(ctx,
		`SELECT id, server_id, config_json, config_hash, source, status, created_at
		 FROM server_xray_config_snapshots
		 WHERE server_id = ? AND status = ?
		 ORDER BY created_at DESC LIMIT 1`,
		serverID, status,
	).Scan(&s.ID, &s.ServerID, &s.ConfigJSON, &s.ConfigHash, &s.Source, &s.Status, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query xray snapshot: %w", err)
	}
	return &s, nil
}

// GetXraySnapshotByID 按 id 获取单条 snapshot(用于历史恢复时调用方校验 server_id)。
func (r *TrafficRepository) GetXraySnapshotByID(ctx context.Context, id int64) (*ServerXrayConfigSnapshot, error) {
	var s ServerXrayConfigSnapshot
	err := r.db.QueryRowContext(ctx,
		`SELECT id, server_id, config_json, config_hash, source, status, created_at
		 FROM server_xray_config_snapshots WHERE id = ? LIMIT 1`,
		id,
	).Scan(&s.ID, &s.ServerID, &s.ConfigJSON, &s.ConfigHash, &s.Source, &s.Status, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query xray snapshot by id: %w", err)
	}
	return &s, nil
}

// UpsertCurrentXraySnapshot 是 master 主动写 / agent 修复重连场景的统一入口:
//   - 已有 current 且 hash 一致 → 不动 DB,返回现有行
//   - 已有 current 但 hash 不同 → 现行 current 改为 old + 新增 current(线性版本链)
//   - 无 current → 直接插入新 current
//
// 不会动 pending_recovery 行(那是另一个状态,由 WritePendingRecovery / AcceptPending 管)。
func (r *TrafficRepository) UpsertCurrentXraySnapshot(ctx context.Context, serverID int64, configJSON, source string) (*ServerXrayConfigSnapshot, error) {
	hash := HashXrayConfig(configJSON)

	conn, err := r.beginImmediateTransaction(ctx)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = finishImmediateTransaction(context.Background(), conn, false)
		}
	}()

	// 查现行 current
	var curID int64
	var curHash string
	err = conn.QueryRowContext(ctx,
		`SELECT id, config_hash FROM server_xray_config_snapshots
		 WHERE server_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1`,
		serverID, XraySnapshotStatusCurrent,
	).Scan(&curID, &curHash)
	hasCur := !errors.Is(err, sql.ErrNoRows)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("query current: %w", err)
	}

	if hasCur && curHash == hash {
		// 无需变更,直接返回现行 current
		if err := finishImmediateTransaction(ctx, conn, true); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}
		committed = true
		return r.GetCurrentXraySnapshot(ctx, serverID)
	}

	// 旧 current 置 old
	if hasCur {
		if _, err := conn.ExecContext(ctx,
			`UPDATE server_xray_config_snapshots SET status = ? WHERE id = ?`,
			XraySnapshotStatusOld, curID,
		); err != nil {
			return nil, fmt.Errorf("mark old: %w", err)
		}
	}

	// 新 current
	res, err := conn.ExecContext(ctx,
		`INSERT INTO server_xray_config_snapshots (server_id, config_json, config_hash, source, status)
		 VALUES (?, ?, ?, ?, ?)`,
		serverID, configJSON, hash, source, XraySnapshotStatusCurrent,
	)
	if err != nil {
		return nil, fmt.Errorf("insert current: %w", err)
	}
	id, _ := res.LastInsertId()

	if err := finishImmediateTransaction(ctx, conn, true); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	committed = true
	return &ServerXrayConfigSnapshot{
		ID: id, ServerID: serverID, ConfigJSON: configJSON, ConfigHash: hash,
		Source: source, Status: XraySnapshotStatusCurrent,
	}, nil
}

// WritePendingXrayRecovery 把 agent 在 server status=offline 后重连上报的配置存为 pending_recovery,
// 不动 current。同 server 已有 pending_recovery → 先删再插(永远只留最新一份待恢复)。
// 返回 true 表示真的写入了一行(hash 与 current 不同);false 表示 hash 与 current 一致,无需 pending。
func (r *TrafficRepository) WritePendingXrayRecovery(ctx context.Context, serverID int64, configJSON, source string) (bool, error) {
	hash := HashXrayConfig(configJSON)

	conn, err := r.beginImmediateTransaction(ctx)
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = finishImmediateTransaction(context.Background(), conn, false)
		}
	}()

	// 若与 current hash 一致 — 上报配置就是主控记的那一份,无需 pending(也无需告警)
	var curHash string
	err = conn.QueryRowContext(ctx,
		`SELECT config_hash FROM server_xray_config_snapshots
		 WHERE server_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1`,
		serverID, XraySnapshotStatusCurrent,
	).Scan(&curHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("query current: %w", err)
	}
	if curHash == hash && curHash != "" {
		if err := finishImmediateTransaction(ctx, conn, true); err != nil {
			return false, fmt.Errorf("commit: %w", err)
		}
		committed = true
		return false, nil
	}

	// 删除旧 pending
	if _, err := conn.ExecContext(ctx,
		`DELETE FROM server_xray_config_snapshots WHERE server_id = ? AND status = ?`,
		serverID, XraySnapshotStatusPendingRecovery,
	); err != nil {
		return false, fmt.Errorf("clear pending: %w", err)
	}

	// 插新 pending
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO server_xray_config_snapshots (server_id, config_json, config_hash, source, status)
		 VALUES (?, ?, ?, ?, ?)`,
		serverID, configJSON, hash, source, XraySnapshotStatusPendingRecovery,
	); err != nil {
		return false, fmt.Errorf("insert pending: %w", err)
	}

	if err := finishImmediateTransaction(ctx, conn, true); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	committed = true
	return true, nil
}

// DiscardPendingXrayRecovery 用户在 UI 上选了"恢复主控配置"或者主控成功 PUT 完成 → 丢弃 pending 行。
func (r *TrafficRepository) DiscardPendingXrayRecovery(ctx context.Context, serverID int64) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM server_xray_config_snapshots WHERE server_id = ? AND status = ?`,
		serverID, XraySnapshotStatusPendingRecovery,
	)
	if err != nil {
		return fmt.Errorf("discard pending: %w", err)
	}
	return nil
}

// AcceptPendingXrayRecovery 用户选了"接受 agent 当前配置": 旧 current 置 old,pending → current。
// 同一事务里完成,失败回滚,pending 与 current 都不动。
func (r *TrafficRepository) AcceptPendingXrayRecovery(ctx context.Context, serverID int64) error {
	conn, err := r.beginImmediateTransaction(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = finishImmediateTransaction(context.Background(), conn, false)
		}
	}()

	var pendingID int64
	err = conn.QueryRowContext(ctx,
		`SELECT id FROM server_xray_config_snapshots
		 WHERE server_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1`,
		serverID, XraySnapshotStatusPendingRecovery,
	).Scan(&pendingID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("no pending recovery for server %d", serverID)
	}
	if err != nil {
		return fmt.Errorf("query pending: %w", err)
	}

	// 旧 current → old
	if _, err := conn.ExecContext(ctx,
		`UPDATE server_xray_config_snapshots SET status = ?
		 WHERE server_id = ? AND status = ?`,
		XraySnapshotStatusOld, serverID, XraySnapshotStatusCurrent,
	); err != nil {
		return fmt.Errorf("mark old: %w", err)
	}

	// pending → current,同时把 source 标记为 manual_accept
	if _, err := conn.ExecContext(ctx,
		`UPDATE server_xray_config_snapshots SET status = ?, source = ? WHERE id = ?`,
		XraySnapshotStatusCurrent, XraySnapshotSourceManualAccept, pendingID,
	); err != nil {
		return fmt.Errorf("promote pending: %w", err)
	}

	if err := finishImmediateTransaction(ctx, conn, true); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

// ListXraySnapshots 返回某 server 全部 snapshot(current + old + pending),按 created_at DESC。
// limit=0 表示不限。前端历史配置 dialog 一次拉全;limit 留给将来分页用。
func (r *TrafficRepository) ListXraySnapshots(ctx context.Context, serverID int64, limit int) ([]ServerXrayConfigSnapshot, error) {
	query := `SELECT id, server_id, config_json, config_hash, source, status, created_at
	          FROM server_xray_config_snapshots
	          WHERE server_id = ?
	          ORDER BY created_at DESC`
	args := []interface{}{serverID}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query snapshots: %w", err)
	}
	defer rows.Close()
	var out []ServerXrayConfigSnapshot
	for rows.Next() {
		var s ServerXrayConfigSnapshot
		if err := rows.Scan(&s.ID, &s.ServerID, &s.ConfigJSON, &s.ConfigHash, &s.Source, &s.Status, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// deprecatedRoutingMarktags — 已废弃需要从 snapshot 中清理的路由规则 marktag 白名单。
// 跟 agent 端 removeDeprecatedRoutingRules 的 deprecated map 保持一致。
var deprecatedRoutingMarktags = map[string]bool{
	"fix_openai": true, // relaydock-agent 8a9f8c9 移除,geosite:openai → direct
}

// MigrateRemoveDeprecatedRulesFromSnapshots 一次性扫 server_xray_config_snapshots,
// 把 status IN ('current', 'pending_recovery') 行的 config_json 解析后,
// 删除 marktag 在 deprecatedRoutingMarktags 里的 routing.rules,重新 marshal + 重算 hash 写回。
// 配合 agent 端 removeDeprecatedRoutingRules — agent 重启上报新 config 时,
// 这里 current 的 hash 已经是同款清理后的版本,hash 对齐 → 不触发 WritePendingXrayRecovery。
//
// 幂等:再次执行扫描时,所有 current 都已无 deprecated marktag → kept 数等于原数 → 跳过 update。
func (r *TrafficRepository) MigrateRemoveDeprecatedRulesFromSnapshots(ctx context.Context) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, server_id, config_json FROM server_xray_config_snapshots WHERE status IN (?, ?)`,
		XraySnapshotStatusCurrent, XraySnapshotStatusPendingRecovery)
	if err != nil {
		return fmt.Errorf("query snapshots: %w", err)
	}
	type todoItem struct {
		id         int64
		serverID   int64
		configJSON string
	}
	var todos []todoItem
	for rows.Next() {
		var it todoItem
		if err := rows.Scan(&it.id, &it.serverID, &it.configJSON); err != nil {
			rows.Close()
			return fmt.Errorf("scan: %w", err)
		}
		todos = append(todos, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	cleaned := 0
	for _, it := range todos {
		newJSON, removed, err := stripDeprecatedRoutingRules(it.configJSON)
		if err != nil {
			// 单个 snapshot 解析失败不阻塞整体 migration,只记日志后继续
			fmt.Printf("[Migrate] snapshot id=%d server=%d strip failed: %v\n", it.id, it.serverID, err)
			continue
		}
		if removed == 0 {
			continue
		}
		newHash := HashXrayConfig(newJSON)
		if _, err := r.db.ExecContext(ctx,
			`UPDATE server_xray_config_snapshots SET config_json = ?, config_hash = ? WHERE id = ?`,
			newJSON, newHash, it.id); err != nil {
			fmt.Printf("[Migrate] snapshot id=%d update failed: %v\n", it.id, err)
			continue
		}
		cleaned++
	}
	if cleaned > 0 {
		fmt.Printf("[Migrate] removed deprecated routing rules from %d xray snapshot(s)\n", cleaned)
	}

	// 加分项:扫一遍所有 server,如果同一 server 的 pending_recovery 跟 current 的 hash 现在相等了
	// (都被清理成同款),pending 已经没意义 → 直接删掉,避免 UI "待恢复"banner 残留。
	dupRows, err := r.db.QueryContext(ctx, `
		SELECT p.id
		  FROM server_xray_config_snapshots p
		  JOIN server_xray_config_snapshots c
		    ON c.server_id = p.server_id AND c.status = ? AND c.config_hash = p.config_hash
		 WHERE p.status = ?`,
		XraySnapshotStatusCurrent, XraySnapshotStatusPendingRecovery)
	if err != nil {
		return fmt.Errorf("query equal-hash pending: %w", err)
	}
	defer dupRows.Close()
	var dupIDs []int64
	for dupRows.Next() {
		var id int64
		if err := dupRows.Scan(&id); err != nil {
			return fmt.Errorf("scan dup id: %w", err)
		}
		dupIDs = append(dupIDs, id)
	}
	if err := dupRows.Err(); err != nil {
		return err
	}
	for _, id := range dupIDs {
		if _, err := r.db.ExecContext(ctx, `DELETE FROM server_xray_config_snapshots WHERE id = ?`, id); err != nil {
			fmt.Printf("[Migrate] delete equal-hash pending id=%d failed: %v\n", id, err)
		}
	}
	if len(dupIDs) > 0 {
		fmt.Printf("[Migrate] dropped %d redundant pending_recovery (hash matches current after cleanup)\n", len(dupIDs))
	}
	return nil
}

// stripDeprecatedRoutingRules 解析 config JSON,移除 routing.rules 中所有 marktag 在白名单里的项,
// 返回新 JSON(2 空格缩进,跟 agent 端 MarshalIndent 一致)+ 被移除条数 + 错误。
// 0 条移除时返回原 JSON 不变,调用方据此决定是否 update。
func stripDeprecatedRoutingRules(configJSON string) (string, int, error) {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return configJSON, 0, fmt.Errorf("unmarshal: %w", err)
	}
	routing, _ := cfg["routing"].(map[string]interface{})
	if routing == nil {
		return configJSON, 0, nil
	}
	rules, _ := routing["rules"].([]interface{})
	if len(rules) == 0 {
		return configJSON, 0, nil
	}
	kept := make([]interface{}, 0, len(rules))
	removed := 0
	for _, r := range rules {
		rule, _ := r.(map[string]interface{})
		if rule != nil {
			if tag, _ := rule["marktag"].(string); deprecatedRoutingMarktags[tag] {
				removed++
				continue
			}
		}
		kept = append(kept, r)
	}
	if removed == 0 {
		return configJSON, 0, nil
	}
	routing["rules"] = kept
	newJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return configJSON, 0, fmt.Errorf("marshal: %w", err)
	}
	return string(newJSON), removed, nil
}
