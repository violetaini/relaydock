package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	LineSpeedTargetMaster = "master"
	LineSpeedTargetRemote = "remote"

	LineSpeedStatusRunning = "running"
	LineSpeedStatusOK      = "ok"
	LineSpeedStatusFailed  = "failed"
)

var (
	ErrLineSpeedTestNotFound   = errors.New("线路测速任务不存在")
	ErrLineSpeedTestNotRunning = errors.New("线路测速任务已结束")
)

type LineSpeedTestResult struct {
	ID                int64      `json:"id"`
	TargetKind        string     `json:"target_kind"`
	ServerID          int64      `json:"server_id"`
	ServerName        string     `json:"server_name"`
	Status            string     `json:"status"`
	Error             string     `json:"error,omitempty"`
	PingMS            float64    `json:"ping_ms"`
	DownloadMbps      float64    `json:"download_mbps"`
	UploadMbps        float64    `json:"upload_mbps"`
	JitterMS          *float64   `json:"jitter_ms,omitempty"`
	PacketLossPercent *float64   `json:"packet_loss_percent,omitempty"`
	ISP               string     `json:"isp"`
	EgressIP          string     `json:"egress_ip"`
	TestServer        string     `json:"test_server"`
	ServerLocation    string     `json:"server_location"`
	Implementation    string     `json:"implementation"`
	CreatedAt         time.Time  `json:"created_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
}

func (r *TrafficRepository) InsertLineSpeedTestResult(ctx context.Context, result LineSpeedTestResult) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	if err := validateLineSpeedTarget(result.TargetKind, result.ServerID); err != nil {
		return 0, err
	}
	status := result.Status
	if status == "" {
		status = LineSpeedStatusRunning
	}
	if status != LineSpeedStatusRunning && status != LineSpeedStatusOK && status != LineSpeedStatusFailed {
		return 0, fmt.Errorf("invalid line speedtest status %q", status)
	}
	res, err := r.db.ExecContext(ctx, `INSERT INTO line_speedtest_results (
		target_kind, server_id, server_name, status, error,
		ping_ms, download_mbps, upload_mbps, jitter_ms, packet_loss_percent,
		isp, egress_ip, test_server, server_location, implementation, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.TargetKind, result.ServerID, result.ServerName, status, result.Error,
		result.PingMS, result.DownloadMbps, result.UploadMbps, result.JitterMS, result.PacketLossPercent,
		result.ISP, result.EgressIP, result.TestServer, result.ServerLocation, result.Implementation, result.CompletedAt)
	if err != nil {
		return 0, fmt.Errorf("insert line speedtest result: %w", err)
	}
	return res.LastInsertId()
}

func (r *TrafficRepository) GetLineSpeedTestResult(ctx context.Context, id int64) (LineSpeedTestResult, error) {
	if r == nil || r.db == nil {
		return LineSpeedTestResult{}, errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return LineSpeedTestResult{}, ErrLineSpeedTestNotFound
	}
	result, err := scanLineSpeedTestResult(r.db.QueryRowContext(ctx, lineSpeedTestSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return LineSpeedTestResult{}, ErrLineSpeedTestNotFound
	}
	if err != nil {
		return LineSpeedTestResult{}, fmt.Errorf("get line speedtest result: %w", err)
	}
	return result, nil
}

func (r *TrafficRepository) ListLineSpeedTestResults(ctx context.Context, targetKind string, serverID int64, limit int) ([]LineSpeedTestResult, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := lineSpeedTestSelect
	args := make([]any, 0, 3)
	if targetKind != "" {
		if err := validateLineSpeedTarget(targetKind, serverID); err != nil {
			return nil, err
		}
		query += ` WHERE target_kind = ? AND server_id = ?`
		args = append(args, targetKind, serverID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list line speedtest results: %w", err)
	}
	defer rows.Close()
	results := make([]LineSpeedTestResult, 0)
	for rows.Next() {
		result, scanErr := scanLineSpeedTestResult(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan line speedtest result: %w", scanErr)
		}
		results = append(results, result)
	}
	return results, rows.Err()
}

// ListLatestSuccessfulLineSpeedTestResults returns at most one successful result
// for each master/remote target. Failed attempts must not erase the last useful
// metrics shown in the target list.
func (r *TrafficRepository) ListLatestSuccessfulLineSpeedTestResults(ctx context.Context) ([]LineSpeedTestResult, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, lineSpeedTestSelect+` WHERE status = 'ok' AND id IN (
		SELECT MAX(id) FROM line_speedtest_results
		WHERE status = 'ok'
		GROUP BY target_kind, server_id
	) ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list latest line speedtest results: %w", err)
	}
	defer rows.Close()
	results := make([]LineSpeedTestResult, 0)
	for rows.Next() {
		result, scanErr := scanLineSpeedTestResult(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan latest line speedtest result: %w", scanErr)
		}
		results = append(results, result)
	}
	return results, rows.Err()
}

// ListLatestLineSpeedTestJobs returns the newest job for every target,
// including failures and in-progress jobs used to restore UI state.
func (r *TrafficRepository) ListLatestLineSpeedTestJobs(ctx context.Context) ([]LineSpeedTestResult, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, lineSpeedTestSelect+` WHERE id IN (
		SELECT MAX(id) FROM line_speedtest_results
		GROUP BY target_kind, server_id
	) ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list latest line speedtest jobs: %w", err)
	}
	defer rows.Close()
	results := make([]LineSpeedTestResult, 0)
	for rows.Next() {
		result, scanErr := scanLineSpeedTestResult(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan latest line speedtest job: %w", scanErr)
		}
		results = append(results, result)
	}
	return results, rows.Err()
}

func (r *TrafficRepository) CompleteLineSpeedTestResult(ctx context.Context, id int64, metrics LineSpeedTestResult) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE line_speedtest_results SET
		status = 'ok', error = '', ping_ms = ?, download_mbps = ?, upload_mbps = ?,
		jitter_ms = ?, packet_loss_percent = ?, isp = ?, egress_ip = ?, test_server = ?,
		server_location = ?, implementation = ?, completed_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'running'`,
		metrics.PingMS, metrics.DownloadMbps, metrics.UploadMbps,
		metrics.JitterMS, metrics.PacketLossPercent, metrics.ISP, metrics.EgressIP,
		metrics.TestServer, metrics.ServerLocation, metrics.Implementation, id)
	if err != nil {
		return fmt.Errorf("complete line speedtest result: %w", err)
	}
	return requireLineSpeedUpdate(res)
}

func (r *TrafficRepository) FailLineSpeedTestResult(ctx context.Context, id int64, message string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE line_speedtest_results
		SET status = 'failed', error = ?, completed_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status = 'running'`, message, id)
	if err != nil {
		return fmt.Errorf("fail line speedtest result: %w", err)
	}
	return requireLineSpeedUpdate(res)
}

func (r *TrafficRepository) DeleteLineSpeedTestResult(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM line_speedtest_results WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete line speedtest result: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrLineSpeedTestNotFound
	}
	return nil
}

const lineSpeedTestSelect = `SELECT id, target_kind, server_id, server_name, status, error,
	ping_ms, download_mbps, upload_mbps, jitter_ms, packet_loss_percent,
	isp, egress_ip, test_server, server_location, implementation, created_at, completed_at
	FROM line_speedtest_results`

func scanLineSpeedTestResult(scanner rowScanner) (LineSpeedTestResult, error) {
	var (
		result             LineSpeedTestResult
		jitter, packetLoss sql.NullFloat64
		completedAt        sql.NullString
	)
	if err := scanner.Scan(
		&result.ID, &result.TargetKind, &result.ServerID, &result.ServerName, &result.Status, &result.Error,
		&result.PingMS, &result.DownloadMbps, &result.UploadMbps, &jitter, &packetLoss,
		&result.ISP, &result.EgressIP, &result.TestServer, &result.ServerLocation, &result.Implementation,
		&result.CreatedAt, &completedAt,
	); err != nil {
		return LineSpeedTestResult{}, err
	}
	if jitter.Valid {
		value := jitter.Float64
		result.JitterMS = &value
	}
	if packetLoss.Valid {
		value := packetLoss.Float64
		result.PacketLossPercent = &value
	}
	result.CompletedAt = parseNullTimeString(completedAt)
	return result, nil
}

func validateLineSpeedTarget(kind string, serverID int64) error {
	switch kind {
	case LineSpeedTargetMaster:
		if serverID != 0 {
			return errors.New("master line speedtest target must use server_id=0")
		}
	case LineSpeedTargetRemote:
		if serverID <= 0 {
			return errors.New("remote line speedtest target requires server_id")
		}
	default:
		return fmt.Errorf("invalid line speedtest target kind %q", kind)
	}
	return nil
}

func requireLineSpeedUpdate(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrLineSpeedTestNotRunning
	}
	return nil
}
