package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	RemoteServerDeletionPending          = "pending"
	RemoteServerDeletionDispatched       = "dispatched"
	RemoteServerDeletionAgentUninstalled = "agent_uninstalled"
	RemoteServerDeletionFailed           = "failed"
)

var (
	ErrRemoteServerDeletionTaskNotFound = errors.New("remote server deletion task not found")
	ErrRemoteServerDeletionTokenInvalid = errors.New("remote server deletion callback token is invalid")
	ErrRemoteServerDeletionTokenExpired = errors.New("remote server deletion callback token has expired")
	ErrRemoteServerDeletionCallbackUsed = errors.New("remote server deletion callback was already consumed")
	ErrRemoteServerDeletionCleanupID    = errors.New("remote server deletion cleanup id does not match")
)

const remoteServerDeletionSchema = `
CREATE TABLE IF NOT EXISTS remote_server_deletion_tasks (
    server_id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    cleanup_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('pending', 'dispatched', 'agent_uninstalled', 'failed')),
    callback_consumed INTEGER NOT NULL DEFAULT 0 CHECK(callback_consumed IN (0, 1)),
    expires_at TIMESTAMP NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    callback_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_remote_server_deletion_token
    ON remote_server_deletion_tasks(token_hash);
CREATE INDEX IF NOT EXISTS idx_remote_server_deletion_status
    ON remote_server_deletion_tasks(status, updated_at);
`

type RemoteServerDeletionTask struct {
	ServerID         int64      `json:"server_id"`
	TokenHash        string     `json:"-"`
	CleanupID        string     `json:"-"`
	Status           string     `json:"status"`
	CallbackConsumed bool       `json:"-"`
	ExpiresAt        time.Time  `json:"expires_at"`
	LastError        string     `json:"last_error,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	CallbackAt       *time.Time `json:"callback_at,omitempty"`
}

type RemoteServerDeleteCounts struct {
	Nodes                         int64 `json:"nodes"`
	NodeSpeedtestResults          int64 `json:"node_speedtest_results"`
	Subaccounts                   int64 `json:"subaccounts"`
	InboundConfigs                int64 `json:"inbound_configs"`
	Outbounds                     int64 `json:"outbounds"`
	XraySnapshots                 int64 `json:"xray_snapshots"`
	BatchInbounds                 int64 `json:"batch_inbounds"`
	BatchOutbounds                int64 `json:"batch_outbounds"`
	NodeTraffic                   int64 `json:"node_traffic"`
	UserTraffic                   int64 `json:"user_traffic"`
	UserEmailTraffic              int64 `json:"user_email_traffic"`
	TrafficSnapshots              int64 `json:"traffic_snapshots"`
	NodeTrafficSnapshots          int64 `json:"node_traffic_snapshots"`
	UserTrafficSnapshots          int64 `json:"user_traffic_snapshots"`
	UserEmailTrafficSnapshots     int64 `json:"user_email_traffic_snapshots"`
	SystemTrafficSnapshots        int64 `json:"system_traffic_snapshots"`
	LineSpeedtestResults          int64 `json:"line_speedtest_results"`
	ManagedInboundResources       int64 `json:"managed_inbound_resources"`
	SelfServiceOffers             int64 `json:"self_service_offers"`
	UserServerGrants              int64 `json:"user_server_grants"`
	UserNodeSelections            int64 `json:"user_node_selections"`
	UserNodeSelectionUsage        int64 `json:"user_node_selection_usage"`
	UserInboundAccessSources      int64 `json:"user_inbound_access_sources"`
	ManagedAccessAudit            int64 `json:"managed_access_audit"`
	RemoteGuardSecrets            int64 `json:"remote_guard_secrets"`
	InstallationRecords           int64 `json:"installation_records"`
	InstallTickets                int64 `json:"install_tickets"`
	SharedServerTokens            int64 `json:"shared_server_tokens"`
	FederationRelations           int64 `json:"federation_relations"`
	TrafficThresholdNotifications int64 `json:"traffic_threshold_notifications"`
	StatRecords                   int64 `json:"stat_records"`
	Total                         int64 `json:"total"`
}

func (r *TrafficRepository) migrateRemoteServerDeletionTasks() error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if _, err := r.db.Exec(remoteServerDeletionSchema); err != nil {
		return fmt.Errorf("migrate remote server deletion tasks: %w", err)
	}
	return nil
}

func scanRemoteServerDeletionTask(scanner interface{ Scan(...any) error }) (*RemoteServerDeletionTask, error) {
	var task RemoteServerDeletionTask
	var consumed int
	var callbackAt sql.NullTime
	if err := scanner.Scan(
		&task.ServerID, &task.TokenHash, &task.CleanupID, &task.Status, &consumed,
		&task.ExpiresAt, &task.LastError, &task.CreatedAt, &task.UpdatedAt, &callbackAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRemoteServerDeletionTaskNotFound
		}
		return nil, err
	}
	task.CallbackConsumed = consumed != 0
	if callbackAt.Valid {
		task.CallbackAt = &callbackAt.Time
	}
	return &task, nil
}

const selectRemoteServerDeletionTask = `SELECT server_id, token_hash, cleanup_id, status,
callback_consumed, expires_at, last_error, created_at, updated_at, callback_at
FROM remote_server_deletion_tasks`

func (r *TrafficRepository) GetRemoteServerDeletionTask(ctx context.Context, serverID int64) (*RemoteServerDeletionTask, error) {
	if r == nil || r.db == nil || serverID <= 0 {
		return nil, ErrRemoteServerDeletionTaskNotFound
	}
	return scanRemoteServerDeletionTask(r.db.QueryRowContext(ctx, selectRemoteServerDeletionTask+` WHERE server_id = ?`, serverID))
}

func (r *TrafficRepository) CreateRemoteServerDeletionTask(ctx context.Context, serverID int64, tokenHash string, expiresAt time.Time) (*RemoteServerDeletionTask, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	tokenHash = strings.TrimSpace(tokenHash)
	if serverID <= 0 || len(tokenHash) != 64 || !expiresAt.After(time.Now().UTC()) {
		return nil, errors.New("invalid remote server deletion task")
	}
	now := time.Now().UTC()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO remote_server_deletion_tasks (
server_id, token_hash, cleanup_id, status, callback_consumed, expires_at,
last_error, created_at, updated_at, callback_at
) VALUES (?, ?, '', ?, 0, ?, '', ?, ?, NULL)
ON CONFLICT(server_id) DO UPDATE SET
token_hash = excluded.token_hash, cleanup_id = '', status = excluded.status,
callback_consumed = 0, expires_at = excluded.expires_at, last_error = '',
created_at = excluded.created_at, updated_at = excluded.updated_at, callback_at = NULL
WHERE remote_server_deletion_tasks.status = ?
   OR remote_server_deletion_tasks.expires_at <= ?`,
		serverID, tokenHash, RemoteServerDeletionPending, expiresAt, now, now,
		RemoteServerDeletionFailed, now,
	); err != nil {
		return nil, fmt.Errorf("create remote server deletion task: %w", err)
	}
	task, err := r.GetRemoteServerDeletionTask(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if task.TokenHash != tokenHash {
		return nil, errors.New("remote server deletion task is already active")
	}
	return task, nil
}

// MarkRemoteServerDeletionDispatched binds the Agent-issued cleanup ID to the
// persisted operation. A callback may win the race and bind it first; in that
// case this method verifies equality without downgrading the completed state.
func (r *TrafficRepository) MarkRemoteServerDeletionDispatched(ctx context.Context, serverID int64, tokenHash, cleanupID string) error {
	tokenHash, cleanupID = strings.TrimSpace(tokenHash), strings.TrimSpace(cleanupID)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin mark deletion dispatched: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	task, err := scanRemoteServerDeletionTask(tx.QueryRowContext(ctx, selectRemoteServerDeletionTask+` WHERE server_id = ?`, serverID))
	if err != nil {
		return err
	}
	if task.TokenHash != tokenHash {
		return ErrRemoteServerDeletionTokenInvalid
	}
	if task.CleanupID != "" && task.CleanupID != cleanupID {
		return ErrRemoteServerDeletionCleanupID
	}
	status := task.Status
	if status == RemoteServerDeletionPending {
		status = RemoteServerDeletionDispatched
	}
	if _, err := tx.ExecContext(ctx, `UPDATE remote_server_deletion_tasks
SET cleanup_id = ?, status = ?, updated_at = ? WHERE server_id = ? AND token_hash = ?`,
		cleanupID, status, time.Now().UTC(), serverID, tokenHash); err != nil {
		return fmt.Errorf("mark deletion dispatched: %w", err)
	}
	return tx.Commit()
}

// ConsumeRemoteServerDeletionCallback atomically validates and consumes one
// callback. Only a SHA-256 digest of the bearer token reaches this method.
func (r *TrafficRepository) ConsumeRemoteServerDeletionCallback(ctx context.Context, tokenHash, cleanupID string, success bool, callbackError string) (*RemoteServerDeletionTask, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	tokenHash, cleanupID = strings.TrimSpace(tokenHash), strings.TrimSpace(cleanupID)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin consume deletion callback: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	task, err := scanRemoteServerDeletionTask(tx.QueryRowContext(ctx, selectRemoteServerDeletionTask+` WHERE token_hash = ?`, tokenHash))
	if errors.Is(err, ErrRemoteServerDeletionTaskNotFound) {
		return nil, ErrRemoteServerDeletionTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if !task.ExpiresAt.After(now) {
		return nil, ErrRemoteServerDeletionTokenExpired
	}
	if task.CallbackConsumed {
		return nil, ErrRemoteServerDeletionCallbackUsed
	}
	if task.CleanupID != "" && task.CleanupID != cleanupID {
		return nil, ErrRemoteServerDeletionCleanupID
	}
	status := RemoteServerDeletionFailed
	lastError := strings.TrimSpace(callbackError)
	if success {
		status = RemoteServerDeletionAgentUninstalled
		lastError = ""
	} else if lastError == "" {
		lastError = "remote Agent cleanup failed"
	}
	result, err := tx.ExecContext(ctx, `UPDATE remote_server_deletion_tasks
SET cleanup_id = ?, status = ?, callback_consumed = 1, last_error = ?, callback_at = ?, updated_at = ?
WHERE server_id = ? AND token_hash = ? AND callback_consumed = 0`,
		cleanupID, status, lastError, now, now, task.ServerID, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("consume deletion callback: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrRemoteServerDeletionCallbackUsed
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit deletion callback: %w", err)
	}
	return r.GetRemoteServerDeletionTask(ctx, task.ServerID)
}

func (r *TrafficRepository) SetRemoteServerDeletionTaskError(ctx context.Context, serverID int64, message string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE remote_server_deletion_tasks
SET last_error = ?, updated_at = ? WHERE server_id = ?`, strings.TrimSpace(message), time.Now().UTC(), serverID)
	return err
}

func (r *TrafficRepository) FailRemoteServerDeletionTask(ctx context.Context, serverID int64, message string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE remote_server_deletion_tasks
SET status = ?, last_error = ?, updated_at = ? WHERE server_id = ?`,
		RemoteServerDeletionFailed, strings.TrimSpace(message), time.Now().UTC(), serverID)
	return err
}

// KeepRemoteServerDeletionDispatched records a post-dispatch verification
// problem without making the task replaceable. Once the request may have
// reached the Agent, replacing its callback token could orphan a successfully
// uninstalled server.
func (r *TrafficRepository) KeepRemoteServerDeletionDispatched(ctx context.Context, serverID int64, message string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE remote_server_deletion_tasks
SET status = CASE WHEN status = ? THEN ? ELSE status END,
    last_error = ?, updated_at = ? WHERE server_id = ?`,
		RemoteServerDeletionPending, RemoteServerDeletionDispatched,
		strings.TrimSpace(message), time.Now().UTC(), serverID)
	return err
}

func (r *TrafficRepository) DeleteRemoteServerDeletionTask(ctx context.Context, serverID int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM remote_server_deletion_tasks WHERE server_id = ?`, serverID)
	return err
}

func (r *TrafficRepository) GetRemoteServerDeleteCounts(ctx context.Context, serverID int64) (RemoteServerDeleteCounts, error) {
	var counts RemoteServerDeleteCounts
	if r == nil || r.db == nil || serverID <= 0 {
		return counts, errors.New("invalid remote server")
	}
	var serverName string
	if err := r.db.QueryRowContext(ctx, `SELECT name FROM remote_servers WHERE id = ?`, serverID).Scan(&serverName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return counts, ErrRemoteServerNotFound
		}
		return counts, err
	}
	queries := []struct {
		dst   *int64
		query string
		args  []any
	}{
		{&counts.Nodes, `SELECT COUNT(*) FROM nodes WHERE original_server = ?`, []any{serverName}},
		{&counts.NodeSpeedtestResults, `SELECT COUNT(*) FROM speed_test_results WHERE node_id IN (SELECT id FROM nodes WHERE original_server = ?)`, []any{serverName}},
		{&counts.Subaccounts, `SELECT COUNT(*) FROM user_subaccounts WHERE routed_node_id IN (SELECT id FROM nodes WHERE original_server = ?)`, []any{serverName}},
		{&counts.InboundConfigs, `SELECT COUNT(*) FROM user_inbound_configs WHERE server_id = ?`, []any{serverID}},
		{&counts.Outbounds, `SELECT COUNT(*) FROM user_outbounds WHERE server_id = ?`, []any{serverID}},
		{&counts.XraySnapshots, `SELECT COUNT(*) FROM server_xray_config_snapshots WHERE server_id = ?`, []any{serverID}},
		{&counts.BatchInbounds, `SELECT COUNT(*) FROM batch_inbounds WHERE server_id = ?`, []any{serverID}},
		{&counts.BatchOutbounds, `SELECT COUNT(*) FROM batch_outbounds WHERE server_id = ?`, []any{serverID}},
		{&counts.NodeTraffic, `SELECT COUNT(*) FROM node_traffic WHERE server_id = ?`, []any{serverID}},
		{&counts.UserTraffic, `SELECT COUNT(*) FROM user_traffic WHERE server_id = ?`, []any{serverID}},
		{&counts.UserEmailTraffic, `SELECT COUNT(*) FROM user_email_traffic WHERE server_id = ?`, []any{serverID}},
		{&counts.TrafficSnapshots, `SELECT COUNT(*) FROM traffic_snapshots WHERE server_id = ?`, []any{serverID}},
		{&counts.NodeTrafficSnapshots, `SELECT COUNT(*) FROM node_traffic_snapshots WHERE server_id = ?`, []any{serverID}},
		{&counts.UserTrafficSnapshots, `SELECT COUNT(*) FROM user_traffic_snapshots WHERE server_id = ?`, []any{serverID}},
		{&counts.UserEmailTrafficSnapshots, `SELECT COUNT(*) FROM user_email_traffic_snapshots WHERE server_id = ?`, []any{serverID}},
		{&counts.SystemTrafficSnapshots, `SELECT COUNT(*) FROM server_system_traffic_snapshots WHERE server_id = ?`, []any{serverID}},
		{&counts.LineSpeedtestResults, `SELECT COUNT(*) FROM line_speedtest_results WHERE target_kind = 'remote' AND server_id = ?`, []any{serverID}},
		{&counts.ManagedInboundResources, `SELECT COUNT(*) FROM managed_inbound_resources WHERE server_id = ?`, []any{serverID}},
		{&counts.SelfServiceOffers, `SELECT COUNT(*) FROM self_service_node_offers WHERE server_id = ?`, []any{serverID}},
		{&counts.UserServerGrants, `SELECT COUNT(*) FROM user_server_grants WHERE server_id = ?`, []any{serverID}},
		{&counts.UserNodeSelections, `SELECT COUNT(*) FROM user_node_selections WHERE grant_id IN (SELECT id FROM user_server_grants WHERE server_id = ?) OR offer_id IN (SELECT id FROM self_service_node_offers WHERE server_id = ?)`, []any{serverID, serverID}},
		{&counts.UserNodeSelectionUsage, `SELECT COUNT(*) FROM user_node_selection_usage WHERE selection_id IN (SELECT id FROM user_node_selections WHERE grant_id IN (SELECT id FROM user_server_grants WHERE server_id = ?) OR offer_id IN (SELECT id FROM self_service_node_offers WHERE server_id = ?))`, []any{serverID, serverID}},
		{&counts.UserInboundAccessSources, `SELECT COUNT(*) FROM user_inbound_access_sources WHERE server_id = ?`, []any{serverID}},
		{&counts.ManagedAccessAudit, `SELECT COUNT(*) FROM managed_access_audit WHERE server_id = ?`, []any{serverID}},
		{&counts.RemoteGuardSecrets, `SELECT COUNT(*) FROM remote_server_guard_secrets WHERE server_id = ?`, []any{serverID}},
		{&counts.InstallationRecords, `SELECT COUNT(*) FROM remote_server_installations WHERE server_id = ?`, []any{serverID}},
		{&counts.InstallTickets, `SELECT COUNT(*) FROM remote_server_install_tickets WHERE server_id = ?`, []any{serverID}},
		{&counts.SharedServerTokens, `SELECT COUNT(*) FROM shared_servers WHERE server_id = ?`, []any{serverID}},
		{&counts.FederationRelations, `SELECT COUNT(*) FROM federated_servers WHERE server_id = ?`, []any{serverID}},
		{&counts.TrafficThresholdNotifications, `SELECT COUNT(*) FROM traffic_threshold_notified WHERE server_id = ?`, []any{serverID}},
	}
	for _, item := range queries {
		if err := r.db.QueryRowContext(ctx, item.query, item.args...).Scan(item.dst); err != nil {
			return counts, fmt.Errorf("count remote server deletion impact: %w", err)
		}
		counts.Total += *item.dst
	}
	counts.StatRecords = counts.NodeTraffic + counts.UserTraffic + counts.UserEmailTraffic +
		counts.TrafficSnapshots + counts.NodeTrafficSnapshots + counts.UserTrafficSnapshots +
		counts.UserEmailTrafficSnapshots + counts.SystemTrafficSnapshots + counts.LineSpeedtestResults
	return counts, nil
}
