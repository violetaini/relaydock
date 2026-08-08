package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrUserDeletionPending     = errors.New("user deletion is pending remote access revocation")
	ErrUserDeletionNotPrepared = errors.New("user deletion has not been prepared")
)

const userDeletionTombstoneSchema = `
CREATE TABLE IF NOT EXISTS user_deletion_tombstones (
    username TEXT PRIMARY KEY,
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMP NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_deletion_tombstones_updated
    ON user_deletion_tombstones(updated_at);
`

func (r *TrafficRepository) ensureUserDeletionTombstones() error {
	if err := managedInitialized(r); err != nil {
		return err
	}
	if _, err := r.db.Exec(userDeletionTombstoneSchema); err != nil {
		return fmt.Errorf("migrate user deletion tombstones: %w", err)
	}
	return nil
}

// IsUserDeletionPending reports whether username is a disabled deletion
// tombstone. Callers that can grant access must reject the operation while it
// is true so a concurrent retry cannot re-provision the account.
func (r *TrafficRepository) IsUserDeletionPending(ctx context.Context, username string) (bool, error) {
	if err := r.ensureUserDeletionTombstones(); err != nil {
		return false, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return false, ErrManagedInvalidArgument
	}
	var exists int
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_deletion_tombstones WHERE username = ?)`, username,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("check user deletion tombstone: %w", err)
	}
	return exists != 0, nil
}

// WithUserProvisioningLease serializes the final remote add-client mutation
// against PrepareUserDeletion. Credentials are reserved before acquiring this
// lease; therefore a deletion committed afterward will always discover and
// revoke anything the callback successfully publishes.
func (r *TrafficRepository) WithUserProvisioningLease(ctx context.Context, username string, provision func() error) error {
	return r.WithUsersProvisioningLease(ctx, []string{username}, provision)
}

func (r *TrafficRepository) WithUsersProvisioningLease(ctx context.Context, usernames []string, provision func() error) error {
	if err := r.ensureUserDeletionTombstones(); err != nil {
		return err
	}
	if provision == nil {
		return ErrManagedInvalidArgument
	}
	unique := make(map[string]struct{}, len(usernames))
	for _, username := range usernames {
		username = strings.TrimSpace(username)
		if username == "" {
			return ErrManagedInvalidArgument
		}
		unique[username] = struct{}{}
	}
	if len(unique) == 0 {
		return ErrManagedInvalidArgument
	}
	normalized := make([]string, 0, len(unique))
	for username := range unique {
		normalized = append(normalized, username)
	}
	sort.Strings(normalized)
	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	for _, username := range normalized {
		var active int
		if err := r.db.QueryRowContext(ctx, `SELECT is_active FROM users WHERE username = ?`, username).Scan(&active); errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		} else if err != nil {
			return fmt.Errorf("check user before provisioning: %w", err)
		}
		var pending int
		if err := r.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM user_deletion_tombstones WHERE username = ?)`, username,
		).Scan(&pending); err != nil {
			return fmt.Errorf("check user deletion before provisioning: %w", err)
		}
		if active == 0 || pending != 0 {
			return ErrUserDeletionPending
		}
	}
	return provision()
}

func (r *TrafficRepository) ListPendingUserDeletions(ctx context.Context, limit int) ([]string, error) {
	if err := r.ensureUserDeletionTombstones(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT username FROM user_deletion_tombstones
ORDER BY updated_at ASC, username ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending user deletions: %w", err)
	}
	defer rows.Close()
	usernames := make([]string, 0)
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, fmt.Errorf("scan pending user deletion: %w", err)
		}
		usernames = append(usernames, username)
	}
	return usernames, rows.Err()
}

// PrepareUserDeletion disables the account and turns every known authorization
// source into a durable revocation job. Every credential gets a legacy-review
// source first, including package credentials created after the managed-node
// migration, so an offline Agent never leaves us without retry material.
func (r *TrafficRepository) PrepareUserDeletion(ctx context.Context, username, actor string) ([]UserInboundAccessSource, error) {
	if err := r.ensureUserDeletionTombstones(); err != nil {
		return nil, err
	}
	username, actor = strings.TrimSpace(username), strings.TrimSpace(actor)
	if username == "" || actor == "" {
		return nil, ErrManagedInvalidArgument
	}

	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin prepare user deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE username = ?`, username).Scan(&role); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, fmt.Errorf("get user before deletion: %w", err)
	}
	if role == RoleAdmin {
		return nil, ErrManagedInvalidArgument
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_deletion_tombstones (
    username, requested_by, requested_at, last_error, updated_at
) VALUES (?, ?, ?, '', ?)
ON CONFLICT(username) DO UPDATE SET requested_by = excluded.requested_by, updated_at = excluded.updated_at`,
		username, actor, now, now); err != nil {
		return nil, fmt.Errorf("save user deletion tombstone: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET is_active = 0, updated_at = ? WHERE username = ?`, now, username,
	); err != nil {
		return nil, fmt.Errorf("disable user for deletion: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE username = ?`, username); err != nil {
		return nil, fmt.Errorf("delete sessions for user deletion: %w", err)
	}

	// Package credentials are not always materialized as package access sources.
	// Give each saved credential its own idempotent revocation source before any
	// remote call can fail.
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_inbound_access_sources (
    username, server_id, inbound_tag, node_id, source_type, source_id,
    desired_state, observed_state, suspend_reason, generation, applied_generation,
    starts_at, created_at, updated_at
)
SELECT c.username, c.server_id, c.inbound_tag,
       COALESCE((
           SELECT MIN(n.id)
           FROM nodes n
           JOIN remote_servers rs ON rs.id = c.server_id
           WHERE n.original_server = rs.name AND n.inbound_tag = c.inbound_tag
       ), 0),
       ?, c.id, ?, ?, ?, 1, 0, c.created_at, c.created_at, ?
FROM user_inbound_configs c
WHERE c.username = ?
ON CONFLICT(username, server_id, inbound_tag, node_id, source_type, source_id) DO NOTHING`,
		ManagedSourceLegacyReview, ManagedDesiredInactive, ManagedObservedUnknown,
		ManagedSuspendUserDisabled, now, username); err != nil {
		return nil, fmt.Errorf("materialize credential revocations: %w", err)
	}

	// A source already pending inactive must retain its generation/backoff. Bump
	// only sources whose desired state changes, plus any inconsistent source that
	// claims its active observation is already applied.
	if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    desired_state = ?, suspend_reason = ?, generation = generation + 1,
    retry_count = 0, next_retry_at = NULL, last_error = '', updated_at = ?
WHERE username = ? AND desired_state != ?`, ManagedDesiredInactive,
		ManagedSuspendUserDisabled, now, username, ManagedDesiredInactive); err != nil {
		return nil, fmt.Errorf("queue user access revocations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    suspend_reason = ?, generation = generation + 1,
    retry_count = 0, next_retry_at = NULL, last_error = '', updated_at = ?
WHERE username = ? AND desired_state = ? AND observed_state != ?
  AND generation = applied_generation`, ManagedSuspendUserDisabled, now, username,
		ManagedDesiredInactive, ManagedObservedInactive); err != nil {
		return nil, fmt.Errorf("repair user access revocations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources
SET suspend_reason = ?, updated_at = ? WHERE username = ? AND suspend_reason != ?`,
		ManagedSuspendUserDisabled, now, username, ManagedSuspendUserDisabled); err != nil {
		return nil, fmt.Errorf("mark user access revocation reason: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections SET
    desired_enabled = 0, updated_at = ?
WHERE grant_id IN (SELECT id FROM user_server_grants WHERE username = ?)`, now, username); err != nil {
		return nil, fmt.Errorf("disable user managed selections: %w", err)
	}
	if err := prepareUserForwardDeletionTx(ctx, tx, username, actor, now); err != nil {
		return nil, err
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "user.deletion_prepared", EntityType: "user",
		Username: username, Details: map[string]any{"desired_state": ManagedDesiredInactive},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit prepare user deletion: %w", err)
	}
	r.revokeMemorySessions(username)

	rows, err := r.db.QueryContext(ctx, selectUserInboundAccessSource+`
WHERE username = ? ORDER BY id ASC`, username)
	if err != nil {
		return nil, fmt.Errorf("list prepared user revocations: %w", err)
	}
	defer rows.Close()
	sources := make([]UserInboundAccessSource, 0)
	for rows.Next() {
		source, scanErr := scanUserInboundAccessSource(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan prepared user revocation: %w", scanErr)
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func (r *TrafficRepository) RecordUserDeletionFailure(ctx context.Context, username, message string) error {
	if err := r.ensureUserDeletionTombstones(); err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return ErrManagedInvalidArgument
	}
	message = sanitizeManagedError(message)
	result, err := r.db.ExecContext(ctx, `UPDATE user_deletion_tombstones
SET last_error = ?, updated_at = ? WHERE username = ?`, message, time.Now().UTC(), username)
	if err != nil {
		return fmt.Errorf("record user deletion failure: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrUserDeletionNotPrepared
	}
	return nil
}

func userDeletionReadyTx(ctx context.Context, tx *sql.Tx, username string) (bool, error) {
	var tombstone int
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_deletion_tombstones WHERE username = ?)`, username,
	).Scan(&tombstone); err != nil {
		return false, err
	}
	if tombstone == 0 {
		return false, ErrUserDeletionNotPrepared
	}

	var pendingSources int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_inbound_access_sources
WHERE username = ? AND (
    desired_state != ? OR observed_state != ? OR generation != applied_generation
)`, username, ManagedDesiredInactive, ManagedObservedInactive).Scan(&pendingSources); err != nil {
		return false, err
	}
	if pendingSources != 0 {
		return false, nil
	}
	forwardingReady, err := userForwardDeletionReadyTx(ctx, tx, username)
	if err != nil {
		return false, err
	}
	if !forwardingReady {
		return false, nil
	}

	// A credential written concurrently after Prepare must stop finalization. A
	// repeated delete request will materialize it and retry the remote revoke.
	var uncoveredCredentials int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_inbound_configs c
WHERE c.username = ? AND NOT EXISTS (
    SELECT 1 FROM user_inbound_access_sources s
    WHERE s.username = c.username AND s.server_id = c.server_id
      AND s.inbound_tag = c.inbound_tag AND s.source_type = ? AND s.source_id = c.id
      AND s.desired_state = ? AND s.observed_state = ?
      AND s.generation = s.applied_generation
)`, username, ManagedSourceLegacyReview, ManagedDesiredInactive,
		ManagedObservedInactive).Scan(&uncoveredCredentials); err != nil {
		return false, err
	}
	return uncoveredCredentials == 0, nil
}

func (r *TrafficRepository) IsUserDeletionReady(ctx context.Context, username string) (bool, error) {
	if err := r.ensureUserDeletionTombstones(); err != nil {
		return false, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return false, ErrManagedInvalidArgument
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, fmt.Errorf("begin check user deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ready, err := userDeletionReadyTx(ctx, tx, username)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit check user deletion: %w", err)
	}
	return ready, nil
}

// FinalizeUserDeletion atomically removes the managed authorization graph and
// every reusable local credential only after all Agent revocations are
// confirmed. Audit history is deliberately retained.
func (r *TrafficRepository) FinalizeUserDeletion(ctx context.Context, username, actor string) error {
	if err := r.ensureUserDeletionTombstones(); err != nil {
		return err
	}
	username, actor = strings.TrimSpace(username), strings.TrimSpace(actor)
	if username == "" || actor == "" {
		return ErrManagedInvalidArgument
	}
	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin finalize user deletion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var userExists, tombstoneExists int
	if err := tx.QueryRowContext(ctx, `SELECT
    EXISTS(SELECT 1 FROM users WHERE username = ?),
    EXISTS(SELECT 1 FROM user_deletion_tombstones WHERE username = ?)`,
		username, username).Scan(&userExists, &tombstoneExists); err != nil {
		return fmt.Errorf("check user before final deletion: %w", err)
	}
	if userExists == 0 && tombstoneExists == 0 {
		r.revokeMemorySessions(username)
		return nil
	}

	ready, err := userDeletionReadyTx(ctx, tx, username)
	if err != nil {
		return err
	}
	if !ready {
		return ErrUserDeletionPending
	}
	if err := finalizeUserForwardDeletionTx(ctx, tx, username); err != nil {
		return err
	}

	steps := []struct {
		name  string
		query string
		args  []any
	}{
		{name: "managed usage", query: `DELETE FROM user_node_selection_usage WHERE grant_id IN (SELECT id FROM user_server_grants WHERE username = ?)`, args: []any{username}},
		{name: "managed sources", query: `DELETE FROM user_inbound_access_sources WHERE username = ?`, args: []any{username}},
		{name: "managed selections", query: `DELETE FROM user_node_selections WHERE grant_id IN (SELECT id FROM user_server_grants WHERE username = ?)`, args: []any{username}},
		{name: "managed grants", query: `DELETE FROM user_server_grants WHERE username = ?`, args: []any{username}},
		{name: "API tokens", query: `DELETE FROM user_api_tokens WHERE username = ?`, args: []any{username}},
		{name: "sessions", query: `DELETE FROM sessions WHERE username = ?`, args: []any{username}},
		{name: "subscriptions", query: `DELETE FROM user_subscriptions WHERE username = ?`, args: []any{username}},
		{name: "proxy providers", query: `DELETE FROM proxy_provider_configs WHERE username = ?`, args: []any{username}},
		{name: "external subscriptions", query: `DELETE FROM external_subscriptions WHERE username = ?`, args: []any{username}},
		{name: "settings", query: `DELETE FROM user_settings WHERE username = ?`, args: []any{username}},
		{name: "subscription token", query: `DELETE FROM user_tokens WHERE username = ?`, args: []any{username}},
		{name: "subaccounts", query: `DELETE FROM user_subaccounts WHERE username = ?`, args: []any{username}},
		{name: "inbound credentials", query: `DELETE FROM user_inbound_configs WHERE username = ?`, args: []any{username}},
		{name: "outbounds", query: `DELETE FROM user_outbounds WHERE username = ?`, args: []any{username}},
		{name: "override scripts", query: `DELETE FROM override_scripts WHERE username = ?`, args: []any{username}},
		{name: "routed action history", query: `DELETE FROM user_routed_outbound_actions WHERE username = ?`, args: []any{username}},
		{name: "traffic records", query: `DELETE FROM user_traffic_records WHERE username = ?`, args: []any{username}},
		{name: "traffic", query: `DELETE FROM user_traffic WHERE username = ?`, args: []any{username}},
		{name: "traffic snapshots", query: `DELETE FROM user_traffic_snapshots WHERE username = ?`, args: []any{username}},
		{name: "owned nodes", query: `DELETE FROM nodes WHERE username = ?`, args: []any{username}},
	}
	for _, step := range steps {
		if _, err := tx.ExecContext(ctx, step.query, step.args...); err != nil {
			return fmt.Errorf("delete user %s: %w", step.name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE invite_codes SET revoked = 1
WHERE kind = 'bind' AND bind_username = ?`, username); err != nil {
		return fmt.Errorf("revoke user-bound invite codes: %w", err)
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "user.deleted", EntityType: "user", Username: username,
	}); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrUserNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_deletion_tombstones WHERE username = ?`, username); err != nil {
		return fmt.Errorf("delete user deletion tombstone: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit finalize user deletion: %w", err)
	}
	r.revokeMemorySessions(username)
	return nil
}
