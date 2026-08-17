package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrUserDisablePending = errors.New("user disable is pending remote access revocation")

// PrepareUserDisable atomically disables the account and materializes one
// durable cleanup source for every saved inbound credential. The managed
// reconciler can therefore finish remote removal after an Agent reconnects
// without discarding the stable credential needed by a later re-enable.
func (r *TrafficRepository) PrepareUserDisable(ctx context.Context, username string) ([]UserInboundAccessSource, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrManagedInvalidArgument
	}
	leasedCtx, releaseAuthorization, err := r.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		return nil, err
	}
	defer releaseAuthorization()
	ctx = leasedCtx

	r.authMutationMu.Lock()
	defer r.authMutationMu.Unlock()
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin prepare user disable: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE username = ?`, username).Scan(&role); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, fmt.Errorf("get user before disable: %w", err)
	}
	if role == RoleAdmin {
		return nil, ErrManagedInvalidArgument
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET is_active = 0, updated_at = ? WHERE username = ?`, now, username,
	); err != nil {
		return nil, fmt.Errorf("disable user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE username = ?`, username); err != nil {
		return nil, fmt.Errorf("delete sessions for user disable: %w", err)
	}
	// Persist private routed revocation in the same transaction as the account
	// status. A crash after commit must not leave a live route without a durable
	// deny/retry marker.
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET is_active = 0, revoke_pending = 1, activation_pending = 0, updated_at = ?
			WHERE username = ? AND (is_active = 1 OR revoke_pending = 1 OR activation_pending = 1)
		  AND EXISTS (
		      SELECT 1 FROM nodes n
		      WHERE n.id = user_subaccounts.routed_node_id
		        AND n.node_type = 'routed'
		        AND n.routed_owner = 'user'
		        AND n.username = user_subaccounts.username
		  )`, now, username); err != nil {
		return nil, fmt.Errorf("prepare private routed user disable revocations: %w", err)
	}

	// Conservatively record observed=active. A Peer may have been accepted by
	// the Agent immediately before the control-plane generation was persisted.
	// Repeated disable requests preserve an already pending generation.
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
ON CONFLICT(username, server_id, inbound_tag, node_id, source_type, source_id)
DO UPDATE SET
    desired_state = excluded.desired_state,
    observed_state = CASE
        WHEN user_inbound_access_sources.generation = user_inbound_access_sources.applied_generation
        THEN excluded.observed_state
        ELSE user_inbound_access_sources.observed_state
    END,
    suspend_reason = excluded.suspend_reason,
    generation = CASE
        WHEN user_inbound_access_sources.generation = user_inbound_access_sources.applied_generation
        THEN user_inbound_access_sources.generation + 1
        ELSE user_inbound_access_sources.generation
    END,
    retry_count = CASE
        WHEN user_inbound_access_sources.generation = user_inbound_access_sources.applied_generation
        THEN 0 ELSE user_inbound_access_sources.retry_count
    END,
    next_retry_at = CASE
        WHEN user_inbound_access_sources.generation = user_inbound_access_sources.applied_generation
        THEN NULL ELSE user_inbound_access_sources.next_retry_at
    END,
    last_error = CASE
        WHEN user_inbound_access_sources.generation = user_inbound_access_sources.applied_generation
        THEN '' ELSE user_inbound_access_sources.last_error
    END,
    updated_at = excluded.updated_at`,
		ManagedSourceLegacyReview, ManagedDesiredInactive, ManagedObservedActive,
		ManagedSuspendUserDisabled, now, username); err != nil {
		return nil, fmt.Errorf("materialize user disable revocations: %w", err)
	}

	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: "user-status", Action: "user.disabled", EntityType: "user",
		Username: username, Details: map[string]any{"desired_state": ManagedDesiredInactive},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit prepare user disable: %w", err)
	}
	r.revokeMemorySessions(username)

	rows, err := r.db.QueryContext(ctx, selectUserInboundAccessSource+`
WHERE username = ? AND source_type = ? AND suspend_reason = ?
ORDER BY id ASC`, username, ManagedSourceLegacyReview, ManagedSuspendUserDisabled)
	if err != nil {
		return nil, fmt.Errorf("list prepared user disable revocations: %w", err)
	}
	defer rows.Close()
	sources := make([]UserInboundAccessSource, 0)
	for rows.Next() {
		source, scanErr := scanUserInboundAccessSource(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan prepared user disable revocation: %w", scanErr)
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func (r *TrafficRepository) IsUserDisablePending(ctx context.Context, username string) (bool, error) {
	if err := managedInitialized(r); err != nil {
		return false, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return false, ErrManagedInvalidArgument
	}
	var pending int
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(
	    SELECT 1 FROM user_inbound_access_sources
	    WHERE username = ? AND source_type = ? AND suspend_reason = ?
	      AND desired_state = ? AND (
	          observed_state != ? OR generation != applied_generation
	      )
	) OR EXISTS(
	    SELECT 1 FROM user_subaccounts
	    WHERE username = ? AND revoke_pending = 1
	)`, username, ManagedSourceLegacyReview, ManagedSuspendUserDisabled,
		ManagedDesiredInactive, ManagedObservedInactive, username).Scan(&pending)
	if err != nil {
		return false, fmt.Errorf("check user disable revocations: %w", err)
	}
	return pending != 0, nil
}
