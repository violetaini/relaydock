package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PreparePackageInboundCredentialCleanup turns a saved package credential into
// a durable inactive access source. The managed-node reconciler owns the final
// Agent removal, credential deletion, and retry backoff from this point on.
func (r *TrafficRepository) PreparePackageInboundCredentialCleanup(
	ctx context.Context,
	cfg UserInboundConfig,
	actor string,
) (*UserInboundAccessSource, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	actor = strings.TrimSpace(actor)
	if cfg.ID <= 0 || strings.TrimSpace(cfg.Username) == "" || cfg.ServerID <= 0 ||
		strings.TrimSpace(cfg.InboundTag) == "" || actor == "" {
		return nil, ErrManagedInvalidArgument
	}

	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin package credential cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var stored UserInboundConfig
	if err := tx.QueryRowContext(ctx, `SELECT id, username, server_id, inbound_tag, protocol, credential_json, created_at
FROM user_inbound_configs WHERE id = ?`, cfg.ID).Scan(
		&stored.ID, &stored.Username, &stored.ServerID, &stored.InboundTag,
		&stored.Protocol, &stored.CredentialJSON, &stored.CreatedAt,
	); errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	} else if err != nil {
		return nil, fmt.Errorf("load package credential for cleanup: %w", err)
	}
	if stored.Username != cfg.Username || stored.ServerID != cfg.ServerID || stored.InboundTag != cfg.InboundTag {
		return nil, ErrManagedServerMismatch
	}

	var nodeID int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MIN(n.id), 0)
FROM nodes n
JOIN remote_servers rs ON rs.id = ?
WHERE n.original_server = rs.name AND n.inbound_tag = ?`, stored.ServerID, stored.InboundTag).Scan(&nodeID); err != nil {
		return nil, fmt.Errorf("resolve package cleanup node: %w", err)
	}

	now := time.Now().UTC()
	var sourceID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM user_inbound_access_sources
WHERE source_type = ? AND source_id = ? LIMIT 1`, ManagedSourceLegacyReview, stored.ID).Scan(&sourceID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO user_inbound_access_sources (
    username, server_id, inbound_tag, node_id, source_type, source_id,
    desired_state, observed_state, suspend_reason, generation, applied_generation,
    starts_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?)`,
			stored.Username, stored.ServerID, stored.InboundTag, nodeID,
			ManagedSourceLegacyReview, stored.ID, ManagedDesiredInactive,
			ManagedObservedActive, ManagedSuspendAdminDisabled,
			stored.CreatedAt.UTC(), stored.CreatedAt.UTC(), now,
		)
		if insertErr != nil {
			return nil, fmt.Errorf("insert package credential cleanup source: %w", insertErr)
		}
		sourceID, err = result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("read package credential cleanup source id: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("find package credential cleanup source: %w", err)
	default:
		if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    username = ?, server_id = ?, inbound_tag = ?, node_id = ?,
    desired_state = ?, observed_state = ?, suspend_reason = ?,
    generation = CASE WHEN generation = applied_generation THEN generation + 1 ELSE generation END,
    retry_count = 0, next_retry_at = NULL, last_error = '', updated_at = ?
WHERE id = ?`, stored.Username, stored.ServerID, stored.InboundTag, nodeID,
			ManagedDesiredInactive, ManagedObservedActive, ManagedSuspendAdminDisabled,
			now, sourceID); err != nil {
			return nil, fmt.Errorf("refresh package credential cleanup source: %w", err)
		}
	}

	source, err := scanUserInboundAccessSource(tx.QueryRowContext(ctx,
		selectUserInboundAccessSource+` WHERE id = ?`, sourceID))
	if err != nil {
		return nil, fmt.Errorf("read package credential cleanup source: %w", err)
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "package_credential.cleanup_prepared", EntityType: "access_source",
		EntityID: source.ID, Username: source.Username, ServerID: source.ServerID,
		Details: map[string]any{"inbound_tag": source.InboundTag, "credential_config_id": stored.ID},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit package credential cleanup: %w", err)
	}
	return &source, nil
}
