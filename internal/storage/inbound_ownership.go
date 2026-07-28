package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// remote_inbound_ownership is the control-plane source of truth for every
// fenced Agent inbound, including tunnel-only entries that intentionally have
// no subscription node or managed-resource row.
func (r *TrafficRepository) migrateRemoteInboundOwnership() error {
	const schema = `
CREATE TABLE IF NOT EXISTS remote_inbound_ownership (
    server_id INTEGER NOT NULL,
    inbound_tag TEXT NOT NULL,
    mutation_id TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(server_id, inbound_tag),
    FOREIGN KEY(server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remote_inbound_ownership_mutation
    ON remote_inbound_ownership(mutation_id);
`
	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate remote inbound ownership: %w", err)
	}

	// Backfill deployments that already persisted generation IDs on nodes or
	// special resources. Conflicting evidence is unsafe and must stop startup.
	var serverID int64
	var inboundTag string
	err := r.db.QueryRow(`
		SELECT server_id, inbound_tag FROM (
			SELECT server_id, inbound_tag, COUNT(DISTINCT mutation_id) AS generations
			FROM (
				SELECT server_id, inbound_tag, mutation_id
				FROM managed_inbound_resources
				WHERE TRIM(COALESCE(mutation_id, '')) != ''
				UNION ALL
				SELECT s.id, n.inbound_tag, n.inbound_mutation_id
				FROM nodes n
				JOIN remote_servers s ON s.name = n.original_server
				WHERE TRIM(COALESCE(n.inbound_mutation_id, '')) != ''
			) evidence
			GROUP BY server_id, inbound_tag
		) conflicts WHERE generations > 1 LIMIT 1`).Scan(&serverID, &inboundTag)
	if err == nil {
		return fmt.Errorf("conflicting inbound mutation ownership for server %d tag %q", serverID, inboundTag)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("inspect inbound mutation ownership: %w", err)
	}
	_, err = r.db.Exec(`
		INSERT OR IGNORE INTO remote_inbound_ownership
			(server_id, inbound_tag, mutation_id, created_at, updated_at)
		SELECT server_id, inbound_tag, MAX(mutation_id), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
		FROM (
			SELECT server_id, inbound_tag, mutation_id
			FROM managed_inbound_resources
			WHERE TRIM(COALESCE(mutation_id, '')) != ''
			UNION ALL
			SELECT s.id, n.inbound_tag, n.inbound_mutation_id
			FROM nodes n
			JOIN remote_servers s ON s.name = n.original_server
			WHERE TRIM(COALESCE(n.inbound_mutation_id, '')) != ''
		) evidence
		GROUP BY server_id, inbound_tag`)
	if err != nil {
		return fmt.Errorf("backfill inbound mutation ownership: %w", err)
	}
	return nil
}

func (r *TrafficRepository) SetRemoteInboundOwnership(ctx context.Context, serverID int64, inboundTag, mutationID string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	mutationID = strings.TrimSpace(mutationID)
	if serverID <= 0 || inboundTag == "" || mutationID == "" {
		return errors.New("server id, inbound tag, and mutation id are required")
	}
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO remote_inbound_ownership
			(server_id, inbound_tag, mutation_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(server_id, inbound_tag) DO UPDATE SET
			mutation_id = excluded.mutation_id,
			updated_at = excluded.updated_at`, serverID, inboundTag, mutationID, now, now)
	if err != nil {
		return fmt.Errorf("set remote inbound ownership: %w", err)
	}
	return nil
}

func (r *TrafficRepository) GetRemoteInboundOwnership(ctx context.Context, serverID int64, inboundTag string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	if serverID <= 0 || inboundTag == "" {
		return "", nil
	}
	var mutationID string
	err := r.db.QueryRowContext(ctx, `
		SELECT mutation_id FROM remote_inbound_ownership
		WHERE server_id = ? AND inbound_tag = ?`, serverID, inboundTag).Scan(&mutationID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get remote inbound ownership: %w", err)
	}
	return strings.TrimSpace(mutationID), nil
}

func (r *TrafficRepository) DeleteRemoteInboundOwnershipIfMutation(ctx context.Context, serverID int64, inboundTag, mutationID string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	mutationID = strings.TrimSpace(mutationID)
	if serverID <= 0 || inboundTag == "" || mutationID == "" {
		return 0, nil
	}
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM remote_inbound_ownership
		WHERE server_id = ? AND inbound_tag = ? AND mutation_id = ?`, serverID, inboundTag, mutationID)
	if err != nil {
		return 0, fmt.Errorf("delete remote inbound ownership: %w", err)
	}
	return result.RowsAffected()
}

func (r *TrafficRepository) ClearRemoteInboundOwnership(ctx context.Context, serverID int64, inboundTag string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	if serverID <= 0 || inboundTag == "" {
		return nil
	}
	if _, err := r.db.ExecContext(ctx, `
		DELETE FROM remote_inbound_ownership
		WHERE server_id = ? AND inbound_tag = ?`, serverID, inboundTag); err != nil {
		return fmt.Errorf("clear remote inbound ownership: %w", err)
	}
	return nil
}

func (r *TrafficRepository) UpdateNodesInboundMutation(ctx context.Context, serverName, inboundTag, mutationID string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	serverName = strings.TrimSpace(serverName)
	inboundTag = strings.TrimSpace(inboundTag)
	mutationID = strings.TrimSpace(mutationID)
	if serverName == "" || inboundTag == "" {
		return 0, nil
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE nodes SET inbound_mutation_id = ?, updated_at = CURRENT_TIMESTAMP
		WHERE original_server = ? AND inbound_tag = ?`, mutationID, serverName, inboundTag)
	if err != nil {
		return 0, fmt.Errorf("update node inbound mutation: %w", err)
	}
	return result.RowsAffected()
}
