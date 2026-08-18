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
	UserManagedNodeCreating = "creating"
	UserManagedNodeActive   = "active"
	UserManagedNodeDeleting = "deleting"
)

var ErrUserManagedNodeCreationNotFound = errors.New("user managed node creation not found")

// UserManagedNodeCreation is the durable owner of a whole dedicated inbound.
// The linked private offer/selection owns credential policy; this row survives
// grant suspension so the reconciler can remove the remote inbound and node.
type UserManagedNodeCreation struct {
	ID          int64     `json:"id"`
	GrantID     int64     `json:"grant_id"`
	Username    string    `json:"username"`
	ServerID    int64     `json:"server_id"`
	InboundTag  string    `json:"inbound_tag"`
	MutationID  string    `json:"mutation_id"`
	NodeID      *int64    `json:"node_id,omitempty"`
	OfferID     *int64    `json:"offer_id,omitempty"`
	SelectionID *int64    `json:"selection_id,omitempty"`
	State       string    `json:"state"`
	LastError   string    `json:"last_error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (r *TrafficRepository) migrateUserManagedNodeCreations() error {
	const schema = `
CREATE TABLE IF NOT EXISTS user_managed_node_creations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id INTEGER NOT NULL,
    username TEXT NOT NULL,
	    server_id INTEGER NOT NULL,
	    inbound_tag TEXT NOT NULL,
	    mutation_id TEXT NOT NULL,
    node_id INTEGER,
    offer_id INTEGER,
    selection_id INTEGER,
    state TEXT NOT NULL DEFAULT 'creating' CHECK(state IN ('creating','active','deleting')),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    UNIQUE(server_id, inbound_tag),
	    UNIQUE(mutation_id),
    UNIQUE(node_id),
    UNIQUE(offer_id),
    UNIQUE(selection_id)
);
CREATE INDEX IF NOT EXISTS idx_user_managed_node_creations_user
    ON user_managed_node_creations(username, state, id);
CREATE INDEX IF NOT EXISTS idx_user_managed_node_creations_grant
    ON user_managed_node_creations(grant_id, state, id);
`
	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate user managed node creations: %w", err)
	}
	return nil
}

const selectUserManagedNodeCreation = `SELECT id, grant_id, username, server_id, inbound_tag, mutation_id,
	       node_id, offer_id, selection_id, state, last_error, created_at, updated_at
FROM user_managed_node_creations`

func scanUserManagedNodeCreation(scanner rowScanner) (UserManagedNodeCreation, error) {
	var item UserManagedNodeCreation
	var nodeID, offerID, selectionID sql.NullInt64
	if err := scanner.Scan(&item.ID, &item.GrantID, &item.Username, &item.ServerID,
		&item.InboundTag, &item.MutationID, &nodeID, &offerID, &selectionID, &item.State,
		&item.LastError, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, err
	}
	if nodeID.Valid {
		item.NodeID = &nodeID.Int64
	}
	if offerID.Valid {
		item.OfferID = &offerID.Int64
	}
	if selectionID.Valid {
		item.SelectionID = &selectionID.Int64
	}
	return item, nil
}

func (r *TrafficRepository) GetUserManagedNodeCreation(ctx context.Context, id int64) (*UserManagedNodeCreation, error) {
	if id <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	item, err := scanUserManagedNodeCreation(r.db.QueryRowContext(ctx, selectUserManagedNodeCreation+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserManagedNodeCreationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user managed node creation: %w", err)
	}
	return &item, nil
}

func (r *TrafficRepository) ListUserManagedNodeCreations(ctx context.Context, username string, grantID int64) ([]UserManagedNodeCreation, error) {
	query := selectUserManagedNodeCreation + ` WHERE 1=1`
	args := make([]any, 0, 2)
	if username = strings.TrimSpace(username); username != "" {
		query += ` AND username=?`
		args = append(args, username)
	}
	if grantID > 0 {
		query += ` AND grant_id=?`
		args = append(args, grantID)
	}
	query += ` ORDER BY id ASC`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list user managed node creations: %w", err)
	}
	defer rows.Close()
	items := make([]UserManagedNodeCreation, 0)
	for rows.Next() {
		item, err := scanUserManagedNodeCreation(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *TrafficRepository) HasUserManagedNodeCreationForInbound(ctx context.Context, username string, serverID int64, inboundTag string) (bool, error) {
	username = strings.TrimSpace(username)
	inboundTag = strings.TrimSpace(inboundTag)
	if username == "" || serverID <= 0 || inboundTag == "" {
		return false, ErrManagedInvalidArgument
	}
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM user_managed_node_creations
WHERE username=? AND server_id=? AND inbound_tag=?
)`, username, serverID, inboundTag).Scan(&exists); err != nil {
		return false, fmt.Errorf("check user managed node creation inbound ownership: %w", err)
	}
	return exists != 0, nil
}

// ReserveUserManagedNodeCreation consumes one grant slot before any remote
// mutation. Creating reservations count alongside active selections so
// concurrent requests cannot exceed MaxActiveNodes.
func (r *TrafficRepository) ReserveUserManagedNodeCreation(ctx context.Context, username string, grantID, serverID int64, inboundTag, mutationID string, now time.Time) (*UserManagedNodeCreation, error) {
	username, inboundTag, mutationID = strings.TrimSpace(username), strings.TrimSpace(inboundTag), strings.TrimSpace(mutationID)
	if username == "" || grantID <= 0 || serverID <= 0 || inboundTag == "" || mutationID == "" || now.IsZero() {
		return nil, ErrManagedInvalidArgument
	}
	leasedCtx, release, err := r.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx = leasedCtx
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	grant, err := scanUserServerGrant(tx.QueryRowContext(ctx, selectUserServerGrant+` WHERE id=? AND username=? AND server_id=?`, grantID, username, serverID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserServerGrantNotFound
	}
	if err != nil {
		return nil, err
	}
	var userEnabled int
	if err := tx.QueryRowContext(ctx, `SELECT is_active FROM users WHERE username=?`, username).Scan(&userEnabled); err != nil {
		return nil, err
	}
	billed, err := grantUsageTx(ctx, tx, grant.ID, grant.BillingMode)
	if err != nil {
		return nil, err
	}
	if state := grant.StateAt(now.UTC(), userEnabled != 0, billed); state != ManagedGrantActive {
		if state == ManagedGrantOverLimit {
			return nil, ErrManagedTrafficLimit
		}
		return nil, ErrManagedGrantInactive
	}
	if grant.MaxActiveNodes > 0 {
		var active, creating int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_node_selections WHERE grant_id=? AND desired_enabled=1`, grant.ID).Scan(&active); err != nil {
			return nil, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_managed_node_creations WHERE grant_id=? AND state='creating'`, grant.ID).Scan(&creating); err != nil {
			return nil, err
		}
		if active+creating >= grant.MaxActiveNodes {
			return nil, ErrManagedActiveNodeLimit
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO user_managed_node_creations
(grant_id,username,server_id,inbound_tag,mutation_id,state,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?)`, grant.ID, username, serverID, inboundTag, mutationID, UserManagedNodeCreating, now.UTC(), now.UTC())
	if managedUniqueViolation(err) {
		return nil, ErrManagedAccessConflict
	}
	if err != nil {
		return nil, fmt.Errorf("reserve user managed node creation: %w", err)
	}
	id, _ := result.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetUserManagedNodeCreation(ctx, id)
}

// PromoteUserManagedNodeCreation atomically transfers the deny-first
// credential tombstone to the private selection and records durable ownership.
// A crash can therefore leave either the restrictive tombstone or the complete
// active graph, never an unowned credential between those states.
func (r *TrafficRepository) PromoteUserManagedNodeCreation(ctx context.Context, id, nodeID, offerID, selectionID, cleanupSourceID, credentialConfigID int64) (*UserManagedNodeCreation, error) {
	if id <= 0 || nodeID <= 0 || offerID <= 0 || selectionID <= 0 || cleanupSourceID <= 0 || credentialConfigID <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	item, err := scanUserManagedNodeCreation(tx.QueryRowContext(ctx, selectUserManagedNodeCreation+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserManagedNodeCreationNotFound
	}
	if err != nil {
		return nil, err
	}
	if item.State != UserManagedNodeCreating && item.State != UserManagedNodeActive {
		return nil, ErrManagedVersionConflict
	}
	var valid int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM nodes n
JOIN remote_servers rs ON rs.id=? AND rs.name=n.original_server
JOIN self_service_node_offers o ON o.id=? AND o.node_id=n.id AND o.server_id=rs.id
  AND o.inbound_tag=n.inbound_tag AND o.owner_username=? AND o.grant_id=?
JOIN user_node_selections s ON s.id=? AND s.offer_id=o.id AND s.grant_id=? AND s.desired_enabled=1
JOIN user_inbound_access_sources active ON active.id=s.access_source_id
  AND active.source_type=? AND active.source_id=s.id AND active.username=?
  AND active.server_id=rs.id AND active.inbound_tag=n.inbound_tag AND active.node_id=n.id
  AND active.desired_state=?
JOIN user_inbound_configs c ON c.id=? AND c.username=? AND c.server_id=rs.id AND c.inbound_tag=n.inbound_tag
JOIN user_inbound_access_sources cleanup ON cleanup.id=? AND cleanup.source_type=?
  AND cleanup.source_id=c.id AND cleanup.username=? AND cleanup.server_id=rs.id
  AND cleanup.inbound_tag=n.inbound_tag AND cleanup.desired_state=?
WHERE n.id=? AND n.username=? AND n.inbound_tag=?
  AND COALESCE(n.inbound_mutation_id,'')=?
)`, item.ServerID, offerID, item.Username, item.GrantID, selectionID, item.GrantID,
		ManagedSourceSelection, item.Username, ManagedDesiredActive,
		credentialConfigID, item.Username, cleanupSourceID, ManagedSourceLegacyReview,
		item.Username, ManagedDesiredInactive, nodeID, item.Username, item.InboundTag, item.MutationID).Scan(&valid); err != nil {
		return nil, err
	}
	if valid == 0 {
		return nil, ErrManagedServerMismatch
	}
	var existingCredential sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT credential_config_id FROM user_node_selections WHERE id=?`, selectionID).Scan(&existingCredential); err != nil {
		return nil, err
	}
	if existingCredential.Valid && existingCredential.Int64 != credentialConfigID {
		return nil, ErrManagedAccessConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections SET credential_config_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, credentialConfigID, selectionID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_managed_node_creations SET
node_id=?,offer_id=?,selection_id=?,state=?,last_error='',updated_at=CURRENT_TIMESTAMP
WHERE id=?`, nodeID, offerID, selectionID, UserManagedNodeActive, id); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM user_inbound_access_sources
WHERE id=? AND source_type=? AND source_id=? AND desired_state=?`, cleanupSourceID,
		ManagedSourceLegacyReview, credentialConfigID, ManagedDesiredInactive)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrManagedAccessSourceNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetUserManagedNodeCreation(ctx, id)
}

func (r *TrafficRepository) FinalizeUserManagedNodeCreation(ctx context.Context, id, nodeID, offerID, selectionID int64) (*UserManagedNodeCreation, error) {
	if id <= 0 || nodeID <= 0 || offerID <= 0 || selectionID <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `UPDATE user_managed_node_creations SET
node_id=?,offer_id=?,selection_id=?,state=?,last_error='',updated_at=CURRENT_TIMESTAMP
WHERE id=? AND state=?`, nodeID, offerID, selectionID, UserManagedNodeActive, id, UserManagedNodeCreating)
	if err != nil {
		return nil, fmt.Errorf("finalize user managed node creation: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrManagedVersionConflict
	}
	return r.GetUserManagedNodeCreation(ctx, id)
}

// RecoverUserManagedNodeCreationLinks closes crash windows between the remote
// transaction and the final ownership update. Every lookup is constrained by
// the reserved user/grant/server/tag tuple, so it cannot adopt a public offer.
func (r *TrafficRepository) RecoverUserManagedNodeCreationLinks(ctx context.Context, id int64) (*UserManagedNodeCreation, error) {
	item, err := r.GetUserManagedNodeCreation(ctx, id)
	if err != nil {
		return nil, err
	}
	var nodeID, offerID, selectionID sql.NullInt64
	err = r.db.QueryRowContext(ctx, `SELECT n.id,o.id,s.id
FROM nodes n
JOIN remote_servers rs ON rs.name=n.original_server AND rs.id=?
JOIN self_service_node_offers o ON o.node_id=n.id AND o.server_id=? AND o.inbound_tag=n.inbound_tag
  AND o.owner_username=? AND o.grant_id=?
LEFT JOIN user_node_selections s ON s.offer_id=o.id AND s.grant_id=?
WHERE n.username=? AND n.inbound_tag=? AND COALESCE(n.inbound_mutation_id,'')=?
ORDER BY n.id ASC LIMIT 1`, item.ServerID, item.ServerID, item.Username, item.GrantID,
		item.GrantID, item.Username, item.InboundTag, item.MutationID).Scan(&nodeID, &offerID, &selectionID)
	if errors.Is(err, sql.ErrNoRows) {
		// A node may exist before its private offer is written. Preserve that link
		// so cleanup can still remove the exact remote generation.
		_ = r.db.QueryRowContext(ctx, `SELECT n.id FROM nodes n JOIN remote_servers rs
ON rs.name=n.original_server AND rs.id=? WHERE n.username=? AND n.inbound_tag=?
AND COALESCE(n.inbound_mutation_id,'')=?
ORDER BY n.id ASC LIMIT 1`, item.ServerID, item.Username, item.InboundTag, item.MutationID).Scan(&nodeID)
	} else if err != nil {
		return nil, err
	}
	hasProgress := item.NodeID == nil && nodeID.Valid ||
		item.OfferID == nil && offerID.Valid ||
		item.SelectionID == nil && selectionID.Valid
	if !hasProgress {
		return item, nil
	}
	_, err = r.db.ExecContext(ctx, `UPDATE user_managed_node_creations SET
node_id=COALESCE(node_id,?),offer_id=COALESCE(offer_id,?),selection_id=COALESCE(selection_id,?),updated_at=CURRENT_TIMESTAMP
WHERE id=?`, nullInt64Value(nodeID), nullInt64Value(offerID), nullInt64Value(selectionID), id)
	if err != nil {
		return nil, err
	}
	return r.GetUserManagedNodeCreation(ctx, id)
}

func nullInt64Value(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func (r *TrafficRepository) MarkUserManagedNodeCreationDeleting(ctx context.Context, id int64, summary string) (*UserManagedNodeCreation, error) {
	if id <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	_, err := r.db.ExecContext(ctx, `UPDATE user_managed_node_creations SET state=?,last_error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		UserManagedNodeDeleting, sanitizeManagedError(summary), id)
	if err != nil {
		return nil, err
	}
	return r.GetUserManagedNodeCreation(ctx, id)
}

// DeleteUserManagedNodeCreationGraph is called only after the remote client and
// dedicated inbound are confirmed absent. It removes the private catalog graph
// without touching unrelated public offers or selections.
func (r *TrafficRepository) DeleteUserManagedNodeCreationGraph(ctx context.Context, id int64) error {
	return r.deleteUserManagedNodeCreationGraph(ctx, id, "", "")
}

// DeleteSupersededUserManagedNodeCreationGraph converges an old user-created
// generation after the same inbound tag has been replaced by a newer durable
// mutation. It deletes only local nodes still carrying the old mutation and
// user owner; the replacement desired state, ownership, and nodes are untouched.
func (r *TrafficRepository) DeleteSupersededUserManagedNodeCreationGraph(ctx context.Context, id int64, serverName, oldMutationID string) error {
	serverName = strings.TrimSpace(serverName)
	oldMutationID = strings.TrimSpace(oldMutationID)
	if serverName == "" || oldMutationID == "" {
		return ErrManagedInvalidArgument
	}
	return r.deleteUserManagedNodeCreationGraph(ctx, id, serverName, oldMutationID)
}

func (r *TrafficRepository) deleteUserManagedNodeCreationGraph(ctx context.Context, id int64, supersededServerName, supersededMutationID string) error {
	item, err := r.GetUserManagedNodeCreation(ctx, id)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if item.SelectionID != nil {
		var sourceID sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT access_source_id FROM user_node_selections WHERE id=?`, *item.SelectionID).Scan(&sourceID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if sourceID.Valid {
			var desired, observed string
			var generation, applied int64
			if err := tx.QueryRowContext(ctx, `SELECT desired_state,observed_state,generation,applied_generation FROM user_inbound_access_sources WHERE id=?`, sourceID.Int64).Scan(&desired, &observed, &generation, &applied); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			} else if err == nil && (desired == ManagedDesiredActive || observed != ManagedObservedInactive || generation != applied) {
				return ErrManagedResourceInUse
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM user_inbound_access_sources WHERE id=?`, sourceID.Int64); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_node_selection_usage WHERE selection_id=?`, *item.SelectionID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_node_selections WHERE id=?`, *item.SelectionID); err != nil {
			return err
		}
	}
	if item.OfferID != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM self_service_node_offers WHERE id=? AND owner_username=? AND grant_id=?`, *item.OfferID, item.Username, item.GrantID); err != nil {
			return err
		}
	}
	if supersededMutationID != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM nodes
WHERE username=? AND original_server=? AND inbound_tag=? AND COALESCE(inbound_mutation_id,'')=?`,
			item.Username, supersededServerName, item.InboundTag, supersededMutationID); err != nil {
			return err
		}
	}
	// A crash may leave the deny-first legacy source in place before the
	// selection promotion step. Once the whole inbound is confirmed absent it
	// is safe to remove that tombstone together with its credential snapshot.
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_inbound_access_sources
WHERE source_type=? AND source_id IN (
  SELECT id FROM user_inbound_configs WHERE username=? AND server_id=? AND inbound_tag=?
)`, ManagedSourceLegacyReview, item.Username, item.ServerID, item.InboundTag); err != nil {
		return err
	}
	var credentialConfigID sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM user_inbound_configs WHERE username=? AND server_id=? AND inbound_tag=?`,
		item.Username, item.ServerID, item.InboundTag).Scan(&credentialConfigID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if credentialConfigID.Valid {
		var linked int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM user_node_selections WHERE credential_config_id=?
  UNION ALL
  SELECT 1 FROM user_node_grants WHERE credential_config_id=?
)`, credentialConfigID.Int64, credentialConfigID.Int64).Scan(&linked); err != nil {
			return err
		}
		if linked == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM user_inbound_configs WHERE id=?`, credentialConfigID.Int64); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_managed_node_creations WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *TrafficRepository) CancelUserManagedNodeCreation(ctx context.Context, id int64) error {
	item, err := r.GetUserManagedNodeCreation(ctx, id)
	if err != nil {
		return err
	}
	if item.NodeID != nil || item.OfferID != nil || item.SelectionID != nil {
		return ErrManagedResourceInUse
	}
	_, err = r.db.ExecContext(ctx, `DELETE FROM user_managed_node_creations WHERE id=? AND state='creating'`, id)
	return err
}
