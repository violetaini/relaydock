package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PrepareUserPrivateSubaccountRevokes persists every private routed revoke
// before the control plane publishes a deny snapshot or contacts an Agent.
// Shared routed nodes are excluded because their routing rule can serve more
// than one user and is reconciled by the package access path.
func (r *TrafficRepository) PrepareUserPrivateSubaccountRevokes(ctx context.Context, username string) error {
	if r == nil || r.db == nil || username == "" {
		return ErrManagedInvalidArgument
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET is_active = 0, revoke_pending = 1, activation_pending = 0,
		    updated_at = CURRENT_TIMESTAMP
			WHERE username = ? AND (is_active = 1 OR revoke_pending = 1 OR activation_pending = 1)
		  AND EXISTS (
		      SELECT 1 FROM nodes n
		      WHERE n.id = user_subaccounts.routed_node_id
		        AND n.node_type = 'routed'
		        AND n.routed_owner = 'user'
		        AND n.username = user_subaccounts.username
		  )`, username)
	if err != nil {
		return fmt.Errorf("prepare private routed revokes: %w", err)
	}
	r.invalidateTrafficBillingCache()
	return nil
}

// MarkUserSubaccountRevokePending records the revoke intent before resolving or
// mutating an Agent. Making the row inactive in the same write keeps the local
// authorization state fail-closed across process crashes and lookup failures.
func (r *TrafficRepository) MarkUserSubaccountRevokePending(ctx context.Context, id int64) error {
	if r == nil || r.db == nil || id <= 0 {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET is_active = 0, revoke_pending = 1, activation_pending = 0,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("mark routed revoke pending: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	r.invalidateTrafficBillingCache()
	return nil
}

// MarkUserSubaccountRevokeFailed leaves the credential and an inactive row in
// place. ManagedNodes can retry it after an Agent reconnects.
func (r *TrafficRepository) MarkUserSubaccountRevokeFailed(ctx context.Context, id int64) error {
	if r == nil || r.db == nil || id <= 0 {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET is_active = 0, revoke_pending = 1, activation_pending = 0,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("persist routed revoke retry: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	r.invalidateTrafficBillingCache()
	return nil
}

// CompleteUserSubaccountRevoke clears the pending marker only after the Agent
// has acknowledged the rule/client removal.
func (r *TrafficRepository) CompleteUserSubaccountRevoke(ctx context.Context, id int64) error {
	if r == nil || r.db == nil || id <= 0 {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET is_active = 0, revoke_pending = 0, activation_pending = 0,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("complete routed revoke: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	r.invalidateTrafficBillingCache()
	return nil
}

func (r *TrafficRepository) ListPendingUserSubaccountRevokes(ctx context.Context, limit int) ([]UserSubaccount, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, routed_node_id, email, credential_json, is_active,
		       revoke_pending, activation_pending, created_at, updated_at
		FROM user_subaccounts
		WHERE revoke_pending = 1 AND activation_pending = 0
		ORDER BY updated_at ASC, id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending routed revokes: %w", err)
	}
	defer rows.Close()
	result := make([]UserSubaccount, 0)
	for rows.Next() {
		var sa UserSubaccount
		var active, pending, activationPending int
		if err := rows.Scan(&sa.ID, &sa.Username, &sa.RoutedNodeID, &sa.Email,
			&sa.CredentialJSON, &active, &pending, &activationPending, &sa.CreatedAt, &sa.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan pending routed revoke: %w", err)
		}
		sa.IsActive = active == 1
		sa.RevokePending = pending == 1
		sa.ActivationPending = activationPending == 1
		result = append(result, sa)
	}
	return result, rows.Err()
}

// ReserveUserSubaccountActivation creates the durable desired-active intent
// before any remote rule or client exists. The simultaneous revoke marker keeps
// limiter snapshots explicitly denied until StageUserSubaccountActivationPolicy.
func (r *TrafficRepository) ReserveUserSubaccountActivation(ctx context.Context, sa UserSubaccount) (int64, error) {
	if r == nil || r.db == nil || sa.Username == "" || sa.RoutedNodeID <= 0 || sa.Email == "" || sa.CredentialJSON == "" {
		return 0, ErrManagedInvalidArgument
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_subaccounts (
		    username, routed_node_id, email, credential_json,
		    is_active, revoke_pending, activation_pending, created_at, updated_at
		) VALUES (?, ?, ?, ?, 0, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(routed_node_id, username) DO UPDATE SET
		    email = excluded.email,
		    credential_json = excluded.credential_json,
		    is_active = 0,
		    revoke_pending = 1,
		    activation_pending = 1,
		    updated_at = CURRENT_TIMESTAMP`,
		sa.Username, sa.RoutedNodeID, sa.Email, sa.CredentialJSON)
	if err != nil {
		return 0, fmt.Errorf("reserve routed activation: %w", err)
	}
	stored, err := r.GetUserSubaccount(ctx, sa.RoutedNodeID, sa.Username)
	if err != nil {
		return 0, err
	}
	if stored == nil {
		return 0, sql.ErrNoRows
	}
	r.invalidateTrafficBillingCache()
	return stored.ID, nil
}

// PrepareUserPrivateSubaccountActivations marks inactive private routes as
// desired-active while retaining a deny marker for the activation transaction.
func (r *TrafficRepository) PrepareUserPrivateSubaccountActivations(ctx context.Context, username string) error {
	if r == nil || r.db == nil || username == "" {
		return ErrManagedInvalidArgument
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET is_active = 0, revoke_pending = 1, activation_pending = 1,
		    updated_at = CURRENT_TIMESTAMP
		WHERE username = ?
		  AND (is_active = 0 OR revoke_pending = 1 OR activation_pending = 1)
			  AND EXISTS (
			      SELECT 1 FROM nodes n
			      WHERE n.id = user_subaccounts.routed_node_id
			        AND n.node_type = 'routed'
			        AND n.routed_owner = 'user'
			        AND n.enabled = 1
			        AND n.username = user_subaccounts.username
			  )`, username)
	if err != nil {
		return fmt.Errorf("prepare private routed activations: %w", err)
	}
	r.invalidateTrafficBillingCache()
	return nil
}

// PrepareUserPrivateRoutedDelete atomically records that the routed node must
// never be activated again and that every associated client remains denied
// until ManagedNodes has removed the rule, client, and outbound.
func (r *TrafficRepository) PrepareUserPrivateRoutedDelete(ctx context.Context, nodeID int64, username string) error {
	if r == nil || r.db == nil || nodeID <= 0 || username == "" {
		return ErrManagedInvalidArgument
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var wasEnabled int
	if err := tx.QueryRowContext(ctx, `
		SELECT enabled FROM nodes
		WHERE id = ? AND username = ? AND node_type = 'routed' AND routed_owner = 'user'`,
		nodeID, username).Scan(&wasEnabled); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE nodes SET enabled = 0, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND username = ? AND node_type = 'routed' AND routed_owner = 'user'`,
		nodeID, username)
	if err != nil {
		return fmt.Errorf("mark private routed node deleting: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET is_active = 0, revoke_pending = 1, activation_pending = 0,
		    updated_at = CURRENT_TIMESTAMP
		WHERE routed_node_id = ?`, nodeID)
	if err != nil {
		return fmt.Errorf("mark private routed delete revoke: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	if wasEnabled != 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_routed_outbound_actions(username, action) VALUES(?, 'delete')`, username); err != nil {
			return fmt.Errorf("record private routed delete action: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.invalidateTrafficBillingCache()
	return nil
}

// FinalizeUserPrivateRoutedDelete removes both retry authority and node metadata
// in one transaction. user_subaccounts intentionally has no routed-node foreign
// key, so callers must not use DeleteRoutedNode for this lifecycle transition.
func (r *TrafficRepository) FinalizeUserPrivateRoutedDelete(ctx context.Context, nodeID int64, username string) error {
	if r == nil || r.db == nil || nodeID <= 0 || username == "" {
		return ErrManagedInvalidArgument
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM user_subaccounts WHERE routed_node_id = ?`, nodeID); err != nil {
		return fmt.Errorf("delete private routed subaccounts: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		DELETE FROM nodes
		WHERE id = ? AND username = ? AND node_type = 'routed'
		  AND routed_owner = 'user' AND enabled = 0`, nodeID, username)
	if err != nil {
		return fmt.Errorf("delete private routed node: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.invalidateTrafficBillingCache()
	return nil
}

// StageUserSubaccountActivationPolicy switches the database-derived limiter
// row to normal while the durable activation intent remains pending. The caller
// must receive a checked limiter ACK before adding the remote client.
func (r *TrafficRepository) StageUserSubaccountActivationPolicy(ctx context.Context, id int64) error {
	return r.updateUserSubaccountActivationState(ctx, id, 0, 0, 1, "stage routed activation policy")
}

// FailUserSubaccountActivation restores the explicit deny while retaining the
// desired-active marker for ManagedNodes retry.
func (r *TrafficRepository) FailUserSubaccountActivation(ctx context.Context, id int64) error {
	return r.updateUserSubaccountActivationState(ctx, id, 0, 1, 1, "fail routed activation")
}

// CompleteUserSubaccountActivation publishes the active state only after rule,
// limiter, and client mutations have all been acknowledged without warnings.
func (r *TrafficRepository) CompleteUserSubaccountActivation(ctx context.Context, id int64) error {
	return r.updateUserSubaccountActivationState(ctx, id, 1, 0, 0, "complete routed activation")
}

func (r *TrafficRepository) updateUserSubaccountActivationState(
	ctx context.Context, id int64, active, revokePending, activationPending int, label string,
) error {
	if r == nil || r.db == nil || id <= 0 {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET is_active = ?, revoke_pending = ?, activation_pending = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, active, revokePending, activationPending, id)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	r.invalidateTrafficBillingCache()
	return nil
}

func (r *TrafficRepository) ListPendingUserSubaccountActivations(ctx context.Context, limit int) ([]UserSubaccount, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, routed_node_id, email, credential_json, is_active,
		       revoke_pending, activation_pending, created_at, updated_at
		FROM user_subaccounts
		WHERE activation_pending = 1
		  AND EXISTS (
		      SELECT 1 FROM nodes n
		      WHERE n.id = user_subaccounts.routed_node_id
		        AND n.node_type = 'routed' AND n.routed_owner = 'user'
		        AND n.enabled = 1
		  )
		ORDER BY updated_at ASC, id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending routed activations: %w", err)
	}
	defer rows.Close()
	result := make([]UserSubaccount, 0)
	for rows.Next() {
		var sa UserSubaccount
		var active, revokePending, activationPending int
		if err := rows.Scan(&sa.ID, &sa.Username, &sa.RoutedNodeID, &sa.Email,
			&sa.CredentialJSON, &active, &revokePending, &activationPending,
			&sa.CreatedAt, &sa.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan pending routed activation: %w", err)
		}
		sa.IsActive = active == 1
		sa.RevokePending = revokePending == 1
		sa.ActivationPending = activationPending == 1
		result = append(result, sa)
	}
	return result, rows.Err()
}

func (r *TrafficRepository) IsUserSubaccountActivationPending(ctx context.Context, username string) (bool, error) {
	if r == nil || r.db == nil || username == "" {
		return false, ErrManagedInvalidArgument
	}
	var pending int
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM user_subaccounts
		WHERE username = ? AND activation_pending = 1
		  AND EXISTS (
		      SELECT 1 FROM nodes n
		      WHERE n.id = user_subaccounts.routed_node_id
		        AND n.node_type = 'routed' AND n.routed_owner = 'user'
		        AND n.enabled = 1
		  )
	)`, username).Scan(&pending)
	return pending != 0, err
}

func (r *TrafficRepository) UpdateUserSubaccountCredential(ctx context.Context, id int64, credentialJSON string) error {
	if r == nil || r.db == nil || id <= 0 || credentialJSON == "" {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE user_subaccounts
		SET credential_json = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, credentialJSON, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RestoreUserOverLimitRevokePending is used when a failed over-limit cleanup
// is compensated. The deny and its retry marker must remain authoritative;
// clearing only the marker would let a later limiter push expose the user.
func (r *TrafficRepository) RestoreUserOverLimitRevokePending(ctx context.Context, username string) error {
	if r == nil || r.db == nil {
		return ErrManagedInvalidArgument
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET is_over_limit = 1, over_limit_revoke_pending = 1
		WHERE username = ?`, username)
	return err
}

// BeginUserOverLimitRestore keeps a durable retry marker while allowing the
// normal limiter snapshot needed immediately before client activation.
func (r *TrafficRepository) BeginUserOverLimitRestore(ctx context.Context, username string) error {
	if r == nil || r.db == nil || username == "" {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET is_over_limit = 0, over_limit_revoke_pending = 1
		WHERE username = ?`, username)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *TrafficRepository) CompleteUserOverLimitRestore(ctx context.Context, username string) error {
	if r == nil || r.db == nil || username == "" {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET over_limit_revoke_pending = 0
		WHERE username = ? AND is_over_limit = 0`, username)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrUserNotFound
	}
	return nil
}
