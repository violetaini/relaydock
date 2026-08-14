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
	AuthorizationModePackage = "package"
	AuthorizationModeCustom  = "custom"
)

var (
	ErrInvalidAuthorizationMode  = errors.New("invalid user authorization mode")
	ErrAuthorizationModeConflict = errors.New("user authorization mode conflicts with requested operation")
)

func NormalizeAuthorizationMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case AuthorizationModePackage, AuthorizationModeCustom:
		return mode, nil
	default:
		return "", ErrInvalidAuthorizationMode
	}
}

func userAuthorizationMode(ctx context.Context, q managedSQLQueryer, username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", ErrManagedInvalidArgument
	}
	var mode string
	err := q.QueryRowContext(ctx, `SELECT CASE
    WHEN COALESCE(package_id, 0) > 0 THEN 'package'
    ELSE COALESCE(NULLIF(LOWER(TRIM(authorization_mode)), ''), 'custom')
END FROM users WHERE username = ?`, username).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read user authorization mode: %w", err)
	}
	return NormalizeAuthorizationMode(mode)
}

func requireUserAuthorizationMode(ctx context.Context, q managedSQLQueryer, username, required string) error {
	required, err := NormalizeAuthorizationMode(required)
	if err != nil {
		return err
	}
	mode, err := userAuthorizationMode(ctx, q, username)
	if err != nil {
		return err
	}
	if mode != required {
		return ErrAuthorizationModeConflict
	}
	return nil
}

// GetUserAuthorizationMode returns the effective mode. A legacy package_id is
// authoritative so partially migrated databases fail closed for manual writes.
func (r *TrafficRepository) GetUserAuthorizationMode(ctx context.Context, username string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	return userAuthorizationMode(ctx, r.db, username)
}

func activeManualAuthorizationExists(ctx context.Context, q managedSQLQueryer, username string) (bool, error) {
	var exists int
	err := q.QueryRowContext(ctx, `SELECT EXISTS(
    SELECT 1 FROM user_node_grants g
    JOIN user_inbound_access_sources s ON s.id = g.access_source_id
    WHERE g.username = ? AND COALESCE(g.source_type, 'manual') = 'manual'
      AND s.source_type = 'direct' AND s.desired_state = 'active'
    UNION ALL
    SELECT 1 FROM user_server_grants g
    WHERE g.username = ? AND COALESCE(g.source_type, 'manual') = 'manual' AND g.enabled = 1
    UNION ALL
    SELECT 1 FROM user_tunnel_grants g
    WHERE g.username = ? AND COALESCE(g.source_type, 'manual') = 'manual' AND g.enabled = 1
)`, username, username, username).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check active manual authorization: %w", err)
	}
	return exists != 0, nil
}

// PreparePackageAuthorizationTransition revokes every active custom grant in a
// single local transaction and moves the account to package mode before remote
// reconciliation starts. The package_id remains empty until assignment commits,
// so the account is fail-closed and legacy custom writes are rejected while a
// transition is in flight. A failed transition can be rolled back with
// CancelPackageAuthorizationTransition after the caller replays its snapshot.
func (r *TrafficRepository) PreparePackageAuthorizationTransition(ctx context.Context, username string) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin package authorization transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := requireUserAuthorizationMode(ctx, tx, username, AuthorizationModeCustom); err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections
SET desired_enabled=0,deactivated_at=COALESCE(deactivated_at,?),updated_at=?
WHERE desired_enabled=1 AND grant_id IN (
    SELECT id FROM user_server_grants
    WHERE username=? AND COALESCE(source_type,'manual')='manual'
)`, now, now, username); err != nil {
		return fmt.Errorf("deactivate custom server selections: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources
SET desired_state='inactive',suspend_reason='admin_disabled',generation=generation+1,
    retry_count=0,next_retry_at=NULL,last_error='',updated_at=?
WHERE source_type='selection'
  AND (desired_state!='inactive' OR suspend_reason!='admin_disabled')
  AND source_id IN (
      SELECT s.id FROM user_node_selections s
      JOIN user_server_grants g ON g.id=s.grant_id
      WHERE g.username=? AND COALESCE(g.source_type,'manual')='manual'
  )`, now, username); err != nil {
		return fmt.Errorf("deactivate custom server access sources: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_server_grants
SET enabled=0,expires_at=CASE WHEN expires_at IS NULL OR expires_at>? THEN ? ELSE expires_at END,
    version=version+1,updated_at=?
WHERE username=? AND COALESCE(source_type,'manual')='manual' AND enabled=1`, now, now, now, username); err != nil {
		return fmt.Errorf("deactivate custom server grants: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_grants
SET version=version+1,updated_at=?
WHERE username=? AND COALESCE(source_type,'manual')='manual'
  AND access_source_id IN (
      SELECT id FROM user_inbound_access_sources
      WHERE desired_state!='inactive' OR suspend_reason!='admin_disabled'
  )`, now, username); err != nil {
		return fmt.Errorf("version custom direct node grants: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources
SET desired_state='inactive',suspend_reason='admin_disabled',generation=generation+1,
    retry_count=0,next_retry_at=NULL,last_error='',updated_at=?
WHERE (desired_state!='inactive' OR suspend_reason!='admin_disabled')
  AND id IN (
      SELECT g.access_source_id FROM user_node_grants g
      WHERE g.username=? AND COALESCE(g.source_type,'manual')='manual'
        AND g.access_source_id IS NOT NULL
  )`, now, username); err != nil {
		return fmt.Errorf("deactivate custom direct node grants: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources
SET desired_state='inactive',suspend_reason='admin_disabled',generation=generation+1,
    retry_count=0,next_retry_at=NULL,last_error='',updated_at=?
WHERE username=? AND source_type='legacy_review'
  AND (desired_state!='inactive' OR suspend_reason!='admin_disabled')`, now, username); err != nil {
		return fmt.Errorf("deactivate legacy custom access sources: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_rules
SET desired_state='inactive',suspend_reason='grant_inactive',generation=generation+1,updated_at=?
WHERE desired_state!='deleted'
  AND (desired_state!='inactive' OR suspend_reason!='grant_inactive')
  AND grant_id IN (
      SELECT id FROM user_tunnel_grants
      WHERE username=? AND COALESCE(source_type,'manual')='manual'
  )`, now, username); err != nil {
		return fmt.Errorf("deactivate custom forwarding rules: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_hops
SET desired_state='inactive',generation=generation+1,updated_at=?
WHERE desired_state!='inactive' AND forward_id IN (
    SELECT f.id FROM user_forward_rules f
    JOIN user_tunnel_grants g ON g.id=f.grant_id
    WHERE f.desired_state!='deleted' AND g.username=?
      AND COALESCE(g.source_type,'manual')='manual'
)`, now, username); err != nil {
		return fmt.Errorf("deactivate custom forwarding hops: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_tunnel_grants
SET enabled=0,expires_at=CASE WHEN expires_at IS NULL OR expires_at>? THEN ? ELSE expires_at END,
    version=version+1,updated_at=?
WHERE username=? AND COALESCE(source_type,'manual')='manual' AND enabled=1`, now, now, now, username); err != nil {
		return fmt.Errorf("deactivate custom tunnel grants: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET authorization_mode='package',updated_at=? WHERE username=? AND COALESCE(package_id,0)=0`, now, username); err != nil {
		return fmt.Errorf("mark package authorization transition: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit package authorization transition: %w", err)
	}
	r.invalidateTrafficBillingCache()
	return nil
}

// CancelPackageAuthorizationTransition restores the durable account mode. The
// caller is responsible for replaying any custom grant snapshot it captured.
func (r *TrafficRepository) CancelPackageAuthorizationTransition(ctx context.Context, username string) error {
	return r.RemovePackageFromUser(ctx, username)
}

// migrateUserAuthorizationModes installs the account-level mode after every
// grant table exists, then turns grants from the losing source into durable
// inactive tombstones for the existing reconcilers to remove remotely.
func (r *TrafficRepository) migrateUserAuthorizationModes() error {
	if err := r.ensureUserColumn("authorization_mode", "TEXT NOT NULL DEFAULT 'custom'"); err != nil {
		return fmt.Errorf("migrate users.authorization_mode: %w", err)
	}
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin authorization mode migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Existing package assignments take precedence over the ALTER TABLE default.
	if _, err := tx.Exec(`UPDATE users SET authorization_mode = CASE
	    WHEN COALESCE(package_id, 0) > 0 THEN 'package' ELSE 'custom'
	END`); err != nil {
		return fmt.Errorf("backfill user authorization modes: %w", err)
	}

	now := time.Now().UTC()
	oppositeServerGrant := `(u.authorization_mode = 'package' AND COALESCE(g.source_type, 'manual') = 'manual')
 OR (u.authorization_mode = 'custom' AND COALESCE(g.source_type, 'manual') = 'package')`
	if _, err := tx.Exec(`UPDATE user_node_selections
SET desired_enabled = 0,
    deactivated_at = COALESCE(deactivated_at, ?),
    updated_at = ?
WHERE desired_enabled = 1 AND grant_id IN (
    SELECT g.id FROM user_server_grants g JOIN users u ON u.username = g.username
    WHERE `+oppositeServerGrant+`
)`, now, now); err != nil {
		return fmt.Errorf("deactivate opposite server selections: %w", err)
	}
	if _, err := tx.Exec(`UPDATE user_inbound_access_sources
SET desired_state = 'inactive', suspend_reason = 'admin_disabled',
    generation = generation + 1, retry_count = 0, next_retry_at = NULL,
    last_error = '', updated_at = ?
WHERE source_type = 'selection'
  AND (desired_state != 'inactive' OR suspend_reason != 'admin_disabled')
  AND source_id IN (
      SELECT s.id FROM user_node_selections s
      JOIN user_server_grants g ON g.id = s.grant_id
      JOIN users u ON u.username = g.username
      WHERE `+oppositeServerGrant+`
  )`, now); err != nil {
		return fmt.Errorf("deactivate opposite server access sources: %w", err)
	}
	if _, err := tx.Exec(`UPDATE user_server_grants AS g
SET enabled = 0,
    expires_at = CASE WHEN expires_at IS NULL OR expires_at > ? THEN ? ELSE expires_at END,
    version = version + 1, updated_at = ?
WHERE enabled = 1 AND EXISTS (
    SELECT 1 FROM users u WHERE u.username = g.username AND (`+oppositeServerGrant+`)
)`, now, now, now); err != nil {
		return fmt.Errorf("deactivate opposite server grants: %w", err)
	}

	oppositeDirectGrant := `(u.authorization_mode = 'package' AND COALESCE(g.source_type, 'manual') = 'manual')
 OR (u.authorization_mode = 'custom' AND COALESCE(g.source_type, 'manual') = 'package')`
	if _, err := tx.Exec(`UPDATE user_node_grants AS g
SET version = version + 1, updated_at = ?
WHERE access_source_id IN (
    SELECT id FROM user_inbound_access_sources
    WHERE desired_state != 'inactive' OR suspend_reason != 'admin_disabled'
  ) AND EXISTS (
    SELECT 1 FROM users u WHERE u.username = g.username AND (`+oppositeDirectGrant+`)
)`, now); err != nil {
		return fmt.Errorf("version opposite direct node grants: %w", err)
	}
	if _, err := tx.Exec(`UPDATE user_inbound_access_sources
SET desired_state = 'inactive', suspend_reason = 'admin_disabled',
    generation = generation + 1, retry_count = 0, next_retry_at = NULL,
    last_error = '', updated_at = ?
WHERE (desired_state != 'inactive' OR suspend_reason != 'admin_disabled')
  AND id IN (
      SELECT g.access_source_id FROM user_node_grants g
      JOIN users u ON u.username = g.username
      WHERE g.access_source_id IS NOT NULL AND (`+oppositeDirectGrant+`)
  )`, now); err != nil {
		return fmt.Errorf("deactivate opposite direct node grants: %w", err)
	}
	// Package access sources from releases before source-tracked node grants are
	// still package entitlements and must not survive a switch to custom mode.
	if _, err := tx.Exec(`UPDATE user_inbound_access_sources
SET desired_state = 'inactive', suspend_reason = 'admin_disabled',
    generation = generation + 1, retry_count = 0, next_retry_at = NULL,
    last_error = '', updated_at = ?
WHERE source_type = 'package'
  AND (desired_state != 'inactive' OR suspend_reason != 'admin_disabled')
  AND username IN (SELECT username FROM users WHERE authorization_mode = 'custom')`, now); err != nil {
		return fmt.Errorf("deactivate legacy package access sources: %w", err)
	}
	if _, err := tx.Exec(`UPDATE user_inbound_access_sources
SET desired_state = 'inactive', suspend_reason = 'admin_disabled',
    generation = generation + 1, retry_count = 0, next_retry_at = NULL,
    last_error = '', updated_at = ?
WHERE source_type = 'legacy_review'
  AND (desired_state != 'inactive' OR suspend_reason != 'admin_disabled')
  AND username IN (SELECT username FROM users WHERE authorization_mode = 'package')`, now); err != nil {
		return fmt.Errorf("deactivate legacy manual access sources: %w", err)
	}

	oppositeTunnelGrant := `(u.authorization_mode = 'package' AND COALESCE(g.source_type, 'manual') = 'manual')
 OR (u.authorization_mode = 'custom' AND COALESCE(g.source_type, 'manual') = 'package')`
	if _, err := tx.Exec(`UPDATE user_forward_rules
SET desired_state = 'inactive', suspend_reason = 'grant_inactive',
    generation = generation + 1, updated_at = ?
WHERE desired_state != 'deleted'
  AND (desired_state != 'inactive' OR suspend_reason != 'grant_inactive')
  AND grant_id IN (
      SELECT g.id FROM user_tunnel_grants g JOIN users u ON u.username = g.username
      WHERE `+oppositeTunnelGrant+`
  )`, now); err != nil {
		return fmt.Errorf("deactivate opposite forwarding rules: %w", err)
	}
	if _, err := tx.Exec(`UPDATE user_forward_hops
SET desired_state = 'inactive', generation = generation + 1, updated_at = ?
WHERE desired_state != 'inactive' AND forward_id IN (
    SELECT f.id FROM user_forward_rules f
    JOIN user_tunnel_grants g ON g.id = f.grant_id
    JOIN users u ON u.username = g.username
    WHERE f.desired_state != 'deleted' AND (`+oppositeTunnelGrant+`)
)`, now); err != nil {
		return fmt.Errorf("deactivate opposite forwarding hops: %w", err)
	}
	if _, err := tx.Exec(`UPDATE user_tunnel_grants AS g
SET enabled = 0,
    expires_at = CASE WHEN expires_at IS NULL OR expires_at > ? THEN ? ELSE expires_at END,
    version = version + 1, updated_at = ?
WHERE enabled = 1 AND EXISTS (
    SELECT 1 FROM users u WHERE u.username = g.username AND (`+oppositeTunnelGrant+`)
)`, now, now, now); err != nil {
		return fmt.Errorf("deactivate opposite tunnel grants: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit authorization mode migration: %w", err)
	}
	return nil
}
