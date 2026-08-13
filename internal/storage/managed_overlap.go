package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type managedSQLQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type managedInboundKey struct {
	serverID   int64
	inboundTag string
}

// NextManagedMonthlyReset returns the first configured local reset boundary
// strictly after now. Reset days are intentionally limited to 1..28 so the
// schedule exists in every month.
func NextManagedMonthlyReset(now time.Time, day int, timezone string) time.Time {
	location, err := time.LoadLocation(strings.TrimSpace(timezone))
	if err != nil {
		location = time.UTC
	}
	if day < 1 {
		day = 1
	}
	if day > 28 {
		day = 28
	}
	local := now.In(location)
	candidate := time.Date(local.Year(), local.Month(), day, 0, 0, 0, 0, location)
	if !candidate.After(local) {
		candidate = candidate.AddDate(0, 1, 0)
	}
	return candidate.UTC()
}

func managedPackageInboundKeys(ctx context.Context, q managedSQLQueryer, nodeIDs []int64) (map[managedInboundKey]struct{}, error) {
	keys := make(map[managedInboundKey]struct{})
	for _, nodeID := range nodeIDs {
		if nodeID <= 0 {
			continue
		}
		rows, err := q.QueryContext(ctx, `SELECT rs.id, COALESCE(n.inbound_tag, '')
FROM nodes n
JOIN remote_servers rs ON rs.name = COALESCE(n.original_server, '')
WHERE n.id = ? AND COALESCE(n.node_type, 'physical') != 'routed'`, nodeID)
		if err != nil {
			return nil, fmt.Errorf("resolve package managed inbounds: %w", err)
		}
		for rows.Next() {
			var key managedInboundKey
			if err := rows.Scan(&key.serverID, &key.inboundTag); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan package managed inbound: %w", err)
			}
			key.inboundTag = strings.TrimSpace(key.inboundTag)
			if key.serverID > 0 && key.inboundTag != "" {
				keys[key] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("iterate package managed inbounds: %w", err)
		}
		_ = rows.Close()
	}
	return keys, nil
}

func managedPackageNodes(ctx context.Context, q managedSQLQueryer, packageID int64) ([]int64, error) {
	var raw string
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(nodes, '[]') FROM packages WHERE id = ?`, packageID).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPackageNotFound
	} else if err != nil {
		return nil, fmt.Errorf("read package nodes for managed overlap: %w", err)
	}
	var nodes []int64
	if err := json.Unmarshal([]byte(raw), &nodes); err != nil {
		return nil, fmt.Errorf("decode package nodes for managed overlap: %w", err)
	}
	return nodes, nil
}

func userPackageContainsManagedInbound(ctx context.Context, q managedSQLQueryer, username string, serverID int64, inboundTag string, now time.Time) (bool, error) {
	var packageID int64
	var packageStart, packageEnd sql.NullTime
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(package_id, 0), package_start_date, package_end_date
FROM users WHERE username = ?`, username).Scan(&packageID, &packageStart, &packageEnd); errors.Is(err, sql.ErrNoRows) {
		return false, ErrUserNotFound
	} else if err != nil {
		return false, fmt.Errorf("read user package for managed overlap: %w", err)
	}
	if packageID <= 0 || packageStart.Valid && now.Before(packageStart.Time) || packageEnd.Valid && !now.Before(packageEnd.Time) {
		return false, nil
	}
	nodes, err := managedPackageNodes(ctx, q, packageID)
	if err != nil {
		return false, err
	}
	keys, err := managedPackageInboundKeys(ctx, q, nodes)
	if err != nil {
		return false, err
	}
	_, exists := keys[managedInboundKey{serverID: serverID, inboundTag: strings.TrimSpace(inboundTag)}]
	return exists, nil
}

func currentUserPackageConflictsWithManagedSelections(ctx context.Context, q managedSQLQueryer, username string, grantID int64, now time.Time) error {
	var packageID int64
	var packageStart, packageEnd sql.NullTime
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(package_id, 0), package_start_date, package_end_date
FROM users WHERE username = ?`, username).Scan(&packageID, &packageStart, &packageEnd); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("read user package for managed overlap: %w", err)
	}
	if packageID <= 0 || packageStart.Valid && now.Before(packageStart.Time) || packageEnd.Valid && !now.Before(packageEnd.Time) {
		return nil
	}
	nodes, err := managedPackageNodes(ctx, q, packageID)
	if err != nil {
		return err
	}
	return packageNodesConflictWithManagedSelections(ctx, q, username, nodes, grantID)
}

func packageNodesConflictWithManagedSelections(ctx context.Context, q managedSQLQueryer, username string, nodeIDs []int64, grantID int64) error {
	keys, err := managedPackageInboundKeys(ctx, q, nodeIDs)
	if err != nil || len(keys) == 0 {
		return err
	}
	query := `SELECT o.server_id, o.inbound_tag
FROM user_node_selections s
JOIN user_server_grants g ON g.id = s.grant_id
JOIN self_service_node_offers o ON o.id = s.offer_id
WHERE g.username = ? AND s.desired_enabled = 1`
	args := []any{username}
	if grantID > 0 {
		query += ` AND g.id = ?`
		args = append(args, grantID)
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("list selections for package overlap: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key managedInboundKey
		if err := rows.Scan(&key.serverID, &key.inboundTag); err != nil {
			return fmt.Errorf("scan selection for package overlap: %w", err)
		}
		key.inboundTag = strings.TrimSpace(key.inboundTag)
		if _, exists := keys[key]; exists {
			return fmt.Errorf("%w: server=%d inbound=%s", ErrManagedAccessConflict, key.serverID, key.inboundTag)
		}
	}
	return rows.Err()
}

func packageNodesConflictWithManualSelections(ctx context.Context, q managedSQLQueryer, username string, nodeIDs []int64) error {
	keys, err := managedPackageInboundKeys(ctx, q, nodeIDs)
	if err != nil || len(keys) == 0 {
		return err
	}
	rows, err := q.QueryContext(ctx, `SELECT o.server_id, o.inbound_tag
FROM user_node_selections s
JOIN user_server_grants g ON g.id = s.grant_id
JOIN self_service_node_offers o ON o.id = s.offer_id
WHERE g.username = ? AND s.desired_enabled = 1 AND COALESCE(g.source_type, 'manual') != 'package'`, username)
	if err != nil {
		return fmt.Errorf("list manual selections for package overlap: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key managedInboundKey
		if err := rows.Scan(&key.serverID, &key.inboundTag); err != nil {
			return err
		}
		key.inboundTag = strings.TrimSpace(key.inboundTag)
		if _, exists := keys[key]; exists {
			return fmt.Errorf("%w: server=%d inbound=%s", ErrManagedAccessConflict, key.serverID, key.inboundTag)
		}
	}
	return rows.Err()
}

func (r *TrafficRepository) packageUpdateConflictsWithManagedSelections(ctx context.Context, packageID int64, nodeIDs []int64) error {
	rows, err := r.db.QueryContext(ctx, `SELECT username FROM users WHERE package_id = ?`, packageID)
	if err != nil {
		return fmt.Errorf("list package users for managed overlap: %w", err)
	}
	var usernames []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan package user for managed overlap: %w", err)
		}
		usernames = append(usernames, username)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate package users for managed overlap: %w", err)
	}
	_ = rows.Close()
	for _, username := range usernames {
		if err := packageNodesConflictWithManualSelections(ctx, r.db, username, nodeIDs); err != nil {
			return err
		}
	}
	return nil
}
