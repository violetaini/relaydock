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

// validateAndNormalizePackageBundle validates resource references and applies
// the same defaults used by individually-created grants.
func (r *TrafficRepository) validateAndNormalizePackageBundle(ctx context.Context, pkg *Package) error {
	seenServers := make(map[int64]struct{}, len(pkg.ServerGrants))
	for i := range pkg.ServerGrants {
		entry := &pkg.ServerGrants[i]
		if _, duplicate := seenServers[entry.ServerID]; entry.ServerID <= 0 || duplicate {
			return fmt.Errorf("invalid package server grant for server %d", entry.ServerID)
		}
		seenServers[entry.ServerID] = struct{}{}
		packageID := pkg.ID
		if packageID <= 0 {
			packageID = 1
		}
		model, err := normalizeGrant(UserServerGrant{
			Username: "package-template", ServerID: entry.ServerID, Enabled: true,
			StartsAt: time.Unix(1, 0).UTC(), MaxActiveNodes: entry.MaxActiveNodes,
			SpeedLimitMbps: entry.SpeedLimitMbps, ConnectionLimit: entry.ConnectionLimit,
			TrafficLimitBytes: entry.TrafficLimitBytes, BillingMode: entry.BillingMode,
			ResetPolicy: entry.ResetPolicy, ResetDay: entry.ResetDay,
			BillingTimezone: "Asia/Shanghai", AllowedProtocols: entry.AllowedProtocols,
			AllowedProtocolProfiles: entry.AllowedProtocolProfiles, CreatedBy: "package-template",
			SourceType: GrantSourcePackage, SourcePackageID: &packageID,
		})
		if err != nil {
			return fmt.Errorf("invalid package server grant for server %d: %w", entry.ServerID, err)
		}
		var exists int
		if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remote_servers WHERE id = ?)`, entry.ServerID).Scan(&exists); err != nil {
			return fmt.Errorf("validate package server grant: %w", err)
		}
		if exists == 0 {
			return ErrRemoteServerNotFound
		}
		entry.BillingMode = model.BillingMode
		entry.ResetPolicy = model.ResetPolicy
		entry.ResetDay = model.ResetDay
		entry.AllowedProtocols = model.AllowedProtocols
		entry.AllowedProtocolProfiles = model.AllowedProtocolProfiles
	}

	seenTunnels := make(map[int64]struct{}, len(pkg.ForwardingGrants))
	for i := range pkg.ForwardingGrants {
		entry := &pkg.ForwardingGrants[i]
		if _, duplicate := seenTunnels[entry.TunnelID]; entry.TunnelID <= 0 || duplicate {
			return fmt.Errorf("invalid package forwarding grant for tunnel %d", entry.TunnelID)
		}
		seenTunnels[entry.TunnelID] = struct{}{}
		packageID := pkg.ID
		if packageID <= 0 {
			packageID = 1
		}
		model := UserTunnelGrant{
			Username: "package-template", TunnelID: entry.TunnelID, Enabled: true,
			StartsAt: time.Unix(1, 0).UTC(), MaxActiveForwards: entry.MaxActiveForwards,
			PerForwardSpeedMbps:       entry.PerForwardSpeedMbps,
			PerForwardConnectionLimit: entry.PerForwardConnectionLimit,
			TrafficLimitBytes:         entry.TrafficLimitBytes,
			BillingModeOverride:       entry.BillingModeOverride, AllowManagedTarget: true,
			CreatedBy: "package-template", SourceType: GrantSourcePackage,
			SourcePackageID: &packageID,
		}
		if err := normalizeTunnelGrant(&model); err != nil {
			return fmt.Errorf("invalid package forwarding grant for tunnel %d: %w", entry.TunnelID, err)
		}
		var exists int
		if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tunnel_templates WHERE id = ?)`, entry.TunnelID).Scan(&exists); err != nil {
			return fmt.Errorf("validate package forwarding grant: %w", err)
		}
		if exists == 0 {
			return ErrTunnelTemplateNotFound
		}
	}
	if pkg.ServerGrants == nil {
		pkg.ServerGrants = []PackageServerGrant{}
	}
	if pkg.ForwardingGrants == nil {
		pkg.ForwardingGrants = []PackageForwardingGrant{}
	}
	return nil
}

func packageGrantWarning(kind string, resourceID int64) string {
	return fmt.Sprintf("%s %d already has a manual grant; package grant was skipped", kind, resourceID)
}

// syncPackageBundleGrantsTx materializes the current package bundle. Manual
// grants always win and are never mutated. When switching packages the old
// package children are first made inactive, so selections and forwards cannot
// silently survive the old authorization.
func (r *TrafficRepository) syncPackageBundleGrantsTx(ctx context.Context, tx *sql.Tx, username string, oldPackageID int64, pkg *Package, startsAt, endsAt time.Time) ([]string, error) {
	now := time.Now().UTC()
	newPackageID := int64(0)
	if pkg != nil {
		newPackageID = pkg.ID
	}
	if oldPackageID > 0 && oldPackageID != newPackageID {
		if err := revokePackageBundleGrantsTx(ctx, tx, username, oldPackageID, now); err != nil {
			return nil, err
		}
	}
	if pkg == nil {
		return nil, nil
	}

	warnings := make([]string, 0)
	desiredServers := make(map[int64]PackageServerGrant, len(pkg.ServerGrants))
	for _, entry := range pkg.ServerGrants {
		desiredServers[entry.ServerID] = entry
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, server_id FROM user_server_grants
WHERE username = ? AND source_type = 'package' AND source_package_id = ?`, username, pkg.ID)
	if err != nil {
		return nil, fmt.Errorf("list package server grants: %w", err)
	}
	var removedServerGrantIDs []int64
	for rows.Next() {
		var id, serverID int64
		if err := rows.Scan(&id, &serverID); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if _, keep := desiredServers[serverID]; !keep {
			removedServerGrantIDs = append(removedServerGrantIDs, id)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, id := range removedServerGrantIDs {
		if err := removePackageServerGrantTx(ctx, tx, id, now); err != nil {
			return nil, err
		}
	}

	activeAtApply := !now.Before(startsAt) && now.Before(endsAt)
	for _, entry := range pkg.ServerGrants {
		var id int64
		var sourceType string
		var sourcePackageID sql.NullInt64
		var enabled int
		err := tx.QueryRowContext(ctx, `SELECT id, COALESCE(source_type, 'manual'), source_package_id, enabled
FROM user_server_grants WHERE username = ? AND server_id = ?`, username, entry.ServerID).Scan(&id, &sourceType, &sourcePackageID, &enabled)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("read existing server grant: %w", err)
		}
		transferablePackageGrant := err == nil && sourceType == GrantSourcePackage && sourcePackageID.Valid &&
			(sourcePackageID.Int64 == pkg.ID || (oldPackageID > 0 && sourcePackageID.Int64 == oldPackageID))
		adoptableManualTombstone := err == nil && sourceType == GrantSourceManual && enabled == 0
		if err == nil && !transferablePackageGrant && !adoptableManualTombstone {
			warnings = append(warnings, packageGrantWarning("server", entry.ServerID))
			continue
		}
		nextReset := any(nil)
		if entry.ResetPolicy == ManagedResetMonthly {
			base := now
			if startsAt.After(base) {
				base = startsAt
			}
			nextReset = NextManagedMonthlyReset(base, entry.ResetDay, "Asia/Shanghai")
		}
		protocols, _ := jsonMarshal(entry.AllowedProtocols)
		profiles, _ := jsonMarshal(entry.AllowedProtocolProfiles)
		if errors.Is(err, sql.ErrNoRows) {
			result, insertErr := tx.ExecContext(ctx, `INSERT INTO user_server_grants(
username,server_id,enabled,starts_at,expires_at,max_active_nodes,speed_limit_mbps,connection_limit,
traffic_limit_bytes,billing_mode,reset_policy,reset_day,billing_timezone,next_reset_at,
allowed_protocols_json,allowed_protocol_profiles_json,source_type,source_package_id,version,created_by)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)`, username, entry.ServerID, 1, startsAt.UTC(), endsAt.UTC(),
				entry.MaxActiveNodes, entry.SpeedLimitMbps, entry.ConnectionLimit, entry.TrafficLimitBytes,
				entry.BillingMode, entry.ResetPolicy, entry.ResetDay, "Asia/Shanghai", nextReset,
				protocols, profiles, GrantSourcePackage, pkg.ID, "package")
			if insertErr != nil {
				return nil, fmt.Errorf("create package server grant: %w", insertErr)
			}
			id, _ = result.LastInsertId()
		} else {
			// Match UpdateUserServerGrant semantics. A template change can narrow
			// protocol policy, but it must revoke newly-disallowed selections and
			// must not silently exceed the new active-node cap.
			disallowedSelectionIDs := make([]int64, 0)
			selectionRows, queryErr := tx.QueryContext(ctx, `SELECT s.id, COALESCE(n.protocol,''), COALESCE(n.clash_config,''), COALESCE(o.inbound_tag,'')
FROM user_node_selections s
JOIN self_service_node_offers o ON o.id=s.offer_id
JOIN nodes n ON n.id=o.node_id
WHERE s.grant_id=? AND s.desired_enabled=1`, id)
			if queryErr != nil {
				return nil, fmt.Errorf("list package server selections: %w", queryErr)
			}
			policyGrant := UserServerGrant{
				AllowedProtocols: entry.AllowedProtocols, AllowedProtocolProfiles: entry.AllowedProtocolProfiles,
			}
			for selectionRows.Next() {
				var selectionID int64
				var protocol, clashConfig, inboundTag string
				if scanErr := selectionRows.Scan(&selectionID, &protocol, &clashConfig, &inboundTag); scanErr != nil {
					_ = selectionRows.Close()
					return nil, fmt.Errorf("scan package server selection: %w", scanErr)
				}
				if !policyGrant.AllowsNodeProtocol(protocol, clashConfig) || !SelfServiceNodeProtocolEligible(protocol, clashConfig) ||
					strings.HasPrefix(strings.ToLower(strings.TrimSpace(inboundTag)), "anydoor-") {
					disallowedSelectionIDs = append(disallowedSelectionIDs, selectionID)
				}
			}
			if queryErr := selectionRows.Close(); queryErr != nil {
				return nil, fmt.Errorf("close package server selections: %w", queryErr)
			}
			for _, selectionID := range disallowedSelectionIDs {
				if _, queryErr := tx.ExecContext(ctx, `UPDATE user_node_selections SET desired_enabled=0,deactivated_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND desired_enabled=1`, now, selectionID); queryErr != nil {
					return nil, fmt.Errorf("deactivate package protocol-restricted selection: %w", queryErr)
				}
			}
			if entry.MaxActiveNodes > 0 {
				var activeSelections int
				if queryErr := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_node_selections WHERE grant_id=? AND desired_enabled=1`, id).Scan(&activeSelections); queryErr != nil {
					return nil, fmt.Errorf("count active package selections: %w", queryErr)
				}
				if activeSelections > entry.MaxActiveNodes {
					return nil, ErrManagedActiveNodeLimit
				}
			}
			var usedBytes int64
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN COALESCE(s.billing_mode_override,g.billing_mode)='both' THEN u.uplink_bytes+u.downlink_bytes ELSE u.downlink_bytes END),0)
FROM user_server_grants g LEFT JOIN user_node_selections s ON s.grant_id=g.id
LEFT JOIN user_node_selection_usage u ON u.selection_id=s.id WHERE g.id=?`, id).Scan(&usedBytes); err != nil {
				return nil, err
			}
			var currentBillingMode string
			if err := tx.QueryRowContext(ctx, `SELECT billing_mode FROM user_server_grants WHERE id=?`, id).Scan(&currentBillingMode); err != nil {
				return nil, err
			}
			if usedBytes > 0 && currentBillingMode != entry.BillingMode {
				return nil, ErrManagedBillingModeConflict
			}
			_, updateErr := tx.ExecContext(ctx, `UPDATE user_server_grants SET enabled=1,starts_at=?,expires_at=?,
max_active_nodes=?,speed_limit_mbps=?,connection_limit=?,traffic_limit_bytes=?,billing_mode=?,reset_policy=?,
reset_day=?,billing_timezone='Asia/Shanghai',next_reset_at=?,allowed_protocols_json=?,allowed_protocol_profiles_json=?,
source_type='package',source_package_id=?,version=version+1,updated_at=CURRENT_TIMESTAMP
WHERE id=? AND (source_type='package' OR (source_type='manual' AND enabled=0))`,
				startsAt.UTC(), endsAt.UTC(), entry.MaxActiveNodes, entry.SpeedLimitMbps, entry.ConnectionLimit,
				entry.TrafficLimitBytes, entry.BillingMode, entry.ResetPolicy, entry.ResetDay, nextReset,
				protocols, profiles, pkg.ID, id)
			if updateErr != nil {
				return nil, fmt.Errorf("update package server grant: %w", updateErr)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
desired_state=CASE WHEN ?=1 AND source_id IN(SELECT id FROM user_node_selections WHERE grant_id=? AND desired_enabled=1) THEN 'active' ELSE 'inactive' END,
suspend_reason=CASE
 WHEN source_id IN(SELECT id FROM user_node_selections WHERE grant_id=? AND desired_enabled=0) THEN 'admin_disabled'
 WHEN ?=1 THEN 'none' ELSE 'expired' END,expires_at=?,generation=generation+1,
retry_count=0,next_retry_at=NULL,last_error='',updated_at=CURRENT_TIMESTAMP
WHERE source_type='selection' AND source_id IN(SELECT id FROM user_node_selections WHERE grant_id=?)`,
				boolInt(activeAtApply), id, id, boolInt(activeAtApply), endsAt.UTC(), id); err != nil {
				return nil, fmt.Errorf("refresh package server sources: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO managed_access_audit(actor,action,entity_type,entity_id,username,server_id,details_json)
VALUES('package','grant.materialized','server_grant',?,?,?,'{}')`, id, username, entry.ServerID); err != nil {
			return nil, fmt.Errorf("audit package server grant: %w", err)
		}
	}

	desiredTunnels := make(map[int64]PackageForwardingGrant, len(pkg.ForwardingGrants))
	for _, entry := range pkg.ForwardingGrants {
		desiredTunnels[entry.TunnelID] = entry
	}
	rows, err = tx.QueryContext(ctx, `SELECT id, tunnel_id FROM user_tunnel_grants
WHERE username = ? AND source_type = 'package' AND source_package_id = ?`, username, pkg.ID)
	if err != nil {
		return nil, fmt.Errorf("list package forwarding grants: %w", err)
	}
	var removedTunnelGrantIDs []int64
	for rows.Next() {
		var id, tunnelID int64
		if err := rows.Scan(&id, &tunnelID); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if _, keep := desiredTunnels[tunnelID]; !keep {
			removedTunnelGrantIDs = append(removedTunnelGrantIDs, id)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, id := range removedTunnelGrantIDs {
		if err := removePackageTunnelGrantTx(ctx, tx, id, now); err != nil {
			return nil, err
		}
	}

	for _, entry := range pkg.ForwardingGrants {
		var id int64
		var sourceType string
		var sourcePackageID sql.NullInt64
		var currentBillingMode sql.NullString
		var enabled int
		err := tx.QueryRowContext(ctx, `SELECT id, COALESCE(source_type, 'manual'), source_package_id, billing_mode_override, enabled FROM user_tunnel_grants
WHERE username=? AND tunnel_id=?`, username, entry.TunnelID).Scan(&id, &sourceType, &sourcePackageID, &currentBillingMode, &enabled)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("read existing forwarding grant: %w", err)
		}
		transferablePackageGrant := err == nil && sourceType == GrantSourcePackage && sourcePackageID.Valid &&
			(sourcePackageID.Int64 == pkg.ID || (oldPackageID > 0 && sourcePackageID.Int64 == oldPackageID))
		adoptableManualTombstone := err == nil && sourceType == GrantSourceManual && enabled == 0
		if err == nil && !transferablePackageGrant && !adoptableManualTombstone {
			warnings = append(warnings, packageGrantWarning("tunnel", entry.TunnelID))
			continue
		}
		if errors.Is(err, sql.ErrNoRows) {
			publicID := forwardingID("grt_")
			result, insertErr := tx.ExecContext(ctx, `INSERT INTO user_tunnel_grants(
public_id,username,tunnel_id,enabled,starts_at,expires_at,max_active_forwards,per_forward_speed_mbps,
per_forward_connection_limit,traffic_limit_bytes,billing_mode_override,allow_managed_target,
allow_custom_public_target,source_type,source_package_id,version,created_by)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'package')`, publicID, username, entry.TunnelID, 1, startsAt.UTC(), endsAt.UTC(),
				entry.MaxActiveForwards, entry.PerForwardSpeedMbps, entry.PerForwardConnectionLimit,
				entry.TrafficLimitBytes, *entry.BillingModeOverride, 1, 0, GrantSourcePackage, pkg.ID)
			if insertErr != nil {
				return nil, fmt.Errorf("create package forwarding grant: %w", insertErr)
			}
			id, _ = result.LastInsertId()
		} else {
			billingChanged := !currentBillingMode.Valid || currentBillingMode.String != *entry.BillingModeOverride
			if billingChanged {
				recorded, err := recordedTunnelGrantTrafficTx(ctx, tx, id)
				if err != nil {
					return nil, fmt.Errorf("read package forwarding usage: %w", err)
				}
				if recorded > 0 {
					return nil, ErrForwardingBillingModeConflict
				}
			}
			var activeForwards int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id=? AND desired_state='active'`, id).Scan(&activeForwards); err != nil {
				return nil, err
			}
			if entry.MaxActiveForwards > 0 && activeForwards > entry.MaxActiveForwards {
				return nil, ErrForwardingConflict
			}
			_, updateErr := tx.ExecContext(ctx, `UPDATE user_tunnel_grants SET enabled=1,starts_at=?,expires_at=?,
max_active_forwards=?,per_forward_speed_mbps=?,per_forward_connection_limit=?,traffic_limit_bytes=?,
billing_mode_override=?,source_type='package',source_package_id=?,version=version+1,updated_at=CURRENT_TIMESTAMP
WHERE id=? AND (source_type='package' OR (source_type='manual' AND enabled=0))`, startsAt.UTC(), endsAt.UTC(), entry.MaxActiveForwards,
				entry.PerForwardSpeedMbps, entry.PerForwardConnectionLimit, entry.TrafficLimitBytes,
				*entry.BillingModeOverride, pkg.ID, id)
			if updateErr != nil {
				return nil, fmt.Errorf("update package forwarding grant: %w", updateErr)
			}
			if billingChanged {
				if _, updateErr := tx.ExecContext(ctx, `UPDATE user_forward_rules SET effective_expires_at=?,billing_mode_snapshot=?,generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE grant_id=? AND desired_state!='deleted'`, endsAt.UTC(), *entry.BillingModeOverride, id); updateErr != nil {
					return nil, fmt.Errorf("refresh package forwarding rules: %w", updateErr)
				}
			} else if _, updateErr := tx.ExecContext(ctx, `UPDATE user_forward_rules SET effective_expires_at=?,generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE grant_id=? AND desired_state!='deleted'`, endsAt.UTC(), id); updateErr != nil {
				return nil, fmt.Errorf("refresh package forwarding rules: %w", updateErr)
			}
			if _, updateErr := tx.ExecContext(ctx, `UPDATE user_forward_hops SET generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE forward_id IN(SELECT id FROM user_forward_rules WHERE grant_id=? AND desired_state!='deleted')`, id); updateErr != nil {
				return nil, fmt.Errorf("refresh package forwarding hops: %w", updateErr)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO tunnel_audit_events(actor,action,entity_type,entity_id,username)
VALUES('package','grant.materialized','tunnel_grant',?,?)`, id, username); err != nil {
			return nil, fmt.Errorf("audit package forwarding grant: %w", err)
		}
	}
	return warnings, nil
}

func revokePackageBundleGrantsTx(ctx context.Context, tx *sql.Tx, username string, packageID int64, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM user_server_grants WHERE username=? AND source_type='package' AND source_package_id=?`, username, packageID)
	if err != nil {
		return err
	}
	var serverGrantIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		serverGrantIDs = append(serverGrantIDs, id)
	}
	_ = rows.Close()
	for _, id := range serverGrantIDs {
		if err := removePackageServerGrantTx(ctx, tx, id, now); err != nil {
			return err
		}
	}
	rows, err = tx.QueryContext(ctx, `SELECT id FROM user_tunnel_grants WHERE username=? AND source_type='package' AND source_package_id=?`, username, packageID)
	if err != nil {
		return err
	}
	var tunnelGrantIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		tunnelGrantIDs = append(tunnelGrantIDs, id)
	}
	_ = rows.Close()
	for _, id := range tunnelGrantIDs {
		if err := removePackageTunnelGrantTx(ctx, tx, id, now); err != nil {
			return err
		}
	}
	return nil
}

func removePackageServerGrantTx(ctx context.Context, tx *sql.Tx, grantID int64, now time.Time) error {
	var children int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_node_selections WHERE grant_id=?`, grantID).Scan(&children); err != nil {
		return err
	}
	if children == 0 {
		_, err := tx.ExecContext(ctx, `DELETE FROM user_server_grants WHERE id=? AND source_type='package'`, grantID)
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections SET desired_enabled=0,deactivated_at=?,updated_at=CURRENT_TIMESTAMP WHERE grant_id=? AND desired_enabled=1`, now, grantID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET desired_state='inactive',suspend_reason='admin_disabled',expires_at=?,generation=generation+1,retry_count=0,next_retry_at=NULL,last_error='',updated_at=CURRENT_TIMESTAMP
WHERE source_type='selection' AND source_id IN(SELECT id FROM user_node_selections WHERE grant_id=?)`, now, grantID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE user_server_grants SET enabled=0,expires_at=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND source_type='package'`, now, grantID)
	return err
}

func removePackageTunnelGrantTx(ctx context.Context, tx *sql.Tx, grantID int64, now time.Time) error {
	var children int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id=?`, grantID).Scan(&children); err != nil {
		return err
	}
	if children == 0 {
		_, err := tx.ExecContext(ctx, `DELETE FROM user_tunnel_grants WHERE id=? AND source_type='package'`, grantID)
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_rules SET desired_state='inactive',suspend_reason='grant_inactive',generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE grant_id=? AND desired_state!='deleted'`, grantID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_hops SET desired_state='inactive',generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE forward_id IN(SELECT id FROM user_forward_rules WHERE grant_id=? AND desired_state!='deleted')`, grantID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE user_tunnel_grants SET enabled=0,expires_at=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND source_type='package'`, now, grantID)
	return err
}

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
