package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

func scanUserNodeSelectionUsage(s rowScanner) (UserNodeSelectionUsage, error) {
	var usage UserNodeSelectionUsage
	var lastReset sql.NullString
	err := s.Scan(&usage.SelectionID, &usage.GrantID, &usage.CycleStartedAt,
		&usage.UplinkBytes, &usage.DownlinkBytes, &usage.LastRawUplink,
		&usage.LastRawDownlink, &usage.CounterEpoch, &lastReset, &usage.UpdatedAt)
	usage.LastResetAt = managedParseNullTime(lastReset)
	return usage, err
}

const selectUserNodeSelectionUsage = `SELECT selection_id, grant_id, cycle_started_at,
       uplink_bytes, downlink_bytes, last_raw_uplink, last_raw_downlink,
       counter_epoch, last_reset_at, updated_at
FROM user_node_selection_usage`

func (r *TrafficRepository) GetUserNodeSelectionUsage(ctx context.Context, selectionID int64) (*UserNodeSelectionUsage, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if selectionID <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	usage, err := scanUserNodeSelectionUsage(r.db.QueryRowContext(ctx, selectUserNodeSelectionUsage+` WHERE selection_id = ?`, selectionID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeSelectionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get managed selection usage: %w", err)
	}
	return &usage, nil
}

func (r *TrafficRepository) ListUserNodeSelectionUsage(ctx context.Context, grantID int64) ([]UserNodeSelectionUsage, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if grantID <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	rows, err := r.db.QueryContext(ctx, selectUserNodeSelectionUsage+` WHERE grant_id = ? ORDER BY selection_id ASC`, grantID)
	if err != nil {
		return nil, fmt.Errorf("list managed selection usage: %w", err)
	}
	defer rows.Close()
	items := make([]UserNodeSelectionUsage, 0)
	for rows.Next() {
		usage, err := scanUserNodeSelectionUsage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan managed selection usage: %w", err)
		}
		items = append(items, usage)
	}
	return items, rows.Err()
}

func counterDelta(raw, previous int64, sameEpoch bool) int64 {
	if sameEpoch && raw >= previous {
		return raw - previous
	}
	// A new epoch, Xray restart, or a counter rollback starts at zero. Counting
	// the new raw value avoids losing all traffic until it catches the old cursor.
	return raw
}

func checkedTrafficAdd(current, delta int64) (int64, error) {
	if delta < 0 || current < 0 || delta > math.MaxInt64-current {
		return 0, ErrManagedInvalidArgument
	}
	return current + delta, nil
}

func (r *TrafficRepository) AccumulateUserNodeSelectionUsage(ctx context.Context, selectionID, rawUp, rawDown int64, counterEpoch string, now time.Time) (*UserNodeSelectionUsage, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	counterEpoch = strings.TrimSpace(counterEpoch)
	if selectionID <= 0 || rawUp < 0 || rawDown < 0 || now.IsZero() || len(counterEpoch) > 256 {
		return nil, ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	now = now.UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin accumulate managed usage: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	usage, err := scanUserNodeSelectionUsage(tx.QueryRowContext(ctx, selectUserNodeSelectionUsage+` WHERE selection_id = ?`, selectionID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeSelectionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get managed usage cursor: %w", err)
	}
	firstObservation := usage.CounterEpoch == "" && usage.LastRawUplink == 0 &&
		usage.LastRawDownlink == 0 && usage.UplinkBytes == 0 && usage.DownlinkBytes == 0
	sameEpoch := usage.CounterEpoch == counterEpoch
	deltaUp, deltaDown := int64(0), int64(0)
	if !firstObservation {
		deltaUp = counterDelta(rawUp, usage.LastRawUplink, sameEpoch)
		deltaDown = counterDelta(rawDown, usage.LastRawDownlink, sameEpoch)
	}
	newUp, err := checkedTrafficAdd(usage.UplinkBytes, deltaUp)
	if err != nil {
		return nil, err
	}
	newDown, err := checkedTrafficAdd(usage.DownlinkBytes, deltaDown)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_selection_usage SET
    uplink_bytes = ?, downlink_bytes = ?, last_raw_uplink = ?,
    last_raw_downlink = ?, counter_epoch = ?, updated_at = ?
WHERE selection_id = ?`, newUp, newDown, rawUp, rawDown, counterEpoch, now, selectionID); err != nil {
		return nil, fmt.Errorf("accumulate managed selection usage: %w", err)
	}
	usage, err = scanUserNodeSelectionUsage(tx.QueryRowContext(ctx, selectUserNodeSelectionUsage+` WHERE selection_id = ?`, selectionID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit accumulate managed usage: %w", err)
	}
	return &usage, nil
}

// RebaseUserNodeSelectionUsage advances the raw counter cursor without adding
// usage. It is used while a legacy package also authorizes the same inbound so
// historical overlaps are not double billed or charged retroactively later.
func (r *TrafficRepository) RebaseUserNodeSelectionUsage(ctx context.Context, selectionID, rawUp, rawDown int64, counterEpoch string, now time.Time) (*UserNodeSelectionUsage, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	counterEpoch = strings.TrimSpace(counterEpoch)
	if selectionID <= 0 || rawUp < 0 || rawDown < 0 || now.IsZero() || len(counterEpoch) > 256 {
		return nil, ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	result, err := r.db.ExecContext(ctx, `UPDATE user_node_selection_usage SET
    last_raw_uplink = ?, last_raw_downlink = ?, counter_epoch = ?, updated_at = ?
WHERE selection_id = ?`, rawUp, rawDown, counterEpoch, now.UTC(), selectionID)
	if err != nil {
		return nil, fmt.Errorf("rebase managed selection usage: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil, ErrUserNodeSelectionNotFound
	}
	usage, err := scanUserNodeSelectionUsage(r.db.QueryRowContext(ctx, selectUserNodeSelectionUsage+` WHERE selection_id = ?`, selectionID))
	if err != nil {
		return nil, fmt.Errorf("reload rebased managed selection usage: %w", err)
	}
	return &usage, nil
}

func (r *TrafficRepository) ResetUserServerGrantUsage(ctx context.Context, grantID int64, cycleStart time.Time, nextResetAt *time.Time, actor string) error {
	if err := managedInitialized(r); err != nil {
		return err
	}
	actor = strings.TrimSpace(actor)
	if grantID <= 0 || cycleStart.IsZero() || actor == "" {
		return ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	cycleStart = cycleStart.UTC()
	if nextResetAt != nil {
		value := nextResetAt.UTC()
		if !value.After(cycleStart) {
			return ErrManagedInvalidArgument
		}
		nextResetAt = &value
	}
	now := time.Now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin reset managed grant usage: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var username string
	var serverID int64
	if err := tx.QueryRowContext(ctx, `SELECT username, server_id FROM user_server_grants WHERE id = ?`, grantID).Scan(&username, &serverID); errors.Is(err, sql.ErrNoRows) {
		return ErrUserServerGrantNotFound
	} else if err != nil {
		return fmt.Errorf("get grant for usage reset: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_selection_usage SET
    cycle_started_at = ?, uplink_bytes = 0, downlink_bytes = 0,
    last_reset_at = ?, updated_at = ? WHERE grant_id = ?`, cycleStart, now, now, grantID); err != nil {
		return fmt.Errorf("reset managed grant usage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_server_grants SET next_reset_at = ?, updated_at = ? WHERE id = ?`, managedNullTime(nextResetAt), now, grantID); err != nil {
		return fmt.Errorf("update managed grant reset schedule: %w", err)
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "grant.usage_reset", EntityType: "server_grant", EntityID: grantID,
		Username: username, ServerID: serverID,
		Details: map[string]any{"cycle_started_at": cycleStart.Format(time.RFC3339)},
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reset managed grant usage: %w", err)
	}
	return nil
}

func (r *TrafficRepository) GetUserServerGrantUsage(ctx context.Context, grantID int64) (uplink, downlink, billed int64, err error) {
	if initErr := managedInitialized(r); initErr != nil {
		err = initErr
		return
	}
	if grantID <= 0 {
		err = ErrManagedInvalidArgument
		return
	}
	err = r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(u.uplink_bytes), 0),
       COALESCE(SUM(u.downlink_bytes), 0),
       COALESCE(SUM(CASE WHEN COALESCE(s.billing_mode_override, g.billing_mode) = ?
           THEN u.uplink_bytes + u.downlink_bytes ELSE u.downlink_bytes END), 0)
FROM user_server_grants g
LEFT JOIN user_node_selections s ON s.grant_id = g.id
LEFT JOIN user_node_selection_usage u ON u.selection_id = s.id
WHERE g.id = ? GROUP BY g.id`, ManagedBillingBoth, grantID).Scan(&uplink, &downlink, &billed)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrUserServerGrantNotFound
	} else if err != nil {
		err = fmt.Errorf("get managed grant usage: %w", err)
	}
	return
}

func managedSensitiveKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, needle := range []string{"credential", "password", "passwd", "secret", "token", "uuid", "private", "config_json", "inbound_json"} {
		if strings.Contains(key, needle) {
			return true
		}
	}
	return false
}

func sanitizeManagedDetails(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		clean := make(map[string]any, len(typed))
		for key, item := range typed {
			if managedSensitiveKey(key) {
				clean[key] = "[redacted]"
			} else {
				clean[key] = sanitizeManagedDetails(item)
			}
		}
		return clean
	case []any:
		clean := make([]any, len(typed))
		for i := range typed {
			clean[i] = sanitizeManagedDetails(typed[i])
		}
		return clean
	case string:
		if len(typed) > 1024 {
			return typed[:1024]
		}
		return typed
	default:
		return typed
	}
}

func sanitizeManagedError(message string) string {
	message = strings.Join(strings.Fields(strings.TrimSpace(message)), " ")
	message = managedSecretAssignmentPattern.ReplaceAllString(message, `$1=[redacted]`)
	message = managedUUIDPattern.ReplaceAllString(message, "[redacted-uuid]")
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

var (
	managedSecretAssignmentPattern = regexp.MustCompile(`(?i)(token|password|passwd|credential|secret|uuid)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)`)
	managedUUIDPattern             = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
)

func appendManagedAccessAuditTx(ctx context.Context, tx *sql.Tx, audit ManagedAccessAudit) error {
	audit.Actor = strings.TrimSpace(audit.Actor)
	audit.Action = strings.TrimSpace(audit.Action)
	audit.EntityType = strings.TrimSpace(audit.EntityType)
	audit.Username = strings.TrimSpace(audit.Username)
	if audit.Actor == "" || audit.Action == "" || audit.EntityType == "" || audit.EntityID < 0 || audit.ServerID < 0 {
		return ErrManagedInvalidArgument
	}
	details := sanitizeManagedDetails(audit.Details)
	if details == nil {
		details = map[string]any{}
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode managed access audit: %w", err)
	}
	createdAt := audit.CreatedAt.UTC()
	if audit.CreatedAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO managed_access_audit
    (actor, action, entity_type, entity_id, username, server_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, audit.Actor, audit.Action, audit.EntityType,
		audit.EntityID, audit.Username, audit.ServerID, string(encoded), createdAt); err != nil {
		return fmt.Errorf("append managed access audit: %w", err)
	}
	return nil
}

func (r *TrafficRepository) AppendManagedAccessAudit(ctx context.Context, audit ManagedAccessAudit) error {
	if err := managedInitialized(r); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin append managed audit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := appendManagedAccessAuditTx(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit append managed audit: %w", err)
	}
	return nil
}

func (r *TrafficRepository) ListManagedAccessAudit(ctx context.Context, username, entityType string, entityID int64, limit int) ([]ManagedAccessAudit, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username, entityType = strings.TrimSpace(username), strings.TrimSpace(entityType)
	if entityID < 0 {
		return nil, ErrManagedInvalidArgument
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT id, actor, action, entity_type, entity_id, username,
       server_id, details_json, created_at FROM managed_access_audit WHERE 1 = 1`
	args := make([]any, 0, 4)
	if username != "" {
		query += ` AND username = ?`
		args = append(args, username)
	}
	if entityType != "" {
		query += ` AND entity_type = ?`
		args = append(args, entityType)
	}
	if entityID > 0 {
		query += ` AND entity_id = ?`
		args = append(args, entityID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list managed access audit: %w", err)
	}
	defer rows.Close()
	items := make([]ManagedAccessAudit, 0)
	for rows.Next() {
		var item ManagedAccessAudit
		var details string
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.EntityType,
			&item.EntityID, &item.Username, &item.ServerID, &details, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan managed access audit: %w", err)
		}
		if err := json.Unmarshal([]byte(details), &item.Details); err != nil {
			item.Details = map[string]any{"decode_error": true}
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *TrafficRepository) ListManagedNodeCatalog(ctx context.Context, username string, now time.Time) ([]ManagedNodeCatalogEntry, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if username == "" || now.IsZero() {
		return nil, ErrManagedInvalidArgument
	}
	now = now.UTC()
	var userEnabled int
	if err := r.db.QueryRowContext(ctx, `SELECT is_active FROM users WHERE username = ?`, username).Scan(&userEnabled); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, fmt.Errorf("get catalog user: %w", err)
	}
	grants, err := r.ListUserServerGrants(ctx, username)
	if err != nil {
		return nil, err
	}
	selections, err := r.ListUserNodeSelections(ctx, username, false)
	if err != nil {
		return nil, err
	}
	entries := make([]ManagedNodeCatalogEntry, 0)
	for _, grant := range grants {
		offers, err := r.ListSelfServiceNodeOffersByServer(ctx, grant.ServerID, true)
		if err != nil {
			return nil, err
		}
		selectionByOffer := make(map[int64]UserNodeSelection)
		activeCount := 0
		for _, selection := range selections {
			if selection.GrantID == grant.ID {
				selectionByOffer[selection.OfferID] = selection
				if selection.DesiredEnabled {
					activeCount++
				}
			}
		}
		_, _, grantBilled, err := r.GetUserServerGrantUsage(ctx, grant.ID)
		if err != nil {
			return nil, err
		}
		grantState := grant.StateAt(now, userEnabled != 0, grantBilled)
		for _, offer := range offers {
			selection, selected := selectionByOffer[offer.ID]
			if !offer.Enabled && !selected {
				continue
			}
			var nodeName, protocol, clashConfig, serverName, serverStatus, originalServer, nodeType, inboundTag, xrayMode string
			var nodeEnabled int
			if err := r.db.QueryRowContext(ctx, `SELECT n.node_name, n.protocol, COALESCE(n.clash_config, ''), n.enabled,
       COALESCE(n.original_server, ''), COALESCE(n.node_type, 'physical'),
       COALESCE(n.inbound_tag, ''), rs.name, rs.status, COALESCE(rs.xray_mode, 'external')
FROM nodes n JOIN remote_servers rs ON rs.id = ? WHERE n.id = ?`, offer.ServerID, offer.NodeID).Scan(
				&nodeName, &protocol, &clashConfig, &nodeEnabled, &originalServer, &nodeType, &inboundTag,
				&serverName, &serverStatus, &xrayMode,
			); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				return nil, fmt.Errorf("resolve managed catalog offer: %w", err)
			}
			entry := ManagedNodeCatalogEntry{
				Offer: offer, Grant: grant, NodeName: nodeName, Protocol: protocol,
				ServerName: serverName, ServerStatus: serverStatus, GrantStatus: grantState,
			}
			entry.ProtocolProfile, _ = SelfServiceNodeProtocolProfile(protocol, clashConfig)
			node := Node{
				ID: offer.NodeID, Protocol: protocol, ClashConfig: clashConfig, Enabled: nodeEnabled != 0,
				NodeType: nodeType, OriginalServer: originalServer, InboundTag: inboundTag,
			}
			server := RemoteServer{ID: offer.ServerID, Name: serverName, XrayMode: xrayMode}
			structureValid := SelfServiceNodeOfferStructureValid(offer, node, server)
			if structureValid && strings.EqualFold(strings.TrimSpace(protocol), "wireguard") {
				structureValid, err = r.ManagedWireGuardNodeProvisionable(ctx, node.ID)
				if err != nil {
					return nil, fmt.Errorf("verify managed WireGuard catalog provenance: %w", err)
				}
			}
			protocolEligible := SelfServiceNodeOfferProtocolEligible(offer, node)
			if selected {
				copy := selection
				entry.Selection = &copy
				if selection.AccessSourceID != nil {
					source, err := r.GetUserInboundAccessSource(ctx, *selection.AccessSourceID)
					if err != nil {
						return nil, fmt.Errorf("resolve managed catalog access source: %w", err)
					}
					entry.AccessSource = source
				}
				if usage, err := r.GetUserNodeSelectionUsage(ctx, selection.ID); err == nil {
					mode := grant.BillingMode
					if selection.BillingModeOverride != nil {
						mode = *selection.BillingModeOverride
					}
					entry.UsageBytes = usage.BilledBytes(mode)
				}
			}
			switch {
			case selected && selection.DesiredEnabled:
				entry.DenyReason = "already_selected"
			case !offer.Enabled:
				entry.DenyReason = "offer_disabled"
			case nodeEnabled == 0:
				entry.DenyReason = "node_disabled"
			case !structureValid:
				entry.DenyReason = "server_mismatch"
			case !grant.AllowsNodeProtocol(protocol, clashConfig) || !protocolEligible:
				entry.DenyReason = "protocol_not_allowed"
			case grantState != ManagedGrantActive:
				entry.DenyReason = grantState
			case serverStatus != RemoteServerStatusConnected:
				entry.DenyReason = "server_offline"
			case grant.MaxActiveNodes > 0 && activeCount >= grant.MaxActiveNodes:
				entry.DenyReason = "node_limit"
			default:
				entry.CanCreate = true
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}
