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

func (g UserServerGrant) StateAt(now time.Time, userEnabled bool, billedBytes int64) string {
	now = now.UTC()
	if !userEnabled {
		return ManagedGrantUserDisabled
	}
	if now.Before(g.StartsAt) {
		return ManagedGrantScheduled
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return ManagedGrantExpired
	}
	if !g.Enabled {
		return ManagedGrantSuspended
	}
	if g.TrafficLimitBytes > 0 && billedBytes >= g.TrafficLimitBytes {
		return ManagedGrantOverLimit
	}
	return ManagedGrantActive
}

func scanUserNodeSelection(s rowScanner) (UserNodeSelection, error) {
	var (
		selection              UserNodeSelection
		credentialID, sourceID sql.NullInt64
		desired                int
		speed                  sql.NullFloat64
		connection             sql.NullInt64
		billing                sql.NullString
		activated, deactivated sql.NullString
	)
	err := s.Scan(&selection.ID, &selection.GrantID, &selection.OfferID, &credentialID, &sourceID,
		&desired, &speed, &connection, &billing, &activated, &deactivated,
		&selection.CreatedAt, &selection.UpdatedAt)
	if err != nil {
		return selection, err
	}
	selection.DesiredEnabled = desired != 0
	if credentialID.Valid {
		selection.CredentialConfigID = &credentialID.Int64
	}
	if sourceID.Valid {
		selection.AccessSourceID = &sourceID.Int64
	}
	if speed.Valid {
		selection.SpeedLimitOverrideMbps = &speed.Float64
	}
	if connection.Valid {
		value := int(connection.Int64)
		selection.ConnectionLimitOverride = &value
	}
	if billing.Valid {
		selection.BillingModeOverride = &billing.String
	}
	selection.ActivatedAt = managedParseNullTime(activated)
	selection.DeactivatedAt = managedParseNullTime(deactivated)
	return selection, nil
}

const selectUserNodeSelection = `SELECT id, grant_id, offer_id, credential_config_id,
       access_source_id, desired_enabled, speed_limit_override_mbps,
       connection_limit_override, billing_mode_override, activated_at,
       deactivated_at, created_at, updated_at
FROM user_node_selections`

func scanUserInboundAccessSource(s rowScanner) (UserInboundAccessSource, error) {
	var source UserInboundAccessSource
	var nextRetry, expires sql.NullString
	err := s.Scan(&source.ID, &source.Username, &source.ServerID, &source.InboundTag,
		&source.NodeID, &source.SourceType, &source.SourceID, &source.DesiredState,
		&source.ObservedState, &source.SuspendReason, &source.Generation,
		&source.AppliedGeneration, &source.RetryCount, &nextRetry, &source.LastError,
		&source.StartsAt, &expires, &source.CreatedAt, &source.UpdatedAt)
	if err != nil {
		return source, err
	}
	source.NextRetryAt = managedParseNullTime(nextRetry)
	source.ExpiresAt = managedParseNullTime(expires)
	return source, nil
}

const selectUserInboundAccessSource = `SELECT id, username, server_id, inbound_tag,
       node_id, source_type, source_id, desired_state, observed_state,
       suspend_reason, generation, applied_generation, retry_count, next_retry_at,
       last_error, starts_at, expires_at, created_at, updated_at
FROM user_inbound_access_sources`

func (r *TrafficRepository) GetUserNodeSelection(ctx context.Context, id int64) (*UserNodeSelection, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	selection, err := scanUserNodeSelection(r.db.QueryRowContext(ctx, selectUserNodeSelection+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeSelectionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user node selection: %w", err)
	}
	return &selection, nil
}

func (r *TrafficRepository) GetUserNodeSelectionForUser(ctx context.Context, id int64, username string) (*UserNodeSelection, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if id <= 0 || username == "" {
		return nil, ErrManagedInvalidArgument
	}
	selection, err := scanUserNodeSelection(r.db.QueryRowContext(ctx, selectUserNodeSelection+`
WHERE id = ? AND grant_id IN (SELECT id FROM user_server_grants WHERE username = ?)`, id, username))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeSelectionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user node selection for user: %w", err)
	}
	return &selection, nil
}

func (r *TrafficRepository) ListUserNodeSelections(ctx context.Context, username string, onlyEnabled bool) ([]UserNodeSelection, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrManagedInvalidArgument
	}
	query := selectUserNodeSelection + ` WHERE grant_id IN (
    SELECT id FROM user_server_grants WHERE username = ?
)`
	if onlyEnabled {
		query += ` AND desired_enabled = 1`
	}
	query += ` ORDER BY id ASC`
	rows, err := r.db.QueryContext(ctx, query, username)
	if err != nil {
		return nil, fmt.Errorf("list user node selections: %w", err)
	}
	defer rows.Close()
	selections := make([]UserNodeSelection, 0)
	for rows.Next() {
		selection, err := scanUserNodeSelection(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user node selection: %w", err)
		}
		selections = append(selections, selection)
	}
	return selections, rows.Err()
}

func grantUsageTx(ctx context.Context, tx *sql.Tx, grantID int64, fallbackMode string) (int64, error) {
	var billed sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT SUM(CASE
    WHEN COALESCE(s.billing_mode_override, ?) = ? THEN u.uplink_bytes + u.downlink_bytes
    ELSE u.downlink_bytes END)
FROM user_node_selection_usage u
JOIN user_node_selections s ON s.id = u.selection_id
WHERE u.grant_id = ?`, fallbackMode, ManagedBillingBoth, grantID).Scan(&billed)
	if err != nil {
		return 0, err
	}
	return billed.Int64, nil
}

func grantSuspendReason(state string) string {
	switch state {
	case ManagedGrantExpired:
		return ManagedSuspendExpired
	case ManagedGrantOverLimit:
		return ManagedSuspendQuotaExceeded
	case ManagedGrantUserDisabled:
		return ManagedSuspendUserDisabled
	default:
		return ManagedSuspendAdminDisabled
	}
}

func (r *TrafficRepository) ActivateUserNodeSelection(ctx context.Context, username string, offerID int64, actor string, now time.Time) (*SelectionActivationResult, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username, actor = strings.TrimSpace(username), strings.TrimSpace(actor)
	if username == "" || actor == "" || offerID <= 0 || now.IsZero() {
		return nil, ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	now = now.UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin activate managed node: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	offer, err := scanSelfServiceNodeOffer(tx.QueryRowContext(ctx, selectSelfServiceNodeOffer+` WHERE id = ?`, offerID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSelfServiceNodeOfferNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get managed offer for activation: %w", err)
	}
	if !offer.Enabled {
		return nil, ErrSelfServiceNodeOfferNotFound
	}
	grant, err := scanUserServerGrant(tx.QueryRowContext(ctx, selectUserServerGrant+`
WHERE username = ? AND server_id = ?`, username, offer.ServerID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserServerGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get grant for activation: %w", err)
	}
	var userEnabled, nodeEnabled int
	var nodeType, nodeProtocol, nodeClashConfig, originalServer, serverName, xrayMode, nodeInbound string
	if err := tx.QueryRowContext(ctx, `SELECT u.is_active, n.enabled,
	       COALESCE(n.node_type, 'physical'), COALESCE(n.protocol, ''), COALESCE(n.clash_config, ''), COALESCE(n.original_server, ''),
	       rs.name, COALESCE(rs.xray_mode, 'external'), COALESCE(n.inbound_tag, '')
FROM users u, nodes n, remote_servers rs
WHERE u.username = ? AND n.id = ? AND rs.id = ?`, username, offer.NodeID, offer.ServerID).Scan(
		&userEnabled, &nodeEnabled, &nodeType, &nodeProtocol, &nodeClashConfig, &originalServer, &serverName, &xrayMode, &nodeInbound,
	); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrManagedServerMismatch
	} else if err != nil {
		return nil, fmt.Errorf("validate managed activation: %w", err)
	}
	node := Node{
		ID: offer.NodeID, Protocol: nodeProtocol, ClashConfig: nodeClashConfig, Enabled: nodeEnabled != 0,
		NodeType: nodeType, OriginalServer: originalServer, InboundTag: nodeInbound,
	}
	server := RemoteServer{ID: offer.ServerID, Name: serverName, XrayMode: xrayMode}
	if !node.Enabled || !SelfServiceNodeOfferStructureValid(offer, node, server) {
		return nil, ErrManagedServerMismatch
	}
	billed, err := grantUsageTx(ctx, tx, grant.ID, grant.BillingMode)
	if err != nil {
		return nil, fmt.Errorf("read grant usage for activation: %w", err)
	}
	if grant.StateAt(now, userEnabled != 0, billed) != ManagedGrantActive {
		if grant.TrafficLimitBytes > 0 && billed >= grant.TrafficLimitBytes {
			return nil, ErrManagedTrafficLimit
		}
		return nil, ErrManagedGrantInactive
	}
	if !grant.AllowsNodeProtocol(nodeProtocol, nodeClashConfig) {
		return nil, fmt.Errorf("%w: %s", ErrManagedProtocolNotAllowed, strings.ToLower(strings.TrimSpace(nodeProtocol)))
	}
	if !SelfServiceNodeOfferProtocolEligible(offer, node) {
		return nil, fmt.Errorf("%w: protocol does not support isolated managed credentials", ErrManagedInvalidArgument)
	}
	selection, scanErr := scanUserNodeSelection(tx.QueryRowContext(ctx, selectUserNodeSelection+`
WHERE grant_id = ? AND offer_id = ?`, grant.ID, offer.ID))
	selectionExists := scanErr == nil
	if scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
		return nil, fmt.Errorf("get existing managed selection: %w", scanErr)
	}
	if selectionExists && selection.CredentialConfigID != nil {
		var credentialProtocol string
		err := tx.QueryRowContext(ctx, `SELECT protocol FROM user_inbound_configs
WHERE id = ? AND username = ? AND server_id = ? AND inbound_tag = ?`,
			*selection.CredentialConfigID, username, offer.ServerID, offer.InboundTag).Scan(&credentialProtocol)
		if errors.Is(err, sql.ErrNoRows) || err == nil && !SelfServiceCredentialProtocolMatches(credentialProtocol, nodeProtocol) {
			return nil, fmt.Errorf("%w: previous managed credential cleanup is pending", ErrManagedAccessConflict)
		}
		if err != nil {
			return nil, fmt.Errorf("validate managed credential protocol snapshot: %w", err)
		}
	}
	if !selectionExists || !selection.DesiredEnabled {
		packageOverlap, err := userPackageContainsManagedInbound(ctx, tx, username, offer.ServerID, offer.InboundTag, now)
		if err != nil {
			return nil, err
		}
		if packageOverlap {
			return nil, fmt.Errorf("%w: server=%d inbound=%s", ErrManagedAccessConflict, offer.ServerID, offer.InboundTag)
		}
	}
	if (!selectionExists || !selection.DesiredEnabled) && grant.MaxActiveNodes > 0 {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_node_selections
WHERE grant_id = ? AND desired_enabled = 1`, grant.ID).Scan(&active); err != nil {
			return nil, fmt.Errorf("count active managed selections: %w", err)
		}
		if active >= grant.MaxActiveNodes {
			return nil, ErrManagedActiveNodeLimit
		}
	}

	created := false
	if !selectionExists {
		result, err := tx.ExecContext(ctx, `INSERT INTO user_node_selections
    (grant_id, offer_id, desired_enabled, created_at, updated_at)
VALUES (?, ?, 1, ?, ?)`, grant.ID, offer.ID, now, now)
		if err != nil {
			return nil, fmt.Errorf("create managed selection: %w", err)
		}
		selection.ID, err = result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("read managed selection id: %w", err)
		}
		selection.GrantID, selection.OfferID = grant.ID, offer.ID
		selection.DesiredEnabled, selection.CreatedAt, selection.UpdatedAt = true, now, now
		created = true
	}

	source, sourceErr := scanUserInboundAccessSource(tx.QueryRowContext(ctx, selectUserInboundAccessSource+`
WHERE source_type = ? AND source_id = ?`, ManagedSourceSelection, selection.ID))
	if errors.Is(sourceErr, sql.ErrNoRows) {
		result, err := tx.ExecContext(ctx, `INSERT INTO user_inbound_access_sources (
    username, server_id, inbound_tag, node_id, source_type, source_id,
    desired_state, observed_state, suspend_reason, generation, applied_generation,
    starts_at, expires_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?)`,
			username, offer.ServerID, offer.InboundTag, offer.NodeID, ManagedSourceSelection, selection.ID,
			ManagedDesiredActive, ManagedObservedUnknown, ManagedSuspendNone,
			grant.StartsAt, managedNullTime(grant.ExpiresAt), now, now)
		if err != nil {
			return nil, fmt.Errorf("create managed access source: %w", err)
		}
		source.ID, err = result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("read managed access source id: %w", err)
		}
		source = UserInboundAccessSource{
			ID: source.ID, Username: username, ServerID: offer.ServerID, InboundTag: offer.InboundTag,
			NodeID: offer.NodeID, SourceType: ManagedSourceSelection, SourceID: selection.ID,
			DesiredState: ManagedDesiredActive, ObservedState: ManagedObservedUnknown,
			SuspendReason: ManagedSuspendNone, Generation: 1, StartsAt: grant.StartsAt,
			ExpiresAt: grant.ExpiresAt, CreatedAt: now, UpdatedAt: now,
		}
	} else if sourceErr != nil {
		return nil, fmt.Errorf("get managed access source: %w", sourceErr)
	} else if !selection.DesiredEnabled || source.DesiredState != ManagedDesiredActive || source.SuspendReason != ManagedSuspendNone {
		if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    desired_state = ?, suspend_reason = ?, generation = generation + 1,
    retry_count = 0, next_retry_at = NULL, last_error = '', starts_at = ?,
    expires_at = ?, updated_at = ? WHERE id = ?`, ManagedDesiredActive,
			ManagedSuspendNone, grant.StartsAt, managedNullTime(grant.ExpiresAt), now, source.ID); err != nil {
			return nil, fmt.Errorf("reactivate managed access source: %w", err)
		}
		source, err = scanUserInboundAccessSource(tx.QueryRowContext(ctx, selectUserInboundAccessSource+` WHERE id = ?`, source.ID))
		if err != nil {
			return nil, fmt.Errorf("reload managed access source: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections SET
    access_source_id = ?, desired_enabled = 1, deactivated_at = NULL, updated_at = ?
WHERE id = ?`, source.ID, now, selection.ID); err != nil {
		return nil, fmt.Errorf("link managed selection source: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_node_selection_usage
    (selection_id, grant_id, cycle_started_at, updated_at)
VALUES (?, ?, ?, ?) ON CONFLICT(selection_id) DO NOTHING`, selection.ID, grant.ID, grant.StartsAt, now); err != nil {
		return nil, fmt.Errorf("initialize managed selection usage: %w", err)
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "selection.activated", EntityType: "node_selection", EntityID: selection.ID,
		Username: username, ServerID: offer.ServerID,
		Details: map[string]any{"offer_id": offer.ID, "generation": source.Generation, "created": created},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		if managedUniqueViolation(err) {
			// Concurrent idempotent requests converge on the winning selection.
			selection, getErr := r.getSelectionByGrantAndOffer(ctx, grant.ID, offer.ID)
			if getErr == nil {
				source, getErr := r.GetUserInboundAccessSource(ctx, *selection.AccessSourceID)
				if getErr == nil {
					return &SelectionActivationResult{Selection: *selection, Source: *source}, nil
				}
			}
		}
		return nil, fmt.Errorf("commit activate managed node: %w", err)
	}
	selection, err = scanUserNodeSelection(r.db.QueryRowContext(ctx, selectUserNodeSelection+` WHERE id = ?`, selection.ID))
	if err != nil {
		return nil, fmt.Errorf("reload activated managed selection: %w", err)
	}
	source, err = scanUserInboundAccessSource(r.db.QueryRowContext(ctx, selectUserInboundAccessSource+` WHERE id = ?`, source.ID))
	if err != nil {
		return nil, fmt.Errorf("reload activated managed source: %w", err)
	}
	return &SelectionActivationResult{Selection: selection, Source: source, Created: created}, nil
}

func (r *TrafficRepository) getSelectionByGrantAndOffer(ctx context.Context, grantID, offerID int64) (*UserNodeSelection, error) {
	selection, err := scanUserNodeSelection(r.db.QueryRowContext(ctx, selectUserNodeSelection+`
WHERE grant_id = ? AND offer_id = ?`, grantID, offerID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeSelectionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &selection, nil
}

func validManagedSuspendReason(reason string) bool {
	switch reason {
	case ManagedSuspendNone, ManagedSuspendExpired, ManagedSuspendQuotaExceeded,
		ManagedSuspendAdminDisabled, ManagedSuspendUserDisabled:
		return true
	default:
		return false
	}
}

func (r *TrafficRepository) DeactivateUserNodeSelection(ctx context.Context, username string, selectionID int64, actor, suspendReason string, now time.Time) (*SelectionActivationResult, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username, actor = strings.TrimSpace(username), strings.TrimSpace(actor)
	suspendReason = strings.TrimSpace(suspendReason)
	if suspendReason == "" {
		suspendReason = ManagedSuspendUserDisabled
	}
	if username == "" || actor == "" || selectionID <= 0 || now.IsZero() || !validManagedSuspendReason(suspendReason) || suspendReason == ManagedSuspendNone {
		return nil, ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	now = now.UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin deactivate managed node: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	selection, err := scanUserNodeSelection(tx.QueryRowContext(ctx, selectUserNodeSelection+`
WHERE id = ? AND grant_id IN (SELECT id FROM user_server_grants WHERE username = ?)`, selectionID, username))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeSelectionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get managed selection for deactivation: %w", err)
	}
	if selection.AccessSourceID == nil {
		return nil, ErrManagedAccessSourceNotFound
	}
	source, err := scanUserInboundAccessSource(tx.QueryRowContext(ctx, selectUserInboundAccessSource+` WHERE id = ?`, *selection.AccessSourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrManagedAccessSourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get source for deactivation: %w", err)
	}
	if selection.DesiredEnabled || source.DesiredState != ManagedDesiredInactive || source.SuspendReason != suspendReason {
		if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections SET
    desired_enabled = 0, updated_at = ? WHERE id = ?`, now, selection.ID); err != nil {
			return nil, fmt.Errorf("deactivate managed selection: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    desired_state = ?, suspend_reason = ?, generation = generation + 1,
    retry_count = 0, next_retry_at = NULL, last_error = '', updated_at = ?
WHERE id = ?`, ManagedDesiredInactive, suspendReason, now, source.ID); err != nil {
			return nil, fmt.Errorf("deactivate managed access source: %w", err)
		}
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "selection.deactivated", EntityType: "node_selection", EntityID: selection.ID,
		Username: username, ServerID: source.ServerID,
		Details: map[string]any{"reason": suspendReason},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit deactivate managed node: %w", err)
	}
	selection, err = scanUserNodeSelection(r.db.QueryRowContext(ctx, selectUserNodeSelection+` WHERE id = ?`, selection.ID))
	if err != nil {
		return nil, err
	}
	source, err = scanUserInboundAccessSource(r.db.QueryRowContext(ctx, selectUserInboundAccessSource+` WHERE id = ?`, source.ID))
	if err != nil {
		return nil, err
	}
	return &SelectionActivationResult{Selection: selection, Source: source}, nil
}

func (r *TrafficRepository) SetUserNodeSelectionCredential(ctx context.Context, selectionID, credentialConfigID int64) error {
	if err := managedInitialized(r); err != nil {
		return err
	}
	if selectionID <= 0 || credentialConfigID <= 0 {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `UPDATE user_node_selections SET
    credential_config_id = ?, updated_at = ?
WHERE id = ? AND EXISTS (
    SELECT 1 FROM user_inbound_configs c
    JOIN user_server_grants g ON g.id = user_node_selections.grant_id
    JOIN self_service_node_offers o ON o.id = user_node_selections.offer_id
    WHERE c.id = ? AND c.username = g.username AND c.server_id = g.server_id
      AND c.inbound_tag = o.inbound_tag
)`, credentialConfigID, time.Now().UTC(), selectionID, credentialConfigID)
	if err != nil {
		return fmt.Errorf("set managed selection credential: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var exists int
		_ = r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_node_selections WHERE id = ?)`, selectionID).Scan(&exists)
		if exists == 0 {
			return ErrUserNodeSelectionNotFound
		}
		return ErrManagedServerMismatch
	}
	return nil
}

func (r *TrafficRepository) ClearUserNodeSelectionCredential(ctx context.Context, selectionID, credentialConfigID int64) error {
	if err := managedInitialized(r); err != nil {
		return err
	}
	if selectionID <= 0 || credentialConfigID <= 0 {
		return ErrManagedInvalidArgument
	}
	_, err := r.db.ExecContext(ctx, `UPDATE user_node_selections SET
    credential_config_id = NULL, updated_at = ?
WHERE id = ? AND credential_config_id = ?`, time.Now().UTC(), selectionID, credentialConfigID)
	if err != nil {
		return fmt.Errorf("clear managed selection credential: %w", err)
	}
	return nil
}

func (r *TrafficRepository) UpdateUserNodeSelectionLimits(ctx context.Context, selectionID int64, speed *float64, connection *int, billing *string, actor string) (*UserNodeSelection, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	actor = strings.TrimSpace(actor)
	if selectionID <= 0 || actor == "" || speed != nil && *speed < 0 || connection != nil && *connection < 0 {
		return nil, ErrManagedInvalidArgument
	}
	var normalizedBilling any
	if billing != nil {
		value := strings.ToLower(strings.TrimSpace(*billing))
		if value != ManagedBillingDownload && value != ManagedBillingBoth {
			return nil, ErrManagedInvalidArgument
		}
		normalizedBilling = value
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	now := time.Now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin update managed selection limits: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	selection, err := scanUserNodeSelection(tx.QueryRowContext(ctx, selectUserNodeSelection+` WHERE id = ?`, selectionID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeSelectionNotFound
	}
	if err != nil {
		return nil, err
	}
	var username, grantBilling string
	var serverID int64
	if err := tx.QueryRowContext(ctx, `SELECT username, server_id, billing_mode
FROM user_server_grants WHERE id = ?`, selection.GrantID).Scan(&username, &serverID, &grantBilling); err != nil {
		return nil, err
	}
	currentBilling := grantBilling
	if selection.BillingModeOverride != nil {
		currentBilling = *selection.BillingModeOverride
	}
	nextBilling := grantBilling
	if value, ok := normalizedBilling.(string); ok {
		nextBilling = value
	}
	if currentBilling != nextBilling {
		var recorded int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(uplink_bytes + downlink_bytes, 0)
FROM user_node_selection_usage WHERE selection_id = ?`, selectionID).Scan(&recorded); errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNodeSelectionNotFound
		} else if err != nil {
			return nil, fmt.Errorf("check managed selection usage before billing change: %w", err)
		}
		if recorded > 0 {
			return nil, ErrManagedBillingModeConflict
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections SET
    speed_limit_override_mbps = ?, connection_limit_override = ?,
    billing_mode_override = ?, updated_at = ? WHERE id = ?`, speed, connection,
		normalizedBilling, now, selectionID); err != nil {
		return nil, fmt.Errorf("update managed selection limits: %w", err)
	}
	if selection.AccessSourceID != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    generation = generation + 1, retry_count = 0, next_retry_at = NULL,
    last_error = '', updated_at = ? WHERE id = ?`, now, *selection.AccessSourceID); err != nil {
			return nil, fmt.Errorf("version managed source limits: %w", err)
		}
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "selection.limits_updated", EntityType: "node_selection",
		EntityID: selectionID, Username: username, ServerID: serverID,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit update managed selection limits: %w", err)
	}
	return r.GetUserNodeSelection(ctx, selectionID)
}

func (r *TrafficRepository) GetUserInboundAccessSource(ctx context.Context, id int64) (*UserInboundAccessSource, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	source, err := scanUserInboundAccessSource(r.db.QueryRowContext(ctx, selectUserInboundAccessSource+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrManagedAccessSourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get managed access source: %w", err)
	}
	return &source, nil
}

func (r *TrafficRepository) ListUserInboundAccessSources(ctx context.Context, username string, serverID int64) ([]UserInboundAccessSource, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	where, args := ` WHERE 1 = 1`, make([]any, 0, 2)
	if username != "" {
		where += ` AND username = ?`
		args = append(args, username)
	}
	if serverID > 0 {
		where += ` AND server_id = ?`
		args = append(args, serverID)
	} else if serverID < 0 {
		return nil, ErrManagedInvalidArgument
	}
	rows, err := r.db.QueryContext(ctx, selectUserInboundAccessSource+where+` ORDER BY id ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("list managed access sources: %w", err)
	}
	defer rows.Close()
	sources := make([]UserInboundAccessSource, 0)
	for rows.Next() {
		source, err := scanUserInboundAccessSource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan managed access source: %w", err)
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func validManagedDesiredState(state string) bool {
	return state == ManagedDesiredActive || state == ManagedDesiredInactive || state == ManagedDesiredDeleted
}

func validManagedObservedState(state string) bool {
	return state == ManagedObservedUnknown || state == ManagedObservedActive || state == ManagedObservedInactive
}

func (r *TrafficRepository) SetUserInboundAccessSourceState(ctx context.Context, id, expectedGeneration int64, desiredState, suspendReason, actor string, expiresAt *time.Time) (*UserInboundAccessSource, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	desiredState, suspendReason, actor = strings.TrimSpace(desiredState), strings.TrimSpace(suspendReason), strings.TrimSpace(actor)
	if id <= 0 || expectedGeneration <= 0 || actor == "" || !validManagedDesiredState(desiredState) || !validManagedSuspendReason(suspendReason) {
		return nil, ErrManagedInvalidArgument
	}
	if desiredState == ManagedDesiredActive && suspendReason != ManagedSuspendNone {
		return nil, ErrManagedInvalidArgument
	}
	if expiresAt != nil {
		value := expiresAt.UTC()
		expiresAt = &value
	}
	now := time.Now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin set managed source state: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    desired_state = ?, suspend_reason = ?, expires_at = ?, generation = generation + 1,
    retry_count = 0, next_retry_at = NULL, last_error = '', updated_at = ?
WHERE id = ? AND generation = ?`, desiredState, suspendReason, managedNullTime(expiresAt), now, id, expectedGeneration)
	if err != nil {
		return nil, fmt.Errorf("set managed source state: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_inbound_access_sources WHERE id = ?)`, id).Scan(&exists); err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrManagedAccessSourceNotFound
		}
		return nil, ErrManagedGenerationConflict
	}
	source, err := scanUserInboundAccessSource(tx.QueryRowContext(ctx, selectUserInboundAccessSource+` WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "access_source.desired_changed", EntityType: "access_source",
		EntityID: id, Username: source.Username, ServerID: source.ServerID,
		Details: map[string]any{"desired_state": desiredState, "generation": source.Generation, "reason": suspendReason},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit set managed source state: %w", err)
	}
	return &source, nil
}

func (r *TrafficRepository) MarkUserInboundAccessSourceApplied(ctx context.Context, id, generation int64, observedState string, now time.Time) (*UserInboundAccessSource, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	observedState = strings.TrimSpace(observedState)
	if id <= 0 || generation <= 0 || now.IsZero() || !validManagedObservedState(observedState) || observedState == ManagedObservedUnknown {
		return nil, ErrManagedInvalidArgument
	}
	now = now.UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin mark managed source applied: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    observed_state = ?, applied_generation = ?, retry_count = 0,
    next_retry_at = NULL, last_error = '', updated_at = ?
WHERE id = ? AND generation = ?`, observedState, generation, now, id, generation)
	if err != nil {
		return nil, fmt.Errorf("mark managed source applied: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_inbound_access_sources WHERE id = ?)`, id).Scan(&exists); err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrManagedAccessSourceNotFound
		}
		return nil, ErrManagedGenerationConflict
	}
	source, err := scanUserInboundAccessSource(tx.QueryRowContext(ctx, selectUserInboundAccessSource+` WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if source.SourceType == ManagedSourceSelection {
		column := "activated_at"
		if observedState == ManagedObservedInactive {
			column = "deactivated_at"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections SET `+column+` = ?, updated_at = ? WHERE id = ?`, now, now, source.SourceID); err != nil {
			return nil, fmt.Errorf("mark managed selection applied: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit mark managed source applied: %w", err)
	}
	return &source, nil
}

func (r *TrafficRepository) MarkUserInboundAccessSourceFailed(ctx context.Context, id, generation int64, errorSummary string, nextRetryAt time.Time) (*UserInboundAccessSource, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if id <= 0 || generation <= 0 || nextRetryAt.IsZero() {
		return nil, ErrManagedInvalidArgument
	}
	errorSummary = sanitizeManagedError(errorSummary)
	if errorSummary == "" {
		return nil, ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    retry_count = retry_count + 1, next_retry_at = ?, last_error = ?, updated_at = ?
WHERE id = ? AND generation = ? AND applied_generation != generation`, nextRetryAt.UTC(), errorSummary, time.Now().UTC(), id, generation)
	if err != nil {
		return nil, fmt.Errorf("mark managed source failed: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var exists int
		if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_inbound_access_sources WHERE id = ?)`, id).Scan(&exists); err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrManagedAccessSourceNotFound
		}
		return nil, ErrManagedGenerationConflict
	}
	return r.GetUserInboundAccessSource(ctx, id)
}

func (r *TrafficRepository) ListPendingUserInboundAccessSources(ctx context.Context, now time.Time, limit int, serverID int64) ([]UserInboundAccessSource, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if now.IsZero() || serverID < 0 {
		return nil, ErrManagedInvalidArgument
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := selectUserInboundAccessSource + ` WHERE generation != applied_generation
AND (next_retry_at IS NULL OR next_retry_at <= ?)`
	args := []any{now.UTC()}
	if serverID > 0 {
		query += ` AND server_id = ?`
		args = append(args, serverID)
	}
	query += ` ORDER BY COALESCE(next_retry_at, created_at) ASC, id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list pending managed access sources: %w", err)
	}
	defer rows.Close()
	sources := make([]UserInboundAccessSource, 0)
	for rows.Next() {
		source, err := scanUserInboundAccessSource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan pending managed source: %w", err)
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

// ExpireDirectUserInboundAccessSources atomically moves applied direct grants
// past their deadline into the existing desired-state reconciliation queue.
// Failed remote cleanup is then retried by ListPendingUserInboundAccessSources.
func (r *TrafficRepository) ExpireDirectUserInboundAccessSources(ctx context.Context, now time.Time, limit int) (int, error) {
	if err := managedInitialized(r); err != nil {
		return 0, err
	}
	if now.IsZero() {
		return 0, ErrManagedInvalidArgument
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	now = now.UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin expire direct access sources: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id, username, server_id FROM user_inbound_access_sources
WHERE source_type = ? AND desired_state = ? AND expires_at IS NOT NULL AND expires_at <= ?
ORDER BY expires_at ASC, id ASC LIMIT ?`, ManagedSourceDirect, ManagedDesiredActive, now, limit)
	if err != nil {
		return 0, fmt.Errorf("list expired direct access sources: %w", err)
	}
	type expiredDirectSource struct {
		id       int64
		username string
		serverID int64
	}
	sources := make([]expiredDirectSource, 0, limit)
	for rows.Next() {
		var source expiredDirectSource
		if err := rows.Scan(&source.id, &source.username, &source.serverID); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan expired direct access source: %w", err)
		}
		sources = append(sources, source)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(sources) == 0 {
		return 0, nil
	}
	updated := 0
	for _, source := range sources {
		result, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    desired_state = ?, suspend_reason = ?, generation = generation + 1,
    retry_count = 0, next_retry_at = NULL, last_error = '', updated_at = ?
WHERE id = ? AND source_type = ? AND desired_state = ?
  AND expires_at IS NOT NULL AND expires_at <= ?`, ManagedDesiredInactive, ManagedSuspendExpired,
			now, source.id, ManagedSourceDirect, ManagedDesiredActive, now)
		if err != nil {
			return 0, fmt.Errorf("expire direct access source %d: %w", source.id, err)
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			continue
		}
		updated++
		if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
			Actor: "reconciler", Action: "access_source.desired_changed", EntityType: "access_source",
			EntityID: source.id, Username: source.username, ServerID: source.serverID,
			Details: map[string]any{"desired_state": ManagedDesiredInactive, "reason": ManagedSuspendExpired},
		}); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit expire direct access sources: %w", err)
	}
	return updated, nil
}

func (r *TrafficRepository) HasEffectiveUserInboundAccess(ctx context.Context, username string, serverID int64, inboundTag string, excludeSourceID int64, now time.Time) (bool, *time.Time, error) {
	if err := managedInitialized(r); err != nil {
		return false, nil, err
	}
	username, inboundTag = strings.TrimSpace(username), strings.TrimSpace(inboundTag)
	if username == "" || serverID <= 0 || inboundTag == "" || excludeSourceID < 0 || now.IsZero() {
		return false, nil, ErrManagedInvalidArgument
	}
	rows, err := r.db.QueryContext(ctx, `SELECT s.expires_at, g.allowed_protocols_json,
	       g.allowed_protocol_profiles_json,
	       COALESCE(n.protocol, ''), COALESCE(n.clash_config, ''), COALESCE(o.inbound_tag, ''),
	       sel.credential_config_id, c.id, c.username, c.server_id, c.inbound_tag, c.protocol,
	       s.observed_state, s.generation, s.applied_generation
FROM user_inbound_access_sources s
JOIN user_node_selections sel ON sel.id = s.source_id AND sel.desired_enabled = 1
JOIN user_server_grants g ON g.id = sel.grant_id AND g.username = s.username AND g.server_id = s.server_id
JOIN self_service_node_offers o ON o.id = sel.offer_id AND o.enabled = 1
	AND o.server_id = s.server_id AND o.inbound_tag = s.inbound_tag
JOIN remote_servers rs ON rs.id = o.server_id AND LOWER(TRIM(COALESCE(rs.xray_mode, 'external'))) = 'embedded'
JOIN nodes n ON n.id = o.node_id AND n.id = s.node_id AND n.enabled = 1
	AND LOWER(TRIM(COALESCE(n.node_type, 'physical'))) = 'physical'
	AND COALESCE(n.original_server, '') = rs.name
	AND COALESCE(n.inbound_tag, '') = o.inbound_tag
LEFT JOIN user_inbound_configs c ON c.id = sel.credential_config_id
WHERE s.username = ? AND s.server_id = ? AND s.inbound_tag = ? AND s.id != ?
	  AND s.source_type = ? AND s.desired_state = ?
	  AND s.starts_at <= ? AND (s.expires_at IS NULL OR s.expires_at > ?)`,
		username, serverID, inboundTag, excludeSourceID, ManagedSourceSelection,
		ManagedDesiredActive, now.UTC(), now.UTC())
	if err != nil {
		return false, nil, fmt.Errorf("resolve effective managed access: %w", err)
	}
	defer rows.Close()
	hasAccess, perpetual := false, false
	var latest *time.Time
	for rows.Next() {
		var expires sql.NullString
		var allowedProtocolsJSON, allowedProtocolProfilesJSON, protocol, clashConfig, offerInboundTag string
		var credentialID, configID, configServerID sql.NullInt64
		var configUsername, configInboundTag, configProtocol sql.NullString
		var observedState string
		var generation, appliedGeneration int64
		if err := rows.Scan(&expires, &allowedProtocolsJSON, &allowedProtocolProfilesJSON, &protocol, &clashConfig, &offerInboundTag,
			&credentialID, &configID, &configUsername, &configServerID, &configInboundTag, &configProtocol,
			&observedState, &generation, &appliedGeneration); err != nil {
			return false, nil, fmt.Errorf("scan effective managed access: %w", err)
		}
		var allowedProtocols []string
		if err := json.Unmarshal([]byte(allowedProtocolsJSON), &allowedProtocols); err != nil {
			return false, nil, fmt.Errorf("decode effective managed access protocols: %w", err)
		}
		allowedProtocols, err = NormalizeManagedGrantAllowedProtocols(allowedProtocols)
		if err != nil {
			return false, nil, fmt.Errorf("decode effective managed access protocols: %w", err)
		}
		var allowedProtocolProfiles []string
		if err := json.Unmarshal([]byte(allowedProtocolProfilesJSON), &allowedProtocolProfiles); err != nil {
			return false, nil, fmt.Errorf("decode effective managed access protocol profiles: %w", err)
		}
		allowedProtocolProfiles, err = NormalizeManagedGrantAllowedProtocolProfiles(allowedProtocolProfiles)
		if err != nil {
			return false, nil, fmt.Errorf("decode effective managed access protocol profiles: %w", err)
		}
		grant := UserServerGrant{AllowedProtocols: allowedProtocols, AllowedProtocolProfiles: allowedProtocolProfiles}
		if !grant.AllowsNodeProtocol(protocol, clashConfig) || !SelfServiceNodeProtocolEligible(protocol, clashConfig) ||
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(offerInboundTag)), "anydoor-") {
			continue
		}
		// A nil credential pointer means this source is still provisioning. Once
		// a credential has been linked, its protocol becomes an immutable safety
		// snapshot: changing the node protocol requires cleanup and reactivation.
		if !credentialID.Valid {
			// Only a source that has never completed provisioning may authorize
			// credential creation without a snapshot. An applied source missing its
			// credential link is corrupt and must fail closed.
			if appliedGeneration != 0 || observedState == ManagedObservedActive {
				continue
			}
		} else {
			if !configID.Valid || configID.Int64 != credentialID.Int64 ||
				!configUsername.Valid || configUsername.String != username ||
				!configServerID.Valid || configServerID.Int64 != serverID ||
				!configInboundTag.Valid || configInboundTag.String != inboundTag ||
				!configProtocol.Valid || !SelfServiceCredentialProtocolMatches(configProtocol.String, protocol) {
				continue
			}
		}
		hasAccess = true
		expiresAt := managedParseNullTime(expires)
		if expiresAt == nil {
			perpetual = true
			continue
		}
		if latest == nil || expiresAt.After(*latest) {
			latest = expiresAt
		}
	}
	if err := rows.Err(); err != nil {
		return false, nil, fmt.Errorf("resolve effective managed access: %w", err)
	}
	if !hasAccess {
		return false, nil, nil
	}
	if perpetual {
		return true, nil, nil
	}
	return true, latest, nil
}
