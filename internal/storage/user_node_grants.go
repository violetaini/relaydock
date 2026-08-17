package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const ManagedSourceDirect = "direct"

var (
	ErrUserNodeGrantNotFound    = errors.New("user node grant not found")
	ErrUserNodeGrantConflict    = errors.New("user node grant conflicts with another source")
	ErrNodeHasActiveDirectGrant = errors.New("node has active direct user grants")
)

// UserNodeGrant is an administrator-assigned, fixed-node authorization. The
// access source owns desired/observed provisioning state; this row owns source
// attribution and the immutable link to the selected node.
type UserNodeGrant struct {
	ID                 int64     `json:"id"`
	Username           string    `json:"username"`
	NodeID             int64     `json:"node_id"`
	CredentialConfigID *int64    `json:"credential_config_id,omitempty"`
	AccessSourceID     int64     `json:"access_source_id"`
	SourceType         string    `json:"source_type"`
	SourcePackageID    *int64    `json:"source_package_id,omitempty"`
	Version            int64     `json:"version"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type UserNodeGrantWithSource struct {
	Grant  UserNodeGrant           `json:"grant"`
	Source UserInboundAccessSource `json:"source"`
}

type WireGuardDirectGrantCandidate struct {
	GrantID  int64
	Username string
}

const selectUserNodeGrant = `SELECT id, username, node_id, credential_config_id,
       access_source_id, source_type, source_package_id, version, created_by,
       created_at, updated_at
FROM user_node_grants`

func scanUserNodeGrant(scanner rowScanner) (UserNodeGrant, error) {
	var grant UserNodeGrant
	var credentialID, accessSourceID, sourcePackageID sql.NullInt64
	if err := scanner.Scan(&grant.ID, &grant.Username, &grant.NodeID, &credentialID,
		&accessSourceID, &grant.SourceType, &sourcePackageID, &grant.Version,
		&grant.CreatedBy, &grant.CreatedAt, &grant.UpdatedAt); err != nil {
		return grant, err
	}
	if credentialID.Valid {
		grant.CredentialConfigID = &credentialID.Int64
	}
	if accessSourceID.Valid {
		grant.AccessSourceID = accessSourceID.Int64
	}
	if sourcePackageID.Valid {
		grant.SourcePackageID = &sourcePackageID.Int64
	}
	return grant, nil
}

// migrateDirectNodeGrants adds direct as a durable access-source type. SQLite
// cannot alter CHECK constraints, so legacy tables are rebuilt transactionally
// once. There are no foreign keys targeting this table; selection references
// are logical IDs and remain unchanged by the copy.
func (r *TrafficRepository) migrateDirectNodeGrants() error {
	for _, legacyTrigger := range []string{
		"revoke_user_node_grants_before_node_delete",
		"revoke_user_node_grants_after_node_safety_change",
	} {
		if _, err := r.db.Exec(`DROP TRIGGER IF EXISTS ` + legacyTrigger); err != nil {
			return fmt.Errorf("drop obsolete direct node grant trigger %s: %w", legacyTrigger, err)
		}
	}
	var sourceDDL string
	if err := r.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='user_inbound_access_sources'`).Scan(&sourceDDL); err != nil {
		return fmt.Errorf("inspect managed access source schema: %w", err)
	}
	if !strings.Contains(strings.ToLower(sourceDDL), "'direct'") {
		tx, err := r.db.Begin()
		if err != nil {
			return fmt.Errorf("begin direct access source migration: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		for _, index := range []string{
			"idx_user_inbound_access_client",
			"idx_user_inbound_access_pending",
			"idx_user_inbound_access_source",
		} {
			if _, err := tx.Exec(`DROP INDEX IF EXISTS ` + index); err != nil {
				return fmt.Errorf("drop managed access source index %s: %w", index, err)
			}
		}
		if _, err := tx.Exec(`ALTER TABLE user_inbound_access_sources RENAME TO user_inbound_access_sources_legacy_direct`); err != nil {
			return fmt.Errorf("rename managed access source table: %w", err)
		}
		if _, err := tx.Exec(`CREATE TABLE user_inbound_access_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    inbound_tag TEXT NOT NULL,
    node_id INTEGER NOT NULL,
    source_type TEXT NOT NULL CHECK(source_type IN ('package', 'selection', 'legacy_review', 'direct')),
    source_id INTEGER NOT NULL,
    desired_state TEXT NOT NULL CHECK(desired_state IN ('active', 'inactive', 'deleted')),
    observed_state TEXT NOT NULL DEFAULT 'unknown' CHECK(observed_state IN ('unknown', 'active', 'inactive')),
    suspend_reason TEXT NOT NULL DEFAULT 'none' CHECK(suspend_reason IN ('none', 'expired', 'quota_exceeded', 'admin_disabled', 'user_disabled')),
    generation INTEGER NOT NULL DEFAULT 1 CHECK(generation >= 1),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK(applied_generation >= 0),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count >= 0),
    next_retry_at TIMESTAMP,
    last_error TEXT NOT NULL DEFAULT '',
    starts_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, server_id, inbound_tag, node_id, source_type, source_id)
)`); err != nil {
			return fmt.Errorf("create direct-capable access source table: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO user_inbound_access_sources (
    id, username, server_id, inbound_tag, node_id, source_type, source_id,
    desired_state, observed_state, suspend_reason, generation, applied_generation,
    retry_count, next_retry_at, last_error, starts_at, expires_at, created_at, updated_at
)
SELECT id, username, server_id, inbound_tag, node_id, source_type, source_id,
       desired_state, observed_state, suspend_reason, generation, applied_generation,
       retry_count, next_retry_at, last_error, starts_at, expires_at, created_at, updated_at
FROM user_inbound_access_sources_legacy_direct`); err != nil {
			return fmt.Errorf("copy managed access sources: %w", err)
		}
		if _, err := tx.Exec(`DROP TABLE user_inbound_access_sources_legacy_direct`); err != nil {
			return fmt.Errorf("drop legacy managed access source table: %w", err)
		}
		if _, err := tx.Exec(`CREATE INDEX idx_user_inbound_access_client ON user_inbound_access_sources(username, server_id, inbound_tag, desired_state);
CREATE INDEX idx_user_inbound_access_pending ON user_inbound_access_sources(server_id, next_retry_at, generation, applied_generation);
CREATE INDEX idx_user_inbound_access_source ON user_inbound_access_sources(source_type, source_id);`); err != nil {
			return fmt.Errorf("recreate managed access source indexes: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit direct access source migration: %w", err)
		}
	}

	const schema = `
CREATE TABLE IF NOT EXISTS user_node_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    node_id INTEGER NOT NULL,
    credential_config_id INTEGER,
    access_source_id INTEGER,
    source_type TEXT NOT NULL DEFAULT 'manual' CHECK(source_type IN ('manual', 'package')),
    source_package_id INTEGER,
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    created_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, node_id)
);
CREATE INDEX IF NOT EXISTS idx_user_node_grants_user ON user_node_grants(username, source_type, node_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_node_grants_source ON user_node_grants(access_source_id) WHERE access_source_id IS NOT NULL;

DROP TRIGGER IF EXISTS guard_user_node_grants_before_node_delete;
DROP TRIGGER IF EXISTS finalize_inactive_user_node_grants_before_node_delete;
DROP TRIGGER IF EXISTS cleanup_user_node_grants_before_node_delete;

CREATE TRIGGER cleanup_user_node_grants_before_node_delete
BEFORE DELETE ON nodes
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM user_node_grants g
        LEFT JOIN user_inbound_access_sources s ON s.id = g.access_source_id
        LEFT JOIN remote_servers rs ON rs.name = OLD.original_server
        WHERE g.node_id = OLD.id AND (
            g.source_type != 'manual' OR g.source_package_id IS NOT NULL
            OR s.id IS NULL OR s.source_type != 'direct'
            OR s.source_id != g.id OR s.node_id != g.node_id
            OR s.username != g.username OR rs.id IS NULL OR s.server_id != rs.id
            OR s.inbound_tag != COALESCE(OLD.inbound_tag, '')
            OR s.desired_state != 'inactive'
            OR s.observed_state != 'inactive'
            OR s.applied_generation != s.generation
        )
        UNION ALL
        SELECT 1 FROM user_inbound_access_sources s
        WHERE s.source_type = 'direct' AND s.node_id = OLD.id AND NOT EXISTS (
            SELECT 1 FROM user_node_grants g
            WHERE g.id = s.source_id AND g.access_source_id = s.id
              AND g.node_id = OLD.id AND g.username = s.username
              AND g.source_type = 'manual' AND g.source_package_id IS NULL
        )
    ) THEN RAISE(ABORT, 'node has active or unreconciled direct user grants') END;

    DELETE FROM user_inbound_access_sources
    WHERE source_type = 'direct' AND node_id = OLD.id;
    DELETE FROM user_node_grants WHERE node_id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS guard_user_node_grants_before_node_safety_change
BEFORE UPDATE OF enabled, node_type, original_server, inbound_tag, protocol, clash_config ON nodes
WHEN EXISTS (
    SELECT 1 FROM user_node_grants g
    JOIN user_inbound_access_sources s ON s.id = g.access_source_id
    WHERE g.node_id = OLD.id AND s.desired_state = 'active'
) AND (
    OLD.enabled != NEW.enabled
    OR COALESCE(OLD.node_type, '') != COALESCE(NEW.node_type, '')
    OR COALESCE(OLD.original_server, '') != COALESCE(NEW.original_server, '')
    OR COALESCE(OLD.inbound_tag, '') != COALESCE(NEW.inbound_tag, '')
    OR COALESCE(OLD.protocol, '') != COALESCE(NEW.protocol, '')
    OR COALESCE(OLD.clash_config, '') != COALESCE(NEW.clash_config, '')
)
BEGIN
    SELECT RAISE(ABORT, 'node has active direct user grants');
END;

`
	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate direct node grants: %w", err)
	}
	return nil
}

// DirectNodeGrantEligible is the authoritative inventory predicate exposed to
// admin clients before they attempt an individualized fixed-node grant.
func DirectNodeGrantEligible(node Node, server RemoteServer) bool {
	nodeType := strings.ToLower(strings.TrimSpace(node.NodeType))
	if nodeType == "" {
		nodeType = "physical"
	}
	return node.ID > 0 && node.Enabled && nodeType == "physical" &&
		strings.TrimSpace(node.OriginalServer) != "" && node.OriginalServer == server.Name &&
		strings.TrimSpace(node.InboundTag) != "" &&
		strings.EqualFold(strings.TrimSpace(server.XrayMode), "embedded") &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(node.InboundTag)), "anydoor-") &&
		SelfServiceNodeProtocolEligible(node.Protocol, node.ClashConfig)
}

// validateNodeDeletion fails before callers perform remote cleanup when any
// selected node still grants a user access.
func (r *TrafficRepository) validateNodeDeletion(ctx context.Context, nodeIDs []int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	unique := make([]int64, 0, len(nodeIDs))
	seen := make(map[int64]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		if id <= 0 {
			return ErrManagedInvalidArgument
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return nil
	}
	placeholders := make([]string, len(unique))
	args := make([]any, len(unique))
	for i, id := range unique {
		placeholders[i] = "?"
		args[i] = id
	}
	var blocked int
	idsClause := strings.Join(placeholders, ",")
	query := `SELECT EXISTS(
    SELECT 1 FROM user_node_grants g
    JOIN nodes n ON n.id = g.node_id
    LEFT JOIN user_inbound_access_sources s ON s.id = g.access_source_id
    LEFT JOIN remote_servers rs ON rs.name = n.original_server
    WHERE g.node_id IN (` + idsClause + `) AND (
        g.source_type != 'manual' OR g.source_package_id IS NOT NULL
        OR s.id IS NULL OR s.source_type != 'direct'
        OR s.source_id != g.id OR s.node_id != g.node_id
        OR s.username != g.username OR rs.id IS NULL OR s.server_id != rs.id
        OR s.inbound_tag != COALESCE(n.inbound_tag, '')
        OR s.desired_state != 'inactive'
        OR s.observed_state != 'inactive'
        OR s.applied_generation != s.generation
    )
    UNION ALL
    SELECT 1 FROM user_inbound_access_sources s
    WHERE s.source_type = 'direct' AND s.node_id IN (` + idsClause + `)
      AND NOT EXISTS (
          SELECT 1 FROM user_node_grants g
          WHERE g.id = s.source_id AND g.access_source_id = s.id
            AND g.node_id = s.node_id AND g.username = s.username
            AND g.source_type = 'manual' AND g.source_package_id IS NULL
      )
)`
	queryArgs := append(append(make([]any, 0, len(args)*2), args...), args...)
	if err := r.db.QueryRowContext(ctx, query, queryArgs...).Scan(&blocked); err != nil {
		return fmt.Errorf("check direct node grant deletion safety: %w", err)
	}
	if blocked != 0 {
		return ErrNodeHasActiveDirectGrant
	}
	return nil
}

func (r *TrafficRepository) ValidateNodeDeletion(ctx context.Context, nodeIDs []int64) error {
	if r == nil {
		return errors.New("traffic repository not initialized")
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	return r.validateNodeDeletion(ctx, nodeIDs)
}

// HasActiveDirectNodeGrantsForServer reports whether changing the identity or
// advertised endpoint of a server would invalidate an individualized fixed
// node grant. Callers must check this before any remote or database mutation.
func (r *TrafficRepository) HasActiveDirectNodeGrantsForServer(ctx context.Context, serverID int64) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return false, ErrManagedInvalidArgument
	}
	var exists int
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(
    SELECT 1
    FROM user_node_grants g
    JOIN user_inbound_access_sources s
      ON s.id = g.access_source_id AND s.source_type = 'direct'
    WHERE s.server_id = ? AND s.desired_state = 'active'
)`, serverID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check active direct grants for server: %w", err)
	}
	return exists != 0, nil
}

// AcquireNodeDeletionLease keeps direct-grant writes serialized from the
// fail-closed preflight through the remote cleanup and final local deletion.
// Without the lease, a new grant could land between the preflight query and an
// irreversible Agent mutation.
func (r *TrafficRepository) AcquireNodeDeletionLease(ctx context.Context, nodeIDs []int64) (func(), error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.managedNodeMu.Lock()
	if err := ctx.Err(); err != nil {
		r.managedNodeMu.Unlock()
		return nil, err
	}
	if err := r.validateNodeDeletion(ctx, nodeIDs); err != nil {
		r.managedNodeMu.Unlock()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(r.managedNodeMu.Unlock) }, nil
}

func loadDirectGrantTargetTx(ctx context.Context, tx *sql.Tx, username string, nodeID int64) (User, Node, RemoteServer, error) {
	var user User
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT username, role, is_active, authorization_mode FROM users WHERE username = ?`, username).
		Scan(&user.Username, &user.Role, &active, &user.AuthorizationMode); errors.Is(err, sql.ErrNoRows) {
		return user, Node{}, RemoteServer{}, ErrUserNotFound
	} else if err != nil {
		return user, Node{}, RemoteServer{}, fmt.Errorf("load direct grant user: %w", err)
	}
	user.IsActive = active != 0
	if !user.IsActive || user.Role != RoleUser {
		return user, Node{}, RemoteServer{}, ErrManagedGrantInactive
	}
	var node Node
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT id, username, node_name, protocol, clash_config,
       enabled, COALESCE(original_server, ''), COALESCE(inbound_tag, ''), COALESCE(node_type, 'physical')
FROM nodes WHERE id = ?`, nodeID).Scan(&node.ID, &node.Username, &node.NodeName,
		&node.Protocol, &node.ClashConfig, &enabled, &node.OriginalServer,
		&node.InboundTag, &node.NodeType); errors.Is(err, sql.ErrNoRows) {
		return user, node, RemoteServer{}, ErrNodeNotFound
	} else if err != nil {
		return user, node, RemoteServer{}, fmt.Errorf("load direct grant node: %w", err)
	}
	node.Enabled = enabled != 0
	var server RemoteServer
	if err := tx.QueryRowContext(ctx, `SELECT id, name, COALESCE(xray_mode, 'external')
FROM remote_servers WHERE name = ?`, node.OriginalServer).Scan(&server.ID, &server.Name, &server.XrayMode); errors.Is(err, sql.ErrNoRows) {
		return user, node, server, ErrRemoteServerNotFound
	} else if err != nil {
		return user, node, server, fmt.Errorf("load direct grant server: %w", err)
	}
	if !DirectNodeGrantEligible(node, server) {
		return user, node, server, ErrManagedServerMismatch
	}
	if strings.EqualFold(strings.TrimSpace(node.Protocol), "wireguard") {
		provisionable, provenanceErr := managedWireGuardNodeProvisionable(ctx, tx, node.ID)
		if provenanceErr != nil {
			return user, node, server, provenanceErr
		}
		if !provisionable {
			return user, node, server, ErrManagedServerMismatch
		}
	}
	return user, node, server, nil
}

func (r *TrafficRepository) UpsertManualUserNodeGrant(ctx context.Context, username string, nodeID int64, expiresAt *time.Time, actor string) (*UserNodeGrantWithSource, bool, error) {
	username, actor = strings.TrimSpace(username), strings.TrimSpace(actor)
	if username == "" || nodeID <= 0 || actor == "" {
		return nil, false, ErrManagedInvalidArgument
	}
	now := time.Now().UTC()
	if expiresAt != nil {
		value := expiresAt.UTC()
		if !value.After(now) {
			return nil, false, ErrManagedInvalidArgument
		}
		expiresAt = &value
	}
	leasedCtx, releaseAuthorization, err := r.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		return nil, false, err
	}
	defer releaseAuthorization()
	ctx = leasedCtx
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin direct node grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := requireUserAuthorizationMode(ctx, tx, username, AuthorizationModeCustom); err != nil {
		return nil, false, err
	}
	_, node, server, err := loadDirectGrantTargetTx(ctx, tx, username, nodeID)
	if err != nil {
		return nil, false, err
	}

	grant, err := scanUserNodeGrant(tx.QueryRowContext(ctx, selectUserNodeGrant+` WHERE username = ? AND node_id = ?`, username, nodeID))
	created := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO user_node_grants (
    username, node_id, source_type, version, created_by, created_at, updated_at
) VALUES (?, ?, ?, 1, ?, ?, ?)`, username, nodeID, GrantSourceManual, actor, now, now)
		if insertErr != nil {
			return nil, false, fmt.Errorf("create direct node grant: %w", insertErr)
		}
		grant.ID, _ = result.LastInsertId()
		grant.Username, grant.NodeID, grant.SourceType = username, nodeID, GrantSourceManual
		grant.Version, grant.CreatedBy, grant.CreatedAt, grant.UpdatedAt = 1, actor, now, now
		created = true
	case err != nil:
		return nil, false, fmt.Errorf("get direct node grant: %w", err)
	case grant.SourceType != GrantSourceManual:
		return nil, false, ErrUserNodeGrantConflict
	}

	if grant.AccessSourceID == 0 {
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO user_inbound_access_sources (
    username, server_id, inbound_tag, node_id, source_type, source_id,
    desired_state, observed_state, suspend_reason, generation, applied_generation,
    starts_at, expires_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?)`,
			username, server.ID, node.InboundTag, nodeID, ManagedSourceDirect, grant.ID,
			ManagedDesiredActive, ManagedObservedUnknown, ManagedSuspendNone,
			now, managedNullTime(expiresAt), now, now)
		if insertErr != nil {
			return nil, false, fmt.Errorf("create direct node access source: %w", insertErr)
		}
		grant.AccessSourceID, _ = result.LastInsertId()
		if _, err := tx.ExecContext(ctx, `UPDATE user_node_grants SET access_source_id = ?, updated_at = ? WHERE id = ?`,
			grant.AccessSourceID, now, grant.ID); err != nil {
			return nil, false, fmt.Errorf("link direct node access source: %w", err)
		}
	} else if !created {
		result, updateErr := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    desired_state = ?, suspend_reason = ?, starts_at = ?, expires_at = ?,
    generation = generation + 1, retry_count = 0, next_retry_at = NULL,
    last_error = '', updated_at = ?
WHERE id = ? AND source_type = ? AND source_id = ?`, ManagedDesiredActive,
			ManagedSuspendNone, now, managedNullTime(expiresAt), now,
			grant.AccessSourceID, ManagedSourceDirect, grant.ID)
		if updateErr != nil {
			return nil, false, fmt.Errorf("reactivate direct node grant: %w", updateErr)
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			return nil, false, ErrManagedAccessSourceNotFound
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_node_grants SET version = version + 1, updated_at = ? WHERE id = ?`, now, grant.ID); err != nil {
			return nil, false, fmt.Errorf("version direct node grant: %w", err)
		}
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "node_grant.activated", EntityType: "node_grant",
		EntityID: grant.ID, Username: username, ServerID: server.ID,
		Details: map[string]any{"node_id": nodeID, "source_type": GrantSourceManual},
	}); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit direct node grant: %w", err)
	}
	result, err := r.GetUserNodeGrant(ctx, grant.ID)
	return result, created, err
}

func (r *TrafficRepository) GetUserNodeGrant(ctx context.Context, id int64) (*UserNodeGrantWithSource, error) {
	if id <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	grant, err := scanUserNodeGrant(r.db.QueryRowContext(ctx, selectUserNodeGrant+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get direct node grant: %w", err)
	}
	if grant.AccessSourceID <= 0 {
		return nil, ErrManagedAccessSourceNotFound
	}
	source, err := r.GetUserInboundAccessSource(ctx, grant.AccessSourceID)
	if err != nil {
		return nil, err
	}
	return &UserNodeGrantWithSource{Grant: grant, Source: *source}, nil
}

func (r *TrafficRepository) ListUserNodeGrants(ctx context.Context, username string) ([]UserNodeGrantWithSource, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrManagedInvalidArgument
	}
	rows, err := r.db.QueryContext(ctx, selectUserNodeGrant+` WHERE username = ? ORDER BY node_id ASC, id ASC`, username)
	if err != nil {
		return nil, fmt.Errorf("list direct node grants: %w", err)
	}
	defer rows.Close()
	grants := make([]UserNodeGrant, 0)
	for rows.Next() {
		grant, err := scanUserNodeGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("scan direct node grant: %w", err)
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items := make([]UserNodeGrantWithSource, 0, len(grants))
	for _, grant := range grants {
		if grant.AccessSourceID <= 0 {
			continue
		}
		source, err := r.GetUserInboundAccessSource(ctx, grant.AccessSourceID)
		if err != nil {
			return nil, err
		}
		items = append(items, UserNodeGrantWithSource{Grant: grant, Source: *source})
	}
	return items, nil
}

func (r *TrafficRepository) ListActiveWireGuardDirectGrantCandidates(ctx context.Context, limit int) ([]WireGuardDirectGrantCandidate, error) {
	return r.ListActiveWireGuardDirectGrantCandidatesAfter(ctx, 0, limit)
}

func (r *TrafficRepository) ListActiveWireGuardDirectGrantCandidatesAfter(
	ctx context.Context,
	afterGrantID int64,
	limit int,
) ([]WireGuardDirectGrantCandidate, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if afterGrantID < 0 {
		return nil, ErrManagedInvalidArgument
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT g.id, g.username
FROM user_node_grants g
JOIN user_inbound_access_sources s
  ON s.id = g.access_source_id AND s.source_type = 'direct' AND s.source_id = g.id
JOIN nodes n ON n.id = g.node_id
WHERE g.source_type = 'manual' AND g.source_package_id IS NULL
  AND s.desired_state = 'active'
  AND LOWER(TRIM(COALESCE(n.protocol, ''))) = 'wireguard'
  AND g.id > ?
ORDER BY g.id ASC LIMIT ?`, afterGrantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list active WireGuard direct grants: %w", err)
	}
	defer rows.Close()
	items := make([]WireGuardDirectGrantCandidate, 0)
	for rows.Next() {
		var item WireGuardDirectGrantCandidate
		if err := rows.Scan(&item.GrantID, &item.Username); err != nil {
			return nil, fmt.Errorf("scan active WireGuard direct grant: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// DeactivateWireGuardDirectGrantIfProvenanceInvalid rechecks provenance while
// holding the account and managed-node write locks. A resource repaired after
// the periodic scan is therefore not revoked by stale observation.
func (r *TrafficRepository) DeactivateWireGuardDirectGrantIfProvenanceInvalid(
	ctx context.Context,
	id int64,
	username, actor string,
) (bool, error) {
	username, actor = strings.TrimSpace(username), strings.TrimSpace(actor)
	if id <= 0 || username == "" || actor == "" {
		return false, ErrManagedInvalidArgument
	}
	leasedCtx, releaseAuthorization, err := r.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		return false, err
	}
	defer releaseAuthorization()
	ctx = leasedCtx
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	grant, err := scanUserNodeGrant(tx.QueryRowContext(ctx, selectUserNodeGrant+` WHERE id = ? AND username = ?`, id, username))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if grant.SourceType != GrantSourceManual || grant.SourcePackageID != nil || grant.AccessSourceID <= 0 {
		return false, nil
	}
	source, err := scanUserInboundAccessSource(tx.QueryRowContext(ctx, selectUserInboundAccessSource+`
WHERE id = ? AND source_type = ? AND source_id = ?`, grant.AccessSourceID, ManagedSourceDirect, grant.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if source.DesiredState != ManagedDesiredActive {
		return false, nil
	}
	var protocol string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(protocol, '') FROM nodes WHERE id = ?`, grant.NodeID).Scan(&protocol); errors.Is(err, sql.ErrNoRows) {
		protocol = "wireguard"
	} else if err != nil {
		return false, err
	}
	if !strings.EqualFold(strings.TrimSpace(protocol), "wireguard") {
		return false, nil
	}
	provisionable, err := managedWireGuardNodeProvisionable(ctx, tx, grant.NodeID)
	if err != nil {
		return false, err
	}
	if provisionable {
		return false, nil
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    desired_state = ?, suspend_reason = ?, generation = generation + 1,
    retry_count = 0, next_retry_at = NULL, last_error = '', updated_at = ?
WHERE id = ? AND generation = ? AND desired_state = ?`, ManagedDesiredInactive,
		ManagedSuspendAdminDisabled, now, source.ID, source.Generation, ManagedDesiredActive)
	if err != nil {
		return false, fmt.Errorf("deactivate invalid WireGuard direct grant: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_grants SET version = version + 1, updated_at = ? WHERE id = ?`, now, grant.ID); err != nil {
		return false, err
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "node_grant.provenance_revoked", EntityType: "node_grant",
		EntityID: grant.ID, Username: username, ServerID: source.ServerID,
		Details: map[string]any{"node_id": grant.NodeID, "inbound_tag": source.InboundTag},
	}); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (r *TrafficRepository) SetUserNodeGrantDesiredState(ctx context.Context, id int64, username, desiredState, actor string) (*UserNodeGrantWithSource, error) {
	username, actor = strings.TrimSpace(username), strings.TrimSpace(actor)
	if id <= 0 || username == "" || actor == "" ||
		(desiredState != ManagedDesiredActive && desiredState != ManagedDesiredInactive) {
		return nil, ErrManagedInvalidArgument
	}
	leasedCtx, releaseAuthorization, err := r.AcquireUserAuthorizationLease(ctx, username)
	if err != nil {
		return nil, err
	}
	defer releaseAuthorization()
	ctx = leasedCtx
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	grant, err := scanUserNodeGrant(tx.QueryRowContext(ctx, selectUserNodeGrant+` WHERE id = ? AND username = ?`, id, username))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNodeGrantNotFound
	}
	if err != nil {
		return nil, err
	}
	if grant.SourceType != GrantSourceManual || grant.AccessSourceID <= 0 {
		return nil, ErrUserNodeGrantConflict
	}
	if desiredState == ManagedDesiredActive {
		if err := requireUserAuthorizationMode(ctx, tx, username, AuthorizationModeCustom); err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	suspendReason := ManagedSuspendAdminDisabled
	if desiredState == ManagedDesiredActive {
		_, _, _, err := loadDirectGrantTargetTx(ctx, tx, username, grant.NodeID)
		if err != nil {
			return nil, err
		}
		suspendReason = ManagedSuspendNone
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources SET
    desired_state = ?, suspend_reason = ?, generation = generation + 1,
    retry_count = 0, next_retry_at = NULL, last_error = '', updated_at = ?
WHERE id = ? AND source_type = ? AND source_id = ?`, desiredState, suspendReason,
		now, grant.AccessSourceID, ManagedSourceDirect, grant.ID)
	if err != nil {
		return nil, fmt.Errorf("set direct node grant state: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return nil, ErrManagedAccessSourceNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_node_grants SET version = version + 1, updated_at = ? WHERE id = ?`, now, grant.ID); err != nil {
		return nil, err
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "node_grant." + desiredState, EntityType: "node_grant",
		EntityID: grant.ID, Username: username, Details: map[string]any{"node_id": grant.NodeID},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetUserNodeGrant(ctx, grant.ID)
}

func (r *TrafficRepository) SetUserNodeGrantCredential(ctx context.Context, id, credentialConfigID int64) error {
	if id <= 0 || credentialConfigID <= 0 {
		return ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `UPDATE user_node_grants SET credential_config_id = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND (credential_config_id IS NULL OR credential_config_id = ?)`, credentialConfigID, id, credentialConfigID)
	if err != nil {
		return fmt.Errorf("link direct node credential: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrManagedAccessConflict
	}
	return nil
}

func (r *TrafficRepository) ClearUserNodeGrantCredential(ctx context.Context, id, credentialConfigID int64) error {
	if id <= 0 || credentialConfigID <= 0 {
		return ErrManagedInvalidArgument
	}
	_, err := r.db.ExecContext(ctx, `UPDATE user_node_grants SET credential_config_id = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND credential_config_id = ?`, id, credentialConfigID)
	return err
}

// HasEffectiveDirectUserInboundAccess deliberately accepts never-applied
// desired sources so the reconciler can create the first credential. Once a
// source has been applied, its immutable credential link must remain valid.
func (r *TrafficRepository) HasEffectiveDirectUserInboundAccess(ctx context.Context, username string, serverID int64, inboundTag string, excludeSourceID int64, now time.Time) (bool, *time.Time, error) {
	username, inboundTag = strings.TrimSpace(username), strings.TrimSpace(inboundTag)
	if username == "" || serverID <= 0 || inboundTag == "" || excludeSourceID < 0 || now.IsZero() {
		return false, nil, ErrManagedInvalidArgument
	}
	rows, err := r.db.QueryContext(ctx, `SELECT n.id, s.expires_at, n.protocol, n.clash_config,
       g.credential_config_id, c.id, c.username, c.server_id, c.inbound_tag, c.protocol,
       s.observed_state, s.generation, s.applied_generation
FROM user_inbound_access_sources s
JOIN user_node_grants g ON g.id = s.source_id AND g.access_source_id = s.id
JOIN users u ON u.username = g.username AND u.is_active = 1
JOIN nodes n ON n.id = g.node_id AND n.id = s.node_id AND n.enabled = 1
JOIN remote_servers rs ON rs.id = s.server_id AND rs.name = n.original_server
    AND LOWER(TRIM(COALESCE(rs.xray_mode, 'external'))) = 'embedded'
LEFT JOIN user_inbound_configs c ON c.id = g.credential_config_id
WHERE s.username = ? AND s.server_id = ? AND s.inbound_tag = ? AND s.id != ?
  AND s.source_type = ? AND s.desired_state = ?
  AND LOWER(TRIM(COALESCE(n.node_type, 'physical'))) = 'physical'
  AND n.inbound_tag = s.inbound_tag
  AND s.starts_at <= ? AND (s.expires_at IS NULL OR s.expires_at > ?)`,
		username, serverID, inboundTag, excludeSourceID, ManagedSourceDirect,
		ManagedDesiredActive, now.UTC(), now.UTC())
	if err != nil {
		return false, nil, fmt.Errorf("resolve effective direct access: %w", err)
	}
	defer rows.Close()
	hasAccess, perpetual := false, false
	var latest *time.Time
	for rows.Next() {
		var nodeID int64
		var expires sql.NullString
		var protocol, clashConfig string
		var credentialID, configID, configServerID sql.NullInt64
		var configUsername, configInbound, configProtocol sql.NullString
		var observed string
		var generation, appliedGeneration int64
		if err := rows.Scan(&nodeID, &expires, &protocol, &clashConfig, &credentialID, &configID,
			&configUsername, &configServerID, &configInbound, &configProtocol,
			&observed, &generation, &appliedGeneration); err != nil {
			return false, nil, err
		}
		if !SelfServiceNodeProtocolEligible(protocol, clashConfig) || strings.HasPrefix(strings.ToLower(inboundTag), "anydoor-") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(protocol), "wireguard") {
			provisionable, provenanceErr := r.ManagedWireGuardNodeProvisionable(ctx, nodeID)
			if provenanceErr != nil {
				return false, nil, provenanceErr
			}
			if !provisionable {
				continue
			}
		}
		if !credentialID.Valid {
			if appliedGeneration != 0 || observed == ManagedObservedActive {
				continue
			}
		} else if !configID.Valid || configID.Int64 != credentialID.Int64 ||
			!configUsername.Valid || configUsername.String != username ||
			!configServerID.Valid || configServerID.Int64 != serverID ||
			!configInbound.Valid || configInbound.String != inboundTag ||
			!configProtocol.Valid || !SelfServiceCredentialProtocolMatches(configProtocol.String, protocol) {
			continue
		}
		hasAccess = true
		expiresAt := managedParseNullTime(expires)
		if expiresAt == nil {
			perpetual = true
		} else if latest == nil || expiresAt.After(*latest) {
			latest = expiresAt
		}
	}
	if err := rows.Err(); err != nil {
		return false, nil, err
	}
	if !hasAccess {
		return false, nil, nil
	}
	if perpetual {
		return true, nil, nil
	}
	return true, latest, nil
}

func (r *TrafficRepository) ListEffectiveDirectNodeIDs(ctx context.Context, username string, now time.Time) ([]int64, error) {
	username = strings.TrimSpace(username)
	if username == "" || now.IsZero() {
		return nil, ErrManagedInvalidArgument
	}
	rows, err := r.db.QueryContext(ctx, `SELECT g.node_id, n.protocol, n.clash_config,
       g.credential_config_id, c.id, c.username, c.server_id, c.inbound_tag, c.protocol,
       s.server_id, s.inbound_tag
FROM user_node_grants g
JOIN user_inbound_access_sources s ON s.id = g.access_source_id AND s.source_type = 'direct' AND s.source_id = g.id
JOIN users u ON u.username = g.username AND u.is_active = 1
JOIN nodes n ON n.id = g.node_id AND n.enabled = 1
JOIN remote_servers rs ON rs.id = s.server_id AND rs.name = n.original_server
    AND LOWER(TRIM(COALESCE(rs.xray_mode, 'external'))) = 'embedded'
LEFT JOIN user_inbound_configs c ON c.id = g.credential_config_id
WHERE g.username = ? AND s.desired_state = 'active' AND s.observed_state = 'active'
  AND s.generation = s.applied_generation
  AND LOWER(TRIM(COALESCE(n.node_type, 'physical'))) = 'physical'
  AND n.inbound_tag = s.inbound_tag
  AND s.starts_at <= ? AND (s.expires_at IS NULL OR s.expires_at > ?)
ORDER BY g.node_id ASC`, username, now.UTC(), now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list effective direct node grants: %w", err)
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var nodeID, sourceServerID int64
		var protocol, clashConfig, sourceInbound string
		var credentialID, configID, configServerID sql.NullInt64
		var configUsername, configInbound, configProtocol sql.NullString
		if err := rows.Scan(&nodeID, &protocol, &clashConfig, &credentialID, &configID,
			&configUsername, &configServerID, &configInbound, &configProtocol,
			&sourceServerID, &sourceInbound); err != nil {
			return nil, err
		}
		if !SelfServiceNodeProtocolEligible(protocol, clashConfig) || !credentialID.Valid ||
			!configID.Valid || configID.Int64 != credentialID.Int64 ||
			!configUsername.Valid || configUsername.String != username ||
			!configServerID.Valid || configServerID.Int64 != sourceServerID ||
			!configInbound.Valid || configInbound.String != sourceInbound ||
			!configProtocol.Valid || !SelfServiceCredentialProtocolMatches(configProtocol.String, protocol) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(protocol), "wireguard") {
			provisionable, provenanceErr := r.ManagedWireGuardNodeProvisionable(ctx, nodeID)
			if provenanceErr != nil {
				return nil, provenanceErr
			}
			if !provisionable {
				continue
			}
		}
		ids = append(ids, nodeID)
	}
	return ids, rows.Err()
}

// ListAuthorizedDirectNodeIDs returns active desired grants even while the
// reconciler is still provisioning their credentials. API callers use this to
// keep the authorized node visible as pending without exposing owner config.
func (r *TrafficRepository) ListAuthorizedDirectNodeIDs(ctx context.Context, username string, now time.Time) ([]int64, error) {
	username = strings.TrimSpace(username)
	if username == "" || now.IsZero() {
		return nil, ErrManagedInvalidArgument
	}
	rows, err := r.db.QueryContext(ctx, `SELECT g.node_id, COALESCE(n.protocol, '')
FROM user_node_grants g
JOIN user_inbound_access_sources s ON s.id=g.access_source_id AND s.source_type='direct' AND s.source_id=g.id
JOIN users u ON u.username=g.username AND u.is_active=1
JOIN nodes n ON n.id=g.node_id AND n.enabled=1
JOIN remote_servers rs ON rs.id=s.server_id AND rs.name=n.original_server
    AND LOWER(TRIM(COALESCE(rs.xray_mode,'external')))='embedded'
WHERE g.username=? AND s.desired_state='active'
  AND LOWER(TRIM(COALESCE(n.node_type,'physical')))='physical'
  AND n.inbound_tag=s.inbound_tag AND s.starts_at<=?
  AND (s.expires_at IS NULL OR s.expires_at>?)
ORDER BY g.node_id ASC`, username, now.UTC(), now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list authorized direct node grants: %w", err)
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		var protocol string
		if err := rows.Scan(&id, &protocol); err != nil {
			return nil, err
		}
		if strings.EqualFold(strings.TrimSpace(protocol), "wireguard") {
			provisionable, provenanceErr := r.ManagedWireGuardNodeProvisionable(ctx, id)
			if provenanceErr != nil {
				return nil, provenanceErr
			}
			if !provisionable {
				continue
			}
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
