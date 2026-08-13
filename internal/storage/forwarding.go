package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/tunnelidentity"
)

const (
	TunnelStateActive    = "active"
	TunnelStateDraining  = "draining"
	TunnelStateSuspended = "suspended"

	ForwardDesiredActive   = "active"
	ForwardDesiredInactive = "inactive"
	ForwardDesiredDeleted  = "deleted"

	ForwardObservedPending        = "pending"
	ForwardObservedProvisioning   = "provisioning"
	ForwardObservedActive         = "active"
	ForwardObservedSuspended      = "suspended"
	ForwardObservedCleanupPending = "cleanup_pending"
	ForwardObservedError          = "error"

	ForwardNetworkTCP    = "tcp"
	ForwardNetworkUDP    = "udp"
	ForwardNetworkTCPUDP = "tcp_udp"
)

var (
	ErrTunnelTemplateNotFound = errors.New("tunnel template not found")
	ErrTunnelGrantNotFound    = errors.New("tunnel grant not found")
	ErrUserForwardNotFound    = errors.New("forward not found")
	ErrForwardingConflict     = errors.New("forwarding resource conflict")
	ErrForwardingForbidden    = errors.New("forwarding operation is not allowed")
	ErrForwardingLimit        = errors.New("forwarding limit reached")
	ErrForwardingInvalid      = errors.New("invalid forwarding argument")
)

type TunnelTemplate struct {
	ID                      int64               `json:"id"`
	PublicID                string              `json:"public_id"`
	Name                    string              `json:"name"`
	Description             string              `json:"description"`
	State                   string              `json:"state"`
	Network                 string              `json:"network"`
	BillingMode             string              `json:"billing_mode"`
	TrafficMultiplierMilli  int                 `json:"traffic_multiplier_milli"`
	MaxTotalForwards        int                 `json:"max_total_forwards"`
	AllowManagedTarget      bool                `json:"allow_managed_target"`
	AllowCustomPublicTarget bool                `json:"allow_custom_public_target"`
	PortRangeStart          int                 `json:"port_range_start"`
	PortRangeEnd            int                 `json:"port_range_end"`
	Version                 int64               `json:"version"`
	CreatedBy               string              `json:"created_by"`
	CreatedAt               time.Time           `json:"created_at"`
	UpdatedAt               time.Time           `json:"updated_at"`
	Hops                    []TunnelTemplateHop `json:"hops"`
}

type TunnelTemplateHop struct {
	ID          int64     `json:"id"`
	TunnelID    int64     `json:"tunnel_id"`
	Position    int       `json:"position"`
	ServerID    int64     `json:"server_id"`
	ServerName  string    `json:"server_name,omitempty"`
	ConnectHost string    `json:"connect_host,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type UserTunnelGrant struct {
	ID                        int64           `json:"id"`
	PublicID                  string          `json:"public_id"`
	Username                  string          `json:"username"`
	TunnelID                  int64           `json:"tunnel_id"`
	Enabled                   bool            `json:"enabled"`
	StartsAt                  time.Time       `json:"starts_at"`
	ExpiresAt                 *time.Time      `json:"expires_at,omitempty"`
	MaxActiveForwards         int             `json:"max_active_forwards"`
	PerForwardSpeedMbps       float64         `json:"per_forward_speed_mbps"`
	PerForwardConnectionLimit int             `json:"per_forward_connection_limit"`
	TrafficLimitBytes         int64           `json:"traffic_limit_bytes"`
	BillingModeOverride       *string         `json:"billing_mode_override,omitempty"`
	AllowManagedTarget        bool            `json:"allow_managed_target"`
	AllowCustomPublicTarget   bool            `json:"allow_custom_public_target"`
	SourceType                string          `json:"source_type"`
	SourcePackageID           *int64          `json:"source_package_id,omitempty"`
	Version                   int64           `json:"version"`
	CreatedBy                 string          `json:"created_by"`
	CreatedAt                 time.Time       `json:"created_at"`
	UpdatedAt                 time.Time       `json:"updated_at"`
	Tunnel                    *TunnelTemplate `json:"tunnel,omitempty"`
	ActiveForwardCount        int             `json:"active_forward_count"`
	UsedBytes                 int64           `json:"used_bytes"`
	State                     string          `json:"state"`
}

func (g UserTunnelGrant) StateAt(now time.Time, userEnabled bool, tunnelState string, usedBytes int64) string {
	if !userEnabled {
		return "user_disabled"
	}
	if now.Before(g.StartsAt) {
		return "scheduled"
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return "expired"
	}
	if !g.Enabled {
		return "suspended"
	}
	if g.TrafficLimitBytes > 0 && usedBytes >= g.TrafficLimitBytes {
		return "over_limit"
	}
	switch tunnelState {
	case TunnelStateActive:
		return "active"
	case TunnelStateDraining:
		return "tunnel_draining"
	default:
		return "tunnel_unavailable"
	}
}

type UserForwardRule struct {
	ID                             int64            `json:"id"`
	PublicID                       string           `json:"public_id"`
	GrantID                        int64            `json:"grant_id"`
	Username                       string           `json:"username"`
	Name                           string           `json:"name"`
	TargetType                     string           `json:"target_type"`
	TargetNodeID                   int64            `json:"target_node_id"`
	TargetHost                     string           `json:"target_host"`
	TargetPort                     int              `json:"target_port"`
	Network                        string           `json:"network"`
	SourceCIDRs                    []string         `json:"source_cidrs"`
	RequestedEntryPort             int              `json:"requested_entry_port"`
	AllocatedEntryPort             int              `json:"allocated_entry_port"`
	DesiredState                   string           `json:"desired_state"`
	ObservedState                  string           `json:"observed_state"`
	SuspendReason                  string           `json:"suspend_reason"`
	Generation                     int64            `json:"generation"`
	AppliedGeneration              int64            `json:"applied_generation"`
	EffectiveExpiresAt             *time.Time       `json:"effective_expires_at,omitempty"`
	BillingModeSnapshot            string           `json:"billing_mode_snapshot"`
	TrafficMultiplierMilliSnapshot int              `json:"traffic_multiplier_milli_snapshot"`
	LastErrorCode                  string           `json:"last_error_code,omitempty"`
	LastErrorDetail                string           `json:"last_error_detail,omitempty"`
	CreatedAt                      time.Time        `json:"created_at"`
	UpdatedAt                      time.Time        `json:"updated_at"`
	Hops                           []UserForwardHop `json:"hops,omitempty"`
}

type UserForwardHop struct {
	ID                int64     `json:"id"`
	ForwardID         int64     `json:"forward_id"`
	TemplateHopID     int64     `json:"template_hop_id"`
	Position          int       `json:"position"`
	ServerID          int64     `json:"server_id"`
	ServerName        string    `json:"server_name,omitempty"`
	ResourceID        string    `json:"resource_id"`
	ResourceTag       string    `json:"resource_tag"`
	ListenPort        int       `json:"listen_port"`
	NextHost          string    `json:"next_host"`
	NextPort          int       `json:"next_port"`
	DesiredState      string    `json:"desired_state"`
	ObservedState     string    `json:"observed_state"`
	Generation        int64     `json:"generation"`
	AppliedGeneration int64     `json:"applied_generation"`
	RetryCount        int       `json:"retry_count"`
	LastError         string    `json:"last_error,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type ForwardUsage struct {
	ForwardID      int64     `json:"forward_id"`
	CycleStartedAt time.Time `json:"cycle_started_at"`
	UplinkBytes    int64     `json:"uplink_bytes"`
	DownlinkBytes  int64     `json:"downlink_bytes"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type ForwardAuditEvent struct {
	ID         int64     `json:"id"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	EntityType string    `json:"entity_type"`
	EntityID   int64     `json:"entity_id"`
	Username   string    `json:"username"`
	Details    string    `json:"details,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func forwardingID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s%x", prefix, time.Now().UnixNano())
	}
	return prefix + hex.EncodeToString(b)
}

func (r *TrafficRepository) migrateForwarding() error {
	const schema = `
CREATE TABLE IF NOT EXISTS tunnel_templates (
 id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','draining','suspended')),
 network TEXT NOT NULL DEFAULT 'tcp_udp' CHECK(network IN ('tcp','tcp_udp')),
 billing_mode TEXT NOT NULL DEFAULT 'both' CHECK(billing_mode IN ('download','both')),
 traffic_multiplier_milli INTEGER NOT NULL DEFAULT 1000 CHECK(traffic_multiplier_milli > 0),
 max_total_forwards INTEGER NOT NULL DEFAULT 0 CHECK(max_total_forwards >= 0),
 allow_managed_target INTEGER NOT NULL DEFAULT 1 CHECK(allow_managed_target IN (0,1)),
 allow_custom_public_target INTEGER NOT NULL DEFAULT 0 CHECK(allow_custom_public_target = 0),
	port_range_start INTEGER NOT NULL DEFAULT 1024 CHECK(port_range_start BETWEEN 1024 AND 65535),
	port_range_end INTEGER NOT NULL DEFAULT 65535 CHECK(port_range_end BETWEEN 1024 AND 65535),
 version INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(port_range_start <= port_range_end)
);
CREATE TABLE IF NOT EXISTS tunnel_template_hops (
 id INTEGER PRIMARY KEY AUTOINCREMENT, tunnel_id INTEGER NOT NULL,
 position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 7), server_id INTEGER NOT NULL,
 connect_host TEXT NOT NULL DEFAULT '', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(tunnel_id, position), UNIQUE(tunnel_id, server_id)
);
CREATE INDEX IF NOT EXISTS idx_tunnel_hops_server ON tunnel_template_hops(server_id);
CREATE TABLE IF NOT EXISTS user_tunnel_grants (
 id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT NOT NULL UNIQUE,
 username TEXT NOT NULL, tunnel_id INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
 starts_at TIMESTAMP NOT NULL, expires_at TIMESTAMP,
 max_active_forwards INTEGER NOT NULL DEFAULT 1 CHECK(max_active_forwards >= 0),
 per_forward_speed_mbps REAL NOT NULL DEFAULT 0 CHECK(per_forward_speed_mbps >= 0),
 per_forward_connection_limit INTEGER NOT NULL DEFAULT 0 CHECK(per_forward_connection_limit >= 0),
 traffic_limit_bytes INTEGER NOT NULL DEFAULT 0 CHECK(traffic_limit_bytes >= 0),
 billing_mode_override TEXT CHECK(billing_mode_override IS NULL OR billing_mode_override IN ('download','both')),
 allow_managed_target INTEGER NOT NULL DEFAULT 1,
 allow_custom_public_target INTEGER NOT NULL DEFAULT 0 CHECK(allow_custom_public_target = 0),
 version INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(username, tunnel_id)
);
CREATE INDEX IF NOT EXISTS idx_tunnel_grants_user ON user_tunnel_grants(username, enabled);
CREATE TABLE IF NOT EXISTS user_forward_rules (
 id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT NOT NULL UNIQUE,
 grant_id INTEGER NOT NULL, username TEXT NOT NULL, name TEXT NOT NULL,
 target_type TEXT NOT NULL CHECK(target_type = 'managed_node'), target_node_id INTEGER NOT NULL,
 target_host TEXT NOT NULL, target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
 network TEXT NOT NULL DEFAULT 'tcp_udp' CHECK(network IN ('tcp','tcp_udp')),
 source_cidrs TEXT NOT NULL DEFAULT '[]',
	requested_entry_port INTEGER NOT NULL DEFAULT 0 CHECK(requested_entry_port = 0 OR requested_entry_port BETWEEN 1024 AND 65535),
 allocated_entry_port INTEGER NOT NULL DEFAULT 0,
 desired_state TEXT NOT NULL DEFAULT 'active' CHECK(desired_state IN ('active','inactive','deleted')),
 observed_state TEXT NOT NULL DEFAULT 'pending' CHECK(observed_state IN ('pending','provisioning','active','suspended','cleanup_pending','error')),
 suspend_reason TEXT NOT NULL DEFAULT 'none', generation INTEGER NOT NULL DEFAULT 1,
 applied_generation INTEGER NOT NULL DEFAULT 0, effective_expires_at TIMESTAMP,
 billing_mode_snapshot TEXT NOT NULL, traffic_multiplier_milli_snapshot INTEGER NOT NULL,
 last_error_code TEXT NOT NULL DEFAULT '', last_error_detail TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_forwards_user ON user_forward_rules(username, desired_state);
CREATE INDEX IF NOT EXISTS idx_forwards_grant ON user_forward_rules(grant_id, desired_state);
CREATE TABLE IF NOT EXISTS user_forward_hops (
 id INTEGER PRIMARY KEY AUTOINCREMENT, forward_id INTEGER NOT NULL, template_hop_id INTEGER NOT NULL,
 position INTEGER NOT NULL, server_id INTEGER NOT NULL, resource_id TEXT NOT NULL UNIQUE,
 resource_tag TEXT NOT NULL UNIQUE,
 listen_port INTEGER NOT NULL, next_host TEXT NOT NULL DEFAULT '', next_port INTEGER NOT NULL DEFAULT 0,
 desired_state TEXT NOT NULL DEFAULT 'active', observed_state TEXT NOT NULL DEFAULT 'pending',
 generation INTEGER NOT NULL DEFAULT 1, applied_generation INTEGER NOT NULL DEFAULT 0,
 retry_count INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(forward_id, position)
);
CREATE INDEX IF NOT EXISTS idx_forward_hops_server ON user_forward_hops(server_id, desired_state);
CREATE TABLE IF NOT EXISTS server_port_allocations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, network TEXT NOT NULL,
 port INTEGER NOT NULL, owner_type TEXT NOT NULL, owner_id INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'reserved', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(server_id, network, port), UNIQUE(owner_type, owner_id, network)
);
CREATE TABLE IF NOT EXISTS user_forward_usage (
 forward_id INTEGER PRIMARY KEY, cycle_started_at TIMESTAMP NOT NULL,
 uplink_bytes INTEGER NOT NULL DEFAULT 0, downlink_bytes INTEGER NOT NULL DEFAULT 0,
 last_raw_uplink INTEGER NOT NULL DEFAULT 0, last_raw_downlink INTEGER NOT NULL DEFAULT 0,
 counter_epoch TEXT NOT NULL DEFAULT '', updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_tunnel_grant_usage_archive (
 grant_id INTEGER PRIMARY KEY, billed_bytes INTEGER NOT NULL DEFAULT 0 CHECK(billed_bytes >= 0),
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tunnel_audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
 entity_type TEXT NOT NULL, entity_id INTEGER NOT NULL, username TEXT NOT NULL DEFAULT '',
 details TEXT NOT NULL DEFAULT '', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_tunnel_audit_entity ON tunnel_audit_events(entity_type, entity_id, created_at DESC);
`
	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate forwarding: %w", err)
	}
	if err := r.ensureTableColumn("user_forward_rules", "source_cidrs", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return fmt.Errorf("migrate user_forward_rules.source_cidrs: %w", err)
	}
	if err := r.migrateForwardingChecks(); err != nil {
		return err
	}
	if err := r.ensureTableColumn("user_forward_hops", "resource_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate user_forward_hops.resource_id: %w", err)
	}
	if err := r.ensureTableColumn("user_tunnel_grants", "source_type", "TEXT NOT NULL DEFAULT 'manual'"); err != nil {
		return fmt.Errorf("migrate tunnel grant source type: %w", err)
	}
	if err := r.ensureTableColumn("user_tunnel_grants", "source_package_id", "INTEGER"); err != nil {
		return fmt.Errorf("migrate tunnel grant source package: %w", err)
	}
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_tunnel_grants_package_source ON user_tunnel_grants(username, source_package_id) WHERE source_type = 'package'`); err != nil {
		return fmt.Errorf("migrate tunnel grant source index: %w", err)
	}
	if _, err := r.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_forward_hops_resource_id ON user_forward_hops(resource_id) WHERE resource_id != ''`); err != nil {
		return fmt.Errorf("migrate user_forward_hops.resource_id index: %w", err)
	}
	if err := r.migrateLegacyForwardedNodes(context.Background()); err != nil {
		return err
	}
	return nil
}

// migrateLegacyForwardedNodes classifies tunnel clones created before nodes
// persisted their provenance in node_type. The active desired inbound is the
// database's authoritative definition for the remote listener. The source
// endpoint and cloned config fingerprint prove the node was derived from that
// tunnel target, without relying on a mutable name, primary tag, or tag prefix.
func (r *TrafficRepository) migrateLegacyForwardedNodes(ctx context.Context) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin legacy forwarded node migration: %w", err)
	}
	defer tx.Rollback()

	const legacyForwardedPredicate = `
LOWER(COALESCE(NULLIF(TRIM(COALESCE(nodes.node_type, '')), ''), 'physical')) = 'physical'
AND nodes.parent_node_id IS NULL
AND LOWER(TRIM(COALESCE(nodes.protocol, ''))) NOT IN ('tunnel', 'dokodemo-door')
AND TRIM(COALESCE(nodes.original_server, '')) != ''
AND TRIM(COALESCE(nodes.inbound_tag, '')) != ''
AND EXISTS (
    SELECT 1
    FROM remote_servers AS server
    JOIN remote_inbound_desired AS desired ON desired.server_id = server.id
    WHERE server.name = TRIM(nodes.original_server)
      AND desired.inbound_tag = TRIM(nodes.inbound_tag)
      AND desired.desired_state = 'active'
      AND json_valid(desired.inbound_json) = 1
      AND json_valid(nodes.clash_config) = 1
      AND json_type(nodes.clash_config, '$.server') = 'text'
      AND TRIM(json_extract(nodes.clash_config, '$.server')) != ''
      AND TRIM(json_extract(nodes.clash_config, '$.server')) IN (
          TRIM(COALESCE(server.domain, '')),
          TRIM(COALESCE(server.pull_address, '')),
          TRIM(COALESCE(server.ip_address, ''))
      )
      AND json_type(nodes.clash_config, '$.port') = 'integer'
      AND json_type(desired.inbound_json, '$.port') = 'integer'
      AND CAST(json_extract(desired.inbound_json, '$.port') AS INTEGER) BETWEEN 1 AND 65535
      AND CAST(json_extract(nodes.clash_config, '$.port') AS INTEGER) =
          CAST(json_extract(desired.inbound_json, '$.port') AS INTEGER)
      AND (
          SELECT COUNT(*)
          FROM nodes AS same_inbound
          WHERE same_inbound.original_server = nodes.original_server
            AND same_inbound.inbound_tag = nodes.inbound_tag
            AND LOWER(COALESCE(NULLIF(TRIM(COALESCE(same_inbound.node_type, '')), ''), 'physical')) = 'physical'
            AND same_inbound.parent_node_id IS NULL
            AND LOWER(TRIM(COALESCE(same_inbound.protocol, ''))) NOT IN ('tunnel', 'dokodemo-door')
      ) = 1
      AND LOWER(TRIM(COALESCE(CASE
          WHEN json_valid(desired.inbound_json) = 1
          THEN json_extract(desired.inbound_json, '$.protocol')
      END, '')))
          IN ('tunnel', 'dokodemo-door')
      AND json_type(desired.inbound_json, '$.settings.address') = 'text'
      AND TRIM(json_extract(desired.inbound_json, '$.settings.address')) != ''
      AND json_type(desired.inbound_json, '$.settings.port') = 'integer'
      AND CAST(json_extract(desired.inbound_json, '$.settings.port') AS INTEGER) BETWEEN 1 AND 65535
      AND EXISTS (
          SELECT 1
          FROM nodes AS source
          WHERE source.id != nodes.id
            AND LOWER(TRIM(COALESCE(source.protocol, ''))) = LOWER(TRIM(COALESCE(nodes.protocol, '')))
            AND json_valid(source.clash_config) = 1
            AND json_type(source.clash_config, '$.server') = 'text'
            AND TRIM(json_extract(source.clash_config, '$.server')) =
                TRIM(json_extract(desired.inbound_json, '$.settings.address'))
            AND json_type(source.clash_config, '$.port') = 'integer'
            AND CAST(json_extract(source.clash_config, '$.port') AS INTEGER) =
                CAST(json_extract(desired.inbound_json, '$.settings.port') AS INTEGER)
            AND json_remove(source.clash_config, '$.name', '$.server', '$.port') =
                json_remove(nodes.clash_config, '$.name', '$.server', '$.port')
      )
)`

	// An offer created while the clone still looked physical must stop granting
	// access in the same transaction that records the corrected provenance.
	if _, err := tx.ExecContext(ctx, `UPDATE self_service_node_offers
SET enabled = 0, updated_at = CURRENT_TIMESTAMP
WHERE enabled = 1
  AND node_id IN (SELECT nodes.id FROM nodes WHERE `+legacyForwardedPredicate+`)`); err != nil {
		return fmt.Errorf("disable legacy forwarded node offers: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE nodes
SET node_type = 'forwarded', updated_at = CURRENT_TIMESTAMP
WHERE `+legacyForwardedPredicate)
	if err != nil {
		return fmt.Errorf("backfill legacy forwarded node provenance: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read legacy forwarded node migration count: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy forwarded node migration: %w", err)
	}
	if changed > 0 {
		r.invalidateTrafficBillingCache()
	}
	return nil
}

func (r *TrafficRepository) migrateForwardingChecks() error {
	ctx := context.Background()
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire forwarding migration connection: %w", err)
	}
	defer conn.Close()
	if err := beginForwardingImmediate(ctx, conn); err != nil {
		return fmt.Errorf("begin forwarding constraint migration: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	var templateSQL, forwardSQL string
	if err := conn.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='tunnel_templates'`).Scan(&templateSQL); err != nil {
		return fmt.Errorf("inspect tunnel_templates: %w", err)
	}
	if err := conn.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='user_forward_rules'`).Scan(&forwardSQL); err != nil {
		return fmt.Errorf("inspect user_forward_rules: %w", err)
	}
	templateSQL = strings.ToLower(templateSQL)
	forwardSQL = strings.ToLower(forwardSQL)
	needsTemplateRebuild := !strings.Contains(templateSQL, ForwardNetworkTCPUDP) || strings.Contains(templateSQL, "between 39000 and 40000")
	hasRequestedEntryPort := strings.Contains(forwardSQL, "requested_entry_port")
	needsForwardRebuild := !strings.Contains(forwardSQL, ForwardNetworkTCPUDP) || !hasRequestedEntryPort

	if needsTemplateRebuild {
		if _, err := conn.ExecContext(ctx, `DROP TABLE IF EXISTS tunnel_templates_forwarding_new;
CREATE TABLE tunnel_templates_forwarding_new (
 id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','draining','suspended')),
 network TEXT NOT NULL DEFAULT 'tcp_udp' CHECK(network IN ('tcp','tcp_udp')),
 billing_mode TEXT NOT NULL DEFAULT 'both' CHECK(billing_mode IN ('download','both')),
 traffic_multiplier_milli INTEGER NOT NULL DEFAULT 1000 CHECK(traffic_multiplier_milli > 0),
 max_total_forwards INTEGER NOT NULL DEFAULT 0 CHECK(max_total_forwards >= 0),
 allow_managed_target INTEGER NOT NULL DEFAULT 1 CHECK(allow_managed_target IN (0,1)),
 allow_custom_public_target INTEGER NOT NULL DEFAULT 0 CHECK(allow_custom_public_target = 0),
 port_range_start INTEGER NOT NULL DEFAULT 1024 CHECK(port_range_start BETWEEN 1024 AND 65535),
 port_range_end INTEGER NOT NULL DEFAULT 65535 CHECK(port_range_end BETWEEN 1024 AND 65535),
 version INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(port_range_start <= port_range_end)
);
INSERT INTO tunnel_templates_forwarding_new(id,public_id,name,description,state,network,billing_mode,traffic_multiplier_milli,max_total_forwards,allow_managed_target,allow_custom_public_target,port_range_start,port_range_end,version,created_by,created_at,updated_at)
SELECT id,public_id,name,description,state,network,billing_mode,traffic_multiplier_milli,max_total_forwards,allow_managed_target,allow_custom_public_target,port_range_start,port_range_end,version,created_by,created_at,updated_at FROM tunnel_templates;
DROP TABLE tunnel_templates;
ALTER TABLE tunnel_templates_forwarding_new RENAME TO tunnel_templates;`); err != nil {
			return fmt.Errorf("rebuild tunnel_templates constraints: %w", err)
		}
	}

	if needsForwardRebuild {
		requestedEntryPortSelect := "0"
		if hasRequestedEntryPort {
			requestedEntryPortSelect = "requested_entry_port"
		}
		forwardRebuildSQL := fmt.Sprintf(`DROP TABLE IF EXISTS user_forward_rules_forwarding_new;
CREATE TABLE user_forward_rules_forwarding_new (
 id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT NOT NULL UNIQUE,
 grant_id INTEGER NOT NULL, username TEXT NOT NULL, name TEXT NOT NULL,
 target_type TEXT NOT NULL CHECK(target_type = 'managed_node'), target_node_id INTEGER NOT NULL,
 target_host TEXT NOT NULL, target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
 network TEXT NOT NULL DEFAULT 'tcp_udp' CHECK(network IN ('tcp','tcp_udp')),
 source_cidrs TEXT NOT NULL DEFAULT '[]',
 requested_entry_port INTEGER NOT NULL DEFAULT 0 CHECK(requested_entry_port = 0 OR requested_entry_port BETWEEN 1024 AND 65535),
 allocated_entry_port INTEGER NOT NULL DEFAULT 0,
 desired_state TEXT NOT NULL DEFAULT 'active' CHECK(desired_state IN ('active','inactive','deleted')),
 observed_state TEXT NOT NULL DEFAULT 'pending' CHECK(observed_state IN ('pending','provisioning','active','suspended','cleanup_pending','error')),
 suspend_reason TEXT NOT NULL DEFAULT 'none', generation INTEGER NOT NULL DEFAULT 1,
 applied_generation INTEGER NOT NULL DEFAULT 0, effective_expires_at TIMESTAMP,
 billing_mode_snapshot TEXT NOT NULL, traffic_multiplier_milli_snapshot INTEGER NOT NULL,
 last_error_code TEXT NOT NULL DEFAULT '', last_error_detail TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO user_forward_rules_forwarding_new(id,public_id,grant_id,username,name,target_type,target_node_id,target_host,target_port,network,source_cidrs,requested_entry_port,allocated_entry_port,desired_state,observed_state,suspend_reason,generation,applied_generation,effective_expires_at,billing_mode_snapshot,traffic_multiplier_milli_snapshot,last_error_code,last_error_detail,created_at,updated_at)
SELECT id,public_id,grant_id,username,name,target_type,target_node_id,target_host,target_port,network,source_cidrs,%s,allocated_entry_port,desired_state,observed_state,suspend_reason,generation,applied_generation,effective_expires_at,billing_mode_snapshot,traffic_multiplier_milli_snapshot,last_error_code,last_error_detail,created_at,updated_at FROM user_forward_rules;
DROP TABLE user_forward_rules;
ALTER TABLE user_forward_rules_forwarding_new RENAME TO user_forward_rules;
CREATE INDEX IF NOT EXISTS idx_forwards_user ON user_forward_rules(username, desired_state);
CREATE INDEX IF NOT EXISTS idx_forwards_grant ON user_forward_rules(grant_id, desired_state);`, requestedEntryPortSelect)
		if _, err := conn.ExecContext(ctx, forwardRebuildSQL); err != nil {
			return fmt.Errorf("rebuild user_forward_rules constraints: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, `UPDATE user_forward_hops
SET generation=generation+1, applied_generation=0, observed_state='pending', last_error='', updated_at=CURRENT_TIMESTAMP
WHERE forward_id IN (
  SELECT id FROM user_forward_rules WHERE network='tcp' AND desired_state='active'
);
UPDATE user_forward_rules
SET network='tcp_udp',
    generation=CASE WHEN desired_state='active' THEN generation+1 ELSE generation END,
    applied_generation=CASE WHEN desired_state='active' THEN 0 ELSE applied_generation END,
    observed_state=CASE WHEN desired_state='active' THEN 'pending' ELSE observed_state END,
    last_error_code=CASE WHEN desired_state='active' THEN '' ELSE last_error_code END,
    last_error_detail=CASE WHEN desired_state='active' THEN '' ELSE last_error_detail END,
    updated_at=CURRENT_TIMESTAMP
WHERE network='tcp';
UPDATE tunnel_templates SET network='tcp_udp',updated_at=CURRENT_TIMESTAMP WHERE network='tcp';`); err != nil {
		return fmt.Errorf("canonicalize forwarding networks: %w", err)
	}
	for _, network := range []string{ForwardNetworkTCP, ForwardNetworkUDP} {
		if _, err := conn.ExecContext(ctx, `INSERT INTO server_port_allocations(server_id,network,port,owner_type,owner_id)
SELECT h.server_id,?,h.listen_port,'forward_hop',h.id
FROM user_forward_hops h
JOIN user_forward_rules f ON f.id=h.forward_id
WHERE f.network=?
  AND NOT EXISTS (
    SELECT 1 FROM server_port_allocations a
    WHERE a.owner_type='forward_hop' AND a.owner_id=h.id AND a.network=?
  )
  AND NOT EXISTS (
    SELECT 1 FROM server_port_allocations a
    WHERE a.server_id=h.server_id AND a.network=? AND a.port=h.listen_port
  )`, network, ForwardNetworkTCPUDP, network, network); err != nil {
			return fmt.Errorf("backfill %s forwarding port allocations: %w", network, err)
		}
	}

	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit forwarding constraint migration: %w", err)
	}
	committed = true
	return nil
}

func beginForwardingImmediate(ctx context.Context, conn *sql.Conn) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err == nil {
			return nil
		}
		message := strings.ToLower(err.Error())
		if !strings.Contains(message, "busy") && !strings.Contains(message, "locked") {
			return err
		}
		delay := time.Duration(attempt+1) * 25 * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func forwardingInitialized(r *TrafficRepository) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	return nil
}

func normalizeTemplate(t *TunnelTemplate) error {
	t.Name = strings.TrimSpace(t.Name)
	t.Description = strings.TrimSpace(t.Description)
	if t.Name == "" || len(t.Hops) < 1 || len(t.Hops) > 8 {
		return ErrForwardingInvalid
	}
	if t.State == "" {
		t.State = TunnelStateActive
	}
	if t.Network == "" || t.Network == ForwardNetworkTCP {
		t.Network = ForwardNetworkTCPUDP
	}
	if t.BillingMode == "" {
		t.BillingMode = ManagedBillingBoth
	}
	if t.TrafficMultiplierMilli == 0 {
		t.TrafficMultiplierMilli = 1000
	}
	if t.PortRangeStart == 0 {
		t.PortRangeStart = 1024
	}
	if t.PortRangeEnd == 0 {
		t.PortRangeEnd = 65535
	}
	if t.State != TunnelStateActive && t.State != TunnelStateDraining && t.State != TunnelStateSuspended ||
		t.Network != ForwardNetworkTCPUDP || (t.BillingMode != ManagedBillingDownload && t.BillingMode != ManagedBillingBoth) ||
		t.TrafficMultiplierMilli <= 0 || t.MaxTotalForwards < 0 || t.PortRangeStart < 1024 ||
		t.PortRangeEnd > 65535 || t.PortRangeStart > t.PortRangeEnd || t.AllowCustomPublicTarget {
		return ErrForwardingInvalid
	}
	t.AllowManagedTarget = true
	seen := map[int64]bool{}
	for i := range t.Hops {
		if t.Hops[i].ServerID <= 0 || seen[t.Hops[i].ServerID] {
			return ErrForwardingInvalid
		}
		t.Hops[i].ConnectHost = strings.TrimSpace(t.Hops[i].ConnectHost)
		if t.Hops[i].ConnectHost != "" && net.ParseIP(t.Hops[i].ConnectHost) == nil {
			return ErrForwardingInvalid
		}
		seen[t.Hops[i].ServerID] = true
		t.Hops[i].Position = i
	}
	return nil
}

func validateTunnelServersTx(ctx context.Context, tx *sql.Tx, hops []TunnelTemplateHop) error {
	for _, hop := range hops {
		var status, host string
		var xrayRunning, locallyOwned int
		err := tx.QueryRowContext(ctx, `SELECT status, COALESCE(xray_running, 0),
       COALESCE(NULLIF(ip_address, ''), NULLIF(ip_address_v6, ''), ''),
       NOT EXISTS(SELECT 1 FROM federated_servers fs WHERE fs.server_id=remote_servers.id)
FROM remote_servers WHERE id = ?`, hop.ServerID).Scan(&status, &xrayRunning, &host, &locallyOwned)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrForwardingInvalid
		}
		if err != nil {
			return fmt.Errorf("validate tunnel server: %w", err)
		}
		if (status != "online" && status != "connected") || xrayRunning == 0 || locallyOwned == 0 || net.ParseIP(strings.TrimSpace(host)) == nil {
			return ErrForwardingInvalid
		}
	}
	return nil
}

func (r *TrafficRepository) CreateTunnelTemplate(ctx context.Context, t TunnelTemplate) (*TunnelTemplate, error) {
	if err := forwardingInitialized(r); err != nil {
		return nil, err
	}
	if err := normalizeTemplate(&t); err != nil {
		return nil, err
	}
	t.PublicID, t.CreatedBy = forwardingID("tun_"), strings.TrimSpace(t.CreatedBy)
	if t.CreatedBy == "" {
		return nil, ErrForwardingInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := validateTunnelServersTx(ctx, tx, t.Hops); err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO tunnel_templates(public_id,name,description,state,network,billing_mode,traffic_multiplier_milli,max_total_forwards,allow_managed_target,allow_custom_public_target,port_range_start,port_range_end,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.PublicID, t.Name, t.Description, t.State, t.Network, t.BillingMode, t.TrafficMultiplierMilli, t.MaxTotalForwards, 1, 0, t.PortRangeStart, t.PortRangeEnd, t.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("create tunnel template: %w", err)
	}
	t.ID, _ = res.LastInsertId()
	for _, hop := range t.Hops {
		if _, err := tx.ExecContext(ctx, `INSERT INTO tunnel_template_hops(tunnel_id,position,server_id,connect_host) VALUES(?,?,?,?)`, t.ID, hop.Position, hop.ServerID, strings.TrimSpace(hop.ConnectHost)); err != nil {
			return nil, fmt.Errorf("create tunnel hop: %w", err)
		}
	}
	if err := insertForwardAudit(ctx, tx, t.CreatedBy, "create", "tunnel_template", t.ID, "", ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetTunnelTemplate(ctx, t.PublicID)
}

const selectTunnelTemplate = `SELECT id,public_id,name,description,state,network,billing_mode,traffic_multiplier_milli,max_total_forwards,allow_managed_target,allow_custom_public_target,port_range_start,port_range_end,version,created_by,created_at,updated_at FROM tunnel_templates`

func scanTunnelTemplate(s rowScanner) (TunnelTemplate, error) {
	var t TunnelTemplate
	var managed, custom int
	err := s.Scan(&t.ID, &t.PublicID, &t.Name, &t.Description, &t.State, &t.Network, &t.BillingMode, &t.TrafficMultiplierMilli, &t.MaxTotalForwards, &managed, &custom, &t.PortRangeStart, &t.PortRangeEnd, &t.Version, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	t.AllowManagedTarget, t.AllowCustomPublicTarget = managed != 0, custom != 0
	return t, err
}

func (r *TrafficRepository) loadTunnelHops(ctx context.Context, t *TunnelTemplate) error {
	rows, err := r.db.QueryContext(ctx, `SELECT h.id,h.tunnel_id,h.position,h.server_id,COALESCE(rs.name,''),h.connect_host,h.created_at FROM tunnel_template_hops h LEFT JOIN remote_servers rs ON rs.id=h.server_id WHERE h.tunnel_id=? ORDER BY h.position`, t.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var h TunnelTemplateHop
		if err := rows.Scan(&h.ID, &h.TunnelID, &h.Position, &h.ServerID, &h.ServerName, &h.ConnectHost, &h.CreatedAt); err != nil {
			return err
		}
		t.Hops = append(t.Hops, h)
	}
	return rows.Err()
}

func (r *TrafficRepository) GetTunnelTemplate(ctx context.Context, publicID string) (*TunnelTemplate, error) {
	if err := forwardingInitialized(r); err != nil {
		return nil, err
	}
	t, err := scanTunnelTemplate(r.db.QueryRowContext(ctx, selectTunnelTemplate+` WHERE public_id=?`, strings.TrimSpace(publicID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTunnelTemplateNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := r.loadTunnelHops(ctx, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TrafficRepository) GetTunnelTemplateByID(ctx context.Context, id int64) (*TunnelTemplate, error) {
	t, err := scanTunnelTemplate(r.db.QueryRowContext(ctx, selectTunnelTemplate+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTunnelTemplateNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := r.loadTunnelHops(ctx, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TrafficRepository) ListTunnelTemplates(ctx context.Context) ([]TunnelTemplate, error) {
	rows, err := r.db.QueryContext(ctx, selectTunnelTemplate+` ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TunnelTemplate{}
	for rows.Next() {
		t, err := scanTunnelTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	for i := range out {
		if err := r.loadTunnelHops(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, rows.Err()
}

func (r *TrafficRepository) UpdateTunnelTemplate(ctx context.Context, publicID string, in TunnelTemplate, expectedVersion int64, actor string) (*TunnelTemplate, error) {
	if err := normalizeTemplate(&in); err != nil {
		return nil, err
	}
	current, err := r.GetTunnelTemplate(ctx, publicID)
	if err != nil {
		return nil, err
	}
	if len(current.Hops) != len(in.Hops) {
		var n int
		r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id IN(SELECT id FROM user_tunnel_grants WHERE tunnel_id=?) AND desired_state!='deleted'`, current.ID).Scan(&n)
		if n > 0 {
			return nil, ErrForwardingConflict
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := validateTunnelServersTx(ctx, tx, in.Hops); err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE tunnel_templates SET name=?,description=?,state=?,network=?,billing_mode=?,traffic_multiplier_milli=?,max_total_forwards=?,port_range_start=?,port_range_end=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND version=?`, in.Name, in.Description, in.State, in.Network, in.BillingMode, in.TrafficMultiplierMilli, in.MaxTotalForwards, in.PortRangeStart, in.PortRangeEnd, current.ID, expectedVersion)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return nil, ErrForwardingConflict
	}
	pathChanged := current.Network != in.Network || len(current.Hops) != len(in.Hops)
	if !pathChanged {
		for i := range in.Hops {
			if in.Hops[i].ServerID != current.Hops[i].ServerID {
				pathChanged = true
			}
		}
	}
	if pathChanged {
		var active int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id IN(SELECT id FROM user_tunnel_grants WHERE tunnel_id=?) AND desired_state!='deleted'`, current.ID).Scan(&active)
		if active > 0 {
			return nil, ErrForwardingConflict
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM tunnel_template_hops WHERE tunnel_id=?`, current.ID); err != nil {
			return nil, err
		}
		for i, h := range in.Hops {
			if _, err = tx.ExecContext(ctx, `INSERT INTO tunnel_template_hops(tunnel_id,position,server_id,connect_host) VALUES(?,?,?,?)`, current.ID, i, h.ServerID, strings.TrimSpace(h.ConnectHost)); err != nil {
				return nil, ErrForwardingInvalid
			}
		}
	}
	if err := insertForwardAudit(ctx, tx, actor, "update", "tunnel_template", current.ID, "", ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetTunnelTemplate(ctx, publicID)
}

func (r *TrafficRepository) DeleteTunnelTemplate(ctx context.Context, publicID, actor string) error {
	t, err := r.GetTunnelTemplate(ctx, publicID)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id IN(SELECT id FROM user_tunnel_grants WHERE tunnel_id=?) AND desired_state!='deleted'`, t.ID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrForwardingConflict
	}
	var packageRefs int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM packages
WHERE EXISTS(SELECT 1 FROM json_each(COALESCE(forwarding_grants, '[]')) entry
WHERE CAST(json_extract(entry.value, '$.tunnel_id') AS INTEGER)=?)`, t.ID).Scan(&packageRefs); err != nil {
		return err
	}
	if packageRefs > 0 {
		return ErrForwardingConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_tunnel_grants WHERE tunnel_id=?`, t.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM tunnel_template_hops WHERE tunnel_id=?`, t.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM tunnel_templates WHERE id=?`, t.ID); err != nil {
		return err
	}
	_ = insertForwardAudit(ctx, tx, actor, "delete", "tunnel_template", t.ID, "", "")
	return tx.Commit()
}

func (r *TrafficRepository) SetTunnelTemplateState(ctx context.Context, publicID, state string, expectedVersion int64, actor string) (*TunnelTemplate, error) {
	if state != TunnelStateActive && state != TunnelStateDraining && state != TunnelStateSuspended {
		return nil, ErrForwardingInvalid
	}
	template, err := r.GetTunnelTemplate(ctx, publicID)
	if err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE tunnel_templates SET state=?,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND version=?`, state, template.ID, expectedVersion)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrForwardingConflict
	}
	if err := insertForwardAudit(ctx, tx, actor, "state_"+state, "tunnel_template", template.ID, "", ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetTunnelTemplate(ctx, publicID)
}

func normalizeTunnelGrant(g *UserTunnelGrant) error {
	g.Username = strings.TrimSpace(g.Username)
	g.SourceType = strings.ToLower(strings.TrimSpace(g.SourceType))
	if g.SourceType == "" {
		g.SourceType = GrantSourceManual
	}
	if g.Username == "" || g.TunnelID <= 0 || g.MaxActiveForwards < 0 || g.PerForwardSpeedMbps < 0 || g.PerForwardConnectionLimit < 0 || g.TrafficLimitBytes < 0 || g.StartsAt.IsZero() || g.AllowCustomPublicTarget {
		return ErrForwardingInvalid
	}
	g.AllowManagedTarget = true
	if g.ExpiresAt != nil {
		v := g.ExpiresAt.UTC()
		g.ExpiresAt = &v
		if !g.ExpiresAt.After(g.StartsAt) {
			return ErrForwardingInvalid
		}
	}
	if g.BillingModeOverride != nil && *g.BillingModeOverride != ManagedBillingBoth && *g.BillingModeOverride != ManagedBillingDownload {
		return ErrForwardingInvalid
	}
	if g.SourceType != GrantSourceManual && g.SourceType != GrantSourcePackage {
		return ErrForwardingInvalid
	}
	if g.SourceType == GrantSourcePackage {
		if g.SourcePackageID == nil || *g.SourcePackageID <= 0 {
			return ErrForwardingInvalid
		}
	} else {
		if g.SourcePackageID != nil {
			return ErrForwardingInvalid
		}
	}
	return nil
}

const selectTunnelGrant = `SELECT id,public_id,username,tunnel_id,enabled,starts_at,expires_at,max_active_forwards,per_forward_speed_mbps,per_forward_connection_limit,traffic_limit_bytes,billing_mode_override,allow_managed_target,allow_custom_public_target,COALESCE(source_type,'manual'),source_package_id,version,created_by,created_at,updated_at FROM user_tunnel_grants`

func scanTunnelGrant(s rowScanner) (UserTunnelGrant, error) {
	var g UserTunnelGrant
	var enabled, managed, custom int
	var expires, billing sql.NullString
	var sourcePackageID sql.NullInt64
	err := s.Scan(&g.ID, &g.PublicID, &g.Username, &g.TunnelID, &enabled, &g.StartsAt, &expires, &g.MaxActiveForwards, &g.PerForwardSpeedMbps, &g.PerForwardConnectionLimit, &g.TrafficLimitBytes, &billing, &managed, &custom, &g.SourceType, &sourcePackageID, &g.Version, &g.CreatedBy, &g.CreatedAt, &g.UpdatedAt)
	g.Enabled = enabled != 0
	g.AllowManagedTarget = managed != 0
	g.AllowCustomPublicTarget = custom != 0
	g.ExpiresAt = managedParseNullTime(expires)
	if billing.Valid {
		g.BillingModeOverride = &billing.String
	}
	if sourcePackageID.Valid {
		id := sourcePackageID.Int64
		g.SourcePackageID = &id
	}
	return g, err
}

func (r *TrafficRepository) CreateUserTunnelGrant(ctx context.Context, g UserTunnelGrant) (*UserTunnelGrant, error) {
	if err := normalizeTunnelGrant(&g); err != nil {
		return nil, err
	}
	g.PublicID = forwardingID("grt_")
	g.CreatedBy = strings.TrimSpace(g.CreatedBy)
	if g.CreatedBy == "" {
		return nil, ErrForwardingInvalid
	}
	if _, err := r.GetTunnelTemplateByID(ctx, g.TunnelID); err != nil {
		return nil, err
	}
	var created *UserTunnelGrant
	err := r.WithUserProvisioningLease(ctx, g.Username, func() error {
		if g.SourceType == GrantSourceManual {
			var tombstoneID int64
			var tombstoneVersion int64
			tombstoneErr := r.db.QueryRowContext(ctx, `SELECT id,version FROM user_tunnel_grants
WHERE username=? AND tunnel_id=? AND source_type='package' AND enabled=0`, g.Username, g.TunnelID).Scan(&tombstoneID, &tombstoneVersion)
			if tombstoneErr != nil && !errors.Is(tombstoneErr, sql.ErrNoRows) {
				return tombstoneErr
			}
			if tombstoneErr == nil {
				res, updateErr := r.db.ExecContext(ctx, `UPDATE user_tunnel_grants SET public_id=?,enabled=?,starts_at=?,expires_at=?,
max_active_forwards=?,per_forward_speed_mbps=?,per_forward_connection_limit=?,traffic_limit_bytes=?,billing_mode_override=?,
allow_managed_target=1,allow_custom_public_target=0,source_type='manual',source_package_id=NULL,version=version+1,
created_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND version=? AND source_type='package' AND enabled=0`,
					g.PublicID, forwardingBoolInt(g.Enabled), g.StartsAt.UTC(), g.ExpiresAt, g.MaxActiveForwards,
					g.PerForwardSpeedMbps, g.PerForwardConnectionLimit, g.TrafficLimitBytes, g.BillingModeOverride,
					g.CreatedBy, tombstoneID, tombstoneVersion)
				if updateErr != nil {
					return updateErr
				}
				if affected, _ := res.RowsAffected(); affected != 1 {
					return ErrForwardingConflict
				}
				g.ID = tombstoneID
				if _, updateErr = r.db.ExecContext(ctx, `INSERT INTO tunnel_audit_events(actor,action,entity_type,entity_id,username) VALUES(?,?,?,?,?)`, g.CreatedBy, "grant.adopted_from_package", "tunnel_grant", g.ID, g.Username); updateErr != nil {
					return updateErr
				}
				created, updateErr = r.GetUserTunnelGrant(ctx, g.PublicID, g.Username)
				return updateErr
			}
		}
		res, err := r.db.ExecContext(ctx, `INSERT INTO user_tunnel_grants(public_id,username,tunnel_id,enabled,starts_at,expires_at,max_active_forwards,per_forward_speed_mbps,per_forward_connection_limit,traffic_limit_bytes,billing_mode_override,allow_managed_target,allow_custom_public_target,source_type,source_package_id,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, g.PublicID, g.Username, g.TunnelID, forwardingBoolInt(g.Enabled), g.StartsAt.UTC(), g.ExpiresAt, g.MaxActiveForwards, g.PerForwardSpeedMbps, g.PerForwardConnectionLimit, g.TrafficLimitBytes, g.BillingModeOverride, 1, 0, g.SourceType, g.SourcePackageID, g.CreatedBy)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrForwardingConflict
			}
			return err
		}
		g.ID, _ = res.LastInsertId()
		_, _ = r.db.ExecContext(ctx, `INSERT INTO tunnel_audit_events(actor,action,entity_type,entity_id,username) VALUES(?,?,?,?,?)`, g.CreatedBy, "create", "tunnel_grant", g.ID, g.Username)
		created, err = r.GetUserTunnelGrant(ctx, g.PublicID, g.Username)
		return err
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func forwardingBoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (r *TrafficRepository) GetUserTunnelGrant(ctx context.Context, publicID, username string) (*UserTunnelGrant, error) {
	q := selectTunnelGrant + ` WHERE public_id=?`
	args := []any{strings.TrimSpace(publicID)}
	if username != "" {
		q += ` AND username=?`
		args = append(args, strings.TrimSpace(username))
	}
	g, err := scanTunnelGrant(r.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTunnelGrantNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}
func (r *TrafficRepository) GetUserTunnelGrantByID(ctx context.Context, id int64) (*UserTunnelGrant, error) {
	g, err := scanTunnelGrant(r.db.QueryRowContext(ctx, selectTunnelGrant+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTunnelGrantNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (r *TrafficRepository) ListUserTunnelGrants(ctx context.Context, username string) ([]UserTunnelGrant, error) {
	username = strings.TrimSpace(username)
	q := selectTunnelGrant
	args := []any{}
	if username != "" {
		q += ` WHERE username=?`
		args = append(args, username)
	}
	q += ` ORDER BY id DESC`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserTunnelGrant{}
	for rows.Next() {
		g, err := scanTunnelGrant(rows)
		if err != nil {
			return nil, err
		}
		_ = r.db.QueryRowContext(ctx, `SELECT
COALESCE((SELECT billed_bytes FROM user_tunnel_grant_usage_archive WHERE grant_id=?),0)+
COALESCE((SELECT SUM((CASE WHEN f.billing_mode_snapshot='both' THEN u.uplink_bytes+u.downlink_bytes ELSE u.downlink_bytes END)*f.traffic_multiplier_milli_snapshot/1000) FROM user_forward_usage u JOIN user_forward_rules f ON f.id=u.forward_id WHERE f.grant_id=?),0)`, g.ID, g.ID).Scan(&g.UsedBytes)
		_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id=? AND desired_state='active'`, g.ID).Scan(&g.ActiveForwardCount)
		g.Tunnel, _ = r.GetTunnelTemplateByID(ctx, g.TunnelID)
		var active int
		_ = r.db.QueryRowContext(ctx, `SELECT is_active FROM users WHERE username=?`, g.Username).Scan(&active)
		state := TunnelStateSuspended
		if g.Tunnel != nil {
			state = g.Tunnel.State
		}
		g.State = g.StateAt(time.Now().UTC(), active != 0, state, g.UsedBytes)
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r *TrafficRepository) UpdateUserTunnelGrant(ctx context.Context, publicID, username string, in UserTunnelGrant, expectedVersion int64, actor string) (*UserTunnelGrant, error) {
	var updated *UserTunnelGrant
	err := r.WithUserProvisioningLease(ctx, username, func() error {
		current, err := r.GetUserTunnelGrant(ctx, publicID, username)
		if err != nil {
			return err
		}
		in.Username = current.Username
		in.TunnelID = current.TunnelID
		in.SourceType = current.SourceType
		in.SourcePackageID = current.SourcePackageID
		if err := normalizeTunnelGrant(&in); err != nil {
			return err
		}
		if in.MaxActiveForwards > 0 {
			var active int
			_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id=? AND desired_state='active'`, current.ID).Scan(&active)
			if active > in.MaxActiveForwards {
				return ErrForwardingConflict
			}
		}
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		res, err := tx.ExecContext(ctx, `UPDATE user_tunnel_grants SET enabled=?,starts_at=?,expires_at=?,max_active_forwards=?,per_forward_speed_mbps=?,per_forward_connection_limit=?,traffic_limit_bytes=?,billing_mode_override=?,allow_managed_target=1,allow_custom_public_target=0,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND version=?`, forwardingBoolInt(in.Enabled), in.StartsAt.UTC(), in.ExpiresAt, in.MaxActiveForwards, in.PerForwardSpeedMbps, in.PerForwardConnectionLimit, in.TrafficLimitBytes, in.BillingModeOverride, current.ID, expectedVersion)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return ErrForwardingConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_forward_rules SET effective_expires_at=?,generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE grant_id=? AND desired_state!='deleted'`, in.ExpiresAt, current.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_forward_hops SET generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE forward_id IN(SELECT id FROM user_forward_rules WHERE grant_id=? AND desired_state!='deleted')`, current.ID); err != nil {
			return err
		}
		if err := insertForwardAudit(ctx, tx, actor, "update", "tunnel_grant", current.ID, current.Username, ""); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		updated, err = r.GetUserTunnelGrant(ctx, publicID, username)
		return err
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (r *TrafficRepository) DeleteUserTunnelGrant(ctx context.Context, publicID, username, actor string) error {
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()

	g, err := r.GetUserTunnelGrant(ctx, publicID, username)
	if err != nil {
		return err
	}
	var n int
	_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id=? AND desired_state!='deleted'`, g.ID).Scan(&n)
	if n > 0 {
		return ErrForwardingConflict
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM user_tunnel_grants WHERE id=?`, g.ID)
	if err != nil {
		return err
	}
	a, _ := res.RowsAffected()
	if a != 1 {
		return ErrTunnelGrantNotFound
	}
	_, _ = r.db.ExecContext(ctx, `INSERT INTO tunnel_audit_events(actor,action,entity_type,entity_id,username) VALUES(?,?,?,?,?)`, actor, "delete", "tunnel_grant", g.ID, g.Username)
	return nil
}

type CreateUserForwardInput struct {
	Username, Name, GrantPublicID, TargetHost string
	TargetNodeID                              int64
	TargetPort                                int
	RequestedEntryPort                        int
	SourceCIDRs                               []string
	TunnelVersion                             int64
	EffectiveExpiresAt                        *time.Time
	Actor                                     string
}

func (r *TrafficRepository) CreateUserForward(ctx context.Context, in CreateUserForwardInput) (*UserForwardRule, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.Name = strings.TrimSpace(in.Name)
	in.TargetHost = strings.TrimSpace(in.TargetHost)
	if in.Username == "" || in.Name == "" || in.TargetNodeID <= 0 || in.TargetHost == "" || in.TargetPort < 1 || in.TargetPort > 65535 || in.RequestedEntryPort < 0 || in.RequestedEntryPort > 65535 {
		return nil, ErrForwardingInvalid
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	g, err := scanTunnelGrant(tx.QueryRowContext(ctx, selectTunnelGrant+` WHERE public_id=? AND username=?`, in.GrantPublicID, in.Username))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTunnelGrantNotFound
	}
	if err != nil {
		return nil, err
	}
	t, err := scanTunnelTemplate(tx.QueryRowContext(ctx, selectTunnelTemplate+` WHERE id=?`, g.TunnelID))
	if err != nil {
		return nil, ErrTunnelTemplateNotFound
	}
	if in.TunnelVersion > 0 && t.Version != in.TunnelVersion {
		return nil, ErrForwardingConflict
	}
	forwardNetwork := ForwardNetworkTCPUDP
	if in.RequestedEntryPort != 0 && (in.RequestedEntryPort < t.PortRangeStart || in.RequestedEntryPort > t.PortRangeEnd) {
		return nil, ErrForwardingInvalid
	}
	var userEnabled int
	if err := tx.QueryRowContext(ctx, `SELECT is_active FROM users WHERE username=?`, in.Username).Scan(&userEnabled); err != nil {
		return nil, ErrUserNotFound
	}
	var used int64
	_ = tx.QueryRowContext(ctx, `SELECT
COALESCE((SELECT billed_bytes FROM user_tunnel_grant_usage_archive WHERE grant_id=?),0)+
COALESCE((SELECT SUM((CASE WHEN f.billing_mode_snapshot='both' THEN u.uplink_bytes+u.downlink_bytes ELSE u.downlink_bytes END)*f.traffic_multiplier_milli_snapshot/1000) FROM user_forward_usage u JOIN user_forward_rules f ON f.id=u.forward_id WHERE f.grant_id=?),0)`, g.ID, g.ID).Scan(&used)
	if g.StateAt(time.Now().UTC(), userEnabled != 0, t.State, used) != "active" {
		return nil, ErrForwardingForbidden
	}
	var active int
	_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id=? AND desired_state='active'`, g.ID).Scan(&active)
	if g.MaxActiveForwards > 0 && active >= g.MaxActiveForwards {
		return nil, ErrForwardingLimit
	}
	if t.MaxTotalForwards > 0 {
		var total int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE grant_id IN(SELECT id FROM user_tunnel_grants WHERE tunnel_id=?) AND desired_state='active'`, t.ID).Scan(&total)
		if total >= t.MaxTotalForwards {
			return nil, ErrForwardingLimit
		}
	}
	var expectedHops int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tunnel_template_hops WHERE tunnel_id=?`, t.ID).Scan(&expectedHops); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT h.id,h.position,h.server_id,COALESCE(h.connect_host,''),COALESCE(rs.name,''),COALESCE(NULLIF(rs.ip_address,''),NULLIF(rs.ip_address_v6,''),''),rs.status,COALESCE(rs.xray_running,0),EXISTS(SELECT 1 FROM federated_servers fs WHERE fs.server_id=rs.id) FROM tunnel_template_hops h JOIN remote_servers rs ON rs.id=h.server_id WHERE h.tunnel_id=? ORDER BY h.position`, t.ID)
	if err != nil {
		return nil, err
	}
	type hopSeed struct {
		id                   int64
		pos                  int
		sid                  int64
		override, name, host string
		status               string
		xrayRunning          int
		federated            int
	}
	seeds := []hopSeed{}
	for rows.Next() {
		var s hopSeed
		if err := rows.Scan(&s.id, &s.pos, &s.sid, &s.override, &s.name, &s.host, &s.status, &s.xrayRunning, &s.federated); err != nil {
			rows.Close()
			return nil, err
		}
		if s.override != "" {
			s.host = s.override
		}
		if net.ParseIP(s.host) == nil || (s.status != "online" && s.status != "connected") || s.xrayRunning == 0 || s.federated != 0 {
			rows.Close()
			return nil, ErrForwardingInvalid
		}
		seeds = append(seeds, s)
	}
	rows.Close()
	if len(seeds) < 1 || len(seeds) > 8 || len(seeds) != expectedHops {
		return nil, ErrForwardingInvalid
	}
	billing := t.BillingMode
	if g.BillingModeOverride != nil {
		billing = *g.BillingModeOverride
	}
	publicID := forwardingID("fwd_")
	sourceCIDRs, err := json.Marshal(in.SourceCIDRs)
	if err != nil {
		return nil, ErrForwardingInvalid
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO user_forward_rules(public_id,grant_id,username,name,target_type,target_node_id,target_host,target_port,network,source_cidrs,requested_entry_port,effective_expires_at,billing_mode_snapshot,traffic_multiplier_milli_snapshot) VALUES(?,?,?,?, 'managed_node',?,?,?,?,?,?,?,?,?)`, publicID, g.ID, in.Username, in.Name, in.TargetNodeID, in.TargetHost, in.TargetPort, forwardNetwork, string(sourceCIDRs), in.RequestedEntryPort, in.EffectiveExpiresAt, billing, t.TrafficMultiplierMilli)
	if err != nil {
		return nil, err
	}
	forwardID, _ := res.LastInsertId()
	serverIDs := make([]int64, len(seeds))
	for i := range seeds {
		serverIDs[i] = seeds[i].sid
	}
	port, err := findCommonForwardPortTx(ctx, tx, serverIDs, forwardNetwork, t.PortRangeStart, t.PortRangeEnd, in.RequestedEntryPort, nil)
	if err != nil {
		return nil, err
	}
	hopIDs := make([]int64, len(seeds))
	resourceTags := make([]string, len(seeds))
	for i, s := range seeds {
		allocationIDs, err := reserveForwardPortTx(ctx, tx, s.sid, forwardNetwork, port)
		if err != nil {
			return nil, err
		}
		resourceID := fmt.Sprintf("rd_%s_h%d", strings.TrimPrefix(publicID, "fwd_"), i)
		resourceTags[i] = tunnelidentity.Tag(resourceID)
		hopIDRes, err := tx.ExecContext(ctx, `INSERT INTO user_forward_hops(forward_id,template_hop_id,position,server_id,resource_id,resource_tag,listen_port,next_host,next_port) VALUES(?,?,?,?,?,?,?,?,?)`, forwardID, s.id, s.pos, s.sid, resourceID, resourceTags[i], port, "", 0)
		if err != nil {
			return nil, err
		}
		hopIDs[i], _ = hopIDRes.LastInsertId()
		for _, allocationID := range allocationIDs {
			if _, err = tx.ExecContext(ctx, `UPDATE server_port_allocations SET owner_id=? WHERE id=?`, hopIDs[i], allocationID); err != nil {
				return nil, err
			}
		}
	}
	for i := range seeds {
		nextHost, nextPort := in.TargetHost, in.TargetPort
		if i < len(seeds)-1 {
			nextHost, nextPort = seeds[i+1].host, port
		}
		if _, err = tx.ExecContext(ctx, `UPDATE user_forward_hops SET next_host=?,next_port=? WHERE id=?`, nextHost, nextPort, hopIDs[i]); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE user_forward_rules SET allocated_entry_port=? WHERE id=?`, port, forwardID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_forward_usage(forward_id,cycle_started_at) VALUES(?,?)`, forwardID, time.Now().UTC()); err != nil {
		return nil, err
	}
	// Seed the collector baseline before Guard enables the entry inbound. The
	// generic collector intentionally treats an unseen tag's first sample as a
	// baseline, which would otherwise discard the tunnel's initial traffic.
	if _, err = tx.ExecContext(ctx, `INSERT INTO node_traffic(server_id,tag,type,uplink,downlink,total_uplink,total_downlink,last_uplink,last_downlink)
VALUES(?,?,'inbound',0,0,0,0,0,0)
ON CONFLICT(server_id,tag,type) DO NOTHING`, seeds[0].sid, resourceTags[0]); err != nil {
		return nil, err
	}
	if err := insertForwardAudit(ctx, tx, in.Actor, "create", "user_forward", forwardID, in.Username, ""); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetUserForward(ctx, publicID, in.Username)
}

func forwardReservationNetworks(network string) ([]string, []string, error) {
	switch network {
	case ForwardNetworkTCP:
		return []string{ForwardNetworkTCP}, []string{ForwardNetworkTCP, ForwardNetworkTCPUDP}, nil
	case ForwardNetworkTCPUDP:
		return []string{ForwardNetworkTCP, ForwardNetworkUDP}, []string{ForwardNetworkTCP, ForwardNetworkUDP, ForwardNetworkTCPUDP}, nil
	default:
		return nil, nil, ErrForwardingInvalid
	}
}

func findCommonForwardPortTx(ctx context.Context, tx *sql.Tx, serverIDs []int64, network string, start, end, requested int, excluded map[int]bool) (int, error) {
	span := end - start + 1
	if len(serverIDs) == 0 || start < 1024 || end > 65535 || span <= 0 || requested < 0 || requested > 65535 {
		return 0, ErrForwardingInvalid
	}
	_, conflictNetworks, err := forwardReservationNetworks(network)
	if err != nil {
		return 0, err
	}
	serverPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(serverIDs)), ",")
	networkPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(conflictNetworks)), ",")
	args := make([]any, 0, len(serverIDs)+len(conflictNetworks)+2)
	for _, serverID := range serverIDs {
		args = append(args, serverID)
	}
	for _, value := range conflictNetworks {
		args = append(args, value)
	}
	args = append(args, start, end)
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT port FROM server_port_allocations WHERE server_id IN (`+serverPlaceholders+`) AND network IN (`+networkPlaceholders+`) AND port BETWEEN ? AND ?`, args...)
	if err != nil {
		return 0, err
	}
	used := make(map[int]bool)
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			rows.Close()
			return 0, err
		}
		used[port] = true
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if requested != 0 {
		if requested < start || requested > end {
			return 0, ErrForwardingInvalid
		}
		if used[requested] || excluded[requested] {
			return 0, ErrForwardingConflict
		}
		return requested, nil
	}
	seedBytes := make([]byte, 2)
	_, _ = rand.Read(seedBytes)
	seed := 0
	if len(seedBytes) == 2 {
		seed = int(seedBytes[0])<<8 | int(seedBytes[1])
	}
	for i := 0; i < span; i++ {
		port := start + (seed+i)%span
		if excluded[port] || used[port] {
			continue
		}
		return port, nil
	}
	return 0, ErrForwardingLimit
}

func reserveForwardPortTx(ctx context.Context, tx *sql.Tx, serverID int64, network string, port int) ([]int64, error) {
	reservationNetworks, _, err := forwardReservationNetworks(network)
	if err != nil {
		return nil, err
	}
	allocationIDs := make([]int64, 0, len(reservationNetworks))
	for _, value := range reservationNetworks {
		res, err := tx.ExecContext(ctx, `INSERT INTO server_port_allocations(server_id,network,port,owner_type,owner_id) VALUES(?,?,?,'forward_hop',0)`, serverID, value, port)
		if err != nil {
			if strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
				return nil, ErrForwardingConflict
			}
			return nil, err
		}
		id, _ := res.LastInsertId()
		allocationIDs = append(allocationIDs, id)
	}
	return allocationIDs, nil
}

// ReallocateUserForwardPorts replaces every per-hop identity and port in one
// transaction. It is only used after Guard reports port_in_use/port_reserved;
// replacing the resource ID avoids mutating an immutable Guard definition.
func (r *TrafficRepository) ReallocateUserForwardPorts(ctx context.Context, publicID, username string) (*UserForwardRule, error) {
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	identityWhere := `public_id=?`
	identityArgs := []any{strings.TrimSpace(publicID)}
	if strings.TrimSpace(username) != "" {
		identityWhere += ` AND username=?`
		identityArgs = append(identityArgs, strings.TrimSpace(username))
	}
	checkArgs := append([]any(nil), identityArgs...)
	res, err := tx.ExecContext(ctx, `UPDATE user_forward_rules SET updated_at=updated_at WHERE `+identityWhere+` AND desired_state='active' AND requested_entry_port=0`, checkArgs...)
	if err != nil {
		return nil, err
	}
	matched, _ := res.RowsAffected()
	if matched != 1 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_forward_rules WHERE `+identityWhere, identityArgs...).Scan(&exists); err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrUserForwardNotFound
		}
		return nil, ErrForwardingConflict
	}
	forward, err := scanUserForward(tx.QueryRowContext(ctx, selectUserForward+` WHERE `+identityWhere, identityArgs...))
	if err != nil {
		return nil, err
	}
	if err := loadForwardHopsFrom(ctx, tx, &forward); err != nil {
		return nil, err
	}
	if len(forward.Hops) == 0 {
		return nil, ErrForwardingConflict
	}
	var portStart, portEnd int
	if err := tx.QueryRowContext(ctx, `SELECT t.port_range_start,t.port_range_end
FROM user_forward_rules f
JOIN user_tunnel_grants g ON g.id=f.grant_id
JOIN tunnel_templates t ON t.id=g.tunnel_id
	WHERE f.id=?`, forward.ID).Scan(&portStart, &portEnd); err != nil {
		return nil, err
	}
	for _, hop := range forward.Hops {
		if _, err := tx.ExecContext(ctx, `DELETE FROM server_port_allocations WHERE owner_type='forward_hop' AND owner_id=?`, hop.ID); err != nil {
			return nil, err
		}
	}
	serverIDs := make([]int64, len(forward.Hops))
	excluded := make(map[int]bool, len(forward.Hops))
	for i, hop := range forward.Hops {
		serverIDs[i] = hop.ServerID
		excluded[hop.ListenPort] = true
	}
	port, err := findCommonForwardPortTx(ctx, tx, serverIDs, ForwardNetworkTCPUDP, portStart, portEnd, 0, excluded)
	if err != nil {
		return nil, err
	}
	resourceTags := make([]string, len(forward.Hops))
	for i, hop := range forward.Hops {
		allocationIDs, err := reserveForwardPortTx(ctx, tx, hop.ServerID, ForwardNetworkTCPUDP, port)
		if err != nil {
			return nil, err
		}
		resourceID := forwardingID("rhop_")
		resourceTags[i] = tunnelidentity.Tag(resourceID)
		if _, err := tx.ExecContext(ctx, `UPDATE user_forward_hops SET resource_id=?,resource_tag=?,listen_port=?,generation=generation+1,applied_generation=0,observed_state='pending',last_error='',updated_at=CURRENT_TIMESTAMP WHERE id=?`, resourceID, resourceTags[i], port, hop.ID); err != nil {
			return nil, err
		}
		for _, allocationID := range allocationIDs {
			if _, err := tx.ExecContext(ctx, `UPDATE server_port_allocations SET owner_id=? WHERE id=?`, hop.ID, allocationID); err != nil {
				return nil, err
			}
		}
	}
	for i := 0; i < len(forward.Hops)-1; i++ {
		if _, err := tx.ExecContext(ctx, `UPDATE user_forward_hops SET next_port=? WHERE id=?`, port, forward.Hops[i].ID); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_rules SET network=?,allocated_entry_port=?,observed_state='pending',generation=generation+1,applied_generation=0,last_error_code='',last_error_detail='',updated_at=CURRENT_TIMESTAMP WHERE id=?`, ForwardNetworkTCPUDP, port, forward.ID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_usage SET last_raw_uplink=0,last_raw_downlink=0,updated_at=CURRENT_TIMESTAMP WHERE forward_id=?`, forward.ID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO node_traffic(server_id,tag,type,uplink,downlink,total_uplink,total_downlink,last_uplink,last_downlink)
VALUES(?,?,'inbound',0,0,0,0,0,0)
ON CONFLICT(server_id,tag,type) DO NOTHING`, forward.Hops[0].ServerID, resourceTags[0]); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetUserForward(ctx, publicID, username)
}

const selectUserForward = `SELECT id,public_id,grant_id,username,name,target_type,target_node_id,target_host,target_port,network,source_cidrs,requested_entry_port,allocated_entry_port,desired_state,observed_state,suspend_reason,generation,applied_generation,effective_expires_at,billing_mode_snapshot,traffic_multiplier_milli_snapshot,last_error_code,last_error_detail,created_at,updated_at FROM user_forward_rules`

func scanUserForward(s rowScanner) (UserForwardRule, error) {
	var f UserForwardRule
	var expiry sql.NullString
	var sourceCIDRs string
	err := s.Scan(&f.ID, &f.PublicID, &f.GrantID, &f.Username, &f.Name, &f.TargetType, &f.TargetNodeID, &f.TargetHost, &f.TargetPort, &f.Network, &sourceCIDRs, &f.RequestedEntryPort, &f.AllocatedEntryPort, &f.DesiredState, &f.ObservedState, &f.SuspendReason, &f.Generation, &f.AppliedGeneration, &expiry, &f.BillingModeSnapshot, &f.TrafficMultiplierMilliSnapshot, &f.LastErrorCode, &f.LastErrorDetail, &f.CreatedAt, &f.UpdatedAt)
	f.EffectiveExpiresAt = managedParseNullTime(expiry)
	_ = json.Unmarshal([]byte(sourceCIDRs), &f.SourceCIDRs)
	return f, err
}

type forwardingRowsQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadForwardHopsFrom(ctx context.Context, queryer forwardingRowsQueryer, f *UserForwardRule) error {
	rows, err := queryer.QueryContext(ctx, `SELECT h.id,h.forward_id,h.template_hop_id,h.position,h.server_id,COALESCE(rs.name,''),h.resource_id,h.resource_tag,h.listen_port,h.next_host,h.next_port,h.desired_state,h.observed_state,h.generation,h.applied_generation,h.retry_count,h.last_error,h.updated_at FROM user_forward_hops h LEFT JOIN remote_servers rs ON rs.id=h.server_id WHERE h.forward_id=? ORDER BY h.position`, f.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var h UserForwardHop
		if err := rows.Scan(&h.ID, &h.ForwardID, &h.TemplateHopID, &h.Position, &h.ServerID, &h.ServerName, &h.ResourceID, &h.ResourceTag, &h.ListenPort, &h.NextHost, &h.NextPort, &h.DesiredState, &h.ObservedState, &h.Generation, &h.AppliedGeneration, &h.RetryCount, &h.LastError, &h.UpdatedAt); err != nil {
			return err
		}
		f.Hops = append(f.Hops, h)
	}
	return rows.Err()
}

func (r *TrafficRepository) loadForwardHops(ctx context.Context, f *UserForwardRule) error {
	return loadForwardHopsFrom(ctx, r.db, f)
}
func (r *TrafficRepository) GetUserForward(ctx context.Context, publicID, username string) (*UserForwardRule, error) {
	q := selectUserForward + ` WHERE public_id=?`
	args := []any{strings.TrimSpace(publicID)}
	if username != "" {
		q += ` AND username=?`
		args = append(args, strings.TrimSpace(username))
	}
	f, err := scanUserForward(r.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserForwardNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := r.loadForwardHops(ctx, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
func (r *TrafficRepository) ListUserForwards(ctx context.Context, username string) ([]UserForwardRule, error) {
	q := selectUserForward + ` WHERE desired_state!='deleted'`
	args := []any{}
	if strings.TrimSpace(username) != "" {
		q += ` AND username=?`
		args = append(args, strings.TrimSpace(username))
	}
	q += ` ORDER BY id DESC`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserForwardRule{}
	for rows.Next() {
		f, err := scanUserForward(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	for i := range out {
		if err := r.loadForwardHops(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, rows.Err()
}

func (r *TrafficRepository) ListForwardReconcileCandidates(ctx context.Context) ([]UserForwardRule, error) {
	rows, err := r.db.QueryContext(ctx, selectUserForward+` WHERE desired_state!='deleted' OR observed_state='cleanup_pending' ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserForwardRule{}
	for rows.Next() {
		forward, err := scanUserForward(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, forward)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := r.loadForwardHops(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SyncUserForwardUsage snapshots the entry-hop node_traffic counters into the
// forwarding ledger. Only position 0 is billed, so a multi-hop route is never
// charged once per server.
func (r *TrafficRepository) SyncUserForwardUsage(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `SELECT f.id, COALESCE(nt.uplink,0), COALESCE(nt.downlink,0)
FROM user_forward_rules f
JOIN user_forward_hops h ON h.forward_id=f.id AND h.position=0
LEFT JOIN node_traffic nt ON nt.server_id=h.server_id AND nt.tag=h.resource_tag AND nt.type='inbound'
`)
	if err != nil {
		return err
	}
	type sample struct{ id, up, down int64 }
	samples := []sample{}
	for rows.Next() {
		var value sample
		if err := rows.Scan(&value.id, &value.up, &value.down); err != nil {
			rows.Close()
			return err
		}
		samples = append(samples, value)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, value := range samples {
		var lastUp, lastDown int64
		if err := tx.QueryRowContext(ctx, `SELECT last_raw_uplink,last_raw_downlink FROM user_forward_usage WHERE forward_id=?`, value.id).Scan(&lastUp, &lastDown); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				if _, err := tx.ExecContext(ctx, `INSERT INTO user_forward_usage(forward_id,cycle_started_at,last_raw_uplink,last_raw_downlink) VALUES(?,?,?,?)`, value.id, time.Now().UTC(), value.up, value.down); err != nil {
					return err
				}
				continue
			}
			return err
		}
		deltaUp, deltaDown := value.up-lastUp, value.down-lastDown
		if deltaUp < 0 {
			deltaUp = value.up
		}
		if deltaDown < 0 {
			deltaDown = value.down
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_forward_usage SET uplink_bytes=uplink_bytes+?,downlink_bytes=downlink_bytes+?,last_raw_uplink=?,last_raw_downlink=?,updated_at=CURRENT_TIMESTAMP WHERE forward_id=?`, deltaUp, deltaDown, value.up, value.down, value.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *TrafficRepository) GetUserForwardUsage(ctx context.Context, forwardID int64) (*ForwardUsage, error) {
	var usage ForwardUsage
	err := r.db.QueryRowContext(ctx, `SELECT forward_id,cycle_started_at,uplink_bytes,downlink_bytes,updated_at FROM user_forward_usage WHERE forward_id=?`, forwardID).Scan(&usage.ForwardID, &usage.CycleStartedAt, &usage.UplinkBytes, &usage.DownlinkBytes, &usage.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserForwardNotFound
	}
	if err != nil {
		return nil, err
	}
	return &usage, nil
}
func (r *TrafficRepository) MarkUserForwardDeployment(ctx context.Context, id int64, observed string, applied bool, code, detail string) error {
	appliedSQL := "applied_generation"
	if applied {
		appliedSQL = "generation"
	}
	_, err := r.db.ExecContext(ctx, `UPDATE user_forward_rules SET observed_state=?,applied_generation=`+appliedSQL+`,last_error_code=?,last_error_detail=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, observed, code, detail, id)
	return err
}

func (r *TrafficRepository) MarkUserForwardSystemState(ctx context.Context, id int64, observed, reason, code, detail string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE user_forward_rules
SET observed_state=?, suspend_reason=?, last_error_code=?, last_error_detail=?, updated_at=CURRENT_TIMESTAMP
WHERE id=? AND desired_state='active'`, observed, reason, code, detail, id)
	return err
}

func (r *TrafficRepository) PrepareUserForwardSystemSuspend(ctx context.Context, publicID, username, reason string) (*UserForwardRule, error) {
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	forward, err := r.GetUserForward(ctx, publicID, username)
	if err != nil {
		return nil, err
	}
	if forward.DesiredState != ForwardDesiredActive {
		return nil, ErrForwardingConflict
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_rules SET observed_state='provisioning',suspend_reason=?,generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND desired_state='active'`, reason, forward.ID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_hops SET generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE forward_id=?`, forward.ID); err != nil {
		return nil, err
	}
	if err := insertForwardAudit(ctx, tx, "system", "system_suspend", "user_forward", forward.ID, forward.Username, reason); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetUserForward(ctx, publicID, username)
}

func (r *TrafficRepository) PrepareUserForwardSystemApply(ctx context.Context, publicID, username string) (*UserForwardRule, error) {
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	forward, err := r.GetUserForward(ctx, publicID, username)
	if err != nil {
		return nil, err
	}
	if forward.DesiredState != ForwardDesiredActive {
		return nil, ErrForwardingConflict
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_rules SET observed_state='provisioning',suspend_reason='none',generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND desired_state='active'`, forward.ID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_forward_hops SET desired_state='active',generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE forward_id=?`, forward.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetUserForward(ctx, publicID, username)
}
func (r *TrafficRepository) MarkUserForwardHop(ctx context.Context, id int64, observed string, applied bool, lastError string) error {
	appliedSQL := "applied_generation"
	if applied {
		appliedSQL = "generation"
	}
	_, err := r.db.ExecContext(ctx, `UPDATE user_forward_hops SET observed_state=?,applied_generation=`+appliedSQL+`,last_error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, observed, lastError, id)
	return err
}
func (r *TrafficRepository) SetUserForwardDesired(ctx context.Context, publicID, username, desired, observed, reason, actor string) (*UserForwardRule, error) {
	if desired != ForwardDesiredActive && desired != ForwardDesiredInactive && desired != ForwardDesiredDeleted {
		return nil, ErrForwardingInvalid
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	f, err := r.GetUserForward(ctx, publicID, username)
	if err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE user_forward_rules SET desired_state=?,observed_state=?,suspend_reason=?,generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE id=?`, desired, observed, reason, f.ID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE user_forward_hops SET desired_state=?,generation=generation+1,updated_at=CURRENT_TIMESTAMP WHERE forward_id=?`, desired, f.ID); err != nil {
		return nil, err
	}
	_ = insertForwardAudit(ctx, tx, actor, desired, "user_forward", f.ID, f.Username, "")
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r.GetUserForward(ctx, publicID, username)
}
func (r *TrafficRepository) FinalizeUserForwardDelete(ctx context.Context, id int64) error {
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_tunnel_grant_usage_archive(grant_id,billed_bytes,updated_at)
SELECT f.grant_id,
       (CASE WHEN f.billing_mode_snapshot='both' THEN u.uplink_bytes+u.downlink_bytes ELSE u.downlink_bytes END)*f.traffic_multiplier_milli_snapshot/1000,
       CURRENT_TIMESTAMP
FROM user_forward_rules f JOIN user_forward_usage u ON u.forward_id=f.id
WHERE f.id=?
ON CONFLICT(grant_id) DO UPDATE SET
 billed_bytes=user_tunnel_grant_usage_archive.billed_bytes+excluded.billed_bytes,
 updated_at=CURRENT_TIMESTAMP`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM server_port_allocations WHERE owner_type='forward_hop' AND owner_id IN(SELECT id FROM user_forward_hops WHERE forward_id=?)`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_forward_hops WHERE forward_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_forward_usage WHERE forward_id=?`, id); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE user_forward_rules SET observed_state='suspended',updated_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func insertForwardAudit(ctx context.Context, tx *sql.Tx, actor, action, entityType string, entityID int64, username, details string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO tunnel_audit_events(actor,action,entity_type,entity_id,username,details) VALUES(?,?,?,?,?,?)`, actor, action, entityType, entityID, username, details)
	return err
}

func (r *TrafficRepository) ListForwardAudit(ctx context.Context, username, entityType string, entityID int64, limit int) ([]ForwardAuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id,actor,action,entity_type,entity_id,username,details,created_at FROM tunnel_audit_events WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(username) != "" {
		query += ` AND username=?`
		args = append(args, strings.TrimSpace(username))
	}
	if strings.TrimSpace(entityType) != "" {
		query += ` AND entity_type=?`
		args = append(args, strings.TrimSpace(entityType))
	}
	if entityID > 0 {
		query += ` AND entity_id=?`
		args = append(args, entityID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ForwardAuditEvent{}
	for rows.Next() {
		var item ForwardAuditEvent
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.EntityType, &item.EntityID, &item.Username, &item.Details, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
