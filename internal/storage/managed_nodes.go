package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ManagedBillingDownload = "download"
	ManagedBillingBoth     = "both"

	ManagedResetNone    = "none"
	ManagedResetMonthly = "monthly"

	ManagedSourcePackage      = "package"
	ManagedSourceSelection    = "selection"
	ManagedSourceLegacyReview = "legacy_review"
	GrantSourceManual         = "manual"
	GrantSourcePackage        = "package"

	ManagedDesiredActive   = "active"
	ManagedDesiredInactive = "inactive"
	ManagedDesiredDeleted  = "deleted"

	ManagedObservedUnknown  = "unknown"
	ManagedObservedActive   = "active"
	ManagedObservedInactive = "inactive"

	ManagedSuspendNone          = "none"
	ManagedSuspendExpired       = "expired"
	ManagedSuspendQuotaExceeded = "quota_exceeded"
	ManagedSuspendAdminDisabled = "admin_disabled"
	ManagedSuspendUserDisabled  = "user_disabled"

	ManagedGrantScheduled    = "scheduled"
	ManagedGrantActive       = "active"
	ManagedGrantSuspended    = "suspended"
	ManagedGrantExpired      = "expired"
	ManagedGrantOverLimit    = "over_limit"
	ManagedGrantUserDisabled = "user_disabled"

	ManagedShadowsocksMultiUserMarker = "x-arcway-managed-users"
)

var (
	ErrSelfServiceNodeOfferNotFound = errors.New("self-service node offer not found")
	ErrSelfServiceNodeOfferExists   = errors.New("self-service node offer already exists")
	ErrUserServerGrantNotFound      = errors.New("user server grant not found")
	ErrUserServerGrantExists        = errors.New("user server grant already exists")
	ErrUserNodeSelectionNotFound    = errors.New("user node selection not found")
	ErrManagedAccessSourceNotFound  = errors.New("managed access source not found")
	ErrManagedVersionConflict       = errors.New("managed resource version conflict")
	ErrManagedGenerationConflict    = errors.New("managed access source generation conflict")
	ErrManagedServerMismatch        = errors.New("managed node server mismatch")
	ErrManagedActiveNodeLimit       = errors.New("managed active node limit reached")
	ErrManagedTrafficLimit          = errors.New("managed traffic limit reached")
	ErrManagedGrantInactive         = errors.New("managed server grant is not active")
	ErrManagedProtocolNotAllowed    = errors.New("managed node protocol is not allowed by server grant")
	ErrManagedAccessConflict        = errors.New("package and managed node access overlap")
	ErrManagedBillingModeConflict   = errors.New("billing mode cannot change after usage is recorded")
	ErrManagedResourceInUse         = errors.New("managed resource is in use")
	ErrManagedInvalidArgument       = errors.New("invalid managed node argument")
)

type SelfServiceNodeOffer struct {
	ID         int64     `json:"id"`
	NodeID     int64     `json:"node_id"`
	ServerID   int64     `json:"server_id"`
	InboundTag string    `json:"inbound_tag"`
	Enabled    bool      `json:"enabled"`
	SortOrder  int       `json:"sort_order"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type UserServerGrant struct {
	ID                      int64      `json:"id"`
	Username                string     `json:"username"`
	ServerID                int64      `json:"server_id"`
	Enabled                 bool       `json:"enabled"`
	StartsAt                time.Time  `json:"starts_at"`
	ExpiresAt               *time.Time `json:"expires_at,omitempty"`
	MaxActiveNodes          int        `json:"max_active_nodes"`
	SpeedLimitMbps          float64    `json:"speed_limit_mbps"`
	ConnectionLimit         int        `json:"connection_limit"`
	TrafficLimitBytes       int64      `json:"traffic_limit_bytes"`
	BillingMode             string     `json:"billing_mode"`
	ResetPolicy             string     `json:"reset_policy"`
	ResetDay                int        `json:"reset_day"`
	BillingTimezone         string     `json:"billing_timezone"`
	NextResetAt             *time.Time `json:"next_reset_at,omitempty"`
	AllowedProtocols        []string   `json:"allowed_protocols"`
	AllowedProtocolProfiles []string   `json:"allowed_protocol_profiles"`
	SourceType              string     `json:"source_type"`
	SourcePackageID         *int64     `json:"source_package_id,omitempty"`
	Version                 int64      `json:"version"`
	CreatedBy               string     `json:"created_by"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

type UserNodeSelection struct {
	ID                      int64      `json:"id"`
	GrantID                 int64      `json:"grant_id"`
	OfferID                 int64      `json:"offer_id"`
	CredentialConfigID      *int64     `json:"credential_config_id,omitempty"`
	AccessSourceID          *int64     `json:"access_source_id,omitempty"`
	DesiredEnabled          bool       `json:"desired_enabled"`
	SpeedLimitOverrideMbps  *float64   `json:"speed_limit_override_mbps,omitempty"`
	ConnectionLimitOverride *int       `json:"connection_limit_override,omitempty"`
	BillingModeOverride     *string    `json:"billing_mode_override,omitempty"`
	ActivatedAt             *time.Time `json:"activated_at,omitempty"`
	DeactivatedAt           *time.Time `json:"deactivated_at,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

type UserInboundAccessSource struct {
	ID                int64      `json:"id"`
	Username          string     `json:"username"`
	ServerID          int64      `json:"server_id"`
	InboundTag        string     `json:"inbound_tag"`
	NodeID            int64      `json:"node_id"`
	SourceType        string     `json:"source_type"`
	SourceID          int64      `json:"source_id"`
	DesiredState      string     `json:"desired_state"`
	ObservedState     string     `json:"observed_state"`
	SuspendReason     string     `json:"suspend_reason"`
	Generation        int64      `json:"generation"`
	AppliedGeneration int64      `json:"applied_generation"`
	RetryCount        int        `json:"retry_count"`
	NextRetryAt       *time.Time `json:"next_retry_at,omitempty"`
	LastError         string     `json:"last_error"`
	StartsAt          time.Time  `json:"starts_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type UserNodeSelectionUsage struct {
	SelectionID     int64      `json:"selection_id"`
	GrantID         int64      `json:"grant_id"`
	CycleStartedAt  time.Time  `json:"cycle_started_at"`
	UplinkBytes     int64      `json:"uplink_bytes"`
	DownlinkBytes   int64      `json:"downlink_bytes"`
	LastRawUplink   int64      `json:"last_raw_uplink"`
	LastRawDownlink int64      `json:"last_raw_downlink"`
	CounterEpoch    string     `json:"counter_epoch"`
	LastResetAt     *time.Time `json:"last_reset_at,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (u UserNodeSelectionUsage) BilledBytes(mode string) int64 {
	if mode == ManagedBillingBoth {
		return u.UplinkBytes + u.DownlinkBytes
	}
	return u.DownlinkBytes
}

type ManagedAccessAudit struct {
	ID         int64          `json:"id"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	EntityType string         `json:"entity_type"`
	EntityID   int64          `json:"entity_id"`
	Username   string         `json:"username"`
	ServerID   int64          `json:"server_id"`
	Details    map[string]any `json:"details,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

type ManagedNodeCatalogEntry struct {
	Offer           SelfServiceNodeOffer     `json:"offer"`
	Grant           UserServerGrant          `json:"grant"`
	Selection       *UserNodeSelection       `json:"selection,omitempty"`
	AccessSource    *UserInboundAccessSource `json:"access_source,omitempty"`
	NodeName        string                   `json:"node_name"`
	Protocol        string                   `json:"protocol"`
	ProtocolProfile string                   `json:"protocol_profile"`
	ServerName      string                   `json:"server_name"`
	ServerStatus    string                   `json:"server_status"`
	GrantStatus     string                   `json:"grant_status"`
	UsageBytes      int64                    `json:"usage_bytes"`
	CanCreate       bool                     `json:"can_create"`
	DenyReason      string                   `json:"deny_reason,omitempty"`
}

type SelectionActivationResult struct {
	Selection UserNodeSelection       `json:"selection"`
	Source    UserInboundAccessSource `json:"source"`
	Created   bool                    `json:"created"`
}

func (r *TrafficRepository) migrateManagedNodes() error {
	const schema = `
CREATE TABLE IF NOT EXISTS self_service_node_offers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL UNIQUE,
    server_id INTEGER NOT NULL,
    inbound_tag TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, inbound_tag)
);
CREATE INDEX IF NOT EXISTS idx_self_service_node_offers_server ON self_service_node_offers(server_id, enabled, sort_order);

CREATE TABLE IF NOT EXISTS user_server_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    starts_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    max_active_nodes INTEGER NOT NULL DEFAULT 0 CHECK(max_active_nodes >= 0),
    speed_limit_mbps REAL NOT NULL DEFAULT 0 CHECK(speed_limit_mbps >= 0),
    connection_limit INTEGER NOT NULL DEFAULT 0 CHECK(connection_limit >= 0),
    traffic_limit_bytes INTEGER NOT NULL DEFAULT 0 CHECK(traffic_limit_bytes >= 0),
    billing_mode TEXT NOT NULL DEFAULT 'download' CHECK(billing_mode IN ('download', 'both')),
    reset_policy TEXT NOT NULL DEFAULT 'none' CHECK(reset_policy IN ('none', 'monthly')),
    reset_day INTEGER NOT NULL DEFAULT 1 CHECK(reset_day BETWEEN 1 AND 28),
    billing_timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
    next_reset_at TIMESTAMP,
    allowed_protocols_json TEXT NOT NULL DEFAULT '[]',
    allowed_protocol_profiles_json TEXT NOT NULL DEFAULT '[]',
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    created_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, server_id)
);
CREATE INDEX IF NOT EXISTS idx_user_server_grants_user ON user_server_grants(username, enabled);
CREATE INDEX IF NOT EXISTS idx_user_server_grants_server ON user_server_grants(server_id, enabled);
CREATE INDEX IF NOT EXISTS idx_user_server_grants_expiry ON user_server_grants(expires_at);

CREATE TABLE IF NOT EXISTS user_node_selections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id INTEGER NOT NULL,
    offer_id INTEGER NOT NULL,
    credential_config_id INTEGER,
    access_source_id INTEGER,
    desired_enabled INTEGER NOT NULL DEFAULT 1 CHECK(desired_enabled IN (0, 1)),
    speed_limit_override_mbps REAL CHECK(speed_limit_override_mbps IS NULL OR speed_limit_override_mbps >= 0),
    connection_limit_override INTEGER CHECK(connection_limit_override IS NULL OR connection_limit_override >= 0),
    billing_mode_override TEXT CHECK(billing_mode_override IS NULL OR billing_mode_override IN ('download', 'both')),
    activated_at TIMESTAMP,
    deactivated_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(grant_id, offer_id)
);
CREATE INDEX IF NOT EXISTS idx_user_node_selections_grant ON user_node_selections(grant_id, desired_enabled);
CREATE INDEX IF NOT EXISTS idx_user_node_selections_offer ON user_node_selections(offer_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_node_selections_source ON user_node_selections(access_source_id) WHERE access_source_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS user_inbound_access_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    inbound_tag TEXT NOT NULL,
    node_id INTEGER NOT NULL,
    source_type TEXT NOT NULL CHECK(source_type IN ('package', 'selection', 'legacy_review')),
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
);
CREATE INDEX IF NOT EXISTS idx_user_inbound_access_client ON user_inbound_access_sources(username, server_id, inbound_tag, desired_state);
CREATE INDEX IF NOT EXISTS idx_user_inbound_access_pending ON user_inbound_access_sources(server_id, next_retry_at, generation, applied_generation);
CREATE INDEX IF NOT EXISTS idx_user_inbound_access_source ON user_inbound_access_sources(source_type, source_id);

CREATE TABLE IF NOT EXISTS user_node_selection_usage (
    selection_id INTEGER PRIMARY KEY,
    grant_id INTEGER NOT NULL,
    cycle_started_at TIMESTAMP NOT NULL,
    uplink_bytes INTEGER NOT NULL DEFAULT 0 CHECK(uplink_bytes >= 0),
    downlink_bytes INTEGER NOT NULL DEFAULT 0 CHECK(downlink_bytes >= 0),
    last_raw_uplink INTEGER NOT NULL DEFAULT 0 CHECK(last_raw_uplink >= 0),
    last_raw_downlink INTEGER NOT NULL DEFAULT 0 CHECK(last_raw_downlink >= 0),
    counter_epoch TEXT NOT NULL DEFAULT '',
    last_reset_at TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_user_node_selection_usage_grant ON user_node_selection_usage(grant_id);

CREATE TABLE IF NOT EXISTS managed_access_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL DEFAULT 0,
    username TEXT NOT NULL DEFAULT '',
    server_id INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_managed_access_audit_user ON managed_access_audit(username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_managed_access_audit_entity ON managed_access_audit(entity_type, entity_id, created_at DESC);

CREATE TABLE IF NOT EXISTS remote_server_guard_secrets (
    server_id INTEGER PRIMARY KEY,
    secret TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate managed nodes: %w", err)
	}
	if err := r.ensureTableColumn("user_server_grants", "allowed_protocols_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return fmt.Errorf("migrate managed grant protocol whitelist: %w", err)
	}
	if err := r.ensureTableColumn("user_server_grants", "allowed_protocol_profiles_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return fmt.Errorf("migrate managed grant protocol profile whitelist: %w", err)
	}
	if err := r.ensureTableColumn("user_server_grants", "source_type", "TEXT NOT NULL DEFAULT 'manual'"); err != nil {
		return fmt.Errorf("migrate managed grant source type: %w", err)
	}
	if err := r.ensureTableColumn("user_server_grants", "source_package_id", "INTEGER"); err != nil {
		return fmt.Errorf("migrate managed grant source package: %w", err)
	}
	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_user_server_grants_package_source ON user_server_grants(username, source_package_id) WHERE source_type = 'package'`); err != nil {
		return fmt.Errorf("migrate managed grant source index: %w", err)
	}

	// Existing credentials cannot be safely attributed to a package or a user selection.
	// Backfill a non-authorizing tombstone so the reconciler can either retain the
	// credential through a real package/selection authorization or remove it. A legacy
	// row must never grant access by itself.
	const backfill = `
INSERT INTO user_inbound_access_sources (
    username, server_id, inbound_tag, node_id, source_type, source_id,
    desired_state, observed_state, suspend_reason, generation, applied_generation,
    starts_at, created_at, updated_at
)
SELECT c.username, c.server_id, c.inbound_tag,
       COALESCE((
           SELECT MIN(n.id)
           FROM nodes n
           JOIN remote_servers rs ON rs.id = c.server_id
           WHERE n.original_server = rs.name AND n.inbound_tag = c.inbound_tag
       ), 0),
       'legacy_review', c.id, 'inactive', 'unknown', 'admin_disabled', 1, 0,
       c.created_at, c.created_at, CURRENT_TIMESTAMP
FROM user_inbound_configs c
WHERE 1 = 1
ON CONFLICT(username, server_id, inbound_tag, node_id, source_type, source_id) DO NOTHING`
	if _, err := r.db.Exec(backfill); err != nil {
		return fmt.Errorf("backfill managed access sources: %w", err)
	}
	// Upgrade databases created by the first managed-node migration, which marked
	// legacy rows active and therefore accidentally made them perpetual grants.
	if _, err := r.db.Exec(`UPDATE user_inbound_access_sources SET
    desired_state = 'inactive', suspend_reason = 'admin_disabled',
    generation = generation + 1, retry_count = 0, next_retry_at = NULL,
    last_error = '', updated_at = CURRENT_TIMESTAMP
WHERE source_type = 'legacy_review' AND desired_state = 'active'`); err != nil {
		return fmt.Errorf("deactivate legacy managed access sources: %w", err)
	}
	return nil
}

// GetOrCreateRemoteServerGuardSecret returns the stable, guard-only secret for
// a remote server. It is deliberately separate from the rotating Agent token.
func (r *TrafficRepository) GetOrCreateRemoteServerGuardSecret(ctx context.Context, serverID int64) (string, error) {
	if err := managedInitialized(r); err != nil {
		return "", err
	}
	if serverID <= 0 {
		return "", ErrManagedInvalidArgument
	}
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remote_servers WHERE id = ?)`, serverID).Scan(&exists); err != nil {
		return "", fmt.Errorf("check remote server for guard secret: %w", err)
	}
	if exists == 0 {
		return "", ErrRemoteServerNotFound
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate guard secret: %w", err)
	}
	candidate := base64.RawURLEncoding.EncodeToString(random)
	if _, err := r.db.ExecContext(ctx, `
INSERT INTO remote_server_guard_secrets (server_id, secret)
VALUES (?, ?)
ON CONFLICT(server_id) DO NOTHING`, serverID, candidate); err != nil {
		return "", fmt.Errorf("store guard secret: %w", err)
	}
	var secret string
	if err := r.db.QueryRowContext(ctx, `SELECT secret FROM remote_server_guard_secrets WHERE server_id = ?`, serverID).Scan(&secret); err != nil {
		return "", fmt.Errorf("read guard secret: %w", err)
	}
	if strings.TrimSpace(secret) == "" {
		return "", errors.New("guard secret is empty")
	}
	return secret, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func managedNullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return u
}

func managedParseNullTime(v sql.NullString) *time.Time {
	return parseNullTimeString(v)
}

func managedUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "unique constraint failed") || strings.Contains(s, "constraint failed") && strings.Contains(s, "unique")
}

func managedInitialized(r *TrafficRepository) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	return nil
}

var managedGrantProtocolAliases = map[string]string{
	"vless":       "vless",
	"vmess":       "vmess",
	"trojan":      "trojan",
	"shadowsocks": "shadowsocks",
	"ss":          "shadowsocks",
	"hysteria":    "hysteria",
	"hysteria2":   "hysteria",
	"hy2":         "hysteria",
	"socks":       "socks",
	"socks5":      "socks",
	"http":        "http",
	"anytls":      "anytls",
	"snell":       "snell",
}

var managedGrantProtocolProfileFamilies = map[string]string{
	"vless-reality": "vless", "vless-tcp-tls": "vless", "vless-grpc-tls": "vless", "vless-wss": "vless", "vless-ws": "vless",
	"vmess-tcp-none": "vmess", "vmess-tcp-tls": "vmess", "vmess-grpc-tls": "vmess", "vmess-wss": "vmess", "vmess-ws": "vmess",
	"trojan-tcp-tls": "trojan", "trojan-reality": "trojan", "trojan-grpc-tls": "trojan", "trojan-wss": "trojan",
	"shadowsocks-classic": "shadowsocks", "shadowsocks-2022": "shadowsocks", "hysteria2": "hysteria", "socks5": "socks", "http": "http", "anytls": "anytls", "snell": "snell",
}

func canonicalManagedGrantProtocol(protocol string) (string, bool) {
	canonical, ok := managedGrantProtocolAliases[strings.ToLower(strings.TrimSpace(protocol))]
	return canonical, ok
}

// NormalizeManagedGrantAllowedProtocols validates the self-service protocol
// families stored on a server grant. An empty list intentionally means every
// publishable managed-client protocol, preserving grants created before this
// policy existed.
func NormalizeManagedGrantAllowedProtocols(protocols []string) ([]string, error) {
	normalized := make([]string, 0, len(protocols))
	seen := make(map[string]struct{}, len(protocols))
	for _, protocol := range protocols {
		canonical, ok := canonicalManagedGrantProtocol(protocol)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported allowed protocol %q", ErrManagedInvalidArgument, strings.TrimSpace(protocol))
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

// NormalizeManagedGrantAllowedProtocolProfiles validates the stable protocol
// combination identifiers stored on a server grant. An empty list adds no
// combination restriction and preserves the behavior of existing grants.
func NormalizeManagedGrantAllowedProtocolProfiles(profiles []string) ([]string, error) {
	normalized := make([]string, 0, len(profiles))
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		profile = strings.ToLower(strings.TrimSpace(profile))
		if _, ok := managedGrantProtocolProfileFamilies[profile]; !ok {
			return nil, fmt.Errorf("%w: unsupported allowed protocol profile %q", ErrManagedInvalidArgument, profile)
		}
		if _, exists := seen[profile]; exists {
			continue
		}
		seen[profile] = struct{}{}
		normalized = append(normalized, profile)
	}
	return normalized, nil
}

func validateManagedGrantProtocolScope(protocols, profiles []string) error {
	if len(profiles) == 0 {
		return nil
	}
	if len(protocols) == 0 {
		return fmt.Errorf("%w: allowed_protocols must match allowed_protocol_profiles", ErrManagedInvalidArgument)
	}
	profileFamilies := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		profileFamilies[managedGrantProtocolProfileFamilies[profile]] = struct{}{}
	}
	if len(profileFamilies) != len(protocols) {
		return fmt.Errorf("%w: allowed_protocols must match allowed_protocol_profiles", ErrManagedInvalidArgument)
	}
	for _, protocol := range protocols {
		if _, exists := profileFamilies[protocol]; !exists {
			return fmt.Errorf("%w: allowed_protocols must match allowed_protocol_profiles", ErrManagedInvalidArgument)
		}
	}
	return nil
}

func (g UserServerGrant) AllowsProtocol(protocol string) bool {
	canonical, publishable := canonicalManagedGrantProtocol(protocol)
	if !publishable {
		return false
	}
	if len(g.AllowedProtocols) == 0 {
		return true
	}
	for _, allowed := range g.AllowedProtocols {
		if allowed == canonical {
			return true
		}
	}
	return false
}

// SelfServiceNodeProtocolProfile derives the stable client-facing combination
// represented by a node's Clash configuration. A profile-restricted grant
// fails closed when the configuration cannot be classified.
func SelfServiceNodeProtocolProfile(protocolName, clashConfig string) (string, bool) {
	protocol, ok := canonicalManagedGrantProtocol(protocolName)
	if !ok {
		return "", false
	}
	var config map[string]interface{}
	if json.Unmarshal([]byte(clashConfig), &config) != nil || config == nil {
		return "", false
	}
	configType, ok := config["type"].(string)
	if !ok {
		return "", false
	}
	configType = strings.ToLower(strings.TrimSpace(configType))
	configFamily, ok := canonicalManagedGrantProtocol(configType)
	if !ok || configFamily != protocol {
		return "", false
	}
	if protocol == "shadowsocks" {
		return managedShadowsocksProtocolProfile(config)
	}
	switch protocol {
	case "hysteria":
		if configType != "hysteria2" {
			return "", false
		}
		return "hysteria2", true
	case "socks":
		return "socks5", true
	case "http":
		return protocol, true
	}

	network := ""
	if value, exists := config["network"]; exists {
		var valid bool
		network, valid = value.(string)
		if !valid {
			return "", false
		}
	}
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		network = "tcp"
	}
	security := ""
	if value, exists := config["security"]; exists {
		var valid bool
		security, valid = value.(string)
		if !valid {
			return "", false
		}
	}
	security = strings.ToLower(strings.TrimSpace(security))
	tls := false
	if value, exists := config["tls"]; exists {
		var valid bool
		tls, valid = value.(bool)
		if !valid {
			return "", false
		}
	}
	if security == "tls" || security == "reality" {
		tls = true
	}
	hasRealityOptions := false
	for _, key := range []string{"reality-opts", "reality_opts"} {
		if value, exists := config[key]; exists {
			if _, valid := value.(map[string]interface{}); !valid {
				return "", false
			}
			hasRealityOptions = true
		}
	}
	reality := security == "reality" || hasRealityOptions

	switch protocol {
	case "snell":
		version, valid := config["version"].(float64)
		if network != "tcp" || !valid || version != 4 && version != 5 {
			return "", false
		}
		return "snell", true
	}

	switch protocol {
	case "vless":
		switch {
		case network == "tcp" && reality:
			return "vless-reality", true
		case network == "tcp" && tls && !reality:
			return "vless-tcp-tls", true
		case network == "grpc" && tls && !reality:
			return "vless-grpc-tls", true
		case network == "ws" && tls && !reality:
			return "vless-wss", true
		case network == "ws" && !tls && !reality:
			return "vless-ws", true
		}
	case "vmess":
		switch {
		case network == "tcp" && !tls && !reality:
			return "vmess-tcp-none", true
		case network == "tcp" && tls && !reality:
			return "vmess-tcp-tls", true
		case network == "grpc" && tls && !reality:
			return "vmess-grpc-tls", true
		case network == "ws" && tls && !reality:
			return "vmess-wss", true
		case network == "ws" && !tls && !reality:
			return "vmess-ws", true
		}
	case "trojan":
		switch {
		case network == "tcp" && reality:
			return "trojan-reality", true
		case network == "tcp" && tls && !reality:
			return "trojan-tcp-tls", true
		case network == "grpc" && tls && !reality:
			return "trojan-grpc-tls", true
		case network == "ws" && tls && !reality:
			return "trojan-wss", true
		}
	}
	return "", false
}

// AllowsNodeProtocol applies both grant layers: protocol family first, then
// the optional exact combination whitelist.
func (g UserServerGrant) AllowsNodeProtocol(protocol, clashConfig string) bool {
	if !g.AllowsProtocol(protocol) {
		return false
	}
	if len(g.AllowedProtocolProfiles) == 0 {
		return true
	}
	profile, ok := SelfServiceNodeProtocolProfile(protocol, clashConfig)
	if !ok {
		return false
	}
	for _, allowed := range g.AllowedProtocolProfiles {
		if allowed == profile {
			return true
		}
	}
	return false
}

func normalizeGrant(g UserServerGrant) (UserServerGrant, error) {
	g.Username = strings.TrimSpace(g.Username)
	g.CreatedBy = strings.TrimSpace(g.CreatedBy)
	g.BillingMode = strings.ToLower(strings.TrimSpace(g.BillingMode))
	g.ResetPolicy = strings.ToLower(strings.TrimSpace(g.ResetPolicy))
	g.BillingTimezone = strings.TrimSpace(g.BillingTimezone)
	g.SourceType = strings.ToLower(strings.TrimSpace(g.SourceType))
	if g.SourceType == "" {
		g.SourceType = GrantSourceManual
	}
	if g.BillingMode == "" {
		g.BillingMode = ManagedBillingDownload
	}
	if g.ResetPolicy == "" {
		g.ResetPolicy = ManagedResetNone
	}
	if g.ResetDay == 0 {
		g.ResetDay = 1
	}
	if g.BillingTimezone == "" {
		g.BillingTimezone = "Asia/Shanghai"
	}
	allowedProtocols, err := NormalizeManagedGrantAllowedProtocols(g.AllowedProtocols)
	if err != nil {
		return g, err
	}
	g.AllowedProtocols = allowedProtocols
	allowedProtocolProfiles, err := NormalizeManagedGrantAllowedProtocolProfiles(g.AllowedProtocolProfiles)
	if err != nil {
		return g, err
	}
	g.AllowedProtocolProfiles = allowedProtocolProfiles
	if err := validateManagedGrantProtocolScope(g.AllowedProtocols, g.AllowedProtocolProfiles); err != nil {
		return g, err
	}
	g.StartsAt = g.StartsAt.UTC()
	if g.ExpiresAt != nil {
		expires := g.ExpiresAt.UTC()
		g.ExpiresAt = &expires
	}
	if g.NextResetAt != nil {
		next := g.NextResetAt.UTC()
		g.NextResetAt = &next
	}
	if g.Username == "" || g.ServerID <= 0 || g.CreatedBy == "" || g.StartsAt.IsZero() {
		return g, ErrManagedInvalidArgument
	}
	if g.SourceType != GrantSourceManual && g.SourceType != GrantSourcePackage {
		return g, ErrManagedInvalidArgument
	}
	if g.SourceType == GrantSourcePackage {
		if g.SourcePackageID == nil || *g.SourcePackageID <= 0 {
			return g, ErrManagedInvalidArgument
		}
	} else {
		if g.SourcePackageID != nil {
			return g, ErrManagedInvalidArgument
		}
	}
	if g.ExpiresAt != nil && !g.ExpiresAt.After(g.StartsAt) {
		return g, fmt.Errorf("%w: expires_at must be after starts_at", ErrManagedInvalidArgument)
	}
	if g.MaxActiveNodes < 0 || g.SpeedLimitMbps < 0 || g.ConnectionLimit < 0 || g.TrafficLimitBytes < 0 {
		return g, fmt.Errorf("%w: limits cannot be negative", ErrManagedInvalidArgument)
	}
	if g.BillingMode != ManagedBillingDownload && g.BillingMode != ManagedBillingBoth {
		return g, fmt.Errorf("%w: invalid billing mode", ErrManagedInvalidArgument)
	}
	if g.ResetPolicy != ManagedResetNone && g.ResetPolicy != ManagedResetMonthly {
		return g, fmt.Errorf("%w: invalid reset policy", ErrManagedInvalidArgument)
	}
	if g.ResetDay < 1 || g.ResetDay > 28 {
		return g, fmt.Errorf("%w: reset day must be between 1 and 28", ErrManagedInvalidArgument)
	}
	if _, err := time.LoadLocation(g.BillingTimezone); err != nil {
		return g, fmt.Errorf("%w: invalid billing timezone", ErrManagedInvalidArgument)
	}
	return g, nil
}

func scanSelfServiceNodeOffer(s rowScanner) (SelfServiceNodeOffer, error) {
	var offer SelfServiceNodeOffer
	var enabled int
	err := s.Scan(&offer.ID, &offer.NodeID, &offer.ServerID, &offer.InboundTag, &enabled,
		&offer.SortOrder, &offer.CreatedBy, &offer.CreatedAt, &offer.UpdatedAt)
	offer.Enabled = enabled != 0
	return offer, err
}

const selectSelfServiceNodeOffer = `SELECT id, node_id, server_id, inbound_tag, enabled,
       sort_order, created_by, created_at, updated_at
FROM self_service_node_offers`

func (r *TrafficRepository) CreateSelfServiceNodeOffer(ctx context.Context, nodeID, serverID int64, createdBy string) (*SelfServiceNodeOffer, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	createdBy = strings.TrimSpace(createdBy)
	if nodeID <= 0 || serverID <= 0 || createdBy == "" {
		return nil, ErrManagedInvalidArgument
	}

	var (
		nodeEnabled    int
		nodeType       string
		nodeProtocol   string
		clashConfig    string
		inboundTag     string
		originalServer string
		serverName     string
		xrayMode       string
	)
	err := r.db.QueryRowContext(ctx, `
SELECT n.enabled, COALESCE(n.node_type, 'physical'), LOWER(COALESCE(n.protocol, '')),
       COALESCE(n.clash_config, ''), COALESCE(n.inbound_tag, ''),
       COALESCE(n.original_server, ''), rs.name, COALESCE(rs.xray_mode, 'external')
FROM nodes n
JOIN remote_servers rs ON rs.id = ?
WHERE n.id = ?`, serverID, nodeID).Scan(
		&nodeEnabled, &nodeType, &nodeProtocol, &clashConfig, &inboundTag, &originalServer, &serverName, &xrayMode,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrManagedServerMismatch
	}
	if err != nil {
		return nil, fmt.Errorf("resolve self-service offer: %w", err)
	}
	node := Node{
		ID: nodeID, Protocol: nodeProtocol, ClashConfig: clashConfig, Enabled: nodeEnabled != 0,
		NodeType: nodeType, OriginalServer: originalServer, InboundTag: inboundTag,
	}
	server := RemoteServer{ID: serverID, Name: serverName, XrayMode: xrayMode}
	offer := SelfServiceNodeOffer{NodeID: nodeID, ServerID: serverID, InboundTag: inboundTag, Enabled: true}
	if !node.Enabled || !SelfServiceNodeOfferStructureValid(offer, node, server) {
		return nil, ErrManagedServerMismatch
	}
	if !SelfServiceNodeOfferProtocolEligible(offer, node) {
		return nil, fmt.Errorf("%w: protocol does not support isolated managed credentials", ErrManagedInvalidArgument)
	}

	now := time.Now().UTC()
	result, err := r.db.ExecContext(ctx, `
INSERT INTO self_service_node_offers
    (node_id, server_id, inbound_tag, enabled, sort_order, created_by, created_at, updated_at)
VALUES (?, ?, ?, 1, 0, ?, ?, ?)`, nodeID, serverID, inboundTag, createdBy, now, now)
	if managedUniqueViolation(err) {
		return nil, ErrSelfServiceNodeOfferExists
	}
	if err != nil {
		return nil, fmt.Errorf("create self-service node offer: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read self-service node offer id: %w", err)
	}
	return r.GetSelfServiceNodeOffer(ctx, id)
}

// SelfServiceNodeProtocolEligible is the single protocol-safety policy used by
// publishing, activation, read-side access checks, and remote reconciliation.
func SelfServiceNodeProtocolEligible(protocolName, clashConfig string) bool {
	protocolName = strings.ToLower(strings.TrimSpace(protocolName))
	switch protocolName {
	case "vless", "vmess", "trojan", "snell", "socks", "socks5", "http", "hysteria", "hysteria2", "hy2":
		return true
	case "ss", "shadowsocks":
		var config map[string]interface{}
		if json.Unmarshal([]byte(clashConfig), &config) != nil {
			return false
		}
		profile, ok := managedShadowsocksProtocolProfile(config)
		if !ok {
			return false
		}
		if profile != "shadowsocks-classic" {
			return true
		}
		multiUser, ok := config[ManagedShadowsocksMultiUserMarker].(bool)
		return ok && multiUser
	default:
		return false
	}
}

func managedShadowsocksProtocolProfile(config map[string]interface{}) (string, bool) {
	cipher, _ := config["cipher"].(string)
	if strings.TrimSpace(cipher) == "" {
		cipher, _ = config["method"].(string)
	}
	switch strings.ToLower(strings.TrimSpace(cipher)) {
	case "aes-128-gcm", "aes-256-gcm":
		return "shadowsocks-classic", true
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return "shadowsocks-2022", true
	default:
		return "", false
	}
}

// SelfServiceCredentialProtocolMatches verifies that a stored credential was
// generated for the same protocol family as the current node. Aliases such as
// ss/shadowsocks and hy2/hysteria2 intentionally compare equal.
func SelfServiceCredentialProtocolMatches(credentialProtocol, nodeProtocol string) bool {
	credentialFamily, credentialOK := canonicalManagedGrantProtocol(credentialProtocol)
	nodeFamily, nodeOK := canonicalManagedGrantProtocol(nodeProtocol)
	return credentialOK && nodeOK && credentialFamily == nodeFamily
}

func selfServiceProtocolEligible(protocolName, clashConfig string) bool {
	return SelfServiceNodeProtocolEligible(protocolName, clashConfig)
}

func SelfServiceNodeOfferProtocolEligible(offer SelfServiceNodeOffer, node Node) bool {
	return !strings.HasPrefix(strings.ToLower(strings.TrimSpace(offer.InboundTag)), "anydoor-") &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(node.InboundTag)), "anydoor-") &&
		SelfServiceNodeProtocolEligible(node.Protocol, node.ClashConfig)
}

// SelfServiceNodeOfferStructureValid verifies that the offer still points to
// the same physical inbound on the same embedded-Xray server. Enabled flags and
// protocol policy are intentionally separate so temporary suspension does not
// erase a user's selection intent.
func SelfServiceNodeOfferStructureValid(offer SelfServiceNodeOffer, node Node, server RemoteServer) bool {
	nodeType := strings.ToLower(strings.TrimSpace(node.NodeType))
	if nodeType == "" {
		nodeType = "physical"
	}
	return offer.NodeID > 0 && offer.NodeID == node.ID && offer.ServerID > 0 && offer.ServerID == server.ID &&
		strings.TrimSpace(offer.InboundTag) != "" && offer.InboundTag == node.InboundTag &&
		nodeType == "physical" && node.OriginalServer == server.Name && strings.TrimSpace(server.Name) != "" &&
		strings.EqualFold(strings.TrimSpace(server.XrayMode), "embedded")
}

func SelfServiceNodeOfferAvailable(offer SelfServiceNodeOffer, node Node, server RemoteServer) bool {
	return offer.Enabled && node.Enabled && SelfServiceNodeOfferStructureValid(offer, node, server) &&
		SelfServiceNodeOfferProtocolEligible(offer, node)
}

func (r *TrafficRepository) GetSelfServiceNodeOffer(ctx context.Context, id int64) (*SelfServiceNodeOffer, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	offer, err := scanSelfServiceNodeOffer(r.db.QueryRowContext(ctx, selectSelfServiceNodeOffer+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSelfServiceNodeOfferNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get self-service node offer: %w", err)
	}
	return &offer, nil
}

func (r *TrafficRepository) listSelfServiceNodeOffers(ctx context.Context, where string, args ...any) ([]SelfServiceNodeOffer, error) {
	rows, err := r.db.QueryContext(ctx, selectSelfServiceNodeOffer+where+` ORDER BY sort_order ASC, id ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("list self-service node offers: %w", err)
	}
	defer rows.Close()
	offers := make([]SelfServiceNodeOffer, 0)
	for rows.Next() {
		offer, err := scanSelfServiceNodeOffer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan self-service node offer: %w", err)
		}
		offers = append(offers, offer)
	}
	return offers, rows.Err()
}

func (r *TrafficRepository) ListSelfServiceNodeOffers(ctx context.Context, includeDisabled bool) ([]SelfServiceNodeOffer, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if includeDisabled {
		return r.listSelfServiceNodeOffers(ctx, "")
	}
	return r.listSelfServiceNodeOffers(ctx, ` WHERE enabled = 1`)
}

func (r *TrafficRepository) ListSelfServiceNodeOffersByServer(ctx context.Context, serverID int64, includeDisabled bool) ([]SelfServiceNodeOffer, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if serverID <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	if includeDisabled {
		return r.listSelfServiceNodeOffers(ctx, ` WHERE server_id = ?`, serverID)
	}
	return r.listSelfServiceNodeOffers(ctx, ` WHERE server_id = ? AND enabled = 1`, serverID)
}

func (r *TrafficRepository) UpdateSelfServiceNodeOffer(ctx context.Context, id int64, enabled bool, sortOrder int) (*SelfServiceNodeOffer, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	if id <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	result, err := r.db.ExecContext(ctx, `UPDATE self_service_node_offers
SET enabled = ?, sort_order = ?, updated_at = ? WHERE id = ?`, boolInt(enabled), sortOrder, time.Now().UTC(), id)
	if err != nil {
		return nil, fmt.Errorf("update self-service node offer: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil, ErrSelfServiceNodeOfferNotFound
	}
	return r.GetSelfServiceNodeOffer(ctx, id)
}

func (r *TrafficRepository) DeleteSelfServiceNodeOffer(ctx context.Context, id int64) error {
	if err := managedInitialized(r); err != nil {
		return err
	}
	if id <= 0 {
		return ErrManagedInvalidArgument
	}
	var selections int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_node_selections WHERE offer_id = ?`, id).Scan(&selections); err != nil {
		return fmt.Errorf("check offer selections: %w", err)
	}
	if selections > 0 {
		return ErrManagedResourceInUse
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM self_service_node_offers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete self-service node offer: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrSelfServiceNodeOfferNotFound
	}
	return nil
}

func scanUserServerGrant(s rowScanner) (UserServerGrant, error) {
	var grant UserServerGrant
	var enabled int
	var expires, nextReset sql.NullString
	var sourcePackageID sql.NullInt64
	var allowedProtocolsJSON, allowedProtocolProfilesJSON string
	err := s.Scan(&grant.ID, &grant.Username, &grant.ServerID, &enabled, &grant.StartsAt, &expires,
		&grant.MaxActiveNodes, &grant.SpeedLimitMbps, &grant.ConnectionLimit, &grant.TrafficLimitBytes,
		&grant.BillingMode, &grant.ResetPolicy, &grant.ResetDay, &grant.BillingTimezone, &nextReset,
		&allowedProtocolsJSON, &allowedProtocolProfilesJSON, &grant.SourceType, &sourcePackageID, &grant.Version, &grant.CreatedBy, &grant.CreatedAt, &grant.UpdatedAt)
	if err != nil {
		return grant, err
	}
	grant.Enabled = enabled != 0
	grant.ExpiresAt = managedParseNullTime(expires)
	grant.NextResetAt = managedParseNullTime(nextReset)
	if sourcePackageID.Valid {
		id := sourcePackageID.Int64
		grant.SourcePackageID = &id
	}
	if err := json.Unmarshal([]byte(allowedProtocolsJSON), &grant.AllowedProtocols); err != nil {
		return grant, fmt.Errorf("decode managed grant allowed protocols: %w", err)
	}
	allowedProtocols, err := NormalizeManagedGrantAllowedProtocols(grant.AllowedProtocols)
	if err != nil {
		return grant, fmt.Errorf("decode managed grant allowed protocols: %w", err)
	}
	grant.AllowedProtocols = allowedProtocols
	if err := json.Unmarshal([]byte(allowedProtocolProfilesJSON), &grant.AllowedProtocolProfiles); err != nil {
		return grant, fmt.Errorf("decode managed grant allowed protocol profiles: %w", err)
	}
	allowedProtocolProfiles, err := NormalizeManagedGrantAllowedProtocolProfiles(grant.AllowedProtocolProfiles)
	if err != nil {
		return grant, fmt.Errorf("decode managed grant allowed protocol profiles: %w", err)
	}
	grant.AllowedProtocolProfiles = allowedProtocolProfiles
	if err := validateManagedGrantProtocolScope(grant.AllowedProtocols, grant.AllowedProtocolProfiles); err != nil {
		return grant, fmt.Errorf("decode managed grant protocol scope: %w", err)
	}
	return grant, nil
}

const selectUserServerGrant = `SELECT id, username, server_id, enabled, starts_at, expires_at,
       max_active_nodes, speed_limit_mbps, connection_limit, traffic_limit_bytes,
       billing_mode, reset_policy, reset_day, billing_timezone, next_reset_at,
	   allowed_protocols_json, allowed_protocol_profiles_json, COALESCE(source_type, 'manual'), source_package_id, version, created_by, created_at, updated_at
FROM user_server_grants`

func (r *TrafficRepository) CreateUserServerGrant(ctx context.Context, grant UserServerGrant) (*UserServerGrant, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	grant, err := normalizeGrant(grant)
	if err != nil {
		return nil, err
	}
	var userExists, serverExists int
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username = ?),
EXISTS(SELECT 1 FROM remote_servers WHERE id = ?)`, grant.Username, grant.ServerID).Scan(&userExists, &serverExists); err != nil {
		return nil, fmt.Errorf("validate user server grant: %w", err)
	}
	if userExists == 0 {
		return nil, ErrUserNotFound
	}
	if serverExists == 0 {
		return nil, ErrRemoteServerNotFound
	}
	now := time.Now().UTC()
	if grant.ResetPolicy == ManagedResetMonthly {
		base := now
		if grant.StartsAt.After(base) {
			base = grant.StartsAt
		}
		next := NextManagedMonthlyReset(base, grant.ResetDay, grant.BillingTimezone)
		grant.NextResetAt = &next
	} else {
		grant.NextResetAt = nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin create user server grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	allowedProtocolsJSON, err := json.Marshal(grant.AllowedProtocols)
	if err != nil {
		return nil, fmt.Errorf("encode managed grant allowed protocols: %w", err)
	}
	allowedProtocolProfilesJSON, err := json.Marshal(grant.AllowedProtocolProfiles)
	if err != nil {
		return nil, fmt.Errorf("encode managed grant allowed protocol profiles: %w", err)
	}
	// A revoked package grant with historical selections is retained as an
	// inactive tombstone because those children still need reconciliation. A
	// subsequent explicit admin grant for the same user/server may safely adopt
	// that row without reviving any old package selection.
	if grant.SourceType == GrantSourceManual {
		var tombstoneID int64
		var tombstoneVersion int64
		tombstoneErr := tx.QueryRowContext(ctx, `SELECT id,version FROM user_server_grants
WHERE username=? AND server_id=? AND source_type='package' AND enabled=0`, grant.Username, grant.ServerID).Scan(&tombstoneID, &tombstoneVersion)
		if tombstoneErr != nil && !errors.Is(tombstoneErr, sql.ErrNoRows) {
			return nil, fmt.Errorf("read package grant tombstone: %w", tombstoneErr)
		}
		if tombstoneErr == nil {
			result, updateErr := tx.ExecContext(ctx, `UPDATE user_server_grants SET enabled=?,starts_at=?,expires_at=?,max_active_nodes=?,
speed_limit_mbps=?,connection_limit=?,traffic_limit_bytes=?,billing_mode=?,reset_policy=?,reset_day=?,billing_timezone=?,
next_reset_at=?,allowed_protocols_json=?,allowed_protocol_profiles_json=?,source_type='manual',source_package_id=NULL,
version=version+1,created_by=?,updated_at=? WHERE id=? AND version=? AND source_type='package' AND enabled=0`,
				boolInt(grant.Enabled), grant.StartsAt, managedNullTime(grant.ExpiresAt), grant.MaxActiveNodes,
				grant.SpeedLimitMbps, grant.ConnectionLimit, grant.TrafficLimitBytes, grant.BillingMode,
				grant.ResetPolicy, grant.ResetDay, grant.BillingTimezone, managedNullTime(grant.NextResetAt),
				string(allowedProtocolsJSON), string(allowedProtocolProfilesJSON), grant.CreatedBy, now, tombstoneID, tombstoneVersion)
			if updateErr != nil {
				return nil, fmt.Errorf("adopt package grant tombstone: %w", updateErr)
			}
			if affected, _ := result.RowsAffected(); affected != 1 {
				return nil, ErrManagedVersionConflict
			}
			if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
				Actor: grant.CreatedBy, Action: "grant.adopted_from_package", EntityType: "server_grant", EntityID: tombstoneID,
				Username: grant.Username, ServerID: grant.ServerID,
			}); err != nil {
				return nil, err
			}
			if err := tx.Commit(); err != nil {
				return nil, fmt.Errorf("commit package grant tombstone adoption: %w", err)
			}
			return r.GetUserServerGrant(ctx, tombstoneID)
		}
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO user_server_grants (
    username, server_id, enabled, starts_at, expires_at, max_active_nodes,
    speed_limit_mbps, connection_limit, traffic_limit_bytes, billing_mode,
    reset_policy, reset_day, billing_timezone, next_reset_at, allowed_protocols_json,
	    allowed_protocol_profiles_json, source_type, source_package_id, version,
	    created_by, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
		grant.Username, grant.ServerID, boolInt(grant.Enabled), grant.StartsAt, managedNullTime(grant.ExpiresAt),
		grant.MaxActiveNodes, grant.SpeedLimitMbps, grant.ConnectionLimit, grant.TrafficLimitBytes,
		grant.BillingMode, grant.ResetPolicy, grant.ResetDay, grant.BillingTimezone,
		managedNullTime(grant.NextResetAt), string(allowedProtocolsJSON), string(allowedProtocolProfilesJSON), grant.SourceType, grant.SourcePackageID, grant.CreatedBy, now, now)
	if managedUniqueViolation(err) {
		return nil, ErrUserServerGrantExists
	}
	if err != nil {
		return nil, fmt.Errorf("create user server grant: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read user server grant id: %w", err)
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: grant.CreatedBy, Action: "grant.created", EntityType: "server_grant", EntityID: id,
		Username: grant.Username, ServerID: grant.ServerID,
		Details: map[string]any{
			"allowed_protocols": grant.AllowedProtocols, "allowed_protocol_profiles": grant.AllowedProtocolProfiles,
		},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit create user server grant: %w", err)
	}
	return r.GetUserServerGrant(ctx, id)
}

func (r *TrafficRepository) GetUserServerGrant(ctx context.Context, id int64) (*UserServerGrant, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	grant, err := scanUserServerGrant(r.db.QueryRowContext(ctx, selectUserServerGrant+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserServerGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user server grant: %w", err)
	}
	return &grant, nil
}

func (r *TrafficRepository) GetUserServerGrantByUserAndServer(ctx context.Context, username string, serverID int64) (*UserServerGrant, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if username == "" || serverID <= 0 {
		return nil, ErrManagedInvalidArgument
	}
	grant, err := scanUserServerGrant(r.db.QueryRowContext(ctx, selectUserServerGrant+` WHERE username = ? AND server_id = ?`, username, serverID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserServerGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user server grant by server: %w", err)
	}
	return &grant, nil
}

func (r *TrafficRepository) ListUserServerGrants(ctx context.Context, username string) ([]UserServerGrant, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrManagedInvalidArgument
	}
	rows, err := r.db.QueryContext(ctx, selectUserServerGrant+` WHERE username = ? ORDER BY id ASC`, username)
	if err != nil {
		return nil, fmt.Errorf("list user server grants: %w", err)
	}
	defer rows.Close()
	grants := make([]UserServerGrant, 0)
	for rows.Next() {
		grant, err := scanUserServerGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user server grant: %w", err)
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (r *TrafficRepository) ListAllUserServerGrants(ctx context.Context) ([]UserServerGrant, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, selectUserServerGrant+` ORDER BY username ASC, server_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list all user server grants: %w", err)
	}
	defer rows.Close()
	grants := make([]UserServerGrant, 0)
	for rows.Next() {
		grant, err := scanUserServerGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user server grant: %w", err)
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (r *TrafficRepository) UpdateUserServerGrant(ctx context.Context, grant UserServerGrant, expectedVersion int64, actor string) (*UserServerGrant, error) {
	if err := managedInitialized(r); err != nil {
		return nil, err
	}
	actor = strings.TrimSpace(actor)
	if grant.ID <= 0 || expectedVersion <= 0 || actor == "" {
		return nil, ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	existing, err := r.GetUserServerGrant(ctx, grant.ID)
	if err != nil {
		return nil, err
	}
	grant.Username = existing.Username
	grant.ServerID = existing.ServerID
	grant.CreatedBy = existing.CreatedBy
	grant.SourceType = existing.SourceType
	grant.SourcePackageID = existing.SourcePackageID
	grant, err = normalizeGrant(grant)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if grant.ResetPolicy == ManagedResetNone {
		grant.NextResetAt = nil
	} else if existing.ResetPolicy != ManagedResetMonthly || existing.NextResetAt == nil ||
		grant.ResetDay != existing.ResetDay || grant.BillingTimezone != existing.BillingTimezone ||
		!grant.StartsAt.Equal(existing.StartsAt) {
		base := now
		if grant.StartsAt.After(base) {
			base = grant.StartsAt
		}
		next := NextManagedMonthlyReset(base, grant.ResetDay, grant.BillingTimezone)
		grant.NextResetAt = &next
	} else {
		grant.NextResetAt = existing.NextResetAt
	}
	if grant.BillingMode != existing.BillingMode {
		var recorded int64
		if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(uplink_bytes + downlink_bytes), 0)
FROM user_node_selection_usage WHERE grant_id = ?`, grant.ID).Scan(&recorded); err != nil {
			return nil, fmt.Errorf("check managed grant usage before billing change: %w", err)
		}
		if recorded > 0 {
			return nil, ErrManagedBillingModeConflict
		}
	}
	var existingUserEnabled int
	if err := r.db.QueryRowContext(ctx, `SELECT is_active FROM users WHERE username = ?`, grant.Username).Scan(&existingUserEnabled); err != nil {
		return nil, fmt.Errorf("read existing grant user state: %w", err)
	}
	_, _, existingBilled, err := r.GetUserServerGrantUsage(ctx, existing.ID)
	if err != nil {
		return nil, err
	}
	existingState := existing.StateAt(now, existingUserEnabled != 0, existingBilled)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin update user server grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Narrowing the whitelist is a revocation, not a presentation-only filter.
	// Mark disallowed selections inactive before refreshing their access sources;
	// widening the policy later deliberately requires the user to opt in again.
	disallowedSelectionIDs := make([]int64, 0)
	rows, err := tx.QueryContext(ctx, `SELECT s.id, COALESCE(n.protocol, ''), COALESCE(n.clash_config, ''), COALESCE(o.inbound_tag, '')
FROM user_node_selections s
JOIN self_service_node_offers o ON o.id = s.offer_id
JOIN nodes n ON n.id = o.node_id
WHERE s.grant_id = ? AND s.desired_enabled = 1`, grant.ID)
	if err != nil {
		return nil, fmt.Errorf("list managed selections for protocol policy: %w", err)
	}
	for rows.Next() {
		var selectionID int64
		var protocol, clashConfig, inboundTag string
		if err := rows.Scan(&selectionID, &protocol, &clashConfig, &inboundTag); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan managed selection protocol: %w", err)
		}
		if !grant.AllowsNodeProtocol(protocol, clashConfig) || !SelfServiceNodeProtocolEligible(protocol, clashConfig) ||
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(inboundTag)), "anydoor-") {
			disallowedSelectionIDs = append(disallowedSelectionIDs, selectionID)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("list managed selection protocols: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close managed selection protocol rows: %w", err)
	}
	for _, selectionID := range disallowedSelectionIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE user_node_selections
SET desired_enabled = 0, updated_at = ? WHERE id = ? AND desired_enabled = 1`, now, selectionID); err != nil {
			return nil, fmt.Errorf("deactivate protocol-restricted managed selection: %w", err)
		}
	}
	if grant.MaxActiveNodes > 0 {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_node_selections
WHERE grant_id = ? AND desired_enabled = 1`, grant.ID).Scan(&active); err != nil {
			return nil, fmt.Errorf("count active managed selections: %w", err)
		}
		if active > grant.MaxActiveNodes {
			return nil, ErrManagedActiveNodeLimit
		}
	}
	allowedProtocolsJSON, err := json.Marshal(grant.AllowedProtocols)
	if err != nil {
		return nil, fmt.Errorf("encode managed grant allowed protocols: %w", err)
	}
	allowedProtocolProfilesJSON, err := json.Marshal(grant.AllowedProtocolProfiles)
	if err != nil {
		return nil, fmt.Errorf("encode managed grant allowed protocol profiles: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE user_server_grants SET
    enabled = ?, starts_at = ?, expires_at = ?, max_active_nodes = ?,
    speed_limit_mbps = ?, connection_limit = ?, traffic_limit_bytes = ?,
    billing_mode = ?, reset_policy = ?, reset_day = ?, billing_timezone = ?,
    next_reset_at = ?, allowed_protocols_json = ?, allowed_protocol_profiles_json = ?,
    version = version + 1, updated_at = ?
WHERE id = ? AND version = ?`, boolInt(grant.Enabled), grant.StartsAt, managedNullTime(grant.ExpiresAt),
		grant.MaxActiveNodes, grant.SpeedLimitMbps, grant.ConnectionLimit, grant.TrafficLimitBytes,
		grant.BillingMode, grant.ResetPolicy, grant.ResetDay, grant.BillingTimezone,
		managedNullTime(grant.NextResetAt), string(allowedProtocolsJSON), string(allowedProtocolProfilesJSON), now, grant.ID, expectedVersion)
	if err != nil {
		return nil, fmt.Errorf("update user server grant: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_server_grants WHERE id = ?)`, grant.ID).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check user server grant version: %w", err)
		}
		if exists == 0 {
			return nil, ErrUserServerGrantNotFound
		}
		return nil, ErrManagedVersionConflict
	}

	var userEnabled int
	if err := tx.QueryRowContext(ctx, `SELECT is_active FROM users WHERE username = ?`, grant.Username).Scan(&userEnabled); err != nil {
		return nil, fmt.Errorf("read grant user state: %w", err)
	}
	billed, err := grantUsageTx(ctx, tx, grant.ID, grant.BillingMode)
	if err != nil {
		return nil, fmt.Errorf("read grant usage during update: %w", err)
	}

	// Changing the authorization window, policy, switch, or account state must
	// version every source so queued Agent commands cannot apply stale access.
	state := grant.StateAt(now, userEnabled != 0, billed)
	active := state == ManagedGrantActive
	if active && existingState != ManagedGrantActive {
		if err := currentUserPackageConflictsWithManagedSelections(ctx, tx, grant.Username, grant.ID, now); err != nil {
			return nil, err
		}
	}
	reason := grantSuspendReason(state)
	if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources
SET desired_state = CASE WHEN ? = 1 AND source_id IN (
        SELECT id FROM user_node_selections WHERE grant_id = ? AND desired_enabled = 1
    ) THEN ? ELSE ? END,
    suspend_reason = CASE WHEN ? = 1 AND source_id IN (
        SELECT id FROM user_node_selections WHERE grant_id = ? AND desired_enabled = 1
    ) THEN ? WHEN source_id IN (
        SELECT id FROM user_node_selections WHERE grant_id = ? AND desired_enabled = 0
    ) THEN ? ELSE ? END,
    expires_at = ?, generation = generation + 1, retry_count = 0,
    next_retry_at = NULL, last_error = '', updated_at = ?
WHERE source_type = ? AND source_id IN (
    SELECT id FROM user_node_selections WHERE grant_id = ?
)`, boolInt(active), grant.ID, ManagedDesiredActive, ManagedDesiredInactive,
		boolInt(active), grant.ID, ManagedSuspendNone, grant.ID, ManagedSuspendUserDisabled, reason,
		managedNullTime(grant.ExpiresAt), now, ManagedSourceSelection, grant.ID); err != nil {
		return nil, fmt.Errorf("refresh grant access sources: %w", err)
	}
	for _, selectionID := range disallowedSelectionIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE user_inbound_access_sources
SET suspend_reason = ? WHERE source_type = ? AND source_id = ?`,
			ManagedSuspendAdminDisabled, ManagedSourceSelection, selectionID); err != nil {
			return nil, fmt.Errorf("mark protocol-restricted managed source: %w", err)
		}
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "grant.updated", EntityType: "server_grant", EntityID: grant.ID,
		Username: grant.Username, ServerID: grant.ServerID,
		Details: map[string]any{
			"expected_version": expectedVersion, "enabled": grant.Enabled,
			"allowed_protocols": grant.AllowedProtocols, "allowed_protocol_profiles": grant.AllowedProtocolProfiles,
			"deactivated_selection_ids": disallowedSelectionIDs,
		},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit update user server grant: %w", err)
	}
	return r.GetUserServerGrant(ctx, grant.ID)
}

func (r *TrafficRepository) DeleteUserServerGrant(ctx context.Context, id, expectedVersion int64, actor string) error {
	if err := managedInitialized(r); err != nil {
		return err
	}
	actor = strings.TrimSpace(actor)
	if id <= 0 || expectedVersion <= 0 || actor == "" {
		return ErrManagedInvalidArgument
	}
	r.managedNodeMu.Lock()
	defer r.managedNodeMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete user server grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var username string
	var serverID int64
	var version int64
	if err := tx.QueryRowContext(ctx, `SELECT username, server_id, version FROM user_server_grants WHERE id = ?`, id).Scan(&username, &serverID, &version); errors.Is(err, sql.ErrNoRows) {
		return ErrUserServerGrantNotFound
	} else if err != nil {
		return fmt.Errorf("get grant before delete: %w", err)
	}
	if version != expectedVersion {
		return ErrManagedVersionConflict
	}
	// The handler removes the remote clients first. Once that succeeds, purge the
	// local managed graph atomically while leaving the audit record intact.
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_inbound_access_sources
WHERE source_type = ? AND source_id IN (
    SELECT id FROM user_node_selections WHERE grant_id = ?
)`, ManagedSourceSelection, id); err != nil {
		return fmt.Errorf("delete grant access sources: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_node_selection_usage WHERE grant_id = ?`, id); err != nil {
		return fmt.Errorf("delete grant usage: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_node_selections WHERE grant_id = ?`, id); err != nil {
		return fmt.Errorf("delete grant selections: %w", err)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM user_server_grants WHERE id = ? AND version = ?`, id, expectedVersion)
	if err != nil {
		return fmt.Errorf("delete user server grant: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrManagedVersionConflict
	}
	if err := appendManagedAccessAuditTx(ctx, tx, ManagedAccessAudit{
		Actor: actor, Action: "grant.deleted", EntityType: "server_grant", EntityID: id,
		Username: username, ServerID: serverID,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete user server grant: %w", err)
	}
	return nil
}
