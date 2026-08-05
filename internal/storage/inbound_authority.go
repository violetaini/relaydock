package storage

import (
	"context"
	"crypto/ecdh"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	DesiredInboundStateActive  = "active"
	DesiredInboundStateDeleted = "deleted"
)

var ErrDesiredInboundMutationChanged = errors.New("desired inbound mutation changed")

var errBackfillWireGuardIdentityDeferred = errors.New("WireGuard database node identity is unavailable until secret initialization")

// DesiredInbound is the durable control-plane intent for one Xray inbound.
// Deleted rows are tombstones and must not be removed or rebuilt from legacy
// inventory during startup migration.
type DesiredInbound struct {
	ServerID     int64           `json:"server_id"`
	InboundTag   string          `json:"inbound_tag"`
	MutationID   string          `json:"mutation_id"`
	InboundJSON  json.RawMessage `json:"inbound_json"`
	DesiredState string          `json:"desired_state"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

func (r *TrafficRepository) migrateRemoteInboundDesired() error {
	const schema = `
CREATE TABLE IF NOT EXISTS remote_inbound_desired (
    server_id INTEGER NOT NULL,
    inbound_tag TEXT NOT NULL,
    mutation_id TEXT NOT NULL DEFAULT '',
    inbound_json TEXT NOT NULL DEFAULT '{}',
    desired_state TEXT NOT NULL CHECK (desired_state IN ('active', 'deleted')),
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(server_id, inbound_tag),
    FOREIGN KEY(server_id) REFERENCES remote_servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remote_inbound_desired_active
    ON remote_inbound_desired(server_id, desired_state);
`
	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate remote inbound desired: %w", err)
	}

	// Legacy inventory is observation, not intent. Bootstrap normal proxy
	// inbounds only from persisted node bindings. Ownership alone is accepted
	// only for historical tunnel-only entries, which intentionally have no node.
	// Every definition still comes from the latest current snapshot. INSERT OR
	// IGNORE is essential: a deletion tombstone must survive every startup.
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin desired inbound backfill: %w", err)
	}
	defer tx.Rollback()

	type snapshot struct {
		serverID int64
		config   string
	}
	rows, err := tx.Query(`
SELECT s.server_id, s.config_json
FROM server_xray_config_snapshots s
JOIN (
    SELECT server_id, MAX(id) AS id
    FROM server_xray_config_snapshots
    WHERE status = 'current'
    GROUP BY server_id
) latest ON latest.id = s.id
ORDER BY s.server_id`)
	if err != nil {
		return fmt.Errorf("list current snapshots for desired inbound backfill: %w", err)
	}
	snapshots := make([]snapshot, 0)
	for rows.Next() {
		var current snapshot
		if err := rows.Scan(&current.serverID, &current.config); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan current snapshot for desired inbound backfill: %w", err)
		}
		snapshots = append(snapshots, current)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate current snapshots for desired inbound backfill: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close current snapshots for desired inbound backfill: %w", err)
	}

	for _, current := range snapshots {
		if _, err := backfillAuthorizedDesiredInbounds(context.Background(), tx, current.serverID, current.config, nil); err != nil {
			return fmt.Errorf("backfill desired inbounds for server %d: %w", current.serverID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit desired inbound backfill: %w", err)
	}
	return nil
}

type desiredInboundStore interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

func desiredInboundBackfillEvidence(ctx context.Context, store desiredInboundStore, serverID int64) (map[string]string, error) {
	rows, err := store.QueryContext(ctx, `
SELECT evidence.inbound_tag, evidence.mutation_id, evidence.priority
FROM (
    SELECT TRIM(COALESCE(n.inbound_tag, '')) AS inbound_tag,
           CASE
             WHEN TRIM(COALESCE(n.inbound_mutation_id, '')) != '' THEN TRIM(n.inbound_mutation_id)
             ELSE 'database-migration:' || s.id || ':' || TRIM(n.inbound_tag)
           END AS mutation_id,
           0 AS priority
    FROM nodes n
    JOIN remote_servers s ON s.name = TRIM(COALESCE(n.original_server, ''))
    WHERE s.id = ?
      AND TRIM(COALESCE(n.inbound_tag, '')) != 'tunnel-in'
    UNION ALL
    SELECT TRIM(inbound_tag) AS inbound_tag,
           TRIM(COALESCE(mutation_id, '')) AS mutation_id,
           1 AS priority
    FROM remote_inbound_ownership
    WHERE server_id = ?
      AND TRIM(inbound_tag) != 'tunnel-in'
      AND TRIM(inbound_tag) LIKE 'tunnel-%'
    UNION ALL
    SELECT 'tunnel-in' AS inbound_tag,
           CASE
             WHEN TRIM(COALESCE(o.mutation_id, '')) != '' THEN TRIM(o.mutation_id)
             ELSE 'database-migration:' || s.id || ':tunnel-in'
           END AS mutation_id,
           2 AS priority
    FROM remote_servers s
    LEFT JOIN remote_inbound_ownership o
      ON o.server_id = s.id AND TRIM(o.inbound_tag) = 'tunnel-in'
    WHERE s.id = ?
      AND COALESCE(s.steal_self, 0) = 1
      AND LOWER(TRIM(COALESCE(s.steal_mode, ''))) IN ('', 'tunnel')
) AS evidence
WHERE evidence.inbound_tag != ''
  AND NOT EXISTS (
      SELECT 1
      FROM remote_inbound_desired d
      WHERE d.server_id = ?
        AND d.inbound_tag = evidence.inbound_tag
        AND d.desired_state = 'deleted'
  )
ORDER BY evidence.priority, evidence.inbound_tag, evidence.mutation_id DESC`, serverID, serverID, serverID, serverID)
	if err != nil {
		return nil, fmt.Errorf("list desired inbound backfill evidence for server %d: %w", serverID, err)
	}
	defer rows.Close()

	evidence := make(map[string]string)
	for rows.Next() {
		var tag, mutationID string
		var priority int
		if err := rows.Scan(&tag, &mutationID, &priority); err != nil {
			return nil, fmt.Errorf("scan desired inbound backfill evidence for server %d: %w", serverID, err)
		}
		if _, exists := evidence[tag]; !exists {
			evidence[tag] = mutationID
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate desired inbound backfill evidence for server %d: %w", serverID, err)
	}
	return evidence, nil
}

// ListAuthorizedInboundTags returns legacy tags that the database permits to
// be adopted into desired state. It does not inspect Agent inventory or
// management-only resources. A deleted desired row always revokes adoption,
// even while the old node or ownership evidence still exists.
func (r *TrafficRepository) ListAuthorizedInboundTags(ctx context.Context, serverID int64) ([]string, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return []string{}, nil
	}
	evidence, err := desiredInboundBackfillEvidence(ctx, r.db, serverID)
	if err != nil {
		return nil, err
	}
	tags := make([]string, 0, len(evidence))
	for tag := range evidence {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, nil
}

// BackfillAuthorizedDesiredInbounds adopts full inbound definitions from a
// supplied Xray config. The config may come from a persisted snapshot or live
// Agent state, so upgrades can bootstrap even when no current snapshot exists.
// Existing active rows and deletion tombstones are preserved.
func (r *TrafficRepository) BackfillAuthorizedDesiredInbounds(ctx context.Context, serverID int64, configJSON string) (int, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return 0, errors.New("server id is required")
	}
	conn, err := r.beginImmediateTransaction(ctx)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = finishImmediateTransaction(context.Background(), conn, false)
		}
	}()

	count, err := backfillAuthorizedDesiredInbounds(ctx, conn, serverID, configJSON, r.openWireGuardPrivateKey)
	if err != nil {
		return 0, err
	}
	if err := finishImmediateTransaction(ctx, conn, true); err != nil {
		return 0, fmt.Errorf("commit authorized desired inbound backfill: %w", err)
	}
	committed = true
	return count, nil
}

// CompleteDeferredDesiredInboundBackfill reruns the latest durable snapshots
// after node-secret encryption is available. Startup migration cannot decrypt
// an existing WireGuard node identity yet, so it deliberately defers those
// listeners instead of trusting plaintext from a snapshot.
func (r *TrafficRepository) CompleteDeferredDesiredInboundBackfill(ctx context.Context) (int, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	type currentSnapshot struct {
		serverID int64
		config   string
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT s.server_id, s.config_json
FROM server_xray_config_snapshots s
JOIN (
    SELECT server_id, MAX(id) AS id
    FROM server_xray_config_snapshots
    WHERE status = 'current'
    GROUP BY server_id
) latest ON latest.id = s.id
ORDER BY s.server_id`)
	if err != nil {
		return 0, fmt.Errorf("list current snapshots for deferred desired inbound backfill: %w", err)
	}
	snapshots := make([]currentSnapshot, 0)
	for rows.Next() {
		var snapshot currentSnapshot
		if err := rows.Scan(&snapshot.serverID, &snapshot.config); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan current snapshot for deferred desired inbound backfill: %w", err)
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("iterate current snapshots for deferred desired inbound backfill: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close current snapshots for deferred desired inbound backfill: %w", err)
	}

	total := 0
	for _, snapshot := range snapshots {
		inserted, err := r.BackfillAuthorizedDesiredInbounds(ctx, snapshot.serverID, snapshot.config)
		if err != nil {
			return total, fmt.Errorf("complete deferred desired inbound backfill for server %d: %w", snapshot.serverID, err)
		}
		total += inserted
	}
	return total, nil
}

func backfillAuthorizedDesiredInbounds(
	ctx context.Context,
	store desiredInboundStore,
	serverID int64,
	configJSON string,
	openWireGuardPrivateKey func(int64, string) (string, error),
) (int, error) {
	evidence, err := desiredInboundBackfillEvidence(ctx, store, serverID)
	if err != nil {
		return 0, err
	}
	if len(evidence) == 0 {
		return 0, nil
	}
	existingRows, err := store.QueryContext(ctx, `
SELECT inbound_tag
FROM remote_inbound_desired
WHERE server_id = ?`, serverID)
	if err != nil {
		return 0, fmt.Errorf("list existing desired inbounds for server %d: %w", serverID, err)
	}
	for existingRows.Next() {
		var tag string
		if err := existingRows.Scan(&tag); err != nil {
			_ = existingRows.Close()
			return 0, fmt.Errorf("scan existing desired inbound for server %d: %w", serverID, err)
		}
		delete(evidence, strings.TrimSpace(tag))
	}
	if err := existingRows.Err(); err != nil {
		_ = existingRows.Close()
		return 0, fmt.Errorf("iterate existing desired inbounds for server %d: %w", serverID, err)
	}
	if err := existingRows.Close(); err != nil {
		return 0, fmt.Errorf("close existing desired inbounds for server %d: %w", serverID, err)
	}
	if len(evidence) == 0 {
		return 0, nil
	}
	inbounds, err := desiredInboundsFromSnapshot(configJSON)
	if err != nil {
		return 0, fmt.Errorf("parse authorized desired inbound source: %w", err)
	}
	inserted := 0
	for tag, mutationID := range evidence {
		inboundJSON, ok := inbounds[tag]
		if !ok || !completeBackfilledInboundDefinition(inboundJSON) {
			continue
		}
		inboundJSON, err = sanitizeBackfilledInboundCredentials(
			ctx, store, serverID, tag, inboundJSON, openWireGuardPrivateKey,
		)
		if err != nil {
			if errors.Is(err, errBackfillWireGuardIdentityDeferred) {
				continue
			}
			return 0, fmt.Errorf("sanitize authorized desired inbound %q: %w", tag, err)
		}
		result, err := store.ExecContext(ctx, `
INSERT OR IGNORE INTO remote_inbound_desired
    (server_id, inbound_tag, mutation_id, inbound_json, desired_state, updated_at)
VALUES (?, ?, ?, ?, 'active', CURRENT_TIMESTAMP)`, serverID, tag, mutationID, string(inboundJSON))
		if err != nil {
			return 0, fmt.Errorf("backfill authorized desired inbound %q: %w", tag, err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("read authorized desired inbound insert count for %q: %w", tag, err)
		}
		inserted += int(count)
	}
	return inserted, nil
}

func completeBackfilledInboundDefinition(raw json.RawMessage) bool {
	var inbound map[string]interface{}
	if json.Unmarshal(raw, &inbound) != nil || strings.TrimSpace(backfillCredentialString(inbound, "tag")) == "" ||
		strings.TrimSpace(backfillCredentialString(inbound, "protocol")) == "" {
		return false
	}
	if _, ok := inbound["settings"].(map[string]interface{}); !ok {
		return false
	}
	switch port := inbound["port"].(type) {
	case float64:
		return port > 0
	case json.Number:
		parsed, err := port.Int64()
		return err == nil && parsed > 0
	case int:
		return port > 0
	case int64:
		return port > 0
	default:
		return false
	}
}

// sanitizeBackfilledInboundCredentials separates the durable listener shape
// from mutable user access. Legacy snapshots and live Agent inventory may
// contain expired, revoked, or injected clients. Only a credential whose
// connection secret is also present on an enabled physical node is retained as
// the listener's creation-time owner; all other users are rebuilt later from
// user_inbound_configs and currently effective grants/packages.
func sanitizeBackfilledInboundCredentials(
	ctx context.Context,
	store desiredInboundStore,
	serverID int64,
	inboundTag string,
	raw json.RawMessage,
	openWireGuardPrivateKey func(int64, string) (string, error),
) (json.RawMessage, error) {
	rows, err := store.QueryContext(ctx, `
SELECT n.id, COALESCE(n.protocol, ''), COALESCE(n.clash_config, ''),
       COALESCE(ns.kind, ''), COALESCE(ns.ciphertext, '')
FROM nodes n
JOIN remote_servers s ON s.name = TRIM(COALESCE(n.original_server, ''))
LEFT JOIN node_secrets ns ON ns.node_id = n.id
WHERE s.id = ?
  AND TRIM(COALESCE(n.inbound_tag, '')) = ?
  AND COALESCE(n.enabled, 1) = 1
  AND LOWER(TRIM(COALESCE(n.node_type, 'physical'))) = 'physical'`, serverID, inboundTag)
	if err != nil {
		return nil, err
	}
	trusted := make([]backfillTrustedNode, 0)
	for rows.Next() {
		var nodeID int64
		var protocol, clashJSON, secretKind, secretCiphertext string
		if err := rows.Scan(&nodeID, &protocol, &clashJSON, &secretKind, &secretCiphertext); err != nil {
			_ = rows.Close()
			return nil, err
		}
		var clash map[string]interface{}
		if json.Unmarshal([]byte(clashJSON), &clash) == nil && clash != nil {
			node := backfillTrustedNode{protocol: protocol, clash: clash}
			if canonicalBackfillProtocol(protocol) == "wireguard" {
				if secretCiphertext != "" && secretKind != wireGuardPrivateKeySecretKind {
					_ = rows.Close()
					return nil, fmt.Errorf("WireGuard database node %d has an invalid secret kind", nodeID)
				}
				privateKey := backfillCredentialString(clash, "private-key")
				if privateKey == "" && secretCiphertext != "" {
					if openWireGuardPrivateKey == nil {
						node.wireGuardIdentityDeferred = true
					} else {
						privateKey, err = openWireGuardPrivateKey(nodeID, secretCiphertext)
						if err != nil {
							_ = rows.Close()
							return nil, fmt.Errorf("open WireGuard database node %d identity: %w", nodeID, err)
						}
					}
				}
				if privateKey != "" {
					node.wireGuardClientPublicKey, err = backfillWireGuardPublicKey(privateKey)
					if err != nil {
						_ = rows.Close()
						return nil, fmt.Errorf("derive WireGuard database node %d public key: %w", nodeID, err)
					}
				}
			}
			trusted = append(trusted, node)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	var inbound map[string]interface{}
	if err := json.Unmarshal(raw, &inbound); err != nil {
		return nil, err
	}
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		return append(json.RawMessage(nil), raw...), nil
	}
	protocol := canonicalBackfillProtocol(backfillCredentialString(inbound, "protocol"))
	if protocol == "shadowsocks" {
		masterPassword, err := backfilledShadowsocks2022MasterPassword(settings, trusted)
		if err != nil {
			return nil, err
		}
		if masterPassword != "" {
			settings["password"] = masterPassword
		}
	}
	if protocol == "wireguard" {
		if err := rebuildBackfilledWireGuardPeers(ctx, store, serverID, inboundTag, inbound, settings, trusted); err != nil {
			return nil, err
		}
		normalized, err := json.Marshal(inbound)
		if err != nil {
			return nil, err
		}
		return normalized, nil
	}
	for _, key := range []string{"clients", "users", "accounts"} {
		value, exists := settings[key]
		if !exists {
			continue
		}
		items, ok := value.([]interface{})
		if !ok {
			settings[key] = []interface{}{}
			continue
		}
		filtered := make([]interface{}, 0, len(items))
		for _, item := range items {
			if backfilledCredentialMatchesNode(protocol, settings, item, trusted) {
				filtered = append(filtered, item)
			}
		}
		settings[key] = filtered
	}
	normalized, err := json.Marshal(inbound)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

type backfillTrustedNode struct {
	protocol                  string
	clash                     map[string]interface{}
	wireGuardClientPublicKey  string
	wireGuardIdentityDeferred bool
}

func canonicalBackfillProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ss":
		return "shadowsocks"
	case "socks5":
		return "socks"
	case "hysteria", "hy2":
		return "hysteria2"
	case "wg":
		return "wireguard"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

func backfilledCredentialMatchesNode(protocol string, settings map[string]interface{}, credential interface{}, nodes []backfillTrustedNode) bool {
	item, ok := credential.(map[string]interface{})
	if !ok {
		return false
	}
	for _, node := range nodes {
		if canonicalBackfillProtocol(node.protocol) != protocol {
			continue
		}
		if nodeType := canonicalBackfillProtocol(backfillCredentialString(node.clash, "type")); nodeType != "" && nodeType != protocol {
			continue
		}
		switch protocol {
		case "vless", "vmess":
			id := backfillCredentialString(item, "id")
			if id != "" && id == backfillCredentialString(node.clash, "uuid") {
				return true
			}
		case "trojan", "anytls":
			password := backfillCredentialString(item, "password")
			if password != "" && password == backfillCredentialString(node.clash, "password") {
				return true
			}
		case "socks", "http":
			user := backfillCredentialString(item, "user")
			password := backfillCredentialString(item, "pass")
			if user != "" && password != "" &&
				user == backfillCredentialString(node.clash, "username") &&
				password == backfillCredentialString(node.clash, "password") {
				return true
			}
		case "hysteria2":
			auth := backfillCredentialString(item, "auth")
			if auth != "" && auth == backfillCredentialString(node.clash, "password") {
				return true
			}
		case "snell":
			psk := backfillCredentialString(item, "psk")
			if psk != "" && psk == backfillCredentialString(node.clash, "psk") {
				return true
			}
		case "shadowsocks":
			method := strings.ToLower(strings.TrimSpace(backfillCredentialString(settings, "method")))
			if !strings.HasPrefix(method, "2022-") {
				continue
			}
			nodeMethod := strings.ToLower(strings.TrimSpace(backfillCredentialString(node.clash, "cipher")))
			if nodeMethod == "" {
				nodeMethod = strings.ToLower(strings.TrimSpace(backfillCredentialString(node.clash, "method")))
			}
			if nodeMethod != method || !strings.HasPrefix(nodeMethod, "2022-") {
				continue
			}
			password := backfillCredentialString(item, "password")
			nodePassword := backfillCredentialString(node.clash, "password")
			if password == "" || nodePassword == "" {
				continue
			}
			if password == nodePassword {
				return true
			}
			separator := strings.LastIndex(nodePassword, ":")
			if separator > 0 && separator < len(nodePassword)-1 && nodePassword[separator+1:] == password {
				return true
			}
		}
	}
	return false
}

func backfilledShadowsocks2022MasterPassword(settings map[string]interface{}, nodes []backfillTrustedNode) (string, error) {
	method := strings.ToLower(strings.TrimSpace(backfillCredentialString(settings, "method")))
	if !strings.HasPrefix(method, "2022-") {
		return "", nil
	}
	masterPassword := ""
	for _, node := range nodes {
		if canonicalBackfillProtocol(node.protocol) != "shadowsocks" {
			continue
		}
		if nodeType := canonicalBackfillProtocol(backfillCredentialString(node.clash, "type")); nodeType != "" && nodeType != "shadowsocks" {
			continue
		}
		nodeMethod := strings.ToLower(strings.TrimSpace(backfillCredentialString(node.clash, "cipher")))
		if nodeMethod == "" {
			nodeMethod = strings.ToLower(strings.TrimSpace(backfillCredentialString(node.clash, "method")))
		}
		if nodeMethod != method {
			continue
		}
		nodePassword := backfillCredentialString(node.clash, "password")
		if nodePassword == "" {
			continue
		}
		candidate := nodePassword
		if separator := strings.IndexByte(nodePassword, ':'); separator > 0 {
			candidate = nodePassword[:separator]
		}
		if masterPassword != "" && masterPassword != candidate {
			return "", errors.New("physical Shadowsocks 2022 nodes disagree on the listener master password")
		}
		masterPassword = candidate
	}
	if masterPassword == "" {
		return "", errors.New("Shadowsocks 2022 inbound lacks authoritative physical-node password metadata")
	}
	return masterPassword, nil
}

type backfillWireGuardMetadata struct {
	ServerPublicKey string                  `json:"server_public_key"`
	ServerAddresses []string                `json:"server_addresses"`
	MTU             int                     `json:"mtu"`
	Peers           []backfillWireGuardPeer `json:"peers"`
}

type backfillWireGuardPeer struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	KeepAlive  int      `json:"keep_alive"`
}

func canonicalBackfillWireGuardKey(value string) (string, error) {
	decoded, err := decodeStoredWireGuardPrivateKey(value)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

func backfillWireGuardPublicKey(privateValue string) (string, error) {
	decoded, err := decodeStoredWireGuardPrivateKey(privateValue)
	if err != nil {
		return "", err
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()), nil
}

func backfillNumericInt(value interface{}) (int, bool) {
	switch current := value.(type) {
	case float64:
		integer := int(current)
		return integer, current == float64(integer)
	case json.Number:
		integer, err := current.Int64()
		return int(integer), err == nil
	case int:
		return current, true
	case int64:
		return int(current), true
	default:
		return 0, false
	}
}

func canonicalBackfillPrefix(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.String(), prefix.Addr().String(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", "", err
	}
	bits := 128
	if address.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(address, bits).String(), address.String(), nil
}

func backfillNodeWireGuardIdentities(nodes []backfillTrustedNode, serverPublicKey string, resourcePort int) (map[string]map[string]struct{}, error) {
	identities := make(map[string]map[string]struct{}, len(nodes))
	addressOwners := make(map[string]string)
	for _, node := range nodes {
		if canonicalBackfillProtocol(node.protocol) != "wireguard" {
			continue
		}
		if nodeType := canonicalBackfillProtocol(backfillCredentialString(node.clash, "type")); nodeType != "" && nodeType != "wireguard" {
			continue
		}
		nodeServerKey, err := canonicalBackfillWireGuardKey(backfillCredentialString(node.clash, "public-key"))
		if err != nil || nodeServerKey != serverPublicKey {
			continue
		}
		if nodePort, ok := backfillNumericInt(node.clash["port"]); !ok || nodePort != resourcePort {
			continue
		}
		if node.wireGuardIdentityDeferred {
			return nil, errBackfillWireGuardIdentityDeferred
		}
		clientPublicKey := node.wireGuardClientPublicKey
		if clientPublicKey == "" {
			return nil, errors.New("WireGuard physical database node lacks a verifiable client identity")
		}
		addresses := make(map[string]struct{})
		for _, key := range []string{"ip", "ipv6"} {
			value := backfillCredentialString(node.clash, key)
			if value == "" {
				continue
			}
			_, address, err := canonicalBackfillPrefix(value)
			if err != nil {
				return nil, fmt.Errorf("validate WireGuard database node address: %w", err)
			}
			if owner, duplicate := addressOwners[address]; duplicate && owner != clientPublicKey {
				return nil, errors.New("WireGuard physical database nodes claim the same address with different client keys")
			}
			addressOwners[address] = clientPublicKey
			addresses[address] = struct{}{}
		}
		if len(addresses) == 0 {
			return nil, errors.New("WireGuard physical database node has no client address")
		}
		if identities[clientPublicKey] == nil {
			identities[clientPublicKey] = make(map[string]struct{}, len(addresses))
		}
		for address := range addresses {
			identities[clientPublicKey][address] = struct{}{}
		}
	}
	if len(identities) == 0 {
		return nil, errors.New("WireGuard inbound lacks an enabled physical database node matching its server key and port")
	}
	return identities, nil
}

func rebuildBackfilledWireGuardPeers(
	ctx context.Context,
	store desiredInboundStore,
	serverID int64,
	inboundTag string,
	inbound map[string]interface{},
	settings map[string]interface{},
	nodes []backfillTrustedNode,
) error {
	rows, err := store.QueryContext(ctx, `
SELECT id, COALESCE(protocol, ''), endpoint_port, public_metadata_json
FROM managed_inbound_resources
WHERE server_id = ? AND inbound_tag = ?`, serverID, inboundTag)
	if err != nil {
		return err
	}
	var resourceID int64
	var resourceProtocol, metadataJSON string
	var resourcePort int
	if rows.Next() {
		if err := rows.Scan(&resourceID, &resourceProtocol, &resourcePort, &metadataJSON); err != nil {
			_ = rows.Close()
			return err
		}
		if rows.Next() {
			_ = rows.Close()
			return errors.New("multiple WireGuard managed resources matched the inbound")
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if resourceID <= 0 || canonicalBackfillProtocol(resourceProtocol) != "wireguard" {
		return errors.New("WireGuard inbound lacks authoritative managed-resource metadata")
	}
	var metadata backfillWireGuardMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return fmt.Errorf("decode WireGuard managed-resource metadata: %w", err)
	}
	serverPublicKey, err := canonicalBackfillWireGuardKey(metadata.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("validate WireGuard managed server public key: %w", err)
	}
	nodeIdentities, err := backfillNodeWireGuardIdentities(nodes, serverPublicKey, resourcePort)
	if err != nil {
		return err
	}
	port, ok := backfillNumericInt(inbound["port"])
	if !ok || port != resourcePort {
		return errors.New("WireGuard inbound port does not match managed-resource metadata")
	}
	derivedPublicKey, err := backfillWireGuardPublicKey(backfillCredentialString(settings, "secretKey"))
	if err != nil || derivedPublicKey != serverPublicKey {
		return errors.New("WireGuard inbound server key does not match managed-resource metadata")
	}
	if metadata.MTU != 0 && (metadata.MTU < 576 || metadata.MTU > 9000) {
		return errors.New("WireGuard managed-resource MTU is invalid")
	}

	probeKeys := make(map[string]map[string]struct{})
	probeRows, err := store.QueryContext(ctx, `
SELECT public_key, addresses_json
FROM wireguard_probe_peers
WHERE resource_id = ? AND state IN ('pending', 'active')`, resourceID)
	if err != nil {
		return err
	}
	for probeRows.Next() {
		var publicKey, addressesJSON string
		if err := probeRows.Scan(&publicKey, &addressesJSON); err != nil {
			_ = probeRows.Close()
			return err
		}
		canonicalKey, keyErr := canonicalBackfillWireGuardKey(publicKey)
		if keyErr != nil {
			_ = probeRows.Close()
			return keyErr
		}
		var addresses []string
		if err := json.Unmarshal([]byte(addressesJSON), &addresses); err != nil {
			_ = probeRows.Close()
			return err
		}
		probeKeys[canonicalKey] = make(map[string]struct{}, len(addresses))
		for _, value := range addresses {
			prefix, _, prefixErr := canonicalBackfillPrefix(value)
			if prefixErr != nil {
				_ = probeRows.Close()
				return prefixErr
			}
			probeKeys[canonicalKey][prefix] = struct{}{}
		}
	}
	if err := probeRows.Err(); err != nil {
		_ = probeRows.Close()
		return err
	}
	if err := probeRows.Close(); err != nil {
		return err
	}

	rebuiltPeers := make([]interface{}, 0, len(metadata.Peers))
	seenKeys := make(map[string]struct{}, len(metadata.Peers))
	matchedNodeKeys := make(map[string]struct{}, len(nodeIdentities))
	matchedProbeKeys := make(map[string]struct{}, len(probeKeys))
	for _, peer := range metadata.Peers {
		publicKey, keyErr := canonicalBackfillWireGuardKey(peer.PublicKey)
		if keyErr != nil || peer.KeepAlive < 0 || peer.KeepAlive > 65535 {
			return errors.New("WireGuard managed-resource peer metadata is invalid")
		}
		if _, duplicate := seenKeys[publicKey]; duplicate {
			return errors.New("WireGuard managed-resource contains duplicate peer keys")
		}
		seenKeys[publicKey] = struct{}{}
		allowedIPs := make([]string, 0, len(peer.AllowedIPs))
		allowedAddresses := make(map[string]struct{}, len(peer.AllowedIPs))
		seenAllowedIPs := make(map[string]struct{}, len(peer.AllowedIPs))
		for _, value := range peer.AllowedIPs {
			prefix, address, prefixErr := canonicalBackfillPrefix(value)
			if prefixErr != nil {
				return fmt.Errorf("validate WireGuard managed peer address: %w", prefixErr)
			}
			if _, duplicate := seenAllowedIPs[prefix]; duplicate {
				return errors.New("WireGuard managed-resource peer contains duplicate allowed IPs")
			}
			seenAllowedIPs[prefix] = struct{}{}
			allowedIPs = append(allowedIPs, prefix)
			allowedAddresses[address] = struct{}{}
		}
		matchesNode := false
		if nodeAddresses, exists := nodeIdentities[publicKey]; exists {
			matchesNode = len(nodeAddresses) > 0
			for address := range nodeAddresses {
				if _, exists := allowedAddresses[address]; !exists {
					matchesNode = false
					break
				}
			}
			if matchesNode {
				matchedNodeKeys[publicKey] = struct{}{}
			}
		}
		matchesProbe := false
		if expected, exists := probeKeys[publicKey]; exists && len(expected) == len(allowedIPs) {
			matchesProbe = true
			for _, prefix := range allowedIPs {
				if _, exists := expected[prefix]; !exists {
					matchesProbe = false
					break
				}
			}
			if matchesProbe {
				matchedProbeKeys[publicKey] = struct{}{}
			}
		}
		if !matchesNode && !matchesProbe {
			continue
		}
		sort.Strings(allowedIPs)
		rebuiltPeers = append(rebuiltPeers, map[string]interface{}{
			"publicKey": publicKey, "allowedIPs": allowedIPs, "keepAlive": peer.KeepAlive,
		})
	}
	if len(rebuiltPeers) == 0 || len(matchedNodeKeys) != len(nodeIdentities) {
		return errors.New("WireGuard managed-resource does not contain every physical database node peer")
	}
	if len(matchedProbeKeys) != len(probeKeys) {
		return errors.New("WireGuard managed-resource does not contain the database probe peer")
	}
	serverAddresses := make([]interface{}, 0, len(metadata.ServerAddresses))
	seenServerAddresses := make(map[string]struct{}, len(metadata.ServerAddresses))
	for _, value := range metadata.ServerAddresses {
		prefix, _, prefixErr := canonicalBackfillPrefix(value)
		if prefixErr != nil {
			return fmt.Errorf("validate WireGuard server address: %w", prefixErr)
		}
		parsedPrefix, _ := netip.ParsePrefix(prefix)
		if parsedPrefix.Bits() != parsedPrefix.Addr().BitLen() {
			return errors.New("WireGuard managed-resource server address must be a host prefix")
		}
		if _, duplicate := seenServerAddresses[prefix]; duplicate {
			return errors.New("WireGuard managed-resource contains duplicate server addresses")
		}
		seenServerAddresses[prefix] = struct{}{}
		serverAddresses = append(serverAddresses, prefix)
	}
	if len(serverAddresses) == 0 {
		return errors.New("WireGuard managed-resource has no server address")
	}
	settings["address"] = serverAddresses
	settings["mtu"] = metadata.MTU
	settings["peers"] = rebuiltPeers
	delete(settings, "clients")
	delete(settings, "users")
	delete(settings, "accounts")
	return nil
}

func backfillCredentialString(value map[string]interface{}, key string) string {
	raw, exists := value[key]
	if !exists || raw == nil {
		return ""
	}
	if text, ok := raw.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func desiredInboundsFromSnapshot(configJSON string) (map[string]json.RawMessage, error) {
	var config struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, err
	}
	result := make(map[string]json.RawMessage, len(config.Inbounds))
	for _, raw := range config.Inbounds {
		var header struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			return nil, fmt.Errorf("decode inbound: %w", err)
		}
		tag := strings.TrimSpace(header.Tag)
		if tag != "" {
			result[tag] = append(json.RawMessage(nil), raw...)
		}
	}
	return result, nil
}

func normalizeActiveDesiredInbound(serverID int64, inboundTag, mutationID string, inboundJSON json.RawMessage) (string, string, json.RawMessage, error) {
	inboundTag = strings.TrimSpace(inboundTag)
	mutationID = strings.TrimSpace(mutationID)
	if serverID <= 0 || inboundTag == "" {
		return "", "", nil, errors.New("server id and inbound tag are required")
	}
	var inbound map[string]interface{}
	if err := json.Unmarshal(inboundJSON, &inbound); err != nil {
		return "", "", nil, fmt.Errorf("inbound JSON must be a JSON object: %w", err)
	}
	storedTag, _ := inbound["tag"].(string)
	if strings.TrimSpace(storedTag) != inboundTag {
		return "", "", nil, errors.New("inbound JSON tag does not match inbound tag")
	}
	normalized, err := json.Marshal(inbound)
	if err != nil {
		return "", "", nil, fmt.Errorf("normalize inbound JSON: %w", err)
	}
	if !completeBackfilledInboundDefinition(normalized) {
		return "", "", nil, errors.New("inbound JSON must include tag, protocol, settings, and a valid port")
	}
	return inboundTag, mutationID, normalized, nil
}

// UpsertActiveDesiredInbound records the full desired definition before it is
// applied to an Agent. A new mutation ID explicitly reactivates a tombstone;
// replaying the deleted generation cannot resurrect it.
func (r *TrafficRepository) UpsertActiveDesiredInbound(ctx context.Context, serverID int64, inboundTag, mutationID string, inboundJSON json.RawMessage) (*DesiredInbound, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	inboundTag, mutationID, inboundJSON, err := normalizeActiveDesiredInbound(serverID, inboundTag, mutationID, inboundJSON)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	result, err := r.db.ExecContext(ctx, `
INSERT INTO remote_inbound_desired
    (server_id, inbound_tag, mutation_id, inbound_json, desired_state, updated_at)
VALUES (?, ?, ?, ?, 'active', ?)
ON CONFLICT(server_id, inbound_tag) DO UPDATE SET
    mutation_id = excluded.mutation_id,
    inbound_json = excluded.inbound_json,
    desired_state = excluded.desired_state,
    updated_at = excluded.updated_at
WHERE remote_inbound_desired.desired_state != 'deleted'
   OR (excluded.mutation_id != ''
       AND remote_inbound_desired.mutation_id != excluded.mutation_id)`,
		serverID, inboundTag, mutationID, string(inboundJSON), now)
	if err != nil {
		return nil, fmt.Errorf("upsert active desired inbound: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read active desired inbound update count: %w", err)
	}
	if count == 0 {
		return nil, ErrDesiredInboundMutationChanged
	}
	return r.GetDesiredInbound(ctx, serverID, inboundTag)
}

// MarkDesiredInboundDeleted retains a tombstone and the last full definition.
// A stale generation cannot delete an inbound that has since been recreated.
func (r *TrafficRepository) MarkDesiredInboundDeleted(ctx context.Context, serverID int64, inboundTag, mutationID string) (*DesiredInbound, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	mutationID = strings.TrimSpace(mutationID)
	if serverID <= 0 || inboundTag == "" {
		return nil, errors.New("server id and inbound tag are required")
	}
	now := time.Now().UTC()
	result, err := r.db.ExecContext(ctx, `
INSERT INTO remote_inbound_desired
    (server_id, inbound_tag, mutation_id, inbound_json, desired_state, updated_at)
VALUES (?, ?, ?, '{}', 'deleted', ?)
ON CONFLICT(server_id, inbound_tag) DO UPDATE SET
    mutation_id = CASE
        WHEN excluded.mutation_id != '' THEN excluded.mutation_id
        ELSE remote_inbound_desired.mutation_id
    END,
    desired_state = 'deleted',
    updated_at = excluded.updated_at
WHERE remote_inbound_desired.mutation_id = ''
   OR remote_inbound_desired.mutation_id = excluded.mutation_id`, serverID, inboundTag, mutationID, now)
	if err != nil {
		return nil, fmt.Errorf("mark desired inbound deleted: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read deleted desired inbound update count: %w", err)
	}
	if count == 0 {
		return nil, ErrDesiredInboundMutationChanged
	}
	return r.GetDesiredInbound(ctx, serverID, inboundTag)
}

func (r *TrafficRepository) ListActiveDesiredInbounds(ctx context.Context, serverID int64) ([]DesiredInbound, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if serverID <= 0 {
		return []DesiredInbound{}, nil
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT server_id, inbound_tag, mutation_id, inbound_json, desired_state, updated_at
FROM remote_inbound_desired
WHERE server_id = ? AND desired_state = 'active'
ORDER BY inbound_tag COLLATE BINARY`, serverID)
	if err != nil {
		return nil, fmt.Errorf("list active desired inbounds: %w", err)
	}
	defer rows.Close()

	inbounds := make([]DesiredInbound, 0)
	for rows.Next() {
		inbound, err := scanDesiredInbound(rows)
		if err != nil {
			return nil, fmt.Errorf("scan active desired inbound: %w", err)
		}
		inbounds = append(inbounds, *inbound)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active desired inbounds: %w", err)
	}
	return inbounds, nil
}

func (r *TrafficRepository) GetDesiredInbound(ctx context.Context, serverID int64, inboundTag string) (*DesiredInbound, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	if serverID <= 0 || inboundTag == "" {
		return nil, nil
	}
	inbound, err := scanDesiredInbound(r.db.QueryRowContext(ctx, `
SELECT server_id, inbound_tag, mutation_id, inbound_json, desired_state, updated_at
FROM remote_inbound_desired
WHERE server_id = ? AND inbound_tag = ?`, serverID, inboundTag))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get desired inbound: %w", err)
	}
	return inbound, nil
}

type desiredInboundScanner interface {
	Scan(dest ...interface{}) error
}

func scanDesiredInbound(scanner desiredInboundScanner) (*DesiredInbound, error) {
	var inbound DesiredInbound
	var inboundJSON string
	if err := scanner.Scan(
		&inbound.ServerID,
		&inbound.InboundTag,
		&inbound.MutationID,
		&inboundJSON,
		&inbound.DesiredState,
		&inbound.UpdatedAt,
	); err != nil {
		return nil, err
	}
	inbound.InboundJSON = json.RawMessage(inboundJSON)
	return &inbound, nil
}
