package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type managedWireGuardProvenanceQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const managedWireGuardProvenanceSelect = `
SELECT d.inbound_json, r.inbound_tag
FROM nodes n
JOIN remote_servers s
  ON s.name = TRIM(COALESCE(n.original_server, ''))
 AND LOWER(TRIM(COALESCE(s.xray_mode, 'external'))) = 'embedded'
JOIN managed_inbound_resources r
  ON r.server_id = s.id
 AND r.inbound_tag = TRIM(COALESCE(n.inbound_tag, ''))
 AND LOWER(TRIM(COALESCE(r.protocol, ''))) = 'wireguard'
JOIN remote_inbound_desired d
  ON d.server_id = s.id
 AND d.inbound_tag = r.inbound_tag
 AND d.desired_state = 'active'
JOIN remote_inbound_ownership o
  ON o.server_id = s.id
 AND o.inbound_tag = r.inbound_tag
JOIN wireguard_probe_peers p
  ON p.resource_id = r.id
 AND p.state = '__PROBE_STATE__'
WHERE n.enabled = 1
  AND LOWER(TRIM(COALESCE(n.protocol, ''))) = 'wireguard'
  AND LOWER(TRIM(COALESCE(n.node_type, 'physical'))) = 'physical'
  AND TRIM(COALESCE(n.inbound_tag, '')) != ''
  AND TRIM(COALESCE(n.inbound_mutation_id, '')) LIKE 'managed-wireguard:%'
  AND TRIM(COALESCE(r.mutation_id, '')) = TRIM(n.inbound_mutation_id)
  AND TRIM(COALESCE(d.mutation_id, '')) = TRIM(n.inbound_mutation_id)
  AND TRIM(COALESCE(o.mutation_id, '')) = TRIM(n.inbound_mutation_id)`

func managedWireGuardProvenanceValid(
	ctx context.Context,
	q managedWireGuardProvenanceQueryer,
	probeStateSQL string,
	where string,
	args ...any,
) (bool, error) {
	var raw, relationalTag string
	query := strings.Replace(managedWireGuardProvenanceSelect, `p.state = '__PROBE_STATE__'`, probeStateSQL, 1)
	err := q.QueryRowContext(ctx, query+where+` LIMIT 1`, args...).Scan(&raw, &relationalTag)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify managed WireGuard provenance: %w", err)
	}
	var inbound map[string]any
	if err := json.Unmarshal([]byte(raw), &inbound); err != nil {
		return false, fmt.Errorf("decode managed WireGuard desired inbound: %w", err)
	}
	protocol, _ := inbound["protocol"].(string)
	tag, _ := inbound["tag"].(string)
	return strings.EqualFold(strings.TrimSpace(protocol), "wireguard") &&
		strings.TrimSpace(tag) == strings.TrimSpace(relationalTag), nil
}

func managedWireGuardNodeProvisionable(
	ctx context.Context,
	q managedWireGuardProvenanceQueryer,
	nodeID int64,
) (bool, error) {
	return managedWireGuardNodeProvisionableWithProbeState(ctx, q, nodeID, `p.state = 'active'`)
}

func managedWireGuardNodeProvisionableWithProbeState(
	ctx context.Context,
	q managedWireGuardProvenanceQueryer,
	nodeID int64,
	probeStateSQL string,
) (bool, error) {
	if nodeID <= 0 {
		return false, nil
	}
	return managedWireGuardProvenanceValid(ctx, q, probeStateSQL, ` AND n.id = ?`, nodeID)
}

// ManagedWireGuardNodeProvisionable proves that a physical WireGuard node was
// created by the panel and still belongs to the same live managed generation.
func (r *TrafficRepository) ManagedWireGuardNodeProvisionable(ctx context.Context, nodeID int64) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	return managedWireGuardNodeProvisionable(ctx, r.db, nodeID)
}

// ManagedWireGuardNodeAuthorityProvisionable accepts a pending probe only for
// the database-authority transaction that publishes policy before restoring
// the probe and authorized peers. It still authenticates the exact node and
// managed generation, so a historical node sharing the same coordinates
// cannot borrow another node's provenance.
func (r *TrafficRepository) ManagedWireGuardNodeAuthorityProvisionable(ctx context.Context, nodeID int64) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	return managedWireGuardNodeProvisionableWithProbeState(
		ctx, r.db, nodeID, `p.state IN ('active', 'pending')`,
	)
}

// ManagedWireGuardInboundProvisionable is the coordinate form used at the
// final credential publication boundary. It requires at least one current
// physical node carrying the same fully authenticated managed generation.
func (r *TrafficRepository) ManagedWireGuardInboundProvisionable(ctx context.Context, serverID int64, inboundTag string) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	if serverID <= 0 || inboundTag == "" {
		return false, nil
	}
	return managedWireGuardProvenanceValid(ctx, r.db, `p.state = 'active'`,
		` AND s.id = ? AND n.inbound_tag = ?`, serverID, inboundTag)
}

// ManagedWireGuardInboundAuthorityProvisionable also accepts a pending probe.
// Database-authority reconciliation publishes the limiter mapping and the
// probe/user peers atomically, then marks that probe active only after the
// Agent acknowledges the inbound mutation.
func (r *TrafficRepository) ManagedWireGuardInboundAuthorityProvisionable(ctx context.Context, serverID int64, inboundTag string) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	if serverID <= 0 || inboundTag == "" {
		return false, nil
	}
	return managedWireGuardProvenanceValid(ctx, r.db, `p.state IN ('active', 'pending')`,
		` AND s.id = ? AND n.inbound_tag = ?`, serverID, inboundTag)
}
