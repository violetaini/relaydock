package storage

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
)

// Explicit bindings survive renames and equivalent endpoints. Legacy entries
// fall back to verified destination/credential matching, never display names.
func (r *TrafficRepository) ForwardNodeTargets(ctx context.Context) (map[int64]int64, error) {
	rows, err := r.db.QueryContext(ctx, `WITH forwards AS (
SELECT n.id, n.inbound_tag, LOWER(TRIM(n.protocol)) protocol,
CASE WHEN json_valid(n.clash_config) THEN n.clash_config ELSE '{}' END cfg,
CASE WHEN json_valid(d.inbound_json) THEN d.inbound_json ELSE '{}' END inbound
FROM nodes n JOIN remote_servers s ON s.name=n.original_server
JOIN remote_inbound_desired d ON d.server_id=s.id AND d.inbound_tag=n.inbound_tag
WHERE n.node_type='forwarded' AND d.desired_state!='deleted'
), sources AS (
SELECT id, LOWER(TRIM(protocol)) protocol,
CASE WHEN json_valid(clash_config) THEN clash_config ELSE '{}' END cfg FROM nodes
)
SELECT f.id,f.inbound_tag,s.id,f.cfg,s.cfg FROM forwards f JOIN sources s
ON s.id!=f.id AND s.protocol=f.protocol
AND LOWER(TRIM(json_extract(s.cfg,'$.server')))=LOWER(TRIM(json_extract(f.inbound,'$.settings.address')))
AND CAST(json_extract(s.cfg,'$.port') AS INTEGER)=CAST(json_extract(f.inbound,'$.settings.port') AS INTEGER)
WHERE LOWER(json_extract(f.inbound,'$.protocol')) IN ('tunnel','dokodemo-door','anydoor')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type match struct {
		ids  []int64
		hint int64
	}
	matches := map[int64]*match{}
	for rows.Next() {
		var id, target int64
		var tag, left, right string
		if err := rows.Scan(&id, &tag, &target, &left, &right); err != nil {
			return nil, err
		}
		var a, b map[string]any
		if json.Unmarshal([]byte(left), &a) != nil || json.Unmarshal([]byte(right), &b) != nil {
			continue
		}
		for _, k := range []string{"name", "server", "port", ManagedShadowsocksMultiUserMarker} {
			delete(a, k)
			delete(b, k)
		}
		if !reflect.DeepEqual(a, b) {
			continue
		}
		m := matches[id]
		if m == nil {
			m = &match{}
			matches[id] = m
			if strings.HasPrefix(tag, "anydoor-node-") {
				m.hint, _ = strconv.ParseInt(strings.TrimPrefix(tag, "anydoor-node-"), 10, 64)
			}
		}
		m.ids = append(m.ids, target)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := map[int64]int64{}
	for id, m := range matches {
		if len(m.ids) == 1 {
			result[id] = m.ids[0]
			continue
		}
		for _, target := range m.ids {
			if target == m.hint {
				result[id] = target
				break
			}
		}
	}
	rows.Close()
	explicit, err := r.db.QueryContext(ctx, `SELECT f.node_id,f.target_node_id FROM node_forward_targets f JOIN nodes n ON n.id=f.node_id WHERE n.node_type='forwarded'`)
	if err != nil {
		return nil, err
	}
	defer explicit.Close()
	for explicit.Next() {
		var id, target int64
		if err := explicit.Scan(&id, &target); err != nil {
			return nil, err
		}
		result[id] = target
	}
	return result, explicit.Err()
}
