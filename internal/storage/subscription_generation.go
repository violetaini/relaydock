package storage

import (
	"context"
	"encoding/json"
	"time"
)

// SubscriptionGeneration stores the recipe, not a one-time copy of its nodes.
// Existing subscriptions with nil Generation retain their historical behavior.
type SubscriptionGeneration struct {
	Kind       string                 `json:"kind"`
	SourceIDs  []int64                `json:"source_ids,omitempty"`
	Processing SubscriptionProcessing `json:"processing"`
	Outputs    []SubscriptionOutput   `json:"outputs"`
}

type SubscriptionProcessing struct {
	Deduplicate   bool     `json:"deduplicate"`
	RemoveDead    bool     `json:"remove_dead"`
	Include       string   `json:"include,omitempty"`
	Exclude       string   `json:"exclude,omitempty"`
	ExcludeTypes  []string `json:"exclude_types,omitempty"`
	Sort          string   `json:"sort,omitempty"`
	SortDirection string   `json:"sort_direction,omitempty"`
	CustomOrder   []string `json:"custom_order,omitempty"`
}

type SubscriptionOutput struct {
	Client           string   `json:"client"`
	Mode             string   `json:"mode"` // full, source, nodes
	TemplateFilename string   `json:"template_filename,omitempty"`
	RuleMode         string   `json:"rule_mode,omitempty"` // template (default), custom
	RuleCategories   []string `json:"rule_categories,omitempty"`
}

func marshalSubscriptionGeneration(g *SubscriptionGeneration) string {
	if g == nil {
		return ""
	}
	b, _ := json.Marshal(g)
	return string(b)
}

// Fingerprints include the complete connection configuration, but never names.
// Results contain no endpoint credentials and are scoped to the recipe owner.
type SubscriptionNodeHealth struct {
	Failures  int       `json:"failures"`
	CheckedAt time.Time `json:"checked_at"`
	Latency   float64   `json:"latency"`
}

func (r *TrafficRepository) ListSubscriptionNodeHealth(ctx context.Context, owner string) (map[string]SubscriptionNodeHealth, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT fingerprint,failures,checked_at,latency FROM subscription_node_health WHERE owner=?`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SubscriptionNodeHealth{}
	for rows.Next() {
		var key string
		var h SubscriptionNodeHealth
		if err := rows.Scan(&key, &h.Failures, &h.CheckedAt, &h.Latency); err != nil {
			return nil, err
		}
		out[key] = h
	}
	return out, rows.Err()
}

func (r *TrafficRepository) RecordSubscriptionNodeHealth(ctx context.Context, owner, key string, success bool, latency float64) error {
	failed := 1
	if success {
		failed = 0
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO subscription_node_health(owner,fingerprint,failures,checked_at,latency) VALUES(?,?,?,CURRENT_TIMESTAMP,?)
 ON CONFLICT(owner,fingerprint) DO UPDATE SET failures=CASE WHEN excluded.failures=0 THEN 0 ELSE subscription_node_health.failures+1 END,checked_at=CURRENT_TIMESTAMP,latency=excluded.latency`, owner, key, failed, latency)
	return err
}
