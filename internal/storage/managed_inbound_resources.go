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

var ErrManagedInboundResourceNotFound = errors.New("managed inbound resource not found")

// ManagedInboundResource is management-only inventory for an Agent inbound.
// It intentionally lives outside nodes: it is never eligible for packages,
// subscriptions, self-service credentials, proxy tests, or URI generation.
type ManagedInboundResource struct {
	ID                 int64           `json:"id"`
	ServerID           int64           `json:"server_id"`
	ServerName         string          `json:"server_name"`
	DisplayName        string          `json:"display_name"`
	Protocol           string          `json:"protocol"`
	InboundTag         string          `json:"inbound_tag"`
	MutationID         string          `json:"-"`
	EndpointHost       string          `json:"endpoint_host"`
	EndpointPort       int             `json:"endpoint_port"`
	PublicMetadataJSON json.RawMessage `json:"-"`
	CreatedBy          string          `json:"created_by"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

func (r *TrafficRepository) migrateManagedInboundResources() error {
	const schema = `
CREATE TABLE IF NOT EXISTS managed_inbound_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    display_name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    inbound_tag TEXT NOT NULL,
    mutation_id TEXT NOT NULL DEFAULT '',
    endpoint_host TEXT NOT NULL DEFAULT '',
    endpoint_port INTEGER NOT NULL,
    public_metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(server_id) REFERENCES remote_servers(id) ON DELETE CASCADE,
    UNIQUE(server_id, inbound_tag)
);
CREATE INDEX IF NOT EXISTS idx_managed_inbound_resources_protocol
    ON managed_inbound_resources(protocol);
CREATE INDEX IF NOT EXISTS idx_managed_inbound_resources_server
    ON managed_inbound_resources(server_id);
`
	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate managed_inbound_resources: %w", err)
	}
	if err := r.ensureTableColumn("managed_inbound_resources", "mutation_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate managed_inbound_resources mutation_id: %w", err)
	}
	return nil
}

func normalizeManagedInboundResource(resource *ManagedInboundResource) error {
	if resource == nil {
		return errors.New("managed inbound resource is required")
	}
	resource.DisplayName = strings.TrimSpace(resource.DisplayName)
	resource.Protocol = strings.ToLower(strings.TrimSpace(resource.Protocol))
	resource.InboundTag = strings.TrimSpace(resource.InboundTag)
	resource.MutationID = strings.TrimSpace(resource.MutationID)
	resource.EndpointHost = strings.TrimSpace(resource.EndpointHost)
	resource.CreatedBy = strings.TrimSpace(resource.CreatedBy)
	if resource.ServerID <= 0 {
		return errors.New("server id is required")
	}
	if resource.DisplayName == "" {
		return errors.New("display name is required")
	}
	if resource.Protocol == "" {
		return errors.New("protocol is required")
	}
	if resource.InboundTag == "" {
		return errors.New("inbound tag is required")
	}
	if resource.EndpointPort < 1 || resource.EndpointPort > 65535 {
		return errors.New("endpoint port must be between 1 and 65535")
	}
	metadata := resource.PublicMetadataJSON
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	var value interface{}
	if err := json.Unmarshal(metadata, &value); err != nil {
		return fmt.Errorf("public metadata must be valid JSON: %w", err)
	}
	if _, ok := value.(map[string]interface{}); !ok {
		return errors.New("public metadata must be a JSON object")
	}
	if key := managedInboundSecretKey(value); key != "" {
		return fmt.Errorf("public metadata contains forbidden secret field %q", key)
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("normalize public metadata: %w", err)
	}
	resource.PublicMetadataJSON = normalized
	return nil
}

func managedInboundSecretKey(value interface{}) string {
	switch current := value.(type) {
	case map[string]interface{}:
		for key, child := range current {
			normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
			if strings.Contains(normalized, "private") || strings.Contains(normalized, "secret") {
				return key
			}
			if nested := managedInboundSecretKey(child); nested != "" {
				return nested
			}
		}
	case []interface{}:
		for _, child := range current {
			if nested := managedInboundSecretKey(child); nested != "" {
				return nested
			}
		}
	}
	return ""
}

const managedInboundResourceSelect = `
SELECT r.id, r.server_id, COALESCE(s.name, ''), r.display_name, r.protocol,
       r.inbound_tag, COALESCE(r.mutation_id, ''), r.endpoint_host, r.endpoint_port, r.public_metadata_json,
       r.created_by, r.created_at, r.updated_at
FROM managed_inbound_resources r
LEFT JOIN remote_servers s ON s.id = r.server_id`

type managedInboundResourceScanner interface {
	Scan(dest ...interface{}) error
}

func scanManagedInboundResource(scanner managedInboundResourceScanner) (*ManagedInboundResource, error) {
	var resource ManagedInboundResource
	var metadata string
	if err := scanner.Scan(
		&resource.ID,
		&resource.ServerID,
		&resource.ServerName,
		&resource.DisplayName,
		&resource.Protocol,
		&resource.InboundTag,
		&resource.MutationID,
		&resource.EndpointHost,
		&resource.EndpointPort,
		&metadata,
		&resource.CreatedBy,
		&resource.CreatedAt,
		&resource.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrManagedInboundResourceNotFound
		}
		return nil, err
	}
	resource.PublicMetadataJSON = json.RawMessage(metadata)
	return &resource, nil
}

func (r *TrafficRepository) CreateManagedInboundResource(ctx context.Context, resource ManagedInboundResource) (*ManagedInboundResource, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if err := normalizeManagedInboundResource(&resource); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	result, err := r.db.ExecContext(ctx, `
INSERT INTO managed_inbound_resources
    (server_id, display_name, protocol, inbound_tag, mutation_id, endpoint_host, endpoint_port,
     public_metadata_json, created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		resource.ServerID, resource.DisplayName, resource.Protocol, resource.InboundTag,
		resource.MutationID, resource.EndpointHost, resource.EndpointPort, string(resource.PublicMetadataJSON),
		resource.CreatedBy, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("create managed inbound resource: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read managed inbound resource id: %w", err)
	}
	return r.GetManagedInboundResource(ctx, id)
}

// UpsertManagedInboundResource is used by Agent inventory reconciliation.
// Once a user has renamed a resource, synchronization preserves that name.
func (r *TrafficRepository) UpsertManagedInboundResource(ctx context.Context, resource ManagedInboundResource) (*ManagedInboundResource, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if err := normalizeManagedInboundResource(&resource); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, `
INSERT INTO managed_inbound_resources
    (server_id, display_name, protocol, inbound_tag, mutation_id, endpoint_host, endpoint_port,
     public_metadata_json, created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(server_id, inbound_tag) DO UPDATE SET
    protocol = excluded.protocol,
    mutation_id = CASE
        WHEN excluded.mutation_id != '' THEN excluded.mutation_id
        ELSE managed_inbound_resources.mutation_id
    END,
    endpoint_host = excluded.endpoint_host,
    endpoint_port = excluded.endpoint_port,
    public_metadata_json = excluded.public_metadata_json,
    updated_at = excluded.updated_at`,
		resource.ServerID, resource.DisplayName, resource.Protocol, resource.InboundTag,
		resource.MutationID, resource.EndpointHost, resource.EndpointPort, string(resource.PublicMetadataJSON),
		resource.CreatedBy, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert managed inbound resource: %w", err)
	}
	return r.GetManagedInboundResourceByServerTag(ctx, resource.ServerID, resource.InboundTag)
}

func (r *TrafficRepository) ListManagedInboundResources(ctx context.Context) ([]ManagedInboundResource, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, managedInboundResourceSelect+` ORDER BY r.updated_at DESC, r.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list managed inbound resources: %w", err)
	}
	defer rows.Close()
	resources := make([]ManagedInboundResource, 0)
	for rows.Next() {
		resource, err := scanManagedInboundResource(rows)
		if err != nil {
			return nil, fmt.Errorf("scan managed inbound resource: %w", err)
		}
		resources = append(resources, *resource)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate managed inbound resources: %w", err)
	}
	return resources, nil
}

func (r *TrafficRepository) GetManagedInboundResource(ctx context.Context, id int64) (*ManagedInboundResource, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if id <= 0 {
		return nil, ErrManagedInboundResourceNotFound
	}
	return scanManagedInboundResource(r.db.QueryRowContext(ctx, managedInboundResourceSelect+` WHERE r.id = ?`, id))
}

func (r *TrafficRepository) GetManagedInboundResourceByServerTag(ctx context.Context, serverID int64, inboundTag string) (*ManagedInboundResource, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	if serverID <= 0 || inboundTag == "" {
		return nil, ErrManagedInboundResourceNotFound
	}
	return scanManagedInboundResource(r.db.QueryRowContext(ctx, managedInboundResourceSelect+` WHERE r.server_id = ? AND r.inbound_tag = ?`, serverID, inboundTag))
}

func (r *TrafficRepository) RenameManagedInboundResource(ctx context.Context, id int64, displayName string) (*ManagedInboundResource, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	displayName = strings.TrimSpace(displayName)
	if id <= 0 || displayName == "" {
		return nil, errors.New("resource id and display name are required")
	}
	result, err := r.db.ExecContext(ctx, `UPDATE managed_inbound_resources SET display_name = ?, updated_at = ? WHERE id = ?`, displayName, time.Now().UTC(), id)
	if err != nil {
		return nil, fmt.Errorf("rename managed inbound resource: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read renamed managed inbound resource count: %w", err)
	}
	if count == 0 {
		return nil, ErrManagedInboundResourceNotFound
	}
	return r.GetManagedInboundResource(ctx, id)
}

func (r *TrafficRepository) DeleteManagedInboundResource(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM managed_inbound_resources WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete managed inbound resource: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read deleted managed inbound resource count: %w", err)
	}
	if count == 0 {
		return ErrManagedInboundResourceNotFound
	}
	return nil
}

func (r *TrafficRepository) DeleteManagedInboundResourceByServerTag(ctx context.Context, serverID int64, inboundTag string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM managed_inbound_resources WHERE server_id = ? AND inbound_tag = ?`, serverID, strings.TrimSpace(inboundTag))
	if err != nil {
		return 0, fmt.Errorf("delete managed inbound resource by server and tag: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted managed inbound resource count: %w", err)
	}
	return count, nil
}

func (r *TrafficRepository) DeleteManagedInboundResourceIfMutation(ctx context.Context, id int64, mutationID string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM managed_inbound_resources WHERE id = ? AND COALESCE(mutation_id, '') = ?`,
		id, strings.TrimSpace(mutationID),
	)
	if err != nil {
		return 0, fmt.Errorf("delete managed inbound resource by mutation: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted managed inbound resource count: %w", err)
	}
	return count, nil
}

func (r *TrafficRepository) DeleteManagedInboundResourceByServerTagMutation(ctx context.Context, serverID int64, inboundTag, mutationID string) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("traffic repository not initialized")
	}
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM managed_inbound_resources WHERE server_id = ? AND inbound_tag = ? AND COALESCE(mutation_id, '') = ?`,
		serverID, strings.TrimSpace(inboundTag), strings.TrimSpace(mutationID),
	)
	if err != nil {
		return 0, fmt.Errorf("delete managed inbound resource by server, tag, and mutation: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted managed inbound resource count: %w", err)
	}
	return count, nil
}
