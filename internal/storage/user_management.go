package storage

import (
	"context"
	"time"
)

// UserManagementResource contains labels and authorization state only. It must
// never expose node configurations, subscription URLs or user credentials.
type UserManagementResource struct {
	Username  string     `json:"-"`
	Kind      string     `json:"kind"`
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Source    string     `json:"source"`
	PackageID int64      `json:"-"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	State     string     `json:"state"`
}

// ListUserManagementResources uses one query for all users, including materialized
// package grants. Inactive accounts retain their authorization inventory.
func (r *TrafficRepository) ListUserManagementResources(ctx context.Context) ([]UserManagementResource, error) {
	rows, err := r.db.QueryContext(ctx, `
 SELECT s.username,'node',s.node_id,n.node_name,
 CASE WHEN s.source_type='package' THEN 'package' WHEN s.source_type='selection' THEN 'server' ELSE 'manual' END,
 COALESCE(g.source_package_id,sg.source_package_id,0),s.expires_at,s.observed_state
 FROM user_inbound_access_sources s JOIN nodes n ON n.id=s.node_id
 LEFT JOIN user_node_grants g ON g.access_source_id=s.id
 LEFT JOIN user_node_selections sel ON sel.access_source_id=s.id
 LEFT JOIN user_server_grants sg ON sg.id=sel.grant_id
 WHERE s.desired_state='active'
 UNION ALL
 SELECT username,'server',g.server_id,r.name,g.source_type,COALESCE(g.source_package_id,0),g.expires_at,'authorized'
 FROM user_server_grants g JOIN remote_servers r ON r.id=g.server_id WHERE g.enabled=1
 UNION ALL
 SELECT us.username,'subscription',f.id,f.name,COALESCE(us.source_type,'manual'),COALESCE(us.source_package_id,0),NULL,'authorized'
 FROM user_subscriptions us JOIN subscribe_files f ON f.id=us.subscription_id
 ORDER BY 1,2,3`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []UserManagementResource{}
	for rows.Next() {
		var v UserManagementResource
		if err := rows.Scan(&v.Username, &v.Kind, &v.ID, &v.Name, &v.Source, &v.PackageID, &v.ExpiresAt, &v.State); err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
