package storage

import "context"

// SubscriptionAssignmentSources returns labels only for the requested user's grants.
func (r *TrafficRepository) SubscriptionAssignmentSources(ctx context.Context, username string) (map[int64]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT subscription_id, COALESCE(source_type,'manual') FROM user_subscriptions WHERE username=?`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sources := map[int64]string{}
	for rows.Next() {
		var id int64
		var source string
		if err := rows.Scan(&id, &source); err != nil {
			return nil, err
		}
		sources[id] = source
	}
	return sources, rows.Err()
}
