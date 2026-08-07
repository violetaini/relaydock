package storage

import (
	"context"
	"database/sql"
	"errors"
)

// FindActiveAdminUsername returns the earliest active administrator without a
// page-size limit. Internal services use it to issue an admin-scoped token.
func (r *TrafficRepository) FindActiveAdminUsername(ctx context.Context) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	var username string
	err := r.db.QueryRowContext(ctx,
		`SELECT username FROM users WHERE role = ? AND is_active = 1 ORDER BY created_at ASC LIMIT 1`,
		RoleAdmin,
	).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return username, err
}
