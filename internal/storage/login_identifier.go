package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// ResolveLoginUsername keeps session ownership and rate limits on the canonical
// account even when its unique email address is used to sign in.
func (r *TrafficRepository) ResolveLoginUsername(ctx context.Context, identifier string) (string, error) {
	identifier = strings.TrimSpace(identifier)
	var username string
	err := r.db.QueryRowContext(ctx, `SELECT username FROM users WHERE username = ?`, identifier).Scan(&username)
	if err == nil {
		return username, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if !strings.Contains(identifier, "@") {
		return "", ErrUserNotFound
	}
	rows, err := r.db.QueryContext(ctx, `SELECT username FROM users WHERE LOWER(email) = LOWER(?) LIMIT 2`, identifier)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		if err := rows.Scan(&username); err != nil {
			return "", err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if count != 1 {
		return "", ErrUserNotFound
	}
	return username, nil
}
