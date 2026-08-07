package storage

import (
	"context"
	"database/sql"
	"time"
)

// Announcement is one message published to the Telegram Bot or Mini App.
type Announcement struct {
	ID         int64      `json:"id"`
	Type       string     `json:"type"`
	Title      string     `json:"title"`
	Body       string     `json:"body"`
	NodeID     int64      `json:"node_id,omitempty"`
	ViaBot     bool       `json:"via_bot"`
	ViaMiniapp bool       `json:"via_miniapp"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

func (r *TrafficRepository) CreateAnnouncement(ctx context.Context, a Announcement) (int64, error) {
	var expiresAt any
	if a.ExpiresAt != nil {
		expiresAt = a.ExpiresAt.UTC()
	}
	result, err := r.db.ExecContext(ctx,
		`INSERT INTO announcements (type, title, body, node_id, via_bot, via_miniapp, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.Type, a.Title, a.Body, a.NodeID, boolToInt(a.ViaBot), boolToInt(a.ViaMiniapp), expiresAt)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (r *TrafficRepository) ListActiveAnnouncements(ctx context.Context, miniappOnly bool) ([]Announcement, error) {
	query := `SELECT id, type, title, body, node_id, via_bot, via_miniapp, created_at, expires_at
	            FROM announcements
	           WHERE (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`
	if miniappOnly {
		query += ` AND via_miniapp = 1`
	}
	query += ` ORDER BY created_at DESC`
	return r.queryAnnouncements(ctx, query)
}

func (r *TrafficRepository) ListPendingBotAnnouncements(ctx context.Context) ([]Announcement, error) {
	return r.queryAnnouncements(ctx,
		`SELECT id, type, title, body, node_id, via_bot, via_miniapp, created_at, expires_at
		   FROM announcements
		  WHERE via_bot = 1 AND bot_delivered_at IS NULL
		    AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		  ORDER BY created_at ASC`)
}

func (r *TrafficRepository) MarkAnnouncementBotDelivered(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE announcements SET bot_delivered_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

func (r *TrafficRepository) DeleteAnnouncement(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM announcements WHERE id = ?`, id)
	return err
}

func (r *TrafficRepository) queryAnnouncements(ctx context.Context, query string, args ...any) ([]Announcement, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Announcement, 0)
	for rows.Next() {
		var item Announcement
		var viaBot, viaMiniapp int
		var expiresAt sql.NullTime
		if err := rows.Scan(
			&item.ID,
			&item.Type,
			&item.Title,
			&item.Body,
			&item.NodeID,
			&viaBot,
			&viaMiniapp,
			&item.CreatedAt,
			&expiresAt,
		); err != nil {
			return nil, err
		}
		item.ViaBot = viaBot != 0
		item.ViaMiniapp = viaMiniapp != 0
		if expiresAt.Valid {
			value := expiresAt.Time
			item.ExpiresAt = &value
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
