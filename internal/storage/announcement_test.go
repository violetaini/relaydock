package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestAnnouncementMigrationRepairsLegacySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE announcements (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL DEFAULT 'general',
		title TEXT NOT NULL DEFAULT '',
		body TEXT NOT NULL DEFAULT '',
		via_bot INTEGER NOT NULL DEFAULT 1,
		via_miniapp INTEGER NOT NULL DEFAULT 1,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP
	)`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	columns := map[string]bool{}
	rows, err := repo.db.Query(`PRAGMA table_info(announcements)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, notNull, pk int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !columns["node_id"] || !columns["bot_delivered_at"] {
		t.Fatalf("repaired columns = %v", columns)
	}

	id, err := repo.CreateAnnouncement(context.Background(), Announcement{
		Type: "general", Body: "maintenance", ViaBot: true, ViaMiniapp: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	items, err := repo.ListPendingBotAnnouncements(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != id || items[0].NodeID != 0 {
		t.Fatalf("pending announcements = %+v", items)
	}
}
