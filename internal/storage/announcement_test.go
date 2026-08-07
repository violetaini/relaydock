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
	var deliveryTable string
	if err := repo.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'announcement_bot_deliveries'`,
	).Scan(&deliveryTable); err != nil {
		t.Fatalf("delivery table migration: %v", err)
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

func TestAnnouncementBotRecipientDeliveryIsDurableAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recipient-delivery.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	id, err := repo.CreateAnnouncement(ctx, Announcement{
		Type: "general", Body: "maintenance", ViaBot: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := repo.MarkAnnouncementBotRecipientDelivered(ctx, id, 1001); err != nil {
			t.Fatalf("mark recipient attempt %d: %v", i+1, err)
		}
	}
	if err := repo.MarkAnnouncementBotRecipientDelivered(ctx, id, 1002); err != nil {
		t.Fatal(err)
	}

	delivered, err := repo.ListAnnouncementBotDeliveredRecipients(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 2 {
		t.Fatalf("delivered recipients = %v, want 2 unique rows", delivered)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	repo, err = NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	delivered, err = repo.ListAnnouncementBotDeliveredRecipients(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := delivered[1001]; !ok {
		t.Fatalf("recipient delivery did not survive reopen: %v", delivered)
	}
	if _, ok := delivered[1002]; !ok {
		t.Fatalf("recipient delivery did not survive reopen: %v", delivered)
	}

	if err := repo.DeleteAnnouncement(ctx, id); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := repo.db.QueryRow(
		`SELECT COUNT(*) FROM announcement_bot_deliveries WHERE announcement_id = ?`, id,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("delivery rows after announcement delete = %d", count)
	}
}
