package storage

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemConfigManagementFeaturesColumnMigrationPreservesValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system-config-migration.db")
	legacyColumn := strings.Join([]string{"enable", "miao", "miao", "wu", "features"}, "_")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	schema := fmt.Sprintf(`
CREATE TABLE system_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    proxy_groups_source_url TEXT NOT NULL DEFAULT '',
    %s INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO system_config (id, proxy_groups_source_url, %s) VALUES (1, '', 0);
`, legacyColumn, legacyColumn)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		t.Fatalf("create legacy system_config: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	cfg, err := repo.GetSystemConfig(context.Background())
	if err != nil {
		t.Fatalf("GetSystemConfig: %v", err)
	}
	if cfg.EnableManagementFeatures {
		t.Fatal("EnableManagementFeatures = true, want migrated false value")
	}

	columns, err := systemConfigColumnNames(repo.db)
	if err != nil {
		t.Fatalf("read migrated columns: %v", err)
	}
	if _, ok := columns[legacyColumn]; ok {
		t.Fatalf("legacy column %q still exists", legacyColumn)
	}
	if _, ok := columns["enable_management_features"]; !ok {
		t.Fatal("enable_management_features column was not created")
	}
}

func systemConfigColumnNames(db *sql.DB) (map[string]struct{}, error) {
	rows, err := db.Query(`PRAGMA table_info(system_config)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns := make(map[string]struct{})
	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = struct{}{}
	}
	return columns, rows.Err()
}
