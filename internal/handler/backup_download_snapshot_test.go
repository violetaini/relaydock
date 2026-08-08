package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestBackupDownloadUsesSingleStandaloneDatabaseSnapshot(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll("data", 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.MkdirAll("subscribes", 0o755); err != nil {
		t.Fatalf("mkdir subscribes: %v", err)
	}

	repo, err := storage.NewTrafficRepository(filepath.Join("data", "arcway.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()
	if err := repo.EnsureUser(context.Background(), "snapshot-user", "password-hash"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if err := os.WriteFile(filepath.Join("data", "traffic.db"), []byte("stale database"), 0o600); err != nil {
		t.Fatalf("write stale database: %v", err)
	}
	if err := os.WriteFile(filepath.Join("data", "traffic.db-wal"), []byte("stale wal"), 0o600); err != nil {
		t.Fatalf("write stale wal: %v", err)
	}
	if err := os.WriteFile(filepath.Join("data", "traffic.db-journal"), []byte("stale journal"), 0o600); err != nil {
		t.Fatalf("write stale journal: %v", err)
	}
	if err := os.WriteFile(filepath.Join("data", "keep.txt"), []byte("keep me"), 0o600); err != nil {
		t.Fatalf("write preserved data file: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/admin/backup/download", nil)
	request.Header.Set("X-Backup-Passphrase", "correct horse battery staple")
	response := httptest.NewRecorder()
	NewBackupDownloadHandler(repo).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("backup status=%d body=%s", response.Code, response.Body.String())
	}
	plaintext, err := decryptBackupStream(bytes.NewReader(response.Body.Bytes()), "correct horse battery staple", maxBackupArchiveBytes)
	if err != nil {
		t.Fatalf("decrypt backup: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(plaintext), int64(len(plaintext)))
	if err != nil {
		t.Fatalf("open backup zip: %v", err)
	}
	if _, _, err := validateBackupArchive(reader); err != nil {
		t.Fatalf("downloaded backup is not accepted by restore validation: %v", err)
	}

	databaseEntries := 0
	var database []byte
	preserved := false
	for _, entry := range reader.File {
		name := filepath.ToSlash(entry.Name)
		lowerName := strings.ToLower(name)
		if strings.HasSuffix(lowerName, ".db-wal") || strings.HasSuffix(lowerName, ".db-shm") ||
			strings.HasSuffix(lowerName, ".db-journal") || lowerName == "data/traffic.db" {
			t.Fatalf("backup contains live SQLite artifact %q", name)
		}
		if name == "data/keep.txt" {
			preserved = true
		}
		if name != "data/arcway.db" {
			continue
		}
		databaseEntries++
		file, err := entry.Open()
		if err != nil {
			t.Fatalf("open database entry: %v", err)
		}
		database, err = io.ReadAll(file)
		closeErr := file.Close()
		if err != nil {
			t.Fatalf("read database entry: %v", err)
		}
		if closeErr != nil {
			t.Fatalf("close database entry: %v", closeErr)
		}
	}
	if databaseEntries != 1 {
		t.Fatalf("database entry count=%d, want 1", databaseEntries)
	}
	if !preserved {
		t.Fatal("ordinary data file was not included in backup")
	}

	extractedPath := filepath.Join(t.TempDir(), "arcway.db")
	if err := os.WriteFile(extractedPath, database, 0o600); err != nil {
		t.Fatalf("write extracted snapshot: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+extractedPath+"?mode=ro")
	if err != nil {
		t.Fatalf("open extracted snapshot: %v", err)
	}
	defer db.Close()
	var quickCheck string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&quickCheck); err != nil {
		t.Fatalf("quick_check extracted snapshot: %v", err)
	}
	if quickCheck != "ok" {
		t.Fatalf("extracted snapshot quick_check=%q, want ok", quickCheck)
	}
	var userCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = 'snapshot-user'`).Scan(&userCount); err != nil {
		t.Fatalf("query snapshot user: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("snapshot user count=%d, want 1", userCount)
	}
}
