package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestValidateLegacyPanelSourceURLAndRedirectOrigin(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{name: "https", raw: "https://panel.example.com", ok: true},
		{name: "loopback explicit", raw: "http://127.0.0.1:8080", ok: true},
		{name: "http public", raw: "http://panel.example.com", ok: false},
		{name: "userinfo", raw: "https://admin:secret@panel.example.com", ok: false},
		{name: "query", raw: "https://panel.example.com/?next=evil", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateLegacyPanelSourceURL(tc.raw, tc.name == "loopback explicit")
			if (err == nil) != tc.ok {
				t.Fatalf("validate(%q) err=%v, want ok=%v", tc.raw, err, tc.ok)
			}
		})
	}

	source, _ := validateLegacyPanelSourceURL("https://panel.example.com", false)
	client := newLegacyPanelHTTPClient(source)
	same, _ := http.NewRequest(http.MethodGet, "https://panel.example.com/api/login", nil)
	if err := client.CheckRedirect(same, []*http.Request{{URL: source}}); err != nil {
		t.Fatalf("same-origin redirect rejected: %v", err)
	}
	cross, _ := http.NewRequest(http.MethodGet, "https://evil.example/api/login", nil)
	if err := client.CheckRedirect(cross, []*http.Request{{URL: source}}); err == nil {
		t.Fatal("cross-origin redirect was accepted")
	}
}

func TestMigrationPathsAndCleanupAreConfined(t *testing.T) {
	if err := ensureMigrateWorkDir(); err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef0123456789abcdef"
	paths, err := migrationSession(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Zip, paths.DB} {
		if err := os.WriteFile(path, []byte("test"), migrateTempFilePerm); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(paths.Subs, migrateWorkPerm); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	defer removeMigrationSession(id)

	gotDB, gotSubs, err := resolveLegacyMigrationPaths(paths.DB, paths.Subs)
	if err != nil || gotDB != paths.DB || gotSubs != paths.Subs {
		t.Fatalf("valid legacy paths rejected: db=%q subs=%q err=%v", gotDB, gotSubs, err)
	}
	if _, _, err := resolveLegacyMigrationPaths("/etc/passwd", paths.Subs); err == nil {
		t.Fatal("outside db path accepted")
	}
	if _, _, err := resolveLegacyMigrationPaths(paths.DB, "/tmp/relaydock-migrate/ffffffffffffffff-subs"); err == nil {
		t.Fatal("mismatched session directory accepted")
	}

	request := httptest.NewRequest(http.MethodDelete, "/api/admin/migrate/cleanup", strings.NewReader(`{"migration_id":"`+id+`"}`))
	recorder := httptest.NewRecorder()
	(&MigrateHandler{}).CleanupLegacySession(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("cleanup status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, path := range []string{paths.Zip, paths.DB, paths.Subs} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("artifact %s remains, err=%v", path, err)
		}
	}

	// A path-like value must never be interpreted as an ID.
	bad := httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodDelete, "/api/admin/migrate/cleanup", strings.NewReader(`{"migration_id":"../../etc/passwd"}`))
	(&MigrateHandler{}).CleanupLegacySession(bad, badReq)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid cleanup id status=%d", bad.Code)
	}
}

func TestExtractLegacyPanelBackupSetsPrivateModesAndLimitsBombs(t *testing.T) {
	root := t.TempDir()
	zipPath := filepath.Join(root, "source.zip")
	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	entry, err := zw.Create("data/legacyPanel.db")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("sqlite-placeholder"))
	sub, err := zw.Create("subscribes/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sub.Write([]byte("nodes: []"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(root, "out.db")
	subsPath := filepath.Join(root, "subs")
	if _, _, err := extractLegacyPanelBackup(zipPath, dbPath, subsPath); err != nil {
		t.Fatal(err)
	}
	if mode := mustMode(t, dbPath); mode.Perm() != migrateTempFilePerm {
		t.Fatalf("db mode=%o, want %o", mode.Perm(), migrateTempFilePerm)
	}
	if mode := mustMode(t, subsPath); mode.Perm() != migrateWorkPerm {
		t.Fatalf("subs mode=%o, want %o", mode.Perm(), migrateWorkPerm)
	}
	if mode := mustMode(t, filepath.Join(subsPath, "example.yaml")); mode.Perm() != migrateTempFilePerm {
		t.Fatalf("sub mode=%o, want %o", mode.Perm(), migrateTempFilePerm)
	}

	// The copy helper is also guarded at the actual stream boundary, not only
	// by ZIP metadata, so a forged uncompressed size cannot bypass the limit.
	var bomb bytes.Buffer
	bombWriter := zip.NewWriter(&bomb)
	bombEntry, err := bombWriter.Create("data/big.db")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = bombEntry.Write([]byte("123456"))
	_ = bombWriter.Close()
	reader, err := zip.NewReader(bytes.NewReader(bomb.Bytes()), int64(bomb.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := copyZipEntry(reader.File[0], filepath.Join(root, "limited.db"), 2, 2); err == nil {
		t.Fatal("stream larger than entry limit was accepted")
	}

	tooMany := filepath.Join(root, "too-many.zip")
	f, err := os.Create(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for i := 0; i <= maxArchiveEntries; i++ {
		name := "ignored/" + strings.Repeat("x", 1) + string(rune('a'+i%26)) + ".txt"
		if _, err := w.Create(name); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	_ = f.Close()
	if _, _, err := extractLegacyPanelBackup(tooMany, filepath.Join(root, "x.db"), filepath.Join(root, "x-subs")); err == nil {
		t.Fatal("archive with too many entries was accepted")
	}
}

func TestExpiredOrphanMigrationArtifactsAreCleaned(t *testing.T) {
	if err := ensureMigrateWorkDir(); err != nil {
		t.Fatal(err)
	}
	id := "abcdefabcdefabcdefabcdefabcdefab"
	paths, _ := migrationSession(id)
	if err := os.WriteFile(paths.DB, []byte("orphan"), migrateTempFilePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.Subs, migrateWorkPerm); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-migrationSessionTTL - time.Hour)
	_ = os.Chtimes(paths.DB, old, old)
	_ = os.Chtimes(paths.Subs, old, old)
	defer removeMigrationSession(id)
	cleanupExpiredMigrationSessions(time.Now())
	if _, err := os.Stat(paths.DB); !os.IsNotExist(err) {
		t.Fatalf("orphan db was not cleaned: %v", err)
	}
}

func TestImportLegacyPanelRejectsNonBlankTargetWithCounts(t *testing.T) {
	if err := ensureMigrateWorkDir(); err != nil {
		t.Fatal(err)
	}
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "admin", "", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "existing", "", "Existing", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef0123456789abcdef"
	paths, _ := migrationSession(id)
	if err := os.WriteFile(paths.DB, []byte("not used"), migrateTempFilePerm); err != nil {
		t.Fatal(err)
	}
	defer removeMigrationSession(id)
	h := NewMigrateHandler(repo, nil)
	body, _ := json.Marshal(map[string]string{"migration_id": id})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/migrate/import-legacyPanel", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUsername(req.Context(), "admin"))
	recorder := httptest.NewRecorder()
	h.ImportLegacyBackup(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("non-blank import status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "users") {
		t.Fatalf("blocking table missing from response: %s", recorder.Body.String())
	}
}

func TestImportLegacyPanelSubscribeCopyFailureLeavesDatabaseRetryable(t *testing.T) {
	if err := ensureMigrateWorkDir(); err != nil {
		t.Fatal(err)
	}
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "admin", "", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}

	id := "fedcba9876543210fedcba9876543210"
	_ = removeMigrationSession(id)
	paths, _ := migrationSession(id)
	defer removeMigrationSession(id)
	source, err := sql.Open("sqlite", paths.DB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TIMESTAMP NOT NULL)`); err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if _, err := source.Exec(`INSERT INTO users(username,password_hash,role,created_at) VALUES ('imported-user','hash','user','2026-01-01 00:00:00')`); err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.DB, migrateTempFilePerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.Subs, migrateWorkPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Subs, "sample.yaml"), []byte("proxies: []\n"), migrateTempFilePerm); err != nil {
		t.Fatal(err)
	}

	blockedDestination := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedDestination, []byte("blocked"), migrateTempFilePerm); err != nil {
		t.Fatal(err)
	}
	h := NewMigrateHandler(repo, nil)
	h.subscribesDir = blockedDestination
	body, _ := json.Marshal(map[string]string{"migration_id": id})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/migrate/import-legacyPanel", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUsername(req.Context(), "admin"))
	recorder := httptest.NewRecorder()
	h.ImportLegacyBackup(recorder, req)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("copy failure status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	blocking, err := repo.LegacyPanelImportBlockingCounts(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocking) != 0 {
		t.Fatalf("database was modified before subscribe copy completed: %#v", blocking)
	}
}

func TestCopySubscribesDirIsAtomicAndIdempotent(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(source, migrateWorkPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sample.yaml"), []byte("proxies: []\n"), migrateTempFilePerm); err != nil {
		t.Fatal(err)
	}
	copied, skipped, err := copySubscribesDir(context.Background(), repo, source, destination)
	if err != nil || copied != 1 || len(skipped) != 0 {
		t.Fatalf("first copy copied=%d skipped=%v err=%v", copied, skipped, err)
	}
	copied, skipped, err = copySubscribesDir(context.Background(), repo, source, destination)
	if err != nil || copied != 0 || len(skipped) != 1 || skipped[0] != "sample.yaml" {
		t.Fatalf("retry copied=%d skipped=%v err=%v", copied, skipped, err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "sample.yaml"))
	if err != nil || string(data) != "proxies: []\n" {
		t.Fatalf("destination data=%q err=%v", data, err)
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
