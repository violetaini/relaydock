package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/securechan"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestInitialSetupSerializesEmptyRepositoryCheck(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "setup.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()
	handler := NewInitialSetupHandler(repo)

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for _, username := range []string{"first-admin", "second-admin"} {
		username := username
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			body, _ := json.Marshal(setupRequest{Username: username, Password: "strong-password"})
			req := httptest.NewRequest(http.MethodPost, "/api/setup/init", bytes.NewReader(body))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			statuses <- recorder.Code
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)

	created, conflicts := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("unexpected setup status %d", status)
		}
	}
	if created != 1 || conflicts != 1 {
		t.Fatalf("created=%d conflicts=%d, want one each", created, conflicts)
	}
	users, err := repo.ListUsers(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("user count=%d, want 1", len(users))
	}
}

func TestExtractZipReaderAtStagesThenFullyReplacesLiveRoots(t *testing.T) {
	root := t.TempDir()
	restoredDatabase := validSQLiteBackupBytes(t)
	mustWriteTestFile(t, filepath.Join(root, "data", "arcway.db"), "live-db")
	mustWriteTestFile(t, filepath.Join(root, "data", "arcway.db-wal"), "stale-wal")
	mustWriteTestFile(t, filepath.Join(root, "data", "arcway.db-shm"), "stale-shm")
	mustWriteTestFile(t, filepath.Join(root, "data", "retained.txt"), "retained")
	mustWriteTestFile(t, filepath.Join(root, "subscribes", "old.yaml"), "old")

	reader := testZipReaderBytes(t, map[string][]byte{
		"data/arcway.db":      restoredDatabase,
		"data/added.txt":      []byte("added"),
		"subscribes/new.yaml": []byte("new"),
	})
	if err := extractZipReaderAt(reader, root); err != nil {
		t.Fatalf("extractZipReaderAt: %v", err)
	}

	// Staging a restore must not mutate the database or subscription tree used
	// by the running process.
	for filename, want := range map[string]string{
		"data/arcway.db":      "live-db",
		"data/retained.txt":   "retained",
		"subscribes/old.yaml": "old",
	} {
		got, err := os.ReadFile(filepath.Join(root, filename))
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}
		if string(got) != want {
			t.Fatalf("%s=%q, want %q", filename, got, want)
		}
	}
	pendingDatabase, err := os.ReadFile(filepath.Join(root, pendingRestoreDirName, "data", "arcway.db"))
	if err != nil || !bytes.Equal(pendingDatabase, restoredDatabase) {
		t.Fatalf("pending database differs from staged database: %v", err)
	}
	for filename, want := range map[string]string{
		"data/added.txt":      "added",
		"subscribes/new.yaml": "new",
	} {
		got, err := os.ReadFile(filepath.Join(root, pendingRestoreDirName, filename))
		if err != nil || string(got) != want {
			t.Fatalf("pending %s=%q, %v; want %q", filename, got, err, want)
		}
	}

	applied, err := ApplyPendingBackupRestore(root)
	if err != nil || !applied {
		t.Fatalf("ApplyPendingBackupRestore: applied=%v err=%v", applied, err)
	}
	restoredDatabaseOnDisk, err := os.ReadFile(filepath.Join(root, "data", "arcway.db"))
	if err != nil || !bytes.Equal(restoredDatabaseOnDisk, restoredDatabase) {
		t.Fatalf("restored database differs from staged database: %v", err)
	}
	for filename, want := range map[string]string{
		"data/added.txt":      "added",
		"subscribes/new.yaml": "new",
	} {
		got, err := os.ReadFile(filepath.Join(root, filename))
		if err != nil || string(got) != want {
			t.Fatalf("restored %s=%q, %v; want %q", filename, got, err, want)
		}
	}
	for _, filename := range []string{
		"data/arcway.db-wal",
		"data/arcway.db-shm",
		"data/retained.txt",
		"subscribes/old.yaml",
	} {
		if _, err := os.Stat(filepath.Join(root, filename)); !os.IsNotExist(err) {
			t.Fatalf("omitted live file %s survived full restore: %v", filename, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, pendingRestoreDirName)); !os.IsNotExist(err) {
		t.Fatalf("pending restore remained after apply: %v", err)
	}
}

func TestExtractZipReaderAtRejectsCorruptSQLiteWithoutPublishing(t *testing.T) {
	root := t.TempDir()
	validDatabase := validSQLiteBackupBytes(t)
	valid := testZipReaderBytes(t, map[string][]byte{
		"data/arcway.db": validDatabase,
	})
	if err := extractZipReaderAt(valid, root); err != nil {
		t.Fatalf("stage initial valid restore: %v", err)
	}

	corrupt := testZipReader(t, map[string]string{
		"data/arcway.db": "not a sqlite database",
	})
	if err := extractZipReaderAt(corrupt, root); err == nil {
		t.Fatal("corrupt SQLite database was accepted")
	}
	pendingDatabase, err := os.ReadFile(filepath.Join(root, pendingRestoreDirName, "data", "arcway.db"))
	if err != nil || !bytes.Equal(pendingDatabase, validDatabase) {
		t.Fatalf("rejected restore displaced the valid pending database: %v", err)
	}
}

func TestExtractZipReaderAtRejectsTraversalWithoutMutation(t *testing.T) {
	root := t.TempDir()
	mustWriteTestFile(t, filepath.Join(root, "data", "existing.txt"), "old")
	reader := testZipReader(t, map[string]string{
		"data/arcway.db": "restored-db",
		"data/new.txt":   "new",
		"data/../escape": "escape",
	})
	if err := extractZipReaderAt(reader, root); err == nil {
		t.Fatal("expected traversal archive rejection")
	}
	got, err := os.ReadFile(filepath.Join(root, "data", "existing.txt"))
	if err != nil || string(got) != "old" {
		t.Fatalf("existing file changed after rejected restore: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "data", "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("new file should not exist after rejected restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, pendingRestoreDirName)); !os.IsNotExist(err) {
		t.Fatalf("invalid restore published a pending tree: %v", err)
	}
}

func TestBackupStreamEncryptionRoundTripAndAuthentication(t *testing.T) {
	plaintext := bytes.Repeat([]byte("arcway-backup-data"), (2*backupStreamChunkBytes)/len("arcway-backup-data")+17)
	var encrypted bytes.Buffer
	if err := encryptBackupStream(&encrypted, bytes.NewReader(plaintext), "correct horse battery staple"); err != nil {
		t.Fatalf("encryptBackupStream: %v", err)
	}
	if !isStreamEncryptedBackup(encrypted.Bytes()) {
		t.Fatal("stream backup magic was not written")
	}
	decrypted, err := decryptBackupStream(bytes.NewReader(encrypted.Bytes()), "correct horse battery staple", int64(len(plaintext)))
	if err != nil {
		t.Fatalf("decryptBackupStream: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted stream backup differs from plaintext")
	}
	if _, err := decryptBackupStream(bytes.NewReader(encrypted.Bytes()), "wrong passphrase", int64(len(plaintext))); err == nil {
		t.Fatal("wrong passphrase unexpectedly decrypted stream backup")
	}
	truncated := append([]byte(nil), encrypted.Bytes()[:encrypted.Len()-(4+16)]...)
	truncated = append(truncated, make([]byte, 4+16)...)
	if _, err := decryptBackupStream(bytes.NewReader(truncated), "correct horse battery staple", int64(len(plaintext))); err == nil {
		t.Fatal("backup truncated at a chunk boundary unexpectedly authenticated")
	}
}

func TestBackupPassphrasesCannotComeFromURLQuery(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "arcway.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()
	handler := NewBackupDownloadHandler(repo)

	getRequest := httptest.NewRequest(http.MethodGet, "/api/backup?passphrase=query-secret", nil)
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET backup status=%d, want %d", getResponse.Code, http.StatusMethodNotAllowed)
	}

	postRequest := httptest.NewRequest(http.MethodPost, "/api/backup?passphrase=query-secret", nil)
	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, postRequest)
	if postResponse.Code != http.StatusBadRequest {
		t.Fatalf("query-only download passphrase status=%d, want %d", postResponse.Code, http.StatusBadRequest)
	}

	restoreRequest := httptest.NewRequest(http.MethodPost, "/api/backup/restore?passphrase=query-secret", nil)
	if got := restorePassphraseFromRequest(restoreRequest); got != "" {
		t.Fatalf("restore passphrase was read from URL query: %q", got)
	}
}

func TestSecureChannelHandshakeLimiterAndSessionBound(t *testing.T) {
	h := &UserSecureChannelHandler{
		sessions:   make(map[string]*userSession),
		handshakes: make(map[string]*handshakeWindow),
	}
	now := time.Now()
	for i := 0; i < maxHandshakesPerWindow; i++ {
		if !h.allowHandshake("192.0.2.1", now) {
			t.Fatalf("handshake %d unexpectedly denied", i+1)
		}
	}
	if h.allowHandshake("192.0.2.1", now) {
		t.Fatal("handshake over per-IP window limit was allowed")
	}
	if !h.allowHandshake("192.0.2.1", now.Add(handshakeWindowDuration)) {
		t.Fatal("handshake window did not reset")
	}

	for i := 0; i < maxUserSecureSessions+20; i++ {
		h.storeSession(stringID(i), &userSession{sess: &securechan.Session{}, createdAt: now, lastUsed: now.Add(time.Duration(i) * time.Nanosecond)}, now)
	}
	h.mu.Lock()
	count := len(h.sessions)
	h.mu.Unlock()
	if count != maxUserSecureSessions {
		t.Fatalf("session count=%d, want bounded %d", count, maxUserSecureSessions)
	}
}

func TestSecureChannelSessionBookkeepingConcurrent(t *testing.T) {
	h := &UserSecureChannelHandler{
		sessions:   make(map[string]*userSession),
		handshakes: make(map[string]*handshakeWindow),
	}
	now := time.Now()
	entry := &userSession{sess: &securechan.Session{}, createdAt: now, lastUsed: now}
	h.storeSession("session", entry, now)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for iteration := 0; iteration < 100; iteration++ {
				when := now.Add(time.Duration(offset*100+iteration) * time.Nanosecond)
				if loaded, ok := h.loadSession("session", when); ok {
					h.touchSession("session", loaded, when)
				}
				h.allowHandshake("198.51.100.1", when)
			}
		}(i)
	}
	wg.Wait()
	h.cleanup(now.Add(time.Second))
}

func TestBoundedSubscriptionCacheEvictsByBytesAndTTL(t *testing.T) {
	cache := newBoundedSubscriptionCache(5)
	now := time.Now()
	cache.put("one", []byte("123"), now)
	cache.put("two", []byte("456"), now)
	if _, ok := cache.get("one", now); ok {
		t.Fatal("oldest entry was not evicted when byte budget was exceeded")
	}
	if got, ok := cache.get("two", now); !ok || string(got) != "456" {
		t.Fatalf("new entry missing: %q, %v", got, ok)
	}
	if _, ok := cache.get("two", now.Add(subscriptionCacheTTL)); ok {
		t.Fatal("expired cache entry was returned")
	}
}

func TestBoundedSubscriptionCacheEvictsZeroByteEntriesByCount(t *testing.T) {
	cache := newBoundedSubscriptionCache(5)
	cache.maxItems = 2
	now := time.Now()
	cache.put("one", nil, now)
	cache.put("two", nil, now)
	cache.put("three", nil, now)
	if _, ok := cache.get("one", now); ok {
		t.Fatal("oldest zero-byte entry was not evicted at item limit")
	}
	if len(cache.entries) != 2 {
		t.Fatalf("zero-byte cache entries=%d, want 2", len(cache.entries))
	}
}

func TestSecureChannelResponseRecorderRejectsOversizeBody(t *testing.T) {
	recorder := &responseRecorder{body: &bytes.Buffer{}, status: http.StatusOK, limit: 4}
	if _, err := recorder.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Write([]byte("5")); !errors.Is(err, errSecureChannelResponseTooLarge) {
		t.Fatalf("oversize response error=%v", err)
	}
	if !recorder.overflow || recorder.body.String() != "1234" {
		t.Fatalf("overflow=%v buffered=%q", recorder.overflow, recorder.body.String())
	}
}

func TestBoundedGeoIPCacheEvictsAndExpires(t *testing.T) {
	cache := newBoundedGeoIPCache(2, time.Hour)
	cache.Store("192.0.2.1", "US")
	cache.Store("192.0.2.2", "DE")
	cache.Store("192.0.2.3", "JP")
	cache.mu.Lock()
	count := len(cache.entries)
	cache.mu.Unlock()
	if count != 2 {
		t.Fatalf("GeoIP cache count=%d, want 2", count)
	}

	expired := newBoundedGeoIPCache(1, -time.Second)
	expired.Store("192.0.2.4", "GB")
	if _, ok := expired.Load("192.0.2.4"); ok {
		t.Fatal("expired GeoIP value was returned")
	}
}

func testZipReader(t *testing.T, files map[string]string) *zip.Reader {
	t.Helper()
	byteFiles := make(map[string][]byte, len(files))
	for filename, content := range files {
		byteFiles[filename] = []byte(content)
	}
	return testZipReaderBytes(t, byteFiles)
}

func testZipReaderBytes(t *testing.T, files map[string][]byte) *zip.Reader {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for filename, content := range files {
		entry, err := writer.Create(filename)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	return reader
}

func validSQLiteBackupBytes(t *testing.T) []byte {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "arcway.db")
	repo, err := storage.NewTrafficRepository(databasePath)
	if err != nil {
		t.Fatalf("create SQLite backup fixture: %v", err)
	}
	if err := repo.Checkpoint(); err != nil {
		_ = repo.Close()
		t.Fatalf("checkpoint SQLite backup fixture: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("close SQLite backup fixture: %v", err)
	}
	database, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("read SQLite backup fixture: %v", err)
	}
	return database
}

func mustWriteTestFile(t *testing.T, filename, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}

func stringID(value int) string {
	return time.Unix(0, int64(value)).Format(time.RFC3339Nano)
}
