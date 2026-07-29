package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

const subscriptionTestWireGuardPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

type gatedSubscriptionReader struct {
	reader  *bytes.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *gatedSubscriptionReader) Read(buffer []byte) (int, error) {
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
	return r.reader.Read(buffer)
}

func newWireGuardSubscriptionTestRepo(t *testing.T) (*storage.TrafficRepository, storage.Node) {
	t.Helper()
	repo := newManagedSecurityTestRepo(t)
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x53}, 32)); err != nil {
		t.Fatalf("configure node secret encryption: %v", err)
	}
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	config, err := json.Marshal(map[string]interface{}{
		"name": "managed-wg", "type": "wireguard", "server": "203.0.113.10", "port": 51820,
		"ip": "10.66.66.2", "private-key": subscriptionTestWireGuardPrivateKey,
		"public-key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", "udp": true,
		"allowed-ips": []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "admin", NodeName: "managed-wg", Protocol: "wireguard",
		ParsedConfig: string(config), ClashConfig: string(config), Enabled: true,
	})
	if err != nil {
		t.Fatalf("create managed WireGuard node: %v", err)
	}
	return repo, node
}

func managedWireGuardSubscriptionYAML(privateKey string) string {
	return "proxies:\n" +
		"  - name: managed-wg\n" +
		"    type: wireguard\n" +
		"    server: 203.0.113.10\n" +
		"    port: 51820\n" +
		"    private-key: " + privateKey + "\n" +
		"    public-key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
}

func createStoredWireGuardSubscription(t *testing.T, repo *storage.TrafficRepository, filename, name string) storage.SubscribeFile {
	t.Helper()
	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, filename, managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateSubscriptionFile(filepath.Join("subscribes", filename), []byte(protected)); err != nil {
		t.Fatal(err)
	}
	file, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name: name, Type: storage.SubscribeTypeUpload, Filename: filename, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func adminSubscribeRequest(method, target string, body *bytes.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	return request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
}

func TestWireGuardSubscriptionContentStoresReferenceAndHydrates(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	content := managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey)
	const scope = "stored-reference.yaml"

	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, scope, content, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(protected, subscriptionTestWireGuardPrivateKey) || !strings.Contains(protected, wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("protected subscription leaked key or missed reference: %s", protected)
	}
	hydrated, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, scope, protected)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hydrated, subscriptionTestWireGuardPrivateKey) || strings.Contains(hydrated, wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("hydrated subscription did not restore key: %s", hydrated)
	}
}

func TestWireGuardSubscriptionContentRejectsCallerCiphertext(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	const scope = "caller-ciphertext.yaml"
	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, scope, managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, scope, protected, false); !errors.Is(err, errUntrustedWireGuardSecret) {
		t.Fatalf("caller ciphertext error = %v, want untrusted marker rejection", err)
	}
}

func TestWireGuardSubscriptionContentLeavesOtherProtocolsUnchanged(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	content := "selected_node_ids: [17]\nproxies:\n  - name: ordinary-vless\n    type: vless\n    uuid: test-uuid\n"
	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, "ordinary.yaml", content, false)
	if err != nil {
		t.Fatal(err)
	}
	if protected != content {
		t.Fatalf("ordinary config changed: %q", protected)
	}
}

func TestWritePrivateSubscriptionFileRestrictsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode assertion")
	}
	directory := filepath.Join(t.TempDir(), "subscribes")
	path := filepath.Join(directory, "test.yaml")
	if err := writePrivateSubscriptionFile(path, []byte("mode: rule\n")); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("file mode = %o, want 600", got)
	}
}

func TestWriteNewPrivateSubscriptionFileNeverDeletesExistingTarget(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "occupied.yaml")
	const existing = "mode: rule\n# existing owner\n"
	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeNewPrivateSubscriptionFile(path, []byte("mode: direct\n")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive write error = %v, want %v", err, os.ErrExist)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != existing {
		t.Fatalf("existing target changed: content=%q err=%v", content, err)
	}
}

func TestOwnedSubscriptionCleanupPreservesReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "replacement.yaml")
	ownership, err := writeNewPrivateSubscriptionFile(path, []byte("mode: rule\n"))
	if err != nil {
		t.Fatal(err)
	}
	replacementPath := filepath.Join(directory, "replacement.tmp")
	const replacement = "mode: direct\n"
	if err := os.WriteFile(replacementPath, []byte(replacement), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, path); err != nil {
		t.Fatal(err)
	}
	if err := removeSubscriptionFileIfOwned(path, ownership); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != replacement {
		t.Fatalf("ownership cleanup removed a replacement: content=%q err=%v", content, err)
	}
}

func TestRuleEditorStoresWireGuardReferenceAndReturnsHydratedContent(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "saved.yaml")
	if err := os.WriteFile(path, []byte("mode: rule\n"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := NewRuleEditorHandler(directory, repo)
	payload, _ := json.Marshal(map[string]string{"content": managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey)})
	request := httptest.NewRequest(http.MethodPut, "/saved.yaml", bytes.NewReader(payload))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", response.Code, response.Body.String())
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), subscriptionTestWireGuardPrivateKey) || !strings.Contains(string(stored), wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("stored file was not protected: %s", stored)
	}
	versions, err := repo.ListRuleVersions(context.Background(), "saved.yaml", 10)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions = %#v, err = %v", versions, err)
	}
	if strings.Contains(versions[0].Content, subscriptionTestWireGuardPrivateKey) || !strings.Contains(versions[0].Content, wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("history was not protected: %s", versions[0].Content)
	}

	for _, endpoint := range []string{"/saved.yaml", "/saved.yaml/history"} {
		getRequest := httptest.NewRequest(http.MethodGet, endpoint, nil)
		getRequest = getRequest.WithContext(auth.ContextWithUsername(getRequest.Context(), "admin"))
		getResponse := httptest.NewRecorder()
		handler.ServeHTTP(getResponse, getRequest)
		if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), subscriptionTestWireGuardPrivateKey) || strings.Contains(getResponse.Body.String(), wireGuardSubscriptionSecretPrefix) {
			t.Fatalf("GET %s status=%d body=%s", endpoint, getResponse.Code, getResponse.Body.String())
		}
	}
}

func TestRuleEditorRejectsInvalidWireGuardPrivateKeyBeforeFileOrHistoryWrite(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "saved.yaml")
	original := []byte("mode: rule\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	handler := NewRuleEditorHandler(directory, repo)
	payload, _ := json.Marshal(map[string]string{"content": managedWireGuardSubscriptionYAML("not-a-wireguard-private-key")})
	request := httptest.NewRequest(http.MethodPut, "/saved.yaml", bytes.NewReader(payload))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, original) {
		t.Fatalf("file changed after rejected update: %q", stored)
	}
	versions, err := repo.ListRuleVersions(request.Context(), "saved.yaml", 10)
	if err != nil || len(versions) != 0 {
		t.Fatalf("stored plaintext history versions = %d, err = %v", len(versions), err)
	}
}

func TestSubscribeImportAndUploadRejectInvalidWireGuardPrivateKeyBeforeWrite(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	handler := NewSubscribeFilesHandler(repo)
	foreignContent := managedWireGuardSubscriptionYAML("not-a-wireguard-private-key")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(foreignContent))
	}))
	defer upstream.Close()

	importPayload, _ := json.Marshal(map[string]string{
		"name": "foreign-import", "url": upstream.URL, "filename": "foreign-import.yaml",
	})
	importRequest := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/import", bytes.NewReader(importPayload))
	importRequest = importRequest.WithContext(auth.ContextWithUsername(importRequest.Context(), "admin"))
	importResponse := httptest.NewRecorder()
	handler.ServeHTTP(importResponse, importRequest)
	if importResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("import status=%d body=%s", importResponse.Code, importResponse.Body.String())
	}
	if _, err := os.Stat(filepath.Join("subscribes", "foreign-import.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign import wrote a file: %v", err)
	}

	var uploadBody bytes.Buffer
	writer := multipart.NewWriter(&uploadBody)
	_ = writer.WriteField("name", "foreign-upload")
	_ = writer.WriteField("filename", "foreign-upload.yaml")
	part, err := writer.CreateFormFile("file", "foreign-upload.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(foreignContent))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	uploadRequest := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/upload", &uploadBody)
	uploadRequest.Header.Set("Content-Type", writer.FormDataContentType())
	uploadRequest = uploadRequest.WithContext(auth.ContextWithUsername(uploadRequest.Context(), "admin"))
	uploadResponse := httptest.NewRecorder()
	handler.ServeHTTP(uploadResponse, uploadRequest)
	if uploadResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("upload status=%d body=%s", uploadResponse.Code, uploadResponse.Body.String())
	}
	if _, err := os.Stat(filepath.Join("subscribes", "foreign-upload.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign upload wrote a file: %v", err)
	}
}

func TestSubscribeFilenameRenameRebindsWireGuardFileAndHistory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode assertion")
	}
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}

	const oldFilename = "wireguard-old.yaml"
	const newFilename = "wireguard-new.yaml"
	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, oldFilename, managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey), false)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join("subscribes", oldFilename)
	if err := writePrivateSubscriptionFile(oldPath, []byte(protected)); err != nil {
		t.Fatal(err)
	}
	file, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name:      "wireguard rename",
		Type:      storage.SubscribeTypeUpload,
		Filename:  oldFilename,
		CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		versionContent, err := protectWireGuardSubscriptionContent(context.Background(), repo, oldFilename, managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey), false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.SaveRuleVersion(context.Background(), oldFilename, versionContent, "admin"); err != nil {
			t.Fatal(err)
		}
	}

	payload, _ := json.Marshal(map[string]string{"filename": newFilename})
	request := httptest.NewRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(file.ID, 10), bytes.NewReader(payload))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	response := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", response.Code, response.Body.String())
	}

	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old file still exists after committed rename: %v", err)
	}
	newPath := filepath.Join("subscribes", newFilename)
	stored, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), subscriptionTestWireGuardPrivateKey) || !strings.Contains(string(stored), wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("renamed file leaked key or missed ciphertext: %s", stored)
	}
	if info, err := os.Stat(newPath); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("renamed file mode=%o, want 600", got)
	}
	if _, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, oldFilename, string(stored)); err == nil {
		t.Fatal("renamed file still decrypts with old filename scope")
	}
	hydrated, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, newFilename, string(stored))
	if err != nil || !strings.Contains(hydrated, subscriptionTestWireGuardPrivateKey) {
		t.Fatalf("renamed file cannot hydrate with new scope: content=%q err=%v", hydrated, err)
	}

	updated, err := repo.GetSubscribeFileByID(context.Background(), file.ID)
	if err != nil || updated.Filename != newFilename {
		t.Fatalf("updated subscription=%#v err=%v", updated, err)
	}
	oldVersions, err := repo.ListRuleVersions(context.Background(), oldFilename, 10)
	if err != nil || len(oldVersions) != 0 {
		t.Fatalf("old versions=%d err=%v", len(oldVersions), err)
	}
	newVersions, err := repo.ListRuleVersions(context.Background(), newFilename, 10)
	if err != nil || len(newVersions) != 2 {
		t.Fatalf("new versions=%d err=%v", len(newVersions), err)
	}
	for _, version := range newVersions {
		if strings.Contains(version.Content, subscriptionTestWireGuardPrivateKey) || !strings.Contains(version.Content, wireGuardSubscriptionSecretPrefix) {
			t.Fatalf("renamed history leaked key or missed ciphertext: %s", version.Content)
		}
		hydrated, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, newFilename, version.Content)
		if err != nil || !strings.Contains(hydrated, subscriptionTestWireGuardPrivateKey) {
			t.Fatalf("renamed history cannot hydrate: content=%q err=%v", hydrated, err)
		}
	}
}

func TestSubscribeFilenameRenameDatabaseFailureKeepsOldFileAndHistory(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}

	const oldFilename = "rollback-old.yaml"
	const newFilename = "rollback-new.yaml"
	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, oldFilename, managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey), false)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join("subscribes", oldFilename)
	if err := writePrivateSubscriptionFile(oldPath, []byte(protected)); err != nil {
		t.Fatal(err)
	}
	file, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name:      "rename source",
		Type:      storage.SubscribeTypeUpload,
		Filename:  oldFilename,
		CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name:      "duplicate name",
		Type:      storage.SubscribeTypeUpload,
		Filename:  "other.yaml",
		CreatedBy: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRuleVersion(context.Background(), oldFilename, protected, "admin"); err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]string{"name": "duplicate name", "filename": newFilename})
	request := httptest.NewRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(file.ID, 10), bytes.NewReader(payload))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	response := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("rename status=%d body=%s", response.Code, response.Body.String())
	}

	stored, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("old file was lost after rollback: %v", err)
	}
	if string(stored) != protected {
		t.Fatalf("old file changed after rollback: %s", stored)
	}
	if _, err := os.Stat(filepath.Join("subscribes", newFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new file remained after rollback: %v", err)
	}
	unchanged, err := repo.GetSubscribeFileByID(context.Background(), file.ID)
	if err != nil || unchanged.Filename != oldFilename || unchanged.Name != "rename source" {
		t.Fatalf("subscription changed after rollback: %#v err=%v", unchanged, err)
	}
	oldVersions, err := repo.ListRuleVersions(context.Background(), oldFilename, 10)
	if err != nil || len(oldVersions) != 1 {
		t.Fatalf("old history after rollback=%#v err=%v", oldVersions, err)
	}
	if _, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, oldFilename, oldVersions[0].Content); err != nil {
		t.Fatalf("old history became unusable after rollback: %v", err)
	}
	newVersions, err := repo.ListRuleVersions(context.Background(), newFilename, 10)
	if err != nil || len(newVersions) != 0 {
		t.Fatalf("new history remained after rollback=%#v err=%v", newVersions, err)
	}
}

func TestSubscribeFilenameRenameRejectsExistingTargetWhenOldFileMissing(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}

	const oldFilename = "missing-old.yaml"
	const newFilename = "occupied-new.yaml"
	file, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name:      "missing physical source",
		Type:      storage.SubscribeTypeUpload,
		Filename:  oldFilename,
		CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, oldFilename, managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRuleVersion(context.Background(), oldFilename, protected, "admin"); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join("subscribes", newFilename)
	const targetContent = "mode: rule\n# unrelated existing file\n"
	if err := writePrivateSubscriptionFile(targetPath, []byte(targetContent)); err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]string{"filename": newFilename})
	request := httptest.NewRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(file.ID, 10), bytes.NewReader(payload))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	response := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("rename status=%d body=%s", response.Code, response.Body.String())
	}

	target, err := os.ReadFile(targetPath)
	if err != nil || string(target) != targetContent {
		t.Fatalf("existing target was changed: content=%q err=%v", target, err)
	}
	unchanged, err := repo.GetSubscribeFileByID(context.Background(), file.ID)
	if err != nil || unchanged.Filename != oldFilename {
		t.Fatalf("subscription changed despite occupied target: %#v err=%v", unchanged, err)
	}
	oldVersions, err := repo.ListRuleVersions(context.Background(), oldFilename, 10)
	if err != nil || len(oldVersions) != 1 {
		t.Fatalf("old history changed despite occupied target: %#v err=%v", oldVersions, err)
	}
	if _, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, oldFilename, oldVersions[0].Content); err != nil {
		t.Fatalf("old history became unusable: %v", err)
	}
	newVersions, err := repo.ListRuleVersions(context.Background(), newFilename, 10)
	if err != nil || len(newVersions) != 0 {
		t.Fatalf("history moved to occupied target: %#v err=%v", newVersions, err)
	}
}

func TestSubscribeCreateEndpointsRejectPathTraversal(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	root := t.TempDir()
	t.Chdir(root)
	handler := NewSubscribeFilesHandler(repo)
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		_, _ = w.Write([]byte("mode: rule\n"))
	}))
	defer upstream.Close()

	requests := []struct {
		name    string
		target  string
		request *http.Request
	}{
		{
			name:   "metadata create",
			target: "/api/admin/subscribe-files",
			request: adminSubscribeRequest(http.MethodPost, "/api/admin/subscribe-files", bytes.NewReader([]byte(
				`{"name":"escape","url":"https://example.invalid","type":"upload","filename":"../outside.yaml"}`))),
		},
		{
			name:   "remote import",
			target: "/api/admin/subscribe-files/import",
			request: adminSubscribeRequest(http.MethodPost, "/api/admin/subscribe-files/import", bytes.NewReader([]byte(
				`{"name":"escape","url":"`+upstream.URL+`","filename":"../outside.yaml"}`))),
		},
		{
			name:   "generated config",
			target: "/api/admin/subscribe-files/create-from-config",
			request: adminSubscribeRequest(http.MethodPost, "/api/admin/subscribe-files/create-from-config", bytes.NewReader([]byte(
				`{"name":"escape","filename":"../outside.yaml","content":"mode: rule\n"}`))),
		},
	}

	var uploadBody bytes.Buffer
	uploadWriter := multipart.NewWriter(&uploadBody)
	_ = uploadWriter.WriteField("name", "escape")
	_ = uploadWriter.WriteField("filename", "../outside.yaml")
	part, err := uploadWriter.CreateFormFile("file", "outside.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("mode: rule\n"))
	if err := uploadWriter.Close(); err != nil {
		t.Fatal(err)
	}
	uploadRequest := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/upload", &uploadBody)
	uploadRequest.Header.Set("Content-Type", uploadWriter.FormDataContentType())
	uploadRequest = uploadRequest.WithContext(auth.ContextWithUsername(uploadRequest.Context(), "admin"))
	requests = append(requests, struct {
		name    string
		target  string
		request *http.Request
	}{name: "upload", target: "/api/admin/subscribe-files/upload", request: uploadRequest})

	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, test.request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if upstreamCalled {
		t.Fatal("path-traversal import contacted its upstream before rejecting the filename")
	}
	if _, err := os.Stat(filepath.Join(root, "outside.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path traversal created an outside file: %v", err)
	}
	files, err := repo.ListSubscribeFiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("path traversal created database rows: %#v", files)
	}
}

func TestSubscribeRenameSerializesWithRuleEditorWrite(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	const oldFilename = "serialize-old.yaml"
	const newFilename = "serialize-new.yaml"
	file := createStoredWireGuardSubscription(t, repo, oldFilename, "serialized rename")

	payload, _ := json.Marshal(map[string]string{"content": managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey)})
	gated := &gatedSubscriptionReader{
		reader: bytes.NewReader(payload), started: make(chan struct{}), release: make(chan struct{}),
	}
	updateRequest := httptest.NewRequest(http.MethodPut, "/"+oldFilename, gated)
	updateRequest = updateRequest.WithContext(auth.ContextWithUsername(updateRequest.Context(), "admin"))
	updateDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		NewRuleEditorHandler("subscribes", repo).ServeHTTP(response, updateRequest)
		updateDone <- response
	}()
	select {
	case <-gated.started:
	case <-time.After(2 * time.Second):
		t.Fatal("rule editor did not reach its locked body read")
	}

	renamePayload, _ := json.Marshal(map[string]string{"filename": newFilename})
	renameRequest := adminSubscribeRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(file.ID, 10), bytes.NewReader(renamePayload))
	renameStarted := make(chan struct{})
	renameDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		close(renameStarted)
		response := httptest.NewRecorder()
		NewSubscribeFilesHandler(repo).ServeHTTP(response, renameRequest)
		renameDone <- response
	}()
	<-renameStarted
	select {
	case response := <-renameDone:
		t.Fatalf("rename escaped the old-filename lock: status=%d body=%s", response.Code, response.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	close(gated.release)

	updateResponse := <-updateDone
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("rule update status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
	renameResponse := <-renameDone
	if renameResponse.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", renameResponse.Code, renameResponse.Body.String())
	}
	if _, err := os.Stat(filepath.Join("subscribes", oldFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old file exists after serialized rename: %v", err)
	}
	stored, err := os.ReadFile(filepath.Join("subscribes", newFilename))
	if err != nil {
		t.Fatal(err)
	}
	hydrated, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, newFilename, string(stored))
	if err != nil || !strings.Contains(hydrated, subscriptionTestWireGuardPrivateKey) {
		t.Fatalf("final file cannot hydrate in new scope: content=%q err=%v", hydrated, err)
	}
	oldVersions, err := repo.ListRuleVersions(context.Background(), oldFilename, 10)
	if err != nil || len(oldVersions) != 0 {
		t.Fatalf("old-scope history remained: %#v err=%v", oldVersions, err)
	}
	newVersions, err := repo.ListRuleVersions(context.Background(), newFilename, 10)
	if err != nil || len(newVersions) != 1 {
		t.Fatalf("new-scope history=%#v err=%v", newVersions, err)
	}
	if _, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, newFilename, newVersions[0].Content); err != nil {
		t.Fatalf("renamed history cannot hydrate: %v", err)
	}
}

func TestConcurrentSubscribeRenamesAllowOnlyOneTargetOwner(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	first := createStoredWireGuardSubscription(t, repo, "race-first.yaml", "race first")
	second := createStoredWireGuardSubscription(t, repo, "race-second.yaml", "race second")
	const target = "race-target.yaml"

	type renameResult struct {
		id       int64
		response *httptest.ResponseRecorder
	}
	start := make(chan struct{})
	results := make(chan renameResult, 2)
	for _, file := range []storage.SubscribeFile{first, second} {
		file := file
		go func() {
			<-start
			payload, _ := json.Marshal(map[string]string{"filename": target})
			request := adminSubscribeRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(file.ID, 10), bytes.NewReader(payload))
			response := httptest.NewRecorder()
			NewSubscribeFilesHandler(repo).ServeHTTP(response, request)
			results <- renameResult{id: file.ID, response: response}
		}()
	}
	close(start)
	firstResult, secondResult := <-results, <-results
	successes, conflicts := 0, 0
	for _, result := range []renameResult{firstResult, secondResult} {
		switch result.response.Code {
		case http.StatusOK:
			successes++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("rename id=%d status=%d body=%s", result.id, result.response.Code, result.response.Body.String())
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("rename outcomes: successes=%d conflicts=%d", successes, conflicts)
	}

	updatedFirst, err := repo.GetSubscribeFileByID(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	updatedSecond, err := repo.GetSubscribeFileByID(context.Background(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	targetOwners := 0
	for _, file := range []storage.SubscribeFile{updatedFirst, updatedSecond} {
		if file.Filename == target {
			targetOwners++
		}
	}
	if targetOwners != 1 {
		t.Fatalf("database target owners=%d: first=%q second=%q", targetOwners, updatedFirst.Filename, updatedSecond.Filename)
	}
	stored, err := os.ReadFile(filepath.Join("subscribes", target))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, target, string(stored)); err != nil {
		t.Fatalf("winning target cannot hydrate: %v", err)
	}
}

func TestDeleteSubscribeClearsHistoryBeforeFilenameReuse(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	const filename = "reused.yaml"
	file := createStoredWireGuardSubscription(t, repo, filename, "old owner")
	oldStored, err := os.ReadFile(filepath.Join("subscribes", filename))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRuleVersionForSubscribe(context.Background(), file.ID, filename, string(oldStored), "admin"); err != nil {
		t.Fatal(err)
	}

	deleteRequest := adminSubscribeRequest(http.MethodDelete, "/api/admin/subscribe-files/"+strconv.FormatInt(file.ID, 10), bytes.NewReader(nil))
	deleteResponse := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	versions, err := repo.ListRuleVersions(context.Background(), filename, 10)
	if err != nil || len(versions) != 0 {
		t.Fatalf("deleted subscription history remained: %#v err=%v", versions, err)
	}
	if _, err := os.Stat(filepath.Join("subscribes", filename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted subscription file remained: %v", err)
	}

	newPrivateKey := strings.Repeat("C", 43) + "="
	var uploadBody bytes.Buffer
	uploadWriter := multipart.NewWriter(&uploadBody)
	_ = uploadWriter.WriteField("name", "new owner")
	_ = uploadWriter.WriteField("filename", filename)
	part, err := uploadWriter.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(managedWireGuardSubscriptionYAML(newPrivateKey)))
	if err := uploadWriter.Close(); err != nil {
		t.Fatal(err)
	}
	uploadRequest := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/upload", &uploadBody)
	uploadRequest.Header.Set("Content-Type", uploadWriter.FormDataContentType())
	uploadRequest = uploadRequest.WithContext(auth.ContextWithUsername(uploadRequest.Context(), "admin"))
	uploadResponse := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(uploadResponse, uploadRequest)
	if uploadResponse.Code != http.StatusCreated {
		t.Fatalf("reuse upload status=%d body=%s", uploadResponse.Code, uploadResponse.Body.String())
	}
	versions, err = repo.ListRuleVersions(context.Background(), filename, 10)
	if err != nil || len(versions) != 0 {
		t.Fatalf("new subscription inherited history: %#v err=%v", versions, err)
	}

	getRequest := adminSubscribeRequest(http.MethodGet, "/api/admin/subscribe-files/"+filename+"/content", bytes.NewReader(nil))
	getResponse := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK {
		t.Fatalf("get reused subscription status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
	if !strings.Contains(getResponse.Body.String(), newPrivateKey) || strings.Contains(getResponse.Body.String(), subscriptionTestWireGuardPrivateKey) {
		t.Fatalf("reused subscription exposed the wrong key: %s", getResponse.Body.String())
	}
}

func TestDeleteSubscribeRejectsStaleFilenameAfterRename(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	const oldFilename = "delete-stale-old.yaml"
	const newFilename = "delete-stale-new.yaml"
	stale := createStoredWireGuardSubscription(t, repo, oldFilename, "stale delete")

	payload, _ := json.Marshal(map[string]string{"filename": newFilename})
	request := adminSubscribeRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(stale.ID, 10), bytes.NewReader(payload))
	response := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", response.Code, response.Body.String())
	}

	err := deleteSubscribeFileAndPhysical(context.Background(), repo, "subscribes", stale)
	if !errors.Is(err, storage.ErrSubscribeFileChanged) {
		t.Fatalf("stale delete error=%v, want %v", err, storage.ErrSubscribeFileChanged)
	}
	current, err := repo.GetSubscribeFileByID(context.Background(), stale.ID)
	if err != nil || current.Filename != newFilename {
		t.Fatalf("renamed subscription was deleted or changed: %#v err=%v", current, err)
	}
	if _, err := os.Stat(filepath.Join("subscribes", newFilename)); err != nil {
		t.Fatalf("renamed physical file was deleted: %v", err)
	}
}

func TestDeleteSubscribePreservesFileOwnedBySubscriptionLink(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	const filename = "shared-link.yaml"
	file := createStoredWireGuardSubscription(t, repo, filename, "managed owner")
	stored, err := os.ReadFile(filepath.Join("subscribes", filename))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRuleVersionForSubscribe(context.Background(), file.ID, filename, string(stored), "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateSubscriptionLink(context.Background(), storage.SubscriptionLink{
		Name: "public link", Type: "clash", RuleFilename: filename,
	}); err != nil {
		t.Fatal(err)
	}

	if err := deleteSubscribeFileAndPhysical(context.Background(), repo, "subscribes", file); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetSubscribeFileByID(context.Background(), file.ID); !errors.Is(err, storage.ErrSubscribeFileNotFound) {
		t.Fatalf("subscription row remained: %v", err)
	}
	if _, err := os.Stat(filepath.Join("subscribes", filename)); err != nil {
		t.Fatalf("shared physical file was removed: %v", err)
	}
	versions, err := repo.ListRuleVersions(context.Background(), filename, 10)
	if err != nil || len(versions) != 1 {
		t.Fatalf("shared rule history was removed: %#v err=%v", versions, err)
	}
}

func TestRenameSubscribeMovesActiveSubscriptionLinkOwner(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	const oldFilename = "shared-rename-old.yaml"
	const newFilename = "shared-rename-new.yaml"
	file := createStoredWireGuardSubscription(t, repo, oldFilename, "shared rename")
	link, err := repo.CreateSubscriptionLink(context.Background(), storage.SubscriptionLink{
		Name: "public rename link", Type: "clash", RuleFilename: oldFilename,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]string{"filename": newFilename})
	request := adminSubscribeRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(file.ID, 10), bytes.NewReader(payload))
	response := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", response.Code, response.Body.String())
	}
	updatedLink, err := repo.GetSubscriptionByID(context.Background(), link.ID)
	if err != nil || updatedLink.RuleFilename != newFilename {
		t.Fatalf("linked owner did not follow rename: %#v err=%v", updatedLink, err)
	}
	if _, err := os.Stat(filepath.Join("subscribes", newFilename)); err != nil {
		t.Fatalf("renamed shared file is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join("subscribes", oldFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old shared file remained active: %v", err)
	}
}

func TestRenameSubscribeRejectsMissingSourceWithoutCreatingTarget(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("ARCWAY_SUBSCRIPTION_STORE_LOCK_PATH", filepath.Join(root, "locks", "subscription-store.lock"))
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	const oldFilename = "missing-source-old.yaml"
	const newFilename = "missing-source-new.yaml"
	file := createStoredWireGuardSubscription(t, repo, oldFilename, "missing source")
	if err := os.Remove(filepath.Join("subscribes", oldFilename)); err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]string{"filename": newFilename})
	request := adminSubscribeRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(file.ID, 10), bytes.NewReader(payload))
	response := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatalf("rename unexpectedly succeeded: %s", response.Body.String())
	}

	stored, err := repo.GetSubscribeFileByID(context.Background(), file.ID)
	if err != nil || stored.Filename != oldFilename {
		t.Fatalf("database owner moved despite missing source: %#v err=%v", stored, err)
	}
	if _, err := os.Stat(filepath.Join("subscribes", newFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rename created a target without a source: %v", err)
	}
}

func TestDeleteSubscriptionLinkPreservesFileOwnedBySubscribeFile(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("ARCWAY_SUBSCRIPTION_STORE_LOCK_PATH", filepath.Join(root, "locks", "subscription-store.lock"))
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	const filename = "shared-managed-file.yaml"
	file := createStoredWireGuardSubscription(t, repo, filename, "managed owner")
	link, err := repo.CreateSubscriptionLink(context.Background(), storage.SubscriptionLink{
		Name: "temporary public owner", Type: "clash", RuleFilename: filename,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := adminSubscribeRequest(http.MethodDelete, "/api/admin/subscriptions/"+strconv.FormatInt(link.ID, 10), bytes.NewReader(nil))
	response := httptest.NewRecorder()
	NewSubscriptionAdminHandler("subscribes", repo).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("delete link status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := repo.GetSubscriptionByID(context.Background(), link.ID); !errors.Is(err, storage.ErrSubscriptionNotFound) {
		t.Fatalf("subscription link remained: %v", err)
	}
	stored, err := repo.GetSubscribeFileByID(context.Background(), file.ID)
	if err != nil || stored.Filename != filename {
		t.Fatalf("managed owner was changed: %#v err=%v", stored, err)
	}
	if _, err := os.Stat(filepath.Join("subscribes", filename)); err != nil {
		t.Fatalf("shared physical file was removed: %v", err)
	}
}
