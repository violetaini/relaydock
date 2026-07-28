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
	"testing"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
)

const subscriptionTestWireGuardPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

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

func TestWireGuardSubscriptionContentStoresReferenceAndHydrates(t *testing.T) {
	repo, node := newWireGuardSubscriptionTestRepo(t)
	content := managedWireGuardSubscriptionYAML(subscriptionTestWireGuardPrivateKey)

	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, content)
	if err != nil {
		t.Fatal(err)
	}
	reference := wireGuardNodeSecretReferencePrefix + strconv.FormatInt(node.ID, 10)
	if strings.Contains(protected, subscriptionTestWireGuardPrivateKey) || !strings.Contains(protected, reference) {
		t.Fatalf("protected subscription leaked key or missed reference: %s", protected)
	}
	hydrated, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, protected)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hydrated, subscriptionTestWireGuardPrivateKey) || strings.Contains(hydrated, reference) {
		t.Fatalf("hydrated subscription did not restore key: %s", hydrated)
	}
}

func TestWireGuardSubscriptionContentRejectsForeignKeyAndCallerReference(t *testing.T) {
	repo, node := newWireGuardSubscriptionTestRepo(t)
	foreign := managedWireGuardSubscriptionYAML("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=")
	if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, foreign); !errors.Is(err, errPersistedWireGuardPrivateKey) {
		t.Fatalf("foreign key error = %v, want persisted-key rejection", err)
	}
	forged := managedWireGuardSubscriptionYAML(wireGuardNodeSecretReferencePrefix + strconv.FormatInt(node.ID, 10))
	if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, forged); !errors.Is(err, errUntrustedWireGuardSecretReference) {
		t.Fatalf("caller reference error = %v, want untrusted-reference rejection", err)
	}
}

func TestWireGuardSubscriptionContentLeavesOtherProtocolsUnchanged(t *testing.T) {
	content := "selected_node_ids: [17]\nproxies:\n  - name: ordinary-vless\n    type: vless\n    uuid: test-uuid\n"
	protected, err := protectWireGuardSubscriptionContent(context.Background(), nil, content)
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

func TestRuleEditorStoresWireGuardReferenceAndReturnsHydratedContent(t *testing.T) {
	repo, node := newWireGuardSubscriptionTestRepo(t)
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
	reference := wireGuardNodeSecretReferencePrefix + strconv.FormatInt(node.ID, 10)
	if strings.Contains(string(stored), subscriptionTestWireGuardPrivateKey) || !strings.Contains(string(stored), reference) {
		t.Fatalf("stored file was not protected: %s", stored)
	}
	versions, err := repo.ListRuleVersions(context.Background(), "saved.yaml", 10)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions = %#v, err = %v", versions, err)
	}
	if strings.Contains(versions[0].Content, subscriptionTestWireGuardPrivateKey) || !strings.Contains(versions[0].Content, reference) {
		t.Fatalf("history was not protected: %s", versions[0].Content)
	}

	for _, endpoint := range []string{"/saved.yaml", "/saved.yaml/history"} {
		getRequest := httptest.NewRequest(http.MethodGet, endpoint, nil)
		getRequest = getRequest.WithContext(auth.ContextWithUsername(getRequest.Context(), "admin"))
		getResponse := httptest.NewRecorder()
		handler.ServeHTTP(getResponse, getRequest)
		if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), subscriptionTestWireGuardPrivateKey) || strings.Contains(getResponse.Body.String(), reference) {
			t.Fatalf("GET %s status=%d body=%s", endpoint, getResponse.Code, getResponse.Body.String())
		}
	}
}

func TestRuleEditorRejectsForeignWireGuardPrivateKeyBeforeFileOrHistoryWrite(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "saved.yaml")
	original := []byte("mode: rule\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	handler := NewRuleEditorHandler(directory, repo)
	payload, _ := json.Marshal(map[string]string{"content": managedWireGuardSubscriptionYAML("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=")})
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

func TestSubscribeImportAndUploadRejectForeignWireGuardPrivateKeyBeforeWrite(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	t.Chdir(t.TempDir())
	handler := NewSubscribeFilesHandler(repo)
	foreignContent := managedWireGuardSubscriptionYAML("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=")
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
