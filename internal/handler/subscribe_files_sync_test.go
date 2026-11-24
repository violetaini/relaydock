package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestSubscribeFileSyncAndAutoUpdate(t *testing.T) {
	tempDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "user1", storage.RoleUser)

	// Mock 外部订阅服务器
	mockYAML := `proxies:
  - name: test-external-node
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: password
`
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockYAML))
	}))
	defer mockServer.Close()

	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}

	// 初始文件
	initialFile := filepath.Join("subscribes", "ext_test.yaml")
	if err := os.WriteFile(initialFile, []byte("proxies: []\n"), 0600); err != nil {
		t.Fatal(err)
	}

	sf, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name:               "External Sub",
		URL:                mockServer.URL,
		Type:               storage.SubscribeTypeImport,
		Filename:           "ext_test.yaml",
		CreatedBy:          "admin",
		AutoUpdateInterval: 7200,
	})
	if err != nil {
		t.Fatalf("CreateSubscribeFile: %v", err)
	}

	h := &subscribeFilesHandler{
		repo:        repo,
		fetchClient: mockServer.Client(),
	}

	// 1. 测试普通用户 user1 尝试同步 admin 的订阅 -> 应返回 404
	reqUser := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/"+strconv.FormatInt(sf.ID, 10)+"/sync", nil)
	reqUser = reqUser.WithContext(auth.ContextWithUsername(context.Background(), "user1"))
	recUser := httptest.NewRecorder()
	h.ServeHTTP(recUser, reqUser)
	if recUser.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-owner user, got %d: %s", recUser.Code, recUser.Body.String())
	}

	// 2. 测试 admin 手动同步该订阅 -> 应返回 200，且 LastSyncAt 被更新
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/"+strconv.FormatInt(sf.ID, 10)+"/sync", nil)
	reqAdmin = reqAdmin.WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	recAdmin := httptest.NewRecorder()
	h.ServeHTTP(recAdmin, reqAdmin)
	if recAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin sync, got %d: %s", recAdmin.Code, recAdmin.Body.String())
	}

	var resp struct {
		File subscribeFileDTO `json:"file"`
	}
	if err := json.Unmarshal(recAdmin.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal sync response: %v", err)
	}

	if resp.File.AutoUpdateInterval != 7200 {
		t.Errorf("expected auto_update_interval=7200, got %d", resp.File.AutoUpdateInterval)
	}
	if resp.File.LastSyncAt == nil {
		t.Errorf("expected last_sync_at to be non-nil after sync")
	}

	// 3. 检查物理文件内容是否已被同步更新
	content, err := os.ReadFile(initialFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte("test-external-node")) {
		t.Errorf("expected physical file to contain 'test-external-node', got:\n%s", string(content))
	}

	// 4. 测试更新 auto_update_interval
	newInterval := 14400
	updateBody, _ := json.Marshal(subscribeFileRequest{
		Name:               sf.Name,
		Filename:           sf.Filename,
		AutoUpdateInterval: &newInterval,
	})
	reqUpdate := httptest.NewRequest(http.MethodPut, "/api/admin/subscribe-files/"+strconv.FormatInt(sf.ID, 10), bytes.NewReader(updateBody))
	reqUpdate = reqUpdate.WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	recUpdate := httptest.NewRecorder()
	h.ServeHTTP(recUpdate, reqUpdate)
	if recUpdate.Code != http.StatusOK {
		t.Fatalf("expected 200 for update, got %d: %s", recUpdate.Code, recUpdate.Body.String())
	}

	reloaded, err := repo.GetSubscribeFileByID(context.Background(), sf.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.AutoUpdateInterval != 14400 {
		t.Errorf("expected updated auto_update_interval=14400, got %d", reloaded.AutoUpdateInterval)
	}
}
