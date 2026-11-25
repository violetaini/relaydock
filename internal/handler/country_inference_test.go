package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestInferCountryCodeFromName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Emoji HK", "🇭🇰 香港 IPLC 01", "HK"},
		{"Emoji JP", "🇯🇵 日本 东京 [2.0x]", "JP"},
		{"Emoji US", "🇺🇸 美国 洛杉矶 BGP", "US"},
		{"Emoji TW", "🇹🇼 台湾 彰化 中继", "TW"},
		{"Emoji SG", "🇸🇬 新加坡 狮城", "SG"},
		{"Emoji KR", "🇰🇷 韩国 首尔", "KR"},
		{"Emoji GB", "🇬🇧 英国 伦敦", "GB"},
		{"Emoji DE", "🇩🇪 德国 法兰克福", "DE"},
		{"IATA HKG", "HKG-Premium-01", "HK"},
		{"IATA NRT", "Tokyo-NRT-Direct", "JP"},
		{"IATA LAX", "US-LAX-Core", "US"},
		{"IATA SIN", "SIN-Relay-05", "SG"},
		{"IATA TPE", "Taipei-TPE-Fast", "TW"},
		{"Prefix bracket [HK]", "[HK] 优质专线 02", "HK"},
		{"Prefix hyphen SG-", "SG-01-HighSpeed", "SG"},
		{"Traditional Chinese 臺灣", "臺灣 臺北 專線", "TW"},
		{"Traditional Chinese 澳門", "澳門 01 節點", "MO"},
		{"Russian", "莫斯科 节点 01", "RU"},
		{"Unknown", "专线中继01", "UN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferCountryCodeFromName(tt.input)
			if got != tt.expected {
				t.Errorf("inferCountryCodeFromName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExternalSubscriptionParsePreviewAndSyncPruning(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}
	defer repo.Close()

	_ = repo.CreateUser(context.Background(), "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, "")

	subscribeDir := filepath.Join(dir, "subscribes")
	_ = os.MkdirAll(subscribeDir, 0755)

	upstreamContent := `
proxies:
  - name: "🇭🇰 香港 01"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: test
  - name: "Tokyo-NRT-02"
    type: vless
    server: 2.2.2.2
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
  - name: "Custom-Unassigned"
    type: trojan
    server: 3.3.3.3
    port: 443
    password: pass
`

	upstreamStatus := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.WriteHeader(upstreamStatus)
		_, _ = w.Write([]byte(upstreamContent))
	}))
	defer server.Close()

	handler := NewSubscribeFilesHandler(repo)
	handler.(*subscribeFilesHandler).fetchClient = server.Client()

	// 1. 测试 parse-preview 接口
	previewReqBody, _ := json.Marshal(map[string]string{
		"url": server.URL,
	})
	previewReq := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/parse-preview", bytes.NewReader(previewReqBody))
	previewReq = previewReq.WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	previewRec := httptest.NewRecorder()

	handler.ServeHTTP(previewRec, previewReq)
	if previewRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from parse-preview, got %d: %s", previewRec.Code, previewRec.Body.String())
	}

	var previewResp struct {
		Count int `json:"count"`
		Nodes []struct {
			Key         string `json:"key"`
			Name        string `json:"name"`
			Type        string `json:"type"`
			CountryCode string `json:"country_code"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(previewRec.Body.Bytes(), &previewResp); err != nil {
		t.Fatalf("failed to decode preview response: %v", err)
	}

	if previewResp.Count != 3 {
		t.Fatalf("expected 3 nodes in preview, got %d", previewResp.Count)
	}
	if previewResp.Nodes[0].CountryCode != "HK" {
		t.Errorf("expected node 0 country code HK, got %s", previewResp.Nodes[0].CountryCode)
	}
	if previewResp.Nodes[1].CountryCode != "JP" {
		t.Errorf("expected node 1 country code JP, got %s", previewResp.Nodes[1].CountryCode)
	}

	// 2. 测试带自定义地区映射的导入 (用户改选第三个节点为 "US")
	customKey := previewResp.Nodes[2].Key
	nodeRegions := map[string]string{
		customKey: "US",
	}

	importReqBody, _ := json.Marshal(map[string]any{
		"name":         "外部测试订阅",
		"url":          server.URL,
		"node_regions": nodeRegions,
	})
	importReq := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/import", bytes.NewReader(importReqBody))
	importReq = importReq.WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	importRec := httptest.NewRecorder()

	handler.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from import, got %d: %s", importRec.Code, importRec.Body.String())
	}

	files, _ := repo.ListSubscribeFiles(context.Background())
	if len(files) == 0 {
		t.Fatalf("expected at least 1 file imported")
	}
	importedFile := files[0]
	if importedFile.Generation == nil || importedFile.Generation.Processing.NodeRegions[customKey] != "US" {
		t.Fatalf("expected node_regions to have custom key mapped to US")
	}

	// 3. 测试自动更新 / 同步时节点变化与旧映射剔除 (Requirement 3)
	// 上游移除了第三个节点，并新增了一个新加坡节点
	updatedUpstreamContent := `
proxies:
  - name: "🇭🇰 香港 01"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: test
  - name: "Tokyo-NRT-02"
    type: vless
    server: 2.2.2.2
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
  - name: "🇸🇬 新加坡 01"
    type: ss
    server: 4.4.4.4
    port: 8388
    cipher: aes-128-gcm
    password: test
`
	upstreamContent = updatedUpstreamContent

	// 执行同步
	syncReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/admin/subscribe-files/%d/sync", importedFile.ID), nil)
	syncReq = syncReq.WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	syncRec := httptest.NewRecorder()

	handler.ServeHTTP(syncRec, syncReq)

	reloaded, err := repo.GetSubscribeFileByID(context.Background(), importedFile.ID)
	if err != nil {
		t.Fatalf("failed to reload file: %v", err)
	}

	// 验证：旧的已删除节点 customKey 必须已被剔除！
	if _, exists := reloaded.Generation.Processing.NodeRegions[customKey]; exists {
		t.Errorf("expected deleted node %s to be pruned from node_regions, but it still exists", customKey)
	}

	// 验证：新节点（新加坡）必须已重新映射地区并存入 NodeRegions！
	foundSG := false
	for _, cc := range reloaded.Generation.Processing.NodeRegions {
		if cc == "SG" {
			foundSG = true
			break
		}
	}
	if !foundSG {
		t.Errorf("expected new Singapore node to be mapped to SG in node_regions")
	}

	// 4. 测试同步失败时记录 LastSyncError 且不破坏已有配置
	upstreamStatus = http.StatusInternalServerError
	upstreamContent = "upstream error 500"
	failSyncReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/admin/subscribe-files/%d/sync", importedFile.ID), nil)
	failSyncReq = failSyncReq.WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	failSyncRec := httptest.NewRecorder()
	handler.ServeHTTP(failSyncRec, failSyncReq)

	if failSyncRec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on sync failure, got %d", failSyncRec.Code)
	}
	reloadedAfterFail, err := repo.GetSubscribeFileByID(context.Background(), importedFile.ID)
	if err != nil {
		t.Fatalf("failed to reload file after fail: %v", err)
	}
	if reloadedAfterFail.Generation == nil || !strings.Contains(reloadedAfterFail.Generation.LastSyncError, "500") {
		t.Errorf("expected LastSyncError to record 500 error, got %q", reloadedAfterFail.Generation.LastSyncError)
	}

	// 5. 测试本地修改配置内容：PUT /api/admin/subscribe-files/{filename}/content
	newLocalContent := `proxies:
  - name: "🇯🇵 Tokyo-Local-01"
    type: ss
    server: 5.5.5.5
    port: 8388
    cipher: aes-128-gcm
    password: test
`
	updateReqBody, _ := json.Marshal(map[string]string{"content": newLocalContent})
	updateReq := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/admin/subscribe-files/%s/content", importedFile.Filename), bytes.NewReader(updateReqBody))
	updateReq = updateReq.WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	updateRec := httptest.NewRecorder()
	handler.ServeHTTP(updateRec, updateReq)

	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from update content, got %d: %s", updateRec.Code, updateRec.Body.String())
	}
	reloadedAfterUpdate, err := repo.GetSubscribeFileByID(context.Background(), importedFile.ID)
	if err != nil {
		t.Fatalf("failed to reload file after update: %v", err)
	}
	if reloadedAfterUpdate.Generation.LastSyncError != "" {
		t.Errorf("expected LastSyncError to be cleared after content update, got %q", reloadedAfterUpdate.Generation.LastSyncError)
	}
	foundJP := false
	for _, cc := range reloadedAfterUpdate.Generation.Processing.NodeRegions {
		if cc == "JP" {
			foundJP = true
			break
		}
	}
	if !foundJP {
		t.Errorf("expected updated proxy to have JP in node_regions")
	}
}
