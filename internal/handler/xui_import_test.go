package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/xui"
)

const sampleXUIJSON = `{
  "success": true,
  "msg": "",
  "obj": [
    {
      "id": 1,
      "up": 1000,
      "down": 5000,
      "total": 1000000,
      "remark": "Test-Reality-US",
      "enable": true,
      "expiryTime": 0,
      "listen": "1.2.3.4",
      "port": 443,
      "protocol": "vless",
      "settings": "{\"clients\": [{\"id\": \"a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d\", \"flow\": \"xtls-rprx-vision\", \"email\": \"user1@test.com\"}]}",
      "streamSettings": "{\"network\": \"tcp\", \"security\": \"reality\", \"realitySettings\": {\"dest\": \"gateway.icloud.com:443\", \"serverNames\": [\"gateway.icloud.com\"], \"privateKey\": \"2K61sLh_b2WwZ2u233L2_9X3-84U3M3L0218_292211\", \"shortIds\": [\"abcd\"]}}",
      "tag": "inbound-443",
      "sniffing": "{\"enabled\": true, \"destOverride\": [\"http\", \"tls\"]}"
    }
  ]
}`

func TestXUIInspectAndImportHandler(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "xui-handler-test.db")
	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	// Create admin user
	if err := repo.CreateUser(t.Context(), "admin", "admin@example.com", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create test remote server
	server := storage.RemoteServer{
		Name:      "test-us-server",
		IPAddress: "1.2.3.4",
		Token:     "test-token-123456",
	}
	if err := repo.CreateRemoteServer(t.Context(), &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}

	h := NewXUIMigrateHandler(repo, nil)

	// Test 1: Inspect endpoint with raw JSON
	inspectBody, _ := json.Marshal(map[string]interface{}{
		"raw_json": sampleXUIJSON,
	})
	inspectReq := httptest.NewRequest(http.MethodPost, "/api/admin/migrate/xui/inspect", bytes.NewReader(inspectBody))
	inspectRec := httptest.NewRecorder()
	h.Inspect(inspectRec, inspectReq)

	if inspectRec.Code != http.StatusOK {
		t.Fatalf("Inspect failed with code %d: %s", inspectRec.Code, inspectRec.Body.String())
	}

	var inspectResp struct {
		Success bool                 `json:"success"`
		Report  xui.XUIInspectReport `json:"report"`
	}
	if err := json.Unmarshal(inspectRec.Body.Bytes(), &inspectResp); err != nil {
		t.Fatalf("Unmarshal inspect resp: %v", err)
	}
	if inspectResp.Report.TotalInbounds != 1 {
		t.Errorf("expected 1 inbound, got %d", inspectResp.Report.TotalInbounds)
	}
	if inspectResp.Report.Protocols["vless"] != 1 {
		t.Errorf("expected 1 vless protocol, got %d", inspectResp.Report.Protocols["vless"])
	}

	// Test 2: Non-destructive Import endpoint
	importReqBody, _ := json.Marshal(xui.XUIImportRequest{
		RawJSON:                 sampleXUIJSON,
		TargetUsername:          "admin",
		DefaultServerID:         server.ID,
		ImportHistoricalTraffic: true,
		CreateManagedResources:  true,
	})
	importReq := httptest.NewRequest(http.MethodPost, "/api/admin/migrate/xui/import", bytes.NewReader(importReqBody))
	importReq = importReq.WithContext(auth.ContextWithUsername(importReq.Context(), "admin"))
	importRec := httptest.NewRecorder()
	h.Import(importRec, importReq)

	if importRec.Code != http.StatusOK {
		t.Fatalf("Import failed with code %d: %s", importRec.Code, importRec.Body.String())
	}

	var importResp xui.XUIImportResult
	if err := json.Unmarshal(importRec.Body.Bytes(), &importResp); err != nil {
		t.Fatalf("Unmarshal import resp: %v", err)
	}
	if !importResp.Success {
		t.Errorf("expected import success=true, got %+v", importResp)
	}
	if importResp.ImportedNodes != 1 {
		t.Errorf("expected 1 imported node, got %d", importResp.ImportedNodes)
	}
	if importResp.ImportedClients != 1 {
		t.Errorf("expected 1 imported client, got %d", importResp.ImportedClients)
	}

	// Verify imported node in DB
	nodes, err := repo.ListAllNodes(t.Context())
	if err != nil {
		t.Fatalf("ListAllNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node in database, found %d", len(nodes))
	}
	if nodes[0].NodeName != "Test-Reality-US" {
		t.Errorf("unexpected node name: %s", nodes[0].NodeName)
	}
	if nodes[0].Protocol != "vless" {
		t.Errorf("unexpected protocol: %s", nodes[0].Protocol)
	}
}
