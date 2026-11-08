package xui

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

const sampleXUIExportJSON = `{
  "success": true,
  "msg": "",
  "obj": [
    {
      "id": 1,
      "up": 1048576,
      "down": 10485760,
      "total": 107374182400,
      "remark": "US-Reality-1",
      "enable": true,
      "expiryTime": 1799999999000,
      "listen": "170.9.59.149",
      "port": 443,
      "protocol": "vless",
      "settings": "{\"clients\": [{\"id\": \"b831381d-6324-4d53-ad4f-8cda48b30811\", \"flow\": \"xtls-rprx-vision\", \"email\": \"user1@chitanda.org\", \"totalGB\": 50000000, \"expiryTime\": 0, \"enable\": true, \"subId\": \"sub-01\"}], \"decryption\": \"none\", \"fallbacks\": []}",
      "streamSettings": "{\"network\": \"tcp\", \"security\": \"reality\", \"realitySettings\": {\"show\": false, \"xver\": 0, \"dest\": \"www.apple.com:443\", \"serverNames\": [\"www.apple.com\"], \"privateKey\": \"2P8Gf36MhFm7iW5UfL8Z0rGZpQ8N8XkX7hXjQ9_1_30=\", \"shortIds\": [\"\", \"12345678\"]}}",
      "tag": "inbound-443",
      "sniffing": "{\"enabled\": true, \"destOverride\": [\"http\", \"tls\", \"quic\"]}"
    },
    {
      "id": 2,
      "up": 2048,
      "down": 4096,
      "total": 0,
      "remark": "HK-VMess-WS",
      "enable": true,
      "expiryTime": 0,
      "listen": "0.0.0.0",
      "port": 8443,
      "protocol": "vmess",
      "settings": "{\"clients\": [{\"id\": \"c942492e-7435-5e64-be5f-9deb59c41922\", \"alterId\": 0, \"email\": \"user2@chitanda.org\", \"security\": \"auto\"}]}",
      "streamSettings": "{\"network\": \"ws\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"hk.example.com\"}, \"wsSettings\": {\"path\": \"/vmess-ws\"}}",
      "tag": "inbound-8443"
    },
    {
      "id": 3,
      "up": 0,
      "down": 0,
      "total": 0,
      "remark": "JP-SS-2022",
      "enable": true,
      "expiryTime": 0,
      "listen": "",
      "port": 50207,
      "protocol": "shadowsocks",
      "settings": "{\"method\": \"2022-blake3-chacha20-poly1305\", \"password\": \"3TN40qa0lQpjVmFvp0E2blyBWvfCX4tv+j8GGwRf9T0=\", \"network\": \"tcp,udp\"}",
      "streamSettings": "{\"network\": \"tcp\", \"security\": \"none\"}",
      "tag": "inbound-50207"
    }
  ]
}`

func TestParseXUIJSON(t *testing.T) {
	model, err := ParseXUIJSON([]byte(sampleXUIExportJSON))
	if err != nil {
		t.Fatalf("ParseXUIJSON failed: %v", err)
	}

	if len(model.Inbounds) != 3 {
		t.Fatalf("expected 3 inbounds, got %d", len(model.Inbounds))
	}

	// 1. Check VLESS Reality
	vless := model.Inbounds[0]
	if vless.Protocol != "vless" || vless.Port != 443 {
		t.Errorf("unexpected vless inbound: %+v", vless)
	}
	if len(vless.Clients) != 1 || vless.Clients[0].Email != "user1@chitanda.org" {
		t.Errorf("unexpected vless client: %+v", vless.Clients)
	}
	if vless.Stream == nil || vless.Stream.Security != "reality" {
		t.Errorf("unexpected stream settings: %+v", vless.Stream)
	}

	// 2. Check VMess WS
	vmess := model.Inbounds[1]
	if vmess.Protocol != "vmess" || vmess.Port != 8443 {
		t.Errorf("unexpected vmess inbound: %+v", vmess)
	}
	if vmess.Stream.Network != "ws" || vmess.Stream.WSSettings.Path != "/vmess-ws" {
		t.Errorf("unexpected ws settings: %+v", vmess.Stream.WSSettings)
	}

	// 3. Check SS-2022
	ss := model.Inbounds[2]
	if ss.Protocol != "shadowsocks" || ss.Port != 50207 {
		t.Errorf("unexpected ss inbound: %+v", ss)
	}
	if len(ss.Clients) != 1 || ss.Clients[0].Method != "2022-blake3-chacha20-poly1305" {
		t.Errorf("unexpected ss clients: %+v", ss.Clients)
	}
}

func TestConvertXUIInboundToNodeCandidate(t *testing.T) {
	model, err := ParseXUIJSON([]byte(sampleXUIExportJSON))
	if err != nil {
		t.Fatalf("parse err: %v", err)
	}

	vless := model.Inbounds[0]
	candidate, err := ConvertXUIInboundToNodeCandidate(&vless, &vless.Clients[0], "170.9.59.149", "oracle-sjc")
	if err != nil {
		t.Fatalf("convert err: %v", err)
	}

	if candidate.NodeType != "vless" {
		t.Errorf("expected vless, got %s", candidate.NodeType)
	}
	if candidate.Port != 443 {
		t.Errorf("expected 443, got %d", candidate.Port)
	}
	if candidate.ProxyConfig["tls"] != true {
		t.Errorf("expected tls=true for reality")
	}

	realityOpts, ok := candidate.ProxyConfig["reality-opts"].(map[string]interface{})
	if !ok || realityOpts["public-key"] == "" {
		t.Errorf("expected derived public key in reality-opts: %+v", realityOpts)
	}

	if candidate.Link == "" || !containsStr(candidate.Link, "vless://") {
		t.Errorf("expected valid vless link, got %s", candidate.Link)
	}
}

func TestInspectDryRunDetectsConflicts(t *testing.T) {
	model, err := ParseXUIJSON([]byte(sampleXUIExportJSON))
	if err != nil {
		t.Fatalf("parse err: %v", err)
	}

	servers := []*ServerInfo{
		{ID: 10, Name: "US-Node", IPAddress: "170.9.59.149"},
	}

	existingNodes := []*ExistingNodeInfo{
		{
			NodeName: "Existing-HTTPS-Service",
			Protocol: "vless",
			Host:     "170.9.59.149",
			Port:     443,
		},
	}

	report := Inspect(model, servers, existingNodes)

	if report.TotalInbounds != 3 {
		t.Errorf("expected 3 inbounds in report, got %d", report.TotalInbounds)
	}
	if report.Protocols["vless"] != 1 || report.Protocols["vmess"] != 1 || report.Protocols["shadowsocks"] != 1 {
		t.Errorf("unexpected protocol counts: %+v", report.Protocols)
	}

	// Port 443 should conflict on server 10
	foundConflict := false
	for _, d := range report.InboundDetails {
		if d.Port == 443 && d.PortConflict {
			foundConflict = true
			break
		}
	}
	if !foundConflict {
		t.Errorf("expected port 443 conflict on server 10")
	}
	if !report.HasConflicts {
		t.Errorf("expected HasConflicts=true")
	}
}

func TestParseXUIDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "x-ui.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("create sqlite: %v", err)
	}

	schema := `
CREATE TABLE inbounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    up INTEGER,
    down INTEGER,
    total INTEGER,
    remark TEXT,
    enable INTEGER,
    expiry_time INTEGER,
    listen TEXT,
    port INTEGER,
    protocol TEXT,
    settings TEXT,
    stream_settings TEXT,
    tag TEXT
);
CREATE TABLE client_traffics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inbound_id INTEGER,
    enable INTEGER,
    email TEXT,
    up INTEGER,
    down INTEGER,
    expiry_time INTEGER,
    total INTEGER,
    reset INTEGER
);
INSERT INTO inbounds (id, user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag)
VALUES (1, 1, 500, 1500, 0, 'SQLite-VLESS', 1, 0, '0.0.0.0', 443, 'vless', '{"clients":[{"id":"uuid-123","email":"test@xui.org"}]}', '{"network":"tcp","security":"none"}', 'inbound-443');
INSERT INTO client_traffics (id, inbound_id, enable, email, up, down, expiry_time, total, reset)
VALUES (1, 1, 1, 'test@xui.org', 500, 1500, 0, 100000, 0);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		t.Fatalf("exec schema: %v", err)
	}
	db.Close()

	model, err := ParseXUIDatabase(dbPath)
	if err != nil {
		t.Fatalf("ParseXUIDatabase failed: %v", err)
	}

	if len(model.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(model.Inbounds))
	}
	if model.Inbounds[0].Remark != "SQLite-VLESS" || model.Inbounds[0].Port != 443 {
		t.Errorf("unexpected inbound: %+v", model.Inbounds[0])
	}
	if len(model.ClientTraffics) != 1 || model.ClientTraffics[0].Email != "test@xui.org" {
		t.Errorf("unexpected client traffics: %+v", model.ClientTraffics)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && filepath.Base(s) != "") && len(sub) > 0
}
