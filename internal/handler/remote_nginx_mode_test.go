package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestReuseExistingBlocksRemoteNginxInstallBeforeAgent(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	if err := repo.UpdateRemoteServerNginxMode(context.Background(), server.ID, remoteNginxModeReuseExisting); err != nil {
		t.Fatal(err)
	}

	handler := NewRemoteManageHandler(repo, nil)
	request := httptest.NewRequest(http.MethodPost, "/api/admin/remote/nginx/install?server_id="+strconv.FormatInt(server.ID, 10), nil)
	response := httptest.NewRecorder()
	handler.HandleNginxInstall(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "复用系统已有 Nginx") {
		t.Fatalf("response does not explain ownership boundary: %s", response.Body.String())
	}
}

func TestRemoteInstallerCarriesReuseExistingNginxPolicy(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	if err := repo.UpdateRemoteServerNginxMode(context.Background(), server.ID, remoteNginxModeReuseExisting); err != nil {
		t.Fatal(err)
	}
	installExpiryGuardAssetFixtures(t)
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")

	handler := NewXrayServerHandler(repo, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+server.Token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	script := response.Body.String()
	for _, expected := range []string{
		"NGINX_MODE='reuse_existing'",
		"nginx_mode: ${NGINX_MODE}",
		`if [ "$CONFIGURED_MODE" = "reuse_existing" ]; then`,
		`if [ "$NGINX_MODE" = "managed" ]; then`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("reuse-existing installer missing %q", expected)
		}
	}
}

func updateRemoteServerNginxModeForTest(t *testing.T, handler *XrayServerHandler, server *storage.RemoteServer, name, mode string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(RemoteServerUpdateRequest{
		ID: server.ID, Name: name, Domain: server.Domain, ConnectionMode: server.ConnectionMode,
		XrayMode: server.XrayMode, NginxMode: mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/admin/remote-servers/update", strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	handler.UpdateRemoteServer(response, request)
	return response
}

func TestUpdateRemoteServerSwitchesAgentNginxModeBeforeDatabase(t *testing.T) {
	var agentMode string
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != remoteNginxModeSwitchPath {
			t.Fatalf("unexpected Agent request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer installation-handler-token" {
			t.Fatalf("unexpected Agent authorization: %q", r.Header.Get("Authorization"))
		}
		var request struct {
			NginxMode string `json:"nginx_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		agentMode = request.NginxMode
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "nginx_mode": request.NginxMode})
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewXrayServerHandler(repo, nil, nil)
	handler.SetRemoteManager(NewRemoteManageHandler(repo, nil))
	response := updateRemoteServerNginxModeForTest(t, handler, server, server.Name, remoteNginxModeReuseExisting)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	stored, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if agentMode != remoteNginxModeReuseExisting || stored.NginxMode != remoteNginxModeReuseExisting {
		t.Fatalf("mode mismatch: agent=%q database=%q", agentMode, stored.NginxMode)
	}
}

func TestUpdateRemoteServerKeepsDatabaseUnchangedWhenAgentRejectsNginxMode(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"success":false,"error":"cannot persist nginx mode"}`, http.StatusInternalServerError)
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	handler := NewXrayServerHandler(repo, nil, nil)
	handler.SetRemoteManager(NewRemoteManageHandler(repo, nil))
	response := updateRemoteServerNginxModeForTest(t, handler, server, "must-not-save", remoteNginxModeReuseExisting)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusBadGateway, response.Body.String())
	}
	stored, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.NginxMode != remoteNginxModeManaged || stored.Name != server.Name {
		t.Fatalf("database changed before Agent ACK: mode=%q name=%q", stored.NginxMode, stored.Name)
	}
}

func TestUpdateRemoteServerRollsAgentBackWhenNginxModeDatabaseWriteFails(t *testing.T) {
	var agentModes []string
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			NginxMode string `json:"nginx_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		agentModes = append(agentModes, request.NginxMode)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "nginx_mode": request.NginxMode})
	}))
	defer agent.Close()

	databasePath := filepath.Join(t.TempDir(), "nginx-mode-rollback.db")
	repo, err := storage.NewTrafficRepository(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name: "rollback-edge", Token: "rollback-token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket, IPAddress: "127.0.0.1",
		ListenPort: testServerPort(t, agent.URL), Domain: "rollback.example.test", NginxMode: remoteNginxModeManaged,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	rawDatabase, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rawDatabase.Exec(`CREATE TRIGGER reject_nginx_mode_update
		BEFORE UPDATE OF nginx_mode ON remote_servers
		WHEN NEW.nginx_mode = 'reuse_existing'
		BEGIN SELECT RAISE(ABORT, 'forced nginx mode failure'); END`); err != nil {
		_ = rawDatabase.Close()
		t.Fatal(err)
	}
	if err := rawDatabase.Close(); err != nil {
		t.Fatal(err)
	}

	handler := NewXrayServerHandler(repo, nil, nil)
	handler.SetRemoteManager(NewRemoteManageHandler(repo, nil))
	response := updateRemoteServerNginxModeForTest(t, handler, server, "other-fields-saved", remoteNginxModeReuseExisting)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Agent 已回滚") {
		t.Fatalf("response does not report rollback: %s", response.Body.String())
	}
	stored, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.NginxMode != remoteNginxModeManaged || stored.Name != "other-fields-saved" {
		t.Fatalf("unexpected database state: mode=%q name=%q", stored.NginxMode, stored.Name)
	}
	wantModes := []string{remoteNginxModeReuseExisting, remoteNginxModeManaged}
	if len(agentModes) != len(wantModes) || agentModes[0] != wantModes[0] || agentModes[1] != wantModes[1] {
		t.Fatalf("Agent mode calls=%v want=%v", agentModes, wantModes)
	}
}
