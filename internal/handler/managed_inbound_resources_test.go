package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
)

type managedWireGuardAgent struct {
	mu      sync.Mutex
	inbound map[string]interface{}
	actions []string
}

func (a *managedWireGuardAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		a.mu.Lock()
		inbounds := make([]map[string]interface{}, 0, 1)
		if a.inbound != nil {
			inbounds = append(inbounds, cloneManagedWireGuardInbound(a.inbound))
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "inbounds": inbounds})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "config": `{"inbounds":[],"routing":{"rules":[]}}`})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, `{"success":false,"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		action := strings.ToLower(strings.TrimSpace(wireGuardStringValue(request["action"])))
		if action == "" {
			action = "add"
		}
		a.mu.Lock()
		a.actions = append(a.actions, action)
		switch action {
		case "add":
			inbound, _ := request["inbound"].(map[string]interface{})
			a.inbound = cloneManagedWireGuardInbound(inbound)
		case "remove":
			a.inbound = nil
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	default:
		http.NotFound(w, r)
	}
}

func (a *managedWireGuardAgent) actionSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.actions...)
}

func cloneManagedWireGuardInbound(inbound map[string]interface{}) map[string]interface{} {
	if inbound == nil {
		return nil
	}
	raw, _ := json.Marshal(inbound)
	var clone map[string]interface{}
	_ = json.Unmarshal(raw, &clone)
	return clone
}

func newManagedInboundHandlerTest(t *testing.T, initialInbound map[string]interface{}) (*RemoteManageHandler, *storage.TrafficRepository, *storage.RemoteServer, *managedWireGuardAgent, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "managed-inbound-handler.db")
	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.CreateUser(context.Background(), "admin", "admin@example.test", "Admin", "test-hash", storage.RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	agentState := &managedWireGuardAgent{inbound: cloneManagedWireGuardInbound(initialInbound)}
	agent := httptest.NewServer(agentState)
	t.Cleanup(agent.Close)
	server := createTunnelChainRemoteServer(t, repo, "managed-wireguard-edge", agent.URL)
	return NewRemoteManageHandler(repo, nil), repo, server, agentState, dbPath
}

func managedWireGuardRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, reader)
	return request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
}

func managedWireGuardCreateBody(t *testing.T, displayName string) map[string]interface{} {
	t.Helper()
	request := wireGuardInboundRequest(t)
	return map[string]interface{}{
		"action":       "add",
		"display_name": displayName,
		"inbound":      request["inbound"],
	}
}

func TestManagedWireGuardResourceCreateListRenameDelete(t *testing.T) {
	handler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	serverID := strconv.FormatInt(server.ID, 10)

	createResponse := httptest.NewRecorder()
	handler.HandleManagedInboundResources(createResponse, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+serverID,
		managedWireGuardCreateBody(t, "Hong Kong WireGuard")))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		Success  bool                      `json:"success"`
		Resource managedInboundResourceDTO `json:"resource"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !created.Success || created.Resource.ID <= 0 || created.Resource.DisplayName != "Hong Kong WireGuard" || created.Resource.CreatedBy != "admin" {
		t.Fatalf("unexpected create response: %+v", created)
	}
	if created.Resource.Protocol != "wireguard" || created.Resource.InboundTag != "wireguard-in" || created.Resource.EndpointPort != 51820 {
		t.Fatalf("unexpected resource identity: %+v", created.Resource)
	}
	lowerResponse := strings.ToLower(createResponse.Body.String())
	if strings.Contains(lowerResponse, "secretkey") || strings.Contains(lowerResponse, "privatekey") || strings.Contains(lowerResponse, "private_key") {
		t.Fatalf("create response exposed secret material: %s", createResponse.Body.String())
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(created.Resource.PublicMetadata, &metadata); err != nil {
		t.Fatalf("decode public metadata: %v", err)
	}
	if strings.TrimSpace(wireGuardStringValue(metadata["server_public_key"])) == "" {
		t.Fatalf("derived server public key missing: %#v", metadata)
	}

	nodes, err := repo.ListAllNodes(context.Background())
	if err != nil || len(nodes) != 0 {
		t.Fatalf("WireGuard entered subscription nodes: nodes=%+v err=%v", nodes, err)
	}

	listResponse := httptest.NewRecorder()
	handler.HandleManagedInboundResources(listResponse, managedWireGuardRequest(t, http.MethodGet, managedInboundResourcesPath, nil))
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), "Hong Kong WireGuard") {
		t.Fatalf("list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}

	renameResponse := httptest.NewRecorder()
	handler.HandleManagedInboundResources(renameResponse, managedWireGuardRequest(t, http.MethodPatch,
		managedInboundResourcesPath+"/"+strconv.FormatInt(created.Resource.ID, 10),
		map[string]interface{}{"display_name": "Renamed WireGuard"}))
	if renameResponse.Code != http.StatusOK || !strings.Contains(renameResponse.Body.String(), "Renamed WireGuard") {
		t.Fatalf("rename status=%d body=%s", renameResponse.Code, renameResponse.Body.String())
	}

	deleteResponse := httptest.NewRecorder()
	handler.HandleManagedInboundResources(deleteResponse, managedWireGuardRequest(t, http.MethodDelete,
		managedInboundResourcesPath+"/"+strconv.FormatInt(created.Resource.ID, 10), nil))
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	if _, err := repo.GetManagedInboundResource(context.Background(), created.Resource.ID); !errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		t.Fatalf("resource remained after delete: %v", err)
	}
	if actions := agent.actionSnapshot(); len(actions) != 2 || actions[0] != "add" || actions[1] != "remove" {
		t.Fatalf("agent actions=%v, want [add remove]", actions)
	}
}

func TestManagedWireGuardResourceRejectsClientPrivateMaterialBeforeAgent(t *testing.T) {
	handler, _, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	basePath := managedInboundResourcesPath + "/wireguard?server_id=" + strconv.FormatInt(server.ID, 10)

	privatePeerBody := managedWireGuardCreateBody(t, "Rejected WireGuard")
	settings := privatePeerBody["inbound"].(map[string]interface{})["settings"].(map[string]interface{})
	settings["peers"].([]interface{})[0].(map[string]interface{})["privateKey"] = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	privateResponse := httptest.NewRecorder()
	handler.HandleManagedInboundResources(privateResponse, managedWireGuardRequest(t, http.MethodPost, basePath, privatePeerBody))
	if privateResponse.Code != http.StatusBadRequest || !strings.Contains(privateResponse.Body.String(), "客户端私钥") {
		t.Fatalf("private key status=%d body=%s", privateResponse.Code, privateResponse.Body.String())
	}

	unknownResponse := httptest.NewRecorder()
	unknownBody := managedWireGuardCreateBody(t, "Rejected WireGuard")
	unknownBody["client_private_key"] = "do-not-store"
	handler.HandleManagedInboundResources(unknownResponse, managedWireGuardRequest(t, http.MethodPost, basePath, unknownBody))
	if unknownResponse.Code != http.StatusBadRequest || !strings.Contains(unknownResponse.Body.String(), "unknown field") {
		t.Fatalf("unknown secret status=%d body=%s", unknownResponse.Code, unknownResponse.Body.String())
	}
	if actions := agent.actionSnapshot(); len(actions) != 0 {
		t.Fatalf("rejected requests reached Agent: %v", actions)
	}
}

func TestManagedWireGuardPersistenceFailureRollsBackRemoteInbound(t *testing.T) {
	handler, repo, server, agent, dbPath := newManagedInboundHandlerTest(t, nil)
	triggerDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer triggerDB.Close()
	if _, err := triggerDB.Exec(`
CREATE TRIGGER fail_managed_wireguard_insert
BEFORE INSERT ON managed_inbound_resources
BEGIN
    SELECT RAISE(FAIL, 'forced managed WireGuard persistence failure');
END;`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Rollback WireGuard")))
	var failureBody struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &failureBody); err != nil {
		t.Fatalf("decode rollback response: %v", err)
	}
	if response.Code != http.StatusBadRequest || failureBody.Status != http.StatusBadGateway || !strings.Contains(response.Body.String(), "已回滚") {
		t.Fatalf("status=%d body=%s, want rollback failure response", response.Code, response.Body.String())
	}
	if actions := agent.actionSnapshot(); len(actions) != 2 || actions[0] != "add" || actions[1] != "remove" {
		t.Fatalf("agent actions=%v, want [add remove]", actions)
	}
	resources, err := repo.ListManagedInboundResources(context.Background())
	if err != nil || len(resources) != 0 {
		t.Fatalf("failed transaction left resources=%+v err=%v", resources, err)
	}
}

func TestManagedWireGuardInventorySyncBackfillsWithoutCreatingNode(t *testing.T) {
	inboundRequest := wireGuardInboundRequest(t)
	inbound := inboundRequest["inbound"].(map[string]interface{})
	handler, repo, server, _, _ := newManagedInboundHandlerTest(t, inbound)

	result := handler.syncInboundsToNodesInternal(context.Background(), server.ID)
	if !result.Success || len(result.Errors) != 0 {
		t.Fatalf("sync result=%+v", result)
	}
	resource, err := repo.GetManagedInboundResourceByServerTag(context.Background(), server.ID, "wireguard-in")
	if err != nil {
		t.Fatalf("synced resource missing: %v", err)
	}
	if resource.DisplayName != "[managed-wireguard-edge] wireguard-in" || resource.CreatedBy != "system-sync" {
		t.Fatalf("unexpected synced resource: %+v", resource)
	}
	if _, err := repo.RenameManagedInboundResource(context.Background(), resource.ID, "Keep My Name"); err != nil {
		t.Fatal(err)
	}
	result = handler.syncInboundsToNodesInternal(context.Background(), server.ID)
	if !result.Success || len(result.Errors) != 0 {
		t.Fatalf("second sync result=%+v", result)
	}
	resource, err = repo.GetManagedInboundResource(context.Background(), resource.ID)
	if err != nil || resource.DisplayName != "Keep My Name" {
		t.Fatalf("sync replaced user rename: resource=%+v err=%v", resource, err)
	}
	nodes, err := repo.ListAllNodes(context.Background())
	if err != nil || len(nodes) != 0 {
		t.Fatalf("sync created subscription nodes: nodes=%+v err=%v", nodes, err)
	}
}
