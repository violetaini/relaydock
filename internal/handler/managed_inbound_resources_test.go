package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	mu                 sync.Mutex
	inbound            map[string]interface{}
	actions            []string
	mutationIDs        []string
	ownerMutationID    string
	addResponseMode    string
	removeResponseMode string
	rejectAddIfExists  bool
	failRemove         bool
	rejectRemove       bool
	beforeAdd          func()
}

func (a *managedWireGuardAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		a.mu.Lock()
		inbounds := make([]map[string]interface{}, 0, 1)
		owners := make(map[string]string)
		if a.inbound != nil {
			inbound := cloneManagedWireGuardInbound(a.inbound)
			inbound["_mutation_fence_known"] = true
			if tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"])); tag != "" && a.ownerMutationID != "" {
				inbound["_mutation_id"] = a.ownerMutationID
				owners[tag] = a.ownerMutationID
			}
			inbounds = append(inbounds, inbound)
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "inbounds": inbounds,
			"mutation_fence_known": true, "mutation_owners": owners,
		})
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
		mutationID := strings.TrimSpace(wireGuardStringValue(request["mutation_id"]))
		a.mutationIDs = append(a.mutationIDs, mutationID)
		beforeAdd := a.beforeAdd
		a.mu.Unlock()
		if action == "add" && beforeAdd != nil {
			beforeAdd()
		}
		a.mu.Lock()
		responseMode := ""
		switch action {
		case "add":
			if a.rejectAddIfExists && a.inbound != nil {
				a.mu.Unlock()
				http.Error(w, `{"success":false,"error":"inbound tag already exists"}`, http.StatusConflict)
				return
			}
			inbound, _ := request["inbound"].(map[string]interface{})
			a.inbound = cloneManagedWireGuardInbound(inbound)
			a.ownerMutationID = mutationID
			responseMode = a.addResponseMode
		case "remove":
			if a.rejectRemove {
				a.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "simulated logical remove rejection"})
				return
			}
			if a.failRemove {
				a.mu.Unlock()
				http.Error(w, `{"success":false,"error":"simulated remove failure"}`, http.StatusBadGateway)
				return
			}
			if mutationID != "" && a.ownerMutationID != "" && mutationID != a.ownerMutationID {
				a.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true, "mutation_id": mutationID,
					"message":    "Inbound removal superseded by a newer mutation",
					"superseded": true, "changed": false,
				})
				return
			}
			a.inbound = nil
			a.ownerMutationID = ""
			responseMode = a.removeResponseMode
		}
		a.mu.Unlock()
		if responseMode == "malformed" {
			_, _ = w.Write([]byte(`{"success":`))
			return
		}
		response := map[string]interface{}{"success": true}
		if mutationID != "" && responseMode != "missing-mutation" {
			response["mutation_id"] = mutationID
		}
		_ = json.NewEncoder(w).Encode(response)
	default:
		http.NotFound(w, r)
	}
}

func (a *managedWireGuardAgent) actionSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.actions...)
}

func (a *managedWireGuardAgent) mutationSnapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.mutationIDs...)
}

func (a *managedWireGuardAgent) setAddResponseMode(value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addResponseMode = value
}

func (a *managedWireGuardAgent) setRemoveResponseMode(value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removeResponseMode = value
}

func (a *managedWireGuardAgent) setRejectAddIfExists(value bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rejectAddIfExists = value
}

func (a *managedWireGuardAgent) setInbound(inbound map[string]interface{}, ownerMutationID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inbound = cloneManagedWireGuardInbound(inbound)
	a.ownerMutationID = ownerMutationID
}

func (a *managedWireGuardAgent) setFailRemove(value bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failRemove = value
}

func (a *managedWireGuardAgent) setRejectRemove(value bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rejectRemove = value
}

func (a *managedWireGuardAgent) setBeforeAdd(callback func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.beforeAdd = callback
}

func (a *managedWireGuardAgent) hasInbound() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inbound != nil
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
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x71}, 32)); err != nil {
		t.Fatalf("ConfigureNodeSecretEncryption: %v", err)
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
	inbound := request["inbound"].(map[string]interface{})
	settings := inbound["settings"].(map[string]interface{})
	clientPrivateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))
	clientPublicKey, err := managedWireGuardPublicKey(clientPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPublicKey, err := managedWireGuardPublicKey(wireGuardStringValue(settings["secretKey"]))
	if err != nil {
		t.Fatal(err)
	}
	peer := settings["peers"].([]interface{})[0].(map[string]interface{})
	peer["publicKey"] = clientPublicKey
	return map[string]interface{}{
		"action":       "add",
		"display_name": displayName,
		"inbound":      inbound,
		"client": map[string]interface{}{
			"private_key":       clientPrivateKey,
			"public_key":        clientPublicKey,
			"address":           []string{"10.66.66.2/32"},
			"dns":               []string{"1.1.1.1", "1.0.0.1"},
			"mtu":               1420,
			"keep_alive":        25,
			"server_public_key": serverPublicKey,
			"allowed_ips":       []string{"0.0.0.0/0", "::/0"},
		},
	}
}

func TestManagedWireGuardResourceCreateListRenameDelete(t *testing.T) {
	handler, repo, server, agent, dbPath := newManagedInboundHandlerTest(t, nil)
	serverID := strconv.FormatInt(server.ID, 10)
	inspectionDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer inspectionDB.Close()
	createBody := managedWireGuardCreateBody(t, "Hong Kong WireGuard")
	clientPrivateKey := createBody["client"].(map[string]interface{})["private_key"].(string)
	stagedResult := make(chan error, 1)
	agent.setBeforeAdd(func() {
		var enabled int
		var rawURL, parsedConfig, clashConfig, ciphertext, originalServer, inboundTag string
		err := inspectionDB.QueryRow(`
SELECT n.enabled, n.raw_url, n.parsed_config, n.clash_config, ns.ciphertext,
       COALESCE(n.original_server, ''), COALESCE(n.inbound_tag, '')
FROM nodes n JOIN node_secrets ns ON ns.node_id = n.id
WHERE lower(n.protocol) = 'wireguard' AND n.node_name = 'Hong Kong WireGuard'`).
			Scan(&enabled, &rawURL, &parsedConfig, &clashConfig, &ciphertext, &originalServer, &inboundTag)
		if err == nil && (enabled != 0 || rawURL != "" || !strings.HasPrefix(ciphertext, "v1:") ||
			originalServer != "" || inboundTag != "" || strings.Contains(parsedConfig, clientPrivateKey) ||
			strings.Contains(clashConfig, clientPrivateKey)) {
			err = fmt.Errorf("unsafe staged node: enabled=%d raw_url=%q original_server=%q inbound_tag=%q ciphertext=%q",
				enabled, rawURL, originalServer, inboundTag, ciphertext)
		}
		stagedResult <- err
	})

	createResponse := httptest.NewRecorder()
	handler.HandleManagedInboundResources(createResponse, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+serverID,
		createBody))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	if err := <-stagedResult; err != nil {
		t.Fatalf("client identity was not encrypted before remote creation: %v", err)
	}
	var created struct {
		Success      bool                      `json:"success"`
		Resource     managedInboundResourceDTO `json:"resource"`
		Node         nodeDTO                   `json:"node"`
		ClientConfig string                    `json:"client_config"`
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
	if created.Node.ID <= 0 || created.Node.Protocol != "wireguard" || !strings.Contains(created.Node.ClashConfig, `"private-key"`) {
		t.Fatalf("ordinary WireGuard node missing from response: %+v", created.Node)
	}
	if !strings.Contains(created.ClientConfig, "[Interface]") || !strings.Contains(created.ClientConfig, "PrivateKey = ") {
		t.Fatalf("client config missing: %q", created.ClientConfig)
	}
	resourceJSON, _ := json.Marshal(created.Resource)
	lowerResource := strings.ToLower(string(resourceJSON))
	if strings.Contains(lowerResource, "secretkey") || strings.Contains(lowerResource, "privatekey") || strings.Contains(lowerResource, "private_key") {
		t.Fatalf("public resource exposed secret material: %s", resourceJSON)
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(created.Resource.PublicMetadata, &metadata); err != nil {
		t.Fatalf("decode public metadata: %v", err)
	}
	if strings.TrimSpace(wireGuardStringValue(metadata["server_public_key"])) == "" {
		t.Fatalf("derived server public key missing: %#v", metadata)
	}

	nodes, err := repo.ListAllNodes(context.Background())
	if err != nil || len(nodes) != 1 || nodes[0].ID != created.Node.ID || !strings.Contains(nodes[0].ClashConfig, `"private-key"`) {
		t.Fatalf("WireGuard ordinary node missing: nodes=%+v err=%v", nodes, err)
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
	if nodes, err := repo.ListAllNodes(context.Background()); err != nil || len(nodes) != 0 {
		t.Fatalf("resource delete left ordinary node: nodes=%+v err=%v", nodes, err)
	}
	if actions := agent.actionSnapshot(); len(actions) != 2 || actions[0] != "add" || actions[1] != "remove" {
		t.Fatalf("agent actions=%v, want [add remove]", actions)
	}
}

func TestManagedWireGuardCreateRecoversMatchingStagedGenerationWithoutReadding(t *testing.T) {
	handler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	body := managedWireGuardCreateBody(t, "Recovered WireGuard")
	inbound := body["inbound"].(map[string]interface{})
	mutationID := "managed-wireguard:recover-generation"
	resource, err := handler.upsertWireGuardManagedResource(context.Background(), server.ID, "Recovered WireGuard", "admin", inbound, mutationID)
	if err != nil {
		t.Fatal(err)
	}
	var client managedWireGuardClient
	clientJSON, _ := json.Marshal(body["client"])
	if err := json.Unmarshal(clientJSON, &client); err != nil {
		t.Fatal(err)
	}
	client, err = validateManagedWireGuardClient(inbound, client)
	if err != nil {
		t.Fatal(err)
	}
	clashConfig, _, err := buildManagedWireGuardClientConfigs(resource.DisplayName, resource.EndpointHost, resource.EndpointPort, client)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := repo.CreateNode(context.Background(), storage.Node{
		Username: repo.GetSystemNodeOwner(context.Background()), NodeName: resource.DisplayName,
		Protocol: "wireguard", ParsedConfig: clashConfig, ClashConfig: clashConfig,
		Enabled: false, InboundMutationID: mutationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	agent.setInbound(inbound, mutationID)

	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10), body))
	if response.Code != http.StatusOK {
		t.Fatalf("recover status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Success   bool    `json:"success"`
		Recovered bool    `json:"recovered"`
		Node      nodeDTO `json:"node"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Success || !payload.Recovered || payload.Node.ID != staged.ID {
		t.Fatalf("recovery payload=%+v", payload)
	}
	if actions := agent.actionSnapshot(); len(actions) != 0 {
		t.Fatalf("recovery resent mutation to Agent: %v", actions)
	}
	attached, err := repo.GetNodeByID(context.Background(), staged.ID)
	if err != nil || !attached.Enabled || attached.OriginalServer != server.Name || attached.InboundTag != resource.InboundTag ||
		!strings.Contains(attached.ClashConfig, `"private-key"`) {
		t.Fatalf("attached=%+v err=%v", attached, err)
	}
}

func TestManagedWireGuardCreateRefusesStagedRecoveryWhenLiveConfigDiffers(t *testing.T) {
	handler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	body := managedWireGuardCreateBody(t, "Uncertain WireGuard")
	inbound := body["inbound"].(map[string]interface{})
	mutationID := "managed-wireguard:uncertain-generation"
	resource, err := handler.upsertWireGuardManagedResource(context.Background(), server.ID, "Uncertain WireGuard", "admin", inbound, mutationID)
	if err != nil {
		t.Fatal(err)
	}
	var client managedWireGuardClient
	clientJSON, _ := json.Marshal(body["client"])
	if err := json.Unmarshal(clientJSON, &client); err != nil {
		t.Fatal(err)
	}
	client, err = validateManagedWireGuardClient(inbound, client)
	if err != nil {
		t.Fatal(err)
	}
	clashConfig, _, err := buildManagedWireGuardClientConfigs(resource.DisplayName, resource.EndpointHost, resource.EndpointPort, client)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := repo.CreateNode(context.Background(), storage.Node{
		Username: repo.GetSystemNodeOwner(context.Background()), NodeName: resource.DisplayName,
		Protocol: "wireguard", ParsedConfig: clashConfig, ClashConfig: clashConfig,
		Enabled: false, InboundMutationID: mutationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	liveInbound := cloneManagedWireGuardInbound(inbound)
	liveInbound["port"] = float64(resource.EndpointPort + 1)
	agent.setInbound(liveInbound, mutationID)

	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10), body))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "配置与预存记录不一致") {
		t.Fatalf("recover mismatch status=%d body=%s", response.Code, response.Body.String())
	}
	if actions := agent.actionSnapshot(); len(actions) != 0 {
		t.Fatalf("uncertain recovery mutated Agent: %v", actions)
	}
	remained, err := repo.GetNodeByID(context.Background(), staged.ID)
	if err != nil || remained.Enabled || remained.OriginalServer != "" || remained.InboundTag != "" {
		t.Fatalf("uncertain staged node was attached: node=%+v err=%v", remained, err)
	}
}

func TestManagedWireGuardDeleteCleansPreAttachStagedIdentity(t *testing.T) {
	handler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	body := managedWireGuardCreateBody(t, "Staged Delete")
	inbound := body["inbound"].(map[string]interface{})
	mutationID := "managed-wireguard:staged-delete"
	resource, err := handler.upsertWireGuardManagedResource(context.Background(), server.ID, "Staged Delete", "admin", inbound, mutationID)
	if err != nil {
		t.Fatal(err)
	}
	var client managedWireGuardClient
	clientJSON, _ := json.Marshal(body["client"])
	_ = json.Unmarshal(clientJSON, &client)
	client, err = validateManagedWireGuardClient(inbound, client)
	if err != nil {
		t.Fatal(err)
	}
	clashConfig, _, err := buildManagedWireGuardClientConfigs(resource.DisplayName, resource.EndpointHost, resource.EndpointPort, client)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := repo.CreateNode(context.Background(), storage.Node{
		Username: repo.GetSystemNodeOwner(context.Background()), NodeName: resource.DisplayName,
		Protocol: "wireguard", ParsedConfig: clashConfig, ClashConfig: clashConfig,
		Enabled: false, InboundMutationID: mutationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	agent.setInbound(inbound, mutationID)
	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodDelete,
		managedInboundResourcesPath+"/"+strconv.FormatInt(resource.ID, 10), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := repo.GetNodeByID(context.Background(), staged.ID); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("staged node survived delete: %v", err)
	}
	if _, err := repo.GetManagedInboundResource(context.Background(), resource.ID); !errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		t.Fatalf("resource survived delete: %v", err)
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

func TestManagedWireGuardPersistenceFailureStopsBeforeRemoteInbound(t *testing.T) {
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
	if response.Code != http.StatusBadRequest || failureBody.Status != http.StatusBadRequest || !strings.Contains(response.Body.String(), "预存失败") {
		t.Fatalf("status=%d body=%s, want preflight persistence failure", response.Code, response.Body.String())
	}
	if actions := agent.actionSnapshot(); len(actions) != 0 {
		t.Fatalf("persistence failure reached Agent: %v", actions)
	}
	resources, err := repo.ListManagedInboundResources(context.Background())
	if err != nil || len(resources) != 0 {
		t.Fatalf("failed transaction left resources=%+v err=%v", resources, err)
	}
	if nodes, err := repo.ListAllNodes(context.Background()); err != nil || len(nodes) != 0 {
		t.Fatalf("failed preflight left nodes=%+v err=%v", nodes, err)
	}
}

func TestManagedWireGuardCreateRejectsExistingRemoteTagBeforeStaging(t *testing.T) {
	existing := wireGuardInboundRequest(t)["inbound"].(map[string]interface{})
	handler, repo, server, agent, _ := newManagedInboundHandlerTest(t, existing)
	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Duplicate WG")))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "相同 Tag") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if actions := agent.actionSnapshot(); len(actions) != 0 {
		t.Fatalf("remote preflight conflict performed mutations: %v", actions)
	}
	if !agent.hasInbound() {
		t.Fatal("remote preflight conflict removed the existing inbound")
	}
	if resources, err := repo.ListManagedInboundResources(context.Background()); err != nil || len(resources) != 0 {
		t.Fatalf("remote preflight conflict staged resources=%+v err=%v", resources, err)
	}
	if nodes, err := repo.ListAllNodes(context.Background()); err != nil || len(nodes) != 0 {
		t.Fatalf("remote preflight conflict staged nodes=%+v err=%v", nodes, err)
	}
}

func TestManagedWireGuardUncertainCreateStaysDetachedAndLocalDeleteDoesNotTouchRemote(t *testing.T) {
	handler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	foreignInbound := wireGuardInboundRequest(t)["inbound"].(map[string]interface{})
	agent.setRejectAddIfExists(true)
	agent.setBeforeAdd(func() {
		agent.setInbound(foreignInbound, "foreign-owner")
	})

	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Uncertain WG")))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "已保留禁用节点和加密凭据") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	nodes, err := repo.ListAllNodes(context.Background())
	if err != nil || len(nodes) != 1 {
		t.Fatalf("uncertain create nodes=%+v err=%v", nodes, err)
	}
	staged := nodes[0]
	if staged.Enabled || staged.OriginalServer != "" || staged.InboundTag != "" || !strings.Contains(staged.ClashConfig, `"private-key"`) {
		t.Fatalf("unsafe uncertain node: %+v", staged)
	}
	resources, err := repo.ListManagedInboundResources(context.Background())
	if err != nil || len(resources) != 1 || resources[0].InboundTag != "wireguard-in" {
		t.Fatalf("uncertain create did not retain coordination resource: resources=%+v err=%v", resources, err)
	}
	mutations := agent.mutationSnapshot()
	if actions := agent.actionSnapshot(); len(actions) != 1 || actions[0] != "add" || len(mutations) != 1 || mutations[0] == "" {
		t.Fatalf("agent actions=%v mutation_ids=%v", actions, mutations)
	}

	nodesHandler := NewNodesHandler(repo, t.TempDir(), handler)
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/admin/nodes/"+strconv.FormatInt(staged.ID, 10), nil)
	deleteRequest = deleteRequest.WithContext(auth.ContextWithUsername(deleteRequest.Context(), "admin"))
	deleteResponse := httptest.NewRecorder()
	nodesHandler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("delete staged node status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	if actions := agent.actionSnapshot(); len(actions) != 1 || actions[0] != "add" {
		t.Fatalf("local staged-node deletion touched remote inbound: %v", actions)
	}
	if !agent.hasInbound() {
		t.Fatal("local staged-node deletion removed the foreign remote inbound")
	}
	if _, err := repo.GetNodeByID(context.Background(), staged.ID); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("staged node remained after local deletion: %v", err)
	}
	resources, err = repo.ListManagedInboundResources(context.Background())
	if err != nil || len(resources) != 1 {
		t.Fatalf("local staged-node deletion removed coordination resource: resources=%+v err=%v", resources, err)
	}
}

func TestManagedWireGuardMissingAddMutationACKRetainsDetachedEncryptedNode(t *testing.T) {
	handler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	agent.setAddResponseMode("missing-mutation")

	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Missing ACK WG")))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "已保留禁用节点和加密凭据") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if actions := agent.actionSnapshot(); len(actions) != 1 || actions[0] != "add" {
		t.Fatalf("uncertain add ACK triggered a rollback: %v", actions)
	}
	mutations := agent.mutationSnapshot()
	if len(mutations) != 1 || mutations[0] == "" {
		t.Fatalf("add did not carry a stable mutation ID: %v", mutations)
	}
	nodes, err := repo.ListAllNodes(context.Background())
	if err != nil || len(nodes) != 1 {
		t.Fatalf("missing ACK nodes=%+v err=%v", nodes, err)
	}
	if nodes[0].Enabled || nodes[0].OriginalServer != "" || nodes[0].InboundTag != "" || !strings.Contains(nodes[0].ClashConfig, `"private-key"`) {
		t.Fatalf("missing ACK did not retain a detached encrypted node: %+v", nodes[0])
	}
	if resources, err := repo.ListManagedInboundResources(context.Background()); err != nil || len(resources) != 1 {
		t.Fatalf("missing ACK resources=%+v err=%v", resources, err)
	}
	if !agent.hasInbound() {
		t.Fatal("test setup did not apply the remote inbound before dropping the mutation ACK")
	}
}

func TestManagedWireGuardConfirmedCreateFailureUsesMatchingFencedRollback(t *testing.T) {
	handler, repo, server, agent, dbPath := newManagedInboundHandlerTest(t, nil)
	triggerDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer triggerDB.Close()
	agent.setBeforeAdd(func() {
		if _, triggerErr := triggerDB.Exec(`
CREATE TRIGGER fail_managed_wireguard_enable
BEFORE UPDATE ON nodes
BEGIN
    SELECT RAISE(FAIL, 'forced WireGuard enable failure');
END;`); triggerErr != nil {
			t.Errorf("create enable failure trigger: %v", triggerErr)
		}
	})

	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Rollback WG")))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "预存节点与远程入站已回滚") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	actions := agent.actionSnapshot()
	mutations := agent.mutationSnapshot()
	if len(actions) != 2 || actions[0] != "add" || actions[1] != "remove" ||
		len(mutations) != 2 || mutations[0] == "" || mutations[0] != mutations[1] {
		t.Fatalf("agent actions=%v mutation_ids=%v", actions, mutations)
	}
	if agent.hasInbound() {
		t.Fatal("confirmed rollback left the remote inbound")
	}
	if nodes, err := repo.ListAllNodes(context.Background()); err != nil || len(nodes) != 0 {
		t.Fatalf("confirmed rollback left nodes=%+v err=%v", nodes, err)
	}
	if resources, err := repo.ListManagedInboundResources(context.Background()); err != nil || len(resources) != 0 {
		t.Fatalf("confirmed rollback left resources=%+v err=%v", resources, err)
	}
}

func TestManagedWireGuardUnconfirmedRollbackRetainsDetachedEncryptedNode(t *testing.T) {
	handler, repo, server, agent, dbPath := newManagedInboundHandlerTest(t, nil)
	triggerDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer triggerDB.Close()
	agent.setRemoveResponseMode("missing-mutation")
	agent.setBeforeAdd(func() {
		if _, triggerErr := triggerDB.Exec(`
CREATE TRIGGER fail_managed_wireguard_enable_unconfirmed
BEFORE UPDATE ON nodes
BEGIN
    SELECT RAISE(FAIL, 'forced WireGuard enable failure');
END;`); triggerErr != nil {
			t.Errorf("create enable failure trigger: %v", triggerErr)
		}
	})

	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Retained WG")))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "自动回滚失败，已保留禁用节点和加密凭据") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	actions := agent.actionSnapshot()
	mutations := agent.mutationSnapshot()
	if len(actions) != 2 || actions[0] != "add" || actions[1] != "remove" ||
		len(mutations) != 2 || mutations[0] == "" || mutations[0] != mutations[1] {
		t.Fatalf("agent actions=%v mutation_ids=%v", actions, mutations)
	}
	nodes, err := repo.ListAllNodes(context.Background())
	if err != nil || len(nodes) != 1 {
		t.Fatalf("unconfirmed rollback nodes=%+v err=%v", nodes, err)
	}
	if nodes[0].Enabled || nodes[0].OriginalServer != "" || nodes[0].InboundTag != "" || !strings.Contains(nodes[0].ClashConfig, `"private-key"`) {
		t.Fatalf("unconfirmed rollback did not retain a detached encrypted node: %+v", nodes[0])
	}
	if resources, err := repo.ListManagedInboundResources(context.Background()); err != nil || len(resources) != 1 {
		t.Fatalf("unconfirmed rollback resources=%+v err=%v", resources, err)
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

func TestManagedWireGuardOrdinaryNodeDeleteClosesRemoteLifecycle(t *testing.T) {
	remoteHandler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	createResponse := httptest.NewRecorder()
	remoteHandler.HandleManagedInboundResources(createResponse, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Delete WG")))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		Resource managedInboundResourceDTO `json:"resource"`
		Node     nodeDTO                   `json:"node"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	nodesHandler := NewNodesHandler(repo, t.TempDir(), remoteHandler).(*nodesHandler)
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/admin/nodes/"+strconv.FormatInt(created.Node.ID, 10), nil)
	deleteRequest = deleteRequest.WithContext(auth.ContextWithUsername(deleteRequest.Context(), "admin"))
	deleteResponse := httptest.NewRecorder()
	nodesHandler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	if _, err := repo.GetNodeByID(context.Background(), created.Node.ID); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("ordinary node remained after delete: %v", err)
	}
	if _, err := repo.GetManagedInboundResource(context.Background(), created.Resource.ID); !errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		t.Fatalf("managed resource remained after ordinary node delete: %v", err)
	}
	if actions := agent.actionSnapshot(); len(actions) != 2 || actions[0] != "add" || actions[1] != "remove" {
		t.Fatalf("agent actions=%v, want [add remove]", actions)
	}
}

func TestStaleOrdinaryNodeCleanupCannotDeleteNewSameTagGeneration(t *testing.T) {
	remoteHandler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	createResponse := httptest.NewRecorder()
	remoteHandler.HandleManagedInboundResources(createResponse, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Replace WG")))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		Resource managedInboundResourceDTO `json:"resource"`
		Node     nodeDTO                   `json:"node"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	staleNode, err := repo.GetNodeByID(context.Background(), created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	newMutationID := "managed-wireguard:generation-new"
	currentNode := staleNode
	currentNode.InboundMutationID = newMutationID
	if _, err := repo.UpdateNode(context.Background(), currentNode); err != nil {
		t.Fatal(err)
	}
	resource, err := repo.GetManagedInboundResource(context.Background(), created.Resource.ID)
	if err != nil {
		t.Fatal(err)
	}
	resource.MutationID = newMutationID
	if _, err := repo.UpsertManagedInboundResource(context.Background(), *resource); err != nil {
		t.Fatal(err)
	}
	agent.mu.Lock()
	agent.ownerMutationID = newMutationID
	agent.mu.Unlock()

	nodesHandler := NewNodesHandler(repo, t.TempDir(), remoteHandler).(*nodesHandler)
	err = nodesHandler.cleanupRemoteInboundForNode(context.Background(), &staleNode)
	if err == nil || !strings.Contains(err.Error(), "新一代") {
		t.Fatalf("stale cleanup err=%v", err)
	}
	if !agent.hasInbound() {
		t.Fatal("stale cleanup removed the newer remote inbound")
	}
	keptNode, err := repo.GetNodeByID(context.Background(), staleNode.ID)
	if err != nil || keptNode.InboundMutationID != newMutationID {
		t.Fatalf("new node generation lost: node=%+v err=%v", keptNode, err)
	}
	keptResource, err := repo.GetManagedInboundResource(context.Background(), resource.ID)
	if err != nil || keptResource.MutationID != newMutationID {
		t.Fatalf("new resource generation lost: resource=%+v err=%v", keptResource, err)
	}
}

func TestManagedWireGuardOrdinaryNodeDeleteRetainsEncryptedNodeWhenRemoteCleanupFails(t *testing.T) {
	remoteHandler, repo, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	createResponse := httptest.NewRecorder()
	remoteHandler.HandleManagedInboundResources(createResponse, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10),
		managedWireGuardCreateBody(t, "Retain WG")))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		Resource managedInboundResourceDTO `json:"resource"`
		Node     nodeDTO                   `json:"node"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	agent.setRejectRemove(true)
	nodesHandler := NewNodesHandler(repo, t.TempDir(), remoteHandler)
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/admin/nodes/"+strconv.FormatInt(created.Node.ID, 10), nil)
	deleteRequest = deleteRequest.WithContext(auth.ContextWithUsername(deleteRequest.Context(), "admin"))
	deleteResponse := httptest.NewRecorder()
	nodesHandler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusBadGateway || !strings.Contains(deleteResponse.Body.String(), "已保留本地节点和加密凭据") {
		t.Fatalf("delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	node, err := repo.GetNodeByID(context.Background(), created.Node.ID)
	if err != nil || !strings.Contains(node.ClashConfig, `"private-key"`) {
		t.Fatalf("remote failure lost the encrypted client node: node=%+v err=%v", node, err)
	}
	if _, err := repo.GetManagedInboundResource(context.Background(), created.Resource.ID); err != nil {
		t.Fatalf("remote failure removed managed resource: %v", err)
	}
	if !agent.hasInbound() {
		t.Fatal("remote WireGuard inbound was removed despite the reported failure")
	}
}

func TestManagedWireGuardRejectsMismatchedClientKeysBeforeAgent(t *testing.T) {
	handler, _, server, agent, _ := newManagedInboundHandlerTest(t, nil)
	body := managedWireGuardCreateBody(t, "Mismatched WG")
	client := body["client"].(map[string]interface{})
	client["public_key"] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	response := httptest.NewRecorder()
	handler.HandleManagedInboundResources(response, managedWireGuardRequest(t, http.MethodPost,
		managedInboundResourcesPath+"/wireguard?server_id="+strconv.FormatInt(server.ID, 10), body))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "does not match") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if actions := agent.actionSnapshot(); len(actions) != 0 {
		t.Fatalf("mismatched keys reached Agent: %v", actions)
	}
}
