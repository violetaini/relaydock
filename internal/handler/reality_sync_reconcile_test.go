package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

const (
	realitySyncStoredUUID = "11111111-1111-4111-8111-111111111111"
	realitySyncWrongUUID  = "22222222-2222-4222-8222-222222222222"
	realitySyncUserUUID   = "33333333-3333-4333-8333-333333333333"
	realitySyncRoutedUUID = "44444444-4444-4444-8444-444444444444"
)

type realitySyncAgent struct {
	mu       sync.Mutex
	inbounds []map[string]interface{}
	actions  []realitySyncAction
}

type realitySyncAction struct {
	Action string
	Tag    string
	Client map[string]interface{}
}

func (a *realitySyncAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		a.mu.Lock()
		inbounds := cloneRealitySyncInbounds(a.inbounds)
		a.mu.Unlock()
		owners := make(map[string]string, len(inbounds))
		for _, inbound := range inbounds {
			tag, _ := inbound["tag"].(string)
			if tag == "" {
				continue
			}
			inbound["_mutation_fence_known"] = true
			inbound["_mutation_id"] = "reality-sync-generation"
			owners[tag] = "reality-sync-generation"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "inbounds": inbounds,
			"mutation_fence_known": true, "mutation_owners": owners,
		})

	case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  `{"inbounds":[],"routing":{"rules":[]}}`,
		})

	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		var request struct {
			Action     string                 `json:"action"`
			Tag        string                 `json:"tag"`
			MutationID string                 `json:"mutation_id"`
			Client     map[string]interface{} `json:"client"`
			Inbound    map[string]interface{} `json:"inbound"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, `{"success":false,"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		a.mu.Lock()
		defer a.mu.Unlock()
		if request.Action == "add" {
			tag, _ := request.Inbound["tag"].(string)
			if tag == "" {
				http.Error(w, `{"success":false,"error":"inbound tag is required"}`, http.StatusBadRequest)
				return
			}
			for i, inbound := range a.inbounds {
				if inboundTag, _ := inbound["tag"].(string); inboundTag == tag {
					a.inbounds[i] = cloneRealitySyncMap(request.Inbound)
					a.actions = append(a.actions, realitySyncAction{Action: request.Action, Tag: tag})
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "changed": true, "mutation_id": request.MutationID})
					return
				}
			}
			a.inbounds = append(a.inbounds, cloneRealitySyncMap(request.Inbound))
			a.actions = append(a.actions, realitySyncAction{Action: request.Action, Tag: tag})
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "changed": true, "mutation_id": request.MutationID})
			return
		}
		if request.Action != "add-client" && request.Action != "remove-client" {
			http.Error(w, `{"success":false,"error":"unsupported action"}`, http.StatusBadRequest)
			return
		}
		for _, inbound := range a.inbounds {
			if inboundTag, _ := inbound["tag"].(string); inboundTag != request.Tag {
				continue
			}
			changed, err := mutateInboundClient(inbound, request.Client, request.Action == "add-client")
			if err != nil {
				http.Error(w, `{"success":false,"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			a.actions = append(a.actions, realitySyncAction{
				Action: request.Action,
				Tag:    request.Tag,
				Client: cloneRealitySyncMap(request.Client),
			})
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"changed": changed,
			})
			return
		}
		http.Error(w, `{"success":false,"error":"inbound not found"}`, http.StatusNotFound)

	default:
		http.NotFound(w, r)
	}
}

func (a *realitySyncAgent) inboundSnapshot(tag string) map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, inbound := range a.inbounds {
		if inboundTag, _ := inbound["tag"].(string); inboundTag == tag {
			return cloneRealitySyncMap(inbound)
		}
	}
	return nil
}

func (a *realitySyncAgent) actionSnapshot() []realitySyncAction {
	a.mu.Lock()
	defer a.mu.Unlock()
	actions := make([]realitySyncAction, len(a.actions))
	for i, action := range a.actions {
		actions[i] = realitySyncAction{
			Action: action.Action,
			Tag:    action.Tag,
			Client: cloneRealitySyncMap(action.Client),
		}
	}
	return actions
}

func cloneRealitySyncInbounds(inbounds []map[string]interface{}) []map[string]interface{} {
	cloned := make([]map[string]interface{}, 0, len(inbounds))
	for _, inbound := range inbounds {
		cloned = append(cloned, cloneRealitySyncMap(inbound))
	}
	return cloned
}

func cloneRealitySyncMap(value map[string]interface{}) map[string]interface{} {
	if value == nil {
		return nil
	}
	raw, _ := json.Marshal(value)
	var cloned map[string]interface{}
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func realitySyncInbound(clients []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"tag":      "reality-in",
		"protocol": "vless",
		"port":     float64(39881),
		"settings": map[string]interface{}{
			"clients":    clients,
			"decryption": "none",
		},
		"streamSettings": map[string]interface{}{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"publicKey":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"shortIds":    []interface{}{"1234567890abcdef"},
				"serverNames": []interface{}{"www.example.com"},
			},
		},
	}
}

func realitySyncStoredNode() storage.Node {
	return storage.Node{
		Username:       "admin",
		NodeName:       "Edge Reality",
		Protocol:       "vless",
		OriginalServer: "edge-reality",
		InboundTag:     "reality-in",
		NodeType:       "physical",
		ClashConfig: `{"name":"Edge Reality","type":"vless","server":"198.51.100.20","port":39881,` +
			`"uuid":"` + realitySyncStoredUUID + `","flow":"xtls-rprx-vision","network":"tcp","tls":true,` +
			`"dialer-proxy":"relay-hop"}`,
	}
}

func TestReconcileManagedRealityInboundRestoresPublishedClient(t *testing.T) {
	tests := []struct {
		name    string
		clients []interface{}
		wantLen int
	}{
		{
			name:    "empty clients",
			clients: []interface{}{},
			wantLen: 1,
		},
		{
			name: "wrong UUID and missing flow while retaining user client",
			clients: []interface{}{
				map[string]interface{}{
					"id": realitySyncWrongUUID, "email": "admin", "level": float64(0),
				},
				map[string]interface{}{
					"id": realitySyncUserUUID, "email": "alice__reality-in", "flow": "xtls-rprx-vision",
				},
			},
			wantLen: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inbound := realitySyncInbound(test.clients)
			original := cloneRealitySyncMap(inbound)
			node := realitySyncStoredNode()

			reconciled, changed, managed, err := reconcileManagedRealityInbound(inbound, &node, "admin")
			if err != nil {
				t.Fatalf("reconcileManagedRealityInbound: %v", err)
			}
			if !managed || !changed {
				t.Fatalf("managed=%v changed=%v, want both true", managed, changed)
			}
			if !reflect.DeepEqual(inbound, original) {
				t.Fatalf("helper mutated input inbound: got=%#v want=%#v", inbound, original)
			}

			settings, _ := reconciled["settings"].(map[string]interface{})
			clients, _ := settings["clients"].([]interface{})
			if len(clients) != test.wantLen {
				t.Fatalf("clients=%#v, want %d entries", clients, test.wantLen)
			}
			adminClient, _ := clients[0].(map[string]interface{})
			if adminClient["id"] != realitySyncStoredUUID || adminClient["email"] != "admin" || adminClient["flow"] != "xtls-rprx-vision" {
				t.Fatalf("restored admin client=%#v", adminClient)
			}
			if test.wantLen == 2 {
				if adminClient["level"] != float64(0) {
					t.Fatalf("admin non-credential fields were discarded: %#v", adminClient)
				}
				userClient, _ := clients[1].(map[string]interface{})
				if userClient["id"] != realitySyncUserUUID || userClient["email"] != "alice__reality-in" || userClient["flow"] != "xtls-rprx-vision" {
					t.Fatalf("unrelated user client changed: %#v", userClient)
				}
			}
		})
	}
}

func TestReconcileManagedRealityInboundAddsCompatibilityMinimumDuringBackgroundSync(t *testing.T) {
	node := realitySyncStoredNode()
	admin := map[string]interface{}{
		"id":    realitySyncStoredUUID,
		"email": "admin",
		"flow":  "xtls-rprx-vision",
	}

	t.Run("missing value receives managed default", func(t *testing.T) {
		inbound := realitySyncInbound([]interface{}{admin})
		reconciled, changed, managed, err := reconcileManagedRealityInbound(inbound, &node, "admin")
		if err != nil || !managed || !changed {
			t.Fatalf("managed=%v changed=%v err=%v, want automatic compatibility rewrite", managed, changed, err)
		}
		stream := reconciled["streamSettings"].(map[string]interface{})
		reality := stream["realitySettings"].(map[string]interface{})
		if got := reality["minClientVer"]; got != managedRealityMinClientVersion {
			t.Fatalf("background sync minClientVer=%#v, want %q", got, managedRealityMinClientVersion)
		}
	})

	t.Run("explicit value remains untouched", func(t *testing.T) {
		inbound := realitySyncInbound([]interface{}{admin})
		stream := inbound["streamSettings"].(map[string]interface{})
		stream["realitySettings"].(map[string]interface{})["minClientVer"] = "26.3.27"
		reconciled, changed, managed, err := reconcileManagedRealityInbound(inbound, &node, "admin")
		if err != nil || !managed || changed {
			t.Fatalf("managed=%v changed=%v err=%v, want preserved explicit value", managed, changed, err)
		}
		reality := reconciled["streamSettings"].(map[string]interface{})["realitySettings"].(map[string]interface{})
		if got := reality["minClientVer"]; got != "26.3.27" {
			t.Fatalf("minClientVer=%#v, want explicit value preserved", got)
		}
	})
}

func TestMergeManagedPhysicalNodeConfigLeavesRoutedNodeUntouched(t *testing.T) {
	parentID := int64(41)
	routed := realitySyncStoredNode()
	routed.ID = 42
	routed.NodeType = "routed"
	routed.ParentNodeID = &parentID
	original := routed

	merged, changed, err := mergeManagedPhysicalNodeConfig(routed, map[string]interface{}{
		"name": "live", "type": "vless", "server": "203.0.113.99", "port": 443,
		"uuid": realitySyncWrongUUID, "flow": "xtls-rprx-vision",
	})
	if err != nil {
		t.Fatalf("mergeManagedPhysicalNodeConfig: %v", err)
	}
	if changed || !reflect.DeepEqual(merged, original) {
		t.Fatalf("routed node was modified: changed=%v got=%#v want=%#v", changed, merged, original)
	}
}

func TestSyncInboundsReconcilesOnlyMatchingPhysicalRealityNode(t *testing.T) {
	tests := []struct {
		name             string
		liveClients      []interface{}
		wantClientCount  int
		withIsolationSet bool
	}{
		{
			name:            "empty live clients restore stored UUID and flow",
			liveClients:     []interface{}{},
			wantClientCount: 1,
		},
		{
			name: "drifted owner is replaced without changing user or routed nodes",
			liveClients: []interface{}{
				map[string]interface{}{"id": realitySyncWrongUUID, "email": "admin"},
				map[string]interface{}{
					"id": realitySyncUserUUID, "email": "alice__reality-in", "flow": "xtls-rprx-vision",
				},
			},
			wantClientCount:  2,
			withIsolationSet: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "reality-sync.db"))
			if err != nil {
				t.Fatalf("NewTrafficRepository: %v", err)
			}
			t.Cleanup(func() { _ = repo.Close() })
			if err := repo.CreateUser(ctx, "admin", "admin@example.test", "Admin", "test-hash", storage.RoleAdmin, ""); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}

			agentState := &realitySyncAgent{inbounds: []map[string]interface{}{realitySyncInbound(test.liveClients)}}
			agent := httptest.NewServer(agentState)
			t.Cleanup(agent.Close)
			server := createTunnelChainRemoteServer(t, repo, "edge-reality", agent.URL)

			physicalTemplate := realitySyncStoredNode()
			physical, err := repo.CreateNode(ctx, physicalTemplate)
			if err != nil {
				t.Fatalf("CreateNode(physical): %v", err)
			}
			var routed storage.RoutedNodeDetail
			var otherServerNode, otherTagNode storage.Node
			if test.withIsolationSet {
				parentID := physical.ID
				routedConfig := realitySyncConfig("Routed Reality", realitySyncRoutedUUID, "192.0.2.44", 443)
				routed, err = repo.CreateRoutedNode(ctx, storage.RoutedNodeDetail{
					Node: storage.Node{
						Username: "admin", NodeName: "Routed Reality", Protocol: "vless", Enabled: true,
						OriginalServer: server.Name, InboundTag: "reality-in", ParentNodeID: &parentID,
						ClashConfig: routedConfig, ParsedConfig: routedConfig,
					},
					RoutedOutboundTag:     "proxy-out",
					RoutedOutboundJSON:    `{"tag":"proxy-out","protocol":"freedom"}`,
					RoutedRuleMarktag:     "route-mark",
					RoutedAdminCredential: `{"id":"` + realitySyncRoutedUUID + `","email":"admin"}`,
				})
				if err != nil {
					t.Fatalf("CreateRoutedNode: %v", err)
				}

				otherServerConfig := realitySyncConfig("Other Server", realitySyncWrongUUID, "192.0.2.50", 39881)
				otherServerNode, err = repo.CreateNode(ctx, storage.Node{
					Username: "admin", NodeName: "Other Server", Protocol: "vless", Enabled: true,
					OriginalServer: "edge-other", InboundTag: "reality-in",
					ClashConfig: otherServerConfig, ParsedConfig: otherServerConfig,
				})
				if err != nil {
					t.Fatalf("CreateNode(other server): %v", err)
				}

				otherTagConfig := realitySyncConfig("Other Tag", realitySyncWrongUUID, "192.0.2.51", 39882)
				otherTagNode, err = repo.CreateNode(ctx, storage.Node{
					Username: "admin", NodeName: "Other Tag", Protocol: "vless", Enabled: true,
					OriginalServer: server.Name, InboundTag: "other-reality-in",
					ClashConfig: otherTagConfig, ParsedConfig: otherTagConfig,
				})
				if err != nil {
					t.Fatalf("CreateNode(other tag): %v", err)
				}
			}

			handler := NewRemoteManageHandler(repo, nil)
			result := handler.syncInboundsToNodesInternal(ctx, server.ID)
			if !result.Success || len(result.Errors) != 0 {
				t.Fatalf("sync result=%+v", result)
			}

			liveInbound := agentState.inboundSnapshot("reality-in")
			clients := realitySyncClients(t, liveInbound)
			if len(clients) != test.wantClientCount {
				t.Fatalf("live clients=%#v, want %d entries", clients, test.wantClientCount)
			}
			if clients[0]["id"] != realitySyncStoredUUID || clients[0]["email"] != "admin" || clients[0]["flow"] != "xtls-rprx-vision" {
				t.Fatalf("live admin credential was not restored: %#v", clients[0])
			}
			if test.wantClientCount == 2 {
				if clients[1]["id"] != realitySyncUserUUID || clients[1]["email"] != "alice__reality-in" || clients[1]["flow"] != "xtls-rprx-vision" {
					t.Fatalf("non-admin client changed: %#v", clients[1])
				}
			}
			actions := agentState.actionSnapshot()
			if len(actions) != 1 || actions[0].Action != "add" || actions[0].Tag != "reality-in" {
				t.Fatalf("Agent actions=%#v, want one exact inbound replacement", actions)
			}

			storedPhysical, err := repo.GetNode(ctx, physical.ID, "admin")
			if err != nil {
				t.Fatalf("GetNode(physical): %v", err)
			}
			var reconciledConfig map[string]interface{}
			if err := json.Unmarshal([]byte(storedPhysical.ClashConfig), &reconciledConfig); err != nil {
				t.Fatalf("decode reconciled physical config: %v", err)
			}
			if reconciledConfig["uuid"] != realitySyncStoredUUID || reconciledConfig["flow"] != "xtls-rprx-vision" {
				t.Fatalf("physical node credential drifted: %#v", reconciledConfig)
			}
			if reconciledConfig["name"] != "Edge Reality" || int(reconciledConfig["port"].(float64)) != 39881 ||
				reconciledConfig["dialer-proxy"] != "relay-hop" {
				t.Fatalf("physical endpoint/chain fields were overwritten: %#v", reconciledConfig)
			}

			if test.withIsolationSet {
				storedRouted, err := repo.GetRoutedNodeDetail(ctx, routed.ID)
				if err != nil {
					t.Fatalf("GetRoutedNodeDetail: %v", err)
				}
				assertRealitySyncConfigFieldsUnchanged(t, routed.ClashConfig, storedRouted.ClashConfig)
				if storedRouted.ParsedConfig != routed.ParsedConfig || storedRouted.RoutedOutboundTag != routed.RoutedOutboundTag ||
					storedRouted.RoutedOutboundJSON != routed.RoutedOutboundJSON || storedRouted.RoutedRuleMarktag != routed.RoutedRuleMarktag ||
					storedRouted.RoutedAdminCredential != routed.RoutedAdminCredential || storedRouted.InboundTag != routed.InboundTag ||
					storedRouted.OriginalServer != routed.OriginalServer || !reflect.DeepEqual(storedRouted.ParentNodeID, routed.ParentNodeID) {
					t.Fatalf("routed node metadata changed: before=%#v after=%#v", routed, storedRouted)
				}
				assertRealitySyncNodeUnchanged(t, repo, otherServerNode, false)
				assertRealitySyncNodeUnchanged(t, repo, otherTagNode, true)
			}
		})
	}
}

func realitySyncConfig(name, id, server string, port int) string {
	config, _ := json.Marshal(map[string]interface{}{
		"name": name, "type": "vless", "server": server, "port": port,
		"uuid": id, "flow": "xtls-rprx-vision", "network": "tcp", "tls": true,
	})
	return string(config)
}

func realitySyncClients(t *testing.T, inbound map[string]interface{}) []map[string]interface{} {
	t.Helper()
	settings, _ := inbound["settings"].(map[string]interface{})
	rawClients, _ := settings["clients"].([]interface{})
	clients := make([]map[string]interface{}, 0, len(rawClients))
	for _, rawClient := range rawClients {
		client, _ := rawClient.(map[string]interface{})
		if client == nil {
			t.Fatalf("invalid client entry: %#v", rawClient)
		}
		clients = append(clients, client)
	}
	return clients
}

func assertRealitySyncNodeUnchanged(t *testing.T, repo *storage.TrafficRepository, original storage.Node, allowServerRefresh bool) {
	t.Helper()
	stored, err := repo.GetNode(context.Background(), original.ID, original.Username)
	if err != nil {
		t.Fatalf("GetNode(%d): %v", original.ID, err)
	}
	if allowServerRefresh {
		assertRealitySyncConfigFieldsUnchanged(t, original.ClashConfig, stored.ClashConfig)
	} else if stored.ClashConfig != original.ClashConfig {
		t.Fatalf("unrelated physical config changed: before=%s after=%s", original.ClashConfig, stored.ClashConfig)
	}
	if stored.ParsedConfig != original.ParsedConfig || stored.OriginalServer != original.OriginalServer || stored.InboundTag != original.InboundTag {
		t.Fatalf("unrelated physical node changed: before=%#v after=%#v", original, stored)
	}
}

func assertRealitySyncConfigFieldsUnchanged(t *testing.T, beforeJSON, afterJSON string) {
	t.Helper()
	var before, after map[string]interface{}
	if err := json.Unmarshal([]byte(beforeJSON), &before); err != nil {
		t.Fatalf("decode original config: %v", err)
	}
	if err := json.Unmarshal([]byte(afterJSON), &after); err != nil {
		t.Fatalf("decode stored config: %v", err)
	}
	delete(before, "server")
	delete(after, "server")
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("config fields other than server changed: before=%#v after=%#v", before, after)
	}
}
