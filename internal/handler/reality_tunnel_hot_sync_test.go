package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/event"
	"github.com/violetaini/relaydock/internal/storage"
)

type realityTunnelHotSyncAgent struct {
	mu sync.Mutex

	inbounds map[string]map[string]interface{}
	routing  map[string]interface{}

	inboundPosts    int
	routingPosts    int
	routingGets     int
	inboundGets     int
	xrayConfigCalls int
	serviceControls int
	failRoutingSets int
}

func newRealityTunnelHotSyncAgent(tunnel map[string]interface{}, routing map[string]interface{}) *realityTunnelHotSyncAgent {
	return &realityTunnelHotSyncAgent{
		inbounds: map[string]map[string]interface{}{
			"tunnel-in": cloneRealityHotSyncMap(tunnel),
		},
		routing: cloneRealityHotSyncMap(routing),
	}
}

func (a *realityTunnelHotSyncAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	a.mu.Lock()
	defer a.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		a.inboundGets++
		inbounds := make([]map[string]interface{}, 0, len(a.inbounds))
		for _, inbound := range a.inbounds {
			inbounds = append(inbounds, cloneRealityHotSyncMap(inbound))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "inbounds": inbounds})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		var request struct {
			Action     string                 `json:"action"`
			Tag        string                 `json:"tag"`
			Inbound    map[string]interface{} `json:"inbound"`
			MutationID string                 `json:"mutation_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.inboundPosts++
		if request.Action == "remove" {
			delete(a.inbounds, request.Tag)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "changed": true, "mutation_id": request.MutationID,
			})
			return
		}
		stored := cloneRealityHotSyncMap(request.Inbound)
		stored["_mutation_id"] = request.MutationID
		a.inbounds[wireGuardStringValue(stored["tag"])] = stored
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "changed": true, "mutation_id": request.MutationID,
		})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/routing":
		a.routingGets++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "routing": cloneRealityHotSyncMap(a.routing),
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/routing":
		var request struct {
			Action  string                 `json:"action"`
			Routing map[string]interface{} `json:"routing"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Action != "set_hot" {
			http.Error(w, `{"success":false,"error":"set_hot required"}`, http.StatusBadRequest)
			return
		}
		a.routingPosts++
		if a.failRoutingSets > 0 {
			a.failRoutingSets--
			http.Error(w, `{"success":false,"error":"injected hot route failure"}`, http.StatusConflict)
			return
		}
		a.routing = cloneRealityHotSyncMap(request.Routing)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "changed": true})
	case r.URL.Path == "/api/child/xray/config":
		a.xrayConfigCalls++
		http.Error(w, `{"success":false,"error":"raw config forbidden"}`, http.StatusInternalServerError)
	case r.URL.Path == "/api/child/services/control":
		a.serviceControls++
		http.Error(w, `{"success":false,"error":"service control forbidden"}`, http.StatusInternalServerError)
	default:
		http.NotFound(w, r)
	}
}

func (a *realityTunnelHotSyncAgent) snapshot() (map[string]interface{}, map[string]interface{}, int, int, int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return cloneRealityHotSyncMap(a.inbounds["tunnel-in"]), cloneRealityHotSyncMap(a.routing),
		a.inboundPosts, a.routingPosts, a.xrayConfigCalls, a.serviceControls
}

func realityHotSyncTunnelInbound(targetPort int) map[string]interface{} {
	return map[string]interface{}{
		"tag":      "tunnel-in",
		"port":     float64(443),
		"protocol": "tunnel",
		"settings": map[string]interface{}{
			"address": "127.0.0.1",
			"port":    float64(targetPort),
			"network": "tcp",
		},
		"_mutation_id": "system:tunnel-in",
	}
}

func seedRealityHotSyncTunnel(t *testing.T, repo *storage.TrafficRepository, serverID int64, tunnel map[string]interface{}) {
	t.Helper()
	seedRealityHotSyncDesiredInbound(t, repo, serverID, tunnel, "system:tunnel-in")
}

func seedRealityHotSyncDesiredInbound(t *testing.T, repo *storage.TrafficRepository, serverID int64, inbound map[string]interface{}, mutationID string) {
	t.Helper()
	desired := observedInboundConfig(inbound)
	raw, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	tag := wireGuardStringValue(inbound["tag"])
	if _, err := repo.UpsertActiveDesiredInbound(context.Background(), serverID, tag, mutationID, raw); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetRemoteInboundOwnership(context.Background(), serverID, tag, mutationID); err != nil {
		t.Fatal(err)
	}
}

func realityHotSyncRouting(domains ...string) map[string]interface{} {
	rawDomains := make([]interface{}, 0, len(domains))
	for _, domain := range domains {
		rawDomains = append(rawDomains, domain)
	}
	return map[string]interface{}{
		"domainStrategy": "AsIs",
		"rules": []interface{}{
			map[string]interface{}{
				"type": "field", "inboundTag": []interface{}{"tunnel-in"},
				"domain": rawDomains, "outboundTag": "nginx",
			},
		},
	}
}

func realityHotSyncRouteDomains(t *testing.T, routing map[string]interface{}) []string {
	t.Helper()
	rules, _ := routing["rules"].([]interface{})
	for _, rawRule := range rules {
		rule, _ := rawRule.(map[string]interface{})
		if wireGuardStringValue(rule["outboundTag"]) != "nginx" {
			continue
		}
		return wireGuardStringValues(rule["domain"])
	}
	return nil
}

func TestRealityCreatePostSyncHotReplacesTunnelAndRoutingWithoutRestart(t *testing.T) {
	tunnel := realityHotSyncTunnelInbound(46174)
	agent := newRealityTunnelHotSyncAgent(tunnel, realityHotSyncRouting("reality.example.test", "site.example.test"))
	agentServer := httptest.NewServer(agent)
	defer agentServer.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	seedRealityHotSyncTunnel(t, repo, server.ID, tunnel)
	handler := NewRemoteManageHandler(repo, nil)
	realityInbound := map[string]interface{}{
		"tag": "reality-in", "port": float64(39081), "protocol": "vless",
		"streamSettings": map[string]interface{}{
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"serverNames": []interface{}{"reality.example.test"},
			},
		},
	}
	// The primary add has already committed when this post-sync helper runs.
	agent.mu.Lock()
	agent.inbounds["reality-in"] = cloneRealityHotSyncMap(realityInbound)
	agent.mu.Unlock()

	if err := handler.cleanupTunnelRouteForReality(context.Background(), server.ID, realityInbound); err != nil {
		t.Fatalf("cleanupTunnelRouteForReality: %v", err)
	}
	gotTunnel, gotRouting, inboundPosts, routingPosts, configCalls, serviceControls := agent.snapshot()
	settings, _ := gotTunnel["settings"].(map[string]interface{})
	if port, ok := wireGuardNumericValue(settings["port"]); !ok || int(port) != 39081 {
		t.Fatalf("tunnel-in target port=%v, want 39081", settings["port"])
	}
	if inboundPosts != 1 || routingPosts != 1 {
		t.Fatalf("hot mutations inbound=%d routing=%d, want 1/1", inboundPosts, routingPosts)
	}
	if got := realityHotSyncRouteDomains(t, gotRouting); len(got) != 1 || got[0] != "site.example.test" {
		t.Fatalf("routing domains=%v, want [site.example.test]", got)
	}
	if configCalls != 0 || serviceControls != 0 {
		t.Fatalf("create post-sync called raw config=%d service control=%d", configCalls, serviceControls)
	}
}

func TestRealityCreateHotSyncFailureCompensatesAcknowledgedInbound(t *testing.T) {
	tunnel := realityHotSyncTunnelInbound(46174)
	agent := newRealityTunnelHotSyncAgent(tunnel, realityHotSyncRouting("rollback.example.test", "site.example.test"))
	agent.failRoutingSets = 1
	agentServer := httptest.NewServer(agent)
	defer agentServer.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	seedRealityHotSyncTunnel(t, repo, server.ID, tunnel)
	if err := repo.CreateUser(context.Background(), "admin", "admin@example.test", "Admin", "test-hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	handler := NewRemoteManageHandler(repo, nil)
	handler.publishInboundEvent = func(event.InboundEvent) error { return nil }
	realityInbound := map[string]interface{}{
		"tag": "rollback-reality", "port": float64(39084), "protocol": "vless",
		"settings": map[string]interface{}{
			"clients": []interface{}{}, "decryption": "none",
		},
		"streamSettings": map[string]interface{}{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]interface{}{
				"target": "rollback.example.test:443", "serverNames": []interface{}{"rollback.example.test"},
				"shortIds": []interface{}{"1234567890abcdef"},
			},
		},
	}
	body, _ := json.Marshal(map[string]interface{}{
		"action": "add", "inbound": realityInbound, "mutation_id": "rollback-reality-generation",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/remote/inbounds?server_id="+strconv.FormatInt(server.ID, 10), bytes.NewReader(body))
	requestContext := auth.ContextWithUsername(context.Background(), "admin")
	request = request.WithContext(suppressDatabaseInboundPostWrite(requestContext))
	response := httptest.NewRecorder()
	handler.HandleInbounds(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("HandleInbounds status=%d body=%s", response.Code, response.Body.String())
	}

	agent.mu.Lock()
	_, realityStillPresent := agent.inbounds["rollback-reality"]
	agent.mu.Unlock()
	gotTunnel, gotRouting, inboundPosts, routingPosts, configCalls, serviceControls := agent.snapshot()
	if realityStillPresent {
		t.Fatal("failed Reality create remained after acknowledged-add compensation")
	}
	settings, _ := gotTunnel["settings"].(map[string]interface{})
	if port, ok := wireGuardNumericValue(settings["port"]); !ok || int(port) != 46174 {
		t.Fatalf("tunnel rollback port=%v, want 46174", settings["port"])
	}
	if got := realityHotSyncRouteDomains(t, gotRouting); len(got) != 2 || got[0] != "rollback.example.test" {
		t.Fatalf("route rollback domains=%v", got)
	}
	if inboundPosts != 4 || routingPosts != 2 {
		t.Fatalf("compensation mutations inbound=%d routing=%d, want 4/2", inboundPosts, routingPosts)
	}
	if configCalls != 0 || serviceControls != 0 {
		t.Fatalf("failed create called raw config=%d service control=%d", configCalls, serviceControls)
	}
}

func TestRealityDeletePostSyncHotRestoresRouteOnlyOnActualChange(t *testing.T) {
	tunnel := realityHotSyncTunnelInbound(39081)
	agent := newRealityTunnelHotSyncAgent(tunnel, realityHotSyncRouting("site.example.test"))
	deletedReality := map[string]interface{}{
		"tag": "deleted-reality", "port": float64(39081), "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{}},
		"streamSettings": map[string]interface{}{
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"serverNames": []interface{}{"reality.example.test"},
			},
		},
		"_mutation_id": "deleted-reality-generation",
	}
	nextReality := map[string]interface{}{
		"tag": "next-reality", "port": float64(39082), "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{}},
		"streamSettings": map[string]interface{}{
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"serverNames": []interface{}{"next.example.test"},
			},
		},
		"_mutation_id": "next-reality-generation",
	}
	agent.inbounds["deleted-reality"] = cloneRealityHotSyncMap(deletedReality)
	agent.inbounds["next-reality"] = cloneRealityHotSyncMap(nextReality)
	agentServer := httptest.NewServer(agent)
	defer agentServer.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	seedRealityHotSyncTunnel(t, repo, server.ID, tunnel)
	seedRealityHotSyncDesiredInbound(t, repo, server.ID, deletedReality, "deleted-reality-generation")
	seedRealityHotSyncDesiredInbound(t, repo, server.ID, nextReality, "next-reality-generation")
	handler := NewRemoteManageHandler(repo, nil)
	handler.publishInboundEvent = func(event.InboundEvent) error { return nil }

	body, _ := json.Marshal(map[string]interface{}{
		"action": "remove", "tag": "deleted-reality", "mutation_id": "deleted-reality-generation",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/remote/inbounds?server_id="+strconv.FormatInt(server.ID, 10), bytes.NewReader(body))
	request = request.WithContext(suppressDatabaseInboundPostWrite(context.Background()))
	response := httptest.NewRecorder()
	handler.HandleInbounds(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("HandleInbounds status=%d body=%s", response.Code, response.Body.String())
	}
	// A retry sees both the restored route and the already-retargeted tunnel, so
	// it must not emit either hot mutation again.
	if err := handler.restoreTunnelRouteForReality(context.Background(), server.ID, []string{"reality.example.test"}, 39081); err != nil {
		t.Fatalf("idempotent restoreTunnelRouteForReality: %v", err)
	}
	gotTunnel, gotRouting, inboundPosts, routingPosts, configCalls, serviceControls := agent.snapshot()
	settings, _ := gotTunnel["settings"].(map[string]interface{})
	if port, ok := wireGuardNumericValue(settings["port"]); !ok || int(port) != 39082 {
		t.Fatalf("tunnel-in target port=%v, want remaining Reality 39082", settings["port"])
	}
	if inboundPosts != 2 || routingPosts != 1 {
		t.Fatalf("delete mutations inbound=%d routing=%d, want remove+retarget / 1", inboundPosts, routingPosts)
	}
	if got := realityHotSyncRouteDomains(t, gotRouting); len(got) != 2 || got[0] != "site.example.test" || got[1] != "reality.example.test" {
		t.Fatalf("routing domains=%v", got)
	}
	if configCalls != 0 || serviceControls != 0 {
		t.Fatalf("delete post-sync called raw config=%d service control=%d", configCalls, serviceControls)
	}
}

func TestNodeDeleteRemoteInboundRetargetsTunnelToRemainingReality(t *testing.T) {
	tunnel := realityHotSyncTunnelInbound(39081)
	agent := newRealityTunnelHotSyncAgent(tunnel, realityHotSyncRouting("site.example.test"))
	deletedReality := map[string]interface{}{
		"tag": "node-deleted-reality", "port": float64(39081), "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{}},
		"streamSettings": map[string]interface{}{
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"serverNames": []interface{}{"node-reality.example.test"},
			},
		},
		"_mutation_id": "node-delete-generation",
	}
	nextReality := map[string]interface{}{
		"tag": "node-next-reality", "port": float64(39083), "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{}},
		"streamSettings": map[string]interface{}{
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"serverNames": []interface{}{"node-next.example.test"},
			},
		},
		"_mutation_id": "node-next-generation",
	}
	agent.inbounds["node-deleted-reality"] = cloneRealityHotSyncMap(deletedReality)
	agent.inbounds["node-next-reality"] = cloneRealityHotSyncMap(nextReality)
	agentServer := httptest.NewServer(agent)
	defer agentServer.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	seedRealityHotSyncTunnel(t, repo, server.ID, tunnel)
	seedRealityHotSyncDesiredInbound(t, repo, server.ID, deletedReality, "node-delete-generation")
	seedRealityHotSyncDesiredInbound(t, repo, server.ID, nextReality, "node-next-generation")
	remote := NewRemoteManageHandler(repo, nil)
	handler := &nodesHandler{repo: repo, remoteManage: remote}
	ctx := suppressDatabaseInboundPostWrite(context.Background())
	if err := handler.deleteRemoteInbound(ctx, server.Name, "node-deleted-reality", "node-delete-generation"); err != nil {
		t.Fatalf("deleteRemoteInbound: %v", err)
	}

	gotTunnel, gotRouting, inboundPosts, routingPosts, configCalls, serviceControls := agent.snapshot()
	settings, _ := gotTunnel["settings"].(map[string]interface{})
	if port, ok := wireGuardNumericValue(settings["port"]); !ok || int(port) != 39083 {
		t.Fatalf("tunnel-in target port=%v, want remaining Reality 39083", settings["port"])
	}
	if inboundPosts != 2 || routingPosts != 1 {
		t.Fatalf("node delete mutations inbound=%d routing=%d, want remove+retarget / 1", inboundPosts, routingPosts)
	}
	if got := realityHotSyncRouteDomains(t, gotRouting); len(got) != 2 || got[1] != "node-reality.example.test" {
		t.Fatalf("node delete routing domains=%v", got)
	}
	if configCalls != 0 || serviceControls != 0 {
		t.Fatalf("node delete called raw config=%d service control=%d", configCalls, serviceControls)
	}
}

func TestRealityDeletePostSyncSkipsServerWithoutTunnelTakeover(t *testing.T) {
	tunnel := realityHotSyncTunnelInbound(39081)
	agent := newRealityTunnelHotSyncAgent(tunnel, realityHotSyncRouting("site.example.test"))
	agentServer := httptest.NewServer(agent)
	defer agentServer.Close()

	repo, server := newRemoteInstallationHandlerRepoWithSteal(t, testServerPort(t, agentServer.URL), false)
	handler := NewRemoteManageHandler(repo, nil)
	if err := handler.restoreTunnelRouteForReality(context.Background(), server.ID, []string{"reality.example.test"}); err != nil {
		t.Fatalf("restoreTunnelRouteForReality: %v", err)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if agent.inboundGets != 0 || agent.routingGets != 0 || agent.inboundPosts != 0 || agent.routingPosts != 0 {
		t.Fatalf("non-takeover delete touched Agent: inbound get/post=%d/%d routing get/post=%d/%d",
			agent.inboundGets, agent.inboundPosts, agent.routingGets, agent.routingPosts)
	}
}

func TestRealityDeleteDoesNotRetargetTunnelToAgentOnlyReality(t *testing.T) {
	tunnel := realityHotSyncTunnelInbound(39081)
	agent := newRealityTunnelHotSyncAgent(tunnel, realityHotSyncRouting("site.example.test"))
	agent.inbounds["agent-only-reality"] = map[string]interface{}{
		"tag": "agent-only-reality", "port": float64(39999), "protocol": "vless",
		"streamSettings": map[string]interface{}{
			"security": "reality",
			"realitySettings": map[string]interface{}{
				"serverNames": []interface{}{"agent-only.example.test"},
			},
		},
	}
	agentServer := httptest.NewServer(agent)
	defer agentServer.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	seedRealityHotSyncTunnel(t, repo, server.ID, tunnel)
	handler := NewRemoteManageHandler(repo, nil)
	if err := handler.restoreTunnelRouteForReality(
		context.Background(), server.ID, []string{"removed.example.test"}, 39081,
	); err != nil {
		t.Fatalf("restoreTunnelRouteForReality: %v", err)
	}
	gotTunnel, _, inboundPosts, routingPosts, configCalls, serviceControls := agent.snapshot()
	settings, _ := gotTunnel["settings"].(map[string]interface{})
	if port, ok := wireGuardNumericValue(settings["port"]); !ok || int(port) != 39081 {
		t.Fatalf("tunnel-in retargeted to an Agent-only Reality: %v", settings["port"])
	}
	if inboundPosts != 0 || routingPosts != 1 {
		t.Fatalf("Agent-only candidate mutations inbound=%d routing=%d, want 0/1", inboundPosts, routingPosts)
	}
	if configCalls != 0 || serviceControls != 0 {
		t.Fatalf("Agent-only candidate called raw config=%d service control=%d", configCalls, serviceControls)
	}
}
