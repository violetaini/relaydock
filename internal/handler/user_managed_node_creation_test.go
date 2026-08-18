package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/event"
	"github.com/violetaini/relaydock/internal/storage"
)

type userManagedCreationAgent struct {
	mu               sync.Mutex
	inbounds         map[string]map[string]interface{}
	mutationIDs      map[string]string
	addResponseMode  string
	failRemove       bool
	failRemoveTag    string
	failRemoveClient bool
	failLimiterCall  int
	failDenyEmail    string
	limiterCalls     int
	events           []string
	limiters         []WSLimiterConfigPayload
	ackedLimiters    []WSLimiterConfigPayload
	probeDomains     []string
	requests         []string
}

func cloneUserManagedTestMap(value map[string]interface{}) map[string]interface{} {
	body, _ := json.Marshal(value)
	var cloned map[string]interface{}
	_ = json.Unmarshal(body, &cloned)
	return cloned
}

func (a *userManagedCreationAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	a.mu.Lock()
	a.requests = append(a.requests, r.Method+" "+r.URL.Path)
	a.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "capabilities": managedReadyAgentCapabilities(),
		})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "config": `{"inbounds":[],"routing":{"rules":[]}}`,
		})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		a.mu.Lock()
		inbounds := make([]map[string]interface{}, 0, len(a.inbounds))
		owners := make(map[string]string)
		tags := make([]string, 0, len(a.inbounds))
		for tag := range a.inbounds {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		for _, tag := range tags {
			inbound := cloneUserManagedTestMap(a.inbounds[tag])
			inbound["_mutation_fence_known"] = true
			inbound["_runtime_status"] = "running"
			if mutationID := a.mutationIDs[tag]; mutationID != "" {
				inbound["_mutation_id"] = mutationID
				owners[tag] = mutationID
			}
			inbounds = append(inbounds, inbound)
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "inbounds": inbounds,
			"mutation_fence_known": true, "mutation_owners": owners,
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
		var payload WSLimiterConfigPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		a.events = append(a.events, "limiter")
		a.limiters = append(a.limiters, payload)
		a.limiterCalls++
		fail := a.failLimiterCall > 0 && a.limiterCalls == a.failLimiterCall
		if !fail && a.failDenyEmail != "" {
			for _, limiterUser := range payload.Users {
				if limiterUser.Email == a.failDenyEmail && limiterUser.Denied {
					fail = true
					a.failDenyEmail = ""
					break
				}
			}
		}
		if !fail {
			a.ackedLimiters = append(a.ackedLimiters, payload)
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": !fail})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/domains/latency":
		var payload realityDomainLatencyProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		a.probeDomains = append(a.probeDomains, payload.Domains...)
		a.mu.Unlock()
		results := make([]realityDomainLatencyProbeResult, 0, len(payload.Domains))
		for index, domain := range payload.Domains {
			results = append(results, realityDomainLatencyProbeResult{
				Domain: domain, Target: domain + ":443", Success: true, LatencyMs: int64(index + 1),
			})
		}
		_ = json.NewEncoder(w).Encode(realityDomainLatencyProbeResponse{Success: true, Results: results})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		action := strings.ToLower(strings.TrimSpace(wireGuardStringValue(request["action"])))
		if action == "" {
			action = "add"
		}
		mutationID := strings.TrimSpace(wireGuardStringValue(request["mutation_id"]))
		a.mu.Lock()
		a.events = append(a.events, action)
		switch action {
		case "add":
			inbound, _ := request["inbound"].(map[string]interface{})
			tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
			if a.inbounds == nil {
				a.inbounds = make(map[string]map[string]interface{})
				a.mutationIDs = make(map[string]string)
			}
			a.inbounds[tag] = cloneUserManagedTestMap(inbound)
			a.mutationIDs[tag] = mutationID
			mode := a.addResponseMode
			a.mu.Unlock()
			if mode == "malformed" {
				_, _ = w.Write([]byte(`{"success":`))
				return
			}
		case "remove":
			tag := strings.TrimSpace(wireGuardStringValue(request["tag"]))
			if a.failRemove || tag == a.failRemoveTag {
				a.mu.Unlock()
				http.Error(w, `{"success":false,"error":"simulated remove failure"}`, http.StatusBadGateway)
				return
			}
			if currentMutation := a.mutationIDs[tag]; mutationID != "" && currentMutation != "" && mutationID != currentMutation {
				a.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true, "mutation_id": mutationID, "superseded": true, "changed": false,
				})
				return
			}
			delete(a.inbounds, tag)
			delete(a.mutationIDs, tag)
			a.mu.Unlock()
		case "remove-client":
			if a.failRemoveClient {
				a.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false, "error": "simulated remove-client failure",
				})
				return
			}
			tag := strings.TrimSpace(wireGuardStringValue(request["tag"]))
			client, _ := request["client"].(map[string]interface{})
			inbound := a.inbounds[tag]
			if inbound == nil || client == nil {
				a.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false, "error": "simulated inbound or client missing",
				})
				return
			}
			if _, err := mutateInboundClient(inbound, client, false); err != nil {
				a.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false, "error": err.Error(),
				})
				return
			}
			a.mu.Unlock()
		default:
			a.mu.Unlock()
		}
		response := map[string]interface{}{"success": true, "changed": action == "add" || action == "remove-client"}
		if mutationID != "" {
			response["mutation_id"] = mutationID
		}
		_ = json.NewEncoder(w).Encode(response)
	default:
		http.NotFound(w, r)
	}
}

func (a *userManagedCreationAgent) snapshots() ([]string, []WSLimiterConfigPayload, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.events...), append([]WSLimiterConfigPayload(nil), a.limiters...), len(a.inbounds) > 0
}

type userManagedCreationFixture struct {
	repo    *storage.TrafficRepository
	handler *ManagedNodesHandler
	agent   *userManagedCreationAgent
	server  *storage.RemoteServer
	grant   *storage.UserServerGrant
}

func newUserManagedCreationFixture(t *testing.T, profiles ...string) userManagedCreationFixture {
	t.Helper()
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	agentState := &userManagedCreationAgent{}
	agentHTTP := httptest.NewServer(agentState)
	t.Cleanup(agentHTTP.Close)
	server := &storage.RemoteServer{
		Name: "user-create-edge", Token: "user-create-token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModePush, IPAddress: "127.0.0.1",
		ListenPort: remoteAgentTestPort(t, agentHTTP.URL), XrayMode: "embedded", Domain: "edge.example.test",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if _, err := repo.UpdateRemoteServerXrayStatus(ctx, server.ID, true, "test"); err != nil {
		t.Fatalf("UpdateRemoteServerXrayStatus: %v", err)
	}

	ws := NewRemoteWSHandler(repo, nil)
	ws.conns.Store(server.ID, &RemoteWSConnection{ServerID: server.ID, Capabilities: managedReadyAgentCapabilities()})
	remote := NewRemoteManageHandler(repo, ws)
	remote.httpClient = agentHTTP.Client()
	listener := event.NewNodeSyncListener(repo, remote.InboundToClashProxyByServerID)
	remote.publishInboundEvent = listener.Handle
	// The WebSocket entry above is a capability-handshake fixture, not a live
	// socket. Keep limiter delivery on authenticated HTTP so asynchronous normal
	// publishes cannot attempt to write through the nil test connection.
	limiter := NewLimiterConfigPusher(repo, nil)
	limiter.httpClient = agentHTTP.Client()
	remote.SetLimiterPusher(limiter)

	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	grant, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true,
		StartsAt: now.Add(-time.Minute), ExpiresAt: &expires, MaxActiveNodes: 2,
		SpeedLimitMbps: 25, ConnectionLimit: 3, BillingMode: storage.ManagedBillingDownload,
		ResetPolicy: storage.ManagedResetNone, ResetDay: 1, BillingTimezone: "Asia/Shanghai",
		AllowedProtocols: []string{"vless"}, AllowedProtocolProfiles: profiles, CreatedBy: "owner",
	})
	if err != nil {
		t.Fatalf("CreateUserServerGrant: %v", err)
	}
	return userManagedCreationFixture{
		repo: repo, handler: NewManagedNodesHandler(repo, remote, limiter), agent: agentState,
		server: server, grant: grant,
	}
}

func userManagedFrontendPayload(tag string) string {
	payload := map[string]interface{}{
		"action": "add", "node_name": "Alice VLESS WS", "ip_version": "v4",
		"client_options": map[string]interface{}{"skip_cert_verify": false},
		"inbound": map[string]interface{}{
			"tag": tag, "listen": "0.0.0.0", "port": 18080, "protocol": "vless",
			"settings": map[string]interface{}{
				"clients": []interface{}{map[string]interface{}{
					"id": "9f7e1882-8692-4494-bb58-9f1e0dfe5777", "email": "admin", "level": 0,
				}},
				"decryption": "none",
			},
			"sniffing": map[string]interface{}{
				"enabled": true, "destOverride": []interface{}{"http", "tls", "quic"}, "routeOnly": false,
			},
			"streamSettings": map[string]interface{}{
				"network": "ws", "security": "none", "wsSettings": map[string]interface{}{"path": "/alice"},
			},
		},
	}
	body, _ := json.Marshal(payload)
	return string(body)
}

func userManagedRealityRequest(protocol, tag, domain, network string) map[string]interface{} {
	var settings map[string]interface{}
	switch protocol {
	case "vless":
		settings = map[string]interface{}{
			"clients":    []interface{}{map[string]interface{}{"id": "9f7e1882-8692-4494-bb58-9f1e0dfe5777", "email": "admin", "flow": "xtls-rprx-vision"}},
			"decryption": "none",
		}
	case "vmess":
		settings = map[string]interface{}{
			"clients": []interface{}{map[string]interface{}{"id": "9f7e1882-8692-4494-bb58-9f1e0dfe5777", "email": "admin", "security": "auto"}},
		}
	case "trojan":
		settings = map[string]interface{}{
			"clients": []interface{}{map[string]interface{}{"password": "admin-password", "email": "admin"}},
		}
	case "shadowsocks":
		settings = map[string]interface{}{
			"clients": []interface{}{map[string]interface{}{"method": "aes-128-gcm", "password": "admin-password", "email": "admin"}},
			"network": "tcp,udp",
		}
	case "hysteria":
		settings = map[string]interface{}{
			"version": 2, "clients": []interface{}{map[string]interface{}{"auth": "admin-password", "email": "admin"}},
		}
	case "socks":
		settings = map[string]interface{}{
			"auth": "password", "accounts": []interface{}{map[string]interface{}{"user": "admin", "pass": "admin-password"}}, "udp": true,
		}
	case "http":
		settings = map[string]interface{}{
			"accounts": []interface{}{map[string]interface{}{"user": "admin", "pass": "admin-password"}}, "allowTransparent": false,
		}
	}
	return map[string]interface{}{
		"action": "add", "node_name": "Reality test", "ip_version": "v4",
		"inbound": map[string]interface{}{
			"tag": tag, "listen": "0.0.0.0", "port": 18443, "protocol": protocol, "settings": settings,
			"streamSettings": map[string]interface{}{
				"network": network, "security": "reality",
				"realitySettings": map[string]interface{}{
					"show": false, "target": domain + ":443", "xver": 0,
					"serverNames": []interface{}{domain}, "privateKey": strings.Repeat("A", 43), "shortIds": []interface{}{"12ab"},
				},
			},
		},
	}
}

func postUserManagedCreation(t *testing.T, fixture userManagedCreationFixture, body string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := managedUserHTTPRequest(http.MethodPost,
		"/api/user/managed-node-creation?server_id="+managedIDString(fixture.server.ID), "alice", body)
	fixture.handler.HandleUserManagedNodeCreation(response, request)
	return response
}

func managedIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}

func retainUserManagedTestCredential(t *testing.T, inbound map[string]interface{}, cfg *storage.UserInboundConfig) {
	t.Helper()
	var credential map[string]interface{}
	if cfg == nil || json.Unmarshal([]byte(cfg.CredentialJSON), &credential) != nil || credential == nil {
		t.Fatal("invalid user-managed test credential")
	}
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		t.Fatal("test inbound has no settings")
	}
	listKey, err := inboundClientListKey(canonicalManagedProtocol(cfg.Protocol), settings)
	if err != nil {
		t.Fatal(err)
	}
	clients, _ := settings[listKey].([]interface{})
	for _, raw := range clients {
		client, _ := raw.(map[string]interface{})
		if client != nil && sameInboundClientForAdd(client, credential, cfg.Protocol) {
			return
		}
	}
	settings[listKey] = append(clients, credential)
}

func TestUserManagedInboundShapeAcceptsFrontendPayloadAndRejectsEscapeHatches(t *testing.T) {
	var valid map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload("shape-test")), &valid); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := validateUserManagedInboundShape(valid); err != nil {
		t.Fatalf("frontend payload rejected: %v", err)
	}

	invalidBodies := []string{
		`{"action":"add","node_name":"bad","ip_version":"v4","inbound":{"tag":"bad-fallback","listen":"0.0.0.0","port":10001,"protocol":"vless","settings":{"clients":[{"id":"x","email":"admin"}],"decryption":"none","fallbacks":[]}}}`,
		`{"action":"add","node_name":"bad","ip_version":"v4","inbound":{"tag":"bad-sockopt","listen":"0.0.0.0","port":10002,"protocol":"vless","settings":{"clients":[{"id":"x","email":"admin"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"none","sockopt":{"mark":1}}}}`,
		`{"action":"add","node_name":"bad","ip_version":"v4","inbound":{"tag":"bad-cert","listen":"0.0.0.0","port":10003,"protocol":"vless","settings":{"clients":[{"id":"x","email":"admin"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificateFile":"/etc/passwd"}}}}`,
		`{"action":"add","node_name":"bad","ip_version":"v4","inbound":{"tag":"bad-wg","listen":"0.0.0.0","port":10004,"protocol":"wireguard","settings":{}}}`,
		`{"action":"add","node_name":"bad","ip_version":"v4","inbound":{"tag":"bad-shared","listen":"0.0.0.0","port":10005,"protocol":"shadowsocks","settings":{"method":"chacha20-poly1305","password":"shared","network":"tcp,udp"}}}`,
	}
	for _, body := range invalidBodies {
		var request map[string]interface{}
		if err := json.Unmarshal([]byte(body), &request); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := validateUserManagedInboundShape(request); err == nil {
			t.Fatalf("unsafe payload was accepted: %s", body)
		}
	}
}

func TestUserManagedInboundShapeRestrictsRealityToSupportedProfiles(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan"} {
		request := userManagedRealityRequest(protocol, "valid-"+protocol+"-reality", "front.example.test", "tcp")
		if _, _, _, _, err := validateUserManagedInboundShape(request); err != nil {
			t.Fatalf("valid %s Reality profile rejected: %v", protocol, err)
		}
	}

	invalid := []struct {
		name, protocol, network string
	}{
		{name: "http Reality", protocol: "http", network: "tcp"},
		{name: "SOCKS Reality", protocol: "socks", network: "tcp"},
		{name: "Shadowsocks Reality", protocol: "shadowsocks", network: "tcp"},
		{name: "Hysteria Reality", protocol: "hysteria", network: "hysteria"},
		{name: "VMess Reality", protocol: "vmess", network: "tcp"},
		{name: "VLESS WebSocket Reality", protocol: "vless", network: "ws"},
		{name: "Trojan WebSocket Reality", protocol: "trojan", network: "ws"},
	}
	for index, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			request := userManagedRealityRequest(test.protocol, "invalid-reality-"+strconv.Itoa(index), "front.example.test", test.network)
			if _, _, _, _, err := validateUserManagedInboundShape(request); err == nil {
				t.Fatal("unsupported Reality profile was accepted")
			}
		})
	}
}

func TestUserManagedRealityResolvedAddressesRejectPrivateAndLocalTargets(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.7", "169.254.169.254", "::1", "fe80::1"} {
		t.Run(raw, func(t *testing.T) {
			if err := validateUserManagedRealityResolvedAddresses("front.example.test", []net.IPAddr{{IP: net.ParseIP(raw)}}); err == nil {
				t.Fatalf("non-public address %s was accepted", raw)
			}
		})
	}
	if err := validateUserManagedRealityResolvedAddresses("front.example.test", []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}); err != nil {
		t.Fatalf("public address rejected: %v", err)
	}
}

func TestUserManagedRealityCreateRejectsPrivateTargetBeforeProbeOrReservation(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-reality")
	resolvedDomain := ""
	fixture.handler.realityResolver = func(_ context.Context, domain string) error {
		resolvedDomain = domain
		return fmt.Errorf("%w: resolves to loopback", storage.ErrManagedInvalidArgument)
	}
	request := userManagedRealityRequest("vless", "private-reality", "private.example.test", "tcp")
	body, _ := json.Marshal(request)
	response := postUserManagedCreation(t, fixture, string(body))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if resolvedDomain != "private.example.test" {
		t.Fatalf("resolver checked %q", resolvedDomain)
	}
	fixture.agent.mu.Lock()
	probes := append([]string(nil), fixture.agent.probeDomains...)
	fixture.agent.mu.Unlock()
	if len(probes) != 0 {
		t.Fatalf("private target reached Agent probe: %v", probes)
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", 0)
	if err != nil || len(creations) != 0 {
		t.Fatalf("private target leaked reservation: %+v err=%v", creations, err)
	}
}

func TestUserManagedRealityCreateRequiresSelectedServerProbe(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-reality")
	fixture.handler.realityResolver = func(context.Context, string) error { return nil }
	if err := fixture.repo.SetSystemSetting(context.Background(), "reality_domains", `["front.example.test"]`); err != nil {
		t.Fatalf("SetSystemSetting: %v", err)
	}
	request := userManagedRealityRequest("vless", "probed-reality", "front.example.test", "tcp")
	body, _ := json.Marshal(request)
	response := postUserManagedCreation(t, fixture, string(body))
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	fixture.agent.mu.Lock()
	probes := append([]string(nil), fixture.agent.probeDomains...)
	fixture.agent.mu.Unlock()
	if len(probes) != 1 || probes[0] != "front.example.test" {
		t.Fatalf("selected-server probes=%v", probes)
	}
}

func TestUserManagedRealityCreateRejectsTargetOutsideSelectedServerCandidates(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-reality")
	fixture.handler.realityResolver = func(context.Context, string) error { return nil }
	request := userManagedRealityRequest("vless", "unapproved-reality", "unapproved.example.test", "tcp")
	body, _ := json.Marshal(request)
	response := postUserManagedCreation(t, fixture, string(body))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	fixture.agent.mu.Lock()
	probes := append([]string(nil), fixture.agent.probeDomains...)
	fixture.agent.mu.Unlock()
	if len(probes) != 0 {
		t.Fatalf("unapproved target reached Agent probe: %v", probes)
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", 0)
	if err != nil || len(creations) != 0 {
		t.Fatalf("unapproved target leaked reservation: %+v err=%v", creations, err)
	}
}

func TestUserManagedRealityDomainsOnlyUsesAuthorizedSelectedServer(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-reality")
	fixture.handler.remoteManage.wsHandler = nil
	fixture.handler.realityResolver = func(context.Context, string) error { return nil }
	fixture.agent.mu.Lock()
	fixture.agent.inbounds = map[string]map[string]interface{}{
		"selected-tls": {
			"tag": "selected-tls", "protocol": "vless", "port": 443,
			"streamSettings": map[string]interface{}{
				"network": "tcp", "security": "tls",
				"tlsSettings": map[string]interface{}{"serverName": "selected-inbound.example.test"},
			},
		},
	}
	fixture.agent.mu.Unlock()

	unauthorizedAgent := &userManagedCreationAgent{}
	unauthorizedHTTP := httptest.NewServer(unauthorizedAgent)
	t.Cleanup(unauthorizedHTTP.Close)
	unauthorizedServer := &storage.RemoteServer{
		Name: "unauthorized-edge", Token: "unauthorized-token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModePush, IPAddress: "127.0.0.1",
		ListenPort: remoteAgentTestPort(t, unauthorizedHTTP.URL), XrayMode: "embedded", Domain: "secret-other-server.example.test",
	}
	if err := fixture.repo.CreateRemoteServer(context.Background(), unauthorizedServer); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}

	response := httptest.NewRecorder()
	request := managedUserHTTPRequest(http.MethodGet,
		"/api/user/managed-node-creation/reality-domains?server_id="+managedIDString(fixture.server.ID), "alice", "")
	fixture.handler.HandleUserManagedNodeCreationRealityDomains(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), unauthorizedServer.Domain) || strings.Contains(response.Body.String(), "domain_servers") {
		t.Fatalf("response disclosed another server: %s", response.Body.String())
	}
	var payload struct {
		ProbeServerID int64                             `json:"probe_server_id"`
		Domains       []realityDomainLatencyProbeResult `json:"domains"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ProbeServerID != fixture.server.ID || len(payload.Domains) != 2 {
		t.Fatalf("scoped payload=%+v body=%s", payload, response.Body.String())
	}
	gotDomains := []string{payload.Domains[0].Domain, payload.Domains[1].Domain}
	sort.Strings(gotDomains)
	wantDomains := []string{"edge.example.test", "selected-inbound.example.test"}
	if strings.Join(gotDomains, ",") != strings.Join(wantDomains, ",") {
		t.Fatalf("domains=%v want=%v", gotDomains, wantDomains)
	}
	unauthorizedAgent.mu.Lock()
	unauthorizedRequests := append([]string(nil), unauthorizedAgent.requests...)
	unauthorizedAgent.mu.Unlock()
	if len(unauthorizedRequests) != 0 {
		t.Fatalf("ungranted server was contacted: %v", unauthorizedRequests)
	}

	denied := httptest.NewRecorder()
	deniedRequest := managedUserHTTPRequest(http.MethodGet,
		"/api/user/managed-node-creation/reality-domains?server_id="+managedIDString(unauthorizedServer.ID), "alice", "")
	fixture.handler.HandleUserManagedNodeCreationRealityDomains(denied, deniedRequest)
	if denied.Code == http.StatusOK {
		t.Fatalf("ungranted server probe succeeded: %s", denied.Body.String())
	}
	unauthorizedAgent.mu.Lock()
	unauthorizedRequests = append([]string(nil), unauthorizedAgent.requests...)
	unauthorizedAgent.mu.Unlock()
	if len(unauthorizedRequests) != 0 {
		t.Fatalf("ungranted server was contacted after denial: %v", unauthorizedRequests)
	}
}

func TestUserManagedRejectsSharedShadowsocksCipherBeforeRemoteWrite(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	request := map[string]interface{}{
		"action": "add", "node_name": "shared shadowsocks", "ip_version": "v4",
		"client_options": map[string]interface{}{"skip_cert_verify": false},
		"inbound": map[string]interface{}{
			"tag": "alice-shared-ss", "listen": "0.0.0.0", "port": 18090, "protocol": "shadowsocks",
			"settings": map[string]interface{}{
				"method": "chacha20-ietf-poly1305", "password": "shared-master-password", "network": "tcp,udp",
				"clients": []interface{}{map[string]interface{}{
					"method": "chacha20-ietf-poly1305", "password": "user-password", "email": "alice",
				}},
			},
		},
	}
	body, _ := json.Marshal(request)
	response := postUserManagedCreation(t, fixture, string(body))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	events, _, _ := fixture.agent.snapshots()
	for _, eventName := range events {
		if eventName == "add" {
			t.Fatalf("shared Shadowsocks rejection happened after Agent write: %v", events)
		}
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", 0)
	if err != nil || len(creations) != 0 {
		t.Fatalf("shared Shadowsocks rejection leaked reservation: %+v err=%v", creations, err)
	}
}

func TestUserManagedAccountCredentialsUseCanonicalLimiterIdentity(t *testing.T) {
	user := storage.User{Username: "alice"}
	for _, protocol := range []string{"socks", "http"} {
		credential, _, err := generateCredential(protocol, user, "", "account-in")
		if err != nil {
			t.Fatalf("generateCredential(%s): %v", protocol, err)
		}
		if identity := wireGuardStringValue(credential["user"]); identity != "alice__account-in" {
			t.Fatalf("%s account identity=%q want canonical limiter key", protocol, identity)
		}
	}
}

func TestUserManagedWSSProfileUsesFinalClientShape(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-wss")
	var request map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload("wss-profile")), &request); err != nil {
		t.Fatal(err)
	}
	inbound := request["inbound"].(map[string]interface{})
	inbound["listen"] = "127.0.0.1"
	if err := fixture.handler.validateUserManagedNodeProfile(fixture.grant, inbound, fixture.server, "alice__wss-profile"); err != nil {
		t.Fatalf("WSS exact profile rejected before final client rewrite: %v", err)
	}
}

func TestUserManagedInboundAvailabilityRejectsMutationlessActiveDesiredButAllowsDeletedTombstone(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	const tag = "desired-authority"
	inbound := json.RawMessage(`{"tag":"desired-authority","listen":"0.0.0.0","port":18081,"protocol":"vless","settings":{"clients":[],"decryption":"none"}}`)
	if _, err := fixture.repo.UpsertActiveDesiredInbound(context.Background(), fixture.server.ID, tag, "", inbound); err != nil {
		t.Fatalf("UpsertActiveDesiredInbound: %v", err)
	}
	if err := fixture.handler.ensureUserManagedInboundAvailable(context.Background(), fixture.server, tag, 18081); !errors.Is(err, storage.ErrManagedAccessConflict) {
		t.Fatalf("mutationless active desired inbound was not rejected: %v", err)
	}
	if _, err := fixture.repo.MarkDesiredInboundDeleted(context.Background(), fixture.server.ID, tag, ""); err != nil {
		t.Fatalf("MarkDesiredInboundDeleted: %v", err)
	}
	if err := fixture.handler.ensureUserManagedInboundAvailable(context.Background(), fixture.server, tag, 18081); err != nil {
		t.Fatalf("deleted tombstone should be reusable by a new mutation: %v", err)
	}
}

func TestUserManagedInboundAvailabilityReservesStagedDesiredPortButSkipsWSSPublicPort(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	inbound := json.RawMessage(`{"tag":"staged-other","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[],"decryption":"none"}}`)
	if _, err := fixture.repo.UpsertActiveDesiredInbound(context.Background(), fixture.server.ID, "staged-other", "", inbound); err != nil {
		t.Fatalf("UpsertActiveDesiredInbound: %v", err)
	}
	if err := fixture.handler.ensureUserManagedInboundAvailable(context.Background(), fixture.server, "new-direct", 443); !errors.Is(err, storage.ErrManagedAccessConflict) {
		t.Fatalf("staged desired port was not reserved before Agent apply: %v", err)
	}
	if err := fixture.handler.ensureUserManagedInboundAvailable(context.Background(), fixture.server, "new-wss", 0); err != nil {
		t.Fatalf("WSS public port must not conflict with the private Xray port: %v", err)
	}
}

func TestUserManagedCreationContextExcludesExternalXrayServers(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	if err := fixture.repo.UpdateRemoteServerXrayMode(context.Background(), fixture.server.ID, "external"); err != nil {
		t.Fatalf("UpdateRemoteServerXrayMode: %v", err)
	}
	payload, err := fixture.handler.userManagedCreationContext(context.Background(), "alice")
	if err != nil {
		t.Fatalf("userManagedCreationContext: %v", err)
	}
	servers, ok := payload["servers"].([]userManagedCreationServer)
	if !ok {
		t.Fatalf("unexpected servers payload: %#v", payload["servers"])
	}
	if len(servers) != 0 {
		t.Fatalf("external Xray server was exposed for managed creation: %+v", servers)
	}
}

func TestUserManagedCreationAcceptsFrontendPayloadAndActivatesCanonicalPolicy(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-vless-ws"))
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].State != storage.UserManagedNodeActive || creations[0].NodeID == nil {
		t.Fatalf("unexpected creations=%+v err=%v", creations, err)
	}
	node, err := fixture.repo.GetNodeByID(context.Background(), *creations[0].NodeID)
	if err != nil || node.Username != "alice" || node.InboundMutationID != creations[0].MutationID {
		t.Fatalf("dedicated node ownership mismatch: node=%+v err=%v", node, err)
	}
	credential, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, "alice-vless-ws")
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	if !strings.Contains(credential.CredentialJSON, `"email":"alice__alice-vless-ws"`) {
		t.Fatalf("credential identity is not canonical: %s", credential.CredentialJSON)
	}
	events, snapshots, _ := fixture.agent.snapshots()
	addIndex := -1
	for index, eventName := range events {
		if eventName == "add" {
			addIndex = index
			break
		}
	}
	if addIndex <= 0 || events[0] != "limiter" {
		t.Fatalf("deny limiter was not applied before remote add: %v", events)
	}
	var sawDenied, sawActive bool
	for _, snapshot := range snapshots {
		for _, user := range snapshot.Users {
			if user.Email != "alice__alice-vless-ws" {
				continue
			}
			if user.Denied {
				sawDenied = true
			} else if user.DeviceLimit == 3 {
				sawActive = true
			}
		}
	}
	if !sawDenied || !sawActive {
		t.Fatalf("canonical limiter identity did not move deny->active: denied=%v active=%v snapshots=%+v", sawDenied, sawActive, snapshots)
	}

	createManagedSecurityTestUser(t, fixture.repo, "bob", storage.RoleUser)
	denied := httptest.NewRecorder()
	deniedRequest := managedUserHTTPRequest(http.MethodDelete,
		"/api/user/managed-node-creation/"+managedIDString(creations[0].ID), "bob", "")
	deniedRequest.SetPathValue("id", managedIDString(creations[0].ID))
	fixture.handler.HandleUserManagedNodeCreationItem(denied, deniedRequest)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("cross-user delete status=%d body=%s", denied.Code, denied.Body.String())
	}
	deleted := httptest.NewRecorder()
	deleteRequest := managedUserHTTPRequest(http.MethodDelete,
		"/api/user/managed-node-creation/"+managedIDString(creations[0].ID), "alice", "")
	deleteRequest.SetPathValue("id", managedIDString(creations[0].ID))
	fixture.handler.HandleUserManagedNodeCreationItem(deleted, deleteRequest)
	if deleted.Code != http.StatusOK {
		t.Fatalf("owner delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	if _, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creations[0].ID); !errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		t.Fatalf("owner delete left creation: %v", err)
	}
}

func TestUserManagedDeletePersistsIntentWhenServerLeaseIsUnavailable(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-delete-pending"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 {
		t.Fatalf("unexpected creations=%+v err=%v", creations, err)
	}
	const nonce = "user-delete-installation"
	if err := fixture.repo.BeginRemoteServerInstallation(context.Background(), fixture.server.ID, nonce, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("BeginRemoteServerInstallation: %v", err)
	}
	deleted := httptest.NewRecorder()
	deleteRequest := managedUserHTTPRequest(http.MethodDelete,
		"/api/user/managed-node-creation/"+managedIDString(creations[0].ID), "alice", "")
	deleteRequest.SetPathValue("id", managedIDString(creations[0].ID))
	fixture.handler.HandleUserManagedNodeCreationItem(deleted, deleteRequest)
	if deleted.Code != http.StatusAccepted {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	pending, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creations[0].ID)
	if err != nil || pending.State != storage.UserManagedNodeDeleting {
		t.Fatalf("delete intent was not durable: %+v err=%v", pending, err)
	}
	if err := fixture.repo.AbortRemoteServerInstallation(context.Background(), fixture.server.ID, nonce); err != nil {
		t.Fatalf("AbortRemoteServerInstallation: %v", err)
	}
	fixture.handler.reconcileUserManagedNodeCreations(context.Background(), time.Now().UTC())
	if _, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creations[0].ID); !errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		t.Fatalf("reconciler did not finish pending delete: %v", err)
	}
}

func TestUserManagedCreationAmbiguousResultAndFailedCleanupRetainDeny(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	fixture.agent.mu.Lock()
	fixture.agent.addResponseMode = "malformed"
	fixture.agent.failRemove = true
	fixture.agent.mu.Unlock()
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-uncertain"))
	if response.Code < http.StatusBadRequest {
		t.Fatalf("ambiguous result unexpectedly succeeded: %d %s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].State != storage.UserManagedNodeDeleting {
		t.Fatalf("ambiguous creation not retained as deleting: %+v err=%v", creations, err)
	}
	credential, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, "alice-uncertain")
	if err != nil {
		t.Fatalf("deny credential was removed after uncertain result: %v", err)
	}
	sources, err := fixture.repo.ListUserInboundAccessSources(context.Background(), "alice", fixture.server.ID)
	if err != nil {
		t.Fatal(err)
	}
	foundDeny := false
	for _, source := range sources {
		if source.SourceType == storage.ManagedSourceLegacyReview && source.SourceID == credential.ID &&
			source.DesiredState == storage.ManagedDesiredInactive {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Fatalf("deny tombstone missing after uncertain result: %+v", sources)
	}
	fixture.handler.reconcileUserManagedNodeCreations(context.Background(), time.Now().UTC().Add(5*time.Minute))
	if _, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creations[0].ID); err != nil {
		t.Fatalf("failed remote cleanup erased durable reservation: %v", err)
	}
	if _, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, "alice-uncertain"); err != nil {
		t.Fatalf("failed remote cleanup erased deny credential: %v", err)
	}
	_, _, inboundPresent := fixture.agent.snapshots()
	if !inboundPresent {
		t.Fatal("test precondition lost: uncertain remote inbound should remain present")
	}
}

func TestUserManagedActivationFailureReinstallsDenyBeforeCleanup(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	fixture.agent.mu.Lock()
	fixture.agent.failLimiterCall = 2 // deny-first succeeds; normal activation fails
	fixture.agent.failRemoveClient = true
	fixture.agent.mu.Unlock()
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-policy-fail"))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].State != storage.UserManagedNodeDeleting {
		t.Fatalf("failed activation did not retain deleting ownership: %+v err=%v", creations, err)
	}
	_, snapshots, inboundPresent := fixture.agent.snapshots()
	if !inboundPresent {
		t.Fatal("test precondition lost: failed cleanup must leave the remote inbound")
	}
	deniedPublishes := 0
	for _, snapshot := range snapshots {
		for _, user := range snapshot.Users {
			if user.Email == "alice__alice-policy-fail" && user.Denied {
				deniedPublishes++
			}
		}
	}
	if deniedPublishes < 2 {
		t.Fatalf("cleanup did not reinstall deny after normal policy failure: snapshots=%+v", snapshots)
	}
}

func TestUserManagedGrantRevocationCleansDedicatedInbound(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-revoke"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	grant, err := fixture.repo.GetUserServerGrant(context.Background(), fixture.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	grant.Enabled = false
	if _, err := fixture.repo.UpdateUserServerGrant(context.Background(), *grant, grant.Version, "owner"); err != nil {
		t.Fatalf("disable grant: %v", err)
	}
	fixture.handler.reconcileUserManagedNodeCreations(context.Background(), time.Now().UTC())
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 0 {
		t.Fatalf("revoked creation still exists: %+v err=%v", creations, err)
	}
	_, _, inboundPresent := fixture.agent.snapshots()
	if inboundPresent {
		t.Fatal("revoked dedicated inbound still exists on Agent")
	}
}

func TestPackageUnbindKeepsCommittedStateAfterMixedUserManagedCleanup(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	ctx := context.Background()
	if err := fixture.repo.DeleteUserServerGrant(ctx, fixture.grant.ID, fixture.grant.Version, "owner"); err != nil {
		t.Fatalf("delete manual fixture grant: %v", err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "user-managed-package", TrafficLimitBytes: 1 << 30, CycleDays: 30,
		ServerGrants: []storage.PackageServerGrant{{
			ServerID: fixture.server.ID, MaxActiveNodes: 2, SpeedLimitMbps: 25, ConnectionLimit: 3,
			BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone, ResetDay: 1,
			AllowedProtocols: []string{"vless"}, AllowedProtocolProfiles: []string{"vless-ws"},
		}},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	start, end := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour)
	assigner := NewPackageAssignHandler(fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter)
	if warnings, err := assigner.AssignAndProvision(ctx, "alice", packageID, start, end, false, 1); err != nil || len(warnings) != 0 {
		t.Fatalf("AssignPackageBundleToUser warnings=%v err=%v", warnings, err)
	}
	grants, err := fixture.repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(grants) != 1 {
		t.Fatalf("package server grants=%+v err=%v", grants, err)
	}
	fixture.grant = &grants[0]
	if response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-package-one")); response.Code != http.StatusCreated {
		t.Fatalf("first create status=%d body=%s", response.Code, response.Body.String())
	}
	var secondRequest map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload("alice-package-two")), &secondRequest); err != nil {
		t.Fatal(err)
	}
	secondRequest["inbound"].(map[string]interface{})["port"] = 18081
	secondBody, _ := json.Marshal(secondRequest)
	if response := postUserManagedCreation(t, fixture, string(secondBody)); response.Code != http.StatusCreated {
		t.Fatalf("second create status=%d body=%s", response.Code, response.Body.String())
	}
	fixture.agent.mu.Lock()
	fixture.agent.failRemoveTag = "alice-package-two"
	fixture.agent.mu.Unlock()

	if err := unbindUserPackage(ctx, fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter, "alice"); err != nil {
		t.Fatalf("committed package unbind returned rollback error: %v", err)
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModeCustom || user.PackageID != 0 {
		t.Fatalf("package assignment was restored after destructive cleanup: user=%+v err=%v", user, err)
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(ctx, "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].InboundTag != "alice-package-two" ||
		creations[0].State != storage.UserManagedNodeDeleting {
		t.Fatalf("mixed cleanup did not retain only failed creation: %+v err=%v", creations, err)
	}
	fixture.agent.mu.Lock()
	_, firstPresent := fixture.agent.inbounds["alice-package-one"]
	_, secondPresent := fixture.agent.inbounds["alice-package-two"]
	fixture.agent.mu.Unlock()
	if firstPresent || !secondPresent {
		t.Fatalf("mixed cleanup runtime state first=%v second=%v", firstPresent, secondPresent)
	}
}

func TestPackageUnbindRequiresUserManagedDenyACKBeforeCommit(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	ctx := context.Background()
	if err := fixture.repo.DeleteUserServerGrant(ctx, fixture.grant.ID, fixture.grant.Version, "owner"); err != nil {
		t.Fatalf("delete manual fixture grant: %v", err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "user-managed-deny-package", TrafficLimitBytes: 1 << 30, CycleDays: 30,
		ServerGrants: []storage.PackageServerGrant{{
			ServerID: fixture.server.ID, MaxActiveNodes: 2, SpeedLimitMbps: 25, ConnectionLimit: 3,
			BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone, ResetDay: 1,
			AllowedProtocols: []string{"vless"}, AllowedProtocolProfiles: []string{"vless-ws"},
		}},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	start, end := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour)
	assigner := NewPackageAssignHandler(fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter)
	if warnings, err := assigner.AssignAndProvision(ctx, "alice", packageID, start, end, false, 1); err != nil || len(warnings) != 0 {
		t.Fatalf("AssignPackageBundleToUser warnings=%v err=%v", warnings, err)
	}
	grants, err := fixture.repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(grants) != 1 {
		t.Fatalf("package server grants=%+v err=%v", grants, err)
	}
	fixture.grant = &grants[0]
	if response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-package-deny")); response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(ctx, "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].SelectionID == nil {
		t.Fatalf("unexpected package creation: %+v err=%v", creations, err)
	}
	creation := creations[0]
	fixture.agent.mu.Lock()
	fixture.agent.failDenyEmail = "alice__alice-package-deny"
	fixture.agent.mu.Unlock()

	if err := unbindUserPackage(ctx, fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter, "alice"); err == nil {
		t.Fatal("package unbind committed without a checked user-managed deny")
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != packageID {
		t.Fatalf("package assignment changed after deny failure: user=%+v err=%v", user, err)
	}
	pending, err := fixture.repo.GetUserManagedNodeCreation(ctx, creation.ID)
	if err != nil || pending.State != storage.UserManagedNodeActive {
		t.Fatalf("deny failure did not preserve the active creation after rollback: %+v err=%v", pending, err)
	}
	selection, err := fixture.repo.GetUserNodeSelection(ctx, *creation.SelectionID)
	if err != nil || !selection.DesiredEnabled {
		t.Fatalf("deny failure did not restore selection access: %+v err=%v", selection, err)
	}
	if _, err := fixture.repo.GetUserInboundConfig(ctx, "alice", fixture.server.ID, creation.InboundTag); err != nil {
		t.Fatalf("deny failure deleted local credential: %v", err)
	}
	fixture.agent.mu.Lock()
	_, runtimePresent := fixture.agent.inbounds[creation.InboundTag]
	acked := append([]WSLimiterConfigPayload(nil), fixture.agent.ackedLimiters...)
	fixture.agent.failDenyEmail = ""
	fixture.agent.mu.Unlock()
	if !runtimePresent {
		t.Fatal("deny failure removed the live credential before package commit")
	}
	latestAcknowledgedDenied := false
	foundAcknowledgedIdentity := false
	for i := len(acked) - 1; i >= 0 && !foundAcknowledgedIdentity; i-- {
		for _, limiterUser := range acked[i].Users {
			if limiterUser.Email == "alice__alice-package-deny" {
				foundAcknowledgedIdentity = true
				latestAcknowledgedDenied = limiterUser.Denied
				break
			}
		}
	}
	if !foundAcknowledgedIdentity || latestAcknowledgedDenied {
		t.Fatalf("test did not preserve the prior acknowledged allow snapshot: %+v", acked)
	}

	if err := unbindUserPackage(ctx, fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter, "alice"); err != nil {
		t.Fatalf("package unbind retry failed: %v", err)
	}
	user, err = fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModeCustom || user.PackageID != 0 {
		t.Fatalf("package retry did not commit: user=%+v err=%v", user, err)
	}
	if _, err := fixture.repo.GetUserManagedNodeCreation(ctx, creation.ID); !errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		t.Fatalf("package retry did not clean creation: %v", err)
	}
	fixture.agent.mu.Lock()
	_, runtimePresent = fixture.agent.inbounds[creation.InboundTag]
	fixture.agent.mu.Unlock()
	if runtimePresent {
		t.Fatal("package retry left dedicated inbound on Agent")
	}
}

func TestPackageUnbindSharedCredentialFailurePrecedesDedicatedDeny(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	ctx := context.Background()
	var sharedRequest map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload("package-shared")), &sharedRequest); err != nil {
		t.Fatal(err)
	}
	sharedRequest["node_name"] = "Package shared node"
	sharedRequest["inbound"].(map[string]interface{})["port"] = 18081
	sharedBody, _ := json.Marshal(sharedRequest)
	sharedResponse := httptest.NewRecorder()
	fixture.handler.remoteManage.HandleInbounds(sharedResponse, managedUserHTTPRequest(http.MethodPost,
		"/api/admin/remote/inbounds?server_id="+managedIDString(fixture.server.ID), "owner", string(sharedBody)))
	if sharedResponse.Code >= http.StatusBadRequest {
		t.Fatalf("create shared inbound status=%d body=%s", sharedResponse.Code, sharedResponse.Body.String())
	}
	var sharedNodeID int64
	nodes, err := fixture.repo.ListNodes(ctx, fixture.repo.GetSystemNodeOwner(ctx))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if node.OriginalServer == fixture.server.Name && node.InboundTag == "package-shared" {
			sharedNodeID = node.ID
			break
		}
	}
	if sharedNodeID == 0 {
		t.Fatalf("shared node was not synchronized: %+v", nodes)
	}
	if err := fixture.repo.DeleteUserServerGrant(ctx, fixture.grant.ID, fixture.grant.Version, "owner"); err != nil {
		t.Fatalf("delete manual fixture grant: %v", err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "mixed-shared-user-managed", TrafficLimitBytes: 1 << 30, CycleDays: 30,
		Nodes: []int64{sharedNodeID},
		ServerGrants: []storage.PackageServerGrant{{
			ServerID: fixture.server.ID, MaxActiveNodes: 2, SpeedLimitMbps: 25, ConnectionLimit: 3,
			BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone, ResetDay: 1,
			AllowedProtocols: []string{"vless"}, AllowedProtocolProfiles: []string{"vless-ws"},
		}},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	start, end := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour)
	assigner := NewPackageAssignHandler(fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter)
	if warnings, err := assigner.AssignAndProvision(ctx, "alice", packageID, start, end, false, 1); err != nil || len(warnings) != 0 {
		t.Fatalf("AssignPackageBundleToUser warnings=%v err=%v", warnings, err)
	}
	grants, err := fixture.repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(grants) != 1 {
		t.Fatalf("package server grants=%+v err=%v", grants, err)
	}
	fixture.grant = &grants[0]
	sharedCredential, err := fixture.repo.GetUserInboundConfig(ctx, "alice", fixture.server.ID, "package-shared")
	if err != nil {
		t.Fatalf("GetUserInboundConfig(shared): %v", err)
	}
	fixture.agent.mu.Lock()
	sharedRuntime := cloneUserManagedTestMap(fixture.agent.inbounds["package-shared"])
	fixture.agent.mu.Unlock()
	retainUserManagedTestCredential(t, sharedRuntime, sharedCredential)
	fixture.agent.mu.Lock()
	fixture.agent.inbounds["package-shared"] = sharedRuntime
	fixture.agent.mu.Unlock()
	if response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-package-mixed")); response.Code != http.StatusCreated {
		t.Fatalf("create dedicated status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(ctx, "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].SelectionID == nil {
		t.Fatalf("unexpected dedicated creation: %+v err=%v", creations, err)
	}
	creation := creations[0]
	fixture.agent.mu.Lock()
	fixture.agent.failRemoveClient = true
	fixture.agent.mu.Unlock()

	if err := unbindUserPackage(ctx, fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter, "alice"); err == nil {
		t.Fatal("package unbind committed after shared credential removal failure")
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != packageID {
		t.Fatalf("package assignment changed after shared credential failure: user=%+v err=%v", user, err)
	}
	currentCreation, err := fixture.repo.GetUserManagedNodeCreation(ctx, creation.ID)
	if err != nil || currentCreation.State != storage.UserManagedNodeActive {
		t.Fatalf("shared cleanup failure changed dedicated creation: %+v err=%v", currentCreation, err)
	}
	selection, err := fixture.repo.GetUserNodeSelection(ctx, *creation.SelectionID)
	if err != nil || !selection.DesiredEnabled {
		t.Fatalf("shared cleanup failure disabled dedicated selection: %+v err=%v", selection, err)
	}
	fixture.agent.mu.Lock()
	sharedRuntime = cloneUserManagedTestMap(fixture.agent.inbounds["package-shared"])
	fixture.agent.mu.Unlock()
	if retained, err := userManagedInboundContainsCredential(sharedRuntime, sharedCredential); err != nil || !retained {
		t.Fatalf("failed shared removal did not preserve old credential: retained=%v err=%v", retained, err)
	}
}

func TestPackageUnbindCrashStageCreationDefersCredentialToSupersededCleanup(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	ctx := context.Background()
	if err := fixture.repo.DeleteUserServerGrant(ctx, fixture.grant.ID, fixture.grant.Version, "owner"); err != nil {
		t.Fatalf("delete manual fixture grant: %v", err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "crash-stage-package", TrafficLimitBytes: 1 << 30, CycleDays: 30,
		ServerGrants: []storage.PackageServerGrant{{
			ServerID: fixture.server.ID, MaxActiveNodes: 2, SpeedLimitMbps: 25, ConnectionLimit: 3,
			BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone, ResetDay: 1,
			AllowedProtocols: []string{"vless"}, AllowedProtocolProfiles: []string{"vless-ws"},
		}},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	start, end := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour)
	assigner := NewPackageAssignHandler(fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter)
	if warnings, err := assigner.AssignAndProvision(ctx, "alice", packageID, start, end, false, 1); err != nil || len(warnings) != 0 {
		t.Fatalf("AssignAndProvision warnings=%v err=%v", warnings, err)
	}
	grants, err := fixture.repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(grants) != 1 {
		t.Fatalf("package server grants=%+v err=%v", grants, err)
	}
	fixture.grant = &grants[0]

	const tag = "alice-crash-before-promotion"
	const oldMutation = "user-managed-crash-before-promotion"
	creation, err := fixture.repo.ReserveUserManagedNodeCreation(ctx, "alice", fixture.grant.ID,
		fixture.server.ID, tag, oldMutation, time.Now().UTC())
	if err != nil {
		t.Fatalf("ReserveUserManagedNodeCreation: %v", err)
	}
	var createRequest map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload(tag)), &createRequest); err != nil {
		t.Fatal(err)
	}
	_, settings, _, protocol, err := validateUserManagedInboundShape(createRequest)
	if err != nil {
		t.Fatal(err)
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	credential, _, _, err := getOrCreateInboundCredential(ctx, fixture.repo, user,
		fixture.server.ID, tag, protocol, settings)
	if err != nil {
		t.Fatalf("getOrCreateInboundCredential: %v", err)
	}
	copyManagedCredentialOptions(protocol, settings, credential)
	if err := replaceInboundCredential(settings, protocol, credential); err != nil {
		t.Fatal(err)
	}
	cfg, err := fixture.repo.GetUserInboundConfig(ctx, "alice", fixture.server.ID, tag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	cleanupSource, err := fixture.repo.PreparePackageInboundCredentialCleanup(ctx, *cfg, "user-managed-create")
	if err != nil || cleanupSource == nil {
		t.Fatalf("PreparePackageInboundCredentialCleanup: %+v err=%v", cleanupSource, err)
	}
	if err := fixture.handler.limiter.PushToServerChecked(ctx, fixture.server.ID); err != nil {
		t.Fatalf("install crash-stage deny: %v", err)
	}
	applyManagedRealityCompatibility(createRequest)
	createBody, _ := json.Marshal(createRequest)
	remoteCreate := managedUserHTTPRequest(http.MethodPost,
		"/api/user/managed-node-creation?server_id="+managedIDString(fixture.server.ID), "alice", string(createBody))
	remoteContext := withManagedNodeMutationID(remoteCreate.Context(), oldMutation)
	remoteContext = withManagedNodeOwner(remoteContext, "alice")
	remoteCreate = remoteCreate.WithContext(remoteContext)
	remoteResponse := httptest.NewRecorder()
	fixture.handler.remoteManage.HandleCreateManagedNode(remoteResponse, remoteCreate)
	if remoteResponse.Code >= http.StatusBadRequest {
		t.Fatalf("remote create status=%d body=%s", remoteResponse.Code, remoteResponse.Body.String())
	}
	var created struct {
		Success bool  `json:"success"`
		NodeID  int64 `json:"node_id"`
	}
	if err := json.Unmarshal(remoteResponse.Body.Bytes(), &created); err != nil || !created.Success || created.NodeID <= 0 {
		t.Fatalf("decode remote create response: %+v err=%v body=%s", created, err, remoteResponse.Body.String())
	}
	crashStage, err := fixture.repo.GetUserManagedNodeCreation(ctx, creation.ID)
	if err != nil || crashStage.State != storage.UserManagedNodeCreating || crashStage.SelectionID != nil ||
		crashStage.OfferID != nil || crashStage.NodeID != nil {
		t.Fatalf("creation did not remain at crash stage: %+v err=%v", crashStage, err)
	}

	const replacementMutation = "admin-replacement-after-crash"
	var adminReplacement map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload(tag)), &adminReplacement); err != nil {
		t.Fatal(err)
	}
	adminReplacement["mutation_id"] = replacementMutation
	adminBody, _ := json.Marshal(adminReplacement)
	adminResponse := httptest.NewRecorder()
	adminRequest := managedUserHTTPRequest(http.MethodPost,
		"/api/admin/remote/inbounds?server_id="+managedIDString(fixture.server.ID), "owner", string(adminBody))
	fixture.handler.remoteManage.HandleInbounds(adminResponse, adminRequest)
	if adminResponse.Code >= http.StatusBadRequest {
		t.Fatalf("admin replacement status=%d body=%s", adminResponse.Code, adminResponse.Body.String())
	}
	var replacementNode *storage.Node
	nodes, err := fixture.repo.ListAllNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range nodes {
		if nodes[i].OriginalServer == fixture.server.Name && nodes[i].InboundTag == tag &&
			nodes[i].InboundMutationID == replacementMutation && nodes[i].Username == fixture.repo.GetSystemNodeOwner(ctx) {
			replacementNode = &nodes[i]
			break
		}
	}
	if replacementNode == nil {
		t.Fatalf("admin replacement node missing: %+v", nodes)
	}
	desired, err := fixture.repo.GetDesiredInbound(ctx, fixture.server.ID, tag)
	if err != nil || desired == nil {
		t.Fatalf("GetDesiredInbound(replacement): %+v err=%v", desired, err)
	}
	desiredInbound, err := decodeDesiredInbound(desired.InboundJSON)
	if err != nil {
		t.Fatal(err)
	}
	retainUserManagedTestCredential(t, desiredInbound, cfg)
	desiredJSON, _ := json.Marshal(desiredInbound)
	if _, err := fixture.repo.UpsertActiveDesiredInbound(ctx, fixture.server.ID, tag,
		replacementMutation, desiredJSON); err != nil {
		t.Fatalf("retain crash-stage credential in desired: %v", err)
	}
	fixture.agent.mu.Lock()
	replacementRuntime := cloneUserManagedTestMap(fixture.agent.inbounds[tag])
	retainUserManagedTestCredential(t, replacementRuntime, cfg)
	fixture.agent.inbounds[tag] = replacementRuntime
	fixture.agent.mu.Unlock()

	if err := unbindUserPackage(ctx, fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter, "alice"); err != nil {
		t.Fatalf("unbindUserPackage: %v", err)
	}
	fixture.handler.reconcileUserManagedNodeCreations(ctx, time.Now().UTC())
	if _, err := fixture.repo.GetUserManagedNodeCreation(ctx, creation.ID); !errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		t.Fatalf("crash-stage creation did not converge: %v", err)
	}
	if _, err := fixture.repo.GetUserInboundConfig(ctx, "alice", fixture.server.ID, tag); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("crash-stage credential config remains: %v", err)
	}
	if _, err := fixture.repo.GetNodeByID(ctx, created.NodeID); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("old user-owned node remains: %v", err)
	}
	currentReplacement, err := fixture.repo.GetNodeByID(ctx, replacementNode.ID)
	if err != nil || currentReplacement.InboundMutationID != replacementMutation {
		t.Fatalf("replacement node changed: %+v err=%v", currentReplacement, err)
	}
	currentDesired, err := fixture.repo.GetDesiredInbound(ctx, fixture.server.ID, tag)
	if err != nil || currentDesired == nil || currentDesired.MutationID != replacementMutation ||
		currentDesired.DesiredState != storage.DesiredInboundStateActive {
		t.Fatalf("replacement desired changed: %+v err=%v", currentDesired, err)
	}
	currentDesiredInbound, err := decodeDesiredInbound(currentDesired.InboundJSON)
	if err != nil {
		t.Fatal(err)
	}
	if retained, err := userManagedInboundContainsCredential(currentDesiredInbound, cfg); err != nil || retained {
		t.Fatalf("old crash-stage credential remains in desired: retained=%v err=%v", retained, err)
	}
	adminCredential := &storage.UserInboundConfig{
		Protocol: "vless", CredentialJSON: `{"id":"9f7e1882-8692-4494-bb58-9f1e0dfe5777","email":"admin"}`,
	}
	if retained, err := userManagedInboundContainsCredential(currentDesiredInbound, adminCredential); err != nil || !retained {
		t.Fatalf("admin credential missing from desired: retained=%v err=%v", retained, err)
	}
	fixture.agent.mu.Lock()
	currentRuntime := cloneUserManagedTestMap(fixture.agent.inbounds[tag])
	fixture.agent.mu.Unlock()
	if retained, err := userManagedInboundContainsCredential(currentRuntime, cfg); err != nil || retained {
		t.Fatalf("old crash-stage credential remains at Agent: retained=%v err=%v", retained, err)
	}
	if retained, err := userManagedInboundContainsCredential(currentRuntime, adminCredential); err != nil || !retained {
		t.Fatalf("admin credential missing at Agent: retained=%v err=%v", retained, err)
	}
	events, _, inboundPresent := fixture.agent.snapshots()
	if !inboundPresent {
		t.Fatal("replacement runtime was removed")
	}
	for _, eventName := range events {
		if eventName == "remove" {
			t.Fatalf("crash-stage cleanup removed replacement inbound: %v", events)
		}
	}
}

func TestCustomRequestCanCancelPendingPackageTransitionAfterCleanup(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	ctx := context.Background()
	if response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-transition-cancel")); response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(ctx, "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 {
		t.Fatalf("unexpected managed creation: %+v err=%v", creations, err)
	}
	targetPackageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "transition-target", TrafficLimitBytes: 1 << 30, CycleDays: 30,
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	packages := NewPackageAssignHandler(fixture.repo, fixture.handler.remoteManage, fixture.handler.limiter)
	service := NewServiceAuthorizationHandler(fixture.repo, packages, fixture.handler, packages.forwarding)
	callBatch := func(body map[string]interface{}) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(body)
		response := httptest.NewRecorder()
		service.HandleBatch(response, managedUserHTTPRequest(http.MethodPost,
			"/api/admin/users/service-authorization/batch", "owner", string(payload)))
		return response
	}
	fixture.agent.mu.Lock()
	fixture.agent.failRemove = true
	fixture.agent.mu.Unlock()
	packageResponse := callBatch(map[string]interface{}{
		"usernames": []string{"alice"}, "mode": storage.AuthorizationModePackage,
		"package": map[string]interface{}{"package_id": targetPackageID},
	})
	if packageResponse.Code != http.StatusMultiStatus {
		t.Fatalf("package transition status=%d body=%s", packageResponse.Code, packageResponse.Body.String())
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != 0 {
		t.Fatalf("failed package transition did not remain fail-closed: user=%+v err=%v", user, err)
	}
	customRequest := map[string]interface{}{
		"usernames": []string{"alice"}, "mode": storage.AuthorizationModeCustom,
		"custom": map[string]interface{}{
			"fixed_node_grants": []interface{}{}, "server_grants": []interface{}{}, "forwarding_grants": []interface{}{},
		},
	}
	pendingResponse := callBatch(customRequest)
	if pendingResponse.Code != http.StatusMultiStatus {
		t.Fatalf("pending custom cancel status=%d body=%s", pendingResponse.Code, pendingResponse.Body.String())
	}
	user, err = fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != 0 {
		t.Fatalf("pending custom cancel left fail-closed mode: user=%+v err=%v", user, err)
	}
	fixture.agent.mu.Lock()
	fixture.agent.failRemove = false
	fixture.agent.mu.Unlock()
	completedResponse := callBatch(customRequest)
	if completedResponse.Code != http.StatusOK {
		t.Fatalf("completed custom cancel status=%d body=%s", completedResponse.Code, completedResponse.Body.String())
	}
	user, err = fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModeCustom || user.PackageID != 0 {
		t.Fatalf("completed custom cancel did not restore custom mode: user=%+v err=%v", user, err)
	}
	if _, err := fixture.repo.GetUserManagedNodeCreation(ctx, creations[0].ID); !errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		t.Fatalf("completed custom cancel left managed creation: %v", err)
	}
}

func TestUserManagedSupersededGenerationCleanupPreservesAdminReplacement(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-superseded"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].NodeID == nil || creations[0].OfferID == nil || creations[0].SelectionID == nil {
		t.Fatalf("unexpected creation: %+v err=%v", creations, err)
	}
	creation := creations[0]
	oldCredential, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, creation.InboundTag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig(old): %v", err)
	}
	oldNode, err := fixture.repo.GetNodeByID(context.Background(), *creation.NodeID)
	if err != nil {
		t.Fatalf("GetNodeByID(old): %v", err)
	}
	desired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || desired == nil {
		t.Fatalf("GetDesiredInbound(old): %+v err=%v", desired, err)
	}
	const replacementMutation = "admin-replacement-generation"
	var adminReplacement map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload(creation.InboundTag)), &adminReplacement); err != nil {
		t.Fatal(err)
	}
	adminReplacement["mutation_id"] = replacementMutation
	adminBody, _ := json.Marshal(adminReplacement)
	adminResponse := httptest.NewRecorder()
	adminRequest := managedUserHTTPRequest(http.MethodPost,
		"/api/admin/remote/inbounds?server_id="+managedIDString(fixture.server.ID), "owner", string(adminBody))
	fixture.handler.remoteManage.HandleInbounds(adminResponse, adminRequest)
	if adminResponse.Code >= http.StatusBadRequest {
		t.Fatalf("admin replacement status=%d body=%s", adminResponse.Code, adminResponse.Body.String())
	}
	var replacementNode *storage.Node
	nodes, err := fixture.repo.ListAllNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := range nodes {
		if nodes[i].OriginalServer == fixture.server.Name && nodes[i].InboundTag == creation.InboundTag &&
			nodes[i].InboundMutationID == replacementMutation && nodes[i].Username == fixture.repo.GetSystemNodeOwner(context.Background()) {
			replacementNode = &nodes[i]
			break
		}
	}
	if replacementNode == nil {
		t.Fatalf("admin replacement did not create a system-owned node: %+v", nodes)
	}
	replacementDesired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || replacementDesired == nil {
		t.Fatalf("GetDesiredInbound(replacement): %+v err=%v", replacementDesired, err)
	}
	replacementDesiredInbound, err := decodeDesiredInbound(replacementDesired.InboundJSON)
	if err != nil {
		t.Fatalf("decode replacement desired inbound: %v", err)
	}
	retainUserManagedTestCredential(t, replacementDesiredInbound, oldCredential)
	replacementDesiredJSON, _ := json.Marshal(replacementDesiredInbound)
	if _, err := fixture.repo.UpsertActiveDesiredInbound(context.Background(), fixture.server.ID,
		creation.InboundTag, replacementMutation, replacementDesiredJSON); err != nil {
		t.Fatalf("retain old credential in replacement desired: %v", err)
	}
	fixture.agent.mu.Lock()
	replacementRuntime := cloneUserManagedTestMap(fixture.agent.inbounds[creation.InboundTag])
	fixture.agent.mu.Unlock()
	retainUserManagedTestCredential(t, replacementRuntime, oldCredential)
	fixture.agent.mu.Lock()
	fixture.agent.inbounds[creation.InboundTag] = replacementRuntime
	fixture.agent.mu.Unlock()
	if retained, err := userManagedInboundContainsCredential(replacementDesiredInbound, oldCredential); err != nil || !retained {
		t.Fatalf("admin replacement desired did not retain the old credential before cleanup: retained=%v err=%v", retained, err)
	}
	fixture.agent.mu.Lock()
	replacementRuntimeBefore := cloneUserManagedTestMap(fixture.agent.inbounds[creation.InboundTag])
	fixture.agent.mu.Unlock()
	if retained, err := userManagedInboundContainsCredential(replacementRuntimeBefore, oldCredential); err != nil || !retained {
		t.Fatalf("admin replacement runtime did not retain the old credential before cleanup: retained=%v err=%v", retained, err)
	}
	fixture.handler.reconcileUserManagedNodeCreations(context.Background(), time.Now().UTC())
	if _, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creation.ID); !errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		t.Fatalf("old creation remains: %v", err)
	}
	if _, err := fixture.repo.GetSelfServiceNodeOffer(context.Background(), *creation.OfferID); !errors.Is(err, storage.ErrSelfServiceNodeOfferNotFound) {
		t.Fatalf("old private offer remains: %v", err)
	}
	if _, err := fixture.repo.GetUserNodeSelection(context.Background(), *creation.SelectionID); !errors.Is(err, storage.ErrUserNodeSelectionNotFound) {
		t.Fatalf("old selection remains: %v", err)
	}
	if _, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, creation.InboundTag); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old credential remains: %v", err)
	}
	if _, err := fixture.repo.GetNodeByID(context.Background(), oldNode.ID); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("old mutation node remains: %v", err)
	}
	currentReplacement, err := fixture.repo.GetNodeByID(context.Background(), replacementNode.ID)
	if err != nil || currentReplacement.InboundMutationID != replacementMutation ||
		currentReplacement.Username != fixture.repo.GetSystemNodeOwner(context.Background()) {
		t.Fatalf("admin replacement node changed: %+v err=%v", currentReplacement, err)
	}
	currentDesired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || currentDesired == nil || currentDesired.DesiredState != storage.DesiredInboundStateActive ||
		currentDesired.MutationID != replacementMutation {
		t.Fatalf("admin replacement desired state changed: %+v err=%v", currentDesired, err)
	}
	currentDesiredInbound, err := decodeDesiredInbound(currentDesired.InboundJSON)
	if err != nil {
		t.Fatalf("decode current replacement desired inbound: %v", err)
	}
	if retained, err := userManagedInboundContainsCredential(currentDesiredInbound, oldCredential); err != nil || retained {
		t.Fatalf("old credential remains in replacement desired inbound: retained=%v err=%v", retained, err)
	}
	adminCredential := &storage.UserInboundConfig{
		Protocol: "vless", CredentialJSON: `{"id":"9f7e1882-8692-4494-bb58-9f1e0dfe5777","email":"admin"}`,
	}
	if retained, err := userManagedInboundContainsCredential(currentDesiredInbound, adminCredential); err != nil || !retained {
		t.Fatalf("admin credential was removed from replacement desired inbound: retained=%v err=%v", retained, err)
	}
	owner, err := fixture.repo.GetRemoteInboundOwnership(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || owner != replacementMutation {
		t.Fatalf("admin replacement ownership changed: %q err=%v", owner, err)
	}
	fixture.agent.mu.Lock()
	currentRuntime := cloneUserManagedTestMap(fixture.agent.inbounds[creation.InboundTag])
	fixture.agent.mu.Unlock()
	if retained, err := userManagedInboundContainsCredential(currentRuntime, oldCredential); err != nil || retained {
		t.Fatalf("old credential remains in replacement Agent runtime: retained=%v err=%v", retained, err)
	}
	if retained, err := userManagedInboundContainsCredential(currentRuntime, adminCredential); err != nil || !retained {
		t.Fatalf("admin credential was removed from replacement Agent runtime: retained=%v err=%v", retained, err)
	}
	events, _, inboundPresent := fixture.agent.snapshots()
	if !inboundPresent {
		t.Fatal("admin replacement runtime was removed")
	}
	foundRemoveClient := false
	for _, eventName := range events {
		if eventName == "remove" {
			t.Fatalf("superseded cleanup mutated the replacement inbound: %v", events)
		}
		foundRemoveClient = foundRemoveClient || eventName == "remove-client"
	}
	if !foundRemoveClient {
		t.Fatalf("superseded cleanup did not remove the old credential: %v", events)
	}
}

func TestUserManagedSupersededGenerationPreservesIndependentDirectAccess(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-superseded-direct"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].NodeID == nil || creations[0].OfferID == nil || creations[0].SelectionID == nil {
		t.Fatalf("unexpected creation: %+v err=%v", creations, err)
	}
	creation := creations[0]
	credential, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, creation.InboundTag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}

	const replacementMutation = "admin-replacement-with-direct-access"
	var adminReplacement map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload(creation.InboundTag)), &adminReplacement); err != nil {
		t.Fatal(err)
	}
	adminReplacement["mutation_id"] = replacementMutation
	adminBody, _ := json.Marshal(adminReplacement)
	adminResponse := httptest.NewRecorder()
	adminRequest := managedUserHTTPRequest(http.MethodPost,
		"/api/admin/remote/inbounds?server_id="+managedIDString(fixture.server.ID), "owner", string(adminBody))
	fixture.handler.remoteManage.HandleInbounds(adminResponse, adminRequest)
	if adminResponse.Code >= http.StatusBadRequest {
		t.Fatalf("admin replacement status=%d body=%s", adminResponse.Code, adminResponse.Body.String())
	}
	var replacementNode *storage.Node
	nodes, err := fixture.repo.ListAllNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := range nodes {
		if nodes[i].OriginalServer == fixture.server.Name && nodes[i].InboundTag == creation.InboundTag &&
			nodes[i].InboundMutationID == replacementMutation && nodes[i].Username == fixture.repo.GetSystemNodeOwner(context.Background()) {
			replacementNode = &nodes[i]
			break
		}
	}
	if replacementNode == nil {
		t.Fatalf("admin replacement did not create a system-owned node: %+v", nodes)
	}
	replacementDesired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || replacementDesired == nil {
		t.Fatalf("GetDesiredInbound(replacement): %+v err=%v", replacementDesired, err)
	}
	replacementInbound, err := decodeDesiredInbound(replacementDesired.InboundJSON)
	if err != nil {
		t.Fatal(err)
	}
	retainUserManagedTestCredential(t, replacementInbound, credential)
	replacementJSON, _ := json.Marshal(replacementInbound)
	if _, err := fixture.repo.UpsertActiveDesiredInbound(context.Background(), fixture.server.ID,
		creation.InboundTag, replacementMutation, replacementJSON); err != nil {
		t.Fatalf("retain direct credential in desired inbound: %v", err)
	}
	fixture.agent.mu.Lock()
	replacementRuntime := cloneUserManagedTestMap(fixture.agent.inbounds[creation.InboundTag])
	retainUserManagedTestCredential(t, replacementRuntime, credential)
	fixture.agent.inbounds[creation.InboundTag] = replacementRuntime
	fixture.agent.mu.Unlock()

	direct, _, err := fixture.repo.UpsertManualUserNodeGrant(context.Background(), "alice", replacementNode.ID, nil, "owner")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	if err := fixture.handler.reconcileSource(context.Background(), direct.Source); err != nil {
		t.Fatalf("reconcile direct grant: %v", err)
	}
	direct, err = fixture.repo.GetUserNodeGrant(context.Background(), direct.Grant.ID)
	if err != nil || direct.Grant.CredentialConfigID == nil || *direct.Grant.CredentialConfigID != credential.ID {
		t.Fatalf("direct grant did not share canonical credential: %+v err=%v", direct, err)
	}

	fixture.handler.reconcileUserManagedNodeCreations(context.Background(), time.Now().UTC())
	if _, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creation.ID); !errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		t.Fatalf("old creation remains: %v", err)
	}
	if _, err := fixture.repo.GetSelfServiceNodeOffer(context.Background(), *creation.OfferID); !errors.Is(err, storage.ErrSelfServiceNodeOfferNotFound) {
		t.Fatalf("old private offer remains: %v", err)
	}
	if _, err := fixture.repo.GetUserNodeSelection(context.Background(), *creation.SelectionID); !errors.Is(err, storage.ErrUserNodeSelectionNotFound) {
		t.Fatalf("old selection remains: %v", err)
	}
	currentDirect, err := fixture.repo.GetUserNodeGrant(context.Background(), direct.Grant.ID)
	if err != nil || currentDirect.Grant.CredentialConfigID == nil || *currentDirect.Grant.CredentialConfigID != credential.ID ||
		currentDirect.Source.DesiredState != storage.ManagedDesiredActive {
		t.Fatalf("independent direct access changed: %+v err=%v", currentDirect, err)
	}
	currentCredential, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, creation.InboundTag)
	if err != nil || currentCredential.ID != credential.ID {
		t.Fatalf("shared direct credential was deleted: %+v err=%v", currentCredential, err)
	}
	currentDesired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || currentDesired == nil || currentDesired.MutationID != replacementMutation {
		t.Fatalf("replacement desired state changed: %+v err=%v", currentDesired, err)
	}
	currentDesiredInbound, err := decodeDesiredInbound(currentDesired.InboundJSON)
	if err != nil {
		t.Fatal(err)
	}
	if retained, err := userManagedInboundContainsCredential(currentDesiredInbound, currentCredential); err != nil || !retained {
		t.Fatalf("direct credential was removed from desired inbound: retained=%v err=%v", retained, err)
	}
	fixture.agent.mu.Lock()
	currentRuntime := cloneUserManagedTestMap(fixture.agent.inbounds[creation.InboundTag])
	fixture.agent.mu.Unlock()
	if retained, err := userManagedInboundContainsCredential(currentRuntime, currentCredential); err != nil || !retained {
		t.Fatalf("direct credential was removed from Agent runtime: retained=%v err=%v", retained, err)
	}
	events, _, inboundPresent := fixture.agent.snapshots()
	if !inboundPresent {
		t.Fatal("replacement runtime was removed")
	}
	for _, eventName := range events {
		if eventName == "remove" || eventName == "remove-client" {
			t.Fatalf("independently authorized replacement credential was mutated: %v", events)
		}
	}
}

func TestUserManagedSupersededCredentialRemovalFailureKeepsDenyAndGraph(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-superseded-retained"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].OfferID == nil || creations[0].SelectionID == nil {
		t.Fatalf("unexpected creation: %+v err=%v", creations, err)
	}
	creation := creations[0]
	oldCredential, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, creation.InboundTag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig(old): %v", err)
	}
	const replacementMutation = "admin-replacement-retaining-user-credential"
	var adminReplacement map[string]interface{}
	if err := json.Unmarshal([]byte(userManagedFrontendPayload(creation.InboundTag)), &adminReplacement); err != nil {
		t.Fatal(err)
	}
	adminReplacement["mutation_id"] = replacementMutation
	adminBody, _ := json.Marshal(adminReplacement)
	adminResponse := httptest.NewRecorder()
	adminRequest := managedUserHTTPRequest(http.MethodPost,
		"/api/admin/remote/inbounds?server_id="+managedIDString(fixture.server.ID), "owner", string(adminBody))
	fixture.handler.remoteManage.HandleInbounds(adminResponse, adminRequest)
	if adminResponse.Code >= http.StatusBadRequest {
		t.Fatalf("admin replacement status=%d body=%s", adminResponse.Code, adminResponse.Body.String())
	}
	desired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || desired == nil {
		t.Fatalf("GetDesiredInbound(replacement): %+v err=%v", desired, err)
	}
	desiredInbound, err := decodeDesiredInbound(desired.InboundJSON)
	if err != nil {
		t.Fatal(err)
	}
	retainUserManagedTestCredential(t, desiredInbound, oldCredential)
	desiredJSON, _ := json.Marshal(desiredInbound)
	if _, err := fixture.repo.UpsertActiveDesiredInbound(context.Background(), fixture.server.ID,
		creation.InboundTag, replacementMutation, desiredJSON); err != nil {
		t.Fatalf("retain old credential in replacement desired: %v", err)
	}
	fixture.agent.mu.Lock()
	replacementRuntime := cloneUserManagedTestMap(fixture.agent.inbounds[creation.InboundTag])
	fixture.agent.mu.Unlock()
	retainUserManagedTestCredential(t, replacementRuntime, oldCredential)
	fixture.agent.mu.Lock()
	fixture.agent.inbounds[creation.InboundTag] = replacementRuntime
	fixture.agent.failRemoveClient = true
	fixture.agent.mu.Unlock()

	fixture.handler.reconcileUserManagedNodeCreations(context.Background(), time.Now().UTC())
	pending, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creation.ID)
	if err != nil || pending.State != storage.UserManagedNodeDeleting {
		t.Fatalf("credential-retaining replacement did not remain deleting: %+v err=%v", pending, err)
	}
	if _, err := fixture.repo.GetSelfServiceNodeOffer(context.Background(), *creation.OfferID); err != nil {
		t.Fatalf("credential-retaining replacement deleted private offer: %v", err)
	}
	selection, err := fixture.repo.GetUserNodeSelection(context.Background(), *creation.SelectionID)
	if err != nil || selection.DesiredEnabled {
		t.Fatalf("credential-retaining replacement did not retain a disabled selection: %+v err=%v", selection, err)
	}
	credential, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, creation.InboundTag)
	if err != nil {
		t.Fatalf("credential-retaining replacement deleted credential graph: %v", err)
	}
	fixture.agent.mu.Lock()
	currentInbound := cloneUserManagedTestMap(fixture.agent.inbounds[creation.InboundTag])
	fixture.agent.mu.Unlock()
	retained, err := userManagedInboundContainsCredential(currentInbound, credential)
	if err != nil || !retained {
		t.Fatalf("replacement no longer contains retained credential: retained=%v err=%v inbound=%+v", retained, err, currentInbound)
	}
	events, snapshots, inboundPresent := fixture.agent.snapshots()
	if !inboundPresent {
		t.Fatal("credential-retaining admin replacement was removed")
	}
	foundRemoveClient := false
	for _, eventName := range events {
		if eventName == "remove" {
			t.Fatalf("credential-retaining replacement received an unsafe inbound mutation: %v", events)
		}
		foundRemoveClient = foundRemoveClient || eventName == "remove-client"
	}
	if !foundRemoveClient {
		t.Fatalf("credential-retaining replacement did not attempt exact removal: %v", events)
	}
	foundDeny := false
	for _, snapshot := range snapshots {
		for _, user := range snapshot.Users {
			if user.Email == "alice__alice-superseded-retained" && user.Denied {
				foundDeny = true
			}
		}
	}
	if !foundDeny {
		t.Fatalf("credential-retaining replacement lost deny policy: %+v", snapshots)
	}
}

func TestUserManagedStagedReplacementWithoutAgentAckRetainsOldDenyAndGraph(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-staged-only"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].OfferID == nil || creations[0].SelectionID == nil {
		t.Fatalf("unexpected creation: %+v err=%v", creations, err)
	}
	creation := creations[0]
	desired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || desired == nil {
		t.Fatalf("GetDesiredInbound(old): %+v err=%v", desired, err)
	}
	const stagedMutation = "admin-staged-without-agent-ack"
	if _, err := fixture.repo.UpsertActiveDesiredInbound(context.Background(), fixture.server.ID,
		creation.InboundTag, stagedMutation, desired.InboundJSON); err != nil {
		t.Fatalf("stage replacement desired inbound: %v", err)
	}
	if err := fixture.repo.SetRemoteInboundOwnership(context.Background(), fixture.server.ID,
		creation.InboundTag, stagedMutation); err != nil {
		t.Fatalf("stage replacement ownership: %v", err)
	}
	oldNode, err := fixture.repo.GetNodeByID(context.Background(), *creation.NodeID)
	if err != nil {
		t.Fatalf("GetNodeByID(old): %v", err)
	}
	staleReplacement := oldNode
	staleReplacement.ID = 0
	staleReplacement.Username = fixture.repo.GetSystemNodeOwner(context.Background())
	staleReplacement.NodeName += " stale staged replacement"
	staleReplacement.InboundMutationID = stagedMutation
	if _, err := fixture.repo.CreateNode(context.Background(), staleReplacement); err != nil {
		t.Fatalf("CreateNode(stale replacement evidence): %v", err)
	}
	// The fake Agent deliberately remains on creation.MutationID. Even matching
	// desired, ownership, and a stale local system node cannot replace the
	// authenticated Agent generation fence.
	if err := fixture.handler.cleanupUserManagedNodeCreation(context.Background(), creation, "owner"); err == nil {
		t.Fatal("cleanup succeeded without replacement Agent acknowledgement")
	}
	pending, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creation.ID)
	if err != nil || pending.State != storage.UserManagedNodeDeleting {
		t.Fatalf("staged-only replacement lost durable cleanup state: %+v err=%v", pending, err)
	}
	if _, err := fixture.repo.GetSelfServiceNodeOffer(context.Background(), *creation.OfferID); err != nil {
		t.Fatalf("staged-only replacement deleted private offer: %v", err)
	}
	if _, err := fixture.repo.GetUserNodeSelection(context.Background(), *creation.SelectionID); err != nil {
		t.Fatalf("staged-only replacement deleted selection: %v", err)
	}
	if _, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, creation.InboundTag); err != nil {
		t.Fatalf("staged-only replacement deleted credential: %v", err)
	}
	_, snapshots, inboundPresent := fixture.agent.snapshots()
	if !inboundPresent {
		t.Fatal("old Agent runtime disappeared in staged-only test")
	}
	foundDeny := false
	for _, snapshot := range snapshots {
		for _, user := range snapshot.Users {
			if user.Email == "alice__alice-staged-only" && user.Denied {
				foundDeny = true
			}
		}
	}
	if !foundDeny {
		t.Fatalf("staged-only replacement lost deny policy: %+v", snapshots)
	}
}

func TestUserManagedAgentReplacementWithoutNodeSyncRetainsOldGraph(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-agent-before-node-sync"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].OfferID == nil || creations[0].SelectionID == nil {
		t.Fatalf("unexpected creation: %+v err=%v", creations, err)
	}
	creation := creations[0]
	desired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || desired == nil {
		t.Fatalf("GetDesiredInbound(old): %+v err=%v", desired, err)
	}
	const replacementMutation = "admin-agent-acked-before-node-sync"
	if _, err := fixture.repo.UpsertActiveDesiredInbound(context.Background(), fixture.server.ID,
		creation.InboundTag, replacementMutation, desired.InboundJSON); err != nil {
		t.Fatalf("stage replacement desired inbound: %v", err)
	}
	if err := fixture.repo.SetRemoteInboundOwnership(context.Background(), fixture.server.ID,
		creation.InboundTag, replacementMutation); err != nil {
		t.Fatalf("stage replacement ownership: %v", err)
	}
	fixture.agent.mu.Lock()
	fixture.agent.mutationIDs[creation.InboundTag] = replacementMutation
	fixture.agent.mu.Unlock()

	if err := fixture.handler.cleanupUserManagedNodeCreation(context.Background(), creation, "owner"); err == nil {
		t.Fatal("cleanup retired the old graph before replacement NodeSync")
	}
	pending, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creation.ID)
	if err != nil || pending.State != storage.UserManagedNodeDeleting {
		t.Fatalf("pre-NodeSync replacement lost durable cleanup state: %+v err=%v", pending, err)
	}
	if _, err := fixture.repo.GetSelfServiceNodeOffer(context.Background(), *creation.OfferID); err != nil {
		t.Fatalf("pre-NodeSync replacement deleted private offer: %v", err)
	}
	if _, err := fixture.repo.GetUserNodeSelection(context.Background(), *creation.SelectionID); err != nil {
		t.Fatalf("pre-NodeSync replacement deleted selection: %v", err)
	}
	if _, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, creation.InboundTag); err != nil {
		t.Fatalf("pre-NodeSync replacement deleted credential graph: %v", err)
	}
	nodes, err := fixture.repo.ListNodes(context.Background(), fixture.repo.GetSystemNodeOwner(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if node.OriginalServer == fixture.server.Name && node.InboundTag == creation.InboundTag &&
			node.InboundMutationID == replacementMutation {
			t.Fatalf("test unexpectedly has a replacement system node: %+v", node)
		}
	}
	_, snapshots, inboundPresent := fixture.agent.snapshots()
	if !inboundPresent {
		t.Fatal("pre-NodeSync replacement runtime was removed")
	}
	foundDeny := false
	for _, snapshot := range snapshots {
		for _, limiterUser := range snapshot.Users {
			if limiterUser.Email == "alice__alice-agent-before-node-sync" && limiterUser.Denied {
				foundDeny = true
			}
		}
	}
	if !foundDeny {
		t.Fatalf("pre-NodeSync replacement lost deny policy: %+v", snapshots)
	}
}

func TestUserManagedNewerDeletedGenerationConvergesOnlyAfterAgentAbsence(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-ws")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-replaced-deleted"))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 1 || creations[0].NodeID == nil {
		t.Fatalf("unexpected creation: %+v err=%v", creations, err)
	}
	creation := creations[0]
	desired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || desired == nil {
		t.Fatalf("GetDesiredInbound(old): %+v err=%v", desired, err)
	}
	const deletedMutation = "admin-replacement-deleted"
	if _, err := fixture.repo.UpsertActiveDesiredInbound(context.Background(), fixture.server.ID,
		creation.InboundTag, deletedMutation, desired.InboundJSON); err != nil {
		t.Fatalf("stage replacement desired: %v", err)
	}
	if _, err := fixture.repo.MarkDesiredInboundDeleted(context.Background(), fixture.server.ID,
		creation.InboundTag, deletedMutation); err != nil {
		t.Fatalf("stage replacement tombstone: %v", err)
	}
	fixture.agent.mu.Lock()
	fixture.agent.inbounds = nil
	fixture.agent.mutationIDs = nil
	fixture.agent.mu.Unlock()

	fixture.handler.reconcileUserManagedNodeCreations(context.Background(), time.Now().UTC())
	if _, err := fixture.repo.GetUserManagedNodeCreation(context.Background(), creation.ID); !errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		t.Fatalf("old creation did not converge after authoritative Agent absence: %v", err)
	}
	if _, err := fixture.repo.GetNodeByID(context.Background(), *creation.NodeID); !errors.Is(err, storage.ErrNodeNotFound) {
		t.Fatalf("old mutation node remains: %v", err)
	}
	currentDesired, err := fixture.repo.GetDesiredInbound(context.Background(), fixture.server.ID, creation.InboundTag)
	if err != nil || currentDesired == nil || currentDesired.DesiredState != storage.DesiredInboundStateDeleted ||
		currentDesired.MutationID != deletedMutation {
		t.Fatalf("newer deletion tombstone changed: %+v err=%v", currentDesired, err)
	}
	events, _, _ := fixture.agent.snapshots()
	for _, eventName := range events {
		if eventName == "remove" || eventName == "remove-client" {
			t.Fatalf("authoritative absence cleanup sent an inbound mutation: %v", events)
		}
	}
}

func TestUserManagedProfileRejectsBeforeRemoteAdd(t *testing.T) {
	fixture := newUserManagedCreationFixture(t, "vless-reality")
	response := postUserManagedCreation(t, fixture, userManagedFrontendPayload("alice-profile-reject"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	events, _, _ := fixture.agent.snapshots()
	for _, eventName := range events {
		if eventName == "add" {
			t.Fatalf("profile rejection happened after remote add: %v", events)
		}
	}
	creations, err := fixture.repo.ListUserManagedNodeCreations(context.Background(), "alice", fixture.grant.ID)
	if err != nil || len(creations) != 0 {
		t.Fatalf("profile rejection leaked reservation: %+v err=%v", creations, err)
	}
	if _, err := fixture.repo.GetUserInboundConfig(context.Background(), "alice", fixture.server.ID, "alice-profile-reject"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("profile rejection credential lookup error=%v, want not found", err)
	}
}
