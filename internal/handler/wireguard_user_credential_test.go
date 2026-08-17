package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestWireGuardUserCredentialConcurrentAllocationIsUnique(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)
	server := &storage.RemoteServer{Name: "wg-concurrent-edge", Token: "token", IPAddress: "127.0.0.1"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	settings, _ := wireGuardCredentialTestSettings(t)
	alice, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := repo.GetUser(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}

	for iteration := 0; iteration < 24; iteration++ {
		inboundTag := fmt.Sprintf("wg-concurrent-%d", iteration)
		start := make(chan struct{})
		credentials := make([]map[string]interface{}, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, user := range []storage.User{alice, bob} {
			wg.Add(1)
			go func(index int, candidate storage.User) {
				defer wg.Done()
				<-start
				credentials[index], _, _, errs[index] = getOrCreateInboundCredential(
					ctx, repo, candidate, server.ID, inboundTag, "wireguard", settings,
				)
			}(i, user)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("iteration %d user %d: %v", iteration, i, err)
			}
		}
		if reflect.DeepEqual(credentials[0]["allowedIPs"], credentials[1]["allowedIPs"]) {
			t.Fatalf("iteration %d allocated duplicate address: %#v", iteration, credentials[0]["allowedIPs"])
		}
	}
}

func TestWireGuardUserPrivateKeyCiphertextIsScopeBoundAndPlaintextFailsClosed(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)
	server := &storage.RemoteServer{Name: "wg-secret-edge", Token: "token", IPAddress: "127.0.0.1"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	privateKey, publicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, serverPublicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := repo.SealWireGuardUserPrivateKey("alice", server.ID, "wg-secret", privateKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if opened, err := repo.OpenWireGuardUserPrivateKey("alice", server.ID, "wg-secret", ciphertext); err != nil || opened != privateKey {
		t.Fatalf("open correct scope: opened=%q err=%v", opened, err)
	}
	if _, err := repo.OpenWireGuardUserPrivateKey("bob", server.ID, "wg-secret", ciphertext); err == nil {
		t.Fatal("ciphertext opened under a different user scope")
	}

	plaintextJSON, err := json.Marshal(wireGuardUserCredentialRecord{
		PrivateKey: privateKey, PublicKey: publicKey, ServerPublicKey: serverPublicKey,
		Address: []string{"10.66.66.9/32"}, MTU: 1280, KeepAlive: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "wg-plaintext",
		Protocol: "wireguard", CredentialJSON: string(plaintextJSON),
	}); err != nil {
		t.Fatalf("save plaintext fixture: %v", err)
	}
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x51}, 32)); err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("ConfigureNodeSecretEncryption err=%v, want plaintext failure", err)
	}
}

func newWireGuardCredentialTestRepo(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo := newManagedSecurityTestRepo(t)
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x51}, 32)); err != nil {
		t.Fatalf("configure secret encryption: %v", err)
	}
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	createManagedSecurityTestUser(t, repo, "bob", storage.RoleUser)
	return repo
}

func wireGuardCredentialTestSettings(t *testing.T) (map[string]interface{}, string) {
	t.Helper()
	serverPrivateKey, serverPublicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generate server keypair: %v", err)
	}
	_, bootstrapPublicKey, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("generate bootstrap keypair: %v", err)
	}
	return map[string]interface{}{
		"secretKey": serverPrivateKey,
		"address":   []interface{}{"10.66.66.1/32"},
		"mtu":       float64(1280),
		"peers": []interface{}{
			map[string]interface{}{
				"publicKey": bootstrapPublicKey,
				"allowedIPs": []interface{}{
					"10.66.66.2/32",
				},
				"keepAlive": float64(17),
			},
		},
	}, serverPublicKey
}

func TestWireGuardUserCredentialStoredEncryptedHydratesAndAllocatesUniquely(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)
	server := &storage.RemoteServer{Name: "wg-edge", Token: "token", IPAddress: "127.0.0.1"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	settings, serverPublicKey := wireGuardCredentialTestSettings(t)

	alice, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	aliceAgentCredential, aliceJSON, reused, err := getOrCreateInboundCredential(ctx, repo, alice, server.ID, "wg-in", "wireguard", settings)
	if err != nil {
		t.Fatalf("create Alice WireGuard credential: %v", err)
	}
	if reused {
		t.Fatal("new WireGuard credential reported reused")
	}
	if got, want := aliceAgentCredential["allowedIPs"], []string{"10.66.66.3/32"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Alice allowedIPs=%#v, want %#v", got, want)
	}
	for _, forbidden := range []string{"privateKey", "encryptedPrivateKey", "serverPublicKey", "address", "mtu"} {
		if _, exists := aliceAgentCredential[forbidden]; exists {
			t.Fatalf("Agent credential leaked %s: %#v", forbidden, aliceAgentCredential)
		}
	}

	stored, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-in")
	if err != nil {
		t.Fatalf("load Alice stored credential: %v", err)
	}
	if stored.CredentialJSON != aliceJSON {
		t.Fatalf("stored JSON mismatch\nstored=%s\nreturned=%s", stored.CredentialJSON, aliceJSON)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(stored.CredentialJSON), &raw); err != nil {
		t.Fatalf("parse stored credential: %v", err)
	}
	if raw["privateKey"] != nil {
		t.Fatalf("stored credential contains plaintext privateKey: %s", stored.CredentialJSON)
	}
	if encrypted, _ := raw["encryptedPrivateKey"].(string); encrypted == "" || !strings.HasPrefix(encrypted, "v1:") {
		t.Fatalf("stored credential encryptedPrivateKey=%#v, want secretbox envelope", raw["encryptedPrivateKey"])
	}

	hydrated, err := HydrateWireGuardUserCredential(repo, *stored)
	if err != nil {
		t.Fatalf("hydrate WireGuard credential: %v", err)
	}
	if !validWireGuardKey(hydrated["privateKey"].(string)) {
		t.Fatalf("hydrated private key is invalid: %#v", hydrated["privateKey"])
	}
	if hydrated["serverPublicKey"] != serverPublicKey {
		t.Fatalf("serverPublicKey=%#v, want %#v", hydrated["serverPublicKey"], serverPublicKey)
	}
	if got, want := hydrated["address"], []string{"10.66.66.3/32"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hydrated address=%#v, want %#v", got, want)
	}
	if hydrated["mtu"] != 1280 || hydrated["keepAlive"] != 17 {
		t.Fatalf("hydrated mtu/keepAlive=%#v/%#v", hydrated["mtu"], hydrated["keepAlive"])
	}

	bob, err := repo.GetUser(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bobAgentCredential, _, _, err := getOrCreateInboundCredential(ctx, repo, bob, server.ID, "wg-in", "wireguard", settings)
	if err != nil {
		t.Fatalf("create Bob WireGuard credential: %v", err)
	}
	if got, want := bobAgentCredential["allowedIPs"], []string{"10.66.66.4/32"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Bob allowedIPs=%#v, want %#v", got, want)
	}

	aliceAgentCredentialAgain, _, reused, err := getOrCreateInboundCredential(ctx, repo, alice, server.ID, "wg-in", "wireguard", settings)
	if err != nil {
		t.Fatalf("reuse Alice WireGuard credential: %v", err)
	}
	if !reused || !reflect.DeepEqual(aliceAgentCredentialAgain["allowedIPs"], aliceAgentCredential["allowedIPs"]) ||
		aliceAgentCredentialAgain["publicKey"] != aliceAgentCredential["publicKey"] {
		t.Fatalf("Alice credential was not reused: got=%#v want=%#v reused=%v", aliceAgentCredentialAgain, aliceAgentCredential, reused)
	}
}

func TestWireGuardPackageLimiterMapsPeerAddressToIndependentUserPolicy(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)
	server := &storage.RemoteServer{Name: "wg-limiter-edge", Token: "token", IPAddress: "127.0.0.1", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "alice", NodeName: "managed-wg", Protocol: "wireguard", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-limit",
		ClashConfig: fmt.Sprintf(
			`{"name":"managed-wg","type":"wireguard","server":"203.0.113.10","port":51820,"private-key":%q,"public-key":%q}`,
			wireGuardYAMLTestKey(0x31), wireGuardYAMLTestKey(0x32),
		),
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "wg-limiter", Nodes: []int64{node.ID}, SpeedLimitMbps: 8, DeviceLimit: 2,
	})
	if err != nil {
		t.Fatalf("create package: %v", err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign package: %v", err)
	}
	settings, _ := wireGuardCredentialTestSettings(t)
	inbound := map[string]interface{}{
		"tag": "wg-limit", "listen": "0.0.0.0", "port": float64(51820), "protocol": "wireguard",
		"settings": cloneInboundMap(map[string]interface{}{"settings": settings})["settings"],
	}
	seedHandlerManagedWireGuardProvenance(t, repo, server, &node, inbound, "managed-wireguard:wg-limit", true)
	alice, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	credential, _, _, err := getOrCreateInboundCredential(ctx, repo, alice, server.ID, "wg-limit", "wireguard", settings)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	configs, err := NewLimiterConfigPusher(repo, nil).BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build limiter config: %v", err)
	}
	limit := findLimiterUser(t, configs, "wg-limit", "alice__wg-limit")
	if limit.SpeedLimit != 1_000_000 || limit.DeviceLimit != 2 {
		t.Fatalf("WireGuard policy=%#v", limit)
	}
	if len(configs) != 1 || len(configs[0].WireGuardPeers) != 2 {
		t.Fatalf("WireGuard peer mapping=%#v", configs)
	}
	wantAddress := credential["allowedIPs"].([]string)[0]
	foundUserPeer := false
	for _, peer := range configs[0].WireGuardPeers {
		if peer.Address == wantAddress && peer.Email == "alice__wg-limit" {
			foundUserPeer = true
			break
		}
	}
	if !foundUserPeer {
		t.Fatalf("WireGuard peer mappings=%#v want address=%s email=alice__wg-limit", configs[0].WireGuardPeers, wantAddress)
	}
}

func TestWireGuardPackageAndSubscriptionRejectSameCoordinateHistoricalNode(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)
	server := &storage.RemoteServer{
		Name: "wg-provenance-edge", Token: "token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "127.0.0.1", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	createNode := func(name string) storage.Node {
		t.Helper()
		node, err := repo.CreateNode(ctx, storage.Node{
			Username: "owner", NodeName: name, Protocol: "wireguard", Enabled: true,
			OriginalServer: server.Name, InboundTag: "wg-shared-coordinate",
			ClashConfig: fmt.Sprintf(
				`{"name":%q,"type":"wireguard","server":"203.0.113.10","port":51820,"private-key":%q,"public-key":%q}`,
				name, wireGuardYAMLTestKey(0x41), wireGuardYAMLTestKey(0x42),
			),
		})
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	validNode := createNode("current-managed-wg")
	historicalNode := createNode("historical-coordinate-wg")
	settings, _ := wireGuardCredentialTestSettings(t)
	inbound := map[string]interface{}{
		"tag": "wg-shared-coordinate", "listen": "0.0.0.0", "port": float64(51820), "protocol": "wireguard",
		"settings": settings,
	}
	seedHandlerManagedWireGuardProvenance(t, repo, server, &validNode, inbound,
		"managed-wireguard:shared-coordinate", true)
	if !packageSubscriptionNodeEligible(ctx, repo, validNode) {
		t.Fatal("current managed WireGuard node was rejected from subscription")
	}
	if packageSubscriptionNodeEligible(ctx, repo, historicalNode) {
		t.Fatal("historical same-coordinate WireGuard node borrowed the current credential")
	}

	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "historical-wg-package", CycleDays: 30, Nodes: []int64{historicalNode.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	hasAccess, err := hasPackageTemplateInboundAccess(ctx, repo, "alice", server.ID, historicalNode.InboundTag, now)
	if err != nil || hasAccess {
		t.Fatalf("historical WireGuard package access=%v err=%v, want rejected", hasAccess, err)
	}
	hasAccess, _, err = hasLegacyPackageInboundAccessIgnoringOverLimit(
		ctx, repo, "alice", server.ID, historicalNode.InboundTag, now,
	)
	if err != nil || hasAccess {
		t.Fatalf("historical WireGuard restore access=%v err=%v, want rejected", hasAccess, err)
	}

	alice, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := createWireGuardInboundCredential(
		ctx, repo, alice, server.ID, historicalNode.InboundTag, settings,
	); err != nil {
		t.Fatalf("seed historical WireGuard credential: %v", err)
	}
	desired := map[string]map[string]interface{}{historicalNode.InboundTag: inbound}
	remote := NewRemoteManageHandler(repo, nil)
	if err := remote.rebuildDatabaseAuthorizedInboundClients(ctx, server.ID, desired, nil); err != nil {
		t.Fatalf("rebuild database-authoritative WireGuard peers: %v", err)
	}
	peers := wireGuardInterfaceSlice(settings["peers"])
	if len(peers) != 1 {
		t.Fatalf("authority restored historical same-coordinate user peer: %#v", peers)
	}
}

func TestWireGuardPeerPublicationWaitsForLimiterACK(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)
	settings, _ := wireGuardCredentialTestSettings(t)
	var eventsMu sync.Mutex
	var events []string
	var failLimiter atomic.Bool
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"inbounds": []interface{}{map[string]interface{}{
					"tag": "wg-order", "protocol": "wireguard", "settings": settings,
				}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
			eventsMu.Lock()
			events = append(events, "limiter")
			eventsMu.Unlock()
			if failLimiter.Load() {
				http.Error(w, "forced limiter failure", http.StatusBadGateway)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			eventsMu.Lock()
			events = append(events, "peer")
			eventsMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "changed": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()
	server := &storage.RemoteServer{
		Name: "wg-order-edge", Token: "token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket, IPAddress: "127.0.0.1",
		ListenPort: testServerPort(t, agent.URL), XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "alice", NodeName: "wg-order", Protocol: "wireguard", Enabled: true,
		OriginalServer: server.Name, InboundTag: "wg-order",
		ClashConfig: fmt.Sprintf(
			`{"name":"wg-order","type":"wireguard","server":"203.0.113.10","port":51820,"private-key":%q,"public-key":%q}`,
			wireGuardYAMLTestKey(0x61), wireGuardYAMLTestKey(0x62),
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound := map[string]interface{}{
		"tag": "wg-order", "listen": "0.0.0.0", "port": float64(51820), "protocol": "wireguard",
		"settings": settings,
	}
	seedHandlerManagedWireGuardProvenance(t, repo, server, &node, inbound, "managed-wireguard:wg-order", true)
	packageID, err := repo.CreatePackage(ctx, storage.Package{Name: "wg-order", Nodes: []int64{node.ID}, SpeedLimitMbps: 5})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, username := range []string{"alice", "bob"} {
		if err := repo.AssignPackageToUser(ctx, username, packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
			t.Fatal(err)
		}
	}
	ws := NewRemoteWSHandler(repo, nil)
	ws.conns.Store(server.ID, &RemoteWSConnection{
		ServerID: server.ID, Capabilities: AgentCapabilities{WireGuardPeerUsersV1: true},
	})
	remote := NewRemoteManageHandler(repo, ws)
	pusher := NewLimiterConfigPusher(repo, ws)
	alice, _ := repo.GetUser(ctx, "alice")
	if err := addUserToInboundWithLimiter(ctx, remote, repo, pusher, alice, server.ID, "wg-order"); err != nil {
		t.Fatalf("publish Alice peer: %v", err)
	}
	eventsMu.Lock()
	gotEvents := append([]string(nil), events...)
	eventsMu.Unlock()
	if !reflect.DeepEqual(gotEvents, []string{"limiter", "peer"}) {
		t.Fatalf("publication order=%#v, want limiter ACK before peer", gotEvents)
	}

	failLimiter.Store(true)
	bob, _ := repo.GetUser(ctx, "bob")
	if err := addUserToInboundWithLimiter(ctx, remote, repo, pusher, bob, server.ID, "wg-order"); err == nil || !strings.Contains(err.Error(), "limiter") {
		t.Fatalf("publish Bob with failed limiter err=%v", err)
	}
	eventsMu.Lock()
	gotEvents = append([]string(nil), events...)
	eventsMu.Unlock()
	if !reflect.DeepEqual(gotEvents, []string{"limiter", "peer", "limiter"}) {
		t.Fatalf("peer was published after failed limiter ACK: %#v", gotEvents)
	}
}

func TestWireGuardAgentMutationUsesPublicPeerPayloadAndRequiresCapability(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)
	settings, _ := wireGuardCredentialTestSettings(t)

	var received atomic.Int64
	var receivedClient map[string]interface{}
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/child/inbounds" {
			http.NotFound(w, r)
			return
		}
		received.Add(1)
		var request struct {
			Client map[string]interface{} `json:"client"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode Agent request: %v", err)
		}
		receivedClient = request.Client
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "changed": true})
	}))
	defer agent.Close()

	server := &storage.RemoteServer{
		Name:           "wg-mutation-edge",
		Token:          "token",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket,
		IPAddress:      "127.0.0.1",
		ListenPort:     testServerPort(t, agent.URL),
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	agentCredential, _, _, err := getOrCreateInboundCredential(ctx, repo, storage.User{Username: "alice"}, server.ID, "wg-in", "wireguard", settings)
	if err != nil {
		t.Fatalf("create WireGuard credential: %v", err)
	}
	ws := NewRemoteWSHandler(repo, nil)
	ws.conns.Store(server.ID, &RemoteWSConnection{ServerID: server.ID, Capabilities: AgentCapabilities{WireGuardPeerUsersV1: true}})
	remote := NewRemoteManageHandler(repo, ws)

	if err := applyPreparedInboundCredential(ctx, remote, server.ID, "wg-in", agentCredential, nil); err != nil {
		t.Fatalf("apply WireGuard credential: %v", err)
	}
	if received.Load() != 1 {
		t.Fatalf("Agent received %d mutations, want 1", received.Load())
	}
	wantKeys := map[string]bool{"publicKey": true, "allowedIPs": true, "keepAlive": true}
	if len(receivedClient) != len(wantKeys) {
		t.Fatalf("Agent client payload leaked extra fields: %#v", receivedClient)
	}
	for key := range wantKeys {
		if _, exists := receivedClient[key]; !exists {
			t.Fatalf("Agent client payload missing %s: %#v", key, receivedClient)
		}
	}

	ws.conns.Store(server.ID, &RemoteWSConnection{ServerID: server.ID, Capabilities: AgentCapabilities{}})
	if err := applyPreparedInboundCredential(ctx, remote, server.ID, "wg-in", agentCredential, nil); err == nil ||
		!strings.Contains(err.Error(), "wireguard_peer_users_v1") {
		t.Fatalf("apply without capability err=%v, want wireguard_peer_users_v1 failure", err)
	}
	if received.Load() != 1 {
		t.Fatalf("Agent was mutated despite missing capability; calls=%d", received.Load())
	}
}

func TestWireGuardCapabilityFallsBackToSystemInfoWithoutWebSocket(t *testing.T) {
	ctx := context.Background()
	repo := newWireGuardCredentialTestRepo(t)

	var systemInfoCalls atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/child/system/info" {
			http.NotFound(w, r)
			return
		}
		systemInfoCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"capabilities": map[string]bool{
				"wireguard_peer_users_v1": true,
			},
		})
	}))
	defer agent.Close()

	server := &storage.RemoteServer{
		Name:           "wg-http-capability",
		Token:          "token",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModePush,
		IPAddress:      "127.0.0.1",
		ListenPort:     testServerPort(t, agent.URL),
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	if err := requireWireGuardPeerUsersCapability(ctx, NewRemoteManageHandler(repo, nil), server.ID); err != nil {
		t.Fatalf("HTTP capability fallback: %v", err)
	}
	if systemInfoCalls.Load() != 1 {
		t.Fatalf("system/info calls=%d, want 1", systemInfoCalls.Load())
	}
}
