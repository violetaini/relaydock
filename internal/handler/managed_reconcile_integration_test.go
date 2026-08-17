package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type managedFakeAgent struct {
	mu         sync.Mutex
	calls      []string
	limiter    WSLimiterConfigPayload
	limiterHit chan struct{}
	limiterACK chan struct{}
	limiterOK  *bool
	inboundOK  *bool
	inboundTag string
	token      string
	addRequest struct {
		Action   string                 `json:"action"`
		Tag      string                 `json:"tag"`
		Client   map[string]interface{} `json:"client"`
		NotAfter *time.Time             `json:"not_after"`
	}
	snapshotHit chan struct{}
}

func (a *managedFakeAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := a.token
	if token == "" {
		token = "agent-token"
	}
	if r.Header.Get("Authorization") != "Bearer "+token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		tag := a.inboundTag
		if tag == "" {
			tag = "vless-in"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"inbounds": []map[string]interface{}{{
				"tag": tag, "protocol": "vless", "settings": map[string]interface{}{"clients": []interface{}{}},
			}},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
		a.mu.Lock()
		a.calls = append(a.calls, "limiter")
		err := json.NewDecoder(r.Body).Decode(&a.limiter)
		a.mu.Unlock()
		if err != nil {
			http.Error(w, "invalid limiter payload", http.StatusBadRequest)
			return
		}
		if a.limiterHit != nil {
			select {
			case a.limiterHit <- struct{}{}:
			default:
			}
		}
		if a.limiterACK != nil {
			select {
			case <-a.limiterACK:
			case <-r.Context().Done():
				return
			}
		}
		success := true
		if a.limiterOK != nil {
			success = *a.limiterOK
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": success})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		a.mu.Lock()
		a.calls = append(a.calls, "add-client")
		err := json.NewDecoder(r.Body).Decode(&a.addRequest)
		success := true
		if a.inboundOK != nil {
			success = *a.inboundOK
		}
		a.mu.Unlock()
		if err != nil {
			http.Error(w, "invalid inbound payload", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": success})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
		// A shared managed-client transaction must not try to upgrade itself into
		// a full database-authority reconcile.
		_, _ = w.Write([]byte(`{"success":false}`))
		select {
		case a.snapshotHit <- struct{}{}:
		default:
		}
	default:
		http.NotFound(w, r)
	}
}

func managedReadyAgentCapabilities() AgentCapabilities {
	return AgentCapabilities{
		ManagedClientsV1: true, ClientExpiry: true,
		LimiterReplace: true, LimiterReplaceAck: true, LimiterDeniedV1: true,
	}
}

func managedRemoteWithCapabilities(repo *storage.TrafficRepository, serverID int64, capabilities AgentCapabilities) *RemoteManageHandler {
	wsHandler := NewRemoteWSHandler(repo, nil)
	wsHandler.conns.Store(serverID, &RemoteWSConnection{ServerID: serverID, Capabilities: capabilities})
	return NewRemoteManageHandler(repo, wsHandler)
}

func TestManagedReconcileProvisionsLimiterBeforeExpiringClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	fakeAgent := &managedFakeAgent{
		snapshotHit: make(chan struct{}, 1),
		limiterHit:  make(chan struct{}, 1),
		limiterACK:  make(chan struct{}),
	}
	agentServer := httptest.NewServer(fakeAgent)
	t.Cleanup(agentServer.Close)
	agentURL, err := url.Parse(agentServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(agentURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}

	server := &storage.RemoteServer{
		Name: "edge-reconcile", Token: "agent-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: host, ListenPort: port, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "managed-vless", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"managed-vless","type":"vless","server":"203.0.113.40","port":443,"uuid":"owner-uuid"}`,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "owner")
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(2 * time.Hour).Truncate(time.Second)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveNodes: 1,
		SpeedLimitMbps: 25, ConnectionLimit: 3, BillingMode: storage.ManagedBillingBoth,
		ResetPolicy: storage.ManagedResetNone, ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "owner",
	}); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate selection: %v", err)
	}

	remoteManage := managedRemoteWithCapabilities(repo, server.ID, managedReadyAgentCapabilities())
	handler := NewManagedNodesHandler(repo, remoteManage, NewLimiterConfigPusher(repo, nil))
	reconcileResult := make(chan error, 1)
	go func() {
		reconcileResult <- handler.reconcileSource(ctx, activation.Source)
	}()
	select {
	case <-fakeAgent.limiterHit:
	case <-time.After(time.Second):
		t.Fatal("limiter request did not reach Agent")
	}
	beginAttempted := make(chan struct{})
	beginDone := make(chan error, 1)
	go func() {
		close(beginAttempted)
		beginDone <- repo.BeginRemoteServerInstallation(context.Background(), server.ID,
			"managed-reconcile-drain", time.Now().Add(time.Minute))
	}()
	<-beginAttempted
	select {
	case err := <-beginDone:
		t.Fatalf("installation Begin split an in-flight managed reconcile: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	fakeAgent.mu.Lock()
	callsBeforeACK := append([]string(nil), fakeAgent.calls...)
	fakeAgent.mu.Unlock()
	if len(callsBeforeACK) != 1 || callsBeforeACK[0] != "limiter" {
		t.Fatalf("client was mutated before limiter ACK: %v", callsBeforeACK)
	}
	close(fakeAgent.limiterACK)
	if err := <-reconcileResult; err != nil {
		t.Fatalf("reconcile managed source: %v", err)
	}
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("installation Begin after managed reconcile: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("installation Begin remained blocked after managed reconcile")
	}
	if err := repo.AbortRemoteServerInstallation(context.Background(), server.ID, "managed-reconcile-drain"); err != nil {
		t.Fatalf("abort test installation: %v", err)
	}

	fakeAgent.mu.Lock()
	calls := append([]string(nil), fakeAgent.calls...)
	limiter := fakeAgent.limiter
	addRequest := fakeAgent.addRequest
	fakeAgent.mu.Unlock()
	if len(calls) < 2 || calls[0] != "limiter" || calls[1] != "add-client" {
		t.Fatalf("agent mutation order=%v, want limiter then add-client", calls)
	}
	for _, call := range calls[2:] {
		if call != "limiter" {
			t.Fatalf("unexpected mutation after add-client: %v", calls)
		}
	}
	if limiter.InboundTag != "vless-in" || len(limiter.Users) != 1 {
		t.Fatalf("unexpected limiter snapshot: %#v", limiter)
	}
	if limiter.Users[0].SpeedLimit != 3_125_000 || limiter.Users[0].DeviceLimit != 3 {
		t.Fatalf("grant limiter not applied: %#v", limiter.Users[0])
	}
	if addRequest.Action != "add-client" || addRequest.Tag != "vless-in" || addRequest.NotAfter == nil || !addRequest.NotAfter.Equal(expires) {
		t.Fatalf("unexpected add-client request: %#v", addRequest)
	}
	if email, _ := addRequest.Client["email"].(string); email == "" || limiter.Users[0].Email != email {
		t.Fatalf("credential and limiter identities differ: client=%#v limiter=%#v", addRequest.Client, limiter.Users[0])
	}

	applied, err := repo.GetUserInboundAccessSource(ctx, activation.Source.ID)
	if err != nil {
		t.Fatalf("reload access source: %v", err)
	}
	if applied.ObservedState != storage.ManagedObservedActive || applied.AppliedGeneration != applied.Generation || applied.LastError != "" {
		t.Fatalf("source was not marked active: %#v", applied)
	}
	ids, err := effectiveManagedNodeIDs(ctx, repo, "alice")
	if err != nil || len(ids) != 1 || ids[0] != node.ID {
		t.Fatalf("provisioned node is not effective: ids=%v err=%v", ids, err)
	}

	select {
	case <-fakeAgent.snapshotHit:
		t.Fatal("managed client transaction triggered a redundant full Xray authority scan")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestLimiterAndManagedReconcileRejectActiveRemoteInstallationBeforeNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fixture := newManagedUserHTTPFixture(t, "alice")
	servers, err := fixture.repo.ListRemoteServers(ctx)
	if err != nil || len(servers) != 1 {
		t.Fatalf("resolve fixture server: servers=%v err=%v", servers, err)
	}
	server := servers[0]

	requested := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case requested <- struct{}{}:
		default:
		}
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	t.Cleanup(agent.Close)
	agentURL, err := url.Parse(agent.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(agentURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.repo.UpdateRemoteServerHeartbeat(ctx, server.Token, host, ""); err != nil {
		t.Fatalf("point fixture server at fake Agent: %v", err)
	}
	if err := fixture.repo.UpdateRemoteServerListenPort(ctx, server.ID, port); err != nil {
		t.Fatalf("update fake Agent port: %v", err)
	}
	if err := fixture.repo.BeginRemoteServerInstallation(ctx, server.ID, "active-managed-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("begin installation: %v", err)
	}

	pusher := NewLimiterConfigPusher(fixture.repo, nil)
	pusher.PushToServer(ctx, server.ID)
	if err := pusher.PushToServerChecked(ctx, server.ID); !errors.Is(err, storage.ErrRemoteInstallationActive) {
		t.Fatalf("checked limiter error=%v, want active installation", err)
	}
	remote := managedRemoteWithCapabilities(fixture.repo, server.ID, managedReadyAgentCapabilities())
	handler := NewManagedNodesHandler(fixture.repo, remote, pusher)
	if err := handler.reconcileSource(ctx, fixture.activation.Source); !errors.Is(err, storage.ErrRemoteInstallationActive) {
		t.Fatalf("managed reconcile error=%v, want active installation", err)
	}
	select {
	case <-requested:
		t.Fatal("active installation allowed limiter or managed reconcile network mutation")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestManagedReconcileReloadsStaleGenerationBeforeRemoteMutation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	fakeAgent := &managedFakeAgent{snapshotHit: make(chan struct{}, 1)}
	agentServer := httptest.NewServer(fakeAgent)
	t.Cleanup(agentServer.Close)
	agentURL, err := url.Parse(agentServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(agentURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}

	server := &storage.RemoteServer{
		Name: "edge-stale", Token: "agent-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: host, ListenPort: port, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "stale-vless", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"stale-vless","type":"vless","server":"203.0.113.41","port":443,"uuid":"owner-uuid"}`,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "owner")
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true, StartsAt: now.Add(-time.Hour),
		ExpiresAt: &expires, MaxActiveNodes: 1, BillingMode: storage.ManagedBillingDownload,
		ResetPolicy: storage.ManagedResetNone, ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "owner",
	}); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate selection: %v", err)
	}
	latest, err := repo.SetUserInboundAccessSourceState(ctx, activation.Source.ID, activation.Source.Generation,
		storage.ManagedDesiredInactive, storage.ManagedSuspendAdminDisabled, "owner", &expires)
	if err != nil {
		t.Fatalf("revoke source: %v", err)
	}

	handler := NewManagedNodesHandler(repo, NewRemoteManageHandler(repo, nil), NewLimiterConfigPusher(repo, nil))
	if err := handler.reconcileSource(ctx, activation.Source); err != nil {
		t.Fatalf("reconcile stale source snapshot: %v", err)
	}
	fakeAgent.mu.Lock()
	calls := append([]string(nil), fakeAgent.calls...)
	fakeAgent.mu.Unlock()
	for _, call := range calls {
		if call == "add-client" {
			t.Fatalf("stale active generation reached agent: %v", calls)
		}
	}
	applied, err := repo.GetUserInboundAccessSource(ctx, activation.Source.ID)
	if err != nil {
		t.Fatalf("reload source: %v", err)
	}
	if applied.Generation != latest.Generation || applied.AppliedGeneration != latest.Generation ||
		applied.DesiredState != storage.ManagedDesiredInactive || applied.ObservedState != storage.ManagedObservedInactive {
		t.Fatalf("latest revoke was not applied: %#v", applied)
	}
}

func TestManagedReconcilerExpiresDirectGrantAndRetriesRemoteRevoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	inboundOK := false
	fakeAgent := &managedFakeAgent{snapshotHit: make(chan struct{}, 1), inboundOK: &inboundOK}
	agentServer := httptest.NewServer(fakeAgent)
	t.Cleanup(agentServer.Close)
	agentURL, err := url.Parse(agentServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(agentURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	server := &storage.RemoteServer{
		Name: "edge-direct-expiry", Token: "agent-token", Status: storage.RemoteServerStatusConnected,
		IPAddress: host, ListenPort: port, XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "direct-expiry", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"direct-expiry","type":"vless","server":"203.0.113.43","port":443,"uuid":"owner-uuid"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(100 * time.Millisecond)
	item, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, &expiresAt, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: node.InboundTag, Protocol: node.Protocol,
		CredentialJSON: `{"id":"alice-direct-uuid","email":"alice__vless-in"}`,
	}); err != nil {
		t.Fatal(err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, node.InboundTag)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetUserNodeGrantCredential(ctx, item.Grant.ID, credential.ID); err != nil {
		t.Fatal(err)
	}
	applied, err := repo.MarkUserInboundAccessSourceApplied(ctx, item.Source.ID, item.Source.Generation,
		storage.ManagedObservedActive, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(expiresAt) + 20*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}

	remote := managedRemoteWithCapabilities(repo, server.ID, managedReadyAgentCapabilities())
	handler := NewManagedNodesHandler(repo, remote, nil)
	handler.reconcileAll(ctx)

	current, err := repo.GetUserInboundAccessSource(ctx, applied.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.DesiredState != storage.ManagedDesiredInactive || current.ObservedState != storage.ManagedObservedActive ||
		current.SuspendReason != storage.ManagedSuspendExpired || current.Generation == current.AppliedGeneration ||
		current.LastError == "" || current.NextRetryAt == nil {
		t.Fatalf("failed expiry revoke was not queued for retry: %+v", current)
	}
	fakeAgent.mu.Lock()
	inboundOK = true
	fakeAgent.mu.Unlock()
	if _, err := repo.MarkUserInboundAccessSourceFailed(ctx, current.ID, current.Generation,
		"retry test", time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	handler.reconcileAll(ctx)
	current, err = repo.GetUserInboundAccessSource(ctx, applied.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.DesiredState != storage.ManagedDesiredInactive || current.ObservedState != storage.ManagedObservedInactive ||
		current.SuspendReason != storage.ManagedSuspendExpired || current.Generation != current.AppliedGeneration || current.LastError != "" {
		t.Fatalf("expired direct grant retry did not converge: %+v", current)
	}
	fakeAgent.mu.Lock()
	calls := append([]string(nil), fakeAgent.calls...)
	removeAction := fakeAgent.addRequest.Action
	fakeAgent.mu.Unlock()
	if len(calls) != 2 || calls[0] != "add-client" || calls[1] != "add-client" || removeAction != "remove-client" {
		t.Fatalf("remote revoke calls=%v request=%#v", calls, fakeAgent.addRequest)
	}
}

func TestManagedReconcileDoesNotAddClientWithoutLimiterACK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixture := newManagedUserHTTPFixture(t, "alice")
	servers, err := fixture.repo.ListRemoteServers(ctx)
	if err != nil || len(servers) != 1 {
		t.Fatalf("resolve fixture server: servers=%v err=%v", servers, err)
	}

	ack := false
	fakeAgent := &managedFakeAgent{
		limiterOK:   &ack,
		inboundTag:  fixture.offer.InboundTag,
		snapshotHit: make(chan struct{}, 1),
		token:       servers[0].Token,
	}
	agentServer := httptest.NewServer(fakeAgent)
	t.Cleanup(agentServer.Close)
	agentURL, err := url.Parse(agentServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(agentURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.repo.UpdateRemoteServerHeartbeat(ctx, servers[0].Token, host, ""); err != nil {
		t.Fatalf("point fixture server at fake Agent: %v", err)
	}
	if err := fixture.repo.UpdateRemoteServerListenPort(ctx, servers[0].ID, port); err != nil {
		t.Fatalf("update fake Agent port: %v", err)
	}

	remote := managedRemoteWithCapabilities(fixture.repo, servers[0].ID, managedReadyAgentCapabilities())
	handler := NewManagedNodesHandler(fixture.repo, remote, NewLimiterConfigPusher(fixture.repo, nil))
	err = handler.reconcileSource(ctx, fixture.activation.Source)
	if err == nil || !strings.Contains(err.Error(), "not acknowledged") {
		t.Fatalf("reconcile error=%v, want missing limiter ACK", err)
	}

	fakeAgent.mu.Lock()
	calls := append([]string(nil), fakeAgent.calls...)
	fakeAgent.mu.Unlock()
	if len(calls) != 1 || calls[0] != "limiter" {
		t.Fatalf("Agent mutations without limiter ACK=%v, want limiter only", calls)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil {
		t.Fatalf("reload source: %v", err)
	}
	if source.ObservedState == storage.ManagedObservedActive || source.LastError == "" {
		t.Fatalf("source did not remain pending after missing ACK: %#v", source)
	}
}

func TestAdminManagedNodeLimitsQueuesRetryWithoutLimiterACK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixture := newManagedUserHTTPFixture(t, "alice")
	servers, err := fixture.repo.ListRemoteServers(ctx)
	if err != nil || len(servers) != 1 {
		t.Fatalf("resolve fixture server: servers=%v err=%v", servers, err)
	}
	server := servers[0]

	ack := false
	fakeAgent := &managedFakeAgent{
		limiterOK:  &ack,
		inboundTag: fixture.offer.InboundTag,
		token:      server.Token,
	}
	agentServer := httptest.NewServer(fakeAgent)
	t.Cleanup(agentServer.Close)
	agentURL, err := url.Parse(agentServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(agentURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.repo.UpdateRemoteServerHeartbeat(ctx, server.Token, host, ""); err != nil {
		t.Fatalf("point fixture server at fake Agent: %v", err)
	}
	if err := fixture.repo.UpdateRemoteServerListenPort(ctx, server.ID, port); err != nil {
		t.Fatalf("update fake Agent port: %v", err)
	}

	linkManagedHandlerCredentialForTest(t, fixture, "alice", "vless")
	baseline, err := fixture.repo.MarkUserInboundAccessSourceApplied(ctx, fixture.activation.Source.ID,
		fixture.activation.Source.Generation, storage.ManagedObservedActive, time.Now().UTC())
	if err != nil {
		t.Fatalf("mark baseline source applied: %v", err)
	}
	remote := managedRemoteWithCapabilities(fixture.repo, server.ID, managedReadyAgentCapabilities())
	handler := NewManagedNodesHandler(fixture.repo, remote, NewLimiterConfigPusher(fixture.repo, nil))
	response := httptest.NewRecorder()
	request := managedUserHTTPRequest(http.MethodPut, "/api/admin/users/alice/managed-nodes/1/limits", "owner",
		`{"speed_limit_override_mbps":12}`)
	request.SetPathValue("username", "alice")
	request.SetPathValue("id", fmt.Sprintf("%d", fixture.activation.Selection.ID))

	handler.HandleAdminManagedNodeLimits(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusAccepted, response.Body.String())
	}
	var payload struct {
		Success      bool   `json:"success"`
		Pending      bool   `json:"pending"`
		PendingError string `json:"pending_error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
	if !payload.Success || !payload.Pending || !strings.Contains(payload.PendingError, "not acknowledged") {
		t.Fatalf("response did not report pending limiter ACK: %#v", payload)
	}

	selection, err := fixture.repo.GetUserNodeSelection(ctx, fixture.activation.Selection.ID)
	if err != nil {
		t.Fatalf("reload selection: %v", err)
	}
	if selection.SpeedLimitOverrideMbps == nil || *selection.SpeedLimitOverrideMbps != 12 {
		t.Fatalf("persisted limit override=%v, want 12", selection.SpeedLimitOverrideMbps)
	}
	source, err := fixture.repo.GetUserInboundAccessSource(ctx, fixture.activation.Source.ID)
	if err != nil {
		t.Fatalf("reload source: %v", err)
	}
	if source.Generation != baseline.Generation+1 || source.AppliedGeneration != baseline.AppliedGeneration ||
		source.LastError == "" || source.NextRetryAt == nil {
		t.Fatalf("failed ACK did not retain a retryable generation: %#v", source)
	}
	pending, err := fixture.repo.ListPendingUserInboundAccessSources(ctx, source.NextRetryAt.Add(time.Millisecond), 10, server.ID)
	if err != nil {
		t.Fatalf("list retryable sources: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != source.ID {
		t.Fatalf("source is not eligible for reconciler retry: %#v", pending)
	}

	fakeAgent.mu.Lock()
	calls := append([]string(nil), fakeAgent.calls...)
	limiter := fakeAgent.limiter
	fakeAgent.mu.Unlock()
	if len(calls) != 1 || calls[0] != "limiter" {
		t.Fatalf("Agent mutations without limiter ACK=%v, want limiter only", calls)
	}
	userLimit := findLimiterUser(t, []WSLimiterConfigPayload{limiter}, fixture.offer.InboundTag, "alice__"+fixture.offer.InboundTag)
	if userLimit.SpeedLimit != 1_500_000 {
		t.Fatalf("pushed speed limit=%d want=1500000", userLimit.SpeedLimit)
	}
}
