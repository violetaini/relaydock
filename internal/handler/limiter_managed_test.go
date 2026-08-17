package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type delayedLimiterSnapshotAgent struct {
	mu            sync.Mutex
	firstStarted  chan struct{}
	secondStarted chan struct{}
	releaseFirst  chan struct{}
	received      int
	applied       []uint64
}

func newDelayedLimiterSnapshotAgent() *delayedLimiterSnapshotAgent {
	return &delayedLimiterSnapshotAgent{
		firstStarted: make(chan struct{}), secondStarted: make(chan struct{}), releaseFirst: make(chan struct{}),
	}
}

func (a *delayedLimiterSnapshotAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "inbounds": []map[string]interface{}{{"tag": "serialized-in"}},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
		var payload WSLimiterConfigPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var speed uint64
		for _, user := range payload.Users {
			if user.Email == "alice__serialized-in" {
				speed = user.SpeedLimit
				break
			}
		}
		a.mu.Lock()
		a.received++
		requestNumber := a.received
		if requestNumber == 1 {
			close(a.firstStarted)
		}
		if requestNumber == 2 {
			close(a.secondStarted)
		}
		a.mu.Unlock()
		if requestNumber == 1 {
			<-a.releaseFirst
		}
		a.mu.Lock()
		a.applied = append(a.applied, speed)
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	default:
		http.NotFound(w, r)
	}
}

func (a *delayedLimiterSnapshotAgent) appliedSnapshot() []uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]uint64(nil), a.applied...)
}

func newSerializedLimiterPushFixture(t *testing.T) (*storage.TrafficRepository, *storage.RemoteServer, *LimiterConfigPusher, *delayedLimiterSnapshotAgent) {
	t.Helper()
	ctx := context.Background()
	agentState := newDelayedLimiterSnapshotAgent()
	agent := httptest.NewServer(agentState)
	t.Cleanup(agent.Close)
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "serialized-edge", Token: "serialized-token", IPAddress: "127.0.0.1",
		ListenPort: remoteAgentTestPort(t, agent.URL), XrayMode: "embedded",
		ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "serialized", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "serialized-in",
		ClashConfig: `{"name":"serialized","type":"vless","server":"127.0.0.1","port":443,"uuid":"owner-uuid"}`,
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "serialized", CycleDays: 30, Nodes: []int64{node.ID}, SpeedLimitMbps: 100, DeviceLimit: 5,
	})
	if err != nil {
		t.Fatalf("create package: %v", err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign package: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "serialized-in", Protocol: "vless",
		CredentialJSON: `{"id":"alice-uuid","email":"alice__serialized-in"}`,
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	oldSpeed := float64(8)
	if err := repo.UpdateUserLimitOverrides(ctx, "alice", &oldSpeed, nil); err != nil {
		t.Fatalf("set old speed: %v", err)
	}
	return repo, server, NewLimiterConfigPusher(repo, nil), agentState
}

func TestLimiterPushSerializesBuildThroughDeliveryPerServer(t *testing.T) {
	testCases := []struct {
		name   string
		leased bool
		push   func(context.Context, *LimiterConfigPusher, int64) error
	}{
		{name: "normal", push: func(ctx context.Context, p *LimiterConfigPusher, serverID int64) error {
			p.PushToServer(ctx, serverID)
			return nil
		}},
		{name: "checked", push: func(ctx context.Context, p *LimiterConfigPusher, serverID int64) error {
			return p.PushToServerChecked(ctx, serverID)
		}},
		{name: "checked_leased", leased: true, push: func(ctx context.Context, p *LimiterConfigPusher, serverID int64) error {
			return p.pushToServerCheckedLeased(ctx, serverID)
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repo, server, pusher, agent := newSerializedLimiterPushFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pushCtx := ctx
			releaseLease := func() {}
			if testCase.leased {
				var err error
				pushCtx, releaseLease, err = repo.AcquireRemoteServerExclusiveMutationLease(ctx, server.ID)
				if err != nil {
					t.Fatalf("acquire outer lease: %v", err)
				}
			}
			defer releaseLease()

			firstDone := make(chan error, 1)
			go func() { firstDone <- testCase.push(pushCtx, pusher, server.ID) }()
			select {
			case <-agent.firstStarted:
			case <-ctx.Done():
				t.Fatalf("first limiter snapshot did not arrive: %v", ctx.Err())
			}
			newSpeed := float64(16)
			if err := repo.UpdateUserLimitOverrides(ctx, "alice", &newSpeed, nil); err != nil {
				t.Fatalf("set new speed: %v", err)
			}
			secondDone := make(chan error, 1)
			go func() { secondDone <- testCase.push(pushCtx, pusher, server.ID) }()

			secondArrivedEarly := false
			select {
			case <-agent.secondStarted:
				secondArrivedEarly = true
			case <-time.After(150 * time.Millisecond):
			}
			close(agent.releaseFirst)
			for index, done := range []<-chan error{firstDone, secondDone} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("push %d: %v", index+1, err)
					}
				case <-ctx.Done():
					t.Fatalf("push %d did not complete: %v", index+1, ctx.Err())
				}
			}
			if secondArrivedEarly {
				t.Fatal("new limiter snapshot reached the Agent while the old snapshot was still pending")
			}
			if applied := agent.appliedSnapshot(); len(applied) != 2 || applied[0] != 1_000_000 || applied[1] != 2_000_000 {
				t.Fatalf("applied limiter snapshots=%v, want old then new with new final", applied)
			}
		})
	}
}

func TestLimiterSkipsOrphanManagedWireGuardResourceWithoutDesiredOrNode(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	server := &storage.RemoteServer{
		Name: "orphan-wg-edge", Token: "token", IPAddress: "203.0.113.40",
		XrayMode: "embedded", Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	resource, err := repo.CreateManagedInboundResource(ctx, storage.ManagedInboundResource{
		ServerID: server.ID, DisplayName: "orphan", Protocol: "wireguard",
		InboundTag: "orphan-wg", MutationID: "orphan-generation",
		EndpointHost: "203.0.113.40", EndpointPort: 51820,
		PublicMetadataJSON: []byte(`{}`), CreatedBy: "legacy-sync",
	})
	if err != nil {
		t.Fatalf("create orphan resource: %v", err)
	}

	snapshots, err := NewLimiterConfigPusher(repo, nil).BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("orphan resource blocked limiter build: %v", err)
	}
	if len(snapshots) != 0 {
		t.Fatalf("orphan resource produced limiter snapshots: %#v", snapshots)
	}
	if _, err := repo.GetWireGuardProbePeer(ctx, resource.ID); !errors.Is(err, storage.ErrWireGuardProbePeerNotFound) {
		t.Fatalf("orphan resource manufactured a probe identity: %v", err)
	}
}

func findLimiterUser(t *testing.T, configs []WSLimiterConfigPayload, tag, email string) WSUserLimitInfo {
	t.Helper()
	for _, config := range configs {
		if config.InboundTag != tag {
			continue
		}
		for _, user := range config.Users {
			if user.Email == email {
				return user
			}
		}
	}
	t.Fatalf("limiter user %s/%s not found in %#v", tag, email, configs)
	return WSUserLimitInfo{}
}

func TestManagedSelectionLimitsFeedLimiterAndDormantCredentialIsCleared(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "edge-1", Token: "token", IPAddress: "203.0.113.10",
		XrayMode: "embedded", Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "managed", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"managed","type":"vless","server":"203.0.113.10","port":443,"uuid":"owner-uuid"}`,
	})
	if err != nil {
		t.Fatalf("create managed node: %v", err)
	}
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "owner")
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	grant, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveNodes: 1,
		SpeedLimitMbps: 50, ConnectionLimit: 4, BillingMode: storage.ManagedBillingDownload,
		ResetPolicy: storage.ManagedResetNone, ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "owner",
	})
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate selection: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "vless-in", Protocol: "vless",
		CredentialJSON: `{"id":"alice-uuid","email":"alice__vless-in"}`,
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}

	pusher := NewLimiterConfigPusher(repo, nil)
	configs, err := pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build grant limiter: %v", err)
	}
	userLimit := findLimiterUser(t, configs, "vless-in", "alice__vless-in")
	if userLimit.SpeedLimit != 6_250_000 || userLimit.DeviceLimit != 4 || userLimit.ConnGroup != connGroupKey("alice", node.ID) {
		t.Fatalf("grant limits not applied: %#v", userLimit)
	}

	zeroSpeed, twoConnections := float64(0), 2
	if _, err := repo.UpdateUserNodeSelectionLimits(ctx, activation.Selection.ID, &zeroSpeed, &twoConnections, nil, "owner"); err != nil {
		t.Fatalf("update selection override: %v", err)
	}
	configs, err = pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build override limiter: %v", err)
	}
	userLimit = findLimiterUser(t, configs, "vless-in", "alice__vless-in")
	if userLimit.SpeedLimit != 0 || userLimit.DeviceLimit != 2 {
		t.Fatalf("selection override not applied: %#v", userLimit)
	}

	if _, err := repo.UpdateUserNodeSelectionLimits(ctx, activation.Selection.ID, nil, nil, nil, "owner"); err != nil {
		t.Fatalf("clear selection override: %v", err)
	}
	globalSpeed, globalConnections := float64(12), 7
	if err := repo.UpdateUserLimitOverrides(ctx, "alice", &globalSpeed, &globalConnections); err != nil {
		t.Fatalf("set user global limits: %v", err)
	}
	grant.SpeedLimitMbps, grant.ConnectionLimit = 0, 0
	grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "owner")
	if err != nil {
		t.Fatalf("clear grant limits: %v", err)
	}
	configs, err = pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build global fallback limiter: %v", err)
	}
	userLimit = findLimiterUser(t, configs, "vless-in", "alice__vless-in")
	if userLimit.SpeedLimit != 1_500_000 || userLimit.DeviceLimit != 7 {
		t.Fatalf("user global fallback not applied: %#v", userLimit)
	}

	if _, err := repo.DeactivateUserNodeSelection(ctx, "alice", activation.Selection.ID, "alice",
		storage.ManagedSuspendUserDisabled, now.Add(time.Minute)); err != nil {
		t.Fatalf("deactivate selection: %v", err)
	}
	configs, err = pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build dormant limiter: %v", err)
	}
	if len(configs) != 1 || configs[0].InboundTag != "vless-in" || len(configs[0].Users) != 0 {
		t.Fatalf("dormant managed credential was not cleared: %#v", configs)
	}
}

func TestMergeManagedLimiterLimitUsesMostRestrictivePositiveValue(t *testing.T) {
	got := mergeManagedLimiterLimit(
		managedLimiterLimit{nodeID: 20, speedMbps: 0, connectionLimit: 8},
		managedLimiterLimit{nodeID: 10, speedMbps: 25, connectionLimit: 0},
	)
	if got.nodeID != 10 || got.speedMbps != 25 || got.connectionLimit != 8 {
		t.Fatalf("unexpected merged managed limit: %#v", got)
	}
}

func TestLegacyPackageLimitRemainsIndependentFromManagedLimits(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{Name: "edge-1", Token: "token", IPAddress: "203.0.113.10", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create remote server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "package-node", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"package-node","type":"vless","server":"203.0.113.10","port":443,"uuid":"owner-uuid"}`,
	})
	if err != nil {
		t.Fatalf("create package node: %v", err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "legacy", Nodes: []int64{node.ID}, SpeedLimitMbps: 20, DeviceLimit: 3,
	})
	if err != nil {
		t.Fatalf("create package: %v", err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign package: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "vless-in", Protocol: "vless",
		CredentialJSON: `{"id":"alice-uuid","email":"alice__vless-in"}`,
	}); err != nil {
		t.Fatalf("save package credential: %v", err)
	}

	configs, err := NewLimiterConfigPusher(repo, nil).BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build package limiter: %v", err)
	}
	userLimit := findLimiterUser(t, configs, "vless-in", "alice__vless-in")
	if userLimit.SpeedLimit != 2_500_000 || userLimit.DeviceLimit != 3 {
		t.Fatalf("legacy package limits changed: %#v", userLimit)
	}
}
