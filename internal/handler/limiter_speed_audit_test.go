package handler

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestBuildLimiterConfigSamePortMultipleNodesAndPackages(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	createManagedSecurityTestUser(t, repo, "bob", storage.RoleUser)

	server := &storage.RemoteServer{
		Name: "edge-shared-port", Token: "tok-shared-port", IPAddress: "127.0.0.1",
		ListenPort: 19001, XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush,
		Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}

	nodeA, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "shared-node-a", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "shared-443", NodeType: "physical",
		ClashConfig: `{"name":"a","type":"vless","server":"127.0.0.1","port":443,"uuid":"u1"}`,
	})
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	nodeB, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "shared-node-b", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "shared-443", NodeType: "physical",
		ClashConfig: `{"name":"b","type":"vless","server":"127.0.0.1","port":443,"uuid":"u2"}`,
	})
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}

	pkgA, err := repo.CreatePackage(ctx, storage.Package{
		Name: "pkg-a", CycleDays: 30, Nodes: []int64{nodeA.ID},
		NodeSpeedLimits:  map[int64]float64{nodeA.ID: 20},
		NodeDeviceLimits: map[int64]int{nodeA.ID: 3},
	})
	if err != nil {
		t.Fatalf("create pkgA: %v", err)
	}
	pkgB, err := repo.CreatePackage(ctx, storage.Package{
		Name: "pkg-b", CycleDays: 30, Nodes: []int64{nodeB.ID},
		NodeSpeedLimits:  map[int64]float64{nodeB.ID: 5},
		NodeDeviceLimits: map[int64]int{nodeB.ID: 7},
	})
	if err != nil {
		t.Fatalf("create pkgB: %v", err)
	}

	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", pkgA, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign alice: %v", err)
	}
	if err := repo.AssignPackageToUser(ctx, "bob", pkgB, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign bob: %v", err)
	}
	for _, uname := range []string{"alice", "bob"} {
		if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
			Username: uname, ServerID: server.ID, InboundTag: "shared-443", Protocol: "vless",
			CredentialJSON: `{"id":"` + uname + `-uuid","email":"` + uname + `__shared-443"}`,
		}); err != nil {
			t.Fatalf("save inbound config %s: %v", uname, err)
		}
	}

	pusher := NewLimiterConfigPusher(repo, nil)
	payloads, err := pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("BuildLimiterConfigForServer: %v", err)
	}
	p, ok := findForwardingLimiterPayload(payloads, "shared-443")
	if !ok {
		t.Fatalf("missing payload for shared-443: %+v", payloads)
	}
	got := make(map[string]WSUserLimitInfo, len(p.Users))
	for _, u := range p.Users {
		got[u.Email] = u
	}
	if got["alice__shared-443"].SpeedLimit != 2_500_000 || got["alice__shared-443"].DeviceLimit != 3 {
		t.Fatalf("alice__shared-443=%+v want speed=2500000 dev=3", got["alice__shared-443"])
	}
	if got["bob__shared-443"].SpeedLimit != 625_000 || got["bob__shared-443"].DeviceLimit != 7 {
		t.Fatalf("bob__shared-443=%+v want speed=625000 dev=7", got["bob__shared-443"])
	}
}

func TestBuildLimiterConfigSamePortMultipleRoutedSubaccounts(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	createManagedSecurityTestUser(t, repo, "bob", storage.RoleUser)

	server := &storage.RemoteServer{
		Name: "edge-routed-same-port", Token: "tok-routed-same", IPAddress: "127.0.0.1",
		ListenPort: 19002, XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush,
		Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}

	physA, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "phys-a", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "shared-443",
		ClashConfig: `{"name":"pa","type":"vless","server":"127.0.0.1","port":443,"uuid":"u1"}`,
	})
	if err != nil {
		t.Fatalf("create physA: %v", err)
	}
	physB, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "phys-b", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "shared-443",
		ClashConfig: `{"name":"pb","type":"vless","server":"127.0.0.1","port":443,"uuid":"u2"}`,
	})
	if err != nil {
		t.Fatalf("create physB: %v", err)
	}
	routedA, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "routed-a", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "shared-443",
		ClashConfig: `{"name":"ra","type":"vless","server":"127.0.0.1","port":443,"uuid":"r1"}`,
	})
	if err != nil {
		t.Fatalf("create routedA: %v", err)
	}
	if err := repo.MarkNodeAsRouted(ctx, routedA.ID, "out-ra", physA.ID); err != nil {
		t.Fatalf("mark routedA: %v", err)
	}
	routedB, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "routed-b", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "shared-443",
		ClashConfig: `{"name":"rb","type":"vless","server":"127.0.0.1","port":443,"uuid":"r2"}`,
	})
	if err != nil {
		t.Fatalf("create routedB: %v", err)
	}
	if err := repo.MarkNodeAsRouted(ctx, routedB.ID, "out-rb", physB.ID); err != nil {
		t.Fatalf("mark routedB: %v", err)
	}

	pkgA, err := repo.CreatePackage(ctx, storage.Package{
		Name: "pkg-ra", CycleDays: 30, Nodes: []int64{routedA.ID},
		NodeSpeedLimits: map[int64]float64{routedA.ID: 8},
	})
	if err != nil {
		t.Fatalf("create pkgA: %v", err)
	}
	pkgB, err := repo.CreatePackage(ctx, storage.Package{
		Name: "pkg-rb", CycleDays: 30, Nodes: []int64{routedB.ID},
		NodeSpeedLimits: map[int64]float64{routedB.ID: 3},
	})
	if err != nil {
		t.Fatalf("create pkgB: %v", err)
	}

	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", pkgA, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign alice: %v", err)
	}
	if err := repo.AssignPackageToUser(ctx, "bob", pkgB, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign bob: %v", err)
	}
	if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username: "alice", RoutedNodeID: routedA.ID, Email: "alice__ra",
		CredentialJSON: `{"id":"ra-uuid","email":"alice__ra"}`, IsActive: true,
	}); err != nil {
		t.Fatalf("upsert alice subaccount: %v", err)
	}
	if _, err := repo.UpsertUserSubaccount(ctx, storage.UserSubaccount{
		Username: "bob", RoutedNodeID: routedB.ID, Email: "bob__rb",
		CredentialJSON: `{"id":"rb-uuid","email":"bob__rb"}`, IsActive: true,
	}); err != nil {
		t.Fatalf("upsert bob subaccount: %v", err)
	}

	pusher := NewLimiterConfigPusher(repo, nil)
	payloads, err := pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("BuildLimiterConfigForServer: %v", err)
	}
	p, ok := findForwardingLimiterPayload(payloads, "shared-443")
	if !ok {
		t.Fatalf("missing payload for shared-443: %+v", payloads)
	}
	got := make(map[string]WSUserLimitInfo, len(p.Users))
	for _, u := range p.Users {
		got[u.Email] = u
	}
	if got["alice__ra"].SpeedLimit != 1_000_000 {
		t.Fatalf("alice__ra speed=%d want 1000000 (8 Mbps)", got["alice__ra"].SpeedLimit)
	}
	if got["bob__rb"].SpeedLimit != 375_000 {
		t.Fatalf("bob__rb speed=%d want 375000 (3 Mbps)", got["bob__rb"].SpeedLimit)
	}
	if got["alice__ra"].ConnGroup == got["bob__rb"].ConnGroup {
		t.Fatalf("expected distinct ConnGroup per user/parent, got both %q", got["alice__ra"].ConnGroup)
	}
}

func TestBuildLimiterConfigSameServerDifferentPortsForSameUser(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	server := &storage.RemoteServer{
		Name: "edge-multi-port", Token: "tok-multi-port", IPAddress: "127.0.0.1",
		ListenPort: 19003, XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush,
		Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	node1, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "p443", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "in-443", NodeType: "physical",
		ClashConfig: `{"name":"p443","type":"vless","server":"127.0.0.1","port":443,"uuid":"u1"}`,
	})
	if err != nil {
		t.Fatalf("create node1: %v", err)
	}
	node2, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "p8443", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "in-8443", NodeType: "physical",
		ClashConfig: `{"name":"p8443","type":"vless","server":"127.0.0.1","port":8443,"uuid":"u2"}`,
	})
	if err != nil {
		t.Fatalf("create node2: %v", err)
	}

	pkgID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "multi-port", CycleDays: 30, Nodes: []int64{node1.ID, node2.ID},
		NodeSpeedLimits: map[int64]float64{node1.ID: 20, node2.ID: 50},
	})
	if err != nil {
		t.Fatalf("create package: %v", err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", pkgID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign package: %v", err)
	}
	// User-specific override on node2 overrides package limit on port 8443 without touching port 443.
	if err := repo.UpdateUserNodeLimits(ctx, "alice", map[int64]float64{node2.ID: 12}, nil); err != nil {
		t.Fatalf("update user node limits: %v", err)
	}
	for _, tag := range []string{"in-443", "in-8443"} {
		if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
			Username: "alice", ServerID: server.ID, InboundTag: tag, Protocol: "vless",
			CredentialJSON: `{"id":"alice-uuid","email":"alice__` + tag + `"}`,
		}); err != nil {
			t.Fatalf("save inbound config %s: %v", tag, err)
		}
	}

	pusher := NewLimiterConfigPusher(repo, nil)
	payloads, err := pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("BuildLimiterConfigForServer: %v", err)
	}
	p443, ok := findForwardingLimiterPayload(payloads, "in-443")
	if !ok || len(p443.Users) != 1 || p443.Users[0].SpeedLimit != 2_500_000 {
		t.Fatalf("in-443 payload=%+v ok=%t want 2500000 B/s", p443, ok)
	}
	p8443, ok := findForwardingLimiterPayload(payloads, "in-8443")
	if !ok || len(p8443.Users) != 1 || p8443.Users[0].SpeedLimit != 1_500_000 {
		t.Fatalf("in-8443 payload=%+v ok=%t want 1500000 B/s", p8443, ok)
	}
}

func TestPushToAllServersIncludesForwardingEntryServerForPackage(t *testing.T) {
	fixture := newForwardingHandlerFixture(t)
	ctx := context.Background()
	setForwardingFixtureSpeed(t, &fixture, 40)

	agentState := &forwardingLimiterTestAgent{capable: true, ack: true}
	agent := httptest.NewServer(agentState)
	t.Cleanup(agent.Close)
	attachForwardingLimiterTestAgent(t, &fixture, agent)

	if err := fixture.handler.deployForward(ctx, fixture.forward); err != nil {
		t.Fatalf("deploy forward: %v", err)
	}
	pusher := NewLimiterConfigPusher(fixture.repo, nil)
	pusher.httpClient = agent.Client()
	pusher.httpClient.Timeout = 100 * time.Millisecond

	// 1. User with forwarding rule only (no Xray UserInboundConfig on entry) still gets pushed by PushToAllServersForUser.
	beforeUser := len(agentState.snapshot())
	pusher.PushToAllServersForUser(ctx, "alice")
	afterUser := agentState.snapshot()
	if len(afterUser) <= beforeUser {
		t.Fatalf("expected PushToAllServersForUser to push forwarding entry server (before=%d after=%d)", beforeUser, len(afterUser))
	}
	userPayload, ok := findForwardingLimiterPayload(afterUser[beforeUser:], fixture.forward.Hops[0].ResourceTag)
	if !ok || !userPayload.InboundSharedLimit || userPayload.NodeLimit != 5_000_000 {
		t.Fatalf("PushToAllServersForUser forwarding payload=%+v ok=%t want 5000000 B/s", userPayload, ok)
	}

	// 2. Package-authorized user with a forwarding rule also gets entry server pushed by PushToAllServersForPackage.
	if err := fixture.repo.CreateUser(ctx, "bob", "bob@example.test", "Bob", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	billingMode := storage.ManagedBillingBoth
	pkgID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "fwd-pkg", CycleDays: 30, Nodes: []int64{fixture.nodeID},
		ForwardingGrants: []storage.PackageForwardingGrant{{
			TunnelID: fixture.grant.TunnelID, MaxActiveForwards: 1, PerForwardSpeedMbps: 40,
			BillingModeOverride: &billingMode,
		}},
	})
	if err != nil {
		t.Fatalf("create package: %v", err)
	}
	now := time.Now().UTC()
	if err := fixture.repo.AssignPackageToUser(ctx, "bob", pkgID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatalf("assign package: %v", err)
	}
	grants, err := fixture.repo.ListUserTunnelGrants(ctx, "bob")
	if err != nil || len(grants) == 0 {
		t.Fatalf("list package grants=%+v err=%v", grants, err)
	}
	expires := now.Add(time.Hour)
	bobFwd, err := fixture.repo.CreateUserForward(ctx, storage.CreateUserForwardInput{
		Username: "bob", Name: "bob-fwd", GrantPublicID: grants[0].PublicID,
		TargetNodeID: fixture.nodeID, TargetHost: fixture.forward.TargetHost, TargetPort: fixture.forward.TargetPort,
		EffectiveExpiresAt: &expires, Actor: "bob",
	})
	if err != nil {
		t.Fatalf("create bob forward: %v", err)
	}

	beforePkg := len(agentState.snapshot())
	pusher.PushToAllServersForPackage(ctx, pkgID)

	afterPkg := agentState.snapshot()
	if len(afterPkg) <= beforePkg {
		t.Fatalf("expected PushToAllServersForPackage to push forwarding entry server (before=%d after=%d)", beforePkg, len(afterPkg))
	}
	payload, ok := findForwardingLimiterPayload(afterPkg[beforePkg:], bobFwd.Hops[0].ResourceTag)
	if !ok || !payload.InboundSharedLimit || payload.NodeLimit != 5_000_000 {
		t.Fatalf("pushed forwarding payload=%+v ok=%t want 5000000 B/s (40 Mbps)", payload, ok)
	}
}
