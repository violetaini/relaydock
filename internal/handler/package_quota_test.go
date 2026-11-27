package handler

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestEvaluatePackageQuotaStateThreeTiersAndPartialTiers(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "quota.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()

	if err := repo.CreateUser(ctx, "owner", "owner@example.test", "Owner", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser owner: %v", err)
	}
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	server := &storage.RemoteServer{
		Name: "edge-hk", Token: "edge-hk-token", IPAddress: "127.0.0.1",
		ListenPort: 2222, XrayMode: "embedded",
		ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if _, err := repo.UpdateRemoteServerXrayStatus(ctx, server.ID, true, "test"); err != nil {
		t.Fatalf("UpdateRemoteServerXrayStatus: %v", err)
	}
	server2 := &storage.RemoteServer{
		Name: "edge-jp", Token: "edge-jp-token", IPAddress: "127.0.0.2",
		ListenPort: 2223, XrayMode: "embedded",
		ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server2); err != nil {
		t.Fatalf("CreateRemoteServer2: %v", err)
	}
	if _, err := repo.UpdateRemoteServerXrayStatus(ctx, server2.ID, true, "test"); err != nil {
		t.Fatalf("UpdateRemoteServerXrayStatus2: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "hk-node", Protocol: "vless",
		OriginalServer: server.Name, InboundTag: "in-hk", NodeType: "physical", Enabled: true,
		ClashConfig: `{"name":"hk-node","type":"vless","server":"127.0.0.1","port":443,"uuid":"owner"}`,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	tunnel, err := repo.CreateTunnelTemplate(ctx, storage.TunnelTemplate{
		Name: "hk-fwd", State: storage.TunnelStateActive,
		BillingMode: storage.ManagedBillingDownload, TrafficMultiplierMilli: 1000,
		CreatedBy: "owner",
		Hops:      []storage.TunnelTemplateHop{{ServerID: server.ID}, {ServerID: server2.ID}},
	})
	if err != nil {
		t.Fatalf("CreateTunnelTemplate: %v", err)
	}

	const gb = float64(1024 * 1024 * 1024)
	both := storage.ManagedBillingBoth
	pkgID, err := repo.CreatePackage(ctx, storage.Package{
		Name:                           "tiered",
		TrafficLimitGB:                 1000.0 / gb, // 1000 bytes total
		NodeModuleTrafficLimitGB:       600.0 / gb,  // 600 bytes node module
		ServerModuleTrafficLimitGB:     500.0 / gb,  // 500 bytes server module
		ForwardingModuleTrafficLimitGB: 500.0 / gb,  // 500 bytes forwarding module
		CycleDays:                      30,
		ResetDay:                       1,
		Nodes:                          []int64{node.ID},
		ServerGrants:                   []storage.PackageServerGrant{{ServerID: server.ID, BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone}},
		ForwardingGrants:               []storage.PackageForwardingGrant{{TunnelID: tunnel.ID, MaxActiveForwards: 2, BillingModeOverride: &both}},
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	now := time.Now().UTC()
	if err := repo.AssignPackageToUser(ctx, "alice", pkgID, now.Add(-time.Hour), now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatalf("AssignPackageToUser: %v", err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	pkg, err := repo.GetPackage(ctx, pkgID)
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}

	// Case 1: Node module exceeds 600 bytes (650 bytes), package total 650 < 1000.
	// Only NodeModuleOver should be true; ServerModuleOver and ForwardingModuleOver remain false.
	for _, sample := range []storage.UserTrafficSample{
		{Email: "alice__in-hk", Username: "alice", Uplink: 0, Downlink: 0, BillingMultiplier: 1},
		{Email: "alice__in-hk", Username: "alice", Uplink: 300, Downlink: 350, BillingMultiplier: 1},
	} {
		if err := repo.UpsertUserTrafficBatch(ctx, server.ID, []storage.UserTrafficSample{sample}, false); err != nil {
			t.Fatalf("UpsertUserTrafficBatch: %v", err)
		}
	}
	state, err := evaluatePackageQuotaState(ctx, repo, &user, pkg)
	if err != nil {
		t.Fatalf("evaluatePackageQuotaState: %v", err)
	}
	if !state.NodeModuleOver || state.PackageOver || state.ServerModuleOver || state.ForwardingModuleOver {
		t.Fatalf("unexpected state when only node module exceeded: %+v", state)
	}

	// Case 2: Add forwarding usage 400 bytes -> total 650 + 400 = 1050 >= 1000 (PackageOver = true).
	// All modules must now be blocked globally!
	grants, err := repo.ListUserTunnelGrants(ctx, "alice")
	if err != nil || len(grants) != 1 {
		t.Fatalf("ListUserTunnelGrants: %v len=%d", err, len(grants))
	}
	expires := now.Add(time.Hour)
	fwd, err := repo.CreateUserForward(ctx, storage.CreateUserForwardInput{
		Username: "alice", Name: "f1", GrantPublicID: grants[0].PublicID,
		TargetNodeID: node.ID, TargetHost: "1.1.1.1", TargetPort: 443,
		EffectiveExpiresAt: &expires, Actor: "alice",
	})
	if err != nil {
		t.Fatalf("CreateUserForward: %v", err)
	}
	entry := fwd.Hops[0]
	if err := repo.UpsertNodeTraffic(ctx, entry.ServerID, entry.ResourceTag, "inbound", 0, 0, false); err != nil {
		t.Fatalf("UpsertNodeTraffic baseline: %v", err)
	}
	if err := repo.UpsertNodeTraffic(ctx, entry.ServerID, entry.ResourceTag, "inbound", 200, 200, false); err != nil {
		t.Fatalf("UpsertNodeTraffic delta: %v", err)
	}
	if err := repo.SyncUserForwardUsage(ctx); err != nil {
		t.Fatalf("SyncUserForwardUsage: %v", err)
	}
	state, err = evaluatePackageQuotaState(ctx, repo, &user, pkg)
	if err != nil {
		t.Fatalf("evaluatePackageQuotaState: %v", err)
	}
	if !state.PackageOver || !state.NodeModuleOver || !state.ServerModuleOver || !state.ForwardingModuleOver {
		t.Fatalf("expected all modules over when package total exceeded: %+v", state)
	}

	// Verify effectiveManagedGrantState & effectiveTunnelGrantState both report over_limit
	serverGrants, err := repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(serverGrants) != 1 {
		t.Fatalf("ListUserServerGrants: %v len=%d", err, len(serverGrants))
	}
	if got := effectiveManagedGrantState(ctx, repo, user, serverGrants[0], 0, now, nil, nil); got != storage.ManagedGrantOverLimit {
		t.Fatalf("effectiveManagedGrantState=%s want=%s", got, storage.ManagedGrantOverLimit)
	}
	tunnelGrants, err := repo.ListUserTunnelGrants(ctx, "alice")
	if err != nil || len(tunnelGrants) != 1 {
		t.Fatalf("ListUserTunnelGrants: %v", err)
	}
	if got := effectiveTunnelGrantState(ctx, repo, user, tunnelGrants[0], storage.TunnelStateActive, now, nil, nil); got != "over_limit" {
		t.Fatalf("effectiveTunnelGrantState=%s want=over_limit", got)
	}
}
