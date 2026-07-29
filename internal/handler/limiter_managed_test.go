package handler

import (
	"context"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

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
