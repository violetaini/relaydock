package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestSubscribeSpeedAndDeviceLimitsEnforcedInLimiter(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	server := &storage.RemoteServer{
		Name: "sub-limit-edge", Token: "sub-limit-token", IPAddress: "203.0.113.50",
		XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	phys, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "phys-sub", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "phys-in",
		ClashConfig: `{"name":"phys-sub","type":"vless","server":"203.0.113.50","port":443,"uuid":"owner"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
		Name: "Sub-Speed", Type: storage.SubscribeTypeCreate, Filename: "sub_speed.yaml",
		CreatedBy: "owner", SelectedNodeIDs: []int64{phys.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, storage.Package{
		Name:                  "sub-speed-pkg",
		CycleDays:             30,
		SubscribeFileIDs:      []int64{sub.ID},
		SubscribeSpeedLimits:  map[int64]float64{sub.ID: 20}, // 20 Mbps -> 2500000 B/s
		SubscribeDeviceLimits: map[int64]int{sub.ID: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", pkgID, now.Add(-time.Hour), now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: phys.InboundTag, Protocol: "vless",
		CredentialJSON: `{"id":"alice","email":"alice__phys-in"}`,
	}); err != nil {
		t.Fatal(err)
	}

	pusher := NewLimiterConfigPusher(repo, nil)
	payloads, err := pusher.BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("BuildLimiterConfigForServer: %v", err)
	}
	if len(payloads) != 1 || len(payloads[0].Users) != 1 {
		t.Fatalf("unexpected limiter payloads: %+v", payloads)
	}
	u := payloads[0].Users[0]
	if u.SpeedLimit != 2500000 || u.DeviceLimit != 3 || u.Denied {
		t.Fatalf("unexpected user limit info = %+v, want SpeedLimit=2500000 DeviceLimit=3 Denied=false", u)
	}
}

func TestSubscriptionQuotaExhaustionRefreshesLimiterAndStopsSubscriptions(t *testing.T) {
	ctx := context.Background()
	agentState := &nodeQuotaAgent{inboundTags: []string{"sub-in-a", "sub-in-b"}}
	agent := httptest.NewServer(agentState)
	t.Cleanup(agent.Close)

	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	server := &storage.RemoteServer{
		Name: "sub-enforce-edge", Token: "sub-enforce-token", IPAddress: "127.0.0.1",
		ListenPort: remoteAgentTestPort(t, agent.URL), XrayMode: "embedded",
		ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	nodeA, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "sub-a", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "sub-in-a",
		ClashConfig: `{"name":"sub-a","type":"vless","server":"203.0.113.51","port":443,"uuid":"ADMIN-A"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "sub-b", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "sub-in-b",
		ClashConfig: `{"name":"sub-b","type":"vless","server":"203.0.113.51","port":444,"uuid":"ADMIN-B"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	subDir := t.TempDir()
	const subBodyA = "port: 7890\nproxies:\n  - name: sub-a\n    type: vless\n    server: 203.0.113.51\n    port: 443\n    uuid: ADMIN-A\n"
	const subBodyB = "port: 7890\nproxies:\n  - name: sub-b\n    type: vless\n    server: 203.0.113.51\n    port: 444\n    uuid: ADMIN-B\n"
	_ = os.WriteFile(filepath.Join(subDir, "sub_a.yaml"), []byte(subBodyA), 0600)
	_ = os.WriteFile(filepath.Join(subDir, "sub_b.yaml"), []byte(subBodyB), 0600)

	subA, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
		Name: "Sub-A", Type: storage.SubscribeTypeCreate, Filename: "sub_a.yaml",
		CreatedBy: "admin", SelectedNodeIDs: []int64{nodeA.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	subB, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
		Name: "Sub-B", Type: storage.SubscribeTypeCreate, Filename: "sub_b.yaml",
		CreatedBy: "admin", SelectedNodeIDs: []int64{nodeB.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Only subscription module + per-subscription quotas configured (no fixed Nodes, no PackageLimitGB).
	pkgID, err := repo.CreatePackage(ctx, storage.Package{
		Name:                          "sub-only-pkg",
		CycleDays:                     30,
		SubscribeModuleTrafficLimitGB: 500.0 / userTrafficLimitBytesPerGB,
		SubscribeFileIDs:              []int64{subA.ID, subB.ID},
		SubscribeTrafficLimits:        map[int64]float64{subA.ID: 200.0 / userTrafficLimitBytesPerGB},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", pkgID, now.Add(-time.Hour), now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	for _, n := range []storage.Node{nodeA, nodeB} {
		if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
			Username: "alice", ServerID: server.ID, InboundTag: n.InboundTag, Protocol: "vless",
			CredentialJSON: `{"id":"alice-secret","email":"alice__` + n.InboundTag + `"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}

	writeUsage := func(tag string, down int64) {
		if err := repo.UpsertUserTrafficBatch(ctx, server.ID, []storage.UserTrafficSample{{
			Email: "alice__" + tag, Username: "alice", Downlink: down, BillingMultiplier: 1,
		}}, false); err != nil {
			t.Fatal(err)
		}
	}
	writeUsage("sub-in-a", 0)
	writeUsage("sub-in-b", 0)
	writeUsage("sub-in-a", 250) // subA exhausted (250 >= 200), subB active (0)

	enforcer := NewTrafficLimitEnforcer(repo, nil, NewLimiterConfigPusher(repo, nil))
	enforcer.CheckAll(ctx)
	assertNodeQuotaRecords(t, agentState.recordsSince(0), map[string]bool{"sub-in-a": true, "sub-in-b": false})

	subHandler := NewSubscriptionHandlerConcrete(repo, subDir)
	fetchSub := func(file string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file, nil)
		req = req.WithContext(auth.ContextWithUsername(req.Context(), "alice"))
		rec := httptest.NewRecorder()
		subHandler.ServeHTTP(rec, req)
		return rec
	}

	// sub_a is over limit -> must stop immediately; sub_b still serves normally.
	if respA := fetchSub("sub_a.yaml"); respA.Code != http.StatusOK || !strings.Contains(respA.Body.String(), "流量已用尽") || strings.Contains(respA.Body.String(), "ADMIN-A") {
		t.Fatalf("exhausted sub_a was not stopped: code=%d body=%s", respA.Code, respA.Body.String())
	}
	if respB := fetchSub("sub_b.yaml"); respB.Code != http.StatusOK || !strings.Contains(respB.Body.String(), "ADMIN-B") {
		t.Fatalf("active sub_b should remain available: code=%d body=%s", respB.Code, respB.Body.String())
	}

	// Exhausting SubscribeModuleLimit (250 + 300 = 550 >= 500) must deny subB as well in limiter & subscriptions.
	offset := len(agentState.recordsSince(0))
	writeUsage("sub-in-b", 300)
	enforcer.CheckAll(ctx)
	assertNodeQuotaRecords(t, agentState.recordsSince(offset), map[string]bool{"sub-in-a": true, "sub-in-b": true})

	if respB := fetchSub("sub_b.yaml"); respB.Code != http.StatusOK || !strings.Contains(respB.Body.String(), "流量已用尽") || strings.Contains(respB.Body.String(), "ADMIN-B") {
		t.Fatalf("module-exhausted sub_b was not stopped: code=%d body=%s", respB.Code, respB.Body.String())
	}

	// PackageSubscribeHandler must also return 404 / no active nodes when all sub nodes are denied.
	pkgSubRec := httptest.NewRecorder()
	pkgSubReq := httptest.NewRequest(http.MethodGet, "/api/user/package-subscribe", nil)
	NewPackageSubscribeHandler(repo).ServeHTTP(pkgSubRec, pkgSubReq.WithContext(auth.ContextWithUsername(pkgSubReq.Context(), "alice")))
	if pkgSubRec.Code != http.StatusNotFound {
		t.Fatalf("package-subscribe when sub module over = %d (%s), want 404", pkgSubRec.Code, pkgSubRec.Body.String())
	}
}

func TestPackageUsedBytesUnionsNodesAndSubscribeOnlyNodesWithoutDoubleCounting(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	srv := &storage.RemoteServer{
		Name: "union-edge", Token: "tok-union", IPAddress: "203.0.113.52",
		XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, srv); err != nil {
		t.Fatal(err)
	}
	node1, _ := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "u-1", Protocol: "vless", Enabled: true,
		OriginalServer: srv.Name, InboundTag: "in-1", ClashConfig: `{}`,
	})
	node2, _ := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "u-2", Protocol: "vless", Enabled: true,
		OriginalServer: srv.Name, InboundTag: "in-2", ClashConfig: `{}`,
	})
	sub, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
		Name: "Union-Sub", Type: storage.SubscribeTypeCreate, Filename: "union.yaml",
		CreatedBy: "admin", SelectedNodeIDs: []int64{node1.ID, node2.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, storage.Package{
		Name:             "union-pkg",
		CycleDays:        30,
		TrafficLimitGB:   1000.0 / userTrafficLimitBytesPerGB, // 1000 bytes
		Nodes:            []int64{node1.ID},                   // overlaps sub on node1; node2 only in sub
		SubscribeFileIDs: []int64{sub.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", pkgID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}

	for _, s := range []storage.UserTrafficSample{
		{Email: "alice__in-1", Username: "alice", Downlink: 0, BillingMultiplier: 1},
		{Email: "alice__in-1", Username: "alice", Downlink: 400, BillingMultiplier: 1},
		{Email: "alice__in-2", Username: "alice", Downlink: 0, BillingMultiplier: 1},
		{Email: "alice__in-2", Username: "alice", Downlink: 300, BillingMultiplier: 1},
	} {
		if err := repo.UpsertUserTrafficBatch(ctx, srv.ID, []storage.UserTrafficSample{s}, false); err != nil {
			t.Fatal(err)
		}
	}

	user, _ := repo.GetUser(ctx, "alice")
	pkg, _ := repo.GetPackage(ctx, pkgID)
	state, err := evaluatePackageQuotaState(ctx, repo, &user, pkg)
	if err != nil {
		t.Fatal(err)
	}
	// Union must be 400 + 300 = 700 (not 1100 double count, not 400 missing node2).
	if state.PackageUsedBytes != 700 || state.PackageOver {
		t.Fatalf("unexpected union package quota state = %+v, want PackageUsedBytes=700 PackageOver=false", state)
	}

	// Add 300 bytes on node2 -> 400 + 600 = 1000 -> PackageOver = true.
	if err := repo.UpsertUserTrafficBatch(ctx, srv.ID, []storage.UserTrafficSample{
		{Email: "alice__in-2", Username: "alice", Downlink: 600, BillingMultiplier: 1},
	}, false); err != nil {
		t.Fatal(err)
	}
	state, err = evaluatePackageQuotaState(ctx, repo, &user, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if state.PackageUsedBytes != 1000 || !state.PackageOver || !state.SubscribeNodeDenied[node1.ID] || !state.SubscribeNodeDenied[node2.ID] {
		t.Fatalf("expected PackageOver=true at 1000 bytes, got %+v", state)
	}
}

func TestPackageExpiryAndDisabledUserImmediatelyStopAllContent(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	srv := &storage.RemoteServer{
		Name: "exp-edge", Token: "tok-exp", IPAddress: "203.0.113.53",
		XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, srv); err != nil {
		t.Fatal(err)
	}
	node, _ := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "exp-node", Protocol: "vless", Enabled: true,
		OriginalServer: srv.Name, InboundTag: "exp-in",
		ClashConfig: `{"name":"exp-node","type":"vless","server":"203.0.113.53","port":443,"uuid":"ADMIN-EXP"}`,
	})
	subDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(subDir, "pkg_sub.yaml"), []byte("proxies:\n  - name: exp\n    type: ss\n    server: 1.1.1.1\n    port: 443\n    password: p\n    cipher: aes-128-gcm\n"), 0600)
	sub, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
		Name: "Pkg-Bundle-Sub", Type: storage.SubscribeTypeCreate, Filename: "pkg_sub.yaml",
		CreatedBy: "admin", SelectedNodeIDs: []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	pkgID, err := repo.CreatePackage(ctx, storage.Package{
		Name:             "exp-pkg",
		CycleDays:        30,
		Nodes:            []int64{node.ID},
		SubscribeFileIDs: []int64{sub.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Assign an already-expired package directly without waiting for background enforcer.
	past := time.Now().UTC().Add(-2 * time.Minute)
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", pkgID, past.Add(-time.Hour), past, false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: srv.ID, InboundTag: node.InboundTag, Protocol: "vless",
		CredentialJSON: `{"id":"alice-exp","email":"alice__exp-in"}`,
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Package-linked subscription (even Type="create") must be rejected immediately upon package expiry!
	subReq := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename=pkg_sub.yaml", nil)
	subRec := httptest.NewRecorder()
	NewSubscriptionHandlerConcrete(repo, subDir).ServeHTTP(subRec, subReq.WithContext(auth.ContextWithUsername(subReq.Context(), "alice")))
	if subRec.Code != http.StatusForbidden {
		t.Fatalf("expired package-bundled sub status=%d want=403 body=%s", subRec.Code, subRec.Body.String())
	}

	// 2. User entitlements must report inactive Subscription & Nodes immediately.
	entitlements, err := ResolveUserServiceEntitlements(ctx, repo, "alice", time.Now().UTC())
	if err != nil || entitlements.Nodes || entitlements.Subscription {
		t.Fatalf("expired user entitlements=%+v err=%v", entitlements, err)
	}

	// 3. Re-activate package window, then disable user -> short_link, package_subscribe & user_nodes must reject immediately!
	future := time.Now().UTC().Add(time.Hour)
	if _, err := repo.AssignPackageBundleToUser(ctx, "alice", pkgID, time.Now().UTC().Add(-time.Minute), future, false, 1); err != nil {
		t.Fatal(err)
	}
	userToken, err := repo.GetOrCreateUserToken(ctx, "alice")
	if err != nil || userToken == "" {
		t.Fatal(err)
	}
	codes, err := repo.ListUserShortCodeInfo(ctx)
	if err != nil || codes["alice"].UserShortCode == "" {
		t.Fatal(err)
	}
	if err := repo.UpdateUserStatus(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}

	pkgHandler := NewPackageSubscribeHandler(repo)
	shortHandler := NewShortLinkHandler(repo, NewSubscriptionHandlerConcrete(repo, subDir), pkgHandler)

	shortRec := httptest.NewRecorder()
	shortReq := httptest.NewRequest(http.MethodGet, "/x/"+codes["alice"].UserShortCode, nil)
	if shortHandler.TryServe(shortRec, shortReq) {
		t.Fatalf("disabled user short link was served: code=%d body=%s", shortRec.Code, shortRec.Body.String())
	}

	pkgRec := httptest.NewRecorder()
	pkgReq := httptest.NewRequest(http.MethodGet, "/api/user/package-subscribe", nil)
	pkgHandler.ServeHTTP(pkgRec, pkgReq.WithContext(auth.ContextWithUsername(pkgReq.Context(), "alice")))
	if pkgRec.Code != http.StatusForbidden {
		t.Fatalf("disabled user package-subscribe status=%d want=403", pkgRec.Code)
	}

	if _, _, accessErr := NewUserNodesHandler(repo, nil).validateNodeAccess(ctx, "alice", node.ID); accessErr == nil {
		t.Fatal("disabled user validateNodeAccess unexpectedly succeeded")
	}
}
