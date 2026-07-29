package handler

import (
	"context"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestManagedGrantState(t *testing.T) {
	now := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	base := storage.UserServerGrant{
		Enabled: true, StartsAt: past, BillingMode: storage.ManagedBillingDownload,
	}
	tests := []struct {
		name       string
		grant      storage.UserServerGrant
		userActive bool
		billed     int64
		want       string
	}{
		{name: "active", grant: base, userActive: true, want: storage.ManagedGrantActive},
		{name: "user disabled wins", grant: base, userActive: false, want: storage.ManagedGrantUserDisabled},
		{name: "admin suspended", grant: withManagedGrant(base, func(g *storage.UserServerGrant) { g.Enabled = false }), userActive: true, want: storage.ManagedGrantSuspended},
		{name: "scheduled", grant: withManagedGrant(base, func(g *storage.UserServerGrant) { g.StartsAt = future }), userActive: true, want: storage.ManagedGrantScheduled},
		{name: "expired at boundary", grant: withManagedGrant(base, func(g *storage.UserServerGrant) { g.ExpiresAt = &now }), userActive: true, want: storage.ManagedGrantExpired},
		{name: "quota at boundary", grant: withManagedGrant(base, func(g *storage.UserServerGrant) { g.TrafficLimitBytes = 100 }), userActive: true, billed: 100, want: storage.ManagedGrantOverLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := managedGrantState(tt.grant, tt.userActive, tt.billed, now); got != tt.want {
				t.Fatalf("managedGrantState()=%q want=%q", got, tt.want)
			}
		})
	}
}

func TestLaterOptionalExpiry(t *testing.T) {
	now := time.Now().UTC()
	earlier, later := now.Add(time.Hour), now.Add(2*time.Hour)

	hasAccess, expiry := laterOptionalExpiry(true, &earlier, true, &later)
	if !hasAccess || expiry == nil || !expiry.Equal(later) {
		t.Fatalf("later expiry = %v, %v", hasAccess, expiry)
	}
	hasAccess, expiry = laterOptionalExpiry(true, nil, true, &later)
	if !hasAccess || expiry != nil {
		t.Fatalf("perpetual source must win: %v, %v", hasAccess, expiry)
	}
	hasAccess, expiry = laterOptionalExpiry(false, nil, false, nil)
	if hasAccess || expiry != nil {
		t.Fatalf("no source unexpectedly granted access: %v, %v", hasAccess, expiry)
	}
}

func TestEffectiveManagedNodeIDsRequireAppliedSourceAndEnabledOffer(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "edge-1", Token: "token", IPAddress: "203.0.113.10",
		XrayMode: "embedded", Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "managed", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"managed","type":"vless","server":"203.0.113.10","port":443,"uuid":"owner-uuid"}`,
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
		Username: "alice", ServerID: server.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveNodes: 1,
		BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "owner",
	}); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate selection: %v", err)
	}

	ids, err := effectiveManagedNodeIDs(ctx, repo, "alice")
	if err != nil || len(ids) != 0 {
		t.Fatalf("provisioning source became visible: ids=%v err=%v", ids, err)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID, activation.Source.Generation,
		storage.ManagedObservedActive, now); err != nil {
		t.Fatalf("mark source applied: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: offer.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"managed-node-test-credential"}`,
	}); err != nil {
		t.Fatalf("save source credential: %v", err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, offer.InboundTag)
	if err != nil {
		t.Fatalf("get source credential: %v", err)
	}
	if err := repo.SetUserNodeSelectionCredential(ctx, activation.Selection.ID, credential.ID); err != nil {
		t.Fatalf("link source credential: %v", err)
	}
	ids, err = effectiveManagedNodeIDs(ctx, repo, "alice")
	if err != nil || len(ids) != 1 || ids[0] != node.ID {
		t.Fatalf("applied source not visible: ids=%v err=%v", ids, err)
	}
	if _, err := repo.UpdateSelfServiceNodeOffer(ctx, offer.ID, false, 0); err != nil {
		t.Fatalf("disable offer: %v", err)
	}
	ids, err = effectiveManagedNodeIDs(ctx, repo, "alice")
	if err != nil || len(ids) != 0 {
		t.Fatalf("disabled offer remained visible: ids=%v err=%v", ids, err)
	}
}

func withManagedGrant(grant storage.UserServerGrant, mutate func(*storage.UserServerGrant)) storage.UserServerGrant {
	mutate(&grant)
	return grant
}

func TestManagedSelectionState(t *testing.T) {
	tests := []struct {
		name   string
		source *storage.UserInboundAccessSource
		want   string
	}{
		{name: "missing", want: "error"},
		{name: "provisioning", source: &storage.UserInboundAccessSource{DesiredState: storage.ManagedDesiredActive, ObservedState: storage.ManagedObservedUnknown, Generation: 2, AppliedGeneration: 1}, want: "provisioning"},
		{name: "active", source: &storage.UserInboundAccessSource{DesiredState: storage.ManagedDesiredActive, ObservedState: storage.ManagedObservedActive, Generation: 2, AppliedGeneration: 2}, want: "active"},
		{name: "suspending", source: &storage.UserInboundAccessSource{DesiredState: storage.ManagedDesiredInactive, ObservedState: storage.ManagedObservedActive, Generation: 3, AppliedGeneration: 2}, want: "suspending"},
		{name: "inactive", source: &storage.UserInboundAccessSource{DesiredState: storage.ManagedDesiredInactive, ObservedState: storage.ManagedObservedInactive, Generation: 3, AppliedGeneration: 3}, want: "inactive"},
		{name: "failed", source: &storage.UserInboundAccessSource{DesiredState: storage.ManagedDesiredActive, ObservedState: storage.ManagedObservedUnknown, Generation: 3, AppliedGeneration: 2, LastError: "offline"}, want: "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := managedSelectionState(tt.source); got != tt.want {
				t.Fatalf("managedSelectionState()=%q want=%q", got, tt.want)
			}
		})
	}
}

func TestManagedCredentialEmail(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: `{"id":"1","email":"alice__edge"}`, want: "alice__edge"},
		{raw: `{"user":"alice","pass":"secret"}`, want: "alice"},
		{raw: `{"id":"1"}`, want: ""},
		{raw: `{`, want: ""},
	}
	for _, tt := range tests {
		if got := managedCredentialEmail(tt.raw); got != tt.want {
			t.Fatalf("managedCredentialEmail(%q)=%q want=%q", tt.raw, got, tt.want)
		}
	}
}

func TestNextManagedMonthlyReset(t *testing.T) {
	now := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	got := nextManagedMonthlyReset(now, 20, "Asia/Shanghai")
	want := time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("next reset=%s want=%s", got, want)
	}

	got = nextManagedMonthlyReset(now, 19, "Asia/Shanghai")
	want = time.Date(2026, 8, 18, 16, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("next reset after boundary=%s want=%s", got, want)
	}
}
