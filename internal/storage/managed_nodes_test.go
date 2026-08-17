package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newManagedNodesTestRepository(t *testing.T) (*TrafficRepository, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed-nodes.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo, path
}

func seedManagedNodesTest(t *testing.T, repo *TrafficRepository) (context.Context, RemoteServer, Node, *SelfServiceNodeOffer) {
	t.Helper()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	server := RemoteServer{
		Name: "edge-a", Token: "edge-a-token", Status: RemoteServerStatusConnected,
		XrayMode: "embedded", ConnectionMode: ConnectionModePush,
	}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://managed", NodeName: "Managed VLESS",
		Protocol: "vless", ParsedConfig: `{}`, ClashConfig: `{}`, Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "admin")
	if err != nil {
		t.Fatalf("CreateSelfServiceNodeOffer: %v", err)
	}
	return ctx, server, node, offer
}

func createManagedGrantForTest(t *testing.T, repo *TrafficRepository, ctx context.Context, serverID int64, now time.Time) *UserServerGrant {
	t.Helper()
	expires := now.Add(24 * time.Hour)
	grant, err := repo.CreateUserServerGrant(ctx, UserServerGrant{
		Username: "alice", ServerID: serverID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &expires, MaxActiveNodes: 2,
		SpeedLimitMbps: 50, ConnectionLimit: 4, TrafficLimitBytes: 10_000,
		BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetMonthly,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateUserServerGrant: %v", err)
	}
	return grant
}

func TestWireGuardSelfServiceRequiresManagedEmbeddedStructure(t *testing.T) {
	if !SelfServiceNodeProtocolEligible("wireguard", `{}`) {
		t.Fatal("WireGuard protocol should support isolated managed peer credentials")
	}
	node := Node{ID: 1, Protocol: "wireguard", Enabled: true, NodeType: "physical", OriginalServer: "edge", InboundTag: "wg-in"}
	offer := SelfServiceNodeOffer{NodeID: 1, ServerID: 2, InboundTag: "wg-in", Enabled: true}
	embedded := RemoteServer{ID: 2, Name: "edge", XrayMode: "embedded"}
	if !SelfServiceNodeOfferStructureValid(offer, node, embedded) {
		t.Fatal("managed embedded WireGuard node was rejected")
	}
	imported := node
	imported.OriginalServer = ""
	imported.InboundTag = ""
	if SelfServiceNodeOfferStructureValid(offer, imported, embedded) {
		t.Fatal("imported static WireGuard node passed managed structure validation")
	}
	external := embedded
	external.XrayMode = "external"
	if SelfServiceNodeOfferStructureValid(offer, node, external) {
		t.Fatal("external Xray WireGuard node passed managed structure validation")
	}
}

func TestWireGuardManagedGrantCatalogAndActivation(t *testing.T) {
	tests := []struct {
		name             string
		allowedProtocols []string
	}{
		{name: "empty whitelist"},
		{name: "explicit whitelist", allowedProtocols: []string{"wireguard"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, _ := newManagedNodesTestRepository(t)
			configureTestNodeSecretEncryption(t, repo, 0x6d)
			ctx, server, node, offer := seedManagedNodesTest(t, repo)
			node.Protocol = "wireguard"
			node.ClashConfig = testWireGuardNodeConfig("managed-wg")
			node.ParsedConfig = node.ClashConfig
			if _, err := repo.UpdateNode(ctx, node); err != nil {
				t.Fatalf("update managed node to WireGuard: %v", err)
			}
			seedManagedWireGuardProvenanceForTest(t, repo, ctx, server, &node, 0x6d)
			now := time.Date(2026, 8, 15, 5, 0, 0, 0, time.UTC)
			grant := createManagedGrantForTest(t, repo, ctx, server.ID, now)
			if tt.allowedProtocols != nil {
				grant.AllowedProtocols = tt.allowedProtocols
				var err error
				grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
				if err != nil {
					t.Fatalf("allow WireGuard: %v", err)
				}
			}

			catalog, err := repo.ListManagedNodeCatalog(ctx, "alice", now)
			if err != nil {
				t.Fatalf("list WireGuard catalog: %v", err)
			}
			if len(catalog) != 1 || !catalog[0].CanCreate || catalog[0].DenyReason != "" {
				t.Fatalf("WireGuard catalog=%+v, want creatable", catalog)
			}
			if catalog[0].ProtocolProfile != "" {
				t.Fatalf("WireGuard profile=%q, want no profile restriction", catalog[0].ProtocolProfile)
			}

			activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
			if err != nil {
				t.Fatalf("activate WireGuard selection: %v", err)
			}
			if !activation.Created || !activation.Selection.DesiredEnabled || activation.Source.DesiredState != ManagedDesiredActive {
				t.Fatalf("unexpected WireGuard activation: %+v", activation)
			}
		})
	}
}

func TestForwardedNodeCannotBecomeSelfServiceOffer(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx := context.Background()
	server := RemoteServer{
		Name: "forwarded-edge", Token: "forwarded-token", Status: RemoteServerStatusConnected,
		XrayMode: "embedded", ConnectionMode: ConnectionModePush,
	}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://forwarded", NodeName: "Forwarded VLESS",
		Protocol: "vless", ParsedConfig: `{}`, ClashConfig: `{}`, Enabled: true,
		OriginalServer: server.Name, InboundTag: "forwarded-in",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := repo.MarkNodeForwarded(ctx, node.ID); err != nil {
		t.Fatalf("MarkNodeForwarded: %v", err)
	}
	forwarded, err := repo.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatalf("GetNodeByID: %v", err)
	}
	if forwarded.NodeType != "forwarded" {
		t.Fatalf("node type = %q, want forwarded", forwarded.NodeType)
	}
	if SelfServiceNodeOfferStructureValid(SelfServiceNodeOffer{
		NodeID: node.ID, ServerID: server.ID, InboundTag: node.InboundTag,
	}, forwarded, server) {
		t.Fatal("forwarded node passed self-service structure validation")
	}
	if _, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "admin"); !errors.Is(err, ErrManagedServerMismatch) {
		t.Fatalf("CreateSelfServiceNodeOffer error = %v, want %v", err, ErrManagedServerMismatch)
	}
}

func TestManagedNodeLifecycleAndGenerationCAS(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, offer := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	grant := createManagedGrantForTest(t, repo, ctx, server.ID, now)

	catalog, err := repo.ListManagedNodeCatalog(ctx, "alice", now)
	if err != nil {
		t.Fatalf("ListManagedNodeCatalog: %v", err)
	}
	if len(catalog) != 1 || !catalog[0].CanCreate {
		t.Fatalf("unexpected initial catalog: %+v", catalog)
	}

	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("ActivateUserNodeSelection: %v", err)
	}
	if !activation.Created || activation.Source.Generation != 1 || !activation.Selection.DesiredEnabled {
		t.Fatalf("unexpected activation: %+v", activation)
	}
	idempotent, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now.Add(time.Second))
	if err != nil {
		t.Fatalf("idempotent ActivateUserNodeSelection: %v", err)
	}
	if idempotent.Created || idempotent.Selection.ID != activation.Selection.ID || idempotent.Source.Generation != 1 {
		t.Fatalf("activation was not idempotent: %+v", idempotent)
	}

	applied, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID, 1, ManagedObservedActive, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("MarkUserInboundAccessSourceApplied: %v", err)
	}
	if applied.AppliedGeneration != 1 || applied.ObservedState != ManagedObservedActive {
		t.Fatalf("unexpected applied source: %+v", applied)
	}
	catalog, err = repo.ListManagedNodeCatalog(ctx, "alice", now.Add(2*time.Second))
	if err != nil || len(catalog) != 1 || catalog[0].AccessSource == nil ||
		catalog[0].AccessSource.ObservedState != ManagedObservedActive ||
		catalog[0].AccessSource.Generation != catalog[0].AccessSource.AppliedGeneration {
		t.Fatalf("catalog omitted applied access state: %+v, %v", catalog, err)
	}

	deactivated, err := repo.DeactivateUserNodeSelection(ctx, "alice", activation.Selection.ID, "alice", ManagedSuspendUserDisabled, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("DeactivateUserNodeSelection: %v", err)
	}
	if deactivated.Source.Generation != 2 || deactivated.Source.DesiredState != ManagedDesiredInactive {
		t.Fatalf("unexpected deactivation: %+v", deactivated)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID, 1, ManagedObservedInactive, now.Add(4*time.Second)); !errors.Is(err, ErrManagedGenerationConflict) {
		t.Fatalf("stale generation error = %v, want %v", err, ErrManagedGenerationConflict)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID, 2, ManagedObservedInactive, now.Add(4*time.Second)); err != nil {
		t.Fatalf("apply deactivation: %v", err)
	}

	pending, err := repo.ListPendingUserInboundAccessSources(ctx, now.Add(5*time.Second), 10, server.ID)
	if err != nil {
		t.Fatalf("ListPendingUserInboundAccessSources: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending sources, got %+v", pending)
	}

	if err := repo.DeleteUserServerGrant(ctx, grant.ID, grant.Version, "admin"); err != nil {
		t.Fatalf("DeleteUserServerGrant: %v", err)
	}
	if _, err := repo.GetUserNodeSelection(ctx, activation.Selection.ID); !errors.Is(err, ErrUserNodeSelectionNotFound) {
		t.Fatalf("selection survived grant delete: %v", err)
	}
	audits, err := repo.ListManagedAccessAudit(ctx, "alice", "server_grant", grant.ID, 20)
	if err != nil {
		t.Fatalf("ListManagedAccessAudit: %v", err)
	}
	if len(audits) == 0 || audits[0].Action != "grant.deleted" {
		t.Fatalf("grant delete audit missing: %+v", audits)
	}
}

func TestManagedGrantCASUsageAndAuditRedaction(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, offer := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	grant := createManagedGrantForTest(t, repo, ctx, server.ID, now)
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("ActivateUserNodeSelection: %v", err)
	}

	usage, err := repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 100, 200, "boot-1", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("first AccumulateUserNodeSelectionUsage: %v", err)
	}
	if usage.UplinkBytes != 0 || usage.DownlinkBytes != 0 || usage.LastRawUplink != 100 || usage.LastRawDownlink != 200 {
		t.Fatalf("unexpected first usage: %+v", usage)
	}
	usage, err = repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 150, 250, "boot-1", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second AccumulateUserNodeSelectionUsage: %v", err)
	}
	usage, err = repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 10, 20, "boot-2", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("epoch AccumulateUserNodeSelectionUsage: %v", err)
	}
	if usage.UplinkBytes != 60 || usage.DownlinkBytes != 70 || usage.BilledBytes(ManagedBillingBoth) != 130 {
		t.Fatalf("unexpected accumulated usage: %+v", usage)
	}
	up, down, billed, err := repo.GetUserServerGrantUsage(ctx, grant.ID)
	if err != nil || up != 60 || down != 70 || billed != 70 {
		t.Fatalf("grant usage = (%d,%d,%d,%v)", up, down, billed, err)
	}

	grant.SpeedLimitMbps = 75
	updated, err := repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("UpdateUserServerGrant: %v", err)
	}
	if updated.Version != grant.Version+1 || updated.SpeedLimitMbps != 75 {
		t.Fatalf("unexpected updated grant: %+v", updated)
	}
	if _, err := repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin"); !errors.Is(err, ErrManagedVersionConflict) {
		t.Fatalf("stale grant version error = %v", err)
	}

	if err := repo.AppendManagedAccessAudit(ctx, ManagedAccessAudit{
		Actor: "admin", Action: "redaction.test", EntityType: "server_grant",
		EntityID: grant.ID, Username: "alice", ServerID: server.ID,
		Details: map[string]any{"token": "do-not-store", "safe": "visible", "nested": map[string]any{"password": "hidden"}},
	}); err != nil {
		t.Fatalf("AppendManagedAccessAudit: %v", err)
	}
	audits, err := repo.ListManagedAccessAudit(ctx, "alice", "server_grant", grant.ID, 20)
	if err != nil {
		t.Fatalf("ListManagedAccessAudit: %v", err)
	}
	if len(audits) == 0 || audits[0].Details["token"] != "[redacted]" || audits[0].Details["safe"] != "visible" {
		t.Fatalf("audit was not redacted: %+v", audits)
	}
	sanitized := sanitizeManagedError(`agent failed token=top-secret client 550e8400-e29b-41d4-a716-446655440000`)
	if strings.Contains(sanitized, "top-secret") || strings.Contains(sanitized, "550e8400-e29b-41d4-a716-446655440000") {
		t.Fatalf("managed error leaked a secret: %q", sanitized)
	}

	nextReset := now.AddDate(0, 1, 0)
	if err := repo.ResetUserServerGrantUsage(ctx, grant.ID, now.Add(4*time.Minute), &nextReset, "system"); err != nil {
		t.Fatalf("ResetUserServerGrantUsage: %v", err)
	}
	reset, err := repo.GetUserNodeSelectionUsage(ctx, activation.Selection.ID)
	if err != nil || reset.UplinkBytes != 0 || reset.DownlinkBytes != 0 || reset.CounterEpoch != "boot-2" || reset.LastRawUplink != 10 || reset.LastRawDownlink != 20 {
		t.Fatalf("unexpected reset usage: %+v, %v", reset, err)
	}
	afterReset, err := repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 15, 25, "boot-2", now.Add(5*time.Minute))
	if err != nil || afterReset.UplinkBytes != 5 || afterReset.DownlinkBytes != 5 {
		t.Fatalf("post-reset usage double-counted: %+v, %v", afterReset, err)
	}
}

func TestManagedNodesMigrationIsIdempotentAndEmailLookupIsExact(t *testing.T) {
	repo, path := newManagedNodesTestRepository(t)
	ctx, server, node, _ := seedManagedNodesTest(t, repo)
	if err := repo.UpsertUserEmailTraffic(ctx, server.ID, "alice__vless-in", 100, 200, false); err != nil {
		t.Fatalf("UpsertUserEmailTraffic baseline: %v", err)
	}
	if err := repo.UpsertUserEmailTraffic(ctx, server.ID, "alice__vless-in", 130, 260, false); err != nil {
		t.Fatalf("UpsertUserEmailTraffic delta: %v", err)
	}
	traffic, err := repo.GetUserEmailTraffic(ctx, server.ID, "alice__vless-in")
	if err != nil || traffic == nil || traffic.Uplink != 30 || traffic.Downlink != 60 {
		t.Fatalf("GetUserEmailTraffic = %+v, %v", traffic, err)
	}
	missing, err := repo.GetUserEmailTraffic(ctx, server.ID, "missing")
	if err != nil || missing != nil {
		t.Fatalf("missing GetUserEmailTraffic = %+v, %v", missing, err)
	}
	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: node.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"legacy-secret"}`,
	}); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}

	if err := repo.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("reopen migrated repository: %v", err)
	}
	defer reopened.Close()
	var tables int
	if err := reopened.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master
WHERE type = 'table' AND name IN (
    'self_service_node_offers', 'user_server_grants', 'user_node_selections',
    'user_inbound_access_sources', 'user_node_selection_usage', 'managed_access_audit'
)`).Scan(&tables); err != nil {
		t.Fatalf("count managed tables: %v", err)
	}
	if tables != 6 {
		t.Fatalf("managed table count = %d, want 6", tables)
	}
	sources, err := reopened.ListUserInboundAccessSources(ctx, "alice", server.ID)
	if err != nil || len(sources) != 1 || sources[0].SourceType != ManagedSourceLegacyReview ||
		sources[0].NodeID != node.ID || sources[0].DesiredState != ManagedDesiredInactive ||
		sources[0].SuspendReason != ManagedSuspendAdminDisabled {
		t.Fatalf("legacy credential backfill = %+v, %v", sources, err)
	}
	hasAccess, expiry, err := reopened.HasEffectiveUserInboundAccess(ctx, "alice", server.ID, node.InboundTag, 0, time.Now().UTC())
	if err != nil || hasAccess || expiry != nil {
		t.Fatalf("legacy tombstone granted access: has=%v expiry=%v err=%v", hasAccess, expiry, err)
	}
	if err := reopened.migrateManagedNodes(); err != nil {
		t.Fatalf("second managed migration: %v", err)
	}
	sources, err = reopened.ListUserInboundAccessSources(ctx, "alice", server.ID)
	if err != nil || len(sources) != 1 {
		t.Fatalf("legacy backfill was not idempotent: %+v, %v", sources, err)
	}
}

func TestManagedNullableExpirySurvivesSQLiteRoundTrip(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, _ := seedManagedNodesTest(t, repo)
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(6 * time.Hour)
	grant, err := repo.CreateUserServerGrant(ctx, UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true, StartsAt: now.Add(-time.Hour),
		ExpiresAt: &expires, MaxActiveNodes: 1, BillingMode: ManagedBillingDownload,
		ResetPolicy: ManagedResetNone, ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "owner",
	})
	if err != nil {
		t.Fatalf("create expiring grant: %v", err)
	}
	if grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(expires) {
		t.Fatalf("grant expiry round trip=%v want=%v", grant.ExpiresAt, expires)
	}
}

func TestManagedNodeConcurrentActivationIsIdempotent(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, offer := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	createManagedGrantForTest(t, repo, ctx, server.ID, now)

	const workers = 8
	start := make(chan struct{})
	results := make(chan *SelectionActivationResult, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent activation: %v", err)
	}
	var selectionID int64
	created := 0
	for result := range results {
		if selectionID == 0 {
			selectionID = result.Selection.ID
		}
		if result.Selection.ID != selectionID || result.Source.Generation != 1 {
			t.Fatalf("concurrent requests diverged: %+v", result)
		}
		if result.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created results = %d, want 1", created)
	}
	selections, err := repo.ListUserNodeSelections(ctx, "alice", true)
	if err != nil || len(selections) != 1 {
		t.Fatalf("selections after concurrent activation = %+v, %v", selections, err)
	}
}
