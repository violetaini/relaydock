package storage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestNormalizeManagedGrantAllowedProtocols(t *testing.T) {
	got, err := NormalizeManagedGrantAllowedProtocols([]string{
		" VLESS ", "ss", "Shadowsocks", "HYSTERIA2", "hy2",
		"SOCKS5", "socks", "AnyTLS", "snell", "http", "vmess", "trojan",
	})
	if err != nil {
		t.Fatalf("NormalizeManagedGrantAllowedProtocols: %v", err)
	}
	want := []string{
		"vless", "shadowsocks", "hysteria", "socks", "anytls",
		"snell", "http", "vmess", "trojan",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized protocols = %#v, want %#v", got, want)
	}

	for _, protocol := range []string{"", "wireguard", "anydoor", "tuic"} {
		t.Run("reject_"+protocol, func(t *testing.T) {
			if _, err := NormalizeManagedGrantAllowedProtocols([]string{protocol}); !errors.Is(err, ErrManagedInvalidArgument) {
				t.Fatalf("NormalizeManagedGrantAllowedProtocols(%q) error = %v, want %v", protocol, err, ErrManagedInvalidArgument)
			}
		})
	}
}

func TestManagedGrantAllowedProtocolsMigrationDefaultsExistingRowsToAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-grant-old-schema.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}
	_, err = db.Exec(`
CREATE TABLE user_server_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    starts_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    max_active_nodes INTEGER NOT NULL DEFAULT 0,
    speed_limit_mbps REAL NOT NULL DEFAULT 0,
    connection_limit INTEGER NOT NULL DEFAULT 0,
    traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
    billing_mode TEXT NOT NULL DEFAULT 'download',
    reset_policy TEXT NOT NULL DEFAULT 'none',
    reset_day INTEGER NOT NULL DEFAULT 1,
    billing_timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
    next_reset_at TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, server_id)
);
INSERT INTO user_server_grants (
    username, server_id, enabled, starts_at, billing_mode, reset_policy,
    reset_day, billing_timezone, version, created_by
) VALUES ('legacy-user', 41, 1, '2026-07-01T00:00:00Z', 'download',
          'none', 1, 'Asia/Shanghai', 1, 'admin');`)
	if err != nil {
		_ = db.Close()
		t.Fatalf("create old managed grant schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close old database: %v", err)
	}

	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatalf("migrate old database: %v", err)
	}
	defer repo.Close()

	grant, err := repo.GetUserServerGrantByUserAndServer(context.Background(), "legacy-user", 41)
	if err != nil {
		t.Fatalf("read migrated grant: %v", err)
	}
	if grant.AllowedProtocols == nil || len(grant.AllowedProtocols) != 0 {
		t.Fatalf("migrated allowed_protocols = %#v, want non-nil empty list", grant.AllowedProtocols)
	}
	if grant.AllowedProtocolProfiles == nil || len(grant.AllowedProtocolProfiles) != 0 {
		t.Fatalf("migrated allowed_protocol_profiles = %#v, want non-nil empty list", grant.AllowedProtocolProfiles)
	}
	if !grant.AllowsProtocol("vless") || !grant.AllowsProtocol("hysteria2") {
		t.Fatalf("empty migrated whitelist did not preserve unrestricted behavior: %#v", grant.AllowedProtocols)
	}
}

func TestManagedActivationProtocolWhitelistIsTransactional(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, offer := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 26, 5, 0, 0, 0, time.UTC)
	grant := createManagedGrantForTest(t, repo, ctx, server.ID, now)

	grant.AllowedProtocols = []string{"trojan"}
	grant, err := repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("restrict grant to trojan: %v", err)
	}
	catalog, err := repo.ListManagedNodeCatalog(ctx, "alice", now)
	if err != nil {
		t.Fatalf("list restricted catalog: %v", err)
	}
	if len(catalog) != 1 || catalog[0].CanCreate || catalog[0].DenyReason != "protocol_not_allowed" {
		t.Fatalf("restricted catalog=%+v", catalog)
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now); !errors.Is(err, ErrManagedProtocolNotAllowed) {
		t.Fatalf("ActivateUserNodeSelection error = %v, want %v", err, ErrManagedProtocolNotAllowed)
	}

	var selections, sources int
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_node_selections WHERE grant_id = ?`, grant.ID).Scan(&selections); err != nil {
		t.Fatalf("count rejected selections: %v", err)
	}
	if err := repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_inbound_access_sources WHERE source_type = ?`, ManagedSourceSelection).Scan(&sources); err != nil {
		t.Fatalf("count rejected access sources: %v", err)
	}
	if selections != 0 || sources != 0 {
		t.Fatalf("rejected activation left writes: selections=%d sources=%d", selections, sources)
	}

	grant.AllowedProtocols = []string{"VLESS"}
	grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("allow vless: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate allowed vless: %v", err)
	}
	if !activation.Created || !activation.Selection.DesiredEnabled || activation.Source.DesiredState != ManagedDesiredActive {
		t.Fatalf("unexpected allowed activation: %+v", activation)
	}
}

func TestManagedGrantProtocolNarrowingRevokesUntilUserReactivates(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, offer := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 26, 6, 0, 0, 0, time.UTC)
	grant := createManagedGrantForTest(t, repo, ctx, server.ID, now)
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate unrestricted vless: %v", err)
	}

	grant.AllowedProtocols = []string{"trojan"}
	grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("narrow grant protocols: %v", err)
	}
	selection, err := repo.GetUserNodeSelection(ctx, activation.Selection.ID)
	if err != nil {
		t.Fatalf("read narrowed selection: %v", err)
	}
	source, err := repo.GetUserInboundAccessSource(ctx, activation.Source.ID)
	if err != nil {
		t.Fatalf("read narrowed access source: %v", err)
	}
	if selection.DesiredEnabled || source.DesiredState != ManagedDesiredInactive || source.SuspendReason != ManagedSuspendAdminDisabled {
		t.Fatalf("narrowed grant did not revoke selection: selection=%+v source=%+v", selection, source)
	}

	grant.AllowedProtocols = []string{"vless"}
	grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("widen grant protocols: %v", err)
	}
	selection, err = repo.GetUserNodeSelection(ctx, activation.Selection.ID)
	if err != nil {
		t.Fatalf("read widened selection: %v", err)
	}
	source, err = repo.GetUserInboundAccessSource(ctx, activation.Source.ID)
	if err != nil {
		t.Fatalf("read widened access source: %v", err)
	}
	if selection.DesiredEnabled || source.DesiredState != ManagedDesiredInactive {
		t.Fatalf("widening unexpectedly restored access: selection=%+v source=%+v", selection, source)
	}

	reactivated, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("user reactivates after widening: %v", err)
	}
	if reactivated.Created || reactivated.Selection.ID != activation.Selection.ID ||
		!reactivated.Selection.DesiredEnabled || reactivated.Source.DesiredState != ManagedDesiredActive {
		t.Fatalf("unexpected user reactivation: %+v", reactivated)
	}
}

func TestManagedProtocolPolicyFailsClosedAfterPublishedNodeDrifts(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, node, offer := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 26, 7, 0, 0, 0, time.UTC)
	createManagedGrantForTest(t, repo, ctx, server.ID, now)
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate initial vless: %v", err)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID,
		activation.Source.Generation, ManagedObservedActive, now); err != nil {
		t.Fatalf("mark initial source active: %v", err)
	}
	linkManagedProtocolCredentialForTest(t, repo, ctx, activation.Selection.ID, "alice", server.ID, offer.InboundTag, "vless")
	hasAccess, _, err := repo.HasEffectiveUserInboundAccess(ctx, "alice", server.ID, offer.InboundTag, 0, now)
	if err != nil || !hasAccess {
		t.Fatalf("initial effective access=%v err=%v", hasAccess, err)
	}

	node.Protocol = "shadowsocks"
	node.ClashConfig = `{"cipher":"aes-128-gcm"}`
	if _, err := repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift node protocol: %v", err)
	}
	hasAccess, _, err = repo.HasEffectiveUserInboundAccess(ctx, "alice", server.ID, offer.InboundTag, 0, now)
	if err != nil || hasAccess {
		t.Fatalf("drifted protocol retained effective access=%v err=%v", hasAccess, err)
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now.Add(time.Minute)); !errors.Is(err, ErrManagedInvalidArgument) {
		t.Fatalf("drifted activation error=%v, want %v", err, ErrManagedInvalidArgument)
	}
}

func TestManagedEffectiveAccessRejectsStructuralDrift(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, node, offer := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 26, 7, 30, 0, 0, time.UTC)
	createManagedGrantForTest(t, repo, ctx, server.ID, now)
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate managed selection: %v", err)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID,
		activation.Source.Generation, ManagedObservedActive, now); err != nil {
		t.Fatalf("mark source applied: %v", err)
	}
	linkManagedProtocolCredentialForTest(t, repo, ctx, activation.Selection.ID, "alice", server.ID, offer.InboundTag, "vless")

	assertEffective := func(want bool) {
		t.Helper()
		got, _, err := repo.HasEffectiveUserInboundAccess(ctx, "alice", server.ID, offer.InboundTag, 0, now)
		if err != nil || got != want {
			t.Fatalf("effective access=%v err=%v, want %v", got, err, want)
		}
	}
	assertEffective(true)

	tests := []struct {
		name    string
		drift   string
		driftID int64
		restore string
	}{
		{name: "routed node", drift: `UPDATE nodes SET node_type = 'routed' WHERE id = ?`, driftID: node.ID,
			restore: `UPDATE nodes SET node_type = 'physical' WHERE id = ?`},
		{name: "wrong original server", drift: `UPDATE nodes SET original_server = 'other-edge' WHERE id = ?`, driftID: node.ID,
			restore: `UPDATE nodes SET original_server = 'edge-a' WHERE id = ?`},
		{name: "wrong node inbound", drift: `UPDATE nodes SET inbound_tag = 'other-inbound' WHERE id = ?`, driftID: node.ID,
			restore: `UPDATE nodes SET inbound_tag = 'vless-in' WHERE id = ?`},
		{name: "external xray", drift: `UPDATE remote_servers SET xray_mode = 'external' WHERE id = ?`, driftID: server.ID,
			restore: `UPDATE remote_servers SET xray_mode = 'embedded' WHERE id = ?`},
		{name: "wrong source node", drift: `UPDATE user_inbound_access_sources SET node_id = node_id + 999 WHERE id = ?`, driftID: activation.Source.ID,
			restore: `UPDATE user_inbound_access_sources SET node_id = ? WHERE id = ?`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := repo.db.ExecContext(ctx, tt.drift, tt.driftID); err != nil {
				t.Fatalf("apply structural drift: %v", err)
			}
			assertEffective(false)
			var restoreErr error
			if tt.name == "wrong source node" {
				_, restoreErr = repo.db.ExecContext(ctx, tt.restore, node.ID, tt.driftID)
			} else {
				_, restoreErr = repo.db.ExecContext(ctx, tt.restore, tt.driftID)
			}
			if restoreErr != nil {
				t.Fatalf("restore structural fixture: %v", restoreErr)
			}
			assertEffective(true)
		})
	}
}

func TestManagedCredentialProtocolSnapshotRejectsAllowedProtocolDrift(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, node, offer := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 26, 8, 0, 0, 0, time.UTC)
	createManagedGrantForTest(t, repo, ctx, server.ID, now)
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate managed selection: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: offer.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"old-vless-credential"}`,
	}); err != nil {
		t.Fatalf("save managed credential: %v", err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, offer.InboundTag)
	if err != nil {
		t.Fatalf("read managed credential: %v", err)
	}
	if err := repo.SetUserNodeSelectionCredential(ctx, activation.Selection.ID, credential.ID); err != nil {
		t.Fatalf("link managed credential: %v", err)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID,
		activation.Source.Generation, ManagedObservedActive, now); err != nil {
		t.Fatalf("mark source applied: %v", err)
	}

	node.Protocol = "vmess"
	node.ClashConfig = `{"name":"managed-vmess","type":"vmess","uuid":"owner"}`
	if _, err := repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift node to another allowed protocol: %v", err)
	}
	hasAccess, _, err := repo.HasEffectiveUserInboundAccess(ctx, "alice", server.ID, offer.InboundTag, 0, now)
	if err != nil || hasAccess {
		t.Fatalf("old VLESS credential remained effective for VMess: access=%v err=%v", hasAccess, err)
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now.Add(time.Minute)); !errors.Is(err, ErrManagedAccessConflict) {
		t.Fatalf("reactivation before credential cleanup error=%v, want %v", err, ErrManagedAccessConflict)
	}
}

func TestManagedCatalogRejectsProtocolThatDriftedUnsafe(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, node, _ := seedManagedNodesTest(t, repo)
	now := time.Date(2026, 7, 26, 8, 30, 0, 0, time.UTC)
	createManagedGrantForTest(t, repo, ctx, server.ID, now)
	node.Protocol = "shadowsocks"
	node.ClashConfig = `{"name":"classic-ss","type":"ss","cipher":"aes-256-gcm"}`
	if _, err := repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("drift catalog node to classic Shadowsocks: %v", err)
	}
	catalog, err := repo.ListManagedNodeCatalog(ctx, "alice", now)
	if err != nil {
		t.Fatalf("list drifted managed catalog: %v", err)
	}
	if len(catalog) != 1 || catalog[0].CanCreate || catalog[0].DenyReason != "protocol_not_allowed" {
		t.Fatalf("unsafe protocol remained creatable in catalog=%+v", catalog)
	}
}

func linkManagedProtocolCredentialForTest(t *testing.T, repo *TrafficRepository, ctx context.Context,
	selectionID int64, username string, serverID int64, inboundTag, protocol string,
) *UserInboundConfig {
	t.Helper()
	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: username, ServerID: serverID, InboundTag: inboundTag,
		Protocol: protocol, CredentialJSON: `{"id":"managed-test-credential"}`,
	}); err != nil {
		t.Fatalf("save managed protocol credential: %v", err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, username, serverID, inboundTag)
	if err != nil {
		t.Fatalf("read managed protocol credential: %v", err)
	}
	if err := repo.SetUserNodeSelectionCredential(ctx, selectionID, credential.ID); err != nil {
		t.Fatalf("link managed protocol credential: %v", err)
	}
	return credential
}

func TestManagedOfferRepositoryRejectsAnydoorTag(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, _ := seedManagedNodesTest(t, repo)
	node, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://anydoor", NodeName: "Anydoor clone",
		Protocol: "vless", ParsedConfig: `{}`, ClashConfig: `{}`, Enabled: true,
		OriginalServer: server.Name, InboundTag: "AnYdOoR-edge-2033",
	})
	if err != nil {
		t.Fatalf("create anydoor-tag node: %v", err)
	}
	if _, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "admin"); !errors.Is(err, ErrManagedInvalidArgument) {
		t.Fatalf("anydoor offer error=%v, want %v", err, ErrManagedInvalidArgument)
	}
}
