package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func seedDirectNodeGrantTest(t *testing.T) (*TrafficRepository, context.Context, RemoteServer, Node) {
	t.Helper()
	repo, _ := newManagedNodesTestRepository(t)
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	server := RemoteServer{
		Name: "direct-edge", Token: "direct-edge-token", Status: RemoteServerStatusConnected,
		XrayMode: "embedded", ConnectionMode: ConnectionModePush,
	}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "vless://owner-secret@direct-edge",
		NodeName: "Direct VLESS", Protocol: "vless", ParsedConfig: `{}`,
		ClashConfig: `{"name":"Direct VLESS","type":"vless","server":"edge.example","port":443,"uuid":"owner-secret"}`,
		Enabled:     true, OriginalServer: server.Name, InboundTag: "direct-in",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	return repo, ctx, server, node
}

func TestManualUserNodeGrantLifecycleAndCredentialFence(t *testing.T) {
	repo, ctx, server, node := seedDirectNodeGrantTest(t)
	expires := time.Now().UTC().Add(24 * time.Hour)
	item, created, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, &expires, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	if !created || item.Grant.SourceType != GrantSourceManual || item.Source.SourceType != ManagedSourceDirect ||
		item.Source.DesiredState != ManagedDesiredActive || item.Grant.AccessSourceID != item.Source.ID {
		t.Fatalf("unexpected grant: %+v", item)
	}
	hasAccess, notAfter, err := repo.HasEffectiveDirectUserInboundAccess(ctx, "alice", server.ID, node.InboundTag, 0, time.Now().UTC())
	if err != nil || !hasAccess || notAfter == nil || !notAfter.Equal(expires) {
		t.Fatalf("initial direct access=(%v,%v,%v)", hasAccess, notAfter, err)
	}

	credential := UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: node.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"alice-secret","email":"alice__direct-in"}`,
	}
	if err := repo.SaveUserInboundConfig(ctx, credential); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}
	saved, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, node.InboundTag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	if err := repo.SetUserNodeGrantCredential(ctx, item.Grant.ID, saved.ID); err != nil {
		t.Fatalf("SetUserNodeGrantCredential: %v", err)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, item.Source.ID, item.Source.Generation, ManagedObservedActive, time.Now().UTC()); err != nil {
		t.Fatalf("MarkUserInboundAccessSourceApplied: %v", err)
	}
	ids, err := repo.ListEffectiveDirectNodeIDs(ctx, "alice", time.Now().UTC())
	if err != nil || len(ids) != 1 || ids[0] != node.ID {
		t.Fatalf("ListEffectiveDirectNodeIDs=%v err=%v", ids, err)
	}

	if _, err := repo.db.ExecContext(ctx, `UPDATE user_node_grants SET credential_config_id = NULL WHERE id = ?`, item.Grant.ID); err != nil {
		t.Fatalf("corrupt grant: %v", err)
	}
	ids, err = repo.ListEffectiveDirectNodeIDs(ctx, "alice", time.Now().UTC())
	if err != nil || len(ids) != 0 {
		t.Fatalf("corrupt credential link remained visible: ids=%v err=%v", ids, err)
	}
	hasAccess, _, err = repo.HasEffectiveDirectUserInboundAccess(ctx, "alice", server.ID, node.InboundTag, 0, time.Now().UTC())
	if err != nil || hasAccess {
		t.Fatalf("corrupt credential link remained authorized: access=%v err=%v", hasAccess, err)
	}
}

func TestManualUserNodeGrantRevocationIsImmediate(t *testing.T) {
	repo, ctx, server, node := seedDirectNodeGrantTest(t)
	item, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	updated, err := repo.SetUserNodeGrantDesiredState(ctx, item.Grant.ID, "alice", ManagedDesiredInactive, "admin")
	if err != nil {
		t.Fatalf("SetUserNodeGrantDesiredState: %v", err)
	}
	if updated.Source.DesiredState != ManagedDesiredInactive || updated.Source.Generation <= item.Source.Generation {
		t.Fatalf("unexpected revoked source: %+v", updated.Source)
	}
	hasAccess, _, err := repo.HasEffectiveDirectUserInboundAccess(ctx, "alice", server.ID, node.InboundTag, 0, time.Now().UTC())
	if err != nil || hasAccess {
		t.Fatalf("revoked source remained effective: access=%v err=%v", hasAccess, err)
	}
	pending, err := repo.ListPendingUserInboundAccessSources(ctx, time.Now().UTC(), 10, server.ID)
	if err != nil || len(pending) != 1 || pending[0].ID != item.Source.ID {
		t.Fatalf("pending cleanup=%+v err=%v", pending, err)
	}
}

func TestManualUserNodeGrantRejectsUnsafeNode(t *testing.T) {
	repo, ctx, _, _ := seedDirectNodeGrantTest(t)
	unsafeNode, err := repo.CreateNode(ctx, Node{
		Username: "admin", RawURL: "socks5://owner:secret@private.example:1080", NodeName: "Unsafe standalone",
		Protocol: "socks5", ClashConfig: `{"type":"socks5","server":"private.example","port":1080,"username":"owner","password":"secret"}`,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", unsafeNode.ID, nil, "admin"); err == nil {
		t.Fatal("unsafe node was accepted as a direct node grant")
	}
}

func TestActiveManualUserNodeGrantGuardsNodeMutation(t *testing.T) {
	repo, ctx, _, node := seedDirectNodeGrantTest(t)
	item, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE nodes SET enabled = 0 WHERE id = ?`, node.ID); err == nil {
		t.Fatal("active direct grant allowed node disable before remote cleanup")
	}
	if _, err := repo.SetUserNodeGrantDesiredState(ctx, item.Grant.ID, "alice", ManagedDesiredInactive, "admin"); err != nil {
		t.Fatalf("SetUserNodeGrantDesiredState: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE nodes SET enabled = 0 WHERE id = ?`, node.ID); err != nil {
		t.Fatalf("inactive direct grant blocked node disable: %v", err)
	}
}

func TestRemoteServerDeletionRejectsDirectNodeGrantReferences(t *testing.T) {
	repo, ctx, server, node := seedDirectNodeGrantTest(t)
	grant, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	if err := repo.ValidateRemoteServerDeletion(ctx, server.ID); err == nil {
		t.Fatal("server deletion validation accepted an active direct node grant")
	}
	if err := repo.DeleteRemoteServer(ctx, server.ID); err == nil {
		t.Fatal("server deletion accepted an active direct node grant")
	}
	credential := UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: node.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"alice-delete-secret","email":"alice__direct-in"}`,
	}
	if err := repo.SaveUserInboundConfig(ctx, credential); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}
	saved, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, node.InboundTag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	if err := repo.SetUserNodeGrantCredential(ctx, grant.Grant.ID, saved.ID); err != nil {
		t.Fatalf("SetUserNodeGrantCredential: %v", err)
	}
	revoked, err := repo.SetUserNodeGrantDesiredState(ctx, grant.Grant.ID, "alice", ManagedDesiredInactive, "admin")
	if err != nil {
		t.Fatalf("SetUserNodeGrantDesiredState: %v", err)
	}
	if err := repo.ValidateRemoteServerDeletion(ctx, server.ID); err == nil {
		t.Fatal("server deletion validation accepted an unreconciled direct grant")
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, revoked.Source.ID, revoked.Source.Generation, ManagedObservedInactive, time.Now().UTC()); err != nil {
		t.Fatalf("MarkUserInboundAccessSourceApplied: %v", err)
	}
	if err := repo.ValidateRemoteServerDeletion(ctx, server.ID); err != nil {
		t.Fatalf("reconciled tombstone failed deletion validation: %v", err)
	}
	if err := repo.DeleteRemoteServer(ctx, server.ID); err != nil {
		t.Fatalf("DeleteRemoteServer with reconciled tombstone: %v", err)
	}
	if _, err := repo.GetRemoteServer(ctx, server.ID); !errors.Is(err, ErrRemoteServerNotFound) {
		t.Fatalf("server remained after delete: %v", err)
	}
	if _, err := repo.GetNodeByID(ctx, node.ID); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("node remained after delete: %v", err)
	}
	if _, err := repo.GetUserNodeGrant(ctx, grant.Grant.ID); !errors.Is(err, ErrUserNodeGrantNotFound) {
		t.Fatalf("direct grant tombstone remained after delete: %v", err)
	}
	if _, err := repo.GetUserInboundAccessSource(ctx, revoked.Source.ID); !errors.Is(err, ErrManagedAccessSourceNotFound) {
		t.Fatalf("direct source tombstone remained after delete: %v", err)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, node.InboundTag); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("direct credential tombstone remained after delete: %v", err)
	}
}

func TestExpireDirectUserInboundAccessSourcesQueuesAppliedGrant(t *testing.T) {
	repo, ctx, _, node := seedDirectNodeGrantTest(t)
	expiresAt := time.Now().UTC().Add(time.Hour)
	item, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, &expiresAt, "admin")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := repo.MarkUserInboundAccessSourceApplied(ctx, item.Source.ID, item.Source.Generation,
		ManagedObservedActive, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE user_inbound_access_sources SET expires_at=? WHERE id=?`,
		time.Now().UTC().Add(-time.Minute), applied.ID); err != nil {
		t.Fatal(err)
	}
	count, err := repo.ExpireDirectUserInboundAccessSources(ctx, time.Now().UTC(), 10)
	if err != nil || count != 1 {
		t.Fatalf("ExpireDirectUserInboundAccessSources count=%d err=%v", count, err)
	}
	source, err := repo.GetUserInboundAccessSource(ctx, applied.ID)
	if err != nil {
		t.Fatal(err)
	}
	if source.DesiredState != ManagedDesiredInactive || source.SuspendReason != ManagedSuspendExpired ||
		source.Generation != applied.Generation+1 || source.AppliedGeneration != applied.Generation {
		t.Fatalf("expired source was not queued: %+v", source)
	}
	pending, err := repo.ListPendingUserInboundAccessSources(ctx, time.Now().UTC(), 10, 0)
	if err != nil || len(pending) != 1 || pending[0].ID != source.ID {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	count, err = repo.ExpireDirectUserInboundAccessSources(ctx, time.Now().UTC(), 10)
	if err != nil || count != 0 {
		t.Fatalf("expiry sweep was not idempotent count=%d err=%v", count, err)
	}
}

func TestRemoteServerDeletionRejectsPackageTemplateReferences(t *testing.T) {
	t.Run("server grant", func(t *testing.T) {
		repo, ctx, server, _ := seedDirectNodeGrantTest(t)
		if _, err := repo.CreatePackage(ctx, Package{
			Name: "server-reference",
			ServerGrants: []PackageServerGrant{{
				ServerID: server.ID,
			}},
		}); err != nil {
			t.Fatalf("CreatePackage: %v", err)
		}
		if err := repo.ValidateRemoteServerDeletion(ctx, server.ID); err == nil {
			t.Fatal("server deletion validation accepted a package server grant reference")
		}
	})

	t.Run("fixed node", func(t *testing.T) {
		repo, ctx, server, node := seedDirectNodeGrantTest(t)
		if _, err := repo.CreatePackage(ctx, Package{
			Name: "node-reference", Nodes: []int64{node.ID},
		}); err != nil {
			t.Fatalf("CreatePackage: %v", err)
		}
		if err := repo.ValidateRemoteServerDeletion(ctx, server.ID); err == nil {
			t.Fatal("server deletion validation accepted a package fixed-node reference")
		}
	})
}

func TestValidateNodeDeletionRequiresReconciledInactiveDirectGrant(t *testing.T) {
	repo, ctx, _, node := seedDirectNodeGrantTest(t)
	grant, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatalf("UpsertManualUserNodeGrant: %v", err)
	}
	if err := repo.ValidateNodeDeletion(ctx, []int64{node.ID}); !errors.Is(err, ErrNodeHasActiveDirectGrant) {
		t.Fatalf("active grant validation error=%v, want %v", err, ErrNodeHasActiveDirectGrant)
	}
	revoked, err := repo.SetUserNodeGrantDesiredState(ctx, grant.Grant.ID, "alice", ManagedDesiredInactive, "admin")
	if err != nil {
		t.Fatalf("SetUserNodeGrantDesiredState: %v", err)
	}
	if err := repo.ValidateNodeDeletion(ctx, []int64{node.ID}); !errors.Is(err, ErrNodeHasActiveDirectGrant) {
		t.Fatalf("unreconciled grant validation error=%v, want %v", err, ErrNodeHasActiveDirectGrant)
	}
	if err := repo.DeleteNodeByID(ctx, node.ID); err == nil {
		t.Fatal("unreconciled direct revoke allowed node deletion")
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, revoked.Source.ID, revoked.Source.Generation,
		ManagedObservedInactive, time.Now().UTC()); err != nil {
		t.Fatalf("MarkUserInboundAccessSourceApplied: %v", err)
	}
	if err := repo.ValidateNodeDeletion(ctx, []int64{node.ID}); err != nil {
		t.Fatalf("reconciled inactive grant blocked node delete preflight: %v", err)
	}
	if err := repo.DeleteNodeByID(ctx, node.ID); err != nil {
		t.Fatalf("DeleteNodeByID: %v", err)
	}
	if _, err := repo.GetUserNodeGrant(ctx, grant.Grant.ID); !errors.Is(err, ErrUserNodeGrantNotFound) {
		t.Fatalf("direct grant tombstone remained after node delete: %v", err)
	}
	if _, err := repo.GetUserInboundAccessSource(ctx, revoked.Source.ID); !errors.Is(err, ErrManagedAccessSourceNotFound) {
		t.Fatalf("direct source tombstone remained after node delete: %v", err)
	}
}

func TestNodeDeletionFailsClosedForOrphanedDirectSource(t *testing.T) {
	repo, ctx, _, node := seedDirectNodeGrantTest(t)
	grant, _, err := repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE user_node_grants SET access_source_id=NULL WHERE id=?`, grant.Grant.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.ValidateNodeDeletion(ctx, []int64{node.ID}); !errors.Is(err, ErrNodeHasActiveDirectGrant) {
		t.Fatalf("orphaned source validation error=%v, want %v", err, ErrNodeHasActiveDirectGrant)
	}
	if err := repo.DeleteNodeByID(ctx, node.ID); err == nil {
		t.Fatal("orphaned direct source allowed node deletion")
	}
	if _, err := repo.GetNodeByID(ctx, node.ID); err != nil {
		t.Fatalf("failed deletion removed node: %v", err)
	}
}
