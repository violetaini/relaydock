package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func seedUserManagedCreationTest(t *testing.T, maxActive int) (*TrafficRepository, context.Context, RemoteServer, *UserServerGrant) {
	t.Helper()
	repo, _ := newManagedNodesTestRepository(t)
	ctx := context.Background()
	for _, username := range []string{"alice", "bob"} {
		if err := repo.CreateUser(ctx, username, username+"@example.test", username, "hash", RoleUser, ""); err != nil {
			t.Fatalf("CreateUser(%s): %v", username, err)
		}
	}
	server := RemoteServer{Name: "user-create-edge", Token: "token", Status: RemoteServerStatusConnected, XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	var aliceGrant *UserServerGrant
	for _, username := range []string{"alice", "bob"} {
		grant, err := repo.CreateUserServerGrant(ctx, UserServerGrant{
			Username: username, ServerID: server.ID, Enabled: true,
			StartsAt: now.Add(-time.Minute), ExpiresAt: &expires, MaxActiveNodes: maxActive,
			BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone,
			ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
		})
		if err != nil {
			t.Fatalf("CreateUserServerGrant(%s): %v", username, err)
		}
		if username == "alice" {
			aliceGrant = grant
		}
	}
	return repo, ctx, server, aliceGrant
}

func TestReserveUserManagedNodeCreationSerializesMaxActiveNodes(t *testing.T) {
	repo, ctx, server, grant := seedUserManagedCreationTest(t, 1)
	now := time.Now().UTC()
	const attempts = 8
	var wg sync.WaitGroup
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, err := repo.ReserveUserManagedNodeCreation(ctx, "alice", grant.ID, server.ID,
				fmt.Sprintf("vless-%d", index), fmt.Sprintf("mutation-%d", index), now)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrManagedActiveNodeLimit) {
			t.Fatalf("unexpected reservation error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful reservations=%d want=1", successes)
	}
}

func TestPrivateUserManagedOfferAndPromotionAreOwnerScoped(t *testing.T) {
	repo, ctx, server, grant := seedUserManagedCreationTest(t, 2)
	now := time.Now().UTC()
	creation, err := repo.ReserveUserManagedNodeCreation(ctx, "alice", grant.ID, server.ID,
		"private-vless", "user-managed-node:test-owner", now)
	if err != nil {
		t.Fatalf("ReserveUserManagedNodeCreation: %v", err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username: "alice", NodeName: "Alice private", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: creation.InboundTag, InboundMutationID: creation.MutationID,
		ClashConfig: `{"name":"Alice private","type":"vless","server":"203.0.113.9","port":443,"uuid":"private"}`,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	offer, err := repo.CreatePrivateSelfServiceNodeOffer(ctx, node.ID, *grant, "alice")
	if err != nil {
		t.Fatalf("CreatePrivateSelfServiceNodeOffer: %v", err)
	}
	if offer.OwnerUsername != "alice" || offer.GrantID == nil || *offer.GrantID != grant.ID {
		t.Fatalf("private offer lost owner/grant: %+v", offer)
	}
	bobCatalog, err := repo.ListManagedNodeCatalog(ctx, "bob", now)
	if err != nil {
		t.Fatalf("ListManagedNodeCatalog(bob): %v", err)
	}
	if len(bobCatalog) != 0 {
		t.Fatalf("private offer leaked into bob catalog: %+v", bobCatalog)
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "bob", offer.ID, "bob", now); !errors.Is(err, ErrSelfServiceNodeOfferNotFound) {
		t.Fatalf("bob activation error=%v want private not-found", err)
	}

	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: creation.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"private","email":"alice__private-vless"}`,
	}); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, creation.InboundTag)
	if err != nil {
		t.Fatalf("GetUserInboundConfig: %v", err)
	}
	cleanup, err := repo.PreparePackageInboundCredentialCleanup(ctx, *credential, "test")
	if err != nil {
		t.Fatalf("PreparePackageInboundCredentialCleanup: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("ActivateUserNodeSelection: %v", err)
	}
	promoted, err := repo.PromoteUserManagedNodeCreation(ctx, creation.ID, node.ID, offer.ID,
		activation.Selection.ID, cleanup.ID, credential.ID)
	if err != nil {
		t.Fatalf("PromoteUserManagedNodeCreation: %v", err)
	}
	if promoted.State != UserManagedNodeActive || promoted.NodeID == nil || *promoted.NodeID != node.ID {
		t.Fatalf("unexpected promoted creation: %+v", promoted)
	}
	selection, err := repo.GetUserNodeSelection(ctx, activation.Selection.ID)
	if err != nil || selection.CredentialConfigID == nil || *selection.CredentialConfigID != credential.ID {
		t.Fatalf("selection credential was not atomically linked: selection=%+v err=%v", selection, err)
	}
	if _, err := repo.GetUserInboundAccessSource(ctx, cleanup.ID); !errors.Is(err, ErrManagedAccessSourceNotFound) {
		t.Fatalf("deny tombstone still exists after promotion: %v", err)
	}
}

func TestRecoverUserManagedNodeCreationWithoutProgressPreservesStaleTimestamp(t *testing.T) {
	repo, ctx, server, grant := seedUserManagedCreationTest(t, 2)
	creation, err := repo.ReserveUserManagedNodeCreation(ctx, "alice", grant.ID, server.ID,
		"stale-reservation", "user-managed-node:stale", time.Now().UTC())
	if err != nil {
		t.Fatalf("ReserveUserManagedNodeCreation: %v", err)
	}
	stale := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	if _, err := repo.db.ExecContext(ctx, `UPDATE user_managed_node_creations SET updated_at=? WHERE id=?`, stale, creation.ID); err != nil {
		t.Fatalf("age reservation: %v", err)
	}
	recovered, err := repo.RecoverUserManagedNodeCreationLinks(ctx, creation.ID)
	if err != nil {
		t.Fatalf("RecoverUserManagedNodeCreationLinks: %v", err)
	}
	if recovered.NodeID != nil || recovered.OfferID != nil || recovered.SelectionID != nil {
		t.Fatalf("empty reservation adopted unexpected links: %+v", recovered)
	}
	if recovered.UpdatedAt.After(stale.Add(time.Second)) {
		t.Fatalf("no-progress recovery refreshed stale timestamp: got=%s stale=%s", recovered.UpdatedAt, stale)
	}
}

func TestRecoverAndPromoteUserManagedNodeCreationRejectWrongMutationGeneration(t *testing.T) {
	repo, ctx, server, grant := seedUserManagedCreationTest(t, 2)
	now := time.Now().UTC()
	creation, err := repo.ReserveUserManagedNodeCreation(ctx, "alice", grant.ID, server.ID,
		"generation-fence", "user-managed-node:expected", now)
	if err != nil {
		t.Fatalf("ReserveUserManagedNodeCreation: %v", err)
	}
	wrongNode, err := repo.CreateNode(ctx, Node{
		Username: "alice", NodeName: "Wrong generation", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: creation.InboundTag,
		InboundMutationID: "user-managed-node:replacement",
		ClashConfig:       `{"name":"Wrong generation","type":"vless","server":"203.0.113.9","port":443,"uuid":"wrong"}`,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	offer, err := repo.CreatePrivateSelfServiceNodeOffer(ctx, wrongNode.ID, *grant, "alice")
	if err != nil {
		t.Fatalf("CreatePrivateSelfServiceNodeOffer: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: creation.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"wrong","email":"alice__generation-fence"}`,
	}); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, creation.InboundTag)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := repo.PreparePackageInboundCredentialCleanup(ctx, *credential, "test")
	if err != nil {
		t.Fatal(err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := repo.RecoverUserManagedNodeCreationLinks(ctx, creation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.NodeID != nil || recovered.OfferID != nil || recovered.SelectionID != nil {
		t.Fatalf("recovery adopted replacement generation: %+v", recovered)
	}
	if _, err := repo.PromoteUserManagedNodeCreation(ctx, creation.ID, wrongNode.ID, offer.ID,
		activation.Selection.ID, cleanup.ID, credential.ID); !errors.Is(err, ErrManagedServerMismatch) {
		t.Fatalf("promotion error=%v want=%v", err, ErrManagedServerMismatch)
	}
}

func TestPromoteUserManagedNodeCreationKeepsDenyWhenRecoveredSelectionWasDeactivated(t *testing.T) {
	repo, ctx, server, grant := seedUserManagedCreationTest(t, 2)
	now := time.Now().UTC()
	creation, err := repo.ReserveUserManagedNodeCreation(ctx, "alice", grant.ID, server.ID,
		"deactivated-recovery", "user-managed-node:deactivated", now)
	if err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, Node{
		Username: "alice", NodeName: "Deactivated recovery", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: creation.InboundTag, InboundMutationID: creation.MutationID,
		ClashConfig: `{"name":"Deactivated recovery","type":"vless","server":"203.0.113.9","port":443,"uuid":"private"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := repo.CreatePrivateSelfServiceNodeOffer(ctx, node.ID, *grant, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: creation.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"private","email":"alice__deactivated-recovery"}`,
	}); err != nil {
		t.Fatal(err)
	}
	credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, creation.InboundTag)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := repo.PreparePackageInboundCredentialCleanup(ctx, *credential, "test")
	if err != nil {
		t.Fatal(err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DeactivateUserNodeSelection(ctx, "alice", activation.Selection.ID,
		"alice", ManagedSuspendAdminDisabled, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.PromoteUserManagedNodeCreation(ctx, creation.ID, node.ID, offer.ID,
		activation.Selection.ID, cleanup.ID, credential.ID); !errors.Is(err, ErrManagedServerMismatch) {
		t.Fatalf("promotion error=%v want=%v", err, ErrManagedServerMismatch)
	}
	if source, err := repo.GetUserInboundAccessSource(ctx, cleanup.ID); err != nil ||
		source.DesiredState != ManagedDesiredInactive {
		t.Fatalf("deny tombstone was removed after deactivation: source=%+v err=%v", source, err)
	}
	current, err := repo.GetUserManagedNodeCreation(ctx, creation.ID)
	if err != nil || current.State != UserManagedNodeCreating {
		t.Fatalf("failed promotion changed creation unexpectedly: current=%+v err=%v", current, err)
	}
}
