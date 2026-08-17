package storage

import (
	"testing"
	"time"
)

func TestPrepareUserDisablePersistsRetryAndRetainsCredential(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, _, _ := seedManagedNodesTest(t, repo)
	if err := repo.SaveUserInboundConfig(ctx, UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "wg-disable", Protocol: "wireguard",
		CredentialJSON: `{"publicKey":"test","address":["10.0.0.2/32"]}`,
	}); err != nil {
		t.Fatal(err)
	}

	sources, err := repo.PrepareUserDisable(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].DesiredState != ManagedDesiredInactive ||
		sources[0].ObservedState != ManagedObservedActive ||
		sources[0].SuspendReason != ManagedSuspendUserDisabled {
		t.Fatalf("prepared disable sources=%#v", sources)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil || user.IsActive {
		t.Fatalf("disabled user active=%v err=%v", user.IsActive, err)
	}
	pending, err := repo.IsUserDisablePending(ctx, "alice")
	if err != nil || !pending {
		t.Fatalf("disable pending=%v err=%v", pending, err)
	}
	if err := repo.UpdateUserStatus(ctx, "alice", true); err != ErrUserDisablePending {
		t.Fatalf("enable during pending revoke error=%v", err)
	}

	repeated, err := repo.PrepareUserDisable(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(repeated) != 1 || repeated[0].Generation != sources[0].Generation {
		t.Fatalf("repeated disable changed pending generation: first=%#v repeated=%#v", sources, repeated)
	}
	if _, err := repo.MarkUserInboundAccessSourceApplied(ctx, sources[0].ID, sources[0].Generation,
		ManagedObservedInactive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	pending, err = repo.IsUserDisablePending(ctx, "alice")
	if err != nil || pending {
		t.Fatalf("completed disable pending=%v err=%v", pending, err)
	}
	if _, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "wg-disable"); err != nil {
		t.Fatalf("completed disable removed stable credential: %v", err)
	}
	if err := repo.UpdateUserStatus(ctx, "alice", true); err != nil {
		t.Fatalf("enable after completed revoke: %v", err)
	}
}
