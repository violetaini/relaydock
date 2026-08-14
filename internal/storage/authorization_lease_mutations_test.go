package storage

import (
	"context"
	"testing"
	"time"
)

func TestUserAuthorizationLeaseBlocksManualGrantMutationUntilRelease(t *testing.T) {
	fixture := newAuthorizationModeFixture(t)
	heldCtx, release, err := fixture.repo.AcquireUserAuthorizationLease(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	// Coordinators pass the leased context through the storage graph, so nested
	// mutations for the same account must remain re-entrant.
	_, releaseNested, err := fixture.repo.AcquireUserAuthorizationLease(heldCtx, "alice")
	if err != nil {
		t.Fatalf("nested authorization lease: %v", err)
	}
	releaseNested()

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, _, grantErr := fixture.repo.UpsertManualUserNodeGrant(
			context.Background(), "alice", fixture.nodeID, nil, "admin",
		)
		done <- grantErr
	}()
	<-started

	select {
	case grantErr := <-done:
		t.Fatalf("manual grant completed while authorization lease was held: %v", grantErr)
	case <-time.After(100 * time.Millisecond):
	}

	release()
	released = true
	select {
	case grantErr := <-done:
		if grantErr != nil {
			t.Fatalf("manual grant after authorization lease release: %v", grantErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("manual grant remained blocked after authorization lease release")
	}
}

func TestPackageAuthorizationLeaseIsReentrantOrderedAndScoped(t *testing.T) {
	fixture := newAuthorizationModeFixture(t)
	ctx := context.Background()
	otherPackageID, err := fixture.repo.CreatePackage(ctx, Package{
		Name: "authorization-package-other", TrafficLimitBytes: 2048, CycleDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}

	heldCtx, release, err := fixture.repo.AcquirePackageAuthorizationLease(ctx, fixture.packageID)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	_, releaseNested, err := fixture.repo.AcquirePackageAuthorizationLease(heldCtx, fixture.packageID)
	if err != nil {
		t.Fatalf("nested package authorization lease: %v", err)
	}
	releaseNested()

	otherDone := make(chan error, 1)
	go func() {
		_, releaseOther, leaseErr := fixture.repo.AcquirePackageAuthorizationLease(ctx, otherPackageID)
		if leaseErr == nil {
			releaseOther()
		}
		otherDone <- leaseErr
	}()
	select {
	case leaseErr := <-otherDone:
		if leaseErr != nil {
			t.Fatalf("unrelated package lease: %v", leaseErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unrelated package lease was blocked by a different package")
	}

	sameDone := make(chan error, 1)
	go func() {
		_, releaseSame, leaseErr := fixture.repo.AcquirePackageAuthorizationLease(ctx, fixture.packageID)
		if leaseErr == nil {
			releaseSame()
		}
		sameDone <- leaseErr
	}()
	select {
	case leaseErr := <-sameDone:
		t.Fatalf("same package lease completed while held: %v", leaseErr)
	case <-time.After(100 * time.Millisecond):
	}

	release()
	released = true
	select {
	case leaseErr := <-sameDone:
		if leaseErr != nil {
			t.Fatalf("same package lease after release: %v", leaseErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("same package lease remained blocked after release")
	}

	userCtx, releaseUser, err := fixture.repo.AcquireUserAuthorizationLease(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseUser()
	if _, releaseOutOfOrder, leaseErr := fixture.repo.AcquirePackageAuthorizationLease(userCtx, fixture.packageID); leaseErr == nil {
		releaseOutOfOrder()
		t.Fatal("package lease acquired after user lease")
	}
}
