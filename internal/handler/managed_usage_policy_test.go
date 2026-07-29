package handler

import (
	"context"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestManagedUsageSyncStopsAfterSelectionDeactivation(t *testing.T) {
	fixture := newManagedUserHTTPFixture(t, "alice")
	ctx := context.Background()
	email := "alice__" + fixture.offer.InboundTag
	if err := fixture.repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: fixture.offer.ServerID, InboundTag: fixture.offer.InboundTag,
		Protocol: "vless", CredentialJSON: `{"id":"alice-id","email":"` + email + `"}`,
	}); err != nil {
		t.Fatalf("SaveUserInboundConfig: %v", err)
	}
	now := time.Now().UTC()
	if err := fixture.repo.UpsertUserEmailTraffic(ctx, fixture.offer.ServerID, email, 100, 100, false); err != nil {
		t.Fatalf("insert traffic baseline: %v", err)
	}
	fixture.handler.syncManagedUsage(ctx, now)
	if err := fixture.repo.UpsertUserEmailTraffic(ctx, fixture.offer.ServerID, email, 200, 300, false); err != nil {
		t.Fatalf("update traffic: %v", err)
	}
	fixture.handler.syncManagedUsage(ctx, now.Add(time.Second))
	usage, err := fixture.repo.GetUserNodeSelectionUsage(ctx, fixture.activation.Selection.ID)
	if err != nil {
		t.Fatalf("GetUserNodeSelectionUsage: %v", err)
	}
	if usage.UplinkBytes != 100 || usage.DownlinkBytes != 200 {
		t.Fatalf("active usage = up:%d down:%d, want up:100 down:200", usage.UplinkBytes, usage.DownlinkBytes)
	}
	if _, err := fixture.repo.DeactivateUserNodeSelection(ctx, "alice", fixture.activation.Selection.ID, "alice",
		storage.ManagedSuspendUserDisabled, now.Add(2*time.Second)); err != nil {
		t.Fatalf("DeactivateUserNodeSelection: %v", err)
	}
	if err := fixture.repo.UpsertUserEmailTraffic(ctx, fixture.offer.ServerID, email, 500, 800, false); err != nil {
		t.Fatalf("update inactive traffic: %v", err)
	}
	fixture.handler.syncManagedUsage(ctx, now.Add(3*time.Second))
	usage, err = fixture.repo.GetUserNodeSelectionUsage(ctx, fixture.activation.Selection.ID)
	if err != nil {
		t.Fatalf("GetUserNodeSelectionUsage after deactivation: %v", err)
	}
	if usage.UplinkBytes != 100 || usage.DownlinkBytes != 200 {
		t.Fatalf("inactive selection accrued usage: up:%d down:%d", usage.UplinkBytes, usage.DownlinkBytes)
	}
}

func TestHistoricalOverlapLimiterUsesStrictestPositiveLimits(t *testing.T) {
	if got := strictestPositiveFloat(50, 20); got != 20 {
		t.Fatalf("strictestPositiveFloat(50, 20) = %v, want 20", got)
	}
	if got := strictestPositiveFloat(0, 20); got != 20 {
		t.Fatalf("strictestPositiveFloat(0, 20) = %v, want 20", got)
	}
	if got := strictestPositiveFloat(50, 0); got != 50 {
		t.Fatalf("strictestPositiveFloat(50, 0) = %v, want 50", got)
	}
	if got := strictestPositiveInt(4, 2); got != 2 {
		t.Fatalf("strictestPositiveInt(4, 2) = %v, want 2", got)
	}
	if got := strictestPositiveInt(0, 2); got != 2 {
		t.Fatalf("strictestPositiveInt(0, 2) = %v, want 2", got)
	}
}
