package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestPackageSubscriptionHeaderIsAbsentWithoutAggregateTotal(t *testing.T) {
	repo, user, pkg := newUserTrafficLimitTestRepo(t)
	ctx := context.Background()
	server := &storage.RemoteServer{Name: "cycle-edge", Token: "cycle-edge-token"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	record := func(uplink int64) {
		t.Helper()
		if err := repo.UpsertUserTrafficBatch(ctx, server.ID, []storage.UserTrafficSample{{
			Email: "alice__cycle", Username: "alice", Uplink: uplink, BillingMultiplier: 1,
		}}, false); err != nil {
			t.Fatal(err)
		}
	}
	record(100)
	record(250)

	handler := &PackageSubscribeHandler{repo: repo}
	response := httptest.NewRecorder()
	handler.writeTrafficHeader(ctx, response, user, pkg)
	if got := response.Header().Get("subscription-userinfo"); got != "" {
		t.Fatalf("subscription-userinfo = %q, want no aggregate traffic header", got)
	}

	if err := repo.ResetUserTrafficCycle(ctx, user.Username); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.writeTrafficHeader(ctx, response, user, pkg)
	if got := response.Header().Get("subscription-userinfo"); got != "" {
		t.Fatalf("subscription-userinfo after reset = %q, want no aggregate traffic header", got)
	}
}
