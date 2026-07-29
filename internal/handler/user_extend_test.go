package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestUserExtendPreservesDisabledMonthlyReset(t *testing.T) {
	repo, _, remote := newPackageLeaseFixture(t, &packageLeaseAgent{})
	ctx := context.Background()
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name:              "extend-reset-policy",
		TrafficLimitBytes: 1024,
		CycleDays:         30,
		IsReset:           true,
		ResetDay:          8,
		Nodes:             []int64{},
	})
	if err != nil {
		t.Fatal(err)
	}

	assign := NewPackageAssignHandler(repo, remote, nil)
	if _, err := assign.AssignAndProvision(ctx, "alice", packageID, time.Now(), time.Now().AddDate(0, 0, 30), false, 1); err != nil {
		t.Fatalf("assign package with reset disabled: %v", err)
	}

	handler := NewUserExtendHandler(assign)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/extend", strings.NewReader(`{"username":"alice","days":30}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("extend status=%d body=%s", rec.Code, rec.Body.String())
	}

	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.IsReset {
		t.Fatal("quick renewal unexpectedly re-enabled monthly traffic reset")
	}
}

func TestResolveTGResetPolicyPreservesOverridesAndPackageDefaults(t *testing.T) {
	now := time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC)
	pkg := &storage.Package{ID: 9, IsReset: true, ResetDay: 8}

	if enabled, day := resolveTGResetPolicy(pkg, nil, now); !enabled || day != 8 {
		t.Fatalf("new binding enabled=%v day=%d, want package default true/8", enabled, day)
	}
	current := &storage.User{PackageID: 9, IsReset: false, ResetDay: 17}
	if enabled, day := resolveTGResetPolicy(pkg, current, now); enabled || day != 17 {
		t.Fatalf("same-package renewal enabled=%v day=%d, want user override false/17", enabled, day)
	}
	current.PackageID = 7
	if enabled, day := resolveTGResetPolicy(pkg, current, now); !enabled || day != 8 {
		t.Fatalf("package switch enabled=%v day=%d, want target default true/8", enabled, day)
	}
}
