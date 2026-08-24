package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func resetTime(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 12, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
}

func TestPackageCreateRejectsInvalidNodeTrafficResetPeriod(t *testing.T) {
	t.Parallel()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "invalid-reset-period.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	request := httptest.NewRequest(http.MethodPost, "/api/admin/packages/create", strings.NewReader(`{
		"name":"invalid-period","cycle_days":30,"is_reset":true,"reset_day":1,
		"node_traffic_reset_period":"weekly","nodes":[]
	}`))
	response := httptest.NewRecorder()
	NewPackageCreateHandler(repo).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestPackageUpdatePreservesOmittedNodeTrafficResetPeriod(t *testing.T) {
	t.Parallel()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "preserve-reset-period.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	packageID, err := repo.CreatePackage(t.Context(), storage.Package{
		Name: "quarterly", CycleDays: 90, IsReset: true, ResetDay: 12,
		NodeTrafficResetPeriod: storage.NodeTrafficResetQuarterly,
	})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/admin/packages/update", strings.NewReader(`{
		"id":`+fmt.Sprint(packageID)+`,"name":"quarterly","cycle_days":90,"nodes":[]
	}`))
	response := httptest.NewRecorder()
	NewPackageUpdateHandler(repo, nil, nil).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	stored, err := repo.GetPackage(t.Context(), packageID)
	if err != nil || stored.NodeTrafficResetPeriod != storage.NodeTrafficResetQuarterly {
		t.Fatalf("stored package=%+v err=%v", stored, err)
	}
}

func TestShouldResetNaturalPeriod(t *testing.T) {
	t.Parallel()
	monthlyBoundary := resetTime(2028, time.February, 29)
	quarterlyBoundary := resetTime(2027, time.April, 30)
	quarterlyEarlierReset := resetTime(2027, time.April, 1)
	yearlyBoundary := resetTime(2027, time.January, 8)

	tests := []struct {
		name    string
		now     time.Time
		enabled bool
		day     int
		period  string
		last    *time.Time
		want    bool
	}{
		{name: "disabled", now: monthlyBoundary, enabled: false, day: 29, period: storage.NodeTrafficResetMonthly, want: false},
		{name: "invalid day", now: monthlyBoundary, enabled: true, day: 32, period: storage.NodeTrafficResetMonthly, want: false},
		{name: "invalid period", now: monthlyBoundary, enabled: true, day: 29, period: "weekly", want: false},
		{name: "monthly clamps leap February", now: monthlyBoundary, enabled: true, day: 31, period: storage.NodeTrafficResetMonthly, want: true},
		{name: "monthly before boundary", now: resetTime(2028, time.February, 28), enabled: true, day: 31, period: storage.NodeTrafficResetMonthly, want: false},
		{name: "monthly already reset", now: resetTime(2028, time.February, 29), enabled: true, day: 31, period: storage.NodeTrafficResetMonthly, last: &monthlyBoundary, want: false},
		{name: "quarter clamps April", now: quarterlyBoundary, enabled: true, day: 31, period: storage.NodeTrafficResetQuarterly, want: true},
		{name: "quarter catches up in later month", now: resetTime(2027, time.May, 12), enabled: true, day: 30, period: storage.NodeTrafficResetQuarterly, want: true},
		{name: "quarter already reset", now: resetTime(2027, time.June, 20), enabled: true, day: 30, period: storage.NodeTrafficResetQuarterly, last: &quarterlyBoundary, want: false},
		{name: "quarter day change does not reset twice", now: quarterlyBoundary, enabled: true, day: 30, period: storage.NodeTrafficResetQuarterly, last: &quarterlyEarlierReset, want: false},
		{name: "year before January boundary", now: resetTime(2027, time.January, 7), enabled: true, day: 8, period: storage.NodeTrafficResetYearly, want: false},
		{name: "year catches up after January", now: resetTime(2027, time.March, 1), enabled: true, day: 8, period: storage.NodeTrafficResetYearly, want: true},
		{name: "year already reset", now: resetTime(2027, time.December, 31), enabled: true, day: 8, period: storage.NodeTrafficResetYearly, last: &yearlyBoundary, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldResetNaturalPeriod(test.now, test.enabled, test.day, test.period, test.last); got != test.want {
				t.Fatalf("shouldResetNaturalPeriod()=%v want=%v", got, test.want)
			}
		})
	}
}
