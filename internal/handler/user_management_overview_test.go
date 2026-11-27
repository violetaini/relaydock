package handler

import (
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestManagementOverviewDeduplicatesPackageExpiryAndNestedUsage(t *testing.T) {
	now := time.Date(2026, 11, 27, 4, 0, 0, 0, time.UTC)
	end := now.Add(5 * 24 * time.Hour)
	user := storage.User{Username: "alice", IsActive: true, PackageID: 1}
	resources := []managementResourceUsage{
		{Kind: "package", ID: 1, Name: "标准套餐", Source: "package", Related: true, Used: 900, ExpiresAt: &end},
		{Kind: "server", ID: 2, ServerID: 2, Name: "香港", Source: "package", Used: 80, Limit: 100, ExpiresAt: &end, State: "active"},
		{Kind: "node", ID: 3, ServerID: 2, Name: "香港所选节点", Source: "server", Related: true, Used: 80, ExpiresAt: &end, State: "active"},
		{Kind: "node", ID: 4, ServerID: 3, Name: "日本独立节点", Source: "package", Used: 20, Limit: 0, ExpiresAt: &end, State: "authorized"},
		{Kind: "subscription", ID: 5, Name: "关联订阅", Related: true, Used: 100, ExpiresAt: &end, State: "authorized"},
	}
	got := buildManagementOverview(user, 100, resources, now)
	if got.BilledBytes != 100 || got.BillingResources != 2 || len(got.TopUsage) != 2 || got.TopUsage[0].Kind != "server" || got.TopUsage[1].ID != 4 {
		t.Fatalf("overlapping totals/ranking: %+v", got)
	}
	if got.NearLimit != 1 || got.OverLimit != 0 || got.LimitedResources != 1 {
		t.Fatalf("quota: %+v", got)
	}
	if got.Expiry == nil || got.Expiry.Kind != "package" || got.Expiry.Days != 5 {
		t.Fatalf("expiry: %+v", got.Expiry)
	}
	count := 0
	for _, alert := range got.Alerts {
		if alert.Code == "expiring" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one package expiry reminder: %+v", got.Alerts)
	}
}

func TestManagementOverviewPrefersUpcomingExpiryAndKeepsPastExpiryAlert(t *testing.T) {
	now := time.Date(2026, 11, 27, 4, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(12*time.Hour)
	got := buildManagementOverview(storage.User{Username: "alice", IsActive: true}, 0, []managementResourceUsage{
		{Kind: "server", ID: 1, Name: "已到期", ExpiresAt: &past},
		{Kind: "server", ID: 2, Name: "明天到期", ExpiresAt: &future},
	}, now)
	if got.Expiry == nil || got.Expiry.ID != 2 || got.Expiry.Expired || got.Expiry.Days != 1 {
		t.Fatalf("nearest future expiry: %+v", got.Expiry)
	}
	if len(got.Alerts) != 2 || got.Alerts[0].Code != "expired" {
		t.Fatalf("past expiry must remain actionable: %+v", got.Alerts)
	}
}

func TestManagementOverviewUnknownReceiptIsNotProvisionFailure(t *testing.T) {
	user := storage.User{Username: "alice", IsActive: true}
	now := time.Now()
	got := buildManagementOverview(user, 0, []managementResourceUsage{{Kind: "node", ID: 1, Name: "待确认", State: "unknown"}}, now)
	if got.Unconfirmed != 1 || len(got.Alerts) != 0 {
		t.Fatalf("unknown must not become delivery failure: %+v", got)
	}
	got = buildManagementOverview(user, 0, []managementResourceUsage{{Kind: "node", ID: 1, Name: "失败", State: "unknown", ProvisionError: true}}, now)
	if len(got.Alerts) != 1 || got.Alerts[0].Code != "provision_failed" {
		t.Fatalf("recorded failure missing: %+v", got)
	}
}

func TestManagementConnectionsRequireFreshSupportedReportsAndCorrectOwnership(t *testing.T) {
	now := time.Date(2026, 11, 27, 4, 0, 0, 0, time.UTC)
	a, b := int64(880001), int64(880002)
	defer managementConnectionReports.Delete(a)
	defer managementConnectionReports.Delete(b)
	user := storage.User{Username: "alice", IsActive: true, CreatedAt: now.Add(-time.Hour)}
	resources := []managementResourceUsage{{Kind: "node", ID: 1, ServerID: a}, {Kind: "node", ID: 2, ServerID: b}, {Kind: "server", ID: b, ServerID: b}}
	got := managementUserActivity(user, resources, now)
	if got.Connections != nil || got.ActiveNodes != nil || got.Complete {
		t.Fatalf("missing reports fabricated a zero: %+v", got)
	}
	recordManagementConnections(a, map[string]int64{"alice|1": 3, "bob|1": 100, "alice|999": 100, "alice|2": 100}, now)
	recordManagementConnections(b, map[string]int64{"alice|2": 5}, now.Add(-2*time.Minute))
	got = managementUserActivity(user, resources, now)
	if got.Connections == nil || *got.Connections != 3 || *got.ActiveNodes != 1 || got.Complete || got.ReportingServers != 1 {
		t.Fatalf("stale/cross-user/cross-server data included: %+v", got)
	}
	recordManagementConnections(b, map[string]int64{}, now)
	got = managementUserActivity(user, resources, now)
	if !got.Complete || *got.Connections != 3 {
		t.Fatalf("explicit empty report must confirm zero: %+v", got)
	}
	recordManagementConnections(a, nil, now)
	got = managementUserActivity(user, resources, now)
	if got.Complete || *got.Connections != 0 || got.ReportingServers != 1 {
		t.Fatalf("unsupported payload retained old connections: %+v", got)
	}
}

func TestManagementResetLabelHonorsDisabledQuarterlyAndYearlyPolicies(t *testing.T) {
	cases := []struct {
		enabled bool
		period  string
		want    string
	}{{false, "monthly", "不自动重置"}, {true, "monthly", "每月 7 日重置"}, {true, "quarterly", "每季度首月 7 日重置"}, {true, "yearly", "每年 1 月 7 日重置"}}
	for _, c := range cases {
		got := managementFixedResetLabel(storage.User{IsReset: c.enabled, ResetDay: 7, NodeTrafficResetPeriod: c.period})
		if got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

func TestManagementSourceFailureRequiresAnUnacknowledgedGeneration(t *testing.T) {
	source := storage.UserInboundAccessSource{DesiredState: storage.ManagedDesiredActive, Generation: 3, AppliedGeneration: 2, LastError: "agent unavailable"}
	if !managementSourceFailed(source) {
		t.Fatal("current failure was lost")
	}
	source.AppliedGeneration = 3
	if managementSourceFailed(source) {
		t.Fatal("old acknowledged error became a current failure")
	}
	source.AppliedGeneration = 0
	source.LastError = ""
	if managementSourceFailed(source) {
		t.Fatal("unknown receipt became a failure")
	}
}
