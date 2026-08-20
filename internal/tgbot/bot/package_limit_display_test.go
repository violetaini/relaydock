package bot

import (
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

func TestTrafficSummaryOmitsDeprecatedPackageTotal(t *testing.T) {
	pkg := map[string]any{"name": "Detail", "traffic_limit_gb": float64(2000)}
	got := formatTrafficSummary("user", pkg, 1024, 2048, 4096, 8192)
	for _, want := range []string{"套餐: Detail", "本周期已用: 3.00 KB", "累计 ↑4.00 KB ↓8.00 KB"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, "2000") || strings.Contains(got, "%") {
		t.Fatalf("summary still renders deprecated package total: %q", got)
	}
}

func TestUserSummaryOmitsDeprecatedPackageTotal(t *testing.T) {
	pkg := map[string]any{"name": "Detail", "traffic_limit_gb": float64(2000)}
	got := displayUserSummary("user", "user", "", true, pkg, "", 1, 2, 3, 4)
	if !strings.Contains(got, "套餐: Detail") || !strings.Contains(got, "本周期") {
		t.Fatalf("summary lost package or cycle usage: %q", got)
	}
	if strings.Contains(got, "2000") {
		t.Fatalf("summary still renders deprecated package total: %q", got)
	}
}

func TestRegistrationPackageKeepsCycleAndExpiryWithoutTotal(t *testing.T) {
	pkg := map[string]any{
		"package_name":     "Detail",
		"traffic_limit_gb": float64(2000),
		"cycle_days":       float64(30),
		"end_date":         "2026-09-20",
	}
	got := formatRegistrationPackage(pkg)
	if !strings.Contains(got, "套餐:Detail (30 天),到期 2026-09-20") {
		t.Fatalf("package details = %q", got)
	}
	if strings.Contains(got, "2000") {
		t.Fatalf("registration still renders deprecated package total: %q", got)
	}
}

func TestMiniAppOmitsDeprecatedPackageTotals(t *testing.T) {
	for _, obsolete := range []string{"traffic_limit_gb", "limit_gb", "u.traffic_limit", "已用 '+pct"} {
		if strings.Contains(webAppHTML, obsolete) {
			t.Fatalf("Mini App still renders deprecated package total via %q", obsolete)
		}
	}
	for _, want := range []string{"本周期已用", "套餐周期", "p.cycle_days"} {
		if !strings.Contains(webAppHTML, want) {
			t.Fatalf("Mini App lost package detail %q", want)
		}
	}
}

func TestDailyTrafficOmitsDeprecatedPackageTotal(t *testing.T) {
	got := formatDailyTraffic(mmwxclient.NotifyUser{
		Username:       "user",
		PackageName:    "Detail",
		TrafficLimitGB: 2000,
		CycleUplink:    1024,
		CycleDownlink:  2048,
		TotalUplink:    4096,
		TotalDownlink:  8192,
	})
	for _, want := range []string{"套餐: Detail", "本周期已用: 3.00 KB", "累计 ↑4.00 KB ↓8.00 KB"} {
		if !strings.Contains(got, want) {
			t.Fatalf("daily summary %q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, "2000") || strings.Contains(got, "%") {
		t.Fatalf("daily summary still renders deprecated package total: %q", got)
	}
}

func TestPackageChoiceKeepsCycleWithoutDeprecatedTotal(t *testing.T) {
	got := formatPackageChoice(mmwxclient.Package{Name: "Detail", TrafficLimitGB: 2000, CycleDays: 30})
	if got != "Detail (30 天)" {
		t.Fatalf("package choice = %q", got)
	}
}
