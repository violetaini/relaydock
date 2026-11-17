package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestTrafficSummaryUnlimitedServersReportRealUsed(t *testing.T) {
	ctx := context.Background()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic-summary.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	if err := repo.CreateUser(ctx, "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	server := &storage.RemoteServer{
		Name:          "unlimited-server",
		Token:         "unlimited-token",
		TrafficLimit:  0, // unlimited
		TrafficSource: "system",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}

	// Upsert twice: first sets baseline, second adds delta (5 GB RX + 5 GB TX = 10 GB)
	const gigabyte = 1024 * 1024 * 1024
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, server.ID, 0, 0, 100); err != nil {
		t.Fatalf("UpsertRemoteServerSystemTraffic baseline: %v", err)
	}
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, server.ID, 5*gigabyte, 5*gigabyte, 100); err != nil {
		t.Fatalf("UpsertRemoteServerSystemTraffic: %v", err)
	}

	h := NewTrafficSummaryHandler(repo)
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/summary", nil)
	req = req.WithContext(auth.ContextWithUsername(ctx, "admin"))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}

	var resp struct {
		Metrics struct {
			TotalLimitGB     float64 `json:"total_limit_gb"`
			TotalUsedGB      float64 `json:"total_used_gb"`
			TotalRemainingGB float64 `json:"total_remaining_gb"`
			UsagePercentage  float64 `json:"usage_percentage"`
			UnlimitedUsedGB  float64 `json:"unlimited_used_gb"`
		} `json:"metrics"`
		History []struct {
			Date   string  `json:"date"`
			UsedGB float64 `json:"used_gb"`
		} `json:"history"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Metrics.TotalUsedGB < 9.9 || resp.Metrics.TotalUsedGB > 10.1 {
		t.Fatalf("TotalUsedGB = %f, want ~10.0", resp.Metrics.TotalUsedGB)
	}
	if resp.Metrics.UnlimitedUsedGB < 9.9 || resp.Metrics.UnlimitedUsedGB > 10.1 {
		t.Fatalf("UnlimitedUsedGB = %f, want ~10.0", resp.Metrics.UnlimitedUsedGB)
	}
	if len(resp.History) == 0 {
		t.Fatal("expected history snapshot to be recorded and returned for unlimited server, got empty")
	}
}

func TestTrafficSummaryMixedUnlimitedAndLimitedServersIncludeUnlimitedInTotalUsed(t *testing.T) {
	ctx := context.Background()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic-summary-mixed.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	defer repo.Close()

	if err := repo.CreateUser(ctx, "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	const gigabyte = 1024 * 1024 * 1024

	// Server 1: Limited to 50 GB, used 10 GB
	srvLimited := &storage.RemoteServer{
		Name:          "limited-server",
		Token:         "limited-token",
		TrafficLimit:  50 * gigabyte,
		TrafficSource: "system",
	}
	if err := repo.CreateRemoteServer(ctx, srvLimited); err != nil {
		t.Fatalf("CreateRemoteServer limited: %v", err)
	}
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, srvLimited.ID, 0, 0, 100); err != nil {
		t.Fatalf("UpsertRemoteServerSystemTraffic baseline: %v", err)
	}
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, srvLimited.ID, 5*gigabyte, 5*gigabyte, 100); err != nil {
		t.Fatalf("UpsertRemoteServerSystemTraffic: %v", err)
	}

	// Server 2: Unlimited (TrafficLimit = 0), used 20 GB
	srvUnlimited := &storage.RemoteServer{
		Name:          "unlimited-server",
		Token:         "unlimited-token",
		TrafficLimit:  0,
		TrafficSource: "system",
	}
	if err := repo.CreateRemoteServer(ctx, srvUnlimited); err != nil {
		t.Fatalf("CreateRemoteServer unlimited: %v", err)
	}
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, srvUnlimited.ID, 0, 0, 100); err != nil {
		t.Fatalf("UpsertRemoteServerSystemTraffic baseline: %v", err)
	}
	if err := repo.UpsertRemoteServerSystemTraffic(ctx, srvUnlimited.ID, 10*gigabyte, 10*gigabyte, 100); err != nil {
		t.Fatalf("UpsertRemoteServerSystemTraffic: %v", err)
	}

	h := NewTrafficSummaryHandler(repo)
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/summary", nil)
	req = req.WithContext(auth.ContextWithUsername(ctx, "admin"))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}

	var resp struct {
		Metrics struct {
			TotalLimitGB     float64 `json:"total_limit_gb"`
			TotalUsedGB      float64 `json:"total_used_gb"`
			TotalRemainingGB float64 `json:"total_remaining_gb"`
			UsagePercentage  float64 `json:"usage_percentage"`
			UnlimitedUsedGB  float64 `json:"unlimited_used_gb"`
		} `json:"metrics"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// TotalUsedGB must include both limited (10 GB) and unlimited (20 GB) = 30 GB
	if resp.Metrics.TotalUsedGB < 29.9 || resp.Metrics.TotalUsedGB > 30.1 {
		t.Fatalf("TotalUsedGB = %f, want ~30.0", resp.Metrics.TotalUsedGB)
	}
	// TotalLimitGB corresponds to the limited server quota = 50 GB
	if resp.Metrics.TotalLimitGB < 49.9 || resp.Metrics.TotalLimitGB > 50.1 {
		t.Fatalf("TotalLimitGB = %f, want ~50.0", resp.Metrics.TotalLimitGB)
	}
	// UnlimitedUsedGB = 20 GB
	if resp.Metrics.UnlimitedUsedGB < 19.9 || resp.Metrics.UnlimitedUsedGB > 20.1 {
		t.Fatalf("UnlimitedUsedGB = %f, want ~20.0", resp.Metrics.UnlimitedUsedGB)
	}
	// TotalRemainingGB = 40 GB (50 GB limit - 10 GB used on limited)
	if resp.Metrics.TotalRemainingGB < 39.9 || resp.Metrics.TotalRemainingGB > 40.1 {
		t.Fatalf("TotalRemainingGB = %f, want ~40.0", resp.Metrics.TotalRemainingGB)
	}
	// UsagePercentage = 20.0% (10 GB / 50 GB * 100)
	if resp.Metrics.UsagePercentage < 19.9 || resp.Metrics.UsagePercentage > 20.1 {
		t.Fatalf("UsagePercentage = %f, want ~20.0", resp.Metrics.UsagePercentage)
	}
}
