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
