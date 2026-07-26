package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestLineSpeedTestResultLifecycle(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "line-speedtest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	id, err := repo.InsertLineSpeedTestResult(context.Background(), LineSpeedTestResult{
		TargetKind:     LineSpeedTargetMaster,
		ServerName:     "主控本机",
		Status:         LineSpeedStatusRunning,
		Implementation: "Ookla Speedtest CLI 1.2.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := repo.GetLineSpeedTestResult(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != LineSpeedStatusRunning || created.CreatedAt.IsZero() || created.CompletedAt != nil {
		t.Fatalf("unexpected running job: %#v", created)
	}

	jitter, loss := 1.25, 0.5
	if err := repo.CompleteLineSpeedTestResult(context.Background(), id, LineSpeedTestResult{
		PingMS:            13.5,
		DownloadMbps:      800.25,
		UploadMbps:        100.75,
		JitterMS:          &jitter,
		PacketLossPercent: &loss,
		ISP:               "Example ISP",
		EgressIP:          "203.0.113.8",
		TestServer:        "Example Test",
		ServerLocation:    "Shanghai, China",
		Implementation:    "Ookla Speedtest CLI 1.2.0",
	}); err != nil {
		t.Fatal(err)
	}
	completed, err := repo.GetLineSpeedTestResult(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != LineSpeedStatusOK || completed.CompletedAt == nil || completed.DownloadMbps != 800.25 {
		t.Fatalf("unexpected completed job: %#v", completed)
	}
	if completed.JitterMS == nil || *completed.JitterMS != jitter || completed.PacketLossPercent == nil || *completed.PacketLossPercent != loss {
		t.Fatalf("optional metrics were not preserved: %#v", completed)
	}
	if err := repo.FailLineSpeedTestResult(context.Background(), id, "late failure"); !errors.Is(err, ErrLineSpeedTestNotRunning) {
		t.Fatalf("second completion error=%v", err)
	}

	items, err := repo.ListLineSpeedTestResults(context.Background(), LineSpeedTargetMaster, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != id {
		t.Fatalf("unexpected result list: %#v", items)
	}
	if err := repo.DeleteLineSpeedTestResult(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetLineSpeedTestResult(context.Background(), id); !errors.Is(err, ErrLineSpeedTestNotFound) {
		t.Fatalf("Get deleted error=%v", err)
	}
}

func TestLineSpeedTestUnavailableMetricsRemainNull(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "line-speedtest-null.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	id, err := repo.InsertLineSpeedTestResult(context.Background(), LineSpeedTestResult{
		TargetKind: LineSpeedTargetRemote,
		ServerID:   7,
		ServerName: "edge-7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteLineSpeedTestResult(context.Background(), id, LineSpeedTestResult{
		PingMS: 10, DownloadMbps: 20, UploadMbps: 5,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := repo.GetLineSpeedTestResult(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if result.JitterMS != nil || result.PacketLossPercent != nil {
		t.Fatalf("NULL metrics became values: %#v", result)
	}
}

func TestLineSpeedTestRunningJobFailsClosedAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "line-speedtest-restart.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := repo.InsertLineSpeedTestResult(context.Background(), LineSpeedTestResult{
		TargetKind: LineSpeedTargetMaster,
		ServerName: "主控本机",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result, err := reopened.GetLineSpeedTestResult(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != LineSpeedStatusFailed || result.CompletedAt == nil || !strings.Contains(result.Error, "主控重启") {
		t.Fatalf("stale task was not failed closed: %#v", result)
	}
}

func TestLineSpeedTestTargetValidation(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "line-speedtest-validation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	for _, input := range []LineSpeedTestResult{
		{TargetKind: LineSpeedTargetMaster, ServerID: 9},
		{TargetKind: LineSpeedTargetRemote},
		{TargetKind: "other"},
	} {
		if _, err := repo.InsertLineSpeedTestResult(context.Background(), input); err == nil {
			t.Fatalf("accepted invalid target %#v", input)
		}
	}
}

func TestListLatestSuccessfulLineSpeedTestResultsIgnoresLaterFailures(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "line-speedtest-latest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()

	insertCompleted := func(kind string, serverID int64, download float64) int64 {
		t.Helper()
		id, insertErr := repo.InsertLineSpeedTestResult(ctx, LineSpeedTestResult{
			TargetKind: kind,
			ServerID:   serverID,
			ServerName: kind,
		})
		if insertErr != nil {
			t.Fatal(insertErr)
		}
		if completeErr := repo.CompleteLineSpeedTestResult(ctx, id, LineSpeedTestResult{DownloadMbps: download}); completeErr != nil {
			t.Fatal(completeErr)
		}
		return id
	}

	insertCompleted(LineSpeedTargetMaster, 0, 100)
	masterLatestID := insertCompleted(LineSpeedTargetMaster, 0, 200)
	failedID, err := repo.InsertLineSpeedTestResult(ctx, LineSpeedTestResult{
		TargetKind: LineSpeedTargetMaster,
		ServerName: "master",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.FailLineSpeedTestResult(ctx, failedID, "network failed"); err != nil {
		t.Fatal(err)
	}
	remoteLatestID := insertCompleted(LineSpeedTargetRemote, 7, 300)

	results, err := repo.ListLatestSuccessfulLineSpeedTestResults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("latest result count=%d, want 2: %#v", len(results), results)
	}
	got := make(map[string]LineSpeedTestResult, len(results))
	for _, result := range results {
		got[result.TargetKind] = result
	}
	if got[LineSpeedTargetMaster].ID != masterLatestID || got[LineSpeedTargetMaster].DownloadMbps != 200 {
		t.Fatalf("master latest=%#v", got[LineSpeedTargetMaster])
	}
	if got[LineSpeedTargetRemote].ID != remoteLatestID || got[LineSpeedTargetRemote].DownloadMbps != 300 {
		t.Fatalf("remote latest=%#v", got[LineSpeedTargetRemote])
	}

	jobs, err := repo.ListLatestLineSpeedTestJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("latest job count=%d, want 2: %#v", len(jobs), jobs)
	}
	latestJobs := make(map[string]LineSpeedTestResult, len(jobs))
	for _, job := range jobs {
		latestJobs[job.TargetKind] = job
	}
	if latestJobs[LineSpeedTargetMaster].ID != failedID || latestJobs[LineSpeedTargetMaster].Status != LineSpeedStatusFailed {
		t.Fatalf("master latest job=%#v", latestJobs[LineSpeedTargetMaster])
	}
	if latestJobs[LineSpeedTargetRemote].ID != remoteLatestID || latestJobs[LineSpeedTargetRemote].Status != LineSpeedStatusOK {
		t.Fatalf("remote latest job=%#v", latestJobs[LineSpeedTargetRemote])
	}
}
