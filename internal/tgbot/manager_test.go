package tgbot

import (
	"context"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestManagerDisabledSettingsRoundTripPreservesMaskedToken(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "arcway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	const token = "123456789:AAExampleToken"
	if err := repo.SetSystemSetting(ctx, settingToken, token); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(repo, nil, http.NotFoundHandler())
	masked := manager.Load(ctx, false).BotToken
	if masked == token || masked == "" {
		t.Fatalf("masked token = %q", masked)
	}

	err = manager.SaveAndRestart(ctx, Settings{
		Enabled:       false,
		BotToken:      masked,
		AdminTGIDs:    []int64{42, 0, -1, 42, 99},
		WebDevPreview: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := manager.Load(ctx, true)
	if got.BotToken != token {
		t.Fatalf("token = %q, want original token", got.BotToken)
	}
	if want := []int64{42, 99}; !reflect.DeepEqual(got.AdminTGIDs, want) {
		t.Fatalf("admin IDs = %v, want %v", got.AdminTGIDs, want)
	}
	if !got.WebDevPreview || got.Enabled || got.Running {
		t.Fatalf("unexpected state: %+v", got)
	}
}

func TestEnsurePublicBaseURLDoesNotOverwriteExplicitSetting(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "arcway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	manager := NewManager(repo, nil, http.NotFoundHandler())
	if err := manager.EnsurePublicBaseURL(ctx, "https://first.example/"); err != nil {
		t.Fatal(err)
	}
	if err := manager.EnsurePublicBaseURL(ctx, "https://second.example"); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetSystemSetting(ctx, "master_url")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://first.example" {
		t.Fatalf("master URL = %q, want first observed URL", got)
	}
}
