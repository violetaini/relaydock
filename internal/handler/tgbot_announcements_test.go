package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestPendingAnnouncementsExcludeDeliveredRecipients(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "announcements.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	packageID, err := repo.CreatePackage(ctx, storage.Package{Name: "Telegram delivery test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []struct {
		username   string
		telegramID int64
	}{
		{username: "alice", telegramID: 1001},
		{username: "bob", telegramID: 1002},
	} {
		if err := repo.CreateUser(ctx, user.username, user.username+"@example.test", user.username, "hash", storage.RoleUser, ""); err != nil {
			t.Fatal(err)
		}
		if err := repo.AssignPackageToUser(ctx, user.username, packageID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), false, 1); err != nil {
			t.Fatal(err)
		}
		if err := repo.BindTelegram(ctx, user.username, user.telegramID, user.username); err != nil {
			t.Fatal(err)
		}
	}
	announcementID, err := repo.CreateAnnouncement(ctx, storage.Announcement{
		Type: "general", Body: "maintenance", ViaBot: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	h := NewTGBotAPIHandler(repo)
	if got := pendingAnnouncementRecipients(t, h); len(got) != 2 {
		t.Fatalf("initial pending recipients = %v", got)
	}

	body, err := json.Marshal(map[string]any{"id": announcementID, "telegram_id": int64(1001)})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/tgbot/announcements/delivered", bytes.NewReader(body))
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("mark recipient status = %d body=%s", response.Code, response.Body.String())
	}

	got := pendingAnnouncementRecipients(t, h)
	if len(got) != 1 || got[0] != 1002 {
		t.Fatalf("pending recipients after delivery = %v, want [1002]", got)
	}
}

func pendingAnnouncementRecipients(t *testing.T, h *TGBotAPIHandler) []int64 {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/admin/tgbot/announcements/pending", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("pending status = %d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Announcements []struct {
			Recipients []int64 `json:"recipients"`
		} `json:"announcements"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Announcements) != 1 {
		t.Fatalf("pending announcements = %+v", payload.Announcements)
	}
	return payload.Announcements[0].Recipients
}
