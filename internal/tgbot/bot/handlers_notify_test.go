package bot

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

func TestBroadcastAnnouncementsTracksRecipientsAndContinuesAfterFailure(t *testing.T) {
	items := []mmwxclient.Announcement{
		{ID: 1, Body: "first", Recipients: []int64{101, 102, 103}},
		{ID: 2, Body: "second", Recipients: []int64{201}},
	}
	var sendCalls []int64
	type delivery struct {
		announcementID int64
		telegramID     int64
	}
	var recipientDeliveries []delivery
	var completed []int64

	broadcastAnnouncements(context.Background(), items,
		func(_ context.Context, telegramID int64, _ string) error {
			sendCalls = append(sendCalls, telegramID)
			if telegramID == 102 {
				return errors.New("temporary Telegram failure")
			}
			return nil
		},
		func(_ context.Context, announcementID, telegramID int64) error {
			recipientDeliveries = append(recipientDeliveries, delivery{announcementID, telegramID})
			return nil
		},
		func(_ context.Context, announcementID int64) error {
			completed = append(completed, announcementID)
			return nil
		},
	)

	if want := []int64{101, 102, 103, 201}; !reflect.DeepEqual(sendCalls, want) {
		t.Fatalf("send calls = %v, want %v", sendCalls, want)
	}
	if want := []delivery{{1, 101}, {1, 103}, {2, 201}}; !reflect.DeepEqual(recipientDeliveries, want) {
		t.Fatalf("recipient deliveries = %v, want %v", recipientDeliveries, want)
	}
	if want := []int64{2}; !reflect.DeepEqual(completed, want) {
		t.Fatalf("completed announcements = %v, want %v", completed, want)
	}
}

func TestBroadcastAnnouncementsStopsBeforeWorkWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	called := false
	broadcastAnnouncements(ctx,
		[]mmwxclient.Announcement{{ID: 1, Body: "first", Recipients: []int64{101}}},
		func(context.Context, int64, string) error {
			called = true
			return context.Canceled
		},
		func(context.Context, int64, int64) error {
			called = true
			return context.Canceled
		},
		func(context.Context, int64) error {
			called = true
			return context.Canceled
		},
	)

	if called {
		t.Fatal("broadcast performed work after its context was canceled")
	}
}
