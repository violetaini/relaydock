package bot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/violetaini/relaydock/internal/tgbot/config"
	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

func TestAuthorizeUpdateAllowsOnlyKnownUsersOrInviteStarts(t *testing.T) {
	var userLookups atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/admin/tgbot/user-by-tg":
			userLookups.Add(1)
			id, _ := strconv.ParseInt(r.URL.Query().Get("tg_id"), 10, 64)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"bound":   id == 200,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	service := New(config.Config{AdminTGIDs: []int64{100}}, mmwxclient.New(server.URL, "test", 1))
	called := make(map[int64]int)
	next := func(_ context.Context, _ *bot.Bot, update *models.Update) {
		called[update.Message.From.ID]++
	}
	handler := service.authorizeUpdate(next)

	handler(context.Background(), nil, privateTextUpdate(100, "/help"))
	handler(context.Background(), nil, privateTextUpdate(200, "/me"))
	handler(context.Background(), nil, privateTextUpdate(300, "/help"))
	handler(context.Background(), nil, privateTextUpdate(301, "/start INVALID"))
	handler(context.Background(), nil, privateTextUpdate(302, "/start valid"))

	if called[100] != 1 || called[200] != 1 || called[302] != 1 {
		t.Fatalf("allowed calls = %#v, want admin, bound user and invite start", called)
	}
	if called[300] != 0 {
		t.Fatalf("unknown users reached handler: %#v", called)
	}
	if called[301] != 1 || called[302] != 1 {
		t.Fatalf("syntactically valid invite starts did not reach authoritative handler: %#v", called)
	}
	if userLookups.Load() != 2 {
		t.Fatalf("user lookups = %d, want 2", userLookups.Load())
	}
}

func TestHandleStartKeepsRejectedUnknownUsersSilent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/admin/tgbot/user-by-tg":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "bound": false})
		case "/api/admin/tgbot/invites/lookup":
			code := r.URL.Query().Get("code")
			if code == "ERROR" {
				http.Error(w, "lookup failed", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"found":   code == "EXPIRED",
				"item": map[string]any{
					"code":   code,
					"kind":   "new",
					"usable": false,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	service := New(config.Config{}, mmwxclient.New(server.URL, "test", 1))
	for _, text := range []string{"/start", "/start INVALID", "/start EXPIRED", "/start ERROR"} {
		// A nil Bot is intentional: any attempted Telegram response would panic and
		// fail the test, proving rejected unknown users remain silent.
		service.handleStart(context.Background(), nil, privateTextUpdate(600, text))
	}
}

func TestAuthorizeUpdatePreservesRegistrationSessionAndRejectsGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "bound": false})
	}))
	t.Cleanup(server.Close)

	service := New(config.Config{}, mmwxclient.New(server.URL, "test", 1))
	service.regSessions.Store(int64(400), &regSession{expiresAt: time.Now().Add(time.Minute)})
	service.regSessions.Store(int64(401), &regSession{expiresAt: time.Now().Add(-time.Minute)})
	var calls int
	handler := service.authorizeUpdate(func(context.Context, *bot.Bot, *models.Update) {
		calls++
	})

	handler(context.Background(), nil, privateTextUpdate(400, "new-user"))
	handler(context.Background(), nil, privateTextUpdate(400, "/help"))
	handler(context.Background(), nil, privateTextUpdate(400, "/cancel"))
	handler(context.Background(), nil, privateTextUpdate(401, "expired-user"))
	group := privateTextUpdate(400, "/me")
	group.Message.Chat.Type = models.ChatTypeGroup
	handler(context.Background(), nil, group)

	if calls != 2 {
		t.Fatalf("handler calls = %d, want registration text and /cancel only", calls)
	}
	if _, ok := service.regSessions.Load(int64(401)); ok {
		t.Fatal("expired registration session was not removed")
	}
}

func TestAuthorizeUpdateRequiresPrivateAccessibleCallback(t *testing.T) {
	service := &Service{cfg: config.Config{AdminTGIDs: []int64{450}}}
	var calls int
	handler := service.authorizeUpdate(func(context.Context, *bot.Bot, *models.Update) {
		calls++
	})

	private := callbackUpdate(450, models.ChatTypePrivate)
	handler(context.Background(), nil, private)
	group := callbackUpdate(450, models.ChatTypeGroup)
	handler(context.Background(), nil, group)
	handler(context.Background(), nil, &models.Update{CallbackQuery: &models.CallbackQuery{
		From: models.User{ID: 450},
	}})

	if calls != 1 {
		t.Fatalf("handler calls = %d, want only the private accessible callback", calls)
	}
}

func TestStartInviteCodeSupportsTelegramCommandSuffix(t *testing.T) {
	code, ok := startInviteCode(" /start@arcway_bot  ab-cd ")
	if !ok || code != "AB-CD" {
		t.Fatalf("startInviteCode() = (%q, %v), want (AB-CD, true)", code, ok)
	}
	if _, ok := startInviteCode("/help AB-CD"); ok {
		t.Fatal("startInviteCode() accepted a non-start command")
	}
	if _, ok := startInviteCode("/start AB-CD ignored"); ok {
		t.Fatal("startInviteCode() accepted extra payload fields")
	}
	if _, ok := startInviteCode("start AB-CD"); ok {
		t.Fatal("startInviteCode() accepted text without a leading slash")
	}
	if !commandAtStart(privateTextUpdate(1, "/start@arcway_bot AB-CD"), "start") {
		t.Fatal("commandAtStart() rejected a suffixed Telegram command")
	}
}

func TestRegisteredStartRouteAcceptsSuffixAndRejectsNonLeadingCommand(t *testing.T) {
	var inviteLookups atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/admin/tgbot/user-by-tg":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "bound": false})
		case "/api/admin/tgbot/invites/lookup":
			inviteLookups.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "found": false})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	service := New(config.Config{}, mmwxclient.New(server.URL, "test", 1))
	telegramBot, err := bot.New(testBotToken,
		bot.WithSkipGetMe(),
		bot.WithDefaultHandler(service.defaultHandler),
		bot.WithMiddlewares(service.rateLimitUpdate, service.authorizeUpdate),
		bot.WithNotAsyncHandlers(),
	)
	if err != nil {
		t.Fatal(err)
	}
	registerCommands(telegramBot, service)

	suffixed := privateTextUpdate(700, "/start@arcway_bot INVALID")
	suffixed.Message.Entities = []models.MessageEntity{{
		Type: models.MessageEntityTypeBotCommand, Offset: 0, Length: len("/start@arcway_bot"),
	}}
	telegramBot.ProcessUpdate(context.Background(), suffixed)

	nonLeading := privateTextUpdate(701, "text /start INVALID")
	nonLeading.Message.Entities = []models.MessageEntity{{
		Type: models.MessageEntityTypeBotCommand, Offset: len("text "), Length: len("/start"),
	}}
	telegramBot.ProcessUpdate(context.Background(), nonLeading)

	if inviteLookups.Load() != 1 {
		t.Fatalf("invite lookups = %d, want only the leading suffixed /start", inviteLookups.Load())
	}
}

func TestRateLimitUpdateSharesQuotaAcrossMessagesAndCallbacks(t *testing.T) {
	rlMu.Lock()
	previous := rlCounter
	rlCounter = map[int64]*rlEntry{}
	rlMu.Unlock()
	t.Cleanup(func() {
		rlMu.Lock()
		rlCounter = previous
		rlMu.Unlock()
	})

	service := &Service{}
	var calls int
	handler := service.rateLimitUpdate(func(context.Context, *bot.Bot, *models.Update) {
		calls++
	})
	for i := 0; i < rateMaxPerWindow-1; i++ {
		handler(context.Background(), nil, privateTextUpdate(500, "/me"))
	}
	callback := callbackUpdate(500, models.ChatTypePrivate)
	handler(context.Background(), nil, callback)
	handler(context.Background(), nil, privateTextUpdate(500, "/me"))

	if calls != rateMaxPerWindow {
		t.Fatalf("handler calls = %d, want shared limit %d", calls, rateMaxPerWindow)
	}
}

func callbackUpdate(tgID int64, chatType models.ChatType) *models.Update {
	return &models.Update{CallbackQuery: &models.CallbackQuery{
		From: models.User{ID: tgID},
		Message: models.MaybeInaccessibleMessage{
			Message: &models.Message{Chat: models.Chat{ID: tgID, Type: chatType}},
		},
	}}
}

func privateTextUpdate(tgID int64, text string) *models.Update {
	return &models.Update{Message: &models.Message{
		From: &models.User{ID: tgID},
		Chat: models.Chat{ID: tgID, Type: models.ChatTypePrivate},
		Text: text,
	}}
}
