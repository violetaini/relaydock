package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/violetaini/relaydock/internal/tgbot/config"
	"github.com/violetaini/relaydock/internal/tgbot/mmwxclient"
)

type simCapturedCall struct {
	Method string
	Body   map[string]any
}

type simMockTGServer struct {
	mu    sync.Mutex
	calls []simCapturedCall
}

func (m *simMockTGServer) record(method string, body map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, simCapturedCall{Method: method, Body: body})
}

func (m *simMockTGServer) lastMessageText() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.calls) - 1; i >= 0; i-- {
		if m.calls[i].Method == "sendMessage" {
			if t, ok := m.calls[i].Body["text"].(string); ok {
				return t
			}
		}
	}
	return ""
}

func (m *simMockTGServer) clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func TestBotSimulationEndToEnd(t *testing.T) {
	mock := &simMockTGServer{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		method := parts[len(parts)-1]
		
		bodyMap := make(map[string]any)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			_ = r.ParseMultipartForm(10 << 20)
			for k, v := range r.MultipartForm.Value {
				if len(v) > 0 {
					bodyMap[k] = v[0]
				}
			}
		} else {
			bodyBytes, _ := io.ReadAll(r.Body)
			if len(bodyBytes) > 0 {
				_ = json.Unmarshal(bodyBytes, &bodyMap)
			}
		}
		mock.record(method, bodyMap)

		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "getMe":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"result": map[string]any{
					"id":         8786574309,
					"is_bot":     true,
					"first_name": "RelayDock Bot",
					"username":   "sjsjnaammam_bot",
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":     true,
				"result": true,
			})
		}
	}))
	defer ts.Close()

	// 1. Authenticate to live RelayDock to get service token
	baseURL := "https://relay.chitanda.net"
	loginBody := `{"username":"admin","password":"Chitanda2026@RelayDock!"}`
	resp, err := http.Post(baseURL+"/api/login", "application/json", strings.NewReader(loginBody))
	if err != nil {
		t.Skipf("Live RelayDock not reachable from this test environment: %v", err)
		return
	}
	defer resp.Body.Close()
	var loginRes struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&loginRes)
	if loginRes.Token == "" {
		t.Skip("Could not obtain admin token from RelayDock")
		return
	}
	t.Logf("[PASS] Authenticated to RelayDock master at %s", baseURL)

	// 2. Initialize mmwxclient pointing to live master
	client := mmwxclient.New(baseURL, loginRes.Token, 30)

	adminTGID := int64(987654321)
	userTGID := int64(888123456)   // Registered user (tguser8794)
	unboundTGID := int64(777654321) // Unknown / unbound user

	cfg := config.Config{
		Enabled:          true,
		PublicBaseURL:    baseURL,
		TGBotToken:       "8786574309:AAHtyPA-OhiPie-JVKaF0Cym_ZcwnZ6H8T0",
		AdminTGIDs:       []int64{adminTGID},
		WebAppURL:        baseURL + "/tg-app",
		WebAppDevPreview: true,
	}

	service := New(cfg, client)

	b, err := bot.New(
		cfg.TGBotToken,
		bot.WithServerURL(ts.URL),
		bot.WithDefaultHandler(service.defaultHandler),
		bot.WithMiddlewares(service.rateLimitUpdate, service.authorizeUpdate),
		bot.WithSkipGetMe(),
		bot.WithNotAsyncHandlers(),
	)
	if err != nil {
		t.Fatalf("Bot creation failed: %v", err)
	}
	registerCommands(b, service)

	ctx := context.Background()

	// -------------------------------------------------------------
	// TEST 1: Unknown Unbound User
	// -------------------------------------------------------------
	t.Run("UnboundUserSilentlyDropped", func(t *testing.T) {
		mock.clear()
		simSendCmd(ctx, b, unboundTGID, "/help")
		if len(mock.calls) != 0 {
			t.Fatalf("Expected unknown user /help to be silently dropped, got: %v", mock.calls)
		}
		t.Log("[PASS] Unbound user /help is silently dropped by authorizeUpdate")

		mock.clear()
		simSendCmd(ctx, b, unboundTGID, "/me")
		if len(mock.calls) != 0 {
			t.Fatalf("Expected unknown user /me to be silently dropped, got: %v", mock.calls)
		}
		t.Log("[PASS] Unbound user /me is silently dropped")

		mock.clear()
		simSendCmd(ctx, b, unboundTGID, "/admin_invite list")
		if len(mock.calls) != 0 {
			t.Fatalf("Expected unknown user /admin_invite to be dropped, got: %v", mock.calls)
		}
		t.Log("[PASS] Unbound user /admin_invite is silently dropped")
	})

	// -------------------------------------------------------------
	// TEST 2: Bound Regular User (userTGID)
	// -------------------------------------------------------------
	t.Run("BoundRegularUserCommands", func(t *testing.T) {
		// 2.1 /help
		mock.clear()
		simSendCmd(ctx, b, userTGID, "/help")
		txt := mock.lastMessageText()
		if !strings.Contains(txt, "Arcway Telegram Bot") || !strings.Contains(txt, "/me") {
			t.Fatalf("Unexpected /help text: %s", txt)
		}
		t.Logf("[PASS] /help response:\n%s", txt)

		// 2.2 /me
		mock.clear()
		simSendCmd(ctx, b, userTGID, "/me")
		txt = mock.lastMessageText()
		if !strings.Contains(txt, "账号:") {
			t.Fatalf("Unexpected /me text: %s", txt)
		}
		t.Logf("[PASS] /me response:\n%s", txt)

		// 2.3 /sub
		mock.clear()
		simSendCmd(ctx, b, userTGID, "/sub")
		txt = mock.lastMessageText()
		t.Logf("[PASS] /sub response:\n%s", txt)

		// 2.4 /traffic
		mock.clear()
		simSendCmd(ctx, b, userTGID, "/traffic")
		txt = mock.lastMessageText()
		if !strings.Contains(txt, "流量统计") {
			t.Fatalf("Unexpected /traffic text: %s", txt)
		}
		t.Logf("[PASS] /traffic response:\n%s", txt)

		// 2.5 /nodes
		mock.clear()
		simSendCmd(ctx, b, userTGID, "/nodes")
		txt = mock.lastMessageText()
		t.Logf("[PASS] /nodes response:\n%s", txt)

		// 2.6 /notify status
		mock.clear()
		simSendCmd(ctx, b, userTGID, "/notify status")
		txt = mock.lastMessageText()
		if !strings.Contains(txt, "通知当前:") {
			t.Fatalf("Unexpected /notify text: %s", txt)
		}
		t.Logf("[PASS] /notify status response:\n%s", txt)
	})

	// -------------------------------------------------------------
	// TEST 3: Regular user blocked on Admin Commands
	// -------------------------------------------------------------
	t.Run("RegularUserBlockedOnAdminCommands", func(t *testing.T) {
		mock.clear()
		simSendCmd(ctx, b, userTGID, "/admin_invite list")
		txt := mock.lastMessageText()
		if !strings.Contains(txt, "本命令仅管理员可用") {
			t.Fatalf("Expected '本命令仅管理员可用', got: %s", txt)
		}
		t.Logf("[PASS] Regular user blocked on /admin_invite: %s", txt)

		mock.clear()
		simSendCmd(ctx, b, userTGID, "/admin_user user1")
		txt = mock.lastMessageText()
		if !strings.Contains(txt, "本命令仅管理员可用") {
			t.Fatalf("Expected '本命令仅管理员可用', got: %s", txt)
		}
		t.Logf("[PASS] Regular user blocked on /admin_user: %s", txt)

		mock.clear()
		simSendCmd(ctx, b, userTGID, "/announce Hello")
		txt = mock.lastMessageText()
		if !strings.Contains(txt, "本命令仅管理员可用") {
			t.Fatalf("Expected '本命令仅管理员可用', got: %s", txt)
		}
		t.Logf("[PASS] Regular user blocked on /announce: %s", txt)
	})

	// -------------------------------------------------------------
	// TEST 4: Admin User (adminTGID)
	// -------------------------------------------------------------
	t.Run("AdminUserCommands", func(t *testing.T) {
		// 4.1 Admin /help
		mock.clear()
		simSendCmd(ctx, b, adminTGID, "/help")
		txt := mock.lastMessageText()
		if !strings.Contains(txt, "/admin_invite") {
			t.Fatalf("Admin /help should show admin commands, got: %s", txt)
		}
		t.Logf("[PASS] Admin /help displays commands")

		// 4.2 Admin /admin_invite list
		mock.clear()
		simSendCmd(ctx, b, adminTGID, "/admin_invite list")
		txt = mock.lastMessageText()
		if !strings.Contains(txt, "邀请码") {
			t.Fatalf("Unexpected /admin_invite list output: %s", txt)
		}
		t.Logf("[PASS] Admin /admin_invite list response:\n%s", txt)

		// 4.3 Admin /admin_user user1
		mock.clear()
		simSendCmd(ctx, b, adminTGID, "/admin_user user1")
		txt = mock.lastMessageText()
		if !strings.Contains(txt, "账号: user1") {
			t.Fatalf("Unexpected /admin_user response: %s", txt)
		}
		t.Logf("[PASS] Admin /admin_user user1 response:\n%s", txt)

		// 4.4 Admin /announce
		mock.clear()
		simSendCmd(ctx, b, adminTGID, "/announce 自动化回归测试系统运行正常")
		txt = mock.lastMessageText()
		if !strings.Contains(txt, "公告已发布") {
			t.Fatalf("Unexpected /announce response: %s", txt)
		}
		t.Logf("[PASS] Admin /announce response: %s", txt)
	})
}

func simSendCmd(ctx context.Context, b *bot.Bot, tgID int64, text string) {
	cmdName := strings.TrimPrefix(strings.Fields(text)[0], "/")
	if at := strings.IndexByte(cmdName, '@'); at >= 0 {
		cmdName = cmdName[:at]
	}
	update := &models.Update{
		ID: 1,
		Message: &models.Message{
			ID:   100,
			Date: int(time.Now().Unix()),
			From: &models.User{ID: tgID, Username: fmt.Sprintf("tg_%d", tgID)},
			Chat: models.Chat{ID: tgID, Type: models.ChatTypePrivate},
			Text: text,
			Entities: []models.MessageEntity{
				{
					Type:   models.MessageEntityTypeBotCommand,
					Offset: 0,
					Length: len("/" + cmdName),
				},
			},
		},
	}
	b.ProcessUpdate(ctx, update)
}
