package handler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestGetOrCreateInboundCredentialRejectsStoredProtocolDrift(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "edge-protocol-drift", Token: "token", IPAddress: "203.0.113.10", XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	storedJSON := `{"id":"old-vless-id","email":"alice__shared-in"}`
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "shared-in",
		Protocol: "vless", CredentialJSON: storedJSON,
	}); err != nil {
		t.Fatal(err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}

	credential, raw, reused, err := getOrCreateInboundCredential(
		ctx, repo, user, server.ID, "shared-in", "trojan", map[string]interface{}{},
	)
	if !errors.Is(err, storage.ErrUserInboundConfigConflict) {
		t.Fatalf("protocol drift error=%v, want %v", err, storage.ErrUserInboundConfigConflict)
	}
	if credential != nil || raw != "" || reused {
		t.Fatalf("protocol drift returned usable credential: credential=%v raw=%q reused=%v", credential, raw, reused)
	}
	stored, loadErr := repo.GetUserInboundConfig(ctx, "alice", server.ID, "shared-in")
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if stored.Protocol != "vless" || stored.CredentialJSON != storedJSON {
		t.Fatalf("protocol drift changed authoritative row: %+v", stored)
	}
}

func TestGetOrCreateInboundCredentialReconcilesStoredVLESSFlow(t *testing.T) {
	tests := []struct {
		name       string
		storedJSON string
		clients    []interface{}
		wantFlow   string
	}{
		{
			name:       "adds flow from matching live id",
			storedJSON: `{"id":"alice-id","email":"alice__vless-in"}`,
			clients: []interface{}{
				map[string]interface{}{"id": "alice-id", "email": "alice__vless-in", "flow": "xtls-rprx-vision"},
			},
			wantFlow: "xtls-rprx-vision",
		},
		{
			name:       "removes stale flow when matching live id has none",
			storedJSON: `{"id":"alice-id","email":"alice__vless-in","flow":"xtls-rprx-vision"}`,
			clients: []interface{}{
				map[string]interface{}{"id": "alice-id", "email": "alice__vless-in"},
			},
		},
		{
			name:       "inherits reference flow before new client is added",
			storedJSON: `{"id":"alice-id","email":"alice__vless-in"}`,
			clients: []interface{}{
				map[string]interface{}{"id": "owner-id", "email": "owner", "flow": "xtls-rprx-vision"},
			},
			wantFlow: "xtls-rprx-vision",
		},
		{
			name:       "matching live id wins over first reference client",
			storedJSON: `{"id":"alice-id","email":"alice__vless-in","flow":"xtls-rprx-vision"}`,
			clients: []interface{}{
				map[string]interface{}{"id": "owner-id", "email": "owner", "flow": "xtls-rprx-vision"},
				map[string]interface{}{"id": "alice-id", "email": "alice__vless-in"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			repo := newManagedSecurityTestRepo(t)
			createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
			server := &storage.RemoteServer{
				Name: "edge-flow-" + tt.name, Token: "token", IPAddress: "203.0.113.10", XrayMode: "embedded",
			}
			if err := repo.CreateRemoteServer(ctx, server); err != nil {
				t.Fatalf("create remote server: %v", err)
			}
			if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
				Username: "alice", ServerID: server.ID, InboundTag: "vless-in",
				Protocol: "vless", CredentialJSON: tt.storedJSON,
			}); err != nil {
				t.Fatalf("save stored credential: %v", err)
			}
			user, err := repo.GetUser(ctx, "alice")
			if err != nil {
				t.Fatalf("get user: %v", err)
			}

			credential, credentialJSON, reused, err := getOrCreateInboundCredential(
				ctx, repo, user, server.ID, "vless-in", "vless",
				map[string]interface{}{"clients": tt.clients},
			)
			if err != nil {
				t.Fatalf("get or create credential: %v", err)
			}
			if !reused {
				t.Fatal("stored credential was not reused")
			}
			assertCredentialFlow(t, credential, tt.wantFlow)

			var returned map[string]interface{}
			if err := json.Unmarshal([]byte(credentialJSON), &returned); err != nil {
				t.Fatalf("parse returned credential JSON: %v", err)
			}
			assertCredentialFlow(t, returned, tt.wantFlow)

			stored, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in")
			if err != nil || stored == nil {
				t.Fatalf("load persisted credential: stored=%+v err=%v", stored, err)
			}
			var persisted map[string]interface{}
			if err := json.Unmarshal([]byte(stored.CredentialJSON), &persisted); err != nil {
				t.Fatalf("parse persisted credential JSON: %v", err)
			}
			assertCredentialFlow(t, persisted, tt.wantFlow)
		})
	}
}

func assertCredentialFlow(t *testing.T, credential map[string]interface{}, want string) {
	t.Helper()
	got, exists := credential["flow"]
	if want == "" {
		if exists {
			t.Fatalf("flow = %#v, want field absent", got)
		}
		return
	}
	if got != want {
		t.Fatalf("flow = %#v, want %q", got, want)
	}
}
