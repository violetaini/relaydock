package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

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
