package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestHandleInboundsRestoresOwnerAfterRejectedOrMismatchedAdd(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		response map[string]any
	}{
		{name: "logical rejection", response: map[string]any{"success": false, "error": "rejected"}},
		{name: "mismatched acknowledgement", response: map[string]any{"success": true, "mutation_id": "different-generation"}},
		{name: "superseded add", response: map[string]any{"success": true, "mutation_id": "new-generation", "superseded": true}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
					_ = json.NewEncoder(w).Encode(testCase.response)
				case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"success": true, "inbounds": []any{},
						"mutation_fence_known": true,
						"mutation_owners":      map[string]string{"same-tag": "old-generation"},
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer agent.Close()

			repo := newRemoteHandlerTestRepo(t)
			if err := repo.CreateUser(context.Background(), "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
				t.Fatal(err)
			}
			server := createRemoteHandlerTestServer(t, repo, "owner-reconcile-edge", agent.URL)
			if err := repo.SetRemoteInboundOwnership(context.Background(), server.ID, "same-tag", "old-generation"); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(map[string]any{
				"action": "add", "mutation_id": "new-generation",
				"inbound": map[string]any{
					"tag": "same-tag", "protocol": "tunnel", "listen": "0.0.0.0", "port": 2033,
					"settings": map[string]any{"address": "127.0.0.1", "port": 80, "network": "tcp,udp"},
				},
			})
			request := httptest.NewRequest(http.MethodPost, "/api/admin/remote/inbounds?server_id="+leaseTestID(server.ID), bytes.NewReader(body))
			request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
			response := httptest.NewRecorder()

			NewRemoteManageHandler(repo, nil).HandleInbounds(response, request)
			if response.Code == http.StatusOK {
				t.Fatalf("failed add was reported successful: %s", response.Body.String())
			}
			owner, err := repo.FindInboundMutationID(context.Background(), server.ID, "same-tag")
			if err != nil {
				t.Fatal(err)
			}
			if owner != "old-generation" {
				t.Fatalf("owner=%q want restored old-generation; response=%s", owner, response.Body.String())
			}
		})
	}
}
