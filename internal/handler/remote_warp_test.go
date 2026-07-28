package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWarpMutationsWaitForExclusiveServerLeaseBeforeReachingAgent(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		body      string
		handle    func(*RemoteManageHandler, http.ResponseWriter, *http.Request)
		agentPath string
	}{
		{name: "install", path: "/api/admin/remote/warp/install", handle: (*RemoteManageHandler).HandleWarpInstall, agentPath: "/api/child/warp/install"},
		{name: "license", path: "/api/admin/remote/warp/license", body: `{"license":"test-license"}`, handle: (*RemoteManageHandler).HandleWarpLicense, agentPath: "/api/child/warp/license"},
		{name: "remove", path: "/api/admin/remote/warp/remove", handle: (*RemoteManageHandler).HandleWarpRemove, agentPath: "/api/child/warp/remove"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			agentCalls := make(chan string, 1)
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				agentCalls <- r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"success":true}`))
			}))
			defer agent.Close()
			repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
			handler := NewRemoteManageHandler(repo, nil)

			_, releaseExclusive, err := repo.AcquireRemoteServerExclusiveMutationLease(context.Background(), server.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer releaseExclusive()
			request := httptest.NewRequest(http.MethodPost, fmt.Sprintf("%s?server_id=%d", test.path, server.ID), strings.NewReader(test.body))
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				test.handle(handler, response, request)
				close(done)
			}()

			select {
			case path := <-agentCalls:
				t.Fatalf("WARP mutation reached Agent while exclusive lease was held: %s", path)
			case <-done:
				t.Fatalf("WARP mutation returned before exclusive lease release: status=%d body=%s", response.Code, response.Body.String())
			case <-time.After(100 * time.Millisecond):
			}

			releaseExclusive()
			select {
			case path := <-agentCalls:
				if path != test.agentPath {
					t.Fatalf("Agent path=%q want=%q", path, test.agentPath)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("WARP mutation did not reach Agent after exclusive lease release")
			}
			select {
			case <-done:
				if response.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("WARP mutation did not finish after exclusive lease release")
			}
		})
	}
}

func TestWarpMutationMapsActiveInstallationToConflictWithoutAgentCall(t *testing.T) {
	agentCalls := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		agentCalls <- struct{}{}
	}))
	defer agent.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "warp-mutation-test", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	handler := NewRemoteManageHandler(repo, nil)
	request := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/admin/remote/warp/install?server_id=%d", server.ID), nil)
	response := httptest.NewRecorder()
	handler.HandleWarpInstall(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
	select {
	case <-agentCalls:
		t.Fatal("WARP mutation reached Agent during active installation")
	default:
	}
}
