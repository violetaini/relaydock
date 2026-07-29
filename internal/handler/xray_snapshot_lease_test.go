package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestXraySnapshotApplyHoldsMutationLeaseThroughRestart(t *testing.T) {
	testStarted := make(chan struct{})
	releaseTest := make(chan struct{})
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/child/xray/test-config":
			close(testStarted)
			<-releaseTest
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "method": "test"})
		case "/api/child/xray/config", "/api/child/services/control":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		case "/api/child/services/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"xray": map[string]any{"running": true}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	remoteManage := NewRemoteManageHandler(repo, nil)
	handler := NewXraySnapshotHandler(repo, remoteManage)
	request := httptest.NewRequest(http.MethodPost, "/api/admin/xray-snapshots/restore", nil)
	applyDone := make(chan error, 1)
	go func() {
		applyDone <- handler.applyConfigToAgent(request, server.ID, `{}`)
	}()

	select {
	case <-testStarted:
	case <-time.After(time.Second):
		t.Fatal("snapshot apply did not reach config validation")
	}
	beginDone := make(chan error, 1)
	go func() {
		beginDone <- repo.BeginRemoteServerInstallation(context.Background(), server.ID, "snapshot-drain-nonce", time.Now().Add(time.Minute))
	}()
	select {
	case err := <-beginDone:
		t.Fatalf("installation began before snapshot apply completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseTest)
	if err := <-applyDone; err != nil {
		t.Fatalf("snapshot apply: %v", err)
	}
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("installation begin after snapshot apply: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("installation remained blocked after snapshot apply")
	}
}

func TestXraySnapshotApplyRejectsActiveInstallationBeforeAgentWrite(t *testing.T) {
	requests := make(chan struct{}, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, "active-snapshot-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	handler := NewXraySnapshotHandler(repo, NewRemoteManageHandler(repo, nil))
	request := httptest.NewRequest(http.MethodPost, "/api/admin/xray-snapshots/restore", nil)
	err := handler.applyConfigToAgent(request, server.ID, `{}`)
	if !errors.Is(err, storage.ErrRemoteInstallationActive) {
		t.Fatalf("snapshot apply error=%v, want active installation", err)
	}
	select {
	case <-requests:
		t.Fatal("active installation allowed an Agent write")
	case <-time.After(50 * time.Millisecond):
	}
}
