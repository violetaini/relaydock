package handler

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestRemoteServerAutoUpdateAgentDefaultAndToggle(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	// 1. 默认创建 -> AutoUpdateAgent 应为 true
	serverDefault := &storage.RemoteServer{
		Name:            "server-auto-default",
		Token:           "token-1",
		Status:          storage.RemoteServerStatusConnected,
		AutoUpdateAgent: true,
	}
	if err := repo.CreateRemoteServer(context.Background(), serverDefault); err != nil {
		t.Fatalf("CreateRemoteServer default: %v", err)
	}
	storedDefault, err := repo.GetRemoteServer(context.Background(), serverDefault.ID)
	if err != nil {
		t.Fatalf("GetRemoteServer default: %v", err)
	}
	if !storedDefault.AutoUpdateAgent {
		t.Fatalf("expected storedDefault.AutoUpdateAgent to be true, got false")
	}

	// 2. 显式创建为 false -> AutoUpdateAgent 应为 false
	serverDisabled := &storage.RemoteServer{
		Name:            "server-auto-disabled",
		Token:           "token-2",
		Status:          storage.RemoteServerStatusConnected,
		AutoUpdateAgent: false,
	}
	if err := repo.CreateRemoteServer(context.Background(), serverDisabled); err != nil {
		t.Fatalf("CreateRemoteServer disabled: %v", err)
	}
	storedDisabled, err := repo.GetRemoteServer(context.Background(), serverDisabled.ID)
	if err != nil {
		t.Fatalf("GetRemoteServer disabled: %v", err)
	}
	if storedDisabled.AutoUpdateAgent {
		t.Fatalf("expected storedDisabled.AutoUpdateAgent to be false, got true")
	}

	// 3. 更新开关 -> 将 false 更改为 true，将 true 更改为 false
	if err := repo.UpdateRemoteServerAutoUpdateAgent(context.Background(), storedDisabled.ID, true); err != nil {
		t.Fatalf("UpdateRemoteServerAutoUpdateAgent: %v", err)
	}
	reloadedDisabled, err := repo.GetRemoteServer(context.Background(), storedDisabled.ID)
	if err != nil {
		t.Fatalf("reloadedDisabled: %v", err)
	}
	if !reloadedDisabled.AutoUpdateAgent {
		t.Fatalf("expected reloadedDisabled.AutoUpdateAgent to be true after toggle")
	}

	if err := repo.UpdateRemoteServerAutoUpdateAgent(context.Background(), storedDefault.ID, false); err != nil {
		t.Fatalf("UpdateRemoteServerAutoUpdateAgent: %v", err)
	}
	reloadedDefault, err := repo.GetRemoteServer(context.Background(), storedDefault.ID)
	if err != nil {
		t.Fatalf("reloadedDefault: %v", err)
	}
	if reloadedDefault.AutoUpdateAgent {
		t.Fatalf("expected reloadedDefault.AutoUpdateAgent to be false after toggle")
	}
}
