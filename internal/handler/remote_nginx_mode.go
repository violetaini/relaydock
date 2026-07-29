package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

const (
	remoteNginxModeManaged       = "managed"
	remoteNginxModeReuseExisting = "reuse_existing"
	remoteNginxModeSwitchPath    = "/api/child/agent/switch-nginx-mode"
	remoteNginxModeRollbackWait  = 30 * time.Second
)

type remoteNginxModeSwitchAcknowledgement struct {
	Success   bool   `json:"success"`
	NginxMode string `json:"nginx_mode"`
	Message   string `json:"message"`
	Error     string `json:"error"`
}

func normalizedRemoteNginxMode(server *storage.RemoteServer) string {
	if server != nil && strings.TrimSpace(server.NginxMode) == remoteNginxModeReuseExisting {
		return remoteNginxModeReuseExisting
	}
	return remoteNginxModeManaged
}

func (h *XrayServerHandler) switchRemoteNginxMode(ctx context.Context, serverID int64, nginxMode string) error {
	if h == nil || h.remoteManager == nil {
		return errors.New("remote Agent manager is unavailable")
	}
	if nginxMode != remoteNginxModeManaged && nginxMode != remoteNginxModeReuseExisting {
		return fmt.Errorf("invalid nginx mode %q", nginxMode)
	}
	payload, err := json.Marshal(map[string]string{"nginx_mode": nginxMode})
	if err != nil {
		return fmt.Errorf("encode nginx mode switch: %w", err)
	}
	result, err := h.remoteManager.ForwardToServer(ctx, serverID, http.MethodPost, remoteNginxModeSwitchPath, payload)
	if err != nil {
		return err
	}
	var acknowledgement remoteNginxModeSwitchAcknowledgement
	if err := json.Unmarshal(result, &acknowledgement); err != nil {
		return fmt.Errorf("Agent returned an invalid nginx mode acknowledgement: %w", err)
	}
	if !acknowledgement.Success {
		message := strings.TrimSpace(acknowledgement.Error)
		if message == "" {
			message = strings.TrimSpace(acknowledgement.Message)
		}
		if message == "" {
			message = "Agent rejected the nginx mode switch"
		}
		return errors.New(message)
	}
	if acknowledgement.NginxMode != nginxMode {
		return fmt.Errorf("Agent acknowledged nginx mode %q, expected %q", acknowledgement.NginxMode, nginxMode)
	}
	return nil
}

func (h *XrayServerHandler) rollbackRemoteNginxMode(parent context.Context, serverID int64, nginxMode string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), remoteNginxModeRollbackWait)
	defer cancel()
	return h.switchRemoteNginxMode(ctx, serverID, nginxMode)
}

func (h *RemoteManageHandler) requireManagedRemoteNginx(ctx context.Context, w http.ResponseWriter, serverID int64) (*storage.RemoteServer, bool) {
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return nil, false
	}
	if normalizedRemoteNginxMode(server) == remoteNginxModeReuseExisting {
		remoteWriteError(w, http.StatusConflict, "该服务器正在复用系统已有 Nginx；Arcway 不会安装、卸载、启停或直接编辑外部 Nginx")
		return nil, false
	}
	return server, true
}

func (h *RemoteManageHandler) requireManagedRemoteNginxSSE(ctx context.Context, w http.ResponseWriter, serverID int64) (*storage.RemoteServer, bool) {
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		remoteSSEError(w, "server not found")
		return nil, false
	}
	if normalizedRemoteNginxMode(server) == remoteNginxModeReuseExisting {
		remoteSSEError(w, "该服务器正在复用系统已有 Nginx；Arcway 不会安装、卸载、启停或直接编辑外部 Nginx")
		return nil, false
	}
	return server, true
}
