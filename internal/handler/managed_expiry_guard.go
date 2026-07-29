package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/guardwire"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/version"
)

const managedExpiryGuardPortOffset = 1

type managedExpiryGuardHTTPError struct {
	StatusCode int
	Body       []byte
}

func (e *managedExpiryGuardHTTPError) Error() string {
	if e == nil {
		return "expiry guard request failed"
	}
	return fmt.Sprintf("expiry guard returned HTTP %d: %s", e.StatusCode, strings.TrimSpace(string(e.Body)))
}

type managedExpiryGuardCapabilities struct {
	ClientExpiry bool `json:"client_expiry"`
	Durable      bool `json:"durable"`
}

func managedAgentHasNativeExpiry(capabilities AgentCapabilities) bool {
	return len(capabilities.MissingManagedNodeCapabilities()) == 0
}

func managedExpiryGuardPort(server *storage.RemoteServer) (int, error) {
	port := server.ListenPort
	if port <= 0 {
		port = 23889
	}
	if port > 65535-managedExpiryGuardPortOffset {
		return 0, errors.New("Agent listen port leaves no adjacent expiry guard port")
	}
	return port + managedExpiryGuardPortOffset, nil
}

func buildManagedExpiryGuardURLCandidates(server *storage.RemoteServer, path string) ([]string, error) {
	port, err := managedExpiryGuardPort(server)
	if err != nil {
		return nil, err
	}
	urls := make([]string, 0, 2)
	for _, address := range []string{server.IPAddress, server.IPAddressV6} {
		address = agentStripPort(strings.TrimSpace(address))
		if address == "" {
			continue
		}
		candidate := buildAgentURL(address, port, path)
		duplicate := false
		for _, previous := range urls {
			if candidate == previous {
				duplicate = true
				break
			}
		}
		if !duplicate {
			urls = append(urls, candidate)
		}
	}
	if len(urls) == 0 {
		return nil, ErrNoAgentURL
	}
	return urls, nil
}

func (h *ManagedNodesHandler) callManagedExpiryGuard(ctx context.Context, serverID int64, method, path string, payload interface{}) ([]byte, error) {
	if h == nil || h.repo == nil {
		return nil, errors.New("managed node handler is unavailable")
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	urls, err := buildManagedExpiryGuardURLCandidates(server, path)
	if err != nil {
		return nil, err
	}
	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	} else {
		body = []byte(`{}`)
	}
	secret, err := h.repo.GetOrCreateRemoteServerGuardSecret(ctx, serverID)
	if err != nil {
		return nil, err
	}
	client := h.guardHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Second}
	}
	var lastErr error
	for _, target := range urls {
		sealedBody, metadata, sealErr := guardwire.Seal(secret, method, path, body, time.Now().UTC())
		if sealErr != nil {
			return nil, sealErr
		}
		request, requestErr := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(sealedBody))
		if requestErr != nil {
			lastErr = requestErr
			continue
		}
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set(guardwire.HeaderTimestamp, metadata.Timestamp)
		request.Header.Set(guardwire.HeaderNonce, metadata.Nonce)
		request.Header.Set(guardwire.HeaderSignature, metadata.Signature)
		request.Header.Set("User-Agent", version.AgentUserAgent)
		response, requestErr := client.Do(request)
		if requestErr != nil {
			lastErr = requestErr
			continue
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		closeErr := response.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if closeErr != nil {
			lastErr = closeErr
			continue
		}
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			// A completed HTTP response came from the intended Guard. Retrying the
			// same application-level rejection through another address can mask its
			// structured code with a later transport error.
			return nil, &managedExpiryGuardHTTPError{StatusCode: response.StatusCode, Body: append([]byte(nil), responseBody...)}
		}
		return responseBody, nil
	}
	if lastErr == nil {
		lastErr = errors.New("expiry guard request failed")
	}
	return nil, lastErr
}

func (h *ManagedNodesHandler) managedConnectionCapabilities(serverID int64) (AgentCapabilities, error) {
	if h.remoteManage == nil || h.remoteManage.wsHandler == nil {
		return AgentCapabilities{}, errors.New("capability handshake is unavailable; reconnect mmw-agent")
	}
	connection, ok := h.remoteManage.wsHandler.GetConnectionByServerID(serverID)
	if !ok {
		return AgentCapabilities{}, errors.New("Agent is offline or has not completed its WebSocket handshake")
	}
	return connection.Capabilities, nil
}

func (h *ManagedNodesHandler) requireManagedExpiryGuard(ctx context.Context, serverID int64) error {
	body, err := h.callManagedExpiryGuard(ctx, serverID, http.MethodGet, "/v1/capabilities", nil)
	if err != nil {
		return errors.New("expiry guard capability handshake failed")
	}
	var capabilities managedExpiryGuardCapabilities
	if err := json.Unmarshal(body, &capabilities); err != nil {
		return fmt.Errorf("invalid expiry guard capabilities: %w", err)
	}
	if !capabilities.ClientExpiry || !capabilities.Durable {
		return errors.New("expiry guard does not advertise durable client expiry")
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return err
	}
	if err := h.syncManagedExpiryGuardAgentToken(ctx, serverID, server.Token); err != nil {
		return errors.New("expiry guard Agent token synchronization failed")
	}
	return nil
}

func (h *ManagedNodesHandler) syncManagedExpiryGuardAgentToken(ctx context.Context, serverID int64, token string) error {
	body, err := h.callManagedExpiryGuard(ctx, serverID, http.MethodPut, "/v1/agent-token", map[string]string{"token": token})
	if err != nil {
		return err
	}
	var ack struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &ack); err != nil || !ack.Success {
		return errors.New("expiry guard did not acknowledge the Agent token")
	}
	return nil
}

func syncRemoteExpiryGuardAgentToken(ctx context.Context, repo *storage.TrafficRepository, serverID int64, token string) error {
	handler := &ManagedNodesHandler{
		repo:            repo,
		guardHTTPClient: &http.Client{Timeout: 4 * time.Second},
	}
	return handler.syncManagedExpiryGuardAgentToken(ctx, serverID, token)
}

func (h *ManagedNodesHandler) ensureManagedClientExpiry(ctx context.Context, serverID int64, inboundTag string, credential map[string]interface{}, notAfter *time.Time) error {
	capabilities, err := h.managedConnectionCapabilities(serverID)
	if err != nil {
		return err
	}
	if managedAgentHasNativeExpiry(capabilities) {
		return nil
	}
	if err := h.requireManagedExpiryGuard(ctx, serverID); err != nil {
		return errors.New("expiry guard is not ready")
	}
	payload := map[string]interface{}{"tag": inboundTag, "client": credential}
	method := http.MethodDelete
	if notAfter != nil {
		method = http.MethodPut
		payload["not_after"] = notAfter.UTC()
	}
	body, err := h.callManagedExpiryGuard(ctx, serverID, method, "/v1/schedules", payload)
	if err != nil {
		return errors.New("expiry guard did not persist the client schedule")
	}
	var ack struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &ack); err != nil || !ack.Success {
		return errors.New("expiry guard did not acknowledge the schedule")
	}
	return nil
}
