package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/guardwire"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/version"
)

const expiryGuardAssetDirEnv = "ARCWAY_GUARD_ASSET_DIR"

const remoteManagementProbeInterval = 2 * time.Second
const remoteInstallationTTL = 30 * time.Minute
const remoteInstallationMaxLifetime = 2 * time.Hour
const remoteInstallTicketTTL = 5 * time.Minute
const remoteInstallTicketPrefix = "arcway-install-"
const remoteInstallationNonceHeader = "X-Arcway-Install-Nonce"
const remoteInstallationPolicyHeader = "X-Arcway-Install-Policy-SHA256"

var errExpiryGuardAssetNotFound = errors.New("expiry guard asset not found")

func (h *XrayServerHandler) allowRemoteManagementProbe(serverID int64, now time.Time) bool {
	h.managementProbeMu.Lock()
	defer h.managementProbeMu.Unlock()
	if h.managementProbes == nil {
		h.managementProbes = make(map[int64]time.Time)
	}
	if previous := h.managementProbes[serverID]; !previous.IsZero() && now.Sub(previous) < remoteManagementProbeInterval {
		return false
	}
	h.managementProbes[serverID] = now
	return true
}

// observedRemoteAddress binds the panel callback to the address that initiated
// this authenticated request. Only X-Real-IP is accepted from a loopback peer;
// the bundled Nginx config overwrites that header with its observed client.
// CF-Connecting-IP and X-Forwarded-For are intentionally ignored because an
// origin reachable outside Cloudflare can receive attacker-supplied values.
func observedRemoteAddress(r *http.Request) string {
	peer := net.ParseIP(agentStripPort(strings.TrimSpace(r.RemoteAddr)))
	if peer == nil {
		return ""
	}
	if peer.IsLoopback() {
		if parsed := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); parsed != nil {
			return parsed.String()
		}
	}
	return peer.String()
}

// GetExpiryGuardAsset serves the panel-built expiry guard to an authenticated
// remote server. The architecture allow-list also makes the requested filename
// independent from untrusted path input.
func (h *XrayServerHandler) GetExpiryGuardAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, ok := remoteBearerToken(r.Header.Get("Authorization"))
	if !ok || h == nil || h.repo == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="remote-server"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	server, err := h.repo.GetRemoteServerByToken(r.Context(), token)
	if err != nil || (server.TokenExpiresAt != nil && !server.TokenExpiresAt.After(time.Now())) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="remote-server"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	arch := strings.TrimSpace(r.URL.Query().Get("arch"))
	if arch != "amd64" && arch != "arm64" {
		http.Error(w, "Unsupported architecture", http.StatusBadRequest)
		return
	}
	name := "arcway-expiry-guard-linux-" + arch
	asset, err := openExpiryGuardAsset(name)
	if errors.Is(err, errExpiryGuardAssetNotFound) {
		http.Error(w, "Expiry guard asset unavailable", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Expiry guard asset unavailable", http.StatusInternalServerError)
		return
	}
	defer asset.Close()

	info, err := asset.Stat()
	if err != nil {
		http.Error(w, "Expiry guard asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	http.ServeContent(w, r, name, info.ModTime(), asset)
}

func remoteBearerToken(authorization string) (string, bool) {
	scheme, token, found := strings.Cut(strings.TrimSpace(authorization), " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func probeRemoteAgent(ctx context.Context, address string, port int) error {
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return connection.Close()
}

func (h *XrayServerHandler) authenticatedRemoteAgentConnected(server *storage.RemoteServer) bool {
	if h == nil || server == nil {
		return false
	}
	if server.ConnectionMode == storage.ConnectionModePush {
		return true
	}
	if server.ConnectionMode != storage.ConnectionModeWebSocket || h.wsHandler == nil {
		return false
	}
	connection, connected := h.wsHandler.GetConnectionByServerID(server.ID)
	return connected && connection.Encrypted && connection.Capabilities.RPC
}

func probeRemoteExpiryGuard(ctx context.Context, client *http.Client, address string, port int, secret string) error {
	const path = "/v1/capabilities"
	body, metadata, err := guardwire.Seal(secret, http.MethodGet, path, []byte(`{}`), time.Now().UTC())
	if err != nil {
		return err
	}
	target := "http://" + net.JoinHostPort(address, strconv.Itoa(port)) + path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(guardwire.HeaderTimestamp, metadata.Timestamp)
	request.Header.Set(guardwire.HeaderNonce, metadata.Nonce)
	request.Header.Set(guardwire.HeaderSignature, metadata.Signature)
	request.Header.Set("User-Agent", version.AgentUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("expiry guard returned HTTP %d", response.StatusCode)
	}
	var capabilities managedExpiryGuardCapabilities
	if err := json.Unmarshal(responseBody, &capabilities); err != nil || !capabilities.ClientExpiry || !capabilities.Durable {
		return errors.New("invalid expiry guard readiness response")
	}
	return nil
}

func newRemoteManagementProbeClient() (*http.Client, *http.Transport) {
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: dialer.DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, transport
}

func remoteInstallationNonce(r *http.Request) (string, bool) {
	nonce := strings.TrimSpace(r.Header.Get(remoteInstallationNonceHeader))
	if len(nonce) < 20 || len(nonce) > 256 || strings.ContainsAny(nonce, " \t\r\n") {
		return "", false
	}
	return nonce, true
}

func (h *XrayServerHandler) authenticatedRemoteInstallation(w http.ResponseWriter, r *http.Request) (*storage.RemoteServer, string, bool) {
	token, tokenOK := remoteBearerToken(r.Header.Get("Authorization"))
	nonce, nonceOK := remoteInstallationNonce(r)
	if !tokenOK || !nonceOK || h == nil || h.repo == nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "unauthorized"})
		return nil, "", false
	}
	server, err := h.repo.GetRemoteServerByToken(r.Context(), token)
	if err != nil || (server.TokenExpiresAt != nil && !server.TokenExpiresAt.After(time.Now())) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "unauthorized"})
		return nil, "", false
	}
	return server, nonce, true
}

func (h *XrayServerHandler) BeginRemoteInstallation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server, nonce, ok := h.authenticatedRemoteInstallation(w, r)
	if !ok {
		return
	}
	panelSourceIPs, err := configuredPanelSourceIPs()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation policy is unavailable"})
		return
	}
	policyContext, err := h.remoteInstallationPolicyContext(r.Context(), r, panelSourceIPs)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation policy is unavailable"})
		return
	}
	policyFingerprint := strings.TrimSpace(r.Header.Get(remoteInstallationPolicyHeader))
	if err := h.repo.BeginRemoteServerInstallationWithPolicyContext(r.Context(), server.ID, nonce, time.Now().Add(remoteInstallationTTL), policyFingerprint, policyContext); err != nil {
		status := http.StatusInternalServerError
		message := "unable to begin installation transaction"
		if errors.Is(err, storage.ErrRemoteInstallationActive) {
			status = http.StatusConflict
			message = "another installation transaction is active"
		} else if errors.Is(err, storage.ErrRemoteInstallationPolicy) {
			status = http.StatusConflict
			message = "installation policy changed; download a new install command"
		} else if errors.Is(err, storage.ErrRemoteInstallationAborted) || errors.Is(err, storage.ErrRemoteInstallationInvalid) {
			status = http.StatusConflict
			message = "installation transaction cannot be started"
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": message})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// RenewRemoteInstallation extends a live installer lease by 30 minutes while
// preserving the hard two-hour deadline anchored at the first successful Begin.
func (h *XrayServerHandler) RenewRemoteInstallation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server, nonce, ok := h.authenticatedRemoteInstallation(w, r)
	if !ok {
		return
	}
	if err := h.repo.RenewRemoteServerInstallation(r.Context(), server.ID, nonce, time.Now(), remoteInstallationTTL, remoteInstallationMaxLifetime); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrRemoteInstallationInvalid) || errors.Is(err, storage.ErrRemoteInstallationAborted) ||
			errors.Is(err, storage.ErrRemoteInstallationRollingBack) {
			status = http.StatusConflict
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction cannot be renewed"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// QuiesceRemoteInstallation waits for any in-flight Prepare to finish and then
// durably blocks later Prepare calls before the installer restores local state.
func (h *XrayServerHandler) QuiesceRemoteInstallation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server, nonce, ok := h.authenticatedRemoteInstallation(w, r)
	if !ok {
		return
	}
	if err := h.repo.MarkRemoteServerInstallationRollingBack(r.Context(), server.ID, nonce); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrRemoteInstallationInvalid) || errors.Is(err, storage.ErrRemoteInstallationAborted) {
			status = http.StatusConflict
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction cannot enter rollback"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (h *XrayServerHandler) AbortRemoteInstallation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server, nonce, ok := h.authenticatedRemoteInstallation(w, r)
	if !ok {
		return
	}
	if err := h.repo.AbortRemoteServerInstallation(r.Context(), server.ID, nonce); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrRemoteInstallationInvalid) {
			status = http.StatusConflict
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction cannot be aborted"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (h *XrayServerHandler) PrepareRemoteInstallation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server, nonce, ok := h.authenticatedRemoteInstallation(w, r)
	if !ok {
		return
	}
	ready, err := h.repo.ValidateRemoteServerInstallationReady(r.Context(), server.ID, nonce)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction is unavailable"})
		return
	}
	if !ready {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction is not ready"})
		return
	}
	if server.StealSelf && h.remoteManager == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "remote deployment manager is unavailable"})
		return
	}
	deferDesiredState := false
	if server.StealSelf && server.XrayMode != "embedded" {
		xrayStatus, statusErr := h.remoteManager.remoteXrayServiceStatus(r.Context(), server.ID)
		if statusErr != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "unable to inspect external Xray state"})
			return
		}
		deferDesiredState = !xrayStatus.Installed
	}
	bypassCtx := h.repo.RemoteServerMutationLeaseBypassContext(r.Context(), server.ID)
	err = h.repo.WithRemoteServerMutationLease(bypassCtx, server.ID, func(exclusiveCtx context.Context) error {
		ready, validateErr := h.repo.ValidateRemoteServerInstallationReady(exclusiveCtx, server.ID, nonce)
		if validateErr != nil {
			return validateErr
		}
		if !ready {
			return storage.ErrRemoteInstallationNotReady
		}
		if server.StealSelf && !deferDesiredState {
			deployer := h.remoteManager.DeployStealSelfConfig
			if h.remoteManager.stealSelfDeployer != nil {
				deployer = h.remoteManager.stealSelfDeployer
			}
			if err := deployer(exclusiveCtx, server.ID); err != nil {
				return fmt.Errorf("deploy desired state: %w", err)
			}
			if err := h.repo.SetRemoteServerXrayBootstrapPending(exclusiveCtx, server.ID, false); err != nil {
				return fmt.Errorf("clear deferred Xray configuration state: %w", err)
			}
		}
		if deferDesiredState {
			if err := h.repo.SetRemoteServerXrayBootstrapPending(exclusiveCtx, server.ID, true); err != nil {
				return fmt.Errorf("record deferred Xray configuration state: %w", err)
			}
			log.Printf("[Remote Install] Deferring desired-state deployment for server %d until external Xray is installed", server.ID)
		}
		return h.repo.MarkRemoteServerInstallationPrepared(exclusiveCtx, server.ID, nonce)
	})
	if err != nil {
		status := http.StatusBadGateway
		message := "final desired-state deployment failed"
		if errors.Is(err, storage.ErrRemoteInstallationInvalid) || errors.Is(err, storage.ErrRemoteInstallationNotReady) || errors.Is(err, storage.ErrRemoteInstallationRollingBack) {
			status = http.StatusConflict
			message = "installation transaction is no longer ready"
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": message})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (h *XrayServerHandler) FinalizeRemoteInstallation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server, nonce, ok := h.authenticatedRemoteInstallation(w, r)
	if !ok {
		return
	}
	if err := h.repo.FinalizeRemoteServerInstallation(r.Context(), server.ID, nonce); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrRemoteInstallationInvalid) || errors.Is(err, storage.ErrRemoteInstallationNotReady) ||
			errors.Is(err, storage.ErrRemoteInstallationNotPrepared) || errors.Is(err, storage.ErrRemoteInstallationAborted) ||
			errors.Is(err, storage.ErrRemoteInstallationRollingBack) {
			status = http.StatusConflict
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction is not ready"})
		return
	}
	// The first Agent scan commonly arrives while the installation lease is still
	// active and is deliberately ignored. Refresh only operational status after
	// finalization so a healthy new server is not left displayed as Xray offline.
	// Node reconciliation remains on the regular scan/reconnect path.
	if h.remoteManager != nil {
		go h.remoteManager.refreshXrayStatusNow(server.ID)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// VerifyRemoteManagementPorts is called by a node after installation. The
// callback makes the panel prove that authenticated HTTP fallback and expiry
// enforcement are reachable through the effective host/cloud firewall.
func (h *XrayServerHandler) VerifyRemoteManagementPorts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server, nonce, ok := h.authenticatedRemoteInstallation(w, r)
	if !ok {
		return
	}
	valid, err := h.repo.ValidateRemoteServerInstallation(r.Context(), server.ID, nonce)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction is unavailable"})
		return
	}
	if !valid {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction is invalid or expired"})
		return
	}
	if !h.allowRemoteManagementProbe(server.ID, time.Now()) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "management readiness probe rate limited"})
		return
	}
	address := observedRemoteAddress(r)
	if address == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "unable to determine node address"})
		return
	}
	agentPort := server.ListenPort
	if agentPort <= 0 {
		agentPort = 23889
	}
	if !storage.IsValidRemoteManagementListenPort(agentPort) || agentPort == 0 {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "invalid management ports"})
		return
	}
	guardSecret, err := h.repo.GetOrCreateRemoteServerGuardSecret(r.Context(), server.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "expiry guard is unavailable"})
		return
	}

	client, transport := newRemoteManagementProbeClient()
	defer transport.CloseIdleConnections()
	// Agent v0.3.7 intentionally closes unauthenticated HTTP connections instead
	// of returning a challenge. Prove fallback-port reachability with TCP, while
	// the installer validates Agent/Xray locally and the adjacent guard provides
	// an authenticated HMAC capability proof without exposing the Agent token.
	var probeErr error
	if !h.authenticatedRemoteAgentConnected(server) {
		probeErr = errors.New("authenticated encrypted Agent WebSocket is unavailable")
	} else if err := probeRemoteAgent(r.Context(), address, agentPort); err != nil {
		probeErr = fmt.Errorf("Agent TCP probe: %w", err)
	} else if err := probeRemoteExpiryGuard(r.Context(), client, address, agentPort+managedExpiryGuardPortOffset, guardSecret); err != nil {
		probeErr = fmt.Errorf("expiry guard capability probe: %w", err)
	}
	if probeErr != nil {
		log.Printf("[Remote Install] Management readiness failed for server %d at %s:%d: %v", server.ID, address, agentPort, probeErr)
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "panel cannot reach the node management ports"})
		return
	}
	if err := h.repo.MarkRemoteServerInstallationReady(r.Context(), server.ID, nonce); err != nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "installation transaction is no longer valid"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "address": address, "agent_port": agentPort, "guard_port": agentPort + managedExpiryGuardPortOffset})
}

func expiryGuardAssetDirectories() []string {
	directories := make([]string, 0, 4)
	if configured := strings.TrimSpace(os.Getenv(expiryGuardAssetDirEnv)); configured != "" {
		directories = append(directories, configured)
	}
	if executable, err := os.Executable(); err == nil {
		directory := filepath.Dir(executable)
		directories = append(directories, directory, filepath.Join(directory, "guard-assets"))
	}
	if workingDirectory, err := os.Getwd(); err == nil {
		directories = append(directories, filepath.Join(workingDirectory, "guard-assets"))
	}

	seen := make(map[string]struct{}, len(directories))
	unique := directories[:0]
	for _, directory := range directories {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			continue
		}
		absolute = filepath.Clean(absolute)
		if _, exists := seen[absolute]; exists {
			continue
		}
		seen[absolute] = struct{}{}
		unique = append(unique, absolute)
	}
	return unique
}

func openExpiryGuardAsset(name string) (*os.File, error) {
	if name != "arcway-expiry-guard-linux-amd64" && name != "arcway-expiry-guard-linux-arm64" {
		return nil, errExpiryGuardAssetNotFound
	}
	for _, directory := range expiryGuardAssetDirectories() {
		path := filepath.Join(directory, name)
		linkInfo, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect expiry guard asset: %w", err)
		}
		if !linkInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("expiry guard asset is not a regular file")
		}
		asset, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open expiry guard asset: %w", err)
		}
		openedInfo, err := asset.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
			asset.Close()
			return nil, fmt.Errorf("expiry guard asset changed while opening")
		}
		return asset, nil
	}
	return nil, errExpiryGuardAssetNotFound
}

func expiryGuardAssetSHA256(name string) (string, error) {
	asset, err := openExpiryGuardAsset(name)
	if err != nil {
		return "", err
	}
	defer asset.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, asset); err != nil {
		return "", fmt.Errorf("hash expiry guard asset: %w", err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
