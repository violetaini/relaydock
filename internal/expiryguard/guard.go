package expiryguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/guardwire"
	"github.com/violetaini/relaydock/internal/version"
)

const (
	stateVersion       = 2
	legacyStateVersion = 1
)

var identityKeys = []string{"email", "id", "publicKey", "password", "user", "psk", "auth"}

type Schedule struct {
	Key           string                 `json:"key"`
	Tag           string                 `json:"tag"`
	Protocol      string                 `json:"protocol,omitempty"`
	Client        map[string]interface{} `json:"client"`
	NotAfter      time.Time              `json:"not_after"`
	Attempts      int                    `json:"attempts,omitempty"`
	NextAttemptAt *time.Time             `json:"next_attempt_at,omitempty"`
}

type stateFile struct {
	Version    int              `json:"version"`
	AgentToken string           `json:"agent_token,omitempty"`
	Entries    []Schedule       `json:"entries"`
	Tunnels    []TunnelResource `json:"tunnels,omitempty"`
}

type Guard struct {
	mu          sync.Mutex
	tunnelOpsMu sync.Mutex
	aclMu       sync.Mutex
	statePath   string
	secret      string
	agentToken  string
	agentURL    string
	client      *http.Client
	commands    CommandRunner
	entries     map[string]Schedule
	tunnels     map[string]TunnelResource
	seenNonces  map[string]time.Time
	wake        chan struct{}
}

func New(statePath, secret, agentToken, agentURL string, client *http.Client) (*Guard, error) {
	statePath = strings.TrimSpace(statePath)
	secret = strings.TrimSpace(secret)
	agentToken = strings.TrimSpace(agentToken)
	agentURL = strings.TrimRight(strings.TrimSpace(agentURL), "/")
	if statePath == "" || secret == "" || agentToken == "" || agentURL == "" {
		return nil, errors.New("state path, guard secret, Agent token, and Agent URL are required")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	guard := &Guard{
		statePath:  statePath,
		secret:     secret,
		agentToken: agentToken,
		agentURL:   agentURL,
		client:     client,
		commands:   OSCommandRunner{},
		entries:    make(map[string]Schedule),
		tunnels:    make(map[string]TunnelResource),
		seenNonces: make(map[string]time.Time),
		wake:       make(chan struct{}, 1),
	}
	if err := guard.load(); err != nil {
		return nil, err
	}
	return guard, nil
}

func scheduleKey(tag string, client map[string]interface{}) (string, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" || len(client) == 0 {
		return "", errors.New("tag and client are required")
	}
	for _, field := range identityKeys {
		value := strings.TrimSpace(fmt.Sprint(client[field]))
		if value == "" || value == "<nil>" {
			continue
		}
		sum := sha256.Sum256([]byte(tag + "\x00" + field + "\x00" + value))
		return hex.EncodeToString(sum[:]), nil
	}
	return "", errors.New("client has no supported identity")
}

func (g *Guard) load() error {
	raw, err := os.ReadFile(g.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read expiry state: %w", err)
	}
	var state stateFile
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("decode expiry state: %w", err)
	}
	if state.Version != legacyStateVersion && state.Version != stateVersion {
		return fmt.Errorf("unsupported expiry state version %d", state.Version)
	}
	if strings.TrimSpace(state.AgentToken) != "" {
		g.agentToken = strings.TrimSpace(state.AgentToken)
	}
	for _, entry := range state.Entries {
		key, keyErr := scheduleKey(entry.Tag, entry.Client)
		if keyErr != nil || entry.Key != key || entry.NotAfter.IsZero() {
			return errors.New("expiry state contains an invalid entry")
		}
		entry.NotAfter = entry.NotAfter.UTC()
		g.entries[key] = entry
	}
	for _, resource := range state.Tunnels {
		if err := validatePersistedTunnelResource(resource); err != nil {
			return fmt.Errorf("expiry state contains an invalid tunnel resource: %w", err)
		}
		if _, exists := g.tunnels[resource.ResourceID]; exists {
			return errors.New("expiry state contains duplicate tunnel resources")
		}
		resource.HardNotAfter = resource.HardNotAfter.UTC()
		resource.LeaseUntil = resource.LeaseUntil.UTC()
		resource.UpdatedAt = resource.UpdatedAt.UTC()
		if resource.NextAttemptAt != nil {
			next := resource.NextAttemptAt.UTC()
			resource.NextAttemptAt = &next
		}
		g.tunnels[resource.ResourceID] = resource
	}
	return os.Chmod(g.statePath, 0600)
}

func (g *Guard) persistLocked() (bool, error) {
	dir := filepath.Dir(g.statePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false, fmt.Errorf("create expiry state directory: %w", err)
	}
	entries := make([]Schedule, 0, len(g.entries))
	for _, entry := range g.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	tunnels := make([]TunnelResource, 0, len(g.tunnels))
	for _, resource := range g.tunnels {
		tunnels = append(tunnels, resource)
	}
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ResourceID < tunnels[j].ResourceID })
	temporary, err := os.CreateTemp(dir, ".expiry-state-*")
	if err != nil {
		return false, fmt.Errorf("create expiry state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return false, fmt.Errorf("protect expiry state: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(stateFile{Version: stateVersion, AgentToken: g.agentToken, Entries: entries, Tunnels: tunnels}); err != nil {
		temporary.Close()
		return false, fmt.Errorf("encode expiry state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, fmt.Errorf("sync expiry state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close expiry state: %w", err)
	}
	if err := os.Rename(temporaryPath, g.statePath); err != nil {
		return false, fmt.Errorf("replace expiry state: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return true, fmt.Errorf("open expiry state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return true, fmt.Errorf("sync expiry state directory: %w", err)
	}
	return true, nil
}

func (g *Guard) UpdateAgentToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("Agent token is required")
	}
	g.mu.Lock()
	previous := g.agentToken
	g.agentToken = token
	committed, err := g.persistLocked()
	if err != nil && !committed {
		g.agentToken = previous
	}
	g.mu.Unlock()
	return err
}

func (g *Guard) currentAgentToken() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.agentToken
}

func (g *Guard) notify() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

func (g *Guard) Upsert(schedule Schedule) error {
	key, err := scheduleKey(schedule.Tag, schedule.Client)
	if err != nil {
		return err
	}
	if schedule.NotAfter.IsZero() {
		return errors.New("not_after is required")
	}
	schedule.Key = key
	schedule.Tag = strings.TrimSpace(schedule.Tag)
	schedule.Protocol = strings.TrimSpace(schedule.Protocol)
	schedule.NotAfter = schedule.NotAfter.UTC()
	schedule.Attempts = 0
	schedule.NextAttemptAt = nil
	g.mu.Lock()
	previous, existed := g.entries[key]
	g.entries[key] = schedule
	committed, err := g.persistLocked()
	if err != nil {
		if !committed {
			if existed {
				g.entries[key] = previous
			} else {
				delete(g.entries, key)
			}
		}
		g.mu.Unlock()
		return err
	}
	g.mu.Unlock()
	g.notify()
	return nil
}

func (g *Guard) Delete(tag string, client map[string]interface{}) error {
	key, err := scheduleKey(tag, client)
	if err != nil {
		return err
	}
	g.mu.Lock()
	previous, existed := g.entries[key]
	delete(g.entries, key)
	committed, err := g.persistLocked()
	if err != nil {
		if !committed && existed {
			g.entries[key] = previous
		}
		g.mu.Unlock()
		return err
	}
	g.mu.Unlock()
	g.notify()
	return nil
}

func (g *Guard) Pending() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.entries)
}

func (g *Guard) due(now time.Time) ([]Schedule, time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var next time.Time
	due := make([]Schedule, 0)
	for _, entry := range g.entries {
		attemptAt := entry.NotAfter
		if entry.NextAttemptAt != nil && entry.NextAttemptAt.After(attemptAt) {
			attemptAt = *entry.NextAttemptAt
		}
		if !now.Before(attemptAt) {
			due = append(due, entry)
			continue
		}
		if next.IsZero() || attemptAt.Before(next) {
			next = attemptAt
		}
	}
	return due, next
}

func retryDelay(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 7 {
		attempts = 7
	}
	return time.Duration(1<<(attempts-1)) * 5 * time.Second
}

func (g *Guard) removeClient(ctx context.Context, entry Schedule) error {
	body, err := json.Marshal(map[string]interface{}{
		"action": "remove-client",
		"tag":    entry.Tag,
		"client": entry.Client,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, g.agentURL+"/api/child/inbounds", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+g.currentAgentToken())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", version.AgentUserAgent)
	response, err := g.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	if err != nil {
		return fmt.Errorf("read agent removal ACK: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("agent returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(raw)))
	}
	var ack struct {
		Success        bool   `json:"success"`
		Message        string `json:"message"`
		RuntimeWarning string `json:"runtime_warning"`
	}
	if err := json.Unmarshal(raw, &ack); err != nil {
		return fmt.Errorf("decode agent removal ACK: %w", err)
	}
	if !ack.Success {
		return errors.New("agent did not acknowledge client removal")
	}
	if strings.TrimSpace(ack.RuntimeWarning) != "" {
		// The Agent has persisted the removal but could not change the live
		// inbound. Keep this expiry entry for a later retry; a scheduler must
		// never turn an intentionally stopped Xray into a start request.
		return fmt.Errorf("agent deferred client removal without restarting Xray: %s", strings.TrimSpace(ack.RuntimeWarning))
	}
	return nil
}

func (g *Guard) agentRequest(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(raw))
	}
	request, err := http.NewRequestWithContext(ctx, method, g.agentURL+path, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+g.currentAgentToken())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", version.AgentUserAgent)
	response, err := g.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("agent returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func (g *Guard) finishAttempt(entry Schedule, attemptErr error, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	current, ok := g.entries[entry.Key]
	if !ok || !current.NotAfter.Equal(entry.NotAfter) {
		return
	}
	if attemptErr == nil {
		delete(g.entries, entry.Key)
	} else {
		current.Attempts++
		next := now.Add(retryDelay(current.Attempts)).UTC()
		current.NextAttemptAt = &next
		g.entries[entry.Key] = current
	}
	committed, persistErr := g.persistLocked()
	if persistErr != nil && !committed && attemptErr == nil {
		// The Agent removed the client, but the durable deletion did not commit.
		// Keep the entry in memory so a later retry can persist completion.
		current.Attempts++
		next := now.Add(retryDelay(current.Attempts)).UTC()
		current.NextAttemptAt = &next
		g.entries[entry.Key] = current
	}
}

func (g *Guard) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	// Recreate the guard-owned nftables table before processing deadlines. An
	// apply request still performs the same rebuild synchronously, so a startup
	// failure cannot silently grant a new tunnel without its requested ACL.
	_ = g.InitializeTunnelSafety(ctx)
	for {
		now := time.Now().UTC()
		due, next := g.due(now)
		for _, entry := range due {
			attemptCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := g.removeClient(attemptCtx, entry)
			cancel()
			g.finishAttempt(entry, err, time.Now().UTC())
		}
		dueTunnels, nextTunnel := g.dueTunnels(time.Now().UTC())
		for _, resource := range dueTunnels {
			attemptCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			g.expireOrCleanupTunnel(attemptCtx, resource)
			cancel()
		}
		if len(due) > 0 || len(dueTunnels) > 0 {
			// Recompute after attempts so newly scheduled retries set the timer.
			continue
		}
		if !nextTunnel.IsZero() && (next.IsZero() || nextTunnel.Before(next)) {
			next = nextTunnel
		}
		wait := time.Hour
		if !next.IsZero() {
			wait = time.Until(next)
			if wait < 0 {
				wait = 0
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-g.wake:
		case <-timer.C:
		}
	}
}

func (g *Guard) openRequest(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	metadata := guardwire.Metadata{
		Timestamp: r.Header.Get(guardwire.HeaderTimestamp),
		Nonce:     r.Header.Get(guardwire.HeaderNonce),
		Signature: r.Header.Get(guardwire.HeaderSignature),
	}
	plaintext, err := guardwire.Open(g.secret, r.Method, r.URL.EscapedPath(), body, metadata, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	g.mu.Lock()
	for nonce, seenAt := range g.seenNonces {
		if now.Sub(seenAt) > guardwire.MaxClockSkew {
			delete(g.seenNonces, nonce)
		}
	}
	if _, replayed := g.seenNonces[metadata.Nonce]; replayed {
		g.mu.Unlock()
		return nil, errors.New("replayed guard request")
	}
	g.seenNonces[metadata.Nonce] = now
	g.mu.Unlock()
	return plaintext, nil
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeRequest(raw []byte, target interface{}) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func (g *Guard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	})
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if _, err := g.openRequest(r); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "unauthorized"})
			return
		}
		capabilities := map[string]interface{}{
			"client_expiry":   true,
			"durable":         true,
			"pending":         g.Pending(),
			"pending_tunnels": g.PendingTunnels(),
		}
		for key, value := range g.tunnelCapabilities(r.Context()) {
			capabilities[key] = value
		}
		writeJSON(w, http.StatusOK, capabilities)
	})
	mux.HandleFunc("PUT /v1/schedules", func(w http.ResponseWriter, r *http.Request) {
		raw, err := g.openRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "unauthorized"})
			return
		}
		var schedule Schedule
		if err := decodeRequest(raw, &schedule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid schedule"})
			return
		}
		if err := g.Upsert(schedule); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})
	mux.HandleFunc("DELETE /v1/schedules", func(w http.ResponseWriter, r *http.Request) {
		raw, err := g.openRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "unauthorized"})
			return
		}
		var request struct {
			Tag    string                 `json:"tag"`
			Client map[string]interface{} `json:"client"`
		}
		if err := decodeRequest(raw, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid schedule identity"})
			return
		}
		if err := g.Delete(request.Tag, request.Client); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})
	mux.HandleFunc("PUT /v1/agent-token", func(w http.ResponseWriter, r *http.Request) {
		raw, err := g.openRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "unauthorized"})
			return
		}
		var request struct {
			Token string `json:"token"`
		}
		if err := decodeRequest(raw, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid Agent token"})
			return
		}
		if err := g.UpdateAgentToken(request.Token); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{"error": "Agent token was not persisted"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	})
	g.registerTunnelRoutes(mux)
	return mux
}
