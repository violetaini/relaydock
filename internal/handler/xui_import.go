package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/xui"
)

// XUIMigrateHandler handles 3x-ui evaluation, dry-run inspection, and non-destructive import.
type XUIMigrateHandler struct {
	repo       *storage.TrafficRepository
	rm         *RemoteManageHandler
	mu         sync.RWMutex
	sessions   map[string]*xuiMigrationSession
	sessionTTL time.Duration
}

type xuiMigrationSession struct {
	ID        string
	Model     *xui.XUIModel
	CreatedAt time.Time
}

func NewXUIMigrateHandler(repo *storage.TrafficRepository, rm *RemoteManageHandler) *XUIMigrateHandler {
	h := &XUIMigrateHandler{
		repo:       repo,
		rm:         rm,
		sessions:   make(map[string]*xuiMigrationSession),
		sessionTTL: 2 * time.Hour,
	}
	go h.cleanupLoop()
	return h
}

func (h *XUIMigrateHandler) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.mu.Lock()
		now := time.Now()
		for id, sess := range h.sessions {
			if now.Sub(sess.CreatedAt) > h.sessionTTL {
				delete(h.sessions, id)
			}
		}
		h.mu.Unlock()
	}
}

func convertServersForInspect(servers []storage.RemoteServer) []*xui.ServerInfo {
	res := make([]*xui.ServerInfo, 0, len(servers))
	for i := range servers {
		s := &servers[i]
		res = append(res, &xui.ServerInfo{
			ID:        s.ID,
			Name:      s.Name,
			IPAddress: s.IPAddress,
		})
	}
	return res
}

func convertNodesForInspect(nodes []storage.Node) []*xui.ExistingNodeInfo {
	res := make([]*xui.ExistingNodeInfo, 0, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		host := n.RelayOrigServer
		if host == "" {
			host = n.OriginalServer
		}
		port := n.RelayOrigPort
		if port == 0 && n.ClashConfig != "" {
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(n.ClashConfig), &m); err == nil {
				if p, ok := m["port"].(float64); ok && p > 0 {
					port = int(p)
				}
				if host == "" {
					if s, ok := m["server"].(string); ok {
						host = s
					}
				}
			}
		}
		res = append(res, &xui.ExistingNodeInfo{
			NodeName: n.NodeName,
			Protocol: n.Protocol,
			Host:     host,
			Port:     port,
		})
	}
	return res
}

// Upload handles uploading of x-ui.db, .zip, .tar.gz, or .json
func (h *XUIMigrateHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 500<<20) // 500 MB limit
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("read uploaded file: %v", err))
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	isArchive := ext == ".zip" || ext == ".tar.gz" || ext == ".tgz"
	isDB := ext == ".db" || ext == ".sqlite"
	isJSON := ext == ".json"

	if !isArchive && !isDB && !isJSON {
		writeJSONError(w, http.StatusBadRequest, "unsupported file format; please upload x-ui.db, .zip, .tar.gz, or .json")
		return
	}

	tmpDir, err := os.MkdirTemp("", "relaydock-xui-upload-*")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to create temp upload directory")
		return
	}
	defer os.RemoveAll(tmpDir)

	tempFile := filepath.Join(tmpDir, header.Filename)
	out, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to write temp file")
		return
	}
	_, err = io.Copy(out, file)
	out.Close()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to copy uploaded file")
		return
	}

	model, err := xui.ParseXUIInput(tempFile)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse 3x-ui data: %v", err))
		return
	}

	sessionID, _ := randomHex(16)
	h.mu.Lock()
	h.sessions[sessionID] = &xuiMigrationSession{
		ID:        sessionID,
		Model:     model,
		CreatedAt: time.Now(),
	}
	h.mu.Unlock()

	// Perform dry-run inspection
	servers, _ := h.repo.ListRemoteServers(r.Context())
	existingNodes, _ := h.repo.ListAllNodes(r.Context())
	report := xui.Inspect(model, convertServersForInspect(servers), convertNodesForInspect(existingNodes))

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"migration_id": sessionID,
		"filename":     header.Filename,
		"source":       model.Source,
		"report":       report,
	})
}

// Inspect handles dry-run evaluation of 3x-ui data
func (h *XUIMigrateHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST allowed")
		return
	}

	var req struct {
		MigrationID string `json:"migration_id"`
		RawJSON     string `json:"raw_json"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var model *xui.XUIModel
	if req.MigrationID != "" {
		h.mu.RLock()
		sess, ok := h.sessions[req.MigrationID]
		h.mu.RUnlock()
		if !ok || sess.Model == nil {
			writeJSONError(w, http.StatusNotFound, "migration session expired or not found")
			return
		}
		model = sess.Model
	} else if strings.TrimSpace(req.RawJSON) != "" {
		var err error
		model, err = xui.ParseXUIJSON([]byte(req.RawJSON))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("parse raw JSON: %v", err))
			return
		}
	} else {
		writeJSONError(w, http.StatusBadRequest, "migration_id or raw_json is required")
		return
	}

	servers, _ := h.repo.ListRemoteServers(r.Context())
	existingNodes, _ := h.repo.ListAllNodes(r.Context())
	report := xui.Inspect(model, convertServersForInspect(servers), convertNodesForInspect(existingNodes))

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"report":  report,
	})
}

// Import safely executes the database import without disrupting remote 3x-ui services
func (h *XUIMigrateHandler) Import(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "only POST allowed")
		return
	}

	admin := strings.TrimSpace(auth.UsernameFromContext(r.Context()))
	if admin == "" {
		writeJSONError(w, http.StatusForbidden, "unauthorized admin")
		return
	}

	var req xui.XUIImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TargetUsername == "" {
		req.TargetUsername = admin
	}

	var model *xui.XUIModel
	if req.MigrationID != "" {
		h.mu.RLock()
		sess, ok := h.sessions[req.MigrationID]
		h.mu.RUnlock()
		if !ok || sess.Model == nil {
			writeJSONError(w, http.StatusNotFound, "migration session expired or not found")
			return
		}
		model = sess.Model
	} else if strings.TrimSpace(req.RawJSON) != "" {
		var err error
		model, err = xui.ParseXUIJSON([]byte(req.RawJSON))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("parse raw JSON: %v", err))
			return
		}
	} else {
		writeJSONError(w, http.StatusBadRequest, "migration_id or raw_json is required")
		return
	}

	result, err := h.repo.ImportXUIModel(r.Context(), model, &req)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("import failed: %v", err))
		return
	}

	log.Printf("[XUI Migrate] Successfully imported %d nodes and %d clients for user %s",
		result.ImportedNodes, result.ImportedClients, req.TargetUsername)

	respondJSON(w, http.StatusOK, result)
}

// DetectRemote queries a remote server's agent to check if 3x-ui is running side-by-side
func (h *XUIMigrateHandler) DetectRemote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "only GET allowed")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var serverID int64
	for i, part := range parts {
		if part == "remote-servers" && i+1 < len(parts) {
			id, err := strconv.ParseInt(parts[i+1], 10, 64)
			if err == nil {
				serverID = id
				break
			}
		}
	}
	if serverID <= 0 {
		if qID := r.URL.Query().Get("server_id"); qID != "" {
			serverID, _ = strconv.ParseInt(qID, 10, 64)
		}
	}
	if serverID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid or missing server_id parameter")
		return
	}

	server, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("server %d not found", serverID))
		return
	}

	raw, err := h.rm.forwardToRemoteServer(r.Context(), serverID, "GET", "/api/child/xui/detect", nil)
	if err != nil {
		// If agent endpoint not yet available, return fallback non-invasive check
		respondJSON(w, http.StatusOK, xui.RemoteXUIDetection{
			Installed:    false,
			Running:      false,
			IsCoexisting: false,
			DetectedAt:   time.Now(),
			Message:      fmt.Sprintf("Agent on server %s (%s) does not report 3x-ui daemon or endpoint is offline: %v", server.Name, server.IPAddress, err),
		})
		return
	}

	var detection xui.RemoteXUIDetection
	if err := json.Unmarshal(raw, &detection); err != nil {
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("parse agent response: %v", err))
		return
	}

	detection.DetectedAt = time.Now()
	respondJSON(w, http.StatusOK, detection)
}
