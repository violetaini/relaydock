package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func (h *TGBotAPIHandler) announcementsPending(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	items, err := h.repo.ListPendingBotAnnouncements(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type pendingAnnouncement struct {
		ID         int64   `json:"id"`
		Title      string  `json:"title"`
		Body       string  `json:"body"`
		Recipients []int64 `json:"recipients"`
	}
	output := make([]pendingAnnouncement, 0, len(items))
	users, err := h.repo.ListActivePackageTGUsers(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	packageNodes := make(map[int64]map[int64]struct{})
	for _, item := range items {
		recipients := make([]int64, 0, len(users))
		for _, user := range users {
			if item.NodeID != 0 {
				nodes, ok := packageNodes[user.PackageID]
				if !ok {
					nodes = make(map[int64]struct{})
					if pkg, packageErr := h.repo.GetPackage(ctx, user.PackageID); packageErr == nil && pkg != nil {
						for _, nodeID := range pkg.Nodes {
							nodes[nodeID] = struct{}{}
						}
					}
					packageNodes[user.PackageID] = nodes
				}
				if _, ok := nodes[item.NodeID]; !ok {
					continue
				}
			}
			recipients = append(recipients, user.TelegramID)
		}
		output = append(output, pendingAnnouncement{
			ID: item.ID, Title: item.Title, Body: item.Body, Recipients: recipients,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "announcements": output})
}

func (h *TGBotAPIHandler) announcementDelivered(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.ID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.repo.MarkAnnouncementBotDelivered(r.Context(), request.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (h *TGBotAPIHandler) announcementsActive(w http.ResponseWriter, r *http.Request) {
	items, err := h.repo.ListActiveAnnouncements(r.Context(), true)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items = filterAnnouncementsForUser(r.Context(), h.repo, r.URL.Query().Get("username"), items)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "announcements": items})
}

func (h *TGBotAPIHandler) postAnnouncement(w http.ResponseWriter, r *http.Request) {
	var request announcementCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id, err := createAnnouncement(r.Context(), h.repo, request)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errAnnouncementBodyRequired) {
			status = http.StatusBadRequest
		}
		writeJSONError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "id": id})
}

type announcementCreateRequest struct {
	Type           string `json:"type"`
	Title          string `json:"title"`
	Body           string `json:"body"`
	NodeID         int64  `json:"node_id"`
	ExpiresMinutes int    `json:"expires_minutes"`
	ViaBot         *bool  `json:"via_bot"`
	ViaMiniapp     *bool  `json:"via_miniapp"`
}

var errAnnouncementBodyRequired = errors.New("body required")

func createAnnouncement(ctx context.Context, repo *storage.TrafficRepository, request announcementCreateRequest) (int64, error) {
	body := strings.TrimSpace(request.Body)
	if body == "" {
		return 0, errAnnouncementBodyRequired
	}
	announcementType := strings.TrimSpace(request.Type)
	if announcementType == "" {
		announcementType = "general"
	}
	viaBot, viaMiniapp := true, true
	if request.ViaBot != nil {
		viaBot = *request.ViaBot
	}
	if request.ViaMiniapp != nil {
		viaMiniapp = *request.ViaMiniapp
	}
	var expiresAt *time.Time
	if request.ExpiresMinutes > 0 {
		value := time.Now().Add(time.Duration(request.ExpiresMinutes) * time.Minute)
		expiresAt = &value
	}
	return repo.CreateAnnouncement(ctx, storage.Announcement{
		Type: announcementType, Title: strings.TrimSpace(request.Title), Body: body,
		NodeID: request.NodeID, ViaBot: viaBot, ViaMiniapp: viaMiniapp, ExpiresAt: expiresAt,
	})
}

func filterAnnouncementsForUser(ctx context.Context, repo *storage.TrafficRepository, username string, items []storage.Announcement) []storage.Announcement {
	username = strings.TrimSpace(username)
	if username == "" {
		return []storage.Announcement{}
	}
	user, err := repo.GetUser(ctx, username)
	if err != nil || user.PackageID <= 0 || user.PackageEndDate != nil && !user.PackageEndDate.After(time.Now()) {
		return []storage.Announcement{}
	}
	nodes := make(map[int64]struct{})
	if pkg, err := repo.GetPackage(ctx, user.PackageID); err == nil && pkg != nil {
		for _, nodeID := range pkg.Nodes {
			nodes[nodeID] = struct{}{}
		}
	}
	filtered := make([]storage.Announcement, 0, len(items))
	for _, item := range items {
		if item.NodeID != 0 {
			if _, ok := nodes[item.NodeID]; !ok {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

// AnnouncementAdminHandler supports the Mini App's announcement list and delete actions.
type AnnouncementAdminHandler struct{ repo *storage.TrafficRepository }

func NewAnnouncementAdminHandler(repo *storage.TrafficRepository) http.Handler {
	return &AnnouncementAdminHandler{repo: repo}
}

func (h *AnnouncementAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := h.repo.ListActiveAnnouncements(r.Context(), false)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "announcements": items})
	case http.MethodPost:
		var request announcementCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		id, err := createAnnouncement(r.Context(), h.repo, request)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "id": id})
	case http.MethodDelete:
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil || id <= 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid id")
			return
		}
		if err := h.repo.DeleteAnnouncement(r.Context(), id); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
