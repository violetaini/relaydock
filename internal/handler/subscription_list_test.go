package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestSubscriptionInventoryDescribesAssignedAndOwnedWithoutExposingRecipes(t *testing.T) {
	repo := newManagedSecurityTestRepo(t)
	ctx := context.Background()
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	createManagedSecurityTestUser(t, repo, "bob", storage.RoleUser)
	global := httptest.NewRecorder()
	NewSubscriptionListHandler(repo).ServeHTTP(global, httptest.NewRequest(http.MethodGet, "/api/subscriptions", nil).WithContext(auth.ContextWithGlobalAPIToken(ctx)))
	if global.Code != http.StatusOK {
		t.Fatalf("global API inventory status=%d", global.Code)
	}
	generation := &storage.SubscriptionGeneration{Kind: "strategy", SourceIDs: []int64{999}, Outputs: []storage.SubscriptionOutput{{Client: "clashmeta", Mode: "full", TemplateFilename: "private-template.yaml"}, {Client: "v2ray", Mode: "nodes"}}}
	shared, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{Name: "Shared", Type: storage.SubscribeTypeCreate, Filename: "shared.yaml", CreatedBy: "admin", URL: "https://private-source.example/?token=owner-secret", Generation: generation, SelectedNodeIDs: []int64{123}})
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"alice", "bob"} {
		_, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{Name: owner + " private", Type: storage.SubscribeTypeUpload, Filename: owner + ".yaml", CreatedBy: owner})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.AssignSubscriptionToUser(ctx, "alice", shared.ID); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/subscriptions", nil).WithContext(auth.ContextWithUsername(ctx, "alice"))
	w := httptest.NewRecorder()
	NewSubscriptionListHandler(repo).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	for _, private := range []string{"owner-secret", "private-source.example", "private-template.yaml", "selected_node_ids", "source_ids", "bob private"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatalf("delivery metadata exposed %s", private)
		}
	}
	var payload struct {
		Subscriptions []struct {
			Name    string   `json:"name"`
			Kind    string   `json:"kind"`
			Access  string   `json:"access_source"`
			Manage  bool     `json:"can_manage"`
			Clients []string `json:"available_clients"`
		} `json:"subscriptions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Subscriptions) != 2 {
		t.Fatalf("inventory=%s", w.Body.String())
	}
	for _, file := range payload.Subscriptions {
		if file.Name == "Shared" && (file.Access != "assigned" || file.Manage || file.Kind != "strategy" || len(file.Clients) != 2) {
			t.Fatalf("assigned metadata=%+v", file)
		}
		if file.Name == "alice private" && (file.Access != "owned" || !file.Manage || file.Kind != "external") {
			t.Fatalf("owned metadata=%+v", file)
		}
	}
	// Knowing a delivered file ID does not grant permission to change its source.
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		r = httptest.NewRequest(method, "/api/admin/subscribe-files/"+strconv.FormatInt(shared.ID, 10), strings.NewReader(`{"name":"tampered"}`)).WithContext(auth.ContextWithUsername(ctx, "alice"))
		w = httptest.NewRecorder()
		NewSubscribeFilesHandler(repo).ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("assigned mutation %s status=%d", method, w.Code)
		}
	}
}

func subscriptionListResponse(t *testing.T, handler http.Handler, username string) map[string]bool {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/subscriptions", nil)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), username))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list subscriptions status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Subscriptions []struct {
			Name      string `json:"name"`
			CanDelete bool   `json:"can_delete"`
		} `json:"subscriptions"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode subscriptions: %v", err)
	}
	result := make(map[string]bool, len(payload.Subscriptions))
	for _, item := range payload.Subscriptions {
		result[item.Name] = item.CanDelete
	}
	return result
}

func TestSubscriptionListReportsDeletePermission(t *testing.T) {
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	adminFile, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name: "管理员分配", Type: storage.SubscribeTypeCreate, Filename: "admin.yaml", CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("create admin subscription: %v", err)
	}
	if _, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name: "用户自建", Type: storage.SubscribeTypeCreate, Filename: "alice.yaml", CreatedBy: "alice",
	}); err != nil {
		t.Fatalf("create user subscription: %v", err)
	}
	if err := repo.AssignSubscriptionToUser(context.Background(), "alice", adminFile.ID); err != nil {
		t.Fatalf("assign admin subscription: %v", err)
	}

	handler := NewSubscriptionListHandler(repo)
	alice := subscriptionListResponse(t, handler, "alice")
	if alice["管理员分配"] {
		t.Fatal("ordinary user can delete an assigned subscription")
	}
	if !alice["用户自建"] {
		t.Fatal("ordinary user cannot delete their own subscription")
	}

	admin := subscriptionListResponse(t, handler, "admin")
	if !admin["管理员分配"] || !admin["用户自建"] {
		t.Fatalf("administrator delete permissions = %#v, want all true", admin)
	}
}

func TestSubscribeFilesDeleteHonorsOwnershipAndCleansAssignments(t *testing.T) {
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	handler := NewSubscribeFilesHandler(repo)

	adminFile, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name: "管理员订阅", Type: storage.SubscribeTypeCreate, Filename: "admin-delete.yaml", CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("create admin subscription: %v", err)
	}
	denied := httptest.NewRequest(http.MethodDelete, "/api/admin/subscribe-files/"+strconv.FormatInt(adminFile.ID, 10), nil)
	denied = denied.WithContext(auth.ContextWithUsername(denied.Context(), "alice"))
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusNotFound {
		t.Fatalf("foreign delete status=%d want=%d body=%s", deniedResponse.Code, http.StatusNotFound, deniedResponse.Body.String())
	}
	if _, err := repo.GetSubscribeFileByID(context.Background(), adminFile.ID); err != nil {
		t.Fatalf("denied delete removed admin subscription: %v", err)
	}

	aliceFile, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name: "用户订阅", Type: storage.SubscribeTypeCreate, Filename: "alice-delete.yaml", CreatedBy: "alice",
	})
	if err != nil {
		t.Fatalf("create user subscription: %v", err)
	}
	if err := repo.AssignSubscriptionToUser(context.Background(), "alice", aliceFile.ID); err != nil {
		t.Fatalf("assign user subscription: %v", err)
	}
	allowed := httptest.NewRequest(http.MethodDelete, "/api/admin/subscribe-files/"+strconv.FormatInt(aliceFile.ID, 10), nil)
	allowed = allowed.WithContext(auth.ContextWithUsername(allowed.Context(), "alice"))
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusOK {
		t.Fatalf("owner delete status=%d body=%s", allowedResponse.Code, allowedResponse.Body.String())
	}
	if _, err := repo.GetSubscribeFileByID(context.Background(), aliceFile.ID); !errors.Is(err, storage.ErrSubscribeFileNotFound) {
		t.Fatalf("deleted subscription lookup error=%v, want not found", err)
	}
	assigned, err := repo.GetUserSubscriptionIDs(context.Background(), "alice")
	if err != nil {
		t.Fatalf("list user subscriptions: %v", err)
	}
	if len(assigned) != 0 {
		t.Fatalf("deleted subscription assignments remain: %#v", assigned)
	}
}
