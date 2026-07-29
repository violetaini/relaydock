package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func newUserTrafficLimitTestRepo(t *testing.T) (*storage.TrafficRepository, storage.User, *storage.Package) {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic-limit.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{Name: "Standard", TrafficLimitBytes: 100 * userTrafficLimitBytesPerGB, CycleDays: 30, ResetDay: 1})
	if err != nil {
		t.Fatalf("CreatePackage: %v", err)
	}
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, time.Now().UTC(), time.Now().UTC().Add(30*24*time.Hour), false, 1); err != nil {
		t.Fatalf("AssignPackageToUser: %v", err)
	}
	user, _ := repo.GetUser(ctx, "alice")
	pkg, _ := repo.GetPackage(ctx, packageID)
	return repo, user, pkg
}

func TestResolveTrafficLimitBytesAndBoundary(t *testing.T) {
	pkg := &storage.Package{TrafficLimitBytes: 100}
	if got := resolveTrafficLimitBytes(nil, pkg); got != 100 {
		t.Fatalf("inherited limit=%d, want 100", got)
	}
	zero := int64(0)
	if got := resolveTrafficLimitBytes(&storage.User{TrafficLimitOverride: &zero}, pkg); got != 0 {
		t.Fatalf("explicit unlimited=%d, want 0", got)
	}
	override := int64(75)
	if got := resolveTrafficLimitBytes(&storage.User{TrafficLimitOverride: &override}, pkg); got != 75 {
		t.Fatalf("override=%d, want 75", got)
	}
	if trafficLimitExceeded(99, 100) || !trafficLimitExceeded(100, 100) || trafficLimitExceeded(1000, 0) {
		t.Fatal("traffic limit boundary semantics changed")
	}
}

func TestUserTrafficLimitHandlerPreservesThreeStates(t *testing.T) {
	repo, _, _ := newUserTrafficLimitTestRepo(t)
	if err := repo.CreateUser(context.Background(), "bob", "bob@example.test", "Bob", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	handler := NewUserTrafficLimitHandler(repo)
	tests := []struct {
		name       string
		body       string
		wantStatus int
		want       *int64
	}{
		{name: "positive override", body: `{"username":"alice","traffic_limit_override_gb":12.5}`, wantStatus: http.StatusOK, want: int64Ptr(12.5 * userTrafficLimitBytesPerGB)},
		{name: "explicit unlimited", body: `{"username":"alice","traffic_limit_override_gb":0}`, wantStatus: http.StatusOK, want: int64Ptr(0)},
		{name: "inherit package", body: `{"username":"alice","traffic_limit_override_gb":null}`, wantStatus: http.StatusOK, want: nil},
		{name: "negative rejected", body: `{"username":"alice","traffic_limit_override_gb":-1}`, wantStatus: http.StatusBadRequest, want: nil},
		{name: "package required", body: `{"username":"bob","traffic_limit_override_gb":10}`, wantStatus: http.StatusConflict, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/api/admin/users/traffic-limit", strings.NewReader(tt.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tt.wantStatus, response.Body.String())
			}
			if tt.wantStatus != http.StatusOK {
				return
			}
			user, err := repo.GetUser(context.Background(), "alice")
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}
			if tt.want == nil {
				if user.TrafficLimitOverride != nil {
					t.Fatalf("override=%v, want nil", *user.TrafficLimitOverride)
				}
			} else if user.TrafficLimitOverride == nil || *user.TrafficLimitOverride != *tt.want {
				t.Fatalf("override=%v, want %d", user.TrafficLimitOverride, *tt.want)
			}
		})
	}
}

func TestSubscriptionTrafficHeaderUsesEffectiveOverride(t *testing.T) {
	repo, user, pkg := newUserTrafficLimitTestRepo(t)
	handler := &PackageSubscribeHandler{repo: repo}
	override := int64(25 * userTrafficLimitBytesPerGB)
	user.TrafficLimitOverride = &override
	response := httptest.NewRecorder()
	handler.writeTrafficHeader(context.Background(), response, user, pkg)
	if got := response.Header().Get("subscription-userinfo"); !strings.Contains(got, "total=26843545600") {
		t.Fatalf("subscription-userinfo=%q, want override total", got)
	}

	zero := int64(0)
	user.TrafficLimitOverride = &zero
	response = httptest.NewRecorder()
	handler.writeTrafficHeader(context.Background(), response, user, pkg)
	if got := response.Header().Get("subscription-userinfo"); got != "" {
		t.Fatalf("explicit unlimited emitted subscription-userinfo=%q", got)
	}
}

func TestUserListReturnsEffectiveTrafficOverride(t *testing.T) {
	repo, _, _ := newUserTrafficLimitTestRepo(t)
	override := int64(12.5 * userTrafficLimitBytesPerGB)
	if err := repo.UpdateUserTrafficLimitOverride(context.Background(), "alice", &override); err != nil {
		t.Fatalf("UpdateUserTrafficLimitOverride: %v", err)
	}
	response := httptest.NewRecorder()
	NewUserListHandler(repo).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/admin/users", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Users []struct {
			Username               string   `json:"username"`
			TrafficLimit           int64    `json:"traffic_limit"`
			TrafficLimitOverrideGB *float64 `json:"traffic_limit_override_gb"`
		} `json:"users"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode user list: %v", err)
	}
	if len(payload.Users) != 1 || payload.Users[0].Username != "alice" || payload.Users[0].TrafficLimit != override ||
		payload.Users[0].TrafficLimitOverrideGB == nil || *payload.Users[0].TrafficLimitOverrideGB != 12.5 {
		t.Fatalf("unexpected user list payload: %+v", payload.Users)
	}
}

func TestUnlimitedOverrideClearsPersistedOverLimitState(t *testing.T) {
	repo, _, _ := newUserTrafficLimitTestRepo(t)
	ctx := context.Background()
	server := &storage.RemoteServer{
		Name: "limit-edge", Token: "limit-edge-token", Status: storage.RemoteServerStatusConnected,
		XrayMode: "embedded", ConnectionMode: storage.ConnectionModePush,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	if err := repo.UpsertUserTraffic(ctx, server.ID, "alice", 0, 0, false); err != nil {
		t.Fatalf("seed user traffic: %v", err)
	}
	if err := repo.UpsertUserTraffic(ctx, server.ID, "alice", 60, 50, false); err != nil {
		t.Fatalf("accumulate user traffic: %v", err)
	}
	limit := int64(100)
	if err := repo.UpdateUserTrafficLimitOverride(ctx, "alice", &limit); err != nil {
		t.Fatalf("set finite override: %v", err)
	}
	enforcer := NewTrafficLimitEnforcer(repo, nil, nil)
	enforcer.CheckAll(ctx)
	over, err := repo.IsUserOverLimit(ctx, "alice")
	if err != nil || !over {
		t.Fatalf("over-limit state=(%v,%v), want true at boundary", over, err)
	}
	zero := int64(0)
	if err := repo.UpdateUserTrafficLimitOverride(ctx, "alice", &zero); err != nil {
		t.Fatalf("UpdateUserTrafficLimitOverride: %v", err)
	}
	enforcer.CheckAll(ctx)
	over, err = repo.IsUserOverLimit(ctx, "alice")
	if err != nil || over {
		t.Fatalf("over-limit state=(%v,%v), want false", over, err)
	}
}

func int64Ptr(value float64) *int64 {
	converted := int64(value)
	return &converted
}
