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
	if got := resolveTrafficLimitBytes(nil, pkg); got != 0 {
		t.Fatalf("retired package aggregate limit=%d, want 0", got)
	}
	zero := int64(0)
	if got := resolveTrafficLimitBytes(&storage.User{AuthorizationMode: storage.AuthorizationModePackage, PackageID: 1, TrafficLimitOverride: &zero}, pkg); got != 0 {
		t.Fatalf("explicit unlimited=%d, want 0", got)
	}
	override := int64(75)
	if got := resolveTrafficLimitBytes(&storage.User{AuthorizationMode: storage.AuthorizationModePackage, PackageID: 1, TrafficLimitOverride: &override}, pkg); got != 0 {
		t.Fatalf("package-mode legacy override=%d, want 0", got)
	}
	if got := resolveTrafficLimitBytes(&storage.User{AuthorizationMode: storage.AuthorizationModeCustom, TrafficLimitOverride: &override}, pkg); got != 0 {
		t.Fatalf("custom legacy override=%d, want 0", got)
	}
	if trafficLimitExceeded(99, 100) || !trafficLimitExceeded(100, 100) || trafficLimitExceeded(1000, 0) {
		t.Fatal("traffic limit boundary semantics changed")
	}
}

func TestUserTrafficLimitHandlerOnlyClearsLegacyOverride(t *testing.T) {
	repo, _, _ := newUserTrafficLimitTestRepo(t)
	if err := repo.CreateUser(context.Background(), "bob", "bob@example.test", "Bob", "hash", storage.RoleUser, ""); err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	handler := NewUserTrafficLimitHandler(repo)
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantNil    bool
	}{
		{name: "positive retired", body: `{"username":"alice","traffic_limit_override_gb":12.5}`, wantStatus: http.StatusBadRequest},
		{name: "zero retired", body: `{"username":"alice","traffic_limit_override_gb":0}`, wantStatus: http.StatusBadRequest},
		{name: "null clears", body: `{"username":"alice","traffic_limit_override_gb":null}`, wantStatus: http.StatusOK, wantNil: true},
		{name: "custom positive retired", body: `{"username":"bob","traffic_limit_override_gb":10}`, wantStatus: http.StatusBadRequest},
	}
	legacy := int64(123)
	if err := repo.UpdateUserTrafficLimitOverride(context.Background(), "alice", &legacy); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/api/admin/users/traffic-limit", strings.NewReader(tt.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tt.wantStatus, response.Body.String())
			}
			if tt.wantStatus != http.StatusOK || !tt.wantNil {
				return
			}
			user, err := repo.GetUser(context.Background(), "alice")
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}
			if user.TrafficLimitOverride != nil {
				t.Fatalf("override=%v, want nil", *user.TrafficLimitOverride)
			}
		})
	}
}

func TestSubscriptionTrafficHeaderIgnoresLegacyPackageOverride(t *testing.T) {
	repo, user, pkg := newUserTrafficLimitTestRepo(t)
	handler := &PackageSubscribeHandler{repo: repo}
	override := int64(25 * userTrafficLimitBytesPerGB)
	user.TrafficLimitOverride = &override
	response := httptest.NewRecorder()
	handler.writeTrafficHeader(context.Background(), response, user, pkg)
	if got := response.Header().Get("subscription-userinfo"); got != "" {
		t.Fatalf("legacy package override emitted subscription-userinfo=%q", got)
	}

	zero := int64(0)
	user.TrafficLimitOverride = &zero
	response = httptest.NewRecorder()
	handler.writeTrafficHeader(context.Background(), response, user, pkg)
	if got := response.Header().Get("subscription-userinfo"); got != "" {
		t.Fatalf("explicit unlimited emitted subscription-userinfo=%q", got)
	}
}

func TestUserListHidesRetiredAggregatesAndReturnsDetailedOverrides(t *testing.T) {
	repo, _, _ := newUserTrafficLimitTestRepo(t)
	override := int64(12.5 * userTrafficLimitBytesPerGB)
	if err := repo.UpdateUserTrafficLimitOverride(context.Background(), "alice", &override); err != nil {
		t.Fatalf("UpdateUserTrafficLimitOverride: %v", err)
	}
	speed, devices := 12.0, 4
	if err := repo.UpdateUserLimitOverrides(context.Background(), "alice", &speed, &devices); err != nil {
		t.Fatalf("UpdateUserLimitOverrides: %v", err)
	}
	if err := repo.UpdateUserNodeLimits(context.Background(), "alice", map[int64]float64{7: 8}, map[int64]int{7: 2}); err != nil {
		t.Fatalf("UpdateUserNodeLimits: %v", err)
	}
	response := httptest.NewRecorder()
	NewUserListHandler(repo).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/admin/users", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Users []struct {
			Username                 string            `json:"username"`
			TrafficLimit             int64             `json:"traffic_limit"`
			TrafficLimitOverrideGB   *float64          `json:"traffic_limit_override_gb"`
			SpeedLimitOverride       *float64          `json:"speed_limit_override"`
			DeviceLimitOverride      *int              `json:"device_limit_override"`
			NodeSpeedLimitOverrides  map[int64]float64 `json:"node_speed_limit_overrides"`
			NodeDeviceLimitOverrides map[int64]int     `json:"node_device_limit_overrides"`
		} `json:"users"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode user list: %v", err)
	}
	if len(payload.Users) != 1 || payload.Users[0].Username != "alice" || payload.Users[0].TrafficLimit != 0 ||
		payload.Users[0].TrafficLimitOverrideGB != nil || payload.Users[0].SpeedLimitOverride != nil ||
		payload.Users[0].DeviceLimitOverride == nil || *payload.Users[0].DeviceLimitOverride != 4 ||
		payload.Users[0].NodeSpeedLimitOverrides[7] != 8 || payload.Users[0].NodeDeviceLimitOverrides[7] != 2 {
		t.Fatalf("unexpected user list payload: %+v", payload.Users)
	}
}

func TestLegacyPackageTrafficOverrideDoesNotSetOverLimitState(t *testing.T) {
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
	if err != nil || over {
		t.Fatalf("legacy aggregate override set over-limit state=(%v,%v)", over, err)
	}
}

func TestUserLimitsAllowDeviceButRejectAggregateSpeed(t *testing.T) {
	repo, _, _ := newUserTrafficLimitTestRepo(t)
	handler := NewUserLimitsHandler(repo, nil, nil)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/admin/users/limits",
		strings.NewReader(`{"username":"alice","device_limit_override":4}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("device override status=%d body=%s", response.Code, response.Body.String())
	}
	user, err := repo.GetUser(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.DeviceLimitOverride == nil || *user.DeviceLimitOverride != 4 || user.SpeedLimitOverride != nil {
		t.Fatalf("stored package user limits=%+v", user)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/admin/users/limits",
		strings.NewReader(`{"username":"alice","speed_limit_override":5,"device_limit_override":4}`)))
	if response.Code != http.StatusConflict {
		t.Fatalf("aggregate speed status=%d want=%d body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
	if err := repo.CreateUser(context.Background(), "custom", "custom@example.test", "Custom", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/admin/users/limits",
		strings.NewReader(`{"username":"custom","speed_limit_override":5}`)))
	if response.Code != http.StatusConflict {
		t.Fatalf("custom aggregate speed status=%d want=%d body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
}
