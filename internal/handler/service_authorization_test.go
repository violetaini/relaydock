package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type serviceAuthorizationFixture struct {
	repo     *storage.TrafficRepository
	handler  *ServiceAuthorizationHandler
	packages *PackageAssignHandler
	dbPath   string
}

func newServiceAuthorizationFixture(t *testing.T) serviceAuthorizationFixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "service-authorization.db")
	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "admin", "admin@example.test", "Admin", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	packages := NewPackageAssignHandler(repo, nil, nil)
	managed := NewManagedNodesHandler(repo, nil, nil)
	forwarding := NewForwardingHandler(repo, nil)
	return serviceAuthorizationFixture{
		repo: repo, packages: packages, dbPath: dbPath,
		handler: NewServiceAuthorizationHandler(repo, packages, managed, forwarding),
	}
}

func (f serviceAuthorizationFixture) addServer(t *testing.T) *storage.RemoteServer {
	t.Helper()
	server := &storage.RemoteServer{
		Name: "service-authorization-edge", Token: "token", Status: storage.RemoteServerStatusConnected,
		IPAddress: "203.0.113.20", XrayMode: "embedded",
	}
	if err := f.repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	return server
}

func (f serviceAuthorizationFixture) batchRequest(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/users/service-authorization/batch", bytes.NewReader(payload))
	response := httptest.NewRecorder()
	f.handler.HandleBatch(response, request)
	return response
}

func TestServiceAuthorizationBatchRequiresExplicitCompleteCustomReplacement(t *testing.T) {
	fixture := newServiceAuthorizationFixture(t)
	response := fixture.batchRequest(t, map[string]any{
		"usernames": []string{"alice"},
		"mode":      storage.AuthorizationModeCustom,
		"custom": map[string]any{
			"fixed_node_grants": []any{},
		},
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	user, err := fixture.repo.GetUser(context.Background(), "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModeCustom || user.PackageID != 0 {
		t.Fatalf("invalid request mutated user: user=%+v err=%v", user, err)
	}
}

func TestServiceAuthorizationSwitchCustomToPackageLeavesManualTombstone(t *testing.T) {
	fixture := newServiceAuthorizationFixture(t)
	server := fixture.addServer(t)
	now := time.Now().UTC().Truncate(time.Second)
	manual, err := fixture.repo.CreateUserServerGrant(context.Background(), storage.UserServerGrant{
		Username: "alice", ServerID: server.ID, Enabled: true, StartsAt: now.Add(-time.Hour),
		BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := fixture.repo.CreatePackage(context.Background(), storage.Package{
		Name: "empty-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.batchRequest(t, map[string]any{
		"usernames": []string{"alice"}, "mode": storage.AuthorizationModePackage,
		"package": map[string]any{"package_id": packageID},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	user, err := fixture.repo.GetUser(context.Background(), "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != packageID {
		t.Fatalf("package switch result: user=%+v err=%v", user, err)
	}
	manual, err = fixture.repo.GetUserServerGrant(context.Background(), manual.ID)
	if err != nil || manual.Enabled || manual.SourceType != storage.GrantSourceManual {
		t.Fatalf("manual grant was not retained as an inactive tombstone: grant=%+v err=%v", manual, err)
	}
}

func TestServiceAuthorizationSwitchPackageToCustomAdoptsPackageTombstone(t *testing.T) {
	fixture := newServiceAuthorizationFixture(t)
	server := fixture.addServer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "server-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []storage.PackageServerGrant{{
			ServerID: server.ID, BillingMode: storage.ManagedBillingDownload,
			ResetPolicy: storage.ManagedResetNone, ResetDay: 1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.packages.AssignAndProvision(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	response := fixture.batchRequest(t, map[string]any{
		"usernames": []string{"alice"}, "mode": storage.AuthorizationModeCustom,
		"custom": map[string]any{
			"fixed_node_grants": []any{}, "forwarding_grants": []any{},
			"server_grants": []any{map[string]any{
				"server_id": server.ID, "enabled": true, "starts_at": now,
				"expires_at": nil, "max_active_nodes": 2, "speed_limit_mbps": 0,
				"connection_limit": 0, "traffic_limit_bytes": 2048,
				"billing_mode": storage.ManagedBillingDownload, "reset_policy": storage.ManagedResetNone,
				"reset_day": 1, "allowed_protocols": []any{}, "allowed_protocol_profiles": []any{},
			}},
		},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModeCustom || user.PackageID != 0 {
		t.Fatalf("custom switch result: user=%+v err=%v", user, err)
	}
	grants, err := fixture.repo.ListUserServerGrants(ctx, "alice")
	if err != nil || len(grants) != 1 || !grants[0].Enabled || grants[0].SourceType != storage.GrantSourceManual {
		t.Fatalf("package tombstone was not adopted: grants=%+v err=%v", grants, err)
	}
}

func TestServiceAuthorizationSwitchPackageToCustomDeletesPackageSubscriptionWithoutWarning(t *testing.T) {
	fixture := newServiceAuthorizationFixture(t)
	t.Setenv("ARCWAY_SUBSCRIPTION_LOCK_DIR", t.TempDir())
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "subscription-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.packages.AssignAndProvision(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	file, err := fixture.repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
		Name: "alice package", Type: storage.SubscribeTypePackage,
		Filename: "service-authorization-alice.yaml", CreatedBy: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.repo.AssignSubscriptionToUser(ctx, "alice", file.ID); err != nil {
		t.Fatal(err)
	}

	response := fixture.batchRequest(t, map[string]any{
		"usernames": []string{"alice"}, "mode": storage.AuthorizationModeCustom,
		"custom": map[string]any{
			"fixed_node_grants": []any{}, "server_grants": []any{}, "forwarding_grants": []any{},
		},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Results []serviceAuthorizationResult `json:"results"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Results) != 1 || len(payload.Results[0].Warnings) != 0 {
		t.Fatalf("unexpected authorization result: %+v", payload.Results)
	}
	if _, err := fixture.repo.GetUserPackageSubscription(ctx, "alice"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("package subscription was not deleted: %v", err)
	}
}

func TestServiceAuthorizationPackageToCustomDBFailureRestoresPackage(t *testing.T) {
	fixture := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "rollback-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.packages.AssignAndProvision(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", fixture.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TRIGGER reject_service_unbind
BEFORE UPDATE OF package_id ON users
WHEN OLD.username='alice' AND NEW.package_id IS NULL
BEGIN SELECT RAISE(ABORT, 'forced unbind failure'); END`); err != nil {
		t.Fatal(err)
	}
	response := fixture.batchRequest(t, map[string]any{
		"usernames": []string{"alice"}, "mode": storage.AuthorizationModeCustom,
		"custom": map[string]any{
			"fixed_node_grants": []any{},
			"server_grants":     []any{}, "forwarding_grants": []any{},
		},
	})
	if response.Code != http.StatusMultiStatus {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != packageID ||
		user.PackageStartDate == nil || user.PackageEndDate == nil {
		t.Fatalf("failed switch did not preserve package: user=%+v err=%v", user, err)
	}
}

func TestServiceAuthorizationPackageCleanupFailureRestoresPackageMode(t *testing.T) {
	fixture := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	server := fixture.addServer(t)
	node, err := fixture.repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "package-selection", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"package-selection","type":"vless","server":"203.0.113.20","port":443}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := fixture.repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "selection-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []storage.PackageServerGrant{{
			ServerID: server.ID, MaxActiveNodes: 1, BillingMode: storage.ManagedBillingDownload,
			ResetPolicy: storage.ManagedResetNone, ResetDay: 1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := fixture.packages.AssignAndProvision(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now); err != nil {
		t.Fatal(err)
	}

	response := fixture.batchRequest(t, map[string]any{
		"usernames": []string{"alice"}, "mode": storage.AuthorizationModeCustom,
		"custom": map[string]any{
			"fixed_node_grants": []any{}, "server_grants": []any{}, "forwarding_grants": []any{},
		},
	})
	if response.Code != http.StatusMultiStatus {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != packageID {
		t.Fatalf("failed cleanup did not restore package mode: user=%+v err=%v", user, err)
	}
	selections, err := fixture.repo.ListUserNodeSelections(ctx, "alice", false)
	if err != nil || len(selections) != 1 || !selections[0].DesiredEnabled {
		t.Fatalf("failed cleanup did not restore package selection: selections=%+v err=%v", selections, err)
	}
}

func TestPackageSwitchCleanupFailureRestoresPreviousPackage(t *testing.T) {
	fixture := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	server := fixture.addServer(t)
	node, err := fixture.repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "old-package-selection", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"old-package-selection","type":"vless","server":"203.0.113.20","port":443}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := fixture.repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	oldPackageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "old-server-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
		ServerGrants: []storage.PackageServerGrant{{
			ServerID: server.ID, MaxActiveNodes: 1, BillingMode: storage.ManagedBillingDownload,
			ResetPolicy: storage.ManagedResetNone, ResetDay: 1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	newPackageID, err := fixture.repo.CreatePackage(ctx, storage.Package{
		Name: "new-empty-package", TrafficLimitBytes: 1024, CycleDays: 30, ResetDay: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if _, err := fixture.packages.AssignAndProvision(ctx, "alice", oldPackageID, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.packages.AssignAndProvision(ctx, "alice", newPackageID, start, end, false, 1); err == nil {
		t.Fatal("package switch unexpectedly succeeded while old child cleanup was unavailable")
	}
	user, err := fixture.repo.GetUser(ctx, "alice")
	if err != nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID != oldPackageID {
		t.Fatalf("failed switch did not restore old package: user=%+v err=%v", user, err)
	}
	selections, err := fixture.repo.ListUserNodeSelections(ctx, "alice", false)
	if err != nil || len(selections) != 1 || !selections[0].DesiredEnabled {
		t.Fatalf("failed switch did not restore old package selection: selections=%+v err=%v", selections, err)
	}
}
