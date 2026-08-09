package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

type proxyProviderFixture struct {
	repo         *storage.TrafficRepository
	handler      http.Handler
	aliceSource1 int64
	aliceSource2 int64
	bobSource    int64
}

func newProxyProviderFixture(t *testing.T) proxyProviderFixture {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "proxy-providers.db"))
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	for _, username := range []string{"alice", "bob"} {
		if err := repo.CreateUser(context.Background(), username, username+"@example.test", username, "test-hash", storage.RoleUser, ""); err != nil {
			t.Fatalf("create user %s: %v", username, err)
		}
	}

	createSource := func(username, name, url string) int64 {
		t.Helper()
		id, err := repo.CreateExternalSubscription(context.Background(), storage.ExternalSubscription{
			Username: username,
			Name:     name,
			URL:      url,
		})
		if err != nil {
			t.Fatalf("create external subscription %s/%s: %v", username, name, err)
		}
		return id
	}

	return proxyProviderFixture{
		repo:         repo,
		handler:      NewProxyProviderConfigsHandler(repo),
		aliceSource1: createSource("alice", "Alice source 1", "https://alice.example/one"),
		aliceSource2: createSource("alice", "Alice source 2", "https://alice.example/two"),
		bobSource:    createSource("bob", "Bob source", "https://bob.example/source"),
	}
}

func proxyProviderDTO(sourceID int64) ProxyProviderConfigDTO {
	return ProxyProviderConfigDTO{
		ExternalSubscriptionID:    sourceID,
		Name:                      "provider",
		Type:                      "http",
		Interval:                  3600,
		Proxy:                     "DIRECT",
		HealthCheckEnabled:        true,
		HealthCheckURL:            "https://www.gstatic.com/generate_204",
		HealthCheckInterval:       300,
		HealthCheckTimeout:        5000,
		HealthCheckLazy:           true,
		HealthCheckExpectedStatus: http.StatusNoContent,
		ProcessMode:               "client",
	}
}

func serveProxyProviderRequest(t *testing.T, handler http.Handler, method, target, username string, dto ProxyProviderConfigDTO) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), username))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestProxyProviderCreateRejectsMissingAndForeignSourcesWithoutDisclosure(t *testing.T) {
	fixture := newProxyProviderFixture(t)
	notFoundBodies := make([]string, 0, 2)

	for _, test := range []struct {
		name       string
		sourceID   int64
		wantStatus int
	}{
		{name: "zero id", sourceID: 0, wantStatus: http.StatusBadRequest},
		{name: "missing source", sourceID: fixture.bobSource + 10_000, wantStatus: http.StatusNotFound},
		{name: "another user's source", sourceID: fixture.bobSource, wantStatus: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			dto := proxyProviderDTO(test.sourceID)
			dto.Username = "bob"
			response := serveProxyProviderRequest(t, fixture.handler, http.MethodPost, "/api/user/proxy-provider-configs", "alice", dto)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), test.wantStatus)
			}
			if test.wantStatus == http.StatusNotFound {
				notFoundBodies = append(notFoundBodies, response.Body.String())
			}
		})
	}

	if len(notFoundBodies) != 2 || notFoundBodies[0] != notFoundBodies[1] {
		t.Fatalf("missing and foreign sources must be indistinguishable: %#v", notFoundBodies)
	}
	configs, err := fixture.repo.ListProxyProviderConfigs(context.Background(), "alice")
	if err != nil {
		t.Fatalf("list configs: %v", err)
	}
	if len(configs) != 0 {
		t.Fatalf("rejected creates persisted configs: %#v", configs)
	}
}

func TestProxyProviderCreateIgnoresForgedUsername(t *testing.T) {
	fixture := newProxyProviderFixture(t)
	dto := proxyProviderDTO(fixture.aliceSource1)
	dto.Username = "bob"
	response := serveProxyProviderRequest(t, fixture.handler, http.MethodPost, "/api/user/proxy-provider-configs", "alice", dto)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	var created ProxyProviderConfigDTO
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if created.Username != "alice" {
		t.Fatalf("created username=%q, want authenticated user alice", created.Username)
	}
	persisted, err := fixture.repo.GetProxyProviderConfig(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get persisted config: %v", err)
	}
	if persisted == nil || persisted.Username != "alice" || persisted.ExternalSubscriptionID != fixture.aliceSource1 {
		t.Fatalf("unexpected persisted config: %#v", persisted)
	}
}

func TestProxyProviderUpdateRebindsOwnedSourceAndPreservesOwner(t *testing.T) {
	fixture := newProxyProviderFixture(t)
	id, err := fixture.repo.CreateProxyProviderConfig(context.Background(), proxyProviderDTO(fixture.aliceSource1).toStorage("alice"))
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}

	dto := proxyProviderDTO(fixture.aliceSource2)
	dto.Username = "bob"
	dto.Name = "updated provider"
	response := serveProxyProviderRequest(t, fixture.handler, http.MethodPut, "/api/user/proxy-provider-configs?id="+strconv.FormatInt(id, 10), "alice", dto)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	persisted, err := fixture.repo.GetProxyProviderConfig(context.Background(), id)
	if err != nil {
		t.Fatalf("get persisted config: %v", err)
	}
	if persisted == nil {
		t.Fatal("updated provider was not persisted")
	}
	if persisted.Username != "alice" {
		t.Fatalf("persisted username=%q, want alice", persisted.Username)
	}
	if persisted.ExternalSubscriptionID != fixture.aliceSource2 {
		t.Fatalf("persisted source=%d, want %d", persisted.ExternalSubscriptionID, fixture.aliceSource2)
	}
	if persisted.Name != "updated provider" {
		t.Fatalf("persisted name=%q", persisted.Name)
	}
}

func TestProxyProviderUpdateRejectsInvalidAndForeignSourcesWithoutChangingBinding(t *testing.T) {
	fixture := newProxyProviderFixture(t)
	id, err := fixture.repo.CreateProxyProviderConfig(context.Background(), proxyProviderDTO(fixture.aliceSource1).toStorage("alice"))
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}

	notFoundBodies := make([]string, 0, 2)
	for _, test := range []struct {
		name       string
		sourceID   int64
		wantStatus int
	}{
		{name: "zero id", sourceID: 0, wantStatus: http.StatusBadRequest},
		{name: "missing source", sourceID: fixture.bobSource + 10_000, wantStatus: http.StatusNotFound},
		{name: "another user's source", sourceID: fixture.bobSource, wantStatus: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			dto := proxyProviderDTO(test.sourceID)
			dto.Username = "bob"
			response := serveProxyProviderRequest(t, fixture.handler, http.MethodPut, "/api/user/proxy-provider-configs?id="+strconv.FormatInt(id, 10), "alice", dto)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), test.wantStatus)
			}
			if test.wantStatus == http.StatusNotFound {
				notFoundBodies = append(notFoundBodies, response.Body.String())
			}
		})
	}
	if len(notFoundBodies) != 2 || notFoundBodies[0] != notFoundBodies[1] {
		t.Fatalf("missing and foreign sources must be indistinguishable: %#v", notFoundBodies)
	}

	persisted, err := fixture.repo.GetProxyProviderConfig(context.Background(), id)
	if err != nil {
		t.Fatalf("get persisted config: %v", err)
	}
	if persisted == nil || persisted.ExternalSubscriptionID != fixture.aliceSource1 || persisted.Username != "alice" {
		t.Fatalf("rejected update changed provider: %#v", persisted)
	}
}

func TestProxyProviderStorageMutationsRequireOwnedSource(t *testing.T) {
	fixture := newProxyProviderFixture(t)
	ctx := context.Background()

	foreignCreate := proxyProviderDTO(fixture.bobSource).toStorage("alice")
	if _, err := fixture.repo.CreateProxyProviderConfig(ctx, foreignCreate); !errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
		t.Fatalf("create with foreign source error = %v, want ErrExternalSubscriptionNotFound", err)
	}
	configs, err := fixture.repo.ListProxyProviderConfigs(ctx, "alice")
	if err != nil {
		t.Fatalf("list configs after rejected create: %v", err)
	}
	if len(configs) != 0 {
		t.Fatalf("rejected storage create persisted configs: %#v", configs)
	}

	owned := proxyProviderDTO(fixture.aliceSource1).toStorage("alice")
	id, err := fixture.repo.CreateProxyProviderConfig(ctx, owned)
	if err != nil {
		t.Fatalf("seed owned provider: %v", err)
	}
	foreignUpdate := proxyProviderDTO(fixture.bobSource).toStorage("alice")
	foreignUpdate.ID = id
	foreignUpdate.Name = "foreign update"
	if err := fixture.repo.UpdateProxyProviderConfig(ctx, foreignUpdate); !errors.Is(err, storage.ErrExternalSubscriptionNotFound) {
		t.Fatalf("update with foreign source error = %v, want ErrExternalSubscriptionNotFound", err)
	}

	persisted, err := fixture.repo.GetProxyProviderConfig(ctx, id)
	if err != nil {
		t.Fatalf("get provider after rejected update: %v", err)
	}
	if persisted == nil || persisted.Username != "alice" || persisted.ExternalSubscriptionID != fixture.aliceSource1 || persisted.Name != owned.Name {
		t.Fatalf("rejected storage update changed provider: %#v", persisted)
	}
}
