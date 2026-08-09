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
	"strings"
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
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatalf("configure provider token encryption: %v", err)
	}

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

func TestProxyProviderConfigValidationAndUniqueNames(t *testing.T) {
	fixture := newProxyProviderFixture(t)
	valid := proxyProviderDTO(fixture.aliceSource1)
	valid.ProcessMode = "mmw"
	created := serveProxyProviderRequest(t, fixture.handler, http.MethodPost, "/api/user/proxy-provider-configs", "alice", valid)
	if created.Code != http.StatusCreated {
		t.Fatalf("legacy mode create status=%d body=%s", created.Code, created.Body.String())
	}
	var result ProxyProviderConfigDTO
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ProcessMode != "server" || result.Type != "http" {
		t.Fatalf("legacy mode was not normalized: %#v", result)
	}

	duplicate := proxyProviderDTO(fixture.aliceSource2)
	response := serveProxyProviderRequest(t, fixture.handler, http.MethodPost, "/api/user/proxy-provider-configs", "alice", duplicate)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d body=%s, want 409", response.Code, response.Body.String())
	}

	for _, test := range []struct {
		name   string
		mutate func(*ProxyProviderConfigDTO)
	}{
		{name: "reserved name", mutate: func(dto *ProxyProviderConfigDTO) { dto.Name = "__PROXY_PROVIDERS__" }},
		{name: "unsupported type", mutate: func(dto *ProxyProviderConfigDTO) { dto.Type = "file" }},
		{name: "short interval", mutate: func(dto *ProxyProviderConfigDTO) { dto.Interval = 1 }},
		{name: "oversized content", mutate: func(dto *ProxyProviderConfigDTO) { dto.SizeLimit = maxProxyProviderBytes + 1 }},
		{name: "invalid filter", mutate: func(dto *ProxyProviderConfigDTO) { dto.Filter = "[" }},
		{name: "invalid health URL", mutate: func(dto *ProxyProviderConfigDTO) { dto.HealthCheckURL = "file:///tmp/check" }},
		{name: "unsafe header", mutate: func(dto *ProxyProviderConfigDTO) { dto.Header = `{"Authorization":"secret"}` }},
		{name: "unsupported override", mutate: func(dto *ProxyProviderConfigDTO) { dto.Override = "prefix: test" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dto := proxyProviderDTO(fixture.aliceSource2)
			dto.Name = "other-" + test.name
			test.mutate(&dto)
			response := serveProxyProviderRequest(t, fixture.handler, http.MethodPost, "/api/user/proxy-provider-configs", "alice", dto)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
		})
	}
}

func TestProxyProviderDeleteAndRotateHideForeignResources(t *testing.T) {
	fixture := newProxyProviderFixture(t)
	ctx := context.Background()
	id, err := fixture.repo.CreateProxyProviderConfig(ctx, proxyProviderDTO(fixture.aliceSource1).toStorage("alice"))
	if err != nil {
		t.Fatal(err)
	}

	foreignDelete := serveProxyProviderRequest(t, fixture.handler, http.MethodDelete, "/api/user/proxy-provider-configs?id="+strconv.FormatInt(id, 10), "bob", ProxyProviderConfigDTO{})
	missingDelete := serveProxyProviderRequest(t, fixture.handler, http.MethodDelete, "/api/user/proxy-provider-configs?id=999999", "bob", ProxyProviderConfigDTO{})
	if foreignDelete.Code != http.StatusNotFound || missingDelete.Code != http.StatusNotFound || foreignDelete.Body.String() != missingDelete.Body.String() {
		t.Fatalf("foreign delete differs from missing: foreign=%d %q missing=%d %q", foreignDelete.Code, foreignDelete.Body.String(), missingDelete.Code, missingDelete.Body.String())
	}

	rotateHandler := NewProxyProviderTokenRotateHandler(fixture.repo)
	foreignRotate := serveProxyProviderRequest(t, rotateHandler, http.MethodPost, "/api/user/proxy-provider-configs/rotate?id="+strconv.FormatInt(id, 10), "bob", ProxyProviderConfigDTO{})
	missingRotate := serveProxyProviderRequest(t, rotateHandler, http.MethodPost, "/api/user/proxy-provider-configs/rotate?id=999999", "bob", ProxyProviderConfigDTO{})
	if foreignRotate.Code != http.StatusNotFound || missingRotate.Code != http.StatusNotFound || foreignRotate.Body.String() != missingRotate.Body.String() {
		t.Fatalf("foreign rotation differs from missing: foreign=%d %q missing=%d %q", foreignRotate.Code, foreignRotate.Body.String(), missingRotate.Code, missingRotate.Body.String())
	}

	ownerRotate := serveProxyProviderRequest(t, rotateHandler, http.MethodPost, "/api/user/proxy-provider-configs/rotate?id="+strconv.FormatInt(id, 10), "alice", ProxyProviderConfigDTO{})
	if ownerRotate.Code != http.StatusOK {
		t.Fatalf("owner rotate status=%d body=%s", ownerRotate.Code, ownerRotate.Body.String())
	}
	if strings.Contains(ownerRotate.Body.String(), "arcway_pp_") {
		t.Fatalf("rotation response exposed token: %s", ownerRotate.Body.String())
	}
}
