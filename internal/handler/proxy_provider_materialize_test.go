package handler

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
	"gopkg.in/yaml.v3"
)

func newProxyProviderRenderRepository(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "provider-render.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x67}, 32)); err != nil {
		t.Fatalf("ConfigureNodeSecretEncryption: %v", err)
	}
	for _, username := range []string{"alice", "bob"} {
		if err := repo.CreateUser(context.Background(), username, username+"@example.test", username, "hash", storage.RoleUser, ""); err != nil {
			t.Fatalf("CreateUser(%s): %v", username, err)
		}
	}
	if err := repo.SetSystemSetting(context.Background(), "master_url", "https://panel.example.test"); err != nil {
		t.Fatalf("SetSystemSetting(master_url): %v", err)
	}
	return repo
}

func createProviderRenderFixture(t *testing.T, repo *storage.TrafficRepository, owner, name, mode, filter string) (storage.ProxyProviderConfig, storage.ExternalSubscription) {
	t.Helper()
	source := storage.ExternalSubscription{
		Username:  owner,
		Name:      name + " source",
		URL:       "https://upstream.example.test/subscription/very-secret-token-" + owner + "-" + name,
		UserAgent: "mihomo-test",
	}
	id, err := repo.CreateExternalSubscription(context.Background(), source)
	if err != nil {
		t.Fatalf("CreateExternalSubscription: %v", err)
	}
	source.ID = id
	config := storage.ProxyProviderConfig{
		Username:                  owner,
		ExternalSubscriptionID:    id,
		Name:                      name,
		Type:                      "http",
		Interval:                  3600,
		HealthCheckEnabled:        true,
		HealthCheckURL:            "https://cp.cloudflare.com/generate_204",
		HealthCheckInterval:       300,
		HealthCheckTimeout:        5000,
		HealthCheckLazy:           true,
		HealthCheckExpectedStatus: 204,
		Filter:                    filter,
		ProcessMode:               mode,
	}
	configID, err := repo.CreateProxyProviderConfig(context.Background(), &config)
	if err != nil {
		t.Fatalf("CreateProxyProviderConfig: %v", err)
	}
	config.ID = configID
	return config, source
}

func providerRenderTemplate(providerName string) string {
	return "mode: rule\nproxies: []\nproxy-groups:\n  - name: PROXY\n    type: select\n    use:\n      - " + providerName + "\nrules:\n  - MATCH,PROXY\n"
}

func TestRenderTemplateWithProxyProvidersBuildsOpaqueNativeProvider(t *testing.T) {
	repo := newProxyProviderRenderRepository(t)
	provider, source := createProviderRenderFixture(t, repo, "alice", "airport", "client", "")
	local := []map[string]any{{"name": "local", "type": "ss", "server": "local.example", "port": 443, "password": "password", "cipher": "aes-128-gcm"}}

	result, err := renderTemplateWithProxyProviders(context.Background(), repo, providerRenderTemplate("airport"), local, "alice", false)
	if err != nil {
		t.Fatalf("renderTemplateWithProxyProviders: %v", err)
	}
	if strings.Contains(result, source.URL) || strings.Contains(result, "very-secret-token") {
		t.Fatalf("rendered config leaked upstream URL: %s", result)
	}

	var document map[string]any
	if err := yaml.Unmarshal([]byte(result), &document); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	definitions, ok := document["proxy-providers"].(map[string]any)
	if !ok {
		t.Fatalf("proxy-providers missing: %#v", document)
	}
	definition, ok := definitions["airport"].(map[string]any)
	if !ok {
		t.Fatalf("airport definition missing: %#v", definitions)
	}
	providerURL, _ := definition["url"].(string)
	wantProviderURL := "https://panel.example.test" + proxyProviderContentPath + strconv.FormatInt(provider.ID, 10)
	if providerURL != wantProviderURL || strings.Contains(providerURL, proxyProviderAccessTokenPrefix) {
		t.Fatalf("provider url = %q", providerURL)
	}
	header, ok := definition["header"].(map[string]any)
	if !ok {
		t.Fatalf("provider header missing: %#v", definition)
	}
	authorization, ok := header["Authorization"].([]any)
	if !ok || len(authorization) != 1 {
		t.Fatalf("provider Authorization header = %#v", header["Authorization"])
	}
	authorizationValue, _ := authorization[0].(string)
	token := strings.TrimPrefix(authorizationValue, "Bearer ")
	if !strings.HasPrefix(token, proxyProviderAccessTokenPrefix) || strings.Contains(providerURL, token) {
		t.Fatalf("provider credential was not isolated from URL: url=%q header=%#v", providerURL, header)
	}
	config, resolvedSource, err := repo.ResolveProxyProviderAccess(context.Background(), token)
	if err != nil {
		t.Fatalf("ResolveProxyProviderAccess: %v", err)
	}
	if config.Username != "alice" || resolvedSource.ID != source.ID {
		t.Fatalf("resolved config/source = %#v / %#v", config, resolvedSource)
	}

	groups := document["proxy-groups"].([]any)
	group := groups[0].(map[string]any)
	use := group["use"].([]any)
	if len(use) != 1 || use[0] != "airport" {
		t.Fatalf("group use = %#v", use)
	}
}

func TestRenderTemplateWithProxyProvidersExpandsServerProvider(t *testing.T) {
	repo := newProxyProviderRenderRepository(t)
	_, source := createProviderRenderFixture(t, repo, "alice", "airport", "server", "HK")
	content := []byte("proxies:\n  - name: HK 01\n    type: ss\n    server: hk.example\n    port: 443\n    cipher: aes-128-gcm\n    password: secret\n  - name: JP 01\n    type: ss\n    server: jp.example\n    port: 443\n    cipher: aes-128-gcm\n    password: secret\n")
	cacheKey := subscriptionContentCacheKey(source.URL, source.UserAgent)
	subscriptionCache.put(cacheKey, content, time.Now())
	t.Cleanup(func() { subscriptionCache.delete(cacheKey) })

	result, err := renderTemplateWithProxyProviders(context.Background(), repo, providerRenderTemplate("airport"), nil, "alice", false)
	if err != nil {
		t.Fatalf("renderTemplateWithProxyProviders: %v", err)
	}
	if strings.Contains(result, "proxy-providers:") || strings.Contains(result, "use:") {
		t.Fatalf("server provider was left native: %s", result)
	}
	if !strings.Contains(result, "airport / HK 01") || strings.Contains(result, "airport / JP 01") {
		t.Fatalf("server provider filter/namespace mismatch: %s", result)
	}
	if strings.Contains(result, source.URL) {
		t.Fatalf("server render leaked upstream URL: %s", result)
	}
}

func TestRenderTemplateWithProxyProvidersFailsClosedAcrossOwners(t *testing.T) {
	repo := newProxyProviderRenderRepository(t)
	createProviderRenderFixture(t, repo, "bob", "private-airport", "client", "")

	_, err := renderTemplateWithProxyProviders(context.Background(), repo, providerRenderTemplate("private-airport"), nil, "alice", false)
	if err == nil || !strings.Contains(err.Error(), "unavailable provider") {
		t.Fatalf("cross-owner render error = %v", err)
	}
}

func TestRenderTemplateWithProxyProvidersForcesExpansionForNonMihomo(t *testing.T) {
	repo := newProxyProviderRenderRepository(t)
	_, source := createProviderRenderFixture(t, repo, "alice", "airport", "client", "")
	content := []byte("proxies:\n  - name: Node\n    type: ss\n    server: node.example\n    port: 443\n    cipher: aes-128-gcm\n    password: secret\n")
	cacheKey := subscriptionContentCacheKey(source.URL, source.UserAgent)
	subscriptionCache.put(cacheKey, content, time.Now())
	t.Cleanup(func() { subscriptionCache.delete(cacheKey) })

	result, err := renderTemplateWithProxyProviders(context.Background(), repo, providerRenderTemplate("airport"), nil, "alice", true)
	if err != nil {
		t.Fatalf("renderTemplateWithProxyProviders: %v", err)
	}
	if strings.Contains(result, "proxy-providers:") || strings.Contains(result, "use:") || !strings.Contains(result, "airport / Node") {
		t.Fatalf("forced server result = %s", result)
	}
	if strings.Contains(result, proxyProviderAccessTokenPrefix) {
		t.Fatalf("persistent/server-expanded render leaked a provider credential: %s", result)
	}
}

func TestRenderTemplateWithoutProvidersDoesNotRequireRepositoryOrOwner(t *testing.T) {
	template := "mode: rule\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [DIRECT]\nrules:\n  - MATCH,PROXY\n"
	result, err := renderTemplateWithProxyProviders(context.Background(), nil, template, nil, "", false)
	if err != nil {
		t.Fatalf("renderTemplateWithProxyProviders: %v", err)
	}
	if !strings.Contains(result, "name: PROXY") || !strings.Contains(result, "proxies:") {
		t.Fatalf("legacy template was not rendered: %s", result)
	}
}

func TestRenderTemplateForceServerRemovesUnreferencedProviderCapabilities(t *testing.T) {
	template := `mode: rule
proxy-providers:
  unused:
    type: http
    url: https://panel.example.test/api/proxy-provider/7
    header:
      Authorization:
        - Bearer arcway_pp_capability_must_not_survive
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,PROXY
`
	result, err := renderTemplateWithProxyProviders(context.Background(), nil, template, nil, "", true)
	if err != nil {
		t.Fatalf("force-server render: %v", err)
	}
	if strings.Contains(result, "proxy-providers:") || strings.Contains(result, "Authorization") || strings.Contains(result, proxyProviderAccessTokenPrefix) {
		t.Fatalf("unreferenced Provider capability survived force-server render: %s", result)
	}
}

func TestRenderTemplateForceServerRemovesCapabilitiesFromMixedTemplate(t *testing.T) {
	repo := newProxyProviderRenderRepository(t)
	_, source := createProviderRenderFixture(t, repo, "alice", "airport", "client", "")
	content := []byte("proxies:\n  - {name: Managed Node, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: secret}\n")
	cacheKey := subscriptionContentCacheKey(source.URL, source.UserAgent)
	subscriptionCache.put(cacheKey, content, time.Now())
	t.Cleanup(func() { subscriptionCache.delete(cacheKey) })

	template := `mode: rule
proxy-providers:
  unused:
    type: http
    url: https://panel.example.test/api/proxy-provider/7
    header:
      Authorization:
        - Bearer arcway_pp_capability_must_not_survive
proxy-groups:
  - name: PROXY
    type: select
    use: [airport]
rules:
  - MATCH,PROXY
`
	result, err := renderTemplateWithProxyProviders(context.Background(), repo, template, nil, "alice", true)
	if err != nil {
		t.Fatalf("force-server mixed render: %v", err)
	}
	if !strings.Contains(result, "airport / Managed Node") {
		t.Fatalf("managed Provider was not expanded: %s", result)
	}
	if strings.Contains(result, "proxy-providers:") || strings.Contains(result, "Authorization") || strings.Contains(result, proxyProviderAccessTokenPrefix) {
		t.Fatalf("mixed Provider capability survived force-server render: %s", result)
	}
}
