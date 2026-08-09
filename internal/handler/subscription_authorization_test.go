package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

const subscriptionAuthorizationFixture = "authorization-fixture: current-user\nmode: rule\nproxies: []\nproxy-groups: []\nrules: []\n"

func newSubscriptionAuthorizationFixture(t *testing.T) (*storage.TrafficRepository, string, storage.SubscribeFile) {
	t.Helper()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)

	directory := t.TempDir()
	filename := "assigned.yaml"
	if err := os.WriteFile(filepath.Join(directory, filename), []byte(subscriptionAuthorizationFixture), 0600); err != nil {
		t.Fatalf("write subscription fixture: %v", err)
	}
	file, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name: "assigned", Type: storage.SubscribeTypeCreate, Filename: filename,
		CustomShortCode: "legacyfile", CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("create subscription fixture: %v", err)
	}
	return repo, directory, file
}

func fetchSubscription(t *testing.T, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSubscriptionEndpointRevalidatesLegacyAndSessionUsers(t *testing.T) {
	repo, directory, file := newSubscriptionAuthorizationFixture(t)
	if err := repo.AssignSubscriptionToUser(context.Background(), "alice", file.ID); err != nil {
		t.Fatal(err)
	}
	legacyToken, err := repo.GetOrCreateUserToken(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	tokens := auth.NewTokenStore(time.Hour)
	sessionToken, _, err := tokens.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewSubscriptionEndpoint(tokens, repo, directory)

	legacyRequest := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename+"&token="+legacyToken, nil)
	legacyResponse := fetchSubscription(t, handler, legacyRequest)
	if legacyResponse.Code != http.StatusOK || !strings.Contains(legacyResponse.Body.String(), "authorization-fixture") {
		t.Fatalf("active legacy token status=%d body=%s", legacyResponse.Code, legacyResponse.Body.String())
	}

	sessionRequest := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	sessionRequest.Header.Set(auth.AuthHeader, sessionToken)
	sessionResponse := fetchSubscription(t, handler, sessionRequest)
	if sessionResponse.Code != http.StatusOK || !strings.Contains(sessionResponse.Body.String(), "authorization-fixture") {
		t.Fatalf("active session status=%d body=%s", sessionResponse.Code, sessionResponse.Body.String())
	}

	if err := repo.UpdateUserStatus(context.Background(), "alice", false); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]*http.Request{
		"legacy token": httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename+"&token="+legacyToken, nil),
		"session":      httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil),
	} {
		if name == "session" {
			request.Header.Set(auth.AuthHeader, sessionToken)
		}
		response := fetchSubscription(t, handler, request)
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "authorization-fixture") || !strings.Contains(response.Body.String(), "订阅已过期") {
			t.Fatalf("disabled %s status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	ghostToken, _, err := tokens.Issue("deleted-user")
	if err != nil {
		t.Fatal(err)
	}
	ghostRequest := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	ghostRequest.Header.Set(auth.AuthHeader, ghostToken)
	ghostResponse := fetchSubscription(t, handler, ghostRequest)
	if ghostResponse.Code != http.StatusOK || strings.Contains(ghostResponse.Body.String(), "authorization-fixture") || !strings.Contains(ghostResponse.Body.String(), "订阅已过期") {
		t.Fatalf("missing session user status=%d body=%s", ghostResponse.Code, ghostResponse.Body.String())
	}
}

func TestSubscriptionAccessFailsClosedAndCoversLegacyTypeLookup(t *testing.T) {
	repo, directory, file := newSubscriptionAuthorizationFixture(t)
	if _, err := repo.CreateSubscriptionLink(context.Background(), storage.SubscriptionLink{
		Name: "clashmeta", Type: "clashmeta", RuleFilename: file.Filename,
	}); err != nil {
		t.Fatalf("create legacy subscription link: %v", err)
	}
	handler := NewSubscriptionHandlerConcrete(repo, directory)

	missingRequest := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	missingRequest = missingRequest.WithContext(auth.ContextWithUsername(missingRequest.Context(), "missing-user"))
	missingResponse := fetchSubscription(t, handler, missingRequest)
	if missingResponse.Code != http.StatusForbidden {
		t.Fatalf("missing ACL user status=%d body=%s", missingResponse.Code, missingResponse.Body.String())
	}

	legacyRequest := func(username string) *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?t=clashmeta", nil)
		return request.WithContext(auth.ContextWithUsername(request.Context(), username))
	}
	denied := fetchSubscription(t, handler, legacyRequest("alice"))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unassigned legacy lookup status=%d body=%s", denied.Code, denied.Body.String())
	}
	if err := repo.AssignSubscriptionToUser(context.Background(), "alice", file.ID); err != nil {
		t.Fatal(err)
	}
	allowed := fetchSubscription(t, handler, legacyRequest("alice"))
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), "authorization-fixture") {
		t.Fatalf("assigned legacy lookup status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	if err := repo.RemoveSubscriptionFromUser(context.Background(), "alice", file.ID); err != nil {
		t.Fatal(err)
	}
	revoked := fetchSubscription(t, handler, legacyRequest("alice"))
	if revoked.Code != http.StatusForbidden {
		t.Fatalf("revoked legacy lookup status=%d body=%s", revoked.Code, revoked.Body.String())
	}

	admin := fetchSubscription(t, handler, legacyRequest("admin"))
	if admin.Code != http.StatusOK || !strings.Contains(admin.Body.String(), "authorization-fixture") {
		t.Fatalf("admin legacy lookup status=%d body=%s", admin.Code, admin.Body.String())
	}
}

func TestSubscriptionShortLinksRequireCurrentUserSuffixAndAssignment(t *testing.T) {
	repo, directory, file := newSubscriptionAuthorizationFixture(t)
	if err := repo.AssignSubscriptionToUser(context.Background(), "alice", file.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateUserCustomShortCode(context.Background(), "alice", "ALC"); err != nil {
		t.Fatal(err)
	}
	users, err := repo.ListUserShortCodeInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	aliceCodes := users["alice"]
	handler := NewShortLinkHandler(repo, NewSubscriptionHandlerConcrete(repo, directory), nil)

	for name, code := range map[string]string{
		"generated file code": file.FileShortCode,
		"custom file code":    file.CustomShortCode,
	} {
		response := fetchSubscription(t, handler, httptest.NewRequest(http.MethodGet, "/x/"+code, nil))
		if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "authorization-fixture") {
			t.Fatalf("standalone %s status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	for name, code := range map[string]string{
		"generated composite": file.FileShortCode + aliceCodes.UserShortCode,
		"custom composite":    file.CustomShortCode + aliceCodes.CustomUserShortCode,
	} {
		response := fetchSubscription(t, handler, httptest.NewRequest(http.MethodGet, "/x/"+code, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "authorization-fixture") {
			t.Fatalf("%s status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	if err := repo.RemoveSubscriptionFromUser(context.Background(), "alice", file.ID); err != nil {
		t.Fatal(err)
	}
	revokedCode := file.FileShortCode + aliceCodes.UserShortCode
	revoked := fetchSubscription(t, handler, httptest.NewRequest(http.MethodGet, "/x/"+revokedCode, nil))
	if revoked.Code != http.StatusForbidden || strings.Contains(revoked.Body.String(), "authorization-fixture") {
		t.Fatalf("revoked composite status=%d body=%s", revoked.Code, revoked.Body.String())
	}
}

func TestAssignedTemplateMaterializesCreatorProviderBeforeRevocation(t *testing.T) {
	repo, directory, file := newSubscriptionAuthorizationFixture(t)
	ctx := context.Background()
	if _, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "local", Protocol: "ss", Enabled: true,
		ClashConfig: `{"name":"local","type":"ss","server":"local.example","port":443,"cipher":"aes-128-gcm","password":"local-secret"}`,
	}); err != nil {
		t.Fatalf("create local node: %v", err)
	}
	source := storage.ExternalSubscription{
		Username: "admin", Name: "provider source", URL: "https://provider.example/subscription",
	}
	sourceID, err := repo.CreateExternalSubscription(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateProxyProviderConfig(ctx, &storage.ProxyProviderConfig{
		Username: "admin", ExternalSubscriptionID: sourceID, Name: "airport", Type: "http", ProcessMode: "client",
	}); err != nil {
		t.Fatal(err)
	}
	providerContent := []byte("proxies:\n  - {name: Provider Node, type: ss, server: provider.example, port: 443, cipher: aes-128-gcm, password: provider-secret}\n")
	cacheKey := subscriptionContentCacheKey(source.URL)
	subscriptionCache.put(cacheKey, providerContent, time.Now())
	t.Cleanup(func() { subscriptionCache.delete(cacheKey) })

	const templateName = "assigned-provider-capability-test.yaml"
	if err := os.MkdirAll("rule_templates", 0755); err != nil {
		t.Fatal(err)
	}
	templatePath := filepath.Join("rule_templates", templateName)
	template := "mode: rule\nproxies: []\nproxy-groups:\n  - name: PROXY\n    type: select\n    use: [airport]\nrules:\n  - MATCH,PROXY\n"
	if err := os.WriteFile(templatePath, []byte(template), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(templatePath) })
	file.TemplateFilename = templateName
	file, err = repo.UpdateSubscribeFile(ctx, file)
	if err != nil {
		t.Fatalf("bind template: %v", err)
	}
	if err := repo.AssignSubscriptionToUser(ctx, "alice", file.ID); err != nil {
		t.Fatal(err)
	}

	handler := NewSubscriptionHandlerConcrete(repo, directory)
	request := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "alice"))
	response := fetchSubscription(t, handler, request)
	if response.Code != http.StatusOK {
		t.Fatalf("assigned fetch status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "airport / Provider Node") {
		t.Fatalf("assigned provider was not materialized: %s", body)
	}
	if strings.Contains(body, "proxy-providers:") || strings.Contains(body, "Authorization") || strings.Contains(body, proxyProviderAccessTokenPrefix) {
		t.Fatalf("assigned response exposed a durable provider capability: %s", body)
	}

	if err := repo.RemoveSubscriptionFromUser(ctx, "alice", file.ID); err != nil {
		t.Fatal(err)
	}
	revokedRequest := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	revokedRequest = revokedRequest.WithContext(auth.ContextWithUsername(revokedRequest.Context(), "alice"))
	revoked := fetchSubscription(t, handler, revokedRequest)
	if revoked.Code != http.StatusForbidden {
		t.Fatalf("revoked assigned fetch status=%d body=%s", revoked.Code, revoked.Body.String())
	}
}

func TestAssignedRawSubscriptionRejectsDurableProviderCapability(t *testing.T) {
	repo, directory, file := newSubscriptionAuthorizationFixture(t)
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x73}, 32)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sourceID, err := repo.CreateExternalSubscription(ctx, storage.ExternalSubscription{
		Username: "admin", Name: "raw provider source", URL: "https://provider.example/raw-capability",
	})
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := repo.CreateProxyProviderConfig(ctx, &storage.ProxyProviderConfig{
		Username: "admin", ExternalSubscriptionID: sourceID, Name: "airport", Type: "http", ProcessMode: "client",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := repo.EnsureProxyProviderAccessToken(ctx, providerID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	raw := "mode: rule\nproxy-providers:\n  airport:\n    type: http\n    url: https://panel.example.test/api/proxy-provider/" + strconv.FormatInt(providerID, 10) + "\n    header:\n      Authorization:\n        - Bearer " + token + "\nproxy-groups:\n  - name: PROXY\n    type: select\n    use: [airport]\nrules:\n  - MATCH,PROXY\n"
	if err := os.WriteFile(filepath.Join(directory, file.Filename), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := repo.AssignSubscriptionToUser(ctx, "alice", file.ID); err != nil {
		t.Fatal(err)
	}

	handler := NewSubscriptionHandlerConcrete(repo, directory)
	request := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "alice"))
	response := fetchSubscription(t, handler, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("assigned raw Provider fetch status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), token) || strings.Contains(response.Body.String(), "Authorization") {
		t.Fatalf("assigned raw response exposed Provider capability: %s", response.Body.String())
	}

	ownerRequest := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	ownerRequest = ownerRequest.WithContext(auth.ContextWithUsername(ownerRequest.Context(), "admin"))
	ownerResponse := fetchSubscription(t, handler, ownerRequest)
	if ownerResponse.Code != http.StatusOK || !strings.Contains(ownerResponse.Body.String(), token) {
		t.Fatalf("owner raw Provider fetch status=%d body=%s", ownerResponse.Code, ownerResponse.Body.String())
	}

	if err := repo.RemoveSubscriptionFromUser(ctx, "alice", file.ID); err != nil {
		t.Fatal(err)
	}
	revokedRequest := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	revokedRequest = revokedRequest.WithContext(auth.ContextWithUsername(revokedRequest.Context(), "alice"))
	revoked := fetchSubscription(t, handler, revokedRequest)
	if revoked.Code != http.StatusForbidden || strings.Contains(revoked.Body.String(), token) {
		t.Fatalf("revoked raw Provider fetch status=%d body=%s", revoked.Code, revoked.Body.String())
	}
}

func TestSubscriptionContainsProxyProvidersHandlesYAMLIndirection(t *testing.T) {
	for name, testCase := range map[string]struct {
		content string
		want    bool
		wantErr bool
	}{
		"absent": {
			content: "mode: rule\nproxies: []\n",
		},
		"empty definition": {
			content: "mode: rule\nproxy-providers: {}\n",
			want:    true,
		},
		"merged definition": {
			content: "defaults: &defaults\n  proxy-providers:\n    hidden: {type: http, url: https://panel.example.test/api/proxy-provider/7}\n<<: *defaults\n",
			want:    true,
		},
		"duplicate definition": {
			content: "proxy-providers: {}\nproxy-providers:\n  hidden: {type: http, url: https://panel.example.test/api/proxy-provider/7}\n",
			wantErr: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := subscriptionContainsProxyProviders([]byte(testCase.content))
			if (err != nil) != testCase.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, testCase.wantErr)
			}
			if got != testCase.want {
				t.Fatalf("containsProviders=%v want=%v", got, testCase.want)
			}
		})
	}
}

func TestForceSyncRegeneratesProviderTemplateInsteadOfReturningRawFile(t *testing.T) {
	repo, directory, file := newSubscriptionAuthorizationFixture(t)
	ctx := context.Background()
	if _, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "local", Protocol: "ss", Enabled: true,
		ClashConfig: `{"name":"local","type":"ss","server":"local.example","port":443,"cipher":"aes-128-gcm","password":"local-secret"}`,
	}); err != nil {
		t.Fatalf("create local node: %v", err)
	}
	source := storage.ExternalSubscription{
		Username: "admin", Name: "provider source", URL: "https://provider.example/force-sync",
	}
	sourceID, err := repo.CreateExternalSubscription(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateProxyProviderConfig(ctx, &storage.ProxyProviderConfig{
		Username: "admin", ExternalSubscriptionID: sourceID, Name: "airport", Type: "http", ProcessMode: "server",
	}); err != nil {
		t.Fatal(err)
	}
	cacheKey := subscriptionContentCacheKey(source.URL)
	putProviderContent := func(name string) {
		content := []byte("proxies:\n  - {name: " + name + ", type: ss, server: provider.example, port: 443, cipher: aes-128-gcm, password: provider-secret}\n")
		subscriptionCache.put(cacheKey, content, time.Now())
	}
	putProviderContent("Before Sync")
	t.Cleanup(func() { subscriptionCache.delete(cacheKey) })

	const templateName = "force-sync-provider-regeneration-test.yaml"
	if err := os.MkdirAll("rule_templates", 0755); err != nil {
		t.Fatal(err)
	}
	templatePath := filepath.Join("rule_templates", templateName)
	template := "mode: rule\nproxies: []\nproxy-groups:\n  - name: PROXY\n    type: select\n    use: [airport]\nrules:\n  - MATCH,PROXY\n"
	if err := os.WriteFile(templatePath, []byte(template), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(templatePath) })
	file.TemplateFilename = templateName
	file, err = repo.UpdateSubscribeFile(ctx, file)
	if err != nil {
		t.Fatalf("bind template: %v", err)
	}
	if err := repo.UpsertUserSettings(ctx, storage.UserSettings{
		Username: "admin", ForceSyncExternal: true, CacheExpireMinutes: 0, KeepNodeName: true,
	}); err != nil {
		t.Fatal(err)
	}

	handler := NewSubscriptionHandlerConcrete(repo, directory)
	syncCalled := false
	handler.syncReferencedExternalSubscriptions = func(_ context.Context, _ *storage.TrafficRepository, _, _ string, subscriptions []storage.ExternalSubscription) error {
		syncCalled = true
		if len(subscriptions) != 1 || subscriptions[0].ID != sourceID {
			t.Fatalf("subscriptions selected for sync = %#v", subscriptions)
		}
		putProviderContent("After Sync")
		return nil
	}
	request := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename="+file.Filename, nil)
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "admin"))
	response := fetchSubscription(t, handler, request)
	if response.Code != http.StatusOK {
		t.Fatalf("force-sync fetch status=%d body=%s", response.Code, response.Body.String())
	}
	if !syncCalled {
		t.Fatal("referenced provider subscription was not synchronized")
	}
	body := response.Body.String()
	if !strings.Contains(body, "airport / After Sync") || strings.Contains(body, "airport / Before Sync") {
		t.Fatalf("template was not regenerated after sync: %s", body)
	}
	if strings.Contains(body, "authorization-fixture") {
		t.Fatalf("rendered template was overwritten with the raw file: %s", body)
	}
}

func TestProviderMaterializationTreatsOwnerlessTemplatesAsCrossOwner(t *testing.T) {
	if !subscriptionProviderRequiresServerMaterialization("admin", "") {
		t.Fatal("ownerless template could issue the fallback admin's Provider credential")
	}
	if !subscriptionProviderRequiresServerMaterialization("bob", "alice") {
		t.Fatal("assigned template did not require Provider materialization")
	}
	if subscriptionProviderRequiresServerMaterialization("alice", "alice") {
		t.Fatal("owner fetch unexpectedly required Provider materialization")
	}
}
