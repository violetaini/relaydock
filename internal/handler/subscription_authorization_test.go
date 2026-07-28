package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
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
