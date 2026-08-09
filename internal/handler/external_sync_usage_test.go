package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/storage"
)

type failingSubscriptionRoundTripper struct{}

func (failingSubscriptionRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: http.MethodGet, URL: request.URL.String(), Err: errors.New("dial failed")}
}

func TestGetUsedExternalSubscriptionURLsHonorsAccessibleFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo, err := storage.NewTrafficRepository(filepath.Join(dir, "external-sync.db"))
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	for _, user := range []struct {
		username string
		role     string
	}{
		{username: "alice", role: storage.RoleUser},
		{username: "bob", role: storage.RoleUser},
		{username: "admin", role: storage.RoleAdmin},
	} {
		if err := repo.CreateUser(ctx, user.username, user.username+"@example.test", user.username, "hash", user.role, ""); err != nil {
			t.Fatalf("create user %s: %v", user.username, err)
		}
	}

	upstreamURLs := []string{
		"https://upstream.example/owned?token=owned",
		"https://upstream.example/assigned?token=assigned",
		"https://upstream.example/unassigned?token=unassigned",
	}
	for _, username := range []string{"alice", "admin"} {
		for i, upstreamURL := range upstreamURLs {
			if _, err := repo.CreateExternalSubscription(ctx, storage.ExternalSubscription{
				Username: username,
				Name:     fmt.Sprintf("source-%d", i),
				URL:      upstreamURL,
			}); err != nil {
				t.Fatalf("create external subscription for %s: %v", username, err)
			}
		}
	}

	createFile := func(name, filename, owner, upstreamURL string) storage.SubscribeFile {
		t.Helper()
		file, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{
			Name: name, Type: storage.SubscribeTypeCreate, Filename: filename, CreatedBy: owner,
		})
		if err != nil {
			t.Fatalf("create subscribe file %s: %v", name, err)
		}
		content := []byte("proxy-providers:\n  source:\n    type: http\n    url: \"" + upstreamURL + "\"\n")
		if err := os.WriteFile(filepath.Join(dir, filename), content, 0o600); err != nil {
			t.Fatalf("write subscribe file %s: %v", name, err)
		}
		return file
	}

	createFile("owned", "owned.yaml", "alice", upstreamURLs[0])
	assigned := createFile("assigned", "assigned.yaml", "bob", upstreamURLs[1])
	createFile("unassigned", "unassigned.yaml", "bob", upstreamURLs[2])
	if err := repo.AssignSubscriptionToUser(ctx, "alice", assigned.ID); err != nil {
		t.Fatalf("assign subscription: %v", err)
	}

	aliceURLs, err := getUsedExternalSubscriptionURLs(ctx, repo, dir, "alice")
	if err != nil {
		t.Fatalf("get alice URLs: %v", err)
	}
	if !aliceURLs[upstreamURLs[0]] || !aliceURLs[upstreamURLs[1]] {
		t.Fatalf("alice URLs = %#v, want owned and assigned sources", aliceURLs)
	}
	if aliceURLs[upstreamURLs[2]] {
		t.Fatalf("alice URLs include unassigned source: %#v", aliceURLs)
	}

	adminURLs, err := getUsedExternalSubscriptionURLs(ctx, repo, dir, "admin")
	if err != nil {
		t.Fatalf("get admin URLs: %v", err)
	}
	for _, upstreamURL := range upstreamURLs {
		if !adminURLs[upstreamURL] {
			t.Fatalf("admin URLs = %#v, missing %q from globally visible file", adminURLs, upstreamURL)
		}
	}
}

func TestDirectProxyProviderURLsOnlyReturnsStoredURLs(t *testing.T) {
	const allowed = "https://upstream.example/sub?token=allowed"
	const unknown = "https://upstream.example/sub?token=unknown"
	content := []byte("proxy-providers:\n  allowed:\n    url: \"" + allowed + "\"\n  unknown:\n    url: \"" + unknown + "\"\n")

	got := directProxyProviderURLs(content, map[string]bool{allowed: true})
	if !got[allowed] || got[unknown] || len(got) != 1 {
		t.Fatalf("direct provider URLs = %#v, want only stored URL", got)
	}
}

func TestExternalSyncRequestErrorsDoNotExposeSubscriptionURL(t *testing.T) {
	const secret = "credential-must-not-leak"
	subscription := storage.ExternalSubscription{
		ID: 77, Name: "private source", URL: "https://upstream.example/sub?token=" + secret,
	}
	client := &http.Client{Transport: failingSubscriptionRoundTripper{}}
	_, _, err := syncSingleExternalSubscription(
		context.Background(), client, nil, "", "alice", subscription, storage.UserSettings{},
	)
	if err == nil || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("sync error=%v, want underlying network classification", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), subscription.URL) {
		t.Fatalf("sync error exposed subscription URL: %v", err)
	}

	subscription.URL = "https://upstream.example/%zz?token=" + secret
	_, _, err = syncSingleExternalSubscription(
		context.Background(), client, nil, "", "alice", subscription, storage.UserSettings{},
	)
	if err == nil {
		t.Fatal("invalid subscription URL was accepted")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), subscription.URL) {
		t.Fatalf("request creation error exposed subscription URL: %v", err)
	}
}

func TestTrafficRefreshRequestErrorsDoNotExposeSubscriptionURL(t *testing.T) {
	const secret = "traffic-credential-must-not-leak"
	subscription := storage.ExternalSubscription{
		ID: 88, Name: "private traffic source", URL: "https://upstream.example/sub?token=" + secret,
	}
	handler := newTrafficSummaryHandler(&http.Client{Transport: failingSubscriptionRoundTripper{}}, nil)
	_, err := handler.fetchExternalSubscriptionTrafficInfo(context.Background(), subscription)
	if err == nil || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("traffic refresh error=%v, want underlying network classification", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), subscription.URL) {
		t.Fatalf("traffic refresh error exposed subscription URL: %v", err)
	}

	subscription.URL = "https://upstream.example/%zz?token=" + secret
	_, err = handler.fetchExternalSubscriptionTrafficInfo(context.Background(), subscription)
	if err == nil {
		t.Fatal("invalid traffic subscription URL was accepted")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), subscription.URL) {
		t.Fatalf("traffic request creation error exposed subscription URL: %v", err)
	}
}

func TestCreateExternalSubscriptionLogsDoNotExposeInvalidURL(t *testing.T) {
	const secret = "create-credential-must-not-leak"
	directory := t.TempDir()
	repo, err := storage.NewTrafficRepository(filepath.Join(directory, "create-external.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.CreateUser(context.Background(), "alice", "alice@example.test", "Alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(directory, "create-external.log")
	if err := logger.EnableDebug(logPath); err != nil {
		t.Fatal(err)
	}
	debugEnabled := true
	t.Cleanup(func() {
		if debugEnabled {
			_ = logger.DisableDebug()
		}
	})

	request := httptest.NewRequest(http.MethodPost, "/api/external-subscriptions", strings.NewReader(
		`{"name":"private source","url":"https://upstream.example/%zz?token=`+secret+`"}`,
	))
	response := httptest.NewRecorder()
	handleCreateExternalSubscription(response, request, repo, "alice")
	_ = logger.DisableDebug()
	debugEnabled = false

	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), secret) || strings.Contains(string(logged), "%zz?token=") {
		t.Fatalf("create external subscription log exposed URL credential: %s", logged)
	}
}
