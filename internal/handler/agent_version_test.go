package handler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type agentVersionRoundTripFunc func(*http.Request) (*http.Response, error)

func (f agentVersionRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestAgentVersionFetchLatestCoalescesConcurrentRequests(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var requests atomic.Int32

	handler := NewAgentVersionHandler(nil, nil)
	handler.httpClient = &http.Client{Transport: agentVersionRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.URL.String(); got != githubLatestReleaseURL {
			t.Errorf("request URL = %q, want %q", got, githubLatestReleaseURL)
		}
		if requests.Add(1) == 1 {
			close(requestStarted)
		}
		select {
		case <-releaseRequest:
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v0.4.5"}`)),
			}, nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	})}

	type result struct {
		version string
		err     string
	}
	leaderResult := make(chan result, 1)
	go func() {
		version, err := handler.fetchLatest(context.Background())
		leaderResult <- result{version: version, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("first GitHub request did not start")
	}

	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		version, err := handler.fetchLatest(ctx)
		cancel()
		if version != "" {
			t.Fatalf("waiting call %d version = %q, want empty cached version", i, version)
		}
		if err != context.DeadlineExceeded.Error() {
			t.Fatalf("waiting call %d error = %q, want %q", i, err, context.DeadlineExceeded)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("GitHub requests while fetch is in flight = %d, want 1", got)
	}

	close(releaseRequest)
	select {
	case got := <-leaderResult:
		if got.version != "0.4.5" || got.err != "" {
			t.Fatalf("leader result = (%q, %q), want (%q, empty)", got.version, got.err, "0.4.5")
		}
	case <-time.After(time.Second):
		t.Fatal("first GitHub request did not finish")
	}

	version, err := handler.fetchLatest(context.Background())
	if version != "0.4.5" || err != "" {
		t.Fatalf("cached result = (%q, %q), want (%q, empty)", version, err, "0.4.5")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("GitHub requests after cache hit = %d, want 1", got)
	}
}
