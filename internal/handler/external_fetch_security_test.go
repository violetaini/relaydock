package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/safefetch"
)

func TestFetchRemoteContentRejectsPrivateDestination(t *testing.T) {
	var reached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte("should not be fetched"))
	}))
	defer server.Close()

	_, err := fetchRemoteContent(server.URL, time.Second)
	if !errors.Is(err, safefetch.ErrProhibitedAddress) {
		t.Fatalf("fetchRemoteContent() error = %v, want ErrProhibitedAddress", err)
	}
	if reached.Load() {
		t.Fatal("private HTTP server received a request")
	}
}
