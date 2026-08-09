package handler

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestSubscribeFileImportRequestErrorsDoNotExposeSubscriptionURL(t *testing.T) {
	const secret = "import-credential-must-not-leak"
	client := &http.Client{Transport: failingSubscriptionRoundTripper{}}
	handler := &subscribeFilesHandler{fetchClient: client}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/import", bytes.NewBufferString(
		`{"name":"private import","url":"https://upstream.example/sub?token=`+secret+`"}`,
	))
	response := httptest.NewRecorder()
	handler.handleImport(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "无法获取订阅内容") {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "upstream.example") {
		t.Fatalf("import error exposed subscription URL: %s", response.Body.String())
	}
}

func TestFetchRemoteContentErrorsDoNotExposeSubscriptionURL(t *testing.T) {
	const secret = "template-fetch-credential-must-not-leak"
	_, err := fetchRemoteContent("https://upstream.example/%zz?token="+secret, time.Second)
	if err == nil {
		t.Fatal("fetchRemoteContent accepted invalid URL")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "upstream.example") {
		t.Fatalf("fetchRemoteContent error exposed subscription URL: %v", err)
	}
}
