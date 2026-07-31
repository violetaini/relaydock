package notify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestSendTelegramUsesPOSTFormBody(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost {
			t.Fatalf("method=%s, want POST", request.Method)
		}
		if request.URL.RawQuery != "" {
			t.Fatalf("Telegram fields leaked into URL query: %s", request.URL.RawQuery)
		}
		if got := request.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatalf("content type=%q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		if form.Get("chat_id") != "chat-secret" || form.Get("text") != "message" || form.Get("parse_mode") != "Markdown" {
			t.Fatalf("unexpected form: %#v", form)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    request,
		}, nil
	})}

	if err := sendTelegram(context.Background(), "bot-secret", "chat-secret", "message"); err != nil {
		t.Fatal(err)
	}
}

func TestSendTelegramRedactsTokenAndURLFromTransportErrors(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, &url.Error{
			Op:  "Post",
			URL: request.URL.String() + "?chat_id=chat-secret",
			Err: errors.New("dial failed with bot-secret"),
		}
	})}

	err := sendTelegram(context.Background(), "bot-secret", "chat-secret", "message")
	if err == nil {
		t.Fatal("transport failure was ignored")
	}
	message := err.Error()
	for _, secret := range []string{"bot-secret", "chat-secret", telegramAPIBase + "bot-secret"} {
		if strings.Contains(message, secret) {
			t.Fatalf("secret %q leaked in error: %s", secret, message)
		}
	}
	if !strings.Contains(message, "[redacted]") {
		t.Fatalf("redaction marker missing: %s", message)
	}
}
