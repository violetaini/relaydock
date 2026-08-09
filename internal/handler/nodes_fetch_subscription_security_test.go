package handler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	arcLogger "github.com/violetaini/relaydock/internal/logger"
)

func TestFetchSubscriptionDoesNotExposeUpstreamSecrets(t *testing.T) {
	var logOutput bytes.Buffer
	globalLogger := arcLogger.GetLogger()
	originalLogger := globalLogger.Logger
	globalLogger.Logger = slog.New(slog.NewTextHandler(&logOutput, nil))
	t.Cleanup(func() {
		globalLogger.Logger = originalLogger
	})

	tests := []struct {
		name           string
		statusCode     int
		body           string
		responseSecret string
	}{
		{
			name:           "error response",
			statusCode:     http.StatusBadGateway,
			body:           "upstream-response-secret-error",
			responseSecret: "upstream-response-secret-error",
		},
		{
			name:           "invalid YAML",
			statusCode:     http.StatusOK,
			body:           "proxies:\n  - name: upstream-response-secret-yaml\n    type: [unterminated",
			responseSecret: "upstream-response-secret-yaml",
		},
		{
			name:           "no proxies",
			statusCode:     http.StatusOK,
			body:           "credential: upstream-response-secret-empty\n",
			responseSecret: "upstream-response-secret-empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logOutput.Reset()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/"+test.responseSecret)
				w.WriteHeader(test.statusCode)
				_, _ = w.Write([]byte(test.body))
			}))
			defer upstream.Close()

			secretToken := "upstream-query-secret-" + strings.ReplaceAll(test.name, " ", "-")
			upstreamURL := upstream.URL + "/subscription?token=" + secretToken
			userAgentSecret := "upstream-user-agent-secret-" + strings.ReplaceAll(test.name, " ", "-")
			response := requestFetchSubscription(t, upstream.Client(), upstreamURL, userAgentSecret)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%q, want 400", response.Code, response.Body.String())
			}

			assertFetchSubscriptionSecretAbsent(t, logOutput.String(), upstreamURL, secretToken, test.responseSecret, userAgentSecret)
			assertFetchSubscriptionSecretAbsent(t, response.Body.String(), upstreamURL, secretToken, test.responseSecret, userAgentSecret)
		})
	}
}

func TestFetchSubscriptionSanitizesURLBearingRequestErrors(t *testing.T) {
	var logOutput bytes.Buffer
	globalLogger := arcLogger.GetLogger()
	originalLogger := globalLogger.Logger
	globalLogger.Logger = slog.New(slog.NewTextHandler(&logOutput, nil))
	t.Cleanup(func() {
		globalLogger.Logger = originalLogger
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := upstream.Client()
	upstream.Close()

	secretToken := "upstream-query-secret-transport"
	upstreamURL := upstream.URL + "/subscription?token=" + secretToken
	response := requestFetchSubscription(t, client, upstreamURL, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q, want 400", response.Code, response.Body.String())
	}

	assertFetchSubscriptionSecretAbsent(t, logOutput.String(), upstreamURL, secretToken)
	assertFetchSubscriptionSecretAbsent(t, response.Body.String(), upstreamURL, secretToken)
	if !strings.Contains(response.Body.String(), "无法获取订阅内容") {
		t.Fatalf("response body=%q, want generic fetch error", response.Body.String())
	}
}

func requestFetchSubscription(t *testing.T, client *http.Client, upstreamURL, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"url": upstreamURL, "user_agent": userAgent})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/nodes/fetch-subscription", bytes.NewReader(body))
	request = request.WithContext(auth.ContextWithUsername(request.Context(), "test-user"))
	response := httptest.NewRecorder()
	(&nodesHandler{fetchClient: client}).handleFetchSubscription(response, request)
	return response
}

func assertFetchSubscriptionSecretAbsent(t *testing.T, output string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(output, secret) {
			t.Fatalf("output contains upstream secret %q: %s", secret, output)
		}
	}
}
