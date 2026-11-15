package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOIDCRejectUnsignedAndMissingClaims(t *testing.T) {
	h, _, _ := setupTestOAuthEnv(t)
	if h.verifyOIDCSignature(context.Background(), "eyJhbGciOiJub25lIn0.e30.", "https://example.test/jwks") == nil {
		t.Fatal("unsigned accepted")
	}
	for _, c := range []map[string]any{{"sub": "x"}, {"sub": "x", "iss": "https://sso.example", "aud": "panel", "exp": 9999999999}} {
		if _, e := parseAndValidateIDToken(createMockJWT(c), "https://sso.example", "panel", "required"); e == nil {
			t.Fatal("missing claims accepted")
		}
	}
}
func TestExchangeRequiresBrowserCookie(t *testing.T) {
	h, _, _ := setupTestOAuthEnv(t)
	code := h.createExchangeCode("secret-session", "admin", "right-browser")
	r := httptest.NewRequest(http.MethodPost, "/api/public/oauth/exchange", strings.NewReader(`{"code":"`+code+`"}`))
	w := httptest.NewRecorder()
	h.ExchangeOAuthCode(w, r)
	if w.Code != 401 {
		t.Fatal("unbound exchange accepted")
	}
}
