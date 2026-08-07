package handler

import (
	"net/http/httptest"
	"testing"
)

func TestObservedPublicBaseURL(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		proto string
		want  string
	}{
		{name: "forwarded https", host: "arcway.example:8443", proto: "https", want: "https://arcway.example:8443"},
		{name: "reject path", host: "arcway.example/path", proto: "https"},
		{name: "reject user info", host: "admin@arcway.example", proto: "https"},
		{name: "reject header injection", host: "arcway.example\r\nX-Test: yes", proto: "https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://localhost/", nil)
			r.Header.Set("X-Forwarded-Host", tt.host)
			r.Header.Set("X-Forwarded-Proto", tt.proto)
			if got := observedPublicBaseURL(r); got != tt.want {
				t.Fatalf("observedPublicBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
