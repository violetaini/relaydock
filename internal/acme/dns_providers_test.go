package acme

import (
	"os"
	"testing"

	"miaomiaowux/internal/dnscredentials"
)

func TestSetDNSCredentialEnvSelectsGlobalModeAndRestoresEnvironment(t *testing.T) {
	const originalToken = "host-token"
	t.Setenv(dnscredentials.CloudflareTokenKey, originalToken)
	t.Setenv(dnscredentials.CloudflareEmailKey, "")
	t.Setenv(dnscredentials.CloudflareGlobalKey, "")

	cleanup, err := SetDNSCredentialEnv("cloudflare", map[string]string{
		dnscredentials.CloudflareTokenKey:  "stale-token",
		dnscredentials.CloudflareEmailKey:  "admin@example.com",
		dnscredentials.CloudflareGlobalKey: "global-key",
	})
	if err != nil {
		t.Fatalf("SetDNSCredentialEnv: %v", err)
	}
	if got := os.Getenv(dnscredentials.CloudflareTokenKey); got != "" {
		t.Fatalf("token leaked into global mode: %q", got)
	}
	if got := os.Getenv(dnscredentials.CloudflareGlobalKey); got != "global-key" {
		t.Fatalf("global key not set: %q", got)
	}
	cleanup()
	if got := os.Getenv(dnscredentials.CloudflareTokenKey); got != originalToken {
		t.Fatalf("original environment was not restored: %q", got)
	}
	if got := os.Getenv(dnscredentials.CloudflareGlobalKey); got != "" {
		t.Fatalf("temporary global key remained after cleanup: %q", got)
	}
}
