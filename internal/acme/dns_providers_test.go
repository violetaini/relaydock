package acme

import (
	"os"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/dnscredentials"
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

func TestSetDNSCredentialEnvHuaweiCloud(t *testing.T) {
	cleanup, err := SetDNSCredentialEnv("huaweicloud", map[string]string{
		"AccessKeyId":     "test-ak-value",
		"SecretAccessKey": "test-sk-value",
	})
	if err != nil {
		t.Fatalf("SetDNSCredentialEnv huaweicloud: %v", err)
	}
	if got := os.Getenv("HUAWEICLOUD_ACCESS_KEY_ID"); got != "test-ak-value" {
		t.Fatalf("HUAWEICLOUD_ACCESS_KEY_ID = %q, want test-ak-value", got)
	}
	if got := os.Getenv("HUAWEICLOUD_SECRET_ACCESS_KEY"); got != "test-sk-value" {
		t.Fatalf("HUAWEICLOUD_SECRET_ACCESS_KEY = %q, want test-sk-value", got)
	}
	if got := os.Getenv("HUAWEICLOUD_REGION"); got != "cn-north-4" {
		t.Fatalf("HUAWEICLOUD_REGION = %q, want cn-north-4", got)
	}

	_, err = NewDNSProviderByName("huaweicloud")
	// Dummy credentials will be rejected by Huawei Cloud IAM (401 APIGW.0301),
	// which verifies that the Lego huaweicloud client was constructed and dialed.
	if err == nil {
		t.Fatalf("expected error with dummy credentials, got nil")
	}
	if !strings.Contains(err.Error(), "huaweicloud") && !strings.Contains(err.Error(), "APIGW") && !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("unexpected error: %v", err)
	}

	cleanup()
	if got := os.Getenv("HUAWEICLOUD_ACCESS_KEY_ID"); got != "" {
		t.Fatalf("HUAWEICLOUD_ACCESS_KEY_ID remained after cleanup: %q", got)
	}
}
