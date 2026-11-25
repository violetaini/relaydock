package handler

import (
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestChitandaCredentialAndInboundHelpers(t *testing.T) {
	if !supportsPerUserInboundCredential("chitanda") {
		t.Fatal("supportsPerUserInboundCredential(chitanda) = false, want true")
	}
	if got, err := inboundClientListKey("chitanda", nil); err != nil || got != "users" {
		t.Fatalf("inboundClientListKey(chitanda) = (%q, %v), want (users, nil)", got, err)
	}
	if got := inboundCredentialPrimaryKey("chitanda"); got != "psk" {
		t.Fatalf("inboundCredentialPrimaryKey(chitanda) = %q, want psk", got)
	}

	cred, rawJSON, err := generateCredential("chitanda", storage.User{Username: "alice"}, "", "ch-in")
	if err != nil {
		t.Fatalf("generateCredential(chitanda): %v", err)
	}
	if rawJSON == "" {
		t.Fatal("rawJSON = empty, want serialized credential")
	}
	psk, _ := cred["psk"].(string)
	if len(psk) < 32 {
		t.Fatalf("generated Chitanda PSK len = %d, want >= 32", len(psk))
	}
	if cred["email"] != "alice__ch-in" {
		t.Fatalf("cred email = %#v, want alice__ch-in", cred["email"])
	}
	if cred["level"] != 0 {
		t.Fatalf("cred level = %#v, want 0", cred["level"])
	}

	proxy := map[string]any{
		"name":                                    "HK Chitanda",
		"type":                                    "chitanda",
		"server":                                  "1.2.3.4",
		"port":                                    28443,
		"psk":                                     "owner-psk-0123456789abcdef01234567",
		storage.ManagedShadowsocksMultiUserMarker: true,
	}
	if !applyCredToProxy(proxy, "chitanda", cred) {
		t.Fatal("applyCredToProxy(chitanda) = false, want true")
	}
	if proxy["psk"] != psk {
		t.Fatalf("proxy psk = %#v, want %q", proxy["psk"], psk)
	}
	if _, leaked := proxy[storage.ManagedShadowsocksMultiUserMarker]; leaked {
		t.Fatalf("internal marker leaked into proxy: %#v", proxy)
	}
}

func TestNormalizeChitandaInboundDefaultsAndClashProxy(t *testing.T) {
	inbound := map[string]any{
		"tag":      "chitanda-h2-abc",
		"protocol": "chitanda",
		"port":     float64(28443),
		"settings": map[string]any{
			"psk":       "legacy-32-byte-psk-0123456789abcd",
			"transport": "h2",
		},
	}
	normalizeChitandaInboundDefaults(map[string]any{"inbound": inbound})
	settings, _ := inbound["settings"].(map[string]any)
	if _, hasTopPSK := settings["psk"]; hasTopPSK {
		t.Fatalf("top-level settings.psk still present after normalization: %#v", settings)
	}
	users, ok := settings["users"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("settings.users = %#v, want 1 user", settings["users"])
	}
	firstUser, _ := users[0].(map[string]any)
	if firstUser["email"] != "admin" || firstUser["psk"] != "legacy-32-byte-psk-0123456789abcd" {
		t.Fatalf("firstUser = %#v", firstUser)
	}

	proxy, err := (&RemoteManageHandler{}).inboundToClashProxy(inbound, "1.2.3.4", "edge", 0, "admin")
	if err != nil {
		t.Fatalf("inboundToClashProxy(chitanda): %v", err)
	}
	if proxy["psk"] != "legacy-32-byte-psk-0123456789abcd" {
		t.Fatalf("proxy psk = %#v", proxy["psk"])
	}
	if proxy[storage.ManagedShadowsocksMultiUserMarker] != true {
		t.Fatalf("managed multi-user marker = %#v, want true", proxy[storage.ManagedShadowsocksMultiUserMarker])
	}
}

func TestSubscriptionNodeAccountingEligibilityChitanda(t *testing.T) {
	legacy := storage.Node{
		OriginalServer: "edge-1",
		Protocol:       "chitanda",
		InboundTag:     "ch-legacy",
		NodeType:       "physical",
		ClashConfig:    `{"name":"Legacy CH","type":"chitanda","server":"1.2.3.4","port":28443,"psk":"0123456789abcdef0123456789abcdef"}`,
	}
	if ok, _ := subscriptionNodeAccountingEligibility(legacy); ok {
		t.Fatal("legacy shared-PSK Chitanda node should not be eligible")
	}

	multiUser := storage.Node{
		OriginalServer: "edge-1",
		Protocol:       "chitanda",
		InboundTag:     "ch-multi",
		NodeType:       "physical",
		ClashConfig:    `{"name":"MultiUser CH","type":"chitanda","server":"1.2.3.4","port":28443,"psk":"0123456789abcdef0123456789abcdef","x-arcway-managed-users":true}`,
	}
	if ok, reason := subscriptionNodeAccountingEligibility(multiUser); !ok {
		t.Fatalf("multi-user Chitanda node rejected: %s", reason)
	}
}
