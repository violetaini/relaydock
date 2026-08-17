package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMutateInboundClientVLESSIsIdempotent(t *testing.T) {
	inbound := map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{}},
	}
	client := map[string]interface{}{"id": "client-1", "email": "alice__edge"}

	changed, err := mutateInboundClient(inbound, client, true)
	if err != nil || !changed {
		t.Fatalf("first add: changed=%v err=%v", changed, err)
	}
	changed, err = mutateInboundClient(inbound, client, true)
	if err != nil || changed {
		t.Fatalf("duplicate add: changed=%v err=%v", changed, err)
	}
	changed, err = mutateInboundClient(inbound, map[string]interface{}{
		"id": "different-id", "email": "alice__edge",
	}, true)
	if err != nil || changed {
		t.Fatalf("duplicate email add: changed=%v err=%v", changed, err)
	}

	changed, err = mutateInboundClient(inbound, client, false)
	if err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	changed, err = mutateInboundClient(inbound, client, false)
	if err != nil || changed {
		t.Fatalf("duplicate remove: changed=%v err=%v", changed, err)
	}
}

func TestMutateInboundClientUsesProtocolList(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		listKey  string
		client   map[string]interface{}
	}{
		{name: "trojan", protocol: "trojan", listKey: "clients", client: map[string]interface{}{"password": "secret", "email": "alice"}},
		{name: "anytls", protocol: "anytls", listKey: "users", client: map[string]interface{}{"password": "secret", "email": "alice"}},
		{name: "snell", protocol: "snell", listKey: "users", client: map[string]interface{}{"psk": "secret", "email": "alice"}},
		{name: "socks", protocol: "socks", listKey: "accounts", client: map[string]interface{}{"user": "alice", "pass": "secret"}},
		{name: "wireguard", protocol: "wireguard", listKey: "peers", client: map[string]interface{}{
			"publicKey": wireGuardYAMLTestKey(0x41), "allowedIPs": []interface{}{"10.66.66.3/32"}, "keepAlive": float64(25),
			"encryptedPrivateKey": "must-not-reach-xray", "serverPublicKey": wireGuardYAMLTestKey(0x42),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := map[string]interface{}{}
			inbound := map[string]interface{}{"protocol": tt.protocol, "settings": settings}
			changed, err := mutateInboundClient(inbound, tt.client, true)
			if err != nil || !changed {
				t.Fatalf("add: changed=%v err=%v", changed, err)
			}
			items, ok := settings[tt.listKey].([]interface{})
			if !ok || len(items) != 1 {
				t.Fatalf("settings.%s = %#v", tt.listKey, settings[tt.listKey])
			}
			if tt.protocol == "wireguard" {
				peer := items[0].(map[string]interface{})
				if _, leaked := peer["encryptedPrivateKey"]; leaked || len(peer) != 3 {
					t.Fatalf("WireGuard peer was not sanitized: %#v", peer)
				}
				changed, err = mutateInboundClient(inbound, map[string]interface{}{"publicKey": wireGuardYAMLTestKey(0x41)}, false)
				if err != nil || !changed {
					t.Fatalf("remove WireGuard peer: changed=%v err=%v", changed, err)
				}
			}
		})
	}
}

func TestMutateInboundClientRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		inbound map[string]interface{}
		client  map[string]interface{}
	}{
		{
			name:    "missing identity",
			inbound: map[string]interface{}{"protocol": "vless", "settings": map[string]interface{}{}},
			client:  map[string]interface{}{"level": 0},
		},
		{
			name:    "unsupported protocol",
			inbound: map[string]interface{}{"protocol": "unknown", "settings": map[string]interface{}{}},
			client:  map[string]interface{}{"email": "alice"},
		},
		{
			name:    "invalid client list",
			inbound: map[string]interface{}{"protocol": "vless", "settings": map[string]interface{}{"clients": "bad"}},
			client:  map[string]interface{}{"id": "client-1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if changed, err := mutateInboundClient(tt.inbound, tt.client, true); err == nil || changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestManagedClientExpirationRenewalPrefersStableEmail(t *testing.T) {
	entries := make(map[string]managedClientExpiration)
	first := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	second := first.Add(24 * time.Hour)
	changed, err := setManagedClientExpiration(entries, "vless-443", "vless", map[string]interface{}{
		"id": "first-id", "email": "alice__vless-443",
	}, &first)
	if err != nil || !changed {
		t.Fatalf("first schedule: changed=%v err=%v", changed, err)
	}
	changed, err = setManagedClientExpiration(entries, "vless-443", "vless", map[string]interface{}{
		"id": "replacement-id", "email": "alice__vless-443",
	}, &second)
	if err != nil || !changed {
		t.Fatalf("renew schedule: changed=%v err=%v", changed, err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(entries))
	}
	for _, entry := range entries {
		if entry.IdentityKey != "email" || entry.IdentityValue != "alice__vless-443" {
			t.Fatalf("identity=%s:%s", entry.IdentityKey, entry.IdentityValue)
		}
		if !entry.NotAfter.Equal(second) {
			t.Fatalf("not_after=%s, want %s", entry.NotAfter, second)
		}
		identity := entry.clientIdentity()
		if len(identity) != 1 || identity["email"] != "alice__vless-443" {
			t.Fatalf("client identity=%#v", identity)
		}
	}
	changed, err = setManagedClientExpiration(entries, "vless-443", "vless", map[string]interface{}{
		"email": "alice__vless-443",
	}, &second)
	if err != nil || changed {
		t.Fatalf("idempotent renewal: changed=%v err=%v", changed, err)
	}
	changed, err = setManagedClientExpiration(entries, "vless-443", "vless", map[string]interface{}{
		"email": "alice__vless-443",
	}, nil)
	if err != nil || !changed || len(entries) != 0 {
		t.Fatalf("clear schedule: changed=%v len=%d err=%v", changed, len(entries), err)
	}
}

func TestManagedClientExpirationFallsBackToProtocolCredential(t *testing.T) {
	deadline := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	entry, err := newManagedClientExpiration("trojan-443", "trojan", map[string]interface{}{
		"password": "credential", "level": 0,
	}, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if entry.IdentityKey != "password" || entry.IdentityValue != "credential" {
		t.Fatalf("identity=%s:%s", entry.IdentityKey, entry.IdentityValue)
	}
	if identity := entry.clientIdentity(); len(identity) != 1 || identity["password"] != "credential" {
		t.Fatalf("client identity=%#v", identity)
	}
}

func TestDueManagedClientExpirationsSeparatesNextDeadline(t *testing.T) {
	now := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	entries := make(map[string]managedClientExpiration)
	for _, item := range []struct {
		tag      string
		email    string
		deadline time.Time
	}{
		{tag: "b", email: "second", deadline: now},
		{tag: "a", email: "first", deadline: now.Add(-time.Minute)},
		{tag: "c", email: "future", deadline: now.Add(time.Hour)},
	} {
		entry, err := newManagedClientExpiration(item.tag, "vless", map[string]interface{}{"email": item.email}, item.deadline)
		if err != nil {
			t.Fatal(err)
		}
		entries[entry.key()] = entry
	}
	due, next := dueManagedClientExpirations(entries, now)
	if len(due) != 2 || due[0].Tag != "a" || due[1].Tag != "b" {
		t.Fatalf("due=%#v", due)
	}
	if next == nil || !next.Equal(now.Add(time.Hour)) {
		t.Fatalf("next=%v", next)
	}
}

func TestManagedClientExpirationSidecarRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	path := managedClientExpirationSidecarPath(configPath)
	if filepath.Dir(path) != dir {
		t.Fatalf("sidecar path=%s", path)
	}
	deadline := time.Date(2026, 7, 20, 8, 0, 0, 123456789, time.UTC)
	entry, err := newManagedClientExpiration("vless-443", "vless", map[string]interface{}{"email": "alice"}, deadline)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]managedClientExpiration{entry.key(): entry}
	if err := writeManagedClientExpirations(path, entries); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("sidecar mode=%#o, want 0600", mode)
	}
	restored, err := loadManagedClientExpirations(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[entry.key()] != entry {
		t.Fatalf("restored=%#v", restored)
	}

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeManagedClientExpirations(path, map[string]managedClientExpiration{}); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("rewritten sidecar mode=%#o, want 0600", mode)
	}
	restored, err = loadManagedClientExpirations(path)
	if err != nil || len(restored) != 0 {
		t.Fatalf("empty restored=%#v err=%v", restored, err)
	}
}

func TestManagedClientExpirationSidecarRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), managedClientExpirySidecarName)
	if err := os.WriteFile(path, []byte(`{"version":99,"entries":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedClientExpirations(path); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestChildInboundRequestParsesRFC3339NotAfter(t *testing.T) {
	var request ChildInboundRequest
	if err := json.Unmarshal([]byte(`{"action":"add-client","not_after":"2026-07-20T08:00:00Z"}`), &request); err != nil {
		t.Fatal(err)
	}
	if request.NotAfter == nil || request.NotAfter.Format(time.RFC3339) != "2026-07-20T08:00:00Z" {
		t.Fatalf("not_after=%v", request.NotAfter)
	}
	if err := json.Unmarshal([]byte(`{"action":"add-client","not_after":"tomorrow"}`), &request); err == nil {
		t.Fatal("expected invalid RFC3339 error")
	}
}
