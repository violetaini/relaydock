package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"

	"gopkg.in/yaml.v3"
)

func newWireGuardYAMLSemanticsRepo(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo := newManagedSecurityTestRepo(t)
	if err := repo.ConfigureNodeSecretEncryption(bytes.Repeat([]byte{0x71}, 32)); err != nil {
		t.Fatalf("configure node secret encryption: %v", err)
	}
	return repo
}

func wireGuardYAMLTestKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func effectiveProxyPrivateKeys(t *testing.T, content string) []string {
	t.Helper()
	var decoded struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(content), &decoded); err != nil {
		t.Fatalf("decode effective YAML: %v\n%s", err, content)
	}
	keys := make([]string, 0, len(decoded.Proxies))
	for _, proxy := range decoded.Proxies {
		if value, ok := proxy["private-key"].(string); ok {
			keys = append(keys, value)
		}
	}
	return keys
}

func protectAndHydrateWireGuardYAML(t *testing.T, repo *storage.TrafficRepository, scope, content, privateKey string) (string, string) {
	t.Helper()
	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, scope, content, false)
	if err != nil {
		t.Fatalf("protect YAML: %v\n%s", err, content)
	}
	if strings.Contains(protected, privateKey) || !strings.Contains(protected, wireGuardSubscriptionSecretPrefix) {
		t.Fatalf("protected YAML leaked key or missed marker:\n%s", protected)
	}
	hydrated, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, scope, protected)
	if err != nil {
		t.Fatalf("hydrate YAML: %v\n%s", err, protected)
	}
	return protected, hydrated
}

func TestWireGuardSubscriptionYAMLMergeAndAliasSemantics(t *testing.T) {
	repo := newWireGuardYAMLSemanticsRepo(t)
	privateKey := wireGuardYAMLTestKey(1)
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "direct type and merged private key",
			content: "key-default: &key-default\n" +
				"  private-key: " + privateKey + "\n" +
				"proxies:\n" +
				"  - name: wg\n" +
				"    type: wireguard\n" +
				"    <<: *key-default\n",
		},
		{
			name: "split merge sources",
			content: "kind: &kind {type: wireguard}\n" +
				"secret: &secret {private-key: " + privateKey + "}\n" +
				"proxies:\n" +
				"  - name: wg\n" +
				"    <<: [*kind, *secret]\n",
		},
		{
			name: "nested merge",
			content: "base: &base {private-key: " + privateKey + "}\n" +
				"wg-default: &wg-default\n" +
				"  <<: *base\n" +
				"  type: wg\n" +
				"proxies:\n" +
				"  - name: wg\n" +
				"    <<: *wg-default\n",
		},
		{
			name: "scalar alias",
			content: "secret: &secret " + privateKey + "\n" +
				"proxies:\n" +
				"  - name: wg\n" +
				"    type: wireguard\n" +
				"    private-key: *secret\n",
		},
		{
			name: "whole mapping aliases",
			content: "wg-default: &wg-default\n" +
				"  type: wireguard\n" +
				"  private-key: " + privateKey + "\n" +
				"proxies:\n" +
				"  - *wg-default\n" +
				"  - *wg-default\n",
		},
		{
			name: "explicit merge tag",
			content: "wg-default: &wg-default {type: wireguard, private-key: " + privateKey + "}\n" +
				"proxies:\n" +
				"  - !!merge '<<': *wg-default\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, hydrated := protectAndHydrateWireGuardYAML(t, repo, "merge-"+strings.ReplaceAll(test.name, " ", "-")+".yaml", test.content, privateKey)
			keys := effectiveProxyPrivateKeys(t, hydrated)
			if len(keys) == 0 {
				t.Fatalf("hydrated YAML has no effective private key:\n%s", hydrated)
			}
			for _, key := range keys {
				if !equalManagedWireGuardKeys(key, privateKey) {
					t.Fatalf("effective private key = %q, want original key", key)
				}
			}
		})
	}
}

func TestWireGuardSubscriptionYAMLExplicitOverridesAndMergePrecedence(t *testing.T) {
	repo := newWireGuardYAMLSemanticsRepo(t)
	managedKey := wireGuardYAMLTestKey(2)
	otherKey := wireGuardYAMLTestKey(3)

	t.Run("type override prevents false positive", func(t *testing.T) {
		content := "defaults: &defaults {type: wireguard, private-key: " + managedKey + "}\n" +
			"proxies:\n" +
			"  - <<: *defaults\n" +
			"    type: vless\n" +
			"    uuid: test-uuid\n"
		if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, "type-override.yaml", content, false); !errors.Is(err, errUnprotectedWireGuardPrivateKey) {
			t.Fatalf("inactive plaintext private-key error = %v, want fail-closed rejection", err)
		}
	})

	t.Run("explicit private key overrides merged value", func(t *testing.T) {
		content := "defaults: &defaults {private-key: " + otherKey + "}\n" +
			"proxies:\n" +
			"  - <<: *defaults\n" +
			"    type: wireguard\n" +
			"    private-key: " + managedKey + "\n"
		if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, "key-override.yaml", content, false); !errors.Is(err, errUnprotectedWireGuardPrivateKey) {
			t.Fatalf("overridden plaintext private-key error = %v, want fail-closed rejection", err)
		}
	})

	t.Run("merge sequence left side wins", func(t *testing.T) {
		content := "kind: &kind {type: wireguard}\n" +
			"first: &first {private-key: " + managedKey + "}\n" +
			"second: &second {private-key: " + otherKey + "}\n" +
			"proxies:\n" +
			"  - <<: [*kind, *first, *second]\n"
		if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, "left-wins.yaml", content, false); !errors.Is(err, errUnprotectedWireGuardPrivateKey) {
			t.Fatalf("lower-precedence plaintext private-key error = %v, want fail-closed rejection", err)
		}
	})
}

func TestWireGuardSubscriptionYAMLRejectsAmbiguousSources(t *testing.T) {
	repo := newWireGuardYAMLSemanticsRepo(t)
	privateKey := wireGuardYAMLTestKey(4)
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "same mapping source used by non WireGuard proxy",
			content: "defaults: &defaults {private-key: " + privateKey + "}\n" +
				"proxies:\n" +
				"  - <<: *defaults\n" +
				"    type: wireguard\n" +
				"  - <<: *defaults\n" +
				"    type: vless\n",
		},
		{
			name: "scalar source aliased by unrelated field",
			content: "secret: &secret " + privateKey + "\n" +
				"password-copy: *secret\n" +
				"proxies:\n" +
				"  - type: wireguard\n" +
				"    private-key: *secret\n",
		},
		{
			name: "mapping source aliased outside proxy list",
			content: "defaults: &defaults {type: wireguard, private-key: " + privateKey + "}\n" +
				"unrelated-copy: *defaults\n" +
				"proxies: [*defaults]\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, "ambiguous.yaml", test.content, false); !errors.Is(err, errAmbiguousWireGuardSecret) {
				t.Fatalf("error = %v, want ambiguous-source rejection", err)
			}
		})
	}
}

func TestWireGuardSubscriptionYAMLRejectsMultipleDocumentsDuplicatesAndCycles(t *testing.T) {
	repo := newWireGuardYAMLSemanticsRepo(t)
	privateKey := wireGuardYAMLTestKey(5)
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "multiple documents",
			content: "proxies: []\n---\n" + managedWireGuardSubscriptionYAML(privateKey),
		},
		{
			name: "normalized duplicate private key",
			content: "proxies:\n" +
				"  - type: wireguard\n" +
				"    private-key: " + privateKey + "\n" +
				"    private_key: " + privateKey + "\n",
		},
		{
			name: "recursive merge alias",
			content: "loop: &loop\n" +
				"  <<: *loop\n" +
				"  type: wireguard\n" +
				"  private-key: " + privateKey + "\n" +
				"proxies: [*loop]\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, "invalid.yaml", test.content, false); err == nil {
				t.Fatal("invalid YAML was accepted")
			}
		})
	}
}

func TestWireGuardSubscriptionYAMLSnapshotValidationAndScopeBinding(t *testing.T) {
	repo := newWireGuardYAMLSemanticsRepo(t)
	privateKey := wireGuardYAMLTestKey(6)
	content := managedWireGuardSubscriptionYAML(privateKey)
	protected, err := protectWireGuardSubscriptionContent(context.Background(), repo, "scope-a.yaml", content, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, "scope-a.yaml", protected, false); !errors.Is(err, errUntrustedWireGuardSecret) {
		t.Fatalf("caller marker error = %v, want untrusted marker", err)
	}
	validated, err := protectWireGuardSubscriptionContent(context.Background(), repo, "scope-a.yaml", protected, true)
	if err != nil {
		t.Fatalf("startup validation rejected authentic marker: %v", err)
	}
	if !strings.Contains(validated, wireGuardSubscriptionSecretPrefix) || strings.Contains(validated, privateKey) {
		t.Fatalf("startup validation changed protection semantics:\n%s", validated)
	}
	if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, "scope-b.yaml", protected, true); !errors.Is(err, errUntrustedWireGuardSecret) {
		t.Fatalf("wrong-scope startup error = %v, want untrusted marker", err)
	}
	if _, err := hydrateWireGuardSubscriptionContent(context.Background(), repo, "scope-b.yaml", protected); !errors.Is(err, errUntrustedWireGuardSecret) {
		t.Fatalf("wrong-scope hydrate error = %v, want untrusted marker", err)
	}
}

func TestWireGuardSubscriptionYAMLRejectsEquivalentPrivateKeyResidue(t *testing.T) {
	repo := newWireGuardYAMLSemanticsRepo(t)
	privateKey := wireGuardYAMLTestKey(7)
	rawEquivalent := strings.TrimSuffix(privateKey, "=")
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "other scalar field",
			content: "backup-key: " + rawEquivalent + "\n" +
				managedWireGuardSubscriptionYAML(privateKey),
		},
		{
			name: "comment",
			content: "# backup-key: " + rawEquivalent + "\n" +
				managedWireGuardSubscriptionYAML(privateKey),
		},
		{
			name: "hex encoded comment",
			content: "# backup-key: " + strings.Repeat("07", 32) + "\n" +
				managedWireGuardSubscriptionYAML(privateKey),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := protectWireGuardSubscriptionContent(context.Background(), repo, "residue.yaml", test.content, false); err == nil {
				t.Fatal("equivalent private-key residue was accepted")
			}
		})
	}
}
