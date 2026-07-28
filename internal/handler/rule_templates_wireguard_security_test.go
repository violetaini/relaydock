package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRuleTemplateSecretsRejectsWireGuardIdentityEverywhere(t *testing.T) {
	privateKey := subscriptionTestWireGuardPrivateKey
	tests := []string{
		"proxies:\n  - name: wg\n    type: wireguard\n    private-key: " + privateKey + "\n",
		"defaults: &defaults {private-key: " + privateKey + "}\nproxies:\n  - <<: *defaults\n    type: vless\n",
		"proxies:\n  - name: wg\n    type: wg\n    private-key: " + wireGuardSubscriptionSecretPrefix + "untrusted\n",
	}
	for _, content := range tests {
		if err := validateRuleTemplateSecrets(content); err == nil || !strings.Contains(err.Error(), "不能保存 WireGuard") {
			t.Fatalf("validateRuleTemplateSecrets(%q) err=%v", content, err)
		}
	}
	if err := validateRuleTemplateSecrets("proxies:\n  - name: ordinary\n    type: vless\n    public-key: " + privateKey + "\n"); err != nil {
		t.Fatalf("ordinary public key was rejected: %v", err)
	}
	if err := validateRuleTemplateSecrets("mode: rule\nproxies: null\n"); err != nil {
		t.Fatalf("empty proxy placeholder was rejected: %v", err)
	}
	if err := validateRuleTemplateSecrets("proxies: {}\n"); err == nil || !strings.Contains(err.Error(), "必须是 YAML 列表") {
		t.Fatalf("invalid proxy placeholder error = %v", err)
	}
}

func TestValidatePersistedRuleTemplateSecretsFailsClosedWithFilename(t *testing.T) {
	directory := t.TempDir()
	placeholder := "mode: rule\nproxies: null\nproxy-groups: []\n"
	if err := os.WriteFile(filepath.Join(directory, "placeholder.yaml"), []byte(placeholder), 0644); err != nil {
		t.Fatal(err)
	}
	ordinary := "proxies:\n  - name: ordinary\n    type: vless\n    uuid: test\n"
	if err := os.WriteFile(filepath.Join(directory, "ordinary.yaml"), []byte(ordinary), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePersistedRuleTemplateSecrets(directory); err != nil {
		t.Fatalf("ordinary persisted template failed validation: %v", err)
	}

	name := "legacy-wireguard.yaml"
	legacy := "proxies:\n  - name: legacy\n    type: wireguard\n    private-key: " + subscriptionTestWireGuardPrivateKey + "\n"
	if err := os.WriteFile(filepath.Join(directory, name), []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}
	err := ValidatePersistedRuleTemplateSecrets(directory)
	if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "拒绝启动") {
		t.Fatalf("persisted template error=%v, want filename and fail-closed message", err)
	}
	stored, readErr := os.ReadFile(filepath.Join(directory, name))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(stored) != legacy {
		t.Fatal("fail-closed template validation modified the historical file")
	}
}

func TestValidatePersistedRuleTemplateSecretsRejectsYAMLSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.yaml")
	if err := os.WriteFile(target, []byte("proxies: []\n"), 0644); err != nil {
		t.Fatal(err)
	}
	linkName := "linked.yaml"
	if err := os.Symlink(target, filepath.Join(directory, linkName)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	err := ValidatePersistedRuleTemplateSecrets(directory)
	if err == nil || !strings.Contains(err.Error(), linkName) || !strings.Contains(err.Error(), "符号链接") {
		t.Fatalf("symlink validation err=%v", err)
	}
}
