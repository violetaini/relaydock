package handler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"miaomiaowux/internal/storage"
)

func TestSyncExternalNodeUpdateToLegacyYAMLSkipsHydratedWireGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	original := "proxies:\n  - name: managed-wg\n    type: wireguard\n    server: 192.0.2.10\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	const privateKey = "panel-hydrated-private-key"
	node := storage.Node{
		NodeName: "managed-wg",
		Protocol: "wireguard",
		ClashConfig: `{"name":"managed-wg","type":"wireguard","server":"198.51.100.20","port":51820,` +
			`"private-key":"` + privateKey + `"}`,
	}
	if err := syncExternalNodeUpdateToLegacyYAML(nil, dir, node.NodeName, node); err != nil {
		t.Fatalf("sync hydrated WireGuard node: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("legacy YAML changed for hydrated WireGuard node:\n%s", got)
	}
	if strings.Contains(string(got), privateKey) {
		t.Fatal("hydrated WireGuard private key leaked into legacy YAML")
	}
}

func TestSyncExternalNodeUpdateToLegacyYAMLPersistsOrdinaryNode(t *testing.T) {
	repo, _ := newWireGuardSubscriptionTestRepo(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	if err := os.WriteFile(path, []byte("proxies:\n  - name: edge\n    type: vless\n    server: 192.0.2.10\n    port: 80\n    uuid: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{
		Name: "legacy", Type: storage.SubscribeTypeUpload, Filename: "legacy.yaml",
	}); err != nil {
		t.Fatal(err)
	}

	node := storage.Node{
		NodeName:    "edge",
		Protocol:    "vless",
		ClashConfig: `{"name":"edge","type":"vless","server":"198.51.100.20","port":443,"uuid":"ordinary"}`,
	}
	if err := syncExternalNodeUpdateToLegacyYAML(repo, dir, node.NodeName, node); err != nil {
		t.Fatalf("sync ordinary node: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "198.51.100.20") ||
		!strings.Contains(string(got), "port: 443") ||
		!strings.Contains(string(got), "uuid: ordinary") {
		t.Fatalf("ordinary node update did not reach legacy YAML:\n%s", got)
	}
}
