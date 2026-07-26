package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeInboundPersistenceFixture(t *testing.T, path string, inbounds []any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": inbounds,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readInboundPersistenceFixture(t *testing.T, path string) map[string]any {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestUpsertInboundConfigFileReplacesAndRepairsDuplicateTags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeInboundPersistenceFixture(t, path, []any{
		map[string]any{"tag": "api", "protocol": "dokodemo-door", "port": 10085},
		map[string]any{"tag": "anydoor-node-7", "protocol": "tunnel", "port": 2001},
		map[string]any{"tag": "anydoor-node-7", "protocol": "tunnel", "port": 2002},
	})

	replacement := map[string]any{
		"tag": "anydoor-node-7", "protocol": "dokodemo-door", "port": 2033,
		"settings": map[string]any{"network": "tcp,udp"},
	}
	if err := upsertInboundConfigFile(path, replacement); err != nil {
		t.Fatalf("upsert inbound: %v", err)
	}

	config := readInboundPersistenceFixture(t, path)
	inbounds, _ := config["inbounds"].([]any)
	counts := map[string]int{}
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		tag, _ := inbound["tag"].(string)
		counts[tag]++
		if tag == "anydoor-node-7" && int(inbound["port"].(float64)) != 2033 {
			t.Fatalf("replacement not persisted: %#v", inbound)
		}
	}
	if counts["anydoor-node-7"] != 1 || counts["api"] != 1 || len(inbounds) != 2 {
		t.Fatalf("unexpected repaired inbounds: %#v", inbounds)
	}
	if _, ok := config["log"]; !ok {
		t.Fatal("upsert discarded unrelated config")
	}
}

func TestUpsertInboundConfigFileAppendsNewTag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeInboundPersistenceFixture(t, path, []any{map[string]any{"tag": "api", "port": 10085}})

	if err := upsertInboundConfigFile(path, map[string]any{"tag": "new-forward", "port": 2033}); err != nil {
		t.Fatalf("upsert inbound: %v", err)
	}
	config := readInboundPersistenceFixture(t, path)
	inbounds, _ := config["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("inbounds=%#v, want existing plus new inbound", inbounds)
	}
}

func TestRemoveInboundConfigFileRemovesAllDuplicateDefinitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeInboundPersistenceFixture(t, path, []any{
		map[string]any{"tag": "api", "port": 10085},
		map[string]any{"tag": "tunnel-route-h0", "port": 2033},
		map[string]any{"tag": "tunnel-route-h0", "port": 2033},
	})

	if err := removeInboundConfigFile(path, "tunnel-route-h0"); err != nil {
		t.Fatalf("remove inbound: %v", err)
	}
	config := readInboundPersistenceFixture(t, path)
	inbounds, _ := config["inbounds"].([]any)
	if len(inbounds) != 1 || inbounds[0].(map[string]any)["tag"] != "api" {
		t.Fatalf("duplicate tag was not fully removed: %#v", inbounds)
	}
}

func TestInboundConfigPersistenceFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "config.json")
	if err := upsertInboundConfigFile(missing, map[string]any{"tag": "forward"}); err == nil {
		t.Fatal("upsert unexpectedly succeeded without a durable config file")
	}
	if err := removeInboundConfigFile(missing, "forward"); err == nil {
		t.Fatal("remove unexpectedly succeeded without a durable config file")
	}
}
