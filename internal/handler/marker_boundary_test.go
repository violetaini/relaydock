package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func configHasManagedMultiUserMarker(t *testing.T, raw string) bool {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	marker, _ := config[storage.ManagedShadowsocksMultiUserMarker].(bool)
	return marker
}

func TestConvertNodeExposesCapabilityWithoutInternalMarker(t *testing.T) {
	raw := `{"name":"managed-ss","type":"ss","cipher":"aes-128-gcm","password":"secret","x-arcway-managed-users":true}`
	dto := convertNode(storage.Node{
		NodeName:       "managed-ss",
		Protocol:       "ss",
		ClashConfig:    raw,
		ParsedConfig:   raw,
		OriginalServer: "edge",
		InboundTag:     "ss-in",
		NodeType:       "physical",
	})

	if !dto.ManagedMultiUser {
		t.Fatal("managed classic Shadowsocks capability was not exposed")
	}
	if strings.Contains(dto.ClashConfig, storage.ManagedShadowsocksMultiUserMarker) {
		t.Fatalf("clash config exposed internal marker: %s", dto.ClashConfig)
	}
	if strings.Contains(dto.ParsedConfig, storage.ManagedShadowsocksMultiUserMarker) {
		t.Fatalf("parsed config exposed internal marker: %s", dto.ParsedConfig)
	}
}

func TestPrepareImportedNodeStripsForgedManagedMarker(t *testing.T) {
	raw := `{"name":"forged","type":"ss","cipher":"aes-256-gcm","password":"secret","x-arcway-managed-users":true}`
	node := storage.Node{ClashConfig: raw, ParsedConfig: raw}

	(&nodesHandler{}).prepareImportedNode(context.Background(), &node, true)

	if configHasManagedMultiUserMarker(t, node.ClashConfig) {
		t.Fatal("manual import retained forged marker in Clash config")
	}
	if configHasManagedMultiUserMarker(t, node.ParsedConfig) {
		t.Fatal("manual import retained forged marker in parsed config")
	}
}

func TestPrepareManagedNodeConfigUpdatePreservesOnlyTrustedSameCipher(t *testing.T) {
	markedAES128 := `{"name":"old","type":"ss","cipher":"aes-128-gcm","password":"old","x-arcway-managed-users":true}`
	unmarkedAES128 := `{"name":"new","type":"ss","cipher":"aes-128-gcm","password":"new"}`
	unmarkedAES256 := `{"name":"new","type":"ss","cipher":"aes-256-gcm","password":"new"}`
	forgedAES128 := `{"name":"new","type":"ss","cipher":"aes-128-gcm","password":"new","x-arcway-managed-users":true}`

	managed := storage.Node{
		Protocol: "shadowsocks", ClashConfig: markedAES128,
		OriginalServer: "edge", InboundTag: "ss-in", NodeType: "physical",
	}
	clash, parsed := prepareManagedNodeConfigUpdate(managed, unmarkedAES128, unmarkedAES128)
	if !configHasManagedMultiUserMarker(t, clash) || !configHasManagedMultiUserMarker(t, parsed) {
		t.Fatal("trusted marker was not preserved for a same-cipher edit")
	}

	clash, parsed = prepareManagedNodeConfigUpdate(managed, unmarkedAES256, markedAES128)
	if configHasManagedMultiUserMarker(t, clash) || configHasManagedMultiUserMarker(t, parsed) {
		t.Fatal("cipher change retained managed marker")
	}

	imported := storage.Node{Protocol: "shadowsocks", ClashConfig: unmarkedAES128}
	clash, parsed = prepareManagedNodeConfigUpdate(imported, forgedAES128, forgedAES128)
	if configHasManagedMultiUserMarker(t, clash) || configHasManagedMultiUserMarker(t, parsed) {
		t.Fatal("client-supplied marker established managed capability")
	}

	legacyForged := storage.Node{Protocol: "shadowsocks", ClashConfig: markedAES128}
	clash, parsed = prepareManagedNodeConfigUpdate(legacyForged, unmarkedAES128, unmarkedAES128)
	if configHasManagedMultiUserMarker(t, clash) || configHasManagedMultiUserMarker(t, parsed) {
		t.Fatal("unbound legacy marker survived a config edit")
	}
}

func TestTempSubscriptionStoreAndAccessStripManagedMarkerWithoutMutatingInput(t *testing.T) {
	original := map[string]any{
		"name": "managed-ss", "type": "ss", "cipher": "aes-128-gcm",
		storage.ManagedShadowsocksMultiUserMarker: true,
	}
	store := &TempSubscriptionStore{subscriptions: make(map[string]*TempSubscription)}
	sub := store.Create([]any{original}, 1, 60)
	stored := sub.Proxies[0].(map[string]any)
	if _, exists := stored[storage.ManagedShadowsocksMultiUserMarker]; exists {
		t.Fatal("temporary subscription store retained internal marker")
	}
	if original[storage.ManagedShadowsocksMultiUserMarker] != true {
		t.Fatal("temporary subscription creation mutated caller map")
	}

	id := "feedcafe"
	legacyProxy := map[string]any{
		"name": "managed-ss", "type": "ss", "cipher": "aes-128-gcm",
		storage.ManagedShadowsocksMultiUserMarker: true,
	}
	tempSubStore.mu.Lock()
	tempSubStore.subscriptions[id] = &TempSubscription{
		ID: id, Proxies: []any{legacyProxy}, MaxAccess: 1,
		ExpireAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}
	tempSubStore.mu.Unlock()
	t.Cleanup(func() {
		tempSubStore.mu.Lock()
		delete(tempSubStore.subscriptions, id)
		tempSubStore.mu.Unlock()
	})

	req := httptest.NewRequest(http.MethodGet, "/t/"+id, nil)
	req.Header.Set("User-Agent", "Mihomo")
	recorder := httptest.NewRecorder()
	(&TempSubscriptionAccessHandler{}).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("temporary subscription response=%d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), storage.ManagedShadowsocksMultiUserMarker) {
		t.Fatalf("temporary subscription exposed internal marker: %s", recorder.Body.String())
	}
	if legacyProxy[storage.ManagedShadowsocksMultiUserMarker] != true {
		t.Fatal("temporary subscription response mutated stored proxy")
	}
}
