package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestRoutedShadowsocksCredentialUsesNodeCipher(t *testing.T) {
	tests := []struct {
		name      string
		cipher    string
		keyLength int
		classic   bool
	}{
		{name: "classic", cipher: "aes-256-gcm", keyLength: 16, classic: true},
		{name: "2022", cipher: "2022-blake3-aes-256-gcm", keyLength: 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := storage.Node{Protocol: "shadowsocks", ClashConfig: `{"type":"ss","cipher":"` + tt.cipher + `"}`}
			method := routedShadowsocksMethod(node)
			credential, _, err := generateRoutedClientCred(node.Protocol, method, "alice__route")
			if err != nil {
				t.Fatalf("generate routed credential: %v", err)
			}
			password, _ := credential["password"].(string)
			decoded, err := base64.StdEncoding.DecodeString(password)
			if err != nil || len(decoded) != tt.keyLength {
				t.Fatalf("password decoded length = %d, err=%v", len(decoded), err)
			}
			_, hasMethod := credential["method"]
			if hasMethod != tt.classic {
				t.Fatalf("credential method presence = %v, want %v: %#v", hasMethod, tt.classic, credential)
			}
			if tt.classic && credential["method"] != tt.cipher {
				t.Fatalf("credential method = %#v, want %q", credential["method"], tt.cipher)
			}
		})
	}
}

func TestReconcileRoutedShadowsocksLiveMethod(t *testing.T) {
	for _, tt := range []struct {
		name           string
		protocol       string
		expectedMethod string
		liveMethod     string
		wantError      bool
	}{
		{name: "matching classic", protocol: "shadowsocks", expectedMethod: "aes-128-gcm", liveMethod: "AES-128-GCM"},
		{name: "mismatched classic", protocol: "ss", expectedMethod: "aes-128-gcm", liveMethod: "aes-256-gcm", wantError: true},
		{name: "missing classic method", protocol: "shadowsocks", expectedMethod: "aes-256-gcm", wantError: true},
		{name: "2022 uses top-level method", protocol: "shadowsocks", expectedMethod: "2022-blake3-aes-256-gcm"},
		{name: "unrelated protocol", protocol: "vless", expectedMethod: "aes-128-gcm"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			credential := map[string]interface{}{"password": "existing-password"}
			err := reconcileRoutedShadowsocksLiveMethod(tt.protocol, tt.expectedMethod, tt.liveMethod, credential)
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, wantError=%v", err, tt.wantError)
			}
			if !tt.wantError && isClassicManagedShadowsocksCipher(tt.expectedMethod) && canonicalManagedProtocol(tt.protocol) == "shadowsocks" {
				if credential["method"] != strings.ToLower(tt.expectedMethod) {
					t.Fatalf("credential method = %#v, want %q", credential["method"], strings.ToLower(tt.expectedMethod))
				}
			}
		})
	}
}

func TestReconcileRoutedClassicCredentialUsesMatchingLiveClient(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/child/inbounds" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"inbounds": []any{map[string]any{
				"tag": "classic-in",
				"settings": map[string]any{"clients": []any{map[string]any{
					"email": "alice__route", "password": "live-password", "method": "aes-128-gcm",
				}}},
			}},
		})
	}))
	t.Cleanup(agent.Close)

	repo := newRemoteHandlerTestRepo(t)
	server := createRemoteHandlerTestServer(t, repo, "classic-route-edge", agent.URL)
	rm := NewRemoteManageHandler(repo, nil)

	credential, credentialJSON, changed, missing, err := reconcileRoutedClassicCredential(
		context.Background(), rm, server.ID, "classic-in", "shadowsocks", "aes-128-gcm", "alice__route",
		map[string]interface{}{"password": "live-password", "email": "alice__route"},
	)
	if err != nil {
		t.Fatalf("reconcile matching client: %v", err)
	}
	if !changed || missing || credential["method"] != "aes-128-gcm" || credential["password"] != "live-password" {
		t.Fatalf("reconciled credential = %#v, changed=%v, missing=%v", credential, changed, missing)
	}
	if !strings.Contains(credentialJSON, `"method":"aes-128-gcm"`) {
		t.Fatalf("credential JSON = %s", credentialJSON)
	}

	_, _, _, _, err = reconcileRoutedClassicCredential(
		context.Background(), rm, server.ID, "classic-in", "shadowsocks", "aes-128-gcm", "alice__route",
		map[string]interface{}{"password": "different-password", "email": "alice__route"},
	)
	if err == nil {
		t.Fatal("mismatched stored password was relabeled from the live client")
	}

	_, _, _, _, err = reconcileRoutedClassicCredential(
		context.Background(), rm, server.ID, "classic-in", "shadowsocks", "aes-256-gcm", "alice__route",
		map[string]interface{}{"password": "live-password", "email": "alice__route"},
	)
	if err == nil {
		t.Fatal("mismatched live cipher was accepted")
	}
}

func TestCloneClashWithCredentialUsesShadowsocksCipherSemantics(t *testing.T) {
	tests := []struct {
		name       string
		parent     string
		credential map[string]interface{}
		want       string
	}{
		{
			name:       "classic uses per-client password",
			parent:     `{"name":"parent","type":"ss","cipher":"aes-128-gcm","password":"owner-password"}`,
			credential: map[string]interface{}{"method": "aes-128-gcm", "password": "user-password"},
			want:       "user-password",
		},
		{
			name:       "2022 combines master and user keys",
			parent:     `{"name":"parent","type":"ss","cipher":"2022-blake3-aes-128-gcm","password":"master:first-user"}`,
			credential: map[string]interface{}{"password": "second-user"},
			want:       "master:second-user",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var proxy map[string]interface{}
			if err := json.Unmarshal([]byte(cloneClashWithCredential(tt.parent, "shadowsocks", tt.credential, "routed")), &proxy); err != nil {
				t.Fatalf("parse clone: %v", err)
			}
			if proxy["password"] != tt.want {
				t.Fatalf("password = %#v, want %q", proxy["password"], tt.want)
			}
		})
	}
}

func TestClassicShadowsocksManagedSettings(t *testing.T) {
	managed := map[string]interface{}{
		"clients": []interface{}{map[string]interface{}{
			"method": "aes-128-gcm", "password": "owner-password", "email": "admin",
		}},
	}
	if got := shadowsocksInboundMethod(managed); got != "aes-128-gcm" {
		t.Fatalf("method = %q, want aes-128-gcm", got)
	}
	if err := validateClassicShadowsocksManagedSettings("shadowsocks", managed); err != nil {
		t.Fatalf("managed classic settings rejected: %v", err)
	}

	shared := map[string]interface{}{"method": "aes-256-gcm", "password": "shared-password"}
	if err := validateClassicShadowsocksManagedSettings("shadowsocks", shared); err == nil {
		t.Fatal("shared-password classic settings were accepted for managed access")
	}
}

func TestClassicShadowsocksCredentialAndSubscriptionOverride(t *testing.T) {
	credential, _, err := generateCredential("shadowsocks", storage.User{Username: "alice"}, "aes-256-gcm", "ss-in")
	if err != nil {
		t.Fatalf("generateCredential: %v", err)
	}
	if credential["method"] != "aes-256-gcm" {
		t.Fatalf("credential method = %#v", credential["method"])
	}
	password, _ := credential["password"].(string)
	if password == "" {
		t.Fatal("credential password is empty")
	}

	proxy := map[string]any{"type": "ss", "cipher": "aes-256-gcm", "password": "owner-password"}
	proxy[storage.ManagedShadowsocksMultiUserMarker] = true
	if !applyCredToProxy(proxy, "shadowsocks", credential) {
		t.Fatal("classic Shadowsocks credential was not applied")
	}
	if proxy["password"] != password {
		t.Fatalf("proxy password = %#v, want per-user password", proxy["password"])
	}
	if _, exists := proxy[storage.ManagedShadowsocksMultiUserMarker]; exists {
		t.Fatalf("internal marker leaked into subscription proxy: %#v", proxy)
	}

	mismatched := map[string]any{"type": "ss", "cipher": "aes-128-gcm", "password": "owner-password"}
	if applyCredToProxy(mismatched, "shadowsocks", credential) {
		t.Fatal("credential with a different classic cipher was applied")
	}
	missingMethod := map[string]any{"password": password}
	if applyCredToProxy(map[string]any{"type": "ss", "cipher": "aes-256-gcm", "password": "owner-password"}, "shadowsocks", missingMethod) {
		t.Fatal("classic credential without a proven method was applied")
	}
}

func TestClassicShadowsocksStoredCredentialGainsMethod(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{Name: "classic-method", Token: "token", IPAddress: "203.0.113.10", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatalf("create server: %v", err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: "ss-in", Protocol: "shadowsocks",
		CredentialJSON: `{"password":"old-password","email":"alice__ss-in","level":0}`,
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	user, _ := repo.GetUser(ctx, "alice")
	settings := map[string]interface{}{"clients": []interface{}{map[string]interface{}{
		"method": "aes-128-gcm", "password": "owner-password", "email": "admin",
	}, map[string]interface{}{
		"method": "aes-128-gcm", "password": "old-password", "email": "alice__ss-in", "level": float64(0),
	}}}
	credential, raw, reused, err := getOrCreateInboundCredential(ctx, repo, user, server.ID, "ss-in", "shadowsocks", settings)
	if err != nil || !reused {
		t.Fatalf("reconcile stored credential: reused=%v err=%v", reused, err)
	}
	if credential["method"] != "aes-128-gcm" {
		t.Fatalf("credential = %#v", credential)
	}
	var persisted map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil || persisted["method"] != "aes-128-gcm" {
		t.Fatalf("persisted credential = %#v, err=%v", persisted, err)
	}
}

func TestClassicShadowsocksStoredCredentialMethodMustMatchLiveClient(t *testing.T) {
	credential := map[string]interface{}{
		"password": "old-password",
		"email":    "alice__ss-in",
	}
	settings := map[string]interface{}{"clients": []interface{}{map[string]interface{}{
		"method": "aes-256-gcm", "password": "different-password", "email": "alice__ss-in",
	}}}
	if changed, err := reconcileClassicShadowsocksCredentialMethod(credential, settings); err == nil || changed {
		t.Fatalf("unverified credential reconciliation = changed %v, err %v", changed, err)
	}
	if _, exists := credential["method"]; exists {
		t.Fatalf("unverified credential was mutated: %#v", credential)
	}

	credential["method"] = "aes-128-gcm"
	if changed, err := reconcileClassicShadowsocksCredentialMethod(credential, settings); err == nil || changed {
		t.Fatalf("mismatched credential reconciliation = changed %v, err %v", changed, err)
	}
}

func TestInboundToClashProxyMapsClassicShadowsocksClient(t *testing.T) {
	inbound := map[string]interface{}{
		"tag": "ss-classic", "protocol": "shadowsocks", "port": float64(8388),
		"settings": map[string]interface{}{
			"network": "tcp,udp",
			"clients": []interface{}{
				map[string]interface{}{"method": "aes-128-gcm", "password": "owner-password", "email": "admin"},
				map[string]interface{}{"method": "aes-128-gcm", "password": "alice-password", "email": "alice__ss-classic"},
			},
		},
	}
	proxy, err := (&RemoteManageHandler{}).inboundToClashProxy(inbound, "203.0.113.10", "edge", 0, "alice__ss-classic")
	if err != nil {
		t.Fatalf("inboundToClashProxy: %v", err)
	}
	if proxy["cipher"] != "aes-128-gcm" || proxy["password"] != "alice-password" {
		t.Fatalf("classic proxy = %#v", proxy)
	}
	if proxy[storage.ManagedShadowsocksMultiUserMarker] != true {
		t.Fatalf("classic proxy is missing managed-users marker: %#v", proxy)
	}
}
