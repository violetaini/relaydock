package storage

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestNormalizeManagedGrantAllowedProtocolProfiles(t *testing.T) {
	got, err := NormalizeManagedGrantAllowedProtocolProfiles([]string{
		" VLESS-REALITY ", "shadowsocks-classic", "shadowsocks-2022", "vless-reality", "HYSTERIA2", "ANYTLS",
	})
	if err != nil {
		t.Fatalf("NormalizeManagedGrantAllowedProtocolProfiles: %v", err)
	}
	want := []string{"vless-reality", "shadowsocks-classic", "shadowsocks-2022", "hysteria2", "anytls"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized profiles = %#v, want %#v", got, want)
	}
	for _, profile := range []string{"", "ss-legacy", "vless-quic", "wireguard"} {
		if _, err := NormalizeManagedGrantAllowedProtocolProfiles([]string{profile}); !errors.Is(err, ErrManagedInvalidArgument) {
			t.Fatalf("profile %q error = %v, want %v", profile, err, ErrManagedInvalidArgument)
		}
	}
}

func TestManagedGrantProtocolProfileFamiliesMustMatch(t *testing.T) {
	valid := UserServerGrant{
		Username: "alice", ServerID: 1, Enabled: true, StartsAt: time.Now().UTC(),
		BillingMode: ManagedBillingDownload, ResetPolicy: ManagedResetNone, ResetDay: 1,
		BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
	}
	tests := []struct {
		name      string
		protocols []string
		profiles  []string
		wantErr   bool
	}{
		{name: "legacy family whitelist", protocols: []string{"vless"}},
		{name: "matching exact profiles", protocols: []string{"SS", "vless"}, profiles: []string{"vless-wss", "shadowsocks-2022"}},
		{name: "matching classic shadowsocks profile", protocols: []string{"shadowsocks"}, profiles: []string{"shadowsocks-classic"}},
		{name: "profiles require families", profiles: []string{"shadowsocks-2022"}, wantErr: true},
		{name: "profile family omitted", protocols: []string{"vless"}, profiles: []string{"vless-wss", "shadowsocks-2022"}, wantErr: true},
		{name: "unused family", protocols: []string{"vless", "vmess"}, profiles: []string{"vless-wss"}, wantErr: true},
		{name: "different family", protocols: []string{"vmess"}, profiles: []string{"vless-wss"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grant := valid
			grant.AllowedProtocols = tt.protocols
			grant.AllowedProtocolProfiles = tt.profiles
			normalized, err := normalizeGrant(grant)
			if tt.wantErr {
				if !errors.Is(err, ErrManagedInvalidArgument) {
					t.Fatalf("normalizeGrant error = %v, want %v", err, ErrManagedInvalidArgument)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeGrant: %v", err)
			}
			if tt.name == "matching exact profiles" && !normalized.AllowsNodeProtocol("shadowsocks", `{"type":"ss","cipher":"2022-blake3-aes-128-gcm"}`) {
				t.Fatal("normalized Shadowsocks 2022 profile was not allowed")
			}
			if tt.name == "matching classic shadowsocks profile" && !normalized.AllowsNodeProtocol("shadowsocks", `{"type":"ss","cipher":"aes-128-gcm"}`) {
				t.Fatal("normalized classic Shadowsocks profile was not allowed")
			}
		})
	}
}

func TestSelfServiceNodeProtocolProfile(t *testing.T) {
	tests := []struct {
		name, protocol, config, want string
		ok                           bool
	}{
		{name: "vless reality", protocol: "vless", config: `{"type":"vless","network":"tcp","reality-opts":{"public-key":"key"}}`, want: "vless-reality", ok: true},
		{name: "vless tcp tls", protocol: "vless", config: `{"type":"vless","tls":true}`, want: "vless-tcp-tls", ok: true},
		{name: "vless grpc tls", protocol: "vless", config: `{"type":"vless","network":"grpc","tls":true}`, want: "vless-grpc-tls", ok: true},
		{name: "vless wss", protocol: "vless", config: `{"type":"vless","network":"ws","tls":true}`, want: "vless-wss", ok: true},
		{name: "vless ws", protocol: "vless", config: `{"type":"vless","network":"ws"}`, want: "vless-ws", ok: true},
		{name: "vmess tcp", protocol: "vmess", config: `{"type":"vmess"}`, want: "vmess-tcp-none", ok: true},
		{name: "vmess tcp tls", protocol: "vmess", config: `{"type":"vmess","tls":true}`, want: "vmess-tcp-tls", ok: true},
		{name: "vmess grpc tls", protocol: "vmess", config: `{"type":"vmess","network":"grpc","tls":true}`, want: "vmess-grpc-tls", ok: true},
		{name: "vmess wss", protocol: "vmess", config: `{"type":"vmess","network":"ws","tls":true}`, want: "vmess-wss", ok: true},
		{name: "vmess ws", protocol: "vmess", config: `{"type":"vmess","network":"ws"}`, want: "vmess-ws", ok: true},
		{name: "trojan tcp tls", protocol: "trojan", config: `{"type":"trojan","tls":true}`, want: "trojan-tcp-tls", ok: true},
		{name: "trojan reality", protocol: "trojan", config: `{"type":"trojan","reality-opts":{}}`, want: "trojan-reality", ok: true},
		{name: "trojan grpc tls", protocol: "trojan", config: `{"type":"trojan","network":"grpc","tls":true}`, want: "trojan-grpc-tls", ok: true},
		{name: "trojan wss", protocol: "trojan", config: `{"type":"trojan","network":"ws","tls":true}`, want: "trojan-wss", ok: true},
		{name: "classic ss aes 128", protocol: "shadowsocks", config: `{"type":"ss","cipher":"aes-128-gcm"}`, want: "shadowsocks-classic", ok: true},
		{name: "classic ss aes 256", protocol: "ss", config: `{"type":"shadowsocks","cipher":"AES-256-GCM"}`, want: "shadowsocks-classic", ok: true},
		{name: "classic ss method", protocol: "shadowsocks", config: `{"type":"ss","method":"aes-128-gcm"}`, want: "shadowsocks-classic", ok: true},
		{name: "ss2022", protocol: "shadowsocks", config: `{"type":"ss","cipher":"2022-blake3-aes-256-gcm"}`, want: "shadowsocks-2022", ok: true},
		{name: "hysteria2", protocol: "hysteria", config: `{"type":"hysteria2"}`, want: "hysteria2", ok: true},
		{name: "socks5", protocol: "socks", config: `{"type":"socks"}`, want: "socks5", ok: true},
		{name: "http", protocol: "http", config: `{"type":"http"}`, want: "http", ok: true},
		{name: "anytls removed from self service", protocol: "anytls", config: `{"type":"anytls","tls":true}`},
		{name: "snell v4", protocol: "snell", config: `{"type":"snell","version":4}`, want: "snell", ok: true},
		{name: "malformed", protocol: "vless", config: `{"type":`},
		{name: "missing type", protocol: "vless", config: `{"network":"ws"}`},
		{name: "type family mismatch", protocol: "vless", config: `{"type":"vmess","network":"ws"}`},
		{name: "reality is not wss", protocol: "vless", config: `{"type":"vless","network":"ws","tls":true,"reality-opts":{}}`},
		{name: "vmess reality unsupported", protocol: "vmess", config: `{"type":"vmess","tls":true,"reality-opts":{}}`},
		{name: "anytls without tls", protocol: "anytls", config: `{"type":"anytls"}`},
		{name: "classic ss chacha unsupported", protocol: "shadowsocks", config: `{"type":"ss","cipher":"chacha20-ietf-poly1305"}`},
		{name: "ss2022 chacha unsupported", protocol: "shadowsocks", config: `{"type":"ss","cipher":"2022-blake3-chacha20-poly1305"}`},
		{name: "snell v6 isolated credentials unsupported", protocol: "snell", config: `{"type":"snell","version":6}`},
		{name: "invalid network field", protocol: "vless", config: `{"type":"vless","network":1,"tls":true}`},
		{name: "invalid reality options", protocol: "vless", config: `{"type":"vless","reality-opts":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := SelfServiceNodeProtocolProfile(tt.protocol, tt.config)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("profile = %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestManagedGrantProtocolProfileActivationAndNarrowing(t *testing.T) {
	repo, _ := newManagedNodesTestRepository(t)
	ctx, server, node, offer := seedManagedNodesTest(t, repo)
	node.ClashConfig = `{"type":"vless","network":"ws"}`
	if _, err := repo.UpdateNode(ctx, node); err != nil {
		t.Fatalf("set profile fixture: %v", err)
	}
	now := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	grant := createManagedGrantForTest(t, repo, ctx, server.ID, now)
	grant.AllowedProtocols = []string{"vless"}
	grant.AllowedProtocolProfiles = []string{"vless-wss"}
	grant, err := repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("restrict to WSS: %v", err)
	}
	catalog, err := repo.ListManagedNodeCatalog(ctx, "alice", now)
	if err != nil || len(catalog) != 1 {
		t.Fatalf("catalog = %+v, err=%v", catalog, err)
	}
	if catalog[0].ProtocolProfile != "vless-ws" || catalog[0].CanCreate || catalog[0].DenyReason != "protocol_not_allowed" {
		t.Fatalf("WS node escaped WSS-only grant: %+v", catalog[0])
	}
	if _, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now); !errors.Is(err, ErrManagedProtocolNotAllowed) {
		t.Fatalf("denied activation error = %v, want %v", err, ErrManagedProtocolNotAllowed)
	}

	grant.AllowedProtocolProfiles = []string{"vless-ws"}
	grant, err = repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin")
	if err != nil {
		t.Fatalf("allow WS: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("activate allowed WS: %v", err)
	}

	grant.AllowedProtocolProfiles = []string{"vless-wss"}
	if _, err := repo.UpdateUserServerGrant(ctx, *grant, grant.Version, "admin"); err != nil {
		t.Fatalf("narrow to WSS: %v", err)
	}
	selection, err := repo.GetUserNodeSelection(ctx, activation.Selection.ID)
	if err != nil {
		t.Fatalf("get narrowed selection: %v", err)
	}
	source, err := repo.GetUserInboundAccessSource(ctx, activation.Source.ID)
	if err != nil {
		t.Fatalf("get narrowed source: %v", err)
	}
	if selection.DesiredEnabled || source.DesiredState != ManagedDesiredInactive || source.SuspendReason != ManagedSuspendAdminDisabled {
		t.Fatalf("profile narrowing did not revoke selection=%+v source=%+v", selection, source)
	}
}
