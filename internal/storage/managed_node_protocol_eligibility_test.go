package storage

import "testing"

func TestSelfServiceProtocolEligible(t *testing.T) {
	tests := []struct {
		name        string
		protocol    string
		clashConfig string
		want        bool
	}{
		{
			name:        "SS2022 AES 128 via ss alias",
			protocol:    "ss",
			clashConfig: `{"cipher":"2022-blake3-aes-128-gcm"}`,
			want:        true,
		},
		{
			name:        "SS2022 AES 256 via shadowsocks alias",
			protocol:    " Shadowsocks ",
			clashConfig: `{"cipher":" 2022-BLAKE3-AES-256-GCM "}`,
			want:        true,
		},
		{
			name:        "SS2022 AES 256 via method field",
			protocol:    "shadowsocks",
			clashConfig: `{"method":"2022-blake3-aes-256-gcm"}`,
			want:        true,
		},
		{
			name:        "SS2022 chacha rejected",
			protocol:    "shadowsocks",
			clashConfig: `{"cipher":"2022-blake3-chacha20-poly1305"}`,
			want:        false,
		},
		{
			name:        "classic Shadowsocks AES 256 shared password rejected",
			protocol:    "shadowsocks",
			clashConfig: `{"cipher":"aes-256-gcm"}`,
			want:        false,
		},
		{
			name:        "classic Shadowsocks AES 128 managed users allowed",
			protocol:    "ss",
			clashConfig: `{"method":" AES-128-GCM ","x-arcway-managed-users":true}`,
			want:        true,
		},
		{
			name:        "classic Shadowsocks AES 256 managed users allowed",
			protocol:    "shadowsocks",
			clashConfig: `{"cipher":"aes-256-gcm","x-arcway-managed-users":true}`,
			want:        true,
		},
		{
			name:        "classic Shadowsocks marker must be boolean",
			protocol:    "shadowsocks",
			clashConfig: `{"cipher":"aes-128-gcm","x-arcway-managed-users":"true"}`,
			want:        false,
		},
		{
			name:        "legacy Shadowsocks chacha rejected",
			protocol:    "ss",
			clashConfig: `{"cipher":"chacha20-ietf-poly1305"}`,
			want:        false,
		},
		{
			name:        "Shadowsocks malformed config rejected",
			protocol:    "ss",
			clashConfig: `{`,
			want:        false,
		},
		{
			name:        "Shadowsocks missing cipher rejected",
			protocol:    "ss",
			clashConfig: `{}`,
			want:        false,
		},
		{name: "Hysteria2 alias allowed", protocol: " HYSTERIA2 ", want: true},
		{name: "VLESS allowed", protocol: "vless", want: true},
		{name: "AnyTLS rejected", protocol: "anytls", clashConfig: `{"type":"anytls","tls":true}`, want: false},
		{name: "TUIC rejected", protocol: "tuic", clashConfig: `{"type":"tuic"}`, want: false},
		{name: "WireGuard rejected", protocol: "wireguard", want: false},
		{name: "empty protocol rejected", protocol: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selfServiceProtocolEligible(tt.protocol, tt.clashConfig); got != tt.want {
				t.Fatalf("selfServiceProtocolEligible(%q, %q) = %v, want %v", tt.protocol, tt.clashConfig, got, tt.want)
			}
		})
	}
}
