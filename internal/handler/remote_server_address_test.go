package handler

import (
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestNormalizeRemoteServerAddressUpdateFollowsOnlyLinkedDomain(t *testing.T) {
	tests := []struct {
		name       string
		server     storage.RemoteServer
		request    RemoteServerUpdateRequest
		wantOld    string
		wantNew    string
		wantDomain string
	}{
		{
			name:       "linked domain follows pull address",
			server:     storage.RemoteServer{Domain: "old.example", PullAddress: "old.example", IPAddress: "192.0.2.10"},
			request:    RemoteServerUpdateRequest{Domain: "old.example", PullAddress: "new.example", PullPort: 23889},
			wantOld:    "old.example",
			wantNew:    "new.example",
			wantDomain: "new.example",
		},
		{
			name:       "custom domain remains independent",
			server:     storage.RemoteServer{Domain: "node.example", PullAddress: "old.example", IPAddress: "192.0.2.10"},
			request:    RemoteServerUpdateRequest{Domain: "node.example", PullAddress: "new.example", PullPort: 23889},
			wantOld:    "node.example",
			wantNew:    "node.example",
			wantDomain: "node.example",
		},
		{
			name:       "unlinked pull domain becomes effective endpoint",
			server:     storage.RemoteServer{IPAddress: "192.0.2.10"},
			request:    RemoteServerUpdateRequest{PullAddress: "new.example", PullPort: 23889},
			wantOld:    "192.0.2.10",
			wantNew:    "new.example",
			wantDomain: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldHost, newHost := normalizeRemoteServerAddressUpdate(&tc.server, &tc.request)
			if oldHost != tc.wantOld || newHost != tc.wantNew || tc.request.Domain != tc.wantDomain {
				t.Fatalf("got old=%q new=%q domain=%q, want old=%q new=%q domain=%q", oldHost, newHost, tc.request.Domain, tc.wantOld, tc.wantNew, tc.wantDomain)
			}
		})
	}
}

func TestChooseClashServerHostFallsBackToIPv6(t *testing.T) {
	server := &storage.RemoteServer{IPAddressV6: "2001:db8::10", IPv6Enabled: true}
	if got := chooseClashServerHost(server); got != "2001:db8::10" {
		t.Fatalf("chooseClashServerHost=%q, want IPv6 fallback", got)
	}
	server.IPv6Enabled = false
	if got := chooseClashServerHost(server); got != "" {
		t.Fatalf("chooseClashServerHost=%q with IPv6 disabled, want empty", got)
	}
}
