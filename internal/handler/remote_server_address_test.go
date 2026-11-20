package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
		{
			name:       "updating domain synchronizes pull address when omitted",
			server:     storage.RemoteServer{Domain: "old.example", PullAddress: "old.example", IPAddress: "192.0.2.10"},
			request:    RemoteServerUpdateRequest{Domain: "unified.example", PullPort: 23889},
			wantOld:    "old.example",
			wantNew:    "unified.example",
			wantDomain: "unified.example",
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

func TestCreateRemoteServerAcceptsDomainForDDNS(t *testing.T) {
	t.Setenv("ARCWAY_PANEL_IPS", "203.0.113.10")
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	dp := &storage.DNSProvider{
		Name: "Test DNS", ProviderType: "cloudflare", Credentials: `{"CF_DNS_API_TOKEN":"token"}`,
	}
	if err := repo.CreateDNSProvider(context.Background(), dp); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(RemoteServerCreateRequest{
		Name: "Unified DDNS", Domain: "unified.example.com",
		DDNSEnabled: true, DDNSProviderID: dp.ID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/remote-servers/create", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).CreateRemoteServer(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	servers, err := repo.ListRemoteServers(context.Background())
	if err != nil || len(servers) != 1 {
		t.Fatalf("expected 1 server, got %v (err=%v)", len(servers), err)
	}
	if servers[0].Domain != "unified.example.com" || servers[0].PullAddress != "unified.example.com" {
		t.Fatalf("expected unified domain, got Domain=%q PullAddress=%q", servers[0].Domain, servers[0].PullAddress)
	}
	if !servers[0].DDNSEnabled || servers[0].DDNSProviderID != dp.ID {
		t.Fatalf("DDNS settings not saved: enabled=%v provider=%d", servers[0].DDNSEnabled, servers[0].DDNSProviderID)
	}
}
