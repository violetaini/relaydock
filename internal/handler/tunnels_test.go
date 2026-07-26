package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTunnelsHandlerListsTunnelAliasesAndHidesManagedResources(t *testing.T) {
	xrayConfig := `{
		"inbounds": [
			{"tag":"legacy-forward","protocol":"tunnel","port":2033,"settings":{"address":"198.51.100.10","port":2033,"network":"tcp,udp"}},
			{"tag":"canonical-forward","protocol":"dokodemo-door","port":3044,"settings":{"address":"198.51.100.20","port":3044,"network":"tcp,udp"}},
			{"tag":"rd-tun-0123456789abcdef","protocol":"dokodemo-door","port":39000,"settings":{"address":"198.51.100.30","port":443,"network":"tcp"}},
			{"tag":"tunnel-in","protocol":"tunnel","port":443,"settings":{"address":"127.0.0.1","port":443,"network":"tcp"}},
			{"tag":"api","protocol":"dokodemo-door","port":10085,"settings":{"address":"127.0.0.1","network":"tcp"}},
			{"tag":"ordinary-node","protocol":"vless","port":8443,"settings":{"clients":[]}}
		],
		"outbounds": [],
		"routing": {"rules": []}
	}`
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/child/xray/config" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "config": xrayConfig})
	}))
	defer agent.Close()

	repo := newTunnelChainTestRepo(t)
	createTunnelChainRemoteServer(t, repo, "tunnel-list-edge", agent.URL)
	handler := NewTunnelsHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/admin/tunnels", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Tunnels []tunnelInfo `json:"tunnels"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Tunnels) != 2 {
		t.Fatalf("tunnels=%#v, want exactly the two legacy resources", body.Tunnels)
	}
	byTag := make(map[string]tunnelInfo, len(body.Tunnels))
	for _, tunnel := range body.Tunnels {
		byTag[tunnel.Tag] = tunnel
	}
	for tag, port := range map[string]int{"legacy-forward": 2033, "canonical-forward": 3044} {
		tunnel, ok := byTag[tag]
		if !ok {
			t.Fatalf("missing tunnel %q in %#v", tag, body.Tunnels)
		}
		if tunnel.ListenPort != port || tunnel.TargetPort != port || tunnel.Network != "tcp,udp" {
			t.Fatalf("tunnel %q=%#v", tag, tunnel)
		}
	}
	if _, exists := byTag["rd-tun-0123456789abcdef"]; exists {
		t.Fatal("managed guard resource leaked into legacy tunnel list")
	}
}

func TestIsTunnelProtocol(t *testing.T) {
	for _, protocol := range []string{"tunnel", " TUNNEL ", "dokodemo-door", " DOKODEMO-DOOR "} {
		if !isTunnelProtocol(protocol) {
			t.Errorf("isTunnelProtocol(%q)=false", protocol)
		}
	}
	for _, protocol := range []string{"", "vless", "dokodemo"} {
		if isTunnelProtocol(protocol) {
			t.Errorf("isTunnelProtocol(%q)=true", protocol)
		}
	}
}

func TestGroupTunnelChainsSplitsDisconnectedUniqueLegacyHops(t *testing.T) {
	tunnels := []tunnelInfo{
		{
			Kind: "inbound", ServerID: 1, Tag: "tunnel-stale-h0", ListenPort: 2033,
			TargetAddress: "missing-next.example", TargetPort: 2033, ServerHosts: []string{"edge-one.example"},
		},
		{
			Kind: "inbound", ServerID: 2, Tag: "tunnel-stale-h1", ListenPort: 2033,
			TargetAddress: "final.example", TargetPort: 443, ServerHosts: []string{"edge-two.example"},
		},
	}

	chains, flat := groupTunnelChains(tunnels)
	if len(flat) != 0 || len(chains) != 2 {
		t.Fatalf("chains=%#v flat=%#v, want two isolated chains", chains, flat)
	}
	seen := map[int64]bool{}
	for _, chain := range chains {
		if len(chain.Hops) != 1 {
			t.Fatalf("disconnected hops were merged: %#v", chain)
		}
		seen[chain.Hops[0].ServerID] = true
	}
	if !seen[1] || !seen[2] {
		t.Fatalf("missing isolated hops: %#v", chains)
	}
}
