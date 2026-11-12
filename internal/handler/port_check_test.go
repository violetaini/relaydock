package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestPortCheckAdminUserAndForwardingFlows(t *testing.T) {
	ctx := context.Background()
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	createManagedSecurityTestUser(t, repo, "bob", storage.RoleUser)

	agent1Calls := 0
	agent1Mux := http.NewServeMux()
	agent1Mux.HandleFunc("/api/child/ports/check", func(w http.ResponseWriter, r *http.Request) {
		agent1Calls++
		port, _ := strconv.Atoi(r.URL.Query().Get("port"))
		w.Header().Set("Content-Type", "application/json")
		if port == 30222 {
			_ = json.NewEncoder(w).Encode(PortCheckResult{
				Success:    true,
				Port:       port,
				Available:  false,
				OccupiedBy: "system_listener",
				Network:    "tcp",
				Reason:     "端口 30222 已被本机 TCP 进程占用 (0.0.0.0:30222)",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(PortCheckResult{
			Success:   true,
			Port:      port,
			Available: true,
			Network:   r.URL.Query().Get("network"),
		})
	})
	agent1HTTP := httptest.NewServer(agent1Mux)
	t.Cleanup(agent1HTTP.Close)

	agent2Mux := http.NewServeMux()
	agent2Mux.HandleFunc("/api/child/ports/check", func(w http.ResponseWriter, r *http.Request) {
		port, _ := strconv.Atoi(r.URL.Query().Get("port"))
		w.Header().Set("Content-Type", "application/json")
		if port == 24002 {
			_ = json.NewEncoder(w).Encode(PortCheckResult{
				Success:    true,
				Port:       port,
				Available:  false,
				OccupiedBy: "xray_inbound",
				Network:    "udp",
				Tag:        "wg-existing",
				Protocol:   "wireguard",
				Reason:     "端口 24002 已被 Xray 入站 wg-existing (wireguard) 占用",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(PortCheckResult{
			Success:   true,
			Port:      port,
			Available: true,
			Network:   r.URL.Query().Get("network"),
		})
	})
	agent2HTTP := httptest.NewServer(agent2Mux)
	t.Cleanup(agent2HTTP.Close)

	srv1 := &storage.RemoteServer{
		Name:           "edge-1",
		Token:          "tok-1",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModePush,
		IPAddress:      "127.0.0.1",
		ListenPort:     remoteAgentTestPort(t, agent1HTTP.URL),
		XrayMode:       "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, srv1); err != nil {
		t.Fatalf("CreateRemoteServer srv1: %v", err)
	}
	_, _ = repo.UpdateRemoteServerXrayStatus(ctx, srv1.ID, true, "test")

	srv2 := &storage.RemoteServer{
		Name:           "edge-2",
		Token:          "tok-2",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModePush,
		IPAddress:      "127.0.0.1",
		ListenPort:     remoteAgentTestPort(t, agent2HTTP.URL),
		XrayMode:       "embedded",
	}
	if err := repo.CreateRemoteServer(ctx, srv2); err != nil {
		t.Fatalf("CreateRemoteServer srv2: %v", err)
	}
	_, _ = repo.UpdateRemoteServerXrayStatus(ctx, srv2.ID, true, "test")

	// Seed desired inbound on srv1 (TCP 24443).
	if _, err := repo.UpsertActiveDesiredInbound(ctx, srv1.ID, "vless-desired", "mut-1", json.RawMessage(`{"tag":"vless-desired","port":24443,"protocol":"vless","settings":{}}`)); err != nil {
		t.Fatalf("UpsertActiveDesiredInbound: %v", err)
	}

	// Seed active user grant on srv1 for alice.
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username:        "alice",
		ServerID:        srv1.ID,
		Enabled:         true,
		StartsAt:        now.Add(-time.Hour),
		ExpiresAt:       &exp,
		MaxActiveNodes:  2,
		BillingMode:     storage.ManagedBillingDownload,
		ResetPolicy:     storage.ManagedResetNone,
		ResetDay:        1,
		BillingTimezone: "Asia/Shanghai",
		CreatedBy:       "admin",
	}); err != nil {
		t.Fatalf("CreateUserServerGrant: %v", err)
	}

	ws := NewRemoteWSHandler(repo, nil)
	remote := NewRemoteManageHandler(repo, ws)
	remote.httpClient = agent1HTTP.Client()
	managed := NewManagedNodesHandler(repo, remote, nil)
	forwarding := NewForwardingHandler(repo, newFakeForwardTunnelDeployer())
	forwarding.SetRemoteManage(remote)

	// 1. WSS 443 short-circuits cleanly without hitting agent as busy 443.
	beforeCalls := agent1Calls
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/admin/remote/port-check?server_id=%d&port=443&protocol=vless-wss", srv1.ID), nil)
	rec := httptest.NewRecorder()
	remote.HandleRemotePortCheck(rec, req)
	var out PortCheckResult
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || !out.Available || out.OccupiedBy != "shared_nginx" || agent1Calls != beforeCalls {
		t.Fatalf("expected WSS 443 shared_nginx pass without agent call, got code=%d out=%+v calls=%d/%d", rec.Code, out, agent1Calls, beforeCalls)
	}

	// 2. desired_inbound TCP blocks vless 24443, allows ignore_tag=vless-desired, allows udp-only wireguard 24443.
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/admin/remote/port-check?server_id=%d&port=24443&protocol=vless", srv1.ID), nil)
	rec = httptest.NewRecorder()
	remote.HandleRemotePortCheck(rec, req)
	out = PortCheckResult{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Available || out.OccupiedBy != "desired_inbound" || out.Tag != "vless-desired" {
		t.Fatalf("expected desired_inbound conflict on 24443 tcp, got code=%d out=%+v", rec.Code, out)
	}

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/admin/remote/port-check?server_id=%d&port=24443&protocol=vless&ignore_tag=vless-desired", srv1.ID), nil)
	rec = httptest.NewRecorder()
	remote.HandleRemotePortCheck(rec, req)
	out = PortCheckResult{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || !out.Available {
		t.Fatalf("expected ignore_tag to pass, got code=%d out=%+v", rec.Code, out)
	}

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/admin/remote/port-check?server_id=%d&port=24443&protocol=wireguard", srv1.ID), nil)
	rec = httptest.NewRecorder()
	remote.HandleRemotePortCheck(rec, req)
	out = PortCheckResult{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || !out.Available {
		t.Fatalf("expected wireguard UDP 24443 not to collide with TCP desired inbound, got code=%d out=%+v", rec.Code, out)
	}

	// 3. Agent OS listener conflict passthrough (30222) and user grant authorization/redaction.
	aliceReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/user/managed-node-creation/port-check?server_id=%d&port=30222&protocol=vless", srv1.ID), nil)
	aliceReq = aliceReq.WithContext(auth.ContextWithUsername(aliceReq.Context(), "alice"))
	rec = httptest.NewRecorder()
	managed.HandleUserManagedNodeCreationPortCheck(rec, aliceReq)
	out = PortCheckResult{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Available || out.OccupiedBy != "system_listener" || out.Tag != "" {
		t.Fatalf("expected user port check system_listener conflict on 30222, got code=%d out=%+v", rec.Code, out)
	}

	bobReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/user/managed-node-creation/port-check?server_id=%d&port=25555&protocol=vless", srv1.ID), nil)
	bobReq = bobReq.WithContext(auth.ContextWithUsername(bobReq.Context(), "bob"))
	rec = httptest.NewRecorder()
	managed.HandleUserManagedNodeCreationPortCheck(rec, bobReq)
	if rec.Code == http.StatusOK {
		t.Fatalf("expected ungranted user bob to be rejected, got 200")
	}

	// 4. Multi-hop forwarding port check + preflight rejection when hop 2 conflicts.
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "admin", NodeName: "Managed Exit", Protocol: "vless", Enabled: true,
		OriginalServer: srv2.Name, InboundTag: "wg-existing",
		ClashConfig: `{"name":"Managed Exit","type":"vless","server":"127.0.0.1","port":443,"uuid":"u"}`,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, srv2.ID, "admin")
	if err != nil {
		t.Fatalf("CreateSelfServiceNodeOffer: %v", err)
	}
	if _, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{
		Username: "alice", ServerID: srv2.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &exp, MaxActiveNodes: 2,
		BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone,
		ResetDay: 1, BillingTimezone: "Asia/Shanghai", CreatedBy: "admin",
	}); err != nil {
		t.Fatalf("CreateUserServerGrant srv2: %v", err)
	}
	activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
	if err != nil {
		t.Fatalf("ActivateUserNodeSelection: %v", err)
	}
	_, _ = repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID, activation.Source.Generation, storage.ManagedObservedActive, now)
	_ = repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{Username: "alice", ServerID: srv2.ID, InboundTag: node.InboundTag, Protocol: "vless", CredentialJSON: `{"id":"alice-2"}`})
	cred, _ := repo.GetUserInboundConfig(ctx, "alice", srv2.ID, node.InboundTag)
	_ = repo.SetUserNodeSelectionCredential(ctx, activation.Selection.ID, cred.ID)

	tunnel, err := repo.CreateTunnelTemplate(ctx, storage.TunnelTemplate{
		Name: "multi-hop", State: storage.TunnelStateActive,
		BillingMode: storage.ManagedBillingDownload, TrafficMultiplierMilli: 1000,
		PortRangeStart: 20000, PortRangeEnd: 30000, CreatedBy: "admin",
		Hops: []storage.TunnelTemplateHop{{ServerID: srv1.ID}, {ServerID: srv2.ID}},
	})
	if err != nil {
		t.Fatalf("CreateTunnelTemplate: %v", err)
	}
	bm := storage.ManagedBillingDownload
	grant, err := repo.CreateUserTunnelGrant(ctx, storage.UserTunnelGrant{
		Username: "alice", TunnelID: tunnel.ID, Enabled: true,
		StartsAt: now.Add(-time.Hour), ExpiresAt: &exp, MaxActiveForwards: 4,
		BillingModeOverride: &bm, AllowManagedTarget: true, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateUserTunnelGrant: %v", err)
	}

	// Out of template range
	fwdReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/user/forwards/port-check?grant_id=%s&port=2033", grant.PublicID), nil)
	fwdReq = fwdReq.WithContext(auth.ContextWithUsername(fwdReq.Context(), "alice"))
	rec = httptest.NewRecorder()
	forwarding.HandleUserForwardPortCheck(rec, fwdReq)
	out = PortCheckResult{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Available || out.OccupiedBy != "tunnel_range" {
		t.Fatalf("expected tunnel_range failure for 2033, got code=%d out=%+v", rec.Code, out)
	}

	// Hop 2 UDP conflict on 24002
	fwdReq = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/user/forwards/port-check?grant_id=%s&port=24002", grant.PublicID), nil)
	fwdReq = fwdReq.WithContext(auth.ContextWithUsername(fwdReq.Context(), "alice"))
	rec = httptest.NewRecorder()
	forwarding.HandleUserForwardPortCheck(rec, fwdReq)
	out = PortCheckResult{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Available || out.OccupiedBy != "xray_inbound" || out.ServerID != srv2.ID {
		t.Fatalf("expected hop 2 xray_inbound conflict on 24002, got code=%d out=%+v", rec.Code, out)
	}

	// Preflight also rejects requested_entry_port=24002 with 409 Conflict
	preflightBody := []byte(fmt.Sprintf(`{"grant_id":%q,"name":"conflict-test","requested_entry_port":24002,"target":{"type":"managed_node","node_id":%d}}`, grant.PublicID, node.ID))
	preReq := httptest.NewRequest(http.MethodPost, "/api/user/forwards/preflight", bytes.NewReader(preflightBody))
	preReq = preReq.WithContext(auth.ContextWithUsername(preReq.Context(), "alice"))
	rec = httptest.NewRecorder()
	forwarding.HandleUserForwardPreflight(rec, preReq)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict from preflight on occupied port 24002, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Free port 25000 succeeds across both hops
	fwdReq = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/user/forwards/port-check?grant_id=%s&port=25000", grant.PublicID), nil)
	fwdReq = fwdReq.WithContext(auth.ContextWithUsername(fwdReq.Context(), "alice"))
	rec = httptest.NewRecorder()
	forwarding.HandleUserForwardPortCheck(rec, fwdReq)
	out = PortCheckResult{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || !out.Available {
		t.Fatalf("expected 25000 available across hops, got code=%d out=%+v", rec.Code, out)
	}
}
