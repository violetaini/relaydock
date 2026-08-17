package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type privateRoutedRevokeAgent struct {
	mu                sync.Mutex
	failLimiter       int
	failRule          int
	failOutbound      int
	warnAddRule       int
	warnAddClient     int
	warnRemoveClient  int
	warnOutbound      int
	failAddAfterApply int
	limiters          int
	rules             int
	clients           int
	present           bool
	outbounds         map[string]bool
	events            []string
}

func (a *privateRoutedRevokeAgent) record(event string) {
	a.events = append(a.events, event)
}

func (a *privateRoutedRevokeAgent) resetEvents() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = nil
}

func (a *privateRoutedRevokeAgent) snapshotEvents() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.events...)
}

func privateRoutedEventIndex(events []string, want string) int {
	for i, event := range events {
		if event == want {
			return i
		}
	}
	return -1
}

func (a *privateRoutedRevokeAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/child/system/info":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"capabilities": map[string]any{
				"limiter_denied_v1": true,
			},
		})
	case "/api/child/limiter":
		var payload WSLimiterConfigPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		denied := false
		for _, user := range payload.Users {
			if user.Email == "alice__private" {
				denied = user.Denied
			}
		}
		a.mu.Lock()
		a.limiters++
		if denied {
			a.record("limiter:deny")
		} else {
			a.record("limiter:normal")
		}
		fail := a.failLimiter > 0
		if fail {
			a.failLimiter--
		}
		a.mu.Unlock()
		if fail {
			http.Error(w, "forced limiter failure", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "replaced": true})
	case "/api/child/routing":
		if r.Method == http.MethodGet {
			a.mu.Lock()
			present := a.present
			a.mu.Unlock()
			rules := []any{}
			if present {
				rules = append(rules, map[string]any{"marktag": "private-rule"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "routing": map[string]any{"rules": rules},
			})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		action, _ := body["action"].(string)
		a.mu.Lock()
		a.rules++
		a.record("rule:" + action)
		fail := a.failRule > 0
		if fail {
			a.failRule--
		}
		a.mu.Unlock()
		if fail {
			http.Error(w, "forced rule revoke failure", http.StatusBadGateway)
			return
		}
		a.mu.Lock()
		warning := ""
		switch action {
		case "add_rule":
			a.present = true
			if a.warnAddRule > 0 {
				a.warnAddRule--
				warning = "forced add rule runtime warning"
			}
		case "remove_rule":
			a.present = false
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true, "runtime_warning": warning})
	case "/api/child/outbounds":
		if r.Method == http.MethodGet {
			a.mu.Lock()
			outbounds := make([]map[string]any, 0, len(a.outbounds))
			for tag, present := range a.outbounds {
				if present {
					outbounds = append(outbounds, map[string]any{"tag": tag})
				}
			}
			a.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "outbounds": outbounds})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		action, _ := body["action"].(string)
		a.mu.Lock()
		a.record("outbound:" + action)
		fail := a.failOutbound > 0
		if fail {
			a.failOutbound--
		}
		warning := ""
		if action == "remove" && a.warnOutbound > 0 {
			a.warnOutbound--
			warning = "forced outbound runtime warning"
		}
		if a.outbounds == nil {
			a.outbounds = make(map[string]bool)
		}
		switch action {
		case "add":
			outbound, _ := body["outbound"].(map[string]any)
			tag, _ := outbound["tag"].(string)
			a.outbounds[tag] = true
		case "remove":
			tag, _ := body["tag"].(string)
			delete(a.outbounds, tag)
		}
		failAfterApply := action == "add" && a.failAddAfterApply > 0
		if failAfterApply {
			a.failAddAfterApply--
		}
		a.mu.Unlock()
		if fail {
			http.Error(w, "forced outbound failure", http.StatusBadGateway)
			return
		}
		if failAfterApply {
			http.Error(w, "forced outbound response loss", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true, "runtime_warning": warning})
	case "/api/child/inbounds":
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":  true,
				"inbounds": []any{map[string]any{"tag": "vless-in"}},
			})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		action, _ := body["action"].(string)
		a.mu.Lock()
		a.clients++
		a.record("client:" + action)
		warning := ""
		if action == "add-client" && a.warnAddClient > 0 {
			a.warnAddClient--
			warning = "forced add client runtime warning"
		}
		if action == "remove-client" && a.warnRemoveClient > 0 {
			a.warnRemoveClient--
			warning = "forced remove client runtime warning"
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true, "runtime_warning": warning})
	default:
		http.NotFound(w, r)
	}
}

func newPrivateRoutedRevokeFixture(t *testing.T, agent *privateRoutedRevokeAgent) (*storage.TrafficRepository, *storage.RoutedNodeDetail, *RemoteManageHandler) {
	t.Helper()
	agent.mu.Lock()
	if agent.outbounds == nil {
		agent.outbounds = make(map[string]bool)
	}
	agent.outbounds["private-out"] = true
	agent.mu.Unlock()
	serverHTTP := httptest.NewServer(agent)
	t.Cleanup(serverHTTP.Close)
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "private-routed-revoke.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err := repo.ConfigureNodeSecretEncryption(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(context.Background(), "alice", "alice@example.test", "alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	server := &storage.RemoteServer{
		Name: "private-routed-revoke-edge", Token: "token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket, IPAddress: "127.0.0.1",
		ListenPort: testServerPort(t, serverHTTP.URL), XrayMode: "embedded",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	parent, err := repo.CreateNode(context.Background(), storage.Node{
		Username: "alice", NodeName: "private-parent", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "vless-in",
		ClashConfig: `{"name":"private-parent","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	parentID := parent.ID
	routed, err := repo.CreateRoutedNode(context.Background(), storage.RoutedNodeDetail{
		Node: storage.Node{
			Username: "alice", NodeName: "private-routed", Protocol: "vless", Enabled: true,
			OriginalServer: server.Name, InboundTag: "vless-in", ParentNodeID: &parentID, RoutedOwner: "user",
			ClashConfig: `{"name":"private-routed","type":"vless","server":"edge.example.test","port":443,"uuid":"private-id"}`,
		},
		RoutedOutboundTag: "private-out", RoutedRuleMarktag: "private-rule",
		RoutedOutboundJSON: `{"tag":"private-out","protocol":"freedom","settings":{}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertUserSubaccount(context.Background(), storage.UserSubaccount{
		Username: "alice", RoutedNodeID: routed.ID, Email: "alice__private",
		CredentialJSON: `{"id":"private-id","email":"alice__private"}`, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	return repo, &routed, NewRemoteManageHandler(repo, nil)
}

func TestPrivateRoutedRevokePersistsAndRetriesPending(t *testing.T) {
	agent := &privateRoutedRevokeAgent{failRule: 1, present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()

	pusher := NewLimiterConfigPusher(repo, nil)
	if err := suspendUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err == nil {
		t.Fatal("first private routed revoke unexpectedly succeeded")
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || !sa.RevokePending {
		t.Fatalf("failed revoke state=%+v err=%v, want inactive pending", sa, err)
	}
	pending, err := repo.IsUserDisablePending(ctx, "alice")
	if err != nil || !pending {
		t.Fatalf("disable pending=%v err=%v, want true", pending, err)
	}
	server, err := repo.GetRemoteServerByName(ctx, "private-routed-revoke-edge")
	if err != nil {
		t.Fatal(err)
	}
	configs, err := NewLimiterConfigPusher(repo, nil).BuildLimiterConfigForServer(ctx, server.ID)
	if err != nil {
		t.Fatalf("build pending routed limiter: %v", err)
	}
	var denied bool
	for _, config := range configs {
		for _, user := range config.Users {
			if user.Email == "alice__private" {
				denied = user.Denied
			}
		}
	}
	if !denied {
		t.Fatalf("pending routed client was not explicitly denied: %#v", configs)
	}
	rows, err := repo.ListPendingUserSubaccountRevokes(ctx, 10)
	if err != nil || len(rows) != 1 || rows[0].ID != sa.ID {
		t.Fatalf("pending routed rows=%+v err=%v", rows, err)
	}

	NewManagedNodesHandler(repo, remote, pusher).reconcileAll(ctx)
	sa, err = repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || sa.RevokePending {
		t.Fatalf("completed revoke state=%+v err=%v, want inactive settled", sa, err)
	}
	pending, err = repo.IsUserDisablePending(ctx, "alice")
	if err != nil || pending {
		t.Fatalf("completed disable pending=%v err=%v, want false", pending, err)
	}
	agent.mu.Lock()
	rules, clients := agent.rules, agent.clients
	agent.mu.Unlock()
	if rules != 2 || clients != 1 {
		t.Fatalf("remote attempts rules=%d clients=%d, want 2/1", rules, clients)
	}
}

func TestPrivateRoutedRevokeRequiresDenyACKBeforeRemoteRemoval(t *testing.T) {
	agent := &privateRoutedRevokeAgent{failLimiter: 1, present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()
	pusher := NewLimiterConfigPusher(repo, nil)

	if err := suspendUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err == nil {
		t.Fatal("revoke unexpectedly proceeded after limiter rejection")
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || !sa.RevokePending {
		t.Fatalf("limiter failure state=%+v err=%v, want inactive pending", sa, err)
	}
	agent.mu.Lock()
	limiters, rules, clients := agent.limiters, agent.rules, agent.clients
	agent.mu.Unlock()
	if limiters != 1 || rules != 0 || clients != 0 {
		t.Fatalf("calls after limiter rejection limiter=%d rules=%d clients=%d, want 1/0/0", limiters, rules, clients)
	}

	if errs := retryPendingUserPrivateRoutedRevokes(ctx, remote, repo, pusher); len(errs) != 0 {
		t.Fatalf("retry errors=%v", errs)
	}
	sa, err = repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || sa.RevokePending {
		t.Fatalf("retry state=%+v err=%v, want inactive settled", sa, err)
	}
	agent.mu.Lock()
	limiters, rules, clients = agent.limiters, agent.rules, agent.clients
	agent.mu.Unlock()
	if limiters != 2 || rules != 1 || clients != 1 {
		t.Fatalf("retry calls limiter=%d rules=%d clients=%d, want 2/1/1", limiters, rules, clients)
	}
}

func TestUserDisableAndOverLimitPersistPrivateRoutedIntentAtomically(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(context.Context, *storage.TrafficRepository) error
	}{
		{
			name: "disable",
			prepare: func(ctx context.Context, repo *storage.TrafficRepository) error {
				_, err := repo.PrepareUserDisable(ctx, "alice")
				return err
			},
		},
		{
			name: "over limit",
			prepare: func(ctx context.Context, repo *storage.TrafficRepository) error {
				return repo.BeginUserOverLimitRevoke(ctx, "alice")
			},
		},
	} {
		for _, initialState := range []string{"active", "activation_pending"} {
			t.Run(test.name+"/"+initialState, func(t *testing.T) {
				repo, routed, _ := newPrivateRoutedRevokeFixture(t, &privateRoutedRevokeAgent{present: true})
				ctx := context.Background()
				if initialState == "activation_pending" {
					sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
					if err != nil || sa == nil {
						t.Fatalf("load staged subaccount=%+v err=%v", sa, err)
					}
					if err := repo.StageUserSubaccountActivationPolicy(ctx, sa.ID); err != nil {
						t.Fatal(err)
					}
				}
				if err := test.prepare(ctx, repo); err != nil {
					t.Fatal(err)
				}
				sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
				if err != nil || sa == nil || sa.IsActive || !sa.RevokePending || sa.ActivationPending {
					t.Fatalf("prepared state=%+v err=%v, want inactive revoke-only pending", sa, err)
				}
			})
		}
	}
}

func TestPrivateRoutedRevokePendingPrecedesServerResolution(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()
	originalServer := routed.OriginalServer
	routed.OriginalServer = "missing-private-routed-edge"
	updated, err := repo.UpdateNode(ctx, routed.Node)
	if err != nil {
		t.Fatal(err)
	}
	routed.Node = updated

	pusher := NewLimiterConfigPusher(repo, nil)
	if err := suspendUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err == nil {
		t.Fatal("revoke with missing server unexpectedly succeeded")
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || !sa.RevokePending {
		t.Fatalf("resolution failure state=%+v err=%v, want inactive pending", sa, err)
	}

	routed.OriginalServer = originalServer
	if _, err := repo.UpdateNode(ctx, routed.Node); err != nil {
		t.Fatal(err)
	}
	if errs := retryPendingUserPrivateRoutedRevokes(ctx, remote, repo, pusher); len(errs) != 0 {
		t.Fatalf("retry after server repair errors=%v", errs)
	}
	sa, err = repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || sa.RevokePending {
		t.Fatalf("settled state=%+v err=%v, want inactive without pending", sa, err)
	}
}

func TestResumePrivateRoutedSettlesAndClearsPending(t *testing.T) {
	agent := &privateRoutedRevokeAgent{failRule: 1, present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()

	pusher := NewLimiterConfigPusher(repo, nil)
	if err := suspendUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err == nil {
		t.Fatal("first private routed revoke unexpectedly succeeded")
	}
	if err := resumeUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err != nil {
		t.Fatalf("resume private routed: %v", err)
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || !sa.IsActive || sa.RevokePending || sa.ActivationPending {
		t.Fatalf("resumed state=%+v err=%v, want active without pending", sa, err)
	}
}

func TestPrivateRoutedActivationOrdersPolicyBeforeClient(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()
	pusher := NewLimiterConfigPusher(repo, nil)

	if err := suspendUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err != nil {
		t.Fatalf("suspend private routed: %v", err)
	}
	agent.resetEvents()
	if err := resumeUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err != nil {
		t.Fatalf("resume private routed: %v", err)
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || !sa.IsActive || sa.RevokePending || sa.ActivationPending {
		t.Fatalf("activation state=%+v err=%v, want fully active", sa, err)
	}
	events := agent.snapshotEvents()
	deny := privateRoutedEventIndex(events, "limiter:deny")
	rule := privateRoutedEventIndex(events, "rule:add_rule")
	normal := privateRoutedEventIndex(events, "limiter:normal")
	client := privateRoutedEventIndex(events, "client:add-client")
	if deny < 0 || rule < 0 || normal < 0 || client < 0 || !(deny < rule && rule < normal && normal < client) {
		t.Fatalf("activation order=%v, want deny < rule < normal limiter < client", events)
	}
}

func TestPrivateRoutedActivationRuntimeWarningPersistsAndManagedRetries(t *testing.T) {
	for _, test := range []struct {
		name string
		warn func(*privateRoutedRevokeAgent)
	}{
		{name: "rule", warn: func(agent *privateRoutedRevokeAgent) { agent.warnAddRule = 1 }},
		{name: "client", warn: func(agent *privateRoutedRevokeAgent) { agent.warnAddClient = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent := &privateRoutedRevokeAgent{present: true}
			repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
			ctx := context.Background()
			pusher := NewLimiterConfigPusher(repo, nil)
			if err := suspendUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err != nil {
				t.Fatalf("suspend private routed: %v", err)
			}
			test.warn(agent)
			if err := resumeUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err == nil {
				t.Fatal("runtime warning unexpectedly completed private routed activation")
			}
			sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
			if err != nil || sa == nil || sa.IsActive || !sa.RevokePending || !sa.ActivationPending {
				t.Fatalf("warning state=%+v err=%v, want inactive activation retry with deny", sa, err)
			}

			NewManagedNodesHandler(repo, remote, pusher).reconcileAll(ctx)
			sa, err = repo.GetUserSubaccount(ctx, routed.ID, "alice")
			if err != nil || sa == nil || !sa.IsActive || sa.RevokePending || sa.ActivationPending {
				t.Fatalf("managed retry state=%+v err=%v, want fully active", sa, err)
			}
		})
	}
}

func TestPrivateRoutedActivationRetriesAfterOutboundResponseLoss(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true, failAddAfterApply: 1}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()
	pusher := NewLimiterConfigPusher(repo, nil)
	if err := suspendUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err != nil {
		t.Fatalf("suspend private routed: %v", err)
	}
	if err := resumeUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err == nil {
		t.Fatal("lost outbound response unexpectedly completed activation")
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || !sa.RevokePending || !sa.ActivationPending {
		t.Fatalf("response-loss state=%+v err=%v, want durable activation retry", sa, err)
	}
	NewManagedNodesHandler(repo, remote, pusher).reconcileAll(ctx)
	sa, err = repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || !sa.IsActive || sa.RevokePending || sa.ActivationPending {
		t.Fatalf("response-loss retry state=%+v err=%v, want fully active", sa, err)
	}
	events := agent.snapshotEvents()
	addCount := 0
	for _, event := range events {
		if event == "outbound:add" {
			addCount++
		}
	}
	if addCount != 2 {
		t.Fatalf("outbound add attempts=%d events=%v, want response-loss attempt plus strict retry", addCount, events)
	}
}

func TestPrivateRoutedDeleteRuntimeWarningRetainsDurableRetry(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true, warnOutbound: 1}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	pusher := NewLimiterConfigPusher(repo, nil)
	h := NewUserRoutedOutboundHandler(repo, remote, pusher)
	sibling, err := repo.CreateRoutedNode(context.Background(), storage.RoutedNodeDetail{
		Node: storage.Node{
			Username: "alice", NodeName: "private-routed-sibling", Protocol: "vless", Enabled: true,
			OriginalServer: routed.OriginalServer, InboundTag: routed.InboundTag,
			ParentNodeID: routed.ParentNodeID, RoutedOwner: "user",
			ClashConfig: `{"name":"private-routed-sibling","type":"vless","server":"edge.example.test","port":443,"uuid":"sibling-id"}`,
		},
		RoutedOutboundTag: "private-out-sibling", RoutedRuleMarktag: "private-rule-sibling",
		RoutedOutboundJSON: `{"tag":"private-out-sibling","protocol":"freedom","settings":{}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertUserSubaccount(context.Background(), storage.UserSubaccount{
		Username: "alice", RoutedNodeID: sibling.ID, Email: "alice__private_sibling",
		CredentialJSON: `{"id":"sibling-id","email":"alice__private_sibling"}`, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/user/routed-outbound?id="+strconv.FormatInt(routed.ID, 10), nil)
	recorder := httptest.NewRecorder()
	h.delete(recorder, req, "alice")
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("first delete status=%d body=%s, want 202", recorder.Code, recorder.Body.String())
	}
	pendingNode, err := repo.GetRoutedNodeDetail(context.Background(), routed.ID)
	if err != nil {
		t.Fatalf("delete warning removed durable node: %v", err)
	}
	if pendingNode.Enabled {
		t.Fatal("delete warning did not preserve durable disabled-node delete intent")
	}
	sa, err := repo.GetUserSubaccount(context.Background(), routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || !sa.RevokePending || sa.ActivationPending {
		t.Fatalf("delete warning state=%+v err=%v, want inactive revoke retry", sa, err)
	}
	events := agent.snapshotEvents()
	deny := privateRoutedEventIndex(events, "limiter:deny")
	rule := privateRoutedEventIndex(events, "rule:remove_rule")
	client := privateRoutedEventIndex(events, "client:remove-client")
	outbound := privateRoutedEventIndex(events, "outbound:remove")
	if deny < 0 || rule < 0 || client < 0 || outbound < 0 || !(deny < rule && rule < client && client < outbound) {
		t.Fatalf("delete order=%v, want deny < rule < client < outbound", events)
	}
	if err := resumeUserPrivateRouted(context.Background(), remote, repo, pusher, "alice"); err != nil {
		t.Fatalf("resume should ignore durable delete target: %v", err)
	}
	sa, err = repo.GetUserSubaccount(context.Background(), routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || !sa.RevokePending || sa.ActivationPending {
		t.Fatalf("resume changed durable delete state=%+v err=%v", sa, err)
	}
	for _, event := range agent.snapshotEvents() {
		if event == "client:add-client" {
			t.Fatalf("resume reactivated delete-pending node: %v", agent.snapshotEvents())
		}
	}

	NewManagedNodesHandler(repo, remote, pusher).reconcileAll(context.Background())
	if _, err := repo.GetRoutedNodeDetail(context.Background(), routed.ID); err == nil {
		t.Fatal("managed delete retry retained routed node")
	}
	sa, err = repo.GetUserSubaccount(context.Background(), routed.ID, "alice")
	if err != nil || sa != nil {
		t.Fatalf("managed delete retry left subaccount=%+v err=%v", sa, err)
	}
	pendingRows, err := repo.ListPendingUserSubaccountRevokes(context.Background(), 10)
	if err != nil || len(pendingRows) != 0 {
		t.Fatalf("managed delete retry left orphan pending rows=%+v err=%v", pendingRows, err)
	}
	siblingState, err := repo.GetUserSubaccount(context.Background(), sibling.ID, "alice")
	if err != nil || siblingState == nil || !siblingState.IsActive || siblingState.RevokePending || siblingState.ActivationPending {
		t.Fatalf("single-node delete disturbed sibling state=%+v err=%v", siblingState, err)
	}
	actions, err := repo.CountUserRoutedOutboundActionsToday(context.Background(), "alice")
	if err != nil || actions != 1 {
		t.Fatalf("delete action count=%d err=%v, want exactly one durable action", actions, err)
	}
}

func TestPrivateRoutedResumeNeverReactivatesDisabledPendingNode(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()
	pusher := NewLimiterConfigPusher(repo, nil)
	if err := repo.PrepareUserPrivateRoutedDelete(ctx, routed.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil {
		t.Fatalf("load delete-pending subaccount=%+v err=%v", sa, err)
	}
	// Simulate a crash that leaves the activation marker set after the node was
	// durably disabled. Resume must treat the node deletion intent as stronger.
	if err := repo.StageUserSubaccountActivationPolicy(ctx, sa.ID); err != nil {
		t.Fatal(err)
	}
	agent.resetEvents()
	if err := resumeUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err != nil {
		t.Fatalf("resume of disabled pending node returned error: %v", err)
	}
	sa, err = repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || !sa.ActivationPending {
		t.Fatalf("resume changed disabled pending state=%+v err=%v", sa, err)
	}
	for _, event := range agent.snapshotEvents() {
		if event == "rule:add_rule" || event == "client:add-client" || event == "outbound:add" {
			t.Fatalf("resume reactivated disabled node via %s; events=%v", event, agent.snapshotEvents())
		}
	}
}

func TestPrivateRoutedDeleteWaitsForUserAuthorizationTransition(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	pusher := NewLimiterConfigPusher(repo, nil)
	h := NewUserRoutedOutboundHandler(repo, remote, pusher)
	ctx, release, err := repo.AcquireUserAuthorizationLease(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.PrepareUserDisable(ctx, "alice"); err != nil {
		release()
		t.Fatal(err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodDelete, "/api/user/routed-outbound?id="+strconv.FormatInt(routed.ID, 10), nil)
		recorder := httptest.NewRecorder()
		h.delete(recorder, req, "alice")
		done <- recorder
	}()
	select {
	case recorder := <-done:
		release()
		t.Fatalf("delete bypassed user authorization lease: status=%d body=%s", recorder.Code, recorder.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	if events := agent.snapshotEvents(); len(events) != 0 {
		release()
		t.Fatalf("delete mutated Agent before authorization transition completed: %v", events)
	}
	release()
	select {
	case recorder := <-done:
		if recorder.Code != http.StatusOK {
			t.Fatalf("serialized delete status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serialized delete did not complete")
	}
}

func TestPrivateRoutedCreateWaitsForUserAuthorizationTransition(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	if err := repo.SetSystemSetting(context.Background(), settingUserRoutedOutboundEnabled, "1"); err != nil {
		t.Fatal(err)
	}
	pusher := NewLimiterConfigPusher(repo, nil)
	h := NewUserRoutedOutboundHandler(repo, remote, pusher)
	_, release, err := repo.AcquireUserAuthorizationLease(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	body := `{
		"parent_node_id":` + strconv.FormatInt(*routed.ParentNodeID, 10) + `,
		"target_node_id":` + strconv.FormatInt(*routed.ParentNodeID, 10) + `,
		"label":"lease-check",
		"outbound":{"protocol":"vless","settings":{"vnext":[{"address":"edge.example.test","port":443}]}}
	}`
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/user/routed-outbound", strings.NewReader(body))
		recorder := httptest.NewRecorder()
		h.create(recorder, req, "alice")
		done <- recorder
	}()
	select {
	case recorder := <-done:
		release()
		t.Fatalf("create bypassed user authorization lease: status=%d body=%s", recorder.Code, recorder.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	if events := agent.snapshotEvents(); len(events) != 0 {
		release()
		t.Fatalf("create mutated Agent before authorization transition completed: %v", events)
	}
	release()
	select {
	case recorder := <-done:
		if recorder.Code != http.StatusOK {
			t.Fatalf("serialized create status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serialized create did not complete")
	}
}

func TestPrivateRoutedOverLimitRestoreFailureRestoresTombstone(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()
	pusher := NewLimiterConfigPusher(repo, nil)
	now := time.Now().UTC()
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "private routed restore", TrafficLimitBytes: 1024 * 1024, CycleDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.BeginUserOverLimitRevoke(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	agent.warnAddClient = 1
	enforcer := NewTrafficLimitEnforcer(repo, remote, pusher)
	if enforcer.restoreOverLimitUserIfAllowed(ctx, "alice", map[string]int64{"alice": 0}, make(map[int64]*storage.Package)) {
		t.Fatal("private routed runtime warning unexpectedly completed over-limit restore")
	}
	overLimit, err := repo.IsUserOverLimit(ctx, "alice")
	if err != nil || !overLimit {
		t.Fatalf("over-limit=%v err=%v, want restored tombstone", overLimit, err)
	}
	pending, err := repo.IsUserOverLimitRevokePending(ctx, "alice")
	if err != nil || !pending {
		t.Fatalf("over-limit pending=%v err=%v, want retry", pending, err)
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || sa.RevokePending || sa.ActivationPending {
		t.Fatalf("compensated private routed state=%+v err=%v, want confirmed inactive while user restore remains pending", sa, err)
	}
}

func TestPrivateRoutedOverLimitRestoreCompletesTransitionLast(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()
	pusher := NewLimiterConfigPusher(repo, nil)
	now := time.Now().UTC()
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "private routed restore success", TrafficLimitBytes: 1024 * 1024, CycleDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.BeginUserOverLimitRevoke(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	// Simulate a process stop after the provisional over-limit clear. The
	// durable transition marker must make the next pass finish private restore.
	if err := repo.BeginUserOverLimitRestore(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	enforcer := NewTrafficLimitEnforcer(repo, remote, pusher)
	if !enforcer.restoreOverLimitUserIfAllowed(ctx, "alice", map[string]int64{"alice": 0}, make(map[int64]*storage.Package)) {
		t.Fatal("private routed over-limit restore did not complete")
	}
	overLimit, err := repo.IsUserOverLimit(ctx, "alice")
	if err != nil || overLimit {
		t.Fatalf("over-limit=%v err=%v, want cleared", overLimit, err)
	}
	pending, err := repo.IsUserOverLimitRevokePending(ctx, "alice")
	if err != nil || pending {
		t.Fatalf("transition pending=%v err=%v, want cleared last", pending, err)
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || !sa.IsActive || sa.RevokePending || sa.ActivationPending {
		t.Fatalf("restored private routed state=%+v err=%v, want active", sa, err)
	}
}

func TestUserEnableWithoutRemoteManagerReturnsActivationPending(t *testing.T) {
	agent := &privateRoutedRevokeAgent{present: true}
	repo, routed, remote := newPrivateRoutedRevokeFixture(t, agent)
	ctx := context.Background()
	pusher := NewLimiterConfigPusher(repo, nil)
	if _, err := repo.PrepareUserDisable(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := suspendUserPrivateRouted(ctx, remote, repo, pusher, "alice"); err != nil {
		t.Fatal(err)
	}

	h := NewUserStatusHandler(repo, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/users/status", strings.NewReader(`{"username":"alice","is_active":true}`))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("enable status=%d body=%s, want 202", recorder.Code, recorder.Body.String())
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive || !sa.RevokePending || !sa.ActivationPending {
		t.Fatalf("enable pending state=%+v err=%v, want durable inactive activation retry", sa, err)
	}
}

func TestRestoreUserOverLimitRevokePendingPreservesDeny(t *testing.T) {
	repo, _ := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "over-limit-restore.db"))
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "alice", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.RestoreUserOverLimitRevokePending(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	over, err := repo.IsUserOverLimit(ctx, "alice")
	if err != nil || !over {
		t.Fatalf("over-limit=%v err=%v", over, err)
	}
	pending, err := repo.IsUserOverLimitRevokePending(ctx, "alice")
	if err != nil || !pending {
		t.Fatalf("over-limit pending=%v err=%v", pending, err)
	}
}
