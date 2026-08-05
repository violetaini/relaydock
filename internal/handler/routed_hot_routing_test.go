package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

type routedHotAgent struct {
	mu              sync.Mutex
	routing         map[string]interface{}
	runtimeRouting  map[string]interface{}
	rejectHot       bool
	hotPosts        int
	batchPosts      int
	inboundAdds     int
	inboundRemoves  int
	serviceControls int
}

func newRoutedHotAgent() *routedHotAgent {
	routing := map[string]interface{}{
		"rules": []interface{}{map[string]interface{}{
			"marktag":     "route-mark",
			"outboundTag": "proxy-out",
			"user":        []interface{}{},
		}},
	}
	return &routedHotAgent{
		routing:        cloneRoutedHotMap(routing),
		runtimeRouting: cloneRoutedHotMap(routing),
	}
}

func cloneRoutedHotMap(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	raw, _ := json.Marshal(input)
	var output map[string]interface{}
	_ = json.Unmarshal(raw, &output)
	return output
}

func (a *routedHotAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/routing":
		a.mu.Lock()
		routing := cloneRoutedHotMap(a.routing)
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "routing": routing})
		return

	case r.Method == http.MethodPost && r.URL.Path == "/api/child/routing":
		var request struct {
			Action  string                 `json:"action"`
			Routing map[string]interface{} `json:"routing"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Action != "set_hot" {
			http.Error(w, `{"success":false,"error":"set_hot required"}`, http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		a.hotPosts++
		reject := a.rejectHot
		if !reject {
			a.routing = cloneRoutedHotMap(request.Routing)
			a.runtimeRouting = cloneRoutedHotMap(request.Routing)
		}
		a.mu.Unlock()
		if reject {
			http.Error(w, `{"success":false,"error":"injected hot route failure"}`, http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "hot applied"})
		return

	case r.Method == http.MethodPost && r.URL.Path == "/api/child/batch-apply":
		var request struct {
			RoutingUserAdditions []struct {
				Marktag     string `json:"marktag"`
				OutboundTag string `json:"outbound_tag"`
				UserEmail   string `json:"user_email"`
			} `json:"routing_user_additions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		a.batchPosts++
		routing := cloneRoutedHotMap(a.routing)
		rules, _ := routing["rules"].([]interface{})
		routingChanged := false
		routingResults := make([]string, 0, len(request.RoutingUserAdditions))
		for _, addition := range request.RoutingUserAdditions {
			matched := -1
			for i, rawRule := range rules {
				rule, _ := rawRule.(map[string]interface{})
				if rule == nil {
					continue
				}
				if addition.Marktag != "" && rule["marktag"] == addition.Marktag {
					matched = i
					break
				}
				if addition.Marktag == "" && addition.OutboundTag != "" && rule["outboundTag"] == addition.OutboundTag {
					matched = i
					break
				}
			}
			if matched < 0 {
				a.mu.Unlock()
				http.Error(w, `{"success":false,"message":"rule not found"}`, http.StatusBadRequest)
				return
			}
			rule := rules[matched].(map[string]interface{})
			users, _ := rule["user"].([]interface{})
			exists := false
			for _, user := range users {
				if user == addition.UserEmail {
					exists = true
					break
				}
			}
			if exists {
				routingResults = append(routingResults, "ok (no-op)")
				continue
			}
			users = append(users, addition.UserEmail)
			rule["user"] = users
			rules[matched] = rule
			routingChanged = true
			routingResults = append(routingResults, "ok")
		}
		routing["rules"] = rules
		a.routing = routing
		a.mu.Unlock()
		inboundResults := make([]string, len(request.RoutingUserAdditions))
		for i := range inboundResults {
			if routingChanged {
				inboundResults[i] = "ok"
			} else {
				inboundResults[i] = "ok (no-op)"
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":          true,
			"inbound_results":  inboundResults,
			"routing_results":  routingResults,
			"routing_changed":  routingChanged,
			"runtime_warnings": []string{},
		})
		return

	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		var request struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		if request.Action == "add-client" {
			a.inboundAdds++
		}
		if request.Action == "remove-client" {
			a.inboundRemoves++
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "changed": true})
		return

	case r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control":
		a.mu.Lock()
		a.serviceControls++
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}

	http.NotFound(w, r)
}

func (a *routedHotAgent) counts() (hotPosts, batchPosts, serviceControls int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hotPosts, a.batchPosts, a.serviceControls
}

func (a *routedHotAgent) inboundCounts() (adds, removes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inboundAdds, a.inboundRemoves
}

func routedHotBatchItem(serverID, routedNodeID int64) routedBatchItem {
	return routedBatchItem{
		ServerID:       serverID,
		InboundTag:     "vless-in",
		Marktag:        "route-mark",
		OutboundTag:    "proxy-out",
		UserEmail:      "alice__route",
		Credential:     map[string]interface{}{"id": "alice-id", "email": "alice__route"},
		CredentialJSON: `{"id":"alice-id","email":"alice__route"}`,
		Username:       "alice",
		RoutedNodeID:   routedNodeID,
	}
}

func newRoutedHotNode(t *testing.T, agent http.Handler) (*storage.TrafficRepository, *storage.RemoteServer, *RemoteManageHandler, storage.RoutedNodeDetail) {
	t.Helper()
	repo, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()
	parent, err := repo.CreateNode(ctx, storage.Node{
		Username:       "alice",
		RawURL:         "vless://parent",
		NodeName:       "Parent",
		Protocol:       "vless",
		ParsedConfig:   `{"type":"vless"}`,
		ClashConfig:    `{"type":"vless"}`,
		Enabled:        true,
		OriginalServer: server.Name,
		InboundTag:     "vless-in",
	})
	if err != nil {
		t.Fatalf("CreateNode(parent): %v", err)
	}
	parentID := parent.ID
	routed, err := repo.CreateRoutedNode(ctx, storage.RoutedNodeDetail{
		Node: storage.Node{
			Username:       "alice",
			NodeName:       "Routed",
			Protocol:       "vless",
			ParsedConfig:   `{"type":"vless"}`,
			ClashConfig:    `{"type":"vless"}`,
			Enabled:        true,
			OriginalServer: server.Name,
			InboundTag:     "vless-in",
			ParentNodeID:   &parentID,
		},
		RoutedOutboundTag:     "proxy-out",
		RoutedOutboundJSON:    `{"tag":"proxy-out"}`,
		RoutedRuleMarktag:     "route-mark",
		RoutedAdminEmail:      "_admin__route",
		RoutedAdminCredential: `{"id":"owner-id","email":"_admin__route","flow":"xtls-rprx-vision"}`,
	})
	if err != nil {
		t.Fatalf("CreateRoutedNode: %v", err)
	}
	return repo, server, remote, routed
}

func TestAddRemoveUserFromRoutedNodeNeverControlsXrayService(t *testing.T) {
	agent := newRoutedHotAgent()
	repo, _, remote, routed := newRoutedHotNode(t, agent)
	ctx := context.Background()
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	if err := addUserToRoutedNode(ctx, remote, repo, user, routed.ID); err != nil {
		t.Fatalf("addUserToRoutedNode: %v", err)
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || !sa.IsActive {
		t.Fatalf("routed add did not activate subaccount: %+v err=%v", sa, err)
	}
	if hot, _, controls := agent.counts(); hot != 1 || controls != 0 {
		t.Fatalf("routed add used hotPosts=%d serviceControls=%d, want 1/0", hot, controls)
	}

	changed, err := removeUserFromRoutedNode(ctx, remote, repo, "alice", routed.ID)
	if err != nil || !changed {
		t.Fatalf("removeUserFromRoutedNode: changed=%v err=%v", changed, err)
	}
	sa, err = repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive {
		t.Fatalf("routed remove left subaccount active: %+v err=%v", sa, err)
	}
	if hot, _, controls := agent.counts(); hot != 2 || controls != 0 {
		t.Fatalf("routed remove used hotPosts=%d serviceControls=%d, want 2/0", hot, controls)
	}
	if adds, removes := agent.inboundCounts(); adds != 1 || removes != 1 {
		t.Fatalf("routed add/remove used inbound adds=%d removes=%d, want 1/1", adds, removes)
	}

	changed, err = removeUserFromRoutedNode(ctx, remote, repo, "alice", routed.ID)
	if err != nil || changed {
		t.Fatalf("repeated routed remove: changed=%v err=%v, want no-op", changed, err)
	}
	if hot, _, controls := agent.counts(); hot != 2 || controls != 0 {
		t.Fatalf("repeated remove used hotPosts=%d serviceControls=%d, want 2/0", hot, controls)
	}
	if _, removes := agent.inboundCounts(); removes != 1 {
		t.Fatalf("repeated remove made %d inbound removals, want 1", removes)
	}
}

func TestAddUserToRoutedNodeHotRejectRevokesPendingClient(t *testing.T) {
	agent := newRoutedHotAgent()
	repo, _, remote, routed := newRoutedHotNode(t, agent)
	ctx := context.Background()
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	agent.mu.Lock()
	agent.rejectHot = true
	agent.mu.Unlock()

	if err := addUserToRoutedNode(ctx, remote, repo, user, routed.ID); err == nil {
		t.Fatal("hot route rejection was reported as a successful routed add")
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || sa.IsActive {
		t.Fatalf("rejected routed add activated subaccount: %+v err=%v", sa, err)
	}
	if adds, removes := agent.inboundCounts(); adds != 1 || removes != 1 {
		t.Fatalf("rejected routed add used inbound adds=%d removes=%d, want 1/1", adds, removes)
	}
	if hot, _, controls := agent.counts(); hot != 1 || controls != 0 {
		t.Fatalf("rejected routed add used hotPosts=%d serviceControls=%d, want 1/0", hot, controls)
	}
}

func TestMutateRoutingRuleUserUsesHotRouteAndIsIdempotent(t *testing.T) {
	agent := newRoutedHotAgent()
	_, server, remote := newPackageLeaseFixture(t, agent)
	ctx := context.Background()

	changed, err := mutateRoutingRuleUserByMarktag(ctx, remote, server.ID, "route-mark", "alice__route", true)
	if err != nil || !changed {
		t.Fatalf("add routed user: changed=%v err=%v", changed, err)
	}
	hotPosts, _, controls := agent.counts()
	if hotPosts != 1 || controls != 0 {
		t.Fatalf("add used hotPosts=%d serviceControls=%d, want 1/0", hotPosts, controls)
	}

	changed, err = mutateRoutingRuleUserByMarktag(ctx, remote, server.ID, "route-mark", "alice__route", true)
	if err != nil || changed {
		t.Fatalf("repeated add: changed=%v err=%v, want no-op", changed, err)
	}
	hotPosts, _, controls = agent.counts()
	if hotPosts != 1 || controls != 0 {
		t.Fatalf("repeated add used hotPosts=%d serviceControls=%d", hotPosts, controls)
	}

	changed, err = mutateRoutingRuleUserByMarktag(ctx, remote, server.ID, "route-mark", "alice__route", false)
	if err != nil || !changed {
		t.Fatalf("remove routed user: changed=%v err=%v", changed, err)
	}
	changed, err = mutateRoutingRuleUserByMarktag(ctx, remote, server.ID, "route-mark", "alice__route", false)
	if err != nil || changed {
		t.Fatalf("repeated remove: changed=%v err=%v, want no-op", changed, err)
	}
	hotPosts, _, controls = agent.counts()
	if hotPosts != 2 || controls != 0 {
		t.Fatalf("remove path used hotPosts=%d serviceControls=%d, want 2/0", hotPosts, controls)
	}
}

func TestRoutedBatchHotRouteRejectKeepsReservationInactiveAndRetries(t *testing.T) {
	agent := newRoutedHotAgent()
	repo, server, remote, routed := newRoutedHotNode(t, agent)
	ctx := context.Background()
	item := routedHotBatchItem(server.ID, routed.ID)

	agent.mu.Lock()
	agent.rejectHot = true
	agent.mu.Unlock()
	_, err := applyRoutedBatchToAgent(ctx, remote, repo, server.ID, []routedBatchItem{item})
	if err == nil {
		t.Fatal("hot route rejection was reported as success")
	}
	sa, err := repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil {
		t.Fatalf("read reserved subaccount: %v", err)
	}
	if sa == nil || sa.IsActive {
		t.Fatalf("hot rejection activated local subaccount: %+v", sa)
	}
	if hot, _, controls := agent.counts(); hot != 1 || controls != 0 {
		t.Fatalf("rejected batch used hotPosts=%d serviceControls=%d, want 1/0", hot, controls)
	}
	if _, removes := agent.inboundCounts(); removes != 1 {
		t.Fatalf("rejected batch made %d compensating inbound removals, want 1", removes)
	}

	agent.mu.Lock()
	agent.rejectHot = false
	agent.mu.Unlock()
	if _, err := applyRoutedBatchToAgent(ctx, remote, repo, server.ID, []routedBatchItem{item}); err != nil {
		t.Fatalf("retry after hot rejection: %v", err)
	}
	sa, err = repo.GetUserSubaccount(ctx, routed.ID, "alice")
	if err != nil || sa == nil || !sa.IsActive {
		t.Fatalf("successful retry did not activate subaccount: %+v err=%v", sa, err)
	}
	if hot, _, controls := agent.counts(); hot != 2 || controls != 0 {
		t.Fatalf("retry used hotPosts=%d serviceControls=%d, want 2/0", hot, controls)
	}

	if _, err := applyRoutedBatchToAgent(ctx, remote, repo, server.ID, []routedBatchItem{item}); err != nil {
		t.Fatalf("idempotent routed batch: %v", err)
	}
	if hot, _, controls := agent.counts(); hot != 2 || controls != 0 {
		t.Fatalf("idempotent batch used hotPosts=%d serviceControls=%d, want 2/0", hot, controls)
	}
}

func TestMutateRoutingRuleUserHotRejectDoesNotChangeRoute(t *testing.T) {
	agent := newRoutedHotAgent()
	_, server, remote := newPackageLeaseFixture(t, agent)
	agent.mu.Lock()
	agent.rejectHot = true
	agent.mu.Unlock()

	changed, err := mutateRoutingRuleUserByMarktag(context.Background(), remote, server.ID, "route-mark", "alice__route", true)
	if err == nil || changed {
		t.Fatalf("rejected hot route returned changed=%v err=%v", changed, err)
	}
	if hot, _, controls := agent.counts(); hot != 1 || controls != 0 {
		t.Fatalf("rejected route used hotPosts=%d serviceControls=%d, want 1/0", hot, controls)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	rules, _ := agent.routing["rules"].([]interface{})
	users, _ := rules[0].(map[string]interface{})["user"].([]interface{})
	if len(users) != 0 {
		t.Fatalf("rejected hot route changed persisted users: %#v", users)
	}
	runtimeRules, _ := agent.runtimeRouting["rules"].([]interface{})
	runtimeUsers, _ := runtimeRules[0].(map[string]interface{})["user"].([]interface{})
	if len(runtimeUsers) != 0 {
		t.Fatalf("rejected hot route changed runtime users: %#v", runtimeUsers)
	}
}
