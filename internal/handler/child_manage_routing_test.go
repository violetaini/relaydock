package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/violetaini/relaydock/internal/capabilities"
	routercommand "github.com/xtls/xray-core/app/router/command"
	"google.golang.org/grpc"
)

func TestMutateRoutingRulesPreservesCurrentRoutingWithoutAliasing(t *testing.T) {
	original := map[string]interface{}{
		"domainStrategy": "AsIs",
		"domainMatcher":  "hybrid",
		"futureOption": map[string]interface{}{
			"enabled": true,
		},
		"rules": []interface{}{
			map[string]interface{}{"type": "field", "outboundTag": "direct"},
			map[string]interface{}{"type": "field", "outboundTag": "blocked"},
		},
	}
	originalJSON, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	candidate, err := mutateRoutingRules(original, "add_rule_hot", ChildRoutingRequest{
		Rule: map[string]interface{}{"type": "field", "outboundTag": "proxy"},
	})
	if err != nil {
		t.Fatalf("mutate routing rules: %v", err)
	}

	rules := candidate["rules"].([]interface{})
	if got := routingRuleOutboundTags(rules); !reflect.DeepEqual(got, []string{"direct", "blocked", "proxy"}) {
		t.Fatalf("candidate tags = %#v", got)
	}
	if candidate["domainStrategy"] != "AsIs" || candidate["domainMatcher"] != "hybrid" {
		t.Fatalf("candidate lost top-level routing fields: %#v", candidate)
	}
	candidate["futureOption"].(map[string]interface{})["enabled"] = false
	rules[0].(map[string]interface{})["outboundTag"] = "changed"

	afterJSON, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalJSON, afterJSON) {
		t.Fatalf("original routing was mutated\nbefore: %s\nafter:  %s", originalJSON, afterJSON)
	}
}

func TestMutateRoutingRulesReplaceRemoveAndMove(t *testing.T) {
	routing := routingWithOutboundTags("a", "b", "c")
	replaceIndex := 1

	replaced, err := mutateRoutingRules(routing, "replace_rule_hot", ChildRoutingRequest{
		Index: &replaceIndex,
		Rule:  map[string]interface{}{"type": "field", "outboundTag": "replacement"},
	})
	if err != nil {
		t.Fatalf("replace rule: %v", err)
	}
	if got := routingRuleOutboundTags(replaced["rules"].([]interface{})); !reflect.DeepEqual(got, []string{"a", "replacement", "c"}) {
		t.Fatalf("replaced tags = %#v", got)
	}

	removeIndex := 1
	removed, err := mutateRoutingRules(routing, "remove_rule_hot", ChildRoutingRequest{Index: &removeIndex})
	if err != nil {
		t.Fatalf("remove rule: %v", err)
	}
	if got := routingRuleOutboundTags(removed["rules"].([]interface{})); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("removed tags = %#v", got)
	}

	from, to := 0, 2
	moved, err := mutateRoutingRules(routing, "move_rule_hot", ChildRoutingRequest{From: &from, To: &to})
	if err != nil {
		t.Fatalf("move rule down: %v", err)
	}
	if got := routingRuleOutboundTags(moved["rules"].([]interface{})); !reflect.DeepEqual(got, []string{"b", "c", "a"}) {
		t.Fatalf("moved-down tags = %#v", got)
	}

	from, to = 2, 0
	moved, err = mutateRoutingRules(routing, "move_rule_hot", ChildRoutingRequest{From: &from, To: &to})
	if err != nil {
		t.Fatalf("move rule up: %v", err)
	}
	if got := routingRuleOutboundTags(moved["rules"].([]interface{})); !reflect.DeepEqual(got, []string{"c", "a", "b"}) {
		t.Fatalf("moved-up tags = %#v", got)
	}
}

func TestMutateRoutingRulesRejectsInvalidRequests(t *testing.T) {
	from, to := 0, 1
	replaceIndex, removeIndex, firstIndex := 1, -1, 0
	tests := []struct {
		name    string
		routing map[string]interface{}
		action  string
		request ChildRoutingRequest
	}{
		{name: "rules type", routing: map[string]interface{}{"rules": "invalid"}, action: "add_rule_hot", request: ChildRoutingRequest{Rule: map[string]interface{}{}}},
		{name: "missing add rule", routing: routingWithOutboundTags("a"), action: "add_rule_hot"},
		{name: "missing replace index", routing: routingWithOutboundTags("a"), action: "replace_rule_hot", request: ChildRoutingRequest{Rule: map[string]interface{}{}}},
		{name: "replace index", routing: routingWithOutboundTags("a"), action: "replace_rule_hot", request: ChildRoutingRequest{Index: &replaceIndex, Rule: map[string]interface{}{}}},
		{name: "missing remove index", routing: routingWithOutboundTags("a"), action: "remove_rule_hot"},
		{name: "remove index", routing: routingWithOutboundTags("a"), action: "remove_rule_hot", request: ChildRoutingRequest{Index: &removeIndex}},
		{name: "stale expected rule", routing: routingWithOutboundTags("a"), action: "remove_rule_hot", request: ChildRoutingRequest{Index: &firstIndex, ExpectedRule: map[string]interface{}{"type": "field", "outboundTag": "b"}}},
		{name: "missing move indexes", routing: routingWithOutboundTags("a"), action: "move_rule_hot"},
		{name: "move target", routing: routingWithOutboundTags("a"), action: "move_rule_hot", request: ChildRoutingRequest{From: &from, To: &to}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := mutateRoutingRules(test.routing, test.action, test.request); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRoutingRuleHotActionErrorClassificationAcrossTransports(t *testing.T) {
	unsupportedBody := []byte(`{"success":false,"error":"Invalid action"}`)
	tests := []struct {
		name        string
		err         error
		unsupported bool
		status      int
	}{
		{name: "http unsupported", err: &remoteHTTPStatusError{Status: http.StatusBadRequest, Body: unsupportedBody, Message: "Invalid action"}, unsupported: true, status: http.StatusBadRequest},
		{name: "websocket unsupported", err: &HTTPLikeError{Status: http.StatusBadRequest, Body: unsupportedBody}, unsupported: true, status: http.StatusBadRequest},
		{name: "http conflict", err: &remoteHTTPStatusError{Status: http.StatusConflict, Body: []byte(`{"error":"routing rule changed"}`), Message: "routing rule changed"}, status: http.StatusConflict},
		{name: "websocket conflict", err: &HTTPLikeError{Status: http.StatusConflict, Body: []byte(`{"error":"routing rule changed"}`)}, status: http.StatusConflict},
		{name: "wrapped websocket conflict", err: fmt.Errorf("forward routing: %w", &HTTPLikeError{Status: http.StatusConflict, Body: []byte(`{"error":"routing rule changed"}`)}), status: http.StatusConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isUnsupportedRoutingRuleHotAction(test.err); got != test.unsupported {
				t.Fatalf("unsupported = %t, want %t", got, test.unsupported)
			}
			status, _, _, ok := routingRemoteHTTPFailure(test.err)
			if !ok || status != test.status {
				t.Fatalf("remote failure status = %d, ok=%t; want %d", status, ok, test.status)
			}
			response := httptest.NewRecorder()
			remoteWriteRoutingMutationError(response, test.err)
			if response.Code != test.status {
				t.Fatalf("response status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestPerformRoutingHotUpdateTransaction(t *testing.T) {
	previous := routingWithOutboundTags("old")
	candidate := routingWithOutboundTags("new")

	t.Run("success", func(t *testing.T) {
		var calls []string
		err := performRoutingHotUpdate(candidate, previous, func(routing map[string]interface{}) error {
			calls = append(calls, routingRuleOutboundTags(routing["rules"].([]interface{}))[0])
			return nil
		}, func() error {
			calls = append(calls, "persist")
			return nil
		})
		if err != nil {
			t.Fatalf("transaction: %v", err)
		}
		if !reflect.DeepEqual(calls, []string{"new", "persist"}) {
			t.Fatalf("calls = %#v", calls)
		}
	})

	t.Run("apply failure restores runtime and does not persist", func(t *testing.T) {
		persisted := false
		var applied []string
		err := performRoutingHotUpdate(candidate, previous, func(routing map[string]interface{}) error {
			tag := routingRuleOutboundTags(routing["rules"].([]interface{}))[0]
			applied = append(applied, tag)
			if tag == "new" {
				return errors.New("apply failed")
			}
			return nil
		}, func() error {
			persisted = true
			return nil
		})
		if err == nil || persisted {
			t.Fatalf("err = %v, persisted = %v", err, persisted)
		}
		if !reflect.DeepEqual(applied, []string{"new", "old"}) {
			t.Fatalf("runtime generations = %#v", applied)
		}
		var transactionErr *routingHotUpdateError
		if !errors.As(err, &transactionErr) || transactionErr.phase != "apply" || transactionErr.rollbackErr != nil {
			t.Fatalf("transaction error = %#v", err)
		}
	})

	t.Run("apply failure retains rollback failure", func(t *testing.T) {
		calls := 0
		err := performRoutingHotUpdate(candidate, previous, func(map[string]interface{}) error {
			calls++
			if calls == 1 {
				return errors.New("apply failed")
			}
			return errors.New("rollback failed")
		}, func() error {
			t.Fatal("persist must not run")
			return nil
		})
		var transactionErr *routingHotUpdateError
		if !errors.As(err, &transactionErr) || transactionErr.phase != "apply" || transactionErr.rollbackErr == nil {
			t.Fatalf("transaction error = %#v", err)
		}
		if calls != 2 {
			t.Fatalf("apply calls = %d, want 2", calls)
		}
	})

	t.Run("persistence failure restores runtime", func(t *testing.T) {
		var applied []string
		err := performRoutingHotUpdate(candidate, previous, func(routing map[string]interface{}) error {
			applied = append(applied, routingRuleOutboundTags(routing["rules"].([]interface{}))[0])
			return nil
		}, func() error {
			return errors.New("write failed")
		})
		if err == nil {
			t.Fatal("expected transaction error")
		}
		if !reflect.DeepEqual(applied, []string{"new", "old"}) {
			t.Fatalf("runtime generations = %#v", applied)
		}
	})

	t.Run("rename-applied failure keeps matching runtime", func(t *testing.T) {
		var applied []string
		err := performRoutingHotUpdate(candidate, previous, func(routing map[string]interface{}) error {
			applied = append(applied, routingRuleOutboundTags(routing["rules"].([]interface{}))[0])
			return nil
		}, func() error {
			return &atomicRenameAppliedError{err: errors.New("directory sync failed")}
		})
		var transactionErr *routingHotUpdateError
		if !errors.As(err, &transactionErr) || !transactionErr.renameApplied {
			t.Fatalf("transaction error = %#v", err)
		}
		if !reflect.DeepEqual(applied, []string{"new"}) {
			t.Fatalf("runtime generations = %#v", applied)
		}
	})

	t.Run("rollback failure is retained", func(t *testing.T) {
		calls := 0
		err := performRoutingHotUpdate(candidate, previous, func(map[string]interface{}) error {
			calls++
			if calls == 2 {
				return errors.New("rollback failed")
			}
			return nil
		}, func() error {
			return errors.New("write failed")
		})
		var transactionErr *routingHotUpdateError
		if !errors.As(err, &transactionErr) || transactionErr.rollbackErr == nil {
			t.Fatalf("transaction error = %#v", err)
		}
	})
}

type recordingRoutingService struct {
	routercommand.UnimplementedRoutingServiceServer
	requests []*routercommand.AddRuleRequest
}

func (service *recordingRoutingService) AddRule(_ context.Context, request *routercommand.AddRuleRequest) (*routercommand.AddRuleResponse, error) {
	service.requests = append(service.requests, request)
	return &routercommand.AddRuleResponse{}, nil
}

func TestChildManageRoutingHotActionsMutateLatestConfig(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	routingService := &recordingRoutingService{}
	routercommand.RegisterRoutingServiceServer(grpcServer, routingService)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	port := listener.Addr().(*net.TCPAddr).Port
	config := map[string]interface{}{
		"inbounds": []interface{}{
			map[string]interface{}{"tag": "api", "port": port},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"domainMatcher":  "hybrid",
			"futureOption":   map[string]interface{}{"keep": true},
			"rules": []interface{}{
				map[string]interface{}{"type": "field", "domain": []interface{}{"one.example"}, "outboundTag": "a"},
			},
		},
	}
	writeTestJSONFile(t, configPath, config)

	previousConfigPaths := childXrayConfigPaths
	childXrayConfigPaths = []string{configPath}
	t.Cleanup(func() { childXrayConfigPaths = previousConfigPaths })
	handler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(directory, "inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}

	postRoutingAction(t, handler, map[string]interface{}{
		"action": "add_rule_hot",
		"rule":   map[string]interface{}{"type": "field", "domain": []interface{}{"two.example"}, "outboundTag": "b"},
	})
	postRoutingAction(t, handler, map[string]interface{}{
		"action": "replace_rule_hot",
		"index":  1,
		"rule":   map[string]interface{}{"type": "field", "domain": []interface{}{"three.example"}, "outboundTag": "c"},
	})
	postRoutingAction(t, handler, map[string]interface{}{
		"action": "add_rule_hot",
		"rule":   map[string]interface{}{"type": "field", "domain": []interface{}{"four.example"}, "outboundTag": "d"},
	})
	postRoutingAction(t, handler, map[string]interface{}{
		"action": "move_rule_hot",
		"from":   2,
		"to":     0,
	})
	postRoutingAction(t, handler, map[string]interface{}{
		"action": "remove_rule_hot",
		"index":  1,
	})

	var persisted map[string]interface{}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &persisted); err != nil {
		t.Fatal(err)
	}
	routing := persisted["routing"].(map[string]interface{})
	if got := routingRuleOutboundTags(routing["rules"].([]interface{})); !reflect.DeepEqual(got, []string{"d", "c"}) {
		t.Fatalf("persisted tags = %#v", got)
	}
	if routing["domainStrategy"] != "AsIs" || routing["domainMatcher"] != "hybrid" {
		t.Fatalf("top-level routing fields were lost: %#v", routing)
	}
	if keep, _ := routing["futureOption"].(map[string]interface{})["keep"].(bool); !keep {
		t.Fatalf("future routing field was lost: %#v", routing)
	}
	if len(routingService.requests) != 5 {
		t.Fatalf("hot apply requests = %d", len(routingService.requests))
	}
	for index, request := range routingService.requests {
		if request.Config == nil || request.ShouldAppend {
			t.Fatalf("request %d did not replace the complete runtime rules: %#v", index, request)
		}
	}
}

func TestChildManageRoutingHotActionRejectsStaleRuleWithConflict(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	writeTestJSONFile(t, configPath, map[string]interface{}{
		"routing": routingWithOutboundTags("current"),
	})

	previousConfigPaths := childXrayConfigPaths
	childXrayConfigPaths = []string{configPath}
	t.Cleanup(func() { childXrayConfigPaths = previousConfigPaths })
	handler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(directory, "inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	index := 0
	body, err := json.Marshal(ChildRoutingRequest{
		Action:       "remove_rule_hot",
		Index:        &index,
		ExpectedRule: map[string]interface{}{"type": "field", "outboundTag": "stale"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/child/routing", bytes.NewReader(body))
	handler.HandleRouting(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale routing action returned %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
	}
}

func TestRemoteManageRoutingHotActionSupportsSetHotOnlyAgentAndRejectsStaleRule(t *testing.T) {
	agent := newRoutedHotAgent()
	_, server, remote := newPackageLeaseFixture(t, agent)
	expected := map[string]interface{}{
		"marktag":     "route-mark",
		"outboundTag": "proxy-out",
		"user":        []interface{}{},
	}
	replacement := map[string]interface{}{
		"type":        "field",
		"outboundTag": "direct",
	}

	postRemoteRoutingAction(t, remote, server.ID, map[string]interface{}{
		"action":        "replace_rule_hot",
		"index":         0,
		"expected_rule": expected,
		"rule":          replacement,
	}, http.StatusOK)
	agent.mu.Lock()
	if got := routingRuleOutboundTags(agent.routing["rules"].([]interface{})); !reflect.DeepEqual(got, []string{"direct"}) {
		agent.mu.Unlock()
		t.Fatalf("legacy Agent routing tags = %#v", got)
	}
	hotPosts := agent.hotPosts
	agent.mu.Unlock()

	postRemoteRoutingAction(t, remote, server.ID, map[string]interface{}{
		"action":        "remove_rule_hot",
		"index":         0,
		"expected_rule": expected,
	}, http.StatusConflict)
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if agent.hotPosts != hotPosts {
		t.Fatalf("stale mutation reached Agent: hot posts %d -> %d", hotPosts, agent.hotPosts)
	}
}

type atomicRoutingAgent struct {
	mu            sync.Mutex
	routing       map[string]interface{}
	nativePosts   int
	snapshotReads int
	setHotPosts   int
}

func (agent *atomicRoutingAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path != "/api/child/routing" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		agent.mu.Lock()
		agent.snapshotReads++
		routing, _ := cloneRoutingConfig(agent.routing)
		agent.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "routing": routing})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request ChildRoutingRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if request.Action == "set_hot" {
		agent.setHotPosts++
		agent.routing, _ = cloneRoutingConfig(request.Routing)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}
	agent.nativePosts++
	candidate, err := mutateRoutingRules(agent.routing, request.Action, request)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errRoutingRuleChanged) {
			status = http.StatusConflict
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	agent.routing = candidate
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func TestRemoteManageRoutingHotActionPrefersAgentAtomicMutation(t *testing.T) {
	agent := &atomicRoutingAgent{routing: routingWithOutboundTags("original")}
	_, server, remote := newPackageLeaseFixture(t, agent)
	expected := map[string]interface{}{"type": "field", "outboundTag": "original"}
	replacement := map[string]interface{}{"type": "field", "outboundTag": "replacement"}

	postRemoteRoutingAction(t, remote, server.ID, map[string]interface{}{
		"action":        "replace_rule_hot",
		"index":         0,
		"expected_rule": expected,
		"rule":          replacement,
	}, http.StatusOK)

	agent.mu.Lock()
	if got := routingRuleOutboundTags(agent.routing["rules"].([]interface{})); !reflect.DeepEqual(got, []string{"replacement"}) {
		agent.mu.Unlock()
		t.Fatalf("atomic Agent routing tags = %#v", got)
	}
	if agent.nativePosts != 1 || agent.snapshotReads != 0 || agent.setHotPosts != 0 {
		agent.mu.Unlock()
		t.Fatalf("atomic path counters native=%d snapshots=%d set_hot=%d", agent.nativePosts, agent.snapshotReads, agent.setHotPosts)
	}
	agent.mu.Unlock()

	postRemoteRoutingAction(t, remote, server.ID, map[string]interface{}{
		"action":        "remove_rule_hot",
		"index":         0,
		"expected_rule": expected,
	}, http.StatusConflict)
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if agent.nativePosts != 2 || agent.snapshotReads != 0 || agent.setHotPosts != 0 {
		t.Fatalf("stale atomic path counters native=%d snapshots=%d set_hot=%d", agent.nativePosts, agent.snapshotReads, agent.setHotPosts)
	}
}

func newFederatedRoutingFixture(t *testing.T, agent http.Handler) (*RemoteManageHandler, int64) {
	t.Helper()
	agentServer := httptest.NewServer(agent)
	t.Cleanup(agentServer.Close)
	ownerRepo, ownerServer := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	const shareToken = "routing-hot-action-share-token"
	if _, err := ownerRepo.CreateSharedServer(context.Background(), ownerServer.ID, hashShareToken(shareToken), "routing hot actions"); err != nil {
		t.Fatal(err)
	}
	ownerFederation := NewFederationHandler(ownerRepo, NewRemoteManageHandler(ownerRepo, nil), capabilities.NewManager())
	ownerServerHTTP := httptest.NewServer(ownerFederation)
	t.Cleanup(ownerServerHTTP.Close)

	consumerRepo, firstConsumerServer := newRemoteInstallationHandlerRepo(t, 23889)
	consumerServer := *firstConsumerServer
	consumerServer.ID = 0
	consumerServer.Name = "federated-routing-consumer"
	consumerServer.Token = "federated-routing-consumer-token"
	if err := consumerRepo.CreateRemoteServer(context.Background(), &consumerServer); err != nil {
		t.Fatal(err)
	}
	if err := consumerRepo.SetFederatedServer(context.Background(), consumerServer.ID, ownerServerHTTP.URL, shareToken, "shared-"); err != nil {
		t.Fatal(err)
	}
	return NewRemoteManageHandler(consumerRepo, nil), consumerServer.ID
}

func TestFederatedRoutingHotActionFallsBackOnOwnerForLegacyAgent(t *testing.T) {
	agent := newRoutedHotAgent()
	remote, serverID := newFederatedRoutingFixture(t, agent)
	expected := map[string]interface{}{
		"marktag":     "route-mark",
		"outboundTag": "proxy-out",
		"user":        []interface{}{},
	}
	postRemoteRoutingAction(t, remote, serverID, map[string]interface{}{
		"action":        "replace_rule_hot",
		"index":         0,
		"expected_rule": expected,
		"rule":          map[string]interface{}{"type": "field", "outboundTag": "federated-direct"},
	}, http.StatusOK)

	agent.mu.Lock()
	defer agent.mu.Unlock()
	if got := routingRuleOutboundTags(agent.routing["rules"].([]interface{})); !reflect.DeepEqual(got, []string{"federated-direct"}) {
		t.Fatalf("federated legacy Agent routing tags = %#v", got)
	}
	if agent.hotPosts != 1 {
		t.Fatalf("federated legacy Agent set_hot posts = %d, want 1", agent.hotPosts)
	}
}

func TestFederatedRoutingHotActionPreservesAtomicConflict(t *testing.T) {
	agent := &atomicRoutingAgent{routing: routingWithOutboundTags("current")}
	remote, serverID := newFederatedRoutingFixture(t, agent)
	postRemoteRoutingAction(t, remote, serverID, map[string]interface{}{
		"action":        "remove_rule_hot",
		"index":         0,
		"expected_rule": map[string]interface{}{"type": "field", "outboundTag": "stale"},
	}, http.StatusConflict)

	agent.mu.Lock()
	defer agent.mu.Unlock()
	if agent.nativePosts != 1 || agent.snapshotReads != 0 || agent.setHotPosts != 0 {
		t.Fatalf("federated conflict counters native=%d snapshots=%d set_hot=%d", agent.nativePosts, agent.snapshotReads, agent.setHotPosts)
	}
}

func routingWithOutboundTags(tags ...string) map[string]interface{} {
	rules := make([]interface{}, 0, len(tags))
	for _, tag := range tags {
		rules = append(rules, map[string]interface{}{"type": "field", "outboundTag": tag})
	}
	return map[string]interface{}{
		"domainStrategy": "AsIs",
		"rules":          rules,
	}
}

func routingRuleOutboundTags(rules []interface{}) []string {
	tags := make([]string, 0, len(rules))
	for _, raw := range rules {
		rule, _ := raw.(map[string]interface{})
		tag, _ := rule["outboundTag"].(string)
		tags = append(tags, tag)
	}
	return tags
}

func writeTestJSONFile(t *testing.T, path string, value interface{}) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func postRoutingAction(t *testing.T, handler *ChildManageHandler, payload map[string]interface{}) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/child/routing", bytes.NewReader(body))
	handler.HandleRouting(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("routing action %v returned %d: %s", payload["action"], response.Code, response.Body.String())
	}
}

func postRemoteRoutingAction(t *testing.T, handler *RemoteManageHandler, serverID int64, payload map[string]interface{}, wantStatus int) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/admin/remote/routing?server_id=%d", serverID), bytes.NewReader(body))
	handler.HandleRouting(response, request)
	if response.Code != wantStatus {
		t.Fatalf("remote routing action %v returned %d, want %d: %s", payload["action"], response.Code, wantStatus, response.Body.String())
	}
}
