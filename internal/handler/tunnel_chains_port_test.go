package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type recordedTunnelInbound struct {
	Port              int
	Target            string
	NextPort          int
	Network           string
	FollowRedirect    bool
	FollowRedirectSet bool
}

func tunnelChainRecordingAgent(t *testing.T, config string, requests *[]recordedTunnelInbound, mu *sync.Mutex, postCount *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "config": config})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			postCount.Add(1)
			var request struct {
				Action  string         `json:"action"`
				Inbound map[string]any `json:"inbound"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			settings, _ := request.Inbound["settings"].(map[string]any)
			followRedirect, followRedirectSet := settings["followRedirect"].(bool)
			recorded := recordedTunnelInbound{
				Port:              toInt(request.Inbound["port"]),
				Target:            strings.TrimSpace(stringValue(settings["address"])),
				NextPort:          toInt(settings["port"]),
				Network:           strings.TrimSpace(stringValue(settings["network"])),
				FollowRedirect:    followRedirect,
				FollowRedirectSet: followRedirectSet,
			}
			mu.Lock()
			*requests = append(*requests, recorded)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func tunnelChainRequestWith(t *testing.T, serverIDs []int64, entryPort int) *http.Request {
	t.Helper()
	body, err := json.Marshal(createChainReq{
		Label: "same-port", ServerIDs: serverIDs, EntryPort: entryPort,
		TargetAddress: "target.example.test", TargetPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPost, "/api/admin/tunnel-chains", bytes.NewReader(body))
}

func TestTunnelChainUsesExplicitPortOnEveryServer(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	var mu sync.Mutex
	var postCount atomic.Int64
	records := make([][]recordedTunnelInbound, 3)
	servers := make([]*httptest.Server, 0, 3)
	serverIDs := make([]int64, 0, 3)
	for i := range records {
		agent := tunnelChainRecordingAgent(t, `{"inbounds":[]}`, &records[i], &mu, &postCount)
		servers = append(servers, agent)
		server := createTunnelChainRemoteServer(t, repo, "same-port-edge-"+string(rune('a'+i)), agent.URL)
		serverIDs = append(serverIDs, server.ID)
	}
	for _, server := range servers {
		defer server.Close()
	}

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, serverIDs, 2033))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if postCount.Load() != 3 {
		t.Fatalf("POST count=%d, want 3", postCount.Load())
	}
	for i, items := range records {
		if len(items) != 1 {
			t.Fatalf("server %d records=%#v", i, items)
		}
		if items[0].Port != 2033 || items[0].Network != "tcp,udp" {
			t.Fatalf("server %d inbound=%#v", i, items[0])
		}
		if !items[0].FollowRedirectSet || items[0].FollowRedirect {
			t.Fatalf("server %d followRedirect must be explicitly false: %#v", i, items[0])
		}
		if i < len(records)-1 && items[0].NextPort != 2033 {
			t.Fatalf("server %d next port=%d, want 2033", i, items[0].NextPort)
		}
	}
}

func TestTunnelChainPrefersIPv6BetweenDualStackRelays(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	var mu sync.Mutex
	var postCount atomic.Int64
	var firstRecords, secondRecords []recordedTunnelInbound
	firstAgent := tunnelChainRecordingAgent(t, `{"inbounds":[]}`, &firstRecords, &mu, &postCount)
	defer firstAgent.Close()
	secondAgent := tunnelChainRecordingAgent(t, `{"inbounds":[]}`, &secondRecords, &mu, &postCount)
	defer secondAgent.Close()
	first := createTunnelChainRemoteServer(t, repo, "dual-stack-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "dual-stack-second", secondAgent.URL)
	if _, _, err := repo.UpdateRemoteServerHeartbeat(context.Background(), first.Token, first.IPAddress, "2001:db8::10"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.UpdateRemoteServerHeartbeat(context.Background(), second.Token, second.IPAddress, "2001:db8::20"); err != nil {
		t.Fatal(err)
	}

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{first.ID, second.ID}, 2033))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(firstRecords) != 1 || firstRecords[0].Target != "2001:db8::20" {
		t.Fatalf("first hop target=%#v, want next relay IPv6", firstRecords)
	}
	if len(secondRecords) != 1 || secondRecords[0].Target != "target.example.test" {
		t.Fatalf("final hop target=%#v", secondRecords)
	}
}

func TestTunnelChainExplicitPortConflictFailsWithoutChangingPorts(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	var mu sync.Mutex
	var postCount atomic.Int64
	var firstRecords, secondRecords []recordedTunnelInbound
	firstAgent := tunnelChainRecordingAgent(t, `{"inbounds":[]}`, &firstRecords, &mu, &postCount)
	defer firstAgent.Close()
	secondAgent := tunnelChainRecordingAgent(t, `{"inbounds":[{"tag":"existing","port":2033,"protocol":"vless"}]}`, &secondRecords, &mu, &postCount)
	defer secondAgent.Close()
	first := createTunnelChainRemoteServer(t, repo, "conflict-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "conflict-second", secondAgent.URL)

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{first.ID, second.ID}, 2033))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("conflicting chain wrote %d inbound(s)", postCount.Load())
	}
	if !strings.Contains(response.Body.String(), "2033") || !strings.Contains(response.Body.String(), second.Name) {
		t.Fatalf("conflict response is not explicit: %s", response.Body.String())
	}
}

func TestTunnelChainAutoSelectsOneCommonPort(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	var mu sync.Mutex
	var postCount atomic.Int64
	var firstRecords, secondRecords []recordedTunnelInbound
	firstAgent := tunnelChainRecordingAgent(t, `{"inbounds":[{"tag":"first-used","port":20000,"protocol":"vless"}]}`, &firstRecords, &mu, &postCount)
	defer firstAgent.Close()
	secondAgent := tunnelChainRecordingAgent(t, `{"inbounds":[{"tag":"second-used","port":20001,"protocol":"vless"}]}`, &secondRecords, &mu, &postCount)
	defer secondAgent.Close()
	first := createTunnelChainRemoteServer(t, repo, "auto-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "auto-second", secondAgent.URL)

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{first.ID, second.ID}, 0))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(firstRecords) != 1 || len(secondRecords) != 1 {
		t.Fatalf("records first=%#v second=%#v", firstRecords, secondRecords)
	}
	selected := firstRecords[0].Port
	if selected == 0 || selected == 20000 || selected == 20001 || secondRecords[0].Port != selected || firstRecords[0].NextPort != selected {
		t.Fatalf("auto ports first=%#v second=%#v", firstRecords[0], secondRecords[0])
	}
}

func TestTunnelChainRejectsDuplicateServersBeforeAgentRequests(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	var mu sync.Mutex
	var postCount atomic.Int64
	var records []recordedTunnelInbound
	agent := tunnelChainRecordingAgent(t, `{"inbounds":[]}`, &records, &mu, &postCount)
	defer agent.Close()
	server := createTunnelChainRemoteServer(t, repo, "duplicate-edge", agent.URL)

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{server.ID, server.ID}, 2033))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("duplicate chain wrote %d inbound(s)", postCount.Load())
	}
}

func TestTunnelChainRejectsPrivilegedEntryPort(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{1, 2}, 1023))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "1024-65535") {
		t.Fatalf("privileged-port response is not explicit: %s", response.Body.String())
	}
}

func TestTunnelChainRejectsExistingLabelOnAnotherConnectedServer(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	var mu sync.Mutex
	var postCount atomic.Int64
	var firstRecords, secondRecords, existingRecords []recordedTunnelInbound
	firstAgent := tunnelChainRecordingAgent(t, `{"inbounds":[]}`, &firstRecords, &mu, &postCount)
	defer firstAgent.Close()
	secondAgent := tunnelChainRecordingAgent(t, `{"inbounds":[]}`, &secondRecords, &mu, &postCount)
	defer secondAgent.Close()
	existingAgent := tunnelChainRecordingAgent(t, `{"inbounds":[{"tag":"tunnel-same-port-h0","protocol":"tunnel","port":31000}]}`, &existingRecords, &mu, &postCount)
	defer existingAgent.Close()
	first := createTunnelChainRemoteServer(t, repo, "label-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "label-second", secondAgent.URL)
	createTunnelChainRemoteServer(t, repo, "label-existing", existingAgent.URL)

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{first.ID, second.ID}, 2033))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("duplicate label wrote %d inbound(s)", postCount.Load())
	}
	if !strings.Contains(response.Body.String(), "same-port") || !strings.Contains(response.Body.String(), "tunnel-same-port-h0") {
		t.Fatalf("duplicate label response is not explicit: %s", response.Body.String())
	}
}

func tunnelChainMutationACKAgent(t *testing.T, mutate func(action string) (int, string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "config": `{"inbounds":[]}`})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			var request struct {
				Action string `json:"action"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			status, body := mutate(request.Action)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestTunnelChainRejectsMutationWarningACK(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	var firstActions []string
	firstAgent := tunnelChainMutationACKAgent(t, func(action string) (int, string) {
		firstActions = append(firstActions, action)
		if action == "remove" {
			return http.StatusOK, `{"success":true}`
		}
		return http.StatusOK, `{"success":true,"warning":"persist_failed"}`
	})
	defer firstAgent.Close()
	secondAgent := tunnelChainMutationACKAgent(t, func(string) (int, string) {
		return http.StatusOK, `{"success":true}`
	})
	defer secondAgent.Close()
	first := createTunnelChainRemoteServer(t, repo, "warning-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "warning-second", secondAgent.URL)

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{first.ID, second.ID}, 2033))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "persist_failed") {
		t.Fatalf("warning ACK was not surfaced: %s", response.Body.String())
	}
	if len(firstActions) != 2 || firstActions[0] != "add" || firstActions[1] != "remove" {
		t.Fatalf("warning ACK did not roll back the possibly-created hop: actions=%v", firstActions)
	}
}

func TestTunnelChainRollsBackCurrentHopAfterAddResponseDrops(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	var firstActions []string
	firstAgent := tunnelChainMutationACKAgent(t, func(action string) (int, string) {
		firstActions = append(firstActions, action)
		return http.StatusOK, `{"success":true}`
	})
	defer firstAgent.Close()

	var secondMu sync.Mutex
	var secondActions []string
	var secondMutationIDs []string
	secondPresent := false
	secondAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "config": `{"inbounds":[]}`})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			var request struct {
				Action     string `json:"action"`
				MutationID string `json:"mutation_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			secondMu.Lock()
			secondActions = append(secondActions, request.Action)
			secondMutationIDs = append(secondMutationIDs, request.MutationID)
			if request.Action == "add" {
				secondPresent = true
			}
			if request.Action == "remove" {
				secondPresent = false
			}
			secondMu.Unlock()
			if request.Action == "add" {
				// Simulate an Agent that completed the add but whose response was
				// lost before the master received an HTTP status/body.
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "hijacking is unavailable", http.StatusInternalServerError)
					return
				}
				conn, _, err := hijacker.Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer secondAgent.Close()

	first := createTunnelChainRemoteServer(t, repo, "drop-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "drop-second", secondAgent.URL)
	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{first.ID, second.ID}, 2033))

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "已确认回滚") {
		t.Fatalf("transport failure was not rolled back: %s", response.Body.String())
	}
	if got, want := firstActions, []string{"add", "remove"}; !slices.Equal(got, want) {
		t.Fatalf("first actions=%v, want %v", got, want)
	}
	secondMu.Lock()
	gotActions := append([]string(nil), secondActions...)
	gotMutationIDs := append([]string(nil), secondMutationIDs...)
	present := secondPresent
	secondMu.Unlock()
	if want := []string{"add", "remove"}; !slices.Equal(gotActions, want) {
		t.Fatalf("current-hop actions=%v, want %v", gotActions, want)
	}
	if present {
		t.Fatal("current hop remained present after response-loss rollback")
	}
	if len(gotMutationIDs) != 2 || gotMutationIDs[0] == "" || gotMutationIDs[0] != gotMutationIDs[1] {
		t.Fatalf("add/remove mutation IDs=%v, want one stable non-empty ID", gotMutationIDs)
	}
}

func TestTunnelChainRollbackWarningIsNotConfirmed(t *testing.T) {
	repo := newTunnelChainTestRepo(t)
	firstAgent := tunnelChainMutationACKAgent(t, func(action string) (int, string) {
		if action == "remove" {
			return http.StatusOK, `{"success":true,"warning":"remove_persist_failed"}`
		}
		return http.StatusOK, `{"success":true}`
	})
	defer firstAgent.Close()
	secondAgent := tunnelChainMutationACKAgent(t, func(string) (int, string) {
		return http.StatusBadGateway, `{"success":false,"error":"forced add failure"}`
	})
	defer secondAgent.Close()
	first := createTunnelChainRemoteServer(t, repo, "rollback-warning-first", firstAgent.URL)
	second := createTunnelChainRemoteServer(t, repo, "rollback-warning-second", secondAgent.URL)

	handler := NewTunnelChainHandler(repo, NewRemoteManageHandler(repo, nil))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tunnelChainRequestWith(t, []int64{first.ID, second.ID}, 2033))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "回滚未完整确认") || strings.Contains(response.Body.String(), "已确认回滚") {
		t.Fatalf("rollback warning was incorrectly confirmed: %s", response.Body.String())
	}
}

func TestGroupTunnelChainsSplitsLegacyDuplicateLabelsByHopTarget(t *testing.T) {
	tunnels := []tunnelInfo{
		{Kind: "inbound", ServerID: 1, Tag: "tunnel-shared-h0", ListenPort: 2033, TargetAddress: "edge-two.example", TargetPort: 2033, ServerHosts: []string{"edge-one.example"}},
		{Kind: "inbound", ServerID: 2, Tag: "tunnel-shared-h1", ListenPort: 2033, TargetAddress: "first-target.example", TargetPort: 443, ServerHosts: []string{"edge-two.example"}},
		{Kind: "inbound", ServerID: 3, Tag: "tunnel-shared-h0", ListenPort: 2033, TargetAddress: "edge-four.example", TargetPort: 2033, ServerHosts: []string{"edge-three.example"}},
		{Kind: "inbound", ServerID: 4, Tag: "tunnel-shared-h1", ListenPort: 2033, TargetAddress: "second-target.example", TargetPort: 8443, ServerHosts: []string{"edge-four.example"}},
	}

	chains, flat := groupTunnelChains(tunnels)
	if len(flat) != 0 || len(chains) != 2 {
		t.Fatalf("chains=%#v flat=%#v, want two separate chains", chains, flat)
	}
	pairs := map[string]bool{}
	ids := map[string]bool{}
	for _, chain := range chains {
		if len(chain.Hops) != 2 {
			t.Fatalf("legacy chain was not kept intact: %#v", chain)
		}
		pairs[fmt.Sprintf("%d-%d", chain.Hops[0].ServerID, chain.Hops[1].ServerID)] = true
		if chain.ID == "" || ids[chain.ID] {
			t.Fatalf("chain instance id is empty or unstable: %#v", chains)
		}
		ids[chain.ID] = true
	}
	if !pairs["1-2"] || !pairs["3-4"] {
		t.Fatalf("independent same-label chains were crossed: %#v", chains)
	}
}

func TestValidateTunnelChainMutationACK(t *testing.T) {
	for _, body := range []string{
		`not-json`,
		`{}`,
		`{"success":false,"error":"rejected"}`,
		`{"success":true,"warning":"persist_failed"}`,
		`{"success":true,"runtime_warning":"runtime deferred"}`,
	} {
		if err := validateTunnelChainMutationACK([]byte(body)); err == nil {
			t.Errorf("ACK %s unexpectedly accepted", body)
		}
	}
	if err := validateTunnelChainMutationACK([]byte(`{"success":true}`)); err != nil {
		t.Fatalf("clean ACK rejected: %v", err)
	}
}
