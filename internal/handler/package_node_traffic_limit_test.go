package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type nodeQuotaAgent struct {
	mu          sync.Mutex
	denied      []bool
	inboundTags []string
	records     []nodeQuotaRecord
}

type nodeQuotaRecord struct {
	inboundTag string
	email      string
	denied     bool
}

func (a *nodeQuotaAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		tags := a.inboundTags
		if len(tags) == 0 {
			tags = []string{"quota-in"}
		}
		inbounds := make([]map[string]any, 0, len(tags))
		for _, tag := range tags {
			inbounds = append(inbounds, map[string]any{"tag": tag})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "inbounds": inbounds})
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/system/info":
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "capabilities": map[string]bool{"limiter_denied_v1": true}})
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/limiter":
		var payload WSLimiterConfigPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, user := range payload.Users {
			a.mu.Lock()
			a.records = append(a.records, nodeQuotaRecord{inboundTag: payload.InboundTag, email: user.Email, denied: user.Denied})
			a.mu.Unlock()
			if user.Email == "alice__quota-in" {
				a.mu.Lock()
				a.denied = append(a.denied, user.Denied)
				a.mu.Unlock()
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	default:
		http.NotFound(w, r)
	}
}

func (a *nodeQuotaAgent) recordsSince(offset int) []nodeQuotaRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]nodeQuotaRecord(nil), a.records[offset:]...)
}

func assertNodeQuotaRecords(t *testing.T, records []nodeQuotaRecord, want map[string]bool) {
	t.Helper()
	got := make(map[string]bool)
	for _, record := range records {
		if record.email == "alice__"+record.inboundTag {
			got[record.inboundTag] = record.denied
		}
	}
	if len(got) != len(want) {
		t.Fatalf("node quota records=%+v want=%+v", records, want)
	}
	for tag, denied := range want {
		if got[tag] != denied {
			t.Fatalf("node quota records=%+v want=%+v", records, want)
		}
	}
}

func TestPackageFixedNodeTrafficQuotaResetsOnCycleRenewalOnly(t *testing.T) {
	ctx := context.Background()
	agentState := &nodeQuotaAgent{}
	agent := httptest.NewServer(agentState)
	t.Cleanup(agent.Close)
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "quota-edge", Token: "quota-token", IPAddress: "127.0.0.1",
		ListenPort: remoteAgentTestPort(t, agent.URL), XrayMode: "embedded",
		ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	node, err := repo.CreateNode(ctx, storage.Node{
		Username: "owner", NodeName: "quota", Protocol: "vless", Enabled: true,
		OriginalServer: server.Name, InboundTag: "quota-in",
		ClashConfig: `{"name":"quota","type":"vless","server":"127.0.0.1","port":443,"uuid":"owner"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "node-quota", CycleDays: 30, IsReset: false, ResetDay: 1,
		Nodes: []int64{node.ID}, NodeTrafficLimits: map[int64]float64{node.ID: 100.0 / userTrafficLimitBytesPerGB},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	end := start.Add(30 * 24 * time.Hour)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end, false, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username: "alice", ServerID: server.ID, InboundTag: node.InboundTag, Protocol: "vless",
		CredentialJSON: `{"id":"alice","email":"alice__quota-in"}`,
	}); err != nil {
		t.Fatal(err)
	}
	for _, uplink := range []int64{0, 100} {
		if err := repo.UpsertUserTrafficBatch(ctx, server.ID, []storage.UserTrafficSample{{
			Email: "alice__quota-in", Username: "alice", Uplink: uplink, BillingMultiplier: 1,
		}}, false); err != nil {
			t.Fatal(err)
		}
	}
	pusher := NewLimiterConfigPusher(repo, nil)
	if err := pusher.PushToServerChecked(ctx, server.ID); err != nil {
		t.Fatalf("publish over-limit snapshot: %v", err)
	}
	// Repeating the exact same assignment window is an idempotent retry, not a
	// renewal. It must retain the current package-cycle usage.
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end, false, 1); err != nil {
		t.Fatalf("retry package assignment: %v", err)
	}
	if err := pusher.PushToServerChecked(ctx, server.ID); err != nil {
		t.Fatalf("publish retry snapshot: %v", err)
	}
	// Extending the entitlement window starts the next package cycle when
	// is_reset=false and resets all fixed-node quota baselines atomically.
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, start, end.Add(30*24*time.Hour), false, 1); err != nil {
		t.Fatalf("renew package assignment: %v", err)
	}
	user, err := repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.IsReset {
		t.Fatal("package-cycle assignment was silently changed to calendar reset")
	}
	if err := pusher.PushToServerChecked(ctx, server.ID); err != nil {
		t.Fatalf("publish renewed-cycle snapshot: %v", err)
	}
	agentState.mu.Lock()
	defer agentState.mu.Unlock()
	if len(agentState.denied) != 3 || !agentState.denied[0] || !agentState.denied[1] || agentState.denied[2] {
		t.Fatalf("quota snapshots denied=%v, want [true true false]", agentState.denied)
	}
}

func TestPackageFixedNodeTrafficQuotaIsIndependentAndRefreshesChecked(t *testing.T) {
	ctx := context.Background()
	agentState := &nodeQuotaAgent{inboundTags: []string{"quota-a", "quota-b"}}
	agent := httptest.NewServer(agentState)
	t.Cleanup(agent.Close)
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "owner", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	server := &storage.RemoteServer{
		Name: "quota-independent-edge", Token: "quota-independent-token", IPAddress: "127.0.0.1",
		ListenPort: remoteAgentTestPort(t, agent.URL), XrayMode: "embedded",
		ConnectionMode: storage.ConnectionModePush, Status: storage.RemoteServerStatusConnected,
	}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	createNode := func(name, tag string) storage.Node {
		node, err := repo.CreateNode(ctx, storage.Node{
			Username: "owner", NodeName: name, Protocol: "vless", Enabled: true,
			OriginalServer: server.Name, InboundTag: tag,
			ClashConfig: `{"name":"` + name + `","type":"vless","server":"127.0.0.1","port":443,"uuid":"owner"}`,
		})
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	nodeA := createNode("quota-a", "quota-a")
	nodeB := createNode("quota-b", "quota-b")
	packageID, err := repo.CreatePackage(ctx, storage.Package{
		Name: "independent-node-quotas", CycleDays: 30, IsReset: false,
		Nodes: []int64{nodeA.ID, nodeB.ID}, NodeTrafficLimits: map[int64]float64{
			nodeA.ID: 100.0 / userTrafficLimitBytesPerGB,
			nodeB.ID: 200.0 / userTrafficLimitBytesPerGB,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := repo.AssignPackageToUser(ctx, "alice", packageID, now.Add(-time.Hour), now.Add(30*24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"quota-a", "quota-b"} {
		if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
			Username: "alice", ServerID: server.ID, InboundTag: tag, Protocol: "vless",
			CredentialJSON: `{"id":"alice","email":"alice__` + tag + `"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	samples := func(bytes int64) []storage.UserTrafficSample {
		return []storage.UserTrafficSample{
			{Email: "alice__quota-a", Username: "alice", Uplink: bytes, BillingMultiplier: 1},
			{Email: "alice__quota-b", Username: "alice", Uplink: bytes, BillingMultiplier: 1},
		}
	}
	if err := repo.UpsertUserTrafficBatch(ctx, server.ID, samples(0), false); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertUserTrafficBatch(ctx, server.ID, samples(100), false); err != nil {
		t.Fatal(err)
	}

	pusher := NewLimiterConfigPusher(repo, nil)
	enforcer := NewTrafficLimitEnforcer(repo, nil, pusher)
	offset := 0
	enforcer.CheckAll(ctx)
	records := agentState.recordsSince(offset)
	assertNodeQuotaRecords(t, records, map[string]bool{"quota-a": true, "quota-b": false})
	offset += len(records)

	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.NodeTrafficLimits = map[int64]float64{
		nodeA.ID: 0,
		nodeB.ID: 50.0 / userTrafficLimitBytesPerGB,
	}
	if err := repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}
	enforcer.CheckAll(ctx)
	records = agentState.recordsSince(offset)
	assertNodeQuotaRecords(t, records, map[string]bool{"quota-a": false, "quota-b": true})
	offset += len(records)

	pkg, err = repo.GetPackage(ctx, packageID)
	if err != nil {
		t.Fatal(err)
	}
	pkg.NodeTrafficLimits = map[int64]float64{}
	if err := repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}
	enforcer.CheckAll(ctx)
	assertNodeQuotaRecords(t, agentState.recordsSince(offset), map[string]bool{"quota-a": false, "quota-b": false})
}
