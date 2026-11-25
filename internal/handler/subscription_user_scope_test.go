package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestSubscriptionUsesRecipientCredentialsAndUserNodeQuota(t *testing.T) {
	repo, _ := generationFixture(t)
	ctx := context.Background()
	createManagedSecurityTestUser(t, repo, "bob", storage.RoleUser)
	server := &storage.RemoteServer{Name: "quota-edge", Token: "test", IPAddress: "203.0.113.10", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	nodes := []storage.Node{}
	for _, tag := range []string{"selected", "outside"} {
		node, err := repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: tag, Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: tag, ClashConfig: fmt.Sprintf(`{"name":%q,"type":"vless","server":"example.net","port":443,"uuid":"ADMIN-SECRET"}`, tag)})
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
	}
	packageID, err := repo.CreatePackage(ctx, storage.Package{Name: "quota-package", CycleDays: 30, Nodes: []int64{nodes[0].ID, nodes[1].ID}, NodeTrafficLimits: map[int64]float64{nodes[0].ID: 100, nodes[1].ID: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for index, username := range []string{"alice", "bob"} {
		now := time.Now().UTC()
		if err := repo.AssignPackageToUser(ctx, username, packageID, now, now.Add(24*time.Hour), false, 1); err != nil {
			t.Fatal(err)
		}
		if err := repo.UpdateUserNodeLimitsWithTraffic(ctx, username, nil, map[int64]float64{nodes[0].ID: float64(50 - index*25)}, nil); err != nil {
			t.Fatal(err)
		}
		for _, node := range nodes {
			if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{Username: username, ServerID: server.ID, InboundTag: node.InboundTag, Protocol: "vless", CredentialJSON: fmt.Sprintf(`{"id":%q,"email":%q}`, username+"-PRIVATE", username+"__"+node.InboundTag)}); err != nil {
				t.Fatal(err)
			}
		}
		for _, amount := range []int64{0, int64(100 * (index + 1))} {
			if err := repo.UpsertUserTrafficBatch(ctx, server.ID, []storage.UserTrafficSample{{Username: username, Email: username + "__selected", Uplink: amount, BillingMultiplier: 1}, {Username: username, Email: username + "__outside", Uplink: amount * 90, BillingMultiplier: 1}}, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	g := generationRecipe()
	g.Kind = "custom"
	w := generationCall(repo, "/api/admin/subscribe-files/generation", generationRequest{Name: "Assigned", Filename: "assigned.yaml", SelectedNodeIDs: []int64{nodes[0].ID}, Generation: g})
	if w.Code != 201 {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	f, _ := repo.GetSubscribeFileByFilename(ctx, "assigned.yaml")
	legacyCap := 999.0
	f.TrafficLimit = &legacyCap
	if _, err := repo.UpdateSubscribeFile(ctx, f); err != nil {
		t.Fatal(err)
	}
	for index, username := range []string{"alice", "bob"} {
		if err := repo.AssignSubscriptionToUser(ctx, username, f.ID); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/api/clash/subscribe?filename=assigned.yaml", nil)
		r = r.WithContext(auth.ContextWithUsername(r.Context(), username))
		response := httptest.NewRecorder()
		NewSubscriptionHandlerConcrete(repo, "subscribes").ServeHTTP(response, r)
		if response.Code != 200 {
			t.Fatalf("user=%s status=%d body=%s", username, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), username+"-PRIVATE") || strings.Contains(response.Body.String(), "ADMIN-SECRET") || strings.Contains(response.Body.String(), "outside") {
			t.Fatalf("recipient %s received an incorrect credential/scope", username)
		}
		wantUsed := int64(100 * (index + 1))
		wantLimit := int64(50-index*25) * userTrafficLimitBytesPerGB
		info := response.Header().Get("subscription-userinfo")
		if !strings.Contains(info, "download="+strconv.FormatInt(wantUsed, 10)) || !strings.Contains(info, "total="+strconv.FormatInt(wantLimit, 10)) {
			t.Fatalf("user=%s header=%s want used=%d limit=%d", username, info, wantUsed, wantLimit)
		}
		r = httptest.NewRequest(http.MethodGet, "/api/admin/subscribe-files/traffic", nil).WithContext(auth.ContextWithUsername(ctx, username))
		response = httptest.NewRecorder()
		NewSubscribeFilesHandler(repo).ServeHTTP(response, r)
		var payload struct {
			Traffic map[int64]subscriptionUserTraffic `json:"traffic"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &payload) != nil || payload.Traffic[f.ID].Used != wantUsed || payload.Traffic[f.ID].Limit != wantLimit {
			t.Fatalf("user traffic API differs from subscription header: %s", response.Body.String())
		}
		portal := httptest.NewRecorder()
		NewPortalSummaryHandler(repo).ServeHTTP(portal, httptest.NewRequest(http.MethodGet, "/api/user/portal-summary", nil).WithContext(auth.ContextWithUsername(ctx, username)))
		var overview UserPortalSummaryResponse
		if portal.Code != 200 || json.Unmarshal(portal.Body.Bytes(), &overview) != nil || overview.Traffic.TotalUsedBytes != wantUsed*91 || overview.Traffic.TotalLimitBytes != wantLimit+100*userTrafficLimitBytesPerGB {
			t.Fatalf("portal did not use the user's resource quotas: %s", portal.Body.String())
		}
	}
	if err := repo.UpdateUserNodeLimitsWithTraffic(ctx, "alice", nil, map[int64]float64{nodes[0].ID: 0}, nil); err != nil {
		t.Fatal(err)
	}
	stats, err := resolveSubscriptionUserTraffic(ctx, repo, "alice", []int64{nodes[0].ID, nodes[0].ID})
	if err != nil || stats.Used != 100 || stats.Limit != 0 || !stats.Unlimited {
		t.Fatalf("unlimited/duplicate-node accounting: %+v err=%v", stats, err)
	}
}

func TestSubscriptionRejectsNodesWithoutPerUserAccounting(t *testing.T) {
	repo, _ := generationFixture(t)
	for index, node := range []storage.Node{
		{NodeName: "shared Chitanda", Protocol: "chitanda", OriginalServer: "edge", InboundTag: "chitanda-in", ClashConfig: `{"type":"chitanda","psk":"shared"}`},
		{NodeName: "shared SS", Protocol: "ss", OriginalServer: "edge", InboundTag: "ss", ClashConfig: `{"type":"ss","cipher":"chacha20-ietf-poly1305","password":"shared"}`},
		{NodeName: "Tunnel", Protocol: "ss", OriginalServer: "edge", InboundTag: "anydoor-node-1", ClashConfig: `{"type":"ss","cipher":"2022-blake3-aes-128-gcm"}`},
		{NodeName: "unmanaged", Protocol: "vless", ClashConfig: `{"type":"vless","uuid":"shared"}`},
	} {
		node.Username = "admin"
		node.Enabled = true
		n, err := repo.CreateNode(context.Background(), node)
		if err != nil {
			t.Fatal(err)
		}
		g := generationRecipe()
		g.Kind = "custom"
		response := generationCall(repo, "/api/admin/subscribe-files/generation", generationRequest{Name: node.NodeName, Filename: fmt.Sprintf("unsupported-%d.yaml", index), SelectedNodeIDs: []int64{n.ID}, Generation: g})
		if response.Code != 422 || !strings.Contains(response.Body.String(), "不能加入订阅") {
			t.Fatalf("unsupported node accepted: status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestSubscriptionRuleEditRetainsLegacyNodesWithoutAllowingNewSharedNodes(t *testing.T) {
	repo, _ := generationFixture(t)
	ctx := context.Background()
	ids := []int64{}
	for _, name := range []string{"legacy", "new shared"} {
		node, err := repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: name, Protocol: "ss", Enabled: true, ClashConfig: `{"type":"ss","server":"example.net","port":443,"cipher":"aes-128-gcm","password":"shared"}`})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, node.ID)
	}
	f, err := repo.CreateSubscribeFile(ctx, storage.SubscribeFile{Name: "Legacy", Filename: "legacy.yaml", Type: storage.SubscribeTypeCreate, CreatedBy: "admin", SelectedNodeIDs: ids[:1]})
	if err != nil {
		t.Fatal(err)
	}
	g := generationRecipe()
	g.Kind = "custom"
	g.Outputs[0].RuleMode = "custom"
	g.Outputs[0].RuleCategories = []string{"github"}
	req := generationRequest{ID: f.ID, SelectedNodeIDs: ids[:1], Generation: g}
	for _, path := range []string{"/api/admin/subscribe-files/generation/preview", "/api/admin/subscribe-files/generation"} {
		w := generationCall(repo, path, req)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "GEOSITE,github,PROXY") {
			t.Fatalf("retained legacy nodes rejected: %s status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
	saved, err := repo.GetSubscribeFileByID(ctx, f.ID)
	if err != nil || len(saved.SelectedNodeIDs) != 1 || saved.SelectedNodeIDs[0] != ids[0] || saved.Generation.Outputs[0].RuleCategories[0] != "github" {
		t.Fatalf("rule edit changed selection or lost rules: %+v %v", saved, err)
	}
	// Retention is an edit compatibility rule, not permission to distribute shared credentials.
	if err := validateSubscriptionNodeSelection(ctx, repo, saved); err == nil {
		t.Fatal("strict assignment validation accepted legacy shared nodes")
	}
	req.SelectedNodeIDs = ids
	w := generationCall(repo, "/api/admin/subscribe-files/generation", req)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "new shared") {
		t.Fatalf("new shared node accepted: %d %s", w.Code, w.Body.String())
	}
	saved, _ = repo.GetSubscribeFileByID(ctx, f.ID)
	if len(saved.SelectedNodeIDs) != 1 {
		t.Fatal("rejected edit changed the existing selection")
	}
	// An existing file ID belonging to another owner cannot grant retention.
	saved.CreatedBy = "alice"
	if err := validateSubscriptionNodeSelectionEdit(ctx, repo, saved); err == nil {
		t.Fatal("retained node exemption crossed ownership")
	}

	// Owner's legacy custom subscription can be previewed/used as a strategy source without exposing it to other users.
	strategyGen := generationRecipe(f.ID)
	strategyPreview := generationCall(repo, "/api/admin/subscribe-files/generation/preview", generationRequest{Generation: strategyGen})
	if strategyPreview.Code != 200 || !strings.Contains(strategyPreview.Body.String(), "legacy") {
		t.Fatalf("legacy custom source rejected in strategy preview: %d %s", strategyPreview.Code, strategyPreview.Body.String())
	}
}

func TestAssignedExternalSourceDoesNotExposeOwnerCredentials(t *testing.T) {
	repo, source := generationFixture(t)
	f := storage.SubscribeFile{CreatedBy: "admin", Generation: generationRecipe(source.ID)}
	ctx := context.WithValue(context.Background(), subscriptionViewerKey{}, "alice")
	if _, _, err := NewSubscriptionHandlerConcrete(repo, "subscribes").generateSubscription(ctx, f, ""); err == nil {
		t.Fatal("shared external credentials were sent without attributable per-user identity")
	}
	g := generationRecipe(source.ID)
	strategy, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{Name: "External strategy", Filename: "external-strategy.yaml", CreatedBy: "admin", Type: "create", Generation: g})
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"subscription_ids":[%d]}`, strategy.ID)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/admin/users/alice/subscriptions", strings.NewReader(body)).WithContext(auth.ContextWithUsername(context.Background(), "admin"))
	NewUserSubscriptionsHandler(repo).ServeHTTP(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("non-meterable assignment status=%d", w.Code)
	}
	assigned, err := repo.GetUserSubscriptionIDs(context.Background(), "alice")
	if err != nil || len(assigned) != 0 {
		t.Fatalf("failed assignment changed user grants: %v %v", assigned, err)
	}
}

func TestSubscriptionServerQuotaIsSharedOnceAcrossItsSelectedNodes(t *testing.T) {
	repo, _ := generationFixture(t)
	ctx := context.Background()
	server := &storage.RemoteServer{Name: "grant-edge", Token: "test", IPAddress: "203.0.113.20", XrayMode: "embedded", Status: storage.RemoteServerStatusConnected}
	if err := repo.CreateRemoteServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant, err := repo.CreateUserServerGrant(ctx, storage.UserServerGrant{Username: "alice", ServerID: server.ID, Enabled: true, StartsAt: now.Add(-time.Hour), MaxActiveNodes: 3, TrafficLimitBytes: 10000, BillingMode: storage.ManagedBillingBoth, ResetPolicy: storage.ManagedResetNone, ResetDay: 1, BillingTimezone: "Asia/Singapore", CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	ids := []int64{}
	for _, tag := range []string{"a", "b"} {
		node, err := repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: tag, Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: tag, ClashConfig: `{"type":"vless","uuid":"owner"}`})
		if err != nil {
			t.Fatal(err)
		}
		offer, err := repo.CreateSelfServiceNodeOffer(ctx, node.ID, server.ID, "admin")
		if err != nil {
			t.Fatal(err)
		}
		activation, err := repo.ActivateUserNodeSelection(ctx, "alice", offer.ID, "alice", now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = repo.MarkUserInboundAccessSourceApplied(ctx, activation.Source.ID, activation.Source.Generation, storage.ManagedObservedActive, now); err != nil {
			t.Fatal(err)
		}
		if err = repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{Username: "alice", ServerID: server.ID, InboundTag: tag, Protocol: "vless", CredentialJSON: `{"id":"alice"}`}); err != nil {
			t.Fatal(err)
		}
		credential, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, tag)
		if err != nil {
			t.Fatal(err)
		}
		if err = repo.SetUserNodeSelectionCredential(ctx, activation.Selection.ID, credential.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 0, 0, "boot", now); err != nil {
			t.Fatal(err)
		}
		if _, err = repo.AccumulateUserNodeSelectionUsage(ctx, activation.Selection.ID, 100, 200, "boot", now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, node.ID)
	}
	stats, err := resolveSubscriptionUserTraffic(ctx, repo, "alice", ids)
	_, _, expected, usageErr := repo.GetUserServerGrantUsage(ctx, grant.ID)
	if err != nil || usageErr != nil || stats.Used != expected || stats.Used != 600 || stats.Limit != 10000 || stats.Unlimited {
		t.Fatalf("shared server quota=%+v expected-used=%d err=%v/%v", stats, expected, err, usageErr)
	}
}
