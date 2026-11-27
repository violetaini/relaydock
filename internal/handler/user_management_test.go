package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func managementBatch(t *testing.T, f serviceAuthorizationFixture, req managementBatchRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, e := json.Marshal(req)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	f.handler.HandleManagementBatch(w, httptest.NewRequest(http.MethodPost, "/api/admin/users/management/batch", bytes.NewReader(body)))
	return w
}

func TestUserManagementExcludesAdminAndFiltersPackageResources(t *testing.T) {
	f := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	server := f.addServer(t)
	pid, e := f.repo.CreatePackage(ctx, storage.Package{Name: "全球套餐", CycleDays: 30, ResetDay: 1, ServerGrants: []storage.PackageServerGrant{{ServerID: server.ID, BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone, ResetDay: 1}}})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	if _, e = f.packages.AssignAndProvision(ctx, "alice", pid, now.Add(-time.Hour), now.AddDate(0, 1, 0), false, 1); e != nil {
		t.Fatal(e)
	}
	for _, query := range []string{"", "?server=" + strconv.FormatInt(server.ID, 10), "?package=" + strconv.FormatInt(pid, 10), "?q=alice&sort=name&size=1&page=9"} {
		w := httptest.NewRecorder()
		NewUserManagementListHandler(f.repo).ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/users/management"+query, nil))
		if w.Code != 200 {
			t.Fatalf("query %s: %d %s", query, w.Code, w.Body.String())
		}
		var out struct {
			Users  []managementUser `json:"users"`
			Total  int              `json:"total"`
			Counts map[string]int   `json:"counts"`
			Page   int              `json:"page"`
		}
		if e = json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		if out.Total != 1 || out.Counts["total"] != 1 || len(out.Users) != 1 || out.Users[0].Username != "alice" || out.Page != 1 {
			t.Fatalf("unexpected result: %+v", out)
		}
		if out.Users[0].CreatedAt.IsZero() || len(out.Users[0].Resources) != 1 || out.Users[0].Resources[0].Kind != "server" {
			t.Fatalf("package resource missing: %+v", out.Users[0])
		}
		for _, secret := range []string{"password_hash", "credential_json", "access_token"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("sensitive field exposed")
			}
		}
	}
	w := httptest.NewRecorder()
	NewUserManagementListHandler(f.repo).ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/users/management?server=999999", nil))
	if !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatal(w.Body.String())
	}
}

func TestUserManagementPreviewPreservesGrantsAndAppendRevokeTouchesOnlySelected(t *testing.T) {
	f := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	a := f.addServer(t)
	b := &storage.RemoteServer{Name: "second-edge", Token: "second", IPAddress: "203.0.113.21", XrayMode: "embedded"}
	if e := f.repo.CreateRemoteServer(ctx, b); e != nil {
		t.Fatal(e)
	}
	original, e := f.repo.CreateUserServerGrant(ctx, storage.UserServerGrant{Username: "alice", ServerID: a.ID, Enabled: true, StartsAt: time.Now().Add(-time.Hour), TrafficLimitBytes: 1234, BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone, ResetDay: 1, CreatedBy: "admin"})
	if e != nil {
		t.Fatal(e)
	}
	gb := 10.0
	req := managementBatchRequest{Usernames: []string{"alice"}, Kind: "server", Operation: "append", IDs: []int64{b.ID}, TrafficGB: &gb, Preview: true, ResetDay: 12}
	w := managementBatch(t, f, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	grants, _ := f.repo.ListUserServerGrants(ctx, "alice")
	if len(grants) != 1 {
		t.Fatal("preview changed authorization")
	}
	req.Preview = false
	w = managementBatch(t, f, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	grants, _ = f.repo.ListUserServerGrants(ctx, "alice")
	if len(grants) != 2 {
		t.Fatal(grants)
	}
	aAfter, _ := f.repo.GetUserServerGrant(ctx, original.ID)
	if !aAfter.Enabled || aAfter.TrafficLimitBytes != 1234 || aAfter.Version != original.Version {
		t.Fatal("append altered existing grant")
	}
	// Repeating append with a different limit must preserve the existing grant.
	gb = 20
	w = managementBatch(t, f, req)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, g := range grants {
		if g.ServerID == b.ID {
			current, _ := f.repo.GetUserServerGrant(ctx, g.ID)
			if current.TrafficLimitBytes != 10*1024*1024*1024 {
				t.Fatal("repeat append overwrote quota")
			}
		}
	}
	req.Operation = "revoke"
	w = managementBatch(t, f, req)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	aAfter, _ = f.repo.GetUserServerGrant(ctx, original.ID)
	if !aAfter.Enabled {
		t.Fatal("revoke removed unrelated server")
	}
}

func TestUserManagementBatchRejectsAdminsAndPackageSwitchWithoutConfirmation(t *testing.T) {
	f := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	server := f.addServer(t)
	pid, e := f.repo.CreatePackage(ctx, storage.Package{Name: "test", CycleDays: 30, ResetDay: 1})
	if e != nil {
		t.Fatal(e)
	}
	req := managementBatchRequest{Usernames: []string{"admin"}, Kind: "server", Operation: "append", IDs: []int64{server.ID}, Preview: true}
	if w := managementBatch(t, f, req); w.Code != 400 {
		t.Fatal(w.Body.String())
	}
	req.Usernames = []string{"alice"}
	req.Kind = "package"
	req.IDs = []int64{pid}
	if w := managementBatch(t, f, req); w.Code != 207 {
		t.Fatal(w.Body.String())
	}
	req.ReplaceAuthorization = true
	if w := managementBatch(t, f, req); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	user, _ := f.repo.GetUser(ctx, "alice")
	if user.PackageID != 0 {
		t.Fatal("preview assigned package")
	}
	req.Preview = false
	if w := managementBatch(t, f, req); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	req.Kind = "server"
	req.IDs = []int64{server.ID}
	req.ReplaceAuthorization = false
	req.Preview = true
	if w := managementBatch(t, f, req); w.Code != 207 {
		t.Fatal(w.Body.String())
	}
	user, _ = f.repo.GetUser(ctx, "alice")
	if user.PackageID != pid {
		t.Fatal("conflict changed package")
	}
}

func TestUserManagementDetailDoesNotCountSubscriptionOrPackageTwice(t *testing.T) {
	f := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	server := f.addServer(t)
	if e := f.repo.UpsertUserEmailTraffic(ctx, server.ID, "alice__example", 0, 1024, false); e != nil {
		t.Fatal(e)
	}
	if e := f.repo.UpsertUserEmailTraffic(ctx, server.ID, "alice__example", 0, 2048, false); e != nil {
		t.Fatal(e)
	}
	node, err := f.repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: "计费节点", Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "example", ClashConfig: `{"name":"计费节点","type":"vless","server":"203.0.113.20","port":443,"uuid":"11111111-1111-1111-1111-111111111111"}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.repo.UpsertManualUserNodeGrant(ctx, "alice", node.ID, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"订阅一", "订阅二"} {
		file, e := f.repo.CreateSubscribeFile(ctx, storage.SubscribeFile{Name: name, Type: storage.SubscribeTypeCreate, Filename: name + ".yaml", CreatedBy: "admin", SelectedNodeIDs: []int64{node.ID}, Generation: &storage.SubscriptionGeneration{Kind: "custom", Outputs: []storage.SubscriptionOutput{{Client: "clashmeta", Mode: "nodes"}}}})
		if e != nil {
			t.Fatal(e)
		}
		if e = f.repo.AssignSubscriptionToUser(ctx, "alice", file.ID); e != nil {
			t.Fatal(e)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/admin/users/alice/management", nil)
	r.SetPathValue("username", "alice")
	NewUserManagementDetailHandler(f.repo).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result struct {
		User      userEntry                 `json:"user"`
		Resources []managementResourceUsage `json:"resources"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.User.TrafficUsed != 1024 {
		t.Fatalf("custom user total=%d, expected one counter of 1024", result.User.TrafficUsed)
	}
	if len(result.Resources) != 3 {
		t.Fatalf("resources=%+v", result.Resources)
	}
	for _, v := range result.Resources {
		if v.Kind == "subscription" && (!v.Related || v.Used != 1024) {
			t.Fatalf("subscription must be overlapping view: %+v", v)
		}
	}
	if result.User.Role == storage.RoleAdmin {
		t.Fatal("admin exposed")
	}
	r.SetPathValue("username", "admin")
	w = httptest.NewRecorder()
	NewUserManagementDetailHandler(f.repo).ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Body.String())
	}
}

func TestUserManagementPackageFixedNodesAppearInFiltersAndUsage(t *testing.T) {
	f := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	server := f.addServer(t)
	node, e := f.repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: "套餐固定节点", Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "pkg-vless", ClashConfig: `{"name":"pkg-vless","type":"vless","server":"203.0.113.20","port":443,"uuid":"11111111-1111-1111-1111-111111111111"}`})
	if e != nil {
		t.Fatal(e)
	}
	pid, e := f.repo.CreatePackage(ctx, storage.Package{Name: "固定节点套餐", CycleDays: 30, ResetDay: 1, Nodes: []int64{node.ID}})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	if e = f.repo.AssignPackageToUser(ctx, "alice", pid, now.Add(-time.Hour), now.AddDate(0, 1, 0), false, 1); e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	NewUserManagementListHandler(f.repo).ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/users/management?node="+strconv.FormatInt(node.ID, 10), nil))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var list struct {
		Users []managementUser `json:"users"`
		Total int              `json:"total"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &list); e != nil {
		t.Fatal(e)
	}
	if list.Total != 1 || len(list.Users) != 1 || len(list.Users[0].Resources) != 1 || list.Users[0].Resources[0].Kind != "node" {
		t.Fatalf("fixed package nodes missing: %s", w.Body.String())
	}
	user, _ := f.repo.GetUser(ctx, "alice")
	resources, e := userManagementUsage(ctx, f.repo, user)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, v := range resources {
		if v.Kind == "node" && v.ID == node.ID && v.Source == "package" {
			found = true
		}
	}
	if !found {
		t.Fatalf("package node not in detail: %+v", resources)
	}
}

func TestUserManagementBatchKeepsIndependentQuotasAndReportsPartialFailure(t *testing.T) {
	f := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	server := f.addServer(t)
	if e := f.repo.CreateUser(ctx, "bob", "bob@example.test", "Bob", "hash", storage.RoleUser, ""); e != nil {
		t.Fatal(e)
	}
	gb := 100.0
	req := managementBatchRequest{Usernames: []string{"alice", "bob"}, Kind: "server", Operation: "append", IDs: []int64{server.ID}, TrafficGB: &gb}
	if w := managementBatch(t, f, req); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, name := range req.Usernames {
		grants, e := f.repo.ListUserServerGrants(ctx, name)
		if e != nil || len(grants) != 1 || grants[0].TrafficLimitBytes != 100*1024*1024*1024 {
			t.Fatalf("quota must be independent for %s: %+v %v", name, grants, e)
		}
	}
	pid, e := f.repo.CreatePackage(ctx, storage.Package{Name: "套餐用户", CycleDays: 30, ResetDay: 1})
	if e != nil {
		t.Fatal(e)
	}
	if result := managementBatch(t, f, managementBatchRequest{Usernames: []string{"bob"}, Kind: "package", Operation: "append", IDs: []int64{pid}, ReplaceAuthorization: true}); result.Code != 200 {
		t.Fatal(result.Body.String())
	}
	req.Preview = true
	w := managementBatch(t, f, req)
	if w.Code != 207 {
		t.Fatal(w.Body.String())
	}
	var result struct {
		Results []serviceAuthorizationResult `json:"results"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if len(result.Results) != 2 || result.Results[0].Status != "ready" || result.Results[1].Status != "failed" {
		t.Fatal(w.Body.String())
	}
}
