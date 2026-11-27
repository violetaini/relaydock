package handler

import (
	"context"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestManagementPackageQuotaReadsAllTiersAndLivePackageEdits(t *testing.T) {
	f := newServiceAuthorizationFixture(t)
	ctx := context.Background()
	server := f.addServer(t)
	node, err := f.repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: "分层节点", Protocol: "vless", Enabled: true, OriginalServer: server.Name, InboundTag: "tier-node", ClashConfig: `{"name":"tier-node","type":"vless","server":"203.0.113.20","port":443,"uuid":"owner"}`})
	if err != nil {
		t.Fatal(err)
	}
	const gb = float64(1024 * 1024 * 1024)
	id, err := f.repo.CreatePackage(ctx, storage.Package{Name: "分层套餐", TrafficLimitGB: 500 / gb, NodeModuleTrafficLimitGB: 100 / gb, NodeTrafficLimits: map[int64]float64{node.ID: 50 / gb}, Nodes: []int64{node.ID}, CycleDays: 30, ResetDay: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err = f.repo.AssignPackageToUser(ctx, "alice", id, now.Add(-time.Hour), now.Add(24*time.Hour), false, 1); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int64{0, 90} {
		if err = f.repo.UpsertUserTrafficBatch(ctx, server.ID, []storage.UserTrafficSample{{Email: "alice__tier-node", Username: "alice", Downlink: n, BillingMultiplier: 1}}, false); err != nil {
			t.Fatal(err)
		}
	}
	user, err := f.repo.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	read := func() ([]managementResourceUsage, []managementQuotaLayer) {
		t.Helper()
		resources, e := userManagementUsage(ctx, f.repo, user)
		if e != nil {
			t.Fatal(e)
		}
		resources, layers, e := managementPackageQuota(ctx, f.repo, user, resources)
		if e != nil {
			t.Fatal(e)
		}
		return resources, layers
	}
	resources, layers := read()
	if len(layers) != 3 || layers[0].Items[0].Used != 90 || layers[0].Items[0].Limit != 500 || layers[1].Items[0].Used != 90 || layers[2].Items[0].Limit != 50 {
		t.Fatalf("tier counters: %+v", layers)
	}
	overview := buildManagementOverview(user, 90, resources, now, layers...)
	if overview.LimitedResources != 3 || overview.NearLimit != 1 || overview.OverLimit != 1 {
		t.Fatalf("tier risks: %+v", overview)
	}
	pkg, err := f.repo.GetPackage(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	pkg.NodeTrafficLimits = map[int64]float64{}
	pkg.NodeModuleTrafficLimitGB = 0
	pkg.NodeModuleTrafficLimitBytes = 0
	if err = f.repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}
	resources, layers = read()
	if len(layers) != 3 || layers[0].Items[0].Used != 90 || layers[1].Items[0].Limit != 0 || layers[2].Items[0].Limit != 0 {
		t.Fatalf("unlimited tiers must retain structural usage after live edit: %+v", layers)
	}
	overview = buildManagementOverview(user, 90, resources, now, layers...)
	if overview.LimitedResources != 1 || overview.OverLimit != 0 || overview.NearLimit != 0 {
		t.Fatalf("package cap lost after edit: %+v", overview)
	}
	for _, v := range resources {
		if v.Kind == "node" && (v.Limit != 0 || v.LimitNote == "") {
			t.Fatalf("unlimited child must show parent constraint: %+v", v)
		}
	}
	pkg.TrafficLimitGB = 0
	pkg.TrafficLimitBytes = 0
	pkg.NodeModuleTrafficLimitGB = 100 / gb
	pkg.NodeModuleTrafficLimitBytes = 100
	if err = f.repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}
	resources, layers = read()
	if len(layers) != 3 || layers[0].Items[0].Limit != 0 || layers[1].Key != "module" || layers[1].Items[0].Used != 90 || layers[2].Items[0].LimitNote == "" {
		t.Fatalf("module-only quota counters: %+v", layers)
	}
	pkg.NodeModuleTrafficLimitGB = 0
	pkg.NodeModuleTrafficLimitBytes = 0
	if err = f.repo.UpdatePackage(ctx, *pkg); err != nil {
		t.Fatal(err)
	}
	_, layers = read()
	if len(layers) != 3 {
		t.Fatalf("structural layers lost: %+v", layers)
	}
	for _, layer := range layers {
		for _, item := range layer.Items {
			if item.Limit != 0 {
				t.Fatalf("unconfigured limit fabricated: %+v", item)
			}
		}
	}
}
