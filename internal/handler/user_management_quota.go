package handler

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type managementQuotaItem struct {
	Kind  string `json:"kind"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Used  int64  `json:"used"`
	Limit int64  `json:"limit"`
	Reset string `json:"reset,omitempty"`
}
type managementQuotaLayer struct {
	Key   string                `json:"key"`
	Title string                `json:"title"`
	Total int                   `json:"total"`
	Items []managementQuotaItem `json:"items"`
}

// Reuse the enforcement counters, not the overlapping subscription totals.
// The response is a view only; it never changes grants or accounting windows.
func managementPackageQuota(ctx context.Context, repo *storage.TrafficRepository, user storage.User, resources []managementResourceUsage) ([]managementResourceUsage, []managementQuotaLayer, error) {
	layers := []managementQuotaLayer{}
	grants, err := repo.ListUserTunnelGrants(ctx, user.Username)
	if err != nil {
		return nil, nil, err
	}
	for _, g := range grants {
		matches := user.PackageID > 0 && g.SourceType == storage.GrantSourcePackage && g.SourcePackageID != nil && *g.SourcePackageID == user.PackageID || user.PackageID == 0 && g.SourceType == storage.GrantSourceManual
		if !matches {
			continue
		}
		name := "转发线路 #" + strconv.FormatInt(g.TunnelID, 10)
		tunnelState := ""
		if g.Tunnel != nil {
			name = g.Tunnel.Name
			tunnelState = g.Tunnel.State
		}
		resources = append(resources, managementResourceUsage{Kind: "forwarding", ID: g.TunnelID, Name: name, Source: g.SourceType, Used: g.UsedBytes, Limit: g.TrafficLimitBytes, ExpiresAt: g.ExpiresAt, State: g.StateAt(time.Now().UTC(), user.IsActive, tunnelState, g.UsedBytes), Reset: "跟随转发授权周期"})
	}
	if user.PackageID <= 0 || user.AuthorizationMode != storage.AuthorizationModePackage {
		return resources, layers, nil
	}
	pkg, err := repo.GetPackage(ctx, user.PackageID)
	if err != nil {
		return nil, nil, err
	}
	quota, err := evaluatePackageQuotaUsage(ctx, repo, &user, pkg, true)
	if err != nil {
		return nil, nil, err
	}
	moduleLimits := map[string]int64{"node": quota.NodeModuleLimitBytes, "server": quota.ServerModuleLimitBytes, "forwarding": quota.ForwardingModuleLimitBytes}
	moduleUsed := map[string]int64{"node": quota.NodeModuleUsedBytes, "server": quota.ServerModuleUsedBytes, "forwarding": quota.ForwardingModuleUsedBytes}
	moduleNames := map[string]string{"node": "节点模块", "server": "服务器模块", "forwarding": "转发模块"}
	moduleCount := map[string]int{}
	individual := managementQuotaLayer{Key: "resource", Title: "单独资源", Items: []managementQuotaItem{}}
	seen := map[string]bool{}
	for i := range resources {
		v := &resources[i]
		if v.Kind == "package" {
			v.Used = quota.PackageUsedBytes
			v.Limit = quota.PackageLimitBytes
			v.Reset = "各模块按自身周期统计"
			v.Note = "套餐用量汇总节点、服务器与转发模块；不与下级重复累加"
			if quota.PackageOver {
				v.State = "over_limit"
			}
			continue
		}
		if _, ok := moduleNames[v.Kind]; !ok {
			continue
		}
		key := v.Kind + ":" + strconv.FormatInt(v.ID, 10)
		if seen[key] {
			continue
		}
		seen[key] = true
		individual.Total++
		// Selected nodes are already represented by their server module.
		if !v.Related {
			moduleCount[v.Kind]++
		}
		module := v.Kind
		if v.Kind == "node" && v.Related {
			module = "server"
		}
		parents := []string{}
		if quota.PackageLimitBytes > 0 {
			parents = append(parents, "套餐总量")
		}
		if moduleLimits[module] > 0 {
			parents = append(parents, moduleNames[module])
		}
		if len(parents) > 0 {
			v.LimitNote = "受" + strings.Join(parents, "、") + "额度约束"
		}
		if quota.PackageOver || trafficLimitExceeded(moduleUsed[module], moduleLimits[module]) || trafficLimitExceeded(v.Used, v.Limit) {
			if v.State == "active" || v.State == "authorized" {
				v.State = "over_limit"
			}
		}
		if v.Limit > 0 {
			individual.Items = append(individual.Items, managementQuotaItem{Kind: v.Kind, ID: v.ID, Name: v.Name, Used: v.Used, Limit: v.Limit, Reset: v.Reset})
		}
	}
	if quota.PackageLimitBytes > 0 {
		layers = append(layers, managementQuotaLayer{Key: "package", Title: "套餐总量", Total: 1, Items: []managementQuotaItem{{Kind: "package", ID: pkg.ID, Name: pkg.Name, Used: quota.PackageUsedBytes, Limit: quota.PackageLimitBytes, Reset: "各模块按自身周期统计"}}})
	}
	modules := managementQuotaLayer{Key: "module", Title: "模块额度", Items: []managementQuotaItem{}}
	for _, kind := range []string{"node", "server", "forwarding"} {
		if moduleCount[kind] > 0 || moduleLimits[kind] > 0 {
			modules.Total++
			if moduleLimits[kind] > 0 {
				modules.Items = append(modules.Items, managementQuotaItem{Kind: kind, Name: moduleNames[kind], Used: moduleUsed[kind], Limit: moduleLimits[kind], Reset: "模块内各资源按自身周期统计"})
			}
		}
	}
	if len(modules.Items) > 0 {
		layers = append(layers, modules)
	}
	if len(individual.Items) > 0 {
		layers = append(layers, individual)
	}
	return resources, layers, nil
}
