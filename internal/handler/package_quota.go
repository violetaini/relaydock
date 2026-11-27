package handler

import (
	"context"
	"math"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// PackageQuotaState captures the evaluated three-tier quota status for a
// package-mode user:
//   - Tier 1: PackageTotal (TrafficLimitBytes) -> disables all modules if exceeded
//   - Tier 2: ModuleTotals (NodeModule / ServerModule / ForwardingModule / SubscribeModule) -> disables only that module if exceeded
//   - Tier 3: Individual resources (per-node / per-server / per-tunnel / per-subscribe) -> evaluated separately per resource
//
// Any tier with limit <= 0 is treated as unlimited/unconfigured, so 1-tier,
// 2-tier, and 3-tier configurations all work seamlessly.
type PackageQuotaState struct {
	PackageLimitBytes int64
	PackageUsedBytes  int64
	PackageOver       bool

	NodeModuleLimitBytes int64
	NodeModuleUsedBytes  int64
	NodeModuleOver       bool

	ServerModuleLimitBytes int64
	ServerModuleUsedBytes  int64
	ServerModuleOver       bool

	ForwardingModuleLimitBytes int64
	ForwardingModuleUsedBytes  int64
	ForwardingModuleOver       bool

	SubscribeModuleLimitBytes int64
	SubscribeModuleUsedBytes  int64
	SubscribeModuleOver       bool

	SubscribeUsedByID   map[int64]int64
	SubscribeOver       map[int64]bool
	SubscribeNodeDenied map[int64]bool
}

func evaluatePackageQuotaState(ctx context.Context, repo *storage.TrafficRepository, user *storage.User, pkg *storage.Package) (PackageQuotaState, error) {
	return evaluatePackageQuotaUsage(ctx, repo, user, pkg, false)
}

// Views need usage even for unconfigured tiers; enforcement can skip those reads.
func evaluatePackageQuotaUsage(ctx context.Context, repo *storage.TrafficRepository, user *storage.User, pkg *storage.Package, allUsage bool) (PackageQuotaState, error) {
	var state PackageQuotaState
	if repo == nil || user == nil || pkg == nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID <= 0 {
		return state, nil
	}

	state.PackageLimitBytes = pkg.TrafficLimitBytes
	state.NodeModuleLimitBytes = pkg.NodeModuleTrafficLimitBytes
	state.ServerModuleLimitBytes = pkg.ServerModuleTrafficLimitBytes
	state.ForwardingModuleLimitBytes = pkg.ForwardingModuleTrafficLimitBytes
	state.SubscribeModuleLimitBytes = pkg.SubscribeModuleTrafficLimitBytes

	hasSubLimits := false
	for _, gb := range pkg.SubscribeTrafficLimits {
		if gb > 0 {
			hasSubLimits = true
			break
		}
	}

	if state.PackageLimitBytes <= 0 &&
		state.NodeModuleLimitBytes <= 0 &&
		state.ServerModuleLimitBytes <= 0 &&
		state.ForwardingModuleLimitBytes <= 0 &&
		state.SubscribeModuleLimitBytes <= 0 &&
		!hasSubLimits && !allUsage {
		return state, nil
	}

	needTotal := state.PackageLimitBytes > 0 || allUsage
	var cachedNodeUsage map[int64]int64

	if (needTotal || state.NodeModuleLimitBytes > 0) && len(pkg.Nodes) > 0 {
		nodeIDs := make([]int64, 0, len(pkg.Nodes))
		seen := make(map[int64]struct{}, len(pkg.Nodes))
		for _, id := range pkg.Nodes {
			if id <= 0 {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			nodeIDs = append(nodeIDs, id)
		}
		if len(nodeIDs) > 0 {
			usage, err := repo.GetUserNodeTraffic(ctx, user.Username, nodeIDs, pkg)
			if err != nil {
				return state, err
			}
			cachedNodeUsage = usage
			for _, id := range nodeIDs {
				state.NodeModuleUsedBytes += usage[id]
			}
		}
	}

	if (needTotal || state.SubscribeModuleLimitBytes > 0 || hasSubLimits) && len(pkg.SubscribeFileIDs) > 0 {
		subNodeMap, uniqueSubNodes := repo.GetPackageSubscribeNodeMap(ctx, pkg.SubscribeFileIDs)
		if len(uniqueSubNodes) > 0 {
			subUsage := cachedNodeUsage
			if subUsage == nil {
				var err error
				subUsage, err = repo.GetUserNodeTraffic(ctx, user.Username, uniqueSubNodes, pkg)
				if err != nil {
					return state, err
				}
			}
			for _, nid := range uniqueSubNodes {
				state.SubscribeModuleUsedBytes += subUsage[nid]
			}
			state.SubscribeUsedByID = make(map[int64]int64, len(pkg.SubscribeFileIDs))
			state.SubscribeOver = make(map[int64]bool, len(pkg.SubscribeFileIDs))
			state.SubscribeNodeDenied = make(map[int64]bool, len(uniqueSubNodes))
			for _, subID := range pkg.SubscribeFileIDs {
				nids := subNodeMap[subID]
				var used int64
				for _, nid := range nids {
					used += subUsage[nid]
				}
				state.SubscribeUsedByID[subID] = used
				if limitGB := pkg.SubscribeTrafficLimits[subID]; limitGB > 0 && !math.IsNaN(limitGB) && !math.IsInf(limitGB, 0) {
					limitBytes := int64(math.Round(limitGB * 1024 * 1024 * 1024))
					if trafficLimitExceeded(used, limitBytes) {
						state.SubscribeOver[subID] = true
						for _, nid := range nids {
							state.SubscribeNodeDenied[nid] = true
						}
					}
				}
			}
		}
	}

	if needTotal || state.ServerModuleLimitBytes > 0 {
		grants, err := repo.ListUserServerGrants(ctx, user.Username)
		if err != nil {
			return state, err
		}
		for _, g := range grants {
			if g.SourceType != storage.GrantSourcePackage || g.SourcePackageID == nil || *g.SourcePackageID != pkg.ID {
				continue
			}
			_, _, billed, err := repo.GetUserServerGrantUsage(ctx, g.ID)
			if err != nil {
				return state, err
			}
			state.ServerModuleUsedBytes += billed
		}
	}

	if needTotal || state.ForwardingModuleLimitBytes > 0 {
		grants, err := repo.ListUserTunnelGrants(ctx, user.Username)
		if err != nil {
			return state, err
		}
		for _, g := range grants {
			if g.SourceType != storage.GrantSourcePackage || g.SourcePackageID == nil || *g.SourcePackageID != pkg.ID {
				continue
			}
			state.ForwardingModuleUsedBytes += g.UsedBytes
		}
	}

	// Note: pkg.Nodes already includes panel nodes from pkg.SubscribeFileIDs, so NodeModuleUsedBytes
	// already accounts for subscription panel nodes without double counting.
	state.PackageUsedBytes = state.NodeModuleUsedBytes + state.ServerModuleUsedBytes + state.ForwardingModuleUsedBytes
	state.PackageOver = trafficLimitExceeded(state.PackageUsedBytes, state.PackageLimitBytes)
	state.NodeModuleOver = state.PackageOver || trafficLimitExceeded(state.NodeModuleUsedBytes, state.NodeModuleLimitBytes)
	state.ServerModuleOver = state.PackageOver || trafficLimitExceeded(state.ServerModuleUsedBytes, state.ServerModuleLimitBytes)
	state.ForwardingModuleOver = state.PackageOver || trafficLimitExceeded(state.ForwardingModuleUsedBytes, state.ForwardingModuleLimitBytes)
	state.SubscribeModuleOver = state.PackageOver || trafficLimitExceeded(state.SubscribeModuleUsedBytes, state.SubscribeModuleLimitBytes)
	if state.SubscribeModuleOver && len(pkg.SubscribeFileIDs) > 0 {
		_, uniqueSubNodes := repo.GetPackageSubscribeNodeMap(ctx, pkg.SubscribeFileIDs)
		if state.SubscribeNodeDenied == nil {
			state.SubscribeNodeDenied = make(map[int64]bool, len(uniqueSubNodes))
		}
		for _, nid := range uniqueSubNodes {
			state.SubscribeNodeDenied[nid] = true
		}
	}
	return state, nil
}

func resolveUserPackageQuotaCached(
	ctx context.Context,
	repo *storage.TrafficRepository,
	user *storage.User,
	pkgCache map[int64]*storage.Package,
	quotaCache map[string]PackageQuotaState,
) PackageQuotaState {
	if repo == nil || user == nil || user.AuthorizationMode != storage.AuthorizationModePackage || user.PackageID <= 0 {
		return PackageQuotaState{}
	}
	if quotaCache != nil {
		if cached, ok := quotaCache[user.Username]; ok {
			return cached
		}
	}
	var pkg *storage.Package
	if pkgCache != nil {
		pkg = pkgCache[user.PackageID]
	}
	if pkg == nil {
		loaded, err := repo.GetPackage(ctx, user.PackageID)
		if err != nil {
			return PackageQuotaState{}
		}
		pkg = loaded
		if pkgCache != nil {
			pkgCache[user.PackageID] = pkg
		}
	}
	state, err := evaluatePackageQuotaState(ctx, repo, user, pkg)
	if err != nil {
		return PackageQuotaState{}
	}
	if quotaCache != nil {
		quotaCache[user.Username] = state
	}
	return state
}

func effectiveManagedGrantState(
	ctx context.Context,
	repo *storage.TrafficRepository,
	user storage.User,
	grant storage.UserServerGrant,
	billedBytes int64,
	now time.Time,
	pkgCache map[int64]*storage.Package,
	quotaCache map[string]PackageQuotaState,
) string {
	state := grant.StateAt(now, user.IsActive, billedBytes)
	if state != storage.ManagedGrantActive {
		return state
	}
	if grant.SourceType == storage.GrantSourcePackage && grant.SourcePackageID != nil &&
		user.AuthorizationMode == storage.AuthorizationModePackage && user.PackageID == *grant.SourcePackageID {
		quota := resolveUserPackageQuotaCached(ctx, repo, &user, pkgCache, quotaCache)
		if quota.ServerModuleOver {
			return storage.ManagedGrantOverLimit
		}
	}
	return state
}

func effectiveTunnelGrantState(
	ctx context.Context,
	repo *storage.TrafficRepository,
	user storage.User,
	grant storage.UserTunnelGrant,
	tunnelState string,
	now time.Time,
	pkgCache map[int64]*storage.Package,
	quotaCache map[string]PackageQuotaState,
) string {
	state := grant.StateAt(now, user.IsActive, tunnelState, grant.UsedBytes)
	if state != "active" && state != "tunnel_draining" {
		return state
	}
	if grant.SourceType == storage.GrantSourcePackage && grant.SourcePackageID != nil &&
		user.AuthorizationMode == storage.AuthorizationModePackage && user.PackageID == *grant.SourcePackageID {
		quota := resolveUserPackageQuotaCached(ctx, repo, &user, pkgCache, quotaCache)
		if quota.ForwardingModuleOver {
			return "over_limit"
		}
	}
	return state
}
