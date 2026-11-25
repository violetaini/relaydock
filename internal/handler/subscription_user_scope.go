package handler

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type subscriptionViewerKey struct{}

func subscriptionGenerationRenderOwner(ctx context.Context, repo *storage.TrafficRepository, owner string) string {
	if viewer, _ := ctx.Value(subscriptionViewerKey{}).(string); viewer != "" && !userIsAdmin(ctx, repo, viewer) {
		return viewer
	}
	return owner
}

func subscriptionNodeAccountingEligibility(node storage.Node) (bool, string) {
	if ok, reason := isPackageNodeMultiUserEligible(node); !ok {
		return false, reason
	}
	if node.NodeType != "routed" && !supportsPerUserInboundCredential(node.Protocol) {
		return false, fmt.Sprintf("协议 %s 尚不支持独立用户凭据与流量统计", node.Protocol)
	}
	if !isDatabaseManagedNode(&node) {
		return false, "未绑定受管服务器和入站，无法按用户统计"
	}
	return true, ""
}

func validateSubscriptionNodeSelection(ctx context.Context, repo *storage.TrafficRepository, f storage.SubscribeFile) error {
	return validateSubscriptionNodeSelectionWithRetained(ctx, repo, f, nil)
}

// Editing rules must not force a legacy subscription to replace its nodes.
// Retained IDs come from storage, never from the proposed selection. New nodes
// and assignment to other users still require per-user accounting eligibility.
func validateSubscriptionNodeSelectionEdit(ctx context.Context, repo *storage.TrafficRepository, f storage.SubscribeFile) error {
	retained := map[int64]bool{}
	if f.ID > 0 && subscriptionKind(f) == "custom" {
		existing, err := repo.GetSubscribeFileByID(ctx, f.ID)
		if err != nil {
			return err
		}
		if existing.CreatedBy == f.CreatedBy && subscriptionKind(existing) == "custom" {
			ids, _, err := subscriptionBoundNodeIDs(ctx, repo, existing)
			if err != nil {
				return err
			}
			for _, id := range ids {
				retained[id] = true
			}
		}
	} else if f.Generation != nil && f.Generation.Kind == "strategy" {
		isAdmin := userIsAdmin(ctx, repo, f.CreatedBy)
		for _, srcID := range f.Generation.SourceIDs {
			if srcID <= 0 || srcID == f.ID {
				continue
			}
			source, err := repo.GetSubscribeFileByID(ctx, srcID)
			if err != nil || subscriptionKind(source) != "custom" {
				continue
			}
			if source.CreatedBy != f.CreatedBy && !(isAdmin && source.CreatedBy == "") {
				continue
			}
			ids, _, err := subscriptionBoundNodeIDs(ctx, repo, source)
			if err != nil {
				return err
			}
			for _, id := range ids {
				retained[id] = true
			}
		}
	}
	return validateSubscriptionNodeSelectionWithRetained(ctx, repo, f, retained)
}

func validateSubscriptionNodeSelectionWithRetained(ctx context.Context, repo *storage.TrafficRepository, f storage.SubscribeFile, retained map[int64]bool) error {
	if f.Generation == nil || f.Generation.Kind == "external" {
		return nil
	}
	ids, _, err := subscriptionBoundNodeIDs(ctx, repo, f)
	if err != nil {
		return err
	}
	if !userIsAdmin(ctx, repo, f.CreatedBy) {
		visible, err := collectUserVisibleNodes(ctx, repo, f.CreatedBy)
		if err != nil {
			return err
		}
		allowed := map[int64]bool{}
		for _, node := range visible {
			allowed[node.ID] = true
		}
		for _, id := range ids {
			if !allowed[id] {
				return errors.New("所选节点已删除或不可访问")
			}
		}
	}
	for _, id := range ids {
		node, err := repo.GetNodeByID(ctx, id)
		if err != nil {
			return errors.New("所选节点已删除或不可访问")
		}
		if ok, reason := subscriptionNodeAccountingEligibility(node); !ok && !retained[id] {
			return fmt.Errorf("节点“%s”不能加入订阅：%s", node.NodeName, reason)
		}
	}
	return nil
}

// Follow the persisted source IDs, rather than a stale list copied when a
// strategy was created. Counting and rendering use the same selected nodes.
func subscriptionBoundNodeIDs(ctx context.Context, repo *storage.TrafficRepository, f storage.SubscribeFile) ([]int64, bool, error) {
	files := []storage.SubscribeFile{f}
	if f.Generation != nil && f.Generation.Kind == "strategy" {
		files = nil
		for _, id := range f.Generation.SourceIDs {
			source, err := repo.GetSubscribeFileByID(ctx, id)
			if err != nil || id == f.ID {
				return nil, false, errors.New("来源订阅已删除或不可访问")
			}
			if source.CreatedBy != f.CreatedBy && (!userIsAdmin(ctx, repo, f.CreatedBy) || (source.CreatedBy != "" && !userIsAdmin(ctx, repo, source.CreatedBy))) {
				return nil, false, errors.New("来源订阅已删除或不可访问")
			}
			if subscriptionKind(source) == "strategy" {
				return nil, false, errors.New("策略订阅不能嵌套")
			}
			files = append(files, source)
		}
	}
	var ids []int64
	seen := map[int64]bool{}
	external := false
	for _, source := range files {
		if subscriptionKind(source) == "external" {
			external = true
			continue
		}
		nodeIDs := source.SelectedNodeIDs
		if len(nodeIDs) == 0 && len(source.SelectedTags) > 0 {
			nodes, err := repo.ListAllNodes(ctx)
			if err != nil {
				return nil, false, err
			}
			tags := map[string]bool{}
			for _, tag := range source.SelectedTags {
				tags[tag] = true
			}
			for _, node := range nodes {
				if node.HasAnyTag(tags) {
					nodeIDs = append(nodeIDs, node.ID)
				}
			}
		}
		for _, id := range nodeIDs {
			if id > 0 && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, external, nil
}

type subscriptionUserTraffic struct {
	Used      int64 `json:"used"`
	Limit     int64 `json:"limit"`
	Unlimited bool  `json:"unlimited"`
}

func subscriptionTrafficAdd(a, b int64) int64 {
	if b <= 0 {
		return a
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// The quota authority is user management: fixed-node overrides/package node
// quotas and server grants. Legacy file caps and whole-server counters are
// deliberately excluded. An unlimited resource cannot become a false finite
// aggregate cap merely because another resource has a quota.
func resolveSubscriptionUserTraffic(ctx context.Context, repo *storage.TrafficRepository, username string, selected []int64) (subscriptionUserTraffic, error) {
	var result subscriptionUserTraffic
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return result, err
	}
	var pkg *storage.Package
	if user.AuthorizationMode == storage.AuthorizationModePackage && user.PackageID > 0 {
		pkg, err = repo.GetPackage(ctx, user.PackageID)
		if err != nil {
			return result, err
		}
	}
	var visible []storage.Node
	if user.Role == storage.RoleAdmin {
		visible, err = repo.ListAllNodes(ctx)
	} else {
		visible, err = collectUserVisibleNodes(ctx, repo, username)
	}
	if err != nil {
		return result, err
	}
	allowed := map[int64]bool{}
	for _, node := range visible {
		if ok, _ := subscriptionNodeAccountingEligibility(node); ok {
			allowed[node.ID] = true
		}
	}
	ids := []int64{}
	for _, id := range selected {
		if allowed[id] {
			ids = append(ids, id)
			delete(allowed, id)
		}
	}
	usage, err := repo.GetUserNodeTraffic(ctx, username, ids, pkg)
	if err != nil {
		return result, err
	}
	grants, err := repo.ListUserServerGrants(ctx, username)
	if err != nil {
		return result, err
	}
	selections, err := repo.ListUserNodeSelections(ctx, username, false)
	if err != nil {
		return result, err
	}
	sources, err := repo.ListUserInboundAccessSources(ctx, username, 0)
	if err != nil {
		return result, err
	}
	nodeBySource := map[int64]int64{}
	for _, source := range sources {
		nodeBySource[source.ID] = source.NodeID
	}
	grantByID := map[int64]storage.UserServerGrant{}
	packageActive := packageAssignmentActive(user, time.Now().UTC())
	for _, grant := range grants {
		if authorizationSourceMatches(user, packageActive, grant.SourceType, grant.SourcePackageID) {
			grantByID[grant.ID] = grant
		}
	}
	selectionByNode := map[int64]storage.UserNodeSelection{}
	for _, selection := range selections {
		if _, ok := grantByID[selection.GrantID]; ok && selection.AccessSourceID != nil {
			selectionByNode[nodeBySource[*selection.AccessSourceID]] = selection
		}
	}
	groupUsed, groupCaps := map[int64]int64{}, map[int64]int64{}
	groupUnlimited := map[int64]bool{}
	for _, id := range ids {
		limitGB, _ := nodeTrafficLimitGB(&user, pkg, id)
		nodeLimit := int64(0)
		if limitGB > 0 && !math.IsNaN(limitGB) && !math.IsInf(limitGB, 0) {
			if limitGB >= float64(math.MaxInt64)/userTrafficLimitBytesPerGB {
				nodeLimit = math.MaxInt64
			} else {
				nodeLimit = int64(math.Round(limitGB * userTrafficLimitBytesPerGB))
			}
		}
		if selection, ok := selectionByNode[id]; ok {
			grant := grantByID[selection.GrantID]
			counter, counterErr := repo.GetUserNodeSelectionUsage(ctx, selection.ID)
			if counterErr != nil && !errors.Is(counterErr, storage.ErrUserNodeSelectionNotFound) {
				return result, counterErr
			}
			used := int64(0)
			if counter != nil {
				mode := grant.BillingMode
				if selection.BillingModeOverride != nil {
					mode = *selection.BillingModeOverride
				}
				used = counter.BilledBytes(mode)
			}
			groupUsed[grant.ID] = subscriptionTrafficAdd(groupUsed[grant.ID], used)
			groupCaps[grant.ID] = subscriptionTrafficAdd(groupCaps[grant.ID], nodeLimit)
			if nodeLimit == 0 {
				groupUnlimited[grant.ID] = true
			}
			continue
		}
		result.Used = subscriptionTrafficAdd(result.Used, usage[id])
		result.Limit = subscriptionTrafficAdd(result.Limit, nodeLimit)
		if nodeLimit == 0 {
			result.Unlimited = true
		}
	}
	for grantID, used := range groupUsed {
		limit := grantByID[grantID].TrafficLimitBytes
		if !groupUnlimited[grantID] && groupCaps[grantID] > 0 && (limit <= 0 || groupCaps[grantID] < limit) {
			limit = groupCaps[grantID]
		}
		result.Used = subscriptionTrafficAdd(result.Used, used)
		result.Limit = subscriptionTrafficAdd(result.Limit, limit)
		if limit <= 0 {
			result.Unlimited = true
		}
	}
	if len(ids) == 0 || result.Unlimited {
		result.Limit = 0
		result.Unlimited = true
	}
	return result, nil
}
