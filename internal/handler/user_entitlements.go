package handler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// UserServiceEntitlements is the effective read-side authorization exposed to
// the user UI. Servers share the nodes page because that is where users choose
// nodes from an authorized server.
type UserServiceEntitlements struct {
	Nodes        bool `json:"nodes"`
	Subscription bool `json:"subscription"`
	Servers      bool `json:"servers"`
	Forwarding   bool `json:"forwarding"`
}

func (e UserServiceEntitlements) pages() []string {
	pages := make([]string, 0, 3)
	if e.Subscription {
		pages = append(pages, "subscription")
	}
	if e.Nodes || e.Servers {
		pages = append(pages, "nodes")
	}
	if e.Forwarding {
		pages = append(pages, "forwarding")
	}
	return pages
}

func effectivePackageAssignment(ctx context.Context, repo *storage.TrafficRepository, user storage.User, now time.Time) (bool, error) {
	if !packageAssignmentActive(user, now) {
		return false, nil
	}
	overLimit, err := repo.IsUserOverLimit(ctx, user.Username)
	if err != nil {
		return false, fmt.Errorf("resolve package traffic state: %w", err)
	}
	return !overLimit, nil
}

func authorizationSourceMatches(user storage.User, packageActive bool, sourceType string, sourcePackageID *int64) bool {
	switch user.AuthorizationMode {
	case storage.AuthorizationModeCustom:
		return sourceType == storage.GrantSourceManual
	case storage.AuthorizationModePackage:
		return packageActive && sourceType == storage.GrantSourcePackage && sourcePackageID != nil &&
			*sourcePackageID == user.PackageID
	default:
		return false
	}
}

// ResolveEffectiveUserNodeIDs resolves every effective node source through one
// path so the web UI, Telegram bot, and permission derivation cannot drift.
func ResolveEffectiveUserNodeIDs(ctx context.Context, repo *storage.TrafficRepository, username string, now time.Time) ([]int64, error) {
	username = strings.TrimSpace(username)
	if repo == nil || username == "" || now.IsZero() {
		return nil, storage.ErrManagedInvalidArgument
	}
	now = now.UTC()
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}
	if !user.IsActive {
		return []int64{}, nil
	}

	nodeIDs := make([]int64, 0)
	seen := make(map[int64]bool)
	add := func(ids ...int64) {
		for _, id := range ids {
			if id > 0 && !seen[id] {
				seen[id] = true
				nodeIDs = append(nodeIDs, id)
			}
		}
	}

	packageActive, err := effectivePackageAssignment(ctx, repo, user, now)
	if err != nil {
		return nil, err
	}
	if packageActive {
		pkg, packageErr := repo.GetPackage(ctx, user.PackageID)
		if packageErr != nil {
			return nil, fmt.Errorf("resolve package nodes: %w", packageErr)
		}
		if pkg != nil {
			add(pkg.Nodes...)
		}
	}

	managedNodeIDs, err := effectiveManagedNodeIDsAt(ctx, repo, username, now)
	if err != nil {
		return nil, fmt.Errorf("resolve managed nodes: %w", err)
	}
	add(managedNodeIDs...)

	if user.AuthorizationMode == storage.AuthorizationModeCustom {
		directNodeIDs, directErr := repo.ListEffectiveDirectNodeIDs(ctx, username, now)
		if directErr != nil {
			return nil, fmt.Errorf("resolve direct nodes: %w", directErr)
		}
		add(directNodeIDs...)
	}

	effective := make([]int64, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		node, nodeErr := repo.GetNodeByID(ctx, nodeID)
		if nodeErr != nil || !node.Enabled || strings.TrimSpace(node.InboundTag) == "" ||
			strings.TrimSpace(node.OriginalServer) == "" {
			continue
		}
		effective = append(effective, nodeID)
	}
	return effective, nil
}

// ResolveUserServiceEntitlements derives visible user services from effective
// authorization state rather than from the global navigation configuration.
func ResolveUserServiceEntitlements(ctx context.Context, repo *storage.TrafficRepository, username string, now time.Time) (UserServiceEntitlements, error) {
	var entitlements UserServiceEntitlements
	username = strings.TrimSpace(username)
	if repo == nil || username == "" || now.IsZero() {
		return entitlements, storage.ErrManagedInvalidArgument
	}
	now = now.UTC()
	user, err := repo.GetUser(ctx, username)
	if err != nil {
		return entitlements, err
	}
	if !user.IsActive {
		return entitlements, nil
	}

	packageActive, err := effectivePackageAssignment(ctx, repo, user, now)
	if err != nil {
		return entitlements, err
	}
	assignedSubscriptions, err := repo.GetUserSubscriptionIDs(ctx, username)
	if err != nil {
		return entitlements, fmt.Errorf("resolve assigned subscriptions: %w", err)
	}
	entitlements.Subscription = packageActive || len(assignedSubscriptions) > 0

	nodeIDs, err := ResolveEffectiveUserNodeIDs(ctx, repo, username, now)
	if err != nil {
		return entitlements, err
	}
	entitlements.Nodes = len(nodeIDs) > 0

	serverGrants, err := repo.ListUserServerGrants(ctx, username)
	if err != nil {
		return entitlements, fmt.Errorf("resolve server grants: %w", err)
	}
	for _, grant := range serverGrants {
		if !authorizationSourceMatches(user, packageActive, grant.SourceType, grant.SourcePackageID) {
			continue
		}
		_, _, billed, usageErr := repo.GetUserServerGrantUsage(ctx, grant.ID)
		if usageErr != nil {
			return entitlements, fmt.Errorf("resolve server grant usage: %w", usageErr)
		}
		if grant.StateAt(now, user.IsActive, billed) == storage.ManagedGrantActive {
			entitlements.Servers = true
			break
		}
	}

	tunnelGrants, err := repo.ListUserTunnelGrants(ctx, username)
	if err != nil {
		return entitlements, fmt.Errorf("resolve forwarding grants: %w", err)
	}
	for _, grant := range tunnelGrants {
		if !authorizationSourceMatches(user, packageActive, grant.SourceType, grant.SourcePackageID) {
			continue
		}
		tunnelState := storage.TunnelStateSuspended
		if grant.Tunnel != nil {
			tunnelState = grant.Tunnel.State
		}
		if grant.StateAt(now, user.IsActive, tunnelState, grant.UsedBytes) == storage.ManagedGrantActive {
			entitlements.Forwarding = true
			break
		}
	}

	return entitlements, nil
}
