package handler

import (
	"context"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// effectiveManagedNodeIDs is the shared read-side access resolver used by node
// lists and subscriptions. Desired state is authoritative, so revocation takes
// effect locally even while an offline Agent is still being reconciled.
func effectiveManagedNodeIDs(ctx context.Context, repo *storage.TrafficRepository, username string) ([]int64, error) {
	entries, err := repo.ListManagedNodeCatalog(ctx, username, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(entries))
	seen := make(map[int64]bool, len(entries))
	for _, entry := range entries {
		if !entry.Offer.Enabled || entry.Selection == nil || !entry.Selection.DesiredEnabled ||
			entry.GrantStatus != storage.ManagedGrantActive || entry.AccessSource == nil ||
			entry.AccessSource.NodeID != entry.Offer.NodeID || entry.AccessSource.ServerID != entry.Offer.ServerID ||
			entry.AccessSource.InboundTag != entry.Offer.InboundTag ||
			entry.AccessSource.DesiredState != storage.ManagedDesiredActive ||
			entry.AccessSource.ObservedState != storage.ManagedObservedActive ||
			entry.AccessSource.Generation != entry.AccessSource.AppliedGeneration ||
			seen[entry.Offer.NodeID] {
			continue
		}
		node, nodeErr := repo.GetNodeByID(ctx, entry.Offer.NodeID)
		server, serverErr := repo.GetRemoteServer(ctx, entry.Offer.ServerID)
		if nodeErr != nil || serverErr != nil || !entry.Grant.AllowsNodeProtocol(node.Protocol, node.ClashConfig) ||
			!storage.SelfServiceNodeOfferAvailable(entry.Offer, node, *server) {
			continue
		}
		if entry.Selection.CredentialConfigID == nil {
			continue
		}
		credential, credentialErr := repo.GetUserInboundConfig(ctx, username, entry.Offer.ServerID, entry.Offer.InboundTag)
		if credentialErr != nil || credential.ID != *entry.Selection.CredentialConfigID ||
			!storage.SelfServiceCredentialProtocolMatches(credential.Protocol, node.Protocol) {
			continue
		}
		seen[entry.Offer.NodeID] = true
		ids = append(ids, entry.Offer.NodeID)
	}
	return ids, nil
}

func hasEffectiveManagedNodeAccess(ctx context.Context, repo *storage.TrafficRepository, username string, nodeID int64) bool {
	ids, err := effectiveManagedNodeIDs(ctx, repo, username)
	if err != nil {
		return false
	}
	for _, id := range ids {
		if id == nodeID {
			return true
		}
	}
	return false
}
