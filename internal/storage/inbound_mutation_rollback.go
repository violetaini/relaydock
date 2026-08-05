package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RestoreDesiredInboundIfMutation restores the control-plane intent that was
// present immediately before a rejected Agent mutation. The mutation/state
// predicate is the fencing boundary: a delayed rollback can never overwrite a
// newer same-tag generation.
func (r *TrafficRepository) RestoreDesiredInboundIfMutation(
	ctx context.Context,
	serverID int64,
	inboundTag, stagedMutationID, stagedState string,
	previous *DesiredInbound,
) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	stagedMutationID = strings.TrimSpace(stagedMutationID)
	stagedState = strings.TrimSpace(stagedState)
	if serverID <= 0 || inboundTag == "" ||
		(stagedState != DesiredInboundStateActive && stagedState != DesiredInboundStateDeleted) {
		return false, errors.New("server id, inbound tag, and staged desired state are required")
	}

	var (
		result interface{ RowsAffected() (int64, error) }
		err    error
	)
	if previous == nil {
		result, err = r.db.ExecContext(ctx, `
DELETE FROM remote_inbound_desired
WHERE server_id = ? AND inbound_tag = ? AND mutation_id = ? AND desired_state = ?`,
			serverID, inboundTag, stagedMutationID, stagedState)
	} else {
		if previous.ServerID != serverID || strings.TrimSpace(previous.InboundTag) != inboundTag {
			return false, errors.New("previous desired inbound does not match rollback target")
		}
		updatedAt := previous.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = time.Now().UTC()
		}
		result, err = r.db.ExecContext(ctx, `
UPDATE remote_inbound_desired
SET mutation_id = ?, inbound_json = ?, desired_state = ?, updated_at = ?
WHERE server_id = ? AND inbound_tag = ? AND mutation_id = ? AND desired_state = ?`,
			strings.TrimSpace(previous.MutationID), string(previous.InboundJSON), previous.DesiredState, updatedAt,
			serverID, inboundTag, stagedMutationID, stagedState)
	}
	if err != nil {
		return false, fmt.Errorf("restore desired inbound mutation: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read restored desired inbound count: %w", err)
	}
	return count == 1, nil
}

// RestoreRemoteInboundOwnershipIfMutation restores the pre-reservation owner
// only while the row still belongs to the rejected generation.
func (r *TrafficRepository) RestoreRemoteInboundOwnershipIfMutation(
	ctx context.Context,
	serverID int64,
	inboundTag, stagedMutationID, previousMutationID string,
) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("traffic repository not initialized")
	}
	inboundTag = strings.TrimSpace(inboundTag)
	stagedMutationID = strings.TrimSpace(stagedMutationID)
	previousMutationID = strings.TrimSpace(previousMutationID)
	if serverID <= 0 || inboundTag == "" || stagedMutationID == "" {
		return false, errors.New("server id, inbound tag, and staged mutation id are required")
	}

	var (
		result interface{ RowsAffected() (int64, error) }
		err    error
	)
	if previousMutationID == "" {
		result, err = r.db.ExecContext(ctx, `
DELETE FROM remote_inbound_ownership
WHERE server_id = ? AND inbound_tag = ? AND mutation_id = ?`,
			serverID, inboundTag, stagedMutationID)
	} else {
		result, err = r.db.ExecContext(ctx, `
UPDATE remote_inbound_ownership
SET mutation_id = ?, updated_at = ?
WHERE server_id = ? AND inbound_tag = ? AND mutation_id = ?`,
			previousMutationID, time.Now().UTC(), serverID, inboundTag, stagedMutationID)
	}
	if err != nil {
		return false, fmt.Errorf("restore remote inbound ownership: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read restored remote inbound ownership count: %w", err)
	}
	return count == 1, nil
}
