package storage

import (
	"context"
	"errors"
)

type ForwardServerDomainChange struct {
	ServerID int64
	Before   string
	After    string
}

// ReplaceForwardNode atomically records the remote intent, inherited client
// configuration and explicit relationship. CAS prevents overwriting concurrent
// node/desired-state edits. It is also used to compensate a rejected Agent write.
func (r *TrafficRepository) ReplaceForwardNode(ctx context.Context, before, after Node, target *Node, targetID int64, targetHost string, oldDesired, desired DesiredInbound, domains ...ForwardServerDomainChange) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, change := range domains {
		res, err := tx.ExecContext(ctx, `UPDATE remote_servers SET domain=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND COALESCE(domain,'')=?`, change.After, change.ServerID, change.Before)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("服务器节点域名已变化，请刷新后重试")
		}
	}
	var duplicate int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE username=? AND node_name=? AND id!=?`, before.Username, after.NodeName, before.ID).Scan(&duplicate); err != nil {
		return err
	}
	if duplicate > 0 {
		return errors.New("节点名称已存在，请使用其他名称")
	}
	if target != nil {
		var config string
		var enabled bool
		if err := tx.QueryRowContext(ctx, `SELECT clash_config,enabled FROM nodes WHERE id=?`, target.ID).Scan(&config, &enabled); err != nil {
			return err
		}
		if config != target.ClashConfig || !enabled {
			return errors.New("目标节点已变化，请刷新后重试")
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE remote_inbound_desired SET inbound_json=?, updated_at=CURRENT_TIMESTAMP WHERE server_id=? AND inbound_tag=? AND mutation_id=? AND desired_state='active' AND inbound_json=?`, string(desired.InboundJSON), oldDesired.ServerID, oldDesired.InboundTag, oldDesired.MutationID, string(oldDesired.InboundJSON))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrDesiredInboundMutationChanged
	}
	tags := serializeNodeTags(&after)
	res, err = tx.ExecContext(ctx, `UPDATE nodes SET raw_url='',node_name=?,protocol=?,parsed_config=?,clash_config=?,enabled=?,tag=?,tags=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND node_type='forwarded' AND clash_config=? AND node_name=? AND enabled=? AND original_server=? AND inbound_tag=? AND inbound_mutation_id=?`, after.NodeName, after.Protocol, after.ParsedConfig, after.ClashConfig, after.Enabled, after.Tag, tags, before.ID, before.ClashConfig, before.NodeName, before.Enabled, before.OriginalServer, before.InboundTag, before.InboundMutationID)
	if err != nil {
		return err
	}
	n, err = res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("转发节点已变化，请刷新后重试")
	}
	if targetID > 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO node_forward_targets(node_id,target_node_id,target_host) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET target_node_id=excluded.target_node_id,target_host=excluded.target_host,updated_at=CURRENT_TIMESTAMP`, before.ID, targetID, targetHost)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM node_forward_targets WHERE node_id=?`, before.ID)
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	r.invalidateTrafficBillingCache()
	return nil
}

// ForwardNodeTargetHosts returns the administrator's DNS overrides, without
// resolving or replacing them with an IP address.
func (r *TrafficRepository) ForwardNodeTargetHosts(ctx context.Context) (map[int64]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT f.node_id,f.target_host FROM node_forward_targets f JOIN nodes n ON n.id=f.node_id WHERE n.node_type='forwarded'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[int64]string{}
	for rows.Next() {
		var id int64
		var host string
		if err := rows.Scan(&id, &host); err != nil {
			return nil, err
		}
		result[id] = host
	}
	return result, rows.Err()
}
