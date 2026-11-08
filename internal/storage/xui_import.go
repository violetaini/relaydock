package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/xui"
)

// ImportXUIModel imports parsed 3x-ui inbounds into RelayDock nodes and inventory.
// This operation is strictly internal to RelayDock database and does NOT stop,
// disrupt, or mutate the running 3x-ui services on remote machines.
func (r *TrafficRepository) ImportXUIModel(ctx context.Context, model *xui.XUIModel, req *xui.XUIImportRequest) (*xui.XUIImportResult, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if model == nil || len(model.Inbounds) == 0 {
		return nil, errors.New("empty 3x-ui model")
	}
	if req == nil {
		req = &xui.XUIImportRequest{}
	}

	start := time.Now()
	result := &xui.XUIImportResult{
		Success:  true,
		Warnings: make([]string, 0),
		Errors:   make([]string, 0),
	}

	// 1. Resolve target username
	targetUser := strings.TrimSpace(req.TargetUsername)
	if targetUser == "" {
		// Default to first active admin
		var admin string
		err := r.db.QueryRowContext(ctx, "SELECT username FROM users WHERE role = 'admin' AND is_active = 1 ORDER BY id ASC LIMIT 1").Scan(&admin)
		if err != nil || admin == "" {
			return nil, errors.New("no active administrator account found to own imported nodes")
		}
		targetUser = admin
	} else {
		// Verify user exists
		var exists int
		_ = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE username = ?", targetUser).Scan(&exists)
		if exists == 0 {
			return nil, fmt.Errorf("target user '%s' does not exist", targetUser)
		}
	}

	// 2. Load remote servers for mapping
	servers, err := r.ListRemoteServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list remote servers: %w", err)
	}
	serverByID := make(map[int64]*RemoteServer)
	serverByIP := make(map[string]*RemoteServer)
	for i := range servers {
		s := &servers[i]
		serverByID[s.ID] = s
		if s.IPAddress != "" {
			serverByIP[s.IPAddress] = s
		}
	}

	// 3. Filter inbounds if specified
	filterMap := make(map[int64]bool)
	if len(req.InboundIDs) > 0 {
		for _, id := range req.InboundIDs {
			filterMap[id] = true
		}
	}

	// Map client traffics by inbound ID and email for fast lookup
	trafficByInboundEmail := make(map[string]*xui.XUIClientTraffic)
	for i := range model.ClientTraffics {
		ct := &model.ClientTraffics[i]
		key := fmt.Sprintf("%d:%s", ct.InboundID, strings.ToLower(strings.TrimSpace(ct.Email)))
		trafficByInboundEmail[key] = ct
	}

	// 4. Process each inbound
	for _, ib := range model.Inbounds {
		if len(filterMap) > 0 && !filterMap[ib.ID] {
			continue
		}

		// Determine target server ID
		var targetServerID int64
		if mappedID, ok := req.ServerMappings[ib.ID]; ok && mappedID > 0 {
			targetServerID = mappedID
		} else if req.DefaultServerID > 0 {
			targetServerID = req.DefaultServerID
		} else if ib.Listen != "" && ib.Listen != "0.0.0.0" && ib.Listen != "::" {
			if s, ok := serverByIP[ib.Listen]; ok {
				targetServerID = s.ID
			}
		} else if len(servers) == 1 {
			targetServerID = servers[0].ID
		}

		targetHost := "127.0.0.1"
		targetServerName := "Imported-XUI"
		if s, ok := serverByID[targetServerID]; ok {
			targetHost = s.IPAddress
			targetServerName = s.Name
		}

		// Process clients (or single default client if empty)
		clientsToImport := ib.Clients
		if len(clientsToImport) == 0 {
			clientsToImport = []xui.XUIClient{{ID: "", Email: fmt.Sprintf("%s-%d", ib.Protocol, ib.Port), Enable: true}}
		}

		for _, cli := range clientsToImport {
			candidate, err := xui.ConvertXUIInboundToNodeCandidate(&ib, &cli, targetHost, targetServerName)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Inbound %s port %d convert failed: %v", ib.Tag, ib.Port, err))
				continue
			}

			// Generate distinct node name if multiple clients
			nodeName := candidate.NodeName
			if len(clientsToImport) > 1 && cli.Email != "" {
				nodeName = fmt.Sprintf("%s (%s)", nodeName, cli.Email)
			}

			node := Node{
				Username:       targetUser,
				RawURL:         candidate.Link,
				NodeName:       nodeName,
				Protocol:       candidate.NodeType,
				ParsedConfig:   candidate.ConfigJSON,
				ClashConfig:    candidate.ConfigJSON,
				Enabled:        ib.Enable && cli.Enable,
				Tag:            targetServerName,
				Tags:           []string{strings.ToUpper(ib.Protocol), targetServerName},
				OriginalServer: candidate.ServerHost,
				InboundTag:     ib.Tag,
				NodeType:       "physical",
			}

			// Save node into RelayDock
			created, err := r.CreateNode(ctx, node)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to store node %s: %v", nodeName, err))
				continue
			}
			result.ImportedNodes++

			// Bind client email for telemetry & user subaccount
			if cli.Email != "" && targetServerID > 0 {
				credMap := map[string]interface{}{
					"email": cli.Email,
				}
				if cli.ID != "" {
					credMap["id"] = cli.ID
				}
				if cli.Password != "" {
					credMap["password"] = cli.Password
				}
				credJSON, _ := json.Marshal(credMap)

				wasNew, bindErr := r.EnsureAdminInboundClient(ctx, targetUser, targetServerID, ib.Tag, ib.Protocol, string(credJSON))
				if bindErr == nil && wasNew {
					result.ImportedClients++
				}
			}

			// Import historical traffic if requested
			if req.ImportHistoricalTraffic && targetServerID > 0 && cli.Email != "" {
				tKey := fmt.Sprintf("%d:%s", ib.ID, strings.ToLower(strings.TrimSpace(cli.Email)))
				if ct, found := trafficByInboundEmail[tKey]; found && (ct.Up > 0 || ct.Down > 0) {
					_, _ = r.db.ExecContext(ctx, `
INSERT INTO user_email_traffic (server_id, email, uplink, downlink)
VALUES (?, ?, ?, ?)
ON CONFLICT(server_id, email) DO UPDATE SET uplink = MAX(user_email_traffic.uplink, excluded.uplink), downlink = MAX(user_email_traffic.downlink, excluded.downlink)`,
						targetServerID, ct.Email, ct.Up, ct.Down,
					)
					result.ImportedTrafficRecords++
				}
			}

			_ = created
		}

		// Create managed inbound inventory entry if requested
		if req.CreateManagedResources && targetServerID > 0 {
			_, err := r.db.ExecContext(ctx, `
INSERT INTO managed_inbound_resources (server_id, display_name, protocol, inbound_tag, endpoint_host, endpoint_port, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(server_id, inbound_tag) DO UPDATE SET
    display_name = excluded.display_name,
    endpoint_port = excluded.endpoint_port,
    endpoint_host = excluded.endpoint_host,
    updated_at = CURRENT_TIMESTAMP`,
				targetServerID, ib.Remark, ib.Protocol, ib.Tag, targetHost, ib.Port, targetUser,
			)
			if err == nil {
				result.CreatedManagedInbounds++
			}
		}
	}

	result.ExecutionTime = time.Since(start).String()
	return result, nil
}
