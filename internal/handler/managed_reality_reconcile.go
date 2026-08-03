package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

func isVLESSRealityInbound(inbound map[string]interface{}) bool {
	protocol, _ := inbound["protocol"].(string)
	if !strings.EqualFold(strings.TrimSpace(protocol), "vless") {
		return false
	}
	stream, _ := inbound["streamSettings"].(map[string]interface{})
	security, _ := stream["security"].(string)
	return strings.EqualFold(strings.TrimSpace(security), "reality")
}

func managedRealityClientFromNode(node *storage.Node, owner string) (map[string]interface{}, bool, error) {
	if node == nil || strings.TrimSpace(node.ClashConfig) == "" {
		return nil, false, nil
	}
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(node.ClashConfig), &config); err != nil {
		return nil, false, fmt.Errorf("parse managed node config: %w", err)
	}
	protocol, _ := config["type"].(string)
	if !strings.EqualFold(strings.TrimSpace(protocol), "vless") {
		return nil, false, nil
	}
	id, _ := config["uuid"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, false, nil
	}
	client := map[string]interface{}{
		"id":    id,
		"email": strings.TrimSpace(owner),
	}
	if flow, _ := config["flow"].(string); strings.TrimSpace(flow) != "" {
		client["flow"] = strings.TrimSpace(flow)
	}
	return client, true, nil
}

// reconcileManagedRealityInbound restores the stable credential already published
// by the panel while retaining unrelated clients on the same inbound.
func reconcileManagedRealityInbound(inbound map[string]interface{}, node *storage.Node, owner string) (map[string]interface{}, bool, bool, error) {
	if !isVLESSRealityInbound(inbound) {
		return inbound, false, false, nil
	}
	desired, managed, err := managedRealityClientFromNode(node, owner)
	if err != nil || !managed {
		return inbound, false, managed, err
	}
	candidate, err := cloneInboundConfig(inbound)
	if err != nil {
		return inbound, false, true, fmt.Errorf("clone Reality inbound: %w", err)
	}
	compatibilityChanged := applyManagedRealityCompatibilityToInbound(candidate)
	settings, _ := candidate["settings"].(map[string]interface{})
	if settings == nil {
		return inbound, false, true, errorsForRealitySettings()
	}
	rawClients, exists := settings["clients"]
	clients, ok := rawClients.([]interface{})
	if exists && !ok {
		return inbound, false, true, fmt.Errorf("Reality inbound clients is not an array")
	}

	owner = strings.TrimSpace(owner)
	desiredID, _ := desired["id"].(string)
	newOwner := map[string]interface{}{}
	for key, value := range desired {
		newOwner[key] = value
	}
	remaining := make([]interface{}, 0, len(clients))
	for _, rawClient := range clients {
		client, _ := rawClient.(map[string]interface{})
		if client == nil {
			remaining = append(remaining, rawClient)
			continue
		}
		clientEmail, _ := client["email"].(string)
		clientID, _ := client["id"].(string)
		if strings.TrimSpace(clientEmail) == owner || strings.TrimSpace(clientID) == desiredID {
			for key, value := range client {
				switch key {
				case "id", "email", "flow":
					continue
				default:
					newOwner[key] = value
				}
			}
			continue
		}
		remaining = append(remaining, rawClient)
	}
	settings["clients"] = append([]interface{}{newOwner}, remaining...)
	candidate["settings"] = settings
	return candidate, compatibilityChanged || !reflect.DeepEqual(candidate, inbound), true, nil
}

func errorsForRealitySettings() error {
	return fmt.Errorf("Reality inbound has no settings")
}

func sanitizeInboundForAgent(inbound map[string]interface{}) (map[string]interface{}, error) {
	candidate, err := cloneInboundConfig(inbound)
	if err != nil {
		return nil, err
	}
	for key := range candidate {
		if strings.HasPrefix(key, "_") {
			delete(candidate, key)
		}
	}
	return candidate, nil
}

func (h *RemoteManageHandler) replaceInboundForSync(ctx context.Context, serverID int64, inbound map[string]interface{}, mutationID string) error {
	mutationID = strings.TrimSpace(mutationID)
	if mutationID == "" {
		return errors.New("mutation_id is required for inbound replacement")
	}
	candidate, err := sanitizeInboundForAgent(inbound)
	if err != nil {
		return fmt.Errorf("sanitize inbound: %w", err)
	}
	body, err := json.Marshal(map[string]interface{}{
		"action":      "add",
		"inbound":     candidate,
		"mutation_id": mutationID,
	})
	if err != nil {
		return fmt.Errorf("encode inbound replacement: %w", err)
	}
	response, err := h.forwardToRemoteServer(ctx, serverID, "POST", "/api/child/inbounds", body)
	if err != nil {
		return fmt.Errorf("replace inbound: %w", err)
	}
	if err := validateManagedWireGuardMutationACK(response, mutationID); err != nil {
		return fmt.Errorf("replace inbound ownership ACK: %w", err)
	}
	if err := applyAgentConfigMutationACK(ctx, h, serverID, "ManagedRealityCredentialRepair", response); err != nil {
		return fmt.Errorf("replace inbound ACK: %w", err)
	}
	return nil
}

func mergeManagedPhysicalNodeConfig(node storage.Node, liveProxy map[string]interface{}) (storage.Node, bool, error) {
	if node.NodeType != "" && node.NodeType != "physical" {
		return node, false, nil
	}
	var existing map[string]interface{}
	if err := json.Unmarshal([]byte(node.ClashConfig), &existing); err != nil {
		return node, false, fmt.Errorf("parse existing node config: %w", err)
	}
	merged := make(map[string]interface{}, len(liveProxy)+5)
	for key, value := range liveProxy {
		merged[key] = value
	}
	// These fields may intentionally point at a relay, a chained proxy, or a
	// user-selected endpoint. Runtime inbound discovery cannot reconstruct them.
	for _, key := range []string{"name", "server", "dialer-proxy", "interface-name", "routing-mark"} {
		if value, ok := existing[key]; ok {
			merged[key] = value
		}
	}
	// A relay node exposes a separate endpoint and must preserve that port. A
	// direct node follows the newly acknowledged inbound port.
	if strings.TrimSpace(node.RelayOrigServer) != "" {
		if value, ok := existing["port"]; ok {
			merged["port"] = value
		}
	}
	merged["name"] = node.NodeName
	encoded, err := json.Marshal(merged)
	if err != nil {
		return node, false, fmt.Errorf("encode reconciled node config: %w", err)
	}
	updated := string(encoded)
	changed := updated != node.ClashConfig || node.ParsedConfig != updated
	node.ClashConfig = updated
	node.ParsedConfig = updated
	return node, changed, nil
}
