package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/violetaini/relaydock/internal/storage"
)

type databaseInboundReconcileResult struct {
	Removed  int
	Restored int
	Updated  int
}

type agentInboundInventory struct {
	Success  bool                     `json:"success"`
	Inbounds []map[string]interface{} `json:"inbounds"`
}

type databaseInboundIntentAlreadyStagedKey struct{}

type suppressDatabaseInboundPostWriteKey struct{}

func databaseInboundIntentAlreadyStaged(ctx context.Context) bool {
	staged, _ := ctx.Value(databaseInboundIntentAlreadyStagedKey{}).(bool)
	return staged
}

func databaseInboundPostWriteSuppressed(ctx context.Context) bool {
	suppressed, _ := ctx.Value(suppressDatabaseInboundPostWriteKey{}).(bool)
	return suppressed
}

func suppressDatabaseInboundPostWrite(ctx context.Context) context.Context {
	return context.WithValue(ctx, suppressDatabaseInboundPostWriteKey{}, true)
}

func xrayConfigObject(configJSON string) (map[string]interface{}, error) {
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("parse Xray config: %w", err)
	}
	return config, nil
}

func xrayConfigInbounds(configJSON string) (map[string]map[string]interface{}, error) {
	config, err := xrayConfigObject(configJSON)
	if err != nil {
		return nil, err
	}
	result := make(map[string]map[string]interface{})
	rawInbounds, _ := config["inbounds"].([]interface{})
	for _, raw := range rawInbounds {
		inbound, _ := raw.(map[string]interface{})
		tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
		if tag != "" {
			result[tag] = inbound
		}
	}
	return result, nil
}

func decodeDesiredInbound(raw json.RawMessage) (map[string]interface{}, error) {
	var inbound map[string]interface{}
	if err := json.Unmarshal(raw, &inbound); err != nil {
		return nil, err
	}
	if inbound == nil {
		return nil, errors.New("desired inbound must be a JSON object")
	}
	return inbound, nil
}

func cloneInboundMap(inbound map[string]interface{}) map[string]interface{} {
	raw, err := json.Marshal(inbound)
	if err != nil {
		return nil
	}
	var cloned map[string]interface{}
	if json.Unmarshal(raw, &cloned) != nil {
		return nil
	}
	return cloned
}

func observedInboundConfig(inbound map[string]interface{}) map[string]interface{} {
	cleaned := make(map[string]interface{}, len(inbound))
	for key, value := range inbound {
		if strings.HasPrefix(key, "_") {
			continue
		}
		cleaned[key] = value
	}
	return cleaned
}

func supplementAuthorizedObservedInbounds(
	baseConfig string,
	observed map[string]map[string]interface{},
	authorizedTags []string,
) (string, error) {
	config, err := xrayConfigObject(baseConfig)
	if err != nil {
		return "", err
	}
	rawInbounds, exists := config["inbounds"]
	if exists && rawInbounds != nil {
		if _, ok := rawInbounds.([]interface{}); !ok {
			return "", errors.New("Xray config inbounds must be an array")
		}
	}
	inbounds, _ := rawInbounds.([]interface{})
	existing, err := xrayConfigInbounds(baseConfig)
	if err != nil {
		return "", err
	}
	for _, tag := range authorizedTags {
		if existing[tag] != nil {
			continue
		}
		candidate := observedInboundConfig(observed[tag])
		if !completeDatabaseDesiredInbound(tag, candidate) {
			continue
		}
		inbounds = append(inbounds, candidate)
		existing[tag] = candidate
	}
	config["inbounds"] = inbounds
	normalized, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode supplemented Xray config: %w", err)
	}
	return string(normalized), nil
}

// rebuildDatabaseAuthorizedInboundClients adds dynamic credentials to the
// durable base listener definitions. The base definitions may contain their
// creation-time owner credential; every subsequently provisioned credential
// must have both a user_inbound_configs row and a currently effective access
// source. Agent inventory is observation only: it can prove a legacy classic
// Shadowsocks credential's missing cipher, but can never create authorization.
func (h *RemoteManageHandler) rebuildDatabaseAuthorizedInboundClients(
	ctx context.Context,
	serverID int64,
	desired map[string]map[string]interface{},
	observed map[string]map[string]interface{},
) error {
	configs, err := h.repo.GetUserInboundConfigsByServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("list database inbound credentials: %w", err)
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return fmt.Errorf("load database inbound credential server: %w", err)
	}
	refs, err := h.repo.ListInboundNodeRefsForServer(ctx, server.Name)
	if err != nil {
		return fmt.Errorf("list database inbound node owners: %w", err)
	}
	nodeOwners := make(map[string]map[string]struct{})
	for _, ref := range refs {
		if !strings.EqualFold(strings.TrimSpace(ref.NodeType), "physical") {
			continue
		}
		node, nodeErr := h.repo.GetNodeByID(ctx, ref.NodeID)
		if nodeErr != nil {
			return fmt.Errorf("load database inbound owner node %d: %w", ref.NodeID, nodeErr)
		}
		if !node.Enabled || node.OriginalServer != server.Name || node.InboundTag != ref.InboundTag {
			continue
		}
		if nodeOwners[ref.InboundTag] == nil {
			nodeOwners[ref.InboundTag] = make(map[string]struct{})
		}
		nodeOwners[ref.InboundTag][node.Username] = struct{}{}
	}
	loadObserved := func() (map[string]map[string]interface{}, error) {
		if observed != nil {
			return observed, nil
		}
		inventory, inventoryErr := h.fetchAgentInboundInventory(ctx, serverID)
		if inventoryErr != nil {
			return nil, inventoryErr
		}
		observed = make(map[string]map[string]interface{}, len(inventory.Inbounds))
		for _, inbound := range inventory.Inbounds {
			if tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"])); tag != "" {
				observed[tag] = inbound
			}
		}
		return observed, nil
	}
	now := time.Now().UTC()
	for _, config := range configs {
		inbound := desired[strings.TrimSpace(config.InboundTag)]
		if inbound == nil {
			continue
		}
		protocol := canonicalManagedProtocol(wireGuardStringValue(inbound["protocol"]))
		if canonicalManagedProtocol(config.Protocol) != protocol {
			return fmt.Errorf("database inbound credential protocol mismatch for %s/%s", config.Username, config.InboundTag)
		}
		var credential map[string]interface{}
		if err := json.Unmarshal([]byte(config.CredentialJSON), &credential); err != nil {
			return fmt.Errorf("decode database inbound credential for %s/%s: %w", config.Username, config.InboundTag, err)
		}
		if credential == nil {
			return fmt.Errorf("database inbound credential for %s/%s is not a JSON object", config.Username, config.InboundTag)
		}
		identityKey := inboundCredentialPrimaryKey(protocol)
		if identityKey == "" || nonEmptyCredentialValue(credential, identityKey) == "" {
			return fmt.Errorf("database inbound credential for %s/%s has no usable identity", config.Username, config.InboundTag)
		}
		settings, _ := inbound["settings"].(map[string]interface{})
		if settings == nil {
			return fmt.Errorf("database-owned inbound %s has no settings object", config.InboundTag)
		}
		listKey, keyErr := inboundClientListKey(protocol, settings)
		if keyErr != nil {
			return fmt.Errorf("resolve credential list for %s: %w", config.InboundTag, keyErr)
		}
		items, exists := settings[listKey]
		clients, ok := items.([]interface{})
		if exists && !ok {
			return fmt.Errorf("database-owned inbound %s has invalid %s list", config.InboundTag, listKey)
		}
		// A migrated desired definition may contain a once-authorized dynamic
		// credential. Remove every known database credential first, then add it
		// back only after current authorization succeeds.
		clients = filterCredentials(clients, credential, protocol)
		settings[listKey] = clients

		user, userErr := h.repo.GetUser(ctx, config.Username)
		if errors.Is(userErr, storage.ErrUserNotFound) {
			continue
		}
		if userErr != nil {
			return fmt.Errorf("load inbound credential user %s: %w", config.Username, userErr)
		}
		if !user.IsActive {
			continue
		}
		overLimit, limitErr := h.repo.IsUserOverLimit(ctx, config.Username)
		if limitErr != nil {
			return fmt.Errorf("load inbound credential limit state for %s: %w", config.Username, limitErr)
		}
		if overLimit {
			continue
		}
		_, ownsNode := nodeOwners[config.InboundTag][config.Username]
		hasAccess := ownsNode
		if !hasAccess {
			hasManaged, _, managedErr := h.repo.HasEffectiveUserInboundAccess(
				ctx, config.Username, serverID, config.InboundTag, 0, now,
			)
			if managedErr != nil {
				return fmt.Errorf("resolve managed inbound access for %s/%s: %w", config.Username, config.InboundTag, managedErr)
			}
			hasPackage, _, packageErr := hasLegacyPackageInboundAccess(
				ctx, h.repo, config.Username, serverID, config.InboundTag, now,
			)
			if packageErr != nil {
				return fmt.Errorf("resolve package inbound access for %s/%s: %w", config.Username, config.InboundTag, packageErr)
			}
			hasAccess = hasManaged || hasPackage
		}
		if hasAccess {
			if protocol == "shadowsocks" && isClassicManagedShadowsocksCipher(shadowsocksInboundMethod(settings)) {
				_, hasStoredMethod := credential["method"]
				if hasStoredMethod {
					if _, methodErr := reconcileClassicShadowsocksCredentialMethod(credential, settings); methodErr != nil {
						return fmt.Errorf("validate database classic Shadowsocks credential for %s/%s: %w", config.Username, config.InboundTag, methodErr)
					}
				} else {
					liveInbounds, inventoryErr := loadObserved()
					if inventoryErr != nil {
						return fmt.Errorf("read live inbound credentials: %w", inventoryErr)
					}
					liveInbound := liveInbounds[strings.TrimSpace(config.InboundTag)]
					liveSettings, _ := liveInbound["settings"].(map[string]interface{})
					if liveSettings == nil {
						return fmt.Errorf("validate database classic Shadowsocks credential for %s/%s: live inbound is unavailable", config.Username, config.InboundTag)
					}
					var methodErr error
					_, methodErr = reconcileClassicShadowsocksCredentialMethod(credential, liveSettings)
					if methodErr != nil {
						return fmt.Errorf("validate database classic Shadowsocks credential for %s/%s: %w", config.Username, config.InboundTag, methodErr)
					}
					if methodErr = validateDatabaseClassicShadowsocksLiveClient(credential, liveSettings); methodErr != nil {
						return fmt.Errorf("validate database classic Shadowsocks credential for %s/%s: %w", config.Username, config.InboundTag, methodErr)
					}
				}
				storedMethod := strings.ToLower(strings.TrimSpace(wireGuardStringValue(credential["method"])))
				if desiredMethod := shadowsocksInboundMethod(settings); storedMethod != desiredMethod {
					return fmt.Errorf("validate database classic Shadowsocks credential for %s/%s: live method %q does not match desired method %q", config.Username, config.InboundTag, storedMethod, desiredMethod)
				}
				if !hasStoredMethod {
					credentialJSON, marshalErr := json.Marshal(credential)
					if marshalErr != nil {
						return fmt.Errorf("encode database classic Shadowsocks credential for %s/%s: %w", config.Username, config.InboundTag, marshalErr)
					}
					if persistErr := h.repo.UpdateUserInboundCredentialJSONByID(ctx, config.ID, string(credentialJSON)); persistErr != nil {
						return fmt.Errorf("persist database classic Shadowsocks credential for %s/%s: %w", config.Username, config.InboundTag, persistErr)
					}
				}
			}
			settings[listKey] = append(clients, credential)
		}
	}
	return nil
}

func validateDatabaseClassicShadowsocksLiveClient(credential, liveSettings map[string]interface{}) error {
	method := strings.ToLower(strings.TrimSpace(wireGuardStringValue(credential["method"])))
	if !isClassicManagedShadowsocksCipher(method) {
		return errors.New("credential has no valid classic Shadowsocks method")
	}
	password := strings.TrimSpace(wireGuardStringValue(credential["password"]))
	email := strings.TrimSpace(wireGuardStringValue(credential["email"]))
	if password == "" && email == "" {
		return errors.New("credential has no verifiable client identity")
	}
	clients, _ := liveSettings["clients"].([]interface{})
	for _, item := range clients {
		client, _ := item.(map[string]interface{})
		if client == nil || !strings.EqualFold(strings.TrimSpace(wireGuardStringValue(client["method"])), method) {
			continue
		}
		if password != "" && strings.TrimSpace(wireGuardStringValue(client["password"])) != password {
			continue
		}
		if email != "" && strings.TrimSpace(wireGuardStringValue(client["email"])) != email {
			continue
		}
		return nil
	}
	return errors.New("credential has no matching live classic Shadowsocks client")
}

func sameInboundConfig(left, right map[string]interface{}) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func databaseTunnelTakeoverEnabled(server *storage.RemoteServer) bool {
	if server == nil || !server.StealSelf {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(server.StealMode))
	return mode == "" || mode == "tunnel"
}

func completeDatabaseDesiredInbound(tag string, inbound map[string]interface{}) bool {
	if inbound == nil || strings.TrimSpace(wireGuardStringValue(inbound["tag"])) != strings.TrimSpace(tag) {
		return false
	}
	if strings.TrimSpace(wireGuardStringValue(inbound["protocol"])) == "" {
		return false
	}
	if _, ok := inbound["settings"].(map[string]interface{}); !ok {
		return false
	}
	port, ok := inbound["port"].(float64)
	return ok && port >= 1 && port <= 65535
}

func decodeAgentInboundMutation(result []byte, expectedMutationID string) error {
	var response struct {
		Success    bool   `json:"success"`
		Error      string `json:"error"`
		Message    string `json:"message"`
		MutationID string `json:"mutation_id"`
		Superseded bool   `json:"superseded"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("decode Agent inbound mutation: %w", err)
	}
	if response.Success && !response.Superseded &&
		(strings.TrimSpace(expectedMutationID) == "" || strings.TrimSpace(response.MutationID) == strings.TrimSpace(expectedMutationID)) {
		return nil
	}
	message := strings.TrimSpace(response.Error)
	if message == "" {
		message = strings.TrimSpace(response.Message)
	}
	if message == "" && response.Superseded {
		message = "inbound mutation was superseded"
	}
	if message == "" {
		message = "Agent did not acknowledge inbound mutation"
	}
	return errors.New(message)
}

func (h *RemoteManageHandler) fetchAgentXrayConfig(ctx context.Context, serverID int64) (string, error) {
	raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/xray/config", nil)
	if err != nil {
		return "", err
	}
	var response struct {
		Success bool   `json:"success"`
		Config  string `json:"config"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return "", fmt.Errorf("decode Agent Xray config: %w", err)
	}
	if !response.Success || strings.TrimSpace(response.Config) == "" {
		return "", errors.New("Agent did not return an Xray config")
	}
	return response.Config, nil
}

func (h *RemoteManageHandler) fetchAgentInboundInventory(ctx context.Context, serverID int64) (agentInboundInventory, error) {
	raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return agentInboundInventory{}, err
	}
	var inventory agentInboundInventory
	if err := json.Unmarshal(raw, &inventory); err != nil {
		return agentInboundInventory{}, fmt.Errorf("decode Agent inbound inventory: %w", err)
	}
	if !inventory.Success {
		return agentInboundInventory{}, errors.New("Agent did not acknowledge inbound inventory")
	}
	return inventory, nil
}

func (h *RemoteManageHandler) applyDatabaseInboundMutation(
	ctx context.Context,
	serverID int64,
	action string,
	tag string,
	mutationID string,
	inbound map[string]interface{},
) error {
	// Reconciliation operates from an intent that is already durable. In
	// particular, deleting an Agent-only listener must not turn the observed
	// mutation owner into a database tombstone or ownership record. It also must
	// not schedule another post-write reconcile for its own hot mutation.
	ctx = context.WithValue(ctx, databaseInboundIntentAlreadyStagedKey{}, true)
	ctx = suppressDatabaseInboundPostWrite(ctx)
	payload := map[string]interface{}{"action": action}
	if action == "remove" {
		payload["tag"] = tag
	} else {
		payload["inbound"] = inbound
	}
	if strings.TrimSpace(mutationID) != "" {
		payload["mutation_id"] = strings.TrimSpace(mutationID)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/inbounds", body)
	if err != nil {
		return err
	}
	return decodeAgentInboundMutation(raw, mutationID)
}

// stageDatabaseInboundMutation persists intent before any Agent write. It is
// called at the lowest owner-side forwarding boundary so internal jobs and
// federation requests cannot bypass the same ordering used by the panel.
func (h *RemoteManageHandler) stageDatabaseInboundMutation(ctx context.Context, serverID int64, body []byte) ([]byte, error) {
	var request map[string]interface{}
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, fmt.Errorf("decode inbound mutation for desired state: %w", err)
	}
	action := strings.ToLower(strings.TrimSpace(wireGuardStringValue(request["action"])))
	if action == "" {
		action = "add"
	}
	switch action {
	case "add":
		inbound, _ := request["inbound"].(map[string]interface{})
		tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
		if tag == "" {
			return nil, errors.New("desired inbound add requires a tag")
		}
		if tag == "api" {
			return body, nil
		}
		if tag == "tunnel-in" {
			server, err := h.repo.GetRemoteServer(ctx, serverID)
			if err != nil {
				return nil, err
			}
			if !databaseTunnelTakeoverEnabled(server) {
				return nil, errors.New("tunnel-in requires database-authorized tunnel takeover")
			}
		}
		mutationID := strings.TrimSpace(wireGuardStringValue(request["mutation_id"]))
		if mutationID == "" {
			mutationID = "database-inbound:" + uuid.NewString()
			request["mutation_id"] = mutationID
		}
		previousDesired, err := h.repo.GetDesiredInbound(ctx, serverID, tag)
		if err != nil {
			return nil, fmt.Errorf("capture desired inbound %s before staging: %w", tag, err)
		}
		inboundJSON, err := json.Marshal(inbound)
		if err != nil {
			return nil, err
		}
		if _, err := h.repo.UpsertActiveDesiredInbound(ctx, serverID, tag, mutationID, inboundJSON); errors.Is(err, storage.ErrDesiredInboundMutationChanged) {
			return nil, errors.New("同 Tag 入站已进入新一代，旧创建操作不能覆盖当前配置")
		} else if err != nil {
			return nil, fmt.Errorf("stage active desired inbound %s: %w", tag, err)
		}
		if err := h.repo.SetRemoteInboundOwnership(ctx, serverID, tag, mutationID); err != nil {
			restored, rollbackErr := h.repo.RestoreDesiredInboundIfMutation(
				ctx, serverID, tag, mutationID, storage.DesiredInboundStateActive, previousDesired,
			)
			if rollbackErr != nil {
				return nil, fmt.Errorf("stage inbound ownership %s: %v; restore desired intent: %w", tag, err, rollbackErr)
			}
			if !restored {
				return nil, fmt.Errorf("stage inbound ownership %s: %v; desired generation changed before rollback", tag, err)
			}
			return nil, fmt.Errorf("stage inbound ownership %s: %w", tag, err)
		}
	case "remove":
		tag := strings.TrimSpace(wireGuardStringValue(request["tag"]))
		if tag == "" {
			return nil, errors.New("desired inbound remove requires a tag")
		}
		if tag == "api" {
			return nil, errors.New("the Xray API inbound is infrastructure-managed")
		}
		mutationID := strings.TrimSpace(wireGuardStringValue(request["mutation_id"]))
		if mutationID == "" {
			if desired, err := h.repo.GetDesiredInbound(ctx, serverID, tag); err != nil {
				return nil, err
			} else if desired != nil {
				mutationID = strings.TrimSpace(desired.MutationID)
			}
			if mutationID == "" {
				mutationID, _ = h.repo.GetRemoteInboundOwnership(ctx, serverID, tag)
			}
			if mutationID != "" {
				request["mutation_id"] = mutationID
			}
		}
		if _, err := h.repo.MarkDesiredInboundDeleted(ctx, serverID, tag, mutationID); errors.Is(err, storage.ErrDesiredInboundMutationChanged) {
			return nil, errors.New("同 Tag 入站已被新一代配置替换，旧操作不能删除它")
		} else if err != nil {
			return nil, fmt.Errorf("stage deleted desired inbound %s: %w", tag, err)
		}
	default:
		// add-client/remove-client mutate credentials governed by package, grant,
		// and expiry tables. They do not replace the base listener intent.
		return body, nil
	}
	normalized, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func databaseForwardInbound(forward storage.UserForwardRule, hop storage.UserForwardHop, serverID int64, now time.Time) (map[string]interface{}, bool) {
	if forward.DesiredState != storage.ForwardDesiredActive ||
		(forward.EffectiveExpiresAt != nil && !forward.EffectiveExpiresAt.After(now)) ||
		hop.ServerID != serverID || hop.DesiredState != storage.ForwardDesiredActive ||
		hop.ObservedState != storage.ForwardObservedActive || hop.AppliedGeneration != hop.Generation ||
		!now.Before(hop.UpdatedAt.Add(forwardTunnelLeaseDuration)) {
		return nil, false
	}
	tag := strings.TrimSpace(hop.ResourceTag)
	if tag == "" || hop.ListenPort < 1 || hop.ListenPort > 65535 ||
		strings.TrimSpace(hop.NextHost) == "" || hop.NextPort < 1 || hop.NextPort > 65535 {
		return nil, false
	}
	return map[string]interface{}{
		"tag":      tag,
		"listen":   "0.0.0.0",
		"port":     hop.ListenPort,
		"protocol": "dokodemo-door",
		"settings": map[string]interface{}{
			"address":        hop.NextHost,
			"port":           hop.NextPort,
			"network":        "tcp,udp",
			"followRedirect": false,
		},
		"sniffing": map[string]interface{}{"enabled": false},
	}, true
}

func (h *RemoteManageHandler) activeForwardInbounds(ctx context.Context, serverID int64) (map[string]map[string]interface{}, error) {
	forwards, err := h.repo.ListForwardReconcileCandidates(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	inbounds := make(map[string]map[string]interface{})
	for _, forward := range forwards {
		for _, hop := range forward.Hops {
			if inbound, ok := databaseForwardInbound(forward, hop, serverID, now); ok {
				inbounds[wireGuardStringValue(inbound["tag"])] = inbound
			}
		}
	}
	return inbounds, nil
}

func desiredXrayConfig(baseConfig string, desired map[string]map[string]interface{}, api map[string]interface{}) (string, error) {
	config, err := xrayConfigObject(baseConfig)
	if err != nil {
		return "", err
	}
	tags := make([]string, 0, len(desired))
	for tag := range desired {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	inbounds := make([]interface{}, 0, len(tags)+1)
	if api != nil {
		inbounds = append(inbounds, observedInboundConfig(api))
	} else if current, _ := xrayConfigInbounds(baseConfig); current["api"] != nil {
		inbounds = append(inbounds, current["api"])
	}
	for _, tag := range tags {
		inbounds = append(inbounds, desired[tag])
	}
	config["inbounds"] = inbounds
	normalized, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode database-owned Xray config: %w", err)
	}
	return string(normalized), nil
}

// canonicalizeDatabaseInbounds keeps non-inbound Xray settings from the
// caller, but always replaces the inbound array with database-authorized
// definitions. This is used by raw config writes and snapshot restoration so a
// historical file cannot resurrect a tombstone or introduce a new listener.
func (h *RemoteManageHandler) canonicalizeDatabaseInbounds(ctx context.Context, serverID int64, candidateConfig string) (string, error) {
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return "", err
	}
	rows, err := h.repo.ListActiveDesiredInbounds(ctx, serverID)
	if err != nil {
		return "", err
	}
	currentInbounds := make(map[string]map[string]interface{})
	if current, currentErr := h.repo.GetCurrentXraySnapshot(ctx, serverID); currentErr != nil {
		return "", currentErr
	} else if current != nil && strings.TrimSpace(current.ConfigJSON) != "" {
		currentInbounds, _ = xrayConfigInbounds(current.ConfigJSON)
	}
	desired := make(map[string]map[string]interface{}, len(rows))
	for _, row := range rows {
		if row.InboundTag == "tunnel-in" && !databaseTunnelTakeoverEnabled(server) {
			continue
		}
		inbound, decodeErr := decodeDesiredInbound(row.InboundJSON)
		if decodeErr != nil {
			return "", fmt.Errorf("decode desired inbound %s: %w", row.InboundTag, decodeErr)
		}
		desired[row.InboundTag] = inbound
	}
	if err := h.rebuildDatabaseAuthorizedInboundClients(ctx, serverID, desired, nil); err != nil {
		return "", err
	}
	forwardInbounds, err := h.activeForwardInbounds(ctx, serverID)
	if err != nil {
		return "", err
	}
	for tag, expected := range forwardInbounds {
		if inbound := currentInbounds[tag]; inbound != nil && sameInboundConfig(expected, observedInboundConfig(inbound)) {
			desired[tag] = expected
		}
	}
	candidateInbounds, err := xrayConfigInbounds(candidateConfig)
	if err != nil {
		return "", err
	}
	api := currentInbounds["api"]
	if api == nil {
		api = candidateInbounds["api"]
	}
	return desiredXrayConfig(candidateConfig, desired, api)
}

func (h *RemoteManageHandler) stageTunnelInfrastructureFromConfig(ctx context.Context, serverID int64, body []byte) error {
	var request struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(body, &request); err != nil || strings.TrimSpace(request.Config) == "" {
		return nil
	}
	inbounds, err := xrayConfigInbounds(request.Config)
	if err != nil {
		return err
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return err
	}
	current, err := h.repo.GetDesiredInbound(ctx, serverID, "tunnel-in")
	if err != nil {
		return err
	}
	mutationID := "system:tunnel-in"
	if current != nil && strings.TrimSpace(current.MutationID) != "" {
		mutationID = strings.TrimSpace(current.MutationID)
	}
	if inbound := inbounds["tunnel-in"]; inbound != nil && databaseTunnelTakeoverEnabled(server) {
		raw, marshalErr := json.Marshal(inbound)
		if marshalErr != nil {
			return marshalErr
		}
		_, err = h.repo.UpsertActiveDesiredInbound(ctx, serverID, "tunnel-in", mutationID, raw)
		if err == nil {
			err = h.repo.SetRemoteInboundOwnership(ctx, serverID, "tunnel-in", mutationID)
		}
		return err
	}
	if current != nil && current.DesiredState == storage.DesiredInboundStateActive && !databaseTunnelTakeoverEnabled(server) {
		_, err = h.repo.MarkDesiredInboundDeleted(ctx, serverID, "tunnel-in", mutationID)
	}
	return err
}

// canonicalizeDatabaseXrayConfigRequest is the final owner-side guard for every
// full-config write, including internal deployment jobs and federation calls.
// Callers may change routing/outbounds/system settings, while the durable
// desired-inbound table supplies the complete inbound list.
func (h *RemoteManageHandler) canonicalizeDatabaseXrayConfigRequest(ctx context.Context, serverID int64, body []byte) ([]byte, error) {
	var request map[string]interface{}
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, fmt.Errorf("decode Xray config mutation: %w", err)
	}
	configJSON := strings.TrimSpace(wireGuardStringValue(request["config"]))
	if configJSON == "" {
		return nil, errors.New("Xray config mutation requires config")
	}
	// tunnel-in is the only infrastructure listener a trusted full-template
	// deployment may establish. Its authorization still comes from the server's
	// persisted takeover mode rather than from the candidate file itself.
	if err := h.stageTunnelInfrastructureFromConfig(ctx, serverID, body); err != nil {
		return nil, err
	}
	canonical, err := h.canonicalizeDatabaseInbounds(ctx, serverID, configJSON)
	if err != nil {
		return nil, err
	}
	request["config"] = canonical
	normalized, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode canonical Xray config mutation: %w", err)
	}
	return normalized, nil
}

// reconcileDatabaseOwnedInboundsLeased enforces the durable desired-inbound
// table as the only source for proxy listeners. The caller must hold the
// per-server exclusive mutation lease.
func (h *RemoteManageHandler) reconcileDatabaseOwnedInboundsLeased(
	ctx context.Context,
	serverID int64,
	agentConfigSeed string,
) (databaseInboundReconcileResult, error) {
	var result databaseInboundReconcileResult
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return result, fmt.Errorf("load remote server: %w", err)
	}
	inventory, err := h.fetchAgentInboundInventory(ctx, serverID)
	if err != nil {
		return result, fmt.Errorf("read Agent inbound inventory: %w", err)
	}
	observed := make(map[string]map[string]interface{}, len(inventory.Inbounds))
	for _, inbound := range inventory.Inbounds {
		tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
		if tag != "" {
			observed[tag] = inbound
		}
	}

	// Before deleting any runtime-only listener, bootstrap only tags for which
	// the database already has durable node/tunnel evidence. The complete live
	// config supplies definitions, but never authority. If any authorized tag
	// still lacks a complete desired definition, fail closed before the first
	// Agent mutation.
	baseConfig := strings.TrimSpace(agentConfigSeed)
	if baseConfig == "" {
		baseConfig, err = h.fetchAgentXrayConfig(ctx, serverID)
		if err != nil {
			return result, fmt.Errorf("read complete Agent Xray config: %w", err)
		}
	}
	if strings.TrimSpace(baseConfig) == "" {
		return result, errors.New("Agent returned an empty complete Xray config")
	}
	authorizedTags, err := h.repo.ListAuthorizedInboundTags(ctx, serverID)
	if err != nil {
		return result, fmt.Errorf("list database-authorized inbound tags: %w", err)
	}
	baseConfig, err = supplementAuthorizedObservedInbounds(baseConfig, observed, authorizedTags)
	if err != nil {
		return result, fmt.Errorf("supplement database-authorized inbounds from Agent inventory: %w", err)
	}
	if _, err := h.repo.BackfillAuthorizedDesiredInbounds(ctx, serverID, baseConfig); err != nil {
		return result, fmt.Errorf("backfill database-authorized inbounds: %w", err)
	}
	rows, err := h.repo.ListActiveDesiredInbounds(ctx, serverID)
	if err != nil {
		return result, fmt.Errorf("list active desired inbounds: %w", err)
	}
	desired := make(map[string]map[string]interface{}, len(rows))
	mutations := make(map[string]string, len(rows))
	for _, row := range rows {
		// tunnel-in exists only for a database-authorized 443 takeover. Historical
		// names alone never grant infrastructure privileges.
		if row.InboundTag == "tunnel-in" && !databaseTunnelTakeoverEnabled(server) {
			continue
		}
		inbound, decodeErr := decodeDesiredInbound(row.InboundJSON)
		if decodeErr != nil {
			return result, fmt.Errorf("decode desired inbound %s: %w", row.InboundTag, decodeErr)
		}
		if !completeDatabaseDesiredInbound(row.InboundTag, inbound) {
			return result, fmt.Errorf("database-authorized inbound %s has no complete desired definition", row.InboundTag)
		}
		// Database-owned Reality listeners must not depend on Xray's implicit
		// minimum-client default. Persist the compatibility floor before the hot
		// runtime comparison so the Agent and every future snapshot converge from
		// the same durable intent without requiring an operator action.
		if applyManagedRealityCompatibilityToInbound(inbound) {
			compatibleJSON, marshalErr := json.Marshal(inbound)
			if marshalErr != nil {
				return result, fmt.Errorf("encode compatible desired inbound %s: %w", row.InboundTag, marshalErr)
			}
			if _, persistErr := h.repo.UpsertActiveDesiredInbound(
				ctx, serverID, row.InboundTag, row.MutationID, compatibleJSON,
			); persistErr != nil {
				return result, fmt.Errorf("persist compatible desired inbound %s: %w", row.InboundTag, persistErr)
			}
		}
		desired[row.InboundTag] = inbound
		mutations[row.InboundTag] = strings.TrimSpace(row.MutationID)
	}
	for _, tag := range authorizedTags {
		if _, ok := desired[tag]; !ok {
			return result, fmt.Errorf("database-authorized inbound %s has no complete desired definition", tag)
		}
	}
	if err := h.rebuildDatabaseAuthorizedInboundClients(ctx, serverID, desired, observed); err != nil {
		return result, err
	}
	forwardInbounds, err := h.activeForwardInbounds(ctx, serverID)
	if err != nil {
		return result, fmt.Errorf("list active forwarding inbounds: %w", err)
	}
	validatedForwardTags := make(map[string]struct{}, len(forwardInbounds))
	for tag, expected := range forwardInbounds {
		if actual := observed[tag]; actual != nil && sameInboundConfig(expected, observedInboundConfig(actual)) {
			validatedForwardTags[tag] = struct{}{}
		}
	}

	// Remove runtime-only listeners first so an authoritative listener can
	// reclaim a conflicting port in the same pass. The observed mutation owner
	// is used only as the deletion CAS and is never persisted as desired state.
	extraTags := make([]string, 0)
	for tag := range observed {
		if tag == "api" {
			continue
		}
		if _, keep := validatedForwardTags[tag]; keep {
			continue
		}
		if _, keep := desired[tag]; !keep {
			extraTags = append(extraTags, tag)
		}
	}
	sort.Strings(extraTags)
	for _, tag := range extraTags {
		mutationID := strings.TrimSpace(wireGuardStringValue(observed[tag]["_mutation_id"]))
		if err := h.applyDatabaseInboundMutation(ctx, serverID, "remove", tag, mutationID, nil); err != nil {
			return result, fmt.Errorf("remove unmanaged inbound %s: %w", tag, err)
		}
		result.Removed++
		delete(observed, tag)
	}

	desiredTags := make([]string, 0, len(desired))
	for tag := range desired {
		desiredTags = append(desiredTags, tag)
	}
	sort.Strings(desiredTags)
	for _, tag := range desiredTags {
		wanted := desired[tag]
		actual, exists := observed[tag]
		actualOwner := ""
		if exists {
			actualOwner = strings.TrimSpace(wireGuardStringValue(actual["_mutation_id"]))
		}
		sameConfig := exists && sameInboundConfig(wanted, observedInboundConfig(actual))
		ownerMatches := mutations[tag] == "" || mutations[tag] == actualOwner
		migrationBootstrap := strings.HasPrefix(mutations[tag], "database-migration:")
		if sameConfig && (ownerMatches || migrationBootstrap) {
			continue
		}
		if err := h.applyDatabaseInboundMutation(ctx, serverID, "add", tag, mutations[tag], wanted); err != nil {
			return result, fmt.Errorf("restore database-owned inbound %s: %w", tag, err)
		}
		if exists {
			result.Updated++
		} else {
			result.Restored++
		}
	}
	// Active forwarding resources have their own durable database lifecycle and
	// expiry guard. Preserve them in the canonical snapshot when observed, but
	// never recreate them here after their hard deadline has removed them.
	for tag := range validatedForwardTags {
		if _, databaseOwned := desired[tag]; !databaseOwned {
			desired[tag] = forwardInbounds[tag]
		}
	}

	// Agent state may supply outbounds, routing and other non-inbound settings,
	// but never the desired inbound set. Reading the live config after hot
	// mutations also keeps raw-editor changes in the canonical snapshot.
	canonicalConfig, err := desiredXrayConfig(baseConfig, desired, observed["api"])
	if err != nil {
		return result, err
	}
	if _, err := h.repo.UpsertCurrentXraySnapshot(ctx, serverID, canonicalConfig, storage.XraySnapshotSourceMasterWrite); err != nil {
		return result, fmt.Errorf("persist database-owned Xray snapshot: %w", err)
	}
	if h.inboundCache != nil {
		h.inboundCache.SyncFromConfig(serverID, canonicalConfig)
	}
	if err := h.repo.DiscardPendingXrayRecovery(ctx, serverID); err != nil {
		return result, fmt.Errorf("discard obsolete Agent recovery snapshot: %w", err)
	}
	return result, nil
}

func (h *RemoteManageHandler) logDatabaseInboundReconcile(serverID int64, source string, result databaseInboundReconcileResult, err error) {
	if err != nil {
		log.Printf("[XrayAuthority] %s server=%d failed: %v", source, serverID, err)
		return
	}
	log.Printf("[XrayAuthority] %s server=%d removed=%d restored=%d updated=%d", source, serverID, result.Removed, result.Restored, result.Updated)
}
