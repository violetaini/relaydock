package handler

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"

	"github.com/google/uuid"
)

const managedInboundResourcesPath = "/api/admin/managed-inbound-resources"

type managedInboundResourceDTO struct {
	ID             int64           `json:"id"`
	ServerID       int64           `json:"server_id"`
	ServerName     string          `json:"server_name"`
	DisplayName    string          `json:"display_name"`
	Protocol       string          `json:"protocol"`
	InboundTag     string          `json:"inbound_tag"`
	EndpointHost   string          `json:"endpoint_host"`
	EndpointPort   int             `json:"endpoint_port"`
	PublicMetadata json.RawMessage `json:"public_metadata"`
	CreatedBy      string          `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func managedInboundResourceResponse(resource *storage.ManagedInboundResource) managedInboundResourceDTO {
	metadata := resource.PublicMetadataJSON
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	return managedInboundResourceDTO{
		ID:             resource.ID,
		ServerID:       resource.ServerID,
		ServerName:     resource.ServerName,
		DisplayName:    resource.DisplayName,
		Protocol:       resource.Protocol,
		InboundTag:     resource.InboundTag,
		EndpointHost:   resource.EndpointHost,
		EndpointPort:   resource.EndpointPort,
		PublicMetadata: metadata,
		CreatedBy:      resource.CreatedBy,
		CreatedAt:      resource.CreatedAt,
		UpdatedAt:      resource.UpdatedAt,
	}
}

type managedWireGuardCreateRequest struct {
	Action      string                  `json:"action"`
	DisplayName string                  `json:"display_name"`
	Inbound     map[string]interface{}  `json:"inbound"`
	Client      *managedWireGuardClient `json:"client"`
}

type managedWireGuardClient struct {
	PrivateKey      string   `json:"private_key"`
	PublicKey       string   `json:"public_key"`
	Address         []string `json:"address"`
	DNS             []string `json:"dns"`
	MTU             int      `json:"mtu"`
	KeepAlive       int      `json:"keep_alive"`
	ServerPublicKey string   `json:"server_public_key"`
	AllowedIPs      []string `json:"allowed_ips"`
}

type managedInboundRenameRequest struct {
	DisplayName string `json:"display_name"`
}

func decodeStrictManagedInboundJSON(r *http.Request, target interface{}) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON object")
		}
		return err
	}
	return nil
}

// HandleManagedInboundResources keeps public inbound inventory for compatibility.
// Panel-created WireGuard profiles additionally become ordinary nodes; only the
// client private key is separated and encrypted at rest.
func (h *RemoteManageHandler) HandleManagedInboundResources(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.repo == nil {
		remoteWriteError(w, http.StatusServiceUnavailable, "managed inbound resource storage unavailable")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, managedInboundResourcesPath), "/")
	switch {
	case path == "" && r.Method == http.MethodGet:
		h.listManagedInboundResources(w, r)
	case path == "wireguard" && r.Method == http.MethodPost:
		h.createManagedWireGuardResource(w, r)
	case path != "":
		id, err := strconv.ParseInt(path, 10, 64)
		if err != nil || id <= 0 {
			remoteWriteError(w, http.StatusNotFound, "managed inbound resource not found")
			return
		}
		switch r.Method {
		case http.MethodPatch:
			h.renameManagedInboundResource(w, r, id)
		case http.MethodDelete:
			h.deleteManagedInboundResource(w, r, id)
		default:
			remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	default:
		remoteWriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *RemoteManageHandler) listManagedInboundResources(w http.ResponseWriter, r *http.Request) {
	resources, err := h.repo.ListManagedInboundResources(r.Context())
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, "failed to list managed inbound resources")
		return
	}
	items := make([]managedInboundResourceDTO, 0, len(resources))
	for index := range resources {
		items = append(items, managedInboundResourceResponse(&resources[index]))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "resources": items})
}

func (h *RemoteManageHandler) createManagedWireGuardResource(w http.ResponseWriter, r *http.Request) {
	serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		remoteWriteError(w, http.StatusBadRequest, "invalid server_id")
		return
	}
	var request managedWireGuardCreateRequest
	if err := decodeStrictManagedInboundJSON(r, &request); err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if request.Action != "" && !strings.EqualFold(strings.TrimSpace(request.Action), "add") {
		remoteWriteError(w, http.StatusBadRequest, "managed WireGuard creation only supports action=add")
		return
	}
	if request.Inbound == nil || canonicalManagedProtocol(wireGuardStringValue(request.Inbound["protocol"])) != "wireguard" {
		remoteWriteError(w, http.StatusBadRequest, "inbound.protocol must be wireguard")
		return
	}
	if key := managedInboundPrivateKey(request.Inbound); key != "" {
		remoteWriteError(w, http.StatusBadRequest, fmt.Sprintf("WireGuard 入站包含客户端私钥字段 %q；客户端私钥只能存入加密节点配置", key))
		return
	}
	validationRequest := map[string]interface{}{"inbound": request.Inbound}
	if message := validateInboundWireGuard(validationRequest); message != "" {
		remoteWriteError(w, http.StatusBadRequest, message)
		return
	}
	tag := strings.TrimSpace(wireGuardStringValue(request.Inbound["tag"]))
	if tag == "" {
		remoteWriteError(w, http.StatusBadRequest, "inbound.tag is required")
		return
	}
	if request.Client == nil {
		remoteWriteError(w, http.StatusBadRequest, "client is required")
		return
	}
	client, err := validateManagedWireGuardClient(request.Inbound, *request.Client)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	server, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil || server == nil {
		remoteWriteError(w, http.StatusNotFound, "server not found")
		return
	}
	operationCtx, release, err := h.repo.AcquireRemoteServerExclusiveMutationLease(r.Context(), serverID)
	if err != nil {
		remoteWriteForwardError(w, err)
		return
	}
	defer release()
	r = r.WithContext(operationCtx)

	// Repeat local checks while holding the exclusive lease. Another request may
	// have completed between the initial fast check and lease acquisition.
	if existingResource, lookupErr := h.repo.GetManagedInboundResourceByServerTag(operationCtx, serverID, tag); lookupErr == nil {
		recoveredNode, recovered, recoveryErr := h.recoverStagedManagedWireGuard(operationCtx, server, existingResource)
		if recoveryErr != nil {
			remoteWriteError(w, http.StatusConflict, "检测到未完成的 WireGuard 创建记录，自动恢复失败: "+recoveryErr.Error())
			return
		}
		if recovered {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "recovered": true,
				"resource": managedInboundResourceResponse(existingResource),
				"node_id":  recoveredNode.ID, "node": convertNode(recoveredNode),
				"client_config": "",
			})
			return
		}
		remoteWriteError(w, http.StatusConflict, "该服务器已存在相同 Tag 的 WireGuard 管理资源")
		return
	} else if !errors.Is(lookupErr, storage.ErrManagedInboundResourceNotFound) {
		remoteWriteError(w, http.StatusInternalServerError, "failed to check managed WireGuard resource")
		return
	}

	// With no recoverable local generation, a pre-existing live tag belongs to
	// something else. Refuse it before staging a new encrypted identity.
	if exists, inventoryErr := h.managedInboundTagExists(operationCtx, serverID, tag); inventoryErr != nil {
		remoteWriteError(w, http.StatusBadGateway, "无法确认远端 WireGuard 入站 Tag: "+inventoryErr.Error())
		return
	} else if exists {
		remoteWriteError(w, http.StatusConflict, "目标服务器已存在相同 Tag 的入站")
		return
	}
	if _, found, lookupErr := h.findManagedNode(r.Context(), server.Name, tag); lookupErr != nil {
		remoteWriteError(w, http.StatusInternalServerError, "failed to check managed WireGuard node")
		return
	} else if found {
		remoteWriteError(w, http.StatusConflict, "该服务器已存在相同 Tag 的 WireGuard 节点")
		return
	}
	mutationID := "managed-wireguard:" + uuid.NewString()
	probePeer, err := newWireGuardProbePeerForInbound(request.Inbound)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "WireGuard 专用探测 Peer 生成失败: "+err.Error())
		return
	}
	if err := appendWireGuardProbePeer(request.Inbound, &probePeer); err != nil {
		remoteWriteError(w, http.StatusBadRequest, "WireGuard 专用探测 Peer 生成失败: "+err.Error())
		return
	}
	displayName := strings.TrimSpace(request.DisplayName)
	resource, err := h.upsertWireGuardManagedResource(r.Context(), serverID, displayName, auth.UsernameFromContext(r.Context()), request.Inbound, mutationID)
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "WireGuard 公开元数据预存失败: "+err.Error())
		return
	}
	probePeer.ResourceID = resource.ID
	if _, err := h.repo.CreateWireGuardProbePeer(r.Context(), probePeer); err != nil {
		_ = h.repo.DeleteManagedInboundResource(r.Context(), resource.ID)
		remoteWriteError(w, http.StatusBadGateway, "WireGuard 专用探测凭据加密预存失败: "+err.Error())
		return
	}
	displayName = resource.DisplayName
	clashConfig, clientConfig, err := buildManagedWireGuardClientConfigs(displayName, resource.EndpointHost, resource.EndpointPort, client)
	if err != nil {
		_ = h.repo.DeleteManagedInboundResource(r.Context(), resource.ID)
		remoteWriteError(w, http.StatusBadRequest, "WireGuard 客户端配置生成失败: "+err.Error())
		return
	}

	// Persist the client identity before touching the remote server. The node is
	// intentionally disabled until the Agent confirms creation. A process crash
	// can therefore leave a recoverable disabled node, never an unrecoverable
	// remote peer whose client private key only existed in memory.
	node, err := h.repo.CreateNode(r.Context(), storage.Node{
		Username:          h.repo.GetSystemNodeOwner(r.Context()),
		NodeName:          displayName,
		Protocol:          "wireguard",
		ParsedConfig:      clashConfig,
		ClashConfig:       clashConfig,
		Enabled:           false,
		InboundMutationID: mutationID,
	})
	if err != nil {
		_ = h.repo.DeleteManagedInboundResource(r.Context(), resource.ID)
		remoteWriteError(w, http.StatusBadGateway, "WireGuard 节点加密预存失败: "+err.Error())
		return
	}
	stagedNodeID := node.ID
	payload, err := json.Marshal(map[string]interface{}{
		"action":      "add",
		"node_name":   strings.TrimSpace(request.DisplayName),
		"inbound":     request.Inbound,
		"mutation_id": mutationID,
	})
	if err != nil {
		_, _ = h.repo.DeleteStagedWireGuardNodeIfMutation(r.Context(), stagedNodeID, mutationID)
		_ = h.repo.DeleteManagedInboundResource(r.Context(), resource.ID)
		remoteWriteError(w, http.StatusBadRequest, "failed to encode managed WireGuard request")
		return
	}
	recorder := h.runManagedInboundMutation(r, serverID, payload)
	if recorder.status >= http.StatusBadRequest {
		message := managedNodeResponseMessage(recorder, "WireGuard 远程入站创建失败")
		if !managedWireGuardMutationApplied(recorder, mutationID) {
			remoteWriteError(w, http.StatusBadGateway, message+"；远端创建结果无法确认，已保留禁用节点和加密凭据")
			return
		}
		if rollbackErr := h.rollbackStagedManagedWireGuard(r, serverID, tag, stagedNodeID, mutationID); rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, message+"；自动回滚失败，已保留禁用节点和加密凭据: "+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, message+"；预存节点与远程入站已回滚")
		return
	}
	if ackErr := validateManagedWireGuardMutationACK(recorder.body.Bytes(), mutationID); ackErr != nil {
		message := ackErr.Error()
		if !managedWireGuardMutationApplied(recorder, mutationID) {
			remoteWriteError(w, http.StatusBadGateway, message+"；远端创建结果无法确认，已保留禁用节点和加密凭据")
			return
		}
		if rollbackErr := h.rollbackStagedManagedWireGuard(r, serverID, tag, stagedNodeID, mutationID); rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, message+"；自动回滚失败，已保留禁用节点和加密凭据: "+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, message+"；预存节点与远程入站已回滚")
		return
	}
	if _, err := h.repo.MarkWireGuardProbePeerActive(r.Context(), resource.ID); err != nil {
		rollbackErr := h.rollbackStagedManagedWireGuard(r, serverID, tag, stagedNodeID, mutationID)
		if rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, "WireGuard 入站已创建但专用探测 Peer 状态保存失败；自动回滚失败，已保留禁用节点和加密凭据: "+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, "WireGuard 入站已创建但专用探测 Peer 状态保存失败；预存节点与远程入站已回滚")
		return
	}
	resource, err = h.repo.GetManagedInboundResourceByServerTag(r.Context(), serverID, tag)
	if err != nil {
		rollbackErr := h.rollbackStagedManagedWireGuard(r, serverID, tag, stagedNodeID, mutationID)
		if rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, "WireGuard 入站已创建但管理记录缺失；自动回滚失败，已保留禁用节点和加密凭据: "+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, "WireGuard 入站已创建但管理记录缺失；预存节点与远程入站已回滚")
		return
	}
	// Attach remote lifecycle coordinates only after a matching Agent ACK. The
	// compare-and-set refuses a row that was concurrently attached or replaced.
	node, err = h.repo.AttachStagedWireGuardNodeIfMutation(r.Context(), stagedNodeID, mutationID, server.Name, tag)
	if err != nil {
		rollbackErr := h.rollbackStagedManagedWireGuard(r, serverID, tag, stagedNodeID, mutationID)
		if rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, "WireGuard 节点启用失败: "+err.Error()+"；自动回滚失败，已保留禁用节点和加密凭据: "+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, "WireGuard 节点启用失败；预存节点与远程入站已回滚: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"resource":      managedInboundResourceResponse(resource),
		"node_id":       node.ID,
		"node":          convertNode(node),
		"client_config": clientConfig,
	})
}

func (h *RemoteManageHandler) renameManagedInboundResource(w http.ResponseWriter, r *http.Request, id int64) {
	var request managedInboundRenameRequest
	if err := decodeStrictManagedInboundJSON(r, &request); err != nil {
		remoteWriteError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	request.DisplayName = strings.TrimSpace(request.DisplayName)
	if request.DisplayName == "" || len([]rune(request.DisplayName)) > 128 {
		remoteWriteError(w, http.StatusBadRequest, "display_name must be between 1 and 128 characters")
		return
	}
	resource, err := h.repo.RenameManagedInboundResource(r.Context(), id, request.DisplayName)
	if errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		remoteWriteError(w, http.StatusNotFound, "managed inbound resource not found")
		return
	}
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, "failed to rename managed inbound resource")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "resource": managedInboundResourceResponse(resource)})
}

func (h *RemoteManageHandler) deleteManagedInboundResource(w http.ResponseWriter, r *http.Request, id int64) {
	resource, err := h.repo.GetManagedInboundResource(r.Context(), id)
	if errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		remoteWriteError(w, http.StatusNotFound, "managed inbound resource not found")
		return
	}
	if err != nil {
		remoteWriteError(w, http.StatusInternalServerError, "failed to read managed inbound resource")
		return
	}
	var stagedNode storage.Node
	if strings.TrimSpace(resource.MutationID) != "" {
		stagedNode, err = h.repo.GetStagedWireGuardNodeByMutation(r.Context(), resource.MutationID)
		if err != nil && !errors.Is(err, storage.ErrNodeNotFound) {
			remoteWriteError(w, http.StatusConflict, "WireGuard 暂存节点状态冲突，未执行删除: "+err.Error())
			return
		}
	}
	payload, _ := json.Marshal(map[string]string{
		"action":      "remove",
		"tag":         resource.InboundTag,
		"mutation_id": resource.MutationID,
	})
	recorder := h.runManagedInboundMutation(r, resource.ServerID, payload)
	if recorder.status >= http.StatusBadRequest {
		copyHTTPResponse(w, recorder)
		return
	}
	if success, message := managedNodeResponseSuccess(recorder); !success {
		remoteWriteError(w, http.StatusBadGateway, message)
		return
	}
	if strings.TrimSpace(resource.MutationID) != "" {
		if err := validateManagedWireGuardMutationACK(recorder.body.Bytes(), resource.MutationID); err != nil {
			remoteWriteError(w, http.StatusConflict, "远端入站所有权已变化，未删除本地记录: "+err.Error())
			return
		}
	}
	// InboundRemoved normally deletes this synchronously. The explicit delete
	// makes the endpoint robust if event listeners are not installed in a test
	// process or a future embedding.
	var deletedResource int64
	if strings.TrimSpace(resource.MutationID) != "" {
		deletedResource, err = h.repo.DeleteManagedInboundResourceIfMutation(r.Context(), id, resource.MutationID)
	} else {
		err = h.repo.DeleteManagedInboundResource(r.Context(), id)
		if err == nil {
			deletedResource = 1
		}
	}
	if err != nil && !errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		remoteWritePartialError(w, "远程 WireGuard 入站已删除，但本地管理记录清理失败")
		return
	}
	if strings.TrimSpace(resource.MutationID) != "" && deletedResource == 0 {
		current, lookupErr := h.repo.GetManagedInboundResource(r.Context(), id)
		switch {
		case errors.Is(lookupErr, storage.ErrManagedInboundResourceNotFound):
			// The synchronous InboundRemoved listener already removed this exact
			// generation. Continue with idempotent node cleanup.
		case lookupErr != nil:
			remoteWritePartialError(w, "远程 WireGuard 入站已删除，但无法确认本地管理记录")
			return
		case strings.TrimSpace(current.MutationID) != strings.TrimSpace(resource.MutationID):
			remoteWriteError(w, http.StatusConflict, "入站已被新一代记录替换，未清理本地节点")
			return
		default:
			remoteWritePartialError(w, "远程 WireGuard 入站已删除，但本地管理记录未清理")
			return
		}
	}
	if strings.TrimSpace(resource.MutationID) != "" {
		_, err = h.repo.DeleteNodesByInboundTagMutation(r.Context(), resource.ServerName, resource.InboundTag, resource.MutationID)
	} else {
		_, err = h.repo.DeleteNodesByInboundTag(r.Context(), resource.ServerName, resource.InboundTag)
	}
	if err != nil {
		remoteWritePartialError(w, "远程 WireGuard 入站已删除，但普通节点记录清理失败")
		return
	}
	if stagedNode.ID > 0 {
		if _, err := h.repo.DeleteStagedWireGuardNodeIfMutation(r.Context(), stagedNode.ID, resource.MutationID); err != nil {
			remoteWritePartialError(w, "远程 WireGuard 入站已删除，但暂存加密节点清理失败")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "status": "deleted", "id": id})
}

func (h *RemoteManageHandler) runManagedInboundMutation(r *http.Request, serverID int64, body []byte) *managedNodeResponseRecorder {
	request := r.Clone(r.Context())
	request.Method = http.MethodPost
	request.URL = cloneURLWithQuery(r, serverID)
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	recorder := &managedNodeResponseRecorder{header: make(http.Header)}
	h.HandleInbounds(recorder, request)
	return recorder
}

func (h *RemoteManageHandler) rollbackManagedInboundResource(r *http.Request, serverID int64, tag, mutationID string) error {
	payload, _ := json.Marshal(map[string]string{"action": "remove", "tag": tag, "mutation_id": mutationID})
	baseCtx := context.WithoutCancel(r.Context())
	removeCtx, cancelRemove := context.WithTimeout(baseCtx, 15*time.Second)
	result, err := h.forwardToRemoteServer(removeCtx, serverID, http.MethodPost, "/api/child/inbounds", payload)
	cancelRemove()
	if err != nil {
		return fmt.Errorf("Agent 未确认 fenced remove: %w", err)
	}
	if err := validateManagedWireGuardMutationACK(result, mutationID); err != nil {
		return fmt.Errorf("Agent fenced remove ACK 无效: %w", err)
	}
	verifyCtx, cancelVerify := context.WithTimeout(baseCtx, 8*time.Second)
	stillExists, err := h.managedInboundTagExists(verifyCtx, serverID, tag)
	cancelVerify()
	if err != nil {
		return fmt.Errorf("无法确认 fenced remove 结果: %w", err)
	}
	if stillExists {
		return errors.New("Agent 已响应 fenced remove，但同 Tag 入站仍存在")
	}
	return nil
}

func (h *RemoteManageHandler) rollbackStagedManagedWireGuard(r *http.Request, serverID int64, tag string, nodeID int64, mutationID string) error {
	if err := h.rollbackManagedInboundResource(r, serverID, tag, mutationID); err != nil {
		return err
	}
	cleanupCtx := context.WithoutCancel(r.Context())
	if _, err := h.repo.DeleteStagedWireGuardNodeIfMutation(cleanupCtx, nodeID, mutationID); err != nil {
		return fmt.Errorf("delete staged WireGuard node: %w", err)
	}
	_, err := h.repo.DeleteManagedInboundResourceByServerTagMutation(cleanupCtx, serverID, tag, mutationID)
	return err
}

func (h *RemoteManageHandler) recoverStagedManagedWireGuard(ctx context.Context, server *storage.RemoteServer, resource *storage.ManagedInboundResource) (storage.Node, bool, error) {
	if server == nil || resource == nil || strings.TrimSpace(resource.MutationID) == "" {
		return storage.Node{}, false, nil
	}
	staged, err := h.repo.GetStagedWireGuardNodeByMutation(ctx, resource.MutationID)
	if errors.Is(err, storage.ErrNodeNotFound) {
		return storage.Node{}, false, nil
	}
	if err != nil {
		return storage.Node{}, false, err
	}
	inbound, fenceKnown, owner, err := h.managedInboundOwnershipFromAgent(ctx, resource.ServerID, resource.InboundTag)
	if err != nil {
		return storage.Node{}, false, err
	}
	if !fenceKnown {
		return storage.Node{}, false, errors.New("Agent 未提供可信的入站所有权清单")
	}
	if inbound == nil {
		return storage.Node{}, false, errors.New("Agent 上不存在对应入站；请删除残留记录后重新创建")
	}
	if strings.TrimSpace(owner) != strings.TrimSpace(resource.MutationID) {
		return storage.Node{}, false, errors.New("Agent 上同 Tag 已由另一代配置持有")
	}
	if err := managedWireGuardInventoryMatchesResource(inbound, resource); err != nil {
		return storage.Node{}, false, fmt.Errorf("Agent 上同代 WireGuard 配置与预存记录不一致: %w", err)
	}
	probePeer, err := h.repo.GetWireGuardProbePeer(ctx, resource.ID)
	if err != nil {
		return storage.Node{}, false, errors.New("预存记录缺少 WireGuard 专用探测凭据")
	}
	present, err := wireGuardInboundHasProbePeer(inbound, probePeer)
	if err != nil {
		return storage.Node{}, false, err
	}
	if !present {
		return storage.Node{}, false, errors.New("Agent 上同代 WireGuard 配置缺少专用探测 Peer")
	}
	if _, err := h.repo.MarkWireGuardProbePeerActive(ctx, resource.ID); err != nil {
		return storage.Node{}, false, fmt.Errorf("恢复 WireGuard 专用探测 Peer 状态: %w", err)
	}
	attached, err := h.repo.AttachStagedWireGuardNodeIfMutation(ctx, staged.ID, resource.MutationID, server.Name, resource.InboundTag)
	if err != nil {
		return storage.Node{}, false, err
	}
	return attached, true, nil
}

func (h *RemoteManageHandler) managedInboundOwnershipFromAgent(ctx context.Context, serverID int64, tag string) (matched map[string]interface{}, fenceKnown bool, owner string, returnErr error) {
	raw, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return nil, false, "", err
	}
	var response struct {
		Success            *bool                    `json:"success"`
		MutationFenceKnown bool                     `json:"mutation_fence_known"`
		MutationOwners     map[string]string        `json:"mutation_owners"`
		Inbounds           []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, false, "", fmt.Errorf("解析 Agent 入站所有权失败: %w", err)
	}
	if response.Success == nil || !*response.Success {
		return nil, false, "", errors.New("Agent 未确认入站清单")
	}
	tag = strings.TrimSpace(tag)
	for _, inbound := range response.Inbounds {
		if strings.TrimSpace(wireGuardStringValue(inbound["tag"])) == tag {
			if matched != nil {
				return nil, response.MutationFenceKnown, "", errors.New("Agent 返回了重复的入站 Tag")
			}
			matched = inbound
		}
	}
	return matched, response.MutationFenceKnown, strings.TrimSpace(response.MutationOwners[tag]), nil
}

func (h *RemoteManageHandler) managedInboundTagExists(ctx context.Context, serverID int64, tag string) (bool, error) {
	result, err := h.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return false, err
	}
	var response struct {
		Success  *bool                    `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return false, fmt.Errorf("解析 Agent 入站清单失败: %w", err)
	}
	if response.Success == nil || !*response.Success {
		return false, errors.New("Agent 未确认入站清单")
	}
	tag = strings.TrimSpace(tag)
	for _, inbound := range response.Inbounds {
		if strings.TrimSpace(wireGuardStringValue(inbound["tag"])) == tag {
			return true, nil
		}
	}
	return false, nil
}

func validateManagedWireGuardMutationACK(body []byte, mutationID string) error {
	var response struct {
		Success        *bool  `json:"success"`
		MutationID     string `json:"mutation_id"`
		Superseded     bool   `json:"superseded"`
		Message        string `json:"message"`
		Error          string `json:"error"`
		Warning        string `json:"warning"`
		RuntimeWarning string `json:"runtime_warning"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("Agent 返回了无法解析的变更结果: %w", err)
	}
	if response.Success == nil || !*response.Success {
		message := strings.TrimSpace(response.Error)
		if message == "" {
			message = strings.TrimSpace(response.Message)
		}
		if message == "" {
			message = "Agent 未确认 WireGuard 变更"
		}
		return errors.New(message)
	}
	if strings.TrimSpace(response.MutationID) != strings.TrimSpace(mutationID) || strings.TrimSpace(mutationID) == "" {
		return errors.New("Agent 未回显匹配的 mutation_id")
	}
	if response.Superseded {
		return errors.New("该 mutation_id 已被同 Tag 的新一代入站替代")
	}
	if warning := strings.TrimSpace(response.Warning); warning != "" {
		return errors.New("Agent WireGuard 变更包含警告: " + warning)
	}
	if warning := strings.TrimSpace(response.RuntimeWarning); warning != "" {
		return errors.New("Agent WireGuard 运行态结果不可信: " + warning)
	}
	return nil
}

func managedWireGuardMutationApplied(recorder *managedNodeResponseRecorder, mutationID string) bool {
	var response struct {
		Success    *bool  `json:"success"`
		Partial    bool   `json:"partial"`
		MutationID string `json:"mutation_id"`
	}
	if recorder == nil || json.Unmarshal(recorder.body.Bytes(), &response) != nil {
		return false
	}
	if strings.TrimSpace(mutationID) == "" || strings.TrimSpace(response.MutationID) != strings.TrimSpace(mutationID) {
		return false
	}
	return response.Partial || (response.Success != nil && *response.Success)
}

func managedInboundPrivateKey(value interface{}) string {
	switch current := value.(type) {
	case map[string]interface{}:
		for key, child := range current {
			normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
			if strings.Contains(normalized, "privatekey") {
				return key
			}
			if nested := managedInboundPrivateKey(child); nested != "" {
				return nested
			}
		}
	case []interface{}:
		for _, child := range current {
			if nested := managedInboundPrivateKey(child); nested != "" {
				return nested
			}
		}
	}
	return ""
}

func validateManagedWireGuardClient(inbound map[string]interface{}, client managedWireGuardClient) (managedWireGuardClient, error) {
	client.PrivateKey = strings.TrimSpace(client.PrivateKey)
	client.PublicKey = strings.TrimSpace(client.PublicKey)
	client.ServerPublicKey = strings.TrimSpace(client.ServerPublicKey)
	client.Address = normalizedWireGuardStrings(client.Address)
	client.DNS = normalizedWireGuardStrings(client.DNS)
	client.AllowedIPs = normalizedWireGuardStrings(client.AllowedIPs)
	if !validWireGuardKey(client.PrivateKey) {
		return client, errors.New("client.private_key must be a 32-byte WireGuard key")
	}
	if !validWireGuardKey(client.PublicKey) {
		return client, errors.New("client.public_key must be a 32-byte WireGuard key")
	}
	derivedClientPublicKey, err := managedWireGuardPublicKey(client.PrivateKey)
	if err != nil || !equalManagedWireGuardKeys(derivedClientPublicKey, client.PublicKey) {
		return client, errors.New("client.public_key does not match client.private_key")
	}
	if len(client.Address) == 0 {
		return client, errors.New("client.address must contain at least one tunnel address")
	}
	for _, address := range client.Address {
		if !validWireGuardHostCIDR(address) {
			return client, errors.New("client.address must use IPv4 /32 or IPv6 /128 host prefixes")
		}
	}
	for _, dnsServer := range client.DNS {
		if net.ParseIP(dnsServer) == nil {
			return client, errors.New("client.dns contains an invalid IP address")
		}
	}
	if client.MTU < 576 || client.MTU > 9000 {
		return client, errors.New("client.mtu must be between 576 and 9000")
	}
	if client.KeepAlive < 0 || client.KeepAlive > 65535 {
		return client, errors.New("client.keep_alive must be between 0 and 65535")
	}
	if len(client.AllowedIPs) == 0 {
		return client, errors.New("client.allowed_ips must contain at least one route")
	}
	for _, allowedIP := range client.AllowedIPs {
		if !validWireGuardIPOrCIDR(allowedIP) {
			return client, errors.New("client.allowed_ips contains an invalid IP/CIDR")
		}
	}

	settings, _ := inbound["settings"].(map[string]interface{})
	serverPublicKey, err := managedWireGuardPublicKey(wireGuardStringValue(settings["secretKey"]))
	if err != nil {
		return client, fmt.Errorf("derive WireGuard server public key: %w", err)
	}
	if !equalManagedWireGuardKeys(serverPublicKey, client.ServerPublicKey) {
		return client, errors.New("client.server_public_key does not match the inbound server key")
	}
	client.ServerPublicKey = serverPublicKey
	if mtu, ok := wireGuardNumericValue(settings["mtu"]); ok && int(mtu) != client.MTU {
		return client, errors.New("client.mtu does not match inbound.settings.mtu")
	}

	var matchingPeer map[string]interface{}
	for _, rawPeer := range wireGuardInterfaceSlice(settings["peers"]) {
		peer, _ := rawPeer.(map[string]interface{})
		if peer != nil && equalManagedWireGuardKeys(wireGuardStringValue(peer["publicKey"]), client.PublicKey) {
			matchingPeer = peer
			break
		}
	}
	if matchingPeer == nil {
		return client, errors.New("client.public_key does not match any inbound peer")
	}
	if keepAlive, ok := wireGuardNumericValue(matchingPeer["keepAlive"]); ok && int(keepAlive) != client.KeepAlive {
		return client, errors.New("client.keep_alive does not match the inbound peer")
	}
	peerAddresses := make(map[string]struct{})
	for _, allowedIP := range wireGuardStringValues(matchingPeer["allowedIPs"]) {
		peerAddresses[strings.TrimSpace(allowedIP)] = struct{}{}
	}
	for _, address := range client.Address {
		if _, ok := peerAddresses[address]; !ok {
			return client, errors.New("client.address is not assigned to the matching inbound peer")
		}
	}
	return client, nil
}

func normalizedWireGuardStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func equalManagedWireGuardKeys(left, right string) bool {
	leftKey, leftErr := decodeManagedWireGuardKey(left)
	rightKey, rightErr := decodeManagedWireGuardKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftKey, rightKey)
}

func buildManagedWireGuardClientConfigs(name, endpointHost string, endpointPort int, client managedWireGuardClient) (string, string, error) {
	name = strings.TrimSpace(name)
	endpointHost = strings.TrimSpace(endpointHost)
	if name == "" || endpointHost == "" || endpointPort < 1 || endpointPort > 65535 {
		return "", "", errors.New("WireGuard endpoint or node name is invalid")
	}
	proxy := map[string]interface{}{
		"name":                 name,
		"type":                 "wireguard",
		"server":               endpointHost,
		"port":                 endpointPort,
		"private-key":          client.PrivateKey,
		"public-key":           client.ServerPublicKey,
		"udp":                  true,
		"mtu":                  client.MTU,
		"allowed-ips":          client.AllowedIPs,
		"persistent-keepalive": client.KeepAlive,
	}
	if len(client.DNS) > 0 {
		proxy["dns"] = client.DNS
	}
	for _, address := range client.Address {
		ip, _, err := net.ParseCIDR(address)
		if err != nil {
			return "", "", fmt.Errorf("parse WireGuard client address: %w", err)
		}
		if ip.To4() != nil {
			proxy["ip"] = ip.String()
		} else {
			proxy["ipv6"] = ip.String()
		}
	}
	encoded, err := json.Marshal(proxy)
	if err != nil {
		return "", "", fmt.Errorf("encode WireGuard node config: %w", err)
	}
	var config strings.Builder
	config.WriteString("[Interface]\nPrivateKey = ")
	config.WriteString(client.PrivateKey)
	config.WriteString("\nAddress = ")
	config.WriteString(strings.Join(client.Address, ", "))
	if len(client.DNS) > 0 {
		config.WriteString("\nDNS = ")
		config.WriteString(strings.Join(client.DNS, ", "))
	}
	config.WriteString("\nMTU = ")
	config.WriteString(strconv.Itoa(client.MTU))
	config.WriteString("\n\n[Peer]\nPublicKey = ")
	config.WriteString(client.ServerPublicKey)
	config.WriteString("\nAllowedIPs = ")
	config.WriteString(strings.Join(client.AllowedIPs, ", "))
	config.WriteString("\nEndpoint = ")
	config.WriteString(net.JoinHostPort(endpointHost, strconv.Itoa(endpointPort)))
	if client.KeepAlive > 0 {
		config.WriteString("\nPersistentKeepalive = ")
		config.WriteString(strconv.Itoa(client.KeepAlive))
	}
	config.WriteByte('\n')
	return string(encoded), config.String(), nil
}

type managedWireGuardPublicMetadata struct {
	ServerPublicKey string                           `json:"server_public_key"`
	ServerAddresses []string                         `json:"server_addresses"`
	MTU             int                              `json:"mtu"`
	Peers           []managedWireGuardPeerPublicData `json:"peers"`
}

type managedWireGuardPeerPublicData struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	KeepAlive  int      `json:"keep_alive"`
}

func managedWireGuardInventoryMatchesResource(inbound map[string]interface{}, resource *storage.ManagedInboundResource) error {
	if resource == nil {
		return errors.New("管理记录为空")
	}
	if canonicalManagedProtocol(wireGuardStringValue(inbound["protocol"])) != "wireguard" ||
		canonicalManagedProtocol(resource.Protocol) != "wireguard" {
		return errors.New("协议不是 WireGuard")
	}
	port, ok := wireGuardNumericValue(inbound["port"])
	if !ok || port != float64(resource.EndpointPort) {
		return fmt.Errorf("监听端口不一致（Agent=%v，预存=%d）", inbound["port"], resource.EndpointPort)
	}
	actual, err := managedWireGuardPublicMetadataFromInbound(inbound)
	if err != nil {
		return err
	}
	var expected managedWireGuardPublicMetadata
	if err := json.Unmarshal(resource.PublicMetadataJSON, &expected); err != nil {
		return fmt.Errorf("解析预存公开配置: %w", err)
	}
	actualCanonical, err := canonicalManagedWireGuardPublicMetadata(actual)
	if err != nil {
		return fmt.Errorf("规范化 Agent 公开配置: %w", err)
	}
	expectedCanonical, err := canonicalManagedWireGuardPublicMetadata(expected)
	if err != nil {
		return fmt.Errorf("规范化预存公开配置: %w", err)
	}
	actualJSON, _ := json.Marshal(actualCanonical)
	expectedJSON, _ := json.Marshal(expectedCanonical)
	if !bytes.Equal(actualJSON, expectedJSON) {
		return errors.New("服务端公钥、地址、MTU 或 Peer 配置不一致")
	}
	return nil
}

func managedWireGuardPublicMetadataFromInbound(inbound map[string]interface{}) (managedWireGuardPublicMetadata, error) {
	settings, _ := inbound["settings"].(map[string]interface{})
	serverPublicKey, err := managedWireGuardPublicKey(wireGuardStringValue(settings["secretKey"]))
	if err != nil {
		return managedWireGuardPublicMetadata{}, fmt.Errorf("derive WireGuard server public key: %w", err)
	}
	metadata := managedWireGuardPublicMetadata{
		ServerPublicKey: serverPublicKey,
		ServerAddresses: wireGuardStringValues(settings["address"]),
		Peers:           make([]managedWireGuardPeerPublicData, 0),
	}
	if mtu, ok := wireGuardNumericValue(settings["mtu"]); ok {
		metadata.MTU = int(mtu)
	}
	for _, rawPeer := range wireGuardInterfaceSlice(settings["peers"]) {
		peer, _ := rawPeer.(map[string]interface{})
		if peer == nil {
			continue
		}
		item := managedWireGuardPeerPublicData{
			PublicKey:  wireGuardStringValue(peer["publicKey"]),
			AllowedIPs: wireGuardStringValues(peer["allowedIPs"]),
		}
		if keepAlive, ok := wireGuardNumericValue(peer["keepAlive"]); ok {
			item.KeepAlive = int(keepAlive)
		}
		metadata.Peers = append(metadata.Peers, item)
	}
	return metadata, nil
}

func canonicalManagedWireGuardPublicMetadata(metadata managedWireGuardPublicMetadata) (managedWireGuardPublicMetadata, error) {
	canonicalKey := func(value string) (string, error) {
		decoded, err := decodeManagedWireGuardKey(value)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(decoded), nil
	}
	serverKey, err := canonicalKey(metadata.ServerPublicKey)
	if err != nil {
		return metadata, fmt.Errorf("invalid server public key: %w", err)
	}
	metadata.ServerPublicKey = serverKey
	metadata.ServerAddresses = normalizedWireGuardStrings(metadata.ServerAddresses)
	sort.Strings(metadata.ServerAddresses)
	for index := range metadata.Peers {
		peerKey, err := canonicalKey(metadata.Peers[index].PublicKey)
		if err != nil {
			return metadata, fmt.Errorf("invalid peer public key: %w", err)
		}
		metadata.Peers[index].PublicKey = peerKey
		metadata.Peers[index].AllowedIPs = normalizedWireGuardStrings(metadata.Peers[index].AllowedIPs)
		sort.Strings(metadata.Peers[index].AllowedIPs)
	}
	sort.Slice(metadata.Peers, func(left, right int) bool {
		if metadata.Peers[left].PublicKey != metadata.Peers[right].PublicKey {
			return metadata.Peers[left].PublicKey < metadata.Peers[right].PublicKey
		}
		leftAllowed := strings.Join(metadata.Peers[left].AllowedIPs, ",")
		rightAllowed := strings.Join(metadata.Peers[right].AllowedIPs, ",")
		if leftAllowed != rightAllowed {
			return leftAllowed < rightAllowed
		}
		return metadata.Peers[left].KeepAlive < metadata.Peers[right].KeepAlive
	})
	return metadata, nil
}

func (h *RemoteManageHandler) upsertWireGuardManagedResource(ctx context.Context, serverID int64, displayName, createdBy string, inbound map[string]interface{}, mutationID string) (*storage.ManagedInboundResource, error) {
	if canonicalManagedProtocol(wireGuardStringValue(inbound["protocol"])) != "wireguard" {
		return nil, errors.New("managed inbound resource protocol is not wireguard")
	}
	if key := managedInboundPrivateKey(inbound); key != "" {
		return nil, fmt.Errorf("WireGuard inbound contains forbidden client private key field %q", key)
	}
	if message := validateInboundWireGuard(map[string]interface{}{"inbound": inbound}); message != "" {
		return nil, errors.New(message)
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil || server == nil {
		return nil, errors.New("server not found")
	}
	tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
	portValue, ok := wireGuardNumericValue(inbound["port"])
	if !ok || portValue < 1 || portValue > 65535 || portValue != float64(int(portValue)) {
		return nil, errors.New("WireGuard endpoint port is invalid")
	}
	metadata, err := managedWireGuardPublicMetadataFromInbound(inbound)
	if err != nil {
		return nil, err
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode WireGuard public metadata: %w", err)
	}
	endpointHost := chooseClashServerHost(server)
	if endpointHost == "" {
		endpointHost = strings.TrimSpace(server.IPAddressV6)
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = fmt.Sprintf("[%s] %s", server.Name, tag)
	}
	createdBy = strings.TrimSpace(createdBy)
	if createdBy == "" {
		createdBy = "system-sync"
	}
	return h.repo.UpsertManagedInboundResource(ctx, storage.ManagedInboundResource{
		ServerID:           serverID,
		DisplayName:        displayName,
		Protocol:           "wireguard",
		InboundTag:         tag,
		MutationID:         strings.TrimSpace(mutationID),
		EndpointHost:       endpointHost,
		EndpointPort:       int(portValue),
		PublicMetadataJSON: metadataJSON,
		CreatedBy:          createdBy,
	})
}

func managedWireGuardPublicKey(privateValue string) (string, error) {
	privateKey, err := decodeManagedWireGuardKey(privateValue)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func decodeManagedWireGuardKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if len(value) == 64 {
		decoded, err := hex.DecodeString(value)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, errors.New("WireGuard key must contain 32 bytes")
}

func managedInboundCreatedBy(ctx context.Context) string {
	if username := strings.TrimSpace(auth.UsernameFromContext(ctx)); username != "" {
		return username
	}
	return "system-sync"
}
