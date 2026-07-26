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
	"net/http"
	"strconv"
	"strings"
	"time"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
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
	Action      string                 `json:"action"`
	DisplayName string                 `json:"display_name"`
	Inbound     map[string]interface{} `json:"inbound"`
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

// HandleManagedInboundResources serves management-only resources. These
// records never enter nodes, packages, subscriptions, URI generation or proxy
// speed tests because a usable WireGuard profile needs a client private key
// that the panel deliberately does not retain.
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
		remoteWriteError(w, http.StatusBadRequest, fmt.Sprintf("WireGuard 请求包含客户端私钥字段 %q；客户端私钥只能保留在浏览器", key))
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
	if _, err := h.repo.GetManagedInboundResourceByServerTag(r.Context(), serverID, tag); err == nil {
		remoteWriteError(w, http.StatusConflict, "该服务器已存在相同 Tag 的 WireGuard 管理资源")
		return
	} else if !errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		remoteWriteError(w, http.StatusInternalServerError, "failed to check managed WireGuard resource")
		return
	}

	payload, err := json.Marshal(map[string]interface{}{
		"action":    "add",
		"node_name": strings.TrimSpace(request.DisplayName),
		"inbound":   request.Inbound,
	})
	if err != nil {
		remoteWriteError(w, http.StatusBadRequest, "failed to encode managed WireGuard request")
		return
	}
	recorder := h.runManagedInboundMutation(r, serverID, payload)
	if recorder.status >= http.StatusBadRequest {
		if managedNodeResponseIsPartial(recorder) {
			rollbackErr := h.rollbackManagedInboundResource(r, serverID, tag)
			message := managedNodeResponseMessage(recorder, "WireGuard 公开元数据落库失败")
			if rollbackErr != nil {
				remoteWriteError(w, http.StatusBadGateway, message+"；自动回滚也失败: "+rollbackErr.Error())
				return
			}
			remoteWriteError(w, http.StatusBadGateway, message+"；刚创建的远程入站已回滚")
			return
		}
		copyHTTPResponse(w, recorder)
		return
	}
	if success, message := managedNodeResponseSuccess(recorder); !success {
		remoteWriteError(w, http.StatusBadGateway, message)
		return
	}
	resource, err := h.repo.GetManagedInboundResourceByServerTag(r.Context(), serverID, tag)
	if err != nil {
		rollbackErr := h.rollbackManagedInboundResource(r, serverID, tag)
		if rollbackErr != nil {
			remoteWriteError(w, http.StatusBadGateway, "WireGuard 入站已创建但管理记录缺失；自动回滚也失败: "+rollbackErr.Error())
			return
		}
		remoteWriteError(w, http.StatusBadGateway, "WireGuard 入站已创建但管理记录缺失；远程入站已回滚")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "resource": managedInboundResourceResponse(resource)})
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
	payload, _ := json.Marshal(map[string]string{"action": "remove", "tag": resource.InboundTag})
	recorder := h.runManagedInboundMutation(r, resource.ServerID, payload)
	if recorder.status >= http.StatusBadRequest {
		copyHTTPResponse(w, recorder)
		return
	}
	if success, message := managedNodeResponseSuccess(recorder); !success {
		remoteWriteError(w, http.StatusBadGateway, message)
		return
	}
	// InboundRemoved normally deletes this synchronously. The explicit delete
	// makes the endpoint robust if event listeners are not installed in a test
	// process or a future embedding.
	if err := h.repo.DeleteManagedInboundResource(r.Context(), id); err != nil && !errors.Is(err, storage.ErrManagedInboundResourceNotFound) {
		remoteWritePartialError(w, "远程 WireGuard 入站已删除，但本地管理记录清理失败")
		return
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

func (h *RemoteManageHandler) rollbackManagedInboundResource(r *http.Request, serverID int64, tag string) error {
	payload, _ := json.Marshal(map[string]string{"action": "remove", "tag": tag})
	recorder := h.runManagedInboundMutation(r, serverID, payload)
	if recorder.status >= http.StatusBadRequest {
		return errors.New(managedNodeResponseMessage(recorder, fmt.Sprintf("回滚 HTTP %d", recorder.status)))
	}
	if success, message := managedNodeResponseSuccess(recorder); !success {
		return errors.New(message)
	}
	_, err := h.repo.DeleteManagedInboundResourceByServerTag(context.Background(), serverID, tag)
	return err
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

func (h *RemoteManageHandler) upsertWireGuardManagedResource(ctx context.Context, serverID int64, displayName, createdBy string, inbound map[string]interface{}) (*storage.ManagedInboundResource, error) {
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
	settings, _ := inbound["settings"].(map[string]interface{})
	serverPublicKey, err := managedWireGuardPublicKey(wireGuardStringValue(settings["secretKey"]))
	if err != nil {
		return nil, fmt.Errorf("derive WireGuard server public key: %w", err)
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
