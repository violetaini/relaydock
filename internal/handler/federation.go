package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/securechan"
	"github.com/violetaini/relaydock/internal/storage"
)

// 联邦(服务器分享)入口:其他 RelayDock 主控凭分享令牌,通过本主控间接管理被分享的服务器。
// 鉴权用分享令牌(X-Share-Token),不走 JWT。本主控始终是 agent 的唯一控制者,
// 所有转发都经 RemoteManageHandler 走 securechan 到 agent。
//
// 消费方↔拥有方这一跳在 HTTPS 之上叠加"令牌揭示的 ECDH"端到端加密(见 federation_crypto.go),
// 拥有方不支持时消费方自动降级为明文+令牌。

type FederationHandler struct {
	repo              *storage.TrafficRepository
	remoteManage      *RemoteManageHandler
	capabilityManager *capabilities.Manager
	sessions          *securechan.SessionCache // 拥有方侧:按分享令牌缓存与消费方的会话
}

func NewFederationHandler(repo *storage.TrafficRepository, remoteManage *RemoteManageHandler, manager *capabilities.Manager) *FederationHandler {
	return &FederationHandler{repo: repo, remoteManage: remoteManage, capabilityManager: manager, sessions: securechan.NewSessionCache(30 * time.Minute)}
}

func (h *FederationHandler) enabled() bool {
	if h.capabilityManager == nil {
		return false
	}
	return h.capabilityManager.HasFeature(capabilities.FeatureServerShare)
}

// authShare 校验分享令牌,返回被分享的 server_id。
func (h *FederationHandler) authShare(r *http.Request) (int64, error) {
	token := strings.TrimSpace(r.Header.Get("X-Share-Token"))
	if token == "" {
		// 兼容 Authorization: Bearer
		if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
		}
	}
	if token == "" {
		return 0, errors.New("missing share token")
	}
	share, err := h.repo.GetSharedServerByTokenHash(r.Context(), hashShareToken(token))
	if err != nil {
		return 0, errors.New("invalid or revoked share token")
	}
	return share.ServerID, nil
}

func (h *FederationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.enabled() {
		writeError(w, http.StatusForbidden, errors.New("server share capability is not enabled on owner"))
		return
	}
	serverID, err := h.authShare(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	switch r.URL.Path {
	case "/api/federation/manage":
		h.handleManage(w, r, serverID)
	case "/api/federation/server-info":
		h.handleServerInfo(w, r, serverID)
	default:
		writeError(w, http.StatusNotFound, errors.New("not found"))
	}
}

// handleManage 转发一条 agent 管理命令(消费方指定 method/path/body,path 限定 /api/child/)。
// 在 HTTPS 之上叠加令牌揭示的 ECDH 端到端加密:支持密钥交换、加密请求、明文降级三种形态。
func (h *FederationHandler) handleManage(w http.ResponseWriter, r *http.Request, serverID int64) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}

	payload, session, err := h.negotiateManage(w, r)
	if err != nil || payload == nil {
		return // negotiateManage 已写错误响应
	}

	var req struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		BodyB64 string `json:"body"` // base64,可空
	}
	if jerr := json.Unmarshal(payload, &req); jerr != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request"))
		return
	}
	if !strings.HasPrefix(req.Path, "/api/child/") {
		writeError(w, http.StatusBadRequest, errors.New("path must be under /api/child/"))
		return
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		cleanPath := strings.TrimSuffix(strings.SplitN(req.Path, "?", 2)[0], "/")
		if cleanPath == "/api/child/xray/config" ||
			cleanPath == "/api/child/xray/config/files" ||
			strings.HasPrefix(cleanPath, "/api/child/xray/config-files") {
			writeError(w, http.StatusForbidden, errors.New("federated raw Xray config writes are disabled; use owner-side managed operations"))
			return
		}
	}
	var body []byte
	if req.BodyB64 != "" {
		b, derr := base64.StdEncoding.DecodeString(req.BodyB64)
		if derr != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid body encoding"))
			return
		}
		body = b
	}

	result, ferr := h.remoteManage.ForwardToAgent(r.Context(), serverID, req.Method, req.Path, body)
	if ferr != nil {
		writeError(w, http.StatusBadGateway, ferr)
		return
	}
	if session != nil {
		if enc, eerr := session.Encrypt(result); eerr == nil {
			w.Header().Set("X-Encrypted", "1")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(enc)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}

// fedToken 取分享令牌(与 authShare 一致),用作会话缓存键。
func fedToken(r *http.Request) string {
	token := strings.TrimSpace(r.Header.Get("X-Share-Token"))
	if token == "" {
		if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
		}
	}
	return token
}

// negotiateManage 处理握手/解密,返回明文 payload 及用于加密响应的 session(明文请求时为 nil)。
func (h *FederationHandler) negotiateManage(w http.ResponseWriter, r *http.Request) ([]byte, *securechan.Session, error) {
	token := fedToken(r)
	body, _ := io.ReadAll(r.Body)

	// 1. 密钥交换:消费方带临时公钥,拥有方生成自己的临时对并派生会话(令牌揭示),回带公钥。
	if kx := r.Header.Get(fedKeyExchangeHeader); kx != "" {
		consPub, ok := decodeKey(kx)
		if !ok {
			writeError(w, http.StatusBadRequest, errors.New("invalid key exchange"))
			return nil, nil, errBadKeyExchange
		}
		ownerPriv, ownerPub, gerr := securechan.GenerateEphemeral()
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, errors.New("key generation failed"))
			return nil, nil, gerr
		}
		session, derr := deriveFederationSession(ownerPriv, ownerPub, consPub, token, false)
		if derr != nil {
			writeError(w, http.StatusInternalServerError, errors.New("session derivation failed"))
			return nil, nil, derr
		}
		if token != "" {
			h.sessions.Set(token, session)
		}
		w.Header().Set(fedKeyExchangeHeader, encodeKey(ownerPub))
		// 握手阶段请求体为明文,响应也明文返回(消费方此时尚未持有会话)。
		return body, nil, nil
	}

	// 2. 加密请求:用缓存会话解密;无会话要求重新协商。
	if r.Header.Get("X-Encrypted") == "1" {
		session := h.sessions.Get(token)
		if session == nil {
			writeError(w, http.StatusPreconditionFailed, errors.New("no session, re-negotiate"))
			return nil, nil, errNoSession
		}
		plain, derr := session.Decrypt(body)
		if derr != nil {
			writeError(w, http.StatusBadRequest, errors.New("decrypt failed"))
			return nil, nil, derr
		}
		return plain, session, nil
	}

	// 3. 明文请求(自动降级)。
	return body, nil, nil
}

var (
	errBadKeyExchange = errors.New("invalid key exchange")
	errNoSession      = errors.New("no session")
)

// handleServerInfo 返回被分享服务器的状态/流量快照(由拥有方主控采集,透传给消费方)。
func (h *FederationHandler) handleServerInfo(w http.ResponseWriter, r *http.Request, serverID int64) {
	srv, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("server not found"))
		return
	}
	trafficUsed, _ := h.repo.GetServerTrafficUsed(r.Context(), serverID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":                   srv.Name,
		"status":                 srv.Status,
		"ip_address":             srv.IPAddress,
		"xray_mode":              srv.XrayMode,
		"traffic_limit":          srv.TrafficLimit,
		"traffic_reset_day":      srv.TrafficResetDay,
		"traffic_used":           trafficUsed + srv.TrafficUsedOffset,
		"current_upload_speed":   srv.CurrentUploadSpeed,
		"current_download_speed": srv.CurrentDownloadSpeed,
		"xray_running":           srv.XrayRunning,
		"xray_version":           srv.XrayVersion,
		"last_heartbeat":         srv.LastHeartbeat,
	})
}
