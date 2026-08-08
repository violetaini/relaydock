// securechan_user.go — 给前端 ↔ 后端 user-facing API 提供 E2E 加密通道。
//
// 协议栈完整复用 internal/securechan/(master↔agent 在用):
//   - X25519 ECDH 密钥交换
//   - HKDF-SHA256 派生双向 AES-256-GCM 密钥
//   - 64-bit 滑动窗口防重放
//   - 二进制 envelope: [version(1)=0x01][seq(8 big-endian)][AES-GCM 密文 + 16B tag]
//
// 接入方式:
//   1. 前端 POST /api/securechan/handshake { client_pub_b64 }
//      → { session_id, server_pub_b64 }
//   2. 前端给敏感 request 加 header X-Secure-Channel: v1 + X-Session-Id: <sid>
//      body = base64(envelope)
//   3. SecureChannelMiddleware 拦截:Decrypt → 用解密 body 喂下游 handler → 用 ResponseRecorder
//      捕获响应 → Encrypt → 写回(同 header)
//   4. 无 X-Secure-Channel header 直接透传(向后兼容老 client + 公共 endpoint)。
//
// Session TTL 30 分钟,失效后前端拿到 X-Secure-Channel-Expired: 1 + 412,自动重做 handshake。

package handler

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/securechan"
)

// 协议常量(必须与前端 src/lib/securechan.ts 保持一致)
const (
	secureChannelVersion       = "v1"
	headerSecureChannel        = "X-Secure-Channel"
	headerSessionID            = "X-Session-Id"
	headerSecureChannelExpired = "X-Secure-Channel-Expired"
	userSessionTTL             = 30 * time.Minute
	maxEncryptedBodyBytes      = 8 << 20 // 8 MiB,防 DoS
	maxSecureChannelResponse   = 8 << 20 // 8 MiB plaintext before encryption
	sessionIDBytes             = 16      // 128-bit session id
	maxUserSecureSessions      = 4096
	maxHandshakeClients        = 10000
	handshakeWindowDuration    = time.Minute
	maxHandshakesPerWindow     = 30
)

// UserSecureChannelHandler 管理前端会话池 + 提供握手 endpoint。
type UserSecureChannelHandler struct {
	mu         sync.Mutex
	sessions   map[string]*userSession
	handshakes map[string]*handshakeWindow
}

type userSession struct {
	sess      *securechan.Session
	createdAt time.Time
	lastUsed  time.Time
	mu        sync.Mutex // 串行化 Encrypt/Decrypt(seq 计数与窗口都是 atomic / mu 保护,这里再加一层语义)
}

type handshakeWindow struct {
	started  time.Time
	lastSeen time.Time
	count    int
}

// NewUserSecureChannelHandler 创建会话池并启动后台清理。
func NewUserSecureChannelHandler() *UserSecureChannelHandler {
	h := &UserSecureChannelHandler{
		sessions:   make(map[string]*userSession),
		handshakes: make(map[string]*handshakeWindow),
	}
	go h.cleanupLoop()
	return h
}

// Handshake POST /api/securechan/handshake
// 请求:  { "client_pub_b64": "<base64 32B X25519>" }
// 响应:  { "session_id": "<hex 32 chars>", "server_pub_b64": "<base64 32B>" }
func (h *UserSecureChannelHandler) Handshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.allowHandshake(GetClientIP(r), time.Now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many handshake requests", http.StatusTooManyRequests)
		return
	}

	var req struct {
		ClientPubB64 string `json:"client_pub_b64"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	clientPub, err := base64.StdEncoding.DecodeString(req.ClientPubB64)
	if err != nil || len(clientPub) != 32 {
		http.Error(w, "invalid client_pub_b64", http.StatusBadRequest)
		return
	}

	serverPriv, serverPub, err := securechan.GenerateEphemeral()
	if err != nil {
		http.Error(w, "keygen failed", http.StatusInternalServerError)
		return
	}
	shared, err := securechan.ComputeSharedSecret(serverPriv, clientPub)
	if err != nil {
		http.Error(w, "ECDH failed", http.StatusInternalServerError)
		return
	}

	// HKDF salt 顺序:把 client 当作 "agent"、server 当作 "master",isMaster=true。
	// 前端必须用 isMaster=false + 同样的 (clientPub, serverPub) salt 顺序。
	sess, err := securechan.DeriveSession(shared, clientPub, serverPub, true)
	if err != nil {
		http.Error(w, "session derive failed", http.StatusInternalServerError)
		return
	}

	sid, err := newSessionID()
	if err != nil {
		http.Error(w, "session id generation failed", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	h.storeSession(sid, &userSession{sess: sess, createdAt: now, lastUsed: now}, now)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"session_id":     sid,
		"server_pub_b64": base64.StdEncoding.EncodeToString(serverPub),
	})
}

// SecureChannelMiddleware 包裹下游 handler,看到 X-Secure-Channel header 就解密 request
// 并加密 response;否则透传(向后兼容 + 公共 endpoint)。
func (h *UserSecureChannelHandler) SecureChannelMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerSecureChannel) != secureChannelVersion {
			next.ServeHTTP(w, r)
			return
		}

		sid := r.Header.Get(headerSessionID)
		entry, ok := h.loadSession(sid, time.Now())
		if !ok {
			h.sendSessionExpired(w)
			return
		}
		// **关键**:GET/HEAD/DELETE/OPTIONS 的 body 会被浏览器 XHR/fetch 按规范丢弃,
		// 前端发不出来 envelope。这些方法只加密响应,不解密请求 body。
		hasBody := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch

		if hasBody {
			// 解密 request body — body 是 base64 编码的 envelope(ASCII 友好,阿里云 / Cloudflare 等
			// CDN/WAF 不会改 ASCII 文本;binary body 会被某些 WAF "智能扫描"而失真)
			bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxEncryptedBodyBytes+1))
			r.Body.Close()
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			if len(bodyBytes) > maxEncryptedBodyBytes {
				http.Error(w, "encrypted body too large", http.StatusRequestEntityTooLarge)
				return
			}
			envelope, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(bodyBytes)))
			if err != nil {
				log.Printf("[securechan_user] base64 decode failed for sid=%s len=%d head=%q err=%v",
					sid, len(bodyBytes), safePrefix(string(bodyBytes), 64), err)
				http.Error(w, "invalid base64 envelope", http.StatusBadRequest)
				return
			}

			entry.mu.Lock()
			plaintext, err := entry.sess.Decrypt(envelope)
			entry.mu.Unlock()
			if err != nil {
				ct := r.Header.Get("Content-Type")
				ver := byte(0)
				if len(envelope) > 0 {
					ver = envelope[0]
				}
				log.Printf("[securechan_user] decrypt failed for sid=%s path=%s method=%s envelope_len=%d envelope_ver=0x%02x req_content_type=%q err=%v",
					sid, r.URL.Path, r.Method, len(envelope), ver, ct, err)
				http.Error(w, "decrypt failed", http.StatusBadRequest)
				return
			}

			// 用解密 body 重建 *http.Request,下游 handler 不感知加密层
			r.Body = io.NopCloser(bytes.NewReader(plaintext))
			r.ContentLength = int64(len(plaintext))
			// 解密后的内容是 JSON — 强制改回 application/json(管理 API 全是 JSON)。
			r.Header.Set("Content-Type", "application/json")
		}

		h.touchSession(sid, entry, time.Now())

		// 缓冲下游响应
		recorder := &responseRecorder{
			ResponseWriter: w,
			body:           &bytes.Buffer{},
			status:         http.StatusOK,
			limit:          maxSecureChannelResponse,
		}
		next.ServeHTTP(recorder, r)
		if recorder.overflow {
			recorder.body.Reset()
			_, _ = recorder.body.WriteString(`{"error":"secure channel response too large","code":"response_too_large"}`)
			recorder.status = http.StatusInternalServerError
		}

		// 加密响应
		entry.mu.Lock()
		respEnvelope, err := entry.sess.Encrypt(recorder.body.Bytes())
		entry.mu.Unlock()
		if err != nil {
			log.Printf("[securechan_user] encrypt response failed for sid=%s: %v", sid, err)
			http.Error(w, "encrypt response failed", http.StatusInternalServerError)
			return
		}

		// 响应也用 base64 text/plain — ASCII-safe,WAF/CDN 不会改
		respB64 := base64.StdEncoding.EncodeToString(respEnvelope)
		w.Header().Set(headerSecureChannel, secureChannelVersion)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Del("Content-Length")
		w.WriteHeader(recorder.status)
		_, _ = w.Write([]byte(respB64))
	})
}

func (h *UserSecureChannelHandler) sendSessionExpired(w http.ResponseWriter) {
	w.Header().Set(headerSecureChannelExpired, "1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPreconditionFailed)
	_, _ = w.Write([]byte(`{"error":"secure channel session expired","code":"session_expired"}`))
}

// cleanupLoop 每 5 分钟扫一次过期 session
func (h *UserSecureChannelHandler) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		h.cleanup(time.Now())
	}
}

func (h *UserSecureChannelHandler) allowHandshake(clientIP string, now time.Time) bool {
	if strings.TrimSpace(clientIP) == "" {
		clientIP = "unknown"
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.handshakes) >= maxHandshakeClients {
		for key, window := range h.handshakes {
			if now.Sub(window.lastSeen) > handshakeWindowDuration {
				delete(h.handshakes, key)
			}
		}
	}
	if len(h.handshakes) >= maxHandshakeClients {
		var oldestKey string
		var oldest time.Time
		for key, window := range h.handshakes {
			if oldestKey == "" || window.lastSeen.Before(oldest) {
				oldestKey, oldest = key, window.lastSeen
			}
		}
		delete(h.handshakes, oldestKey)
	}

	window := h.handshakes[clientIP]
	if window == nil || now.Sub(window.started) >= handshakeWindowDuration {
		h.handshakes[clientIP] = &handshakeWindow{started: now, lastSeen: now, count: 1}
		return true
	}
	window.lastSeen = now
	if window.count >= maxHandshakesPerWindow {
		return false
	}
	window.count++
	return true
}

func (h *UserSecureChannelHandler) storeSession(id string, session *userSession, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneSessionsLocked(now)
	if len(h.sessions) >= maxUserSecureSessions {
		var oldestID string
		var oldest time.Time
		for candidateID, candidate := range h.sessions {
			if oldestID == "" || candidate.lastUsed.Before(oldest) {
				oldestID, oldest = candidateID, candidate.lastUsed
			}
		}
		delete(h.sessions, oldestID)
	}
	h.sessions[id] = session
}

func (h *UserSecureChannelHandler) loadSession(id string, now time.Time) (*userSession, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry, ok := h.sessions[id]
	if !ok {
		return nil, false
	}
	if now.Sub(entry.lastUsed) > userSessionTTL {
		delete(h.sessions, id)
		return nil, false
	}
	return entry, true
}

func (h *UserSecureChannelHandler) touchSession(id string, entry *userSession, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if current, ok := h.sessions[id]; ok && current == entry {
		entry.lastUsed = now
	}
}

func (h *UserSecureChannelHandler) pruneSessionsLocked(now time.Time) {
	for id, entry := range h.sessions {
		if now.Sub(entry.lastUsed) > userSessionTTL {
			delete(h.sessions, id)
		}
	}
}

func (h *UserSecureChannelHandler) cleanup(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneSessionsLocked(now)
	for key, window := range h.handshakes {
		if now.Sub(window.lastSeen) > handshakeWindowDuration {
			delete(h.handshakes, key)
		}
	}
}

func newSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// responseRecorder 缓冲下游 handler 写的 status + body,供加密包装。
type responseRecorder struct {
	http.ResponseWriter
	body     *bytes.Buffer
	status   int
	limit    int
	overflow bool
}

var errSecureChannelResponseTooLarge = errors.New("secure channel response too large")

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	// 不调用 r.ResponseWriter.WriteHeader — header 由外层 Encrypt 后再写
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.overflow || r.limit > 0 && len(b) > r.limit-r.body.Len() {
		r.overflow = true
		return 0, errSecureChannelResponseTooLarge
	}
	return r.body.Write(b)
}

// Header 直接代理,允许下游 handler set 业务 header(会被外层 w 看见 — 但 securechan
// 协议层 header 由外层覆写,业务 header 仍透传)。
func (r *responseRecorder) Header() http.Header {
	return r.ResponseWriter.Header()
}
