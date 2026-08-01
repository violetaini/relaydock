package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ProbeWSHandler broadcasts one public-probe snapshot to every connected
// visitor. The page has a normal HTTP fallback, but sharing one calculation
// every second avoids N visitors independently polling SQLite and the
// metric store.
//
// This endpoint is intentionally unauthenticated. Connection limits, bounded
// queues and a read deadline are therefore part of the security boundary.
type ProbeWSHandler struct {
	public   *ProbePublicHandler
	upgrader websocket.Upgrader

	mu           sync.Mutex
	clients      map[*probeWSClient]struct{}
	perIP        map[string]int
	pending      int
	pendingPerIP map[string]int
	running      bool
}

type probeWSClient struct {
	conn *websocket.Conn
	send chan []byte
	ip   string
}

const (
	probeWSMaxClients      = 200
	probeWSMaxPerIP        = 5
	probeWSBroadcastPeriod = time.Second
	probeWSWriteTimeout    = 10 * time.Second
	probeWSPongTimeout     = 60 * time.Second
	probeWSPingPeriod      = 25 * time.Second
	probeWSSendBuffer      = 4
)

func NewProbeWSHandler(public *ProbePublicHandler) *ProbeWSHandler {
	return &ProbeWSHandler{
		public: public,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			// This is deliberately public, read-only data. Browser origin is not
			// a credential boundary here; admission controls are handled below.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		clients:      make(map[*probeWSClient]struct{}),
		perIP:        make(map[string]int),
		pendingPerIP: make(map[string]int),
	}
}

func (h *ProbeWSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h == nil || h.public == nil || h.public.repo == nil {
		http.NotFound(w, r)
		return
	}
	if !probeDisguiseEnabled(r.Context(), h.public.repo) {
		http.NotFound(w, r)
		return
	}

	ip := probeWSClientIP(r)
	if !h.reserveClientSlot(ip) {
		// A retryable response lets the frontend fall back to GET polling.
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.releaseClientSlot(ip)
		return
	}
	c := &probeWSClient{conn: conn, send: make(chan []byte, probeWSSendBuffer), ip: ip}

	// Build an initial frame before admitting the client. It makes a healthy
	// connection useful immediately rather than requiring a five-second wait.
	var initial []byte
	if payload, err := h.public.buildPayload(r.Context()); err == nil {
		initial, _ = json.Marshal(payload)
	}

	h.mu.Lock()
	h.releaseClientSlotLocked(ip)
	h.clients[c] = struct{}{}
	h.perIP[ip]++
	if len(initial) > 0 {
		c.send <- initial
	}
	start := !h.running
	if start {
		h.running = true
	}
	h.mu.Unlock()

	if start {
		go h.broadcastLoop()
	}
	go h.writePump(c)
	h.readPump(c)
}

// reserveClientSlot accounts for handshakes that have passed admission but
// have not yet completed WebSocket upgrade. Keeping the reservation separate
// means a burst of concurrent Upgrade calls cannot bypass either limit, while
// the mutex is never held across network I/O.
func (h *ProbeWSHandler) reserveClientSlot(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients)+h.pending >= probeWSMaxClients || h.perIP[ip]+h.pendingPerIP[ip] >= probeWSMaxPerIP {
		return false
	}
	h.pending++
	h.pendingPerIP[ip]++
	return true
}

func (h *ProbeWSHandler) releaseClientSlot(ip string) {
	h.mu.Lock()
	h.releaseClientSlotLocked(ip)
	h.mu.Unlock()
}

func (h *ProbeWSHandler) releaseClientSlotLocked(ip string) {
	if h.pending > 0 {
		h.pending--
	}
	if h.pendingPerIP[ip] <= 1 {
		delete(h.pendingPerIP, ip)
	} else {
		h.pendingPerIP[ip]--
	}
}

func (h *ProbeWSHandler) readPump(c *probeWSClient) {
	defer h.removeClient(c)
	c.conn.SetReadLimit(512)
	_ = c.conn.SetReadDeadline(time.Now().Add(probeWSPongTimeout))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(probeWSPongTimeout))
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
		// The stream is server-to-client only. A browser never has to send an
		// application frame here, so accepting and ignoring arbitrary input
		// would create a needless CPU/connection-pressure surface.
		_ = c.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "read-only stream"),
			time.Now().Add(probeWSWriteTimeout),
		)
		return
	}
}

func (h *ProbeWSHandler) writePump(c *probeWSClient) {
	ticker := time.NewTicker(probeWSPingPeriod)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				return
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(probeWSWriteTimeout))
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(probeWSWriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (h *ProbeWSHandler) removeClient(c *probeWSClient) {
	if h == nil || c == nil {
		return
	}
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
		if h.perIP[c.ip] <= 1 {
			delete(h.perIP, c.ip)
		} else {
			h.perIP[c.ip]--
		}
	}
	h.mu.Unlock()
	_ = c.conn.Close()
}

func (h *ProbeWSHandler) broadcastLoop() {
	ticker := time.NewTicker(probeWSBroadcastPeriod)
	defer ticker.Stop()
	for range ticker.C {
		h.mu.Lock()
		if len(h.clients) == 0 {
			h.running = false
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()

		payload, err := h.public.buildPayload(nil)
		if err != nil {
			continue
		}
		message, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		h.mu.Lock()
		for client := range h.clients {
			select {
			case client.send <- message:
			default:
				// A blocked visitor must not pin the shared broadcaster or grow
				// unbounded memory. Close it outside the lock.
				go h.removeClient(client)
			}
		}
		h.mu.Unlock()
	}
}

// probeWSClientIP accepts X-Real-IP only when the direct peer is loopback.
// The bundled Nginx reverse proxy is local and overwrites that header with the
// visitor it observed; a direct client cannot spoof it. X-Forwarded-For stays
// deliberately ignored because the origin may be reachable directly.
func probeWSClientIP(r *http.Request) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		remote = host
	}
	peer := net.ParseIP(strings.Trim(remote, "[]"))
	if peer == nil {
		return remote
	}
	if peer.IsLoopback() {
		if realIP := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); realIP != nil {
			return realIP.String()
		}
	}
	return peer.String()
}
