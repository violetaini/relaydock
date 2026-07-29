package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/violetaini/relaydock/internal/probe"
)

// TCPingRequest 表示 TCP ping 请求
type TCPingRequest struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Timeout int    `json:"timeout"` // 超时时间，单位毫秒，默认5000
	// Protocol 节点协议名(小写,如 "hysteria2" / "vless")。
	// 设了 UDP 协议(hysteria/hysteria2/hy2/tuic)时走 udping 路径,否则走原 TCP DialTimeout。
	// 不传(空)兼容老前端 — 走 TCP 路径,保持向后兼容。
	Protocol string `json:"protocol,omitempty"`
}

// TCPingResponse 表示 TCP ping 响应
type TCPingResponse struct {
	Success bool    `json:"success"`
	Latency float64 `json:"latency"` // 延迟（以毫秒为单位）
	Error   string  `json:"error,omitempty"`
}

// 创建一个新的 TCP ping 处理程序
func NewTCPingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "only POST is supported"})
			return
		}

		var req TCPingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}

		if req.Host == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "host is required"})
			return
		}

		if req.Port <= 0 || req.Port > 65535 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid port"})
			return
		}

		timeout := req.Timeout
		if timeout <= 0 {
			timeout = 5000
		}
		if timeout > 30000 {
			timeout = 30000
		}

		address := net.JoinHostPort(req.Host, fmt.Sprintf("%d", req.Port))
		timeoutDuration := time.Duration(timeout) * time.Millisecond

		log.Printf("[TCPing] Testing %s with timeout %dms (protocol=%q)", address, timeout, req.Protocol)

		resp := pingOne(r.Context(), req, timeoutDuration)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})
}

// pingOne 是单次探测的公共路径,根据 req.Protocol 自动选 TCP / UDP 探测。
// 单节点 handler + 批量 handler 共用,保证语义一致。
func pingOne(ctx context.Context, req TCPingRequest, timeout time.Duration) TCPingResponse {
	address := net.JoinHostPort(req.Host, fmt.Sprintf("%d", req.Port))

	// QUIC-based UDP 协议:走 udping(发 QUIC VN trigger 等响应)。
	// TCP DialTimeout 对 hysteria/hysteria2/hy2/tuic 端口永远 fail(没 TCP 套接字)— 这是历史 bug。
	if probe.IsUDPProtocol(req.Protocol) {
		rtt, err := probe.UDPProbe(ctx, req.Host, req.Port, req.Protocol, timeout)
		if err != nil {
			log.Printf("[UDPing] %s (%s) failed: %v", address, req.Protocol, err)
			return TCPingResponse{Success: false, Error: err.Error()}
		}
		latency := float64(rtt.Microseconds()) / 1000.0
		log.Printf("[UDPing] %s (%s) succeeded: %.2fms", address, req.Protocol, latency)
		return TCPingResponse{Success: true, Latency: latency}
	}

	// TCP 路径(向后兼容 — protocol 不传或非 UDP 协议都走这里)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		log.Printf("[TCPing] %s failed: %v", address, err)
		return TCPingResponse{Success: false, Error: err.Error()}
	}
	conn.Close()
	log.Printf("[TCPing] %s succeeded: %.2fms", address, latency)
	return TCPingResponse{Success: true, Latency: latency}
}

// 创建批处理 TCP ping 处理程序
func NewTCPingBatchHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "only POST is supported"})
			return
		}

		var requests []TCPingRequest
		if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}

		if len(requests) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "no nodes to test"})
			return
		}

		if len(requests) > 200 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "max 200 nodes allowed"})
			return
		}

		results := make([]TCPingResponse, len(requests))
		done := make(chan struct{}, len(requests))
		ctx := r.Context()

		for i, req := range requests {
			go func(idx int, item TCPingRequest) {
				defer func() { done <- struct{}{} }()

				if item.Host == "" || item.Port <= 0 || item.Port > 65535 {
					results[idx] = TCPingResponse{Success: false, Error: "invalid host or port"}
					return
				}

				timeout := item.Timeout
				if timeout <= 0 {
					timeout = 5000
				}
				if timeout > 30000 {
					timeout = 30000
				}

				// 跟单节点路径共用 pingOne — UDP/TCP 协议感知一致;批量请求里
				// hy2/tuic 节点也能走 udping(每个 goroutine 独立 UDP socket,无端口竞争)。
				results[idx] = pingOne(ctx, item, time.Duration(timeout)*time.Millisecond)
			}(i, req)
		}

		for range requests {
			<-done
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(results)
	})
}
