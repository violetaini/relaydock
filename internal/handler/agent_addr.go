package handler

// agent_addr.go — master → agent 反向 HTTP 请求的 URL 候选与 IPv4/IPv6 fallback。
//
// 背景:
//   1. RemoteServer 现在同时有 IPAddress(v4 主用)和 IPAddressV6(新增)两个字段。
//   2. WS-first 反向 RPC 是首选,本文件只为 WS 不可用时的 HTTP fallback 提供"按候选清单逐个试"的能力。
//   3. 原来 4 处直连用 strings.LastIndex(":") 自己删 port 的逻辑,对 IPv6 地址会错误截断
//      ("2001:db8::1" 截成 "2001:db8::"),且部分位置缺 [] 包裹。本文件用 net.SplitHostPort
//      统一处理,顺手修掉这两个老 bug。
//
// 使用方式:消费方只需 tryHTTPWithFallback(ctx, client, server, method, path, body, header) 即可,
// 内部自动 v4 优先 → v6 fallback;若 v4/v6 都不通,返回 lastErr 包裹的最终错误。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

// buildAgentURL 把单个 IP literal(v4 或 v6) + port + path 拼成有效 URL。
// 规则:
//   - 空 IP → 空串(调用方需要 skip)
//   - 已带 [] 的 IPv6 → 直接拼
//   - 裸 IPv6(含 ":")→ 自动加 []
//   - IPv4 / hostname → 直接拼
func buildAgentURL(ip string, port int, path string) string {
	if ip == "" {
		return ""
	}
	if strings.HasPrefix(ip, "[") {
		return fmt.Sprintf("http://%s:%d%s", ip, port, path)
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("http://[%s]:%d%s", ip, port, path)
	}
	return fmt.Sprintf("http://%s:%d%s", ip, port, path)
}

// agentStripPort 把可能带 port 的地址规整成纯 IP literal。
// 例:
//
//	"1.2.3.4:5678"      -> "1.2.3.4"
//	"[2001:db8::1]:5678" -> "2001:db8::1"
//	"2001:db8::1"        -> "2001:db8::1"(SplitHostPort 失败,回退原值)
//	"1.2.3.4"            -> "1.2.3.4"
//
// 用 stdlib net.SplitHostPort,正确处理 v4/v6/带 bracket,消灭原来的 LastIndex(":") bug。
func agentStripPort(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// buildAgentURLCandidates 按优先级返回 [v4, v6] URL 候选。空字段自动跳过。
// 默认端口 23889(与 deployRemoteCertificateHTTP / pushViaHTTP 等老路径默认一致)。
func buildAgentURLCandidates(server *storage.RemoteServer, path string) []string {
	port := server.ListenPort
	if port <= 0 {
		port = 23889
	}
	var urls []string
	if v4 := agentStripPort(server.IPAddress); v4 != "" {
		if u := buildAgentURL(v4, port, path); u != "" {
			urls = append(urls, u)
		}
	}
	if v6 := agentStripPort(server.IPAddressV6); v6 != "" {
		if u := buildAgentURL(v6, port, path); u != "" {
			// 去重:IPv6-only 服务器场景下 IPAddress 装的可能也是 v6,与 IPAddressV6 同值
			already := false
			for _, prev := range urls {
				if prev == u {
					already = true
					break
				}
			}
			if !already {
				urls = append(urls, u)
			}
		}
	}
	return urls
}

// ErrNoAgentURL 表示 server 既没有 v4 也没有 v6 — 没法发请求。
var ErrNoAgentURL = errors.New("server has no agent URL (IPAddress and IPAddressV6 both empty)")

// httpHeader 是一个简化的 header 接口 — 直接传 http.Header(可空)。
// hdr 内的字段会逐 key 拷贝到 request,**Content-Type / Authorization / User-Agent 一律由调用方在 hdr 里塞**。
// (helper 不假定 Content-Type 是 JSON,避免对 cert deploy / form 等多种 payload 强加约束。)
func tryHTTPWithFallback(
	ctx context.Context,
	client *http.Client,
	server *storage.RemoteServer,
	method, path string,
	body []byte,
	hdr http.Header,
) (*http.Response, error) {
	urls := buildAgentURLCandidates(server, path)
	if len(urls) == 0 {
		return nil, ErrNoAgentURL
	}
	var lastErr error
	for i, u := range urls {
		var reader io.Reader
		if len(body) > 0 {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, reader)
		if err != nil {
			lastErr = err
			continue
		}
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		resp, err := client.Do(req)
		// 成功 + 非 5xx:无论 2xx 还是 4xx,都是 agent 给出的明确答复,**不 fallback**。
		// 业务错误(4xx)语义错就是错,fallback 到 v6 也会一样错,只会浪费时间且双重打日志。
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if i+1 < len(urls) {
			log.Printf("[agent_addr] %s %s on server %d candidate %q failed (%v), trying next", method, path, server.ID, u, lastErr)
		}
	}
	return nil, fmt.Errorf("all candidates failed for server %d %s %s: %w", server.ID, method, path, lastErr)
}
