// Package mcp 在主控内提供嵌入式 MCP server(streamable-HTTP),供 OpenClaw 等 agent 运维 RelayDock。
// 设计:工具是薄封装,内部把调用转成对现有 REST mux 的 HTTP 请求(带调用方 API 令牌),
// 复用现有 handler + 鉴权链(RequireToken/RequireAdmin),零业务逻辑复制,权限与 Web 端一致。
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

type ctxKey string

const tokenCtxKey ctxKey = "mmwx_api_token"

func withToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenCtxKey, token)
}

func tokenFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(tokenCtxKey).(string); ok {
		return v
	}
	return ""
}

// bridge 持有内部 mux(主控顶层路由),把工具调用回放成内部 HTTP 请求。
type bridge struct {
	mux http.Handler
}

// call 以调用方的 API 令牌发起一次内部 HTTP 调用,返回状态码与响应体。
func (b *bridge) call(ctx context.Context, method, path string, body any) (int, []byte) {
	var reader *bytes.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if tok := tokenFromCtx(ctx); tok != "" {
		req.Header.Set("MM-Authorization", tok)
	}
	rec := httptest.NewRecorder()
	b.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// result 把内部响应转成 MCP 工具结果:>=400 作为工具错误透传,其余作为文本(JSON)返回。
func result(code int, body []byte) (*mcpgo.CallToolResult, error) {
	if code >= 400 {
		return mcpgo.NewToolResultError(fmt.Sprintf("HTTP %d: %s", code, string(body))), nil
	}
	return mcpgo.NewToolResultText(string(body)), nil
}

func (b *bridge) get(ctx context.Context, path string) (*mcpgo.CallToolResult, error) {
	code, body := b.call(ctx, http.MethodGet, path, nil)
	return result(code, body)
}

// getWithQuery 把 argsBody 当 querystring 拼到 path 后,适配 mmwx 大量 query-style GET endpoint
// (例如 /api/admin/remote/inbounds?server_id=...)。基础类型(string/number/bool)直接 Set,
// 复杂类型(map/array)JSON 序列化后 Set。omit 用来跳过控制字段(如 confirm)和已经在 path 里的字段。
func (b *bridge) getWithQuery(ctx context.Context, path string, args map[string]any, omit ...string) (*mcpgo.CallToolResult, error) {
	if len(args) > 0 {
		q := url.Values{}
		skip := map[string]bool{"confirm": true}
		for _, o := range omit {
			skip[o] = true
		}
		for k, v := range args {
			if skip[k] {
				continue
			}
			switch val := v.(type) {
			case string:
				if val != "" {
					q.Set(k, val)
				}
			case bool:
				q.Set(k, fmt.Sprintf("%t", val))
			case float64, float32, int, int64:
				q.Set(k, fmt.Sprintf("%v", val))
			default:
				if buf, err := json.Marshal(v); err == nil {
					q.Set(k, string(buf))
				}
			}
		}
		if encoded := q.Encode(); encoded != "" {
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			path = path + sep + encoded
		}
	}
	code, body := b.call(ctx, http.MethodGet, path, nil)
	return result(code, body)
}

func (b *bridge) send(ctx context.Context, method, path string, body any) (*mcpgo.CallToolResult, error) {
	code, respBody := b.call(ctx, method, path, body)
	return result(code, respBody)
}

// pathEscape 用于把用户提供的标识(用户名等)安全拼进路径。
func pathEscape(s string) string { return url.PathEscape(s) }
