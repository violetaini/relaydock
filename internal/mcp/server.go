package mcp

import (
	"context"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/server"
)

// NewHandler 构建嵌入式 MCP server,返回可挂到主控 mux(/mcp)的 http.Handler。
// mux 为主控顶层路由(工具调用经它复用现有 REST handler + 鉴权)。
func NewHandler(mux http.Handler) http.Handler {
	s := server.NewMCPServer("relaydock", "0.1.0")
	b := &bridge{mux: mux}

	registerNodeTools(s, b)
	registerServerTools(s, b)
	registerSubscribeTools(s, b)
	registerUserPackageTools(s, b)
	registerTemplateRuleTools(s, b)
	registerMiscTools(s, b)

	return server.NewStreamableHTTPServer(s,
		server.WithStateLess(true), // 无状态:每次请求独立,适配无会话的 agent 调用
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			// 把 API 令牌从请求头提取进 context,供 bridge 在内部回放时携带
			tok := strings.TrimSpace(r.Header.Get("MM-Authorization"))
			if tok == "" {
				if bearer := strings.TrimSpace(r.Header.Get("Authorization")); bearer != "" {
					tok = strings.TrimSpace(strings.TrimPrefix(bearer, "Bearer "))
				}
			}
			return withToken(ctx, tok)
		}),
	)
}
