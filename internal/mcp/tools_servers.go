package mcp

import (
	"context"
	"net/http"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerServerTools 远程服务器/服务管理域(list/create/update/delete + 入站/出站/路由读取 +
// 服务控制 + xray/nginx 安装 + agent 升级 + xray 配置 dry-run + reality 域名 + 节点同步)。
func registerServerTools(s *server.MCPServer, b *bridge) {
	// 只读
	s.AddTool(readTool("server_list", "列出所有远程服务器(状态、IP、xray 运行情况等)。"),
		func(ctx context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.get(ctx, "/api/admin/remote-servers")
		})

	s.AddTool(readTool("server_service_status", "查询某远程服务器上服务(xray/nginx 等)的运行状态。",
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.getWithQuery(ctx, "/api/admin/remote/services/status", argsBody(req))
		})

	s.AddTool(readTool("server_inbound_list", "列出某远程服务器的 xray 入站。",
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.getWithQuery(ctx, "/api/admin/remote/inbounds", argsBody(req))
		})

	s.AddTool(readTool("server_inbound_outbounds", "列出某远程服务器 xray 当前出站(direct/freedom/blackhole/路由出站等)。",
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.getWithQuery(ctx, "/api/admin/remote/outbounds", argsBody(req))
		})

	s.AddTool(readTool("server_routing_get", "读取某远程服务器 xray 当前路由配置(routing.rules 等)。",
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.getWithQuery(ctx, "/api/admin/remote/routing", argsBody(req))
		})

	s.AddTool(readTool("server_system_info", "读取远程服务器系统资源(CPU/内存/磁盘/uptime/内核版本)。用于故障排查。",
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.getWithQuery(ctx, "/api/admin/remote/system/info", argsBody(req))
		})

	s.AddTool(readTool("server_xray_config_get", "拉取远程服务器当前完整 xray-config.json(诊断/审计场景)。",
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.getWithQuery(ctx, "/api/admin/remote/xray/config", argsBody(req))
		})

	s.AddTool(readTool("server_reality_domains", "列出某远程服务器候选的 reality 目标域名(常用于创建 reality 入站时选 dest)。",
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.getWithQuery(ctx, "/api/admin/remote/reality-domains", argsBody(req))
		})

	s.AddTool(readTool("server_check_same_ip", "检测当前服务器列表中存在哪些相同 IP 的服务器(诊断「重复服务器」问题)。"),
		func(ctx context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.get(ctx, "/api/admin/check-same-ip")
		})

	// 写
	s.AddTool(writeTool("server_create", "新增一台远程服务器(主控登记;真正接入需在该机器上跑 relaydock-agent 并提供 token)。", false,
		mcpgo.WithString("name", mcpgo.Required(), mcpgo.Description("服务器名称")),
		mcpgo.WithString("ip_address", mcpgo.Description("IP 地址(可选)")),
		mcpgo.WithString("domain", mcpgo.Description("域名(可选)")),
		mcpgo.WithString("connection_mode", mcpgo.Description("push / pull / auto;默认 push")),
		mcpgo.WithNumber("listen_port", mcpgo.Description("agent 监听端口")),
		mcpgo.WithNumber("traffic_limit", mcpgo.Description("流量限额(字节)")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/remote-servers/create", argsBody(req))
		})

	s.AddTool(writeTool("server_update", "更新远程服务器属性(改名、改 IP/域名、改连接模式、改限额等)。", true,
		mcpgo.WithNumber("id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
		mcpgo.WithString("name", mcpgo.Description("新名称")),
		mcpgo.WithString("ip_address", mcpgo.Description("新 IP")),
		mcpgo.WithString("domain", mcpgo.Description("新域名")),
		mcpgo.WithString("connection_mode", mcpgo.Description("push / pull / auto / websocket")),
		mcpgo.WithNumber("listen_port", mcpgo.Description("agent 监听端口")),
		mcpgo.WithNumber("traffic_limit", mcpgo.Description("流量限额(字节)")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/remote-servers/update", argsBody(req))
		})

	s.AddTool(writeTool("server_delete", "删除远程服务器(=断开 agent + 失去该服务器上所有节点)。", true,
		mcpgo.WithNumber("id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
		mcpgo.WithBoolean("confirm", mcpgo.Description("必须为 true 才执行")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			if msg, ok := confirmGate(req, "删除远程服务器"); !ok {
				return msg, nil
			}
			return b.send(ctx, http.MethodPost, "/api/admin/remote-servers/delete", argsBody(req))
		})

	s.AddTool(writeTool("server_service_control", "控制远程服务器上的服务(启动/停止/重启 xray、nginx 等)。", true,
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
		mcpgo.WithString("service", mcpgo.Required(), mcpgo.Description("服务名,如 xray / nginx")),
		mcpgo.WithString("action", mcpgo.Required(), mcpgo.Description("动作:start / stop / restart")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/remote/services/control", argsBody(req))
		})

	s.AddTool(writeTool("server_inbound_apply", "在远程服务器上新增/更新/删除一个 xray 入站。action=add/update/remove;add/update 传 inbound 对象,remove 传 tag。", true,
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
		mcpgo.WithString("action", mcpgo.Required(), mcpgo.Description("add / update / remove")),
		mcpgo.WithObject("inbound", mcpgo.Description("入站对象(add/update 时必填)")),
		mcpgo.WithString("tag", mcpgo.Description("入站 tag(remove 时必填)")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			sid, err := req.RequireString("server_id")
			if err != nil {
				return mcpgo.NewToolResultError("server_id 必填"), nil
			}
			return b.send(ctx, http.MethodPost, "/api/admin/remote/inbounds?server_id="+pathEscape(sid), argsBody(req, "server_id"))
		})

	s.AddTool(writeTool("server_xray_test_config", "对一份 xray-config 做 dry-run 校验(不写入,只校验语法/字段)。常用于改路由前的预检。", false,
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
		mcpgo.WithObject("config", mcpgo.Required(), mcpgo.Description("完整 xray 配置 JSON")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/remote/xray/test-config", argsBody(req))
		})

	// SSE 运维:bridge 经 httptest 录制器消费整条流到结束,把进度日志一次性返回(执行并等待完成型)
	s.AddTool(writeTool("server_xray_install", "在远程服务器安装 Xray(耗时操作,会等待完成并返回安装日志)。", true,
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
		mcpgo.WithBoolean("confirm", mcpgo.Description("必须为 true 才执行")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			if msg, ok := confirmGate(req, "安装 Xray"); !ok {
				return msg, nil
			}
			return b.send(ctx, http.MethodPost, "/api/admin/remote/xray/install-stream", argsBody(req))
		})

	s.AddTool(writeTool("server_nginx_install", "在远程服务器安装 Nginx(耗时操作,会等待完成并返回日志)。", true,
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
		mcpgo.WithBoolean("confirm", mcpgo.Description("必须为 true 才执行")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			if msg, ok := confirmGate(req, "安装 Nginx"); !ok {
				return msg, nil
			}
			return b.send(ctx, http.MethodPost, "/api/admin/remote/nginx/install-stream", argsBody(req))
		})

	s.AddTool(writeTool("server_agent_upgrade", "升级远程 relaydock-agent(SSE 等完成;升级期间该 agent 会重启,短暂失联)。", true,
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
		mcpgo.WithBoolean("confirm", mcpgo.Description("必须为 true 才执行")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			if msg, ok := confirmGate(req, "升级 relaydock-agent"); !ok {
				return msg, nil
			}
			return b.send(ctx, http.MethodPost, "/api/admin/remote/agent/upgrade-stream", argsBody(req))
		})

	s.AddTool(writeTool("server_sync_nodes", "把远程服务器的入站同步为节点管理中的节点。", false,
		mcpgo.WithString("server_id", mcpgo.Required(), mcpgo.Description("服务器 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/remote/sync-nodes", argsBody(req))
		})
}
