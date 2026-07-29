package mcp

import (
	"context"
	"net/http"
	"strconv"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerTemplateRuleTools 订阅模板(V3 / V2 规则模板)+ 自定义规则 域。
// 注意:V3 的 /process 端点会读磁盘 rule_templates/{name},不暴露;只暴露 list/preview-with-tags/analyze。
func registerTemplateRuleTools(s *server.MCPServer, b *bridge) {
	// —— V3 模板 ——
	s.AddTool(readTool("template_v3_list", "列出所有 V3 订阅模板(RelayDock 模板系统,带 selected_tags 筛选)。"),
		func(ctx context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.get(ctx, "/api/admin/template-v3")
		})

	s.AddTool(readTool("template_v3_preview", "用 inline content + 一批 proxies 预览渲染后的订阅 YAML。常用于改模板前预览效果。",
		mcpgo.WithString("template_content", mcpgo.Required(), mcpgo.Description("V3 模板内容(YAML 字符串)")),
		mcpgo.WithArray("proxies", mcpgo.Required(), mcpgo.Description("代理节点数组(Clash 节点对象)")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/template-v3/preview-with-tags", argsBody(req))
		})

	s.AddTool(readTool("template_v3_analyze", "分析一份订阅 URL,提取节点的区域/tag 分布(用于评估筛选效果)。",
		mcpgo.WithString("subscription_url", mcpgo.Required(), mcpgo.Description("订阅 URL")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/template-v3/analyze-subscription", argsBody(req))
		})

	// —— V2 规则模板(老版,只读) ——
	s.AddTool(readTool("rule_template_list", "列出旧版 V2 规则模板(已被 V3 取代,仅用于读老订阅生成器配置)。"),
		func(ctx context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.get(ctx, "/api/admin/templates")
		})

	s.AddTool(readTool("rule_template_get", "查询单个 V2 模板内容。",
		mcpgo.WithNumber("id", mcpgo.Required(), mcpgo.Description("模板 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			idF, err := req.RequireFloat("id")
			if err != nil {
				return mcpgo.NewToolResultError("id 必填"), nil
			}
			return b.get(ctx, "/api/admin/templates/"+strconv.FormatInt(int64(idF), 10))
		})

	// —— 自定义规则 CRUD ——
	s.AddTool(readTool("custom_rule_list", "列出所有自定义订阅分流规则(将在订阅生成时插入到模板规则之前,优先级更高)。"),
		func(ctx context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.get(ctx, "/api/admin/custom-rules")
		})

	s.AddTool(readTool("custom_rule_get", "查询单条自定义规则详情。",
		mcpgo.WithNumber("id", mcpgo.Required(), mcpgo.Description("规则 ID")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			idF, err := req.RequireFloat("id")
			if err != nil {
				return mcpgo.NewToolResultError("id 必填"), nil
			}
			return b.get(ctx, "/api/admin/custom-rules/"+strconv.FormatInt(int64(idF), 10))
		})

	s.AddTool(writeTool("custom_rule_create", "新增自定义分流规则。type 见现有规则示例(DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD/IP-CIDR/GEOIP)。", false,
		mcpgo.WithString("type", mcpgo.Required(), mcpgo.Description("规则类型")),
		mcpgo.WithString("payload", mcpgo.Required(), mcpgo.Description("规则匹配体")),
		mcpgo.WithString("policy", mcpgo.Required(), mcpgo.Description("命中后的策略,如 DIRECT / PROXY / 节点组名")),
		mcpgo.WithString("remark", mcpgo.Description("备注")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/custom-rules", argsBody(req))
		})

	s.AddTool(writeTool("custom_rule_update", "更新自定义规则(覆盖式)。", true,
		mcpgo.WithNumber("id", mcpgo.Required(), mcpgo.Description("规则 ID")),
		mcpgo.WithString("type", mcpgo.Description("新类型")),
		mcpgo.WithString("payload", mcpgo.Description("新匹配体")),
		mcpgo.WithString("policy", mcpgo.Description("新策略")),
		mcpgo.WithString("remark", mcpgo.Description("新备注")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			idF, err := req.RequireFloat("id")
			if err != nil {
				return mcpgo.NewToolResultError("id 必填"), nil
			}
			return b.send(ctx, http.MethodPut, "/api/admin/custom-rules/"+strconv.FormatInt(int64(idF), 10), argsBody(req, "id"))
		})

	s.AddTool(writeTool("custom_rule_delete", "删除自定义规则(影响所有订阅生成)。", true,
		mcpgo.WithNumber("id", mcpgo.Required(), mcpgo.Description("规则 ID")),
		mcpgo.WithBoolean("confirm", mcpgo.Description("必须为 true 才执行")),
	),
		func(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			idF, err := req.RequireFloat("id")
			if err != nil {
				return mcpgo.NewToolResultError("id 必填"), nil
			}
			if msg, ok := confirmGate(req, "删除自定义规则"); !ok {
				return msg, nil
			}
			return b.send(ctx, http.MethodDelete, "/api/admin/custom-rules/"+strconv.FormatInt(int64(idF), 10), nil)
		})

	s.AddTool(writeTool("custom_rule_apply", "把当前所有自定义规则应用到现有订阅(触发一次订阅缓存刷新)。", false),
		func(ctx context.Context, _ mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
			return b.send(ctx, http.MethodPost, "/api/admin/apply-custom-rules", nil)
		})
}
