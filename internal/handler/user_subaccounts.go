package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

// UserSubaccountsHandler 给管理员查看一个用户的所有子账户(user_subaccounts 路由出站 + user_inbound_configs 入站绑定)
// 以及每个子账户对应的节点/服务器信息。
//
// 路径: GET /api/admin/users/subaccounts?username=xxx
type UserSubaccountsHandler struct {
	repo *storage.TrafficRepository
}

func NewUserSubaccountsHandler(repo *storage.TrafficRepository) http.Handler {
	return &UserSubaccountsHandler{repo: repo}
}

type subaccountItem struct {
	Type       string `json:"type"` // "routed" 或 "inbound"
	Email      string `json:"email,omitempty"`
	Identifier string `json:"identifier,omitempty"` // 凭据(uuid / password) 用于显示;不要透出 credential_json 原始体
	NodeID     int64  `json:"node_id,omitempty"`
	NodeName   string `json:"node_name,omitempty"`
	ServerID   int64  `json:"server_id,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	InboundTag string `json:"inbound_tag,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	IsActive   bool   `json:"is_active"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

type userSubaccountsResponse struct {
	Success     bool             `json:"success"`
	Username    string           `json:"username"`
	Subaccounts []subaccountItem `json:"subaccounts"`
}

func (h *UserSubaccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeError(w, http.StatusBadRequest, errStr("username required"))
		return
	}

	ctx := r.Context()

	// 节点 + 服务器索引,后面查询时拼接
	nodes, _ := h.repo.ListAllNodes(ctx)
	nodeByID := make(map[int64]storage.Node, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	servers, _ := h.repo.ListRemoteServers(ctx)
	serverByID := make(map[int64]string, len(servers))
	serverByName := make(map[string]int64, len(servers))
	for _, s := range servers {
		serverByID[s.ID] = s.Name
		serverByName[s.Name] = s.ID
	}

	items := make([]subaccountItem, 0)

	// 1. 路由出站子账号(user_subaccounts ↔ nodes(routed))
	if routed, err := h.repo.ListUserSubaccounts(ctx, username); err == nil {
		for _, sa := range routed {
			node := nodeByID[sa.RoutedNodeID]
			it := subaccountItem{
				Type:       "routed",
				Email:      sa.Email,
				Identifier: identifierFromCredJSON(sa.CredentialJSON),
				NodeID:     sa.RoutedNodeID,
				NodeName:   node.NodeName,
				IsActive:   sa.IsActive,
				UpdatedAt:  sa.UpdatedAt.Format("2006-01-02 15:04:05"),
				InboundTag: node.InboundTag,
			}
			if node.OriginalServer != "" {
				it.ServerName = node.OriginalServer
				it.ServerID = serverByName[node.OriginalServer]
			}
			items = append(items, it)
		}
	}

	// 2. inbound 绑定(user_inbound_configs ↔ remote_servers + inbound_tag)
	if confs, err := h.repo.GetUserInboundConfigs(ctx, username); err == nil {
		for _, c := range confs {
			it := subaccountItem{
				Type:       "inbound",
				Identifier: identifierFromCredJSON(c.CredentialJSON),
				ServerID:   c.ServerID,
				ServerName: serverByID[c.ServerID],
				InboundTag: c.InboundTag,
				Protocol:   c.Protocol,
				IsActive:   true,
				UpdatedAt:  c.CreatedAt.Format("2006-01-02 15:04:05"),
			}
			items = append(items, it)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userSubaccountsResponse{
		Success:     true,
		Username:    username,
		Subaccounts: items,
	})
}

// identifierFromCredJSON 从凭据 JSON 提取展示用的标识(uuid / password / id) — 完整 JSON 不外发。
func identifierFromCredJSON(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return ""
	}
	for _, k := range []string{"uuid", "password", "id"} {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// errStr 把 string 包成 error,避免 fmt.Errorf 在多个地方引用一行常量
type errStrStr string

func (e errStrStr) Error() string { return string(e) }

func errStr(s string) error { return errStrStr(s) }
