package handler

import (
	"context"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

// 流量归因(email → 恰好一个用户 + 一/多个节点)。三个流量视图(节点视图 / 用户视图 / 节点列表)
// 共用同一个归因器,保证口径一致、消除"物理父入站与 routed 出站双算"的历史 bug。
//
// 归因优先级(与 storage.ResolveUsernameByEmail 对齐,#1/#2 在这里直接落到 routed 节点):
//  1. user_subaccounts.email → 该 routed 节点(**忽略 is_active**,UNIQUE(routed_node_id,email) 保证唯一)
//  2. _admin__ 占位 email → nodes.routed_admin_email 对应的 routed 节点
//  3. users.email → username → 该 user 在本 server 的物理入站节点
//  4. `<username>__<tag>` 取首段 → 同上
//  5. 否则丢弃(脏 email:outbound tag 等)
//
// 关键不变量:**任何 routed email(含被停用)都在 #1/#2 命中并归 routed 节点,永不落到父入站**。
// 于是物理节点总量 = Σ其非-routed email = 入站总量 − routed 部分(自动成立,无需显式相减)。

// nodeShare 表示一条 email 归属到某节点;Scale 为均分分母(1=全量,N=该 email 在 N 个物理入站间均分)。
type nodeShare struct {
	NodeID     int64
	NodeName   string
	ServerName string
	Scale      int
}

// emailAttribution 是一条 email 的归因结果。Username 为空表示丢弃(脏数据)。
type emailAttribution struct {
	Username string
	Routed   bool
	Shares   []nodeShare
}

// emailAttributor 预加载全部映射,classify 为纯内存操作(不再每 email 打 DB)。
type emailAttributor struct {
	routedByEmail   map[string]nodeShare // #1+#2: email → routed 节点
	routedEmailUser map[string]string    // email → 归属 username
	inbNodeByKey    map[string]storage.Node
	serverNameByID  map[int64]string
	userServerTags  map[string]map[int64][]string // username → serverID → []inbound_tag
	serverInbTags   map[string][]string           // serverName → 该 server 物理入站 tags(admin 自用兜底)
	usersEmail      map[string]string             // users.email → username
	realUsernames   map[string]bool
}

// buildEmailAttributor 一次性加载归因所需全部映射。
func (h *TrafficHandler) buildEmailAttributor(ctx context.Context) (*emailAttributor, error) {
	a := &emailAttributor{
		routedByEmail:   map[string]nodeShare{},
		routedEmailUser: map[string]string{},
		inbNodeByKey:    map[string]storage.Node{},
		serverNameByID:  map[int64]string{},
		userServerTags:  map[string]map[int64][]string{},
		serverInbTags:   map[string][]string{},
		usersEmail:      map[string]string{},
		realUsernames:   map[string]bool{},
	}

	nodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		return nil, err
	}
	nodesByID := make(map[int64]storage.Node, len(nodes))
	for _, n := range nodes {
		nodesByID[n.ID] = n
		if n.NodeType != "routed" && n.InboundTag != "" {
			a.inbNodeByKey[n.OriginalServer+"::"+n.InboundTag] = n
			a.serverInbTags[n.OriginalServer] = append(a.serverInbTags[n.OriginalServer], n.InboundTag)
		}
	}

	// #1 user_subaccounts(全部,忽略 is_active)→ routed 节点
	subs, err := h.repo.ListAllSubaccounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range subs {
		n, ok := nodesByID[s.RoutedNodeID]
		if !ok {
			continue
		}
		a.routedByEmail[s.Email] = nodeShare{NodeID: n.ID, NodeName: n.NodeName, ServerName: n.OriginalServer, Scale: 1}
		a.routedEmailUser[s.Email] = s.Username
	}
	// #2 _admin__ 占位 email → routed 节点
	admins, err := h.repo.ListRoutedAdminEmailNodes(ctx)
	if err != nil {
		return nil, err
	}
	for _, ad := range admins {
		n, ok := nodesByID[ad.NodeID]
		if !ok {
			continue
		}
		if _, exists := a.routedByEmail[ad.Email]; exists {
			continue // 子账号优先
		}
		a.routedByEmail[ad.Email] = nodeShare{NodeID: n.ID, NodeName: n.NodeName, ServerName: n.OriginalServer, Scale: 1}
		a.routedEmailUser[ad.Email] = ad.Username
	}

	servers, err := h.repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range servers {
		a.serverNameByID[s.ID] = s.Name
	}

	cfgs, err := h.repo.ListAllUserInboundConfigs(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range cfgs {
		if a.userServerTags[c.Username] == nil {
			a.userServerTags[c.Username] = map[int64][]string{}
		}
		a.userServerTags[c.Username][c.ServerID] = append(a.userServerTags[c.Username][c.ServerID], c.InboundTag)
	}

	users, err := h.repo.ListUsers(ctx, 100000)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		a.realUsernames[u.Username] = true
		if u.Email != "" {
			a.usersEmail[u.Email] = u.Username
		}
	}
	return a, nil
}

// classify 把一条 email(在 serverID 上采集到的)归因到用户与节点。纯内存。
func (a *emailAttributor) classify(email string, serverID int64) emailAttribution {
	// #1 + #2:routed(含被停用的子账号 / admin 占位)——永不落父入站
	if ns, ok := a.routedByEmail[email]; ok {
		return emailAttribution{Username: a.routedEmailUser[email], Routed: true, Shares: []nodeShare{ns}}
	}
	// _admin__ 前缀但没有任何 routed 节点持有 → 孤儿,丢弃(与 ResolveUsernameByEmail 一致)
	if strings.HasPrefix(email, "_admin__") {
		return emailAttribution{}
	}
	// #3/#4:解析物理用户
	username := a.resolveUser(email)
	if username == "" || !a.realUsernames[username] {
		return emailAttribution{}
	}
	serverName := a.serverNameByID[serverID]
	if serverName == "" {
		return emailAttribution{}
	}
	tags := a.userServerTags[username][serverID]
	if len(tags) == 0 {
		// admin 自用 inbound(email==username、没走绑套餐注册)→ 摊到该 server 所有物理入站。
		// routed email 已在 #1/#2 拦截,这里只会是真实物理流量,不会污染。
		tags = a.serverInbTags[serverName]
		if len(tags) == 0 {
			return emailAttribution{}
		}
	}
	scale := len(tags)
	var shares []nodeShare
	for _, tag := range tags {
		if n, ok := a.inbNodeByKey[serverName+"::"+tag]; ok {
			shares = append(shares, nodeShare{NodeID: n.ID, NodeName: n.NodeName, ServerName: serverName, Scale: scale})
		}
	}
	if len(shares) == 0 {
		return emailAttribution{}
	}
	return emailAttribution{Username: username, Shares: shares}
}

// resolveUser 复刻 ResolveUsernameByEmail 的 #3/#4/#5(#1/#2 已在 classify 前置处理)。
func (a *emailAttributor) resolveUser(email string) string {
	if u, ok := a.usersEmail[email]; ok {
		return u
	}
	// 按最长真实用户名匹配 `<username>__`,避免用户名含 `__`/尾 `_` 时首个 `__` 拆错(纯内存,遍历预载的 realUsernames)。
	best := ""
	for u := range a.realUsernames {
		if len(u) > len(best) && strings.HasPrefix(email, u+"__") {
			best = u
		}
	}
	if best != "" {
		return best
	}
	if i := strings.Index(email, "__"); i > 0 {
		return email[:i]
	}
	return email
}

// scaled 按 share.Scale 均分一条 email 流量(Scale<=1 原样)。
func scaledEmailTraffic(uet storage.UserEmailTraffic, scale int) storage.UserEmailTraffic {
	if scale <= 1 {
		return uet
	}
	uet.Uplink /= int64(scale)
	uet.Downlink /= int64(scale)
	uet.LastUplink /= int64(scale)
	uet.LastDownlink /= int64(scale)
	return uet
}
