package event

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"miaomiaowux/internal/storage"
)

// InboundToClashFunc 入站转 Clash 配置的函数类型
type InboundToClashFunc func(serverID int64, inbound map[string]any) (string, error)

// NodeSyncListener 节点同步监听器
type NodeSyncListener struct {
	repo           *storage.TrafficRepository
	inboundToClash InboundToClashFunc
}

type managedNodePlan struct {
	name          string
	host          string
	port          int
	relayOrigHost string
	relayOrigPort int
}

// 创建节点同步监听器
func NewNodeSyncListener(repo *storage.TrafficRepository, converter InboundToClashFunc) *NodeSyncListener {
	return &NodeSyncListener{
		repo:           repo,
		inboundToClash: converter,
	}
}

// 处理入站事件
func (l *NodeSyncListener) Handle(event InboundEvent) error {
	ctx := context.Background()

	switch event.Type {
	case EventInboundAdded:
		return l.handleAdded(ctx, event)
	case EventInboundRemoved:
		return l.handleRemoved(ctx, event)
	case EventInboundUpdated:
		return l.handleUpdated(ctx, event)
	}
	return nil
}

func (l *NodeSyncListener) handleAdded(ctx context.Context, event InboundEvent) error {
	// 获取服务器信息
	server, err := l.repo.GetRemoteServer(ctx, event.ServerID)
	if err != nil {
		log.Printf("[NodeSync] Failed to get server %d: %v", event.ServerID, err)
		return fmt.Errorf("读取服务器 %d 失败: %w", event.ServerID, err)
	}

	if event.Tag == "api" {
		return nil
	}
	if strings.TrimSpace(event.MutationID) != "" {
		if err := l.repo.SetRemoteInboundOwnership(ctx, event.ServerID, event.Tag, event.MutationID); err != nil {
			log.Printf("[NodeSync] Failed to persist inbound ownership for %s: %v", event.Tag, err)
			return fmt.Errorf("保存入站 %s 所有权失败: %w", event.Tag, err)
		}
	}
	// The dedicated WireGuard creation endpoint creates the ordinary node only
	// after it has encrypted the client private key. Inventory events contain no
	// client secret, so converting them here would create a broken duplicate.
	if strings.EqualFold(strings.TrimSpace(event.Protocol), "wireguard") {
		return nil
	}
	// 端口转发入站默认不进节点表；「转发已有节点」才克隆源节点生成配套节点。
	if isTunnelProtocol(event.Protocol) {
		if event.ForwardNodeID > 0 {
			return l.createForwardTunnelNode(ctx, event, server)
		}
		return nil
	}

	// 生成节点名称：优先使用自定义名称，否则使用 tag 或 protocol:port
	var nodeName string
	if event.NodeName != "" {
		nodeName = event.NodeName
	} else if event.Tag != "" {
		nodeName = fmt.Sprintf("[%s] %s", server.Name, event.Tag)
	} else {
		nodeName = fmt.Sprintf("[%s] %s:%d", server.Name, event.Protocol, event.Port)
	}

	// 系统节点归属的 username(真实 admin,不是字面值 "admin")
	sysOwner := l.repo.GetSystemNodeOwner(ctx)

	// 转换为 Clash 配置
	clashConfig, err := l.inboundToClash(event.ServerID, event.Inbound)
	if err != nil {
		log.Printf("[NodeSync] Failed to convert inbound to clash: %v", err)
		return fmt.Errorf("转换入站 %s 为节点失败: %w", event.Tag, err)
	}

	// 解析 clash 配置 — inboundToClash 已用 chooseClashServerHost 把 server 填成 v4 host
	// (Domain → PullAddress → IPv4)。
	var clashMap map[string]any
	if err := json.Unmarshal([]byte(clashConfig), &clashMap); err != nil {
		log.Printf("[NodeSync] Failed to parse clash config: %v", err)
		return fmt.Errorf("解析入站 %s 的节点配置失败: %w", event.Tag, err)
	}
	v4Host, _ := clashMap["server"].(string)
	v6Host := strings.TrimSpace(server.IPAddressV6)

	// 按 ip_version / 中转 决定要建哪些节点(name + clash server host + 可选 port 覆盖 + 中转原值)
	var plans []managedNodePlan
	if relayHost := strings.TrimSpace(event.RelayServer); relayHost != "" {
		// 中转:单节点,clash server/port=中转地址;原服务器=v4Host + 原 clash 端口记到 relay_orig_*。
		// 中转优先,忽略 ip_version(中转是单一地址,不分 v4/v6)。
		origPort := clashPortOf(clashMap)
		relayPort := event.RelayPort
		if relayPort <= 0 {
			relayPort = origPort // 端口默认填节点端口
		}
		plans = []managedNodePlan{{name: nodeName, host: relayHost, port: relayPort, relayOrigHost: v4Host, relayOrigPort: origPort}}
	} else {
		switch event.IPVersion {
		case "v6":
			// 勾 v6:强制用 IPv6 字面地址,忽略 Domain/PullAddress
			if v6Host == "" {
				log.Printf("[NodeSync] server %s 无 IPv6,ip_version=v6 跳过创建", server.Name)
				return fmt.Errorf("服务器 %s 未配置 IPv6，无法创建 IPv6 节点", server.Name)
			}
			plans = []managedNodePlan{{name: nodeName, host: v6Host}}
		case "both":
			plans = []managedNodePlan{{name: nodeName, host: v4Host}}
			if v6Host != "" {
				plans = append(plans, managedNodePlan{name: nodeName + "(v6)", host: v6Host})
			} else {
				log.Printf("[NodeSync] server %s 无 IPv6,both 退化为仅 v4", server.Name)
			}
		default: // "" / "v4" —— 现状行为
			plans = []managedNodePlan{{name: nodeName, host: v4Host}}
		}
	}

	// admin 已同步过的同 server 节点(按 server-host + protocol + port 去重)
	existingNodes, err := l.repo.ListNodes(ctx, sysOwner)
	if err != nil {
		return fmt.Errorf("读取现有节点失败: %w", err)
	}
	// 已占用的节点名集合 —— 撞名(不同物理节点碰巧同名)时用 UniqueNodeName 加后缀,保证订阅侧 proxy name 唯一
	takenNames := make(map[string]bool, len(existingNodes))
	for _, n := range existingNodes {
		takenNames[n.NodeName] = true
	}

	// Replacing an inbound reuses the same tag. Keep the stable node IDs (package
	// assignments and saved subscriptions may reference them), but replace every
	// connection field from the newly acknowledged inbound. Merely updating the
	// mutation token would leave an old UUID/Reality key behind and publish a node
	// that can no longer connect.
	if reconciled, reconcileErr := l.reconcileAddedManagedNodes(ctx, server, event, clashMap, plans, existingNodes); reconciled {
		return reconcileErr
	} else if reconcileErr != nil {
		return reconcileErr
	}

	// Only an inbound with no existing managed node may claim a legacy external
	// node. Otherwise a same-coordinate external row could short-circuit the
	// replacement above and leave the actual managed node stale.
	if matched, claimErr := l.tryClaimExternalNode(ctx, server, event, clashConfig); matched {
		return claimErr
	} else if claimErr != nil {
		return claimErr
	}

	var createErrors []error
	for _, p := range plans {
		// 真重复(同 server-host + protocol + port)才 skip —— 带上 host,避免「both」时 v4/v6 同 proto+port 互相误杀
		if nodeWithHostProtoPortExists(existingNodes, server.Name, p.host, event.Protocol, event.Port) {
			log.Printf("[NodeSync] Node with same host/protocol/port exists, skip: %s @ %s", p.name, p.host)
			continue
		}
		// 撞名但物理坐标不同(如同名的 VLESS / HY2)→ 加协议后缀,而不是丢弃
		name := storage.UniqueNodeName(p.name, event.Protocol, takenNames)

		cfg, err := cloneClashWithServerPort(clashMap, name, p.host, p.port)
		if err != nil {
			log.Printf("[NodeSync] Failed to build clash config for %s: %v", name, err)
			createErrors = append(createErrors, fmt.Errorf("构建节点 %s 配置失败: %w", name, err))
			continue
		}
		node := storage.Node{
			Username:          sysOwner,
			NodeName:          name,
			Protocol:          event.Protocol,
			ClashConfig:       cfg,
			ParsedConfig:      cfg,
			Enabled:           true,
			Tag:               fmt.Sprintf("远程:%s", server.Name),
			OriginalServer:    server.Name,
			InboundTag:        event.Tag,
			InboundMutationID: event.MutationID,
		}
		if p.relayOrigHost != "" {
			node.RelayOrigServer = p.relayOrigHost
			node.RelayOrigPort = p.relayOrigPort
		}
		created, err := l.repo.CreateNode(ctx, node)
		if err != nil {
			log.Printf("[NodeSync] Failed to create node %s: %v", name, err)
			createErrors = append(createErrors, fmt.Errorf("创建节点 %s 失败: %w", name, err))
			continue
		}
		takenNames[name] = true
		log.Printf("[NodeSync] Created node: %s", name)
		l.prependNodeOrder(ctx, sysOwner, created.ID)
	}
	return errors.Join(createErrors...)
}

func (l *NodeSyncListener) reconcileAddedManagedNodes(
	ctx context.Context,
	server *storage.RemoteServer,
	event InboundEvent,
	clashMap map[string]any,
	plans []managedNodePlan,
	existingNodes []storage.Node,
) (bool, error) {
	managed := make([]storage.Node, 0, len(plans))
	for _, node := range existingNodes {
		if node.OriginalServer != server.Name || node.InboundTag != event.Tag ||
			(node.NodeType != "" && node.NodeType != "physical") {
			continue
		}
		managed = append(managed, node)
	}
	if len(managed) == 0 {
		return false, nil
	}

	var reconcileErrors []error
	used := make([]bool, len(managed))
	takenNames := make(map[string]bool, len(existingNodes)+len(plans))
	for _, node := range existingNodes {
		takenNames[node.NodeName] = true
	}
	for _, plan := range plans {
		candidate := -1
		planV6 := strings.Contains(plan.host, ":")
		for index := range managed {
			if used[index] {
				continue
			}
			var current map[string]any
			_ = json.Unmarshal([]byte(managed[index].ClashConfig), &current)
			currentHost, _ := current["server"].(string)
			if currentHost == plan.host {
				candidate = index
				break
			}
			if candidate < 0 && strings.Contains(currentHost, ":") == planV6 {
				candidate = index
			}
		}
		if candidate < 0 {
			for index := range managed {
				if !used[index] {
					candidate = index
					break
				}
			}
		}
		if candidate < 0 {
			name := storage.UniqueNodeName(plan.name, event.Protocol, takenNames)
			config, err := cloneClashWithServerPort(clashMap, name, plan.host, plan.port)
			if err != nil {
				log.Printf("[NodeSync] Failed to build replacement node for %s: %v", event.Tag, err)
				reconcileErrors = append(reconcileErrors, fmt.Errorf("构建替换节点 %s 失败: %w", event.Tag, err))
				continue
			}
			created, err := l.repo.CreateNode(ctx, storage.Node{
				Username:          l.repo.GetSystemNodeOwner(ctx),
				NodeName:          name,
				Protocol:          event.Protocol,
				ClashConfig:       config,
				ParsedConfig:      config,
				Enabled:           true,
				Tag:               fmt.Sprintf("远程:%s", server.Name),
				OriginalServer:    server.Name,
				InboundTag:        event.Tag,
				InboundMutationID: event.MutationID,
				RelayOrigServer:   plan.relayOrigHost,
				RelayOrigPort:     plan.relayOrigPort,
			})
			if err != nil {
				log.Printf("[NodeSync] Failed to create replacement node for %s: %v", event.Tag, err)
				reconcileErrors = append(reconcileErrors, fmt.Errorf("创建替换节点 %s 失败: %w", event.Tag, err))
				continue
			}
			takenNames[name] = true
			l.prependNodeOrder(ctx, created.Username, created.ID)
			continue
		}
		used[candidate] = true
		node := managed[candidate]
		config, err := cloneClashWithServerPort(clashMap, node.NodeName, plan.host, plan.port)
		if err != nil {
			log.Printf("[NodeSync] Failed to rebuild managed node %d: %v", node.ID, err)
			reconcileErrors = append(reconcileErrors, fmt.Errorf("重建节点 %d 失败: %w", node.ID, err))
			continue
		}
		node.Protocol = event.Protocol
		node.ClashConfig = config
		node.ParsedConfig = config
		node.OriginalServer = server.Name
		node.InboundTag = event.Tag
		node.InboundMutationID = event.MutationID
		node.RelayOrigServer = plan.relayOrigHost
		node.RelayOrigPort = plan.relayOrigPort
		if _, err := l.repo.UpdateNode(ctx, node); err != nil {
			log.Printf("[NodeSync] Failed to replace managed node %d for %s: %v", node.ID, event.Tag, err)
			reconcileErrors = append(reconcileErrors, fmt.Errorf("更新节点 %d 失败: %w", node.ID, err))
		}
	}

	// Historical duplicates are left in place. They may own routed children or
	// package references, so deleting them requires a separate reference-aware
	// cleanup rather than guessing during an inbound replacement.
	return true, errors.Join(reconcileErrors...)
}

// cloneClashWithServer 浅拷贝 clash proxy map,覆盖顶层 name 与 server,返回 JSON。
// clash proxy 是扁平对象(server/name/port/type/uuid... 均顶层),浅拷贝足够 —— 只改顶层键,
// 不触碰 ws-opts/reality-opts 等嵌套结构,两节点共享嵌套引用也安全。
func cloneClashWithServer(clashMap map[string]any, name, serverHost string) (string, error) {
	return cloneClashWithServerPort(clashMap, name, serverHost, 0)
}

// cloneClashWithServerPort 同 cloneClashWithServer,额外在 port>0 时覆盖顶层 port(中转用)。
func cloneClashWithServerPort(clashMap map[string]any, name, serverHost string, port int) (string, error) {
	cp := make(map[string]any, len(clashMap))
	for k, v := range clashMap {
		cp[k] = v
	}
	cp["name"] = name
	cp["server"] = serverHost
	if port > 0 {
		cp["port"] = port
	}
	b, err := json.Marshal(cp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// clashPortOf 从 clash proxy map 读出顶层 port(float64/int 兼容),取不到返回 0。
func clashPortOf(m map[string]any) int {
	switch v := m["port"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// nodeWithHostProtoPortExists 判断 existing 中是否已有 同 server名 + 同 clash server host + 同协议 + 同端口 的节点。
func nodeWithHostProtoPortExists(existing []storage.Node, serverName, host, protocol string, port int) bool {
	for _, n := range existing {
		if n.OriginalServer != serverName {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
			continue
		}
		if h, _ := cfg["server"].(string); h != host {
			continue
		}
		if proto, _ := cfg["type"].(string); !protocolEquivalent(proto, protocol) {
			continue
		}
		var p int
		switch v := cfg["port"].(type) {
		case float64:
			p = int(v)
		case int:
			p = v
		}
		if p == port {
			return true
		}
	}
	return false
}

// prependNodeOrder 把新节点 ID 放到用户节点排序表最前面(去重)——
// 用户拖过顺序后直接 append 会把新节点甩到底部,不直观。
func (l *NodeSyncListener) prependNodeOrder(ctx context.Context, owner string, nodeID int64) {
	settings, err := l.repo.GetUserSettings(ctx, owner)
	if err != nil {
		return
	}
	filtered := make([]int64, 0, len(settings.NodeOrder)+1)
	filtered = append(filtered, nodeID)
	for _, id := range settings.NodeOrder {
		if id != nodeID {
			filtered = append(filtered, id)
		}
	}
	settings.NodeOrder = filtered
	if err := l.repo.UpsertUserSettings(ctx, settings); err != nil {
		log.Printf("[NodeSync] prepend new node to node_order failed: %v", err)
	}
}

// createForwardTunnelNode 为「转发已有节点」生成的 tunnel 创建配套节点:
// 配置克隆源节点,但 name 拼接 " | Tunnel"、server 改为 tunnel 服务器 IP、port 改为 tunnel 监听端口、
// inbound_tag = tunnel tag、original_server = tunnel 服务器名(便于管理/删除时定位)。
func (l *NodeSyncListener) createForwardTunnelNode(ctx context.Context, event InboundEvent, server *storage.RemoteServer) error {
	src, err := l.repo.GetNodeByID(ctx, event.ForwardNodeID)
	if err != nil {
		log.Printf("[NodeSync] forward-tunnel: 源节点 %d 不存在: %v", event.ForwardNodeID, err)
		return fmt.Errorf("读取转发源节点 %d 失败: %w", event.ForwardNodeID, err)
	}
	// 与 syncInboundsToNodes / InboundToClashProxyByServerID 同优先序:
	// Domain → 非私有 PullAddress → IPAddress;不能用 chooseClashServerHost(在 handler 包,跨包麻烦)就内联一遍
	serverHost := strings.TrimSpace(server.Domain)
	if serverHost == "" {
		if p := strings.TrimSpace(server.PullAddress); p != "" {
			if ip := net.ParseIP(p); ip == nil || (!ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) {
				serverHost = p
			}
		}
	}
	if serverHost == "" {
		serverHost = strings.TrimSpace(server.IPAddress)
	}
	if serverHost == "" {
		log.Printf("[NodeSync] forward-tunnel: 服务器 %s 无 IP/域名,跳过", server.Name)
		return fmt.Errorf("服务器 %s 没有可用 IP 或域名", server.Name)
	}

	sysOwner := l.repo.GetSystemNodeOwner(ctx)
	// 同一个远端入站的事件可能因重试重复送达；命中已有配套节点时原位更新，
	// 避免每次重试都创建一个带名称后缀的新节点。
	existingNodes, err := l.repo.ListNodes(ctx, sysOwner)
	if err != nil {
		log.Printf("[NodeSync] forward-tunnel: 读取现有节点失败，跳过幂等更新: %v", err)
		return fmt.Errorf("读取转发配套节点失败: %w", err)
	}
	var existingClone *storage.Node
	takenNames := make(map[string]bool, len(existingNodes))
	for i := range existingNodes {
		n := &existingNodes[i]
		takenNames[n.NodeName] = true
		if existingClone == nil && n.OriginalServer == server.Name && n.InboundTag == event.Tag &&
			(n.NodeType == "" || n.NodeType == "physical") {
			existingClone = n
		}
	}
	nodeName := ""
	if existingClone != nil {
		nodeName = existingClone.NodeName
	} else {
		requestedName := strings.TrimSpace(event.NodeName)
		if requestedName == "" {
			requestedName = src.NodeName + " | Tunnel"
		}
		// 撞名(如源节点已有同名 Tunnel 配套)→ 加协议后缀保证唯一,而不是丢弃。
		nodeName = storage.UniqueNodeName(requestedName, src.Protocol, takenNames)
	}

	// 克隆源节点 clash 配置,改 name/server/port(端口取 tunnel 监听端口)
	var clashMap map[string]any
	if err := json.Unmarshal([]byte(src.ClashConfig), &clashMap); err != nil {
		log.Printf("[NodeSync] forward-tunnel: 解析源节点 clash 配置失败: %v", err)
		return fmt.Errorf("解析转发源节点配置失败: %w", err)
	}
	clashMap["name"] = nodeName
	clashMap["server"] = serverHost
	clashMap["port"] = event.Port
	clashJSON, err := json.Marshal(clashMap)
	if err != nil {
		log.Printf("[NodeSync] forward-tunnel: 序列化 clash 配置失败: %v", err)
		return fmt.Errorf("生成转发配套节点配置失败: %w", err)
	}

	if existingClone != nil {
		// Update only fields owned by the forwarding event. Enabled, tags,
		// chain-proxy selection, relay metadata and other administrator-managed
		// state remain exactly as configured on the existing clone.
		node := *existingClone
		node.NodeName = nodeName
		node.Protocol = src.Protocol
		node.ClashConfig = string(clashJSON)
		node.ParsedConfig = string(clashJSON)
		node.OriginalServer = server.Name
		node.InboundTag = event.Tag
		node.InboundMutationID = event.MutationID
		if _, err := l.repo.UpdateNode(ctx, node); err != nil {
			log.Printf("[NodeSync] forward-tunnel: 更新配套节点失败: %v", err)
			return fmt.Errorf("更新转发配套节点失败: %w", err)
		} else {
			log.Printf("[NodeSync] forward-tunnel: 已更新配套节点: %s (-> %s:%d)", nodeName, serverHost, event.Port)
		}
		return nil
	}
	node := storage.Node{
		Username:          sysOwner,
		NodeName:          nodeName,
		Protocol:          src.Protocol,
		ClashConfig:       string(clashJSON),
		ParsedConfig:      string(clashJSON),
		Enabled:           true,
		Tag:               fmt.Sprintf("远程:%s", server.Name),
		OriginalServer:    server.Name,
		InboundTag:        event.Tag,
		InboundMutationID: event.MutationID,
	}
	if _, err := l.repo.CreateNode(ctx, node); err != nil {
		log.Printf("[NodeSync] forward-tunnel: 创建配套节点失败: %v", err)
		return fmt.Errorf("创建转发配套节点失败: %w", err)
	} else {
		log.Printf("[NodeSync] forward-tunnel: 已创建配套节点: %s (-> %s:%d)", nodeName, serverHost, event.Port)
	}
	return nil
}

func isTunnelProtocol(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tunnel", "dokodemo-door":
		return true
	default:
		return false
	}
}

// protocolEquivalent 判断 clash type 与 xray protocol 是否同一种协议。
// clash 用 `type: ss`,xray 用 `protocol: shadowsocks`,其他名字一致。
func protocolEquivalent(clashType, xrayProtocol string) bool {
	a := strings.ToLower(strings.TrimSpace(clashType))
	b := strings.ToLower(strings.TrimSpace(xrayProtocol))
	if a == b {
		return true
	}
	norm := func(s string) string {
		if s == "ss" {
			return "shadowsocks"
		}
		return s
	}
	return norm(a) == norm(b)
}

// tryClaimExternalNode 扫所有"外部节点"(original_server=” 且 inbound_tag=”),
// 看是否有节点的 clash_config 指向 (server 的 IP/Domain/PullAddress 之一) + 同 port + 同 protocol,
// 命中即把该节点 UPDATE 为受管节点(填上 original_server + inbound_tag),返回 true。
// 这避免迁移场景下:mmw 原有节点 + agent 扫描新创建节点 → 重复 2 条节点的问题。
func (l *NodeSyncListener) tryClaimExternalNode(ctx context.Context, server *storage.RemoteServer, event InboundEvent, agentClashConfig string) (bool, error) {
	// 候选地址:能让外部节点 server 字段命中该 remote_server 的所有可能形式
	candidates := map[string]bool{}
	for _, a := range []string{server.IPAddress, server.Domain, server.PullAddress} {
		if strings.TrimSpace(a) != "" {
			candidates[a] = true
		}
	}
	if len(candidates) == 0 {
		return false, nil
	}

	allNodes, err := l.repo.ListAllNodes(ctx)
	if err != nil {
		log.Printf("[NodeSync] tryClaimExternalNode: list all nodes failed: %v", err)
		return false, fmt.Errorf("读取可认领节点失败: %w", err)
	}
	for _, n := range allNodes {
		// Agent events must never claim an ordinary user's imported node, even
		// when its host/port/protocol happen to match this managed server. Missing
		// owner records also fail closed instead of inheriting legacy admin trust.
		owner, ownerErr := l.repo.GetUser(ctx, n.Username)
		if ownerErr != nil || owner.Role != storage.RoleAdmin {
			continue
		}
		// 只看"外部节点":没关联 server / inbound,且不是 routed 子节点
		if strings.TrimSpace(n.OriginalServer) != "" || strings.TrimSpace(n.InboundTag) != "" {
			continue
		}
		if n.NodeType == "routed" {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal([]byte(n.ClashConfig), &cfg); err != nil {
			continue
		}
		srv, _ := cfg["server"].(string)
		if !candidates[srv] {
			continue
		}
		var port int
		switch p := cfg["port"].(type) {
		case float64:
			port = int(p)
		case int:
			port = p
		}
		if port != event.Port {
			continue
		}
		proto, _ := cfg["type"].(string)
		if !protocolEquivalent(proto, event.Protocol) {
			continue
		}

		// 命中:更新该节点
		log.Printf("[NodeSync] Claim external node id=%d name=%q for %s/%s:%d", n.ID, n.NodeName, server.Name, event.Protocol, event.Port)
		// 用 agent 转出来的 clash_config 替换,但保留原节点名(用户可能改过中文名)
		var newCfg map[string]any
		if err := json.Unmarshal([]byte(agentClashConfig), &newCfg); err == nil {
			if name, _ := cfg["name"].(string); name != "" {
				newCfg["name"] = name
			}
			if updated, err := json.Marshal(newCfg); err == nil {
				agentClashConfig = string(updated)
			}
		}
		if err := l.repo.ClaimExternalNode(ctx, n.ID, server.Name, event.Tag, event.MutationID, fmt.Sprintf("远程:%s", server.Name), agentClashConfig); err != nil {
			log.Printf("[NodeSync] ClaimExternalNode failed: %v", err)
			return false, fmt.Errorf("认领外部节点 %d 失败: %w", n.ID, err)
		}
		return true, nil
	}
	return false, nil
}

func (l *NodeSyncListener) handleRemoved(ctx context.Context, event InboundEvent) error {
	server, err := l.repo.GetRemoteServer(ctx, event.ServerID)
	if err != nil {
		log.Printf("[NodeSync] Failed to get server %d: %v", event.ServerID, err)
		return fmt.Errorf("读取服务器 %d 失败: %w", event.ServerID, err)
	}

	// Delete only the generation that emitted this event. Legacy unfenced
	// events are accepted only after the Agent confirms the tag has no owner.
	var deleteErr error
	if strings.TrimSpace(event.MutationID) != "" {
		_, deleteErr = l.repo.DeleteNodesByInboundTagMutation(ctx, server.Name, event.Tag, event.MutationID)
	} else {
		_, deleteErr = l.repo.DeleteNodesByInboundTag(ctx, server.Name, event.Tag)
	}
	if deleteErr != nil {
		log.Printf("[NodeSync] Failed to delete nodes: %v", deleteErr)
	} else {
		log.Printf("[NodeSync] Deleted nodes for inbound: %s/%s", server.Name, event.Tag)
	}
	if strings.TrimSpace(event.MutationID) != "" {
		_, err = l.repo.DeleteManagedInboundResourceByServerTagMutation(ctx, event.ServerID, event.Tag, event.MutationID)
	} else {
		_, err = l.repo.DeleteManagedInboundResourceByServerTag(ctx, event.ServerID, event.Tag)
	}
	if err != nil {
		log.Printf("[NodeSync] Failed to delete managed inbound resource: %v", err)
	}
	var ownershipErr error
	if strings.TrimSpace(event.MutationID) != "" {
		if _, deleteOwnershipErr := l.repo.DeleteRemoteInboundOwnershipIfMutation(ctx, event.ServerID, event.Tag, event.MutationID); deleteOwnershipErr != nil {
			ownershipErr = deleteOwnershipErr
			log.Printf("[NodeSync] Failed to delete inbound ownership: %v", deleteOwnershipErr)
		}
	}
	return errors.Join(deleteErr, err, ownershipErr)
}

func (l *NodeSyncListener) handleUpdated(ctx context.Context, event InboundEvent) error {
	server, err := l.repo.GetRemoteServer(ctx, event.ServerID)
	if err != nil {
		log.Printf("[NodeSync] Failed to get server %d: %v", event.ServerID, err)
		return fmt.Errorf("读取服务器 %d 失败: %w", event.ServerID, err)
	}
	// Agent inventory only contains server-side WireGuard data. Rebuilding the
	// client proxy from it would discard the encrypted client identity.
	if strings.EqualFold(strings.TrimSpace(event.Protocol), "wireguard") {
		return nil
	}

	clashConfig, err := l.inboundToClash(event.ServerID, event.Inbound)
	if err != nil {
		log.Printf("[NodeSync] Failed to convert inbound to clash: %v", err)
		return fmt.Errorf("转换入站 %s 为节点失败: %w", event.Tag, err)
	}

	// v4/域名节点:用 base 配置(server = chooseClashServerHost)更新。
	// 订阅生成时 proxy 名取 node_name 列(subscription.go:988),clash_config 内的 name 仅内部用,无需特意保留。
	var updateErrors []error
	if updateErr := l.repo.UpdateNodeByInboundTag(ctx, server.Name, event.Tag, clashConfig, "v4"); updateErr != nil {
		log.Printf("[NodeSync] Failed to update v4 node: %v", updateErr)
		updateErrors = append(updateErrors, fmt.Errorf("更新 IPv4 节点失败: %w", updateErr))
	}

	// IPv6 节点:同一 inbound_tag 下若存在 v6 节点,用相同入站配置但 server 改回 v6 字面地址更新,
	// 避免被 base(v4)配置覆盖回 v4。server 无 v6 时无 v6 节点,跳过。
	if v6Host := strings.TrimSpace(server.IPAddressV6); v6Host != "" {
		var m map[string]any
		if json.Unmarshal([]byte(clashConfig), &m) == nil {
			name, _ := m["name"].(string)
			if v6cfg, cerr := cloneClashWithServer(m, name, v6Host); cerr == nil {
				if updateErr := l.repo.UpdateNodeByInboundTag(ctx, server.Name, event.Tag, v6cfg, "v6"); updateErr != nil {
					log.Printf("[NodeSync] Failed to update v6 node: %v", updateErr)
					updateErrors = append(updateErrors, fmt.Errorf("更新 IPv6 节点失败: %w", updateErr))
				}
			}
		}
	}
	log.Printf("[NodeSync] Updated node(s) for inbound: %s/%s", server.Name, event.Tag)
	return errors.Join(updateErrors...)
}
