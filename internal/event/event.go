package event

// EventType 事件类型
type EventType string

const (
	EventInboundAdded   EventType = "inbound.added"
	EventInboundRemoved EventType = "inbound.removed"
	EventInboundUpdated EventType = "inbound.updated"
)

// InboundEvent 入站事件数据
type InboundEvent struct {
	Type       EventType
	ServerID   int64          // 服务器 ID
	Tag        string         // 入站 Tag
	MutationID string         // 创建该 Tag 当前这一代入站的 fencing token
	Protocol   string         // 协议类型
	Port       int            // 端口
	Inbound    map[string]any // 完整入站配置 (添加/更新时)
	NodeName   string         // 自定义节点显示名称（可选）
	// ForwardNodeID > 0 表示这是「转发已有节点」创建的 tunnel：
	// 监听器会据此克隆源节点配置生成一个配套节点（server 改为 tunnel 服务器 IP/端口），而非跳过 tunnel
	ForwardNodeID int64
	// IPVersion 控制生成节点的 clash server 取哪个地址：
	//   "" / "v4" → 现状（chooseClashServerHost：Domain→PullAddress→IPv4）
	//   "v6"      → 强制用 server.IPAddressV6 字面地址（忽略 Domain）
	//   "both"    → 同时生成 v4 节点 + v6 节点（v6 节点名加 "(v6)" 后缀）
	IPVersion string
	// 中转(relay)：非空时生成的节点 clash server/port 用中转地址，原服务器地址/端口记到节点
	// relay_orig_*（供列表展示 + 取消中转还原）。设了中转则忽略 IPVersion（中转是单一地址）。
	RelayServer string
	RelayPort   int
}

// Listener 事件监听器接口
type Listener interface {
	Handle(event InboundEvent) error
}
