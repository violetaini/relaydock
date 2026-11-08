package xui

import (
	"time"
)

// XUIModel represents parsed data from 3x-ui (SQLite db or JSON export).
type XUIModel struct {
	Inbounds       []XUIInbound       `json:"inbounds"`
	ClientTraffics []XUIClientTraffic `json:"client_traffics"`
	Settings       map[string]string  `json:"settings,omitempty"`
	Source         string             `json:"source"`
}

// XUIInbound represents a single inbound in 3x-ui.
type XUIInbound struct {
	ID                int64              `json:"id"`
	UserID            int64              `json:"user_id"`
	Up                int64              `json:"up"`
	Down              int64              `json:"down"`
	Total             int64              `json:"total"`
	Remark            string             `json:"remark"`
	Enable            bool               `json:"enable"`
	ExpiryTime        int64              `json:"expiry_time"`
	Listen            string             `json:"listen"`
	Port              int                `json:"port"`
	Protocol          string             `json:"protocol"`
	Tag               string             `json:"tag"`
	RawSettings       string             `json:"settings"`
	RawStreamSettings string             `json:"stream_settings"`
	RawSniffing       string             `json:"sniffing,omitempty"`
	Clients           []XUIClient        `json:"clients,omitempty"`
	Stream            *XUIStreamSettings `json:"stream,omitempty"`
}

// XUIClient represents a client configured in a 3x-ui inbound.
type XUIClient struct {
	ID         string `json:"id"`
	Password   string `json:"password,omitempty"`
	Email      string `json:"email"`
	Flow       string `json:"flow,omitempty"`
	TotalGB    int64  `json:"totalGB,omitempty"`
	ExpiryTime int64  `json:"expiryTime,omitempty"`
	Enable     bool   `json:"enable"`
	SubID      string `json:"subId,omitempty"`
	Reset      int    `json:"reset,omitempty"`
	LimitIP    int    `json:"limitIp,omitempty"`
	Method     string `json:"method,omitempty"`
}

// XUIStreamSettings represents transport and security options in 3x-ui.
type XUIStreamSettings struct {
	Network         string              `json:"network"`
	Security        string              `json:"security"`
	RealitySettings *XUIRealitySettings `json:"realitySettings,omitempty"`
	TLSSettings     *XUITLSSettings     `json:"tlsSettings,omitempty"`
	TCPSettings     *XUITCPSettings     `json:"tcpSettings,omitempty"`
	WSSettings      *XUIWSSettings      `json:"wsSettings,omitempty"`
	GRPCSettings    *XUIGRPCSettings    `json:"grpcSettings,omitempty"`
}

// XUIRealitySettings contains Xray Reality parameters.
type XUIRealitySettings struct {
	Show        bool     `json:"show"`
	Xver        int      `json:"xver"`
	Dest        string   `json:"dest"`
	ServerNames []string `json:"serverNames"`
	ServerName  string   `json:"serverName,omitempty"`
	PrivateKey  string   `json:"privateKey"`
	PublicKey   string   `json:"publicKey,omitempty"`
	ShortIds    []string `json:"shortIds"`
	ShortId     string   `json:"shortId,omitempty"`
	SpiderX     string   `json:"spiderX,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

// XUITLSSettings contains TLS configuration.
type XUITLSSettings struct {
	ServerName   string           `json:"serverName"`
	Certificates []XUICertificate `json:"certificates,omitempty"`
	ALPN         []string         `json:"alpn,omitempty"`
}

type XUICertificate struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile          string `json:"keyFile"`
}

type XUITCPSettings struct {
	Header map[string]interface{} `json:"header,omitempty"`
}

type XUIWSSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

type XUIGRPCSettings struct {
	ServiceName string `json:"serviceName"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}

// XUIClientTraffic mirrors 3x-ui's client_traffics table.
type XUIClientTraffic struct {
	ID         int64  `json:"id"`
	InboundID  int64  `json:"inbound_id"`
	Enable     bool   `json:"enable"`
	Email      string `json:"email"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	ExpiryTime int64  `json:"expiry_time"`
	Total      int64  `json:"total"`
	Reset      int    `json:"reset"`
}

// ServerInfo provides lightweight server metadata for conflict detection and mapping without cyclic dependencies.
type ServerInfo struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
}

// ExistingNodeInfo describes an active node for port collision checks.
type ExistingNodeInfo struct {
	NodeName string `json:"node_name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

// XUIInspectReport provides pre-flight dry-run evaluation.
type XUIInspectReport struct {
	TotalInbounds   int                 `json:"total_inbounds"`
	TotalClients    int                 `json:"total_clients"`
	TotalTrafficUp  int64               `json:"total_traffic_up"`
	TotalTrafficDown int64              `json:"total_traffic_down"`
	Protocols       map[string]int      `json:"protocols"`
	InboundDetails  []XUIInboundDetail  `json:"inbound_details"`
	Warnings        []string            `json:"warnings"`
	HasConflicts    bool                `json:"has_conflicts"`
}

type XUIInboundDetail struct {
	ID                 int64    `json:"id"`
	Port               int      `json:"port"`
	Protocol           string   `json:"protocol"`
	Remark             string   `json:"remark"`
	Tag                string   `json:"tag"`
	Network            string   `json:"network"`
	Security           string   `json:"security"`
	SNI                string   `json:"sni"`
	ClientsCount       int      `json:"clients_count"`
	ClientEmails       []string `json:"client_emails"`
	Compatible         bool     `json:"compatible"`
	Warning            string   `json:"warning,omitempty"`
	PortConflict       bool     `json:"port_conflict"`
	ExistingConflict   string   `json:"existing_conflict,omitempty"`
	MatchingServerID   int64    `json:"matching_server_id,omitempty"`
	MatchingServerName string   `json:"matching_server_name,omitempty"`
}

// XUIImportRequest specifies parameters for the non-destructive import.
type XUIImportRequest struct {
	MigrationID             string          `json:"migration_id,omitempty"`
	RawJSON                 string          `json:"raw_json,omitempty"`
	TargetUsername          string          `json:"target_username"`
	DefaultServerID         int64           `json:"default_server_id"`
	ServerMappings          map[int64]int64 `json:"server_mappings"` // inboundID -> remoteServerID
	InboundIDs              []int64         `json:"inbound_ids"`     // If non-empty, only import specified inbounds
	ImportHistoricalTraffic bool            `json:"import_historical_traffic"`
	CreateManagedResources  bool            `json:"create_managed_resources"`
}

// XUIImportResult reports the outcome of the import.
type XUIImportResult struct {
	Success                bool     `json:"success"`
	ImportedNodes          int      `json:"imported_nodes"`
	ImportedClients        int      `json:"imported_clients"`
	ImportedTrafficRecords int      `json:"imported_traffic_records"`
	CreatedManagedInbounds int      `json:"created_managed_inbounds"`
	Warnings               []string `json:"warnings,omitempty"`
	Errors                 []string `json:"errors,omitempty"`
	ExecutionTime          string   `json:"execution_time"`
}

// ConvertedNodeCandidate is an in-memory intermediate structure before database write.
type ConvertedNodeCandidate struct {
	InboundID    int64
	ServerID     int64
	ServerName   string
	ServerHost   string
	NodeName     string
	NodeType     string
	Tag          string
	Port         int
	Link         string
	ProxyConfig  map[string]interface{}
	ConfigJSON   string
	Clients      []XUIClient
	InboundMap   map[string]interface{}
}

// RemoteXUIDetection contains status returned by remote agent.
type RemoteXUIDetection struct {
	Installed       bool      `json:"installed"`
	Running         bool      `json:"running"`
	DBPath          string    `json:"db_path,omitempty"`
	BinaryPath      string    `json:"binary_path,omitempty"`
	ServiceUnit     string    `json:"service_unit,omitempty"`
	InboundCount    int       `json:"inbound_count"`
	ClientCount     int       `json:"client_count"`
	ActivePorts     []int     `json:"active_ports"`
	DetectedAt      time.Time `json:"detected_at"`
	IsCoexisting    bool      `json:"is_coexisting"` // True when running alongside RelayDock agent
	Message         string    `json:"message"`
}
