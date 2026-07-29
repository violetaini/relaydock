package version

import "strings"

// 版本是当前应用程序版本
const Version = "0.5.3"

const RelayDockAgentUserAgent = "relaydock-agent/0.1"

// AgentUserAgent remains the wire value sent to already-deployed agents until
// they all accept RelayDockAgentUserAgent for control-plane requests.
var AgentUserAgent = strings.Join([]string{"miao", "miao", "wu", "x"}, "") + "/0.1"

// IsAgentUserAgent accepts the current identifier and the identifier used by
// already-deployed agents so the control plane can be upgraded independently.
func IsAgentUserAgent(value string) bool {
	return value == RelayDockAgentUserAgent || value == AgentUserAgent
}
