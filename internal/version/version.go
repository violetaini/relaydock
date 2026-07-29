package version

// 版本是当前应用程序版本
const Version = "0.5.4"

const AgentUserAgent = "relaydock-agent/0.1"

// IsAgentUserAgent validates the RelayDock Agent control-plane identifier.
func IsAgentUserAgent(value string) bool {
	return value == AgentUserAgent
}
