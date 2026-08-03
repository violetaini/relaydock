package version

// 版本是当前应用程序版本
const Version = "0.6.10"

// APIContract is the compatibility level shared by the control-plane HTTP API
// and externally deployed frontend bundles. It changes only when a frontend
// cannot safely run against the immediately preceding API contract.
const APIContract = 1

const AgentUserAgent = "relaydock-agent/0.1"

// IsAgentUserAgent validates the RelayDock Agent control-plane identifier.
func IsAgentUserAgent(value string) bool {
	return value == AgentUserAgent
}
