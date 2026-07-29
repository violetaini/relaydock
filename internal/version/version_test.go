package version

import "testing"

func TestIsAgentUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      bool
	}{
		{name: "current", userAgent: RelayDockAgentUserAgent, want: true},
		{name: "legacy", userAgent: AgentUserAgent, want: true},
		{name: "unknown", userAgent: "other-agent/0.1", want: false},
		{name: "empty", userAgent: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAgentUserAgent(tt.userAgent); got != tt.want {
				t.Fatalf("IsAgentUserAgent(%q) = %v, want %v", tt.userAgent, got, tt.want)
			}
		})
	}
}
