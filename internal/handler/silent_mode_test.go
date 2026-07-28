package handler

import "testing"

func TestSilentModeAllowsOnlyExactAgentUninstallCallbackPath(t *testing.T) {
	manager := &SilentModeManager{}
	if !manager.isAllowedPath(AgentUninstallCompletePath) {
		t.Fatal("exact Agent uninstall callback path was blocked")
	}
	for _, path := range []string{
		AgentUninstallCompletePath + "/extra",
		AgentUninstallCompletePath + "-spoof",
		"/api/remote/agent/uninstall-complet",
	} {
		if manager.isAllowedPath(path) {
			t.Fatalf("similar callback path was unexpectedly allowed: %q", path)
		}
	}
}
