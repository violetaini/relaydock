package handler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconcileInboundFirewallUsesInjectedAgentSynchronizer(t *testing.T) {
	want := errors.New("synthetic firewall failure")
	calls := 0
	handler := &ChildManageHandler{
		inboundFirewallSync: func(ctx context.Context) error {
			calls++
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("firewall synchronization has no deadline")
			}
			return want
		},
	}
	if err := handler.reconcileInboundFirewall(); !errors.Is(err, want) {
		t.Fatalf("error=%v want=%v", err, want)
	}
	if calls != 1 {
		t.Fatalf("calls=%d want=1", calls)
	}
}

func TestReconcileInboundFirewallIsNoopWithoutOwnedHelper(t *testing.T) {
	handler := &ChildManageHandler{}
	if err := handler.reconcileInboundFirewall(); err != nil {
		t.Fatal(err)
	}
}

func TestSyncArcwayInboundFirewallRejectsOutdatedHelper(t *testing.T) {
	directory := t.TempDir()
	helperPath := filepath.Join(directory, "firewall")
	if err := os.WriteFile(helperPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	err := syncArcwayInboundFirewallPaths(context.Background(), helperPath, filepath.Join(directory, "missing.env"))
	if err == nil || !strings.Contains(err.Error(), "outdated") {
		t.Fatalf("error=%v want outdated helper rejection", err)
	}
}

func TestSyncArcwayInboundFirewallExecutesCurrentHelper(t *testing.T) {
	directory := t.TempDir()
	helperPath := filepath.Join(directory, "firewall")
	helper := "#!/bin/sh\n# PUBLIC_RULES_RAW= -arcway-firewall-rules=\nexit 0\n"
	if err := os.WriteFile(helperPath, []byte(helper), 0755); err != nil {
		t.Fatal(err)
	}
	if err := syncArcwayInboundFirewallPaths(context.Background(), helperPath, filepath.Join(directory, "missing.env")); err != nil {
		t.Fatal(err)
	}
}
