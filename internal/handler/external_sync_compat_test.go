package handler

import (
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestRefreshExternalNodeNameReplacesGeneratedSuffix(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		suffix   string
		want     string
	}{
		{name: "replace", existing: "Tokyo 10.00GB📊 8Days⏳", suffix: " 8.50GB📊 7Days⏳", want: "Tokyo 8.50GB📊 7Days⏳"},
		{name: "remove", existing: "Tokyo 10.00GB📊 8Days⏳", want: "Tokyo"},
		{name: "clean accumulated legacy suffixes", existing: "Tokyo 10.00GB📊 8Days⏳ 8.50GB📊 7Days⏳", suffix: " 7.00GB📊 6Days⏳", want: "Tokyo 7.00GB📊 6Days⏳"},
		{name: "preserve ordinary name", existing: "Tokyo Premium", suffix: " 900MB📊", want: "Tokyo Premium 900MB📊"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refreshExternalNodeName(tt.existing, tt.suffix); got != tt.want {
				t.Fatalf("refreshExternalNodeName(%q, %q) = %q, want %q", tt.existing, tt.suffix, got, tt.want)
			}
		})
	}
}

func TestPreserveExternalNodeNameDoesNotStripIdenticalUpstreamName(t *testing.T) {
	const upstreamName = "Quota 10GB📊"
	if got := preserveExternalNodeName(upstreamName, upstreamName, ""); got != upstreamName {
		t.Fatalf("identical upstream name changed to %q", got)
	}
	if got := preserveExternalNodeName("Tokyo 10GB📊", "Tokyo", ""); got != "Tokyo" {
		t.Fatalf("stale generated suffix was not removed: %q", got)
	}
}

func TestMatchExternalNodeByNameUsesSourceAndIgnoresStaleSuffix(t *testing.T) {
	nodes := []storage.Node{
		{ID: 1, RawURL: "https://first.example/sub", NodeName: "Tokyo 10.00GB📊 8Days⏳"},
		{ID: 2, RawURL: "https://second.example/sub", NodeName: "Tokyo 8.50GB📊 7Days⏳"},
	}
	matched := matchExternalNodeByName(nodes, "https://first.example/sub", "Tokyo 8.50GB📊 7Days⏳")
	if matched == nil || matched.ID != 1 {
		t.Fatalf("matched = %#v, want first subscription node", matched)
	}
	if matched := matchExternalNodeByName(nodes, "https://missing.example/sub", "Tokyo 8.50GB📊 7Days⏳"); matched != nil {
		t.Fatalf("cross-subscription node matched: %#v", matched)
	}
}
