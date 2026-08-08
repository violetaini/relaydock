package main

import "testing"

func TestLongLivedRequestPaths(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "/api/admin/remote/xray/install-stream", want: true},
		{path: "/api/admin/remote/agent/upgrade-stream", want: true},
		{path: "/api/admin/update/apply-sse", want: true},
		{path: "/api/ws/dashboard", want: true},
		{path: "/api/public/probe-ws", want: true},
		{path: "/api/remote/ws", want: true},
		{path: "/api/speedtest/tester/ws", want: true},
		{path: "/api/admin/backup/download", want: false},
		{path: "/api/admin/backup/restore", want: false},
		{path: "/api/setup/restore-backup", want: false},
		{path: "/mcp", want: true},
		{path: "/api/login", want: false},
		{path: "/api/admin/remote-servers", want: false},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := isLongLivedRequestPath(test.path); got != test.want {
				t.Fatalf("isLongLivedRequestPath(%q)=%v, want %v", test.path, got, test.want)
			}
		})
	}
}
