package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestNodeTCPingToolOnlyAcceptsNodeIDAndTimeout(t *testing.T) {
	s := server.NewMCPServer("test", "0.0.0")
	registerNodeTools(s, &bridge{mux: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	})})

	tool := s.GetTool("node_tcping")
	if tool == nil {
		t.Fatal("node_tcping tool is not registered")
	}
	if !strings.Contains(tool.Tool.Description, "Mihomo") || !strings.Contains(tool.Tool.Description, "真实协议链路") {
		t.Fatalf("unexpected description: %q", tool.Tool.Description)
	}
	wantProperties := map[string]bool{"node_id": true, "timeout": true}
	if len(tool.Tool.InputSchema.Properties) != len(wantProperties) {
		t.Fatalf("unexpected properties: %#v", tool.Tool.InputSchema.Properties)
	}
	for name := range tool.Tool.InputSchema.Properties {
		if !wantProperties[name] {
			t.Fatalf("unexpected property %q", name)
		}
	}
	if !reflect.DeepEqual(tool.Tool.InputSchema.Required, []string{"node_id"}) {
		t.Fatalf("unexpected required properties: %#v", tool.Tool.InputSchema.Required)
	}
}

func TestNodeTCPingToolForwardsOnlyNodeIDAndTimeout(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode forwarded body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	s := server.NewMCPServer("test", "0.0.0")
	registerNodeTools(s, &bridge{mux: mux})
	tool := s.GetTool("node_tcping")
	if tool == nil {
		t.Fatal("node_tcping tool is not registered")
	}

	result, err := tool.Handler(context.Background(), mcpgo.CallToolRequest{Params: mcpgo.CallToolParams{
		Name: "node_tcping",
		Arguments: map[string]any{
			"node_id":  float64(42),
			"timeout":  float64(6000),
			"host":     "127.0.0.1",
			"port":     float64(22),
			"protocol": "tcp",
		},
	}})
	if err != nil {
		t.Fatalf("invoke node_tcping: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("unexpected tool result: %#v", result)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/admin/tcping" {
		t.Fatalf("unexpected forwarded request: %s %s", gotMethod, gotPath)
	}
	wantBody := map[string]any{"node_id": float64(42), "timeout": float64(6000)}
	if !reflect.DeepEqual(gotBody, wantBody) {
		t.Fatalf("unexpected forwarded body: got %#v, want %#v", gotBody, wantBody)
	}
}

func TestNodeTCPingToolRejectsMissingNodeID(t *testing.T) {
	called := false
	s := server.NewMCPServer("test", "0.0.0")
	registerNodeTools(s, &bridge{mux: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	})})
	tool := s.GetTool("node_tcping")

	result, err := tool.Handler(context.Background(), mcpgo.CallToolRequest{Params: mcpgo.CallToolParams{
		Name:      "node_tcping",
		Arguments: map[string]any{"timeout": float64(5000)},
	}})
	if err != nil {
		t.Fatalf("invoke node_tcping: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected tool error, got %#v", result)
	}
	if called {
		t.Fatal("request was forwarded without node_id")
	}
}
