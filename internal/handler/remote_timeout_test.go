package handler

import (
	"context"
	"testing"
	"time"
)

func TestRemoteOperationTimeout(t *testing.T) {
	if got := remoteOperationTimeout("/api/child/line-speedtest/run"); got != 5*time.Minute {
		t.Fatalf("line speedtest timeout = %v, want 5m", got)
	}
	if got := remoteOperationTimeout("/api/child/warp/install"); got != 75*time.Second {
		t.Fatalf("WARP timeout = %v, want 75s", got)
	}
	if got := remoteOperationTimeout("/api/child/services/status"); got != 30*time.Second {
		t.Fatalf("default timeout = %v, want 30s", got)
	}
	if got := NewRemoteManageHandler(nil, nil).httpClient.Timeout; got != 5*time.Minute {
		t.Fatalf("remote HTTP client timeout = %v, want 5m", got)
	}
}

func TestRemoteTransportTimeoutLeavesFallbackBudget(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	wsCtx, cancelWS := remoteTransportContext(parent, "/api/child/services/status")
	cancelWS()
	if wsCtx.Err() == nil {
		t.Fatal("cancelled WS transport context is still active")
	}
	if parent.Err() != nil {
		t.Fatalf("WS transport cancellation leaked to parent: %v", parent.Err())
	}

	fallbackCtx, cancelFallback := remoteTransportContext(parent, "/api/child/services/status")
	defer cancelFallback()
	if fallbackCtx.Err() != nil {
		t.Fatalf("HTTP fallback started with an expired context: %v", fallbackCtx.Err())
	}
}
