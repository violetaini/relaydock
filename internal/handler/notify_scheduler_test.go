package handler

import (
	"context"
	"testing"
)

type notifyContextKey struct{}

func TestDetachedNotifyContextSurvivesRequestCancellation(t *testing.T) {
	requestContext, cancel := context.WithCancel(context.WithValue(context.Background(), notifyContextKey{}, "trace"))
	cancel()

	detached := detachedNotifyContext(requestContext)
	if detached.Err() != nil {
		t.Fatalf("detached context inherited cancellation: %v", detached.Err())
	}
	if detached.Done() != nil {
		t.Fatal("detached context exposes a cancellation channel")
	}
	if got := detached.Value(notifyContextKey{}); got != "trace" {
		t.Fatalf("context value=%v, want trace", got)
	}
}
