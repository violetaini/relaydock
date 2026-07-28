package event

import (
	"errors"
	"strings"
	"testing"
)

type failingInboundListener struct {
	err error
}

func (listener failingInboundListener) Handle(InboundEvent) error {
	return listener.err
}

func TestBusPublishReturnsListenerErrors(t *testing.T) {
	bus := &Bus{listeners: make(map[EventType][]Listener)}
	bus.Subscribe(EventInboundAdded, failingInboundListener{err: errors.New("node sync failed")})
	if err := bus.Publish(InboundEvent{Type: EventInboundAdded}); err == nil || !strings.Contains(err.Error(), "node sync failed") {
		t.Fatalf("publish error=%v", err)
	}
}
