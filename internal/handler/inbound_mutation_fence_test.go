package handler

import (
	"path/filepath"
	"testing"
)

func TestChildInboundMutationFenceRejectsLateAddAfterPersistedRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	first := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	first.inboundsMu.Lock()
	skip, err := first.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: "tunnel-race-h0", MutationID: "operation-old"})
	first.inboundsMu.Unlock()
	if err != nil || skip {
		t.Fatalf("begin remove skip=%v err=%v", skip, err)
	}

	// Simulate a new Agent process receiving the delayed add after the remove
	// already acknowledged. The sidecar tombstone must still reject it.
	second := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	second.inboundsMu.Lock()
	_, err = second.beginInboundMutationLocked("add", &ChildInboundRequest{
		MutationID: "operation-old",
		Inbound:    map[string]interface{}{"tag": "tunnel-race-h0"},
	})
	second.inboundsMu.Unlock()
	if err == nil {
		t.Fatal("late add unexpectedly passed the persisted remove fence")
	}

	second.inboundsMu.Lock()
	_, err = second.beginInboundMutationLocked("add", &ChildInboundRequest{
		MutationID: "operation-new",
		Inbound:    map[string]interface{}{"tag": "tunnel-race-h0"},
	})
	skip, removeErr := second.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: "tunnel-race-h0", MutationID: "operation-old"})
	second.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("new mutation was rejected: %v", err)
	}
	if removeErr != nil || !skip {
		t.Fatalf("old remove must not delete newer mutation: skip=%v err=%v", skip, removeErr)
	}
}
