package handler

import "testing"

func TestValidateAgentClientMutation(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantDeferred bool
		wantError    bool
	}{
		{name: "applied", body: `{"success":true,"message":"client added"}`},
		{name: "runtime deferred", body: `{"success":true,"runtime_warning":"runtime apply failed"}`, wantDeferred: true},
		{name: "legacy no-op", body: `{"success":true,"message":"client already present (no-op)"}`},
		{name: "explicit unchanged", body: `{"success":true,"changed":false}`},
		{name: "explicit changed", body: `{"success":true,"changed":true}`},
		{name: "negative ACK", body: `{"success":false}`, wantError: true},
		{name: "invalid ACK", body: `not-json`, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deferred, err := validateAgentClientMutation([]byte(test.body))
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %v", err, test.wantError)
			}
			if deferred != test.wantDeferred {
				t.Fatalf("deferred = %v, want %v", deferred, test.wantDeferred)
			}
		})
	}
}

func TestInspectAgentConfigMutationACKDoesNotTreatNoOpAsRestartSignal(t *testing.T) {
	for _, test := range []struct {
		name         string
		body         string
		wantDeferred bool
	}{
		{name: "no op", body: `{"success":true,"message":"already present (no-op)"}`},
		{name: "unchanged", body: `{"success":true,"changed":false}`},
		{name: "runtime warning", body: `{"success":true,"runtime_warning":"runtime deferred"}`, wantDeferred: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			deferred, err := inspectAgentConfigMutationACK([]byte(test.body))
			if err != nil {
				t.Fatal(err)
			}
			if deferred != test.wantDeferred {
				t.Fatalf("deferred = %v, want %v", deferred, test.wantDeferred)
			}
		})
	}
}

func TestValidateAgentBatchItemResult(t *testing.T) {
	tests := []struct {
		result    string
		wantNoOp  bool
		wantError bool
	}{
		{result: "ok"},
		{result: "ok (no-op)", wantNoOp: true},
		{result: "err: inbound missing", wantError: true},
		{result: "applied", wantError: true},
		{result: "", wantError: true},
	}
	for _, test := range tests {
		noOp, err := validateAgentBatchItemResult(test.result)
		if noOp != test.wantNoOp || (err != nil) != test.wantError {
			t.Fatalf("result %q: noOp=%v err=%v", test.result, noOp, err)
		}
	}
}
