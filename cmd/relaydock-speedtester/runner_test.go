package main

import (
	"strings"
	"testing"
)

func TestLatencyOnlyResultRejectsFailedProbe(t *testing.T) {
	result, err := latencyOnlyResult(-1, "203.0.113.9")
	if err == nil || !strings.Contains(err.Error(), "Mihomo") {
		t.Fatalf("latencyOnlyResult error = %v", err)
	}
	if result.LatencyMs != -1 || result.EgressIP != "203.0.113.9" {
		t.Fatalf("latencyOnlyResult = %+v", result)
	}

	result, err = latencyOnlyResult(27, "203.0.113.9")
	if err != nil || result.LatencyMs != 27 {
		t.Fatalf("successful latencyOnlyResult = %+v, %v", result, err)
	}
}
