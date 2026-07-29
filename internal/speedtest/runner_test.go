package speedtest

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

func TestSplitThreadByteBudgetPreservesTotalCap(t *testing.T) {
	const budget = int64(64*1024 + 3)
	var total int64
	for index := 0; index < 4; index++ {
		limit, active := splitThreadByteBudget(budget, 4, index)
		if !active {
			t.Fatalf("worker %d unexpectedly inactive", index)
		}
		total += limit
	}
	if total != budget {
		t.Fatalf("worker budgets sum to %d bytes, want %d", total, budget)
	}
}

func TestSplitThreadByteBudgetDoesNotTurnEmptyShareIntoUnlimited(t *testing.T) {
	for index := 0; index < 4; index++ {
		limit, active := splitThreadByteBudget(2, 4, index)
		if index < 2 && (!active || limit != 1) {
			t.Fatalf("worker %d = (%d, %v), want (1, true)", index, limit, active)
		}
		if index >= 2 && (active || limit != 0) {
			t.Fatalf("worker %d = (%d, %v), want (0, false)", index, limit, active)
		}
	}
}
