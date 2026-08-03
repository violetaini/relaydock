package componentupdate

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestRunOnceRunsEveryTaskAfterFailure(t *testing.T) {
	var failed, succeeded atomic.Int32
	scheduler := Scheduler{Tasks: []Task{
		{Name: "failure", Run: func(context.Context) error {
			failed.Add(1)
			return errors.New("expected")
		}},
		{Name: "success", Run: func(context.Context) error {
			succeeded.Add(1)
			return nil
		}},
	}}
	scheduler.RunOnce(context.Background())
	if failed.Load() != 1 || succeeded.Load() != 1 {
		t.Fatalf("runs = failure:%d success:%d", failed.Load(), succeeded.Load())
	}
}

func TestRunOnceSkipsNilTask(t *testing.T) {
	called := false
	Scheduler{Tasks: []Task{{}, {Run: func(context.Context) error { called = true; return nil }}}}.RunOnce(context.Background())
	if !called {
		t.Fatal("non-nil task was not run")
	}
}
