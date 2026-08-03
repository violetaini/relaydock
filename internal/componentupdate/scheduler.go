// Package componentupdate runs maintenance for external components that are
// explicitly pinned by the current backend release.
package componentupdate

import (
	"context"
	"log"
	"time"
)

// Task is one idempotent component reconciliation operation.
type Task struct {
	Name string
	Run  func(context.Context) error
}

// Scheduler runs every task immediately and then at Interval. A failed task is
// logged and retried on the next interval; it never prevents another component
// from reconciling.
type Scheduler struct {
	Interval time.Duration
	Tasks    []Task
	Logf     func(string, ...any)
}

func (s Scheduler) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Interval <= 0 {
		s.Interval = 6 * time.Hour
	}
	if s.Logf == nil {
		s.Logf = log.Printf
	}
	go func() {
		s.RunOnce(ctx)
		ticker := time.NewTicker(s.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.RunOnce(ctx)
			}
		}
	}()
}

// RunOnce is exported so the same exact reconciliation behavior can be tested
// and can be used by a future administrative maintenance command.
func (s Scheduler) RunOnce(parent context.Context) {
	if parent == nil {
		parent = context.Background()
	}
	logf := s.Logf
	if logf == nil {
		logf = log.Printf
	}
	for _, task := range s.Tasks {
		if task.Run == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
		err := task.Run(ctx)
		cancel()
		if err != nil {
			logf("[Component Update] %s: %v", task.Name, err)
		}
	}
}
