package handler

import (
	"math"
	"strings"
	"sync"
	"time"
)

// ProbeSysWire is the compact system-metrics payload sent by a RelayDock Agent
// inside its regular traffic report.  It is intentionally separate from
// RemoteSystemTraffic: the latter is accounting data, while these values are
// only used for the public probe's live display.
//
// The Has* flags make a zero value unambiguous.  Agents omit disabled probes
// by sending the corresponding flag as false, so the public API never has to
// guess whether a zero means "idle" or "not collected".
type ProbeSysWire struct {
	CPUPct    float64 `json:"cpu_pct"`
	LoadAvg   string  `json:"loadavg,omitempty"`
	MemUsed   int64   `json:"mem_used"`
	MemTotal  int64   `json:"mem_total"`
	DiskUsed  int64   `json:"disk_used"`
	DiskTotal int64   `json:"disk_total"`
	HasCPU    bool    `json:"has_cpu"`
	HasMem    bool    `json:"has_mem"`
	HasDisk   bool    `json:"has_disk"`
}

// ProbeSysSnapshot is a validated, local-only copy of the most recent Agent
// report.  It is deliberately not persisted: live status should disappear
// after a control-plane restart instead of accidentally presenting old values
// as current data.
type ProbeSysSnapshot struct {
	CPUPct    float64
	LoadAvg   string
	MemUsed   int64
	MemTotal  int64
	DiskUsed  int64
	DiskTotal int64
	HasCPU    bool
	HasMem    bool
	HasDisk   bool
	At        time.Time
}

const probeMetricsMaxAge = 90 * time.Second

// ProbeMetricsStore holds one sanitized live system snapshot per managed
// server.  The key is never exposed by public handlers; it is only used to
// associate an authenticated Agent report with the administrator-selected
// server record.
type ProbeMetricsStore struct {
	mu   sync.RWMutex
	data map[int64]ProbeSysSnapshot
}

func NewProbeMetricsStore() *ProbeMetricsStore {
	return &ProbeMetricsStore{data: make(map[int64]ProbeSysSnapshot)}
}

// IngestSys validates a report before making it visible.  Invalid individual
// metric groups are discarded rather than poisoning the whole snapshot.  The
// return value is false when the report contained no usable metric at all.
func (s *ProbeMetricsStore) IngestSys(serverID int64, wire ProbeSysWire) bool {
	if s == nil || serverID <= 0 {
		return false
	}

	snapshot := ProbeSysSnapshot{At: time.Now()}
	if wire.HasCPU && !math.IsNaN(wire.CPUPct) && !math.IsInf(wire.CPUPct, 0) && wire.CPUPct >= 0 && wire.CPUPct <= 100 {
		snapshot.HasCPU = true
		snapshot.CPUPct = wire.CPUPct
		// Load average is presentation-only. Keep it bounded and free of
		// controls because it ultimately reaches an unauthenticated response.
		loadAvg := strings.TrimSpace(wire.LoadAvg)
		if len(loadAvg) <= 96 && !strings.ContainsAny(loadAvg, "\r\n\x00") {
			snapshot.LoadAvg = loadAvg
		}
	}
	if wire.HasMem && wire.MemTotal > 0 && wire.MemUsed >= 0 && wire.MemUsed <= wire.MemTotal {
		snapshot.HasMem = true
		snapshot.MemUsed = wire.MemUsed
		snapshot.MemTotal = wire.MemTotal
	}
	if wire.HasDisk && wire.DiskTotal > 0 && wire.DiskUsed >= 0 && wire.DiskUsed <= wire.DiskTotal {
		snapshot.HasDisk = true
		snapshot.DiskUsed = wire.DiskUsed
		snapshot.DiskTotal = wire.DiskTotal
	}
	if !snapshot.HasCPU && !snapshot.HasMem && !snapshot.HasDisk {
		return false
	}

	s.mu.Lock()
	s.data[serverID] = snapshot
	s.mu.Unlock()
	return true
}

// Snapshot returns a copy only while it is recent enough to describe a live
// Agent.  A paused/old Agent must not leave stale CPU or disk data on the
// public page indefinitely.
func (s *ProbeMetricsStore) Snapshot(serverID int64) (ProbeSysSnapshot, bool) {
	if s == nil || serverID <= 0 {
		return ProbeSysSnapshot{}, false
	}
	s.mu.RLock()
	snapshot, ok := s.data[serverID]
	s.mu.RUnlock()
	if !ok || snapshot.At.IsZero() || time.Since(snapshot.At) > probeMetricsMaxAge {
		return ProbeSysSnapshot{}, false
	}
	return snapshot, true
}

// PruneExpired releases snapshots for disconnected or deleted servers after
// their visibility window. It is called by the public payload builder, so a
// removed server cannot accumulate process-local probe data until restart.
func (s *ProbeMetricsStore) PruneExpired(now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	for serverID, snapshot := range s.data {
		if snapshot.At.IsZero() || now.Sub(snapshot.At) > probeMetricsMaxAge {
			delete(s.data, serverID)
		}
	}
	s.mu.Unlock()
}

func (s *ProbeMetricsStore) Delete(serverID int64) {
	if s == nil || serverID <= 0 {
		return
	}
	s.mu.Lock()
	delete(s.data, serverID)
	s.mu.Unlock()
}
