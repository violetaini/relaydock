package bot

import (
	"sync"
	"time"
)

// 简单 per-tg_id 全局限流:固定窗口 60 秒,N 次。

const (
	rateWindowSeconds = 60
	rateMaxPerWindow  = 20
	rateLimitMaxKeys  = 10000
)

var (
	rlMu      sync.Mutex
	rlCounter = map[int64]*rlEntry{}
)

type rlEntry struct {
	count       int
	windowStart time.Time
}

func allowTGID(tgID int64) bool {
	rlMu.Lock()
	defer rlMu.Unlock()
	now := time.Now()
	e := rlCounter[tgID]
	window := time.Duration(rateWindowSeconds) * time.Second
	if e == nil {
		if !makeRateLimitRoom(rlCounter, now, window) {
			return false
		}
		rlCounter[tgID] = &rlEntry{count: 1, windowStart: now}
		return true
	}
	if now.Sub(e.windowStart) >= window {
		rlCounter[tgID] = &rlEntry{count: 1, windowStart: now}
		return true
	}
	e.count++
	return e.count <= rateMaxPerWindow
}

// makeRateLimitRoom bounds cardinality under hostile, ever-changing client
// identifiers. Expired windows are removed lazily only when the map is full;
// if every entry is still active, new identifiers are denied until space opens.
func makeRateLimitRoom[K comparable](entries map[K]*rlEntry, now time.Time, window time.Duration) bool {
	if len(entries) < rateLimitMaxKeys {
		return true
	}
	for key, entry := range entries {
		if entry == nil || now.Sub(entry.windowStart) >= window {
			delete(entries, key)
		}
	}
	return len(entries) < rateLimitMaxKeys
}
