package handler

import "github.com/violetaini/relaydock/internal/storage"

// resolveTrafficLimitBytes returns the effective package total traffic cap.
// A user override is authoritative whenever present, including an explicit zero.
func resolveTrafficLimitBytes(user *storage.User, pkg *storage.Package) int64 {
	if user != nil && user.TrafficLimitOverride != nil {
		return *user.TrafficLimitOverride
	}
	if pkg != nil {
		return pkg.TrafficLimitBytes
	}
	return 0
}

// trafficLimitExceeded centralizes the boundary rule used by list views and enforcement.
// Zero and negative limits mean unlimited; reaching a positive cap is over limit.
func trafficLimitExceeded(usedBytes, limitBytes int64) bool {
	return limitBytes > 0 && usedBytes >= limitBytes
}
