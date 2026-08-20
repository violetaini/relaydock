package handler

import "github.com/violetaini/relaydock/internal/storage"

// resolveTrafficLimitBytes retains the old call shape while aggregate traffic
// is retired. Fixed nodes, managed servers, and forwarding grants each enforce
// their own resource quota.
func resolveTrafficLimitBytes(user *storage.User, pkg *storage.Package) int64 {
	_, _ = user, pkg
	return 0
}

// trafficLimitExceeded centralizes the boundary rule used by list views and enforcement.
// Zero and negative limits mean unlimited; reaching a positive cap is over limit.
func trafficLimitExceeded(usedBytes, limitBytes int64) bool {
	return limitBytes > 0 && usedBytes >= limitBytes
}
