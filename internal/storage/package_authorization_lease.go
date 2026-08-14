package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

type packageAuthorizationLeaseContextKey struct{}

type packageAuthorizationLeaseContext struct {
	repo       *TrafficRepository
	packageIDs map[int64]struct{}
}

func normalizePackageAuthorizationLeaseIDs(packageIDs []int64) ([]int64, error) {
	unique := make(map[int64]struct{}, len(packageIDs))
	for _, packageID := range packageIDs {
		if packageID <= 0 {
			return nil, ErrManagedInvalidArgument
		}
		unique[packageID] = struct{}{}
	}
	if len(unique) == 0 {
		return nil, ErrManagedInvalidArgument
	}
	normalized := make([]int64, 0, len(unique))
	for packageID := range unique {
		normalized = append(normalized, packageID)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i] < normalized[j] })
	return normalized, nil
}

// AcquirePackageAuthorizationLease serializes template snapshots and commits
// with assignment transitions and their final Agent mutations. Package leases
// are always acquired before user authorization leases; multiple package IDs
// are sorted so A -> B and B -> A transitions cannot deadlock.
func (r *TrafficRepository) AcquirePackageAuthorizationLease(ctx context.Context, packageIDs ...int64) (context.Context, func(), error) {
	if r == nil || r.db == nil {
		return ctx, func() {}, errors.New("traffic repository not initialized")
	}
	normalized, err := normalizePackageAuthorizationLeaseIDs(packageIDs)
	if err != nil {
		return ctx, func() {}, err
	}
	if held, _ := ctx.Value(packageAuthorizationLeaseContextKey{}).(*packageAuthorizationLeaseContext); held != nil {
		if held.repo != r {
			return ctx, func() {}, ErrManagedInvalidArgument
		}
		for _, packageID := range normalized {
			if _, ok := held.packageIDs[packageID]; !ok {
				return ctx, func() {}, fmt.Errorf("%w: nested package authorization lease must not expand its package set", ErrManagedInvalidArgument)
			}
		}
		return ctx, func() {}, nil
	}
	if heldUsers, _ := ctx.Value(userAuthorizationLeaseContextKey{}).(*userAuthorizationLeaseContext); heldUsers != nil {
		return ctx, func() {}, fmt.Errorf("%w: package authorization lease must be acquired before user authorization lease", ErrManagedInvalidArgument)
	}

	locks := make([]*sync.Mutex, 0, len(normalized))
	for _, packageID := range normalized {
		value, _ := r.packageAuthorizationLeases.LoadOrStore(packageID, &sync.Mutex{})
		lock := value.(*sync.Mutex)
		lock.Lock()
		locks = append(locks, lock)
	}
	heldPackageIDs := make(map[int64]struct{}, len(normalized))
	for _, packageID := range normalized {
		heldPackageIDs[packageID] = struct{}{}
	}
	leasedCtx := context.WithValue(ctx, packageAuthorizationLeaseContextKey{}, &packageAuthorizationLeaseContext{
		repo: r, packageIDs: heldPackageIDs,
	})
	return leasedCtx, func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Unlock()
		}
	}, nil
}
