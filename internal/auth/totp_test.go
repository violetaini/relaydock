package auth

import (
	"sync"
	"testing"
	"time"
)

func TestTwoFactorPendingTokenConsumedAfterMaximumFailures(t *testing.T) {
	store := NewTwoFactorPendingStore(time.Minute)
	token, err := store.Issue("alice", true)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt < maxTwoFactorAttempts; attempt++ {
		if !store.RecordFailure(token) {
			t.Fatalf("attempt %d consumed token early", attempt)
		}
		if username, remember, ok := store.Validate(token); !ok || username != "alice" || !remember {
			t.Fatalf("attempt %d validation = %q %v %v", attempt, username, remember, ok)
		}
	}
	if store.RecordFailure(token) {
		t.Fatal("maximum failure did not consume token")
	}
	if _, _, ok := store.Validate(token); ok {
		t.Fatal("consumed token remained valid")
	}
}

func TestTwoFactorPendingAcquireIsSingleUseUnderConcurrency(t *testing.T) {
	store := NewTwoFactorPendingStore(time.Minute)
	token, err := store.Issue("alice", false)
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, ok := store.Acquire(token); ok {
				acquired <- struct{}{}
			}
		}()
	}
	wg.Wait()
	if got := len(acquired); got != 1 {
		t.Fatalf("concurrent acquires = %d, want 1", got)
	}
	if !store.Finish(token, true) {
		t.Fatal("acquired token could not be consumed")
	}
	if _, _, ok := store.Acquire(token); ok {
		t.Fatal("consumed token was acquired again")
	}
}

func TestTwoFactorPendingRevokeUserRemovesAcquiredToken(t *testing.T) {
	store := NewTwoFactorPendingStore(time.Minute)
	token, err := store.Issue("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := store.Acquire(token); !ok {
		t.Fatal("could not acquire pending token")
	}
	store.RevokeUser("alice")
	if store.IsAcquired(token) {
		t.Fatal("revoked user's pending token remained acquired")
	}
}

func TestTwoFactorPendingIssueReplacesPriorChallengeForUser(t *testing.T) {
	store := NewTwoFactorPendingStore(time.Minute)
	first, err := store.Issue("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Issue("alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := store.Acquire(first); ok {
		t.Fatal("older pending token remained usable")
	}
	username, rememberMe, ok := store.Acquire(second)
	if !ok || username != "alice" || !rememberMe {
		t.Fatalf("replacement challenge = %q %v %v", username, rememberMe, ok)
	}
}
