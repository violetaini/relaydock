package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestDeleteExternalSubscriptionDoesNotDeleteForeignProviderConfigs(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "external-subscription-owner.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()

	bobSourceID, err := repo.CreateExternalSubscription(ctx, ExternalSubscription{
		Username: "bob",
		Name:     "Bob source",
		URL:      "https://bob.example/subscription",
	})
	if err != nil {
		t.Fatalf("CreateExternalSubscription: %v", err)
	}
	bobProviderID, err := repo.CreateProxyProviderConfig(ctx, &ProxyProviderConfig{
		Username:               "bob",
		ExternalSubscriptionID: bobSourceID,
		Name:                   "Bob provider",
		Type:                   "http",
	})
	if err != nil {
		t.Fatalf("CreateProxyProviderConfig: %v", err)
	}

	if err := repo.DeleteExternalSubscription(ctx, bobSourceID, "alice"); !errors.Is(err, ErrExternalSubscriptionNotFound) {
		t.Fatalf("foreign delete error = %v, want ErrExternalSubscriptionNotFound", err)
	}
	if _, err := repo.GetExternalSubscription(ctx, bobSourceID, "bob"); err != nil {
		t.Fatalf("foreign delete removed subscription: %v", err)
	}
	provider, err := repo.GetProxyProviderConfig(ctx, bobProviderID)
	if err != nil {
		t.Fatalf("GetProxyProviderConfig: %v", err)
	}
	if provider == nil || provider.Username != "bob" || provider.ExternalSubscriptionID != bobSourceID {
		t.Fatalf("foreign delete changed provider: %#v", provider)
	}
}
