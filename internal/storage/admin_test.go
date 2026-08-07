package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestFindActiveAdminUsernameSkipsDisabledAdministrator(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "arcway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	if err := repo.CreateUser(ctx, "disabled", "", "", "hash", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateUserStatus(ctx, "disabled", false); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "active", "", "", "hash", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}

	got, err := repo.FindActiveAdminUsername(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != "active" {
		t.Fatalf("active admin = %q, want active", got)
	}
}
