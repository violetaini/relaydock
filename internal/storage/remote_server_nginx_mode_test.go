package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRemoteServerNginxModeRoundTrip(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()

	managed := &RemoteServer{Name: "managed-edge", Token: "managed-token"}
	if err := repo.CreateRemoteServer(ctx, managed); err != nil {
		t.Fatal(err)
	}
	storedManaged, err := repo.GetRemoteServer(ctx, managed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedManaged.NginxMode != "managed" {
		t.Fatalf("default nginx mode = %q, want managed", storedManaged.NginxMode)
	}

	reuse := &RemoteServer{Name: "reuse-edge", Token: "reuse-token", NginxMode: "reuse_existing"}
	if err := repo.CreateRemoteServer(ctx, reuse); err != nil {
		t.Fatal(err)
	}
	storedReuse, err := repo.GetRemoteServer(ctx, reuse.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedReuse.NginxMode != "reuse_existing" {
		t.Fatalf("stored nginx mode = %q, want reuse_existing", storedReuse.NginxMode)
	}

	if err := repo.UpdateRemoteServerNginxMode(ctx, reuse.ID, "managed"); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.GetRemoteServer(ctx, reuse.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.NginxMode != "managed" {
		t.Fatalf("updated nginx mode = %q, want managed", updated.NginxMode)
	}
	if err := repo.UpdateRemoteServerNginxMode(ctx, reuse.ID, "external"); err == nil {
		t.Fatal("invalid nginx mode was accepted")
	}
}
