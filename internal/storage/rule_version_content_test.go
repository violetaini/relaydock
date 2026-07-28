package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRuleVersionContentMigrationListsAndUpdatesAtomically(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "rule-version-content.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()

	if _, err := repo.SaveRuleVersion(ctx, "first.yaml", "first-v1", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRuleVersion(ctx, "first.yaml", "first-v2", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRuleVersion(ctx, "second.yaml", "second-v1", "admin"); err != nil {
		t.Fatal(err)
	}

	versions, err := repo.ListAllRuleVersionContents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 3 {
		t.Fatalf("versions=%+v, want three rows", versions)
	}
	if versions[0].ID >= versions[1].ID || versions[1].ID >= versions[2].ID {
		t.Fatalf("versions are not in stable ID order: %+v", versions)
	}
	if versions[0].Filename != "first.yaml" || versions[0].Content != "first-v1" ||
		versions[2].Filename != "second.yaml" || versions[2].Content != "second-v1" {
		t.Fatalf("unexpected version contents: %+v", versions)
	}

	if err := repo.UpdateRuleVersionContents(ctx, map[int64]string{
		versions[0].ID: "first-v1-encrypted",
		versions[2].ID: "second-v1-encrypted",
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.ListAllRuleVersionContents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if updated[0].Content != "first-v1-encrypted" || updated[1].Content != "first-v2" || updated[2].Content != "second-v1-encrypted" {
		t.Fatalf("unexpected batch update result: %+v", updated)
	}

	if err := repo.UpdateRuleVersionContents(ctx, map[int64]string{
		versions[0].ID:        "must-roll-back",
		versions[2].ID + 1000: "missing-row",
	}); err == nil {
		t.Fatal("batch update with a missing row unexpectedly succeeded")
	}
	afterRollback, err := repo.ListAllRuleVersionContents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterRollback[0].Content != "first-v1-encrypted" {
		t.Fatalf("failed batch partially updated history: %+v", afterRollback)
	}
}
