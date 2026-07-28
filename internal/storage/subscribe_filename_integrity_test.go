package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSubscribeFilenameRejectsPathsAndNonYAML(t *testing.T) {
	invalid := []string{
		"", ".", "..", "../escape.yaml", `..\escape.yaml`, "nested/file.yaml",
		`nested\file.yaml`, "/absolute.yaml", "config.json", "config.yaml/extra",
	}
	for _, filename := range invalid {
		if err := ValidateSubscribeFilename(filename); err == nil {
			t.Errorf("ValidateSubscribeFilename(%q) succeeded", filename)
		}
	}
	for _, filename := range []string{"config.yaml", "config.yml", "CONFIG.YAML"} {
		if err := ValidateSubscribeFilename(filename); err != nil {
			t.Errorf("ValidateSubscribeFilename(%q) = %v", filename, err)
		}
	}
}

func TestSubscribeFilenameUniqueIndexRejectsDuplicate(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "subscriptions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	ctx := context.Background()
	if _, err := repo.CreateSubscribeFile(ctx, SubscribeFile{
		Name: "first", Type: SubscribeTypeUpload, Filename: "shared.yaml",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateSubscribeFile(ctx, SubscribeFile{
		Name: "second", Type: SubscribeTypeUpload, Filename: "shared.yaml",
	}); !errors.Is(err, ErrSubscribeFileExists) {
		t.Fatalf("duplicate filename error = %v, want %v", err, ErrSubscribeFileExists)
	}
}

func TestSubscribeFilenameMigrationDiagnosesLegacyDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-duplicates.db")
	repo, err := NewTrafficRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`DROP INDEX idx_subscribe_files_filename_unique`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.Exec(`INSERT INTO subscribe_files (name, url, type, filename) VALUES
		('legacy-one', '', 'upload', 'duplicate.yaml'),
		('legacy-two', '', 'upload', 'duplicate.yaml')`); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = NewTrafficRepository(path)
	if err == nil {
		t.Fatal("migration accepted duplicate legacy filenames")
	}
	message := err.Error()
	if !strings.Contains(message, "duplicate subscribe filenames") || !strings.Contains(message, "duplicate.yaml") || !strings.Contains(message, "ids=") {
		t.Fatalf("migration error did not diagnose duplicate rows: %v", err)
	}
}

func TestSubscribeFilenameMigrationRejectsInvalidStoredRows(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, repo *TrafficRepository)
		want  string
	}{
		{
			name: "subscription",
			setup: func(t *testing.T, repo *TrafficRepository) {
				if _, err := repo.db.Exec(`INSERT INTO subscribe_files (name, url, type, filename) VALUES ('invalid', '', 'upload', '../escape.yaml')`); err != nil {
					t.Fatal(err)
				}
			},
			want: "invalid existing subscribe_files filenames",
		},
		{
			name: "rule history",
			setup: func(t *testing.T, repo *TrafficRepository) {
				if _, err := repo.db.Exec(`INSERT INTO rule_versions (filename, version, content, created_by) VALUES ('../escape.yaml', 1, 'proxies: []', 'admin')`); err != nil {
					t.Fatal(err)
				}
			},
			want: "invalid existing rule_versions filenames",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid-filename.db")
			repo, err := NewTrafficRepository(path)
			if err != nil {
				t.Fatal(err)
			}
			test.setup(t, repo)
			if err := repo.Close(); err != nil {
				t.Fatal(err)
			}
			_, err = NewTrafficRepository(path)
			if err == nil || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "../escape.yaml") {
				t.Fatalf("migration error=%v, want diagnostic containing %q", err, test.want)
			}
		})
	}
}

func TestStandaloneRuleHistoryAndSubscriptionOwnershipAreMutuallyExclusive(t *testing.T) {
	ctx := context.Background()
	t.Run("subscription wins", func(t *testing.T) {
		repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "subscription-wins.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer repo.Close()
		if _, err := repo.CreateSubscribeFile(ctx, SubscribeFile{Name: "owner", Type: SubscribeTypeUpload, Filename: "owned.yaml"}); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.SaveRuleVersionWithoutSubscribe(ctx, "owned.yaml", "proxies: []", "admin"); !errors.Is(err, ErrSubscribeFileChanged) {
			t.Fatalf("standalone save error=%v, want %v", err, ErrSubscribeFileChanged)
		}
		versions, err := repo.ListRuleVersions(ctx, "owned.yaml", 10)
		if err != nil || len(versions) != 0 {
			t.Fatalf("standalone history was inserted: %#v err=%v", versions, err)
		}
	})

	t.Run("standalone history wins", func(t *testing.T) {
		repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "history-wins.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer repo.Close()
		if _, err := repo.SaveRuleVersionWithoutSubscribe(ctx, "standalone.yaml", "proxies: []", "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateSubscribeFile(ctx, SubscribeFile{Name: "owner", Type: SubscribeTypeUpload, Filename: "standalone.yaml"}); !errors.Is(err, ErrSubscribeFilenameHistory) {
			t.Fatalf("subscription create error=%v, want %v", err, ErrSubscribeFilenameHistory)
		}
	})
}

func TestDeleteSubscribeFileUsesFilenameCompareAndSwap(t *testing.T) {
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "delete-cas.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	file, err := repo.CreateSubscribeFile(ctx, SubscribeFile{Name: "owner", Type: SubscribeTypeUpload, Filename: "current.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRuleVersionForSubscribe(ctx, file.ID, file.Filename, "proxies: []", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteSubscribeFile(ctx, file.ID, "stale.yaml"); !errors.Is(err, ErrSubscribeFileChanged) {
		t.Fatalf("stale delete error=%v, want %v", err, ErrSubscribeFileChanged)
	}
	if _, err := repo.GetSubscribeFileByID(ctx, file.ID); err != nil {
		t.Fatalf("stale delete removed subscription: %v", err)
	}
	versions, err := repo.ListRuleVersions(ctx, file.Filename, 10)
	if err != nil || len(versions) != 1 {
		t.Fatalf("stale delete removed history: %#v err=%v", versions, err)
	}
}
