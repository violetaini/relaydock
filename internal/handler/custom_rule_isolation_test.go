package handler

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestCustomRuleAllowedForSubscribeFileRequiresSelectionAndOwner(t *testing.T) {
	ctx := context.Background()
	rule := storage.CustomRule{ID: 7, CreatedBy: "alice", Enabled: true}

	allowed, err := customRuleAllowedForSubscribeFile(ctx, nil, storage.SubscribeFile{
		CreatedBy:             "alice",
		SelectedCustomRuleIDs: []int64{7},
	}, rule)
	if err != nil || !allowed {
		t.Fatalf("owner-selected rule allowed=%v err=%v", allowed, err)
	}

	for name, file := range map[string]storage.SubscribeFile{
		"not-selected": {CreatedBy: "alice"},
		"other-owner":  {CreatedBy: "bob", SelectedCustomRuleIDs: []int64{7}},
	} {
		t.Run(name, func(t *testing.T) {
			allowed, err := customRuleAllowedForSubscribeFile(ctx, nil, file, rule)
			if err != nil {
				t.Fatal(err)
			}
			if allowed {
				t.Fatal("cross-tenant or unselected rule was allowed")
			}
		})
	}
}

func TestCustomRuleAllowedForOwnerlessFileRequiresAdministratorRule(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "admin", "", "", "hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateUser(ctx, "alice", "", "", "hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	file := storage.SubscribeFile{SelectedCustomRuleIDs: []int64{7}}

	for creator, want := range map[string]bool{"admin": true, "alice": false, "": false} {
		allowed, err := customRuleAllowedForSubscribeFile(ctx, repo, file, storage.CustomRule{ID: 7, CreatedBy: creator})
		if err != nil {
			t.Fatal(err)
		}
		if allowed != want {
			t.Fatalf("creator %q allowed=%v want=%v", creator, allowed, want)
		}
	}
}

func TestFloatToStringPreservesNumericValue(t *testing.T) {
	for input, want := range map[float64]string{
		0:       "0",
		1.25:    "1.25",
		-3.5:    "-3.5",
		1000.01: "1000.01",
	} {
		if got := floatToString(input); got != want {
			t.Fatalf("floatToString(%v)=%q want=%q", input, got, want)
		}
	}
}
