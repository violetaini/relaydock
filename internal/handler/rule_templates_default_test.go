package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func defaultTemplateTestHandler(t *testing.T) *RuleTemplatesHandler {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "templates.db"))
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	cfg, err := repo.GetSystemConfig(context.Background())
	if err != nil {
		t.Fatalf("get system config: %v", err)
	}
	cfg.DefaultTemplateFilename = "default.yaml"
	if err := repo.UpdateSystemConfig(context.Background(), cfg); err != nil {
		t.Fatalf("set default template: %v", err)
	}
	return NewRuleTemplatesHandler(repo)
}

func TestDefaultRuleTemplateCannotBeDeleted(t *testing.T) {
	h := defaultTemplateTestHandler(t)
	recorder := httptest.NewRecorder()
	h.handleDeleteTemplate(recorder, httptest.NewRequest(http.MethodDelete, "/api/admin/rule-templates/default.yaml", nil), "default.yaml")
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
}

func TestDefaultRuleTemplateCannotBeRenamed(t *testing.T) {
	h := defaultTemplateTestHandler(t)
	recorder := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"old_name":"default.yaml","new_name":"renamed.yaml"}`)
	h.handleRenameTemplate(recorder, httptest.NewRequest(http.MethodPost, "/api/admin/rule-templates/rename", body))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
}
