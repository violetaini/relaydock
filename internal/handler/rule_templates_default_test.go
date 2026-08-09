package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func templateAdminRequest(req *http.Request) *http.Request {
	return req.WithContext(auth.ContextWithGlobalAPIToken(req.Context()))
}

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

func TestRuleTemplateAtomicUpdateKeepsOriginalBytesWhenTargetExists(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("rule_templates", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("rule_templates/original.yaml", []byte("old: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("rule_templates/existing.yaml", []byte("existing: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	h := defaultTemplateTestHandler(t)
	recorder := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"content":"new: true\n","new_name":"existing.yaml"}`)
	h.handleUpdateTemplate(recorder, templateAdminRequest(httptest.NewRequest(http.MethodPut, "/api/admin/rule-templates/original.yaml", body)), "original.yaml")
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	content, err := os.ReadFile("rule_templates/original.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old: true\n" {
		t.Fatalf("original content changed after rejected rename: %q", content)
	}
}

func TestRuleTemplateAtomicUpdateMovesOwnerAndContentTogether(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("rule_templates", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("rule_templates/original.yaml", []byte("old: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	h := defaultTemplateTestHandler(t)
	if err := h.repo.SetRuleTemplateOwner(context.Background(), "original.yaml", "alice"); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"content":"new: true\n","new_name":"renamed.yaml"}`)
	h.handleUpdateTemplate(recorder, templateAdminRequest(httptest.NewRequest(http.MethodPut, "/api/admin/rule-templates/original.yaml", body)), "original.yaml")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if _, err := os.Stat("rule_templates/original.yaml"); !os.IsNotExist(err) {
		t.Fatalf("original template still exists: %v", err)
	}
	content, err := os.ReadFile("rule_templates/renamed.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new: true\n" {
		t.Fatalf("renamed content = %q", content)
	}
	owner, err := h.repo.GetRuleTemplateOwner(context.Background(), "renamed.yaml")
	if err != nil || owner != "alice" {
		t.Fatalf("renamed owner = %q, err=%v", owner, err)
	}
}

func TestLegacyRuleTemplateRenameMovesOwnerAndContentTogether(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("rule_templates", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("rule_templates/original.yaml", []byte("old: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	h := defaultTemplateTestHandler(t)
	if err := h.repo.SetRuleTemplateOwner(context.Background(), "original.yaml", "alice"); err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"old_name":"original.yaml","new_name":"renamed.yaml"}`)
	recorder := httptest.NewRecorder()
	h.handleRenameTemplate(recorder, templateAdminRequest(httptest.NewRequest(http.MethodPost, "/api/admin/rule-templates/rename", body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := os.Stat("rule_templates/original.yaml"); !os.IsNotExist(err) {
		t.Fatalf("original template still exists after rename: %v", err)
	}
	content, err := os.ReadFile("rule_templates/renamed.yaml")
	if err != nil || string(content) != "old: true\n" {
		t.Fatalf("renamed content=%q err=%v", content, err)
	}
	owner, err := h.repo.GetRuleTemplateOwner(context.Background(), "renamed.yaml")
	if err != nil || owner != "alice" {
		t.Fatalf("renamed owner=%q err=%v", owner, err)
	}
	oldOwner, err := h.repo.GetRuleTemplateOwner(context.Background(), "original.yaml")
	if err != nil || oldOwner != "" {
		t.Fatalf("original owner remained after rename: owner=%q err=%v", oldOwner, err)
	}
}
