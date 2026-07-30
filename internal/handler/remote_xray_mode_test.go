package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestEmbeddedXrayRejectsExternalInstallerAndRemover(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	if err := repo.UpdateRemoteServerXrayMode(context.Background(), server.ID, "embedded"); err != nil {
		t.Fatal(err)
	}
	h := NewRemoteManageHandler(repo, nil)

	tests := []struct {
		name string
		path string
		run  func(http.ResponseWriter, *http.Request)
	}{
		{name: "install stream", path: "/api/admin/remote/xray/install-stream", run: h.HandleXrayInstallStream},
		{name: "remove stream", path: "/api/admin/remote/xray/remove-stream", run: h.HandleXrayRemoveStream},
		{name: "install legacy", path: "/api/admin/remote/xray/install", run: h.HandleXrayInstall},
		{name: "remove legacy", path: "/api/admin/remote/xray/remove", run: h.HandleXrayRemove},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, tt.path+"?server_id="+strconv.FormatInt(server.ID, 10), nil)
			tt.run(recorder, request)
			if recorder.Code != http.StatusConflict {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "内嵌 Xray 随 Agent 更新") {
				t.Fatalf("response does not explain update boundary: %s", recorder.Body.String())
			}
		})
	}
}

func TestFederatedXrayRejectsCoreInstallerAndRemover(t *testing.T) {
	repo, server := newRemoteInstallationHandlerRepo(t, 23889)
	if err := repo.SetFederatedServer(context.Background(), server.ID, "https://owner.example.test", "share-token", "shared-"); err != nil {
		t.Fatal(err)
	}
	h := NewRemoteManageHandler(repo, nil)

	tests := []struct {
		name string
		path string
		run  func(http.ResponseWriter, *http.Request)
	}{
		{name: "install stream", path: "/api/admin/remote/xray/install-stream", run: h.HandleXrayInstallStream},
		{name: "remove stream", path: "/api/admin/remote/xray/remove-stream", run: h.HandleXrayRemoveStream},
		{name: "install legacy", path: "/api/admin/remote/xray/install", run: h.HandleXrayInstall},
		{name: "remove legacy", path: "/api/admin/remote/xray/remove", run: h.HandleXrayRemove},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, tt.path+"?server_id="+strconv.FormatInt(server.ID, 10), nil)
			tt.run(recorder, request)
			if recorder.Code != http.StatusConflict {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "共享服务器的 Xray 核心") {
				t.Fatalf("response does not explain ownership boundary: %s", recorder.Body.String())
			}
		})
	}
}
