package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestAvatarHandler_UploadServeAndDelete(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	avatarsDir := filepath.Join(tempDir, "avatars")

	repo, err := storage.NewTrafficRepository(dbPath)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()

	// 创建测试用户 (username, email, nickname, passwordHash, role, remark)
	err = repo.CreateUser(context.Background(), "alice", "alice@example.com", "Alice", "hashed_pwd", storage.RoleUser, "")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	h := NewAvatarHandler(repo, avatarsDir)

	// 1. 上传一个假的 PNG 图片
	// PNG signature: 89 50 4E 47 0D 0A 1A 0A
	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "custom_avatar.png")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	if _, err := part.Write(pngData); err != nil {
		t.Fatalf("failed to write png data: %v", err)
	}
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/user/avatar", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req = req.WithContext(auth.ContextWithUsername(req.Context(), "alice"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp avatarResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !resp.Success || resp.AvatarURL == "" {
		t.Fatalf("upload response invalid: %+v", resp)
	}

	if resp.Profile.Avatar != resp.AvatarURL {
		t.Fatalf("profile avatar (%s) != response avatar (%s)", resp.Profile.Avatar, resp.AvatarURL)
	}

	// 2. GET 访问该头像
	getReq := httptest.NewRequest(http.MethodGet, resp.AvatarURL, nil)
	getW := httptest.NewRecorder()
	h.ServeHTTP(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("expected status 200 for GET %s, got %d", resp.AvatarURL, getW.Code)
	}
	if !bytes.Equal(getW.Body.Bytes()[:8], pngData[:8]) {
		t.Fatalf("served data does not match uploaded PNG")
	}

	// 3. DELETE 清除头像
	delReq := httptest.NewRequest(http.MethodDelete, "/api/user/avatar", nil)
	delReq = delReq.WithContext(auth.ContextWithUsername(delReq.Context(), "alice"))
	delW := httptest.NewRecorder()
	h.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusOK {
		t.Fatalf("expected status 200 for DELETE, got %d: %s", delW.Code, delW.Body.String())
	}

	// 再次查询用户確認 avatar_url 已為空
	user, err := repo.GetUser(context.Background(), "alice")
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if user.AvatarURL != "" {
		t.Fatalf("expected empty avatar_url, got %s", user.AvatarURL)
	}

	// 再次 GET 原 URL 應該 404
	getReq2 := httptest.NewRequest(http.MethodGet, resp.AvatarURL, nil)
	getW2 := httptest.NewRecorder()
	h.ServeHTTP(getW2, getReq2)
	if getW2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", getW2.Code)
	}
}
