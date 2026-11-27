package handler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

var safeFilenameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// AvatarHandler 处理用户头像上传、查看与删除。
type AvatarHandler struct {
	repo       *storage.TrafficRepository
	avatarsDir string
}

func NewAvatarHandler(repo *storage.TrafficRepository, avatarsDir string) *AvatarHandler {
	if repo == nil {
		panic("avatar handler requires repository")
	}
	if strings.TrimSpace(avatarsDir) == "" {
		avatarsDir = "avatars"
	}
	_ = os.MkdirAll(avatarsDir, 0755)
	return &AvatarHandler{
		repo:       repo,
		avatarsDir: avatarsDir,
	}
}

type avatarResponse struct {
	Success   bool            `json:"success"`
	AvatarURL string          `json:"avatar_url"`
	Profile   profileResponse `json:"profile,omitempty"`
}

func (h *AvatarHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodDelete:
		h.handleDelete(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// handleGet 公开提供头像静态文件服务
func (h *AvatarHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	rawFilename := strings.TrimPrefix(r.URL.Path, "/api/user/avatar")
	rawFilename = strings.TrimPrefix(rawFilename, "/")
	rawFilename = strings.TrimSpace(rawFilename)

	if rawFilename == "" || !safeFilenameRegex.MatchString(rawFilename) || strings.Contains(rawFilename, "..") {
		http.NotFound(w, r)
		return
	}

	cleanBase := filepath.Base(rawFilename)
	filePath := filepath.Join(h.avatarsDir, cleanBase)

	stat, err := os.Stat(filePath)
	if err != nil || stat.IsDir() {
		http.NotFound(w, r)
		return
	}

	ext := strings.ToLower(filepath.Ext(cleanBase))
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		switch ext {
		case ".webp":
			contentType = "image/webp"
		case ".png":
			contentType = "image/png"
		case ".jpg", ".jpeg":
			contentType = "image/jpeg"
		case ".gif":
			contentType = "image/gif"
		case ".svg":
			contentType = "image/svg+xml"
		default:
			contentType = "application/octet-stream"
		}
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400, stale-while-revalidate=604800")
	http.ServeFile(w, r, filePath)
}

// handlePost 处理头像图片上传
func (h *AvatarHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if strings.TrimSpace(username) == "" {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	// 限制最大 5MB
	const maxUploadSize = 5 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("解析上传图片失败: %w", err))
		return
	}

	file, header, err := r.FormFile("avatar")
	if err != nil {
		file, header, err = r.FormFile("file")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("请选择要上传的头像图片"))
		return
	}
	defer file.Close()

	// 读取前 512 字节检测类型
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, errors.New("读取图片数据失败"))
		return
	}
	sniffed := buf[:n]

	detected := http.DetectContentType(sniffed)
	origExt := strings.ToLower(filepath.Ext(header.Filename))

	var ext string
	switch {
	case strings.HasPrefix(detected, "image/jpeg"):
		ext = ".jpg"
	case strings.HasPrefix(detected, "image/png"):
		ext = ".png"
	case strings.HasPrefix(detected, "image/gif"):
		ext = ".gif"
	case strings.HasPrefix(detected, "image/webp") || origExt == ".webp":
		ext = ".webp"
	case strings.Contains(detected, "xml") && (origExt == ".svg" || strings.Contains(string(sniffed), "<svg")):
		ext = ".svg"
	default:
		writeError(w, http.StatusBadRequest, errors.New("仅支持 JPG、PNG、GIF、WEBP 或 SVG 格式的图片"))
		return
	}

	// 生成安全且唯一的文件名
	userHash := fmt.Sprintf("%x", sha256.Sum256([]byte(username)))[:10]
	uniqueFilename := fmt.Sprintf("%s_%d%s", userHash, time.Now().UnixNano()/1e6, ext)
	targetPath := filepath.Join(h.avatarsDir, uniqueFilename)

	dst, err := os.Create(targetPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("保存头像失败: %w", err))
		return
	}
	defer dst.Close()

	if _, err := dst.Write(sniffed); err != nil {
		_ = os.Remove(targetPath)
		writeError(w, http.StatusInternalServerError, fmt.Errorf("写入头像失败: %w", err))
		return
	}

	if _, err := io.Copy(dst, file); err != nil {
		_ = os.Remove(targetPath)
		writeError(w, http.StatusInternalServerError, fmt.Errorf("写入头像失败: %w", err))
		return
	}

	// 清理该用户旧的上传头像
	h.cleanUserOldAvatars(userHash, uniqueFilename)

	avatarURL := "/api/user/avatar/" + uniqueFilename

	// 更新用户 profile
	currentUser, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	update := storage.UserProfileUpdate{
		Email:     currentUser.Email,
		Nickname:  currentUser.Nickname,
		AvatarURL: avatarURL,
	}
	if err := h.repo.UpdateUserProfile(r.Context(), username, update); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	updatedUser, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := avatarResponse{
		Success:   true,
		AvatarURL: avatarURL,
		Profile: profileResponse{
			Username: updatedUser.Username,
			Email:    updatedUser.Email,
			Nickname: updatedUser.Nickname,
			Avatar:   updatedUser.AvatarURL,
			Role:     updatedUser.Role,
			IsAdmin:  updatedUser.Role == storage.RoleAdmin,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleDelete 清除自定义头像
func (h *AvatarHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	username := auth.UsernameFromContext(r.Context())
	if strings.TrimSpace(username) == "" {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}

	currentUser, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	update := storage.UserProfileUpdate{
		Email:     currentUser.Email,
		Nickname:  currentUser.Nickname,
		AvatarURL: "",
	}
	if err := h.repo.UpdateUserProfile(r.Context(), username, update); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	userHash := fmt.Sprintf("%x", sha256.Sum256([]byte(username)))[:10]
	h.cleanUserOldAvatars(userHash, "")

	updatedUser, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := avatarResponse{
		Success:   true,
		AvatarURL: "",
		Profile: profileResponse{
			Username: updatedUser.Username,
			Email:    updatedUser.Email,
			Nickname: updatedUser.Nickname,
			Avatar:   updatedUser.AvatarURL,
			Role:     updatedUser.Role,
			IsAdmin:  updatedUser.Role == storage.RoleAdmin,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *AvatarHandler) cleanUserOldAvatars(userHash, keepFilename string) {
	entries, err := os.ReadDir(h.avatarsDir)
	if err != nil {
		return
	}
	prefix := userHash + "_"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, prefix) && name != keepFilename {
			_ = os.Remove(filepath.Join(h.avatarsDir, name))
		}
	}
}
