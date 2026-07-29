package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/validator"

	"gopkg.in/yaml.v3"
)

type subscribeFilesHandler struct {
	repo *storage.TrafficRepository
}

var errSubscribeFilenameTargetExists = errors.New("目标订阅文件已存在")

func writePrivateSubscriptionFile(path string, content []byte) error {
	unlock, err := lockSubscriptionFilenames(filepath.Base(path))
	if err != nil {
		return err
	}
	defer unlock()
	return writePrivateSubscriptionFileUnlocked(path, content)
}

func writePrivateSubscriptionFileUnlocked(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".arcway-subscription-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// writeNewPrivateSubscriptionFile creates a fully written private file without
// replacing an existing path. It is used during filename changes so a failed
// database transaction can discard the new copy while the old file remains.
func writeNewPrivateSubscriptionFile(path string, content []byte) (ownership os.FileInfo, err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(directory, ".arcway-subscription-rename-*")
	if err != nil {
		return nil, err
	}
	temporaryPath := file.Name()
	linked := false
	defer os.Remove(temporaryPath)
	defer func() {
		if file != nil {
			if closeErr := file.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
		// os.Link can fail because another writer already owns path. Only
		// remove the destination when this invocation actually linked it.
		if err != nil && linked {
			_ = removeSubscriptionFileIfOwned(path, ownership)
		}
	}()
	if err = file.Chmod(0600); err != nil {
		return nil, err
	}
	if _, err = file.Write(content); err != nil {
		return nil, err
	}
	if err = file.Sync(); err != nil {
		return nil, err
	}
	ownership, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	file = nil
	if err = os.Link(temporaryPath, path); err != nil {
		return nil, err
	}
	linked = true
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return ownership, nil
}

// 返回一个仅用于管理订阅文件的处理程序。
func NewSubscribeFilesHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("subscribe files handler requires repository")
	}

	return &subscribeFilesHandler{
		repo: repo,
	}
}

func (h *subscribeFilesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/subscribe-files")
	path = strings.Trim(path, "/")

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.handleList(w, r)
	case path == "" && r.Method == http.MethodPost:
		h.handleCreate(w, r)
	case path == "reorder" && r.Method == http.MethodPut:
		h.handleReorder(w, r)
	case path == "traffic" && r.Method == http.MethodGet:
		h.handleTraffic(w, r)
	case path == "import" && r.Method == http.MethodPost:
		h.handleImport(w, r)
	case path == "upload" && r.Method == http.MethodPost:
		h.handleUpload(w, r)
	case path == "create-from-config" && r.Method == http.MethodPost:
		h.handleCreateFromConfig(w, r)
	case strings.HasSuffix(path, "/users") && r.Method == http.MethodGet:
		// GET /api/admin/subscribe-files/{id}/users — 列出该订阅分配给哪些用户(同步自 mmw v0.7.3)
		idStr := strings.TrimSuffix(path, "/users")
		h.handleGetSubscriptionUsers(w, r, idStr)
	case strings.HasSuffix(path, "/content") && r.Method == http.MethodGet:
		// GET /api/admin/subscribe-files/{文件名}/内容
		filename := strings.TrimSuffix(path, "/content")
		h.handleGetContent(w, r, filename)
	case strings.HasSuffix(path, "/content") && r.Method == http.MethodPut:
		// PUT /api/admin/subscribe-files/{文件名}/内容
		filename := strings.TrimSuffix(path, "/content")
		h.handleUpdateContent(w, r, filename)
	case path != "" && path != "import" && path != "upload" && path != "create-from-config" && (r.Method == http.MethodPut || r.Method == http.MethodPatch):
		h.handleUpdate(w, r, path)
	case path != "" && path != "import" && path != "upload" && path != "create-from-config" && r.Method == http.MethodDelete:
		h.handleDelete(w, r, path)
	default:
		allowed := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
		methodNotAllowed(w, allowed...)
	}
}

func (h *subscribeFilesHandler) handleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	unlock, err := lockSubscriptionStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()
	files, err := h.repo.ListSubscribeFiles(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 数据隔离:
	//   - 普通用户:只看自己创建的
	//   - admin:看 created_by="" / created_by=自己 / created_by 是另一个 admin。
	//     普通用户通过"生成订阅"创建的私有订阅对 admin 不可见(避免泄露其他用户的私订阅)。
	//   注:这里只过滤"列表"。admin 仍可通过 GET/PUT/DELETE 路径直接拿订阅 ID 操作,后台清理 / 帮用户排错时需要。
	username := auth.UsernameFromContext(ctx)
	isAdmin := userIsAdmin(ctx, h.repo, username)
	if !isAdmin {
		filtered := make([]storage.SubscribeFile, 0, len(files))
		for _, f := range files {
			if f.CreatedBy == username {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	} else {
		files = filterAdminVisibleSubscribeFiles(ctx, h.repo, files, username)
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"files": h.convertSubscribeFilesWithVersions(ctx, files),
	})
}

func (h *subscribeFilesHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req subscribeFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.Name == "" {
		writeBadRequest(w, "订阅名称是必填项")
		return
	}
	if req.URL == "" {
		writeBadRequest(w, "链接地址是必填项")
		return
	}
	if req.Type == "" {
		writeBadRequest(w, "类型是必填项")
		return
	}
	if req.Filename == "" {
		writeBadRequest(w, "文件名是必填项")
		return
	}
	req.Filename = strings.TrimSpace(req.Filename)
	if err := storage.ValidateSubscribeFilename(req.Filename); err != nil {
		writeBadRequest(w, "文件名必须是 .yaml 或 .yml 结尾且不能包含路径")
		return
	}
	unlock, err := lockSubscriptionFilenames(req.Filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()
	if _, err := os.Lstat(filepath.Join("subscribes", req.Filename)); err == nil {
		writeError(w, http.StatusConflict, errSubscribeFilenameTargetExists)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	username := auth.UsernameFromContext(r.Context())

	// 配额校验:普通用户创建订阅受全局配额限制(admin 不限)。
	if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}

	file := storage.SubscribeFile{
		Name:                      req.Name,
		Description:               req.Description,
		URL:                       req.URL,
		Type:                      req.Type,
		Filename:                  req.Filename,
		TemplateFilename:          req.TemplateFilename,
		SelectedTags:              req.SelectedTags,
		SelectedNodeIDs:           req.SelectedNodeIDs,
		SelectedCustomRuleIDs:     req.SelectedCustomRuleIDs,
		SelectedOverrideScriptIDs: req.SelectedOverrideScriptIDs,
		StatsServerIDs:            req.StatsServerIDs,
		TrafficLimit:              req.TrafficLimit,
		CreatedBy:                 username,
	}
	if req.RawOutput != nil {
		file.RawOutput = *req.RawOutput
	}
	if req.SortOrder != nil {
		file.SortOrder = *req.SortOrder
	}
	if req.CustomShortCode != nil {
		file.CustomShortCode = *req.CustomShortCode
	}
	filePath := filepath.Join("subscribes", req.Filename)
	ownership, err := writeNewPrivateSubscriptionFile(filePath, []byte("proxies: []\n"))
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			writeError(w, http.StatusConflict, errSubscribeFilenameTargetExists)
			return
		}
		writeError(w, http.StatusInternalServerError, errors.New("保存订阅文件失败"))
		return
	}

	created, err := h.repo.CreateSubscribeFile(r.Context(), file)
	if err != nil {
		_ = removeSubscriptionFileIfOwned(filePath, ownership)
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) || errors.Is(err, storage.ErrSubscribeFilenameHistory) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 不要为基于 URL 的订阅自动应用自定义规则
	// 它们将在首次获取订阅时应用

	respondJSON(w, http.StatusCreated, map[string]any{
		"file": convertSubscribeFile(created),
	})
}

func (h *subscribeFilesHandler) handleImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Filename    string `json:"filename"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.URL == "" {
		writeBadRequest(w, "订阅URL是必填项")
		return
	}
	if req.Name == "" {
		writeBadRequest(w, "订阅名称是必填项")
		return
	}
	// Reject a caller-supplied path before making the upstream request. A
	// generated or Content-Disposition filename is validated again below.
	if strings.TrimSpace(req.Filename) != "" {
		filename := strings.TrimSpace(req.Filename)
		extension := strings.ToLower(filepath.Ext(filename))
		if extension != ".yaml" && extension != ".yml" {
			filename += ".yaml"
		}
		if err := storage.ValidateSubscribeFilename(filename); err != nil {
			writeBadRequest(w, "文件名必须是 .yaml 或 .yml 结尾且不能包含路径")
			return
		}
		req.Filename = filename
	}

	// 创建HTTP客户端并获取订阅内容
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("无效的订阅URL"))
		return
	}

	// 添加User-Agent头
	httpReq.Header.Set("User-Agent", "clash-meta/2.4.0")

	resp, err := client.Do(httpReq)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("无法获取订阅内容: "+err.Error()))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadRequest, errors.New("订阅服务器返回错误状态"))
		return
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("读取订阅内容失败"))
		return
	}

	// 验证YAML格式
	var yamlCheck map[string]any
	if err := yaml.Unmarshal(body, &yamlCheck); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("订阅内容不是有效的YAML格式"))
		return
	}
	// 从content-disposition获取文件名
	filename := req.Filename
	if filename == "" {
		contentDisposition := resp.Header.Get("Content-Disposition")
		if contentDisposition != "" {
			filename = parseFilenameFromContentDisposition(contentDisposition)
		}
		if filename == "" {
			filename = fmt.Sprintf("subscription_%d.yaml", time.Now().Unix())
		}
	}

	// 确保文件名有.yaml或.yml扩展名
	ext := filepath.Ext(filename)
	if ext != ".yaml" && ext != ".yml" {
		filename = filename + ".yaml"
	}
	filename = strings.TrimSpace(filename)
	if err := storage.ValidateSubscribeFilename(filename); err != nil {
		writeBadRequest(w, "文件名必须是 .yaml 或 .yml 结尾且不能包含路径")
		return
	}
	unlock, err := lockSubscriptionFilenames(filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()
	protectedContent, err := protectWireGuardSubscriptionContent(r.Context(), h.repo, filename, string(body), false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}

	filePath := filepath.Join("subscribes", filename)
	ownership, err := writeNewPrivateSubscriptionFile(filePath, []byte(protectedContent))
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			writeError(w, http.StatusConflict, errSubscribeFilenameTargetExists)
			return
		}
		writeError(w, http.StatusInternalServerError, errors.New("保存订阅文件失败"))
		return
	}

	username := auth.UsernameFromContext(r.Context())

	// 配额校验:普通用户创建订阅受全局配额限制(admin 不限)。
	if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
		_ = removeSubscriptionFileIfOwned(filePath, ownership)
		writeError(w, http.StatusForbidden, err)
		return
	}

	// 保存到数据库
	file := storage.SubscribeFile{
		Name:        req.Name,
		Description: req.Description,
		URL:         req.URL,
		Type:        storage.SubscribeTypeImport,
		Filename:    filename,
		CreatedBy:   username,
	}

	created, err := h.repo.CreateSubscribeFile(r.Context(), file)
	if err != nil {
		// 如果数据库保存失败，删除已保存的文件
		_ = removeSubscriptionFileIfOwned(filePath, ownership)
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) || errors.Is(err, storage.ErrSubscribeFilenameHistory) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 不要对导入的文件自动应用自定义规则
	// 如果需要，用户可以手动启用自动同步

	respondJSON(w, http.StatusCreated, map[string]any{
		"file": convertSubscribeFile(created),
	})
}

func (h *subscribeFilesHandler) handleUpload(w http.ResponseWriter, r *http.Request) {
	// 解析multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 详见上下文
		writeBadRequest(w, "解析表单失败")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeBadRequest(w, "文件上传失败")
		return
	}
	defer file.Close()

	name := r.FormValue("name")
	if name == "" {
		name = strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
	}

	description := r.FormValue("description")
	filename := r.FormValue("filename")
	if filename == "" {
		filename = header.Filename
	}

	// 确保文件名有.yaml或.yml扩展名
	ext := filepath.Ext(filename)
	if ext != ".yaml" && ext != ".yml" {
		filename = filename + ".yaml"
	}
	filename = strings.TrimSpace(filename)
	if err := storage.ValidateSubscribeFilename(filename); err != nil {
		writeBadRequest(w, "文件名必须是 .yaml 或 .yml 结尾且不能包含路径")
		return
	}

	// 读取并验证YAML格式
	content, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("读取文件失败"))
		return
	}

	var yamlCheck map[string]any
	if err := yaml.Unmarshal(content, &yamlCheck); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("文件不是有效的YAML格式"))
		return
	}
	unlock, err := lockSubscriptionFilenames(filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()
	protectedContent, err := protectWireGuardSubscriptionContent(r.Context(), h.repo, filename, string(content), false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}

	filePath := filepath.Join("subscribes", filename)
	ownership, err := writeNewPrivateSubscriptionFile(filePath, []byte(protectedContent))
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			writeError(w, http.StatusConflict, errSubscribeFilenameTargetExists)
			return
		}
		writeError(w, http.StatusInternalServerError, errors.New("保存订阅文件失败"))
		return
	}

	username := auth.UsernameFromContext(r.Context())

	// 配额校验:普通用户创建订阅受全局配额限制(admin 不限)。
	if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
		_ = removeSubscriptionFileIfOwned(filePath, ownership)
		writeError(w, http.StatusForbidden, err)
		return
	}

	// 保存到数据库
	subscribeFile := storage.SubscribeFile{
		Name:        name,
		Description: description,
		URL:         "", // 上传的文件没有URL
		Type:        storage.SubscribeTypeUpload,
		Filename:    filename,
		CreatedBy:   username,
	}

	created, err := h.repo.CreateSubscribeFile(r.Context(), subscribeFile)
	if err != nil {
		// 如果数据库保存失败，删除已保存的文件
		_ = removeSubscriptionFileIfOwned(filePath, ownership)
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) || errors.Is(err, storage.ErrSubscribeFilenameHistory) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 不要对上传的文件自动应用自定义规则
	// 如果需要，用户可以手动启用自动同步

	respondJSON(w, http.StatusCreated, map[string]any{
		"file": convertSubscribeFile(created),
	})
}

func (h *subscribeFilesHandler) handleUpdate(w http.ResponseWriter, r *http.Request, idSegment string) {
	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的订阅ID")
		return
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()

	existing, err := h.repo.GetSubscribeFileByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 所有权校验:普通用户只能改自己创建的订阅。
	uname := auth.UsernameFromContext(r.Context())
	isAdmin := userIsAdmin(r.Context(), h.repo, uname)
	if !isAdmin && existing.CreatedBy != uname {
		writeError(w, http.StatusNotFound, storage.ErrSubscribeFileNotFound)
		return
	}

	var req subscribeFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	// 短码编辑只允许管理员:普通用户即使是订阅创建者,也不能改 custom_short_code(短码归全局命名空间,必须管理)。
	// CustomShortCode 是 *string:nil = 前端没传(内联更新模板/标签等场景),不要碰短码;
	// 非 nil + 值变化 = 用户主动改 → 需要管理员权限。
	if !isAdmin && req.CustomShortCode != nil && *req.CustomShortCode != existing.CustomShortCode {
		writeError(w, http.StatusForbidden, errors.New("只有管理员可以编辑短码"))
		return
	}

	// 更新字段
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.URL != "" {
		existing.URL = req.URL
	}
	if req.Type != "" {
		existing.Type = req.Type
	}
	// 更新 auto_sync_custom_rules（如果提供）
	wasAutoSyncEnabled := existing.AutoSyncCustomRules
	if req.AutoSyncCustomRules != nil {
		existing.AutoSyncCustomRules = *req.AutoSyncCustomRules
	}
	existing.TemplateFilename = req.TemplateFilename
	if req.SelectedTags != nil {
		existing.SelectedTags = req.SelectedTags
	}
	if req.SelectedNodeIDs != nil {
		existing.SelectedNodeIDs = req.SelectedNodeIDs
	}
	if req.SelectedCustomRuleIDs != nil {
		existing.SelectedCustomRuleIDs = req.SelectedCustomRuleIDs
	}
	if req.SelectedOverrideScriptIDs != nil {
		existing.SelectedOverrideScriptIDs = req.SelectedOverrideScriptIDs
	}
	existing.StatsServerIDs = req.StatsServerIDs
	existing.TrafficLimit = req.TrafficLimit
	// 仅当前端显式传了 custom_short_code 才覆盖(同上,nil = 内联更新场景,保留原值)
	if req.CustomShortCode != nil {
		existing.CustomShortCode = *req.CustomShortCode
	}
	if req.RawOutput != nil {
		existing.RawOutput = *req.RawOutput
	}
	if req.SortOrder != nil {
		existing.SortOrder = *req.SortOrder
	}

	// 处理文件名更新
	oldFilename := existing.Filename
	needRenameFile := false
	if req.Filename != "" && req.Filename != existing.Filename {
		// 验证新文件名
		ext := filepath.Ext(req.Filename)
		if ext != ".yaml" && ext != ".yml" {
			writeError(w, http.StatusBadRequest, errors.New("文件名必须以 .yaml 或 .yml 结尾"))
			return
		}
		if err := storage.ValidateSubscribeFilename(req.Filename); err != nil {
			writeBadRequest(w, "文件名必须是 .yaml 或 .yml 结尾且不能包含路径")
			return
		}

		// 检查新文件名是否已被其他订阅使用
		if existingFile, err := h.repo.GetSubscribeFileByFilename(r.Context(), req.Filename); err == nil && existingFile.ID != id {
			writeError(w, http.StatusConflict, errors.New("文件名已被其他订阅使用"))
			return
		}

		existing.Filename = req.Filename
		needRenameFile = true
	}

	var updated storage.SubscribeFile
	if needRenameFile {
		updated, err = h.renameSubscriptionFile(r.Context(), existing, oldFilename)
	} else {
		updated, err = h.repo.UpdateSubscribeFile(r.Context(), existing)
	}
	if err != nil {
		if errors.Is(err, errSubscribeFilenameTargetExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		if errors.Is(err, storage.ErrSubscribeFilenameHistory) || errors.Is(err, storage.ErrSubscribeFileChanged) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 如果 auto_sync 刚刚启用（从 false 更改为 true），则触发立即同步
	if !wasAutoSyncEnabled && updated.AutoSyncCustomRules {
		go func() {
			addedGroups, err := syncCustomRulesToFile(context.Background(), h.repo, updated)
			if err != nil {
				logger.Info("[AutoSync] 同步自定义规则失败", "filename", updated.Filename, "id", updated.ID, "error", err)
			} else {
				logger.Info("[AutoSync] 同步自定义规则成功", "filename", updated.Filename, "id", updated.ID)
				if len(addedGroups) > 0 {
					logger.Info("[AutoSync] 添加的代理组", "groups", addedGroups)
				}
			}
		}()
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"file": convertSubscribeFile(updated),
	})
}

func (h *subscribeFilesHandler) renameSubscriptionFile(ctx context.Context, file storage.SubscribeFile, oldFilename string) (storage.SubscribeFile, error) {
	newFilename := strings.TrimSpace(file.Filename)
	oldFilename = strings.TrimSpace(oldFilename)
	if err := storage.ValidateSubscribeFilename(oldFilename); err != nil {
		return storage.SubscribeFile{}, fmt.Errorf("旧文件名不合法: %w", err)
	}
	if err := storage.ValidateSubscribeFilename(newFilename); err != nil {
		return storage.SubscribeFile{}, fmt.Errorf("新文件名不合法: %w", err)
	}
	versions, err := h.repo.ListRuleVersionContentsByFilename(ctx, oldFilename)
	if err != nil {
		return storage.SubscribeFile{}, fmt.Errorf("读取订阅历史失败: %w", err)
	}
	for index := range versions {
		rebound, err := rebindWireGuardSubscriptionContent(ctx, h.repo, oldFilename, newFilename, versions[index].Content)
		if err != nil {
			return storage.SubscribeFile{}, fmt.Errorf("重绑定历史版本 %d 失败: %w", versions[index].ID, err)
		}
		versions[index].Content = rebound
	}

	oldPath := filepath.Join("subscribes", oldFilename)
	newPath := filepath.Join("subscribes", newFilename)
	if _, err := os.Lstat(newPath); err == nil {
		return storage.SubscribeFile{}, errSubscribeFilenameTargetExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return storage.SubscribeFile{}, fmt.Errorf("检查目标订阅文件失败: %w", err)
	}
	oldOwnership, statErr := os.Lstat(oldPath)
	if errors.Is(statErr, os.ErrNotExist) {
		return storage.SubscribeFile{}, errors.New("旧订阅文件不存在，拒绝提交改名")
	}
	if statErr != nil {
		return storage.SubscribeFile{}, fmt.Errorf("检查旧订阅文件失败: %w", statErr)
	}
	if !oldOwnership.Mode().IsRegular() {
		return storage.SubscribeFile{}, errors.New("旧订阅文件不是普通文件，拒绝提交改名")
	}
	oldContent, readErr := os.ReadFile(oldPath)
	if readErr != nil {
		return storage.SubscribeFile{}, fmt.Errorf("读取旧订阅文件失败: %w", readErr)
	}
	rebound, err := rebindWireGuardSubscriptionContent(ctx, h.repo, oldFilename, newFilename, string(oldContent))
	if err != nil {
		return storage.SubscribeFile{}, fmt.Errorf("重绑定订阅文件失败: %w", err)
	}
	newOwnership, err := writeNewPrivateSubscriptionFile(newPath, []byte(rebound))
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return storage.SubscribeFile{}, errSubscribeFilenameTargetExists
		}
		return storage.SubscribeFile{}, fmt.Errorf("写入新订阅文件失败: %w", err)
	}

	updated, err := h.repo.RenameSubscribeFileAndRuleVersions(ctx, file, oldFilename, versions)
	if err != nil {
		if cleanupErr := removeSubscriptionFileIfOwned(newPath, newOwnership); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			logger.Info("[订阅改名] 数据库回滚后清理新文件失败", "filename", newFilename, "error", cleanupErr)
		}
		return storage.SubscribeFile{}, err
	}
	if err := removeSubscriptionFileIfOwned(oldPath, oldOwnership); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The database and new 0600 file are already consistent. Keeping the
		// old encrypted orphan is safer than deleting or rolling back the new
		// working copy after commit.
		logger.Info("[订阅改名] 清理旧加密文件失败", "filename", oldFilename, "error", err)
	}
	return updated, nil
}

func (h *subscribeFilesHandler) handleDelete(w http.ResponseWriter, r *http.Request, idSegment string) {
	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的订阅ID")
		return
	}

	// 获取文件信息以便删除物理文件
	file, err := h.repo.GetSubscribeFileByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 所有权校验:普通用户只能删自己创建的订阅。
	if uname := auth.UsernameFromContext(r.Context()); !userIsAdmin(r.Context(), h.repo, uname) && file.CreatedBy != uname {
		writeError(w, http.StatusNotFound, storage.ErrSubscribeFileNotFound)
		return
	}
	if err := deleteSubscribeFileAndPhysical(r.Context(), h.repo, "subscribes", file); err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *subscribeFilesHandler) handleReorder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}
	if len(req.IDs) == 0 {
		writeBadRequest(w, "排序列表不能为空")
		return
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()

	if err := h.repo.ReorderSubscribeFiles(r.Context(), req.IDs); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "reordered"})
}

func (h *subscribeFilesHandler) handleTraffic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	files, err := h.repo.ListSubscribeFiles(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 普通用户(开了"订阅管理"权限后能进来):流量列必须显示套餐口径,
	// 跟 /api/traffic/summary 上的"流量信息"页保持一致 —— 否则下面那条
	// GetAllRemoteServersTrafficTotals 路径会把全平台所有用户的 inbound 流量
	// 全聚合返回,与该用户毫无关系。
	username := auth.UsernameFromContext(ctx)
	if !userIsAdmin(ctx, h.repo, username) {
		h.handleTrafficForUser(ctx, w, username, files)
		return
	}

	allNodes, err := h.repo.ListAllNodes(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	allExternalSubs, _ := h.repo.ListAllExternalSubscriptions(ctx)
	extSubByName := make(map[string]storage.ExternalSubscription, len(allExternalSubs))
	for _, s := range allExternalSubs {
		extSubByName[s.Name] = s
	}

	type trafficItem struct {
		Used  int64 `json:"used"`
		Limit int64 `json:"limit"`
	}
	result := make(map[int64]trafficItem, len(files))

	now := time.Now()
	for _, f := range files {
		nodes := allNodes
		if len(f.SelectedTags) > 0 {
			tagsMap := make(map[string]bool, len(f.SelectedTags))
			for _, t := range f.SelectedTags {
				tagsMap[t] = true
			}
			filtered := make([]storage.Node, 0)
			for _, n := range allNodes {
				if n.HasAnyTag(tagsMap) {
					filtered = append(filtered, n)
				}
			}
			nodes = filtered
		}

		// 收集外部订阅名(用于把订阅源自带的 used/total 也算进去 — 与服务器流量并列)
		extSubNames := make(map[string]bool)
		for _, n := range nodes {
			if n.Tag != "" && n.Tag != "手动输入" {
				extSubNames[n.Tag] = true
			}
		}

		// 服务器流量范围:
		//   stats_server_ids 非空 → 仅统计选中的服务器
		//   stats_server_ids 空(默认)→ 统计全部服务器
		var serverScopeIDs []int64
		if strings.TrimSpace(f.StatsServerIDs) != "" {
			for _, s := range strings.Split(f.StatsServerIDs, ",") {
				if id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && id > 0 {
					serverScopeIDs = append(serverScopeIDs, id)
				}
			}
		}

		var totalUsed, totalLimit int64
		if len(serverScopeIDs) > 0 {
			limit, used, _ := h.repo.GetRemoteServerTrafficTotals(ctx, serverScopeIDs)
			totalUsed += used
			totalLimit += limit
		} else {
			limit, used, _ := h.repo.GetAllRemoteServersTrafficTotals(ctx)
			totalUsed += used
			totalLimit += limit
		}

		for name := range extSubNames {
			sub, ok := extSubByName[name]
			if !ok {
				continue
			}
			if sub.Expire != nil && sub.Expire.Before(now) {
				continue
			}
			totalLimit += sub.Total
			switch sub.TrafficMode {
			case "download":
				totalUsed += sub.Download
			case "upload":
				totalUsed += sub.Upload
			default:
				totalUsed += sub.Upload + sub.Download
			}
		}

		// 仅当订阅自带 traffic_limit > 0 时才作为"用户显式覆盖"使用;
		// nil / 0 都视作"跟随服务器算出的 totalLimit",避免前端 inline payload 把 0 持久化后覆盖掉服务器额度。
		if f.TrafficLimit != nil && *f.TrafficLimit > 0 {
			totalLimit = int64(*f.TrafficLimit * 1024 * 1024 * 1024)
		}
		result[f.ID] = trafficItem{Used: totalUsed, Limit: totalLimit}
	}

	respondJSON(w, http.StatusOK, map[string]any{"traffic": result})
}

// handleTrafficForUser 给单个普通用户返回订阅流量:对该用户名下每个订阅文件
// 都填同一组 {used, limit} = 用户套餐口径,跟 /api/traffic/summary 完全一致。
// 没绑套餐的用户:返回 0/0(前端会显示无限制/未消耗,行为与流量信息页一致)。
func (h *subscribeFilesHandler) handleTrafficForUser(ctx context.Context, w http.ResponseWriter, username string, files []storage.SubscribeFile) {
	type trafficItem struct {
		Used  int64 `json:"used"`
		Limit int64 `json:"limit"`
	}
	result := make(map[int64]trafficItem, len(files))

	var used, limit int64
	if username != "" {
		if user, err := h.repo.GetUser(ctx, username); err == nil && user.PackageID > 0 {
			if pkg, perr := h.repo.GetPackage(ctx, user.PackageID); perr == nil {
				limit = resolveTrafficLimitBytes(&user, pkg)
				if raw, terr := h.repo.GetUserTotalTraffic(ctx, username); terr == nil {
					used = raw * pkg.TrafficMultiplier()
				}
			}
		}
	}

	for _, f := range files {
		if f.CreatedBy != username {
			continue
		}
		// 订阅自定义限额覆盖套餐限额(管理员路径的同款语义)
		fileLimit := limit
		if f.TrafficLimit != nil {
			fileLimit = int64(*f.TrafficLimit * 1024 * 1024 * 1024)
		}
		result[f.ID] = trafficItem{Used: used, Limit: fileLimit}
	}

	respondJSON(w, http.StatusOK, map[string]any{"traffic": result})
}

// parseFilenameFromContentDisposition 从Content-Disposition头解析文件名
// 支持格式: attachment;filename*=UTF-8”%E6%B3%A1%E6%B3%A1Dog
func parseFilenameFromContentDisposition(header string) string {
	// 查找 filename*= 部分
	if idx := strings.Index(header, "filename*="); idx != -1 {
		// 提取等号后的内容
		value := header[idx+10:]
		// 查找两个单引号后的内容
		if idx2 := strings.LastIndex(value, "''"); idx2 != -1 {
			encoded := value[idx2+2:]
			// URL解码
			if decoded, err := url.QueryUnescape(encoded); err == nil {
				return decoded
			}
		}
	}

	// 如果没有filename*=，尝试filename=
	if idx := strings.Index(header, "filename="); idx != -1 {
		value := header[idx+9:]
		value = strings.Trim(value, `"`)
		if idx2 := strings.IndexAny(value, ";,"); idx2 != -1 {
			value = value[:idx2]
		}
		return strings.TrimSpace(value)
	}

	return ""
}

type subscribeFileRequest struct {
	Name                      string   `json:"name"`
	Description               string   `json:"description"`
	URL                       string   `json:"url"`
	Type                      string   `json:"type"`
	Filename                  string   `json:"filename"`
	AutoSyncCustomRules       *bool    `json:"auto_sync_custom_rules,omitempty"`
	TemplateFilename          string   `json:"template_filename"`
	SelectedTags              []string `json:"selected_tags"`
	SelectedNodeIDs           []int64  `json:"selected_node_ids"`
	SelectedCustomRuleIDs     []int64  `json:"selected_custom_rule_ids"`
	SelectedOverrideScriptIDs []int64  `json:"selected_override_script_ids"`
	StatsServerIDs            string   `json:"stats_server_ids"`
	TrafficLimit              *float64 `json:"traffic_limit"`
	// 必须用指针以区分"前端没传"vs"前端想清空":
	// 内联更新(只发 template_filename)时 CustomShortCode 字段缺省,
	// 旧 string 零值会被误判为"想把短码清空"→ 触发"只有管理员可以编辑短码"。
	CustomShortCode *string `json:"custom_short_code,omitempty"`
	RawOutput       *bool   `json:"raw_output,omitempty"`
	SortOrder       *int    `json:"sort_order,omitempty"`
}

type subscribeFileDTO struct {
	ID                        int64     `json:"id"`
	Name                      string    `json:"name"`
	Description               string    `json:"description"`
	Type                      string    `json:"type"`
	Filename                  string    `json:"filename"`
	FileShortCode             string    `json:"file_short_code"`
	CustomShortCode           string    `json:"custom_short_code"`
	AutoSyncCustomRules       bool      `json:"auto_sync_custom_rules"`
	TemplateFilename          string    `json:"template_filename"`
	SelectedTags              []string  `json:"selected_tags"`
	SelectedNodeIDs           []int64   `json:"selected_node_ids"`
	SelectedCustomRuleIDs     []int64   `json:"selected_custom_rule_ids"`
	SelectedOverrideScriptIDs []int64   `json:"selected_override_script_ids"`
	StatsServerIDs            string    `json:"stats_server_ids"`
	TrafficLimit              *float64  `json:"traffic_limit"`
	SortOrder                 int       `json:"sort_order"`
	RawOutput                 bool      `json:"raw_output"`
	CreatedBy                 string    `json:"created_by"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
	LatestVersion             int64     `json:"latest_version,omitempty"`
}

func convertSubscribeFile(file storage.SubscribeFile) subscribeFileDTO {
	// nil → 空数组,避免 JSON 序列化成 null 让前端 .map / .has 走错分支
	tags := file.SelectedTags
	if tags == nil {
		tags = []string{}
	}
	nodeIDs := file.SelectedNodeIDs
	if nodeIDs == nil {
		nodeIDs = []int64{}
	}
	ruleIDs := file.SelectedCustomRuleIDs
	if ruleIDs == nil {
		ruleIDs = []int64{}
	}
	scriptIDs := file.SelectedOverrideScriptIDs
	if scriptIDs == nil {
		scriptIDs = []int64{}
	}
	return subscribeFileDTO{
		ID:                        file.ID,
		Name:                      file.Name,
		Description:               file.Description,
		Type:                      file.Type,
		Filename:                  file.Filename,
		FileShortCode:             file.FileShortCode,
		CustomShortCode:           file.CustomShortCode,
		AutoSyncCustomRules:       file.AutoSyncCustomRules,
		TemplateFilename:          file.TemplateFilename,
		SelectedTags:              tags,
		SelectedNodeIDs:           nodeIDs,
		SelectedCustomRuleIDs:     ruleIDs,
		SelectedOverrideScriptIDs: scriptIDs,
		StatsServerIDs:            file.StatsServerIDs,
		TrafficLimit:              file.TrafficLimit,
		SortOrder:                 file.SortOrder,
		RawOutput:                 file.RawOutput,
		CreatedBy:                 file.CreatedBy,
		CreatedAt:                 file.CreatedAt,
		UpdatedAt:                 file.UpdatedAt,
	}
}

func convertSubscribeFiles(files []storage.SubscribeFile) []subscribeFileDTO {
	result := make([]subscribeFileDTO, 0, len(files))
	for _, file := range files {
		result = append(result, convertSubscribeFile(file))
	}
	return result
}

func (h *subscribeFilesHandler) convertSubscribeFilesWithVersions(ctx context.Context, files []storage.SubscribeFile) []subscribeFileDTO {
	result := make([]subscribeFileDTO, 0, len(files))
	for _, file := range files {
		dto := convertSubscribeFile(file)

		// 获取最新版本号
		if versions, err := h.repo.ListRuleVersions(ctx, file.Filename, 1); err == nil && len(versions) > 0 {
			dto.LatestVersion = versions[0].Version
		}

		result = append(result, dto)
	}
	return result
}

// 保存生成的配置为订阅文件
func (h *subscribeFilesHandler) handleCreateFromConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Filename    string `json:"filename"`
		Content     string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.Name == "" {
		writeBadRequest(w, "订阅名称是必填项")
		return
	}
	if req.Content == "" {
		writeBadRequest(w, "配置内容不能为空")
		return
	}

	// 获取当前用户名和设置，判断是否需要校验
	username := auth.UsernameFromContext(r.Context())
	shouldValidate := true // 默认进行校验
	if username != "" {
		// 获取用户设置
		settings, err := h.repo.GetUserSettings(r.Context(), username)
		if err == nil {
			// 只有在使用新模板系统时才进行校验
			shouldValidate = settings.UseNewTemplateSystem
			logger.Info("[创建订阅文件] 用户设置", "username", username, "use_new_template_system", settings.UseNewTemplateSystem, "should_validate", shouldValidate)
		} else if !errors.Is(err, storage.ErrUserSettingsNotFound) {
			logger.Info("[创建订阅文件] 获取用户设置失败，使用默认行为(进行校验)", "username", username, "error", err)
		}
	}

	// 设置默认文件名
	filename := req.Filename
	if filename == "" {
		filename = req.Name
	}

	// 确保文件名有.yaml或.yml扩展名
	ext := filepath.Ext(filename)
	if ext != ".yaml" && ext != ".yml" {
		filename = filename + ".yaml"
	}
	filename = strings.TrimSpace(filename)
	if err := storage.ValidateSubscribeFilename(filename); err != nil {
		writeBadRequest(w, "文件名必须是 .yaml 或 .yml 结尾且不能包含路径")
		return
	}

	// 验证YAML格式，使用Node API保持顺序和格式
	var rootNode yaml.Node
	if err := yaml.Unmarshal([]byte(req.Content), &rootNode); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("配置内容不是有效的YAML格式"))
		return
	}

	// 只有在使用新模板系统时才进行配置校验
	if shouldValidate {
		// 校验配置内容
		var configMap map[string]interface{}
		var tempBuf bytes.Buffer
		tempEncoder := yaml.NewEncoder(&tempBuf)
		tempEncoder.SetIndent(2)
		if err := tempEncoder.Encode(&rootNode); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("编码配置用于校验失败"))
			return
		}
		if err := yaml.Unmarshal(tempBuf.Bytes(), &configMap); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("解析配置用于校验失败"))
			return
		}

		validationResult := validator.ValidateClashConfig(configMap)
		if !validationResult.Valid {
			logger.Info("[创建订阅文件] [配置校验] 校验失败", "filename", filename)
			var errorMessages []string
			for _, issue := range validationResult.Issues {
				if issue.Level == validator.ErrorLevel {
					errorMsg := issue.Message
					if issue.Location != "" {
						errorMsg = fmt.Sprintf("%s (位置: %s)", errorMsg, issue.Location)
					}
					errorMessages = append(errorMessages, errorMsg)
					logger.Info("[创建订阅文件] [配置校验] 错误", "message", errorMsg)
				}
			}
			writeError(w, http.StatusBadRequest, errors.New("配置校验失败: "+strings.Join(errorMessages, "; ")))
			return
		}

		// 如果有自动修复，使用修复后的配置
		if validationResult.FixedConfig != nil {
			fixedYAML, err := yaml.Marshal(validationResult.FixedConfig)
			if err != nil {
				writeError(w, http.StatusInternalServerError, errors.New("序列化修复配置失败"))
				return
			}
			if err := yaml.Unmarshal(fixedYAML, &rootNode); err != nil {
				writeError(w, http.StatusInternalServerError, errors.New("解析修复配置失败"))
				return
			}

			// 记录自动修复的警告
			for _, issue := range validationResult.Issues {
				if issue.Level == validator.WarningLevel && issue.AutoFixed {
					logger.Info("[创建订阅文件] [配置校验] 警告(已修复)", "message", issue.Message, "location", issue.Location)
				}
			}
		}
	} else {
		logger.Info("[创建订阅文件] 使用旧模板系统，跳过配置校验", "filename", filename)
	}

	// 修复short-id字段，确保使用双引号
	// 修复ShortIdStyleInNode(&rootNode)

	// 重新序列化YAML，保持原有顺序和格式
	reserializedContent, err := MarshalYAMLWithIndent(&rootNode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("处理YAML内容失败"))
		return
	}

	// 修复表情符号/反斜杠转义
	fixedContent := RemoveUnicodeEscapeQuotes(string(reserializedContent))

	unlock, err := lockSubscriptionFilenames(filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()
	protectedContent, err := protectWireGuardSubscriptionContent(r.Context(), h.repo, filename, fixedContent, false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}

	// WireGuard 私钥以文件范围绑定的密文落盘，只有返回订阅时才在内存中解密。
	filePath := filepath.Join("subscribes", filename)
	ownership, err := writeNewPrivateSubscriptionFile(filePath, []byte(protectedContent))
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			writeError(w, http.StatusConflict, errSubscribeFilenameTargetExists)
			return
		}
		writeError(w, http.StatusInternalServerError, errors.New("保存订阅文件失败"))
		return
	}

	// 配额校验:普通用户创建订阅受全局配额限制(admin 不限)。
	if err := checkUserQuota(r.Context(), h.repo, username, "subscribe"); err != nil {
		_ = removeSubscriptionFileIfOwned(filePath, ownership)
		writeError(w, http.StatusForbidden, err)
		return
	}

	// 保存到数据库
	file := storage.SubscribeFile{
		Name:        req.Name,
		Description: req.Description,
		URL:         "",
		Type:        storage.SubscribeTypeCreate,
		Filename:    filename,
		CreatedBy:   username,
	}

	created, err := h.repo.CreateSubscribeFile(r.Context(), file)
	if err != nil {
		// 如果数据库保存失败，删除已保存的文件
		_ = removeSubscriptionFileIfOwned(filePath, ownership)
		if errors.Is(err, storage.ErrCustomShortCodeExists) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, storage.ErrSubscribeFileExists) || errors.Is(err, storage.ErrSubscribeFilenameHistory) {
			writeError(w, http.StatusConflict, errors.New("订阅名称已存在"))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// 初始化自定义规则应用记录以防止首次修改时出现重复
	h.initializeCustomRuleApplications(r.Context(), created.ID)

	respondJSON(w, http.StatusCreated, map[string]any{
		"file": convertSubscribeFile(created),
	})
}

// 获取订阅文件内容
func (h *subscribeFilesHandler) handleGetContent(w http.ResponseWriter, r *http.Request, filename string) {
	if filename == "" {
		writeBadRequest(w, "文件名不能为空")
		return
	}

	// 验证文件名
	filename, err := url.QueryUnescape(filename)
	if err != nil {
		writeBadRequest(w, "无效的文件名")
		return
	}
	if err := storage.ValidateSubscribeFilename(filename); err != nil {
		writeBadRequest(w, "无效的文件名")
		return
	}
	unlock, err := lockSubscriptionFilenames(filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()

	// 检查文件是否存在于数据库
	sf, err := h.repo.GetSubscribeFileByFilename(r.Context(), filename)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, errors.New("订阅文件不存在"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 所有权校验:普通用户只能看自己创建的订阅内容。
	if uname := auth.UsernameFromContext(r.Context()); !userIsAdmin(r.Context(), h.repo, uname) && sf.CreatedBy != uname {
		writeError(w, http.StatusNotFound, errors.New("订阅文件不存在"))
		return
	}

	// 读取文件内容
	filePath := filepath.Join("subscribes", filename)
	content, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, errors.New("文件不存在"))
			return
		}
		writeError(w, http.StatusInternalServerError, errors.New("读取文件失败"))
		return
	}
	hydratedContent, err := hydrateWireGuardSubscriptionContent(r.Context(), h.repo, filename, string(content))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("WireGuard 节点配置暂不可用"))
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"content": hydratedContent,
	})
}

// 更新订阅文件内容
func (h *subscribeFilesHandler) handleUpdateContent(w http.ResponseWriter, r *http.Request, filename string) {
	if filename == "" {
		writeBadRequest(w, "文件名不能为空")
		return
	}

	// 验证文件名
	filename, err := url.QueryUnescape(filename)
	if err != nil {
		writeBadRequest(w, "无效的文件名")
		return
	}
	if err := storage.ValidateSubscribeFilename(filename); err != nil {
		writeBadRequest(w, "无效的文件名")
		return
	}
	unlock, err := lockSubscriptionFilenames(filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()

	// 检查文件是否存在于数据库
	subscribeFile, err := h.repo.GetSubscribeFileByFilename(r.Context(), filename)
	if err != nil {
		if errors.Is(err, storage.ErrSubscribeFileNotFound) {
			writeError(w, http.StatusNotFound, errors.New("订阅文件不存在"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 所有权校验:普通用户只能改自己创建的订阅内容。
	if uname := auth.UsernameFromContext(r.Context()); !userIsAdmin(r.Context(), h.repo, uname) && subscribeFile.CreatedBy != uname {
		writeError(w, http.StatusNotFound, errors.New("订阅文件不存在"))
		return
	}

	// 解析请求体
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "请求格式不正确")
		return
	}

	if req.Content == "" {
		writeBadRequest(w, "内容不能为空")
		return
	}

	// 验证YAML格式，使用 Node API 保持顺序
	var rootNode yaml.Node
	if err := yaml.Unmarshal([]byte(req.Content), &rootNode); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("内容不是有效的YAML格式: "+err.Error()))
		return
	}

	// 转换为 map 进行基本校验（只检查错误，不做修复）
	var yamlCheck map[string]any
	if err := yaml.Unmarshal([]byte(req.Content), &yamlCheck); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("内容不是有效的YAML格式: "+err.Error()))
		return
	}

	// 校验配置内容
	validationResult := validator.ValidateClashConfig(yamlCheck)
	if !validationResult.Valid {
		logger.Info("[更新订阅文件] [配置校验] 校验失败", "filename", filename)
		var errorMessages []string
		for _, issue := range validationResult.Issues {
			if issue.Level == validator.ErrorLevel {
				errorMsg := issue.Message
				if issue.Location != "" {
					errorMsg = fmt.Sprintf("%s (位��: %s)", errorMsg, issue.Location)
				}
				errorMessages = append(errorMessages, errorMsg)
				logger.Info("[更新订阅文件] [配置校验] 错误", "message", errorMsg)
			}
		}
		writeError(w, http.StatusBadRequest, errors.New("配置校验失败: "+strings.Join(errorMessages, "; ")))
		return
	}

	// 直接保存前端发送的内容（已经过前端修复，保持字段顺序）
	contentToSave := RemoveUnicodeEscapeQuotes(req.Content)
	protectedContent, err := protectWireGuardSubscriptionContent(r.Context(), h.repo, filename, contentToSave, false)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}

	// 记录警告信息（如果有）
	for _, issue := range validationResult.Issues {
		if issue.Level == validator.WarningLevel {
			logger.Info("[更新订阅文件] [配置校验] 警告(前端已修复)", "message", issue.Message, "location", issue.Location)
		}
	}

	// 保存文件
	filePath := filepath.Join("subscribes", filename)
	if err := writePrivateSubscriptionFileUnlocked(filePath, []byte(protectedContent)); err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("保存文件失败"))
		return
	}

	// 保存版本记录(author = 当前调用者,而非硬编码 "admin")
	author := auth.UsernameFromContext(r.Context())
	if author == "" {
		author = "admin"
	}
	version, err := h.repo.SaveRuleVersionForSubscribe(r.Context(), subscribeFile.ID, filename, protectedContent, author)
	if err != nil {
		// 版本保存失败不影响文件保存，只记录错误
		writeError(w, http.StatusInternalServerError, errors.New("保存版本记录失败"))
		return
	}

	// 更新数据库中的updated_at字段
	subscribeFile.UpdatedAt = time.Now()
	_, err = h.repo.UpdateSubscribeFile(r.Context(), subscribeFile)
	if err != nil {
		// 更新时间戳失败不影响文件保存，只记录错误
		writeError(w, http.StatusInternalServerError, errors.New("更新订阅信息失败"))
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status":  "updated",
		"version": version,
	})
}

// initializeCustomRuleApplications 记录新创建的订阅文件的初始自定义规则应用程序状态。
// 当从内容中已包含自定义规则的生成器页面创建文件时，会调用此方法。
// 我们只记录应用程序状态，而不重新应用规则（这会重复它们）。
func (h *subscribeFilesHandler) initializeCustomRuleApplications(ctx context.Context, fileID int64) {
	// 获取所有已启用的自定义规则以记录其当前状态
	rules, err := h.repo.ListEnabledCustomRules(ctx, "")
	if err != nil {
		logger.Info("[Subscribe] 获取自定义规则失败", "error", err)
		return
	}

	if len(rules) == 0 {
		return
	}

	// 记录每个规则的当前状态而不修改文件
	for _, rule := range rules {
		// 计算内容哈希以跟踪未来的变化
		hash := sha256.Sum256([]byte(rule.Content))
		contentHash := hex.EncodeToString(hash[:])

		// 解析规则内容以提取应用的实际规则/提供程序
		// 这必须与 applyRulesRule 和 applyRuleProvidersRule 中使用的格式匹配
		var appliedContent string
		if rule.Type == "rules" {
			// 解析规则内容，得到规则数组
			var newRules []interface{}

			// 尝试首先解析为地图（使用“rules:”键）
			var parsedAsMap map[string]interface{}
			if err := yaml.Unmarshal([]byte(rule.Content), &parsedAsMap); err == nil {
				if rulesValue, hasRulesKey := parsedAsMap["rules"]; hasRulesKey {
					if rulesArray, ok := rulesValue.([]interface{}); ok {
						newRules = rulesArray
					}
				}
			}

			// 尝试解析为 YAML 数组
			if len(newRules) == 0 {
				if err := yaml.Unmarshal([]byte(rule.Content), &newRules); err != nil {
					// 解析为纯文本
					lines := strings.Split(rule.Content, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" && !strings.HasPrefix(line, "#") {
							newRules = append(newRules, line)
						}
					}
				}
			}

			// 序列化为 JSON 格式（与 applyRulesRule 相同）
			if len(newRules) > 0 {
				appliedJSON, _ := json.Marshal(newRules)
				appliedContent = string(appliedJSON)
			}
		} else if rule.Type == "rule-providers" {
			// 解析规则提供者内容
			var parsedContent map[string]interface{}
			if err := yaml.Unmarshal([]byte(rule.Content), &parsedContent); err == nil {
				var providersMap map[string]interface{}
				if providersValue, hasProvidersKey := parsedContent["rule-providers"]; hasProvidersKey {
					if pm, ok := providersValue.(map[string]interface{}); ok {
						providersMap = pm
					}
				} else {
					providersMap = parsedContent
				}

				// 序列化为JSON格式
				if len(providersMap) > 0 {
					appliedJSON, _ := json.Marshal(providersMap)
					appliedContent = string(appliedJSON)
				}
			}
		} else if rule.Type == "dns" {
			// 对于 DNS 规则，我们不跟踪应用的内容
			appliedContent = ""
		}

		app := &storage.CustomRuleApplication{
			SubscribeFileID: fileID,
			CustomRuleID:    rule.ID,
			RuleType:        rule.Type,
			RuleMode:        rule.Mode,
			AppliedContent:  appliedContent,
			ContentHash:     contentHash,
		}

		if err := h.repo.UpsertCustomRuleApplication(ctx, app); err != nil {
			logger.Info("[Subscribe] 记录自定义规则应用失败", "rule_id", rule.ID, "error", err)
		}
	}

	logger.Info("[Subscribe] 记录自定义规则应用状态完成", "rule_count", len(rules), "file_id", fileID)
}

// handleGetSubscriptionUsers GET /api/admin/subscribe-files/{id}/users
// 返回该订阅文件分配给哪些用户 + 各自的 user_short_code / custom_user_short_code(同步自 mmw v0.7.3)
func (h *subscribeFilesHandler) handleGetSubscriptionUsers(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeBadRequest(w, "invalid subscription file ID")
		return
	}

	users, err := h.repo.GetUsersBySubscriptionID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if users == nil {
		users = []storage.UserShortCodeInfo{}
	}

	respondJSON(w, http.StatusOK, map[string]any{"users": users})
}

// filterAdminVisibleSubscribeFiles 给 admin 视角的 handleList 用 — 隐藏掉普通用户私创的订阅文件。
// 实现:对所有 distinct created_by 一次性查 role,O(distinct creators) 次 GetUser,避免每条订阅 N+1。
//   - created_by 空 → 保留(无主历史数据)
//   - created_by == self(当前 admin) → 保留
//   - created_by 是另一个 admin → 保留(admin 之间互见)
//   - created_by 是普通用户 → 隐藏(该用户私创的"生成订阅",不应被其他 admin 看到)
func filterAdminVisibleSubscribeFiles(ctx context.Context, repo *storage.TrafficRepository, files []storage.SubscribeFile, self string) []storage.SubscribeFile {
	if len(files) == 0 {
		return files
	}
	creators := map[string]struct{}{}
	for _, f := range files {
		if f.CreatedBy != "" && f.CreatedBy != self {
			creators[f.CreatedBy] = struct{}{}
		}
	}
	adminCreators := make(map[string]bool, len(creators))
	for c := range creators {
		if u, err := repo.GetUser(ctx, c); err == nil && u.Role == storage.RoleAdmin {
			adminCreators[c] = true
		}
	}
	out := make([]storage.SubscribeFile, 0, len(files))
	for _, f := range files {
		if f.CreatedBy == "" || f.CreatedBy == self || adminCreators[f.CreatedBy] {
			out = append(out, f)
		}
	}
	return out
}
