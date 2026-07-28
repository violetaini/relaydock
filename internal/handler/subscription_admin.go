package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
)

type subscriptionAdminHandler struct {
	repo    *storage.TrafficRepository
	baseDir string
}

// 返回一个管理订阅链接的仅管理处理程序。
func NewSubscriptionAdminHandler(baseDir string, repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("subscription admin handler requires repository")
	}

	if baseDir == "" {
		baseDir = filepath.FromSlash("subscribes")
	}

	return &subscriptionAdminHandler{
		repo:    repo,
		baseDir: filepath.Clean(baseDir),
	}
}

func (h *subscriptionAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/subscriptions")
	path = strings.Trim(path, "/")

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.handleList(w, r)
	case path == "" && r.Method == http.MethodPost:
		h.handleCreate(w, r)
	case path != "" && (r.Method == http.MethodPut || r.Method == http.MethodPatch):
		h.handleUpdate(w, r, path)
	case path != "" && r.Method == http.MethodDelete:
		h.handleDelete(w, r, path)
	default:
		allowed := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
		methodNotAllowed(w, allowed...)
	}
}

func (h *subscriptionAdminHandler) handleList(w http.ResponseWriter, r *http.Request) {
	unlock, err := lockSubscriptionStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()
	links, err := h.repo.ListSubscriptionLinks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"subscriptions": convertSubscriptions(links),
	})
}

func (h *subscriptionAdminHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeBadRequest(w, "上传格式不正确")
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))
	typ := strings.TrimSpace(r.FormValue("type"))
	buttons := r.MultipartForm.Value["buttons"]

	file, header, err := r.FormFile("rule_file")
	if err != nil {
		writeBadRequest(w, "规则文件是必填项")
		return
	}
	defer file.Close()
	unlock, err := lockSubscriptionStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()

	filename, ownership, err := h.persistRuleFileLocked(r.Context(), name, header, file, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	link := storage.SubscriptionLink{
		Name:         name,
		Type:         typ,
		Description:  description,
		Buttons:      buttons,
		RuleFilename: filename,
	}

	created, err := h.repo.CreateSubscriptionLink(r.Context(), link)
	if err != nil {
		_ = removeSubscriptionFileIfOwned(filepath.Join(h.baseDir, filename), ownership)
		switch {
		case errors.Is(err, storage.ErrSubscriptionExists):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusBadRequest, err)
		}
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"subscription": convertSubscription(created),
	})
}

func (h *subscriptionAdminHandler) handleUpdate(w http.ResponseWriter, r *http.Request, idSegment string) {
	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的订阅标识")
		return
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()

	existing, err := h.repo.GetSubscriptionByID(r.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrSubscriptionNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeBadRequest(w, "上传格式不正确")
		return
	}

	name := strings.TrimSpace(firstValue(r.MultipartForm.Value["name"], existing.Name))
	description := strings.TrimSpace(firstValue(r.MultipartForm.Value["description"], existing.Description))
	typ := strings.TrimSpace(firstValue(r.MultipartForm.Value["type"], existing.Type))
	buttons := r.MultipartForm.Value["buttons"]
	if len(buttons) == 0 {
		buttons = existing.Buttons
	}

	var filename = existing.RuleFilename
	var uploadedNewFile bool
	var newOwnership os.FileInfo
	if header, err := fileHeader(r.MultipartForm.File["rule_file"]); err == nil {
		file, openErr := header.Open()
		if openErr != nil {
			writeError(w, http.StatusBadRequest, openErr)
			return
		}
		defer file.Close()

		persisted, ownership, persistErr := h.persistRuleFileLocked(r.Context(), name, header, file, existing.RuleFilename)
		if persistErr != nil {
			writeError(w, http.StatusBadRequest, persistErr)
			return
		}
		filename = persisted
		newOwnership = ownership
		uploadedNewFile = true
	}

	updated, err := h.repo.UpdateSubscriptionLink(r.Context(), storage.SubscriptionLink{
		ID:           existing.ID,
		Name:         name,
		Type:         typ,
		Description:  description,
		Buttons:      buttons,
		RuleFilename: filename,
	})
	if err != nil {
		if newOwnership != nil {
			_ = removeSubscriptionFileIfOwned(filepath.Join(h.baseDir, filename), newOwnership)
		}
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrSubscriptionNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, storage.ErrSubscriptionExists) {
			status = http.StatusConflict
		}
		writeError(w, status, err)
		return
	}

	if uploadedNewFile && filename != existing.RuleFilename {
		h.cleanupRuleFileLocked(r.Context(), existing.RuleFilename)
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"subscription": convertSubscription(updated),
	})
}

func (h *subscriptionAdminHandler) handleDelete(w http.ResponseWriter, r *http.Request, idSegment string) {
	id, err := strconv.ParseInt(idSegment, 10, 64)
	if err != nil || id <= 0 {
		writeBadRequest(w, "无效的订阅标识")
		return
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer unlock()

	existing, err := h.repo.GetSubscriptionByID(r.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrSubscriptionNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	if err := h.repo.DeleteSubscriptionLink(r.Context(), id); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrSubscriptionNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}

	h.cleanupRuleFileLocked(r.Context(), existing.RuleFilename)

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *subscriptionAdminHandler) persistRuleFileLocked(ctx context.Context, name string, header *multipart.FileHeader, src multipart.File, fallback string) (string, os.FileInfo, error) {
	if header == nil {
		return fallback, nil, nil
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".yaml" && ext != ".yml" {
		return "", nil, errors.New("仅支持 YAML 规则文件")
	}
	if ext == ".yml" {
		ext = ".yaml"
	}

	if header.Size > 10<<20 { // 详见上下文
		return "", nil, errors.New("规则文件大小不可超过 10MB")
	}

	filename := buildRuleFilename(name, ext)
	if err := storage.ValidateSubscribeFilename(filename); err != nil {
		return "", nil, err
	}
	content, err := io.ReadAll(io.LimitReader(src, (10<<20)+1))
	if err != nil {
		return "", nil, fmt.Errorf("读取规则文件失败: %w", err)
	}
	if len(content) > 10<<20 {
		return "", nil, errors.New("规则文件大小不可超过 10MB")
	}
	protected, err := protectWireGuardSubscriptionContent(ctx, h.repo, filename, string(content), false)
	if err != nil {
		return "", nil, err
	}

	destination := filepath.Join(h.baseDir, filename)
	if filename == fallback && fallback != "" {
		if err := writePrivateSubscriptionFileUnlocked(destination, []byte(protected)); err != nil {
			return "", nil, fmt.Errorf("保存规则文件失败: %w", err)
		}
		return filename, nil, nil
	}
	ownership, err := writeNewPrivateSubscriptionFile(destination, []byte(protected))
	if err != nil {
		return "", nil, fmt.Errorf("保存规则文件失败: %w", err)
	}
	return filename, ownership, nil
}

func (h *subscriptionAdminHandler) cleanupRuleFileLocked(ctx context.Context, filename string) {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return
	}
	if err := storage.ValidateSubscribeFilename(filename); err != nil {
		return
	}
	count, err := h.repo.CountSubscriptionsByFilename(ctx, filename)
	if err != nil || count > 0 {
		return
	}
	if _, err := h.repo.GetSubscribeFileByFilename(ctx, filename); err == nil {
		return
	} else if !errors.Is(err, storage.ErrSubscribeFileNotFound) {
		return
	}

	path := filepath.Join(h.baseDir, filename)
	ownership, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		return
	}
	if err := removeSubscriptionFileIfOwned(path, ownership); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
}

func buildRuleFilename(name, ext string) string {
	base := strings.TrimSpace(name)
	if base == "" {
		base = "subscription"
	}
	runes := make([]rune, 0, len(base))
	for _, r := range base {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			runes = append(runes, r)
		case unicode.IsSpace(r):
			runes = append(runes, '-')
		case r == '-' || r == '_':
			runes = append(runes, r)
		}
	}
	if len(runes) == 0 {
		runes = []rune("subscription")
	}
	base = strings.Trim(strings.ToLower(string(runes)), "-")
	if base == "" {
		base = "subscription"
	}

	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%s-%d%s", base, timestamp, ext)
}

func fileHeader(headers []*multipart.FileHeader) (*multipart.FileHeader, error) {
	if len(headers) == 0 {
		return nil, errors.New("no file")
	}
	return headers[0], nil
}

func firstValue(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return values[0]
}

type subscriptionDTO struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Description  string    `json:"description"`
	RuleFilename string    `json:"rule_filename"`
	Buttons      []string  `json:"buttons"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func convertSubscription(link storage.SubscriptionLink) subscriptionDTO {
	return subscriptionDTO{
		ID:           link.ID,
		Name:         link.Name,
		Type:         link.Type,
		Description:  link.Description,
		RuleFilename: link.RuleFilename,
		Buttons:      append([]string(nil), link.Buttons...),
		CreatedAt:    link.CreatedAt,
		UpdatedAt:    link.UpdatedAt,
	}
}

func convertSubscriptions(links []storage.SubscriptionLink) []subscriptionDTO {
	result := make([]subscriptionDTO, 0, len(links))
	for _, link := range links {
		result = append(result, convertSubscription(link))
	}
	return result
}

// NewSubscriptionListHandler 为经过身份验证的用户返回可公开访问的订阅元数据。
// 对于管理员用户，返回所有订阅。对于普通用户，仅返回分配给他们的订阅。
func NewSubscriptionListHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("subscription list handler requires repository")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}

		// 从上下文中获取用户名
		username := auth.UsernameFromContext(r.Context())
		if username == "" {
			writeError(w, http.StatusUnauthorized, errors.New("username not found in context"))
			return
		}

		// 让用户检查角色
		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		var files []storage.SubscribeFile

		// 管理员用户可以查看所有订阅
		if user.Role == storage.RoleAdmin {
			files, err = repo.ListSubscribeFiles(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		} else {
			// 普通用户只能看到分配给他们的订阅
			files, err = repo.GetUserSubscriptions(r.Context(), username)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}

			// 用户无手动分配的订阅但有套餐时，返回虚拟套餐订阅条目
			if len(files) == 0 && user.PackageID > 0 {
				if pkg, pkgErr := repo.GetPackage(r.Context(), user.PackageID); pkgErr == nil {
					files = []storage.SubscribeFile{{
						ID:            -1,
						Name:          pkg.Name,
						Description:   pkg.Description,
						Type:          "package",
						Filename:      "__package__",
						FileShortCode: pkg.ShortCode,
						UpdatedAt:     pkg.UpdatedAt,
					}}
				}
			}

			// 追加用户自己创建的订阅(套餐之外用户手动创建的),否则在订阅链接页面看不到
			seen := make(map[int64]bool, len(files))
			for _, f := range files {
				seen[f.ID] = true
			}
			if own, oerr := repo.ListSubscribeFiles(r.Context()); oerr == nil {
				for _, f := range own {
					if f.CreatedBy == username && !seen[f.ID] {
						files = append(files, f)
						seen[f.ID] = true
					}
				}
			}
		}

		// 从系统设置检查是否全局启用短链接
		systemConfig, sysErr := repo.GetSystemConfig(r.Context())
		enableShortLink := true
		if sysErr == nil {
			enableShortLink = systemConfig.EnableShortLink
		}

		// 仅在启用短链接时获取用户短代码(优先用户自定义短码,否则系统自动短码)。
		// 管理员现在也能编辑自己的 user_short_code(订阅文件 popover 里),所以订阅链接也拼上,
		// 与普通用户一致 = /x/{fileShortCode}{userShortCode}。short_link.go 会先按整 code 找文件,
		// 找不到再按"文件短码+用户短码"分裂,所以拼上 admin 自己的短码不影响"全权访问"语义。
		var userShortCode string
		if enableShortLink {
			userShortCode, err = repo.GetEffectiveUserShortCode(r.Context(), username)
			if err != nil {
				// 如果用户短代码不存在，它将在下次令牌访问时生成
				userShortCode = ""
			}
		}
		_ = user // role 字段不再用于此处的短码逻辑(保留 user 变量供其他地方使用)

		type item struct {
			ID              int64     `json:"id"`
			Name            string    `json:"name"`
			Description     string    `json:"description"`
			Filename        string    `json:"filename"`
			Type            string    `json:"type"`
			CanDelete       bool      `json:"can_delete"`
			FileShortCode   string    `json:"file_short_code,omitempty"`
			CustomShortCode string    `json:"custom_short_code,omitempty"`
			UpdatedAt       time.Time `json:"updated_at"`
			LatestVersion   int64     `json:"latest_version,omitempty"`
		}

		payload := make([]item, 0, len(files))
		for _, file := range files {
			var latestVersion int64
			if versions, err := repo.ListRuleVersions(r.Context(), file.Filename, 1); err == nil && len(versions) > 0 {
				latestVersion = versions[0].Version
			}

			fileShortCode := ""
			customShortCode := ""
			if enableShortLink {
				fileShortCode = file.FileShortCode
				customShortCode = file.CustomShortCode
			}

			payload = append(payload, item{
				ID:              file.ID,
				Name:            file.Name,
				Description:     file.Description,
				Filename:        file.Filename,
				Type:            file.Type,
				CanDelete:       file.ID > 0 && (user.Role == storage.RoleAdmin || file.CreatedBy == username),
				FileShortCode:   fileShortCode,
				CustomShortCode: customShortCode,
				UpdatedAt:       file.UpdatedAt,
				LatestVersion:   latestVersion,
			})
		}

		respondJSON(w, http.StatusOK, map[string]any{
			"subscriptions":   payload,
			"user_short_code": userShortCode,
		})
	})
}
