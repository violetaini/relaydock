package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"miaomiaowux/internal/auth"
	"miaomiaowux/internal/storage"
)

type RuleTemplatesHandler struct {
	repo *storage.TrafficRepository
}

func NewRuleTemplatesHandler(repo *storage.TrafficRepository) *RuleTemplatesHandler {
	return &RuleTemplatesHandler{repo: repo}
}

// canModifyRuleTemplate 判断当前用户能否修改/删除指定模板:
// 管理员任意;普通用户仅限自己上传的(归属为空的历史模板视为管理员所有,普通用户不可动)。
func (h *RuleTemplatesHandler) canModifyRuleTemplate(r *http.Request, filename string) bool {
	username := auth.UsernameFromContext(r.Context())
	if h.repo == nil {
		return true
	}
	if userIsAdmin(r.Context(), h.repo, username) {
		return true
	}
	owner, _ := h.repo.GetRuleTemplateOwner(r.Context(), filename)
	return owner != "" && owner == username
}

const (
	ruleTemplateMaxCount    = 200     // rule_templates 目录最多文件数
	ruleTemplateMaxFileSize = 2 << 20 // 单个模板文件最大 2MB
)

// countRuleTemplates 统计 rule_templates 目录下的模板文件数量。
func countRuleTemplates(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			n++
		}
	}
	return n
}

func (h *RuleTemplatesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 删除 /api/rule-templates 前缀
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/rule-templates")

	switch {
	case path == "" || path == "/":
		// 列出模板
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleListTemplates(w, r)
	case path == "/upload":
		// 上传模板
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleUploadTemplate(w, r)
	case path == "/rename":
		// 重命名模板
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleRenameTemplate(w, r)
	default:
		// 从路径中提取模板名称（删除前导斜杠）
		templateName := strings.TrimPrefix(path, "/")

		switch r.Method {
		case http.MethodGet:
			// 获取具体模板内容(所有用户可读,用于使用模板)
			h.handleGetTemplate(w, r, templateName)
		case http.MethodPut:
			// 更新模板内容:仅管理员或模板所有者
			if !h.canModifyRuleTemplate(r, templateName) {
				http.Error(w, "无权修改该模板", http.StatusForbidden)
				return
			}
			h.handleUpdateTemplate(w, r, templateName)
		case http.MethodDelete:
			// 删除模板:仅管理员或模板所有者
			if !h.canModifyRuleTemplate(r, templateName) {
				http.Error(w, "无权删除该模板", http.StatusForbidden)
				return
			}
			h.handleDeleteTemplate(w, r, templateName)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (h *RuleTemplatesHandler) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	templatesDir := "rule_templates"

	// 读取目录
	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		http.Error(w, "Failed to read templates directory", http.StatusInternalServerError)
		return
	}

	// 过滤 YAML 文件
	var templates []string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			templates = append(templates, entry.Name())
		}
	}

	// 归属信息(供前端控制"删除/修改仅自己的"),并附带当前用户名与是否管理员。
	allOwners, _ := h.repo.ListRuleTemplateOwners(r.Context())
	username := auth.UsernameFromContext(r.Context())
	isAdmin := userIsAdmin(r.Context(), h.repo, username)

	// 数据隔离:
	//   - admin → 全部归属信息原样返回(管理需要)
	//   - 非 admin → templates 里隐藏"别人私有的模板文件",owners 只保留自己的归属信息
	//     (防止普通用户从该接口枚举其它用户名)
	visibleTemplates := templates
	visibleOwners := allOwners
	if !isAdmin {
		visibleOwners = make(map[string]string, 1)
		filtered := make([]string, 0, len(templates))
		for _, fn := range templates {
			owner, hasOwner := allOwners[fn]
			if !hasOwner {
				// 无归属记录 = 内置/公共模板,所有人可见
				filtered = append(filtered, fn)
				continue
			}
			if owner == username {
				// 自己的私有模板:保留 + 暴露归属(给前端显示"可编辑/删除")
				filtered = append(filtered, fn)
				visibleOwners[fn] = owner
			}
			// 其它人的私有模板:对当前用户彻底隐藏
		}
		visibleTemplates = filtered
	}

	// 返回 JSON 响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"templates": visibleTemplates,
		"owners":    visibleOwners,
		"username":  username,
		"is_admin":  isAdmin,
	})
}

func (h *RuleTemplatesHandler) handleGetTemplate(w http.ResponseWriter, r *http.Request, templateName string) {
	// 安全性：防止目录遍历
	if strings.Contains(templateName, "..") || strings.Contains(templateName, "/") || strings.Contains(templateName, "\\") {
		http.Error(w, "Invalid template name", http.StatusBadRequest)
		return
	}

	templatesDir := "rule_templates"
	templatePath := filepath.Join(templatesDir, templateName)

	// 检查文件是否存在
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	// 读取文件内容
	content, err := os.ReadFile(templatePath)
	if err != nil {
		http.Error(w, "Failed to read template", http.StatusInternalServerError)
		return
	}

	// 返回包含内容的 JSON 响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"content": string(content),
	})
}

func (h *RuleTemplatesHandler) handleUpdateTemplate(w http.ResponseWriter, r *http.Request, templateName string) {
	// 安全性：防止目录遍历
	if strings.Contains(templateName, "..") || strings.Contains(templateName, "/") || strings.Contains(templateName, "\\") {
		http.Error(w, "Invalid template name", http.StatusBadRequest)
		return
	}

	templatesDir := "rule_templates"
	templatePath := filepath.Join(templatesDir, templateName)

	// 检查文件是否存在
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "模板文件不存在",
		})
		return
	}

	// 解析请求体
	var payload struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 单文件大小上限
	if len(payload.Content) > ruleTemplateMaxFileSize {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("模板内容过大,不能超过 %dMB", ruleTemplateMaxFileSize>>20),
		})
		return
	}
	if err := validateRuleTemplateSecrets(payload.Content); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}

	// 将内容写入文件
	if err := os.WriteFile(templatePath, []byte(payload.Content), 0644); err != nil {
		http.Error(w, "Failed to save template", http.StatusInternalServerError)
		return
	}

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "模板保存成功",
	})
}

func (h *RuleTemplatesHandler) handleDeleteTemplate(w http.ResponseWriter, r *http.Request, templateName string) {
	// 安全性：防止目录遍历
	if strings.Contains(templateName, "..") || strings.Contains(templateName, "/") || strings.Contains(templateName, "\\") {
		http.Error(w, "Invalid template name", http.StatusBadRequest)
		return
	}
	if h.repo != nil {
		cfg, err := h.repo.GetSystemConfig(r.Context())
		if err != nil {
			http.Error(w, "读取默认模板设置失败", http.StatusInternalServerError)
			return
		}
		if cfg.DefaultTemplateFilename == templateName {
			http.Error(w, "默认模板不能删除，请先更换默认模板", http.StatusConflict)
			return
		}
	}

	templatesDir := "rule_templates"
	templatePath := filepath.Join(templatesDir, templateName)

	// 检查文件是否存在
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "模板文件不存在",
		})
		return
	}

	// 删除文件
	if err := os.Remove(templatePath); err != nil {
		http.Error(w, "Failed to delete template", http.StatusInternalServerError)
		return
	}
	_ = h.repo.DeleteRuleTemplateOwner(r.Context(), templateName)

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "模板删除成功",
	})
}

func (h *RuleTemplatesHandler) handleRenameTemplate(w http.ResponseWriter, r *http.Request) {
	// 解析请求体
	var payload struct {
		OldName string `json:"old_name"`
		NewName string `json:"new_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	oldName := strings.TrimSpace(payload.OldName)
	newName := strings.TrimSpace(payload.NewName)

	// 验证姓名
	if oldName == "" || newName == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "文件名不能为空",
		})
		return
	}

	// 安全性：防止目录遍历
	if strings.Contains(oldName, "..") || strings.Contains(oldName, "/") || strings.Contains(oldName, "\\") ||
		strings.Contains(newName, "..") || strings.Contains(newName, "/") || strings.Contains(newName, "\\") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// 确保新名称具有 .yaml 或 .yml 扩展名
	if !strings.HasSuffix(newName, ".yaml") && !strings.HasSuffix(newName, ".yml") {
		newName = newName + ".yaml"
	}

	if h.repo != nil {
		cfg, err := h.repo.GetSystemConfig(r.Context())
		if err != nil {
			http.Error(w, "读取默认模板设置失败", http.StatusInternalServerError)
			return
		}
		if cfg.DefaultTemplateFilename == oldName {
			http.Error(w, "默认模板不能重命名，请先更换默认模板", http.StatusConflict)
			return
		}
	}
	// 默认模板保护优先于归属判断，确保所有调用方都得到明确且一致的冲突语义。
	if !h.canModifyRuleTemplate(r, oldName) {
		http.Error(w, "无权重命名该模板", http.StatusForbidden)
		return
	}

	templatesDir := "rule_templates"
	oldPath := filepath.Join(templatesDir, oldName)
	newPath := filepath.Join(templatesDir, newName)

	// 检查旧文件是否存在
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "原文件不存在",
		})
		return
	}

	// 检查新文件是否已存在
	if _, err := os.Stat(newPath); err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "目标文件名已存在",
		})
		return
	}

	// 重命名文件
	if err := os.Rename(oldPath, newPath); err != nil {
		http.Error(w, "Failed to rename template", http.StatusInternalServerError)
		return
	}
	_ = h.repo.RenameRuleTemplateOwner(r.Context(), oldName, newName)

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "模板重命名成功",
		"filename": newName,
	})
}

func (h *RuleTemplatesHandler) handleUploadTemplate(w http.ResponseWriter, r *http.Request) {
	// 解析多部分表单（限制为 10MB）
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// 从表单中获取文件
	file, header, err := r.FormFile("template")
	if err != nil {
		http.Error(w, "Failed to get file from request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 验证文件扩展名
	filename := header.Filename
	if !strings.HasSuffix(filename, ".yaml") && !strings.HasSuffix(filename, ".yml") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "只支持 .yaml 或 .yml 文件",
		})
		return
	}

	// 单文件大小上限
	if header.Size > ruleTemplateMaxFileSize {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("模板文件过大,单文件不能超过 %dMB", ruleTemplateMaxFileSize>>20),
		})
		return
	}

	// 安全性：清理文件名
	filename = filepath.Base(filename)
	if strings.Contains(filename, "..") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// 如果不存在则创建模板目录
	templatesDir := "rule_templates"
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		http.Error(w, "Failed to create templates directory", http.StatusInternalServerError)
		return
	}

	// 数量上限
	if countRuleTemplates(templatesDir) >= ruleTemplateMaxCount {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("模板数量已达上限 (%d)", ruleTemplateMaxCount),
		})
		return
	}

	// 创建目标文件
	templatePath := filepath.Join(templatesDir, filename)

	// 检查文件是否已经存在
	if _, err := os.Stat(templatePath); err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("模板文件 %s 已存在", filename),
		})
		return
	}

	// 读取文件内容(限制大小,防止 multipart 头部声明不实)
	content, err := io.ReadAll(io.LimitReader(file, ruleTemplateMaxFileSize+1))
	if err != nil {
		http.Error(w, "Failed to read template file", http.StatusInternalServerError)
		return
	}
	if len(content) > ruleTemplateMaxFileSize {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("模板文件过大,单文件不能超过 %dMB", ruleTemplateMaxFileSize>>20),
		})
		return
	}
	if err := validateRuleTemplateSecrets(string(content)); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	if err := os.WriteFile(templatePath, content, 0644); err != nil {
		http.Error(w, "Failed to save template file", http.StatusInternalServerError)
		return
	}

	// 记录归属(普通用户上传 → 该用户;管理员上传 → 管理员用户名)
	_ = h.repo.SetRuleTemplateOwner(r.Context(), filename, auth.UsernameFromContext(r.Context()))

	// 返回带有文件名的成功响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"filename": filename,
		"message":  "模板上传成功",
	})
}

func validateRuleTemplateSecrets(content string) error {
	root, sources, err := wireGuardProxyPrivateKeySources(content)
	if err != nil {
		return fmt.Errorf("模板 YAML 无效: %w", err)
	}
	if len(sources) > 0 || len(scalarNodesWithPrefix(root, wireGuardSubscriptionSecretPrefix)) > 0 {
		return fmt.Errorf("规则模板不能保存 WireGuard 客户端私钥，请在节点管理中创建节点")
	}
	if err := ensureNoUnprotectedPrivateKeyFields(root); err != nil {
		return fmt.Errorf("规则模板不能保存 WireGuard 客户端私钥，请在节点管理中创建节点: %w", err)
	}
	return nil
}

// ValidatePersistedRuleTemplateSecrets fails startup when an existing template
// contains a WireGuard client identity. Templates are reusable policy, not a
// node-secret container, so encrypting a historical key in place would preserve
// an unsafe and ambiguous template meaning. Operators must remove the identity
// from the named template before the panel serves requests again.
func ValidatePersistedRuleTemplateSecrets(templatesDir string) error {
	templatesDir = filepath.Clean(strings.TrimSpace(templatesDir))
	if templatesDir == "" || templatesDir == "." {
		return errors.New("规则模板目录不能为空")
	}
	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		return fmt.Errorf("读取规则模板目录失败: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		lowerName := strings.ToLower(name)
		if !strings.HasSuffix(lowerName, ".yaml") && !strings.HasSuffix(lowerName, ".yml") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("规则模板 %s 必须是普通文件，禁止符号链接", name)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("读取规则模板 %s 信息失败: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("规则模板 %s 必须是普通文件", name)
		}
		if info.Size() > ruleTemplateMaxFileSize {
			return fmt.Errorf("规则模板 %s 超过 %dMB 上限", name, ruleTemplateMaxFileSize>>20)
		}
		content, err := os.ReadFile(filepath.Join(templatesDir, name))
		if err != nil {
			return fmt.Errorf("读取规则模板 %s 失败: %w", name, err)
		}
		if err := validateRuleTemplateSecrets(string(content)); err != nil {
			return fmt.Errorf("规则模板 %s 含有禁止的客户端身份，面板已拒绝启动: %w", name, err)
		}
	}
	return nil
}
