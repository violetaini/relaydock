package handler

import (
	"net/http"

	"github.com/violetaini/relaydock/internal/storage"
)

type subscribeFilesListHandler struct {
	repo *storage.TrafficRepository
}

// 返回一个用于列出订阅文件的处理程序（对于所有经过身份验证的用户）。
func NewSubscribeFilesListHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("subscribe files list handler requires repository")
	}

	return &subscribeFilesListHandler{
		repo: repo,
	}
}

func (h *subscribeFilesListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	files, err := h.repo.ListSubscribeFiles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	result := convertSubscribeFiles(files)

	respondJSON(w, http.StatusOK, map[string]any{
		"files": result,
	})
}
