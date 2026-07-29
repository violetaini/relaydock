package handler

import (
	"encoding/json"
	"net/http"

	"github.com/violetaini/relaydock/internal/storage"
)

// ProbePublicHandler 提供"伪装成探针"的公开(无鉴权)只读服务器状态。
// 安全红线:只序列化下方白名单字段,绝不返回 IP / token / host / inbound 等敏感信息。
type ProbePublicHandler struct {
	repo      *storage.TrafficRepository
	wsHandler *RemoteWSHandler
}

func NewProbePublicHandler(repo *storage.TrafficRepository, ws *RemoteWSHandler) *ProbePublicHandler {
	return &ProbePublicHandler{repo: repo, wsHandler: ws}
}

// probeServer 是对外暴露的白名单字段集合(刻意不含 id/ip/token/host/reset_day 等)。
type probeServer struct {
	Name          string `json:"name,omitempty"` // show_name 关闭时省略
	UploadSpeed   int64  `json:"upload_speed"`   // B/s
	DownloadSpeed int64  `json:"download_speed"` // B/s
	TrafficUsed   int64  `json:"traffic_used"`
	TrafficLimit  int64  `json:"traffic_limit"`
	Online        bool   `json:"online"`
}

// ServeHTTP 处理 GET /api/public/probe-servers(无鉴权)。
// 伪装未开启 → {enabled:false};开启 → {enabled:true, title, show_name, servers:[白名单]}。
func (h *ProbePublicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")

	if v, _ := h.repo.GetSystemSetting(ctx, probeDisguiseEnabledKey); v != "1" {
		json.NewEncoder(w).Encode(map[string]any{"enabled": false})
		return
	}

	title, _ := h.repo.GetSystemSetting(ctx, probeDisguiseTitleKey)
	showName := func() bool { v, _ := h.repo.GetSystemSetting(ctx, probeDisguiseShowNameKey); return v == "1" }()

	idSet := map[int64]bool{}
	if raw, _ := h.repo.GetSystemSetting(ctx, probeDisguiseServerIDsKey); raw != "" {
		var ids []int64
		if json.Unmarshal([]byte(raw), &ids) == nil {
			for _, id := range ids {
				idSet[id] = true
			}
		}
	}

	servers, _ := h.repo.ListRemoteServers(ctx)
	out := make([]probeServer, 0, len(idSet))
	for i := range servers {
		s := &servers[i]
		if !idSet[s.ID] {
			continue
		}
		used, _ := h.repo.GetServerTrafficUsed(ctx, s.ID)
		used += s.TrafficUsedOffset
		online := (h.wsHandler != nil && h.wsHandler.IsConnected(s.Token)) || s.Status == "connected"
		ps := probeServer{
			UploadSpeed:   s.CurrentUploadSpeed,
			DownloadSpeed: s.CurrentDownloadSpeed,
			TrafficUsed:   used,
			TrafficLimit:  s.TrafficLimit,
			Online:        online,
		}
		if showName {
			ps.Name = s.Name
		}
		out = append(out, ps)
	}

	json.NewEncoder(w).Encode(map[string]any{
		"enabled":   true,
		"title":     title,
		"show_name": showName,
		"servers":   out,
	})
}
