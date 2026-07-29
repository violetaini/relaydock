package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

// AgentVersionHandler 给前端用:
//   - 取目标服务器 agent 上报的当前版本
//   - 取 GitHub 最新 release tag(全局缓存 1 小时)
//   - 比对后返回 upgrade_available
//
// 一个端点搞定两件事,前端单次调用即可在每个服务器卡片旁渲染"版本 + 红点"。
type AgentVersionHandler struct {
	rm   *RemoteManageHandler
	repo *storage.TrafficRepository

	latestMu      sync.Mutex
	latestVersion string    // 形如 "0.1.1"(去掉 GitHub tag 前缀 'v')
	latestFetched time.Time // 最近一次成功拉取时间
	latestErr     string    // 最近一次失败原因(显示用,不阻塞)
}

func NewAgentVersionHandler(rm *RemoteManageHandler, repo *storage.TrafficRepository) *AgentVersionHandler {
	return &AgentVersionHandler{rm: rm, repo: repo}
}

const githubLatestReleaseURL = "https://api.github.com/repos/violetaini/relaydock-agent/releases/latest"

// 缓存 5 分钟 — 之前 1h 太长,刚发新 release UI 要等一小时才更新,期间"升级"按钮
// 会因为 compareSemver(current, staleCachedLatest) ≥ 0 被前端 disable,用户没法点。
// 5min 是开发期 + GitHub API rate limit(60 req/hour 未鉴权)的折中。
const latestCacheTTL = 5 * time.Minute

func (h *AgentVersionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only GET"))
		return
	}
	if !userIsAdmin(r.Context(), h.repo, auth.UsernameFromContext(r.Context())) {
		writeError(w, http.StatusForbidden, errors.New("admin only"))
		return
	}
	sidStr := r.URL.Query().Get("server_id")
	sid, err := strconv.ParseInt(sidStr, 10, 64)
	if err != nil || sid <= 0 {
		writeBadRequest(w, "server_id required")
		return
	}

	current, currentErr := h.fetchAgentCurrent(r.Context(), sid)
	latest, latestErr := h.fetchLatest(r.Context())

	resp := map[string]any{
		"server_id":         sid,
		"current":           current,
		"latest":            latest,
		"upgrade_available": isUpgradeAvailable(current, latest),
	}
	if currentErr != "" {
		resp["current_error"] = currentErr
	}
	if latestErr != "" {
		resp["latest_error"] = latestErr
	}
	// agent 不可达 → 返回 502,前端 react-query 视为 error 不写 data 缓存,
	// server.status 翻回 connected 后组件重新挂载时不会消费 stale "?" cache,自动 refetch。
	// 区分两类失败:
	//   - current 空 + currentErr 非空 → agent 不可达(或转发失败)= 502 BadGateway
	//   - current 空 + currentErr 空   → agent 可达但旧版未上报版本 = 200(保留 "?" 显示让升级提示生效)
	if current == "" && currentErr != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

// fetchAgentCurrent 取目标 agent 的版本号。
// 旧 agent 不返回 agent_version 字段 → 空字符串,前端按"未知版本/需要升级"处理。
func (h *AgentVersionHandler) fetchAgentCurrent(ctx context.Context, serverID int64) (string, string) {
	// WS-first:新 agent 经 auth 上报了 agent_version 就直接用,不反向拉。
	// 端口隐身(HidePortOnWS)关闭入站后反向 HTTP 不可达;旧 agent 不上报则 fallback 反向 HTTP。
	if h.rm.wsHandler != nil {
		if conn, ok := h.rm.wsHandler.GetConnectionByServerID(serverID); ok && conn.AgentVersion != "" {
			return conn.AgentVersion, ""
		}
	}
	// 5s 超时即可,system-info 本来就是轻量 endpoint
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := h.rm.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/system/info", nil)
	if err != nil {
		return "", err.Error()
	}
	var info struct {
		AgentVersion string `json:"agent_version"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", "parse system info: " + err.Error()
	}
	return strings.TrimSpace(info.AgentVersion), ""
}

// fetchLatest 取 GitHub 最新 release 的版本号,带 1 小时缓存。
// 取不到时返回上次缓存值(可能为空)+ 错误信息,不阻塞调用。
func (h *AgentVersionHandler) fetchLatest(ctx context.Context) (string, string) {
	h.latestMu.Lock()
	cached := h.latestVersion
	cachedErr := h.latestErr
	stale := time.Since(h.latestFetched) > latestCacheTTL
	h.latestMu.Unlock()
	if !stale && cached != "" {
		return cached, ""
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, githubLatestReleaseURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.latestMu.Lock()
		h.latestErr = err.Error()
		h.latestMu.Unlock()
		return cached, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := "github status " + strconv.Itoa(resp.StatusCode)
		h.latestMu.Lock()
		h.latestErr = msg
		h.latestMu.Unlock()
		return cached, msg
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return cached, err.Error()
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(raw, &rel); err != nil {
		return cached, "parse: " + err.Error()
	}
	v := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	if v == "" {
		return cached, "empty tag_name"
	}
	h.latestMu.Lock()
	h.latestVersion = v
	h.latestFetched = time.Now()
	h.latestErr = ""
	h.latestMu.Unlock()
	_ = cachedErr
	return v, ""
}

// isUpgradeAvailable 简单语义版本比对(major.minor.patch),非数字段降级到字符串比对。
//
//	current 空        → 视为需要升级(老 agent 不报版本)
//	current == latest → 不需要
//	current < latest  → 需要
//	current > latest  → 不需要(本地比 GitHub 新,通常是开发版)
func isUpgradeAvailable(current, latest string) bool {
	current = strings.TrimSpace(current)
	latest = strings.TrimSpace(latest)
	if latest == "" {
		// 没拉到 GitHub 信息 — 没法判断,默认不报"可升级",避免误导
		return false
	}
	if current == "" {
		return true
	}
	return compareSemver(current, latest) < 0
}

// compareSemver:正数=a>b, 负数=a<b, 0=相等;非数字段走字符串比较。
func compareSemver(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var av, bv string
		if i < len(pa) {
			av = pa[i]
		}
		if i < len(pb) {
			bv = pb[i]
		}
		ai, aerr := strconv.Atoi(av)
		bi, berr := strconv.Atoi(bv)
		if aerr == nil && berr == nil {
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
			continue
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}
