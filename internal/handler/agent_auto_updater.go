package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// StartAgentAutoUpdater 启动 Agent 后台自动平滑升级检查任务。
// 对标记了 auto_update_agent=true 的已连接服务器，周期性检查 GitHub Release，
// 当检测到新版本时在后台自动执行升级。
func StartAgentAutoUpdater(ctx context.Context, vh *AgentVersionHandler, rm *RemoteManageHandler, repo *storage.TrafficRepository) {
	if vh == nil || rm == nil || repo == nil {
		return
	}

	// 启动后先等待 2 分钟，让主控与各 Agent 完成握手建立稳定连接
	initialTimer := time.NewTimer(2 * time.Minute)
	defer initialTimer.Stop()

	runCheck := func() {
		latest, latestErr := vh.fetchLatest(ctx)
		if latest == "" || latestErr != "" {
			return
		}

		servers, err := repo.ListRemoteServers(ctx)
		if err != nil {
			return
		}

		for _, s := range servers {
			// 仅针对开启了自动更新、状态为 connected、且非联邦分享的受管服务器
			if !s.AutoUpdateAgent || s.Status != storage.RemoteServerStatusConnected || s.IsFederated {
				continue
			}

			current, _ := vh.fetchAgentCurrent(ctx, s.ID)
			if isUpgradeAvailable(current, latest) {
				log.Printf("[Agent Auto-Update] Server %d (%s) has newer agent available (current: %q, latest: %q); starting auto-update", s.ID, s.Name, current, latest)

				// 构造升级请求并执行
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("/api/admin/remote/agent/upgrade-stream?server_id=%d", s.ID), nil)
				rec := httptest.NewRecorder()
				rm.forwardUpgradeStream(rec, req, s.ID)

				log.Printf("[Agent Auto-Update] Server %d (%s) auto-update finished with code %d", s.ID, s.Name, rec.Code)
			}
		}
	}

	select {
	case <-ctx.Done():
		return
	case <-initialTimer.C:
		runCheck()
	}

	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCheck()
		}
	}
}
