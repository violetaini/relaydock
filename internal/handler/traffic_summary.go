package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/storage"
)

const bytesPerGigabyte = 1073741824.0

type TrafficSummaryHandler struct {
	client *http.Client
	repo   *storage.TrafficRepository
}

type trafficSummaryResponse struct {
	Metrics trafficSummaryMetrics `json:"metrics"`
	History []trafficDailyUsage   `json:"history"`
}

type trafficSummaryMetrics struct {
	TotalLimitGB     float64 `json:"total_limit_gb"`
	TotalUsedGB      float64 `json:"total_used_gb"`
	TotalRemainingGB float64 `json:"total_remaining_gb"`
	UsagePercentage  float64 `json:"usage_percentage"`
	// UnlimitedUsedGB 仅管理员视角:不限流量服务器(traffic_limit=0)的已用流量合计,
	// 不计入上面的百分比;前端在"已用流量"旁用图标 hover 展示。
	UnlimitedUsedGB float64 `json:"unlimited_used_gb"`
}

type trafficDailyUsage struct {
	Date   string  `json:"date"`
	UsedGB float64 `json:"used_gb"`
}

func NewTrafficSummaryHandler(repo *storage.TrafficRepository) *TrafficSummaryHandler {
	if repo == nil {
		panic("traffic summary handler requires repository")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	return newTrafficSummaryHandler(client, repo)
}

func newTrafficSummaryHandler(client *http.Client, repo *storage.TrafficRepository) *TrafficSummaryHandler {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	return &TrafficSummaryHandler{client: client, repo: repo}
}

func (h *TrafficSummaryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("only GET is supported"))
		return
	}

	ctx := r.Context()
	username := auth.UsernameFromContext(ctx)

	var user storage.User
	haveUser := false
	if username != "" && h.repo != nil {
		if u, err := h.repo.GetUser(ctx, username); err == nil {
			user = u
			haveUser = true
		}
	}
	isAdmin := haveUser && user.Role == storage.RoleAdmin

	var totalLimit, totalUsed, unlimitedUsed int64
	// serverListOK 跟踪 ListRemoteServers 是否成功 — 后面 recordSnapshot 用它兜底,
	// 防止"DB 临时报错 → 全 0 → ON CONFLICT 覆盖正确历史"事故(实际 2026-05-31 已发生)。
	serverListOK := false

	if isAdmin {
		// 管理员:汇总所有服务器(含主控本机,它也是 remote_servers 一行)。
		// 限流服务器(traffic_limit>0)计入 已用/限额;不限流量服务器(=0)的已用单独汇总,
		// 前端在"已用流量"旁用图标 hover 展示,不计入百分比(否则分母没有限额会失真)。
		if servers, err := h.repo.ListRemoteServers(ctx); err == nil {
			serverListOK = true
			for _, s := range servers {
				aggregated, _ := h.repo.GetServerTrafficUsed(ctx, s.ID)
				used := aggregated + s.TrafficUsedOffset
				if s.TrafficLimit > 0 {
					totalLimit += s.TrafficLimit
					totalUsed += used
				} else {
					unlimitedUsed += used
				}
			}
		} else {
			logger.Warn("[流量] ListRemoteServers 失败,跳过本次快照避免覆盖历史", "error", err)
		}
		// 外部订阅流量:仅当系统级"外部订阅同步"开关开启时并入。
		if enabled, _ := h.repo.IsSyncTrafficEnabled(ctx); enabled {
			extLimit, extUsed := h.fetchExternalSubscriptionTraffic(ctx, username)
			totalLimit += extLimit
			totalUsed += extUsed
		}
	} else if haveUser {
		// 普通用户:套餐流量。已用按套餐流量倍率(oneway×1 / twoway×2)计费,
		// 与限额判定口径一致(见 traffic_limit_enforcer:已用×TrafficMultiplier 比限额)。
		if user.PackageID > 0 {
			if pkg, perr := h.repo.GetPackage(ctx, user.PackageID); perr == nil {
				totalLimit += resolveTrafficLimitBytes(&user, pkg)
				if raw, terr := h.repo.GetUserTotalTraffic(ctx, username); terr == nil {
					totalUsed += raw * pkg.TrafficMultiplier()
				}
			}
		}
		// 外部订阅(该用户开启 sync_traffic 时)叠加。
		extLimit, extUsed := h.fetchExternalSubscriptionTraffic(ctx, username)
		totalLimit += extLimit
		totalUsed += extUsed
	}

	totalRemaining := totalLimit - totalUsed
	if totalRemaining < 0 {
		totalRemaining = 0
	}

	if isAdmin {
		// 两道守卫,任一命中都跳过 record — 避免污染 traffic_records:
		//   1. serverListOK=false:ListRemoteServers 出错,totalLimit/totalUsed 全 0 是假象不是真实状态
		//   2. totalLimit==0 && totalUsed==0:理论上正常环境不可能(必有 server 配置 traffic_limit),
		//      出现 = 数据异常,写进去会被 ON CONFLICT(date) DO UPDATE 覆盖正确历史
		//      → 前端 loadHistory delta = today - 0 ≈ 全部历史累计,首页图表出 1.9TB 这种诡异数字
		switch {
		case !serverListOK:
			logger.Warn("[流量] 跳过快照: ListRemoteServers 失败,无法判断当前流量")
		case totalLimit == 0 && totalUsed == 0:
			logger.Warn("[流量] 跳过快照: totalLimit/totalUsed 全 0,可能 DB 临时异常")
		default:
			if err := h.recordSnapshot(ctx, totalLimit, totalUsed, totalRemaining); err != nil {
				logger.Info("[流量] 记录快照失败", "error", err)
			}
		}
	} else if haveUser {
		if err := h.repo.RecordUserDaily(ctx, username, time.Now(), totalLimit, totalUsed, totalRemaining); err != nil {
			logger.Info("[流量] 记录用户快照失败", "error", err)
		}
	}

	var history []trafficDailyUsage
	if isAdmin {
		history, _ = h.loadHistory(ctx, 30)
	} else if username != "" {
		history, _ = h.loadUserHistory(ctx, username, 30)
	}

	metrics := trafficSummaryMetrics{
		TotalLimitGB:     roundUpTwoDecimals(bytesToGigabytes(totalLimit)),
		TotalUsedGB:      roundUpTwoDecimals(bytesToGigabytes(totalUsed)),
		TotalRemainingGB: roundUpTwoDecimals(bytesToGigabytes(totalRemaining)),
		UsagePercentage:  roundUpTwoDecimals(usagePercentage(totalUsed, totalLimit)),
		UnlimitedUsedGB:  roundUpTwoDecimals(bytesToGigabytes(unlimitedUsed)),
	}

	response := trafficSummaryResponse{
		Metrics: metrics,
		History: history,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// 获取最新的流量摘要并保留快照。
func (h *TrafficSummaryHandler) RecordDailyUsage(ctx context.Context) error {
	var totalLimit, totalRemaining, totalUsed int64

	// **聚合所有 remote servers 流量**(老 bug:这块完全没算,只算 external 订阅 → 写 0 进 db
	// → 每日趋势图除了少数几天有 external 数据外全是 0,显示成大尖峰加 flat line)。
	// 算法跟 BuildSummary admin 分支一致:aggregated + offset,限流的计入,不限流的丢弃。
	// ListRemoteServers 失败时 skip 整个写入,避免 ON CONFLICT 覆盖正确历史。
	serverListOK := false
	if h.repo != nil {
		if servers, err := h.repo.ListRemoteServers(ctx); err == nil {
			serverListOK = true
			for _, s := range servers {
				aggregated, _ := h.repo.GetServerTrafficUsed(ctx, s.ID)
				used := aggregated + s.TrafficUsedOffset
				if used < 0 {
					used = 0 // offset 设过头时兜底,防止负值拉低总数
				}
				if s.TrafficLimit > 0 {
					totalLimit += s.TrafficLimit
					totalUsed += used
				}
				// 不限流服务器不计入 totalLimit / totalUsed(同 BuildSummary 行为)
			}
		} else {
			logger.Warn("[流量记录] ListRemoteServers 失败,跳过本次快照避免覆盖历史", "error", err)
		}
	}

	// 同步并添加外部订阅流量(系统级 sync_traffic 开关开时才有数据)
	externalLimit, externalUsed := h.syncAndFetchExternalSubscriptionTraffic(ctx)
	if externalLimit > 0 || externalUsed > 0 {
		totalLimit += externalLimit
		totalUsed += externalUsed
		logger.Info("[流量记录] 外部订阅流量",
			"limit_gb", bytesToGigabytes(externalLimit),
			"used_gb", bytesToGigabytes(externalUsed))
	}

	totalRemaining = totalLimit - totalUsed
	if totalRemaining < 0 {
		totalRemaining = 0
	}

	// 守卫:ListRemoteServers 失败 / 没数据时不写入,避免 ON CONFLICT(date) 把已有正确历史覆盖成 0。
	// 跟 BuildSummary admin 守卫一致。
	switch {
	case !serverListOK:
		logger.Warn("[流量记录] 跳过快照: ListRemoteServers 失败,无法判断当前流量")
		return nil
	case totalLimit == 0 && totalUsed == 0:
		logger.Warn("[流量记录] 跳过快照: totalLimit/totalUsed 全 0,可能 DB 临时异常")
		return nil
	}

	logger.Info("[流量记录] 总计流量",
		"limit_gb", roundUpTwoDecimals(bytesToGigabytes(totalLimit)),
		"used_gb", roundUpTwoDecimals(bytesToGigabytes(totalUsed)),
		"remaining_gb", roundUpTwoDecimals(bytesToGigabytes(totalRemaining)),
		"usage_percent", roundUpTwoDecimals(usagePercentage(totalUsed, totalLimit)))

	if err := h.recordSnapshot(ctx, totalLimit, totalUsed, totalRemaining); err != nil {
		logger.Error("[流量记录] 保存快照到数据库失败", "error", err)
		return err
	}

	logger.Info("[流量记录] 快照已成功保存到数据库")
	return nil
}

// 启用sync_traffic（系统级设置）时，syncAndFetchExternalSubscriptionTraffic 会同步来自外部订阅的流量信息
// 返回未过期订阅的totalLimit 和totalUsed
func (h *TrafficSummaryHandler) syncAndFetchExternalSubscriptionTraffic(ctx context.Context) (int64, int64) {
	if h.repo == nil {
		return 0, 0
	}

	// 检查sync_traffic是否启用（系统级设置）
	enabled, err := h.repo.IsSyncTrafficEnabled(ctx)
	if err != nil {
		logger.Warn("[流量记录] 检查sync_traffic设置失败", "error", err)
		return 0, 0
	}

	if !enabled {
		logger.Info("[流量记录] sync_traffic未启用，跳过外部订阅同步")
		return 0, 0
	}

	// 获取所有用户的所有外部订阅
	subs, err := h.repo.ListAllExternalSubscriptions(ctx)
	if err != nil {
		logger.Warn("[流量记录] 获取外部订阅失败", "error", err)
		return 0, 0
	}

	if len(subs) == 0 {
		logger.Info("[Traffic Record] No external subscriptions found")
		return 0, 0
	}

	logger.Info("[流量记录] 同步外部订阅", "count", len(subs))

	var totalLimit, totalUsed int64
	now := time.Now()

	for _, sub := range subs {
		// 从订阅 URL 获取并更新流量信息
		updatedSub, err := h.fetchExternalSubscriptionTrafficInfo(ctx, sub)
		if err != nil {
			logger.Info("[流量记录] 获取订阅流量失败", "name", sub.Name, "error", err)
			// 如果获取失败，则使用现有数据
			updatedSub = sub
		} else {
			// 更新数据库中的订阅
			if updateErr := h.repo.UpdateExternalSubscription(ctx, updatedSub); updateErr != nil {
				logger.Info("[流量记录] 更新订阅失败", "name", sub.Name, "error", updateErr)
			}
		}

		// 跳过过期的订阅
		if updatedSub.Expire != nil && updatedSub.Expire.Before(now) {
			logger.Info("[流量记录] 跳过已过期订阅", "name", updatedSub.Name, "expired_at", updatedSub.Expire.Format("2006-01-02 15:04:05"))
			continue
		}

		// 添加来自此订阅的流量
		totalLimit += updatedSub.Total
		totalUsed += updatedSub.Upload + updatedSub.Download

		if updatedSub.Expire == nil {
			logger.Info("[流量记录] 添加长期订阅流量",
				"name", updatedSub.Name,
				"limit_gb", bytesToGigabytes(updatedSub.Total),
				"used_gb", bytesToGigabytes(updatedSub.Upload+updatedSub.Download))
		} else {
			logger.Info("[流量记录] 添加订阅流量",
				"name", updatedSub.Name,
				"limit_gb", bytesToGigabytes(updatedSub.Total),
				"used_gb", bytesToGigabytes(updatedSub.Upload+updatedSub.Download),
				"expires", updatedSub.Expire.Format("2006-01-02 15:04:05"))
		}
	}

	logger.Info("[流量记录] 外部订阅流量总计",
		"limit_gb", bytesToGigabytes(totalLimit),
		"used_gb", bytesToGigabytes(totalUsed))

	return totalLimit, totalUsed
}

// 从外部订阅 URL 获取流量信息
func (h *TrafficSummaryHandler) fetchExternalSubscriptionTrafficInfo(ctx context.Context, sub storage.ExternalSubscription) (storage.ExternalSubscription, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return sub, fmt.Errorf("create request: %w", err)
	}

	userAgent := sub.UserAgent
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := h.client.Do(req)
	if err != nil {
		return sub, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return sub, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析订阅用户信息标头
	userInfo := resp.Header.Get("subscription-userinfo")
	if userInfo == "" {
		return sub, nil // 没有可用的交通信息
	}

	// 解析交通信息
	upload, download, total, expire := ParseTrafficInfoHeader(userInfo)

	sub.Upload = upload
	sub.Download = download
	sub.Total = total
	sub.Expire = expire

	logger.Info("[流量记录] 解析流量信息",
		"name", sub.Name,
		"upload_mb", float64(upload)/(1024*1024),
		"download_mb", float64(download)/(1024*1024),
		"total_gb", float64(total)/(1024*1024*1024))

	return sub, nil
}

func roundUpTwoDecimals(value float64) float64 {
	return math.Ceil(value*100) / 100
}

func bytesToGigabytes(total int64) float64 {
	if total <= 0 {
		return 0
	}

	return float64(total) / bytesPerGigabyte
}

func usagePercentage(used, limit int64) float64 {
	if limit <= 0 {
		return 0
	}

	return (float64(used) / float64(limit)) * 100
}

func (h *TrafficSummaryHandler) recordSnapshot(ctx context.Context, totalLimit, totalUsed, totalRemaining int64) error {
	if h.repo == nil {
		return nil
	}

	return h.repo.RecordDaily(ctx, time.Now(), totalLimit, totalUsed, totalRemaining)
}

func (h *TrafficSummaryHandler) loadHistory(ctx context.Context, days int) ([]trafficDailyUsage, error) {
	if h.repo == nil {
		return nil, nil
	}

	records, err := h.repo.ListRecent(ctx, days)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, nil
	}

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Date.Before(records[j].Date)
	})

	usages := make([]trafficDailyUsage, 0, len(records))
	var prevUsed int64
	var hasPrev bool

	for _, record := range records {
		delta := record.TotalUsed
		if hasPrev {
			delta = record.TotalUsed - prevUsed
			if delta < 0 {
				delta = 0
			}
		}

		prevUsed = record.TotalUsed
		hasPrev = true

		usages = append(usages, trafficDailyUsage{
			Date:   record.Date.Format("2006-01-02"),
			UsedGB: roundUpTwoDecimals(bytesToGigabytes(delta)),
		})
	}

	return usages, nil
}

func (h *TrafficSummaryHandler) loadUserHistory(ctx context.Context, username string, days int) ([]trafficDailyUsage, error) {
	if h.repo == nil {
		return nil, nil
	}
	records, err := h.repo.ListUserRecent(ctx, username, days)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Date.Before(records[j].Date)
	})
	usages := make([]trafficDailyUsage, 0, len(records))
	var prevUsed int64
	var hasPrev bool
	for _, record := range records {
		delta := record.TotalUsed
		if hasPrev {
			delta = record.TotalUsed - prevUsed
			if delta < 0 {
				delta = 0
			}
		}
		prevUsed = record.TotalUsed
		hasPrev = true
		usages = append(usages, trafficDailyUsage{
			Date:   record.Date.Format("2006-01-02"),
			UsedGB: roundUpTwoDecimals(bytesToGigabytes(delta)),
		})
	}
	return usages, nil
}

// fetchExternalSubscriptionTraffic 从外部订阅中获取订阅文件中实际使用的流量
// 返回未过期订阅（或没有过期日期的长期订阅）的totalLimit和totalUsed
func (h *TrafficSummaryHandler) fetchExternalSubscriptionTraffic(ctx context.Context, username string) (int64, int64) {
	// 检查sync_traffic是否启用
	settings, err := h.repo.GetUserSettings(ctx, username)
	if err != nil || !settings.SyncTraffic {
		return 0, 0
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		logger.Info("[流量] 锁定订阅存储失败", "error", err)
		return 0, 0
	}
	defer unlock()

	subscribeFiles, err := h.repo.ListSubscribeFiles(ctx)
	if err != nil {
		logger.Info("[流量] 获取订阅文件列表失败", "error", err)
		return 0, 0
	}

	// 收集所有订阅文件中使用的所有外部订阅 URL
	usedExternalURLs := make(map[string]bool)
	for _, file := range subscribeFiles {
		if err := storage.ValidateSubscribeFilename(file.Filename); err != nil {
			logger.Info("[流量] 拒绝非法订阅文件名", "filename", file.Filename, "error", err)
			return 0, 0
		}
		// 读取订阅文件内容
		filePath := filepath.Join("subscribes", file.Filename)
		data, err := os.ReadFile(filePath)
		if err != nil {
			logger.Info("[流量] 读取订阅文件失败", "filename", file.Filename, "error", err)
			continue
		}

		// 获取此文件中引用的外部订阅 URL
		fileURLs, err := GetExternalSubscriptionsFromFile(ctx, data, username, h.repo)
		if err != nil {
			logger.Info("[流量] 解析订阅文件失败", "filename", file.Filename, "error", err)
			continue
		}

		// 合并到使用过的 URL
		for url := range fileURLs {
			usedExternalURLs[url] = true
		}
	}

	if len(usedExternalURLs) == 0 {
		logger.Info("[流量] 未找到使用中的外部订阅")
		return 0, 0
	}

	logger.Info("[流量] 找到使用中的外部订阅", "count", len(usedExternalURLs))

	// 获取所有外部订阅
	subs, err := h.repo.ListExternalSubscriptions(ctx, username)
	if err != nil {
		logger.Info("[流量] 获取外部订阅失败", "error", err)
		return 0, 0
	}

	var totalLimit int64
	var totalUsed int64
	now := time.Now()

	for _, sub := range subs {
		// 如果此订阅未在任何订阅文件中使用，则跳过
		if !usedExternalURLs[sub.URL] {
			continue
		}

		// 如果订阅已过期则跳过
		// 如果 Expire 为 nil，则为长期订阅，不应跳过
		if sub.Expire != nil && sub.Expire.Before(now) {
			logger.Info("[流量] 跳过已过期订阅", "name", sub.Name, "expired_at", sub.Expire.Format("2006-01-02 15:04:05"))
			continue
		}

		// 添加来自此订阅的流量
		totalLimit += sub.Total
		totalUsed += sub.Upload + sub.Download

		if sub.Expire == nil {
			logger.Info("[流量] 添加长期订阅流量", "name", sub.Name, "limit", sub.Total, "used", sub.Upload+sub.Download)
		} else {
			logger.Info("[流量] 添加订阅流量",
				"name", sub.Name,
				"limit", sub.Total,
				"used", sub.Upload+sub.Download,
				"expires", sub.Expire.Format("2006-01-02 15:04:05"))
		}
	}

	logger.Info("[流量] 外部订阅流量总计", "limit", totalLimit, "used", totalUsed)
	return totalLimit, totalUsed
}
