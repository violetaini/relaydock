package handler

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

const managementConnectionMaxAge = 90 * time.Second

type managementConnectionReport struct {
	At     time.Time
	Counts map[string]int64
}

// Keep freshness with the observation, rather than inferring a zero from a
// missing/stale legacy connection map. These snapshots are not billing data.
var managementConnectionReports sync.Map // server ID -> managementConnectionReport

func recordManagementConnections(serverID int64, counts map[string]int64, now time.Time) {
	if counts == nil {
		managementConnectionReports.Delete(serverID)
		return
	}
	copied := make(map[string]int64, len(counts))
	for key, value := range counts {
		if value < 0 {
			managementConnectionReports.Delete(serverID)
			return
		}
		copied[key] = value
	}
	managementConnectionReports.Store(serverID, managementConnectionReport{At: now.UTC(), Counts: copied})
}

type managementActivity struct {
	Connections      *int64     `json:"connections"`
	ActiveNodes      *int       `json:"active_nodes"`
	ReportedAt       *time.Time `json:"reported_at,omitempty"`
	ReportingServers int        `json:"reporting_servers"`
	ExpectedServers  int        `json:"expected_servers"`
	Complete         bool       `json:"complete"`
	MaxAgeSeconds    int        `json:"max_age_seconds"`
}

type managementExpiry struct {
	Kind    string    `json:"kind"`
	ID      int64     `json:"id"`
	Name    string    `json:"name"`
	At      time.Time `json:"at"`
	Days    int       `json:"days"`
	Expired bool      `json:"expired"`
}

type managementAlert struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Message  string `json:"message"`
	Tab      string `json:"tab"`
}

type managementOverview struct {
	QuotaLayers        []managementQuotaLayer    `json:"quota_layers"`
	BilledBytes        int64                     `json:"billed_bytes"`
	Activity           managementActivity        `json:"activity"`
	Expiry             *managementExpiry         `json:"expiry"`
	LimitedResources   int                       `json:"limited_resources"`
	UnlimitedResources int                       `json:"unlimited_resources"`
	NearLimit          int                       `json:"near_limit"`
	OverLimit          int                       `json:"over_limit"`
	Unconfirmed        int                       `json:"unconfirmed"`
	Alerts             []managementAlert         `json:"alerts"`
	TopUsage           []managementResourceUsage `json:"top_usage"`
	BillingResources   int                       `json:"billing_resources"`
}

func managementUserActivity(user storage.User, resources []managementResourceUsage, now time.Time) managementActivity {
	result := managementActivity{MaxAgeSeconds: int(managementConnectionMaxAge.Seconds())}
	servers := map[int64]bool{}
	nodeServers := map[int64]int64{}
	for _, v := range resources {
		if v.ServerID > 0 {
			servers[v.ServerID] = true
			if v.Kind == "node" {
				nodeServers[v.ID] = v.ServerID
			}
		}
	}
	result.ExpectedServers = len(servers)
	connections := int64(0)
	active := map[int64]bool{}
	for id := range servers {
		raw, ok := managementConnectionReports.Load(id)
		if !ok {
			continue
		}
		report, ok := raw.(managementConnectionReport)
		if !ok || now.Sub(report.At) > managementConnectionMaxAge || report.At.After(now.Add(time.Second)) || report.At.Before(user.CreatedAt) {
			continue
		}
		result.ReportingServers++
		if result.ReportedAt == nil || report.At.After(*result.ReportedAt) {
			at := report.At
			result.ReportedAt = &at
		}
		for group, n := range report.Counts {
			split := strings.LastIndex(group, "|")
			if split <= 0 || group[:split] != user.Username || n <= 0 {
				continue
			}
			nodeID, e := strconv.ParseInt(group[split+1:], 10, 64)
			if e != nil || nodeServers[nodeID] != id {
				continue
			}
			connections = subscriptionTrafficAdd(connections, n)
			active[nodeID] = true
		}
	}
	if result.ReportingServers > 0 {
		result.Connections = &connections
		count := len(active)
		result.ActiveNodes = &count
	}
	result.Complete = result.ExpectedServers > 0 && result.ReportingServers == result.ExpectedServers
	return result
}

func buildManagementOverview(user storage.User, billed int64, resources []managementResourceUsage, now time.Time, layers ...managementQuotaLayer) managementOverview {
	out := managementOverview{QuotaLayers: layers, BilledBytes: billed, Activity: managementUserActivity(user, resources, now), Alerts: []managementAlert{}, TopUsage: []managementResourceUsage{}}
	add := func(code, severity string, v managementResourceUsage, text, tab string) {
		out.Alerts = append(out.Alerts, managementAlert{Code: code, Severity: severity, Kind: v.Kind, ID: v.ID, Name: v.Name, Message: text, Tab: tab})
	}
	if !user.IsActive {
		add("account_disabled", "bad", managementResourceUsage{}, "账号已停用，用户无法使用已分配的服务。", "settings")
	}
	var pkgExpiry *managementResourceUsage
	for i := range resources {
		if resources[i].Kind == "package" && resources[i].ExpiresAt != nil {
			pkgExpiry = &resources[i]
			break
		}
	}
	seen := map[string]bool{}
	offline := map[int64]bool{}
	ranked := map[string]bool{}
	var future, past *managementExpiry
	for _, v := range resources {
		key := v.Kind + ":" + strconv.FormatInt(v.ID, 10)
		if seen[key] {
			continue
		}
		seen[key] = true
		if v.State == "unknown" {
			out.Unconfirmed++
		}
		if v.Kind == "node" || v.Kind == "server" || v.Kind == "forwarding" || v.Kind == "package" && v.Limit > 0 {
			if v.Limit > 0 {
				out.LimitedResources++
				if v.Used >= v.Limit {
					out.OverLimit++
					add("quota_exceeded", "bad", v, "额度已用尽，需调整额度或等待重置。", "traffic")
				} else if float64(v.Used)/float64(v.Limit) >= 0.8 {
					out.NearLimit++
					add("quota_near", "warn", v, "已使用至少 80% 的额度，请留意剩余用量。", "traffic")
				}
			} else if v.LimitNote == "" {
				out.UnlimitedResources++
			}
		}
		if v.Kind == "node" || v.Kind == "server" || v.Kind == "forwarding" {
			if !v.Related {
				out.BillingResources++
				if v.Used > 0 && !ranked[key] {
					ranked[key] = true
					out.TopUsage = append(out.TopUsage, v)
				}
			}
			if v.ServerOffline && v.ServerID > 0 && !offline[v.ServerID] {
				offline[v.ServerID] = true
				name := v.ServerName
				if name == "" {
					name = v.Name
				}
				alert := v
				alert.Name = name
				add("server_offline", "warn", alert, "服务器已离线，相关节点可能暂时无法连接。", "resources")
			}
		}
		if v.ProvisionError {
			add("provision_failed", "warn", v, "服务器应用授权时出现错误，请检查下发状态。", "resources")
		}
		if v.State == "invalid" {
			add("source_invalid", "warn", v, "订阅来源已失效，请检查关联配置。", "resources")
		}
		// Child selections and package-derived expiry dates are represented once
		// by their parent grant. A different expiry remains a separate constraint.
		if v.ExpiresAt == nil || v.Kind == "subscription" || v.Kind == "node" && v.Related {
			continue
		}
		if pkgExpiry != nil && v.Kind != "package" && v.Source == "package" && v.ExpiresAt.Equal(*pkgExpiry.ExpiresAt) {
			continue
		}
		expired := !v.ExpiresAt.After(now)
		days := int(math.Ceil(v.ExpiresAt.Sub(now).Hours() / 24))
		if expired {
			days = int(math.Ceil(now.Sub(*v.ExpiresAt).Hours() / 24))
		}
		candidate := &managementExpiry{Kind: v.Kind, ID: v.ID, Name: v.Name, At: *v.ExpiresAt, Days: days, Expired: expired}
		if expired {
			if past == nil || candidate.At.After(past.At) {
				past = candidate
			}
			add("expired", "bad", v, "授权已到期，需要续期后继续使用。", "resources")
		} else {
			if future == nil || candidate.At.Before(future.At) {
				future = candidate
			}
			if days <= 7 {
				add("expiring", "warn", v, "将在 "+strconv.Itoa(days)+" 天内到期，请及时安排续期。", "resources")
			}
		}
	}
	for _, layer := range layers {
		if layer.Key != "module" {
			continue
		}
		for _, item := range layer.Items {
			if item.Limit <= 0 {
				continue
			}
			out.LimitedResources++
			v := managementResourceUsage{Kind: item.Kind, ID: item.ID, Name: item.Name}
			if item.Used >= item.Limit {
				out.OverLimit++
				add("quota_exceeded", "bad", v, "模块额度已用尽，相关资源受限。", "traffic")
			} else if float64(item.Used)/float64(item.Limit) >= 0.8 {
				out.NearLimit++
				add("quota_near", "warn", v, "模块额度已使用至少 80%，请留意剩余用量。", "traffic")
			}
		}
	}
	if future != nil {
		out.Expiry = future
	} else {
		out.Expiry = past
	}
	sort.SliceStable(out.TopUsage, func(i, j int) bool {
		if out.TopUsage[i].Used == out.TopUsage[j].Used {
			return out.TopUsage[i].Name < out.TopUsage[j].Name
		}
		return out.TopUsage[i].Used > out.TopUsage[j].Used
	})
	if len(out.TopUsage) > 3 {
		out.TopUsage = out.TopUsage[:3]
	}
	sort.SliceStable(out.Alerts, func(i, j int) bool { return out.Alerts[i].Severity == "bad" && out.Alerts[j].Severity != "bad" })
	return out
}

func managementFixedResetLabel(user storage.User) string {
	if !user.IsReset || user.ResetDay < 1 || user.ResetDay > 31 {
		return "不自动重置"
	}
	period, e := storage.NormalizeNodeTrafficResetPeriod(user.NodeTrafficResetPeriod)
	if e != nil {
		return "重置规则待确认"
	}
	label := "每月"
	if period == storage.NodeTrafficResetQuarterly {
		label = "每季度首月"
	}
	if period == storage.NodeTrafficResetYearly {
		label = "每年 1 月"
	}
	return label + " " + strconv.Itoa(user.ResetDay) + " 日重置"
}

// A historical error for an already acknowledged generation is not a current
// delivery failure. Unknown/missing receipts alone never create an error alert.
func managementSourceFailed(source storage.UserInboundAccessSource) bool {
	return source.DesiredState == storage.ManagedDesiredActive && source.Generation > source.AppliedGeneration && strings.TrimSpace(source.LastError) != ""
}
