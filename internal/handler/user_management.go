package handler

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type managementUser struct {
	userEntry
	Resources     []storage.UserManagementResource `json:"resources"`
	NearestExpiry *time.Time                       `json:"nearest_expiry,omitempty"`
}

// NewUserManagementListHandler is separate from the legacy directory used by
// account selectors. Filtering, sorting and paging are applied on the server.
func NewUserManagementListHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		users, err := repo.ListUsers(r.Context(), 2147483647)
		if err != nil {
			writeError(w, 500, err)
			return
		}
		all, err := repo.ListUserManagementResources(r.Context())
		if err != nil {
			writeError(w, 500, err)
			return
		}
		index := map[string][]storage.UserManagementResource{}
		byUser := map[string]storage.User{}
		for _, u := range users {
			byUser[u.Username] = u
		}
		options := map[string]map[int64]string{"node": {}, "server": {}, "subscription": {}, "package": {}}
		for _, v := range all {
			u, ok := byUser[v.Username]
			if !ok || u.Role != storage.RoleUser {
				continue
			}
			// A manual subscription can accompany either authorization mode. Other
			// resources must belong to the current grant source (including packages).
			if v.Kind != "subscription" && ((u.PackageID > 0 && v.PackageID != u.PackageID) || (u.PackageID == 0 && v.PackageID > 0)) {
				continue
			}
			if v.Source == storage.ManagedSourceSelection {
				v.Source = "server"
			}
			index[v.Username] = append(index[v.Username], v)
			options[v.Kind][v.ID] = v.Name
		}
		// Fixed package nodes are declared on the package itself; they need not
		// have a direct-grant row. Read the declared bundle as well as selections.
		packages, err := repo.ListPackages(r.Context())
		if err != nil {
			writeError(w, 500, err)
			return
		}
		nodes, err := repo.ListAllNodes(r.Context())
		if err != nil {
			writeError(w, 500, err)
			return
		}
		packageMap := map[int64]storage.Package{}
		for _, p := range packages {
			packageMap[p.ID] = p
		}
		nodeNames := map[int64]string{}
		for _, n := range nodes {
			nodeNames[n.ID] = n.NodeName
		}
		for _, u := range users {
			if u.Role != storage.RoleUser || u.PackageID <= 0 {
				continue
			}
			p, ok := packageMap[u.PackageID]
			if !ok {
				continue
			}
			for _, id := range p.Nodes {
				name, exists := nodeNames[id]
				if !exists {
					continue
				}
				duplicate := false
				for _, v := range index[u.Username] {
					if v.Kind == "node" && v.ID == id {
						duplicate = true
						break
					}
				}
				if duplicate {
					continue
				}
				index[u.Username] = append(index[u.Username], storage.UserManagementResource{Username: u.Username, Kind: "node", ID: id, Name: name, Source: "package", PackageID: u.PackageID, ExpiresAt: u.PackageEndDate, State: "authorized"})
				options["node"][id] = name
			}
		}
		q := r.URL.Query()
		query := strings.ToLower(strings.TrimSpace(q.Get("q")))
		from, to := q.Get("from"), q.Get("to")
		for _, v := range []string{from, to} {
			if v != "" {
				if _, err := time.Parse("2006-01-02", v); err != nil {
					writeBadRequest(w, "注册日期无效")
					return
				}
			}
		}
		if from != "" && to != "" && from > to {
			writeBadRequest(w, "开始日期不能晚于结束日期")
			return
		}
		filtered := []managementUser{}
		activeCount, totalCount := 0, 0
		for _, entry := range buildUserEntries(r.Context(), repo, users) {
			if entry.Role != storage.RoleUser {
				continue
			}
			totalCount++
			if entry.IsActive {
				activeCount++
			}
			if entry.PackageID != nil {
				options["package"][*entry.PackageID] = entry.PackageName
			}
			if q.Get("status") == "active" && !entry.IsActive || q.Get("status") == "disabled" && entry.IsActive {
				continue
			}
			if q.Get("view") == "renewal" && entry.PackageID == nil {
				continue
			}
			if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{entry.Username, entry.Nickname, entry.Email, entry.Remark, entry.PackageName, entry.UserShortCode}, " ")), query) {
				continue
			}
			day := entry.CreatedAt.Format("2006-01-02")
			if from != "" && day < from || to != "" && day > to {
				continue
			}
			resources := index[entry.Username]
			if resources == nil {
				resources = []storage.UserManagementResource{}
			}
			match := true
			for _, kind := range []string{"package", "server", "subscription", "node"} {
				ids := q.Get(kind)
				if ids == "" {
					continue
				}
				found := false
				for _, id := range strings.Split(ids, ",") {
					if kind == "package" && entry.PackageID != nil && strconv.FormatInt(*entry.PackageID, 10) == id {
						found = true
					}
					for _, v := range resources {
						if v.Kind == kind && strconv.FormatInt(v.ID, 10) == id {
							found = true
						}
					}
				}
				if !found {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			item := managementUser{userEntry: entry, Resources: resources}
			if entry.PackageEndDate != nil {
				v, _ := time.ParseInLocation("2006-01-02", *entry.PackageEndDate, time.Local)
				item.NearestExpiry = &v
			}
			for _, v := range resources {
				if v.ExpiresAt != nil && (item.NearestExpiry == nil || v.ExpiresAt.Before(*item.NearestExpiry)) {
					copy := *v.ExpiresAt
					item.NearestExpiry = &copy
				}
			}
			filtered = append(filtered, item)
		}
		sortKey := q.Get("sort")
		sort.SliceStable(filtered, func(i, j int) bool {
			a, b := filtered[i], filtered[j]
			switch sortKey {
			case "name":
				if a.Nickname != b.Nickname {
					return a.Nickname < b.Nickname
				}
			case "traffic":
				if a.TrafficUsed != b.TrafficUsed {
					return a.TrafficUsed > b.TrafficUsed
				}
			case "expiry":
				if a.NearestExpiry == nil && b.NearestExpiry != nil {
					return false
				}
				if a.NearestExpiry != nil && b.NearestExpiry == nil {
					return true
				}
				if a.NearestExpiry != nil && b.NearestExpiry != nil && !a.NearestExpiry.Equal(*b.NearestExpiry) {
					return a.NearestExpiry.Before(*b.NearestExpiry)
				}
			case "oldest":
				if !a.CreatedAt.Equal(b.CreatedAt) {
					return a.CreatedAt.Before(b.CreatedAt)
				}
			default:
				if !a.CreatedAt.Equal(b.CreatedAt) {
					return a.CreatedAt.After(b.CreatedAt)
				}
			}
			return a.Username < b.Username
		})
		total := len(filtered)
		matching := make([]string, 0, total)
		for _, v := range filtered {
			matching = append(matching, v.Username)
		}
		page, _ := strconv.Atoi(q.Get("page"))
		if page < 1 {
			page = 1
		}
		size, _ := strconv.Atoi(q.Get("size"))
		if size < 1 || size > 100 {
			size = 25
		}
		pages := (total + size - 1) / size
		if pages < 1 {
			pages = 1
		}
		if page > pages {
			page = pages
		}
		start := (page - 1) * size
		end := start + size
		if end > total {
			end = total
		}
		type option struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		}
		filterOptions := map[string][]option{}
		for kind, values := range options {
			items := []option{}
			for id, name := range values {
				items = append(items, option{id, name})
			}
			sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
			filterOptions[kind] = items
		}
		writeJSON(w, 200, map[string]any{"users": filtered[start:end], "total": total, "page": page, "pages": pages, "matching_usernames": matching, "counts": map[string]int{"total": totalCount, "active": activeCount}, "filter_options": filterOptions})
	})
}

type managementResourceUsage struct {
	Kind      string     `json:"kind"`
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Source    string     `json:"source"`
	Used      int64      `json:"used"`
	Limit     int64      `json:"limit"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Reset     string     `json:"reset"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	State     string     `json:"state"`
	Related   bool       `json:"related"`
	Note      string     `json:"note,omitempty"`
}

func NewUserManagementDetailHandler(repo *storage.TrafficRepository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		username := r.PathValue("username")
		user, err := repo.GetUser(r.Context(), username)
		if err != nil {
			writeError(w, 404, err)
			return
		}
		if user.Role != storage.RoleUser {
			writeBadRequest(w, "用户管理仅管理普通用户")
			return
		}
		resources, err := userManagementUsage(r.Context(), repo, user)
		if err != nil {
			writeError(w, 500, err)
			return
		}
		for i := range resources {
			if resources[i].ExpiresAt != nil && !resources[i].ExpiresAt.After(time.Now()) {
				resources[i].State = "expired"
			}
			if !user.IsActive {
				resources[i].State = "user_disabled"
			}
		}
		audits, err := repo.ListManagedAccessAudit(r.Context(), username, "", 0, 100)
		if err != nil {
			writeError(w, 500, err)
			return
		}
		// Do not return raw audit details: some older writers predate sanitization.
		type audit struct {
			Actor  string    `json:"actor"`
			Action string    `json:"action"`
			Kind   string    `json:"kind"`
			At     time.Time `json:"at"`
		}
		records := []audit{}
		for _, v := range audits {
			records = append(records, audit{v.Actor, v.Action, v.EntityType, v.CreatedAt})
		}
		entries := buildUserEntries(r.Context(), repo, []storage.User{user})
		writeJSON(w, 200, map[string]any{"user": entries[0], "resources": resources, "records": records, "as_of": time.Now().UTC(), "usage_note": "总用量来自用户计费记录，订阅及套餐关联用量不重复累加。各资源按自己的重置周期统计。"})
	})
}

func userManagementUsage(ctx context.Context, repo *storage.TrafficRepository, user storage.User) ([]managementResourceUsage, error) {
	result := []managementResourceUsage{}
	nodes, err := repo.ListAllNodes(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]storage.Node{}
	ids := []int64{}
	for _, n := range nodes {
		byID[n.ID] = n
		ids = append(ids, n.ID)
	}
	var pkg *storage.Package
	if user.PackageID > 0 {
		p, e := repo.GetPackage(ctx, user.PackageID)
		if e != nil {
			return nil, e
		}
		pkg = p
	}
	usage, err := repo.GetUserNodeTraffic(ctx, user.Username, ids, pkg)
	if err != nil {
		return nil, err
	}
	fixed, err := repo.ListUserNodeGrants(ctx, user.Username)
	if err != nil {
		return nil, err
	}
	sourceMatches := func(source string, pid *int64) bool {
		return user.PackageID > 0 && source == storage.GrantSourcePackage && pid != nil && *pid == user.PackageID || user.PackageID == 0 && source == storage.GrantSourceManual
	}
	nodeUsed := map[int64]int64{}
	seen := map[int64]bool{}
	reset := "不自动重置"
	if user.NodeTrafficResetPeriod == "monthly" || user.IsReset {
		reset = "每月重置"
		if user.IsReset {
			reset = "每月 " + strconv.Itoa(user.ResetDay) + " 日重置"
		}
	}
	if pkg != nil {
		packageSources, e := repo.ListUserInboundAccessSources(ctx, user.Username, 0)
		if e != nil {
			return nil, e
		}
		states := map[int64]storage.UserInboundAccessSource{}
		for _, s := range packageSources {
			if s.SourceType == storage.ManagedSourcePackage {
				states[s.NodeID] = s
			}
		}
		for _, id := range pkg.Nodes {
			n, ok := byID[id]
			if !ok || seen[id] {
				continue
			}
			seen[id] = true
			nodeUsed[id] = usage[id]
			limit, _ := nodeTrafficLimitGB(&user, pkg, id)
			// Legacy package provisioning does not create an access-source receipt.
			// The package proves authorization, not an outstanding delivery job.
			state := "authorized"
			var updated *time.Time
			if v, ok := states[id]; ok {
				state = v.ObservedState
				copy := v.UpdatedAt
				updated = &copy
			}
			if !n.Enabled {
				state = "inactive"
			}
			result = append(result, managementResourceUsage{Kind: "node", ID: id, Name: n.NodeName, Source: "package", Used: usage[id], Limit: int64(limit * userTrafficLimitBytesPerGB), ExpiresAt: user.PackageEndDate, Reset: reset, State: state, UpdatedAt: updated})
		}
	}
	for _, v := range fixed {
		if !sourceMatches(v.Grant.SourceType, v.Grant.SourcePackageID) || v.Source.DesiredState != storage.ManagedDesiredActive {
			continue
		}
		n := byID[v.Grant.NodeID]
		limit, _ := nodeTrafficLimitGB(&user, pkg, n.ID)
		used := usage[n.ID]
		nodeUsed[n.ID] = used
		seen[n.ID] = true
		result = append(result, managementResourceUsage{Kind: "node", ID: n.ID, Name: n.NodeName, Source: v.Grant.SourceType, Used: used, Limit: int64(limit * userTrafficLimitBytesPerGB), ExpiresAt: v.Source.ExpiresAt, Reset: reset, State: v.Source.ObservedState, UpdatedAt: &v.Source.UpdatedAt})
	}
	servers, err := repo.ListRemoteServers(ctx)
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	for _, v := range servers {
		names[v.ID] = v.Name
	}
	grants, err := repo.ListUserServerGrants(ctx, user.Username)
	if err != nil {
		return nil, err
	}
	sources, err := repo.ListUserInboundAccessSources(ctx, user.Username, 0)
	if err != nil {
		return nil, err
	}
	nodeBySource := map[int64]int64{}
	for _, v := range sources {
		nodeBySource[v.ID] = v.NodeID
	}
	selections, err := repo.ListUserNodeSelections(ctx, user.Username, false)
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if !g.Enabled || !sourceMatches(g.SourceType, g.SourcePackageID) {
			continue
		}
		_, _, used, e := repo.GetUserServerGrantUsage(ctx, g.ID)
		if e != nil {
			return nil, e
		}
		period := "不自动重置"
		if g.ResetPolicy == storage.ManagedResetMonthly {
			period = "每月 " + strconv.Itoa(g.ResetDay) + " 日重置"
		}
		result = append(result, managementResourceUsage{Kind: "server", ID: g.ServerID, Name: names[g.ServerID], Source: g.SourceType, Used: used, Limit: g.TrafficLimitBytes, ExpiresAt: g.ExpiresAt, Reset: period, State: "authorized", Note: "包含此服务器授权下所选节点的用量"})
		for _, sel := range selections {
			if sel.GrantID != g.ID || sel.AccessSourceID == nil {
				continue
			}
			id := nodeBySource[*sel.AccessSourceID]
			counter, e := repo.GetUserNodeSelectionUsage(ctx, sel.ID)
			if e != nil && !errors.Is(e, storage.ErrUserNodeSelectionNotFound) {
				return nil, e
			}
			if counter == nil {
				continue
			}
			mode := g.BillingMode
			if sel.BillingModeOverride != nil {
				mode = *sel.BillingModeOverride
			}
			nodeUsed[id] = counter.BilledBytes(mode)
			if seen[id] {
				continue
			}
			seen[id] = true
			limit, _ := nodeTrafficLimitGB(&user, pkg, id)
			state := "inactive"
			if sel.DesiredEnabled {
				state = "active"
			}
			result = append(result, managementResourceUsage{Kind: "node", ID: id, Name: byID[id].NodeName, Source: "server", Used: nodeUsed[id], Limit: int64(limit * userTrafficLimitBytesPerGB), ExpiresAt: g.ExpiresAt, Reset: period, UpdatedAt: &counter.UpdatedAt, State: state, Related: true, Note: "已包含在服务器授权用量中"})
		}
	}
	files, err := repo.GetUserSubscriptions(ctx, user.Username)
	if err != nil {
		return nil, err
	}
	assignment, err := repo.SubscriptionAssignmentSources(ctx, user.Username)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		bound, external, e := subscriptionBoundNodeIDs(ctx, repo, f)
		if e != nil {
			result = append(result, managementResourceUsage{Kind: "subscription", ID: f.ID, Name: f.Name, Source: assignment[f.ID], Related: true, State: "invalid", Reset: "跟随关联节点", Note: "来源配置已失效，请到订阅管理检查；关联用量暂不可用"})
			continue
		}
		sum := int64(0)
		dedup := map[int64]bool{}
		for _, id := range bound {
			if !dedup[id] {
				sum = subscriptionTrafficAdd(sum, nodeUsed[id])
				dedup[id] = true
			}
		}
		note := "订阅关联用量；共享凭据无法区分具体通过哪份订阅使用"
		if external {
			note = "包含外部共享节点，仅能展示可按用户统计的关联节点用量"
		}
		result = append(result, managementResourceUsage{Kind: "subscription", ID: f.ID, Name: f.Name, Source: assignment[f.ID], Used: sum, Reset: "跟随关联节点", State: "authorized", Related: true, Note: note})
	}
	if pkg != nil {
		sum := int64(0)
		for _, v := range result {
			if v.Kind == "server" || v.Kind == "node" && !v.Related {
				sum = subscriptionTrafficAdd(sum, v.Used)
			}
		}
		result = append(result, managementResourceUsage{Used: sum, Kind: "package", ID: pkg.ID, Name: pkg.Name, Source: "package", ExpiresAt: user.PackageEndDate, Reset: "各资源分别计费", State: "authorized", Related: true, Note: "套餐是授权容器，不额外累加流量"})
	}
	return result, nil
}
