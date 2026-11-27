package handler

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

// A scoped batch mutation must not rewrite an unrelated grant family or
// resave its policy through the full-replacement editor's defaults. The scope
// travels with the authorization lease, including its rollback reconciler.
type managementGrantScopeKey struct{}
type managementGrantScope struct {
	Kind string
	IDs  map[int64]bool
}

func managementGrantInScope(ctx context.Context, kind string, id int64) bool {
	scope, ok := ctx.Value(managementGrantScopeKey{}).(managementGrantScope)
	return !ok || scope.Kind == kind && scope.IDs[id]
}

type managementBatchRequest struct {
	Usernames            []string   `json:"usernames"`
	Kind                 string     `json:"kind"`
	Operation            string     `json:"operation"`
	IDs                  []int64    `json:"ids"`
	ExpiresAt            *time.Time `json:"expires_at"`
	TrafficGB            *float64   `json:"traffic_gb"`
	ResetDay             int        `json:"reset_day"`
	ReplaceAuthorization bool       `json:"replace_authorization"`
	Preview              bool       `json:"preview"`
}

// HandleManagementBatch updates only the selected family. The existing
// authorization reconciler owns provisioning and rollback, including credentials.
func (h *ServiceAuthorizationHandler) HandleManagementBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req managementBatchRequest
	if decodeServiceAuthorizationJSON(w, r, &req) != nil {
		return
	}
	if len(req.Usernames) == 0 || len(req.Usernames) > 200 || len(req.IDs) == 0 || len(req.IDs) > 500 {
		writeBadRequest(w, "每次选择 1–200 位用户、1–500 个资源")
		return
	}
	if req.Operation != "append" && req.Operation != "revoke" {
		writeBadRequest(w, "无效的授权操作")
		return
	}
	switch req.Kind {
	case "node", "server", "subscription", "package":
	default:
		writeBadRequest(w, "无效的资源类型")
		return
	}
	if req.Kind == "package" && len(req.IDs) != 1 {
		writeBadRequest(w, "每次只能选择一个套餐")
		return
	}
	if req.TrafficGB != nil && (math.IsNaN(*req.TrafficGB) || math.IsInf(*req.TrafficGB, 0) || *req.TrafficGB < 0 || *req.TrafficGB > float64(math.MaxInt64)/userTrafficLimitBytesPerGB) {
		writeBadRequest(w, "流量额度无效")
		return
	}
	if req.ResetDay < 0 || req.ResetDay > 31 {
		writeBadRequest(w, "重置日必须在 1–31 之间")
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		writeBadRequest(w, "到期日期必须晚于当前时间")
		return
	}
	users := []string{}
	seen := map[string]bool{}
	for _, name := range req.Usernames {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			writeBadRequest(w, "用户名为空或重复")
			return
		}
		u, e := h.repo.GetUser(r.Context(), name)
		if e != nil || u.Role != storage.RoleUser || storage.IsReservedUsername(name) {
			writeBadRequest(w, "仅能操作现有普通用户")
			return
		}
		seen[name] = true
		users = append(users, name)
	}
	ids := map[int64]bool{}
	for _, id := range req.IDs {
		if id <= 0 || ids[id] {
			writeBadRequest(w, "资源 ID 无效或重复")
			return
		}
		ids[id] = true
	}
	// Validate resources even for preview/revoke, so stale selections cannot
	// produce a misleading success response.
	for id := range ids {
		var e error
		switch req.Kind {
		case "node":
			_, e = h.repo.GetNodeByID(r.Context(), id)
		case "server":
			_, e = h.repo.GetRemoteServer(r.Context(), id)
		case "package":
			_, e = h.repo.GetPackage(r.Context(), id)
		case "subscription":
			_, e = h.repo.GetSubscribeFileByID(r.Context(), id)
		}
		if e != nil {
			writeBadRequest(w, "所选资源已删除，请刷新后重试")
			return
		}
	}
	results := []serviceAuthorizationResult{}
	allOK := true
	for _, name := range users {
		status := "applied"
		var warnings []string
		packageIDs := []int64{}
		if req.Kind == "package" && req.Operation == "append" {
			packageIDs = req.IDs
		}
		err := withStableUserPackageAuthorizationLease(r.Context(), h.repo, name, packageIDs, func(ctx context.Context, u storage.User) error {
			if req.Kind == "subscription" {
				return h.applyManagementSubscriptions(ctx, u, req, ids)
			}
			if req.Kind == "package" {
				if req.Operation == "revoke" {
					if u.PackageID != req.IDs[0] {
						return nil
					}
					if !req.ReplaceAuthorization {
						return errors.New("撤销套餐需要确认切换为自定义授权")
					}
					if req.Preview {
						return nil
					}
					var e error
					warnings, status, e = h.applyCustom(ctx, name, emptyCustomAuthorizationRequest(), managedActor(r))
					return e
				}
				if !req.ReplaceAuthorization {
					return errors.New("分配套餐将替换现有服务授权，请确认")
				}
				p := serviceAuthorizationPackageRequest{PackageID: req.IDs[0]}
				if req.ExpiresAt != nil {
					p.ExpireDate = req.ExpiresAt.In(time.Local).Format("2006-01-02")
				}
				parsed, e := h.validatePackageRequest(ctx, p)
				if e != nil {
					return e
				}
				if req.Preview {
					return nil
				}
				warnings, status, e = h.applyPackage(ctx, name, *parsed, managedActor(r))
				return e
			}
			if u.PackageID > 0 && !req.ReplaceAuthorization {
				return errors.New("该用户使用套餐；请保留套餐，或明确确认改为自定义授权")
			}
			snapshot, e := h.captureCustomSnapshot(ctx, name)
			if e != nil {
				return e
			}
			custom := customRequestFromSnapshot(snapshot)
			if u.PackageID > 0 {
				custom = emptyCustomAuthorizationRequest()
			}
			fixed, servers := *custom.FixedNodeGrants, *custom.ServerGrants
			if req.Kind == "node" {
				next := []serviceAuthorizationFixedNodeGrant{}
				existing := map[int64]bool{}
				for _, v := range fixed {
					if ids[v.NodeID] && req.Operation == "revoke" {
						continue
					}
					next = append(next, v)
					existing[v.NodeID] = true
				}
				if req.Operation == "append" {
					validation := emptyCustomAuthorizationRequest()
					chosen := []serviceAuthorizationFixedNodeGrant{}
					for _, id := range req.IDs {
						chosen = append(chosen, serviceAuthorizationFixedNodeGrant{NodeID: id, ExpiresAt: req.ExpiresAt})
						if !existing[id] {
							next = append(next, serviceAuthorizationFixedNodeGrant{NodeID: id, ExpiresAt: req.ExpiresAt})
						}
					}
					validation.FixedNodeGrants = &chosen
					if e = h.validateCustomRequest(ctx, &validation); e != nil {
						return e
					}
				}
				custom.FixedNodeGrants = &next
			} else {
				next := []serviceAuthorizationServerGrant{}
				existing := map[int64]bool{}
				for _, v := range servers {
					if ids[v.ServerID] && req.Operation == "revoke" {
						continue
					}
					next = append(next, v)
					existing[v.ServerID] = true
				}
				if req.Operation == "append" {
					chosen := []serviceAuthorizationServerGrant{}
					for _, id := range req.IDs {
						v := serviceAuthorizationServerGrant{ServerID: id, Enabled: true, StartsAt: time.Now().UTC(), ExpiresAt: req.ExpiresAt, BillingMode: storage.ManagedBillingDownload, ResetPolicy: storage.ManagedResetNone, ResetDay: 1}
						if req.TrafficGB != nil {
							v.TrafficLimitBytes = int64(*req.TrafficGB * userTrafficLimitBytesPerGB)
						}
						if req.ResetDay > 0 {
							v.ResetPolicy = storage.ManagedResetMonthly
							v.ResetDay = req.ResetDay
						}
						chosen = append(chosen, v)
						if !existing[id] {
							next = append(next, v)
						}
					}
					validation := emptyCustomAuthorizationRequest()
					validation.ServerGrants = &chosen
					if e = h.validateCustomRequest(ctx, &validation); e != nil {
						return e
					}
				}
				custom.ServerGrants = &next
			}
			if req.Preview {
				return nil
			}
			if u.PackageID == 0 {
				changedIDs := map[int64]bool{}
				for id := range ids {
					changedIDs[id] = true
				}
				if req.Operation == "append" {
					if req.Kind == "node" {
						for _, v := range fixed {
							delete(changedIDs, v.NodeID)
						}
					} else {
						for _, v := range servers {
							delete(changedIDs, v.ServerID)
						}
					}
				}
				if len(changedIDs) == 0 {
					return nil
				}
				ctx = context.WithValue(ctx, managementGrantScopeKey{}, managementGrantScope{Kind: req.Kind, IDs: changedIDs})
			}
			// Limit changes are staged before provisioning; restore them if the
			// authorization mutation rolls back. Existing grants are left untouched.
			if req.Kind == "node" && req.Operation == "append" && req.TrafficGB != nil {
				limits := map[int64]float64{}
				for id, v := range u.NodeTrafficLimitOverrides {
					limits[id] = v
				}
				for id := range ids {
					exists := false
					for _, v := range fixed {
						if v.NodeID == id {
							exists = true
						}
					}
					if !exists {
						limits[id] = *req.TrafficGB
					}
				}
				if e = h.repo.UpdateUserNodeLimitsWithTraffic(ctx, name, u.NodeSpeedLimitOverrides, limits, u.NodeDeviceLimitOverrides); e != nil {
					return e
				}
			}
			warnings, status, e = h.applyCustom(ctx, name, custom, managedActor(r))
			if e != nil && req.Kind == "node" && req.TrafficGB != nil {
				restore := h.repo.UpdateUserNodeLimitsWithTraffic(ctx, name, u.NodeSpeedLimitOverrides, u.NodeTrafficLimitOverrides, u.NodeDeviceLimitOverrides)
				e = errors.Join(e, restore)
			}
			return e
		})
		if err == nil && !req.Preview {
			auditErr := h.repo.AppendManagedAccessAudit(r.Context(), storage.ManagedAccessAudit{Actor: managedActor(r), Action: "batch_" + req.Operation, EntityType: req.Kind, Username: name, Details: map[string]any{"resource_ids": req.IDs}, CreatedAt: time.Now().UTC()})
			if auditErr != nil {
				warnings = append(warnings, "操作记录保存失败，请检查服务日志")
			}
		}

		if req.Preview && err == nil {
			status = "ready"
		}
		res := serviceAuthorizationResult{Username: name, Mode: req.Kind, Status: status, Warnings: warnings}
		if err != nil {
			allOK = false
			res.Status = "failed"
			res.Error = err.Error()
		}
		results = append(results, res)
	}
	code := 200
	if !allOK {
		code = 207
	}
	writeJSON(w, code, map[string]any{"success": allOK, "preview": req.Preview, "results": results})
}

func (h *ServiceAuthorizationHandler) applyManagementSubscriptions(ctx context.Context, u storage.User, req managementBatchRequest, ids map[int64]bool) error {
	current, e := h.repo.SubscriptionAssignmentSources(ctx, u.Username)
	if e != nil {
		return e
	}
	manual := map[int64]bool{}
	for id, source := range current {
		if source == storage.GrantSourceManual {
			manual[id] = true
		}
	}
	for id := range ids {
		if req.Operation == "revoke" {
			if current[id] == storage.GrantSourcePackage {
				return errors.New("套餐内订阅需通过套餐调整，不能单独撤销")
			}
			delete(manual, id)
			continue
		}
		f, e := h.repo.GetSubscribeFileByID(ctx, id)
		if e != nil {
			return e
		}
		if f.Generation == nil && f.CreatedBy != u.Username {
			return errors.New("外部共享凭据无法按用户统计，不能分配")
		}
		if e = validateSubscriptionNodeSelection(ctx, h.repo, f); e != nil {
			return e
		}
		_, external, e := subscriptionBoundNodeIDs(ctx, h.repo, f)
		if e != nil {
			return e
		}
		if external && f.CreatedBy != u.Username {
			return fmt.Errorf("订阅 %s 包含不可按用户统计的外部共享节点", f.Name)
		}
		if current[id] != storage.GrantSourcePackage {
			manual[id] = true
		}
	}
	if req.Preview {
		return nil
	}
	next := []int64{}
	for id := range manual {
		next = append(next, id)
	}
	sort.Slice(next, func(i, j int) bool { return next[i] < next[j] })
	if e = h.repo.SetUserSubscriptions(ctx, u.Username, next); e != nil {
		return e
	}
	return nil
}
