package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // 嵌入时区库,LoadLocation 不依赖系统 zoneinfo(纠正缺 /etc/localtime 的机器)

	appconfigs "github.com/violetaini/relaydock/configs"
	"github.com/violetaini/relaydock/internal/agentfirewall"
	"github.com/violetaini/relaydock/internal/agentlog"
	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/capabilities"
	"github.com/violetaini/relaydock/internal/captcha"
	"github.com/violetaini/relaydock/internal/child"
	"github.com/violetaini/relaydock/internal/componentupdate"
	"github.com/violetaini/relaydock/internal/ddns"
	"github.com/violetaini/relaydock/internal/event"
	"github.com/violetaini/relaydock/internal/handler"
	"github.com/violetaini/relaydock/internal/logger"
	mcpserver "github.com/violetaini/relaydock/internal/mcp"
	"github.com/violetaini/relaydock/internal/notify"
	"github.com/violetaini/relaydock/internal/patches"
	"github.com/violetaini/relaydock/internal/proxygroups"
	"github.com/violetaini/relaydock/internal/runtimepaths"
	"github.com/violetaini/relaydock/internal/securechan"
	"github.com/violetaini/relaydock/internal/speedtest"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/traffic"
	"github.com/violetaini/relaydock/internal/version"
	"github.com/violetaini/relaydock/internal/web"
	ruletemplates "github.com/violetaini/relaydock/rule_templates"
	"github.com/violetaini/relaydock/subscribes"

	"gopkg.in/yaml.v3"
)

// ServerConfig表示配置文件结构
type ServerConfig struct {
	Mode           string `yaml:"mode"`            // "主控"或"远程"
	MasterServer   string `yaml:"master_server"`   // 主服务器 URL（用于远程模式）
	RemoteToken    string `yaml:"remote_token"`    // 用于远程服务器身份验证的令牌
	ConnectionMode string `yaml:"connection_mode"` // "websocket"、"http"、"pull"、"auto"
	Port           string `yaml:"port"`            // 服务器端口
	ChildAPIToken  string `yaml:"child_api_token"` // 用于子 API 身份验证的令牌
}

// 从 YAML 文件加载配置
func loadConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// initTimezone 兜底进程时区。Go 按 TZ 环境变量、其次 /etc/localtime 解析 time.Local;
// 部分精简 VPS / 容器的 /etc/localtime 缺失或损坏时会静默回退 UTC,导致按本地 HH:MM 调度的
// 「每日流量通知」等功能整体偏移(主机是 CST 时差 8 小时),日志时间戳也会错。
// 这里仅在 time.Local 落到 UTC 且用户未显式设置 TZ 时,用 /etc/timezone 纠正。
func initTimezone() {
	if zone := time.Now().Location().String(); zone != "UTC" && zone != "" {
		logger.Info("本地时区", "zone", zone)
		return
	}
	// 已落到 UTC。用户显式设了 TZ(含 TZ=UTC)就尊重其选择,不再纠正。
	if _, explicit := os.LookupEnv("TZ"); explicit {
		logger.Info("本地时区", "zone", "UTC", "source", "TZ")
		return
	}
	// TZ 未设且 time.Local=UTC,极可能是 /etc/localtime 缺失,用 /etc/timezone 兜底。
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		if name := strings.TrimSpace(string(data)); name != "" && name != "UTC" {
			if loc, err := time.LoadLocation(name); err == nil {
				time.Local = loc
				logger.Info("本地时区已按 /etc/timezone 纠正", "zone", name)
				return
			}
		}
	}
	logger.Warn("无法确定本地时区,按 UTC 运行;每日通知等按本地时间的功能会偏移,请设置环境变量 TZ(如 TZ=Asia/Shanghai)")
}

func main() {
	// 解析命令行标志
	configPath := flag.String("c", "", "Path to configuration file")
	firewallRulesPath := flag.String("arcway-firewall-rules", "", "Print public Xray inbound firewall rules and exit")
	productUpdateJobPath := flag.String("arcway-update-helper", "", "Run the isolated product update helper for a transaction file")
	flag.Parse()
	if *productUpdateJobPath != "" {
		logger.Init()
		if err := handler.RunProductUpdateHelper(*productUpdateJobPath); err != nil {
			logger.Error("产品更新事务失败", "error", err)
			os.Exit(1)
		}
		return
	}
	if *firewallRulesPath != "" {
		rules, err := agentfirewall.RulesFromFile(*firewallRulesPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "derive Xray inbound firewall rules: %v\n", err)
			os.Exit(1)
		}
		for _, rule := range rules {
			fmt.Printf("%s %d\n", rule.Protocol, rule.Port)
		}
		return
	}

	// 初始化logger
	logger.Init()
	if waitForRecovery, err := handler.ResumeProductUpdateOnStartup(); err != nil {
		logger.Error("产品更新恢复失败", "error", err)
		os.Exit(1)
	} else if waitForRecovery {
		// The transient helper will stop this service before it touches the
		// database or binary. Keep this process inert until systemd delivers that
		// stop, rather than starting a potentially inconsistent control plane.
		logger.Warn("检测到中断的产品更新，已安排独立恢复事务")
		select {}
	}
	initTimezone()
	logger.Info("RelayDock 服务器启动中", "version", version.Version)

	dataDirectory, err := runtimepaths.DataDirectory()
	if err != nil {
		logger.Error("数据目录初始化失败", "error", err)
		os.Exit(1)
	}

	// 启动日志清理任务（每天凌晨3点清理7天前的日志）
	go startLogCleanup(dataDirectory)

	// 从文件加载配置（如果指定）
	var config *ServerConfig
	if *configPath != "" {
		var err error
		config, err = loadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config file: %v", err)
		}
		log.Printf("Loaded configuration from %s", *configPath)
	}

	repo, err := storage.NewTrafficRepository(filepath.Join(dataDirectory, "arcway.db"))
	if err != nil {
		logger.Error("流量数据库初始化失败", "error", err)
		os.Exit(1)
	}
	defer repo.Close()

	addr := getAddr(config, repo)

	masterIdentity, err := securechan.LoadOrGenerate(filepath.Join(dataDirectory, "arcway_master.key"))
	if err != nil {
		logger.Error("加密密钥初始化失败", "error", err)
		os.Exit(1)
	}
	if err := repo.ConfigureNodeSecretEncryption(masterIdentity.PrivateKey.Seed()); err != nil {
		logger.Error("WireGuard 节点私钥加密初始化失败", "error", err)
		os.Exit(1)
	}
	logger.Info("主控加密公钥已加载", "public_key", masterIdentity.PublicKeyBase64())

	cryptoConfig := handler.NewCryptoConfig(masterIdentity, securechan.NewSessionCache(1*time.Hour))

	capabilityManager := capabilities.NewManager()

	authManager, err := auth.NewManager(repo)
	if err != nil {
		logger.Error("认证管理器加载失败", "error", err)
		os.Exit(1)
	}

	tokenStore := auth.NewTokenStore(24 * time.Hour)
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		tokenStore.SetSecret(jwtSecret)
		logger.Info("JWT_SECRET 已配置，会话令牌将使用 HMAC 签名")
	}

	// 从数据库加载持久会话
	ctx := context.Background()
	sessions, err := repo.LoadSessions(ctx)
	if err != nil {
		logger.Warn("从数据库加载会话失败", "error", err)
	} else {
		for _, session := range sessions {
			tokenStore.LoadSession(session.Token, session.Username, session.ExpiresAt)
		}
		logger.Info("会话加载完成", "count", len(sessions))
	}

	// 周期清理内存中过期 token(防 tokens map 因未被 Lookup 的过期项缓慢泄漏)
	go tokenStore.StartCleanup(ctx, 10*time.Minute)

	// 从数据库中清理过期会话
	if err := repo.CleanupExpiredSessions(ctx); err != nil {
		logger.Warn("清理过期会话失败", "error", err)
	}

	subscribeDir := filepath.Join("subscribes")
	if err := subscribes.Ensure(subscribeDir); err != nil {
		logger.Error("订阅文件准备失败", "error", err)
		os.Exit(1)
	}
	recovery, err := handler.ReconcileSubscriptionStore(ctx, repo, subscribeDir)
	if err != nil {
		logger.Error("订阅文件与数据库一致性恢复失败", "error", err)
		os.Exit(1)
	}
	if recovery.Imported > 0 || recovery.Orphaned > 0 {
		logger.Info("订阅存储恢复完成", "legacy_imported", recovery.Imported, "orphaned", recovery.Orphaned)
	}
	if err := handler.ProtectPersistedWireGuardSubscriptionSecrets(ctx, repo, subscribeDir); err != nil {
		logger.Error("WireGuard 订阅私钥迁移失败", "error", err)
		os.Exit(1)
	}

	ruleTemplatesDir := filepath.Join("rule_templates")
	if err := ruletemplates.Ensure(ruleTemplatesDir); err != nil {
		logger.Error("规则模板文件准备失败", "error", err)
		os.Exit(1)
	}
	if patched, err := patches.ApplyGEODefaults(ruleTemplatesDir); err != nil {
		logger.Warn("GEO 模板默认配置迁移出错(不影响启动)", "error", err)
	} else if patched > 0 {
		logger.Info("GEO 模板默认配置已补齐", "count", patched)
	}

	// rule_templates 补丁:Ensure 不覆盖已存在文件(保护用户自定义),
	// 但对历史已知错误的 dns 块(语义比对,顺序无关)做一次精准替换。详见 internal/patches 包注释。
	if patched, err := patches.ApplyDNSPatches(ruleTemplatesDir); err != nil {
		logger.Warn("DNS 模板补丁应用过程出错(不影响启动)", "error", err)
	} else if patched > 0 {
		logger.Info("DNS 模板补丁已应用", "count", patched)
	}
	if err := handler.ValidatePersistedRuleTemplateSecrets(ruleTemplatesDir); err != nil {
		logger.Error("规则模板 WireGuard 私钥校验失败", "error", err)
		os.Exit(1)
	}

	// 初始化代理组配置 Store（纯内存存储）
	// 优先从系统配置的远程地址拉取，失败时使用随版本审核的内置配置。
	var proxyGroupsStore *proxygroups.Store

	// 获取系统配置中的远程地址
	systemConfig, err := repo.GetSystemConfig(ctx)
	if err != nil {
		logger.Warn("加载系统配置失败", "error", err)
	}

	agentlog.SetEnabled(systemConfig.AgentLogEnabled)

	handler.InitNotifier(notify.Config{
		Enabled:                   systemConfig.NotifyEnabled,
		BotToken:                  systemConfig.TelegramBotToken,
		ChatID:                    systemConfig.TelegramChatID,
		NotifyLogin:               systemConfig.NotifyLogin,
		NotifySubscribeFetch:      systemConfig.NotifySubscribeFetch,
		NotifyDailyTraffic:        systemConfig.NotifyDailyTraffic,
		NotifyServerOffline:       systemConfig.NotifyServerOffline,
		NotifyServerOnline:        systemConfig.NotifyServerOnline,
		NotifyTrafficThreshold:    systemConfig.NotifyTrafficThreshold,
		DailyTrafficTime:          systemConfig.NotifyDailyTrafficTime,
		TrafficThresholdPercent:   systemConfig.NotifyTrafficThresholdPercent,
		NotifyTrafficThreshold80:  systemConfig.NotifyTrafficThreshold80,
		NotifyOverLimit:           systemConfig.NotifyOverLimit,
		NotifyPackageExpiring:     systemConfig.NotifyPackageExpiring,
		PackageExpiringDaysAhead:  systemConfig.NotifyPackageExpiringDays,
		NotifyPackageExpired:      systemConfig.NotifyPackageExpired,
		NotifyUserRegistered:      systemConfig.NotifyUserRegistered,
		NotifyTelegramBound:       systemConfig.NotifyTelegramBound,
		NotifyCertResult:          systemConfig.NotifyCertResult,
		NotifyAgentLongOffline:    systemConfig.NotifyAgentLongOffline,
		AgentLongOfflineMinutes:   systemConfig.NotifyAgentLongOfflineMinutes,
		NotifyDeviceLimitExceeded: systemConfig.NotifyDeviceLimitExceeded,
	})

	// TG bot 已拆为独立项目,通过 /api/admin/tgbot/* HTTP 调主控。
	// 主控仅保留 admin REST handler + 邀请码 web UI + storage 字段 + notify 裸 HTTP 通知。
	tgbotAPIHandler := handler.NewTGBotAPIHandler(repo)

	// 从远程拉取配置
	data, resolvedURL, fetchErr := proxygroups.FetchConfig(systemConfig.ProxyGroupsSourceURL)
	if fetchErr != nil {
		logger.Warn("拉取代理组配置失败", "error", fetchErr)
		proxyGroupsStore, err = proxygroups.NewStore(appconfigs.ProxyGroups, "embedded-fallback")
		if err != nil {
			logger.Error("创建代理组存储失败", "error", err)
			os.Exit(1)
		}
		logger.Info("代理组存储已使用内置配置初始化", "reason", "远程拉取失败")
	} else {
		// 远程拉取成功
		proxyGroupsStore, err = proxygroups.NewStore(data, resolvedURL)
		if err != nil {
			logger.Error("代理组配置无效", "source", resolvedURL, "error", err)
			os.Exit(1)
		}
		logger.Info("代理组配置加载成功", "source", resolvedURL)
	}

	trafficHandler := handler.NewTrafficSummaryHandler(repo)
	packageSubscribeHandler := handler.NewPackageSubscribeHandler(repo)
	userRepo := auth.NewRepositoryAdapter(repo)

	mux := http.NewServeMux()
	mux.Handle("/api/setup/status", handler.NewSetupStatusHandler(repo))
	mux.Handle("/api/setup/init", handler.NewInitialSetupHandler(repo))
	mux.Handle("/api/setup/verify-domain", handler.NewVerifyDomainHandler())
	mux.Handle("/api/setup/restore-backup", handler.NewSetupRestoreBackupHandler(repo))

	// 从 system_settings 读 3 个安全限流器的自定义阈值(KV 缺失 → fallback hardcoded 默认值)。
	// 同一份配置后面给 brute_force + subscription_rate 构造时复用。
	secCfg := handler.LoadSecuritySettings(context.Background(), repo)
	loginRateLimiter := handler.NewLoginRateLimiterWithConfig(
		secCfg.LoginRateMaxAttempts, secCfg.LoginRateWindowMinutes, secCfg.LoginRateLockMinutes,
	)
	loginRateLimiter.SetSkipLocalIP(secCfg.SkipLocalIP)
	twoFactorStore := auth.NewTwoFactorPendingStore(5 * time.Minute)
	turnstileVerifier := captcha.New(repo)

	// 公开端点:登录页前端拉这个拿 site_key 决定是否渲染 widget(在 auth 之前必须可访问)。
	// 两 key 都空时 enabled=false → 前端不渲染、后端 Verify 直接放行,无侵入降级。
	mux.HandleFunc("/api/captcha/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":  turnstileVerifier.Enabled(r.Context()),
			"site_key": turnstileVerifier.SiteKey(r.Context()),
		})
	})

	mux.Handle("/api/login", handler.NewLoginHandler(authManager, tokenStore, repo, loginRateLimiter, twoFactorStore, turnstileVerifier))
	mux.Handle("/api/login/2fa", handler.NewTwoFactorLoginHandler(tokenStore, repo, twoFactorStore))
	mux.Handle("/api/login/recovery", handler.NewRecoveryLoginHandler(tokenStore, repo, twoFactorStore))

	// 仅限管理端点
	mux.Handle("/api/admin/credentials", auth.RequireAdmin(tokenStore, userRepo, handler.NewCredentialsHandler(authManager, tokenStore)))

	// TG bot 相关 API(单前缀,handler 内部按 path 分发):
	//   - invites CRUD(admin web UI 用)
	//   - bind/unbind/user-by-tg/user-summary/user-subscriptions/user-nodes(独立 TG bot 用)
	mux.Handle("/api/admin/tgbot/", auth.RequireAdmin(tokenStore, userRepo, tgbotAPIHandler))
	mux.Handle("/api/admin/users", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserListHandler(repo)))
	userCreateHandler := handler.NewUserCreateHandler(repo)
	mux.Handle("/api/admin/users/create", auth.RequireAdmin(tokenStore, userRepo, userCreateHandler))
	// /api/admin/users/delete 依赖 remoteManageHandler + limiterPusher 做 xray client 清理，注册下移到 ~line 348 之后
	// /api/admin/users/status (启用/禁用) 同样依赖 remoteManageHandler + limiterPusher,见同区
	mux.Handle("/api/admin/users/reset-password", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserResetPasswordHandler(repo)))
	mux.Handle("/api/admin/users/remark", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserRemarkHandler(repo)))
	mux.Handle("/api/admin/users/short-code", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserShortCodeHandler(repo)))
	mux.Handle("/api/admin/users/update-email", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserUpdateEmailHandler(repo)))
	mux.Handle("/api/admin/users/subaccounts", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserSubaccountsHandler(repo)))
	mux.Handle("/api/admin/users/", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserSubscriptionsHandler(repo)))
	mux.Handle("/api/admin/subscriptions", auth.RequireAdmin(tokenStore, userRepo, handler.NewSubscriptionAdminHandler(subscribeDir, repo)))
	mux.Handle("/api/admin/subscriptions/", auth.RequireAdmin(tokenStore, userRepo, handler.NewSubscriptionAdminHandler(subscribeDir, repo)))
	mux.Handle("/api/admin/subscribe-files", auth.RequireToken(tokenStore, userRepo, handler.NewSubscribeFilesHandler(repo)))
	mux.Handle("/api/admin/subscribe-files/", auth.RequireToken(tokenStore, userRepo, handler.NewSubscribeFilesHandler(repo)))
	mux.Handle("/api/admin/rules/", auth.RequireAdmin(tokenStore, userRepo, http.StripPrefix("/api/admin/rules/", handler.NewRuleEditorHandler(subscribeDir, repo))))
	mux.Handle("/api/admin/rule-templates", auth.RequireToken(tokenStore, userRepo, handler.NewRuleTemplatesHandler(repo)))
	mux.Handle("/api/admin/rule-templates/", auth.RequireToken(tokenStore, userRepo, handler.NewRuleTemplatesHandler(repo)))
	// 在remoteManageHandler之后注册的节点处理程序（见下文）
	mux.Handle("/api/admin/sync-external-subscriptions", auth.RequireAdmin(tokenStore, userRepo, handler.NewSyncExternalSubscriptionsHandler(repo, subscribeDir)))
	mux.Handle("/api/admin/sync-external-subscription", auth.RequireAdmin(tokenStore, userRepo, handler.NewSyncSingleExternalSubscriptionHandler(repo, subscribeDir)))
	// 同步 handler 本身按 context username 限定范围(syncExternalSubscriptionsManual 只同步本人订阅),
	// 普通用户也应能同步自己导入的外部订阅。新增 user 路由(RequireToken)避免普通用户撞 RequireAdmin 的 403;
	// admin 路由保留兼容旧前端。
	mux.Handle("/api/user/sync-external-subscriptions", auth.RequireToken(tokenStore, userRepo, handler.NewSyncExternalSubscriptionsHandler(repo, subscribeDir)))
	mux.Handle("/api/user/sync-external-subscription", auth.RequireToken(tokenStore, userRepo, handler.NewSyncSingleExternalSubscriptionHandler(repo, subscribeDir)))
	mux.Handle("/api/admin/rules/latest", auth.RequireAdmin(tokenStore, userRepo, handler.NewRuleMetadataHandler(subscribeDir, repo)))
	mux.Handle("/api/admin/custom-rules", auth.RequireToken(tokenStore, userRepo, handler.NewCustomRulesHandler(repo)))
	mux.Handle("/api/admin/custom-rules/", auth.RequireToken(tokenStore, userRepo, handler.NewCustomRuleHandler(repo)))
	mux.Handle("/api/admin/apply-custom-rules", auth.RequireToken(tokenStore, userRepo, handler.NewApplyCustomRulesHandler(repo)))
	mux.Handle("/api/admin/override-scripts", auth.RequireToken(tokenStore, userRepo, handler.NewOverrideScriptsHandler(repo)))
	mux.Handle("/api/admin/override-scripts/", auth.RequireToken(tokenStore, userRepo, handler.NewOverrideScriptsHandler(repo)))
	mux.Handle("/api/admin/templates", auth.RequireToken(tokenStore, userRepo, handler.NewTemplatesHandler(repo)))
	mux.Handle("/api/admin/templates/", auth.RequireToken(tokenStore, userRepo, handler.NewTemplateHandler(repo)))
	mux.Handle("/api/admin/templates/convert", auth.RequireToken(tokenStore, userRepo, handler.NewTemplateConvertHandler()))
	mux.Handle("/api/admin/templates/fetch-source", auth.RequireToken(tokenStore, userRepo, handler.NewTemplateFetchSourceHandler()))
	mux.Handle("/api/admin/backup/download", auth.RequireAdmin(tokenStore, userRepo, handler.NewBackupDownloadHandler(repo)))
	mux.Handle("/api/admin/backup/restore", auth.RequireAdmin(tokenStore, userRepo, handler.NewBackupRestoreHandler(repo)))
	mux.Handle("/api/admin/update/status", auth.RequireAdmin(tokenStore, userRepo, handler.NewUpdateStatusHandler()))
	mux.Handle("/api/admin/update/check", auth.RequireAdmin(tokenStore, userRepo, handler.NewUpdateCheckHandler()))
	mux.Handle("/api/admin/update/apply", auth.RequireAdmin(tokenStore, userRepo, handler.NewUpdateApplyHandler()))
	mux.Handle("/api/admin/update/apply-sse", auth.RequireAdmin(tokenStore, userRepo, handler.NewUpdateApplySSEHandler()))
	// This endpoint is used only by the root-owned update helper over loopback
	// with a one-time transaction token. It does not expose a public health API.
	mux.Handle("/api/internal/update-health", handler.NewUpdateHealthHandler())
	mux.Handle("/api/admin/proxy-groups/sync", auth.RequireAdmin(tokenStore, userRepo, handler.NewProxyGroupsSyncHandler(repo, proxyGroupsStore)))

	// Template V3 端点（仅限管理员）
	templateV3Handler := handler.NewTemplateV3Handler(repo)
	mux.Handle("/api/admin/template-v3", auth.RequireToken(tokenStore, userRepo, templateV3Handler))
	mux.Handle("/api/admin/template-v3/", auth.RequireToken(tokenStore, userRepo, templateV3Handler))

	// 包管理端点（仅限管理员）— list/create 不依赖 limiterPusher;delete 需解绑用户,延后到 remoteManageHandler/limiterPusher 创建后注册
	mux.Handle("/api/admin/packages", auth.RequireAdmin(tokenStore, userRepo, handler.NewPackageListHandler(repo)))
	packageCreateHandler := handler.NewPackageCreateHandler(repo)
	packageCreateHandler.SetCapabilityManager(capabilityManager)
	mux.Handle("/api/admin/packages/create", auth.RequireAdmin(tokenStore, userRepo, packageCreateHandler))

	// 用户端点（所有经过身份验证的用户）
	mux.Handle("/api/proxy-groups", auth.RequireToken(tokenStore, userRepo, handler.NewProxyGroupsHandler(proxyGroupsStore)))
	mux.Handle("/api/user/2fa/status", auth.RequireToken(tokenStore, userRepo, handler.NewTwoFactorStatusHandler(repo)))
	mux.Handle("/api/user/2fa/setup", auth.RequireToken(tokenStore, userRepo, handler.NewTwoFactorSetupHandler(authManager, repo)))
	mux.Handle("/api/user/2fa/verify-setup", auth.RequireToken(tokenStore, userRepo, handler.NewTwoFactorVerifySetupHandler(repo)))
	mux.Handle("/api/user/2fa/disable", auth.RequireToken(tokenStore, userRepo, handler.NewTwoFactorDisableHandler(authManager, repo)))
	mux.Handle("/api/user/password", auth.RequireToken(tokenStore, userRepo, handler.NewPasswordHandler(authManager)))
	mux.Handle("/api/user/profile", auth.RequireToken(tokenStore, userRepo, handler.NewProfileHandler(repo)))
	mux.Handle("/api/user/settings", auth.RequireToken(tokenStore, userRepo, handler.NewUserSettingsHandler(repo, tokenStore)))
	mux.Handle("/api/user/config", auth.RequireToken(tokenStore, userRepo, handler.NewUserConfigHandler(repo)))
	mux.Handle("/api/user/token", auth.RequireToken(tokenStore, userRepo, handler.NewUserTokenHandler(repo)))
	// 代理集合(Clash proxy-provider)配置 — 用户自己 CRUD;handler 内做 username 隔离
	mux.Handle("/api/user/proxy-provider-configs", auth.RequireToken(tokenStore, userRepo, handler.NewProxyProviderConfigsHandler(repo)))
	// 每用户 API 令牌(供 MCP / 程序化访问);明文仅创建时返回一次
	mux.Handle("/api/user/api-tokens", auth.RequireToken(tokenStore, userRepo, handler.NewUserAPITokensHandler(repo)))
	mux.Handle("/api/user/api-tokens/", auth.RequireToken(tokenStore, userRepo, handler.NewUserAPITokensHandler(repo)))
	mux.Handle("/api/user/external-subscriptions", auth.RequireToken(tokenStore, userRepo, handler.NewExternalSubscriptionsHandler(repo)))
	mux.Handle("/api/user/external-subscriptions/nodes", auth.RequireToken(tokenStore, userRepo, handler.NewExternalSubscriptionNodesHandler(repo)))
	mux.Handle("/api/user/external-subscriptions/check-filter", auth.RequireToken(tokenStore, userRepo, handler.NewExternalSubscriptionCheckFilterHandler(repo)))
	// Debug日志相关endpoint
	mux.Handle("/api/user/debug/", auth.RequireToken(tokenStore, userRepo, handler.NewDebugHandler(repo)))

	mux.Handle("/api/traffic/summary", auth.RequireToken(tokenStore, userRepo, trafficHandler))
	mux.Handle("/api/traffic/summary/aggregated", auth.RequireToken(tokenStore, userRepo, trafficHandler))
	mux.Handle("/api/subscriptions", auth.RequireToken(tokenStore, userRepo, handler.NewSubscriptionListHandler(repo)))
	mux.Handle("/api/user/package-subscribe", auth.RequireToken(tokenStore, userRepo, packageSubscribeHandler))
	mux.Handle("/api/dns/resolve", auth.RequireToken(tokenStore, userRepo, handler.NewDNSHandler()))
	mux.Handle("/api/subscribe-files", auth.RequireToken(tokenStore, userRepo, handler.NewSubscribeFilesListHandler(repo)))
	mux.Handle("/api/clash/subscribe", handler.NewSubscriptionEndpoint(tokenStore, repo, subscribeDir))

	// Xray 管理端点（经过身份验证的用户）
	xrayHandler := handler.NewXrayHandler(repo)
	mux.Handle("/api/xray/outbound/add", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.AddOutbound)))
	mux.Handle("/api/xray/outbound/remove", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.RemoveOutbound)))
	mux.Handle("/api/xray/outbound/list", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.ListOutbounds)))
	mux.Handle("/api/xray/stats", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.GetStats)))
	mux.Handle("/api/xray/stats/system", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(xrayHandler.GetSystemStats)))

	// 流量收集器（早期创建，以便可以与处理程序共享）
	trafficCollector := traffic.NewCollector(repo)
	// 主控本机自采间隔跟随「上报间隔」(dashboard_refresh_interval_ms,会同步给所有 agent),
	// 与 Agent 保持一致;未设置时默认每秒上报。speed 仍用 speed_collect_interval。
	reportMs := 1000
	if val, _ := repo.GetSystemSetting(context.Background(), "dashboard_refresh_interval_ms"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 1000 && n <= 60000 {
			reportMs = n
		}
	}
	trafficCollector.SetInterval(time.Duration(reportMs) * time.Millisecond)
	if systemConfig.SpeedCollectInterval > 0 {
		trafficCollector.SetSpeedInterval(time.Duration(systemConfig.SpeedCollectInterval) * time.Second)
	}

	// Xray 服务器处理程序（远程服务器管理复用）
	xrayServerHandler := handler.NewXrayServerHandler(repo, trafficCollector, cryptoConfig)

	// 面向浏览器的实时数据推送 WS(替代前端高频轮询):RequireToken 认(支持 ?token= query 参数),
	// hub 内按 admin/user 角色区分推送内容。数据源复用 xrayServerHandler.BuildRemoteServersList。
	dashboardWSHub := handler.NewDashboardWSHub(repo, xrayServerHandler, getAllowedOrigins())
	mux.Handle("/api/ws/dashboard", auth.RequireToken(tokenStore, userRepo, dashboardWSHub))

	// 远程服务器管理端点（仅限管理员）
	mux.Handle("/api/admin/remote-servers", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.ListRemoteServers)))
	mux.Handle("/api/admin/remote-servers/create", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.CreateRemoteServer)))
	mux.Handle("/api/admin/remote-servers/reveal-token", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.RevealServerToken)))
	// 接入分享服务器(消费方)
	mux.Handle("/api/admin/remote-servers/add-shared", auth.RequireAdmin(tokenStore, userRepo, handler.NewAddSharedServerHandler(repo)))
	mux.Handle("/api/admin/remote-servers/update", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.UpdateRemoteServer)))
	mux.Handle("/api/admin/remote-servers/reorder", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.ReorderRemoteServers)))
	mux.Handle("/api/admin/remote-servers/delete-impact", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.GetRemoteServerDeleteImpact)))
	mux.Handle("/api/admin/remote-servers/delete", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.DeleteRemoteServer)))
	mux.Handle("/api/admin/check-same-ip", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayServerHandler.CheckSameIP)))

	// 远程服务器公共端点（无管理员身份验证，基于令牌）
	mux.Handle("/api/remote/heartbeat", http.HandlerFunc(xrayServerHandler.RemoteHeartbeat))
	mux.Handle("/api/remote/token/refresh", http.HandlerFunc(xrayServerHandler.RefreshRemoteToken))
	mux.Handle("/api/remote/install.sh", http.HandlerFunc(xrayServerHandler.GetRemoteInstallScript))
	mux.Handle("/api/remote/expiry-guard", http.HandlerFunc(xrayServerHandler.GetExpiryGuardAsset))
	mux.Handle("/api/remote/install-begin", http.HandlerFunc(xrayServerHandler.BeginRemoteInstallation))
	mux.Handle("/api/remote/install-renew", http.HandlerFunc(xrayServerHandler.RenewRemoteInstallation))
	mux.Handle("/api/remote/install-quiesce", http.HandlerFunc(xrayServerHandler.QuiesceRemoteInstallation))
	mux.Handle("/api/remote/install-abort", http.HandlerFunc(xrayServerHandler.AbortRemoteInstallation))
	mux.Handle("/api/remote/management-ready", http.HandlerFunc(xrayServerHandler.VerifyRemoteManagementPorts))
	mux.Handle(handler.AgentUninstallCompletePath, http.HandlerFunc(xrayServerHandler.HandleAgentUninstallComplete))
	mux.Handle("/api/remote/install-prepare", http.HandlerFunc(xrayServerHandler.PrepareRemoteInstallation))
	mux.Handle("/api/remote/install-finalize", http.HandlerFunc(xrayServerHandler.FinalizeRemoteInstallation))

	// 流量采集与统计
	trafficApiHandler := handler.NewTrafficHandler(repo, trafficCollector)
	// Public-probe host metrics are intentionally process-local. They are fed
	// by authenticated Agent reports and vanish on a control-plane restart
	// instead of becoming stale persistent monitoring data.
	probeMetricsStore := handler.NewProbeMetricsStore()
	xrayServerHandler.SetProbeMetricsStore(probeMetricsStore)
	remoteTrafficHandler := handler.NewRemoteTrafficHandler(repo, trafficCollector, cryptoConfig)
	remoteTrafficHandler.SetProbeMetricsStore(probeMetricsStore)
	mux.Handle("/api/admin/traffic", auth.RequireAdmin(tokenStore, userRepo, trafficApiHandler))
	mux.Handle("/api/admin/traffic/", auth.RequireAdmin(tokenStore, userRepo, trafficApiHandler))
	mux.Handle("/api/remote/traffic", remoteTrafficHandler)
	// 把 traffic 汇总/明细 handler 注入实时 WS hub,快照复用其 JSON 输出(traffic-summary + admin-traffic)。
	dashboardWSHub.SetTrafficHandlers(trafficHandler, trafficApiHandler)

	// 远程速度处理程序（来自子服务器的 HTTP 推送）
	remoteSpeedHandler := handler.NewRemoteSpeedHandler(repo, cryptoConfig)
	mux.Handle("/api/remote/speed", remoteSpeedHandler)

	// 远程服务器的 WebSocket 处理程序
	remoteWSHandler := handler.NewRemoteWSHandler(repo, trafficCollector)
	remoteWSHandler.SetCrypto(cryptoConfig)
	remoteWSHandler.SetProbeMetricsStore(probeMetricsStore)
	mux.Handle("/api/remote/ws", remoteWSHandler)

	// 限速配置推送器
	limiterPusher := handler.NewLimiterConfigPusher(repo, remoteWSHandler)
	limiterPusher.SetCapabilityManager(capabilityManager)
	remoteWSHandler.SetLimiterPusher(limiterPusher)
	remoteWSHandler.SetCapabilityManager(capabilityManager)
	xrayServerHandler.SetLimiterPusher(limiterPusher)
	xrayServerHandler.SetCapabilityManager(capabilityManager)

	// 远程服务器管理代理（将命令转发到子服务器）
	remoteManageHandler := handler.NewRemoteManageHandler(repo, remoteWSHandler)
	remoteManageHandler.SetCrypto(cryptoConfig)
	// inbound cache: 套餐绑/换绑时 in-memory 算 cred 用,从 xray config snapshot 派生。
	inboundCache := handler.NewInboundCache()
	remoteManageHandler.SetInboundCache(inboundCache)
	// 启动时预热(异步,不阻塞 main):从 DB current snapshot 把每台 server 的 inbound 索引拉进 cache。
	// 新 agent 第一次连上来前,套餐绑套餐如果选了这个 server 的 inbound,有 DB snapshot 就立即 cache hit。
	go func() {
		ctx := context.Background()
		servers, err := repo.ListRemoteServers(ctx)
		if err != nil {
			log.Printf("[InboundCache] warmup list servers failed: %v", err)
			return
		}
		for _, s := range servers {
			inboundCache.WarmupFromDB(ctx, repo, s.ID)
		}
		log.Printf("[InboundCache] warmup done for %d servers", len(servers))
	}()
	// agent 重连后校正 embedded→external 漂移。
	remoteWSHandler.SetXrayModeCorrectCallback(remoteManageHandler.CorrectXrayModeDrift)
	xrayServerHandler.SetRemoteManager(remoteManageHandler)
	xrayServerHandler.SetWSHandler(remoteWSHandler)

	// Managed self-service nodes: admins publish eligible physical inbounds and
	// grant per-server access; users only select an offer and never receive raw
	// inbound configuration through the management API.
	managedNodesHandler := handler.NewManagedNodesHandler(repo, remoteManageHandler, limiterPusher)
	managedReconcileCtx, stopManagedReconciler := context.WithCancel(context.Background())
	managedNodesHandler.StartReconciler(managedReconcileCtx)
	mux.Handle("/api/admin/managed-node-offers", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleOffers)))
	mux.Handle("/api/admin/managed-node-offers/{id}", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleOffer)))
	mux.Handle("/api/admin/users/{username}/server-grants", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleAdminGrants)))
	mux.Handle("/api/admin/users/{username}/server-grants/{id}", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleAdminGrant)))
	mux.Handle("/api/admin/users/{username}/server-grants/{id}/retry", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleAdminGrantRetry)))
	mux.Handle("/api/admin/users/{username}/managed-nodes", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleAdminManagedNodes)))
	mux.Handle("/api/admin/users/{username}/managed-nodes/{id}/limits", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleAdminManagedNodeLimits)))
	mux.Handle("/api/admin/users/{username}/managed-nodes/{id}/retry", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleAdminManagedNodeRetry)))
	mux.Handle("/api/user/managed-nodes", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleUserManagedNodes)))
	mux.Handle("/api/user/managed-nodes/{id}", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleUserManagedNode)))
	mux.Handle("/api/user/managed-nodes/{id}/retry", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(managedNodesHandler.HandleUserManagedNodeRetry)))

	// Forwarding management: admins define ordered server routes and grants;
	// users can only create forwards against their own effective grants and
	// managed-node access. Remote mutations go through the signed expiry guard.
	forwardingHandler := handler.NewForwardingHandler(repo, handler.NewForwardingGuardDeployer(managedNodesHandler))
	forwardingReconcileCtx, stopForwardingReconciler := context.WithCancel(context.Background())
	forwardingHandler.StartReconciler(forwardingReconcileCtx)
	mux.Handle("/api/admin/tunnel-templates", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminTunnelTemplates)))
	mux.Handle("/api/admin/tunnel-templates/preflight", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminTunnelTemplatePreflight)))
	mux.Handle("/api/admin/tunnel-templates/{id}", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminTunnelTemplate)))
	mux.Handle("/api/admin/tunnel-templates/{id}/state", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminTunnelTemplateState)))
	mux.Handle("/api/admin/users/{username}/tunnel-grants", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminUserTunnelGrants)))
	mux.Handle("/api/admin/users/{username}/tunnel-grants/{id}", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminUserTunnelGrant)))
	mux.Handle("/api/admin/users/{username}/tunnel-grants/{id}/{action}", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminUserTunnelGrantAction)))
	mux.Handle("/api/admin/forwards", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminForwards)))
	mux.Handle("/api/admin/forwards/{id}", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminForward)))
	mux.Handle("/api/admin/forwards/{id}/{action}", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleAdminForward)))
	mux.Handle("/api/user/tunnel-grants", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleUserTunnelGrants)))
	mux.Handle("/api/user/forwards", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleUserForwards)))
	mux.Handle("/api/user/forwards/preflight", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleUserForwardPreflight)))
	mux.Handle("/api/user/forwards/{id}", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleUserForward)))
	mux.Handle("/api/user/forwards/{id}/{action}", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(forwardingHandler.HandleUserForward)))

	// DDNS 管理器:agent 心跳触发 IPChanged 时同步 pull_address 域名的 A/AAAA 记录到新 IP。
	// reconciler 跑后台 5min ticker 兜底失败重试(IPChanged 已消费 → 后续心跳 IP 不变就不会再触发,
	// 没 reconciler 的话 DDNS 失败就永远卡住)。
	ddnsManager := ddns.NewManager(repo)
	go ddnsManager.StartReconciler(context.Background())
	remoteWSHandler.SetDDNSManager(ddnsManager)
	xrayServerHandler.SetDDNSManager(ddnsManager)
	// 状态查询(前端 Tooltip 用) + 手动同步(前端"立即重试"按钮),都走子路径 /api/admin/servers/{id}/ddns-*
	ddnsAdminHandler := handler.NewDDNSAdminHandler(repo, ddnsManager)
	mux.Handle("/api/admin/servers/", auth.RequireAdmin(tokenStore, userRepo, ddnsAdminHandler))

	// 一次性老格式凭据 email 迁移(ae60947 漏回填存量)。
	// 启动延迟 60s — 等 agent WS 重连。失败的行下次启动重试,全部成功才写 done 标记。
	handler.NewCredentialEmailMigrator(repo, remoteManageHandler).Start(context.Background(), 60*time.Second)

	// 一次性补写 user_inbound_configs 孤儿 — collector 有 (server, email) 流量但表里
	// 没该用户的 inbound 持有记录,导致 /api/admin/traffic/user-nodes & node-users 反查空。
	// 只补 role=user 的真实付费用户,admin 自用走 handler fallback,不污染本表。
	// 延迟 90s — 比 CredentialEmailMigrator(60s)晚跑,确保它先把老 email 迁完再补剩下的。
	handler.NewOrphanInboundConfigBackfiller(repo).Start(context.Background(), 90*time.Second)

	// 凌晨 03:30 扫一次,清理 xray inbound 上 db 已无主的 client(残留 vmess/trojan UUID 等)。
	// 触发场景:用户删除时 server 离线 → push remove 失败 → db 已清但 xray config 仍残留。
	handler.NewOrphanXrayClientCleaner(repo, remoteManageHandler).Start(context.Background())

	// 依赖 limiterPusher 的端点
	packageUpdateHandler := handler.NewPackageUpdateHandler(repo, remoteManageHandler, limiterPusher)
	packageUpdateHandler.SetCapabilityManager(capabilityManager)
	mux.Handle("/api/admin/packages/update", auth.RequireAdmin(tokenStore, userRepo, packageUpdateHandler))
	packageAssignHandler := handler.NewPackageAssignHandler(repo, remoteManageHandler, limiterPusher)
	tgbotAPIHandler.SetPackageAssign(packageAssignHandler) // 让 TGBOT 注册/兑换的套餐走同一套下发
	mux.Handle("/api/admin/packages/assign", auth.RequireAdmin(tokenStore, userRepo, packageAssignHandler))
	// 快捷续期:复用 packageAssignHandler 的 AssignAndProvision(samePackage 快路径),只延长 package_end_date
	mux.Handle("/api/admin/users/extend", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserExtendHandler(packageAssignHandler)))
	mux.Handle("/api/admin/packages/unassign", auth.RequireAdmin(tokenStore, userRepo, handler.NewPackageUnassignHandler(repo, remoteManageHandler, limiterPusher)))
	// 删除套餐:解绑所有绑定用户(移除入站凭据/清 package_id/删套餐订阅)后再删,故依赖 remoteManageHandler/limiterPusher
	mux.Handle("/api/admin/packages/", auth.RequireAdmin(tokenStore, userRepo, handler.NewPackageDeleteHandler(repo, remoteManageHandler, limiterPusher)))
	// 服务器分享:拥有方生成/管理分享令牌
	mux.Handle("/api/admin/server-share/", auth.RequireAdmin(tokenStore, userRepo, handler.NewServerShareHandler(repo, capabilityManager)))
	speedTesterWS := handler.NewSpeedTesterWSHandler(repo)
	speedTesterWS.SetCapabilityManager(capabilityManager)
	mux.Handle("/api/speedtest/tester/ws", speedTesterWS) // 家用测速端反向连入(token 认证,无 JWT)
	speedTestHandler := handler.NewSpeedTestHandler(repo, capabilityManager)
	speedTestHandler.SetTesterWS(speedTesterWS)
	mux.Handle("/api/admin/speedtest/", auth.RequireAdmin(tokenStore, userRepo, speedTestHandler))
	lineSpeedTestHandler := handler.NewLineSpeedTestHandler(repo, remoteManageHandler)
	mux.Handle("/api/admin/line-speedtest/", auth.RequireAdmin(tokenStore, userRepo, lineSpeedTestHandler))
	// Tunnel(dokodemo 转发入站)聚合管理:跨所有远程/分享服务器列出 protocol==tunnel 入站,供节点管理「Tunnel 管理」弹窗使用
	mux.Handle("/api/admin/tunnels", auth.RequireAdmin(tokenStore, userRepo, handler.NewTunnelsHandler(repo, remoteManageHandler)))
	// 链式端口转发编排:选有序多台服务器建 N 条首尾相接的单跳 tunnel。
	mux.Handle("/api/admin/tunnel-chains", auth.RequireAdmin(tokenStore, userRepo, handler.NewTunnelChainHandler(repo, remoteManageHandler)))
	// 联邦入口(分享令牌鉴权,供其他主控间接管理被分享服务器)
	federationHandler := handler.NewFederationHandler(repo, remoteManageHandler, capabilityManager)
	mux.Handle("/api/federation/manage", federationHandler)
	mux.Handle("/api/federation/server-info", federationHandler)
	mux.Handle("/api/admin/users/limits", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserLimitsHandler(repo, limiterPusher, capabilityManager)))
	mux.Handle("/api/admin/users/traffic-limit", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserTrafficLimitHandler(repo)))
	mux.Handle("/api/admin/users/node-limits", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserNodeLimitsHandler(repo, limiterPusher, capabilityManager)))
	mux.Handle("/api/admin/users/delete", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserDeleteHandler(repo, remoteManageHandler, limiterPusher, managedNodesHandler)))
	mux.Handle("/api/admin/users/status", auth.RequireAdmin(tokenStore, userRepo, handler.NewUserStatusHandler(repo, remoteManageHandler, limiterPusher, tokenStore)))

	// 用户节点管理（普通用户查看套餐节点、管理自己的出站）
	userNodesHandler := handler.NewUserNodesHandler(repo, remoteManageHandler)
	mux.Handle("/api/user/nodes", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(userNodesHandler.HandleListNodes)))
	mux.Handle("/api/user/nodes/outbound", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(userNodesHandler.HandleOutbound)))
	mux.Handle("/api/user/nodes/outbounds", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(userNodesHandler.HandleListOutbounds)))

	// 注册节点处理程序（需要remoteManageHandler进行远程入站清理）
	mux.Handle("/api/admin/nodes", auth.RequireToken(tokenStore, userRepo, handler.NewNodesHandler(repo, subscribeDir, remoteManageHandler)))
	mux.Handle("/api/admin/nodes/", auth.RequireToken(tokenStore, userRepo, handler.NewNodesHandler(repo, subscribeDir, remoteManageHandler)))
	// URI 管理:每个用户 × 其可见节点 的成品分享 URI(后端 substore 生成),仅管理员可用
	mux.Handle("/api/admin/node-uris", auth.RequireAdmin(tokenStore, userRepo, handler.NewNodeURIsHandler(repo)))

	// 路由出站(routed node)管理:给物理节点挂多个虚拟出站节点
	routedOutboundHandler := handler.NewRoutedOutboundHandler(repo, remoteManageHandler)
	mux.Handle("/api/admin/routed-outbound", auth.RequireAdmin(tokenStore, userRepo, routedOutboundHandler))
	// 用户私有路由出站(routed_owner='user'):普通用户为自己创建/删除/查询专属出站
	mux.Handle("/api/user/routed-outbound", auth.RequireToken(tokenStore, userRepo, handler.NewUserRoutedOutboundHandler(repo, remoteManageHandler)))

	// 从兼容面板备份导入数据。
	migrateHandler := handler.NewMigrateHandler(repo, remoteManageHandler)
	mux.Handle("/api/admin/migrate/fetch-legacy-backup", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.FetchLegacyBackup)))
	mux.Handle("/api/admin/migrate/upload-legacy-backup", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.UploadLegacyBackup)))
	mux.Handle("/api/admin/migrate/cleanup", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.CleanupLegacySession)))
	mux.Handle("/api/admin/migrate/import-legacy-backup", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.ImportLegacyBackup)))
	mux.Handle("/api/admin/migrate/distinct-node-servers", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.DistinctNodeServers)))
	mux.Handle("/api/admin/migrate/patch-client-emails", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.PatchClientEmails)))
	mux.Handle("/api/admin/migrate/takeover-external-xray", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(migrateHandler.TakeoverExternalXray)))

	// 初始化事件系统以进行入站同步
	eventBus := event.GetBus()
	nodeSyncListener := event.NewNodeSyncListener(repo, remoteManageHandler.InboundToClashProxyByServerID)
	eventBus.Subscribe(event.EventInboundAdded, nodeSyncListener)
	eventBus.Subscribe(event.EventInboundRemoved, nodeSyncListener)
	eventBus.Subscribe(event.EventInboundUpdated, nodeSyncListener)
	log.Println("[Event] Inbound event listeners registered")

	mux.Handle("/api/admin/remote/services/status", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleServicesStatus)))
	mux.Handle("/api/admin/remote/services/control", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleServiceControl)))
	mux.Handle("/api/admin/remote/xray/install", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayInstall)))
	mux.Handle("/api/admin/remote/xray/versions", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayVersions)))
	mux.Handle("/api/admin/remote/xray/remove", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayRemove)))
	mux.Handle("/api/admin/remote/xray/config", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayConfig)))
	mux.Handle("/api/admin/remote/xray/test-config", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayTestConfig)))
	mux.Handle("/api/admin/remote/xray/config/files", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayConfigFiles)))
	mux.Handle("/api/admin/remote/nginx/install", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxInstall)))
	mux.Handle("/api/admin/remote/nginx/remove", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxRemove)))
	// Cloudflare WARP — 每个 agent 各自注册 + 注入 warp-v4 / warp-v6 双 outbound
	mux.Handle("/api/admin/remote/warp/install", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleWarpInstall)))
	mux.Handle("/api/admin/remote/warp/status", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleWarpStatus)))
	mux.Handle("/api/admin/remote/warp/license", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleWarpLicense)))
	mux.Handle("/api/admin/remote/warp/remove", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleWarpRemove)))
	// SSE 流安装/删除
	mux.Handle("/api/admin/remote/xray/install-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayInstallStream)))
	mux.Handle("/api/admin/remote/xray/remove-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXrayRemoveStream)))
	mux.Handle("/api/admin/remote/nginx/install-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxInstallStream)))
	mux.Handle("/api/admin/remote/nginx/remove-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxRemoveStream)))
	mux.Handle("/api/admin/remote/agent/upgrade-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleAgentUpgradeStream)))
	mux.Handle("/api/admin/remote/agent/uninstall-stream", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleAgentUninstallStream)))
	mux.Handle("/api/admin/remote/agent/version-info", auth.RequireAdmin(tokenStore, userRepo, handler.NewAgentVersionHandler(remoteManageHandler, repo)))
	mux.Handle("/api/admin/remote/nginx/config", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxConfig)))
	mux.Handle("/api/admin/remote/nginx/config/files", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxConfigFiles)))
	mux.Handle("/api/admin/remote/nginx/servers-list", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleNginxServersList)))
	mux.Handle("/api/admin/remote/system/info", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleSystemInfo)))
	// 远程服务器Xray入站/出站/路由管理
	mux.Handle("/api/admin/remote/inbounds", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleInbounds)))
	mux.Handle("/api/admin/managed-nodes/create", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleCreateManagedNode)))
	mux.Handle("/api/admin/managed-inbound-resources", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleManagedInboundResources)))
	mux.Handle("/api/admin/managed-inbound-resources/", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleManagedInboundResources)))
	mux.Handle("/api/admin/remote/outbounds", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleOutbounds)))
	mux.Handle("/api/admin/remote/routing", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRouting)))
	mux.Handle("/api/admin/remote/scan", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleScan)))
	mux.Handle("/api/admin/remote/xray/system-config", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleXraySystemConfig)))
	mux.Handle("/api/admin/remote/reality-domains", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleRealityDomains)))
	mux.Handle("/api/admin/remote/reality-domains/custom", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleAddCustomRealityDomain)))
	mux.Handle("/api/admin/remote/reality-domains/custom/delete", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleDeleteCustomRealityDomain)))
	mux.Handle("/api/admin/remote/setup-ssl", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleSetupSSL)))
	mux.Handle("/api/admin/remote/deploy-steal-self", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleDeployStealSelfConfig)))
	mux.Handle("/api/admin/remote/sync-nodes", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleSyncInboundsToNodes)))
	mux.Handle("/api/admin/remote/switch-steal-mode", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleSwitchStealMode)))
	mux.Handle("/api/admin/remote/website/add", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleAddWebsite)))
	mux.Handle("/api/admin/remote/website/validate", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleValidateSite)))
	mux.Handle("/api/admin/remote/user-speeds", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleUserSpeeds)))
	// 令牌重置端点
	// xray 配置 snapshot / 跑路恢复 / 历史回滚
	xraySnapshotHandler := handler.NewXraySnapshotHandler(repo, remoteManageHandler)
	mux.Handle("/api/admin/xray-snapshots/", auth.RequireAdmin(tokenStore, userRepo, xraySnapshotHandler))
	// 慢通道:把 services/status + recovery-status handler + WS handler 注入实时 hub(主控定时查在线服务器状态,消 N+1)。
	dashboardWSHub.SetStatusHandlers(http.HandlerFunc(remoteManageHandler.HandleServicesStatus), xraySnapshotHandler, remoteWSHandler)

	mux.Handle("/api/admin/remote-servers/reset-server-token", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleResetServerToken)))
	mux.Handle("/api/admin/remote-servers/reset-agent-token", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleResetAgentToken)))
	mux.Handle("/api/admin/remote-servers/reset-all-tokens", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(remoteManageHandler.HandleResetAllTokens)))

	// 节点连通性端点。普通用户只可按可见 node_id 探测；受管 WireGuard
	// 通过 Agent 确认入站运行状态并测量管理链路 RTT。
	mux.Handle("/api/admin/tcping", auth.RequireToken(tokenStore, userRepo, handler.NewTCPingHandler(repo, remoteManageHandler)))
	mux.Handle("/api/admin/tcping/batch", auth.RequireToken(tokenStore, userRepo, handler.NewTCPingBatchHandler(repo, remoteManageHandler)))

	// 子服务器模式配置
	// 确定我们是否处于儿童/远程模式：
	// 1. 配置文件设置了remote_token，或者
	// 2. 环境变量 RELAYDOCK_MODE=child
	var childClient *child.Client
	var childManageHandler *handler.ChildManageHandler
	isChildMode := false
	var masterURL, masterToken, connectionMode, childAPIToken string

	// 首先检查配置文件
	if config != nil && config.RemoteToken != "" {
		isChildMode = true
		masterURL = config.MasterServer
		masterToken = config.RemoteToken
		connectionMode = config.ConnectionMode
		childAPIToken = config.ChildAPIToken
		log.Printf("[Child Mode] Detected from config file (remote_token present)")
	}

	// 环境变量可以覆盖或补充配置
	if os.Getenv("RELAYDOCK_MODE") == "child" {
		isChildMode = true
	}
	if envMasterURL := os.Getenv("RELAYDOCK_MASTER_URL"); envMasterURL != "" {
		masterURL = envMasterURL
	}
	if envMasterToken := os.Getenv("RELAYDOCK_MASTER_TOKEN"); envMasterToken != "" {
		masterToken = envMasterToken
	}
	if envConnectionMode := os.Getenv("RELAYDOCK_CONNECTION_MODE"); envConnectionMode != "" {
		connectionMode = envConnectionMode
	}
	if envChildAPIToken := os.Getenv("RELAYDOCK_CHILD_API_TOKEN"); envChildAPIToken != "" {
		childAPIToken = envChildAPIToken
	}

	// 默认连接模式 - 使用"auto"进行自动回退（websocket -> http -> pull）
	if connectionMode == "" {
		connectionMode = "auto"
	}

	if isChildMode {
		if masterURL != "" && masterToken != "" {
			childConfig := child.Config{
				MasterURL:             masterURL,
				Token:                 masterToken,
				ConnectionMode:        connectionMode,
				TrafficReportInterval: time.Duration(systemConfig.TrafficCollectInterval) * time.Second,
				SpeedReportInterval:   time.Duration(systemConfig.SpeedCollectInterval) * time.Second,
				HeartbeatInterval:     time.Duration(systemConfig.HeartbeatInterval) * time.Second,
			}
			childClient = child.NewClient(childConfig, trafficCollector, repo)
			log.Printf("[Child Mode] Configured: master=%s, mode=%s", masterURL, connectionMode)
		} else {
			log.Printf("[Child Mode] Warning: master_server or remote_token not set")
		}

		// 为pull模式注册子 API
		if childClient != nil {
			childAPIHandler := handler.NewChildAPIHandler(childClient, childAPIToken)
			mux.Handle("/api/child/traffic", childAPIHandler)
			mux.Handle("/api/child/speed", http.HandlerFunc(childAPIHandler.ServeSpeedHTTP))
			log.Printf("[Child Mode] Child API registered at /api/child/traffic and /api/child/speed")
		}

		// 注册子管理API（用于主机远程控制）
		childManageHandler = handler.NewChildManageHandler(masterToken)

		// 启动时检查并补全 Xray 配置
		go func() {
			// 延迟 2 秒，等待服务稳定
			time.Sleep(2 * time.Second)
			result := childManageHandler.EnsureXrayConfig()
			if result.Modified {
				log.Printf("[Child Mode] Xray config auto-completed: added %v", result.AddedSections)
				if result.Error == "" {
					log.Printf("[Child Mode] Xray restarted after config update")
				}
			}
			if result.Error != "" {
				log.Printf("[Child Mode] Xray config check: %s", result.Error)
			} else if !result.Modified {
				log.Printf("[Child Mode] Xray config OK, no changes needed")
			}
		}()

		mux.Handle("/api/child/services/status", http.HandlerFunc(childManageHandler.HandleServicesStatus))
		mux.Handle("/api/child/services/control", http.HandlerFunc(childManageHandler.HandleServiceControl))
		mux.Handle("/api/child/xray/install", http.HandlerFunc(childManageHandler.HandleXrayInstall))
		mux.Handle("/api/child/xray/remove", http.HandlerFunc(childManageHandler.HandleXrayRemove))
		mux.Handle("/api/child/xray/config", http.HandlerFunc(childManageHandler.HandleXrayConfig))
		mux.Handle("/api/child/xray/config/files", http.HandlerFunc(childManageHandler.HandleXrayConfigFiles))
		mux.Handle("/api/child/xray/system-config", http.HandlerFunc(childManageHandler.HandleXraySystemConfig))
		mux.Handle("/api/child/nginx/install", http.HandlerFunc(childManageHandler.HandleNginxInstall))
		mux.Handle("/api/child/nginx/remove", http.HandlerFunc(childManageHandler.HandleNginxRemove))
		mux.Handle("/api/child/nginx/config", http.HandlerFunc(childManageHandler.HandleNginxConfig))
		mux.Handle("/api/child/nginx/config/files", http.HandlerFunc(childManageHandler.HandleNginxConfigFiles))
		mux.Handle("/api/child/system/info", http.HandlerFunc(childManageHandler.HandleSystemInfo))
		// X射线入站/出站/路由管理
		mux.Handle("/api/child/inbounds", http.HandlerFunc(childManageHandler.HandleInbounds))
		mux.Handle("/api/child/outbounds", http.HandlerFunc(childManageHandler.HandleOutbounds))
		mux.Handle("/api/child/routing", http.HandlerFunc(childManageHandler.HandleRouting))
		mux.Handle("/api/child/scan", http.HandlerFunc(childManageHandler.HandleScan))
		mux.Handle("/api/child/domains/latency", http.HandlerFunc(childManageHandler.HandleDomainLatencyProbe))
		log.Printf("[Child Mode] Management API registered at /api/child/*")
	}

	// Xray 示例 API（仅限管理员）
	xrayExamplesHandler := handler.NewXrayExamplesHandler("Xray-examples")
	mux.Handle("/api/admin/xray-examples", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayExamplesHandler.HandleGetProtocolCombinations)))

	// Xray 密钥生成 API（仅限管理员）
	xrayKeyGenHandler := handler.NewXrayKeyGeneratorHandler()
	mux.Handle("/api/admin/xray/generate-keys", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayKeyGenHandler.GenerateKeys)))
	mux.Handle("/api/admin/xray/generate-x25519", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(xrayKeyGenHandler.GenerateX25519)))

	// 系统设置 API（仅限管理员）
	systemSettingsHandler := handler.NewSystemSettingsHandler(repo, cryptoConfig)
	systemSettingsHandler.SetCollector(trafficCollector)
	systemSettingsHandler.SetWSHandler(remoteWSHandler)
	// 启动时加载加密设置
	if encVal, _ := repo.GetSystemSetting(context.Background(), "require_encryption"); encVal == "true" {
		cryptoConfig.SetRequireEncryption(true)
	}
	// 启动时把 DB 里的默认主题注入到下发的 index.html(无 cookie 的用户首屏据此套主题,无闪烁)
	if theme, _ := repo.GetSystemSetting(context.Background(), handler.DefaultThemeKey); theme != "" {
		web.SetDefaultTheme(theme)
	}
	// 自定义安全阈值(登录/暴力防护/订阅频率)— 写入后 handler 内部热更新 3 个 limiter 单例,无需重启
	mux.Handle("/api/admin/security-settings", auth.RequireAdmin(tokenStore, userRepo, handler.NewSecuritySettingsHandler(repo)))
	// Turnstile 配置自测:前端 widget 验完拿 token,后端用 DB 已存 secret 调 cloudflare siteverify,
	// 返回详细 error_codes 供前端诊断"两 key 配错 / 域名没白名单 / 网络不通"等场景。
	mux.Handle("/api/admin/security-settings/turnstile/test", auth.RequireAdmin(tokenStore, userRepo, handler.NewTurnstileTestHandler(turnstileVerifier)))
	mux.Handle("/api/admin/system-settings/api-token", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(systemSettingsHandler.GetAPIToken)))
	mux.Handle("/api/admin/system-settings/api-token/regenerate", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(systemSettingsHandler.RegenerateAPIToken)))
	mux.Handle("/api/admin/system-settings/master-url", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetMasterURL(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetMasterURL(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/redeem-template", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetRedeemTemplate(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetRedeemTemplate(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 自定义登录页壁纸:管理员读写 + 公开读取(登录页未鉴权时读)
	mux.Handle("/api/admin/system-settings/login-wallpaper", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetLoginWallpaper(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetLoginWallpaper(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.HandleFunc("/api/public/login-wallpaper", systemSettingsHandler.GetLoginWallpaperPublic)
	// 项目品牌:管理员可自定义名称、Logo 和 favicon；登录前也只读公开这三个无敏感字段。
	mux.Handle("/api/admin/system-settings/branding", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetBranding(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetBranding(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.HandleFunc("/api/public/branding", systemSettingsHandler.GetBrandingPublic)

	// 公开端点:伪装探针的只读服务器状态 + 共享 WebSocket 广播。两条路径复用
	// 同一个严格白名单 DTO；伪装关闭时 HTTP 返回 {enabled:false}，WS 返回 404。
	// 走明文(前端 shouldEncrypt 已放行 /api/public/);此处 remoteWSHandler 已构造(见上文)。
	probePublicHandler := handler.NewProbePublicHandler(repo, remoteWSHandler, probeMetricsStore)
	mux.Handle("/api/public/probe-servers", probePublicHandler)
	mux.Handle("/api/public/probe-ws", handler.NewProbeWSHandler(probePublicHandler))

	// 伪装探针配置(开关 + 标题 + 展示的服务器 + 是否显名)
	mux.Handle("/api/admin/system-settings/probe-disguise", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetProbeDisguise(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetProbeDisguise(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 默认主题(flat / pixel):PUT 保存后重读并同步注入到 index.html,让新用户首屏立即用新默认
	mux.Handle("/api/admin/system-settings/default-theme", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetDefaultTheme(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetDefaultTheme(w, r)
			if theme, _ := repo.GetSystemSetting(r.Context(), handler.DefaultThemeKey); theme != "" {
				web.SetDefaultTheme(theme)
			}
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/short-link", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetShortLinkEnabled(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetShortLinkEnabled(w, r)
		default:
			http.Error(w, "��法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 节点名称倍率前缀(开关 + 左右分隔符)
	mux.Handle("/api/admin/system-settings/node-name-multiplier-prefix", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetNodeNameMultiplierPrefix(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetNodeNameMultiplierPrefix(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/intervals", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetIntervals(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetIntervals(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 公开:所有登录用户可拿前端 dashboard 刷新间隔(默认 1000ms,admin 可在系统设置改)
	mux.Handle("/api/system-config/refetch-interval", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(systemSettingsHandler.GetPublicIntervals)))
	// admin:写前端 dashboard 刷新间隔,clamp [1000, 60000] ms
	mux.Handle("/api/admin/system-settings/dashboard-refresh", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(systemSettingsHandler.SetDashboardRefresh)))

	// 用户权限 / 配额(全局策略)
	userPermsHandler := handler.NewUserPermissionsHandler(repo)
	mux.Handle("/api/admin/system-settings/user-permissions", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			userPermsHandler.AdminGet(w, r)
		case http.MethodPut, http.MethodPost:
			userPermsHandler.AdminSet(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	// 普通用户拿自己适用的可见页面 + 配额 + 已用量
	mux.Handle("/api/user/permissions", auth.RequireToken(tokenStore, userRepo, http.HandlerFunc(userPermsHandler.UserGet)))
	mux.Handle("/api/admin/system-settings/agent-log", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetAgentLogEnabled(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetAgentLogEnabled(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/admin/system-settings/override-scripts", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetOverrideScriptsEnabled(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetOverrideScriptsEnabled(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/admin/system-settings/subscription-output-format", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetSubscriptionOutputFormat(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetSubscriptionOutputFormat(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/admin/system-settings/silent-mode", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetSilentMode(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetSilentMode(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/require-encryption", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetRequireEncryption(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetRequireEncryption(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/management-features", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetManagementFeaturesEnabled(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetManagementFeaturesEnabled(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/root-short-links", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetRootShortLinks(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetRootShortLinks(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/admin/system-settings/default-template", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			systemSettingsHandler.GetDefaultTemplate(w, r)
		case http.MethodPut:
			systemSettingsHandler.SetDefaultTemplate(w, r)
		default:
			http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		}
	})))

	// 通知配置 API（仅限管理员）
	notifyConfigHandler := handler.NewNotifyConfigHandler(repo)
	mux.Handle("/api/admin/notify-config", auth.RequireAdmin(tokenStore, userRepo, notifyConfigHandler))
	mux.Handle("/api/admin/notify-config/test", auth.RequireAdmin(tokenStore, userRepo, notifyConfigHandler))

	// 证书管理 API（仅限管理员）
	certHandler := handler.NewCertificateHandler(repo, remoteWSHandler)
	if childManageHandler != nil {
		certHandler.SetLocalDeployer(childManageHandler.DeployCertificateFiles)
	}
	certHandler.SetOnMasterURLChanged(remoteManageHandler.BroadcastMasterURLUpdate)
	certHandler.SetRemoteManage(remoteManageHandler) // 联邦服务器证书下发走拥有方主控
	remoteManageHandler.SetCertificateHandler(certHandler)
	// Refresh the Agent Xray snapshot before using it to reconcile panel-managed
	// certificate material. The latter is content-deduplicated and only restarts
	// Xray when a referenced certificate actually changed.
	remoteWSHandler.SetXrayConfigSyncCallback(func(ctx context.Context, serverID int64, prevStatus string) {
		remoteManageHandler.SyncXrayConfigOnReconnect(ctx, serverID, prevStatus)
		certHandler.SyncManagedXrayCertificatesOnReconnect(ctx, serverID)
	})
	remoteManageHandler.SetStealSelfDeployer(remoteManageHandler.DeployStealSelfConfig)
	remoteWSHandler.SetScanResultHandler(remoteManageHandler.HandleScanResult)
	remoteWSHandler.SetStealSelfDeployer(remoteManageHandler.DeployStealSelfConfig)
	mux.Handle("/api/admin/certificates", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.ListCertificates)))
	mux.Handle("/api/admin/certificates/valid", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.ListValidCertificates)))
	mux.Handle("/api/admin/certificates/create", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.CreateCertificate)))
	mux.Handle("/api/admin/certificates/renew", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.RenewCertificate)))
	mux.Handle("/api/admin/certificates/auto-renew", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.SetAutoRenew)))
	mux.Handle("/api/admin/certificates/auto-deploy", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.SetAutoDeploy)))
	mux.Handle("/api/admin/certificates/deploy", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.DeployCertificate)))
	mux.Handle("/api/admin/certificates/upload", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.UploadCertificate)))
	mux.Handle("/api/admin/certificates/delete", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.DeleteCertificate)))
	mux.Handle("/api/admin/certificates/", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.GetCertificate)))
	mux.Handle("/api/admin/master-cert-status", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.GetMasterCertStatus)))
	mux.Handle("/api/admin/deploy-master-cert", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.DeployMasterCert)))
	mux.Handle("/api/admin/enable-https", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.EnableHTTPS)))

	// DNS 提供商管理 API（仅限管理员）
	mux.Handle("/api/admin/dns-providers", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.ListDNSProviders)))
	mux.Handle("/api/admin/dns-providers/create", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(certHandler.CreateDNSProvider)))
	mux.Handle("/api/admin/dns-providers/", auth.RequireAdmin(tokenStore, userRepo, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			certHandler.RevealDNSProviderCredentials(w, r)
		case http.MethodPut:
			certHandler.UpdateDNSProvider(w, r)
		case http.MethodDelete:
			certHandler.DeleteDNSProvider(w, r)
		default:
			http.NotFound(w, r)
		}
	})))

	// 创建订阅处理程序（在端点和短链接之间共享）
	subscriptionHandler := handler.NewSubscriptionHandlerConcrete(repo, subscribeDir)

	// 短链接重置端点（已验证）
	mux.Handle("/api/user/short-link", auth.RequireToken(tokenStore, userRepo, handler.NewShortLinkResetHandler(repo)))
	mux.Handle("/api/user/custom-short-code", auth.RequireToken(tokenStore, userRepo, handler.NewUserCustomShortCodeSelfHandler(repo)))

	// 临时订阅端点
	// 中间件:RequireToken(非 admin 也能进 handler),handler 内按"管理功能 → 节点管理"开关决定是否放行。
	// 路径保留 /api/admin/ 前缀以避免破坏既有前端调用;实际权限语义由 handler 控制。
	mux.Handle("/api/admin/temp-subscription", auth.RequireToken(tokenStore, userRepo, handler.NewTempSubscriptionHandler(repo)))
	tempSubAccessHandler := handler.NewTempSubscriptionAccessHandler()

	// 短链接和 Web 应用程序的组合处理程序
	// 这会捕获任何 6 字符路径（如 /AbC123）并将它们路由到短链接处理程序
	// /t/{id} 路径路由到临时订阅处理程序
	// 所有其他路径都转到 Web 处理程序
	shortLinkHandler := handler.NewShortLinkHandler(repo, subscriptionHandler, packageSubscribeHandler)
	// 暴力防护 / 订阅频率限制 用前面 LoadSecuritySettings 拿到的同一份 secCfg 构造,
	// system_settings 里有自定义阈值就用它们,没有就 fallback 到 hardcoded 默认值(24h/24h/30 次/2h)。
	bruteForceProtector := handler.NewBruteForceProtectorWithConfig(
		secCfg.BruteForceEnabled, secCfg.BruteForceMaxFailures,
		secCfg.BruteForceWindowMinutes, secCfg.BruteForceBlockMinutes,
	)
	bruteForceProtector.SetSkipLocalIP(secCfg.SkipLocalIP)
	subRateLimiter := handler.NewSubscriptionRateLimiterWithConfig(
		secCfg.SubRateEnabled, secCfg.SubRateLimit, secCfg.SubRateWindowMinutes,
	)
	subRateLimiter.SetSkipLocalIP(secCfg.SkipLocalIP)
	go subRateLimiter.StartCleanup(context.Background())
	webUI := web.Handler()
	if webRoot := strings.TrimSpace(os.Getenv("ARCWAY_WEB_ROOT")); webRoot != "" {
		logger.Info("已配置外部前端目录，目录不可用时自动回退内嵌页面", "path", webRoot)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(r.URL.Path, "/")
		clientIP := handler.GetClientIP(r)

		isTempSub := strings.HasPrefix(path, "t/") && len(path) == 10

		// 暴力探测封禁检查：仅对 /x/ 短链探测路径生效(失败计数也只来自 /x/ 与临时订阅)。
		// SPA 路由(/nodes、/users 等单段 alphanumeric)、静态资源、临时订阅一律放行,
		// 否则被封 IP 连前端 UI 都无法加载(SPA 路由与短码长得一样,不能一并拦截)。
		if strings.HasPrefix(path, "x/") && bruteForceProtector.IsBlocked(clientIP, r.URL.Path) {
			http.NotFound(w, r)
			return
		}

		isSubscriptionFetch := isTempSub ||
			(strings.HasPrefix(path, "x/") && len(path) > 2 && isAlphanumeric(path[2:]))
		if isSubscriptionFetch && !subRateLimiter.Allow(clientIP) {
			http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests)
			return
		}

		// 检查这是否是临时订阅访问（以"t/"开头，后跟 8 个十六进制字符）
		if isTempSub {
			rec := &handler.StatusRecorder{ResponseWriter: w, StatusCode: 200}
			tempSubAccessHandler.ServeHTTP(rec, r)
			if rec.StatusCode == http.StatusNotFound || rec.StatusCode == http.StatusForbidden {
				bruteForceProtector.RecordFailure(clientIP, r.URL.Path)
			}
			return
		}
		// 可变长度短链接匹配（/x/{fileCode}{userCode} 格式）
		if strings.HasPrefix(path, "x/") {
			code := path[2:]
			if len(code) >= 2 && isAlphanumeric(code) {
				if shortLinkHandler.TryServe(w, r) {
					return
				}
				bruteForceProtector.RecordFailure(clientIP, r.URL.Path)
				http.NotFound(w, r)
				return
			}
		}

		// 可选根路径短链接:直接 GET /<code>(无 /x/ 前缀)。
		// 系统设置启用后,把单段 alphanumeric 路径(看起来像短码)按 /x/<code> 试一遍,
		// 命中即返回订阅内容。不命中**必须 fall-through 到 SPA**,因为 /nodes / /users / /packages
		// 这些前端路由也是单段 alphanumeric,如果直接 404 会把整个前端路由废掉。
		if cfg, cfgErr := repo.GetSystemConfig(r.Context()); cfgErr == nil && cfg.EnableRootShortLinks &&
			path != "" && !strings.Contains(path, "/") && !strings.Contains(path, ".") &&
			len(path) >= 2 && isAlphanumeric(path) && subRateLimiter.Allow(clientIP) {
			origURL := r.URL.Path
			r.URL.Path = "/x/" + path
			if shortLinkHandler.TryServe(w, r) {
				return
			}
			r.URL.Path = origURL
			// 没命中短链接 → 不计暴力枚举(SPA 路由也长这样,无法区分),fall-through 让 web.Handler 决定
		}

		// 否则，传递给 Web 处理程序
		webUI.ServeHTTP(w, r)
	})

	// 嵌入式 MCP server(streamable-HTTP):供 OpenClaw 等 agent 运维。鉴权在工具调用时按 API 令牌经 mux 复用现有链。
	mux.Handle("/mcp", mcpserver.NewHandler(mux))

	// E2E 加密通道 — 复用 internal/securechan(X25519 + AES-256-GCM + 滑动窗口防重放)
	// 接到前端 user-facing API。客户端不发 X-Secure-Channel header 时透传,完全向后兼容。
	secureChannelHandler := handler.NewUserSecureChannelHandler()
	mux.Handle("/api/securechan/handshake", http.HandlerFunc(secureChannelHandler.Handshake))

	silentModeManager := handler.NewSilentModeManager(repo, tokenStore)
	// 中间件顺序:SecureChannelMiddleware 必须在 silentMode/CORS 之**内**(更靠近 mux),
	// 因为它会替换 request.Body 与 response body,外层 CORS/silentMode 只需看请求 path/header 即可。
	handlerWithSecureChannel := secureChannelHandler.SecureChannelMiddleware(mux)
	handlerWithSilentMode := silentModeManager.Middleware(handlerWithSecureChannel)

	allowedOrigins := getAllowedOrigins()
	handlerWithCORS := withCORS(handlerWithSilentMode, allowedOrigins)
	// HTTPS 启用后,应用层拦截非合法 Host 的请求(IP+端口直连等)→ 308 重定向到正确域名。
	// 跟 bind host 解耦,Docker / 跨机反代 / 裸机都能正确工作。详见 host_enforcement.go。
	handlerWithHostEnforce := handler.EnforceHTTPSHost(handlerWithCORS, repo)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handlerWithHostEnforce,
		ReadHeaderTimeout: 5 * time.Second,
	}

	collectorCtx, stopCollector := context.WithCancel(context.Background())

	trafficCollector.OnServerOffline = handler.SendServerOfflineNotification
	// 启动 Xray 流量收集器（每 1 分钟）
	go trafficCollector.Start(collectorCtx)
	// 启动拉模式服务器的速度收集（每 3 秒）
	go trafficCollector.StartSpeedCollection(collectorCtx)
	// 启动每日快照和清理任务
	go startDailySnapshotTask(collectorCtx, trafficHandler, trafficCollector)
	// WAL 巡检:每 5 分钟 wal_checkpoint(TRUNCATE),把 -wal 抽干并截断,防止长跑容器里 arcway.db-wal 无界膨胀。
	go startWALCheckpointTask(collectorCtx, repo)
	// 一次性补:上一轮已切到 traffic_source='system' 但 daily snapshot baseline 缺失的 server。
	// 行数 < 7 视为"切换时漏迁移"(覆盖本周维度);ON CONFLICT 覆盖,重启重跑也安全。
	// 新装的 system server 跑 7 天后自然有 ≥7 行,不会被误触发。
	go backfillSystemSnapshotsForSwitchedServers(collectorCtx, repo)
	// 启动流量超限检查（每 2 分钟）
	trafficEnforcer := handler.NewTrafficLimitEnforcer(repo, remoteManageHandler, limiterPusher)
	go trafficEnforcer.Start(collectorCtx, time.Duration(systemConfig.TrafficCheckInterval)*time.Second)
	// 启动 WebSocket 陈旧连接清理
	remoteWSHandler.StartCleanupLoop(collectorCtx, 1*time.Minute)
	// 启动通知调度器
	go handler.StartNotifyScheduler(collectorCtx, repo)

	// 外部测速组件由当前后端的内置目录明确指定版本。启动时立即对比，
	// 之后定期重试下载失败项；只更新已由 Arcway 管理的副本。
	componentTasks := []componentupdate.Task{{
		Name: "Ookla Speedtest",
		Run:  lineSpeedTestHandler.AutoUpdate,
	}}
	if capabilityManager.HasFeature(capabilities.FeatureSpeedTest) {
		componentTasks = append(componentTasks, componentupdate.Task{
			Name: "Mihomo",
			Run: func(ctx context.Context) error {
				_, err := speedtest.AutoUpdateManagedMihomo(ctx)
				return err
			},
		})
	}
	componentupdate.Scheduler{Tasks: componentTasks}.Start(collectorCtx)

	// 一次性数据迁移:给老 routed 节点补 creator 的 user_subaccounts 行 — 让 admin 自己用 routed 节点的
	// 流量能走 user_subaccounts 命中而不依赖 ResolveUsernameByEmail 的 _admin__ 反查 fallback。
	// 幂等:NOT EXISTS 保护重启不重复写。新建节点已在 routed_outbound.create 同步处理,这里只补历史欠账。
	if n, err := repo.BackfillRoutedCreatorSubaccounts(context.Background()); err != nil {
		log.Printf("[Startup] BackfillRoutedCreatorSubaccounts failed: %v", err)
	} else if n > 0 {
		log.Printf("[Startup] BackfillRoutedCreatorSubaccounts: filled %d creator subaccount row(s) for legacy routed nodes", n)
	}

	// 一次性补:历史 bug 导致「套餐开了按月重置但用户行 is_reset=0」的存量用户从未重置。
	// system_settings flag 保证只跑一次,避免覆盖新版允许的用户级显式关闭。
	if n, alreadyDone, err := repo.BackfillUserResetFromPackage(context.Background()); err != nil {
		log.Printf("[Startup] BackfillUserResetFromPackage failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] BackfillUserResetFromPackage: already done, skip")
	} else if n > 0 {
		log.Printf("[Startup] BackfillUserResetFromPackage: enabled monthly reset for %d user(s) per their package", n)
	}

	// 一次性数据迁移:清掉旧"new<last 启发式重启检测"误判累加的 total_* 脏数据。
	// 新算法用 agent 上报的 xray_boot_time 作权威重启信号,total_* 从下一轮 collector tick
	// 起按真重启累加。详见 internal/storage/traffic.go:ResetTrafficTotalsForXrayBootTimeMigration。
	// flag = traffic_total_reset_v2_done,system_settings 表里防重复。
	if n, alreadyDone, err := repo.ResetTrafficTotalsForXrayBootTimeMigration(context.Background()); err != nil {
		log.Printf("[Startup] ResetTrafficTotalsForXrayBootTimeMigration failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] ResetTrafficTotalsForXrayBootTimeMigration: already done, skip")
	} else {
		log.Printf("[Startup] ResetTrafficTotalsForXrayBootTimeMigration: reset done, %d rows affected (3 tables)", n)
	}

	// 紧急修复:reset migration 把 node_traffic.uplink/downlink 改成了 last_*(很小),snapshot
	// baseline 还是历史累计 → 服务器视图算"已用 = current - snapshot"全负数 → clamp 0 → "流量丢失"。
	// 真正修复:从 node_traffic_snapshots 反推恢复 node_traffic 到 reset 前的累计值。
	// 取每个 (server, tag) 历史 snapshot 中 (uplink+downlink) 最大值,绕开 today snapshot 被
	// reset 后写入的污染数据。详见 internal/storage/traffic.go:RestoreNodeTrafficFromSnapshots。
	if n, alreadyDone, err := repo.RestoreNodeTrafficFromSnapshots(context.Background()); err != nil {
		log.Printf("[Startup] RestoreNodeTrafficFromSnapshots failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] RestoreNodeTrafficFromSnapshots: already done, skip")
	} else {
		log.Printf("[Startup] RestoreNodeTrafficFromSnapshots: restored %d node_traffic row(s) from snapshots", n)
	}
	// 同款,对 user_traffic 表
	if n, alreadyDone, err := repo.RestoreUserTrafficFromSnapshots(context.Background()); err != nil {
		log.Printf("[Startup] RestoreUserTrafficFromSnapshots failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] RestoreUserTrafficFromSnapshots: already done, skip")
	} else {
		log.Printf("[Startup] RestoreUserTrafficFromSnapshots: restored %d user_traffic row(s) from snapshots", n)
	}

	// 清掉 reset 前用户用 admin UI "重置流量"留下的负偏移 — reset migration 已经做过等效操作,
	// 负偏移叠加只会让"已用 = (current+offset) - snapshot" 算成大负数 → clamp 0,显示假象。
	// 正偏移保留(用户记账累计的语义,有保留价值)。
	if n, alreadyDone, err := repo.ClearNegativeTrafficUsedOffsetsAfterReset(context.Background()); err != nil {
		log.Printf("[Startup] ClearNegativeTrafficUsedOffsetsAfterReset failed: %v", err)
	} else if alreadyDone {
		log.Printf("[Startup] ClearNegativeTrafficUsedOffsetsAfterReset: already done, skip")
	} else {
		log.Printf("[Startup] ClearNegativeTrafficUsedOffsetsAfterReset: cleared %d server(s) with negative offset", n)
	}
	// 启动分享服务器(联邦)状态/流量轮询（每 30 秒从拥有方拉取）
	handler.SetFederationCapabilities(capabilityManager)
	go handler.StartFederationPoller(collectorCtx, repo)
	// 启动证书自动续订检查程序（每 24 小时检查一次是否有 30 天内过期的证书）
	certHandler.StartRenewalChecker(collectorCtx)
	// TODO: 启动远程服务器离线检测任务（功能尚未实现）
	// 开始离线检测任务（collectorCtx，repo）

	// 如果处于子模式，则启动子客户端
	if childClient != nil {
		childClient.Start(collectorCtx)
		log.Printf("[Child Mode] Client started")
	}

	// 全局 API token 只能通过鉴权后的管理接口按需读取，禁止写入进程日志。
	if _, err := repo.GetAPIToken(context.Background()); err != nil {
		log.Printf("警告: 获取 API token 失败: %v", err)
	} else {
		log.Printf("全局 API token 已加载")
	}

	go func() {
		logger.Info("RelayDock HTTP 服务器启动", "version", version.Version, "address", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP服务器运行失败", "error", err)
			os.Exit(1)
		}
	}()

	waitForShutdown(srv, stopCollector, stopManagedReconciler, stopForwardingReconciler)
	managedNodesHandler.WaitForReconciler()
	forwardingHandler.WaitForReconciler()
}

func getAddr(config *ServerConfig, repo *storage.TrafficRepository) string {
	port := "12889"
	if config != nil && config.Port != "" {
		port = config.Port
	} else if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	// 默认绑 0.0.0.0,通用所有部署形态(裸机 / Docker / 跨机反代)。
	// 以前在 https 启用时强绑 127.0.0.1 是为了"禁止 IP+端口直连",但这套物理层拦截
	// 在 Docker 容器内会让 -p 端口映射失效(容器内 lo 跟 host 端口隔绝)。
	// 改用应用层 host 中间件(internal/handler/host_enforcement.go)做"直连拦截",
	// 跟 bind host 解耦。BIND_HOST env 留给高级场景显式覆盖。
	host := "0.0.0.0"
	if v := strings.TrimSpace(os.Getenv("BIND_HOST")); v != "" {
		host = v
	}
	log.Printf("[Main] HTTP server binding to %s:%s", host, port)
	_ = repo // 保留参数:其它 host enforcement 在 main.go 主流程里包裹
	return host + ":" + port
}

// 检查字符串是否仅包含字母数字字符
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func waitForShutdown(srv *http.Server, cancels ...context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	logger.Info("收到关闭信号，开始优雅关闭")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 停止所有后台任务
	for _, cancelFunc := range cancels {
		if cancelFunc != nil {
			cancelFunc()
		}
	}

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("优雅关闭失败", "error", err)
	} else {
		logger.Info("服务器已安全关闭")
	}
}

// backfillSystemSnapshotsForSwitchedServers 一次性修复上一轮 source 切换产生的两个 bug:
//  1. daily snapshot baseline 缺失 → today/week/month 三个时间按钮显示同一固定值
//  2. **更严重**:offset 锁在"oldDisplay - 小 system_raw"≈ xray total → 之后 cycle 被 SET 成 xray total
//     又没动 offset → traffic_used = cycle + offset = 2 × xray total **翻倍**
//
// MigrateXraySnapshotsToSystem 现在同时 reset offset = 0,所以本函数对全部 system source server 跑一次
// 即可修复以上两 bug。**用 system_settings 表里的 marker 控制只跑一次** — 跑完写 marker,后续启动检测到
// marker 直接跳过。这样用户手动校准的 traffic_used(走 dialog "已用流量"字段触发 handler 的 offset 调整)
// 不会被后续启动的 backfill 反复冲掉。
//
// 启动后 30s 延迟跑,避开启动峰值;失败只 log,不阻塞主控。
const backfillSystemTrafficOffsetResyncMarker = "system_traffic_offset_resync_v1_done"

func backfillSystemSnapshotsForSwitchedServers(ctx context.Context, repo *storage.TrafficRepository) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// marker 检查 — 已跑过就跳过,保护用户手动校准不被覆盖
	if val, err := repo.GetSystemSetting(scanCtx, backfillSystemTrafficOffsetResyncMarker); err == nil && val != "" {
		log.Printf("[Backfill SystemSnap] one-time resync already done at %s, skip", val)
		return
	}

	servers, err := repo.ListRemoteServers(scanCtx)
	if err != nil {
		log.Printf("[Backfill SystemSnap] list remote servers failed: %v", err)
		return
	}

	migrated := 0
	for _, s := range servers {
		if s.TrafficSource != "system" {
			continue
		}
		if err := repo.MigrateXraySnapshotsToSystem(scanCtx, s.ID); err != nil {
			log.Printf("[Backfill SystemSnap] migrate server %d (%s) failed: %v", s.ID, s.Name, err)
			continue
		}
		migrated++
		log.Printf("[Backfill SystemSnap] server %d (%s) migrated xray history → system, offset reset to 0",
			s.ID, s.Name)
	}
	if migrated > 0 {
		log.Printf("[Backfill SystemSnap] one-time resync done: migrated %d server(s)", migrated)
	}

	// 写 marker — 即便没 migrate 任何 server(全是 xray source)也写,避免每次启动重复扫
	if err := repo.SetSystemSetting(scanCtx, backfillSystemTrafficOffsetResyncMarker, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("[Backfill SystemSnap] write marker failed: %v", err)
	}
}

// 创建每日快照并清理旧数据
// startWALCheckpointTask 每 5 分钟做一次 wal_checkpoint(TRUNCATE):把 WAL 已提交帧写回主库并截断 -wal 文件。
// SQLite 默认 PASSIVE 自动 checkpoint 在持续并发读下常抽不干、且从不截断文件;配合 DSN 里的 journal_size_limit,
// 这个巡检保证长跑容器里 arcway.db-wal 不会无界膨胀。TRUNCATE 会等 reader(有 5s busy_timeout),
// 偶发 SQLITE_BUSY 属正常,下一轮再来,非致命。
func startWALCheckpointTask(ctx context.Context, repo *storage.TrafficRepository) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := repo.Checkpoint(); err != nil {
				log.Printf("[WAL] periodic checkpoint failed: %v", err)
			}
		}
	}
}

func startDailySnapshotTask(ctx context.Context, trafficHandler *handler.TrafficSummaryHandler, trafficCollector *traffic.Collector) {
	if trafficHandler == nil {
		return
	}

	// 带重试的流量收集函数
	runWithRetry := func() {
		logger.Info("[流量收集器] 开始每日流量收集", "start_time", time.Now().Format("2006-01-02 15:04:05"))

		maxRetries := 3
		retryDelay := 30 * time.Second

		for attempt := 1; attempt <= maxRetries; attempt++ {
			runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := trafficHandler.RecordDailyUsage(runCtx)
			cancel()

			if err == nil {
				logger.Info("[流量收集器] 每日流量收集成功")
				// RecordDailyUsage 只写了 daily_usage 聚合表。前端「今天/本周」筛选需要的
				// node_traffic_snapshots + user_traffic_snapshots 必须靠 collector 单独跑 —
				// 老 bug:从来没人调过这俩函数,导致快照表永远空,「今天/本周」实际显示全月数据。
				if trafficCollector != nil {
					snapCtx, snapCancel := context.WithTimeout(ctx, 60*time.Second)
					if serr := trafficCollector.CreateDailySnapshots(snapCtx); serr != nil {
						logger.Error("[流量收集器] 节点/用户快照保存失败", "error", serr)
					}
					snapCancel()
				}
				return
			}

			logger.Warn("[流量收集器] 每日流量收集失败", "attempt", attempt, "max_retries", maxRetries, "error", err)

			if attempt < maxRetries {
				logger.Info("[流量收集器] 准备重试", "delay", retryDelay)
				select {
				case <-ctx.Done():
					logger.Info("[流量收集器] 重试已取消（服务器关闭）")
					return
				case <-time.After(retryDelay):
					// 继续重试
				}
			}
		}

		logger.Error("[流量收集器] 达到最大重试次数后仍失败", "max_retries", maxRetries)
	}

	// 启动后不立即跑,改为等到下一个 00:00:00 触发第一次,之后每 24h 一次。
	// 用户需求:每日流量记录在 0 点产生,而不是服务器启动时刻。
	now := time.Now()
	nextMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Add(24 * time.Hour)
	firstDelay := time.Until(nextMidnight)
	logger.Info("[流量收集器] 定时调度器已启动", "first_run_at", nextMidnight.Format("2006-01-02 15:04:05"), "interval", "24小时")

	firstTimer := time.NewTimer(firstDelay)
	select {
	case <-ctx.Done():
		firstTimer.Stop()
		logger.Info("[流量收集器] 定时调度器已停止")
		return
	case <-firstTimer.C:
		runWithRetry()
	}

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("[流量收集器] 定时调度器已停止")
			return
		case <-ticker.C:
			runWithRetry()
		}
	}
}

// 启动日志清理任务
func startLogCleanup(dataDirectory string) {
	logManager := logger.NewLogManager(filepath.Join(dataDirectory, "logs"))

	// 一轮清理：debug 日志(log_*, 7天) + lumberjack 主日志(arcway*, 兜底保留最新2个)
	runCleanup := func() {
		if err := logManager.CleanupOldLogs(); err != nil {
			logger.Error("[日志清理] 清理 debug 日志失败", "error", err)
		}
		if err := logManager.EnforceMaxFiles("arcway", 2); err != nil {
			logger.Error("[日志清理] 清理主日志失败", "error", err)
		}
	}

	// 启动时立即清理一次
	runCleanup()

	// 兜底巡检(主轮转由 lumberjack 负责,这里 10 分钟扫一次)
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	logger.Info("[日志清理] 定时清理任务已启动", "interval", "10分钟", "debug_max_age", "7天", "main_keep", 2)

	for range ticker.C {
		runCleanup()
	}
}
