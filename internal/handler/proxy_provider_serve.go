package handler

import (
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/proxyparser"
	"github.com/violetaini/relaydock/internal/safefetch"
	"github.com/violetaini/relaydock/internal/storage"
	"gopkg.in/yaml.v3"
)

const (
	proxyProviderAccessTokenPrefix = "arcway_pp_"
	geoIPCacheTTL                  = 24 * time.Hour
	maxGeoIPCacheEntries           = 4096
	subscriptionCacheTTL           = 5 * time.Minute
	maxSubscriptionBytes           = 50 << 20 // 50MB
	maxSubscriptionCacheBytes      = 64 << 20 // cache budget shared by all subscriptions
	maxSubscriptionCacheItems      = 1024
	maxProxyProviderNodes          = 20_000
	maxProxyProviderBytes          = 50 << 20
)

type geoIPResponse struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
}

var geoIPCache = newBoundedGeoIPCache(maxGeoIPCacheEntries, geoIPCacheTTL)
var geoIPLookupPending = sync.Map{} // map[string]struct{}; prevents duplicate asynchronous lookups
var geoIPHTTPClient = &http.Client{Timeout: 5 * time.Second}

type subscriptionCacheEntry struct {
	content   []byte
	fetchedAt time.Time
	element   *list.Element
}

type boundedSubscriptionCache struct {
	mu       sync.Mutex
	entries  map[string]*subscriptionCacheEntry
	lru      *list.List
	bytes    int64
	maxBytes int64
	maxItems int
}

type geoIPCacheEntry struct {
	value     string
	expiresAt time.Time
}

type boundedGeoIPCache struct {
	mu         sync.Mutex
	entries    map[string]geoIPCacheEntry
	maxEntries int
	ttl        time.Duration
}

var subscriptionCache = newBoundedSubscriptionCache(maxSubscriptionCacheBytes)

func newBoundedGeoIPCache(maxEntries int, ttl time.Duration) *boundedGeoIPCache {
	return &boundedGeoIPCache{entries: make(map[string]geoIPCacheEntry), maxEntries: maxEntries, ttl: ttl}
}

// Store/Load/Delete intentionally match sync.Map's small surface because tests
// and public-probe handlers seed this package cache directly.
func (c *boundedGeoIPCache) Store(key, value any) {
	ip, ok := key.(string)
	country, valueOK := value.(string)
	if !ok || !valueOK {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		now := time.Now()
		for candidate, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, candidate)
			}
		}
	}
	if len(c.entries) >= c.maxEntries {
		for candidate := range c.entries {
			delete(c.entries, candidate)
			break
		}
	}
	c.entries[ip] = geoIPCacheEntry{value: country, expiresAt: time.Now().Add(c.ttl)}
}

func (c *boundedGeoIPCache) Load(key any) (any, bool) {
	ip, ok := key.(string)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[ip]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.entries, ip)
		return nil, false
	}
	return entry.value, true
}

func (c *boundedGeoIPCache) Delete(key any) {
	ip, ok := key.(string)
	if !ok {
		return
	}
	c.mu.Lock()
	delete(c.entries, ip)
	c.mu.Unlock()
}

func newBoundedSubscriptionCache(maxBytes int64) *boundedSubscriptionCache {
	return &boundedSubscriptionCache{
		entries:  make(map[string]*subscriptionCacheEntry),
		lru:      list.New(),
		maxBytes: maxBytes,
		maxItems: maxSubscriptionCacheItems,
	}
}

func (c *boundedSubscriptionCache) get(key string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if now.Sub(entry.fetchedAt) >= subscriptionCacheTTL {
		c.removeLocked(key, entry)
		return nil, false
	}
	c.lru.MoveToFront(entry.element)
	return entry.content, true
}

func (c *boundedSubscriptionCache) put(key string, content []byte, now time.Time) {
	size := int64(len(content))
	if size > c.maxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok {
		c.removeLocked(key, existing)
	}
	for len(c.entries) >= c.maxItems && c.lru.Len() > 0 {
		oldestKey := c.lru.Back().Value.(string)
		c.removeLocked(oldestKey, c.entries[oldestKey])
	}
	for c.bytes+size > c.maxBytes && c.lru.Len() > 0 {
		oldestKey := c.lru.Back().Value.(string)
		c.removeLocked(oldestKey, c.entries[oldestKey])
	}
	entry := &subscriptionCacheEntry{content: content, fetchedAt: now}
	entry.element = c.lru.PushFront(key)
	c.entries[key] = entry
	c.bytes += size
}

func (c *boundedSubscriptionCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		c.removeLocked(key, entry)
	}
}

func (c *boundedSubscriptionCache) deletePrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if strings.HasPrefix(key, prefix) {
			c.removeLocked(key, entry)
		}
	}
}

func (c *boundedSubscriptionCache) removeLocked(key string, entry *subscriptionCacheEntry) {
	delete(c.entries, key)
	c.lru.Remove(entry.element)
	c.bytes -= int64(len(entry.content))
}

// 失效指定URL的订阅内容缓存
func InvalidateSubscriptionContentCache(url string) {
	subscriptionCache.deletePrefix(subscriptionContentCachePrefix(url) + ":")
}

func subscriptionContentCachePrefix(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return fmt.Sprintf("subscription:%x", sum[:])
}

func subscriptionContentCacheKey(rawURL string, userAgents ...string) string {
	userAgent := "clash-meta/2.4.0"
	if len(userAgents) > 0 && strings.TrimSpace(userAgents[0]) != "" {
		userAgent = strings.TrimSpace(userAgents[0])
	}
	sum := sha256.Sum256([]byte(userAgent))
	return fmt.Sprintf("%s:%x", subscriptionContentCachePrefix(rawURL), sum[:])
}

// 查询 IP 的国家代码
func getGeoIPCountryCode(ipOrHost string) string {
	if ipOrHost == "" {
		return ""
	}
	token := strings.TrimSpace(os.Getenv("ARCWAY_IPINFO_TOKEN"))
	if token == "" {
		return ""
	}

	// 如果是域名，先解析为 IP
	ip := ipOrHost
	if net.ParseIP(ipOrHost) == nil {
		// 是域名，需要解析
		ips, err := net.LookupIP(ipOrHost)
		if err != nil || len(ips) == 0 {
			logger.Info("[GeoIP] 域名解析失败", "domain", ipOrHost, "error", err)
			return ""
		}
		ip = ips[0].String()
	}

	// 检查缓存
	if cached, ok := geoIPCache.Load(ip); ok {
		return cached.(string)
	}

	// 查询 API
	resp, err := geoIPHTTPClient.Get(fmt.Sprintf("https://api.ipinfo.io/lite/%s?token=%s", url.PathEscape(ip), url.QueryEscape(token)))
	if err != nil {
		logger.Info("[GeoIP] IP查询失败", "ip", ip, "error", sanitizeSubscriptionRequestError(err))
		// 缓存空结果避免重复查询
		geoIPCache.Store(ip, "")
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Info("[GeoIP] 查询返回非成功状态", "ip", ip, "status", resp.StatusCode)
		geoIPCache.Store(ip, "")
		return ""
	}

	var result geoIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Info("[GeoIP] 响应解析失败", "ip", ip, "error", err)
		geoIPCache.Store(ip, "")
		return ""
	}

	// 缓存结果
	countryCode := strings.ToUpper(result.CountryCode)
	geoIPCache.Store(ip, countryCode)
	logger.Info("[GeoIP] IP地理位置查询成功", "ip", ip, "country", countryCode)
	return countryCode
}

// cachedOrQueueGeoIPCountryCode returns a cached country code immediately and
// queues a bounded background lookup for a public literal address on a cache
// miss. Server-management and public-probe list handlers must not wait on a
// third-party GeoIP request. Cache hits are local-only; cache misses reject
// private, link-local, carrier-grade NAT and documentation ranges so opening
// a list cannot disclose an internal/test address to the GeoIP provider.
func cachedOrQueueGeoIPCountryCode(ipAddress string) string {
	ip := net.ParseIP(strings.TrimSpace(ipAddress))
	if ip == nil {
		return ""
	}
	key := ip.String()
	if cached, ok := geoIPCache.Load(key); ok {
		if countryCode, ok := cached.(string); ok {
			return publicCountryCode(countryCode)
		}
		return ""
	}
	if !isGeoIPLookupPublicIP(ip) {
		return ""
	}
	if strings.TrimSpace(os.Getenv("ARCWAY_IPINFO_TOKEN")) == "" {
		return ""
	}
	if _, loaded := geoIPLookupPending.LoadOrStore(key, struct{}{}); !loaded {
		go func() {
			defer geoIPLookupPending.Delete(key)
			_ = getGeoIPCountryCode(key)
		}()
	}
	return ""
}

func publicCountryCode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 2 {
		return ""
	}
	for _, r := range value {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return value
}

func isGeoIPLookupPublicIP(ip net.IP) bool {
	if !isPublicProbeIP(ip) {
		return false
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		// RFC 5737 documentation ranges must never result in an external call.
		if (ipv4[0] == 192 && ipv4[1] == 0 && ipv4[2] == 2) ||
			(ipv4[0] == 198 && ipv4[1] == 51 && ipv4[2] == 100) ||
			(ipv4[0] == 203 && ipv4[1] == 0 && ipv4[2] == 113) {
			return false
		}
	}
	return true
}

// 通过缓存获取订阅内容（5 分钟 TTL）
func fetchSubscriptionContent(sub *storage.ExternalSubscription) ([]byte, error) {
	userAgent := strings.TrimSpace(sub.UserAgent)
	if userAgent == "" {
		userAgent = "clash-meta/2.4.0"
	}
	cacheKey := subscriptionContentCacheKey(sub.URL, userAgent)

	// 检查缓存
	if content, ok := subscriptionCache.get(cacheKey, time.Now()); ok {
		logger.Info("[SubscriptionCache] 缓存命中", "source_id", sub.ID, "source_name", sub.Name)
		return content, nil
	}

	logger.Info("[SubscriptionCache] 缓存未命中，正在拉取", "source_id", sub.ID, "source_name", sub.Name)

	// 拉取订阅内容
	client := safefetch.NewClient(30*time.Second, maxSubscriptionBytes)
	req, err := http.NewRequest(http.MethodGet, sub.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for subscription source %d: invalid URL", sub.ID)
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription source %d: %w", sub.ID, sanitizeSubscriptionRequestError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 限制读取大小,防恶意/故障订阅源返回超大 body 触发 OOM(订阅内容通常 <几 MB)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// 存入缓存
	subscriptionCache.put(cacheKey, body, time.Now())

	return body, nil
}

type proxyProviderContentFetcher func(*storage.ExternalSubscription) ([]byte, error)

// ProxyProviderContentHandler serves a provider's normalized proxy list through
// an opaque, independently revocable Authorization credential. The URL contains
// only a non-secret provider ID so reverse-proxy access logs cannot capture the
// credential.
type ProxyProviderContentHandler struct {
	repo  *storage.TrafficRepository
	fetch proxyProviderContentFetcher
}

func NewProxyProviderContentHandler(repo *storage.TrafficRepository) http.Handler {
	if repo == nil {
		panic("proxy provider content handler requires repository")
	}
	return &ProxyProviderContentHandler{repo: repo, fetch: fetchSubscriptionContent}
}

func (h *ProxyProviderContentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	const routePrefix = "/api/proxy-provider/"
	if !strings.HasPrefix(r.URL.Path, routePrefix) {
		writeProxyProviderNotFound(w)
		return
	}
	providerIDText := strings.TrimPrefix(r.URL.Path, routePrefix)
	providerID, err := strconv.ParseInt(providerIDText, 10, 64)
	if err != nil || providerID <= 0 || strings.Contains(providerIDText, "/") {
		writeProxyProviderNotFound(w)
		return
	}

	token := auth.BearerToken(r)
	cfg, sub, err := h.repo.ResolveProxyProviderAccess(r.Context(), token)
	if err != nil {
		writeProxyProviderNotFound(w)
		return
	}
	providerType := ""
	if cfg != nil {
		providerType = strings.ToLower(strings.TrimSpace(cfg.Type))
		if providerType == "" {
			providerType = "http"
		}
	}
	if cfg == nil || sub == nil || cfg.ID != providerID || providerType != "http" || normalizeProxyProviderMode(cfg.ProcessMode) != "client" {
		writeProxyProviderNotFound(w)
		return
	}

	content, err := h.fetch(sub)
	if err != nil {
		http.Error(w, "proxy provider source unavailable", http.StatusBadGateway)
		return
	}
	proxies, err := decodeProviderNodeSet(cfg, content)
	if err != nil || len(proxies) == 0 {
		http.Error(w, "proxy provider source unavailable", http.StatusBadGateway)
		return
	}
	normalized, err := marshalProxyProviderContent(proxies, cfg.SizeLimit)
	if err != nil {
		http.Error(w, "proxy provider source unavailable", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(normalized)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(normalized)
}

func writeProxyProviderNotFound(w http.ResponseWriter) {
	http.Error(w, "not found", http.StatusNotFound)
}

func normalizeProxyProviderContent(content []byte, configuredLimit int) ([]byte, error) {
	config := &storage.ProxyProviderConfig{Type: "http", SizeLimit: configuredLimit}
	proxies, err := decodeProviderNodeSet(config, content)
	if err != nil {
		return nil, err
	}
	return marshalProxyProviderContent(proxies, configuredLimit)
}

func proxyProviderContentLimit(configuredLimit int) int {
	if configuredLimit > 0 && configuredLimit < maxProxyProviderBytes {
		return configuredLimit
	}
	return maxProxyProviderBytes
}

func marshalProxyProviderContent(proxies []map[string]any, configuredLimit int) ([]byte, error) {
	limit := proxyProviderContentLimit(configuredLimit)
	normalized, err := yaml.Marshal(map[string]any{"proxies": proxies})
	if err != nil {
		return nil, fmt.Errorf("marshal proxy provider content: %w", err)
	}
	if len(normalized) > limit || len(normalized) > maxProxyProviderBytes {
		return nil, errors.New("normalized proxy provider content exceeds size limit")
	}
	return normalized, nil
}

// preprocessSubscriptionContent 预处理订阅内容。
// URI 解析与内容类型检测统一委托给共享 module proxyparser。
// YAML 的实际解析仍由本地完成（module 不依赖 yaml）。
func preprocessSubscriptionContent(content []byte) ([]byte, error) {
	proxies, kind, decoded, err := proxyparser.Preprocess(content)
	if err != nil {
		return nil, err
	}
	switch kind {
	case proxyparser.ContentURIList:
		logger.Info("[预处理] 检测到 URI 列表，经 proxyparser 解析", "count", len(proxies))
		out, mErr := yaml.Marshal(map[string]any{"proxies": proxies})
		if mErr != nil {
			return nil, fmt.Errorf("URI 列表转 YAML 失败: %w", mErr)
		}
		return out, nil
	case proxyparser.ContentHTML:
		logger.Info("[预处理] 检测到 HTML 内容，跳过")
		return content, nil
	case proxyparser.ContentClashYAML:
		return decoded, nil
	default:
		return decoded, nil
	}
}

// 查找 YAML 文档中的代理节点
func findProxiesNode(root *yaml.Node) *yaml.Node {
	if root == nil {
		return nil
	}

	// 处理文档节点
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		return findProxiesNode(root.Content[0])
	}

	// 句柄映射节点
	if root.Kind == yaml.MappingNode {
		for i := 0; i < len(root.Content)-1; i += 2 {
			keyNode := root.Content[i]
			valueNode := root.Content[i+1]
			if keyNode.Kind == yaml.ScalarNode && keyNode.Value == "proxies" {
				return valueNode
			}
		}
	}

	return nil
}

// 获取订阅内容并返回所有节点名称
func fetchSubscriptionNodeNames(sub *storage.ExternalSubscription) ([]string, error) {
	// 获取订阅内容（带缓存）
	body, err := fetchSubscriptionContent(sub)
	if err != nil {
		return nil, err
	}

	// 预处理内容（处理base64编码）
	body, err = preprocessSubscriptionContent(body)
	if err != nil {
		return nil, fmt.Errorf("preprocess subscription content: %w", err)
	}

	// 解析 YAML 内容
	var rootNode yaml.Node
	if err := yaml.Unmarshal(body, &rootNode); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	// 查找代理节点
	proxiesNode := findProxiesNode(&rootNode)
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("no proxies found in subscription")
	}

	// 提取节点名称
	var nodeNames []string
	for _, proxyNode := range proxiesNode.Content {
		if proxyNode.Kind != yaml.MappingNode {
			continue
		}

		// 找到“姓名”字段
		for i := 0; i < len(proxyNode.Content)-1; i += 2 {
			keyNode := proxyNode.Content[i]
			valueNode := proxyNode.Content[i+1]
			if keyNode.Kind == yaml.ScalarNode && keyNode.Value == "name" && valueNode.Kind == yaml.ScalarNode {
				nodeNames = append(nodeNames, valueNode.Value)
				break
			}
		}
	}

	return nodeNames, nil
}

// NodeInfo 节点信息（名称和服务器地址）
type NodeInfo struct {
	Name   string `json:"name"`
	Server string `json:"server"`
}

// 获取订阅内容并返回带有名称和服务器的所有节点
func fetchSubscriptionNodes(sub *storage.ExternalSubscription) ([]NodeInfo, error) {
	// 获取订阅内容（带缓存）
	body, err := fetchSubscriptionContent(sub)
	if err != nil {
		return nil, err
	}

	// 预处理内容（处理base64编码）
	body, err = preprocessSubscriptionContent(body)
	if err != nil {
		return nil, fmt.Errorf("preprocess subscription content: %w", err)
	}

	// 解析 YAML 内容
	var rootNode yaml.Node
	if err := yaml.Unmarshal(body, &rootNode); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	// 查找代理节点
	proxiesNode := findProxiesNode(&rootNode)
	if proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("no proxies found in subscription")
	}

	// 提取节点信息（名称和服务器）
	var nodes []NodeInfo
	for _, proxyNode := range proxiesNode.Content {
		if proxyNode.Kind != yaml.MappingNode {
			continue
		}

		node := NodeInfo{}
		for i := 0; i < len(proxyNode.Content)-1; i += 2 {
			keyNode := proxyNode.Content[i]
			valueNode := proxyNode.Content[i+1]
			if keyNode.Kind == yaml.ScalarNode && valueNode.Kind == yaml.ScalarNode {
				switch keyNode.Value {
				case "name":
					node.Name = valueNode.Value
				case "server":
					node.Server = valueNode.Value
				}
			}
		}
		if node.Name != "" {
			nodes = append(nodes, node)
		}
	}

	return nodes, nil
}

// checkFilterMatches 检查过滤器/排除过滤器/geo-ip-过滤器是否与任何节点匹配
// 返回匹配节点的数量
func checkFilterMatches(sub *storage.ExternalSubscription, filter, excludeFilter, geoIPFilter string) (int, error) {
	// 获取节点
	nodes, err := fetchSubscriptionNodes(sub)
	if err != nil {
		return 0, err
	}

	logger.Info("[checkFilterMatches] 订阅节点信息", "sub_name", sub.Name, "node_count", len(nodes), "filter", filter, "exclude_filter", excludeFilter, "geo_ip_filter", geoIPFilter)

	// 编译正则表达式
	var filterRegex, excludeRegex *regexp.Regexp

	if filter != "" {
		filterRegex, err = regexp.Compile(filter)
		if err != nil {
			logger.Info("[checkFilterMatches] 无效的过滤正则表达式", "error", err)
			return 0, fmt.Errorf("invalid filter regex: %w", err)
		}
	}

	if excludeFilter != "" {
		excludeRegex, err = regexp.Compile(excludeFilter)
		if err != nil {
			logger.Info("[checkFilterMatches] 无效的排除过滤正则表达式", "error", err)
			return 0, fmt.Errorf("invalid exclude-filter regex: %w", err)
		}
	}

	// 构建 GeoIP 过滤国家代码地图
	geoIPCountryCodes := make(map[string]bool)
	if geoIPFilter != "" {
		for _, code := range strings.Split(geoIPFilter, ",") {
			geoIPCountryCodes[strings.TrimSpace(strings.ToUpper(code))] = true
		}
	}

	// 计算匹配节点数
	matchCount := 0
	for _, node := range nodes {
		// 首先应用排除过滤器（删除匹配的名称）
		if excludeRegex != nil && excludeRegex.MatchString(node.Name) {
			continue
		}

		// 应用过滤器和 GeoIP 匹配
		if filterRegex != nil {
			if filterRegex.MatchString(node.Name) {
				// 节点名称与过滤器正则表达式匹配，计算它
				matchCount++
				continue
			}

			// 节点名称不匹配，请检查 GeoIP（如果可用）
			if len(geoIPCountryCodes) > 0 && node.Server != "" {
				countryCode := getGeoIPCountryCode(node.Server)
				if countryCode != "" && geoIPCountryCodes[countryCode] {
					// IP位置匹配，统计一下
					matchCount++
					continue
				}
			}
			// 正则表达式和 GeoIP 都不匹配，跳过此节点
			continue
		}

		// 没有过滤器正则表达式，只有 GeoIP 过滤器
		if len(geoIPCountryCodes) > 0 {
			if node.Server != "" {
				countryCode := getGeoIPCountryCode(node.Server)
				if countryCode != "" && geoIPCountryCodes[countryCode] {
					matchCount++
				}
			}
			continue
		}

		// 根本不过滤，计算所有节点
		matchCount++
	}

	logger.Info("[checkFilterMatches] 匹配结果", "filter", filter, "geo_ip_filter", geoIPFilter, "match_count", matchCount)
	return matchCount, nil
}
