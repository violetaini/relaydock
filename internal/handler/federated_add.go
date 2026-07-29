package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/version"
)

// 消费方:接入一台"分享服务器"。探测拥有方联邦接口校验令牌,然后建一条 remote_servers 行 + federated_servers 标记。
type AddSharedServerHandler struct {
	repo   *storage.TrafficRepository
	client *http.Client
}

func NewAddSharedServerHandler(repo *storage.TrafficRepository) *AddSharedServerHandler {
	return &AddSharedServerHandler{repo: repo, client: newFederationHTTPClient()}
}

const maxFederationResponseBytes = 1 << 20

var blockedFederationCIDRs = func() []*net.IPNet {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	}
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, _ := net.ParseCIDR(value)
		out = append(out, network)
	}
	return out
}()

func isPublicFederationIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	for _, network := range blockedFederationCIDRs {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func resolvePublicFederationHost(ctx context.Context, host string) ([]net.IPAddr, error) {
	if parsed := net.ParseIP(host); parsed != nil {
		if !isPublicFederationIP(parsed) {
			return nil, errors.New("拥有方地址不能指向本机或非公网网络")
		}
		return []net.IPAddr{{IP: parsed}}, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("无法解析拥有方地址")
	}
	for _, address := range addresses {
		if !isPublicFederationIP(address.IP) {
			return nil, errors.New("拥有方域名解析到了本机或非公网网络")
		}
	}
	return addresses, nil
}

func validateFederationOwnerURL(ctx context.Context, raw string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("拥有方地址格式不正确")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("拥有方地址仅支持 http 或 https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("拥有方地址只能填写控制端根地址")
	}
	if _, err := resolvePublicFederationHost(ctx, parsed.Hostname()); err != nil {
		return nil, err
	}
	return parsed, nil
}

func newFederationHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("解析拥有方地址: %w", err)
		}
		addresses, err := resolvePublicFederationHost(ctx, host)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("拥有方控制端不允许 HTTP 重定向")
		},
	}
}

func (h *AddSharedServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	var req struct {
		OwnerURL   string `json:"owner_url"`
		ShareToken string `json:"share_token"`
		Name       string `json:"name"`
		Prefix     string `json:"prefix"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("请求格式不正确"))
		return
	}
	ownerURL := strings.TrimRight(strings.TrimSpace(req.OwnerURL), "/")
	shareToken := strings.TrimSpace(req.ShareToken)
	if ownerURL == "" || shareToken == "" {
		writeError(w, http.StatusBadRequest, errors.New("拥有方地址和分享令牌必填"))
		return
	}
	if !strings.HasPrefix(ownerURL, "http://") && !strings.HasPrefix(ownerURL, "https://") {
		ownerURL = "https://" + ownerURL
	}
	validatedURL, err := validateFederationOwnerURL(r.Context(), ownerURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ownerURL = strings.TrimRight(validatedURL.String(), "/")

	// 探测拥有方联邦接口,校验令牌并取服务器信息
	info, err := h.probe(r, ownerURL, shareToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		if n, _ := info["name"].(string); n != "" {
			name = n
		} else {
			name = "共享服务器"
		}
	}
	if _, lookupErr := h.repo.GetRemoteServerByName(r.Context(), name); lookupErr == nil {
		writeError(w, http.StatusConflict, errors.New("显示名称已存在,请指定其他名称"))
		return
	} else if !errors.Is(lookupErr, storage.ErrRemoteServerNotFound) {
		writeError(w, http.StatusInternalServerError, lookupErr)
		return
	}
	ip, _ := info["ip_address"].(string)
	// 拥有方 xray 模式透传,避免消费方按默认 'external' 显示与拥有方不一致(联邦轮询里也会持续同步)
	xrayMode, _ := info["xray_mode"].(string)
	if xrayMode != "embedded" && xrayMode != "external" {
		xrayMode = ""
	}

	token, err := generateSecureToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	server := &storage.RemoteServer{
		Name:      name,
		Token:     token, // 占位:联邦服务器不直连 agent,不使用此 token
		Status:    "connected",
		IPAddress: ip,
		XrayMode:  xrayMode,
	}
	if err := h.repo.CreateRemoteServer(r.Context(), server); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := h.repo.SetFederatedServer(r.Context(), server.ID, ownerURL, shareToken, strings.TrimSpace(req.Prefix)); err != nil {
		// 回滚:删除刚建的服务器行
		_ = h.repo.DeleteRemoteServer(r.Context(), server.ID)
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": server.ID, "name": name, "status": "connected"})
}

func (h *AddSharedServerHandler) probe(r *http.Request, ownerURL, shareToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, ownerURL+"/api/federation/server-info", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Share-Token", shareToken)
	req.Header.Set("User-Agent", version.AgentUserAgent)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, errors.New("无法连接到拥有方主控")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("分享令牌无效或已被吊销")
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("拥有方未开启服务器分享能力")
	}
	if resp.StatusCode >= 400 {
		return nil, errors.New("拥有方联邦接口返回错误")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFederationResponseBytes+1))
	if err != nil || len(body) > maxFederationResponseBytes {
		return nil, errors.New("拥有方返回数据过大")
	}
	var info map[string]any
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, errors.New("拥有方返回数据异常")
	}
	return info, nil
}
