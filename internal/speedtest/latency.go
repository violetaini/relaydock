package speedtest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	protocolLatencyURL         = "https://cp.cloudflare.com/generate_204"
	protocolLatencyWorkers     = 20
	protocolLatencySessionMax  = 2
	protocolLatencyStartWait   = 8 * time.Second
	protocolLatencyOutputLimit = 16 << 10
	protocolLatencyAPISecret   = "arcway-local-protocol-probe"
)

var supportedProtocolLatencyProxyTypes = map[string]string{
	"vmess":       "vmess",
	"vless":       "vless",
	"trojan":      "trojan",
	"ss":          "ss",
	"shadowsocks": "ss",
	"ssr":         "ssr",
	"socks":       "socks5",
	"socks5":      "socks5",
	"http":        "http",
	"hysteria":    "hysteria",
	"hy2":         "hysteria2",
	"hysteria2":   "hysteria2",
	"tuic":        "tuic",
	"anytls":      "anytls",
	"wg":          "wireguard",
	"wireguard":   "wireguard",
	"snell":       "snell",
	"ssh":         "ssh",
	"mieru":       "mieru",
}

// ProtocolLatencyTarget is one complete Mihomo proxy object serialized as JSON.
// Timeout applies to the data-plane URL test after the temporary core is ready.
type ProtocolLatencyTarget struct {
	ClashConfig string
	// DialerChain contains the immediate dialer's config first, followed by
	// that dialer's own dependency. The runner rewrites all names/references.
	DialerChain []string
	// WireGuardRelayBypass is aligned with ClashConfig followed by DialerChain.
	// A true entry leaves an imported WireGuard endpoint on Mihomo's native UDP
	// socket instead of the optional fixed-port relay for managed probes.
	WireGuardRelayBypass []bool
	// Hosts pins already-authorized endpoint hostnames to public addresses.
	// It prevents a second DNS lookup from turning a user-visible node into an
	// internal-network probe while preserving the original hostname for SNI.
	Hosts   map[string]string
	Timeout time.Duration
}

// ProtocolLatencyResult reports the URL-test latency through the actual proxy
// protocol stack. Err is per target; one malformed proxy must not fail a batch.
type ProtocolLatencyResult struct {
	Latency float64
	Err     error
}

type preparedProtocolLatencyTarget struct {
	index                int
	name                 string
	proxies              []map[string]interface{}
	wireGuardRelayBypass []bool
	hosts                map[string]string
	timeout              time.Duration
}

type mihomoLatencySession struct {
	client          *http.Client
	cmd             *exec.Cmd
	done            chan error
	workdir         string
	wireGuardRelays []io.Closer
	stopOnce        sync.Once
}

type mihomoLatencyStartError struct {
	err          error
	configLikely bool
}

type mihomoLatencyProxySnapshot struct {
	Proxies map[string]json.RawMessage `json:"proxies"`
}

func (e *mihomoLatencyStartError) Error() string { return e.err.Error() }
func (e *mihomoLatencyStartError) Unwrap() error { return e.err }

var protocolLatencySessions = make(chan struct{}, protocolLatencySessionMax)
var protocolLatencyCleanupOnce sync.Once

// ProbeProtocolLatency starts an isolated Mihomo for this request, loads every
// valid target, and invokes Mihomo's native /proxies/{name}/delay API. A failed
// combined configuration is bisected so a single unsupported node cannot poison
// the rest of a batch.
func ProbeProtocolLatency(ctx context.Context, mihomoBin string, targets []ProtocolLatencyTarget) []ProtocolLatencyResult {
	results := make([]ProtocolLatencyResult, len(targets))
	if len(targets) == 0 {
		return results
	}

	prepared := make([]preparedProtocolLatencyTarget, 0, len(targets))
	for index, target := range targets {
		proxy, err := decodeProtocolLatencyProxy(target.ClashConfig)
		if err != nil {
			results[index].Err = err
			continue
		}
		name := fmt.Sprintf("arcway-probe-%d", index+1)
		proxies := make([]map[string]interface{}, 0, len(target.DialerChain)+1)
		proxies = append(proxies, proxy)
		valid := true
		for _, dependencyConfig := range target.DialerChain {
			dependency, dependencyErr := decodeProtocolLatencyProxy(dependencyConfig)
			if dependencyErr != nil {
				results[index].Err = errors.New("前置代理的 Mihomo 配置无效")
				valid = false
				break
			}
			proxies = append(proxies, dependency)
		}
		if !valid {
			continue
		}
		wireGuardRelayBypass := make([]bool, len(proxies))
		copy(wireGuardRelayBypass, target.WireGuardRelayBypass)
		if existing := strings.TrimSpace(fmt.Sprint(proxies[len(proxies)-1]["dialer-proxy"])); existing != "" && existing != "<nil>" {
			results[index].Err = errors.New("节点引用了未包含的前置代理，无法按真实链路测试")
			continue
		}
		for level := range proxies {
			proxyName := name
			if level > 0 {
				proxyName = fmt.Sprintf("%s-hop-%d", name, level)
			}
			proxies[level]["name"] = proxyName
			if level+1 < len(proxies) {
				proxies[level]["dialer-proxy"] = fmt.Sprintf("%s-hop-%d", name, level+1)
			}
		}
		prepared = append(prepared, preparedProtocolLatencyTarget{
			index: index, name: name, proxies: proxies, wireGuardRelayBypass: wireGuardRelayBypass,
			hosts:   cloneLatencyHosts(target.Hosts),
			timeout: normalizedProtocolLatencyTimeout(target.Timeout),
		})
	}
	if len(prepared) == 0 {
		return results
	}

	select {
	case protocolLatencySessions <- struct{}{}:
		defer func() { <-protocolLatencySessions }()
	case <-ctx.Done():
		for _, target := range prepared {
			results[target.index].Err = errors.New("协议延迟测试已取消")
		}
		return results
	}

	probeProtocolLatencyGroup(ctx, mihomoBin, prepared, results)
	return results
}

func decodeProtocolLatencyProxy(raw string) (map[string]interface{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("节点缺少 Mihomo 配置")
	}
	var proxy map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&proxy); err != nil || proxy == nil {
		return nil, errors.New("节点 Mihomo 配置不是有效的 JSON 对象")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("节点 Mihomo 配置包含多余内容")
	}
	proxyType := strings.ToLower(strings.TrimSpace(fmt.Sprint(proxy["type"])))
	if proxyType == "" || proxyType == "<nil>" {
		return nil, errors.New("节点 Mihomo 配置缺少协议类型")
	}
	canonicalType, supported := supportedProtocolLatencyProxyTypes[proxyType]
	if !supported {
		return nil, fmt.Errorf("节点协议 %q 不支持 Mihomo 延迟测试", proxyType)
	}
	proxy["type"] = canonicalType
	if canonicalType == "mieru" {
		normalizeMieruPortSelection(proxy)
	}
	if err := validateProtocolLatencyInlineSecrets(proxy, canonicalType); err != nil {
		return nil, err
	}
	return proxy, nil
}

func normalizeMieruPortSelection(proxy map[string]interface{}) {
	portRange := strings.TrimSpace(fmt.Sprint(proxy["port-range"]))
	if portRange == "" || portRange == "<nil>" {
		return
	}
	delete(proxy, "port")
}

func validateProtocolLatencyInlineSecrets(proxy map[string]interface{}, proxyType string) error {
	var walk func(value interface{}, root bool) error
	walk = func(value interface{}, root bool) error {
		switch typed := value.(type) {
		case map[string]interface{}:
			for key, child := range typed {
				normalizedKey := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", "-"))
				switch normalizedKey {
				case "certificate":
					if !inlinePEMContains(child, "CERTIFICATE") {
						return errors.New("Mihomo 延迟测试不允许节点配置读取本地证书文件")
					}
				case "private-key":
					if root && proxyType == "wireguard" {
						if !inlineWireGuardKey(child) {
							return errors.New("WireGuard 延迟测试需要内联的 32 字节私钥")
						}
					} else if !inlinePEMContains(child, "PRIVATE KEY") {
						return errors.New("Mihomo 延迟测试不允许节点配置读取本地私钥文件")
					}
				}
				if err := walk(child, false); err != nil {
					return err
				}
			}
		case []interface{}:
			for _, child := range typed {
				if err := walk(child, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(proxy, true)
}

func inlinePEMContains(value interface{}, marker string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	text = strings.TrimSpace(text)
	return strings.Contains(text, "-----BEGIN "+marker+"-----") ||
		(strings.HasPrefix(text, "-----BEGIN ") && strings.Contains(text, marker+"-----"))
}

func inlineWireGuardKey(value interface{}) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	text = strings.TrimSpace(text)
	if len(text) == 64 {
		if decoded, err := hex.DecodeString(text); err == nil && len(decoded) == 32 {
			return true
		}
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(text); err == nil && len(decoded) == 32 {
			return true
		}
	}
	return false
}

func normalizedProtocolLatencyTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 5 * time.Second
	}
	if timeout < 500*time.Millisecond {
		return 500 * time.Millisecond
	}
	if timeout > 30*time.Second {
		return 30 * time.Second
	}
	return timeout
}

func cloneLatencyHosts(hosts map[string]string) map[string]string {
	if len(hosts) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(hosts))
	for host, address := range hosts {
		host = strings.TrimSpace(host)
		address = strings.TrimSpace(address)
		if host != "" && address != "" {
			cloned[host] = address
		}
	}
	return cloned
}

func probeProtocolLatencyGroup(ctx context.Context, mihomoBin string, targets []preparedProtocolLatencyTarget, results []ProtocolLatencyResult) {
	if len(targets) == 0 {
		return
	}
	session, err := startMihomoLatencySession(ctx, mihomoBin, targets)
	if err != nil {
		var startErr *mihomoLatencyStartError
		if len(targets) > 1 && errors.As(err, &startErr) && startErr.configLikely {
			middle := len(targets) / 2
			probeProtocolLatencyGroup(ctx, mihomoBin, targets[:middle], results)
			probeProtocolLatencyGroup(ctx, mihomoBin, targets[middle:], results)
			return
		}
		message := errors.New(safeMihomoLatencyError(err))
		for _, target := range targets {
			results[target.index].Err = message
		}
		return
	}
	defer session.stop()

	workers := protocolLatencyWorkers
	if len(targets) < workers {
		workers = len(targets)
	}
	jobs := make(chan preparedProtocolLatencyTarget)
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for target := range jobs {
				latency, probeErr := requestMihomoProtocolLatency(ctx, session.client, target.name, target.timeout)
				results[target.index] = ProtocolLatencyResult{Latency: latency, Err: probeErr}
			}
		}()
	}
	for _, target := range targets {
		select {
		case jobs <- target:
		case <-ctx.Done():
			results[target.index].Err = errors.New("协议延迟测试已取消")
		}
	}
	close(jobs)
	wait.Wait()
}

func startMihomoLatencySession(ctx context.Context, mihomoBin string, targets []preparedProtocolLatencyTarget) (*mihomoLatencySession, error) {
	if strings.TrimSpace(mihomoBin) == "" {
		return nil, &mihomoLatencyStartError{err: errors.New("Mihomo 核心路径为空")}
	}
	bin, err := filepath.Abs(mihomoBin)
	if err != nil {
		return nil, &mihomoLatencyStartError{err: errors.New("无法解析 Mihomo 核心路径")}
	}
	parent := filepath.Join("data", "mihomo-probe-tmp")
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, &mihomoLatencyStartError{err: fmt.Errorf("创建 Mihomo 探测目录: %w", err)}
	}
	_ = os.Chmod(parent, 0700)
	protocolLatencyCleanupOnce.Do(func() {
		cleanupAbandonedMihomoLatencyWorkdirs(parent)
	})
	workdir, err := os.MkdirTemp(parent, "run-")
	if err != nil {
		return nil, &mihomoLatencyStartError{err: fmt.Errorf("创建 Mihomo 临时目录: %w", err)}
	}
	workdir, err = filepath.Abs(workdir)
	if err != nil {
		_ = os.RemoveAll(workdir)
		return nil, &mihomoLatencyStartError{err: errors.New("无法解析 Mihomo 临时目录")}
	}
	_ = os.Chmod(workdir, 0700)
	var wireGuardRelays []io.Closer
	cleanup := func() {
		closeMihomoWireGuardRelays(wireGuardRelays)
		_ = os.RemoveAll(workdir)
	}

	socketPath := filepath.Join(workdir, "controller.sock")
	proxies := make([]map[string]interface{}, 0, len(targets))
	relayProxies := make([]map[string]interface{}, 0, len(targets))
	hosts := make(map[string]string)
	for _, target := range targets {
		for index, proxy := range target.proxies {
			cloned := cloneProtocolLatencyProxy(proxy)
			proxies = append(proxies, cloned)
			if index >= len(target.wireGuardRelayBypass) || !target.wireGuardRelayBypass[index] {
				relayProxies = append(relayProxies, cloned)
			}
		}
		for host, address := range target.hosts {
			if _, exists := hosts[host]; !exists {
				hosts[host] = address
			}
		}
	}
	wireGuardRelays, err = prepareMihomoWireGuardRelays(ctx, relayProxies, hosts)
	if err != nil {
		cleanup()
		var configErr *wireGuardRelayConfigError
		return nil, &mihomoLatencyStartError{err: err, configLikely: errors.As(err, &configErr)}
	}
	config := map[string]interface{}{
		"allow-lan":                false,
		"ipv6":                     true,
		"mode":                     "rule",
		"log-level":                "warning",
		"unified-delay":            false,
		"tcp-concurrent":           true,
		"external-controller-unix": socketPath,
		"secret":                   protocolLatencyAPISecret,
		"profile": map[string]interface{}{
			"store-selected": false,
			"store-fake-ip":  false,
		},
		"proxies": proxies,
	}
	if len(hosts) > 0 {
		config["hosts"] = hosts
	}
	configBytes, err := yaml.Marshal(config)
	if err != nil {
		cleanup()
		return nil, &mihomoLatencyStartError{err: errors.New("无法生成 Mihomo 探测配置"), configLikely: true}
	}
	configPath := filepath.Join(workdir, "config.yaml")
	configFile, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		cleanup()
		return nil, &mihomoLatencyStartError{err: fmt.Errorf("创建 Mihomo 探测配置: %w", err)}
	}
	_, writeErr := configFile.Write(configBytes)
	closeErr := configFile.Close()
	if writeErr != nil || closeErr != nil {
		cleanup()
		return nil, &mihomoLatencyStartError{err: errors.New("写入 Mihomo 探测配置失败")}
	}

	output := &boundedSynchronizedBuffer{limit: protocolLatencyOutputLimit}
	cmd := exec.Command(bin, "-d", workdir, "-f", configPath)
	cmd.Env = mihomoLatencyProcessEnvironment(workdir)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, &mihomoLatencyStartError{err: fmt.Errorf("启动 Mihomo 核心: %w", err)}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(dialCtx, "unix", socketPath)
		},
		DisableCompression: true,
	}
	session := &mihomoLatencySession{
		client: &http.Client{Transport: transport}, cmd: cmd, done: done, workdir: workdir,
		wireGuardRelays: wireGuardRelays,
	}

	deadline := time.NewTimer(protocolLatencyStartWait)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case waitErr := <-done:
			cleanup()
			configLikely := mihomoLatencyOutputLooksLikeConfigError(output.String())
			_ = waitErr
			// Mihomo's startup output can include serialized proxy fields. Never
			// return it to API clients because those fields may contain credentials.
			return nil, &mihomoLatencyStartError{err: errors.New("Mihomo 无法加载节点配置"), configLikely: configLikely}
		case <-ticker.C:
			ready, readyErr := mihomoLatencyTargetsReady(ctx, session.client, targets)
			if readyErr == nil && ready {
				return session, nil
			}
		case <-ctx.Done():
			session.stop()
			return nil, &mihomoLatencyStartError{err: errors.New("Mihomo 协议延迟测试已取消")}
		case <-deadline.C:
			session.stop()
			return nil, &mihomoLatencyStartError{err: errors.New("Mihomo 核心启动超时")}
		}
	}
}

func mihomoLatencyTargetsReady(ctx context.Context, client *http.Client, targets []preparedProtocolLatencyTarget) (bool, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://mihomo/proxies", nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+protocolLatencyAPISecret)
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Mihomo controller returned HTTP %d", response.StatusCode)
	}
	var snapshot mihomoLatencyProxySnapshot
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	if err := decoder.Decode(&snapshot); err != nil || snapshot.Proxies == nil {
		return false, errors.New("Mihomo controller returned an invalid proxy snapshot")
	}
	for _, target := range targets {
		for _, proxy := range target.proxies {
			name, ok := proxy["name"].(string)
			if !ok || strings.TrimSpace(name) == "" {
				return false, errors.New("Mihomo probe proxy is missing its runtime name")
			}
			if _, exists := snapshot.Proxies[name]; !exists {
				return false, nil
			}
		}
	}
	return true, nil
}

func cleanupAbandonedMihomoLatencyWorkdirs(parent string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "run-") {
			continue
		}
		_ = os.RemoveAll(filepath.Join(parent, entry.Name()))
	}
}

func mihomoLatencyProcessEnvironment(workdir string) []string {
	environment := []string{"HOME=" + workdir, "TMPDIR=" + workdir}
	// These variables only support the test helper. Production Mihomo does not
	// inherit SAFE_PATHS, proxy credentials, or other service environment data.
	for _, name := range []string{
		"ARCWAY_MIHOMO_LATENCY_HELPER",
		"ARCWAY_MIHOMO_LATENCY_TEST_BINARY",
		"ARCWAY_MIHOMO_LATENCY_HELPER_ERROR",
	} {
		if value, exists := os.LookupEnv(name); exists {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func mihomoLatencyOutputLooksLikeConfigError(output string) bool {
	output = strings.ToLower(output)
	for _, marker := range []string{"config", "yaml", "unmarshal", "proxy", "unsupported", "parse"} {
		if strings.Contains(output, marker) {
			return true
		}
	}
	return false
}

func (s *mihomoLatencySession) stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		if transport, ok := s.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		if s.cmd != nil && s.cmd.Process != nil {
			if runtime.GOOS == "windows" {
				_ = s.cmd.Process.Kill()
			} else {
				_ = s.cmd.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-s.done:
			case <-time.After(2 * time.Second):
				_ = s.cmd.Process.Kill()
				<-s.done
			}
		}
		closeMihomoWireGuardRelays(s.wireGuardRelays)
		_ = os.RemoveAll(s.workdir)
	})
}

func requestMihomoProtocolLatency(ctx context.Context, client *http.Client, proxyName string, timeout time.Duration) (float64, error) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	query := url.Values{}
	query.Set("url", protocolLatencyURL)
	query.Set("timeout", fmt.Sprintf("%d", timeout.Milliseconds()))
	query.Set("expected", "204")
	endpoint := "http://mihomo/proxies/" + url.PathEscape(proxyName) + "/delay?" + query.Encode()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, errors.New("无法创建 Mihomo 延迟请求")
	}
	request.Header.Set("Authorization", "Bearer "+protocolLatencyAPISecret)
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return 0, errors.New("Mihomo 协议握手或测试请求超时")
		}
		return 0, errors.New("Mihomo 无法通过该节点完成测试请求")
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	if readErr != nil {
		return 0, errors.New("无法读取 Mihomo 延迟结果")
	}
	if response.StatusCode != http.StatusOK {
		// Mihomo error payloads are free-form and can echo serialized proxy
		// fields. Keep them out of the API response because those fields may
		// contain passwords, UUIDs, tokens, or private keys.
		return 0, fmt.Errorf("Mihomo 无法通过该节点完成测试请求（HTTP %d）", response.StatusCode)
	}
	var payload struct {
		Delay json.Number `json:"delay"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil || payload.Delay == "" {
		return 0, errors.New("Mihomo 返回了无效的延迟结果")
	}
	delay, err := payload.Delay.Float64()
	if err != nil || delay < 0 {
		return 0, errors.New("Mihomo 返回了无效的延迟数值")
	}
	return delay, nil
}

func safeMihomoLatencyError(err error) string {
	if err == nil {
		return "Mihomo 协议延迟测试失败"
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	lower := strings.ToLower(message)
	for _, marker := range []string{
		"password", "passwd", "private-key", "private_key", "private key",
		"token", "secret", "uuid", "credential", "authorization", "psk",
	} {
		if strings.Contains(lower, marker) {
			return "Mihomo 协议延迟测试失败（敏感详情已隐藏）"
		}
	}
	if len(message) > 300 {
		message = message[:300] + "..."
	}
	return message
}

type boundedSynchronizedBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *boundedSynchronizedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(data)
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.buf.Write(data)
	}
	return written, nil
}

func (b *boundedSynchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
