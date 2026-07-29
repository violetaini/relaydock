package speedtest

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	defaultTestURL      = "https://dl.google.com/dl/android/studio/install/3.4.1.0/android-studio-ide-183.5522156-windows.exe"
	defaultTestDuration = 8 * time.Second // 默认测速时长:下满 8s,按真实字节/真实耗时算速率
	latencyProbeURL     = "https://www.gstatic.com/generate_204"
	cfLatencyProbeURL   = "https://cp.cloudflare.com/generate_204" // 真连接延迟用 Cloudflare 204(全球边缘 + CDN 边)
	egressIPProbeURL    = "https://api.ipify.org"                  // 经代理回显出口 IP,用于核对出站链路是否符合预期
	mixedPort           = 17900                                    // 串行测速,固定端口即可
	cfLatencySamples    = 3                                        // 真延迟探测样本数,取最快 2 个平均(去掉首包冷启动 + 抖动尾;3 次足够稳,5 次太慢)
)

// runMu 串行化测速:一次只跑一个节点,避免并发抢带宽导致结果失真。
var runMu sync.Mutex

// Result 单节点测速结果。
type Result struct {
	DownMbps  float64
	LatencyMs int64
	Bytes     int64
	Duration  time.Duration
	EgressIP  string // 经代理观察到的出口 IP(可为空,失败不影响测速主流程)
}

// Options 测速参数(留空用默认)。
type Options struct {
	TestURL      string        // 测试下载 URL(默认大文件)
	TestDuration time.Duration // 测速时长(默认 8s):下载这么久,按真实字节/耗时算速率
	TestBytes    int64         // 可选下载上限(0=不限,纯按时长)
	Threads      int           // 并发下载线程数(默认 1,>=2 时并行下载,带宽聚合)
	Timeout      time.Duration
	LatencyOnly  bool // true 仅测真连接延迟(Cloudflare 204 多采样)不跑大文件下载
}

// RunNodeTest 用 mihomo 起单节点代理,测延迟 + 下行吞吐。clashConfigJSON 是 node.ClashConfig。
func RunNodeTest(ctx context.Context, mihomoBin, clashConfigJSON string, opts Options) (Result, error) {
	runMu.Lock()
	defer runMu.Unlock()

	if opts.TestDuration <= 0 {
		opts.TestDuration = defaultTestDuration
	}
	testURL := opts.TestURL
	if testURL == "" {
		testURL = defaultTestURL // 固定大文件,下载满测速时长即停
	}
	if opts.Timeout <= 0 {
		opts.Timeout = opts.TestDuration + 30*time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var proxy map[string]any
	if err := json.Unmarshal([]byte(clashConfigJSON), &proxy); err != nil {
		return Result{}, fmt.Errorf("解析节点 clash 配置失败: %w", err)
	}
	name, _ := proxy["name"].(string)
	if name == "" {
		name = "node"
		proxy["name"] = name
	}

	mini := map[string]any{
		"mixed-port":          mixedPort,
		"allow-lan":           false,
		"mode":                "rule",
		"log-level":           "warning",
		"external-controller": "127.0.0.1:0",
		"proxies":             []map[string]any{proxy},
		"proxy-groups": []map[string]any{
			{"name": "PROXY", "type": "select", "proxies": []string{name}},
		},
		"rules": []string{"MATCH,PROXY"},
	}
	cfg, err := yaml.Marshal(mini)
	if err != nil {
		return Result{}, err
	}

	workdir := filepath.Join("data", "speedtest-tmp", fmt.Sprintf("%d", time.Now().UnixNano()))
	stop, err := startMihomo(mihomoBin, workdir, cfg)
	if err != nil {
		return Result{}, err
	}
	defer func() { stop(); os.RemoveAll(workdir) }()

	egressIP := measureEgressIP(ctx)

	// LatencyOnly:只测真连接延迟(多采样 Cloudflare 204,取最快 3 个均值),不跑大文件下载
	if opts.LatencyOnly {
		latency := measureLatencyCloudflare(ctx, cfLatencySamples)
		return Result{LatencyMs: latency, EgressIP: egressIP}, nil
	}

	latency := measureLatency(ctx)

	threads := opts.Threads
	if threads < 1 {
		threads = 1
	}
	n, dur, err := downloadTimed(ctx, testURL, opts.TestDuration, opts.TestBytes, threads)
	if err != nil {
		return Result{LatencyMs: latency, EgressIP: egressIP}, fmt.Errorf("下载测速失败: %w", err)
	}
	mbps := 0.0
	if dur > 0 {
		mbps = float64(n) * 8 / dur.Seconds() / 1e6
	}
	return Result{DownMbps: mbps, LatencyMs: latency, Bytes: n, Duration: dur, EgressIP: egressIP}, nil
}

func startMihomo(bin, workdir string, cfg []byte) (func(), error) {
	if err := os.MkdirAll(workdir, 0755); err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(workdir, "config.yaml")
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-d", workdir, "-f", cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", mixedPort)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, derr := (&net.Dialer{Timeout: 500 * time.Millisecond}).Dial("tcp", addr); derr == nil {
			c.Close()
			var once sync.Once
			return func() {
				once.Do(func() {
					done := make(chan error, 1)
					go func() { done <- cmd.Wait() }()
					// Windows 不支持向子进程发 SIGTERM,直接 Kill;其它平台先优雅 SIGTERM 再兜底 Kill。
					if runtime.GOOS == "windows" {
						_ = cmd.Process.Kill()
					} else {
						_ = cmd.Process.Signal(syscall.SIGTERM)
					}
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						_ = cmd.Process.Kill()
						<-done
					}
				})
			}, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return nil, fmt.Errorf("mihomo 启动超时(端口 %d 15s 内未就绪)", mixedPort)
}

// proxyClient 经 mihomo mixed-port 走代理的 HTTP 客户端。
//
// 性能调优(单流测速接近 iperf3 单线程):
//   - ReadBufferSize 1MB:loopback 接 mihomo 时降低 read syscall 频率;默认 4KB 在 1Gbps 下要 ~30k 次/秒
//   - DisableCompression:测试文件多为已压缩二进制,客户端再 gzip 一次纯浪费 CPU
//   - ForceAttemptHTTP2=false + TLSNextProto={}:HTTP/2 单流会被流控限速,HTTP/1.1 直接吃满
//   - DisableKeepAlives=false 默认:虽然单次只发一个请求,但 HTTPS 的 TLS 复用对多次探测有帮助
//   - 单进程复用一个 Transport,避免反复建 TLS / 连接池
func proxyClient() *http.Client {
	return &http.Client{Transport: sharedProxyTransport()}
}

var (
	sharedTransportOnce sync.Once
	sharedTransport     *http.Transport
)

func sharedProxyTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
		sharedTransport = &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			ReadBufferSize:     1 << 20, // 1MB
			WriteBufferSize:    64 << 10,
			DisableCompression: true,
			ForceAttemptHTTP2:  false,
			TLSNextProto:       map[string]func(string, *tls.Conn) http.RoundTripper{}, // 显式禁 HTTP/2
			MaxIdleConns:       64,
			IdleConnTimeout:    90 * time.Second,
		}
	})
	return sharedTransport
}

// 测速吞吐用的 io.Copy 缓冲(1MB);default 32KB 在 >100Mbps 时 syscall 太密。
var bigCopyBufPool = sync.Pool{
	New: func() any { b := make([]byte, 1<<20); return &b },
}

// measureLatency 经代理 GET 一个 204 端点,返回毫秒;失败返回 -1。
func measureLatency(ctx context.Context) int64 {
	client := proxyClient()
	client.Timeout = 10 * time.Second
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latencyProbeURL, nil)
	if err != nil {
		return -1
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return time.Since(start).Milliseconds()
}

// measureLatencyCloudflare 用 Cloudflare 204(全球边缘 + CDN 边)多次采样,取最快 3 个的均值;
// 首包受 TLS 握手 / mihomo cold-start 影响,平均后更接近"真连接延迟"。全部失败返回 -1。
func measureLatencyCloudflare(ctx context.Context, samples int) int64 {
	if samples <= 0 {
		samples = cfLatencySamples
	}
	client := proxyClient()
	client.Timeout = 8 * time.Second
	probes := make([]int64, 0, samples)
	for i := 0; i < samples; i++ {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfLatencyProbeURL, nil)
		if err != nil {
			continue
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		probes = append(probes, time.Since(start).Milliseconds())
	}
	if len(probes) == 0 {
		return -1
	}
	// 取最快 2 个均值(去掉首包冷启动的最慢一个);不足 2 个全取
	sortInt64Asc(probes)
	keep := 2
	if len(probes) < keep {
		keep = len(probes)
	}
	var sum int64
	for i := 0; i < keep; i++ {
		sum += probes[i]
	}
	return sum / int64(keep)
}

func sortInt64Asc(a []int64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// measureEgressIP 经代理请求一个 IP 回显端点,拿到出口 IP;失败返回空(不影响主测速流程)。
func measureEgressIP(ctx context.Context) string {
	client := proxyClient()
	client.Timeout = 8 * time.Second
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, egressIPProbeURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(buf))
	// 简单校验:含 . 或 :,长度合理(IPv4 / IPv6)。
	if len(ip) < 3 || len(ip) > 45 || (!strings.Contains(ip, ".") && !strings.Contains(ip, ":")) {
		return ""
	}
	return ip
}

// downloadTimed 经代理下载,最多下载 dur 时长(到时即停),可选 maxBytes 上限(0=不限)。
// threads >= 2 时并行起 N 路下载聚合带宽(单连接受拥塞控制 / 单核加密上限制约,多连接能更接近真实带宽)。
// 返回实际下载字节数与实际墙钟耗时。到时停止是正常结束(不算错误);时长内连接全部出错才算失败。
func downloadTimed(ctx context.Context, dlURL string, dur time.Duration, maxBytes int64, threads int) (int64, time.Duration, error) {
	dlCtx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	if threads <= 1 {
		return downloadSingle(dlCtx, dlURL, maxBytes)
	}

	var wg sync.WaitGroup
	results := make([]int64, threads)
	errs := make([]error, threads)
	start := time.Now()
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			threadLimit, active := splitThreadByteBudget(maxBytes, threads, idx)
			if !active {
				return
			}
			n, _, e := downloadSingle(dlCtx, dlURL, threadLimit)
			results[idx] = n
			errs[idx] = e
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	var total int64
	var firstErr error
	for i := 0; i < threads; i++ {
		total += results[i]
		if errs[i] != nil && firstErr == nil {
			firstErr = errs[i]
		}
	}
	if total > 0 {
		// 至少有一路下到了字节就算成功 — 多线程聚合下,部分子流被掐不影响主流统计
		return total, elapsed, nil
	}
	return 0, elapsed, firstErr
}

// splitThreadByteBudget divides a total byte cap across workers. A zero cap
// means unlimited; active=false prevents a zero-sized share becoming unlimited.
func splitThreadByteBudget(maxBytes int64, threads, index int) (limit int64, active bool) {
	if threads <= 0 || index < 0 || index >= threads {
		return 0, false
	}
	if maxBytes <= 0 {
		return 0, true
	}
	limit = maxBytes / int64(threads)
	if int64(index) < maxBytes%int64(threads) {
		limit++
	}
	return limit, limit > 0
}

// downloadSingle 单连接下载,被 downloadTimed 复用。
// 性能:用 1MB 缓冲的 io.CopyBuffer(默认 io.Copy 是 32KB,>100Mbps 时 syscall 太密);
// Accept-Encoding identity 防中间盒强行 gzip 已压缩内容白费 CPU。
func downloadSingle(ctx context.Context, dlURL string, maxBytes int64) (int64, time.Duration, error) {
	client := proxyClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 relaydock-speedtest/1.0")
	req.Header.Set("Accept-Encoding", "identity")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var reader io.Reader = resp.Body
	if maxBytes > 0 {
		reader = io.LimitReader(resp.Body, maxBytes)
	}
	buf := bigCopyBufPool.Get().(*[]byte)
	defer bigCopyBufPool.Put(buf)
	n, cerr := io.CopyBuffer(io.Discard, reader, *buf)
	elapsed := time.Since(start)
	// 到时(deadline)是预期的正常结束;文件提前下完也正常。只有时长内提前出错才算失败。
	if ctx.Err() == context.DeadlineExceeded || cerr == nil {
		return n, elapsed, nil
	}
	return n, elapsed, cerr
}
