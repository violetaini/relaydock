package speedtest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDecodeProtocolLatencyProxyCanonicalizesSupportedTypes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "vmess", want: "vmess"},
		{input: "vless", want: "vless"},
		{input: "trojan", want: "trojan"},
		{input: "ss", want: "ss"},
		{input: "shadowsocks", want: "ss"},
		{input: "ssr", want: "ssr"},
		{input: "socks", want: "socks5"},
		{input: "socks5", want: "socks5"},
		{input: "http", want: "http"},
		{input: "hysteria", want: "hysteria"},
		{input: "hy2", want: "hysteria2"},
		{input: "hysteria2", want: "hysteria2"},
		{input: "tuic", want: "tuic"},
		{input: "anytls", want: "anytls"},
		{input: "wg", want: "wireguard"},
		{input: "wireguard", want: "wireguard"},
		{input: "snell", want: "snell"},
		{input: "ssh", want: "ssh"},
		{input: "mieru", want: "mieru"},
		{input: " SHADOWSOCKS ", want: "ss"},
	}

	for _, tt := range tests {
		t.Run(strings.TrimSpace(tt.input), func(t *testing.T) {
			raw := fmt.Sprintf(`{"name":"original","type":%q,"server":"203.0.113.10","port":443}`, tt.input)
			proxy, err := decodeProtocolLatencyProxy(raw)
			if err != nil {
				t.Fatalf("decodeProtocolLatencyProxy() error = %v", err)
			}
			if got := proxy["type"]; got != tt.want {
				t.Fatalf("canonical type = %#v, want %q", got, tt.want)
			}
			if got := proxy["name"]; got != "original" {
				t.Fatalf("proxy name = %#v, want original", got)
			}
		})
	}
}

func TestDecodeProtocolLatencyProxyRejectsTypesUnsupportedByPinnedMihomo(t *testing.T) {
	for _, proxyType := range []string{"naive", "juicity"} {
		t.Run(proxyType, func(t *testing.T) {
			_, err := decodeProtocolLatencyProxy(fmt.Sprintf(`{"name":"unsupported","type":%q}`, proxyType))
			if err == nil || !strings.Contains(err.Error(), "不支持 Mihomo 延迟测试") {
				t.Fatalf("decodeProtocolLatencyProxy() error = %v, want pinned-Mihomo rejection", err)
			}
		})
	}
}

func TestDecodeProtocolLatencyProxyNormalizesMieruPortRange(t *testing.T) {
	proxy, err := decodeProtocolLatencyProxy(`{"name":"mieru","type":"mieru","server":"203.0.113.10","port":0,"port-range":"5000-5010"}`)
	if err != nil {
		t.Fatalf("decodeProtocolLatencyProxy() error = %v", err)
	}
	if _, exists := proxy["port"]; exists {
		t.Fatalf("Mieru port-range config retained mutually exclusive port: %#v", proxy)
	}
	if proxy["port-range"] != "5000-5010" {
		t.Fatalf("Mieru port-range = %#v", proxy["port-range"])
	}
}

func TestDecodeProtocolLatencyProxyRejectsLocalSecretPaths(t *testing.T) {
	wireGuardKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	inlineCertificate := "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
	inlinePrivateKey := "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----"
	tests := []struct {
		name    string
		proxy   map[string]interface{}
		wantErr bool
	}{
		{
			name: "TLS certificate path",
			proxy: map[string]interface{}{
				"type": "vless", "certificate": "/etc/ssl/private/client.pem",
			},
			wantErr: true,
		},
		{
			name: "nested TLS private key path",
			proxy: map[string]interface{}{
				"type": "vless", "download-settings": map[string]interface{}{"private-key": "/etc/shadow"},
			},
			wantErr: true,
		},
		{
			name: "inline TLS identity",
			proxy: map[string]interface{}{
				"type": "vless", "certificate": inlineCertificate, "private-key": inlinePrivateKey,
			},
		},
		{
			name: "WireGuard key path",
			proxy: map[string]interface{}{
				"type": "wireguard", "private-key": "/etc/shadow",
			},
			wantErr: true,
		},
		{
			name: "inline WireGuard key",
			proxy: map[string]interface{}{
				"type": "wireguard", "private-key": wireGuardKey,
			},
		},
		{
			name: "SSH key path",
			proxy: map[string]interface{}{
				"type": "ssh", "private-key": "/root/.ssh/id_ed25519",
			},
			wantErr: true,
		},
		{
			name: "inline SSH key",
			proxy: map[string]interface{}{
				"type": "ssh", "private-key": "-----BEGIN OPENSSH PRIVATE KEY-----\nTEST\n-----END OPENSSH PRIVATE KEY-----",
			},
		},
		{
			name: "SSH password",
			proxy: map[string]interface{}{
				"type": "ssh", "username": "probe", "password": "secret",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.proxy)
			if err != nil {
				t.Fatal(err)
			}
			_, err = decodeProtocolLatencyProxy(string(raw))
			if test.wantErr && err == nil {
				t.Fatal("decodeProtocolLatencyProxy() error = nil, want local-path rejection")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("decodeProtocolLatencyProxy() error = %v", err)
			}
			if err != nil && (strings.Contains(err.Error(), "/etc/") || strings.Contains(err.Error(), "/root/")) {
				t.Fatalf("decodeProtocolLatencyProxy() exposed a local path: %v", err)
			}
		})
	}
}

func TestDecodeProtocolLatencyProxyRejectsNonProxyTypes(t *testing.T) {
	for _, proxyType := range []string{
		"direct", "reject", "reject-drop", "pass", "compatible",
		"selector", "url-test", "fallback", "load-balance", "relay",
	} {
		t.Run(proxyType, func(t *testing.T) {
			_, err := decodeProtocolLatencyProxy(fmt.Sprintf(`{"name":"not-a-proxy","type":%q}`, proxyType))
			if err == nil {
				t.Fatal("decodeProtocolLatencyProxy() error = nil, want unsupported type error")
			}
			if !strings.Contains(err.Error(), "不支持 Mihomo 延迟测试") {
				t.Fatalf("decodeProtocolLatencyProxy() error = %q, want unsupported type context", err)
			}
		})
	}
}

func TestDecodeProtocolLatencyProxyRejectsInvalidObjects(t *testing.T) {
	tests := map[string]string{
		"empty":        "",
		"invalid JSON": `{"type":`,
		"array":        `[{"type":"vmess"}]`,
		"null":         `null`,
		"missing type": `{"name":"missing"}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeProtocolLatencyProxy(raw); err == nil {
				t.Fatal("decodeProtocolLatencyProxy() error = nil, want validation error")
			}
		})
	}
}

func TestRequestMihomoProtocolLatencyUsesNativeDelayAPI(t *testing.T) {
	const proxyName = "edge / Hong Kong?%"
	const timeout = 1750 * time.Millisecond

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("request method = %q, want GET", request.Method)
		}
		if request.URL.Scheme != "http" || request.URL.Host != "mihomo" {
			t.Fatalf("request URL origin = %s://%s, want http://mihomo", request.URL.Scheme, request.URL.Host)
		}
		wantPath := "/proxies/" + url.PathEscape(proxyName) + "/delay"
		if got := request.URL.EscapedPath(); got != wantPath {
			t.Fatalf("request escaped path = %q, want %q", got, wantPath)
		}
		query := request.URL.Query()
		if got := query.Get("url"); got != protocolLatencyURL {
			t.Fatalf("url query = %q, want %q", got, protocolLatencyURL)
		}
		if got := query.Get("timeout"); got != "1750" {
			t.Fatalf("timeout query = %q, want 1750", got)
		}
		if got := query.Get("expected"); got != "204" {
			t.Fatalf("expected query = %q, want 204", got)
		}
		if len(query) != 3 {
			t.Fatalf("query = %#v, want exactly url, timeout, and expected", query)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+protocolLatencyAPISecret {
			t.Fatalf("Authorization = %q, want Mihomo bearer secret", got)
		}
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Fatal("request context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= time.Second || remaining > timeout {
			t.Fatalf("request deadline remaining = %v, want a fresh %v deadline", remaining, timeout)
		}
		return latencyResponse(http.StatusOK, `{"delay":42.5}`), nil
	})}

	latency, err := requestMihomoProtocolLatency(context.Background(), client, proxyName, timeout)
	if err != nil {
		t.Fatalf("requestMihomoProtocolLatency() error = %v", err)
	}
	if latency != 42.5 {
		t.Fatalf("requestMihomoProtocolLatency() latency = %v, want 42.5", latency)
	}
}

func TestRequestMihomoProtocolLatencyReturnsSanitizedErrors(t *testing.T) {
	const secret = "latency-secret-must-not-leak"

	tests := []struct {
		name       string
		statusCode int
		body       string
		want       string
	}{
		{
			name:       "Mihomo error payload",
			statusCode: http.StatusBadGateway,
			body:       `{"message":"dial failed: password=` + secret + ` private-key=` + secret + `"}`,
			want:       "HTTP 502",
		},
		{name: "invalid JSON", statusCode: http.StatusOK, body: `{`, want: "无效的延迟结果"},
		{name: "missing delay", statusCode: http.StatusOK, body: `{}`, want: "无效的延迟结果"},
		{name: "negative delay", statusCode: http.StatusOK, body: `{"delay":-1}`, want: "无效的延迟数值"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return latencyResponse(tt.statusCode, tt.body), nil
			})}
			latency, err := requestMihomoProtocolLatency(context.Background(), client, "probe", time.Second)
			if err == nil {
				t.Fatal("requestMihomoProtocolLatency() error = nil, want error")
			}
			if latency != 0 {
				t.Fatalf("requestMihomoProtocolLatency() latency = %v, want 0 on error", latency)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("requestMihomoProtocolLatency() error = %q, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("requestMihomoProtocolLatency() leaked a credential: %q", err)
			}
		})
	}

	t.Run("transport error", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("proxy password=" + secret)
		})}
		_, err := requestMihomoProtocolLatency(context.Background(), client, "probe", time.Second)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("requestMihomoProtocolLatency() error = %v, want sanitized transport error", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, fmt.Errorf("password=%s: %w", secret, request.Context().Err())
		})}
		_, err := requestMihomoProtocolLatency(context.Background(), client, "probe", 25*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "超时") || strings.Contains(err.Error(), secret) {
			t.Fatalf("requestMihomoProtocolLatency() error = %v, want sanitized timeout", err)
		}
	})
}

func TestSafeMihomoLatencyErrorHidesSensitiveDetails(t *testing.T) {
	const secret = "credential-value-must-not-leak"
	for _, message := range []string{
		"password=" + secret,
		"PASSWD: " + secret,
		"private-key=" + secret,
		"private_key=" + secret,
		"private key: " + secret,
		"token=" + secret,
		"secret=" + secret,
		"uuid=" + secret,
		"credential=" + secret,
		"Authorization: Bearer " + secret,
		"psk=" + secret,
	} {
		got := safeMihomoLatencyError(errors.New(message))
		if strings.Contains(got, secret) || !strings.Contains(got, "敏感详情已隐藏") {
			t.Fatalf("safeMihomoLatencyError(%q) = %q, want hidden detail", message, got)
		}
	}
}

func TestStartMihomoLatencySessionWritesIsolatedMinimalConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Mihomo latency sessions use a Unix controller socket")
	}

	root, err := os.MkdirTemp("/tmp", "arcway-mihomo-test-")
	if err != nil {
		t.Fatalf("MkdirTemp(): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Chdir(root)
	helper, helperErrors := writeMihomoLatencyHelper(t)
	t.Setenv("SAFE_PATHS", "/etc:/root")

	targets := []preparedProtocolLatencyTarget{
		{
			name: "arcway-probe-1",
			proxies: []map[string]interface{}{
				{
					"name": "arcway-probe-1", "type": "vless", "server": "edge.example.test",
					"port": 443, "uuid": "test-credential", "dialer-proxy": "arcway-probe-1-hop-1",
				},
				{
					"name": "arcway-probe-1-hop-1", "type": "socks5", "server": "198.51.100.7",
					"port": 1080, "password": "test-password",
				},
			},
			hosts: map[string]string{"edge.example.test": "203.0.113.7"},
		},
	}

	session, err := startMihomoLatencySession(context.Background(), helper, targets)
	if err != nil {
		diagnostics, _ := os.ReadFile(helperErrors)
		t.Fatalf("startMihomoLatencySession() error = %v; helper diagnostics = %s", err, diagnostics)
	}
	stopped := false
	defer func() {
		if !stopped {
			session.stop()
		}
	}()

	workdir := session.workdir
	assertMode(t, filepath.Dir(workdir), 0700)
	assertMode(t, workdir, 0700)
	configPath := filepath.Join(workdir, "config.yaml")
	assertMode(t, configPath, 0600)

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", configPath, err)
	}
	var config map[string]interface{}
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		t.Fatalf("generated config is invalid YAML: %v", err)
	}

	assertConfigValue(t, config, "allow-lan", false)
	assertConfigValue(t, config, "ipv6", true)
	assertConfigValue(t, config, "mode", "rule")
	assertConfigValue(t, config, "log-level", "warning")
	assertConfigValue(t, config, "unified-delay", false)
	assertConfigValue(t, config, "tcp-concurrent", true)
	assertConfigValue(t, config, "secret", protocolLatencyAPISecret)

	controller, ok := config["external-controller-unix"].(string)
	if !ok || controller != filepath.Join(workdir, "controller.sock") {
		t.Fatalf("external-controller-unix = %#v, want socket inside workdir", config["external-controller-unix"])
	}
	for _, forbidden := range []string{
		"port", "socks-port", "mixed-port", "redir-port", "tproxy-port", "tun",
		"external-controller", "external-ui",
	} {
		if _, exists := config[forbidden]; exists {
			t.Fatalf("generated config unexpectedly exposes %q", forbidden)
		}
	}

	proxies, ok := config["proxies"].([]interface{})
	if !ok || len(proxies) != 2 {
		t.Fatalf("generated proxies = %#v, want primary plus one dialer", config["proxies"])
	}
	hosts, ok := config["hosts"].(map[string]interface{})
	if !ok || hosts["edge.example.test"] != "203.0.113.7" {
		t.Fatalf("generated hosts = %#v, want pinned endpoint", config["hosts"])
	}
	profile, ok := config["profile"].(map[string]interface{})
	if !ok || profile["store-selected"] != false || profile["store-fake-ip"] != false {
		t.Fatalf("generated profile = %#v, want persistence disabled", config["profile"])
	}

	session.stop()
	stopped = true
	if _, err := os.Stat(workdir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary workdir still exists after stop: Stat error = %v", err)
	}
}

func TestCleanupAbandonedMihomoLatencyWorkdirs(t *testing.T) {
	parent := t.TempDir()
	abandoned := filepath.Join(parent, "run-abandoned")
	if err := os.MkdirAll(abandoned, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(abandoned, "config.yaml"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(parent, "keep-cache")
	if err := os.MkdirAll(keep, 0700); err != nil {
		t.Fatal(err)
	}

	cleanupAbandonedMihomoLatencyWorkdirs(parent)

	if _, err := os.Stat(abandoned); !os.IsNotExist(err) {
		t.Fatalf("abandoned run directory still exists: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("unrelated directory was removed: %v", err)
	}
}

// TestMihomoLatencyHelperProcess is launched through a small wrapper script by
// TestStartMihomoLatencySessionWritesIsolatedMinimalConfig.
func TestMihomoLatencyHelperProcess(t *testing.T) {
	if os.Getenv("ARCWAY_MIHOMO_LATENCY_HELPER") != "1" {
		return
	}
	if os.Getenv("SAFE_PATHS") != "" {
		failMihomoLatencyHelper("helper inherited SAFE_PATHS")
	}
	configPath := helperArgument(os.Args, "-f")
	if configPath == "" {
		failMihomoLatencyHelper("helper did not receive -f")
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		failMihomoLatencyHelper("helper read config: %v", err)
	}
	var config struct {
		Controller string `yaml:"external-controller-unix"`
	}
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		failMihomoLatencyHelper("helper parse config: %v", err)
	}
	listener, err := net.Listen("unix", config.Controller)
	if err != nil {
		failMihomoLatencyHelper("helper listen: %v", err)
	}
	defer listener.Close()
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		_ = connection.Close()
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func latencyResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func writeMihomoLatencyHelper(t *testing.T) (string, string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable(): %v", err)
	}
	t.Setenv("ARCWAY_MIHOMO_LATENCY_HELPER", "1")
	t.Setenv("ARCWAY_MIHOMO_LATENCY_TEST_BINARY", binary)
	errorPath := filepath.Join(t.TempDir(), "mihomo-test-helper.err")
	t.Setenv("ARCWAY_MIHOMO_LATENCY_HELPER_ERROR", errorPath)
	path := filepath.Join(t.TempDir(), "mihomo-test-helper")
	script := "#!/bin/sh\nexec \"$ARCWAY_MIHOMO_LATENCY_TEST_BINARY\" -test.run=^TestMihomoLatencyHelperProcess$ -- \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	return path, errorPath
}

func failMihomoLatencyHelper(format string, arguments ...interface{}) {
	message := fmt.Sprintf(format, arguments...)
	_ = os.WriteFile(os.Getenv("ARCWAY_MIHOMO_LATENCY_HELPER_ERROR"), []byte(message), 0600)
	os.Exit(2)
}

func helperArgument(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %q = %04o, want %04o", path, got, want)
	}
}

func assertConfigValue(t *testing.T, config map[string]interface{}, key string, want interface{}) {
	t.Helper()
	if got := config[key]; got != want {
		t.Fatalf("generated config %q = %#v, want %#v", key, got, want)
	}
}
