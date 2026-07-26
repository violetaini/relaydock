package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"miaomiaowux/templates"
)

const nginxBridgeHelperStart = "cat > /usr/local/sbin/arcway-nginx-bridge << 'EOF'\n"

func generatedNginxBridgeHelper(t *testing.T) string {
	t.Helper()
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	_, tail, found := strings.Cut(response.Body.String(), nginxBridgeHelperStart)
	if !found {
		t.Fatal("generated installer is missing the Nginx bridge helper")
	}
	helper, _, found := strings.Cut(tail, "\nEOF\n")
	if !found {
		t.Fatal("generated installer has an unterminated Nginx bridge helper")
	}
	return helper
}

func TestRemoteInstallNginxBridgeAsset(t *testing.T) {
	helper := generatedNginxBridgeHelper(t)
	for _, expected := range []string{
		`HTTP_INCLUDE='/www/server/panel/vhost/nginx/*.conf'`,
		`STREAM_INCLUDE='/www/server/panel/vhost/nginx/tcp/*.conf'`,
		`include %s;\n`,
		`$MANAGED_ROOT/servers/*.conf`,
		`$MANAGED_ROOT/stream_servers/*.conf`,
		`map $http_upgrade $arcway_connection_upgrade {`,
		`-c "$BT_CONF" -t`,
		`-c "$BT_CONF" -T`,
		`# configuration file $HTTP_LOADER:`,
		`# configuration file $STREAM_LOADER:`,
		`rollback_bridge()`,
		`-c "$BT_CONF" -s reload`,
	} {
		if !strings.Contains(helper, expected) {
			t.Errorf("Nginx bridge helper missing %q", expected)
		}
	}
	if strings.Contains(helper, "ln -s") {
		t.Fatal("Nginx bridge helper uses a certificate-directory symlink")
	}
	if shell, err := exec.LookPath("sh"); err == nil {
		command := exec.Command(shell, "-n")
		command.Stdin = strings.NewReader(helper)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("generated Nginx bridge helper failed sh -n: %v\n%s", err, output)
		}
	}

	installScript := responseInstallScriptForNginxBridge(t)
	for _, expected := range []string{
		"/usr/local/sbin/arcway-nginx-bridge",
		"ExecStartPre=/usr/local/sbin/arcway-nginx-bridge",
		"/usr/local/sbin/arcway-nginx-bridge || return 1",
		`print "/usr/local/sbin/arcway-nginx-bridge || exit 1"`,
		"/www/server/panel/vhost/nginx/zz_arcway_loader.conf",
		"/www/server/panel/vhost/nginx/tcp/zz_arcway_loader.conf",
		`NGINX_CONF_PATH="${NGINX_PREFIX%/}/conf/nginx.conf"`,
	} {
		if !strings.Contains(installScript, expected) {
			t.Errorf("generated installer missing Nginx bridge integration %q", expected)
		}
	}
}

func responseInstallScriptForNginxBridge(t *testing.T) string {
	t.Helper()
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	return response.Body.String()
}

type nginxBridgeFixture struct {
	helperPath       string
	logPath          string
	httpLoader       string
	streamLoader     string
	mainConfig       string
	reloadFailMarker string
	environment      []string
}

func newNginxBridgeFixture(t *testing.T) nginxBridgeFixture {
	t.Helper()
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock is unavailable")
	}
	root := t.TempDir()
	btPrefix := filepath.Join(root, "www/server/nginx")
	vhostDir := filepath.Join(root, "www/server/panel/vhost/nginx")
	streamDir := filepath.Join(vhostDir, "tcp")
	managedRoot := filepath.Join(root, "usr/local/nginx")
	runDir := filepath.Join(root, "run")
	for _, directory := range []string{filepath.Join(btPrefix, "sbin"), filepath.Join(btPrefix, "conf"), streamDir, runDir} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	mainConfig := filepath.Join(btPrefix, "conf/nginx.conf")
	mainContent := "http {\n    include " + vhostDir + "/*.conf;\n}\n" +
		"stream {\n    include " + streamDir + "/*.conf;\n}\n"
	if err := os.WriteFile(mainConfig, []byte(mainContent), 0600); err != nil {
		t.Fatal(err)
	}

	helper := generatedNginxBridgeHelper(t)
	helper = strings.ReplaceAll(helper, "/www/server/panel/vhost/nginx", vhostDir)
	helper = strings.ReplaceAll(helper, "/www/server/nginx", btPrefix)
	helper = strings.ReplaceAll(helper, "/usr/local/nginx", managedRoot)
	helper = strings.ReplaceAll(helper, "/run/arcway-nginx-bridge", filepath.Join(runDir, "arcway-nginx-bridge"))
	helper = strings.ReplaceAll(helper, `chown root:root "$temp"`, `true`)
	helperPath := filepath.Join(root, "arcway-nginx-bridge")
	if err := os.WriteFile(helperPath, []byte(helper), 0700); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(root, "nginx.log")
	reloadFailMarker := filepath.Join(root, "reload.failed")
	httpLoader := filepath.Join(vhostDir, "zz_arcway_loader.conf")
	streamLoader := filepath.Join(streamDir, "zz_arcway_loader.conf")
	fakeNginx := `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_NGINX_LOG"
case " $* " in
    *" -t "*)
        [ "${FAKE_NGINX_FAIL_TEST:-0}" != "1" ]
        ;;
    *" -T "*)
        [ "${FAKE_NGINX_FAIL_DUMP:-0}" != "1" ] || exit 1
        printf '# configuration file %s:\n' "$FAKE_NGINX_CONF"
        if [ -f "$FAKE_HTTP_LOADER" ] && [ "${FAKE_NGINX_OMIT_HTTP:-0}" != "1" ]; then
            printf '# configuration file %s:\n' "$FAKE_HTTP_LOADER"
            cat "$FAKE_HTTP_LOADER"
        fi
        if [ -f "$FAKE_STREAM_LOADER" ] && [ "${FAKE_NGINX_OMIT_STREAM:-0}" != "1" ]; then
            printf '# configuration file %s:\n' "$FAKE_STREAM_LOADER"
            cat "$FAKE_STREAM_LOADER"
        fi
        ;;
    *" -s reload "*)
        if [ "${FAKE_NGINX_FAIL_RELOAD_ONCE:-0}" = "1" ] && [ ! -e "$FAKE_RELOAD_FAIL_MARKER" ]; then
            : > "$FAKE_RELOAD_FAIL_MARKER"
            exit 1
        fi
        ;;
    *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(btPrefix, "sbin/nginx"), []byte(fakeNginx), 0700); err != nil {
		t.Fatal(err)
	}
	return nginxBridgeFixture{
		helperPath: helperPath, logPath: logPath, httpLoader: httpLoader, streamLoader: streamLoader,
		mainConfig: mainConfig, reloadFailMarker: reloadFailMarker,
		environment: append(os.Environ(),
			"FAKE_NGINX_LOG="+logPath,
			"FAKE_NGINX_CONF="+mainConfig,
			"FAKE_HTTP_LOADER="+httpLoader,
			"FAKE_STREAM_LOADER="+streamLoader,
			"FAKE_RELOAD_FAIL_MARKER="+reloadFailMarker,
		),
	}
}

func (fixture nginxBridgeFixture) run(t *testing.T, extraEnvironment ...string) ([]byte, error) {
	t.Helper()
	command := exec.Command(fixture.helperPath)
	command.Env = append(append([]string{}, fixture.environment...), extraEnvironment...)
	return command.CombinedOutput()
}

func TestNginxBridgeHelperIsIdempotent(t *testing.T) {
	fixture := newNginxBridgeFixture(t)
	if output, err := fixture.run(t); err != nil {
		t.Fatalf("first bridge run failed: %v\n%s", err, output)
	}
	for _, loader := range []string{fixture.httpLoader, fixture.streamLoader} {
		info, err := os.Stat(loader)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("loader %s mode=%#o want=0600", loader, info.Mode().Perm())
		}
	}
	firstLog, err := os.ReadFile(fixture.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(firstLog), "-s reload"); got != 1 {
		t.Fatalf("first run reload count=%d want=1\n%s", got, firstLog)
	}
	if output, err := fixture.run(t); err != nil {
		t.Fatalf("second bridge run failed: %v\n%s", err, output)
	}
	secondLog, err := os.ReadFile(fixture.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(secondLog), "-s reload"); got != 1 {
		t.Fatalf("idempotent second run reloaded Nginx: count=%d\n%s", got, secondLog)
	}
}

func TestNginxBridgeHelperRollsBackWhenLoaderIsNotEffective(t *testing.T) {
	fixture := newNginxBridgeFixture(t)
	const oldHTTP = "# previous HTTP loader\n"
	const oldStream = "# previous stream loader\n"
	if err := os.WriteFile(fixture.httpLoader, []byte(oldHTTP), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.streamLoader, []byte(oldStream), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := fixture.run(t, "FAKE_NGINX_OMIT_STREAM=1")
	if err == nil {
		t.Fatalf("bridge accepted an unloaded stream loader:\n%s", output)
	}
	if !strings.Contains(string(output), "stream loader was written but is not loaded") {
		t.Fatalf("bridge failure was not explicit: %s", output)
	}
	for path, expected := range map[string]string{fixture.httpLoader: oldHTTP, fixture.streamLoader: oldStream} {
		content, readErr := os.ReadFile(path)
		if readErr != nil || string(content) != expected {
			t.Fatalf("loader %s was not restored: content=%q err=%v", path, content, readErr)
		}
	}
}

func TestNginxBridgeHelperRollsBackAfterReloadFailure(t *testing.T) {
	fixture := newNginxBridgeFixture(t)
	const oldHTTP = "# previous HTTP loader\n"
	const oldStream = "# previous stream loader\n"
	if err := os.WriteFile(fixture.httpLoader, []byte(oldHTTP), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.streamLoader, []byte(oldStream), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := fixture.run(t, "FAKE_NGINX_FAIL_RELOAD_ONCE=1")
	if err == nil {
		t.Fatalf("bridge accepted a failed reload:\n%s", output)
	}
	for path, expected := range map[string]string{fixture.httpLoader: oldHTTP, fixture.streamLoader: oldStream} {
		content, readErr := os.ReadFile(path)
		if readErr != nil || string(content) != expected {
			t.Fatalf("loader %s was not restored after reload failure: content=%q err=%v", path, content, readErr)
		}
	}
	logContent, readErr := os.ReadFile(fixture.logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got := strings.Count(string(logContent), "-s reload"); got != 2 {
		t.Fatalf("reload count=%d want=2 (failed new config + restored old config)\n%s", got, logContent)
	}
}

func TestNginxTemplatesUsePortableCertificateAndProxyHeaders(t *testing.T) {
	for _, name := range []string{
		"fallback/domain_proxy.conf",
		"fallback/domain_static.conf",
		"tunnel/domain_proxy.conf",
		"tunnel/domain_static.conf",
		"wss_domain.conf.tpl",
		"mmwx_domain.conf",
	} {
		content, err := templates.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(content)
		if !strings.Contains(text, "/usr/local/nginx/cert/") {
			t.Errorf("%s does not use the absolute managed certificate directory", name)
		}
		if strings.Contains(text, "ssl_certificate            cert/") || strings.Contains(text, "$proxy_add_forwarded") || strings.Contains(text, "$connection_upgrade") || strings.Contains(text, "$http_connection") {
			t.Errorf("%s still depends on a prefix-relative path or project-private Nginx variable", name)
		}
		if strings.Contains(text, "proxy_set_header Connection") && !strings.Contains(text, "$arcway_connection_upgrade") {
			t.Errorf("%s does not use the Arcway-owned WebSocket upgrade map", name)
		}
		if name == "wss_domain.conf.tpl" {
			if strings.Contains(text, "http2                      on;") || !strings.Contains(text, "listen                     443 ssl http2;") {
				t.Errorf("%s does not use the Nginx 1.24-compatible HTTP/2 listen syntax", name)
			}
		}
	}
	for _, name := range []string{"fallback/nginx.conf", "tunnel/nginx.conf", "single_nginx.conf"} {
		content, err := templates.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(content), "map $http_upgrade $arcway_connection_upgrade {") {
			t.Errorf("%s does not define the Arcway-owned WebSocket upgrade map", name)
		}
	}
}
