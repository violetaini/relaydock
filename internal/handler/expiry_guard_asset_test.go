package handler

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/expiryguard"
	"github.com/violetaini/relaydock/internal/storage"
	"github.com/violetaini/relaydock/internal/version"
)

func newExpiryGuardAssetHandler(t *testing.T) (*XrayServerHandler, string) {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	installExpiryGuardAssetFixtures(t)
	token := "remote-asset-token"
	server := &storage.RemoteServer{
		Name: "asset-edge", Token: token, Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatalf("CreateRemoteServer: %v", err)
	}
	return NewXrayServerHandler(repo, nil, nil), token
}

func installExpiryGuardAssetFixtures(t *testing.T) {
	t.Helper()
	assetDirectory := t.TempDir()
	for _, name := range []string{"arcway-expiry-guard-linux-amd64", "arcway-expiry-guard-linux-arm64"} {
		if err := os.WriteFile(filepath.Join(assetDirectory, name), []byte("\x7fELF-test-"+name), 0755); err != nil {
			t.Fatalf("write guard fixture: %v", err)
		}
	}
	t.Setenv(expiryGuardAssetDirEnv, assetDirectory)
}

func requestExpiryGuardAsset(handler *XrayServerHandler, method, arch, authorization string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/api/remote/expiry-guard?arch="+arch, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.GetExpiryGuardAsset(response, request)
	return response
}

func TestExpiryGuardAssetRequiresRemoteBearerToken(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)

	for _, authorization := range []string{"", "Bearer invalid-token", token, "Basic " + token} {
		response := requestExpiryGuardAsset(handler, http.MethodGet, "amd64", authorization)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q status=%d want=%d", authorization, response.Code, http.StatusUnauthorized)
		}
		if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("security headers missing: %#v", response.Header())
		}
	}
}

func TestExpiryGuardAssetValidatesArchitectureAndMissingAsset(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)
	t.Setenv(expiryGuardAssetDirEnv, t.TempDir())

	invalid := requestExpiryGuardAsset(handler, http.MethodGet, "386", "Bearer "+token)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid architecture status=%d want=%d", invalid.Code, http.StatusBadRequest)
	}

	missing := requestExpiryGuardAsset(handler, http.MethodGet, "arm64", "Bearer "+token)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing asset status=%d want=%d body=%s", missing.Code, http.StatusNotFound, missing.Body.String())
	}
}

func TestExpiryGuardAssetServesConfiguredBinary(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)
	directory := t.TempDir()
	t.Setenv(expiryGuardAssetDirEnv, directory)
	const content = "guard-binary-content"
	name := "arcway-expiry-guard-linux-amd64"
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	response := requestExpiryGuardAsset(handler, http.MethodGet, "amd64", "bearer "+token)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if response.Body.String() != content {
		t.Fatalf("body=%q want=%q", response.Body.String(), content)
	}
	if got := response.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := response.Header().Get("Content-Disposition"); got != `attachment; filename="`+name+`"` {
		t.Fatalf("Content-Disposition=%q", got)
	}
}

func TestExpiryGuardAssetRejectsNonRegularAsset(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)
	directory := t.TempDir()
	t.Setenv(expiryGuardAssetDirEnv, directory)
	name := "arcway-expiry-guard-linux-amd64"
	if err := os.Symlink(filepath.Join(directory, "does-not-matter"), filepath.Join(directory, name)); err != nil {
		t.Fatal(err)
	}

	response := requestExpiryGuardAsset(handler, http.MethodGet, "amd64", "Bearer "+token)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("symlink status=%d want=%d", response.Code, http.StatusInternalServerError)
	}
}

func TestRemoteInstallScriptInstallsExpiryGuard(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10, 2001:db8::10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet,
		"https://panel.example/api/remote/install.sh?listen_port=25000", nil)
	request.Host = "panel.example"
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusOK, response.Body.String())
	}

	script := response.Body.String()
	for _, expected := range []string{
		"ASSET_RELEASE_BASE_URL='https://github.com/violetaini/relaydock/releases/download/v" + version.Version + "'",
		"AGENT_GITHUB_URL=\"${ASSET_RELEASE_BASE_URL}/relaydock-agent-linux-${ARCH_NAME}\"",
		"release_asset_sha256() {",
		"download_verified_github_asset() {",
		"AGENT_SHA256=$(release_asset_sha256 \"relaydock-agent-linux-${ARCH_NAME}\" \"${ASSET_RELEASE_BASE_URL}/checksums.txt\" \"$DOWNLOAD_DIR/relaydock-agent-checksums.txt\") || exit 1",
		"download_verified_github_asset \"relaydock-agent\" \"$AGENT_DOWNLOAD\" \"$AGENT_SHA256\" \"$AGENT_GITHUB_URL\" || exit 1",
		"GUARD_GITHUB_URL=\"${ASSET_RELEASE_BASE_URL}/arcway-expiry-guard-linux-${ARCH_NAME}\"",
		"Downloading $label from GitHub Release...",
		"Downloading $label from master fallback...",
		"relaydock-agent SHA-256 verification failed",
		"/api/remote/expiry-guard?arch=${ARCH_NAME}",
		"/api/remote/management-ready",
		"/api/remote/install-begin",
		"/api/remote/install-renew",
		"/api/remote/install-abort",
		"/api/remote/install-prepare",
		"/api/remote/install-finalize",
		"CURL_AUTH_HEADER_FILE=\"$DOWNLOAD_DIR/curl-auth.header\"",
		"printf 'Authorization: Bearer %s\\n' \"$TOKEN\"",
		"printf 'User-Agent: %s\\n' '" + version.AgentUserAgent + "' >> \"$CURL_AUTH_HEADER_FILE\"",
		"chmod 0600 \"$CURL_AUTH_HEADER_FILE\"",
		"start_install_renewal",
		"assert_install_lease",
		"disabled UFW status is unavailable; auditing its persisted rules directly",
		"snapshot_quiesced_mutable_state()",
		"if ! snapshot_quiesced_mutable_state; then",
		`if [ "$PREPARE_ATTEMPTED" = "1" ] && ! quiesce_remote_installation; then`,
		`retry_remote_install_post "/api/remote/install-finalize" 120 0`,
		"flock -n 9",
		"TRY_GUARD_PORT=$((TRY_PORT + 1))",
		"ARCWAY_GUARD_LISTEN=:${GUARD_PORT}",
		"ARCWAY_GUARD_SECRET=${GUARD_SECRET}",
		"ARCWAY_AGENT_TOKEN=${TOKEN}",
		"hide_port_on_ws: false",
		"if [ \"$(id -u)\" -ne 0 ]",
		"select_download_root()",
		"for candidate in /var/tmp /tmp",
		"temporary storage has less than 128 MiB free",
		"mktemp -d \"${DOWNLOAD_ROOT%/}/arcway-install.XXXXXX\"",
		"validate_elf()",
		"rollback_install()",
		"TRACKED_PATHS=(",
		"MUTATION_STARTED=1",
		"invalid trusted panel source IP",
		"existing Arcway services did not stop",
		"rollback backup retained at $BACKUP_DIR",
		"automatic rollback was incomplete",
		"XRAY_REQUIRED_AFTER_INSTALL=0",
		`if [ "$XRAY_MODE" != "embedded" ] && [ "$XRAY_REQUIRED_AFTER_INSTALL" = "1" ]`,
		`if [ "$XRAY_REQUIRED_AFTER_INSTALL" = "1" ] && ! printf`,
		"xray.service exists but no working external Xray binary was found",
		"External Xray is not installed; install it from this server's Service Control panel.",
		"takeover mode requires a working Nginx installation",
		"/var/lib/relaydock-agent",
		"/var/lib/arcway-expiry-guard",
		"chmod 0600 /var/lib/arcway-expiry-guard/state.json",
		"PANEL_SOURCE_IPS='203.0.113.10 2001:db8::10'",
		"ARCWAY_PANEL_IPS='$PANEL_SOURCE_IPS'",
		"-arcway-firewall-rules=\"$XRAY_CONFIG_PATH\"",
		"ARCWAY_XRAY_CONFIG_PATH",
		"PUBLIC_RULES_RAW=$(mktemp",
		"sort -u -o \"$PUBLIC_RULES\" \"$PUBLIC_RULES\"",
		"printf -- '-A %s -p %s --dport %s",
		"\"$HOST_FILTER_RESTORE\" -w 5 --test --noflush",
		"\"$HOST_FILTER_RESTORE\" -w 5 --noflush",
		"ufw allow proto tcp from \"$PANEL_IP\" to any port \"$MANAGEMENT_PORT\"",
		"comment 'arcway-managed'",
		"/etc/arcway-port-firewall.env",
		"/usr/local/sbin/arcway-agent-firewall",
		"ExecStartPre=/usr/local/sbin/arcway-agent-firewall",
		"ExecStartPre=/usr/local/sbin/arcway-agent-firewall --nft-only",
		"Requires=relaydock-agent.service",
		"depend() { need net relaydock-agent; }",
		"FIREWALL_RUNTIME_DIR=/var/lib/arcway-expiry-guard",
		"chmod 0700 \"$FIREWALL_RUNTIME_DIR\"",
		"FIREWALL_LOCK_FILE=\"$FIREWALL_RUNTIME_DIR/firewall.flock\"",
		"exec 8>\"$FIREWALL_LOCK_FILE\"",
		"chmod 0600 \"$FIREWALL_LOCK_FILE\"",
		"flock -w 30 8",
		"RULESET=$(mktemp \"$FIREWALL_RUNTIME_DIR/arcway-agent-firewall.nft.XXXXXX\")",
		"table inet arcway",
		"nft -c -f \"$RULESET\"",
		"nft -f \"$RULESET\"",
		"FIREWALL_MODE=${1:-full}",
		"HOST_FILTER_CHAIN=ARCWAY_PANEL_IN",
		"ensure_host_filter_chain()",
		"ensure_host_filter_chain iptables ipv4 || exit 1",
		"ensure_host_filter_chain ip6tables ipv6 || exit 1",
		"-I INPUT 1 -m comment --comment \"$HOST_FILTER_COMMENT\" -j \"$HOST_FILTER_CHAIN\"",
		"OLD_FIREWALL_USES_HOST_CHAIN=0",
		"host firewall chain ARCWAY_PANEL_IN is not owned",
		"is installed but cannot inspect the host INPUT filter",
		"ip saddr %s tcp dport { %s, %s } accept",
		"ip6 saddr %s tcp dport { %s, %s } accept",
		"tcp dport { %s, %s } drop",
		"relaydock-agent listen_port drifted from the protected Arcway port",
		"/etc/systemd/system/arcway-expiry-guard.service",
		"chmod 0644 /etc/systemd/system/relaydock-agent.service /etc/systemd/system/arcway-expiry-guard.service",
		"/etc/init.d/arcway-expiry-guard",
		"/usr/local/bin/arcway-expiry-guard-supervisor.sh",
		"/usr/local/sbin/arcway-agent-firewall || return 1",
		`supervisor="supervise-daemon"`,
		"respawn_delay=5",
		"respawn_max=0",
		"relaydock-agent was not registered in the OpenRC default runlevel",
		"arcway-expiry-guard was not registered in the OpenRC default runlevel",
		"systemctl disable relaydock-agent",
		"systemctl disable arcway-expiry-guard",
		"rc-update del relaydock-agent default",
		"rc-update del arcway-expiry-guard default",
		"cleanup_legacy_firewall()",
		"SCRIPT_PROTOCOL='https'",
		"CONNECTION_MODE='websocket'",
		"connection_mode: ${CONNECTION_MODE}",
		"for health_attempt in 1 2 3 4 5 6 7 8 9 10; do",
		"Agent did not become ready within the verification window",
	} {
		if !strings.Contains(script, expected) {
			t.Errorf("install script missing %q", expected)
		}
	}
	if strings.Contains(script, "ARCWAY_GUARD_SECRET=${TOKEN}") {
		t.Fatal("install script reused the rotating Agent token as the guard secret")
	}
	if strings.Contains(script, `-H "Authorization: Bearer ${TOKEN}"`) {
		t.Fatal("install script exposes the long-lived token in curl argv")
	}
	if strings.Contains(script, "AGENT_VERSION=") {
		t.Fatal("install script depends on an independently moving upstream Agent release")
	}
	for _, forbidden := range []string{
		"/api/remote/relaydock-agent",
		"AGENT_MASTER_URL=",
		"download_verified_asset \"relaydock-agent\"",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("install script retains Agent panel fallback: %q", forbidden)
		}
	}
	agentDownloadStart := strings.Index(script, `AGENT_GITHUB_URL="${ASSET_RELEASE_BASE_URL}/relaydock-agent-linux-${ARCH_NAME}"`)
	guardDownloadStart := strings.Index(script, `GUARD_GITHUB_URL="${ASSET_RELEASE_BASE_URL}/arcway-expiry-guard-linux-${ARCH_NAME}"`)
	if agentDownloadStart < 0 || guardDownloadStart <= agentDownloadStart {
		t.Fatal("installer Agent download block is incomplete")
	}
	for _, forbidden := range []string{"MASTER_URL", "CURL_AUTH_HEADER_FILE", `-H @"$CURL_AUTH_HEADER_FILE"`} {
		if strings.Contains(script[agentDownloadStart:guardDownloadStart], forbidden) {
			t.Fatalf("Agent GitHub download block leaked panel fallback data: %q", forbidden)
		}
	}
	if strings.Contains(script, "external Xray mode requires a working Xray installation") {
		t.Fatal("install script still requires Xray before installing an external-mode Agent")
	}
	githubDownloadStart := strings.Index(script, `echo "Downloading $label from GitHub Release..."`)
	masterFallbackStart := strings.Index(script, `echo "Downloading $label from master fallback..."`)
	downloadHelperEnd := strings.Index(script, `AGENT_GITHUB_URL="${ASSET_RELEASE_BASE_URL}/relaydock-agent-linux-${ARCH_NAME}"`)
	if githubDownloadStart < 0 || masterFallbackStart <= githubDownloadStart || downloadHelperEnd <= masterFallbackStart {
		t.Fatal("installer release download helper is incomplete")
	}
	if strings.Contains(script[githubDownloadStart:masterFallbackStart], `CURL_AUTH_HEADER_FILE`) {
		t.Fatal("installer leaks the node credential to GitHub")
	}
	if !strings.Contains(script[masterFallbackStart:downloadHelperEnd], `-H @"$CURL_AUTH_HEADER_FILE"`) {
		t.Fatal("installer does not authenticate the panel-hosted asset fallback")
	}
	if strings.Contains(script, `command_background="yes"`) {
		t.Fatal("OpenRC services are not supervised after startup")
	}
	if strings.Contains(script, "ufw allow \"${GUARD_PORT}/tcp\"") {
		t.Fatal("install script exposes the expiry guard to all IPv4 sources")
	}
	if strings.Contains(script, "-m multiport") {
		t.Fatal("install script depends on the optional xtables multiport module")
	}
	if strings.Contains(script, "MASTER_HOST=") || strings.Contains(script, "getent ahosts") {
		t.Fatal("install script derives trusted panel sources from ingress DNS")
	}
	if strings.Contains(script, "has_external_ipv6") {
		t.Fatal("install script makes IPv6 protection depend on address timing")
	}
	for _, staleLock := range []string{
		`LOCK_DIR=/run/arcway-agent-firewall.lock`,
		`LOCK_OWNER=`,
		`kill -0 "$LOCK_OWNER"`,
		`rm -rf "$LOCK_DIR"`,
		`rm -f "$FIREWALL_LOCK_FILE"`,
		`rm -rf "$FIREWALL_LOCK_FILE"`,
		`FIREWALL_LOCK_FILE=/run/`,
		`RULESET="/run/`,
		`/run/arcway-agent-firewall`,
	} {
		if strings.Contains(script, staleLock) {
			t.Fatalf("install script retains the stale directory-lock implementation: %q", staleLock)
		}
	}
	if strings.Index(script, "nft -c -f \"$RULESET\"") > strings.Index(script, "nft -f \"$RULESET\"") {
		t.Fatal("install script applies the firewall before validating its transaction")
	}
	downloadIndex := strings.Index(script, "Downloading $label from GitHub Release")
	dependencyIndex := strings.Index(script, "firewall_stack_ready()")
	backupIndex := strings.Index(script, "BACKUP_DIR=\"$DOWNLOAD_DIR/backup\"")
	mutationIndex := strings.Index(script, "MUTATION_STARTED=1")
	if downloadIndex < 0 || dependencyIndex < 0 || backupIndex < 0 || mutationIndex < 0 ||
		downloadIndex > dependencyIndex || dependencyIndex > backupIndex || backupIndex > mutationIndex {
		t.Fatal("install script mutates the running node before downloads and integrity checks complete")
	}
	runtimeDirIndex := strings.Index(script, "mkdir -p /var/lib/arcway-expiry-guard")
	firstFirewallRunIndex := strings.Index(script, "if ! ARCWAY_AGENT_BINARY=\"$AGENT_DOWNLOAD\" /usr/local/sbin/arcway-agent-firewall; then")
	if runtimeDirIndex < 0 || firstFirewallRunIndex < runtimeDirIndex {
		t.Fatal("install script invokes the firewall helper before creating its writable runtime directory")
	}
	readyIndex := strings.Index(script, `if [ "$management_ready" != "1" ]`)
	legacyCleanupIndex := strings.Index(script, `cleanup_legacy_firewall()`)
	completeIndex := strings.Index(script, "Installation Complete!")
	if readyIndex < 0 || legacyCleanupIndex < readyIndex || completeIndex < legacyCleanupIndex {
		t.Fatal("install script reports success or removes rollback-only firewall state before semantic readiness")
	}
	firewallBootIndex := strings.LastIndex(script, `/usr/local/sbin/arcway-agent-firewall || exit 1`)
	agentBootIndex := strings.LastIndex(script, `nohup /usr/local/bin/relaydock-agent-supervisor.sh`)
	guardBootIndex := strings.LastIndex(script, `nohup /usr/local/bin/arcway-expiry-guard-supervisor.sh`)
	if firewallBootIndex < 0 || agentBootIndex < firewallBootIndex || guardBootIndex < agentBootIndex {
		t.Fatal("rc.local managed services are not ordered firewall, Agent, expiry guard")
	}
	for _, unsafePipe := range []string{
		`bash -c "$(curl`,
		`install-nginx.sh | bash`,
	} {
		if strings.Contains(script, unsafePipe) {
			t.Fatalf("install script executes an unchecked streamed installer: %s", unsafePipe)
		}
	}
	for _, packageMutation := range []string{
		"apt-get install", "apt-get purge", "apk add", "dnf install", "yum install", "pacman -S", "zypper",
		"XTLS/Xray-install", "install-nginx.sh",
	} {
		if strings.Contains(script, packageMutation) {
			t.Fatalf("generated node installer mutates unmanaged dependencies: %q", packageMutation)
		}
	}
	for _, forbidden := range []string{"gh-proxy.com", "mirror.ghproxy.com", "1ms.cc"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("install script uses untrusted download proxy %q", forbidden)
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		command := exec.Command(bash, "-n")
		command.Stdin = strings.NewReader(script)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("generated install script failed bash -n: %v\n%s", err, output)
		}

		const helperStart = "cat > /usr/local/sbin/arcway-agent-firewall << 'EOF'\n"
		_, helperTail, found := strings.Cut(script, helperStart)
		if !found {
			t.Fatal("generated install script is missing the firewall helper body")
		}
		helper, _, found := strings.Cut(helperTail, "\nEOF\n")
		if !found {
			t.Fatal("generated install script has an unterminated firewall helper")
		}
		shell, shellErr := exec.LookPath("sh")
		if shellErr != nil {
			shell = bash
		}
		command = exec.Command(shell, "-n")
		command.Stdin = strings.NewReader(helper)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("generated firewall helper failed sh -n: %v\n%s", err, output)
		}
	}
}

func TestRemoteInstallScriptSelectsSafeTemporaryFilesystem(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusOK, response.Body.String())
	}

	script := response.Body.String()
	functionStart := strings.Index(script, "select_download_root() {")
	functionEnd := strings.Index(script, "DOWNLOAD_ROOT=$(select_download_root)")
	if functionStart < 0 || functionEnd <= functionStart {
		t.Fatal("generated installer is missing select_download_root")
	}
	selector := script[functionStart:functionEnd]
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}

	tests := []struct {
		name        string
		varTmpKB    int
		tmpKB       int
		wantRoot    string
		wantFailure string
	}{
		{name: "prefers filesystem with enough space", varTmpKB: 80_000_000, tmpKB: 29_000, wantRoot: "/var/tmp"},
		{name: "fails before download when both are full", varTmpKB: 64_000, tmpKB: 29_000, wantFailure: "less than 128 MiB free"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockBin := t.TempDir()
			dfScript := `#!/bin/sh
case "$*" in
  *"/var/tmp"*) available=` + strconv.Itoa(test.varTmpKB) + ` ;;
  *) available=` + strconv.Itoa(test.tmpKB) + ` ;;
esac
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf 'mock 100000000 1 %s 1%% /mock\n' "$available"
`
			if err := os.WriteFile(filepath.Join(mockBin, "df"), []byte(dfScript), 0755); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(bash, "-c", selector+"\nselect_download_root")
			command.Env = append(os.Environ(), "PATH="+mockBin+":"+os.Getenv("PATH"))
			output, runErr := command.CombinedOutput()
			if test.wantFailure != "" {
				if runErr == nil || !strings.Contains(string(output), test.wantFailure) {
					t.Fatalf("selector error=%v output=%q want failure containing %q", runErr, output, test.wantFailure)
				}
				return
			}
			if runErr != nil {
				t.Fatalf("selector failed: %v output=%q", runErr, output)
			}
			if got := strings.TrimSpace(string(output)); got != test.wantRoot {
				t.Fatalf("selected root=%q want=%q", got, test.wantRoot)
			}
		})
	}
}

func TestRemoteInstallHostFilterSurvivesLaterDefaultDrop(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10, 2001:db8::10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	script := response.Body.String()
	const helperStart = "cat > /usr/local/sbin/arcway-agent-firewall << 'EOF'\n"
	_, helperTail, found := strings.Cut(script, helperStart)
	if !found {
		t.Fatal("generated installer is missing the firewall helper body")
	}
	helper, _, found := strings.Cut(helperTail, "\nEOF\n")
	if !found {
		t.Fatal("generated installer has an unterminated firewall helper")
	}
	for _, expected := range []string{
		`HOST_FILTER_CHAIN=ARCWAY_PANEL_IN`,
		`HOST_FILTER_COMMENT=arcway-managed`,
		`remove_host_filter_chain()`,
		`printf -- '-A %s -s %s -p tcp --dport %s`,
		`"$HOST_FILTER_RESTORE" -w 5 --test --noflush`,
		`"$HOST_FILTER_RESTORE" -w 5 --noflush`,
		`-I INPUT 1 -m comment --comment "$HOST_FILTER_COMMENT" -j "$HOST_FILTER_CHAIN" || return 1`,
	} {
		if !strings.Contains(helper, expected) {
			t.Errorf("firewall helper missing %q", expected)
		}
	}
	if strings.Contains(helper, "-m multiport") {
		t.Fatal("host compatibility filter uses the optional multiport matcher")
	}
	nftApply := strings.Index(helper, `nft -f "$RULESET"`)
	nftOnlyExit := strings.Index(helper, `if [ "$FIREWALL_MODE" = "--nft-only" ]`)
	hostFilter := strings.Index(helper, `ensure_host_filter_chain()`)
	if nftApply < 0 || nftOnlyExit < nftApply || hostFilter < nftOnlyExit {
		t.Fatal("firewall helper does not apply nft before its sandbox-safe exit and host INPUT integration")
	}

	const agentUnitStart = "cat > /etc/systemd/system/relaydock-agent.service << EOF\n"
	_, agentTail, found := strings.Cut(script, agentUnitStart)
	if !found {
		t.Fatal("generated installer is missing the Agent unit")
	}
	agentUnit, _, found := strings.Cut(agentTail, "\nEOF\n")
	if !found || !strings.Contains(agentUnit, "ExecStartPre=/usr/local/sbin/arcway-agent-firewall\n") {
		t.Fatal("Agent unit does not apply the full host firewall before startup")
	}

	const guardUnitStart = "cat > /etc/systemd/system/arcway-expiry-guard.service << EOF\n"
	_, guardTail, found := strings.Cut(script, guardUnitStart)
	if !found {
		t.Fatal("generated installer is missing the Guard unit")
	}
	guardUnit, _, found := strings.Cut(guardTail, "\nEOF\n")
	if !found || !strings.Contains(guardUnit, "Requires=relaydock-agent.service") ||
		!strings.Contains(guardUnit, "ExecStartPre=/usr/local/sbin/arcway-agent-firewall --nft-only") {
		t.Fatal("sandboxed Guard unit does not rely on the Agent's full firewall setup")
	}
	if strings.Contains(guardUnit, "ExecStartPre=/usr/local/sbin/arcway-agent-firewall\n") {
		t.Fatal("sandboxed Guard unit invokes the xtables-writing firewall mode")
	}

	collisionCheck := strings.Index(script, "is not owned by the installed Arcway helper")
	transactionBegin := strings.Index(script, `retry_remote_install_post "/api/remote/install-begin"`)
	if collisionCheck < 0 || transactionBegin < collisionCheck {
		t.Fatal("reserved host firewall chain collision is not rejected before the install transaction")
	}
	rollbackOwnership := strings.Index(script, `if [ "$OLD_FIREWALL_USES_HOST_CHAIN" != "1" ]`)
	rollbackDelete := strings.Index(script, `-X ARCWAY_PANEL_IN`)
	if rollbackOwnership < 0 || rollbackDelete < rollbackOwnership {
		t.Fatal("rollback does not remove a host filter chain unsupported by the restored helper")
	}
}

func TestRemoteInstallFirewallHelperReconcilesHostInputChain(t *testing.T) {
	if testing.Short() {
		t.Skip("requires an isolated Linux network namespace")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare is unavailable")
	}
	for _, tool := range []string{"nft", "iptables", "ip6tables", "flock"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is unavailable", tool)
		}
	}
	if err := exec.Command(unshare, "-n", "true").Run(); err != nil {
		t.Skipf("network namespace creation is unavailable: %v", err)
	}

	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	const helperStart = "cat > /usr/local/sbin/arcway-agent-firewall << 'EOF'\n"
	_, helperTail, found := strings.Cut(response.Body.String(), helperStart)
	if !found {
		t.Fatal("generated installer is missing the firewall helper body")
	}
	helper, _, found := strings.Cut(helperTail, "\nEOF\n")
	if !found {
		t.Fatal("generated installer has an unterminated firewall helper")
	}

	testRoot := t.TempDir()
	configPath := filepath.Join(testRoot, "config.yaml")
	xrayConfigPath := filepath.Join(testRoot, "xray.json")
	guardEnvPath := filepath.Join(testRoot, "guard.env")
	firewallEnvPath := filepath.Join(testRoot, "firewall.env")
	runtimeDir := filepath.Join(testRoot, "runtime")
	helperPath := filepath.Join(testRoot, "arcway-agent-firewall")
	mockBin := filepath.Join(testRoot, "mock-bin")
	failureLog := filepath.Join(testRoot, "xtables-failure.log")
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mockBin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mockBin, "iptables"), []byte("#!/bin/sh\nexit 42\n"), 0700); err != nil {
		t.Fatal(err)
	}
	fakeAgentPath := filepath.Join(mockBin, "relaydock-agent")
	if err := os.WriteFile(fakeAgentPath, []byte("#!/bin/sh\nprintf '%b\\n' \"${FAKE_ARCWAY_RULES:-tcp 2033\\nudp 2033\\nudp 51820}\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("listen_port: \"23889\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xrayConfigPath, []byte("{\"inbounds\":[]}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guardEnvPath, []byte("ARCWAY_GUARD_LISTEN=:23890\nARCWAY_AGENT_URL=http://127.0.0.1:23889\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firewallEnvPath, []byte("ARCWAY_AGENT_PORT=23889\nARCWAY_GUARD_PORT=23890\nARCWAY_PANEL_IPS='203.0.113.10'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	helper = strings.ReplaceAll(helper, "/etc/relaydock-agent/config.yaml", configPath)
	helper = strings.ReplaceAll(helper, "/etc/arcway-expiry-guard.env", guardEnvPath)
	helper = strings.ReplaceAll(helper, "/etc/arcway-port-firewall.env", firewallEnvPath)
	helper = strings.ReplaceAll(helper, "FIREWALL_RUNTIME_DIR=/var/lib/arcway-expiry-guard", "FIREWALL_RUNTIME_DIR="+runtimeDir)
	if err := os.WriteFile(helperPath, []byte(helper), 0700); err != nil {
		t.Fatal(err)
	}

	harness := `set -eu
iptables -w 5 -t filter -P INPUT DROP
ip6tables -w 5 -t filter -P INPUT DROP
export ARCWAY_AGENT_PORT=23889 ARCWAY_GUARD_PORT=23890 ARCWAY_PANEL_IPS=203.0.113.10
export ARCWAY_XRAY_CONFIG_PATH=` + shellSingleQuote(xrayConfigPath) + ` ARCWAY_AGENT_BINARY=` + shellSingleQuote(fakeAgentPath) + `
if PATH=` + shellSingleQuote(mockBin) + `:/usr/sbin:/usr/bin:/bin ` + shellSingleQuote(helperPath) + ` >` + shellSingleQuote(failureLog) + ` 2>&1; then
    exit 1
fi
grep -F -- 'iptables is installed but cannot inspect the host INPUT filter' ` + shellSingleQuote(failureLog) + ` >/dev/null
! iptables -w 5 -t filter -S ARCWAY_PANEL_IN >/dev/null 2>&1
` + shellSingleQuote(helperPath) + `
` + shellSingleQuote(helperPath) + `
INPUT_RULES=$(iptables -w 5 -t filter -S INPUT)
CHAIN_RULES=$(iptables -w 5 -t filter -S ARCWAY_PANEL_IN)
[ "$(printf '%s\n' "$INPUT_RULES" | awk '/arcway-managed/ && /ARCWAY_PANEL_IN/ { count++ } END { print count+0 }')" -eq 1 ]
[ "$(printf '%s\n' "$CHAIN_RULES" | awk '/203[.]0[.]113[.]10/ && /--dport 23889/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 1 ]
[ "$(printf '%s\n' "$CHAIN_RULES" | awk '/203[.]0[.]113[.]10/ && /--dport 23890/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 1 ]
[ "$(printf '%s\n' "$CHAIN_RULES" | awk '/-p tcp/ && /--dport 2033/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 1 ]
[ "$(printf '%s\n' "$CHAIN_RULES" | awk '/-p udp/ && /--dport 2033/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 1 ]
[ "$(printf '%s\n' "$CHAIN_RULES" | awk '/-p udp/ && /--dport 51820/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 1 ]
HOST_FILTER_BEFORE=$(iptables -w 5 -t filter -S ARCWAY_PANEL_IN)
if FAKE_ARCWAY_RULES='tcp 23889' ` + shellSingleQuote(helperPath) + ` >/dev/null 2>&1; then
    exit 1
fi
HOST_FILTER_AFTER=$(iptables -w 5 -t filter -S ARCWAY_PANEL_IN)
[ "$HOST_FILTER_BEFORE" = "$HOST_FILTER_AFTER" ]
FAKE_ARCWAY_RULES='udp 51820' ` + shellSingleQuote(helperPath) + `
CHAIN_RULES=$(iptables -w 5 -t filter -S ARCWAY_PANEL_IN)
! printf '%s\n' "$CHAIN_RULES" | grep -F -- '--dport 2033' >/dev/null
[ "$(printf '%s\n' "$CHAIN_RULES" | awk '/-p udp/ && /--dport 51820/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 1 ]
export ARCWAY_PANEL_IPS=198.51.100.20
` + shellSingleQuote(helperPath) + `
CHAIN_RULES=$(iptables -w 5 -t filter -S ARCWAY_PANEL_IN)
! printf '%s\n' "$CHAIN_RULES" | grep -F -- '203.0.113.10' >/dev/null
[ "$(printf '%s\n' "$CHAIN_RULES" | awk '/198[.]51[.]100[.]20/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 2 ]
HOST_FILTER_BEFORE=$(iptables -w 5 -t filter -S ARCWAY_PANEL_IN)
export ARCWAY_PANEL_IPS=192.0.2.30
` + shellSingleQuote(helperPath) + ` --nft-only
HOST_FILTER_AFTER=$(iptables -w 5 -t filter -S ARCWAY_PANEL_IN)
[ "$HOST_FILTER_BEFORE" = "$HOST_FILTER_AFTER" ]
nft list chain inet arcway input >/dev/null
export ARCWAY_PANEL_IPS=2001:db8::10
` + shellSingleQuote(helperPath) + `
IPV4_CHAIN_RULES=$(iptables -w 5 -t filter -S ARCWAY_PANEL_IN)
! printf '%s\n' "$IPV4_CHAIN_RULES" | grep -F -- '198.51.100.20' >/dev/null
[ "$(printf '%s\n' "$IPV4_CHAIN_RULES" | awk '/--dport 2033/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 2 ]
IPV6_CHAIN_RULES=$(ip6tables -w 5 -t filter -S ARCWAY_PANEL_IN)
[ "$(printf '%s\n' "$IPV6_CHAIN_RULES" | awk '/2001:db8::10/ && /-j ACCEPT/ { count++ } END { print count+0 }')" -eq 2 ]
`
	command := exec.Command(unshare, "-n", "sh", "-c", harness)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("firewall helper host-chain integration failed: %v\n%s", err, output)
	}
}

func TestRemoteInstallFirewallHelperSerializesWithKernelLock(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock is unavailable")
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is unavailable")
	}

	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	const helperStart = "cat > /usr/local/sbin/arcway-agent-firewall << 'EOF'\n"
	_, helperTail, found := strings.Cut(response.Body.String(), helperStart)
	if !found {
		t.Fatal("generated installer is missing the firewall helper body")
	}
	helper, _, found := strings.Cut(helperTail, "\nEOF\n")
	if !found {
		t.Fatal("generated installer has an unterminated firewall helper")
	}
	lockStart := strings.Index(helper, "umask 077\nFIREWALL_RUNTIME_DIR=")
	if lockStart < 0 {
		t.Fatal("generated firewall helper has no kernel-lock block")
	}
	lockEndOffset := strings.Index(helper[lockStart:], "\nRULESET=")
	if lockEndOffset < 0 {
		t.Fatal("generated firewall helper kernel-lock block is unterminated")
	}
	lockBlock := helper[lockStart : lockStart+lockEndOffset]
	runtimeDir := t.TempDir()
	lockFile := filepath.Join(runtimeDir, "firewall.flock")
	lockBlock = strings.Replace(lockBlock,
		"FIREWALL_RUNTIME_DIR=/var/lib/arcway-expiry-guard",
		"FIREWALL_RUNTIME_DIR="+shellSingleQuote(runtimeDir), 1)

	if err := os.WriteFile(lockFile, []byte("stale\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockFile, 0644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(shell, "-c", lockBlock).CombinedOutput(); err != nil {
		t.Fatalf("firewall helper did not acquire an existing regular lock file: %v\n%s", err, output)
	}
	info, err := os.Stat(lockFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("firewall lock mode=%#o want=0600", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	holder := exec.CommandContext(ctx, shell, "-c",
		"exec 7>"+shellSingleQuote(lockFile)+"; flock -x 7; printf 'ready\\n'; read release")
	holderInput, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	holderOutput, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	holderFinished := false
	defer func() {
		if holderFinished {
			return
		}
		_ = holderInput.Close()
		_ = holder.Process.Kill()
		_ = holder.Wait()
	}()
	ready, err := bufio.NewReader(holderOutput).ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatalf("lock holder did not acquire the test lock: ready=%q err=%v", ready, err)
	}

	contender := exec.CommandContext(ctx, shell, "-c", lockBlock)
	if err := contender.Start(); err != nil {
		t.Fatal(err)
	}
	contenderDone := make(chan error, 1)
	go func() { contenderDone <- contender.Wait() }()
	select {
	case err := <-contenderDone:
		t.Fatalf("firewall helper bypassed a held kernel lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := holderInput.Write([]byte("release\n")); err != nil {
		t.Fatal(err)
	}
	if err := holderInput.Close(); err != nil {
		t.Fatal(err)
	}
	holderErr := holder.Wait()
	holderFinished = true
	if holderErr != nil {
		t.Fatalf("lock holder failed: %v", holderErr)
	}
	select {
	case err := <-contenderDone:
		if err != nil {
			t.Fatalf("firewall helper did not acquire the released kernel lock: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("firewall helper did not acquire the released kernel lock")
	}
}

func TestRemoteInstallRenewalWorkersReapSleepChildren(t *testing.T) {
	if _, err := os.Stat("/proc/self/task"); err != nil {
		t.Skip("requires Linux procfs process ancestry")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}

	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	script := response.Body.String()
	start := strings.Index(script, "INSTALL_RENEW_PID=\"\"")
	if start < 0 {
		t.Fatal("generated installer has no renewal worker block")
	}
	endOffset := strings.Index(script[start:], "\n# Start the durable panel-side transaction")
	if endOffset < 0 {
		t.Fatal("generated installer renewal worker block is unterminated")
	}
	workerBlock := script[start : start+endOffset]

	harness := `
set -Eeuo pipefail
DOWNLOAD_DIR=$(mktemp -d)
RENEW_CHILD=""
HARD_STOP_CHILD=""
cleanup_test_jobs() {
    for pid in "${RENEW_CHILD:-}" "${HARD_STOP_CHILD:-}" "${INSTALL_RENEW_PID:-}" "${INSTALL_HARD_STOP_PID:-}"; do
        [ -z "$pid" ] || kill "$pid" >/dev/null 2>&1 || true
    done
    rm -rf "$DOWNLOAD_DIR"
}
trap cleanup_test_jobs EXIT
retry_remote_install_post() { return 0; }
` + workerBlock + `
wait_for_worker_child() {
    local parent_pid="$1" children="" attempt=0
    while [ "$attempt" -lt 100 ]; do
        children=$(cat "/proc/$parent_pid/task/$parent_pid/children" 2>/dev/null || true)
        set -- $children
        if [ "$#" -gt 0 ]; then
            printf '%s\n' "$1"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.01
    done
    return 1
}
start_install_renewal
RENEW_CHILD=$(wait_for_worker_child "$INSTALL_RENEW_PID")
HARD_STOP_CHILD=$(wait_for_worker_child "$INSTALL_HARD_STOP_PID")
stop_install_renewal
survivors=0
for pid in "$RENEW_CHILD" "$HARD_STOP_CHILD"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
        survivors=$((survivors + 1))
    fi
done
if [ "$survivors" -ne 0 ]; then
    echo "renewal workers left $survivors sleep child process(es) behind" >&2
    exit 1
fi
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, bash, "-c", harness)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("renewal worker cleanup failed: %v\n%s", err, output)
	}
}

func TestRemoteInstallRollbackAcceptsConfirmedInactiveService(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}

	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	script := response.Body.String()
	start := strings.Index(script, "restore_systemd_service_state() {")
	if start < 0 {
		t.Fatal("generated installer has no systemd restore helper")
	}
	endOffset := strings.Index(script[start:], "\nrollback_install() {")
	if endOffset < 0 {
		t.Fatal("generated installer systemd restore helper is unterminated")
	}
	restoreHelper := script[start : start+endOffset]

	binDir := t.TempDir()
	fakeSystemctl := `#!/bin/sh
case "$1" in
    disable|enable|unmask|start|stop) exit 0 ;;
    is-enabled) printf '%s\n' disabled; exit 0 ;;
    is-active) [ "${FAKE_SYSTEMD_ACTIVE:-0}" = 1 ] && exit 0 || exit 3 ;;
    *) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(binDir, "systemctl"), []byte(fakeSystemctl), 0755); err != nil {
		t.Fatal(err)
	}
	harness := restoreHelper + `
restore_systemd_service_state relaydock-agent disabled 0
if FAKE_SYSTEMD_ACTIVE=1 restore_systemd_service_state relaydock-agent disabled 0; then
    echo "restore accepted a service that remained active" >&2
    exit 1
fi
`
	command := exec.Command(bash, "-c", harness)
	command.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("systemd rollback state check failed: %v\n%s", err, output)
	}
}

func TestRemoteInstallUFWStatusFailureRequiresEnabledPolicy(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}

	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	script := response.Body.String()
	start := strings.Index(script, "UFW_ACTIVE=0\nif command -v ufw")
	if start < 0 {
		t.Fatal("generated installer has no UFW status gate")
	}
	endMarker := "\nif command -v ufw >/dev/null 2>&1; then\n    UFW_PORT_PATTERN=\"\""
	endOffset := strings.Index(script[start:], endMarker)
	if endOffset < 0 {
		t.Fatal("generated installer UFW status gate is unterminated")
	}

	binDir := t.TempDir()
	ufwConfig := filepath.Join(t.TempDir(), "ufw.conf")
	fakeUFW := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "ufw"), []byte(fakeUFW), 0755); err != nil {
		t.Fatal(err)
	}
	detectionBlock := strings.ReplaceAll(script[start:start+endOffset], "/etc/ufw/ufw.conf", shellSingleQuote(ufwConfig))
	runDetection := func(config string) ([]byte, error) {
		t.Helper()
		if err := os.WriteFile(ufwConfig, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(bash, "-c", detectionBlock+"\nprintf 'active=%s status=%s\\n' \"$UFW_ACTIVE\" \"$UFW_STATUS\"\n")
		command.Env = append(os.Environ(), "PATH="+binDir+":/usr/bin:/bin")
		return command.CombinedOutput()
	}

	disabledOutput, disabledErr := runDetection("ENABLED=no\n")
	if disabledErr != nil {
		t.Fatalf("disabled UFW status failure was rejected: %v\n%s", disabledErr, disabledOutput)
	}
	if !strings.Contains(string(disabledOutput), "active=0 status=Status: inactive") {
		t.Fatalf("disabled UFW did not enter audited inactive mode: %s", disabledOutput)
	}

	enabledOutput, enabledErr := runDetection("ENABLED=yes\n")
	if enabledErr == nil {
		t.Fatalf("enabled UFW status failure was accepted: %s", enabledOutput)
	}
	if !strings.Contains(string(enabledOutput), "active UFW policy cannot be inspected") {
		t.Fatalf("enabled UFW failure was not explicit: %s", enabledOutput)
	}
}

func TestRemoteInstallActiveUFWReapplyUsesDownloadedAgent(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}

	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	script := response.Body.String()
	end := strings.Index(script, "\ncat > /usr/local/sbin/arcway-nginx-bridge")
	if end < 0 {
		t.Fatal("generated installer is missing the post-UFW boundary")
	}
	start := strings.LastIndex(script[:end], `    if [ "$UFW_ACTIVE" = "1" ]; then`)
	if start < 0 {
		t.Fatal("generated installer is missing the active-UFW firewall reapply")
	}
	const blockEndMarker = "\n    fi\n"
	blockEnd := strings.Index(script[start:end], blockEndMarker)
	if blockEnd < 0 {
		t.Fatal("generated installer active-UFW firewall reapply is unterminated")
	}
	fragment := script[start : start+blockEnd+len(blockEndMarker)]

	testRoot := t.TempDir()
	downloadedAgent := filepath.Join(testRoot, "relaydock-agent.download")
	if err := os.WriteFile(downloadedAgent, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	firewallHelper := filepath.Join(testRoot, "arcway-agent-firewall")
	helper := `#!/bin/sh
set -eu
[ "${ARCWAY_AGENT_BINARY:-}" = "$EXPECTED_AGENT_BINARY" ]
[ -x "$ARCWAY_AGENT_BINARY" ]
`
	if err := os.WriteFile(firewallHelper, []byte(helper), 0755); err != nil {
		t.Fatal(err)
	}
	fragment = strings.ReplaceAll(fragment, "/usr/local/sbin/arcway-agent-firewall", shellSingleQuote(firewallHelper))
	command := exec.Command(bash, "-c", fragment)
	command.Env = append(os.Environ(),
		"UFW_ACTIVE=1",
		"AGENT_DOWNLOAD="+downloadedAgent,
		"EXPECTED_AGENT_BINARY="+downloadedAgent,
		"ARCWAY_AGENT_BINARY=",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("active-UFW clean-install reapply did not use the downloaded Agent: %v\n%s", err, output)
	}

	reapply := `ARCWAY_AGENT_BINARY="$AGENT_DOWNLOAD" /usr/local/sbin/arcway-agent-firewall`
	if count := strings.Count(script, reapply); count < 2 {
		t.Fatalf("downloaded Agent override count=%d want at least 2", count)
	}
	installIndex := strings.Index(script, `install -m 0755 "$AGENT_DOWNLOAD" /usr/local/bin/.relaydock-agent.new`)
	if installIndex < 0 || start >= installIndex {
		t.Fatal("active-UFW reapply no longer runs before the Agent is installed")
	}
}

func TestShellSingleQuotePreventsCommandSubstitution(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	marker := filepath.Join(t.TempDir(), "injected")
	value := "value'$(touch${IFS}" + marker + ")"
	command := exec.Command(bash, "-c", "value="+shellSingleQuote(value)+`; printf '%s' "$value"`)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("quoted assignment failed: %v\n%s", err, output)
	}
	if string(output) != value {
		t.Fatalf("quoted value=%q want=%q", output, value)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("command substitution escaped quoting: stat err=%v", err)
	}
}

func TestRemoteInstallScriptQuotesStoredToken(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	installExpiryGuardAssetFixtures(t)
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	marker := filepath.Join(t.TempDir(), "injected")
	token := "remote-'$(touch${IFS}" + marker + ")'"
	server := &storage.RemoteServer{Name: "quoted-token", Token: token, ConnectionMode: storage.ConnectionModeWebSocket}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	line := ""
	for _, candidate := range strings.Split(response.Body.String(), "\n") {
		if strings.HasPrefix(candidate, "TOKEN=") {
			line = candidate
			break
		}
	}
	if line == "" {
		t.Fatal("generated script has no TOKEN assignment")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	command := exec.Command(bash, "-c", line+`; printf '%s' "$TOKEN"`)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("generated token assignment failed: %v\n%s", err, output)
	}
	if string(output) != token {
		t.Fatalf("generated token=%q want=%q", output, token)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("generated script executed token content: stat err=%v", err)
	}
}

func TestRemoteInstallScriptIgnoresPolicyQueryOverrides(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	installExpiryGuardAssetFixtures(t)
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name: "stored-policy", Token: "stored-policy-token", ConnectionMode: storage.ConnectionModePush,
		ListenPort: 25000, XrayMode: "external", StealSelf: false, StealMode: "default",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh?steal_self=1&xray_mode=embedded&connection_mode=websocket&listen_port=26000", nil)
	request.Header.Set("Authorization", "Bearer "+server.Token)
	response := httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).GetRemoteInstallScript(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	script := response.Body.String()
	for _, expected := range []string{
		"AUTO_STEAL_SELF='0'",
		"XRAY_MODE='external'",
		"CONNECTION_MODE='http'",
		"LISTEN_PORT='25000'",
	} {
		if !strings.Contains(script, expected) {
			t.Errorf("generated script missing stored policy %q", expected)
		}
	}
	for _, forbidden := range []string{"AUTO_STEAL_SELF='1'", "XRAY_MODE='embedded'", "LISTEN_PORT='26000'", "INSTALL_ARGUMENT"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("generated script accepted query override %q", forbidden)
		}
	}
}

func TestNormalizeMasterURL(t *testing.T) {
	valid := map[string]string{
		"":                               "",
		" HTTPS://Example.COM./ ":        "https://example.com",
		"http://localhost:12889":         "http://localhost:12889",
		"http://[2001:db8::1]:8443/":     "http://[2001:db8::1]:8443",
		"https://xn--bcher-kva.example/": "https://xn--bcher-kva.example",
	}
	for input, expected := range valid {
		got, err := normalizeMasterURL(input)
		if err != nil {
			t.Errorf("normalizeMasterURL(%q): %v", input, err)
			continue
		}
		if got != expected {
			t.Errorf("normalizeMasterURL(%q)=%q want=%q", input, got, expected)
		}
	}

	invalid := []string{
		"ftp://example.com",
		"https://user:pass@example.com",
		"https://example.com/path",
		"https://example.com?query=1",
		"https://example.com/#fragment",
		"https://example.com:0",
		"https://example.com:65536",
		"https://bad_host.example",
		"https://example.com\n$(touch /tmp/arcway-injected)",
		"https://example.com';$(touch${IFS}/tmp/arcway-injected)",
	}
	for _, input := range invalid {
		if got, err := normalizeMasterURL(input); err == nil {
			t.Errorf("normalizeMasterURL(%q) accepted as %q", input, got)
		}
	}
}

func TestDefaultMasterSchemeNeverDowngradesNonLoopbackHosts(t *testing.T) {
	tests := []struct {
		host   string
		hasTLS bool
		want   string
	}{
		{host: "panel.example", want: "https"},
		{host: "panel.example:8080", want: "https"},
		{host: "192.0.2.10:12889", want: "https"},
		{host: "localhost:12889", want: "http"},
		{host: "127.0.0.1:12889", want: "http"},
		{host: "panel.example", hasTLS: true, want: "https"},
	}
	for _, tc := range tests {
		if got := defaultMasterScheme(tc.host, tc.hasTLS); got != tc.want {
			t.Errorf("defaultMasterScheme(%q, %v)=%q want=%q", tc.host, tc.hasTLS, got, tc.want)
		}
	}
}

func TestNormalizePanelSourceIPs(t *testing.T) {
	addresses, err := normalizePanelSourceIPs("2001:db8::1, 203.0.113.8;203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(addresses, " "); got != "203.0.113.8 2001:db8::1" {
		t.Fatalf("normalized addresses = %q", got)
	}
	if _, err := normalizePanelSourceIPs("203.0.113.8 invalid"); err == nil {
		t.Fatal("invalid panel source IP was accepted")
	}
}

func TestVerifyRemoteManagementPorts(t *testing.T) {
	var agentListener, guardListener net.Listener
	var agentPort int
	for attempt := 0; attempt < 50; attempt++ {
		candidate, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := candidate.Addr().(*net.TCPAddr).Port
		if port >= 65535 {
			_ = candidate.Close()
			continue
		}
		adjacent, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port+1)))
		if err != nil {
			_ = candidate.Close()
			continue
		}
		agentListener, guardListener, agentPort = candidate, adjacent, port
		break
	}
	if agentListener == nil {
		t.Fatal("could not allocate adjacent management ports")
	}
	t.Cleanup(func() {
		_ = agentListener.Close()
		_ = guardListener.Close()
	})

	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name: "ready-edge", Token: "ready-token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket, IPAddress: "127.0.0.1", ListenPort: agentPort,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	guardSecret, err := repo.GetOrCreateRemoteServerGuardSecret(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	agentServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/child/system/info" {
			http.NotFound(w, r)
			return
		}
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Errorf("public readiness probe exposed Authorization=%q", authorization)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})}
	go func() { _ = agentServer.Serve(agentListener) }()
	t.Cleanup(func() { _ = agentServer.Close() })
	guard, err := expiryguard.New(filepath.Join(t.TempDir(), "state.json"), guardSecret, server.Token, "http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	guardServer := &http.Server{Handler: guard.Handler()}
	go func() { _ = guardServer.Serve(guardListener) }()
	t.Cleanup(func() { _ = guardServer.Close() })
	stored, err := repo.GetRemoteServerByToken(context.Background(), "ready-token")
	if err != nil {
		t.Fatal(err)
	}
	if stored.IPAddress != "127.0.0.1" || stored.ListenPort != agentPort {
		t.Fatalf("stored management address=%q port=%d", stored.IPAddress, stored.ListenPort)
	}
	handler := NewXrayServerHandler(repo, nil, nil)
	wsHandler := NewRemoteWSHandler(repo, nil)
	wsHandler.conns.Store(server.Token, &RemoteWSConnection{
		ServerID: server.ID, Encrypted: true, Capabilities: AgentCapabilities{RPC: true},
	})
	handler.SetWSHandler(wsHandler)
	const installNonce = "ready-installation-nonce"
	if err := repo.BeginRemoteServerInstallation(context.Background(), server.ID, installNonce, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/remote/management-ready", nil)
	request.RemoteAddr = "127.0.0.1:32123"
	request.Header.Set("Authorization", "Bearer ready-token")
	request.Header.Set(remoteInstallationNonceHeader, installNonce)
	response := httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).VerifyRemoteManagementPorts(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("unencrypted status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.VerifyRemoteManagementPorts(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.VerifyRemoteManagementPorts(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "2" {
		t.Fatalf("rate limit status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}

	if err := guardListener.Close(); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	blockedHandler := NewXrayServerHandler(repo, nil, nil)
	blockedHandler.SetWSHandler(wsHandler)
	blockedHandler.VerifyRemoteManagementPorts(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("blocked status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestObservedRemoteAddressOnlyTrustsLocalProxyHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/remote/management-ready", nil)
	request.RemoteAddr = "198.51.100.20:44321"
	request.Header.Set("CF-Connecting-IP", "127.0.0.1")
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	request.Header.Set("X-Real-IP", "127.0.0.1")
	if got := observedRemoteAddress(request); got != "198.51.100.20" {
		t.Fatalf("direct peer address=%q", got)
	}
	request.RemoteAddr = "127.0.0.1:44321"
	request.Header.Set("CF-Connecting-IP", "10.0.0.1")
	request.Header.Set("X-Forwarded-For", "10.0.0.2")
	request.Header.Set("X-Real-IP", "203.0.113.25")
	if got := observedRemoteAddress(request); got != "203.0.113.25" {
		t.Fatalf("proxied peer address=%q", got)
	}
	request.Header.Set("X-Real-IP", "invalid")
	if got := observedRemoteAddress(request); got != "127.0.0.1" {
		t.Fatalf("untrusted forwarded headers changed address to %q", got)
	}
}

func TestRemoteInstallationHTTPLifecycleIsNonceBoundAndIdempotent(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	server, err := handler.repo.GetRemoteServerByToken(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	policyRequest := httptest.NewRequest(http.MethodPost, "https://panel.example/api/remote/install-begin", nil)
	policyContext, err := handler.remoteInstallationPolicyContext(context.Background(), policyRequest, []string{"203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	policyFingerprint, err := storage.RemoteServerInstallationPolicyFingerprintWithContext(server, policyContext)
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "http-installation-lifecycle-nonce"
	request := func(path, requestNonce string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://panel.example"+path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set(remoteInstallationNonceHeader, requestNonce)
		r.Header.Set(remoteInstallationPolicyHeader, policyFingerprint)
		return r
	}

	response := httptest.NewRecorder()
	handler.BeginRemoteInstallation(response, request("/api/remote/install-begin", nonce))
	if response.Code != http.StatusOK {
		t.Fatalf("begin status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.BeginRemoteInstallation(response, request("/api/remote/install-begin", nonce))
	if response.Code != http.StatusOK {
		t.Fatalf("idempotent begin status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.RenewRemoteInstallation(response, request("/api/remote/install-renew", nonce))
	if response.Code != http.StatusOK {
		t.Fatalf("renew status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.BeginRemoteInstallation(response, request("/api/remote/install-begin", "different-installation-nonce"))
	if response.Code != http.StatusConflict {
		t.Fatalf("conflicting begin status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.PrepareRemoteInstallation(response, request("/api/remote/install-prepare", nonce))
	if response.Code != http.StatusConflict {
		t.Fatalf("prepare before ready status=%d body=%s", response.Code, response.Body.String())
	}
	if err := handler.repo.MarkRemoteServerInstallationReady(context.Background(), server.ID, nonce); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.PrepareRemoteInstallation(response, request("/api/remote/install-prepare", nonce))
	if response.Code != http.StatusOK {
		t.Fatalf("prepare status=%d body=%s", response.Code, response.Body.String())
	}
	for attempt := 0; attempt < 2; attempt++ {
		response = httptest.NewRecorder()
		handler.FinalizeRemoteInstallation(response, request("/api/remote/install-finalize", nonce))
		if response.Code != http.StatusOK {
			t.Fatalf("finalize attempt %d status=%d body=%s", attempt+1, response.Code, response.Body.String())
		}
	}
	active, err := handler.repo.IsRemoteServerInstallationActive(context.Background(), server.ID)
	if err != nil || active {
		t.Fatalf("active after finalize=(%v, %v)", active, err)
	}
}

func TestRemoteInstallationBeginRejectsChangedPanelPolicyContext(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	server, err := handler.repo.GetRemoteServerByToken(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://panel.example/api/remote/install-begin", nil)
	originalContext, err := handler.remoteInstallationPolicyContext(context.Background(), request, []string{"203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := storage.RemoteServerInstallationPolicyFingerprintWithContext(server, originalContext)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(panelSourceIPsEnv, "203.0.113.11")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set(remoteInstallationNonceHeader, "changed-panel-policy-nonce")
	request.Header.Set(remoteInstallationPolicyHeader, fingerprint)
	response := httptest.NewRecorder()
	handler.BeginRemoteInstallation(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
}

func TestRemoteManagementAgentProbeRequiresTCPReachability(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr)
	if err := probeRemoteAgent(context.Background(), address.IP.String(), address.Port); err != nil {
		t.Fatalf("Agent probe rejected reachable TCP port: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probeRemoteAgent(context.Background(), address.IP.String(), address.Port); err == nil {
		t.Fatal("Agent probe accepted a closed TCP port")
	}
}

func TestAuthenticatedRemoteAgentConnectedRequiresEncryptedRPC(t *testing.T) {
	handler := &XrayServerHandler{}
	websocketServer := &storage.RemoteServer{ID: 7, ConnectionMode: storage.ConnectionModeWebSocket}
	var nilHandler *XrayServerHandler
	if nilHandler.authenticatedRemoteAgentConnected(&storage.RemoteServer{ID: 8, ConnectionMode: storage.ConnectionModePush}) {
		t.Fatal("nil handler accepted a push-mode installation")
	}
	if handler.authenticatedRemoteAgentConnected(websocketServer) {
		t.Fatal("handler accepted an Agent without a WebSocket handler")
	}
	if handler.authenticatedRemoteAgentConnected(&storage.RemoteServer{ID: 8, ConnectionMode: "unknown"}) {
		t.Fatal("handler accepted an unsupported connection mode")
	}
	if !handler.authenticatedRemoteAgentConnected(&storage.RemoteServer{ID: 8, ConnectionMode: storage.ConnectionModePush}) {
		t.Fatal("handler rejected an authenticated push-mode installation callback")
	}
	wsHandler := &RemoteWSHandler{}
	handler.SetWSHandler(wsHandler)
	for _, connection := range []*RemoteWSConnection{
		{ServerID: 7, Capabilities: AgentCapabilities{RPC: true}},
		{ServerID: 7, Encrypted: true},
	} {
		wsHandler.conns.Store("agent", connection)
		if handler.authenticatedRemoteAgentConnected(websocketServer) {
			t.Fatalf("handler accepted insecure Agent connection: %+v", connection)
		}
		wsHandler.conns.Delete("agent")
	}
	wsHandler.conns.Store("agent", &RemoteWSConnection{
		ServerID: 7, Encrypted: true, Capabilities: AgentCapabilities{RPC: true},
	})
	if !handler.authenticatedRemoteAgentConnected(websocketServer) {
		t.Fatal("handler rejected an encrypted RPC-capable Agent connection")
	}
	if handler.authenticatedRemoteAgentConnected(&storage.RemoteServer{ID: 9, ConnectionMode: storage.ConnectionModeWebSocket}) {
		t.Fatal("handler accepted an encrypted connection for a different server")
	}
}

func TestRemoteExpiryGuardProbeRejectsSemanticFailures(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	for _, body := range []string{
		`{"client_expiry":false,"durable":true}`,
		`{"client_expiry":true,"durable":false}`,
		`{not-json}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		port := server.Listener.Addr().(*net.TCPAddr).Port
		err := probeRemoteExpiryGuard(context.Background(), client, "127.0.0.1", port, "probe-secret")
		server.Close()
		if err == nil {
			t.Fatalf("expiry guard probe accepted %q", body)
		}
	}
}

func TestRemoteExpiryGuardProbeDoesNotFollowRedirects(t *testing.T) {
	var redirectedRequests atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success":       true,
			"client_expiry": true,
			"durable":       true,
		})
	}))
	t.Cleanup(redirectTarget.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)
	address := redirector.Listener.Addr().(*net.TCPAddr)
	client, transport := newRemoteManagementProbeClient()
	t.Cleanup(transport.CloseIdleConnections)

	if err := probeRemoteExpiryGuard(context.Background(), client, address.IP.String(), address.Port, "probe-secret"); err == nil {
		t.Fatal("expiry guard probe accepted a redirect")
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("expiry guard probe followed redirect; target requests=%d", got)
	}
}

func TestRemoteInstallScriptRejectsQueryToken(t *testing.T) {
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet,
		"https://panel.example/api/remote/install.sh?token="+token, nil)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=%d", response.Code, http.StatusUnauthorized)
	}
}

func TestRemoteInstallScriptConsumesShortLivedTicketOnce(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	handler, token := newExpiryGuardAssetHandler(t)
	server, err := handler.repo.GetRemoteServerByToken(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	const ticket = remoteInstallTicketPrefix + "single-consumption-ticket"
	if err := handler.repo.CreateRemoteServerInstallTicket(context.Background(), server.ID, ticket, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
		r.Header.Set("Authorization", "Bearer "+ticket)
		return r
	}
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request())
	if response.Code != http.StatusOK {
		t.Fatalf("first download status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request())
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("second download status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRevealServerTokenReturnsAuthoritativeInstallCommand(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10 2001:db8::10")
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name: "reveal-command", Token: "reveal-token", ConnectionMode: storage.ConnectionModeWebSocket,
		ListenPort: 25000, XrayMode: "embedded", StealSelf: true, StealMode: "tunnel",
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://panel.example:8443/api/admin/remote-servers/reveal-token?server_id="+strconv.FormatInt(server.ID, 10), nil)
	response := httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).RevealServerToken(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Success        bool   `json:"success"`
		Token          string `json:"token"`
		InstallCommand string `json:"install_command"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.Token != server.Token {
		t.Fatalf("unexpected reveal response: %+v", result)
	}
	for _, expected := range []string{
		`(set -eu;`,
		`-o "$installer"`,
		`https://panel.example:8443/api/remote/install.sh?connection_mode=websocket&front_service=xray&listen_port=25000&steal_self=1&xray_mode=embedded`,
		`ARCWAY_PANEL_IPS='203.0.113.10 2001:db8::10'`,
		`bash "$installer"`,
	} {
		if !strings.Contains(result.InstallCommand, expected) {
			t.Errorf("authoritative install command missing %q: %s", expected, result.InstallCommand)
		}
	}
	if strings.Contains(result.InstallCommand, " | bash") {
		t.Fatalf("authoritative install command streams into bash: %s", result.InstallCommand)
	}
	if strings.Contains(result.InstallCommand, server.Token) {
		t.Fatalf("authoritative install command exposes the long-lived server token: %s", result.InstallCommand)
	}
}

func TestRevealServerTokenRenewsExpiringCredentialBeforeIssuingInstallTicket(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	installExpiryGuardAssetFixtures(t)

	for _, testCase := range []struct {
		name      string
		expiresAt time.Time
	}{
		{name: "expired", expiresAt: time.Now().Add(-time.Hour)},
		{name: "expires before ticket", expiresAt: time.Now().Add(remoteInstallTicketTTL / 2)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "traffic.db")
			repo, err := storage.NewTrafficRepository(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = repo.Close() })

			const originalToken = "expired-install-token"
			server := &storage.RemoteServer{
				Name:           "expiring-reveal-command",
				Token:          originalToken,
				ConnectionMode: storage.ConnectionModeWebSocket,
				ListenPort:     25000,
			}
			if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(context.Background(),
				"UPDATE remote_servers SET token_expires_at = ? WHERE id = ?", testCase.expiresAt, server.ID); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			handler := NewXrayServerHandler(repo, nil, nil)
			request := httptest.NewRequest(http.MethodGet,
				"https://panel.example/api/admin/remote-servers/reveal-token?server_id="+strconv.FormatInt(server.ID, 10), nil)
			response := httptest.NewRecorder()
			handler.RevealServerToken(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("reveal status=%d", response.Code)
			}
			var result struct {
				Success        bool   `json:"success"`
				Token          string `json:"token"`
				InstallCommand string `json:"install_command"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !result.Success || result.Token == "" || result.Token == originalToken {
				t.Fatal("reveal did not return a renewed server credential")
			}
			stored, err := repo.GetRemoteServer(context.Background(), server.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Token != result.Token || stored.TokenExpiresAt == nil || !stored.TokenExpiresAt.After(time.Now().Add(remoteInstallTicketTTL)) {
				t.Fatal("renewed server credential was not persisted with sufficient lifetime")
			}

			matches := regexp.MustCompile(`Authorization: Bearer (arcway-install-[^']+)`).FindStringSubmatch(result.InstallCommand)
			if len(matches) != 2 {
				t.Fatal("install command did not contain a one-time ticket")
			}
			download := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
			download.Header.Set("Authorization", "Bearer "+matches[1])
			downloadResponse := httptest.NewRecorder()
			handler.GetRemoteInstallScript(downloadResponse, download)
			if downloadResponse.Code != http.StatusOK {
				t.Fatalf("install ticket download status=%d", downloadResponse.Code)
			}
		})
	}
}

func TestRevealServerTokenDoesNotInferTakeoverFromHistoricalStealMode(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name: "historical-mode", Token: "historical-token", ConnectionMode: storage.ConnectionModeWebSocket,
		StealMode: "tunnel", StealSelf: false,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/admin/remote-servers/reveal-token?server_id="+strconv.FormatInt(server.ID, 10), nil)
	response := httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).RevealServerToken(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		InstallCommand string `json:"install_command"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.InstallCommand, "steal_self=1") {
		t.Fatalf("historical steal_mode unexpectedly authorized port 443 takeover: %s", result.InstallCommand)
	}
}

func TestAuthoritativeInstallCommandDownloadsThenExecutes(t *testing.T) {
	bash, bashErr := exec.LookPath("bash")
	if bashErr != nil {
		t.Skip("bash is unavailable")
	}
	if _, curlErr := exec.LookPath("curl"); curlErr != nil {
		t.Skip("curl is unavailable")
	}
	marker := filepath.Join(t.TempDir(), "injected")
	token := "download-'$(touch${IFS}" + marker + ")'"
	type requestMetadata struct{ authorization, connectionMode string }
	requestValues := make(chan requestMetadata, 1)
	downloadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestValues <- requestMetadata{r.Header.Get("Authorization"), r.URL.Query().Get("connection_mode")}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("#!/bin/bash\nprintf '%s\\n%s\\n%s\\n' \"$ARCWAY_PANEL_IPS\" \"${1:-}\" \"$0\"\n"))
	}))
	defer downloadServer.Close()

	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.SetSystemSetting(context.Background(), "master_url", downloadServer.URL); err != nil {
		t.Fatal(err)
	}
	server := &storage.RemoteServer{
		Name: "execute-command", Token: token, ConnectionMode: storage.ConnectionModeWebSocket, ListenPort: 25000,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://ignored.example/api/admin/remote-servers/reveal-token", nil)
	commandText, err := NewXrayServerHandler(repo, nil, nil).buildRemoteInstallCommand(request, server, []string{"203.0.113.10", "2001:db8::10"}, false, "xray")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(bash, "-c", commandText)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("install command failed: %v\ncommand=%s\n%s", err, commandText, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 3 || lines[0] != "203.0.113.10 2001:db8::10" || lines[1] != "" {
		t.Fatalf("downloaded installer output=%q", output)
	}
	metadata := <-requestValues
	if metadata.authorization == "Bearer "+token || !strings.HasPrefix(metadata.authorization, "Bearer ") || metadata.connectionMode != "websocket" {
		t.Fatalf("request metadata=%+v", metadata)
	}
	ticket := strings.TrimPrefix(metadata.authorization, "Bearer ")
	consumed, err := repo.ConsumeRemoteServerInstallTicket(context.Background(), ticket, time.Now())
	if err != nil || consumed.ID != server.ID {
		t.Fatalf("install command did not use a valid one-time ticket: server=%+v err=%v", consumed, err)
	}
	if _, err := os.Stat(lines[2]); !os.IsNotExist(err) {
		t.Fatalf("temporary installer was not deleted: %s (stat err=%v)", lines[2], err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("install command executed token content: stat err=%v", err)
	}
	server.ConnectionMode = storage.ConnectionModePush
	pushCommand, err := NewXrayServerHandler(repo, nil, nil).buildRemoteInstallCommand(request, server, []string{"203.0.113.10"}, false, "xray")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pushCommand, "connection_mode=http") {
		t.Fatalf("HTTP Push command did not configure Agent HTTP mode: %s", pushCommand)
	}
}

func TestRemoteInstallScriptRejectsInvalidPanelSourceConfiguration(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "not-an-ip")
	handler, token := newExpiryGuardAssetHandler(t)
	request := httptest.NewRequest(http.MethodGet, "https://panel.example/api/remote/install.sh", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.GetRemoteInstallScript(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
}

func TestUpdateRemoteServerRejectsListenPortChange(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name: "fixed-port-edge", Token: "fixed-port-token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket, ListenPort: 25000,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(RemoteServerUpdateRequest{
		ID: server.ID, Name: server.Name, ListenPort: 25001,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/admin/remote-servers/update", strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).UpdateRemoteServer(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
	stored, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ListenPort != 25000 {
		t.Fatalf("listen port changed to %d", stored.ListenPort)
	}
	body, err = json.Marshal(RemoteServerUpdateRequest{
		ID: server.ID, Name: server.Name, ListenPort: 25000, ConnectionMode: storage.ConnectionModePush,
	})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPut, "/api/admin/remote-servers/update", strings.NewReader(string(body)))
	response = httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).UpdateRemoteServer(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("connection mode status=%d want=%d body=%s", response.Code, http.StatusConflict, response.Body.String())
	}
}

func TestUpdateRemoteServerValidatesDDNSBeforeMainUpdate(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name: "ddns-before", Token: "ddns-token", Status: storage.RemoteServerStatusConnected,
		PullAddress: "old.example.com", ConnectionMode: storage.ConnectionModeWebSocket,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(RemoteServerUpdateRequest{
		ID: server.ID, Name: "should-not-save", PullAddress: "new.example.com",
		DDNSEnabled: true, DDNSProviderID: 999999,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/admin/remote-servers/update", strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	NewXrayServerHandler(repo, nil, nil).UpdateRemoteServer(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	stored, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Name != "ddns-before" {
		t.Fatalf("main server update was applied before DDNS validation: name=%q", stored.Name)
	}
}

func TestCreateRemoteServerRejectsInvalidManagementPortPair(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	handler := NewXrayServerHandler(repo, nil, nil)
	for _, port := range []int{-1, 1, 1023, 65535, 65536} {
		body, err := json.Marshal(RemoteServerCreateRequest{Name: "invalid-port", ListenPort: port})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/admin/remote-servers", strings.NewReader(string(body)))
		response := httptest.NewRecorder()
		handler.CreateRemoteServer(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("port=%d status=%d want=%d body=%s", port, response.Code, http.StatusBadRequest, response.Body.String())
		}
	}
}

func TestCreateRemoteServerAcceptsManagementPortBoundaries(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10 2001:db8::10")
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	handler := NewXrayServerHandler(repo, nil, nil)
	for _, port := range []int{0, 1024, 65534} {
		body, err := json.Marshal(RemoteServerCreateRequest{
			Name: "valid-port-" + strconv.Itoa(port), ConnectionMode: storage.ConnectionModeWebSocket, ListenPort: port,
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://panel.example/api/admin/remote-servers", strings.NewReader(string(body)))
		response := httptest.NewRecorder()
		handler.CreateRemoteServer(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("port=%d status=%d body=%s", port, response.Code, response.Body.String())
		}
		var result RemoteServerResponse
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if !result.Success || result.Server == nil || result.Server.ListenPort != port {
			t.Fatalf("port=%d response=%+v", port, result)
		}
		if !strings.Contains(result.InstallCommand, "ARCWAY_PANEL_IPS='203.0.113.10 2001:db8::10'") {
			t.Fatalf("port=%d command missing trusted panel sources: %s", port, result.InstallCommand)
		}
		if !strings.Contains(result.InstallCommand, `-o "$installer"`) || strings.Contains(result.InstallCommand, " | ") {
			t.Fatalf("port=%d command does not fully download the installer before execution: %s", port, result.InstallCommand)
		}
		listenParameter := "listen_port=" + strconv.Itoa(port)
		if port == 0 && strings.Contains(result.InstallCommand, "listen_port=") {
			t.Fatalf("default port command unexpectedly contains listen_port: %s", result.InstallCommand)
		}
		if port > 0 && !strings.Contains(result.InstallCommand, listenParameter) {
			t.Fatalf("port=%d command missing %s: %s", port, listenParameter, result.InstallCommand)
		}
	}
}

func TestCreateRemoteServerPersistsConsistentTakeoverSettings(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	handler := NewXrayServerHandler(repo, nil, nil)
	tests := []struct {
		name      string
		stealSelf bool
		stealMode string
		domain    string
	}{
		{name: "disabled", stealMode: "default"},
		{name: "tunnel", stealSelf: true, stealMode: "tunnel", domain: "tunnel.example.com"},
		{name: "fallback", stealSelf: true, stealMode: "fallback", domain: "fallback.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(RemoteServerCreateRequest{
				Name: tc.name, ConnectionMode: storage.ConnectionModeWebSocket,
				StealSelf: tc.stealSelf, Use443: tc.stealSelf, StealMode: tc.stealMode, Domain: tc.domain,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://panel.example/api/admin/remote-servers", strings.NewReader(string(body)))
			response := httptest.NewRecorder()
			handler.CreateRemoteServer(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var result RemoteServerResponse
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Server == nil || result.Server.StealSelf != tc.stealSelf || result.Server.Use443 != tc.stealSelf || result.Server.StealMode != tc.stealMode {
				t.Fatalf("server=%+v want steal_self/use_443=%v steal_mode=%s", result.Server, tc.stealSelf, tc.stealMode)
			}
			hasQueryOption := strings.Contains(result.InstallCommand, "steal_self=1")
			if hasQueryOption != tc.stealSelf {
				t.Fatalf("command takeover option=%v want=%v: %s", hasQueryOption, tc.stealSelf, result.InstallCommand)
			}
			stored, err := repo.GetRemoteServer(context.Background(), result.Server.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.StealSelf != tc.stealSelf || stored.Use443 != tc.stealSelf || stored.StealMode != tc.stealMode {
				t.Fatalf("stored=%+v", stored)
			}
		})
	}
}

func TestCreateRemoteServerRejectsInconsistentTakeoverSettings(t *testing.T) {
	t.Setenv(panelSourceIPsEnv, "203.0.113.10")
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	handler := NewXrayServerHandler(repo, nil, nil)
	tests := []RemoteServerCreateRequest{
		{Name: "mode-without-flags", ConnectionMode: storage.ConnectionModeWebSocket, StealMode: "tunnel", Domain: "edge.example.com"},
		{Name: "missing-use443", ConnectionMode: storage.ConnectionModeWebSocket, StealSelf: true, StealMode: "tunnel", Domain: "edge.example.com"},
		{Name: "missing-domain", ConnectionMode: storage.ConnectionModeWebSocket, StealSelf: true, Use443: true, StealMode: "fallback"},
		{Name: "flags-with-default", ConnectionMode: storage.ConnectionModeWebSocket, StealSelf: true, Use443: true, StealMode: "default", Domain: "edge.example.com"},
		{Name: "unknown-mode", ConnectionMode: storage.ConnectionModeWebSocket, StealMode: "unknown"},
		{Name: "invalid-domain", ConnectionMode: storage.ConnectionModeWebSocket, Domain: "https://edge.example.com/path"},
	}
	for _, requestBody := range tests {
		t.Run(requestBody.Name, func(t *testing.T) {
			body, err := json.Marshal(requestBody)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://panel.example/api/admin/remote-servers", strings.NewReader(string(body)))
			response := httptest.NewRecorder()
			handler.CreateRemoteServer(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want=%d body=%s", response.Code, http.StatusBadRequest, response.Body.String())
			}
		})
	}
}

func TestRemoteServerHeartbeatRejectsListenPortDrift(t *testing.T) {
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	server := &storage.RemoteServer{
		Name: "heartbeat-port-edge", Token: "heartbeat-port-token", Status: storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModeWebSocket, ListenPort: 25000,
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateRemoteServerHeartbeatWithRestart(context.Background(), storage.HeartbeatUpdate{
		Token: server.Token, ListenPort: 25001,
	}); err == nil {
		t.Fatal("heartbeat listen port drift was accepted")
	}
	stored, err := repo.GetRemoteServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ListenPort != 25000 {
		t.Fatalf("listen port changed to %d", stored.ListenPort)
	}

	pending := &storage.RemoteServer{
		Name: "first-heartbeat-port", Token: "first-heartbeat-token", Status: storage.RemoteServerStatusPending,
		ConnectionMode: storage.ConnectionModeWebSocket,
	}
	if err := repo.CreateRemoteServer(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateRemoteServerHeartbeatWithRestart(context.Background(), storage.HeartbeatUpdate{
		Token: pending.Token, ListenPort: 26000,
	}); err != nil {
		t.Fatalf("first heartbeat port was rejected: %v", err)
	}
	stored, err = repo.GetRemoteServer(context.Background(), pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ListenPort != 26000 {
		t.Fatalf("first heartbeat listen port=%d want=26000", stored.ListenPort)
	}
	if _, err := repo.UpdateRemoteServerHeartbeatWithRestart(context.Background(), storage.HeartbeatUpdate{
		Token: pending.Token, ListenPort: 0, IPAddress: "198.51.100.20",
	}); err != nil {
		t.Fatalf("zero-port heartbeat after provisioning was rejected: %v", err)
	}
	stored, err = repo.GetRemoteServer(context.Background(), pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ListenPort != 26000 || stored.IPAddress != "198.51.100.20" {
		t.Fatalf("zero-port heartbeat stored port=%d ip=%q", stored.ListenPort, stored.IPAddress)
	}
	if _, err := repo.UpdateRemoteServerHeartbeatWithRestart(context.Background(), storage.HeartbeatUpdate{
		Token: pending.Token, ListenPort: 26001, IPAddress: "198.51.100.99",
	}); !errors.Is(err, storage.ErrRemoteListenPortMismatch) {
		t.Fatalf("drift error=%v want ErrRemoteListenPortMismatch", err)
	}
	stored, err = repo.GetRemoteServer(context.Background(), pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ListenPort != 26000 || stored.IPAddress != "198.51.100.20" {
		t.Fatalf("rejected drift partially updated server: port=%d ip=%q", stored.ListenPort, stored.IPAddress)
	}
}
