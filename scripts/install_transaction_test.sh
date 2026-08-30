#!/bin/bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_SCRIPT="$REPO_ROOT/install.sh"
TEST_ROOT=$(mktemp -d)

cleanup() {
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_file_equals() {
    expected=$1
    actual=$2
    [ -f "$actual" ] || fail "missing restored file: $actual"
    cmp -s "$expected" "$actual" || fail "restored file differs: $actual"
}

MOCK_BIN="$TEST_ROOT/mock-bin"
MOCK_RELEASE_ASSET_DIR="$TEST_ROOT/release-assets"
mkdir -p "$MOCK_BIN" "$MOCK_RELEASE_ASSET_DIR"
install -m 0755 \
    "$REPO_ROOT/deploy/arcway-wireguard-probe-egress.sh" \
    "$MOCK_RELEASE_ASSET_DIR/arcway-wireguard-probe-egress"
install -m 0644 \
    "$REPO_ROOT/deploy/arcway-wireguard-probe-egress.service" \
    "$MOCK_RELEASE_ASSET_DIR/arcway-wireguard-probe-egress.service"
install -m 0644 \
    "$REPO_ROOT/deploy/arcway-wireguard-probe-relay.conf" \
    "$MOCK_RELEASE_ASSET_DIR/arcway-wireguard-probe-relay.conf"
install -m 0644 \
    "$REPO_ROOT/deploy/wireguard-probe-egress.conf.example" \
    "$MOCK_RELEASE_ASSET_DIR/arcway-wireguard-probe-egress.conf.example"
export MOCK_RELEASE_ASSET_DIR

cat > "$MOCK_BIN/apt-get" <<'EOF'
#!/bin/bash
: > "${MOCK_APT_MARKER:?}"
exit 0
EOF

cat > "$MOCK_BIN/curl" <<'EOF'
#!/bin/bash
printf '%s\n' '{"tag_name":"v-test"}'
EOF

cat > "$MOCK_BIN/jq" <<'EOF'
#!/bin/bash
cat >/dev/null
printf '%s\n' 'v-test'
EOF

cat > "$MOCK_BIN/uname" <<'EOF'
#!/bin/bash
if [ "${1:-}" = "-m" ]; then
    printf '%s\n' 'x86_64'
else
    exec /usr/bin/uname "$@"
fi
EOF

cat > "$MOCK_BIN/wget" <<'EOF'
#!/bin/bash
url=""
output=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -O)
            shift
            output=${1:-}
            ;;
        http://*|https://*)
            url=$1
            ;;
    esac
    shift
done
[ -n "$url" ] && [ -n "$output" ] || exit 2
asset=${url##*/}
case "$asset" in
    relaydock-agent-linux-*)
        echo "installer must not download panel-local Agent assets: $asset" >&2
        exit 95
        ;;
esac
if [ "$asset" = "checksums.txt" ]; then
    for name in \
        arcway-linux-amd64 \
        arcway-expiry-guard-linux-amd64 \
        arcway-expiry-guard-linux-arm64 \
        arcway-wireguard-probe-egress \
        arcway-wireguard-probe-egress.service \
        arcway-wireguard-probe-relay.conf \
        arcway-wireguard-probe-egress.conf.example; do
        if [ -f "$MOCK_RELEASE_ASSET_DIR/$name" ]; then
            digest=$(sha256sum "$MOCK_RELEASE_ASSET_DIR/$name" | awk '{print $1}')
        else
            digest=$(printf 'new-%s\n' "$name" | sha256sum | awk '{print $1}')
        fi
        if [ "${MOCK_BAD_CHECKSUM_ASSET:-}" = "$name" ]; then
            digest=0000000000000000000000000000000000000000000000000000000000000000
        fi
        printf '%s  %s\n' "$digest" "$name"
    done > "$output"
elif [ -f "$MOCK_RELEASE_ASSET_DIR/$asset" ]; then
    cp "$MOCK_RELEASE_ASSET_DIR/$asset" "$output"
else
    printf 'new-%s\n' "$asset" > "$output"
fi
EOF

cat > "$MOCK_BIN/ip" <<'EOF'
#!/bin/bash
if [ "${1:-}" = "-4" ] && [ "${2:-}" = "route" ] && [ "${3:-}" = "get" ]; then
    printf '%s\n' '1.1.1.1 via 192.0.2.254 dev eth0 src 192.0.2.10 uid 0'
    exit 0
fi
if [ "${1:-}" = "-o" ] && [ "${2:-}" = "-4" ]; then
    printf '%s\n' '2: eth0    inet 192.0.2.10/24 scope global eth0'
    exit 0
fi
exit 2
EOF

cat > "$MOCK_BIN/iptables" <<'EOF'
#!/bin/bash
exit 0
EOF

cat > "$MOCK_BIN/systemd-analyze" <<'EOF'
#!/bin/bash
[ "${1:-}" = "verify" ] || exit 2
[ -f "${2:-}" ] || exit 2
grep -q '^ExecStart=' "$2" || exit 1
[ "${MOCK_VERIFY_FAIL:-}" != 1 ] || exit 1
printf '%s\n' "$2" >> "${MOCK_VERIFY_LOG:?}"
EOF

cat > "$MOCK_BIN/systemctl" <<'EOF'
#!/bin/bash
set -u
state_dir=${MOCK_STATE_DIR:?}
command=${1:-}
shift || true

requested_unit=arcway.service
for arg in "$@"; do
    case "$arg" in
        *.service) requested_unit=$arg ;;
    esac
done
unit=${ARCWAY_SYSTEMD_UNIT_DIR:?}/$requested_unit
if [ "$requested_unit" = "arcway-wireguard-probe-egress.service" ]; then
    state_prefix=wireguard-
else
    state_prefix=
fi
enabled_file="$state_dir/${state_prefix}enabled"
active_file="$state_dir/${state_prefix}active"

if [ "${MOCK_FAIL_COMMAND:-}" = "$command" ] && [ "$requested_unit" = "arcway.service" ] && [ ! -e "$state_dir/injected-$command" ]; then
    if [ "$command" = start ] && [ -n "${MOCK_DATABASE_PATH:-}" ]; then
        printf '%s\n' migrated-database > "$MOCK_DATABASE_PATH"
        printf '%s\n' migrated-wal > "$MOCK_DATABASE_PATH-wal"
        printf '%s\n' migrated-shm > "$MOCK_DATABASE_PATH-shm"
    fi
    : > "$state_dir/injected-$command"
    exit 1
fi

enable_state() {
    if [ -f "$unit" ] && grep -q '^# MOCK_STATIC=1$' "$unit"; then
        printf '%s\n' static
    else
        if [ -f "$enabled_file" ]; then
            cat "$enabled_file"
        else
            printf '%s\n' disabled
        fi
    fi
}

case "$command" in
    cat)
        [ -f "$unit" ]
        ;;
    is-active)
        state=inactive
        [ ! -f "$active_file" ] || state=$(cat "$active_file")
        if [ "$state" = active ]; then
            [ "${1:-}" = "--quiet" ] || printf '%s\n' active
            exit 0
        fi
        [ "${1:-}" = "--quiet" ] || printf '%s\n' inactive
        exit 3
        ;;
    is-enabled)
        state=$(enable_state)
        printf '%s\n' "$state"
        case "$state" in
            enabled|enabled-runtime) exit 0 ;;
            *) exit 1 ;;
        esac
        ;;
    show)
        if [ -f "$active_file" ] && [ "$(cat "$active_file")" = active ]; then
            printf '%s\n' active
        else
            printf '%s\n' inactive
        fi
        ;;
    stop)
        printf '%s\n' inactive > "$active_file"
        ;;
    disable)
        printf '%s\n' disabled > "$enabled_file"
        ;;
    unmask)
        :
        ;;
    daemon-reload)
        :
        ;;
    enable)
        runtime=false
        for arg in "$@"; do
            [ "$arg" = "--runtime" ] && runtime=true
        done
        if [ -f "$unit" ] && grep -q '^# MOCK_STATIC=1$' "$unit"; then
            exit 1
        fi
        if [ "$runtime" = true ]; then
            printf '%s\n' enabled-runtime > "$enabled_file"
        else
            printf '%s\n' enabled > "$enabled_file"
        fi
        ;;
    start)
        printf '%s\n' active > "$active_file"
        ;;
    *)
        echo "unexpected systemctl command: $command $*" >&2
        exit 2
        ;;
esac
EOF

chmod +x "$MOCK_BIN"/*

make_old_installation() {
    case_root=$1
    enable_state=$2
    active_state=$3
    panel_port=${4:-12889}
    install_dir="$case_root/bin"
    data_dir="$case_root/data"
    config_dir="$case_root/config"
    guard_dir="$case_root/lib/guard-assets"
    # Simulate an old panel-local Agent cache. It must remain untouched by
    # updates because remote Agents now fetch from GitHub Release directly.
    agent_dir="$case_root/lib/agent-assets"
    unit_dir="$case_root/systemd"
    state_dir="$case_root/state"
    expected_dir="$case_root/expected"
    mkdir -p "$install_dir" "$data_dir" "$config_dir" "$guard_dir" "$agent_dir" "$unit_dir" "$state_dir" "$expected_dir"

    printf '%s\n' old-binary > "$install_dir/arcway"
    printf '%s\n' old-backup > "$install_dir/arcway.bak"
    printf '%s\n' old-guard-amd64 > "$guard_dir/arcway-expiry-guard-linux-amd64"
    printf '%s\n' old-guard-arm64 > "$guard_dir/arcway-expiry-guard-linux-arm64"
    printf '%s\n' old-agent-amd64 > "$agent_dir/relaydock-agent-linux-amd64"
    printf '%s\n' old-agent-arm64 > "$agent_dir/relaydock-agent-linux-arm64"
    printf '%s\n' old-version > "$data_dir/.version"
    printf '%s\n' old-database > "$data_dir/arcway.db"
    printf '%s\n' old-wal > "$data_dir/arcway.db-wal"
    printf '%s\n' old-shm > "$data_dir/arcway.db-shm"
    cat > "$unit_dir/arcway.service" <<EOF
[Unit]
Description=old Arcway
$(if [ "$enable_state" = static ]; then printf '%s\n' '# MOCK_STATIC=1'; fi)
[Service]
Type=simple
WorkingDirectory=$case_root
ExecStart=$install_dir/arcway
Environment="PORT=$panel_port"
Environment="DATABASE_PATH=$data_dir/arcway.db"
Environment="ARCWAY_GUARD_ASSET_DIR=$guard_dir"
Environment="ARCWAY_AGENT_ASSET_DIR=$agent_dir"
Environment="ARCWAY_PANEL_IPS=192.0.2.1"
[Install]
WantedBy=multi-user.target
EOF
    chmod 0755 "$install_dir/arcway" "$guard_dir"/arcway-expiry-guard-linux-* "$agent_dir"/relaydock-agent-linux-*
    printf '%s\n' "$enable_state" > "$state_dir/enabled"
    printf '%s\n' "$active_state" > "$state_dir/active"

    cp "$install_dir/arcway" "$expected_dir/arcway"
    cp "$install_dir/arcway.bak" "$expected_dir/arcway.bak"
    cp "$guard_dir/arcway-expiry-guard-linux-amd64" "$expected_dir/guard-amd64"
    cp "$guard_dir/arcway-expiry-guard-linux-arm64" "$expected_dir/guard-arm64"
    cp "$unit_dir/arcway.service" "$expected_dir/arcway.service"
    cp "$data_dir/.version" "$expected_dir/version"
    cp "$data_dir/arcway.db" "$expected_dir/arcway.db"
    cp "$data_dir/arcway.db-wal" "$expected_dir/arcway.db-wal"
    cp "$data_dir/arcway.db-shm" "$expected_dir/arcway.db-shm"
}

make_old_wireguard_installation() {
    case_root=$1
    enable_state=${2:-enabled}
    active_state=${3:-active}
    mkdir -p "$case_root/systemd/arcway.service.d" "$case_root/config" "$case_root/expected"
    printf '%s\n' old-wireguard-script > "$case_root/bin/arcway-wireguard-probe-egress"
    printf '%s\n' old-wireguard-unit > "$case_root/systemd/arcway-wireguard-probe-egress.service"
    printf '%s\n' old-wireguard-dropin > "$case_root/systemd/arcway.service.d/wireguard-probe-relay.conf"
    printf '%s\n' '203.0.113.10 51820 192.0.2.10 39443 443' > "$case_root/config/wireguard-probe-egress.conf"
    printf '%s\n' old-wireguard-example > "$case_root/config/wireguard-probe-egress.conf.example"
    chmod 0755 "$case_root/bin/arcway-wireguard-probe-egress"
    printf '%s\n' "$enable_state" > "$case_root/state/wireguard-enabled"
    printf '%s\n' "$active_state" > "$case_root/state/wireguard-active"
    cp "$case_root/bin/arcway-wireguard-probe-egress" "$case_root/expected/wireguard-script"
    cp "$case_root/systemd/arcway-wireguard-probe-egress.service" "$case_root/expected/wireguard-unit"
    cp "$case_root/systemd/arcway.service.d/wireguard-probe-relay.conf" "$case_root/expected/wireguard-dropin"
    cp "$case_root/config/wireguard-probe-egress.conf" "$case_root/expected/wireguard-config"
    cp "$case_root/config/wireguard-probe-egress.conf.example" "$case_root/expected/wireguard-example"
}

run_fault_case() {
    failpoint=$1
    expected_enabled=$2
    expected_active=$3
    old_wireguard=${4:-false}
    case_root="$TEST_ROOT/$failpoint"
    make_old_installation "$case_root" "$expected_enabled" "$expected_active"
    if [ "$old_wireguard" = true ]; then
        make_old_wireguard_installation "$case_root" enabled-runtime active
    fi
    script_failpoint=""
    systemctl_fail_command=""
    verify_fail=0
    case "$failpoint" in
        after_binary_swap|after_first_guard_swap|after_wireguard_assets_swap)
            script_failpoint=$failpoint
            ;;
        daemon_reload_failure)
            systemctl_fail_command=daemon-reload
            ;;
        start_failure)
            systemctl_fail_command=start
            ;;
        unit_verify_failure)
            verify_fail=1
            ;;
    esac

    set +e
    PATH="$MOCK_BIN:/usr/bin:/bin" \
        MOCK_APT_MARKER="$case_root/apt-called" \
        MOCK_VERIFY_LOG="$case_root/verify.log" \
        MOCK_VERIFY_FAIL="$verify_fail" \
        MOCK_STATE_DIR="$case_root/state" \
        MOCK_FAIL_COMMAND="$systemctl_fail_command" \
        MOCK_DATABASE_PATH="$case_root/data/arcway.db" \
        ARCWAY_INSTALL_DIR="$case_root/bin" \
        ARCWAY_DATA_DIR="$case_root/data" \
        ARCWAY_CONFIG_DIR="$case_root/config" \
        ARCWAY_GUARD_ASSET_DIR="$case_root/lib/guard-assets" \
        ARCWAY_SYSTEMD_UNIT_DIR="$case_root/systemd" \
        ARCWAY_INSTALL_LOCK_FILE="$case_root/install.lock" \
        ARCWAY_DATABASE_PATH="$case_root/data/arcway.db" \
        ARCWAY_TEST_FAILPOINT="$script_failpoint" \
        PORT=12889 \
        bash "$INSTALL_SCRIPT" reinstall >"$case_root/output.log" 2>&1
    result=$?
    set -e
    [ "$result" -ne 0 ] || fail "$failpoint unexpectedly succeeded"

    assert_file_equals "$case_root/expected/arcway" "$case_root/bin/arcway"
    assert_file_equals "$case_root/expected/arcway.bak" "$case_root/bin/arcway.bak"
    assert_file_equals "$case_root/expected/guard-amd64" "$case_root/lib/guard-assets/arcway-expiry-guard-linux-amd64"
    assert_file_equals "$case_root/expected/guard-arm64" "$case_root/lib/guard-assets/arcway-expiry-guard-linux-arm64"
    assert_file_equals "$case_root/expected/arcway.service" "$case_root/systemd/arcway.service"
    assert_file_equals "$case_root/expected/version" "$case_root/data/.version"
    assert_file_equals "$case_root/expected/arcway.db" "$case_root/data/arcway.db"
    assert_file_equals "$case_root/expected/arcway.db-wal" "$case_root/data/arcway.db-wal"
    assert_file_equals "$case_root/expected/arcway.db-shm" "$case_root/data/arcway.db-shm"

    if [ "$old_wireguard" = true ]; then
        assert_file_equals "$case_root/expected/wireguard-script" "$case_root/bin/arcway-wireguard-probe-egress"
        assert_file_equals "$case_root/expected/wireguard-unit" "$case_root/systemd/arcway-wireguard-probe-egress.service"
        assert_file_equals "$case_root/expected/wireguard-dropin" "$case_root/systemd/arcway.service.d/wireguard-probe-relay.conf"
        assert_file_equals "$case_root/expected/wireguard-config" "$case_root/config/wireguard-probe-egress.conf"
        assert_file_equals "$case_root/expected/wireguard-example" "$case_root/config/wireguard-probe-egress.conf.example"
        [ "$(cat "$case_root/state/wireguard-enabled")" = enabled-runtime ] || fail "$failpoint did not restore WireGuard enable state"
        [ "$(cat "$case_root/state/wireguard-active")" = active ] || fail "$failpoint did not restore WireGuard active state"
    else
        for path in \
            "$case_root/bin/arcway-wireguard-probe-egress" \
            "$case_root/systemd/arcway-wireguard-probe-egress.service" \
            "$case_root/systemd/arcway.service.d/wireguard-probe-relay.conf" \
            "$case_root/config/wireguard-probe-egress.conf" \
            "$case_root/config/wireguard-probe-egress.conf.example"; do
            [ ! -e "$path" ] || fail "$failpoint left a WireGuard probe asset: $path"
        done
        wireguard_enable_state=$(cat "$case_root/state/wireguard-enabled" 2>/dev/null || printf '%s\n' disabled)
        wireguard_active_state=$(cat "$case_root/state/wireguard-active" 2>/dev/null || printf '%s\n' inactive)
        [ "$wireguard_enable_state" = disabled ] || fail "$failpoint left the WireGuard service enabled"
        [ "$wireguard_active_state" = inactive ] || fail "$failpoint left the WireGuard service active"
    fi

    actual_enabled=$(PATH="$MOCK_BIN:/usr/bin:/bin" MOCK_STATE_DIR="$case_root/state" \
        ARCWAY_SYSTEMD_UNIT_DIR="$case_root/systemd" systemctl is-enabled arcway.service 2>/dev/null || true)
    [ "$actual_enabled" = "$expected_enabled" ] || fail "$failpoint enabled state: $actual_enabled, want $expected_enabled"
    actual_active=$(cat "$case_root/state/active")
    [ "$actual_active" = "$expected_active" ] || fail "$failpoint active state: $actual_active, want $expected_active"

    if find "$case_root/bin" "$case_root/data" "$case_root/lib" "$case_root/systemd" \
        -name '*.arcway-stage.*' -print -quit | grep -q .; then
        fail "$failpoint left an atomic stage file"
    fi
    case "$failpoint" in
        daemon_reload_failure|start_failure)
            [ -s "$case_root/verify.log" ] || fail "$failpoint replaced a unit without systemd-analyze verify"
            ;;
    esac
    grep -q '已恢复原状态' "$case_root/output.log" || fail "$failpoint did not report a complete rollback"
}

run_fault_case after_binary_swap enabled active
run_fault_case after_first_guard_swap enabled-runtime inactive
run_fault_case daemon_reload_failure disabled active
run_fault_case start_failure static inactive
run_fault_case unit_verify_failure enabled active
run_fault_case after_wireguard_assets_swap enabled active true

# Static relay assets are rejected before the running installation is touched
# when their release checksum does not match.
BAD_RELAY_CHECKSUM_ROOT="$TEST_ROOT/bad-relay-checksum"
make_old_installation "$BAD_RELAY_CHECKSUM_ROOT" enabled active
set +e
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$BAD_RELAY_CHECKSUM_ROOT/apt-called" \
    MOCK_BAD_CHECKSUM_ASSET=arcway-wireguard-probe-egress \
    MOCK_STATE_DIR="$BAD_RELAY_CHECKSUM_ROOT/state" \
    ARCWAY_INSTALL_DIR="$BAD_RELAY_CHECKSUM_ROOT/bin" \
    ARCWAY_DATA_DIR="$BAD_RELAY_CHECKSUM_ROOT/data" \
    ARCWAY_CONFIG_DIR="$BAD_RELAY_CHECKSUM_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$BAD_RELAY_CHECKSUM_ROOT/lib/guard-assets" \
    ARCWAY_SYSTEMD_UNIT_DIR="$BAD_RELAY_CHECKSUM_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$BAD_RELAY_CHECKSUM_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" reinstall >"$BAD_RELAY_CHECKSUM_ROOT/output.log" 2>&1
bad_relay_checksum_result=$?
set -e
[ "$bad_relay_checksum_result" -ne 0 ] || fail "bad WireGuard relay checksum unexpectedly succeeded"
assert_file_equals "$BAD_RELAY_CHECKSUM_ROOT/expected/arcway" "$BAD_RELAY_CHECKSUM_ROOT/bin/arcway"
[ "$(cat "$BAD_RELAY_CHECKSUM_ROOT/state/active")" = active ] || fail "checksum rejection stopped the current service"
if grep -q '正在恢复原状态' "$BAD_RELAY_CHECKSUM_ROOT/output.log"; then
    fail "checksum rejection entered a transaction"
fi

# An unsafe explicit egress address is also rejected during preflight.
BAD_RELAY_IP_ROOT="$TEST_ROOT/bad-relay-ip"
make_old_installation "$BAD_RELAY_IP_ROOT" enabled active
set +e
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$BAD_RELAY_IP_ROOT/apt-called" \
    MOCK_STATE_DIR="$BAD_RELAY_IP_ROOT/state" \
    ARCWAY_INSTALL_DIR="$BAD_RELAY_IP_ROOT/bin" \
    ARCWAY_DATA_DIR="$BAD_RELAY_IP_ROOT/data" \
    ARCWAY_CONFIG_DIR="$BAD_RELAY_IP_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$BAD_RELAY_IP_ROOT/lib/guard-assets" \
    ARCWAY_SYSTEMD_UNIT_DIR="$BAD_RELAY_IP_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$BAD_RELAY_IP_ROOT/install.lock" \
    ARCWAY_MIHOMO_WIREGUARD_LOCAL_IPV4=127.0.0.1 \
    bash "$INSTALL_SCRIPT" reinstall >"$BAD_RELAY_IP_ROOT/output.log" 2>&1
bad_relay_ip_result=$?
set -e
[ "$bad_relay_ip_result" -ne 0 ] || fail "unsafe WireGuard relay IP unexpectedly succeeded"
assert_file_equals "$BAD_RELAY_IP_ROOT/expected/arcway" "$BAD_RELAY_IP_ROOT/bin/arcway"
[ "$(cat "$BAD_RELAY_IP_ROOT/state/active")" = active ] || fail "IP preflight rejection stopped the current service"
if grep -q '正在恢复原状态' "$BAD_RELAY_IP_ROOT/output.log"; then
    fail "IP preflight rejection entered a transaction"
fi

# Unknown systemd enable states are rejected before the installed files or service are touched.
UNSUPPORTED_ROOT="$TEST_ROOT/unsupported-enable-state"
make_old_installation "$UNSUPPORTED_ROOT" masked active
set +e
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$UNSUPPORTED_ROOT/apt-called" \
    MOCK_VERIFY_LOG="$UNSUPPORTED_ROOT/verify.log" \
    MOCK_STATE_DIR="$UNSUPPORTED_ROOT/state" \
    ARCWAY_INSTALL_DIR="$UNSUPPORTED_ROOT/bin" \
    ARCWAY_DATA_DIR="$UNSUPPORTED_ROOT/data" \
    ARCWAY_CONFIG_DIR="$UNSUPPORTED_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$UNSUPPORTED_ROOT/lib/guard-assets" \
    ARCWAY_SYSTEMD_UNIT_DIR="$UNSUPPORTED_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$UNSUPPORTED_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" reinstall >"$UNSUPPORTED_ROOT/output.log" 2>&1
unsupported_result=$?
set -e
[ "$unsupported_result" -ne 0 ] || fail "unsupported enable state unexpectedly succeeded"
assert_file_equals "$UNSUPPORTED_ROOT/expected/arcway" "$UNSUPPORTED_ROOT/bin/arcway"
assert_file_equals "$UNSUPPORTED_ROOT/expected/guard-amd64" "$UNSUPPORTED_ROOT/lib/guard-assets/arcway-expiry-guard-linux-amd64"
assert_file_equals "$UNSUPPORTED_ROOT/expected/arcway.service" "$UNSUPPORTED_ROOT/systemd/arcway.service"
assert_file_equals "$UNSUPPORTED_ROOT/expected/version" "$UNSUPPORTED_ROOT/data/.version"
[ "$(cat "$UNSUPPORTED_ROOT/state/active")" = active ] || fail "unsupported state check stopped the service"
grep -q '服务启用状态不受支持' "$UNSUPPORTED_ROOT/output.log" || fail "unsupported state failure was not explicit"
if grep -q '正在恢复原状态' "$UNSUPPORTED_ROOT/output.log"; then
    fail "unsupported state entered a transaction before rejection"
fi

# The same isolated setup must also complete a normal reinstall transaction.
SUCCESS_ROOT="$TEST_ROOT/success"
make_old_installation "$SUCCESS_ROOT" enabled active
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$SUCCESS_ROOT/apt-called" \
    MOCK_VERIFY_LOG="$SUCCESS_ROOT/verify.log" \
    MOCK_STATE_DIR="$SUCCESS_ROOT/state" \
    ARCWAY_INSTALL_DIR="$SUCCESS_ROOT/bin" \
    ARCWAY_DATA_DIR="$SUCCESS_ROOT/data" \
    ARCWAY_CONFIG_DIR="$SUCCESS_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$SUCCESS_ROOT/lib/guard-assets" \
    ARCWAY_SYSTEMD_UNIT_DIR="$SUCCESS_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$SUCCESS_ROOT/install.lock" \
    PORT=19090 \
    bash "$INSTALL_SCRIPT" reinstall >"$SUCCESS_ROOT/output.log" 2>&1
grep -q '^new-arcway-linux-amd64$' "$SUCCESS_ROOT/bin/arcway" || fail "successful reinstall did not replace binary"
grep -q '^old-binary$' "$SUCCESS_ROOT/bin/arcway.bak" || fail "successful reinstall did not atomically retain prior binary"
grep -q '^new-arcway-expiry-guard-linux-amd64$' "$SUCCESS_ROOT/lib/guard-assets/arcway-expiry-guard-linux-amd64" || fail "successful reinstall did not replace amd64 guard"
grep -q '^new-arcway-expiry-guard-linux-arm64$' "$SUCCESS_ROOT/lib/guard-assets/arcway-expiry-guard-linux-arm64" || fail "successful reinstall did not replace arm64 guard"
grep -q '^old-agent-amd64$' "$SUCCESS_ROOT/lib/agent-assets/relaydock-agent-linux-amd64" || fail "successful reinstall changed the legacy Agent cache"
grep -q '^old-agent-arm64$' "$SUCCESS_ROOT/lib/agent-assets/relaydock-agent-linux-arm64" || fail "successful reinstall changed the legacy Agent cache"
grep -q '^v-test$' "$SUCCESS_ROOT/data/.version" || fail "successful reinstall did not replace version file"
[ "$(cat "$SUCCESS_ROOT/state/enabled")" = enabled ] || fail "successful reinstall is not enabled"
[ "$(cat "$SUCCESS_ROOT/state/active")" = active ] || fail "successful reinstall is not active"
[ "$(cat "$SUCCESS_ROOT/state/wireguard-enabled")" = enabled ] || fail "successful reinstall did not enable the WireGuard probe service"
[ "$(cat "$SUCCESS_ROOT/state/wireguard-active")" = active ] || fail "successful reinstall did not start the WireGuard probe service"
[ -s "$SUCCESS_ROOT/verify.log" ] || fail "successful reinstall did not verify staged unit"
cmp -s "$MOCK_RELEASE_ASSET_DIR/arcway-wireguard-probe-egress" "$SUCCESS_ROOT/bin/arcway-wireguard-probe-egress" || fail "successful reinstall did not install the verified WireGuard script"
cmp -s "$MOCK_RELEASE_ASSET_DIR/arcway-wireguard-probe-egress.conf.example" "$SUCCESS_ROOT/config/wireguard-probe-egress.conf.example" || fail "successful reinstall did not install the verified WireGuard example"
[ "$(stat -c '%a' "$SUCCESS_ROOT/config/wireguard-probe-egress.conf")" = 600 ] || fail "WireGuard probe configuration is not private"
grep -q '^192\.0\.2\.10 39443 443$' "$SUCCESS_ROOT/config/wireguard-probe-egress.conf" || fail "successful reinstall wrote the wrong WireGuard probe tuple"
grep -Fq "ExecStart=$SUCCESS_ROOT/bin/arcway-wireguard-probe-egress apply $SUCCESS_ROOT/config/wireguard-probe-egress.conf" "$SUCCESS_ROOT/systemd/arcway-wireguard-probe-egress.service" || fail "WireGuard service does not use the detected custom installation paths"
grep -Fq "ExecStartPre=$SUCCESS_ROOT/bin/arcway-wireguard-probe-egress status $SUCCESS_ROOT/config/wireguard-probe-egress.conf" "$SUCCESS_ROOT/systemd/arcway.service.d/wireguard-probe-relay.conf" || fail "RelayDock drop-in does not validate the managed WireGuard rules"
grep -q '^Environment="PORT=19090"$' "$SUCCESS_ROOT/systemd/arcway.service" || fail "explicit PORT did not override the existing port"
if grep -q '^Environment="ARCWAY_AGENT_ASSET_DIR=' "$SUCCESS_ROOT/systemd/arcway.service"; then
    fail "reinstall retained the obsolete Agent asset directory setting"
fi
if grep -q '^Environment="ARCWAY_SPEEDTESTER_ASSET_DIR=' "$SUCCESS_ROOT/systemd/arcway.service"; then
    fail "reinstall retained the obsolete speedtester asset directory setting"
fi

# A non-interactive reinstall keeps the current port when PORT is not provided.
INHERIT_PORT_ROOT="$TEST_ROOT/inherit-port"
make_old_installation "$INHERIT_PORT_ROOT" enabled active 18080
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$INHERIT_PORT_ROOT/apt-called" \
    MOCK_VERIFY_LOG="$INHERIT_PORT_ROOT/verify.log" \
    MOCK_STATE_DIR="$INHERIT_PORT_ROOT/state" \
    ARCWAY_INSTALL_DIR="$INHERIT_PORT_ROOT/bin" \
    ARCWAY_DATA_DIR="$INHERIT_PORT_ROOT/data" \
    ARCWAY_CONFIG_DIR="$INHERIT_PORT_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$INHERIT_PORT_ROOT/lib/guard-assets" \
    ARCWAY_SYSTEMD_UNIT_DIR="$INHERIT_PORT_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$INHERIT_PORT_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" reinstall >"$INHERIT_PORT_ROOT/output.log" 2>&1
grep -q '^Environment="PORT=18080"$' "$INHERIT_PORT_ROOT/systemd/arcway.service" || fail "reinstall did not inherit the existing port"

# A non-interactive uninstall preserves data unless deletion is explicitly requested.
UNINSTALL_ROOT="$TEST_ROOT/uninstall-default"
make_old_installation "$UNINSTALL_ROOT" enabled active
make_old_wireguard_installation "$UNINSTALL_ROOT" enabled active
mkdir -p "$UNINSTALL_ROOT/lib/speedtester-assets"
printf '%s\n' legacy-speedtester > "$UNINSTALL_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-amd64"
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_STATE_DIR="$UNINSTALL_ROOT/state" \
    ARCWAY_INSTALL_DIR="$UNINSTALL_ROOT/bin" \
    ARCWAY_DATA_DIR="$UNINSTALL_ROOT/data" \
    ARCWAY_CONFIG_DIR="$UNINSTALL_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$UNINSTALL_ROOT/lib/guard-assets" \
    ARCWAY_SYSTEMD_UNIT_DIR="$UNINSTALL_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$UNINSTALL_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" uninstall >"$UNINSTALL_ROOT/output.log" 2>&1
[ -f "$UNINSTALL_ROOT/data/arcway.db" ] || fail "non-interactive uninstall deleted data by default"
[ ! -e "$UNINSTALL_ROOT/bin/arcway" ] || fail "uninstall did not remove the binary"
[ -e "$UNINSTALL_ROOT/lib/agent-assets/relaydock-agent-linux-amd64" ] || fail "uninstall removed the legacy Agent cache"
[ -f "$UNINSTALL_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-amd64" ] || fail "uninstall removed the legacy speedtester cache"
[ ! -e "$UNINSTALL_ROOT/systemd/arcway.service" ] || fail "uninstall did not remove the systemd unit"
[ ! -e "$UNINSTALL_ROOT/systemd/arcway-wireguard-probe-egress.service" ] || fail "uninstall did not remove the WireGuard service unit"
[ ! -e "$UNINSTALL_ROOT/systemd/arcway.service.d/wireguard-probe-relay.conf" ] || fail "uninstall did not remove the WireGuard drop-in"
[ ! -e "$UNINSTALL_ROOT/bin/arcway-wireguard-probe-egress" ] || fail "uninstall did not remove the WireGuard egress script"
[ -f "$UNINSTALL_ROOT/config/wireguard-probe-egress.conf" ] || fail "data-preserving uninstall removed the WireGuard configuration"
[ "$(cat "$UNINSTALL_ROOT/state/wireguard-enabled")" = disabled ] || fail "uninstall left the WireGuard service enabled"
[ "$(cat "$UNINSTALL_ROOT/state/wireguard-active")" = inactive ] || fail "uninstall left the WireGuard service active"
grep -q '保留数据模式' "$UNINSTALL_ROOT/output.log" || fail "uninstall did not report preserved data"

# Uninstall leaves the entire legacy speedtester directory untouched.
UNINSTALL_SENTINEL_ROOT="$TEST_ROOT/uninstall-sentinel"
make_old_installation "$UNINSTALL_SENTINEL_ROOT" enabled active
mkdir -p "$UNINSTALL_SENTINEL_ROOT/lib/speedtester-assets"
printf '%s\n' managed-old > "$UNINSTALL_SENTINEL_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-amd64"
printf '%s\n' operator-owned > "$UNINSTALL_SENTINEL_ROOT/lib/speedtester-assets/operator-note"
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_STATE_DIR="$UNINSTALL_SENTINEL_ROOT/state" \
    ARCWAY_INSTALL_DIR="$UNINSTALL_SENTINEL_ROOT/bin" \
    ARCWAY_DATA_DIR="$UNINSTALL_SENTINEL_ROOT/data" \
    ARCWAY_CONFIG_DIR="$UNINSTALL_SENTINEL_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$UNINSTALL_SENTINEL_ROOT/lib/guard-assets" \
    ARCWAY_SYSTEMD_UNIT_DIR="$UNINSTALL_SENTINEL_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$UNINSTALL_SENTINEL_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" uninstall >"$UNINSTALL_SENTINEL_ROOT/output.log" 2>&1
grep -q '^operator-owned$' "$UNINSTALL_SENTINEL_ROOT/lib/speedtester-assets/operator-note" || fail "uninstall removed unrelated speedtester directory content"
grep -q '^managed-old$' "$UNINSTALL_SENTINEL_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-amd64" || fail "uninstall changed the legacy speedtester cache"
[ -d "$UNINSTALL_SENTINEL_ROOT/lib/speedtester-assets" ] || fail "sentinel uninstall removed the legacy speedtester directory"

# flock is a hard prerequisite and is checked before apt/download activity.
NO_FLOCK_BIN="$TEST_ROOT/no-flock-bin"
mkdir -p "$NO_FLOCK_BIN"
set +e
PATH="$NO_FLOCK_BIN" MOCK_APT_MARKER="$TEST_ROOT/no-flock-apt-called" \
    ARCWAY_INSTALL_LOCK_FILE="$TEST_ROOT/no-flock.lock" \
    /bin/bash "$INSTALL_SCRIPT" reinstall >"$TEST_ROOT/no-flock.log" 2>&1
no_flock_result=$?
set -e
[ "$no_flock_result" -ne 0 ] || fail "installer succeeded without flock"
[ ! -e "$TEST_ROOT/no-flock-apt-called" ] || fail "installer ran apt before rejecting missing flock"
grep -q '缺少 flock' "$TEST_ROOT/no-flock.log" || fail "missing-flock failure was not explicit"

# A held lock also rejects the second installer before dependencies/downloads.
LOCK_FILE="$TEST_ROOT/contended.lock"
exec 8>"$LOCK_FILE"
flock -n 8
set +e
PATH="$MOCK_BIN:/usr/bin:/bin" MOCK_APT_MARKER="$TEST_ROOT/contended-apt-called" \
    ARCWAY_INSTALL_LOCK_FILE="$LOCK_FILE" \
    bash "$INSTALL_SCRIPT" reinstall >"$TEST_ROOT/contended.log" 2>&1
contended_result=$?
set -e
[ "$contended_result" -ne 0 ] || fail "installer succeeded while lock was held"
[ ! -e "$TEST_ROOT/contended-apt-called" ] || fail "installer ran apt before rejecting lock contention"

echo "install transaction tests passed"
