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
mkdir -p "$MOCK_BIN"

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
        relaydock-speedtester-linux-amd64 \
        relaydock-speedtester-linux-arm64 \
        relaydock-speedtester-windows-amd64.exe \
        relaydock-speedtester-windows-arm64.exe; do
        digest=$(printf 'new-%s\n' "$name" | sha256sum | awk '{print $1}')
        if [ "${MOCK_BAD_CHECKSUM_ASSET:-}" = "$name" ]; then
            digest=0000000000000000000000000000000000000000000000000000000000000000
        fi
        printf '%s  %s\n' "$digest" "$name"
    done > "$output"
else
    printf 'new-%s\n' "$asset" > "$output"
fi
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
unit=${ARCWAY_SYSTEMD_UNIT_DIR:?}/arcway.service
command=${1:-}
shift || true

if [ "${MOCK_FAIL_COMMAND:-}" = "$command" ] && [ ! -e "$state_dir/injected-$command" ]; then
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
        cat "$state_dir/enabled"
    fi
}

case "$command" in
    cat)
        [ -f "$unit" ]
        ;;
    is-active)
        state=$(cat "$state_dir/active")
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
        if [ "$(cat "$state_dir/active")" = active ]; then
            printf '%s\n' active
        else
            printf '%s\n' inactive
        fi
        ;;
    stop)
        printf '%s\n' inactive > "$state_dir/active"
        ;;
    disable)
        printf '%s\n' disabled > "$state_dir/enabled"
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
            printf '%s\n' enabled-runtime > "$state_dir/enabled"
        else
            printf '%s\n' enabled > "$state_dir/enabled"
        fi
        ;;
    start)
        printf '%s\n' active > "$state_dir/active"
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
    speedtester_dir="$case_root/lib/speedtester-assets"
    unit_dir="$case_root/systemd"
    state_dir="$case_root/state"
    expected_dir="$case_root/expected"
    mkdir -p "$install_dir" "$data_dir" "$config_dir" "$guard_dir" "$agent_dir" "$speedtester_dir" "$unit_dir" "$state_dir" "$expected_dir"

    printf '%s\n' old-binary > "$install_dir/arcway"
    printf '%s\n' old-backup > "$install_dir/arcway.bak"
    printf '%s\n' old-guard-amd64 > "$guard_dir/arcway-expiry-guard-linux-amd64"
    printf '%s\n' old-guard-arm64 > "$guard_dir/arcway-expiry-guard-linux-arm64"
    printf '%s\n' old-agent-amd64 > "$agent_dir/relaydock-agent-linux-amd64"
    printf '%s\n' old-agent-arm64 > "$agent_dir/relaydock-agent-linux-arm64"
    printf '%s\n' old-speedtester-linux-amd64 > "$speedtester_dir/relaydock-speedtester-linux-amd64"
    printf '%s\n' old-speedtester-linux-arm64 > "$speedtester_dir/relaydock-speedtester-linux-arm64"
    printf '%s\n' old-speedtester-windows-amd64 > "$speedtester_dir/relaydock-speedtester-windows-amd64.exe"
    printf '%s\n' old-speedtester-windows-arm64 > "$speedtester_dir/relaydock-speedtester-windows-arm64.exe"
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
Environment="ARCWAY_SPEEDTESTER_ASSET_DIR=$speedtester_dir"
Environment="ARCWAY_PANEL_IPS=192.0.2.1"
[Install]
WantedBy=multi-user.target
EOF
    chmod 0755 "$install_dir/arcway" "$guard_dir"/arcway-expiry-guard-linux-* "$agent_dir"/relaydock-agent-linux-* "$speedtester_dir"/relaydock-speedtester-*
    chmod 0710 "$speedtester_dir"
    printf '%s\n' "$enable_state" > "$state_dir/enabled"
    printf '%s\n' "$active_state" > "$state_dir/active"

    cp "$install_dir/arcway" "$expected_dir/arcway"
    cp "$install_dir/arcway.bak" "$expected_dir/arcway.bak"
    cp "$guard_dir/arcway-expiry-guard-linux-amd64" "$expected_dir/guard-amd64"
    cp "$guard_dir/arcway-expiry-guard-linux-arm64" "$expected_dir/guard-arm64"
    cp "$speedtester_dir/relaydock-speedtester-linux-amd64" "$expected_dir/speedtester-linux-amd64"
    cp "$speedtester_dir/relaydock-speedtester-linux-arm64" "$expected_dir/speedtester-linux-arm64"
    cp "$speedtester_dir/relaydock-speedtester-windows-amd64.exe" "$expected_dir/speedtester-windows-amd64.exe"
    cp "$speedtester_dir/relaydock-speedtester-windows-arm64.exe" "$expected_dir/speedtester-windows-arm64.exe"
    cp "$unit_dir/arcway.service" "$expected_dir/arcway.service"
    cp "$data_dir/.version" "$expected_dir/version"
    cp "$data_dir/arcway.db" "$expected_dir/arcway.db"
    cp "$data_dir/arcway.db-wal" "$expected_dir/arcway.db-wal"
    cp "$data_dir/arcway.db-shm" "$expected_dir/arcway.db-shm"
}

run_fault_case() {
    failpoint=$1
    expected_enabled=$2
    expected_active=$3
    speedtester_state=${4:-existing}
    case_root="$TEST_ROOT/$failpoint"
    if [ "$speedtester_state" = missing ]; then
        case_root="$case_root-missing-speedtester"
    fi
    make_old_installation "$case_root" "$expected_enabled" "$expected_active"
    if [ "$speedtester_state" = missing ]; then
        rm -rf "$case_root/lib/speedtester-assets"
    fi
    script_failpoint=""
    systemctl_fail_command=""
    verify_fail=0
    case "$failpoint" in
        after_binary_swap|after_first_guard_swap|after_first_speedtester_swap)
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
        ARCWAY_SPEEDTESTER_ASSET_DIR="$case_root/lib/speedtester-assets" \
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
    if [ "$speedtester_state" = missing ]; then
        [ ! -e "$case_root/lib/speedtester-assets" ] || fail "$failpoint left a newly-created speedtester asset directory"
    else
        assert_file_equals "$case_root/expected/speedtester-linux-amd64" "$case_root/lib/speedtester-assets/relaydock-speedtester-linux-amd64"
        assert_file_equals "$case_root/expected/speedtester-linux-arm64" "$case_root/lib/speedtester-assets/relaydock-speedtester-linux-arm64"
        assert_file_equals "$case_root/expected/speedtester-windows-amd64.exe" "$case_root/lib/speedtester-assets/relaydock-speedtester-windows-amd64.exe"
        assert_file_equals "$case_root/expected/speedtester-windows-arm64.exe" "$case_root/lib/speedtester-assets/relaydock-speedtester-windows-arm64.exe"
        [ "$(stat -c '%a' "$case_root/lib/speedtester-assets")" = 710 ] || fail "$failpoint did not restore the speedtester directory mode"
    fi
    assert_file_equals "$case_root/expected/arcway.service" "$case_root/systemd/arcway.service"
    assert_file_equals "$case_root/expected/version" "$case_root/data/.version"
    assert_file_equals "$case_root/expected/arcway.db" "$case_root/data/arcway.db"
    assert_file_equals "$case_root/expected/arcway.db-wal" "$case_root/data/arcway.db-wal"
    assert_file_equals "$case_root/expected/arcway.db-shm" "$case_root/data/arcway.db-shm"

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
run_fault_case after_first_speedtester_swap enabled active
run_fault_case after_first_speedtester_swap enabled active missing
run_fault_case daemon_reload_failure disabled active
run_fault_case start_failure static inactive
run_fault_case unit_verify_failure enabled active

# Every speedtester asset must be covered by the release checksum before a transaction starts.
run_speedtester_checksum_case() {
    checksum_asset=$1
    checksum_root="$TEST_ROOT/speedtester-checksum-$checksum_asset"
    make_old_installation "$checksum_root" enabled active
    cp "$checksum_root/lib/speedtester-assets/$checksum_asset" "$checksum_root/expected/checksum-asset"

    set +e
    PATH="$MOCK_BIN:/usr/bin:/bin" \
        MOCK_APT_MARKER="$checksum_root/apt-called" \
        MOCK_BAD_CHECKSUM_ASSET="$checksum_asset" \
        MOCK_STATE_DIR="$checksum_root/state" \
        ARCWAY_INSTALL_DIR="$checksum_root/bin" \
        ARCWAY_DATA_DIR="$checksum_root/data" \
        ARCWAY_CONFIG_DIR="$checksum_root/config" \
        ARCWAY_GUARD_ASSET_DIR="$checksum_root/lib/guard-assets" \
        ARCWAY_SPEEDTESTER_ASSET_DIR="$checksum_root/lib/speedtester-assets" \
        ARCWAY_SYSTEMD_UNIT_DIR="$checksum_root/systemd" \
        ARCWAY_INSTALL_LOCK_FILE="$checksum_root/install.lock" \
        bash "$INSTALL_SCRIPT" reinstall >"$checksum_root/output.log" 2>&1
    checksum_result=$?
    set -e

    [ "$checksum_result" -ne 0 ] || fail "invalid checksum unexpectedly succeeded: $checksum_asset"
    assert_file_equals "$checksum_root/expected/arcway" "$checksum_root/bin/arcway"
    assert_file_equals "$checksum_root/expected/checksum-asset" "$checksum_root/lib/speedtester-assets/$checksum_asset"
    [ "$(cat "$checksum_root/state/active")" = active ] || fail "checksum failure stopped the existing service: $checksum_asset"
    grep -Fq "SHA-256 校验失败: $checksum_asset" "$checksum_root/output.log" || fail "checksum failure was not explicit: $checksum_asset"
    if grep -q '正在恢复原状态' "$checksum_root/output.log"; then
        fail "checksum failure entered the update transaction: $checksum_asset"
    fi
}

run_speedtester_checksum_case relaydock-speedtester-linux-amd64
run_speedtester_checksum_case relaydock-speedtester-linux-arm64
run_speedtester_checksum_case relaydock-speedtester-windows-amd64.exe
run_speedtester_checksum_case relaydock-speedtester-windows-arm64.exe

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
grep -q '^new-relaydock-speedtester-linux-amd64$' "$SUCCESS_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-amd64" || fail "successful reinstall did not replace linux amd64 speedtester"
grep -q '^new-relaydock-speedtester-linux-arm64$' "$SUCCESS_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-arm64" || fail "successful reinstall did not replace linux arm64 speedtester"
grep -q '^new-relaydock-speedtester-windows-amd64.exe$' "$SUCCESS_ROOT/lib/speedtester-assets/relaydock-speedtester-windows-amd64.exe" || fail "successful reinstall did not replace windows amd64 speedtester"
grep -q '^new-relaydock-speedtester-windows-arm64.exe$' "$SUCCESS_ROOT/lib/speedtester-assets/relaydock-speedtester-windows-arm64.exe" || fail "successful reinstall did not replace windows arm64 speedtester"
grep -q '^v-test$' "$SUCCESS_ROOT/data/.version" || fail "successful reinstall did not replace version file"
[ "$(cat "$SUCCESS_ROOT/state/enabled")" = enabled ] || fail "successful reinstall is not enabled"
[ "$(cat "$SUCCESS_ROOT/state/active")" = active ] || fail "successful reinstall is not active"
[ -s "$SUCCESS_ROOT/verify.log" ] || fail "successful reinstall did not verify staged unit"
grep -q '^Environment="PORT=19090"$' "$SUCCESS_ROOT/systemd/arcway.service" || fail "explicit PORT did not override the existing port"
if grep -q '^Environment="ARCWAY_AGENT_ASSET_DIR=' "$SUCCESS_ROOT/systemd/arcway.service"; then
    fail "reinstall retained the obsolete Agent asset directory setting"
fi
grep -q "^Environment=\"ARCWAY_SPEEDTESTER_ASSET_DIR=$SUCCESS_ROOT/lib/speedtester-assets\"$" "$SUCCESS_ROOT/systemd/arcway.service" || fail "reinstall did not preserve the speedtester asset directory"

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

# Update mode discovers legacy paths from the installed unit and its environment file.
LEGACY_UPDATE_ROOT="$TEST_ROOT/legacy-update"
make_old_installation "$LEGACY_UPDATE_ROOT" enabled active
sed -i '/^Environment="ARCWAY_GUARD_ASSET_DIR=/d' "$LEGACY_UPDATE_ROOT/systemd/arcway.service"
sed -i "s|^Environment=\"ARCWAY_SPEEDTESTER_ASSET_DIR=.*|Environment=\"ARCWAY_SPEEDTESTER_ASSET_DIR=$LEGACY_UPDATE_ROOT/lib/ignored-speedtester-assets\"|" "$LEGACY_UPDATE_ROOT/systemd/arcway.service"
sed -i "/^\[Service\]/a EnvironmentFile=$LEGACY_UPDATE_ROOT/config/arcway.env" "$LEGACY_UPDATE_ROOT/systemd/arcway.service"
printf '%s\n' \
    "ARCWAY_GUARD_ASSET_DIR=$LEGACY_UPDATE_ROOT/lib/guard-assets" \
    "ARCWAY_AGENT_ASSET_DIR=$LEGACY_UPDATE_ROOT/lib/agent-assets" \
    "ARCWAY_SPEEDTESTER_ASSET_DIR=$LEGACY_UPDATE_ROOT/lib/speedtester-assets" \
    > "$LEGACY_UPDATE_ROOT/config/arcway.env"
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$LEGACY_UPDATE_ROOT/apt-called" \
    MOCK_VERIFY_LOG="$LEGACY_UPDATE_ROOT/verify.log" \
    MOCK_STATE_DIR="$LEGACY_UPDATE_ROOT/state" \
    ARCWAY_SYSTEMD_UNIT_DIR="$LEGACY_UPDATE_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$LEGACY_UPDATE_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" update >"$LEGACY_UPDATE_ROOT/output.log" 2>&1
grep -q '^new-arcway-linux-amd64$' "$LEGACY_UPDATE_ROOT/bin/arcway" || fail "legacy update did not preserve the binary directory"
grep -q '^new-arcway-expiry-guard-linux-amd64$' "$LEGACY_UPDATE_ROOT/lib/guard-assets/arcway-expiry-guard-linux-amd64" || fail "legacy update did not preserve the guard directory"
grep -q '^old-agent-amd64$' "$LEGACY_UPDATE_ROOT/lib/agent-assets/relaydock-agent-linux-amd64" || fail "legacy update changed the Agent cache"
grep -q '^new-relaydock-speedtester-windows-arm64.exe$' "$LEGACY_UPDATE_ROOT/lib/speedtester-assets/relaydock-speedtester-windows-arm64.exe" || fail "legacy update did not preserve the speedtester directory"
grep -q '^v-test$' "$LEGACY_UPDATE_ROOT/data/.version" || fail "legacy update did not preserve the data directory"
if grep -q '^Environment="ARCWAY_AGENT_ASSET_DIR=' "$LEGACY_UPDATE_ROOT/systemd/arcway.service"; then
    fail "legacy update retained the obsolete Agent asset directory setting"
fi
grep -q "^ARCWAY_AGENT_ASSET_DIR=$LEGACY_UPDATE_ROOT/lib/agent-assets$" "$LEGACY_UPDATE_ROOT/config/arcway.env" || fail "legacy update changed the operator EnvironmentFile"
grep -q "^Environment=\"ARCWAY_SPEEDTESTER_ASSET_DIR=$LEGACY_UPDATE_ROOT/lib/speedtester-assets\"$" "$LEGACY_UPDATE_ROOT/systemd/arcway.service" || fail "legacy update did not persist the detected speedtester directory"
[ ! -e "$LEGACY_UPDATE_ROOT/lib/ignored-speedtester-assets" ] || fail "legacy update ignored EnvironmentFile precedence"
[ "$(cat "$LEGACY_UPDATE_ROOT/state/active")" = active ] || fail "legacy update did not restart the service"
grep -q '检测到现有安装布局' "$LEGACY_UPDATE_ROOT/output.log" || fail "legacy update did not report layout detection"

# An explicit speedtester directory replaces an existing direct unit assignment.
OVERRIDE_UPDATE_ROOT="$TEST_ROOT/override-update"
OVERRIDE_SPEEDTESTER_DIR="$OVERRIDE_UPDATE_ROOT/lib/override-speedtester-assets"
make_old_installation "$OVERRIDE_UPDATE_ROOT" enabled active
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$OVERRIDE_UPDATE_ROOT/apt-called" \
    MOCK_VERIFY_LOG="$OVERRIDE_UPDATE_ROOT/verify.log" \
    MOCK_STATE_DIR="$OVERRIDE_UPDATE_ROOT/state" \
    ARCWAY_INSTALL_DIR="$OVERRIDE_UPDATE_ROOT/bin" \
    ARCWAY_DATA_DIR="$OVERRIDE_UPDATE_ROOT/data" \
    ARCWAY_CONFIG_DIR="$OVERRIDE_UPDATE_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$OVERRIDE_UPDATE_ROOT/lib/guard-assets" \
    ARCWAY_SPEEDTESTER_ASSET_DIR="$OVERRIDE_SPEEDTESTER_DIR" \
    ARCWAY_SYSTEMD_UNIT_DIR="$OVERRIDE_UPDATE_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$OVERRIDE_UPDATE_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" update >"$OVERRIDE_UPDATE_ROOT/output.log" 2>&1
grep -q '^new-relaydock-speedtester-linux-amd64$' "$OVERRIDE_SPEEDTESTER_DIR/relaydock-speedtester-linux-amd64" || fail "explicit update did not install speedtester assets in the override directory"
grep -q "^Environment=\"ARCWAY_SPEEDTESTER_ASSET_DIR=$OVERRIDE_SPEEDTESTER_DIR\"$" "$OVERRIDE_UPDATE_ROOT/systemd/arcway.service" || fail "explicit update did not replace the speedtester unit assignment"
[ "$(cat "$OVERRIDE_UPDATE_ROOT/state/active")" = active ] || fail "explicit speedtester update did not restart the service"

# An EnvironmentFile conflict must fail explicitly before download or transaction work.
CONFLICT_ROOT="$TEST_ROOT/environment-file-conflict"
CONFLICT_OVERRIDE_DIR="$CONFLICT_ROOT/lib/override-speedtester-assets"
make_old_installation "$CONFLICT_ROOT" enabled active
sed -i "/^\[Service\]/a EnvironmentFile=$CONFLICT_ROOT/config/arcway.env" "$CONFLICT_ROOT/systemd/arcway.service"
printf '%s\n' "ARCWAY_SPEEDTESTER_ASSET_DIR=$CONFLICT_ROOT/lib/speedtester-assets" > "$CONFLICT_ROOT/config/arcway.env"
set +e
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$CONFLICT_ROOT/apt-called" \
    MOCK_VERIFY_LOG="$CONFLICT_ROOT/verify.log" \
    MOCK_STATE_DIR="$CONFLICT_ROOT/state" \
    ARCWAY_INSTALL_DIR="$CONFLICT_ROOT/bin" \
    ARCWAY_DATA_DIR="$CONFLICT_ROOT/data" \
    ARCWAY_CONFIG_DIR="$CONFLICT_ROOT/config" \
    ARCWAY_GUARD_ASSET_DIR="$CONFLICT_ROOT/lib/guard-assets" \
    ARCWAY_SPEEDTESTER_ASSET_DIR="$CONFLICT_OVERRIDE_DIR" \
    ARCWAY_SYSTEMD_UNIT_DIR="$CONFLICT_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$CONFLICT_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" update >"$CONFLICT_ROOT/output.log" 2>&1
conflict_result=$?
set -e
[ "$conflict_result" -ne 0 ] || fail "conflicting EnvironmentFile speedtester directory unexpectedly succeeded"
assert_file_equals "$CONFLICT_ROOT/expected/speedtester-linux-amd64" "$CONFLICT_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-amd64"
[ ! -e "$CONFLICT_OVERRIDE_DIR" ] || fail "EnvironmentFile conflict created the override asset directory"
[ "$(cat "$CONFLICT_ROOT/state/active")" = active ] || fail "EnvironmentFile conflict stopped the service"
grep -q 'EnvironmentFile 中的 ARCWAY_SPEEDTESTER_ASSET_DIR 会覆盖目标目录' "$CONFLICT_ROOT/output.log" || fail "EnvironmentFile conflict was not explicit"
if grep -q '下载 arcway' "$CONFLICT_ROOT/output.log" || grep -q '正在恢复原状态' "$CONFLICT_ROOT/output.log"; then
    fail "EnvironmentFile conflict was not rejected before download and transaction work"
fi

# Units created before the variable existed may keep assets beside the panel binary.
ADJACENT_ROOT="$TEST_ROOT/adjacent-speedtester-assets"
make_old_installation "$ADJACENT_ROOT" enabled active
sed -i '/^Environment="ARCWAY_SPEEDTESTER_ASSET_DIR=/d' "$ADJACENT_ROOT/systemd/arcway.service"
mv "$ADJACENT_ROOT/lib/speedtester-assets" "$ADJACENT_ROOT/bin/speedtester-assets"
PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_APT_MARKER="$ADJACENT_ROOT/apt-called" \
    MOCK_VERIFY_LOG="$ADJACENT_ROOT/verify.log" \
    MOCK_STATE_DIR="$ADJACENT_ROOT/state" \
    ARCWAY_SYSTEMD_UNIT_DIR="$ADJACENT_ROOT/systemd" \
    ARCWAY_INSTALL_LOCK_FILE="$ADJACENT_ROOT/install.lock" \
    bash "$INSTALL_SCRIPT" update >"$ADJACENT_ROOT/output.log" 2>&1
grep -q '^new-relaydock-speedtester-linux-amd64$' "$ADJACENT_ROOT/bin/speedtester-assets/relaydock-speedtester-linux-amd64" || fail "update did not detect adjacent speedtester assets"
grep -q "^Environment=\"ARCWAY_SPEEDTESTER_ASSET_DIR=$ADJACENT_ROOT/bin/speedtester-assets\"$" "$ADJACENT_ROOT/systemd/arcway.service" || fail "update did not persist the adjacent speedtester directory"

# A non-interactive uninstall preserves data unless deletion is explicitly requested.
UNINSTALL_ROOT="$TEST_ROOT/uninstall-default"
make_old_installation "$UNINSTALL_ROOT" enabled active
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
[ ! -e "$UNINSTALL_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-amd64" ] || fail "uninstall did not remove linux amd64 speedtester"
[ ! -e "$UNINSTALL_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-arm64" ] || fail "uninstall did not remove linux arm64 speedtester"
[ ! -e "$UNINSTALL_ROOT/lib/speedtester-assets/relaydock-speedtester-windows-amd64.exe" ] || fail "uninstall did not remove windows amd64 speedtester"
[ ! -e "$UNINSTALL_ROOT/lib/speedtester-assets/relaydock-speedtester-windows-arm64.exe" ] || fail "uninstall did not remove windows arm64 speedtester"
[ ! -e "$UNINSTALL_ROOT/lib/speedtester-assets" ] || fail "uninstall did not remove the empty speedtester asset directory"
[ ! -e "$UNINSTALL_ROOT/systemd/arcway.service" ] || fail "uninstall did not remove the systemd unit"
grep -q '保留数据模式' "$UNINSTALL_ROOT/output.log" || fail "uninstall did not report preserved data"

# Uninstall removes only managed speedtester assets when the directory has unrelated content.
UNINSTALL_SENTINEL_ROOT="$TEST_ROOT/uninstall-sentinel"
make_old_installation "$UNINSTALL_SENTINEL_ROOT" enabled active
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
[ ! -e "$UNINSTALL_SENTINEL_ROOT/lib/speedtester-assets/relaydock-speedtester-linux-amd64" ] || fail "sentinel uninstall left managed speedtester assets"
[ -d "$UNINSTALL_SENTINEL_ROOT/lib/speedtester-assets" ] || fail "sentinel uninstall removed a non-empty speedtester directory"

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
