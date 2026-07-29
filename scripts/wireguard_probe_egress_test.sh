#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
script="$repo_root/deploy/arcway-wireguard-probe-egress.sh"
test_root=$(mktemp -d)

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ "$(id -u)" == "0" ]] || fail "this test must run as root"

mock_bin="$test_root/bin"
mock_state="$test_root/iptables-state"
mkdir -p "$mock_bin" "$mock_state" "$test_root/runtime"

cat >"$mock_bin/iptables" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

state_dir=${MOCK_IPTABLES_STATE:?}
[[ "${1:-}" == "-w" && "${2:-}" == "10" ]] || exit 2
shift 2
[[ "${1:-}" != "-t" ]] || exit 2
operation=${1:?}
chain=${2:?}
shift 2
if [[ "$operation" == "-I" && "${1:-}" =~ ^[0-9]+$ ]]; then
    shift
fi
key=$(printf '%q ' "$@")
state="$state_dir/filter-$chain"
touch "$state"
printf '%s\n' "$operation $chain $key" >>"$state_dir/invocations"

case "$operation" in
    -C)
        [[ "${MOCK_IPTABLES_CHECK_ERROR:-0}" != "1" ]] || exit 2
        grep -Fxq -- "$key" "$state"
        ;;
    -I)
        if [[ -n "${MOCK_IPTABLES_FAIL_INSERT_MATCH:-}" && "$key" == *"$MOCK_IPTABLES_FAIL_INSERT_MATCH"* ]]; then
            exit 2
        fi
        if [[ "${MOCK_IPTABLES_INSERT_DELAY:-0}" != "0" ]]; then
            sleep "$MOCK_IPTABLES_INSERT_DELAY"
        fi
        printf '%s\n' "$key" >>"$state"
        ;;
    -D)
        if [[ -n "${MOCK_IPTABLES_FAIL_DELETE_MATCH:-}" && "$key" == *"$MOCK_IPTABLES_FAIL_DELETE_MATCH"* ]]; then
            exit 2
        fi
        next="$state.next.$$"
        awk -v target="$key" 'BEGIN { removed = 0 } !removed && $0 == target { removed = 1; next } { print }' "$state" >"$next"
        if ! grep -Fxq -- "$key" "$state"; then
            rm -f -- "$next"
            exit 1
        fi
        mv "$next" "$state"
        ;;
    *)
        exit 2
        ;;
esac
MOCK
chmod 0755 "$mock_bin/iptables"

config="$test_root/wireguard-probe-egress.conf"
runtime_state="$test_root/runtime/rules.conf"

write_one_rule() {
    cat >"$config" <<'EOF'
# remote WireGuard endpoint and local relay destination
154.19.43.82 51821 23.145.248.44 443
EOF
    chmod 0600 "$config"
}

write_two_rules() {
    cat >"$config" <<'EOF'
154.19.43.82 51821 23.145.248.44 443
154.19.43.83 51822 23.145.248.44 443
EOF
    chmod 0600 "$config"
}

run_script() {
    env PATH="$mock_bin:/usr/bin:/bin" \
        MOCK_IPTABLES_STATE="$mock_state" \
        MOCK_IPTABLES_CHECK_ERROR="${MOCK_IPTABLES_CHECK_ERROR:-0}" \
        MOCK_IPTABLES_FAIL_INSERT_MATCH="${MOCK_IPTABLES_FAIL_INSERT_MATCH:-}" \
        MOCK_IPTABLES_FAIL_DELETE_MATCH="${MOCK_IPTABLES_FAIL_DELETE_MATCH:-}" \
        MOCK_IPTABLES_INSERT_DELAY="${MOCK_IPTABLES_INSERT_DELAY:-0}" \
        bash "$script" "$@" "$config" "$runtime_state"
}

rule_count() {
    local file="$mock_state/filter-INPUT"
    [[ -f "$file" ]] || { echo 0; return; }
    awk 'NF { count++ } END { print count + 0 }' "$file"
}

clear_mock_rules() {
    : >"$mock_state/filter-INPUT"
    : >"$mock_state/invocations"
}

write_one_rule
run_script apply
[[ "$(rule_count)" == "1" ]] || fail "apply did not create one INPUT rule"
[[ -s "$runtime_state" ]] || fail "apply did not write runtime state"
grep -Fq -- '--sport 51821 -d 23.145.248.44 --dport 443' "$mock_state/filter-INPUT" || {
    fail "apply did not create the exact source and destination tuple"
}
if grep -Fq -- '-t nat' "$mock_state/invocations"; then
    fail "apply invoked the NAT table"
fi

run_script apply
[[ "$(rule_count)" == "1" ]] || fail "repeated apply duplicated the INPUT rule"
run_script status

cat >"$config" <<'EOF'
154.19.43.83 51822 23.145.248.44 443
EOF
chmod 0600 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted a changed configuration while old rules were active"
fi
run_script remove
[[ "$(rule_count)" == "0" ]] || fail "remove left the INPUT rule behind"
[[ ! -e "$runtime_state" ]] || fail "remove left runtime state behind"
run_script remove

write_two_rules
if MOCK_IPTABLES_FAIL_INSERT_MATCH=154.19.43.83 run_script apply >/dev/null 2>&1; then
    fail "apply ignored an INPUT insertion failure"
fi
[[ "$(rule_count)" == "0" ]] || fail "failed apply did not roll back its INPUT rule"
[[ ! -e "$runtime_state" ]] || fail "failed apply wrote runtime state"

if MOCK_IPTABLES_CHECK_ERROR=1 run_script apply >/dev/null 2>&1; then
    fail "apply treated an iptables check error as a missing rule"
fi
[[ "$(rule_count)" == "0" ]] || fail "check error created a rule"

run_script apply
if MOCK_IPTABLES_CHECK_ERROR=1 run_script remove >/dev/null 2>&1; then
    fail "remove treated an iptables check error as a missing rule"
fi
[[ "$(rule_count)" == "2" ]] || fail "check error changed rules during remove"
[[ -s "$runtime_state" ]] || fail "check error deleted runtime state during remove"
if MOCK_IPTABLES_FAIL_DELETE_MATCH=154.19.43.83 run_script remove >/dev/null 2>&1; then
    fail "remove ignored an INPUT deletion failure"
fi
[[ "$(rule_count)" == "2" ]] || fail "failed remove did not restore previously deleted rules"
[[ -s "$runtime_state" ]] || fail "failed remove deleted runtime state"
if MOCK_IPTABLES_CHECK_ERROR=1 run_script status >/dev/null 2>&1; then
    fail "status treated an iptables check error as a missing rule"
fi
run_script remove

write_one_rule
MOCK_IPTABLES_INSERT_DELAY=0.2 run_script apply &
first_pid=$!
MOCK_IPTABLES_INSERT_DELAY=0.2 run_script apply &
second_pid=$!
wait "$first_pid" || fail "first concurrent apply failed"
wait "$second_pid" || fail "second concurrent apply failed"
[[ "$(rule_count)" == "1" ]] || fail "concurrent apply duplicated the INPUT rule"
run_script remove

write_one_rule
chmod 0666 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted a group- or world-writable configuration"
fi
chmod 0600 "$config"
chown 65534 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted a configuration not owned by root"
fi
chown 0 "$config"

cat >"$config" <<'EOF'
999.19.43.82 51821 23.145.248.44 443
EOF
chmod 0600 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted an invalid IPv4 address"
fi

write_one_rule
run_script apply
clear_mock_rules
if run_script status >/dev/null 2>&1; then
    fail "status accepted a missing INPUT rule"
fi
run_script remove

echo "wireguard relay input rule tests passed"
