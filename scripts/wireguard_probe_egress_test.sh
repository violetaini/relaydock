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
table=filter
if [[ "${1:-}" == "-t" ]]; then
    table=${2:?}
    shift 2
fi
operation=${1:?}
chain=${2:?}
shift 2
if [[ "$operation" == "-I" && "${1:-}" =~ ^[0-9]+$ ]]; then
    shift
fi
key=$(printf '%q ' "$@")
identity="$table $chain $key"
state="$state_dir/$table-$chain"
touch "$state"
printf '%s %s %s\n' "$operation" "$table" "$chain $key" >>"$state_dir/invocations"

matches_failure() {
    local configured=$1
    [[ -n "$configured" && "$identity" == *"$configured"* ]]
}

case "$operation" in
    -C)
        matches_failure "${MOCK_IPTABLES_FAIL_CHECK_MATCH:-}" && exit 2
        grep -Fxq -- "$key" "$state"
        ;;
    -I)
        matches_failure "${MOCK_IPTABLES_FAIL_INSERT_MATCH:-}" && exit 2
        if [[ "${MOCK_IPTABLES_INSERT_DELAY:-0}" != "0" ]]; then
            sleep "$MOCK_IPTABLES_INSERT_DELAY"
        fi
        printf '%s\n' "$key" >>"$state"
        ;;
    -D)
        matches_failure "${MOCK_IPTABLES_FAIL_DELETE_MATCH:-}" && exit 2
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
# endpoint, local relay socket, and externally visible source port
154.19.43.82 51821 23.145.248.44 39443 443
EOF
    chmod 0600 "$config"
}

write_two_rules() {
    cat >"$config" <<'EOF'
154.19.43.82 51821 23.145.248.44 39443 443
154.19.43.83 51822 23.145.248.44 39443 443
EOF
    chmod 0600 "$config"
}

run_script() {
    env PATH="$mock_bin:/usr/bin:/bin" \
        MOCK_IPTABLES_STATE="$mock_state" \
        MOCK_IPTABLES_FAIL_CHECK_MATCH="${MOCK_IPTABLES_FAIL_CHECK_MATCH:-}" \
        MOCK_IPTABLES_FAIL_INSERT_MATCH="${MOCK_IPTABLES_FAIL_INSERT_MATCH:-}" \
        MOCK_IPTABLES_FAIL_DELETE_MATCH="${MOCK_IPTABLES_FAIL_DELETE_MATCH:-}" \
        MOCK_IPTABLES_INSERT_DELAY="${MOCK_IPTABLES_INSERT_DELAY:-0}" \
        bash "$script" "$@" "$config" "$runtime_state"
}

iptables_mock() {
    env MOCK_IPTABLES_STATE="$mock_state" "$mock_bin/iptables" "$@"
}

rule_count() {
    local table=$1 chain=$2 file
    file="$mock_state/$table-$chain"
    [[ -f "$file" ]] || { echo 0; return; }
    awk 'NF { count++ } END { print count + 0 }' "$file"
}

assert_rule_counts() {
    local filter_want=$1 nat_want=$2 label=$3
    [[ "$(rule_count filter INPUT)" == "$filter_want" ]] || fail "$label: unexpected INPUT rule count"
    [[ "$(rule_count nat POSTROUTING)" == "$nat_want" ]] || fail "$label: unexpected SNAT rule count"
}

write_one_rule
run_script apply
assert_rule_counts 1 1 "initial apply"
[[ -s "$runtime_state" ]] || fail "apply did not write runtime state"
grep -Fxq '154.19.43.82 51821 23.145.248.44 39443 443' "$runtime_state" || {
    fail "runtime state did not preserve separate relay and public ports"
}
grep -Fq -- '-s 154.19.43.82 --sport 51821 -d 23.145.248.44 --dport 39443 -m conntrack --ctstate ESTABLISHED' \
    "$mock_state/filter-INPUT" || fail "INPUT rule is not limited to the restored endpoint tuple"
grep -Fq -- '-s 23.145.248.44 --sport 39443 -d 154.19.43.82 --dport 51821' \
    "$mock_state/nat-POSTROUTING" || fail "SNAT rule is not limited to the relay endpoint tuple"
grep -Fq -- '-j SNAT --to-source 23.145.248.44:443' "$mock_state/nat-POSTROUTING" || {
    fail "SNAT rule does not publish UDP 443"
}
if grep -Eq -- 'PREROUTING|DNAT|--dport 443' "$mock_state/filter-INPUT"; then
    fail "INPUT rule exposed the public UDP port instead of the local relay port"
fi

run_script apply
assert_rule_counts 1 1 "repeated apply"
run_script status

: >"$mock_state/nat-POSTROUTING"
run_script apply
assert_rule_counts 1 1 "missing SNAT repair"
: >"$mock_state/filter-INPUT"
run_script apply
assert_rule_counts 1 1 "missing INPUT repair"

cat >"$config" <<'EOF'
154.19.43.83 51822 23.145.248.44 39443 443
EOF
chmod 0600 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted a changed configuration while old rules were active"
fi
assert_rule_counts 1 1 "rejected config replacement"
run_script remove
assert_rule_counts 0 0 "remove"
[[ ! -e "$runtime_state" ]] || fail "remove left runtime state behind"
run_script remove

write_two_rules
if MOCK_IPTABLES_FAIL_INSERT_MATCH='--sport 51822' run_script apply >/dev/null 2>&1; then
    fail "apply ignored an INPUT insertion failure"
fi
assert_rule_counts 0 0 "INPUT insertion rollback"
[[ ! -e "$runtime_state" ]] || fail "failed apply wrote runtime state"

if MOCK_IPTABLES_FAIL_INSERT_MATCH='--dport 51822' run_script apply >/dev/null 2>&1; then
    fail "apply ignored a SNAT insertion failure"
fi
assert_rule_counts 0 0 "SNAT insertion rollback"

if MOCK_IPTABLES_FAIL_CHECK_MATCH='nat POSTROUTING' run_script apply >/dev/null 2>&1; then
    fail "apply treated an iptables check error as a missing rule"
fi
assert_rule_counts 0 0 "check failure"

run_script apply
assert_rule_counts 2 2 "two-rule apply"
if MOCK_IPTABLES_FAIL_CHECK_MATCH='filter INPUT' run_script remove >/dev/null 2>&1; then
    fail "remove treated an iptables check error as a missing rule"
fi
assert_rule_counts 2 2 "remove check failure"
[[ -s "$runtime_state" ]] || fail "check failure deleted runtime state"

if MOCK_IPTABLES_FAIL_DELETE_MATCH='--dport 51822' run_script remove >/dev/null 2>&1; then
    fail "remove ignored a SNAT deletion failure"
fi
assert_rule_counts 2 2 "SNAT deletion rollback"
[[ -s "$runtime_state" ]] || fail "failed remove deleted runtime state"

if MOCK_IPTABLES_FAIL_DELETE_MATCH='--sport 51822' run_script remove >/dev/null 2>&1; then
    fail "remove ignored an INPUT deletion failure"
fi
assert_rule_counts 2 2 "INPUT deletion rollback"
run_script status
run_script remove

write_one_rule
MOCK_IPTABLES_INSERT_DELAY=0.2 run_script apply &
first_pid=$!
MOCK_IPTABLES_INSERT_DELAY=0.2 run_script apply &
second_pid=$!
wait "$first_pid" || fail "first concurrent apply failed"
wait "$second_pid" || fail "second concurrent apply failed"
assert_rule_counts 1 1 "concurrent apply"
run_script remove

write_one_rule
run_script apply
: >"$mock_state/nat-POSTROUTING"
if run_script status >/dev/null 2>&1; then
    fail "status accepted a missing SNAT rule"
fi
run_script remove

write_one_rule
run_script apply
: >"$mock_state/filter-INPUT"
if run_script status >/dev/null 2>&1; then
    fail "status accepted a missing INPUT rule"
fi
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
999.19.43.82 51821 23.145.248.44 39443 443
EOF
chmod 0600 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted an invalid IPv4 address"
fi

cat >"$config" <<'EOF'
154.19.43.82 51821 23.145.248.44 443 443
EOF
chmod 0600 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted identical relay and public ports"
fi

cat >"$config" <<'EOF'
154.19.43.82 51821 23.145.248.44 39443 0
EOF
chmod 0600 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted public source port zero"
fi

cat >"$config" <<'EOF'
154.19.43.82 51821 23.145.248.44 39443 443
154.19.43.82 51821 23.145.248.44 39443 444
EOF
chmod 0600 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted conflicting SNAT targets for one endpoint tuple"
fi

cat >"$config" <<'EOF'
154.19.43.82 51821 23.145.248.44 443
EOF
chmod 0600 "$config"
if run_script apply >/dev/null 2>&1; then
    fail "apply accepted legacy four-field configuration"
fi

# Upgrade cleanup accepts the previous four-field state and removes its exact
# filter rule without fabricating a NAT rule.
cp -- "$config" "$runtime_state"
chmod 0600 "$runtime_state"
iptables_mock -w 10 -I INPUT 1 \
    -p udp -s 154.19.43.82 --sport 51821 -d 23.145.248.44 --dport 443 \
    -m comment --comment arcway-mihomo-wg-relay-input-v1 -j ACCEPT
assert_rule_counts 1 0 "legacy setup"
run_script status
run_script remove
assert_rule_counts 0 0 "legacy removal"

echo "wireguard relay egress rule tests passed"
