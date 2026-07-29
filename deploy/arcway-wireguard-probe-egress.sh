#!/usr/bin/env bash
set -euo pipefail

readonly RULE_COMMENT="arcway-mihomo-wg-relay-input-v1"
readonly DEFAULT_CONFIG="/etc/arcway/wireguard-probe-egress.conf"
readonly DEFAULT_STATE="/run/arcway-wireguard-probe-egress/rules.conf"

action="${1:-}"
config_path="${2:-$DEFAULT_CONFIG}"
state_path="${3:-$DEFAULT_STATE}"

usage() {
    echo "Usage: $0 {apply|remove|status} [CONFIG_PATH] [STATE_PATH]" >&2
    exit 2
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

valid_ipv4() {
    local value=$1 first second third fourth extra octet
    IFS=. read -r first second third fourth extra <<<"$value"
    [[ -z "${extra:-}" && -n "$first" && -n "$second" && -n "$third" && -n "$fourth" ]] || return 1
    for octet in "$first" "$second" "$third" "$fourth"; do
        [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
}

valid_port() {
    local value=$1
    [[ "$value" =~ ^[0-9]+$ ]] && ((10#$value >= 1 && 10#$value <= 65535))
}

validate_path() {
    local value=$1 label=$2
    [[ "$value" == /* && "$value" != *"/../"* && "$value" != */.. && "$value" != *"/./"* && "$value" != */. ]] || {
        fail "$label must be an absolute normalized path"
    }
}

validate_secure_file() {
    local value=$1 label=$2 owner
    [[ -f "$value" && ! -L "$value" ]] || fail "$label is not a regular file: $value"
    owner=$(stat -c %u -- "$value") || fail "cannot inspect $label: $value"
    [[ "$owner" == "0" ]] || fail "$label must be owned by root: $value"
    if find "$value" -maxdepth 0 -perm /0022 -print -quit | grep -q .; then
        fail "$label must not be group- or world-writable: $value"
    fi
}

validate_secure_directory() {
    local value=$1 owner
    [[ -d "$value" && ! -L "$value" ]] || fail "state directory is unavailable: $value"
    owner=$(stat -c %u -- "$value") || fail "cannot inspect state directory: $value"
    [[ "$owner" == "0" ]] || fail "state directory must be owned by root: $value"
    if find "$value" -maxdepth 0 -perm /0022 -print -quit | grep -q .; then
        fail "state directory must not be group- or world-writable: $value"
    fi
}

load_rules() {
    local source=$1 output=$2 line remote_ip remote_port local_ip local_port extra
    : >"$output"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        read -r remote_ip remote_port local_ip local_port extra <<<"$line"
        [[ -n "${remote_ip:-}" ]] || continue
        [[ -z "${extra:-}" ]] || fail "configuration lines must contain exactly four fields"
        valid_ipv4 "$remote_ip" || fail "invalid remote IPv4 address in configuration"
        valid_port "$remote_port" || fail "invalid remote UDP port in configuration"
        valid_ipv4 "$local_ip" || fail "invalid local IPv4 address in configuration"
        valid_port "$local_port" || fail "invalid local UDP port in configuration"
        printf '%s %s %s %s\n' "$remote_ip" "$remote_port" "$local_ip" "$local_port" >>"$output"
    done <"$source"
    [[ -s "$output" ]] || fail "configuration does not contain any WireGuard relay endpoints"
    if [[ "$(sort "$output" | uniq -d | wc -l)" != "0" ]]; then
        fail "configuration contains duplicate WireGuard relay endpoints"
    fi
}

filter_rule() {
    local operation=$1 remote_ip=$2 remote_port=$3 local_ip=$4 local_port=$5
    shift 5
    iptables -w 10 "$operation" INPUT "$@" \
        -p udp -s "$remote_ip" --sport "$remote_port" -d "$local_ip" --dport "$local_port" \
        -m comment --comment "$RULE_COMMENT" -j ACCEPT
}

rule_exists() {
    local remote_ip=$1 remote_port=$2 local_ip=$3 local_port=$4 result
    set +e
    filter_rule -C "$remote_ip" "$remote_port" "$local_ip" "$local_port" >/dev/null
    result=$?
    set -e
    case "$result" in
        0) return 0 ;;
        1) return 1 ;;
        *) fail "iptables failed while checking the rule for $remote_ip:$remote_port -> $local_ip:$local_port" ;;
    esac
}

[[ "$action" == "apply" || "$action" == "remove" || "$action" == "status" ]] || usage
[[ "$(id -u)" == "0" ]] || fail "this command must run as root"
command -v iptables >/dev/null || fail "iptables is required"
command -v flock >/dev/null || fail "flock is required"
validate_path "$config_path" "configuration path"
validate_path "$state_path" "state path"

state_dir=$(dirname "$state_path")
validate_secure_directory "$state_dir"
lock_path="$state_dir/.lock"
if [[ -e "$lock_path" || -L "$lock_path" ]]; then
    validate_secure_file "$lock_path" "lock file"
else
    : >"$lock_path"
    chmod 0600 "$lock_path"
fi
exec {lock_fd}>"$lock_path"
flock -w 30 "$lock_fd" || fail "timed out waiting for the WireGuard relay rule lock"

temporary_files=()
cleanup() {
    local path
    for path in "${temporary_files[@]}"; do
        [[ -z "$path" ]] || rm -f -- "$path"
    done
}
trap cleanup EXIT

normalize_rules_file() {
    local source=$1 label=$2 output
    validate_secure_file "$source" "$label"
    output=$(mktemp "$state_dir/.rules.XXXXXXXX")
    chmod 0600 "$output"
    temporary_files+=("$output")
    load_rules "$source" "$output"
    normalized_rules_file=$output
}

config_rules=""
state_rules=""
rules_file=""
normalized_rules_file=""

case "$action" in
    apply)
        normalize_rules_file "$config_path" "configuration"
        config_rules=$normalized_rules_file
        rules_file=$config_rules
        if [[ -e "$state_path" || -L "$state_path" ]]; then
            normalize_rules_file "$state_path" "state file"
            state_rules=$normalized_rules_file
            cmp -s "$config_rules" "$state_rules" || fail "active rules differ; remove them before applying a new configuration"
        fi
        ;;
    remove|status)
        if [[ -e "$state_path" || -L "$state_path" ]]; then
            normalize_rules_file "$state_path" "state file"
            state_rules=$normalized_rules_file
            rules_file=$state_rules
        else
            normalize_rules_file "$config_path" "configuration"
            config_rules=$normalized_rules_file
            rules_file=$config_rules
        fi
        ;;
esac

case "$action" in
    apply)
        added_rules=()
        apply_complete=0
        rollback_apply() {
            local index
            local -a tuple
            for ((index=${#added_rules[@]}-1; index>=0; index--)); do
                read -r -a tuple <<<"${added_rules[index]}"
                filter_rule -D "${tuple[@]}" >/dev/null 2>&1 || {
                    echo "WARNING: failed to roll back rule: ${added_rules[index]}" >&2
                }
            done
        }
        cleanup_apply() {
            local result=$1
            trap - EXIT INT TERM
            ((apply_complete == 1)) || rollback_apply
            cleanup
            exit "$result"
        }
        trap 'cleanup_apply $?' EXIT
        trap 'exit 130' INT TERM

        while read -r remote_ip remote_port local_ip local_port; do
            if ! rule_exists "$remote_ip" "$remote_port" "$local_ip" "$local_port"; then
                filter_rule -I "$remote_ip" "$remote_port" "$local_ip" "$local_port" 1
                added_rules+=("$remote_ip $remote_port $local_ip $local_port")
            fi
        done <"$rules_file"

        state_tmp=$(mktemp "$state_path.XXXXXXXX")
        temporary_files+=("$state_tmp")
        chmod 0600 "$state_tmp"
        cp -- "$rules_file" "$state_tmp"
        mv -f -- "$state_tmp" "$state_path"
        apply_complete=1
        ;;
    remove)
        removed_rules=()
        remove_complete=0
        rollback_remove() {
            local index
            local -a tuple
            for ((index=${#removed_rules[@]}-1; index>=0; index--)); do
                read -r -a tuple <<<"${removed_rules[index]}"
                filter_rule -I "${tuple[@]}" 1 >/dev/null 2>&1 || {
                    echo "WARNING: failed to restore rule: ${removed_rules[index]}" >&2
                }
            done
        }
        cleanup_remove() {
            local result=$1
            trap - EXIT INT TERM
            ((remove_complete == 1)) || rollback_remove
            cleanup
            exit "$result"
        }
        trap 'cleanup_remove $?' EXIT
        trap 'exit 130' INT TERM

        while read -r remote_ip remote_port local_ip local_port; do
            while rule_exists "$remote_ip" "$remote_port" "$local_ip" "$local_port"; do
                filter_rule -D "$remote_ip" "$remote_port" "$local_ip" "$local_port"
                removed_rules+=("$remote_ip $remote_port $local_ip $local_port")
            done
        done <"$rules_file"
        if [[ -e "$state_path" || -L "$state_path" ]]; then
            [[ -f "$state_path" && ! -L "$state_path" ]] || fail "state path is unsafe: $state_path"
            rm -f -- "$state_path"
        fi
        remove_complete=1
        ;;
    status)
        missing=0
        while read -r remote_ip remote_port local_ip local_port; do
            if ! rule_exists "$remote_ip" "$remote_port" "$local_ip" "$local_port"; then
                echo "Missing rule: $remote_ip:$remote_port -> $local_ip:$local_port" >&2
                missing=1
            fi
        done <"$rules_file"
        ((missing == 0)) || fail "one or more WireGuard relay input rules are missing"
        ;;
esac
