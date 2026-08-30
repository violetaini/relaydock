#!/usr/bin/env bash
set -euo pipefail

readonly FILTER_RULE_COMMENT="arcway-mihomo-wg-relay-input-v1"
readonly NAT_RULE_COMMENT="arcway-mihomo-wg-relay-snat-v1"
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
    [[ "$value" =~ ^[0-9]{1,5}$ ]] && ((10#$value >= 1 && 10#$value <= 65535))
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
    local value=$1 label=${2:-directory} owner
    [[ -d "$value" && ! -L "$value" ]] || fail "$label is unavailable: $value"
    owner=$(stat -c %u -- "$value") || fail "cannot inspect $label: $value"
    [[ "$owner" == "0" ]] || fail "$label must be owned by root: $value"
    if find "$value" -maxdepth 0 -perm /0022 -print -quit | grep -q .; then
        fail "$label must not be group- or world-writable: $value"
    fi
}

load_rules() {
    local source=$1 output=$2 format=$3
    local line rule_type remote_ip remote_port local_ip relay_port public_port
    local -a fields
    : >"$output"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        read -r -a fields <<<"$line"
        ((${#fields[@]} > 0)) || continue

        if [[ "$format" == "config" ]]; then
            ((${#fields[@]} == 3)) || fail "configuration lines must contain exactly three fields"
            rule_type=generic
            remote_ip=-
            remote_port=0
            local_ip=${fields[0]}
            relay_port=${fields[1]}
            public_port=${fields[2]}
        else
            case ${#fields[@]} in
                3)
                    rule_type=generic
                    remote_ip=-
                    remote_port=0
                    local_ip=${fields[0]}
                    relay_port=${fields[1]}
                    public_port=${fields[2]}
                    ;;
                5)
                    rule_type=endpoint
                    remote_ip=${fields[0]}
                    remote_port=${fields[1]}
                    local_ip=${fields[2]}
                    relay_port=${fields[3]}
                    public_port=${fields[4]}
                    ;;
                4)
                    rule_type=legacy
                    remote_ip=${fields[0]}
                    remote_port=${fields[1]}
                    local_ip=${fields[2]}
                    relay_port=${fields[3]}
                    public_port=0
                    ;;
                *)
                    fail "state lines must contain exactly three, four, or five fields"
                    ;;
            esac
        fi

        if [[ "$rule_type" != "generic" ]]; then
            valid_ipv4 "$remote_ip" || fail "invalid remote IPv4 address in state"
            valid_port "$remote_port" || fail "invalid remote UDP port in state"
            remote_port=$((10#$remote_port))
        fi
        valid_ipv4 "$local_ip" || fail "invalid local IPv4 address"
        valid_port "$relay_port" || fail "invalid local relay UDP port"
        relay_port=$((10#$relay_port))
        if [[ "$public_port" == "0" ]]; then
            [[ "$format" == "state" && "$rule_type" != "generic" ]] || fail "invalid public source UDP port"
            rule_type=legacy
        else
            valid_port "$public_port" || fail "invalid public source UDP port"
            public_port=$((10#$public_port))
            ((relay_port != public_port)) || fail "local relay and public source UDP ports must differ"
        fi
        printf '%s %s %s %s %s %s\n' \
            "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port" >>"$output"
    done <"$source"
    [[ -s "$output" ]] || fail "$format does not contain any WireGuard relay rules"
    if awk '{ if ($1 == "generic") print $1, $4, $5; else print $1, $2, $3, $4, $5 }' "$output" \
        | sort | uniq -d | grep -q .; then
        fail "$format contains duplicate WireGuard relay rule tuples"
    fi
}

write_state_rules() {
    local source=$1 destination=$2
    local rule_type remote_ip remote_port local_ip relay_port public_port
    while read -r rule_type remote_ip remote_port local_ip relay_port public_port; do
        case "$rule_type" in
            generic)
                printf '%s %s %s\n' "$local_ip" "$relay_port" "$public_port"
                ;;
            endpoint)
                printf '%s %s %s %s %s\n' \
                    "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port"
                ;;
            legacy)
                printf '%s %s %s %s\n' "$remote_ip" "$remote_port" "$local_ip" "$relay_port"
                ;;
            *)
                fail "unknown normalized rule type: $rule_type"
                ;;
        esac
    done <"$source" >"$destination"
}

filter_rule() {
    local operation=$1 rule_type=$2 remote_ip=$3 remote_port=$4 local_ip=$5 relay_port=$6 public_port=$7
    shift 7
    case "$rule_type" in
        generic)
            iptables -w 10 "$operation" INPUT "$@" \
                -p udp -d "$local_ip" --dport "$relay_port" \
                -m conntrack --ctstate ESTABLISHED \
                -m comment --comment "$FILTER_RULE_COMMENT" -j ACCEPT
            ;;
        endpoint)
            iptables -w 10 "$operation" INPUT "$@" \
                -p udp -s "$remote_ip" --sport "$remote_port" -d "$local_ip" --dport "$relay_port" \
                -m conntrack --ctstate ESTABLISHED \
                -m comment --comment "$FILTER_RULE_COMMENT" -j ACCEPT
            ;;
        legacy)
            iptables -w 10 "$operation" INPUT "$@" \
                -p udp -s "$remote_ip" --sport "$remote_port" -d "$local_ip" --dport "$relay_port" \
                -m comment --comment "$FILTER_RULE_COMMENT" -j ACCEPT
            ;;
        *)
            fail "unknown filter rule type: $rule_type"
            ;;
    esac
}

nat_rule() {
    local operation=$1 rule_type=$2 remote_ip=$3 remote_port=$4 local_ip=$5 relay_port=$6 public_port=$7
    shift 7
    case "$rule_type" in
        generic)
            iptables -w 10 -t nat "$operation" POSTROUTING "$@" \
                -p udp -s "$local_ip" --sport "$relay_port" \
                -m comment --comment "$NAT_RULE_COMMENT" \
                -j SNAT --to-source "$local_ip:$public_port"
            ;;
        endpoint)
            iptables -w 10 -t nat "$operation" POSTROUTING "$@" \
                -p udp -s "$local_ip" --sport "$relay_port" -d "$remote_ip" --dport "$remote_port" \
                -m comment --comment "$NAT_RULE_COMMENT" \
                -j SNAT --to-source "$local_ip:$public_port"
            ;;
        *)
            fail "unknown NAT rule type: $rule_type"
            ;;
    esac
}

run_rule() {
    local kind=$1
    shift
    case "$kind" in
        filter) filter_rule "$@" ;;
        nat) nat_rule "$@" ;;
        *) fail "unknown rule kind: $kind" ;;
    esac
}

rule_exists() {
    local kind=$1 rule_type=$2 remote_ip=$3 remote_port=$4 local_ip=$5 relay_port=$6 public_port=$7 result
    set +e
    run_rule "$kind" -C "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port" >/dev/null
    result=$?
    set -e
    case "$result" in
        0) return 0 ;;
        1) return 1 ;;
        *) fail "iptables failed while checking the $kind $rule_type rule via $local_ip:$relay_port" ;;
    esac
}

insert_rule() {
    local kind=$1
    shift
    run_rule "$kind" -I "$@" 1
}

delete_rule() {
    local kind=$1
    shift
    run_rule "$kind" -D "$@"
}

[[ "$action" == "apply" || "$action" == "remove" || "$action" == "status" ]] || usage
[[ "$(id -u)" == "0" ]] || fail "this command must run as root"
command -v iptables >/dev/null || fail "iptables is required"
command -v flock >/dev/null || fail "flock is required"
validate_path "$config_path" "configuration path"
validate_path "$state_path" "state path"

state_dir=$(dirname "$state_path")
validate_secure_directory "$state_dir" "state directory"
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
    local source=$1 label=$2 format=$3 output
    validate_secure_directory "$(dirname "$source")" "$label directory"
    validate_secure_file "$source" "$label"
    output=$(mktemp "$state_dir/.rules.XXXXXXXX")
    chmod 0600 "$output"
    temporary_files+=("$output")
    load_rules "$source" "$output" "$format"
    normalized_rules_file=$output
}

config_rules=""
state_rules=""
rules_file=""
normalized_rules_file=""

case "$action" in
    apply)
        normalize_rules_file "$config_path" "configuration" config
        config_rules=$normalized_rules_file
        rules_file=$config_rules
        if [[ -e "$state_path" || -L "$state_path" ]]; then
            normalize_rules_file "$state_path" "state file" state
            state_rules=$normalized_rules_file
            cmp -s "$config_rules" "$state_rules" || fail "active rules differ; remove them before applying a new configuration"
        fi
        ;;
    remove|status)
        if [[ -e "$state_path" || -L "$state_path" ]]; then
            normalize_rules_file "$state_path" "state file" state
            state_rules=$normalized_rules_file
            rules_file=$state_rules
        else
            normalize_rules_file "$config_path" "configuration" config
            config_rules=$normalized_rules_file
            rules_file=$config_rules
        fi
        ;;
esac

case "$action" in
    apply)
        added_rules=()
        apply_complete=0
        state_was_present=0
        [[ -e "$state_path" || -L "$state_path" ]] && state_was_present=1
        rollback_apply() {
            local index kind rule_type remote_ip remote_port local_ip relay_port public_port
            for ((index=${#added_rules[@]}-1; index>=0; index--)); do
                read -r kind rule_type remote_ip remote_port local_ip relay_port public_port <<<"${added_rules[index]}"
                delete_rule "$kind" "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port" \
                    >/dev/null 2>&1 || echo "WARNING: failed to roll back rule: ${added_rules[index]}" >&2
            done
            if ((state_was_present == 0)) && [[ -e "$state_path" || -L "$state_path" ]]; then
                if [[ -f "$state_path" && ! -L "$state_path" ]]; then
                    rm -f -- "$state_path" || echo "WARNING: failed to roll back state file: $state_path" >&2
                else
                    echo "WARNING: refusing to remove unsafe state path during rollback: $state_path" >&2
                fi
            fi
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

        while read -r rule_type remote_ip remote_port local_ip relay_port public_port; do
            for kind in nat filter; do
                if ! rule_exists "$kind" "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port"; then
                    insert_rule "$kind" "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port"
                    added_rules+=("$kind $rule_type $remote_ip $remote_port $local_ip $relay_port $public_port")
                fi
            done
        done <"$rules_file"

        if ((state_was_present == 0)); then
            state_tmp=$(mktemp "$state_path.XXXXXXXX")
            temporary_files+=("$state_tmp")
            chmod 0600 "$state_tmp"
            write_state_rules "$rules_file" "$state_tmp"
            mv -f -- "$state_tmp" "$state_path"
        fi
        apply_complete=1
        ;;
    remove)
        removed_rules=()
        remove_complete=0
        state_was_present=0
        [[ -e "$state_path" || -L "$state_path" ]] && state_was_present=1
        rollback_remove() {
            local index kind rule_type remote_ip remote_port local_ip relay_port public_port restore_tmp
            for ((index=${#removed_rules[@]}-1; index>=0; index--)); do
                read -r kind rule_type remote_ip remote_port local_ip relay_port public_port <<<"${removed_rules[index]}"
                insert_rule "$kind" "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port" \
                    >/dev/null 2>&1 || echo "WARNING: failed to restore rule: ${removed_rules[index]}" >&2
            done
            if ((state_was_present == 1)) && [[ ! -e "$state_path" && ! -L "$state_path" ]]; then
                restore_tmp=$(mktemp "$state_path.rollback.XXXXXXXX") || {
                    echo "WARNING: failed to create rollback state file: $state_path" >&2
                    return
                }
                chmod 0600 "$restore_tmp"
                if write_state_rules "$rules_file" "$restore_tmp" && mv -f -- "$restore_tmp" "$state_path"; then
                    :
                else
                    rm -f -- "$restore_tmp"
                    echo "WARNING: failed to restore state file: $state_path" >&2
                fi
            fi
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

        while read -r rule_type remote_ip remote_port local_ip relay_port public_port; do
            for kind in filter nat; do
                [[ "$kind" != "nat" || "$rule_type" != "legacy" ]] || continue
                while rule_exists "$kind" "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port"; do
                    delete_rule "$kind" "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port"
                    removed_rules+=("$kind $rule_type $remote_ip $remote_port $local_ip $relay_port $public_port")
                done
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
        while read -r rule_type remote_ip remote_port local_ip relay_port public_port; do
            for kind in filter nat; do
                [[ "$kind" != "nat" || "$rule_type" != "legacy" ]] || continue
                if ! rule_exists "$kind" "$rule_type" "$remote_ip" "$remote_port" "$local_ip" "$relay_port" "$public_port"; then
                    echo "Missing $kind $rule_type rule via $local_ip:$relay_port" >&2
                    missing=1
                fi
            done
        done <"$rules_file"
        ((missing == 0)) || fail "one or more WireGuard relay firewall rules are missing"
        ;;
esac
