#!/usr/bin/env bash
# demo_net.sh — set up / tear down virtual network for the firewall demo.
#
# Creates a Linux bridge `br-rlfw` (10.10.10.1/24) in the default namespace
# and 3 network namespaces representing distinct hosts:
#
#     attacker1   ns ip 10.10.10.20  (sends SQLi / XSS)
#     attacker2   ns ip 10.10.10.21  (sends cmd injection)
#     benign      ns ip 10.10.10.30  (sends valid POST /login)
#
# The target server runs in the default ns, bound to the bridge IP
# (10.10.10.1:80). All packets between any namespace and the server cross
# the bridge, so the daemon's iptables/NFQUEUE rules in the default ns
# inspect everything.
#
# Usage:
#     sudo bash demo_net.sh up
#     sudo bash demo_net.sh down
#     sudo bash demo_net.sh status
#     sudo bash demo_net.sh exec <ns> <cmd...>
set -euo pipefail

BRIDGE="br-rlfw"
BR_IP="10.10.10.1"
PREFIX="24"

# name | host_veth | ns_veth | ns_ip
HOSTS=(
    "attacker1|veth-h-a1|veth-n-a1|10.10.10.20"
    "attacker2|veth-h-a2|veth-n-a2|10.10.10.21"
    "benign|veth-h-bn|veth-n-bn|10.10.10.30"
)

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "must run as root (use 'wsl -u root' or sudo)" >&2
        exit 1
    fi
}

cmd_up() {
    require_root

    if ip link show "$BRIDGE" >/dev/null 2>&1; then
        echo "[i] bridge $BRIDGE already exists — bringing it up"
    else
        ip link add "$BRIDGE" type bridge
        ip addr add "${BR_IP}/${PREFIX}" dev "$BRIDGE"
    fi
    ip link set "$BRIDGE" up

    for entry in "${HOSTS[@]}"; do
        IFS='|' read -r ns h_veth n_veth ns_ip <<<"$entry"

        if ip netns list | grep -q "^${ns}\b"; then
            echo "[i] netns ${ns} already exists — re-creating"
            ip netns del "$ns"
        fi
        ip netns add "$ns"

        if ip link show "$h_veth" >/dev/null 2>&1; then
            ip link del "$h_veth"
        fi
        ip link add "$h_veth" type veth peer name "$n_veth"

        ip link set "$h_veth" master "$BRIDGE"
        ip link set "$h_veth" up

        ip link set "$n_veth" netns "$ns"
        ip -n "$ns" link set "$n_veth" up
        ip -n "$ns" addr add "${ns_ip}/${PREFIX}" dev "$n_veth"
        ip -n "$ns" link set lo up
        ip -n "$ns" route add default via "$BR_IP"

        echo "[+] ${ns} ${ns_ip} via ${n_veth} (bridge ${h_veth})"
    done

    sysctl -qw net.ipv4.ip_forward=1 || true
    # Disable reverse-path filtering on the bridge stack — without this,
    # packets entering on a bridge slave (veth-h-X) but routed via the
    # bridge IP can hit asymmetric checks and get silently dropped on the
    # return path after the first few packets.
    sysctl -qw net.ipv4.conf.all.rp_filter=0 || true
    sysctl -qw net.ipv4.conf.default.rp_filter=0 || true
    sysctl -qw "net.ipv4.conf.${BRIDGE//-/_}.rp_filter=0" 2>/dev/null || \
        sysctl -qw "net.ipv4.conf.${BRIDGE}.rp_filter=0" 2>/dev/null || true
    echo
    echo "[ok] demo network ready. bridge=$BRIDGE($BR_IP/$PREFIX), 3 namespaces."
    echo "     server should bind to ${BR_IP}:80"
}

cmd_down() {
    require_root
    for entry in "${HOSTS[@]}"; do
        IFS='|' read -r ns h_veth n_veth ns_ip <<<"$entry"
        ip netns del "$ns" 2>/dev/null || true
        ip link del "$h_veth" 2>/dev/null || true
    done
    if ip link show "$BRIDGE" >/dev/null 2>&1; then
        ip link set "$BRIDGE" down 2>/dev/null || true
        ip link del "$BRIDGE" 2>/dev/null || true
    fi
    echo "[ok] demo network torn down."
}

cmd_status() {
    require_root
    echo "=== bridge ==="
    ip -br addr show "$BRIDGE" 2>/dev/null || echo "  (no $BRIDGE)"
    echo
    echo "=== namespaces ==="
    ip netns list || true
    for entry in "${HOSTS[@]}"; do
        IFS='|' read -r ns h_veth n_veth ns_ip <<<"$entry"
        if ip netns list | grep -q "^${ns}\b"; then
            echo "--- $ns ---"
            ip -n "$ns" -br addr show 2>/dev/null
        fi
    done
}

cmd_exec() {
    require_root
    local ns="${1:?ns name required}"; shift
    exec ip netns exec "$ns" "$@"
}

case "${1:-}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    exec)   shift; cmd_exec "$@" ;;
    *)
        cat <<EOF
usage: $0 {up|down|status|exec <ns> <cmd...>}

Examples:
    sudo bash $0 up
    sudo bash $0 status
    sudo bash $0 exec attacker1 curl -sS http://10.10.10.1/login -d "password=' or 1=1--"
    sudo bash $0 exec benign    curl -sS http://10.10.10.1/login -d "password=secret123"
    sudo bash $0 down
EOF
        exit 1
        ;;
esac
