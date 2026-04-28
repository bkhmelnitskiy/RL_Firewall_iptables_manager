#!/usr/bin/env bash
# demo_start.sh — interactive demo for live presentations.
#
# Brings up the full firewall stack and stays running until Ctrl+C.
# You drive the demo from a SECOND terminal by issuing curl commands.
#
# Architecture (see demo_net.sh):
#     br-rlfw 10.10.10.1/24  (target_server + nfqueue_daemon)
#         ├── attacker1   netns 10.10.10.20
#         ├── attacker2   netns 10.10.10.21
#         └── benign      netns 10.10.10.30
#
# Default block mode is "iptables" — each blocked IP becomes a NEW rule
# in chain RLFW_BLOCK, so the audience SEES the firewall grow live with
# each attack. Use --ipset for the production-grade O(1) hash:ip.
#
# Usage:
#     sudo bash demo_start.sh                       # iptables mode (visual)
#     sudo bash demo_start.sh --ipset               # ipset mode (production)
#     sudo bash demo_start.sh --threshold 1         # block on first hit
#     sudo bash demo_start.sh --threshold 5         # block on 5th hit
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")" && pwd)"
BLOCK_MODE="iptables"
THRESHOLD="3"
QUEUE="0"
CHAIN="RLFW_BLOCK"
IPSET_NAME="rlfw_demo_block"
EVENTS_LOG="/tmp/rlfw_events.jsonl"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ipset)        BLOCK_MODE="ipset"; shift ;;
        --iptables)     BLOCK_MODE="iptables"; shift ;;
        --threshold)    THRESHOLD="$2"; shift 2 ;;
        --queue)        QUEUE="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^set -e/p' "$0" | sed 's/^# \?//' | head -n -1
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (sudo bash $0)" >&2
    exit 1
fi
cd "$PROJECT"

cyan()  { printf "\033[36m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
yel()   { printf "\033[33m%s\033[0m\n" "$*"; }
red()   { printf "\033[31m%s\033[0m\n" "$*"; }
banner() { echo; cyan "═══════════════════════════════════════════════════════════════"; cyan "  $*"; cyan "═══════════════════════════════════════════════════════════════"; }

SERVER_PID=""
DAEMON_PID=""

cleanup() {
    set +e
    echo
    banner "CLEANUP"
    [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null && echo "  killed daemon ($DAEMON_PID)"
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null && echo "  killed server ($SERVER_PID)"
    sleep 0.5
    iptables -D INPUT -p tcp --dport "80" -j NFQUEUE --queue-num "$QUEUE" 2>/dev/null
    if [[ "$BLOCK_MODE" == "iptables" ]]; then
        iptables -D INPUT -j "$CHAIN" 2>/dev/null
        iptables -F "$CHAIN" 2>/dev/null
        iptables -X "$CHAIN" 2>/dev/null
    else
        iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null
        ipset destroy "$IPSET_NAME" 2>/dev/null
    fi
    bash demo_net.sh down 2>/dev/null
    rm -f "$EVENTS_LOG"
    echo "  done."
}
trap cleanup EXIT INT TERM

# --- pre-flight: kill any leftover server/daemon, free port 80 ---
banner "PRE-FLIGHT"
# All these expectedly fail when there's nothing leftover — disable -e for the cleanup block.
set +e
pkill -f target_server.py 2>/dev/null && echo "  killed leftover target_server"
pkill -f nfqueue_daemon.py 2>/dev/null && echo "  killed leftover daemon"
iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE" 2>/dev/null
iptables -D INPUT -j "$CHAIN" 2>/dev/null
iptables -F "$CHAIN" 2>/dev/null
iptables -X "$CHAIN" 2>/dev/null
iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null
ipset destroy "$IPSET_NAME" 2>/dev/null
sleep 0.3
set -e
if ss -tln 2>/dev/null | grep -q ':80 '; then
    red "  port 80 is still in use!"
    ss -tlnp | grep ':80 ' || true
    exit 1
fi
green "  port 80 free, no leftover processes"

# --- 1. virtual network ---
banner "1. NETWORK SETUP"
bash demo_net.sh up

# --- 2. firewall plumbing ---
banner "2. IPTABLES / IPSET"
if [[ "$BLOCK_MODE" == "iptables" ]]; then
    iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
    iptables -I INPUT 1 -j "$CHAIN"
    yel "  mode=iptables — every block adds a NEW rule to chain $CHAIN"
    yel "  watch live with: watch -n 0.5 'sudo iptables -L $CHAIN -n --line-numbers'"
else
    ipset create "$IPSET_NAME" hash:ip timeout 3600 2>/dev/null || ipset flush "$IPSET_NAME"
    iptables -I INPUT 1 -m set --match-set "$IPSET_NAME" src -j DROP
    yel "  mode=ipset — single iptables rule, set membership grows on each block"
    yel "  watch live with: watch -n 0.5 'sudo ipset list $IPSET_NAME | tail -20'"
fi
iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE"
iptables -L INPUT -n --line-numbers | head -8

# --- 3. target server bound to bridge IP ---
banner "3. TARGET SERVER on 10.10.10.1:80"
sed 's/HOST           = "0\.0\.0\.0"/HOST           = "10.10.10.1"/' target_server.py > /tmp/target_server_demo.py
python3 -u /tmp/target_server_demo.py >/tmp/rlfw_demo_server.log 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || { red "server failed"; cat /tmp/rlfw_demo_server.log; exit 1; }
green "  server PID=$SERVER_PID  (log: /tmp/rlfw_demo_server.log)"

# --- 4. NFQUEUE daemon ---
banner "4. NFQUEUE DAEMON"
DAEMON_ARGS=(
    --queue "$QUEUE"
    --block-mode "$BLOCK_MODE"
    --block-threshold "$THRESHOLD"
    --ensemble-dir artifacts/packet_models_v2
    --events-log "$EVENTS_LOG"
)
if [[ "$BLOCK_MODE" == "ipset" ]]; then
    DAEMON_ARGS+=(--ipset "$IPSET_NAME")
else
    DAEMON_ARGS+=(--chain "$CHAIN")
fi

# Start daemon in background, stream its output to THIS terminal so the
# audience watches HIT/PACKET DROPPED/FIREWALL RULE ADDED lines live.
python3 -u nfqueue_daemon.py "${DAEMON_ARGS[@]}" 2>&1 | sed 's/^/[daemon] /' &
DAEMON_PID=$(jobs -p | tail -1)
sleep 2
kill -0 "$DAEMON_PID" 2>/dev/null || { red "daemon failed"; exit 1; }
green "  daemon running (PID=$DAEMON_PID, mode=$BLOCK_MODE, threshold=$THRESHOLD)"

# --- 5. cheat sheet for the audience ---
banner "READY — drive the demo from another terminal"
cat <<EOF
$(yel "Open a SECOND terminal and try these:")

  $(green "# clean request — should pass:")
  sudo bash demo_net.sh exec benign \\
      curl -v http://10.10.10.1/login -d "password=secret123"

  $(green "# SQLi — daemon will drop, after $THRESHOLD attempts the IP gets a firewall rule:")
  sudo bash demo_net.sh exec attacker1 \\
      curl --max-time 4 "http://10.10.10.1/p?id=%27%20or%201%3D1--"

  $(green "# XSS — separate IP, independent counter:")
  sudo bash demo_net.sh exec attacker2 \\
      curl --max-time 4 "http://10.10.10.1/p?x=%3Cscript%3Ealert(1)%3C/script%3E"

  $(green "# Cmd injection:")
  sudo bash demo_net.sh exec attacker2 \\
      curl --max-time 4 "http://10.10.10.1/p?c=%3C!--%23exec%20cmd=%22/bin/cat%20/etc/passwd%22--%3E"

  $(green "# After threshold reached, even a benign request from the blocked IP fails (kernel DROP):")
  sudo bash demo_net.sh exec attacker1 \\
      curl --max-time 4 http://10.10.10.1/login -d "password=secret123"

$(yel "Watch the firewall in a third terminal:")
EOF
if [[ "$BLOCK_MODE" == "iptables" ]]; then
    echo "  watch -n 0.5 'sudo iptables -L $CHAIN -n --line-numbers'"
else
    echo "  watch -n 0.5 'sudo ipset list $IPSET_NAME | tail -20'"
fi
cat <<EOF

$(yel "Watch correlated events:")
  tail -f $EVENTS_LOG

$(red "Press Ctrl+C in this terminal to stop everything and clean up.")
EOF

# --- 6. block until interrupted ---
wait "$DAEMON_PID"
