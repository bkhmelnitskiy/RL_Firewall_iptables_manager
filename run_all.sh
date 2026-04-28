#!/usr/bin/env bash
#
# RL_FIREWALL_IPTABLES — odpal całość jednym poleceniem.
#
# Tworzy dedykowany chain RLFW_BLOCK, wpina go na górę INPUT, startuje
# oba detektory. Każde wykryte złośliwe IP trafia jako osobna reguła
# DROP w RLFW_BLOCK — widać to live w `iptables -L RLFW_BLOCK` lub
# `iptables -L INPUT`.
#
# Uruchomienie (jako root):
#   bash run_all.sh                       # interfejs lo, blokuje pierwszy hit
#   bash run_all.sh --iface eth0          # prawdziwy interfejs
#   bash run_all.sh --threshold 3         # blokuj po 3 próbach
#   bash run_all.sh --mode ipset          # jeden rule + ipset hash (produkcja)
#
# Stop: Ctrl+C — cleanup zdejmuje chain i reguły.
#
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

IFACE="lo"
THRESHOLD=1
CHAIN="RLFW_BLOCK"
IPSET_NAME="rlfw_block"
QUEUE_NUM=0
EVENTS_LOG="/tmp/rlfw_events.jsonl"
MODE="iptables"   # 'iptables' (per-IP rules, visible) or 'ipset' (hash, production)
DEMO_SERVER=0     # --demo also spawns target_server.py on :80 for the demo

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)     IFACE="$2"; shift 2 ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --mode)      MODE="$2"; shift 2 ;;
        --chain)     CHAIN="$2"; shift 2 ;;
        --queue)     QUEUE_NUM="$2"; shift 2 ;;
        --events)    EVENTS_LOG="$2"; shift 2 ;;
        --demo)      DEMO_SERVER=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: bash run_all.sh [opts]
  --iface NAME       interface to sniff (default: lo)
  --threshold N      attacks per IP before block (default: 1)
  --mode MODE        iptables | ipset (default: iptables — visible in -L)
  --chain NAME       iptables chain (default: RLFW_BLOCK)
  --events PATH      JSONL event log (default: /tmp/rlfw_events.jsonl)
  --demo             also start target_server.py on :80 (for presentations)
EOF
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (wsl -u root bash run_all.sh)"; exit 1; }

say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m  OK: %s\033[0m\n" "$*"; }

FLOW_PID=""; PKT_PID=""; TARGET_PID=""

cleanup() {
    say "cleanup"
    [[ -n "$PKT_PID"    ]] && kill -TERM "$PKT_PID"    2>/dev/null || true
    [[ -n "$FLOW_PID"   ]] && kill -TERM "$FLOW_PID"   2>/dev/null || true
    [[ -n "$TARGET_PID" ]] && kill -TERM "$TARGET_PID" 2>/dev/null || true
    sleep 0.3
    [[ -n "$PKT_PID"    ]] && kill -KILL "$PKT_PID"    2>/dev/null || true
    [[ -n "$FLOW_PID"   ]] && kill -KILL "$FLOW_PID"   2>/dev/null || true
    [[ -n "$TARGET_PID" ]] && kill -KILL "$TARGET_PID" 2>/dev/null || true

    iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE_NUM" 2>/dev/null || true
    iptables -D INPUT -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    if [[ "$MODE" == "ipset" ]]; then
        iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
        ipset destroy "$IPSET_NAME" 2>/dev/null || true
    fi
    ok "iptables cleaned"
}
trap cleanup EXIT INT TERM

say "prerequisites"
if [[ "$MODE" == "ipset" ]]; then
    command -v ipset >/dev/null || { apt-get install -y ipset >/dev/null 2>&1; }
fi
python3 -c "import netfilterqueue, scapy, sklearn, pandas" 2>/dev/null \
    || pip install --break-system-packages NetfilterQueue scapy scikit-learn pandas >/dev/null 2>&1
ok "tools ready"

say "configuring iptables (mode=$MODE)"
# Remove any leftovers from previous runs (safe: -D fails silently if rule absent)
iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE_NUM" 2>/dev/null || true
iptables -D INPUT -j "$CHAIN" 2>/dev/null || true
iptables -F "$CHAIN" 2>/dev/null || true
iptables -X "$CHAIN" 2>/dev/null || true
if [[ "$MODE" == "ipset" ]]; then
    iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
    ipset destroy "$IPSET_NAME" 2>/dev/null || true
fi

if [[ "$MODE" == "iptables" ]]; then
    iptables -N "$CHAIN"
    iptables -I INPUT 1 -j "$CHAIN"
    ok "chain $CHAIN created + linked from INPUT (first rule)"
else
    ipset create "$IPSET_NAME" hash:ip timeout 3600
    iptables -I INPUT 1 -m set --match-set "$IPSET_NAME" src -j DROP
    ok "ipset $IPSET_NAME created + match-set DROP linked from INPUT"
fi
iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE_NUM"
ok "NFQUEUE queue=$QUEUE_NUM attached to tcp dpt:80"

# Create events log with world-writable perms (operators tail from non-root)
: > "$EVENTS_LOG"
chmod 644 "$EVENTS_LOG"
ok "events log → $EVENTS_LOG"

if [[ "$DEMO_SERVER" == "1" ]]; then
    say "DEMO — starting target_server.py on :80"
    python3 target_server.py >/tmp/rlfw_target.log 2>&1 &
    TARGET_PID=$!
    sleep 0.7
    if ! kill -0 "$TARGET_PID" 2>/dev/null; then
        echo "target_server failed" >&2; exit 1
    fi
    ok "target_server PID=$TARGET_PID"
fi

say "LAYER 2 — nfqueue_daemon (packet-level signatures, threshold=$THRESHOLD)"
python3 nfqueue_daemon.py \
    --queue "$QUEUE_NUM" \
    --block-mode "$MODE" \
    --chain "$CHAIN" \
    --ipset "$IPSET_NAME" \
    --block-threshold "$THRESHOLD" \
    --events-log "$EVENTS_LOG" &
PKT_PID=$!
sleep 1
if ! kill -0 "$PKT_PID" 2>/dev/null; then
    echo "nfqueue_daemon failed" >&2; exit 1
fi
ok "nfqueue_daemon PID=$PKT_PID"

say "LAYER 1 — flow_monitor (flow RF on $IFACE)"
python3 flow_monitor.py \
    --iface "$IFACE" \
    --block-mode "$MODE" \
    --chain "$CHAIN" \
    --ipset "$IPSET_NAME" \
    --block-threshold "$THRESHOLD" \
    --events-log "$EVENTS_LOG" &
FLOW_PID=$!
sleep 2
if ! kill -0 "$FLOW_PID" 2>/dev/null; then
    echo "flow_monitor failed" >&2; exit 1
fi
ok "flow_monitor PID=$FLOW_PID"

cat <<BANNER

================================================================
  RL_FIREWALL uruchomiony — czeka na ruch.
================================================================
  Zablokowane IP pojawią się jako reguły w iptables:
    iptables -L $CHAIN -n --line-numbers
  Lub live:
    watch -n1 'iptables -L $CHAIN -n --line-numbers'

  Log zdarzeń (JSONL):
    tail -f $EVENTS_LOG

  Stop: Ctrl+C
================================================================

BANNER

wait -n "$PKT_PID" "$FLOW_PID" 2>/dev/null || true
wait
