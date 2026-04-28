#!/usr/bin/env bash
# demo_full.sh — full end-to-end demo with separate network interfaces.
#
# Architecture (see demo_net.sh):
#   br-rlfw 10.10.10.1/24  (default ns, target_server + daemons)
#       │
#       ├── attacker1   netns 10.10.10.20  (sends SQLi)
#       ├── attacker2   netns 10.10.10.21  (sends XSS, cmd injection)
#       └── benign      netns 10.10.10.30  (sends valid POST /login)
#
# Demo flow:
#   1. Setup network + iptables/NFQUEUE/ipset.
#   2. Start target_server (bound to 10.10.10.1:80) + nfqueue_daemon.
#   3. Send benign request from 10.10.10.30 — expects HTTP 401.
#   4. Send SQLi from 10.10.10.20 ×N (threshold) — daemon drops, then ipset adds it.
#   5. Send benign from 10.10.10.30 — still works (proves selective blocking).
#   6. Send benign from blocked 10.10.10.20 — kernel timeout (proof of ipset).
#   7. Send XSS from 10.10.10.21 — separate IP, independent counter.
#   8. Cleanup.
set -euo pipefail

PROJECT="/mnt/c/Users/khmel/Desktop/RL_FIREWALL_IPTABLES-main"
THRESHOLD="${THRESHOLD:-3}"
QUEUE="${QUEUE:-0}"
IPSET_NAME="${IPSET_NAME:-rlfw_demo_block}"
EVENTS_LOG="/tmp/rlfw_demo_events.jsonl"
DAEMON_LOG="/tmp/rlfw_demo_daemon.log"
SERVER_LOG="/tmp/rlfw_demo_server.log"
BR_IP="10.10.10.1"
ATK1_IP="10.10.10.20"
ATK2_IP="10.10.10.21"
BENIGN_IP="10.10.10.30"

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2; exit 1
fi
cd "$PROJECT"

cyan()  { printf "\033[36m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
red()   { printf "\033[31m%s\033[0m\n" "$*"; }
yel()   { printf "\033[33m%s\033[0m\n" "$*"; }
banner(){ echo; cyan "═══════════════════════════════════════════════════════════════"; cyan "  $*"; cyan "═══════════════════════════════════════════════════════════════"; }

DAEMON_PID=""
SERVER_PID=""
cleanup() {
    set +e
    banner "CLEANUP"
    [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null && echo "  killed daemon"
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null && echo "  killed server"
    sleep 0.5
    iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE" 2>/dev/null
    iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null
    ipset destroy "$IPSET_NAME" 2>/dev/null
    bash demo_net.sh down
    rm -f "$EVENTS_LOG" "$DAEMON_LOG" "$SERVER_LOG"
    echo "  done."
}
trap cleanup EXIT INT TERM

# ----- prepare deps -----
banner "DEPENDENCIES"
command -v ipset >/dev/null || { yel "  apt-get install ipset"; apt-get install -y ipset; }
python3 -c "import netfilterqueue" 2>/dev/null || { yel "  pip install NetfilterQueue"; pip install --break-system-packages NetfilterQueue scapy; }

# ----- build virtual net -----
banner "1. NETWORK SETUP"
bash demo_net.sh up
bash demo_net.sh status

# ----- ipset + iptables -----
banner "2. IPSET + IPTABLES"
ipset destroy "$IPSET_NAME" 2>/dev/null || true
ipset create "$IPSET_NAME" hash:ip timeout 3600
iptables -I INPUT 1 -m set --match-set "$IPSET_NAME" src -j DROP
iptables -A INPUT    -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE"
iptables -L INPUT -n --line-numbers | head -10

# ----- target server bound to bridge IP -----
banner "3. START TARGET SERVER on ${BR_IP}:80"
sed "s/HOST           = \"0\\.0\\.0\\.0\"/HOST           = \"${BR_IP}\"/" target_server.py > /tmp/target_server_demo.py
python3 /tmp/target_server_demo.py >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || { red "server failed"; cat "$SERVER_LOG"; exit 1; }
green "  server PID=$SERVER_PID"

# ----- nfqueue daemon (V2 ensemble + threshold) -----
banner "4. START NFQUEUE DAEMON  (--ensemble-dir packet_models_v2 --block-threshold $THRESHOLD)"
python3 -u nfqueue_daemon.py \
    --queue "$QUEUE" \
    --block-mode ipset \
    --ipset "$IPSET_NAME" \
    --block-threshold "$THRESHOLD" \
    --ensemble-dir artifacts/packet_models_v2 \
    --events-log "$EVENTS_LOG" \
    >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
sleep 2
kill -0 "$DAEMON_PID" 2>/dev/null || { red "daemon failed"; cat "$DAEMON_LOG"; exit 1; }
green "  daemon PID=$DAEMON_PID"

# helper — captures both http_code and curl exit rc reliably
ns_curl() {
    local ns="$1"; shift
    local code
    code=$(ip netns exec "$ns" curl -sS -m 6 -o /dev/null -w "%{http_code}" "$@" 2>/dev/null)
    local rc=$?
    echo "${code}|rc=${rc}"
}

# wait for daemon to settle after a burst of drops (NFQUEUE backlog drains)
settle() { sleep 2; }

# ============================================================
# Scenario 1 — benign from a clean IP
# ============================================================
banner "SCENARIO 1 — benign POST /login from ${BENIGN_IP}"
echo "  expected: HTTP 200 (correct password)"
out=$(ns_curl benign -X POST "http://${BR_IP}/login" -d "password=secret123")
echo "  result: $out"
[[ "$out" =~ ^200 ]] && green "  OK — benign passes through" || { red "  FAIL — benign blocked"; }

# ============================================================
# Scenario 2 — SQLi from attacker1, count up to threshold
# ============================================================
banner "SCENARIO 2 — SQLi attack from ${ATK1_IP}, threshold=${THRESHOLD}"
echo "  expected: each curl times out (daemon drops), threshold reached → ipset adds IP"
for i in $(seq 1 $((THRESHOLD + 1))); do
    out=$(ns_curl attacker1 "http://${BR_IP}/p?id=%27%20or%201%3D1--")
    echo "  attempt #$i  →  $out"
done
sleep 1
yel "  --- daemon log (last 8 lines) ---"
tail -8 "$DAEMON_LOG"
yel "  --- ipset members ---"
ipset list "$IPSET_NAME" | tail -10

settle

# ============================================================
# Scenario 3 — benign request from blocked attacker1
# ============================================================
banner "SCENARIO 3 — benign POST from blocked ${ATK1_IP}"
echo "  expected: kernel-side DROP (curl timeout, http_code=000)"
out=$(ns_curl attacker1 -X POST "http://${BR_IP}/login" -d "password=secret123")
echo "  result: $out"
if [[ "$out" =~ ^000 ]] || [[ "$out" =~ "rc=28" ]]; then
    green "  OK — blocked IP gets kernel DROP"
else
    red "  FAIL — got: $out"
fi

settle
sleep 3

# ============================================================
# Scenario 4 — benign STILL works from clean IP
# ============================================================
banner "SCENARIO 4 — benign from ${BENIGN_IP} (still clean)"
echo "  expected: still HTTP 200 — proves blocking is per-IP"
yel "  --- iptables INPUT counters before ---"
iptables -L INPUT -n -v | head -8
out=$(ns_curl benign -X POST "http://${BR_IP}/login" -d "password=secret123")
echo "  result: $out"
yel "  --- iptables INPUT counters after ---"
iptables -L INPUT -n -v | head -8
[[ "$out" =~ ^200 ]] && green "  OK — clean IP unaffected" || red "  FAIL — clean IP got blocked"

settle

# ============================================================
# Scenario 5 — XSS attack from a different IP, independent counter
# ============================================================
banner "SCENARIO 5 — XSS from ${ATK2_IP} — independent per-IP counter"
for i in $(seq 1 $((THRESHOLD + 1))); do
    out=$(ns_curl attacker2 "http://${BR_IP}/p?x=%3Cscript%3Ealert(1)%3C/script%3E")
    echo "  attempt #$i  →  $out"
done
sleep 1
yel "  --- ipset members (now 2 blocked IPs) ---"
ipset list "$IPSET_NAME" | tail -10

# ============================================================
# Scenario 6 — events.jsonl correlation
# ============================================================
banner "SCENARIO 6 — JSONL events log (per-IP correlation)"
if [[ -s "$EVENTS_LOG" ]]; then
    echo "  events from ${ATK1_IP}:"
    grep "$ATK1_IP" "$EVENTS_LOG" | head -3
    echo
    echo "  events from ${ATK2_IP}:"
    grep "$ATK2_IP" "$EVENTS_LOG" | head -3
    echo
    yel "  total events: $(wc -l < "$EVENTS_LOG")"
else
    yel "  (no events.jsonl — daemon may not have flushed yet)"
fi

# ============================================================
# Final summary
# ============================================================
banner "FINAL STATE"
yel "  --- iptables INPUT ---"
iptables -L INPUT -n --line-numbers | head -10
yel "  --- ipset members ---"
ipset list "$IPSET_NAME" | grep -A20 "^Members:" || true
yel "  --- daemon HIT lines ---"
grep -E "HIT|BLOCK|ATTEMPT" "$DAEMON_LOG" | head -20

green "
╔══════════════════════════════════════════════════════╗
║  DEMO COMPLETE                                       ║
║                                                      ║
║  Demonstrated:                                       ║
║   • server bound to non-loopback IP (${BR_IP})       ║
║   • 3 distinct virtual hosts, distinct interfaces    ║
║   • per-IP block lists (attacker1, attacker2)        ║
║   • benign IP unaffected by other IPs being blocked  ║
║   • kernel-side DROP for already-blocked IPs         ║
╚══════════════════════════════════════════════════════╝
"
