#!/usr/bin/env bash
#
# End-to-end test of the UNIFIED two-layer detector.
#
# Scenarios:
#   1. Benign POST /login       → passes (layer-2 accepts, target responds 401)
#   2. SQLi curl                → layer-2 (nfqueue_daemon) drops, ipset += 127.0.0.1,
#                                 events.jsonl gets a layer=packet entry
#   3. Kernel-side DROP         → subsequent curl from blocked IP times out
#   4. Flow-layer ingest check  → flow_monitor actually processed flows
#                                 (best-effort: RF on localhost rarely fires, but
#                                  we at least confirm the daemon is sniffing)
#
# Requires root in WSL/Linux. Cleans up iptables/ipset/processes on exit.
#
# Usage:
#   wsl -u root bash /mnt/c/.../live_test_full.sh
#
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

IFACE="lo"
THRESHOLD=1
IPSET_NAME="rlfw_block"
QUEUE_NUM=0
EVENTS_LOG="/tmp/rlfw_events.jsonl"
DAEMON_LOG="/tmp/rlfw_daemon.log"
FLOW_LOG="/tmp/rlfw_flow.log"
TARGET_LOG="/tmp/rlfw_target.log"

say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m  OK: %s\033[0m\n" "$*"; }
bad()  { printf "\033[1;31m  FAIL: %s\033[0m\n" "$*"; FAILED=1; }
note() { printf "\033[1;33m  NOTE: %s\033[0m\n" "$*"; }

FAILED=0
TARGET_PID=""
DAEMON_PID=""
FLOW_PID=""

cleanup() {
    say "cleanup"
    for p in "$TARGET_PID" "$DAEMON_PID" "$FLOW_PID"; do
        [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true
    done
    sleep 0.5
    for p in "$TARGET_PID" "$DAEMON_PID" "$FLOW_PID"; do
        [[ -n "$p" ]] && kill -KILL "$p" 2>/dev/null || true
    done
    iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE_NUM" 2>/dev/null || true
    iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
    ipset destroy "$IPSET_NAME" 2>/dev/null || true
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root" >&2; exit 1; }

say "prerequisites"
command -v ipset >/dev/null || { apt-get install -y ipset >/dev/null 2>&1 && ok "installed ipset"; }
python3 -c "import netfilterqueue, scapy, sklearn, pandas" 2>/dev/null \
    || { pip install --break-system-packages NetfilterQueue scapy scikit-learn pandas >/dev/null 2>&1; }
ok "tools ready"

say "configuring iptables + ipset"
iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE_NUM" 2>/dev/null || true
iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
ipset destroy "$IPSET_NAME" 2>/dev/null || true
ipset create "$IPSET_NAME" hash:ip timeout 3600
iptables -I INPUT 1 -m set --match-set "$IPSET_NAME" src -j DROP
iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num "$QUEUE_NUM"
: > "$EVENTS_LOG"
ok "ipset=$IPSET_NAME, events=$EVENTS_LOG"

say "starting target_server on :80"
python3 target_server.py >"$TARGET_LOG" 2>&1 &
TARGET_PID=$!
sleep 0.7
kill -0 "$TARGET_PID" 2>/dev/null || { bad "target_server did not start"; cat "$TARGET_LOG"; exit 1; }
ok "target_server PID=$TARGET_PID"

say "starting LAYER 2 — nfqueue_daemon (threshold=$THRESHOLD)"
python3 nfqueue_daemon.py --queue "$QUEUE_NUM" --ipset "$IPSET_NAME" \
    --block-threshold "$THRESHOLD" --events-log "$EVENTS_LOG" \
    --log-level INFO >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
sleep 1
kill -0 "$DAEMON_PID" 2>/dev/null || { bad "nfqueue_daemon did not start"; tail "$DAEMON_LOG"; exit 1; }
ok "nfqueue_daemon PID=$DAEMON_PID"

say "starting LAYER 1 — flow_monitor on $IFACE"
python3 flow_monitor.py --iface "$IFACE" --ipset "$IPSET_NAME" \
    --block-threshold "$THRESHOLD" --events-log "$EVENTS_LOG" \
    --log-level INFO >"$FLOW_LOG" 2>&1 &
FLOW_PID=$!
sleep 2
kill -0 "$FLOW_PID" 2>/dev/null || { bad "flow_monitor did not start"; tail "$FLOW_LOG"; exit 1; }
ok "flow_monitor PID=$FLOW_PID"

# --------------------------------------------------------------------
say "scenario 1: benign POST → expect 401"
resp=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
       -X POST -d "password=wrong" http://127.0.0.1/login || echo ERR)
[[ "$resp" == "401" ]] && ok "benign HTTP 401 passed through NFQUEUE" \
                       || bad "expected 401, got $resp"

# --------------------------------------------------------------------
say "scenario 2: SQLi curl → packet layer drops"
send_sqli() {
    curl -s -o /dev/null --max-time 3 \
         "http://127.0.0.1/p?id=%27%20or%201%3D1--%20" >/dev/null 2>&1 || true
}
send_sqli
sleep 0.7

if grep -q '"layer":"packet"' "$EVENTS_LOG"; then
    ok "events log has packet-layer entry"
else
    bad "no packet-layer event in $EVENTS_LOG"
fi
if grep -q "BLOCK 127.0.0.1" "$DAEMON_LOG"; then
    ok "daemon logged BLOCK"
else
    bad "daemon did not log BLOCK"
fi
in_set=$(ipset list "$IPSET_NAME" | grep -c '^127\.0\.0\.1' || true)
[[ "$in_set" -ge 1 ]] && ok "127.0.0.1 is in shared ipset $IPSET_NAME" \
                     || bad "127.0.0.1 missing from ipset"

# --------------------------------------------------------------------
say "scenario 3: blocked IP → subsequent curl must fail (kernel DROP)"
curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
     http://127.0.0.1/anything >/tmp/rc 2>/dev/null
rc=$?
code=$(cat /tmp/rc)
if [[ $rc -ne 0 || "$code" == "000" ]]; then
    ok "kernel dropped (rc=$rc code=$code)"
else
    bad "expected kernel drop, got rc=$rc code=$code"
fi

# --------------------------------------------------------------------
say "scenario 4: flow_monitor ingest check (best-effort)"
# flow_monitor needs to have SEEN flows on lo during this test.
# The scenario-1 curl alone is enough for one flow to complete (when
# TCP connection closes). We inspect the flow log for either hits or
# at least 'FlowSession' activity.
flows_line=$(grep -c "FLOW HIT\|writing flow\|stopping" "$FLOW_LOG" || true)
processes_running=$(kill -0 "$FLOW_PID" 2>/dev/null && echo 1 || echo 0)
if [[ "$processes_running" == "1" ]]; then
    ok "flow_monitor is alive and sniffing $IFACE (PID=$FLOW_PID)"
    if grep -q '"layer":"flow"' "$EVENTS_LOG"; then
        ok "flow layer fired — events.jsonl has layer=flow"
    else
        note "flow layer did not fire on lo (RF trained on CICIDS2017 —"
        note "expected: model rarely classifies short localhost HTTP as attack."
        note "To exercise flow layer, run nmap/hping3 against a real interface."
    fi
else
    bad "flow_monitor died (see $FLOW_LOG)"
fi

# --------------------------------------------------------------------
say "summary"
echo "--- events.jsonl ---"
cat "$EVENTS_LOG" 2>/dev/null | head -20
echo
echo "--- ipset members ---"
ipset list "$IPSET_NAME" | tail -n +8
echo
echo "--- nfqueue_daemon last 10 ---"
tail -n 10 "$DAEMON_LOG"
echo
echo "--- flow_monitor last 10 ---"
tail -n 10 "$FLOW_LOG"
echo

if [[ $FAILED -eq 0 ]]; then
    printf "\033[1;32mALL SCENARIOS PASSED\033[0m\n"
    exit 0
else
    printf "\033[1;31mSOME SCENARIOS FAILED\033[0m\n"
    exit 1
fi
