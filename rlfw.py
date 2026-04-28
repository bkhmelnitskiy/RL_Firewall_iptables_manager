"""
RL_FIREWALL_IPTABLES — uruchamia cały system jednym poleceniem.

Demo-friendly orkiestrator dla obu warstw IDS:
    Layer 1 (flow_monitor.py)   — Random Forest na statystykach przepływu
    Layer 2 (nfqueue_daemon.py) — sygnatury web-attack na powierzchni HTTP

Co robi przy starcie:
    1. Tworzy łańcuch iptables RLFW_BLOCK i wpina go na górę INPUT.
    2. Wpina regułę NFQUEUE dla TCP/80 → daemon dostaje pakiety HTTP.
    3. Startuje obydwa daemony jako subprocessy.
    4. Multipleksuje ich logi do konsoli z prefixami [PKT] / [FLOW].
    5. Co 2 s sprawdza `iptables -L RLFW_BLOCK -n --line-numbers` —
       gdy zauważy nową regułę, pokazuje aktualny stan łańcucha
       (widz na sali widzi że firewall faktycznie się zmienił).

Stop: Ctrl+C — cleanup zdejmuje wszystkie reguły i łańcuch.

Uruchomienie (Linux/WSL, root):
    sudo python3 rlfw.py                       # interfejs lo, threshold=1
    sudo python3 rlfw.py --iface eth0          # prawdziwy interfejs
    sudo python3 rlfw.py --threshold 3         # demo "pakiet zdropowany ×2,
                                                  trzeci → reguła w iptables"
    sudo python3 rlfw.py --demo                # +odpala target_server.py:80
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess as sp
import sys
import threading
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent

DEFAULT_CHAIN = "RLFW_BLOCK"
DEFAULT_QUEUE = 0
DEFAULT_IPSET = "rlfw_block"
DEFAULT_EVENTS = "/tmp/rlfw_events.jsonl"


# ---------- terminal helpers ----------

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    GRAY = "\033[90m"


def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


COLOR = _color_enabled()


def c(text: str, color: str) -> str:
    return f"{color}{text}{C.RESET}" if COLOR else text


def banner(line: str, color: str = C.CYAN) -> None:
    bar = "=" * 64
    print(c(bar, color))
    print(c(f"  {line}", color + C.BOLD if COLOR else color))
    print(c(bar, color))


def step(msg: str) -> None:
    print(c(f"==> {msg}", C.CYAN))


def ok(msg: str) -> None:
    print(c(f"  OK: {msg}", C.GREEN))


def warn(msg: str) -> None:
    print(c(f"  !! {msg}", C.YELLOW))


def fail(msg: str) -> None:
    print(c(f"  FAIL: {msg}", C.RED))


# ---------- iptables helpers ----------

def run(cmd: list[str], check: bool = True, quiet: bool = False) -> sp.CompletedProcess:
    res = sp.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0 and not quiet:
        sys.stderr.write(f"{' '.join(cmd)} failed: {res.stderr.strip()}\n")
    return res


def iptables_setup(chain: str, queue_num: int) -> None:
    iptables_teardown(chain, queue_num, quiet=True)
    run(["iptables", "-N", chain])
    run(["iptables", "-I", "INPUT", "1", "-j", chain])
    # --queue-bypass: if the daemon can't keep up (queue full) or dies, the
    # rule is bypassed instead of dropping every TCP/80 packet. Demo stays
    # responsive even under retransmit storms.
    run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80",
         "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass"])


def iptables_teardown(chain: str, queue_num: int, quiet: bool = False) -> None:
    run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "80",
         "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass"],
        check=not quiet, quiet=True)
    # legacy form without --queue-bypass, in case someone runs cleanup against
    # an older setup
    run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "80",
         "-j", "NFQUEUE", "--queue-num", str(queue_num)],
        check=not quiet, quiet=True)
    run(["iptables", "-D", "INPUT", "-j", chain], check=not quiet, quiet=True)
    run(["iptables", "-F", chain], check=not quiet, quiet=True)
    run(["iptables", "-X", chain], check=not quiet, quiet=True)


def iptables_list_rules(chain: str) -> list[str]:
    res = sp.run(["iptables", "-L", chain, "-n", "--line-numbers"],
                 capture_output=True, text=True)
    if res.returncode != 0:
        return []
    return res.stdout.splitlines()


# ---------- loopback aliases (demo: distinct source IPs on lo) ----------

LO_ALIAS_NET = "10.0.0"          # 10.0.0.1 .. 10.0.0.N as /24 on lo
LO_ALIAS_CIDR = 24


def lo_aliases_add(n: int) -> list[str]:
    """Add 10.0.0.1..10.0.0.N as /24 aliases on lo. Returns the IPs added."""
    added: list[str] = []
    for i in range(1, n + 1):
        ip = f"{LO_ALIAS_NET}.{i}"
        # idempotent: ignore "exists" errors
        res = sp.run(["ip", "addr", "add", f"{ip}/{LO_ALIAS_CIDR}", "dev", "lo"],
                     capture_output=True, text=True)
        if res.returncode == 0 or "File exists" in res.stderr:
            added.append(ip)
        else:
            sys.stderr.write(f"ip addr add {ip} failed: {res.stderr.strip()}\n")
    return added


def lo_aliases_remove(n: int) -> None:
    for i in range(1, n + 1):
        ip = f"{LO_ALIAS_NET}.{i}"
        sp.run(["ip", "addr", "del", f"{ip}/{LO_ALIAS_CIDR}", "dev", "lo"],
               capture_output=True, text=True)


# ---------- subprocess streaming with prefix ----------

def _stream(prefix: str, color: str, proc: sp.Popen, stop: threading.Event) -> None:
    assert proc.stdout is not None
    tag = c(f"[{prefix}]", color)
    for line in proc.stdout:
        if stop.is_set():
            break
        sys.stdout.write(f"{tag} {line}")
        sys.stdout.flush()


def spawn(prefix: str, color: str, argv: list[str]) -> sp.Popen:
    proc = sp.Popen(
        argv,
        cwd=str(HERE),
        stdout=sp.PIPE,
        stderr=sp.STDOUT,
        text=True,
        bufsize=1,
    )
    return proc


# ---------- iptables-watch thread ----------

def watch_chain(chain: str, stop: threading.Event) -> None:
    """Poll the chain every 2 s; when rule count changes, dump current state."""
    last_count = -1
    while not stop.is_set():
        rules = iptables_list_rules(chain)
        # Output of `iptables -L CHAIN -n --line-numbers` for an empty chain
        # is 2 header lines. Each rule adds one line.
        rule_count = max(0, len(rules) - 2)
        if rule_count != last_count:
            if last_count >= 0 and rule_count > last_count:
                added = rule_count - last_count
                banner(f"IPTABLES UPDATED  (+{added} rule"
                       f"{'s' if added > 1 else ''} in chain {chain},"
                       f" total={rule_count})", C.MAGENTA)
                for line in rules:
                    print(c(f"  {line}", C.MAGENTA))
                print(c("=" * 64, C.MAGENTA))
            last_count = rule_count
        for _ in range(20):           # 20 × 0.1 s = 2 s, but responsive to stop
            if stop.is_set():
                return
            time.sleep(0.1)


# ---------- main ----------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="RL_FIREWALL_IPTABLES — single-command launcher (demo-friendly).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--iface", default="lo",
                    help="Interface for flow_monitor sniffer (default: lo).")
    ap.add_argument("--threshold", type=int, default=1,
                    help="Attacks per src IP before iptables rule is added "
                         "(default 1 = block on first hit). Each individual "
                         "attack packet is dropped regardless.")
    ap.add_argument("--mode", default="iptables", choices=["iptables", "ipset"],
                    help="iptables (default, visible in -L); ipset (production).")
    ap.add_argument("--chain", default=DEFAULT_CHAIN,
                    help=f"iptables chain (default {DEFAULT_CHAIN}).")
    ap.add_argument("--queue", type=int, default=DEFAULT_QUEUE,
                    help=f"NFQUEUE number (default {DEFAULT_QUEUE}).")
    ap.add_argument("--events", default=DEFAULT_EVENTS,
                    help=f"Shared JSONL event log (default {DEFAULT_EVENTS}).")
    ap.add_argument("--ensemble-dir", default="artifacts/packet_models_v2",
                    help="Dir with per-attack .pkl models for inline ML "
                         "detection (default: V2 set — sqli/xss/cmd_injection).")
    ap.add_argument("--demo", action="store_true",
                    help="Also start target_server.py on :80 (dummy login, "
                         "so localhost curl has something to talk to).")
    ap.add_argument("--lo-aliases", type=int, default=0, metavar="N",
                    help="Add N additional source addresses (10.0.0.1..10.0.0.N) "
                         "as aliases on lo. Lets attack_demo.py rotate src IP per "
                         "attack so each one gets a distinct entry in iptables "
                         "(rather than every attack coming from 127.0.0.1, which "
                         "would die after the first block). Removed at cleanup.")
    ap.add_argument("--no-flow", action="store_true",
                    help="Skip Layer 1 (flow_monitor). Useful if cicflowmeter "
                         "deps aren't installed and you only want signatures.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Detect+log only; never touch iptables/ipset (safe rehearsal).")
    args = ap.parse_args()

    if os.geteuid() != 0:
        fail("must run as root (sudo / wsl -u root)")
        return 1

    if args.mode == "ipset" and shutil.which("ipset") is None:
        fail("--mode ipset requested but `ipset` binary is not installed.")
        warn("install: apt-get install -y ipset")
        return 1

    banner("RL_FIREWALL_IPTABLES — uruchamianie systemu")
    print(c(f"  iface     = {args.iface}",     C.GRAY))
    print(c(f"  threshold = {args.threshold}", C.GRAY))
    print(c(f"  mode      = {args.mode}",      C.GRAY))
    print(c(f"  chain     = {args.chain}",     C.GRAY))
    print(c(f"  queue     = {args.queue}",     C.GRAY))
    print(c(f"  events    = {args.events}",    C.GRAY))
    if args.lo_aliases > 0:
        print(c(f"  lo aliases= 10.0.0.1..10.0.0.{args.lo_aliases}", C.GRAY))
    if args.dry_run:
        warn("DRY-RUN: detekcja działa, ale firewall nie jest dotykany.")
    print()

    procs: list[tuple[str, sp.Popen]] = []
    stop = threading.Event()
    threads: list[threading.Thread] = []

    def cleanup(*_) -> None:
        if stop.is_set():
            return
        stop.set()
        print()
        step("cleanup")
        for name, p in procs:
            if p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass
        time.sleep(0.4)
        for name, p in procs:
            if p.poll() is None:
                try:
                    p.kill()
                except Exception:
                    pass
        if not args.dry_run:
            iptables_teardown(args.chain, args.queue, quiet=True)
            if args.mode == "ipset":
                run(["iptables", "-D", "INPUT", "-m", "set",
                     "--match-set", DEFAULT_IPSET, "src", "-j", "DROP"], quiet=True)
                run(["ipset", "destroy", DEFAULT_IPSET], quiet=True)
        if args.lo_aliases > 0:
            lo_aliases_remove(args.lo_aliases)
        ok("iptables cleaned, processes stopped")

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # ----- iptables setup -----
    if not args.dry_run:
        step(f"konfiguruję iptables (mode={args.mode}, chain={args.chain})")
        if args.mode == "iptables":
            iptables_setup(args.chain, args.queue)
            ok(f"łańcuch {args.chain} stworzony i podpięty pod INPUT (pozycja 1)")
        else:
            run(["ipset", "create", DEFAULT_IPSET, "hash:ip", "timeout", "3600", "-exist"])
            run(["iptables", "-I", "INPUT", "1", "-m", "set",
                 "--match-set", DEFAULT_IPSET, "src", "-j", "DROP"])
            run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80",
                 "-j", "NFQUEUE", "--queue-num", str(args.queue),
                 "--queue-bypass"])
            ok(f"ipset {DEFAULT_IPSET} stworzony i wpięty w INPUT")
        ok(f"NFQUEUE {args.queue} przejmuje TCP/80")
    else:
        warn("[dry-run] iptables nietknięty")

    if args.lo_aliases > 0:
        step(f"dodaję {args.lo_aliases} aliasów źródłowych na lo")
        added = lo_aliases_add(args.lo_aliases)
        ok(f"aliasy lo: {', '.join(added)}")

    # Start fresh events log so demo isn't polluted by yesterday's runs
    Path(args.events).write_text("")
    os.chmod(args.events, 0o644)
    ok(f"events log → {args.events}")

    # ----- optional target server -----
    if args.demo:
        step("startuję target_server.py na :80")
        ts = spawn("TGT", C.GRAY, ["python3", str(HERE / "target_server.py")])
        procs.append(("target_server", ts))
        time.sleep(0.6)
        if ts.poll() is not None:
            fail(f"target_server zakończył się natychmiast (rc={ts.returncode})")
            cleanup(); return 1
        threads.append(threading.Thread(
            target=_stream, args=("TGT", C.GRAY, ts, stop), daemon=True))
        ok("target_server PID=%d" % ts.pid)

    # ----- Layer 2 (packet) -----
    step(f"startuję LAYER 2 — nfqueue_daemon (signatures, threshold={args.threshold})")
    pkt_argv = [
        "python3", "-u", str(HERE / "nfqueue_daemon.py"),
        "--queue", str(args.queue),
        "--block-mode", args.mode,
        "--chain", args.chain,
        "--ipset", DEFAULT_IPSET,
        "--block-threshold", str(args.threshold),
        "--events-log", args.events,
    ]
    if args.ensemble_dir:
        pkt_argv += ["--ensemble-dir", args.ensemble_dir]
    if args.dry_run:
        pkt_argv.append("--dry-run")
    pkt = spawn("PKT", C.YELLOW, pkt_argv)
    procs.append(("nfqueue_daemon", pkt))
    time.sleep(1.0)
    if pkt.poll() is not None:
        fail(f"nfqueue_daemon zakończył się natychmiast (rc={pkt.returncode})")
        # Drain whatever it printed before dying
        try:
            for line in pkt.stdout:
                sys.stdout.write(f"{c('[PKT]', C.YELLOW)} {line}")
        except Exception:
            pass
        cleanup(); return 1
    threads.append(threading.Thread(
        target=_stream, args=("PKT", C.YELLOW, pkt, stop), daemon=True))
    ok(f"nfqueue_daemon PID={pkt.pid}")

    # ----- Layer 1 (flow) -----
    if not args.no_flow:
        step(f"startuję LAYER 1 — flow_monitor (RF na {args.iface})")
        flow_argv = [
            "python3", "-u", str(HERE / "flow_monitor.py"),
            "--iface", args.iface,
            "--block-mode", args.mode,
            "--chain", args.chain,
            "--ipset", DEFAULT_IPSET,
            "--block-threshold", str(args.threshold),
            "--events-log", args.events,
        ]
        if args.dry_run:
            flow_argv.append("--dry-run")
        flow = spawn("FLOW", C.GREEN, flow_argv)
        procs.append(("flow_monitor", flow))
        time.sleep(2.0)
        if flow.poll() is not None:
            fail(f"flow_monitor zakończył się natychmiast (rc={flow.returncode})")
            try:
                for line in flow.stdout:
                    sys.stdout.write(f"{c('[FLOW]', C.GREEN)} {line}")
            except Exception:
                pass
            cleanup(); return 1
        threads.append(threading.Thread(
            target=_stream, args=("FLOW", C.GREEN, flow, stop), daemon=True))
        ok(f"flow_monitor PID={flow.pid}")
    else:
        warn("Layer 1 pominięta (--no-flow)")

    # ----- iptables watcher -----
    if not args.dry_run and args.mode == "iptables":
        watcher = threading.Thread(target=watch_chain,
                                   args=(args.chain, stop), daemon=True)
        watcher.start()
        threads.append(watcher)

    for t in threads:
        if not t.is_alive():
            t.start()

    # ----- ready banner -----
    print()
    banner("SYSTEM URUCHOMIONY — czeka na ruch", C.GREEN)
    print(c("  Wysyłaj atakujący ruch (np. curl /search?q=' or 1=1--)", C.GRAY))
    print(c(f"  Każdy hit:        >>> PACKET DROPPED  src=...  hit n/{args.threshold}", C.GRAY))
    if args.threshold > 1:
        print(c(f"  Po {args.threshold} hitach:    ### FIREWALL RULE ADDED → iptables -A {args.chain} -s ...", C.GRAY))
    else:
        print(c(f"  Pierwszy hit:     ### FIREWALL RULE ADDED → iptables -A {args.chain} -s ...", C.GRAY))
    print(c(f"  Stan firewalla:   iptables -L {args.chain} -n --line-numbers", C.GRAY))
    print(c(f"  Log JSONL:        tail -f {args.events}", C.GRAY))
    print(c("  Zatrzymaj:        Ctrl+C", C.GRAY))
    print()

    # ----- block until any subprocess dies -----
    try:
        while not stop.is_set():
            for name, p in procs:
                if p.poll() is not None:
                    warn(f"{name} died (rc={p.returncode})")
                    cleanup(); return 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
