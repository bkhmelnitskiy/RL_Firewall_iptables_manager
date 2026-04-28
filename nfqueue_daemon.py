"""
Inline HTTP web-attack detector (NFQUEUE, Linux/WSL).

Pipeline per packet:
  kernel NFQUEUE → scapy parse → reassemble per-flow → on full HTTP request:
    extract_attack_surface() → SignatureCounter(web_attack_universal)
      → hit  : drop packet, add src IP to ipset (→ kernel-level DROP)
      → miss : accept packet, drop flow state

Design notes:
  - HTTP/1.1 only on port 80. HTTPS requires TLS termination upstream.
  - Fail-open on parse error (we'd rather pass a bad packet than kill legit).
  - Rate limit via ipset: ONE iptables rule references the set, we add/remove
    IPs with O(1) kernel ops and no iptables table explosion.
  - Naive per-flow buffer keyed by 4-tuple. Flushed when:
      * request complete (\r\n\r\n + optional Content-Length body bytes)
      * flow silent for FLOW_TIMEOUT_S
      * buffer exceeds MAX_FLOW_BYTES (DoS guard)

Setup (run as root on Linux/WSL):
  apt install libnetfilter-queue-dev ipset
  pip install NetfilterQueue scapy
  ipset create webattack_block hash:ip timeout 3600
  iptables -I INPUT -m set --match-set webattack_block src -j DROP
  iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
  python3 nfqueue_daemon.py
"""
from __future__ import annotations

import argparse
import json
import logging
import pickle
import re
import signal
import socket
import struct
import subprocess as sp
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from attack_signatures import SignatureCounter
from packet_preprocess import extract_attack_surface


# Default model names looked up in --ensemble-dir. Overridden at load time:
# the daemon scans the directory for *.pkl and uses each filename stem as the
# attack label, so switching from the 8-model E11 ensemble to the 3-model V2
# set (sqli/xss/cmd_injection) is a matter of pointing --ensemble-dir
# elsewhere — no code change.
PER_ATTACK = ["sqli", "xss", "cmd_injection", "path_traversal",
              "ldap_injection", "xpath_injection", "ssi"]


QUEUE_NUM = 0
IPSET_NAME = "rlfw_block"         # shared with flow_monitor.py (E13)
IPSET_TIMEOUT = 3600              # seconds IP stays blocked
FLOW_TIMEOUT_S = 10.0             # silent flow GC
MAX_FLOW_BYTES = 256 * 1024       # hard cap per flow buffer
GC_EVERY_N_PACKETS = 500
FIRED_FLOW_TTL = 5.0              # de-dup TCP retransmits on a fired 4-tuple
                                  # (curl resends the same payload after the
                                  # daemon's drop; without this, ONE attack
                                  # request counts as 3-4 hits)

CONTENT_LENGTH_RE = re.compile(rb"^content-length\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE)


log = logging.getLogger("nfqueue_daemon")


@dataclass
class FlowState:
    buf: bytearray = field(default_factory=bytearray)
    last_seen: float = field(default_factory=time.time)


class Blocker:
    """
    Maintains the kernel-side block list of attack source IPs.

    Two modes:
      * "iptables" (DEFAULT, demo-friendly): each blocked IP gets its own
        rule 'iptables -A RLFW_BLOCK -s IP -j DROP'. Visible in
        `iptables -L RLFW_BLOCK`. Easy to see live additions at a talk.
      * "ipset" (production): single iptables rule references
        'ipset rlfw_block hash:ip'; adds are O(1) via 'ipset add'.

    Every attack packet is always dropped at packet level. Blocker
    controls only whether (and when) the source IP graduates to a
    kernel-wide block.

    threshold=1 (default) → block on first hit.
    threshold=N>1         → count attempts; block on the N-th.
    """

    def __init__(self, setname: str, timeout: int, dry_run: bool = False,
                 threshold: int = 1, mode: str = "iptables",
                 chain: str = "RLFW_BLOCK"):
        self.setname = setname
        self.timeout = timeout
        self.dry_run = dry_run
        self.threshold = max(1, int(threshold))
        self.mode = mode
        self.chain = chain
        self._attempts: dict[str, int] = {}
        self._seen: set[str] = set()

    def block(self, src_ip: str, reason: str) -> None:
        if src_ip in self._seen:
            return
        n = self._attempts.get(src_ip, 0) + 1
        self._attempts[src_ip] = n

        log.warning(">>> PACKET DROPPED  src=%s  hit %d/%d  reason=%s",
                    src_ip, n, self.threshold, reason)

        if n < self.threshold:
            remaining = self.threshold - n
            log.warning("    IP not yet in firewall (need %d more hit%s to add iptables rule)",
                        remaining, "s" if remaining > 1 else "")
            return

        self._seen.add(src_ip)
        if self.dry_run:
            log.warning("    [dry-run] would add firewall rule for %s", src_ip)
            return

        if self.mode == "ipset":
            self._add_to_ipset(src_ip)
            log.warning("### FIREWALL UPDATED: ipset add %s %s timeout %d",
                        self.setname, src_ip, self.timeout)
        else:
            self._add_iptables_rule(src_ip)
            log.warning("### FIREWALL RULE ADDED: iptables -A %s -s %s -j DROP",
                        self.chain, src_ip)
            log.warning("    Verify with: iptables -L %s -n --line-numbers",
                        self.chain)

    def _add_iptables_rule(self, src_ip: str) -> None:
        try:
            sp.run(["iptables", "-A", self.chain, "-s", src_ip, "-j", "DROP"],
                   check=True, capture_output=True, text=True)
        except sp.CalledProcessError as exc:
            log.error("iptables -A %s -s %s failed: %s",
                      self.chain, src_ip, exc.stderr.strip())

    def _add_to_ipset(self, src_ip: str) -> None:
        try:
            sp.run(
                ["ipset", "add", self.setname, src_ip, "timeout", str(self.timeout), "-exist"],
                check=True, capture_output=True, text=True,
            )
        except FileNotFoundError:
            log.error("ipset missing — falling back to iptables rule")
            self._add_iptables_rule(src_ip)
        except sp.CalledProcessError as exc:
            log.error("ipset add failed for %s: %s", src_ip, exc.stderr.strip())


def parse_ip_tcp(data: bytes) -> tuple[str, str, int, int, bytes] | None:
    """
    Manual IPv4 + TCP header parser. Returns (src, dst, sport, dport, payload)
    or None for non-IPv4 / non-TCP / malformed.

    Replaces scapy `IP(data)` on the hot path because scapy's lazy layer
    construction takes ~10-100ms per packet in WSL — a moderate attack
    storm (curl retransmits) starves benign traffic. struct.unpack is
    microseconds and that's all we need (src/sport/dst/dport + TCP payload).
    """
    if len(data) < 20:
        return None
    vihl = data[0]
    if (vihl >> 4) != 4:        # IPv4 only
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl + 20:
        return None
    if data[9] != 6:            # TCP protocol number
        return None
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    sport, dport = struct.unpack("!HH", data[ihl:ihl + 4])
    data_off = (data[ihl + 12] >> 4) * 4
    if data_off < 20 or len(data) < ihl + data_off:
        return None
    payload = bytes(data[ihl + data_off:])
    return src, dst, sport, dport, payload


def request_is_complete(buf: bytes) -> bool:
    """True once we have headers + (if Content-Length) the full body."""
    sep = buf.find(b"\r\n\r\n")
    if sep < 0:
        return False
    headers = buf[:sep]
    body_len = len(buf) - (sep + 4)
    m = CONTENT_LENGTH_RE.search(headers)
    if m is None:
        return True
    try:
        expected = int(m.group(1))
    except ValueError:
        return True
    return body_len >= expected


def fire_signatures(sc: SignatureCounter, surface: bytes) -> int:
    try:
        text = surface.decode("latin-1", errors="replace")
    except Exception:
        return 0
    return int(sc.transform([text]).sum())


class Daemon:
    def __init__(self, blocker: Blocker, dry_run: bool = False,
                 ensemble_dir: str | None = None,
                 events_log: str | None = None):
        self.sc = SignatureCounter("web_attack_universal")
        self.ensemble: dict[str, object] = {}
        if ensemble_dir:
            md = Path(ensemble_dir)
            # Auto-enumerate *.pkl in directory. Filename stem = attack label.
            # Skips known non-model files (e.g. results.json, *.log).
            pkls = sorted(md.glob("*.pkl"))
            if not pkls:
                log.warning("ensemble dir has no *.pkl: %s", md)
            for p in pkls:
                attack = p.stem
                try:
                    with open(p, "rb") as f:
                        self.ensemble[attack] = pickle.load(f)
                    log.info("loaded ensemble model %s (%s)", attack, p)
                except Exception as exc:
                    log.warning("failed to load %s: %s", p, exc)
        self.flows: dict[tuple, FlowState] = {}
        self.fired_flows: dict[tuple, float] = {}   # 4-tuple → fired-at ts
        self.blocker = blocker
        self.dry_run = dry_run
        self.events_log = events_log
        self.packets_seen = 0
        self.requests_scanned = 0
        self.hits = 0

    # -------- flow bookkeeping --------

    def _gc(self, now: float) -> None:
        stale = [k for k, fs in self.flows.items() if now - fs.last_seen > FLOW_TIMEOUT_S]
        for k in stale:
            self.flows.pop(k, None)
        stale_fired = [k for k, t in self.fired_flows.items()
                       if now - t > FIRED_FLOW_TTL]
        for k in stale_fired:
            self.fired_flows.pop(k, None)

    # -------- main per-packet callback --------

    def callback(self, nfpkt) -> None:
        self.packets_seen += 1
        if self.packets_seen % GC_EVERY_N_PACKETS == 0:
            self._gc(time.time())

        try:
            verdict = self._inspect(nfpkt)
        except Exception as exc:
            log.debug("inspect failed, fail-open: %s", exc)
            verdict = "accept"

        if verdict == "drop":
            nfpkt.drop()
        else:
            nfpkt.accept()

    def _inspect(self, nfpkt) -> str:
        parsed = parse_ip_tcp(nfpkt.get_payload())
        if parsed is None:
            return "accept"
        src_ip, dst_ip, sport, dport, payload = parsed
        key = (src_ip, sport, dst_ip, dport)

        # If this 4-tuple already fired recently, treat any further packet on
        # the same connection as a TCP retransmit of the attack payload —
        # drop it silently without re-scanning or bumping the block counter.
        fired_at = self.fired_flows.get(key)
        if fired_at is not None and (time.time() - fired_at) < FIRED_FLOW_TTL:
            return "drop" if not self.dry_run else "accept"

        if not payload:                # SYN, ACK, FIN — no HTTP yet
            return "accept"

        fs = self.flows.get(key)
        if fs is None:
            fs = FlowState()
            self.flows[key] = fs
        fs.buf.extend(payload)
        fs.last_seen = time.time()

        if len(fs.buf) > MAX_FLOW_BYTES:
            self.flows.pop(key, None)
            return "accept"

        if not request_is_complete(bytes(fs.buf)):
            return "accept"

        try:
            surface = extract_attack_surface(bytes(fs.buf))
        except Exception as exc:
            log.debug("extract_attack_surface failed: %s", exc)
            self.flows.pop(key, None)
            return "accept"

        self.requests_scanned += 1
        self.flows.pop(key, None)

        n_hits = fire_signatures(self.sc, surface)
        ensemble_labels: list[str] = []
        if self.ensemble:
            text = surface.decode("latin-1", errors="replace")
            for name, mdl in self.ensemble.items():
                try:
                    if int(mdl.predict([text])[0]) == 1:
                        ensemble_labels.append(name)
                except Exception as exc:
                    log.debug("ensemble model %s failed: %s", name, exc)

        fired = (n_hits > 0) or bool(ensemble_labels)
        if not fired:
            return "accept"

        self.hits += 1
        snippet = surface[:120].decode("latin-1", errors="replace")
        if ensemble_labels:
            reason = f"ensemble={'+'.join(ensemble_labels)} rule_hits={n_hits}"
        else:
            reason = f"web_attack_universal hits={n_hits}"
        log.info("HIT src=%s %s surface=%r", src_ip, reason, snippet)
        self.fired_flows[key] = time.time()   # suppress retransmit rescans
        self.blocker.block(src_ip, reason=reason)
        self._append_event(src_ip, reason, ensemble_labels, n_hits)
        return "drop" if not self.dry_run else "accept"

    def _append_event(self, src_ip: str, reason: str,
                      labels: list[str], n_hits: int) -> None:
        if not self.events_log:
            return
        ev = {
            "ts":       time.strftime("%Y-%m-%dT%H:%M:%S"),
            "layer":    "packet",
            "src_ip":   src_ip,
            "label":    "+".join(labels) if labels else "web_attack_universal",
            "rule_hits": n_hits,
            "reason":   reason,
        }
        try:
            with open(self.events_log, "a") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception as exc:
            log.debug("events log append failed: %s", exc)


def run(args: argparse.Namespace) -> int:
    # Imported here so --help works without netfilterqueue installed.
    try:
        from netfilterqueue import NetfilterQueue  # type: ignore
    except ImportError:
        log.error("NetfilterQueue not installed. pip install NetfilterQueue scapy (Linux/WSL only)")
        return 1

    blocker = Blocker(args.ipset, args.ipset_timeout, dry_run=args.dry_run,
                      threshold=args.block_threshold,
                      mode=args.block_mode, chain=args.chain)
    daemon = Daemon(blocker, dry_run=args.dry_run,
                    ensemble_dir=args.ensemble_dir,
                    events_log=args.events_log)

    nfq = NetfilterQueue()
    # max_len=8192: under attack, TCP retransmits + multiple parallel attackers
    # can flood the default 1024-deep queue and starve benign traffic.
    try:
        nfq.bind(args.queue, daemon.callback, max_len=8192)
    except TypeError:
        # older NetfilterQueue without max_len kwarg
        nfq.bind(args.queue, daemon.callback)
    log.info("Listening on NFQUEUE %d (dry-run=%s)", args.queue, args.dry_run)

    def _stop(_sig, _frm):
        log.info("stopping — seen=%d scanned=%d hits=%d flows=%d",
                 daemon.packets_seen, daemon.requests_scanned, daemon.hits, len(daemon.flows))
        nfq.unbind()
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    try:
        nfq.run()
    finally:
        nfq.unbind()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Inline HTTP attack detector via NFQUEUE")
    ap.add_argument("--queue", type=int, default=QUEUE_NUM)
    ap.add_argument("--ipset", default=IPSET_NAME)
    ap.add_argument("--ipset-timeout", type=int, default=IPSET_TIMEOUT)
    ap.add_argument("--dry-run", action="store_true",
                    help="Log hits but always accept packets (no DROP, no ipset add).")
    ap.add_argument("--block-threshold", type=int, default=1,
                    help="Number of attacks from same src IP before ipset block. "
                         "Packets are always dropped per-hit; this only delays "
                         "the kernel-side IP block. Default 1 (block on first).")
    ap.add_argument("--block-mode", default="iptables",
                    choices=["iptables", "ipset"],
                    help="iptables (default): per-IP rules in RLFW_BLOCK chain "
                         "(visible in iptables -L). ipset: single hash-based "
                         "rule (scales better, less visible).")
    ap.add_argument("--chain", default="RLFW_BLOCK",
                    help="iptables chain receiving DROP rules (mode=iptables).")
    ap.add_argument("--ensemble-dir", default=None,
                    help="Optional directory with per-attack .pkl models (sqli.pkl, xss.pkl, ...). "
                         "When set, each request runs through every model in addition to rule-based "
                         "universal; ANY hit from any source drops. Label logged shows which attack(s) fired.")
    ap.add_argument("--events-log", default=None,
                    help="Append JSONL events here (shared with flow_monitor for correlation).")
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = ap.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
