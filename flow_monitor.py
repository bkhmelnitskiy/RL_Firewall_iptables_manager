"""
Layer-1 (flow-based) continuous network monitor.

Subscribes to the cicflowmeter FlowSession on a network interface. Each
completed flow is scored by MLDetector (Random Forest trained on
CICIDS2017 flow statistics). On non-benign prediction:
    - add src IP to the shared `rlfw_block` ipset (same set as the
      packet-layer daemon uses — ONE iptables DROP rule blocks both)
    - append a JSONL event to the unified log so operators can correlate
      flow- and packet-layer decisions

Usage (Linux/WSL, root):
    python3 flow_monitor.py --iface eth0
    python3 flow_monitor.py --iface lo --block-threshold 3 --dry-run
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import subprocess as sp
import sys
import time
from pathlib import Path

import pandas as pd

# cicflowmeter is vendored under ./cicflowmeter/src
sys.path.insert(0, str(Path(__file__).parent / "cicflowmeter" / "src"))

from cicflowmeter.sniffer import create_sniffer  # noqa: E402

from detector import MLDetector  # noqa: E402


log = logging.getLogger("flow_monitor")


class Blocker:
    """Same semantics as nfqueue_daemon.Blocker — iptables or ipset mode."""

    def __init__(self, setname: str, timeout: int, threshold: int = 1,
                 dry_run: bool = False, mode: str = "iptables",
                 chain: str = "RLFW_BLOCK"):
        self.setname = setname
        self.timeout = timeout
        self.threshold = max(1, int(threshold))
        self.dry_run = dry_run
        self.mode = mode
        self.chain = chain
        self._attempts: dict[str, int] = {}
        self._seen: set[str] = set()

    def block(self, src_ip: str, reason: str) -> None:
        if src_ip in self._seen:
            return
        n = self._attempts.get(src_ip, 0) + 1
        self._attempts[src_ip] = n

        log.warning(">>> FLOW ATTACK DETECTED  src=%s  hit %d/%d  reason=%s",
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
            try:
                sp.run(
                    ["ipset", "add", self.setname, src_ip,
                     "timeout", str(self.timeout), "-exist"],
                    check=True, capture_output=True, text=True,
                )
                log.warning("### FIREWALL UPDATED: ipset add %s %s timeout %d",
                            self.setname, src_ip, self.timeout)
            except (FileNotFoundError, sp.CalledProcessError) as exc:
                log.error("ipset add failed: %s — falling back to iptables", exc)
                self._iptables_add(src_ip)
        else:
            self._iptables_add(src_ip)
            log.warning("### FIREWALL RULE ADDED: iptables -A %s -s %s -j DROP",
                        self.chain, src_ip)
            log.warning("    Verify with: iptables -L %s -n --line-numbers",
                        self.chain)

    def _iptables_add(self, src_ip: str) -> None:
        try:
            sp.run(["iptables", "-A", self.chain, "-s", src_ip, "-j", "DROP"],
                   check=True, capture_output=True, text=True)
        except sp.CalledProcessError as exc:
            log.error("iptables -A %s -s %s failed: %s",
                      self.chain, src_ip, exc.stderr.strip())


class MLBlockerWriter:
    """
    OutputWriter-compatible (has .write(data: dict)). Replaces the default
    CSV/HTTP writer on FlowSession so each completed flow goes straight
    to the ML detector instead of disk.
    """

    def __init__(self, detector: MLDetector, blocker: Blocker,
                 event_log: str | None = None):
        self.detector = detector
        self.blocker = blocker
        self.event_log = event_log
        self.flows_seen = 0
        self.hits = 0

    def write(self, data: dict) -> None:
        self.flows_seen += 1
        try:
            df = pd.DataFrame([data])
            attacks = self.detector.check(df)
        except Exception as exc:
            log.debug("detector failed for flow: %s", exc)
            return

        for a in attacks:
            self.hits += 1
            src = str(a.get("src_ip", "")).strip()
            label = str(a.get("label", "ATTACK")).strip()
            dst = a.get("dst_ip", "")
            dport = a.get("dst_port", 0)
            log.warning("FLOW HIT src=%s label=%s dst=%s:%s",
                        src, label, dst, dport)
            self.blocker.block(src, reason=f"flow:{label}")
            self._append_event(src, label, dst, dport)

    def _append_event(self, src: str, label: str, dst: str, dport) -> None:
        if not self.event_log:
            return
        ev = {
            "ts":       time.strftime("%Y-%m-%dT%H:%M:%S"),
            "layer":    "flow",
            "src_ip":   src,
            "dst_ip":   dst,
            "dst_port": dport,
            "label":    label,
            "reason":   "ml-rf",
        }
        try:
            with open(self.event_log, "a") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception as exc:
            log.debug("event log append failed: %s", exc)


def main() -> int:
    ap = argparse.ArgumentParser(description="Layer-1 flow-based continuous monitor")
    ap.add_argument("--iface", required=True,
                    help="Network interface to sniff (e.g. eth0, lo)")
    ap.add_argument("--ipset", default="rlfw_block",
                    help="Shared ipset name (same as nfqueue_daemon default)")
    ap.add_argument("--ipset-timeout", type=int, default=3600)
    ap.add_argument("--block-threshold", type=int, default=1,
                    help="Flow-level attack attempts before block. Default 1.")
    ap.add_argument("--block-mode", default="iptables",
                    choices=["iptables", "ipset"],
                    help="iptables (default): per-IP rules in RLFW_BLOCK chain. "
                         "ipset: single-rule hash-based.")
    ap.add_argument("--chain", default="RLFW_BLOCK",
                    help="iptables chain (mode=iptables).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Log hits but do not touch ipset/iptables.")
    ap.add_argument("--events-log", default=None,
                    help="Append JSONL events here (shared with nfqueue_daemon).")
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = ap.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    log.info("loading MLDetector (flow-based Random Forest) ...")
    detector = MLDetector()
    blocker = Blocker(args.ipset, args.ipset_timeout,
                      args.block_threshold, args.dry_run,
                      mode=args.block_mode, chain=args.chain)
    writer = MLBlockerWriter(detector, blocker, args.events_log)

    # cicflowmeter insists on output_mode being set; we build with "csv"
    # to /dev/null then replace the writer on the session object.
    sniffer, session = create_sniffer(
        input_file=None,
        input_interface=args.iface,
        output_mode="csv",
        output="/dev/null",
        input_directory=None,
        fields=None,
        verbose=False,
    )
    session.output_writer = writer

    log.info("flow monitor listening on %s (ipset=%s threshold=%d dry_run=%s)",
             args.iface, args.ipset, args.block_threshold, args.dry_run)
    sniffer.start()

    def _stop(_sig=None, _frm=None):
        log.info("stopping — flows_seen=%d hits=%d",
                 writer.flows_seen, writer.hits)
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
        try:
            sniffer.stop()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    try:
        sniffer.join()
    finally:
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
        try:
            session.flush_flows()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
