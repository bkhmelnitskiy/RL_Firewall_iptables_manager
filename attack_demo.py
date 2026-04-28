"""
Generator ataków do prezentacji RL_FIREWALL_IPTABLES.

Wysyła kontrolowane payloady do lokalnego targetu, żeby pokazać widowni:
  1. Każdy atakujący request → daemon loguje "PACKET DROPPED" (curl: timeout).
  2. Po przekroczeniu thresholdu → reguła pojawia się w iptables i każda
     kolejna próba z tego IP umiera od razu na kernel-side DROP.

Użycie (drugi terminal, podczas gdy `sudo python3 rlfw.py --demo` leci):

    python3 attack_demo.py                # menu interaktywne (PL)
    python3 attack_demo.py --all          # wszystkie ataki po kolei z pauzą
    python3 attack_demo.py sqli           # pojedynczy typ
    python3 attack_demo.py sqli xss path  # wybrane
    python3 attack_demo.py --target 192.168.1.10:80 sqli
    python3 attack_demo.py --repeat 5 sqli   # 5× pod rząd (pokaż threshold)

Typy ataków (Layer 2 — sygnaturowy):
    sqli, xss, path, cmd, ldap, xpath, ssi, scanner

Layer 1 (flow-based RF):
    brute   — symulacja bruteforce loginu (200 prób, długie połączenia)

`benign` wysyła normalny request — nie powinien być zdropowany.
"""
from __future__ import annotations

import argparse
import itertools
import os
import re
import socket
import subprocess as sp
import sys
import time
import urllib.parse
from dataclasses import dataclass


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


COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, color: str) -> str:
    return f"{color}{text}{C.RESET}" if COLOR else text


def banner(line: str, color: str = C.CYAN) -> None:
    bar = "─" * 64
    print()
    print(c(bar, color))
    print(c(f"  {line}", color + (C.BOLD if COLOR else "")))
    print(c(bar, color))


# ---------- attack catalog ----------

@dataclass
class Attack:
    key: str
    name_pl: str
    explanation_pl: str
    method: str               # "GET" or "POST" or "RAW"
    path: str | None = None   # for GET/POST
    body: str | None = None   # for POST
    raw: bytes | None = None  # for RAW (bypass curl)


def _q(s: str) -> str:
    """URL-encode a payload so curl doesn't choke on spaces / special chars."""
    return urllib.parse.quote(s, safe="")


ATTACKS: dict[str, Attack] = {
    "benign": Attack(
        key="benign",
        name_pl="BENIGN — normalny request",
        explanation_pl="Zwykły GET. Nie powinien być zdropowany — pokazuje "
                       "że firewall nie blokuje legitnego ruchu.",
        method="GET",
        path="/",
    ),
    "sqli": Attack(
        key="sqli",
        name_pl="SQL INJECTION",
        explanation_pl="Klasyczne `' or 1=1--` w parametrze. Sygnatury "
                       "web_attack_universal łapią tautologię + kometarz SQL.",
        method="GET",
        path=f"/search?id={_q(chr(39) + ' or 1=1--')}",
    ),
    "xss": Attack(
        key="xss",
        name_pl="CROSS-SITE SCRIPTING (XSS)",
        explanation_pl="Reflected XSS — `<script>alert(1)</script>` w query. "
                       "Sygnatura wyłapuje `<script` po URL-decode.",
        method="GET",
        path=f"/profile?name={_q('<script>alert(1)</script>')}",
    ),
    "path": Attack(
        key="path",
        name_pl="PATH TRAVERSAL",
        explanation_pl="`../../../../etc/passwd` — próba wyjścia poza katalog "
                       "webroot. Sygnatura matchuje sekwencję `../` + `/etc/`.",
        method="GET",
        path=f"/file?f={_q('../../../../etc/passwd')}",
    ),
    "cmd": Attack(
        key="cmd",
        name_pl="COMMAND INJECTION",
        explanation_pl="`;cat /etc/passwd` doklejone do parametru — próba "
                       "uruchomienia shella przez aplikację webową.",
        method="GET",
        path=f"/exec?cmd={_q(';cat /etc/passwd')}",
    ),
    "ldap": Attack(
        key="ldap",
        name_pl="LDAP INJECTION",
        explanation_pl="Zaburzenie filtra LDAP `(|(uid=*))` — bypass "
                       "autentykacji w aplikacjach używających LDAP.",
        method="GET",
        path=f"/login?user={_q('admin)(|(uid=*))')}",
    ),
    "xpath": Attack(
        key="xpath",
        name_pl="XPATH INJECTION",
        explanation_pl="`' or '1'='1` w XPath query — analogiczne do SQLi, "
                       "ale dla baz XML/XSLT.",
        method="GET",
        path=f"/xml?q={_q(chr(39) + ' or ' + chr(39) + '1' + chr(39) + '=' + chr(39) + '1')}",
    ),
    "ssi": Attack(
        key="ssi",
        name_pl="SERVER-SIDE INCLUDES (SSI)",
        explanation_pl='`<!--#exec cmd="ls"-->` — wstrzyknięcie SSI dyrektywy '
                       "wykonującej polecenie systemowe.",
        method="GET",
        path=f"/page?body={_q(chr(60) + '!--#exec cmd=' + chr(34) + 'ls' + chr(34) + '-->')}",
    ),
    "scanner": Attack(
        key="scanner",
        name_pl="SCANNER (nikto/nessus fingerprint)",
        explanation_pl="Request z User-Agent skanera + ścieżka `.nasl` — "
                       "klasyczny ślad automatycznych skanerów podatności.",
        method="RAW",
        raw=(b"GET /xss?test=cross_site_scripting.nasl HTTP/1.1\r\n"
             b"Host: localhost\r\n"
             b"User-Agent: Nessus SOAP\r\n"
             b"\r\n"),
    ),
}


# ---------- source IP discovery + rotation ----------

LO_ALIAS_RE = re.compile(r"inet\s+(10\.0\.0\.\d+)/")


def discover_lo_aliases() -> list[str]:
    """Return 10.0.0.X aliases currently bound to lo. Excludes 127.0.0.1."""
    res = sp.run(["ip", "-4", "addr", "show", "lo"],
                 capture_output=True, text=True)
    if res.returncode != 0:
        return []
    return LO_ALIAS_RE.findall(res.stdout)


# ---------- request senders ----------

def send_curl(method: str, target: str, path: str,
              src_ip: str | None,
              body: str | None = None,
              timeout: float = 3.0) -> tuple[int, str]:
    """Returns (return_code, short_status). 0 = HTTP response received."""
    url = f"http://{target}{path}"
    cmd = ["curl", "-sS", "-o", "/dev/null",
           "-w", "%{http_code} time=%{time_total}s",
           "--max-time", str(timeout),
           "-X", method, url]
    if src_ip:
        cmd += ["--interface", src_ip]
    if body is not None:
        cmd += ["-d", body, "-H", "Content-Type: application/x-www-form-urlencoded"]
    res = sp.run(cmd, capture_output=True, text=True)
    return res.returncode, (res.stdout or res.stderr).strip()


def send_raw(target: str, raw: bytes, src_ip: str | None,
             timeout: float = 3.0) -> tuple[int, str]:
    host, _, port_s = target.partition(":")
    port = int(port_s or 80)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if src_ip:
            s.bind((src_ip, 0))
        s.connect((host, port))
        try:
            s.sendall(raw)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 4096:
                    break
        finally:
            s.close()
        first = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        return 0, first or "(empty response)"
    except socket.timeout:
        return 28, "timeout (pakiet zdropowany przez daemon)"
    except OSError as exc:
        return 7, f"connection refused/error: {exc}"


def perform(attack: Attack, target: str, src_ip: str | None,
            timeout: float) -> None:
    src_label = f"src={src_ip}" if src_ip else "src=127.0.0.1 (default)"
    print(c(f"  źródło ataku: {src_label}", C.MAGENTA))
    if attack.method == "RAW":
        assert attack.raw is not None
        # human-readable preview of the raw bytes
        preview = attack.raw.decode("latin-1", errors="replace").rstrip()
        print(c("  RAW request:", C.GRAY))
        for line in preview.splitlines():
            print(c(f"    {line}", C.GRAY))
        rc, status = send_raw(target, attack.raw, src_ip, timeout)
    else:
        url = f"http://{target}{attack.path}"
        body_part = f" -d {attack.body!r}" if attack.body else ""
        iface_part = f" --interface {src_ip}" if src_ip else ""
        print(c(f"  $ curl --max-time {timeout}{iface_part} -X {attack.method} '{url}'{body_part}", C.GRAY))
        rc, status = send_curl(attack.method, target, attack.path or "/",
                               src_ip, attack.body, timeout)

    if rc == 0:
        if status.startswith("000"):
            print(c(f"  ↳ rc={rc}  status={status}  (target nie odpowiedział)", C.YELLOW))
        else:
            print(c(f"  ↳ {status}", C.GREEN))
    elif rc == 28:
        print(c(f"  ↳ rc=28 TIMEOUT  →  pakiet ZDROPOWANY przez daemon "
                "(sprawdź log [PKT])", C.YELLOW))
    elif rc == 7:
        print(c(f"  ↳ rc=7 CONNECTION REFUSED  →  IP już w iptables "
                "(kernel-side DROP)", C.RED))
    else:
        print(c(f"  ↳ rc={rc}  {status}", C.RED))


# ---------- brute-force (Layer 1) ----------

def run_brute(target: str, attempts: int = 50, hold: float = 2.0,
              workers: int = 5) -> None:
    import http.client
    import random
    import string
    import threading

    host, _, port_s = target.partition(":")
    port = int(port_s or 80)

    def attempt(i: int) -> None:
        pwd = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        body = f"username=admin&password={pwd}".encode()
        try:
            conn = http.client.HTTPConnection(host, port, timeout=4)
            conn.request("POST", "/login", body=body, headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
                "Connection": "keep-alive",
            })
            resp = conn.getresponse()
            resp.read()
            time.sleep(hold)        # keep flow open — Layer 1 RF needs duration
            conn.close()
            print(c(f"  [{i:03d}] HTTP {resp.status}  pwd={pwd}", C.GRAY))
        except Exception as exc:
            print(c(f"  [{i:03d}] error: {exc}", C.YELLOW))

    sem = threading.Semaphore(workers)
    def worker(i: int) -> None:
        with sem:
            attempt(i)

    print(c(f"  bruteforce → http://{target}/login  ({attempts} attempts, "
            f"{workers} workers, hold {hold}s)", C.GRAY))
    print(c("  (Layer 1 RF potrzebuje czasu — flowy muszą się zakończyć.)", C.GRAY))
    threads = [__import__("threading").Thread(target=worker, args=(i,), daemon=True)
               for i in range(1, attempts + 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ---------- top-level orchestration ----------

class SourcePool:
    """Cycles through a list of source IPs (or yields None to use default lo)."""

    def __init__(self, ips: list[str], rotate: bool):
        self.ips = ips
        self.rotate = rotate and bool(ips)
        self._cycle = itertools.cycle(ips) if self.ips else None
        self._fixed: str | None = None

    def set_fixed(self, ip: str | None) -> None:
        """Force a single source IP (None = back to rotation/default)."""
        self._fixed = ip

    def next(self) -> str | None:
        if self._fixed is not None:
            return self._fixed
        if self.rotate and self._cycle is not None:
            return next(self._cycle)
        return None

    def describe(self) -> str:
        if self._fixed is not None:
            return f"fixed {self._fixed}"
        if self.rotate:
            return f"rotacja po {len(self.ips)} aliasach lo ({self.ips[0]}…{self.ips[-1]})"
        return "127.0.0.1 (brak aliasów)"


def show_attack(key: str, target: str, pool: SourcePool,
                timeout: float, pause: bool) -> None:
    if key == "brute":
        banner("BRUTE-FORCE  (Layer 1 — flow RF)", C.MAGENTA)
        print(c("  Long-held POST flows do /login, 50 prób równolegle.", C.GRAY))
        run_brute(target)
        return

    a = ATTACKS.get(key)
    if a is None:
        print(c(f"  Nieznany typ ataku: {key}", C.RED))
        return

    color = C.GREEN if key == "benign" else C.YELLOW
    banner(a.name_pl, color)
    print(c(f"  {a.explanation_pl}", C.GRAY))
    perform(a, target, pool.next(), timeout)
    if pause:
        try:
            input(c("\n  [enter] dalej, [ctrl+c] stop  ", C.CYAN))
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)


def menu(target: str, pool: SourcePool, timeout: float) -> None:
    items = [("0", "benign",  "BENIGN — normalny request (pokaz że NIE blokujemy)"),
             ("1", "sqli",    "SQL Injection"),
             ("2", "xss",     "Cross-Site Scripting"),
             ("3", "path",    "Path Traversal"),
             ("4", "cmd",     "Command Injection"),
             ("5", "ldap",    "LDAP Injection"),
             ("6", "xpath",   "XPath Injection"),
             ("7", "ssi",     "Server-Side Includes"),
             ("8", "scanner", "Scanner fingerprint (nikto/nessus)"),
             ("9", "brute",   "Brute-force /login  (Layer 1 — flow RF)"),
             ("a", "all",     "WSZYSTKIE ataki Layer 2 po kolei"),
             ("r", "repeat",  "Powtórz ostatni atak N razy (pokaz thresholdu)"),
             ("s", "src",     "Zmień źródłowy adres IP"),
             ("q", "quit",    "Wyjdź")]
    last = None
    while True:
        banner(f"MENU  →  cel: {target}   źródło: {pool.describe()}")
        for ch, _, label in items:
            print(c(f"  [{ch}]  {label}", C.CYAN))
        try:
            choice = input(c("\n  wybierz: ", C.CYAN)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        m = {ch: key for ch, key, _ in items}
        key = m.get(choice)
        if key == "quit" or key is None:
            return
        if key == "src":
            try:
                ans = input(c("  IP źródła (puste = rotacja/default): ",
                              C.CYAN)).strip()
            except (EOFError, KeyboardInterrupt):
                print(); continue
            pool.set_fixed(ans or None)
            continue
        if key == "all":
            for k in ["benign", "sqli", "xss", "path", "cmd", "ldap",
                      "xpath", "ssi", "scanner"]:
                show_attack(k, target, pool, timeout, pause=True)
                last = k
            continue
        if key == "repeat":
            if not last:
                print(c("  Najpierw odpal jakiś atak.", C.YELLOW))
                continue
            try:
                n = int(input(c("  ile razy? [5]: ", C.CYAN)).strip() or "5")
            except ValueError:
                n = 5
            for i in range(n):
                print(c(f"\n  ── powtórzenie {i+1}/{n} ──", C.MAGENTA))
                show_attack(last, target, pool, timeout, pause=False)
                time.sleep(0.4)
            continue
        show_attack(key, target, pool, timeout, pause=False)
        last = key


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Demo attack generator dla RL_FIREWALL_IPTABLES.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("attacks", nargs="*",
                    help="Lista typów ataków do odpalenia (puste = menu). "
                         f"Dostępne: {', '.join(list(ATTACKS) + ['brute'])}")
    ap.add_argument("--target", default="127.0.0.1:80",
                    help="host:port targetu (default 127.0.0.1:80).")
    ap.add_argument("--timeout", type=float, default=1.5,
                    help="curl --max-time / socket timeout (default 1.5s — "
                         "krótko, żeby ograniczyć ilość retransmitów per atak "
                         "i nie zatkać kolejki NFQUEUE).")
    ap.add_argument("--all", action="store_true",
                    help="Odpal wszystkie ataki Layer 2 z pauzami.")
    ap.add_argument("--repeat", type=int, default=1,
                    help="Powtórz każdy wybrany atak N razy (pokaz thresholdu).")
    ap.add_argument("--src", default=None, metavar="IP",
                    help="Wymuś jeden source IP zamiast rotacji.")
    ap.add_argument("--pool", default=None, metavar="IP1,IP2,...",
                    help="Pula źródłowych IP do rotacji "
                         "(default: auto-wykryte aliasy 10.0.0.X na lo).")
    ap.add_argument("--no-rotate", action="store_true",
                    help="Wyłącz rotację — wszystko z 127.0.0.1.")
    args = ap.parse_args()

    if args.pool:
        ips = [x.strip() for x in args.pool.split(",") if x.strip()]
    else:
        ips = discover_lo_aliases()
    pool = SourcePool(ips, rotate=not args.no_rotate)
    if args.src:
        pool.set_fixed(args.src)

    if not ips and not args.src and not args.no_rotate:
        print(c("  UWAGA: brak aliasów lo (10.0.0.X) — wszystkie ataki polecą "
                "z 127.0.0.1, więc po pierwszej blokadzie nie pokażesz kolejnych.",
                C.YELLOW))
        print(c("  Odpal firewall z `--lo-aliases 10`, albo podaj `--pool a,b,c`.",
                C.YELLOW))
        print()

    if args.all:
        for k in ["benign", "sqli", "xss", "path", "cmd", "ldap",
                  "xpath", "ssi", "scanner"]:
            for _ in range(args.repeat):
                show_attack(k, args.target, pool, args.timeout, pause=False)
                time.sleep(0.3)
        return 0

    if not args.attacks:
        menu(args.target, pool, args.timeout)
        return 0

    for k in args.attacks:
        for _ in range(args.repeat):
            show_attack(k, args.target, pool, args.timeout, pause=False)
            time.sleep(0.3)
    return 0


if __name__ == "__main__":
    sys.exit(main())
