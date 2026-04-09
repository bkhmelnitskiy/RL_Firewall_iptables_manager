import subprocess as sp
from pathlib import Path
from typing import Literal

import pandas as pd



class Rule:
    def __init__(
        self,
        chain: str,
        source: str,
        destination: str,
        protocol: str,
        port: int,
        action: Literal["ACCEPT", "DROP"],
    ):
        self.chain       = chain
        self.source      = source
        self.destination = destination
        self.protocol    = protocol
        self.port        = port
        self.action      = action

    def to_iptables_args(self) -> list[str]:
        args: list[str] = []
        if self.source:
            args += ["-s", self.source]
        if self.destination:
            args += ["-d", self.destination]
        if self.protocol:
            args += ["-p", self.protocol]
        if self.port:
            args += ["--dport", str(self.port)]
        args += ["-j", self.action]
        return args

    def summary(self) -> str:
        return (
            f"{self.source} → {self.destination} "
            f"| {self.protocol}:{self.port} | {self.action}"
        )



class FirewallManager:
    def __init__(self):
        self._rules: list[Rule] = []

    def _iptables(self, args: list[str]) -> None:
        sp.run(["sudo", "iptables"] + args, check=True, capture_output=True, text=True)

    def append_rule(self, rule: Rule) -> None:
        self._iptables(["-A", rule.chain] + rule.to_iptables_args())
        self._rules.append(rule)

    def delete_rule(self, chain: str, rule: Rule | None = None, index: int | None = None) -> None:
        if index is not None:
            if index < 1:
                raise ValueError("iptables rule index starts at 1")
            self._iptables(["-D", chain, str(index)])
            if index <= len(self._rules):
                del self._rules[index - 1]
            return
        if rule is None:
            raise ValueError("Provide rule or index")
        self._iptables(["-D", chain] + rule.to_iptables_args())
        self._rules = [r for r in self._rules if not _rule_eq(r, rule)]

    def list_rules(self, chain: str = "INPUT") -> None:
        result = sp.run(
            ["sudo", "iptables", "-L", chain, "--line-numbers", "-n"],
            capture_output=True, text=True,
        )
        print(result.stdout or result.stderr)

    def flush_chain(self, chain: str = "INPUT") -> None:
        self._iptables(["-F", chain])
        self._rules.clear()


def _rule_eq(a: Rule, b: Rule) -> bool:
    return (
        a.chain == b.chain and a.source == b.source
        and a.destination == b.destination and a.protocol == b.protocol
        and a.port == b.port and a.action == b.action
    )



_BLOCKED: set[str] = set()   


def enforce_attacks(
    attacks: list[dict],
    chain: str = "INPUT",
) -> int:
    if not attacks:
        return 0

    fw = FirewallManager()
    added = 0

    for attack in attacks:
        src_ip = attack["src_ip"]
        if src_ip in _BLOCKED:
            continue

        rule = Rule(
            chain=chain,
            source=src_ip,
            destination=attack.get("dst_ip", ""),
            protocol=attack.get("protocol", "tcp"),
            port=attack.get("dst_port", 0),
            action="DROP",
        )
        try:
            fw.append_rule(rule)
            _BLOCKED.add(src_ip)
            label  = attack.get("label", "ATTACK")
            reason = attack.get("reason", "?")
            count  = attack.get("count", "")
            count_str = f" [{count} flows]" if count else ""
            print(f"  [BLOCKED] [{label}] [{reason}]{count_str} {rule.summary()}")
            added += 1
        except sp.CalledProcessError as exc:
            print(f"  [ERROR] iptables failed for {src_ip}: {exc.stderr.strip()}")

    return added



_PROTOCOL_MAP = {6: "tcp", 17: "udp"}


def enforce_predictions(
    predictions_path: str | Path = "prediction.csv",
    chain: str = "INPUT",
    processed_rows: int = 0,
) -> int:
    path = Path(predictions_path)
    if not path.exists():
        return processed_rows

    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()

    pred_col = "ml_prediction" if "ml_prediction" in df.columns else "prediction"
    new_rows = df.iloc[processed_rows:]

    if new_rows.empty:
        print("No new predictions to process.")
        return processed_rows

    attacks_df = new_rows[new_rows[pred_col].str.upper() != "BENIGN"]
    if attacks_df.empty:
        print(f"Checked {len(new_rows)} rows — no attacks.")
        return processed_rows + len(new_rows)

    dst_col  = next((c for c in df.columns if c.lower() in ("dst_port", "destination port")), None)
    prot_col = next((c for c in df.columns if c.lower() == "protocol"), None)

    attack_dicts = []
    seen: set[str] = set()
    for _, row in attacks_df.iterrows():
        src_ip   = str(row.get("src_ip", "")).strip()
        dst_ip   = str(row.get("dst_ip", "")).strip()
        dst_port = int(row[dst_col])  if dst_col  and pd.notna(row[dst_col])  else 0
        protocol = _PROTOCOL_MAP.get(int(row[prot_col]), "tcp") if prot_col and pd.notna(row[prot_col]) else "tcp"
        label    = str(row[pred_col]).strip()

        if src_ip in seen:
            continue
        seen.add(src_ip)
        attack_dicts.append({
            "src_ip": src_ip, "dst_ip": dst_ip,
            "dst_port": dst_port, "protocol": protocol,
            "label": label, "reason": "ml",
        })

    enforce_attacks(attack_dicts, chain=chain)
    return processed_rows + len(new_rows)


if __name__ == "__main__":
    enforce_predictions()
