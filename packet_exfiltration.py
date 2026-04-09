import csv
import subprocess
import sys
from pathlib import Path

import pandas as pd

from detector import MLDetector
from iptables_rules_generator import enforce_attacks


INTERFACE       = "eth0"
CAPTURE_SECONDS = 30

PCAP_FILE    = Path("dump.pcap")
CYCLE_CSV    = Path("dump_cycle.csv")
OUTPUT_CSV   = Path("output.csv")
PREDICTION_CSV = Path("prediction.csv")

MODEL_PATH    = Path("artifacts/model.pkl")
SCALER_PATH   = Path("artifacts/scaler.pkl")
FEATURES_PATH = Path("artifacts/feature_order.json")



def capture_chunk() -> None:
    subprocess.run(
        ["sudo", "tcpdump", "-i", INTERFACE,
         "-w", str(PCAP_FILE), "-G", str(CAPTURE_SECONDS), "-W", "1"],
        check=True,
    )


def convert_to_csv() -> None:
    subprocess.run(
        ["cicflowmeter", "-f", str(PCAP_FILE), "-c", str(CYCLE_CSV)],
        check=True,
    )


def append_cycle_to_output() -> None:
    if not CYCLE_CSV.exists() or CYCLE_CSV.stat().st_size == 0:
        return
    if not OUTPUT_CSV.exists() or OUTPUT_CSV.stat().st_size == 0:
        CYCLE_CSV.replace(OUTPUT_CSV)
        return
    with CYCLE_CSV.open("r", newline="") as src, \
         OUTPUT_CSV.open("a", newline="") as dst:
        reader = csv.reader(src)
        writer = csv.writer(dst)
        next(reader, None)          
        writer.writerows(reader)
    CYCLE_CSV.unlink(missing_ok=True)


def load_new_rows(processed: int) -> tuple[pd.DataFrame, int]:
    if not OUTPUT_CSV.exists():
        return pd.DataFrame(), processed
    df = pd.read_csv(OUTPUT_CSV)
    new = df.iloc[processed:].copy()
    return new, len(df)


def write_predictions(new_flows: pd.DataFrame, attacks: list[dict]) -> None:
    if new_flows.empty:
        return
    attack_map = {a["src_ip"]: a["label"] for a in attacks}
    out = new_flows.copy()
    out["prediction"] = (
        out["src_ip"].astype(str).str.strip()
        .map(lambda ip: attack_map.get(ip, "BENIGN"))
    )
    write_header = not PREDICTION_CSV.exists() or PREDICTION_CSV.stat().st_size == 0
    out.to_csv(PREDICTION_CSV, mode="a", index=False, header=write_header)



def main() -> None:
    print(f"Firewall monitor starting — interface={INTERFACE}, window={CAPTURE_SECONDS}s\n")

    detector = MLDetector(
        model_path=MODEL_PATH,
        scaler_path=SCALER_PATH,
        features_path=FEATURES_PATH,
    )
    processed = 0

    while True:
        try:
            print("── [1/4] Capturing …")
            capture_chunk()

            print("── [2/4] Converting pcap → flows …")
            convert_to_csv()
            append_cycle_to_output()

            new_flows, processed = load_new_rows(processed)
            print(f"── [3/4] Analysing {len(new_flows)} new flow(s) …")

            attacks = detector.check(new_flows)
            write_predictions(new_flows, attacks)

            print(f"── [4/4] ", end="")
            if attacks:
                print(f"{len(attacks)} attacker(s) found — blocking:")
                enforce_attacks(attacks)
            else:
                print("No attacks detected.")
            print()

        except subprocess.CalledProcessError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            break
        except KeyboardInterrupt:
            print("\nStopped.")
            break


if __name__ == "__main__":
    main()
