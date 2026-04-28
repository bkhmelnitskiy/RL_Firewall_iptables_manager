# RL_FIREWALL_IPTABLES

## Project Overview
Two-layer network intrusion detection system that feeds iptables:

1. **Flow-based IDS** (existing) — Random Forest classifier trained on CICIDS2017
   flow statistics (CICFlowMeter output). Good for DoS/scan/brute-force detection
   at connection granularity.

2. **Packet-level web-attack detector** (added 2026-04-21/22) — parallel module
   that inspects raw HTTP request bytes (URI + body) for content-based web
   attacks (SQLi, XSS, cmd injection, path traversal, LDAP/XPath injection,
   SSI). Trained on CSIC 2010 + ECML/PKDD 2007, validated on FWAF and
   HttpParamsDataset.

See `HISTORY.md` for the full evolution of the packet-level detector across
13 etaps (raw → normalized → decoded → signature-based rule engine →
parser fix + signature expansion → RandomForest per-attack ensemble →
block threshold + live iptables/NFQUEUE test → unified two-layer
continuous system).

## Architecture

### Flow-based IDS (CICIDS2017)
- `train_model.py` — trains Random Forest classifier on CICIDS2017 CSV datasets, outputs model/scaler/features to `artifacts/`.
- `detector.py` — `MLDetector` class, loads trained flow model and runs inference on network flow DataFrames.
- `infer_model.py` — runs inference on new data using saved model.
- `iptables_rules_generator.py` — `Rule` class + generates and applies iptables rules from detection results.
- `column_mapping.py` — maps CICFlowMeter output columns to model feature names.
- `flow_monitor.py` — **continuous** flow-layer monitor (E13). Uses
  cicflowmeter `FlowSession` via scapy AsyncSniffer; replaces the default
  CSV writer with `MLBlockerWriter` that calls `MLDetector.check()` on
  each completed flow and adds attacking src IPs to the shared
  `rlfw_block` ipset. Appends unified JSONL events with `layer=flow`.
- `packet_exfiltration.py`, `simulate_brute_force.py`, `target_server.py` — simulation utilities.

### Packet-level web-attack detector
- `packet_preprocess.py` — parses CSIC/ECML datasets into unified pickles.
  Provides two preprocessing functions:
  - `normalize_http(raw)` — strips file extensions + most headers (keeps only
    Content-Type, Content-Length, Referer). Variant: `normalized`.
  - `extract_attack_surface(raw)` — **V2 (recommended)**: keeps only URI+body,
    URL-decodes recursively (up to 3 rounds, handles double encoding),
    lowercases. Variant: `decoded`.
- `attack_signatures.py` — defines 124 per-attack regex signatures grouped by
  attack type (`SIGNATURES` dict). `SignatureCounter` sklearn transformer
  returns count matrix. `web_attack_universal` signatures = union of all
  per-attack signatures. (Expanded from 101 → 124 in Etap 10 — added
  inline-comment SQLi, Windows cmd + control-char separators, scanner
  fingerprints, PHP code-exec, null-byte, single `../etc/...` variants.)
- `train_packet_model.py` — CLI for training a per-attack binary classifier.
  - `--attack` ∈ {web_attack_generic, web_attack_universal, sqli, xss,
    cmd_injection, path_traversal, ldap_injection, xpath_injection, ssi}
  - `--data-variant` ∈ {raw, normalized, decoded}
  - `--use-signatures` — adds SignatureCounter via FeatureUnion with TF-IDF.
  - `--signatures-only` — uses ONLY signature features (no TF-IDF).
  - `--clf {logreg,rf}` — classifier choice. RF respects individual feature
    thresholds via tree splits (better for rare signatures). `--rf-n-estimators`
    controls tree count (default 200).
  - Output dir auto-suffixed: `_sig`, `_sigonly`, `_rf_sigonly`, etc.
- `train_3models.py` — V2 trainer (active). Trains 3 binary classifiers
  (sqli/xss/cmd_injection) on the new CSV datasets. Sweeps 5 algorithms ×
  3 feature variants per attack, picks best F1 winner. Writes to
  `artifacts/packet_models_v2/`.
- `retrain_cmd.py` — failed experiment to lower cmd_injection FWAF FPR by
  augmenting with ECML cmd_injection. Augmentation hurt all metrics —
  script preserves the original `cmd_injection.pkl`.
- `eval_3models.py` — cross-dataset validation of the 3 V2 models on FWAF +
  HttpParamsDataset (with per-attack labels) + CSIC benign. Replaces the
  per-variant evaluate_fwaf.py / evaluate_fwaf_ensemble.py /
  evaluate_cross_dataset.py / evaluate_httpparams.py from earlier etaps.
- `evaluate_fwaf_rules.py` — pure rule-based (ANY signature fires) FWAF
  eval — independent baseline. Supports `--dump-misses N` / `--dump-fps N`
  to sample missed/FP payloads for signature tuning.

### Directories
- `artifacts/` — flow model (`model.pkl`, `scaler.pkl`, `feature_order.json`).
- `artifacts/datasets/` — preprocessed HTTP payload pickles (raw, normalized, decoded).
- `artifacts/packet_models_v2/` — **active V2 ensemble**:
  - `sqli.pkl` (3.9 MB) — hybrid (TF-IDF char-ngram 3-5 + 21 sqli sigs) + LinearSVC.
  - `xss.pkl` (3.5 MB) — TF-IDF char-ngram 3-5 + LinearSVC (no sigs).
  - `cmd_injection.pkl` (1.3 MB) — TF-IDF char-ngram 3-5 + LinearSVC (no sigs).
  - `results.json` / `results.md` — full algo×feature sweep metrics.
  - `eval.log` — cross-dataset eval results (FWAF / HttpParams / CSIC).
- `artifacts/third_party/` — external datasets (FWAF lives under `~/fwaf_data/` in WSL to avoid Defender).
- `datasets/` — CICIDS2017 CSVs (Layer 1 input) + 3 CSV per-attack datasets:
  - `Modified_SQL_Dataset.csv` (30919 rows, sqli)
  - `XSS_dataset.csv` (13686 rows, xss)
  - `command injection.csv` (2106 rows, cmd_injection)
- `cicflowmeter/` — network flow feature extraction tool.
- `web-application-attacks-datasets-master/` — CSIC + ECML source data.

## Production deployment (2026-04-27 — V2, 4-model ensemble)

**Total models in production: 4.**

**Layer 1 — flow-based (1 model):** Random Forest on CICIDS2017 flow
features (`artifacts/model.pkl`). Drops DoS / port scans / brute-force at
flow granularity.

**Layer 2 — packet-level web attacks (3 ML models):** per-attack binary
classifiers in `artifacts/packet_models_v2/`. Each uses TF-IDF char-ngram
(3,5) + LinearSVC; sqli additionally has 21 regex signatures concatenated
via FeatureUnion. **Rule-based + RF ensemble from earlier etaps removed.**

| Attack | Algorithm | Features | Test F1 | FWAF FPR | FWAF hit | HP norm FPR | HP attack TPR |
|---|---|---|---:|---:|---:|---:|---:|
| sqli | LinearSVC | TF-IDF char35 + 21 sigs (hybrid) | 0.9956 | 0.297% | 14.4% | 0.026% | 99.48% |
| xss | LinearSVC | TF-IDF char35 only | 0.9986 | 0.096% | 26.3% | 0.010% | 94.55% |
| cmd_injection | LinearSVC | TF-IDF char35 only | 0.9951 | 2.473% ⚠ | 51.9% | 0.047% | 91.01% |
| **ensemble OR** | — | — | — | **2.836%** | **68.36%** | **0.083%** | — |

Training datasets (CSV, in `datasets/`):
- `Modified_SQL_Dataset.csv` — 11382 sqli + 19537 benign
- `XSS_dataset.csv` — 7373 xss + 6313 benign
- `command injection.csv` — 514 cmdi + 1591 benign (small — drives the 2.47% FPR)

Why LinearSVC won: sweep across LogReg / RandomForest / GradientBoostingClassifier
/ LinearSVC / MultinomialNB × 3 feature variants (tfidf_char35 / sigs only /
hybrid). LinearSVC was top F1 across all 3 attacks, fits in <1.5 s. GBC matched
F1 but 40-50× slower. RF cross-dataset noisy on cmd (P=0.55).

Why hybrid only for sqli: hybrid = TF-IDF + per-attack signatures. For sqli it
adds +0.0009 F1 (already ~0.99) and lets LinearSVC weight rare-but-strong
patterns like `union select`. For xss/cmd it adds nothing — char-ngrams already
saturate.

Why cmd_injection has 2.47% FWAF FPR: training set is tiny (~2k rows) and
narrowly SSI-style (`<!--#exec cmd=...-->`). Augmenting with ECML
`cmd_injection` made FWAF FPR worse (4.6% / 2.7%) — see `retrain_cmd.py`.
The 91% TPR on HttpParams cmdi shows the model works; the FWAF FPR comes
from FWAF goodqueries having a lot of obfuscated-looking URIs.

**Deploy:**
```bash
# packet daemon picks up all 3 V2 models from --ensemble-dir
sudo python3 nfqueue_daemon.py --ensemble-dir artifacts/packet_models_v2
# or both layers via run_all.sh / rlfw.py (V2 is the new default)
sudo bash run_all.sh --iface eth0 --threshold 3
sudo python3 rlfw.py --iface eth0 --threshold 3
```

Log reason on hit: `reason=ensemble=sqli+xss rule_hits=3` (V2 models that
fired, plus rule-based hit count for the universal signature set if the
daemon is also running rule-based path).

**Etap 13 (unified two-layer continuous system):** both layers run
simultaneously, share one `rlfw_block` ipset + one iptables DROP rule +
one JSONL events log (`/tmp/rlfw_events.jsonl` by default). Start via
`run_all.sh` / `rlfw.py`. End-to-end test: `sudo bash live_test_full.sh`.

## Workflow

**Flow-based (existing):**
```
pcap → CICFlowMeter → CSV → train_model.py → model.pkl → MLDetector → iptables
```

**Packet-level (new):**
```
HTTP bytes → extract_attack_surface() → SignatureCounter(universal).transform()
  → (count>0) → DROP rule for source IP
```

## Common Commands

```bash
# Flow-based training (Layer 1, CICIDS2017)
python3 train_model.py --dataset datasets/ --n-estimators 100

# V2 trainer — sweep 5 algos × 3 feature variants × 3 attacks → pick best F1
python3 train_3models.py
# Cross-dataset eval of the 3 V2 winners
python3 eval_3models.py
# Retry cmd_injection with augmented data + hybrid (kept original — see HISTORY)
python3 retrain_cmd.py

# Pure rule-based FWAF baseline (no models, 124 universal sigs)
python3 evaluate_fwaf_rules.py
python3 evaluate_fwaf_rules.py --dump-misses 2500 --out misses.txt

# Daemon offline tests (14 cases, no kernel)
python3 test_nfqueue_daemon.py
```

## Key Dependencies
- scikit-learn (Random Forest, LogisticRegression, TfidfVectorizer, FeatureUnion).
- pandas, numpy, scipy (sparse matrices).
- matplotlib (confusion matrix plots).
- iptables (system, Linux only).
- python-netfilterqueue + scapy (planned, for NFQUEUE inline inspection).

## Runtime environment notes
- Training/evaluation runs under **WSL Ubuntu** (WSL2 Linux kernel 5+).
- Most binaries/models live under `/mnt/c/…` (Windows filesystem) and are
  executed via `wsl --exec bash -c 'cd /mnt/c/… && python3 …'`.
- **Windows Defender quarantines** `fwaf/badqueries.txt` (contains attack
  payloads) when written under `C:\`. Mitigation: FWAF source data lives in
  WSL home `~/fwaf_data/` (outside `/mnt/c/` scanner scope). Same mitigation
  applies to HttpParams (`~/httpparams/`).

## Notes
- iptables rules require root/sudo on Linux.
- Flow dataset: CICIDS2017 (Canadian Institute for Cybersecurity).
- Flow model excludes port/packet count features that leak identity
  (see `DEFAULT_EXCLUDE` in `train_model.py`).
- Packet datasets: CSIC 2010 (97k rows) + ECML/PKDD 2007 (50k rows) for
  training; FWAF (1.3M URIs) + HttpParamsDataset (31k params) for validation.
- Attack surface extraction uses recursive URL-decode (3 rounds) to handle
  double-encoded payloads like `%2527` → `%27` → `'`.

## NFQUEUE inline inspection (implemented 2026-04-22)

`nfqueue_daemon.py` — inline HTTP attack detector. Reads packets from NFQUEUE,
reassembles per-flow (keyed on 4-tuple, honors Content-Length, GC after
10 s silence, hard cap 256 KB / flow), runs `extract_attack_surface()` +
`SignatureCounter("web_attack_universal")`. On hit: drops packet + adds
src IP to ipset `webattack_block`. Fail-open on any parse error. Ipset
gives O(1) kernel-side blocking with a single iptables rule — no table
explosion under flood.

Offline test suite: `python3 test_nfqueue_daemon.py` (10 tests — reassembly,
Content-Length partial body, split-segment POST, fail-open on garbage,
dry-run never drops, benign passes, SQLi/XSS fire, blocker-threshold
counting, threshold-packet-drop-before-ipset, ensemble-model-load).

Live end-to-end test (Linux/WSL, root): `live_test.sh` spins up
target_server + daemon on real iptables/ipset/NFQUEUE, runs 3 scenarios
(benign passthrough → attack blocked → subsequent traffic kernel-dropped)
and cleans up. Verified 2026-04-23 under WSL2 kernel 6.6, threshold=3.

Deployment (Linux/WSL, root):
```
apt install libnetfilter-queue-dev ipset
pip install --break-system-packages NetfilterQueue scapy

ipset create webattack_block hash:ip timeout 3600
iptables -I INPUT -m set --match-set webattack_block src -j DROP
iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0

python3 nfqueue_daemon.py --dry-run        # log-only, safe first run
python3 nfqueue_daemon.py                  # enforce
```

Decisions baked in (see top of `nfqueue_daemon.py` for rationale):
- HTTP on port 80 only; HTTPS requires TLS termination upstream (Etap 10).
- Fail-open on parse error — prefer passing a bad packet over killing legit.
- ipset `hash:ip timeout=3600` instead of per-IP iptables rule.
- Naive per-flow buffer; upgrade to scapy TCPSession only if real-traffic
  test shows missed reassemblies.
- `--block-threshold N` (E12): every attack packet is always dropped, but
  the kernel-side ipset block triggers only after N attempts from same
  src IP. Default 1 (block on first). Useful when deploying inline to
  avoid a single FP → permanent IP ban.
