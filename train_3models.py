"""
Trening 3 modeli per typ ataku (sqli / xss / cmd_injection) na nowych
datasetach + porównanie kilku algorytmów i wariantów cech.

Datasety:
  - datasets/Modified_SQL_Dataset.csv     (Query, Label)        SQLi
  - datasets/XSS_dataset.csv              (Sentence, Label)     XSS
  - datasets/command injection.csv        (sentence, Label)     cmd injection (HTML-encoded)

Algorytmy testowane (sklearn):
  - LogisticRegression(class_weight=balanced)
  - RandomForestClassifier(n_estimators=200, class_weight=balanced)
  - GradientBoostingClassifier(n_estimators=100)
  - LinearSVC(class_weight=balanced)
  - MultinomialNB

Warianty cech:
  - tfidf_char35   : char n-gram (3,5), max_features=50000
  - sigs           : SignatureCounter(<attack>)  — same regex hits
  - hybrid         : FeatureUnion(tfidf_char35 + sigs)

Per (attack, algo, feature) liczymy precision/recall/F1/ROC-AUC na test split.
Najlepszy F1 -> wygrywa, zapisany do artifacts/packet_models_v2/<attack>.pkl.

Uwaga:
  cmd injection CSV ma payloady HTML-encoded (`&lt;`, `&quot;`, `%20`).
  Dla spójności z runtime (`extract_attack_surface` daje URL-decoded
  lowercase URI+body) preprocessing: html.unescape -> urllib unquote (3x)
  -> lowercase. To samo robimy dla SQLi/XSS dla pewności.
"""
from __future__ import annotations

import argparse
import html
import json
import pickle
import time
import warnings
from pathlib import Path
from typing import Callable
from urllib.parse import unquote

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    f1_score, precision_score, recall_score, roc_auc_score, accuracy_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from attack_signatures import SignatureCounter

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "artifacts" / "packet_models_v2"
OUT_DIR.mkdir(parents=True, exist_ok=True)

DATASETS = {
    "sqli": {
        "path": ROOT / "datasets" / "Modified_SQL_Dataset.csv",
        "text_col": "Query",
        "label_col": "Label",
    },
    "xss": {
        "path": ROOT / "datasets" / "XSS_dataset.csv",
        "text_col": "Sentence",
        "label_col": "Label",
    },
    "cmd_injection": {
        "path": ROOT / "datasets" / "command injection.csv",
        "text_col": "sentence",
        "label_col": "Label",
    },
}


def normalize_payload(s: str) -> str:
    """Same surface as runtime extract_attack_surface(): URL-decoded lowercase."""
    if not isinstance(s, str):
        return ""
    s = html.unescape(s)
    prev = None
    for _ in range(3):
        if s == prev:
            break
        prev = s
        try:
            s = unquote(s)
        except Exception:
            break
    return s.lower()


def load_attack(name: str) -> tuple[list[str], np.ndarray]:
    cfg = DATASETS[name]
    df = pd.read_csv(cfg["path"])
    df = df.dropna(subset=[cfg["text_col"], cfg["label_col"]])
    X = df[cfg["text_col"]].astype(str).map(normalize_payload).tolist()
    y = df[cfg["label_col"]].astype(int).values
    return X, y


def build_feature(name: str, attack: str):
    if name == "tfidf_char35":
        return TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5),
            max_features=50000, lowercase=False, sublinear_tf=True,
        )
    if name == "sigs":
        return SignatureCounter(attack)
    if name == "hybrid":
        return FeatureUnion([
            ("tfidf", TfidfVectorizer(
                analyzer="char_wb", ngram_range=(3, 5),
                max_features=50000, lowercase=False, sublinear_tf=True,
            )),
            ("sigs", SignatureCounter(attack)),
        ])
    raise ValueError(name)


def build_clf(name: str):
    if name == "logreg":
        return LogisticRegression(
            max_iter=2000, class_weight="balanced", solver="liblinear",
        )
    if name == "rf":
        return RandomForestClassifier(
            n_estimators=200, class_weight="balanced",
            n_jobs=-1, random_state=42,
        )
    if name == "gbc":
        return GradientBoostingClassifier(n_estimators=100, random_state=42)
    if name == "linsvc":
        return LinearSVC(class_weight="balanced", max_iter=3000)
    if name == "mnb":
        return MultinomialNB()
    raise ValueError(name)


ALGOS = ["logreg", "rf", "gbc", "linsvc", "mnb"]
FEATURES = ["tfidf_char35", "sigs", "hybrid"]


def fit_and_eval(X_tr, y_tr, X_te, y_te, feat_name, algo_name, attack):
    feat = build_feature(feat_name, attack)
    clf = build_clf(algo_name)

    # MNB requires non-negative; SignatureCounter outputs counts (>=0), TF-IDF >=0 too. OK.
    # GBC + sigs alone may struggle; still test.

    pipe = Pipeline([("feat", feat), ("clf", clf)])

    t0 = time.time()
    pipe.fit(X_tr, y_tr)
    t_fit = time.time() - t0

    y_pred = pipe.predict(X_te)

    # ROC-AUC: only if classifier exposes proba/decision
    auc = None
    try:
        if hasattr(pipe.named_steps["clf"], "predict_proba"):
            scores = pipe.predict_proba(X_te)[:, 1]
        else:
            scores = pipe.decision_function(X_te)
        auc = float(roc_auc_score(y_te, scores))
    except Exception:
        auc = None

    return {
        "precision": float(precision_score(y_te, y_pred, zero_division=0)),
        "recall": float(recall_score(y_te, y_pred, zero_division=0)),
        "f1": float(f1_score(y_te, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_te, y_pred)),
        "roc_auc": auc,
        "fit_seconds": round(t_fit, 2),
    }, pipe


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip-slow", action="store_true",
                    help="Skip GBC + RF on large datasets")
    args = ap.parse_args()

    all_results: dict = {}
    winners: dict = {}

    for attack in DATASETS:
        print(f"\n{'='*70}\n=== ATTACK: {attack} ===\n{'='*70}")
        X, y = load_attack(attack)
        pos = int(y.sum())
        neg = int((y == 0).sum())
        print(f"loaded n={len(X)}  pos={pos}  neg={neg}  ratio={pos/(pos+neg):.3f}")

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=args.test_size, random_state=args.seed, stratify=y,
        )
        print(f"train={len(X_tr)}  test={len(X_te)}")

        attack_results = []
        best_pipe = None
        best_key = None
        best_f1 = -1.0

        for feat_name in FEATURES:
            for algo_name in ALGOS:
                # Skip combinations that don't make sense
                if algo_name == "mnb" and feat_name == "hybrid":
                    # FeatureUnion outputs sparse mixed; MNB OK with non-negative
                    pass

                key = f"{feat_name}__{algo_name}"
                if args.skip_slow and algo_name in ("gbc", "rf") and len(X_tr) > 20000:
                    print(f"  [{key}] skipped (--skip-slow)")
                    continue

                try:
                    metrics, pipe = fit_and_eval(
                        X_tr, y_tr, X_te, y_te, feat_name, algo_name, attack,
                    )
                except Exception as e:
                    print(f"  [{key}] FAILED: {type(e).__name__}: {e}")
                    attack_results.append({
                        "feat": feat_name, "algo": algo_name,
                        "error": f"{type(e).__name__}: {e}",
                    })
                    continue

                row = {"feat": feat_name, "algo": algo_name, **metrics}
                attack_results.append(row)
                auc_str = f"{metrics['roc_auc']:.4f}" if metrics['roc_auc'] is not None else "  n/a "
                print(
                    f"  [{key:<24}] "
                    f"P={metrics['precision']:.4f}  R={metrics['recall']:.4f}  "
                    f"F1={metrics['f1']:.4f}  AUC={auc_str}  "
                    f"fit={metrics['fit_seconds']:>6.2f}s"
                )

                if metrics["f1"] > best_f1:
                    best_f1 = metrics["f1"]
                    best_pipe = pipe
                    best_key = key

        all_results[attack] = attack_results

        if best_pipe is None:
            print(f"!! no winner for {attack}")
            continue

        winners[attack] = {"key": best_key, "f1": best_f1}
        out_path = OUT_DIR / f"{attack}.pkl"
        with out_path.open("wb") as f:
            pickle.dump(best_pipe, f)
        print(f"\n>>> WINNER {attack}: {best_key}  F1={best_f1:.4f}  -> {out_path}")

    # Persist results
    with (OUT_DIR / "results.json").open("w") as f:
        json.dump(
            {"results": all_results, "winners": winners}, f, indent=2,
        )

    # Markdown ladder
    md_lines = ["# Training results — 3 per-attack models\n"]
    for attack, rows in all_results.items():
        md_lines.append(f"\n## {attack}\n")
        md_lines.append("| feature | algo | precision | recall | F1 | AUC | fit s |")
        md_lines.append("|---|---|---:|---:|---:|---:|---:|")
        ranked = sorted(
            [r for r in rows if "error" not in r],
            key=lambda r: r["f1"], reverse=True,
        )
        for r in ranked:
            auc = f"{r['roc_auc']:.4f}" if r['roc_auc'] is not None else "—"
            md_lines.append(
                f"| {r['feat']} | {r['algo']} | "
                f"{r['precision']:.4f} | {r['recall']:.4f} | **{r['f1']:.4f}** | "
                f"{auc} | {r['fit_seconds']:.2f} |"
            )
        for r in [r for r in rows if "error" in r]:
            md_lines.append(f"| {r['feat']} | {r['algo']} | ERROR: {r['error']} |||||")
    with (OUT_DIR / "results.md").open("w") as f:
        f.write("\n".join(md_lines))

    print(f"\n=== ALL DONE ===")
    print(f"Winners:")
    for k, v in winners.items():
        print(f"  {k}: {v['key']}  F1={v['f1']:.4f}")
    print(f"Results: {OUT_DIR}/results.json + results.md")


if __name__ == "__main__":
    main()
